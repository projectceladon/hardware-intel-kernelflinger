/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors: Sylvain Chouleur <sylvain.chouleur@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 *          Jocelyn Falempe <jocelyn.falempe@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <efi.h>
#include <efilib.h>
#include <lib.h>
#include <openssl/sha.h>

#include "fastboot.h"
#include "uefi_utils.h"
#include "gpt.h"
#include "android.h"
#include "keystore.h"
#include "security.h"

static void hash_buffer(CHAR8 *buffer, UINT64 len, CHAR8 *hash)
{
	SHA_CTX sha_ctx;

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, buffer, len);
	SHA1_Final(hash, &sha_ctx);
}

static void report_hash(const CHAR16 *base, const CHAR16 *name, CHAR8 *hash)
{
	CHAR8 hashstr[SHA_DIGEST_LENGTH * 2 + 1];
	CHAR8 *pos;
	CHAR8 hex;
	int i;

	for (i = 0, pos = hashstr; i < SHA_DIGEST_LENGTH * 2; i++) {
		hex = ((i & 1) ? hash[i / 2] & 0xf : hash[i / 2] >> 4);
		*pos++ = (hex > 9 ? (hex + 'a' - 10) : (hex + '0'));
	}
	*pos = '\0';

	fastboot_info("target: %s%s", base, name);
	fastboot_info("hash: %a", hashstr);
}

static UINTN get_bootimage_len(CHAR8 *buffer, UINTN buffer_len)
{
	struct boot_img_hdr *hdr;
	struct boot_signature *bs;
	UINTN len;

	if (buffer_len < sizeof(*hdr)) {
		error(L"boot image too small");
		return 0;
	}
	hdr = (struct boot_img_hdr *) buffer;

	if (strncmp((CHAR8 *) BOOT_MAGIC, hdr->magic, BOOT_MAGIC_SIZE)) {
		error(L"bad boot magic");
		return 0;
	}

	len = bootimage_size(hdr);
	debug(L"len %lld", len);

	if (len > buffer_len + BOOT_SIGNATURE_MAX_SIZE) {
		error(L"boot image too big");
		return 0;
	}

	bs = get_boot_signature(&buffer[len], BOOT_SIGNATURE_MAX_SIZE);

	if (bs) {
		len += bs->total_size;
		free_boot_signature(bs);
	} else {
		debug(L"boot image doesn't seem to have a signature");
	}

	debug(L"total boot image size %d", len);
	return len;
}

EFI_STATUS get_boot_image_hash(CHAR16 *label)
{
	struct gpt_partition_interface gparti;
	CHAR8 *data;
	UINT64 len;
	UINT64 offset;
	CHAR8 hash[SHA_DIGEST_LENGTH];
	EFI_STATUS ret;

	ret = gpt_get_partition_by_label(label, &gparti, EMMC_USER_PART);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to get partition %s", label);
		return ret;
	}

	len = (gparti.part.ending_lba + 1 - gparti.part.starting_lba) * gparti.bio->Media->BlockSize;
	offset = gparti.part.starting_lba * gparti.bio->Media->BlockSize;

	if (len > 100 * MiB) {
		error(L"partition too large to contain a boot image");
		return EFI_INVALID_PARAMETER;
	}
	data = AllocatePool(len);
	if (!data) {
		return EFI_OUT_OF_RESOURCES;
	}

	ret = uefi_call_wrapper(gparti.dio->ReadDisk, 5, gparti.dio, gparti.bio->Media->MediaId, offset, len, data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to read partition");
		FreePool(data);
		return ret;
	}

	len = get_bootimage_len(data, len);
	if (len) {
		hash_buffer(data, len, hash);
		report_hash(L"/", label, hash);
	}
	FreePool(data);
	return EFI_SUCCESS;
}

#define MAX_DIR 10
#define MAX_FILENAME_LEN (256 * sizeof(CHAR16))
#define DIR_BUFFER_SIZE (MAX_DIR * MAX_FILENAME_LEN)
static CHAR16 *path;
static CHAR16 *subname[MAX_DIR];
static INTN subdir;

static void hash_file(EFI_FILE *dir, EFI_FILE_INFO *fi)
{
	EFI_FILE *file;
	void *data;
	CHAR8 hash[SHA_DIGEST_LENGTH];
	EFI_STATUS ret;
	UINTN size;

	if (!fi->Size) {
		hash_buffer(NULL, 0, hash);
		report_hash(path, fi->FileName, hash);
		return;
	}

	ret = uefi_call_wrapper(dir->Open, 5, dir, &file, fi->FileName, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(ret))
		return;

	size = fi->FileSize;

	data = AllocatePool(size);
	if (!data)
		goto close;

	ret = uefi_call_wrapper(file->Read, 3, file, &size, data);
	if (EFI_ERROR(ret))
		goto free;

	hash_buffer(data, size, hash);
	report_hash(path, fi->FileName, hash);

free:
	FreePool(data);
close:
	uefi_call_wrapper(file->Close, 1, file);
}

/*
 * generate a string with the current directory
 * updated each time we open/close a directory
 */
 static void initpath(void)
 {
	path = AllocateZeroPool(DIR_BUFFER_SIZE);
	if (!path)
		return;
	StrCat(path, L"/bootloader/");
 }

static void pushdir(CHAR16 *dir)
{
	if (!path)
		return;

	if (StrSize(path) + StrSize(dir) > DIR_BUFFER_SIZE)
		return;

	subname[subdir] = path + StrLen(path);
	StrCat(path, dir);
	StrCat(path, L"/");
	debug(L"Opening %s", path);
}

static void popdir(void)
{
	if (!path)
		return;
	if (subdir > 0) {
		*subname[subdir - 1] = L'\0';
		debug(L"Return to %s", path);
		return;
	}
	FreePool(path);
	path = NULL;
	debug(L"Free path");
}

EFI_STATUS get_esp_hash(void)
{
	EFI_STATUS ret;
	EFI_FILE_IO_INTERFACE *io;
	EFI_FILE *dirs[MAX_DIR];
	CHAR8 buf[sizeof(EFI_FILE_INFO) + MAX_FILENAME_LEN];
	EFI_FILE_INFO *fi = (EFI_FILE_INFO *) buf;
	UINTN size = sizeof(buf);

	ret = get_esp_fs(&io);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to get partition ESP");
		return ret;
	}

	subdir = 0;
	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &dirs[subdir]);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open root directory");
		return ret;
	}
	initpath();
	do {
		size = sizeof(buf);
		ret = uefi_call_wrapper(dirs[subdir]->Read, 3, dirs[subdir], &size, fi);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, "Cannot read directory entry");
			/* continue to walk the ESP partition */
			size = 0;
		}
		if (!size && subdir >= 0) {
			/* size is 0 means there are no more files/dir in current directory
			 * so if we are in a subdir, go back 1 level */
			uefi_call_wrapper(dirs[subdir]->Close, 1, dirs[subdir]);
			popdir();
			subdir--;
			continue;
		}
		if (fi->Attribute & EFI_FILE_DIRECTORY) {
			EFI_FILE *parent;

			if (!StrCmp(fi->FileName, L".") || !StrCmp(fi->FileName, L".."))
				continue;
			if (subdir == MAX_DIR - 1) {
				error(L"too much subdir, ignoring %s", fi->FileName);
				continue;
			}
			parent = dirs[subdir];
			pushdir(fi->FileName);
			subdir++;
			ret = uefi_call_wrapper(parent->Open, 5, parent, &dirs[subdir], fi->FileName, EFI_FILE_MODE_READ, 0);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, "Cannot open directory %s", fi->FileName);
				/* continue to walk the ESP partition */
				popdir();
				subdir--;
			}
		} else {
			hash_file(dirs[subdir], fi);
		}
	} while (size || subdir >= 0);
	return EFI_SUCCESS;
}

/*
 * minimum ext4 definition to get the total size of the filesystem
 */

#define EXT4_SB_OFFSET 1024
#define EXT4_SUPER_MAGIC 0xEF53
#define EXT4_VALID_FS 0x0001

#define VERITY_METADATA_SIZE 32768
#define VERITY_METADATA_MAGIC_NUMBER 0xb001b001

#define EXT4_HASH_SIZE 32
#define EXT4_BLOCK_SIZE 4096
#define HASHES_PER_BLOCK (EXT4_BLOCK_SIZE / EXT4_HASH_SIZE)

struct ext4_super_block {
	INT32 unused;
	INT32 s_blocks_count_lo;
	INT32 unused2[4];
	INT32 s_log_block_size;
	INT32 unused3[7];
	UINT16 s_magic;
	UINT16 s_state;
	INT32 unused4[69];
	INT32 s_blocks_count_hi;
};

struct ext4_verity_header {
	UINT32 magic;
	UINT32 protocol_version;
};

/* adapted from build_verity_tree.cpp */
static UINT64 verity_tree_blocks(UINT64 data_size, INT32 level)
{
	UINT64 level_blocks = DIV_ROUND_UP(data_size, EXT4_BLOCK_SIZE);

	do {
		level_blocks = DIV_ROUND_UP(level_blocks, HASHES_PER_BLOCK);
	} while (level--);

	return level_blocks;
}

/* adapted from build_verity_tree.cpp */
static UINT64 verity_tree_size(UINT64 data_size)
{
	UINT64 verity_blocks = 0;
	UINT64 level_blocks;
	INT32 levels = 0;
	UINT64 tree_size;

	do {
		level_blocks = verity_tree_blocks(data_size, levels);
		levels++;
		verity_blocks += level_blocks;
	} while (level_blocks > 1);

	tree_size = verity_blocks * EXT4_BLOCK_SIZE;
	debug(L"verity tree size %lld\n", tree_size);
	return tree_size;
}

static EFI_STATUS read_partition(struct gpt_partition_interface *gparti, UINT64 offset, UINT64 len, void *data)
{
	UINT64 partlen;
	UINT64 partoffset;
	EFI_STATUS ret;

	partlen = (gparti->part.ending_lba + 1 - gparti->part.starting_lba) * gparti->bio->Media->BlockSize;
	partoffset = gparti->part.starting_lba * gparti->bio->Media->BlockSize;

	if (len + offset > partlen) {
		error(L"attempt to read outside of partition %s, (len %lld offset %lld partition len %lld)", gparti->part.name, len, offset, partlen);
		return EFI_INVALID_PARAMETER;
	}
	ret = uefi_call_wrapper(gparti->dio->ReadDisk, 5, gparti->dio, gparti->bio->Media->MediaId, partoffset + offset, len, data);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"read partition %s failed", gparti->part.name);
	return ret;
}

#define CHUNK 1024 * 1024
#define MIN(a, b) ((a < b) ? (a) : (b))
static EFI_STATUS hash_partition(struct gpt_partition_interface *gparti, UINT64 len, CHAR8 *hash)
{
	SHA_CTX sha_ctx;
	CHAR8 *buffer;
	UINT64 offset;
	UINT64 chunklen;
	EFI_STATUS ret;

	SHA1_Init(&sha_ctx);

	buffer = AllocatePool(CHUNK);
	if (!buffer)
		return EFI_OUT_OF_RESOURCES;

	for (offset = 0; offset < len; offset += CHUNK) {
		chunklen = MIN(len - offset, CHUNK);
		ret = read_partition(gparti, offset, chunklen, buffer);
		if (EFI_ERROR(ret))
			goto free;
		SHA1_Update(&sha_ctx, buffer, chunklen);
	}
	SHA1_Final(hash, &sha_ctx);

free:
	FreePool(buffer);
	return ret;
}

static EFI_STATUS get_ext4_len(struct gpt_partition_interface *gparti, UINT64 *len)
{
	UINT64 block_size;
	UINT64 len_blocks;
	struct ext4_super_block sb;
	EFI_STATUS ret;

	ret = read_partition(gparti, EXT4_SB_OFFSET, sizeof(sb), &sb);
	if (EFI_ERROR(ret))
		return ret;

	if (sb.s_magic != EXT4_SUPER_MAGIC) {
		error(L"Ext4 super magic not found [%02x]", sb.s_magic);
		return EFI_INVALID_PARAMETER;
	}
	if ((sb.s_state & EXT4_VALID_FS) != EXT4_VALID_FS) {
		error(L"Ext4 invalid FS [%02x]", sb.s_state);
		return EFI_INVALID_PARAMETER;
	}
	block_size = 1024 << sb.s_log_block_size;
	len_blocks = ((UINT64) sb.s_blocks_count_hi << 32) + sb.s_blocks_count_lo;
	*len = block_size * len_blocks;

	return EFI_SUCCESS;
}

static EFI_STATUS check_verity_header(struct gpt_partition_interface *gparti, UINT64 ext4_len)
{
	EFI_STATUS ret;
	struct ext4_verity_header vh;

	ret = read_partition(gparti, ext4_len, sizeof(vh), &vh);
	if (EFI_ERROR(ret))
		return ret;

	if (vh.magic != VERITY_METADATA_MAGIC_NUMBER) {
		debug(L"verity magic not found");
		return EFI_INVALID_PARAMETER;
	}
	if (vh.protocol_version) {
		debug(L"verity protocol version unsupported %d", vh.protocol_version);
		return EFI_INVALID_PARAMETER;
	}
	return EFI_SUCCESS;
}

EFI_STATUS get_ext4_hash(CHAR16 *label)
{
	struct gpt_partition_interface gparti;
	CHAR8 hash[SHA_DIGEST_LENGTH];
	EFI_STATUS ret;
	UINT64 ext4_len;

	ret = gpt_get_partition_by_label(label, &gparti, EMMC_USER_PART);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to get partition %s", label);
		return ret;
	}

	ret = get_ext4_len(&gparti, &ext4_len);
	if (EFI_ERROR(ret))
		return ret;

	ret = check_verity_header(&gparti, ext4_len);
	if (EFI_ERROR(ret))
		return ret;

	ext4_len += verity_tree_size(ext4_len) + VERITY_METADATA_SIZE;

	debug(L"filesystem size %lld\n", ext4_len);

	ret = hash_partition(&gparti, ext4_len, hash);
	if (EFI_ERROR(ret))
		return ret;
	report_hash(L"/", gparti.part.name, hash);
	return EFI_SUCCESS;
}
