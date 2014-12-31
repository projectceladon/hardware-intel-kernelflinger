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
#include <fastboot.h>
#include <openssl/rand.h>
#include <android.h>

#include "fastboot_usb.h"
#include "uefi_utils.h"
#include "gpt.h"
#include "gpt_bin.h"
#include "flash.h"
#include "SdHostIo.h"
#include "Mmc.h"
#include "sparse.h"
#include "oemvars.h"
#include "vars.h"

static struct gpt_partition_interface gparti;
static UINT64 cur_offset;

#define part_start (gparti.part.starting_lba * gparti.bio->Media->BlockSize)
#define part_end ((gparti.part.ending_lba + 1) * gparti.bio->Media->BlockSize)

#define is_inside_partition(off, sz) \
		(off >= part_start && off + sz <= part_end)

EFI_STATUS flash_skip(UINT64 size)
{
	if (!is_inside_partition(cur_offset, size)) {
		error(L"Attempt to skip outside of partition [%ld %ld] [%ld %ld]",
				part_start, part_end, cur_offset, cur_offset + size);
		return EFI_INVALID_PARAMETER;
	}
	cur_offset += size;
	return EFI_SUCCESS;
}

EFI_STATUS flash_write(VOID *data, UINTN size)
{
	EFI_STATUS ret;

	if (!gparti.bio)
		return EFI_INVALID_PARAMETER;

	if (!is_inside_partition(cur_offset, size)) {
		error(L"Attempt to write outside of partition [%ld %ld] [%ld %ld]",
				part_start, part_end, cur_offset, cur_offset + size);
		return EFI_INVALID_PARAMETER;
	}
	ret = uefi_call_wrapper(gparti.dio->WriteDisk, 5, gparti.dio, gparti.bio->Media->MediaId, cur_offset, size, data);
	if (EFI_ERROR(ret))
		efi_perror(ret, "Failed to write bytes");

	cur_offset += size;
	return ret;
}

EFI_STATUS flash_fill(UINT32 pattern, UINTN size)
{
	UINT32 *buf;
	UINTN i;
	EFI_STATUS ret;

	buf = AllocatePool(size);
	if (!buf)
		return EFI_OUT_OF_RESOURCES;

	for (i = 0; i < size / sizeof(UINTN); i++)
		buf[i] = pattern;

	ret = flash_write(buf, size);
	FreePool(buf);
	return ret;
}

static EFI_STATUS flash_into_esp(VOID *data, UINTN size, CHAR16 *label)
{
	EFI_STATUS ret;
	EFI_FILE_IO_INTERFACE *io;

	ret = get_esp_fs(&io);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to get partition ESP");
		return ret;
	}
	return uefi_write_file_with_dir(io, label, data, size);
}

static EFI_STATUS flash_gpt(VOID *data, UINTN size)
{
	struct gpt_bin_header *gb_hdr;
	struct gpt_bin_part *gb_part;
	EFI_STATUS ret;

	gb_hdr = data;
	gb_part = (struct gpt_bin_part *)&gb_hdr[1];

	if (gb_hdr->magic != GPT_BIN_MAGIC)
		return EFI_INVALID_PARAMETER;

	if (size != sizeof(*gb_hdr) + gb_hdr->npart * sizeof(*gb_part))
		return EFI_INVALID_PARAMETER;

	ret = gpt_create(gb_hdr->start_lba, gb_hdr->npart, gb_part, EMMC_USER_PART);
	if (EFI_ERROR(ret))
		return ret;

	return (EFI_SUCCESS | REFRESH_PARTITION_VAR);
}

static EFI_STATUS flash_keystore(VOID *data, UINTN size)
{
	EFI_STATUS ret;

	ret = set_user_keystore(data, size);
	if (ret)
		efi_perror(ret, "Coudn't modify KeyStore");

	return ret;
}

static EFI_STATUS flash_efirun(VOID *data, UINTN size)
{
	return fastboot_usb_stop(NULL, data, size, UNKNOWN_TARGET);
}

static EFI_STATUS flash_sfu(VOID *data, UINTN size)
{
	return flash_into_esp(data, size, L"BIOSUPDATE.fv");
}

static EFI_STATUS flash_ifwi(VOID *data, UINTN size)
{
	return flash_into_esp(data, size, L"ifwi.bin");
}

#define MBR_CODE_SIZE	440
static EFI_STATUS flash_mbr(VOID *data, UINTN size)
{
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;

	if (size > MBR_CODE_SIZE)
		return EFI_INVALID_PARAMETER;

	ret = gpt_get_root_disk(&gparti, EMMC_USER_PART);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to get disk information");
		return ret;
	}

	ret = uefi_call_wrapper(gparti.dio->WriteDisk, 5, gparti.dio,
				gparti.bio->Media->MediaId, 0, size, data);
	if (EFI_ERROR(ret))
		efi_perror(ret, "Failed to flash MBR");

	return ret;
}

static EFI_STATUS flash_zimage(VOID *data, UINTN size)
{
	struct boot_img_hdr *bootimage, *new_bootimage;
	VOID *new_cur, *cur;
	UINTN new_size, partlen;
	EFI_STATUS ret;

	ret = gpt_get_partition_by_label(L"boot", &gparti, EMMC_USER_PART);
	if (EFI_ERROR(ret)) {
		error(L"Unable to get information on the boot partition");
		return ret;
	}

	partlen = (gparti.part.ending_lba + 1 - gparti.part.starting_lba)
		* gparti.bio->Media->BlockSize;
	bootimage = AllocatePool(partlen);
	if (!bootimage) {
		error(L"Unable to allocate bootimage buffer");
		return EFI_OUT_OF_RESOURCES;
	}

	ret = uefi_call_wrapper(gparti.dio->ReadDisk, 5, gparti.dio,
				gparti.bio->Media->MediaId,
				gparti.part.starting_lba * gparti.bio->Media->BlockSize,
				partlen, bootimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to load the current bootimage");
		goto out;
	}

	if (strncmpa((CHAR8 *)BOOT_MAGIC, bootimage->magic, BOOT_MAGIC_SIZE)) {
		error(L"boot partition does not contain a valid bootimage");
		ret = EFI_UNSUPPORTED;
		goto out;
	}

	new_size = bootimage_size(bootimage) - bootimage->kernel_size
		+ pagealign(bootimage, size);
	if (new_size > partlen) {
		error(L"Kernel image is too large to fit in the boot partition");
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	new_bootimage = AllocateZeroPool(new_size);
	if (!new_bootimage) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	/* Create the new bootimage. */
	memcpy((VOID *)new_bootimage, bootimage, bootimage->page_size);

	new_bootimage->kernel_size = size;
	new_bootimage->kernel_addr = bootimage->kernel_addr;
	new_cur = (VOID *)new_bootimage + bootimage->page_size;
	memcpy(new_cur, data, size);

	new_cur += pagealign(new_bootimage, size);
	cur = (VOID *)bootimage + bootimage->page_size
		+ pagealign(bootimage, bootimage->kernel_size);
	memcpy(new_cur, cur, bootimage->ramdisk_size);

	new_cur += pagealign(new_bootimage, new_bootimage->ramdisk_size);
	cur += pagealign(bootimage, bootimage->ramdisk_size);
	memcpy(new_cur, cur, bootimage->second_size);

	/* Flash new the bootimage. */
	cur_offset = gparti.part.starting_lba * gparti.bio->Media->BlockSize;
	ret = flash_write(new_bootimage, new_size);

	FreePool(new_bootimage);

 out:
	FreePool(bootimage);
	return ret;
}

static struct label_exception {
	CHAR16 *name;
	EFI_STATUS (*flash_func)(VOID *data, UINTN size);
} LABEL_EXCEPTIONS[] = {
	{ L"gpt", flash_gpt },
	{ L"keystore", flash_keystore },
	{ L"efirun", flash_efirun },
	{ L"sfu", flash_sfu },
	{ L"ifwi", flash_ifwi },
	{ L"mbr", flash_mbr },
	{ L"oemvars", flash_oemvars },
	{ L"zimage", flash_zimage }
};

EFI_STATUS flash(VOID *data, UINTN size, CHAR16 *label)
{
	CHAR16 *esp = L"/ESP/";
	UINTN i;
	EFI_STATUS ret;

	/* special case for writing inside esp partition */
	if (!StrnCmp(esp, label, StrLen(esp)))
		return flash_into_esp(data, size, &label[ARRAY_SIZE(esp)]);

	/* special cases */
	for (i = 0; i < ARRAY_SIZE(LABEL_EXCEPTIONS); i++)
		if (!StrCmp(LABEL_EXCEPTIONS[i].name, label))
			return LABEL_EXCEPTIONS[i].flash_func(data, size);

	ret = gpt_get_partition_by_label(label, &gparti, EMMC_USER_PART);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to get partition %s", label);
		return ret;
	}

	cur_offset = gparti.part.starting_lba * gparti.bio->Media->BlockSize;

	if (is_sparse_image(data, size))
		ret = flash_sparse(data, size);
	else
		ret = flash_write(data, size);

	if (EFI_ERROR(ret))
		return ret;

	if (!CompareGuid(&gparti.part.type, &EfiPartTypeSystemPartitionGuid))
		return gpt_refresh();

	return EFI_SUCCESS;
}

EFI_STATUS flash_file(EFI_HANDLE image, CHAR16 *filename, CHAR16 *label)
{
	EFI_STATUS ret;
	EFI_FILE_IO_INTERFACE *io = NULL;
	VOID *buffer = NULL;
	UINTN size = 0;

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, image, &FileSystemProtocol, (void *)&io);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to get FileSystemProtocol");
		goto out;
	}

	ret = uefi_read_file(io, filename, &buffer, &size);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to read file %s", filename);
		goto out;
	}

	ret = flash(buffer, size, label);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to flash file %s on partition %s", filename, label);
		goto free_buffer;
	}

free_buffer:
	FreePool(buffer);
out:
	return ret;

}

#define SDIO_DFLT_TIMEOUT 3000
#define CARD_ADDRESS (1 << 16)
EFI_STATUS secure_erase(EFI_SD_HOST_IO_PROTOCOL *sdio, UINT64 start, UINT64 end, UINTN timeout)
{
	CARD_STATUS status;
	EFI_STATUS ret;

	debug(L"Secure erase lba %ld -> %ld", start, end);

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, ERASE_GROUP_START, start, NoData, NULL, 0, ResponseR1, SDIO_DFLT_TIMEOUT, (UINT32 *) &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed set start erase");
		return ret;
	}

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, ERASE_GROUP_END, end, NoData, NULL, 0, ResponseR1, SDIO_DFLT_TIMEOUT, (UINT32 *) &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed set end erase");
		return ret;
	}

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, ERASE, 0x80000000, NoData, NULL, 0, ResponseR1, timeout, (UINT32 *) &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Secure Erase Failed");
		return ret;
	}

	do {
		uefi_call_wrapper(BS->Stall, 1, 100000);
		ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, SEND_STATUS, CARD_ADDRESS, NoData, NULL, 0, ResponseR1, SDIO_DFLT_TIMEOUT, (UINT32 *) &status);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, "failed get status");
			return ret;
		}
	} while (!status.READY_FOR_DATA);
	debug(L"Secure erase success");
	return ret;
}

static EFI_STATUS fill_with(EFI_BLOCK_IO *bio, UINT64 start, UINT64 end,
			    VOID *pattern, UINTN pattern_blocks)
{
	UINT64 lba;
	UINT64 size;
	EFI_STATUS ret;

	debug(L"Fill lba %d -> %d", start, end);
	for (lba = start; lba <= end; lba += pattern_blocks) {
		if (lba + pattern_blocks > end + 1)
			size = end - lba + 1;
		else
			size = pattern_blocks;

		ret = uefi_call_wrapper(bio->WriteBlocks, 5, bio, bio->Media->MediaId, lba, bio->Media->BlockSize * size, pattern);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, "Failed to erase block %ld", lba);
			goto exit;
		}
	}
	ret = EFI_SUCCESS;

 exit:
	return ret;
}

/* It is faster to erase multiple block at once
 * 4096 * 512 => 2MB
 */
#define N_BLOCK (4096)
static EFI_STATUS fill_zero(EFI_BLOCK_IO *bio, UINT64 start, UINT64 end)
{
	EFI_STATUS ret;
	VOID *emptyblock;

	emptyblock = AllocateZeroPool(bio->Media->BlockSize * N_BLOCK);
	if (!emptyblock)
		return EFI_OUT_OF_RESOURCES;

	ret = fill_with(bio, start, end, emptyblock, N_BLOCK);

	FreePool(emptyblock);

	return ret;
}

static EFI_STATUS get_mmc_info(EFI_SD_HOST_IO_PROTOCOL *sdio, UINTN *erase_grp_size, UINTN *timeout)
{
	EXT_CSD *ext_csd;
	void *rawbuffer;
	UINTN offset;
	UINT32 status;
	EFI_STATUS ret;

	/* ext_csd pointer must be aligned to a multiple of sdio->HostCapability.BoundarySize
	 * allocate twice the needed size, and compute the offset to get an aligned buffer
	 */
	rawbuffer = AllocateZeroPool(2 * sdio->HostCapability.BoundarySize);
	if (!rawbuffer)
		return EFI_OUT_OF_RESOURCES;

	offset = (UINTN) rawbuffer & (sdio->HostCapability.BoundarySize - 1);
	offset = sdio->HostCapability.BoundarySize - offset;
	ext_csd = (EXT_CSD *) ((CHAR8 *)rawbuffer + offset);

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, SEND_EXT_CSD, CARD_ADDRESS, InData, (void *)ext_csd, sizeof(EXT_CSD), ResponseR1, SDIO_DFLT_TIMEOUT, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "failed get ext_csd");
		goto out;
	}

	/* Erase group size is 512Kbyte × HC_ERASE_GRP_SIZE
	 * so it's 1024 x HC_ERASE_GRP_SIZE in sector count
	 * timeout is 300ms x ERASE_TIMEOUT_MULT per erase group*/
	*erase_grp_size = 1024 * ext_csd->HC_ERASE_GRP_SIZE;
	*timeout = 300 * ext_csd->ERASE_TIMEOUT_MULT;

	debug(L"eMMC parameter: erase grp size %d sectors, timeout %d ms", *erase_grp_size, *timeout);

out:
	FreePool(rawbuffer);
	return ret;
}

EFI_STATUS erase_blocks(EFI_BLOCK_IO *bio, UINT64 start, UINT64 end)
{
	EFI_SD_HOST_IO_PROTOCOL *sdio;
	EFI_STATUS ret;
	UINTN erase_grp_size;
	UINTN timeout;
	UINT64 reminder;
	/* UINT64 size; */

	/* size in MB for debug */
	/* size = (bio->Media->BlockSize * (end - start + 1)) / MiB; */
	/* debug("Erasing partition start %ld end %ld Size %ld MB", start, end, size); */

	/* check if we can use secure erase command */
	ret = LibLocateProtocol(&gEfiSdHostIoProtocolGuid, (void **)&sdio);
	if (EFI_ERROR(ret)) {
		debug(L"failed to get sdio protocol, fallback to filling with zeros");
		goto fallback;
	}
	ret = get_mmc_info(sdio, &erase_grp_size, &timeout);
	if (EFI_ERROR(ret)) {
		debug(L"failed to get mmc parameter, fallback to filling with zeros");
		goto fallback;
	}
	if ((end - start + 1) < erase_grp_size)
		goto fallback;

	reminder = start % erase_grp_size;
	if (reminder) {
		ret = fill_zero(bio, start, start + erase_grp_size - reminder - 1);
		if (EFI_ERROR(ret)) {
			error(L"failed to fill with zeros");
			return ret;
		}
		start += erase_grp_size - reminder;
	}

	reminder = (end + 1) % erase_grp_size;
	if (reminder) {
		ret = fill_zero(bio, end + 1 - reminder, end);
		if (EFI_ERROR(ret)) {
			error(L"failed to fill with zeros");
			return ret;
		}
		end -= reminder;
	}
	timeout = timeout * ((end + 1 - start) / erase_grp_size);
	return secure_erase(sdio, start, end, timeout);

fallback:
	return fill_zero(bio, start, end);
}

EFI_STATUS erase_by_label(CHAR16 *label)
{
	EFI_STATUS ret;

	if (!StrCmp(L"keystore", label))
		return set_user_keystore(NULL, 0);

	ret = gpt_get_partition_by_label(label, &gparti, EMMC_USER_PART);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to get partition %s", label);
		return ret;
	}
	ret = erase_blocks(gparti.bio, gparti.part.starting_lba, gparti.part.ending_lba);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to erase partition %s", label);
		return ret;
	}
	if (!CompareGuid(&gparti.part.type, &EfiPartTypeSystemPartitionGuid))
		return gpt_refresh();

	return EFI_SUCCESS;
}

static EFI_STATUS generate_random_number_chunk(VOID *chunk, UINTN size)
{
	EFI_STATUS ret;
	EFI_TIME time;
	UINTN i;

	/* Initialize OpenSSL Random number generator.  */
#define ENTROPY_NEEDED 32
	ret = uefi_call_wrapper(RT->GetTime, 2, &time, NULL);
	if (ret != EFI_SUCCESS)
		return ret;

	UINT64 seed = ((UINT64)time.Year << 48) | ((UINT64)time.Month << 40) |
		((UINT64)time.Day << 32) | ((UINT64)time.Hour << 24) |
		((UINT64)time.Minute << 16) | ((UINT64)time.Second << 8) |
		((UINT64)time.Daylight);

	for (i = 0; i <= (ENTROPY_NEEDED / sizeof(seed)) + 1; i++)
		RAND_seed(&seed, sizeof(seed));

	if (RAND_status() != 1) {
		error(L"OpenSSL Random number generator initialization failed");
		return EFI_NOT_READY;
	}

	if (RAND_bytes(chunk, size) != 1) {
		error(L"Failed to generate buffer of random numbers");
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}

EFI_STATUS garbage_disk(void)
{
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;
	VOID *chunk;
	UINTN size;

	ret = gpt_get_root_disk(&gparti, EMMC_USER_PART);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to get disk information");
		return ret;
	}

	size = gparti.bio->Media->BlockSize * N_BLOCK;
	chunk = AllocatePool(size);
	if (!chunk) {
		error(L"Unable to allocate the garbage chunk");
		return EFI_OUT_OF_RESOURCES;
	}

	ret = generate_random_number_chunk(chunk, size);
	if (EFI_ERROR(ret)) {
		FreePool(chunk);
		return ret;
	}

	ret = fill_with(gparti.bio, gparti.part.starting_lba,
			gparti.part.ending_lba, chunk, N_BLOCK);

	FreePool(chunk);
	return gpt_refresh();
}
