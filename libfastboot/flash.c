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
#include <keystore.h>
#include <fastboot.h>
#include "uefi_utils.h"
#include "gpt.h"
#include "gpt_bin.h"
#include "flash.h"
#include "SdHostIo.h"
#include "Mmc.h"
#include "sparse.h"

#define KEYSTORE_VAR L"KeyStore"

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

	ret = gpt_create(gb_hdr->start_lba, gb_hdr->npart, gb_part);
	if (EFI_ERROR(ret))
		return ret;

	return (EFI_SUCCESS | REFRESH_PARTITION_VAR);
}

static EFI_STATUS flash_keystore(VOID *data, UINTN size)
{
	EFI_STATUS ret;

	if (size) {
		struct keystore *ks = get_keystore(data, size);

		if (!ks) {
			error(L"keystore data is invalid");
			return EFI_INVALID_PARAMETER;
		}

		free_keystore(ks);
	}

	ret = set_efi_variable(&fastboot_guid, KEYSTORE_VAR,
			       size, data, TRUE, FALSE);
	if (ret)
		efi_perror(ret, "Coudn't modify KeyStore");

	return ret;
}

EFI_STATUS flash(VOID *data, UINTN size, CHAR16 *label)
{
	CHAR16 *esp = L"/ESP/";
	CHAR16 *gpt = L"gpt";
	CHAR16 *keystore = L"keystore";
	EFI_STATUS ret;

	/* special case for writing inside esp partition */
	if (!StrnCmp(esp, label, StrLen(esp)))
		return flash_into_esp(data, size, &label[ARRAY_SIZE(esp)]);

	/* special case for writing gpt partition table */
	if (!StrCmp(gpt, label))
		return flash_gpt(data, size);

	/* Special case for writing keystore */
	if (!StrCmp(keystore, label))
		return flash_keystore(data, size);

	ret = gpt_get_partition_by_label(label, &gparti);
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

/* It is faster to erase multiple block at once
 * 4096 * 512 => 2MB
 */
#define N_BLOCK (4096)
EFI_STATUS fill_zero(EFI_BLOCK_IO *bio, UINT64 start, UINT64 end)
{
	UINT64 lba;
	UINT64 size;
	VOID *emptyblock;
	EFI_STATUS ret;

	debug(L"Erase lba %d -> %d", start, end);
	emptyblock = AllocateZeroPool(bio->Media->BlockSize * N_BLOCK);
	if (!emptyblock)
		return EFI_OUT_OF_RESOURCES;

	for (lba = start; lba <= end; lba += N_BLOCK) {
		if (lba + N_BLOCK > end + 1)
			size = end - lba + 1;
		else
			size = N_BLOCK;

		ret = uefi_call_wrapper(bio->WriteBlocks, 5, bio, bio->Media->MediaId, lba, bio->Media->BlockSize * size, emptyblock);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, "Failed to erase block %ld", lba);
			goto free_block;
		}
	}
	ret = EFI_SUCCESS;

free_block:
	FreePool(emptyblock);
	return ret;
}

EFI_STATUS get_mmc_info(EFI_SD_HOST_IO_PROTOCOL *sdio, UINTN *erase_grp_size, UINTN *timeout)
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

	ret = gpt_get_partition_by_label(label, &gparti);
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
