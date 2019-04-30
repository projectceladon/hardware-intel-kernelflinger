/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Author: Haoyu Tang <haoyu.tang@intel.com>
 *         Chen, ZhiminX <zhiminx.chen@intel.com>
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
#include <efiapi.h>
#include <lib.h>
#include <vars.h>
#include <byteswap.h>
#include <stdlib.h>

#include "log.h"
#include "acpi.h"
#include "slot.h"
#include "gpt.h"
#include "dt_table.h"
#include "protocol/AcpiTableProtocol.h"
#include "security.h"
#include "targets.h"

static struct ACPI_TABLE_LOADED {
	UINTN index[ACPI_TABLE_MAX_LOAD_NUM];
	UINT32 count;
} loaded_table;

static CHAR8 loaded_idx_str[ACPI_TABLE_MAX_LOAD_NUM*4];

static enum boot_target acpi_target = UNKNOWN_TARGET;

VOID acpi_set_boot_target(enum boot_target target)
{
	acpi_target = target;
}

static enum boot_target acpi_get_boot_target(VOID)
{
	return acpi_target;
}

static UINT8 acpi_csum(VOID *base, UINT32 n)
{
	UINT8 *p;
	UINT8 sum;

	p = (UINT8 *)base;

	sum = 0;
	for (UINT32 i = 0; i < n; i++) {
		sum += *p;
		p++;
	}

	return sum;
}

EFI_STATUS acpi_image_get_length(const CHAR16 *label, struct ACPI_INFO **acpi_info)
{
	UINT32 MediaId;
	EFI_STATUS ret;
	struct dt_table_header aosp_header;
	UINT32 magic, total_size;
	UINT64 partition_size;
	UINT64 partition_start;
	struct ACPI_INFO *current_acpi;
	struct gpt_partition_interface gpart;

	ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Partition %s not found", label);
		return ret;
	}
	MediaId = gpart.bio->Media->MediaId;
	partition_start = gpart.part.starting_lba * gpart.bio->Media->BlockSize;
	partition_size = (gpart.part.ending_lba + 1 - gpart.part.starting_lba) *
		gpart.bio->Media->BlockSize;
	debug(L"Reading %s image header", label);
	ret = uefi_call_wrapper(gpart.dio->ReadDisk, 5, gpart.dio, MediaId,
				partition_start, sizeof(aosp_header), &aosp_header);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"ReadDisk (%s_header)", label);
		return ret;
	}

	magic = bswap_32(aosp_header.magic);
	total_size = bswap_32(aosp_header.total_size);
	if (magic != ACPI_TABLE_MAGIC) {
		error(L"This partition has no ACPI image, the magic is: 0x%x", magic);
		return EFI_INVALID_PARAMETER;
	}

	current_acpi = AllocatePool(sizeof(struct ACPI_INFO));
	if (!current_acpi) {
		error(L"Alloc memory for %s ACPI_INFO failed", label);
		return EFI_OUT_OF_RESOURCES;
	}

#if defined(USE_AVB) && defined(USE_ACPIO) && defined(USE_ACPI)
	/*
	  If AVB case, get the image length from mixins' definition.
	 */
	if (!StrnCmp(label, L"acpio_", 6))
		(*current_acpi).img_size = BOARD_ACPIOIMAGE_PARTITION_SIZE;
	else if (!StrnCmp(label, L"acpi_", 5))
		(*current_acpi).img_size = BOARD_ACPIIMAGE_PARTITION_SIZE;
	else {
		error(L"%s is not acpio or acpi", label);
		FreePool(current_acpi);
		return EFI_INVALID_PARAMETER;
	}

	if ((*current_acpi).img_size > partition_size) {
		error(L"%s image is larger than partition size", label);
		FreePool(current_acpi);
		return EFI_INVALID_PARAMETER;
	}
#else
	(*current_acpi).img_size = total_size;
	if (((*current_acpi).img_size + BOOT_SIGNATURE_MAX_SIZE) > partition_size) {
		error(L"%s image is larger than partition size", label);
		FreePool(current_acpi);
		return EFI_INVALID_PARAMETER;
	}
#endif

	(*current_acpi).MediaId = MediaId;
	(*current_acpi).partition_start = partition_start;
	(*current_acpi).partition_size = partition_size;
	*acpi_info = current_acpi;
	return EFI_SUCCESS;
}

static EFI_STATUS acpi_image_load_partition(const CHAR16 *label, VOID **image)
{
	EFI_STATUS ret;
	struct gpt_partition_interface gpart;
	VOID *acpiimage;
	struct ACPI_INFO *acpi_info;

	ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Partition %s not found", label);
		return ret;
	}
	ret = acpi_image_get_length(label, &acpi_info);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Partition %s can't get size", label);
		return ret;
	}

	acpiimage = AllocatePool((*acpi_info).img_size);
	if (!acpiimage) {
		error(L"Alloc memory for %s image failed", label);
		FreePool(acpi_info);
		return EFI_OUT_OF_RESOURCES;
	}
	debug(L"Reading %s image: %d bytes", label, (*acpi_info).img_size);
	ret = uefi_call_wrapper(gpart.dio->ReadDisk, 5, gpart.dio, (*acpi_info).MediaId,
				(*acpi_info).partition_start, (*acpi_info).img_size, acpiimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"ReadDisk Error for %s image read", label);
		FreePool(acpi_info);
		FreePool(acpiimage);
		return ret;
	}
	*image = acpiimage;
	FreePool(acpi_info);
	return EFI_SUCCESS;
}

EFI_STATUS install_acpi_table(VOID *acpi_table, UINTN acpi_table_size,
			      UINTN *tablekey)
{
	EFI_STATUS ret;
	struct _EFI_ACPI_TABLE_PROTOCOL *acpiprotocol = NULL;
	EFI_GUID guid = EFI_ACPI_TABLE_PROTOCOL_GUID;

	ret = LibLocateProtocol(&guid, (VOID **)&acpiprotocol);
	if (EFI_ERROR(ret) || !acpiprotocol) {
		efi_perror(ret, L"LibLocateProtocol: Failed by guid of acpi");
		return ret;
	}

	ret = uefi_call_wrapper(acpiprotocol->InstallAcpiTable, 4, acpiprotocol,
				acpi_table, acpi_table_size, tablekey);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to install acpi table");
		return ret;
	}

	return ret;
}

static VOID acpi_add_table_index(UINTN index)
{
	if (loaded_table.count < ACPI_TABLE_MAX_LOAD_NUM) {
		loaded_table.index[loaded_table.count] = index;
		loaded_table.count++;
	}
}

CHAR8 *acpi_loaded_table_idx_to_string(VOID)
{
	if (loaded_table.count > 0)
		efi_snprintf(loaded_idx_str, sizeof(loaded_idx_str),
			     (CHAR8 *)"%d", loaded_table.index[0]);

	for (UINT32 i = 1; i < loaded_table.count; ++i) {
		efi_snprintf(loaded_idx_str, sizeof(loaded_idx_str),
			     (CHAR8 *)"%a,%d", loaded_idx_str,
			     loaded_table.index[i]);
	}

	return loaded_idx_str;
}

static EFI_STATUS acpi_image_parse_table(VOID *acpiimage, int is_acpio)
{
	struct dt_table_header *header = (struct dt_table_header *)(acpiimage);
	struct dt_table_entry *entry;
	struct ACPI_DESC_HEADER *acpi_header;
	VOID *acpi_table;
	UINTN dt_size, dt_offset, tablekey;

	UINT32 entry_size = bswap_32(header->dt_entry_size);
	UINT32 entry_offset = bswap_32(header->dt_entries_offset);
	UINT32 entry_count = bswap_32(header->dt_entry_count);
	EFI_STATUS ret;

	for (UINT32 i = 0; i < entry_count; i++, entry_offset += entry_size) {
		entry = (struct dt_table_entry *)(acpiimage + entry_offset);

		dt_size = bswap_32(entry->dt_size);
		dt_offset = bswap_32(entry->dt_offset);
		if (dt_size == 0 || dt_offset == 0)
			continue;

		acpi_table = acpiimage + dt_offset;
		acpi_header = (struct ACPI_DESC_HEADER *)(acpi_table);
		debug(L"acpi table info: magic=0x%08x, size=%d",
		      *(UINT32 *)(acpi_header), acpi_header->length);
		if (acpi_csum(acpi_table, dt_size))
			continue;

		ret = install_acpi_table(acpi_table, dt_size, &tablekey);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Warning: acpi_table %d install failed.", i);
			continue;
		}

		if (is_acpio)
			acpi_add_table_index(i);
	}

	return EFI_SUCCESS;
}

static EFI_STATUS install_acpi_image_from_partition(int is_acpio)
{
	EFI_STATUS ret = EFI_SUCCESS;
	const CHAR16 *acpi_label;

	if (is_acpio)
		acpi_label = slot_label(ACPIO_LABEL);
	else
		acpi_label = slot_label(ACPI_LABEL);

	VOID *acpiimage = NULL;

	ret = acpi_image_load_partition(acpi_label, &acpiimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to load image from %s partition",
			   acpi_label);
		return ret;
	}
	ret = acpi_image_parse_table(acpiimage, is_acpio);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to install acpi table from %s image",
			   acpi_label);
		return ret;
	}
	FreePool(acpiimage);

	return ret;
}

static EFI_STATUS check_install_acpi_image(VOID *image, int is_acpio)
{
	EFI_STATUS ret = EFI_SUCCESS;
	struct dt_table_header *aosp_header;
	UINT32 magic;

	aosp_header = (struct dt_table_header *)image;
	magic = bswap_32(aosp_header->magic);
	if (magic != ACPI_TABLE_MAGIC)
		return EFI_SUCCESS;

	ret = acpi_image_parse_table(image, is_acpio);
	if (EFI_ERROR(ret))
		return ret;

	return EFI_SUCCESS;
}

/*
 * | acpi | acpio | 1stMnt | slotAB | bootMode |                 do                 |
 * |  0   |   0   |   0    |   -    |     -    | Nothing                            |
 * |  0   |   0   |   1    |   -    |   boot   | inst(firststage_mnt_ssdt)          |
 * |  0   |   0   |   1    |   -    | recovery | Nothing                            |
 * |  0   |   1   |   -    |   -    |   boot   | inst(acpio)                        |
 * |  0   |   1   |   -    |   0    | recovery | inst(recovery_acpio)               |
 * |  0   |   1   |   -    |   1    | recovery | Nothing                            |
 * |  1   |   0   |   -    |   -    |     -    | inst(acpi)                         |
 * |  1   |   1   |   -    |   -    |   boot   | inst(acpi) && inst(acpio)          |
 * |  1   |   1   |   -    |   0    | recovery | inst(acpi) && inst(recovery_acpio) |
 * |  1   |   1   |   -    |   1    | recovery | inst(acpi)                         |
 */
EFI_STATUS install_acpi_table_from_partitions(VOID *image,
					      const char *part_name)
{
	int is_acpio;
	enum boot_target target;

	target = acpi_get_boot_target();

	if (!strcmp(part_name, "acpi")) {
		is_acpio = 0;
	} else if (!strcmp(part_name, "acpio")) {
		is_acpio = 1;
		if (target == RECOVERY)
			return EFI_SUCCESS;
	} else {
		error(L"Acpi table from partition %a not installed", part_name);
		return EFI_NOT_FOUND;
	}

	debug(L"Install acpi table from %a-partition", part_name);
	if (image == NULL)
		return install_acpi_image_from_partition(is_acpio);
	else
		return check_install_acpi_image(image, is_acpio);
}

EFI_STATUS install_acpi_table_from_recovery_acpio(VOID *image)
{
	enum boot_target target;

	target = acpi_get_boot_target();

	if (!use_slot()) {
		if (target == RECOVERY) {
			debug(L"Install acpi table from recovery_acpio");
			return check_install_acpi_image(image, 1);
		}
	}

	debug(L"recovery_acpio not loaded, target=%d", target);
	return EFI_SUCCESS;
}

