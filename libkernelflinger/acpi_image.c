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

static struct ACPI_TABLE_SELECTED {
	UINTN id[ACPI_TABLE_MAX_SELECTED_NUM];
	UINT32 count;
} selected_table;

static CHAR8 selected_ids_str[ACPI_TABLE_MAX_SELECTED_NUM*8];

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

static EFI_STATUS acpi_image_load_partition(const CHAR16 *label, VOID **image)
{
	UINT32 MediaId;
	UINT32 img_size;
	EFI_STATUS ret;
	struct gpt_partition_interface gpart;
	UINTN partition_start;
	UINTN partition_size;
	VOID *acpiimage;
	struct dt_table_header aosp_header;
	UINT32 magic, total_size;

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

	img_size = total_size + BOOT_SIGNATURE_MAX_SIZE;
	if (img_size > partition_size) {
		error(L"%s image is larger than partition size", label);
		return EFI_INVALID_PARAMETER;
	}
	acpiimage = AllocatePool(img_size);
	if (!acpiimage) {
		error(L"Alloc memory for %s image failed", label);
		return EFI_OUT_OF_RESOURCES;
	}

	debug(L"Reading %s image: %d bytes", label, img_size);
	ret = uefi_call_wrapper(gpart.dio->ReadDisk, 5, gpart.dio, MediaId,
				partition_start, img_size, acpiimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"ReadDisk Error for %s image read", label);
		FreePool(acpiimage);
		return ret;
	}
	*image = acpiimage;
	return EFI_SUCCESS;
}

EFI_STATUS install_acpi_table(VOID *acpi_table, UINTN acpi_table_size,
			      UINTN *tablekey)
{
	EFI_STATUS ret;
	struct _EFI_ACPI_TABLE_PROTOCOL *acpiprotocol = NULL;
	EFI_GUID guid = EFI_ACPI_TABLE_PROTOCOL_GUID;

	ret = LibLocateProtocol(&guid, (VOID **)&acpiprotocol);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"LibLocateProtocol: Failed by guid of acpi");
		return ret;
	}

	ret = uefi_call_wrapper(acpiprotocol->InstallAcpiTable, 4, acpiprotocol,
				acpi_table, acpi_table_size, tablekey);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"ACPI: Failed to install acpi table");
		return ret;
	}

	return ret;
}

EFI_STATUS acpi_parse_selected_table_id(CHAR8 *id_str, UINT32 id_str_len)
{
	CHAR8 *str, *nptr, *endptr;
	UINT32 i;

	str = AllocateZeroPool(id_str_len + 1);
	if (!str) {
		error(L"Alloc memory for acpi selected table id failed");
		return EFI_OUT_OF_RESOURCES;
	}
	strncpy(str, id_str, id_str_len);

	i = 0;
	nptr = str;
	while (i < ACPI_TABLE_MAX_SELECTED_NUM) {
		selected_table.id[i++] = strtoul((char *)nptr, (char **)&endptr, 16);

		if (*endptr == ',') {
			nptr = endptr + 1;
			continue;
		}
		if (*endptr == '\0')
			break;

		FreePool(str);
		return EFI_INVALID_PARAMETER;
	}
	selected_table.count = i;

	FreePool(str);
	return EFI_SUCCESS;
}

static int acpi_is_selected_table_id(UINTN id)
{
	acpi_parse_selected_table_id("0x0,0x123", 9); // I'm hard code, remove me

	for (UINT32 i = 0; i < selected_table.count; ++i) {
		if (id == selected_table.id[i])
			return 0;
	}
	return -1;
}

CHAR8 *acpi_selected_table_ids_to_string(VOID)
{
	if (selected_table.count > 0)
		efi_snprintf(selected_ids_str, sizeof(selected_ids_str),
			     (CHAR8 *)"0x%x", selected_table.id[0]);

	for (UINT32 i = 1; i < selected_table.count; ++i) {
		efi_snprintf(selected_ids_str, sizeof(selected_ids_str),
			     (CHAR8 *)"%a,0x%x", selected_ids_str,
			     selected_table.id[i]);
	}

	return selected_ids_str;
}

static EFI_STATUS acpi_image_parse_table(VOID *acpiimage)
{
	struct dt_table_header *header = (struct dt_table_header *)(acpiimage);
	struct dt_table_entry *entry;
	struct ACPI_DESC_HEADER *acpi_header;
	VOID *acpi_table;
	UINTN dt_size, dt_offset, id, tablekey;

	UINT32 entry_size = bswap_32(header->dt_entry_size);
	UINT32 entry_offset = bswap_32(header->dt_entries_offset);
	UINT32 entry_count = bswap_32(header->dt_entry_count);
	EFI_STATUS ret;

	for (UINT32 i = 0; i < entry_count; i++) {
		entry = (struct dt_table_entry *)(acpiimage + entry_offset);

		id = bswap_32(entry->id);
		if (acpi_is_selected_table_id(id) < 0)
			continue;

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
			efi_perror(ret, L"Failed to install acpi table");
			return ret;
		}

		entry_offset += entry_size;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS install_acpi_image_from_partition(CHAR16 *label)
{
	EFI_STATUS ret = EFI_SUCCESS;
	const CHAR16 *acpi_label = slot_label(label);

	VOID *acpiimage = NULL;

	ret = acpi_image_load_partition(acpi_label, &acpiimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to load image from %s partition",
			   acpi_label);
		return ret;
	}
	ret = acpi_image_parse_table(acpiimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to install acpi table from %s image",
				   acpi_label);
		return ret;
	}
	FreePool(acpiimage);

	return ret;
}

static EFI_STATUS check_install_acpi_image(VOID *image)
{
	EFI_STATUS ret = EFI_SUCCESS;
	struct dt_table_header *aosp_header;
	UINT32 magic;

	aosp_header = (struct dt_table_header *)image;
	magic = bswap_32(aosp_header->magic);
	if (magic != ACPI_TABLE_MAGIC)
		return EFI_SUCCESS;

	ret = acpi_image_parse_table(image);
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
static EFI_STATUS install_table_from_acpi_partition(VOID *image)
{
	debug(L"Install acpi table from acpi-partition");
	if (image == NULL)
		return install_acpi_image_from_partition(ACPI_LABEL);
	else
		return check_install_acpi_image(image);

	debug(L"Acpi table from acpi-partition not installed");
	return EFI_SUCCESS;
}

static EFI_STATUS install_table_from_acpio_partition(VOID *image,
						     enum boot_target target)
{
	if (target != RECOVERY) {
		debug(L"Install acpi table from acpio-partition, target=%d", target);
		if (image == NULL)
			return install_acpi_image_from_partition(ACPIO_LABEL);
		else
			return check_install_acpi_image(image);
	}

	debug(L"Acpi table from acpio-partition not installed, target=%d", target);
	return EFI_SUCCESS;
}

EFI_STATUS install_acpi_table_from_partitions(VOID *image,
					      const char *part_name,
					      enum boot_target target)
{
	if (!strcmp(part_name, "acpi")) {
		return install_table_from_acpi_partition(image);
	} else if (!strcmp(part_name, "acpio")) {
		return install_table_from_acpio_partition(image, target);
	}

	error(L"Acpi table from partition %s not installed", part_name);
	return EFI_NOT_FOUND;
}

EFI_STATUS install_acpi_table_from_recovery_acpio(VOID *image, enum boot_target target)
{
	if (!use_slot()) {
		if (target == RECOVERY) {
			debug(L"Install acpi table from recovery_acpio");
			return check_install_acpi_image(image);
		}
	}

	debug(L"recovery_acpio not loaded, target=%d", target);
	return EFI_SUCCESS;
}

