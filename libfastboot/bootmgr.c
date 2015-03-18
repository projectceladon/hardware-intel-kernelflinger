/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jeremy Compostella <jeremy.compostella@intel.com>
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

#include <lib.h>

#include "gpt.h"
#include "bootmgr.h"

#define BOOTOPTION_LEN 8

typedef struct {
	UINT32		attributes;
	UINT16		file_path_list_length;
	CHAR16		description[1]; /* variable length field */
	EFI_DEVICE_PATH file_path_list[1]; /* variable length field */
} __attribute__((packed)) EFI_LOAD_OPTION;

static EFI_STATUS find_free_entry(CHAR16 *entry)
{
	EFI_STATUS ret;
	CHAR8 data;
	CHAR16 name[BOOTOPTION_LEN + 1];
	UINTN i, len, size;
        UINT32 flags;

	for (i = 0; i <= 0xFFFF; i++) {
		len = SPrint(name, sizeof(name), VarBootOption, i);
		if (len != BOOTOPTION_LEN) {
			error(L"Failed to format load option variable name");
			return EFI_UNSUPPORTED;
		}
		size = sizeof(data);
		ret = uefi_call_wrapper(RT->GetVariable, 5, name, &EfiGlobalVariable,
					&flags, &size, &data);
		if (ret == EFI_NOT_FOUND) {
			*entry = i;
			return EFI_SUCCESS;
		}
		if (ret == EFI_BUFFER_TOO_SMALL)
			continue;
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to read '%s' variable", name);
			return ret;
		}
	}

	return EFI_NOT_FOUND;
}

static EFI_STATUS find_load_option_entry(CHAR16 *description, CHAR16 *entry)
{
	EFI_STATUS ret;
	UINTN bufsize, namesize;
	CHAR16 *name;
	EFI_GUID guid;
	CHAR8 number[5];
	UINTN size;
	EFI_LOAD_OPTION *load_option;
	UINT32 flags;

	bufsize = 64;		/* Initial size large enough to handle
				   usual variable names length and
				   avoid the ReallocatePool as much as
				   possible.  */
	name = AllocateZeroPool(bufsize);
	if (!name) {
		error(L"Failed to re-allocate variable name buffer");
		return EFI_OUT_OF_RESOURCES;
	}

	for (;;) {
		namesize = bufsize;
		ret = uefi_call_wrapper(RT->GetNextVariableName, 3, &namesize,
					name, &guid);
		if (ret == EFI_NOT_FOUND)
			break;
		if (ret == EFI_BUFFER_TOO_SMALL) {
			name = ReallocatePool(name, bufsize, namesize);
			if (!name) {
				error(L"Failed to re-allocate variable name buffer");
				return EFI_OUT_OF_RESOURCES;
			}
			bufsize = namesize;
			continue;
		}
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"GetNextVariableName failed");
			goto exit;
		}
		if (memcmp(&EfiGlobalVariable, &guid, sizeof(guid)))
			continue;
		if (!(StrLen(name) == StrLen(L"Boot0000") &&
		      !memcmp(L"Boot", name, StrLen(L"Boot") * sizeof(CHAR16)) &&
		      name[4] >= '0' && name[4] <= '9' &&
		      name[5] >= '0' && name[5] <= '9' &&
		      name[6] >= '0' && name[6] <= '9' &&
		      name[7] >= '0' && name[7] <= '9'))
			continue;

		ret = get_efi_variable(&guid, name, &size, (VOID **)&load_option, &flags);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to read '%s' variable", name);
			goto exit;
		}

		if (size < sizeof(EFI_LOAD_OPTION) + StrSize(description) ||
		    StrCmp(load_option->description, description)) {
			FreePool(load_option);
			continue;
		}
		FreePool(load_option);

		ret = str_to_stra(number, &name[StrLen(L"Boot")], sizeof(number));
		if (EFI_ERROR(ret))
			goto exit;

		*entry = strtoul((char *)number, NULL, 16);
		return EFI_SUCCESS;
	}

exit:
	FreePool(name);
	return ret;
}

static UINTN buf_size;
static CHAR8 *buffer;

static EFI_STATUS create_buffer(UINTN initial_size)
{
	buffer = AllocatePool(initial_size);
	if (!buffer)
		return EFI_OUT_OF_RESOURCES;

	buf_size = initial_size;
	return EFI_SUCCESS;
}

static EFI_STATUS append_to_buffer(VOID *data, UINTN size)
{
	buffer = ReallocatePool(buffer, buf_size, buf_size + size);
	if (!buffer)
		return EFI_OUT_OF_RESOURCES;

	memcpy(buffer + buf_size, data, size);
	buf_size += size;

	return EFI_SUCCESS;
}

static void free_buffer()
{
	if (buffer)
		FreePool(buffer);
	buf_size = 0;
}

static EFI_STATUS set_file_path(CHAR16 *bootloader_path)
{
	EFI_STATUS ret;
	EFI_DEVICE_PATH file_path;
	UINTN path_size = StrSize(bootloader_path);

	file_path.Type = MEDIA_FILEPATH_DP;
	file_path.SubType = MEDIA_FILEPATH_DP;
	SetDevicePathNodeLength(&file_path, sizeof(file_path) + path_size);

	ret = append_to_buffer(&file_path, sizeof(file_path));
	if (EFI_ERROR(ret))
		return ret;

	ret = append_to_buffer(bootloader_path, path_size);
	if (EFI_ERROR(ret))
		return ret;

	return EFI_SUCCESS;
}

static EFI_STATUS set_device_path(CHAR16 *part_label, CHAR16 *bootloader_path)
{
	EFI_STATUS ret;
	EFI_GUID guid;
	UINTN handle_nb = 0;
	EFI_HANDLE *handle_buf = NULL;
	EFI_DEVICE_PATH *device_path;

	ret = gpt_get_partition_guid(part_label, &guid, EMMC_USER_PART);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get '%s' partition GUID", part_label);
		return ret;
	}

	ret = LibLocateHandleByDiskSignature(MBR_TYPE_EFI_PARTITION_TABLE_HEADER,
					     SIGNATURE_TYPE_GUID,
					     (void *)&guid,
					     &handle_nb,
					     &handle_buf);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get handle for '%s' partition",
			   part_label);
		return ret;
	}
	if (handle_nb != 1) {
		error(L"Too many handles for '%s' partition", part_label);
		ret = EFI_UNSUPPORTED;
		goto exit;
	}

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, handle_buf[0],
				&DevicePathProtocol, (VOID*)&device_path);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get device path");
		goto exit;
	}

	while (!IsDevicePathEndType(device_path)) {
		ret = append_to_buffer(device_path, DevicePathNodeLength(device_path));
		if (EFI_ERROR(ret))
			goto exit;
		device_path = NextDevicePathNode(device_path);
	}

	ret = set_file_path(bootloader_path);
	if (EFI_ERROR(ret))
		goto exit;

	ret = append_to_buffer(device_path, DevicePathNodeLength(device_path));
	if (EFI_ERROR(ret))
		goto exit;

exit:
	FreePool(handle_buf);
	return ret;
}

static EFI_STATUS create_load_option(CHAR16 *description, CHAR16 *part_label,
				     CHAR16 *bootloader_path, CHAR16 entry)
{
	EFI_STATUS ret;
	EFI_LOAD_OPTION *load_option;
	CHAR16 varname[BOOTOPTION_LEN + 1];
	UINTN len, header_size;

	ret = create_buffer(offsetof(EFI_LOAD_OPTION, description));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to create load option buffer");
		return ret;
	}

	ret = append_to_buffer(description, StrSize(description));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to append description");
		goto exit;
	}

	header_size = buf_size;

	ret = set_device_path(part_label, bootloader_path);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set device path");
		goto exit;
	}

	len = SPrint(varname, sizeof(varname), VarBootOption, entry);
	if (len != BOOTOPTION_LEN) {
		error(L"Failed to format load option variable name");
		ret = EFI_UNSUPPORTED;
		goto exit;
	}

	load_option = (EFI_LOAD_OPTION *)buffer;
	load_option->attributes = LOAD_OPTION_ACTIVE;
	load_option->file_path_list_length = buf_size - header_size;
	ret = set_efi_variable(&EfiGlobalVariable, varname, buf_size,
			       load_option, TRUE, TRUE);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to write '%s' variable", varname);

exit:
	free_buffer();
	return ret;
}

static EFI_STATUS install_in_boot_order(CHAR16 entry)
{
	EFI_STATUS ret;
	CHAR16 *entries = NULL;
	CHAR16 *new_entries;
	UINTN size = 0;
	UINTN new_size, i, j;
	UINT32 flags;

	ret = get_efi_variable(&EfiGlobalVariable, VarBootOrder, &size,
			       (VOID **)&entries, &flags);
	if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
		efi_perror(ret, L"Failed to read '%s' variable", VarBootOrder);
		return ret;
	}

	if (size && entries[0] == entry)
		goto exit;

	for (i = 0; i < size / sizeof(CHAR16); i++)
		if (entries[i] == entry)
			break;

	if (!size || i == (size / sizeof(CHAR16)))
		new_size = size + sizeof(CHAR16);
	else
		new_size = size;

	new_entries = AllocatePool(new_size);
	if (!new_entries) {
		error(L"Failed to allocate new entries for '%s'", VarBootOrder);
		ret = EFI_OUT_OF_RESOURCES;
		goto exit;
	}

	new_entries[0] = entry;
	for (i = 0, j = 1; i < size / sizeof(CHAR16); i++) {
		if (entries[i] == entry)
			continue;
		new_entries[j++] = entries[i];
	}

	ret = set_efi_variable(&EfiGlobalVariable, VarBootOrder, new_size, new_entries,
			       TRUE, TRUE);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to set '%s' variable", VarBootOrder);

	FreePool(new_entries);

exit:
	if (entries)
		FreePool(entries);
	return ret;
}

EFI_STATUS bootmgr_register_entry(CHAR16 *description, CHAR16 *part_label,
				  CHAR16 *bootloader_path)
{
	EFI_STATUS ret;
	CHAR16 entry = -1;

	ret = find_load_option_entry(description, &entry);
	if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
		efi_perror(ret, L"Failed to Look up for the existant load option");
		return ret;
	}

	if (ret == EFI_NOT_FOUND) {
		ret = find_free_entry(&entry);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to find a new free load option entry");
			return ret;
		}
	}

	ret = create_load_option(description, part_label, bootloader_path, entry);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to create/update the load option");
		return ret;
	}

	ret = install_in_boot_order(entry);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set the boot order");
		return ret;
	}

	return EFI_SUCCESS;
}
