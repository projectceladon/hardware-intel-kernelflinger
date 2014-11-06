/*
 * Copyright (c) 2014, Intel Corporation
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

#include "info.h"
#include <efi.h>
#include <efilib.h>
#include <vars.h>
#include <lib.h>
#include <fastboot.h>

#include "uefi_utils.h"

#define MAX_INFO_LENGTH	50

char *INFO_UNDEFINED = "N/A";
static char bootloader_version[MAX_INFO_LENGTH];
static char device_name[MAX_INFO_LENGTH];
static char variant[MAX_INFO_LENGTH];

char *info_bootloader_version(void)
{
	CHAR16 *version;

	if (bootloader_version[0] != '\0')
		return bootloader_version;

	version = get_efi_variable_str(&loader_guid, LOADER_VERSION_VAR);
	if (!version)
		return INFO_UNDEFINED;

	if (StrLen(version) >= sizeof(bootloader_version)) {
		error(L"Bootloader string is too long.");
		FreePool(version);
		return INFO_UNDEFINED;
	}

	str_to_stra((CHAR8 *)bootloader_version, version, StrLen(version) + 1);

	return bootloader_version;
}

static char *info_get_from_variable(const EFI_GUID *guid, CHAR16 *varname, char *cache)
{
	EFI_STATUS ret;
	CHAR8 *value = NULL;
	UINTN size;

	if (cache[0] != '\0')
		return cache;

	ret = get_efi_variable(guid, varname, &size, (VOID **)&value, NULL);
	if (EFI_ERROR(ret) || !value)
		return INFO_UNDEFINED;

	if (size >= MAX_INFO_LENGTH) {
		error(L"Variable value string is too long.");
		FreePool(value);
		return INFO_UNDEFINED;
	}

	memcpy((CHAR8 *)cache, value, size);
	cache[size + 1] = '\0';

	return cache;
}

char *info_variant(void)
{
	return info_get_from_variable(&fastboot_guid, L"Variant", variant);
}

char *info_product(void)
{
	return info_get_from_variable(&fastboot_guid, L"Product", device_name);
}

BOOLEAN info_is_production_signing(void)
{
	return FALSE;
}
