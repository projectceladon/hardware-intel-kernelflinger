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

char *info_bootloader_version(void)
{
	EFI_STATUS ret;
	CHAR16 *version;
	char *value = INFO_UNDEFINED;

	if (bootloader_version[0] != '\0')
		return bootloader_version;

	version = get_efi_variable_str(&loader_guid, LOADER_VERSION_VAR);
	if (!version)
		return INFO_UNDEFINED;

	if (StrLen(version) >= sizeof(bootloader_version)) {
		error(L"Bootloader string is too long.");
		goto exit;
	}

	ret = str_to_stra((CHAR8 *)bootloader_version, version, StrLen(version) + 1);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to convert bootloader version to CHAR8");
		goto exit;
	}

	value = bootloader_version;

exit:
	FreePool(version);
	return value;
}

char *info_variant(void)
{
#ifdef HAL_AUTODETECT
	return get_property_device();
#else
	return INFO_UNDEFINED;
#endif

}

char *info_product(void)
{
	return TARGET_BOOTLOADER_BOARD_NAME;
}

