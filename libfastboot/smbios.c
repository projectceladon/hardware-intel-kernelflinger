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

#include <efi.h>
#include <efilib.h>

#include "smbios.h"

char *SMBIOS_UNDEFINED = "N/A";

#define offsetof(st, m) __builtin_offsetof(st, m)
/* Allow cast to pointer from integer of different size.  */
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

#define SMBIOS_GET_STRING(type, field) \
	smbios_get_string(type, offsetof(SMBIOS_TYPE##type, field))

static char *smbios_get_string(UINT8 type, UINT8 offset)
{
	SMBIOS_STRUCTURE_TABLE *table;
	EFI_STATUS ret;
	SMBIOS_STRUCTURE_POINTER sm_struct;
	UINT8 i;
	CHAR8 *str;

	ret = LibGetSystemConfigurationTable(&SMBIOSTableGuid, (VOID**)&table);
	if (EFI_ERROR(ret))
		return SMBIOS_UNDEFINED;

	sm_struct.Hdr = (SMBIOS_HEADER *)table->TableAddress;
	for (i = 0; i < table->TableLength; i++) {
		if (sm_struct.Hdr->Type == type)
			break;
		LibGetSmbiosString(&sm_struct, -1);
	}

	if (i == table->TableLength)
		return SMBIOS_UNDEFINED;

	str = LibGetSmbiosString(&sm_struct, sm_struct.Raw[offset]);

	return str ? (char *)str : SMBIOS_UNDEFINED;
}

char *smbios_get_hw_version(void)
{
	return SMBIOS_GET_STRING(1, Version);
}

char *smbios_get_ifwi_version(void)
{
	return SMBIOS_GET_STRING(0, BiosVersion);
}

char *smbios_get_serial_number(void)
{
	return SMBIOS_GET_STRING(1, SerialNumber);
}
