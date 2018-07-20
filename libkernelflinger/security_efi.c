/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
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

#include "security_interface.h"
#include "lib.h"
#include "security.h"
#include "storage.h"

#ifdef RPMB_STORAGE
#include "rpmb_storage.h"

static UINT8 fixed_rpmb_keys[][RPMB_KEY_SIZE] = {
#ifdef FIXED_RPMB_KEY
		FIXED_RPMB_KEY
#else
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31",
		"12345ABCDEF1234512345ABCDEF12345"
#endif
};
#endif

/* now does not support this interface on UEFI platform */
EFI_STATUS set_device_security_info(__attribute__((unused)) IN void *security_data)
{
	EFI_STATUS ret = EFI_SUCCESS;

#ifdef RPMB_STORAGE
	// Set the fixed RPMB key
	if (is_boot_device_removable()) {
		// For removable storage, such as USB disk, always use one fixed RPMB key.
		return set_rpmb_derived_key(fixed_rpmb_keys, RPMB_KEY_SIZE, 1);
	}

	// Try to several possible fixed RPMB keys
	ret = set_rpmb_derived_key(fixed_rpmb_keys, sizeof(fixed_rpmb_keys), ARRAY_SIZE(fixed_rpmb_keys));
#endif

	return ret;
}

EFI_STATUS set_platform_secure_boot(__attribute__((unused)) IN UINT8 secure)
{
	return EFI_UNSUPPORTED;
}

/* UEFI specification 2.4. Section 3.3
 * The platform firmware is operating in secure boot mode if the value
 * of the SetupMode variable is 0 and the SecureBoot variable is set
 * to 1. A platform cannot operate in secure boot mode if the
 * SetupMode variable is set to 1. The SecureBoot variable should be
 * treated as read- only.
 */
BOOLEAN is_platform_secure_boot_enabled(VOID)
{
	EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;
	EFI_STATUS ret;
	UINT8 value;

	ret = get_efi_variable_byte(&global_guid, SETUP_MODE_VAR, &value);
	if (EFI_ERROR(ret))
		return FALSE;

	if (value != 0)
		return FALSE;

	ret = get_efi_variable_byte(&global_guid, SECURE_BOOT_VAR, &value);
	if (EFI_ERROR(ret))
		return FALSE;

	return value == 1;
}

BOOLEAN is_eom_and_secureboot_enabled(VOID)
{
	BOOLEAN sbflags;
	BOOLEAN enduser = TRUE;

	sbflags = is_platform_secure_boot_enabled();

	return sbflags && enduser;
}
