/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
 *         Jeremy Compostella <jeremy.compostella@intel.com>
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

#include "keystore.h"
#include "vars.h"
#include "ui.h"
#include "lib.h"

#define OFF_MODE_CHARGE_VAR	L"off-mode-charge"
#define OEM_LOCK_VAR		L"OEMLock"
#define KEYSTORE_VAR		L"KeyStore"

#define OEM_LOCK_UNLOCKED	(1 << 0)
#define OEM_LOCK_VERIFIED	(1 << 1)

const EFI_GUID fastboot_guid = { 0x1ac80a82, 0x4f0c, 0x456b,
	{0x9a, 0x99, 0xde, 0xbe, 0xb4, 0x31, 0xfc, 0xc1} };
/* Gummiboot's GUID, we use some of the same variables */
const EFI_GUID loader_guid = { 0x4a67b082, 0x0a4c, 0x41cf,
	{0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f} };

/* GUIDs for various interesting Android partitions */
const EFI_GUID boot_ptn_guid = { 0x49a4d17f, 0x93a3, 0x45c1,
	{0xa0, 0xde, 0xf5, 0x0b, 0x2e, 0xbe, 0x25, 0x99 } };
const EFI_GUID recovery_ptn_guid = { 0x4177c722, 0x9e92, 0x4aab,
	{0x86, 0x44, 0x43, 0x50, 0x2b, 0xfd, 0x55, 0x06 } };
const EFI_GUID misc_ptn_guid = { 0xef32a33b, 0xa409, 0x486c,
	{0x91, 0x41, 0x9f, 0xfb, 0x71, 0x1f, 0x62, 0x66 } };

static BOOLEAN provisioning_mode = FALSE;
static enum device_state current_state = UNKNOWN_STATE;

static struct state_display {
	char *string;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color;
} STATE_DISPLAY[] = {
	{ "unknown", &COLOR_RED },
	{ "locked", &COLOR_WHITE },
	{ "verified", &COLOR_WHITE },
	{ "unlocked", &COLOR_RED }
};

static CHAR8 current_off_mode_charge[2];

BOOLEAN get_current_off_mode_charge(void)
{
	UINTN size;
	CHAR8 *data;

	if (current_off_mode_charge[0] == '\0') {
		if (EFI_ERROR(get_efi_variable(&fastboot_guid, OFF_MODE_CHARGE_VAR,
					       &size, (VOID **)&data, NULL)))
			return TRUE;

		if (size != sizeof(current_off_mode_charge)
		    || (strcmp(data, (CHAR8 *)"0") && strcmp(data, (CHAR8 *)"1"))) {
			FreePool(data);
			return TRUE;
		}

		memcpy(current_off_mode_charge, data, sizeof(current_off_mode_charge));
		FreePool(data);
	}

	return !strcmp(current_off_mode_charge, (CHAR8 *)"1");
}

enum device_state get_current_state()
{
	UINT8 *stored_state;
	UINTN dsize;
	EFI_STATUS ret;
	UINT32 flags;

	if (current_state == UNKNOWN_STATE) {
		ret = get_efi_variable((EFI_GUID *)&fastboot_guid, OEM_LOCK_VAR,
				       &dsize, (void **)&stored_state, &flags);
		/* If the variable does not exist, assume unlocked. */
		if (ret == EFI_NOT_FOUND) {
			debug(L"OEMLock not set, device is in provisioning mode");
			provisioning_mode = TRUE;
			current_state = UNLOCKED;
			goto exit;
		}

		/* If we can't read the state, be safe and assume locked. */
		if (EFI_ERROR(ret) || !dsize) {
			error(L"Couldn't read %s, assuming locked", OEM_LOCK_VAR);
			current_state = LOCKED;
			goto exit;
#ifndef USERFASTBOOT
		} else if (flags & EFI_VARIABLE_RUNTIME_ACCESS) {
			error(L"%s has RUNTIME_ACCESS flag, assuming locked", OEM_LOCK_VAR);
			current_state = LOCKED;
#endif
		} else {
			if (stored_state[0] & OEM_LOCK_UNLOCKED)
				current_state = UNLOCKED;
			else if (stored_state[0] & OEM_LOCK_VERIFIED)
				current_state = VERIFIED;
			else
				current_state = LOCKED;

			debug(L"device state %d", current_state);
		}
		FreePool(stored_state);
	}

exit:
	return current_state;
}

EFI_STATUS set_current_state(enum device_state state)
{
	UINT8 stored_state;

	switch (state) {
	case LOCKED:
		stored_state = 0;
		break;
	case VERIFIED:
		stored_state = OEM_LOCK_VERIFIED;
		break;
	case UNLOCKED:
		stored_state = OEM_LOCK_UNLOCKED;
		break;
	default:
		return EFI_INVALID_PARAMETER;
	}

	EFI_STATUS ret = set_efi_variable(&fastboot_guid, OEM_LOCK_VAR,
					  sizeof(stored_state), &stored_state,
					  TRUE, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to set %a variable", OEM_LOCK_VAR);
		return ret;
	}

	debug(L"device state is now %d", state);
	current_state = state;
	return EFI_SUCCESS;
}

#ifndef USER
EFI_STATUS reprovision_state_vars(VOID)
{
	return set_efi_variable(&fastboot_guid, OEM_LOCK_VAR,
				0, 0, TRUE, FALSE);
}
#endif

EFI_STATUS set_off_mode_charge(BOOLEAN enabled)
{
	CHAR8 *val = (CHAR8 *)(enabled ? "1" : "0");
	EFI_STATUS ret = set_efi_variable(&fastboot_guid, OFF_MODE_CHARGE_VAR,
					  2, val, TRUE, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set %a variable", OFF_MODE_CHARGE_VAR);
		return ret;
	}

	memcpy(current_off_mode_charge, val, 2);
	return EFI_SUCCESS;
}

EFI_STATUS get_user_keystore(VOID **keystorep, UINTN *sizep)
{
	UINT32 flags;
	VOID *keystore;
	UINTN size;
	EFI_STATUS ret;

	ret = get_efi_variable(&fastboot_guid, KEYSTORE_VAR,
			       &size, &keystore, &flags);

	if (EFI_ERROR(ret) || size == 0)
		return EFI_NOT_FOUND;

#ifndef USERFASTBOOT
	if (flags & EFI_VARIABLE_RUNTIME_ACCESS) {
		FreePool(keystore);
		return EFI_NOT_FOUND;
	}
#endif
	*sizep = size;
	*keystorep = keystore;
	return EFI_SUCCESS;
}

EFI_STATUS set_user_keystore(VOID *data, UINTN size)
{
	if (size) {
		struct keystore *ks = get_keystore(data, size);

		if (!ks) {
			error(L"keystore data is invalid");
			return EFI_INVALID_PARAMETER;
		}

		free_keystore(ks);
	}

	return set_efi_variable(&fastboot_guid, KEYSTORE_VAR,
			       size, data, TRUE, FALSE);
}

char *get_current_state_string()
{
	return STATE_DISPLAY[get_current_state() + 1].string;
}

EFI_GRAPHICS_OUTPUT_BLT_PIXEL *get_current_state_color()
{
	return STATE_DISPLAY[get_current_state() + 1].color;
}

BOOLEAN device_is_unlocked()
{
	return get_current_state() == UNLOCKED;
}

BOOLEAN device_is_locked()
{
	return get_current_state() == LOCKED;
}

BOOLEAN device_is_verified()
{
	return get_current_state() == VERIFIED;
}

BOOLEAN device_is_provisioning(void)
{
	/* Force OEM_LOCK_VAR check if we haven't already */
	get_current_state();

	return provisioning_mode;
}

VOID clear_provisioning_mode(void)
{
	provisioning_mode = FALSE;
}

