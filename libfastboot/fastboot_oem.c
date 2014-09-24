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

#include <lib.h>

#include "uefi_utils.h"
#include "flash.h"
#include "fastboot.h"
#include "fastboot_ui.h"

#include "fastboot_oem.h"

const EFI_GUID fastboot_guid = { 0x1ac80a82, 0x4f0c, 0x456b,
				 {0x9a, 0x99, 0xde, 0xbe, 0xb4, 0x31, 0xfc, 0xc1} };

#define OEM_LOCK_VAR L"OEMLock"

static enum device_state current_state = UNKNOWN_STATE;

static void fastboot_oem_publish(void)
{
	fastboot_publish("secure", device_is_locked() ? "yes" : "no");
	fastboot_publish("unlocked", device_is_unlocked() ? "yes" : "no");
}

enum device_state get_current_state()
{
	UINT32 *stored_state;
	UINTN dsize;
	EFI_STATUS ret;
	UINT32 flags;

	if (current_state == UNKNOWN_STATE) {
		ret = get_efi_variable((EFI_GUID *)&fastboot_guid, OEM_LOCK_VAR,
				       &dsize, (void **)&stored_state, &flags);
		/* If the variable does not exist, assume unlocked. */
		if (ret == EFI_NOT_FOUND) {
			current_state = UNLOCKED;
			goto exit;
		}

		/* If we can't read the state, be safe and assume locked. */
		if (EFI_ERROR(ret) || !dsize) {
			error(L"Couldn't read %s, assuming locked", OEM_LOCK_VAR);
			current_state = LOCKED;
		} else if (flags & EFI_VARIABLE_RUNTIME_ACCESS) {
			error(L"%s has RUNTIME_ACCESS flag, assuming locked", OEM_LOCK_VAR);
			current_state = LOCKED;
		} else
			current_state = *stored_state;
	}

exit:
	return current_state;
}

static EFI_STATUS set_current_state(enum device_state state)
{
	UINT32 stored_state = state;
	EFI_STATUS ret = set_efi_variable(&fastboot_guid, OEM_LOCK_VAR,
					  sizeof(stored_state), &stored_state,
					  TRUE, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to set %a variable", OEM_LOCK_VAR);
		return ret;
	}

	current_state = state;
	fastboot_oem_publish();
	fastboot_ui_refresh();

	return EFI_SUCCESS;
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

static void change_device_state(enum device_state new_state)
{
	EFI_STATUS ret;

	if (get_current_state() == new_state) {
		error(L"Device is already in the required state.");
		fastboot_okay("");
		return;
	}

	if (!fastboot_ui_confirm_for_state(new_state))
		goto exit;

	ui_print(L"Erasing userdata...");
	ret = erase_by_label(L"data");
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to wipe data.\n");
		return;
	}

	ui_print(L"Erase done.");

	ret = set_current_state(new_state);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to change the device state\n");
		return;
	}

exit:
	fastboot_okay("");
}

static void cmd_oem_lock(__attribute__((__unused__)) CHAR8 *arg)
{
	change_device_state(LOCKED);
}

static void cmd_oem_unlock(__attribute__((__unused__)) CHAR8 *arg)
{
	change_device_state(UNLOCKED);
}

static void cmd_oem_verified(__attribute__((__unused__)) CHAR8 *arg)
{
	change_device_state(VERIFIED);
}

void fastboot_oem_init(void) {
	fastboot_oem_register("lock", cmd_oem_lock, FALSE);
	fastboot_oem_register("unlock", cmd_oem_unlock, FALSE);
	fastboot_oem_register("verified", cmd_oem_verified, FALSE);
	fastboot_oem_publish();
}
