/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Authors: Sylvain Chouleur <sylvain.chouleur@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 *          Jocelyn Falempe <jocelyn.falempe@intel.com>
 *          Andrew Boie <andrew.p.boie@intel.com>
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
#include "fastboot.h"
#include "flash.h"
#include "fastboot_ui.h"
#include "gpt.h"

static cmdlist_t cmdlist;

static EFI_STATUS fastboot_flashing_publish(void)
{
	EFI_STATUS ret;

	ret = fastboot_publish("secure", device_is_locked() ? "yes" : "no");
	if (EFI_ERROR(ret))
		return ret;

	return fastboot_publish("unlocked", device_is_unlocked() ? "yes" : "no");
}

EFI_STATUS change_device_state(enum device_state new_state, BOOLEAN interactive)
{
	EFI_STATUS ret;

	/* "Eng" builds skip all these security policies */
#ifdef USERDEBUG
	/* Data wipes and UI prompts are skipped if the device is in
	 * provisioning mode to avoid unnecessary steps and user interaction
	 * during provisioning */
	if (!device_is_provisioning()) {
		/* 'eng' or 'userdebug' bootloaders skip the prompts
		 * to make CI automation easier */
#ifdef USER
		if (interactive && !fastboot_ui_confirm_for_state(new_state)) {
			fastboot_fail("Refusing to change device state");
			return EFI_ACCESS_DENIED;
		}
#endif
		ui_print(L"Erasing userdata...");
		ret = erase_by_label(L"data");
		if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
			if (interactive)
				fastboot_fail("Failed to wipe data.");
			return ret;
		}

		if (ret == EFI_NOT_FOUND)
			ui_print(L"No userdata partition to erase.");
		else
			ui_print(L"Erase done.");
	}
#endif

	ret = set_current_state(new_state);
	if (EFI_ERROR(ret)) {
		if (interactive)
			fastboot_fail("Failed to change the device state");
		return ret;
	}

	fastboot_ui_refresh();
	ret = fastboot_flashing_publish();
	if (EFI_ERROR(ret)) {
		if (interactive)
			fastboot_fail("Failed to publish OEM variables");
		return ret;
	}

	if (interactive)
		fastboot_okay("");
	/* Ensure logs variable is deleted on a successful
	   state transition.  */
	del_efi_variable(&loader_guid, LOG_VAR);

	return EFI_SUCCESS;
}

static BOOLEAN is_already_in_state(enum device_state state)
{
	if (get_current_state() == state && !device_is_provisioning()) {
		error(L"Device is already in the required state.");
		fastboot_okay("");
		return TRUE;
	}

	return FALSE;
}

static void cmd_lock(__attribute__((__unused__)) INTN argc,
		     __attribute__((__unused__)) CHAR8 **argv)
{
	if (!is_already_in_state(LOCKED))
		change_device_state(LOCKED, TRUE);
}

static BOOLEAN frp_allows_unlock()
{
	UINT8 persist_byte;
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;
	UINT64 offset;

	ret = gpt_get_partition_by_label(L"persistent", &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret))
		return TRUE;	/* Allow if the persistent partition
				   does not exist */

	/* We need to check the last byte of the partition. The gparti
	 * .dio object is a handle to the beginning of the disk */
	offset = ((gparti.part.ending_lba + 1) * gparti.bio->Media->BlockSize) - 1;
	ret = uefi_call_wrapper(gparti.dio->ReadDisk, 5, gparti.dio,
				gparti.bio->Media->MediaId, offset,
				sizeof(persist_byte), &persist_byte);
	if (EFI_ERROR(ret)) {
		/* Pathological if this fails, GPT screwed up? */
		efi_perror(ret, L"Couldn't read persistent partition");
		return FALSE;
	}

	/* Per the specification, value of 1 means unlock is OK */
	return persist_byte == 1;
}

static void cmd_unlock(__attribute__((__unused__)) INTN argc,
		       __attribute__((__unused__)) CHAR8 **argv)
{
	BOOLEAN unlock_allowed;

	if (is_already_in_state(UNLOCKED))
		return;

	/* Allow if device is in provisioning mode */
	if (device_is_provisioning())
		unlock_allowed = TRUE;
	else
		unlock_allowed = no_device_unlock() ? FALSE : frp_allows_unlock();

	if (unlock_allowed == FALSE) {
#ifdef USER
		fastboot_fail("Unlocking device not allowed");
#else
		fastboot_info("Unlock protection is set");
		fastboot_info("Unlocking anyway since this is not a User build");
		change_device_state(UNLOCKED, TRUE);
#endif
	} else {
		change_device_state(UNLOCKED, TRUE);
	}
}

static void cmd_flashing(INTN argc, CHAR8 **argv)
{
	if (argc < 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	fastboot_run_cmd(cmdlist, (char *)argv[1], argc - 1, argv + 1);
}

static struct fastboot_cmd COMMANDS[] = {
	{ "lock",	LOCKED,	cmd_lock },
	{ "unlock",	LOCKED,	cmd_unlock }
};

static struct fastboot_cmd flashing = { "flashing", LOCKED, cmd_flashing };

EFI_STATUS fastboot_flashing_init(void)
{
	EFI_STATUS ret;
	UINTN i;

	ret = fastboot_flashing_publish();
	if (EFI_ERROR(ret))
		return ret;

	for (i = 0; i < ARRAY_SIZE(COMMANDS); i++) {
		ret = fastboot_register_into(&cmdlist, &COMMANDS[i]);
		if (EFI_ERROR(ret))
			return ret;
	}

	fastboot_register(&flashing);

	return EFI_SUCCESS;
}

void fastboot_flashing_free()
{
	fastboot_cmdlist_unregister(&cmdlist);
}
