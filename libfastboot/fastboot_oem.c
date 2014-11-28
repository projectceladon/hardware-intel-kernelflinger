/*
 * Copyright (c) 2014, Intel Corporation
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
#include <vars.h>

#include "uefi_utils.h"
#include "flash.h"
#include "hashes.h"
#include "fastboot.h"
#include "fastboot_ui.h"
#include "gpt.h"

#include "fastboot_oem.h"
#include "intel_variables.h"

#define OFF_MODE_CHARGE		"off-mode-charge"

static void fastboot_oem_publish(void)
{
	fastboot_publish("secure", device_is_locked() ? "yes" : "no");
	fastboot_publish("unlocked", device_is_unlocked() ? "yes" : "no");
	fastboot_publish(OFF_MODE_CHARGE, get_current_off_mode_charge() ? "1" : "0");
	publish_intel_variables();
}

static void change_device_state(enum device_state new_state)
{
	EFI_STATUS ret;

	if (get_current_state() == new_state) {
		error(L"Device is already in the required state.");
		fastboot_okay("");
		return;
	}

	/* "Eng" builds skip all these security policies */
#ifdef USERDEBUG
	/* Data wipes and UI prompts are skipped if the device is in
	 * provisioning mode to avoid unnecessary steps and user interaction
	 * during provisioning */
	if (!device_is_provisioning()) {
		/* 'eng' or 'userdebug' bootloaders skip the prompts
		 * to make CI automation easier */
#ifdef USER
		if (!fastboot_ui_confirm_for_state(new_state)) {
			fastboot_fail("Refusing to change device state");
			return;
		}
#endif
		ui_print(L"Erasing userdata...");
		ret = erase_by_label(L"data");
		if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
			fastboot_fail("Failed to wipe data.\n");
			return;
		}

		if (ret == EFI_NOT_FOUND)
			ui_print(L"Not userdata partition to erase.");
		else
			ui_print(L"Erase done.");
	}
#endif

	ret = set_current_state(new_state);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to change the device state\n");
		return;
	}

	fastboot_oem_publish();
	fastboot_ui_refresh();
	clear_provisioning_mode();
	fastboot_okay("");
}

static void cmd_oem_lock(__attribute__((__unused__)) INTN argc,
			 __attribute__((__unused__)) CHAR8 **argv)
{
	change_device_state(LOCKED);
}

static void cmd_oem_unlock(__attribute__((__unused__)) INTN argc,
			   __attribute__((__unused__)) CHAR8 **argv)
{
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;
	UINT64 offset;
	UINT8 unlock_allowed;

	/* Enforce if we're not in provisioning mode and the persistent
	 * partition exists */
	if (!device_is_provisioning() &&
	    !EFI_ERROR(gpt_get_partition_by_label(L"persistent", &gparti))) {

		/* We need to check the last byte of the partition. The gparti
		 * .dio object is a handle to the beginning of the disk */
		offset = ((gparti.part.ending_lba + 1)
			  * gparti.bio->Media->BlockSize) - 1;
		ret = uefi_call_wrapper(gparti.dio->ReadDisk, 5, gparti.dio,
					gparti.bio->Media->MediaId, offset, 1,
					&unlock_allowed);
		if (EFI_ERROR(ret)) {
			/* Pathological if this fails, GPT screwed up? */
			efi_perror(ret, "Couldn't read persistent partition");
			unlock_allowed = 0;
		}
	} else {
		unlock_allowed = 1;
	}

	if (unlock_allowed == 0) {
#ifdef USER
		fastboot_fail("Unlocking device not allowed");
#else
		fastboot_info("Unlock protection is set");
		fastboot_info("Unlocking anyway since this is not a User build");
		change_device_state(UNLOCKED);
#endif
	} else {
		change_device_state(UNLOCKED);
	}
}

static void cmd_oem_verified(__attribute__((__unused__)) INTN argc,
			     __attribute__((__unused__)) CHAR8 **argv)
{
	change_device_state(VERIFIED);
}

static void cmd_oem_off_mode_charge(__attribute__((__unused__)) INTN argc,
				    CHAR8 **argv)
{
	EFI_STATUS ret;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	if (strcmp(argv[1], (CHAR8* )"1") && strcmp(argv[1], (CHAR8 *)"0")) {
		fastboot_fail("Invalid value");
		error(L"Please specify 1 or 0 to enable/disable charge mode");
		return;
	}

        ret = set_off_mode_charge(!strcmp(argv[1], (CHAR8* )"1"));
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to set %a", OFF_MODE_CHARGE);
		return;
	}

	fastboot_oem_publish();
	fastboot_okay("");
}

static void cmd_oem_setvar(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	CHAR16 *varname;
	CHAR8 *value = NULL;

	if (argc < 2 || argc > 3) {
		fastboot_fail("Invalid parameter");
		return;
	}

	varname = stra_to_str(argv[1]);
	if (argc == 3)
		value = argv[2];

	ret = set_efi_variable(&loader_guid, varname,
			       value ? strlen(value) + 1 : 0, value,
			       TRUE, FALSE);
	if (EFI_ERROR(ret))
		fastboot_fail("Unable to %a '%s' variable",
			      value ? "set" : "clear", varname);
	else
		fastboot_okay("");

	FreePool(varname);
}

static void cmd_oem_reboot(INTN argc, CHAR8 **argv)
{
	CHAR16 *target;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	target = stra_to_str(argv[1]);
	if (!target) {
		fastboot_fail("Unable to convert string");
		return;
	}

	ui_print(L"Rebooting to %s ...", target);
	fastboot_okay("");
	reboot(target);
}

static void cmd_oem_garbage_disk(__attribute__((__unused__)) INTN argc,
				 __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret = garbage_disk();

	if (ret == EFI_SUCCESS)
		fastboot_okay("");
	else
		fastboot_fail("Garbage disk failed, %r", ret);
}

static void cmd_oem_gethashes(__attribute__((__unused__)) INTN argc,
			      __attribute__((__unused__)) CHAR8 **argv)
{
	get_boot_image_hash(L"boot");
	get_boot_image_hash(L"recovery");
	get_esp_hash();
	get_ext4_hash(L"system");
	fastboot_okay("");
}

#ifndef USER
static void cmd_oem_reprovision(__attribute__((__unused__)) INTN argc,
			        __attribute__((__unused__)) CHAR8 **argv)
{
	if (EFI_ERROR(reprovision_state_vars())) {
		fastboot_fail("Unable to clear provisioning variables");
		return;
	}
	fastboot_okay("");
	reboot(L"dnx");
}
#endif

void fastboot_oem_init(void)
{
	fastboot_oem_publish();
	fastboot_oem_register("lock", cmd_oem_lock, FALSE);
	fastboot_oem_register("unlock", cmd_oem_unlock, FALSE);
	fastboot_oem_register("verified", cmd_oem_verified, FALSE);
	fastboot_oem_register(OFF_MODE_CHARGE, cmd_oem_off_mode_charge, FALSE);

	/* The following commands are not part of the Google
	 * requirements.  They are provided for engineering and
	 * provisioning purpose only and those which modify the
	 * device are restricted to the unlocked state.  */
	fastboot_oem_register("setvar", cmd_oem_setvar, TRUE);
	fastboot_oem_register("garbage-disk", cmd_oem_garbage_disk, TRUE);
	fastboot_oem_register("reboot", cmd_oem_reboot, FALSE);
	fastboot_oem_register("get-hashes", cmd_oem_gethashes, FALSE);
#ifndef USER
	fastboot_oem_register("reprovision", cmd_oem_reprovision, FALSE);
#endif
}
