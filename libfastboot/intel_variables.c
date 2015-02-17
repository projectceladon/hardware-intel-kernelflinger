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

#include <security.h>
#include <lib.h>
#include <vars.h>

#include "uefi_utils.h"
#include "fastboot.h"
#include "fastboot_oem.h"
#include "smbios.h"
#include "intel_variables.h"

/* "secureboot": Indicates whether UEFI Secure Boot is enabled. This
   is a pre-requisite for Verified Boot.  */
static void publish_secureboot(void)
{
	fastboot_publish("secureboot",
			 is_efi_secure_boot_enabled() ? "yes" : "no" );
}

/* "product-name": Reports "product_name" field in DMI.  */
static void publish_product_name(void)
{
	fastboot_publish("product-name",
			 SMBIOS_GET_STRING(1, ProductName));
}

/* "firmware": Reports the current device firmware version from
 * DMI. Combines the values of DMI "bios_vendor" and "bios_version"
 * fields.  */
static char firmware_str[128];
static void publish_firmware(void)
{
	snprintf((CHAR8 *)firmware_str, sizeof(firmware_str) - 1,
		 (CHAR8 *)"%a %a",
		 SMBIOS_GET_STRING(0, Vendor),
		 SMBIOS_GET_STRING(0, BiosVersion));
	fastboot_publish("firmware", firmware_str);
}

/* "boot-state": Indicates the device's color-coded boot state as per
 * Google's Verified Boot specification. Possible values are "GREEN",
 * "ORANGE", "RED", or "YELLOW". If the bootloader doesn't support
 * Verified Boot, "unknown" will be returned.  */
static char *BOOT_STATES_STRING[] = {
	"GREEN", "YELLOW", "ORANGE", "RED"
};
static void publish_boot_state(void)
{
	UINT8 state;
	EFI_STATUS ret;

	ret = get_efi_variable_byte(&fastboot_guid, BOOT_STATE_VAR, &state);
	if (EFI_ERROR(ret) || state >= ARRAY_SIZE(BOOT_STATES_STRING)) {
		fastboot_publish("boot-state", "unknown");
		return;
	}

	fastboot_publish("boot-state", BOOT_STATES_STRING[state]);
}

/* "device-state": Indicates the device's lock state as per Google's
 * Verified Boot specification. Possible values are "unlocked",
 * "locked", "verified". */
static void publish_device_state(void)
{
	fastboot_publish("device-state", get_current_state_string());
}

/* "board": Indicates the board information, combining the values of
 * DMI "board_vendor", "board_name", and "board_version" fields.  */
static char board_str[128];
static void publish_board(void)
{
	snprintf((CHAR8 *)board_str, sizeof(board_str),
		 (CHAR8 *)"%a %a %a",
		 SMBIOS_GET_STRING(2, Manufacturer),
		 SMBIOS_GET_STRING(2, ProductName),
		 SMBIOS_GET_STRING(2, Version));
	fastboot_publish("board", board_str);
}

/* "serialno": The device serial number. */
static void publish_serialno(void)
{
	fastboot_publish("serialno",
			 SMBIOS_GET_STRING(1, SerialNumber));
}

void publish_intel_variables(void)
{
	publish_secureboot();
	publish_product_name();
	publish_firmware();
	publish_boot_state();
	publish_device_state();
	publish_board();
	publish_serialno();
}
