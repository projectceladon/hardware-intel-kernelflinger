/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
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

#include <ui.h>

#include "lib.h"
#include "ux.h"
#include "vars.h"

#define TIMEOUT_SECS	60

static const ui_textline_t red_state[] = {
	{ &COLOR_YELLOW,	"RECOVER",				TRUE },
	{ &COLOR_WHITE,		"Press Volume UP key",			FALSE },
	{ &COLOR_WHITE,		"",					FALSE },
	{ &COLOR_LIGHTRED,	"POWER OFF",				TRUE },
	{ &COLOR_WHITE,		"Press Volume DOWN key",		FALSE },
	{ &COLOR_WHITE,		"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"Your device is unable to start",	FALSE },
	{ &COLOR_LIGHTGRAY,	"because the boot image has",		FALSE },
	{ &COLOR_LIGHTGRAY,	"failed to verify or is corrupted.",	FALSE },
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"You may attempt to recover",		FALSE },
	{ &COLOR_LIGHTGRAY,	"the device.",				FALSE },
	{ NULL, NULL, FALSE}
};

static const ui_textline_t bad_recovery[] = {
	{ &COLOR_YELLOW,	"FASTBOOT",				TRUE },
	{ &COLOR_WHITE,		"Press Volume UP key",			FALSE },
	{ &COLOR_WHITE,		"",					FALSE },
	{ &COLOR_LIGHTRED,	"POWER OFF",				TRUE },
	{ &COLOR_WHITE,		"Press Volume DOWN key",		FALSE },
	{ &COLOR_WHITE,		"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"Your device is unable to start",	FALSE },
	{ &COLOR_LIGHTGRAY,	"because the Recovery Console",		FALSE },
	{ &COLOR_LIGHTGRAY,	"image has failed to verify or is",	FALSE },
	{ &COLOR_LIGHTGRAY,	"corrupted.",				FALSE },
	{ &COLOR_LIGHTGRAY, 	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"You may repair your device with",	FALSE },
	{ &COLOR_LIGHTGRAY,	"Fastboot.",				FALSE },
	{ NULL, NULL, FALSE }
};

static const ui_textline_t device_altered_unlocked[] = {
	{ &COLOR_YELLOW, 	"START",				TRUE },
	{ &COLOR_WHITE, 	"Press Volume UP key",			FALSE },
	{ &COLOR_WHITE, 	"",					FALSE },
	{ &COLOR_LIGHTRED, 	"FASTBOOT",				TRUE },
	{ &COLOR_WHITE, 	"Press Volume DOWN key",		FALSE },
	{ &COLOR_WHITE, 	"",					FALSE },
	{ &COLOR_LIGHTRED, 	"WARNING:",				TRUE },
	{ &COLOR_LIGHTGRAY, 	"Your device has been altered",		FALSE },
	{ &COLOR_LIGHTGRAY, 	"from its factory configuration.",	FALSE },
	{ &COLOR_LIGHTGRAY, 	"and is no longer in a locked or",	FALSE },
	{ &COLOR_LIGHTGRAY, 	"verified state.",			FALSE },
	{ &COLOR_LIGHTGRAY, 	"",					FALSE },
	{ &COLOR_LIGHTGRAY, 	"If you were not responsible for",	FALSE },
	{ &COLOR_LIGHTGRAY, 	"these changes, the security of",	FALSE },
	{ &COLOR_LIGHTGRAY, 	"your device may be at risk.",		FALSE },
	{ &COLOR_LIGHTGRAY, 	"Choose \"FASTBOOT\" to change",	FALSE },
	{ &COLOR_LIGHTGRAY, 	"your device's state.",			FALSE },
	{ NULL, NULL, FALSE }
};

static const ui_textline_t secure_boot_off[] = {
	{ &COLOR_YELLOW,	"START",				TRUE },
	{ &COLOR_WHITE,		"Press Volume UP key",			FALSE },
	{ &COLOR_WHITE,		"",					FALSE },
	{ &COLOR_LIGHTRED,	"POWER OFF",				TRUE },
	{ &COLOR_WHITE,		"Press Volume DOWN key",		FALSE },
	{ &COLOR_WHITE,		"",					FALSE },
	{ &COLOR_LIGHTRED,	"WARNING:",				TRUE },
	{ &COLOR_LIGHTGRAY,	"Your device has been altered",		FALSE },
	{ &COLOR_LIGHTGRAY,	"from its factory configuration.",	FALSE },
	{ &COLOR_LIGHTGRAY,	"and is no longer in a locked or",	FALSE },
	{ &COLOR_LIGHTGRAY,	"verified state due to UEFI Secure",	FALSE },
	{ &COLOR_LIGHTGRAY,	"Boot being disabled.",			FALSE },
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"If you were not responsible for",	FALSE },
	{ &COLOR_LIGHTGRAY,	"these changes, the security of",	FALSE },
	{ &COLOR_LIGHTGRAY,	"your device may be at risk.",		FALSE },
	{ &COLOR_LIGHTGRAY,	"Enter BIOS setup to re-enable",	FALSE },
	{ &COLOR_LIGHTGRAY,	"UEFI Secure Boot.",			FALSE },
	{ NULL, NULL, FALSE }
};

static const ui_textline_t device_altered_keystore[] = {
	{ &COLOR_YELLOW,	"START",				TRUE },
	{ &COLOR_WHITE,		"Press Volume UP key",			FALSE },
	{ &COLOR_WHITE,		"",					FALSE },
	{ &COLOR_LIGHTRED,	"FASTBOOT",				TRUE },
	{ &COLOR_WHITE,		"Press Volume DOWN key",		FALSE },
	{ &COLOR_WHITE,		"",					FALSE },
	{ &COLOR_LIGHTRED,	"WARNING:",				TRUE },
	{ &COLOR_LIGHTGRAY,	"Your device has been altered",		FALSE },
	{ &COLOR_LIGHTGRAY,	"from its factory configuration.",	FALSE },
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"If you were not responsible for",	FALSE },
	{ &COLOR_LIGHTGRAY,	"these changes, the security of",	FALSE },
	{ &COLOR_LIGHTGRAY,	"your device may be at risk.",		FALSE },
	{ &COLOR_LIGHTGRAY,	"Choose \"FASTBOOT\" to clear",		FALSE },
	{ &COLOR_LIGHTGRAY,	"or upload a new user keystore.",	FALSE },
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"The device was unable to verify",	FALSE },
	{ &COLOR_LIGHTGRAY,	"the keystore with ID:",		FALSE },
	{ NULL, NULL, FALSE }
};

static const char *VENDOR_IMG_NAME = "splash_intel";

static UINTN swidth;
static UINTN sheight;

static EFI_STATUS display_text(const ui_textline_t *text1,
			       const ui_textline_t *text2) {
	UINTN width, height, margin, x, y;
	ui_image_t *vendor;
	ui_font_t *font;
	EFI_STATUS ret;

	ui_clear_screen();

	margin = swidth / 10;

	vendor = ui_image_get(VENDOR_IMG_NAME);
	if (!vendor) {
		efi_perror(EFI_UNSUPPORTED, "Unable to load '%a' image",
			   VENDOR_IMG_NAME);
		return EFI_UNSUPPORTED;
	}

	font = ui_font_get("18x32");
	if (!font) {
		efi_perror(EFI_UNSUPPORTED, "Unable to find 18x32 font");
		return EFI_UNSUPPORTED;
	}

	if (swidth > sheight) {	/* Landscape orientation. */
		width = (swidth / 2) - (2 * margin);
		height = vendor->height * width / vendor->width;
		x = margin;
		y = (sheight / 2) - (height / 2);
		ui_image_draw_scale(vendor, x, y , width, height);

		ret = ui_textarea_display_text(text1, font, swidth / 2 + margin, &y);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, "Unable to display text.");
			return ret;
		}
	} else {		/* Portrait orientation. */
		height = sheight / 3;
		width = vendor->width * height / vendor->height;
		x = (swidth / 2) - (width / 2);
		y = margin;
		ui_image_draw_scale(vendor, x, y , width, height);

		y += height + margin;
		ret = ui_textarea_display_text(text1, font, x, &y);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, "Unable to display text.");
			return ret;
		}
	}

	if (text2) {
		ret = ui_textarea_display_text(text2, font, x, &y);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, "Unable to display text.");
			return ret;
		}
	}

	return EFI_SUCCESS;
}

static EFI_STATUS clear_text() {
	UINTN margin;

	margin = sheight / 10;
	if (swidth > sheight)	/* Landscape orientation. */
		return ui_clear_area(swidth / 2, margin,
				     swidth / 2, sheight - (2 * margin));
	/* Portrait orientation. */
	return ui_clear_area(0, sheight / 3 + margin,
			     swidth, sheight - (sheight / 3) - margin);
}

static BOOLEAN ux_display_splash() {
	UINT8 value;
	EFI_STATUS ret;

	ret = get_efi_variable_byte(&loader_guid, L"UIDisplaySplash", &value);
	if (EFI_ERROR(ret) || value != 1)
		return FALSE;

	return TRUE;
}

BOOLEAN ux_prompt_user(const ui_textline_t *text1,
		       const ui_textline_t *text2) {
	BOOLEAN answer;

	ui_init(&swidth, &sheight);

	display_text(text1, text2);
	answer = ui_input_to_bool(TIMEOUT_SECS);
	clear_text();
	return answer;
}

BOOLEAN ux_prompt_user_keystore_unverified(UINT8 *hash) {
	char buf[15];
	const ui_textline_t hash_text[] = {
		{ &COLOR_WHITE, buf, FALSE },
		{ NULL, NULL, FALSE }
	};

	snprintf((CHAR8 *)buf, sizeof(buf),
		 (CHAR8 *)"%02x%02x-%02x%02x-%02x%02x",
		 hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]);

	return ux_prompt_user(device_altered_keystore, hash_text);
}

BOOLEAN ux_warn_user_unverified_recovery(VOID) {
	return ux_prompt_user(bad_recovery, NULL);
}

BOOLEAN ux_prompt_user_bootimage_unverified(VOID) {
	return ux_prompt_user(red_state, NULL);
}

BOOLEAN ux_prompt_user_secure_boot_off(VOID) {
	return ux_prompt_user(secure_boot_off, NULL);
}

BOOLEAN ux_prompt_user_device_unlocked(VOID) {
	return ux_prompt_user(device_altered_unlocked, NULL);
}

VOID ux_init(VOID) {
	uefi_call_wrapper(ST->ConOut->Reset, 2, ST->ConOut, FALSE);
        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut,
			  EFI_WHITE | EFI_BACKGROUND_BLACK);
	uefi_call_wrapper(ST->ConOut->EnableCursor, 2, ST->ConOut, FALSE);

	if (ux_display_splash()) {
		ui_init(&swidth, &sheight);
		ui_display_vendor_splash();
	}
}

