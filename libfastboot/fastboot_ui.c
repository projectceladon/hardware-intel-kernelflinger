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
#include <lib.h>
#include <vars.h>
#include <ui.h>
#include <security.h>

#include "uefi_utils.h"
#include "fastboot_oem.h"
#include "fastboot_ui.h"
#include "smbios.h"
#include "info.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

static const ui_textline_t unlocked_headers[] = {
	{ &COLOR_WHITE,		"        Unlock bootloader?",			TRUE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_WHITE,		"If you unlock the bootloader, you will",	FALSE },
	{ &COLOR_WHITE,		"be able to install custom operating",		FALSE },
	{ &COLOR_WHITE,		"system software on this device and such",	FALSE },
	{ &COLOR_WHITE,		"software will not be verified at boot.",	FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_WHITE,		"Changing device state will also delete",	FALSE },
	{ &COLOR_WHITE,		"all personal data from your device",		FALSE },
	{ &COLOR_WHITE,		"(a 'factory data reset').",			FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_YELLOW,	"YES",						TRUE },
	{ &COLOR_WHITE,		"Press Volume UP key",				FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_YELLOW,	"NO",						TRUE },
	{ &COLOR_WHITE,		"Press Volume DOWN key",			FALSE },
	{ NULL, NULL, FALSE }
};

static ui_textline_t locked_headers[] = {
	{ &COLOR_WHITE,		"         Lock bootloader?", 			TRUE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_WHITE,		"If you lock the bootloader, you will", 	FALSE },
	{ &COLOR_WHITE,		"prevent the device from having any",		FALSE },
	{ &COLOR_WHITE,		"custom software flashed until it is",		FALSE },
	{ &COLOR_WHITE,		"again set to 'unlocked' or 'verified'",	FALSE },
	{ &COLOR_WHITE,		"state.",					FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_WHITE,		"Changing device state will also delete",	FALSE },
	{ &COLOR_WHITE,		"all personal data from your device",		FALSE },
	{ &COLOR_WHITE,		"(a 'factory data reset').",			FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_YELLOW,	"YES",						TRUE },
	{ &COLOR_WHITE,		"Press Volume UP key",				FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_YELLOW,	"NO",						TRUE },
	{ &COLOR_WHITE,		"Press Volume DOWN key",			FALSE },
	{ NULL, NULL, FALSE }
};

static ui_textline_t verified_headers[] = {
	{ &COLOR_WHITE,		"     Set bootloader to Verified?",		TRUE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_WHITE,		"If you set the loader to Verified state,",	FALSE },
	{ &COLOR_WHITE,		"you may flash custom software to",		FALSE },
	{ &COLOR_WHITE,		"the device and the loader will attempt",	FALSE },
	{ &COLOR_WHITE,		"to verify these custom images against",	FALSE },
	{ &COLOR_WHITE,		"either the OEM keystore or a keystore",	FALSE },
	{ &COLOR_WHITE,		"supplied by you. Some, but not all",		FALSE },
	{ &COLOR_WHITE,		"fastboot commands will be available.",		FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_WHITE,		"Changing device state will also delete",	FALSE },
	{ &COLOR_WHITE,		"all personal data from your device",		FALSE },
	{ &COLOR_WHITE,		"(a 'factory data reset').",			FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_YELLOW,	"YES",						TRUE },
	{ &COLOR_WHITE,		"Press Volume UP key",				FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_YELLOW,	"NO",						TRUE },
	{ &COLOR_WHITE,		"Press Volume DOWN key",			FALSE },
	{ NULL, NULL, FALSE }
};

static struct msg_for_state {
	const ui_textline_t *msg;
	enum device_state state;
} const FASTBOOT_UI_CONFIRM[] = {
	{ unlocked_headers,	UNLOCKED },
	{ locked_headers,	LOCKED },
	{ verified_headers,	VERIFIED }
};

static const char *DROID_IMG_NAME = "droid_operation";
static const UINTN SPACE = 20;
static char *FASTBOOT_FONT_NAME = "18x32";

/* Boot menu. */
static ui_boot_action_t BOOT_ACTIONS[] = {
	{ "start",		NULL,	NORMAL_BOOT },
	{ "restartbootloader",	NULL,	FASTBOOT },
	{ "recoverymode",	NULL,	RECOVERY },
	{ "reboot",		NULL,	REBOOT },
	{ "power_off",		NULL,	POWER_OFF },
	{ NULL,			NULL,	UNKNOWN_TARGET }
};

static BOOLEAN fastboot_ui_initialized = FALSE;
static UINTN margin;
static UINTN swidth, sheight;
static UINTN area_x;
static UINTN area_y;
static ui_boot_menu_t *boot_menu;
static ui_font_t *fastboot_font;

static EFI_STATUS fastboot_ui_clear_dynamic_part(void)
{
	return ui_clear_area(area_x, area_y,
			     swidth - area_x,
			     sheight - area_y - margin);
}

static void fastboot_ui_info_product_name(ui_textline_t *line)
{
	line->str = info_product();
}

static void fastboot_ui_info_variant(ui_textline_t *line)
{
	line->str = info_variant();
}

static void fastboot_ui_info_hw_version(ui_textline_t *line)
{
	line->str = SMBIOS_GET_STRING(1, Version);
}

static void fastboot_ui_info_bootloader_version(ui_textline_t *line)
{
	line->str = info_bootloader_version();
}

static void fastboot_ui_info_ifwi_version(ui_textline_t *line)
{
	line->str = SMBIOS_GET_STRING(0, BiosVersion);
}

static void fastboot_ui_info_serial_number(ui_textline_t *line)
{
	line->str = SMBIOS_GET_STRING(1, SerialNumber);
}

static void fastboot_ui_info_signing(ui_textline_t *line)
{
	BOOLEAN state = info_is_production_signing();

	line->str = state ? "PRODUCTION" : "DEVELOPMENT";
}

static void fastboot_ui_info_secure_boot(ui_textline_t *line)
{
	BOOLEAN state = is_efi_secure_boot_enabled();

	line->str = state ? "ENABLED" : "DISABLED";
	line->color = state ? &COLOR_GREEN : &COLOR_RED;
}

static void fastboot_ui_info_lock_state(ui_textline_t *line)
{
	line->str = get_current_state_string();
	line->color = get_current_state_color();
}

struct info_text_fun {
	const char *header;
	void (*get_value)(ui_textline_t *textline);
} const INFOS[] = {
	{ "PRODUCT NAME", fastboot_ui_info_product_name },
	{ "VARIANT", fastboot_ui_info_variant },
	{ "HW_VERSION", fastboot_ui_info_hw_version },
	{ "BOOTLOADER VERSION", fastboot_ui_info_bootloader_version },
	{ "IFWI VERSION", fastboot_ui_info_ifwi_version },
	{ "SERIAL NUMBER", fastboot_ui_info_serial_number },
	{ "SIGNING", fastboot_ui_info_signing },
	{ "SECURE BOOT", fastboot_ui_info_secure_boot },
	{ "LOCK STATE", fastboot_ui_info_lock_state }
};

static UINTN fastboot_ui_info_draw(UINTN x, UINTN y)
{
	static const UINTN LINE_LEN = 42;
	UINTN i;
	ui_textarea_t *textarea;
	char *dst;

	textarea = ui_textarea_create(ARRAY_SIZE(INFOS) + 2, LINE_LEN, fastboot_font, NULL);
	dst = AllocatePool(LINE_LEN);
	if (!dst)
		return y;

	memcpy(dst, "FASTBOOT MODE", strlen((CHAR8 *)"FASTBOOT MODE") + 1);
	ui_textarea_set_line(textarea, 0, dst, &COLOR_RED, TRUE);
	ui_textarea_set_line(textarea, 1, NULL, NULL, FALSE);
	for (i = 2; i < textarea->line_nb; i++) {
		char *dst = AllocatePool(LINE_LEN);
		if (!dst) {
			ui_textarea_free(textarea);
			return y;
		}

		ui_textline_t line = { &COLOR_WHITE, NULL, FALSE };
		INFOS[i - 2].get_value(&line);

		snprintf((CHAR8 *)dst, LINE_LEN, (CHAR8 *)"%a - %a",
			 INFOS[i - 2].header, line.str);
		ui_textarea_set_line(textarea, i, dst, line.color, line.bold);
	}

	ui_textarea_draw(textarea, x, y);
	ui_textarea_free(textarea);

	return y + textarea->height;
}

BOOLEAN fastboot_ui_confirm_for_state(enum device_state target)
{
	UINTN i;
	BOOLEAN result = FALSE;
	UINTN y = area_y;

	/* No way to ask for user confirmation, assume yes. */
	if (!fastboot_ui_initialized)
		return TRUE;

	for (i = 0; i < ARRAY_SIZE(FASTBOOT_UI_CONFIRM); i++)
		if (target == FASTBOOT_UI_CONFIRM[i].state) {
			fastboot_ui_clear_dynamic_part();
			ui_textarea_display_text(FASTBOOT_UI_CONFIRM[i].msg,
						 fastboot_font, area_x, &y);
			result = ui_input_to_bool(60);
			fastboot_ui_refresh();
		}

	return result;
}

void fastboot_ui_refresh(void)
{
	UINTN y = area_y;

	if (!fastboot_ui_initialized)
		return;

	fastboot_ui_clear_dynamic_part();
	ui_boot_menu_draw(boot_menu, area_x, &y);
	fastboot_ui_info_draw(area_x, y + 20);
}

EFI_STATUS fastboot_ui_init(void)
{
	ui_image_t *droid;
	UINTN width, height, x, y;
	EFI_STATUS ret = EFI_SUCCESS;

	ret = ui_init(&swidth, &sheight);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Init screen failed");
		return ret;
	}

	ui_clear_screen();

	margin = swidth * 10 / 100;
	ret = EFI_UNSUPPORTED;

	droid = ui_image_get(DROID_IMG_NAME);
	if (!droid) {
		efi_perror(EFI_OUT_OF_RESOURCES,
			   "Unable to load '%a' image",
			   DROID_IMG_NAME);
		return EFI_OUT_OF_RESOURCES;
	}

	if (swidth > sheight) {	/* Landscape orientation. */
		width = (swidth / 2) - (2 * margin);
		height = droid->height * width / droid->width;
		x = margin;
		y = (sheight / 2) - (height / 2);
	} else {		/* Portrait orientation. */
		height = sheight / 3;
		width = droid->width * height / droid->height;
		x = (swidth / 2) - (width / 2);
		y = margin;
	}

	ret = ui_image_draw_scale(droid, x, y, width, height);
	if (EFI_ERROR(ret))
		return ret;

	if (swidth > sheight) {	/* Landscape orientation. */
		area_x = swidth / 2 + margin;
		area_y = y;
	} else {		/* Portrait orientation. */
		area_x = x;
		area_y = sheight / 2;
	}

	fastboot_font = ui_font_get(FASTBOOT_FONT_NAME);
	if (!fastboot_font) {
		efi_perror(EFI_UNSUPPORTED, "Unable to find '%a' font",
			   FASTBOOT_FONT_NAME);
		return EFI_UNSUPPORTED;
	}

	boot_menu = ui_boot_menu_create(BOOT_ACTIONS, fastboot_font);
	if (!boot_menu) {
		error(L"Failed to build boot menu");
		return EFI_OUT_OF_RESOURCES;
	}

	fastboot_ui_initialized = TRUE;

	fastboot_ui_refresh();

	uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);

	return ret;
}

enum boot_target fastboot_ui_event_handler()
{
	return ui_boot_menu_event_handler(boot_menu, ui_read_input());
}

void fastboot_ui_destroy(void)
{
	ui_boot_menu_free(boot_menu);
	ui_print_clear();
	ui_display_vendor_splash();
	fastboot_ui_initialized = FALSE;
}
