/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors:  Jeremy Compostella <jeremy.compostella@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
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
#include <ui.h>

#define NOT_READY_USECS	(100 * 1000)

extern EFI_GUID GraphicsOutputProtocol;

EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_BLACK	= { 0, 0, 0, 0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_WHITE	= { 255, 255, 255, 0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_LIGHTGRAY = { 127, 127, 127, 0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_LIGHTRED  = { 127, 0, 0, 0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_YELLOW	= { 255, 255, 0, 0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_RED	= { 255, 0, 0, 0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_GREEN	= { 0, 255, 0, 0 };


static BOOLEAN initialized = FALSE;

typedef struct graphic {
	EFI_GRAPHICS_OUTPUT_PROTOCOL *output;
	UINT32 width;
	UINT32 height;
	UINT32 mode;
} graphic_t;

static graphic_t graphic;

static ui_textarea_t *default_textarea = NULL;
static UINTN default_textarea_x;
static UINTN default_textarea_y;

static const char *VENDOR_IMG_NAME = "splash_intel";
static BOOLEAN ui_display_splash = FALSE;

EFI_STATUS ui_init(UINTN *width_p, UINTN *height_p, BOOLEAN display_splash)
{
	UINT32 mode;
	UINTN info_size;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
	EFI_STATUS ret;
	BOOLEAN last_succeed = FALSE;

	if (initialized) {
		*width_p = graphic.width;
		*height_p = graphic.height;
		return EFI_SUCCESS;
	}

	ui_display_splash = display_splash;

	ret = LibLocateProtocol(&GraphicsOutputProtocol, (VOID **)&graphic.output);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Unable to locate graphics output protocol, graphic disabled");
		graphic.output = NULL;
		return ret;
	}

	/* Set the best mode possible. */
	for (mode = 0 ; mode < graphic.output->Mode->MaxMode ; mode++) {
		ret = uefi_call_wrapper(graphic.output->QueryMode, 4, graphic.output,
					mode, &info_size, &info);

		if (last_succeed
		    && (graphic.width > info->HorizontalResolution
			|| graphic.height > info->VerticalResolution))
			continue;

		ret = uefi_call_wrapper(graphic.output->SetMode, 2, graphic.output, mode);
		if (EFI_ERROR(ret)) {
			debug(L"Failed to set mode=%d (%dx%d): %r", graphic.mode,
			      graphic.width, graphic.height, ret);
			continue;
		}

		last_succeed = TRUE;
		graphic.width = info->HorizontalResolution;
		graphic.height = info->VerticalResolution;
		graphic.mode = mode;
	}

	if (!last_succeed)
		return EFI_UNSUPPORTED;

	ret = ui_default_screen();
	if (EFI_ERROR(ret))
		return ret;

	*width_p = graphic.width;
	*height_p = graphic.height;

	initialized = TRUE;

	return EFI_SUCCESS;
}

EFI_STATUS ui_default_screen(void)
{
	UINTN width, height, x, y, margin;
	ui_image_t *vendor;
	ui_font_t *font;

	if (!graphic.output)
		return EFI_UNSUPPORTED;

	/* Initialize log area */
	margin = graphic.width / 10;
	if (!default_textarea) {
		font = ui_font_get("12x22");
		if (!font)
			return EFI_UNSUPPORTED;

		x = margin / font->cheight;
		y = (graphic.width - (2 * margin)) / font->cwidth;
		default_textarea = ui_textarea_create(x, y, font, &COLOR_YELLOW);
		if (!default_textarea) {
			efi_perror(EFI_OUT_OF_RESOURCES, "Failed to build the textarea");
			return EFI_OUT_OF_RESOURCES;
		}

		default_textarea_x = margin;
		default_textarea_y = graphic.height - margin;
	}

	if (!ui_display_splash)
		return EFI_SUCCESS;

	ui_clear_screen();

	/* Vendor splash */
	vendor = ui_image_get(VENDOR_IMG_NAME);
	if (!vendor) {
		efi_perror(EFI_UNSUPPORTED, "Unable to get '%a' image",
			   VENDOR_IMG_NAME);
		return EFI_UNSUPPORTED;
	}

	margin = graphic.width * 20 / 100;
	if (graphic.width > graphic.height) { /* Landscape orientation. */
		width = graphic.width - (2 * margin);
		height = vendor->height * width / vendor->width;
		x = margin;
		y = (graphic.height / 2) - (height / 2);
	} else {		/* Portrait orientation. */
		height = graphic.height / 3;
		width = vendor->width * height / vendor->height;
		x = (graphic.width / 2) - (width / 2);
		y = margin;
	}

	ui_image_draw_scale(vendor, x, y , width, height);

	return EFI_SUCCESS;
}

void ui_free(void)
{
	if (!default_textarea)
		return;

	ui_textarea_free(default_textarea);
	default_textarea = NULL;
}

BOOLEAN ui_is_ready()
{
	return initialized;
}

EFI_STATUS ui_clear_screen()
{
	if (!ui_is_ready())
		return EFI_UNSUPPORTED;

	return ui_clear_area(0, 0, graphic.width, graphic.height);
}

EFI_STATUS ui_clear_area(UINTN x, UINTN y, UINTN width, UINTN height)
{
	EFI_STATUS ret;

	if (!ui_is_ready())
		return EFI_UNSUPPORTED;

	ret = uefi_call_wrapper(graphic.output->Blt, 10, graphic.output,
				(EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)&COLOR_BLACK,
				EfiBltVideoFill, 0, 0, x, y, width, height, 0);

	if (default_textarea)
		ret = ui_textarea_draw(default_textarea, default_textarea_x,
				       default_textarea_y);

	return ret;
}

EFI_STATUS ui_draw_blt(EFI_GRAPHICS_OUTPUT_BLT_PIXEL *blt, UINTN x, UINTN y,
		       UINTN width, UINTN height)
{
	EFI_STATUS ret;

	if (!graphic.output)
		return EFI_UNSUPPORTED;

	ret = uefi_call_wrapper(graphic.output->Blt, 10, graphic.output, blt, EfiBltBufferToVideo,
				0, 0, x, y, width, height, 0);
	if (EFI_ERROR(ret))
		efi_perror(ret, "Failed to display blt");

	return ret;
}

static char *build_str(CHAR16 *fmt, va_list args)
{
	CHAR16 buf[default_textarea ? default_textarea->row_nb : 200];
	char *str = NULL;
	UINTN len;

	if (!ui_is_ready())
		return NULL;

	len = VSPrint(buf, sizeof(buf), fmt, args);

	str = AllocatePool(len + 1);
	if (!str)
		return NULL;

	if (EFI_ERROR(str_to_stra((CHAR8 *)str, buf, len + 1))) {
		FreePool(str);
		return NULL;
	}

	str[len] = '\0';
	return str;
}

static void ui_print_string(EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color, char *str)
{
	ui_textarea_newline(default_textarea, str, color, FALSE);
	ui_textarea_draw(default_textarea, default_textarea_x, default_textarea_y);
}

void ui_print(CHAR16 *fmt, ...)
{
	va_list args;
	char *str;

	if (!ui_is_ready())
		return;

	va_start(args, fmt);
	str = build_str(fmt, args);
	if (!str)
		return;

	ui_print_string(NULL, str);
}

void ui_error(CHAR16 *fmt, ...)
{
	va_list args;
	char *str;

	if (!ui_is_ready())
		return;

	va_start(args, fmt);
	str = build_str(fmt, args);
	if (!str)
		return;

	ui_print_string(&COLOR_RED, (char *)str);
}

void ui_print_clear(void)
{
	if (!ui_is_ready())
		return;

	ui_textarea_clear(default_textarea);
}

ui_events_t ui_read_input(void)
{
	EFI_INPUT_KEY key;
	EFI_STATUS ret;

	ret = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
				ST->ConIn, &key);

	if (ret == EFI_SUCCESS) {
		switch (key.ScanCode) {
		case SCAN_UP:
		case SCAN_PAGE_UP:
		case SCAN_HOME:
		case SCAN_RIGHT:
			return EV_UP;
		case SCAN_DOWN:
		case SCAN_PAGE_DOWN:
		case SCAN_END:
		case SCAN_LEFT:
			return EV_DOWN;
		default:
			break;
		}
	}

	return EV_NONE;
}

ui_events_t ui_wait_for_input(UINTN timeout_secs)
{
	UINT64 timeout_left;

	timeout_left = timeout_secs * 1000000;

	uefi_call_wrapper(BS->Stall, 1, 500 * 1000);
	uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);

	do {
		ui_events_t event = ui_read_input();
		if (event != EV_NONE)
			return event;

		/* If we get here, either we had EFI_NOT_READY indicating
		 * no pending keystroke, EFI_DEVICE_ERROR, or some key
		 * we don't care about was pressed */

		uefi_call_wrapper(BS->Stall, 1, NOT_READY_USECS);
		timeout_left -= NOT_READY_USECS;
	} while (timeout_left);

	halt_system();
}

BOOLEAN ui_input_to_bool(UINTN timeout_secs)
{
	return ui_wait_for_input(timeout_secs) == EV_UP ? TRUE : FALSE;
}
