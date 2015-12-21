/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Gaelle Nassiet <gaellex.nassiet@intel.com>
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

#ifdef USE_POWER_BUTTON

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

static const ui_textline_t yes_no_menu[][2] = {
	{ { &COLOR_WHITE, "Yes", TRUE }, { NULL, NULL, FALSE } },
	{ { &COLOR_WHITE, "No", TRUE }, { NULL, NULL, FALSE } }
};

static UINTN current = 1; /* dafault answer is No */

static EFI_STATUS ui_confirm_draw_menu(ui_font_t *font, UINTN x, UINTN y,
				       UINTN width, UINTN height)
{
	EFI_STATUS ret;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color;
	UINTN i, y1 = y;

	for (i = 0; i < ARRAY_SIZE(yes_no_menu); i++) {
		color = current == i ? &COLOR_HIGHLIGHT : &COLOR_BLACK;
		ui_fill_area(x, y1, width, height, color);
		ret = ui_textarea_display_text(yes_no_menu[i], font, x, &y1,
					       width, height, color);
		if (EFI_ERROR(ret))
			return ret;
	}

	return EFI_SUCCESS;
}
#else
static const ui_textline_t yes_no_text[] = {
	{ &COLOR_YELLOW,	"YES",				TRUE },
	{ &COLOR_WHITE,		"Press Volume UP key",		FALSE },
	{ &COLOR_WHITE,		"",				FALSE },
	{ &COLOR_YELLOW,	"NO",				TRUE },
	{ &COLOR_WHITE,		"Press Volume DOWN key",	FALSE },
	{ NULL, NULL, FALSE }
};
#endif

#define TIMEOUT_SECS 60
BOOLEAN ui_confirm(const ui_textline_t *text, UINTN width, UINTN height,
		   UINTN x, UINTN y)
{
	ui_events_t event;

#ifdef USE_POWER_BUTTON
	UINTN line_nb, len, row_nb = 0;
	EFI_STATUS ret;
	ui_font_t *font;
	UINTN text_height, scaled_text_height, scaled_text_width, line_height;

	font = ui_font_get_default();
	if (!font) {
		error(L"Default font not available");
		return FALSE;
	}

	for (line_nb = 0; text[line_nb].str; line_nb++) {
		len = strlen((CHAR8 *)text[line_nb].str);
		row_nb = row_nb < len ? len : row_nb;
	}

	if (!line_nb || !row_nb) {
		error(L"Invalid text for ui_confirm");
		return FALSE;
	}

	text_height = line_nb * height / (line_nb + ARRAY_SIZE(yes_no_menu));
	ret = ui_textarea_display_text(text, font, x, &y, width, text_height, NULL);
	if (EFI_ERROR(ret))
		return FALSE;

	ui_get_scaled_dimension((row_nb * font->cwidth), (line_nb * font->cheight),
				width, text_height, &scaled_text_width, &scaled_text_height);
	line_height = scaled_text_height / line_nb;

	ret = ui_confirm_draw_menu(font, x, y, scaled_text_width, line_height);
	if (EFI_ERROR(ret))
		return FALSE;
	for (;;) {
		event = ui_wait_for_input(TIMEOUT_SECS);
		switch (event) {
		case EV_UP:
		case EV_DOWN:
			current = (current + 1) % ARRAY_SIZE(yes_no_menu);
			ret = ui_confirm_draw_menu(font, x, y, scaled_text_width, line_height);
			if (EFI_ERROR(ret))
				return FALSE;
			break;
		case EV_POWER:
			return !current;
		default:
			break;
		}
	}
#else
	const ui_textline_t *texts[] = {text, yes_no_text};
	ui_display_texts(texts, x, y, width, height);
	event = ui_wait_for_input(TIMEOUT_SECS);
	return event == EV_UP ? TRUE : FALSE;
#endif
}
