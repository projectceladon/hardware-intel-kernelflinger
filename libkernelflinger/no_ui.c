/*
 * Copyright (c) 2016, Intel Corporation
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
#include <log.h>
#include <lib.h>
#include <ui.h>

#define NOT_READY_USECS		(100 * 1000)
/* Time between calls to ReadKeyStroke to check if it is being actively held
 * Smaller stall values seem to result in false reporting of no key pressed
 * on several devices */
#define HOLD_KEY_STALL_TIME	500
#define HOLD_KEY_STALL_TIME_MAX	(10 * 1000)

static inline void ui_log(CHAR16 *fmt, va_list args)
{
	vlog(fmt, args);
	log(L"\n");
}

void ui_print(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ui_log(fmt, args);
	va_end(args);
}

void ui_info(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ui_log(fmt, args);
	va_end(args);
}

void ui_info_n(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlog(fmt, args);
	va_end(args);
}

void ui_warning(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ui_log(fmt, args);
	va_end(args);
}

void ui_error(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ui_log(fmt, args);
	va_end(args);
}

void ui_free(void)
{
	/* Nothing to do */
}

void ui_wait_for_key_release(void)
{
	/* Nothing to do */
}

/* Some UI related functions used in Kernelflinegr */
static int get_hold_key_stall_time(void)
{
	EFI_STATUS ret;
	static unsigned long hold_key_stall_time;

	if (hold_key_stall_time)
		goto out;

	ret = get_efi_variable_long_from_str8(&loader_guid,
					     HOLD_KEY_STALL_TIME_VAR,
					     &hold_key_stall_time);
	if (EFI_ERROR(ret)) {
		debug(L"Couldn't read timeout variable; assuming default");
	} else {
		if (hold_key_stall_time > 0 &&
		    hold_key_stall_time < HOLD_KEY_STALL_TIME_MAX) {
			debug(L"hold_key_stall_time=%d ms", hold_key_stall_time);
			goto out;
		}
		debug(L"pathological key stall time, use default");
	}

	hold_key_stall_time = HOLD_KEY_STALL_TIME;
out:
	return hold_key_stall_time;
}

ui_events_t ui_keycode_to_event(UINT16 keycode)
{
	switch (keycode) {
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
#ifdef USE_POWER_BUTTON
		case SCAN_POWER:
			return EV_POWER;
#endif
	default:
		return EV_NONE;
	}
}

ui_events_t ui_read_input(void)
{
	EFI_INPUT_KEY key;
	EFI_STATUS ret;

	ret = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
				ST->ConIn, &key);

	if (ret != EFI_SUCCESS)
		return EV_NONE;

	return ui_keycode_to_event(key.ScanCode);
}

static BOOLEAN test_key(BOOLEAN check_code, ui_events_t event)
{
	EFI_INPUT_KEY key;
	EFI_STATUS ret = EFI_SUCCESS;
	BOOLEAN result = TRUE;

	uefi_call_wrapper(BS->Stall, 1, get_hold_key_stall_time() * 1000);

	ret = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
					ST->ConIn, &key);
	if (ret != EFI_SUCCESS) {
		debug(L"err=%r", ret);
		return FALSE;
	}

	if (check_code)
		result = (ui_keycode_to_event(key.ScanCode) == event);

	/* flush any stacked up key events in the queue before
	 * we sleep again */
	while (uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
				 ST->ConIn, &key) == EFI_SUCCESS) {
		/* spin */
	}

	return result;
}

BOOLEAN ui_enforce_key_held(UINT32 milliseconds, ui_events_t event)
{
	BOOLEAN ret = TRUE;
	UINT32 i;
	int stall_time = get_hold_key_stall_time();

	for (i = 0; i < (milliseconds / stall_time); i++) {
		ret = test_key(TRUE, event);
		if (!ret) {
			break;
		}
	}
	return ret;
}
