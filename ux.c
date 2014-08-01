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

#include "kernelflinger.h"
#include "ux.h"

#define TIMEOUT_SECS	60
#define NOT_READY_USECS	(100 * 1000)

enum key_events {
	EV_UP,
	EV_DOWN,
	EV_TIMEOUT,
};

struct text_line {
	UINTN color;
	CHAR16 *text;
};

static const struct text_line red_state[] = {
	{EFI_LIGHTRED, L"RECOVER"},
	{EFI_WHITE, L"Press Volume UP key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTRED, L"POWER OFF"},
	{EFI_WHITE, L"Press Volume DOWN key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTGRAY, L"Your device is unable to start"},
	{EFI_LIGHTGRAY, L"because the boot image has"},
	{EFI_LIGHTGRAY, L"failed to verify."},
	{EFI_LIGHTGRAY, L""},
	{EFI_LIGHTGRAY, L"You may attempt to recover"},
	{EFI_LIGHTGRAY, L"the device."},
	{0, NULL} };

static const struct text_line bad_recovery[] = {
	{EFI_YELLOW, L"FASTBOOT"},
	{EFI_WHITE, L"Press Volume UP key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTRED, L"POWER OFF"},
	{EFI_WHITE, L"Press Volume DOWN key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTGRAY, L"Your device is unable to start"},
	{EFI_LIGHTGRAY, L"because the Recovery Console image has"},
	{EFI_LIGHTGRAY, L"failed to verify."},
	{EFI_LIGHTGRAY, L""},
	{EFI_LIGHTGRAY, L"You may repair your device with Fastboot."},
	{0, NULL } };

static const struct text_line device_altered_unlocked[] = {
	{EFI_YELLOW, L"START"},
	{EFI_WHITE, L"Press Volume UP key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTRED, L"FASTBOOT"},
	{EFI_WHITE, L"Press Volume DOWN key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTRED, L"WARNING:"},
	{EFI_LIGHTGRAY, L"Your device has been altered"},
	{EFI_LIGHTGRAY, L"from its factory configuration."},
	{EFI_LIGHTGRAY, L"and is no longer in a locked or"},
	{EFI_LIGHTGRAY, L"verified state."},
	{EFI_LIGHTGRAY, L""},
	{EFI_LIGHTGRAY, L"If you were not responsible for"},
	{EFI_LIGHTGRAY, L"these changes, the security of"},
	{EFI_LIGHTGRAY, L"your device may be at risk."},
	{EFI_LIGHTGRAY, L"Choose \"FASTBOOT\" to change"},
	{EFI_LIGHTGRAY, L"your device's state."},
	{0, NULL } };

static const struct text_line secure_boot_off[] = {
	{EFI_YELLOW, L"START"},
	{EFI_WHITE, L"Press Volume UP key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTRED, L"POWER OFF"},
	{EFI_WHITE, L"Press Volume DOWN key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTRED, L"WARNING:"},
	{EFI_LIGHTGRAY, L"Your device has been altered"},
	{EFI_LIGHTGRAY, L"from its factory configuration."},
	{EFI_LIGHTGRAY, L"and is no longer in a locked or"},
	{EFI_LIGHTGRAY, L"verified state due to UEFI Secure"},
	{EFI_LIGHTGRAY, L"Boot being disabled."},
	{EFI_LIGHTGRAY, L""},
	{EFI_LIGHTGRAY, L"If you were not responsible for"},
	{EFI_LIGHTGRAY, L"these changes, the security of"},
	{EFI_LIGHTGRAY, L"your device may be at risk."},
	{EFI_LIGHTGRAY, L"Enter BIOS setup to re-enable"},
	{EFI_LIGHTGRAY, L"UEFI Secure Boot."},
	{0, NULL } };

static const struct text_line device_altered_keystore[] = {
	{EFI_YELLOW, L"START"},
	{EFI_WHITE, L"Press Volume UP key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTRED, L"FASTBOOT"},
	{EFI_WHITE, L"Press Volume DOWN key"},
	{EFI_WHITE, L""},
	{EFI_LIGHTRED, L"WARNING:"},
	{EFI_LIGHTGRAY, L"Your device has been altered"},
	{EFI_LIGHTGRAY, L"from its factory configuration."},
	{EFI_LIGHTGRAY, L""},
	{EFI_LIGHTGRAY, L"If you were not responsible for"},
	{EFI_LIGHTGRAY, L"these changes, the security of"},
	{EFI_LIGHTGRAY, L"your device may be at risk."},
	{EFI_LIGHTGRAY, L"Choose \"FASTBOOT\" to clear"},
	{EFI_LIGHTGRAY, L"or upload a new user keystore."},
	{EFI_LIGHTGRAY, L""},
	{EFI_LIGHTGRAY, L"The device was unable to verify"},
	{EFI_LIGHTGRAY, L"the keystore with ID:"},
	{EFI_LIGHTGRAY, L""},
	{0, NULL } };


static enum key_events wait_for_input(VOID)
{
	EFI_INPUT_KEY key;
	UINT64 timeout_left;
	EFI_STATUS ret;

	timeout_left = TIMEOUT_SECS * 1000000;

	uefi_call_wrapper(BS->Stall, 1, 500 * 1000);
        uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);

	while (timeout_left) {
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

		/* If we get here, either we had EFI_NOT_READY indicating
		 * no pending keystroke, EFI_DEVICE_ERROR, or some key
		 * we don't care about was pressed */
		uefi_call_wrapper(BS->Stall, 1, NOT_READY_USECS);
		timeout_left -= NOT_READY_USECS;
	}
	return EV_TIMEOUT;
}


static VOID clear_screen(VOID)
{
	uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);
}


static VOID display_text(const struct text_line strings[])
{
	int i = 0;

	while (strings[i].text) {
		uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut,
				strings[i].color | EFI_BACKGROUND_BLACK);
		Print(L"%s\n", strings[i].text);
		i++;
	}
}

static BOOLEAN input_to_bool(VOID)
{
	enum key_events e = wait_for_input();
	switch (e) {
	case EV_TIMEOUT:
		halt_system();
	case EV_UP:
		return TRUE;
	case EV_DOWN:
		return FALSE;
	}
	return FALSE;
}


BOOLEAN ux_prompt_user_keystore_unverified(UINT8 *hash) {
	clear_screen();
	display_text(device_altered_keystore);
	Print(L"%02x%02x-%02x%02x-%02x%02x\n",
			hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]);
	return input_to_bool();
}

BOOLEAN ux_warn_user_unverified_recovery(VOID) {
	clear_screen();
	display_text(bad_recovery);
	return input_to_bool();
}

BOOLEAN ux_prompt_user_bootimage_unverified(VOID) {
	clear_screen();
	display_text(red_state);
	return input_to_bool();
}

BOOLEAN ux_prompt_user_secure_boot_off(VOID) {
	clear_screen();
	display_text(secure_boot_off);
	return input_to_bool();
}

BOOLEAN ux_prompt_user_device_unlocked(VOID) {
	clear_screen();
	display_text(device_altered_unlocked);
	return input_to_bool();
}

EFI_STATUS ux_init(VOID) {
	uefi_call_wrapper(ST->ConOut->Reset, 2, ST->ConOut, FALSE);
        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut,
			EFI_WHITE | EFI_BACKGROUND_BLACK);
	uefi_call_wrapper(ST->ConOut->EnableCursor, 2, ST->ConOut, FALSE);

	return EFI_SUCCESS;
}


