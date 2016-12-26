/*
 * Copyright (c) 2016, Intel Corporation
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
#include <efiapi.h>
#include <lib.h>
#include <fastboot.h>
#ifdef CRASHMODE_USE_ADB
#include <adb.h>
#endif

#include "options.h"
#include "ioc_can.h"

#ifdef CRASHMODE_USE_ADB
static EFI_STATUS enter_crashmode(enum boot_target *target)
{
	EFI_STATUS ret;

#ifdef USER
#error "adb in crashmode MUST be disabled on a USER build"
#endif

	ret = adb_init();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to initialize adb");
		return ret;
	}

	debug(L"adb implementation is initialized");
	for (;;) {
		ret = adb_run();
		if (EFI_ERROR(ret))
			break;

		*target = adb_get_boot_target();
		if (*target != UNKNOWN_TARGET)
			break;
	}
	adb_exit();

	return ret;
}
#endif

static EFI_STATUS enter_fastboot_mode(enum boot_target *target)
{
	EFI_STATUS ret;
	void *efiimage, *bootimage;
	UINTN imagesize;

	ret = notify_ioc_ready();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"notify ioc ready failed");
	}

	for (;;) {
		*target = UNKNOWN_TARGET;
		bootimage = NULL;
		efiimage = NULL;

		ret = fastboot_start(&bootimage, &efiimage, &imagesize, target);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Fastboot mode failed");
			break;
		}

		if (*target == UNKNOWN_TARGET)
			continue;

		if ((*target == NORMAL_BOOT) || (*target == FASTBOOT))
			reboot_to_target(*target);
		break;
	}

	return ret;
}

static enum boot_target check_command_line(EFI_HANDLE image)
{
	EFI_STATUS ret;
	enum boot_target target = FASTBOOT;
	static EFI_LOADED_IMAGE *limg;
	UINTN argc, i;
        CHAR16 **argv;

        ret = uefi_call_wrapper(BS->OpenProtocol, 6, image,
				&LoadedImageProtocol, (VOID **)&limg,
				image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open LoadedImageProtocol");
		return FASTBOOT;
	}

	ret = get_argv(limg, &argc, &argv);
	if (EFI_ERROR(ret))
		return FASTBOOT;

	for (i = 0; i < argc; i++)
		if (!StrCmp(argv[i], L"-c"))
			target = CRASHMODE;

	FreePool(argv);
	return target;
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table)
{
	enum boot_target target;

	InitializeLib(image, sys_table);
	target = check_command_line(image);

	for (;;) {
		switch (target) {
		case UNKNOWN_TARGET:
#ifndef CRASHMODE_USE_ADB
		case CRASHMODE:
#endif
		case FASTBOOT:
			enter_fastboot_mode(&target);
			break;
#ifdef CRASHMODE_USE_ADB
		case CRASHMODE:
			enter_crashmode(&target);
			break;
#endif
		default:
			reboot_to_target(target);
		}
	}

	return EFI_SUCCESS;
}
