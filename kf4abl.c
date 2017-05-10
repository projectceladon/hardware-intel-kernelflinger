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
#ifdef IOC_USE_SLCAN
#include "ioc_can.h"
#endif
#include "android.h"
#include "slot.h"
#ifdef __SUPPORT_ABL_BOOT
#include "security.h"

#define MAX_CMD_BUF 0x1000
static CHAR8 cmd_buf[MAX_CMD_BUF];

typedef struct {
	/* version of the struct. 0x0001 for this version */
	uint16_t 			Version;
	/* Trusty’s mem base address */
	uint32_t 			TrustyMemBase;
	/* assumed to be 16MB */
	uint32_t 			TrustyMemSize;
	/* seed value retrieved from CSE */
	uint8_t 			seed[32];
	struct rot_data_t 	RotData;
}__attribute__((packed)) trusty_boot_params_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t patch_M:4;
		uint32_t patch_Y:7;
		uint32_t version_C:7;
		uint32_t version_B:7;
		uint32_t version_A:7;
	};
} os_version_t;

static trusty_boot_params_t *p_trusty_boot_params = NULL;
#endif

struct abl_boot_info {
	UINT32 magic;
	UINT32 bootimage_len;
	UINT32 bootimage_crc;
	UINT32 bootimage_pos;
	UINT32 reserved1;
	UINT32 reserved2;
	UINT32 reserved3;
	UINT32 reserved4;
};

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

#ifdef __SUPPORT_ABL_BOOT
static EFI_STATUS process_bootimage(void *bootimage, UINTN imagesize)
{
	EFI_STATUS ret;

	if (bootimage) {
		/* 'fastboot boot' case, only allowed on unlocked devices.*/
		if (device_is_unlocked()) {
			UINT32 crc;

			ret = uefi_call_wrapper(BS->CalculateCrc32, 3, bootimage, imagesize, &crc);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"CalculateCrc32 failed");
				return ret;
			}

			ret = android_image_start_buffer_abl(bootimage,
								NORMAL_BOOT, BOOT_STATE_GREEN, NULL,
								NULL, (const CHAR8 *)cmd_buf);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"Couldn't load Boot image");
				return ret;
			}
		}
	}

	return EFI_SUCCESS;
}
#else
static EFI_STATUS process_bootimage(void *bootimage, UINTN imagesize)
{
	EFI_STATUS ret;

	if (bootimage) {
		/* 'fastboot boot' case, only allowed on unlocked devices.*/
		if (device_is_unlocked()) {
			struct bootloader_message bcb;
			struct abl_boot_info *p;
			UINT32 crc;

			ret = uefi_call_wrapper(BS->CalculateCrc32, 3, bootimage, imagesize, &crc);

			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"CalculateCrc32 failed");
				return ret;
			}

			memset(&bcb, 0, sizeof(struct bootloader_message));

			p = (struct abl_boot_info *)bcb.abl;
			p->magic = 0xABCDABCD;
			p->bootimage_len = imagesize;
			p->bootimage_crc = crc;
			p->bootimage_pos = (UINT32)bootimage;

			ret = write_bcb(MISC_LABEL, &bcb);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"Unable to update BCB contents!");
				return ret;
			}

			ret = reboot_to_target(NORMAL_BOOT, EfiResetWarm);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"Warm reset failed!");
				return ret;
			}
		}
	}

	return EFI_SUCCESS;
}
#endif

static EFI_STATUS enter_fastboot_mode(enum boot_target *target)
{
	EFI_STATUS ret;
	void *efiimage, *bootimage;
	UINTN imagesize;

#ifdef IOC_USE_SLCAN
	ret = notify_ioc_ready();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"notify ioc ready failed");
	}
#endif

	for (;;) {
		*target = UNKNOWN_TARGET;
		bootimage = NULL;
		efiimage = NULL;

		ret = fastboot_start(&bootimage, &efiimage, &imagesize, target);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Fastboot mode failed");
			break;
		}

		ret = process_bootimage(bootimage, imagesize);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Process bootimage failed");
			if (bootimage) {
				FreePool(bootimage);
				bootimage = NULL;
			}
			break;
		}

		if (*target == UNKNOWN_TARGET)
			continue;

		if ((*target == NORMAL_BOOT) || (*target == FASTBOOT))
			reboot_to_target(*target, EfiResetCold);
		break;
	}

	return ret;
}

#ifdef __SUPPORT_ABL_BOOT
static enum boot_target check_command_line(EFI_HANDLE image, CHAR8 *cmd_buf, UINTN max_cmd_size)
{
	EFI_STATUS ret;
	enum boot_target target = FASTBOOT;
	static EFI_LOADED_IMAGE *limg;
	UINTN argc, i;
	CHAR16 **argv;
	UINTN cmd_len = 0;
	CHAR8 arg8[256] = "";
	UINTN arglen;
	CHAR8 *trusty_str = (CHAR8 *)"trusty.param_addr=";
	UINTN trusty_str_len;

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

	cmd_buf[0] = 0;
	trusty_str_len = strlen((CHAR8 *)trusty_str);

	/*Parse boot target*/
	for (i = 0; i < argc; i++) {
		log(L" abl cmd %02d: ", i);
		log(L"%s\n", argv[i]);
		if (!StrCmp(argv[i], L"ABL.boot_target=CRASHMODE"))
			target = CRASHMODE;
		else if (!StrCmp(argv[i], L"ABL.boot_target=NORMAL_BOOT"))
			target = NORMAL_BOOT;
		else if (!StrCmp(argv[i], L"ABL.boot_target=RECOVERY"))
			target = RECOVERY;

		arglen = StrLen(argv[i]);
		if (arglen > (int)sizeof(arg8) - 2)
			arglen = sizeof(arg8) - 2;
		str_to_stra((CHAR8 *)arg8, argv[i], arglen + 1);
		if (cmd_len + arglen + 1 < max_cmd_size) {
			if (cmd_buf[0] != 0) {
				strncpy((CHAR8 *)(cmd_buf + cmd_len), (const CHAR8 *)" ", 1);
				cmd_len ++;
			}

			//Parse "trusty.param_addr=xxxxx"
			if ((arglen > trusty_str_len) && (!strncmp(arg8, (CHAR8 *)trusty_str, trusty_str_len))) {
				UINT32 num;
				CHAR8 *nptr = (CHAR8 *)(arg8 + trusty_str_len);
				num = strtoul((char *)nptr, 0, 16);
				debug(L"Parsed trusty param addr is 0x%x", num);
				p_trusty_boot_params = (trusty_boot_params_t *)num;
			} else {
				strncpy((CHAR8 *)(cmd_buf + cmd_len), (const CHAR8 *)arg8, arglen);
				cmd_len += arglen;
			}
		}
	}

	debug(L"boot target: %d", target);
	FreePool(argv);
	return target;
}
#else
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
#endif

#ifdef __SUPPORT_ABL_BOOT
/* Load a boot image into RAM.
 *
 * boot_target  - Boot image to load. Values supported are NORMAL_BOOT, RECOVERY,
 *                and ESP_BOOTIMAGE (for 'fastboot boot')
 * target_path  - Path to load boot image from for ESP_BOOTIMAGE case, ignored
 *                otherwise.
 * bootimage    - Returned allocated pointer value for the loaded boot image.
 * oneshot      - For ESP_BOOTIMAGE case, flag indicating that the image should
 *                be deleted.
 *
 * Return values:
 * EFI_INVALID_PARAMETER - Unsupported boot target type, key is not well-formed,
 *                         or loaded boot image was missing or corrupt
 * EFI_ACCESS_DENIED     - Validation failed against OEM or embedded certificate,
 *                         boot image still usable
 */
static EFI_STATUS load_boot_image(
				IN enum boot_target boot_target,
				IN CHAR16 *target_path,
				OUT VOID **bootimage,
				IN BOOLEAN oneshot)
{
	EFI_STATUS ret;

	switch (boot_target) {
	case NORMAL_BOOT:
	case CHARGER:
		ret = EFI_NOT_FOUND;
		if (use_slot() && !slot_get_active())
			break;
		do {
			const CHAR16 *label = slot_label(BOOT_LABEL);
			ret = android_image_load_partition(label, bootimage);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"Failed to load boot image from %s partition",
						label);
				if (use_slot())
					slot_boot_failed(boot_target);
			}
		} while (EFI_ERROR(ret) && slot_get_active());
		break;

	case RECOVERY:
		if (recovery_in_boot_partition()) {
			ret = load_boot_image(NORMAL_BOOT, target_path, bootimage, oneshot);
			break;
		}
		if (use_slot() && !slot_recovery_tries_remaining()) {
			ret = EFI_NOT_FOUND;
			break;
		}
		ret = android_image_load_partition(RECOVERY_LABEL, bootimage);
		break;
	default:
		*bootimage = NULL;
		return EFI_INVALID_PARAMETER;
	}

	if (!EFI_ERROR(ret))
		debug(L"boot image loaded");

	return ret;
}


static EFI_STATUS start_boot_image(VOID *bootimage, UINT8 boot_state,
				enum boot_target boot_target,
				X509 *verifier_cert,
				CHAR8 *abl_cmd_line)
{
	EFI_STATUS ret;
#ifdef USER
	/* per bootloaderequirements.pdf */
	if (boot_state == BOOT_STATE_ORANGE) {
		ret = android_clear_memory();
		if (EFI_ERROR(ret)) {
			error(L"Failed to clear memory. Load image aborted.");
			return ret;
		}
	}
#endif

	set_efi_variable(&fastboot_guid, BOOT_STATE_VAR, sizeof(boot_state),
					&boot_state, FALSE, TRUE);

#ifdef OS_SECURE_BOOT
	ret = set_os_secure_boot(boot_state == BOOT_STATE_GREEN);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to set os secure boot");
#endif

	ret = slot_boot(boot_target);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write slot boot");
		return ret;
	}

	debug(L"chainloading boot image, boot state is %s",
	boot_state_to_string(boot_state));
	ret = android_image_start_buffer_abl(bootimage,
						boot_target, boot_state, NULL,
						verifier_cert, (const CHAR8 *)abl_cmd_line);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Couldn't load Boot image");

	ret = slot_boot_failed(boot_target);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to write slot failure");

	return ret;
}

static EFI_STATUS init_trusty_rot_params(trusty_boot_params_t *param, UINT8 boot_state, VOID *image)
{
	EFI_STATUS ret;
	struct rot_data_t rot;

	ret = get_rot_data(image, boot_state, NULL, &rot);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get rot data");
		return ret;
	}

	if (!param)
		return EFI_INVALID_PARAMETER;

	param->RotData.version = rot.version;
	param->RotData.deviceLocked = rot.deviceLocked;
	param->RotData.verifiedBootState = rot.verifiedBootState;
	param->RotData.osVersion = rot.osVersion;
	param->RotData.patchMonthYear = rot.patchMonthYear;
	//key_size is initialized in ABL for now
	//key_hash256 is initialized in ABL for now

	debug(L"RotData.version = %d", param->RotData.version);
	debug(L"RotData.deviceLocked = %d", param->RotData.deviceLocked);
	debug(L"RotData.verifiedBootState = %d", param->RotData.verifiedBootState);
	debug(L"RotData.osVersion = %d", param->RotData.osVersion);
	debug(L"RotData.patchMonthYear = %d", param->RotData.patchMonthYear);
	debug(L"RotData.key_size = %d", param->RotData.key_size);
	return EFI_SUCCESS;
}

#define TRUSTY_VMCALL_SMC 0x74727500
static EFI_STATUS launch_trusty_os(trusty_boot_params_t *param)
{
	if (!param)
		return EFI_INVALID_PARAMETER;

	asm volatile(
		"vmcall; \n"
		: : "a"(TRUSTY_VMCALL_SMC), "D"((uint32_t)&param->RotData));

	return EFI_SUCCESS;
}

EFI_STATUS boot_android(enum boot_target boot_target, CHAR8 *abl_cmd_line)
{
	EFI_STATUS ret;
	CHAR16 *target_path = NULL;
	VOID *bootimage = NULL;
	BOOLEAN oneshot = FALSE;
	UINT8 boot_state = BOOT_STATE_GREEN;
	X509 *verifier_cert = NULL;

	debug(L"Loading boot image");
	ret = load_boot_image(boot_target, target_path, &bootimage, oneshot);
	FreePool(target_path);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to load boot image");
		return ret;
	}

	if (boot_target == NORMAL_BOOT) {
		ret = init_trusty_rot_params(p_trusty_boot_params, boot_state, bootimage);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to init trusty rot params");
			return ret;
		}

		ret = launch_trusty_os(p_trusty_boot_params);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to launch trusty os");
			return ret;
		}
	}

	ret = start_boot_image(bootimage, boot_state, boot_target, verifier_cert, abl_cmd_line);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to start boot image");
		return ret;
	}

	return EFI_INVALID_PARAMETER;
}
#endif	// __SUPPORT_ABL_BOOT

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table)
{
	enum boot_target target;
	EFI_STATUS ret;

	InitializeLib(image, sys_table);
#ifdef __SUPPORT_ABL_BOOT
	target = check_command_line(image, cmd_buf, sizeof(cmd_buf) - 1);
#else
	target = check_command_line(image);
#endif

	ret = slot_init();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Slot management initialization failed");
		return ret;
	}

	for (;;) {
		switch (target) {
#ifdef __SUPPORT_ABL_BOOT
		case NORMAL_BOOT:
		case RECOVERY:
			boot_android(target, cmd_buf);
			break;
#endif
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
			reboot_to_target(target, EfiResetCold);
		}
	}

	return EFI_SUCCESS;
}
