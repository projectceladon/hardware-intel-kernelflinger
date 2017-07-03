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
#include "timer.h"
#ifdef __SUPPORT_ABL_BOOT
#ifdef USE_AVB
#include "avb_init.h"
#include "libavb/libavb.h"
#include "libavb/uefi_avb_ops.h"
#endif
#include "security.h"

#include <libtipc.h>

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
	CHAR8 *secureboot_str = (CHAR8 *)"ABL.secureboot=";
	UINTN secureboot_str_len;

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
	secureboot_str_len = strlen((CHAR8 *)secureboot_str);

	/*Parse boot target*/
	for (i = 0; i < argc; i++) {
		debug(L" abl cmd %02d: %s", i, argv[i]);
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
			} else if ((arglen > secureboot_str_len) && (!strncmp(arg8, (CHAR8 *)secureboot_str, secureboot_str_len))) {
				UINT8 val;
				CHAR8 *nptr = (CHAR8 *)(arg8 + secureboot_str_len);
                                val = (UINT8)strtoul((char *)nptr, 0, 10);
				ret = set_abl_secure_boot(val);
				if (EFI_ERROR(ret))
					efi_perror(ret, L"Failed to set secure boot");
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
#ifndef USE_AVB
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
#endif


#ifdef USE_AVB
static EFI_STATUS start_boot_image(VOID *bootimage, UINT8 boot_state,
				enum boot_target boot_target,
				AvbSlotVerifyData *slot_data,
				CHAR8 *abl_cmd_line)
#else
static EFI_STATUS start_boot_image(VOID *bootimage, UINT8 boot_state,
				enum boot_target boot_target,
				X509 *verifier_cert,
				CHAR8 *abl_cmd_line)
#endif
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

#ifndef USE_SLOT
	ret = slot_boot(boot_target);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write slot boot");
		return ret;
	}
#endif
	log(L"chainloading boot image, boot state is %s\n",
	boot_state_to_string(boot_state));
#ifdef USE_AVB
	ret = android_image_start_buffer_abl(bootimage,
						boot_target, boot_state, NULL,
						slot_data, (const CHAR8 *)abl_cmd_line);
#else
        ret = android_image_start_buffer_abl(bootimage,
						boot_target, boot_state, NULL,
						verifier_cert, (const CHAR8 *)abl_cmd_line);
#endif
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

#ifndef USE_AVB
/* Validate an image.
 *
 * Parameters:
 * boot_target    - Boot image to load. Values supported are NORMAL_BOOT,
 *                  RECOVERY, and ESP_BOOTIMAGE (for 'fastboot boot')
 * bootimage      - Bootimage to validate
 * verifier_cert  - Return the certificate that validated the boot image
 *
 * Return values:
 * BOOT_STATE_GREEN  - Boot image is valid against provided certificate
 * BOOT_STATE_YELLOW - Boot image is valid against embedded certificate
 * BOOT_STATE_RED    - Boot image is not valid
 */
static UINT8 validate_bootimage(
		IN enum boot_target boot_target,
		IN VOID *bootimage,
		OUT X509 **verifier_cert)
{
	CHAR16 target[BOOT_TARGET_SIZE];
	CHAR16 *expected;
	CHAR16 *expected2 = NULL;
	UINT8 boot_state;

	boot_state = verify_android_boot_image(bootimage, oem_cert,
						oem_cert_size, target,
						verifier_cert);

	if (boot_state == BOOT_STATE_RED) {
		error(L"boot image doesn't verify");
		return boot_state;
	}

	switch (boot_target) {
	case NORMAL_BOOT:
	case MEMORY:
		expected = L"/boot";
		/* in case of multistage ota */
		expected2 = L"/recovery";
		break;
	case CHARGER:
		expected = L"/boot";
		break;
	case RECOVERY:
		if (recovery_in_boot_partition())
			expected = L"/boot";
		else
			expected = L"/recovery";
		break;
	case ESP_BOOTIMAGE:
		/* "live" bootable image */
		expected = L"/boot";
		break;
	default:
		expected = NULL;
	}

	if ((!expected || StrCmp(expected, target)) &&
		(!expected2 || StrCmp(expected2, target))) {
		error(L"boot image has unexpected target name");
		return BOOT_STATE_RED;
	}

	return boot_state;
}
#endif

#ifdef USE_AVB
EFI_STATUS avb_boot_android(enum boot_target boot_target, CHAR8 *abl_cmd_line)
{
	AvbOps *ops;
	const char *slot_suffix = "";
	AvbPartitionData *boot;
	AvbSlotVerifyData *slot_data;
	AvbSlotVerifyResult verify_result;
	const char *requested_partitions[] = {"boot", NULL};
	EFI_STATUS ret;
	VOID *bootimage = NULL;
        const struct boot_img_hdr *header;
	UINT8 boot_state = BOOT_STATE_GREEN;
	bool allow_verification_error = FALSE;

	debug(L"Loading boot image");
	if (boot_target == RECOVERY) {
		requested_partitions[0] = "recovery";
	}

	ops = avb_init();
	if (ops) {
		if (ops->read_is_device_unlocked(ops, &allow_verification_error) != AVB_IO_RESULT_OK) {
			avb_fatal("Error determining whether device is unlocked.\n");
			return EFI_ABORTED;
		}
	}
	else {
		return EFI_OUT_OF_RESOURCES;
	}

#ifdef USE_SLOT
	slot_suffix = slot_get_active();
	if (!slot_suffix) {
		error(L"suffix is null");
		slot_suffix = "";
	}
#endif

        verify_result = avb_slot_verify(ops,
                                      requested_partitions,
                                      slot_suffix,
                                      allow_verification_error,
                                      &slot_data);

	if (slot_data->num_loaded_partitions != 1) {
		avb_error("No boot partition.\n");
		ret = EFI_LOAD_ERROR;
		return ret;
	}

	boot = &slot_data->loaded_partitions[0];

	header = (const struct boot_img_hdr *)boot->data;
	bootimage = boot->data;
	/* Check boot image header magic field. */
	if (avb_memcmp(BOOT_MAGIC, header->magic, BOOT_MAGIC_SIZE)) {
		avb_error("Wrong boot image header magic.\n");
		ret = EFI_NOT_FOUND;
		return ret;
	}
	avb_debug("boot image read success\n");
	avb_debugv("slot",
		slot_suffix,
		" which verified "
		"with result ",
		avb_slot_verify_result_to_string(verify_result),
		" .\n",
		NULL);
	switch (verify_result) {
	case AVB_SLOT_VERIFY_RESULT_OK:
		if (allow_verification_error) {
			boot_state = BOOT_STATE_ORANGE;
		}
		else {
			boot_state = BOOT_STATE_GREEN;
		}
		break;

	case AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION:
	case AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX:
	case AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED:
		if (allow_verification_error) {
		/* Do nothing since we allow this. */
			avb_debugv("Allowing slot ",
			slot_suffix,
			" which verified "
			"with result ",
			avb_slot_verify_result_to_string(verify_result),
			" because |allow_verification_error| is true.\n",
			NULL);
			boot_state = BOOT_STATE_ORANGE;
		}
		else {
			boot_state = BOOT_STATE_RED;
		}
		break;
	default:
		if (allow_verification_error) {
			boot_state = BOOT_STATE_ORANGE;
		}
		else {
			boot_state = BOOT_STATE_RED;
		}
		break;
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

		trusty_ipc_init();
		trusty_ipc_shutdown();
	}

	ret = start_boot_image(bootimage, boot_state, boot_target, slot_data, abl_cmd_line);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to start boot image");
		return ret;
	}
        return EFI_SUCCESS;
}
#endif

#ifndef USE_AVB
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
	boot_state = validate_bootimage(boot_target, bootimage, &verifier_cert);
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

		trusty_ipc_init();
		trusty_ipc_shutdown();
	}

	ret = start_boot_image(bootimage, boot_state, boot_target, verifier_cert, abl_cmd_line);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to start boot image");
		return ret;
	}

	return EFI_INVALID_PARAMETER;
}
#endif
#endif	// __SUPPORT_ABL_BOOT

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table)
{
	enum boot_target target;
	EFI_STATUS ret;

	set_boottime_stamp(0);
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

#ifdef __FORCE_FASTBOOT
	target = FASTBOOT;
#endif
	debug(L"target=%d", target);
	for (;;) {
		switch (target) {
#ifdef __SUPPORT_ABL_BOOT
		case NORMAL_BOOT:
		case RECOVERY:
#ifdef USE_AVB
			ret = avb_boot_android(target, cmd_buf);
#else
			ret = boot_android(target, cmd_buf);
#endif
			if (EFI_ERROR(ret))
				target = FASTBOOT;
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
