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


#include <efi.h>
#include <efiapi.h>
#include <efilib.h>

#include "vars.h"
#include "lib.h"
#include "security.h"
#include "android.h"
#include "ux.h"
#include "options.h"
#include "power.h"

#define KERNELFLINGER_VERSION	L"kernelflinger-00.05"

/* Ensure this is embedded in the EFI binary somewhere */
static const char __attribute__((used)) magic[] = "### KERNELFLINGER ###";

/* For reading EFI globals */
static const EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;
#define SECURE_BOOT_VAR         L"SecureBoot"

enum boot_target {
        NORMAL_BOOT,
        RECOVERY,
        FASTBOOT,
        ESP_BOOTIMAGE,
        ESP_EFI_BINARY,
        MEMORY,
        CHARGER
};

/* Default max wait time for console reset in units of milliseconds if no EFI
 * variable is set for this platform.
 * You want this value as small as possible as this is added to
 * the boot time for EVERY boot */
#define EFI_RESET_WAIT_MS           50

/* Interval in ms to check on startup for initial press of magic key */
#define DETECT_KEY_STALL_TIME_MS    1

/* Time between calls to ReadKeyStroke to check if it is being actively held
 * Smaller stall values seem to result in false reporting of no key pressed
 * on several devices */
#define HOLD_KEY_STALL_TIME         (500 * 1000)

/* How long magic key should be held to force Fastboot mode */
#define FASTBOOT_HOLD_DELAY         (4 * 1000 * 1000)

/* If we find this in the root of the EFI system partition, unconditionally
 * load the Fastboot image */
#define FASTBOOT_SENTINEL         L"\\force_fastboot"

/* Path to Fastboot image */
#define FASTBOOT_PATH             L"\\fastboot.img"


static EFI_HANDLE g_parent_image;
static EFI_HANDLE g_disk_device;
static EFI_LOADED_IMAGE *g_loaded_image;

extern struct {
        UINT32 oem_keystore_size;
        UINT32 oem_key_size;
        UINT32 oem_keystore_offset;
        UINT32 oem_key_offset;
} oem_keystore_table;

static VOID *oem_keystore;
static UINTN oem_keystore_size;

static VOID *oem_key;
static UINTN oem_key_size;

#if DEBUG_MESSAGES
static CHAR16 *boot_target_to_string(enum boot_target bt)
{
        switch (bt) {
        case NORMAL_BOOT:
                return L"boot";
        case RECOVERY:
                return L"recovery";
        case FASTBOOT:
                return L"fastboot";
        case ESP_BOOTIMAGE:
                return L"ESP bootimage";
        case ESP_EFI_BINARY:
                return L"ESP efi binary";
        case MEMORY:
                return L"RAM bootimage";
        case CHARGER:
                return L"Charge mode";
        default:
                return L"unknown";
        }
}


static CHAR16 *boot_state_to_string(UINT8 boot_state)
{
        switch (boot_state) {
        case BOOT_STATE_GREEN:
                return L"GREEN";
        case BOOT_STATE_YELLOW:
                return L"YELLOW";
        case BOOT_STATE_ORANGE:
                return L"ORANGE";
        case BOOT_STATE_RED:
                return L"RED";
        default:
                return L"UNKNOWN";
        }
}
#endif

#ifndef INSECURE
static BOOLEAN is_efi_secure_boot_enabled(VOID)
{
        UINT8 sb;

        if (EFI_ERROR(get_efi_variable_byte(&global_guid, SECURE_BOOT_VAR,
                                        &sb)))
                return FALSE;
        return sb != 0;
}


static BOOLEAN is_device_locked_or_verified(VOID)
{
        UINT8 *data = NULL;
        UINTN dsize;
        BOOLEAN result;

        /* If we can't read the state, be safe and assume locked */
        if (EFI_ERROR(get_efi_variable(&fastboot_guid, OEM_LOCK_VAR,
                                        &dsize, (void **)&data)) || !dsize) {
                debug("Couldn't read OEMLock, assuming locked");
                result = TRUE;
                goto out;
        }

        /* Legacy OEMLock format, used to have string "0" or "1"
         * for unlocked/locked */
        if (dsize == 2 && data[1] == '\0') {
                if (data[0] == '0') {
                        result = FALSE;
                        goto out;
                }
                if (data[0] == '1') {
                        result = TRUE;
                        goto out;
                }
        }

        if (data[0] & OEM_LOCK_VERIFIED)
                result = TRUE;
        else if (data[0] & OEM_LOCK_UNLOCKED)
                result = FALSE;
        else
                result = TRUE;
out:
        FreePool(data);
        return result;
}

/* If a user-provided keystore is present it must be selected for later.
 * If no user-provided keystore is present then the original factory
 * keystore must be selected instead. Selection of a keystore is
 * independent of validation of that keystore. */
static VOID select_keystore(VOID **keystore, UINTN *size)
{
        if (EFI_ERROR(get_efi_variable(&fastboot_guid, KEYSTORE_VAR,
                                        size, keystore)) ||
                        *size == 0) {
                debug("selected OEM keystore");
                *keystore = oem_keystore;
                *size = oem_keystore_size;
        } else {
                debug("selected User-supplied keystore");
        }
}
#endif

static enum boot_target check_fastboot_sentinel(VOID)
{
        debug("checking ESP for %s", FASTBOOT_SENTINEL);
        if (file_exists(g_disk_device, FASTBOOT_SENTINEL))
                return FASTBOOT;
        return NORMAL_BOOT;
}


static enum boot_target check_magic_key(VOID)
{
        int i;
        EFI_STATUS ret = EFI_NOT_READY;
        EFI_INPUT_KEY key;
        enum boot_target bt;
        UINT8 *data;
        UINTN dsize;
        int wait_ms = EFI_RESET_WAIT_MS;

        debug("checking for magic key");
        uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);

        /* Some systems require a short stall before we can be sure there
         * wasn't a keypress at boot. Read the EFI variable which determines
         * that time for this platform */
        if (EFI_ERROR(get_efi_variable(&fastboot_guid, MAGIC_KEY_TIMEOUT_VAR,
                                        &dsize, (void **)&data)) || !dsize) {
                debug("Couldn't read timeout variable; assuming default");
        } else {
                if (data[dsize - 1] != '\0') {
                        debug("bad data for magic key timeout");
                        wait_ms = EFI_RESET_WAIT_MS;
                } else {
                        wait_ms = strtoul((char *)data, NULL, 10);
                        if (wait_ms < 0 || wait_ms > 1000) {
                                debug("pathological magic key timeout, use default");
                                wait_ms = EFI_RESET_WAIT_MS;
                        }
                }
        }

        debug("Reset wait time: %d", wait_ms);

        /* Check for 'magic' key. Some BIOSes are flaky about this
         * so wait for the ConIn to be ready after reset */
        for (i = 0; i <= wait_ms; i += DETECT_KEY_STALL_TIME_MS) {
                ret = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
                                        ST->ConIn, &key);
                if (ret == EFI_SUCCESS || i == wait_ms)
                        break;
                uefi_call_wrapper(BS->Stall, 1, DETECT_KEY_STALL_TIME_MS * 1000);
        }

        if (EFI_ERROR(ret))
                return NORMAL_BOOT;

        debug("ReadKeyStroke: (%d tries) %d %d", i, key.ScanCode, key.UnicodeChar);

        Print(L"Continue holding key for %d seconds to force Fastboot mode.\n",
                        FASTBOOT_HOLD_DELAY / 1000000);
        Print(L"Release key now to load Recovery Console.");

        for (i = 0; i < (FASTBOOT_HOLD_DELAY / HOLD_KEY_STALL_TIME); i++) {
                uefi_call_wrapper(BS->Stall, 1, HOLD_KEY_STALL_TIME);

                ret = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
                                ST->ConIn, &key);
                if (ret != EFI_SUCCESS) {
                        debug("err=%r", ret);
                        break;
                }
                Print(L".");

                /* flush any stacked up key events in the queue before
                 * we sleep again */
                while (uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
                                ST->ConIn, &key) == EFI_SUCCESS) {
                }
        }

        if (ret == EFI_SUCCESS) {
                bt = FASTBOOT;
                Print(L"FASTBOOT\n");
        } else {
                bt = RECOVERY;
                Print(L"RECOVERY\n");
        }

        /* In case we need to prompt the user about something, don't continue
         * until the key is released */
        while (1) {
                uefi_call_wrapper(BS->Stall, 1, HOLD_KEY_STALL_TIME);

                ret = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
                                ST->ConIn, &key);
                if (ret != EFI_SUCCESS) {
                        debug("err=%r", ret);
                        break;
                }

                /* flush */
                while (uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
                                ST->ConIn, &key) == EFI_SUCCESS) {
                }
        }
        return bt;
}


static enum boot_target check_bcb(CHAR16 **target_path, BOOLEAN *oneshot)
{
        EFI_STATUS ret;
        struct bootloader_message bcb;
        CHAR16 *target = NULL;
        enum boot_target t;

        debug("checking bootloader control block");
        *oneshot = FALSE;
        *target_path = NULL;

        ret = read_bcb(&misc_ptn_guid, &bcb);
        if (EFI_ERROR(ret)) {
                Print(L"Unable to read BCB\n");
                t = NORMAL_BOOT;
                goto out;
        }

        /* We own the status field; clear it in case there is any stale data */
        bcb.status[0] = '\0';

        if (!strncmpa(bcb.command, (CHAR8 *)"boot-", 5)) {
                target = stra_to_str(bcb.command + 5);
                debug("BCB boot target: '%s'", target);
        } else if (!strncmpa(bcb.command, (CHAR8 *)"bootonce-", 9)) {
                target = stra_to_str(bcb.command + 9);
                bcb.command[0] = '\0';
                debug("BCB oneshot boot target: '%s'", target);
                *oneshot = TRUE;
        }

        ret = write_bcb(&misc_ptn_guid, &bcb);
        if (EFI_ERROR(ret))
                Print(L"Unable to update BCB contents!\n");

        if (!target) {
                t = NORMAL_BOOT;
                goto out;
        }

        if (target[0] == L'\\') {
                UINTN len;

                if (!file_exists(g_disk_device, target)) {
                        Print(L"Specified BCB file '%s' doesn't exist\n",
                                        target);
                        t = NORMAL_BOOT;
                        goto out;
                }

                len = StrLen(target);
                if (len > 4) {
                        *target_path = StrDuplicate(target);
                        if (!StrCmp(target + (len - 4), L".efi") ||
                                        !StrCmp(target + (len - 4), L".EFI")) {
                                t = ESP_EFI_BINARY;
                        } else {
                                t = ESP_BOOTIMAGE;
                        }
                        goto out;
                }
                Print(L"BCB file '%s' appears to be malformed\n", target);
                t = NORMAL_BOOT;
                goto out;
        }

        if (!StrCmp(target, L"fastboot") || !StrCmp(target, L"bootloader")) {
                t = FASTBOOT;
                goto out;
        }

        if (!StrCmp(target, L"recovery")) {
                t = RECOVERY;
                goto out;
        }

        Print(L"Unknown boot target in BCB: '%s'\n", target);
        t = NORMAL_BOOT;

out:
        FreePool(target);
        return t;
}


static enum boot_target check_loader_entry_one_shot(VOID)
{
        CHAR16 *target;
        enum boot_target ret;

        debug("checking %s", LOADER_ENTRY_ONESHOT);
        target = get_efi_variable_str(&loader_guid, LOADER_ENTRY_ONESHOT);

        set_efi_variable(&loader_guid, LOADER_ENTRY_ONESHOT, 0, NULL,
                        TRUE, TRUE);

        if (!target || !StrCmp(target, L"")) {
                ret = NORMAL_BOOT;
        } else if (!StrCmp(target, L"fastboot") || !StrCmp(target, L"bootloader")) {
                ret = FASTBOOT;
        } else if (!StrCmp(target, L"recovery")) {
                ret = RECOVERY;
        } else if (!StrCmp(target, L"charging")) {
                ret = CHARGER;
        } else {
                Print(L"Unknown oneshot boot target: '%s'\n", target);
                ret = NORMAL_BOOT;
        }

        FreePool(target);
        return ret;
}


static enum boot_target check_command_line(VOID **address)
{
        UINTN argc, pos;
        CHAR16 **argv;
        enum boot_target bt;

        *address = NULL;
        bt = NORMAL_BOOT;

        debug("checking loader command line");

        if (EFI_ERROR(get_argv(g_loaded_image, &argc, &argv)))
                return NORMAL_BOOT;

        for (pos = 0; pos < argc; pos++) {
                debug("Argument %d: %s", pos, argv[pos]);

                if (!StrCmp(argv[pos], L"-a")) {
                        pos++;
                        if (pos >= argc) {
                                Print(L"-a requires a memory address\n");
                                goto out;
                        }

                        *address = (VOID *)strtoul16(argv[pos], NULL, 0);
                        bt = MEMORY;
                        continue;
                }

                /* If we get here the argument isn't recognized */
                if (pos == 0) {
                        /* EFI is inconsistent and only seems to populate the image
                         * name as argv[0] when called from a shell. Do nothing. */
                        continue;
                } else {
                        Print(L"unexpected argument %s\n", argv[pos]);
                        goto out;
                }
        }

out:
        FreePool(argv);
        return bt;
}


static enum boot_target check_charge_mode()
{
        enum wake_sources wake_source;
        CHAR16 *offmode;

        offmode = get_efi_variable_str8(&fastboot_guid, OFF_MODE_CHARGE);
        if (offmode) {
                BOOLEAN charger_off = !StrCmp(offmode, L"0");
                FreePool(offmode);
                if (charger_off) {
                        return NORMAL_BOOT;
                }
        }

        wake_source = rsci_get_wake_source();
        if ((wake_source == WAKE_USB_CHARGER_INSERTED) ||
            (wake_source == WAKE_ACDC_CHARGER_INSERTED))
                return CHARGER;

        return NORMAL_BOOT;
}


/* Policy:
 * 1. Check if the "-a xxxxxxxxx" command line was passed in, if so load an
 *    android boot image from RAM at that location.
 * 2. Check if the fastboot sentinel file \force_fastboot is present, and if
 *    so, force fastboot mode. Use in bootable media.
 * 3. Check for "magic key" being held. Short press loads Recovery. Long press
 *    loads Fastboot.
 * 4. Check bootloader control block for a boot target, which could be
 *    the name of a boot image that we know how to read from a partition,
 *    or a boot image file in the ESP. BCB can specify oneshot or persistent
 *    targets.
 * 5. Check LoaderEntryOneShot for a boot target
 * 6. Check if we should go into charge mode or normal boot
 *
 * target_address - If MEMORY returned, physical address to load data
 * target_path - If ESP_EFI_BINARY or ESP_BOOTIMAGE returned, path to the
 *               image on the EFI System Partition
 * oneshot - Whether this is a one-shot boot, indicating that the image at
 *           target_path should be deleted before chainloading
 *
 */
static enum boot_target choose_boot_target(VOID **target_address,
                CHAR16 **target_path, BOOLEAN *oneshot)
{
        enum boot_target ret;

        *target_path = NULL;
        *target_address = NULL;
        *oneshot = TRUE;

        ret = check_command_line(target_address);
        if (ret != NORMAL_BOOT)
                return ret;

        ret = check_fastboot_sentinel();
        if (ret != NORMAL_BOOT) {
                return ret;
        }

        ret = check_magic_key();
        if (ret != NORMAL_BOOT)
                return ret;

        ret = check_bcb(target_path, oneshot);
        if (ret != NORMAL_BOOT)
                return ret;

        ret = check_loader_entry_one_shot();
        if (ret != NORMAL_BOOT)
                return ret;

        return check_charge_mode();
}


/* Load a boot image into RAM. If a keystore is supplied, validate the image
 * against it.
 *
 * boot_target - Boot image to load. Values supported are NORMAL_BOOT, RECOVERY,
 *               and ESP_BOOTIMAGE (for 'fastboot boot')
 * keystore    - Keystore to validate image with. If null, no validation
 *               done.
 * keystore_size - Size of keystore in bytes
 * target_path - Path to load boot image from for ESP_BOOTIMAGE case, ignored
 *               otherwise.
 * bootimage   - Returned allocated pointer value for the loaded boot image.
 * oneshot     - For ESP_BOOTIMAGE case, flag indicating that the image should
 *               be deleted.
 *
 * Return values:
 * EFI_INVALID_PARAMETER - Unsupported boot target type, keystore is not well-formed,
 * or loaded boot image was missing or corrupt
 * EFI_ACCESS_DENIED - Validation failed against supplied keystore
 */
static EFI_STATUS load_boot_image(
                IN enum boot_target boot_target,
                IN VOID *keystore,
                IN UINTN keystore_size,
                IN CHAR16 *target_path,
                OUT VOID **bootimage,
                IN BOOLEAN oneshot)
{
        CHAR16 target[BOOT_TARGET_SIZE];
        EFI_STATUS ret;

        switch (boot_target) {
        case NORMAL_BOOT:
        case CHARGER:
                ret = android_image_load_partition(&boot_ptn_guid, bootimage);
                break;
        case RECOVERY:
                ret = android_image_load_partition(&recovery_ptn_guid, bootimage);
                break;
        case ESP_BOOTIMAGE:
                /* "fastboot boot" case */
                ret = android_image_load_file(g_disk_device, target_path, oneshot,
                        bootimage);
                break;
        default:
                return EFI_INVALID_PARAMETER;
        }

        if (EFI_ERROR(ret))
                return ret;

        debug("boot image loaded");
        if (keystore) {
                CHAR16 *expected;

                ret = verify_android_boot_image(*bootimage, keystore,
                        keystore_size, target);

                if (EFI_ERROR(ret)) {
                        debug("boot image doesn't verify");
                        goto out;
                }

                switch (boot_target) {
                case NORMAL_BOOT:
                case CHARGER:
                        expected = L"/boot";
                        break;
                case RECOVERY:
                        expected = L"/recovery";
                        break;
                default:
                        expected = NULL;
                }

                if (!expected || StrCmp(expected, target)) {
                        debug("boot image has unexpected target name");
                        ret = EFI_ACCESS_DENIED;
                }
        }

out:
        if (EFI_ERROR(ret))
                FreePool(bootimage);

        return ret;
}


/* Chainload another EFI application on the ESP with the specified path,
 * optionally deleting the file before entering */
static EFI_STATUS enter_efi_binary(CHAR16 *path, BOOLEAN delete)
{
        EFI_DEVICE_PATH *edp;
        EFI_STATUS ret;
        EFI_HANDLE image;

        edp = FileDevicePath(g_disk_device, path);
        if (!edp) {
                Print(L"Couldn't generate a path\n");
                return EFI_INVALID_PARAMETER;
        }

        ret = uefi_call_wrapper(BS->LoadImage, 6, FALSE, g_parent_image,
                        edp, NULL, 0, &image);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"BS->LoadImage '%s'", path);
        } else {
                if (delete) {
                        ret = file_delete(g_disk_device, path);
                        if (EFI_ERROR(ret))
                                efi_perror(ret, "Couldn't delete %s", path);
                }
                ret = uefi_call_wrapper(BS->StartImage, 3, image, NULL, NULL);
                uefi_call_wrapper(BS->UnloadImage, 1, image);
        }
        FreePool(edp);
        return ret;
}


static VOID enter_fastboot_mode(UINT8 boot_state, VOID *target_address)
        __attribute__ ((noreturn));


/* Enter Fastboot mode. If bootimage is NULL, load it from the file on the
 * EFI system partition */
static VOID enter_fastboot_mode(UINT8 boot_state, VOID *bootimage)
{
        /* Fastboot is conceptually part of the bootloader itself. That it
         * happens to currently be an Android Boot Image, and not part of the
         * kernelflinger EFI binary, is an implementation detail. Fastboot boot
         * image is not independently replaceable by end user without also
         * replacing the bootloader.  On an ARM device the bootloader/fastboot
         * are a single binary.
         *
         * Entering Fastboot is ALWAYS verified by the OEM Keystore, regardless
         * of the device's current boot state/selected keystore/etc. If it
         * doesn't verify we unconditionally halt the system. */
        EFI_STATUS ret;

        set_efi_variable(&fastboot_guid, BOOT_STATE_VAR, sizeof(boot_state),
                        &boot_state, FALSE, TRUE);

        if (!bootimage) {
                ret = android_image_load_file(g_disk_device, FASTBOOT_PATH,
                                FALSE, &bootimage);
                if (EFI_ERROR(ret)) {
                        Print(L"Couldn't load Fastboot image\n");
                        goto die;
                }
        }

#ifndef INSECURE
        CHAR16 target[BOOT_TARGET_SIZE];
        ret = verify_android_boot_image(bootimage, oem_keystore,
                        oem_keystore_size, target);
        if (EFI_ERROR(ret)) {
                Print(L"Fastboot image not verified\n");
                goto die;
        }

        if (StrCmp(target, L"/fastboot")) {
                Print(L"This does not appear to be a Fastboot image\n");
                goto die;
        }
#endif
        debug("chainloading fastboot, boot state is %s",
                        boot_state_to_string(boot_state));
        android_image_start_buffer(g_parent_image, bootimage, FALSE, NULL);
        Print(L"Couldn't chainload Fastboot image\n");
die:
        /* Allow plenty of time for the error to be visible before the
         * screen goes blank */
        pause(30);
        halt_system();
}


EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table)
{
        EFI_STATUS ret;
        CHAR16 *target_path = NULL;
        VOID *target_address = NULL;
        VOID *bootimage = NULL;
        BOOLEAN oneshot = FALSE;
        BOOLEAN lock_prompted = FALSE;
        VOID *selected_keystore = NULL;
        UINTN selected_keystore_size = 0;
        enum boot_target boot_target = NORMAL_BOOT;
        UINT8 boot_state = BOOT_STATE_GREEN;
        CHAR16 *loader_version = KERNELFLINGER_VERSION;
        UINT8 hash[KEYSTORE_HASH_SIZE];

        /* gnu-efi initialization */
        InitializeLib(image, sys_table);
        ux_init();

        debug("%s", loader_version);
        set_efi_variable_str(&loader_guid, LOADER_VERSION_VAR,
                        FALSE, TRUE, loader_version);

        /* populate globals */
        g_parent_image = image;
        ret = uefi_call_wrapper(BS->OpenProtocol, 6, image,
                        &LoadedImageProtocol, (VOID **)&g_loaded_image,
                        image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"OpenProtocol: LoadedImageProtocol");
                return ret;
        }
        g_disk_device = g_loaded_image->DeviceHandle;
        oem_keystore = (UINT8 *)&oem_keystore_table +
                        oem_keystore_table.oem_keystore_offset;
        oem_keystore_size = oem_keystore_table.oem_keystore_size;
        oem_key = (UINT8 *)&oem_keystore_table +
                        oem_keystore_table.oem_key_offset;
        oem_key_size = oem_keystore_table.oem_key_size;
        debug("oem key size %d keystore size %d", oem_key_size,
                        oem_keystore_size);

        debug("choosing a boot target");
        /* No UX prompts before this point, do not want to interfere
         * with magic key detection */
        boot_target = choose_boot_target(&target_address, &target_path,
                        &oneshot);
        debug("selected '%s'",  boot_target_to_string(boot_target));

#ifndef INSECURE
        debug("checking device state");

        if (!is_efi_secure_boot_enabled()) {
                debug("uefi secure boot is disabled");
                boot_state = BOOT_STATE_ORANGE;
                lock_prompted = TRUE;

                /* Need to warn early, before we even enter Fastboot
                 * or run EFI binaries. Set lock_prompted to true so
                 * we don't ask again later */
                if (!ux_prompt_user_secure_boot_off())
                        halt_system();
        } else  if (!is_device_locked_or_verified()) {
                boot_state = BOOT_STATE_ORANGE;
                debug("Device is unlocked");
        } else {
                debug("examining keystore");

                select_keystore(&selected_keystore, &selected_keystore_size);
                if (EFI_ERROR(verify_android_keystore(selected_keystore,
                                        selected_keystore_size,
                                        oem_key, oem_key_size, hash))) {
                        debug("keystore not validated");
                        boot_state = BOOT_STATE_YELLOW;
                }
        }
#else
        /* Make sure it's abundantly clear! */
        Print(L"INSECURE BOOTLOADER - SYSTEM SECURITY IN RED STATE\n");
        pause(1);
        boot_state = BOOT_STATE_RED;
#endif

        /* EFI binaries are validated by the BIOS */
        if (boot_target == ESP_EFI_BINARY) {
                debug("entering EFI binary");
                ret = enter_efi_binary(target_path, oneshot);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"EFI Application exited abnormally");
                        pause(3);
                }
                FreePool(target_path);
                reboot();
        }

        /* Fastboot is always validated by the OEM keystore baked into
         * the kernelflinger binary */
        if (boot_target == FASTBOOT || boot_target == MEMORY) {
                debug("entering Fastboot mode");
                enter_fastboot_mode(boot_state, target_address);
        }

        /* Past this point is where we start to care if the keystore isn't
         * validated or the device is unlocked via Fastboot, start to prompt
         * the user if we aren't GREEN */

        /* If the user keystore is bad the only way to fix it is via
         * fastboot */
        if (boot_state == BOOT_STATE_YELLOW &&
                        !ux_prompt_user_keystore_unverified(hash)) {
                enter_fastboot_mode(BOOT_STATE_RED, NULL);
        }

        /* If the device is unlocked the only way to re-lock it is
         * via fastboot. Skip this UX if we already prompted earlier
         * about EFI secure boot being turned off */
        if (boot_state == BOOT_STATE_ORANGE && !lock_prompted &&
                        !ux_prompt_user_device_unlocked()) {
                enter_fastboot_mode(BOOT_STATE_RED, NULL);
        }

fallback:
        debug("loading boot image");
        ret = load_boot_image(boot_target, selected_keystore,
                        selected_keystore_size, target_path,
                        &bootimage, oneshot);
        FreePool(target_path);
        target_path = NULL;

        if (EFI_ERROR(ret)) {
                debug("couldn't load boot image: %r", ret);
                if (ret == EFI_ACCESS_DENIED)
                        boot_state = BOOT_STATE_RED;

                /* Recovery itself is unverified. Only way to
                 * un-hose this device is through Fastboot */
                if (boot_target == RECOVERY) {
                        debug("recovery image is bad");
                        if (ux_warn_user_unverified_recovery())
                                enter_fastboot_mode(BOOT_STATE_RED, NULL);
                        else
                                halt_system();
                }

                if (!ux_prompt_user_bootimage_unverified())
                        halt_system();

                /* Fall back to loading Recovery Console so they
                 * can sideload an OTA to fix their device */
                debug("fall back to recovery console");
                boot_target = RECOVERY;
                FreePool(bootimage);
                goto fallback;
        }

        set_efi_variable(&fastboot_guid, BOOT_STATE_VAR, sizeof(boot_state),
                        &boot_state, FALSE, TRUE);

        /* per bootloaderequirements.pdf */
        if (boot_state != BOOT_STATE_GREEN)
                android_clear_memory();

        debug("chainloading boot image, boot state is %s",
                        boot_state_to_string(boot_state));
        return android_image_start_buffer(g_parent_image, bootimage,
                        boot_target == CHARGER, NULL);
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */

