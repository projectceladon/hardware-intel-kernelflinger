/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <efi.h>
#include <efilib.h>
#include <ui.h>

#include "android.h"
#include "efilinux.h"
#include "lib.h"
#include "security.h"
#include "vars.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "storage.h"
#include "text_parser.h"
#include "watchdog.h"
#ifdef HAL_AUTODETECT
#include "blobstore.h"
#endif
#include "slot.h"
#include "pae.h"
#include "timer.h"
#ifdef RPMB_STORAGE
#include "rpmb_storage.h"
#endif
#include "acpi.h"

#define ROOTFS_PREFIX L"skip_initramfs rootwait ro init=/init root="

static EFI_STATUS prepend_command_line_rootfs(CHAR16 **cmdline16, X509 *verity_cert)
{
        EFI_GUID system_uuid;
        EFI_STATUS ret;
        char *key_id = NULL;

        ret = gpt_get_partition_uuid(slot_label(SYSTEM_LABEL),
                                     &system_uuid, LOGICAL_UNIT_USER);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to get %s partition UUID", SYSTEM_LABEL);
                return ret;
        }

        if (!verity_cert) {
#if defined(USERDEBUG)
                error(L"Cannot boot without a verity certificate");
                return EFI_INVALID_PARAMETER;
#else
                ret = prepend_command_line(cmdline16, ROOTFS_PREFIX "PARTUUID=%g",
                                           &system_uuid);
                return ret;
#endif
        }

        ret = get_android_verity_key_id(verity_cert, &key_id);
        if (EFI_ERROR(ret))
                return ret;

        ret = prepend_command_line(cmdline16, ROOTFS_PREFIX "/dev/dm-0 dm=\"system "
                                   "none ro,0 1 android-verity %a PARTUUID=%g\"",
                                   key_id, &system_uuid);
        FreePool(key_id);

        return ret;
}

EFI_STATUS prepend_slot_command_line(CHAR16 **cmdline16,
        enum boot_target boot_target,
        VBDATA *vb_data)
{
        EFI_STATUS ret;

        if ((boot_target == NORMAL_BOOT || boot_target == CHARGER) &&
                recovery_in_boot_partition() && vb_data) {

                ret = prepend_command_line_rootfs(cmdline16, vb_data);
                if (vb_data)
                        X509_free(vb_data);

                if (EFI_ERROR(ret))
                        return ret;

                if (slot_get_verity_corrupted()) {
                        ret = prepend_command_line(cmdline16,
                                L"androidboot.veritymode=eio");
                        if (EFI_ERROR(ret))
                                return ret;
                }
        }

        return EFI_SUCCESS;
}


UINTN get_vb_cmdlen(VBDATA *vb_data)
{
        (void)vb_data;
        return 0;
}

char *get_vb_cmdline(VBDATA *vb_data)
{
        (void)vb_data;
        return NULL;
}
