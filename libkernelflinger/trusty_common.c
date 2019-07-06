/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
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
#include "options.h"
#include "power.h"
#include "trusty_common.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "efilinux.h"

#ifdef USE_AVB
EFI_STATUS load_tos_image(OUT VOID **bootimage)
{
        EFI_STATUS ret;
        UINT8 verify_state = BOOT_STATE_GREEN;
        UINT8 verify_state_new;
        AvbSlotVerifyData *slot_data;
        BOOLEAN b_secureboot = is_platform_secure_boot_enabled();

        if (!b_secureboot)
                verify_state = BOOT_STATE_YELLOW;
#ifndef USER
        if (device_is_unlocked())
                verify_state = BOOT_STATE_ORANGE;
#endif

        verify_state_new = verify_state;

        ret = android_image_load_partition_avb("tos", bootimage, &verify_state_new, &slot_data);  // Do not try to switch slot if failed
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"TOS image loading failed");
                return ret;
        }

        if (verify_state != verify_state_new) {
#ifndef USERDEBUG
                error(L"Invalid TOS image. Boot anyway on ENG build");
                ret = EFI_SUCCESS;
#else
                if (b_secureboot) {
                        error(L"TOS image doesn't verify, stop since secure boot enabled");
                        ret = EFI_SECURITY_VIOLATION;
                } else {
                        error(L"TOS image doesn't verify, continue since secure boot disabled");
                        ret = EFI_SUCCESS;
                }
#endif
        }

        return ret;
}

#else // USE_AVB == false
/* Open the tos partition and load the tos image into memory
 * Parameters:
 * label    - Label for the partition in the GPT
 * image    - the image pointer after loading from the GPT
 * Return values:
 * EFI_SUCCESS           - image is loaded
 * EFI_ACCESS_DENIED     - Error in image loading
 * EFI_INVALID_PARAMETER - wrong image size
 * EFI_OUT_OF_RESOURCES  - Out of memory
 */
static EFI_STATUS tos_image_load_partition(IN const CHAR16 *label, OUT VOID **image)
{
        UINT32 MediaId;
        UINT32 img_size;
        EFI_STATUS ret;
        struct gpt_partition_interface gpart;
        UINT64 partition_start;
        UINT64 partition_size;
        VOID *bootimg;
        struct boot_img_hdr aosp_header;

        ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Partition %s not found", label);
                return ret;
        }
        MediaId = gpart.bio->Media->MediaId;
        partition_start = gpart.part.starting_lba * gpart.bio->Media->BlockSize;
        partition_size = (gpart.part.ending_lba + 1 - gpart.part.starting_lba) *
                gpart.bio->Media->BlockSize;
        debug(L"Reading TOS image header");
        ret = uefi_call_wrapper(gpart.dio->ReadDisk, 5, gpart.dio, MediaId,
                                partition_start,
                                sizeof(aosp_header), &aosp_header);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"ReadDisk (aosp_header)");
                return ret;
        }
        img_size = bootimage_size(&aosp_header) + BOOT_SIGNATURE_MAX_SIZE;
        if (img_size > partition_size) {
                error(L"TOS image is larger than partition size");
                return EFI_INVALID_PARAMETER;
        }
        bootimg = AllocatePool(img_size);
        if (!bootimg) {
                error(L"Alloc memory for TOS image failed");
                return EFI_OUT_OF_RESOURCES;
        }

        debug(L"Reading Tos image: %d bytes", img_size);
        ret = uefi_call_wrapper(gpart.dio->ReadDisk, 5, gpart.dio, MediaId, partition_start,
                                img_size, bootimg);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"ReadDisk Error for TOS image read");
                FreePool(bootimg);
                return ret;
        }
        *image = bootimg;
        return EFI_SUCCESS;
}

EFI_STATUS load_tos_image(OUT VOID **bootimage)
{
        CHAR16 target[BOOT_TARGET_SIZE];
        EFI_STATUS ret;
        UINT8 verify_state;

        ret = tos_image_load_partition(TOS_LABEL, bootimage);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"TOS image loading failed");
                return ret;
        }

        verify_state = verify_android_boot_image(*bootimage, oem_cert,
                                                 oem_cert_size, target, NULL);
        if (verify_state != BOOT_STATE_GREEN) {
                error(L"TOS image doesn't verify");
                ret = EFI_SECURITY_VIOLATION;
                goto cleanup_tos;
        }

        if (StrCmp(L"/tos", target)) {
                error(L"TOS image has unexpected target name");
                ret = EFI_SECURITY_VIOLATION;
                goto cleanup_tos;
        }
        return EFI_SUCCESS;

cleanup_tos:
#ifndef USERDEBUG
        if(EFI_SECURITY_VIOLATION == ret) {
                error(L"Invalid TOS image. Boot anyway on ENG build");
                return EFI_SUCCESS;
        }
#endif
        if (*bootimage)
                FreePool(*bootimage);
        return ret;
}

#endif // USE_AVB
