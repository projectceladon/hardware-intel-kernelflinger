/*
 * Copyright (c) 2016, Intel Corporation
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
#include "trusty.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "efilinux.h"

/* Trusty OS (TOS) definitions */
#define TOS_HEADER_MAGIC       0x6d6d76656967616d
#define TOS_HIGH_ADDR          0x3fffffff   /* Less than 1 GB */

/* This is structure to proivde required data to Trusty when calling Trusty entry.
 * It is required to send the public key used to verify the android boot image,
 * the state of the device, the EFI memory map which is contained in the platform
 * info structure and the return address
 */
struct tos_startup_info {
        /* Device state */
        enum device_state state;
        /* Platform info structure pointer address */
        UINT64 platform_info_addr;
        /* The platform info structure size */
        UINT32 platform_info_size;
        /* The public key to verify the android boot image */
        EVP_PKEY *pkey;
};

/* Make sure the header address is 8-byte aligned */
struct tos_image_header {
        /* a 64bit magic value */
        UINT64 magic;
        /* size of this structure */
        UINT32 size;
        /* version of the TOS header */
        UINT32 version;
        /* reserved for re-design */
        UINT32 reserved1;
        /* entry offset */
        UINT32 entry_offset;
        /* reserved for re-design */
        UINT32 reserved2;
        UINT32 reserved3;
        /* boot loader will allocate this size,
         * and populate rt_mem_base */
        UINT32 rt_mem_base;
        UINT32 rt_mem_size;
        /* boot loader will allocate this size,
         * and populate ldr_mem_base */
        UINT32 ldr_mem_base;
        UINT32 ldr_mem_size;
        /* whole image package size after 4K
         * aligned 0-padding */
        UINT32 image_size;
        UINT32 padding;
};

/* Platform info structure to store the EFI memory map and any future platform
 * info used for launching trusty
 */
struct tos_platform_info {
        /* EFI memory map address */
        UINT32 memmap_addr;
        /* EFI memory map size */
        UINT32 memmap_size;
        /* Addres of load-time region where image is actually loaded */
        UINT32 load_addr;
        /* Address of allocated runtime memory region */
        UINT32 run_addr;
};

/* Get the TOS image header from the bootimage
 * Parameters:
 * bootimage - the address of android boot image that contains the tos image
 * Return values:
 * Returns the tos image header address or NULL
 */
static struct tos_image_header *get_tosimage_header(IN VOID *bootimage)
{
        struct boot_img_hdr *aosp_header;
        struct tos_image_header *tos_header;

        aosp_header = (struct boot_img_hdr *)bootimage;
        tos_header = (struct tos_image_header *)((UINT8 *)bootimage + aosp_header->page_size);
        if (tos_header->magic == TOS_HEADER_MAGIC)
                return tos_header;

        return NULL;
}

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
        UINTN partition_start;
        UINTN partition_size;
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

/*
 * 1. Boot loader gets the tos image header address from kernel slot in
 *    android boot image (aosp_header + page_size)
 * 2. Boot loader should copy the to-be-loaded image to the
 *    address of ldr_mem_base, and then call into
 *    the entry of entry[32/64]_offset+ldr_mem_base.
 */
static EFI_STATUS start_tos_image(IN VOID *bootimage)
{
        EFI_STATUS ret;
        UINTN map_key, desc_size;
        UINT32 desc_ver, load_size, tos_ret;
        UINTN nr_entries;
        EFI_PHYSICAL_ADDRESS load_base = 0, runtime_base = 0;
        EFI_PHYSICAL_ADDRESS platform_info_phy_addr = 0, startup_info_phy_addr = 0;
        struct tos_platform_info *platform_info = NULL;
        struct tos_startup_info  *startup_info = NULL;
        UINT8 *memory_map = NULL;
        enum device_state state;
        UINT32 (*call_entry)(struct tos_startup_info*);
        struct tos_image_header *tos_header;
        struct boot_img_hdr *aosp_header;
        EVP_PKEY *boot_pkey = NULL;

        /* Find tos header in memory */
        debug(L"Reading TOS image header");
        tos_header = get_tosimage_header(bootimage);
        if (!tos_header) {
                error(L"This partition does not contain a TOS image");
                return EFI_INVALID_PARAMETER;
        }

        aosp_header = (struct boot_img_hdr *)bootimage;
        if (tos_header->image_size != aosp_header->kernel_size) {
                error(L"TOS image size mismatches in tos header and boot img header");
                return EFI_INVALID_PARAMETER;
        }
        /* Get the fixed addresses for runtime
         * and loadtime regions from tos header */
        load_base = tos_header->ldr_mem_base;
        runtime_base = tos_header->rt_mem_base;
        load_size = tos_header->ldr_mem_size;

        /* Allocate loadtime and runtime regions at specified addresses */
        ret = allocate_pages(AllocateAddress,
                             EfiLoaderData,
                             EFI_SIZE_TO_PAGES(load_size),
                             &load_base);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for loadtime memory failed");
                goto cleanup;
        }

        ret = allocate_pages(AllocateAddress,
                             EfiRuntimeServicesData,
                             EFI_SIZE_TO_PAGES(tos_header->rt_mem_size),
                             &runtime_base);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for runtime memory failed");
                goto cleanup;
        }

        /* Allocate space for startup structure */
        startup_info_phy_addr = TOS_HIGH_ADDR;
        ret = allocate_pages(AllocateMaxAddress,
                             EfiLoaderData,
                             EFI_SIZE_TO_PAGES(sizeof(struct tos_startup_info)),
                             &startup_info_phy_addr);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for TOS startup structure failed");
                goto cleanup;
        }
        startup_info = (struct tos_startup_info *)startup_info_phy_addr;
        memset(startup_info, 0, sizeof(*startup_info));
        state = get_current_state();

        /* Allocate space for platform structure */
        platform_info_phy_addr = TOS_HIGH_ADDR;
        ret = allocate_pages(AllocateMaxAddress,
                             EfiLoaderData,
                             EFI_SIZE_TO_PAGES(sizeof(struct tos_platform_info)),
                             &platform_info_phy_addr);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for TOS platform structure failed");
                goto cleanup;
        }
        platform_info = (struct tos_platform_info *)platform_info_phy_addr;

        debug(L"TOS Loadtime memory address = 0x%x, Runtime memory address = 0x%x", load_base, runtime_base);

        /* Initialize platform info structure */
        memset(platform_info, 0, sizeof(*platform_info));
        /* Relocate to Loadtime region for TOS header + TOS */
        memcpy((VOID *)load_base, (VOID *)tos_header, tos_header->image_size);

        /* Get EFI memory map */
        memory_map = (CHAR8 *)LibMemoryMap(&nr_entries, &map_key, &desc_size, &desc_ver);
        if (!memory_map) {
                error(L"Get EFI memory map failed");
                goto cleanup;
        }

        /* Initialize platform structure */
        platform_info->memmap_addr = (UINT32)(UINTN)memory_map;
        platform_info->memmap_size = desc_size * nr_entries;
        platform_info->load_addr = (UINT32)load_base;
        platform_info->run_addr = (UINT32)runtime_base;

        /* Initialize startup struct */
        startup_info->platform_info_addr = (UINT64)(UINTN)platform_info;
        startup_info->platform_info_size = sizeof(*platform_info);
        startup_info->state = state;
        startup_info->pkey = boot_pkey;

        /* Call TOS entry point */
        call_entry = (UINT32(*)(struct tos_startup_info*))(
                        (UINTN)load_base + tos_header->entry_offset);
        debug(L"Call TOS loader entry_addr = 0x%x", call_entry);
        tos_ret = call_entry(startup_info);

        if (tos_ret) {
                error(L"Load and start Trusty OS failed: 0x%x", tos_ret);
                ret = EFI_INVALID_PARAMETER;
                goto cleanup;
        }
        debug(L"TOS launch succeeded!");

cleanup:
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Error has occurred!");
                if (runtime_base)
                        free_pages(runtime_base, EFI_SIZE_TO_PAGES(tos_header->rt_mem_size));
        }
        /* Free all the memory we allocated in this function */
        if (load_base)
                free_pages(load_base, EFI_SIZE_TO_PAGES(load_size));
        if (startup_info_phy_addr)
                free_pages(startup_info_phy_addr, EFI_SIZE_TO_PAGES(sizeof(struct tos_startup_info)));
        if (platform_info_phy_addr)
                free_pages(platform_info_phy_addr, EFI_SIZE_TO_PAGES(sizeof(struct tos_platform_info)));
        if (memory_map)
                FreePool(memory_map);
        return ret;
}

static EFI_STATUS load_tos_image(OUT VOID **bootimage)
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
                ret = EFI_SUCCESS;
        }
#endif
        if (*bootimage)
                FreePool(*bootimage);
        return ret;
}

EFI_STATUS start_trusty(IN enum boot_target boot_target, IN UINT8 boot_state)
{
        EFI_STATUS ret;
        VOID *tosimage;

        if (boot_target != NORMAL_BOOT &&
            boot_target != RECOVERY &&
            boot_target != CHARGER &&
            boot_target != MEMORY) {
                debug(L"TOS image start skipped");
                return EFI_SUCCESS;
        }

        if (boot_state == BOOT_STATE_RED) {
#ifndef USERDEBUG
               debug(L"Red state: invalid boot image. Start trusty anyway as ENG build");
#else
               error(L"Red state: invalid boot image. Stop");
               return EFI_INVALID_PARAMETER;
#endif
        }

        ret = load_tos_image(&tosimage);
        if (EFI_ERROR(ret))
                return ret;

        return start_tos_image(tosimage);
}

