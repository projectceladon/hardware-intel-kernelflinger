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
#define TOS_HEADER_MAGIC         0x6d6d76656967616d
#define TOS_HIGH_ADDR            0x3fffffff   /* Less than 1 GB */
#define TOS_STARTUP_VERSION      0x01
#define SIPI_AP_HIGH_ADDR        0x100000  /* Less than 1MB */
#define SIPI_AP_MEMORY_LENGTH    0x1000  /* 4KB in length */
#define VMM_MEM_BASE             0x34C00000
#define VMM_MEM_SIZE             0x01000000
#define TRUSTY_MEM_BASE          0x32C00000
#define TRUSTY_MEM_SIZE          0x01000000

/* This is structure to proivde required data to Trusty when calling Trusty entry.
 * It is required to send the public key used to verify the android boot image,
 * the state of the device, the EFI memory map which is contained in the platform
 * info structure and the return address
 */
struct tos_startup_info {
        /* version of TOS startup info structure, currently set it as 1 */
        UINT32 version;
        /* Size of this structure for mismatching check */
        UINT32 size;
        /* root of trust fields */
         struct rot_data_t rot;
        /* UEFI memory map address */
        UINT64 efi_memmap;
        /* UEFI memory map size */
        UINT32 efi_memmap_size;
        /* Reserved for AP's wake-up */
        UINT32 sipi_ap_wkup_addr;
        /* Bootloader retrieves the trust/vmm IMRs froom CSE/BIOS */
        UINT64 trusty_mem_base;
        UINT64 vmm_mem_base;
        UINT32 trusty_mem_size;
        UINT32 vmm_mem_size;
} ;

/* Make sure the header address is 8-byte aligned */
struct tos_image_header {
        /* a 64bit magic value */
        UINT64 magic;
        /* version of the TOS header */
        UINT32 version;
        /* size of this structure */
        UINT32 size;
        /* TOS image version */
        UINT32 tos_version;
        /* entry offset */
        UINT32 entry_offset;
        /* Bootloader allocates a memory region with this specified size, and copies TOS image to
        *  this allocated space
        */
        UINT32 tos_ldr_size;
        /* Trusty IMR base + seed_msg_dst_offset */
        UINT32 seed_msg_dst_offset;
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

/* Get the VMM  base address and size */
static EFI_STATUS get_address_size_vmm(OUT UINT64 *vmm_mem_base, OUT UINT32 *vmm_size )
{
        EFI_STATUS ret;
        /* Need to rework the code for these values should be read from B-UINT regsiter */
        if (!vmm_mem_base || !vmm_size)
                return EFI_INVALID_PARAMETER;

        *vmm_mem_base = VMM_MEM_BASE;
        *vmm_size = VMM_MEM_SIZE;

        ret = allocate_pages(AllocateAddress,
                             EfiRuntimeServicesData,
                             EFI_SIZE_TO_PAGES(VMM_MEM_SIZE),
                             vmm_mem_base);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for VMM base addess failed");
                return EFI_OUT_OF_RESOURCES;
        }
        return EFI_SUCCESS;
}

/* Get the TRUSTY  base address and size */
static EFI_STATUS get_address_size_trusty(OUT UINT64 *trusty_mem_base, OUT UINT32 *trusty_size )
{
        EFI_STATUS ret;

        /* Need to rework the code for these values should be read from B-UINT regsiter */
        if (!trusty_mem_base || !trusty_size)
                return EFI_INVALID_PARAMETER;

        *trusty_mem_base = TRUSTY_MEM_BASE;
        *trusty_size = TRUSTY_MEM_SIZE;

        ret = allocate_pages(AllocateAddress,
                             EfiRuntimeServicesData,
                             EFI_SIZE_TO_PAGES(TRUSTY_MEM_SIZE),
                             trusty_mem_base);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for Trusty base addess failed");
                return EFI_OUT_OF_RESOURCES;
        }
        return EFI_SUCCESS;
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
static EFI_STATUS start_tos_image(IN VOID *bootimage, IN struct rot_data_t *rot_data)
{
        EFI_STATUS ret;
        UINTN map_key, desc_size;
        UINT32 desc_ver, load_size, tos_ret;
        UINTN nr_entries;
        EFI_PHYSICAL_ADDRESS load_base = 0;
        EFI_PHYSICAL_ADDRESS startup_info_phy_addr = 0;
        EFI_PHYSICAL_ADDRESS sipi_ap_addr = 0;
        struct tos_startup_info  *startup_info = NULL;
        UINT8 *memory_map = NULL;
        UINT32 (*call_entry)(struct tos_startup_info*);
        struct tos_image_header *tos_header;
        struct boot_img_hdr *boot_image_header;
        UINT64 temp_trusty_base_address, temp_vmm_base_address;
        UINT32 temp_trusty_address_size, temp_vmm_address_size;

        /* Find tos header in memory */
        debug(L"Reading TOS image header");
        if (!bootimage || !rot_data)
                return EFI_INVALID_PARAMETER;

        tos_header = get_tosimage_header(bootimage);
        if (!tos_header) {
                error(L"This partition does not contain a TOS image");
                return EFI_INVALID_PARAMETER;
        }

        boot_image_header = (struct boot_img_hdr *)bootimage;

        if (tos_header->size != sizeof(struct tos_image_header)){
                error(L"TOS header size mismatches in tos header");
                return EFI_INVALID_PARAMETER;
        }

        load_size = tos_header->tos_ldr_size;

        /* Allocate SIPI region */
        sipi_ap_addr = SIPI_AP_HIGH_ADDR;
        ret = allocate_pages(AllocateMaxAddress,
                             EfiLoaderData,
                             EFI_SIZE_TO_PAGES(SIPI_AP_MEMORY_LENGTH),
                             &sipi_ap_addr);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for TOS startup structure failed");
                goto cleanup;
        }

        /* Allocate loadtime at specified addresses */
        ret = allocate_pages(AllocateAnyPages,
                             EfiLoaderData,
                             EFI_SIZE_TO_PAGES(load_size),
                             &load_base);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for loadtime memory failed");
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
        startup_info = (struct tos_startup_info *)(UINTN)startup_info_phy_addr;
        memset(startup_info, 0, sizeof(*startup_info));

        debug(L"TOS Loadtime memory address = 0x%x", load_base);

        /* Relocate to Loadtime region for TOS header + TOS */
        memcpy((VOID *)(UINTN)load_base, (VOID *)tos_header, boot_image_header->kernel_size);

        /* Get EFI memory map */
        memory_map = (CHAR8 *)LibMemoryMap(&nr_entries, &map_key, &desc_size, &desc_ver);
        if (!memory_map) {
                error(L"Get EFI memory map failed");
                goto cleanup;
        }

        /* Initialize startup struct */
        startup_info->version = TOS_STARTUP_VERSION;
        startup_info->size = sizeof(struct tos_startup_info);
        memcpy(&startup_info->rot, rot_data, sizeof(*rot_data));
        startup_info->efi_memmap = (UINT64)(UINTN)memory_map;
        startup_info->efi_memmap_size = desc_size * nr_entries;
        startup_info->sipi_ap_wkup_addr = (UINT32)sipi_ap_addr;
        ret = get_address_size_vmm(&temp_vmm_base_address, &temp_vmm_address_size);
        if (EFI_ERROR(ret)){
                efi_perror(ret, L"Get VMM address failed");
                goto cleanup;
        }
        startup_info->vmm_mem_base = temp_vmm_base_address;
        startup_info->vmm_mem_size = temp_vmm_address_size;
        ret = get_address_size_trusty(&temp_trusty_base_address, &temp_trusty_address_size);
        if (EFI_ERROR(ret)){
                efi_perror(ret, L"Get Trusty address failed");
                goto cleanup;
        }
        startup_info->trusty_mem_base = temp_trusty_base_address;
        startup_info->trusty_mem_size = temp_trusty_address_size;

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
        }
        /* Free all the memory we allocated in this function */
        if (load_base)
                free_pages(load_base, EFI_SIZE_TO_PAGES(load_size));
        if (startup_info_phy_addr)
                free_pages(startup_info_phy_addr, EFI_SIZE_TO_PAGES(sizeof(struct tos_startup_info)));
        if (memory_map)
                FreePool(memory_map);
        if (sipi_ap_addr)
                free_pages(sipi_ap_addr, EFI_SIZE_TO_PAGES(SIPI_AP_MEMORY_LENGTH));
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

EFI_STATUS start_trusty(IN struct rot_data_t *rot_data)
{
        EFI_STATUS ret;
        VOID *tosimage;

        ret = load_tos_image(&tosimage);
        if (EFI_ERROR(ret))
                return ret;

        return start_tos_image(tosimage, rot_data);
}

