/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef GUMMIBOOT_ANDROID_H

#include "efi.h"
#include "efilib.h"

#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512
#define BOOT_EXTRA_ARGS_SIZE 1024

struct boot_img_hdr
{
    unsigned char magic[BOOT_MAGIC_SIZE];

    unsigned kernel_size;  /* size in bytes */
    unsigned kernel_addr;  /* physical load addr */

    unsigned ramdisk_size; /* size in bytes */
    unsigned ramdisk_addr; /* physical load addr */

    unsigned second_size;  /* size in bytes */
    unsigned second_addr;  /* physical load addr */

    unsigned tags_addr;    /* physical addr for kernel tags */
    unsigned page_size;    /* flash page size we assume */
    unsigned unused[2];    /* future expansion: should be 0 */

    unsigned char name[BOOT_NAME_SIZE]; /* asciiz product name */

    unsigned char cmdline[BOOT_ARGS_SIZE];

    unsigned id[8]; /* timestamp / checksum / sha1 / etc */

    /* Supplemental command line data; kept here to maintain
     * binary compatibility with older versions of mkbootimg */
    unsigned char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
};

/*
** +-----------------+ 
** | boot header     | 1 page
** +-----------------+
** | kernel          | n pages  
** +-----------------+
** | ramdisk         | m pages  
** +-----------------+
** | second stage    | o pages
** +-----------------+
**
** n = (kernel_size + page_size - 1) / page_size
** m = (ramdisk_size + page_size - 1) / page_size
** o = (second_size + page_size - 1) / page_size
**
** 0. all entities are page_size aligned in flash
** 1. kernel and ramdisk are required (size != 0)
** 2. second is optional (second_size == 0 -> no second)
** 3. load each element (kernel, ramdisk, second) at
**    the specified physical address (kernel_addr, etc)
** 4. prepare tags at tag_addr.  kernel_args[] is
**    appended to the kernel commandline in the tags.
** 5. r0 = 0, r1 = MACHINE_TYPE, r2 = tags_addr
** 6. if second_size != 0: jump to second_addr
**    else: jump to kernel_addr
*/


/* Bootloader Message
 *
 * This structure describes the content of a block in flash
 * that is used for recovery and the bootloader to talk to
 * each other.
 *
 * The command field is updated by linux when it wants to
 * reboot into recovery or to update radio or bootloader firmware.
 * It is also updated by the bootloader when firmware update
 * is complete (to boot into recovery for any final cleanup)
 *
 * The status field is written by the bootloader after the
 * completion of an "update-radio" or "update-hboot" command.
 *
 * The recovery field is only written by linux and used
 * for the system to send a message to recovery or the
 * other way around.
 */
struct bootloader_message {
        CHAR8 command[32];
        CHAR8 status[32];
        CHAR8 recovery[1024];
};

/* Functions to load an Android boot image.
 * You can do this from a file, a partition GUID, or
 * from a RAM buffer */
EFI_STATUS android_image_start_buffer(
                IN EFI_HANDLE parent_image,
                IN VOID *bootimage,
                IN BOOLEAN enable_charger,
                IN EFI_GUID *swap);

EFI_STATUS android_image_load_partition(
                IN const EFI_GUID *guid,
                OUT VOID **bootimage_p);

EFI_STATUS android_image_load_file(
                IN EFI_HANDLE device,
                IN CHAR16 *loader,
                IN BOOLEAN delete,
                OUT VOID **bootimage_p);

EFI_STATUS read_bcb(
                IN const EFI_GUID *bcb_guid,
                OUT struct bootloader_message *bcb);

EFI_STATUS write_bcb(
                IN const EFI_GUID *bcb_guid,
                IN struct bootloader_message *bcb);

/* Perform a security  RAM wipe */
EFI_STATUS android_clear_memory(void);

/* Sanity check the data and return a pointer to the header.
 * Return NULL if the sanity check fails */
struct boot_img_hdr *get_bootimage_header(VOID *bootimage_blob);

/* Return the size of a boot image, DOES NOT include any signature
 * block */
UINTN bootimage_size(struct boot_img_hdr *aosp_header);

#endif

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */
