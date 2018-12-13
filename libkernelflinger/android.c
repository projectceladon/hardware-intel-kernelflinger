/*
 * Copyright (c) 2013, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
 * Some Linux bootstrapping code adapted from efilinux by
 * Matt Fleming <matt.fleming@intel.com>
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
#ifdef USE_AVB
#include "avb_init.h"
#endif
#ifdef RPMB_STORAGE
#include "rpmb_storage.h"
#endif
#include "acpi.h"
#ifdef USE_FIRSTSTAGE_MOUNT
#include "firststage_mount.h"
#endif

#define OS_INITIATED L"os_initiated"

#if __LP64__
#define EFI_LOADER_SIGNATURE "EL64"
#else
#define EFI_LOADER_SIGNATURE "EL32"
#endif

struct setup_header {
        UINT8 setup_secs;        /* Sectors for setup code */
        UINT16 root_flags;
        UINT32 sys_size;
        UINT16 ram_size;
        UINT16 video_mode;
        UINT16 root_dev;
        UINT16 signature;        /* Boot signature */
        UINT16 jump;
        UINT32 header;
        UINT16 version;
        UINT16 su_switch;
        UINT16 setup_seg;
        UINT16 start_sys;
        UINT16 kernel_ver;
        UINT8 loader_id;
        UINT8 load_flags;
        UINT16 movesize;
        UINT32 code32_start;        /* Start of code loaded high */
        UINT32 ramdisk_start;        /* Start of initial ramdisk */
        UINT32 ramdisk_len;        /* Lenght of initial ramdisk */
        UINT32 bootsect_kludge;
        UINT16 heap_end;
        UINT8 ext_loader_ver;  /* Extended boot loader version */
        UINT8 ext_loader_type; /* Extended boot loader ID */
        UINT32 cmd_line_ptr;   /* 32-bit pointer to the kernel command line */
        UINT32 ramdisk_max;    /* Highest legal initrd address */
        UINT32 kernel_alignment; /* Physical addr alignment required for kernel */
        UINT8 relocatable_kernel; /* Whether kernel is relocatable or not */
        UINT8 min_alignment;
        UINT16 xloadflags;
        UINT32 cmdline_size;
        UINT32 hardware_subarch;
        UINT64 hardware_subarch_data;
        UINT32 payload_offset;
        UINT32 payload_length;
        UINT64 setup_data;
        UINT64 pref_address;
        UINT32 init_size;
        UINT32 handover_offset;
} __attribute__((packed));

struct efi_info {
        UINT32 efi_loader_signature;
        UINT32 efi_systab;
        UINT32 efi_memdesc_size;
        UINT32 efi_memdesc_version;
        UINT32 efi_memmap;
        UINT32 efi_memmap_size;
        UINT32 efi_systab_hi;
        UINT32 efi_memmap_hi;
};

#define E820_UNDEFINED    0
#define E820_RAM          1
#define E820_RESERVED     2
#define E820_ACPI         3
#define E820_NVS          4
#define E820_UNUSABLE     5

struct e820_entry {
        UINT64 addr;                /* start of memory segment */
        UINT64 size;                /* size of memory segment */
        UINT32 type;                /* type of memory segment */
} __attribute__((packed));

struct screen_info {
        UINT8  orig_x;           /* 0x00 */
        UINT8  orig_y;           /* 0x01 */
        UINT16 ext_mem_k;        /* 0x02 */
        UINT16 orig_video_page;  /* 0x04 */
        UINT8  orig_video_mode;  /* 0x06 */
        UINT8  orig_video_cols;  /* 0x07 */
        UINT8  flags;            /* 0x08 */
        UINT8  unused2;          /* 0x09 */
        UINT16 orig_video_ega_bx;/* 0x0a */
        UINT16 unused3;          /* 0x0c */
        UINT8  orig_video_lines; /* 0x0e */
        UINT8  orig_video_isVGA; /* 0x0f */
        UINT16 orig_video_points;/* 0x10 */

        /* VESA graphic mode -- linear frame buffer */
        UINT16 lfb_width;        /* 0x12 */
        UINT16 lfb_height;       /* 0x14 */
        UINT16 lfb_depth;        /* 0x16 */
        UINT32 lfb_base;         /* 0x18 */
        UINT32 lfb_size;         /* 0x1c */
        UINT16 cl_magic, cl_offset; /* 0x20 */
        UINT16 lfb_linelength;   /* 0x24 */
        UINT8  red_size;         /* 0x26 */
        UINT8  red_pos;          /* 0x27 */
        UINT8  green_size;       /* 0x28 */
        UINT8  green_pos;        /* 0x29 */
        UINT8  blue_size;        /* 0x2a */
        UINT8  blue_pos;         /* 0x2b */
        UINT8  rsvd_size;        /* 0x2c */
        UINT8  rsvd_pos;         /* 0x2d */
        UINT16 vesapm_seg;       /* 0x2e */
        UINT16 vesapm_off;       /* 0x30 */
        UINT16 pages;            /* 0x32 */
        UINT16 vesa_attributes;  /* 0x34 */
        UINT32 capabilities;     /* 0x36 */
        UINT8  _reserved[6];     /* 0x3a */
} __attribute__((packed));

struct boot_params {
        struct screen_info screen_info;
        UINT8 apm_bios_info[0x14];
        UINT8 _pad2[4];
        UINT64 tboot_addr;
        UINT8 ist_info[0x10];
        UINT8 _pad3[16];
        UINT8 hd0_info[16];
        UINT8 hd1_info[16];
        UINT8 sys_desc_table[0x10];
        UINT8 olpc_ofw_header[0x10];
        UINT8 _pad4[128];
        UINT8 edid_info[0x80];
        struct efi_info efi_info;
        UINT32 alt_mem_k;
        UINT32 scratch;
        UINT8 e820_entries;
        UINT8 eddbuf_entries;
        UINT8 edd_mbr_sig_buf_entries;
        UINT8 _pad6[6];
        struct setup_header hdr;
        UINT8 _pad7[0x290-0x1f1-sizeof(struct setup_header)];
        UINT32 edd_mbr_sig_buffer[16];
        struct e820_entry e820_map[128];
        UINT8 _pad8[48];
        UINT8 eddbuf[0x1ec];
        UINT8 _pad9[276];
};

/* See "Intel IA32/64 Architecture Software Developper Manual"
 * Volume 3 - Chapter 3.4.5 "Segment Descriptors".
 */
struct segment_descriptor {
        UINT16 limit0;
        UINT16 base0;
        UINT8 base1;
        UINTN type: 4;
        UINTN descriptor_type: 1;
        UINTN descriptor_privilege_level: 2;
        UINTN present: 1;
        UINTN limit1: 4;
        UINTN available: 1;
        UINTN code_segment_64bit: 1;
        UINTN default_operation_size: 1;
        UINTN granularity: 1;
        UINT8 base2;
} __attribute__((__packed__));

typedef struct {
        UINT16 limit;
        struct segment_descriptor *base;
} __attribute__((packed)) dt_addr_t;

static dt_addr_t *gdt;

typedef void(*kernel_func)(void *, struct boot_params *);

#define SEGMENT_TYPE_DATA             0
#define SEGMENT_TYPE_READ_WRITE       (1 << 1)
#define SEGMENT_TYPE_CODE             (1 << 3)
#define SEGMENT_TYPE_EXEC_READ        (1 << 1)
#define SEGMENT_TYPE_TASK             ((1 << 3) | 1)
#define SEGMENT_OPERATION_SIZE_16BITS 0
#define SEGMENT_OPERATION_SIZE_32BITS 1
#define SEGMENT_GRANULARITY_4KB       1
#define DESCRIPTOR_TYPE_CODE_OR_DATA  1

#ifndef __SUPPORT_ABL_BOOT
static EFI_STATUS setup_gdt(void)
{
        EFI_STATUS ret;

        ret = emalloc(sizeof(gdt), 8, (EFI_PHYSICAL_ADDRESS *)&gdt, TRUE);
        if (EFI_ERROR(ret))
                return ret;

        gdt->limit = 0x800;
        ret = emalloc(gdt->limit, 8, (EFI_PHYSICAL_ADDRESS *)&gdt->base, TRUE);
        if (EFI_ERROR(ret))
                return ret;

        memset(gdt->base, 0x0, gdt->limit);

        /* According to "Intel IA32/64 Architecture Software
         * Developper Manual"
         * Volume 3 - Chapter 3.5.1 "Segment Descriptor Tables"
         * The first descriptor in the GDT is not used by the
         * processor.  */

        gdt->base[1].limit0 = 0xffff;
        gdt->base[1].base0 = 0x0000;
        gdt->base[1].base1 = 0x00;
        gdt->base[1].type = SEGMENT_TYPE_CODE | SEGMENT_TYPE_EXEC_READ;
        gdt->base[1].descriptor_type = DESCRIPTOR_TYPE_CODE_OR_DATA;
        gdt->base[1].descriptor_privilege_level = 0;
        gdt->base[1].present = 1;
        gdt->base[1].limit1 = 0xf;
        gdt->base[1].available = 0;
        gdt->base[1].code_segment_64bit = 0;
        gdt->base[1].default_operation_size = SEGMENT_OPERATION_SIZE_32BITS;
        gdt->base[1].granularity = SEGMENT_GRANULARITY_4KB;
        gdt->base[1].base2 = 0x00;

        gdt->base[2] = gdt->base[1];
        gdt->base[2].type = SEGMENT_TYPE_DATA | SEGMENT_TYPE_READ_WRITE;

        gdt->base[3].limit0 = 0x0000;
        gdt->base[3].base0 = 0x0000;
        gdt->base[3].base1 = 0x00;
        gdt->base[3].type = SEGMENT_TYPE_TASK;
        gdt->base[3].descriptor_type = 0;
        gdt->base[3].descriptor_privilege_level = 0;
        gdt->base[3].present = 1;
        gdt->base[3].limit1 = 0x0;
        gdt->base[3].available = 0;
        gdt->base[3].code_segment_64bit = 0;
        gdt->base[3].default_operation_size = SEGMENT_OPERATION_SIZE_16BITS;
        gdt->base[3].granularity = SEGMENT_GRANULARITY_4KB;
        gdt->base[3].base2 = 0x00;

        return EFI_SUCCESS;
}
#endif  /* __SUPPORT_ABL_BOOT */

/* WARNING: Do not make any call that might change the memory mapping
 * (allocation, print, ...) in this function.  */
static void setup_e820_map(struct boot_params *boot_params,
                           EFI_MEMORY_DESCRIPTOR *mem_entries,
                           UINTN nr_entries,
                           UINTN entry_sz)
{
        struct e820_entry *e820_map = boot_params->e820_map;
        UINTN i, n_page = 0;

        for (i = 0; i < nr_entries; i++) {
                EFI_MEMORY_DESCRIPTOR *d;
                unsigned int cur_type = 0;

                d = (EFI_MEMORY_DESCRIPTOR *)((unsigned long)mem_entries + (i * entry_sz));
                switch (d->Type) {
                case EfiReservedMemoryType:
                case EfiRuntimeServicesCode:
                case EfiRuntimeServicesData:
                case EfiMemoryMappedIO:
                case EfiMemoryMappedIOPortSpace:
                case EfiPalCode:
                        cur_type = E820_RESERVED;
                        break;

                case EfiUnusableMemory:
                        cur_type = E820_UNUSABLE;
                        break;

                case EfiACPIReclaimMemory:
                        cur_type = E820_ACPI;
                        break;

                case EfiLoaderCode:
                case EfiLoaderData:
                case EfiBootServicesCode:
                case EfiBootServicesData:
                case EfiConventionalMemory:
                        cur_type = E820_RAM;
                        break;

                case EfiACPIMemoryNVS:
                        cur_type = E820_NVS;
                        break;

                default:
                        continue;
                }

                if (n_page &&
                    e820_map[n_page - 1].type == cur_type &&
                    (e820_map[n_page - 1].addr + e820_map[n_page - 1].size) == d->PhysicalStart) {
                        e820_map[n_page - 1].size += d->NumberOfPages << EFI_PAGE_SHIFT;
                        continue;
                }

                e820_map[n_page].addr = d->PhysicalStart;
                e820_map[n_page].size = d->NumberOfPages << EFI_PAGE_SHIFT;
                e820_map[n_page].type = cur_type;
                n_page++;
        }

        boot_params->e820_entries = n_page;
}

/* WARNING: Do not make any call that might change the memory mapping
 * (allocation, print, ...) in this function.  */
static EFI_STATUS setup_memory_map(struct boot_params *boot_params, UINTN *key)
{
        UINTN nr_entries, entry_sz;
        EFI_MEMORY_DESCRIPTOR *mem_entries;
        UINT32 entry_ver;
        struct efi_info *efi = &boot_params->efi_info;

        /* This function can be called several times. The previous
         * memory map buffer must be freed. */
        if (efi->efi_memmap) {
                UINTN prev_memmap = efi->efi_memmap;
#ifdef  __LP64__
                prev_memmap = prev_memmap |
                        (EFI_PHYSICAL_ADDRESS)efi->efi_memmap_hi << 32;
#endif
                FreePool((VOID *)prev_memmap);
        }

        mem_entries = LibMemoryMap(&nr_entries, key, &entry_sz, &entry_ver);
        if (!mem_entries)
                return EFI_OUT_OF_RESOURCES;

        if (is_UEFI()) {
                efi->efi_systab = (UINT32)(UINTN)ST;
                efi->efi_memdesc_size = entry_sz;
                efi->efi_memdesc_version = entry_ver;
                efi->efi_memmap = (UINT32)(UINTN)mem_entries;
                efi->efi_memmap_size = entry_sz * nr_entries;
#ifdef  __LP64__
                efi->efi_systab_hi = (EFI_PHYSICAL_ADDRESS)ST >> 32;
                efi->efi_memmap_hi = (EFI_PHYSICAL_ADDRESS)mem_entries >> 32;
#endif

                memcpy(&efi->efi_loader_signature,
                       EFI_LOADER_SIGNATURE, sizeof(efi->efi_loader_signature));
        }

        setup_e820_map(boot_params, mem_entries, nr_entries, entry_sz);
        if (!is_UEFI())
                FreePool(mem_entries);

        return EFI_SUCCESS;
}

static inline EFI_STATUS handover_jump(EFI_HANDLE image,
                                       struct boot_params *boot_params,
                                       EFI_PHYSICAL_ADDRESS kernel_start)
{
        EFI_STATUS ret = EFI_LOAD_ERROR;
        UINTN map_key, i;

#ifdef RPMB_STORAGE
        clear_rpmb_key();
#endif
        log(L"handover jump ...\n");

#ifndef __SUPPORT_ABL_BOOT
        ret = setup_gdt();
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to setup GDT");
                return ret;
        }
#endif  /* __SUPPORT_ABL_BOOT */

        /* According to UEFI specification 2.4 Chapter 6.4
         * EFI_BOOT_SERVICES.ExitBootServices(), Firmware
         * implementation may choose to do a partial shutdown of the
         * boot services during the first call to ExitBootServices().
         * Hence, we give two chances to ExitBootServices() to
         * succeed.
         */
        for (i = 0; i < 2; i++) {
                ret = setup_memory_map(boot_params, &map_key);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"Failed to setup memory map");
                        return ret;
                }

                /* Do not add extra code between setup_memory_map() call and
                 * ExitBootServices() call or memory_map key might mismatch
                 * and ExitBootServices call might fail.
                 */

                ret = uefi_call_wrapper(BS->ExitBootServices, 2, image, map_key);
                if (!EFI_ERROR(ret))
                        goto boot;
        }

        return ret;

boot:

#if __LP64__
        /* The 64-bit kernel entry is 512 bytes after the start. */
        kernel_start += 512;
#endif

        /* Load GDT. */
        if (gdt)
                asm volatile ("lgdt %0" :: "m" (*gdt));

        asm volatile ("cli; jmp *%0"
                      : /* no outputs */
                      : "m" (kernel_start), "a" (0), "S" (boot_params), "D"(0)
                      : "memory");

        /* Shouldn't get here. */
        return EFI_LOAD_ERROR;
}



UINT32 pagealign(struct boot_img_hdr *hdr, UINT32 blob_size)
{
        UINT32 page_mask = hdr->page_size - 1;
        return (blob_size + page_mask) & (~page_mask);
}


UINTN bootimage_size(struct boot_img_hdr *aosp_header)
{
        UINTN size;

        size = pagealign(aosp_header, aosp_header->kernel_size) +
               pagealign(aosp_header, aosp_header->ramdisk_size) +
               pagealign(aosp_header, aosp_header->second_size) +
               aosp_header->page_size;

        if (aosp_header->header_version == 1)
                size += pagealign(aosp_header, aosp_header->recovery_dtbo_size);

        return size;
}


struct boot_img_hdr *get_bootimage_header(VOID *bootimage_blob)
{
        struct boot_img_hdr *hdr;

        if (!bootimage_blob)
                return NULL;

        hdr = (struct boot_img_hdr *)bootimage_blob;
        if (memcmp(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE))
                return NULL;
        return hdr;
}


static EFI_STATUS setup_ramdisk(UINT8 *bootimage)
{
        struct boot_img_hdr *aosp_header;
        struct boot_params *bp;
        UINT32 roffset, rsize;
        EFI_PHYSICAL_ADDRESS ramdisk_addr;
        EFI_STATUS ret;

        aosp_header = (struct boot_img_hdr *)bootimage;
        bp = (struct boot_params *)(bootimage + aosp_header->page_size);

        roffset = aosp_header->page_size + pagealign(aosp_header,
                        aosp_header->kernel_size);
        rsize = aosp_header->ramdisk_size;
        if (!rsize) {
                debug(L"boot image has no ramdisk");
                return EFI_SUCCESS; // no ramdisk, so nothing to do
        }

        bp->hdr.ramdisk_len = rsize;
        debug(L"ramdisk size %d", rsize);
        ret = emalloc(rsize, 0x1000, &ramdisk_addr, FALSE);
        if (EFI_ERROR(ret))
                return ret;

        if ((UINTN)ramdisk_addr > bp->hdr.ramdisk_max) {
                error(L"Ramdisk address is too high!");
                efree(ramdisk_addr, rsize);
                return EFI_OUT_OF_RESOURCES;
        }
        memcpy((VOID *)(UINTN)ramdisk_addr, bootimage + roffset, rsize);
        bp->hdr.ramdisk_start = (UINT32)(UINTN)ramdisk_addr;
        return EFI_SUCCESS;
}


static EFI_STATUS setup_acpi_table(VOID *bootimage,
                                   __attribute__((__unused__)) enum boot_target target)
{
        struct boot_img_hdr *aosp_header;

        debug(L"Setup acpi table");
        aosp_header = (struct boot_img_hdr *)bootimage;

#ifdef USE_ACPIO
        if (aosp_header->header_version == 1) {
                VOID *acpio;
                acpio = bootimage + aosp_header->recovery_dtbo_offset;
                return install_acpi_table_from_recovery_acpio(acpio, target);
        }
#endif
#ifdef USE_FIRSTSTAGE_MOUNT
        return install_firststage_mount_ssdt(target);
#endif
        debug(L"Acpi table not setup");
        return EFI_SUCCESS;
}


static CHAR16 *get_serial_port(void)
{
        CHAR8 *data;
        UINTN size;
        CHAR16 *val, *pos;
        EFI_STATUS ret;

        ret = get_efi_variable(&loader_guid, SERIAL_PORT_VAR,
                        &size, (VOID **)&data, NULL);
        if (EFI_ERROR(ret))
                goto error;

        if (size < 3) {
                FreePool(data);
                goto error;
        }

        /* Historical: older Fastboot versions saved this as a 16-bit
         * string, newer ones as 8-bit. Do a little inspection to
         * see which is the case, and upconvert as necessary */
        if (data[0] && data[1]) {
                /* 16 bit string with 8bit data would have at least one 0*/
                data[size - 1] = '\0';
                val = stra_to_str(data);
                FreePool(data);
                if (!val)
                        goto error;
        } else {
                if (size % 2 == 0) {
                        data[size - 1] = '\0';
                        data[size - 2] = '\0';
                        val = (CHAR16 *)data;
                } else {
                        FreePool(data);
                        goto error;
                }
        }

        pos = val;

        /* Only [0-9a-zA-Z,] acceptable. Any funny business, give up */
        while (*pos) {
                if ( ! ( (*pos >= L'0' && *pos <= L'9') ||
                         (*pos >= L'a' && *pos <= L'z') ||
                         (*pos >= L'A' && *pos <= L'Z') ||
                         *pos == L',')) {
                        FreePool(val);
                        goto error;
                }
                pos++;
        }
        return val;
error:
        return NULL;
}


#ifndef __SUPPORT_ABL_BOOT
static CHAR16 *get_wake_reason(void)
{
        enum wake_sources wake_source;

        wake_source = rsci_get_wake_source();
        switch(wake_source) {
        case WAKE_BATTERY_INSERTED:
                return L"battery_inserted";
        case WAKE_USB_CHARGER_INSERTED:
                return L"usb_charger_inserted";
        case WAKE_ACDC_CHARGER_INSERTED:
                return L"acdc_charger_inserted";
        case WAKE_POWER_BUTTON_PRESSED:
                return L"power_button_pressed";
        case WAKE_RTC_TIMER:
                return L"rtc_timer";
        case WAKE_BATTERY_REACHED_IA_THRESHOLD:
                return L"battery_reached_ia_threshold";
        default:
                debug(L"wake_source = 0x%02x", wake_source);
        }

        return NULL;
}


static CHAR16 *get_reset_reason(void)
{
        enum reset_sources reset_source;

        reset_source = rsci_get_reset_source();
        switch (reset_source) {
#ifndef IGNORE_NOT_APPLICABLE_RESET
        case RESET_NOT_APPLICABLE:
                return L"not_applicable";
#endif
        case RESET_OS_INITIATED:
                return OS_INITIATED;
        case RESET_FORCED:
                return L"forced";
        case RESET_FW_UPDATE:
                return L"firmware_update";
        case RESET_KERNEL_WATCHDOG:
                return L"watchdog";
        case RESET_SECURITY_WATCHDOG:
                return L"security_watchdog";
        case RESET_SECURITY_INITIATED:
                return L"security_initiated";
        case RESET_EC_WATCHDOG:
                return L"ec_watchdog";
        case RESET_PMIC_WATCHDOG:
                return L"pmic_watchdog";
        case RESET_SHORT_POWER_LOSS:
                return L"short_power_loss";
        case RESET_PLATFORM_SPECIFIC:
                return L"platform_specific";
        case RESET_UNKNOWN:
                return L"unknown";
        default:
                debug(L"reset_source = 0x%02x", reset_source);
        }

        return NULL;
}


static CHAR16 *get_boot_reason(void)
{
        CHAR16 *bootreason, *pos;

        bootreason = get_wake_reason();
        if (bootreason)
                goto done;

        bootreason = get_reset_reason();
        if (bootreason && StrCmp(bootreason, OS_INITIATED))
                goto done;

        /* in case of an OS initiated reboot => get reason from efi var */
        bootreason = get_reboot_reason();
        if (!bootreason) {
                error(L"Error while trying to read the reboot reason");
                bootreason = L"unknown";
                goto done;
        }

        pos = bootreason;
        while (*pos) {
                /* Only allow alphanumeric characters */
                if (!((*pos >= L'0' && *pos <= L'9') ||
                            (*pos >= L'a' && *pos <= L'z') ||
                            *pos == L'_')) {
                        error(L"Error, reboot reason contains non-alphanumeric characters");
                        bootreason = L"unknown";
                        goto done;
                }
                pos++;
        }

done:
        del_reboot_reason();
        return bootreason;
}
#endif

static EFI_STATUS prepend_command_line(CHAR16 **cmdline, CHAR16 *fmt, ...)
{
        CHAR16 *old;
        va_list args;
        CHAR16 *string;
        CHAR16 *new;

        old = *cmdline;
        va_start(args, fmt);
        string = VPoolPrint(fmt, args);
        va_end(args);

        if (!string)
                return EFI_OUT_OF_RESOURCES;

        new = PoolPrint(L"%s %s", string, old);
        FreePool(string);
        if (!new)
                return EFI_OUT_OF_RESOURCES;

        FreePool(old);
        *cmdline = new;
        return EFI_SUCCESS;
}


static CHAR16 *get_command_line(IN struct boot_img_hdr *aosp_header,
                                IN enum boot_target boot_target)
{
        CHAR16 *cmdline16 = NULL;
#ifndef USER
        CHAR16 *cmdline_append = NULL;
        CHAR16 *cmdline_prepend = NULL;
        BOOLEAN needs_pause = FALSE;

        if (boot_target == NORMAL_BOOT || boot_target == MEMORY) {
                cmdline16 = get_efi_variable_str8(&loader_guid, CMDLINE_REPLACE_VAR);
                cmdline_append = get_efi_variable_str8(&loader_guid, CMDLINE_APPEND_VAR);
                cmdline_prepend = get_efi_variable_str8(&loader_guid, CMDLINE_PREPEND_VAR);
        }
#else
        (void)boot_target; /* Get rid of a unused parameter warning */
#endif

        if (!cmdline16) {
                CHAR8 full_cmdline[BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE];
                int offset = BOOT_ARGS_SIZE;

                /* include the potential NUL terminal char */
                memcpy(full_cmdline, aosp_header->cmdline, BOOT_ARGS_SIZE);
                /* if there is extra cmdline arguments */
                if (aosp_header->extra_cmdline[0]) {
                        /* legacy boot.img format cmdline is NUL terminated */
                        if (!aosp_header->cmdline[BOOT_ARGS_SIZE - 1])
                                offset--;
                        memcpy(full_cmdline + offset,
                               aosp_header->extra_cmdline,
                               BOOT_EXTRA_ARGS_SIZE);
                }

                cmdline16 = stra_to_str(full_cmdline);

                if (!cmdline16)
                        return NULL;
#ifndef USER
        } else {
                error(L"Boot image command line overridden with '%s'", cmdline16);
                needs_pause = TRUE;
#endif
        }

#ifndef USER
        if (cmdline_prepend) {
                EFI_STATUS ret;

                error(L"Prepending '%s' to command line", cmdline_prepend);
                needs_pause = TRUE;

                ret = prepend_command_line(&cmdline16, L"%s", cmdline_prepend);
                FreePool(cmdline_prepend);
                if (EFI_ERROR(ret))
                        error(L"couldn't prepend to command line");
        }

        if (cmdline_append) {
                EFI_STATUS ret;

                error(L"Appending '%s' to command line", cmdline_append);
                needs_pause = TRUE;

                ret = prepend_command_line(&cmdline_append, L"%s", cmdline16);
                if (EFI_ERROR(ret)) {
                        error(L"couldn't prepend to command line");
                        FreePool(cmdline_append);
                } else {
                        FreePool(cmdline16);
                        cmdline16 = cmdline_append;
                }
        }

        if (needs_pause)
                pause(1);
#endif

        return cmdline16;
}

EFI_STATUS get_bootimage_2nd(VOID *bootimage, VOID **second, UINT32 *size)
{
        struct boot_img_hdr *bh;
        UINT32 offset;

        bh = get_bootimage_header(bootimage);
        if (!bh)
                return EFI_INVALID_PARAMETER;

        /* Nothing to do? */
        if (bh->second_size == 0)
                return EFI_NOT_FOUND;

        offset = bh->page_size + pagealign(bh, bh->kernel_size) +
                 pagealign(bh, bh->ramdisk_size);
        *second = (UINT8 *)bootimage + offset;
        *size = bh->second_size;
        return EFI_SUCCESS;
}

#ifdef HAL_AUTODETECT
EFI_STATUS get_bootimage_blob(VOID *bootimage, enum blobtype btype, VOID **blob,
                              UINT32 *blobsize)
{
        VOID *second;
        UINT32 second_size;
        struct blobstore *bs;
        char *device_id;
        EFI_STATUS ret;

        device_id = get_device_id();
        debug(L"Lookup blobstore data %a-%d", device_id, btype);

        ret = get_bootimage_2nd(bootimage, &second, &second_size);
        if (EFI_ERROR(ret))
                return EFI_UNSUPPORTED;

        bs = blobstore_get(second, second_size);
        if (!bs)
                return EFI_UNSUPPORTED;

        if (blobstore_get_item(bs, device_id, btype, blob, blobsize))
                return EFI_NOT_FOUND;

        return EFI_SUCCESS;
}

/* File format is a series of lines, which could be a blank line,
 * #<comment> or <key>=<value>. We don't do sanity checking as the
 * blobstore is covered by the verified boot signature and is hence
 * trusted */
static EFI_STATUS parse_bootvars_line(char *line, VOID *ctx)
{
        CHAR16 **cmdline16 = (CHAR16 **)ctx;

        if (strlen((CHAR8 *)line) == 0 || line[0] == '#')
                return EFI_SUCCESS;

        return prepend_command_line(cmdline16, L"%a", line);
}

static EFI_STATUS add_bootvars(VOID *bootimage, CHAR16 **cmdline16)
{
        VOID *bootvars;
        UINT32 bvsize;
        EFI_STATUS ret;

        ret = get_bootimage_blob(bootimage, BLOB_TYPE_BOOTVARS, &bootvars,
                                 &bvsize);
        if (EFI_ERROR(ret)) {
                if (ret == EFI_UNSUPPORTED || ret == EFI_NOT_FOUND) {
                        debug(L"Not setting bootvars: %r", ret);
                        return EFI_SUCCESS;
                }
                efi_perror(ret, L"Couldn't get bootvars");
                return ret;
        }

        return parse_text_buffer(bootvars, bvsize, parse_bootvars_line,
                                 cmdline16);
}
#endif

#define ROOTFS_PREFIX L"skip_initramfs rootwait ro init=/init root="

#ifndef USE_AVB
#ifndef __SUPPORT_ABL_BOOT
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
#endif  /* __SUPPORT_ABL_BOOT */

#else
#define AVB_ROOTFS_PREFIX L"skip_initramfs rootwait ro init=/init"
#define DISABLE_AVB_ROOTFS_PREFIX L" root="
static EFI_STATUS avb_prepend_command_line_rootfs(
                __attribute__((__unused__)) OUT CHAR16 **cmdline16,
                IN enum boot_target boot_target)
{
        EFI_STATUS ret = EFI_SUCCESS;

        if (boot_target == RECOVERY)
                return ret;

        if (use_slot()) {
                ret = prepend_command_line(cmdline16, AVB_ROOTFS_PREFIX);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"Failed to add AVB rootfs prefix");
                        return ret;
                }
        }
        return ret;
}
#endif  // defined USE_AVB

#ifndef __SUPPORT_ABL_BOOT
static EFI_STATUS setup_command_line(
                IN UINT8 *bootimage,
                IN enum boot_target boot_target,
                IN EFI_GUID *swap_guid,
                IN UINT8 boot_state,
#ifdef USE_AVB
                IN AvbSlotVerifyData *slot_data
#else
                IN X509 *verity_cert
#endif
                )
{
        CHAR16 *cmdline16 = NULL;
        char   *serialno = NULL;
        CHAR16 *serialport = NULL;
        CHAR16 *bootreason = NULL;

        EFI_PHYSICAL_ADDRESS cmdline_addr;
        CHAR8 *cmdline;
        UINTN cmdlen;
        UINTN avb_cmdlen = 0;
        EFI_STATUS ret;
        struct boot_params *buf;
        struct boot_img_hdr *aosp_header;
        CHAR8 time_str8[128] = {0};
        CHAR16 *time_str16 = NULL;
#ifdef USE_AVB
        EFI_GUID system_uuid;
#endif

        aosp_header = (struct boot_img_hdr *)bootimage;
        buf = (struct boot_params *)(bootimage + aosp_header->page_size);

        cmdline16 = get_command_line(aosp_header, boot_target);
        if (!cmdline16) {
                ret = EFI_OUT_OF_RESOURCES;
                goto out;
        }

        /* Append serial number from DMI */
        serialno = get_serial_number();
        if (serialno) {
                ret = prepend_command_line(&cmdline16,
                                L"androidboot.serialno=%a g_ffs.iSerialNumber=%a",
                                serialno, serialno);
                if (EFI_ERROR(ret))
                        goto out;
        }

        if (boot_target == CHARGER) {
                ret = prepend_command_line(&cmdline16,
                                L"androidboot.mode=charger");
                if (EFI_ERROR(ret))
                        goto out;
        }

        bootreason = get_boot_reason();
        if (!bootreason) {
                ret = EFI_OUT_OF_RESOURCES;
                goto out;
        }

        ret = prepend_command_line(&cmdline16, L"androidboot.bootreason=%s", bootreason);
        if (EFI_ERROR(ret))
                goto out;

        ret = prepend_command_line(&cmdline16, L"androidboot.verifiedbootstate=%s",
                                   boot_state_to_string(boot_state));
        if (EFI_ERROR(ret))
                goto out;

        if (swap_guid) {
                ret = prepend_command_line(&cmdline16, L"resume=PARTUUID=%g",
                        swap_guid);
                if (EFI_ERROR(ret))
                        goto out;
        }

        serialport = get_serial_port();
        if (serialport) {
                ret = prepend_command_line(&cmdline16, L"console=%s", serialport);
                if (EFI_ERROR(ret))
                        goto out;
        }

        prepend_command_line(&cmdline16, L"androidboot.selinux=permissive");

#ifndef USER
        if (get_disable_watchdog()) {
                ret = prepend_command_line(&cmdline16, CONVERT_TO_WIDE(TCO_OPT_DISABLED));
                if (EFI_ERROR(ret))
                        goto out;
        }
#endif

        PCI_DEVICE_PATH *boot_device = get_boot_device();
        if (boot_device) {
                ret = prepend_command_line(&cmdline16,
                                           L"androidboot.diskbus=%02x.%x",
                                           boot_device->Device,
                                           boot_device->Function);
                if (EFI_ERROR(ret))
                        goto out;
        } else
                error(L"Boot device not found, diskbus parameter not set in the commandline!");

        ret = prepend_command_line(&cmdline16, L"androidboot.bootloader=%a",
                                   get_property_bootloader());
        if (EFI_ERROR(ret))
                goto out;

        ret = prepend_command_line(&cmdline16, L"androidboot.acpio_idx=%a ",
                                   acpi_loaded_table_idx_to_string());
        if (EFI_ERROR(ret))
                goto out;

#ifdef HAL_AUTODETECT
        ret = prepend_command_line(&cmdline16, L"androidboot.brand=%a "
                                   "androidboot.name=%a androidboot.device=%a "
                                   "androidboot.model=%a", get_property_brand(),
                                   get_property_name(), get_property_device(),
                                   get_property_model());
        if (EFI_ERROR(ret))
                goto out;

        ret = add_bootvars(bootimage, &cmdline16);
        if (EFI_ERROR(ret))
                goto out;
#endif

#ifndef USE_AVB
        if ((boot_target == NORMAL_BOOT || boot_target == CHARGER || boot_target == MEMORY) &&
            recovery_in_boot_partition()) {
                ret = prepend_command_line_rootfs(&cmdline16, verity_cert);
                if (verity_cert)
                        X509_free(verity_cert);
                if (EFI_ERROR(ret))
                        goto out;

                if (slot_get_verity_corrupted()) {
                        ret = prepend_command_line(&cmdline16, L"androidboot.veritymode=eio");
                        if (EFI_ERROR(ret))
                                goto out;
                }
        }
#else // defined USE_AVB
        avb_prepend_command_line_rootfs(&cmdline16, boot_target);

#ifdef AVB_CMDLINE
        if (slot_data && slot_data->cmdline && boot_target != RECOVERY) {
                avb_cmdlen = strlen((const CHAR8*)slot_data->cmdline);
        }
#endif // AVB_CMDLINE

        if (use_slot()) {
                if (slot_get_active()) {
                        ret = prepend_command_line(&cmdline16, L"androidboot.slot_suffix=%a",
                                                   slot_get_active());
                        if (EFI_ERROR(ret))
                                goto out;
                }

#ifdef AVB_CMDLINE
                if (slot_data && slot_data->cmdline && (!avb_strstr(slot_data->cmdline,"root=")))
#endif // AVB_CMDLINE
                {
                        ret = gpt_get_partition_uuid(slot_label(SYSTEM_LABEL),
                                                                &system_uuid, LOGICAL_UNIT_USER);
                        if (EFI_ERROR(ret)) {
                                efi_perror(ret, L"Failed to get %s partition UUID", SYSTEM_LABEL);
                                goto out;
                        }

                        ret = prepend_command_line(&cmdline16, DISABLE_AVB_ROOTFS_PREFIX "PARTUUID=%g",
                                                   &system_uuid);
                        if (EFI_ERROR(ret))
                                goto out;
                }
        }
#endif // USE_AVB

        /* append stages boottime */
        set_boottime_stamp(TM_JMP_KERNEL);
        construct_stages_boottime(time_str8, sizeof(time_str8));
        time_str16 = stra_to_str(time_str8);
        if (time_str16) {
                ret = prepend_command_line(&cmdline16, L"androidboot.boottime=%s", time_str16);
                if (EFI_ERROR(ret))
                        goto out;
        }

        /* Documentation/x86/boot.txt: "The kernel command line can be located
         * anywhere between the end of the setup heap and 0xA0000" */
        cmdline_addr = 0xA0000;
        cmdlen = StrLen(cmdline16);
        ret = allocate_pages(AllocateMaxAddress, EfiLoaderData,
                             EFI_SIZE_TO_PAGES(cmdlen + 1 + avb_cmdlen + 1),
                             &cmdline_addr);
        if (EFI_ERROR(ret))
                goto out;

        cmdline = (CHAR8 *)(UINTN)cmdline_addr;
        ret = str_to_stra(cmdline, cmdline16, cmdlen + 1);
        if (EFI_ERROR(ret)) {
                error(L"Non-ascii characters in command line");
                free_pages(cmdline_addr, EFI_SIZE_TO_PAGES(cmdlen + 1 + avb_cmdlen + 1));
                goto out;
        }

#ifdef USE_AVB
        if (avb_cmdlen > 0) {
                cmdline[cmdlen] = ' ';
                memcpy(cmdline + cmdlen + 1, slot_data->cmdline, avb_cmdlen);
                cmdlen += avb_cmdlen + 1;
                cmdline[cmdlen] = 0;
        }
#endif

        buf->hdr.cmd_line_ptr = (UINT32)(UINTN)cmdline;
        ret = EFI_SUCCESS;
out:
        FreePool(cmdline16);
        if (serialport)
                FreePool(serialport);
        if (time_str16)
                FreePool(time_str16);

        return ret;
}
#endif

extern EFI_GUID GraphicsOutputProtocol;
#define VIDEO_TYPE_EFI 0x70

static void setup_screen_info_from_gop(struct screen_info *pinfo)
{
        EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
        EFI_STATUS ret;

        ret = LibLocateProtocol(&GraphicsOutputProtocol, (void **)&gop);
        if (EFI_ERROR(ret)) {
                debug(L"Unable to locate graphics output protocol: %r", ret);
                return;
        }

        pinfo->orig_video_isVGA = VIDEO_TYPE_EFI;
        pinfo->lfb_base = (UINT32)gop->Mode->FrameBufferBase;
        pinfo->lfb_size = gop->Mode->FrameBufferSize;
        pinfo->lfb_width = gop->Mode->Info->HorizontalResolution;
        pinfo->lfb_height = gop->Mode->Info->VerticalResolution;
        pinfo->lfb_linelength = gop->Mode->Info->PixelsPerScanLine * 4;
}

static EFI_STATUS handover_kernel(CHAR8 *bootimage, EFI_HANDLE parent_image)
{
        EFI_PHYSICAL_ADDRESS kernel_start;
        EFI_PHYSICAL_ADDRESS boot_addr;
        struct boot_params *boot_params;
        UINT64 init_size;
        EFI_STATUS ret;
        struct boot_img_hdr *aosp_header;
        struct boot_params *buf;
        UINT8 setup_sectors;
        UINT32 setup_size;
        UINT32 ksize;
        UINT32 koffset;

        aosp_header = (struct boot_img_hdr *)bootimage;
        buf = (struct boot_params *)(bootimage + aosp_header->page_size);

        koffset = aosp_header->page_size;
        setup_sectors = buf->hdr.setup_secs;
        setup_sectors++; /* Add boot sector */
        setup_size = (UINT32)setup_sectors * 512;
        ksize = aosp_header->kernel_size - setup_size;
        kernel_start = buf->hdr.pref_address;
        init_size = buf->hdr.init_size;
        buf->hdr.loader_id = 0xFF;
        memset(&buf->screen_info, 0x0, sizeof(buf->screen_info));

        setup_screen_info_from_gop(&buf->screen_info);

        ret = allocate_pages(AllocateAddress, EfiLoaderData,
                             EFI_SIZE_TO_PAGES(init_size), &kernel_start);
        if (EFI_ERROR(ret)) {
                /*
                 * We failed to allocate the preferred address, so
                 * just allocate some memory and hope for the best.
                 */
                ret = emalloc(init_size, buf->hdr.kernel_alignment, &kernel_start,
                              FALSE);
                if (EFI_ERROR(ret))
                        return ret;
        }

        memcpy((CHAR8 *)(UINTN)kernel_start, bootimage + koffset + setup_size, ksize);

        boot_addr = 0x3fffffff;
        ret = allocate_pages(AllocateMaxAddress, EfiLoaderData,
                             EFI_SIZE_TO_PAGES(16384), &boot_addr);
        if (EFI_ERROR(ret))
                goto out;

#ifdef USE_WATCHDOG
        if (!watchdog_disabled_from_cmdline((CHAR8 *)(UINTN)buf->hdr.cmd_line_ptr)) {
                ret = start_watchdog(TCO_DEFAULT_TIMEOUT);
                if (EFI_ERROR(ret))
                        efi_perror(ret, L"Failed to start watchdog");
        }
#endif

        /* Free UI resources. */
        ui_free();

        log_flush_to_var(FALSE);

        boot_params = (struct boot_params *)(UINTN)boot_addr;
        memset(boot_params, 0x0, 16384);

        /* Save screen_info */
        memcpy(&boot_params->screen_info, &buf->screen_info,
                sizeof(struct screen_info));
        /* See Linux Documentation/x86/boot.txt */
        memcpy(&boot_params->hdr, (CHAR8 *)(&buf->hdr),
               ((CHAR8 *)buf)[0x201] + 0x202 - offsetof(struct boot_params, hdr));
        boot_params->hdr.code32_start = (UINT32)((UINT64)kernel_start);

        ret = handover_jump(parent_image, boot_params, kernel_start);
        /* Shouldn't get here */
        efi_perror(ret, L"handover to Linux kernel has failed");

        free_pages(boot_addr, EFI_SIZE_TO_PAGES(16384));
out:
        efree(kernel_start, ksize);
        return ret;
}

EFI_STATUS android_image_load_partition(
                IN const CHAR16 *label,
                OUT VOID **bootimage_p)
{
        UINT32 MediaId;
        UINT32 img_size;
        VOID *bootimage;
        EFI_STATUS ret;
        struct boot_img_hdr aosp_header;
        struct gpt_partition_interface gpart;
        UINTN partition_start;

        *bootimage_p = NULL;
        ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
        if (EFI_ERROR(ret)) {
                error(L"Partition %s not found", label);
                return ret;
        }
        MediaId = gpart.bio->Media->MediaId;
        partition_start = gpart.part.starting_lba * gpart.bio->Media->BlockSize;

        debug(L"Reading boot image header");
        ret = uefi_call_wrapper(gpart.dio->ReadDisk, 5, gpart.dio, MediaId,
                                partition_start,
                                sizeof(aosp_header), &aosp_header);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"ReadDisk (header)");
                return ret;
        }
        if (memcmp(aosp_header.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
                error(L"This partition does not appear to contain an Android boot image");
                return EFI_INVALID_PARAMETER;
        }

        img_size = bootimage_size(&aosp_header) + BOOT_SIGNATURE_MAX_SIZE;
        bootimage = AllocatePool(img_size);
        if (!bootimage)
                return EFI_OUT_OF_RESOURCES;

        debug(L"Reading full boot image (%d bytes)", img_size);
        ret = uefi_call_wrapper(gpart.dio->ReadDisk, 5, gpart.dio, MediaId, partition_start,
                                img_size, bootimage);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"ReadDisk");
                FreePool(bootimage);
                return ret;
        }

        *bootimage_p = bootimage;
        return EFI_SUCCESS;
}


EFI_STATUS android_image_load_file(
                IN EFI_HANDLE device,
                IN CHAR16 *loader,
                IN BOOLEAN delete,
                OUT VOID **bootimage_p)
{
        EFI_STATUS ret, ret2;
        VOID *bootimage = NULL;
        EFI_DEVICE_PATH *path;
        EFI_GUID SimpleFileSystemProtocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
        EFI_GUID EfiFileInfoId = EFI_FILE_INFO_ID;
        EFI_FILE_IO_INTERFACE *drive;
        EFI_FILE_INFO *fileinfo = NULL;
        EFI_FILE *imagefile, *root;
        UINTN buffersize = sizeof(EFI_FILE_INFO);
        struct boot_img_hdr *aosp_header;

        *bootimage_p = NULL;
        debug(L"Locating boot image from file %s", loader);
        path = FileDevicePath(device, loader);
        if (!path) {
                error(L"Error getting device path.");
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return EFI_INVALID_PARAMETER;
        }

        /* Open the device */
        ret = uefi_call_wrapper(BS->HandleProtocol, 3, device,
                        &SimpleFileSystemProtocol, (void **)&drive);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"HandleProtocol (SimpleFileSystemProtocol)");
                return ret;
        }
        ret = uefi_call_wrapper(drive->OpenVolume, 2, drive, &root);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"OpenVolume");
                return ret;
        }

        /* Get information about the boot image file, we need to know
         * how big it is, and allocate a suitable buffer */
        ret = uefi_call_wrapper(root->Open, 5, root, &imagefile, loader,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Open");
                return ret;
        }
        fileinfo = AllocatePool(buffersize);
        if (!fileinfo)
                return EFI_OUT_OF_RESOURCES;

        ret = uefi_call_wrapper(imagefile->GetInfo, 4, imagefile,
                        &EfiFileInfoId, &buffersize, fileinfo);
        if (ret == EFI_BUFFER_TOO_SMALL) {
                /* buffersize updated with the required space for
                 * the request */
                FreePool(fileinfo);
                fileinfo = AllocatePool(buffersize);
                if (!fileinfo)
                        return EFI_OUT_OF_RESOURCES;
                ret = uefi_call_wrapper(imagefile->GetInfo, 4, imagefile,
                        &EfiFileInfoId, &buffersize, fileinfo);
        }
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"GetInfo");
                goto out;
        }
        buffersize = fileinfo->FileSize;

        /* Add BOOT_SIGNATURE_MAX_SIZE just in case the image is unsigned */
        bootimage = AllocatePool(buffersize + BOOT_SIGNATURE_MAX_SIZE);
        if (!bootimage) {
                ret = EFI_OUT_OF_RESOURCES;
                goto out;
        }

        /* Read the file into the buffer */
        ret = uefi_call_wrapper(imagefile->Read, 3, imagefile,
                        &buffersize, bootimage);
        if (ret == EFI_BUFFER_TOO_SMALL) {
                /* buffersize updated with the required space for
                 * the request. By the way it doesn't make any
                 * sense to me why this is needed since we supposedly
                 * got the file size from the GetInfo call but
                 * whatever... */
                FreePool(bootimage);
                bootimage = AllocatePool(buffersize);
                if (!fileinfo) {
                        ret = EFI_OUT_OF_RESOURCES;
                        goto out;
                }
                ret = uefi_call_wrapper(imagefile->Read, 3, imagefile,
                        &buffersize, bootimage);
        }
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Read");
                goto out;
        }

        debug(L"Read boot image from file (%d bytes)", buffersize);

        aosp_header = (struct boot_img_hdr *)bootimage;
        if (memcmp(aosp_header->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
                error(L"File does not appear to contain an Android boot image");
                ret = EFI_INVALID_PARAMETER;
        }
out:
        if (delete) {
                //this should close handle and flush FS
                ret2 = uefi_call_wrapper(imagefile->Delete, 1, imagefile);
                if (EFI_ERROR(ret2)) {
                        efi_perror(ret2, L"Couldn't delete source file");
                        goto out_free;
                }
        } else {
                ret2 = uefi_call_wrapper(imagefile->Close, 1, imagefile);
                if (EFI_ERROR(ret2)) {
                        efi_perror(ret2, L"Couldn't close source file");
                        goto out_free;
                }
        }

out_free:
        FreePool(fileinfo);
        if (ret == EFI_SUCCESS) {
                *bootimage_p = bootimage;
        } else {
                FreePool(bootimage);
        }
        return ret;
}

#ifdef USE_AVB
EFI_STATUS get_avb_flow_result(
                IN AvbSlotVerifyData *slot_data,
                IN bool allow_verification_error,
                IN AvbABFlowResult flow_result,
                IN OUT UINT8 *boot_state)
{
        AvbPartitionData *boot;
        const struct boot_img_hdr *header;

        if (!slot_data || !boot_state)
                return EFI_INVALID_PARAMETER;

        if (slot_data->num_loaded_partitions < 1) {
                avb_error("No avb partition.\n");
                return EFI_LOAD_ERROR;
        }

        boot = &slot_data->loaded_partitions[0];
        header = (const struct boot_img_hdr *)boot->data;
        /* Check boot image header magic field. */
        if (avb_memcmp(BOOT_MAGIC, header->magic, BOOT_MAGIC_SIZE)) {
                avb_error("Wrong image header magic.\n");
                return EFI_NOT_FOUND;
        }
        avb_debug("Image read success\n");

        switch (flow_result) {
        case AVB_AB_FLOW_RESULT_OK:
                if (allow_verification_error && *boot_state < BOOT_STATE_ORANGE)
                        *boot_state = BOOT_STATE_ORANGE;
                break;

        case AVB_AB_FLOW_RESULT_OK_WITH_VERIFICATION_ERROR:
        case AVB_AB_FLOW_RESULT_ERROR_OOM:
        case AVB_AB_FLOW_RESULT_ERROR_IO:
        case AVB_AB_FLOW_RESULT_ERROR_NO_BOOTABLE_SLOTS:
        case AVB_AB_FLOW_RESULT_ERROR_INVALID_ARGUMENT:
                if (allow_verification_error && *boot_state <= BOOT_STATE_ORANGE) {
                /* Do nothing since we allow this. */
                        avb_debugv("Allow avb ab flow with result ",
                        avb_ab_flow_result_to_string(flow_result),
                        " because |allow_verification_error| is true.\n",
                        NULL);
                        *boot_state = BOOT_STATE_ORANGE;
                } else
                        *boot_state = BOOT_STATE_RED;
                break;
        default:
                if (allow_verification_error && *boot_state <= BOOT_STATE_ORANGE)
                        *boot_state = BOOT_STATE_ORANGE;
                else
                        *boot_state = BOOT_STATE_RED;
                break;
        }

        return EFI_SUCCESS;
}

EFI_STATUS get_avb_result(
                IN AvbSlotVerifyData *slot_data,
                IN bool allow_verification_error,
                IN AvbSlotVerifyResult verify_result,
                IN OUT UINT8 *boot_state)
{
        AvbPartitionData *boot;
        const struct boot_img_hdr *header;

        if (!slot_data || !boot_state)
                return EFI_INVALID_PARAMETER;

        if (slot_data->num_loaded_partitions < 1) {
                avb_error("No avb partition.\n");
                return EFI_LOAD_ERROR;
        }

        boot = &slot_data->loaded_partitions[0];
        header = (const struct boot_img_hdr *)boot->data;
        /* Check boot image header magic field. */
        if (avb_memcmp(BOOT_MAGIC, header->magic, BOOT_MAGIC_SIZE)) {
                avb_error("Wrong image header magic.\n");
                return EFI_NOT_FOUND;
        }
        avb_debug("Image read success\n");

        switch (verify_result) {
        case AVB_SLOT_VERIFY_RESULT_OK:
                if (allow_verification_error && *boot_state < BOOT_STATE_ORANGE)
                        *boot_state = BOOT_STATE_ORANGE;
                break;

        case AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION:
        case AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX:
        case AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED:
                if (allow_verification_error && *boot_state <= BOOT_STATE_ORANGE) {
                /* Do nothing since we allow this. */
                        avb_debugv("Allow avb verified with result ",
                        avb_slot_verify_result_to_string(verify_result),
                        " because |allow_verification_error| is true.\n",
                        NULL);
                        *boot_state = BOOT_STATE_ORANGE;
                } else
                        *boot_state = BOOT_STATE_RED;
                break;
        default:
                if (allow_verification_error && *boot_state <= BOOT_STATE_ORANGE)
                        *boot_state = BOOT_STATE_ORANGE;
                else
                        *boot_state = BOOT_STATE_RED;
                break;
        }

        return EFI_SUCCESS;
}


EFI_STATUS android_image_load_partition_avb(
                IN const char *label,
                OUT VOID **bootimage_p,
                IN OUT UINT8* boot_state,
                AvbSlotVerifyData **slot_data)
{
        EFI_STATUS ret = EFI_SUCCESS;
        AvbOps *ops;
        const char *slot_suffix = "";
        AvbPartitionData *boot;
        AvbSlotVerifyResult verify_result = 0;
        AvbSlotVerifyFlags flags;
        const char *requested_partitions[] = {label, NULL};
        VOID *bootimage = NULL;
        bool allow_verification_error = *boot_state != BOOT_STATE_GREEN;
        *bootimage_p = NULL;

        ops = avb_init();
        if (! ops) {
                ret = EFI_OUT_OF_RESOURCES;
                goto fail;
        }

        if (use_slot()) {
                slot_suffix = slot_get_active();
                if (!slot_suffix) {
                        error(L"suffix is null");
                        slot_suffix = "";
                }
        }

        flags = AVB_SLOT_VERIFY_FLAGS_NONE;
        if (allow_verification_error)
                flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;

        verify_result = avb_slot_verify(ops,
                        requested_partitions,
                        slot_suffix,
                        flags,
                        AVB_HASHTREE_ERROR_MODE_RESTART,
                        slot_data);

        debug(L"avb_slot_verify ret %d\n", verify_result);

        ret = get_avb_result(*slot_data,
                        allow_verification_error,
                        verify_result,
                        boot_state);

        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to get avb result for boot");
                goto fail;
        }

        boot = &(*slot_data)->loaded_partitions[0];
        bootimage = boot->data;
        *bootimage_p = bootimage;
        return ret;
fail:
        *boot_state = BOOT_STATE_RED;
        return ret;
}


EFI_STATUS android_image_load_partition_avb_ab(
                IN const char *label,
                OUT VOID **bootimage_p,
                IN OUT UINT8* boot_state,
                AvbSlotVerifyData **slot_data)
{
#ifndef USE_SLOT
        return android_image_load_partition_avb(label, bootimage_p, boot_state, slot_data);
#else
        EFI_STATUS ret = EFI_SUCCESS;
        AvbABFlowResult flow_result;
        AvbPartitionData *boot;
        AvbSlotVerifyFlags flags;
        const char *requested_partitions[] = {label, NULL};
        VOID *bootimage = NULL;
        bool allow_verification_error = *boot_state != BOOT_STATE_GREEN;
        *bootimage_p = NULL;

        flags = AVB_SLOT_VERIFY_FLAGS_NONE;
        if (allow_verification_error)
                flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;

        flow_result = avb_ab_flow(&ab_ops, requested_partitions, flags, AVB_HASHTREE_ERROR_MODE_RESTART, slot_data);
        ret = get_avb_flow_result(*slot_data,
                allow_verification_error,
                flow_result,
                boot_state);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to get avb slot a/b flow result for boot");
                goto fail;
        }
        slot_set_active_cached((*slot_data)->ab_suffix);

        boot = &(*slot_data)->loaded_partitions[0];
        bootimage = boot->data;
        *bootimage_p = bootimage;
        return ret;
fail:
        *boot_state = BOOT_STATE_RED;
        return ret;
#endif // USE_SLOT
}
#endif // USE_AVB

#ifdef __SUPPORT_ABL_BOOT
static UINTN cmd_line_add_str (CHAR8 *cmd_buf, UINTN max_cmd_size, UINTN pos, CHAR8 prefix, const CHAR8 *str)
{
        UINTN len;

        if (str == NULL)
                return pos;

        len = strlen (str);
        if (pos + len + 1 >= max_cmd_size - 1)
                return pos;

        if (pos > 0)
                cmd_buf[pos++] = prefix;
        memcpy (&cmd_buf[pos], str, len);

        return pos + len;
}

/*
 *  Add entry "item=value" to the command line.
 *  If value is null, just add item, without the equal
 */
void cmdline_add_item (CHAR8 *cmd_buf, UINTN max_cmd_size, const CHAR8 *item, const CHAR8 *value)
{
        UINTN pos = strlen(cmd_buf);

        pos = cmd_line_add_str (cmd_buf, max_cmd_size, pos, ' ', item);
        if (value)
                pos = cmd_line_add_str (cmd_buf, max_cmd_size, pos, '=', value);

        cmd_buf[pos] = 0;
}

#ifdef USE_AVB
static EFI_STATUS setup_command_line_abl(
                IN UINT8 *bootimage,
                IN enum boot_target boot_target,
                const CHAR8 *abl_cmd_line,
                AvbSlotVerifyData *slot_data,
                UINT8 boot_state)
#else
static EFI_STATUS setup_command_line_abl(
                IN UINT8 *bootimage,
                IN enum boot_target boot_target,
                const CHAR8 *abl_cmd_line,
                UINT8 boot_state)
#endif
{
        CHAR16 *cmdline16 = NULL;
        EFI_PHYSICAL_ADDRESS cmdline_addr;
        CHAR8 *cmdline;
        UINTN cmdsize;
        UINTN cmdlen;
        EFI_STATUS ret = EFI_SUCCESS;
        struct boot_params *buf;
        struct boot_img_hdr *aosp_header;
#ifdef USE_AVB
        UINTN avb_cmd_len = 0;
#endif
        char   *serialno = NULL;
        CHAR16 *serialport = NULL;
        CHAR16 *bootreason = NULL;
#ifdef USE_AVB
        EFI_GUID system_uuid;
#endif
        UINTN abl_cmd_len = 0;
        CHAR8 time_str8[128] = {0};

        if (abl_cmd_line != NULL)
               abl_cmd_len = strlen(abl_cmd_line);

        aosp_header = (struct boot_img_hdr *)bootimage;
        buf = (struct boot_params *)(bootimage + aosp_header->page_size);

        cmdline16 = get_command_line(aosp_header, boot_target);
        if (!cmdline16) {
                ret = EFI_OUT_OF_RESOURCES;
                goto out;
        }

        /* Append serial number from DMI */
        serialno = get_serial_number();
        if (serialno) {
                ret = prepend_command_line(&cmdline16,
                                L"androidboot.serialno=%a g_ffs.iSerialNumber=%a",
                                serialno, serialno);
                if (EFI_ERROR(ret))
                        goto out;
        }

        bootreason = get_reboot_reason();
        if (!bootreason) {
                ret = EFI_OUT_OF_RESOURCES;
                goto out;
        }

        ret = prepend_command_line(&cmdline16, L"androidboot.bootreason=%s", bootreason);
        if (EFI_ERROR(ret))
                goto out;

        ret = prepend_command_line(&cmdline16, L"androidboot.verifiedbootstate=%s",
                                   boot_state_to_string(boot_state));
        if (EFI_ERROR(ret))
                goto out;

        serialport = get_serial_port();
        if (serialport) {
                ret = prepend_command_line(&cmdline16, L"console=%s", serialport);
                if (EFI_ERROR(ret))
                        goto out;
        }

#ifndef USER
        if (get_disable_watchdog()) {
                ret = prepend_command_line(&cmdline16, CONVERT_TO_WIDE(TCO_OPT_DISABLED));
                if (EFI_ERROR(ret))
                        goto out;
        }
#endif

        PCI_DEVICE_PATH *boot_device = get_boot_device();
        if (boot_device) {
                ret = prepend_command_line(&cmdline16,
                                           L"androidboot.diskbus=%02x.%x",
                                           boot_device->Device,
                                           boot_device->Function);
                if (EFI_ERROR(ret))
                        goto out;
        } else
                error(L"Boot device not found, diskbus parameter not set in the commandline!");

        ret = prepend_command_line(&cmdline16, L"androidboot.bootloader=%a",
                                   get_property_bootloader());
        if (EFI_ERROR(ret))
                goto out;

        ret = prepend_command_line(&cmdline16, L"androidboot.acpio_idx=%a ",
                                   acpi_loaded_table_idx_to_string());
        if (EFI_ERROR(ret))
                goto out;

#ifdef HAL_AUTODETECT
        ret = prepend_command_line(&cmdline16, L"androidboot.brand=%a "
                                   "androidboot.name=%a androidboot.device=%a "
                                   "androidboot.model=%a", get_property_brand(),
                                   get_property_name(), get_property_device(),
                                   get_property_model());
        if (EFI_ERROR(ret))
                goto out;

        ret = add_bootvars(bootimage, &cmdline16);
        if (EFI_ERROR(ret))
                goto out;
#endif
#ifdef USE_AVB
        avb_prepend_command_line_rootfs(&cmdline16, boot_target);

        if (use_slot()) {
                if (slot_get_active()) {
                        ret = prepend_command_line(&cmdline16, L"androidboot.slot_suffix=%a",
                                                   slot_get_active());
                        if (EFI_ERROR(ret))
                                goto out;
                }

                if (slot_data && slot_data->cmdline && (!avb_strstr(slot_data->cmdline,"root="))) {
                        ret = gpt_get_partition_uuid(slot_label(SYSTEM_LABEL),
                                                                &system_uuid, LOGICAL_UNIT_USER);
                        if (EFI_ERROR(ret)) {
                                efi_perror(ret, L"Failed to get %s partition UUID", SYSTEM_LABEL);
                                goto out;
                        }

                        ret = prepend_command_line(&cmdline16, DISABLE_AVB_ROOTFS_PREFIX "PARTUUID=%g",
                                                   &system_uuid);
                        if (EFI_ERROR(ret))
                                goto out;
                }
        }
#endif

        cmdlen = StrLen(cmdline16);
#ifdef USE_AVB
        if (!slot_data || !slot_data->cmdline)
                goto out;
        avb_cmd_len = strlen((const CHAR8 *)slot_data->cmdline);
        /* +256: for extra cmd line */
        cmdsize = cmdlen + avb_cmd_len + abl_cmd_len + 256;
#else
        /* +256: for extra cmd line */
        cmdsize = cmdlen + abl_cmd_len + 256;
#endif
        cmdline_addr = (EFI_PHYSICAL_ADDRESS)((UINTN)AllocatePool(cmdsize));
        if (cmdline_addr == 0) {
                ret = EFI_OUT_OF_RESOURCES;
                goto out;
        }

        cmdline = (CHAR8 *)(UINTN)cmdline_addr;
        ret = str_to_stra(cmdline, cmdline16, cmdlen + 1);
        if (EFI_ERROR(ret)) {
                error(L"Non-ascii characters in command line");
                free_pages(cmdline_addr, EFI_SIZE_TO_PAGES(cmdlen + 1));
                goto out;
        }
#ifdef USE_AVB
        if (avb_cmd_len > 0)
        {
            cmdline[cmdlen] = ' ';
            memcpy(cmdline + cmdlen + 1, slot_data->cmdline, avb_cmd_len);
            cmdlen += avb_cmd_len + 1;
        }
#endif

        /* append command line from ABL */
        if (abl_cmd_len > 0)
        {
                cmdline[cmdlen] = ' ';
                memcpy(cmdline + cmdlen + 1, abl_cmd_line, abl_cmd_len + 1);
        }

        /* append stages boottime */
        set_boottime_stamp(TM_JMP_KERNEL);
        construct_stages_boottime(time_str8, sizeof(time_str8));
        cmdline_add_item(cmdline, cmdsize, (const CHAR8 *)"androidboot.boottime", time_str8);

        buf->hdr.cmd_line_ptr = (UINT32)(UINTN)cmdline;
        ret = EFI_SUCCESS;
out:
        FreePool(cmdline16);
        return ret;
}
#endif

EFI_STATUS android_image_start_buffer(
                IN EFI_HANDLE parent_image,
                IN VOID *bootimage,
                IN enum boot_target boot_target,
                IN UINT8 boot_state,
                IN __attribute__((unused)) EFI_GUID *swap_guid,
#ifdef USE_AVB
                IN AvbSlotVerifyData *slot_data,
#else
                IN __attribute__((unused)) X509 *verity_cert,
#endif
                IN __attribute__((unused)) const CHAR8 *abl_cmd_line)
{
        struct boot_img_hdr *aosp_header;
        struct boot_params *buf;
        EFI_STATUS ret;

        if (!bootimage)
                return EFI_INVALID_PARAMETER;

        aosp_header = (struct boot_img_hdr *)bootimage;
        if (memcmp(aosp_header->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
                error(L"buffer does not appear to contain an Android boot image");
                return EFI_INVALID_PARAMETER;
        }

        ret = setup_acpi_table(bootimage, boot_target);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"setup_acpi_table");
                return ret;
        }

        buf = (struct boot_params *)(bootimage + aosp_header->page_size);

        /* Check boot sector signature */
        if (buf->hdr.signature != 0xAA55) {
                error(L"bzImage kernel corrupt");
                return EFI_INVALID_PARAMETER;
        }

        if (buf->hdr.header != SETUP_HDR) {
                error(L"Setup code version is invalid");
                return EFI_INVALID_PARAMETER;
        }

        if (buf->hdr.version < 0x20c) {
                /* Protocol 2.12, kernel 3.8 required */
                error(L"Kernel header version %x too old", buf->hdr.version);
                return EFI_INVALID_PARAMETER;
        }

        if (!buf->hdr.relocatable_kernel) {
                error(L"Expected relocatable kernel\n");
                return EFI_INVALID_PARAMETER;
        }

        debug(L"Creating command line");

#ifdef __SUPPORT_ABL_BOOT
#ifdef USE_AVB
        ret = setup_command_line_abl(bootimage, boot_target,
                                     abl_cmd_line,
                                     slot_data,
                                     boot_state);
#else
        ret = setup_command_line_abl(bootimage, boot_target,
                                     abl_cmd_line,
                                     boot_state);
#endif
#else
        ret = setup_command_line(bootimage, boot_target,
                                 swap_guid,
                                 boot_state,
#ifdef USE_AVB
                                 slot_data
#else
                                 verity_cert
#endif
                                 );
#endif
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"setup_command_line");
                return ret;
        }

        if (!recovery_in_boot_partition() || boot_target == RECOVERY) {
                debug(L"Loading the ramdisk");
                ret = setup_ramdisk(bootimage);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"setup_ramdisk");
                        goto out_cmdline;
                }
        }

        debug(L"Loading the kernel");
        ret = handover_kernel(bootimage, parent_image);
        efi_perror(ret, L"handover_kernel");

        efree(buf->hdr.ramdisk_start, buf->hdr.ramdisk_len);
        buf->hdr.ramdisk_start = 0;
        buf->hdr.ramdisk_len = 0;
out_cmdline:
        free_pages(buf->hdr.cmd_line_ptr,
                        strlena((CHAR8 *)(UINTN)buf->hdr.cmd_line_ptr) + 1);
        buf->hdr.cmd_line_ptr = 0;
        return ret;
}


#if DEBUG_MESSAGES
VOID dump_bcb(IN struct bootloader_message *bcb)
{
        if (bcb->command && bcb->status)
                debug(L"BCB: cmd '%a' status '%a'", bcb->command, bcb->status);
}
#else
#define dump_bcb(b) (void)0
#endif

EFI_STATUS read_bcb(
                IN const CHAR16 *label,
                OUT struct bootloader_message *bcb)
{
        EFI_STATUS ret;
        struct gpt_partition_interface gpart;
        UINTN partition_start;

        debug(L"Locating BCB");
        ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
        if (EFI_ERROR(ret))
                return EFI_INVALID_PARAMETER;
        partition_start = gpart.part.starting_lba * gpart.bio->Media->BlockSize;

        debug(L"Reading BCB");
        ret = uefi_call_wrapper(gpart.dio->ReadDisk, 5, gpart.dio,
                                gpart.bio->Media->MediaId,
                                partition_start, sizeof(*bcb), bcb);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"ReadDisk (bcb)");
                return ret;
        }
        bcb->command[31] = '\0';
        bcb->status[31] = '\0';
        dump_bcb(bcb);

        return EFI_SUCCESS;
}



EFI_STATUS write_bcb(
                IN const CHAR16 *label,
                IN struct bootloader_message *bcb)
{
        EFI_STATUS ret;
        struct gpt_partition_interface gpart;
        UINTN partition_start;

        debug(L"Locating BCB");
        ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
        if (EFI_ERROR(ret))
                return EFI_INVALID_PARAMETER;
        partition_start = gpart.part.starting_lba * gpart.bio->Media->BlockSize;

        debug(L"Writing BCB");
        ret = uefi_call_wrapper(gpart.dio->WriteDisk, 5, gpart.dio,
                                gpart.bio->Media->MediaId,
                                partition_start, sizeof(*bcb), bcb);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"WriteDisk (bcb)");
                return ret;
        }
        dump_bcb(bcb);

        return EFI_SUCCESS;
}


EFI_STATUS android_clear_memory()
{
        EFI_STATUS ret = EFI_SUCCESS;
        UINTN nr_entries, key, entry_sz;
        CHAR8 *mem_entries;
        UINT32 entry_ver;
        UINTN i;
        CHAR8 *mem_map;
        EFI_TPL OldTpl;

        OldTpl = uefi_call_wrapper(BS->RaiseTPL, 1, TPL_NOTIFY);
        mem_entries = (CHAR8 *)LibMemoryMap(&nr_entries, &key, &entry_sz, &entry_ver);
        if (!mem_entries) {
                uefi_call_wrapper(BS->RestoreTPL, 1, OldTpl);
                return EFI_OUT_OF_RESOURCES;
        }

        sort_memory_map(mem_entries, nr_entries, entry_sz);
        mem_map = mem_entries;

#ifndef __LP64__
        ret = pae_init(mem_entries, nr_entries, entry_sz);
        if (EFI_ERROR(ret))
                goto err;
#endif

        for (i = 0; i < nr_entries; mem_entries += entry_sz, i++) {
                EFI_MEMORY_DESCRIPTOR *entry;
                EFI_PHYSICAL_ADDRESS start;
                UINT64 map_sz, len;
                void *buf;

                entry = (EFI_MEMORY_DESCRIPTOR *)mem_entries;
                if (entry->Type != EfiConventionalMemory)
                        continue;

                start = entry->PhysicalStart;
                map_sz = entry->NumberOfPages * EFI_PAGE_SIZE;

                for (; map_sz > 0; map_sz -= len, start += len) {
                        len = map_sz;
#ifdef __LP64__
                        buf = (void *)start;
#else
                        ret = pae_map(start, (unsigned char **)&buf, &len);
                        if (EFI_ERROR(ret))
                                goto pae_err;
#endif
                        uefi_call_wrapper(BS->SetMem, 3, buf, len, 0);
                }
        }

#ifndef __LP64__
pae_err:
        pae_exit();
err:
#endif
        uefi_call_wrapper(BS->RestoreTPL, 1, OldTpl);
        FreePool((void *)mem_map);
        return ret;
}

BOOLEAN recovery_in_boot_partition(void)
{
        EFI_STATUS ret;
        struct gpt_partition_interface gpart;

        if (!use_slot())
                return FALSE;

        ret = gpt_get_partition_by_label(RECOVERY_LABEL, &gpart, LOGICAL_UNIT_USER);
        return ret == EFI_NOT_FOUND;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */
