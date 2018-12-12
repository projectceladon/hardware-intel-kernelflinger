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
#include <libtipc.h>
#include <hecisupport.h>
#include <openssl/hkdf.h>
#include "vars.h"
#include "lib.h"
#include "timer.h"
#include "security.h"
#include "android.h"
#include "options.h"
#include "power.h"
#include "trusty_interface.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "efilinux.h"
#include "rpmb_storage.h"

#define BOOTLOADER_SEED_MAX_ENTRIES  4
#define SECURITY_ABL_TRUSTY_SEED_LEN 32

/* structure of seed info */
typedef struct _seed_info {
	uint8_t svn;
	uint8_t padding[3];
	uint8_t seed[SECURITY_ABL_TRUSTY_SEED_LEN];
} __attribute__((packed)) seed_info_t;

typedef struct {
	/* version of the struct. 0x0001 for this version */
	uint16_t 			Version;
	/* Trusty’s mem base address */
	uint32_t 			TrustyMemBase;
	/* assumed to be 16MB */
	uint32_t 			TrustyMemSize;
	/* seed value retrieved from CSE */
	uint32_t			num_seeds;
	seed_info_t 		seed_list[BOOTLOADER_SEED_MAX_ENTRIES];
	struct rot_data_t 	RotData;
} __attribute__((packed)) trusty_boot_params_t;

typedef struct trusty_startup_params {
	/* Size of this structure */
	uint64_t size_of_this_struct;
	/* Load time base address of trusty */
	uint32_t load_base;
	/* Load time size of trusty */
	uint32_t load_size;
	/* Seed */
	uint32_t num_seeds;
	seed_info_t seed_list[BOOTLOADER_SEED_MAX_ENTRIES];
	/* Rot */
	struct rot_data_t RotData;
	/* Concatenation of mmc product name with a string representation of PSN */
	char serial[MMC_PROD_NAME_WITH_PSN_LEN];
} __attribute__((packed)) trusty_startup_params_t;

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
};

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

static trusty_boot_params_t *trusty_boot_params;

static EFI_STATUS init_trusty_startup_params(trusty_startup_params_t *param, UINTN base, UINTN sz, uint32_t num, seed_info_t *seed_list)
{
	char *serialno;

	if (!param || !seed_list || num > BOOTLOADER_SEED_MAX_ENTRIES || num == 0)
		return EFI_INVALID_PARAMETER;

	memset(param, 0, sizeof(trusty_startup_params_t));
	param->size_of_this_struct = sizeof(trusty_startup_params_t);
	param->load_base = base;
	param->load_size = sz;
	param->num_seeds = num;
	serialno = get_serial_number();
	if (!serialno)
		return EFI_NOT_FOUND;

	memcpy(param->serial, serialno, MMC_PROD_NAME_WITH_PSN_LEN);
	memcpy(param->seed_list, seed_list, sizeof(param->seed_list));

	memset(seed_list, 0, sizeof(param->seed_list));

	return EFI_SUCCESS;
}

#define TRUSTY_VMCALL_SMC 0x74727500
static EFI_STATUS launch_trusty_os(trusty_startup_params_t *param)
{
	if (!param)
		return EFI_INVALID_PARAMETER;

	asm volatile(
		"vmcall; \n"
		: : "a"(TRUSTY_VMCALL_SMC), "D"((uint32_t)param));

	return EFI_SUCCESS;
}

EFI_STATUS set_trusty_param(IN VOID *param_data)
{
	trusty_boot_params = (trusty_boot_params_t *)param_data;
	return EFI_SUCCESS;
}

EFI_STATUS start_trusty(VOID *tosimage)
{
	EFI_STATUS ret;
	const struct boot_img_hdr *header;
	UINTN load_base;
	trusty_startup_params_t trusty_startup_params;

	if (!tosimage)
		return EFI_INVALID_PARAMETER;

	if (!trusty_boot_params)
		return EFI_NOT_READY;

	header = (const struct boot_img_hdr *)tosimage;
	load_base = (UINTN)(tosimage + header->page_size);
	ret = init_trusty_startup_params(&trusty_startup_params, load_base,
			header->kernel_size, trusty_boot_params->num_seeds, trusty_boot_params->seed_list);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to init trusty startup params");
		goto fail;
	}

	ret = launch_trusty_os(&trusty_startup_params);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to launch trusty os");
		goto fail;
	}
	set_boottime_stamp(TM_LAUNCH_TRUSTY_DONE);

	trusty_ipc_init();
	trusty_ipc_shutdown();

	// Send EOP heci messages
	ret = heci_end_of_post();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send EOP message to CSE FW, halt");
		goto fail;
	}

fail:
	memset(trusty_startup_params.seed_list, 0, sizeof(trusty_startup_params.seed_list));

	return ret;
}
