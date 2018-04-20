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
#include "vars.h"
#include "lib.h"
#include "security.h"
#include "android.h"
#include "options.h"
#include "power.h"
#include "trusty_interface.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "efilinux.h"
#include "libelfloader.h"

#define TRUSTY_MEM_SIZE		0x1000000
#define TRUSTY_MEM_ALIGNED_16K	0x4000
#define TRUSTY_MEM_MAX_ADDRESS	0xFFFFFFFF

typedef struct trusty_boot_param {
	/* Size of this structure */
	uint32_t size_of_this_struct;
	uint32_t version;
	UINT64 trusty_mem_base;
        UINT32 trusty_mem_size;
} __attribute__((packed)) trusty_boot_param_t;

/* This is structure to proivde required data to Trusty when calling Trusty entry.
 * It is required to send the public key used to verify the android boot image,
 * the state of the device, the EFI memory map which is contained in the platform
 * info structure and the return address
 */
typedef struct tos_startup_params {
	/* Size of this structure */
	uint32_t size_of_this_struct;
	uint32_t version;
	uint32_t runtime_addr;
	uint32_t entry_point;
	uint32_t runtime_size;
} __attribute__((aligned(8))) trusty_startup_params_t;

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

static EFI_STATUS init_trusty_startup_params(trusty_startup_params_t *param, UINTN base,
	UINTN size, trusty_boot_param_t *boot_param)
{
	UINT64 entry_addr;

	if (!param || !boot_param)
		return EFI_INVALID_PARAMETER;

	if (!relocate_elf_image(base, size, boot_param->trusty_mem_base + 0x1000,
				(boot_param->trusty_mem_size << 10) - 0x1000, &entry_addr)) {
		error(L"relocate tos image failed");
		return EFI_INVALID_PARAMETER;
	}

	memset(param, 0, sizeof(trusty_startup_params_t));
	param->size_of_this_struct = sizeof(trusty_startup_params_t);
	param->runtime_addr = boot_param->trusty_mem_base;
	param->entry_point = entry_addr + 0x400;
	param->version = 1;
	param->runtime_size = TRUSTY_MEM_SIZE;

	return EFI_SUCCESS;
}

#ifdef __LP64__
#define ACRN_HC_LAUNCH_TRUSTY 0x80000070
static EFI_STATUS launch_trusty_os(trusty_startup_params_t *param)
{
	EFI_STATUS ret = EFI_SUCCESS;
	register signed long smc_id asm("r8") = ACRN_HC_LAUNCH_TRUSTY;

	if (!param)
		return EFI_INVALID_PARAMETER;

	asm volatile (
		"vmcall;"
		: "=a"(ret)
		: "r"(smc_id), "D"((UINTN)param));

	return ret;
}
#else
static EFI_STATUS launch_trusty_os(__attribute__((unused)) trusty_startup_params_t *param)
{
	efi_perror(ret, L"Unsupport to launch trusty on 32bit");
	return EFI_UNSUPPORTED;
}
#endif

EFI_STATUS set_trusty_param(__attribute__((unused)) IN VOID *param_data)
{
	return EFI_UNSUPPORTED;
}

EFI_STATUS start_trusty(VOID *tosimage)
{
        EFI_STATUS ret;
	const struct boot_img_hdr *header;
	UINTN load_base;
	trusty_startup_params_t trusty_startup_params;
	trusty_boot_param_t trusty_boot_params;
	EFI_PHYSICAL_ADDRESS Memory;

	if (!tosimage)
		return EFI_INVALID_PARAMETER;

	header = (const struct boot_img_hdr *)tosimage;
	load_base = (UINTN)(tosimage + header->page_size);
	Memory = (EFI_PHYSICAL_ADDRESS)(TRUSTY_MEM_MAX_ADDRESS - TRUSTY_MEM_SIZE - TRUSTY_MEM_ALIGNED_16K + 1);
	ret = uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress,
				EfiRuntimeServicesData,  EFI_SIZE_TO_PAGES(TRUSTY_MEM_SIZE + TRUSTY_MEM_ALIGNED_16K), &Memory);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to allocate trusty pages");
		goto fail;
	}

	trusty_boot_params.trusty_mem_base = ((UINT64)Memory + TRUSTY_MEM_ALIGNED_16K - 1) & ~(TRUSTY_MEM_ALIGNED_16K - 1);
	trusty_boot_params.trusty_mem_size = TRUSTY_MEM_SIZE;

	ret = init_trusty_startup_params(&trusty_startup_params, load_base, header->kernel_size, &trusty_boot_params);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to init trusty startup params");
		goto fail;
	}

	ret = launch_trusty_os(&trusty_startup_params);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to launch trusty os");
		goto fail;
	}

	trusty_ipc_init();
	trusty_ipc_shutdown();

	//Need to implement virtual HECI otherwise it would cause crash
#if 0
	ret = heci_end_of_post();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send EOP message to CSE FW, halt");
		goto fail;
	}
#endif

	return ret;

fail:
	uefi_call_wrapper(BS->FreePages, 2, Memory, EFI_SIZE_TO_PAGES(TRUSTY_MEM_SIZE + TRUSTY_MEM_ALIGNED_16K));

	return ret;
}
