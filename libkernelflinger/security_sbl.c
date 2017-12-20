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
#include "security_interface.h"
#include "rpmb_storage.h"

#define SECURITY_SBL_RPMB_KEY_SIZE 64
#define SECURITY_SBL_SEED_SIZE 64
#define BOOTLOADER_SEED_MAX_ENTRIES  10

/* structure of seed info */
typedef struct _seed_info {
	uint8_t cse_svn;
	uint8_t bios_svn;
	uint8_t padding[2];
	uint8_t seed[SECURITY_SBL_SEED_SIZE];
} __attribute__((packed)) seed_info_t;

typedef struct device_sec_info{
	uint32_t size_of_this_struct;
	/* version info
		0: baseline structure
		1: add xx new field
	*/
	uint32_t Version;
	/* platform:
		0: dummy
		1: APL
		2: ICL
		3: CWP
		4: Brillo
		Others: reserved
	*/
	uint32_t platform;
	/* flags info:
		Bit0: manufacturing state(0: manufacturing done; 1: in manufacturing mode)
		Bit1: secure mode state(0: disabled; 1:enabled)
		Bit2: test seeds
	*/
	uint32_t flags;
	uint32_t pad1;
	uint32_t num_seeds;
	seed_info_t useed_list[BOOTLOADER_SEED_MAX_ENTRIES];
	seed_info_t dseed_list[BOOTLOADER_SEED_MAX_ENTRIES];
	uint8_t rpmb_key[RPMB_MAX_PARTITION_NUMBER][SECURITY_SBL_RPMB_KEY_SIZE];
	uint8_t attkb_enc_key[32];
	char serial[MMC_PROD_NAME_WITH_PSN_LEN];
	char pad2;
} __attribute__((packed)) device_sec_info_t;

EFI_STATUS set_device_security_info(IN VOID *security_data)
{
	EFI_STATUS ret;
	UINT8 i;
	device_sec_info_t *dev_sec;
	UINT8 invlida_key[RPMB_KEY_SIZE] = {0x0};
	UINT8 rpmb_key[RPMB_MAX_PARTITION_NUMBER][RPMB_KEY_SIZE];
	UINT8 length_cmp = RPMB_KEY_SIZE > SECURITY_SBL_RPMB_KEY_SIZE ? SECURITY_SBL_RPMB_KEY_SIZE :
		RPMB_KEY_SIZE;

	if (!security_data)
		return EFI_INVALID_PARAMETER;

	dev_sec = (device_sec_info_t *)security_data;
	if (dev_sec->size_of_this_struct != sizeof(device_sec_info_t))
		return EFI_INVALID_PARAMETER;

	for (i = 0; i < RPMB_MAX_PARTITION_NUMBER; i++)
	{
		if (!memcmp(dev_sec->rpmb_key[i], invlida_key, length_cmp))
			break;
		memcpy(rpmb_key[i], dev_sec->rpmb_key[i], length_cmp);
	}

	if (i > 0)
		ret = set_rpmb_derived_key(rpmb_key, sizeof(rpmb_key), i);
	else
		ret = EFI_NOT_FOUND;

	if (EFI_ERROR(ret))
	{
		efi_perror(ret, L"Failed to generate the rpmb key");
	}

	return ret;
}
