/*
 * Copyright (C) 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <lib.h>
#include <vars.h>
#include <security.h>
#include "rpmb_storage.h"
#include <aes_gcm.h>
#include <keybox_provision.h>

#define RPMB_ATTKB_BLOCK_ADDR 60

static struct gcm_key attkb_key = {0};
static encrypted_attkb_t enc_kb;
static UINT8 *start_kb_addr = NULL;
static UINT8 rpmb_key[32];
static UINT8 rpmb_buffer[256];

static void prepare_aad(encrypted_attkb_t *enc_kb, UINT8 *iv, UINTN kb_sz)
{
	memset(enc_kb, 0, sizeof(encrypted_attkb_t));
	enc_kb->header.version = 1;
	enc_kb->header.size = sizeof(attkb_cipher_blob_t) + kb_sz;
	enc_kb->header.format.encrypted = 1;
	enc_kb->cipher_blob.format_version = 1;
	enc_kb->cipher_blob.blob_sz = kb_sz;
	memcpy(enc_kb->cipher_blob.iv, iv, GCM_IV_SIZE);
}

static EFI_STATUS encrypt_keybox(UINT8 *kb_data, UINTN kb_sz,UINT8 *out, UINTN *out_sz)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT8 iv[GCM_IV_SIZE];
	UINTN tag_offset;

	ret = generate_random_numbers(iv, sizeof(iv));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate IV");
		return EFI_ABORTED;
	}

	prepare_aad(&enc_kb, iv, kb_sz);
	aes_256_gcm_encrypt(&attkb_key,
			iv, GCM_IV_SIZE,
			&enc_kb, sizeof(enc_kb),
			kb_data, kb_sz,
			out, out_sz);

	//update tag
	tag_offset = *out_sz - GCM_TAG_SIZE;
	memcpy(enc_kb.cipher_blob.tag, out + tag_offset, GCM_TAG_SIZE);

	return ret;

}

static void prepare_attkb_metadata_block(attkb_meta_block_t *data, UINTN kb_size)
{
	memcpy(data->signature, ATTKB_META_SIGNATURE, ATTKB_META_SIGNATURE_LENGTH);
	data->length = RPMB_BLOCK_SIZE;
	data->revision = 0;
	data->flag |= ATTKB_PRESENT_FLAG_BIT;
	data->attkb_addr = ATTKB_META_BASE_ADDRESS + 1;
	data->attkb_size = kb_size;

}

static EFI_STATUS write_attkb_data_real(UINT8 *start_kb_addr, UINTN write_sz)
{
	EFI_STATUS ret = EFI_SUCCESS;
	RPMB_RESPONSE_RESULT rpmb_result;
	UINT16 blk_addr = RPMB_ATTKB_BLOCK_ADDR;
	UINT16 blk_cnt;
	UINTN remain;
	UINT16 i;
	UINT8 *data_addr = start_kb_addr;

	blk_cnt = write_sz / RPMB_BLOCK_SIZE;
	remain = write_sz % RPMB_BLOCK_SIZE;
	for (i=0; i<blk_cnt; i++) {
		ret = write_rpmb_data(NULL, 1, blk_addr, data_addr, rpmb_key, &rpmb_result);
		debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to write keybox data");
			return ret;
		}
		blk_addr++;
		data_addr = data_addr + RPMB_BLOCK_SIZE;
	}

	if (remain) {
		memset(rpmb_buffer, 0, RPMB_BLOCK_SIZE);
		memcpy(rpmb_buffer, data_addr, remain);
		ret = write_rpmb_data(NULL, 1, blk_addr, data_addr, rpmb_key, &rpmb_result);
		debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to write keybox data");
			return ret;
		}
	}
	return ret;
}

static EFI_STATUS write_attkb_data_sim(UINT8 *start_kb_addr, UINTN write_sz)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT16 blk_addr = RPMB_ATTKB_BLOCK_ADDR;
	UINT32 byte_offset = blk_addr * RPMB_BLOCK_SIZE;

	ret = simulate_write_rpmb_data(byte_offset, start_kb_addr, write_sz);
	debug(L"ret=%d", ret);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write keybox magic data");
		return ret;
	}

	return ret;
}

EFI_STATUS flash_keybox(VOID *data, UINTN size)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINTN total_sz;
	UINTN write_sz;
	UINTN kb_meta_sz;
	UINT8 *cipher_blob;
	UINTN cipher_blob_sz;
	UINT8 *addr;

	total_sz = sizeof(attkb_meta_block_t) + sizeof(encrypted_attkb_t) + size + GCM_TAG_SIZE;
	start_kb_addr = AllocatePool(total_sz);
        if (!start_kb_addr)
                return EFI_OUT_OF_RESOURCES;

	cipher_blob = start_kb_addr + sizeof(attkb_meta_block_t) + sizeof(encrypted_attkb_t);
	encrypt_keybox(data, size, cipher_blob, &cipher_blob_sz);

	addr = start_kb_addr;
	kb_meta_sz = sizeof(encrypted_attkb_t) + size;
	prepare_attkb_metadata_block((attkb_meta_block_t *)addr, kb_meta_sz);

	addr = addr + sizeof(attkb_meta_block_t);
	memcpy(addr, &enc_kb, sizeof(encrypted_attkb_t));

	write_sz = sizeof(attkb_meta_block_t) + sizeof(encrypted_attkb_t) + size;
	if (is_eom_and_secureboot_enabled())
		ret = write_attkb_data_real(start_kb_addr, write_sz);
	else
		ret = write_attkb_data_sim(start_kb_addr, write_sz);

	return ret;
}
