/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Author: kwen <kui.wen@intel.com>
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

#include <lib.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "protocol/Mmc.h"
#include "protocol/SdHostIo.h"
#include "sdio.h"
#include "storage.h"
#include "rpmb.h"

#define TIMEOUT_DATA			3000
#define TIMEOUT_COMMAND			1000
#define RPMB_PARTITION			3
#define RPMB_DATA_FRAME_SIZE		512
#define RPMB_DATA_MAC			32
#define RPMB_KEY_SIZE 			32
#define RPMB_MAC_SIZE 			32
#define RPMB_ERROR_MASK			0x07
#define RPMB_NONCE_SIZE 		16

#define CARD_ADDRESS			1
#define STATUS_ERROR_MASK		0xFCFFA080

#define RPMB_RESPONSE_KEY_WRITE		0x0100
#define RPMB_RESPONSE_COUNTER_READ	0x0200
#define RPMB_RESPONSE_AUTH_WRITE	0x0300
#define RPMB_RESPONSE_AUTH_READ		0x0400
#define RPMB_RESPONSE_READ_RESULT	0x0500

#define RPMB_REQUEST_KEY_WRITE		0x0001
#define RPMB_REQUEST_COUNTER_READ	0x0002
#define RPMB_REQUEST_AUTH_WRITE		0x0003
#define RPMB_REQUEST_AUTH_READ		0x0004
#define RPMB_REQUEST_STATUS		0x0005

#define EXT_CSD_PART_CONF		179
#define MMC_SWITCH_MODE_WRITE_BYTE	3

#define CPU_TO_BE16_SWAP(x)	\
	((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
#define CPU_TO_BE32_SWAP(x)	\
	((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | \
	(((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))
#define BE16_TO_CPU_SWAP(x)	\
	((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
#define BE32_TO_CPU_SWAP(x)	\
	((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | \
	(((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))

/* length of the part of the frame used for HMAC computation */
#define HMAC_DATA_LEN \
	(sizeof(rpmb_data_frame) - offsetof(rpmb_data_frame, data))

typedef union {
	UINT32 data;
	struct {
		UINT32  CmdSet:              3;
		UINT32  Reserved0:           5;
		UINT32  Value:               8;
		UINT32  Index:               8;
		UINT32  Access:              2;
		UINT32  Reserved1:           6;
	};
} RPMB_SWITCH_ARGUMENT;

static INT32 rpmb_calc_hmac_sha256(rpmb_data_frame *frames, UINT8 blocks_cnt, const UINT8 key[], UINT32 key_size,
		UINT8 mac[], UINT32 mac_size)
{
	HMAC_CTX ctx;
	INT32 ret = 1;
	UINT32 i;

	HMAC_CTX_init(&ctx);
	ret = HMAC_Init_ex(&ctx, key, key_size, EVP_sha256(), NULL);
	if (ret == 0)
		goto out;

	for (i = 0; i < blocks_cnt; i++)
		HMAC_Update(&ctx, frames[i].data, HMAC_DATA_LEN);

	ret = HMAC_Final(&ctx, mac, &mac_size);
	if (ret == 0)
		goto out;
	if (mac_size != RPMB_MAC_SIZE) {
		ret = 0;
		goto out;
	}

out:
	HMAC_CTX_cleanup(&ctx);

	return ret;
}

static INT32 rpmb_check_mac(const UINT8 *key, rpmb_data_frame *frames, UINT8 cnt)
{
	UINT8 mac[RPMB_MAC_SIZE];
	INT32 ret = 1;

	if (cnt == 0) {
		debug(L"RPMB 0 output frames");
		return 0;
	}

	ret = rpmb_calc_hmac_sha256(frames, cnt, key, RPMB_KEY_SIZE, mac, RPMB_MAC_SIZE);
	if (ret == 0) {
		debug(L"calculate hmac failed");
		return ret;
	}

	if (memcmp(mac, frames[cnt - 1].key_mac, RPMB_MAC_SIZE)) {
		debug(L"RPMB hmac mismatch resule MAC");
		return 0;
	}

	return ret;
}

EFI_STATUS get_emmc_sdio(EFI_SD_HOST_IO_PROTOCOL **sdio)
{
	static BOOLEAN initialized = FALSE;
	static EFI_SD_HOST_IO_PROTOCOL *sdio_rpmb;
	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path;
	EFI_HANDLE sdio_handle = NULL;
	static struct storage *supported_storage;

	if (initialized && sdio_rpmb)
		*sdio = sdio_rpmb;

	ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				&BlockIoProtocol, NULL, &nb_handle, &handles);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to locate Block IO Protocol");
		return ret;
	}

	extern struct storage STORAGE(STORAGE_EMMC);
	supported_storage = &STORAGE(STORAGE_EMMC);
	for (i = 0; i < nb_handle; i++) {
		device_path = DevicePathFromHandle(handles[i]);
		if (supported_storage->probe(device_path)) {
			debug(L"Is emmc device");
			break;
		}
	}

	if (i == nb_handle)
		return EFI_UNSUPPORTED;

	ret = sdio_get(device_path, &sdio_handle, &sdio_rpmb);
	if (EFI_ERROR(ret))
		return EFI_UNSUPPORTED;

	initialized = TRUE;
	*sdio = sdio_rpmb;

	return ret;
}

EFI_STATUS get_emmc_partition_num(EFI_SD_HOST_IO_PROTOCOL *sdio,
		UINT8 *current_part)
{
	EXT_CSD *ext_csd;
	void *rawbuffer;
	UINT32 status;
	EFI_STATUS ret;

	if (!sdio || !current_part)
		return EFI_INVALID_PARAMETER;

	ret = alloc_aligned(&rawbuffer, (void **)&ext_csd, sizeof(*ext_csd), 8);
	if (EFI_ERROR(ret))
		return ret;

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, SEND_EXT_CSD,
				CARD_ADDRESS << 16, InData, (void *)ext_csd,
				sizeof(EXT_CSD), ResponseR1, TIMEOUT_DATA, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed get eMMC EXT_CSD");
		goto out;
	}

	*current_part = ext_csd->PARTITION_CONFIG;
	debug(L"current EMMC parition num is %d", *current_part);

out:
	FreePool(rawbuffer);

	return ret;
}

EFI_STATUS emmc_partition_switch(EFI_SD_HOST_IO_PROTOCOL *sdio, UINT8 part)
{
	UINT32 status;
	CARD_STATUS card_status;
	EFI_STATUS ret = EFI_SUCCESS;
	RPMB_SWITCH_ARGUMENT arg;

	arg.CmdSet = 0;
	arg.Value = part;
	arg.Index = EXT_CSD_PART_CONF;
	arg.Access = MMC_SWITCH_MODE_WRITE_BYTE;

	debug(L"Enter emmc_partition_switch");

	if (sdio == NULL)
		return EFI_INVALID_PARAMETER;

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, SWITCH,
				arg.data, NoData, NULL,
				0, ResponseR1b, TIMEOUT_DATA, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send SWITCH command");
		return ret;
	}
	if (status & STATUS_ERROR_MASK) {
		error(L"status error in SWITCH, status=0x%08x", status);
		return EFI_ABORTED;
	}

	do {
		ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, SEND_STATUS,
					CARD_ADDRESS << 16, NoData, NULL,
					0, ResponseR1, TIMEOUT_COMMAND, (UINT32 *)&card_status);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to send SEND_STATUS command");
			return ret;
		}

	} while (!card_status.READY_FOR_DATA);

	debug(L" EMMC parition %d switching successfully", part);

	return ret;
}

static EFI_STATUS emmc_get_current_part_switch_part(EFI_SD_HOST_IO_PROTOCOL *sdio,
		UINT8 *current_part, UINT8 switch_part)
{
	EFI_STATUS ret;

	if (!sdio || !current_part)
		return EFI_INVALID_PARAMETER;

	ret = get_emmc_partition_num(sdio, current_part);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get current partition");
		return ret;
	}

	if (*current_part == switch_part)
		return ret;

	ret = emmc_partition_switch(sdio, switch_part);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to switch parition %d", switch_part);
		return ret;
	}

	return ret;
}
static EFI_STATUS emmc_rpmb_send_blockcount(EFI_SD_HOST_IO_PROTOCOL *sdio,
		UINT8 count, BOOLEAN is_rel_write)
{
	EFI_STATUS ret;
	UINT32 status;
	UINT32 arg = count;

	if (!sdio)
		return EFI_INVALID_PARAMETER;

	if (is_rel_write)
		arg  |= (1 << 31);

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio,
				SET_BLOCK_COUNT, arg, NoData, NULL, 0,
				ResponseR1, TIMEOUT_COMMAND, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send command SET_BLOCK_COUNT");
		return ret;
	}
	if (status & STATUS_ERROR_MASK) {
		error(L"status error in SET_BLOCK_COUNT, status=0x%08x", status);
		return EFI_ABORTED;
	}

	return ret;
}

EFI_STATUS emmc_rpmb_send_request(EFI_SD_HOST_IO_PROTOCOL *sdio,
		rpmb_data_frame *data_frame, UINT8 count, BOOLEAN is_rel_write)
{
	EFI_STATUS ret;
	UINT32 status;

	if (!sdio || !data_frame)
		return EFI_INVALID_PARAMETER;

	ret = emmc_rpmb_send_blockcount(sdio, count, is_rel_write);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set block count");
		return ret;
	}

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio,
				WRITE_MULTIPLE_BLOCK, 0, OutData, (VOID *)data_frame,
				RPMB_DATA_FRAME_SIZE * count, ResponseR1, TIMEOUT_DATA, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send command WRITE_MULTIPLE_BLOCK");
		return ret;
	}
	if (status & STATUS_ERROR_MASK) {
		error(L"status error in WRITE_MULTIPLE_BLOCK, status=0x%08x", status);
		return EFI_ABORTED;
	}
	debug(L"send_request status = %0x", status);

	return ret;
}

EFI_STATUS emmc_rpmb_get_response(EFI_SD_HOST_IO_PROTOCOL *sdio,
		rpmb_data_frame *data_frame, UINT8 count)
{
	EFI_STATUS ret;
	UINT32 status;

	if (!sdio || !data_frame)
		return EFI_INVALID_PARAMETER;

	debug(L"enter emmc_rpmb_get_response");

	ret = emmc_rpmb_send_blockcount(sdio, count, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set block count");
		return ret;
	}

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio,
				READ_MULTIPLE_BLOCK, 0, InData, (VOID *)data_frame,
				RPMB_DATA_FRAME_SIZE * count, ResponseR1, TIMEOUT_DATA, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send command READ_MULTIPLE_BLOCK");
		return ret;
	}
	if (status & STATUS_ERROR_MASK) {
		error(L"status error in READ_MULTIPLE_BLOCK, status=0x%08x", status);
		return EFI_ABORTED;
	}

	return ret;
}

static EFI_STATUS emmc_rpmb_request_response(EFI_SD_HOST_IO_PROTOCOL *sdio,
		rpmb_data_frame *request_data_frame, rpmb_data_frame *response_data_frame, UINT8 req_count,
		UINT8 res_count, UINT16 expected, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	UINT16 res_result;

	ret = emmc_rpmb_send_request(sdio, request_data_frame, req_count, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		return ret;
	}

	ret = emmc_rpmb_get_response(sdio, response_data_frame, res_count);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get rpmb response");
		return ret;
	}

	if (BE16_TO_CPU_SWAP(response_data_frame->req_resp) != expected) {
		error(L"The response is not expected, expected resp=0x%08x, returned resp=0x%08x",
		expected, response_data_frame->req_resp);
		return EFI_ABORTED;
	}

	res_result = BE16_TO_CPU_SWAP(response_data_frame->result);
	debug(L"response result is %0x", res_result);
	*result = (RPMB_RESPONSE_RESULT)res_result;
	if (res_result) {
		debug(L"RPMB operation failed");
		return EFI_ABORTED;
	}

	return ret;
}

EFI_STATUS emmc_read_rpmb_data(UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT8 current_part;
	rpmb_data_frame data_in_frame;
	rpmb_data_frame *data_out_frame = NULL;
	UINT32 i;
	UINT8 random[16] = {0};
	EFI_SD_HOST_IO_PROTOCOL *sdio = NULL;

	debug(L"read rpmb data: number of block=%d from blk %d", blk_count, blk_addr);
	if (!buffer || !result)
		return EFI_INVALID_PARAMETER;

	ret = get_emmc_sdio(&sdio);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get sdio");
		return ret;
	}

	ret = emmc_get_current_part_switch_part(sdio, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret))
		return ret;

	data_out_frame = AllocatePool(sizeof(rpmb_data_frame) * blk_count);
	if (!data_out_frame) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	memset(&data_in_frame, 0, sizeof(data_in_frame));
	memset(data_out_frame, 0, sizeof(rpmb_data_frame) * blk_count);
	data_in_frame.address = CPU_TO_BE16_SWAP(blk_addr);
	data_in_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_AUTH_READ);
	ret = generate_random_numbers(random, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		goto out;
	}
	memcpy(data_in_frame.nonce, random, RPMB_NONCE_SIZE);
	ret = emmc_rpmb_request_response(sdio, &data_in_frame, data_out_frame, 1, blk_count,
		RPMB_RESPONSE_AUTH_READ, result);
	if (EFI_ERROR(ret))
		goto out;

	if (key && (rpmb_check_mac(key, data_out_frame, blk_count) == 0)) {
		debug(L"rpmb_check_mac failed");
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	if (memcmp(&random, &data_out_frame[blk_count - 1].nonce, RPMB_NONCE_SIZE)) {
		debug(L"Random is not expected in out data frame");
		ret = EFI_ABORTED;
		goto out;
	}
	for (i = 0; i < blk_count; i++)
		memcpy((UINT8 *)buffer + i * 256, data_out_frame[i].data, 256);

out:
	ret_switch_partition = emmc_partition_switch(sdio, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	if (data_out_frame)
		FreePool(data_out_frame);

	return ret;
}

EFI_STATUS emmc_write_rpmb_data(UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT32 write_counter;
	UINT8 current_part;
	rpmb_data_frame status_frame;
	rpmb_data_frame *data_in_frame = NULL;
	UINT32 i;
	UINT8 mac[RPMB_DATA_MAC];
	EFI_SD_HOST_IO_PROTOCOL *sdio = NULL;

	debug(L"write rpmb data: number of block =%d from blk %d", blk_count, blk_addr);
	if (!buffer || !result)
		return EFI_INVALID_PARAMETER;

	ret = get_emmc_sdio(&sdio);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get sdio");
		return ret;
	}

	ret = emmc_get_current_part_switch_part(sdio, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret))
		return ret;

	data_in_frame = AllocatePool(sizeof(rpmb_data_frame));
	if (!data_in_frame) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	ret = emmc_get_counter(&write_counter, key, result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get counter");
		goto out;
	}

	for (i = 0; i < blk_count; i++) {
		memset(data_in_frame, 0, sizeof(rpmb_data_frame));
		data_in_frame->address = CPU_TO_BE16_SWAP(blk_addr + i);
		data_in_frame->block_count = CPU_TO_BE16_SWAP(1);
		data_in_frame->req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_AUTH_WRITE);
		data_in_frame->write_counter = CPU_TO_BE32_SWAP(write_counter);
		memcpy(&data_in_frame->data, (UINT8 *)buffer + i * 256, 256);

		if (rpmb_calc_hmac_sha256(data_in_frame, 1,
			key, RPMB_KEY_SIZE,
			mac, RPMB_MAC_SIZE) == 0) {
			ret = EFI_INVALID_PARAMETER;
			goto out;
		}

		memcpy(data_in_frame->key_mac, mac, RPMB_DATA_MAC);
		ret = emmc_rpmb_send_request(sdio, data_in_frame, 1, TRUE);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to send request to rpmb");
			goto out;
		}

		memset(&status_frame, 0, sizeof(status_frame));
		status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);
		ret = emmc_rpmb_request_response(sdio, &status_frame, &status_frame, 1, 1,
			RPMB_RESPONSE_AUTH_WRITE, result);
		if (EFI_ERROR(ret))
			goto out;

		if (write_counter >= BE32_TO_CPU_SWAP(status_frame.write_counter)) {
			efi_perror(ret, L"RPMB write counter not incremeted returned counter is 0x%0x",
			status_frame.write_counter);
			ret = EFI_ABORTED;
			goto out;
		}
		write_counter++;
	}

out:
	ret_switch_partition = emmc_partition_switch(sdio, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	if (data_in_frame)
		FreePool(data_in_frame);

	return ret;
}

EFI_STATUS emmc_program_key(const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT8 current_part;
	rpmb_data_frame data_frame, status_frame;
	EFI_SD_HOST_IO_PROTOCOL *sdio = NULL;

	debug(L"enter emmc_program_key");
	if (!key || !result)
		return EFI_INVALID_PARAMETER;

	ret = get_emmc_sdio(&sdio);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get sdio");
		return ret;
	}

	ret = emmc_get_current_part_switch_part(sdio, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret))
		return ret;

	memset(&data_frame, 0, sizeof(data_frame));
	data_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_KEY_WRITE);
	memcpy(data_frame.key_mac, key, RPMB_KEY_SIZE);
	ret = emmc_rpmb_send_request(sdio, &data_frame, 1, TRUE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to request rpmb");
		goto out;
	}

	memset(&status_frame, 0, sizeof(status_frame));
	status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);

	ret = emmc_rpmb_request_response(sdio, &status_frame, &status_frame, 1, 1,
			RPMB_RESPONSE_KEY_WRITE, result);
	if (EFI_ERROR(ret))
		goto out;

out:
	ret_switch_partition = emmc_partition_switch(sdio, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	return ret;
}

EFI_STATUS emmc_get_counter(UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT8 current_part;
	rpmb_data_frame counter_frame;
	EFI_SD_HOST_IO_PROTOCOL *sdio = NULL;

	debug(L"enter emmc_get_counter");
	if (!result || !write_counter)
		return EFI_INVALID_PARAMETER;

	ret = get_emmc_sdio(&sdio);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get sdio");
		return ret;
	}

	ret = emmc_get_current_part_switch_part(sdio, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret))
		return ret;

	memset(&counter_frame, 0, sizeof(counter_frame));
	counter_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_COUNTER_READ);
	ret = generate_random_numbers(counter_frame.nonce, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		goto out;
	}
	ret = emmc_rpmb_request_response(sdio, &counter_frame, &counter_frame, 1, 1,
		RPMB_RESPONSE_COUNTER_READ, result);
	if (EFI_ERROR(ret))
		goto out;

	if (key && (rpmb_check_mac(key, &counter_frame, 1) == 0)) {
		debug(L"rpmb_check_mac failed");
		ret = EFI_ABORTED;
		goto out;
	}

	*write_counter = BE32_TO_CPU_SWAP(counter_frame.write_counter);
	debug(L"current counter is 0x%0x", *write_counter);

out:
	ret_switch_partition = emmc_partition_switch(sdio, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	return ret;
}
