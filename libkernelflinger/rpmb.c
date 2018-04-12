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

#ifdef USE_SD_PASS_THRU
#include "protocol/SdMmcPassThru.h"
#endif

#ifdef USE_UFS_SCSI_PASS_THRU
#include "protocol/ufs.h"
#include "protocol/ScsiPassThruExt.h"
#endif

#include "protocol/SdHostIo.h"
#include "sdio.h"
#include "storage.h"
#include "rpmb.h"
#include "gpt.h"

#define EMMC_GENERIC_TIMEOUT		(2500 * 1000)
#define TIMEOUT_DATA			3000
#define TIMEOUT_COMMAND			1000
#define RPMB_PARTITION			3
#define RPMB_DATA_FRAME_SIZE		512
#define RPMB_DATA_MAC			32
#define RPMB_KEY_SIZE			32
#define RPMB_MAC_SIZE			32
#define RPMB_ERROR_MASK			0x07
#define RPMB_NONCE_SIZE			16

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

#define MAGIC_KEY_OFFSET		0
#define MAGIC_KEY_DATA			"key_sim"
#define MAGIC_KEY_SIZE			7
#define WRITE_COUNTER_SIZE		4

#define EXT_CSD_PART_CONF		179
#define MMC_SWITCH_MODE_WRITE_BYTE	3

/* here 1024 means 1024 blocks, so 1024 blocks * 256 B = 256KB */
#define RPMB_ADDR_BOUNDARY_SIZE 1024

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
		UINT32  CmdSet:			3;
		UINT32  Reserved0:		5;
		UINT32  Value:			8;
		UINT32  Index:			8;
		UINT32  Access:			2;
		UINT32  Reserved1:		6;
	};
} RPMB_SWITCH_ARGUMENT;

struct rpmb_ops {
	EFI_STATUS (*get_storage_protocol)(void **rpmb_dev, EFI_HANDLE disk_handle);
	EFI_STATUS (*program_rpmb_key)(void *rpmb_dev,
			const void *key, RPMB_RESPONSE_RESULT * result);
	EFI_STATUS (*get_storage_partition_num)(void *rpmb_dev,
			UINT8 * current_part);
	EFI_STATUS (*storage_partition_switch)(void *rpmb_dev, UINT8 part);
	EFI_STATUS (*get_rpmb_counter)(void *rpmb_dev,
			UINT32 *write_counter, const void *key,
			RPMB_RESPONSE_RESULT * result);

	EFI_STATUS (*read_rpmb_data)(void *rpmb_dev,
			UINT16 blk_count, UINT16 blk_addr, void *buffer,
			const void *key, RPMB_RESPONSE_RESULT * result);
	EFI_STATUS (*write_rpmb_data)(void *rpmb_dev,
			UINT16 blk_count, UINT16 blk_addr, void *buffer,
			const void *key, RPMB_RESPONSE_RESULT * result);

	EFI_STATUS (*rpmb_send_request)(void *rpmb_dev,
			rpmb_data_frame * data_frame, UINT8 count,
			BOOLEAN is_rel_write);
	EFI_STATUS(*rpmb_get_response)(void *rpmb_dev,
			rpmb_data_frame * data_frame, UINT8 count);

};

#ifdef USE_SD_PASS_THRU
typedef struct {
	EFI_SD_MMC_PASS_THRU_PROTOCOL *passthru_prot;
	UINT8 slot;
} rpmb_dev_passthru_t;
static rpmb_dev_passthru_t def_rpmb_dev_passthru;
#endif

#ifdef USE_UFS_SCSI_PASS_THRU
static EFI_EXT_SCSI_PASS_THRU_PROTOCOL *def_rpmb_ufs_scsi_passthru;
UINT8 target[TARGET_MAX_BYTES] = {0x00};
#endif

typedef EFI_SD_HOST_IO_PROTOCOL * rpmb_dev_sdio_t;
static rpmb_dev_sdio_t def_rpmb_dev_sdio;

static BOOLEAN g_initialized = FALSE;
struct rpmb_ops emmc_rpmb_ops_sdio;
static struct rpmb_ops *storage_rpmb_ops = &emmc_rpmb_ops_sdio;

static INT32 rpmb_calc_hmac_sha256(rpmb_data_frame *frames, UINT8 blocks_cnt,
		const UINT8 key[], UINT32 key_size,
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

#ifdef USE_SD_PASS_THRU
static EMMC_DEVICE_PATH *rpmb_get_emmc_device_path(EFI_DEVICE_PATH *p)
{
	for (; !IsDevicePathEndType(p); p = NextDevicePathNode(p))
		if (DevicePathType(p) == MESSAGING_DEVICE_PATH
				&& DevicePathSubType(p) == MSG_EMMC_DP)
			return (EMMC_DEVICE_PATH *)p;

	return NULL;
}


EFI_STATUS get_emmc_passthru(void **rpmb_dev, EFI_HANDLE disk_handle)
{
	static BOOLEAN initialized = FALSE;
	rpmb_dev_passthru_t *rpmb_dev_passthru = &def_rpmb_dev_passthru;
	EFI_SD_MMC_PASS_THRU_PROTOCOL *passthru_prot;
	rpmb_dev_passthru_t **passthru = (rpmb_dev_passthru_t **)rpmb_dev;
	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path = NULL;
	EMMC_DEVICE_PATH *emmc_device_path = NULL;
	EFI_GUID guid = EFI_SD_MMC_PASS_THRU_PROTOCOL_GUID;
	extern struct storage STORAGE(STORAGE_EMMC);
	static struct storage *supported_storage = &STORAGE(STORAGE_EMMC);

	if (initialized && rpmb_dev_passthru->passthru_prot) {
		*passthru = rpmb_dev_passthru;
		return EFI_SUCCESS;
	}

	if (disk_handle != NULL) {
		device_path = DevicePathFromHandle(disk_handle);
		if (supported_storage->probe(device_path)) {
			debug(L"Is emmc device for the device handle with pass through");
			goto find;
		}
	}

	ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				&BlockIoProtocol, NULL, &nb_handle, &handles);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to locate Block IO Protocol");
		return ret;
	}

	for (i = 0; i < nb_handle; i++) {
		device_path = DevicePathFromHandle(handles[i]);
		if (supported_storage->probe(device_path)) {
			debug(L"Is emmc device with pass through");
			break;
		}
	}

	if (i == nb_handle)
		return EFI_UNSUPPORTED;

find:
	emmc_device_path = rpmb_get_emmc_device_path(device_path);
	rpmb_dev_passthru->slot = emmc_device_path->SlotNum;

	ret = LibLocateProtocol(&guid, (void **)&passthru_prot);
	if (EFI_ERROR(ret)) {
		error(L"failed to get SD_MMC_PassThru protocol");
		return ret;
	}
	rpmb_dev_passthru->passthru_prot = passthru_prot;
	*passthru = rpmb_dev_passthru;
	initialized = TRUE;

	debug(L"get eMMC pass through, slot: %d", rpmb_dev_passthru->slot);

	return ret;
}

EFI_STATUS get_emmc_partition_num_passthru(void *rpmb_dev, UINT8 *current_part)
{
	EXT_CSD *ext_csd;
	void *rawbuffer;
	EFI_STATUS ret;
	EFI_SD_MMC_COMMAND_BLOCK sdmmc_cmd_blk = {0};
	EFI_SD_MMC_STATUS_BLOCK sdmmc_status_blk = {0};
	EFI_SD_MMC_PASS_THRU_COMMAND_PACKET packet = {0};
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!passthru || !current_part)
		return EFI_INVALID_PARAMETER;

	ret = alloc_aligned(&rawbuffer, (void **)&ext_csd, sizeof(*ext_csd), passthru->passthru_prot->IoAlign);
	if (EFI_ERROR(ret))
		return ret;

	memset((void *)ext_csd, 0, sizeof(EXT_CSD));
	packet.SdMmcCmdBlk    = &sdmmc_cmd_blk;
	packet.SdMmcStatusBlk = &sdmmc_status_blk;

	sdmmc_cmd_blk.CommandIndex = SEND_EXT_CSD;
	sdmmc_cmd_blk.CommandType  = SdMmcCommandTypeAdtc;
	sdmmc_cmd_blk.ResponseType = SdMmcResponseTypeR1;
	sdmmc_cmd_blk.CommandArgument = 0x00000000;
	packet.InDataBuffer = (void *)ext_csd;
	packet.InTransferLength = sizeof(EXT_CSD);
	packet.Timeout		= EMMC_GENERIC_TIMEOUT;

	ret = uefi_call_wrapper(passthru->passthru_prot->PassThru, 4, passthru->passthru_prot, passthru->slot, &packet, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed get eMMC EXT_CSD");
		goto Error;
	}

	*current_part = ext_csd->PARTITION_CONFIG;
	debug(L"current EMMC parition num is %d", *current_part);

Error:
	FreePool(rawbuffer);

	return ret;
}

EFI_STATUS emmc_partition_switch_passthru(void *rpmb_dev, UINT8 part)
{
	EFI_STATUS ret = EFI_SUCCESS;
	RPMB_SWITCH_ARGUMENT arg;
	EFI_SD_MMC_COMMAND_BLOCK sdmmc_cmd_blk = {0};
	EFI_SD_MMC_STATUS_BLOCK sdmmc_status_blk = {0};
	EFI_SD_MMC_PASS_THRU_COMMAND_PACKET packet = {0};
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!passthru)
		return EFI_INVALID_PARAMETER;

	arg.CmdSet = 0;
	arg.Value = part;
	arg.Index = EXT_CSD_PART_CONF;
	arg.Access = MMC_SWITCH_MODE_WRITE_BYTE;

	packet.SdMmcCmdBlk    = &sdmmc_cmd_blk;
	packet.SdMmcStatusBlk = &sdmmc_status_blk;
	sdmmc_cmd_blk.CommandIndex = SWITCH;
	sdmmc_cmd_blk.CommandType  = SdMmcCommandTypeAc;
	sdmmc_cmd_blk.ResponseType = SdMmcResponseTypeR1b;
	sdmmc_cmd_blk.CommandArgument = arg.data;
	packet.Timeout		= EMMC_GENERIC_TIMEOUT;

	ret = uefi_call_wrapper(passthru->passthru_prot->PassThru, 4, passthru->passthru_prot, passthru->slot, &packet, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send SWITCH command");
		return ret;
	}

	memset(&sdmmc_cmd_blk, 0, sizeof(sdmmc_cmd_blk));
	memset(&sdmmc_status_blk, 0, sizeof(sdmmc_status_blk));
	memset(&packet, 0, sizeof(packet));
	packet.SdMmcCmdBlk    = &sdmmc_cmd_blk;
	packet.SdMmcStatusBlk = &sdmmc_status_blk;
	sdmmc_cmd_blk.CommandIndex = SEND_STATUS;
	sdmmc_cmd_blk.CommandType  = SdMmcCommandTypeAc;
	sdmmc_cmd_blk.ResponseType = SdMmcResponseTypeR1b;
	sdmmc_cmd_blk.CommandArgument = CARD_ADDRESS << 16;
	packet.Timeout		= EMMC_GENERIC_TIMEOUT;

	ret = uefi_call_wrapper(passthru->passthru_prot->PassThru, 4, passthru->passthru_prot, passthru->slot, &packet, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send SEND_STATUS command");
		return ret;
	}

	debug(L" EMMC parition %d switching successfully", part);

	return ret;
}

static EFI_STATUS emmc_get_current_part_switch_part_passthru(void *rpmb_dev, UINT8 *current_part, UINT8 switch_part)
{
	EFI_STATUS ret;
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!passthru || !current_part)
		return EFI_INVALID_PARAMETER;

	ret = get_emmc_partition_num_passthru(rpmb_dev, current_part);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get current partition");
		return ret;
	}

	if (*current_part == switch_part)
		return ret;

	ret = emmc_partition_switch_passthru(rpmb_dev, switch_part);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to switch parition %d", switch_part);
		return ret;
	}

	return ret;
}

static EFI_STATUS emmc_rpmb_send_blockcount_passthru(void *rpmb_dev, UINT8 count, BOOLEAN is_rel_write)
{
	EFI_STATUS ret;
	UINT32 arg = count;
	EFI_SD_MMC_COMMAND_BLOCK sdmmc_cmd_blk = {0};
	EFI_SD_MMC_STATUS_BLOCK sdmmc_status_blk = {0};
	EFI_SD_MMC_PASS_THRU_COMMAND_PACKET packet = {0};
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!passthru)
		return EFI_INVALID_PARAMETER;

	if (is_rel_write)
		arg  |= (1 << 31);

	packet.SdMmcCmdBlk    = &sdmmc_cmd_blk;
	packet.SdMmcStatusBlk = &sdmmc_status_blk;
	sdmmc_cmd_blk.CommandIndex = SET_BLOCK_COUNT;
	sdmmc_cmd_blk.CommandType  = SdMmcCommandTypeAc;
	sdmmc_cmd_blk.ResponseType = SdMmcResponseTypeR1;
	sdmmc_cmd_blk.CommandArgument = arg;
	packet.Timeout		= EMMC_GENERIC_TIMEOUT;

	ret = uefi_call_wrapper(passthru->passthru_prot->PassThru, 4, passthru->passthru_prot, passthru->slot, &packet, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send command SET_BLOCK_COUNT");
		return ret;
	}

	return ret;
}

EFI_STATUS emmc_rpmb_send_request_passthru(void *rpmb_dev, rpmb_data_frame *data_frame, UINT8 count, BOOLEAN is_rel_write)
{
	EFI_STATUS ret;
	EFI_SD_MMC_COMMAND_BLOCK sdmmc_cmd_blk = {0};
	EFI_SD_MMC_STATUS_BLOCK sdmmc_status_blk = {0};
	EFI_SD_MMC_PASS_THRU_COMMAND_PACKET packet = {0};
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!passthru || !data_frame)
		return EFI_INVALID_PARAMETER;

	ret = emmc_rpmb_send_blockcount_passthru(rpmb_dev, count, is_rel_write);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set block count");
		return ret;
	}

	packet.SdMmcCmdBlk    = &sdmmc_cmd_blk;
	packet.SdMmcStatusBlk = &sdmmc_status_blk;
	sdmmc_cmd_blk.CommandIndex = WRITE_MULTIPLE_BLOCK;
	sdmmc_cmd_blk.CommandType  = SdMmcCommandTypeAdtc;
	sdmmc_cmd_blk.ResponseType = SdMmcResponseTypeR1;
	sdmmc_cmd_blk.CommandArgument = 0;
	packet.OutDataBuffer = (void *)data_frame;
	packet.OutTransferLength = RPMB_DATA_FRAME_SIZE * count;
	//
	// Calculate timeout value through the below formula.
	// Timeout = (transfer size) / (2MB/s).
	// Taking 2MB/s as divisor is because it's nearest to the eMMC lowest
	// transfer speed (2.4MB/s).
	// Refer to eMMC 5.0 spec section 6.9.1 for details.
	//
	packet.Timeout		= (packet.OutTransferLength / (2 * 1024 * 1024) + 1) * 1000 * 1000;

	ret = uefi_call_wrapper(passthru->passthru_prot->PassThru, 4, passthru->passthru_prot, passthru->slot, &packet, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send command WRITE_MULTIPLE_BLOCK");
		return ret;
	}

	return ret;
}

EFI_STATUS emmc_rpmb_get_response_passthru(void *rpmb_dev, rpmb_data_frame *data_frame, UINT8 count)
{
	EFI_STATUS ret;
	EFI_SD_MMC_COMMAND_BLOCK sdmmc_cmd_blk = {0};
	EFI_SD_MMC_STATUS_BLOCK sdmmc_status_blk = {0};
	EFI_SD_MMC_PASS_THRU_COMMAND_PACKET packet = {0};
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!passthru || !data_frame)
		return EFI_INVALID_PARAMETER;

	debug(L"enter emmc_rpmb_get_response");

	ret = emmc_rpmb_send_blockcount_passthru(rpmb_dev, count, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set block count");
		return ret;
	}

	packet.SdMmcCmdBlk    = &sdmmc_cmd_blk;
	packet.SdMmcStatusBlk = &sdmmc_status_blk;
	sdmmc_cmd_blk.CommandIndex = READ_MULTIPLE_BLOCK;
	sdmmc_cmd_blk.CommandType  = SdMmcCommandTypeAdtc;
	sdmmc_cmd_blk.ResponseType = SdMmcResponseTypeR1;
	sdmmc_cmd_blk.CommandArgument = 0;
	packet.InDataBuffer = (void *)data_frame;
	packet.InTransferLength = RPMB_DATA_FRAME_SIZE * count;
	//
	// Calculate timeout value through the below formula.
	// Timeout = (transfer size) / (2MB/s).
	// Taking 2MB/s as divisor is because it's nearest to the eMMC lowest
	// transfer speed (2.4MB/s).
	// Refer to eMMC 5.0 spec section 6.9.1 for details.
	//
	packet.Timeout		= (packet.InTransferLength / (2 * 1024 * 1024) + 1) * 1000 * 1000;

	ret = uefi_call_wrapper(passthru->passthru_prot->PassThru, 4, passthru->passthru_prot, passthru->slot, &packet, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send command READ_MULTIPLE_BLOCK");
		return ret;
	}

	return ret;
}

static EFI_STATUS emmc_rpmb_request_response_passthru(void *rpmb_dev,
		rpmb_data_frame *request_data_frame, rpmb_data_frame *response_data_frame, UINT8 req_count,
		UINT8 res_count, UINT16 expected, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	UINT16 res_result;

	ret = emmc_rpmb_send_request_passthru(rpmb_dev, request_data_frame, req_count, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		return ret;
	}

	ret = emmc_rpmb_get_response_passthru(rpmb_dev, response_data_frame, res_count);
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

EFI_STATUS emmc_read_rpmb_data_passthru(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT8 current_part;
	rpmb_data_frame data_in_frame;
	rpmb_data_frame *data_out_frame = NULL;
	UINT32 i;
	UINT8 random[16] = {0};
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	debug(L"read rpmb data: number of block=%d from blk %d", blk_count, blk_addr);
	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!buffer || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	ret = emmc_get_current_part_switch_part_passthru(rpmb_dev, &current_part, RPMB_PARTITION);
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
	ret = emmc_rpmb_request_response_passthru(rpmb_dev, &data_in_frame, data_out_frame, 1,
			blk_count, RPMB_RESPONSE_AUTH_READ, result);
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
	ret_switch_partition = emmc_partition_switch_passthru(rpmb_dev, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	if (data_out_frame)
		FreePool(data_out_frame);

	return ret;
}

EFI_STATUS emmc_get_counter_passthru(void *rpmb_dev, UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT8 current_part;
	rpmb_data_frame counter_frame;
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!result || !write_counter || !passthru)
		return EFI_INVALID_PARAMETER;

	ret = emmc_get_current_part_switch_part_passthru(rpmb_dev, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret))
		return ret;

	memset(&counter_frame, 0, sizeof(counter_frame));
	counter_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_COUNTER_READ);
	ret = generate_random_numbers(counter_frame.nonce, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		goto out;
	}

	ret = emmc_rpmb_request_response_passthru(rpmb_dev, &counter_frame, &counter_frame,
		1, 1, RPMB_RESPONSE_COUNTER_READ, result);
	if (EFI_ERROR(ret))
		goto out;

	if (key && (rpmb_check_mac(key, &counter_frame, 1) == 0)) {
		debug(L"rpmb_check_mac failed");
		*result = RPMB_RES_AUTH_FAILURE;
		ret = EFI_ABORTED;
		goto out;
	}

	*write_counter = BE32_TO_CPU_SWAP(counter_frame.write_counter);
	debug(L"current counter is 0x%0x", *write_counter);

out:
	ret_switch_partition = emmc_partition_switch_passthru(rpmb_dev, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	return ret;
}

EFI_STATUS emmc_write_rpmb_data_passthru(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT32 write_counter;
	UINT8 current_part;
	rpmb_data_frame status_frame;
	rpmb_data_frame *data_in_frame = NULL;
	UINT32 i;
	UINT8 mac[RPMB_DATA_MAC];
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	debug(L"write rpmb data: number of block =%d from blk %d", blk_count, blk_addr);
	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!buffer || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	ret = emmc_get_current_part_switch_part_passthru(rpmb_dev, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret))
		return ret;

	data_in_frame = AllocatePool(sizeof(rpmb_data_frame));
	if (!data_in_frame) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	ret = emmc_get_counter_passthru(rpmb_dev, &write_counter, key, result);
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
		ret = emmc_rpmb_send_request_passthru(rpmb_dev, data_in_frame, 1, TRUE);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to send request to rpmb");
			goto out;
		}

		memset(&status_frame, 0, sizeof(status_frame));
		status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);
		ret = emmc_rpmb_request_response_passthru(rpmb_dev, &status_frame, &status_frame, 1, 1,
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
	ret_switch_partition = emmc_partition_switch_passthru(rpmb_dev, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	if (data_in_frame)
		FreePool(data_in_frame);

	return ret;
}

EFI_STATUS emmc_program_key_passthru(void *rpmb_dev, const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT8 current_part;
	rpmb_data_frame data_frame, status_frame;
	rpmb_dev_passthru_t *passthru = (rpmb_dev_passthru_t *)rpmb_dev;

	debug(L"enter emmc_program_key");

	if (passthru == NULL)
		passthru = &def_rpmb_dev_passthru;

	if (!key || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	ret = emmc_get_current_part_switch_part_passthru(rpmb_dev, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"emmc_get_current_part_switch_part failed");
		return ret;
	}

	memset(&data_frame, 0, sizeof(data_frame));
	data_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_KEY_WRITE);
	memcpy(data_frame.key_mac, key, RPMB_KEY_SIZE);
	ret = emmc_rpmb_send_request_passthru(rpmb_dev, &data_frame, 1, TRUE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to request rpmb");
		goto out;
	}

	memset(&status_frame, 0, sizeof(status_frame));
	status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);

	ret = emmc_rpmb_request_response_passthru(rpmb_dev, &status_frame, &status_frame,
		1, 1, RPMB_RESPONSE_KEY_WRITE, result);
	if (EFI_ERROR(ret))
		goto out;

out:
	ret_switch_partition = emmc_partition_switch_passthru(rpmb_dev, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
		return ret;
	}

	return ret;
}
#endif  // USE_SD_PASS_THRU

EFI_STATUS get_emmc_partition_num_sdio(void *rpmb_dev,
		UINT8 *current_part)
{
	EXT_CSD *ext_csd;
	void *rawbuffer;
	UINT32 status;
	EFI_STATUS ret;
	EFI_SD_HOST_IO_PROTOCOL *sdio = (EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev;

	if (!sdio)
		sdio = def_rpmb_dev_sdio;

	if (!sdio || !current_part)
		return EFI_INVALID_PARAMETER;


	ret = alloc_aligned(&rawbuffer, (void **)&ext_csd, sizeof(*ext_csd), sdio->HostCapability.BoundarySize);
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

EFI_STATUS get_emmc_sdio(void **rpmb_dev, EFI_HANDLE disk_handle)
{
	static BOOLEAN initialized = FALSE;
	EFI_SD_HOST_IO_PROTOCOL *sdio_rpmb = def_rpmb_dev_sdio;
	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path;
	EFI_HANDLE sdio_handle = NULL;
	EFI_SD_HOST_IO_PROTOCOL **sdio = (EFI_SD_HOST_IO_PROTOCOL **)rpmb_dev;
	extern struct storage STORAGE(STORAGE_EMMC);
	static struct storage *supported_storage = &STORAGE(STORAGE_EMMC);

	if (initialized && sdio_rpmb) {
		*sdio = sdio_rpmb;
		return EFI_SUCCESS;
	}

	if (disk_handle != NULL) {
		device_path = DevicePathFromHandle(disk_handle);
		if (supported_storage->probe(device_path)) {
			debug(L"Is emmc device for the device handle with sdio");
			goto find;
		}
	}

	ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				&BlockIoProtocol, NULL, &nb_handle, &handles);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to locate Block IO Protocol");
		return ret;
	}

	for (i = 0; i < nb_handle; i++) {
		device_path = DevicePathFromHandle(handles[i]);
		if (supported_storage->probe(device_path)) {
			debug(L"Is emmc device with sdio");
			break;
		}
	}

	if (i == nb_handle)
		return EFI_UNSUPPORTED;

find:
	ret = sdio_get(device_path, &sdio_handle, &sdio_rpmb);
	if (EFI_ERROR(ret))
		return EFI_UNSUPPORTED;

	initialized = TRUE;
	*sdio = sdio_rpmb;

	return ret;
}

EFI_STATUS emmc_partition_switch_sdio(void *rpmb_dev, UINT8 part)
{
	UINT32 status;
	CARD_STATUS card_status;
	EFI_STATUS ret = EFI_SUCCESS;
	RPMB_SWITCH_ARGUMENT arg;
	EFI_SD_HOST_IO_PROTOCOL *sdio = (EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev;

	arg.CmdSet = 0;
	arg.Value = part;
	arg.Index = EXT_CSD_PART_CONF;
	arg.Access = MMC_SWITCH_MODE_WRITE_BYTE;

	debug(L"Enter emmc_partition_switch");

	if (sdio == NULL)
		sdio = def_rpmb_dev_sdio;

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

static EFI_STATUS emmc_get_current_part_switch_part_sdio(EFI_SD_HOST_IO_PROTOCOL *sdio,
		UINT8 *current_part, UINT8 switch_part)
{
	EFI_STATUS ret;

	if (!sdio || !current_part)
		return EFI_INVALID_PARAMETER;

	ret = get_emmc_partition_num_sdio(sdio, current_part);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get current partition");
		return ret;
	}

	if (*current_part == switch_part)
		return ret;

	ret = emmc_partition_switch_sdio(sdio, switch_part);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to switch parition %d", switch_part);
		return ret;
	}

	return ret;
}

static EFI_STATUS emmc_rpmb_send_blockcount_sdio(EFI_SD_HOST_IO_PROTOCOL *sdio,
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

EFI_STATUS emmc_rpmb_send_request_sdio(void *rpmb_dev,
		rpmb_data_frame *data_frame, UINT8 count, BOOLEAN is_rel_write)
{
	EFI_STATUS ret;
	UINT32 status;
	EFI_SD_HOST_IO_PROTOCOL *sdio = (EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev;
	void *rawbuffer;
	rpmb_data_frame *rdf;

	if (sdio == NULL)
		sdio = def_rpmb_dev_sdio;

	if (!sdio || !data_frame)
		return EFI_INVALID_PARAMETER;

	ret = emmc_rpmb_send_blockcount_sdio(sdio, count, is_rel_write);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set block count");
		return ret;
	}

	ret = alloc_aligned(&rawbuffer, (void **)&rdf, RPMB_DATA_FRAME_SIZE * count,
				sdio->HostCapability.BoundarySize);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"alloc_aligned failed");
		return ret;
	}

	memcpy(rdf, data_frame, RPMB_DATA_FRAME_SIZE * count);

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio,
				WRITE_MULTIPLE_BLOCK, 0, OutData, (VOID *)rdf,
				RPMB_DATA_FRAME_SIZE * count, ResponseR1, TIMEOUT_DATA, &status);
	FreePool(rawbuffer);
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

EFI_STATUS emmc_rpmb_get_response_sdio(void *rpmb_dev,
		rpmb_data_frame *data_frame, UINT8 count)
{
	EFI_STATUS ret;
	UINT32 status;
	EFI_SD_HOST_IO_PROTOCOL *sdio = (EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev;
	void *rawbuffer;
	rpmb_data_frame *rdf;

	if (sdio == NULL)
		sdio = def_rpmb_dev_sdio;

	if (!sdio || !data_frame)
		return EFI_INVALID_PARAMETER;

	debug(L"enter emmc_rpmb_get_response");

	ret = emmc_rpmb_send_blockcount_sdio(sdio, count, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set block count");
		return ret;
	}

	ret = alloc_aligned(&rawbuffer, (void **)&rdf, RPMB_DATA_FRAME_SIZE * count,
				sdio->HostCapability.BoundarySize);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"alloc_aligned failed");
		return ret;
	}

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio,
				READ_MULTIPLE_BLOCK, 0, InData, (VOID *)rdf,
				RPMB_DATA_FRAME_SIZE * count, ResponseR1, TIMEOUT_DATA, &status);
	memcpy(data_frame, rdf, RPMB_DATA_FRAME_SIZE * count);
	FreePool(rawbuffer);

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

static EFI_STATUS emmc_rpmb_request_response_sdio(EFI_SD_HOST_IO_PROTOCOL *sdio,
		rpmb_data_frame *request_data_frame, rpmb_data_frame *response_data_frame, UINT8 req_count,
		UINT8 res_count, UINT16 expected, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	UINT16 res_result;

	ret = emmc_rpmb_send_request_sdio(sdio, request_data_frame, req_count, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		return ret;
	}

	ret = emmc_rpmb_get_response_sdio(sdio, response_data_frame, res_count);
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

EFI_STATUS emmc_read_rpmb_data_sdio(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT8 current_part;
	rpmb_data_frame data_in_frame;
	rpmb_data_frame *data_out_frame = NULL;
	UINT32 i;
	UINT8 random[16] = {0};
	EFI_SD_HOST_IO_PROTOCOL *sdio = (EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev;

	debug(L"read rpmb data: number of block=%d from blk %d", blk_count, blk_addr);
	if (sdio == NULL)
		sdio = def_rpmb_dev_sdio;

	if (!buffer || !result || !sdio)
		return EFI_INVALID_PARAMETER;

	ret = emmc_get_current_part_switch_part_sdio(sdio, &current_part, RPMB_PARTITION);
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
	ret = emmc_rpmb_request_response_sdio(sdio, &data_in_frame, data_out_frame, 1, blk_count,
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
	ret_switch_partition = emmc_partition_switch_sdio(sdio, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	if (data_out_frame)
		FreePool(data_out_frame);

	return ret;
}

EFI_STATUS emmc_get_counter_sdio(void *rpmb_dev, UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT8 current_part;
	rpmb_data_frame counter_frame;
	EFI_SD_HOST_IO_PROTOCOL *sdio = (EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev;

	debug(L"enter emmc_get_counter_sdio");
	if (sdio == NULL)
		sdio = def_rpmb_dev_sdio;

	if (!result || !write_counter || !sdio)
		return EFI_INVALID_PARAMETER;

	ret = emmc_get_current_part_switch_part_sdio(sdio, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to switch part");
		return ret;
	}

	memset(&counter_frame, 0, sizeof(counter_frame));
	counter_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_COUNTER_READ);
	ret = generate_random_numbers(counter_frame.nonce, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		goto out;
	}
	ret = emmc_rpmb_request_response_sdio(sdio, &counter_frame, &counter_frame, 1, 1,
		RPMB_RESPONSE_COUNTER_READ, result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read RPMB_RESPONSE_COUNTER_READ");
		goto out;
	}

	if (key && (rpmb_check_mac(key, &counter_frame, 1) == 0)) {
		debug(L"rpmb_check_mac failed");
		*result = RPMB_RES_AUTH_FAILURE;
		ret = EFI_ABORTED;
		goto out;
	}

	*write_counter = BE32_TO_CPU_SWAP(counter_frame.write_counter);
	debug(L"current counter is 0x%0x", *write_counter);

out:
	ret_switch_partition = emmc_partition_switch_sdio(sdio, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	return ret;
}

EFI_STATUS emmc_write_rpmb_data_sdio(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT32 write_counter;
	UINT8 current_part;
	rpmb_data_frame status_frame;
	rpmb_data_frame *data_in_frame = NULL;
	UINT32 i;
	UINT8 mac[RPMB_DATA_MAC];
	EFI_SD_HOST_IO_PROTOCOL *sdio = (EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev;

	debug(L"write rpmb data: number of block =%d from blk %d", blk_count, blk_addr);
	if (sdio == NULL)
		sdio = def_rpmb_dev_sdio;

	if (!buffer || !result || !sdio)
		return EFI_INVALID_PARAMETER;

	ret = emmc_get_current_part_switch_part_sdio(sdio, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret))
		return ret;

	data_in_frame = AllocatePool(sizeof(rpmb_data_frame));
	if (!data_in_frame) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	ret = emmc_get_counter_sdio(sdio, &write_counter, key, result);
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
		ret = emmc_rpmb_send_request_sdio(sdio, data_in_frame, 1, TRUE);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to send request to rpmb");
			goto out;
		}

		memset(&status_frame, 0, sizeof(status_frame));
		status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);
		ret = emmc_rpmb_request_response_sdio(sdio, &status_frame, &status_frame, 1, 1,
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
	ret_switch_partition = emmc_partition_switch_sdio(sdio, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	if (data_in_frame)
		FreePool(data_in_frame);

	return ret;
}

EFI_STATUS emmc_program_key_sdio(void *rpmb_dev, const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS, ret_switch_partition;
	UINT8 current_part;
	rpmb_data_frame data_frame, status_frame;
	EFI_SD_HOST_IO_PROTOCOL *sdio = (EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev;

	debug(L"enter emmc_program_key");
	if (sdio == NULL)
		sdio = def_rpmb_dev_sdio;

	if (!key || !result)
		return EFI_INVALID_PARAMETER;

	ret = emmc_get_current_part_switch_part_sdio(sdio, &current_part, RPMB_PARTITION);
	if (EFI_ERROR(ret))
		return ret;

	memset(&data_frame, 0, sizeof(data_frame));
	data_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_KEY_WRITE);
	memcpy(data_frame.key_mac, key, RPMB_KEY_SIZE);
	ret = emmc_rpmb_send_request_sdio(sdio, &data_frame, 1, TRUE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to request rpmb");
		goto out;
	}

	memset(&status_frame, 0, sizeof(status_frame));
	status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);

	ret = emmc_rpmb_request_response_sdio(sdio, &status_frame, &status_frame, 1, 1,
			RPMB_RESPONSE_KEY_WRITE, result);
	if (EFI_ERROR(ret))
		goto out;

out:
	ret_switch_partition = storage_partition_switch(sdio, current_part);
	if (EFI_ERROR(ret_switch_partition)) {
		efi_perror(ret, L"Failed to switch emmc current partition");
		ret = ret_switch_partition;
	}

	return ret;
}

static EFI_STATUS rpmb_simulate_read_write_teedata_partition(
		BOOLEAN bread, UINT32 offset, UINT32 len, void *data)
{
	UINT64 partlen;
	UINT64 partoffset;
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;

	if (!data)
		return EFI_INVALID_PARAMETER;

	ret = gpt_get_partition_by_label(L"teedata", &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		error(L"teedata partition not found");
		return ret;
	}

	partlen = (gparti.part.ending_lba + 1 - gparti.part.starting_lba) * gparti.bio->Media->BlockSize;
	partoffset = gparti.part.starting_lba * gparti.bio->Media->BlockSize;

	if (len + offset > partlen) {
		debug(L"attempt to read/write outside of partition %s, (len %lld offset %lld partition len %lld)",
				gparti.part.name, len, offset, partlen);
		return EFI_END_OF_MEDIA;
	}
	if (bread) {
		ret = uefi_call_wrapper(gparti.dio->ReadDisk, 5,
				gparti.dio, gparti.bio->Media->MediaId, partoffset + offset, len, data);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"read partition %s failed", gparti.part.name);
	} else {
		ret = uefi_call_wrapper(gparti.dio->WriteDisk, 5,
				gparti.dio, gparti.bio->Media->MediaId, partoffset + offset, len, data);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"write partition %s failed", gparti.part.name);
	}

	return ret;
}

EFI_STATUS simulate_get_rpmb_counter(UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	unsigned char data[MAGIC_KEY_SIZE + RPMB_KEY_SIZE + WRITE_COUNTER_SIZE];
	unsigned char counter_data[WRITE_COUNTER_SIZE];

	ret = rpmb_simulate_read_write_teedata_partition(TRUE, MAGIC_KEY_OFFSET,
			MAGIC_KEY_SIZE + RPMB_KEY_SIZE + WRITE_COUNTER_SIZE, data);
	if (EFI_ERROR(ret)) {
		error(L"read data from emulation rpmb parition failed");
		return ret;
	}

	if (memcmp(data, MAGIC_KEY_DATA, MAGIC_KEY_SIZE)) {
		*result = RPMB_RES_NO_AUTH_KEY_PROGRAM;
		return EFI_ABORTED;
	}
	if (memcmp(&data[MAGIC_KEY_SIZE], key, RPMB_KEY_SIZE)) {
		*result = RPMB_RES_AUTH_FAILURE;
		return EFI_ABORTED;
	}
	memcpy(counter_data, &data[MAGIC_KEY_SIZE + RPMB_KEY_SIZE], WRITE_COUNTER_SIZE);
	*write_counter = ((UINT32)counter_data[0]) << 24;
	*write_counter |= ((UINT32)counter_data[1]) << 16;
	*write_counter |= ((UINT32)counter_data[2]) << 8;
	*write_counter |= ((UINT32)counter_data[3]);

	return ret;
}

EFI_STATUS simulate_program_rpmb_key(const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	unsigned char data[MAGIC_KEY_SIZE + RPMB_KEY_SIZE + WRITE_COUNTER_SIZE];
	unsigned char magic[MAGIC_KEY_SIZE];

	if (!key || !result)
		return EFI_INVALID_PARAMETER;

	ret = rpmb_simulate_read_write_teedata_partition(TRUE, MAGIC_KEY_OFFSET,
			MAGIC_KEY_SIZE, magic);
	if (EFI_ERROR(ret)) {
		error(L"read key from emulation rpmb parition failed");
		return ret;
	}

	memset(data, 0, sizeof(data));
	if (memcmp(magic, MAGIC_KEY_DATA, MAGIC_KEY_SIZE)) {
		debug(L"rpmb key not provisioned");
		memcpy(data, MAGIC_KEY_DATA, MAGIC_KEY_SIZE);
		memcpy(&data[MAGIC_KEY_SIZE], key, RPMB_KEY_SIZE);

		ret = rpmb_simulate_read_write_teedata_partition(FALSE, MAGIC_KEY_OFFSET,
				MAGIC_KEY_SIZE + RPMB_KEY_SIZE + WRITE_COUNTER_SIZE, data);
		if (EFI_ERROR(ret)) {
			error(L"write key magic, key and counter to emulation rpmb parition failed");
			return ret;
		}
	} else {
		debug(L"rpmb key already provisioned");
		*result = RPMB_RES_GENERAL_FAILURE;
		return EFI_ABORTED;
	}

	return ret;
}

EFI_STATUS simulate_read_rpmb_data(UINT32 offset, void *buffer,
		UINT32 size)
{
	EFI_STATUS ret;

	if (!buffer)
		return EFI_INVALID_PARAMETER;

	ret = rpmb_simulate_read_write_teedata_partition(TRUE, offset,
			size, buffer);
	if (EFI_ERROR(ret))
		error(L"read data from emulation parition failed");

	return ret;
}

EFI_STATUS simulate_write_rpmb_data(UINT32 offset, void *buffer,
		UINT32 size)
{
	EFI_STATUS ret;

	if (!buffer)
		return EFI_INVALID_PARAMETER;

	ret = rpmb_simulate_read_write_teedata_partition(FALSE, offset,
			size, buffer);
	if (EFI_ERROR(ret))
		error(L"write data to emulation parition failed");

	return ret;
}

struct rpmb_ops emmc_rpmb_ops_sdio = {
	.get_storage_protocol = get_emmc_sdio,
	.program_rpmb_key = emmc_program_key_sdio,
	.get_storage_partition_num = get_emmc_partition_num_sdio,
	.storage_partition_switch = emmc_partition_switch_sdio,
	.get_rpmb_counter = emmc_get_counter_sdio,
	.read_rpmb_data = emmc_read_rpmb_data_sdio,
	.write_rpmb_data = emmc_write_rpmb_data_sdio,
	.rpmb_send_request = emmc_rpmb_send_request_sdio,
	.rpmb_get_response = emmc_rpmb_get_response_sdio
};

#ifdef USE_SD_PASS_THRU
struct rpmb_ops emmc_rpmb_ops_passthru = {
	.get_storage_protocol = get_emmc_passthru,
	.program_rpmb_key = emmc_program_key_passthru,
	.get_storage_partition_num = get_emmc_partition_num_passthru,
	.storage_partition_switch = emmc_partition_switch_passthru,
	.get_rpmb_counter = emmc_get_counter_passthru,
	.read_rpmb_data = emmc_read_rpmb_data_passthru,
	.write_rpmb_data = emmc_write_rpmb_data_passthru,
	.rpmb_send_request = emmc_rpmb_send_request_passthru,
	.rpmb_get_response = emmc_rpmb_get_response_passthru
};
#endif  // USE_SD_PASS_THRU

#ifdef USE_UFS_SCSI_PASS_THRU
EFI_STATUS get_ufs_passthru(void **rpmb_dev, EFI_HANDLE disk_handle)
{
	static BOOLEAN initialized = FALSE;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL **passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL **)rpmb_dev;

	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path = NULL;
	EFI_GUID guid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	extern struct storage STORAGE(STORAGE_UFS);
	static struct storage *supported_storage = &STORAGE(STORAGE_UFS);

	if (initialized && def_rpmb_ufs_scsi_passthru) {
		*passthru = def_rpmb_ufs_scsi_passthru;
		return EFI_SUCCESS;
	}

	if (disk_handle != NULL) {
		device_path = DevicePathFromHandle(disk_handle);
		if (supported_storage->probe(device_path)) {
			debug(L"Is ufs device for the device handle with pass through");
			goto find;
		}
	}

	ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				&BlockIoProtocol, NULL, &nb_handle, &handles);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to locate Block IO Protocol");
		return ret;
	}

	for (i = 0; i < nb_handle; i++) {
		device_path = DevicePathFromHandle(handles[i]);
		if (supported_storage->probe(device_path)) {
			debug(L"Is ufs device with pass through");
			break;
		}
	}

	if (i == nb_handle)
		return EFI_UNSUPPORTED;

find:

	ret = LibLocateProtocol(&guid, (void **)&def_rpmb_ufs_scsi_passthru);
	if (EFI_ERROR(ret)) {
		error(L"failed to get UFS pass thru protocol");
		return ret;
	}
	*passthru = def_rpmb_ufs_scsi_passthru;
	initialized = TRUE;

	debug(L"get ufs pass through");

	return ret;
}

/* For reading/writing UFS RPMB, which is not required to swtich partition since the interface
      read/write includes the parition number, therefore always return RPMB_PARTITION in order to
      be comptitable with EMMC
*/
EFI_STATUS get_ufs_partition_num_passthru(void *rpmb_dev, UINT8 *current_part)
{
	EFI_STATUS ret = EFI_SUCCESS;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!passthru || !current_part)
		return EFI_INVALID_PARAMETER;

	*current_part = RPMB_PARTITION;

	return ret;
}

/* For reading/writing UFS RPMB, which is not required to swtich partition since the interface
      read/write includes the parition number, therefore always return OK in order to
      be comptitable with EMMC
*/
EFI_STATUS ufs_partition_switch_passthru(void *rpmb_dev, __attribute__((__unused__)) UINT8 part)
{
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!passthru)
		return EFI_INVALID_PARAMETER;

	debug(L"ufs parition switching successfully");

	return EFI_SUCCESS;
}

EFI_STATUS ufs_rpmb_send_request_passthru(void *rpmb_dev, rpmb_data_frame *data_frame, UINT8 count,
	__attribute__((unused)) BOOLEAN is_rel_write)
{
	EFI_STATUS ret;
	EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET packet = {0};
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;
	struct command_descriptor_block_security_protocol cdb;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!passthru || !data_frame)
		return EFI_INVALID_PARAMETER;

	ZeroMem(&cdb, sizeof(cdb));

	cdb.op_code = UFS_SECURITY_PROTOCOL_OUT;
	cdb.sec_protocol = 0xEC;
	cdb.inc_512 = 0;
	cdb.sec_protocol_specific = BE16_TO_CPU_SWAP(0x0001);
	cdb.allocation_transfer_length = BE32_TO_CPU_SWAP(RPMB_DATA_FRAME_SIZE * count);

	packet.Timeout = BLOCK_TIMEOUT * count;
	packet.OutDataBuffer = (void *)data_frame;
	packet.Cdb = &cdb;
	packet.OutTransferLength = RPMB_DATA_FRAME_SIZE * count;
	packet.CdbLength = sizeof(cdb);
	packet.DataDirection = EFI_EXT_SCSI_DATA_DIRECTION_WRITE;

	ret = uefi_call_wrapper(passthru->PassThru, 5, passthru, &target[0], UFS_RPMB_LUN, &packet, NULL);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send RPMB request");
		return ret;
	}
	debug(L"send_request status = %0x", packet.TargetStatus);
	return ret;
}

EFI_STATUS ufs_rpmb_get_response_passthru(void *rpmb_dev, rpmb_data_frame *data_frame, UINT8 count)
{
	EFI_STATUS ret;
	EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET packet = {0};
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;
	struct command_descriptor_block_security_protocol cdb;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!passthru || !data_frame)
		return EFI_INVALID_PARAMETER;

	ZeroMem(&cdb, sizeof(cdb));

	cdb.op_code = UFS_SECURITY_PROTOCOL_IN;
	cdb.sec_protocol = 0xEC;
	cdb.inc_512 = 0;
	cdb.sec_protocol_specific = BE16_TO_CPU_SWAP(0x0001);
	cdb.allocation_transfer_length = BE32_TO_CPU_SWAP(RPMB_DATA_FRAME_SIZE * count);

	packet.Timeout = BLOCK_TIMEOUT * count;
	packet.InDataBuffer = (void *)data_frame;
	packet.Cdb = &cdb;
	packet.InTransferLength = RPMB_DATA_FRAME_SIZE * count;
	packet.CdbLength = sizeof(cdb);
	packet.DataDirection = EFI_EXT_SCSI_DATA_DIRECTION_READ;

	ret = uefi_call_wrapper(passthru->PassThru, 5, passthru, &target[0], UFS_RPMB_LUN, &packet, NULL);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send RPMB request");
		return ret;
	}
	debug(L"get_response status = %0x", packet.TargetStatus);
	return ret;
}


static EFI_STATUS ufs_rpmb_request_response_passthru(void *rpmb_dev,
		rpmb_data_frame *request_data_frame, rpmb_data_frame *response_data_frame, UINT8 req_count,
		UINT8 res_count, UINT16 expected, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	UINT16 res_result;

	ret = ufs_rpmb_send_request_passthru(rpmb_dev, request_data_frame, req_count, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		return ret;
	}

	ret = ufs_rpmb_get_response_passthru(rpmb_dev, response_data_frame, res_count);
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

EFI_STATUS ufs_read_rpmb_data_passthru(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame data_in_frame;
	rpmb_data_frame *data_out_frame = NULL;
	UINT32 i;
	UINT8 random[16] = {0};
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"read rpmb data: number of block=%d from blk %d", blk_count, blk_addr);
	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!buffer || !result || !passthru)
		return EFI_INVALID_PARAMETER;

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
	ret = ufs_rpmb_request_response_passthru(rpmb_dev, &data_in_frame, data_out_frame, 1,
			blk_count, RPMB_RESPONSE_AUTH_READ, result);
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

	if (data_out_frame)
		FreePool(data_out_frame);

	return ret;
}

EFI_STATUS ufs_get_counter_passthru(void *rpmb_dev, UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame counter_frame;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!result || !write_counter || !passthru)
		return EFI_INVALID_PARAMETER;

	memset(&counter_frame, 0, sizeof(counter_frame));
	counter_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_COUNTER_READ);
	ret = generate_random_numbers(counter_frame.nonce, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		goto out;
	}

	debug(L"ufs_get_counter_passthru: ufs_rpmb_request_response_passthru");
	ret = ufs_rpmb_request_response_passthru(rpmb_dev, &counter_frame, &counter_frame,
		1, 1, RPMB_RESPONSE_COUNTER_READ, result);
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

	return ret;
}

EFI_STATUS ufs_write_rpmb_data_passthru(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT32 write_counter;
	rpmb_data_frame status_frame;
	rpmb_data_frame *data_in_frame = NULL;
	UINT32 i;
	UINT8 mac[RPMB_DATA_MAC];
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"write rpmb data: number of block =%d from blk %d", blk_count, blk_addr);
	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!buffer || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	data_in_frame = AllocatePool(sizeof(rpmb_data_frame));
	if (!data_in_frame) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	ret = ufs_get_counter_passthru(rpmb_dev, &write_counter, key, result);
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
		ret = ufs_rpmb_send_request_passthru(rpmb_dev, data_in_frame, 1, TRUE);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to send request to rpmb");
			goto out;
		}

		memset(&status_frame, 0, sizeof(status_frame));
		status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);
		ret = ufs_rpmb_request_response_passthru(rpmb_dev, &status_frame, &status_frame, 1, 1,
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
	if (data_in_frame)
		FreePool(data_in_frame);

	return ret;
}

EFI_STATUS ufs_program_key_passthru(void *rpmb_dev, const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame data_frame, status_frame;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"enter ufs_program_key");

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!key || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	memset(&data_frame, 0, sizeof(data_frame));
	data_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_KEY_WRITE);
	memcpy(data_frame.key_mac, key, RPMB_KEY_SIZE);
	ret = ufs_rpmb_send_request_passthru(rpmb_dev, &data_frame, 1, TRUE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to request rpmb");
		return ret;
	}

	memset(&status_frame, 0, sizeof(status_frame));
	status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);

	ret = ufs_rpmb_request_response_passthru(rpmb_dev, &status_frame, &status_frame,
		1, 1, RPMB_RESPONSE_KEY_WRITE, result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to request response rpmb");
		return ret;
	}

	return ret;
}

struct rpmb_ops ufs_rpmb_ops_passthru = {
	.get_storage_protocol = get_ufs_passthru,
	.program_rpmb_key = ufs_program_key_passthru,
	.get_storage_partition_num = get_ufs_partition_num_passthru,
	.storage_partition_switch = ufs_partition_switch_passthru,
	.get_rpmb_counter = ufs_get_counter_passthru,
	.read_rpmb_data = ufs_read_rpmb_data_passthru,
	.write_rpmb_data = ufs_write_rpmb_data_passthru,
	.rpmb_send_request = ufs_rpmb_send_request_passthru,
	.rpmb_get_response = ufs_rpmb_get_response_passthru
};

#endif // USE_UFS_SCSI_PASS_THRU

EFI_STATUS rpmb_init(EFI_HANDLE disk_handle)
{
	g_initialized = TRUE;
	storage_rpmb_ops = &emmc_rpmb_ops_sdio;
	void *rpmb_dev;
	enum storage_type type;
	EFI_STATUS ret;

	ret = get_boot_device_type(&type);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get storage type ");
		return ret;
	}

	switch (type) {
#ifdef USE_UFS_SCSI_PASS_THRU
	case STORAGE_UFS:
		if ((*ufs_rpmb_ops_passthru.get_storage_protocol)((void **)(&rpmb_dev), disk_handle) == EFI_SUCCESS) {
			debug(L"init ufs rpmb pass through success");
			storage_rpmb_ops = &ufs_rpmb_ops_passthru;
			return EFI_SUCCESS;
		}
		error(L"init ufs rpmb using pass through failed");
		break;
#endif
	case STORAGE_EMMC:
		if ((*emmc_rpmb_ops_sdio.get_storage_protocol)((void **)(&rpmb_dev), disk_handle) == EFI_SUCCESS) {
			debug(L"init emmc rpmb sdio success");
			def_rpmb_dev_sdio = (EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev;
			return EFI_SUCCESS;
		}
		error(L"init emmc rpmb using sdio failed");

#ifdef USE_SD_PASS_THRU
		if ((*emmc_rpmb_ops_passthru.get_storage_protocol)((void **)(&rpmb_dev), disk_handle) == EFI_SUCCESS) {
			debug(L"init emmc rpmb pass through success");
			storage_rpmb_ops = &emmc_rpmb_ops_passthru;
			return EFI_SUCCESS;
		}
		error(L"init emmc rpmb using pass through failed");
#endif
		break;
	default:
		error(L"boot device not supported");
		return EFI_NOT_FOUND;

	}

	return EFI_NOT_FOUND;
}

EFI_STATUS get_storage_protocol(void **rpmb_dev, EFI_HANDLE disk_handle)
{
	if (!g_initialized)
		rpmb_init(disk_handle);

	return storage_rpmb_ops->get_storage_protocol(rpmb_dev, disk_handle);
}

EFI_STATUS program_rpmb_key(void *rpmb_dev, const void *key, RPMB_RESPONSE_RESULT *result)
{
	return storage_rpmb_ops->program_rpmb_key(rpmb_dev, key, result);
}

EFI_STATUS get_storage_partition_num(void *rpmb_dev, UINT8 *current_part)
{
	return storage_rpmb_ops->get_storage_partition_num(rpmb_dev, current_part);
}

EFI_STATUS storage_partition_switch(void *rpmb_dev, UINT8 part)
{
	return storage_rpmb_ops->storage_partition_switch(rpmb_dev, part);
}

EFI_STATUS get_rpmb_counter(void *rpmb_dev, UINT32 *write_counter, const void *key,
			RPMB_RESPONSE_RESULT *result)
{
	return storage_rpmb_ops->get_rpmb_counter(rpmb_dev, write_counter, key, result);
}

EFI_STATUS read_rpmb_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
			const void *key, RPMB_RESPONSE_RESULT *result)
{
	if (blk_addr >= RPMB_ADDR_BOUNDARY_SIZE) {
		error(L"Cannot access address greater than 256KB for physical read, addr is 0x%0x", blk_addr);
		*result = RPMB_RES_ADDRESS_FAILURE;
		return EFI_INVALID_PARAMETER;
	}

	return storage_rpmb_ops->read_rpmb_data(rpmb_dev, blk_count, blk_addr, buffer, key, result);
}

EFI_STATUS write_rpmb_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
			const void *key, RPMB_RESPONSE_RESULT *result)
{
	if (blk_addr >= RPMB_ADDR_BOUNDARY_SIZE) {
		error(L"Cannot access address greater than 256KB for physical write, addr is 0x%0x", blk_addr);
		*result = RPMB_RES_ADDRESS_FAILURE;
		return EFI_INVALID_PARAMETER;
	}

	return storage_rpmb_ops->write_rpmb_data(rpmb_dev, blk_count, blk_addr, buffer, key, result);
}

EFI_STATUS rpmb_send_request(void *rpmb_dev,
			rpmb_data_frame *data_frame, UINT8 count, BOOLEAN is_rel_write)
{
	UINT16 trusty_addr;

	if (BE16_TO_CPU_SWAP(data_frame->req_resp) == RPMB_REQUEST_AUTH_WRITE
		|| BE16_TO_CPU_SWAP(data_frame->req_resp) == RPMB_REQUEST_AUTH_READ) {
		trusty_addr = BE16_TO_CPU_SWAP(data_frame->address);
		if (trusty_addr < RPMB_ADDR_BOUNDARY_SIZE) {
			error(L"Cannot access address less than 256KB for trusty usage, addr is 0x%0x, cmd is 0x%0x",
                              trusty_addr, BE16_TO_CPU_SWAP(data_frame->req_resp));
			return EFI_INVALID_PARAMETER;
		}
	}

	return storage_rpmb_ops->rpmb_send_request(rpmb_dev, data_frame, count, is_rel_write);
}

EFI_STATUS rpmb_get_response(void *rpmb_dev,
			rpmb_data_frame *data_frame, UINT8 count)
{
	return storage_rpmb_ops->rpmb_get_response(rpmb_dev, data_frame, count);
}
