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

#ifndef _RPMB_H_
#define _RPMB_H_

#include <lib.h>

typedef enum {
	RPMB_RES_OK,
	RPMB_RES_GENERAL_FAILURE,
	RPMB_RES_AUTH_FAILURE,
	RPMB_RES_COUNTER_FAILURE,
	RPMB_RES_ADDRESS_FAILURE,
	RPMB_RES_WRITE_FAILURE,
	RPMB_RES_READ_FAILURE,
	RPMB_RES_NO_AUTH_KEY_PROGRAM,
	RPMB_RES_WRITE_COUNTER_EXPIRED = 0X80,
} RPMB_RESPONSE_RESULT;

#pragma pack(1)
typedef struct {
	UINT8 stuff[196];
	UINT8 key_mac[32];
	UINT8 data[256];
	UINT8 nonce[16];
	UINT32 write_counter;
	UINT16 address;
	UINT16 block_count;
	UINT16 result;
	UINT16 req_resp;
} rpmb_data_frame;
#pragma pack()

EFI_STATUS emmc_read_rpmb_data(UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT * result);
EFI_STATUS emmc_write_rpmb_data(UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result);
EFI_STATUS emmc_program_key(const void *key, RPMB_RESPONSE_RESULT *result);
EFI_STATUS emmc_get_counter(UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result);
EFI_STATUS get_emmc_sdio(EFI_SD_HOST_IO_PROTOCOL **sdio);
EFI_STATUS emmc_partition_switch(EFI_SD_HOST_IO_PROTOCOL *sdio, UINT8 part);
EFI_STATUS emmc_rpmb_send_request(EFI_SD_HOST_IO_PROTOCOL *sdio,
		rpmb_data_frame *data_frame, UINT8 count, BOOLEAN is_rel_write);
EFI_STATUS emmc_rpmb_get_response(EFI_SD_HOST_IO_PROTOCOL *sdio,
		rpmb_data_frame *data_frame, UINT8 count);
EFI_STATUS get_emmc_partition_num(EFI_SD_HOST_IO_PROTOCOL *sdio,
		UINT8 *current_part);

#endif	/* _RPMB_H_ */
