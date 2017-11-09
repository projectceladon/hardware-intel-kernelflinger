/******************************************************************************
 *
 * INTEL CONFIDENTIAL
 *
 * Copyright (c) 2017 Intel Corporation All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to
 * the source code (Material) are owned by Intel Corporation or its suppliers
 * or licensors. Title to the Material remains with Intel Corporation or its
 * suppliers and licensors. The Material contains trade secrets and proprietary
 * and confidential information of Intel or its suppliers and licensors. The
 * Material is protected by worldwide copyright and trade secret laws and
 * treaty provisions. No part of the Material may be used, copied, reproduced,
 * modified, published, uploaded, posted, transmitted, distributed, or
 * disclosed in any way without Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery
 * of the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be
 * express and approved by Intel in writing.
 *
 ******************************************************************************/

#include <lib.h>
#include <hecisupport.h>

/*
 * Send message with ack
 */
static EFI_STATUS heci_send_w_ack(uint8_t *Message, uint32_t Length, uint32_t *RecLength, uint8_t HostAddress, uint8_t DevAddr)
{
	EFI_STATUS ret = EFI_NOT_READY;

	EFI_GUID guid = HECI_PROTOCOL_GUID;
	EFI_HECI_PROTOCOL *protocol = NULL;

	ret = LibLocateProtocol(&guid, (void **)&protocol);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get heciprotocol");
		return ret;
	}

	ret = uefi_call_wrapper(protocol->SendwACK, 5, (UINT32 *)Message, Length, RecLength, HostAddress, DevAddr);
	debug(L"uefi_call_wrapper(SendwACK) =  %d", ret);

	return ret;
}

/*
 *  Determine SEC mode.
 */
static EFI_STATUS heci_get_sec_mode (unsigned *sec_mode)
{
	EFI_STATUS ret;

	EFI_GUID guid = HECI_PROTOCOL_GUID;
	EFI_HECI_PROTOCOL *protocol = NULL;

	ret = LibLocateProtocol(&guid, (void **)&protocol);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get heciprotocol");
		return ret;
	}

	ret = uefi_call_wrapper(protocol->GetSeCMode, 1, sec_mode);
	if (EFI_ERROR(ret)) {
		return ret;
	}

	debug(L"HECI sec_mode %X", *sec_mode);
	return ret;
}

/*
* Send End of Post
 */
EFI_STATUS heci_end_of_post(void)
{
	EFI_STATUS ret;

	uint32_t HeciSendLength;
	uint32_t HeciRecvLength;
	GEN_END_OF_POST *SendEOP;
	GEN_END_OF_POST_ACK __attribute__((__unused__)) *EOPResp;
	uint32_t SeCMode;
	uint8_t DataBuffer[sizeof(GEN_END_OF_POST_ACK)];

	debug(L"Start Send HECI Message: EndOfPost");
	ret = heci_get_sec_mode(&SeCMode);
	if (EFI_ERROR(ret) || (SeCMode != SEC_MODE_NORMAL)) {
		return ret;
	}
	debug(L"GetSeCMode successful");

	memset(DataBuffer, sizeof(DataBuffer), 0);

	SendEOP = (GEN_END_OF_POST*)DataBuffer;
	SendEOP->MKHIHeader.Fields.GroupId = EOP_GROUP_ID;
	SendEOP->MKHIHeader.Fields.Command = EOP_CMD_ID;

	debug(L"GEN_END_OF_POST size is %x", sizeof(GEN_END_OF_POST));
	HeciSendLength = sizeof(GEN_END_OF_POST);
	HeciRecvLength = sizeof(DataBuffer);

	ret = heci_send_w_ack (
	             DataBuffer,
	             HeciSendLength,
	             &HeciRecvLength,
	             BIOS_FIXED_HOST_ADDR,
	             PREBOOT_FIXED_SEC_ADDR);

	EOPResp = (GEN_END_OF_POST_ACK*)DataBuffer;

	debug(L"Group    =%08x", EOPResp->Header.Fields.GroupId);
	debug(L"Command  =%08x", EOPResp->Header.Fields.Command);
	debug(L"IsRespone=%08x", EOPResp->Header.Fields.IsResponse);
	debug(L"Result   =%08x", EOPResp->Header.Fields.Result);
	debug(L"RequestedActions   =%08x", EOPResp->Data.RequestedActions);

	return ret;
}

