/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Jeremy Compostella <jeremy.compostella@intel.com>
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

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include <lib.h>

#include "protocol/Afws_general_heci_agent.h"
#include "protocol/Afws_keymaster_heci_agent.h"
#include "protocol/Heci.h"
#include "protocol/MkhiMsgs.h"

#include "txe.h"

typedef struct pcr_extend_request {
        MKHI_MESSAGE_HEADER hdr;
        ANDROID_HECI_KEYMASTER_CMD_PCR_EXTEND_REQUEST pcr_req;
} pcr_extend_request_t;

typedef struct pcr_extend_response {
        MKHI_MESSAGE_HEADER hdr;
        ANDROID_HECI_KEYMASTER_CMD_PCR_EXTEND_RESPONSE pcr_rsp;
} pcr_extend_response_t;

EFI_STATUS txe_bind_root_of_trust(UINT8 *hash, UINTN hash_size)
{
        EFI_STATUS ret;
        EFI_GUID heci_protocol_guid = HECI_PROTOCOL_GUID;
        EFI_HECI_PROTOCOL *heci;
        pcr_extend_request_t req;
        pcr_extend_response_t rsp;
        UINT32 length;

        if (!hash || hash_size != ANDROID_HECI_KEYMASTER_PCR_EXTEND_MESSAGE_SIZE)
                return EFI_INVALID_PARAMETER;

        ret = LibLocateProtocol(&heci_protocol_guid, (void **)&heci);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to access to the HECI protocol");
                return ret;
        }

        memset(&req, 0, sizeof(req));
        req.hdr.Fields.GroupId = MKHI_AFWS_GROUP_ID;
        req.pcr_req.Header.CmdClass = ANDROID_HECI_AGENT_CMD_CLASS_KEY_MASTER;
        req.pcr_req.Header.CmdId = ANDROID_HECI_KEYMASTER_CMD_ID_PCR_EXTEND;
        req.pcr_req.Header.InputSize = sizeof(req.pcr_req);
        memcpy(&req.pcr_req.Message, hash, hash_size);

        ret = uefi_call_wrapper(heci->SendMsg, 4, (UINT32 *)&req, sizeof(req),
                                BIOS_FIXED_HOST_ADDR, HECI_CORE_MESSAGE_ADDR);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to send the PCR extend request");
                return ret;
        }

        memset(&rsp, 0, sizeof(rsp));
        length = sizeof(rsp);
        ret = uefi_call_wrapper(heci->ReadMsg, 3, BLOCKING, (UINT32 *)&rsp, &length);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to get the PCR extend response");
                return ret;
        }

	if (rsp.hdr.Fields.Result != SEC_SUCCESS) {
		error(L"Invalid MKHI response: %d", rsp.hdr.Fields.Result);
		return EFI_UNSUPPORTED;
	}

	if (length != sizeof(rsp)) {
                error(L"Invalid PCR extend response length");
                return EFI_UNSUPPORTED;
        }

        if (rsp.pcr_rsp.Header.ResponseCode != ANDROID_HECI_AGENT_RESPONSE_CODE_SUCCESS) {
                error(L"PCR extend request failed: %d", rsp.pcr_rsp.Header.ResponseCode);
                return EFI_UNSUPPORTED;
        }

        return EFI_SUCCESS;
}
