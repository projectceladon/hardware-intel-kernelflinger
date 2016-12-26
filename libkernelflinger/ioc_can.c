/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Author: kui.wen@intel.com
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
#include <log.h>
#include <lib.h>
#include "ioc_can.h"
#include "protocol/ioc_uart_protocol.h"

EFI_STATUS notify_ioc_ready()
{
	EFI_STATUS ret;
	EFI_GUID guid = EFI_IOC_UART_PROTOCOL_GUID;
	IOC_UART_PROTOCOL *iocprotocol = NULL;

	ret = LibLocateProtocol(&guid, (void **)&iocprotocol);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get iocprotocol");
		return ret;
	}

	ret = uefi_call_wrapper(iocprotocol->NotifyIOCCMReady, 1, iocprotocol);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set CM ready to IOC");
		return ret;
	}

	return ret;
}

EFI_STATUS set_suppress_heart_beat_timeout(UINT32 timeout)
{
	EFI_STATUS ret;
	IOC_UART_PROTOCOL *iocprotocol = NULL;
	EFI_GUID guid = EFI_IOC_UART_PROTOCOL_GUID;

	ret = LibLocateProtocol(&guid, (void **)&iocprotocol);
	if (EFI_ERROR(ret)) {
		return ret;
	}

	ret = uefi_call_wrapper(iocprotocol->SetSuppressHeartBeatTimeout, 2, iocprotocol, timeout);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set suppress heart beat timeout");
		return ret;
	}

	return ret;
}