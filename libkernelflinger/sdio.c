/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Author: Jérémy Compostella <jeremy.compostella@intel.com>
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
 * This file defines bootlogic data structures, try to keep it without
 * any external definitions in order to ease export of it.
 */

#include <lib.h>

#include "storage.h"
#include "protocol/Mmc.h"
#include "protocol/SdHostIo.h"
#include "sdio.h"

#define SDCARD_ERASE_GROUP_START	32
#define SDCARD_ERASE_GROUP_END		33
#define STATUS_ERROR_MASK		0xFCFFA080

EFI_STATUS sdio_get(EFI_DEVICE_PATH *p, EFI_SD_HOST_IO_PROTOCOL **sdio)
{
	EFI_STATUS ret;
	EFI_HANDLE sdio_handle;
	EFI_GUID guid = EFI_SD_HOST_IO_PROTOCOL_GUID;

	ret = uefi_call_wrapper(BS->LocateDevicePath, 3, &guid, &p, &sdio_handle);
	if (EFI_ERROR(ret))
		return ret;

	return uefi_call_wrapper(BS->HandleProtocol, 3, sdio_handle, &guid, (void **)sdio);
}

static EFI_STATUS sdio_erase_group(EFI_SD_HOST_IO_PROTOCOL *sdio, UINT64 start,
				   UINT64 end, UINTN timeout, UINT16 card_address,
				   BOOLEAN emmc)
{
	EFI_STATUS ret;
	UINT32 status;
	CARD_STATUS card_status;

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio,
				emmc ? ERASE_GROUP_START : SDCARD_ERASE_GROUP_START,
				start, NoData, NULL, 0, ResponseR1, SDIO_DFLT_TIMEOUT, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed set start erase");
		return ret;
	}
	if (status & STATUS_ERROR_MASK) {
		error(L"Failed set erase group start, status=0x%08x", status);
		return ret;
	}

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio,
				emmc ? ERASE_GROUP_END : SDCARD_ERASE_GROUP_END,
				end, NoData, NULL, 0, ResponseR1, SDIO_DFLT_TIMEOUT, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed set end erase");
		return ret;
	}
	if (status & STATUS_ERROR_MASK) {
		error(L"Failed set erase group end, status=0x%08x", status);
		return ret;
	}

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, ERASE, 0x80000000,
				NoData, NULL, 0, ResponseR1, timeout, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Erase command Failed");
		return ret;
	}
	if (status & STATUS_ERROR_MASK) {
		error(L"Erase Failed, status=0x%08x", status);
		return ret;
	}

	do {
		pause(1);
		ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, SEND_STATUS,
					card_address << 16, NoData, NULL, 0,
					ResponseR1, SDIO_DFLT_TIMEOUT,
					(UINT32 *)&card_status);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed get status");
			return ret;
		}
	} while (!card_status.READY_FOR_DATA);

	return ret;
}

EFI_STATUS sdio_erase(EFI_SD_HOST_IO_PROTOCOL *sdio, EFI_BLOCK_IO *bio,
		      UINT64 start, UINT64 end,
		      UINT16 card_address, UINTN erase_grp_size, UINTN erase_timeout,
		      BOOLEAN emmc)
{
	EFI_STATUS ret;
	UINT64 left;
	UINTN timeout;

	if (!sdio || !bio)
		return EFI_INVALID_PARAMETER;

	left = start % erase_grp_size;
	if (left) {
		ret = fill_zero(bio, start, start + erase_grp_size - left - 1);
		if (EFI_ERROR(ret)) {
			error(L"Failed to fill with zeros");
			return ret;
		}
		start += erase_grp_size - left;
	}

	left = (end + 1) % erase_grp_size;
	if (left) {
		ret = fill_zero(bio, end + 1 - left, end);
		if (EFI_ERROR(ret)) {
			error(L"Failed to fill with zeros");
			return ret;
		}
		end -= left;
	}

	timeout = erase_timeout * ((end + 1 - start) / erase_grp_size);
	return sdio_erase_group(sdio, start, end, timeout, card_address, emmc);
}
