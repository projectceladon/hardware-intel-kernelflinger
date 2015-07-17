/*
 * Copyright (c) 2015, Intel Corporation
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
 * This file defines bootlogic data structures, try to keep it without
 * any external definitions in order to ease export of it.
 */

#include <lib.h>
#include "storage.h"
#include "protocol/Mmc.h"
#include "protocol/SdHostIo.h"

#define SDIO_DFLT_TIMEOUT 3000
#define CARD_ADDRESS (1 << 16)

EFI_GUID gEfiSdHostIoProtocolGuid = EFI_SD_HOST_IO_PROTOCOL_GUID;

static EFI_STATUS secure_erase(EFI_SD_HOST_IO_PROTOCOL *sdio, UINT64 start, UINT64 end, UINTN timeout)
{
	CARD_STATUS status;
	EFI_STATUS ret;

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, ERASE_GROUP_START, start, NoData, NULL, 0, ResponseR1, SDIO_DFLT_TIMEOUT, (UINT32 *) &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed set start erase");
		return ret;
	}

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, ERASE_GROUP_END, end, NoData, NULL, 0, ResponseR1, SDIO_DFLT_TIMEOUT, (UINT32 *) &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed set end erase");
		return ret;
	}

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, ERASE, 0x80000000, NoData, NULL, 0, ResponseR1, timeout, (UINT32 *) &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Secure Erase Failed");
		return ret;
	}

	do {
		uefi_call_wrapper(BS->Stall, 1, 100000);
		ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, SEND_STATUS, CARD_ADDRESS, NoData, NULL, 0, ResponseR1, SDIO_DFLT_TIMEOUT, (UINT32 *) &status);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"failed get status");
			return ret;
		}
	} while (!status.READY_FOR_DATA);
	return ret;
}

static EFI_STATUS get_mmc_info(EFI_SD_HOST_IO_PROTOCOL *sdio, UINTN *erase_grp_size, UINTN *timeout)
{
	EXT_CSD *ext_csd;
	void *rawbuffer;
	UINTN offset;
	UINT32 status;
	EFI_STATUS ret;

	/* ext_csd pointer must be aligned to a multiple of sdio->HostCapability.BoundarySize
	 * allocate twice the needed size, and compute the offset to get an aligned buffer
	 */
	rawbuffer = AllocateZeroPool(2 * sdio->HostCapability.BoundarySize);
	if (!rawbuffer)
		return EFI_OUT_OF_RESOURCES;

	offset = (UINTN) rawbuffer & (sdio->HostCapability.BoundarySize - 1);
	offset = sdio->HostCapability.BoundarySize - offset;
	ext_csd = (EXT_CSD *) ((CHAR8 *)rawbuffer + offset);

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, SEND_EXT_CSD, CARD_ADDRESS, InData, (void *)ext_csd, sizeof(EXT_CSD), ResponseR1, SDIO_DFLT_TIMEOUT, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"failed get ext_csd");
		goto out;
	}

	/* Erase group size is 512Kbyte × HC_ERASE_GRP_SIZE
	 * so it's 1024 x HC_ERASE_GRP_SIZE in sector count
	 * timeout is 300ms x ERASE_TIMEOUT_MULT per erase group*/
	*erase_grp_size = 1024 * ext_csd->HC_ERASE_GRP_SIZE;
	*timeout = 300 * ext_csd->ERASE_TIMEOUT_MULT;

	debug(L"eMMC parameter: erase grp size %d sectors, timeout %d ms", *erase_grp_size, *timeout);

out:
	FreePool(rawbuffer);
	return ret;
}

static EFI_STATUS mmc_erase_blocks(__attribute__((unused)) EFI_HANDLE handle, EFI_BLOCK_IO *bio, UINT64 start, UINT64 end)
{
	EFI_SD_HOST_IO_PROTOCOL *sdio;
	EFI_STATUS ret;
	UINTN erase_grp_size;
	UINTN timeout;
	UINT64 reminder;

	/* check if we can use secure erase command */
	ret = LibLocateProtocol(&gEfiSdHostIoProtocolGuid, (void **)&sdio);
	if (EFI_ERROR(ret)) {
		debug(L"failed to get sdio protocol");
		return ret;
	}
	ret = get_mmc_info(sdio, &erase_grp_size, &timeout);
	if (EFI_ERROR(ret)) {
		debug(L"failed to get mmc parameter");
		return ret;
	}
	if ((end - start + 1) < erase_grp_size)
		return ret;

	reminder = start % erase_grp_size;
	if (reminder) {
		ret = fill_zero(bio, start, start + erase_grp_size - reminder - 1);
		if (EFI_ERROR(ret)) {
			error(L"failed to fill with zeros");
			return ret;
		}
		start += erase_grp_size - reminder;
	}

	reminder = (end + 1) % erase_grp_size;
	if (reminder) {
		ret = fill_zero(bio, end + 1 - reminder, end);
		if (EFI_ERROR(ret)) {
			error(L"failed to fill with zeros");
			return ret;
		}
		end -= reminder;
	}
	timeout = timeout * ((end + 1 - start) / erase_grp_size);
	return secure_erase(sdio, start, end, timeout);
}

/* This mapping of GPPs is hardcoded for now.  If a new board comes
 * with a different mapping, we will have to find a clean way to
 * identify it
 */
#define CONTROLLER_EMMC_USER_PARTITION 0
#define CONTROLLER_EMMC_GPP1 4
#define CONTROLLER_UNKNOWN ((UINT32)-1)
static UINT32 log_unit_to_mmc_ctrl(logical_unit_t log_unit)
{
	switch(log_unit) {
	case LOGICAL_UNIT_USER:
		return CONTROLLER_EMMC_USER_PARTITION;
	case LOGICAL_UNIT_FACTORY:
		return CONTROLLER_EMMC_GPP1;
	default:
		error(L"Unknown logical unit %d", log_unit);
		return CONTROLLER_UNKNOWN;
	}
}

static EFI_STATUS mmc_check_logical_unit(EFI_DEVICE_PATH *p, logical_unit_t log_unit)
{
	UINT32 ctrl = log_unit_to_mmc_ctrl(log_unit);

	if (ctrl == CONTROLLER_UNKNOWN)
		return EFI_NOT_FOUND;

	while (!IsDevicePathEndType(p)) {
		if (DevicePathType(p) == HARDWARE_DEVICE_PATH
		    && DevicePathSubType(p) == HW_CONTROLLER_DP
		    && ((CONTROLLER_DEVICE_PATH *)p)->Controller == ctrl)
			return EFI_SUCCESS;
		/* get the next device path node */
		p = NextDevicePathNode(p);
	}

	return EFI_NOT_FOUND;
}

static BOOLEAN is_emmc(EFI_DEVICE_PATH *p)
{
	while (!IsDevicePathEndType(p)) {
		if (DevicePathType(p) == HARDWARE_DEVICE_PATH
		    && DevicePathSubType(p) == HW_CONTROLLER_DP)
			return TRUE;
		p = NextDevicePathNode(p);
	}
	return FALSE;
}

struct storage STORAGE(STORAGE_EMMC) = {
	.erase_blocks = mmc_erase_blocks,
	.check_logical_unit = mmc_check_logical_unit,
	.probe = is_emmc,
	.name = L"eMMC"
};
