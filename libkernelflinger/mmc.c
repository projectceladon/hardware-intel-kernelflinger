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
#include "sdio.h"

/* eMMC card address is enforced to 1 by the BIOS at eMMC
   initialization.  */
#define CARD_ADDRESS		1

static EFI_STATUS get_mmc_info(EFI_SD_HOST_IO_PROTOCOL *sdio,
			       UINTN *erase_grp_size, UINTN *timeout)
{
	EXT_CSD *ext_csd;
	void *rawbuffer;
	UINT32 status;
	EFI_STATUS ret;

	ret = alloc_aligned(&rawbuffer, (void **)&ext_csd, sizeof(*ext_csd),
			    sdio->HostCapability.BoundarySize);
	if (EFI_ERROR(ret))
		return ret;

	ret = uefi_call_wrapper(sdio->SendCommand, 9, sdio, SEND_EXT_CSD,
				CARD_ADDRESS << 16, InData, (void *)ext_csd,
				sizeof(EXT_CSD), ResponseR1, SDIO_DFLT_TIMEOUT, &status);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed get eMMC EXT_CSD");
		goto out;
	}

	/* Erase group size is 512Kbyte × HC_ERASE_GRP_SIZE so it's
	 * 1024 x HC_ERASE_GRP_SIZE in sector count timeout is 300ms x
	 * ERASE_TIMEOUT_MULT per erase group*/
	*erase_grp_size = 1024 * ext_csd->HC_ERASE_GRP_SIZE;
	*timeout = 300 * ext_csd->ERASE_TIMEOUT_MULT;

	debug(L"eMMC parameter: erase grp size %d sectors, timeout %d ms",
	      *erase_grp_size, *timeout);

out:
	FreePool(rawbuffer);
	return ret;
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

BOOLEAN is_emmc(EFI_DEVICE_PATH *p)
{
	while (!IsDevicePathEndType(p)) {
		if (DevicePathType(p) == HARDWARE_DEVICE_PATH
		    && DevicePathSubType(p) == HW_CONTROLLER_DP)
			return TRUE;
		p = NextDevicePathNode(p);
	}
	return FALSE;
}

static EFI_STATUS mmc_erase_blocks(EFI_HANDLE handle, EFI_BLOCK_IO *bio,
				   UINT64 start, UINT64 end)
{
	EFI_STATUS ret;
	EFI_SD_HOST_IO_PROTOCOL *sdio;
	EFI_DEVICE_PATH *dev_path;
	UINTN erase_grp_size, timeout;

	dev_path = DevicePathFromHandle(handle);
	if (!dev_path) {
		error(L"Failed to get device path");
		return EFI_UNSUPPORTED;
	}

	ret = sdio_get(dev_path, &sdio);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get SDIO protocol");
		return ret;
	}

	ret = get_mmc_info(sdio, &erase_grp_size, &timeout);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get erase group size");
		return ret;
	}

	return sdio_erase(sdio, bio, start, end,
			  CARD_ADDRESS, erase_grp_size, timeout, TRUE);
}

struct storage STORAGE(STORAGE_EMMC) = {
	.erase_blocks = mmc_erase_blocks,
	.check_logical_unit = mmc_check_logical_unit,
	.probe = is_emmc,
	.name = L"eMMC"
};
