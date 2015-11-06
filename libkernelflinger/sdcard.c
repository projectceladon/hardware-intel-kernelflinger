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
#include "sdio.h"
#include "protocol/CardInfo.h"
#include "mmc.h"

static EFI_STATUS get_card_data(EFI_SD_HOST_IO_PROTOCOL *sdio,
				CARD_DATA **card_data)
{
	EFI_STATUS ret;
	struct _EFI_EMMC_CARD_INFO_PROTOCOL *info;
	EFI_GUID guid = EFI_CARD_INFO_PROTOCOL_GUID;

	ret = LibLocateProtocol(&guid, (void **)&info);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Unable to locate card info output protocol");
                return ret;
        }

	if (sdio != info->CardData->SdHostIo)
		return EFI_UNSUPPORTED;

	switch (info->CardData->CardType) {
	case SDMemoryCard:
	case SDMemoryCard2:
	case SDMemoryCard2High:
		*card_data = info->CardData;
		return EFI_SUCCESS;
	default:
		return EFI_UNSUPPORTED;
	}
}

static EFI_STATUS sdcard_erase_blocks(EFI_HANDLE handle, EFI_BLOCK_IO *bio,
				      UINT64 start, UINT64 end)
{
	EFI_STATUS ret;
	EFI_SD_HOST_IO_PROTOCOL *sdio;
	EFI_DEVICE_PATH *dev_path;
	CARD_DATA *card_data;

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

	ret = get_card_data(sdio, &card_data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get card data");
		return ret;
	}

	return sdio_erase(sdio, bio, start, end,
			  card_data->Address, 1, SDIO_DFLT_TIMEOUT, FALSE);
}

/* SDCards do not support hardware level partitions */
static EFI_STATUS sdcard_check_logical_unit(__attribute__((unused)) EFI_DEVICE_PATH *p,
					    logical_unit_t log_unit)
{
	return log_unit == LOGICAL_UNIT_USER ? EFI_SUCCESS : EFI_UNSUPPORTED;
}

static BOOLEAN is_sdcard(EFI_DEVICE_PATH *p)
{
	EFI_STATUS ret;
	EFI_SD_HOST_IO_PROTOCOL *sdio;

	ret = sdio_get(p, &sdio);
	if (EFI_ERROR(ret))
		return FALSE;

	return !is_emmc(p);
}

struct storage STORAGE(STORAGE_SDCARD) = {
	.erase_blocks = sdcard_erase_blocks,
	.check_logical_unit = sdcard_check_logical_unit,
	.probe = is_sdcard,
	.name = L"SDCard"
};
