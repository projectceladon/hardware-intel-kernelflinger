/*
 * Copyright (c) 2018, Intel Corporation
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

#ifndef MSG_VIRTUAL_MEDIA_DP
#define MSG_VIRTUAL_MEDIA_DP	0x20
#endif

static EFI_DEVICE_PATH *get_virtual_media_device_path(EFI_DEVICE_PATH *p)
{
	for (; !IsDevicePathEndType(p); p = NextDevicePathNode(p))
		if (DevicePathType(p) == MESSAGING_DEVICE_PATH
		    && DevicePathSubType(p) == MSG_VIRTUAL_MEDIA_DP)
			return p;
	return NULL;
}

static EFI_STATUS virtual_media_erase_blocks(EFI_HANDLE handle, __attribute__((unused)) EFI_BLOCK_IO *bio,
	__attribute__((unused))EFI_LBA start, __attribute__((unused))EFI_LBA end)
{
	EFI_STATUS ret;
	EFI_DEVICE_PATH *dp = DevicePathFromHandle(handle);

	if (!dp) {
		error(L"Failed to get device path from handle");
		return EFI_INVALID_PARAMETER;
	}

	ret = EFI_UNSUPPORTED;
	return ret;
}

static EFI_STATUS virtual_media_check_logical_unit(EFI_DEVICE_PATH *p, logical_unit_t log_unit)
{
	p = get_virtual_media_device_path(p);
	if (!p)
		return EFI_NOT_FOUND;

	if (log_unit != LOGICAL_UNIT_USER)
		return EFI_NOT_FOUND;

	return EFI_SUCCESS;

}

static BOOLEAN is_virtual_media(EFI_DEVICE_PATH *p)
{
	return get_virtual_media_device_path(p) != NULL;
}

struct storage STORAGE(STORAGE_VIRTUAL) = {
	.erase_blocks = virtual_media_erase_blocks,
	.check_logical_unit = virtual_media_check_logical_unit,
	.probe = is_virtual_media,
	.name = L"VIRTUAL_MEDIA"
};

