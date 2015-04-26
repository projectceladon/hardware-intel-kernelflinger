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
 */

#include <efi.h>
#include <efilib.h>
#include <log.h>
#include "storage.h"
#include "mmc.h"
#include "ufs.h"

static struct storage *storage;

static EFI_STATUS identify_storage(EFI_DEVICE_PATH *device_path)
{
	debug(L"Identifying storage");
	if (!device_path)
		goto out;

	if (is_emmc(device_path)) {
		debug(L"eMMC storage identified");
		storage = &storage_emmc;
		return EFI_SUCCESS;
	}

	if (is_ufs(device_path)) {
		debug(L"UFS storage identified");
		storage = &storage_ufs;
		return EFI_SUCCESS;
	}

out:
	error(L"Unsupported storage");
	return EFI_UNSUPPORTED;
}

EFI_STATUS storage_check_logical_unit(EFI_DEVICE_PATH *p, logical_unit_t log_unit)
{
	if (!storage && EFI_ERROR(identify_storage(p)))
		return EFI_UNSUPPORTED;

	return storage->check_logical_unit(p, log_unit);
}

EFI_STATUS storage_erase_blocks(EFI_HANDLE handle, EFI_BLOCK_IO *bio, UINT64 start, UINT64 end)
{
	if (!storage &&
	    EFI_ERROR(identify_storage(DevicePathFromHandle(handle))))
		return EFI_UNSUPPORTED;

	debug(L"Erase lba %ld -> %ld", start, end);
	return storage->erase_blocks(handle, bio, start, end);
}
