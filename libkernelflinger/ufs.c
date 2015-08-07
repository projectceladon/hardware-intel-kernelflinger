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
#include "protocol/ufs.h"
#include "protocol/ScsiPassThruExt.h"

static EFI_DEVICE_PATH *get_scsi_device_path(EFI_DEVICE_PATH *p)
{
	for (; !IsDevicePathEndType(p); p = NextDevicePathNode(p))
		if (DevicePathType(p) == MESSAGING_DEVICE_PATH
		    && DevicePathSubType(p) == MSG_SCSI_DP)
			return p;
	return NULL;
}

static EFI_STATUS ufs_erase_blocks(EFI_HANDLE handle, __attribute__((unused)) EFI_BLOCK_IO *bio, UINT64 start, UINT64 end)
{
	EFI_STATUS ret;
	EFI_GUID ScsiPassThruProtocolGuid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *scsi;
	EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET scsi_req;
	struct unmap_parameter unmap;
	struct command_descriptor_block cdb;
	EFI_HANDLE scsi_handle;
	EFI_DEVICE_PATH *dp = DevicePathFromHandle(handle);
	EFI_DEVICE_PATH *scsi_dp = dp;
	UINT8 target_bytes[TARGET_MAX_BYTES];
	UINT8 *target = target_bytes;
	UINT64 lun;

	if (!dp) {
		error(L"Failed to get device path from handle");
		return EFI_INVALID_PARAMETER;
	}
	ret = uefi_call_wrapper(BS->LocateDevicePath, 3, &ScsiPassThruProtocolGuid,
				&scsi_dp, &scsi_handle);
	if (EFI_ERROR(ret)) {
		error(L"Failed to locate SCSI root device");
		return ret;
	}

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, scsi_handle,
				&ScsiPassThruProtocolGuid, (void *)&scsi);
	if (EFI_ERROR(ret)) {
		error(L"failed to get scsi protocol");
		return ret;
	}

	scsi_dp = get_scsi_device_path(dp);
	if (!dp) {
		error(L"Failed to get SCSI device path");
		return EFI_NOT_FOUND;
	}

	ret = uefi_call_wrapper(scsi->GetTargetLun, 4, scsi, scsi_dp, (UINT8 **)&target, &lun);
	if (EFI_ERROR(ret)) {
		error(L"Failed to get LUN of current device");
		return ret;
	}

	ZeroMem(&scsi_req, sizeof(scsi_req));
	ZeroMem(&unmap, sizeof(unmap));
	ZeroMem(&cdb, sizeof(cdb));

	cdb.op_code = UFS_UNMAP;
	cdb.param_length = htobe16(sizeof(unmap));

	unmap.data_length = htobe16(sizeof(unmap) - sizeof(unmap.data_length));
	unmap.block_desc_length = htobe16(sizeof(unmap.block_desc));
	unmap.block_desc.lba = htobe64(start);
	unmap.block_desc.count = htobe32(end - start + 1);

	scsi_req.Timeout = BLOCK_TIMEOUT * (end - start + 1);
	scsi_req.OutDataBuffer = &unmap;
	scsi_req.Cdb = &cdb;
	scsi_req.OutTransferLength = sizeof(unmap);
	scsi_req.CdbLength = sizeof(cdb);
	scsi_req.DataDirection = EFI_EXT_SCSI_DATA_DIRECTION_WRITE;

	ret = uefi_call_wrapper(scsi->PassThru, 5, scsi, target, lun, &scsi_req, NULL);
	return ret;
}

/* This mapping of LUNs is hardcoded for now.  If a new board comes
 * with a different mapping, we will have to find a clean way to
 * identify it
 */
#define LUN_FACTORY 3
#define LUN_USER 0
#define LUN_UNKNOWN ((UINT64)-1)
static UINT64 log_unit_to_ufs_lun(logical_unit_t log_unit)
{
	switch(log_unit) {
	case LOGICAL_UNIT_USER:
		return LUN_USER;
	case LOGICAL_UNIT_FACTORY:
		return LUN_FACTORY;
	default:
		error(L"Unknown logical partition %d", log_unit);
		return LUN_UNKNOWN;
	}
}

static EFI_STATUS ufs_check_logical_unit(EFI_DEVICE_PATH *p, logical_unit_t log_unit)
{
	EFI_GUID ScsiPassThruProtocolGuid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *scsi;
	EFI_STATUS ret;
	UINT8 target_bytes[TARGET_MAX_BYTES];
	UINT8 *target = target_bytes;
	UINT64 target_lun;
	UINT64 lun;

	lun = log_unit_to_ufs_lun(log_unit);
	if (lun == LUN_UNKNOWN)
		return EFI_NOT_FOUND;

	ret = LibLocateProtocol(&ScsiPassThruProtocolGuid, (void **)&scsi);
	if (EFI_ERROR(ret)) {
		error(L"failed to get scsi protocol");
		return ret;
	}

	p = get_scsi_device_path(p);
	if (!p)
		return EFI_NOT_FOUND;

	ret = uefi_call_wrapper(scsi->GetTargetLun, 4, scsi, p, (UINT8 **)&target, &target_lun);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to get LUN for device");

	/* First byte is used to identify well known logical units like Boot or RPMB.
	 * Here we only want normal logical units so first byte must be 0
	 * Second byte contains the LUN number.
	 */
	if ((target_lun & 0xFF) != 0)
		return EFI_NOT_FOUND;
	target_lun = (target_lun >> 8) & 0xFF;

	return target_lun == lun ? EFI_SUCCESS : EFI_NOT_FOUND;
}

static BOOLEAN is_ufs(EFI_DEVICE_PATH *p)
{
	return get_scsi_device_path(p) != NULL;
}

struct storage STORAGE(STORAGE_UFS) = {
	.erase_blocks = ufs_erase_blocks,
	.check_logical_unit = ufs_check_logical_unit,
	.probe = is_ufs,
	.name = L"UFS"
};
