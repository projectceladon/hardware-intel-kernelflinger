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
#include "ufs.h"
#include "protocol/ufs.h"
#include "protocol/ScsiPassThruExt.h"

EFI_STATUS ufs_erase_blocks(EFI_HANDLE handle, __attribute__((unused)) EFI_BLOCK_IO *bio, UINT64 start, UINT64 end)
{
	EFI_STATUS ret;
	EFI_GUID ScsiPassThruProtocolGuid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *scsi;
	EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET scsi_req;
	struct unmap_parameter unmap;
	struct command_descriptor_block cdb;

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, handle,
				&ScsiPassThruProtocolGuid, (void *)&scsi);
	if (EFI_ERROR(ret)) {
		debug(L"failed to get scsi protocol");
		return ret;
	}

	ZeroMem(&scsi_req, sizeof(scsi_req));
	ZeroMem(&unmap, sizeof(unmap));
	ZeroMem(&cdb, sizeof(cdb));

	cdb.op_code = UFS_UNMAP;
	cdb.param_length = sizeof(unmap);

	unmap.data_length = htobe16(sizeof(unmap) - sizeof(unmap.data_length));
	unmap.block_desc_length = htobe16(sizeof(unmap.block_desc));
	unmap.block_desc.lba = htobe64(start);
	unmap.block_desc.count = htobe32(end - start);

	scsi_req.Timeout = BLOCK_TIMEOUT * (end - start);
	scsi_req.OutDataBuffer = &unmap;
	scsi_req.Cdb = &cdb;
	scsi_req.OutTransferLength = sizeof(unmap);
	scsi_req.CdbLength = sizeof(cdb);
	scsi_req.DataDirection = EFI_EXT_SCSI_DATA_DIRECTION_READ;

	ret = uefi_call_wrapper(scsi->PassThru, 5, scsi, 0, 0, &scsi_req, NULL);
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

EFI_STATUS ufs_check_logical_unit(EFI_DEVICE_PATH *p, logical_unit_t log_unit)
{
	EFI_GUID ScsiPassThruProtocolGuid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *scsi;
	EFI_STATUS ret;
	UINT8 target[TARGET_MAX_BYTES];
	UINT64 target_lun;
	UINT64 lun;

	lun = log_unit_to_ufs_lun(log_unit);
	if (lun == LUN_UNKNOWN)
		return EFI_NOT_FOUND;

	ret = LibLocateProtocol(&ScsiPassThruProtocolGuid, (void **)&scsi);
	if (EFI_ERROR(ret)) {
		debug(L"failed to get scsi protocol");
		return ret;
	}
	uefi_call_wrapper(scsi->GetTargetLun, 4, scsi, p, (UINT8 **)&target, &target_lun);

	return target_lun == lun ? EFI_SUCCESS : EFI_NOT_FOUND;
}

BOOLEAN is_ufs(EFI_DEVICE_PATH *p)
{
	while (!IsDevicePathEndType(p)) {
		if (DevicePathType(p) == MESSAGING_DEVICE_PATH
		    && DevicePathSubType(p) == MSG_SCSI_DP)
			return TRUE;
		p = NextDevicePathNode(p);
	}
	return FALSE;
}

struct storage storage_ufs = {
	ufs_erase_blocks,
	ufs_check_logical_unit,
};
