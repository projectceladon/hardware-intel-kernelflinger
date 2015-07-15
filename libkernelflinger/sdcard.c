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
#include "pci.h"

#define PCI_VENDOR_ID_INTEL 0x8086
#define PCI_DEVICE_ID_INTEL_BYT_SD 0x0f16

static pci_device_ids_t sd_supported[] = {
	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_BYT_SD},
};

static EFI_STATUS sdcard_erase_blocks(__attribute__((unused)) EFI_HANDLE handle,
				      __attribute__((unused)) EFI_BLOCK_IO * bio,
				      __attribute__((unused)) UINT64 start,
				      __attribute__((unused)) UINT64 end)
{
	return EFI_UNSUPPORTED;
}

/* SDCards do not support hardware level partitions */
static EFI_STATUS sdcard_check_logical_unit(__attribute__((unused)) EFI_DEVICE_PATH *p,
					    logical_unit_t log_unit)
{
	return log_unit == LOGICAL_UNIT_USER ? EFI_SUCCESS : EFI_UNSUPPORTED;
}

static BOOLEAN is_sdcard(EFI_DEVICE_PATH *p)
{
	EFI_STATUS rc;
	EFI_PCI_IO *pciio;
	pci_device_ids_t ids;
	UINTN i;

	rc = get_pci_device(p, &pciio);
	if (EFI_ERROR(rc))
		return FALSE;

	rc = get_pci_ids(pciio, &ids);
	if (EFI_ERROR(rc))
		return FALSE;

	for (i = 0; i < ARRAY_SIZE(sd_supported); i++) {
		if (ids.vendor_id == sd_supported[i].vendor_id &&
		    ids.device_id == sd_supported[i].device_id) {
			return TRUE;
		}
	}

	return FALSE;
}

struct storage STORAGE(STORAGE_SDCARD) = {
	.erase_blocks = sdcard_erase_blocks,
	.check_logical_unit = sdcard_check_logical_unit,
	.probe = is_sdcard,
	.name = L"SDCard"
};
