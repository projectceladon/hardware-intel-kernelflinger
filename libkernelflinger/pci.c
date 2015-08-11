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
#include "log.h"
#include "pci.h"
#include "protocol.h"

PCI_DEVICE_PATH* get_pci_device_path(EFI_DEVICE_PATH *p)
{
	while (!IsDevicePathEndType(p)) {
		if (DevicePathType(p) == HARDWARE_DEVICE_PATH
		    && DevicePathSubType(p) == HW_PCI_DP)
			return (PCI_DEVICE_PATH *)p;
		p = NextDevicePathNode(p);
	}
	return NULL;
}

EFI_STATUS get_pci_device(IN EFI_DEVICE_PATH *p, OUT EFI_PCI_IO **p_pciio)
{
	EFI_STATUS ret;
	EFI_HANDLE pci_handle;
	EFI_DEVICE_PATH *tmp_path = p;

	ret = locate_device_path(&PciIoProtocol, &tmp_path, &pci_handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to locate handle for EFI_PCI_IO_PROTOCOL");
		return ret;
	}

	ret = handle_protocol(pci_handle, &PciIoProtocol, (void**)p_pciio);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open PciIoProtocol");
		return ret;
	}

	return EFI_SUCCESS;
}

EFI_STATUS get_pci_ids(IN EFI_PCI_IO *pciio, OUT pci_device_ids_t *ids)
{
	return uefi_call_wrapper(pciio->Pci.Read, 5, pciio, EfiPciIoWidthUint16,
				 0, 2, ids);
}
