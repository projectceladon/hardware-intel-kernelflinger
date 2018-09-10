/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Author: Haoyu Tang <haoyu.tang@intel.com>
 *         Chen, ZhiminX <zhiminx.chen@intel.com>
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
#include <efiapi.h>

#include "acpi.h"
#include "firststage_mount.h"
#include "firststage_mount_cfg.h"
#include "lib.h"
#include "protocol/AcpiTableProtocol.h"
#include "storage.h"

static CHAR8 csum(void *base, UINTN n)
{
	CHAR8 *p;
	CHAR8 sum;
	UINTN bytesDone;

	p = (CHAR8 *)base;

	sum = 0;
	for (bytesDone = 0; bytesDone < n; bytesDone++) {
		sum += *p;
		p++;
	}

	return sum;
}

EFI_STATUS install_firststage_mount_ssdt(enum boot_target target)
{
	EFI_STATUS ret;
	UINTN ssdt_len;
	UINTN TableKey;

	if ((target == NORMAL_BOOT) || (target == CHARGER)
		|| (target == ESP_BOOTIMAGE) || (target == MEMORY)) {
		debug(L"Install firststage_mount_ssdt, target=%d", target);
		ssdt_len = sizeof(AmlCode);

		ret = install_acpi_table(AmlCode, ssdt_len, &TableKey);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to install ssdt.");
			return ret;
		}
	}

	debug(L"firststage_mount_ssdt not installed, target=%d", target);
	return EFI_SUCCESS;
}
