/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jeremy Compostella <jeremy.compostella@intel.com>
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

#include <lib.h>

#include "adb_socket.h"
#include "service.h"

static EFI_STATUS reboot_service_open(const char *arg, void **context)
{
	CHAR16 *target = NULL;

	if (!arg || !context)
		return EFI_INVALID_PARAMETER;

	target = stra_to_str((CHAR8 *)arg);
	if (!target) {
		error(L"Failed to convert reboot target to CHAR16");
		return EFI_OUT_OF_RESOURCES;
	}

	/* Sanity check */
	if (name_to_boot_target(target) == UNKNOWN_TARGET) {
		error(L"Unknown boot target %s", target);
		FreePool(target);
		return EFI_INVALID_PARAMETER;
	}

	*context = target;

	return EFI_SUCCESS;
}

static EFI_STATUS reboot_service_ready(asock_t s)
{
	if (!asock_context(s))
		return EFI_INVALID_PARAMETER;

	adb_set_boot_target(name_to_boot_target(asock_context(s)));

	return EFI_SUCCESS;
}

static EFI_STATUS reboot_service_close(asock_t s)
{
	if (!asock_context(s))
		return EFI_INVALID_PARAMETER;

	FreePool(asock_context(s));

	return EFI_SUCCESS;
}

static EFI_STATUS reboot_service_okay(__attribute__((__unused__)) asock_t s)
{
	error(L"reboot_service does not support OKAY message");
	return EFI_UNSUPPORTED;
}

static EFI_STATUS reboot_service_read(__attribute__((__unused__)) asock_t s,
				      __attribute__((__unused__)) unsigned char *data,
				      __attribute__((__unused__)) UINT32 length)
{
	error(L"reboot_service does not support READ message");
	return EFI_UNSUPPORTED;
}

service_t reboot_service = {
	.name	 = "reboot",
	.open	 = reboot_service_open,
	.ready	 = reboot_service_ready,
	.close	 = reboot_service_close,
	.okay	 = reboot_service_okay,
	.read	 = reboot_service_read
};
