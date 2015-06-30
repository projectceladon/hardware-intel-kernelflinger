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
#include "watchdog.h"
#include "protocol/tco_protocol.h"

static EFI_GUID gEfiTcoResetProtocolGuid = EFI_TCO_RESET_PROTOCOL_GUID;

EFI_STATUS start_watchdog(UINT32 seconds)
{
        EFI_TCO_RESET_PROTOCOL *tco;
        EFI_STATUS ret;

        ret = LibLocateProtocol(&gEfiTcoResetProtocolGuid, (void **)&tco);
        if (EFI_ERROR(ret)) {
                if (ret == EFI_NOT_FOUND) {
                        debug(L"WARNING: watchdog disabled and not started");
                        return EFI_SUCCESS;
                }
                return ret;
        }

        if (seconds < TCO_MIN_TIMEOUT)
                seconds = TCO_MIN_TIMEOUT;

        debug(L"Starting watchdog for %d seconds", seconds);
        return uefi_call_wrapper(tco->EnableTcoReset, 1, &seconds);
}
