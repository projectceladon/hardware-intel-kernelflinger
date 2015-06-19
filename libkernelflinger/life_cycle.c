/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Author: Leo Sartre <leo.sartre@intel.com>
 *         Jeremy Compostella <jeremy.compostella@intel.com>
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

#include "life_cycle.h"
#include "protocol/LifeCycleProtocol.h"

EFI_STATUS life_cycle_is_enduser(BOOLEAN *enduser)
{
	EFI_STATUS ret;
	EFI_GUID guid = EFI_LIFE_CYCLE_STATE_PROTOCOL_GUID;
	EFI_LIFE_CYCLE_STATE_PROTOCOL *lf;
	EFI_LIFE_CYCLE_STATE state;

	ret = LibLocateProtocol(&guid, (void **)&lf);
	if (EFI_ERROR(ret)) {
		debug(L"Life Cycle Protocol is not supported");
		return ret;
	}

	if (lf->Revision != EFI_LIFE_CYCLE_STATE_PROTOCOL_REVISION1)
		return EFI_INCOMPATIBLE_VERSION;

	ret = uefi_call_wrapper(lf->GetLifeCycleState, 2, lf, &state);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get life cycle state");
		return ret;
	}

	*enduser = state == LC_STATE_ENDUSER;

	return EFI_SUCCESS;
}
