/*
 * copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Author: Jeremy Compostella <jeremy.compostella@intel.com>
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
#include "security.h"
#include "sl_vmm_api.h"

#define SL_GVB_DATA_VERSION 0

static const char SL_MAGIC[sizeof(((sl_version_t *)0)->magic)] = "SL";

static inline sl_ret_code_t sl_hypercall(UINT32 leaf, UINT32 b_val, UINT32 c, UINT32 d)
{
	int status;
#if __LP64__
	asm volatile("xchg{q}  %%rbx, %q1 \n\t"
		     "vmcall              \n\t"
		     "xchg{q}  %%rbx, %q1 \n\t"
		     : "=a" (status), "+g" (b_val), "+c" (c), "+d" (d)
		     : "0" (leaf), "m" (b_val)
		     : "memory");
#else
	asm volatile("push %%ebx     \n\t"
		     "mov  %1, %%ebx \n\t"
		     "vmcall         \n\t"
		     "mov  %%ebx,% 1 \n\t"
		     "pop  %%ebx     \n\t"
		     : "=a" (status), "+g" (b_val), "+c" (c), "+d" (d)
		     : "0" (leaf), "m" (b_val)
		     : "memory");
#endif
	return status;
}

EFI_STATUS silentlake_bind_root_of_trust(enum device_state state, X509 *verifier_cert)
{
	EFI_STATUS ret;
	sl_ret_code_t sl_ret;
	sl_gvb_data_t data = {
		.version    = SL_GVB_DATA_VERSION,
		.lock_state = state
	};
	UINT8 *temp_hash;
	UINT32 reg[4] = { 0, 0, 0, 0 };

	cpuid(SL_CMD_HSEC_GET_INFO, reg);
	sl_version_t vmm_v = { reg[0] >> 16, reg[0], { reg[1] >> 24, reg[1] >> 16 },
			       reg[1] >> 8, reg[1] };
	if (memcmp(SL_MAGIC, vmm_v.magic, sizeof(SL_MAGIC)))
		return EFI_UNSUPPORTED;

	debug(L"Silentlake vmm version: %c%c %d.%d", vmm_v.magic[0], vmm_v.magic[1],
	      vmm_v.major, vmm_v.minor);

	if (verifier_cert) {
		ret = compute_pub_key_hash(verifier_cert, &temp_hash,
					   (UINTN *)&data.key_size);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to compute rot bitstream for sl");
			return ret;
		}
		CopyMem(data.key_value, temp_hash, data.key_size);
	} else {
		debug(L"No certificate given, passing zero filled hash to sl");
		data.key_size = SHA256_DIGEST_LENGTH;
		memset(data.key_value, 0, data.key_size);
	}

	sl_ret = sl_hypercall(SL_CMD_HSEC_SET_GVB_INFO, 0,
			      (UINT32)((EFI_PHYSICAL_ADDRESS)&data),
			      (UINT32)sizeof(data));
	if (sl_ret != SL_SUCCESS) {
		error(L"Failed to set Silentlake properties, 0x%x", sl_ret);
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}
