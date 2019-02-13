/*
 * Copyright (c) 2019, Intel Corporation
 * All rights reserved.
 *
 * Author: Genshen Li <genshen.li@intel.com>
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
#include "security.h"
#include "security_vb2.h"

EFI_STATUS rot_pub_key_sha256(IN VBDATA *vb_data,
                        OUT UINT8 **hash_p)
{
	EFI_STATUS ret = EFI_SUCCESS;
	const uint8_t *vbmeta_pub_key;
	UINTN vbmeta_pub_key_len;

	if (vb_data && hash_p) {
		ret = avb_vbmeta_image_verify(vb_data->vbmeta_images[0].vbmeta_data,
			vb_data->vbmeta_images[0].vbmeta_size,
			&vbmeta_pub_key,
			&vbmeta_pub_key_len);

		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to get the vbmeta_pub_key");
			return ret;
		}

		ret = raw_pub_key_sha256(vbmeta_pub_key, vbmeta_pub_key_len, hash_p);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"Failed to compute key hash");
	} else
		ret = EFI_INVALID_PARAMETER;

	return ret;
}
