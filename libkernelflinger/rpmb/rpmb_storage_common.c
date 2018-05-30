/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Author: kwen <kui.wen@intel.com>
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

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "rpmb_storage_common.h"

/* length of the part of the frame used for HMAC computation */
#define HMAC_DATA_LEN \
	(sizeof(rpmb_data_frame) - offsetof(rpmb_data_frame, data))

INT32 rpmb_calc_hmac_sha256(rpmb_data_frame *frames, UINT8 blocks_cnt,
		const UINT8 key[], UINT32 key_size,
		UINT8 mac[], UINT32 mac_size)
{
	HMAC_CTX ctx;
	INT32 ret = 1;
	UINT32 i;

	HMAC_CTX_init(&ctx);
	ret = HMAC_Init_ex(&ctx, key, key_size, EVP_sha256(), NULL);
	if (ret == 0)
		goto out;

	for (i = 0; i < blocks_cnt; i++)
		HMAC_Update(&ctx, frames[i].data, HMAC_DATA_LEN);

	ret = HMAC_Final(&ctx, mac, &mac_size);
	if (ret == 0)
		goto out;
	if (mac_size != RPMB_MAC_SIZE) {
		ret = 0;
		goto out;
	}

out:
	HMAC_CTX_cleanup(&ctx);

	return ret;
}

INT32 rpmb_check_mac(const UINT8 *key, rpmb_data_frame *frames, UINT8 cnt)
{
	UINT8 mac[RPMB_MAC_SIZE];
	INT32 ret = 1;

	if (cnt == 0) {
		debug(L"RPMB 0 output frames");
		return 0;
	}

	ret = rpmb_calc_hmac_sha256(frames, cnt, key, RPMB_KEY_SIZE, mac, RPMB_MAC_SIZE);
	if (ret == 0) {
		debug(L"calculate hmac failed");
		return ret;
	}

	if (memcmp(mac, frames[cnt - 1].key_mac, RPMB_MAC_SIZE)) {
		debug(L"RPMB hmac mismatch resule MAC");
		return 0;
	}

	return ret;
}
