/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Authors: Anisha Kulkarni <anisha.dattatraya.kulkarni@intel.com>
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
#include <lib.h>
#include "Tcg2Protocol.h"
#include "Tpm2CommandLib.h"
#include "tpm2_security.h"

#define NV_INDEX_AT_PERM_ATTR		0x01500046
#define NV_INDEX_TRUSTYOS_SEED		0x01500047
#define NV_INDEX_VBMETA_KEY_HASH	0x01500048
#define NV_INDEX_FB_BL_POLICY		0x01500049

EFI_STATUS tpm2_create_nvindex(TPMI_RH_NV_INDEX nv_index,
			       TPMA_NV attributes,
			       UINT32 data_size)
{
	TPMI_RH_PROVISION auth_handle = TPM_RH_PLATFORM;
	TPM2B_NV_PUBLIC public_info;
	TPM2B_AUTH nv_auth;

	nv_auth.size = 0;
	public_info.size = sizeof(TPMI_RH_NV_INDEX)
			   + sizeof(TPMI_ALG_HASH) + sizeof(TPMA_NV)
			   + sizeof(UINT16) + sizeof(UINT16);

	public_info.nvPublic.nvIndex = nv_index;
	public_info.nvPublic.nameAlg = TPM_ALG_SHA256;
	public_info.nvPublic.attributes = attributes;
	public_info.nvPublic.authPolicy.size = 0;
	public_info.nvPublic.dataSize = data_size;

	return Tpm2NvDefineSpace(auth_handle, NULL,
				 &nv_auth, &public_info);
}

EFI_STATUS tpm2_write_nvindex(TPMI_RH_NV_INDEX nv_index,
			      UINT16 data_size, BYTE *data, UINT16 offset)
{
	EFI_STATUS ret = EFI_SUCCESS;
	TPMS_AUTH_COMMAND session_data = {0};
	TPMI_RH_NV_AUTH auth_handle = TPM_RH_PLATFORM;
	TPM2B_MAX_BUFFER nv_write_data;
	UINT16 left_size = data_size;
	UINT16 written_size = 0;
	UINT16 cur_size;

	session_data.sessionHandle = TPM_RS_PW;

	// Make sure the data buffer not overflow, maybe write data several times.
	// But if attributes->TPMA_NV_WRITEALL == 1, then write will failed.
	while (left_size > 0) {
		cur_size = (left_size > sizeof(nv_write_data.buffer)) ? sizeof(nv_write_data.buffer) : left_size;
		nv_write_data.size = cur_size;
		memcpy(nv_write_data.buffer, data + written_size, nv_write_data.size);
		ret = Tpm2NvWrite(auth_handle, nv_index,
			   &session_data, &nv_write_data, written_size + offset);
		if (EFI_ERROR(ret)) {
			error(L"Write TPM NV index failed, index: 0x%x, size: %d, written_size: %d, ret: %d",
					nv_index, nv_write_data.size, written_size, ret);
			break;
		}
		left_size -= cur_size;
		written_size += cur_size;
	}

	return ret;
}

EFI_STATUS tpm2_write_lock_nvindex(TPMI_RH_NV_INDEX nv_index)
{
	TPMS_AUTH_COMMAND session_data = {0};
	TPMI_RH_NV_AUTH auth_handle = TPM_RH_PLATFORM;

	session_data.sessionHandle = TPM_RS_PW;

	return Tpm2NvWriteLock(auth_handle, nv_index, &session_data);
}

EFI_STATUS tpm2_read_nvindex(TPMI_RH_NV_INDEX nv_index,
				UINT16 *data_size, BYTE *data, UINT16 offset)
{
	EFI_STATUS ret;
	TPMS_AUTH_COMMAND session_data;
	TPMI_RH_NV_AUTH auth_handle = TPM_RH_PLATFORM;
	TPM2B_MAX_BUFFER nv_read_data;
	UINT16 left_size = *data_size;
	UINT16 read_size = 0;
	UINT16 cur_size;

	session_data.sessionHandle  = TPM_RS_PW;
	session_data.nonce.size     = 0;
	*((UINT8 *) &(session_data.sessionAttributes)) = 0;
	session_data.hmac.size      = 0;

	while (left_size > 0) {
		cur_size = (left_size > sizeof(nv_read_data.buffer)) ? sizeof(nv_read_data.buffer) : left_size;
		nv_read_data.size = cur_size;

		ret = Tpm2NvRead(auth_handle, nv_index, &session_data, nv_read_data.size, read_size + offset, &nv_read_data);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Read NVIndex failed");
			return ret;
		}
		if (nv_read_data.size > cur_size) {
			// Overflow?
			error(L"Overflow after read the NVindex");
			return EFI_ABORTED;
		}
		if (nv_read_data.size == 0) {
			// No data read
			break;
		}
		memcpy(data + read_size, nv_read_data.buffer, nv_read_data.size);
		left_size -= nv_read_data.size;
		read_size += nv_read_data.size;
	}
	*data_size = read_size;

	return EFI_SUCCESS;
}

EFI_STATUS tpm2_read_lock_nvindex(TPMI_RH_NV_INDEX nv_index)
{
	TPMS_AUTH_COMMAND session_data;
	TPMI_RH_NV_AUTH auth_handle = TPM_RH_PLATFORM;

	session_data.sessionHandle  = TPM_RS_PW;
	session_data.nonce.size     = 0;
	*((UINT8 *)&(session_data.sessionAttributes)) = 0;
	session_data.hmac.size      = 0;

	return Tpm2NvReadLock(auth_handle, nv_index, &session_data);
}

static void set_attributes(TPMA_NV *attributes, BOOLEAN read_lock, BOOLEAN write_lock)
{
	attributes->TPMA_NV_PPREAD = 1;
	attributes->TPMA_NV_PPWRITE = 1;
	attributes->TPMA_NV_PLATFORMCREATE = 1;
	attributes->TPMA_NV_WRITEALL = 1;
	if (write_lock)
		attributes->TPMA_NV_WRITEDEFINE = 1;
	if (read_lock)
		attributes->TPMA_NV_READ_STCLEAR = 1;

#ifndef SOFT_FUSE
	attributes->TPMA_NV_POLICY_DELETE = 1;
#endif
}

static EFI_STATUS create_index_and_write_lock(TPM_NV_INDEX nv_index, TPMA_NV attributes,
					      UINT16 data_size, BYTE *data)
{
	EFI_STATUS ret;

	ret = tpm2_create_nvindex(nv_index, attributes, data_size);
	if (EFI_ERROR(ret)) {
		error(L"NV Index failed to create, index: 0x%x, size: %d, ret: %d", nv_index, data_size, ret);
		return ret;
	}

	ret = tpm2_write_nvindex(nv_index, data_size, data, 0);
	if (EFI_ERROR(ret)) {
		error(L"Write to NV Index failed, index: 0x%x, size: %d, ret: %d", nv_index, data_size, ret);
		return ret;
	}

	ret = tpm2_write_lock_nvindex(nv_index);
	if (EFI_ERROR(ret))
		error(L"Write lock to NV Index failed, index: 0x%x, ret: %d", nv_index, ret);

	return ret;
}

#ifndef USER
EFI_STATUS tpm2_show_index(UINT32 index, uint8_t *out_buffer, UINTN out_buffer_size)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;

	ret = Tpm2NvReadPublic(index, &NvPublic, &NvName);
	if (EFI_ERROR(ret)) {
		error(L"Read TPM NV index %x ret: %d", index, ret);
		return ret;
	}
	efi_snprintf(out_buffer, out_buffer_size, (CHAR8 *)
		"Read TPM NV index %x success, public size: %d, nvIndex: 0x%x, nameAlg: %d, attributes: 0x%x, data size: %d, name size: %d",
		index,
		NvPublic.size, NvPublic.nvPublic.nvIndex, NvPublic.nvPublic.nameAlg,
		NvPublic.nvPublic.attributes, NvPublic.nvPublic.dataSize, NvName.size);

	return EFI_SUCCESS;
}

EFI_STATUS tpm2_delete_index(UINT32 index)
{
	EFI_STATUS ret = Tpm2NvUndefineSpace(TPM_RH_PLATFORM, index, NULL);

	if (EFI_ERROR(ret))
		error(L"Delete TPM NV index failed, index: %x, ret: %d", index, ret);

	return ret;
}
#endif // USER

static void dump_data(
		__attribute__((unused)) UINT8 *data,
		__attribute__((unused)) UINT16 data_size)
{
#if 0  // Change to 1 for dump the data
	CHAR16 buf[2048 * 2 + 2];
	UINT16 i;

	for (i = 0; i < data_size && i < sizeof(buf) / 2 - 1; i++)
		SPrint(buf + i * 2, sizeof(buf) - i * 2, L"%02x", data[i]);
	debug(L"Data: %s", buf);
#endif
}

EFI_STATUS tpm2_fuse_trusty_seed(void)
{
	EFI_STATUS ret;
	TPM2B_DIGEST trusty_seed;
	TPMA_NV attributes = {0};
	UINT8 read_seed[TRUSTY_SEED_SIZE];
	UINT16 read_seed_size = TRUSTY_SEED_SIZE;

	ret = Tpm2GetRandom(TRUSTY_SEED_SIZE, &trusty_seed);
	if (EFI_ERROR(ret)) {
		error(L"Tpm2GetRandom failed");
		goto out;
	}
	dump_data(trusty_seed.buffer, TRUSTY_SEED_SIZE);

	set_attributes(&attributes, TRUE, TRUE);
	ret = create_index_and_write_lock(NV_INDEX_TRUSTYOS_SEED, attributes, TRUSTY_SEED_SIZE, trusty_seed.buffer);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to create and write trusty seed");
		goto out;
	}
	debug(L"Success create and write trusty seed");

	// Read the data again to verify it
	ret = tpm2_read_nvindex(NV_INDEX_TRUSTYOS_SEED, &read_seed_size, read_seed, 0);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Read trusty seed back failed just after write it");
		goto out;
	}
	if (memcmp(trusty_seed.buffer, read_seed, sizeof(read_seed))) {
		error(L"Security error! Read trusty seed back but verify failed!");
		dump_data(read_seed, TRUSTY_SEED_SIZE);
		ret = EFI_SECURITY_VIOLATION;
	}

out:
	// Always clear the memory
	// Maybe be optimized?
	memset(trusty_seed.buffer, 0, TRUSTY_SEED_SIZE);
	memset(read_seed, 0, TRUSTY_SEED_SIZE);
	return ret;
}

EFI_STATUS tpm2_read_trusty_seed(UINT8 seed[TRUSTY_SEED_SIZE])
{
	EFI_STATUS ret;
	EFI_STATUS ret2;
	UINT16 seed_size = TRUSTY_SEED_SIZE;

	ret = tpm2_read_nvindex(NV_INDEX_TRUSTYOS_SEED, &seed_size, seed, 0);
	ret2 = tpm2_read_lock_nvindex(NV_INDEX_TRUSTYOS_SEED);  // Lock anyway
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Read trusty seed failed");
		goto out;
	}
	if (EFI_ERROR(ret2)) {
		efi_perror(ret2, L"Security error! Set trusty seed read lock failed!");
		// die?
		ret = ret2;
		goto out;
	}
	if (seed_size != TRUSTY_SEED_SIZE) {
		efi_perror(ret, L"Read trusty seed failed, read %d bytes data, but expect %d",
				TRUSTY_SEED_SIZE, seed_size);
		ret = EFI_COMPROMISED_DATA;
		goto out;
	}
	dump_data(seed, TRUSTY_SEED_SIZE);
	return EFI_SUCCESS;

out:
	memset(seed, 0, TRUSTY_SEED_SIZE);
	return ret;
}

#ifdef BUILD_ANDROID_THINGS
EFI_STATUS tpm2_fuse_perm_attr(void *data, uint32_t size)
{
	EFI_STATUS ret;
	TPMA_NV attributes = {0};

	if (size > 2048) {
		error(L"AT Permanent attributes exceeds maximum size");
		return EFI_INVALID_PARAMETER;
	}

	set_attributes(&attributes, FALSE, TRUE);

	ret = create_index_and_write_lock(NV_INDEX_AT_PERM_ATTR, attributes, size, data);
	if (EFI_ERROR(ret))
		return ret;

	debug(L"AT Permanent attributes fused succesfully");
	return ret;
}
#endif

EFI_STATUS tpm2_fuse_vbmeta_key_hash(void *data, uint32_t size)
{
	EFI_STATUS ret;
	TPMA_NV attributes = {0};

	if (size != 32) {
		error(L"VBMETA Key Hash size is not 32 bytes");
		return EFI_INVALID_PARAMETER;
	}

	set_attributes(&attributes, FALSE, TRUE);

	ret = create_index_and_write_lock(NV_INDEX_VBMETA_KEY_HASH, attributes, size, data);
	if (EFI_ERROR(ret))
		return ret;

	debug(L"VBMETA Key Hash created successfully");
	return ret;
}

EFI_STATUS tpm2_fuse_bootloader_policy(void *data, uint32_t size)
{
	EFI_STATUS ret;
	TPMA_NV attributes = {0};
	TPMI_RH_NV_AUTH auth_handle = TPM_RH_PLATFORM;
	TPMS_AUTH_COMMAND session_data = {0};
	UINT64 set_bits = 0;

	if (size != sizeof(set_bits)) {
		error(L"bootloader policy size is not 8 bytes");
		return EFI_INVALID_PARAMETER;
	}

	session_data.sessionHandle = TPM_RS_PW;
	set_attributes(&attributes, FALSE, FALSE);
	attributes.TPMA_NV_BITS = 1;

	ret = tpm2_create_nvindex(NV_INDEX_FB_BL_POLICY, attributes, sizeof(set_bits));
	if (EFI_ERROR(ret) && (ret != EFI_ALREADY_STARTED))
		return ret;

	memcpy(&set_bits, data, size);
	ret = Tpm2NvSetBits(auth_handle, NV_INDEX_FB_BL_POLICY, &session_data, set_bits);
	if (EFI_ERROR(ret))
		return ret;

	debug(L"Bootloader policy created successfully");
	return ret;
}

EFI_STATUS tpm2_init(void)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;

	// Check the SEED nvindex
	ret = Tpm2NvReadPublic(NV_INDEX_TRUSTYOS_SEED, &NvPublic, &NvName);
	if (!EFI_ERROR(ret)) {
		// Success
		if (NvPublic.nvPublic.dataSize == TRUSTY_SEED_SIZE) {
			debug(L"Trusty seed already fused");
			return EFI_SUCCESS;
		}

		// Find it, but the data is empty wrong.
		error(L"Find trusty seed nv index, but the data is wrong");
		return EFI_COMPROMISED_DATA;
	}

	if (ret != EFI_NOT_FOUND) {
		efi_perror(ret, L"Read trusty seed index failed");
		return ret;
	}

	// Can't find it, try to init it now
	ret = tpm2_fuse_trusty_seed();
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to fuse trusty seed");

	return ret;
}

EFI_STATUS tpm2_end(void)
{
	// Maybe set read lock again
	tpm2_read_lock_nvindex(NV_INDEX_TRUSTYOS_SEED);

	return EFI_SUCCESS;
}
