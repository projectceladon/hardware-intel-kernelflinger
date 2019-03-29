/*
 * Copyright (C) 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <aes_gcm.h>
#include "log.h"

static void dump(UINT8 *p, int size)
{
	int i;

	(VOID)p;

	for(i=0; i<size; i++)
		debug(L"%02x ", p[i]);
}
/**
 * aes_256_gcm_encrypt - Helper function for encrypt.
 * @key:          Key object.
 * @iv:           Initialization vector to use for Cipher Block Chaining.
 * @iv_size:      Number of bytes iv @iv.
 * @aad:          AAD to use for infomation.
 * @aad_size:     Number of bytes aad @aad.
 * @plain:        Data to encrypt, it is only plaintext.
 * @plain_size:   Number of bytes in @plain.
 * @out:          Data out, it contains ciphertext and tag.
 * @out_size:     Number of bytes out @out.
 *
 * Return: 0 on success, < 0 if an error was detected.
 */
int aes_256_gcm_encrypt(const struct gcm_key *key,
			const void *iv, size_t iv_size,
			const void *aad, size_t aad_size,
			const void *plain, size_t plain_size,
			void *out, size_t *out_size)
{
	int rc = AES_GCM_ERR_GENERIC;
	EVP_CIPHER_CTX *ctx;
	int out_len, fin_len;
	UINT8 *tag;

	if ((key == NULL) || (iv == NULL) || (iv_size == 0) ||
		(plain == NULL) || (out == NULL) || (out_size == NULL)) {
		error(L"invalid args!\n");
		return AES_GCM_ERR_GENERIC;
	}

	/*creat cipher ctx*/
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		error(L"fail to create CTX....\n");
		goto exit;
	}

	/* Set cipher, key and iv */
	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
					(unsigned char *)key, (unsigned char *)iv)) {
		error(L"CipherInit fail\n");
		goto exit;
	}

	/* set iv length.*/
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL)) {
		error(L"set iv length fail\n");
		goto exit;
	}

	/* set to aad info.*/
	if (NULL != aad) {
		if (!EVP_EncryptUpdate(ctx, NULL, &out_len, (UINT8 *)aad, aad_size)) {
			error(L"set aad info fail\n");
			goto exit;
		}
	}

	/* Encrypt plaintext */
	if (!EVP_EncryptUpdate(ctx, out, &out_len, plain, plain_size)) {
		error(L"Encrypt plain text fail.\n");
		goto exit;
	}

	debug(L"cipher len partial is %08x\n", out_len);

	if (!EVP_EncryptFinal_ex(ctx, out + out_len, &fin_len)) {
		error(L"EncryptFinal fail.\n");
		goto exit;
	}
        out_len += fin_len;
        debug(L"cipher_len final is %08x\n", out_len);
	debug(L"cipher text is as follows:\n");
	dump(out, out_len);
	tag = out + out_len;
	/*get TAG*/
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(struct gcm_tag), tag)) {
		error(L"get TAG fail.\n");
		rc = AES_GCM_ERR_AUTH_FAILED;
		goto exit;
	}

	out_len += sizeof(struct gcm_tag);
	*out_size = out_len;

	debug(L"tag text is as follows:\n");
        dump(tag, sizeof(struct gcm_tag));
	rc = AES_GCM_NO_ERROR;

exit:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return rc;
}

/**
 * aes_256_gcm_decrypt - Helper function for decrypt.
 * @key:          Key object.
 * @iv:           Initialization vector to use for Cipher Block Chaining.
 * @iv_size:      Number of bytes iv @iv.
 * @aad:          AAD to use for infomation.
 * @aad_size:     Number of bytes aad @aad.
 * @cipher:       Data in to decrypt, it contains ciphertext and tag.
 * @cipher_size:  Number of bytes in @cipher.
 * @out:          Data out, it is only plaintext.
 * @out_size:     Number of bytes out @out.
 *
 * Return: 0 on success, < 0 if an error was detected.
 */
int aes_256_gcm_decrypt(const struct gcm_key *key,
			const void *iv, size_t iv_size,
			const void *aad, size_t aad_size,
			const void *cipher, size_t cipher_size,
			void *out, size_t *out_size)
{
	int rc = AES_GCM_ERR_GENERIC;
	EVP_CIPHER_CTX *ctx;
	int out_len, data_len;
	UINT8 *tag;

	if ((key == NULL) || (iv == NULL) || (iv_size == 0) ||
		(cipher == NULL) || (out == NULL) || (out_size == NULL)) {
		error(L"invalid args!\n");
		return AES_GCM_ERR_GENERIC;
	}

	/*creat cipher ctx*/
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		error(L"fail to create CTX....\n");
		goto exit;
	}

	/* Set cipher, key and iv */
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
					(unsigned char *)key, (unsigned char *)iv)) {
		error(L"CipherInit fail\n");
		goto exit;
	}

	/* set iv length.*/
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL)) {
		error(L"set iv length fail\n");
		goto exit;
	}

	/* set to aad info.*/
	if (NULL != aad) {
		if (!EVP_DecryptUpdate(ctx, NULL, &out_len, (uint8_t *)aad, aad_size)) {
			error(L"set aad info fail\n");
			goto exit;
		}
	}

	/* Decrypt plaintext */
	data_len = cipher_size - sizeof(struct gcm_tag);
	if (!EVP_DecryptUpdate(ctx, out, &out_len, cipher, data_len)) {
		error(L"Decrypt cipher text fail.\n");
		goto exit;
	}

	debug(L"decrypt partial output:\n");
	dump((UINT8 *)out, out_len);
	tag = (UINT8 *)cipher + data_len;
	/*set TAG*/
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(struct gcm_tag), tag)) {
		error(L"set TAG fail.\n");
		goto exit;
	}

	/* Check TAG */
	if (!EVP_DecryptFinal_ex(ctx, out+out_len, &data_len)) {
		error(L"fail to check TAG.\n");
		rc = AES_GCM_ERR_AUTH_FAILED;
		goto exit;
	}

	out_len += data_len;
	debug(L"decrypt final output:\n");
	dump((UINT8 *)out, out_len);

	*out_size = out_len;

	rc = AES_GCM_NO_ERROR;

exit:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return rc;
}
