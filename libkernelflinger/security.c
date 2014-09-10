/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Matt Wood <matthew.d.wood@intel.com>
 * Author: Andrew Boie <andrew.p.boie@intel.com>
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

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "security.h"
#include "android.h"
#include "keystore.h"
#include "lib.h"

static VOID pr_error_openssl(void)
{
	unsigned long code;

	while ( (code = ERR_get_error()) )
		/* Sadly, can't print out the friendly error string  because
		 * all the BIO snprintf() functions are stubbed out due to the
		 * lack of most 8-bit string functions in gnu-efi. Look up the
		 * codes using 'openssl errstr' in a shell */
		debug(L"openssl error code %08X", code);
}


static EVP_PKEY *get_pkey(CONST UINT8 *cert, UINTN certsize)
{
        BIO *bio;
        X509 *x509 = NULL;
        EVP_PKEY *pkey = NULL;

        /* BIO is the OpenSSL input/output abstraction. Instantiate
         * one using a memory buffer containing the certificate */
        bio = BIO_new_mem_buf((void *)cert, certsize);
        if (!bio) {
                goto done;
        }

        /* Obtain an x509 structure from the DER cert data */
        x509 = d2i_X509_bio(bio, NULL);
        if (!x509) {
                goto done;
        }

        /* And finally get the public key out of the certificate */
        pkey = X509_get_pubkey(x509);
        if (!pkey) {
                goto done;
        }

        if (EVP_PKEY_RSA != EVP_PKEY_type(pkey->type)) {
                EVP_PKEY_free(pkey);
                pkey = NULL;
        }
done:
        BIO_free(bio);
        if (x509 != NULL)
                X509_free(x509);
        return pkey;
}


static EFI_STATUS get_hash_buffer(UINTN nid, VOID **hash, UINTN *hashsz)
{
        switch (nid) {
        case NID_sha1WithRSAEncryption:
                *hashsz = SHA_DIGEST_LENGTH;
                break;
        case NID_sha256WithRSAEncryption:
                *hashsz = SHA256_DIGEST_LENGTH;
                break;
        case NID_sha512WithRSAEncryption:
                *hashsz = SHA512_DIGEST_LENGTH;
                break;
        default:
                return EFI_UNSUPPORTED;
        }

        *hash = malloc(*hashsz);
        if (!*hash)
                return EFI_OUT_OF_RESOURCES;
        return EFI_SUCCESS;
}



static EFI_STATUS hash_keystore(struct keystore *ks,
                VOID **hash, UINTN *hashsz)
{
        int nid = ks->sig.id.nid;
        unsigned char *buf;
        EFI_STATUS ret;

        ret = get_hash_buffer(nid, hash, hashsz);
        if (EFI_ERROR(ret))
                return ret;

        switch (nid) {
        case NID_sha1WithRSAEncryption:
                buf = SHA1((const unsigned char *)ks->inner_data,
                                ks->inner_sz, *hash);
                break;
        case NID_sha256WithRSAEncryption:
                buf = SHA256((const unsigned char *)ks->inner_data,
                                ks->inner_sz, *hash);
                break;
        case NID_sha512WithRSAEncryption:
                buf = SHA512((const unsigned char *)ks->inner_data,
                                ks->inner_sz, *hash);
                break;
        default:
                buf = NULL;
        }

        if (buf == NULL) {
                free(*hash);
                return EFI_INVALID_PARAMETER;
        }
        return EFI_SUCCESS;
}


static EFI_STATUS hash_bootimage(struct boot_signature *bs,
                VOID *bootimage, UINTN imgsize, void **hash, UINTN *hashsz)
{
        int nid = bs->id.nid;
        EFI_STATUS eret;

        eret = get_hash_buffer(nid, hash, hashsz);
        if (EFI_ERROR(eret))
                return eret;

        /* Hash the bootimage + the AuthenticatedAttributes data */
        switch (nid) {
        case NID_sha1WithRSAEncryption:
        {
                SHA_CTX sha_ctx;

                if (1 != SHA1_Init(&sha_ctx))
                        break;

                SHA1_Update(&sha_ctx, bootimage, imgsize);
                SHA1_Update(&sha_ctx, bs->attributes.data,
                                bs->attributes.data_sz);
                SHA1_Final(*hash, &sha_ctx);
                OPENSSL_cleanse(&sha_ctx, sizeof(sha_ctx));

                return EFI_SUCCESS;
        }
        case NID_sha256WithRSAEncryption:
        {
                SHA256_CTX sha_ctx;

                if (1 != SHA256_Init(&sha_ctx))
                        break;

                SHA256_Update(&sha_ctx, bootimage, imgsize);
                SHA256_Update(&sha_ctx, bs->attributes.data,
                                bs->attributes.data_sz);
                SHA256_Final(*hash, &sha_ctx);
                OPENSSL_cleanse(&sha_ctx, sizeof(sha_ctx));

                return EFI_SUCCESS;
        }
        case NID_sha512WithRSAEncryption:
        {
                SHA512_CTX sha_ctx;

                if (1 != SHA512_Init(&sha_ctx))
                        break;

                SHA512_Update(&sha_ctx, bootimage, imgsize);
                SHA512_Update(&sha_ctx, bs->attributes.data,
                                bs->attributes.data_sz);
                SHA512_Final(*hash, &sha_ctx);
                OPENSSL_cleanse(&sha_ctx, sizeof(sha_ctx));

                return EFI_SUCCESS;
        }
        default:
                /* nothing to do */
                break;
        }
        free(*hash);
        return EFI_INVALID_PARAMETER;
}


static int get_rsa_verify_nid(int nid)
{
        switch (nid) {
        case NID_sha256WithRSAEncryption:
                return NID_sha256;
        case NID_sha512WithRSAEncryption:
                return NID_sha512;
        case NID_sha1WithRSAEncryption:
                return NID_sha1;
        default:
                return nid;
        }
}


static EFI_STATUS check_bootimage(CHAR8 *bootimage, UINTN imgsize,
                struct boot_signature *sig, struct keystore *ks)
{
        VOID *hash;
        UINTN hash_sz;
        EFI_STATUS ret;
        struct keybag *kb;

        ret = hash_bootimage(sig, bootimage, imgsize, &hash, &hash_sz);
        if (EFI_ERROR(ret))
                return EFI_ACCESS_DENIED;

        ret = EFI_ACCESS_DENIED;
        kb = ks->bag;
        while (kb) {
                int rsa_ret;

                if (sig->id.nid != kb->info.id.nid) {
                        debug(L"algorithm mismatch (signature %d, keystore %d)",
                                        sig->id.nid, kb->info.id.nid);
                        kb = kb->next;
                        continue;
                }

                rsa_ret = RSA_verify(get_rsa_verify_nid(sig->id.nid),
                                hash, hash_sz, sig->signature,
                                sig->signature_len, kb->info.key_material);
                if (rsa_ret == 1) {
                        ret = EFI_SUCCESS;
                        break;
                } else {
                        pr_error_openssl();
                }
                kb = kb->next;
        }

        free(hash);
        return ret;
}


static EFI_STATUS check_keystore(VOID *hash, UINTN hash_sz, struct keystore *ks,
                VOID *key, UINTN key_size)
{
        EFI_STATUS ret = EFI_ACCESS_DENIED;
        EVP_PKEY *pkey = NULL;
        UINTN rsa_ret;

        pkey = get_pkey(key, key_size);
        if (!pkey)
                goto out;

        rsa_ret = RSA_verify(get_rsa_verify_nid(ks->sig.id.nid),
                        hash, hash_sz,
                        ks->sig.signature, ks->sig.signature_len,
                        EVP_PKEY_get1_RSA(pkey));
        if (rsa_ret == 1)
                ret = EFI_SUCCESS;
        else
                pr_error_openssl();
out:
        EVP_PKEY_free(pkey);
        return ret;
}


EFI_STATUS verify_android_boot_image(IN VOID *bootimage, IN VOID *keystore,
                IN UINTN keystore_size, OUT CHAR16 *target)
{
        struct boot_signature *sig = NULL;
        struct keystore *ks = NULL;
        struct boot_img_hdr *hdr;
        UINT8 *signature_data;
        UINTN imgsize;
        EFI_STATUS ret;
        CHAR16 *target_tmp;

        if (!bootimage || !keystore || !target) {
                ret = EFI_INVALID_PARAMETER;
                goto out;
        }

        debug(L"decoding keystore data");
        ks = get_keystore(keystore, keystore_size);
        if (!ks) {
                debug(L"bad keystore");
                ret = EFI_INVALID_PARAMETER;
                goto out;
        }

        debug(L"get boot image header");
        hdr = get_bootimage_header(bootimage);
        if (!hdr) {
                debug(L"bad boot image data");
                ret = EFI_INVALID_PARAMETER;
                goto out;
        }

        debug(L"decoding boot image signature");
        imgsize = bootimage_size(hdr);
        signature_data = (UINT8*)bootimage + imgsize;
        sig = get_boot_signature(signature_data, BOOT_SIGNATURE_MAX_SIZE);
        if (!sig) {
                debug(L"boot image signature invalid or missing");
                ret = EFI_ACCESS_DENIED;
                goto out;
        }

        debug(L"verifying boot image");
        ret = check_bootimage(bootimage, imgsize, sig, ks);

        target_tmp = stra_to_str((CHAR8*)sig->attributes.target);
        StrNCpy(target, target_tmp, BOOT_TARGET_SIZE);
        FreePool(target_tmp);
out:
        free_keystore(ks);
        free_boot_signature(sig);

        return ret;
}

EFI_STATUS verify_android_keystore(IN VOID *keystore, IN UINTN keystore_size,
                IN VOID *key, IN UINTN key_size, OUT VOID *keystore_hash)
{
        struct keystore *ks = NULL;
        UINTN hash_sz;
        CHAR8 *hash = NULL;
        EFI_STATUS ret = EFI_INVALID_PARAMETER;

        if (!keystore || !key || !keystore_hash)
                goto out;

        memset(keystore_hash, 0xFF, KEYSTORE_HASH_SIZE);
        debug(L"decoding keystore data");
        ks = get_keystore(keystore, keystore_size);
        if (!ks)
                goto out;

        debug(L"hashing keystore data");
        ret = hash_keystore(ks, (VOID **)&hash, &hash_sz);
        if (EFI_ERROR(ret))
                goto out;

        debug(L"keystore hash is %02x%02x-%02x%02x-%02x%02x",
                        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]);

        memcpy(keystore_hash, hash, KEYSTORE_HASH_SIZE);

        debug(L"verifying keystore data");
        ret = check_keystore(hash, hash_sz, ks, key, key_size);
out:
        free(hash);
        free_keystore(ks);
        return ret;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */

