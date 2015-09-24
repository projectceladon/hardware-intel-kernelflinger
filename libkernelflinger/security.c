/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Matt Wood <matthew.d.wood@intel.com>
 * Author: Andrew Boie <andrew.p.boie@intel.com>
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
#include "signature.h"
#include "lib.h"
#include "vars.h"

#define SETUP_MODE_VAR	        L"SetupMode"
#define SECURE_BOOT_VAR         L"SecureBoot"

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


static EVP_PKEY *get_rsa_pubkey(X509 *cert)
{
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        if (!pkey)
                return NULL;

        if (EVP_PKEY_RSA != EVP_PKEY_type(pkey->type)) {
                EVP_PKEY_free(pkey);
                return NULL;
        }
        return pkey;
}


static X509 *der_to_x509(CONST UINT8 *der, UINTN size)
{
        BIO *bio;
        X509 *x509;

        /* BIO is the OpenSSL input/output abstraction. Instantiate
         * one using a memory buffer containing the certificate */
        bio = BIO_new_mem_buf((void *)der, size);
        if (!bio)
                return NULL;

        /* Obtain an x509 structure from the DER cert data */
        x509 = d2i_X509_bio(bio, NULL);
        BIO_free(bio);
        return x509;
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
                                  struct boot_signature *sig, X509 *cert)
{
        VOID *hash;
        UINTN hash_sz;
        EFI_STATUS ret;
        int rsa_ret;
        EVP_PKEY *pkey = NULL;
        RSA *rsa;

        ret = hash_bootimage(sig, bootimage, imgsize, &hash, &hash_sz);
        if (EFI_ERROR(ret))
                return EFI_ACCESS_DENIED;

        ret = EFI_ACCESS_DENIED;
        pkey = get_rsa_pubkey(cert);
        if (!pkey)
                goto free_hash;

        rsa = EVP_PKEY_get1_RSA(pkey);
        if (!rsa)
                goto free_pkey;

        rsa_ret = RSA_verify(get_rsa_verify_nid(sig->id.nid),
                             hash, hash_sz, sig->signature,
                             sig->signature_len, rsa);
        if (rsa_ret == 1)
                ret = EFI_SUCCESS;
        else
                pr_error_openssl();

free_pkey:
        EVP_PKEY_free(pkey);
free_hash:
        free(hash);
        return ret;
}


static EFI_STATUS add_digest(X509_ALGOR *algo)
{
        int nid = OBJ_obj2nid(algo->algorithm);
        const EVP_MD *md;
        int ret;

        switch (nid) {
        case NID_sha256WithRSAEncryption:
                md = EVP_sha256();
                break;
        case NID_sha512WithRSAEncryption:
                md = EVP_sha512();
                break;
        default:
                error(L"Unsupported digest algorithm: %a", OBJ_nid2sn(nid));
                return EFI_UNSUPPORTED;
        }

        ret = EVP_add_digest(md);
        if (ret == 0)
                error(L"Failed to add digest %a", OBJ_nid2sn(nid));

        return ret != 0 ? EFI_SUCCESS : EFI_UNSUPPORTED;
}


UINT8 verify_android_boot_image(IN VOID *bootimage, IN VOID *der_cert,
                                IN UINTN cert_size, OUT CHAR16 *target,
                                OUT UINT8 *hash)
{
        struct boot_signature *sig = NULL;
        struct boot_img_hdr *hdr;
        UINT8 *signature_data;
        UINTN imgsize;
        UINT8 verify_state = BOOT_STATE_RED;
        CHAR16 *target_tmp;
        X509 *verifier_cert = NULL;
        EVP_PKEY *oemkey = NULL;
        EFI_STATUS ret;

        if (!bootimage || !der_cert || !target)
                goto out;

        debug(L"get boot image header");
        hdr = get_bootimage_header(bootimage);
        if (!hdr) {
                debug(L"bad boot image data");
                goto out;
        }

        debug(L"decoding boot image signature");
        imgsize = bootimage_size(hdr);
        signature_data = (UINT8*)bootimage + imgsize;
        sig = get_boot_signature(signature_data, BOOT_SIGNATURE_MAX_SIZE);
        if (!sig) {
                debug(L"boot image signature invalid or missing");
                goto out;
        }

        X509 *cert = der_to_x509(der_cert, cert_size);
        if (!cert) {
                debug(L"Failed to get OEM certificate");
                goto free_sig;
        }

        debug(L"verifying boot image");
        ret = check_bootimage(bootimage, imgsize, sig, cert);
        if (!EFI_ERROR(ret)) {
                verify_state = BOOT_STATE_GREEN;
                verifier_cert = cert;
                goto done;
        }

        if (ret != EFI_ACCESS_DENIED || !sig->certificate) {
                debug(L"Bootimage verification failure");
                goto done;
        }

        debug(L"Bootimage does not verify against the OEM key, trying included certificate");
        ret = check_bootimage(bootimage, imgsize, sig, sig->certificate);
        if (EFI_ERROR(ret))
                goto done;

        verifier_cert = sig->certificate;
        oemkey = get_rsa_pubkey(cert);
        if (!oemkey ||
            EFI_ERROR(add_digest(sig->certificate->sig_alg)) ||
            X509_verify(sig->certificate, oemkey) != 1) {
                verify_state = BOOT_STATE_YELLOW;
                goto done;
        }

        debug(L"Embedded certificate verified by OEM key");
        verify_state = BOOT_STATE_GREEN;

done:
        if (hash && verifier_cert)
                X509_digest(verifier_cert, EVP_sha1(), hash, NULL);
        if (oemkey)
                EVP_PKEY_free(oemkey);
        X509_free(cert);
        target_tmp = stra_to_str((CHAR8*)sig->attributes.target);
        if (!target_tmp) {
                verify_state = BOOT_STATE_RED;
                goto free_sig;
        }

        StrNCpy(target, target_tmp, BOOT_TARGET_SIZE);
        FreePool(target_tmp);
free_sig:
        free_boot_signature(sig);
out:

        return verify_state;
}

/* UEFI specification 2.4. Section 3.3
   The platform firmware is operating in secure boot mode if the value
   of the SetupMode variable is 0 and the SecureBoot variable is set
   to 1. A platform cannot operate in secure boot mode if the
   SetupMode variable is set to 1. The SecureBoot variable should be
   treated as read- only. */
BOOLEAN is_efi_secure_boot_enabled(VOID)
{
        EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;
        EFI_STATUS ret;
        UINT8 value;

        ret = get_efi_variable_byte(&global_guid, SETUP_MODE_VAR, &value);
        if (EFI_ERROR(ret))
                return FALSE;

        if (value != 0)
                return FALSE;

        ret = get_efi_variable_byte(&global_guid, SECURE_BOOT_VAR, &value);
        if (EFI_ERROR(ret))
                return FALSE;

        return value == 1;
}

static X509 *find_cert_in_pkcs7(PKCS7 *p7, const unsigned char *cert_sha256)
{
        STACK_OF(X509) *certs = NULL;
        X509 *x509;
        int id;
        unsigned int size;
        unsigned char digest[SHA256_DIGEST_LENGTH];
        const EVP_MD *fdig = EVP_sha256();
        int i;

        id = OBJ_obj2nid(p7->type);
        switch (id) {
        case NID_pkcs7_signed:
                certs = p7->d.sign->cert;
                break;
        case NID_pkcs7_signedAndEnveloped:
                certs = p7->d.signed_and_enveloped->cert;
                break;
        default:
                break;
        }

        if (!certs)
                return NULL;

        for (i = 0; i < sk_X509_num(certs); i++) {
                x509 = sk_X509_value(certs, i);
                if (!X509_digest(x509, fdig, digest, &size)) {
                        error(L"Failed to compute X509 digest");
                        return NULL;
                }
                if (size != sizeof(digest))
                        continue;
                if (!memcmp(cert_sha256, digest, sizeof(digest)))
                        return x509;
        }

        return NULL;
}

EFI_STATUS verify_pkcs7(const unsigned char *cert_sha256, UINTN cert_size,
                        const VOID *pkcs7, UINTN pkcs7_size,
                        VOID **data_p, int *size)
{
        X509 *x509;
        PKCS7 *p7 = NULL;
        X509_STORE *store = NULL;
        BIO *p7_bio = NULL, *data_bio = NULL;
        VOID *payload = NULL;
        char *tmp;
        int ret;

        if (cert_size != SHA256_DIGEST_LENGTH) {
                error(L"Invalid SHA256 length for trusted certificate");
                goto done;
        }

        p7_bio = BIO_new_mem_buf((void *)pkcs7, pkcs7_size);
        if (!p7_bio) {
                error(L"Failed to create PKCS7 BIO");
                goto done;
        }

        p7 = d2i_PKCS7_bio(p7_bio, NULL);
        if (!p7) {
                error(L"Failed to read PKCS7");
                goto done;
        }

        x509 = find_cert_in_pkcs7(p7, cert_sha256);
        if (!x509) {
                error(L"Could not find the root certificate");
                goto done;
        }

        store = X509_STORE_new();
        if (!store) {
                error(L"Failed to create x509 store");
                goto done;
        }

        ret = X509_STORE_add_cert(store, x509);
        if (ret != 1) {
                error(L"Failed to add trusted certificate to store");
                goto done;
        }

        data_bio = BIO_new(BIO_s_mem());
        if (!data_bio) {
                error(L"Failed to create data BIO");
                goto done;
        }

        EVP_add_digest(EVP_sha256());
        ret = PKCS7_verify(p7, NULL, store, NULL, data_bio, 0);
        if (ret != 1) {
                error(L"PKCS7 verification failed");
                goto done;
        }

        *size = BIO_get_mem_data(data_bio, &tmp);
        if (*size == -1) {
                error(L"Failed to get PKCS7 data");
                goto done;
        }

        payload = AllocatePool(*size);
        if (!payload) {
                error(L"Failed to allocate data buffer");
                goto done;
        }

        memcpy(payload, tmp, *size);
        *data_p = payload;

done:
        if (p7_bio)
                BIO_free(p7_bio);
        if (p7)
                PKCS7_free(p7);
        if (store)
                X509_STORE_free(store);
        if (data_bio)
                BIO_free(data_bio);

        return payload ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */

