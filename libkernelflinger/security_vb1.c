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
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "security.h"
#include "android.h"
#include "signature.h"
#include "lib.h"
#include "vars.h"
#include "life_cycle.h"

#ifdef USE_IPP_SHA256
#include "sha256_ipps.h"
#endif


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

        *hash = AllocatePool(*hashsz);
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
#ifdef USE_IPP_SHA256
        {
                SHA256_IPPS_CTX ctx;

                ippsSHA256_Init(&ctx);
                ippsSHA256_Update(&ctx, bootimage, imgsize);
                ippsSHA256_Update(&ctx, (uint8_t *)bs->attributes.data,
                                    bs->attributes.data_sz);
                ippsSHA256_Final(&ctx, (uint32_t *)*hash);
                return EFI_SUCCESS;
        }
#else
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
#endif
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
        FreePool(*hash);
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
        FreePool(hash);
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


static EFI_STATUS pub_key_hash(X509 *cert, UINT8 **hash_p,
                               const EVP_MD *hash_algo)
{
        static UINT8 hash[SHA256_DIGEST_LENGTH];
        EFI_STATUS fun_ret = EFI_INVALID_PARAMETER;
        BIO *bio = NULL;
        EVP_PKEY *pkey = NULL;
        RSA *rsa;
        int ret;
        int size;
        char *raw_pkey;

        if (hash_algo != EVP_sha256() && hash_algo != EVP_sha1())
                return EFI_UNSUPPORTED;

        if (!hash_p || !cert)
                return EFI_INVALID_PARAMETER;

        bio = BIO_new(BIO_s_mem());
        if (!bio) {
                error(L"Failed to allocate the RoT bitstream BIO");
                return EFI_OUT_OF_RESOURCES;
        }

        pkey = get_rsa_pubkey(cert);
        if (!pkey) {
                error(L"Failed to get the public key from the certificate");
                goto out;
        }

        rsa = EVP_PKEY_get1_RSA(pkey);
        if (!rsa) {
                error(L"Failed to get the RSA key from the public key");
                goto out;
        }

        ret = i2d_RSAPublicKey_bio(bio, rsa);
        if (ret <= 0) {
                error(L"Failed to write the RSA key to RoT bitstream BIO");
                goto out;
        }

        size = BIO_get_mem_data(bio, &raw_pkey);
        if (size == -1) {
                error(L"Failed to get the RoT bitstream BIO content");
                goto out;
        }

        ret = EVP_Digest(raw_pkey, size, hash, NULL, hash_algo, NULL);
        if (ret == 0) {
                error(L"Failed to hash the RoT bitstream");
                goto out;
        }

        *hash_p = hash;
        fun_ret = EFI_SUCCESS;

out:
        if (pkey)
                EVP_PKEY_free(pkey);
        if (bio)
                BIO_free(bio);
        return fun_ret;
}


EFI_STATUS pub_key_sha256(X509 *cert, UINT8 **hash_p)
{
        return pub_key_hash(cert, hash_p, EVP_sha256());
}


EFI_STATUS pub_key_sha1(X509 *cert, UINT8 **hash_p)
{
        return pub_key_hash(cert, hash_p, EVP_sha1());
}


UINT8 verify_android_boot_image(IN VOID *bootimage, IN VOID *der_cert,
                                IN UINTN cert_size, OUT CHAR16 *target,
                                OUT X509 **verifier_cert)
{
        struct boot_signature *sig = NULL;
        struct boot_img_hdr *hdr;
        UINT8 *signature_data;
        UINTN imgsize;
        UINT8 verify_state = BOOT_STATE_RED;
        CHAR16 *target_tmp;
        EVP_PKEY *oemkey = NULL;
        EFI_STATUS ret;

        if (!bootimage || !der_cert || !target)
                goto out;

        if (verifier_cert)
                *verifier_cert = NULL;

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
                if (verifier_cert)
                        *verifier_cert = X509_dup(cert);
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

        if (verifier_cert)
                *verifier_cert = X509_dup(sig->certificate);
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

static EFI_STATUS get_x509_name_entry(X509 *cert, int nid, char **value)
{
        X509_NAME *name;
        UINTN i, j, nb_entry;
        X509_NAME_ENTRY *ent;
        ASN1_OBJECT *obj;
        ASN1_STRING *val;

        name = X509_get_issuer_name(cert);
        if (!name)
                return EFI_INVALID_PARAMETER;

        nb_entry = X509_NAME_entry_count(name);
        for (i = 0; i < nb_entry; i++) {
                ent = X509_NAME_get_entry(name, i);
                obj = X509_NAME_ENTRY_get_object(ent);
                val = X509_NAME_ENTRY_get_data(ent);

                if (!obj || !val) {
                        error(L"Failed to get entry content");
                        continue;
                }

                if (OBJ_obj2nid(obj) != nid)
                        continue;

                for (j = 0; j < (UINTN)val->length; j++)
                        if (val->data[j] > 0x7F) {
                                error(L"Non-ASCII value unsupported");
                                return EFI_UNSUPPORTED;
                        }

                *value = strdup((char *)val->data);
                if (!*value)
                        return EFI_OUT_OF_RESOURCES;

                return EFI_SUCCESS;
        }

        return EFI_NOT_FOUND;
}

#define KEY_ID_SEPARATOR ":#"

EFI_STATUS get_android_verity_key_id(X509 *cert, char **value)
{
        EFI_STATUS ret;
        char *common_name = NULL, *keyid = NULL;
        UINT8 *hash;
        UINTN strsize, prefix_len;
        int len;

        if (!cert || !value)
                return EFI_INVALID_PARAMETER;

        ret = get_x509_name_entry(cert, NID_commonName, &common_name);
        if (EFI_ERROR(ret))
                goto out;

        ret = pub_key_sha1(cert, &hash);
        if (EFI_ERROR(ret))
                goto out;

        prefix_len = strlen((CHAR8 *)common_name) +
                strlen((CHAR8 *)KEY_ID_SEPARATOR);
        strsize = prefix_len + (SHA_DIGEST_LENGTH * 2) + 1;
        keyid = AllocatePool(strsize);
        if (!keyid)
                goto out;

        len = efi_snprintf((CHAR8 *)keyid, prefix_len + 1,
                           (CHAR8 *)"%a" KEY_ID_SEPARATOR, common_name);
        if (len != (int)prefix_len) {
                ret = EFI_BAD_BUFFER_SIZE;
                goto out;
        }

        ret = bytes_to_hex_stra(hash, SHA_DIGEST_LENGTH,
                                (CHAR8 *)keyid + len, strsize - len);
        if (EFI_ERROR(ret))
                goto out;

        *value = keyid;

out:
        if (common_name)
                FreePool(common_name);
        if (EFI_ERROR(ret) && keyid)
                FreePool(keyid);
        return ret;
}


EFI_STATUS rot_pub_key_sha256(IN VBDATA *vb_data,
                        OUT UINT8 **hash_p)
{
        EFI_STATUS ret = EFI_SUCCESS;

        if (vb_data && hash_p) {
                ret = pub_key_sha256(vb_data, hash_p);
                if (EFI_ERROR(ret))
                        efi_perror(ret, L"Failed to compute key hash");
        } else
                ret = EFI_INVALID_PARAMETER;

        return ret;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */

