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

#include <efi.h>
#include <efilib.h>
#include <openssl/x509.h>

#ifndef _SECURITY_H_
#define _SECURITY_H_

#define BOOT_TARGET_SIZE         32
#define BOOT_SIGNATURE_MAX_SIZE  4096

/* Compute the Root Of Trust bistream and returns its SHA256 hash.
 * The RoT bitstream consists of the device State value (1 for locked
 * and 0 for unlocked) followed by the public key value of CERT.  CERT
 * must be the certificate that has been used to validate the
 * bootimage.  */
EFI_STATUS compute_rot_bitstream_hash(X509 *cert, UINT8 **hash_p,
				      UINTN *hash_size);

/* Given an Android boot image, test if it is signed with the provided
 * certificate or the embedded one
 *
 * Parameters:
 * bootimage - data pointer to an Android boot image which may or may not
 *             be signed. This code may seek up to BOOT_SIGNATURE_MAX_SIZE
 *             past the end of the boot image size as reported by its header
 *             to search for the ASN.1 AndroidVerifiedBootSignature message.
 * der_cert  - DER certificate to validate image with
 * cert_size - Size of DER certificate
 * target    - Pointer to buffer of BOOT_TARGET_SIZE, which will be filled in
 *             with AuthenticatedAttributes 'target' field iff the image is
 *             verified. Caller should only check this on EFI_SUCCESS.
 * verifier_cert  - Return the certificate that validated the boot image
 *
 * Return values:
 * BOOT_STATE_GREEN  - Boot image is validated against provided certificate
 * BOOT_STATE_YELLOW - Boot image is validated against embedded certificate
 * BOOT_STATE_RED    - Boot image is not validated
 */
UINT8 verify_android_boot_image(
        IN VOID *bootimage,
        IN VOID *der_cert,
        IN UINTN cert_size,
        OUT CHAR16 *target,
        OUT X509 **verifier_cert);

/* Determines if UEFI Secure Boot is enabled or not. */
BOOLEAN is_efi_secure_boot_enabled(VOID);

EFI_STATUS set_os_secure_boot(BOOLEAN secure);

/* Given a PKCS7 (DER encoded), look for the root certificate based on
 * CERT_SHA256 and verify the PKCS7.  On success, EFI_SUCCESS is
 * return and the PKCS7 payload is returned in DATA as a dynamically
 * allocated buffer.
 */
EFI_STATUS verify_pkcs7(const unsigned char *cert_sha256, UINTN cert_size,
			const VOID *pkcs7, UINTN pkcs7_size,
			VOID **data, int *size);

#endif
