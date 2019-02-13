/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _SECURITY_VB1_H_
#define _SECURITY_VB1_H_

/* Compute sums of the public key value of X509 input CERT */
EFI_STATUS pub_key_sha256(X509 *cert, UINT8 **hash_p);
EFI_STATUS pub_key_sha1(X509 *cert, UINT8 **hash_p);

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

/* Given a X509 certificate, build the following string:
 * COMMON_NAME:#PUBLIC_KEY_SHA1
 * Where COMMON_NAME is the certificate issuer CN and PUBLIC_KEY_SHA1
 * is the X509 certificate public key SHA1 hash.
 */
EFI_STATUS get_android_verity_key_id(X509 *cert, char **value);

EFI_STATUS rot_pub_key_sha256(IN VBDATA *vb_data,
                        OUT UINT8 **hash_p);


#endif
