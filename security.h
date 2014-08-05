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

#ifndef _SECURITY_H_
#define _SECURITY_H_

#define BOOT_TARGET_SIZE         32
#define BOOT_SIGNATURE_MAX_SIZE  2048

/* Given an Android boot image, test if it is signed with the provided
 * keystore
 *
 * Parameters:
 * bootimage - data pointer to an Android boot image which may or may not
 *             be signed. This code may seek up to BOOT_SIGNATURE_MAX_SIZE
 *             past the end of the boot image size as reported by its header
 *             to search for the ASN.1 AndroidVerifiedBootSignature message.
 * keystore - data pointer to DER-encoded ASN.1 keystore per Google spec
 *            keystore_size - size of the keystore data
 * target - Pointer to buffer of BOOT_TARGET_SIZE, which will be filled in
 *          with AuthenticatedAttributes 'target' field iff the image is
 *          verified. Caller should only check this on EFI_SUCCESS.
 *
 * Return values:
 * EFI_SUCCESS: Boot image is validated
 * EFI_INVALID_PARAMETER - Boot image and/or keystore are not well-formed
 * EFI_ACCESS_DENIED - Boot image or AuthenticatedAttributes is not verifiable
 *                     or boot image is unsigned
 */
EFI_STATUS verify_android_boot_image(
        IN VOID *bootimage,
        IN VOID *keystore,
        IN UINTN keystore_size,
        OUT CHAR16 *target);

#define KEYSTORE_HASH_SIZE        6

/* Given a keystore, return EFI_SUCCESS if it is signed with the supplied key.
 *
 * Parameters:
 * keystore - data pointer to DER-encoded ASN.1 keystore per Google spec
 * keystore_size - size of the keystore data
 * key - public key data to verify the keystore with. The specifics of this
 *       data depend on the chosen algorithm in the keystore message
 * key_size - Size of the public key data
 * keystore_hash - pointer to a buffer of KEYSTORE_HASH_SIZE. Will be filled
 *                 in with a partial hash of the keystore data even if the
 *                 verification fails so that it can be reported to UX
 *
 * Return values:
 * EFI_SUCCESS - Keystore is validated by the OEM key
 * EFI_ACCESS_DENIED - Keystore is not validated
 * EFI_INVALID_PARAMETER - Keystore data is not well-formed
 */
EFI_STATUS verify_android_keystore(
        IN VOID *keystore,
        IN UINTN keystore_size,
        IN VOID *key,
        IN UINTN key_size,
        OUT VOID *keystore_hash);

#endif
