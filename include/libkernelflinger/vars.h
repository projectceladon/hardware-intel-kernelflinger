/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
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

#ifndef _VARS_H_
#define _VARS_H_

/* Gummiboot's loader GUID, for compatibility we honor some of the
 * same variables */
extern const EFI_GUID loader_guid;

#define LOADER_ENTRY_ONESHOT    L"LoaderEntryOneShot"
/* Report bootloader version */
#define LOADER_VERSION_VAR      L"LoaderVersion"

/* GUID for variables used to communicate with Fastboot */
extern const EFI_GUID fastboot_guid;

#define SERIAL_PORT_VAR         L"SerialPort"

/* Current device state, set by Fastboot  */
#define OEM_LOCK_VAR		L"OEMLock"
#define OEM_LOCK_UNLOCKED	(1 << 0)
#define OEM_LOCK_VERIFIED	(1 << 1)

/* Boot state that we report before exiting boot services, per
 * Google's verified boot spec */
#define BOOT_STATE_VAR		L"BootState"
#define BOOT_STATE_GREEN	0
#define BOOT_STATE_YELLOW	1
#define BOOT_STATE_ORANGE	2
#define BOOT_STATE_RED		3

/* EFI Variable to store user-supplied key store binary data */
#define KEYSTORE_VAR		L"KeyStore"

/* If set to the string "0", disable entering charge mode and
 * boot normally instead */
#define OFF_MODE_CHARGE		L"off-mode-charge"

/* Various interesting partition GUIDs */
extern const EFI_GUID boot_ptn_guid;
extern const EFI_GUID recovery_ptn_guid;
extern const EFI_GUID misc_ptn_guid;

/* EFI variable which stores the max timeout for checking whether the
 * magic key was pressed at startup */
#define MAGIC_KEY_TIMEOUT_VAR   L"MagicKeyTimeout"

#endif /* _VARS_H_ */

