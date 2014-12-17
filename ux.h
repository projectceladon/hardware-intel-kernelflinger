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

#ifndef _UX_H_
#define _UX_H_

#include <efi.h>
#include <efilib.h>

/* TRUE: OK, use keystore anyway
 * FALSE: Fastboot */
BOOLEAN ux_prompt_user_keystore_unverified(UINT8 *hash);

/* TRUE: Fastboot
 * FALSE: halt system */
BOOLEAN ux_warn_user_unverified_recovery(VOID);

/* TRUE: Recovery
 * FALSE: Halt system */
BOOLEAN ux_prompt_user_bootimage_unverified(VOID);

/* TRUE: OK to boot
 * FALSE: Fastboot */
BOOLEAN ux_prompt_user_device_unlocked(VOID);

/* TRUE: OK to boot
 * FALSE: power off */
BOOLEAN ux_prompt_user_secure_boot_off(VOID);

/* Inform the user about the multiple crash events and let him choose
 * a boot target */
enum boot_target ux_crash_event_prompt_user_for_boot_target(VOID);

VOID ux_init(VOID);

#endif
