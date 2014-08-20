/*
 * Copyright (c) 2013, Intel Corporation
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

#ifndef _KF_LIB_H_
#define _KF_LIB_H_

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>

/* pulls in memcpy, memset, bunch of other posix functions */
#include "OpenSslSupport.h"

/* The offsetof in the uefi shim support library headers generates
 * warnings, use this instead */
#ifdef offsetof
#undef offsetof
#define offsetof(TYPE, MEMBER) ((UINTN) &((TYPE *)0)->MEMBER)
#endif

/* debug stuff */

#define DEBUG_MESSAGES 0

#if DEBUG_MESSAGES
#define debug(fmt, ...) do { \
    Print(L##fmt L"\n", ##__VA_ARGS__); \
} while(0)

#define debug_pause(x) pause(x)
#else
#define debug(fmt, ...) (void)0
#define debug_pause(x) (void)(x)
#endif

#define efi_perror(ret, x, ...) Print(x L": %r", ##__VA_ARGS__, ret)


/*
 * EFI Variables
 */
EFI_STATUS get_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN *size_p, VOID **data_p);

CHAR16 *get_efi_variable_str(const EFI_GUID *guid, CHAR16 *key);

EFI_STATUS get_efi_variable_byte(const EFI_GUID *guid, CHAR16 *key, UINT8 *byte);

EFI_STATUS set_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN size, VOID *data, BOOLEAN nonvol, BOOLEAN runtime);

EFI_STATUS set_efi_variable_str(const EFI_GUID *guid, CHAR16 *key,
                BOOLEAN nonvol, BOOLEAN runtime, CHAR16 *val);

/*
 * File I/O
 */

EFI_STATUS file_delete(IN EFI_HANDLE disk, IN const CHAR16 *name);

BOOLEAN file_exists(IN EFI_HANDLE disk, IN const CHAR16 *path);

/*
 * String manipulation
 */
CHAR16 *stra_to_str(CHAR8 *stra);

EFI_STATUS str_to_stra(CHAR8 *dst, CHAR16 *src, UINTN len);

VOID StrNCpy(OUT CHAR16 *dest, IN const CHAR16 *src, UINT32 n);

UINT8 getdigit(IN CHAR16 *str);

EFI_STATUS string_to_guid(IN CHAR16 *in_guid_str, OUT EFI_GUID *guid);

UINTN strtoul16(const CHAR16 *nptr, CHAR16 **endptr, UINTN base);

/*
 * misc
 */
#define _unused __attribute__((unused))

VOID halt_system(VOID) __attribute__ ((noreturn));

VOID pause(UINTN seconds);

VOID reboot(VOID) __attribute__ ((noreturn));



#endif
