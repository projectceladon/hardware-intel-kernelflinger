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
#include <ui.h>
#include <log.h>

/* pulls in memcpy, memset, bunch of other posix functions */
#include "OpenSslSupport.h"

/* The offsetof in the uefi shim support library headers generates
 * warnings, use this instead */
#ifdef offsetof
#undef offsetof
#define offsetof(TYPE, MEMBER) ((UINTN) &((TYPE *)0)->MEMBER)
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define _CONVERT_TO_WIDE(x) L ## x
#define CONVERT_TO_WIDE(x) _CONVERT_TO_WIDE(x)

/* Current EFI image handle.  To be use as parent image with the
   LoadImage boot service */
extern EFI_HANDLE g_parent_image;

/*
 * EFI Variables
 */
EFI_STATUS get_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN *size_p, VOID **data_p,  UINT32 *flags_p);

CHAR16 *get_efi_variable_str(const EFI_GUID *guid, CHAR16 *key);
CHAR16 *get_efi_variable_str8(const EFI_GUID *guid, CHAR16 *key);

EFI_STATUS get_efi_variable_byte(const EFI_GUID *guid, CHAR16 *key, UINT8 *byte);
EFI_STATUS get_efi_variable_long_from_str8(const EFI_GUID *guid, CHAR16 *key,
                                           unsigned long *i);

EFI_STATUS set_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN size, VOID *data, BOOLEAN nonvol, BOOLEAN runtime);

EFI_STATUS set_efi_variable_str(const EFI_GUID *guid, CHAR16 *key,
                BOOLEAN nonvol, BOOLEAN runtime, CHAR16 *val);

/*
 * File I/O
 */

EFI_STATUS file_delete(IN EFI_HANDLE disk, IN const CHAR16 *name);

BOOLEAN file_exists(IN EFI_HANDLE disk, IN const CHAR16 *path);

EFI_STATUS file_read(IN EFI_FILE_HANDLE dir, IN const CHAR16 *name,
                OUT CHAR8 **content, OUT UINTN *len);

/*
 * String manipulation
 */
CHAR16 *stra_to_str(CHAR8 *stra);

EFI_STATUS str_to_stra(CHAR8 *dst, CHAR16 *src, UINTN len);

int vsnprintf(CHAR8 *dst, UINTN size, const CHAR8 *format, va_list ap);

int snprintf(CHAR8 *str, UINTN size, const CHAR8 *format, ...);

VOID StrNCpy(OUT CHAR16 *dest, IN const CHAR16 *src, UINT32 n);

UINT8 getdigit(IN CHAR16 *str);

EFI_STATUS string_to_guid(IN CHAR16 *in_guid_str, OUT EFI_GUID *guid);

UINTN strtoul16(const CHAR16 *nptr, CHAR16 **endptr, UINTN base);

char *strcasestr(const char *s, const char *find);

/*
 * misc
 */
#define _unused __attribute__((unused))

VOID halt_system(VOID) __attribute__ ((noreturn));

VOID pause(UINTN seconds);

VOID reboot(CHAR16 *target) __attribute__ ((noreturn));

EFI_STATUS alloc_aligned(VOID **free_addr, VOID **aligned_addr,
                         UINTN size, UINTN align);
#endif
