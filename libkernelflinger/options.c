/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
 * Author: Anisha Dattatraya Kulkarni <anisha.dattatraya.kulkarni@intel.com>
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

#include "lib.h"

static CHAR16 *tokenize(CHAR16 *str, BOOLEAN set_zero)
{
        static CHAR16 *saveptr;
        CHAR16 *ret;

        if (str)
                saveptr = str;

        if (!saveptr)
                return NULL;

        // skip leading delimiters
        while (*saveptr == L' ')
                saveptr++;

        // end of the string, no more tokens
        if (*saveptr == L'\0')
                return NULL;

        ret = saveptr;
        // now scan until we find another delimiter or the end of the string
        while (*saveptr != L' ' && *saveptr != L'\0')
                saveptr++;

        if (*saveptr != L'\0') {
                if (set_zero)
                        *saveptr = L'\0';
                saveptr++;
        }

        return ret;
}


EFI_STATUS
get_argv(EFI_LOADED_IMAGE *loaded_image, UINTN *argc_p, CHAR16 ***argv_p, CHAR16 **options)
{
        CHAR16* token, *str, *cur, *cmdline;
        UINTN argc, i;
        CHAR16 **argv;

        cmdline = (CHAR16 *)loaded_image->LoadOptions;
        if (!cmdline)
                cmdline = L"";

        // Count up the number of arguments
        str = StrDuplicate(cmdline);
        if (!str)
                return EFI_OUT_OF_RESOURCES;

        for (argc = 0, cur = str; ; cur = NULL) {
                token = tokenize(cur, FALSE);
                if (token == NULL)
                        break;
                argc++;
        }

        argv = AllocatePool((argc + 1) * sizeof(CHAR16 *));
        if (!argv)
                return EFI_OUT_OF_RESOURCES;

        for (i = 0, cur = str; ; cur = NULL, i++) {
                token = tokenize(cur, TRUE);
                if (token == NULL) {
                        argv[i] = NULL;
                        break;
                }
                argv[i] = token;
        }

        *argc_p = argc;
        *argv_p = argv;
        *options = str;
        return EFI_SUCCESS;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */
