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

#include <efi.h>
#include <efilib.h>

#include "lib.h"
#include "vars.h"


CHAR16 *stra_to_str(CHAR8 *stra)
{
        UINTN len, i;
        CHAR16 *str;

        len = strlena(stra);
        str = AllocatePool((len + 1) * sizeof(CHAR16));

        if (!str)
                return NULL;
        for (i = 0; i < len; i++)
                str[i] = (CHAR16)stra[i];
        str[i] = 0;
        return str;
}


EFI_STATUS vsnprintf(CHAR8 *dst, UINTN size, const CHAR8 *format, va_list ap)
{
        UINTN len;
        EFI_STATUS ret = EFI_OUT_OF_RESOURCES;
        CHAR16 *format16 = stra_to_str((CHAR8 *)format);
        if (!format16)
                return ret;

        CHAR16 *dst16 = AllocatePool(size * sizeof(CHAR16));
        if (!dst16)
                goto free_format16;

        len = VSPrint(dst16, size * sizeof(CHAR16), format16, ap);

        if (str_to_stra((CHAR8 *)dst, dst16, len + 1) == EFI_SUCCESS) {
                ret = EFI_SUCCESS;
                dst[len] = '\0';
        }

        FreePool(dst16);
free_format16:
        FreePool(format16);
        return ret;
}


EFI_STATUS snprintf(CHAR8 *str, UINTN size, const CHAR8 *format, ...)
{
        va_list args;
        int ret;

        va_start(args, format);
        ret = vsnprintf(str, size, format, args);
        va_end(args);
        return ret;
}


EFI_STATUS get_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN *size_p, VOID **data_p, UINT32 *flags_p)
{
        VOID *data;
        UINTN size;
        UINT32 flags;
        EFI_STATUS ret;

        size = EFI_MAXIMUM_VARIABLE_SIZE;
        data = AllocatePool(size);
        if (!data)
                return EFI_OUT_OF_RESOURCES;

        ret = uefi_call_wrapper(RT->GetVariable, 5, key, (EFI_GUID *)guid,
                        &flags, &size, data);

        if (EFI_ERROR(ret)) {
                FreePool(data);
                return ret;
        }

        if (size_p)
                *size_p = size;
        if (flags_p)
                *flags_p = flags;
        *data_p = data;

        return EFI_SUCCESS;
}


CHAR16 *get_efi_variable_str(const EFI_GUID *guid, CHAR16 *key)
{
        CHAR16 *data;
        EFI_STATUS ret;
        UINTN size;

        ret = get_efi_variable(guid, key, &size, (VOID **)&data, NULL);
        if (EFI_ERROR(ret))
                return NULL;

        if (!size || size % 2 != 0 || data[(size / 2) - 1] != 0) {
                FreePool(data);
                return NULL;
        }

        return data;
}


CHAR16 *get_efi_variable_str8(const EFI_GUID *guid, CHAR16 *key)
{
        CHAR8 *data;
        CHAR16 *value;
        EFI_STATUS ret;
        UINTN size;

        ret = get_efi_variable(guid, key, &size, (VOID **)&data, NULL);
        if (EFI_ERROR(ret) || !data || !size)
                return NULL;

        if (data[size - 1] != '\0') {
                FreePool(data);
                return NULL;
        }

        value = stra_to_str(data);
        FreePool(data);
        return value;
}


EFI_STATUS get_efi_variable_byte(const EFI_GUID *guid, CHAR16 *key, UINT8 *byte)
{
        CHAR16 *data;
        EFI_STATUS ret;
        UINTN size;

        ret = get_efi_variable(guid, key, &size, (VOID **)&data, NULL);
        if (EFI_ERROR(ret))
                return ret;

        if (!size) {
                FreePool(data);
                return EFI_NOT_FOUND;
        }

        *byte = data[0];
        FreePool(data);
        return EFI_SUCCESS;
}


EFI_STATUS set_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN size, VOID *data, BOOLEAN nonvol, BOOLEAN runtime)
{
        EFI_STATUS ret;
        UINT32 flags = EFI_VARIABLE_BOOTSERVICE_ACCESS;

        if (nonvol)
                flags |= EFI_VARIABLE_NON_VOLATILE;
        if (runtime)
                flags |= EFI_VARIABLE_RUNTIME_ACCESS;

        /* Storage attributes are only applied to a variable when creating the
         * variable. If a preexisting variable is rewritten with different
         * attributes, the result is indeterminate and may vary between
         * implementations. The correct method of changing the attributes of a
         * variable is to delete the variable and recreate it with different
         * attributes. */
        ret = uefi_call_wrapper(RT->SetVariable, 5, key, (EFI_GUID *)guid, 0, 0, 0);
        if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
                efi_perror(ret, L"Couldn't clear EFI variable");
                return ret;
        }

        if (size && data)
                return uefi_call_wrapper(RT->SetVariable, 5, key, (EFI_GUID *)guid, flags,
                        size, data);
        return EFI_SUCCESS;
}


EFI_STATUS set_efi_variable_str(const EFI_GUID *guid, CHAR16 *key,
                BOOLEAN nonvol, BOOLEAN runtime, CHAR16 *val)
{
        return set_efi_variable(guid, key,
                        val ? ((StrLen(val) + 1) * sizeof(CHAR16)) : 0,
                        val, nonvol, runtime);
}


EFI_STATUS file_delete(IN EFI_HANDLE disk, IN const CHAR16 *name)
{
        EFI_STATUS ret;
        EFI_FILE *file;
        EFI_FILE *root_dir;

        root_dir = LibOpenRoot(disk);
        if (!root_dir)
                return EFI_LOAD_ERROR;

        ret = uefi_call_wrapper(root_dir->Open, 5, root_dir, &file,
                        (CHAR16 *)name, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Couldn't open the file in order to delete");
                goto out;
        }
        ret = uefi_call_wrapper(file->Delete, 1, file);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Couldn't delete source file");
                goto out;
        }
out:
        uefi_call_wrapper(root_dir->Close, 1, root_dir);
        return ret;
}


BOOLEAN file_exists(IN EFI_HANDLE disk, IN const CHAR16 *path)
{
        EFI_FILE *root_dir;
        EFI_FILE *file;
        EFI_STATUS ret;
        BOOLEAN exists = TRUE;

        root_dir = LibOpenRoot(disk);
        if (!root_dir)
                return FALSE;

        ret = uefi_call_wrapper(root_dir->Open, 5, root_dir, &file,
                        (CHAR16 *)path, EFI_FILE_MODE_READ, 0);
        if (EFI_ERROR(ret)) {
                exists = FALSE;
        } else {
                uefi_call_wrapper(file->Close, 1, file);
        }

        uefi_call_wrapper(root_dir->Close, 1, root_dir);
        return exists;
}

EFI_STATUS file_read(IN EFI_FILE_HANDLE dir, IN const CHAR16 *name,
                     OUT CHAR8 **content, OUT UINTN *len)
{
        EFI_FILE_HANDLE handle;
        EFI_FILE_INFO *info;
        CHAR8 *buf;
        UINTN buflen;
        EFI_STATUS err;
        EFI_FILE *root_dir;

        root_dir = LibOpenRoot(dir);
        if (!root_dir)
                return EFI_LOAD_ERROR;

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle,
                        (CHAR16 *)name, EFI_FILE_MODE_READ, 0);

        if (EFI_ERROR(err))
                goto out;

        info = LibFileInfo(handle);
        if (!info) {
                err = EFI_UNSUPPORTED;
                goto out;
        }

        buflen = info->FileSize + 1;
        buf = AllocatePool(buflen);
        if (!buf) {
                err = EFI_OUT_OF_RESOURCES;
                goto out;
        }

        err = uefi_call_wrapper(handle->Read, 3, handle, &buflen, buf);
        if (EFI_ERROR(err) == EFI_SUCCESS) {
                buf[buflen] = '\0';
                *content = buf;
                *len = buflen;
        } else
                FreePool(buf);

        FreePool(info);
        uefi_call_wrapper(handle->Close, 1, handle);

out:
        uefi_call_wrapper(root_dir->Close, 1, root_dir);
        return err;
}

VOID StrNCpy(OUT CHAR16 *dest, IN const CHAR16 *src, UINT32 n)
{
        UINT32 i;

        for (i = 0; i < n && src[i] != 0; i++)
                dest[i] = src[i];
        for ( ; i < n; i++)
                dest[i] = 0;
}


UINT8 getdigit(IN CHAR16 *str)
{
        CHAR16 bytestr[3];
        bytestr[2] = 0;
        StrNCpy(bytestr, str, 2);
        return (UINT8)xtoi(bytestr);
}


EFI_STATUS string_to_guid(
                IN CHAR16 *in_guid_str,
                OUT EFI_GUID *guid)
{
        CHAR16 gstr[37];
        int i;

        StrNCpy(gstr, in_guid_str, 36);
        gstr[36] = 0;
        gstr[8] = 0;
        gstr[13] = 0;
        gstr[18] = 0;
        guid->Data1 = (UINT32)xtoi(gstr);
        guid->Data2 = (UINT16)xtoi(&gstr[9]);
        guid->Data3 = (UINT16)xtoi(&gstr[14]);

        guid->Data4[0] = getdigit(&gstr[19]);
        guid->Data4[1] = getdigit(&gstr[21]);
        for (i = 0; i < 6; i++)
                guid->Data4[i + 2] = getdigit(&gstr[24 + (i * 2)]);

        return EFI_SUCCESS;
}


EFI_STATUS str_to_stra(CHAR8 *dst, CHAR16 *src, UINTN len)
{
        UINTN i;

        /* This is NOT how to do UTF16 to UTF8 conversion. For now we're just
         * going to hope that nobody's putting non-ASCII characters in
         * the source string! We'll at least abort with an error
         * if we see any funny stuff */
        for (i = 0; i < len; i++) {
                if (src[i] > 0x7F)
                        return EFI_INVALID_PARAMETER;

                dst[i] = (CHAR8)src[i];
                if (!src[i])
                        break;
        }
        dst[len - 1] = '\0';
        return EFI_SUCCESS;
}


/*
 * Parameters Passed : character  : char to be converted to int
 *                     base       : the base of convertion ( hex, dec etc)
 *
 * Returns           :   value    : character after conversion to int
 *
 * This function converts character to integer.
 */
static INTN to_digit(CHAR16 character, UINTN base)
{
        UINTN value = -1;

        if (character >= '0' && character <= '9')
                value = character - '0';
        else if (character >= 'a' && character <= 'z')
                value = 0xA + character - 'a';
        else if (character >= 'A' && character <= 'Z')
                value = 0xA + character - 'A';

        return value < base ? (INTN)value : -1;
}


/*
 * Parameters Passed : nptr  : Pointer to the string to be converted to int
 *                     base  : the base of convertion ( hex, dec etc)
 *               endptr: Reference to the next character after the converted string
 * Returns           : value : coverted unsigned long int
 *
 * This function converts String to unsigned long int.
 */
UINTN strtoul16(const CHAR16 *nptr, CHAR16 **endptr, UINTN base)
{
        UINTN value = 0;

        if (!nptr)
                goto out;

        if ((base == 0 || base == 16) &&
            (StrLen(nptr) > 2 && nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X'))) {
                nptr += 2;
                base = 16;
        }

        if (base == 0)
                base = 10;

        for (; *nptr != '\0' ; nptr++) {
                INTN t = to_digit(*nptr, base);
                if (t == -1)
                        goto out;
                value = (value * base) + t;
        }

out:
        if (endptr)
                *endptr = (CHAR16 *)nptr;
        return value;
}


VOID pause(UINTN seconds)
{
        uefi_call_wrapper(BS->Stall, 1, seconds * 1000000);
}


VOID halt_system(VOID)
{
        uefi_call_wrapper(RT->ResetSystem, 4, EfiResetShutdown, EFI_SUCCESS,
                          0, NULL);
        while (1) { }
}


VOID reboot(CHAR16 *target)
{
        EFI_STATUS ret;

        if (target) {
                ret = set_efi_variable_str(&loader_guid, LOADER_ENTRY_ONESHOT,
                                           TRUE, TRUE, target);
                if (EFI_ERROR(ret)) {
                        error(L"Unable to set LoaderEntryOneShot");
                        pause(30);
                        halt_system();
                }
        }

        uefi_call_wrapper(RT->ResetSystem, 4, EfiResetCold, EFI_SUCCESS,
                          0, NULL);
        while (1) { }
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */

