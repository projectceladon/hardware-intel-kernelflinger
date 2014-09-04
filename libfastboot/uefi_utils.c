/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors: Sylvain Chouleur <sylvain.chouleur@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 *          Jocelyn Falempe <jocelyn.falempe@intel.com>
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
#include <lib.h>
#include "protocol.h"
#include "uefi_utils.h"

/* GUID for ESP partition on gmin */
const EFI_GUID esp_ptn_guid = { 0x2568845d, 0x2332, 0x4675,
		{0xbc, 0x39, 0x8f, 0xa5, 0xa4, 0x74, 0x8d, 0x15}};

EFI_STATUS get_esp_handle(EFI_HANDLE *esp)
{
	EFI_STATUS ret;
	UINTN no_handles;
	EFI_HANDLE *handles;

	ret = LibLocateHandleByDiskSignature(
		MBR_TYPE_EFI_PARTITION_TABLE_HEADER,
		SIGNATURE_TYPE_GUID,
		(void *)&esp_ptn_guid,
		&no_handles,
		&handles);

	if (EFI_ERROR(ret)) {
		error(L"Failed to found partition: %r\n", ret);
		return ret;
	}

	if (no_handles == 1) {
		*esp = handles[0];
		ret = EFI_SUCCESS;
	} else {
		error(L"%d handles found for ESP, expecting 1\n", no_handles);
		ret = EFI_VOLUME_CORRUPTED;
	}

	if (handles)
		FreePool(handles);
	return ret;
}

EFI_STATUS get_esp_fs(EFI_FILE_IO_INTERFACE **esp_fs)
{
	EFI_STATUS ret = EFI_SUCCESS;
	EFI_GUID SimpleFileSystemProtocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
	EFI_HANDLE esp_handle = NULL;
	EFI_FILE_IO_INTERFACE *esp;

	ret = get_esp_handle(&esp_handle);
	if (EFI_ERROR(ret)) {
		error(L"Failed to get ESP partition: %r\n", ret);
		return ret;
	}

	ret = handle_protocol(esp_handle, &SimpleFileSystemProtocol,
			      (void **)&esp);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"HandleProtocol for ESP partition failed");
		return ret;
	}
	*esp_fs = esp;

	return ret;
}

EFI_STATUS uefi_read_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void **data, UINTN *size)
{
	EFI_STATUS ret;
	EFI_FILE_INFO *info;
	UINTN info_size;
	EFI_FILE *file;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &file);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Open, 5, file, &file, filename, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(ret))
		goto out;

	info_size = SIZE_OF_EFI_FILE_INFO + 200;

	info = AllocatePool(info_size);
	if (!info)
		goto close;

	ret = uefi_call_wrapper(file->GetInfo, 4, file, &GenericFileInfo, &info_size, info);
	if (EFI_ERROR(ret))
		goto free_info;

	*size = info->FileSize;
	*data = AllocatePool(*size);

retry:
	ret = uefi_call_wrapper(file->Read, 3, file, size, *data);
	if (ret == EFI_BUFFER_TOO_SMALL) {
		FreePool(*data);
		*data = AllocatePool(*size);
		goto retry;
	}

	if (EFI_ERROR(ret))
		FreePool(*data);

free_info:
	FreePool(info);
close:
	uefi_call_wrapper(file->Close, 1, file);
out:
	if (EFI_ERROR(ret))
		error(L"Failed to read file %s:%r\n", filename, ret);
	return ret;
}

EFI_STATUS uefi_write_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void *data, UINTN *size)
{
	EFI_STATUS ret;
	EFI_FILE *file, *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(root->Open, 5, root, &file, filename, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Write, 3, file, size, data);
	uefi_call_wrapper(file->Close, 1, file);

out:
	if (EFI_ERROR(ret))
		error(L"Failed to write file %s:%r\n", filename, ret);
	return ret;
}

EFI_STATUS uefi_create_dir(EFI_FILE *parent, EFI_FILE **dir, CHAR16 *dirname)
{
	return uefi_call_wrapper(parent->Open, 5, parent, dir, dirname,
				 EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
				 EFI_FILE_DIRECTORY);
}

#define MAX_SUBDIR 10
EFI_STATUS uefi_write_file_with_dir(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void *data, UINTN size)
{
	EFI_STATUS ret;
	EFI_FILE *dirs[MAX_SUBDIR];
	EFI_FILE *file;
	CHAR16 *start;
	CHAR16 *end;
	INTN subdir = 0;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &dirs[0]);
	if (EFI_ERROR(ret)) {
		error(L"Failed to open root directory, error %r\n", ret);
		return ret;
	}
	start = filename;
	for (end = filename; *end; end++) {
		if (*end != '/')
			continue;
		if (start == end) {
			start++;
			continue;
		}

		*end = 0;
		debug("create directory %s\n", start);
		ret = uefi_create_dir(dirs[subdir], &dirs[subdir + 1], start);
		*end = '/';
		if (EFI_ERROR(ret))
			goto out;
		subdir++;
		if (subdir >= MAX_SUBDIR - 1) {
			error(L"too many subdirectories, limit is %d\n", MAX_SUBDIR);
			ret = EFI_INVALID_PARAMETER;
			goto out;
		}
		start = end + 1;
	}
	debug("write file %s\n", start);
	ret = uefi_call_wrapper(dirs[subdir]->Open, 5, dirs[subdir], &file, start, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Write, 3, file, &size, data);
	uefi_call_wrapper(file->Close, 1, file);

out:
	for (; subdir >= 0; subdir--)
		uefi_call_wrapper(dirs[subdir]->Close, 1, dirs[subdir]);

	if (EFI_ERROR(ret))
		error(L"Failed to write file %s: %r\n", filename, ret);
	return ret;
}

void uefi_reset_system(EFI_RESET_TYPE reset_type)
{
	uefi_call_wrapper(RT->ResetSystem, 4, reset_type,
			  EFI_SUCCESS, 0, NULL);
}

void uefi_shutdown(void)
{
	uefi_reset_system(EfiResetShutdown);
}

EFI_STATUS uefi_delete_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename)
{
	EFI_STATUS ret;
	EFI_FILE *file, *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(root->Open, 5, root, &file, filename,
				EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Delete, 1, file);

out:
	if (EFI_ERROR(ret) || ret == EFI_WARN_DELETE_FAILURE)
		error(L"Failed to delete file %s:%r\n", filename, ret);

	return ret;
}

BOOLEAN uefi_exist_file(EFI_FILE *parent, CHAR16 *filename)
{
	EFI_STATUS ret;
	EFI_FILE *file;

	ret = uefi_call_wrapper(parent->Open, 5, parent, &file, filename,
				EFI_FILE_MODE_READ, 0);
	if (!EFI_ERROR(ret))
		uefi_call_wrapper(file->Close, 1, file);
	else if (ret != EFI_NOT_FOUND) // IO error
		error(L"Failed to found file %s:%r\n", filename, ret);

	return ret == EFI_SUCCESS;
}

BOOLEAN uefi_exist_file_root(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename)
{
	EFI_STATUS ret;
	EFI_FILE *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret)) {
		error(L"Failed to open volume %s:%r\n", filename, ret);
		return FALSE;
	}

	return uefi_exist_file(root, filename);
}

EFI_STATUS uefi_create_directory(EFI_FILE *parent, CHAR16 *dirname)
{
	EFI_STATUS ret;
	EFI_FILE *dir;

	ret = uefi_create_dir(parent, &dir, dirname);

	if (EFI_ERROR(ret)) {
		error(L"Failed to create directory %s:%r\n", dirname, ret);
	} else {
		uefi_call_wrapper(dir->Close, 1, dir);
	}

	return ret;
}

EFI_STATUS uefi_create_directory_root(EFI_FILE_IO_INTERFACE *io, CHAR16 *dirname)
{
	EFI_STATUS ret;
	EFI_FILE *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret)) {
		error(L"Failed to open volume %s:%r\n", dirname, ret);
		return ret;
	}

	return uefi_create_directory(root, dirname);
}

EFI_STATUS uefi_usleep(UINTN useconds)
{
	return uefi_call_wrapper(BS->Stall, 1, useconds);
}

EFI_STATUS uefi_msleep(UINTN mseconds)
{
	return uefi_usleep(mseconds * 1000);
}

int sprintf(char *str, const char *format, ...)
{
	va_list args;
	UINTN len;
	int ret = -1;
	CHAR16 *str16;
	CHAR16 *format16 = stra_to_str((CHAR8 *)format);

	if (!format16)
		return -1;

	va_start(args, format);
	str16 = VPoolPrint(format16, args);
	va_end(args);

	if (!str16)
		goto free_format16;

	len = StrLen(str16);
	if (str_to_stra((CHAR8 *)str, str16, len) == EFI_SUCCESS) {
		ret = 0;
		str[len] = '\0';
	}

	FreePool(str16);
free_format16:
	FreePool(format16);
	return ret;
}

int snprintf(char *str, size_t size, const char *format, ...)
{
	va_list args;
	int ret;

	va_start(args, format);
	ret = vsnprintf(str, size, format, args);
	va_end(args);
	return ret;
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	UINTN len;
	int ret = -1;
	CHAR16 *format16 = stra_to_str((CHAR8 *)format);
	if (!format16)
		return -1;

	CHAR16 *str16 = AllocatePool(size * sizeof(CHAR16));
	if (!str16)
		goto free_format16;

	len = VSPrint(str16, size * sizeof(CHAR16), format16, ap);

	if (str_to_stra((CHAR8 *)str, str16, len + 1) == EFI_SUCCESS) {
		ret = 0;
		str[len] = '\0';
	}

	FreePool(str16);
free_format16:
	FreePool(format16);
	return ret;
}
