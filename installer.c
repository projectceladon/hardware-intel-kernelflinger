/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Jeremy Compostella <jeremy.compostella@intel.com>
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
 */

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>
#include <stdio.h>

#include "lib.h"
#include "uefi_utils.h"
#include "protocol.h"
#include "flash.h"
#include "gpt.h"
#include "sparse.h"
#include "sparse_format.h"
#include "fastboot.h"
#include "fastboot_oem.h"
#include "fastboot_usb.h"

static BOOLEAN last_cmd_succeeded;
static fastboot_handle fastboot_flash_cmd;
static EFI_FILE_IO_INTERFACE *file_io_interface;
static data_callback_t fastboot_rx_cb, fastboot_tx_cb;
static CHAR16 *installer_batch_filename;
static CHAR8 DEFAULT_OPTIONS[] = "--batch installer.cmd";
static BOOLEAN need_tx_cb;

#define inst_perror(ret, x, ...) do { \
	fastboot_fail(x ": %r", ##__VA_ARGS__, ret); \
} while (0);

static void flush_tx_buffer(void)
{
	while (need_tx_cb) {
		need_tx_cb = FALSE;
		fastboot_tx_cb(NULL, 0);
	}
}

static void run_command(void *line, INTN size)
{
	fastboot_rx_cb(line, size);
	flush_tx_buffer();
}

static void run_fastboot_handle(fastboot_handle handle, INTN argc, CHAR8 **argv)
{
	handle(argc, argv);
	flush_tx_buffer();
}

static void installer_flash_buffer(void *data, unsigned size,
				   INTN argc, CHAR8 **argv)
{
	fastboot_set_dlbuffer(data, size);
	run_fastboot_handle(fastboot_flash_cmd, argc, argv);
	fastboot_set_dlbuffer(NULL, 0);
}

static EFI_STATUS read_file(EFI_FILE *file, UINTN size, void *data)
{
	EFI_STATUS ret;
	UINTN nsize = size;

	ret = uefi_call_wrapper(file->Read, 3, file, &nsize, data);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Failed to read file");
		return ret;
	}
	if (size != nsize) {
		fastboot_fail("Failed to read %d bytes (only %d read)",
			      size, nsize);
		return EFI_INVALID_PARAMETER;
	}

	return ret;
}

/* This function splits a huge sparse file into smaller ones and flash
   them. */
static void installer_split_and_flash(CHAR16 *filename, UINTN size,
				      UINTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	struct sparse_header sph, *new_sph;
	struct chunk_header *ckh, *skip_ckh;
	void *buf, *data;
	UINTN remaining_data = size;
	UINTN data_size, read_size, flash_size, header_size, already_read;
	void *read_ptr;
	INTN nb_chunks;
	EFI_FILE *file;
	__le32 blk_count;

	ret = uefi_open_file(file_io_interface, filename, &file);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Failed to open %s file", filename);
		return;
	}

	ret = read_file(file, sizeof(sph), &sph);
	if (EFI_ERROR(ret))
		return;
	remaining_data -= sizeof(sph);

	if (!is_sparse_image((void *) &sph, sizeof(sph))) {
		fastboot_fail("sparse file expected");
		return;
	}

	buf = AllocatePool(MAX_DOWNLOAD_SIZE);
	if (!buf) {
		fastboot_fail("Failed to allocate %d bytes", MAX_DOWNLOAD_SIZE);
		return;
	}
	data = buf;

	/* New sparse header. */
	memcpy(data, &sph, sizeof(sph));
	new_sph = data;
	data += sizeof(*new_sph);

	/* Sparse skip chunk. */
	skip_ckh = data;
	skip_ckh->chunk_type = CHUNK_TYPE_DONT_CARE;
	skip_ckh->total_sz = sizeof(*skip_ckh);
	data += sizeof(*skip_ckh);

	header_size = data - buf;
	data_size = MAX_DOWNLOAD_SIZE - header_size;
	nb_chunks = sph.total_chunks;
	read_size = data_size;
	read_ptr = data;
	blk_count = 0;

	while (nb_chunks > 0 && remaining_data > 0) {
		new_sph->total_chunks = 1;
		new_sph->total_blks = skip_ckh->chunk_sz = blk_count;

		if (remaining_data < read_size)
			read_size = remaining_data;

		/* Read a new piece of the input sparse file. */
		ret = read_file(file, read_size, read_ptr);
		if (EFI_ERROR(ret))
			goto exit;
		remaining_data -= read_size;

		/* Process the loaded chunks to build the new header
		   and the skip chunk. */
		flash_size = header_size;
		ckh = data;
		while ((void *)ckh + sizeof(*ckh) <= read_ptr + read_size &&
		       (void *)ckh + ckh->total_sz <= read_ptr + read_size) {
			if (nb_chunks == 0) {
				fastboot_fail("Corrupted sparse file: too many chunks");
				goto exit;
			}
			flash_size += ckh->total_sz;
			new_sph->total_blks += ckh->chunk_sz;
			blk_count += ckh->chunk_sz;
			new_sph->total_chunks++;
			nb_chunks--;
			ckh = (void *)ckh + ckh->total_sz;
		}

		/* Handle the inconsistencies. */
		if (flash_size == header_size) {
			if ((void *)ckh + sizeof(*ckh) < read_ptr + read_size) {
				fastboot_fail("Corrupted sparse file");
				goto exit;
			} else {
				fastboot_fail("Found a too big chunk");
				goto exit;
			}
		}

		installer_flash_buffer(buf, flash_size, argc, argv);
		if (!last_cmd_succeeded)
			goto exit;

		/* Move the incomplete chunk from the end to the
		   beginning of the buffer. */
		if (buf + flash_size < read_ptr + read_size) {
			already_read = read_ptr + read_size - (void *)ckh;
			memcpy(data, ckh, already_read);
			read_size = data_size - already_read;
			read_ptr = data + already_read;
		} else {
			read_size = data_size;
			read_ptr = data;
		}
	}

exit:
	FreePool(buf);
}

static void installer_flash_cmd(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	CHAR16 *filename;
	void *data;
	UINTN size;

	if (argc != 3) {
		fastboot_fail("Flash command requires exactly 3 arguments");
		return;
	}

	/* The fastboot flash command does not want the file parameter. */
	argc--;

	filename = stra_to_str(argv[2]);
	if (!filename) {
		fastboot_fail("Failed to convert CHAR8 filename to CHAR16");
		return;
	}

	ret = uefi_get_file_size(file_io_interface, filename, &size);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Failed to get %s file size", filename);
		goto exit;
	}

	if (size > MAX_DOWNLOAD_SIZE) {
		installer_split_and_flash(filename, size, argc, argv);
		goto exit;
	}

	ret = uefi_read_file(file_io_interface, filename, &data, &size);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Unable to read file %s", filename);
		goto exit;
	}

	installer_flash_buffer(data, size, argc, argv);
	FreePool(data);

exit:
	FreePool(filename);
}

static CHAR16 *get_format_image_filename(CHAR8 *label)
{
	CHAR8 *filename;
	CHAR16 *filename16;
	UINTN label_length;

	if (!strcmp(label, (CHAR8 *)"data"))
		label = (CHAR8 *)"userdata";

	label_length = strlena(label);
	filename = AllocateZeroPool(label_length + 5);
	if (!filename) {
		fastboot_fail("Unable to allocate CHAR8 filename buffer");
		return NULL;
	}
	memcpy(filename, label, label_length);
	memcpy(filename + label_length, ".img", 4);
	filename16 = stra_to_str(filename);
	FreePool(filename);
	if (!filename16) {
		fastboot_fail("Unable to allocate CHAR16 filename buffer");
		return NULL;
	}

	return filename16;
}

/* Simulate the fastboot host format command:
   1. get a filesystem image from a file;
   2. erase the partition;
   3. flash the filesystem image; */
static void installer_format(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	void *data = NULL;
	UINTN size;
	CHAR16 *filename;
	struct fastboot_cmd *cmd;

	filename = get_format_image_filename(argv[1]);
	if (!filename)
		return;

	ret = uefi_read_file(file_io_interface, filename, &data, &size);
	if (ret == EFI_NOT_FOUND && !StrCmp(L"userdata.img", filename)) {
		fastboot_info("userdata.img is missing, cannot format %a", argv[1]);
		fastboot_info("Android fs_mgr will manage this");
	} else if (EFI_ERROR(ret)) {
		inst_perror(ret, "Unable to read file %s", filename);
		goto free_filename;
	}

	cmd = get_root_cmd((CHAR8 *)"erase");
	if (!cmd) {
		fastboot_fail("Unknown 'erase' command");
		goto free_data;
	}

	run_fastboot_handle(cmd->handle, argc, argv);
	if (!last_cmd_succeeded)
		goto free_data;

	if (data)
		installer_flash_buffer(data, size, argc, argv);

free_data:
	FreePool(data);
free_filename:
	FreePool(filename);
}

static void batch(__attribute__((__unused__)) INTN argc,
		  __attribute__((__unused__)) CHAR8 **argv)
{
	if (argc != 2) {
		fastboot_fail("Batch command takes one parameter");
		return;
	}

	installer_batch_filename = stra_to_str(argv[1]);
	if (!installer_batch_filename) {
		fastboot_fail("Failed to convert CHAR8 filename to CHAR16");
		return;
	}

	fastboot_okay("");
}

static void usage(__attribute__((__unused__)) INTN argc,
		  __attribute__((__unused__)) CHAR8 **argv)
{
	Print(L"Usage: installer [OPTIONS | COMMANDS]\n");
	Print(L"  installer is an EFI application acting like the fastboot command.\n\n");
	Print(L" COMMANDS               fastboot commands (cf. the fastboot manual page)\n");
	Print(L" --help, -h             print this help and exit\n");
	Print(L" --batch, -b FILE       run all the fastboot commands of FILE\n");
	Print(L"If no option is provided, the installer assumes '%a'\n", DEFAULT_OPTIONS);
	Print(L"Note: 'boot', 'update', 'flash-raw' and 'flashall' commands are NOT supported\n");

	fastboot_okay("");
}

static void unsupported_cmd(__attribute__((__unused__)) INTN argc,
			    CHAR8 **argv)
{
	fastboot_fail("installer does not the support the '%a' command", argv[0]);
}

static struct replacements {
	CHAR8 *name;
	fastboot_handle new_handle;
	fastboot_handle *save_handle;
	enum device_state min_state;
} REPLACEMENTS[] = {
	/* Fastboot changes. */
	{ (CHAR8 *)"flash",	installer_flash_cmd,	&fastboot_flash_cmd,	UNKNOWN_STATE},
	{ (CHAR8 *)"format",	installer_format,	NULL, 			VERIFIED },
	/* Unsupported commands. */
	{ (CHAR8 *)"update",	unsupported_cmd,	NULL,			UNKNOWN_STATE },
	{ (CHAR8 *)"flashall",	unsupported_cmd,	NULL,			UNKNOWN_STATE },
	{ (CHAR8 *)"boot",	unsupported_cmd,	NULL,			UNKNOWN_STATE },
	{ (CHAR8 *)"devices",	unsupported_cmd,	NULL,			UNKNOWN_STATE },
	{ (CHAR8 *)"download",	unsupported_cmd,	NULL,			UNKNOWN_STATE },
	/* Installer specific commands. */
	{ (CHAR8 *)"--help",	usage,			NULL,			LOCKED },
	{ (CHAR8 *)"-h",	usage,			NULL,			LOCKED },
	{ (CHAR8 *)"--batch",	batch,			NULL,			LOCKED },
	{ (CHAR8 *)"-b",	batch,			NULL,			LOCKED },
};

static void installer_replace_functions()
{
	struct fastboot_cmd *cmd;
	UINTN i;

	for (i = 0; i < ARRAY_SIZE(REPLACEMENTS); i++) {
		cmd = get_root_cmd(REPLACEMENTS[i].name);

		if (cmd && REPLACEMENTS[i].save_handle)
			*(REPLACEMENTS[i].save_handle) = cmd->handle;

		if (cmd && REPLACEMENTS[i].new_handle)
			cmd->handle = REPLACEMENTS[i].new_handle;

		if (!cmd && REPLACEMENTS[i].new_handle)
			fastboot_register((char *)REPLACEMENTS[i].name,
					  REPLACEMENTS[i].new_handle,
					  REPLACEMENTS[i].min_state);
	}
}

static void skip_whitespace(char **line)
{
	char *cur = *line;
	while (*cur && isspace(*cur))
		cur++;
	*line = cur;
}

static void run_batch()
{
	EFI_STATUS ret;
	void *data;
	UINTN size;
	char *buf, *line, *eol, *p;
	int lineno = 0;

	ret = uefi_read_file(file_io_interface, installer_batch_filename, &data, &size);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Failed to read %s file", installer_batch_filename);
		FreePool(installer_batch_filename);
		return;
	}
	FreePool(installer_batch_filename);

	/* Extra byte so we can always terminate the last line. */
	buf = AllocatePool(size + 1);
	if (!buf) {
		fastboot_fail("Failed to allocate buffer");
		FreePool(data);
		return;
	}
	memcpy(buf, data, size);
	buf[size] = 0;

	for (line = buf; line - buf < (ssize_t)size; line = eol+1) {
		lineno++;

		/* Detect line and terminate. */
		eol = (char *)strchr((CHAR8 *)line, '\n');
		if (!eol)
			eol = line + strlen((CHAR8 *)line);
		*eol = 0;

		/* Snip space character for sanity. */
		p = line + strlen((CHAR8 *)line);
		while (p > line && isspace(*(p-1)))
			*(--p) = 0;

		skip_whitespace(&line);
		if (*line == '\0')
			continue;

		Print(L"Starting command: '%a'\n", line);
		run_command(line, strlen((CHAR8 *)line));
		if (!last_cmd_succeeded) {
			error(L"Failed at line %d", lineno);
			break;
		}
		Print(L"Command successfully executed\n");
	}

	FreePool(data);
	FreePool(buf);
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *_table)
{
	EFI_STATUS ret;
	EFI_LOADED_IMAGE *loaded_img = NULL;
	CHAR8 *options, *buf;
	UINTN i;

	InitializeLib(image, _table);

	ret = handle_protocol(image, &LoadedImageProtocol, (void **)&loaded_img);
	if (ret != EFI_SUCCESS) {
		inst_perror(ret, "LoadedImageProtocol error");
		return ret;
	}

	/* Initialize File IO interface. */
	ret = uefi_call_wrapper(BS->HandleProtocol, 3, loaded_img->DeviceHandle,
				&FileSystemProtocol, (void *)&file_io_interface);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Failed to get FileSystemProtocol");
		return ret;
	}

	/* Prepare parameters. */
	UINTN size = StrLen(loaded_img->LoadOptions) + 1;
	buf = options = AllocatePool(size);
	if (!options) {
		fastboot_fail("Unable to allocate buffer for parameters");
		return EFI_OUT_OF_RESOURCES;
	}
	str_to_stra(options, loaded_img->LoadOptions, size);
	/* Snip control and space characters. */
	for (i = size - 1; options[i] <= ' '; i--)
		options[i] = '\0';
	/* Drop the first parameter.  */
	options = strchr(options, ' ');
	skip_whitespace((char **)&options);

	/* Initialize the fastboot library. */
	fastboot_start(NULL, NULL, NULL, NULL);
	installer_replace_functions();
	if (!fastboot_flash_cmd) {
		fastboot_fail("Failed to get the flash handle");
		goto exit;
	}

	/* Process options. */
	run_command(*options != '\0' ? options : DEFAULT_OPTIONS,
		       *options != '\0' ? strlen(options) + 1 : sizeof(DEFAULT_OPTIONS));
	if (installer_batch_filename)
		run_batch();

exit:
	FreePool(buf);
	return last_cmd_succeeded ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/* USB wrapper functions. */
EFI_STATUS fastboot_usb_start(start_callback_t start_cb,
			      data_callback_t rx_cb,
			      data_callback_t tx_cb,
			      __attribute__((__unused__)) void **bootimage,
			      __attribute__((__unused__)) void **efiimage,
			      __attribute__((__unused__)) UINTN *imagesize,
			      __attribute__((__unused__)) enum boot_target *target)
{
	fastboot_tx_cb = tx_cb;
	fastboot_rx_cb = rx_cb;
	start_cb();

	return EFI_SUCCESS;
}

EFI_STATUS fastboot_usb_stop(__attribute__((__unused__)) void *bootimage,
			     __attribute__((__unused__)) void *efiimage,
			     __attribute__((__unused__)) UINTN imagesize,
			     enum boot_target target)
{
	if (target == NORMAL_BOOT || target == REBOOT)
		reboot(NULL);

	return EFI_SUCCESS;
}

int usb_read(__attribute__((__unused__)) void *buf,
	     __attribute__((__unused__)) unsigned len)
{
	return 0;
}

int usb_write(void *pBuf, uint32_t size)
{
#define PREFIX_LEN 4

	if (size < PREFIX_LEN)
		return 0;

	if (!memcmp((CHAR8 *)"INFO", pBuf, PREFIX_LEN)) {
		Print(L"(bootloader) %a\n", pBuf + PREFIX_LEN);
		need_tx_cb = TRUE;
	} if (!memcmp((CHAR8 *)"OKAY", pBuf, PREFIX_LEN)) {
		if (((char *)pBuf)[PREFIX_LEN] != '\0')
			Print(L"%a\n", pBuf + PREFIX_LEN);
		last_cmd_succeeded = TRUE;
	} else if (!memcmp((CHAR8 *)"FAIL", pBuf, PREFIX_LEN)) {
		error(L"%a", pBuf + PREFIX_LEN);
		last_cmd_succeeded = FALSE;
	}

	return 0;
}

/* UI wrapper functions. */
void fastboot_ui_destroy(void)
{
}

void fastboot_ui_refresh(void)
{
}

EFI_STATUS fastboot_ui_init(void)
{
	return EFI_SUCCESS;
}
