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
#include <vars.h>
#include <string.h>
#include <ui.h>

#include "uefi_utils.h"
#include "gpt.h"
#include "fastboot.h"
#include "fastboot_usb.h"
#include "flash.h"
#include "fastboot_oem.h"
#include "fastboot_ui.h"
#include "smbios.h"
#include "info.h"

#define MAGIC_LENGTH 64
#define MAX_DOWNLOAD_SIZE 512*1024*1024
#define MAX_VARIABLE_LENGTH 128

struct fastboot_cmd {
	struct fastboot_cmd *next;
	const CHAR8 *prefix;
	unsigned prefix_len;
	BOOLEAN restricted;
	fastboot_handle handle;
};

struct fastboot_var {
	struct fastboot_var *next;
	char name[MAX_VARIABLE_LENGTH];
	char value[MAX_VARIABLE_LENGTH];
};

enum fastboot_states {
	STATE_OFFLINE,
	STATE_COMMAND,
	STATE_COMPLETE,
	STATE_START_DOWNLOAD,
	STATE_DOWNLOAD,
	STATE_GETVAR,
	STATE_ERROR,
};

EFI_GUID guid_linux_data = {0x0fc63daf, 0x8483, 0x4772, {0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}};

static struct fastboot_cmd *cmdlist;
static struct fastboot_cmd *oem_cmdlist;
static char command_buffer[MAGIC_LENGTH];
static struct fastboot_var *varlist;
static enum fastboot_states fastboot_state = STATE_OFFLINE;
/* Download buffer and size, for download and flash commands */
static void *dlbuffer;
static unsigned dlsize;

static const char *flash_verified_whitelist[] = {
	"bootloader",
	"boot",
	"system",
	"oem", /* alternate name for vendor */
	"vendor",
	"recovery",
	/* Following three needed even though not specifically listed
	 * since formatting a partition necessitates flashing a sparse
	 * filesystem image */
	"cache",
	"data",
	"userdata",
	NULL
};

static const char *erase_verified_whitelist[] = {
	"cache",
	"data",
	"userdata",
	/* following three needed so we can flash them even though not
	 * specifically listed, they all contain filesystems which can
	 * be sent over as sparse images */
	"system",
	"vendor",
	"oem",
	NULL
};

static void cmd_register(struct fastboot_cmd **list, const char *prefix,
			 fastboot_handle handle, BOOLEAN restricted)
{
	struct fastboot_cmd *cmd;
	cmd = AllocatePool(sizeof(*cmd));
	if (!cmd) {
		error(L"Failed to allocate fastboot command %a", prefix);
		return;
	}
	cmd->prefix = (CHAR8 *)prefix;
	cmd->prefix_len = strlen((const CHAR8 *)prefix);
	cmd->restricted = restricted;
	cmd->handle = handle;
	cmd->next = *list;
	*list = cmd;
}

void fastboot_register(const char *prefix,
		       fastboot_handle handle,
		       BOOLEAN restricted)
{
	cmd_register(&cmdlist, prefix, handle, restricted);
}

void fastboot_oem_register(const char *prefix,
			   fastboot_handle handle,
			   BOOLEAN restricted)
{
	cmd_register(&oem_cmdlist, prefix, handle, restricted);
}

struct fastboot_var *fastboot_getvar(const char *name)
{
	struct fastboot_var *var;

	for (var = varlist; var; var = var->next)
		if (!strcmp((CHAR8 *)name, (const CHAR8 *)var->name))
			return var;

	return NULL;
}

/*
 * remove all fastboot variable which starts with partition-
 */
#define MATCH_PART "partition-"
static void clean_partition_var(void)
{
	struct fastboot_var *var;
	struct fastboot_var *old_varlist;
	struct fastboot_var *next;

	old_varlist = varlist;
	varlist = NULL;

	for (var = old_varlist; var; var = next) {
		next = var->next;
		if (!memcmp(MATCH_PART, var->name, strlena((CHAR8 *) MATCH_PART))) {
			FreePool(var);
		} else {
			var->next = varlist;
			varlist = var;
		}
	}
}

void fastboot_publish(const char *name, const char *value)
{
	struct fastboot_var *var;
	UINTN namelen = strlena((CHAR8 *) name) + 1;
	UINTN valuelen = strlena((CHAR8 *) value) + 1;

	if (namelen > sizeof(var->name) ||
	    valuelen > sizeof(var->value)) {
		error(L"name or value too long");
		return;
	}
	var = fastboot_getvar(name);
	if (!var) {
		var = AllocateZeroPool(sizeof(*var));
		if (!var) {
			error(L"Failed to allocate variable %a", name);
			return;
		}
		var->next = varlist;
		varlist = var;
	}
	CopyMem(var->name, name, namelen);
	CopyMem(var->value, value, valuelen);
}

static void publish_partsize(void)
{
	struct gpt_partition_interface *gparti;
	UINTN part_count;
	UINTN i;

	gpt_list_partition(&gparti, &part_count);

	for (i = 0; i < part_count; i++) {
		char fastboot_var[MAX_VARIABLE_LENGTH];
		char partsize[MAX_VARIABLE_LENGTH];
		UINT64 size;

		size = gparti[i].bio->Media->BlockSize
			* (gparti[i].part.ending_lba + 1 - gparti[i].part.starting_lba);

		if (EFI_ERROR(snprintf((CHAR8 *)fastboot_var, sizeof(fastboot_var),
				       (CHAR8 *)"partition-size:%s", gparti[i].part.name)))
			continue;
		if (EFI_ERROR(snprintf((CHAR8 *)partsize, sizeof(partsize),
				       (CHAR8 *)"0x%lX", size)))
			continue;

		fastboot_publish(fastboot_var, partsize);

		if (EFI_ERROR(snprintf((CHAR8 *)fastboot_var, sizeof(fastboot_var),
				       (CHAR8 *)"partition-type:%s", gparti[i].part.name)))
			continue;

		if (!CompareGuid(&gparti[i].part.type, &guid_linux_data))
			fastboot_publish(fastboot_var, "ext4");
		else if (!CompareGuid(&gparti[i].part.type, &EfiPartTypeSystemPartitionGuid))
			fastboot_publish(fastboot_var, "vfat");
		else
			fastboot_publish(fastboot_var, "none");
	}
}

static void fastboot_ack(const char *code, const char *format, va_list ap)
{
	CHAR8 response[MAGIC_LENGTH];
	CHAR8 reason[MAGIC_LENGTH];
	EFI_STATUS ret;
	int i;

	ret = vsnprintf(reason, MAGIC_LENGTH, (CHAR8 *)format, ap);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, "Failed to build reason string");
		return;
	}
	ZeroMem(response, sizeof(response));

	/* Nip off trailing newlines */
	for (i = strlen(reason); (i > 0) && reason[i - 1] == '\n'; i--)
		reason[i - 1] = '\0';
	snprintf(response, MAGIC_LENGTH, (CHAR8 *)"%a%a", code, reason);
	debug(L"SENT %a %a", code, reason);
	if (usb_write(response, MAGIC_LENGTH) < 0)
		fastboot_state = STATE_ERROR;
}

void fastboot_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fastboot_ack("INFO", fmt, ap);
	va_end(ap);
}

void fastboot_fail(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fastboot_ack("FAIL", fmt, ap);
	va_end(ap);

	fastboot_state = STATE_COMPLETE;
}

void fastboot_okay(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fastboot_ack("OKAY", fmt, ap);
	va_end(ap);

	fastboot_state = STATE_COMPLETE;
}

static BOOLEAN is_in_white_list(const CHAR8 *key, const char **white_list)
{
	do {
		if (!strcmp(key, (CHAR8 *)*white_list))
			return TRUE;
	} while (*++white_list);

	return FALSE;
}

static void cmd_flash(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	CHAR16 *label;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	if (device_is_verified()
	    && !is_in_white_list(argv[1], flash_verified_whitelist)) {
		error(L"Flash %a is prohibited in verified state.", argv[1]);
		fastboot_fail("Prohibited command in verified state.");
		return;
	}

	label = stra_to_str((CHAR8*)argv[1]);
	if (!label) {
		error(L"Failed to get label %a", argv[1]);
		fastboot_fail("Allocation error");
		return;
	}
	ui_print(L"Flashing %s ...", label);

	ret = flash(dlbuffer, dlsize, label);
	FreePool(label);
	if (EFI_ERROR(ret))
		fastboot_fail("Flash failure: %r", ret);
	else {
		ui_print(L"Flash done.");
		fastboot_okay("");
		/* update partition variable in case it has changed */
		if (ret & REFRESH_PARTITION_VAR) {
			clean_partition_var();
			publish_partsize();
		}
	}
}

static void cmd_erase(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	CHAR16 *label;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	if (device_is_verified()
	    && !is_in_white_list(argv[1], erase_verified_whitelist)) {
		error(L"Erase %a is prohibited in verified state.", argv[1]);
		fastboot_fail("Prohibited command in verified state.");
		return;
	}

	label = stra_to_str((CHAR8*)argv[1]);
	if (!label) {
		error(L"Failed to get label %a", argv[1]);
		fastboot_fail("Allocation error");
		return;
	}
	ui_print(L"Erasing %s ...", label);
	ret = erase_by_label(label);
	FreePool(label);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Erase failure: %r", ret);
		return;
	}

	ui_print(L"Erase done.");
	fastboot_okay("");
}

static void cmd_boot(__attribute__((__unused__)) INTN argc,
		     __attribute__((__unused__)) CHAR8 **argv)
{
	if (device_is_verified()) {
		error(L"Boot command is prohibited in verified state.");
		fastboot_fail("Prohibited command in verified state.");
		return;
	}

	fastboot_usb_stop(dlbuffer, NULL, 0, UNKNOWN_TARGET);
	ui_print(L"Booting received image ...");
	fastboot_okay("");
}

static void worker_getvar_all(struct fastboot_var *start)
{
	static struct fastboot_var *var;
	if (start)
		var = start;

	if (var) {
		fastboot_info("%a: %a", var->name, var->value);
		var = var->next;
	} else
		fastboot_okay("");
}

static void cmd_getvar(INTN argc, CHAR8 **argv)
{
	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	if (!strcmp(argv[1], (CHAR8 *)"all")) {
		fastboot_state = STATE_GETVAR;
		worker_getvar_all(varlist);
	} else {
		struct fastboot_var *var;
		var = fastboot_getvar((char *)argv[1]);
		if (var && var->value) {
			fastboot_okay("%a", var->value);
		} else {
			fastboot_okay("");
		}
	}
}

static void cmd_continue(__attribute__((__unused__)) INTN argc,
			 __attribute__((__unused__)) CHAR8 **argv)
{
	ui_print(L"Continuing ...");
	fastboot_usb_stop(NULL, NULL, 0, NORMAL_BOOT);
	fastboot_okay("");
}

static void cmd_reboot(__attribute__((__unused__)) INTN argc,
		       __attribute__((__unused__)) CHAR8 **argv)
{
	ui_print(L"Rebooting ...");
	fastboot_usb_stop(NULL, NULL, 0, REBOOT);
	fastboot_okay("");
}

static void cmd_reboot_bootloader(__attribute__((__unused__)) INTN argc,
				  __attribute__((__unused__)) CHAR8 **argv)
{
	ui_print(L"Rebooting to bootloader ...");
	fastboot_okay("");
	reboot(L"bootloader");
}

static struct fastboot_cmd *get_cmd(struct fastboot_cmd *list, const CHAR8 *name)
{
	struct fastboot_cmd *cmd;
	for (cmd = list; cmd; cmd = cmd->next)
		if (!memcmp(name, cmd->prefix, cmd->prefix_len))
			return cmd;

	return NULL;
}

static void cmd_oem(INTN argc, CHAR8 **argv)
{
	struct fastboot_cmd *cmd;

	if (argc < 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	cmd = get_cmd(oem_cmdlist, argv[1]);
	if (!cmd) {
		fastboot_fail("unknown command 'oem %a'", argv[1]);
		return;
	}
	if (cmd->restricted && device_is_locked()) {
		fastboot_fail("'oem %a' not allowed on locked devices", argv[1]);
		return;
	}

	cmd->handle(argc - 1, argv + 1);
}

static void fastboot_read_command(void)
{
	usb_read(command_buffer, sizeof(command_buffer));
}
#define BLK_DOWNLOAD (8*1024*1024)

static void cmd_download(INTN argc,
			 CHAR8 **argv)
{
	char response[MAGIC_LENGTH];
	UINTN newdlsize;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	newdlsize = strtoul((const char *)argv[1], NULL, 16);

	ui_print(L"Receiving %d bytes ...", newdlsize);
	if (newdlsize == 0) {
		fastboot_fail("no data to download");
		return;
	} else if (newdlsize > MAX_DOWNLOAD_SIZE) {
		fastboot_fail("data too large");
		return;
	}
	if (dlbuffer) {
		if (newdlsize > dlsize) {
			FreePool(dlbuffer);
			dlbuffer = AllocatePool(newdlsize);
		}
	} else {
		dlbuffer = AllocatePool(newdlsize);
	}
	if (!dlbuffer) {
		error(L"Failed to allocate download buffer (0x%x bytes)", dlsize);
		fastboot_fail("Memory allocation failure");
		return;
	}
	dlsize = newdlsize;

	sprintf(response, "DATA%08x", dlsize);
	if (usb_write(response, strlen((CHAR8 *)response)) < 0) {
		fastboot_state = STATE_ERROR;
		return;
	}
	fastboot_state = STATE_START_DOWNLOAD;
}

static void worker_download(void)
{
	int len;

	if (dlsize > BLK_DOWNLOAD)
		len = BLK_DOWNLOAD;
	else
		len = dlsize;

	if (usb_read(dlbuffer, len)) {
		error(L"Failed to receive %d bytes", dlsize);
		fastboot_fail("Usb receive failed");
		return;
	}
	fastboot_state = STATE_DOWNLOAD;
}

static void fastboot_process_tx(__attribute__((__unused__)) void *buf,
				__attribute__((__unused__)) unsigned len)
{
	switch (fastboot_state) {
	case STATE_GETVAR:
		worker_getvar_all(NULL);
		break;
	case STATE_COMPLETE:
		fastboot_read_command();
		break;
	case STATE_START_DOWNLOAD:
		worker_download();
		break;
	default:
		/* Nothing to do */
		break;
	}
}

#define MAX_ARGS 64

static void split_args(CHAR8 *str, INTN *argc, CHAR8 *argv[])
{
	argv[0] = str;
	while (*str != ' ' && *str != ':' && str != '\0')
		str++;

	*argc = 1;
	while (*str != '\0' && *argc < MAX_ARGS) {
		*str++ = '\0';
		argv[(*argc)++] = str;
		while (*str != '\0' && *str != ' ')
			str++;
	}
}

static void fastboot_process_rx(void *buf, unsigned len)
{
	struct fastboot_cmd *cmd;
	static unsigned received_len = 0;
	CHAR8 *s;
	CHAR8 *argv[MAX_ARGS];
	INTN argc;
	int req_len;

	switch (fastboot_state) {
	case STATE_DOWNLOAD:
		received_len += len;
		if (dlsize > MiB)
			debug(L"\rRX %d MiB / %d MiB", received_len/MiB, dlsize / MiB);
		else
			debug(L"\rRX %d KiB / %d KiB", received_len/1024, dlsize / 1024);
		if (received_len < dlsize) {
			s = buf;
			req_len = dlsize - received_len;
			if (req_len > BLK_DOWNLOAD)
				req_len = BLK_DOWNLOAD;
			usb_read(&s[len], req_len);
		} else {
			fastboot_state = STATE_COMMAND;
			fastboot_okay("");
		}
		break;
	case STATE_COMPLETE:
		((CHAR8 *)buf)[len] = 0;
		debug(L"GOT %a", (CHAR8 *)buf);

		fastboot_state = STATE_COMMAND;

		cmd = get_cmd(cmdlist, buf);
		if (cmd) {
			if (cmd->restricted && device_is_locked()) {
				fastboot_fail("command not allowed on locked devices");
				return;
			}
			split_args(buf, &argc, argv);
			cmd->handle(argc, argv);
			received_len = 0;

			if (fastboot_state == STATE_COMMAND)
				fastboot_fail("unknown reason");
		} else {
			error(L"unknown command '%a'", buf);
			fastboot_fail("unknown command");
		}
		break;
	default:
		error(L"Inconsistent fastboot state: 0x%x", fastboot_state);
	}
}

static void fastboot_start_callback(void)
{
	fastboot_state = STATE_COMPLETE;
	fastboot_read_command();
}

EFI_STATUS fastboot_start(void **bootimage, void **efiimage, UINTN *imagesize,
			  enum boot_target *target)
{
	EFI_STATUS ret;
	char download_max_str[30];

	ret = uefi_call_wrapper(BS->SetWatchdogTimer, 4, 0, 0, 0, NULL);
	if (EFI_ERROR(ret) && ret != EFI_UNSUPPORTED) {
		efi_perror(ret, L"Couldn't disable watchdog timer");
		/* Might as well continue even though this failed ... */
	}

	fastboot_publish("product", info_product());
	fastboot_publish("version-bootloader", info_bootloader_version());

	if (EFI_ERROR(snprintf((CHAR8 *)download_max_str, sizeof(download_max_str),
			       (CHAR8 *)"0x%lX", MAX_DOWNLOAD_SIZE)))
		debug(L"Failed to set download_max_str string");
	else
		fastboot_publish("max-download-size", download_max_str);

	fastboot_register("download:", cmd_download, TRUE);
	fastboot_register("flash:", cmd_flash, TRUE);
	fastboot_register("erase:", cmd_erase, TRUE);
	fastboot_register("getvar:", cmd_getvar, FALSE);
	fastboot_register("boot", cmd_boot, TRUE);
	fastboot_register("continue", cmd_continue, FALSE);
	fastboot_register("reboot", cmd_reboot, FALSE);
	fastboot_register("reboot-bootloader", cmd_reboot_bootloader, FALSE);

	publish_partsize();

	fastboot_register("oem", cmd_oem, FALSE);
	fastboot_oem_init();
	ret = fastboot_ui_init();
	if (EFI_ERROR(ret))
		efi_perror(ret, "Fastboot UI initialization failed, continue anyway.");

	ret = fastboot_usb_start(fastboot_start_callback, fastboot_process_rx,
				 fastboot_process_tx, bootimage, efiimage,
				 imagesize, target);

	fastboot_ui_destroy();
	return ret;
}
