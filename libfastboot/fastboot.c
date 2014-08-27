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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "uefi_utils.h"
#include "gpt.h"

#include "fastboot.h"
#include "fastboot_usb.h"
#include "flash.h"
#include "fastboot_oem.h"

#define MAGIC_LENGTH 64
#define MAX_DOWNLOAD_SIZE 512*1024*1024
#define MAX_VARIABLE_LENGTH 128

struct fastboot_cmd {
	struct fastboot_cmd *next;
	const CHAR8 *prefix;
	unsigned prefix_len;
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

static void cmd_register(struct fastboot_cmd **list, const char *prefix,
			 fastboot_handle handle)
{
	struct fastboot_cmd *cmd;
	cmd = AllocatePool(sizeof(*cmd));
	if (!cmd) {
		error(L"Failed to allocate fastboot command %a\n", prefix);
		return;
	}
	cmd->prefix = (CHAR8 *)prefix;
	cmd->prefix_len = strlen((const CHAR8 *)prefix);
	cmd->handle = handle;
	cmd->next = *list;
	*list = cmd;
}

void fastboot_register(const char *prefix,
		       fastboot_handle handle)
{
	cmd_register(&cmdlist, prefix, handle);
}

void fastboot_oem_register(const char *prefix,
			   fastboot_handle handle)
{
	cmd_register(&oem_cmdlist, prefix, handle);
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
		error(L"name or value too long\n");
		return;
	}
	var = fastboot_getvar(name);
	if (!var) {
		var = AllocateZeroPool(sizeof(*var));
		if (!var) {
			error(L"Failed to allocate variable %a\n", name);
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

		size = gparti[i].bio->Media->BlockSize * (gparti[i].part.ending_lba + 1 - gparti[i].part.starting_lba);

		if (snprintf(fastboot_var, sizeof(fastboot_var), "partition-size:%s", gparti[i].part.name) < 0)
			continue;
		if (snprintf(partsize, sizeof(partsize), "0x%lX", size) < 0)
			continue;

		fastboot_publish(fastboot_var, partsize);

		if (snprintf(fastboot_var, sizeof(fastboot_var), "partition-type:%s", gparti[i].part.name) < 0)
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
	char response[MAGIC_LENGTH];
	char reason[MAGIC_LENGTH];
	int i;

	if (vsnprintf(reason, MAGIC_LENGTH, format, ap) < 0) {
		error(L"Failed to build reason string\n");
		return;
	}
	ZeroMem(response, sizeof(response));

	/* Nip off trailing newlines */
	for (i = strlen((CHAR8 *)reason); (i > 0) && reason[i - 1] == '\n'; i--)
		reason[i - 1] = '\0';
	snprintf(response, MAGIC_LENGTH, "%a%a", code, reason);
	debug("SENT %a %a\n", code, reason);
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

static void cmd_flash(CHAR8 *arg)
{
	EFI_STATUS ret;
	CHAR16 *label = stra_to_str((CHAR8*)arg);
	if (!label) {
		error(L"Failed to get label %a\n", arg);
		fastboot_fail("Allocation error");
		return;
	}
	debug("Writing %s\n", label);

	ret = flash(dlbuffer, dlsize, label);
	FreePool(label);
	if (EFI_ERROR(ret))
		fastboot_fail("Flash failure: %r", ret);
	else {
		fastboot_okay("");
		/* update partition variable in case it has changed */
		if (ret & REFRESH_PARTITION_VAR) {
			clean_partition_var();
			publish_partsize();
		}
	}
}

static void cmd_erase(CHAR8 *arg)
{
	EFI_STATUS ret;
	CHAR16 *label = stra_to_str((CHAR8*)arg);
	if (!label) {
		error(L"Failed to get label %a\n", arg);
		fastboot_fail("Allocation error");
		return;
	}
	info(L"Erasing %s\n", label);
	ret = erase_by_label(label);
	FreePool(label);
	if (EFI_ERROR(ret))
		fastboot_fail("Flash failure: %r", ret);
	else
		fastboot_okay("");
}

/* static void cmd_boot(CHAR8 *arg) */
/* { */
/* 	struct bootimg_hooks hooks; */
/* 	EFI_STATUS ret; */

/* 	info(L"Booting custom image\n", arg); */

/* 	hooks.before_exit = boot_ok; */
/* 	hooks.watchdog = tco_start_watchdog; */
/* 	hooks.before_jump = NULL; */

/* 	ret = android_image_start_buffer(dlbuffer, NULL, &hooks); */

/* 	fastboot_fail("boot failure: %r", ret); */
/* } */

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

static void cmd_getvar(CHAR8 *arg)
{
	if (!strcmp(arg, (CHAR8 *)"all")) {
		fastboot_state = STATE_GETVAR;
		worker_getvar_all(varlist);
	} else {
		struct fastboot_var *var;
		var = fastboot_getvar((char *)arg);
		if (var && var->value) {
			fastboot_okay("%a", var->value);
		} else {
			fastboot_okay("");
		}
	}
}

static void cmd_reboot(__attribute__((__unused__)) CHAR8 *arg)
{
	info(L"Rebooting\n");
	fastboot_okay("");
	uefi_reset_system(EfiResetCold);
}

static struct fastboot_cmd *get_cmd(struct fastboot_cmd *list, const CHAR8 *name)
{
	struct fastboot_cmd *cmd;
	for (cmd = list; cmd; cmd = cmd->next)
		if (!memcmp(name, cmd->prefix, cmd->prefix_len))
			return cmd;
	return NULL;
}

static void cmd_oem(CHAR8 *arg)
{
	struct fastboot_cmd *cmd;

	while (arg[0] == ' ')
		arg++;

	cmd = get_cmd(oem_cmdlist, arg);
	if (!cmd) {
		fastboot_fail("unknown command 'oem %a'", arg);
		return;
	}

	cmd->handle(arg + cmd->prefix_len);
}

static void fastboot_read_command(void)
{
	usb_read(command_buffer, sizeof(command_buffer));
}
#define BLK_DOWNLOAD (8*1024*1024)

static void cmd_download(CHAR8 *arg)
{
	char response[MAGIC_LENGTH];
	UINTN newdlsize;

	newdlsize = strtoul((const char *)arg, NULL, 16);

	debug("Receiving %d bytes\n", newdlsize);
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
		error(L"Failed to allocate download buffer (0x%x bytes)\n", dlsize);
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
		error(L"Failed to receive %d bytes\n", dlsize);
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

static void fastboot_process_rx(void *buf, unsigned len)
{
	struct fastboot_cmd *cmd;
	static unsigned received_len = 0;
	CHAR8 *s;
	int req_len;

	switch (fastboot_state) {
	case STATE_DOWNLOAD:
		received_len += len;
		if (dlsize > MiB)
			Print(L"\rRX %d MiB / %d MiB", received_len/MiB, dlsize / MiB);
		else
			Print(L"\rRX %d KiB / %d KiB", received_len/1024, dlsize / 1024);
		if (received_len < dlsize) {
			s = buf;
			req_len = dlsize - received_len;
			if (req_len > BLK_DOWNLOAD)
				req_len = BLK_DOWNLOAD;
			usb_read(&s[len], req_len);
		} else {
			Print(L"\n");
			fastboot_state = STATE_COMMAND;
			fastboot_okay("");
		}
		break;
	case STATE_COMPLETE:
		((CHAR8 *)buf)[len] = 0;
		debug("GOT %a\n", (CHAR8 *)buf);

		fastboot_state = STATE_COMMAND;

		cmd = get_cmd(cmdlist, buf);
		if (cmd) {
			cmd->handle(buf + cmd->prefix_len);
			received_len = 0;

			if (fastboot_state == STATE_COMMAND)
				fastboot_fail("unknown reason");
		} else {
			error(L"unknown command '%a'\n", buf);
			fastboot_fail("unknown command");
		}
		break;
	default:
		error(L"Inconsistent fastboot state: 0x%x\n", fastboot_state);
	}
}

static void fastboot_start_callback(void)
{
	fastboot_state = STATE_COMPLETE;
	fastboot_read_command();
}

int fastboot_start()
{
	char download_max_str[30];

	if (snprintf(download_max_str, sizeof(download_max_str), "0x%lX", MAX_DOWNLOAD_SIZE))
		debug("Failed to set download_max_str string\n");
	else
		fastboot_publish("max-download-size", download_max_str);

	fastboot_register("reboot", cmd_reboot);
	fastboot_register("continue", cmd_reboot);
	fastboot_register("flash:", cmd_flash);
	fastboot_register("getvar:", cmd_getvar);
	fastboot_register("download:", cmd_download);
	fastboot_register("erase:", cmd_erase);

	publish_partsize();

	fastboot_register("oem", cmd_oem);
	fastboot_oem_init();

	fastboot_usb_start(fastboot_start_callback, fastboot_process_rx, fastboot_process_tx);

	return 0;
}
