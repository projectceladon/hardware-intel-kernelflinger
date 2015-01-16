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
 *
 */

#include <efi.h>
#include <efilib.h>

#include "log.h"
#include "lib.h"
#include "vars.h"

static SERIAL_IO_INTERFACE *serial;

#define SERIAL_BAUD_RATE	115200
#define SERIAL_FIFO_DEPTH	1
#define SERIAL_TIMEOUT		1
#define SERIAL_PARITY		1
#define SERIAL_DATA_BITS	8
#define SERIAL_STOP_BITS	1

#define BUFFER_SIZE 128
static CHAR16 buf16[BUFFER_SIZE];
static CHAR8 buf8[BUFFER_SIZE];

#ifndef USER
#define LOG_BUF_SIZE 1024
static CHAR8 log_buf[LOG_BUF_SIZE];
static UINTN pos;

EFI_STATUS log_flush_to_var()
{
	return set_efi_variable(&loader_guid, L"KernelflingerLogs",
				sizeof(log_buf), log_buf, FALSE, TRUE);
}

static void log_append_to_buffer(CHAR8 *msg, UINTN length)
{
	if (pos + length >= LOG_BUF_SIZE)
		pos = 0;

	memcpy(log_buf + pos, msg, length);
	pos += length;
}
#endif

static EFI_STATUS serial_init()
{
	EFI_STATUS ret;
	EFI_GUID guid = SERIAL_IO_PROTOCOL;

	ret = LibLocateProtocol(&guid, (void **)&serial);
	if (EFI_ERROR(ret))
		return ret;

	ret = uefi_call_wrapper(serial->SetAttributes, 7, serial,
				SERIAL_BAUD_RATE, SERIAL_FIFO_DEPTH,
				SERIAL_TIMEOUT, SERIAL_PARITY,
				SERIAL_DATA_BITS, SERIAL_STOP_BITS);
	if (EFI_ERROR(ret))
		return ret;

	ret = uefi_call_wrapper(serial->Reset, 1, serial);
	if (EFI_ERROR(ret))
		return ret;

	return EFI_SUCCESS;
}

void log(const CHAR16 *fmt, ...)
{
	va_list args;
	UINTN length;

	if (!serial && !EFI_ERROR(serial_init()))
		return;

	va_start(args, fmt);

	length = VSPrint(buf16, sizeof(buf16), (CHAR16 *)fmt, args) + 1;

	if (EFI_ERROR(str_to_stra(buf8, buf16, length)))
		goto exit;

	if (EFI_ERROR(uefi_call_wrapper(serial->Write, 3, serial, &length, buf8)))
		goto exit;

#ifndef USER
	log_append_to_buffer(buf8, length);
#endif
exit:
	va_end(args);
}
