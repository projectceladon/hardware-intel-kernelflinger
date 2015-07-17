/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
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
 * This file defines bootlogic data structures, try to keep it without
 * any external definitions in order to ease export of it.
 */

#ifndef _STORAGE_H_
#define _STORAGE_H_

#include <efi.h>
#include "gpt.h"

enum storage_type {
	STORAGE_EMMC,
	STORAGE_UFS,
	STORAGE_ALL,
};

/* It is faster to erase multiple block at once */
#define N_BLOCK (4096)

struct storage {
	EFI_STATUS (*erase_blocks)(EFI_HANDLE handle, EFI_BLOCK_IO *bio, UINT64 start, UINT64 end);
	EFI_STATUS (*check_logical_unit)(EFI_DEVICE_PATH *p, logical_unit_t log_unit);
	BOOLEAN (*probe)(EFI_DEVICE_PATH *p);
	const CHAR16 *name;
};

#define STORAGE(X) storage_##X

EFI_STATUS identify_boot_device(enum storage_type type);
PCI_DEVICE_PATH *get_boot_device(void);
EFI_STATUS storage_set_boot_device(EFI_HANDLE device);
EFI_STATUS storage_check_logical_unit(EFI_DEVICE_PATH *p, logical_unit_t log_unit);
EFI_STATUS storage_erase_blocks(EFI_HANDLE handle, EFI_BLOCK_IO *bio, UINT64 start, UINT64 end);
EFI_STATUS fill_with(EFI_BLOCK_IO *bio, UINT64 start, UINT64 end,
		     VOID *pattern, UINTN pattern_blocks);
EFI_STATUS fill_zero(EFI_BLOCK_IO *bio, UINT64 start, UINT64 end);

#endif	/* _STORAGE_H_ */
