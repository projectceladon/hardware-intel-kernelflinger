/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Author: genshen <genshen.li@intel.com>
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
#ifndef _RPMB_STORAGE_H_
#define _RPMB_STORAGE_H_

#define RPMB_KEY_SIZE    32

typedef struct rpmb_storage {
	BOOLEAN (*is_rpmb_programed)(void);
	EFI_STATUS (*program_rpmb_key)(UINT8 *key);

	EFI_STATUS (*write_rpmb_device_state)(UINT8 state);
	EFI_STATUS (*read_rpmb_device_state)(UINT8 *state);

	EFI_STATUS (*write_rpmb_rollback_index)(size_t index, UINT64 in_rollback_index);
	EFI_STATUS (*read_rpmb_rollback_index)(size_t index, UINT64 *out_rollback_index);
} rpmb_storage_t;

void rpmb_storage_init(BOOLEAN real);

void clear_rpmb_key(void);
void set_rpmb_key(UINT8 *key);
EFI_STATUS erase_rpmb_all_blocks(void);
EFI_STATUS derive_rpmb_key(UINT8 *out_key);

BOOLEAN is_rpmb_programed(void);
EFI_STATUS program_rpmb_key(UINT8 *key);

EFI_STATUS write_rpmb_device_state(UINT8 state);
EFI_STATUS read_rpmb_device_state(UINT8 *state);

EFI_STATUS write_rpmb_rollback_index(size_t index, UINT64 in_rollback_index);
EFI_STATUS read_rpmb_rollback_index(size_t index, UINT64 *out_rollback_index);
#endif
