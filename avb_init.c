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
#include "avb_init.h"

//Global AvbOps data structure
static AvbOps *ops = NULL;

AvbOps *avb_init(void)
{
	avb_print("UEFI AVB-based bootloader\n");

	if (ops != NULL) {
		return ops;
	}

	ops = uefi_avb_ops_new();
	if (!ops) {
		avb_fatal("Error allocating AvbOps.\n");
		return NULL;
	}

	return ops;
}

bool avb_update_stored_rollback_indexes_for_slot(AvbOps* ops, AvbSlotVerifyData* slot_data)
{
	int n;

	for (n = 0; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS; n++) {
		uint64_t rollback_index = slot_data->rollback_indexes[n];
		if (rollback_index > 0) {
			AvbIOResult io_ret;
			uint64_t current_stored_rollback_index;

			io_ret = ops->read_rollback_index(ops, n, &current_stored_rollback_index);
			if (io_ret != AVB_IO_RESULT_OK) {
				return false;
			}

			if (rollback_index > current_stored_rollback_index) {
				io_ret = ops->write_rollback_index(ops, n, rollback_index);
				if (io_ret != AVB_IO_RESULT_OK) {
					return false;
				}
			}
		}
	}
	return true;
}
