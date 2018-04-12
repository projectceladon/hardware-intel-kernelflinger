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

#ifndef _UFS_PROTOCOL_H_
#define _UFS_PROTOCOL_H_

#include <endian.h>

#define CDB_LENGTH			10
#define BLOCK_TIMEOUT			10000	/* 100ns units => 1ms by block */
#define UFS_UNMAP			0x42
#define UFS_SECURITY_PROTOCOL_IN	0xa2
#define UFS_SECURITY_PROTOCOL_OUT	0xb5
#define UFS_RPMB_LUN			0x44c1


struct command_descriptor_block_unmap {
	__be8 op_code;		/* Operation Code (must be 0x42 for unmap) */
	__be8 reserved;
	__be32 reserved2;
	__be8 group:5;		/* group number */
	__be8 reserved3:3;
	__be16 param_length;	/* parameter list length */
	__be8 control;		/* must be 0 */
} __attribute__((packed));

struct unmap_block_descriptor {
	__be64 lba;		/* first LBA to be unmapped */
	__be32 count;		/* number of LBAs to be unmapped */
	__be32 reserved;
} __attribute__((packed));

struct unmap_parameter {
	__be16 data_length; /* length in bytes of the following data */
	__be16 block_desc_length; /* length in bytes of the unmap block descriptor */
	__be32 reserved;
	struct unmap_block_descriptor block_desc;
} __attribute__((packed));

struct command_descriptor_block_security_protocol {
	__be8 op_code;
	__be8 sec_protocol;
	__be16 sec_protocol_specific;
	__be8 reserved1:7;
	__be8 inc_512:1;
	__be8 reserved2;
	__be32 allocation_transfer_length;
	__be8 reserved3;
	__be8 control;
} __attribute__((packed));

#endif	/* _UFS_PROTOCOL_H_ */
