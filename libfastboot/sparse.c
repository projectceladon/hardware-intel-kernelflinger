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
#include "uefi_utils.h"

#include "flash.h"
#include "sparse_format.h"

BOOLEAN is_sparse_image(void *data, UINT64 size)
{
	struct sparse_header *sph;

	if (size < sizeof(struct sparse_header))
		return FALSE;

	sph = data;

	debug(L"sparse header : magic %08x, major %d, minor %d, fdhrsz %d, chdrsz %d, bz %d",
	      sph->magic, sph->major_version, sph->minor_version,
	      sph->file_hdr_sz, sph->chunk_hdr_sz, sph->blk_sz);
	debug(L"tot blk %d, tot chk %d", sph->total_blks, sph->total_chunks);

	if (sph->magic != SPARSE_HEADER_MAGIC)
		return FALSE;
	if (sph->major_version > 1)
		return FALSE;
	if (sph->file_hdr_sz < sizeof(struct sparse_header))
		return FALSE;
	if (sph->chunk_hdr_sz < sizeof(struct chunk_header))
		return FALSE;

	debug(L"Found a valid sparse image");
	return TRUE;
}

static EFI_STATUS flash_chunk(struct sparse_header *sph, struct chunk_header *ckh, CHAR8 *data, unsigned int size)
{
	switch (ckh->chunk_type) {
	case CHUNK_TYPE_RAW:
		if (size % sph->blk_sz || size != ckh->chunk_sz * sph->blk_sz) {
			error(L"inconsistent raw chunk");
			return EFI_INVALID_PARAMETER;
		}
		return flash_write(data, size);
	case CHUNK_TYPE_DONT_CARE:
		return flash_skip(ckh->chunk_sz * sph->blk_sz);
	case CHUNK_TYPE_FILL:
		return flash_fill(*((UINT32 *) data), ckh->chunk_sz * sph->blk_sz);
	case CHUNK_TYPE_CRC32:
		debug(L"crc chunk not implemented yet %d", size);
		break;
	default:
		error(L"Unknow chunk type %04x", ckh->chunk_type);
		return EFI_INVALID_PARAMETER;
	}
	return EFI_SUCCESS;
}

EFI_STATUS flash_sparse(void *data, UINT64 size)
{
	struct sparse_header *sph;
	CHAR8 *s;
	UINT64 rlen;
	unsigned int i;
	EFI_STATUS ret;

	rlen = size;
	s = data;
	sph = data;
	s += sph->file_hdr_sz;

	for (i = 0; i < sph->total_chunks; i++) {
		struct chunk_header *ckh;
		ckh = (struct chunk_header *) s;

		if (rlen < sph->chunk_hdr_sz || rlen < ckh->total_sz) {
			error(L"sparse chunk truncated, %ld, %ld", rlen, size);
			return EFI_INVALID_PARAMETER;
		}
		if (ckh->total_sz < sph->chunk_hdr_sz) {
			error(L"sparse chunk malformated, %d, %d", ckh->total_sz, sph->chunk_hdr_sz);
			return EFI_INVALID_PARAMETER;
		}
		ret = flash_chunk(sph, ckh, s + sph->chunk_hdr_sz, ckh->total_sz - sph->chunk_hdr_sz);
		if (EFI_ERROR(ret))
			return ret;

		s += ckh->total_sz;
		rlen -= ckh->total_sz;
	}
	return EFI_SUCCESS;
}
