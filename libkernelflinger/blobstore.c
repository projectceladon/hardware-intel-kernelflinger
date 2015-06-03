/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
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

/* See docstring in device/intel/build/blobstore.py for detail on use-cases
 * and how the data is structured */

#include <efi.h>
#include <efilib.h>

#include "log.h"
#include "lib.h"
#include "blobstore.h"

#define BLOB_STORE_MAGIC	"BLOBSTOR"
#define BLOB_KEY_LENGTH		64

/* All of these are packed structure with little-endian values.
 * This code won't work on big-endian machines without adding some
 * byte-swapping, but so far all Intel CPUs are little-endian */
struct metablock {
	char blob_key[BLOB_KEY_LENGTH];
	unsigned int blob_type;
	unsigned int next_item_offset;
	unsigned int data_offset;
	unsigned int data_size;
} __attribute__((packed));

struct blobstore {
	char magic[8];
	unsigned int version;
	unsigned int total_size;
	unsigned int hashmap_sz;
	unsigned int hashmap[0]; /* of hashmap_sz */
} __attribute__((packed));

unsigned int hash_blob_key(char *key, enum blobtype type, unsigned int hsize)
{
	unsigned int hash_val;

	/* based on libcutils hashmapHash() algorithm */
	for (hash_val = 0; *key != '\0'; key++)
		hash_val = hash_val * 31 + *key;
	hash_val = hash_val * 31 + (unsigned int)type;
	return hash_val % hsize;
}


/* Sanity check a memory buffer and return a blobstore pointer if it
 * checks out */
struct blobstore *blobstore_get(void *mem, unsigned int size)
{
	struct blobstore *bs;

	bs = (struct blobstore *)mem;
	if (size < sizeof(struct blobstore))
		return NULL;

	if (memcmp(bs->magic, BLOB_STORE_MAGIC, sizeof(bs->magic))) {
		debug(L"bad blobstore magic, probably not a blobstore");
		return NULL;
	}

	if (size != bs->total_size) {
		error(L"bad size value %u != %u", size, bs->total_size);
		return NULL;
	}

	if (bs->version != 1) {
		error(L"unsupported blobstore version");
		return NULL;
	}

	return bs;
}


int blobstore_get_item(struct blobstore *bs, char *key, enum blobtype type,
		       void **data, unsigned int *size)
{
	unsigned char *start;
	unsigned int hash;
	unsigned int offset;
	struct metablock *mb;

	hash = hash_blob_key(key, type, bs->hashmap_sz);
	offset = bs->hashmap[hash];
	start = (unsigned char *)bs;

	debug(L"GET: %a-%d (%d=%d)", key, type, hash, offset);

	if (!offset) {
		debug(L"not found in hash table");
		return -2;
	}

	if (offset >= bs->total_size) {
		error(L"bad offset in blobstore hash table");
		return -1;
	}

	do  {
		mb = (struct metablock *)(start + offset);
		if (!strncmp((CHAR8 *)key, (CHAR8 *)mb->blob_key, BLOB_KEY_LENGTH) &&
		    type == mb->blob_type) {
			if (mb->data_offset + mb->data_size > bs->total_size) {
				error(L"bad offset in blobstore meta block");
				return -1;
			}
			*data = (void *)(start + mb->data_offset);
			*size = mb->data_size;
			return 0;
		}
		offset = mb->next_item_offset;
	} while (offset);

	/* Not found */
	debug(L"not found in hash table (no matching meta blocks)");
	return -2;
}


