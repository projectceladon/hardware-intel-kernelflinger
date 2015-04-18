/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Sridhar Uyyala <sridhar.uyyala@intel.com>
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

#ifndef BLOBSTORE_H_
#define BLOBSTORE_H_

#include <efi.h>

#define BLOB_KEY_LENGTH                  64

#define BLOBSTORE_SUCCESS                0
#define BLOBSTORE_FAILURE               -1
#define BLOBSTORE_BLOB_NOT_FOUND        -100
#define BLOBSTORE_BUFFER_INSUFFICIENT   -200
#define BLOBSTORE_BLOBTYPE_UNKNOWN      -300
#define BLOBSTORE_STORAGE_FULL          -400
#define BLOBSTORE_UNKNOWN_ERROR         -500

typedef enum blobtypes_t {
        BLOB_TYPE_DTB = 0, BLOB_TYPE_OEMVARS, BLOB_TYPE_END
} blobtype_t;

#define VALID_BLOB_TYPE(__t)  ((__t) >= BLOB_TYPE_DTB && (__t) < BLOB_TYPE_END)

typedef struct blobstore_t blobstore_t;

/**
 * blobstore_allocate - allocates blob store
 *
 * Allocates blob store in heap, initializes internal data structures
 * and handle is returned to caller.
 *
 * On success, the blob store handle is returned.
 */
blobstore_t *blobstore_allocate();

/**
 * blobstore_free - frees blob store
 * @self: handle to blob store
 *
 * Closes all internal resources and deallocates blob store from heap
 */
void blobstore_free(blobstore_t *self);

/**
 * blobstore_load - loads existing blobstore_t from given memory location
 * @self: handle to blob store
 * @location: in memory location of blob store
 *
 * Validates magic in blob_store and loads blob store from given
 * memory location.
 *
 * On success, 0 is returned.
 * On failure, -1 is returned.
 */
int blobstore_load(blobstore_t *self, void *location);

/**
 * blobstore_getblob - lookups requested blob from blob store given blob key and type
 * @self: handle to blob store
 * @blob: allocated buffer where requested blob will be copied if found
 * @blob_size: size of @blob
 * @blob_key: Key which is used to lookup blob in blob store
 * @blob_type: Type of blob to be returned with matching key
 *
 * blobstore_getblob lookups given key in blob store and if key is found then
 * blobs are enumerated on given blobType. Once  blob is found it is copied
 * to given buffer location (@blob) and @blob_size is set with blob size.
 *
 * If the caller wants to know the size of blob to allocate the buffer,
 * simply calling this function with @blob set to NULL and/or @blob_size is
 * set to 0 results in @blob_size set to requested size.
 *
 * On success, 0 is returned.
 * On failure,
 *         negative value(<0)  is returned. failure reasons are as follows,
 *         1) If no blob found with given key  BLOBSTORE_BLOB_NOT_FOUND is returned
 *         2) If given buffer size is less than blob_size found in container then
 *                 BLOBSTORE_BUFFER_INSUFFICIENT is returned with actual blob_size set.
 *         3) If wrong blob_type is passed fails with BLOBSTORE_BLOBTYPE_UNKNOWN
 *
 */
int blobstore_getblob(blobstore_t *self, void *blob, UINT32 *blob_size,
                CHAR8 blob_key[BLOB_KEY_LENGTH], blobtype_t blob_type);

/**
 * blobstore_close - closes blob store
 * @self: handle to blob store
 *
 * closes and frees internal resources
 */
void blobstore_close(blobstore_t *self);

/**
 * blobstore_printinfo - print debug information about blob store
 * @self: handle to blob store
 *
 * Prints all debug information about blob store including number of blobs stored
 * and types of blobs stored along with keys and type.
 */
void blobstore_printinfo(blobstore_t *self);

#ifndef USER

/**
 * blobstore_putblob - stores requested blob in blob store with given blob key and type
 * @self: handle to BlobStore
 * @blob: buffer containing blob
 * @blob_size: @blob buffer size
 * @blob_key: Key which is used to store blob in BlobStore
 * @blob_type: Type of blob to be stored
 *
 * blobstore_putblob stores the given blob in the blobStore with given key and type.
 * First, it lookups key in blob store for any existing blobs. If a blob is already
 * stored with given key and type, new blob is stored in blobstore decoupling old
 * one. If no key or type is found, blob is stored as new entry associated with
 * given key and type.
 *
 * marking as static as this functionality is not required in loader
 *
 * On success, 0 is returned.
 * On failure,
 *  negative value(<0)  is returned. failure reasons are as follows,
 *         1) If container blob store is full returns BLOBSTORE_STORAGE_FULL
 *         2) If wrong blob_type is passed fails with BLOBSTORE_BLOBTYPE_UNKNOWN
 *         3) For IO failures returns BLOBSTORE_UNKNOWN_ERROR;
 *
 */
int blobstore_putblob(blobstore_t *self, void *blob, UINT32 blob_size,
                CHAR8 blob_key[BLOB_KEY_LENGTH], blobtype_t blob_type);

/**
 * blobstore_create - Creates new blob store at given location in memory
 * @self: handle to blob store
 * @location: in memory location to create new blob store
 *
 * Creates new blob store at given memory location.
 *
 * marking as static as this functionality is not required in loader
 * On success, 0 is returned.
 * On failure, -1 is returned.
 */
int blobstore_create(blobstore_t *self, void *location, UINT32 size);

#endif

#endif /* BLOBSTORE_H_ */
