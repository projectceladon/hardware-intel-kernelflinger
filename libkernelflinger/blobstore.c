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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "blobstore.h"
#include "log.h"
#include "lib.h"
#include "arraylist.h"
#include "dict.h"


#define SUPER_BLOCK_MAGIC "####FFFF"
#define MATA_BLOCK_MAGIC "FFFF####"

/**
 *
 * BlobStore Design and Format:
 *
 * Requirements:
 * 1. Ability to store variable sized blobs associated with Key
 * 2. Support multiple BlobTypes per a Key
 * 3. Blob retrieval and storing should be efficient.
 * 4. Ability to add Blobs of different types independently
 * 5. Support future extensions - update existing entries.
 * 6. Design to support up to 1K entries.
 *
 * BlobStore container makes use of file system like semantics to store
 * Blobs <Blobs-MetaData followed by Blobs>. Blobs-MetaData describes blob's
 * information in the container - location with in container, size and
 * blob identity (key,type).
 *
 * When BlobStore is created for first time, analogous to file system format,
 * file container is formatted to creates all necessary Blobs-MetaData in contiguous.
 * To keep design simple, container requires maximum number of blobs to be
 * supported in the container. This makes it easier to pre-allocate necessary
 * Blobs-MetaData contiguous.
 *
 * Blobs-MetaData consists of a superblock and metablocks.
 *
 * __superblock : This is first block in blobStore container,analogous to file
 * system superBlock, holds information about capacity of container, blobs start
 * location, blobs end location, where and how  MetaBlocks are stored.
 *
 * __metablock: Contains Information about blobs - blobKey, location, size. This is
 * to i-node(Index Node) structure in Linux/Unix file systems.
 *
 * In order to support multiple blobTypes associated with blobKey, _MetaBlock
 * maintains  MetaBlob for each type of blob supported.
 *
 * __metablob: Contains information about specific blobType - blob location, Size.
 *
 * blob: is variable sized binary data stored in the container.
 *
 * Visual layout of container:
 * ---------------------------
 *
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * |__superblock {number_of_blocks, block_size} | __metablock1 {__metablob1,  |
 * ----------------------------------------------------------------------------
 * |__metablob2} | __metablock2 {__metablob1, __metablob2} | __metablock3 {   |
 * ----------------------------------------------------------------------------
 * |{__metablob1, __metablob2} |__metablock4{ __metablob1,__metablob2}| blob1 |
 * ----------------------------------------------------------------------------
 * | blob2 |     blob3    | blob4 | blob5 |     blob6      |blob7| blob8|<EOF>|
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 *
 *
 * When BlobStore is created for first time, blob data area will be empty.
 * To make Blob retrieval efficient all Blobs-MetaData is maintained in memory.
 * BlobStore maintains a  list (free_blocks_list) for all available/unoccupied
 * _MeaBlocks and all used blocks are maintained in dictionary for faster
 * retrieval.
 *
 * If a new Blob is given to store,
 *
 * 1) SuperBlock is queried for current blobs end location and new Blob is
 * appended at the end. blobEndLocation is expanded to include new Blob.
 * 2) lookup is performed in dictionary to see if any associated key is found.
 *  If yes, its MetaBlock is updated and persisted.
 *  If not found, a new MetaBlock is retrieved from free list, updating blob
 *  location, size and persisted.
 *
 * To retrieve Blob from store,
 * 1) Dictionary Lookup is performed to see if any associated key is found.
 *    If yes, its located is retrieved by enumerating MetaBlobs based on type and
 *    once location, size is found, it is retrieved from memory/container.
 *    If not, return NOT found.
 */


/*blobstore layout structures*/

typedef struct __superblock_t {
        CHAR8 magic[8];
        UINT32 version;
        UINT32 number_of_blocks;
        UINT32 block_size;
        UINT32 blobs_location;
        UINT32 blobs_end_location;
} __superblock_t;

typedef struct __metablob_t {
        UINT32 blob_type;
        UINT32 blob_location;
        UINT32 blob_size;
} __metablob_t;

typedef struct __metablock_t {
        CHAR8 magic[8];
        UINT32 block_id;
        UINT32 block_number;
        CHAR8 blob_key[BLOB_KEY_LENGTH];
        __metablob_t meta_blobs[BLOB_TYPE_END];
} __metablock_t;


/*blobstore layout structure wrapers*/

typedef struct stream_t stream_t;
struct stream_t {
        void *sd; //stream descriptor
        BOOLEAN ready;
        int position;
        int (*open)(stream_t *self, void *location);
        int (*read)(stream_t *self, void *buf, UINT32 size);
        int (*write)(stream_t *self, void *buf, UINT32 size);
        int (*seek)(stream_t *self, UINT32 offset);
        void (*close)(stream_t *self);
};

typedef struct superblock_t superblock_t;
struct superblock_t {
        struct __superblock_t __sb;
        int on_disk_size;
        int (*read)(superblock_t *self, stream_t *sh);
        int (*write)(superblock_t *self, stream_t *sh);
        void (*printInfo)(superblock_t *self);
        int (*validate)(superblock_t *self);
        int (*update)(superblock_t *self, UINT32 blob_end_location);
};

typedef struct metablock_t metablock_t;
struct metablock_t {
        struct __metablock_t __mb;
        BOOLEAN used;
        int ondisk_size;
        int (*read)(metablock_t *self, stream_t *sh, UINT32 block_location);
        int (*write)(metablock_t *self, stream_t *sh, UINT32 block_location);
        void (*print_info)(metablock_t *self);
        int (*validate)(metablock_t *self);
        int (*update)(metablock_t *self, CHAR8 *blob_key, blobtype_t blob_type,
                        UINT32 blob_location, UINT32 blob_size);
        __metablob_t* (*getBlob)(metablock_t *self, blobtype_t blob_type);
};

struct blobstore_t {
        stream_t *stream;
        char *path;
        BOOLEAN ready;
        superblock_t *superblock;
        dict_t *used_blocks_dict;
        arraylist_t *free_blocks_list;
};

static int superblock_validate(superblock_t *self) {
        __superblock_t *__sb;
        if (!self) {
                return -1;
        }
        __sb = &self->__sb;
        if (strncmp(__sb->magic, (CHAR8 *) SUPER_BLOCK_MAGIC, sizeof(__sb->magic))) {
                error(L"SuperBlock Magic invalid");
                return -1;
        }
        return 0;
}

static int superblock_read(superblock_t *self, stream_t *sh) {
        if (!self || !sh) {
                return -1;
        }

        if (sh->seek(sh, 0) != 0) {
                return -1;
        }

        if (sh->read(sh, (void *) &self->__sb, self->on_disk_size) != 0) {
                error(L"failed to read SuperBlock");
                return -1;
        }

        if (self->validate(self) != 0) {
                error(L"Invalid SuperBlock");
                return -1;
        }
        return 0;
}

static int superblock_write(superblock_t *self, stream_t *sh) {
        if (!self || !sh) {
                return -1;
        }

        if (self->validate(self) != 0) {
                error(L"Invalid SuperBlock");
                return -1;
        }

        if (sh->seek(sh, 0) != 0) {
                return -1;
        }

        if (sh->write(sh, &self->__sb, self->on_disk_size) != 0) {
                return -1;
        }
        return 0;
}

static void superblock_print(superblock_t *self) {
        __superblock_t *__sb;
        if (!self) {
                return;
        }
        __sb = &self->__sb;
        debug(L"SuperBlock:");
        debug(L"_magic: %s", __sb->magic);
        debug(L"_version: %d", __sb->version);
        debug(L"_numberOfBlocks: %d", __sb->number_of_blocks);
        debug(L"_blockSize: %d", __sb->block_size);
        debug(L"_blobsLocation: %d", __sb->blobs_location);
        debug(L"_blobsEndLocation: %d", __sb->blobs_end_location);
        debug(L"..............");
}

static int superblock_update(superblock_t *self, UINT32 blob_end_location) {
        __superblock_t *__sb;
        if (!self || self->validate(self)) {
                return -1;
        }
        __sb = &self->__sb;
        __sb->blobs_end_location = blob_end_location;
        return 0;
}

static superblock_t *superblock_allocate(UINT32 number_of_blocks, UINT32 block_size) {
        superblock_t *sb;
        __superblock_t *__sb;
        sb = (superblock_t *) AllocatePool(sizeof(superblock_t));
        if (!sb) {
                error(L"failed to allocate memory");
                return NULL;
        }
        //initialize layout structure
        __sb = &sb->__sb;
        strncpy(__sb->magic, (CHAR8 *) SUPER_BLOCK_MAGIC, sizeof(__sb->magic));
        __sb->version = 1;
        __sb->number_of_blocks = number_of_blocks;
        __sb->block_size = block_size;
        __sb->blobs_location = (sizeof(__superblock_t) + 1 +
                                 (number_of_blocks * block_size));
        __sb->blobs_end_location = __sb->blobs_location;

        //initialize layout wrapper structure
        sb->on_disk_size = sizeof(__superblock_t );
        sb->read = superblock_read;
        sb->write = superblock_write;
        sb->printInfo = superblock_print;
        sb->validate = superblock_validate;
        sb->update = superblock_update;

        return sb;
}

static void superblock_free(superblock_t *self) {
        FreePool(self);
}

static int metablock_validate(metablock_t *self) {
        __metablock_t *__mb;
        if (!self) {
                return -1;
        }
        __mb = &self->__mb;
        if (strncmp(__mb->magic, (CHAR8 *) MATA_BLOCK_MAGIC, sizeof(__mb->magic))) {
                error(L"MetaBlock Magic invalid");
                return -1;
        }
        return 0;
}

static int metablock_read(metablock_t *self, stream_t *sh, UINT32 block_location) {
        if (!self || !sh) {
                return -1;
        }

        if (sh->seek(sh, block_location) != 0) {
                return -1;
        }

        if (sh->read(sh, (void *) &self->__mb, self->ondisk_size) != 0) {
                error(L"failed to read MetaBlock");
                return -1;
        }

        if (self->validate(self) != 0) {
                error(L"Invalid MetaBlock");
                return -1;
        }

        if (self->__mb.blob_key[0] == '\0') {
                self->used = FALSE;
        } else {
                self->used = TRUE;
        }

        return 0;
}

static int metablock_write(metablock_t *self, stream_t *sh, UINT32 block_location) {
        if (!self || !sh) {
                return -1;
        }

        if (self->validate(self) != 0) {
                error(L"Invalid MetaBlock");
                return -1;
        }

        if (sh->seek(sh, block_location) != 0) {
                return -1;
        }

        if (sh->write(sh, &self->__mb, self->ondisk_size) != 0) {
                error(L"write failed");
                return -1;
        }
        return 0;
}

static int metablock_update(metablock_t *self, CHAR8 *blobKey, blobtype_t blob_type,
                UINT32 blob_location, UINT32 blob_size) {
        __metablob_t *__mBlob;
        if (!self || !blobKey || !VALID_BLOB_TYPE(blob_type)) {
                return -1;
        }

        strncpy(self->__mb.blob_key, blobKey, BLOB_KEY_LENGTH);
        __mBlob = &self->__mb.meta_blobs[0];
        __mBlob += blob_type;
        __mBlob->blob_location = blob_location;
        __mBlob->blob_size = blob_size;
        return 0;
}

static __metablob_t* metablock_getblob(metablock_t *self, blobtype_t blob_type)
{
        __metablob_t *__mBlob;

        if(!self || !VALID_BLOB_TYPE(blob_type)) {
                return NULL;
        }
        __mBlob = &self->__mb.meta_blobs[0];
        __mBlob += blob_type;
        return __mBlob;

}

static void metablock_print(metablock_t *self) {
        __metablob_t *__mBlob;
        __metablock_t *__mb;
        blobtype_t blob_type;

        if (!self) {
                return;
        }
        __mb = &self->__mb;

        debug(L"metaBlock:");
        debug(L"_magic: %s", __mb->magic);
        debug(L"_blockId: %d", __mb->block_id);
        debug(L"_blockNumber: %d", __mb->block_number);
        debug(L"_blobKey: %s", __mb->blob_key);
        debug(L"Blobs:");
        __mBlob = __mb->meta_blobs;
        for (blob_type = BLOB_TYPE_DTB; blob_type < BLOB_TYPE_END; blob_type++) {
                debug(L"Blob Location: %d", __mBlob->blob_location);
                debug(L"Blob Size: %d", __mBlob->blob_size);
                __mBlob++;
        }
        debug(L"...............");

}

static metablock_t *metablock_allocate(UINT32 block_number) {
        __metablob_t *mBlob;
        __metablock_t *__mb;
        blobtype_t blob_type;
        metablock_t *mb = (metablock_t *) AllocatePool(sizeof(metablock_t));
        if (!mb) {
                error(L"failed to allocateMetaBlock");
                return NULL;
        }
        __mb = &mb->__mb;
        strncpy(__mb->magic, (CHAR8 *) MATA_BLOCK_MAGIC, sizeof(__mb->magic));
        __mb->block_id = 0;
        __mb->block_number = block_number;
        strncpy(__mb->blob_key, (CHAR8 *) "", BLOB_KEY_LENGTH);

        mBlob = __mb->meta_blobs;
        for (blob_type = BLOB_TYPE_DTB; blob_type < BLOB_TYPE_END; blob_type++) {
                mBlob->blob_type = blob_type;
                mBlob->blob_size = 0;
                mBlob->blob_location = 0;
                mBlob++;
        }
        //layout wrapper
        mb->ondisk_size = sizeof(__metablock_t );
        mb->used = FALSE;
        mb->read = metablock_read;
        mb->write = metablock_write;
        mb->print_info = metablock_print;
        mb->validate = metablock_validate;
        mb->update = metablock_update;
        mb->getBlob = metablock_getblob;

        return mb;
}

static void metablock_free(metablock_t *mb) {
        FreePool(mb);
}

static int memorystream_open(stream_t *self, void *location) {
        if (!self || !location) {
                return -1;
        }
        self->sd = location;
        self->position = 0;
        self->ready = TRUE;
        return 0;
}

static void memorystream_close(stream_t *self) {
        if (!self) {
                return;
        }
        self->ready = FALSE;
        self->position = 0;
        return;
}

static int memorystream_read(stream_t *self, void *buf, UINT32 size) {
        if (!self || !self->ready || !buf) {
                return -1;
        }
        memcpy(buf, self->sd + self->position, size);
        self->position += size;
        return 0;
}

static int memorystream_write(stream_t *self, void *buf, UINT32 size) {
        if (!self || !self->ready || !buf) {
                return -1;
        }
        memcpy(self->sd + self->position, buf, size);
        self->position += size;
        return 0;
}

static int memorystream_seek(stream_t *self, UINT32 offset) {
        if (!self || !self->ready) {
                return -1;
        }
        self->position = offset;
        return 0;
}

static stream_t *memorystream_allocate() {
        stream_t *sh; //stream handle
        sh = (stream_t *) AllocatePool(sizeof(stream_t));
        if (!sh) {
                return NULL;
        }
        sh->sd = NULL;
        sh->ready = FALSE;
        sh->position = 0;
        sh->open = memorystream_open;
        sh->read = memorystream_read;
        sh->write = memorystream_write;
        sh->seek = memorystream_seek;
        sh->close = memorystream_close;
        return sh;
}

static void memorystream_free(stream_t *self) {
        if (!self)
                return;

        if (self->ready) {
                self->close(self);
        }
        FreePool(self);
}

static UINT32 blobstore_calc_blocklocation(UINT32 block_number) {
        return sizeof(__superblock_t) + 1 + ((block_number - 1) * sizeof(__metablock_t));
}

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
int blobstore_load(blobstore_t *self, void *location) {
        metablock_t *mb;
        superblock_t *sb;
        stream_t *sh;
        UINT32 block_number;

        debug(L"Loading BlobStore...");
        if (!self || !location) {
                error(L"Invalid parameters");
                return -1;
        }
        sh = self->stream;
        sh->open(sh, location);

        // read superblock
        self->superblock = superblock_allocate(0, 0);
        if (!self->superblock) {
                error(L"failed to allocateSuperblock");
                goto free;
        }
        sb = self->superblock;
        if (sb->read(sb, sh) == -1) {
                error(L"failed to read SuperBlock");
                goto free;
        }

        self->free_blocks_list = arraylist_allocate(sb->__sb.number_of_blocks + 1);
        if (!self->free_blocks_list) {
                error(L"Failed to allocate free_blocks_list");
                goto free;
        }
        self->used_blocks_dict = dict_allocate(sb->__sb.number_of_blocks + 1);
        if (!self->used_blocks_dict) {
                error(L"Failed to allocate used_blocks_dict");
                goto free;
        }

        // read all metaBlocks
        for (block_number = 1; block_number < (sb->__sb.number_of_blocks + 1);
                        block_number++) {
                int blockLocation;
                mb = metablock_allocate(block_number);
                if (!mb) {
                        error(L"failed to allocateMetaBlock\n");
                        goto free;
                }
                blockLocation = blobstore_calc_blocklocation(block_number);
                if (mb->read(mb, sh, blockLocation) != 0) {
                        error(L"failed to read metaBlocks\n");
                        goto free;
                }
                if (!mb->used) {
                        arraylist_append(self->free_blocks_list, (value_type) mb);
                } else {
                        dict_update(self->used_blocks_dict, mb->__mb.blob_key, (value_type) mb);
                }
        }
        self->ready = TRUE;
        return 0;

free:   blobstore_close(self);
        return -1;
}

#ifndef USER
/**
 * blobstore_create - Creates new BlobStore at given location in memory
 * @self: handle to BlobStore
 * @location: in memory location to create new BlobStore
 *
 * Creates new BlobStore at given memory location.
 *
 * On success, 0 is returned.
 * On failure, -1 is returned.
 */
int blobstore_create(blobstore_t *self, void *location, UINT32 size) {
        UINT32 block_location;
        superblock_t *sb;
        UINT32 block_number;
        stream_t *stream;

        debug(L"Creating BlobStore...");
        if (!self || !location || !size) {
                error(L"Invalid parameters");
                return -1;
        }
        stream = self->stream;
        stream->open(stream, location);
        if (!stream->ready) {
                goto free;
        }

        // create superblock
        debug(L"creating superblock...");
        sb = superblock_allocate(size, sizeof(__metablock_t ));
        if (!sb) {
                error(L"failed to allocateSuperblock");
                goto free;
        }
        if (sb->write(sb, self->stream) != 0) {
                error(L"failed to write SuperBlock");
                goto free;
        }
        self->superblock = sb;

        self->free_blocks_list = arraylist_allocate(sb->__sb.number_of_blocks + 1);
        if (!self->free_blocks_list) {
                error(L"Failed to allocate free_blocks_list");
                goto free;
        }
        self->used_blocks_dict = dict_allocate(sb->__sb.number_of_blocks + 1);
        if (!self->used_blocks_dict) {
                error(L"Failed to allocate used_blocks_dict");
                goto free;
        }

        // write metaBlocks
        debug(L"creating metaBlocks...\n");
        for (block_number = 1; block_number < size + 1; block_number++) {
                metablock_t *mb = metablock_allocate(block_number);
                if (!mb) {
                        error(L"failed to allocate meta block");
                        goto free;
                }
                block_location = blobstore_calc_blocklocation(block_number);
                if (mb->write(mb, self->stream, block_location) != 0) {
                        error(L"MetaBlock write failed");
                        goto free;
                }
                arraylist_append(self->free_blocks_list, (value_type) mb);
        }
        self->ready = TRUE;
        return 0;

free:   blobstore_close(self);
        return -1;
}


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
 * stored with given key and type, new blob is stored in blobStore decoupling old
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
                CHAR8 blob_key[BLOB_KEY_LENGTH], blobtype_t blob_type) {
        metablock_t *matched_block = NULL;
        metablock_t *block = NULL;
        stream_t *sh = NULL;
        UINT32 blob_location;
        UINT32 block_location;
        superblock_t *sb = NULL;

        if (!self || !self->ready || !blob_key) {
                error(L"Invalid parameters");
                return -1;
        }

        if (!VALID_BLOB_TYPE(blob_type)) {
                return BLOBSTORE_BLOBTYPE_UNKNOWN;
        }

        sh = self->stream;
        sb = self->superblock;

        matched_block = (metablock_t*) dict_get(self->used_blocks_dict, blob_key);
        if (matched_block == NULL) {
                block = (metablock_t*) arraylist_pop(self->free_blocks_list);
        } else {
                block = matched_block;
        }

        if (block == NULL) {
                error(L"BlobStore is full");
                return BLOBSTORE_STORAGE_FULL;
        }

        blob_location = sb->__sb.blobs_end_location;

        // persist blob
        sh->seek(sh, blob_location);
        if (sh->write(sh, blob, blob_size) != 0) {
                return -1;
        }

        //update meta and super blocks with new blob location, size

        block_location = blobstore_calc_blocklocation(block->__mb.block_number);
        if (block->update(block, blob_key, blob_type,
                                blob_location, blob_size) != 0) {
                error(L"failed to update meta block");
                return -1;
        }
        if (block->write(block, sh, block_location) != 0) {
                error(L"failed to write meta block");
                goto revert_metadata;
        }

        if (sb->update(sb, blob_location + blob_size) != 0) {
                error(L"failed to update super block");
                goto revert_metadata;
        }
        if (sb->write(sb, sh) != 0) {
                error(L"failed to write super block");
                goto revert_metadata;
        }

        //Add block to dictionary
        if (dict_update(self->used_blocks_dict, blob_key, (value_type) block) != 0) {
                error(L"failed to insert blob into dictionary");
                goto revert_metadata;
        }
        return 0;

revert_metadata:
        //update meta and super blocks to original
        block->update(block, blob_key, blob_type, 0, 0);
        block->write(block, sh, block_location);
        sb->update(sb, blob_location);
        sb->write(sb, sh);
        return -1;
}

#endif //#ifndef USER

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
                CHAR8 blob_key[BLOB_KEY_LENGTH], blobtype_t blob_type) {
        metablock_t *matched_block = NULL;
        __metablob_t *__mBlob = NULL;
        stream_t *sh;
        superblock_t *sb = NULL;
        UINT32 data_start, data_end;

        if (!self || !self->ready || !blob_size) {
                error(L"Invalid parameters");
                return -1;
        }

        if (!VALID_BLOB_TYPE(blob_type)) {
                return BLOBSTORE_BLOBTYPE_UNKNOWN;
        }

        sh = self->stream;
        sb = self->superblock;
        data_start = sb->__sb.blobs_location;
        data_end = sb->__sb.blobs_end_location;



        //dictionary Lookup
        matched_block = (metablock_t*) dict_get(self->used_blocks_dict, blob_key);
        if (matched_block == NULL) {
                error(L"No Blob found with given key %s", blob_key);
                return BLOBSTORE_BLOB_NOT_FOUND;
        }
        __mBlob = matched_block->getBlob(matched_block, blob_type);
        if (!__mBlob) {
                error(L"failed to get meta blob");
                return -1;
        }

        //validate blobLocation and size before reading
        if (__mBlob->blob_location < data_start && __mBlob->blob_location > data_end) {
                error(L"MetaBlob: Invalid blobLocation found");
                return -1;
        }
        if (__mBlob->blob_size <= 0) {
                error(L"MetaBlob: Invalid blobSize found");
                return -1;
        }

        if ((blob == NULL) || (*blob_size == 0)) {
                *blob_size = __mBlob->blob_size;
                return BLOBSTORE_BUFFER_INSUFFICIENT;
        }

        //read blob and return
        sh->seek(sh, __mBlob->blob_location);
        if (sh->read(sh, blob, __mBlob->blob_size) != 0) {
                error(L"Unable to retrieve the blob");
                return -1;
        }
        *blob_size = __mBlob->blob_size;
        return 0;
}


/**
 * blobstore_close - closes blob store
 * @self: handle to BlobStore
 *
 * Closes and frees all internal resources
 */
void blobstore_close(blobstore_t *self) {
        metablock_t *mb;
        dict_entry_t *de;
        stream_t *stream;
        int i = 0;

        if (!self || !self->ready) {
                return;
        }
        stream = self->stream;
        // Free metaBlocks
        dict_iterator_t it;
        dict_iterator_begin(self->used_blocks_dict, &it);
        while ((de = dict_iterator_pop(&it))) {
                metablock_free((metablock_t*) de->value);
                FreePool(de);
        }
        dict_iterator_end(&it);

        for (i = 0; i <= arraylist_length(self->free_blocks_list); i++) {
                mb = (metablock_t *) arraylist_pop(self->free_blocks_list);
                metablock_free(mb);
        }

        // Free SuperBlock
        superblock_free(self->superblock);
        arraylist_free(self->free_blocks_list);
        dict_free(self->used_blocks_dict);

        //Close the back-end file
        stream->close(stream);

        self->free_blocks_list = NULL;
        self->used_blocks_dict = NULL;
        self->superblock = NULL;
        self->ready = FALSE;
}

/**
 * blobstore_printinfo - Print debug information about blob store
 * @self: handle to BlobStore
 *
 * Prints all debug information about blob store including number of blobs stored
 * and types of blobs stored along with keys and type.
 */
void blobstore_printinfo(blobstore_t *self) {
        metablock_t *block = NULL;
        dict_entry_t *de;
        superblock_t *sb;
        int i;

        if (!self || !self->ready) {
                return;
        }
        sb = (superblock_t *) self->superblock;

        sb->printInfo(sb);
        debug(L"------used blocked-----");

        dict_iterator_t it;
        dict_iterator_begin(self->used_blocks_dict, &it);
        while ((de = dict_iterator_Next(&it))) {
                block = (metablock_t*) de->value;
                block->print_info(block);
        }
        dict_iterator_end(&it);
        debug(L"-----free blocks------");

        for (i = 0; i <= arraylist_length(self->free_blocks_list); i++) {
                block = (metablock_t*) arraylist_get(self->free_blocks_list, i);
                block->print_info(block);
        }
}

/**
 * blobstore_allocate - allocates blob store
 *
 * Allocates blob store in heap, initializes internal data structures
 * and handle is returned to caller.
 *
 * On success, the blob store handle is returned.
 */
blobstore_t *blobstore_allocate() {
        blobstore_t *bs;
        bs = (blobstore_t *) AllocatePool(sizeof(blobstore_t));
        if (!bs) {
                return NULL;
        }
        bs->free_blocks_list = NULL;
        bs->used_blocks_dict = NULL;
        bs->superblock = NULL;
        bs->stream = memorystream_allocate();
        if (!bs->stream) {
                FreePool(bs);
                return NULL;
        }
        bs->ready = FALSE;
        return bs;
}

/**
 * blobstore_free - frees blob store
 * @self: handle to blob store
 *
 * Closes all internal resources and deallocates blob store from heap
 */
void blobstore_free(blobstore_t *self) {
        if (!self)
                return;

        if (self->ready) {
                blobstore_close(self);
        }
        memorystream_free(self->stream);
        self->stream = NULL;
        FreePool(self);
}

