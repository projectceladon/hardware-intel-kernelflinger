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

#include "dict.h"
#include "log.h"
#include "lib.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "arraylist.h"


struct dict_t {
        int size;
        int key_count;
        dict_entry_t** hash_table;
        CHAR8 **all_keys;
        BOOLEAN ready;
};

static unsigned int dict_hash_string(dict_t *self, CHAR8 key[DICT_KEY_LENGTH]) {
        unsigned hash_val;

        if (!self)
                return 0;

        for (hash_val = 0; *key != '\0'; key++) {
                // 31 odd prime gives better distribution
                hash_val = *key + 31 * hash_val;
        }
        return hash_val % self->size;
}

/**
 * dict_popentry - removes and returns dictionary entry matched with given key
 * @self: handle to dictionary
 * @key:  Key used to lookup dictionary
 *
 * On success, return entry found with matching key.
 * on failure, returns NULL if key is not found in dictionary
 */
dict_entry_t *dict_popentry(dict_t *self, CHAR8 key[DICT_KEY_LENGTH]) {
        dict_entry_t *e, *p = NULL;
        unsigned int hash_val;
        if (!key || !self || !self->ready) {
                return NULL;
        }
        hash_val = dict_hash_string(self, key);
        for (e = self->hash_table[hash_val]; e != NULL; e = e->next) {
                if (!strncmp(key, e->key, DICT_KEY_LENGTH)) {
                        if (!p) {  //first element
                                self->hash_table[hash_val] = e->next;
                        } else {
                                p->next = e->next;
                        }
                        return e;
                }
                p = e;
        }
        return NULL;
}

/**
 * dict_getentry - returns dictionary entry matched with given key
 * @self: handle to dictionary
 * @key:  Key used to lookup dictionary
 *
 * On success, return entry found with matching key.
 * on failure, returns NULL if key is not found in dictionary
 */
dict_entry_t *dict_getentry(dict_t *self, CHAR8 key[DICT_KEY_LENGTH]) {
        dict_entry_t *e;
        if (!self || !key || !self->ready) {
                return NULL;
        }
        for (e = self->hash_table[dict_hash_string(self, key)];
                                        e != NULL; e = e->next) {
                if (!strncmp(key, e->key, DICT_KEY_LENGTH)) {
                        return e;
                }
        }
        return NULL;
}

/**
 * dict_get - returns value (stored in DictEntry) matched with given key
 * @self: handle to Dictionary
 * @key:  Key used to lookup dictionary
 *
 * On success, return 'value' found with matching key.
 * on failure, returns NULL if key is not found in dictionary
 */
value_type dict_get(dict_t *self, CHAR8 key[DICT_KEY_LENGTH]) {
        dict_entry_t *e;
        if (!self || !key || !self->ready) {
                return NULL;
        }
        return (!(e = dict_getentry(self, key)) ? NULL : e->value);
}

/**
 * dict_update - updates (key,value) pair in dictionary
 * @self: handle to Dictionary
 * @key:  Key used to lookup dictionary
 * @val:  value to be stored in dictionary associated with key
 *
 * Lookup a key value in hashTable and enumerates the entry list for
 * matching key. If key is matched in entry list overwrites
 * the (key, value) pair with new values. if no entry is found with given
 * key, a new entry is created and adds to existing entry list.
 *
 * Note that multiple keys  may hash to same HashTable entry. If so,
 * all entries added to a list associated with entry.
 *
 * On success, return 0.
 * on failure, returns -1
 */
int dict_update(dict_t *self, CHAR8 key[DICT_KEY_LENGTH], value_type val) {
        dict_entry_t *e;
        unsigned int hash_val;

        if (!self || !key || !val || !self->ready) {
                return -1;
        }
        if (!(e = dict_getentry(self, key))) {
                e = (dict_entry_t*) AllocatePool(sizeof(dict_entry_t));
                if (!e)
                        return -1;
                hash_val = dict_hash_string(self, key);
                e->next = self->hash_table[hash_val];
                strncpy(e->key, key, DICT_KEY_LENGTH);
                e->value = val;
                self->hash_table[hash_val] = e;
                //book keeping keys for iteration
                assert(self->key_count < self->size);
                if (self->key_count < self->size) {
                        self->all_keys[self->key_count++] = e->key;
                }
                return 0;
        }
        //updates entry
        e->value = val;
        //TODO: should it return existing one?
        return 0;
}

/**
 * dict_length - returns size of dictionary hash table
 * @self: handle to Dictionary
 *
 * size of hash table is same as @Size passed in allocateDict. Not
 * Number of entries in dictionary
 *
 * TODO: May be useful to find number of entries in the Dictionary
 * instead of actual hash table size ?
 *
 * On success, returns size of dictionary hash table
 */
int dict_length(dict_t *self) {
        if (!self || !self->ready) {
                return -1;
        }
        return self->size;
}

/**
 * dict_iterator_begin - initializes Iterator
 * @dict: handle to Dictionary to iterate
 * @it: pointer to DictionaryIterator
 *
 * dict_iterator_begin simply initializes internal indexing values
 * to begin enumeration on the hash table. This is first step to
 * iterate dictionary values, follows DictIteratorNext to start
 * enumerator.
 *
 */
void dict_iterator_begin(dict_t *dict, dict_iterator_t *it) {
        if (!it || !dict || !dict->ready)
                return;
        it->index = 0;
        it->e = NULL;
        it->dict = dict;
        it->begin = TRUE;
}

/**
 * dict_iterator_next - retrieves next dictionary entry(key, value)
 * @it: pointer to iterator used in DictIteratorBegin
 *
 * Simply finds next available (key, val) pair in hash table.
 * on each call iterator maintains track of (key, val) index returned
 * so far, so it can enumerate the next element from last index.
 * If no more elements are found or all (key, val) are enumerated,
 * this simply returns NULL.
 *
 * On success, dictionary entry is returned consisting of (Key, Value) pair
 * On failure, NULL returned
 */
dict_entry_t *dict_iterator_Next(dict_iterator_t *it) {
        dict_t *dict;
        if (!it || !it->begin || !it->dict->ready)
                return NULL;
        it->e = NULL;
        dict = it->dict;
        if (it->index < dict->key_count) {
                it->e = dict_getentry(dict, dict->all_keys[it->index]);
                it->index++;
        }
        return it->e;
}

/**
 * dict_iterator_pop - Removes and returns next dictionary entry(key, value)
 * @it: pointer to iterator used in DictIteratorBegin
 *
 * Same semantics as dict_iterator_next, however in this case dictionary entry
 * consisting of (key, val) is removed from Dictionary.
 *
 * On success, Dictionary entry is returned consisting of (Key, Value) pair
 * On failure, NULL returned
 */
dict_entry_t *dict_iterator_pop(dict_iterator_t *it) {
        int i;
        dict_t *dict;
        if (!it || !it->begin || !it->dict->ready)
                return NULL;
        it->e = NULL;
        dict = it->dict;
        if (it->index < dict->key_count) {
                it->e = dict_popentry(dict, dict->all_keys[it->index]);
                //shift elements
                for (i = it->index; i < (dict->key_count - 1); i++) {
                        dict->all_keys[i] = dict->all_keys[i + 1];
                }
                dict->all_keys[dict->key_count - 1] = NULL;
                dict->key_count--;

        }
        return it->e;
}

/**
 * dict_iterator_end - marks end of iteration
 * @it: pointer to dictionary iterator
 *
 * dict_iterator_end marks end of iterator by resetting internal index tracking
 * of hash table and explicitly sets flag to mark end of enumeration.
 *
 * This is last step in enumerator. Usually called after dict_iterator_next
 * returns NULL on marking end of enumeration.
 *
 *
 */
void dict_iterator_end(dict_iterator_t *it) {
        if (!it || !it->begin || !it->dict->ready)
                return;
        it->index = 0;
        it->e = NULL;
        it->begin = FALSE;
        it->dict = NULL;
}

/**
 * dict_printinfo - Debug information about dictionary
 * @self: handle to Dictionary
 *
 *  TODO - list (key, val) pairs using iterator
 */
void dict_printinfo(dict_t *self) {
        if (!self || !self->ready) {
                return;
        }
        debug(L"Dictionary Size = %d", self->size);
}

/**
 *
 * dict_allocate - allocated dictionary of given size in heap
 * @size: maximum number of entries to be maintained in dictionary
 *
 * allocates dictionary with hash table for storing (key, value) of
 * given size in heap.
 *
 * On success, returns handle to Dictionary allocated in heap
 * On failure, NULL is returned.
 */
dict_t *dict_allocate(int size) {
        dict_t *dict;
        int i;
        CHAR8 *key_ptr;
        dict = (dict_t *) AllocatePool(sizeof(dict_t));
        if (!dict) {
                error(L"failed to allocate dictionary");
                return NULL;
        }
        dict->size = size;
        dict->hash_table = (dict_entry_t**) AllocatePool(sizeof(dict_entry_t*) * size);
        if (!dict->hash_table) {
                error(L"failed to allocate hashTable");
                FreePool(dict);
                return NULL;
        }
        for (i = 0; i < size; i++)
                dict->hash_table[i] = NULL;
        dict->all_keys = (CHAR8**) AllocatePool(sizeof(key_ptr) * size);
        if (!dict->all_keys) {
                error(L"failed to allocate key cache");
                FreePool(dict->hash_table);
                FreePool(dict);
                return NULL;
        }
        dict->key_count = 0;
        dict->ready = TRUE;
        return dict;
}

/**
 * dict_free - frees Dictionary
 * @self: handle to Dictionary
 *
 * deallocates internal resources and itself
 */
void dict_free(dict_t *self) {
        if (!self || !self->ready)
                return;

        if (self->hash_table) {
                FreePool(self->hash_table);
        }
        if (self->all_keys) {
                FreePool(self->all_keys);
        }
        FreePool(self);
}
