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

#ifndef _DICT_H
#define _DICT_H

#include <stdio.h>
#include <stdlib.h>
#include "log.h"

typedef char* value_type;

typedef struct dict_t dict_t;
#define DICT_KEY_LENGTH 64

typedef struct dict_entry_t dict_entry_t;
struct dict_entry_t {
        dict_entry_t *next;
        CHAR8 key[DICT_KEY_LENGTH];
        value_type value;
};

typedef struct dict_iterator_t dict_iterator_t;
struct dict_iterator_t {
        int index;
        dict_entry_t *e;
        BOOLEAN begin;
        dict_t *dict;
};

/**
 *
 * dict_allocate - allocated dictionary of given size in heap
 * @size: maximum number of entries to be maintained in dictionary
 *
 * allocates dictionary with hash table (key, value) pair of
 * given size in heap.
 *
 * On success, returns handle to Dictionary allocated in heap
 * On failure, NULL is returned.
 */
dict_t *dict_allocate(int size);

/**
 * dict_free - frees Dictionary
 * @self: handle to Dictionary
 *
 * deallocates internal resources and itself
 */
void dict_free(dict_t *self);

/**
 * dict_popentry - removes and returns dictionary entry matched with given key
 * @self: handle to dictionary
 * @key:  Key used to lookup dictionary
 *
 * On success, return entry found with matching key.
 * on failure, returns NULL if key is not found in dictionary
 */
dict_entry_t *dict_popentry(dict_t *self, CHAR8 key[DICT_KEY_LENGTH]);

/**
 * dict_getentry - returns dicitonary entry matched with given key
 * @self: handle to dictionary
 * @key:  Key used to lookup dictionary
 *
 * On success, return entry found with matching key.
 * on failure, returns NULL if key is not found in dictionary
 */
dict_entry_t *dict_getentry(dict_t *self, CHAR8 key[DICT_KEY_LENGTH]);

/**
 * dict_get - returns value (stored in dictionary entry) matched with given key
 * @self: handle to dictionary
 * @key:  Key used to lookup dictionary
 *
 * On success, return 'value' found with matching key.
 * on failure, returns NULL if key is not found in dictionary
 */
value_type dict_get(dict_t *self, CHAR8 key[DICT_KEY_LENGTH]);

/**
 * dict_update - updates key,value pair in dictionary
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
int dict_update(dict_t *self, CHAR8 key[DICT_KEY_LENGTH], value_type val);

/**
 * dict_length - returns size of dictionary hash table
 * @self: handle to dictionary
 *
 * TODO: May be useful to find number of entries in the Dictionary
 * instead of actual hash table size ?
 *
 * On success, returns size of dictionary hash table
 */
int dict_length(dict_t *self);

/**
 * dict_iterator_begin - initializes iterator for enumeration
 * @dict: handle to Dictionary to iterate
 * @it: pointer to dictionary iterator
 *
 * dict_iterator_begin simply initializes internal indexing values
 * to begin enumeration on the hash table. This is first step to
 * iterate dictionary values, follows DictIteratorNext to start
 * enumerator.
 *
 */
void dict_iterator_begin(dict_t *self, dict_iterator_t *it);

/**
 * dict_iterator_next - retrieves next dictionary entry(key, value)
 * @it: pointer to iterator used in dict_iterator_begin
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
dict_entry_t *dict_iterator_Next(dict_iterator_t *it);

/**
 * dict_iterator_pop - Removes and returns next dictionary entry(key, value)
 * @it: pointer to iterator used in dict_iterator_begin
 *
 * Same semantics as DictIteratorNext, however in this case DictEntry consisting
 * of (key, val) is removed from Dictionary.
 *
 * On success, DictEntry is returned consisting of (Key, Value) pair
 * On failure, NULL returned
 */
dict_entry_t *dict_iterator_pop(dict_iterator_t *it);

/**
 * dict_iterator_end - marks end of iteration
 * @it: pointer to dictionary iterator
 *
 * dict_iterator_end marks end of iterator by resetting internal index tracking
 * of hash table and explicitly sets a flag to mark end of enumeration.
 *
 * This is last step in enumerator. Usually this is called after DictIteratorNext
 * returns NULL on enumeration marking end of enumeration.
 *
 */
void dict_iterator_end(dict_iterator_t *it);

/**
 * dict_printinfo - Debug information about dictionary
 * @self: handle to Dictionary
 *
 */
void dict_printinfo(dict_t *self);
#endif

