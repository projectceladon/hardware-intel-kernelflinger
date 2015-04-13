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

#ifndef _ARRAYLIST_H
#define _ARRAYLIST_H

typedef struct arraylist_t arraylist_t;


/**
 * arraylist_allocate- allocates re-sizable array of given size in heap
 * @size - capacity of arraylist (number of entries)
 * On success, ArrayList handle to allocated memory is returned.
 * On failure, NULL is returned.
 */
arraylist_t *arraylist_allocate(int size);

/**
 * arraylist_free - Frees ArrayList allocated in arraylist_allocate()
 * @self: handle to arraylist
 *
 * frees ArrayList internal resources and itself
 *
 */
void arraylist_free(arraylist_t *self);

/**
 * arraylist_length - Returns number of entries of arraylist
 * @self: handle to arraylist
 *
 * On Success,
 * Returns number of entries stored in arraylist NOT arraylist size
 * If no entries are found returns 0.
 */
int arraylist_length(arraylist_t *self);

/**
 * arraylist_get - Returns arraylist entry at given index
 * @self: handle to arraylist
 * @index: index of arraylist
 *
 * On success, returns a entry stored at given index.
 * On failure, returns NULL if given index is <0 or >number of entries stored.
 */
char *arraylist_get(arraylist_t *self, int index);

/**
 * arraylist_pop - removes last entry from arraylist
 * @self: handle to ArrayList
 *
 * arraylist_pop - removes the last entry in the arraylist and adjusts
 * number Of entries in the arrayList. If no entries are found then returns NULL.
 */
char *arraylist_pop(arraylist_t *self);

/**
 * arraylist_append - appends a entry at the end of arraylist.
 * @self: handle to ArrayList
 * @value : value to be stored.
 *
 * arraylist_append as a given value at the end of the arraylist.
 * If the arrayList  is full (last index is size of the arrayList) -
 * then arraylist is dynamically resized.
 */
int arraylist_append(arraylist_t *self, char *value);

/**
 * arraylist_printinfo - prints debug information about arraylist
 * @self: handle to ArrayList
 *
 * Enumerates all entries stored in arraylist into debug log.
 */
void arraylist_printinfo(arraylist_t *self);

#endif
