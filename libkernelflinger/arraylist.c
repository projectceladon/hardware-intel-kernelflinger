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

#include "arraylist.h"
#include "lib.h"

#include <stdio.h>
#include <stdlib.h>

// extend size of arraylist once original limit is reached
#define ARRAYLIST_DATA_EXTEND                4

struct arraylist_t {
        int size;
        int extend_size;
        int data_marker;
        char **data;
};

/**
 * arraylist_length - Returns number of entries in arraylist
 * @self: handle to arraylist
 *
 * On Success,
 * Returns number of entries stored in arraylist NOT arraylist size
 * If no entries are found returns 0.
 */
int arraylist_length(arraylist_t *self) {
        if (!self)
                return 0;
        return self->data_marker;
}

/**
 * arraylist_get - Returns arraylist entry at given index
 * @self: handle to arraylist
 * @index: index of arraylist
 *
 *
 * On success, returns a entry stored at given index.
 * On failure, returns NULL if given index is <0 or >numberOfEntries stored.
 */
char *arraylist_get(arraylist_t *self, int index) {
        if (!self)
                return NULL;

        if (index >= 0 && index <= self->data_marker)
                return self->data[index];
        return NULL;
}

/**
 * arraylist_append - appends a entry at the end of arraylist.
 * @self: handle to arraylist
 * @value : value to be stored.
 *
 * arraylist_append as a given value at the end of the arraylist.
 * If the arraylist  is full (last index is size of the arraylist) -
 * then arraylist is dynamically resized with  extended size (which is
 * set current  length + 4).
 *
 * On success, returns 0.
 * On failure, returns -1.
 */
int arraylist_append(arraylist_t *self, char *value) {
        char **new_data;

        if (!self)
                return -1;

        if (self->data_marker > self->size) {
                new_data = ReallocatePool(self->data, self->size * sizeof(char *),
                                (self->size + self->extend_size) * sizeof(char *));
                if (!new_data) {
                        error(L"ReallocatePool failed for ArrayList extend data");
                        return -1;
                }
                self->data = new_data;
                self->size += self->extend_size;
        }
        self->data_marker++;
        self->data[self->data_marker] = value;
        return 0;

}

/**
 * arraylist_pop - removes last entry from arraylist
 * @self: handle to ArrayList
 *
 * arraylist_pop - removes the last entry in the arraylist and adjusts
 * number Of entries in the arraylist. If no entries are found then returns NULL.
 */
char *arraylist_pop(arraylist_t *self) {
        char *data = NULL;

        if (!self)
                return NULL;

        if (self->data_marker >= 0) {
                data = self->data[self->data_marker];
                self->data[self->data_marker] = NULL;
                self->data_marker--;
        }
        return data;
}

/**
 * arraylist_printinfo - prints debug information about arraylist
 * @self: handle to arraylist
 *
 * Enumerates all entries stored in ArrayList into debug log.
 *
 */
void arraylist_printinfo(arraylist_t *self) {
        int i;

        if (!self)
                return;

        debug(L"ArrayList Size:%d", self->size);
        debug(L"ArrayList dataSize:%d", self->data_marker);
        for (i = 0; i <= self->data_marker; i++)
                debug(L"ArrayList data:0x%lx @ index=%d", self->data[i], i);
}

/**
 * arraylist_allocate- allocates re-sizable array of given size in heap
 * @size - capacity of arrayList (number of entries)
 * On success, ArrayList handle to allocated memory is returned.
 * On failure, NULL is returned.
 */
arraylist_t *arraylist_allocate(int size) {
        arraylist_t *head;
        head = (arraylist_t *) AllocatePool(sizeof(arraylist_t));
        if (!head) {
                error(L"failed to allocate memory");
                return NULL;
        }
        head->size = size;
        head->data_marker = -1;
        head->data = AllocatePool(size * sizeof(char*));
        if (!head->data) {
                FreePool(head->data);
                FreePool(head);
                return NULL;
        }
        head->extend_size = ARRAYLIST_DATA_EXTEND;

        return head;
}

/**
 * arraylist_free - Frees arraylist allocated in arraylist_allocate
 * @self: handle to arraylist
 *
 * frees arraylist internal resources and itself
 *
 */
void arraylist_free(arraylist_t *self) {
        if (!self)
                return;

        if (self->data) {
                FreePool(self->data);
        }
        FreePool(self);
}
