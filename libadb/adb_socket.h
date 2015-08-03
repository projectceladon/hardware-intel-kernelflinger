/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jeremy Compostella <jeremy.compostella@intel.com>
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

#ifndef _ADB_SOCKET_H_
#define _ADB_SOCKET_H_

#include <efi.h>
#include <efilib.h>

#include "adb.h"

typedef struct asock * asock_t;

struct service;

#define MAX_ADB_SOCKET 5

/* Host to device */
EFI_STATUS asock_open(UINT32 remote, struct service *service, char *arg);
EFI_STATUS asock_close(asock_t s);
EFI_STATUS asock_okay(asock_t s);
EFI_STATUS asock_read(asock_t s, unsigned char *data, UINT32 length);

/* Device to host */
EFI_STATUS asock_write(asock_t s, unsigned char *data, UINT32 length);
EFI_STATUS asock_send_okay(asock_t s);
EFI_STATUS asock_send_close(asock_t s);

/* Tools */
void *asock_context(asock_t s);
asock_t asock_find(UINT32 local, UINT32 remote);
void asock_close_all();

#endif	/* _ADB_SOCKET_H_ */
