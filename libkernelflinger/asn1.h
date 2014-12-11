/*
 * Copyright (C) 2014 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _ASN_1_H_
#define _ASN_1_H_

int decode_integer(const unsigned char **datap, long *sizep, int raw,
		long *intval, unsigned char **intdata, long *intsize);

int decode_octet_string(const unsigned char **datap, long *sizep,
		unsigned char **osp, long *oslen);

int decode_object(const unsigned char **datap, long *sizep,
		int *nid);

int decode_printable_string(const unsigned char **datap, long *sizep,
		char *buf, size_t buf_sz);

int consume_sequence(const unsigned char **datap, long *sizep);

int skip_sequence(const unsigned char **datap, long *sizep);

#endif

