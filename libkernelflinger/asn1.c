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


#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include "asn1.h"

#ifndef KERNELFLINGER
#include "userfastboot_ui.h"
#else
#define pr_error(x...) do { } while(0)
#define pr_debug(x...) do { } while(0)
#endif

/* Decode an integer from an ASN.1 message
 * datap - Pointer-pointer to data containing the integer message. Will be
 *         incremented past it on success
 * size - maximum size of the integer data
 * raw - flag indicating we shouldn't try to convert to a C long type
 * intval - Pointer to returned 'integer' value if not raw
 * intdata/intsize - updated to integer data if raw
 * returns the actual amount of bytes consumed, or -1 on error */
int decode_integer(const unsigned char **datap, long *sizep, int raw,
		long *intval, unsigned char **intdata, long *intsize)
{
	ASN1_INTEGER *ai;
	const unsigned char *orig;

	orig = *datap;
	ai = d2i_ASN1_INTEGER(NULL, datap, *sizep);
	if (!ai) {
		pr_error("integer conversion failed\n");
		return -1;
	}

	if (raw) {
		if (intdata && intsize) {
			*intdata = malloc(ai->length);
			if (!*intdata) {
				pr_error("out of memory\n");
				return -1;
			}
			memcpy(*intdata, ai->data, ai->length);
			*intsize = ai->length;
		}
	} else {
		if (intval) {
			*intval = ASN1_INTEGER_get(ai);
		}
	}
	M_ASN1_INTEGER_free(ai);
	*sizep = *sizep - (*datap - orig);
	return 0;
}


int decode_octet_string(const unsigned char **datap, long *sizep,
		unsigned char **osp, long *oslen)
{
	ASN1_OCTET_STRING *os;
	const unsigned char *orig;
	unsigned char *osd;

	orig = *datap;
	os = d2i_ASN1_OCTET_STRING(NULL, datap, *sizep);
	if (!os) {
		pr_error("octet string conversion failed\n");
		return -1;
	}
	if (os->length <= 0) {
		pr_error("empty octet string\n");
		M_ASN1_OCTET_STRING_free(os);
		return -1;
	}

	*oslen = os->length;
	osd = malloc(os->length);
	if (!osd) {
		pr_error("out of memory\n");
		M_ASN1_OCTET_STRING_free(os);
		return -1;
	}

	memcpy(osd, os->data, os->length);
	*osp = osd;
	M_ASN1_OCTET_STRING_free(os);
	*sizep = *sizep - (*datap - orig);
	return 0;
}


int decode_object(const unsigned char **datap, long *sizep,
		int *nid)
{
	ASN1_OBJECT *o;
	const unsigned char *orig;

	orig = *datap;
	o = d2i_ASN1_OBJECT(NULL, datap, *sizep);
	if (!o) {
		pr_error("octet string conversion failed\n");
		return -1;
	}
	*nid = OBJ_obj2nid(o);
	ASN1_OBJECT_free(o);
	if (*nid == NID_undef) {
		pr_error("undefined object\n");
		return -1;
	}

	*sizep = *sizep - (*datap - orig);
	return 0;
}


int decode_printable_string(const unsigned char **datap, long *sizep,
		char *buf, size_t buf_sz)
{
	ASN1_STRING *s;
	const unsigned char *orig;
	int len;

	orig = *datap;
	s = M_d2i_ASN1_PRINTABLESTRING(NULL, datap, *sizep);
	if (!s) {
		pr_error("printable string conversion failed\n");
		return -1;
	}
	if (!s->length) {
		pr_error("empty string\n");
		M_ASN1_PRINTABLESTRING_free(s);
		return -1;
	}

	/* s->length contains the length of the string *NOT* including
	 * the trailing \0. It is guaranteed to be NULL terminated however.
	 * See d2i_ASN1_type_bytes() */
	if ((size_t)(s->length + 1) > buf_sz)
		len = buf_sz;
	else
		len = s->length + 1;

	memcpy(buf, s->data, len);
	buf[len - 1] = '\0';
	M_ASN1_PRINTABLESTRING_free(s);
	*sizep = *sizep - (*datap - orig);
	return 0;
}


/* Consume a sequence type in the ASN.1 message.
 * datap - Pointer to data conatining the sequence. Will be updated to the address
 *         of the first item in the sequence.
 * sizep - Maximum size of the sequence data, adjusted to the actual size on return
 * Returns the number of bytes in datap consumed, or -1 on some error */
int consume_sequence(const unsigned char **datap, long *sizep)
{
	int tag, xclass, j;
	long len, remain, size;
	const unsigned char *data, *orig;

	data = *datap;
	size = *sizep;
	orig = data;

	j = ASN1_get_object(&data, &len, &tag, &xclass, size);
	if (j & 0x80) {
		pr_error("ASN.1 encoding error\n");
		return -1;
	}
	remain = size - (data - orig);

	if (!(j & V_ASN1_CONSTRUCTED) || tag != V_ASN1_SEQUENCE) {
		pr_error("sequence not found\n");
		return -1;
	}

	if (len > remain) {
		pr_error("bad length\n");
		return -1;
	}

	*datap = data;
	*sizep = len;
	return data - orig;
}

/* vim: cindent:noexpandtab:softtabstop=8:shiftwidth=8:noshiftround
 */

