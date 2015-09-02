/*
 * Copyright (C) 2014 The Android Open Source Project
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
#include <openssl/x509.h>
#include <openssl/objects.h>

#include "signature.h"
#include "asn1.h"

#ifndef KERNELFLINGER
#include "userfastboot_ui.h"
#else
#include "lib.h"
#define pr_error(x, ...) error(CONVERT_TO_WIDE(x), ##__VA_ARGS__)
#define pr_debug(x, ...) debug(CONVERT_TO_WIDE(x), ##__VA_ARGS__)
#endif

void free_boot_signature(struct boot_signature *bs)
{
	if (!bs)
		return;

	free(bs->signature);
	free(bs->id.parameters);
	if (bs->certificate)
		X509_free(bs->certificate);
	free(bs);
}


#ifndef KERNELFLINGER
void dump_boot_signature(struct boot_signature *bs)
{
	pr_debug("boot sig format       %ld\n", bs->format_version);
	pr_debug("boot sig algo id      %d\n", bs->id.nid);
	pr_debug("target                %s\n", bs->attributes.target);
	pr_debug("length                %ld\n", bs->attributes.length);
	pr_debug("signature len         %ld\n", bs->signature_len);
}
#endif

static int decode_algorithm_identifier(const unsigned char **datap, long *sizep,
		struct algorithm_identifier *ai)
{
	long seq_size = *sizep;
	const unsigned char *orig = *datap;

	if (consume_sequence(datap, &seq_size) < 0)
		return -1;

	if (decode_object(datap, &seq_size, &ai->nid))
		return -1;

	if (seq_size) {
		pr_error("parameters not supported yet\n");
		return -1;
	} else {
		ai->parameters = NULL;
	}

	*sizep = *sizep - (*datap - orig);
	return 0;
}


static int decode_auth_attributes(const unsigned char **datap, long *sizep,
		struct auth_attributes *aa)
{
	long seq_size = *sizep;
	const unsigned char *orig = *datap;

	if (consume_sequence(datap, &seq_size) < 0)
		return -1;

	if (decode_printable_string(datap, &seq_size, aa->target,
				sizeof(aa->target)))
		return -1;

	if (decode_integer(datap, &seq_size, 0, &aa->length,
				NULL, NULL))
		return -1;

	/* Note the address and size of auth_attributes block,
	 * as this blob needs to be appended to the boot image
	 * before generating a signature */
	aa->data = orig;
	aa->data_sz = *datap - orig;

	*sizep = *sizep - (*datap - orig);
	return 0;
}


static int decode_boot_signature(const unsigned char **datap, long *sizep,
		struct boot_signature *bs)
{
	long seq_size = *sizep;
	const unsigned char *orig = *datap;

	if (consume_sequence(datap, &seq_size) < 0)
		return -1;

	if (decode_integer(datap, &seq_size, 0, &bs->format_version,
				NULL, NULL))
		return -1;

	pr_debug("BootSignature format version %ld\n", bs->format_version);
	switch (bs->format_version) {
	case 0:
		break;
	case 1:
	{
		BIO *bio;
		bio = BIO_new_mem_buf((void *)*datap, seq_size);
		if (!bio) {
			pr_error("Failed to allocate BIO ressources\n");
			return -1;
		}
		bs->certificate = d2i_X509_bio(bio, NULL);
		if (bs->certificate) {
			seq_size -= BIO_number_read(bio);
			*datap += BIO_number_read(bio);
		}
		BIO_free(bio);
		break;
	}
	default:
		pr_error("unsupported boot signature format %ld\n",
			 bs->format_version);
		return -1;
	}

	if (decode_algorithm_identifier(datap, &seq_size, &bs->id)) {
		pr_error("bad algorithm identifier\n");
		return -1;
	}

	if (decode_auth_attributes(datap, &seq_size, &bs->attributes)) {
		pr_error("bad authenticated attributes\n");
		free(bs->id.parameters);
		return -1;
	}

	if (decode_octet_string(datap, &seq_size, (unsigned char **)&bs->signature,
				&bs->signature_len)) {
		pr_error("bad signature data\n");
		free(bs->id.parameters);
		return -1;
	}

	bs->total_size = (*datap - orig);
	*sizep = *sizep - (*datap - orig);
	return 0;
}

struct boot_signature *get_boot_signature(const void *data, long size)
{
	const unsigned char *pos = data;
	long remain = size;
	struct boot_signature *bs = malloc(sizeof(*bs));
	if (!bs)
		return NULL;

	if (decode_boot_signature(&pos, &remain, bs)) {
		free(bs);
		return NULL;
	}
	return bs;
}

/* vim: cindent:noexpandtab:softtabstop=8:shiftwidth=8:noshiftround
 */

