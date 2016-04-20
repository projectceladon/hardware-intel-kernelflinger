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
#include "lib.h"

void free_boot_signature(struct boot_signature *bs)
{
	if (!bs)
		return;

	FreePool(bs->signature);
	FreePool(bs->id.parameters);
	if (bs->certificate)
		X509_free(bs->certificate);
	FreePool(bs);
}

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
		error(L"parameters not supported yet");
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

	debug(L"BootSignature format version %ld", bs->format_version);
	switch (bs->format_version) {
	case 0:
		break;
	case 1:
	{
		BIO *bio;
		bio = BIO_new_mem_buf((void *)*datap, seq_size);
		if (!bio) {
			error(L"Failed to allocate BIO ressources");
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
		error(L"unsupported boot signature format %ld",
		      bs->format_version);
		return -1;
	}

	if (decode_algorithm_identifier(datap, &seq_size, &bs->id)) {
		error(L"bad algorithm identifier");
		return -1;
	}

	if (decode_auth_attributes(datap, &seq_size, &bs->attributes)) {
		error(L"bad authenticated attributes");
		FreePool(bs->id.parameters);
		return -1;
	}

	if (decode_octet_string(datap, &seq_size, (unsigned char **)&bs->signature,
				&bs->signature_len)) {
		error(L"bad signature data");
		FreePool(bs->id.parameters);
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
	struct boot_signature *bs = AllocatePool(sizeof(*bs));
	if (!bs)
		return NULL;

	if (decode_boot_signature(&pos, &remain, bs)) {
		FreePool(bs);
		return NULL;
	}
	return bs;
}

/* vim: cindent:noexpandtab:softtabstop=8:shiftwidth=8:noshiftround
 */

