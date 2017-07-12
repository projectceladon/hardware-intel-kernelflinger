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

/* AOSP ASN.1 grammar for boot signature
 *
 * AndroidVerifiedBootSignature DEFINITIONS ::=
 *      BEGIN
 *           FormatVersion ::= INTEGER
 *           Certificate ::= Certificate OPTIONAL
 *           AlgorithmIdentifier  ::=  SEQUENCE {
 *                algorithm OBJECT IDENTIFIER,
 *                parameters ANY DEFINED BY algorithm OPTIONAL
 *           }
 *           AuthenticatedAttributes ::= SEQUENCE {
 *                  target CHARACTER STRING,
 *                  length INTEGER
 *           }
 *
 *           Signature ::= OCTET STRING
 *      END
 */

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
	}

	ai->parameters = NULL;
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

#ifdef USER
	if (decode_printable_string(datap, &seq_size, aa->target,
				    sizeof(aa->target)))
		return -1;
#endif
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

EFI_STATUS decode_boot_signature(const unsigned char *data, long size,
				 struct boot_signature *bs)
{
	EFI_STATUS ret = EFI_INVALID_PARAMETER;
	const unsigned char *orig = data;
	long format_version;

	memset(bs, 0, sizeof(*bs));

	if (consume_sequence(&data, &size) < 0)
		return EFI_INVALID_PARAMETER;

	if (decode_integer(&data, &size, 0, &format_version,
			   NULL, NULL))
		return EFI_INVALID_PARAMETER;

	debug(L"BootSignature format version %ld", format_version);
	switch (format_version) {
	case 0:
		break;
	case 1:
		{
			BIO *bio;
			bio = BIO_new_mem_buf((void *)data, size);
			if (!bio) {
				error(L"Failed to allocate BIO ressources");
				return EFI_OUT_OF_RESOURCES;
			}
			bs->certificate = d2i_X509_bio(bio, NULL);
			if (bs->certificate) {
				size -= BIO_number_read(bio);
				data += BIO_number_read(bio);
			}
			BIO_free(bio);
			break;
		}
	default:
		error(L"unsupported boot signature format %ld",
		      format_version);
		return EFI_INVALID_PARAMETER;
	}

	if (decode_algorithm_identifier(&data, &size, &bs->id)) {
		error(L"bad algorithm identifier");
		goto err;
	}

	if (decode_auth_attributes(&data, &size, &bs->attributes)) {
		error(L"bad authenticated attributes");
		goto err;
	}

	if (decode_octet_string(&data, &size, (unsigned char **)&bs->signature,
				&bs->signature_len)) {
		error(L"bad signature data");
		goto err;
	}

	bs->total_size = (data - orig);
	return EFI_SUCCESS;

err:
	if (bs->certificate)
		X509_free(bs->certificate);
	if (bs->id.parameters)
		FreePool(bs->id.parameters);
	return ret;
}
