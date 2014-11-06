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
#include <openssl/objects.h>

#include "keystore.h"
#include "asn1.h"

#ifndef KERNELFLINGER
#include "userfastboot_ui.h"
#else
#define pr_error(x...) do { } while(0)
#define pr_debug(x...) do { } while(0)
#endif

static void free_keybag(struct keybag *kb)
{
	while (kb) {
		struct keybag *n = kb;
		kb = kb->next;

		free(n->info.id.parameters);
		RSA_free(n->info.key_material);
		free(n);
	}
}


void free_keystore(struct keystore *ks)
{
	if (!ks)
		return;

	free(ks->sig.signature);
	free(ks->sig.id.parameters);
	free(ks->inner_data);
	free_keybag(ks->bag);
	free(ks);
}


void free_boot_signature(struct boot_signature *bs)
{
	if (!bs)
		return;

	free(bs->signature);
	free(bs->id.parameters);
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


void dump_keystore(struct keystore *ks)
{
	struct keybag *kb;
	if (!ks)
		return;

	pr_debug("keystore-----------\n");
	pr_debug("format_version        %ld\n", ks->format_version);
	kb = ks->bag;
	pr_debug("key-bag------------\n");
	while (kb) {
		struct keyinfo *ki = &kb->info;
		pr_debug("key-info ---------\n");
		pr_debug("algo id               %d\n", ki->id.nid);
		pr_debug("modulus len           %d\n",
				BN_num_bytes(ki->key_material->n));
		kb = kb->next;
		pr_debug("--end-key-info----\n");
	}
	pr_debug("-end-key-bag------\n");
	dump_boot_signature(&ks->sig);
	pr_debug("-end-keystore-------\n");
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


static int decode_rsa_public_key(const unsigned char **datap, long *sizep,
		RSA **rsap)
{
	long seq_size = *sizep;
	const unsigned char *orig = *datap;
	unsigned char *modulus = NULL;
	long modulus_len;
	unsigned char *exponent = NULL;
	long exponent_len;
	RSA *rsa = NULL;

	if (consume_sequence(datap, &seq_size) < 0)
		goto out_err;

	if (decode_integer(datap, &seq_size, 1, NULL, &modulus,
				&modulus_len))
		goto out_err;

	if (decode_integer(datap, &seq_size, 1, NULL, &exponent,
				&exponent_len))
		goto out_err;

	rsa = RSA_new();
	if (!rsa)
		goto out_err;
	rsa->n = BN_bin2bn(modulus, modulus_len, NULL);
	if (!rsa->n)
		goto out_err;
	rsa->e = BN_bin2bn(exponent, exponent_len, NULL);
	if (!rsa->e)
		goto out_err;

	free(modulus);
	free(exponent);
	*rsap = rsa;
	*sizep = *sizep - (*datap - orig);
	return 0;
out_err:
	if (rsa)
		RSA_free(rsa);
	free(exponent);
	free(modulus);
	return -1;
}


static int decode_keyinfo(const unsigned char **datap, long *sizep,
		struct keyinfo *ki)
{
	long seq_size = *sizep;
	const unsigned char *orig = *datap;

	if (consume_sequence(datap, &seq_size) < 0)
		return -1;

	if (decode_algorithm_identifier(datap, &seq_size, &ki->id)) {
		pr_error("bad algorithm identifier\n");
		return -1;
	}

	if (decode_rsa_public_key(datap, &seq_size, &ki->key_material)) {
		pr_error("bad RSA public key data\n");
		free(ki->id.parameters);
		ki->id.parameters = NULL;
		return -1;
	}

	*sizep = *sizep - (*datap - orig);
	return 0;
}


static int decode_keybag(const unsigned char **datap, long *sizep,
		struct keybag **kbp)
{
	long seq_size = *sizep;
	const unsigned char *orig = *datap;
	struct keybag *ret = NULL;

	if (consume_sequence(datap, &seq_size) < 0)
		goto error;

	while (seq_size > 0) {
		struct keybag *kb = malloc(sizeof *kb);
		if (!kb) {
			pr_error("out of memory\n");
			goto error;
		}

		if (decode_keyinfo(datap, &seq_size, &kb->info)) {
			pr_error("bad keyinfo data\n");
			free(kb);
			goto error;
		}
		kb->next = ret;
		ret = kb;
	}

	*sizep = *sizep - (*datap - orig);
	*kbp = ret;
	return 0;
error:
	free_keybag(ret);
	return -1;
}


static int decode_keystore(const unsigned char **datap, long *sizep,
		struct keystore *ks)
{
	long seq_size = *sizep;
	const unsigned char *orig = *datap;
	int new_seq_size;

	if (consume_sequence(datap, &seq_size) < 0)
		return -1;

	if (decode_integer(datap, &seq_size, 0, &ks->format_version,
			NULL, NULL))
		return -1;

	if (decode_keybag(datap, &seq_size, &ks->bag)) {
		pr_error("bad keybag data\n");
		return -1;
	}

	/* size of the so-called 'inner keystore' before signature
	 * was appended, needed for verification */
	ks->inner_sz = *datap - orig;
	ks->inner_data = malloc(ks->inner_sz);
	if (!ks->inner_data) {
		pr_error("out of memory\n");
		free_keybag(ks->bag);
		return -1;
	}
	memcpy(ks->inner_data, orig, ks->inner_sz);
	/* Now fix the size data in the sequence struct since the
	 * 'inner keybag' sequence does not contain a signature block */
	new_seq_size = ks->inner_sz - 4; // size of the sequence header
	ks->inner_data[2] = (new_seq_size >> 8) & 0xFF;
	ks->inner_data[3] = new_seq_size & 0xff;

	if (decode_boot_signature(datap, &seq_size, &ks->sig)) {
		free_keybag(ks->bag);
		free(ks->inner_data);
		pr_error("bad boot signature data\n");
		return -1;
	}

	*sizep = *sizep - (*datap - orig);
	return 0;
}


struct keystore *get_keystore(const void *data, long size)
{
	const unsigned char *pos = data;
	long remain = size;
	struct keystore *ks = malloc(sizeof(*ks));
	if (!ks)
		return NULL;

	if (decode_keystore(&pos, &remain, ks)) {
		free(ks);
		return NULL;
	}
	return ks;
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

