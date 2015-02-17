/*
 * Copyright (c) 2013, Intel Corporation
 * All rights reserved.
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
 */

#include <efi.h>
#include <efilib.h>

#include "acpi.h"
#include "power.h"
#include "efilinux.h"
#include "lib.h"

static struct RSCI_TABLE *RSCI_table = NULL;

#define RSDT_SIG "RSDT"
#define RSDP_SIG "RSD PTR "

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

#ifndef ALLOW_UNSUPPORTED_ACPI_TABLE
static const struct ACPI_DESC_HEADER SUPPORTED_TABLES[] = {
	{ .signature = "RSCI",
	  .oem_id = "INTEL ",
	  .oem_table_id = "BOOTSRC ",
	  .revision = 1 }
};
#endif

/* This macro is defined to get a specified field from an acpi table
 * which will be loader if necessary.
 * <table> parameter is the name of the requested table passed as-is.
 *
 * Example: get_acpi_field(RSCI, wake_source)
 *
 * In this example, the macro requires that :
 *
 *  - RSCI_SIG is a define of the RSCI table signature,
 *  - RSCI_table is a global variable which will contains the table data,
 *  - struct RSCI_TABLE is the type of the requested table.
 */
#define get_acpi_field(table, field)				\
	(typeof(table##_table->field))				\
	_get_acpi_field((CHAR8 *)#table, (CHAR8 *)#field,	\
			(VOID **)&table##_table,		\
			offsetof(struct table##_TABLE, field), sizeof(table##_table->field))

static UINT64 _get_acpi_field(CHAR8 *name, CHAR8 *fieldname _unused, VOID **var, UINTN offset, UINTN size)
{
	if (size > sizeof(UINT64)) {
		return -1;
	}

	if (!*var) {
		EFI_STATUS ret = get_acpi_table((CHAR8 *)name, (VOID **)var);
		if (EFI_ERROR(ret)) {
			return -1;
		}
	}

	UINT64 ret = 0;
	CopyMem((CHAR8 *)&ret, (CHAR8 *)*var + offset, size);
	return ret;
}

EFI_STATUS get_rsdt_table(struct RSDT_TABLE **rsdt)
{
	EFI_GUID acpi2_guid = ACPI_20_TABLE_GUID;
	struct RSDP_TABLE *rsdp;
	EFI_STATUS ret;

	ret = LibGetSystemConfigurationTable(&acpi2_guid, (VOID **)&rsdp);
	if (EFI_ERROR(ret)) {
		goto out;
	}

	if (strncmpa((CHAR8 *)rsdp->signature, (CHAR8 *)RSDP_SIG, sizeof(RSDP_SIG) - 1)) {
		ret = EFI_COMPROMISED_DATA;
		goto out;
	}

	*rsdt = (struct RSDT_TABLE *)(UINTN)rsdp->rsdt_address;
	if (strncmpa((CHAR8 *)(*rsdt)->header.signature, (CHAR8 *)RSDT_SIG, sizeof(RSDT_SIG) - 1)) {
		ret = EFI_COMPROMISED_DATA;
		goto out;
	}
out:
	return ret;
}

static EFI_STATUS acpi_table_is_supported(struct ACPI_DESC_HEADER *t)
{
#ifdef ALLOW_UNSUPPORTED_ACPI_TABLE
	(void)t; /* eliminate compiler warning */
	debug(L"WARNING: skipping validation check on ACPI table %c%c%c%c",
	      t->signature[0], t->signature[1], t->signature[2], t->signature[3]);
	return EFI_SUCCESS;
#else
	const struct ACPI_DESC_HEADER *id = NULL;
	UINTN i;

	for (i = 0; i < ARRAY_SIZE(SUPPORTED_TABLES); i++)
		if (!memcmp(SUPPORTED_TABLES[i].signature, t->signature, sizeof(t->signature))) {
			id = &SUPPORTED_TABLES[i];
			break;
		}

	if (id && !memcmp(id->oem_id, t->oem_id, sizeof(t->oem_id))
	    && !memcmp(id->oem_table_id, t->oem_table_id, sizeof(t->oem_table_id))
	    && id->revision == t->revision)
		return EFI_SUCCESS;

	return EFI_UNSUPPORTED;
#endif
}

static UINTN acpi_verify_checksum(struct ACPI_DESC_HEADER *table)
{
	UINT32 i;
	CHAR8 sum = 0, *data = (CHAR8 *)table;

	for (i = 0; i < table->length; i++)
		sum += data[i];

	return sum == 0 ? EFI_SUCCESS : EFI_CRC_ERROR;
}

EFI_STATUS get_acpi_table(CHAR8 *signature, VOID **table)
{
	struct RSDT_TABLE *rsdt;
	EFI_STATUS ret;
	int nb_acpi_tables;
	int i;

	ret = get_rsdt_table(&rsdt);
	if (EFI_ERROR(ret))
		goto out;

	nb_acpi_tables = (rsdt->header.length - sizeof(rsdt->header)) / sizeof(rsdt->entry[1]);
	ret = EFI_NOT_FOUND;
	for (i = 0 ; i < nb_acpi_tables; i++) {
		struct ACPI_DESC_HEADER *header = (VOID *)(UINTN)rsdt->entry[i];
		if (!strncmpa(header->signature, signature, strlena(signature))) {
			debug(L"Found %c%c%c%c table", signature[0], signature[1], signature[2], signature[3]);
			ret = acpi_verify_checksum(header);
			if (EFI_ERROR(ret)) {
				error(L"Invalid checksum for %c%c%c%c table", signature[0],
				      signature[1], signature[2], signature[3]);
				break;
			}

			ret = acpi_table_is_supported(header);
			if (EFI_ERROR(ret)) {
				error(L"Failed to match a supported ACPI table entry");
				break;
			}

			*table = header;
			ret = EFI_SUCCESS;
			break;
		}
	}
out:
	return ret;
}

enum wake_sources rsci_get_wake_source(void)
{
	return get_acpi_field(RSCI, wake_source);
}

enum reset_sources rsci_get_reset_source(void)
{
	return get_acpi_field(RSCI, reset_source);
}

