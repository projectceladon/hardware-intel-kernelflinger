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

static struct FACP_TABLE *FACP_table = NULL;
#ifdef USE_RSCI
static struct RSCI_TABLE *RSCI_table = NULL;
#endif
static struct OEM1_TABLE *OEM1_table = NULL;

#define SIG_SIZE (sizeof(((struct ACPI_DESC_HEADER *)0)->signature))

static const char XSDT_SIG[SIG_SIZE] = "XSDT";
static const char RSDP_SIG[8] = "RSD PTR ";

#ifndef ALLOW_UNSUPPORTED_ACPI_TABLE
static const struct ACPI_DESC_HEADER SUPPORTED_TABLES[] = {
	{ .signature = "FACP",
	  .oem_id = "INTEL ",
	  .oem_table_id = "EDK2    ",
	  .revision = 5 },
	{ .signature = "RSCI",
	  .oem_id = "INTEL ",
	  .oem_table_id = "BOOTSRC ",
	  .revision = 2 },
	{ .signature = "OEM1",
	  .oem_id = "INTEL ",
	  .oem_table_id = "ENRGYMGT",
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
		if (!memcmp(SUPPORTED_TABLES[i].signature, t->signature, SIG_SIZE)) {
			id = &SUPPORTED_TABLES[i];
			break;
		}

	if (id && !memcmp(id->oem_id, t->oem_id, sizeof(t->oem_id))
	    && !memcmp(id->oem_table_id, t->oem_table_id, sizeof(t->oem_table_id))
	    && id->revision >= t->revision)
		return EFI_SUCCESS;

	return EFI_UNSUPPORTED;
#endif
}

static UINT64 _get_acpi_field(CHAR8 *name, CHAR8 *fieldname _unused, VOID **var, UINTN offset, UINTN size)
{
	EFI_STATUS ret_supported;
	struct ACPI_DESC_HEADER *acpi_desc_hdr = NULL;

	if (size > sizeof(UINT64)) {
		return -1;
	}

	if (!*var) {
		EFI_STATUS ret = get_acpi_table((CHAR8 *)name, var);
		if (EFI_ERROR(ret)) {
			return -1;
		}
	}

	acpi_desc_hdr = *var;
	ret_supported = acpi_table_is_supported(acpi_desc_hdr);
	if (EFI_ERROR(ret_supported)) {
		error(L"Failed to match a supported ACPI table entry");
		return -1;
	}

	/* verify that (offset + size) of element is within the ACPI table */
	if (offset + size > acpi_desc_hdr->length)
		return -1;

	UINT64 ret = 0;
	CopyMem((CHAR8 *)&ret, (CHAR8 *)*var + offset, size);
	return ret;
}


static EFI_STATUS acpi_verify_checksum(struct ACPI_DESC_HEADER *table)
{
	UINT32 i;
	CHAR8 sum = 0, *data = (CHAR8 *)table;

	for (i = 0; i < table->length; i++)
		sum += data[i];

	return sum == 0 ? EFI_SUCCESS : EFI_CRC_ERROR;
}

EFI_STATUS get_xsdt_table(struct XSDT_TABLE **xsdt)
{
	EFI_GUID acpi2_guid = ACPI_20_TABLE_GUID;
	struct RSDP_TABLE *rsdp;
	EFI_STATUS ret;

	ret = LibGetSystemConfigurationTable(&acpi2_guid, (VOID **)&rsdp);
	if (EFI_ERROR(ret)) {
		goto out;
	}

	if (memcmp(rsdp->signature, RSDP_SIG, sizeof(RSDP_SIG))) {
		ret = EFI_COMPROMISED_DATA;
		goto out;
	}

	*xsdt = (struct XSDT_TABLE *)(UINTN)rsdp->xsdt_address;
	if (memcmp((*xsdt)->header.signature, XSDT_SIG, SIG_SIZE)) {
		ret = EFI_COMPROMISED_DATA;
		goto out;
	}

	ret = acpi_verify_checksum((struct ACPI_DESC_HEADER *)*xsdt);
	if (EFI_ERROR(ret)) {
		error(L"Invalid checksum for XSDT table");
		goto out;
	}

out:
	return ret;
}

EFI_STATUS get_acpi_table(const CHAR8 *signature, VOID **table)
{
	struct XSDT_TABLE *xsdt;
	EFI_STATUS ret;
	UINTN i, nb_acpi_tables, sign_count = 1;
	char *end;

	if (!memcmp("DSDT", signature, SIG_SIZE)) {
		UINT64 dsdt = get_acpi_field(FACP, DSDT);
		if (dsdt == (UINT64)-1)
			return EFI_NOT_FOUND;
		*table = (VOID *)(UINTN)dsdt;
		goto out;
	}

	ret = get_xsdt_table(&xsdt);
	if (EFI_ERROR(ret))
		return ret;

	if (!memcmp(XSDT_SIG, signature, SIG_SIZE)) {
		*table = xsdt;
		goto out;
	}

	if (strlen(signature) > SIG_SIZE) {
		sign_count = strtoul((char *)signature + SIG_SIZE, &end, 10);
		if (*end != '\0' || sign_count == 0)
			return EFI_INVALID_PARAMETER;
	}

	nb_acpi_tables = (xsdt->header.length - sizeof(xsdt->header)) / sizeof(xsdt->entry[1]);
	ret = EFI_NOT_FOUND;
	for (i = 0; i < nb_acpi_tables; i++) {
		struct ACPI_DESC_HEADER *header = (VOID *)(UINTN)xsdt->entry[i];
		if (!memcmp(header->signature, signature, SIG_SIZE)) {
			if (sign_count > 1) {
				sign_count--;
				continue;
			}
			*table = header;
			goto out;
		}
	}

	return EFI_NOT_FOUND;

out:
	debug(L"Found %c%c%c%c table", signature[0], signature[1],
	      signature[2], signature[3]);
	ret = acpi_verify_checksum(*table);
	if (EFI_ERROR(ret))
		error(L"Invalid checksum for %c%c%c%c table", signature[0],
		      signature[1], signature[2], signature[3]);

	return ret;
}

#ifdef USE_RSCI
enum wake_sources rsci_get_wake_source(void)
{
	return get_acpi_field(RSCI, wake_source);
}

enum reset_sources rsci_get_reset_source(void)
{
	return get_acpi_field(RSCI, reset_source);
}

enum reset_types rsci_get_reset_type(void)
{
	return get_acpi_field(RSCI, reset_type);
}

UINT32 rsci_get_reset_extra_info(void)
{
	return get_acpi_field(RSCI, reset_extra_info);
}
#else
enum wake_sources rsci_get_wake_source(void)
{
	return WAKE_NOT_APPLICABLE;
}

enum reset_sources rsci_get_reset_source(void)
{
	return RESET_NOT_APPLICABLE;
}

enum reset_types rsci_get_reset_type(void)
{
	return NOT_APPLICABLE;
}

UINT32 rsci_get_reset_extra_info(void)
{
	return -1;
}
#endif /* USE_RSCI */

UINT8 oem1_get_ia_apps_to_use(void)
{
	return get_acpi_field(OEM1, ia_apps_to_use);
}

UINT8 oem1_get_ia_apps_cap(void)
{
	return get_acpi_field(OEM1, ia_apps_cap);
}

UINT16 oem1_get_ia_apps_run(void)
{
	return get_acpi_field(OEM1, ia_apps_run);
}

#if DEBUG_MESSAGES
const CHAR16 *wake_source_string(enum wake_sources ws)
{
	switch (ws) {
	case WAKE_NOT_APPLICABLE:
		return L"Not applicable";
	case WAKE_BATTERY_INSERTED:
		return L"Battery inserted";
	case WAKE_USB_CHARGER_INSERTED:
		return L"USB charger";
	case WAKE_ACDC_CHARGER_INSERTED:
		return L"ACDC charger";
	case WAKE_POWER_BUTTON_PRESSED:
		return L"Power button";
	case WAKE_RTC_TIMER:
		return L"RTC timer";
	case WAKE_BATTERY_REACHED_IA_THRESHOLD:
		return L"Battery reached IA_THRESHOLD";
	case WAKE_ERROR:
		return L"Error";
	}
	return L"Invalid wake source";
}

const CHAR16 *reset_type_string(enum reset_types rt)
{
	switch (rt) {
	case NOT_APPLICABLE:
		return L"Not Applicable";
	case WARM_RESET:
		return L"Warm Reset";
	case COLD_RESET:
		return L"Cold Reset";
	case GLOBAL_RESET:
		return L"Global Reset";
	}
	return L"Invalid Reset Type";
}

const CHAR16 *reset_source_string(enum reset_sources rs)
{
	switch (rs) {
	case RESET_NOT_APPLICABLE:
		return L"Not Applicable";
	case RESET_OS_INITIATED:
		return L"OS Initiated";
	case RESET_FORCED:
		return L"Forced";
	case RESET_FW_UPDATE:
		return L"FW Update";
	case RESET_KERNEL_WATCHDOG:
		return L"Kernel Watchdog";
	case RESET_SECURITY_WATCHDOG:
		return L"Security Watchdog";
	case RESET_SECURITY_INITIATED:
		return L"Security Initiated";
	case RESET_EC_WATCHDOG:
		return L"EC Watchdog";
	case RESET_PMIC_WATCHDOG:
		return L"PMIC Watchdog";
	case RESET_SHORT_POWER_LOSS:
		return L"Short power loss";
	case RESET_PLATFORM_SPECIFIC:
		return L"Platform Specific";
	case RESET_UNKNOWN:
		return L"Unknown";
	case RESET_ERROR:
		return L"Error";
	}
	return L"Invalid Reset Source";
}
#endif
