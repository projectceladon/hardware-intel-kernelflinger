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
 *
 */

#ifndef __ACPI_H__
#define __ACPI_H__

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>

/** Generic ACPI table header **/
struct ACPI_DESC_HEADER {
	CHAR8   signature[4];		/* ASCII Table identifier */
	UINT32  length;			/* Length of the table, including the header */
	CHAR8   revision;		/* Revision of the structure */
	CHAR8   checksum;		/* Sum of all fields must be 0 */
	CHAR8   oem_id[6];		/* ASCII OEM identifier */
	CHAR8   oem_table_id[8];	/* ASCII OEM table identifier */
	UINT32  oem_revision;		/* OEM supplied revision number */
	CHAR8   creator_id[4];		/* Vendor ID of utility creator of the table */
	UINT32  creator_revision;	/* Revision of utility creator of the table */
};

struct RSDP_TABLE {
	CHAR8	signature[8];		/* "RSD PTR " */
	CHAR8	checksum;		/* RSDP Checksum (bytes 0-19) */
	CHAR8	oem_id[6];		/* OEM ID String */
	CHAR8	revision;		/* ACPI Revision (0=1.0,2=2.0) */
	UINT32	rsdt_address;		/* 32-bit RSDT Pointer */
	UINT32	length;			/* RSDP Length */
	UINT64	xsdt_address;		/* 64-bit XSDT Pointer */
	CHAR8	extended_checksum;	/* RSDP Checksum (full) */
	CHAR8	reserved[3];		/* Reserved */
};

struct RSDT_TABLE {
	struct ACPI_DESC_HEADER header;	/* System Description Table Header */
	UINT32 entry[1];		/* Table Entries */
};

struct RSCI_TABLE {
	struct ACPI_DESC_HEADER header;	/* System Description Table Header */
	CHAR8 wake_source;		/* How system woken up from S4 or S5 */
	CHAR8 reset_source;		/* How system was reset */
	CHAR8 reset_type;		/* Identify type of reset */
	CHAR8 shutdown_source;		/* How system was last shutdown */
	UINT32 indicators;		/* Bitmap with additional info */
};

enum {
	OEM1_USE_IA_APPS_CAP,
	OEM1_USE_IA_APPS_RUN
};

struct OEM1_TABLE {
	struct ACPI_DESC_HEADER header;	/* System Description Table Header */
	UINT8 fixedoptions0;		/* Fixed Platform Options 0 */
	UINT8 fixedoptions1;		/* Fixed Platform Options 1*/
	UINT8 dbiingpio;		/* DBIIN GPIO number */
	UINT8 dbioutgpio;		/* DBIOUT GPIO number */
	UINT8 batchptyp;       		/* Identification / Authentication chip
					 * inside the battery */
	UINT16 ia_apps_run;		/* Minimum battery voltage required to
					 * boot the platform if FG has been
					 * reset */
	UINT8 batiddbibase;		/* Resistance in KOhms for BSI used to
					 * indicate a digital battery */
	UINT8 batidanlgbase;		/* Resistance in KOhms for BSI beyond
					 * which the battery is an analog
					 * battery */
	UINT8 ia_apps_cap; 		/* Minimum capacity at which to boot to Main
					 * OS */
	UINT16 vbattfreqlmt;		/* Battery Voltage up to which the CPU
					 * frequency should be limited */
	UINT8 capfreqidx;   		/* Index into the Frequency table at which
					 * the CPU Frequency should be capped. */
	UINT8 rsvd1;			/* Reserved */
	UINT8 battidx; 			/* Battery Index: Charging profile to use in
					 * case of fixed battery */
	UINT8 ia_apps_to_use;		/* Whether to use the IA_APPS_RUN (value
					 * = 1) or IA_APPS_CAP (value = 0) to
					 * while booting */
	UINT8 turbochrg;		/* Maximum Turbo charge supported (in
					 * multiples of 100mA). Zero means no Turbo
					 * charge */
	UINT8 rsvd2[11];		/* Reserved */
} __attribute__ ((packed));

EFI_STATUS get_acpi_table(CHAR8 *signature, VOID **table);
UINT16 oem1_get_ia_apps_run(void);
UINT8 oem1_get_ia_apps_cap(void);
UINT8 oem1_get_ia_apps_to_use(void);

#endif /* __ACPI_H__ */
