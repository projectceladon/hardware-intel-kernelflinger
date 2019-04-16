/*
 * Copyright (c) 2019, Intel Corporation
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

#include <lib.h>
#include <acpi.h>

#include "lsacpi.h"

static void print_table(struct ACPI_DESC_HEADER *table)
{
	ss_printf(L"%c%c%c%c  0x%08x  %5d\n",
		  table->signature[0], table->signature[1],
		  table->signature[2], table->signature[3],
		  table, table->length);
}

static EFI_STATUS lsacpi_main(INTN argc,
			      __attribute__((__unused__)) const char **argv)
{
	EFI_STATUS ret;
	struct ACPI_DESC_HEADER *table;
	struct XSDT_TABLE *xsdt;
	UINTN i, count;

	if (argc != 1)
		return EFI_INVALID_PARAMETER;

	ss_printf(L"Name   Address    Size\n-\n");

	ret = get_acpi_table("DSDT", (VOID *)&table);
	if (!EFI_ERROR(ret))
		print_table(table);

	ret = get_acpi_table("XSDT", (VOID *)&xsdt);
	if (EFI_ERROR(ret))
		return EFI_SUCCESS;

	print_table((struct ACPI_DESC_HEADER *)xsdt);

	count = (xsdt->header.length - sizeof(xsdt->header)) /
		sizeof(xsdt->entry[1]);
	for (i = 0; i < count; i++)
		print_table((struct ACPI_DESC_HEADER *)(UINTN)xsdt->entry[i]);

	return EFI_SUCCESS;
}

shcmd_t lsacpi_shcmd = {
	.name = "lsacpi",
	.summary = "List the ACPI tables",
	.help = "Usage: lsacpi",
	.main = lsacpi_main
};
