/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors:  Jeremy Compostella <jeremy.compostella@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
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

#include <efi.h>
#include <efilib.h>
#include <lib.h>
#include <ui.h>

#include "res/img_res.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

static UINT64 get_blt_size(UINTN width, UINTN height)
{
	UINTN size = MultU64x32 ((UINT64) width, height);

	if (size > DivU64x32((UINTN) ~0, sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL), NULL))
		return 0;

	return MultU64x32(size, sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
}

/*
 * Bilinear interpolation:
 * f(x,y) = (1/(x2-x1)(y2-y1)) * (f(Q11)(x2-x)(y2-y) +
 *				f(Q21)(x-x1)(y2-y) +
 *				f(Q12)(x2-x)(y-y1) +
 *				f(Q22)(x-x1)(y-y1))
 */
static void bilinear_scale(unsigned char *s, unsigned char *d,
			   int sx, int sy, int dx, int dy,
			   int depth)
{
	double ratio_x = (double)(sx - 1) / dx;
	double ratio_y = (double)(sy - 1) / dy;
	int i, j, k;
	sx *= depth;
	for (i = 0; i < dy; i++ )
		for (j = 0; j < dx; j++) {
			double x = j * ratio_x;
			double y = i * ratio_y;
			int x1 = x;
			int x2 = x1 + 1;
			int y1 = y;
			int y2 = y1 + 1;
			for (k = 0; k < depth; k++) {
				d[j * depth + i * dx * depth + k] = (1 / ((x2 - x1) * (y2 - y1))) *
					(s[x1 * depth + y1 * sx + k] * (x2 - x) * (y2 - y) +
					 s[x2 * depth + y1 * sx + k] * (x - x1) * (y2 - y) +
					 s[x1 * depth + y2 * sx + k] * (x2 - x) * (y - y1) +
					 s[x2 * depth + y2 * sx + k] * (x - x1) * (y - y1));
			}
		}
}

ui_image_t *ui_image_get(const char *name)
{
	unsigned int i;

	for (i = 0 ; i < ARRAY_SIZE(ui_images) ; i++)
		if (!strcmp((CHAR8 *)ui_images[i].name, (CHAR8 *)name))
			return &ui_images[i];

	return NULL;
}

EFI_STATUS ui_image_draw(ui_image_t *image, UINTN x, UINTN y)
{
	EFI_STATUS ret;

	ret = ui_draw_blt(image->blt, x, y, image->width, image->height);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to display image %a", image->name);

	return ret;
}

EFI_STATUS ui_image_draw_scale(ui_image_t *image, UINTN x, UINTN y, UINTN width, UINTN height)
{
	EFI_STATUS ret = EFI_SUCCESS;
	ui_image_t to_draw;

	memcpy(&to_draw, image, sizeof(to_draw));

	if (width == 0)
		width = to_draw.width * height / to_draw.height;
	if (height == 0)
		height = to_draw.height * width / to_draw.width;

	to_draw.blt = AllocatePool(get_blt_size(width, height));
	if (!to_draw.blt) {
		ret = EFI_OUT_OF_RESOURCES;
		efi_perror(ret, L"Failed to allocate buffer");
		goto out;
	}

	to_draw.width = width;
	to_draw.height = height;

	bilinear_scale((unsigned char *)image->blt,
		       (unsigned char *)to_draw.blt,
		       image->width, image->height,
		       to_draw.width, to_draw.height,
		       sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));

	ret = ui_image_draw(&to_draw, x, y);

out:
	if (to_draw.blt)
		FreePool(to_draw.blt);
	return ret;
}
