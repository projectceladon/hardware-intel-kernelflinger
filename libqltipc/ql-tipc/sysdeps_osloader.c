/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <trusty/sysdeps.h>
#include "log.h"
#include "lib.h"
#include <efi.h>
#include <efilib.h>

#define UNUSED(x) (void)(x)

extern int trusty_encode_page_info(struct ns_mem_page_info *page_info,
                                   void *vaddr);

void trusty_lock(struct trusty_dev *dev)
{
    UNUSED(dev);
}
void trusty_unlock(struct trusty_dev *dev)
{
    UNUSED(dev);
}

void trusty_local_irq_disable(unsigned long *state)
{
    UNUSED(state);
}

void trusty_local_irq_restore(unsigned long *state)
{
    UNUSED(state);
}

void trusty_idle(struct trusty_dev *dev)
{
    /* ToDo */
    UNUSED(dev);
}

void trusty_abort(void)
{
    /* ToDo */
    __builtin_unreachable();
}

void trusty_printf(const char *format, ...)
{
    va_list ap;
    CHAR16 *format16;
    format16 = stra_to_str((CHAR8 *)format);

    va_start(ap, format);
    vlog(format16, ap);
    va_end(ap);
    FreePool(format16);
}

void *trusty_memcpy(void *dest, void *src, size_t n)
{
    return memcpy(dest, src, n);
}

void *trusty_memset(void *dest, const int c, size_t n)
{
    return memset(dest, c, n);
}

char *trusty_strcpy(char *dest, const char *src)
{
    return (char *)strcpy((CHAR8 *)dest, (CHAR8 *)src);
}

size_t trusty_strlen(const char *str)
{
    return strlen((CHAR8 *)str);
}

void *trusty_calloc(size_t n, size_t size)
{
    return AllocatePool(n*size);
}

void trusty_free(void *addr)
{
    if (addr)
        FreePool(addr);
}

void *trusty_membuf_alloc(struct ns_mem_page_info *page_info, size_t size)
{
    void *pa = NULL, *aligned_pa = NULL;
    int res;
    EFI_STATUS ret;

    ret = alloc_aligned(&pa, &aligned_pa, size, 4096);

    if (EFI_ERROR(ret)) {
        trusty_printf("alloc_aligned failed\n");
    }

    if (!aligned_pa)
        return NULL;

    /* get memory attibutes */
    res = trusty_encode_page_info(page_info, aligned_pa);
    if (res) {
        trusty_membuf_free(pa);
        return NULL;
    }
    return aligned_pa;
}

void trusty_membuf_free(void *pa)
{
    if (pa)
        FreePool(pa);
}
