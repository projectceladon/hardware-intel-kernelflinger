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

#include <trusty/rpmb.h>
#include <trusty/trusty_dev.h>
#include <trusty/util.h>


#define UNUSED(x) (void)(x)

void *rpmb_storage_get_ctx(void)
{
    return NULL;
}

int rpmb_storage_send(void *rpmb_dev, const void *rel_write_data,
                      size_t rel_write_size, const void *write_data,
                      size_t write_size, void *read_buf, size_t read_size)
{
    UNUSED(rpmb_dev);
    UNUSED(rel_write_data);
    UNUSED(rel_write_size);
    UNUSED(write_data);
    UNUSED(write_size);
    UNUSED(read_buf);
    UNUSED(read_size);
    return TRUSTY_ERR_NONE;
}
