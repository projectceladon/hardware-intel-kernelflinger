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

#include "../libkernelflinger/protocol/SdHostIo.h"
#include "../include/libkernelflinger/rpmb.h"

#define RPMB_PARTITION 3

void *rpmb_storage_get_ctx(void)
{
    EFI_STATUS ret;
    EFI_SD_HOST_IO_PROTOCOL *sdio;

    ret = get_emmc_sdio(&sdio);
    if (EFI_ERROR(ret)) {
        trusty_error("Failed to get emmc sdio.\n");
        return NULL;
    }

    return (void *)sdio;
}

static int mmc_rpmb_request(EFI_SD_HOST_IO_PROTOCOL *sdio, rpmb_data_frame *s,
                            unsigned int count, bool is_rel_write)
{
    EFI_STATUS ret;

    ret = emmc_rpmb_send_request(sdio, s, count, is_rel_write);
        if (EFI_ERROR(ret)) {
            trusty_error("Failed to send rpmb request.\n");
            return -1;
        }

    return 0;
}

static int mmc_rpmb_response(EFI_SD_HOST_IO_PROTOCOL *sdio, rpmb_data_frame *s,
                             unsigned int count)
{
    EFI_STATUS ret;

    ret = emmc_rpmb_get_response(sdio, s, count);
    if (EFI_ERROR(ret)) {
        trusty_error("Failed to send rpmb reponse.\n");
        return -1;
    }
    return 0;
}

int rpmb_storage_send(void *rpmb_dev, const void *rel_write_data,
                      size_t rel_write_size, const void *write_data,
                      size_t write_size, void *read_buf, size_t read_size)
{
    uint8_t rpmb_rel_write_data[rel_write_size];
    uint8_t rpmb_write_data[write_size];
    uint8_t rpmb_read_data[read_size];
    uint8_t original_part;
    int ret = TRUSTY_ERR_NONE;

    if (rpmb_dev == NULL) {
        trusty_error("rpmb_dev is NULL.\n");
         return TRUSTY_ERR_INVALID_ARGS;
    }

    ret = get_emmc_partition_num((EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev, &original_part);
    if (EFI_ERROR(ret)) {
        trusty_error("Failed to get emmc current part number.\n");
        return ret;
    }

    if (original_part != RPMB_PARTITION) {
        ret = emmc_partition_switch((EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev, RPMB_PARTITION);
        if (EFI_ERROR(ret)) {
            trusty_error("Failed to switch RPMB parition.\n");
            return ret;
        }
    }

    if (rel_write_size) {
        if (rel_write_size % MMC_BLOCK_SIZE) {
            trusty_error(
                "rel_write_size is not a multiple of MMC_BLOCK_SIZE: %d\n",
                 rel_write_size);
            ret = TRUSTY_ERR_INVALID_ARGS;
            goto end;
        }
        memcpy(rpmb_rel_write_data, rel_write_data, rel_write_size);
        ret = mmc_rpmb_request((EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev,
                               (rpmb_data_frame *)rpmb_rel_write_data,
                                rel_write_size / MMC_BLOCK_SIZE, true);
        if (ret) {
            trusty_error("failed to execute rpmb reliable write\n");
            goto end;
        }
    }

    if (write_size) {
        if (write_size % MMC_BLOCK_SIZE) {
            trusty_error("write_size is not a multiple of MMC_BLOCK_SIZE: %d\n",
                         write_size);
            ret = TRUSTY_ERR_INVALID_ARGS;
            goto end;
        }
        memcpy(rpmb_write_data, write_data, write_size);
        ret = mmc_rpmb_request((EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev,
                               (rpmb_data_frame *)rpmb_write_data,
                                write_size / MMC_BLOCK_SIZE, false);
        if (ret) {
            trusty_error("failed to execute rpmb write\n");
            goto end;
        }
    }

    if (read_size) {
        if (read_size % MMC_BLOCK_SIZE) {
            trusty_error("read_size is not a multiple of MMC_BLOCK_SIZE: %d\n",
                         read_size);
            ret = TRUSTY_ERR_INVALID_ARGS;
            goto end;
        }
        ret = mmc_rpmb_response((EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev,
                                (rpmb_data_frame *)rpmb_read_data,
                                 read_size / MMC_BLOCK_SIZE);
        memcpy((void *)read_buf, rpmb_read_data, read_size);

        if (ret < 0) {
            trusty_error("failed to execute rpmb read\n");
            goto end;
        }
    }

end:
    /*back to original part*/
    if (original_part != RPMB_PARTITION) {
        if (emmc_partition_switch((EFI_SD_HOST_IO_PROTOCOL *)rpmb_dev, original_part) != EFI_SUCCESS) {
            trusty_error("Failed to switch RPMB parition.\n");
            return TRUSTY_ERR_GENERIC;
        }
    }

    return ret;
}
