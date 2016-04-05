/*
 * Copyright (c) 2016, Intel Corporation
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

#ifndef _SL_VMM_API_H_
#define _SL_VMM_API_H_

#define CPUID_CODE_INFO         0x56583240
#define CPUID_CODE_PERF_SAMPLE  0x56583241
#define CPUID_CODE_PERF_TRACE   0x56583242
#define CPUID_CODE_PERF_PATH    0x56583243
#define CPUID_CODE_EPTAD        0x56583248
#define CPUID_CODE_CACHESIM     0x56583250
#define CPUID_CODE_PCI_TRACE    0x56583261
#define CPUID_CODE_MEM_TRACE    0x56583262
#define CPUID_CODE_PMV          0x56583263

typedef enum perf_type_t {
        SL_CMD_HSEC_GET_INFO        =    0x56583264, /* hypersec interface */
        SL_CMD_HSEC_CONFIG          =    0x56583265,
        SL_CMD_HSEC_START           =    0x56583266,
        SL_CMD_HSEC_STOP            =    0x56583267,
        SL_CMD_HSEC_REG_SECT        =    0x56583268,
        SL_CMD_HSEC_CREATE_VIEW     =    0x56583269,
        SL_CMD_HSEC_REMOVE_VIEW     =    0x5658326A,
        SL_CMD_HSEC_ADD_PAGE        =    0x5658326B,
        SL_CMD_HSEC_INIT_VIEW       =    0x5658326C,
        SL_CMD_HSEC_CHANGE_MEM_PERM =    0x5658326D,
        SL_CMD_HSEC_CHK_ACCESS_RIGHT=    0x5658326E,
        SL_CMD_HSEC_REG_VIDT        =    0x5658326F,
        SL_CMD_HSEC_REG_SL_INFO     =    0x56583270,
        SL_CMD_HSEC_GET_CURR_VIEW   =    0x56583271,
        SL_CMD_HSEC_UPDATE_PERM     =    0x56583272,
        SL_CMD_HSEC_UUID            =    0x56583273,
        SL_CMD_HSEC_MAP_SHM         =    0x56583274,
        SL_CMD_HSEC_VIDT_VERIFY_STATUS = 0x56583275,
        SL_CMD_HSEC_GET_DEBUG_STATUS =   0x56583276,
        SL_CMD_HSEC_VERIFY_VIDT     =    0x56583277,
        SL_CMD_HSEC_UNMAP_SHM       =    0x56583278,
        SL_CMD_HSEC_GET_UUID_INSTANCE_COUNT = 0x56583279,
        SL_CMD_HSEC_SET_GVB_INFO    =    0x5658327A,
        SL_CMD_HSEC_GET_GVB_INFO    =    0x5658327B,
        SL_CMD_HSEC_ACTIVATE_KEEP_ALIVE_VIEW = 0x5658327C,
        SL_CMD_HSEC_RESERVED1       =    0x5658327D, /* Reserved for future use */
        SL_CMD_HSEC_RESERVED2       =    0x5658327E,
        SL_CMD_HSEC_RESERVED3       =    0x5658327F,
        SL_CMD_HSEC_GET_TA_PROPERTIES =  0x56583280,
        SL_CMD_HSEC_PSTA_GET_BOOT_INFO=  0x56583281,
        SL_CMD_HSEC_GET_VMM_VIEWID    =  0x56583282,
        SL_CMD_HSEC_GET_AVAIL_HEAP    =  0x56583283,
        SL_CMD_HSEC_GET_VIEW_STATS    =  0x56583284,
        SL_CMD_HSEC_GET_VMEXIT_COUNT  =  0x56583285,
        SL_CMD_HSEC_MAX               =  0x56583286
} perf_type_t;

typedef enum sl_ret_code_t {
        SL_SUCCESS = 0x0,
        SL_ERROR_INVALID_VIEW,
        SL_ERROR_BAD_PARAMETERS,
        SL_ERROR_TR_INVALID_ACCESS,
        SL_ERROR_TR_INVALID_PERMS,
        SL_ERROR_TR_READ_FAILURE,
        SL_ERROR_OUT_OF_MEMORY,
        SL_ERROR_TR_PERM_MISMATCH,
        SL_ERROR_TR_VERIFICATION,
        SL_ERROR_TR_HASH_CALCULATION,
        SL_ERROR_TR_ITEM_NOT_FOUND,
        SL_ERROR_TR_WRITE,
        SL_ERROR_TR_INVALID_TYPE,
        SL_ERROR_TR_DEBUG_NOT_ENABLED,
        SL_ERROR_TR_NO_PHYS_MEM,
        SL_ERROR_TR_UNKNOWN
} sl_ret_code_t;

typedef struct sl_gvb_data {
        UINT32 version; /* Data structure version */
        UINT32 lock_state; /* Device state to bind with */
        UINT32 key_size; /* Length of the key_value */
        UINT8  key_value[SHA256_DIGEST_LENGTH]; /* HASH of the GVB public key */
} __attribute__((packed)) sl_gvb_data_t;

typedef struct sl_version {
        UINT16 major;
        UINT16 minor;
        CHAR8  magic[2];
        UINT8  type;
        UINT8  soc;
} sl_version_t;

#endif /* _SL_VMM_API_H_ */
