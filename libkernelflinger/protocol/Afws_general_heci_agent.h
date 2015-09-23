/*
 * Copyright (c) 2015, Intel Corporation
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

#ifndef _AFWS_GENERAL_HECI_AGENT_H_
#define _AFWS_GENERAL_HECI_AGENT_H_


#ifndef BIT
#define BIT(x) (1 << (x))
#endif


#ifdef __cplusplus
extern "C" {
#endif /*  __cplusplus */

        typedef enum
        {
                ANDROID_HECI_AGENT_RESPONSE_CODE_SUCCESS              = 0x00000000,
                ANDROID_HECI_AGENT_RESPONSE_CODE_FAILURE              = 0x00000001,
                ANDROID_HECI_AGENT_RESPONSE_CODE_INVALID_PARAMS       = 0x00000002,
                ANDROID_HECI_AGENT_RESPONSE_CODE_NOT_SUPPORTED        = 0x00000003,
                ANDROID_HECI_AGENT_RESPONSE_CODE_UNKNOWN_CMD          = 0x00000004,
                ANDROID_HECI_AGENT_RESPONSE_INVALID_MSG_FORMAT        = 0x00000005,
                ANDROID_HECI_AGENT_RESPONSE_CODE_RPMB_FAILURE         = 0x00000006
        } ANDROID_HECI_AGENT_RESPONSE_CODE;

        typedef enum
        {
                ANDROID_HECI_AGENT_CMD_CLASS_GENERAL                  = 0x00000000,
                ANDROID_HECI_AGENT_CMD_CLASS_KEY_MASTER               = 0x00000001,
                ANDROID_HECI_AGENT_CMD_CLASS_AMAZON                   = 0x00000002,
                ANDROID_HECI_AGENT_CMD_CLASS_MAX
        } ANDROID_HECI_AGENT_CMD_CLASS;

        typedef enum
        {
                ANDROID_HECI_GENERAL_CMD_ID_GET_SUPPORTED_CLASSES     = 0x00000000,
                ANDROID_HECI_GENERAL_CMD_ID_MAX
        } ANDROID_HECI_GENERAL_CMD_ID;


        typedef struct
        {
                UINT32     CmdClass;
                UINT32     CmdId;
                UINT32     InputSize;
        } ANDROID_HECI_AGENT_REQ_HEADER;

        typedef struct
        {
                UINT32   ClientVersion;
                UINT32   CmdClass;
                UINT32   CmdId;
                UINT32   ResponseCode;
                UINT32   OutputSize;
        } ANDROID_HECI_AGENT_RESP_HEADER;

        typedef struct
        {
                ANDROID_HECI_AGENT_REQ_HEADER          Header;
        } ANDROID_HECI_GENERAL_CMD_GET_SUPPORTED_CLASSES_REQUEST;


        typedef struct
        {
                ANDROID_HECI_AGENT_RESP_HEADER         Header;
                UINT32                                 NumClasses;
                UINT32                                 Classes[0];
        } ANDROID_HECI_GENERAL_CMD_GET_SUPPORTED_CLASSES_RESPONSE;

#ifdef __cplusplus
}
#endif /*  __cplusplus */


#endif // _AFWS_GENERAL_HECI_AGENT_H_
