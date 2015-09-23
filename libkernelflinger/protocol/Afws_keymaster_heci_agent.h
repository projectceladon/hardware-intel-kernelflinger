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

#ifndef _AFWS_KEYMASTER_HECI_AGENT_H_
#define _AFWS_KEYMASTER_HECI_AGENT_H_

#include "Afws_general_heci_agent.h"


//10C4F8F7-650B-4878-A5C5-740FD475769A
#define ANDROID_HECI_KEYMASTER_AGENT_GUID                  { 0x10c4f8f7, 0x650b, 0x4878, {0xa5, 0xc5, 0x74, 0xf, 0xd4, 0x75, 0x76, 0x9a} }


#define ANDROID_HECI_KEYMASTER_AGENT_CMD_VERSION                  1
#define ANDROID_HECI_KEYMASTER_AGENT_MAX_MTU                      4096


#define ANDROID_HECI_KEYMASTER_KEY_OPAQUE_SIZE                    0
#define ANDROID_HECI_KEYMASTER_PUBLIC_EXPONENT_MAX_SIZE           4
#define ANDROID_HECI_KEYMASTER_INTERFACE_VERSION                  1
#define ANDROID_HECI_KEYMASTER_MAX_KEY_SIZE                       256
#define ANDROID_HECI_KEYMASTER_PCR_EXTEND_MESSAGE_SIZE            32


#ifdef __cplusplus
extern "C" {
#endif /*  __cplusplus */


        typedef enum
        {
                ANDROID_HECI_KEYMASTER_CMD_ID_GET_CAPS                 = 0x00000000,
                ANDROID_HECI_KEYMASTER_CMD_ID_RSA_GEN_KEY              = 0x00000001,
                ANDROID_HECI_KEYMASTER_CMD_ID_RSA_IMPORT_KEY           = 0x00000002,
                ANDROID_HECI_KEYMASTER_CMD_ID_RSA_GET_PUBLIC_KEY       = 0x00000003,
                ANDROID_HECI_KEYMASTER_CMD_ID_RSA_DELETE_ALL_KEYS      = 0x00000004,
                ANDROID_HECI_KEYMASTER_CMD_ID_RSA_SIGN_DATA_NOPAD      = 0x00000005,
                ANDROID_HECI_KEYMASTER_CMD_ID_RSA_VERIFY_DATA_NOPAD    = 0x00000006,
                ANDROID_HECI_KEYMASTER_CMD_ID_PCR_EXTEND               = 0x00000007,
                ANDROID_HECI_KEYMASTER_CMD_ID_MAX
        } ANDROID_HECI_KEYMASTER_CMD_ID;


        typedef enum
        {
                ANDROID_HECI_KEYMASTER_KEY_TYPE_RSA,
                ANDROID_HECI_KEYMASTER_KEY_TYPE_DSA,
                ANDROID_HECI_KEYMASTER_KEY_TYPE_EC
        } ANDROID_HECI_KEYMASTER_KEY_TYPE;

        typedef enum
        {
                ANDROID_HECI_KEYMASTER_RSA_KEY_SIZE_512      = BIT(0),
                ANDROID_HECI_KEYMASTER_RSA_KEY_SIZE_1024     = BIT(1),
                ANDROID_HECI_KEYMASTER_RSA_KEY_SIZE_2048     = BIT(2)
        } ANDROID_HECI_KEYMASTER_RSA_KEY_SIZE;

        typedef struct
        {
                UINT32                                  Type;
                UINT32                                  Length;
                UINT8                                   Value[0];
        } ANDROID_HECI_KEYMASTER_KEY_CAPS;

        typedef struct
        {
                UINT32                                 KeySizes;
                UINT32                                 KeyOpaqueSize;
        } ANDROID_HECI_KEYMASTER_RSA_CAPS_PARAMS;


        typedef struct
        {
                ANDROID_HECI_AGENT_REQ_HEADER          Header;
        } ANDROID_HECI_KEYMASTER_CMD_GET_CAPS_REQUEST;

        typedef struct
        {
                ANDROID_HECI_AGENT_RESP_HEADER            Header;
                UINT32                                    InterfaceVersion;
                UINT32                                    NumAlgs;
                ANDROID_HECI_KEYMASTER_KEY_CAPS           KeyCapabilities[0];
        } ANDROID_HECI_KEYMASTER_CMD_GET_CAPS_RESPONSE;

        typedef struct
        {
                ANDROID_HECI_AGENT_REQ_HEADER          Header;
                UINT32                                 KeySize;
                UINT8                                  PublicExponent[ANDROID_HECI_KEYMASTER_PUBLIC_EXPONENT_MAX_SIZE]; // In big-endian
        } ANDROID_HECI_KEYMASTER_CMD_RSA_GEN_KEY_REQUEST;

        typedef struct
        {
                ANDROID_HECI_AGENT_RESP_HEADER         Header;
                UINT8                                  KeyOpaque[ANDROID_HECI_KEYMASTER_KEY_OPAQUE_SIZE];
        } ANDROID_HECI_KEYMASTER_CMD_RSA_GEN_KEY_RESPONSE;

        typedef struct
        {
                ANDROID_HECI_AGENT_REQ_HEADER          Header;
                UINT32                                 KeySize;
                UINT8                                  PublicExponent[ANDROID_HECI_KEYMASTER_PUBLIC_EXPONENT_MAX_SIZE]; // In big-endian
                UINT8                                  Modulus[ANDROID_HECI_KEYMASTER_MAX_KEY_SIZE]; // In big-endian
                UINT8                                  PrivateExponent[ANDROID_HECI_KEYMASTER_MAX_KEY_SIZE]; // In big-endian
        } ANDROID_HECI_KEYMASTER_CMD_RSA_IMPORT_KEY_REQUEST;

        typedef struct
        {
                ANDROID_HECI_AGENT_RESP_HEADER         Header;
                UINT8                                  KeyOpaque[ANDROID_HECI_KEYMASTER_KEY_OPAQUE_SIZE];
        } ANDROID_HECI_KEYMASTER_CMD_RSA_IMPORT_KEY_RESPONSE;

        typedef struct
        {
                ANDROID_HECI_AGENT_REQ_HEADER          Header;
                UINT8                                  KeyOpaque[ANDROID_HECI_KEYMASTER_KEY_OPAQUE_SIZE];
        } ANDROID_HECI_KEYMASTER_CMD_RSA_GET_PUBLIC_KEY_REQUEST;

        typedef struct
        {
                ANDROID_HECI_AGENT_RESP_HEADER         Header;
                UINT32                                 KeySize;
                UINT8                                  PublicExponent[ANDROID_HECI_KEYMASTER_PUBLIC_EXPONENT_MAX_SIZE]; // In big-endian
                UINT8                                  Modulus[ANDROID_HECI_KEYMASTER_MAX_KEY_SIZE]; // In big-endian
        } ANDROID_HECI_KEYMASTER_CMD_RSA_GET_PUBLIC_KEY_RESPONSE;

        typedef struct
        {
                ANDROID_HECI_AGENT_REQ_HEADER          Header;
        } ANDROID_HECI_KEYMASTER_CMD_RSA_DELETE_ALL_KEYS_REQUEST;

        typedef struct
        {
                ANDROID_HECI_AGENT_RESP_HEADER         Header;
        } ANDROID_HECI_KEYMASTER_CMD_RSA_DELETE_ALL_KEYS_RESPONSE;

        typedef struct
        {
                ANDROID_HECI_AGENT_REQ_HEADER          Header;
                UINT32                                 DataSize;
                UINT8                                  Data[ANDROID_HECI_KEYMASTER_MAX_KEY_SIZE];
                UINT8                                  KeyOpaque[ANDROID_HECI_KEYMASTER_KEY_OPAQUE_SIZE];
        } ANDROID_HECI_KEYMASTER_CMD_RSA_SIGN_DATA_NOPAD_REQUEST;

        typedef struct
        {
                ANDROID_HECI_AGENT_RESP_HEADER         Header;
                UINT32                                 SignatureSize;
                UINT8                                  Signature[ANDROID_HECI_KEYMASTER_MAX_KEY_SIZE]; // In big-endian
        } ANDROID_HECI_KEYMASTER_CMD_RSA_SIGN_DATA_NOPAD_RESPONSE;

        typedef struct
        {
                ANDROID_HECI_AGENT_REQ_HEADER          Header;
                UINT32                                 DataSize;
                UINT8                                  Data[ANDROID_HECI_KEYMASTER_MAX_KEY_SIZE];
                UINT32                                 SignatureSize;
                UINT8                                  Signature[ANDROID_HECI_KEYMASTER_MAX_KEY_SIZE]; // In big-endian
                UINT8                                  KeyOpaque[ANDROID_HECI_KEYMASTER_KEY_OPAQUE_SIZE];
        } ANDROID_HECI_KEYMASTER_CMD_RSA_VERIFY_DATA_NOPAD_REQUEST;

        typedef struct
        {
                ANDROID_HECI_AGENT_RESP_HEADER         Header;
                UINT32                                 Verified;
        } ANDROID_HECI_KEYMASTER_CMD_RSA_VERIFY_DATA_NOPAD_RESPONSE;


        typedef struct
        {
                ANDROID_HECI_AGENT_REQ_HEADER          Header;
                UINT8                                  Message[ANDROID_HECI_KEYMASTER_PCR_EXTEND_MESSAGE_SIZE];
        } ANDROID_HECI_KEYMASTER_CMD_PCR_EXTEND_REQUEST;

        typedef struct
        {
                ANDROID_HECI_AGENT_RESP_HEADER         Header;
        } ANDROID_HECI_KEYMASTER_CMD_PCR_EXTEND_RESPONSE;

#ifdef __cplusplus
}
#endif /*  __cplusplus */


#endif // _AFWS_KEYMASTER_HECI_AGENT_H_
