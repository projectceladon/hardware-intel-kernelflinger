/*
 * Copyright (c) 2017, Intel Corporation
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

#ifndef _GPIO_PROTOCOL_H_
#define _GPIO_PROTOCOL_H_

/* GPIO Protocol GUID */
#define EDKII_GPIO_PROTOCOL_GUID { 0x239a4037, 0x5231, 0x44d6,{0xa2, 0xab, 0x51, 0x74, 0xcd, 0x81, 0xff, 0x85 }}

typedef struct _EDKII_GPIO_PROTOCOL EDKII_GPIO_PROTOCOL;

/* Get Max GPIO count.

        @param[in]   This                  A pointer to the EDKII_GPIO_PROTOCOL instance.
        @param[out]  MaxCount              Max GPIO count
        @retval EFI_SUCCESS                The operation succeeded.
*/

typedef EFI_STATUS(EFIAPI *EDKII_GET_MAX_COUNT)(IN EDKII_GPIO_PROTOCOL *This, OUT UINT32 *MaxCount);

/* Check GPIO direction.

        @param[in]   This                  A pointer to the EDKII_GPIO_PROTOCOL instance.
        @param[in]   PinNum 		   Target GPIO.
        @Param[OUT]  GpioDirection         Pointer to the returned GPIO direction (GpIn/GpOut/GpInOut).
        @retval      EFI_SUCCESS           The operation succeeded.
*/

typedef EFI_STATUS(EFIAPI *EDKII_GET_GPIO_DIRECTION)(
    IN EDKII_GPIO_PROTOCOL *This, IN UINT32 PinNum,
    OUT GPIO_DIRECTION *GpioDirection);

/* Set GPIO direction to GPI/GPO/GPIO.

        @param[in]   This                  A pointer to the EDKII_GPIO_PROTOCOL instance.
        @param[in]   PinNum 	           Target GPIO.
        @Param[in]   GpioDirection         GPIO direction to set.
        @retval      EFI_SUCCESS           The operation succeeded.
*/

typedef EFI_STATUS(EFIAPI *EDKII_SET_GPIO_DIRECTION)(
    IN EDKII_GPIO_PROTOCOL *This, IN UINT32 PinNum,
    IN GPIO_DIRECTION GpioDirection);

/* Check GPIO direction, if it is GPI, get input value.

        @param[in]   This                  A pointer to the EDKII_GPIO_PROTOCOL instance.
        @param[in]   PinNum 	           Target GPIO.
        @param[out]  GpiLevel              GPIO Input level
                                           0: Low, 1: High
        @retval EFI_SUCCESS                The operation succeeded.
*/

typedef EFI_STATUS(EFIAPI *EDKII_GPIO_GET_GPI_LEVEL)(
    IN EDKII_GPIO_PROTOCOL *This, IN UINT32 PinNum, OUT GPIO_LEVEL *GpiLevel);

/* Check GPIO direction, if it is GPO, Set output value.

        @param[in]   This                  A pointer to the EDKII_GPIO_PROTOCOL instance.
        @param[in]   PinNum 	           Target GPIO.
        @param[in]   GpoLevel              GPO output level
                                           0: Low, 1: High
        @retval EFI_SUCCESS                The operation succeeded.
*/

typedef EFI_STATUS(EFIAPI *EDKII_GPIO_SET_GPO_LEVEL)(
    IN EDKII_GPIO_PROTOCOL *This, IN UINT32 PinNum, IN GPIO_LEVEL GpoLevel);

/* Get Pad Mode.

        @param[in]   This                  A pointer to the EDKII_GPIO_PROTOCOL instance.
        @param[in]   PinNum 	           Target GPIO.
        @Param[OUT]  PadMode               0: Function 0 (GPIO mode),
                                           1: Function 1, 2: Function 2, 3: Function 3,
                                           4: Function 4, 5: Function 5
        @retval      EFI_SUCCESS           The operation succeeded.
*/

typedef EFI_STATUS(EFIAPI *EDKII_GET_MODE)(IN EDKII_GPIO_PROTOCOL *This,
                                           IN UINT32 PinNum,
                                           OUT PAD_MODE *PadMode);

/* Set Pad Mode to Function0, Function1... (Function0 is GPIO mode)

        @param[in]  This                   A pointer to the EDKII_GPIO_PROTOCOL instance.
        @param[in]  GPIO_NAME              Target GPIO.
        @param[out] PadMode                GPIO mode to set.
        @retval EFI_SUCCESS                The operation succeeded.

*/

typedef EFI_STATUS(EFIAPI *EDKII_SET_MODE)(IN EDKII_GPIO_PROTOCOL *This,
                                           IN UINT32 PinNum,
                                           IN PAD_MODE PadMode);

struct _EDKII_GPIO_PROTOCOL
{
        EDKII_GET_MAX_COUNT GetMaxCount;
        EDKII_GET_MODE GetMode;
        EDKII_SET_MODE SetMode;
        EDKII_GET_GPIO_DIRECTION GetGpioDirection; /* Get GPIO direction */
        EDKII_SET_GPIO_DIRECTION SetGpioDirection; /* Set GPIO direction */
        EDKII_GPIO_GET_GPI_LEVEL GetGpiLevel;      /* Get GPI level */
        EDKII_GPIO_SET_GPO_LEVEL SetGpoLevel;      /* Set GPO level */
};

extern EFI_GUID gEdkiiGpioProtocolGuid;

#endif /* _GPIO_PROTOCOL_H_ */
