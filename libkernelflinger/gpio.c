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

#include <lib.h>
#include <uefi_utils.h>
#include <vars.h>

#include "gpio.h"
#include "protocol.h"
#include "protocol/GpioProtocol.h"
#include "smbios.h"

EFI_GUID gEDKIIGPIOProtocolGuid = EDKII_GPIO_PROTOCOL_GUID;

static EDKII_GPIO_PROTOCOL *get_gpio_device()
{
        EFI_STATUS ret;
        static EDKII_GPIO_PROTOCOL *gpio_device = NULL;

        if (gpio_device)
                return gpio_device;

        ret = LibLocateProtocol(&gEDKIIGPIOProtocolGuid, (void **)&gpio_device);
        if (EFI_ERROR(ret) || !gpio_device) {
                error(L"Failed to locate gpio device protocol");
                return NULL;
        }

        return gpio_device;
}

/* get max GPIO count */
EFI_STATUS gpio_get_max_count(UINT32 *count)
{
        EFI_STATUS ret;
        EDKII_GPIO_PROTOCOL *gpio_device = NULL;

        gpio_device = get_gpio_device();
        if (gpio_device == NULL)
                return EFI_UNSUPPORTED;

        ret = uefi_call_wrapper(gpio_device->GetMaxCount, 2, gpio_device, count);
        if (EFI_ERROR(ret))
                efi_perror(ret, L"failed to get max count");
        return ret;
}

/* get gpio pin mode */
EFI_STATUS get_gpio_pin_mode(UINT32 PinNum, PAD_MODE *mode)
{
        EFI_STATUS ret;
        EDKII_GPIO_PROTOCOL *gpio_device = NULL;

        gpio_device = get_gpio_device();
        if (gpio_device == NULL)
                return EFI_UNSUPPORTED;

        ret = uefi_call_wrapper(gpio_device->GetMode, 3, gpio_device, PinNum, mode);
        if (EFI_ERROR(ret))
                efi_perror(ret, L"failed to get pin mode");
        return ret;
}

/* set gpio pin mode */
EFI_STATUS set_gpio_pin_mode(UINT32 PinNum, PAD_MODE mode)
{
        EFI_STATUS ret;
        EDKII_GPIO_PROTOCOL *gpio_device = NULL;

        gpio_device = get_gpio_device();
        if (gpio_device == NULL)
                return EFI_UNSUPPORTED;

        ret = uefi_call_wrapper(gpio_device->SetMode, 3, gpio_device, PinNum, mode);
        if (EFI_ERROR(ret))
                efi_perror(ret, L"failed to set pin mode");
        return ret;
}

/* get gpio pin direction */
EFI_STATUS get_gpio_pin_dir(UINT32 PinNum, GPIO_DIRECTION *dir)
{
        EFI_STATUS ret;
        EDKII_GPIO_PROTOCOL *gpio_device = NULL;

        gpio_device = get_gpio_device();
        if (gpio_device == NULL)
                return EFI_UNSUPPORTED;

        ret = uefi_call_wrapper(gpio_device->GetGpioDirection, 3, gpio_device, PinNum, dir);
        if (EFI_ERROR(ret))
                efi_perror(ret, L"failed to get pin direction");
        return ret;
}

/* set gpio pin direction */
EFI_STATUS set_gpio_pin_dir(UINT32 PinNum, GPIO_DIRECTION dir)
{
        EFI_STATUS ret;
        EDKII_GPIO_PROTOCOL *gpio_device = NULL;

        gpio_device = get_gpio_device();
        if (gpio_device == NULL)
                return EFI_UNSUPPORTED;

        ret = uefi_call_wrapper(gpio_device->SetGpioDirection, 3, gpio_device, PinNum, dir);
        if (EFI_ERROR(ret))
                efi_perror(ret, L"failed to set pin direction");
        return ret;
}

/* get gpio pin level */
EFI_STATUS get_gpio_pin_level(UINT32 PinNum, GPIO_LEVEL *level)
{
        EFI_STATUS ret;
        EDKII_GPIO_PROTOCOL *gpio_device = NULL;

        gpio_device = get_gpio_device();
        if (gpio_device == NULL)
                return EFI_UNSUPPORTED;

        ret = uefi_call_wrapper(gpio_device->GetGpiLevel, 3, gpio_device, PinNum, level);
        if (EFI_ERROR(ret))
                efi_perror(ret, L"failed to get pin level");
        return ret;
}

/* set gpio pin level */
EFI_STATUS set_gpio_pin_level(UINT32 PinNum, GPIO_LEVEL level)
{
        EFI_STATUS ret;
        EDKII_GPIO_PROTOCOL *gpio_device = NULL;

        gpio_device = get_gpio_device();
        if (gpio_device == NULL)
                return EFI_UNSUPPORTED;

        ret = uefi_call_wrapper(gpio_device->SetGpoLevel, 3, gpio_device, PinNum, level);
        if (EFI_ERROR(ret))
                efi_perror(ret, L"failed to set pin level");
        return ret;
}
