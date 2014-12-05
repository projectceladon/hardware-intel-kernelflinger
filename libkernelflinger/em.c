/*
 * Copyright (c) 2015, Intel Corporation
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

#include "acpi.h"
#include "lib.h"
#include "protocol/ChargingAppletProtocol.h"

#include "em.h"

#ifdef USE_CHARGING_APPLET
static EFI_GUID gChargingAppletProtocolGuid = CHARGING_APPLET_PROTOCOL_GUID;

struct battery_status {
        BATTERY_INFO BatteryInfo;
        BOOLEAN BatteryPresent;
        BOOLEAN BatteryValid;
        BOOLEAN CapacityReadable;
        BATTERY_VOLTAGE BatteryVoltageLevel;
        BATTERY_CAPACITY BatteryCapacityLevel;
};

static EFI_STATUS get_battery_status(struct battery_status *status)
{
        CHARGING_APPLET_PROTOCOL *charging_protocol;
        EFI_STATUS ret;

        ret = LibLocateProtocol(&gChargingAppletProtocolGuid,
                                (VOID **)&charging_protocol);
        if (EFI_ERROR(ret))
                goto error;

        ret = uefi_call_wrapper(charging_protocol->GetBatteryInfo, 7,
                                charging_protocol,
                                &status->BatteryInfo,
                                &status->BatteryPresent,
                                &status->BatteryValid,
                                &status->CapacityReadable,
                                &status->BatteryVoltageLevel,
                                &status->BatteryCapacityLevel);
        if (EFI_ERROR(ret))
                goto error;

        return ret;

error:
        efi_perror(ret, L"Failed to get the battery status");
        return ret;
}

BOOLEAN is_charger_plugged_in(void)
{
        CHARGING_APPLET_PROTOCOL *charging_protocol;
        CHARGER_TYPE type;
        EFI_STATUS ret;

        ret = LibLocateProtocol(&gChargingAppletProtocolGuid,
                                (VOID **)&charging_protocol);
        if (EFI_ERROR(ret))
                goto error;

        ret = uefi_call_wrapper(charging_protocol->GetChargerType, 2,
                                charging_protocol, &type);
        if (EFI_ERROR(ret))
                goto error;

        return type != ChargerUndefined;

error:
        efi_perror(ret, L"Failed to get charger status");
        return FALSE;
}

BOOLEAN is_battery_below_boot_OS_threshold(void)
{
        struct battery_status status;
        EFI_STATUS ret;
        UINTN value, threshold;
        UINT8 ia_apps_to_use;

        ret = get_battery_status(&status);
        if (EFI_ERROR(ret))
                return FALSE;

        ia_apps_to_use = oem1_get_ia_apps_to_use();
        if (ia_apps_to_use == (UINT8)-1) {
                error(L"OEM1 ACPI table parse error");
                return FALSE;
        }

        if (status.CapacityReadable && ia_apps_to_use == OEM1_USE_IA_APPS_CAP) {
                value = status.BatteryCapacityLevel;
                threshold = oem1_get_ia_apps_cap();
                debug(L"Battery: %d%% Threshold: %d%%", value, threshold);
        } else {
                value = status.BatteryVoltageLevel;
                threshold = oem1_get_ia_apps_run();
                debug(L"Battery: %dmV Threshold: %dmV", value, threshold);
                if (value == 0) {
                        /* This is very common to have such an issue
                           when we are working on a new hardware.
                           Instead of blocking the boot flow, we raise
                           an error.  */
                        error(L"Impossible 0mV battery voltage. This has to be fixed !");
                        error(L"Assuming battery voltage is above threshold");
                        return FALSE;
                }
        }

        return value < threshold;
}

EFI_STATUS get_battery_voltage(UINTN *voltage)
{
        struct battery_status status;
        EFI_STATUS ret;

        ret = get_battery_status(&status);
        if (EFI_ERROR(ret))
                return ret;

        *voltage = status.BatteryVoltageLevel;

        return EFI_SUCCESS;
}
#else
BOOLEAN is_charger_plugged_in(void)
{
        debug(L"WARNING: charging protocol disabled, assume charger is not plugged-in");
        return FALSE;
}

BOOLEAN is_battery_below_boot_OS_threshold(void)
{
        debug(L"WARNING: charging protocol disabled, assume battery level is above BOOT_OS");
        return FALSE;
}

EFI_STATUS get_battery_voltage(__attribute__((__unused__)) UINTN *voltage)
{
        debug(L"WARNING: charging protocol is disabled");
        return EFI_UNSUPPORTED;
}
#endif  /* USE_CHARGING_APPLET */
