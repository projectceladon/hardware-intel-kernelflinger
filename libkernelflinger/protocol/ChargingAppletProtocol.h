/**@file
   EFI Charging Applet Protocol definition

   @copyright
   Copyright (c) 1999 - 2015 Intel Corporation. All rights reserved
   This software and associated documentation (if any) is furnished
   under a license and may only be used or copied in accordance
   with the terms of the license. Except as permitted by the
   license, no part of this software or documentation may be
   reproduced, stored in a retrieval system, or transmitted in any
   form or by any means without the express written consent of
   Intel Corporation.
   This file contains an 'Intel Peripheral Driver' and is uniquely
   identified as "Intel Reference Module" and is licensed for Intel
   CPUs and chipsets under the terms of your license agreement with
   Intel or your vendor. This file may be modified by the user, subject
   to additional terms of the license agreement.

   @par Specification
**/

#ifndef _CHARGING_APPLET_PROTOCOL_H_
#define _CHARGING_APPLET_PROTOCOL_H_

#define CHARGING_APPLET_PROTOCOL_GUID                                        \
        {0x810139A7, 0x133E, 0x44A1, {0xAC, 0x6F, 0xD2, 0x04, 0x62, 0x13, 0x9D, 0x90}}

typedef struct _CHARGING_APPLET_PROTOCOL CHARGING_APPLET_PROTOCOL;

//
// Charger Type
//
typedef enum {
        SdpCharger,
        DcpCharger,
        CdpCharger,
        AcaCharger,
        AdapCharger,
        WirelessCharger,
        ChargerOther,
        ChargerUndefined
} CHARGER_TYPE;

//
// Current Charging State.
//
typedef enum {
        ChargeOn,
        ChargeFull,
        NoCharge
} CHARGE_STATE;

//
// Battery Infomation
//
typedef struct {
        UINT16  DesignCapacity;
} BATTERY_INFO;

typedef UINT8   BATTERY_CAPACITY;
typedef UINT16  BATTERY_VOLTAGE;

//
// Prototypes
//
typedef
EFI_STATUS
(EFIAPI *CHARGING_APPLET_GET_CHARGER_TYPE) (
        IN CHARGING_APPLET_PROTOCOL      *This,
        OUT CHARGER_TYPE                 *ChargerType
        );

typedef
EFI_STATUS
(EFIAPI *CHARGING_APPLET_SET_CHARGE_RATE) (
        IN CHARGING_APPLET_PROTOCOL      *This,
        IN UINT32                        ChargeRate
        );

typedef
EFI_STATUS
(EFIAPI *CHARGING_APPLET_GET_CURRENT_CHARGE_STATE) (
        IN CHARGING_APPLET_PROTOCOL      *This,
        OUT UINT32                       *CurrentCapacity,
        OUT CHARGE_STATE                 *CurrentState
        );

typedef
EFI_STATUS
(EFIAPI *CHARGING_APPLET_GET_BATTERY_INFO) (
        IN CHARGING_APPLET_PROTOCOL      *This,
        OUT BATTERY_INFO                 *BatteryInfo,
        OUT BOOLEAN                      *BatteryPresent,
        OUT BOOLEAN                      *BatteryValid,
        OUT BOOLEAN                      *CapacityReadable,    // based on FG.STATUS.POR
        OUT BATTERY_VOLTAGE              *BatteryVoltageLevel, // mVolts
        OUT BATTERY_CAPACITY             *BatteryCapacityLevel // Percentage
        );

typedef
EFI_STATUS
(EFIAPI *CHARGING_APPLET_PUT_PLATFORM_LOW_POWER_MODE) (
        IN CHARGING_APPLET_PROTOCOL      *This,
        IN BOOLEAN                       PowerSaveMode,
        IN BOOLEAN                       DisplayPMState
        );


//
//  struct CHARGING_APPLET_PROTOCOL
//
struct _CHARGING_APPLET_PROTOCOL {
        CHARGING_APPLET_GET_CHARGER_TYPE              GetChargerType;
        CHARGING_APPLET_SET_CHARGE_RATE               SetChargeRate;
        CHARGING_APPLET_GET_CURRENT_CHARGE_STATE      GetCurrentChargeState;
        CHARGING_APPLET_GET_BATTERY_INFO              GetBatteryInfo;
        CHARGING_APPLET_PUT_PLATFORM_LOW_POWER_MODE   PutPlatformToLowPowerMode;
        UINT16                                        MajorRevision;
        UINT16                                        MinorRevision;
};

#endif
