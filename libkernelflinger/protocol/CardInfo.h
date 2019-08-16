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
 *
 * This file defines bootlogic data structures, try to keep it without
 * any external definitions in order to ease export of it.
 */

#ifndef _CARD_INFO_H_
#define _CARD_INFO_H_

#include "protocol/Mmc.h"

#define EFI_CARD_INFO_PROTOCOL_GUID					\
	{								\
		0x1ebe5ab9, 0x2129, 0x49e7, { 0x84, 0xd7, 0xee, 0xb9, 0xfc, 0xe5, 0xde, 0xdd } \
	}

typedef enum {
	UnknownCard = 0,
	MMCCard,                /* MMC card */
	CEATACard,              /* CE-ATA device */
	SDMemoryCard,           /* SD 1.1 card */
	SDMemoryCard2,          /* SD 2.0 or above standard card */
	SDMemoryCard2High       /* SD 2.0 or above high capacity card */
} CARD_TYPE;

typedef struct {
	CHAR8   *Language;
	CHAR16  *UnicodeString;
} EFI_UNICODE_STRING_TABLE;

typedef struct {
	UINT8  Reserved0;
	UINT8  Features_Exp;
	UINT8  SectorCount_Exp;
	UINT8  LBALow_Exp;
	UINT8  LBAMid_Exp;
	UINT8  LBAHigh_Exp;
	UINT8  Control;
	UINT8  Reserved1[2];
	UINT8  Features_Error;
	UINT8  SectorCount;
	UINT8  LBALow;
	UINT8  LBAMid;
	UINT8  LBAHigh;
	UINT8  Device_Head;
	UINT8  Command_Status;
} TASK_FILE;

typedef EFI_DEVICE_PATH EFI_DEVICE_PATH_PROTOCOL;

typedef struct {
	UINT16  Reserved0[10];
	UINT16  SerialNumber[10];
	UINT16  Reserved1[3];
	UINT16  FirmwareRevision[4];
	UINT16  ModelNumber[20];
	UINT16  Reserved2[33];
	UINT16  MajorVersion;
	UINT16  Reserved3[19];
	UINT16  MaximumLBA[4];
	UINT16  Reserved4[2];
	UINT16  Sectorsize;
	UINT16  Reserved5;
	UINT16  DeviceGUID[4];
	UINT16  Reserved6[94];
	UINT16  Features;
	UINT16  MaxWritesPerAddress;
	UINT16  Reserved7[47];
	UINT16  IntegrityWord;
} IDENTIFY_DEVICE_DATA;

typedef struct {
	UINT32  Reserved0;
	UINT32  Reserved1:               16;
	UINT32  SD_BUS_WIDTH:            4;
	UINT32  SD_SECURITY:             3;
	UINT32  DATA_STAT_AFTER_ERASE:   1;
	UINT32  SD_SPEC:                 4;
	UINT32  SCR_STRUCT:              4;
} SCR;

typedef struct {
	UINT8   Reserved0[50];
	UINT8   ERASE_OFFSET:               2;
	UINT8   ERASE_TIMEOUT:              6;
	UINT16  ERASE_SIZE;
	UINT8   Reserved1:                  4;
	UINT8   AU_SIZE:                    4;
	UINT8   PERFORMANCE_MOVE;
	UINT8   SPEED_CLASS;
	UINT32  SIZE_OF_PROTECTED_AREA;
	UINT32  SD_CARD_TYPE:              16;
	UINT32  Reserved2:                 13;
	UINT32  SECURED_MODE:               1;
	UINT32  DAT_BUS_WIDTH:              2;
} SD_STATUS_REG;

typedef struct {
	UINT8   Reserved0[34];
	UINT16  Group1BusyStatus;
	UINT16  Group2BusyStatus;
	UINT16  Group3BusyStatus;
	UINT16  Group4BusyStatus;
	UINT16  Group5BusyStatus;
	UINT16  Group6BusyStatus;
	UINT8   DataStructureVersion;
	UINT8   Group21Status;
	UINT8   Group43Status;
	UINT8   Group65Status;
	UINT16  Group1Function;
	UINT16  Group2Function;
	UINT16  Group3Function;
	UINT16  Group4Function;
	UINT16  Group5Function;
	UINT16  Group6Function;
	UINT16  MaxCurrent;
} SWITCH_STATUS;

#define MAX_NUMBER_OF_PARTITIONS 8

typedef struct _EFI_EMMC_RPMB_OP_PROTOCOL  EFI_EMMC_RPMB_OP_PROTOCOL;

typedef BOOLEAN (EFIAPI *IS_RPMBKEY_PROGRAMMED)(EFI_EMMC_RPMB_OP_PROTOCOL *This);

typedef EFI_STATUS (EFIAPI *EMMC_PROGRAM_RPMBKEY)(EFI_EMMC_RPMB_OP_PROTOCOL *This,
						  UINT8 * KeyString);

struct _EFI_EMMC_RPMB_OP_PROTOCOL {
	IS_RPMBKEY_PROGRAMMED EmmcIsRPMBProgrammed;
	EMMC_PROGRAM_RPMBKEY  EmmcProgramRPMBKey;
};

/* Depending on the BIOS release/vendor, the MMC_PARTITION_DATA and
 * CARD_DATA structures can be different. */
typedef struct {
	UINT32                    Signature;
	EFI_HANDLE                Handle;
	BOOLEAN                   Present;
	EFI_DEVICE_PATH_PROTOCOL  *DevPath;
	EFI_BLOCK_IO     BlockIo;
	EFI_BLOCK_IO_MEDIA        BlockIoMedia;
	struct CARD_DATA_v1       *CardData;
} MMC_PARTITION_DATA_v1;

struct CARD_DATA_v1 {
	UINT32                    Signature;
	EFI_HANDLE                Handle;
	MMC_PARTITION_DATA_v1     Partitions[MAX_NUMBER_OF_PARTITIONS];
	EFI_SD_HOST_IO_PROTOCOL   *SdHostIo;
	EFI_UNICODE_STRING_TABLE  *ControllerNameTable;
	CARD_TYPE                 CardType;
	UINT8                     CurrentBusWidth;
	BOOLEAN                   DualVoltage;
	BOOLEAN                   NeedFlush;
	UINT8                     Reserved[3];
	UINT16                    Address;
	UINT32                    BlockLen;
	UINT32                    MaxFrequency;
	UINT64                    BlockNumber;
	CARD_STATUS               CardStatus;
	OCR                       OCRRegister;
	CID                       CIDRegister;
	CSD                       CSDRegister;
	EXT_CSD                   ExtCSDRegister;
	UINT8                     *RawBufferPointer;
	UINT8                     *AlignedBuffer;
	TASK_FILE                 TaskFile;
	IDENTIFY_DEVICE_DATA      IndentifyDeviceData;
	SCR                       SCRRegister;
	SD_STATUS_REG             SDSattus;
	SWITCH_STATUS             SwitchStatus;
};

typedef struct {
	UINT32                    Signature;
	EFI_HANDLE                Handle;
	EFI_HANDLE                SmmHandle;
	BOOLEAN                   Present;
	EFI_DEVICE_PATH_PROTOCOL  *DevPath;
	EFI_BLOCK_IO     BlockIo;
	EFI_BLOCK_IO_MEDIA        BlockIoMedia;
	struct CARD_DATA_v2       *CardData;
} MMC_PARTITION_DATA_v2;

struct CARD_DATA_v2 {
	UINT32                    Signature;
	EFI_HANDLE                Handle;
	MMC_PARTITION_DATA_v2     Partitions[MAX_NUMBER_OF_PARTITIONS];
	EFI_SD_HOST_IO_PROTOCOL   *SdHostIo;
	EFI_EMMC_RPMB_OP_PROTOCOL RPMBIo;
	EFI_UNICODE_STRING_TABLE  *ControllerNameTable;
	CARD_TYPE                 CardType;
	UINT8                     CurrentBusWidth;
	BOOLEAN                   DualVoltage;
	BOOLEAN                   NeedFlush;
	UINT8                     Reserved[3];
	UINT16                    Address;
	UINT32                    BlockLen;
	UINT32                    MaxFrequency;
	UINT64                    BlockNumber;
	CARD_STATUS               CardStatus;
	OCR                       OCRRegister;
	CID                       CIDRegister;
	CSD                       CSDRegister;
	EXT_CSD                   ExtCSDRegister;
	UINT8                     *RawBufferPointer;
	UINT8                     *AlignedBuffer;
	TASK_FILE                 TaskFile;
	IDENTIFY_DEVICE_DATA      IndentifyDeviceData;
	SCR                       SCRRegister;
	SD_STATUS_REG             SDSattus;
	SWITCH_STATUS             SwitchStatus;
};

typedef union CARD_DATA {
	struct CARD_DATA_v1 v1;
	struct CARD_DATA_v2 v2;
} CARD_DATA;

struct _EFI_EMMC_CARD_INFO_PROTOCOL {
	CARD_DATA *CardData;
};

#endif	/* _CARD_INFO_H_ */
