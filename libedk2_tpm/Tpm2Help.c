/** @file
  Implement TPM2 helper functions.

Copyright (c) 2013 - 2016, Intel Corporation. All rights reserved. <BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <efi.h>
#include <efilib.h>
#include "Tpm2Help.h"
#include "Tcg2Protocol.h"


/**
  Switches the endianness of a 16-bit integer.

  This function swaps the bytes in a 16-bit unsigned value to switch the value
  from little endian to big endian or vice versa. The byte swapped value is
  returned.

  @param  Value A 16-bit unsigned value.

  @return The byte swapped Value.

**/

UINT16
EFIAPI
SwapBytes16 (
  IN      UINT16                    Operand
  )
{
  return (UINT16) ((Operand << 8) | (Operand >> 8));
}

/**
  Switches the endianness of a 32-bit integer.

  This function swaps the bytes in a 32-bit unsigned value to switch the value
  from little endian to big endian or vice versa. The byte swapped value is
  returned.

  @param  Value A 32-bit unsigned value.

  @return The byte swapped Value.

**/
UINT32
EFIAPI
SwapBytes32 (
  IN      UINT32                    Operand
  )
{
  UINT32  LowerBytes;
  UINT32  HigherBytes;

  LowerBytes  = (UINT32) SwapBytes16 ((UINT16) Operand);
  HigherBytes = (UINT32) SwapBytes16 ((UINT16) (Operand >> 16));

  return (LowerBytes << 16 | HigherBytes);
}

UINT32
EFIAPI
WriteUnaligned32 (
  OUT     UINT32                    *Buffer,
  IN      UINT32                    Value
  )
{
  ASSERT (Buffer != NULL);

  return *Buffer = Value;
}

UINT16
EFIAPI
WriteUnaligned16 (
  OUT     UINT16                    *Buffer,
  IN      UINT16                    Value
  )
{
  ASSERT (Buffer != NULL);

  return *Buffer = Value;
}

UINT16
EFIAPI
ReadUnaligned16 (
  IN CONST UINT16              *Buffer
  )
{
  ASSERT (Buffer != NULL);

  return *Buffer;
}

UINT32
EFIAPI
ReadUnaligned32 (
  IN      CONST UINT32              *Buffer
  )

{
  ASSERT (Buffer != NULL);

  return *Buffer;
}


UINT32
EFIAPI
CopyAuthSessionCommand (
  IN      TPMS_AUTH_COMMAND         *AuthSessionIn, OPTIONAL
  OUT     UINT8                     *AuthSessionOut
  )
{
  UINT8  *Buffer;

  Buffer = (UINT8 *)AuthSessionOut;

  //
  // Add in Auth session
  //
  if (AuthSessionIn != NULL) {
    //  sessionHandle
    WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32(AuthSessionIn->sessionHandle));
    Buffer += sizeof(UINT32);

    // nonce
    WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (AuthSessionIn->nonce.size));
    Buffer += sizeof(UINT16);

    CopyMem (Buffer, AuthSessionIn->nonce.buffer, AuthSessionIn->nonce.size);
    Buffer += AuthSessionIn->nonce.size;

    // sessionAttributes
    *(UINT8 *)Buffer = *(UINT8 *)&AuthSessionIn->sessionAttributes;
    Buffer++;

    // hmac
    WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (AuthSessionIn->hmac.size));
    Buffer += sizeof(UINT16);

    CopyMem (Buffer, AuthSessionIn->hmac.buffer, AuthSessionIn->hmac.size);
    Buffer += AuthSessionIn->hmac.size;
  } else {
    //  sessionHandle
    WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32(TPM_RS_PW));
    Buffer += sizeof(UINT32);

    // nonce = nullNonce
    WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16(0));
    Buffer += sizeof(UINT16);

    // sessionAttributes = 0
    *(UINT8 *)Buffer = 0x00;
    Buffer++;

    // hmac = nullAuth
    WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16(0));
    Buffer += sizeof(UINT16);
  }

  return (UINT32)(UINTN)(Buffer - (UINT8 *)AuthSessionOut);
}

