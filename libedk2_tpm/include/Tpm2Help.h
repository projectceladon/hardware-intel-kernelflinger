#include <efi.h>
#include <efiapi.h>
#include <efilib.h>
#include "Tcg2Protocol.h"
#include "Tpm2DeviceLib.h"

#ifndef _TPM2_HELP_H_
#define _TPM2_HELP_H_

UINT16
EFIAPI
SwapBytes16 (
  IN      UINT16                    Value
  );


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
  IN      UINT32                    Value
  );

UINT32
EFIAPI
WriteUnaligned32 (
  OUT     UINT32                    *Buffer,
  IN      UINT32                    Value
  );

UINT16
EFIAPI
WriteUnaligned16 (
  OUT     UINT16                    *Buffer,
  IN      UINT16                    Value
  );

UINT16
EFIAPI
ReadUnaligned16 (
  IN CONST UINT16              *Buffer
  );

UINT32
EFIAPI
ReadUnaligned32 (
  IN      CONST UINT32              *Buffer
  );

UINT32
EFIAPI
CopyAuthSessionCommand (
  IN      TPMS_AUTH_COMMAND         *AuthSessionIn, OPTIONAL
  OUT     UINT8                     *AuthSessionOut
  );

#endif
