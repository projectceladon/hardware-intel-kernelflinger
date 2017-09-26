#include <efi.h>
#include <efiapi.h>
#include <efilib.h>
#include "Tcg2Protocol.h"
#include "Tpm2DeviceLib.h"

#ifndef _TPM2_HELP_H_
#define _TPM2_HELP_H_

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

/**
  Switches the endianness of a 64-bit integer.

  This function swaps the bytes in a 64-bit unsigned value to switch the value
  from little endian to big endian or vice versa. The byte swapped value is
  returned.

  @param  Value A 64-bit unsigned value.

  @return The byte swapped Value.

**/
UINT64
EFIAPI
SwapBytes64 (
  IN      UINT64                    Value
  );

/**
  Writes a 32-bit value to memory that may be unaligned.

  This function writes the 32-bit value specified by Value to Buffer. Value is
  returned. The function guarantees that the write operation does not produce
  an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 32-bit value that may be unaligned.
  @param  Value   The 32-bit value to write to Buffer.

  @return The 32-bit value to write to Buffer.

**/

UINT32
EFIAPI
WriteUnaligned32 (
  OUT     UINT32                    *Buffer,
  IN      UINT32                    Value
  );

/**
  Writes a 16-bit value to memory that may be unaligned.

  This function writes the 16-bit value specified by Value to Buffer. Value is
  returned. The function guarantees that the write operation does not produce
  an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 16-bit value that may be unaligned.
  @param  Value   16-bit value to write to Buffer.

  @return The 16-bit value to write to Buffer.

**/

UINT16
EFIAPI
WriteUnaligned16 (
  OUT     UINT16                    *Buffer,
  IN      UINT16                    Value
  );

/**
  Reads a 16-bit value from memory that may be unaligned.

  This function returns the 16-bit value pointed to by Buffer. The function
  guarantees that the read operation does not produce an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 16-bit value that may be unaligned.

  @return The 16-bit value read from Buffer.

**/
UINT16
EFIAPI
ReadUnaligned16 (
  IN CONST UINT16              *Buffer
  );

/**
  Reads a 32-bit value from memory that may be unaligned.

  This function returns the 32-bit value pointed to by Buffer. The function
  guarantees that the read operation does not produce an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 32-bit value that may be unaligned.

  @return The 32-bit value read from Buffer.

**/
UINT32
EFIAPI
ReadUnaligned32 (
  IN      CONST UINT32              *Buffer
  );

/**
  Writes a 64-bit value to memory that may be unaligned.

  This function writes the 64-bit value specified by Value to Buffer. Value is
  returned. The function guarantees that the write operation does not produce
  an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 64-bit value that may be unaligned.
  @param  Value   The 64-bit value to write to Buffer.

  @return The 64-bit value to write to Buffer.

**/

UINT64
EFIAPI
WriteUnaligned64 (
  OUT     UINT64                    *Buffer,
  IN      UINT64                    Value
  );

/**
  Copy AuthSessionIn to TPM2 command buffer.

  @param [in]  AuthSessionIn   Input AuthSession data
  @param [out] AuthSessionOut  Output AuthSession data in TPM2 command buffer

  @return AuthSession size
**/

UINT32
EFIAPI
CopyAuthSessionCommand (
  IN      TPMS_AUTH_COMMAND         *AuthSessionIn, OPTIONAL
  OUT     UINT8                     *AuthSessionOut
  );

#endif
