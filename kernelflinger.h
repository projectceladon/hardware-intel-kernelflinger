#ifndef _DUMMYBOOT_H_
#define _DUMMYBOOT_H_

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>

#include "lib.h"

#define DEBUG_MESSAGES 1

#if DEBUG_MESSAGES
#define debug(fmt, ...) do { \
    Print(L##fmt L"\n", ##__VA_ARGS__); \
} while(0)

#define debug_pause(x) pause(x)
#else
#define debug(fmt, ...) (void)0
#define debug_pause(x) (void)(x)
#endif

#define efi_perror(ret, x, ...) Print(x L": %r", ##__VA_ARGS__, ret)

#define KERNELFLINGER_VERSION	L"kernelflinger-00.01"

#define _unused __attribute__((unused))

extern const EFI_GUID fastboot_guid;
extern const EFI_GUID loader_guid;

#endif
