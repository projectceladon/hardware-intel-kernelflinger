/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
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


#include <efi.h>
#include <efiapi.h>
#include <efilib.h>

#include "ux.h"
#include "ui.h"
#include "lib.h"
#include "unittest.h"
#include "blobstore.h"
#include "watchdog.h"

/*
 * This is the hardware second timeout value
 */
#define TCO_SECOND_TIMEOUT 3

static VOID test_watchdog(VOID)
{
        EFI_STATUS ret;
        UINT32 timeout = 30;

        ret = start_watchdog(timeout);
        if (EFI_ERROR(ret))
                Print(L"Coudln't start watchdog, ");
        else {
                Print(L"Watchdog should reset at the end of the countdown\n");
                for (timeout += TCO_SECOND_TIMEOUT; timeout != 0; timeout--) {
                        pause(1);
                        Print(L"%d seconds left...\n", timeout);
                }
                Print(L"Watchdog did not reset the platform, ");
        }
        Print(L"test Failed\n");
}


static VOID test_keys(VOID)
{
        const UINTN wait_s = 10;
        UINTN i;
        ui_events_t event;

        Print(L"Reading keys for the next %d seconds...\n", wait_s);
        for (i = 0; i <= wait_s * 1000; i += 1) {
                event = ui_read_input();
                if (event == EV_NONE) {
                        uefi_call_wrapper(BS->Stall, 1, 1000);
                        continue;
                }
                Print(L"Received %d key event\n", event);
        }
}

static UINT8 fake_hash[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB};

static VOID test_ux(VOID)
{
        /* TODO: some method of programmatically verifying that these work */
        ux_prompt_user(RED_STATE_CODE, TRUE, NULL, 0);
        ux_prompt_user(RED_STATE_CODE, FALSE, NULL, 0);
        ux_prompt_user(BAD_RECOVERY_CODE, TRUE, NULL, 0);
        ux_prompt_user(BAD_RECOVERY_CODE, FALSE, NULL, 0);
        ux_prompt_user(DEVICE_UNLOCKED_CODE, TRUE, NULL, 0);
        ux_prompt_user(DEVICE_UNLOCKED_CODE, FALSE, NULL, 0);
        ux_prompt_user(SECURE_BOOT_CODE, TRUE, NULL, 0);
        ux_prompt_user(SECURE_BOOT_CODE, FALSE, NULL, 0);
        ux_prompt_user(BOOTIMAGE_UNTRUSTED_CODE, TRUE, fake_hash, sizeof(fake_hash));
        ux_prompt_user(BOOTIMAGE_UNTRUSTED_CODE, FALSE, fake_hash, sizeof(fake_hash));
        ux_prompt_user_for_boot_target(NO_ERROR_CODE);
        ux_prompt_user_for_boot_target(CRASH_EVENT_CODE);
        ux_prompt_user_for_boot_target(NOT_BOOTABLE_CODE);
        ux_display_low_battery(3);
}

static struct test_suite {
        CHAR16 *name;
        VOID (*fun)(VOID);
} TEST_SUITES[] = {
        { L"ux", test_ux },
        { L"keys", test_keys },
        { L"watchdog", test_watchdog }
};

VOID unittest_main(CHAR16 *testname)
{
        BOOLEAN found = FALSE;
        UINTN i;

        for (i = 0; i < ARRAY_SIZE(TEST_SUITES); i++)
                if (!testname || !StrCmp(L"all", testname) ||
                    !StrCmp(TEST_SUITES[i].name, testname)) {
                        found = TRUE;
                        Print(L"'%s' test suite begins\n", TEST_SUITES[i].name);
                        TEST_SUITES[i].fun();
                        Print(L"'%s' test suite terminated\n", TEST_SUITES[i].name);
                }

        if (!found)
                Print(L"'%s' test suite not found\n", testname);
}
