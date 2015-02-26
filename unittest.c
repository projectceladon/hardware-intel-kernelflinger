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


static VOID test_blobstore(VOID)
{
        blobstore_t *db;
        CHAR8 blob[1024];
        CHAR8 res_blob[1024];
        CHAR8 blob_key[64];
        UINT32 blob_size = 1024;
        int i;
        int meta_data_size = 150 * 1024;
        int data_size = 1024 * 1024 * 2; // dtb+ oem
        void *location = AllocatePool(meta_data_size + data_size );
        BOOLEAN test_pass = FALSE;
        int rc = 0;

        Print(L"Creating blob store with 1024 entries...\n");
        Print(L"blobstore location : 0x%lx\n", location);
        db = blobstore_allocate();
        if (blobstore_create(db, location, 1024) != 0) {
                Print(L"Failed to create blob store\n");
                goto end;
        }
        Print(L"Put test blobs into blob store...\n");
        for (i=1; i<=1024; i++) {
                snprintf(blob_key, 64, (CHAR8 *)"key%d",i);
                snprintf(blob, 1024, (CHAR8 *)"This is my Dtb%d", i);
                rc = blobstore_putblob(db, blob, strlen(blob)+1,
                                          blob_key, BLOB_TYPE_DTB);
                if(rc != 0)
                {
                        Print(L"Failed to Put dtb Blob. ret=%d\n", rc);
                        Print(L"blob_key:%a Blob:'%a'\n",
                                          blob_key, blob);
                        goto end;
                }
                snprintf(blob, 1024, (CHAR8 *)"This is my OemVar%d", i);
                rc = blobstore_putblob(db, blob, strlen(blob)+1,
                                          blob_key, BLOB_TYPE_OEMVARS);
                if (rc != 0)
                {
                        Print(L"Failed to Put Oem Blob ret=%d\n",rc);
                        Print(L"blobKey:%a Blob:'%a'\n",
                                          blob_key, blob);
                        goto end;
                }
        }

        Print(L"Close blob store...\n");
        blobstore_close(db);
        Print(L"Re-open/Load blob store...\n");
        rc = blobstore_load(db, location);
        if(rc != 0) {
                Print(L"Failed to load blobstore ret=%d\n",rc);
                goto end;
        }
        Print(L"Query blobs and Verify...\n");

        for (i=1024; i>=1; i--) {
                snprintf(blob_key, 64, (CHAR8 *)"key%d",i);
                // reset blobSize to show available size for blob Buffer
                blob_size = 1024;
                rc = blobstore_getblob(db, res_blob, &blob_size,
                                        blob_key, BLOB_TYPE_DTB);
                if(rc != 0) {
                        Print(L"Failed to Get Dtb Blob ret=%d\n",rc);
                        Print(L"blobKey:'%a'\n", blob_key);
                        goto end;
                }

                snprintf(blob, 1024, (CHAR8 *)"This is my Dtb%d",i);
                if(strncmp(res_blob, blob, 1024) != 0) {
                        Print(L"Dtb Blob Verification failed.\n");
                        Print(L"blobKey:%a Blob Put:'%a' Got:'%a'\n",
                                        blob_key, blob, res_blob);
                        goto end;
                }

                //reset blob_size to show available size for blob Buffer
                blob_size = 1024;
                rc = blobstore_getblob(db, res_blob, &blob_size,
                                blob_key, BLOB_TYPE_OEMVARS);
                if(rc != 0) {
                        Print(L"Failed to Get OemVars Blob. ret=%d\n",rc);
                        Print(L"blob_key:'%a'\n", blob_key);
                        goto end;
                }

                snprintf(blob, 1024, (CHAR8 *)"This is my OemVar%d",i);
                if(strncmp(res_blob, blob, 1024) != 0) {
                        Print(L"OemVar Blob Verification failed.\n");
                        Print(L"blobKey:%a Blob Put:%a Got:%a\n",
                                                blob_key, blob, res_blob);
                        goto end;
                }
        }
        test_pass = TRUE;
end:
        Print(L"Close blob store...\n");
        blobstore_close(db);
        blobstore_free(db);
        FreePool(location);
        if (test_pass)
                Print(L"Test Passed.\n");
        else
                Print(L"Test Failed.\n");

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
        ux_prompt_user_bootimage_unverified();
        ux_warn_user_unverified_recovery();
        ux_prompt_user_device_unlocked();
        ux_prompt_user_secure_boot_off();
        ux_prompt_user_keystore_unverified(fake_hash);
        ux_crash_event_prompt_user_for_boot_target();
}

static struct test_suite {
        CHAR16 *name;
        VOID (*fun)(VOID);
} TEST_SUITES[] = {
        { L"ux", test_ux },
        { L"keys", test_keys },
        { L"blobstore",test_blobstore }
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
