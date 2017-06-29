/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <trusty/keymaster.h>
#include <trusty/rpmb.h>
#include <trusty/trusty_ipc.h>
#include <trusty/util.h>
#include "security.h"

#define LOCAL_LOG 0
#define UNUSED(x) (void)(x)

static struct trusty_ipc_chan km_chan;
static bool initialized;
static int trusty_km_version = 1;
extern struct rot_data_t g_rot_data;
static int km_send_request(struct keymaster_message *msg, void *req,
                           size_t req_len, void *data, size_t data_len)
{
    int num_iovecs = 1;

    /* If data is non-NULL, req must be non-NULL */
    trusty_assert(!(!req && data));

    struct trusty_ipc_iovec req_iovs[3] = {
        { .base = msg, .len = sizeof(*msg) },
        { .base = req, .len = req_len },
        { .base = data, .len = data_len },
    };

    if (req && data) {
        num_iovecs = 3;
    } else if (req) {
        num_iovecs = 2;
    }

    return trusty_ipc_send(&km_chan, req_iovs, num_iovecs, true);
}

static int km_read_response(struct keymaster_message *msg, uint32_t cmd,
                            void *resp, size_t resp_len)
{
    int rc;
    struct trusty_ipc_iovec resp_iovs[2] = {
        { .base = msg, .len = sizeof(*msg) },
        { .base = resp, .len = resp_len },
    };

    rc = trusty_ipc_recv(&km_chan, resp_iovs, resp ? 2 : 1, true);
    if (rc < 0) {
        trusty_error("failed (%d) to recv response\n", rc);
        return rc;
    }
    if (msg->cmd != (cmd | KEYMASTER_RESP_BIT)) {
        trusty_error("malformed response\n");
        return TRUSTY_ERR_GENERIC;
    }
    return rc;
}

static int km_do_tipc(uint32_t cmd, void *req, uint32_t req_len,
                      void *data, uint32_t data_len, bool handle_rpmb)
{
    int rc;
    struct keymaster_message msg = { .cmd = cmd };
    struct km_no_response resp;

    rc = km_send_request(&msg, req, req_len, data, data_len);
    if (rc < 0) {
        trusty_error("%s: failed (%d) to send km request\n", __func__, rc);
        return rc;
    }

    if (handle_rpmb) {
        /* handle any incoming RPMB requests */
        rc = rpmb_storage_proxy_poll();
        if (rc < 0) {
            trusty_error("%s: failed (%d) to get RPMB requests\n", __func__,
                         rc);
            return rc;
        }
    }

    rc = km_read_response(&msg, cmd, &resp, sizeof(resp));
    if (rc < 0) {
        trusty_error("%s: failed (%d) to read km response\n", __func__, rc);
        return rc;
    }

    return resp.error;
}

static int32_t MessageVersion(uint8_t major_ver, uint8_t minor_ver,
                              uint8_t subminor_ver) {
    UNUSED(subminor_ver);
    int32_t message_version = -1;
    switch (major_ver) {
    case 0:
        message_version = 0;
        break;
    case 1:
        switch (minor_ver) {
        case 0:
            message_version = 1;
            break;
        case 1:
            message_version = 2;
            break;
        }
        break;
    case 2:
        message_version = 3;
        break;
    }
    return message_version;
}

static int km_get_version(int32_t *version)
{
    int rc;
    struct keymaster_message msg = { .cmd = KM_GET_VERSION };
    struct km_get_version_resp resp;

    rc = km_send_request(&msg, NULL, 0, NULL, 0);
    if (rc < 0) {
        trusty_error("failed to send km version request", rc);
        return rc;
    }

    rc = km_read_response(&msg, KM_GET_VERSION, &resp, sizeof(resp));
    if (rc < 0) {
        trusty_error("%s: failed (%d) to read km response\n", __func__, rc);
        return rc;
    }

    *version = MessageVersion(resp.major_ver, resp.minor_ver,
                              resp.subminor_ver);
    return rc;
}

int km_tipc_init(struct trusty_ipc_dev *dev)
{
    int rc;

    trusty_assert(dev);

    trusty_ipc_chan_init(&km_chan, dev);
    trusty_debug("Connecting to Keymaster service\n");

    /* connect to km service and wait for connect to complete */
    rc = trusty_ipc_connect(&km_chan, KEYMASTER_PORT, true);
    if (rc < 0) {
        trusty_error("failed (%d) to connect to '%s'\n", rc, KEYMASTER_PORT);
        return rc;
    }

    int32_t version = -1;
    rc = km_get_version(&version);
    if (rc < 0) {
        trusty_error("failed (%d) to get keymaster version\n", rc);
        return rc;
    }
    if (version < trusty_km_version) {
        trusty_error("keymaster version mismatch. Expected %d, received %d\n",
                     trusty_km_version, version);
        return TRUSTY_ERR_GENERIC;
    }

    /* sent the ROT information to trusty */
    trusty_set_boot_params(g_rot_data.osVersion,
                g_rot_data.patchMonthYear,
                g_rot_data.verifiedBootState,
                g_rot_data.deviceLocked,
                g_rot_data.keyHash256,
                g_rot_data.keySize);

    /* TODO: (KM2.0 features)set the attestation_key and append the attest cert */
    //trusty_set_attestation_key(NULL, 0,KM_ALGORITHM_RSA);

    return TRUSTY_ERR_NONE;
}

void km_tipc_shutdown(struct trusty_ipc_dev *dev)
{
    UNUSED(dev);
    if (!initialized)
        return;
    /* close channel */
    trusty_ipc_close(&km_chan);

    initialized = false;
}

int trusty_set_boot_params(uint32_t os_version, uint32_t os_patchlevel,
                           keymaster_verified_boot_t verified_boot_state,
                           bool device_locked, uint8_t *verified_boot_key_hash,
                           uint32_t verified_boot_key_hash_size)
{
    struct km_set_boot_params_req req = {
        .os_version = os_version,
        .os_patchlevel = os_patchlevel,
        .device_locked = (uint32_t)device_locked,
        .verified_boot_state = (uint32_t)verified_boot_state,
        .verified_boot_key_hash_size = verified_boot_key_hash_size,
    };

    return km_do_tipc(KM_SET_BOOT_PARAMS, &req, sizeof(req),
                      verified_boot_key_hash, verified_boot_key_hash_size,
                      false);
}

int trusty_set_attestation_key(uint8_t *key, uint32_t key_size,
                               keymaster_algorithm_t algorithm)
{
    struct km_set_attestation_key_req req = {
        .algorithm = (uint32_t)algorithm,
        .key_size = key_size
    };
    trusty_debug("key_size: %d\n", key_size);

    return km_do_tipc(KM_SET_ATTESTATION_KEY, &req, sizeof(req), key, key_size,
                      true);
}

int trusty_append_attestation_cert_chain(uint8_t *cert, uint32_t cert_size,
                                         keymaster_algorithm_t algorithm)
{
    struct km_append_attestation_cert_chain_req req = {
        .algorithm = (uint32_t)algorithm,
        .cert_size = cert_size
    };
    trusty_debug("cert_size: %d\n", cert_size);

    return km_do_tipc(KM_APPEND_ATTESTATION_CERT_CHAIN, &req, sizeof(req), cert,
                      cert_size, true);
}
