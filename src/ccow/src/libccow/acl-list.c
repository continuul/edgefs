/*
 * Copyright (c) 2015-2018 Nexenta Systems, inc.
 *
 * This file is part of EdgeFS Project
 * (see https://github.com/Nexenta/edgefs).
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
#include <uv.h>

#include <execinfo.h>
#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "rtbuf.h"

/**
 * Build acl key
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size the bid size
 * @param oid the NULL terminated string of name id of the object
 * @param oid_size the oid size
 * @param uvid_timestamp - object timestamp or 0
 * @returns the key: bid/iod@uvid
 */
static void
get_acl_key(char *key, const char *bid, size_t bid_size, const char *oid, size_t oid_size, uint64_t uvid_timestamp)
{
    char uvid[64];
    memcpy(key, bid, bid_size);
    key[bid_size - 1] = '/';
    memcpy(key + bid_size, oid, oid_size);
    key[bid_size + oid_size - 1] = '@';
    sprintf(uvid, "%ld", uvid_timestamp);
    memcpy(key + bid_size + oid_size, uvid, strlen(uvid) + 1);
}

/**
 * Insert acl value into acls list
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size the bid size
 * @param oid the NULL terminated string of name id of the object
 * @param oid_size the oid size
 * @param uvid_timestamp - object timestamp or 0
 * @param iov - io buffer iov[0] -> value
 * @returns 0 on success, negative error code on failure
 */
int
ccow_acl_put(ccow_t tctx, const char *bid, size_t bid_size, const char *oid,
             size_t oid_size, uint64_t uvid_timestamp, struct iovec *iov_value)
{

    ccow_shard_context_t acls_shard_context;

    int err = ccow_shard_context_create(RT_SYSVAL_ACL_SHARD,
                                        strlen(RT_SYSVAL_ACL_SHARD) + 1,
                                        RT_SYSVAL_ACL_SHARD_COUNT, &acls_shard_context);
    if (err) {
        log_error(lg, "ACL put create shard context error: %d", err);
        return err;
    }

    char service_psevdo_bucket[UINT512_BYTES * 2 + 1];
    uint512_dump(&tctx->tenant_hash_id, service_psevdo_bucket, UINT512_BYTES * 2 + 1);

    struct iovec iov[2];

    char key[1024];
    get_acl_key(key, bid, bid_size, oid, oid_size, uvid_timestamp);

    iov[0].iov_base = key;
    iov[0].iov_len = strlen(key) + 1;
    iov[1].iov_base = iov_value[0].iov_base;
    iov[1].iov_len = iov_value[0].iov_len;

    err = ccow_sharded_list_put(tctx, service_psevdo_bucket,
                                strlen(service_psevdo_bucket) + 1, acls_shard_context, iov, 2);
    if (err) {
        log_error(lg, "ACL put error: %d", err);
    }

    ccow_shard_context_destroy(&acls_shard_context);
    return err;
}

/**
 * Delete acl key from the tenant
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size the bid size
 * @param oid the NULL terminated string of name id of the object
 * @param oid_size the oid size
 * @param uvid_timestamp - object timestamp or 0
 * @returns 0 on success, negative error code on failure
 */
int
ccow_acl_delete(ccow_t tctx, const char *bid, size_t bid_size, const char *oid,
                size_t oid_size, uint64_t uvid_timestamp)
{
    ccow_shard_context_t acls_shard_context;

    int err = ccow_shard_context_create(RT_SYSVAL_ACL_SHARD,
                                        strlen(RT_SYSVAL_ACL_SHARD) + 1,
                                        RT_SYSVAL_ACL_SHARD_COUNT, &acls_shard_context);
    if (err) {
        log_error(lg, "ACL delete create shard context error: %d", err);
        return err;
    }

    char service_psevdo_bucket[UINT512_BYTES * 2 + 1];
    uint512_dump(&tctx->tenant_hash_id, service_psevdo_bucket, UINT512_BYTES * 2 + 1);

    char key[1024];
    get_acl_key(key, bid, bid_size, oid, oid_size, uvid_timestamp);

    err = ccow_sharded_list_delete(tctx, service_psevdo_bucket,
                                   strlen(service_psevdo_bucket) + 1, acls_shard_context, key, strlen(key) + 1);
    if (err) {
        log_error(lg, "ACL delete error: %d", err);
    }

    ccow_shard_context_destroy(&acls_shard_context);
    return err;
}

/**
 * Get acl's value
 *
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size the bid size
 * @param oid the NULL terminated string of name id of the object
 * @param oid_size the oid size
 * @param uvid_timestamp - object timestamp or 0
 * @param iov - io buffer, at least one element to keep value
 * @returns 0 on success, negative error code on failure
 */
int
ccow_acl_get(ccow_t tctx, const char *bid, size_t bid_size, const char *oid,
             size_t oid_size, uint64_t uvid_timestamp, struct iovec *iov)
{

    ccow_shard_context_t acls_shard_context;

    int err = ccow_shard_context_create(RT_SYSVAL_ACL_SHARD,
                                        strlen(RT_SYSVAL_ACL_SHARD) + 1,
                                        RT_SYSVAL_ACL_SHARD_COUNT, &acls_shard_context);
    if (err) {
        log_error(lg, "ACL get create shard context error: %d", err);
        return err;
    }

    char service_psevdo_bucket[UINT512_BYTES * 2 + 1];
    uint512_dump(&tctx->tenant_hash_id, service_psevdo_bucket, UINT512_BYTES * 2 + 1);

    char key[1024];
    get_acl_key(key, bid, bid_size, oid, oid_size, uvid_timestamp);

    err = ccow_sharded_list_get(tctx, service_psevdo_bucket,
                                strlen(service_psevdo_bucket) + 1, acls_shard_context, key, strlen(key) + 1, iov, 1);

    ccow_shard_context_destroy(&acls_shard_context);
    return err;
}
