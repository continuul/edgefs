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
 * Insert name/value into the users list
 *
 * @param tctx the tenant cluster context
 * @param iov - io buffers iov[0] -> name, iov[1] -> value
 * @returns 0 on success, negative error code on failure
 */
int ccow_user_put(ccow_t tctx, struct iovec *iov)
{

    ccow_shard_context_t users_shard_context;

    int err = ccow_shard_context_create(RT_SYSVAL_USER_SHARD,
                                        strlen(RT_SYSVAL_USER_SHARD) + 1,
                                        RT_SYSVAL_USER_SHARD_COUNT, &users_shard_context);
    if (err) {
        log_error(lg, "User put create shard context error: %d", err);
        return err;
    }
    users_shard_context->encryption = 1;

    char service_psevdo_bucket[UINT512_BYTES * 2 + 1];
    uint512_dump(&tctx->tenant_hash_id, service_psevdo_bucket, UINT512_BYTES * 2 + 1);

    err = ccow_sharded_list_put(tctx, service_psevdo_bucket,
                                strlen(service_psevdo_bucket) + 1, users_shard_context, iov, 2);
    if (err) {
        log_error(lg, "User put error: %d", err);
    }

    ccow_shard_context_destroy(&users_shard_context);
    return err;
}

/**
 * Delete user name from the tenant
 *
 * @param tctx the tenant cluster context
 * @param name value
 * @param name_size  name size
 * @returns 0 on success, negative error code on failure
 */
int ccow_user_delete(ccow_t tctx, char *name, size_t name_size)
{
    ccow_shard_context_t users_shard_context;

    int err = ccow_shard_context_create(RT_SYSVAL_USER_SHARD,
                                        strlen(RT_SYSVAL_USER_SHARD) + 1,
                                        RT_SYSVAL_USER_SHARD_COUNT, &users_shard_context);
    if (err) {
        log_error(lg, "User delete create shard context error: %d", err);
        return err;
    }

    char service_psevdo_bucket[UINT512_BYTES * 2 + 1];
    uint512_dump(&tctx->tenant_hash_id, service_psevdo_bucket, UINT512_BYTES * 2 + 1);

    err = ccow_sharded_list_delete(tctx, service_psevdo_bucket,
                                   strlen(service_psevdo_bucket) + 1, users_shard_context, name, name_size);
    if (err) {
        log_error(lg, "User delete error: %d", err);
    }

    ccow_shard_context_destroy(&users_shard_context);
    return err;
}

/**
 * Get user's value by name
 *
 *
 * @param tctx the tenant cluster context
 * @param name value
 * @param name_size  name size
 * @param iov - io buffer, at least one element to keep value
 * @returns 0 on success, negative error code on failure
 */
int ccow_user_get(ccow_t tctx, char *name, size_t name_size, struct iovec *iov)
{

    ccow_shard_context_t users_shard_context;

    int err = ccow_shard_context_create(RT_SYSVAL_USER_SHARD,
                                        strlen(RT_SYSVAL_USER_SHARD) + 1,
                                        RT_SYSVAL_USER_SHARD_COUNT, &users_shard_context);
    if (err) {
        log_error(lg, "User get create shard context error: %d", err);
        return err;
    }

    char service_psevdo_bucket[UINT512_BYTES * 2 + 1];
    uint512_dump(&tctx->tenant_hash_id, service_psevdo_bucket, UINT512_BYTES * 2 + 1);

    err = ccow_sharded_list_get(tctx, service_psevdo_bucket,
                                strlen(service_psevdo_bucket) + 1, users_shard_context, name, name_size, iov, 1);
    if (err) {
        log_error(lg, "User get error: %d", err);
    }

    ccow_shard_context_destroy(&users_shard_context);
    return err;
}

/**
 * Get user's list
 *
 * @param tctx the tenant cluster context
 * @param marker value, the list results are greater then marker
 * @param marker_size  marker size
 * @param count - maximum number of the list items
 * @param iter output lookup iterator
 * @returns 0 on success, negative error code on failure
 */
int ccow_user_list(ccow_t tctx, char *marker, size_t marker_size, int count, ccow_lookup_t * iter)
{

    ccow_shard_context_t users_shard_context;

    int err = ccow_shard_context_create(RT_SYSVAL_USER_SHARD,
                                        strlen(RT_SYSVAL_USER_SHARD) + 1,
                                        RT_SYSVAL_USER_SHARD_COUNT, &users_shard_context);
    if (err) {
        log_error(lg, "Users list create shard context error: %d", err);
        return err;
    }

    char service_psevdo_bucket[UINT512_BYTES * 2 + 1];
    uint512_dump(&tctx->tenant_hash_id, service_psevdo_bucket, UINT512_BYTES * 2 + 1);

    err = ccow_sharded_get_list(tctx, service_psevdo_bucket,
                                strlen(service_psevdo_bucket) + 1, users_shard_context,
                                marker, marker_size, NULL, count, iter);
    if (err) {
        log_error(lg, "Users list error: %d", err);
    }

    ccow_shard_context_destroy(&users_shard_context);
    return err;
}
