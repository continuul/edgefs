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
#include "ccowutil.h"
#include "ccow-impl.h"

static int create_service_objects(const char *cid, size_t cid_size, const char *tid, size_t tid_size)
{

    int err = 0;
    ccow_t cl = NULL;

    // Skip special tenants
    if (accounting_tid_skip((char *)tid, tid_size))
        return 0;

    // Add users and acl sharded lists
    ccow_shard_context_t users_shard_context = NULL;
    ccow_shard_context_t acls_shard_context = NULL;

    err = ccow_shard_context_create(RT_SYSVAL_USER_SHARD,
                                    strlen(RT_SYSVAL_USER_SHARD) + 1, RT_SYSVAL_USER_SHARD_COUNT, &users_shard_context);
    if (err) {
        log_error(lg, "users_shard_context error: %d", err);
        goto _exit;
    }
    users_shard_context->encryption = 1;

    err = ccow_shard_context_create(RT_SYSVAL_ACL_SHARD,
                                    strlen(RT_SYSVAL_ACL_SHARD) + 1, RT_SYSVAL_ACL_SHARD_COUNT, &acls_shard_context);
    if (err) {
        log_error(lg, "acls_shard_context create error: %d", err);
        goto _exit;
    }
    // Find psevdo bucket name
    err = ccow_default_tenant_init(cid, cid_size, tid, tid_size, &cl);
    if (err) {
        log_error(lg, "ccow_default_tenant_init error: %d", err);
        goto _exit;
    }

    char service_psevdo_bucket[UINT512_BYTES * 2 + 1];
    uint512_dump(&cl->tenant_hash_id, service_psevdo_bucket, UINT512_BYTES * 2 + 1);

    err = ccow_sharded_list_create(cl, service_psevdo_bucket, strlen(service_psevdo_bucket) + 1, users_shard_context);
    if (err) {
        log_error(lg, "users list create error: %d", err);
        goto _exit;
    }

    err = ccow_sharded_list_create(cl, service_psevdo_bucket, strlen(service_psevdo_bucket) + 1, acls_shard_context);
    if (err) {
        log_error(lg, "acl list create error: %d", err);
    }

 _exit:
    if (cl)
        ccow_tenant_term(cl);
    if (users_shard_context)
        ccow_shard_context_destroy(&users_shard_context);
    if (acls_shard_context)
        ccow_shard_context_destroy(&acls_shard_context);

    return err;
}

/*
 * Initiate attempt to read TID/BID/OID 0x0 (CCOW cluster system object) and
 * modify it if found.  Return error if cluster object not found. Create
 * new/empty tenant object.
 */
int ccow_tenant_create(ccow_t tctx, const char *tid, size_t tid_size, ccow_completion_t c_in)
{
    int err;
    struct ccow *tc = tctx;
    ccow_completion_t c;
    ccow_lookup_t iter = NULL;

    assert(tid && tid_size > 0);

    if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN, strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
        log_error(lg, "Operation not permitted");
        log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
        return -EPERM;
    }

    if (tid_size > REPLICAST_STR_MAXLEN) {
        log_error(lg, "TID length is greater then %d", REPLICAST_STR_MAXLEN);
        return -EINVAL;
    }

    /* read this cluster object */

    err = ccow_create_completion(tc, NULL, NULL, 2, &c);
    if (err)
        return err;
    err = ccow_tenant_get(tc->cid, tc->cid_size, "", 1, "", 1, "", 1, c, NULL, 0, 0, CCOW_GET, &iter);
    if (err) {
        ccow_drop(c);
        return err;
    }

    err = ccow_wait(c, 0);
    if (err) {
        ccow_drop(c);
	if (iter)
		ccow_lookup_release(iter);
        if (err == -ENOENT) {
            log_warn(lg, "Cluster's system object not found");
            return err;
        }
        log_error(lg, "Error while reading cluster's system object: %d", err);
        return err;
    }

    /* create new+empty tenant object with btree name index */
    err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE, RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
    if (err) {
        if (iter)
            ccow_lookup_release(iter);
        ccow_drop(c);
        return err;
    }

    /* default is 1 */
    uint16_t num_vers = 1;
    err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS, (void *)&num_vers, NULL);
    if (err) {
        if (iter)
            ccow_lookup_release(iter);
        ccow_drop(c);
        return err;
    }

    /* 48 entries max of ~ 1K per entry */
    uint16_t order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_1K;
    err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER, &order, NULL);
    if (err) {
        if (iter)
            ccow_lookup_release(iter);
        ccow_drop(c);
        return err;
    }

    if (iter) {
        ccow_copy_inheritable_md_to_comp(iter->metadata, c);
        if (c_in) {
            err = ccow_copy_inheritable_md(c_in, c);
            if (err) {
                if (iter)
                    ccow_lookup_release(iter);
                ccow_drop(c);
                return err;
            }
        }
        ccow_lookup_release(iter);
        iter = NULL;
    }
    err = ccow_tenant_put(tc->cid, tc->cid_size, tid, tid_size,
                          "", 1, "", 1, c, NULL, 0, 0, CCOW_PUT, NULL, RD_ATTR_NO_OVERWRITE);
    if (err) {
        ccow_release(c);
        return err;
    }

    err = ccow_wait(c, 1);
    if (err) {
        return err;
    }

    /* add tenant to the cluster object */

    ccow_completion_t c_add;
    err = ccow_create_completion(tc, NULL, NULL, 1, &c_add);
    if (err)
        return err;

    char buf[CCOW_CLUSTER_CHUNK_SIZE];
    struct iovec iov = {.iov_base = buf };
    memcpy(iov.iov_base, tid, tid_size);
    iov.iov_len = tid_size;
    err = ccow_container_update_list(tc->cid, tc->cid_size, "", 1, "", 1, "", 1, c_add, &iov, 1, CCOW_INSERT_LIST);
    if (err) {
        ccow_release(c_add);
        return err;
    }

    err = ccow_wait(c_add, 0);
    if (err) {
        ccow_tenant_delete(tc, tid, tid_size);
        return err;
    }

    err = create_service_objects(tc->cid, tc->cid_size, tid, tid_size);

    return err;
}
