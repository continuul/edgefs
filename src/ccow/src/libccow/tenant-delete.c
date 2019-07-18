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

#define MAX_SERVICE 10000

static int delete_service_objects(char *cid, size_t cid_size, char *tid, size_t tid_size)
{

    int err = 0;
    ccow_t cl = NULL;
    ccow_shard_context_t users_shard_context = NULL;
    ccow_shard_context_t acls_shard_context = NULL;

    // Skip special tenants
    if (accounting_tid_skip(tid, tid_size))
        return 0;

    // Add users and acl sharded lists
    err = ccow_shard_context_create(RT_SYSVAL_USER_SHARD,
                                    strlen(RT_SYSVAL_USER_SHARD) + 1, RT_SYSVAL_USER_SHARD_COUNT, &users_shard_context);
    if (err) {
        log_error(lg, "users_shard_context error: %d", err);
        goto _exit;
    }

    err = ccow_shard_context_create(RT_SYSVAL_ACL_SHARD,
                                    strlen(RT_SYSVAL_ACL_SHARD) + 1, RT_SYSVAL_ACL_SHARD_COUNT, &acls_shard_context);
    if (err) {
        log_error(lg, "acls_shard_context create error: %d", err);
        goto _exit;
    }
    // Create tenant context
    err = ccow_default_tenant_init(cid, cid_size, tid, tid_size, &cl);
    if (err) {
        log_error(lg, "ccow_default_tenant_init error: %d", err);
        goto _exit;
    }

    char service_psevdo_bucket[UINT512_BYTES * 2 + 1];
    uint512_dump(&cl->tenant_hash_id, service_psevdo_bucket, UINT512_BYTES * 2 + 1);

    // Delete users sharded list
    err = ccow_sharded_list_destroy(cl, service_psevdo_bucket, strlen(service_psevdo_bucket) + 1, users_shard_context);
    if (err) {
        log_error(lg, "users list delete error: %d", err);
        goto _exit;
    }
    // Delete acls sharded list
    err = ccow_sharded_list_destroy(cl, service_psevdo_bucket, strlen(service_psevdo_bucket) + 1, acls_shard_context);
    if (err) {
        log_error(lg, "acl list delete error: %d", err);
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

static int
tenant_used_by_service(ccow_t cl, const char *tid, size_t tid_size) {
	struct isgw_service_entry* table = NULL;
	int err;
	ccow_completion_t c;

	char tenent_path[cl->cid_size + tid_size];
	int tenent_len;

	sprintf(tenent_path,"%s/%s", cl->cid, tid);
	tenent_len = strlen(tenent_path);

	log_debug(lg, "Check tenant: %s", tenent_path);

	/*
	 * Read root system object with NHID = 0x0
	 */
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "ccow_create_completion returned error = %d", err);
		return err;
	}

	char buf = 0;
	struct iovec iov = { .iov_base = &buf, .iov_len = 1 };
	ccow_lookup_t iter = NULL, biter = NULL;
	err = ccow_tenant_get("", 1, RT_SYSVAL_TENANT_ADMIN, strlen(RT_SYSVAL_TENANT_ADMIN) + 1,
		"", 1, "", 1, c, &iov, 1, MAX_SERVICE, CCOW_GET_LIST, &iter);
	if (err) {
		ccow_release(c);
		log_warn(lg, "ccow_tenant_get = %d", err);
		return err;
	}
	err = ccow_wait(c, -1);
	if (err == -ENOENT) {
		return 0;
	}
	if (err) {
		log_warn(lg, "Error while reading system object: %d, ", err);
		return err;
	}

	int pos = 0;
	struct ccow_metadata_kv *kv;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++))) {
		/*
		 * Iterate through all the buckets listed in the tenant
		 * Bucket name is a service ID
		 */
		int get_err = 0;
		char *sid = (char *)kv->key;
		uint16_t sid_size = kv->key_size;

		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		if (err) {
			log_error(lg, "ccow_create_completion failed with error: %d",
				err);
			goto _cleanup;
		}

		err = ccow_tenant_get("", 1, RT_SYSVAL_TENANT_ADMIN, strlen(RT_SYSVAL_TENANT_ADMIN) + 1,
			sid, sid_size, "", 1, c, &iov, 1, MAX_SERVICE, CCOW_GET_LIST, &biter);

		if (err) {
			ccow_release(c);
			log_debug(lg, "Cannot get service information %s: %d", sid, err);
			goto _cleanup;
		}
		err = ccow_wait(c, -1);
		if (err == -ENOENT) {
			err = 0;
			ccow_lookup_release(biter);
			biter = NULL;
			continue;
		}
		if (err) {
			if (biter) {
				ccow_lookup_release(biter);
				biter = NULL;
			}
			log_debug(lg, "Cannot get service %s wait error: %d", sid, err);
			goto _cleanup;
		}

		struct ccow_metadata_kv *bkv;
		int bpos = 0;
		/* Looking for tenants to be served */
		while ((bkv = ccow_lookup_iter(biter, CCOW_MDTYPE_NAME_INDEX, bpos++))) {
			if (bkv->key_size == 0)
				continue;
			char *path = (char *)bkv->key;
			char *sp = NULL;
			char *tpath = path;
			sp = strchr(path,'@');
			if (sp) {
			   tpath = sp + 1;
			} else {
				sp = strchr(path,',');
				if (sp) {
					*sp = 0;
				}
			}
			int tlen = strlen(tpath);
			log_debug(lg, "Service check sid: %s, tenant path: %s[%d], tpath: %s[%d]",
				 sid, tenent_path, tenent_len, tpath, tlen);

			if (tlen == tenent_len && strncmp(tpath, tenent_path, tlen) == 0) {
				err = -EPERM;
				goto _cleanup;
			}
			if (tlen > tenent_len && strncmp(tpath, tenent_path, tenent_len) == 0 && tpath[tenent_len] == '/') {
				err = -EPERM;
				goto _cleanup;
			}
		}
		ccow_lookup_release(biter);
		biter = NULL;
	}
_cleanup:
	if (biter)
		ccow_lookup_release(biter);
	if (iter)
		ccow_lookup_release(iter);
	log_debug(lg, "Service check err: %d", err);
	return err;
}


/*
 * Initiate attempt to read TID/BID/OID 0x0 (CCOW cluster system object) and
 * delete it if found. Return error if does not exist.
 */
int ccow_tenant_delete(ccow_t tctx, const char *tid, size_t tid_size)
{
    int err;
    struct ccow *tc = tctx;
    ccow_completion_t c;

    assert(tid && tid_size > 0);

    if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN, strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
        log_error(lg, "Operation not permitted");
        log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
        return -EPERM;
    }

    /* check to see if tenant has buckets, disallow delete */

    err = ccow_create_completion(tc, NULL, NULL, 1, &c);
    if (err)
        return err;

    ccow_lookup_t iter = NULL;
    struct iovec iov = {.iov_base = NULL,.iov_len = 0 };
    err = ccow_tenant_get(tc->cid, tc->cid_size, tid, tid_size, "", 1, "", 1, c, &iov, 1, 1, CCOW_GET_LIST, &iter);
    if (err) {
        ccow_release(c);
        return err;
    }

    err = ccow_wait(c, -1);
    int services = 0;
    if (err == 0 && iter) {
        struct ccow_metadata_kv *kv = NULL;
        kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, 0);
        if (kv && kv->key_size > 1) {
            ccow_lookup_release(iter);
            log_error(lg, "Tenant object has buckets: delete \
			    buckets first");
            return RT_ERR_NOT_EMPTY;
        }
    } else if (err != -ENOENT) {
        if (iter)
            ccow_lookup_release(iter);
        log_error(lg, "Error while accessing tenant object: %d", err);
        log_hexdump(lg, "CID:", tc->cid, tc->cid_size);
        log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
        return err;
    }

    if (iter)
        ccow_lookup_release(iter);

	// Check services
	if (tc->cid_size > 1 && tid_size > 1) {
		err = tenant_used_by_service(tc, tid, tid_size);
		if (err)
			return err;
	}

    /* Delete service objects */
    err = delete_service_objects(tc->cid, tc->cid_size, tc->tid, tc->tid_size);
    if (err) {
        log_error(lg, "service objects delete error: %d", err);
    }

    /* try to delete tenant object */
    err = ccow_create_completion(tc, NULL, NULL, 2, &c);
    if (err)
        return err;

    err = ccow_tenant_put(tc->cid, tc->cid_size, tid, tid_size,
                          "", 1, "", 1, c, NULL, 0, 0, CCOW_PUT, NULL, RD_ATTR_LOGICAL_DELETE);
    if (err) {
        ccow_drop(c);
        return err;
    }

    err = ccow_wait(c, 0);
    if (err) {
        ccow_drop(c);
        if (err == -ENOENT) {
            log_warn(lg, "Cluster system object not found");
            return err;
        }
        log_error(lg, "Error while reading cluster system " "object: %d", err);
        return err;
    }

    /* delete tenant from the cluster object */

    char buf[CCOW_CLUSTER_CHUNK_SIZE];
    iov.iov_base = buf;
    memcpy(iov.iov_base, tid, tid_size);
    iov.iov_len = tid_size;
    err = ccow_container_update_list(tc->cid, tc->cid_size, "", 1, "", 1, "", 1, c, &iov, 1, CCOW_DELETE_LIST);
    if (err) {
        ccow_release(c);
        return err;
    }

    err = ccow_wait(c, 1);
    if (err) {
        return err;
    }

    return 0;
}
