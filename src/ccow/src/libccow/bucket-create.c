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

#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "rtbuf.h"


int
ccow_bucket_create(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_completion_t c_in)
{
	int err;
	struct ccow *tc = tctx;
	ccow_lookup_t iter = NULL;

	if (bid_size > REPLICAST_STR_MAXLEN) {
		log_error(lg, "BID length is greater then %d", REPLICAST_STR_MAXLEN);
		return -EINVAL;
	}

	/* try to read bucket object */
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 3, &c);
	if (err)
		return err;

	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    "", 1, "", 1, c, NULL, 0, 0, CCOW_GET, &iter);
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
			log_warn(lg, "Parent tenant object not found");
			return err;
		}
		log_error(lg, "Error while reading parent tenant object: %d", err);
		return err;
	}

	/* create new+empty bucket object with btree name index */
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		ccow_drop(c);
		return err;
	}

	/* default is 1 */
	uint16_t num_vers = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
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
				ccow_release(c);
				return err;
			}
		}
		ccow_lookup_release(iter);
		iter = NULL;
	}
	err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    bid, bid_size, "", 1, c, NULL, 0, 0, CCOW_PUT, NULL,
	    RD_ATTR_NO_OVERWRITE);
	if (err) {
		ccow_release(c);
		return err;
	}

	uint16_t flags = RT_INLINE_DATA_TYPE_BUCKET;
	err = ccow_attr_modify_default(c, CCOW_ATTR_INLINE_DATA_FLAGS,
	    (void *)&flags, NULL);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		ccow_drop(c);
		return err;
	}


	err = ccow_wait(c, 1);
	if (err) {
		return err;
	}

	char hash[UINT512_BYTES*2+1];
	hash_id_to_buffer(&c->vm_name_hash_id, hash);
	err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    bid, bid_size, hash, strlen(hash) + 1, c, NULL, 0, 0, CCOW_PUT, NULL,
	    RD_ATTR_OBJECT_REPLACE || RD_ATTR_NO_TRLOG);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 2);
	if (err) {
		return err;
	}

	// Create NFS objects
	if (tc->cid_size > 1 && tc->tid_size > 1 && bid_size > 1) {
		err = ccow_bucket_inode_ref_create(tc, bid, bid_size,
			RT_SYSVAL_FOT_INODE2OID, strlen(RT_SYSVAL_FOT_INODE2OID) + 1);
		if (err) {
			return err;
		}
	}

	/*
	 * Add bucket to the tenant object
	 */
	char buf[CCOW_BUCKET_CHUNK_SIZE];
	struct iovec iov = { .iov_base = buf };
	memcpy(iov.iov_base, bid, bid_size);
	iov.iov_len = bid_size;
	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	if (err)
		return err;

	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    "", 1, "", 1, c, NULL, 0, 0, CCOW_GET, &iter);
	if (err) {
		ccow_drop(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		/* This tenant doesnt exist so you are admin doing bad things
		 * or tenant violating their tenancy. */
		ccow_drop(c);
		if (err == -ENOENT)
			err = -EPERM;
		goto _cleanup;
	}

	c->cont_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
	err = ccow_container_update_list(tc->cid, tc->cid_size,
					 tc->tid, tc->tid_size,
					 "", 1, "", 1, c, &iov, 1,
					 CCOW_INSERT_LIST);
	if (err) {
		ccow_release(c);
		goto _cleanup;
	}
	err = ccow_wait(c, 1);
	if (err) {
		ccow_bucket_delete(tc, bid, bid_size);
	}

_cleanup:
	if (iter)
		ccow_lookup_release(iter);
	return err;
}

int
ccow_bucket_inode_ref_create(ccow_t tctx, const char *bid, size_t bid_size, const char *oid, size_t oid_size)
{
	int err;
	struct ccow *tc = tctx;

	if (bid_size > REPLICAST_STR_MAXLEN) {
		log_error(lg, "BID length is greater then %d", REPLICAST_STR_MAXLEN);
		return -EINVAL;
	}

	/* try to read bucket object */
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	/* create new+empty bucket object with btree name index */
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
	if (err) {
		ccow_release(c);
		return err;
	}

	/* default is 1 */
	uint16_t num_vers = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	if (err) {
		ccow_release(c);
		return err;
	}

	/* 48 entries max of ~ 1K per entry */
	uint16_t order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_1K;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER, &order, NULL);
	if (err) {
		ccow_release(c);
		return err;
	}

	uint16_t flags = RT_INLINE_DATA_TYPE_NFS_AUX;
	err = ccow_attr_modify_default(c, CCOW_ATTR_INLINE_DATA_FLAGS,
	    (void *)&flags, NULL);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_put_notrlog(bid, bid_size, oid, oid_size, c, NULL, 0, 0);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err) {
		return err;
	}

	return err;
}
