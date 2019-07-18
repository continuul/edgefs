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

/*
 * Initiate attempt to read system object and delete cluster if it found.
 * Return error if does not exist.
 */
int
ccow_cluster_delete(ccow_t tctx, const char *cid, size_t cid_size)
{
	int err;
	struct ccow *tc = tctx;
	ccow_completion_t c;

	assert(cid && cid_size > 0);

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Operation not permitted");
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		return -EPERM;
	}

	/* check to see if cluster has tenants, disallow delete */

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	ccow_lookup_t iter;
	struct iovec iov = { .iov_base = NULL, .iov_len = 0 };
	err = ccow_tenant_get(cid, cid_size, "", 1,
	    "", 1, "", 1, c, &iov, 1, 10, CCOW_GET_LIST, &iter);
	if (err) {
		ccow_release(c);
		return err;
	}
	int tenant_cnt = 0;
	err = ccow_wait(c, -1);
	if (err == 0) {
		struct ccow_metadata_kv *kv = NULL;
		do {
			kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
			    tenant_cnt);
			if(kv == NULL)
				break;
			tenant_cnt++;
		} while (kv != NULL);
		ccow_lookup_release(iter);

		if (tenant_cnt == 1) {
			/* delete logical "root" tenant */

			ccow_completion_t c2;

			err = ccow_create_completion(tc, NULL, NULL, 1, &c2);
			if (err) {
				return err;
			}

			char buf[CCOW_CLUSTER_CHUNK_SIZE];
			iov.iov_base = buf;
			memcpy(iov.iov_base, "root", 5);
			iov.iov_len = 5;
			err = ccow_container_update_list(cid, cid_size,
							 "", 1, "", 1, "", 1,
							 c2, &iov, 1,
							 CCOW_DELETE_LIST);
			if (err) {
				ccow_release(c2);
				log_error(lg, "Error while deleting logical object: %d", err);
				return err;
			}

			err = ccow_wait(c2, 0);
			if (err && err != -ENOENT) {
				log_error(lg, "Error while executing "
				    "logical object: %d", err);
				return err;
			}
		} else {
			log_error(lg, "Cluster object has %d tenants: delete tenants first",
			    tenant_cnt - 1);
			return RT_ERR_NOT_EMPTY;
		}
	} else {
		if (iter)
			ccow_lookup_release(iter);
		if (err == -ENOENT) {
			log_warn(lg, "Cluster delete: object not found: %d", err);
		} else
			log_error(lg, "Cluster delete: error while accessing "
			    "cluster object: %d", err);
		log_hexdump(lg, "CID:", tc->cid, tc->cid_size);
		return err;
	}

	/* try to get sysobj object */
	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	if (err)
		return err;

	err = ccow_tenant_get("", 1, "", 1, "", 1, "", 1,
	    c, NULL, 0, 0, CCOW_GET, NULL);
	if (err) {
		ccow_drop(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		ccow_drop(c);
		if (err == -ENOENT) {
			log_warn(lg, "Root system object not found");
			return err;
		}
		log_error(lg, "Error while reading root system object: %d", err);
		return err;
	}
	/* delete cluster from the root object */

	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	iov.iov_base = buf;
	memcpy(iov.iov_base, cid, cid_size);
	iov.iov_len = cid_size;
	err = ccow_container_update_list("", 1, "", 1, "", 1, "", 1,
					 c, &iov, 1, CCOW_DELETE_LIST);
	if (err) {
		ccow_release(c);
		return err;
	}
	err = ccow_wait(c, 1);
	if (err) {
		log_error(lg, "Error while deleting cluster from system: %d",
		    err);
		return err;
	}

	if (tenant_cnt < 2) {
		//
		// Attempt to delete actual object.
		//
		ccow_completion_t c3;
		err = ccow_create_completion(tc, NULL, NULL, 1, &c3);
		if (err)
			return err;

		err = ccow_tenant_put(cid, cid_size, "", 1, "", 1, "", 1,
		    c3, NULL, 0, 0, CCOW_PUT, NULL,
		    RD_ATTR_LOGICAL_DELETE);
		if (err) {
			ccow_release(c3);
			return err;
		}
		err = ccow_wait(c3, 0);
		if (err) {
			if (err == -ENOENT) {
				log_warn(lg, "Cluster %s not found.", cid);
				return err;
			}
			log_error(lg, "Error while deleting cluster %s: %d", cid, err);
			return err;
		}
	}
	return 0;
}
