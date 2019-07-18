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
 * Initiate attempt to read CID/TID/BID/OID 0x0 root system object and
 * constructs iterator object if found.
 *
 */
int
ccow_cluster_lookup(ccow_t tctx, const char *pattern, size_t p_size,
    size_t count, ccow_lookup_t *iter)
{
	int err;
	struct ccow *tc = tctx;

	if (iter)
		*iter = NULL;

	if (pattern && p_size == 0)
		return -EINVAL;
	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Operation not permitted");
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		return -EPERM;
	}

	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	struct iovec iov = { .iov_base = buf };
	memcpy(iov.iov_base, pattern, p_size);
	iov.iov_len = p_size;
	ccow_completion_t get_comp;

	err = ccow_create_completion(tc, NULL, NULL, 1, &get_comp);
	if (err)
		return err;

	err = ccow_tenant_get("", 1, "", 1, "", 1, "", 1, get_comp,
	    &iov, 1, count, CCOW_GET_LIST, iter);
	if (err) {
		ccow_release(get_comp);
		return err;
	}

	err = ccow_wait(get_comp, 0);
	if (err) {
		if (iter && *iter) {
			ccow_lookup_release(*iter);
			*iter = NULL;
		}
		if (err == -ENOENT) {
			log_warn(lg, "Cluster lookup error: %d (not found)", err);
			return err;
		}
		log_error(lg, "Cluster lookup error: %d", err);
		return err;
	}

	return 0;
}
