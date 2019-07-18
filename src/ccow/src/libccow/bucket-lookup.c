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
#include <regex.h>

#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"

/*
 * Bucket Lookup API
 * Expected behaviour is as follows..
 *  input ( "test" )
 *	-- if no buckets exist in tenant, return -ENOENT
 *	-- if buckets exist all named < "test" eg "a" "b", return -ENOENT
 *	-- if buckets exist named > "test"  return the count next buckets
 */

int
ccow_bucket_lookup(ccow_t tctx, const char *pattern, size_t p_size, size_t count,
    ccow_lookup_t *iter)
{
	int err;
	struct ccow *tc = tctx;
	ccow_completion_t c;

	if (iter)
		*iter = NULL;

	if (pattern && p_size == 0)
		return -EINVAL;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	struct iovec iov = { .iov_base = buf };
	memcpy(iov.iov_base, pattern, p_size);
	iov.iov_len = p_size;
	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    "", 1, "", 1, c, &iov, 1, count, CCOW_GET_LIST, iter);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, -1);
	if (err) {
		if (iter && *iter) {
			ccow_lookup_release(*iter);
			*iter = NULL;
		}
		if (err == -ENOENT) {
			log_warn(lg, "Bucket lookup error: %d (not found)", err);
			return err;
		}
		log_error(lg, "Bucket lookup error: %d", err);
		return err;
	}

	return 0;
}

