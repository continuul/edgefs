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
#include "rcvd_cache.h"
#include "logger.h"
#include "reptrans.h"
#include "putcommon_server.h"

int
reptrans_init_rcvd_cache(struct repdev *dev)
{
	dev->rcvd_cache = hashtable_create(RCVD_CACHE_MAX_ENTRIES, 0, 0.05);
	if (!dev->rcvd_cache) {
		log_error(lg, "Unable to create a hashtable for rcvd chids");
		return -1;
	}
	return 0;
}

void
reptrans_destroy_rcvd_cache(struct repdev *dev)
{
	if (!dev->rcvd_cache)
		return;
	hashtable_destroy(dev->rcvd_cache);
}

void reptrans_addto_rcvd_cache(hashtable_t *rcvd_cache, uint512_t *chid,
    struct putcommon_srv_req *req)
{
	uint64_t pval = (uint64_t) req, *rval = NULL;
	uint512_logdump(lg, "Adding to rcvd_cache: ", chid);
	int err = hashtable_put(rcvd_cache, chid, sizeof(uint512_t),
			&pval, sizeof (uint64_t));
	if (err < 0) {
		char idstr[UINT512_BYTES * 2 + 1];
		uint512_dump(chid, idstr, UINT512_BYTES * 2 + 1);
		log_error(lg, "Unable to insert chid into hashtable: %s", idstr);
		return;
	}
}

void reptrans_rmfrom_rcvd_cache(hashtable_t *rcvd_cache, uint512_t *chid)
{
	uint512_logdump(lg, "Removing from rcvd_cache: ", chid);
	hashtable_remove(rcvd_cache, chid, sizeof(uint512_t));
}

struct putcommon_srv_req *
reptrans_lookup_rcvd_cache(hashtable_t *rcvd_cache, uint512_t *chid)
{
	size_t n;
	uint64_t *rval = NULL;
	struct putcommon_srv_req *hreq = NULL;
	uint512_logdump(lg, "Lookup in rcvd_cache: ", chid);
	rval = hashtable_get(rcvd_cache, chid, sizeof(uint512_t), &n);
	if (rval) {
		uint512_logdump(lg, "Found in rcvd_cache: ", chid);
		hreq = (struct putcommon_srv_req *) (*rval);
	} else
		uint512_logdump(lg, "Not Found in rcvd_cache: ", chid);

	return hreq;
}
