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

#include "ccow-impl.h"
#include "ccowd-impl.h"
#include "fastlzlib.h"
#include "gwcache.h"

struct gwcache_data {
	struct repdev *dev;
	uint64_t attrs;
	uint64_t offset;
	uint512_t chid;
	crypto_hash_t hash_type;
	uv_thread_t thread;
};

gwcache_stats_t gw_stats;
static struct gw_lru lru;

int
gw_lru_init(struct repdev *dev)
{
	assert(dev->gw_cache != 0);
	assert(lru.gl_hash == NULL);

	memset(&gw_stats, 0, sizeof(gwcache_stats_t));

	lru.gl_hash = hashtable_create(GW_LRU_TABLE_SZ, HT_KEY_CONST | HT_VALUE_CONST,
					0.001);
	if (!lru.gl_hash) {
		log_error(lg, "GW-cache Failed to create LRU");
		return -ENOMEM;
	}

	log_debug(lg, "Enter %s", __func__);
	init_list_head(&lru);
	lru.gl_max_chids = dev->bg_config->gw_cache_chids_in_mem ?
			dev->bg_config->gw_cache_chids_in_mem : DEFAULT_LRU_CHIDS;
	return 0;
}

void
gw_lru_destroy()
{
	log_debug(lg, "Enter %s", __func__);
	uv_mutex_lock(&lru.gl_mutex);
	destroy_list(&lru);

	/* If list is not empty, free all the elements */
	if (lru.gl_hash)
		hashtable_destroy(lru.gl_hash);
	memset(&gw_stats, 0, sizeof(gwcache_stats_t));
	uv_mutex_unlock(&lru.gl_mutex);
	uv_mutex_destroy(&lru.gl_mutex);
}

struct chid_node *
gw_lru_get_first_node()
{
	struct chid_node *node = NULL;
	QUEUE *q;

	if (!QUEUE_EMPTY(&lru.gl_list)) {
		q = QUEUE_HEAD(&lru.gl_list);
		node = QUEUE_DATA(q, struct chid_node, item);
	}
	return node;
}

/*
 * There is a big lock protecting hash table and a list.
 * Call this function in "done" after reply is sent back to the client
 */
void
gw_lru_update(uint512_t *chid)
{
	struct chid_node *node;
	size_t sz;
	int err;

	/* TODO: Do we need time stamp?? */
	char chidstr[UINT512_BYTES*2+1];
	uint512_dump(chid, chidstr, UINT512_BYTES*2+1);

	uv_mutex_lock(&lru.gl_mutex);
	node = hashtable_get(lru.gl_hash, chid, sizeof(uint512_t), &sz);
	if (node) {
		/* CHID in LRU. Move it to the head of list */
		move_node_to_head(&lru, node);
		gw_stats.lru_hits++;
		uv_mutex_unlock(&lru.gl_mutex);
		log_debug(lg, "CHID %s found in LRU", chidstr);
		return;
	}
	log_debug(lg, "CHID %s NOT in LRU", chidstr);

	/* New CHID. Add to head of LRU */
	gw_stats.lru_misses++;

	node = je_malloc(sizeof(*node));
	if (!node) {
		log_error(lg, "GW-cache Failed to allocate memory to update LRU");
		uv_mutex_unlock(&lru.gl_mutex);
		return;
	}
	QUEUE_INIT(&node->item);
	node->cl_chid = *chid;

	add_to_head(&lru, node);
	err = hashtable_put(lru.gl_hash, &node->cl_chid, sizeof(uint512_t),
				node, sizeof(*node));
	if (err) {
		remove_from_head(&lru);
		log_error(lg, "GW-cache Failed to add LRU entry into hashtable");
		uv_mutex_unlock(&lru.gl_mutex);
		return;
	}

	/* If there is overflow, remove the least used (tail) element */
	if (lru.gl_nr > lru.gl_max_chids) {
		gw_stats.lru_evicts++;
		remove_from_tail(&lru);
	}
	uv_mutex_unlock(&lru.gl_mutex);
}

static void
gwcachedget_populate(struct getcommon_client_req *r)
{
	struct ccow_io *io = r->io;
	struct ccow_completion *c = io->comp;
	struct gwcache_data *gwdata = (struct gwcache_data *)r->data;
	struct repdev *dev = gwdata->dev;
	char chidstr[UINT512_BYTES*2+1];

	type_tag_t tt;
	int err;

	if (c->status != 0 || !r->rb) {
		log_error(lg, "GW-cache Failed to async fetch CHID, status %d",
				c->status);
		return;
	}

	uint512_dump(&gwdata->chid, chidstr, UINT512_BYTES*2+1);
	log_debug(lg, "GW-cache trying to populate cache for CHID %s", chidstr);

	/*
	 * We update storage. But we don't update LRU. LRU is update by IO path.
	 */
	tt = attr_to_type_tag(io->attributes);
	uint64_t start_time = reptrans_get_timestamp(dev);
	err = reptrans_put_blob_with_attr(dev, tt, r->hash_type, r->rb,
					  &r->chid, 0, start_time);
	if (err != 0) {
		log_error(lg, "GW-cache put on device failed CHID %s", chidstr);
		rtbuf_destroy(r->rb);
	}

	gw_stats.populates++;
}

static void
gwcachedget_fetch_chid_done(uv_work_t *wreq, int status)
{
	if (status == 0)
		gw_stats.populates++;

	je_free(wreq);
}

extern volatile unsigned long gw_cache_throttle;

static void
gwcachedget_fetch_chid_exec(void *arg)
{
	uv_work_t *wreq = (uv_work_t*) arg;
	struct gwcache_data *gwdata = wreq->data;
	struct repdev *dev = gwdata->dev;
	char chidstr[UINT512_BYTES*2+1];
	struct ccow_op *op;
	struct ccow_io *io;
	ccow_completion_t c;
	ccow_t tc;
	int err;

	tc = reptrans_get_tenant_context(dev->rt, 0);

	if (!tc) {
		log_error(lg, "GW-cache(%s): failed to get tenant context",
				dev->name);
		return;
	}

	uint512_dump(&gwdata->chid, chidstr, UINT512_BYTES*2+1);
	log_trace(lg, "Fetching CHID %s for cache-tc %p", chidstr, tc);

	memset(&c, 0, sizeof(c));
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "GW-cache(%s): failed to create completion",
				dev->name);
		reptrans_put_tenant_context(dev->rt, tc);
		return;
	}
	err = ccow_operation_create(c, CCOW_GET, &op);
	if (err) {
		log_error(lg, "GW-cache(%s): failed to create IO op",
				dev->name);
		ccow_release(c);
		reptrans_put_tenant_context(dev->rt, tc);
		return;
	}
	op->offset = gwdata->offset;
	err = ccow_unnamedget_create(c, gwcachedget_populate, op, &io, NULL);
	if (err) {
		log_error(lg, "GW-cache(%s): failed to create GET req",
				dev->name);
		ccow_operation_destroy(op, 1);
		ccow_release(c);
		reptrans_put_tenant_context(dev->rt, tc);
		return;
	}
	struct getcommon_client_req *r = CCOW_IO_REQ(io);
	rtbuf_t *rb = NULL;

	r->chid = gwdata->chid;
	r->hash_type = gwdata->hash_type;
	r->compress_type = COMPRESSOR_DEFAULT;
	r->chunkmap_data = &rb;
	r->data = gwdata;

	assert(r->gw_cache == 0);
	r->gw_cache = 1;

	atomic_dec(&gw_cache_throttle);

	/* Allocate chunk for uncompress */
	op->chunks = rtbuf_init_alloc_one(REPLICAST_DGRAM_MAXLEN);
	memset(op->chunks->bufs[0].base, 0, op->chunks->bufs[0].len);
	if (!op->chunks) {
		log_error(lg, "GW-cache(%s): failed to allocate chunk", dev->name);
		ccow_operation_destroy(op, 1);
		ccow_release(c);
		reptrans_put_tenant_context(dev->rt, tc);
		return;
	}
	io->attributes = gwdata->attrs;

	err = ccow_start_io(io);
	if (err) {
		log_error(lg, "GW-cache(%s): failed to start GET req", dev->name);
		ccow_operation_destroy(op, 1);
		ccow_release(c);
		reptrans_put_tenant_context(dev->rt, tc);
		return;
	}
	err = ccow_wait(c, -1);
	if (err)
		log_error(lg, "GW-cache(%s): fetch CHID failed err %d",
			      dev->name, err);

	reptrans_put_tenant_context(dev->rt, tc);
	je_free(gwdata);
	je_free(wreq);
}

void
gwcachedget_fetch_chid(struct repdev *dev, uint64_t attrs, uint64_t offset,
			uint512_t *chid, crypto_hash_t hash_type)
{
	struct gwcache_data *gwdata;

	uv_work_t *wreq = je_malloc(sizeof (*wreq));
	if (!wreq) {
		log_error(lg, "GW-cache(%s): failed to allocate memory",
				dev->name);
		return;
	}

	gwdata = je_malloc(sizeof(*gwdata));
	if (!gwdata) {
		log_error(lg, "GW-cache(%s): failed to allocate memory",
				dev->name);
		je_free(wreq);
		return;
	}

	gwdata->attrs = attrs;
	gwdata->offset = offset;
	gwdata->chid = *chid;
	gwdata->hash_type = hash_type;
	gwdata->dev = dev;

	wreq->data = gwdata;

	uv_thread_create(&gwdata->thread, gwcachedget_fetch_chid_exec, wreq);
}

int
gwcache_contains_chid(uint512_t *chid)
{
	struct chid_node *node;
	size_t sz;
	int rv;

	uv_mutex_lock(&lru.gl_mutex);
	node = hashtable_get(lru.gl_hash, chid, sizeof(uint512_t), &sz);
	rv = node ? 1 : 0;
	uv_mutex_unlock(&lru.gl_mutex);

	return rv;
}
