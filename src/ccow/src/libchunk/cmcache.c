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
#include <errno.h>
#include "ccowutil.h"
#include "ccow-impl.h"
#include "ccow.h"
#include "queue.h"
#include "cmcache.h"

/*
 * Evict items from CMCACHE.
 *
 * Scope private.
 */
static void
ccow_cmcache_evict(cmcache_t *cmc, uint64_t count)
{
	struct ccow *tc = cmc->tc;
	nassert(tc->loop_thrid == uv_thread_self());

	uint64_t rem = count;

	QUEUE * ent;
	cmcache_entry_t * itm;

	if (cmc->cmc_lru_count > tc->cmcache_lru_lowat) {
		while (!QUEUE_EMPTY(&cmc->cmc_lru_q)) {

			if ((cmc->cmc_lru_count < tc->cmcache_lru_hiwat) &&
			    (rem == 0)) {
				break;
			}

			QUEUE * ent = QUEUE_NEXT(&cmc->cmc_lru_q);
			itm = QUEUE_DATA(ent, cmcache_entry_t, cmc_lru_link);

			QUEUE_REMOVE(ent);
			QUEUE_REMOVE(&itm->cmc_col_link);

			cmc->cmc_lru_count--;
			tc->stats.cmcache.cmc_lru_count = cmc->cmc_lru_count;
			tc->stats.cmcache.cmc_evicts++;

			if (itm->value) {
				tc->stats.cmcache.cmc_size -= rtbuf_len(itm->value);
				rtbuf_flat_destroy(itm->value);
				itm->value = NULL;
			}
			je_free(itm);

			if (rem > 0) {
				rem--;
			}
		}
	}

}

/*
 * CMCACHE timer close callback.
 *
 * Scope: PRIVATE
 */
static void
ccow_cmcache_timer_close_cb(uv_handle_t* handle)
{
	struct ccow * tc = handle->data;

	je_free(handle);
}

/*
 * CMCACHE timer callback.
 *
 * Scope: PRIVATE
 */
static void
ccow_cmcache_timer_cb(uv_timer_t* handle, int status)
{
	struct ccow * tc = handle->data;
	nassert(tc->loop_thrid == uv_thread_self());

	cmcache_t * cmc = tc->cmcache;

	size_t used = tc->stats.ucache.total_ram - tc->stats.ucache.free_ram;
	int cmcache_too_big = (tc->stats.ucache.mem_limit &&
	    tc->stats.cmcache.cmc_size >= tc->stats.ucache.mem_limit);

	if (used >= tc->stats.ucache.ucsize_lim || cmcache_too_big) {
		ccow_cmcache_evict(cmc, CMCACHE_EVICT_CNT_HI);
	} else {
		ccow_cmcache_evict(cmc, CMCACHE_EVICT_CNT_LOW);
	}
}

/*
 * Initialize memory of Chunk Manifest cache
 *
 * Scope: PRIVATE
 */
cmcache_t *
ccow_cmcache_create(struct ccow* tc)
{
	int err;

	nassert(tc->loop_thrid == uv_thread_self());

	cmcache_t *cmc = je_calloc(1, sizeof (cmcache_t));
	if (cmc == NULL) {
		log_error(lg, "Memory allocation failure.");
		goto _err_exit;
	}

	log_info(lg, "Creating tenant cmcache hash size of %lu",
	    tc->cmcache_hash_size);

	cmc->cache = je_calloc(tc->cmcache_hash_size, sizeof (cmcache_hdr_t));
	if (cmc->cache == NULL) {
		log_error(lg, "Memory allocation failure.");
		goto _err_exit;
	}

	cmc->cmc_lru_count = 0;
	tc->stats.cmcache.cmc_lru_count = 0;
	tc->stats.cmcache.cmc_lru_max = 0;

	QUEUE_INIT(&cmc->cmc_lru_q);

	cmc->cmc_timer_req = je_malloc(sizeof (*cmc->cmc_timer_req));
	if (cmc->cmc_timer_req == NULL) {
		log_error(lg, "Memory allocation failure.");
		goto _err_exit;
	}

	cmc->tc = tc;

	err = uv_timer_init(tc->loop, cmc->cmc_timer_req);
	if (err != 0) {
		log_error(lg, "uv_timer_init returned error \"%s\"", strerror(errno));
		goto _err_exit;
	}

	cmc->cmc_timer_req->data = tc;

	err = uv_timer_start(cmc->cmc_timer_req, ccow_cmcache_timer_cb,
	    tc->cmcache_timer_timeout, tc->cmcache_timer_repeat);
	if (err != 0) {
		log_error(lg, "uv_timer_start returned error \"%s\"", strerror(errno));
		goto _err_exit;
	}

	tc->stats.cmcache.cmc_hash_size = tc->cmcache_hash_size;
	tc->stats.cmcache.cmc_lru_hiwat   = tc->cmcache_lru_hiwat;
	tc->stats.cmcache.cmc_lru_lowat = tc->cmcache_lru_lowat;

	return cmc;

_err_exit:
	if (cmc != NULL) {

		if (cmc->cmc_timer_req != NULL) {
			je_free(cmc->cmc_timer_req);
		}

		if (cmc->cache != NULL) {
			je_free(cmc->cache);
			cmc->cache = NULL;
		}

		je_free(cmc);
		cmc = NULL;
	}

	return NULL;
}

/*
 * Insert reflist into Chunk Manifest cache
 *
 * Scope: private
 */
void
ccow_cmcache_put(cmcache_t * cmc, uint512_t * chid, rtbuf_t * rt)
{
	uint32_t hv = 0;

	assert(cmc != NULL);
	assert(chid != NULL);

	struct ccow *tc = cmc->tc;

	nassert(tc->loop_thrid == uv_thread_self());

	/* position in cache */
	FNV_hash(chid, sizeof (uint512_t), global_seed, &hv);
	int i = hv % tc->cmcache_hash_size;

	/*
	 * don't add to cache if memory limits exceeded.
	 */
	size_t used = tc->stats.ucache.total_ram - tc->stats.ucache.free_ram;
	int cmcache_too_big = (tc->stats.ucache.mem_limit &&
	    tc->stats.cmcache.cmc_size >= tc->stats.ucache.mem_limit);

	if (used >= tc->stats.ucache.ucsize_lim || cmcache_too_big) {
		ccow_cmcache_evict(cmc, CMCACHE_EVICT_CNT_HI);
		return;
	}

	if (cmc->cache[i].cmc_col_count == 0) {
		/* empty cache header, initialize the collision queue */
		QUEUE_INIT(&cmc->cache[i].hdr);
	}

	QUEUE * ent;
	cmcache_entry_t * itm;

	QUEUE_FOREACH(ent, &cmc->cache[i].hdr) {
		itm = QUEUE_DATA(ent, cmcache_entry_t, cmc_col_link);

		if (uint512_cmp(&itm->key, chid) == 0) {

			if (rt) {
				/* hot chunk, move it to the tail */
				QUEUE_REMOVE(&itm->cmc_lru_link);
				QUEUE_INSERT_TAIL(&cmc->cmc_lru_q, &itm->cmc_lru_link);

				tc->stats.cmcache.cmc_put_hits++;
			} else {
				/* overwrite evict */
				QUEUE_REMOVE(&itm->cmc_col_link);
				QUEUE_REMOVE(&itm->cmc_lru_link);
				cmc->cmc_lru_count--;
				tc->stats.cmcache.cmc_lru_count = cmc->cmc_lru_count;
				tc->stats.cmcache.cmc_overwr_evicts++;

				if (itm->value) {
					tc->stats.cmcache.cmc_size -= rtbuf_len(itm->value);
					rtbuf_flat_destroy(itm->value);
					itm->value = NULL;
				}
				je_free(itm);
			}

			return;
		}
	}

	tc->stats.cmcache.cmc_put_misses++;

	itm = je_calloc(1, sizeof(cmcache_entry_t));
	if (itm == NULL) {
		log_debug(lg, "Memory allocation error");
		return;
	}

	size_t total_len;
	itm->value = rtbuf_flat(rt, &total_len);
	if (!itm->value) {
		je_free(itm);
		log_debug(lg, "Memory allocation error");
		return;
	}

	/* put new in place */
	QUEUE_INSERT_TAIL(&cmc->cmc_lru_q, &itm->cmc_lru_link);
	cmc->cmc_lru_count++;
	tc->stats.cmcache.cmc_lru_count = cmc->cmc_lru_count;
	if (cmc->cmc_lru_count > tc->stats.cmcache.cmc_lru_max) {
		tc->stats.cmcache.cmc_lru_max = cmc->cmc_lru_count;
	}

	QUEUE_INSERT_HEAD(&cmc->cache[i].hdr, &itm->cmc_col_link);
	cmc->cache[i].cmc_col_count++;

	memcpy(&itm->key, chid, sizeof(uint512_t));

	tc->stats.cmcache.cmc_size += total_len;
	if (tc->stats.cmcache.cmc_size > tc->stats.cmcache.cmc_size_max) {
		tc->stats.cmcache.cmc_size_max = tc->stats.cmcache.cmc_size;
	}
}

/*
 * Get reflist from cmcache
 *
 * Scope: private
 */
int
ccow_cmcache_get(cmcache_t *cmc, uint512_t *chid, rtbuf_t ** rl)
{
	uint32_t hv;
	*rl = NULL;

	assert(cmc != NULL);
	assert(chid != NULL);
	assert(rl != NULL);

	struct ccow *tc = cmc->tc;

	nassert(tc->loop_thrid == uv_thread_self());

	/* position in cache */
	FNV_hash(chid, sizeof (uint512_t), global_seed, &hv);
	int i = hv % tc->cmcache_hash_size;

	QUEUE * ent;
	cmcache_entry_t * itm;

	if (cmc->cmc_lru_count == 0) {
		QUEUE_INIT(&cmc->cmc_lru_q);
	}

	if (cmc->cache[i].cmc_col_count == 0) {
		QUEUE_INIT(&cmc->cache[i].hdr);
	}

	QUEUE_FOREACH(ent, &cmc->cache[i].hdr) {
		itm = QUEUE_DATA(ent, cmcache_entry_t, cmc_col_link);

		if (itm->value && uint512_cmp(&itm->key, chid) == 0) {
			/* hit */
			tc->stats.cmcache.cmc_hits++;

			*rl = rtbuf_clone_bufs(itm->value);
			return *rl != NULL;
		}
	}

	/* miss */
	tc->stats.cmcache.cmc_misses++;
	return 0;
}

void
ccow_cmcache_free(cmcache_t *cmc)
{
	struct ccow *tc = cmc->tc;
	nassert(tc->loop_thrid == uv_thread_self());

	if (cmc->cmc_timer_req != NULL) {
		uv_timer_stop(cmc->cmc_timer_req);
		uv_close((uv_handle_t *) cmc->cmc_timer_req, ccow_cmcache_timer_close_cb);
	}

	QUEUE * ent;
	cmcache_entry_t * itm;

	if (cmc->cmc_lru_count > 0) {
		while (!QUEUE_EMPTY(&cmc->cmc_lru_q)) {
			QUEUE * ent = QUEUE_NEXT(&cmc->cmc_lru_q);
			itm = QUEUE_DATA(ent, cmcache_entry_t, cmc_lru_link);

			QUEUE_REMOVE(ent);
			QUEUE_REMOVE(&itm->cmc_col_link);

			cmc->cmc_lru_count--;
			tc->stats.cmcache.cmc_lru_count = cmc->cmc_lru_count;

			if (itm->value) {
				tc->stats.cmcache.cmc_size -= rtbuf_len(itm->value);
				rtbuf_flat_destroy(itm->value);
				itm->value = NULL;
			}
			je_free(itm);
		}
	}

	je_free(cmc->cache);
	je_free(cmc);
}

