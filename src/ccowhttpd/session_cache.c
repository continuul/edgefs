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
#include <sys/types.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "session_cache.h"

strsess_timeout_entry_t strsess_timeout;
strsess_cache_t *sess_cache;


void
on_strsess_timeout(h2o_timeout_entry_t *entry)
{
	strsess_timeout_entry_t *se = (strsess_timeout_entry_t *)entry;

	strsess_cache_timecheck(se->cache);

	h2o_timeout_unlink(&strsess_timeout.super);
	h2o_timeout_link(se->ctx->loop, &se->ctx->one_sec_timeout,
	    &strsess_timeout.super);
}

void
on_strsess_evict(strsess_cache_entry_t *entry)
{
	log_trace(lg, "evict call");
	if (entry->ss) {
		log_trace(lg, "evict session: %lu", entry->ss->sid);
		session_close(entry->ss);
		session_destroy(entry->ss);
	}
}

int
strsess_cache_ini(strsess_cache_t **cache, const uint32_t c,
			  void (*free_entry)(strsess_cache_entry_t *))
{
	assert(c != 0);
	strsess_cache_t *new = NULL;

	if (cache == NULL)
		return -EINVAL;
	if ((new = je_malloc(sizeof(*new))) == NULL)
		return -ENOMEM;
	if (pthread_rwlock_init(&new->lock, NULL) != 0) {
		je_free(new);
		return -ENOMEM;
	}

	new->c = c;
	new->entries = NULL;
	new->free_entry = free_entry;
	new->stats.hit = 0;
	new->stats.miss = 0;
	new->stats.evicted = 0;
	log_trace(lg, "new cache %p created", new);
	*cache = new;
	return 0;
}

int
strsess_cache_fini(strsess_cache_t *cache)
{
	strsess_cache_entry_t *entry, *tmp = NULL;

	if (cache == NULL)
		return -EINVAL;

	pthread_rwlock_wrlock(&cache->lock);

	HASH_ITER(hh, cache->entries, entry, tmp) {
		if (cache->free_entry)
			cache->free_entry(entry);
		HASH_DEL(cache->entries, entry);
		je_free(entry);
	}

	pthread_rwlock_unlock(&cache->lock);
	pthread_rwlock_destroy(&cache->lock);
	log_trace(lg, "cache %p destroyed", cache);
	je_free(cache);
	return 0;
}

int
strsess_cache_insert(strsess_cache_t *c, uint32_t expire_ts, strsess_cache_entry_t **entry)
{
	strsess_cache_entry_t *t = NULL;
	strsess_cache_entry_t *e = NULL;
	uint64_t newkey;
	struct timespec tp;

	if (c == NULL)
		return -EINVAL;

	(void)clock_gettime(CLOCK_REALTIME, &tp);

	uint32_t hv;
	uint32_t hvkey = tp.tv_nsec + rand();
	FNV_hash(&hvkey, sizeof (uint32_t), 2166136261UL, &hv);
	newkey = STRSESS_KEY_SET(hv, tp.tv_sec + expire_ts);

	uint64_t *sid = &newkey;
	pthread_rwlock_wrlock(&c->lock);
	HASH_FIND_INT64(c->entries, sid, t);

	if (t != NULL) {
		pthread_rwlock_unlock(&c->lock);
		return -EEXIST;
	}

	if ((e = je_malloc(sizeof(*e))) == NULL) {
		pthread_rwlock_unlock(&c->lock);
		return -ENOMEM;
	}

	e->sid = *sid;
	e->expire_ts = tp.tv_sec + expire_ts;
	*entry = e;

	HASH_ADD_INT64(c->entries, sid, e);

	if (HASH_COUNT(c->entries) >= c->c) {
		HASH_ITER(hh, c->entries, e, t) {
			if (c->free_entry)
				c->free_entry(e);
			HASH_DELETE(hh, c->entries, e);
			je_free(e);
			c->stats.evicted++;
			break;
		}
	}
	pthread_rwlock_unlock(&c->lock);
	return 0;
}

int
strsess_cache_lookup(strsess_cache_t *c, uint64_t *sid, strsess_cache_entry_t **entry)
{
	strsess_cache_entry_t *e = NULL;
	int rv = 0;
	struct timespec tp;

	if (c == NULL || sid == NULL)
		return -EINVAL;

	pthread_rwlock_rdlock(&c->lock);
	HASH_FIND_INT64(c->entries, sid, e);

	if (e != NULL) {
		(void)clock_gettime(CLOCK_REALTIME, &tp);
		/* LRUing by deleting and re-inserting it to head */
		pthread_rwlock_unlock(&c->lock);
		pthread_rwlock_wrlock(&c->lock);
		HASH_DELETE(hh, c->entries, e);
		e->expire_ts = tp.tv_sec + STRSESS_CACHE_TIMEOUT_S;
		HASH_ADD_INT64(c->entries, sid, e);
		/* because of macro magic */
		c->stats.hit++;
		*entry = e;
	} else {
		c->stats.miss++;
		rv = -ENOENT;
	}

	pthread_rwlock_unlock(&c->lock);
	return rv;
}

int
strsess_cache_remove(strsess_cache_t *c, uint64_t *sid)
{
	strsess_cache_entry_t *e = NULL;
	int rc = 0;

	if (c == NULL)
		return -EINVAL;

	pthread_rwlock_wrlock(&c->lock);
	HASH_FIND_INT64(c->entries, sid, e);

	if (e != NULL) {
		if (c->free_entry)
			c->free_entry(e);
		HASH_DELETE(hh, c->entries, e);
		je_free(e);
	} else {
		rc = -ENOENT;
	}
	pthread_rwlock_unlock(&c->lock);
	return rc;
}

void
strsess_cache_timecheck(strsess_cache_t *c)
{
	strsess_cache_entry_t *entry, *e;
	struct timespec tp;

	(void)clock_gettime(CLOCK_REALTIME, &tp);

	pthread_rwlock_wrlock(&c->lock);
	HASH_ITER(hh, c->entries, entry, e) {
		if (entry->expire_ts >= tp.tv_sec)
			continue;
		log_trace(lg, "sid: %lu, entry->expire_ts: %u, ts: %lu",
				entry->sid, entry->expire_ts, tp.tv_sec);
		if (c->free_entry) {
			pthread_rwlock_unlock(&c->lock);
			c->free_entry(entry);
			pthread_rwlock_wrlock(&c->lock);
		}
		HASH_DELETE(hh, c->entries, entry);
		je_free(entry);
	}
	pthread_rwlock_unlock(&c->lock);
}
