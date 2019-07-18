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
#include "ccowutil.h"
#include "list_cache.h"

#define YIELD_NUM 10

list_timeout_entry_t list_timeout;
list_cache_t *list_cache;

int
cache_record_ini(int action, char *etag, uint64_t uvid,
		uint64_t size, uint64_t genid, uint512_t *vmchid,  int deleted,
		uint64_t inode,char *content_type, list_cache_record_t **rec) {

	list_cache_record_t *r = NULL;
	if ((r = je_malloc(sizeof(*r))) == NULL)
		return -ENOMEM;

	r->expire_ts = 0;
	r->action = action;
	if (etag) {
		int len = strlen(etag) + 1;
		r->etag = je_malloc(len);
	    if (r->etag == NULL)
			return -ENOMEM;
		memcpy(r->etag, etag, len);
	} else {
		r->etag = NULL;
	}
	r->uvid = uvid;
	r->size = size;
	r->genid = genid;
	memcpy(&r->vmchid, vmchid, sizeof(r->vmchid));
	r->deleted = deleted;
	r->inode = inode;
	if (content_type) {
		int len = strlen(content_type) + 1;
		r->content_type = je_malloc(len);
	    if (r->content_type == NULL)
			return -ENOMEM;
		memcpy(r->content_type, content_type, len);
	} else {
	   r->content_type = NULL;
	}

    *rec = r;
	return 0;
}

int
cache_record_free(list_cache_record_t *rec) {
	if (rec->etag)
		je_free(rec->etag);
	if (rec->content_type)
		je_free(rec->content_type);
	if (rec)
		je_free(rec);
	return 0;
}

char *
cache_record_str(list_cache_record_t *rec, char *buf, int maxsize) {
	char str[256];
	sprintf(buf,"expire_ts: %u, action: %d, etag: %s, uvid: %lu,\n" \
			"size: %lu, genid: %lu, vmchid: %s,\n" \
			"deleted: %d, inode: %lu, content_type: %s",
			rec->expire_ts, rec->action, rec->etag, rec->uvid,
			rec->size, rec->genid, str_hash_id(&rec->vmchid, str, 64),
			rec->deleted, rec->inode, rec->content_type);

	return buf;
}


static int
keycmp(const void *ka, const size_t ka_len, const void *kb, const size_t kb_len)
{
	int diff;
	ssize_t len_diff;
	unsigned int len;

	len = ka_len;
	len_diff = (ssize_t) ka_len - (ssize_t) kb_len;
	if (len_diff > 0) {
		len = kb_len;
		len_diff = 1;
	}

	diff = memcmp(ka, kb, len);
	return diff ? diff : len_diff<0 ? -1 : len_diff;
}


void
on_list_timeout(h2o_timeout_entry_t *entry)
{
	list_timeout_entry_t *se = (list_timeout_entry_t *)entry;

	list_cache_timecheck(se->cache);

	h2o_timeout_unlink(&list_timeout.super);
	h2o_timeout_link(se->ctx->loop, &se->ctx->one_sec_timeout,
	    &list_timeout.super);
}

int
list_cache_ini(list_cache_t **cache, char *cluster)
{
	list_cache_t *new = NULL;

	if (cache == NULL)
		return -EINVAL;
	if ((new = je_malloc(sizeof(*new))) == NULL)
		return -ENOMEM;
	if (pthread_rwlock_init(&new->lock, NULL) != 0) {
		je_free(new);
		return -ENOMEM;
	}

	new->sl = msl_create(keycmp);
	clock_gettime(CLOCK_REALTIME, &new->tp);

	memcpy(new->cluster, cluster, MAX_ITEM_SIZE);

	*cache = new;
	return 0;
}

static void
free_records(struct skiplist *sl) {
	struct skiplist_iter it;
	list_cache_record_t *rec;
	size_t ksize, vsize;

	it = msl_iter_next(sl, NULL);
	while (it.v != NULL) {
		void *key = msl_iter_getk(&it, &ksize);
		rec = (list_cache_record_t *) msl_iter_getv(&it, &vsize);
		cache_record_free(rec);
		je_free(key);
		it = msl_iter_next(sl, &it);
	}
}


int
list_cache_fini(list_cache_t *cache)
{
	if (cache == NULL)
		return -EINVAL;

	pthread_rwlock_wrlock(&cache->lock);

	free_records(cache->sl);
	msl_destroy(cache->sl);

	pthread_rwlock_unlock(&cache->lock);
	pthread_rwlock_destroy(&cache->lock);
	je_free(cache);
	return 0;
}

int
list_cache_insert(list_cache_t *c, void *key, size_t key_size,
		list_cache_record_t *rec)
{
	struct timespec tp;
	char *newkey = NULL;

	if (c == NULL || rec == NULL)
		return -EINVAL;

	clock_gettime(CLOCK_REALTIME, &tp);

	pthread_rwlock_wrlock(&c->lock);

	rec->expire_ts = tp.tv_sec + LIST_CACHE_TIMEOUT_S;

	struct skiplist_iter it;

	// Search old
	msl_search(c->sl, key, key_size, &it);

	// Erase old
	if (it.v != NULL) {
		size_t ksize, vsize;
		void *k = msl_iter_getk(&it, &ksize);
		if (key_size == ksize && keycmp(key, key_size, k, ksize) == 0) {
			newkey = k;
			void *value = msl_iter_getv(&it, &vsize);
			if (vsize > 0) {
				cache_record_free((list_cache_record_t *)value);
			}
		}
	}

	if (newkey == NULL){
		newkey = je_malloc(key_size);
		if (newkey == NULL) {
			pthread_rwlock_unlock(&c->lock);
			return -ENOMEM;
		}
		memcpy(newkey, key, key_size);
	}

	// Set new
	int err = msl_set(c->sl, newkey, key_size, rec, sizeof(rec), NULL);


	pthread_rwlock_unlock(&c->lock);
	return err;
}

int
list_cache_list(list_cache_t *c, char *prefix, size_t prefix_size,
		char **key, char **value, int *action, int *count, int not_equal)
{
	char str[256];
	char buf[4096];

	if (c == NULL || *count == 0)
		return -EINVAL;

	pthread_rwlock_wrlock(&c->lock);

	struct skiplist_iter it;

	memcpy(buf, prefix, prefix_size);
	buf[prefix_size] = '\0';
	log_trace(lg, "List cache prefix: %s", buf);

	// Search old
	msl_search(c->sl, prefix, prefix_size, &it);


	char *k;
	list_cache_record_t *rec;

	int n = 0;

	while (it.v != NULL) {
		size_t ksize;
		k = msl_iter_getk(&it, &ksize);

		if (k == NULL || ksize == 0) {
			break;
		}

		if (prefix_size > 0) {
			int l = (prefix_size < ksize ? prefix_size : ksize);
			int d = strncmp(k, prefix, l);
			if (d < 0 || (not_equal && d == 0)) {
				it = msl_iter_next(c->sl, &it);
				continue;
			}
		}

		rec =  (list_cache_record_t *)msl_iter_getv(&it, NULL);
		int vsize = sprintf(buf,"%lu;%lu;%s;%s;%s;%lu;%u;%lu", rec->uvid, rec->genid,
				str_hash_id(&rec->vmchid, str, 64), rec->etag, rec->content_type,
				rec->size, rec->deleted, rec->inode);
		key[n] = je_strndup(k, ksize);
		value[n] = je_strndup(buf, vsize);
		action[n] = rec->action;

		n++;
		if (n == *count) {
			break;
		}
		it = msl_iter_next(c->sl, &it);
	}
	log_trace(lg, "List cache found: %d", n);
	*count = n;

	pthread_rwlock_unlock(&c->lock);
	return 0;
}


list_cache_record_t *
list_cache_lookup(list_cache_t *c, void *key, size_t key_size)
{
	struct skiplist_iter it;
	list_cache_record_t *rec;
	int rv = 0;

	if (c == NULL || key == NULL)
		return NULL;

	pthread_rwlock_rdlock(&c->lock);

	msl_search(c->sl, key, key_size, &it);
	rec = msl_iter_getv(&it, NULL);

	pthread_rwlock_unlock(&c->lock);

	return  rec;
}

void
list_cache_timecheck(list_cache_t *c)
{
	struct timespec tp;
	char buf[MAX_ITEM_SIZE];

	clock_gettime(CLOCK_REALTIME, &tp);

	int64_t delta = tp.tv_sec - c->tp.tv_sec;

	if (delta < LIST_CACHE_CHECK)
		return;

	clock_gettime(CLOCK_REALTIME, &c->tp);

	uint64_t trlog_ts =  trlog_marker_timestamp(c->cluster);

	if (trlog_ts == 0) {
		log_error(lg, "Could not read TRLOG marker");
		return;
	}


	pthread_rwlock_wrlock(&c->lock);

	struct skiplist_iter it;
	list_cache_record_t *rec;

	it = msl_iter_next(c->sl, NULL);

	int n = 0;
	while (it.v != NULL) {
		n++;
		size_t ksize, vsize;
		void *key = msl_iter_getk(&it, &ksize);
		void *value = msl_iter_getv(&it, &vsize);
		rec = (list_cache_record_t *)value;

		it = msl_iter_next(c->sl, &it);

		if (rec->expire_ts < trlog_ts) {
			memcpy(buf, key, ksize);
			buf[ksize] = '\0';
			msl_erase(c->sl, buf, ksize, NULL);
			cache_record_free(rec);
			je_free(key);
		}

		// Yield to the other threads
		if ((n % YIELD_NUM) == 0) {
			log_trace(lg, "Do yield");
			pthread_rwlock_unlock(&c->lock);
			pthread_yield();
			pthread_rwlock_wrlock(&c->lock);
			msl_search(c->sl, buf, ksize, &it);
		}
	}

	pthread_rwlock_unlock(&c->lock);
	log_trace(lg, "List cache check done, final size: %d", msl_count(c->sl));

}
