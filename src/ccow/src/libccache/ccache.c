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
#include "hashtable.h"
#include "ccowutil.h"
#include "queue.h"
#include "ccache.h"

ccache_t *
ccache_create(size_t cachesz, cc_free_val_cb_t free_cb,
	cc_copyout_cb_t copyout_cb, cc_copyin_cb_t copyin_cb)
{
	ccache_t *cc = je_calloc(1, sizeof (ccache_t));
	if (!cc)
		return NULL;
	log_info(lg, "Creating ccache size of %lu", cachesz);
	cc->cache = je_calloc(cachesz, sizeof (ccache_entry_t));
	if (!cc->cache) {
		je_free(cc);
		return NULL;
	}
	uv_rwlock_init(&cc->lock);
	cc->entries_nr = cachesz;
	cc->free_val = free_cb;
	cc->copyout = copyout_cb;
	cc->copyin = copyin_cb;
	cc->override = 1;
	return cc;
}

void
ccache_set_override(ccache_t *cc, uint8_t override) {
	cc->override = override;
}

static void
ccache_remove_r(ccache_t *cc, ccache_entry_t* entry, uint8_t first) {
	if (entry->next)
		ccache_remove_r(cc, entry->next, 0);
	entry->next = NULL;
	if (cc->free_val)
		cc->free_val(entry->value, entry->val_len, cc->private_data);
	else
		je_free(entry->value);

	if (!first)
		je_free(entry);
}

void
ccache_free(ccache_t *cc) {
	if (cc == NULL)
		return;
	uv_rwlock_wrlock(&cc->lock);
	for (size_t i = 0; i < cc->entries_nr; i++)
		if (cc->cache[i].value)
			ccache_remove_r(cc, cc->cache + i, 1);
	uv_rwlock_wrunlock(&cc->lock);
	uv_rwlock_destroy(&cc->lock);
	je_free(cc->cache);
	je_free(cc);
}

static ccache_entry_t*
ccache_lookup_r(const uint512_t *chid, ccache_entry_t* entry) {
	assert(chid);
	assert(entry);
	if (!uint512_cmp(chid, &entry->key))
		return entry;
	else if (entry->next)
		return ccache_lookup_r(chid, entry->next);
	else
		return NULL;
}

int
ccache_get(ccache_t *cc, uint512_t *chid, void **outval)
{
	uint32_t hv;
	ccache_entry_t* e = NULL;
	assert(cc != NULL);
	assert(chid != NULL);
	assert(outval != NULL);

	/* position in cache */
	FNV_hash(chid, sizeof (uint512_t), global_seed, &hv);
	uint32_t i = hv % cc->entries_nr;
	uv_rwlock_rdlock(&cc->lock);

	if (cc->cache[i].value) {
		e = ccache_lookup_r(chid, cc->cache + i);
		if (e) {
			*outval = cc->copyout ? cc->copyout(e->value,
				e->val_len, cc->private_data) :
				cc->cache[i].value;
		}
	}
	if (e)
		cc->hits++;
	else
		cc->misses++;
	uv_rwlock_rdunlock(&cc->lock);
	return e != NULL;
}

int
ccache_has(ccache_t *cc, uint512_t *chid)
{
	uint32_t hv;
	ccache_entry_t* e = NULL;
	assert(cc != NULL);
	assert(chid != NULL);

	/* position in cache */
	FNV_hash(chid, sizeof (uint512_t), global_seed, &hv);
	uint32_t i = hv % cc->entries_nr;
	uv_rwlock_rdlock(&cc->lock);

	if (cc->cache[i].value)
		e = ccache_lookup_r(chid, cc->cache + i);
	uv_rwlock_rdunlock(&cc->lock);

	return e != NULL;
}

static int
ccache_insert_r(ccache_t* cc, uint512_t* chid, ccache_entry_t* e,
	void* value, size_t len) {
	int rc = 0;
	if (!e->value || cc->override) {
		if (e->value) {
			if (cc->free_val)
				cc->free_val(e->value, e->val_len,
					cc->private_data);
			else
				je_free(e->value);
		}
		memcpy(&e->key, chid, sizeof(uint512_t));
		if (cc->copyin) {
			e->value = cc->copyin(value, len, cc->private_data);
			if (!e->value)
				rc = -ENOMEM;
			e->val_len = len;
		} else {
			e->value = value;
			e->val_len = len;
		}
	} else {
		if (!uint512_cmp(chid, &e->key))
			rc = -EEXIST;
		else if (e->next)
			rc = ccache_insert_r(cc, chid, e->next, value, len);
		else {
			e->next = je_calloc(1, sizeof(ccache_entry_t));
			if (!e->next)
				rc = -ENOMEM;
			else
				rc = ccache_insert_r(cc, chid, e->next, value, len);
		}
	}
	return rc;
}

int
ccache_put2(ccache_t * cc, uint512_t * chid, void *inval, size_t size)
{
	uint32_t hv = 0;

	assert(cc != NULL);
	assert(chid != NULL);
	assert(inval != NULL);
	int err = 0;

	/* position in cache */
	FNV_hash(chid, sizeof (uint512_t), global_seed, &hv);
	uint32_t i = hv % cc->entries_nr;
	uv_rwlock_wrlock(&cc->lock);
	err = ccache_insert_r(cc, chid, cc->cache + i, inval, size);
	uv_rwlock_wrunlock(&cc->lock);
	return err;
}

int
ccache_put(ccache_t * cc, uint512_t * chid, void *inval)
{
	return ccache_put2(cc, chid, inval, 0);
}

