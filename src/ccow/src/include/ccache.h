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
#ifndef __CCACHE_H__
#define __CCACHE_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "queue.h"
#include "rtbuf.h"

typedef struct ccache_entry {
	uint512_t key;
	void *value;
	size_t val_len;
	struct ccache_entry* next;
} ccache_entry_t;

typedef void (* cc_free_val_cb_t)(void *value, size_t len, void *data);
typedef void * (* cc_copyout_cb_t)(void *value, size_t len, void *data);
typedef void * (* cc_copyin_cb_t)(void *value, size_t len, void *data);

typedef struct {
	void *private_data; /* for example, struct ccow *tc */
	uv_mutex_t pos_mutex;
	/* number of hash entries */
	ccache_entry_t *cache;
	uint32_t entries_nr;
	/* a function that will free ccache_entry_t.value */
	cc_free_val_cb_t free_val;
	/* a function that will copy ccache_entry_t.value out for cache */
	cc_copyout_cb_t copyout;
	/* a function that will copy data into cache */
	cc_copyin_cb_t copyin;
	uv_rwlock_t lock;
	/* override value instead of chaining */
	uint8_t	 override;
	/* stats */
	uint32_t hits;
	uint32_t misses;
} ccache_t;

ccache_t *ccache_create(size_t cachesz, cc_free_val_cb_t free_cb,
			cc_copyout_cb_t cout_cb, cc_copyin_cb_t cin_cb);
void ccache_free(ccache_t *cc);
int ccache_get(ccache_t *cc, uint512_t *chid, void **outval);
int ccache_put(ccache_t * cc, uint512_t * chid, void *inval);
/*
 * ccache_put2() allow to store size of value. Default ccache_put() doesn't use
 * the size cause it relies on callbacks which manage data size internally
 */
int ccache_put2(ccache_t * cc, uint512_t * chid, void *inval, size_t size);
/*
 * The ccache support 2 modes: overridde and chaining.
 * 1. override mode (default).
 * 	Cache entry is overridden in case of a hash ID collision
 * 2. chaining mode.
 * 	The collision is resolved by chaining entries which have equal hash ID.
 */
void ccache_set_override(ccache_t *cc, uint8_t override);

static void
cc_rt_free_cb(void *value, size_t len, void *data)
{
	rtbuf_destroy((rtbuf_t *)value);
}

static void *
cc_rt_copyout_cb(void *value, size_t len, void *data)
{
	return (void *) rtbuf_clone((rtbuf_t *)value);
}

static void *
cc_rt_copyin_cb(void *value, size_t len, void *data)
{
	return (void *) rtbuf_clone((rtbuf_t *)value);
}

int
ccache_has(ccache_t *cc, uint512_t *chid);

#ifdef	__cplusplus
}
#endif

#endif
