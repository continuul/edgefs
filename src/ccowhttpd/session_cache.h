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
#ifndef session_cache_h
#define session_cache_h

#ifdef __cplusplus
extern "C" {
#endif

#include "uthash.h"
#include "ccowutil.h"
#include "ccow.h"
#include "h2o.h"
#include "param.h"
#include "session.h"
#include "ccowobj.h"


#define STRSESS_CACHE_NUM	4096
#define STRSESS_CACHE_TIMEOUT_S 30

typedef struct strsess_cache_entry {
	uint64_t sid;
	uint32_t expire_ts;
	UT_hash_handle hh;
	session_t *ss;
} strsess_cache_entry_t;

typedef struct strsess_cache_stat {
    uint32_t hit;
    uint32_t miss;
    uint32_t evicted;
} strsess_cache_stat_t;

typedef struct strsess_cache {
	uint32_t c; // capacity
	strsess_cache_entry_t *entries;
	uv_rwlock_t lock;
	strsess_cache_stat_t stats;
	void (*free_entry) (strsess_cache_entry_t *); //cb to free items; optional
} strsess_cache_t;

typedef struct strsess_timeout_entry_t {
	h2o_timeout_entry_t super;
	h2o_context_t *ctx;
	strsess_cache_t *cache;
} strsess_timeout_entry_t;

extern strsess_timeout_entry_t strsess_timeout;
extern strsess_cache_t *sess_cache;

#define STRSESS_KEY_SET(_hv, _ts) \
	((((uint64_t)_hv) << 32) | ((uint32_t)_ts))
#define STRSESS_KEY_TS(_key) \
	((uint32_t)_key)

int strsess_cache_ini(strsess_cache_t **cache, const uint32_t c,
			  void (*free_entry)(strsess_cache_entry_t *));

int strsess_cache_fini(strsess_cache_t *cache);

int strsess_cache_insert(strsess_cache_t *c, uint32_t expire_ts, strsess_cache_entry_t **entry);

int strsess_cache_lookup(strsess_cache_t *c, uint64_t *sid, strsess_cache_entry_t **entry);

int strsess_cache_remove(strsess_cache_t *c, uint64_t *sid);

void strsess_cache_timecheck(strsess_cache_t *c);

void on_strsess_timeout(h2o_timeout_entry_t *entry);

void on_strsess_evict(strsess_cache_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif
