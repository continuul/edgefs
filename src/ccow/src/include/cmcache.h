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
#ifndef __CMCACHE_H__
#define __CMCACHE_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "queue.h"
#include "rtbuf.h"

#define CMCACHE_HASH_SIZE	16*1024
#define CMCACHE_HASH_SIZE_MAX	1024*1024

#define CMCACHE_TIMER_TIMEOUT	5000
#define CMCACHE_TIMER_REPEAT	3000

#define CMCACHE_EVICT_CNT_HI	   3
#define CMCACHE_EVICT_CNT_LOW	   1

struct ccow;
typedef struct ccow *ccow_t;

typedef struct {
	uint512_t key;
	rtbuf_t *value;

	QUEUE cmc_col_link;				// collision link
	QUEUE cmc_lru_link;				// lru link
} cmcache_entry_t;

typedef struct {
	uint64_t cmc_col_count;
	QUEUE hdr;
} cmcache_hdr_t;

typedef struct {
	struct ccow *tc;
	cmcache_hdr_t *cache;
	uv_timer_t *cmc_timer_req;

	uint64_t cmc_lru_count;
	QUEUE cmc_lru_q;
} cmcache_t;

cmcache_t * ccow_cmcache_create(struct ccow *tc);

void ccow_cmcache_free(cmcache_t *cm);

struct refentry;

void ccow_cmcache_put(cmcache_t *cmc, uint512_t *chid, rtbuf_t * rl);
int  ccow_cmcache_get(cmcache_t *cmc, uint512_t *chid, rtbuf_t ** rl);

#ifdef	__cplusplus
}
#endif

#endif
