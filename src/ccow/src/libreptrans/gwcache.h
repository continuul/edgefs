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

#ifndef _GECACHE_H__
#define _GECACHE_H__

#include <uv.h>
#include <hashtable.h>
#include "queue.h"
#include "reptrans.h"

#define GW_LRU_TABLE_SZ	1024
#define DEFAULT_LRU_CHIDS	1024*1024

struct chid_node {
	QUEUE item;
	uint512_t cl_chid;
	uint64_t cl_ts;
};

struct gw_lru {
	QUEUE		gl_list;
	hashtable_t	*gl_hash;
	uv_mutex_t	gl_mutex;
	int64_t		gl_nr;	/* To catch underflow due to bugs */
	int64_t		gl_max_chids;
};

typedef struct _gwcache_stats_ {
	// stats
	uint64_t lru_hits;
	uint64_t lru_misses;
	uint64_t lru_evicts;
	uint64_t populates;
	uint64_t evicts;
	uint64_t hits;
	uint64_t misses;

} gwcache_stats_t;

static inline void
init_node(struct chid_node *node)
{
	QUEUE_INIT(&node->item);
}

static inline int
is_list_empty(struct chid_node *node)
{
	return QUEUE_EMPTY(&node->item);
}

static inline void
init_list_head(struct gw_lru *lru)
{
	QUEUE_INIT(&lru->gl_list);
	uv_mutex_init(&lru->gl_mutex);
	lru->gl_nr = 0L;
}

static inline void
destroy_list(struct gw_lru *lru)
{
	struct chid_node *node;
	QUEUE *q;

	while (!QUEUE_EMPTY(&lru->gl_list)) {
		q = QUEUE_HEAD(&lru->gl_list);
		node = QUEUE_DATA(q, struct chid_node, item);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		je_free(node);
	}
}

static inline void
add_node_before(struct chid_node *node, struct chid_node *new)
{
	QUEUE_ADD(&new->item, &node->item);
}

static inline void
add_node_after(struct chid_node *node, struct chid_node *new)
{
	QUEUE_ADD(&node->item, &new->item);
}

static inline void
remove_node(struct chid_node *node)
{
	QUEUE_REMOVE(&node->item);
}

static inline void
add_to_head(struct gw_lru *lru, struct chid_node *node)
{
	QUEUE_INSERT_HEAD(&lru->gl_list, &node->item);
	lru->gl_nr++;
}

static inline void
add_to_tail(struct gw_lru *lru, struct chid_node *node)
{
	QUEUE_INSERT_TAIL(&lru->gl_list, &node->item);
	lru->gl_nr++;
}

static inline void
remove_from_head(struct gw_lru *lru)
{
	QUEUE *q;

	q = QUEUE_HEAD(&lru->gl_list);
	if (!q) {
		QUEUE_REMOVE(q);
		struct chid_node *node = QUEUE_DATA(q, struct chid_node, item);
		je_free(node);
		lru->gl_nr--;
		assert(lru->gl_nr >= 0);
	}
}

static inline void
move_node_to_head(struct gw_lru *lru, struct chid_node *node)
{
	remove_node(node);
	add_to_head(lru, node);
}

static inline void
remove_from_tail(struct gw_lru *lru)
{
	QUEUE *q;

	q = QUEUE_HEAD(&lru->gl_list);
	if (!q) {
		QUEUE_REMOVE(q);
		struct chid_node *node = QUEUE_DATA(q, struct chid_node, item);
		je_free(node);
		lru->gl_nr--;
		assert(lru->gl_nr >= 0);
	}
}

void gwcachedget_fetch_chid(struct repdev *dev, uint64_t attrs, uint64_t offset,
				uint512_t *chid, crypto_hash_t hash_type);

void gw_lru_update(uint512_t *chid);
int gw_lru_init(struct repdev *dev);
void gw_lru_destroy();
struct chid_node *gw_lru_get_first_node();
int gwcache_contains_chid(uint512_t *chid);
#endif
