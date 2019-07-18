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
#ifndef list_cache_h
#define list_cache_h

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
#include "skiplist.h"

#define ACTION_PUT 0
#define ACTION_DEL 1
#define LIST_CACHE_TIMEOUT_S 300
#define LIST_CACHE_CHECK 60


typedef struct list_cache_record {
	uint32_t expire_ts;
    int action;
    char *etag;
	uint64_t uvid;
	uint64_t size;
	uint64_t genid;
	uint512_t vmchid;
	int deleted;
	uint64_t inode;
	char *content_type;
} list_cache_record_t;

typedef struct list_cache {
	struct skiplist *sl;
	uv_rwlock_t lock;
	struct timespec tp;
	char cluster[MAX_ITEM_SIZE];
} list_cache_t;

typedef struct list_timeout_entry_t {
	h2o_timeout_entry_t super;
	h2o_context_t *ctx;
	list_cache_t *cache;
} list_timeout_entry_t;


extern list_timeout_entry_t list_timeout;
extern list_cache_t *list_cache;

int cache_record_ini(int action, char *etag, uint64_t uvid,
		uint64_t size, uint64_t genid, uint512_t *vmchid,  int deleted,
		uint64_t inode, char *content_type, list_cache_record_t **rec);

int cache_record_free(list_cache_record_t *rec);

char *cache_record_str(list_cache_record_t *rec, char *buf, int maxsize);

int list_cache_ini(list_cache_t **cache, char *cluster);

int list_cache_fini(list_cache_t *cache);

int list_cache_insert(list_cache_t *c, void *key, size_t key_size,
		list_cache_record_t *rec);

list_cache_record_t *list_cache_lookup(list_cache_t *c, void *key, size_t key_size);

int list_cache_list(list_cache_t *c, char *prefix, size_t prefix_size,
		char **key, char **value, int *action, int *count, int not_equal);


void list_cache_timecheck(list_cache_t *c);

void on_list_timeout(h2o_timeout_entry_t *entry);


#ifdef __cplusplus
}
#endif

#endif
