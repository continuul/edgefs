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
#ifndef _SKIPLIST_H
#define _SKIPLIST_H

#ifdef __cplusplus
extern "C" {
#endif

struct skiplist;
struct skiplist_node;

struct skiplist_iter {
    struct skiplist_node *v;
};

typedef int (*msl_keycmp_t)(const void *ka, const size_t ka_len,
    const void *kb, const size_t kb_len);

struct skiplist *msl_create(msl_keycmp_t keycmp);
void msl_destroy(struct skiplist *msl);
void msl_destroy_free(struct skiplist *msl);

int msl_set(struct skiplist *msl, const void *key, const size_t key_size,
    const void *value, const size_t value_size, struct skiplist_iter *it);
void *msl_get(struct skiplist *msl, const void *key, const size_t key_size,
    size_t *value_size);
void *msl_erase(struct skiplist *msl, const void *key, const size_t key_size,
	void **old_key);
struct skiplist_iter msl_iter_next(struct skiplist *msl, struct skiplist_iter *it);
void *msl_iter_getk(struct skiplist_iter *it, size_t *ksize);
void *msl_iter_getv(struct skiplist_iter *it, size_t *vsize);
void msl_debug(struct skiplist *msl, int do_hash);
int msl_count(struct skiplist *msl);
int msl_iter_getf(struct skiplist_iter *it);
int msl_iter_setf(struct skiplist_iter *it, int newflag);

void
msl_search(struct skiplist *msl, const void *key, const size_t key_size,
		struct skiplist_iter *it);


#ifdef __cplusplus
}
#endif

#endif
