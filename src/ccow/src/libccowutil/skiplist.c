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
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include "ccowutil.h"
#include "logger.h"
#include "skiplist.h"

#define RANDOM_MAX 10
#define RANDOM_THRESHOLD 5
#define MAX_HEIGHT 16

struct skiplist_node {
	const void *key;
	size_t key_size;
	const void *value;
	size_t value_size;
	int flag;

	struct skiplist_node *next[MAX_HEIGHT];
};

struct skiplist {
	struct skiplist_node head;
	int level;
	int count;
	msl_keycmp_t keycmp;
};

struct skiplist *
msl_create(msl_keycmp_t keycmp)
{
	struct skiplist *msl = (struct skiplist *)je_calloc(1,
	    sizeof (struct skiplist));
	if (msl == NULL) {
		return NULL;
	}

	msl->keycmp = keycmp;
	srand(time(NULL));

	return msl;
}

void
msl_destroy(struct skiplist *msl)
{
	if (msl == NULL) {
		return;
	}

	struct skiplist_node *ph = &msl->head;
	while (ph->next[0] != NULL) {
		struct skiplist_node *next = ph->next[0]->next[0];
		je_free(ph->next[0]);
		ph->next[0] = next;
	}

	je_free(msl);
}

void
msl_destroy_free(struct skiplist *msl)
{
	if (msl == NULL) {
		return;
	}

	struct skiplist_node *ph = &msl->head;
	while (ph->next[0] != NULL) {
		struct skiplist_node *next = ph->next[0]->next[0];
		if (ph->next[0]->key)
			je_free((void *)ph->next[0]->key);
		if (ph->next[0]->value)
			je_free((void *)ph->next[0]->value);
		je_free(ph->next[0]);
		ph->next[0] = next;
	}

	je_free(msl);
}

static struct skiplist_node *
find_prev(struct skiplist *msl, const void *key, const size_t key_size,
    struct skiplist_node *prevs[])
{
	assert(msl != NULL);
	assert(key != NULL);

	struct skiplist_node *ph = &msl->head;
	int level;
	for (level = msl->level; level >= 0; level--) {
		while (ph->next[level] != NULL
		    && msl->keycmp(ph->next[level]->key, ph->next[level]->key_size,
			    key, key_size) < 0) {
			ph = ph->next[level];
		}
		if (prevs != NULL) {
			prevs[level] = ph;
		}
	}

	return ph;
}

void
msl_search(struct skiplist *msl, const void *key, const size_t key_size,
		struct skiplist_iter *it)
{
	if (msl == NULL || key == NULL) {
		it->v = NULL;
		return;
	}

	struct skiplist_node *prevs[MAX_HEIGHT];
	it->v = find_prev(msl, key, key_size, prevs);

	if (it->v == NULL)
		return;

	size_t ksize;
	char *k = msl_iter_getk(it, &ksize);
	if (k == NULL || ksize == 0) {
		*it = msl_iter_next(msl, it);
		return;
	}

	int len = (key_size < ksize ? key_size : ksize);
	if (strncmp(k, key, len) < 0) {
		*it = msl_iter_next(msl, it);
	}

	return;
}

static int
pick_level()
{
	int level = 0;
	while (rand() % RANDOM_MAX < RANDOM_THRESHOLD
	    && level < MAX_HEIGHT - 1) {
		level++;
	}

	return level;
}

int
msl_set(struct skiplist *msl, const void *key, const size_t key_size,
    const void *value, const size_t value_size, struct skiplist_iter *it)
{
	if (msl == NULL || key == NULL) {
		return -1;
	}

	struct skiplist_node *prevs[MAX_HEIGHT];
	struct skiplist_node *prev = find_prev(msl, key, key_size, prevs);
	if (prev->next[0] != NULL &&
	    msl->keycmp(prev->next[0]->key, prev->next[0]->key_size, key, key_size) == 0) {
		prev->next[0]->value = value;
		prev->next[0]->value_size = value_size;
		return 0;
	}

	struct skiplist_node *node = (struct skiplist_node *)je_calloc(1,
	    sizeof (struct skiplist_node));
	if (node == NULL) {
		return -1;
	}
	node->key = key;
	node->key_size = key_size;
	node->value = value;
	node->value_size = value_size;
	node->flag = 0;

	int level = pick_level();
	assert(level >= 0 && level < MAX_HEIGHT);

	while (msl->level < level) {
		msl->level++;
		prevs[msl->level] = &msl->head;
	}

	while (level >= 0) {
		node->next[level] = prevs[level]->next[level];
		prevs[level]->next[level] = node;

		level--;
	}

	if (it)
		it->v = node;

	msl->count++;
	return 0;
}

void *
msl_get(struct skiplist *msl, const void *key, const size_t key_size,
    size_t *value_size)
{
	if (msl == NULL || key == NULL) {
		return NULL;
	}

	struct skiplist_node *prev = find_prev(msl, key, key_size, NULL);
	assert(prev != NULL);

	if (prev->next[0] != NULL &&
	    msl->keycmp(prev->next[0]->key, prev->next[0]->key_size, key, key_size) == 0) {
		if (value_size)
			*value_size = prev->next[0]->value_size;
		return (void *)prev->next[0]->value;
	}

	return NULL;
}

void *
msl_erase(struct skiplist *msl, const void *key, const size_t key_size,
	void **old_key)
{
	if (msl == NULL || key == NULL) {
		return NULL;
	}

	struct skiplist_node *prevs[MAX_HEIGHT];
	struct skiplist_node *prev = find_prev(msl, key, key_size, prevs);
	if (prev->next[0] == NULL ||
	    msl->keycmp(prev->next[0]->key, prev->next[0]->key_size, key, key_size) != 0) {
		return NULL;
	}

	struct skiplist_node *cur = prev->next[0];
	const void *old_value = cur->value;

	int level;
	for (level = 0; level <= msl->level; level++) {
		if (prevs[level]->next[level] != cur) {
			break;
		}
		prevs[level]->next[level] = cur->next[level];
	}

	if (old_key)
		*old_key = (void *)cur->key;
	je_free(cur);

	while (msl->level > 0 && msl->head.next[msl->level] == NULL) {
		msl->level--;
	}

	msl->count--;
	return (void *)old_value;
}

static const struct skiplist_iter null_iter;

struct skiplist_iter
msl_iter_next(struct skiplist *msl, struct skiplist_iter *it)
{
	if (msl == NULL || msl->head.next[0] == NULL) {
		return null_iter;
	}

	struct skiplist_iter next;
	next.v = msl->head.next[0];
	if (it != NULL) {
		next.v = it->v->next[0];
	}

	return next;
}

void *
msl_iter_getk(struct skiplist_iter *it, size_t *ksize)
{
	if (it == NULL || it->v == NULL) {
		return NULL;
	}

	if (ksize)
		*ksize = it->v->key_size;
	return (void *)it->v->key;
}

void *
msl_iter_getv(struct skiplist_iter *it, size_t *vsize)
{
	if (it == NULL || it->v == NULL) {
		return NULL;
	}

	if (vsize)
		*vsize = it->v->value_size;
	return (void *)it->v->value;
}

int
msl_iter_getf(struct skiplist_iter *it)
{
	if (it == NULL || it->v == NULL) {
		return -1;
	}

	return it->v->flag;
}

int
msl_iter_setf(struct skiplist_iter *it, int newflag)
{
	if (it == NULL || it->v == NULL) {
		return -1;
	}

	it->v->flag = newflag;
	return it->v->flag;
}

void
msl_debug(struct skiplist *msl, int do_hash)
{
	if (msl == NULL) {
		log_info(lg, "skip_list is null\n");
		return;
	}

	int level;
	for (level = 0; level <= msl->level; level++) {
		printf("level(%d): ", level);
		struct skiplist_node *cur = msl->head.next[level];
		while (cur != NULL) {
			if (do_hash) {
				uint32_t h;
				tiny_hash(cur->key, cur->key_size, &h);
				printf(" -> 0x%04x", (uint16_t)h);
			} else
				printf(" -> %s", (char *)cur->key);
			cur = cur->next[level];
		}
		printf("\n");
	}
}

int
msl_count(struct skiplist *msl)
{
	return msl->count;
}
