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
#include <stdlib.h>
#include <stdint.h>

#include "ccowutil.h"
#include "lfq.h"
#include "utringbuffer.h"

UT_icd pointer_icd = { sizeof(void *), NULL, NULL, NULL };

lfqueue_t
lfqueue_create(size_t depth)
{
	lfqueue_t q = (lfqueue_t)je_malloc(sizeof (struct _lfqueue_t));
	if (!q)
		return NULL;
	q->popped_count = 0;
	utringbuffer_new(q->ring, depth, &pointer_icd);
	pthread_spin_init(&q->ring_lock, PTHREAD_PROCESS_PRIVATE);
	return q;
}

void
lfqueue_destroy(lfqueue_t q)
{
	pthread_spin_destroy(&q->ring_lock);
	utringbuffer_free(q->ring);
	je_free(q);
}

int
lfqueue_enqueue(lfqueue_t q, void *data)
{
	pthread_spin_lock(&q->ring_lock);
	if (q->ring->n + q->popped_count == 0) {
		pthread_spin_unlock(&q->ring_lock);
		return -EBUSY;
	}
	utringbuffer_push_back(q->ring, &data);
	q->popped_count--;
	pthread_spin_unlock(&q->ring_lock);
	return 0;
}

void *
lfqueue_dequeue(lfqueue_t q)
{
	void **data;
	pthread_spin_lock(&q->ring_lock);
	if (utringbuffer_empty(q->ring) || q->popped_count == 0) {
		pthread_spin_unlock(&q->ring_lock);
		return NULL;
	}
	int idx = utringbuffer_len(q->ring) + q->popped_count;
	assert(idx >= 0);
	data = utringbuffer_eltptr(q->ring, idx);
	q->popped_count++;
	pthread_spin_unlock(&q->ring_lock);
	return *data;
}

int
lfqueue_length(lfqueue_t q)
{
	int len;
	pthread_spin_lock(&q->ring_lock);
	len = q->popped_count;
	pthread_spin_unlock(&q->ring_lock);
	return -len;
}

int
lfqueue_cap(lfqueue_t q)
{
	int popped;
	pthread_spin_lock(&q->ring_lock);
	popped = q->popped_count;
	pthread_spin_unlock(&q->ring_lock);
	return q->ring->n - (-popped);
}
