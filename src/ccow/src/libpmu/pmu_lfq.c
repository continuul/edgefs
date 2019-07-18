//
// Copyright (c) 2015-2018 Nexenta Systems, inc.
//
// This file is part of EdgeFS Project
// (see https://github.com/Nexenta/edgefs).
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//



#include "pmu_lfq.h"
#include "pmu_private.h"

#define PMU_LFQ_SIZE 64

struct pmu_lfq {
	volatile unsigned queue_head;
	volatile unsigned queue_tail;
	void* pmu_queue[PMU_LFQ_SIZE];
};

pmu_lfq_t
pmu_lfq_create(void)
{
	struct pmu_lfq *h = calloc(1, sizeof(struct pmu_lfq));
	if (!h)
		return NULL;
	h->queue_head = 1;
	h->queue_tail = 0;
	return h;
}

void
pmu_lfq_destroy(pmu_lfq_t h)
{
	je_free(h);
}

static inline int
pmu_lfq_advance(volatile unsigned *idx)
{
	unsigned old, new;
	do
	{
		old = *idx;
		new = (old + 1) % PMU_LFQ_SIZE;
	} while(!__sync_bool_compare_and_swap(idx, old, new));

	return old;
}

bool
pmu_lfq_produce(pmu_lfq_t h, void *data_ptr)
{
	struct pmu_lfq *q = h;

	if ((q->queue_head + 1) % PMU_LFQ_SIZE == q->queue_tail)
		return false;

	q->pmu_queue[q->queue_head] = data_ptr;
	pmu_lfq_advance(&q->queue_head);

	return true;
}

void *
pmu_lfq_consume(pmu_lfq_t h)
{
	struct pmu_lfq *q = h;

	if (q->queue_tail == q->queue_head)
		return NULL;

	int idx = pmu_lfq_advance(&q->queue_tail);
	return q->pmu_queue[idx];
}
