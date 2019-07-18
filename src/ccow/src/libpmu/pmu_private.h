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


#ifndef _PMU_PRIVATE_H
#define _PMU_PRIVATE_H 1

#include "ccowutil.h"
#include "logger.h"
#include "pmu.h"
#include "pmu_lfq.h"
#include "pmu_vdev.h"

// TODO: remove
#include "pmu_test.h"

#define MAX_RECV_FRAMES 256

static uint64_t prior_start = 0L;

typedef struct chunk_track {
	pmu_if_t *pi;
	unsigned chunk_num;
	ticks_t first_seen;
	ticks_t latest_seen;
	ticks_t latest_originated;
	unsigned datagrams_seen;
	unsigned n_datagrams;
	unsigned char bitmap[(PMU_TEST_MAX_DATAGRAMS+7)/8];
	const frame_header_t *frame[PMU_TEST_MAX_DATAGRAMS];
} chunk_track_t;

#define bmap_set(bm,bit) (bm[(bit)/8] |= (1 << ((bit)%8)))
#define bmap_test(bm,bit) (bm[(bit)/8] & (1 << ((bit)%8)))

const frame_header_t *first_frame(const chunk_track_t *t);
void *copy_chunk (chunk_track_t *t,size_t *len);

void transaction_complete(void *p);
void pmu_vdev_notify_all(pmu_if_t *pi);

#endif /* _PMU_PRIVATE_H */
