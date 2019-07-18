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


#ifndef _PMU_VEV_H
#define _PMU_VEV_H

#include "pmu_lfq.h"

typedef unsigned long int ticks_t;	// time from the hpet clock, hept_hz() ticks per second

typedef struct busy_event {
	ticks_t start;
	ticks_t duration;
} busy_event_t;


struct pmu_vdev {
	uint128_t id;
	uv_async_t exit_kick;
	uv_async_t lfq_kick;
	pmu_lfq_t to_vdev;
	pmu_lfq_t rtn;
	struct pmu_vdev *next;
};

struct pmu_vdevlist {
	struct pmu_vdev *vdevlist;
	int vdevcount;
};

int pmu_vdev_register(struct pmu_vdev *pmu_vdev);
int pmu_vdev_unregister(struct pmu_vdev *pmu_vdev);

struct pmu_vdev *select_vdev(unsigned chunknum);


#endif /* _PMU_VEV_H */
