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
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <lfq.h>

#include <ccowfsio.h>
#include <queue.h>

#include "fsio_system.h"

static int api_stats_enabled = 0;

struct timespec
fsio_debug_start_call(ci_t * ci, fsio_api api)
{
	struct timespec time;

	if (!api_stats_enabled)
		return time;

	log_trace(fsio_lg,"ci: %p, api: %u", ci, api);
	clock_gettime(CLOCK_REALTIME, &time);

	atomic_inc(&(ci->api_debug_stats[api].call_count));

	log_debug(fsio_lg,"completed ci: %p, api: %u", ci, api);
	return time;
}

void
fsio_debug_end_call(ci_t * ci, fsio_api api, struct timespec start_time,
    int err)
{
	struct timespec end_time;
	uint64_t time;

	if (!api_stats_enabled)
		return;

	log_trace(fsio_lg, "ci: %p, api: %u, err: %d", ci, api, err);
	clock_gettime(CLOCK_REALTIME, &end_time);

	if (err)
		atomic_inc(&(ci->api_debug_stats[api].err_count));

	/*
	 * Get time taken in micro seconds
	 */
	time = (end_time.tv_sec - start_time.tv_sec) * 1000 * 1000;
	time += (end_time.tv_nsec - start_time.tv_nsec) / 1000;

	if (ci->api_debug_stats[api].min_time == 0 ||
	    ci->api_debug_stats[api].min_time > time)
		ci->api_debug_stats[api].min_time = time;

	if (ci->api_debug_stats[api].max_time < time)
		ci->api_debug_stats[api].max_time = time;

	ci->api_debug_stats[api].total_time += time;

	log_debug(fsio_lg, "completed ci: %p, api: %u, err: %d", ci, api, err);
}

void
fsio_debug_log_api_stats(ci_t *ci)
{
	if (!api_stats_enabled)
		return;

	for (int api=0; api<MAX_FSIO_API; api++) {
		log_error(fsio_lg,
		    "API: %d calls: %lu errors: %lu min:%lu max: %lu total: %lu",
		    api, ci->api_debug_stats[api].call_count,
		    ci->api_debug_stats[api].err_count,
		    ci->api_debug_stats[api].min_time,
		    ci->api_debug_stats[api].max_time,
		    ci->api_debug_stats[api].total_time);

	}

	return;
}
