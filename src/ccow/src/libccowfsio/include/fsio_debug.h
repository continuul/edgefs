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
#ifndef __FSIO_DEBUG_H__
#define __FSIO_DEBUG_H__

#include <ccowfsio.h>
#include <queue.h>

typedef enum __public_api__
{
	READDIR_CB = 0,
	READDIR_CB4,
	READSYMLINK,
	LOOKUP,
	LINK,
	UNLINK,
	DELETE,
	BG_DELETE,
	MKDIR,
	TOUCH,
	MKSYMLINK,
	GET_FILE_STAT,
	SET_FILE_STAT,
	CHMOD,
	CHOWN,
	FIND,
	MOVE,
	OPEN,
	READ,
	WRITE,
	CLOSE,
	FLUSH,
	FETCH,

	MAX_FSIO_API
} fsio_api;

typedef struct __api_stats__
{
	uint64_t call_count;
	uint64_t err_count;
	uint64_t min_time;
	uint64_t max_time;
	uint64_t total_time;

} api_stats;

#define DEBUG_START_CALL(CI, API) \
    struct timespec time; \
    time = fsio_debug_start_call(CI, API); \
    time = time;

#define DEBUG_END_CALL(CI, API, ERR) \
    fsio_debug_end_call(CI, API, time, ERR)

struct timespec fsio_debug_start_call(ci_t * ci, fsio_api api);

void fsio_debug_end_call(ci_t * ci, fsio_api api, struct timespec start_time,
    int err);
void fsio_debug_log_api_stats(ci_t * ci);

#endif /*__FSIO_DEBUG_H__*/
