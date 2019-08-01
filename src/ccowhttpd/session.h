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
#ifndef session_h
#define session_h

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

#include "param.h"
#include "objio.h"
#include "libauth/bucket_options.h"

// Request types
enum {
	RT_UNKNOWN,
	RT_OBJECT_CREATE,
	RT_OBJECT_REPLACE,
	RT_OBJECT_DELETE,
	RT_STREAM_GET,
	RT_STREAM_POST,
	RT_STREAM_HEAD,
	RT_APPEND,
	RT_WRBLOCK,
	RT_KV_CREATE,
	RT_KV_REPLACE,
	RT_KV_POST,
	RT_KV_GET,
	RT_KV_DELETE,
	RT_KV_LIST
};

static const char* REQUEST_STR[] = {
		"UNKNOWN",
		"OBJECT_CREATE",
		"OBJECT_REPLACE",
		"OBJECT_DELETE",
		"STREAM_GET",
		"STREAM_POST",
		"STREAM_HEAD",
		"APPEND",
		"WRBLOCK",
		"KV_CREATE",
		"KV_REPLACE",
		"KV_POST",
		"KV_GET",
		"KV_DELETE",
		"KV_LIST"
};


typedef struct session {
	uint64_t sid;
	objio_info_t *ci;
	pthread_mutex_t sess_lock;

	// Types
	int request_type;
	int method_type;

	// Keys
	int streamsession;
	int appendblock;
	int randwrblock;
	int kv;
	int kvget;
	int finalize;
	int cancel;
	int del;

	// Range
	uint64_t offset;
	uint64_t length;

	// Counters
	uint64_t modifiedBytes;
    int opCount;
	uint64_t logicalSize;


    //
    // Attributes
    //
    param_vector *attrs;

    //
    //  Options
    //
    param_vector *opts;
} session_t;

int session_update(param *comp, int method_type, param_vector *query_params, param_vector *headers,
		session_t *ss, int reuse);

int session_create(objio_info_t *ci, param *comp, int method_type,
	param_vector *query_params, param_vector *headers, uint64_t expiration, session_t **session);

int session_valid(session_t *ss);

int session_ending(session_t *ss);

void session_destroy(session_t *ss);

void session_close(session_t *ss);

int session_closed(session_t *ss);

void session_dump(char *header, session_t *ss);


#ifdef __cplusplus
}
#endif

#endif
