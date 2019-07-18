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
#ifndef request_h
#define request_h

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

#include "param.h"
#include "objio.h"
#include "h2o.h"


// Request types
enum {
	S3_GET,
	S3_HEAD,
	S3_BUCKET_CREATE,
	S3_BUCKET_DELETE,
	S3_BUCKET_HEAD,
	S3_GET_ACL,
	S3_GET_TAGGING,
	S3_GET_TORRENT,
	S3_GET_UPLOADS,
	S3_UNKNOWN
};

static const char* S3_STR[] = {
		"S3_GET",
		"S3_HEAD",
		"S3_BUCKET_CREATE",
		"S3_BUCKET_DELETE",
		"S3_BUCKET_HEAD",
		"S3_GET_ACL",
		"S3_GET_TAGGING",
		"S3_GET_TORRENT",
		"S3_GET_UPLOADS",
		"UNKNOWN"
};


typedef struct request {
	objio_info_t *ci;

	// Types
	int request_type;
	int method_type;

	// Range
	uint64_t offset;
	uint64_t length;

	// Counters
	uint64_t modifiedBytes;
    int opCount;
	uint64_t logicalSize;

	// Multipart
	objio_info_t *ci_part;
	int nparts;
	int ipart;
	uint64_t opart;

    //
    // Attributes
    //
    param_vector *attrs;

    //
    //  Options
    //
    param_vector *opts;
} request_t;

typedef struct version {
   uint64_t genid;
   uint64_t uvid;
   uint512_t vmchid;
   uint8_t deleted;
} version_t;


int request_create(h2o_req_t *req, objio_info_t *ci, int method_type,
	param_vector *query_params, param_vector *headers, request_t **request);

int get_request_type(param_vector *query_params, int method_type,
		char *bid, int bid_size, char *oid, int oid_size);

int request_valid(request_t *ss);

void request_destroy(request_t *ss);

void request_close(request_t *ss);

void request_close_part(request_t *rq);

int request_closed(request_t *ss);

void request_dump(char *header, request_t *ss);


#ifdef __cplusplus
}
#endif

#endif
