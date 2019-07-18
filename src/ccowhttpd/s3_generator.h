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
#ifndef s3_generator_h
#define s3_generator_h

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

#include "objio.h"
#include "param.h"
#include "request.h"
#include "request_util.h"


typedef struct s3_generator {
	h2o_generator_t super;
	request_t *rq;
	off_t off;
	h2o_req_t *req;
	size_t bytesleft;
	size_t bufzise;
	size_t ccow_logical_size;
	h2o_iovec_t content_encoding;
	unsigned send_etag : 1;
	char *buf;
	struct json_object *jparts;
	struct {
		size_t filesize;
		size_t range_count;
		size_t *range_infos;  /* size_t shows in pair. first is start offset, then length */
		h2o_iovec_t boundary; /* boundary used for multipart/byteranges */
		h2o_iovec_t mimetype; /* original mimetype for multipart */
		size_t current_range; /* range that processing now */
	} ranged;
	struct {
		char last_modified[H2O_TIMESTR_RFC1123_LEN + 1];
		char etag[H2O_FILECACHE_ETAG_MAXLEN + 1];
	} header_bufs;
	param_vector *headers;
	param_vector *query_params;
	void (*do_work)(struct s3_generator *self, h2o_req_t *req,
		    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);
} s3_generator_t;

// Helper methods
void add_s3_headers_conditional(s3_generator_t *self, h2o_req_t *req);

int request_end(h2o_req_t *req, s3_generator_t *self, int writes);

int request_error(h2o_req_t *req, s3_generator_t *self, int error, int status,
		const char *reason, char* bid, char *oid);

int request_error_xml(h2o_req_t *req, s3_generator_t *self, int status,
	char *reason, char *code, char *message, char* bid, char *oid);

// Generator creators
int create_s3_get_generator(h2o_req_t *req, s3_generator_t *self);

int create_s3_head_generator(h2o_req_t *req, s3_generator_t *self);

int create_s3_bucket_create_generator(h2o_req_t *req, s3_generator_t *self);

int create_s3_bucket_delete_generator(h2o_req_t *req, s3_generator_t *self);

int create_s3_bucket_head_generator(h2o_req_t *req, s3_generator_t *self);


/**
 * Create generator object
 */
int create_s3_generator(h2o_req_t *req,
		param_vector *query_params, param_vector *headers,
		request_t *rq, int flags, s3_generator_t **generator);

/**
 * Close request/transaction and free resources
 */
void do_s3_close(h2o_generator_t *_self, h2o_req_t *req);

int is_s3_closed(h2o_generator_t *_self);




#ifdef __cplusplus
}
#endif

#endif
