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
#ifndef ccowobj_generator_h
#define ccowobj_generator_h

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

#include "objio.h"
#include "param.h"
#include "session.h"
#include "request_util.h"


#define MAX_BUF_SIZE (8*4*1024*1024UL)
#define BOUNDARY_SIZE 20
#define FIXED_PART_SIZE (sizeof("\r\n--") - 1 + BOUNDARY_SIZE + \
    sizeof("\r\nContent-Range: bytes=-/\r\nContent-Type: \r\n\r\n") - 1)
#define CONTENT_UNKNOWN 0
#define CONTENT_JSON 1
#define CONTENT_CSV 2
#define CONTENT_OCTET 3


struct ccowobj_generator {
	h2o_generator_t super;
	session_t *ss;
	off_t off;
	h2o_req_t *req;
	size_t bytesleft;
	size_t ccow_logical_size;
	h2o_iovec_t content_encoding;
	unsigned send_etag : 1;
	char *buf;
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
	void (*do_work)(struct ccowobj_generator *self, h2o_req_t *req,
		    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);
};

typedef struct ccowobj_generator ccowobj_generator_t;

/**
 * Create generator object
 */
int create_generator(h2o_req_t *req,
		param_vector *query_params, param_vector *headers,
		session_t *ss, int flags, ccowobj_generator_t **generator);

/**
 * Close session/transaction and free resources
 */
void do_close(h2o_generator_t *_self, h2o_req_t *req);

int is_closed(h2o_generator_t *_self);

h2o_send_state_t do_pull(h2o_generator_t *_self, h2o_req_t *req, h2o_iovec_t *buf);

void do_create(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);

void do_delete(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);

void do_get(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);

void do_head(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);

void do_recv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);

void do_recv_kv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);

void do_del_kv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);

void do_list_kv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);

void do_get_kv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr);

// Generator creators
int create_object_create_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_object_replace_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_object_delete_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_stream_head_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_stream_get_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_stream_post_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_append_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_wrblock_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_kv_create_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_kv_replace_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_kv_post_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_kv_del_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_kv_list_generator(h2o_req_t *req, ccowobj_generator_t *self);

int create_kv_get_generator(h2o_req_t *req, ccowobj_generator_t *self);


// Creators table
static int (*creator_table[])(h2o_req_t *, ccowobj_generator_t *) = {
		NULL,
		create_object_create_generator,
		create_object_replace_generator,
		create_object_delete_generator,
		create_stream_get_generator,
		create_stream_post_generator,
		create_stream_head_generator,
		create_append_generator,
		create_wrblock_generator,
		create_kv_create_generator,
		create_kv_replace_generator,
		create_kv_post_generator,
		create_kv_get_generator,
		create_kv_del_generator,
		create_kv_list_generator
};


#ifdef __cplusplus
}
#endif

#endif
