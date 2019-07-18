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
#ifndef request_util_h
#define request_util_h

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <errno.h>
#include "ccowutil.h"
#include "h2o.h"
#include "param.h"
#include "request.h"

enum { METHOD_IS_GET, METHOD_IS_PUT, METHOD_IS_POST, METHOD_IS_HEAD, METHOD_IS_DELETE, METHOD_IS_OPTIONS, METHOD_IS_OTHER };
static const char* METHOD_STR[] = { "GET", "PUT", "POST", "HEAD", "DELETE", "OPTIONS", "OTHER" };

static inline int
str_iovec(h2o_iovec_t v, char *out, int max)
{
	if (!v.base || v.len == 0) {
		out[0] = 0;
		return 0;
	}
	if ((int)v.len > (max-1))
		return -EINVAL;
	memcpy(out, v.base, v.len);
	out[v.len] = 0;
	return 0;
}

void add_headers_unconditional(h2o_req_t *req);

int get_method_type(h2o_req_t *req);

void get_operation_type(int method_type, char *bid, param_vector *query_params, char *operation);

int add_response_header(h2o_req_t *req, char *name, char *value);

int add_response_header_int64(h2o_req_t *req, char *name, int64_t value);

int add_response_header_uint64(h2o_req_t *req, char *name, uint64_t value);

int add_response_header_last_modified(h2o_req_t *req, uint64_t uvid);

int query_parse(h2o_mem_pool_t *pool, h2o_iovec_t *query, param_vector *params);

int headers_parse(h2o_mem_pool_t *pool, const h2o_headers_t *headers, param_vector *params);

char *headers_get(const h2o_headers_t *headers, char *name, char *buffer, int max_len);

char *str_hash_id(uint512_t *hash_id, char *buf, int len);

int uri_unescape(char *s, int len);

int uri_escape(char *s, int len, char *out, int max_out, int encodeSlash);

char *calc_md5(char *s, int len, char *out);

h2o_iovec_t encode_versionId(h2o_req_t *req, uint64_t uvid, uint64_t genid,
		uint512_t *vmchid, uint8_t deleted);

int
decode_versionId(h2o_req_t *req, char *versionId, int vlen, version_t *version);


#ifdef __cplusplus
}
#endif

#endif
