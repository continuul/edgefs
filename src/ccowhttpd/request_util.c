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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include "h2o.h"

#include "ccowutil.h"
#include "param.h"
#include "request_util.h"
#include "request.h"

#define DEFAULT_SIZE 64
#define MAX_BUF 4096
#define LAST_MODIFIED "last-modified"

int
get_method_type(h2o_req_t *req) {
	if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET"))) {
		return METHOD_IS_GET;
	} else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"))) {
		return METHOD_IS_HEAD;
	} else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST"))) {
		return METHOD_IS_POST;
	} else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("PUT"))) {
		return METHOD_IS_PUT;
	} else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("DELETE"))) {
		return METHOD_IS_DELETE;
	} else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("OPTIONS"))) {
		return METHOD_IS_OPTIONS;
	}
	return METHOD_IS_OTHER;
}

void
get_operation_type(int method_type, char *bid, param_vector *query_params, char *operation) {
	if (param_has(H2O_STRLIT("acl"), query_params)) { // ACLs
		if (method_type == METHOD_IS_GET) {
			strcpy(operation, "read_acp");
		} else {
			strcpy(operation, "write_acp");
		}
	} else if (bid == NULL || bid[0] == 0) { // Account/tenant
		if (method_type == METHOD_IS_GET ||
			method_type == METHOD_IS_HEAD) {
			strcpy(operation, "bucket_list");
		} else {
			strcpy(operation, "bucket_create");
		}
	} else { // Object/bucket
		if (method_type == METHOD_IS_GET ||
			method_type == METHOD_IS_HEAD ||
			method_type == METHOD_IS_OPTIONS) {
			strcpy(operation, "read");
		} else {
			strcpy(operation, "write");
		}
	}
}


int
add_response_header(h2o_req_t *req, char *name, char *value) {
	if (!name || !value)
		return 0;
	int len = strlen(value);
	if (len == 0)
		return 0;
	h2o_iovec_t ivalue;
	ivalue = h2o_strdup(&req->pool, value,  len);
	if (ivalue.base == NULL) {
		return -ENOMEM;
	}
	h2o_add_header_by_str(&req->pool, &req->res.headers, PARAM_STR(name), 0, NULL,
			ivalue.base, ivalue.len);
    return 0;
}

int
add_response_header_int64(h2o_req_t *req, char *name, int64_t value) {
	char buf[128];
	sprintf(buf,"%ld", value);
	return add_response_header(req, name, buf);
}

int
add_response_header_uint64(h2o_req_t *req, char *name, uint64_t value) {
	char buf[128];
	sprintf(buf,"%lu", value);
	return add_response_header(req, name, buf);
}

int
add_response_header_last_modified(h2o_req_t *req, uint64_t uvid) {
	char buf[H2O_TIMESTR_RFC1123_LEN + 1];
	time_t time = (time_t) (uvid / 1000000);
	struct tm tm;
	gmtime_r(&time, &tm);
	h2o_time2str_rfc1123(buf, &tm);

	add_response_header(req, LAST_MODIFIED, buf);
	return 0;
}


int
uri_unescape(char *s, int len) {
	char *c = s;
	char *p = s;
	char tmp[3];
	tmp[2] = 0;

	int n = 0;
	while(c < (s+len)) {
		n++;
		if (*c != '%') {
			*p = *c;
		} else if (*c == '%') {
			c++;
			if ((c+1) > (s+len))
				return -EINVAL;
			memcpy(tmp, c, 2);
			int t = (int) strtol(tmp, NULL, 16);
			if (t == 0) {
				return -EINVAL;
			}
			*p = (char) t;
			c += 1;
		}
		p++;
		c++;
	}
	return (p - s);
}

int
uri_escape(char *s, int len, char *out, int max_out, int encodeSlash) {
	char *c = s;
	char ch;
	char *p = out;
	int out_len = 0;

	int n = 0;
	while(c < (s+len)) {
		n++;
		ch = *c;
		if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
		    (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' ||
		    ch == '~' || ch == '.') {
			*p = *c;
		} else if (ch == '/') {
			if (encodeSlash) {
				sprintf(p,"%%%02X",ch);
				p += 2;
			} else {
				*p = *c;
			}
		} else {
			sprintf(p,"%%%02X",ch);
			p += 2;
		}
		p++;
		c++;
		out_len = (p - out);
		if (out_len > max_out)
			break;
	}
	out[out_len] = 0;
	return out_len;
}


char *
calc_md5(char *s, int len, char *out) {
	int i, l;
	unsigned char res[MD5_DIGEST_LENGTH];

	MD5((const unsigned char*)s, len, res);

	char *cur = out;
	for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
	  l = sprintf(cur, "%02x", res[i]);
	  cur += l;
	}
    return out;
}


h2o_iovec_t
encode_versionId(h2o_req_t *req, uint64_t uvid, uint64_t genid, uint512_t *vmchid, uint8_t deleted) {
	char key[MAX_BUF], buf[MAX_BUF], md5[MD5_DIGEST_LENGTH*2 + 1];
    int len = sprintf(key,"%lu/%lu/%s/%d", uvid, genid, str_hash_id(vmchid, buf, 128), deleted);
    calc_md5(key, len, md5);
    len = sprintf(buf,"%s/%s", key, md5);
    return h2o_uri_escape(&req->pool, buf, len, NULL);
}


int
decode_versionId(h2o_req_t *req, char *versionId, int vlen, version_t *version) {
	if (!versionId) {
		return -EINVAL;
	}

	char key[MAX_BUF], buf[MAX_BUF], md5[MD5_DIGEST_LENGTH*2 + 1];


	char *p, *sptr, *token;
	int res, rest;

	token = versionId;

	p = strstr(versionId, "%2F");
	if (p == NULL)
		return -EINVAL;
	*p = '\0';

	if (token == NULL)
		return -EINVAL;

	log_trace(lg, "parse versionId, token1: %s", token);

	res = sscanf(token, "%lu", &version->uvid);
	log_trace(lg, "parse uvid, res: %d", res);
	if (res < 1)
		return -EINVAL;

	token = p + 3;
	rest = (token - versionId);
	if (rest > vlen)
		return -EINVAL;

	p = strstr(token, "%2F");
	if (p == NULL)
		return -EINVAL;
	*p = '\0';
	log_trace(lg, "parse versionId, token2: %s", token);

	res = sscanf(token, "%lu", &version->genid);
	if (res < 1)
		return -EINVAL;

	token = p + 3;
	rest = (token - versionId);
	if (rest > vlen)
		return -EINVAL;

	p = strstr(token, "%2F");
	if (p == NULL)
		return -EINVAL;
	*p = '\0';
	log_trace(lg, "parse versionId, token3: %s", token);

	uint512_fromhex(token, (UINT512_BYTES * 2 + 1),
	    &version->vmchid);

	token = p + 3;
	rest = (token - versionId);
	if (rest > vlen)
		return -EINVAL;

	p = strstr(token, "%2F");
	if (p == NULL)
		return -EINVAL;
	*p = '\0';
	log_trace(lg, "parse versionId, token4: %s", token);

	int d;
	res = sscanf(token, "%d", &d);
	if (res < 1)
		return -EINVAL;

	version->deleted = (uint8_t) d;

	return 0;
}


void
add_headers_unconditional(h2o_req_t *req) {
	unsigned char ch[8];
	char buf[32];
	h2o_iovec_t value;

	RAND_bytes(ch, 8);
	char *p = buf;
	for (int i=0; i<8; i++) {
		sprintf(p,"%02hhx",ch[i]);
		p += 2;
	}

	value = h2o_strdup(&req->pool, buf,  16);
	h2o_add_header_by_str(&req->pool, &req->res.headers, H2O_STRLIT("x-amz-request-id"),  0,
	    "x-amz-request-id", value.base, value.len);

	RAND_bytes(ch, 8);
	p = buf;
	for (int i=0; i<8; i++) {
		sprintf(p,"%02hhx",ch[i]);
		p += 2;
	}

	value = h2o_strdup(&req->pool, buf,  16);
	h2o_add_header_by_str(&req->pool, &req->res.headers, H2O_STRLIT("x-amz-id-2"),  0,
	    "x-amz-id-2", value.base, value.len);

	h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ACCEPT_RANGES, NULL, H2O_STRLIT("bytes"));
}


int
query_parse(h2o_mem_pool_t *pool, h2o_iovec_t *query, param_vector *params) {
	int err = param_init(pool, DEFAULT_SIZE, ALLOCATE_ON, params);
	if (err)
		return -err;

	if (query->base == NULL || query->len == 0 || *query->base == '\0')
		return 0;


	char buf[MAX_BUF];
	char *qptr = query->base;
	int qlen = query->len;
	if (qlen >= MAX_BUF)
		qlen = MAX_BUF - 1;
	memcpy(buf, qptr, qlen);
	buf[qlen] = '\0';

	char *p, *sptr;
	char *token, *peq;
	param *q;

	p = buf;
	while (1) {
		token = strtok_r(p, "&", &sptr);
		if (token == NULL)
			break;
		peq = strchr(token, '=');
		if (peq != NULL) {
			*peq = '\0';
			peq++;
			err = param_add(PARAM_STR(token), PARAM_STR(peq), params);
			if (err)
				return -err;
		} else {
			err = param_add(PARAM_STR(token), NULL, 0, params);
			if (err)
				return -err;
		}
		p = NULL;
	}

	log_trace(lg, "query params size: %d", params->size);
	return params->size;
}


int
headers_parse(h2o_mem_pool_t *pool, const h2o_headers_t *headers, param_vector *params) {
	int err = param_init(pool, DEFAULT_SIZE, LOWERCASE_ON, params);
	if (err)
		return -err;

	if (headers == NULL || headers->size == 0)
		return 0;


	unsigned int cursor = -1;
	for (++cursor; cursor < headers->size; ++cursor) {
		h2o_header_t *t = headers->entries + cursor;
		err = param_add(t->name->base, t->name->len, t->value.base, t->value.len, params);
		if (err) {
			log_error(lg, "header add error: %d", err);
			return -err;
		}
	}

	log_trace(lg, "headers size: %d", params->size);
	return 0;
}


char *
headers_get(const h2o_headers_t *headers, char *name, char *buffer, int max_len) {
	if (headers == NULL || headers->size == 0) {
		*buffer = 0;
		return buffer;
	}

	int name_len = strlen(name);
	unsigned int cursor = -1;
	for (++cursor; cursor < headers->size; ++cursor) {
		h2o_header_t *t = headers->entries + cursor;
		if (name_len != (int) t->name->len)
			continue;
		if (memcmp(t->name->base, name, t->name->len) == 0 && (int) t->value.len < max_len) {
			memcpy(buffer, t->value.base, t->value.len);
			buffer[t->value.len] = 0;
			return buffer;
		}
	}

	*buffer = 0;
	return buffer;
}


char *
str_hash_id(uint512_t *hash_id, char *buf, int len) {
    char hash[UINT512_BYTES*2+1];
    uint512_dump(hash_id, hash, UINT512_BYTES*2+1);
    hash[len] = '\0';
    memcpy(buf, hash, len+1);
    return buf;
}
