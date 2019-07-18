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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <json-c/json.h>

#include "ccowutil.h"
#include "ccow.h"
#include "libauth/json_path.h"
#include "h2o.h"
#include "ccowobj.h"
#include "objio.h"
#include "request_util.h"
#include "s3_generator.h"

#define MAX_S3_BUF_SIZE (8*4*1024*1024UL)
#define MIN_S3_BUF_SIZE (1024*1024UL)


// Headers methods
void
add_s3_headers_conditional(s3_generator_t *self, h2o_req_t *req) {
	char buf[4096];
	int len;
	h2o_iovec_t value;

	add_response_header_uint64(req, "multipart", self->rq->ci->multipart);

	if (self->rq->ci->file)
		add_response_header_uint64(req, "x-file", 1);

	add_response_header_uint64(req, "x-uvid", self->rq->ci->uvid);
	add_response_header_uint64(req, "x-genid", self->rq->ci->genid);

	add_response_header_uint64(req, "x-ccow-logical-size", self->ccow_logical_size);

	add_response_header(req, "content-type", self->rq->ci->content_type);

	if (self->rq->ci->quota_count)
		add_response_header_uint64(req, "x-container-meta-quota-count", self->rq->ci->quota_count);

	if (self->rq->ci->quota_bytes)
		add_response_header_uint64(req, "x-container-meta-quota-bytes", self->rq->ci->quota_bytes);


	if (self->rq->ci->num_vers > 1) {
		h2o_iovec_t versionId = encode_versionId(req, self->rq->ci->uvid, self->rq->ci->genid,
		    &self->rq->ci->vmchid, self->rq->ci->deleted);

		if (versionId.base != NULL) {
			log_trace(lg, "adding versionId header");
			h2o_add_header_by_str(&req->pool, &req->res.headers, PARAM_STR("x-amz-version-id"), 0, NULL,
			    versionId.base, versionId.len);
		} else {
			log_trace(lg, "adding versionId header fails");
		}
	}

	sprintf(buf, "\"%s\"", self->rq->ci->etag);
	//log_trace(lg, "etag: %s", buf);
	add_response_header(req, "etag", buf);

	if (self->rq->ci->attrs) { // Add attribute headers
		for (int i=0; i<param_count(self->rq->ci->attrs); i++) {
			param *p = param_get(i, self->rq->ci->attrs);
			if (p && p->key.base && p->key.len && p->val.base != NULL && p->val.len > 0) {
				int klen = p->key.len - 1;
				int vlen = p->val.len - 1;
				h2o_add_header_by_str(&req->pool, &req->res.headers, p->key.base, klen, 0, NULL,
						p->val.base, vlen);
			}
		}
	}
}


int
request_end(h2o_req_t *req, s3_generator_t *self, int writes) {
	self->bytesleft = 0;
	static h2o_generator_t generator = {NULL, NULL};
	h2o_start_response(req, &generator);
	h2o_send(req, NULL, 0, H2O_SEND_STATE_FINAL);
	self->rq->ci->writes += writes;
	do_s3_close(&self->super, req);
	return 0;
}

static char *
sanitize(char *resource) {
	char *p;
	p = resource;
	while (*p) {
		if (*p == '<')
			*p = '[';
		if (*p == '>')
			*p = ']';
		p++;
	}
	return resource;
}

int
request_error(h2o_req_t *req, s3_generator_t *self, int error, int status,
		const char *reason, char* bid, char *oid) {
	char resource[2048];
	char message[2048];
	if (bid && oid) {
		sprintf(resource,"%s/%s", bid, oid);
	} else if (bid) {
		sprintf(resource,"%s", bid);
	} else {
		strcpy(resource,"");
	}
	sprintf(message, "%s error: %d for %s", reason, error, sanitize(resource));
	log_error(lg, "%s", message);
	h2o_send_error_generic(req, status, reason, reason, 0);
	do_s3_close(&self->super, req);
	return 0;
}

int
request_error_xml(h2o_req_t *req, s3_generator_t *self, int status,
		char *reason, char *code, char *message, char* bid, char *oid) {
	char resource[2048];
	char xml[2048];
	char requestId[64];
	if (bid && oid) {
		sprintf(resource,"%s/%s", bid, oid);
	} else if (bid) {
		sprintf(resource,"%s", bid);
	} else {
		strcpy(resource,"");
	}
	headers_get(&req->res.headers, "x-amz-request-id", requestId, 64);
	log_error(lg, "%s error: %s code: %s reason: %s, resource: %s", requestId, message, code, reason, resource);
	sprintf(xml, "<?xml version=\"1.0\"?><Error><Code>%s</Code><Message>%s</Message><Resource>%s</Resource><RequestId>%s</RequestId></Error>",
			code, message, sanitize(resource), requestId);
	h2o_send_error_generic(req, status, reason, xml, 0);
	do_s3_close(&self->super, req);
	return 0;
}


// Close method
void
do_s3_close(h2o_generator_t *_self, h2o_req_t *req)
{
	s3_generator_t *self = (void *)_self;

	if (self->headers) {
		param_free(self->headers);
		self->headers = NULL;
	}

	if (self->query_params) {
		param_free(self->query_params);
		self->query_params = NULL;
	}

	if (self->jparts) {
		json_object_put(self->jparts);
		self->jparts = NULL;
	}

	log_trace(lg, "do_s3_close");
	request_close(self->rq);
	request_destroy(self->rq);
}


int
is_s3_closed(h2o_generator_t *_self)
{
	if (_self == NULL)
		return 1;

	s3_generator_t *self = (void *)_self;

	if (self->rq) {
		return request_closed(self->rq);
	}

	return (self->rq->ci == NULL);
}


// Creators table
static int (*s3_creator_table[])(h2o_req_t *, s3_generator_t *) = {
	create_s3_get_generator,
	create_s3_head_generator,
	create_s3_bucket_create_generator,
	create_s3_bucket_delete_generator,
	create_s3_bucket_head_generator,
	NULL
};


int
create_s3_generator(h2o_req_t *req,
    param_vector *query_params, param_vector *headers,
    request_t *rq, int flags, s3_generator_t **generator)
{
	s3_generator_t *self;
	int err = 0;
	*generator = NULL;

	if (!rq) {
		log_error(lg, "request object not defined");
		return -EINVAL;
	}

	self = h2o_mem_alloc_pool(&req->pool, *self, 1);
	if (!self) {
		log_error(lg, "out of memory");
		return -ENOMEM;
	}

	h2o_iovec_t content_encoding = (h2o_iovec_t){NULL};
	self->ranged.range_count = 0;
	self->ranged.range_infos = NULL;
	self->content_encoding = content_encoding;
	self->send_etag = (flags & CCOWOBJ_FLAG_NO_ETAG) == 0;

	self->query_params = query_params;
	self->headers = headers;
	self->rq = rq;
	self->ccow_logical_size = 0;
	self->req = NULL;
	self->jparts = NULL;

	int (*creator)(h2o_req_t *, s3_generator_t *) = s3_creator_table[rq->request_type];
	if (creator == NULL) {
		log_error(lg, "Creator for request %s not defined: ", S3_STR[rq->request_type]);
		return -EINVAL;
	}

	err = creator(req, self);
	if (err) {
		log_error(lg, "Creator for request %s call error: %d", S3_STR[rq->request_type], err);
		return err;
	}

	log_trace(lg, "%s: %s/%s  offset:%lu, bytesleft %ld", S3_STR[rq->request_type],
	    rq->ci->bid, rq->ci->oid, self->off, self->bytesleft);

	*generator = self;
	return 0;
}
