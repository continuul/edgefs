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


void
do_s3_bucket_head(s3_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "S3 BUCKET HEAD");

	/* link the request */
	self->req = req;

	int err = objio_bucket_head(self->rq->ci);
	log_trace(lg, "S3 bucket head check err: %d", err);
	if (err == -ENOENT) {
		request_error_xml(req, self, 404,
		    "Not Found", "NoSuchBucket",
		    "The specified bucket does not exist.",
		    self->rq->ci->bid, NULL);
		return;
	}
	if (err) {
		request_error(req, self, err, 500,
		    "Service unavailable", self->rq->ci->bid, NULL);
		return;
	}

	add_response_header_uint64(req, "x-container-bytes-used", self->rq->ci->logical_size);
	add_response_header_uint64(req, "x-container-object-count", self->rq->ci->object_count);


	/* setup response */
	req->res.status = 200;

	req->res.content_length = self->bytesleft;
	req->res.mime_attr = mime_attr;

	add_response_header_last_modified(req, self->rq->ci->uvid);

	if (self->content_encoding.base != NULL)
		h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, NULL, self->content_encoding.base,
		    self->content_encoding.len);


	// Add Headers
	add_s3_headers_conditional(self, req);

	/* special path for cases where we do not need to send any data */
	request_end(req, self, 0);
	return;
}



int
create_s3_bucket_head_generator(h2o_req_t *req, s3_generator_t *self)
{
	int err;
	uint64_t offset = 0;
	uint64_t length = 0;
	request_t *rq = self->rq;

	self->do_work = do_s3_bucket_head;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = 0;
	self->req = NULL;
	self->bytesleft =  rq->ci->size;
	self->ccow_logical_size = rq->ci->logical_size;
	return 0;
}



