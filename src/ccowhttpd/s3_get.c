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



// Proceed methods
static void
do_s3_get_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
	s3_generator_t *self = (void *)_self;
	size_t rlen;
	ssize_t rret;
	h2o_iovec_t vec;
	h2o_send_state_t send_state;

	// Start response
	if (req->_generator == NULL)
		h2o_start_response(req, &self->super);


	/* read the object */
	rlen = self->bytesleft;
	if (rlen > self->bufzise)
		rlen = self->bufzise;

	log_trace(lg, "bytesleft %ld len %ld off %lu", self->bytesleft, rlen, self->off);

	rret = objio_pread(self->rq->ci, self->buf, rlen, self->off);
	if (rret == -1) {
		log_error(lg, "Read error %s/%s", self->rq->ci->bid, self->rq->ci->oid);
		h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
		do_s3_close(&self->super, req);
		return;
	}
	self->off += rret;
	self->bytesleft -= rret;
	if (self->bytesleft == 0) {
		send_state = H2O_SEND_STATE_FINAL;
	} else {
		send_state = H2O_SEND_STATE_IN_PROGRESS;
	}

	/* send (and close if done) */
	vec.base = self->buf;
	vec.len = rret;

	log_trace(lg, "bytewrite %lu", rret);

	h2o_send(req, &vec, 1, send_state);
	if (send_state == H2O_SEND_STATE_FINAL)
		do_s3_close(&self->super, req);
}

static void
do_s3_multipart_get_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
	s3_generator_t *self = (void *)_self;
	size_t rlen;
	ssize_t rret;
	h2o_iovec_t vec;
	h2o_send_state_t send_state;

	// Start response
	if (req->_generator == NULL)
		h2o_start_response(req, &self->super);

	struct json_object *part;
	int p;
	int64_t off;
	int64_t size;
	const char *bid;
	const char *oid;
	int err = 0;

	while (self->rq->ipart < self->rq->nparts) {
		part = json_object_array_get_idx(self->jparts, self->rq->ipart);
		if (!part ||
		    !get_by_path_int(part, "part",  &p) ||
		    !get_by_path_string(part, "bucket",  &bid) ||
		    !get_by_path_string(part, "name",  &oid) ||
		    !get_by_path_int64(part, "size",  &size)) {
			log_error(lg, "Read part %d error %s/%s", self->rq->ipart, self->rq->ci->bid, self->rq->ci->oid);
			h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
			do_s3_close(&self->super, req);
			return;
		}
		log_trace(lg, "Num: %d", p);
		log_trace(lg, "Bid: %s", bid);
		log_trace(lg, "Oid: %s", oid);
		log_trace(lg, "Size: %ld", size);
		off = self->off - self->rq->opart;
		if (off >= 0 && off < size)
			break;
		self->rq->ipart++;
		self->rq->opart += size;
	}

	// Check part
	if (self->rq->ipart >= self->rq->nparts) {
		log_error(lg, "No more parts error %s/%s", self->rq->ci->bid, self->rq->ci->oid);
		h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
		do_s3_close(&self->super, req);
		return;
	}


	/* read the part */
	rlen = size - off;
	if (rlen > self->bytesleft)
		rlen = self->bytesleft;
	if (rlen > self->bufzise)
		rlen = self->bufzise;

	log_trace(lg, "multipart_get bytesleft %ld len %ld off %lu", self->bytesleft, rlen, self->off);

	// Open new part
	if (self->rq->ci_part == NULL) {
		err = objio_create(self->rq->ci->tc, self->rq->ci->tid_cid, self->rq->ci->tid_cid_size,
		    (char*)bid, strlen(bid) + 1, (char*)oid, strlen(oid) + 1,
		    CCOW_STREAMSESSION_MAXOPTS, &self->rq->ci_part);
		if (err) {
			log_error(lg, "Create part session error %s/%s", bid, oid);
			h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
			do_s3_close(&self->super, req);
			return;
		}
		err = objio_open(self->rq->ci_part);
		if (err) {
			log_error(lg, "Open part session error %s/%s", bid, oid);
			h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
			do_s3_close(&self->super, req);
			return;
		}
	}

	rret = objio_pread(self->rq->ci_part, self->buf, rlen, off);
	if (rret == -1) {
		log_error(lg, "Read part error %s/%s", bid, oid);
		h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
		do_s3_close(&self->super, req);
		return;
	}

	self->off += rret;
	self->bytesleft -= rret;

	// Close part, move to next
	if ((rlen + off) >= (uint64_t) size) {
		objio_close(self->rq->ci_part, 0);
		objio_destroy(self->rq->ci_part);
		self->rq->ci_part = NULL;
		self->rq->ipart++;
		self->rq->opart += size;
		// Check next part
		if (self->bytesleft > 0 && 	(self->rq->ipart >= self->rq->nparts)) {
			log_error(lg, "No more parts error %s/%s", self->rq->ci->bid, self->rq->ci->oid);
			h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
			do_s3_close(&self->super, req);
			return;
		}
	}


	// Set send state
	if (self->bytesleft == 0) {
		send_state = H2O_SEND_STATE_FINAL;
	} else {
		send_state = H2O_SEND_STATE_IN_PROGRESS;
	}

	/* send (and close if done) */
	vec.base = self->buf;
	vec.len = rret;

	h2o_send(req, &vec, 1, send_state);
	if (send_state == H2O_SEND_STATE_FINAL)
		do_s3_close(&self->super, req);
}


static
void set_buffer_size(s3_generator_t *self, uint32_t chunk_size) {
	self->bufzise = self->bytesleft;
	if (self->bufzise > MAX_S3_BUF_SIZE) {
		self->bufzise = (MAX_S3_BUF_SIZE / self->rq->ci->chunk_size) * chunk_size;
	}
	if (self->bytesleft < MIN_S3_BUF_SIZE)
		self->bufzise = MIN_S3_BUF_SIZE;
	if (self->bytesleft < self->bufzise)
		self->bufzise = self->bytesleft;
}

// Do methods
void
do_s3_get(s3_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "GET");

	/* link the request */
	self->req = req;

	/* setup response */
	if (self->ranged.range_count == 0) {
		req->res.status = 200;
	} else {
		req->res.status = 206;
	}

	req->res.content_length = self->bytesleft;
	req->res.mime_attr = mime_attr;

	if (self->ranged.range_count > 1) {
		mime_type.base = h2o_mem_alloc_pool(&req->pool, char, 52);
		mime_type.len = sprintf(mime_type.base, "multipart/byteranges; boundary=%s", self->ranged.boundary.base);
	}

	add_response_header_last_modified(req, self->rq->ci->uvid);

	if (self->content_encoding.base != NULL)
		h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, NULL, self->content_encoding.base,
		    self->content_encoding.len);
	if (self->ranged.range_count == 1) {
		req->res.status = 206;
		h2o_iovec_t content_range;
		content_range.base = h2o_mem_alloc_pool(&req->pool, char, 128);
		content_range.len = sprintf(content_range.base, "bytes %zd-%zd/%zd", self->ranged.range_infos[0],
		    self->ranged.range_infos[0] + self->ranged.range_infos[1] - 1, self->ranged.filesize);
		h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_RANGE, NULL, content_range.base, content_range.len);
	}

	// Add Headers
	add_s3_headers_conditional(self, req);

	/* special path for cases where we do not need to send any data */
	if (self->bytesleft == 0) {
		request_end(req, self, 0);
		return;
	}

	if (self->ranged.range_count == 1)
		self->off = self->ranged.range_infos[0];

	set_buffer_size(self, self->rq->ci->chunk_size);

	log_trace(lg, "Bytesleft: %lu, chunk_size: %u, bufsize: %lu",
	    self->bytesleft, self->rq->ci->chunk_size, self->bufzise);

	self->buf = h2o_mem_alloc_pool(&req->pool, char, self->bufzise);
	if (self->buf == NULL) {
		log_error(lg, "Not enough memory for read buffer");
		h2o_send_error_500(req, "Server error", "please try again later", 0);
		do_s3_close(&self->super, req);
		return;
	}

	/* send data */
	if (self->ranged.range_count < 2) {
		log_trace(lg, "Do read");
		do_s3_get_proceed(&self->super, req);
	} else {
		log_error(lg, "Multiple ranges request is not supported");
		h2o_send_error_400(req, "Invalid request", "please correct request and try again", 0);
		do_s3_close(&self->super, req);
	}
}

void
do_s3_multipart_get(s3_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "GET");

	/* link the request */
	self->req = req;

	/* setup response */
	if (self->ranged.range_count == 0) {
		req->res.status = 200;
	} else {
		req->res.status = 206;
	}

	req->res.content_length = self->bytesleft;
	req->res.mime_attr = mime_attr;

	if (self->ranged.range_count > 1) {
		mime_type.base = h2o_mem_alloc_pool(&req->pool, char, 52);
		mime_type.len = sprintf(mime_type.base, "multipart/byteranges; boundary=%s", self->ranged.boundary.base);
	}

	add_response_header_last_modified(req, self->rq->ci->uvid);

	if (self->content_encoding.base != NULL)
		h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, NULL, self->content_encoding.base,
		    self->content_encoding.len);
	if (self->ranged.range_count == 1) {
		h2o_iovec_t content_range;
		content_range.base = h2o_mem_alloc_pool(&req->pool, char, 128);
		content_range.len = sprintf(content_range.base, "bytes %zd-%zd/%zd", self->ranged.range_infos[0],
		    self->ranged.range_infos[0] + self->ranged.range_infos[1] - 1, self->ranged.filesize);
		h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_RANGE, NULL, content_range.base, content_range.len);
	}

	// Add Headers
	add_s3_headers_conditional(self, req);

	/* special path for cases where we do not need to send any data */
	if (self->bytesleft == 0) {
		request_end(req, self, 0);
		return;
	}

	if (self->ranged.range_count == 1)
		self->off = self->ranged.range_infos[0];


	set_buffer_size(self, self->rq->ci->chunk_size);

	log_trace(lg, "Bytesleft: %lu, chunk_size: %u, bufsize: %lu",
	    self->bytesleft, self->rq->ci->chunk_size, self->bufzise);

	self->buf = h2o_mem_alloc_pool(&req->pool, char, self->bufzise);

	if (self->buf == NULL) {
		log_error(lg, "Not enough memory for read buffer");
		h2o_send_error_500(req, "Server error", "please try again later", 0);
		do_s3_close(&self->super, req);
		return;
	}

	log_trace(lg, "Do GET multipart");
	char* buf = h2o_mem_alloc_pool(&req->pool, char, self->rq->ci->logical_size+1);
	if (buf == NULL) {
		log_error(lg, "Not enough memory for multipart read buffer");
		h2o_send_error_500(req, "Server error", "please try again later", 0);
		do_s3_close(&self->super, req);
		return;
	}
	int rret = objio_pread(self->rq->ci, buf, self->rq->ci->logical_size, 0);
	if (rret == -1) {
		log_error(lg, "Multipart read error");
		h2o_send_error_500(req, "Multipart IO error", "please try again later", 0);
		do_s3_close(&self->super, req);
		return;
	}

	if ((uint64_t)rret != self->rq->ci->logical_size) {
		log_error(lg, "Multipart read error, ");
		h2o_send_error_500(req, "Multipart IO check error", "please try again later", 0);
		do_s3_close(&self->super, req);
		return;
	}

	buf[rret] = '\0';
	log_trace(lg, "The parts json object: %s",buf);

	self->jparts = json_tokener_parse(buf);
	if (!self->jparts) {
		log_error(lg, "Multipart get json parse error");
		h2o_send_error_400(req, "Bad request", "json parse error", 0);
		do_s3_close(&self->super, req);
		return;
	}

	self->rq->nparts = json_object_array_length(self->jparts);
	if (self->rq->nparts <= 0) {
		log_error(lg, "Multipart no parts");
		h2o_send_error_400(req, "Bad request", "no parts", 0);
		do_s3_close(&self->super, req);
		return;
	}

	/* send data */
	if (self->ranged.range_count < 2) {
		log_trace(lg, "Do read");
		do_s3_multipart_get_proceed(&self->super, req);
	} else {
		log_error(lg, "Multiple ranges request is not supported");
		h2o_send_error_400(req, "Invalid request", "please correct request and try again", 0);
		do_s3_close(&self->super, req);
	}
}



// Generator creators
int
create_s3_get_generator(h2o_req_t *req, s3_generator_t *self)
{
	int err;
	uint64_t offset;
	uint64_t length;
	request_t *rq = self->rq;

	log_trace(lg,"s3_get open");
	err = objio_open(rq->ci);
	if (err)
		return err;

	// Range
	log_trace(lg,"s3_get set range rq->ci->logical_size: %ld", rq->ci->logical_size);
	offset = rq->offset;
	length = rq->length;

	if (self->rq->ci->multipart != 2) {
		self->do_work = do_s3_get;
		self->super.proceed = do_s3_get_proceed;
	} else {
		self->do_work = do_s3_multipart_get;
		self->super.proceed = do_s3_multipart_get_proceed;
	}
	self->super.stop = do_s3_close;
	self->off = offset;
	if (rq->ci->size <= offset) {
		self->off = 0;
		self->bytesleft = 0;
	} else {
		uint64_t len = rq->ci->size - offset;
		self->bytesleft = (length < len && length > 0 ? length : len);
	}
	self->ccow_logical_size = self->bytesleft;
	return 0;
}

