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
#include "session_cache.h"
#include "ccowobj.h"
#include "objio.h"
#include "request_util.h"
#include "ccowobj_generator.h"


// Headers methods
static void
add_headers_conditional(ccowobj_generator_t *self, h2o_req_t *req) {
	char buf[4096];
	int len;
	h2o_iovec_t value;

	add_response_header_uint64(req, "multipart", self->ss->ci->multipart);

	add_response_header_uint64(req, "x-uvid", self->ss->ci->uvid);
	add_response_header_uint64(req, "x-genid", self->ss->ci->genid);

	add_response_header_uint64(req, "x-ccow-logical-size", self->ccow_logical_size);

	add_response_header(req, "content-type", self->ss->ci->content_type);

	add_response_header(req, "x-nhid", str_hash_id(&self->ss->ci->nhid, buf, 64));

	add_response_header(req, "x-vmchid", str_hash_id(&self->ss->ci->vmchid, buf, 64));

	sprintf(buf, "\"%s\"", self->ss->ci->etag);
	add_response_header(req, "etag", buf);

	if (self->ss->ci->attrs) { // Add attribute headers
		for (int i=0; i<param_count(self->ss->ci->attrs); i++) {
			param *p = param_get(i, self->ss->ci->attrs);
			if (p && p->key.base && p->key.len && p->val.base != NULL && p->val.len > 0) {
				int klen = p->key.len - 1;
				int vlen = p->val.len - 1;
				h2o_add_header_by_str(&req->pool, &req->res.headers, p->key.base, klen, 0, NULL,
						p->val.base, vlen);
			}
		}
	}
}

static int
get_content_type(ccowobj_generator_t *self) {
	param *pcontent = param_find(H2O_STRLIT("content-type"), self->headers);
	if (!pcontent) {
		return CONTENT_UNKNOWN;
	}

	if (param_value_equal(pcontent, H2O_STRLIT("application/json"))) {
		return CONTENT_JSON;
	}

	if (param_value_equal(pcontent, H2O_STRLIT("text/csv"))) {
		return CONTENT_CSV;
	}

	if (param_value_equal(pcontent, H2O_STRLIT("application/octet-stream"))) {
		return CONTENT_OCTET;
	}

	return CONTENT_UNKNOWN;
}

// Proceed methods
static void
do_write_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
	ccowobj_generator_t *self = (void *)_self;
	size_t rlen;
	ssize_t rret;
	h2o_iovec_t vec;
	h2o_send_state_t send_state;

	/* read the entity */
	rlen = self->bytesleft;
	if (rlen > MAX_BUF_SIZE)
		rlen = MAX_BUF_SIZE;

	log_trace(lg, "bytesleft %ld len %ld off 0x%lx", self->bytesleft, rlen, self->off);

	rret = objio_pwrite(self->ss->ci, self->buf, rlen, self->off);
	if (rret == -1) {
		h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
		do_close(&self->super, req);
		return;
	}
	self->off += rret;
	self->bytesleft -= rret;
}

// Proceed methods
static void
do_read_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
	ccowobj_generator_t *self = (void *)_self;
	size_t rlen;
	ssize_t rret;
	h2o_iovec_t vec;
	h2o_send_state_t send_state;

	/* read the file */
	rlen = self->bytesleft;
	if (rlen > MAX_BUF_SIZE)
		rlen = MAX_BUF_SIZE;

	log_trace(lg, "bytesleft %ld len %ld off 0x%lx", self->bytesleft, rlen, self->off);

	rret = objio_pread(self->ss->ci, self->buf, rlen, self->off);
	if (rret == -1) {
		h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
		do_close(&self->super, req);
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

	h2o_send(req, &vec, 1, send_state);
	if (send_state == H2O_SEND_STATE_FINAL)
		do_close(&self->super, req);
}

static void
do_kvlist_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
	ccowobj_generator_t *self = (void *)_self;
	size_t rlen;
	ssize_t rret;
	h2o_iovec_t vec;
	h2o_send_state_t send_state;

	log_trace(lg, "bytesleft %ld", self->bytesleft);

	send_state = H2O_SEND_STATE_FINAL;

	/* send (and close if done) */
	vec.base = self->buf;
	vec.len = self->bytesleft;

	h2o_send(req, &vec, 1, send_state);
	do_close(&self->super, req);
}


static void
do_recv_multirange_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
}

static void
do_read_multirange_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
	ccowobj_generator_t *self = (void *)_self;
	size_t rlen, used_buf = 0;
	ssize_t rret, vecarrsize;
	h2o_iovec_t vec[2];
	h2o_send_state_t send_state;

	if (self->bytesleft == 0) {
		size_t *range_cur = self->ranged.range_infos + 2 * self->ranged.current_range;
		size_t range_end = *range_cur + *(range_cur + 1) - 1;
		if (H2O_LIKELY(self->ranged.current_range != 0))
			used_buf =
				sprintf(self->buf, "\r\n--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zd-%zd/%zd\r\n\r\n",
				    self->ranged.boundary.base, self->ranged.mimetype.base, *range_cur, range_end, self->ranged.filesize);
		else
			used_buf =
				sprintf(self->buf, "--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zd-%zd/%zd\r\n\r\n",
				    self->ranged.boundary.base, self->ranged.mimetype.base, *range_cur, range_end, self->ranged.filesize);
		self->ranged.current_range++;
		self->off = *range_cur;
		self->bytesleft = *++range_cur;
	}
	rlen = self->bytesleft;
	if (rlen + used_buf > MAX_BUF_SIZE)
		rlen = MAX_BUF_SIZE - used_buf;

	log_trace(lg, "len %ld off 0x%lx", rlen, self->off);

	rret = objio_pread(self->ss->ci, self->buf + used_buf, rlen, self->off);
	if (rret == -1)
		goto Error;
	self->off += rret;
	self->bytesleft -= rret;

	vec[0].base = self->buf;
	vec[0].len = rret + used_buf;
	if (self->ranged.current_range == self->ranged.range_count && self->bytesleft == 0) {
		vec[1].base = h2o_mem_alloc_pool(&req->pool, char, sizeof("\r\n--") - 1 + BOUNDARY_SIZE + sizeof("--\r\n"));
		vec[1].len = sprintf(vec[1].base, "\r\n--%s--\r\n", self->ranged.boundary.base);
		vecarrsize = 2;
		send_state = H2O_SEND_STATE_FINAL;
	} else {
		vecarrsize = 1;
		send_state = H2O_SEND_STATE_IN_PROGRESS;
	}
	h2o_send(req, vec, vecarrsize, send_state);
	if (send_state == H2O_SEND_STATE_FINAL)
		do_close(&self->super, req);
	return;

Error:
	h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
	do_close(&self->super, req);
	return;
}


// Generator creators
int
create_object_create_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	log_trace(lg,"object_create_generator init");
	err = objio_create_new(ss->ci, 0, self->ss->attrs);
	if (err)
		return err;

	self->do_work = do_create;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = 0;
	self->req = NULL;
	self->bytesleft =  0;
	self->ccow_logical_size = 0;

	return 0;
}

int
create_object_replace_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	log_trace(lg,"object_replace_generator init");
	err = objio_create_new(ss->ci, 1, self->ss->attrs);
	if (err)
		return err;

	self->do_work = do_create;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = 0;
	self->req = NULL;
	self->bytesleft =  0;
	self->ccow_logical_size = 0;

	return 0;
}

int
create_object_delete_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	self->do_work = do_delete;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = 0;
	self->req = NULL;
    self->bytesleft = req->entity.len;
	return 0;
}


int
create_kv_create_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	log_trace(lg,"kv_create_generator init");
	err = objio_create_new(ss->ci, 0, self->ss->attrs);
	if (err)
		return err;

	self->do_work = do_create;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = 0;
	self->req = NULL;
	self->bytesleft =  0;
	self->ccow_logical_size = 0;

	return 0;
}


int
create_kv_replace_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	log_trace(lg,"kv_replace_generator init");
	err = objio_create_new(ss->ci, 1, self->ss->attrs);
	if (err)
		return err;

	self->do_work = do_create;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = 0;
	self->req = NULL;
	self->bytesleft =  0;
	self->ccow_logical_size = 0;

	return 0;
}

int
create_stream_head_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	// Reuse session?
	if (ss->sid > 0 && ss->ci->c) {
		log_trace(lg,"head_generator reuse");
	} else {
		err = objio_open(ss->ci);
		log_trace(lg,"head_generator open err: %d", err);
		if (err)
			return err;
	}

	self->do_work = do_head;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = 0;
	self->req = NULL;
	self->bytesleft =  ss->ci->size;
	self->ccow_logical_size = ss->ci->logical_size;

	return 0;
}

int
create_stream_get_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	uint64_t offset;
	uint64_t length;
	session_t *ss = self->ss;

	// Reuse session?
	if (ss && ss->sid > 0 && ss->ci->c) {
		log_trace(lg,"stream_get reuse");
	} else {
		log_trace(lg,"stream_get open");
		err = objio_open(ss->ci);
		if (err)
			return err;
	}

	// Range
	log_trace(lg,"stream_get set range ss->ci->logical_size: %ld", ss->ci->logical_size);
	offset = ss->offset;
	length = ss->length;

	self->do_work = do_get;
	self->super.proceed = do_read_proceed;
	self->super.stop = do_close;
	self->off = offset;
	self->req = NULL;
	if (ss->ci->logical_size <= offset) {
		self->off = 0;
		self->bytesleft = 0;
	} else {
		uint64_t len = ss->ci->logical_size - offset;
		self->bytesleft = (length < len && length > 0 ? length : len);
	}
	self->ccow_logical_size = self->bytesleft;
	return 0;
}

int
create_stream_post_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	uint64_t offset = 0;
	session_t *ss = self->ss;

	// Reuse session?
	if (ss && ss->sid > 0 && ss->ci->c) {
		log_trace(lg,"post reuse");
	} else {
		log_trace(lg,"post open");
		err = objio_open(ss->ci);
		if (err) {
			if (err == -ENOENT) {
				err = objio_create_new(ss->ci, 1, self->ss->attrs);
				if (err)
					return err;
			} else
				return err;
		}
	}

	// Range
	log_trace(lg,"post set range");
	offset = ss->offset;

	self->do_work = do_recv;

	self->super.proceed = do_write_proceed;
	self->super.stop = do_close;
	self->off = offset;
	self->req = NULL;
	self->bytesleft = req->entity.len;

	size_t new_size = self->off + self->bytesleft;
	self->ccow_logical_size = (new_size > ss->ci->logical_size ? new_size:  ss->ci->logical_size);
	return 0;
}

int
create_append_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	// Reuse session?
	log_trace(lg,"append open");
	err = objio_open(ss->ci);
	if (err) {
		return err;
	}

	// Range
	log_trace(lg,"append set range");
	self->do_work = do_recv;

	self->super.proceed = do_write_proceed;
	self->super.stop = do_close;
	self->off = ss->ci->logical_size;
	self->req = NULL;
	self->bytesleft = req->entity.len;
	self->ccow_logical_size = ss->ci->logical_size + self->bytesleft;
	return 0;
}

int
create_wrblock_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	// Reuse session?
	log_trace(lg,"wrblock open");
	err = objio_open(ss->ci);
	if (err) {
		return err;
	}

	// Range
	log_trace(lg,"wrblock set range");
	self->do_work = do_recv;

	self->super.proceed = do_write_proceed;
	self->super.stop = do_close;
	self->off = ss->offset;
	self->req = NULL;
	self->bytesleft = req->entity.len;

	size_t new_size = self->off + self->bytesleft;
	self->ccow_logical_size = (new_size > ss->ci->logical_size ? new_size:  ss->ci->logical_size);

	return 0;
}

int
create_kv_post_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	uint64_t offset = 0;
	session_t *ss = self->ss;

	// Reuse session?
	if (ss && ss->sid > 0 && ss->ci->c) {
		log_trace(lg,"kv post reuse");
	} else {
		log_trace(lg,"kv post open");
		err = objio_open(ss->ci);
		if (err) {
			if (err == -ENOENT) {
				err = 0;
			} else
				return err;
		}
	}

	self->do_work = do_recv_kv;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = offset;
	self->req = NULL;
	self->bytesleft = req->entity.len;
	return 0;
}

int
create_kv_del_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	uint64_t offset = 0;
	session_t *ss = self->ss;

	// Reuse session?
	if (ss && ss->sid > 0 && ss->ci->c) {
		log_trace(lg,"kv del reuse");
	} else {
		log_trace(lg,"kv del open");
		err = objio_open(ss->ci);
		if (err) {
			if (err == -ENOENT) {
				err = 0;
			} else
				return err;
		}
	}

	self->do_work = do_del_kv;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = offset;
	self->req = NULL;
	self->bytesleft = req->entity.len;
	return 0;
}

int
create_kv_list_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	self->do_work = do_list_kv;
	self->super.proceed = do_kvlist_proceed;
	self->super.stop = do_close;
	self->off = 0;
	self->req = NULL;
	self->bytesleft = req->entity.len;
	return 0;
}

int
create_kv_get_generator(h2o_req_t *req, ccowobj_generator_t *self)
{
	int err;
	session_t *ss = self->ss;

	self->do_work = do_get_kv;
	self->super.proceed = NULL;
	self->super.stop = do_close;
	self->off = 0;
	self->req = NULL;
	self->bytesleft = req->entity.len;
	return 0;
}


int
create_generator(h2o_req_t *req,
		param_vector *query_params, param_vector *headers,
		session_t *ss, int flags, ccowobj_generator_t **generator)
{
	ccowobj_generator_t *self;
	int err = 0;
	*generator = NULL;

	if (!ss) {
		log_error(lg, "session object not defined");
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
	self->ss = ss;
	self->ccow_logical_size = 0;


	int (*creator)(h2o_req_t *, ccowobj_generator_t *) = creator_table[ss->request_type];
	if (creator == NULL) {
		log_error(lg, "Creator for request %s not defined: ", REQUEST_STR[ss->request_type]);
		return -EINVAL;
	}

	err = creator(req, self);
	if (err) {
		log_error(lg, "Creator for request %s call error: %d", REQUEST_STR[ss->request_type], err);
		return err;
	}

	log_trace(lg, "%s: %s/%s  offset:%lu, bytesleft %ld", REQUEST_STR[ss->request_type],
			ss->ci->bid, ss->ci->oid, self->off, self->bytesleft);

	*generator = self;
	return 0;
}

// Close method
void
do_close(h2o_generator_t *_self, h2o_req_t *req)
{
	ccowobj_generator_t *self = (void *)_self;

	if (self->headers) {
		param_free(self->headers);
		self->headers = NULL;
	}

	if (self->query_params) {
		param_free(self->query_params);
		self->query_params = NULL;
	}

	if (self->ss && session_ending(self->ss)) {
		log_trace(lg, "do_close session ending: %lu", self->ss->sid);
		if (self->ss->sid) {
			if (strsess_cache_remove(sess_cache, &self->ss->sid) != 0) {
				session_close(self->ss);
				session_destroy(self->ss);
			}
		} else {
			session_close(self->ss);
			session_destroy(self->ss);
		}
		self->ss = NULL;
	}
}


int
is_closed(h2o_generator_t *_self)
{
	if (_self == NULL)
		return 1;

	ccowobj_generator_t *self = (void *)_self;

	if (self->ss) {
		return session_closed(self->ss);
	}

	return (self->ss->ci == NULL);
}

static int request_end(h2o_req_t *req, ccowobj_generator_t *self, int writes) {
	self->bytesleft = 0;
	static h2o_generator_t generator = {NULL, NULL};
	h2o_start_response(req, &generator);
	h2o_send(req, NULL, 0, H2O_SEND_STATE_FINAL);
	self->ss->ci->writes += writes;
	do_close(&self->super, req);
	return 0;
}



h2o_send_state_t
do_pull(h2o_generator_t *_self, h2o_req_t *req, h2o_iovec_t *buf)
{
	ccowobj_generator_t *self = (void *)_self;
	ssize_t rret;

	log_trace(lg, "bytesleft %ld len %ld off 0x%lx",
	    self->bytesleft, buf->len, self->off);

	if (self->bytesleft < buf->len)
		buf->len = self->bytesleft;

	rret = objio_pread(self->ss->ci, buf->base, buf->len, self->off);
	if (rret <= 0) {
		buf->len = 0;
		self->bytesleft = 0;
		do_close(&self->super, req);
		return H2O_SEND_STATE_ERROR;
	} else {
		buf->len = rret;
		self->off += rret;
		self->bytesleft -= rret;
	}

	if (self->bytesleft != 0)
		return H2O_SEND_STATE_IN_PROGRESS;
	do_close(&self->super, req);
	return H2O_SEND_STATE_FINAL;
}




void
do_get(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "GET");

	/* link the request */
	self->req = req;

	/* setup response */
	req->res.status = 206;

	req->res.content_length = self->bytesleft;
	req->res.mime_attr = mime_attr;

	if (self->ranged.range_count > 1) {
		mime_type.base = h2o_mem_alloc_pool(&req->pool, char, 52);
		mime_type.len = sprintf(mime_type.base, "multipart/byteranges; boundary=%s", self->ranged.boundary.base);
	}

	add_response_header_last_modified(req, self->ss->ci->uvid);

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
	add_headers_conditional(self, req);

	/* special path for cases where we do not need to send any data */
	if (self->bytesleft == 0) {
		request_end(req, self, 0);
		return;
	}

	/* send data */
	h2o_start_response(req, &self->super);

	if (self->ranged.range_count == 1)
		self->off = self->ranged.range_infos[0];
	// TODO: investigate..
	if (0 && req->_ostr_top->start_pull != NULL && self->ranged.range_count < 2) {
		req->_ostr_top->start_pull(req->_ostr_top, do_pull);
	} else {
		size_t bufsz = MAX_BUF_SIZE;
		if (self->bytesleft < bufsz)
			bufsz = self->bytesleft;
		self->buf = h2o_mem_alloc_pool(&req->pool, char, bufsz);
		if (self->ranged.range_count < 2) {
			log_trace(lg, "next buf");
			do_read_proceed(&self->super, req);
		} else {
			self->bytesleft = 0;
			self->super.proceed = do_read_multirange_proceed;
			do_read_multirange_proceed(&self->super, req);
		}
	}
}

void
do_create(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "CREATE");

	/* link the request */
	self->req = req;

	/* setup response */
	req->res.status = 200;

	req->res.content_length = self->bytesleft;
	req->res.mime_attr = mime_attr;

	/* special path for cases where we do not need to send any data */
	request_end(req, self, 0);
	return;
}


void
do_delete(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "DELETE");

	/* link the request */
	self->req = req;

	/* setup response */
	req->res.status = 200;

	req->res.content_length = self->bytesleft;
	req->res.mime_attr = mime_attr;

	int err = objio_delete(self->ss->ci);
	if (err) {
		if (err && err == -ENOENT) {
			h2o_send_error_404(req, "Not found", "no key", 0);
			do_close(&self->super, req);
			return;
		}
		log_error(lg, "delete error: %d", err);
		h2o_send_error_500(req, "Server error", "please try again later", 0);
		do_close(&self->super, req);
		return;
	}

	request_end(req, self, 0);
	return;
}


void
do_head(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "HEAD");

	/* link the request */
	self->req = req;

	/* setup response */
	req->res.status = 200;

	req->res.content_length = self->bytesleft;
	req->res.mime_attr = mime_attr;

	if (self->ranged.range_count > 1) {
		mime_type.base = h2o_mem_alloc_pool(&req->pool, char, 52);
		mime_type.len = sprintf(mime_type.base, "multipart/byteranges; boundary=%s", self->ranged.boundary.base);
	}

	add_response_header_last_modified(req, self->ss->ci->uvid);

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
	add_headers_conditional(self, req);

	/* special path for cases where we do not need to send any data */
	request_end(req, self, 0);
	return;
}

void
do_recv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "POST");

	/* link the request */
	self->req = req;

	/* setup response */
	req->res.status = 200;

	req->res.content_length = 0;
	req->res.mime_attr = mime_attr;

	if (self->ranged.range_count > 1) {
		mime_type.base = h2o_mem_alloc_pool(&req->pool, char, 52);
		mime_type.len = sprintf(mime_type.base, "multipart/byteranges; boundary=%s", self->ranged.boundary.base);
	}
//	h2o_filecache_get_last_modified(self->file.ref, self->header_bufs.last_modified);
//	h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_LAST_MODIFIED, NULL, self->header_bufs.last_modified,
//	    H2O_TIMESTR_RFC1123_LEN);
	if (self->ranged.range_count == 1) {
		h2o_iovec_t content_range;
		content_range.base = h2o_mem_alloc_pool(&req->pool, char, 128);
		content_range.len = sprintf(content_range.base, "bytes %zd-%zd/%zd", self->ranged.range_infos[0],
		    self->ranged.range_infos[0] + self->ranged.range_infos[1] - 1, self->ranged.filesize);
		h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_RANGE, NULL, content_range.base, content_range.len);
	}

	/* special path recv of empty data */
	if (self->bytesleft == 0) {
		request_end(req, self, 1);
		return;
	}

	/* recv data */
	h2o_start_response(req, &self->super);

	if (self->ranged.range_count == 1)
		self->off = self->ranged.range_infos[0];

	size_t bufsz = MAX_BUF_SIZE;
	if (self->bytesleft < bufsz)
		bufsz = self->bytesleft;
	self->buf = req->entity.base;
	if (self->ranged.range_count < 2)
		do_write_proceed(&self->super, req);
	else {
		self->bytesleft = 0;
		self->super.proceed = do_recv_multirange_proceed;
		do_recv_multirange_proceed(&self->super, req);
	}

	/* special path recv of empty data */
	if (self->bytesleft == 0) {
		h2o_send(req, NULL, 0, H2O_SEND_STATE_FINAL);
		do_close(&self->super, req);
	}
}


void
do_recv_kv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "KV POST");

	int err = 0;

	/* link the request */
	self->req = req;
	self->buf = req->entity.base;

	/* setup response */
	req->res.status = 200;

	req->res.content_length = 0;
	req->res.mime_attr = mime_attr;

	/* special path recv of empty data */
	if (self->bytesleft == 0) {
		request_end(req, self, 0);
		return;
	}

	/* recv data */
	struct json_object *jobj;
	struct json_object_iterator it;
	struct json_object_iterator itEnd;
	size_t rlen;
	char *key;
	char *value;

	/* read the entity */
	rlen = self->bytesleft;
	log_trace(lg, "KV POST rlen: %lu", rlen);

	param *pkey = param_find(H2O_STRLIT("key"), self->query_params);
	if (pkey != NULL) { // key case
		log_trace(lg, "KV POST key case");
		param *pcontent_type = param_find(H2O_STRLIT("content-type"), self->headers);
		param *ptimestamp = param_find(H2O_STRLIT("timestamp"), self->headers);
		char timestamp[MAX_ITEM_SIZE] = "";
		char content_type[MAX_ITEM_SIZE] = "";

		if (ptimestamp)
			param_value_str(ptimestamp, timestamp, MAX_ITEM_SIZE);
		if (pcontent_type)
			param_value_str(pcontent_type, content_type, MAX_ITEM_SIZE);

		err = objio_kvput_ext(self->ss->ci, pkey->val.base, pkey->val.len,  self->buf, self->bytesleft,
			timestamp, content_type);
		if (err) {
			log_error(lg, "KV POST insert error: %d", err);
			h2o_send_error_500(req, "Server error", "please try again later", 0);
			do_close(&self->super, req);
			return;
		}
		request_end(req, self, 1);
		return;
	}

	char *buf = h2o_mem_alloc_pool(&req->pool, char, rlen + 1);
	memcpy(buf, self->buf, rlen);
	buf[rlen] = '\0';

	int content_type = get_content_type(self);

	if (content_type == CONTENT_UNKNOWN) {
		err = -EINVAL;
		log_error(lg, "KV POST no content");
		h2o_send_error_400(req, "Bad request", "no content/type", 0);
		do_close(&self->super, req);
		return;
	}

	if (content_type ==  CONTENT_JSON) {
		jobj = json_tokener_parse(buf);
		if (!jobj) {
			log_error(lg, "KV POST json parse error");
			h2o_send_error_400(req, "Bad request", "json parse error", 0);
			do_close(&self->super, req);
			return;
		}
		it = json_object_iter_begin(jobj);
		itEnd = json_object_iter_end(jobj);

		int n = 0;
		while (!json_object_iter_equal(&it, &itEnd)) {
			key = (char *)json_object_iter_peek_name(&it);
			value = (char *)json_object_get_string(json_object_iter_peek_value(&it));
			log_trace(lg, "KV POST %s -> %s", key, value);
			err = objio_kvput(self->ss->ci, key, strlen(key),  value, strlen(value));
			if (err) {
				log_error(lg, "KV POST insert error: %d", err);
				h2o_send_error_500(req, "Server error", "please try again later", 0);
				do_close(&self->super, req);
				return;
			}
			n++;
			json_object_iter_next(&it);
		}
		json_object_put(jobj);

		request_end(req, self, n);
		return;
	}

	if (content_type == CONTENT_CSV) {
		log_trace(lg, "KV POST text/csv case: %s", buf);

		char *p, *value, *token = NULL, *sptr = NULL;
		int n = 0;

		p = buf;
		while (1) {
			token = strtok_r(p, "\n", &sptr);
			if (token == NULL)
				break;
			value = strstr(token,";");
			if (!value)
				continue;
			*value = '\0';
			value++;
			log_trace(lg, "KV POST %s -> %s", token, value);
			err = objio_kvput(self->ss->ci, token, strlen(token),  value, strlen(value));
			if (err) {
				log_error(lg, "KV POST insert error: %d", err);
				h2o_send_error_500(req, "Server error", "please try again later", 0);
				do_close(&self->super, req);
				return;
			}
			n++;
			p = NULL;
		}

		request_end(req, self, n);
		return;
	}

	log_error(lg, "KV POST invalid content/type");
	h2o_send_error_400(req, "Bad request", "invalid content/type", 0);
	do_close(&self->super, req);
	return;
}

void
do_del_kv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr)
{
	log_trace(lg, "KV DEL");

	int err = 0;

	/* link the request */
	self->req = req;
	self->buf = req->entity.base;

	/* setup response */
	req->res.status = 200;

	req->res.content_length = 0;
	req->res.mime_attr = mime_attr;


	/* del data */
	struct json_object *jobj;
	struct json_object_iterator it;
	struct json_object_iterator itEnd;
	size_t rlen;
	char *key;
	char *value;

    param *pkey = param_find(H2O_STRLIT("key"), self->query_params);
    if (pkey != NULL) {
		log_trace(lg, "KV DEL found key");
		err = objio_kvdel(self->ss->ci, pkey->val.base, pkey->val.len);
		if (err) {
			log_error(lg, "KV DEL error: %d", err);
			h2o_send_error_500(req, "Server error", "please try again later", 0);
			do_close(&self->super, req);
			return;
		}
		request_end(req, self, 1);
		return;
    }

	rlen = self->bytesleft;
	if (rlen == 0) {
		request_end(req, self, 0);
		return;
	}

	int content_type = get_content_type(self);

	if (content_type == CONTENT_UNKNOWN) {
		err = -EINVAL;
		log_error(lg, "KV DEL no content");
		h2o_send_error_400(req, "Bad request", "no content/type", 0);
		do_close(&self->super, req);
		return;
	}

	char *buf = h2o_mem_alloc_pool(&req->pool, char, rlen + 1);
	memcpy(buf, self->buf, rlen);
	buf[rlen] = '\0';
	log_trace(lg, "KV DEL rlen: %lu", rlen);

	if (content_type ==  CONTENT_JSON) {
		jobj = json_tokener_parse(buf);
		if (!jobj) {
			log_error(lg, "KV DEL json parse error");
			h2o_send_error_400(req, "Bad request", "json parse error", 0);
			do_close(&self->super, req);
			return;
		}
		it = json_object_iter_begin(jobj);
		itEnd = json_object_iter_end(jobj);

		int n = 0;
		while (!json_object_iter_equal(&it, &itEnd)) {
			key = (char *)json_object_iter_peek_name(&it);
			log_trace(lg, "KV DEL key %s", key);
			err = objio_kvdel(self->ss->ci, key, strlen(key));
			if (err) {
				log_error(lg, "KV DEL error: %d", err);
				h2o_send_error_500(req, "Server error", "please try again later", 0);
				do_close(&self->super, req);
				return;
			}
			n++;
			json_object_iter_next(&it);
		}

		json_object_put(jobj);
		request_end(req, self, n);
		return;
	}

	if (content_type == CONTENT_CSV) {
		log_trace(lg, "KV DEL text/csv case: %s", buf);

	    char *p, *value, *token = NULL, *sptr = NULL;
	    int n = 0;

	    p = buf;
	    while (1) {
		    token = strtok_r(p, "\n", &sptr);
		    if (token == NULL)
			    break;
		    value = strstr(token,";");
		    if (value) {
			    *value = '\0';
		    }
		    log_trace(lg, "KV DEL %s", token);
		    err = objio_kvdel(self->ss->ci, token, strlen(token));
		    if (err) {
			    log_error(lg, "KV DEL error: %d", err);
			    h2o_send_error_500(req, "Server error", "please try again later", 0);
			    do_close(&self->super, req);
			    return;
		    }
		    n++;
		    p = NULL;
	    }

	    request_end(req, self, n);
	    return;
	}


	log_error(lg, "KV DEL invalid content/type");
	h2o_send_error_400(req, "Bad request", "invalid content/type", 0);
	do_close(&self->super, req);
	return;

}

void
do_list_kv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr) {

	log_trace(lg, "KV List");

	int err = 0;

	/* link the request */
	self->req = req;
	self->buf = req->entity.base;

	/* setup response */
	req->res.status = 206;

	req->res.content_length = 0;
	req->res.mime_attr = mime_attr;


	char pattern[MAX_ITEM_SIZE] = "";
	char marker[MAX_ITEM_SIZE] = "";
	char **key;
	char **value;
	char *buf, *p;
	int r;
	param *pkey;
	uint32_t total, len = 0;
	uint32_t count = (uint32_t) param_find_long(H2O_STRLIT("maxresults"), 1000, self->query_params);
	int values = (int) param_find_long(H2O_STRLIT("values"), 0, self->query_params);

	pkey = param_find(H2O_STRLIT("key"), self->query_params);
	if (pkey) {
		param_value_str(pkey, marker, MAX_ITEM_SIZE);
	}
	pkey = param_find(H2O_STRLIT("marker"), self->query_params);
	if (pkey) {
		param_value_str(pkey, marker, MAX_ITEM_SIZE);
	}

	pkey = param_find(H2O_STRLIT("pattern"), self->query_params);
	if (pkey) {
		param_value_str(pkey, pattern, MAX_ITEM_SIZE);
	}

	log_trace(lg, "KV list pattern %s, marker: %s values: %d", pattern, marker, values);

	key = h2o_mem_alloc_pool(&req->pool, char*, count);
	value = h2o_mem_alloc_pool(&req->pool, char*, count);

	if (values) {
		err = objio_kvlist(self->ss->ci, pattern, marker, key, value, &count, &total);
	} else { // keys only
		err = objio_kvlist_keys(self->ss->ci, pattern, marker, key, &count, &total);
	}
	if (err && err != -ENOENT) {
		log_error(lg, "KV List error: %d", err);
		h2o_send_error_500(req, "Server error", "please try again later", 0);
		do_close(&self->super, req);
		return;
	}

	log_trace(lg, "KV List count: %u, total: %u", count, total);

	if (count == 0 || err == -ENOENT) {
		request_end(req, self, 0);
		return;
	}

	int content_type = get_content_type(self);

    if (content_type == CONTENT_JSON) {
        buf = h2o_mem_alloc_pool(&req->pool, char, (6 + count*6 + total));
        if (values) {
            p = buf; *p = '{';p++;len++;
            for (unsigned int i=0; i<count; i++) {
                log_trace(lg, "kvlist %s -> %s", key[i], value[i]);
                r = sprintf(p,"\"%s\":\"%s\",",key[i], value[i]);
                p += r;
                len += r;
            }
            p--; *p = '}';
        } else {
            p = buf; *p = '[';p++;len++;
            for (unsigned int i=0; i<count; i++) {
                log_trace(lg, "kvlist key %s", key[i]);
                r = sprintf(p,"\"%s\",",key[i]);
                p += r;
                len += r;
            }
            p--; *p = ']';
        }
        log_trace(lg, "KV List json len: %d", len);
    } else if (content_type == CONTENT_OCTET) {
		if (values) {
			buf = h2o_mem_alloc_pool(&req->pool, char, (1 + total));
			len = sprintf(buf,"%s", value[0]);
		} else {
	        buf = h2o_mem_alloc_pool(&req->pool, char, (2 + count*2 + total));
			p = buf;
            for (unsigned int i=0; i<count; i++) {
                log_trace(lg, "kvlist key %s", key[i]);
                r = sprintf(p,"%s\n", key[i]);
                p += r;
                len += r;
            }
		}
		log_info(lg, "KV List len: %d", len);
	} else { // if (content_type == CONTENT_CSV || content_type == CONTENT_UNKNOWN) {
		buf = h2o_mem_alloc_pool(&req->pool, char, (6 + count*6 + total));
		p = buf;
		if (values) {
			for (unsigned int i=0; i<count; i++) {
				log_trace(lg, "kvlist %s -> %s", key[i], value[i]);
				char *v = value[i];
				if (strstr(v,",") || strstr(v,"\n") || strstr(v,"\"\"")) {
					r = sprintf(p,"%s;\"%s\"\n",key[i], v);
				} else {
					r = sprintf(p,"%s;%s\n",key[i], v);
				}
				p += r;
				len += r;
			}
		} else { // keys only
			for (unsigned int i=0; i<count; i++) {
				log_trace(lg, "kvlist key %s", key[i]);
				r = sprintf(p,"%s\n",key[i]);
				p += r;
				len += r;
			}
		}
		log_trace(lg, "KV List csv len: %d", len);
	}


	/* send data */
	self->buf = buf;
	self->bytesleft = len;
	req->res.content_length = len;
	h2o_start_response(req, &self->super);
	do_kvlist_proceed(&self->super, req);

	// free key/value
	for (unsigned int i=0; i<count; i++) {
		je_free(key[i]);
		if (values)
			je_free(value[i]);
	}
}

static char*
alloc_buffer(void *arg, uint32_t size) {
    return h2o_mem_alloc_pool(arg, char, size);
}

void
do_get_kv(ccowobj_generator_t *self, h2o_req_t *req,
    h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr) {

	log_trace(lg, "KV get");

	int err = 0;

	/* link the request */
	self->req = req;
	self->buf = req->entity.base;

	/* setup response */
	req->res.status = 200;

	req->res.content_length = 0;
	req->res.mime_attr = mime_attr;


	char key[MAX_ITEM_SIZE] = "";
	char *value = NULL;

	param *pkey = param_find(H2O_STRLIT("key"), self->query_params);

	if (pkey == NULL) {
		err = -EINVAL;
		log_error(lg, "KV get no key");
		h2o_send_error_400(req, "Bad request", "no key", 0);
		do_close(&self->super, req);
		return;
	}


	param_value_str(pkey, key, MAX_ITEM_SIZE);
	log_trace(lg, "KV get key %s", key);


	h2o_iovec_t vec;
	uint32_t nout = 0;
	char content_type[MAX_ITEM_SIZE];

	err =  objio_kvget(self->ss->ci, key, &req->pool, alloc_buffer,
		&value, &nout, content_type, MAX_ITEM_SIZE);
	if (err && err != -ENOENT) {
		log_error(lg, "KV get error: %d", err);
		h2o_send_error_500(req, "Server error", "please try again later", 0);
		do_close(&self->super, req);
		return;
	}

	log_trace(lg, "KV get err: %d, nout: %u", err, nout);
	if (err == -ENOENT) {
		h2o_send_error_404(req, "Not found", "no key", 0);
		do_close(&self->super, req);
		return;
	}

	log_trace(lg, "key %s, value len: %d", key, nout);

	/* send data */
	self->bytesleft = nout;
	req->res.content_length = nout;

	/* send (and close if done) */
	vec.base = value;
	vec.len = self->bytesleft;

	if (content_type[0] != '\0') {
		log_trace(lg, "key %s, add record content type: %s", key, content_type);
		h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL,
			content_type, strlen(content_type));
	} else if (self->ss->ci->content_type[0] != '\0') {
		log_trace(lg, "key %s, add common content type: %s", key, self->ss->ci->content_type);
		h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL,
			self->ss->ci->content_type, strlen(self->ss->ci->content_type));
	} else {
		log_trace(lg, "key %s, content type unknown", key);
	}

	static h2o_generator_t generator = {NULL, NULL};
	h2o_start_response(req, &generator);
	h2o_send(req, &vec, 1, H2O_SEND_STATE_FINAL);
	do_close(&self->super, req);
}
