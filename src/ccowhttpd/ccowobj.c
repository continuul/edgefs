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

#include "ccowutil.h"
#include "ccow.h"
#include "h2o.h"
#include "ccowobj.h"
#include "objio.h"
#include "session.h"
#include "session_cache.h"
#include "request_util.h"
#include "ccowobj_generator.h"
#include "request.h"
#include "libauth/user.h"
#include "libauth/auth.h"
#include "s3_generator.h"
#include <sig2auth.h>
#include <sig4auth.h>

#include "templates.c.h"

static int
tm_is_lessthan(struct tm *x, struct tm *y)
{
#define CMP(f) \
	if (x->f < y->f) \
	return 1; \
	else if (x->f > y->f) \
	return 0;
	CMP(tm_year);
	CMP(tm_mon);
	CMP(tm_mday);
	CMP(tm_hour);
	CMP(tm_min);
	CMP(tm_sec);
	return 0;
#undef CMP
}

#define MAX_AUTH_SIZE 8192


static int
send_dir_listing(h2o_req_t *req, struct objio_info *ci, int is_get)
{
	static h2o_generator_t generator = {NULL, NULL};
	DIR *dp;
	h2o_buffer_t *body;
	h2o_iovec_t bodyvec;
	ccow_completion_t comp;
	int err;

	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &comp);
	if (err) {
		return -1;
	}

	/* build html */
	if ((dp = opendir(ci->bid)) == NULL)
		return -1;
	body = build_dir_listing_html(&req->pool, req->path_normalized, dp);
	closedir(dp);

	bodyvec = h2o_iovec_init(body->bytes, body->size);
	h2o_buffer_link_to_pool(body, &req->pool);

	/* send response */
	req->res.status = 200;
	req->res.reason = "OK";
	h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, H2O_STRLIT("text/html; charset=utf-8"));

	/* send headers */
	if (!is_get) {
		h2o_send_inline(req, NULL, 0);
		return 0;
	}

	/* send data */
	h2o_start_response(req, &generator);
	h2o_send(req, &bodyvec, 1, H2O_SEND_STATE_FINAL);
	return 0;
}

static size_t *
process_range(h2o_mem_pool_t *pool, h2o_iovec_t *range_value, size_t file_size, size_t *ret)
{
#define CHECK_EOF() \
	if (buf == buf_end) \
	return NULL;

#define CHECK_OVERFLOW(range) \
	if (range == SIZE_MAX) \
	return NULL;

	size_t range_start = SIZE_MAX, range_count = 0;
	char *buf = range_value->base, *buf_end = buf + range_value->len;
	int needs_comma = 0;
	H2O_VECTOR(size_t) ranges = {NULL};

	if (range_value->len < 6 || memcmp(buf, "bytes=", 6) != 0)
		return NULL;

	buf += 6;
	CHECK_EOF();

	/* most range requests contain only one range */
	do {
		while (1) {
			if (*buf != ',') {
				if (needs_comma)
					return NULL;
				break;
			}
			needs_comma = 0;
			buf++;
			while (H2O_UNLIKELY(*buf == ' ') || H2O_UNLIKELY(*buf == '\t')) {
				buf++;
				CHECK_EOF();
			}
		}
		if (H2O_UNLIKELY(buf == buf_end))
			break;
		if (H2O_LIKELY((range_start = h2o_strtosizefwd(&buf, buf_end - buf)) != SIZE_MAX)) {
			CHECK_EOF();
			if (*buf++ != '-')
				return NULL;
			range_count = h2o_strtosizefwd(&buf, buf_end - buf);
			if (H2O_UNLIKELY(range_start >= file_size)) {
				range_start = SIZE_MAX;
			} else if (H2O_LIKELY(range_count != SIZE_MAX)) {
				if (H2O_UNLIKELY(range_count > file_size - 1))
					range_count = file_size - 1;
				if (H2O_LIKELY(range_start <= range_count))
					range_count -= range_start - 1;
				else
					range_start = SIZE_MAX;
			} else {
				range_count = file_size - range_start;
			}
		} else if (H2O_LIKELY(*buf++ == '-')) {
			CHECK_EOF();
			range_count = h2o_strtosizefwd(&buf, buf_end - buf);
			if (H2O_UNLIKELY(range_count == SIZE_MAX))
				return NULL;
			if (H2O_LIKELY(range_count != 0)) {
				if (H2O_UNLIKELY(range_count > file_size))
					range_count = file_size;
				range_start = file_size - range_count;
			} else {
				range_start = SIZE_MAX;
			}
		} else {
			return NULL;
		}

		if (H2O_LIKELY(range_start != SIZE_MAX)) {
			h2o_vector_reserve(pool, &ranges, ranges.size + 2);
			ranges.entries[ranges.size++] = range_start;
			ranges.entries[ranges.size++] = range_count;
		}
		if (buf != buf_end)
			while (H2O_UNLIKELY(*buf == ' ') || H2O_UNLIKELY(*buf == '\t')) {
				buf++;
				CHECK_EOF();
			}
		needs_comma = 1;
	} while (H2O_UNLIKELY(buf < buf_end));
	*ret = ranges.size / 2;
	return ranges.entries;
#undef CHECK_EOF
#undef CHECK_OVERFLOW
}

static void
gen_rand_string(h2o_iovec_t *s)
{
	unsigned i;
	static const char alphanum[] = "0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (i = 0; i < s->len; ++i) {
		s->base[i] = alphanum[h2o_rand() % (sizeof(alphanum) - 1)];
	}

	s->base[s->len] = 0;
}

static int
delegate_dynamic_request(h2o_req_t *req, const char *local_path, size_t local_path_len,
    h2o_mimemap_type_t *mime_type)
{
	h2o_filereq_t *filereq;
	h2o_handler_t *handler;

	assert(mime_type->data.dynamic.pathconf.handlers.size == 1);

	filereq = h2o_mem_alloc_pool(&req->pool, *filereq, 1);
	filereq->local_path = h2o_strdup(&req->pool, local_path, local_path_len);

	h2o_req_bind_conf(req, req->hostconf, &mime_type->data.dynamic.pathconf);
	req->filereq = filereq;

	handler = mime_type->data.dynamic.pathconf.handlers.entries[0];
	return handler->on_req(handler, req);
}

static int
try_dynamic_request(ccowobj_handler_t *self, h2o_req_t *req, char *rpath, size_t rpath_len)
{
	/* we have full local path in {rpath,rpath_len}, and need to split it into name and path_info */
	struct stat st;
	size_t slash_at = self->tenant_path.len;

	while (1) {
		/* find the next slash (or return -1 if failed) */
		for (++slash_at;; ++slash_at) {
			if (slash_at >= rpath_len)
				return -1;
			if (rpath[slash_at] == '/')
				break;
		}
		/* change the slash to '\0', and check if the file exists */
		rpath[slash_at] = '\0';
		if (stat(rpath, &st) != 0)
			return -1;
		if (!S_ISDIR(st.st_mode))
			break;
		/* restore slash, and continue the search */
		rpath[slash_at] = '/';
	}

	/* file found! */
	h2o_mimemap_type_t *mime_type = h2o_mimemap_get_type_by_extension(self->mimemap, h2o_get_filext(rpath, slash_at));
	switch (mime_type->type) {
	case H2O_MIMEMAP_TYPE_MIMETYPE:
		return -1;
	case H2O_MIMEMAP_TYPE_DYNAMIC:
		return delegate_dynamic_request(req, rpath, slash_at, mime_type);
	}
	log_error(lg, "unknown h2o_miemmap_type_t::type (%d)", (int)mime_type->type);
	abort();
}

static void
send_method_not_allowed(h2o_req_t *req)
{
	h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ALLOW, NULL, H2O_STRLIT("GET, HEAD"));
	h2o_send_error_405(req, "Method Not Allowed", "method not allowed", H2O_SEND_ERROR_KEEP_HEADERS);
}

static int
serve_with_generator(ccowobj_generator_t *generator, h2o_req_t *req,
    int method_type, const char *rpath, size_t rpath_len, h2o_mimemap_type_t *mime_type)
{
	ssize_t if_modified_since_header_index, if_none_match_header_index;
	ssize_t range_header_index;

	log_info(lg, "serve_with_generator request type: %s", REQUEST_STR[generator->ss->request_type]);

	/* obtain mime type */
	if (mime_type->type == H2O_MIMEMAP_TYPE_DYNAMIC) {
		do_close(&generator->super, req);
		return delegate_dynamic_request(req, rpath, rpath_len, mime_type);
	}
	assert(mime_type->type == H2O_MIMEMAP_TYPE_MIMETYPE);

	/* if-non-match and if-modified-since */
	if ((if_none_match_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_NONE_MATCH, SIZE_MAX)) != -1) {
		h2o_iovec_t *if_none_match = &req->headers.entries[if_none_match_header_index].value;
		char etag[H2O_FILECACHE_ETAG_MAXLEN + 1];
//		size_t etag_len = h2o_filecache_get_etag(generator->file.ref, etag);
//		if (h2o_memis(if_none_match->base, if_none_match->len, etag, etag_len)) {
		//	req->res.status = 304;
		//	req->res.reason = "Not Modified";
		//	add_headers_unconditional(generator, req);
		//	h2o_send_inline(req, NULL, 0);
		//}
	} else if ((if_modified_since_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_MODIFIED_SINCE, SIZE_MAX)) != -1) {
		h2o_iovec_t *ims_vec = &req->headers.entries[if_modified_since_header_index].value;
		struct tm ims_tm, *last_modified_tm;
		if (h2o_time_parse_rfc1123(ims_vec->base, ims_vec->len, &ims_tm) == 0) {
//			last_modified_tm = h2o_filecache_get_last_modified(generator->file.ref, NULL);
//			if (!tm_is_lessthan(&ims_tm, last_modified_tm)) {
			//	req->res.status = 304;
			//	req->res.reason = "Not Modified";
			//	add_headers_unconditional(generator, req);
			//	h2o_send_inline(req, NULL, 0);
			//}
		}
	}

	/* only allow GET or POST for static files */
	if (method_type == METHOD_IS_OTHER) {
		do_close(&generator->super, req);
		send_method_not_allowed(req);
		return 0;
	}

	/* if-range */
	if ((range_header_index = h2o_find_header(&req->headers, H2O_TOKEN_RANGE, SIZE_MAX)) != -1) {
		h2o_iovec_t *range = &req->headers.entries[range_header_index].value;
		size_t *range_infos, range_count;
		range_infos = process_range(&req->pool, range, generator->bytesleft, &range_count);
		if (range_infos == NULL) {
			h2o_iovec_t content_range;
			content_range.base = h2o_mem_alloc_pool(&req->pool, char, 32);
			content_range.len = sprintf(content_range.base, "bytes */%zu", generator->bytesleft);
			h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_RANGE, NULL, content_range.base, content_range.len);
			h2o_send_error_416(req, "Request Range Not Satisfiable", "requested range not satisfiable",
			    H2O_SEND_ERROR_KEEP_HEADERS);
			do_close(&generator->super, req);
			return 0;
		}
		generator->ranged.range_count = range_count;
		generator->ranged.range_infos = range_infos;
		generator->ranged.current_range = 0;
		generator->ranged.filesize = generator->bytesleft;

		/* set content-length according to range */
		log_trace(lg, "Range count: %d", (int) range_count);
		if (range_count == 1) { // One range case
			generator->off = range_infos[0];
			generator->bytesleft = range_infos[1];
			log_trace(lg, "Range count == 1, off: %ld, bytesleft: %ld", generator->off, generator->bytesleft);
		} else {
			generator->ranged.mimetype = h2o_strdup(&req->pool, mime_type->data.mimetype.base, mime_type->data.mimetype.len);
			size_t final_content_len = 0, size_tmp = 0, size_fixed_each_part, i;
			generator->ranged.boundary.base = h2o_mem_alloc_pool(&req->pool, char, BOUNDARY_SIZE + 1);
			generator->ranged.boundary.len = BOUNDARY_SIZE;
			gen_rand_string(&generator->ranged.boundary);
			i = generator->bytesleft;
			while (i) {
				i /= 10;
				size_tmp++;
			}
			size_fixed_each_part = FIXED_PART_SIZE + mime_type->data.mimetype.len + size_tmp;
			for (i = 0; i < range_count; i++) {
				size_tmp = *range_infos++;
				if (size_tmp == 0)
					final_content_len++;
				while (size_tmp) {
					size_tmp /= 10;
					final_content_len++;
				}

				size_tmp = *(range_infos - 1);
				final_content_len += *range_infos;

				size_tmp += *range_infos++ - 1;
				if (size_tmp == 0)
					final_content_len++;
				while (size_tmp) {
					size_tmp /= 10;
					final_content_len++;
				}
			}
			final_content_len += sizeof("\r\n--") - 1 + BOUNDARY_SIZE + sizeof("--\r\n") - 1 + size_fixed_each_part * range_count -
				(sizeof("\r\n") - 1);
			generator->bytesleft = final_content_len;
		}
		generator->do_work(generator, req, mime_type->data.mimetype, &h2o_mime_attributes_as_is);
		return 0;
	}

	generator->do_work(generator, req, mime_type->data.mimetype, &mime_type->data.attr);
	return 0;
}


static int
serve_with_s3_generator(s3_generator_t *generator, h2o_req_t *req,
    int method_type, const char *rpath, size_t rpath_len, h2o_mimemap_type_t *mime_type)
{
	ssize_t if_modified_since_header_index, if_none_match_header_index;
	ssize_t range_header_index;

	log_info(lg, "serve_with_s3_generator request type: %s", S3_STR[generator->rq->request_type]);

	/* obtain mime type */
	if (mime_type->type == H2O_MIMEMAP_TYPE_DYNAMIC) {
		do_close(&generator->super, req);
		return delegate_dynamic_request(req, rpath, rpath_len, mime_type);
	}
	assert(mime_type->type == H2O_MIMEMAP_TYPE_MIMETYPE);

	/* if-non-match and if-modified-since */
	if ((if_none_match_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_NONE_MATCH, SIZE_MAX)) != -1) {
		h2o_iovec_t *if_none_match = &req->headers.entries[if_none_match_header_index].value;
		char etag[H2O_FILECACHE_ETAG_MAXLEN + 1];
	} else if ((if_modified_since_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_MODIFIED_SINCE, SIZE_MAX)) != -1) {
		h2o_iovec_t *ims_vec = &req->headers.entries[if_modified_since_header_index].value;
		struct tm ims_tm, *last_modified_tm;
		if (h2o_time_parse_rfc1123(ims_vec->base, ims_vec->len, &ims_tm) == 0) {
//			last_modified_tm = h2o_filecache_get_last_modified(generator->file.ref, NULL);
//			if (!tm_is_lessthan(&ims_tm, last_modified_tm)) {
			//	req->res.status = 304;
			//	req->res.reason = "Not Modified";
			//	add_headers_unconditional(generator, req);
			//	h2o_send_inline(req, NULL, 0);
			//}
		}
	}

	/* only allow GET or POST for static files */
	if (method_type == METHOD_IS_OTHER) {
		do_s3_close(&generator->super, req);
		send_method_not_allowed(req);
		return 0;
	}

	/* if-range */
	if ((range_header_index = h2o_find_header(&req->headers, H2O_TOKEN_RANGE, SIZE_MAX)) != -1) {
		h2o_iovec_t *range = &req->headers.entries[range_header_index].value;
		size_t *range_infos, range_count;
		range_infos = process_range(&req->pool, range, generator->bytesleft, &range_count);
		if (range_infos == NULL) {
			h2o_iovec_t content_range;
			content_range.base = h2o_mem_alloc_pool(&req->pool, char, 32);
			content_range.len = sprintf(content_range.base, "bytes */%zu", generator->bytesleft);
			h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_RANGE, NULL, content_range.base, content_range.len);
			h2o_send_error_416(req, "Request Range Not Satisfiable", "requested range not satisfiable",
			    H2O_SEND_ERROR_KEEP_HEADERS);
			do_s3_close(&generator->super, req);
			return 0;
		}
		generator->ranged.range_count = range_count;
		generator->ranged.range_infos = range_infos;
		generator->ranged.current_range = 0;
		generator->ranged.filesize = generator->bytesleft;

		/* set content-length according to range */
		log_trace(lg, "Range count: %d", (int) range_count);
		if (range_count == 1) { // One range case
			generator->off = range_infos[0];
			generator->bytesleft = range_infos[1];
			log_trace(lg, "Range count == 1, off: %ld, bytesleft: %ld", generator->off, generator->bytesleft);
		} else {
			generator->ranged.mimetype = h2o_strdup(&req->pool, mime_type->data.mimetype.base, mime_type->data.mimetype.len);
			size_t final_content_len = 0, size_tmp = 0, size_fixed_each_part, i;
			generator->ranged.boundary.base = h2o_mem_alloc_pool(&req->pool, char, BOUNDARY_SIZE + 1);
			generator->ranged.boundary.len = BOUNDARY_SIZE;
			gen_rand_string(&generator->ranged.boundary);
			i = generator->bytesleft;
			while (i) {
				i /= 10;
				size_tmp++;
			}
			size_fixed_each_part = FIXED_PART_SIZE + mime_type->data.mimetype.len + size_tmp;
			for (i = 0; i < range_count; i++) {
				size_tmp = *range_infos++;
				if (size_tmp == 0)
					final_content_len++;
				while (size_tmp) {
					size_tmp /= 10;
					final_content_len++;
				}

				size_tmp = *(range_infos - 1);
				final_content_len += *range_infos;

				size_tmp += *range_infos++ - 1;
				if (size_tmp == 0)
					final_content_len++;
				while (size_tmp) {
					size_tmp /= 10;
					final_content_len++;
				}
			}
			final_content_len += sizeof("\r\n--") - 1 + BOUNDARY_SIZE + sizeof("--\r\n") - 1 + size_fixed_each_part * range_count -
				(sizeof("\r\n") - 1);
			generator->bytesleft = final_content_len;
		}
		generator->do_work(generator, req, mime_type->data.mimetype, &h2o_mime_attributes_as_is);
		return 0;
	}

	generator->do_work(generator, req, mime_type->data.mimetype, &mime_type->data.attr);
	return 0;
}


static void send_error(char *module, int err, h2o_req_t *req) {
	if (err == 0)
		return;
	log_error(lg, "Sending error response from %s, error: %d", module, err);
	char buf[2048];
	if (err == -ENOMEM) {
		sprintf(buf, "Out of resources in %s", module);
		h2o_send_error_503(req, "Service Unavailable", buf, 0);
		return;
	}
	if (err == -EINVAL) {
		sprintf(buf, "Bad Request in %s", module);
		h2o_send_error_400(req, "Bad Request", buf, H2O_SEND_ERROR_HTTP1_CLOSE_CONNECTION);
		return;
	}
	sprintf(buf, "Unknown error in %s", module);
	h2o_send_error_500(req, "Service Error", buf, 0);
}

static int get_bid_oid(	char *rpath, char *bid, int *bid_size, char *oid, int *oid_size) {
	int matched = sscanf(rpath, "%2047[^/]/%2047[^\n]", bid, oid);
	if (matched == 2) {
		*bid_size = strlen(bid) + 1;
		*oid_size = strlen(oid) + 1;
	} else if (matched == 1) {
		*bid_size = strlen(bid) + 1;
		oid[0] = 0;
		*oid_size = 1;
	} else {
		bid[0] = 0;
		*bid_size = 1;
		oid[0] = 0;
		*oid_size = 1;
	}
	return 0;
}

static int on_edgex(ccowobj_handler_t *self, h2o_req_t *req,
		int method_type,
		param *comp,
		param_vector *query_params,
		param_vector *headers,
		char *rpath, size_t rpath_len,
		char *bid, int bid_size,
		char *oid, int oid_size) {

	int err = 0;
	char buf[4096];

	uint64_t sid;
	ccowobj_generator_t *generator = NULL;
	session_t *ss = NULL;
	strsess_cache_entry_t *sess_entry = NULL;
	objio_info_t *ci = NULL;
	ccow_t tc;

	// Find session
	sid = param_find_uint64(H2O_STRLIT("x-session-id"), 0, headers);
	log_info(lg, "Find session sid: %lu in params", sid);
	if (sid > 0) {
		int res = strsess_cache_lookup(sess_cache, &sid, &sess_entry);
		log_info(lg, "Session lookup sid: %lu, res: %d", sid, res);
		if (res == 0 && sess_entry) {
			ss = sess_entry->ss;
			err = session_update(comp, method_type, query_params, headers, sess_entry->ss, 1);
			if (err) {
				send_error("Update session", err, req);
				goto _exit;
			}
			log_info(lg, "Reuse session sid: %lu", sid);
			session_dump("Reuse session", ss);
			add_response_header_uint64(req, "x-session-id", ss->sid);
		}
	}

	tc = h2o_context_get_handler_context(req->conn->ctx, &self->super);

	if (!sess_entry) { // Create new IO object
		log_info(lg, "Create io object");
		err = objio_create(tc, self->tenant_path.base, self->tenant_path.len, bid, bid_size, oid, oid_size,
				CCOW_STREAMSESSION_MAXOPTS, &ci);
		if (err) {
			send_error("Create io", err, req);
			goto _exit;
		}
		// Create session
		err = session_create(ci, comp, method_type, query_params, headers, &ss);
		if (err) {
			send_error("Create session", err, req);
			goto _exit;
		}

		if (!session_ending(ss)) {
			err = strsess_cache_insert(sess_cache, STRSESS_CACHE_TIMEOUT_S, &sess_entry);
			if (err) {
				send_error("Session cache", err, req);
				goto _exit;
			}
			ss->sid = sess_entry->sid;
			sess_entry->ss = ss;
			session_dump("New session for reuse", ss);

			add_response_header_uint64(req, "x-session-id", ss->sid);
		} else {
			session_dump("New session for request", ss);
		}
	}

	h2o_timestamp_t ts;
	h2o_get_timestamp(req->conn->ctx, &req->pool, &ts);
	h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_DATE, NULL, ts.str->rfc1123, strlen(ts.str->rfc1123));

	errno = create_generator(req, query_params, headers, ss, self->flags, &generator);
	if (errno == 0) {
		return serve_with_generator(generator, req, method_type, rpath, rpath_len,
				h2o_mimemap_get_type_by_extension(self->mimemap, h2o_get_filext(rpath, rpath_len)));
	}

	// Error flow
	log_info(lg, "Create generator error: %d", errno);
	if (errno == -ENOMEM) {
		h2o_send_error_503(req, "Service Unavailable", "please try again later", 0);
	} else if (errno == -ENOENT) {
		h2o_send_error_404(req, "Object not found", "please correct request", 0);
	} else if (errno == -EINVAL) {
		h2o_send_error_400(req, "Bad request", "please correct request", 0);
	} else if (errno == -EINVAL) {
		h2o_send_error_400(req, "Bad request", "please correct request", 0);
	} else {
		h2o_send_error_500(req, "Server error", "please try again later", 0);
	}

_exit: if (query_params)
		param_free(query_params);
	if (headers)
		param_free(headers);
	if (ss) {
		if (strsess_cache_remove(sess_cache, &ss->sid) != 0) {
			session_close(ss);
			session_destroy(ss);
		}
	} else if (ci) {
		objio_destroy(ci);
	}
	return err;
}


static int on_s3(ccowobj_handler_t *self, h2o_req_t *req,
		int method_type,
		param_vector *query_params,
		param_vector *headers,
		char *rpath, size_t rpath_len,
		char *bid, int bid_size,
		char *oid, int oid_size) {

	int err = 0;

	s3_generator_t *generator = NULL;
	request_t *rq = NULL;
	objio_info_t *ci = NULL;
	ccow_t tc;

	// Find context
	tc = h2o_context_get_handler_context(req->conn->ctx, &self->super);

	log_info(lg, "Create io object");
	err = objio_create(tc, self->tenant_path.base, self->tenant_path.len,
			bid, bid_size, oid, oid_size, CCOW_STREAMSESSION_MAXOPTS, &ci);
	if (err) {
		send_error("Create io", err, req);
		goto _exit;
	}

	// Create request
	err = request_create(req, ci, method_type, query_params, headers, &rq);
	if (err) {
		send_error("Create request", err, req);
		goto _exit;
	}

	h2o_timestamp_t ts;
	h2o_get_timestamp(req->conn->ctx, &req->pool, &ts);
	h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_DATE, NULL, ts.str->rfc1123, strlen(ts.str->rfc1123));

	errno = create_s3_generator(req, query_params, headers, rq, self->flags, &generator);
	if (errno == 0) {
		return serve_with_s3_generator(generator, req, method_type, rpath, rpath_len,
				h2o_mimemap_get_type_by_extension(self->mimemap, h2o_get_filext(rpath, rpath_len)));
	}

	// Error flow
	log_info(lg, "Create generator error: %d", errno);
	if (errno == -ENOMEM) {
		h2o_send_error_503(req, "Service Unavailable", "please try again later", 0);
	} else if (errno == -ENOENT) {
		h2o_send_error_404(req, "Not found", "please correct request", 0);
	} else if (errno == -EINVAL) {
		h2o_send_error_400(req, "Bad request", "please correct request", 0);
	} else if (errno == -EINVAL) {
		h2o_send_error_400(req, "Bad request", "please correct request", 0);
	} else {
		h2o_send_error_500(req, "Server error", "please try again later", 0);
	}

_exit: if (query_params)
		param_free(query_params);
	if (headers)
		param_free(headers);
	if (rq) {
		request_close(rq);
		request_destroy(rq);
	} else if (ci) {
		objio_destroy(ci);
	}
	return err;
}

static int
query_authentication(ccowobj_handler_t *self, h2o_req_t *req,
		param_vector *query_params, param_vector *headers,
		int method_type, char *rpath, User **user) {

	char key_str[MAX_ITEM_SIZE];
	char expected_str[MAX_ITEM_SIZE];
	char signature[MAX_SIGNATURE_LENGTH];
	int err;

	log_trace(lg, "Query authentication");

	param *key = param_find(H2O_STRLIT("AWSAccessKeyId"), query_params);
	param *expected = param_find(H2O_STRLIT("Signature"), query_params);

	param_value_str(key, key_str, MAX_ITEM_SIZE - 1);
	param_value_str(expected, expected_str, MAX_ITEM_SIZE - 1);
	int res = uri_unescape(expected_str, strlen(expected_str));
	if (res < 0) {
		log_error(lg, "Invalid signature %s", param_str(expected, expected_str, MAX_ITEM_SIZE - 1));
		h2o_send_error_403(req, "Forbidden", "Invalid signature", 0);
		return -EINVAL;
	}
	expected_str[res] = 0;

	log_trace(lg, "Key: %s", key_str);
	err = get_user_by_authkey(self->cid, self->tid, key_str, user);
	if (err) {
		log_error(lg, "User %s not found", key_str);
		h2o_send_error_403(req, "Forbidden", "User not found", 0);
		return -EINVAL;
	}
	const char *secret = user_property_string(*user, "secret", NULL);
	if (secret == NULL) {
		log_error(lg, "User %s invalid", key_str);
		h2o_send_error_403(req, "Forbidden", "User invalid", 0);
		return -EINVAL;
	}

	err = query_sign_request(query_params,
			(char *) METHOD_STR[method_type],
			rpath,
			(char *)secret,
			signature,
			MAX_ITEM_SIZE);
	if (err) {
		log_error(lg, "Could not sign");
		h2o_send_error_403(req, "Forbidden", "Could not sign", 0);
		return -EINVAL;
	}

	log_trace(lg, "Expected: %s", expected_str);
	log_trace(lg, "Signature: %s", signature);
	if (strcmp(signature, expected_str) != 0) {
		log_error(lg, "Unexpected signature query");
		h2o_send_error_403(req, "Forbidden", "Unexpected signature", 0);
		return -EINVAL;
	}
	return 0;
}


static int
version2_authentication(ccowobj_handler_t *self, h2o_req_t *req,
		param_vector *query_params, param_vector *headers,
		int method_type, char *rpath, char *auth_str, User **user) {

	char expected_str[MAX_ITEM_SIZE];
	char signature[MAX_SIGNATURE_LENGTH];
	int err;

	log_trace(lg, "Version 2 authentication");
	char *key = auth_str + 4;
	char *expected;
	char *p = strstr(auth_str, ":");
	if (p == NULL) {
		log_error(lg, "Invalid authorization %s", auth_str);
		h2o_send_error_403(req, "Forbidden", "Invalid authorization", 0);
		return -EINVAL;
	}
	expected = p + 1;
	*p = 0;
	log_trace(lg, "Key: %s", key);

	err = get_user_by_authkey(self->cid, self->tid, key, user);
	if (err) {
		log_error(lg, "User %s not found", key);
		h2o_send_error_403(req, "Forbidden", "User not found", 0);
		return -EINVAL;
	}
	const char *secret = user_property_string(*user, "secret", NULL);
	if (secret == NULL) {
		log_error(lg, "User %s invalid, no secret", key);
		h2o_send_error_403(req, "Forbidden", "User invalid", 0);
		return -EINVAL;
	}

	err = sig2auth_sign_request(query_params,
			headers,
			(char *) METHOD_STR[method_type],
	        rpath,
		    (char *)secret,
			signature,
			MAX_SIGNATURE_LENGTH);
	if (err) {
		log_error(lg, "Could not sign");
		h2o_send_error_403(req, "Forbidden", "Could not sign", 0);
		return -EINVAL;
	}

	log_trace(lg, "Expected: %s", expected);
	log_trace(lg, "Signature: %s", signature);
	if (strcmp(signature, expected) != 0) {
		log_error(lg, "Unexpected signature v2");
		h2o_send_error_403(req, "Forbidden", "Unexpected signature", 0);
		return -EINVAL;
	}
	return 0;
}


static int
version4_authentication(ccowobj_handler_t *self, h2o_req_t *req,
		param_vector *query_params, param_vector *headers,
		int method_type, char *rpath, char *auth_str, User **user) {

	char signature[MAX_SIGNATURE_LENGTH];
	int err;

	log_trace(lg, "Version 4 authentication");

	char *credential_scope = strstr(auth_str, "Credential=");
	char *signedHeaders = strstr(auth_str, "SignedHeaders=");
	char *expected = strstr(auth_str, "Signature=");
	char key[MAX_ITEM_SIZE];
	char *p;

	if (credential_scope == NULL || signedHeaders == NULL || expected == NULL) {
		log_error(lg, "Invalid authorization %s", auth_str);
		h2o_send_error_403(req, "Forbidden", "Invalid authorization", 0);
		return -EINVAL;
	}

	p = strstr(credential_scope, ",");
	if (p == NULL) {
		log_error(lg, "Invalid authorization %s", auth_str);
		h2o_send_error_403(req, "Forbidden", "Invalid authorization", 0);
		return -EINVAL;
	}
	*p = 0;
	credential_scope += strlen("Credential=");
	p = strstr(credential_scope, "/");
	if (p == NULL) {
		log_error(lg, "Invalid authorization %s", auth_str);
		h2o_send_error_403(req, "Forbidden", "Invalid authorization", 0);
		return -EINVAL;
	}
	memcpy(key, credential_scope, (p - credential_scope));
	key[p - credential_scope] = 0;
	credential_scope = p + 1;

	p = strstr(signedHeaders, ",");
	if (p == NULL) {
		log_error(lg, "Invalid authorization %s", auth_str);
		h2o_send_error_403(req, "Forbidden", "Invalid authorization", 0);
		return -EINVAL;
	}
	*p = 0;
	signedHeaders += strlen("SignedHeaders=");

	expected += strlen("Signature=");


// Credential=PTAA8RZIP6WJP5SRH2MS/20180214/us-west-1/s3/aws4_request,
// SignedHeaders=host;x-amz-content-sha256;x-amz-date
//,Signature=fd3560cd198508e84b665b86626593d1b2d9f89a5b322c61438b6c5df2d54de9"

	log_trace(lg, "credential_scope: %s", credential_scope);
	log_trace(lg, "signedHeaders   : %s", signedHeaders);
	log_trace(lg, "auth  key       : %s", key);
	log_trace(lg, "region          : %s", self->region);

	err = get_user_by_authkey(self->cid, self->tid, key, user);
	if (err) {
		log_error(lg, "User %s not found", key);
		h2o_send_error_403(req, "Forbidden", "User not found", 0);
		return -EINVAL;
	}
	const char *secret = user_property_string(*user, "secret", NULL);
	if (secret == NULL) {
		log_error(lg, "User %s invalid, no secret", key);
		h2o_send_error_403(req, "Forbidden", "User invalid", 0);
		return -EINVAL;
	}
	log_trace(lg, "secret  key       : %s", secret);

	err =  sig4auth_sign_request(&req->pool, query_params, headers,
			(char *) METHOD_STR[method_type],
			rpath,
			credential_scope,
			signedHeaders,
			(char *)secret,
			self->region,
			signature, MAX_SIGNATURE_LENGTH);
	if (err) {
		log_error(lg, "Could not sign");
		h2o_send_error_403(req, "Forbidden", "Could not sign", 0);
		return -EINVAL;
	}

	log_trace(lg, "Expected: %s", expected);
	log_trace(lg, "Signature: %s", signature);
	if (strcmp(signature, expected) != 0) {
		log_error(lg, "Unexpected signature v4");
		h2o_send_error_403(req, "Forbidden", "Unexpected signature", 0);
		return -EINVAL;
	}

	return 0;
}


static int
on_req(h2o_handler_t *_self, h2o_req_t *req)
{
	ccowobj_handler_t *self = (void *)_self;
	char *rpath;
	size_t rpath_len, req_path_prefix;
	h2o_iovec_t query = {NULL, 0};
	param_vector *query_params = NULL;
	param_vector *headers = NULL;
	param *comp;
	param *auth = NULL;
	char auth_str[MAX_AUTH_SIZE];

	int err = 0;
	char buf[4096];
	char bid[2048];
	char oid[2048];
	int bid_size, oid_size;
	char host[MAX_ITEM_SIZE];

	add_headers_unconditional(req);

	if (req->path_normalized.len < self->conf_path.len) {
		h2o_iovec_t dest = h2o_uri_escape(&req->pool, self->conf_path.base, self->conf_path.len, "/");
		if (req->query_at != SIZE_MAX)
			dest = h2o_concat(&req->pool, dest, h2o_iovec_init(req->path.base + req->query_at, req->path.len - req->query_at));
		h2o_send_redirect(req, 301, "Moved Permanently", dest.base, dest.len);
		return 0;
	}

	if (req->query_at != SIZE_MAX) {
		query = h2o_iovec_init(&req->path.base[req->query_at + 1], req->path.len - req->query_at - 1);
	}


	// Parse query
	query_params = h2o_mem_alloc_pool(&req->pool, param_vector, 1);
	query_parse(&req->pool, &query, query_params);
	param_dump("query", query_params);

	// Parse headers
	headers = h2o_mem_alloc_pool(&req->pool, param_vector, 1);
	err = headers_parse(&req->pool, &req->headers, headers);
	if (err < 0) {
		h2o_send_error_400(req, "Invalid", "Invalid headers", 0);
		goto _exit;
	}

	// Add Host
	if (str_iovec(req->input.authority, host, MAX_ITEM_SIZE) != 0) {
		log_error(lg, "Invalid host");
		h2o_send_error_400(req, "Invalid", "Invalid host", 0);
		goto _exit;
	}
	err = param_add(PARAM_STR("host"), PARAM_STR(host), headers);
	param_dump("headers", headers);

	/* build path */
	req_path_prefix = self->conf_path.len;
	if (self->subdomains) {
		char *p = strstr(host, ".");
		if (p == NULL) {
			log_error(lg, "Invalid host header");
			h2o_send_error_400(req, "Invalid", "Invalid host header", 0);
			goto _exit;
		}
		int lbucket = (p - host);
		rpath = alloca(self->tenant_path.len + (req->path_normalized.len - req_path_prefix) + 1 + lbucket + 1);
		memcpy(rpath, host, lbucket);
		rpath[lbucket] = '/';
		memcpy(rpath + (lbucket+1), req->path_normalized.base + req_path_prefix, req->path_normalized.len - req_path_prefix);
		rpath_len = req->path_normalized.len - req_path_prefix + lbucket + 1;
		rpath[rpath_len] = '\0';
		log_trace(lg, "subdomain rpath: %s", rpath);
	} else {
		rpath = alloca(self->tenant_path.len + (req->path_normalized.len - req_path_prefix) + 1);
		memcpy(rpath, req->path_normalized.base + req_path_prefix, req->path_normalized.len - req_path_prefix);
		rpath_len = req->path_normalized.len - req_path_prefix;
		rpath[rpath_len] = '\0';
		log_trace(lg, "rpath: %s", rpath);
	}


	// Get bid/oid
	err = get_bid_oid(rpath, bid, &bid_size, oid, &oid_size);
	if (err != 0) {
		h2o_send_error_400(req, "Invalid", "Invalid path encoding", 0);
		goto _exit;
	}

	log_trace(lg, "bid: %s, oid: %s", bid, oid);


	// Method
	int method_type = get_method_type(req);
	auth = param_find(H2O_STRLIT("authorization"), headers);
	param_value_str(auth, auth_str, MAX_AUTH_SIZE - 1);

	log_trace(lg, "Host: %s, %s/%s Method: %s Authorization: %s",
			host, self->cid, self->tid, METHOD_STR[method_type], auth_str);

	// Operation
	char operation[64];
	get_operation_type(method_type, bid, query_params, operation);
	log_info(lg, "Operation: %s", operation);

	User *user = NULL;
	ACL *acl;


	// Public check
	if (self->aclOn) {
		err = get_access(self->cid, self->tid, bid, oid, operation, user, &acl);
		if (err != 0) {
			if (self->authOn)
				goto _auth;
			log_error(lg, "Public access denied err: %d", err);
			h2o_send_error_403(req, "Forbidden", "Access denied", 0);
			goto _exit;
		}
		goto _public;
	}

_auth:
	// Auth check
	if (self->authOn) {
		log_info(lg, "Auth check");
		if (param_has(H2O_STRLIT("AWSAccessKeyId"), query_params) &&
			param_has(H2O_STRLIT("Expires"), query_params) &&
			param_has(H2O_STRLIT("Signature"), query_params)) {
			err = query_authentication(self, req, query_params, headers,
					method_type, rpath, &user);
			if (err) {
				goto _exit;
			}
		} else if (auth && strncmp(auth_str, "AWS ", 4) == 0) {
			err = version2_authentication(self, req, query_params, headers,
					method_type, rpath, auth_str, &user);
			if (err) {
				goto _exit;
			}
		} else if (auth && strncmp(auth_str, "AWS4-HMAC-SHA256 ", 17) == 0) {
			err = version4_authentication(self, req, query_params, headers,
					method_type, rpath, auth_str, &user);
			if (err) {
				goto _exit;
			}
		} else {
			log_error(lg, "No signature");
			h2o_send_error_403(req, "Forbidden", "No signature", 0);
			goto _exit;
		}
	}


	// ACL check
	if (self->aclOn) {
		err = get_access(self->cid, self->tid, bid, oid, operation, user, &acl);
		if (err != 0) {
			log_error(lg, "Access denied err: %d", err);
			h2o_send_error_403(req, "Forbidden", "Access denied", 0);
			goto _exit;
		}
	}

_public:

	/* test for ?comp= and redirect to slow path if not */
	comp = param_find(H2O_STRLIT("comp"), query_params);
	if (comp) {
		log_info(lg, "Edgex process -->");
		return on_edgex(self, req, method_type, comp, query_params, headers,
				rpath, rpath_len, bid, bid_size, oid, oid_size);
	}

	int request_type = get_request_type(query_params, method_type, bid, bid_size, oid, oid_size);
	log_info(lg, "S3 request type: %d", request_type);
	if (request_type < S3_GET_ACL) {
		log_info(lg, "S3 process -->");
		return on_s3(self, req, method_type, query_params, headers,
				rpath, rpath_len, bid, bid_size, oid, oid_size);
	}

	log_info(lg, "delegate -->");
	h2o_delegate_request(req);

_exit:
	if (query_params)
		param_free(query_params);
	if (headers)
		param_free(headers);
	return 0;
}


static void
on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
	ccowobj_handler_t *self = (void *)_self;
	ccow_t tc;

	log_trace(lg, "%s", self->tenant_path.base);

	if (sscanf(self->tenant_path.base, "%2047[^/]/%2047[^/]", self->cid, self->tid) < 2) {
		log_error(lg, "open error: wrong ccow backing store format, expecting cluster/tenant");
		return;
	}
	self->cid_size = strlen(self->cid) + 1;
	self->tid_size = strlen(self->tid) + 1;

	int fd = open("/opt/nedge/etc/ccow/ccow.json", O_RDONLY);
	char *buf = je_calloc(1, 16384);
	ssize_t count = read(fd, buf, 16383);
	if (count <= 0) {
		close(fd);
		log_error(lg, "read error: /opt/nedge/etc/ccow/ccow.json");
		return;
	}
	close(fd);
	int err = ccow_tenant_init(buf, self->cid, self->cid_size, self->tid, self->tid_size, &tc);
	je_free(buf);

	if (err) {
		log_error(lg, "tenant init error: %d", err);
		return;
	}

	h2o_context_set_handler_context(ctx, &self->super, tc);
	h2o_mimemap_on_context_init(self->mimemap, ctx);
}

static void
on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
	ccowobj_handler_t *self = (void *)_self;

	ccow_t tc = h2o_context_get_handler_context(ctx, &self->super);

	log_trace(lg, "%s", self->tenant_path.base);

	h2o_mimemap_on_context_dispose(self->mimemap, ctx);
	ccow_tenant_term(tc);
}

static void
on_dispose(h2o_handler_t *_self)
{
	ccowobj_handler_t *self = (void *)_self;
	size_t i;

	log_trace(lg, "%s", self->tenant_path.base);

	je_free(self->conf_path.base);
	je_free(self->tenant_path.base);
	h2o_mem_release_shared(self->mimemap);
}

ccowobj_handler_t *
ccowobj_register(h2o_pathconf_t *pathconf, const char *tenant_path,
           h2o_mimemap_t *mimemap, int authOn, int aclOn, char *region,
		   int subdomains, int flags)
{
	ccowobj_handler_t *self;
	size_t i;

	self = (void *)h2o_create_handler(pathconf, sizeof (*self));

	/* setup callbacks */
	self->super.on_context_init = on_context_init;
	self->super.on_context_dispose = on_context_dispose;
	self->super.dispose = on_dispose;
	self->super.on_req = on_req;

	/* setup attributes */
	self->conf_path = h2o_strdup_slashed(NULL, pathconf->path.base, pathconf->path.len);
	self->tenant_path = h2o_strdup_slashed(NULL, tenant_path, SIZE_MAX);
	if (mimemap != NULL) {
		h2o_mem_addref_shared(mimemap);
		self->mimemap = mimemap;
	} else {
		self->mimemap = h2o_mimemap_create();
	}
	self->authOn = authOn;
	self->aclOn = aclOn;
	if (region)
		strncpy(self->region, region, sizeof(self->region) - 1);
	self->subdomains = subdomains;
	self->flags = flags;

	log_trace(lg, "Register %s authOn: %d, aclOn: %d, region: %s, subdomains: %d",
		self->tenant_path.base, self->authOn, self->aclOn, self->region, self->subdomains = subdomains);

	return self;
}

void
ccowobj_deregister_ctx(ccowobj_handler_t *h, h2o_context_t *ctx)
{
	h->super.on_context_dispose((h2o_handler_t*)h, ctx);
	h->super.on_context_dispose = NULL;
}

h2o_mimemap_t *
ccowobj_get_mimemap(ccowobj_handler_t *handler)
{
	return handler->mimemap;
}
