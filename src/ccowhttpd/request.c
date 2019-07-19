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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/uio.h>

#include "ccowutil.h"
#include "request.h"
#include "param.h"
#include "request_util.h"

static int default_s3_attributes(param_vector *headers, param_vector *attrs) {
	int err = 0;

	err = param_add_from(H2O_STRLIT("content-type"),
	    H2O_STRLIT("application/octet-stream"), headers, attrs);
	if (err)
		return err;

	err = param_add_from_as(H2O_STRLIT("ip"),
	    H2O_STRLIT("x-source"),
	    H2O_STRLIT("-"), headers, attrs);
	if (err)
		return err;

	err = param_add_from_as(H2O_STRLIT("username"),
	    H2O_STRLIT("x-owner"),
	    H2O_STRLIT("-"), headers, attrs);
	if (err)
		return err;

	char buf[MAX_ITEM_SIZE];
	for (int i=0; i<param_count(headers); i++) {
		param *p = param_get(i, headers);
		if (param_key_str(p, buf, MAX_ITEM_SIZE) &&
		    (strstr(buf, "x-amz-meta-") ||
		     strstr(buf, "x-amz-expiration") ||
		     strstr(buf, "x-amz-server-side-encryption"))) {
			if (p->val.base == NULL || p->val.len == 0) {
				err = param_add(p->key.base, p->key.len, H2O_STRLIT("\n"), attrs);
			} else {
				err = param_add_param(p, attrs);
			}
			if (err)
				return err;
		}
	}
	return 0;
}


int
get_request_type(param_vector *query_params, int method_type, char *bid, int bid_size, char *oid, int oid_size) {
	if (oid == NULL || oid_size == 0 || strlen(oid) == 0) {
		if (method_type == METHOD_IS_HEAD) {
			return S3_BUCKET_HEAD;
		}
		if (method_type == METHOD_IS_DELETE) {
			return S3_BUCKET_DELETE;
		}
		if (method_type == METHOD_IS_PUT &&
		    !param_has(H2O_STRLIT("acl"), query_params) &&
		    !param_has(H2O_STRLIT("cores"), query_params) &&
		    !param_has(H2O_STRLIT("lifecycle"), query_params) &&
		    !param_has(H2O_STRLIT("encryption"), query_params) &&
		    !param_has(H2O_STRLIT("policy"), query_params) &&
		    !param_has(H2O_STRLIT("tagging"), query_params) &&
		    !param_has(H2O_STRLIT("versioning"), query_params)) {
			return S3_BUCKET_CREATE;
		}
		return S3_UNKNOWN;
	}
	if (method_type == METHOD_IS_GET) {
		if (param_has(H2O_STRLIT("acl"), query_params))
			return S3_GET_ACL;
		if (param_has(H2O_STRLIT("tagging"), query_params))
			return S3_GET_TAGGING;
		if (param_has(H2O_STRLIT("torrent"), query_params))
			return S3_GET_TORRENT;
		if (param_has(H2O_STRLIT("uploadId"), query_params))
			return S3_GET_UPLOADS;
		return S3_GET;
	}
	if (method_type == METHOD_IS_HEAD) {
		return S3_HEAD;
	}
	return S3_UNKNOWN;
}


int
request_update(int method_type, param_vector *query_params, param_vector *headers,
		request_t *rq, int reuse) {
	// Method
	rq->method_type = method_type;
	rq->request_type = get_request_type(query_params, method_type,
			rq->ci->bid, rq->ci->bid_size, rq->ci->oid, rq->ci->oid_size);

	int err = default_s3_attributes(headers, rq->attrs);
	if (err) {
		log_error(lg, "Invalid edgex attributes");
		return err;
	}

	return 0;
}

int
request_create(h2o_req_t *req, objio_info_t *ci, int method_type,
	param_vector *query_params, param_vector *headers, request_t **request)
{
	char buf[MAX_ITEM_SIZE];
	request_t *rq;

	rq = h2o_mem_alloc_pool(&req->pool, *rq, 1);
	if (!rq) {
		return -ENOMEM;
	}

	rq->ci = ci;
	rq->offset = 0;
	rq->length = 0;

	rq->modifiedBytes = 0;
	rq->opCount = 0;
	rq->logicalSize = 0;

	rq->ci_part = NULL;
	rq->nparts = 0;
	rq->ipart = 0;
	rq->opart = 0;

	rq->attrs = NULL;
	rq->opts = NULL;

	// Attributes
	rq->attrs = h2o_mem_alloc_pool(&req->pool, *rq->attrs, 1);
	if (!rq->attrs) {
		request_destroy(rq);
		return -ENOMEM;
	}

	int err = param_init(&req->pool, PARAM_DEFAULT_SIZE, ALLOCATE_ON, rq->attrs);
	if (err) {
		request_destroy(rq);
		return err;
	}

	// Options
	rq->opts = h2o_mem_alloc_pool(&req->pool, *rq->opts, 1);
	if (!rq->opts) {
		request_destroy(rq);
		return -ENOMEM;
	}

	err = param_init(&req->pool, PARAM_DEFAULT_SIZE, ALLOCATE_ON, rq->opts);
	if (err) {
		request_destroy(rq);
		return err;
	}

	err = request_update(method_type, query_params, headers, rq, 0);
	if (err) {
		request_destroy(rq);
		return err;
	}

	param *versionId = param_find(H2O_STRLIT("versionId"), query_params);

	if (versionId != NULL) {
		version_t version;
		err = decode_versionId(req, versionId->val.base, versionId->val.len, &version);
		if (!err) {
			log_trace(lg, "Decoded decoding version id");
			ci->genid = version.genid;
			ci->uvid = version.uvid;
			ci->vmchid = version.vmchid;
			ci->deleted = version.deleted;
			str_hash_id(&ci->vmchid, ci->vmchid_str, 128);
		} else {
			log_error(lg, "Error decoding version id %s", param_str(versionId, buf, MAX_ITEM_SIZE));
		}
	}

	*request = rq;
	return 0;
}


void
request_destroy(request_t *rq) {
	if (!rq)
		return;
	if (rq->attrs) {
		param_free(rq->attrs);
	}
	if (rq->opts) {
		param_free(rq->opts);
	}
}

void
request_close(request_t *rq) {
	if (!rq)
		return;

	if (rq->ci) {
		objio_close(rq->ci, 0);
		objio_destroy(rq->ci);
		rq->ci = NULL;
	}

	request_close_part(rq);
}

void
request_close_part(request_t *rq) {
	if (!rq)
		return;

	if (rq->ci_part) {
		objio_close(rq->ci_part, 0);
		objio_destroy(rq->ci_part);
		rq->ci_part = NULL;
	}
}


int
request_closed(request_t *rq) {
	return (rq->ci == NULL);
}


void
request_dump(char *header, request_t *rq) {
	if (!rq) {
		log_trace(lg, "<<%s empty>>", header);
		return;
	}
	log_trace(lg, "<<%s>>", header);
	log_trace(lg, "  request: %s", S3_STR[rq->request_type]);
	log_trace(lg, "  method: %s", METHOD_STR[rq->method_type]);

	log_trace(lg, "  offset: %lu", rq->offset);
	log_trace(lg, "  length: %lu", rq->length);

	if (rq->ci) {
		log_trace(lg, "  ci->bid: %s", rq->ci->bid);
		log_trace(lg, "  ci->oid: %s", rq->ci->oid);
		log_trace(lg, "  ci->oflags: %d", rq->ci->oflags);
		log_trace(lg, "  ci->autocommit: %d", rq->ci->autocommit);
		log_trace(lg, "  ci->multipart: %d", rq->ci->multipart);
		log_trace(lg, "  ci->io_count: %d", rq->ci->io_count);
		log_trace(lg, "  ci->max_io_count: %d", rq->ci->max_io_count);
		log_trace(lg, "  ci->cont_flags: %d", rq->ci->cont_flags);
		log_trace(lg, "  ci->genid: %lu", rq->ci->genid);
		log_trace(lg, "  ci->uvid: %lu", rq->ci->uvid);
		log_trace(lg, "  ci->writes: %d", rq->ci->writes);
		log_trace(lg, "  ci->content_type: %s", rq->ci->content_type);
		log_trace(lg, "  ci->etag: %s", rq->ci->etag);
		log_trace(lg, "  ci->chunk_size: %u", rq->ci->chunk_size);
		log_trace(lg, "  ci->btree_order: %u", rq->ci->btree_order);
		log_trace(lg, "  ci->num_vers: %u", rq->ci->num_vers);
		log_trace(lg, "  ci->rep_count: %u", rq->ci->rep_count);
		log_trace(lg, "  ci->sync_put: %u", rq->ci->sync_put);
	}

	log_trace(lg, "  modifiedBytes: %lu", rq->modifiedBytes);
	log_trace(lg, "  opCount: %d", rq->opCount);
	log_trace(lg, "  logicalSize: %lu", rq->logicalSize);

	param_dump("  attrs:", rq->attrs);
	param_dump("   opts:", rq->opts);
}
