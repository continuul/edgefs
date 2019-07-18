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
#include "session.h"
#include "param.h"
#include "request_util.h"

static int default_attributes(param_vector *headers, param_vector *attrs) {
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

static int default_options(param_vector *headers, param_vector *opts) {
	int err = 0;

	err = param_add_from(H2O_STRLIT("x-ccow-truncate-length"),
			H2O_STRLIT("0"), headers, opts);
	if (err)
		return err;

	err = param_add_from(H2O_STRLIT("x-ccow-vm-content-hash-id"),
			NULL, 0, headers, opts);
	if (err)
		return err;

	err = param_add_from(H2O_STRLIT("x-ccow-uvid-timestamp"),
			H2O_STRLIT("0"), headers, opts);
	if (err)
		return err;

	err = param_add_from(H2O_STRLIT("x-ccow-tx-generation-id"),
			H2O_STRLIT("0"), headers, opts);
	if (err)
		return err;


	return 0;
}

static int get_edgex_request_type(session_t *ss, int method_type) {
	if (ss->streamsession) {
		if (method_type == METHOD_IS_PUT || method_type == METHOD_IS_POST) {
			if (ss->ci->oflags & CCOW_O_REPLACE) {
				return RT_OBJECT_REPLACE;
			}
			if (ss->ci->oflags & CCOW_O_CREATE) {
				return RT_OBJECT_CREATE;
			}
			return RT_STREAM_POST;
		}
		if (method_type == METHOD_IS_GET) {
			if (ss->finalize) {
				ss->finalize = 0;
				ss->cancel = 1;
			}
			return RT_STREAM_GET;
		}
		if (method_type == METHOD_IS_HEAD) {
			return RT_STREAM_HEAD;
		}
	}

	if (ss->appendblock) {
		if (method_type == METHOD_IS_PUT || method_type == METHOD_IS_POST) {
			ss->finalize = 1;
			ss->cancel = 0;
			return RT_APPEND;
		}
	}

	if (ss->randwrblock) {
		if (method_type == METHOD_IS_PUT || method_type == METHOD_IS_POST) {
			ss->finalize = 1;
			ss->cancel = 0;
			return RT_WRBLOCK;
		}
	}

	if (ss->kv) {
		if (method_type == METHOD_IS_PUT || method_type == METHOD_IS_POST) {
			if (ss->ci->oflags & CCOW_O_REPLACE) {
				return RT_KV_REPLACE;
			}
			if (ss->ci->oflags & CCOW_O_CREATE) {
				return RT_KV_CREATE;
			}
			return RT_KV_POST;
		}
		if (method_type == METHOD_IS_GET) {
			ss->finalize = 1;
			ss->cancel = 0;
			return RT_KV_LIST;
		}
		if (method_type == METHOD_IS_HEAD) {
			return RT_STREAM_HEAD;
		}
		if (method_type == METHOD_IS_DELETE) {
			return RT_KV_DELETE;
		}
	}

	if (ss->kvget) {
		if (method_type == METHOD_IS_GET) {
			return RT_KV_GET;
		}
	}

	if (ss->del) {
		return RT_OBJECT_DELETE;
	}

	return RT_UNKNOWN;
}

int
session_valid(session_t *ss) {
	if (!ss)
		return 0;

	if (ss->request_type == RT_UNKNOWN)
		return 0;

	if (!(ss->streamsession || ss->appendblock || ss->randwrblock || ss->kv || ss->kvget))
	   return 0;

	if (ss->finalize && ss->cancel)
		return 0;

	if (ss->request_type == RT_UNKNOWN)
		return 0;

	return 1;
}


int
session_update(param *comp,	int method_type, param_vector *query_params, param_vector *headers,
		session_t *ss, int reuse) {
	// Method
	ss->method_type = method_type;

	// Keys
	ss->finalize = param_has(H2O_STRLIT("finalize"), query_params);
	ss->cancel = param_has(H2O_STRLIT("cancel"), query_params);

	if (!reuse) {
		ss->streamsession = param_value_equal(comp, H2O_STRLIT("streamsession"));
		ss->appendblock = param_value_equal(comp, H2O_STRLIT("appendblock"));
		ss->randwrblock = param_value_equal(comp, H2O_STRLIT("randwrblock"));
		ss->kv = param_value_equal(comp, H2O_STRLIT("kv"));
		ss->kvget = param_value_equal(comp, H2O_STRLIT("kvget"));
		ss->del = param_value_equal(comp, H2O_STRLIT("del"));

		if (!(ss->streamsession || ss->appendblock || ss->randwrblock || ss->kv || ss->kvget)) {
			ss->streamsession = 1;
		}
		ss->ci->max_io_count = (int) param_find_long(H2O_STRLIT("x-ccow-streamsession-maxops"),
				CCOW_STREAMSESSION_MAXOPTS, headers);
	}

	ss->ci->oflags = (int) param_find_long(H2O_STRLIT("x-ccow-object-oflags"), 0, headers);
	ss->ci->autocommit = (int) param_find_long(H2O_STRLIT("x-ccow-autocommit"), 1, headers);

	// Range
	ss->offset = (uint64_t) param_find_long(H2O_STRLIT("x-ccow-offset"), 0, headers);
	ss->length = (uint64_t) param_find_long(H2O_STRLIT("x-ccow-length"), 0, headers);

	if (!reuse) {
		int err = default_attributes(headers, ss->attrs);
		if (err) {
			log_error(lg, "Invalid edgex attributes");
			return err;
		}

		err = default_options(headers, ss->opts);
		if (err) {
			log_error(lg, "Invalid edgex options");
			return err;
		}
	}

	ss->request_type = get_edgex_request_type(ss, method_type);

	if (session_valid(ss)) {
		return 0;
	}  else {
		return -EINVAL;
	}
}

int
session_create(objio_info_t *ci, param *comp, int method_type,
		param_vector *query_params, param_vector *headers, session_t **session) {

	session_t *ss;

	ss = je_malloc(sizeof (*ss));
	if (!ss) {
		return -ENOMEM;
	}

	ss->sid = 0;
	ss->ci = ci;

	ss->modifiedBytes = 0;
	ss->opCount = 0;
	ss->logicalSize = 0;

	ss->attrs = NULL;
	ss->opts = NULL;

	// Attributes
	ss->attrs = je_malloc(sizeof (*ss->attrs));
	if (!ss->attrs) {
		session_destroy(ss);
		return -ENOMEM;
	}

	int err = param_init(NULL, PARAM_DEFAULT_SIZE, ALLOCATE_ON, ss->attrs);
	if (err) {
		session_destroy(ss);
		return err;
	}

	// Options
	ss->opts = je_malloc(sizeof (*ss->opts));
	if (!ss->opts) {
		session_destroy(ss);
		return -ENOMEM;
	}

	err = param_init(NULL, PARAM_DEFAULT_SIZE, ALLOCATE_ON, ss->opts);
	if (err) {
		session_destroy(ss);
		return err;
	}

	err = session_update(comp, method_type, query_params, headers, ss, 0);
	if (err) {
		session_destroy(ss);
		return err;
	}

	// kv types
	if (ss->kv || ss->kvget) {
		ss->ci->kv = 1;
	}

	// Get create headers
	ss->ci->chunk_size = (uint32_t) param_find_long(H2O_STRLIT("x-ccow-chunkmap-chunk-size"),
			ss->ci->chunk_size, headers);

	ss->ci->btree_order = (uint16_t) param_find_long(H2O_STRLIT("x-ccow-chunkmap-btree-order"),
			ss->ci->btree_order, headers);

	ss->ci->num_vers = (uint16_t) param_find_long(H2O_STRLIT("x-ccow-number-of-versions"),
			ss->ci->num_vers, headers);

	ss->ci->rep_count = (uint8_t) param_find_long(H2O_STRLIT("x-ccow-replication-count"),
			ss->ci->rep_count, headers);


	if (!session_valid(ss)) {
		log_error(lg, "Invalid edgex request");
		session_destroy(ss);
		return -EINVAL;
	}

	pthread_mutex_init(&ss->sess_lock, NULL);

	log_trace(lg, "session %p created", ss);
	*session = ss;
	return 0;
}


int
session_ending(session_t *ss) {
	return (ss->finalize || ss->cancel || ss->del);
}


void
session_destroy(session_t *ss) {
	if (!ss)
		return;
	if (ss->attrs) {
		param_free(ss->attrs);
		je_free(ss->attrs);
	}
	if (ss->opts) {
		param_free(ss->opts);
		je_free(ss->opts);
	}
	log_trace(lg, "session %p destroyed", ss);
	je_free(ss);
}

void
session_close(session_t *ss) {
	if (!ss)
		return;

	log_trace(lg, "session close sid: %lu cancel: %d", ss->sid, ss->cancel);

	pthread_mutex_lock(&ss->sess_lock);
	if (ss->ci) {
		objio_close(ss->ci, ss->cancel);
		objio_destroy(ss->ci);
		ss->ci = NULL;
	}
	pthread_mutex_unlock(&ss->sess_lock);
}

int
session_closed(session_t *ss) {
	int res = 0;
	pthread_mutex_lock(&ss->sess_lock);
	res = (ss->ci == NULL);
	pthread_mutex_unlock(&ss->sess_lock);
	return res;
}


void
session_dump(char *header, session_t *ss) {
	if (!ss) {
		log_trace(lg, "<<%s empty>>", header);
		return;
	}
	log_trace(lg, "<<%s>>", header);
	log_trace(lg, "  sid: %lu", ss->sid);
	log_trace(lg, "  request: %s", REQUEST_STR[ss->request_type]);
	log_trace(lg, "  method: %s", METHOD_STR[ss->method_type]);
	log_trace(lg, "  streamsession: %d", ss->streamsession);
	log_trace(lg, "  appendblock: %d", ss->appendblock);
	log_trace(lg, "  randwrblock: %d", ss->randwrblock);
	log_trace(lg, "  kv: %d", ss->kv);
	log_trace(lg, "  kvget: %d", ss->kvget);
	log_trace(lg, "  finalize: %d", ss->finalize);
	log_trace(lg, "  cancel: %d", ss->cancel);
	log_trace(lg, "  delete: %d", ss->del);

	log_trace(lg, "  offset: %lu", ss->offset);
	log_trace(lg, "  length: %lu", ss->length);


	if (ss->ci) {
		log_trace(lg, "  ci->bid: %s", ss->ci->bid);
		log_trace(lg, "  ci->oid: %s", ss->ci->oid);
		log_trace(lg, "  ci->kv: %d", ss->ci->kv);
		log_trace(lg, "  ci->oflags: %d", ss->ci->oflags);
		log_trace(lg, "  ci->autocommit: %d", ss->ci->autocommit);
		log_trace(lg, "  ci->multipart: %d", ss->ci->multipart);
		log_trace(lg, "  ci->io_count: %d", ss->ci->io_count);
		log_trace(lg, "  ci->max_io_count: %d", ss->ci->max_io_count);
		log_trace(lg, "  ci->cont_flags: %d", ss->ci->cont_flags);
		log_trace(lg, "  ci->genid: %lu", ss->ci->genid);
		log_trace(lg, "  ci->writes: %d", ss->ci->writes);
		log_trace(lg, "  ci->content_type: %s", ss->ci->content_type);
		log_trace(lg, "  ci->etag: %s", ss->ci->etag);
		log_trace(lg, "  ci->chunk_size: %u", ss->ci->chunk_size);
		log_trace(lg, "  ci->btree_order: %u", ss->ci->btree_order);
		log_trace(lg, "  ci->num_vers: %u", ss->ci->num_vers);
		log_trace(lg, "  ci->rep_count: %u", ss->ci->rep_count);
		log_trace(lg, "  ci->sync_put: %u", ss->ci->sync_put);
	}

	log_trace(lg, "  modifiedBytes: %lu", ss->modifiedBytes);
	log_trace(lg, "  opCount: %d", ss->opCount);
	log_trace(lg, "  logicalSize: %lu", ss->logicalSize);

	param_dump("  attrs:", ss->attrs);
	param_dump("   opts:", ss->opts);
}
