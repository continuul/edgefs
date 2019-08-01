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
#include <time.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/uio.h>

#include "ccowutil.h"
#include "msgpackalt.h"
#include "ccow.h"
#include "trlog.h"
#include "request_util.h"
#include "objio.h"
#include "list_cache.h"

/* enough to operate with up to 400GB object size without re-open */
#define OBJIO_CHUNK_SIZE_MAX	(4 * 1024 * 1024UL)
#define OBJIO_BTREE_ORDER 640
#define VALUE_BUFFER_SIZE 65536
#define STR_MAXLEN		512
#define KEY_STR_MAXLEN	2048
#define CACHE_LIST_STEP 128

struct chunk_context {
	char ma_bufs[2 * OBJIO_CHUNK_SIZE_MAX];
	uint64_t s0;
	uint64_t s1;
	uint64_t s2;
	size_t l0;
	size_t l1;
	size_t l2;
	char *buf;
};

int
objio_create(ccow_t tc, char *tid_cid, int tid_cid_size, char *bid, int bid_size, char *oid, int oid_size,
		int max_io_count, objio_info_t **ci_out)
{
	objio_info_t *ci;
	int matched;
	int err;

	*ci_out = NULL;

	ci = je_malloc(sizeof (*ci));
	if (!ci)
		return -ENOMEM;

	memcpy(ci->tid_cid, tid_cid, tid_cid_size);
	memcpy(ci->cid, ci->tid_cid, tid_cid_size);
	char *p = strstr(ci->cid,"/");
	if (p == NULL) {
		return - EINVAL;
	}
	*p = '\0';
	ci->cid_size = strlen(ci->cid);
	ci->bid[0] = '\0';
	ci->oid[0] = '\0';

	memcpy(ci->bid, bid, bid_size);
	memcpy(ci->oid, oid, oid_size);

	ci->bid_size = bid_size;
	ci->oid_size = oid_size;
	ci->tid_cid_size = tid_cid_size;
	ci->tc = tc;
	ci->kv = 0;
	ci->chunk_size = OBJIO_CHUNK_SIZE_MAX;
	ci->btree_order = OBJIO_BTREE_ORDER;
	ci->num_vers = 0;
	ci->rep_count = 0;
	ci->sync_put = 0;
	ci->logical_size = 0;
	ci->c = 0;
	ci->io_count = 0;
	ci->max_io_count = max_io_count;
	ci->genid = 0;
	ci->uvid = 0;
	ci->writes = 0;
	ci->start_iter = NULL;
	ci->file = 0;
	ci->multipart = 0;
	ci->multipart_size = 0;
	ci->size = 0;
	ci->file_size = 0;
	ci->autocommit = 1;
	ci->etag[0] = '\0';
	ci->content_type[0] = '\0';
	strcpy(ci->chunk_map, "btree_map");
	ci->vmchid_str[0] = '\0';
	ci->quota_bytes = 0;
	ci->quota_count = 0;
	ci->object_count = 0;

	ci->key_size = 0;
	memcpy(ci->key, ci->tid_cid, ci->tid_cid_size-1);
	ci->key_size += ci->tid_cid_size-1;
	ci->key[ci->key_size] = '/';
	ci->key_size++;
	memcpy(ci->key + ci->key_size, ci->bid, ci->bid_size-1);
	ci->key_size += ci->bid_size-1;
	ci->key[ci->key_size] = '/';
	ci->key_size++;
	memcpy(ci->key + ci->key_size, ci->oid, ci->oid_size-1);
	ci->key_size += ci->oid_size-1;
	ci->key[ci->key_size] = '\0';

	// Allocate attrs
	ci->attrs = je_malloc(sizeof (*ci->attrs));
	if (!ci->attrs) {
		ci->attrs = NULL;
		return -ENOMEM;
	}

	err = param_init(NULL, PARAM_DEFAULT_SIZE, ALLOCATE_ON, ci->attrs);
	if (err) {
		return err;
	}

	*ci_out = ci;
	return 0;
}

void
objio_destroy(objio_info_t *ci)
{
	if (ci) {
		if (ci->attrs) {
			param_free(ci->attrs);
			je_free(ci->attrs);
		}
		je_free(ci);
	}
}

static int
objio_modify_defaults(objio_info_t *ci)
{
	int err = 0;
	if (ci->kv) {
		strcpy(ci->chunk_map, "btree_key_val");
		err = ccow_attr_modify_default(ci->c, CCOW_ATTR_CHUNKMAP_TYPE,
				(void *) &ci->chunk_map, NULL);
		if (err)
			return err;

		uint16_t flags = RT_INLINE_DATA_TYPE_USER_KV;
		err = ccow_attr_modify_default(ci->c, CCOW_ATTR_INLINE_DATA_FLAGS,
		    (void *)&flags, NULL);
		if (err)
			return err;
	}

	log_trace(lg, "modify_defaults");
	err = ccow_attr_modify_default(ci->c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
			    (void *) &ci->chunk_size, NULL);
	if (err)
		return err;

	err = ccow_attr_modify_default(ci->c, CCOW_ATTR_BTREE_ORDER,
	    &ci->btree_order, NULL);
	if (err)
		return err;

	if (ci->num_vers) {
		err = ccow_attr_modify_default(ci->c, CCOW_ATTR_NUMBER_OF_VERSIONS,
		    (void *)&ci->num_vers, NULL);
		if (err)
			return err;
	}

	if (ci->rep_count) {
		err = ccow_attr_modify_default(ci->c, CCOW_ATTR_REPLICATION_COUNT,
		    (void *)&ci->rep_count, NULL);
		if (err)
			return err;
	}

	if (ci->expiration) {
		err = ccow_attr_modify_default(ci->c, CCOW_ATTR_OBJECT_DELETE_AFTER,
		    (void *)&ci->expiration, NULL);
		if (err)
			return err;
	}

	if (ci->sync_put) {
		err = ccow_attr_modify_default(ci->c, CCOW_ATTR_SYNC_PUT,
		    (void *)&ci->sync_put, NULL);
		if (err)
			return err;
	}


	return 0;
}

static int objio_modify_custom(ccow_completion_t c, param_vector *attrs) {
    int err = 0;

    for (int i=0; i<param_count(attrs); i++) {
        param *p = param_get(i, attrs);
        if (p && p->val.base != NULL && p->val.len > 0) {
            char *key = strndupa(p->key.base, p->key.len);
            char *val = strndupa(p->val.base, p->val.len);
            err = ccow_attr_modify_custom(c, CCOW_KVTYPE_RAW,
                key, p->key.len + 1, val, p->val.len + 1, NULL);
            if (err)
                return err;
        }
    }

    return 0;
}


static void read_attributes(objio_info_t *ci, ccow_lookup_t iter) {
	int pos = 0, hash_size = 0;
	struct ccow_metadata_kv *kv = NULL;
	ci->etag[0] = '\0';
	int n = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA | CCOW_MDTYPE_CUSTOM, pos++))) {
		n++;
		if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
			ci->logical_size = (uint64_t) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, RT_SYSKEY_OBJECT_COUNT) == 0) {
			ci->object_count = (uint64_t) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
			ci->chunk_size = (uint32_t) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_BTREE_ORDER) == 0) {
			ci->btree_order = (uint16_t) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, RT_SYSKEY_NUMBER_OF_VERSIONS) == 0) {
			ci->num_vers = (uint16_t) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, RT_SYSKEY_OBJECT_DELETED) == 0) {
			ci->deleted = (uint8_t) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, RT_SYSKEY_VM_CONTENT_HASH_ID) == 0) {
			memcpy(&ci->vmchid, kv->value, sizeof(uint512_t));
		} else if (strcmp(kv->key, RT_SYSKEY_NAME_HASH_ID) == 0) {
			memcpy(&ci->nhid, kv->value, sizeof(uint512_t));
		} else if (strcmp(kv->key, "multipart") == 0) {
			ci->multipart = (int) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, "x-container-meta-quota-bytes") == 0) {
			ci->quota_bytes = (int) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, "x-container-meta-quota-count") == 0) {
			ci->quota_count = (int) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, RT_SYSKEY_TX_GENERATION_ID) == 0) {
			ci->genid = *(uint64_t *)kv->value;
		} else if (strcmp(kv->key, RT_SYSKEY_UVID_TIMESTAMP) == 0) {
			ci->uvid = *(uint64_t *)kv->value;
		} else if (strcmp(kv->key, "ETag") == 0 && kv->value_size < MAX_ITEM_SIZE) {
			memcpy(ci->etag, kv->value, kv->value_size);
			ci->etag[kv->value_size] = '\0';
		} else if (strstr(kv->key, "multipart_size")) {
			ci->multipart_size = (uint64_t) ccow_kvconvert_to_int64(kv);
		} else if (strstr(kv->key, "X-file-size")) {
			ci->file = 1;
			ci->file_size = (uint64_t) ccow_kvconvert_to_int64(kv);
		} else if (strstr(kv->key, "x-amz-meta")  && kv->value_size < MAX_ITEM_SIZE) {
			param_add(kv->key, kv->key_size, kv->value, kv->value_size, ci->attrs);
		} else if (strcmp(kv->key, "content-type") == 0 && kv->value_size < MAX_ITEM_SIZE) {
			memcpy(ci->content_type, kv->value, kv->value_size);
			ci->content_type[kv->value_size] = '\0';
		}
	}

	if (ci->etag[0] == '\0') {
		str_hash_id(&ci->vmchid, ci->etag, 64);
	}

	if (ci->multipart == 2) {
		ci->size = ci->multipart_size;
	} else {
		if (ci->file) {
			ci->size = ci->file_size;
		} else {
			ci->size = ci->logical_size;
		}
	}
}



static void add_attributes(objio_info_t *ci, ccow_lookup_t iter) {
	int pos = 0;
	struct ccow_metadata_kv *kv = NULL;
	log_trace(lg, "attrs address: %p", ci->attrs);
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_CUSTOM, pos++))) {
		if (strcmp(kv->key, "x-container-meta-quota-bytes") == 0) {
			ci->quota_bytes = (int) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, "x-container-meta-quota-count") == 0) {
			ci->quota_count = (int) ccow_kvconvert_to_int64(kv);
		} else if (strstr(kv->key, "x-amz-meta") && kv->value_size < MAX_ITEM_SIZE) {
			param_add(kv->key, kv->key_size, kv->value, kv->value_size, ci->attrs);
		}
	}
}


int
objio_create_new(objio_info_t *ci, int replace, param_vector *attrs)
{
	int err;

	if (!ci->chunk_size || (ci->chunk_size % 512 != 0) ||
	    ci->chunk_size > OBJIO_CHUNK_SIZE_MAX) {
		log_error(lg, "attribute %s not found or incorrect (%d) on init",
		    RT_SYSKEY_CHUNKMAP_CHUNK_SIZE, ci->chunk_size);
		return -EBADF;
	}


	ci->cont_flags = (replace ? CCOW_CONT_F_REPLACE : 0);
	log_trace(lg, "create new %s/%s replace: %d",
			ci->bid, ci->oid, replace);

	err = ccow_create_stream_completion(ci->tc, NULL, NULL, ci->max_io_count, &ci->c,
		ci->bid, ci->bid_size, ci->oid, ci->oid_size, &ci->genid, &ci->cont_flags,
		&ci->start_iter);
	if (err)
		return err;

	log_trace(lg, "create new %s/%s ci->cont_flags: %d",
			ci->bid, ci->oid, ci->cont_flags);

	if (!replace && ci->cont_flags & CCOW_CONT_F_EXIST) {
		log_warn(lg, "object %s/%s exist on create",
		    ci->bid, ci->oid);
		return -EINVAL;
	}

	err = objio_modify_defaults(ci);
	if (err)
		return err;

	err = objio_modify_custom(ci->c, attrs);
	if (err)
		return err;

	ci->io_count = 0;
	ci->logical_size = 0;

	err = ccow_put_cont(ci->c, NULL, 0, 0, 1,  &ci->io_count);
	if (err) {
		log_error(lg, "create error on I/O submit: %d", err);
		return err;
	}

	err = ccow_wait(ci->c, ci->io_count);
	if (err != 0) {
		log_error(lg, "create error on CCOW wait: %d", err);
		return err;
	}

	ci->writes = 1;

	return 0;
}


int
objio_open(objio_info_t *ci)
{
	int err;

	ci->cont_flags = 0;

	if (ci->genid > 0 && ci->uvid > 0) { // Verioning
		err = ccow_create_stream_completion_versioned(ci->tc, NULL, NULL, ci->max_io_count, &ci->c,
				ci->bid, ci->bid_size, ci->oid, ci->oid_size,
				&ci->genid, ci->uvid, ci->vmchid_str, &ci->cont_flags, &ci->start_iter);
		if (err)
			return err;
		log_trace(lg, "opened object version %s/%s genid: %lu, flags: %d",
			    ci->bid, ci->oid, ci->genid, (int) ci->cont_flags);
	} else {
		err = ccow_create_stream_completion(ci->tc, NULL, NULL, ci->max_io_count, &ci->c,
			ci->bid, ci->bid_size, ci->oid, ci->oid_size,
			&ci->genid, &ci->cont_flags, &ci->start_iter);
		if (err)
			return err;
		log_trace(lg, "opened object %s/%s flags: %d",
			    ci->bid, ci->oid, (int) ci->cont_flags);
	}
	if (!(ci->cont_flags & CCOW_CONT_F_EXIST)) {
		log_warn(lg, "object %s/%s not found on stream open",
		    ci->bid, ci->oid);
		err = ccow_cancel(ci->c);
		ci->c = NULL;
		return -ENOENT;
	}

	ci->io_count = 0;
	ci->logical_size = 0;

	if (ci->start_iter) {
		read_attributes(ci, ci->start_iter);
	}

	if (!ci->chunk_size ||
	    ci->chunk_size > OBJIO_CHUNK_SIZE_MAX) {
		log_error(lg, "attribute %s not found or incorrect (%d) on init",
		    RT_SYSKEY_CHUNKMAP_CHUNK_SIZE, ci->chunk_size);
		ccow_release(ci->c);
		ci->c = NULL;
		return -EBADF;
	}

	return 0;
}

void
objio_close(objio_info_t *ci, int cancel)
{
	int err;
	char buf[MAX_ITEM_SIZE];

	if (!ci)
		return;

	if (!ci->c)
		return;

	// Cancel
	if (ci->writes == 0 || cancel || !ci->autocommit) {
		err = ccow_cancel(ci->c);
		ci->c = NULL;
		if (err)
			log_error(lg, "cancel err: %d", err);
		return;
	}

	// Finalize
	log_trace(lg, "finalize read attributes");
	ccow_lookup_t iter;
	err = ccow_finalize(ci->c, &iter);
	ci->c = NULL;
	if (err) {
		log_error(lg, "cannot finalize stream on close: %d", err);
		return;
	}
	read_attributes(ci, iter);
	log_trace(lg, "finalize read attributes done");
	ccow_lookup_release(iter);
	list_cache_record_t *rec = NULL;
	err = cache_record_ini(ACTION_PUT, ci->etag, ci->uvid,
			ci->size, ci->genid, &ci->vmchid,  0,
			0, ci->content_type, &rec);
	if (err) {
		log_error(lg, "cannot create list cache record: %d", err);
		return;
	}
	log_trace(lg,"record_ini done");

	log_trace(lg, "Insert into list cache key: %s", ci->key);
	log_trace(lg, "Insert into list cache value: %s", cache_record_str(rec, buf, MAX_ITEM_SIZE));
	err = list_cache_insert(list_cache, ci->key, ci->key_size, rec);
	if (err) {
		log_error(lg, "cannot insert list cache into cache: %d", err);
		return;
	}
}


static int
objio_rmw_check(objio_info_t *ci, uint64_t offset,  char *buf,
    size_t length, struct iovec **iov, size_t *iovcnt, int write,
    struct chunk_context *ch_ctx)
{
	int err = 0;
	uint64_t s0 = 0, s1 = 0, s2 = 0;
	size_t l0 = 0, l1 = 0, l2 = 0;
	size_t t = 0;
	size_t cnt = 0;
	size_t iov_idx = 0;

	/*
	 * start and length of region 0. this is the unaligned region at the
	 * beginning of the request.  length may be zero if the offset is
	 * page aligned.
	 */

	log_trace(lg, "offset = %"PRIx64" : chunk_size = %d length: %ld",
	    offset, ci->chunk_size, length);

	s0 = offset % ci->chunk_size;

	if (s0 == 0) {
		l0 = 0;
	} else {
		if (ci->chunk_size - s0 < length) {
			l0 = ci->chunk_size - s0;
		} else {
			l0 = length;
		}

		t += l0;
	}

	/*
	 * start and length of region 1. this is the aligned region in the
	 * middle of the request. length may be zero.
	 */
	s1 = s0 + l0;
	if (t < length) {
		l1 = ((length - l0) / ci->chunk_size) * ci->chunk_size;
		t += l1;
	}

	/*
	 * start and length of region 2. this is the sub-page sized region at
	 * the end of the request.
	 */
	s2 = s1 + l1;
	if (t < length) {
		l2 = length - t;
	}

	ch_ctx->s0 = s0;
	ch_ctx->s1 = s1;
	ch_ctx->s2 = s2;
	ch_ctx->l0 = l0;
	ch_ctx->l1 = l1;
	ch_ctx->l2 = l2;
	ch_ctx->buf = buf;

	uint64_t doff = (offset / ci->chunk_size) * ci->chunk_size;
	log_trace(lg, "s0 : 0x%"PRIx64" %lu doff: %lu", s0, s0, doff);
	log_trace(lg, "s1 : 0x%"PRIx64" %lu", s1, s1);
	log_trace(lg, "s2 : 0x%"PRIx64" %lu", s2, s2);
	log_trace(lg, "l0 : 0x%"PRIx64" %lu", l0, l0);
	log_trace(lg, "l1 : 0x%"PRIx64" %lu", l1, l1);
	log_trace(lg, "l2 : 0x%"PRIx64" %lu", l2, l2);

	if (write) {
		/*
		 * initialize io vector
		 */
		cnt = l1 / ci->chunk_size;
		if (l0 > 0) cnt++;
		if (l2 > 0) cnt++;
		log_trace(lg, "cnt : %lu", cnt);


		struct iovec *v = je_calloc(cnt, sizeof (struct iovec));
		if (v == NULL) {
			*iovcnt = 0;
			return -ENOMEM;
		}

		/*
		 * writes may require read/modify/write on unaligned pages
		 */
		if (l0 > 0) {
			struct iovec iov = {
				.iov_base = &ch_ctx->ma_bufs[0],
				.iov_len  = ci->chunk_size
			};

			err = ccow_get_cont(ci->c, &iov, 1,
			    doff, 1, &ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get: %d", err);
				return err;
			}

			err = ccow_wait(ci->c, ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get wait:"
				    " %d", err);
				return err;
			}

			memcpy(&ch_ctx->ma_bufs[0] + s0, buf, l0);

			v[iov_idx].iov_base = &ch_ctx->ma_bufs[0];
			v[iov_idx++].iov_len = ci->chunk_size;
		}

		if (l2 > 0) {
			struct iovec iov = {
				.iov_base = &ch_ctx->ma_bufs[ci->chunk_size],
				.iov_len  = ci->chunk_size
			};

			err = ccow_get_cont(ci->c, &iov, 1, offset + l0 + l1,
			    1, &ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get2: %d",
				    err);
				return err;
			}

			err = ccow_wait(ci->c, ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get wait2:"
				    " %d", err);
				return err;
			}

			memcpy(&ch_ctx->ma_bufs[ci->chunk_size],
			    buf + l0 + l1, l2);

			v[iov_idx + l1/ci->chunk_size].iov_base =
				&ch_ctx->ma_bufs[ci->chunk_size];
			v[iov_idx + l1/ci->chunk_size].iov_len = ci->chunk_size;
		}

		char *base = buf + l0;

		while (l1 > 0) {
			log_trace(lg, "add %lu: %u", iov_idx,  ci->chunk_size);
			v[iov_idx].iov_base = base;
			v[iov_idx].iov_len = ci->chunk_size;

			base += ci->chunk_size;
			iov_idx++;
			l1 -= ci->chunk_size;
		}

		if (ci->logical_size < offset + length) {
			ci->logical_size = offset + length;
		}


		*iov = v;
		*iovcnt = cnt;

		if (cnt > 0 && (ci->logical_size % ci->chunk_size) != 0) {
			size_t wrlength = doff + cnt*ci->chunk_size;
			log_trace(lg, "wrlength: %lu, ci->logical_size: %lu", wrlength, ci->logical_size);
			if (wrlength > ci->logical_size) {
				v[cnt-1].iov_len = ci->logical_size % ci->chunk_size;
				log_trace(lg, "adjust %lu: %lu", (cnt-1), v[cnt-1].iov_len);
			}
		}
	} else { // Read

		cnt = l1 / ci->chunk_size;
		if (l0 > 0) cnt++;
		if (l2 > 0) cnt++;

		/*
		 * reads may require alignnent adjustment for unaligned pages
		 */
		struct iovec *v = je_calloc(cnt, sizeof (struct iovec));
		if (l0 > 0) {
			v[iov_idx].iov_base = &ch_ctx->ma_bufs[0];
			v[iov_idx++].iov_len = ci->chunk_size;
		}

		if (l2 > 0) {
			v[iov_idx + l1/ci->chunk_size].iov_base =
				&ch_ctx->ma_bufs[ci->chunk_size];
			v[iov_idx + l1/ci->chunk_size].iov_len = ci->chunk_size;
		}

		char *base = buf + l0;

		while (l1 > 0) {
			v[iov_idx].iov_base = base;
			v[iov_idx].iov_len = ci->chunk_size;

			base += ci->chunk_size;
			iov_idx++;
			l1 -= ci->chunk_size;
		}

		*iov = v;
		*iovcnt = cnt;
	}

	return err;
}

int
objio_pread(objio_info_t *ci, char *buf, size_t length, uint64_t offset)
{
	int err;
	struct chunk_context ch_ctx;
	struct iovec *iov = NULL;
	size_t iovcnt;

	uint64_t doff = (offset / ci->chunk_size) * ci->chunk_size;

	err = objio_rmw_check(ci, offset, buf, length, &iov, &iovcnt, 0, &ch_ctx);
	if (err) {
		log_error(lg, "read bs_ccowbd_chunk returned error: %d", err);
		goto _exit;
	}

	if (ci->io_count + 2 > ci->max_io_count) {
		objio_close(ci, 0);
		objio_open(ci);
	}

	log_trace(lg, "reading %ld chunks of size %u io_count %u", iovcnt,
	    ci->chunk_size, ci->io_count);

	err = ccow_get_cont(ci->c, iov, iovcnt, doff, 1,
	    &ci->io_count);
	if (err) {
		log_error(lg, "get error on I/O submit: %d", err);
		goto _exit;
	}

	err = ccow_wait(ci->c, ci->io_count);
	if (err != 0) {
		log_error(lg, "get error on CCOW wait: %d", err);
		goto _exit;
	}

	if (ch_ctx.l0 > 0) {
		char *base = (char*)iov[0].iov_base + ch_ctx.s0;
		memcpy(ch_ctx.buf, base, ch_ctx.l0);
	}

	if (ch_ctx.l2 > 0) {
		char *base = iov[iovcnt - 1].iov_base;
		memcpy(ch_ctx.buf + ch_ctx.l0 + ch_ctx.l1,
		    base, ch_ctx.l2);
	}

	je_free(iov);
	iov = NULL;

	return length;

_exit:;
	if (iov != NULL) {
		je_free(iov);
		iov = NULL;
	}
	return err;
}

int
objio_pwrite(objio_info_t *ci, void *buf, uint32_t length,
    uint64_t offset)
{
	int err;
	struct chunk_context ch_ctx;
	struct iovec *iov = NULL;
	size_t iovcnt;

	uint64_t doff = (offset / ci->chunk_size) * ci->chunk_size;

	err = objio_rmw_check(ci, offset, buf, length, &iov, &iovcnt, 1, &ch_ctx);
	if (err) {
		log_error(lg, "write bs_ccowbd_chunk returned error: %d", err);
		goto _exit;
	}

	log_trace(lg, "offset: %lu", doff);
	for (unsigned int i=0; i<iovcnt; i++) {
		log_trace(lg, "iov[%d].iov_len: %d", i, (int) iov[i].iov_len);
	}

	err = ccow_put_cont(ci->c, iov, iovcnt, doff, 1,
	    &ci->io_count);
	if (err) {
		log_error(lg, "put error on I/O submit: %d", err);
		goto _exit;
	}

	err = ccow_wait(ci->c, ci->io_count);
	if (err != 0) {
		log_error(lg, "put error on CCOW wait: %d", err);
		goto _exit;
	}

	je_free(iov);
	iov = NULL;

	ci->writes += length;

	log_trace(lg, "ci->io_count: %d, length: %d", ci->io_count, length);

	return length;

_exit:;
	if (iov != NULL) {
		je_free(iov);
		iov = NULL;
	}
	return err;
}


int
objio_kvput(objio_info_t *ci, void *key, uint64_t key_len,  void *value, uint64_t value_len)
{
	int err;
	struct iovec iov[2];
	uv_buf_t uv_b;

	iov[0].iov_base = key;
	iov[0].iov_len = key_len;


	/* packing value */
	uint8_t ver = 5;
	msgpack_p *p = msgpack_pack_init();
	if (!p) {
		err = -ENOMEM;
		goto _exit;
	}
	err = msgpack_pack_uint8(p, ver);
	if (err) {
		err = -ENOMEM;
		goto _exit;
	}
	err = msgpack_pack_raw(p, (const void *)value, value_len);
	if (err) {
		err = -ENOMEM;
		goto _exit;
	}

	msgpack_get_buffer(p, &uv_b);

	iov[1].iov_base = uv_b.base;
	iov[1].iov_len = uv_b.len;

	int c_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
	ccow_stream_flags(ci->c, &c_flags);
	err = ccow_insert_list_cont(ci->c, &iov[0], 2, 1, &ci->io_count);

	log_trace(lg, "insert err: %d, ci->io_count: %d", err, ci->io_count);
	if (err != 0) {
		log_error(lg, "put error on CCOW insert_list: %d", err);
		goto _exit;
	}

	err = ccow_wait(ci->c, ci->io_count);
	if (err != 0) {
		log_error(lg, "put error on CCOW wait: %d", err);
		goto _exit;
	}

	ci->writes += 1;

_exit:
	if (p)
		msgpack_pack_free(p);
	return err;
}

int
objio_kvput_ext(objio_info_t *ci, void *key, uint64_t key_len, void *value, uint64_t value_len,
	char *timestamp, char *content_type)
{
	int err;
	struct iovec iov[2];
	uv_buf_t uv_b;

	iov[0].iov_base = key;
	iov[0].iov_len = key_len;


	/* packing value */
	uint8_t ver = 6;
	msgpack_p *p = msgpack_pack_init();
	if (!p) {
		err = -ENOMEM;
		goto _exit;
	}
	err = msgpack_pack_uint8(p, ver);
	if (err) {
		err = -ENOMEM;
		goto _exit;
	}
	err = msgpack_pack_raw(p, (const void *)value, value_len);
	if (err) {
		err = -ENOMEM;
		goto _exit;
	}
	err = msgpack_pack_str(p, (const void *)timestamp);
	if (err) {
		log_error(lg, "pack error: %d", err);
		err = -ENOMEM;
		goto _exit;
	}
	if (content_type[0] == '\0' && ci->content_type[0] != '\0') {
		err = msgpack_pack_str(p, (const void *)ci->content_type);
	} else {
		err = msgpack_pack_str(p, (const void *)content_type);
	}
	if (err) {
		log_error(lg, "pack error: %d", err);
		err = -ENOMEM;
		goto _exit;
	}

	msgpack_get_buffer(p, &uv_b);

	iov[1].iov_base = uv_b.base;
	iov[1].iov_len = uv_b.len;

	int c_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
	ccow_stream_flags(ci->c, &c_flags);
	err = ccow_insert_list_cont(ci->c, &iov[0], 2, 1, &ci->io_count);

	log_trace(lg, "insert err: %d, ci->io_count: %d", err, ci->io_count);
	if (err != 0) {
		log_error(lg, "put error on CCOW insert_list: %d", err);
		goto _exit;
	}

	err = ccow_wait(ci->c, ci->io_count);
	if (err != 0) {
		log_error(lg, "put error on CCOW wait: %d", err);
		goto _exit;
	}

	ci->writes += 1;

_exit:
	if (p)
		msgpack_pack_free(p);
	return err;
}

int
objio_kvdel(objio_info_t *ci, void *key, uint64_t key_len)
{
	int err;
	struct iovec iov[1];
    uv_buf_t uv_b;

	iov[0].iov_base = key;
	iov[0].iov_len = key_len;


    err = ccow_delete_list_cont(ci->c, &iov[0], 1, 1, &ci->io_count);
	log_trace(lg, "delete err: %d, ci->io_count: %d", err, ci->io_count);

	err = ccow_wait(ci->c, ci->io_count);
	if (err != 0) {
		log_error(lg, "delete error on CCOW wait: %d", err);
		goto _exit;
	}

	ci->writes += 1;

_exit:
	return err;
}

static int
unpackValue(void *value, size_t value_size, char *buf, size_t buf_size) {
	if (value_size == 0 || !value) {
		buf[0] = '\0';
		return 0;
	}
	int err = 0;
	uint8_t ver=0;
	uint64_t timestamp = 0;
	uint64_t generation = 0;
	uint64_t size = 0;
	uint64_t inode = 0;
	uint512_t vmchid;
	char etag[STR_MAXLEN] = "";
	char content_type[STR_MAXLEN] = "";
	char owner[STR_MAXLEN] = "";
	char srcip[STR_MAXLEN] = "";
	uint8_t object_deleted = 0;
	msgpack_u *u = msgpack_unpack_init(value, value_size, 0);
	err = msgpack_unpack_uint8(u, &ver);
	if (err) {
		goto _exit;
	}
	log_trace(lg, "ver: %u", ver);
	if (ver == 1) {
		err = msgpack_unpack_uint8(u, &object_deleted);
		if (err) {
			goto _exit;
		}
		err = msgpack_unpack_uint64(u, &timestamp);
		if (err) {
			goto _exit;
		}
		err = msgpack_unpack_uint64(u, &generation);
		if (err) {
			goto _exit;
		}
		err = msgpack_unpack_uint512(u, &vmchid);
		if (err) {
			goto _exit;
		}
		err = msgpack_unpack_str(u, etag, STR_MAXLEN);
		if (err) {
			goto _exit;
		}
		err = msgpack_unpack_str(u, content_type, STR_MAXLEN);
		if (err) {
			goto _exit;
		}
		err = msgpack_unpack_uint64(u, &size);
		if (err) {
			goto _exit;
		}
		err = msgpack_unpack_uint64(u, &inode);
		if (err) {
			goto _exit;
		}
		err = msgpack_unpack_str(u, owner, STR_MAXLEN);
		if (err) {
			goto _exit;
		}
		err = msgpack_unpack_str(u, srcip, STR_MAXLEN);
		if (err) {
			goto _exit;
		}
		char vmchid_buf[UINT512_BYTES * 2 + 1] = "";
		sprintf(buf,"%lu;%lu;%s;%s;%s;%lu;%u;%lu;%s;%s", timestamp, generation,
		    str_hash_id(&vmchid, vmchid_buf, 64), etag, content_type, size, object_deleted, inode, owner, srcip);
		goto _exit;
	}
	if (ver == 2) {
		err = msgpack_unpack_str(u, buf, buf_size);
		goto _exit;
	}
	if (ver == 3) {
		err = msgpack_unpack_uint64(u, &inode);
		if (err)
			goto _exit;
		uint8_t type = (inode >> 60) & 3;
		sprintf(buf,"%lu;%u", inode, type);
		goto _exit;
	}
	if (ver == 4) {
		uint32_t st_mode, st_uid, st_gid;
		uint64_t st_dev, st_rdev, tv_sec;
		uint64_t st_atim_tv_sec, st_atim_tv_nsec;
		uint64_t st_mtim_tv_sec, st_mtim_tv_nsec;
		uint64_t st_ctim_tv_sec, st_ctim_tv_nsec;
		err = msgpack_unpack_uint32(u, &st_mode);
		if (err)
			goto _exit;
		err = msgpack_unpack_uint32(u, &st_uid);
		if (err)
			goto _exit;
		err = msgpack_unpack_uint32(u, &st_gid);
		if (err)
			goto _exit;
		err = msgpack_unpack_uint64(u, &st_dev);
		if (err)
			goto _exit;
		err = msgpack_unpack_uint64(u, &st_rdev);
		if (err)
			goto _exit;
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) &st_atim_tv_sec);
		if (err)
			goto _exit;
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & st_atim_tv_nsec);
		if (err)
			goto _exit;
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & st_mtim_tv_sec);
		if (err)
			goto _exit;
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & st_mtim_tv_nsec);
		if (err)
			goto _exit;
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & st_ctim_tv_sec);
		if (err)
			goto _exit;
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & st_ctim_tv_nsec);
		if (err)
			goto _exit;
		sprintf(buf,"%u;%u;%u;%lu;%lu;%lu;%lu;%lu;%lu",
				st_mode, st_uid, st_gid,
				st_atim_tv_sec, st_atim_tv_nsec,
				st_mtim_tv_sec, st_mtim_tv_nsec,
				st_ctim_tv_sec, st_ctim_tv_nsec);
		goto _exit;
	}
	if (ver == 5) {
		const uint8_t *data;
		uint32_t nout;
		err = msgpack_unpack_raw(u, &data, &nout);
		if (!err)
		    memcpy(buf, data, nout);
		goto _exit;
	}
	if (ver == 6) {
		char ts[STR_MAXLEN] = "";
		const uint8_t *data;
		uint32_t nout;
		err = msgpack_unpack_raw(u, &data, &nout);
		if (err)
			goto _exit;
		err = msgpack_unpack_str(u, ts, STR_MAXLEN);
		if (err)
			goto _exit;
		err = msgpack_unpack_str(u, content_type, STR_MAXLEN);
		if (err)
			goto _exit;
		sprintf(buf,"%s;%s;%u;%s", ts, content_type, nout, (char *)data);
		goto _exit;
	}

_exit:
	msgpack_unpack_free(u);
	return err;
}

static int
unpackKeyExt(void *value, size_t value_size, char *buf, size_t buf_size) {
	buf[0] = '\0';
	if (value_size == 0 || !value) {
		return 0;
	}
	int err = 0;
	uint8_t ver=0;

	msgpack_u *u = msgpack_unpack_init(value, value_size, 0);
	err = msgpack_unpack_uint8(u, &ver);
	if (err) {
		goto _exit;
	}
	log_trace(lg, "ver: %u", ver);
	if (ver == 6) {
		char ts[STR_MAXLEN] = "";
		char content_type[STR_MAXLEN] = "";
		const uint8_t *data;
		uint32_t nout;
		err = msgpack_unpack_raw(u, &data, &nout);
		if (err)
			goto _exit;
		err = msgpack_unpack_str(u, ts, STR_MAXLEN);
		if (err)
			goto _exit;
		err = msgpack_unpack_str(u, content_type, STR_MAXLEN);
		if (err)
			goto _exit;
		long lts = strtol(ts, NULL, 10);
		if (lts > 0) {
			if (lts > 9999999999L) {
				lts = lts/1000;
			}
			time_t t = (time_t) lts;
			strftime(ts, STR_MAXLEN, "%Y-%m-%d %H:%M:%S", localtime(&t));
		}
		sprintf(buf,"%s\t%s\t%u", ts, content_type, nout);
		goto _exit;
	}

_exit:
	msgpack_unpack_free(u);
	return err;
}

static void
free_cache_space(char **cache, int cache_count) {
	if (!cache)
		return;
	for (int i=0; i< cache_count; i++) {
		if (cache[i]) {
			je_free(cache[i]);
			cache[i] = NULL;
		}
	}
}

static void
load_more_cache(int last_cache, char **cache_key, char **cache_value, int *action, int *cache_count) {
	if (*cache_count == 0 && last_cache < 0)
		return;
	char *prefix = strdupa(cache_key[last_cache]);
	log_trace(lg, "prefix: %s", prefix);

	free_cache_space(cache_key, *cache_count);
	free_cache_space(cache_value, *cache_count);

	*cache_count = CACHE_LIST_STEP;
	list_cache_list(list_cache, prefix, strlen(prefix),
			cache_key, cache_value, action, cache_count, 1);
}


static int objio_kvlist_bucket(objio_info_t *ci, char *prefix, char *marker, char **key, char **value, uint32_t *count,
		uint32_t *total) {
	int err = 0;
	uv_buf_t uv_b;

	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	*total = 0;
	unsigned int n = 0;
	int ccur = 0;

	int action[CACHE_LIST_STEP];
	char *cache_key[CACHE_LIST_STEP];
	char *cache_value[CACHE_LIST_STEP];
	int last_cache = -1;

	size_t marker_size = strlen(marker);
	size_t prefix_size = strlen(prefix);
	int cache_count = CACHE_LIST_STEP;

	char *start = "";
	char cache_start[MAX_ITEM_SIZE];
	size_t start_size;
	size_t cache_start_size;
	if (marker_size > 0 && marker_size > prefix_size) {
		start = marker;
		start_size = marker_size;
		cache_start_size = sprintf(cache_start, "%s%s", ci->key, marker);
	} else if (prefix_size > 0) {
		start = prefix;
		start_size = prefix_size;
		cache_start_size = sprintf(cache_start, "%s%s", ci->key, prefix);
	} else {
		start_size = 0;
		cache_start_size = sprintf(cache_start, "%s", ci->key);
	}

	char *pattern = (prefix_size > marker_size ? prefix : marker);
	int plength = strlen(pattern);

	list_cache_list(list_cache, cache_start, cache_start_size, cache_key, cache_value, action, &cache_count, 0);

	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "kvlist error on create compleatin: %d", err);
		goto _exit;
	}

	log_trace(lg, "kvlist count: %d, prefix: %s, marker: %s", *count, prefix, marker);
	log_trace(lg, "kvlist start: %s, cache_start: %s", start, cache_start);

	struct iovec iovkey = { .iov_base = start, .iov_len = start_size };

	err = ccow_get_list(ci->bid, ci->bid_size, ci->oid, ci->oid_size, c, &iovkey, 1, *count, &iter);
	if (err) {
		log_error(lg, "kvlist error on get list: %d", err);
		goto _exit;
	}

	err = ccow_wait(c, 0);
	if (err && err != -ENOENT) {
		log_error(lg, "kc list error on CCOW wait: %d", err);
		goto _exit;
	} else {
		c = NULL;
	}

	if (err == -ENOENT) { // No entry, copy from cache
		log_trace(lg, "kvlist bucket ENOENT copy from cache cache_count: %d", cache_count);
		while (n < *count && cache_count > 0) {
			if (ccur < cache_count) {
				last_cache = ccur;
				if (action[ccur] == ACTION_PUT) {
					key[n] = je_strdup(cache_key[ccur] + ci->key_size);
					value[n] = cache_value[ccur];
					*total += strlen(key[n]) + strlen(value[n]);
					cache_value[ccur] = NULL;
					n++;
				}
				ccur++;
			} else {
				log_trace(lg, "kvlist bucket all from cache, upload..");
				load_more_cache(last_cache, cache_key, cache_value, action, &cache_count);
				log_trace(lg, "kvlist bucket all from cache, uploaded: %d", cache_count);
				ccur = 0;
			}
		}
		goto _exit;
	}

	struct ccow_metadata_kv *kv;
	void *t;

	int value_len;
	do {
		t = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1);
		kv = (struct ccow_metadata_kv *) t;
		if (kv == NULL) { // End of ccow list, copy from cache
			log_trace(lg, "kvlist bucket all from cache cache_count: %d", cache_count);
			while (n < *count && cache_count > 0) {
				if (ccur < cache_count) {
					last_cache = ccur;
					if (action[ccur] == ACTION_PUT) {
						log_trace(lg, "kvlist bucket add cache_key: %s", cache_key[ccur]);
						key[n] = je_strdup(cache_key[ccur] + ci->key_size);
						value[n] = cache_value[ccur];
						*total += strlen(key[n]) + strlen(value[n]);
						cache_value[ccur] = NULL;
						n++;
					}
					ccur++;
				} else {
					log_trace(lg, "kvlist bucket all from cache, upload..");
					load_more_cache(last_cache, cache_key, cache_value, action, &cache_count);
					log_trace(lg, "kvlist bucket all from cache, uploaded: %d", cache_count);
					ccur = 0;
				}
			}
			break;
		}

		// End of cache, load more
		if (ccur == cache_count && cache_count > 0) {
			log_trace(lg, "kvlist bucket more from cache loading..");
			load_more_cache(last_cache, cache_key, cache_value, action, &cache_count);
			log_trace(lg, "kvlist bucket more from cache loaded cache_count: %d", cache_count);
			ccur = 0;
		}

		if (plength > 0) {
			int l = (plength < kv->key_size ? plength : kv->key_size);
			if (strncmp(kv->key, pattern, l) < 0) {
				continue;
			}
		}

		while (n < *count && cache_count > 0 && ccur < cache_count
				&& strcmp(kv->key, cache_key[ccur] + ci->key_size) > 0) { // from cache
			if (ccur < cache_count) {
				last_cache = ccur;
				if (action[ccur] == ACTION_PUT) {
					log_trace(lg, "kvlist bucket add cache_key: %s", cache_key[ccur]);
					key[n] = je_strdup(cache_key[ccur] + ci->key_size);
					value[n] = cache_value[ccur];
					*total += strlen(key[n]) + strlen(value[n]);
					cache_value[ccur] = NULL;
					n++;
				}
				ccur++;
			} else {
				load_more_cache(last_cache, cache_key, cache_value, action, &cache_count);
				log_trace(lg, "kvlist bucket more from cache loaded cache_count: %d", cache_count);
				ccur = 0;
			}
		}

		if (cache_count > 0 && ccur < cache_count && strcmp(kv->key, cache_key[ccur] + ci->key_size) == 0) {
			last_cache = ccur;
			if (action[ccur] == ACTION_DEL) { // skip del
				log_trace(lg, "kvlist bucket DEL skip cache_key: %s", cache_key[ccur]);
				ccur++;
				continue;
			}
			if (action[ccur] == ACTION_PUT) { // skip cache PUT
				log_trace(lg, "kvlist bucket PUT skip cache_key: %s", cache_key[ccur]);
				ccur++;
			}
		}

		char buf[VALUE_BUFFER_SIZE] = "";
		err = unpackValue(kv->value, kv->value_size, buf, VALUE_BUFFER_SIZE);
		if (err) {
			log_error(lg, "kvlist error on unpack: %d", err);
			goto _exit;
		}

		value_len = strlen(buf);
		key[n] = je_strndup(kv->key, kv->key_size);
		log_trace(lg, "kvlist bucket add from ccow key: %s", key[n]);
		value[n] = je_strndup(buf, value_len);
		*total += kv->key_size + value_len;
		n++;
	} while (kv != NULL);

	*count = n;

	// Free space
	free_cache_space(cache_key, cache_count);
	free_cache_space(cache_value, cache_count);

	_exit: if (iter)
		ccow_lookup_release(iter);
	if (c)
		ccow_release(c);
	return err;
}

int objio_kvlist(objio_info_t *ci, char *prefix, char *marker, char **key, char **value, uint32_t *count,
		uint32_t *total) {
	int err = 0;
	uv_buf_t uv_b;

	if (ci->oid_size == 0 || ci->oid[0] == '\0') {
		return objio_kvlist_bucket(ci, prefix, marker, key, value, count, total);
	}

	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	*total = 0;

	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "kvlist error on create compleatin: %d", err);
		goto _exit;
	}

	size_t marker_size = strlen(marker);
	size_t prefix_size = strlen(prefix);

	char *pattern = (prefix_size > marker_size ? prefix : marker);
	log_trace(lg, "kvlist count: %d, pattern: %s", *count, pattern);

	int plength = strlen(pattern);
	struct iovec iovkey = { .iov_base = pattern, .iov_len = plength };

	err = ccow_get_list(ci->bid, ci->bid_size, ci->oid, ci->oid_size, c, &iovkey, 1, *count, &iter);
	if (err) {
		log_error(lg, "kvlist error on get list: %d", err);
		goto _exit;
	}

	err = ccow_wait(c, 0);
	if (err) {
		if (err != -ENOENT)
			log_error(lg, "kc list error on CCOW wait: %d", err);
		goto _exit;
	} else {
		c = NULL;
	}

	struct ccow_metadata_kv *kv;
	void *t;
	unsigned int n = 0;
	int value_len;
	do {
		t = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1);
		kv = (struct ccow_metadata_kv *) t;
		if (kv == NULL) {
			break;
		}
		if (plength > 0) {
			int l = (plength < kv->key_size ? plength : kv->key_size);
			if (strncmp(kv->key, pattern, l) < 0) {
				continue;
			}
		}
		if (prefix_size > 0) {
			if (kv->key_size < prefix_size)
				break;
			if (strncmp(kv->key, prefix, prefix_size) != 0) {
				break;
			}
		}

		char buf[VALUE_BUFFER_SIZE] = "";
		err = unpackValue(kv->value, kv->value_size, buf, VALUE_BUFFER_SIZE);
		if (err) {
			log_error(lg, "kvlist error on unpack: %d", err);
			goto _exit;
		}
		value_len = strlen(buf);
		key[n] = je_strndup(kv->key, kv->key_size);
		value[n] = je_strndup(buf, value_len);
		*total += kv->key_size + value_len;
		n++;
	} while (kv != NULL && n < *count);

	*count = n;

	_exit: if (iter)
		ccow_lookup_release(iter);
	if (c)
		ccow_release(c);
	return err;
}

int objio_kvlist_keys(objio_info_t *ci, char *prefix, char *marker, char **key, uint32_t *count,
		uint32_t *total) {
	int err = 0;
	uv_buf_t uv_b;

	if (ci->oid_size == 0 || ci->oid[0] == '\0') {
		return -EINVAL;
	}

	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	*total = 0;

	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "kvlist error on create compleatin: %d", err);
		goto _exit;
	}

	size_t marker_size = strlen(marker);
	size_t prefix_size = strlen(prefix);

	char *pattern = (prefix_size > marker_size ? prefix : marker);
	log_trace(lg, "kvlist count: %d, pattern: %s", *count, pattern);

	int plength = strlen(pattern);
	struct iovec iovkey = { .iov_base = pattern, .iov_len = plength };

	err = ccow_get_list(ci->bid, ci->bid_size, ci->oid, ci->oid_size, c, &iovkey, 1, *count, &iter);
	if (err) {
		log_error(lg, "kvlist error on get list: %d", err);
		goto _exit;
	}

	err = ccow_wait(c, 0);
	if (err) {
		if (err != -ENOENT)
			log_error(lg, "kc list error on CCOW wait: %d", err);
		goto _exit;
	} else {
		c = NULL;
	}

	struct ccow_metadata_kv *kv;
	void *t;
	unsigned int n = 0;
	int value_len;
	do {
		t = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1);
		kv = (struct ccow_metadata_kv *) t;
		if (kv == NULL) {
			break;
		}
		if (plength > 0) {
			int l = (plength < kv->key_size ? plength : kv->key_size);
			if (strncmp(kv->key, pattern, l) < 0) {
				continue;
			}
		}
		if (prefix_size > 0) {
			if (kv->key_size < prefix_size)
				break;
			if (strncmp(kv->key, prefix, prefix_size) != 0) {
				break;
			}
		}

		char ext[KEY_STR_MAXLEN] = "";
		char buf[KEY_STR_MAXLEN] = "";
		int key_len = 0;
		err = unpackKeyExt(kv->value, kv->value_size, ext, KEY_STR_MAXLEN);
		if (err) {
			log_error(lg, "kvlist key error on unpack: %d", err);
			goto _exit;
		}
		if (ext[0] != '\0') {
			strncpy(buf, kv->key, kv->key_size);
			strcat(buf, "\t");
			strcat(buf, ext);
			key_len = strlen(buf);
			key[n] = je_strndup(buf, key_len);
		} else {
			key[n] = je_strndup(kv->key, kv->key_size);
			key_len = kv->key_size;
		}
		*total += key_len;
		n++;
	} while (kv != NULL && n < *count);

	*count = n;

	_exit: if (iter)
		ccow_lookup_release(iter);
	if (c)
		ccow_release(c);
	return err;
}

int objio_kvget(objio_info_t *ci, char *key, void *arg, char *(*alloc_buf)(void *arg, uint32_t size),
	char **value, uint32_t *nout, char *content_type, uint32_t content_max) {
	int err = 0;
	uv_buf_t uv_b;
	msgpack_u *u = NULL;

	if (ci->oid_size == 0 || ci->oid[0] == '\0' || key == NULL || key[0] == '\0') {
		return -EINVAL;
	}

	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;

	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "kvget error on create completion: %d", err);
		goto _exit;
	}

	log_trace(lg, "kvget key: %s", key);

	int klength = strlen(key);
	struct iovec iovkey = { .iov_base = key, .iov_len = klength };

	uint32_t count = 1;

	err = ccow_get_list(ci->bid, ci->bid_size, ci->oid, ci->oid_size, c, &iovkey, 1, count, &iter);
	if (err) {
		log_error(lg, "kvget error on get list: %d", err);
		goto _exit;
	}

	err = ccow_wait(c, 0);
	if (err) {
		if (err != -ENOENT)
			log_error(lg, "kvget error on CCOW wait: %d", err);
		goto _exit;
	} else {
		c = NULL;
	}

	struct ccow_metadata_kv *kv;
	void *t;
	unsigned int n = 0;
	int value_len;
	do {
		t = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX | CCOW_MDTYPE_CUSTOM, -1);
		kv = (struct ccow_metadata_kv *) t;
		if (kv == NULL) {
			break;
		}

		if (kv->mdtype == CCOW_MDTYPE_CUSTOM) {
			if (strcmp(kv->key, "content-type") == 0 && kv->value_size < MAX_ITEM_SIZE) {
				memcpy(ci->content_type, kv->value, kv->value_size);
				ci->content_type[kv->value_size] = '\0';
			}
			continue;
		}

		int l = (klength < kv->key_size ? klength : kv->key_size);
		if (strncmp(kv->key, key, l) < 0) {
			continue;
		}

		uint8_t ver=0;
		u = msgpack_unpack_init(kv->value, kv->value_size, 0);
		err = msgpack_unpack_uint8(u, &ver);
		if (err) {
			log_error(lg, "kvget error on unpack: %d", err);
			goto _exit;
		}
		if (ver != 5 && ver != 6) {
			err = -EINVAL;
			log_error(lg, "kvget error on unpack: %d", err);
			goto _exit;
		}

		const uint8_t *data;
		err = msgpack_unpack_raw(u, &data, nout);
		if (err) {
			log_error(lg, "kvget error on unpack: %d", err);
			goto _exit;
		}

		content_type[0] = '\0';

		if (ver == 6) {
			char ts[STR_MAXLEN] = "";
			err = msgpack_unpack_str(u, ts, STR_MAXLEN);
			if (err)
				log_error(lg, "kvget error on unpack: %d", err);
			err = msgpack_unpack_str(u, content_type, content_max);
			if (err)
				log_error(lg, "kvget error on unpack: %d", err);
		}

		*value = alloc_buf(arg, *nout);
		if (*value == NULL) {
			err = -ENOMEM;
			log_error(lg, "kvget error on unpack: %d", err);
			goto _exit;
		}
		memcpy(*value, data, *nout);
		n++;
		goto _exit;
	} while (kv != NULL && n < count);


_exit:
	if (n == 0) {
		err = -ENOENT;
	}

	if (iter)
		ccow_lookup_release(iter);
	if (c)
		ccow_release(c);
	if (u)
		msgpack_unpack_free(u);

	return err;
}

int objio_delete(objio_info_t *ci) {
	int err = 0;

	ccow_completion_t c = NULL;

	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "delete error on create compleatin: %d", err);
		goto _exit;
	}

	err = ccow_delete(ci->bid, ci->bid_size, ci->oid, ci->oid_size, c);
	if (err) {
		log_error(lg, "delete error: %d", err);
		goto _exit;
	}

	err = ccow_wait(c, 0);
	if (err) {
		if (err != -ENOENT)
			log_error(lg, "delete error on CCOW wait: %d", err);
		goto _exit;
	} else {
		c = NULL;
		list_cache_record_t *rec = NULL;
		err = cache_record_ini(ACTION_DEL, NULL, ci->uvid, ci->size, ci->genid, &ci->vmchid, 0, 0, NULL, &rec);
		if (err) {
			log_error(lg, "cannot create list cache record: %d", err);
			goto _exit;
		}
		log_trace(lg, "Delete list cache key: %s", ci->key);
		err = list_cache_insert(list_cache, ci->key, ci->key_size, rec);
	}

	_exit: if (c)
		ccow_release(c);
	return err;
}

int objio_get_attributes(objio_info_t *ci, char *bid, int bid_size, char* oid, int oid_size) {
	int err = 0;

	ccow_completion_t c = NULL;

	// Get attributes
	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "get object attributes: %d", err);
		c = NULL;
		return err;
	}

    ccow_lookup_t iter = NULL;

	err = ccow_get(bid, bid_size, oid, oid_size, c, NULL, 0, 0, &iter);
	if (err || !iter) {
		log_error(lg, "get object attributes: %d", err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_error(lg, "get object attributes: %d", err);
		ccow_release(c);
		return err;
	}

	read_attributes(ci, iter);
	ccow_lookup_release(iter);

	return err;
}


int objio_bucket_create(objio_info_t *ci, param_vector *attrs) {
	int err = 0;

	ccow_completion_t c = NULL;

	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "bucket create error on create compleatin: %d", err);
		c = NULL;
		return err;
	}

	err = ccow_bucket_create(ci->tc, ci->bid, ci->bid_size, c);
	if (err) {
		ccow_release(c);
		log_error(lg, "bucket create error: %d", err);
		return err;
	}
	ccow_release(c);

	log_trace(lg, "bucket object create ok");

	// Get attributes
	err = objio_get_attributes(ci, ci->bid, ci->bid_size, "", 1);
	if (err) {
		log_error(lg, "bucket create read attributes error: %d", err);
		return err;
	}

	// Str nhid
	char nhid[UINT512_BYTES*2+1];
	str_hash_id(&ci->nhid, nhid, UINT512_BYTES*2);


	// Create metadata
	c = NULL;
	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "bucket create error on create compleatin: %d", err);
		return err;
	}

	err = objio_modify_custom(c, attrs);
	if (err) {
		ccow_release(c);
		return err;
	}

	log_trace(lg, "bucket %s attribute object %s", ci->bid, nhid);

	err = ccow_put_notrlog(ci->bid, ci->bid_size, nhid, UINT512_BYTES*2+1, c,
	    NULL, 0, 0);
	if (err) {
		log_error(lg, "bucket attributes create error: %d", err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, -1);
	if (err) {
		ccow_release(c);
		log_error(lg, "bucket attributes create error on wait: %d", err);
	}
	log_trace(lg, "bucket attribute create ok");

	return err;
}


int objio_bucket_delete(objio_info_t *ci) {
	int err = 0;

	ccow_completion_t c = NULL;

	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "bucket delete error on create compleatin: %d", err);
		goto _exit;
	}

	// Delete metadata
	char nhid[UINT512_BYTES*2+1];
	str_hash_id(&ci->nhid, nhid, UINT512_BYTES*2);
	err = ccow_delete(ci->bid, ci->bid_size, nhid, UINT512_BYTES*2+1, c);
	if (err) {
		log_error(lg, "bucket attributes delete error: %d", err);
	} else {
		err = ccow_wait(c, 0);
		if (err) {
			ccow_drop(c);
			log_error(lg, "bucket attributes delete error on CCOW wait: %d", err);
		}
		c = NULL;
	}
	log_trace(lg, "bucket attributes delete ok");

	err = ccow_bucket_delete(ci->tc, ci->bid, ci->bid_size);
	log_trace(lg, "bucket delete error: %d", err);

_exit: if (c)
	       ccow_release(c);
       return err;
}


int objio_bucket_head(objio_info_t *ci) {
	int err = 0;

	// Get attributes
	err = objio_get_attributes(ci, ci->bid, ci->bid_size, "", 1);
	if (err) {
		log_error(lg, "bucket head read attributes error: %d", err);
		return err;
	}

	ccow_completion_t c = NULL;

	err = ccow_create_completion(ci->tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "bucket head error on create compleatin: %d", err);
		goto _exit;
	}

	ccow_lookup_t iter = NULL;

	char nhid[UINT512_BYTES*2+1];
	str_hash_id(&ci->nhid, nhid, UINT512_BYTES*2);
	log_trace(lg, "objio_bucket_head nhid: %s", nhid);
	err = ccow_get(ci->bid, ci->bid_size, nhid, UINT512_BYTES*2+1, c, NULL,
	    0, 0, &iter);
	if (err) {
		log_error(lg, "bucket head attributes error: %d", err);
		err = 0;
		goto _exit;
	}

	err = ccow_wait(c, -1);
	if (err) {
		log_error(lg, "bucket head attributes error on CCOW wait: %d", err);
		err = 0;
		goto _exit;
	}

	if (iter) {
		add_attributes(ci, iter);
	}

_exit: if (c)
	       ccow_release(c);
       if (iter)
	       ccow_lookup_release(iter);
       return err;
}


uint64_t trlog_marker_timestamp(char *cluster) {
	ccow_t ta;
	uint64_t ts = 0;

	int fd = open("/opt/nedge/etc/ccow/ccow.json", O_RDONLY);
	char *buf = je_calloc(1, 16384);
	ssize_t count = read(fd, buf, 16383);
	if (count <= 0) {
		je_free(buf);
		close(fd);
		log_error(lg, "read error: /opt/nedge/etc/ccow/ccow.json");
		return ts;
	}
	close(fd);

	int err = ccow_admin_init(buf, cluster, strlen(cluster) + 1, &ta);
	je_free(buf);

	if (err) {
		log_error(lg, "tenant init error: %d", err);
		return ts;
	}

	char *marker_arr[2];
	int marker_arr_len;

	marker_arr[0] = (char *) je_calloc(1, MARKER_RECORD_MAXSIZE);
	marker_arr[1] = (char *) je_calloc(1, MARKER_RECORD_MAXSIZE);
	if (!marker_arr[0] || !marker_arr[1]) {
		log_error(lg, "marker read error: %d", -ENOMEM);
		return ts;
	}


	err = trlog_read_marker(ta, SHARD_LEADER_PREFIX, marker_arr, &marker_arr_len);
	if (err == 0) {
		if (marker_arr_len == 2) {
			ts = strtoull((char*) marker_arr[1], NULL, 10);
			if (errno == EINVAL || errno == ERANGE) {
				log_error(lg, "Cannot convert %s: %s",
				SHARD_LEADER_PREFIX, (char*) marker_arr[1]);
				ts = 0;
			} else {
				ts -= TRLOG_PROCESSING_QUARANTINE*10*1000000UL;
				ts /= 1000000;
			}
		}
	}

	je_free(marker_arr[0]);
	je_free(marker_arr[1]);

	ccow_tenant_term(ta);

	return ts;
}
