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
#include <uv.h>

#include <execinfo.h>
#include "ccowutil.h"
#include "skiplist.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "rtbuf.h"
#include "sop_cache.h"

int
ccow_shard_context_set_overwrite(ccow_shard_context_t shard_context,
    int overwrite)
{
	shard_context->overwrite = overwrite;
	return 0;
}

int
ccow_shard_context_set_eventual(ccow_shard_context_t shard_context,
    int eventual)
{
	shard_context->eventual = eventual;
	return 0;
}

int
ccow_shard_context_set_inline_flag(ccow_shard_context_t shard_context,
    uint16_t flag)
{
	shard_context->inline_data_flag = flag;
	return 0;
}

int
ccow_shard_context_create(char *shard_name, size_t shard_name_size,
    int shard_count, ccow_shard_context_t *shard_context)
{
	struct ccow_shard_context *sc = je_malloc(sizeof(*sc));

	if (!sc) {
		return -ENOMEM;
	}
	sc->shard_name = je_calloc(1, shard_name_size);
	if (!sc->shard_name) {
		je_free(sc);
		return -ENOMEM;
	}
	memcpy(sc->shard_name, shard_name, shard_name_size);
	sc->shard_name_size = shard_name_size;
	sc->shard_count = shard_count;
	sc->encryption = 0;
	sc->eventual = 0;
	sc->overwrite = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
	sc->inline_data_flag = 0;
	*shard_context = sc;
	return 0;
}

void
ccow_shard_context_destroy(ccow_shard_context_t *shard_context)
{
	struct ccow_shard_context *sc = *shard_context;

	je_free(sc->shard_name);
	je_free(sc);
}

static char *
get_shard_name(char *buf, ccow_shard_context_t shard_context, int n)
{
	sprintf(buf, "%s.%d", shard_context->shard_name, n);
	return buf;
}


int
ccow_sharded_list_create(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context)
{
	uint64_t zero = 0;
	uint16_t num_vers;
	int err = 0, i;
	struct ccow *tc = tctx;

	if (bid_size > REPLICAST_STR_MAXLEN) {
		log_error(lg, "BID length is greater then %d",
		    REPLICAST_STR_MAXLEN);
		return -EINVAL;
	}

	for (i = 0; i < shard_context->shard_count; i++) {
		ccow_completion_t c;

		err = ccow_create_completion(tc, NULL, NULL, 1, &c);
		if (err)
			return err;

		/*
		 * create new+empty object with btree name index.
		 */
		err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
		    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
		if (err) {
			ccow_release(c);
			return err;
		}

		/*
		 * default is 1.
		 */
		num_vers = 1;

		err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
		    (void *)&num_vers, NULL);
		if (err) {
			ccow_release(c);
			return err;
		}

		err = ccow_attr_modify_default(c, CCOW_ATTR_LOGICAL_SZ,
		    (void *)&zero, NULL);
		if (err) {
			ccow_release(c);
			return err;
		}

		err = ccow_attr_modify_default(c, CCOW_ATTR_PREV_LOGICAL_SZ,
		    (void *)&zero, NULL);
		if (err) {
			ccow_release(c);
			return err;
		}

		err = ccow_attr_modify_default(c, CCOW_ATTR_OBJECT_COUNT,
		    (void *) &zero, NULL);
		if (err) {
			ccow_release(c);
			return err;
		}

		err = ccow_attr_modify_default(c, CCOW_ATTR_ESTIMATED_USED,
		    (void *) &zero, NULL);
		if (err) {
			ccow_release(c);
			return err;
		}

		if (shard_context->encryption) {
			uint8_t hash_type = HASH_TYPE_BLAKE2B_256;

			CRYPTO_ENC_SET(hash_type);
			err = ccow_attr_modify_default(c, CCOW_ATTR_HASH_TYPE,
			    (void *) &hash_type, NULL);
			if (err) {
				ccow_release(c);
				return err;
			}
		}

		/*
		 * 48 entries max of ~ 1K per entry.
		 */
		uint16_t order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_1K;

		err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		    &order, NULL);
		if (err) {
			ccow_release(c);
			return err;
		}

		// Set inline data flag
		err = ccow_attr_modify_default(c, CCOW_ATTR_INLINE_DATA_FLAGS,
			(void *)&shard_context->inline_data_flag, NULL);
		if (err) {
			ccow_release(c);
			return err;
		}

		char oid[1024];

		get_shard_name(oid, shard_context, i);
		log_debug(lg, "Creating shard %s", oid);

		err = ccow_put_notrlog(bid, bid_size, oid, strlen(oid) + 1, c,
		    NULL, 0, 0);
		if (err) {
			log_error(lg, "Shard %s create error: %d", oid, err);
			ccow_release(c);
			return err;
		}

		err = ccow_wait(c, 0);
		if (err) {
			log_error(lg, "Shard %s create error: %d", oid, err);
			if (err != -EEXIST)
				return err;
		}
	}

	return err;
}

int
ccow_sharded_attributes_create(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context)
{

	return ccow_sharded_list_create(tctx, bid, bid_size, shard_context);
}

static sop_rec_table*
get_rec_table_from_cache(struct ccow *tc,const char *bid, char *shard_name) {
	int err = 0;

	char path[2048] = "";
	sop_rec_table *sop_rec_tb = NULL;
	sprintf(path,"%s/%s/%s/%s",tc->cid, tc->tid, bid, shard_name);
	size_t path_size = strlen(path) + 1;
	if (sop_shard_table_get(tc->shard_cache, path, path_size, &sop_rec_tb) != 0) {
		return NULL;
	}
	return sop_rec_tb;
}



static int
ccow_sharded_flush(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, uint64_t *genid, int i)
{
	int err = 0;
	ccow_completion_t c = NULL;
	struct ccow *tc = tctx;

	struct iovec iov[1];
	char *key = "";
	iov[0].iov_base = key;
	iov[0].iov_len = 1;
	size_t iovcnt = 1;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Shard flush create completion error: %d", err);
		return err;
	}

	c->shard_index = i;

	char oid[1024] = "";
	get_shard_name(oid, shard_context, i);

	/*
	 * Use SOP operation to send flush.
	 */
	c->cont_flags |= CCOW_CONT_F_EVENTUAL_SOP;
	c->sop_generation = genid;

	err = ccow_container_update_list(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, strlen(oid) + 1, c, iov, iovcnt,
	    CCOW_SOP_FLUSH);
	if (err) {
		log_error(lg, "Shard %s flush error: %d", oid, err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err && err != -EEXIST) {
		log_error(lg, "Shard %s flush error: %d", oid, err);
	}

	return err;
}

int
ccow_sharded_list_destroy(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context)
{
	int err = 0, i, res = 0;
	struct ccow *tc = tctx;

	sop_rec_table *sop_rec_tb = get_rec_table_from_cache(tc, bid, shard_context->shard_name);

	for (i = 0; i < shard_context->shard_count; i++) {
		char oid[1024] = "";
		get_shard_name(oid, shard_context, i);
		log_debug(lg, "Deleting shard %s", oid);

		if (sop_rec_tb) {
			err = ccow_sharded_flush(tc, bid, bid_size,	shard_context, &sop_rec_tb->genid[i], i);
			if (err) {
				log_error(lg, "Shard %s delete flush error: %d", oid, err);
			} else {
				log_debug(lg, "Shard %s delete flushed, genid: %lu", oid, sop_rec_tb->genid[i]);
			}
		}

		ccow_completion_t c;

		err = ccow_create_completion(tc, NULL, NULL, 1, &c);
		if (err) {
	    	sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
			return err;
		}

		err = ccow_delete_notrlog(bid, bid_size, oid, strlen(oid) + 1, c);
		if (err) {
			log_error(lg, "Shard %s delete error: %d", oid, err);
			ccow_release(c);
	    	sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
			return err;
		}

		err = ccow_wait(c, 0);
		if (err) {
			if (err && err != -ENOENT) {
				log_error(lg, "Shard %s delete error: %d", oid,
				    err);
		    	sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
				return err;
			}
			res = err;
		}
	}

	// Success
	sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
	if (res == 0 && sop_rec_tb) {
		char path[2048] = "";
		sprintf(path,"%s/%s/%s/%s",tc->cid, tc->tid, bid, shard_context->shard_name);
		err = sop_shard_table_delete(tc->shard_cache, path, strlen(path) + 1);
	}
	return res;
}

int
ccow_sharded_attributes_destroy(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context)
{

	return ccow_sharded_list_destroy(tctx, bid, bid_size, shard_context);
}

/*
 * Calculate the shard index of the key
 */
static int
get_shard(char *key, size_t key_size, int shard_count)
{
	uint512_t hash;
	int err;

	err = crypto_hash_with_type(HASH_TYPE_DEFAULT, (uint8_t *) key,
	    key_size, (uint8_t *) & hash);

	if (err) {
		log_error(lg,
		    "Error while calculating shard_count " "hash id value: %d",
		    err);
		return -EINVAL;
	}
	uint16_t mask = shard_count - 1;
	int i = HASHCALC(&hash, mask);

	return i;
}

static int
read_shard_attributes(struct ccow *tc,const char *bid, char *shard_name, int index,
		int64_t *size, int64_t *objs, int64_t *used, uint64_t *genid) {
	char oid[1024];
	sprintf(oid, "%s.%d", shard_name, index);
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	int err = ccow_create_completion(tc, NULL,  NULL, 1, &c);
	if (err) {
		log_error(lg, "Shard %s could not create completion err: %d", oid, err);
		goto _exit;
	}
	err = ccow_get(bid, strlen(bid) + 1,  oid, strlen(oid) + 1, c, NULL, 0, 0, &iter);
	if (err) {
		if (c)
			ccow_release(c);
		log_error(lg, "Shard %s could not start get attributes err: %d", oid, err);
		goto _exit;
	}

	err = ccow_wait(c, 0);
	if (err) {
		if (err != -ENOENT)
			log_error(lg, "Shard %s could not get attributes err: %d", oid, err);
		if (iter)
				ccow_lookup_release(iter);
		goto _exit;
	}
	struct ccow_metadata_kv *kv;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
		if (!strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE)) {
			*size = *(uint64_t *) kv->value;
			continue;
		}
		if (!strcmp(kv->key, RT_SYSKEY_OBJECT_COUNT)) {
			*objs = *(uint64_t *) kv->value;
			continue;
		}
		if (!strcmp(kv->key, RT_SYSKEY_ESTIMATED_USED)) {
			*used = *(uint64_t *) kv->value;
			continue;
		}
		if (!strcmp(kv->key, RT_SYSKEY_TX_GENERATION_ID)) {
			*genid = *(uint64_t *) kv->value;
			continue;
		}
	}
	if (iter)
		ccow_lookup_release(iter);
_exit:
    return err;
}

int
evict_sop_cache(struct ccow *tc) {
	int err = 0;
	unsigned int key_count = 0;
	void **keys = NULL;
	char *ckey;
	ccow_shard_context_t context;
	uint64_t timeout;
	sop_rec_table *sop_rec_tb;
	size_t ent_size;
	keys = hashtable_keys(tc->shard_cache->ht, &key_count);


	for (unsigned int i = 0; i < key_count; i++) {
		ckey = (char *) keys[i];
		sop_rec_tb = hashtable_get(tc->shard_cache->ht, keys[i], strlen(ckey) + 1, &ent_size);

		if (!sop_rec_tb)
			continue;

		timeout = (get_timestamp_us() - sop_rec_tb->insert_time_last);
		if (timeout < CACHE_EVICT_TIMEOUT) {
			continue;
		}


		err = ccow_shard_context_create(sop_rec_tb->shard_name,
		    strlen(sop_rec_tb->shard_name) + 1,
			sop_rec_tb->shard_count, &context);
		if (err) {
			log_error(lg, "Shard %s.%d evict context error: %d", sop_rec_tb->shard_name, i, err);
			continue;
		}

		// Read attributes, check genid
		//int64_t size, objs, used;
		uint64_t g;
		int evict = 1;
		for (int i=0; i<sop_rec_tb->shard_count; i++) {
			err = ccow_sharded_flush(tc, sop_rec_tb->bid, strlen(sop_rec_tb->bid) + 1, context, &g, i);
			if (err) {
				log_error(lg, "Shard %s.%d evict flush error: %d", sop_rec_tb->shard_name, i, err);
				continue;
			} else {
				log_debug(lg, "Shard %s.%d evict flushed, genid: %lu", sop_rec_tb->shard_name, i, g);
			}

			log_debug(lg, "Checking cache %s.%d genid_cluster: %lu, genid_cache: %lu, busy_count: %d",
					ckey, i, g, sop_rec_tb->genid[i], sop_rec_tb->busy_count);

			if (g && g < sop_rec_tb->genid[i]) {
				evict = 0;
				break;
			}
		}

		ccow_shard_context_destroy(&context);

		if (!evict) {
			continue;
		}

		timeout = (get_timestamp_us() - sop_rec_tb->insert_time_last);
		if (timeout < CACHE_EVICT_TIMEOUT) {
			continue;
		}

		log_debug(lg, "Evicting %s from cache, timeout: %lu", ckey, timeout);
		err = sop_shard_table_delete(tc->shard_cache, keys[i], strlen(ckey) + 1);
		log_debug(lg, "Evicting result: %d", err);
	}

	if (keys)
		je_free(keys);

	return 0;
}


static int
add_cache_record(struct ccow *tc,const char *bid, char *shard_name, struct iovec *iov,
    size_t iovcnt, int64_t delta_size, int64_t delta_objs, int64_t delta_used,
    int index, int shard_count, int optype, uint64_t genid)
{
	int err = 0;

	if (iovcnt == 0) {
		err = -EINVAL;
		goto _exit;
	}

	char path[2048] = "";
	sop_rec_table *sop_rec_tb = NULL;
	sprintf(path,"%s/%s/%s/%s", tc->cid, tc->tid, bid, shard_name);
	size_t path_size = strlen(path) + 1;

	sop_rec_table *new_rec_tb = NULL;

	err = sop_shard_table_get(tc->shard_cache, path, path_size, &sop_rec_tb);

	// shard table not found, create a new one
	if (err) {
		new_rec_tb = sop_rec_table_create(shard_count, bid, shard_name);
		if (!new_rec_tb) {
			err = -ENOMEM;
			goto _exit;
		}
		// New table - Read attributes
		int64_t size = 0, objs = 0, used = 0;
		uint64_t g = 0;
		for (int i=0; i<shard_count; i++) {
			err = read_shard_attributes(tc, bid, shard_name, i,
			    &size, &objs, &used, &g);
			if (err == -ENOENT)
				continue;
			if (err) {
				sop_rec_table_destroy(new_rec_tb);
				log_error(lg, "Could not read attributes from %s.%d",
				    shard_name, i);
				goto _exit;
			}
			new_rec_tb->size += size;
			new_rec_tb->objs += objs;
			new_rec_tb->used += used;
			new_rec_tb->genid[i] = g;
		}
		err = sop_shard_table_init(tc->shard_cache, shard_count, path,
		    path_size, bid, shard_name, new_rec_tb, &sop_rec_tb);
		if (err && err != -EEXIST) {
			log_error(lg, "Shard %s cache init error: %d", shard_name, err);
			goto _exit;
		}
	}

	char *key = iov[0].iov_base;
	size_t key_size = iov[0].iov_len;

	void *value = NULL;
	size_t value_size = 0;
	if (iovcnt > 1) {
		value = iov[1].iov_base;
		value_size = iov[1].iov_len;
	}
	log_debug(lg, "Adding cache path: %s, key: %s, optype: %d, genid: %lu, deltas: %ld %ld %ld",
	    path, key, optype, genid, delta_size, delta_objs, delta_used);
	sop_rec_t *sop_rec = sop_rec_init(key, key_size, value, value_size,
	    delta_size,	delta_objs, delta_used, index, optype, genid);
	if (!sop_rec) {
		log_error(lg, "Shard %s put no memory for cache", shard_name);
		err = -ENOMEM;
		goto _exit; // memory will be freed by eviction process
	}
	err = sop_rec_table_put(sop_rec_tb, sop_rec);
	if (err) {
		sop_rec_destroy(sop_rec);
	}

_exit:
    if (sop_rec_tb) {
    	sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
    }
	return err;
}



int
ccow_sharded_list_put_v2(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, struct iovec *iov, size_t iovcnt,
	int overwrite)
{
	int err = 0;
	ccow_completion_t c = NULL;
	struct ccow *tc = tctx;
	char *key = iov[0].iov_base;
	size_t key_size = iov[0].iov_len;
	int put_retry = 0;

	/*
	 * Insert the key value pair in the btree.
	 */
_local_retry:
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Shard put create completion error: %d", err);
		return err;
	}

	int i = get_shard(key, key_size, shard_context->shard_count);

	if (i < 0) {
		return i;
	}
	c->shard_index = i;

	char oid[1024] = "";

	get_shard_name(oid, shard_context, i);

	/*
	 * Use SOP operation to put value.
	 */
	c->cont_flags = overwrite;

	uint64_t genid = 0;
	if (shard_context->eventual) {
		c->cont_flags |= CCOW_CONT_F_EVENTUAL_SOP;

		/* This will contain latest tx genid of SOP op processed on
		 * the backend master device */
		c->sop_generation = &genid;
	}

	err = ccow_container_update_list(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, strlen(oid) + 1, c, iov, iovcnt,
	    CCOW_INSERT_LIST);
	if (err) {
		log_error(lg, "Shard %s put error: %d", oid, err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err && err != -EEXIST) {
		put_retry++;
		log_error(lg, "Shard %s put error: %d (retry=%d)", oid, err, put_retry);
		if (put_retry < 5)
			goto _local_retry;
	}

	// Add to cache
	if (shard_context->eventual) {
		int err = add_cache_record(tc, bid, shard_context->shard_name, iov, iovcnt, 0, 0, 0,
		    i, shard_context->shard_count, SOP_CACHE_INSERT, genid);

		if (err) {
			log_error(lg, "Shard %s put to cache error: %d", oid, err);
			goto _exit;
		}
	}

_exit:
	return err;
}

/* Set uint64_t type attribute */
static inline void
set_uint64_attr(ccow_metadata_kv_t attr, char *key, uint64_t *val)
{
	attr->mdtype = CCOW_MDTYPE_METADATA;
	attr->type = CCOW_KVTYPE_UINT64;
	attr->key = key;
	/* TODO: Find out if this should be strlen(key) + 1 */
	attr->key_size = strlen(key);
	attr->value = val;
	attr->value_size = sizeof(uint64_t);
}

static inline int
set_uint64_attr_iovec(ccow_metadata_kv_t attr, char *key, uint64_t *val,
			msgpack_p **p, uv_buf_t *ubuf, struct iovec *iov)
{
	int err;

	set_uint64_attr(attr, key, val);
	err = ccow_pack_mdkv(attr, p);
	if (err) {
		log_error(lg, "Invalid mdkv packing %d", err);
		return err;
	}
	err = msgpack_get_buffer(*p, ubuf);
	if (err) {
		log_error(lg, "Invalid msgpacking err: %d", err);
		return -ENOMEM;;
	}
	iov->iov_base = ubuf->base;
	iov->iov_len = ubuf->len;
	return 0;
}

int
ccow_sharded_list_put(ccow_t tctx, const char *bid, size_t bid_size,
	ccow_shard_context_t shard_context, struct iovec *iov, size_t iovcnt)
{
	return ccow_sharded_list_put_v2(tctx, bid, bid_size, shard_context,
		iov, iovcnt, shard_context->overwrite);
}

static inline int
check_attr_conflict(int64_t delta_size, int64_t delta_objs, int64_t delta_used)
{
	return !((delta_size >= 0 && delta_objs >= 0 && delta_used >= 0) ||
		(delta_size <= 0 && delta_objs <= 0 && delta_used <= 0));
}

static int
ccow_sharded_list_update_with_md(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, char *parent_key, size_t parent_key_size,
    char *child_key, size_t child_key_size,
    struct iovec *iov, size_t iovcnt,
    int64_t delta_size, int64_t delta_objs, int64_t delta_used, ccow_op_t optype)
{
	int err = 0;
	ccow_completion_t c = NULL;
	ccow_op_t op;
	struct ccow *tc = tctx;
	int shard_index;
	char *key = child_key ? child_key : parent_key;
	size_t key_size = child_key ? child_key_size : parent_key_size;
	int64_t total_delta;	/* to determine if values are +ve ot -ve */

	assert(key != NULL && key_size != 0);

	/* If there is no delta or no list to be updated, return */
	if (delta_size == 0 && delta_objs == 0 &&
	    delta_used == 0 && iov == NULL)
		return 0;

	/* One or more attributes should all either be positive or negative */
	if (check_attr_conflict(delta_size, delta_objs, delta_used))
		return -ERANGE;

	/* Total will either be +ve or negative. Conflict already checked */
	total_delta = delta_size + delta_objs + delta_used;

	/* If this is MD only op and there is no delta, return back */
	if ((optype == CCOW_INSERT_MD || optype == CCOW_DELETE_MD) &&
	    total_delta == 0) {
		/* If MD only op then list vector should be empty */
		assert (iov == NULL);
		return 0;
	}

	/* append attributes into a new iovec */
	size_t newiovcnt = iovcnt;
	size_t idx = 0;
	struct iovec newiov[newiovcnt + 3];
	struct ccow_metadata_kv attr[3];
	msgpack_p *p[3] = { NULL, NULL, NULL };
	uv_buf_t ubuf[3];
	uint64_t d_size, d_objs, d_used;

	shard_index = get_shard(key, key_size, shard_context->shard_count);
	if (shard_index < 0) {
		err = -EINVAL;
		goto _local_err;
	}

	/* copy existing iov into newiov */
	for (size_t i = 0; i < iovcnt; i++) {
		newiov[i].iov_base = iov[i].iov_base;
		newiov[i].iov_len = iov[i].iov_len;
	}

	/* Convert LIST_WITH_MD op to LIST op, if there is no meta-data */
	if ((optype == CCOW_INSERT_LIST_WITH_MD ||
	     optype == CCOW_DELETE_LIST_WITH_MD) && total_delta == 0) {
		op = optype == CCOW_INSERT_LIST_WITH_MD ? CCOW_INSERT_LIST :
							  CCOW_DELETE_LIST;
	} else {
		op = optype;
	}

	d_size = labs(delta_size) + 0LLU;
	d_objs = labs(delta_objs) + 0LLU;
	d_used = labs(delta_used) + 0LLU;

	log_debug(lg, "Put/delete %s/%s/%s/%s key: %s, with delta_size: %ld "
			"deltaobs: %ld, deltaused: %ld",
			tc->cid, tc->tid, bid, shard_context->shard_name, key, delta_size,
			delta_objs, delta_used);


	if (delta_size) {
		err = set_uint64_attr_iovec(&attr[idx], RT_SYSKEY_LOGICAL_SIZE,
					    &d_size, &p[idx], &ubuf[idx],
					    &newiov[iovcnt + idx]);

		if (err)
			goto _local_err;
		idx++;
	}

	if (d_objs) {
		err = set_uint64_attr_iovec(&attr[idx], RT_SYSKEY_OBJECT_COUNT,
					    &d_objs, &p[idx], &ubuf[idx],
					    &newiov[iovcnt + idx]);

		if (err)
			goto _local_err;
		idx++;
	}

	if (d_used) {
		err = set_uint64_attr_iovec(&attr[idx],
					    RT_SYSKEY_ESTIMATED_USED,
					    &d_used, &p[idx], &ubuf[idx],
					    &newiov[iovcnt + idx]);

		if (err)
			goto _local_err;
		idx++;
	}

	/*
	 * Insert the key value pair in the btree.
	 */
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Shard list update with md create "
				"completion error: %d", err);
		goto _local_err;
	}

	c->shard_index = shard_index;
	char shard_oid[1024] = "";
	get_shard_name(shard_oid, shard_context, shard_index);

	if (optype == CCOW_INSERT_LIST_WITH_MD)
		c->cont_flags = shard_context->overwrite;

	uint64_t genid = 0;
	if (shard_context->eventual) {
		c->cont_flags |= CCOW_CONT_F_EVENTUAL_SOP;

		/* This will contain latest tx genid of SOP op processed on
		 * the backend master device */
		c->sop_generation = &genid;
	}

	/* Increment the IO vector count by no. of MD parameters */
	newiovcnt += idx;

	/*
	 * Use SOP operation to put value.
	 */
	err = ccow_container_update_list(tc->cid, tc->cid_size,
		tc->tid, tc->tid_size, bid, bid_size, shard_oid,
		strlen(shard_oid) + 1, c, newiov, newiovcnt, op);

	if (err) {
		log_error(lg, "Err: %d Failed to put/del with update %s/%s/%s/%s ", err,
		    tc->cid, tc->tid, bid, shard_oid);
		ccow_release(c);
		goto _local_err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		log_error(lg, "Err: %d Failed to update wait %s/%s/%s/%s ",
		    err, tc->cid, tc->tid, bid, shard_oid);
		goto _local_err;
	}

	// Add to cache
	if (shard_context->eventual) {
		int o = SOP_CACHE_MD;
		switch (optype) {
			case CCOW_INSERT_LIST_WITH_MD:
				o = SOP_CACHE_INSERT;
				break;
			case CCOW_DELETE_LIST_WITH_MD:
				o = SOP_CACHE_DELETE;
				break;
			default:
				o = SOP_CACHE_MD;
		}
		int err = add_cache_record(tc, bid, shard_context->shard_name, iov, iovcnt,
		    delta_size, delta_objs, delta_used,
			shard_index, shard_context->shard_count, o, genid);


		if (err) {
			log_error(lg, "Shard %s put to cache error: %d", shard_oid, err);
			goto _local_err;
		}
	}

_local_err:
	if (total_delta) {
		for (int i = 0; i < 3; i++)
			if (p[i])
				msgpack_pack_free(p[i]);
	}
	return err;
}

int
ccow_sharded_list_put_with_md(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, char *parent_key, size_t parent_key_size,
    char *child_key, size_t child_key_size,
    struct iovec *iov, size_t iovcnt,
    int64_t delta_size, int64_t delta_objs, int64_t delta_used)
{
	int err = 0;

	err = ccow_sharded_list_update_with_md(tctx, bid, bid_size, shard_context,
		parent_key, parent_key_size,
		child_key, child_key_size, iov, iovcnt,
		delta_size, delta_objs, delta_used,
		CCOW_INSERT_LIST_WITH_MD);
	if (err) {
		/* fixup error message */
		log_error(lg, "Shard put error: %d", err);
	}
	return err;
}

int
ccow_sharded_list_delete_with_md(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, char *parent_key, size_t parent_key_size,
    char *child_key, size_t child_key_size,
    int64_t delta_size, int64_t delta_objs, int64_t delta_used)
{
	int err = 0;
	struct iovec iov[2];

	iov[0].iov_base = child_key;
	iov[0].iov_len = child_key_size;
	iov[1].iov_base = "";
	iov[1].iov_len = 1;
	err = ccow_sharded_list_update_with_md(tctx, bid, bid_size, shard_context,
		parent_key, parent_key_size,
		child_key, child_key_size, iov, 2,
		delta_size, delta_objs, delta_used,
		CCOW_DELETE_LIST_WITH_MD);
	if (err) {
		/* fixup error message */
		log_error(lg, "Shard delete error %d", err);
	}
	return err;
}

int
ccow_sharded_attributes_put(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, char *key, size_t key_size,
    int64_t delta_size, int64_t delta_objs, int64_t delta_used)
{
	int err = 0, shard_index;
	ccow_completion_t c = NULL;
	struct ccow *tc = tctx;
	int64_t total_delta;	/* to determine if values are +ve ot -ve */

	/* If there is no delta to be updated, return */
	if (delta_size == 0 && delta_objs == 0 && delta_used == 0)
		return 0;

	/* One or more attributes should all either be positive or negative */
	if (check_attr_conflict(delta_size, delta_objs, delta_used))
		return -ERANGE;

	/* Total will either be +ve or negative. Conflict already checked */
	total_delta = delta_size + delta_objs + delta_used;

	/*
	 * Determine INSERT or DELETE operation.
	 */
	ccow_op_t optype = total_delta > 0 ? CCOW_INSERT_MD : CCOW_DELETE_MD;

	return ccow_sharded_list_update_with_md(tctx, bid, bid_size,
						shard_context, key,
						key_size, NULL, 0,
						NULL, 0,
						delta_size, delta_objs,
						delta_used, optype);
}

int
ccow_sharded_list_delete(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, char *key, size_t key_size)
{
	int err = 0;
	ccow_completion_t c = NULL;
	struct ccow *tc = tctx;
	struct iovec iov[1];

	/*
	 * Insert the key value pair in the btree.
	 */
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Shard list delete create completion error: %d",
		    err);
		return err;
	}

	int i = get_shard(key, key_size, shard_context->shard_count);

	if (i < 0) {
		return i;
	}
	c->shard_index = i;

	char oid[1024] = "";

	get_shard_name(oid, shard_context, i);

	iov[0].iov_base = key;
	iov[0].iov_len = key_size;

	uint64_t genid = 0;
	if (shard_context->eventual) {
		c->cont_flags |= CCOW_CONT_F_EVENTUAL_SOP;

		/* This will contain latest tx genid of SOP op processed on
		 * the backend master device */
		c->sop_generation = &genid;
	}

	/*
	 * Use SOP operation to put value.
	 */
	err = ccow_container_update_list(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, strlen(oid) + 1, c, iov, 1,
	    CCOW_DELETE_LIST);
	if (err) {
		log_error(lg, "Shard %s delete error: %d", oid, err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err) {
		if (err != -ENOENT)
			log_error(lg, "Shard %s delete error: %d", oid, err);
	}

	// Add to cache
	if (shard_context->eventual) {
		int err = add_cache_record(tc, bid, shard_context->shard_name, iov, 1, 0, 0, 0,
		    i, shard_context->shard_count, SOP_CACHE_DELETE, genid);
		if (err) {
			log_error(lg, "Shard %s put to cache error: %d", oid, err);
		}
	}

	return err;
}

/* Get cache methods */
static int
get_cache_record(struct ccow *tc,const char *bid, char *shard_name, char *key, size_t key_size, struct iovec *iov) {
	int err;
	char path[2048] = "";
	sop_rec_table *sop_rec_tb = NULL;
	sprintf(path,"%s/%s/%s/%s",tc->cid, tc->tid, bid, shard_name);
	size_t path_size = strlen(path) + 1;
	if (sop_shard_table_get(tc->shard_cache, path, path_size, &sop_rec_tb) != 0) {
		log_debug(lg, "Shard %s table not found", path);
		return -ENOENT;
	}

	if (!sop_rec_tb) {
		log_debug(lg, "Shard %s table undefined", path);
		return -ENOENT;
	}

	sop_rec_t *sop_rec = NULL;
	err = sop_rec_table_get(sop_rec_tb, key, key_size, &sop_rec);
	if (err) {
		log_debug(lg, "Shard %s record %s not found", path, key);
		sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
		return -ENOENT;
	}

	if (!sop_rec) {
		log_debug(lg, "Shard %s record %s undefined", path, key);
		sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
		return -ENOENT;
	}

	log_debug(lg, "Shard %s record %s found optype: %d", path, key, sop_rec->optype);

	if (sop_rec->optype == SOP_CACHE_INSERT) {
		iov->iov_len = sop_rec->value_size;
		if (sop_rec->value_size) {
			iov->iov_base = je_malloc(sop_rec->value_size);
			memcpy(iov->iov_base, sop_rec->value,
					sop_rec->value_size);
		} else {
			iov->iov_base = NULL;
		}
	} else {
		iov->iov_len = 0;
		iov->iov_base = NULL;
	}

	int res = sop_rec->optype;
	sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
	return res;
}


/* Get methods */

int
ccow_sharded_list_get(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, char *key, size_t key_size,
    struct iovec *iov, size_t iovcnt)
{
	int err = 0;
	ccow_completion_t c = NULL;
	struct ccow *tc = tctx;

	int i = get_shard(key, key_size, shard_context->shard_count);
	if (i < 0)
		return i;

	char oid[1024] = "";
	get_shard_name(oid, shard_context, i);

	int res = get_cache_record(tc, bid, shard_context->shard_name, key, key_size, iov);
	log_debug(lg, "Get key %s, shard %s cache: %d", key, shard_context->shard_name, res);
	if (res == SOP_CACHE_INSERT) {
		return 0;
	}
	if (res == SOP_CACHE_DELETE) {
		return -ENOENT;
	}


	/*
	 * Get by key
	 */
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Shard list get create completion error: %d",
		    err);
		return err;
	}

	ccow_lookup_t iter = NULL;
	struct iovec iovkey = {.iov_base = key,.iov_len = key_size };

	err = ccow_get_list(bid, bid_size, oid, strlen(oid) + 1, c, &iovkey, 1,
	    1, &iter);
	if (err) {
		log_error(lg, "Shard %s get error: %d", oid, err);
		goto _exit;
	}

	err = ccow_wait(c, 0);
	if (err) {
		if (err != -ENOENT)
			log_error(lg, "Shard %s get error: %d", oid, err);
		goto _exit;
	} else {
		c = NULL;
	}

	struct ccow_metadata_kv *kv;

	iov->iov_len = 0;
	iov->iov_base = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1))) {
		if (!strcmp(kv->key, key)) {
			iov->iov_len = kv->value_size;
			if (kv->value_size) {
				iov->iov_base = je_malloc(kv->value_size);
				memcpy(iov->iov_base, kv->value,
				    kv->value_size);
			} else {
				iov->iov_base = NULL;
			}
			goto _exit;
		}
	}

	err = -ENOENT;
	log_debug(lg, "Shard %s get no entry error: %d", oid, err);

_exit:
	if (iter)
		ccow_lookup_release(iter);
	if (c)
		ccow_release(c);
	return err;
}

typedef struct
{
	int count;
	int shard_count;
	uv_mutex_t *shard_lock;
	uv_cond_t *shard_cond;
} merge_result;

typedef struct
{
	struct ccow *tc;
	const char *bid;
	size_t bid_size;
	char oid[1024];
	int err;
	int64_t *logical_size;
	int64_t *object_count;
	int64_t *estimated_used;
	ccow_completion_t c;
	ccow_lookup_t iter;
	merge_result *mr;
} merge_attributes;

static void
attributes_reader(merge_attributes * ma, ccow_lookup_t iter)
{
	struct ccow_metadata_kv *kv;

	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
		if (!strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE)) {
			*ma->logical_size += *(uint64_t *) kv->value;
			continue;
		}
		if (!strcmp(kv->key, RT_SYSKEY_OBJECT_COUNT)) {
			*ma->object_count += *(uint64_t *) kv->value;
			continue;
		}
		if (!strcmp(kv->key, RT_SYSKEY_ESTIMATED_USED)) {
			*ma->estimated_used += *(uint64_t *) kv->value;
			continue;
		}
	}
}

static void
one_completed_attributes(ccow_completion_t c, void *arg, int index, int err)
{
	merge_attributes *ma = arg;

	if (err) {
		ma->err = err;
	}

	uv_mutex_lock(ma->mr->shard_lock);
	ma->mr->count++;
	uv_cond_signal(ma->mr->shard_cond);
	uv_mutex_unlock(ma->mr->shard_lock);
}

int
ccow_sharded_attributes_get(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, int64_t * logical_size,
    int64_t * object_count, int64_t * estimated_used)
{
	int err = 0;
	struct ccow *tc = tctx;

	*logical_size = 0;
	*object_count = 0;
	*estimated_used = 0;

	// Get attributes from cache
	sop_rec_table *sop_rec_tb = get_rec_table_from_cache(tc, bid, shard_context->shard_name);
	if (sop_rec_tb) {
		*logical_size = sop_rec_tb->size;
		*object_count = sop_rec_tb->objs;
		*estimated_used = sop_rec_tb->used;
		log_debug(lg, "Shard %s cached attributes size: %ld, objs: %ld, used: %ld",
				shard_context->shard_name, sop_rec_tb->size, sop_rec_tb->objs, sop_rec_tb->used);
    	sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
		return 0;
	}


	/* Init sync primitives. */
	uv_mutex_t shard_lock;

	uv_mutex_init(&shard_lock);
	uv_cond_t shard_cond;

	uv_cond_init(&shard_cond);

	merge_attributes marr[shard_context->shard_count];
	struct iovec iov[1];

	merge_result mr;

	mr.count = 0;
	mr.shard_count = shard_context->shard_count;
	mr.shard_lock = &shard_lock;
	mr.shard_cond = &shard_cond;

	for (int i = 0; i < shard_context->shard_count; i++) {
		marr[i].tc = tctx;
		marr[i].bid = bid;
		marr[i].bid_size = bid_size;
		get_shard_name(marr[i].oid, shard_context, i);

		marr[i].err = 0;
		marr[i].logical_size = logical_size;
		marr[i].object_count = object_count;
		marr[i].estimated_used = estimated_used;

		marr[i].iter = NULL;
		marr[i].mr = &mr;
		marr[i].c = NULL;

		marr[i].err = ccow_create_completion(tctx, &marr[i],
		    one_completed_attributes, 1, &marr[i].c);
		if (marr[i].err) {
			log_error(lg, "Shard lists attributes read create "
			    "completion error: %d", err);
			err = marr[i].err;
			goto _exit;
		}
	}

	for (int i = 0; i < shard_context->shard_count; i++) {
		int err_create = ccow_get(marr[i].bid, marr[i].bid_size,
		    marr[i].oid, strlen(marr[i].oid) + 1, marr[i].c, iov, 0, 0,
		    &marr[i].iter);
		if (err_create) {
			if (marr[i].c)
				ccow_release(marr[i].c);
			uv_mutex_lock(&shard_lock);
			err = err_create;
			marr[i].err = err_create;
			mr.count++;
			uv_mutex_unlock(&shard_lock);
		}
	}

	uv_mutex_lock(&shard_lock);
	while (mr.count < mr.shard_count) {
		uv_cond_wait(mr.shard_cond, &shard_lock);
	}
	uv_mutex_unlock(&shard_lock);

	if (err) {
		log_error(lg, "Sharded attributes read error: %d", err);
		goto _exit;
	}

	for (int i = 0; i < shard_context->shard_count; i++) {
		attributes_reader(&marr[i], marr[i].iter);
	}

_exit:
	for (int i = 0; i < shard_context->shard_count; i++) {
		if (marr[i].iter) {
			ccow_lookup_release(marr[i].iter);
			marr[i].iter = NULL;
		}
		if (marr[i].err != 0 && err == 0)
			err = marr[i].err;
	}
	return err;
}

static int
ccow_sharded_get_list_one(ccow_completion_t c, const char *bid,
    size_t bid_size, char *oid, struct iovec *iov, int count,
    ccow_lookup_t * iter)
{
	int err = 0;

	log_debug(lg, "Get %d from %s marker: %s marker_size: %d", count, oid,
	    (char *) iov->iov_base, (int) iov->iov_len);

	err = ccow_get_list(bid, bid_size, oid, strlen(oid) + 1, c, iov, 1,
	    count, iter);
	if (err) {
		log_error(lg, "Shard %s get one error: %d", oid, err);
		goto _exit;
	}

	return 0;

_exit:
	return err;
}

typedef struct
{
	struct ccow *tc;
	const char *bid;
	size_t bid_size;
	char marker[1024];
	size_t marker_size;
	char oid[1024];
	volatile int err;
	int count;
	int pos;
	int end;
	int index;
	ccow_completion_t c;
	ccow_lookup_t iter;
	merge_result *mr;
} merge_lists;

static void
read_list(merge_lists * ma)
{
	ccow_completion_t c = NULL;
	struct ccow_metadata_kv *kv;

	ma->err = ccow_create_completion(ma->tc, NULL, NULL, 1, &c);
	if (ma->err) {
		log_error(lg, "Shard list %d read error: %d", ma->index,
		    ma->err);
		return;
	}

	struct iovec iov = {.iov_base = ma->marker,.iov_len =
		ma->marker_size };

	ma->err = ccow_sharded_get_list_one(c, ma->bid, ma->bid_size, ma->oid,
	    &iov, ma->count, &ma->iter);
	if (ma->err) {
		ma->end = 1;
		goto _exit;
	}

	ma->err = ccow_wait(c, 0);
	if (ma->err) {
		goto _exit;
	} else {
		c = NULL;
	}

	ma->pos = 0;
	kv = ccow_lookup_iter(ma->iter, CCOW_MDTYPE_NAME_INDEX, ma->pos);
	if (!kv) {
		ma->end = 1;
		goto _exit;
	}
	while (strcmp(kv->key, ma->marker) <= 0) {
		/* should be more then marker. */
		kv = ccow_lookup_iter(ma->iter, CCOW_MDTYPE_NAME_INDEX,
		    ++ma->pos);
		if (!kv) {
			ma->end = 1;
			goto _exit;
		}
	}

_exit:
	/* iterator has to be cleaned up in the caller */
	if (c) {
		ccow_release(c);
	}
}

/*
 * Add kv to lookup.
 */
static int
add_kv_to_lookup(ccow_lookup_t * iter, struct ccow_metadata_kv *kv)
{

	struct ccow_metadata_kv *akv = je_calloc(1, sizeof(*akv));

	if (!akv) {
		return -ENOMEM;
	}

	akv->mdtype = CCOW_MDTYPE_NAME_INDEX;
	akv->key = NULL;
	akv->key_size = kv->key_size;
	if (kv->key_size > 0) {
		akv->key = je_malloc(kv->key_size);
		if (!akv->key) {
			je_free(akv);
			return -ENOMEM;
		}
		memcpy(akv->key, kv->key, kv->key_size);
	}
	akv->type = kv->type;
	akv->value_size = 0;
	if (kv->value_size) {
		akv->value = je_malloc(kv->value_size);
		if (!akv->value) {
			je_free(akv->key);
			je_free(akv);
			return -ENOMEM;
		}
		memcpy(akv->value, kv->value, kv->value_size);
		akv->value_size = kv->value_size;
	}

	uv_buf_t uv_b;

	uv_b.base = (void *) akv;
	uv_b.len = sizeof(*akv);

	rtbuf_add((*iter)->name_index, &uv_b, 1);
	return 0;
}

static void
one_completed(ccow_completion_t c, void *arg, int index, int err)
{
	merge_lists *ma = arg;

	if (err) {
		ma->err = err;
		if (ma->iter) {
			ccow_lookup_release(ma->iter);
			ma->iter = NULL;
		}
	}

	uv_mutex_lock(ma->mr->shard_lock);
	ma->mr->count++;
	uv_cond_signal(ma->mr->shard_cond);
	uv_mutex_unlock(ma->mr->shard_lock);
}

int
ccow_sharded_get_list(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_shard_context_t shard_context, char *marker, size_t marker_size,
    char *end_marker, int count, ccow_lookup_t * iter)
{
	struct ccow *tc = tctx;
	int scount, err = 0, i;
	char start[1024];
	struct ccow_metadata_kv *kv;

	// Cache skip list iterator
	struct skiplist_iter cache_it;
	sop_rec_table *sop_rec_tb = get_rec_table_from_cache(tc, bid, shard_context->shard_name);


	/* Initialize the iter. */
	*iter = ccow_lookup_create(NULL, CCOW_LOOKUP_CLASS_OBJECT);
	if (!(*iter)) {
		sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
		return -ENOMEM;
	}
	(*iter)->name_index = rtbuf_init_empty();
	if ((*iter)->name_index == NULL) {
		ccow_lookup_release(*iter);
		*iter = NULL;
		sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
		return -ENOMEM;
	}

	size_t start_size = marker_size;

	if (marker && marker_size > 0)
		memcpy(start, marker, marker_size);
	else
		strcpy(start, "");

	/* Init sync primitives. */
	uv_mutex_t shard_lock;

	uv_mutex_init(&shard_lock);
	uv_cond_t shard_cond;

	uv_cond_init(&shard_cond);

	scount = shard_context->shard_count;
	merge_lists marr[scount];
	struct iovec iov[scount];

	merge_result mr;

	mr.count = 0;
	mr.shard_count = scount;
	mr.shard_lock = &shard_lock;
	mr.shard_cond = &shard_cond;

	int one_count = count / scount + 8;

	log_debug(lg, "Sharded get list one count: %d shard_count: %d",
	    one_count, scount);
	for (i = 0; i < scount; i++) {
		marr[i].tc = tctx;
		marr[i].bid = bid;
		marr[i].bid_size = bid_size;
		memcpy(marr[i].marker, start, start_size);
		marr[i].marker_size = start_size;
		marr[i].count = one_count;
		get_shard_name(marr[i].oid, shard_context, i);

		marr[i].err = 0;
		marr[i].pos = 0;
		marr[i].end = 0;
		marr[i].index = i;
		marr[i].iter = NULL;
		marr[i].mr = &mr;
		marr[i].c = NULL;
		marr[i].err = ccow_create_completion(tctx, &marr[i],
		    one_completed, 1, &marr[i].c);
		if (marr[i].err) {
			log_error(lg,
			    "Shard lists read create completion error: %d",
			    err);
			err = marr[i].err;
			goto _exit;
		}
	}

	for (i = 0; i < scount; i++) {
		iov[i].iov_base = marr[i].marker;
		iov[i].iov_len = marr[i].marker_size;

		int err_create = ccow_sharded_get_list_one(marr[i].c,
		    marr[i].bid, marr[i].bid_size, marr[i].oid, &iov[i],
		    marr[i].count, &marr[i].iter);
		if (err_create) {
			if (marr[i].c) {
				ccow_release(marr[i].c);
			}
			uv_mutex_lock(&shard_lock);
			marr[i].err = err_create;
			err = err_create;
			mr.count++;
			uv_mutex_unlock(&shard_lock);
		}
	}

	uv_mutex_lock(&shard_lock);
	while (mr.count < mr.shard_count) {
		uv_cond_wait(mr.shard_cond, &shard_lock);
	}
	uv_mutex_unlock(&shard_lock);

	/* check for empty lists, get start keys. */
	for (i = 0; i < scount; i++) {
		if (marr[i].err) {
			if (marr[i].err != -ENOENT && marr[i].err != EINTR) {
				log_error(lg, "Set error: %d", marr[i].err);
				err = marr[i].err;
			}
			marr[i].end = 1;
			continue;
		}
		marr[i].pos = 0;
		kv = ccow_lookup_iter(marr[i].iter, CCOW_MDTYPE_NAME_INDEX,
		    marr[i].pos);
		if (!kv) {
			marr[i].end = 1;
			continue;
		}
		while (strcmp(kv->key, start) <= 0) {
			/* should be more then marker. */
			kv = ccow_lookup_iter(marr[i].iter,
			    CCOW_MDTYPE_NAME_INDEX, ++marr[i].pos);
			if (!kv) {
				marr[i].end = 1;
				break;
			}
		}
	}

	if (err) {
		log_error(lg, "Shard lists read one list error: %d", err);
		goto _exit;
	}

	/* Search in cache */
	if (sop_rec_tb) {
		msl_search(sop_rec_tb->sl, start, start_size, &cache_it);
	}

	/* Merge. */
	int num = 0;
	int imin = -1;
	char *key = NULL;
	size_t ksize;
	struct ccow_metadata_kv ckv;

	while (num < count) {
		imin = -1;
		key = NULL;
		for (i = 0; i < scount; i++) {
			if (marr[i].end) {
				/* ignore empty shard. */
				continue;
			}
			kv = ccow_lookup_iter(marr[i].iter,
			    CCOW_MDTYPE_NAME_INDEX, marr[i].pos);
			if (!kv) {
				/* end, need more here. */
				if (marr[i].iter) {
					ccow_lookup_release(marr[i].iter);
					marr[i].iter = NULL;
				}
				read_list(&marr[i]);
				if (marr[i].err) {
					if (marr[i].iter) {
						ccow_lookup_release(marr[i].iter);
						marr[i].iter = NULL;
					}
					log_error(lg,
					    "Shard lists read error: %d", err);
					goto _exit;
				}
				if (marr[i].end)
					/* ignore empty shard. */
					continue;
				kv = ccow_lookup_iter(marr[i].iter,
				    CCOW_MDTYPE_NAME_INDEX, marr[i].pos);
				if (!kv) {
					marr[i].end = 1;
					continue;
				}
			}
			if (strcmp(kv->key, start) <= 0) {
				/* more then marker. */
				continue;
			}
			if (end_marker && strcmp(kv->key, end_marker) > 0) {
				/* end, setup end flag. */
				marr[i].end = 1;
				continue;
			}
			if (!key) {
				/* no key. */
				key = kv->key;
				imin = i;
				continue;
			}
			if (strcmp(kv->key, key) < 0) {
				/* smaller key. */
				key = kv->key;
				imin = i;
			}
		}
		if (imin < 0) {
			/* no candidate for merge, add all from cache */
			if (sop_rec_tb) {
				while (cache_it.v != NULL) {
					ckv.key = msl_iter_getk(&cache_it, &ksize);
					ckv.key_size = ksize;
					if (end_marker && strcmp(ckv.key, end_marker) > 0) {
						break;
					}
					sop_rec_t *rec = (sop_rec_t *)msl_iter_getv(&cache_it, NULL);
					if (rec->optype == SOP_CACHE_INSERT) {
						ckv.value = rec->value;
						ckv.value_size = rec->value_size;
						err = add_kv_to_lookup(iter, &ckv);
						if (err) {
							log_error(lg, "Shard lists add new item error: %d", err);
							goto _exit;
						}
						num++;
					}
					cache_it = msl_iter_next(sop_rec_tb->sl, &cache_it);
				}
			}
			break;
		}
		kv = ccow_lookup_iter(marr[imin].iter, CCOW_MDTYPE_NAME_INDEX, marr[imin].pos);
		if (sop_rec_tb && cache_it.v != NULL) { // Check cache
			ckv.key = msl_iter_getk(&cache_it, &ksize);
			ckv.key_size = ksize;

			sop_rec_t *rec = (sop_rec_t *)msl_iter_getv(&cache_it, NULL);
			int cmp = strcmp(ckv.key, kv->key);
			if (cmp < 0) { /* smaller key, select cache. */
				if (rec->optype == SOP_CACHE_INSERT) {
					ckv.value = rec->value;
					ckv.value_size = rec->value_size;
					kv = &ckv;
					cache_it = msl_iter_next(sop_rec_tb->sl, &cache_it);
				} else {// DELETE
					cache_it = msl_iter_next(sop_rec_tb->sl, &cache_it);
					continue;
				}
			} else if (cmp == 0)  { // select both
				if (rec->optype == SOP_CACHE_INSERT) {
					ckv.value = rec->value;
					ckv.value_size = rec->value_size;
					kv = &ckv;
					marr[imin].pos++;
					cache_it = msl_iter_next(sop_rec_tb->sl, &cache_it);
				} else { // DELETE
					marr[imin].pos++;
					cache_it = msl_iter_next(sop_rec_tb->sl, &cache_it);
					continue;
				}
			} else { // cmp > 0, select cluster
				marr[imin].pos++;
			}
		} else {
			marr[imin].pos++;
		}
		err = add_kv_to_lookup(iter, kv);
		if (err) {
			log_error(lg, "Shard lists add new item error: %d",
			    err);
			goto _exit;
		}
		num++;

		marker = kv->key;

		memcpy(start, kv->key, kv->key_size);
		start_size = kv->key_size;

		memcpy(marr[imin].marker, start, start_size);
		marr[imin].marker_size = start_size;
	}

_exit:
	if (err) {
		if (*iter)
			ccow_lookup_release(*iter);
		*iter = NULL;
	}
	for (i = 0; i < scount; i++) {
		if (marr[i].iter) {
			ccow_lookup_release(marr[i].iter);
			marr[i].iter = NULL;
		}
	}
	sop_shard_table_detach(tc->shard_cache, sop_rec_tb);
	return err;
}

/* Test support function */
void
test_get_shard_name(char *dir_name, char *dentry,
		char *shard_name, int shard_count)
{
	int shard_index;
	struct ccow_shard_context sc;

	sc.shard_name = dir_name;
	shard_index = get_shard(dentry, strlen(dentry) + 1, shard_count);
	assert(shard_index >= 0);
	get_shard_name(shard_name, &sc, shard_index);
}
