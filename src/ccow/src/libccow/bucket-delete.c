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

#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "ccowfsio.h"

#define MAX_SERVICE 10000

static int
test_root(struct ccow *tc, const char *bid, size_t bid_size)
{
	int err = 0;
	int res = 0;

	ccow_shard_context_t list_shard_context;
	ccow_lookup_t iter = NULL;
	msgpack_u *u = NULL;

	err = ccow_shard_context_create(ROOT_INODE_STR,
	    strlen(ROOT_INODE_STR) + 1, FSIO_DIR_SHARD_COUNT,
	    &list_shard_context);
	if (err) {
		res = err;
		goto _exit;
	}


	err = ccow_sharded_get_list(tc, bid, bid_size,
	    list_shard_context, "", 1, NULL, 5, &iter);

	ccow_shard_context_destroy(&list_shard_context);

	if (err) {
		if (err != -ENOENT)
			res = err;
		goto _exit;
	}

	struct ccow_metadata_kv *kv;
	void *t;
	int num = 0;
	do {
		t = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1);
		kv = (struct ccow_metadata_kv *)t;
		if (kv == NULL) {
			break;
		}

		if (kv->type != CCOW_KVTYPE_RAW)
			continue;

		uint8_t ver=0;
		uint64_t inode = 0;
		u = msgpack_unpack_init(kv->value, kv->value_size, 0);
		err = msgpack_unpack_uint8(u, &ver);
		if (err) {
			res = err;
			goto _exit;
		}
		if (ver != 3) {
			msgpack_unpack_free(u);
			u = NULL;
			continue;
		}
		err = msgpack_unpack_uint64(u, &inode);
		if (err) {
			res = err;
			goto _exit;
		}
		uint8_t type = (inode >> 60) & 3;
		if (inode != CCOW_FSIO_ROOT_INODE &&
		    inode != CCOW_FSIO_S3OBJ_DIR_INODE &&
			inode != CCOW_FSIO_LOST_FOUND_DIR_INODE) {
			num++;
		}
		msgpack_unpack_free(u);
		u = NULL;
	} while (kv != NULL);

	res = (num > 0 ? -EPERM : 0);

_exit:
	if (u)
		msgpack_unpack_free(u);
	if (iter)
		ccow_lookup_release(iter);
	return res;
}

static int
test_object(struct ccow *tc, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size)
{
	int err = 0;
	int res = 0;

	ccow_completion_t c;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Error while ccow_create_completion: %d", err);
		res = err;
		goto _done;
	}

	err = ccow_get_test(bid, bid_size, oid, oid_size, c);
	if (err) {
		log_error(lg, "Error while ccow_get_test: %d", err);
		res = err;
		ccow_release(c);
		goto _done;
	}

	err = ccow_wait(c, 0);
	if (err == -ENOENT) {
		log_warn(lg, "No entry found err: %d", err);
		res = 0;
		goto _done;
	}
	if (err) {
		log_error(lg, "Operation error: %d", err);
		res = err;
		goto _done;
	}

	res = 1;

_done:
	return res;
}

static int
fsio_delete_bucket(ccow_t tc, const char *bid, size_t bid_size)
{
	ccow_shard_context_t list_shard_context;
	ccow_completion_t c;
	int err;

	err = 0;
	c = NULL;

	/* FLUSHER_STAT_OBJ */
	err = ccow_shard_context_create(FLUSHER_STAT_OBJ,
	    strlen(FLUSHER_STAT_OBJ) + 1, 1, &list_shard_context);
	if (err) {
		log_error(lg, "ccow_shard_context_create failed, err %d",
		    err);
		goto out;
	}

	err = ccow_sharded_list_destroy(tc, bid, bid_size,
	    list_shard_context);
	ccow_shard_context_destroy(&list_shard_context);

	if (err && err != -ENOENT) {
		log_error(lg, "ccow_sharded_list_delete failed, err %d",
		    err);
		goto out;
	}

	/* RECOVERY_TABLE_STR */
	err = ccow_shard_context_create(RECOVERY_TABLE_STR,
	    strlen(RECOVERY_TABLE_STR) + 1, RECOVERY_TABLE_SHARD_COUNT,
	    &list_shard_context);
	if (err) {
		log_error(lg, "ccow_shard_context_create failed, err %d",
		    err);
		goto out;
	}

	err = ccow_sharded_list_destroy(tc, bid, bid_size,
	    list_shard_context);
	ccow_shard_context_destroy(&list_shard_context);

	if (err && err != -ENOENT) {
		log_error(lg, "ccow_sharded_list_destroy failed, err %d",
		    err);
		goto out;
	}

	err = ccow_create_completion(tc, NULL, NULL, 3, &c);
	if (err) {
		log_error(lg, "ccow_create_completion failed, err %d",
		    err);
		goto out;
	}

	/* Delete FOT */
	err = ccow_delete_notrlog(bid, bid_size,
		INODE_OBJECT_LOOKUP, strlen(INODE_OBJECT_LOOKUP) + 1, c);
	err = ccow_wait(c, -1);
	if (err && err != -ENOENT) {
		log_error(lg, "ccow_wait failed, err %d", err);
		goto out;
	}

	/* INODE_MASTER_STR */
	err = ccow_delete_notrlog(bid, bid_size, INODE_MASTER_STR,
	    strlen(INODE_MASTER_STR) + 1, c);
	if (err) {
		log_error(lg, "ccow_delete failed, err %d", err);
		goto out;
	}

	err = ccow_wait(c, -1);
	if (err && err != -ENOENT) {
		log_error(lg, "ccow_wait failed, err %d", err);
		goto out;
	}

	/* CCOW_FSIO_ROOT_INODE */

	err = ccow_shard_context_create(ROOT_INODE_STR,
	    strlen(ROOT_INODE_STR) + 1, FSIO_DIR_SHARD_COUNT,
	    &list_shard_context);
	if (err) {
		log_error(lg, "ccow_shard_context_create failed, err %d", err);
		goto out;
	}

	err = ccow_sharded_list_destroy(tc, bid, bid_size,
	    list_shard_context);
	ccow_shard_context_destroy(&list_shard_context);

	if (err && err != -ENOENT) {
		log_error(lg, "ccow_sharded_list_destroy failed, err %d", err);
		goto out;
	}


	/* CCOW_FSIO_LOST_FOUND_DIR_INODE */

	err = ccow_shard_context_create(LOST_FOUND_INODE_STR,
	    strlen(LOST_FOUND_INODE_STR) + 1, FSIO_DIR_SHARD_COUNT,
	    &list_shard_context);
	if (err) {
		log_error(lg, "ccow_shard_context_create failed, err %d", err);
		goto out;
	}

	err = ccow_sharded_list_destroy(tc, bid, bid_size,
	    list_shard_context);
	ccow_shard_context_destroy(&list_shard_context);

	if (err && err != -ENOENT) {
		log_error(lg, "ccow_sharded_list_destroy failed, err %d", err);
	}


out:
	if (c)
		ccow_release(c);

	err = 0; // igonore errors
	return (err);
}

static int
bucket_used_by_service(ccow_t cl, const char *bid, size_t bid_size) {
	struct isgw_service_entry* table = NULL;
	int err;
	ccow_completion_t c;

	char bucket_path[cl->cid_size + cl->tid_size + bid_size];
	int bucket_len;

	sprintf(bucket_path,"%s/%s/%s", cl->cid, cl->tid, bid);
	bucket_len = strlen(bucket_path);

	log_debug(lg, "Check bucket: %s", bucket_path);

	/*
	 * Read root system object with NHID = 0x0
	 */
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "ccow_create_completion returned error = %d", err);
		return err;
	}

	char buf = 0;
	struct iovec iov = { .iov_base = &buf, .iov_len = 1 };
	ccow_lookup_t iter = NULL, biter = NULL;
	err = ccow_tenant_get("", 1, RT_SYSVAL_TENANT_ADMIN, strlen(RT_SYSVAL_TENANT_ADMIN) + 1,
		"", 1, "", 1, c, &iov, 1, MAX_SERVICE, CCOW_GET_LIST, &iter);
	if (err) {
		ccow_release(c);
		log_warn(lg, "ccow_tenant_get = %d", err);
		return err;
	}
	err = ccow_wait(c, -1);
	if (err == -ENOENT) {
		return 0;
	}
	if (err) {
		log_warn(lg, "Error while reading system object: %d, ", err);
		return err;
	}

	int pos = 0;
	struct ccow_metadata_kv *kv;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++))) {
		/*
		 * Iterate through all the buckets listed in the tenant
		 * Bucket name is a service ID
		 */
		int get_err = 0;
		char *sid = (char *)kv->key;
		uint16_t sid_size = kv->key_size;

		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		if (err) {
			log_error(lg, "ccow_create_completion failed with error: %d",
				err);
			goto _cleanup;
		}

		err = ccow_tenant_get("", 1, RT_SYSVAL_TENANT_ADMIN, strlen(RT_SYSVAL_TENANT_ADMIN) + 1,
			sid, sid_size, "", 1, c, &iov, 1, MAX_SERVICE, CCOW_GET_LIST, &biter);

		if (err) {
			ccow_release(c);
			log_debug(lg, "Cannot get service information %s: %d", sid, err);
			goto _cleanup;
		}
		err = ccow_wait(c, -1);
		if (err == -ENOENT) {
			err = 0;
			ccow_lookup_release(biter);
			biter = NULL;
			continue;
		}
		if (err) {
			if (biter) {
				ccow_lookup_release(biter);
				biter = NULL;
			}
			log_debug(lg, "Cannot get service %s wait error: %d", sid, err);
			goto _cleanup;
		}

		struct ccow_metadata_kv *bkv;
		int bpos = 0;
		/* Looking for buckets to be served */
		while ((bkv = ccow_lookup_iter(biter, CCOW_MDTYPE_NAME_INDEX, bpos++))) {
			if (bkv->key_size == 0)
				continue;
			char *path = (char *)bkv->key;
			char *sp = NULL;
			char *bpath = path;
			sp = strchr(path,'@');
			if (sp) {
			   bpath = sp + 1;
			} else {
				sp = strchr(path,',');
				if (sp) {
					*sp = 0;
				}
			}
			int blen = strlen(bpath);
			log_debug(lg, "Service check sid: %s, bucket path: %s[%d], bpath: %s[%d]",
				 sid, bucket_path, bucket_len, bpath, blen);

			if (blen == bucket_len && strncmp(bpath, bucket_path, blen) == 0) {
				err = -EPERM;
				goto _cleanup;
			}
			if (blen > bucket_len && strncmp(bpath, bucket_path, bucket_len) == 0 && bpath[bucket_len] == '/') {
				err = -EPERM;
				goto _cleanup;
			}
		}
		ccow_lookup_release(biter);
		biter = NULL;
	}
_cleanup:
	if (biter)
		ccow_lookup_release(biter);
	if (iter)
		ccow_lookup_release(iter);
	log_debug(lg, "Service check err: %d", err);
	return err;
}


int
ccow_bucket_delete(ccow_t tctx, const char *bid, size_t bid_size)
{
	int err;
	struct ccow *tc = tctx;
	ccow_completion_t c;

	/* check to see if bucket has objects, disallow delete */
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	ccow_lookup_t iter;
	struct iovec iov = { .iov_base = "", .iov_len = 1 };
	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, "", 1, c, &iov, 1,
	    1, CCOW_GET_LIST, &iter);
	if (err) {
		log_error(lg, "Delete bucket 1 err: %d", err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, -1);
	if (err == 0 && iter) {
		struct ccow_metadata_kv *kv = NULL;
		int pos = 0;
		int found = 0;
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++))) {
			if (kv && kv->key) {
				if (test_object(tc, bid, bid_size, kv->key, kv->key_size)) {
					found = 1;
					break;
				}
			}
		}
		if (found) {
			log_warn(lg, "Attempting to delete bucket while it still holds contents.");
			ccow_dump_iter_to_logger(iter, CCOW_MDTYPE_NAME_INDEX);
			ccow_lookup_release(iter);
			return RT_ERR_NOT_EMPTY;
		}
	} else if (err != -ENOENT) {
		if (iter)
			ccow_lookup_release(iter);
		log_error(lg, "Error while accessing bucket: %d", err);
		log_hexdump(lg, "CID:", tc->cid, tc->cid_size);
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		log_hexdump(lg, "BID:", (char *)bid, bid_size);
		return err;
	}

	ccow_lookup_release(iter);

	// Check nfs objects
	if (tc->cid_size > 1 && tc->tid_size > 1 && bid_size > 1) {
		err = test_root(tc, bid, bid_size);
		if (err == -EPERM) {
			log_error(lg, "NFS root not empty %d",  err);
			return RT_ERR_NOT_EMPTY;
		}
	}

	// Check services
	if (tc->cid_size > 1 && tc->tid_size > 1 && bid_size > 1) {
		err = bucket_used_by_service(tc, bid, bid_size);
		if (err)
			return err;
	}

	/* try to delete bucket object */
	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	if (err)
		return err;

	err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, "", 1, c, NULL, 0,
	    0, CCOW_PUT, NULL, RD_ATTR_LOGICAL_DELETE | RD_ATTR_EXPUNGE_OBJECT);
	if (err) {
		log_error(lg, "Delete bucket 2 err: %d", err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_error(lg, "Delete bucket object err: %d", err);
		return err;
	}

	char hash[UINT512_BYTES*2+1];
	hash_id_to_buffer(&c->vm_name_hash_id, hash);
	err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    bid, bid_size, hash, strlen(hash) + 1, c, NULL, 0, 0, CCOW_PUT, NULL,
	    RD_ATTR_LOGICAL_DELETE | RD_ATTR_EXPUNGE_OBJECT | RD_ATTR_NO_TRLOG);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 1);
	if (err && err != -ENOENT) {
		log_error(lg, "Delete bucket 4 err: %d", err);
		return err;
	}

	if (err == -ENOENT) {
		err = 0;
	}


	// Delete NFS objects
	if (tc->cid_size > 1 && tc->tid_size > 1 && bid_size > 1) {
		err = fsio_delete_bucket(tc, bid, bid_size);
		if (err) {
			log_error(lg, "Delete bucket fsio objects err: %d", err);
			return err;
		}
	}


	/* delete bucket from the tenant object */

	char buf[CCOW_BUCKET_CHUNK_SIZE];
	iov.iov_base = buf;
	memcpy(iov.iov_base, bid, bid_size);
	iov.iov_len = bid_size;
	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	if (err)
		return err;

	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    "", 1, "", 1, c, NULL, 0, 0, CCOW_GET, &iter);
	if (err) {
		ccow_drop(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		log_error(lg, "Delete bucket tenant get err: %d", err);
		ccow_drop(c);
		if (err == -ENOENT)
			err = -EPERM;
		goto _cleanup;
	}

	err = ccow_container_update_list(tc->cid, tc->cid_size,
					 tc->tid, tc->tid_size,
					 "", 1, "", 1, c, &iov, 1,
					 CCOW_DELETE_LIST);
	if (err) {
		ccow_release(c);
		goto _cleanup;
	}
	err = ccow_wait(c, 1);
	if (err) {
		log_error(lg, "Delete bucket container update err: %d", err);
		err = 0;
	}

_cleanup:
	if (iter)
		ccow_lookup_release(iter);
	return err;
}
