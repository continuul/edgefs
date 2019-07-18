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
#include <pthread.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <lfq.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "ccow.h"
#include "ccowutil.h"
#include "hashtable.h"
#include "ccowfsio.h"

#include "replicast.h"

#include "fsio_inode.h"
#include "fsio_s3_transparency.h"
#include "fsio_disk.h"
#include "fsio_flusher.h"
#include "fsio_debug.h"
#include "fsio_common.h"
#include "fsio_system.h"
#include "fsio_dir.h"
#include "fsio_cache.h"
#include "fsio_recovery.h"
#include "tc_pool.h"

#define INODE_HASH_TABLE_MAX_SIZE (1024 * 10)
#define INODE_HASH_TABLE_MAX_LOAD_FACTOR (0.05)
#define INODE_S3DIR_EXPIRE_TIMEOUT_US (180ULL * 1000000ULL)
#define INODE_EXPIRE_TIMEOUT_US (5ULL * 1000000ULL)

#define MD_MODE					0x0001
#define MD_UID					0x0002
#define MD_GID					0x0004
#define MD_SIZE					0x0008
#define MD_BLKSIZE				0x0010
#define MD_ATIME				0x0020
#define MD_CTIME				0x0040
#define MD_MTIME				0x0080
#define MD_REFCOUNT				0x0100
#define MD_SNAP_COUNT			0x0200
#define MD_ALL					0x03FF

int __encode_dir_attrs(ccowfs_inode * inode, void **encoded_attrs,
    uint64_t * encoded_attrs_len);

static int
__remove_inode_from_hash_table_locked(ccowfs_inode * inode)
{

	log_trace(fsio_lg, "%s inode: %lu", __func__, inode->ino);

	if (!QUEUE_EMPTY(&inode->list_q)) {
		hashtable_remove(inode->ci->inode_cache.inode_table,
			(void *) inode->ino_str, strlen(inode->ino_str));

		QUEUE_REMOVE(&inode->list_q);
		QUEUE_INIT(&inode->list_q);
		inode->ci->inode_cache.count--;
	}

	log_debug(fsio_lg, "completed %s inode: %lu", __func__, inode->ino);

	return 0;
}

static int
__remove_inode_from_hash_table(ccowfs_inode * inode)
{
	int err;

	log_trace(fsio_lg, "%s inode: %lu", __func__, inode->ino);

	pthread_rwlock_wrlock(&(inode->ci->inode_cache.hash_table_rwlock));
	err = __remove_inode_from_hash_table_locked(inode);
	if (err)
		log_error(fsio_lg,
		    "__remove_inode_from_hash_table_locked return %d for inode: %lu",
			err, inode->ino);
	pthread_rwlock_unlock(&(inode->ci->inode_cache.hash_table_rwlock));

	log_debug(fsio_lg, "completed %s inode: %lu", __func__, inode->ino);

	return err;
}

static int
set_snap_count(ccow_completion_t c, ccow_lookup_t iter, uint32_t snap_count)
{

	log_trace(fsio_lg, "c: %p, iter: %p, snap_count: %u", c,
	    iter, snap_count);
	return ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT32,
	    X_FILE_SNAP_COUNT, strlen(X_FILE_SNAP_COUNT) + 1,
	    (void *) &snap_count, 0, iter);
}

static int
set_symlink(ccow_completion_t c, ccow_lookup_t iter, char *link)
{

	log_trace(fsio_lg, "c: %p, iter: %p, link: \"%s\"", c,
	    iter, link);
	return ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, X_FILE_SYMLINK,
	    strlen(X_FILE_SYMLINK) + 1, (void *) link, strlen(link) + 1, iter);
}

static int
set_mode(ccow_completion_t c, ccow_lookup_t iter, uint16_t mode)
{

	log_trace(fsio_lg, "c: %p, iter: %p, mode: %u", c, iter,
	    mode);
	return ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT16, X_FILE_MODE,
	    strlen(X_FILE_MODE) + 1, (void *) &mode, 0, iter);
}

static int
set_size(ccow_completion_t c, ccow_lookup_t iter, size_t size)
{

	log_trace(fsio_lg, "c: %p, iter: %p, size: %lu", c, iter,
	    size);
	return ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, X_FILE_SIZE,
	    strlen(X_FILE_SIZE) + 1, (void *) &size, 0, iter);
}

static int
set_blksize(ccow_completion_t c, ccow_lookup_t iter, size_t size)
{

	log_trace(fsio_lg, "c: %p, iter: %p, size: %lu", c, iter,
	    size);
	return ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *) &size, NULL);
}

static int
set_refcount(ccow_completion_t c, ccow_lookup_t iter, uint64_t link_count)
{

	log_trace(fsio_lg, "c: %p, iter: %p, link_count: %lu", c,
	    iter, link_count);
	return ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, X_FILE_REFCOUNT,
	    strlen(X_FILE_REFCOUNT) + 1, (void *) &link_count, 0, iter);
}

static int
set_uid(ccow_completion_t c, ccow_lookup_t iter, uint16_t uid)
{

	log_trace(fsio_lg, "c: %p, iter: %p, uid: %u", c, iter,
	    uid);
	return ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT16, X_FILE_UID,
	    strlen(X_FILE_UID) + 1, (void *) &uid, 0, iter);
}

static int
set_gid(ccow_completion_t c, ccow_lookup_t iter, uint16_t gid)
{
	log_trace(fsio_lg, "c: %p, iter: %p, gid: %u", c, iter,
	    gid);
	return ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT16, X_FILE_GID,
	    strlen(X_FILE_GID) + 1, (void *) &gid, 0, iter);
}

static int
set_atime(ccow_completion_t c, ccow_lookup_t iter, struct timespec *t)
{
	uint64_t time;

	log_trace(fsio_lg, "c: %p, iter: %p, t: %p", c, iter, t);
	/*
	 * Set time in micro seconds.
	 */
	time = (t->tv_sec * 1000 * 1000) + t->tv_nsec / 1000;

	return ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, X_FILE_ATIME,
	    strlen(X_FILE_ATIME) + 1, (void *) &time, 0, iter);
}

static int
set_ctime(ccow_completion_t c, ccow_lookup_t iter, struct timespec *t)
{

	log_trace(fsio_lg, "c: %p, iter: %p, t: %p", c, iter, t);
	/*
	 * Set time in micro seconds.
	 */
	uint64_t time = (t->tv_sec * 1000 * 1000) + t->tv_nsec / 1000;

	return ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, X_FILE_CTIME,
	    strlen(X_FILE_CTIME) + 1, (void *) &time, 0, iter);
}

static int
set_mtime(ccow_completion_t c, ccow_lookup_t iter, struct timespec *t)
{

	log_trace(fsio_lg, "c: %p, iter: %p, t: %p", c, iter, t);
	/*
	 * Set time in micro seconds.
	 */
	uint64_t time = (t->tv_sec * 1000 * 1000) + t->tv_nsec / 1000;

	return ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, X_FILE_MTIME,
	    strlen(X_FILE_MTIME) + 1, (void *) &time, 0, iter);
}

static int
set_btree_order(ccow_completion_t c)
{
	log_trace(fsio_lg, "c: %p", c );

	int order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_DEFAULT;

	return ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *) &order, NULL);
}

static void
__inode_free(ccowfs_inode * inode)
{

	if (inode) {
		log_trace(fsio_lg, "inode: %lu (%p)", inode->ino, inode);

		if (inode->oid)
			je_free(inode->oid);
		if (inode->dir_list_context)
			ccow_shard_context_destroy(&inode->dir_list_context);
		pthread_mutex_lock(&inode->json_handle_mutex);
		if (inode->json_handle) {
			put_s3_json_handle(inode->json_handle);
			inode->json_handle = NULL;
		}
		pthread_mutex_unlock(&inode->json_handle_mutex);
		pthread_mutex_destroy(&(inode->json_handle_mutex));
		log_debug(fsio_lg, "completed %s: inode: %lu", __func__, inode->ino);
		je_free(inode);
	}
}

static int
__update_inode_oid(ccowfs_inode * inode)
{
	int err = 0;

	log_trace(fsio_lg, "inode: %lu", inode->ino);
	assert(inode->oid == NULL);

	if (INODE_IS_S3OBJ(inode->ino)) {
		err = get_s3_obj_name(inode->ci, inode->ino_str, &inode->oid);
		if (err) {
			log_softerror(fsio_lg, err,
			    "get_s3_obj_name inode: %s", inode->ino_str);
			goto out;
		}
		inode->oid_size = strlen(inode->oid) + 1;
		goto out;
	}

	inode->oid = (char *) je_calloc(1, INODE_STR_MAX_SIZE);
	if (!inode->oid) {
		err = ENOMEM;
		log_error(fsio_lg, "Failed to allocate memory");
		goto out;
	}

	if (inode->ino == CCOW_FSIO_ROOT_INODE)
		snprintf(inode->oid, INODE_STR_MAX_SIZE, "%s", ROOT_INODE_STR);
	else if (inode->ino == CCOW_FSIO_LOST_FOUND_DIR_INODE)
		snprintf(inode->oid, INODE_STR_MAX_SIZE, "%s", LOST_FOUND_INODE_STR);
	else if (inode->ino == CCOW_FSIO_S3OBJ_DIR_INODE)
		snprintf(inode->oid, INODE_STR_MAX_SIZE, "%s", "");
	else
		snprintf(inode->oid, INODE_STR_MAX_SIZE, "%ju", inode->ino);

	 inode->oid_size = strlen(inode->oid) + 1;

	if (INODE_IS_DISK_DIR(inode->ino)) {
		err = ccow_fsio_dir_context_create(inode);
		if (err)
			goto out;
	}

out:
	if (err) {
		log_softerror(fsio_lg, err,
		    "update failed for bucket: %s inode: %lu",
		    inode->ci->bid, inode->ino);

		if (inode->oid)
			je_free(inode->oid);
		inode->oid = NULL;
		inode->oid_size = 0;
	}

	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

	return err;
}

static int
__inherit_bucket_attrs(ci_t * ci, ccow_completion_t c)
{
	int err = 0;

	log_trace(fsio_lg, "ci: %p, c: %p", ci, c);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *) &(ci->bk_attrs.chunk_size), NULL);
	if (err) {
		log_error(fsio_lg,
		    "ccow_attr_modify_default return %d", err);
		return err;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_MARKER,
	    (void *) &(ci->bk_attrs.chunkmap_btree_marker), NULL);
	if (err) {
		log_error(fsio_lg,
		    "ccow_attr_modify_default return %d", err);
		return err;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_REPLICATION_COUNT,
	    (void *) &(ci->bk_attrs.replication_count), NULL);
	if (err) {
		log_error(fsio_lg,
		    "ccow_attr_modify_default return %d", err);
		return err;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_SYNC_PUT,
	    (void *) &(ci->bk_attrs.sync_put), NULL);
	if (err) {
		log_error(fsio_lg,
		    "ccow_attr_modify_default return %d", err);
		return err;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_EC_ENABLE,
	    (void *) &(ci->bk_attrs.ec_enabled), NULL);
	if (err) {
		log_error(fsio_lg,
		    "ccow_attr_modify_default return %d", err);
		return err;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_EC_ALGORITHM,
	    (void *) &(ci->bk_attrs.ec_data_mode), NULL);
	if (err) {
		log_error(fsio_lg,
		    "ccow_attr_modify_default return %d", err);
		return err;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_EC_TRG_POLICY,
	    (void *) &(ci->bk_attrs.ec_trg_policy), NULL);
	if (err)
		log_error(fsio_lg,
		    "ccow_attr_modify_default return %d", err);

	log_debug(fsio_lg, "completed ci: %p, c: %p", ci, c);

	return err;
}

static int
__create_disk_inode(ccowfs_inode * inode, char *link)
{
	int err = 0;
	struct timespec time;
	ccow_completion_t c = NULL;
	uint64_t genid = 0;

	log_trace(fsio_lg, "inode: %ju, link: \"%s\"", inode->ino, link);

	clock_gettime(CLOCK_REALTIME, &time);

	inode->stat.st_atim = time;
	inode->stat.st_ctim = time;
	inode->stat.st_mtim = time;

	/* By default, files have link count 1 */
	inode->stat.st_nlink = 1;

	err = ccowfs_create_stream_completion(inode->ci,
				inode->oid, inode->oid_size,
				&genid, 1, inode->ino, &c, NULL);
	if (err) {
		log_error(fsio_lg, "ccowfs_create_stream_completion return %d",
			err);
		goto out;
	}

	if ((inode->stat.st_mode & S_IFMT) == S_IFLNK){
		err = set_symlink(c, NULL, link);
		if (err) {
			log_error(fsio_lg, "set_symlink return %d",
			    err);
			goto out;
		}
		assert(INODE_IS_SYMLINK(inode->ino));
	}
	assert(!INODE_IS_S3OBJ(inode->ino)  && ! INODE_IS_DISK_DIR(inode->ino));

#define __ATTR(n, v)				\
	err = set_ ## n(c, NULL, (v));		\
	if (err) {				\
		goto out;			\
	}

	__ATTR(mode, inode->stat.st_mode)
	__ATTR(uid, inode->stat.st_uid)
	__ATTR(gid, inode->stat.st_gid)
	__ATTR(size, inode->stat.st_size)
	__ATTR(blksize, inode->stat.st_blksize)
	__ATTR(atime, &time)
	__ATTR(ctime, &time)
	__ATTR(mtime, &time)
	__ATTR(refcount, inode->stat.st_nlink)
	__ATTR(snap_count, inode->snap_count)
#undef  __ATTR
	if (!S_ISDIR(inode->stat.st_mode))
		set_btree_order(c);

	err = __inherit_bucket_attrs(inode->ci, c);
	if (err) {
		log_error(fsio_lg, "__inherit_bucket_attrs return %d", err);
		goto out;
	}

	err = ccow_finalize(c, NULL);
	if (err) {
		log_error(fsio_lg, "ccow_finalize return %d",
					err);
		goto out;
	}
	c = NULL;
	atomic_inc64((unsigned long *) &(inode->ci->used_count_diff));

out:
	if (err) {
		inode->ci->ccow_err = err;
		log_softerror(fsio_lg, err,
		    "failed for bucket: %s inode: %lu",
		    inode->ci->bid, inode->ino);

		if (err == -EEXIST || err == EEXIST)
			err = EEXIST;
	}
	assert(c == NULL);

	if (c)
		ccow_cancel(c);

	log_debug(fsio_lg, "completed inode: %ju, link: \"%s\" err:%d", inode->ino,
	    link, err);

	return err;
}

static int
__delete_disk_inode(ccowfs_inode * inode)
{
	int err = 0;
	ccow_completion_t c = NULL;
	struct iovec iov_name;

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	DEBUG_START_CALL(inode->ci, BG_DELETE);
	assert(inode->ino != CCOW_FSIO_S3OBJ_DIR_INODE);

	if (inode->ino == CCOW_FSIO_ROOT_INODE) {
		log_error(fsio_lg, "Can't delete root node - likely BUG");
		goto out;
	}
	if (inode->ino == CCOW_FSIO_LOST_FOUND_DIR_INODE) {
		log_error(fsio_lg, "Can't delete .lost+found node");
		goto out;
	}
	if (inode->oid_size <= 1) {
		log_error(fsio_lg, "Can't delete bucket node - likely BUG");
		goto out;
	}
	/* TODO: Is this refresh needed? If link count is 0 then refresh fails? */
	/* Fetch actual object/file info. */
	ccowfs_inode_refresh_locked(inode);

	err = ccowfs_create_completion(inode->ci, NULL, NULL, inode->ino, &c);
	if (err) {
		log_error(fsio_lg, "ccowfs_create_completion return %d",
		    err);
		goto out;
	}

	err = ccow_delete_notrlog(inode->ci->bid, inode->ci->bid_size,
	    inode->oid, inode->oid_size, c);
	if (err) {
		log_error(fsio_lg, "ccow_delete_notrlog return %d",
		    err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_wait fail");
		goto out;
	}
	c = NULL;

	atomic_dec64((unsigned long *) &(inode->ci->used_count_diff));
	atomic_add64((unsigned long *) &(inode->ci->used_bytes_diff),
	    -inode->logical_size);
	log_trace(fsio_lg, "subtract stats counter by: %ld",
	    -inode->logical_size);

	/*
	 * Remove the inode from deleted inode table.
	 * * Ignore any errors.
	 */
	ccowfs_recovery_remove(inode);

out:
	if (err) {
		inode->ci->ccow_err = err;
		log_error(fsio_lg,
		    "failed for bucket: %s inode: %lu err: %d",
		    inode->ci->bid, inode->ino, err);
	}
	if (c)
		ccow_release(c);
	DEBUG_END_CALL(inode->ci, BG_DELETE, err);
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

	return err;
}

typedef struct __fetch_inode_cb_args
{
	ccowfs_inode *inode;
	ccow_lookup_t iter;
	struct timespec time;
	int recovery;

} fetch_inode_args;

static int
__fetch_inode_done(fetch_inode_args * cb_args)
{
	ccowfs_inode *inode;
	struct stat *stat = NULL;
	ccow_lookup_t iter = NULL;
	int pos = 0;
	char *key;
	struct ccow_metadata_kv *kv;
	int isdir = 0;
	int err = 0;
	int for_recovery = 0;
	struct timespec time;

	log_trace(fsio_lg, "cb_args: %p", cb_args);

	if (cb_args->iter)
		iter = cb_args->iter;
	inode = cb_args->inode;
	time = cb_args->time;
	for_recovery = cb_args->recovery;

	stat = &(inode->stat);

	if (iter != NULL) {
		pos = 0;
		while ((kv = ccow_lookup_iter(iter,
			    CCOW_MDTYPE_METADATA | CCOW_MDTYPE_CUSTOM,
			    pos++))) {
			key = kv->key;
			if (strcmp(key, RT_SYSKEY_CHUNKMAP_TYPE) == 0) {
				if (strcmp(kv->value, "btree_key_val") == 0)
					isdir = 1;
			} else if (strcmp(key, RT_SYSKEY_TX_GENERATION_ID) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &inode->genid);
			} else if (strcmp(key, X_FILE_MODE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT16, kv,
				    &stat->st_mode);
				stat->st_mode &= 0xffff;
			} else if (strcmp(key, X_FILE_UID) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT16, kv,
				    &stat->st_uid);
				stat->st_uid &= 0xffff;
			} else if (strcmp(key, X_FILE_GID) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT16, kv,
				    &stat->st_gid);
				stat->st_gid &= 0xffff;
			} else if (strcmp(key,
				RT_SYSKEY_REPLICATION_COUNT) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv,
				    &stat->st_rdev);
			} else if (strcmp(key,
				RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv,
				    &stat->st_blksize);
			} else if (strcmp(key, X_FILE_SIZE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv,
				    &stat->st_size);
			} else if (strcmp(key, RT_SYSKEY_PREV_LOGICAL_SIZE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv,
				    &inode->prev_logical_size);
			} else if (strcmp(key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv,
				    &inode->logical_size);
			} else if (strcmp(key, X_FILE_ATIME) == 0) {
				uint64_t time;

				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv,
				    &time);
				stat->st_atim.tv_sec = time / (1000 * 1000);
				stat->st_atim.tv_nsec =
				    (time % (1000 * 1000)) * 1000;
			} else if (strcmp(key, X_FILE_CTIME) == 0) {
				uint64_t time;

				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv,
				    &time);
				stat->st_ctim.tv_sec = time / (1000 * 1000);
				stat->st_ctim.tv_nsec =
				    (time % (1000 * 1000)) * 1000;
			} else if (strcmp(key, X_FILE_MTIME) == 0) {
				uint64_t time;

				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv,
				    &time);
				stat->st_mtim.tv_sec = time / (1000 * 1000);
				stat->st_mtim.tv_nsec =
				    (time % (1000 * 1000)) * 1000;
			} else if (strcmp(key, X_FILE_REFCOUNT) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv,
				    &stat->st_nlink);
			} else if (strcmp(key, X_FILE_SNAP_COUNT) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv,
				    &inode->snap_count);
			}
		}

		if (inode->ino == CCOW_FSIO_ROOT_INODE) {
			stat->st_mode = (stat->st_mode & 07777) | S_IFDIR;
		}

		if ((isdir + (S_ISDIR(stat->st_mode) ? 1 : 0)) == 1) {
			err = -EIO;
			log_error(fsio_lg,
			    "failed for bucket: %s inode: %lu err: %d",
			    inode->ci->bid, inode->ino, err);
			goto out;
		}

		/*
		 * Update the block count.
		 */
		stat->st_blocks = (stat->st_size + S_BLKSIZE - 1) / S_BLKSIZE;
	} else {
		/*
		 * The object is present but no attributes.
		 * We cannot handle this case.
		 */
		err = -EIO;
		log_error(fsio_lg,
		    "failed for bucket: %s inode: %lu err: %d",
		    inode->ci->bid, inode->ino, err);
		goto out;
	}

	stat->st_ino = inode->ino;

	if (!for_recovery && stat->st_nlink == 0) {
		/*
		 * The inode present on disk but no link count.
		 * It has no namespace entry.
		 * Most likely, deleted inode which still has references on it,
		 * but may be a deleted inode which was orphaned during an
		 * unclean shutdown.
		 * We should not give additional ref on the inode except to
		 * the recovery handlers, which may need to delete orphaned
		 * inodes.
		 */
		err = ENOENT;
		log_softerror(fsio_lg, err,
		    "failed for bucket: No link. %s inode: %lu err: %d refcount %lu deleted: %lu",
			inode->ci->bid, inode->ino, err, atomic_get_uint64(&inode->refcount), inode->deleted);
		goto out;
	}
	assert(inode->ready == 0);
	atomic_set_uint64(&inode->ready, 1);

out:
	DEBUG_END_CALL(inode->ci, FETCH, err);
	log_debug(fsio_lg, "completed cb_args: %p", cb_args);

	return err;
}

static void
__fetch_inode_cb(ccow_completion_t comp, void *arg, int index, int status)
{
	fetch_inode_args *cb_args = (fetch_inode_args *) arg;

	log_trace(fsio_lg,
	    "comp: %p, arg: %p, index: %d, status: %d", comp, arg, index,
	    status);

	/*
	 * If completion is successful, get the attributes from iter
	 */
	if (status == 0) {
		status = __fetch_inode_done(cb_args);
	}
	if (cb_args->iter) {
		ccow_lookup_release(cb_args->iter);
		cb_args->iter = NULL;
	}

	if (status) {
		/*
		 * On error: remove the not-ready inode from hash table and free
		 * it.
		 * Only one thread cab be fetching the inode at a time.
		 * No one can have ref on this inode at this stage as it is not
		 * ready.
		 * No need to take any locks other than the hash table lock.
		 * Only hash table should have ref on the inode.
		 */
		nassert(cb_args->inode->ready == 0
		    && cb_args->inode->refcount == 1);

		__remove_inode_from_hash_table(cb_args->inode);
		__inode_free(cb_args->inode);
		cb_args->inode = NULL;
	}

	if (cb_args)
		je_free(cb_args);

	log_trace(fsio_lg,
	    "completed comp: %p, arg: %p, index: %d, status: %d", comp, arg,
	    index, status);
}

static int
__fetch_inode_from_disk(ccowfs_inode * inode, int sync, int recovery)
{
	ccow_completion_t c = NULL;
	int err = 0;
	fetch_inode_args *cb_args = NULL;

	log_trace(fsio_lg, "inode: %ju, sync: %d, recovery %d", inode->ino,
	    sync, recovery);
	DEBUG_START_CALL(inode->ci, FETCH);

	if (INODE_IS_S3OBJ(inode->ino) || INODE_IS_DISK_DIR(inode->ino))
		sync = 1;

	if (INODE_IS_S3OBJ(inode->ino)) {
		err = get_s3_obj_stats(inode->ci, inode->ino_str, &inode->stat);
		if (! err) {
			assert(inode->ready == 0);
			atomic_set_uint64(&inode->ready, 1);
		}
		goto out;
	}
	else if (INODE_IS_DISK_DIR(inode->ino)) {
		err = ccow_fsio_dir_fetch_attr(inode);
		if (! err) {
			assert(inode->ready == 0);
			atomic_set_uint64(&inode->ready, 1);
		}
		goto out;
	}

	cb_args = (fetch_inode_args *) je_calloc(1, sizeof(fetch_inode_args));
	if (!cb_args) {
		err = ENOENT;
		goto out;
	}

	cb_args->inode = inode;
	cb_args->iter = NULL;
	cb_args->time = time;
	cb_args->recovery = recovery;

	/*
	 * inode should not be present in hash table.
	 * The inode->ino  field must be populated.
	 * Populate the in memory structure from the on disk inode.
	 */
	if (sync)
		err = ccowfs_create_completion(inode->ci, NULL, NULL, inode->ino, &c);
	else
		err = ccowfs_create_completion(inode->ci, (void *) cb_args,
		    __fetch_inode_cb, inode->ino, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_create_completion return %d", err);

		/*Free cb_args here as callback won't be called*/
		je_free(cb_args);
		cb_args = NULL;
		goto out;
	}

	err = ccow_get(inode->ci->bid, inode->ci->bid_size, inode->oid,
	    inode->oid_size, c, NULL, 0, 256, &cb_args->iter);
	if (err){
		log_error(fsio_lg, "ccow_get return %d", err);
		goto out;
	}

	if (sync) {
		err = ccow_wait(c, 0);
		if (err) {
			log_softerror(fsio_lg, err, "ccow_wait fail");
			goto out;
		}

		err = __fetch_inode_done(cb_args);
		if (err && err != ENOENT)
			log_error(fsio_lg,
			    "__fetch_inode_done inode: %ju return %d",
				inode->ino, err);
		c = NULL;
	}

out:
	if (err) {
		inode->ci->ccow_err = err;

		if (err == -ENOENT || err == ENOENT)
			err = ENOENT;
		else {
			log_error(fsio_lg,
			    "%s failed for bucket: %s inode: %lu err: %d",
			    __func__, inode->ci->bid, inode->ino, err);
		}
		if (c)
			ccow_release(c);
	}

	if (sync) {
		if (cb_args) {
			if (cb_args->iter)
				ccow_lookup_release(cb_args->iter);
			je_free(cb_args);
		}
	}
	log_debug(fsio_lg, "completed inode: %lu, sync: %d, recovery: %d",
	    inode->ino, sync, recovery);

	return err;
}

/**
 * __update_md_to_disk_completion does not flush the data to disk directly.
 * It is responsible to update the MD to completion and disk_worker layer
 * It then sets the inode as dirty, the flusher thread will eventually flush the MD to disk
 */
static int
__update_md_to_disk_completion(ccowfs_inode *inode, uint16_t params)
{
	int err = 0;
	ci_t *ci = inode->ci;
	struct stat *stat = NULL;
	ccow_completion_t c = NULL;

	log_trace(fsio_lg, "inode: %ju, c: %p", inode->ino, c);

	DEBUG_START_CALL(ci, FLUSH);

	if (inode->read_only)
		goto out;

	/* Don't really need any extra OP from completion to update MD */
	err = disk_worker_get_md_ref(inode->ci, &(inode->disk_worker),
			&c);
	if (err) {
		log_error(fsio_lg, "disk_worker_get_md_ref return %d", err);
		goto out;
	}

	/*
	 * Caller must have lock on the inode.
	 * Fill the completion with inode metadata
	 */
	stat = &(inode->stat);

#define    __ATTR(n, v)			\
	err = set_ ## n(c, NULL, (v));	\
	if (err) {			\
		ccow_release(c);	\
		c = NULL;		\
		goto out;		\
	}

	if (params & MD_MODE)
		__ATTR(mode, stat->st_mode)
	if (params & MD_UID)
		__ATTR(uid, stat->st_uid)
	if (params & MD_GID)
		__ATTR(gid, stat->st_gid)
	if (params & MD_SIZE)
		__ATTR(size, stat->st_size)
	if (params & MD_BLKSIZE)
		__ATTR(blksize, inode->stat.st_blksize)
	if (params & MD_ATIME)
		__ATTR(atime, &stat->st_atim)
	if (params & MD_CTIME)
		__ATTR(ctime, &stat->st_ctim)
	if (params & MD_MTIME)
		__ATTR(mtime, &stat->st_mtim)
	if (params & MD_REFCOUNT)
		__ATTR(refcount, stat->st_nlink)
	if (params & MD_SNAP_COUNT)
		__ATTR(snap_count, inode->snap_count)
#undef    __ATTR
	assert(!S_ISDIR(inode->stat.st_mode));
	set_btree_order(c);

    err = disk_worker_put_md_ref(inode->ci, &(inode->disk_worker));
    if (err) {
        log_error(fsio_lg, "disk_worker_put_md_ref return %d",
            err);
        goto out;
    }

out:
    DEBUG_END_CALL(ci, FLUSH, err);

	if (err) {
		ci->ccow_err = err;
		log_softerror(fsio_lg, err, "failed for bucket: %s inode: %lu",
		    ci->bid, inode->ino);

		if (err == -ENOENT || err == ENOENT)
			err = ENOENT;
	}

	log_debug(fsio_lg, "completed inode: %lu, c: %p", inode->ino, c);

	return err;
}

#define	CCOWFSIO_NEWNODE_MEMONLY	(1 << 0)

static int
__create_inmemory_inode(ci_t *ci, inode_t ino, int flags,
    ccowfs_inode **out_inode)
{
	int err = 0;
	ccowfs_inode *inode = NULL;

	log_trace(fsio_lg, "ci: %p, ino: %lu, out_inode: %p", ci, ino,
	    out_inode);

	/*
	 * Allocate new ccowfs_inode.
	 */
	inode = (ccowfs_inode *) je_calloc(sizeof(ccowfs_inode), 1);
	if (!inode) {
		err = ENOMEM;
		log_error(fsio_lg, "Failed to allocate memory");
		goto out;
	}

	err = pthread_mutex_init(&inode->buffer_cache_mutex, NULL);
	if (err) {
		log_error(fsio_lg, "pthread_mutex_init return %d",
			err);
		goto out;
	}

	err = pthread_mutex_init(&inode->json_handle_mutex, NULL);
	if (err) {
		log_error(fsio_lg, "pthread_mutex_init return %d",
			err);
		goto out;
	}

	err = pthread_rwlock_init(&(inode->rwlock), NULL);
	if (err) {
		log_error(fsio_lg, "pthread_rwlock_init return %d",
		    err);
		goto out;
	}

	err = pthread_rwlock_init(&(inode->namespace_rwlock), NULL);
	if (err) {
		log_error(fsio_lg, "pthread_rwlock_init return %d",
		    err);
		goto out;
	}

	inode->deleted = 0;
	inode->ready = 0;
	inode->ci = ci;
	inode->ino = ino;
	if ((flags & CCOWFSIO_NEWNODE_MEMONLY) == 0) {
		snprintf(inode->ino_str, INODE_STR_MAX_SIZE, "%ju", inode->ino);
		err = __update_inode_oid(inode);
		if (err) {
			log_softerror(fsio_lg, err, "__update_inode_oid return error");
			goto out;
		}

		err = disk_worker_init(ci, &(inode->disk_worker), inode->oid,
		    inode->oid_size, ino);
		if (err) {
			log_softerror(fsio_lg, err, "disk_worker_init return error");
			goto out;
		}
	}

	if (inode->ino == CCOW_FSIO_S3OBJ_DIR_INODE
	    || INODE_IS_S3OBJ(inode->ino))
		inode->read_only = 1;
	else
		inode->read_only = 0;

	inode->expire_us = get_timestamp_us() + INODE_EXPIRE_TIMEOUT_US;

	QUEUE_INIT(&inode->dirty_q);
	QUEUE_INIT(&inode->list_q);
	QUEUE_INIT(&inode->buffer_cache_q);

out:
	if (err) {
		log_softerror(fsio_lg, err, "failed for bucket: %s inode: %lu",
		    ci->bid, ino);

		__inode_free(inode);
		inode = NULL;
	}

	*out_inode = inode;

	log_debug(fsio_lg, "completed ci: %p, ino: %lu, out_inode: %p", ci, ino,
	    out_inode);

	return err;
}

static void
__freeup_inodes(ci_t * ci, uint64_t count)
{
	uint64_t i = 0;
	QUEUE *q;
	QUEUE *tmp_q;
	ccowfs_inode *inode = NULL;

	log_trace(fsio_lg, "ci: %p, count: %lu", ci, count);

	QUEUE_FOREACH_SAFE(q, tmp_q, &ci->inode_cache.cached_inode_list) {
		inode = QUEUE_DATA(q, ccowfs_inode, list_q);
		if (atomic_get_uint64(&inode->refcount) == 1 && !inode->dirty) {
			/*
			 * We have the hash table lock -
			 * no new ref can be taken on this inode.
			 * Only hash table has a ref on it and inode is not
			 * dirty.
			 * We can free this inode.
			 */
			__remove_inode_from_hash_table_locked(inode);

			pthread_rwlock_destroy(&(inode->rwlock));
			pthread_mutex_destroy(&(inode->buffer_cache_mutex));
			pthread_rwlock_destroy(&(inode->namespace_rwlock));
			disk_worker_term(ci, &(inode->disk_worker));
			__inode_free(inode);

			i++;
			if (i == count)
				break;
		}
	}

	log_debug(fsio_lg, "completed ci: %p, count: %lu", ci, count);

	return;
}

static int
__add_inode_to_hash_table_locked(ccowfs_inode * inode)
{
	int err;

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	err = hashtable_put(inode->ci->inode_cache.inode_table,
	    (void *) inode->ino_str, strlen(inode->ino_str),
	    (void *) inode, sizeof(ccowfs_inode *));

	if (err) {
		log_error(fsio_lg, "hashtable_put return %d", err);
		goto out;

	}

	QUEUE_INSERT_TAIL(&inode->ci->inode_cache.cached_inode_list,
	    &inode->list_q);
	inode->ci->inode_cache.count++;

	if (MAX_INODE_TO_CACHE <= inode->ci->inode_cache.count) {
		/*
		 * Cached many inodes. Try to do cache cleanup
		 * * Cleanup inodes with refcount as 1 and based on LRU
		 */
		__freeup_inodes(inode->ci, MAX_INODES_TO_CLEAN);
	}

	/*
	 * Get one ref for the hash table.
	 * This ref will be dropped when the inode leaves the hash table.
	 */
	ccowfs_inode_get(inode);

out:
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

	return err;
}


static int
__inode_put_all(ccowfs_inode * inode)
{
	int err;
	inode_t ino = inode->ino;

	log_trace(fsio_lg, "inode: %lu", ino);

	nassert(inode->refcount > 0);

	atomic_set_uint64(&inode->refcount, 1);

	/*
	 * FLusher thread has gone away.
	 * If we still have dirty inode we need to flush them here.
	 */
	if (!QUEUE_EMPTY(&inode->dirty_q)) {
		err = ccowfs_inode_sync(inode, 0);

		QUEUE_REMOVE(&inode->dirty_q);
		QUEUE_INIT(&inode->dirty_q);
	}

	ccowfs_inode_put(inode);

	log_debug(fsio_lg, "completed inode: %lu", ino);

	return err;
}

int
ccowfs_inode_cache_init(ci_t * ci)
{
	int err = 0;
	int flags = 0;
	uint64_t inode_server_id = 0;

	log_trace(fsio_lg, "ci: %p", ci);

	err = pthread_mutex_init(&ci->inode_gen_mutex, NULL);
	if (err) {
		log_error(fsio_lg, "pthread_mutex_init error %d\n", err);
		ci->ccow_err = err;
		goto out;
	}
	assert(ci->last_inode_ts == 0);
	ci->last_inode_ts = get_nondecreasing_timestamp_us();

	QUEUE_INIT(&ci->open_files_head);
	err = pthread_mutex_init(&ci->queue_mutex, NULL);
	if (err) {
		log_error(fsio_lg, "pthread_mutex_init error %d\n", err);
		ci->ccow_err = err;
		goto out;
	}

	flags = flags | HT_VALUE_CONST;

	ci->inode_cache.inode_table =
	    hashtable_create(INODE_HASH_TABLE_MAX_SIZE, flags,
	    INODE_HASH_TABLE_MAX_LOAD_FACTOR);
	assert(ci->inode_cache.inode_table != NULL);

	err = pthread_rwlock_init(&(ci->inode_cache.hash_table_rwlock), NULL);
	if (err) {
		log_error(fsio_lg, "pthread_rwlock_init return %d",
		    err);
		hashtable_destroy(ci->inode_cache.inode_table);
		ci->inode_cache.inode_table = NULL;
		goto out;
	}

	QUEUE_INIT(&ci->inode_cache.cached_inode_list);
	ci->inode_cache.init_done = 1;

	err = fsio_flusher_init(ci);
out:
	if (err) {
		log_error(fsio_lg, "failed for bucket: %s", ci->bid);
	}

	log_debug(fsio_lg, "completed ci: %p", ci);

	return err;
}

int
ccowfs_inode_cache_term(ci_t * ci)
{
	QUEUE *q;
	ccowfs_inode *inode;

	log_trace(fsio_lg, "ci: %p", ci);

	fsio_flusher_term(ci);
	s3dir_free_cache(ci);

	/*
	 * Remove all inodes from hash table and drop ref.
	 * We trust on caller to make sure that there are no in flight
	 * operations.
	 * No indoe should have any open ref. We will drop all open ref on the
	 * inode.
	 */
	pthread_rwlock_wrlock(&(ci->inode_cache.hash_table_rwlock));

	while (!QUEUE_EMPTY(&ci->inode_cache.cached_inode_list)) {
		q = QUEUE_NEXT(&ci->inode_cache.cached_inode_list);
		inode = QUEUE_DATA(q, ccowfs_inode, list_q);

		/*
		 * The inode must be present in hash table.
		 * * We remove the inode from hash table
		 */
		__remove_inode_from_hash_table_locked(inode);

		/*
		 * Drop all ref on the inode
		 * We can crash in in-flight ops.
		 * Assumption is there are no in flight ops.
		 * We are deleting the ci->inode_cache here, so nothing much we
		 * can do.
		 * [TODO] Can we wait for the in-flight ops?
		 */
		pthread_rwlock_unlock(&(ci->inode_cache.hash_table_rwlock));
		__inode_put_all(inode);
		inode = NULL;
		pthread_rwlock_wrlock(&(ci->inode_cache.hash_table_rwlock));
	}

	assert(QUEUE_EMPTY(&ci->inode_cache.cached_inode_list));
	assert(ci->inode_cache.count == 0);

	hashtable_destroy(ci->inode_cache.inode_table);

	pthread_rwlock_unlock(&(ci->inode_cache.hash_table_rwlock));
	pthread_rwlock_destroy(&(ci->inode_cache.hash_table_rwlock));

	memset(&(ci->inode_cache), 0, sizeof(libccowfsio_inode_cache));

	log_debug(fsio_lg, "completed ci: %p", ci);

	return 0;
}

int
ccowfs_inode_create_new_get(ci_t * ci, inode_t ino, uint16_t mode,
    uint16_t uid, uint16_t gid, char *link, ccowfs_inode ** new_inode,
    inode_t * new_ino)
{
	ccowfs_inode *inode = NULL;
	struct stat *stat = NULL;
	int err;
	ccow_fsio_inode_type ino_type = FSIO_INODE_FILE;

	log_trace(fsio_lg, "ci: %p, ino: %lu, mode: %u, uid: %u, gid: %u, "
	    "link: \"%s\", new_inode: %p, new_ino: %p", ci, ino, mode, uid,
	    gid, link, new_inode, new_ino);

	if (!ino) {
		if (S_ISDIR(mode))
			ino_type = FSIO_INODE_DIR;
		else if (link)
			ino_type = FSIO_INODE_SYMINK;

		ccow_fsio_get_new_inode_number(ci, ino_type, &ino);
	}

	err = __create_inmemory_inode(ci, ino, 0, &inode);
	if (err != 0) {
		log_error(fsio_lg,
		    "__create_inmemory_inode return %d", err);
		ci->ccow_err = err;
		return err;
	}

	/*
	 * Set the default stat.
	 */
	stat = &(inode->stat);
	stat->st_mode = mode;
	stat->st_uid = uid;
	stat->st_gid = gid;
	stat->st_nlink = 0;
	stat->st_ino = ino;
	stat->st_size = 0;
	stat->st_blksize = ci->bk_attrs.chunk_size;
	stat->st_blocks = 0;

	if (! inode->read_only) {
		/** Create on disk inode
		 *  No need to lock the in-memory inode yet as ino is unique.
		 */
		if (INODE_IS_DISK_DIR(inode->ino))
			err = ccow_fsio_dir_create(inode);
		else
			err = __create_disk_inode(inode, link);

		if (err != 0) {
			log_error(fsio_lg, "Failed to create disk inode :%lu err: %d",
				inode->ino, err);
			ci->ccow_err = err;
			goto out;
		}
	}
	inode->ready = 1;

	/*
	 * Insert the new node in hash table.
	 */
	pthread_rwlock_wrlock(&(ci->inode_cache.hash_table_rwlock));
	err = __add_inode_to_hash_table_locked(inode);
	pthread_rwlock_unlock(&(ci->inode_cache.hash_table_rwlock));
	if (err) {
		log_error(fsio_lg,
		    "__add_inode_to_hash_table_locked return %d", err);
		goto out;
	}

	/*
	 * Get one ref for our caller.
	 */
	ccowfs_inode_get(inode);

	*new_inode = inode;
	if (new_ino)
		*new_ino = inode->ino;

out:
	if (err) {
		log_softerror(fsio_lg, err, "failed for bucket: %s inode: %lu",
		    ci->bid, ino);

		__inode_free(inode);
	}

	log_debug(fsio_lg, "completed ci: %p, ino: %lu, mode: %u, uid: %u, "
	    "gid: %u, link: \"%s\", new_inode: %p, new_ino: %p", ci, ino, mode,
	    uid, gid, link, new_inode, new_ino);

	return err;
}

int
ccowfs_inode_create_root_obj_lite(ccow_t tc, ci_t * ci)
{
	ccowfs_inode *inode = NULL;
	struct iovec iov[2];
	void *encoded_attrs = NULL;
	uint64_t encoded_attrs_len = 0;
	struct timespec time;
	int err;

	clock_gettime(CLOCK_REALTIME, &time);
	inode = (ccowfs_inode *)je_malloc(sizeof(ccowfs_inode));
	/*
	 * Set the default stat.
	 */
	inode->stat.st_mode = S_IFDIR | (07755);
	inode->stat.st_uid = inode->stat.st_gid = inode->stat.st_nlink = 0;
	inode->stat.st_size = inode->stat.st_blocks = 0;
	inode->stat.st_ino = CCOW_FSIO_ROOT_INODE;
	inode->stat.st_blksize = ci->bk_attrs.chunk_size;
	inode->stat.st_atim = inode->stat.st_mtim = inode->stat.st_ctim = time;
	inode->ino = CCOW_FSIO_ROOT_INODE;
	inode->ci = ci;

	err = ccow_shard_context_create(ROOT_INODE_STR,
	    strlen(ROOT_INODE_STR) + 1, FSIO_DIR_SHARD_COUNT,
	    &inode->dir_list_context);
	if (err) {
		log_error(fsio_lg, "ccow_shard_context_create return error %d",
		    err);
		goto out;
	}

	err = ccow_sharded_list_create(tc, inode->ci->bid, inode->ci->bid_size,
	    inode->dir_list_context);
	if (err) {
		log_error(fsio_lg, "ccow_sharded_list_create return error %d",
		    err);
		goto out;
	}

	err = __encode_dir_attrs(inode, &encoded_attrs, &encoded_attrs_len);
	if (err)
		goto out;

	assert(encoded_attrs && encoded_attrs_len);
	iov[0].iov_base = ".";
	iov[0].iov_len = 2;
	iov[1].iov_base = encoded_attrs;
	iov[1].iov_len = encoded_attrs_len;

	/*
	 * We insert the FSIO_DIR_ENCODED_ATTR key evertime we set attrs.
	 * * Allow overwrite for this key
	 */
	err = ccow_sharded_list_put_v2(tc, inode->ci->bid, inode->ci->bid_size,
	    inode->dir_list_context, iov, 2, CCOW_CONT_F_INSERT_LIST_OVERWRITE);
	if (err) {
		log_error(fsio_lg, "ccow_sharded_list_put_v2 gave err: %d",
		    err);
		goto out;
	}

	err = ccow_sharded_attributes_put(tc, inode->ci->bid,
	    inode->ci->bid_size, inode->dir_list_context, inode->oid,
	    inode->oid_size, 0, 0, 0);

	ccow_shard_context_destroy(&inode->dir_list_context);

out:
	if (encoded_attrs)
		je_free(encoded_attrs);
	if (inode)
		je_free(inode);
	return err;
}

int
ccowfs_inode_create_mem_s3dir(ci_t * ci,  uint16_t mode, uint16_t uid,
    uint16_t gid, ccowfs_inode **new_inode, inode_t *new_ino)
{
	ccowfs_inode *inode = NULL;
	struct stat *stat = NULL;
	inode_t ino;
	int err;

	log_trace(fsio_lg, "ci: %p, mode: %u, uid: %u, gid: %u, "
	    "new_inode: %p, new_ino: %p", ci, mode, uid,
	    gid, new_inode, new_ino);

	ccow_fsio_get_new_inode_number(ci, FSIO_INODE_S3OBJ, &ino);
	ino |= FSIO_INODE_MEMONLY;

	err = __create_inmemory_inode(ci, ino, CCOWFSIO_NEWNODE_MEMONLY,
	    &inode);
	if (err != 0) {
		log_error(fsio_lg,
		    "__create_inmemory_inode return %d", err);
		ci->ccow_err = err;
		return err;
	}

	/*
	 * Set the default stat.
	 */
	stat = &(inode->stat);
	stat->st_mode = mode;
	stat->st_uid = uid;
	stat->st_gid = gid;
	stat->st_nlink = 1;
	stat->st_ino = ino;
	stat->st_size = 1500;
	stat->st_blksize = ci->bk_attrs.chunk_size;
	stat->st_blocks = 1;

	inode->read_only = 1;
	inode->ready = 1;

	/*
	 * Insert the new node in hash table.
	 */
	pthread_rwlock_wrlock(&(ci->inode_cache.hash_table_rwlock));
	err = __add_inode_to_hash_table_locked(inode);
	pthread_rwlock_unlock(&(ci->inode_cache.hash_table_rwlock));
	if (err) {
		log_error(fsio_lg,
		    "__add_inode_to_hash_table_locked return %d", err);
		goto out;
	}

	/*
	 * Get one ref for our caller.
	 */
	ccowfs_inode_get(inode);

	*new_inode = inode;
	if (new_ino)
		*new_ino = inode->ino;

out:
	if (err) {
		log_softerror(fsio_lg, err, "failed for bucket: %s inode: %lu",
		    ci->bid, ino);

		__inode_free(inode);
	}

	log_debug(fsio_lg, "completed ci: %p, ino: %lu, mode: %u, uid: %u, "
	    "gid: %u, new_inode: %p, new_ino: %p", ci, ino, mode,
	    uid, gid, new_inode, new_ino);

	return err;
}

int
ccowfs_inode_link_locked(ccowfs_inode * inode)
{
	int err = 0;
	struct timespec time;

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	inode->stat.st_nlink++;

	if (inode->read_only)
		goto out;

	clock_gettime(CLOCK_REALTIME, &time);
	inode->stat.st_ctim = time;

	err =  __update_md_to_disk_completion(inode, MD_REFCOUNT | MD_CTIME);
	if (err) {
		log_error(fsio_lg, "__update_md return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}

out:
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

	return err;
}

int
ccowfs_inode_mark_deleted(ccowfs_inode *inode)
{
	atomic_set_uint64(&inode->deleted, 1);
	return 0;
}

int
ccowfs_inode_unlink_locked(ccowfs_inode * inode)
{
	int err = 0;
	struct timespec time;

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	assert(inode->stat.st_nlink > 0);
	inode->stat.st_nlink--;

	if (inode->read_only) {
		log_error(fsio_lg,
		    "Modification of readonly inode");
		goto out;
	}

	clock_gettime(CLOCK_REALTIME, &time);
	inode->stat.st_ctim = time;

	err =  __update_md_to_disk_completion(inode, MD_REFCOUNT | MD_CTIME);
	if (err) {
		log_error(fsio_lg, "__update_md return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}

	/*
	 * Even if link count is zero, no need to delete the object here.
	 * the on disk object will be deleted when last ref is put.
	 * We still keep the inode in hash table,
	 * When someone tries to look for this inode, we check the deleted flag
	 * and return enoent.
	 */

	if (inode->stat.st_nlink == 0)
		err = ccowfs_inode_mark_deleted(inode);

out:
	if (err) {
		log_error(fsio_lg,
		    "%s failed for bucket: %s inode: %lu err: %d", __func__,
		    inode->ci->bid, inode->ino, err);
	}

	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

	return err;
}

int
ccowfs_inode_link(ccowfs_inode * inode)
{
	int err;

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	/* not to be used for directories */
	assert(! INODE_IS_DISK_DIR(inode->ino));

	ccowfs_inode_lock(inode);
	err = ccowfs_inode_link_locked(inode);
	ccowfs_inode_unlock(inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_link_locked return %d", err);
		goto out;
	}

	err = ccowfs_inode_sync(inode, 1);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_sync return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}

out:

	log_debug(fsio_lg, "completed inode: %lu", inode->ino);
	return err;
}

int
ccowfs_inode_unlink(ccowfs_inode * inode)
{
	int err;

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	/* not to be used for directories */
	assert(! INODE_IS_DISK_DIR(inode->ino));

	ccowfs_inode_lock(inode);
	err = ccowfs_inode_unlink_locked(inode);
	ccowfs_inode_unlock(inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_unlink_locked return %d", err);
		goto out;
	}

	err = ccowfs_inode_sync(inode, 1);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_sync return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}

out:
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);
	return err;
}

int
ccowfs_inode_get_impl(ccowfs_inode * inode)
{
	log_trace(fsio_lg, "inode: %lu", inode->ino);
	atomic_inc64(&inode->refcount);

	return 0;
}

int
ccowfs_inode_put_impl(ccowfs_inode * inode)
{
	int err = 0;
	inode_t ino = inode->ino;

	log_trace(fsio_lg, "inode: %lu", ino);

	nassert(inode->refcount > 0);
	atomic_dec64(&inode->refcount);

	if (atomic_get_uint64(&inode->refcount) == 1
	    && (atomic_get_uint64(&inode->deleted) ||
	    inode->stat.st_nlink == 0)) {
		/*
		 * Inode is marked for deletion and has only one ref count.
		 * The only ref is for the hash table.
		 * Hash table cannot give more refs as it is marked for deletion.
		 * Remove the inode from hash table and delete the on disk object.
		 */
		__remove_inode_from_hash_table(inode);
		if (inode->ino != 2) // FIXME: need to review refcount!!
			atomic_set_uint64(&inode->refcount, 0);
	}

	if (atomic_get_uint64(&inode->refcount) == 0) {
		log_debug(fsio_lg,
                    "Last ref on inode %ju going away", inode->ino);
		/*
		 * Last ref gone. Free up the inode.
		 * This inode is not presetn in hash table. No new ref possible.
		 */

		/*
		 * Must not present in the dirty queue.
		 */
		assert(QUEUE_EMPTY(&inode->dirty_q));

		/*
		 * Must not present in the all inode list
		 */
		assert(QUEUE_EMPTY(&inode->list_q));

		if (INODE_IS_DISK_DIR(inode->ino)){
			if (atomic_get_uint64(&inode->deleted)) {
				log_debug(fsio_lg, "Deleting dir %ju",
				    inode->ino);
				err = ccow_fsio_dir_delete(inode);

				/*
				 * Remove the inode from deleted inode table.
				 * * Ignore any errors.
				 */
				ccowfs_recovery_remove(inode);
			}
		}
		else if (inode->stat.st_nlink == 0 && !(inode->ino & FSIO_INODE_MEMONLY)) {
			err = __delete_disk_inode(inode);
			if (err)
				log_error(fsio_lg,
				    "__delete_disk_inode return %d", err);
			/*
			 * Just free the in memory inode even in err case.
			 */
		} else
			log_debug(fsio_lg, "inode: %lu, st_nlink: %lu", ino,
			    inode->stat.st_nlink);

		pthread_rwlock_destroy(&(inode->rwlock));
		pthread_rwlock_destroy(&(inode->namespace_rwlock));
		pthread_mutex_destroy(&(inode->buffer_cache_mutex));
		disk_worker_term(inode->ci, &(inode->disk_worker));
		__inode_free(inode);
		inode = NULL;
	}

	log_debug(fsio_lg, "completed inode: %lu", ino);

	return err;
}

int
ccowfs_inode_get_inode_no(ccowfs_inode * inode, inode_t * ino)
{
	/** No need to take any lock.
	 *  Caller has a ref on the ccowfs_inode struct
	 *  and ino can never be updated.
	 */
	log_trace(fsio_lg, "inode: %lu, ino: %p", inode->ino, ino);
	*ino = inode->ino;

	return 0;
}

static int
ccowfs_inode_fetch_genid(ccowfs_inode *inode, uint64_t *genid)
{
	int err;
	struct ccow_metadata_kv *kv = NULL;
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	ci_t *ci = inode->ci;
	ccow_t tc;

	log_trace(fsio_lg, "ci: %p, invalidating genid ino = %lu", ci, inode->ino);

	*genid = 0;

	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccow_create_completion return %d", err);
		goto out;
	}

	err = ccow_get(ci->bid, ci->bid_size, inode->oid,
	    inode->oid_size, c, NULL, 0, 0, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_get_list return %d", err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_wait return error");
		goto out;
	}
	c = NULL;

	if (iter != NULL) {
		struct ccow_metadata_kv *kv = NULL;
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
			if (strcmp(kv->key, RT_SYSKEY_TX_GENERATION_ID) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, genid);
				if (*genid == 0)
					break;
				goto out;
			}
		}
	}
	log_debug(fsio_lg, "invalidation error");
	err = ENOENT;

out:
	if (c)
		ccow_release(c);

	if (iter)
		ccow_lookup_release(iter);

	log_debug(fsio_lg, "invalidation completed ci: %p, genid: %ld", ci, *genid);

	return err;
}

static int
ccowfs_inode_expire_check(ccowfs_inode *inode)
{
	uint64_t newts = get_timestamp_us();
	int expired = inode->expire_us < newts;
	if (expired) {
		inode->expire_us = newts + INODE_EXPIRE_TIMEOUT_US;

		/* additionally for files, verify genid */
		if (INODE_IS_FILE(inode->ino)) {
			uint64_t cur_genid;
			int err = ccowfs_inode_fetch_genid(inode, &cur_genid);
			if (!err && cur_genid == inode->genid) {
				log_debug(fsio_lg, "ino %lu cur_genid %lu genid %lu : current, no need to invalidate",
				    inode->ino, cur_genid, inode->genid);
				expired = 0;
			}
		}
	}
	return expired;
}

static int
__ccowfs_inode_get_by_ino_private(ci_t * ci, inode_t ino,
    ccowfs_inode ** out_inode, struct stat *in_stat, int recovery)
{
	int err = 0;
	ccowfs_inode *inode = NULL;
	size_t size = 0;
	uint64_t inode_ready = 0;
	uint64_t inode_deleted = 0;
	int sync = out_inode ? 1 : 0;
	int wait = 1;
	int allocated = 0;
	char ind[INODE_STR_MAX_SIZE];
	struct s3dir *s3;

	log_trace(fsio_lg, "ci: %p, ino: %lu, out_inode: %p, in_stat: %p, "
	    "recovery: %d", ci, ino, out_inode, in_stat, recovery);
	if (ino & FSIO_INODE_MEMONLY) {
		if (find_cached_s3dir_by_ino(ci, ino, &s3)) {
			if (out_inode)
				*out_inode = s3->inode;
			ccowfs_inode_get(s3->inode);
			if (in_stat) {
				/*
				 * Stats for this inode are available.
				 * Copy "based on first file" stats for times.
				 */
				s3->inode->stat.st_atim = in_stat->st_atim;
				s3->inode->stat.st_ctim = in_stat->st_ctim;
				s3->inode->stat.st_mtim = in_stat->st_mtim;
			}
			return 0;
		}
	}

	snprintf(ind, INODE_STR_MAX_SIZE, "%ju", ino);

	/*
	 * This is the only interface to get first ref on the inode.
	 * This call is responsible for fetching the inode from disk to cache
	 * memory.
	 *
	 * We can get called in two modes: sync and async.
	 * sync case:
	 *     inode present in cache:
	 *         wait for it to become ready.
	 *         Take ref on the indoe and return the inmemory inode.
	 * async case:
	 *     inode present in cache:
	 *         return
	 *     else
	 *         Add the not-redy inode in cache
	 *         start the inode fetch process
	 *     Don'y wait for the inode to become ready
	 *     Don't take additional ref on the inode
	 *
	 * Take the hash_table RD or WR lock as required.
	 */

get_inode:
	while (1) {
		pthread_rwlock_wrlock(&(ci->inode_cache.hash_table_rwlock));
		inode =
		    (ccowfs_inode *) hashtable_get(ci->inode_cache.inode_table,
		    (void *) ind, strlen(ind), &size);

		if (inode) {
			/*
			 * This inode needs to be invalidated. Remove, and re-fetch.
			 */
			if (atomic_get_uint64(&inode->refcount) == 1 &&
			    !inode->dirty && ccowfs_inode_expire_check(inode)) {
				__remove_inode_from_hash_table_locked(inode);
				__inode_free(inode);
				inode = NULL;
				pthread_rwlock_unlock(&(ci->inode_cache.
					hash_table_rwlock));
				break;
			}

			/*
			 * Move the inode at the end of the list - for LRU.
			 */
			QUEUE_REMOVE(&inode->list_q);
			QUEUE_INSERT_TAIL(&inode->ci->inode_cache.
			    cached_inode_list, &inode->list_q);

			if (sync) {
				inode_ready = atomic_get_uint64(&inode->ready);
				inode_deleted = atomic_get_uint64(&inode->deleted);
				if (inode_deleted == 1) {
					/*
					 * Inode marked for deletion.
					 * Don't give additional refs.
					 */
					pthread_rwlock_unlock(&(ci->
						inode_cache.
						hash_table_rwlock));
					err = ENOENT;
					goto out;
				}
				if (inode_ready) {
					/*
					 * Inode is present in cache and ready.
					 * job done for sync mode. return the
					 * inode with additional ref.
					 */
					ccowfs_inode_get(inode);
					*out_inode = inode;
					pthread_rwlock_unlock(&(ci->
						inode_cache.
						hash_table_rwlock));
					break;
				} else {
					/*
					 * Wait for the inode to become ready.
					 */
					pthread_rwlock_unlock(&(ci->
						inode_cache.
						hash_table_rwlock));
					usleep(100);
					continue;
				}
			} else {
				/*
				 * Inode is present in cache.
				 * job done for async mode. We can return.
				 */
				pthread_rwlock_unlock(&(ci->inode_cache.
					hash_table_rwlock));
				break;
			}
		} else {
			pthread_rwlock_unlock(&(ci->inode_cache.
				hash_table_rwlock));
			break;
		}
	}

	if (inode == NULL) {
		/*
		 * node not present in hash table. Get it from disk.
		 */

		err = __create_inmemory_inode(ci, ino, 0, &inode);
		if (err) {
			log_softerror(fsio_lg, err,
			    "__create_inmemory_inode return error");
			goto out;
		}
		allocated = 1;

		/*
		 * Add it to the hash table, so no other thread will try to
		 * fetch it.
		 */
		pthread_rwlock_wrlock(&(ci->inode_cache.hash_table_rwlock));
		if (hashtable_contains(ci->inode_cache.inode_table,
			(void *) ind, strlen(ind))) {
			/*
			 * some other thread got the chance to fetch the same
			 * inode from disk.
			 */
			__inode_free(inode);
			inode = NULL;

			pthread_rwlock_unlock(&(ci->inode_cache.
				hash_table_rwlock));
			goto get_inode;
		} else {
			err = __add_inode_to_hash_table_locked(inode);
			pthread_rwlock_unlock(&(ci->inode_cache.
				hash_table_rwlock));
		}

		if (in_stat) {
			/*
			 * Stats for this inode are available.
			 * No need to fetch it again from disk.
			 */
			memcpy(&(inode->stat), in_stat, sizeof(struct stat));

			assert(inode->ready == 0);
			atomic_inc64(&inode->ready);
			goto out;
		}

		if (sync) {
			err = __fetch_inode_from_disk(inode, 1, recovery);
			if (err) {
				if (err == ENOENT)
					goto out;
				log_softerror(fsio_lg, err,
				    "__fetch_inode_from_disk fail");
				goto out;
			}

			ccowfs_inode_get(inode);
			*out_inode = inode;
		} else {
			err = __fetch_inode_from_disk(inode, 0, 0);
			goto out;
		}
	}

out:
	if (err && err != ENOENT) {
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    ci->bid, ino, err);
	}

	if (err && allocated && inode) {
		assert(inode->ready == 0);
		__remove_inode_from_hash_table(inode);
		__inode_free(inode);
	}

	log_debug(fsio_lg, "completed ci: %p, ino: %lu, out_inode: %p, "
	    "in_stat: %p, recovery: %d", ci, ino, out_inode, in_stat, recovery);

	return err;
}

int
ccowfs_inode_get_by_ino(ci_t * ci, inode_t ino, ccowfs_inode ** out_inode)
{

	log_trace(fsio_lg, "ci: %p, ino: %lu, out_inode: %p", ci, ino, out_inode);
	return __ccowfs_inode_get_by_ino_private(ci, ino, out_inode, NULL, 0);
}

int
ccowfs_inode_cache_s3_inode(ci_t * ci, inode_t ino, struct stat *stat)
{

	log_trace(fsio_lg, "ci: %p, ino: %lu, stat: %p", ci, ino, stat);
	return __ccowfs_inode_get_by_ino_private(ci, ino, NULL, stat, 0);
}

/* get inodes for recovery handler, allows return of inodes with link count 0 */
int
ccowfs_inode_get_by_ino_for_recovery(ci_t * ci, inode_t ino,
    ccowfs_inode ** out_inode)
{

	log_trace(fsio_lg, "ci: %p, ino: %lu, out_inode: %p", ci, ino, out_inode);
	return __ccowfs_inode_get_by_ino_private(ci, ino, out_inode, NULL, 1);
}

int
ccowfs_inode_get_attr_locked(ccowfs_inode * inode, struct stat *stat)
{

	log_trace(fsio_lg, "inode: %lu, stat: %p", inode->ino, stat);

	/* The block count is not maintained on disk.
	* The size is correctly maintained. Refresh the block count from size.
	*/
	inode->stat.st_blocks = (inode->stat.st_size + S_BLKSIZE - 1) / S_BLKSIZE;

	memcpy(stat, &(inode->stat), sizeof(struct stat));
	stat->st_ino = inode->ino;

	if (inode->ino == CCOW_FSIO_S3OBJ_DIR_INODE) {
		struct timespec time;
		clock_gettime(CLOCK_REALTIME, &time);
		inode->stat.st_atim = time;
		inode->stat.st_ctim = time;
		inode->stat.st_mtim = time;
	}

	return 0;
}

static int
__update_size_locked(ccowfs_inode * inode, off_t new_logical_size)
{

	log_trace(fsio_lg, "inode: %lu, new_logical_size: %lu", inode->ino,
	    new_logical_size);

	inode->stat.st_size = new_logical_size;

	/*
	 * Update the block count.
	 */
	inode->stat.st_blocks =
	    (inode->stat.st_size + S_BLKSIZE - 1) / S_BLKSIZE;

	return 0;
}

int
ccowfs_inode_update_atime_locked(ccowfs_inode *inode)
{
    int err = 0;
    struct timespec time;

    log_trace(fsio_lg, "inode: %ju", inode->ino);

    if (inode->read_only)
        return EPERM;

    // temp disabled in FP1
    return 0;

	assert(! INODE_IS_DISK_DIR(inode->ino));

    clock_gettime(CLOCK_REALTIME, &time);
    inode->stat.st_atim = time;

	err =  __update_md_to_disk_completion(inode, MD_ATIME);
	if (err) {
		log_error(fsio_lg, "__update_md return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}
	ccowfs_inode_mark_dirty(inode);

    log_debug(fsio_lg, "completed inode: %ju", inode->ino);

out:
    return err;
}

static int
__update_mtime_locked(ccowfs_inode * inode)
{
    int err = 0;
    struct timespec time;

    log_trace(fsio_lg, "inode: %ju", inode->ino);

    if (inode->read_only) {
        log_error(fsio_lg,
            "Modification of readonly inode");
        return EPERM;
    }

    clock_gettime(CLOCK_REALTIME, &time);
    inode->stat.st_mtim = time;

    log_debug(fsio_lg, "completed inode: %ju", inode->ino);

    return err;
}

static int
__update_ctime_locked(ccowfs_inode * inode)
{
    int err = 0;
    struct timespec time;

    log_trace(fsio_lg, "inode: %ju", inode->ino);

    if (inode->read_only) {
        log_error(fsio_lg,
            "Modification of readonly inode");
        return EPERM;
    }

    clock_gettime(CLOCK_REALTIME, &time);

    inode->stat.st_ctim = time;

    log_debug(fsio_lg, "completed inode: %ju", inode->ino);

    return err;
}

int
ccowfs_inode_set_attr(ccowfs_inode * inode, struct stat *stat)
{
    int err;
    struct timespec time;

    log_trace(fsio_lg, "inode: %lu, stat: %p", inode->ino, stat);

    if (inode->read_only)
        return EPERM;

    assert(stat->st_ino == inode->ino);

    ccowfs_inode_lock(inode);

    /* Update the in memory inode MD */
    stat->st_mode &= 07777;
    stat->st_mode |= (inode->stat.st_mode & S_IFMT);
    memcpy(&(inode->stat), stat, sizeof(struct stat));
    clock_gettime(CLOCK_REALTIME, &time);
    inode->stat.st_ctim = time;
    __update_size_locked(inode, stat->st_size);

	if (INODE_IS_DISK_DIR(inode->ino)) {
		err = ccow_fsio_dir_set_attr(inode);
		if (err)
			log_error(fsio_lg, "Setting attributes on object return %d", err);
	}
	else {
		err =  __update_md_to_disk_completion(inode, MD_ALL);
		if (err) {
			log_error(fsio_lg, "__update_md return %d for inode: %lu",
				err, inode->ino);
			goto out;
		}
	}

out:
    ccowfs_inode_unlock(inode);
	err = ccowfs_inode_sync(inode, 1);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_sync return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}

    log_debug(fsio_lg, "completed inode: %lu, stat: %p", inode->ino, stat);

    return err;
}

int
ccowfs_inode_master_set_attr_locked(ccowfs_inode *inode, struct stat *stat)
{
    int err;

    memcpy(&(inode->stat), stat, sizeof(struct stat));
	err =  __update_md_to_disk_completion(inode, MD_ALL);
	if (err) {
		log_error(fsio_lg, "__update_md return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}

out:
    return err;
}

int
ccowfs_inode_sync(ccowfs_inode * inode, int client_flush)
{
	int err;

	log_trace(fsio_lg, "inode: %lu, client_flush: %d", inode->ino,
	    client_flush);

	err = fsio_buffer_cache_flush(inode, client_flush);
	if (err) {
		log_error(fsio_lg, "fsio_buffer_cache_flush failed for "
		    "inode: %lu with err  %d", inode->ino,  err);
		goto out;
	}

	log_debug(fsio_lg, "completed inode: %lu, client_flush: %d",
	    inode->ino, client_flush);
out:
	return err;
}

int
ccowfs_namespace_inode_lock(ccowfs_inode * inode)
{

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	return pthread_rwlock_wrlock(&(inode->namespace_rwlock));
}

int
ccowfs_namespace_inode_unlock(ccowfs_inode * inode)
{

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	return pthread_rwlock_unlock(&(inode->namespace_rwlock));
}

int
ccowfs_inode_lock(ccowfs_inode * inode)
{

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	return pthread_rwlock_wrlock(&(inode->rwlock));
}

int
ccowfs_inode_unlock(ccowfs_inode * inode)
{

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	return pthread_rwlock_unlock(&(inode->rwlock));
}

int
ccowfs_inode_lock_shared(ccowfs_inode * inode)
{

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	return pthread_rwlock_rdlock(&(inode->rwlock));
}

int
ccowfs_inode_unlock_shared(ccowfs_inode * inode)
{

	log_trace(fsio_lg, "inode: %lu", inode->ino);

	return pthread_rwlock_unlock(&(inode->rwlock));
}

void
s3dir_invalidate_all(ci_t *ci)
{
	QUEUE *q;
	struct s3dir *s3;

	log_trace(fsio_lg, "ci->bid: %s", ci->bid);

	QUEUE_FOREACH(q, &ci->s3dirs_head) {
		s3 = QUEUE_DATA(q, struct s3dir, q_fld);
		s3->inode->stat.st_mtime++;
	}
	if (find_cached_s3dir_by_ino(ci, CCOW_FSIO_S3OBJ_DIR_INODE, &s3))
		s3->inode->stat.st_mtime++;
}

int
find_cached_s3dir_by_path(ci_t *ci, const char *path, struct s3dir **s3dir)
{
	QUEUE *q;
	struct s3dir *s3;

	QUEUE_FOREACH(q, &ci->s3dirs_head) {
		s3 = QUEUE_DATA(q, struct s3dir, q_fld);
		if (strcmp(s3->path, path) == 0) {
			*s3dir = s3;
			return (1);
		}
	}

	return (0);
}

int
find_cached_s3dir_by_ino(ci_t *ci, inode_t ino, struct s3dir **s3dir)
{
	QUEUE *q;
	struct s3dir *s3;

	QUEUE_FOREACH(q, &ci->s3dirs_head) {
		s3 = QUEUE_DATA(q, struct s3dir, q_fld);
		if (s3->ino == ino) {
			*s3dir = s3;
			return (1);
		}
	}

	return (0);
}

int
find_cached_s3dir_lookup(ci_t *ci, inode_t parent_ino, char *name, struct s3dir **s3dir)
{
	struct s3dir *s3, *parent;
	unsigned int len = 0, plen = 0;
	QUEUE *q;
	int err;

	if (parent_ino != CCOW_FSIO_S3OBJ_DIR_INODE &&
	    !find_cached_s3dir_by_ino(ci, parent_ino, &parent))
		return (0);

	if (parent_ino != CCOW_FSIO_S3OBJ_DIR_INODE) {
		plen = strlen(parent->path);
		len = plen + 1 + strlen(name);
	}

	QUEUE_FOREACH(q, &ci->s3dirs_head) {
		s3 = QUEUE_DATA(q, struct s3dir, q_fld);

		if (parent_ino == CCOW_FSIO_S3OBJ_DIR_INODE &&
		    strcmp(s3->path, name) == 0) {
			*s3dir = s3;
			return (1);
		} else if (s3->parent_ino == parent_ino &&
		    strlen(s3->path) == len &&
		    s3->path[plen] == '/' &&
		    strcmp(s3->path + plen + 1, name) == 0) {
			*s3dir = s3;
			return (1);
		}
	}

	return (0);
}

int
s3dir_expire_check(struct s3dir *d)
{
	uint64_t newts = get_timestamp_us();
	int expired = d->expire_us < newts;
	if (expired)
		d->expire_us = newts + INODE_S3DIR_EXPIRE_TIMEOUT_US;
	return expired;
}

int
s3dir_add(ci_t *ci, inode_t parent_ino, char *name, struct s3dir **out_s3dir)
{
	ccowfs_inode *inode;
	struct s3dir *d, *s3dir = NULL;
	inode_t ino;
	int err;

	if (find_cached_s3dir_lookup(ci, parent_ino, name, &s3dir)) {
		if (out_s3dir)
			*out_s3dir = s3dir;
		return (EEXIST);
	}

	err = ccowfs_inode_create_mem_s3dir(ci, S_IFDIR | 0555, 0, 0, &inode,
	    &ino);
	if (err)
		return (err);

	d = je_calloc(1, sizeof(struct s3dir));
	if (d == NULL)
		return (ENOMEM);

	err = s3dir_mkpath(ci, parent_ino, name, &d->path);
	if (err)
		goto out;

	d->ino = ino;
	d->inode = inode;
	d->name = d->path + (strlen(d->path) - strlen(name));
	d->parent_ino = parent_ino;
	d->inode->oid = strdup("");
	d->inode->oid_size = 1;
	d->expire_us = get_timestamp_us() + INODE_S3DIR_EXPIRE_TIMEOUT_US;

	/* we can overrid this from the "top" object in the dir in lookup! */
	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	d->inode->stat.st_atim = time;
	d->inode->stat.st_ctim = time;
	d->inode->stat.st_mtim = time;

	ccowfs_inode_get(inode); /* Avoid inode free. */

	QUEUE_INSERT_TAIL(&ci->s3dirs_head, &d->q_fld);
	if (out_s3dir) {
		*out_s3dir = d;
	}
	return (0);
out:
	je_free(d);
	return err;
}

int
s3dir_free_cache(ci_t *ci)
{
	struct s3dir *s3;
	QUEUE *q, *tmp_q;

	QUEUE_FOREACH_SAFE(q, tmp_q, &ci->s3dirs_head) {
		s3 = QUEUE_DATA(q, struct s3dir, q_fld);
		QUEUE_REMOVE(&(s3->q_fld));
		ccowfs_inode_put(s3->inode);
		je_free(s3->path);
		je_free(s3);
	}

	return (0);
}

int
s3dir_mkpath(ci_t *ci, inode_t parent_ino, char *name, char **path)
{
	struct s3dir *s3;
	int f;

	if (parent_ino == CCOW_FSIO_S3OBJ_DIR_INODE) {
		*path = je_strdup(name);
		if (*path == NULL)
			return (ENOMEM);
		return (0);
	}

	f = find_cached_s3dir_by_ino(ci, parent_ino, &s3);

	if (!f)
		return (EINVAL);
	else {
		*path = je_malloc(strlen(s3->path) + strlen(name) + 2);
		if (*path == NULL)
			return (ENOMEM);
		sprintf(*path, "%s/%s", s3->path, name);
	}

	return (0);
}

int
ccow_fsio_get_file_stat(ci_t * ci, inode_t ino, struct stat *stat)
{
	ccowfs_inode *inode = NULL;
	struct s3dir *s3;
	int err;

	log_trace(fsio_lg, "ci: %p, ino: %lu, stat: %p", ci, ino, stat);

	if (ino & FSIO_INODE_MEMONLY) {
		if (find_cached_s3dir_by_ino(ci, ino, &s3)) {
			if (s3dir_expire_check(s3)) {
				uint64_t current_genid = 0;
				err = get_s3_index_genid(ci, &current_genid);
				log_debug(lg, "check invalidation %s err %d current_genid %lu ci->objects_genid %lu",
				    s3->path, err, current_genid, ci->objects_genid);
				if (err || current_genid != ci->objects_genid) {
					/* invalidate all S3 pseudo folders in
					 * the bucket, including .objects */
					s3dir_invalidate_all(ci);
				}
			}
			*stat = s3->inode->stat;
			return (0);
		}
		log_warn(fsio_lg, "Fail to get cached inode %lu. "
		    "Return dummy stat for it\n", ino);
		struct stat st;
		st.st_mode = S_IFDIR | (0555);
		st.st_atime = st.st_mtime = st.st_ctime = 0;
		st.st_nlink = 1;
		st.st_ino = ino;
		st.st_uid = 0;
		st.st_gid = 0;
		st.st_size = 0;
		st.st_blksize = ci->bk_attrs.chunk_size;
		st.st_blocks = 0;
		*stat = st;
		return (0);
	}

	DEBUG_START_CALL(ci, GET_FILE_STAT);
	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		if (err != ENOENT)
			log_error(fsio_lg, "ccowfs_inode_get_by_ino return %d",
			    err);
		goto out;
	}

	ccowfs_inode_lock_shared(inode);
	err = ccowfs_inode_get_attr_locked(inode, stat);
	ccowfs_inode_unlock_shared(inode);

	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_attr_locked return %d", err);
		goto out;
	}

out:
	if (err && err != ENOENT) {
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    ci->bid, ino, err);
	}

	if (inode)
		ccowfs_inode_put(inode);
	DEBUG_END_CALL(ci, GET_FILE_STAT, err);
	log_debug(fsio_lg, "completed ci: %p, ino: %lu, stat: %p, err: %d", ci,
	    ino,stat, err);

	return err;
}

int
ccow_fsio_set_file_stat(ci_t * ci, inode_t ino, struct stat *stat)
{
	ccowfs_inode *inode = NULL;
	int err;

	log_trace(fsio_lg, "ci: %p, ino: %lu, stat: %p", ci, ino, stat);

	DEBUG_START_CALL(ci, SET_FILE_STAT);
	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d", err);
		goto out;
	}

	err = ccowfs_inode_set_attr(inode, stat);

out:
	if (err) {
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    ci->bid, ino, err);
	}

	if (inode)
		ccowfs_inode_put(inode);
	DEBUG_END_CALL(ci, SET_FILE_STAT, err);
	log_debug(fsio_lg, "completed ci: %p, ino: %lu, stat: %p", ci, ino,
	    stat);

	return err;
}

int
ccowfs_inode_clone_get(ccowfs_inode *src_inode, ci_t *dest_ci,
    ccowfs_inode **dest_inode)
{
	int err;
	inode_t ino;
	ccowfs_inode *inode = NULL;
	struct ccow_copy_opts copy_opts;
	ccow_completion_t c = NULL;
	ci_t *ci = src_inode->ci;
	int io_blocked = 0;
	int md_blocked = 0;

	log_trace(fsio_lg, "src_inode: %lu, dest_ci: %p",
	    src_inode->ino, dest_ci);

	/*
	 * Get new inode number
	 * Clone the src_inode as new inode
	 * Set mode, uid, gid on dest_inode from src_inode
	 * Take ref on dest_inode for the caller
	 */
	ccow_fsio_get_new_inode_number(dest_ci, FSIO_INODE_FILE, &ino);

	err = __create_inmemory_inode(dest_ci, ino, 0, &inode);
	if (err != 0) {
		log_error(fsio_lg,
		    "__create_inmemory_inode return %d", err);
		dest_ci->ccow_err = err;
		return err;
	}

	/** Clone the src inode
	 *  No need to lock the in-memory inode yet as ino is unique.
	 */
	copy_opts.tid = dest_ci->tid;
	copy_opts.tid_size = dest_ci->tid_size;
	copy_opts.bid = dest_ci->bid;
	copy_opts.bid_size = dest_ci->bid_size;
	copy_opts.oid = inode->oid;
	copy_opts.oid_size = inode->oid_size;
	copy_opts.genid = NULL;
	copy_opts.version_uvid_timestamp = 0;
	copy_opts.version_vm_content_hash_id = NULL;

	err = ccowfs_create_completion(inode->ci, NULL, NULL, src_inode->ino,
	    &c);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_create_completion return %d", err);
		goto out;
	}

	/*
	 * Pause IO and MD updated for the source inode.
	 */
	ccowfs_inode_lock(src_inode);
	md_blocked = 1;

	/*
	 * Set the default stat same as the src_inode
	 * Update the inode number in the stats for new inode.
	 * Start with 1 as link count for the new inode.
	 */
	memcpy(&inode->stat, &src_inode->stat, sizeof(inode->stat));
	inode->stat.st_ino = ino;
	inode->stat.st_nlink = 1;

	/*
	 * Flush any open IO as if client is requesting the flush.
	 */
	err = disk_worker_freez(ci, &(src_inode->disk_worker), 1);
	if (err) {
		log_error(fsio_lg,
		    "disk_worker_freez return %d", err);
		goto out;
	}
	io_blocked = 1;

	err = ccow_clone(c, ci->tid, ci->tid_size, ci->bid, ci->bid_size,
	    src_inode->oid, src_inode->oid_size, &copy_opts);
	if (err) {
		log_error(fsio_lg, "ccow_clone return %d", err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_wait fail");
		goto out;
	}

	c = NULL;
	inode->ready = 1;

	/*
	 * Insert the new node in hash table.
	 */
	pthread_rwlock_wrlock(&(ci->inode_cache.hash_table_rwlock));
	err = __add_inode_to_hash_table_locked(inode);
	pthread_rwlock_unlock(&(ci->inode_cache.hash_table_rwlock));
	if (err) {
		log_error(fsio_lg, "__add_inode_to_hash_table_locked return %d",
		    err);
		goto out;
	}

	/*
	 * Get one ref for our caller.
	 */
	ccowfs_inode_get(inode);
	*dest_inode = inode;

out:
	if (io_blocked)
		disk_worker_unfreez(ci, &(src_inode->disk_worker));

	if (md_blocked)
		ccowfs_inode_unlock(src_inode);

	if (err) {
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    ci->bid, ino, err);

		__inode_free(inode);

		if (c)
			ccow_release(c);

		*dest_inode = NULL;
	}

	log_debug(fsio_lg, "completed src_inode: %lu, dest_ci: %p, "
	    "dest_inode: %lu", src_inode->ino, dest_ci, (*dest_inode)->ino);

	return err;
}

int
ccowfs_inode_refresh_locked(ccowfs_inode * inode)
{
	log_trace(fsio_lg, "inode: %lu", inode->ino);

	inode->ready = 0;
	return __fetch_inode_from_disk(inode, 1, 0);
}

int
ccowfs_inode_inc_snap_count(ccowfs_inode * inode)
{
	int err;
	log_trace(fsio_lg, "inode: %lu", inode->ino);

	inode->snap_count++;

	err =  __update_md_to_disk_completion(inode, MD_SNAP_COUNT);
	if (err) {
		log_error(fsio_lg, "__update_md return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}

out:
	return err;
}

int
ccowfs_inode_dec_snap_count(ccowfs_inode * inode)
{
	int err;
	log_trace(fsio_lg, "inode: %lu", inode->ino);

	assert(inode->snap_count != 0);
	inode->snap_count--;

	err =  __update_md_to_disk_completion(inode, MD_SNAP_COUNT);
	if (err) {
		log_error(fsio_lg, "__update_md return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}

out:
	return err;
}

int
ccowfs_inode_update_size(ccowfs_inode *inode, size_t new_size)
{
	int err = 0;
	uint16_t params = MD_MTIME;

	ccowfs_inode_lock(inode);
	__update_mtime_locked(inode);

	if (inode->stat.st_size < (off_t)new_size) {
		__update_size_locked(inode, new_size);
		__update_ctime_locked(inode);
		params |= MD_SIZE | MD_CTIME;
	}

	if (INODE_IS_DISK_DIR(inode->ino)) {
		err = ccow_fsio_dir_set_attr(inode);
		if (err) {
			log_error(fsio_lg, "Setting attributes on object "
			    "return %d", err);
			goto out;
		}
	}
	else {
		err = __update_md_to_disk_completion(inode, params);
		if (err) {
			log_error(fsio_lg, "__update_md return %d for inode: %lu",
				err, inode->ino);
			goto out;
		}
		ccowfs_inode_mark_dirty(inode);
	}

out:
	ccowfs_inode_unlock(inode);

	return err;
}

int
ccowfs_inode_get_size(ccowfs_inode *inode, size_t *size)
{
	*size = atomic_get_uint64((uint64_t*)(&inode->stat.st_size));

	return 0;
}

int
ccowfs_inode_parse_s3_multipart_json(ccowfs_inode *inode, uint64_t chunk_size)
{
	int err = 0;
	ccow_completion_t c = NULL;

	log_trace(fsio_lg, "inode: %lu", inode->ino);
	assert(INODE_IS_S3OBJ(inode->ino) && inode->multipart);

	/** Read the main object and get the JSON data
	 */
	char *json_data = je_calloc(1, inode->json_size + 1);
	uint64_t iovcnt;

	if (inode->json_size % chunk_size)
		iovcnt = (inode->json_size / chunk_size) + 1;
	else
		iovcnt = (inode->json_size / chunk_size);

	log_debug(fsio_lg, "json_size :%lu chunk_size :%lu iovcnt :%lu",
		inode->json_size, chunk_size, iovcnt);

	struct iovec *iov = (struct iovec *) je_calloc(iovcnt, sizeof(struct iovec));
	if (!iov) {
		err = ENOMEM;
		goto out;
	}

	for (uint64_t i=0; i<iovcnt; i++) {
		iov[i].iov_base = (void *) (json_data + i * chunk_size);
		iov[i].iov_len = chunk_size;
	}

	err = ccowfs_create_completion(inode->ci, NULL, NULL, inode->ino, &c);
	if (err) {
		log_error(fsio_lg, "create_completion err: %d for inode: %lu",
		    err, inode->ino);
		goto out;
	}

	err = ccow_get(inode->ci->bid, inode->ci->bid_size, inode->oid,
	    inode->oid_size, c, iov, iovcnt, 0, NULL);
	if (err) {
		log_error(fsio_lg, "ccow_get error: %d for inode: %lu",
		    err, inode->ino);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_wait fail");
		goto out;
	}
	c = NULL;

	log_debug(fsio_lg, "inode :%lu JSON: %s", inode->ino, json_data);

	pthread_mutex_lock(&inode->json_handle_mutex);
	if (inode->json_handle) {
		/* This could be old version of the json. purge it */
		put_s3_json_handle(inode->json_handle);
		inode->json_handle = NULL;
	}

	/** Parse the json and store it inside inode.
	 *	S3 handling owns the parsed json and is abstracted from inode level.
	 */
	err = get_s3_json_handle(json_data, &(inode->json_handle));
	pthread_mutex_unlock(&inode->json_handle_mutex);
	if (err) {
		log_error(fsio_lg,
			"get_s3_json_handle failed for inode: %lu with error :%d",
			inode->ino, err);
		goto out;
	}

out:
	pthread_mutex_lock(&inode->json_handle_mutex);
	if (err && inode->json_handle) {
		put_s3_json_handle(inode->json_handle);
		inode->json_handle = NULL;
	}
	pthread_mutex_unlock(&inode->json_handle_mutex);
	if (c)
		ccow_release(c);
	if (iov)
		je_free(iov);
	if (json_data)
		je_free(json_data);

	return err;
}

int
testonly_get_inode_ref(ci_t * ci, inode_t ino, void **inode_ref)
{
	int err;
	ccowfs_inode *inode = NULL;

	log_trace(fsio_lg, "ci: %p, ino: %lu, inode_ref: %p", ci, ino,
	    inode_ref);

	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	*inode_ref = (void *)inode;

	log_debug(fsio_lg, "completed ci: %p, ino: %lu, inode_ref: %p", ci, ino,
	    inode_ref);

	return err;
}

int
testonly_put_inode_ref(ci_t * ci, void *inode_ref)
{
	ccowfs_inode *inode = (ccowfs_inode *) inode_ref;

	log_trace(fsio_lg, "ci: %p, inode_ref: %p", ci, inode_ref);

	ccowfs_inode_put(inode);

	log_debug(fsio_lg, "completed ci: %p, inode_ref: %p", ci, inode_ref);

	return 0;
}

int
testonly_remove_inode_from_cache_by_ref(ci_t * ci, void *inode_ref)
{
	int err;
	ccowfs_inode *inode = (ccowfs_inode *)inode_ref;

	nassert(inode->refcount > 1);

	if(inode->dirty) {
		err = ccowfs_inode_sync(inode, 0);
		if (err) {
			log_error(fsio_lg,
				"ccowfs_inode_sync return %d", err);
			goto out;
		}
	}

	err = __remove_inode_from_hash_table(inode);
	if (err) {
		log_error(fsio_lg,
		    "__remove_inode_from_hash_table return %d", err);
		goto out;
	}

out:
	return err;
}

int
testonly_remove_inode_from_cache(ci_t * ci, inode_t ino)
{
	int err;
	ccowfs_inode *inode = NULL;

	log_trace(fsio_lg, "ci: %p, ino: %lu", ci, ino);

	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d", err);
		goto out;
	}

	if(inode->dirty) {
		err = ccowfs_inode_sync(inode, 0);
		if (err) {
			log_error(fsio_lg,
				"ccowfs_inode_sync return %d", err);
			goto out;
		}
	}

	err = __remove_inode_from_hash_table(inode);
	if (err) {
		log_error(fsio_lg,
		    "__remove_inode_from_hash_table return %d", err);
		goto out;
	}

out:
	if (inode)
		ccowfs_inode_put(inode);

	log_debug(fsio_lg, "completed ci: %p, ino: %lu", ci, ino);

	return err;
}

int
testonly_fetch_inode(ci_t * ci, inode_t ino, int sync)
{
	int err;
	ccowfs_inode *inode = NULL;

	log_trace(fsio_lg, "ci: %p, ino: %lu, sync: %d", ci, ino, sync);

	if (sync)
		err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	else
		err = ccowfs_inode_get_by_ino(ci, ino, NULL);

	if (inode)
		ccowfs_inode_put(inode);

	log_debug(fsio_lg, "completed ci: %p, ino: %lu, sync: %d", ci, ino,
	    sync);

	return err;
}

int
testonly_refresh_inode(ci_t * ci, inode_t ino)
{
	int err;
	ccowfs_inode *inode = NULL;

	log_trace(fsio_lg, "ci: %p, ino: %lu", ci, ino);

	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_get_by_ino returned %d, ino: %lu",
		    err, ino);
		goto out_nolock;
	}

	ccowfs_inode_lock(inode);

	err = ccowfs_inode_refresh_locked(inode);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_refresh_locked returned %d, ino: %lu",
		    err, ino);
	}

	ccowfs_inode_unlock(inode);

out_nolock:
	if (inode)
		ccowfs_inode_put(inode);

	log_debug(fsio_lg, "completed ci: %p, ino: %lu", ci, ino);

	return err;
}

int
testonly_create_inode(ci_t* ci, inode_t parent_ino, char *name, uint16_t mode,
    uint16_t uid, uint16_t gid, inode_t * newnode_ino, char *link)
{
	ccowfs_inode *child_inode = NULL;
	ccowfs_inode *parent_inode = NULL;
	int err;
	inode_t child_ino;

	log_trace(fsio_lg, "ci: %p, parent_ino: %lu, name: \"%s\", mode: %u, "
	    "uid: %u, gid: %u, link: \"%s\"",
	    ci , parent_ino, name, mode, uid, gid, link);

	/* Get a ref on parent inode */
	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg,
		"ccowfs_inode_get_by_ino return %d for inode: %lu",
		err, parent_ino);
		goto out_nolock;
	}

	ccowfs_namespace_inode_lock(parent_inode);

	/* create new inode */
	err = ccowfs_inode_create_new_get(ci, 0, mode, uid, gid,
		link, &child_inode, &child_ino);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_create_new_get return %d", err);
		goto out;
	}
	if (newnode_ino)
		*newnode_ino = child_ino;

out:
	ccowfs_namespace_inode_unlock(parent_inode);

out_nolock:
	if (parent_inode)
		ccowfs_inode_put(parent_inode);
	if (child_inode)
		ccowfs_inode_put(child_inode);

	if (err) {
		log_error(fsio_lg,
		    "failed for bucket: %s inode: %lu name: %s err: %d",
		    ci->bid, parent_ino, name, err);
	}

	log_debug(fsio_lg, "completed ci: %p, parent_ino: %lu, name: \"%s\", "
	    "mode: %u, uid: %u, gid: %u, newnode_ino: %lu, link: \"%s\"",
	    ci, parent_ino, name, mode, uid, gid, child_ino, link);

	return err;
}

int testonly_inode_mark_deleted(ci_t *ci, inode_t ino)
{
	int err;
	ccowfs_inode *inode = NULL;

	log_trace(fsio_lg, "ci: %p, ino: %lu", ci, ino);

	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_get_by_ino returned %d, ino: %lu",
		    err, ino);
		goto out_nolock;
	}

	ccowfs_inode_lock(inode);

	err = ccowfs_inode_mark_deleted(inode);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_mark_deleted returned %d, ino: %lu",
		    err, ino);
	}

	ccowfs_inode_unlock(inode);

out_nolock:
	if (inode)
		ccowfs_inode_put(inode);

	log_debug(fsio_lg, "completed ci: %p, ino: %lu", ci, ino);

	return err;
}

int testonly_inode_delete_unsafe(ci_t *ci, inode_t parent_ino, char *name,
    inode_t child_ino)
{
	ccowfs_inode *child_inode = NULL;
	ccowfs_inode *parent_inode = NULL;
	int err = 0, child_namespace_locked = 0, in_parent = 0;
	inode_t lookup_in_parent = 0;

	log_trace(fsio_lg, "%s: parent_ino: %lu, name: \"%s\", child_ino: %lu",
	    __func__, parent_ino, name, child_ino);

	/* delete an inode but allow some failures and do not use
	 * the recovery table
	 */

	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d for inode: %lu",
		    err, parent_ino);
		goto out_nolock;
	}

	ccowfs_namespace_inode_lock(parent_inode);

	err = ccow_fsio_lookup(ci, parent_ino, name, &lookup_in_parent);
	if (err == 0) {
		/* is this the inode we are trying to delete ? */
		if (lookup_in_parent == child_ino)
			in_parent = 1;
		else
			log_warn(fsio_lg, "Found name: %s in parent_ino: %lu "
			    "with ino: %lu does not match child_ino: %lu",
			    name, parent_ino, lookup_in_parent, child_ino);
	} else if (err != ENOENT) {
		log_error(fsio_lg,
		    "ccow_fsio_lookup return %d parent: %lu name: %s",
		    err, parent_ino, name);
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, child_ino, &child_inode);
	if (err) {
		if (err == ENOENT && in_parent) {
			log_warn(fsio_lg, "Remove stale dir entry");
			err = ccow_fsio_dir_remove_entry(ci, parent_inode, name, 0);
			if (err)
				log_error(fsio_lg, "Fail to remove stale entry");
		} else {
			log_error(fsio_lg,
			    "ccowfs_inode_get_by_ino return: %d for inode: %lu",
			    err, child_ino);
		}
		goto out;
	}

	if (INODE_IS_DISK_DIR(child_ino)) {
		/* Note: no check if the dir is empty */

		ccowfs_namespace_inode_lock(child_inode);
		child_namespace_locked = 1;

		/* Remove ".." from child dir, and pro-actively decrement its
		 * link count for both "." and itself
		 */
		err = ccow_fsio_dir_remove_entry(ci, child_inode, "..", 2);
		if (err && err != ENOENT) {
			log_error(fsio_lg, "failed to remove '..' entry "
			    "bucket: %s inode: %lu err: %d",
			    ci->bid, child_inode->ino, err);
			goto out;
		}

		/* Remove the child entry from the parent
		 * We will decrement parent link count for the ".."
		 */
		if (in_parent) {
			err = ccow_fsio_dir_remove_entry(ci, parent_inode, name, 1);
			if (err && err != ENOENT) {
				log_error(fsio_lg,
				    "ccow_fsio_dir_remove_entry return %d "
				    "parent: %lu name: %s", err, parent_ino, name);
				goto out;
			}
		}
		atomic_set_uint64(&child_inode->deleted, 1);
	} else if (child_inode->snap_count != 0) {
		/*
		 * Not allowed to delete file which has active snapshots
		 * Directories cannot have snapshot.
		 */
		err = EPERM;
		goto out;
	} else {
		/* Remove the child entry from the parent
		 */
		if (in_parent) {
			err = ccow_fsio_dir_remove_entry(ci, parent_inode,
			    name, 0);
			if (err) {
				log_error(fsio_lg,
				    "ccow_fsio_dir_remove_entry return %d "
				    "parent: %lu name: %s", err, parent_ino, name);
				goto out;
			}
		}

		ccowfs_inode_lock(child_inode);
		/* Drop the link count for the file. */
		child_inode->stat.st_nlink = 0;

		err =  __update_md_to_disk_completion(child_inode, MD_REFCOUNT | MD_CTIME);
		if (err) {
			log_error(fsio_lg, "__update_md return %d for inode: %lu",
				err, child_inode->ino);
			ccowfs_inode_unlock(child_inode);
			goto out;
		}
		/* mark the inode deleted */
		atomic_set_uint64(&child_inode->deleted, 1);
		ccowfs_inode_unlock(child_inode);
		err = ccowfs_inode_sync(child_inode, 1);
		if (err) {
			log_error(fsio_lg, "ccowfs_inode_sync return %d for "
			    "inode: %lu", err, child_inode->ino);
		}
	}

out:
	if (child_namespace_locked)
		ccowfs_namespace_inode_unlock(child_inode);

	ccowfs_namespace_inode_unlock(parent_inode);

out_nolock:
	if (child_inode)
		ccowfs_inode_put(child_inode);
	if (parent_inode)
		ccowfs_inode_put(parent_inode);

	if (err) {
		ci->ccow_err = err;
		log_softerror(fsio_lg, err,
		    "failed for bucket: %s inode: %lu name: %s",
		    ci->bid, parent_ino, name);
	}
	log_debug(fsio_lg, "completed %s: parent_ino: %lu, name: \"%s\"",
	    __func__, parent_ino, name);

	return err;
}

int
testonly_get_inode_ref_for_recovery(ci_t * ci, inode_t ino, void **inode_ref)
{
	int err;
	ccowfs_inode *inode = NULL;

	log_trace(fsio_lg, "ci: %p, ino: %lu, inode_ref: %p", ci, ino,
	    inode_ref);

	/* allows getting inodes with link count 0 */
	err = ccowfs_inode_get_by_ino_for_recovery(ci, ino, &inode);
	*inode_ref = (void *)inode;

	log_debug(fsio_lg, "completed ci: %p, ino: %lu, inode_ref: %p", ci, ino,
	    inode_ref);

	return err;
}

int
testonly_inode_purge_by_ref(ci_t *ci, void *inode_ref)
{
	int err = 0;
	ccowfs_inode *inode = (ccowfs_inode *)inode_ref;
	inode_t ino = inode->ino;

	log_trace(fsio_lg, "ci: %p, inode: %lu", ci, ino);
	err = __remove_inode_from_hash_table(inode);
	if (err) {
		log_error(fsio_lg, "__remove_inode_from_hash_table failed "
		    "err:%d", err);
		goto out;
	}
	__inode_free(inode);

out:
	log_debug(fsio_lg, "completed inode: %lu", ino);

	return err;
}

int
testonly_inode_unlink_by_ref(ci_t *ci, void *inode_ref, int mark_deleted,
    int do_flush)
{
	int err = 0;
	ccowfs_inode *inode = (ccowfs_inode *)inode_ref;
	struct timespec time;

	log_trace(fsio_lg, "ci: %p, inode: %lu", ci, inode->ino);

	ccowfs_inode_lock(inode);

	assert(inode->stat.st_nlink > 0);
	inode->stat.st_nlink--;

	if (inode->read_only) {
		log_error(fsio_lg,
		    "Modification of readonly inode");
		err = EPERM;
		goto out;
	}

	clock_gettime(CLOCK_REALTIME, &time);
	inode->stat.st_ctim = time;

	err =  __update_md_to_disk_completion(inode, MD_REFCOUNT | MD_CTIME);
	if (err) {
		log_error(fsio_lg, "__update_md return %d for inode: %lu",
			err, inode->ino);
		ccowfs_inode_unlock(inode);
		goto out;
	}

	if (mark_deleted && inode->stat.st_nlink == 0)
		ccowfs_inode_mark_deleted(inode);

	ccowfs_inode_unlock(inode);

	if (do_flush) {
		err = ccowfs_inode_sync(inode, 1);
		if (err) {
			log_error(fsio_lg, "ccowfs_inode_sync return %d for "
			    "inode: %lu", err, inode->ino);
		}
	}

out:
	if (err) {
		log_error(fsio_lg,
		    "%s failed for bucket: %s inode: %lu err: %d", __func__,
		    inode->ci->bid, inode->ino, err);
	}

	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

	return err;
}
