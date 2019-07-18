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
#include <assert.h>
#include <time.h>
#include <string.h>
#include <lfq.h>

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ccow.h>
#include <ccowfsio.h>
#include <msgpackalt.h>

#include "fsio_system.h"
#include "fsio_inode.h"
#include "fsio_listcache.h"
#include "fsio_disk.h"
#include "fsio_debug.h"
#include "fsio_common.h"
#include "fsio_dir.h"
#include "fsio_s3_transparency.h"
#include "fsio_recovery.h"
#include "tc_pool.h"

/**
 * Sharded list is used for directory.
 * Maintain the FSIO directory OPs in this file.
 * This interface will abstract the sharded list API from other FSIO code.
 */

#define MAX_ATTR_VALUE_SIZE 64

#define FSIO_DIR_ATIME_FLAG 0x01
#define FSIO_DIR_MTIME_FLAG 0x02
#define FSIO_DIR_CTIME_FLAG 0x04

/**
 * Two types of attributes:
 * 1. List attributes : attrs which are maintained encoded in the btree
 *    these are maintained as value for the key "."
 * 2. Inc/Dec attributes: attrs which can be incrmented/decremented.
 *                        These are kept on dir_list_context the as metadata
 */
static char FSIO_DIR_ENCODED_ATTR[] = ".";

#define FSIO_DIR_ENCODED_ATTR_VERSION 4

int
__encode_dir_attrs(ccowfs_inode * inode, void **encoded_attrs,
    uint64_t * encoded_attrs_len)
{
	int err;
	msgpack_p *p = msgpack_pack_init();
	uv_buf_t uv_b;

	log_trace(fsio_lg, "%s for inode: %lu", __func__, inode->ino);

	err = msgpack_pack_uint8(p, FSIO_DIR_ENCODED_ATTR_VERSION);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint8 return %d", err);
		goto out;
	}

	err = msgpack_pack_uint32(p, inode->stat.st_mode);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint32 return %d", err);
		goto out;
	}
	err = msgpack_pack_uint32(p, inode->stat.st_uid);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint32 return %d", err);
		goto out;
	}
	err = msgpack_pack_uint32(p, inode->stat.st_gid);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint32 return %d", err);
		goto out;
	}
	err = msgpack_pack_uint64(p, inode->stat.st_dev);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint32 return %d", err);
		goto out;
	}
	err = msgpack_pack_uint64(p, inode->stat.st_rdev);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint32 return %d", err);
		goto out;
	}

	err = msgpack_pack_uint64(p, (uint64_t) (inode->stat.st_atim.tv_sec));
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d", err);
		goto out;
	}
	err = msgpack_pack_uint64(p, (uint64_t) (inode->stat.st_atim.tv_nsec));
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d", err);
		goto out;
	}
	err = msgpack_pack_uint64(p, (uint64_t) (inode->stat.st_mtim.tv_sec));
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d", err);
		goto out;
	}
	err = msgpack_pack_uint64(p, (uint64_t) (inode->stat.st_mtim.tv_nsec));
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d", err);
		goto out;
	}
	err = msgpack_pack_uint64(p, (uint64_t) (inode->stat.st_ctim.tv_sec));
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d", err);
		goto out;
	}
	err = msgpack_pack_uint64(p, (uint64_t) (inode->stat.st_ctim.tv_nsec));
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d", err);
		goto out;
	}

	msgpack_get_buffer(p, &uv_b);
	*encoded_attrs = je_calloc(1, uv_b.len);
	if (!*encoded_attrs) {
		log_error(fsio_lg, "Failed to allocate memory");
		err = ENOMEM;
		goto out;
	}

	memcpy(*encoded_attrs, uv_b.base, uv_b.len);
	*encoded_attrs_len = uv_b.len;

out:
	if (p)
		msgpack_pack_free(p);

	log_debug(fsio_lg, "Completed %s inode: %lu", __func__, inode->ino);
	return err;
}

static int
__decode_dir_attrs(ccowfs_inode * inode, void *encoded_attrs,
    uint64_t encoded_attrs_len)
{
	int err;
	msgpack_u *u;
	uint8_t ver;

	log_trace(fsio_lg, "%s for inode: %lu", __func__, inode->ino);

	u = msgpack_unpack_init(encoded_attrs, encoded_attrs_len, 0);
	err = msgpack_unpack_uint8(u, &ver);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint8 return %d", err);
		goto out;
	}

	if (ver == FSIO_DIR_ENCODED_ATTR_VERSION) {
		err = msgpack_unpack_uint32(u, &(inode->stat.st_mode));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint32 return %d", err);
			goto out;
		}
		err = msgpack_unpack_uint32(u, &(inode->stat.st_uid));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint32 return %d", err);
			goto out;
		}
		err = msgpack_unpack_uint32(u, &(inode->stat.st_gid));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint32 return %d", err);
			goto out;
		}
		err = msgpack_unpack_uint64(u, &(inode->stat.st_dev));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint32 return %d", err);
			goto out;
		}
		err = msgpack_unpack_uint64(u, &(inode->stat.st_rdev));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint32 return %d", err);
			goto out;
		}
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & (inode->stat.st_atim.tv_sec));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & (inode->stat.st_atim.tv_nsec));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & (inode->stat.st_mtim.tv_sec));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & (inode->stat.st_mtim.tv_nsec));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & (inode->stat.st_ctim.tv_sec));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}
		err =
		    msgpack_unpack_uint64(u,
		    (uint64_t *) & (inode->stat.st_ctim.tv_nsec));
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}
	} else {
		log_error(fsio_lg, "Wrong dir attr version %d", ver);
		err = -EIO;
	}

out:
	if (u)
		msgpack_unpack_free(u);

	log_debug(fsio_lg, "Completed %s inode: %lu", __func__, inode->ino);
	return err;
}

static int
__set_times(ccowfs_inode * inode, int flag, int dir_create)
{
	int err = 0;
	struct timespec time;

	log_trace(fsio_lg, "%s for inode: %lu", __func__, inode->ino);

	clock_gettime(CLOCK_REALTIME, &time);


	if (flag & FSIO_DIR_ATIME_FLAG)
		inode->stat.st_atim = time;
	if (flag & FSIO_DIR_MTIME_FLAG)
		inode->stat.st_mtim = time;
	if (flag & FSIO_DIR_CTIME_FLAG)
		inode->stat.st_ctim = time;


	/**
	 * Important attributes from consistency stand point already being
	 * updated earlier during file add/remove. Attributes can be updated
	 * later. Except dir create case.
	 */
	if (dir_create) { // Dir create case
		log_debug(fsio_lg, "Set create time inode: %lu", inode->ino);
		err = ccow_fsio_dir_set_attr(inode);
	} else {
		// atime flush temp disabled, mark dirty only if mtime or ctime is set
		if ((flag & FSIO_DIR_MTIME_FLAG) || (flag & FSIO_DIR_CTIME_FLAG)) {
			log_debug(fsio_lg, "Mark dirty inode: %lu", inode->ino);
			err = ccowfs_inode_mark_dirty(inode);
		}
	}

	log_debug(fsio_lg, "Completed %s inode: %lu", __func__, inode->ino);

	return err;
}

static int
__is_dir_empty(ccowfs_inode * inode)
{
	ccow_t tc;
	int err;

	log_trace(fsio_lg, "for inode: %lu", inode->ino);

	err = tc_pool_get_tc(inode->ci->tc_pool_handle, inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		return 0;
	}

	int64_t s, n, b;
	err = ccow_sharded_attributes_get(tc, inode->ci->bid,
	    inode->ci->bid_size, inode->dir_list_context, &s, &n, &b);

	log_debug(fsio_lg, "list GET inode: %lu dir_size: %lu, err: %d",
		inode->ino, inode->stat.st_size, err);

	if (err) {
		log_error(fsio_lg, "failed to GET inode: %lu, err: %d",
			inode->ino, err);
		return 0;
	}

	inode->stat.st_size = s;
	inode->stat.st_nlink = n;
	inode->stat.st_blocks = b;

	if (inode->stat.st_size <= (off_t) EMPTY_DIR_SIZE)
		return 1;

	return 0;
}

static int
__init_default_attributes(ccowfs_inode * inode)
{
	int err = 0;

	log_trace(fsio_lg, "%s for inode: %lu", __func__, inode->ino);

	ccow_t tc;

	err = tc_pool_get_tc(inode->ci->tc_pool_handle, inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
		    err);
		goto out;
	}

	err = ccow_fsio_dir_set_attr(inode);
	if (err)
		goto out;

	err =
	    ccow_sharded_attributes_put(tc, inode->ci->bid,
	    inode->ci->bid_size, inode->dir_list_context, inode->oid,
	    inode->oid_size, 0, 0, 0);

out:
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);
	return err;
}

int
ccow_fsio_dir_fetch_attr(ccowfs_inode * inode)
{
	int err = 0;
	struct iovec iov[1] = { 0 };

	log_trace(fsio_lg, "%s inode: %lu", __func__, inode->ino);

	if (inode->deleted) {
		log_debug(fsio_lg, "Already deleted inode: %lu", inode->ino);
		err = ENOENT;
		goto out;
	}

	ccow_t tc;
	err = tc_pool_get_tc(inode->ci->tc_pool_handle, inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
		    err);
		goto out;
	}
	err = ccow_sharded_list_get(tc, inode->ci->bid, inode->ci->bid_size,
	    inode->dir_list_context,
	    FSIO_DIR_ENCODED_ATTR, strlen(FSIO_DIR_ENCODED_ATTR) + 1, iov, 1);
	if (err) {
		goto out;
	}

	assert(iov->iov_base);
	err = __decode_dir_attrs(inode, (void *) iov->iov_base, iov->iov_len);
	je_free(iov->iov_base);
	iov->iov_base = NULL;
	if (err)
		goto out;

	int64_t s, n, b;
	err = ccow_sharded_attributes_get(tc, inode->ci->bid,
	    inode->ci->bid_size, inode->dir_list_context, &s, &n, &b);

	log_debug(fsio_lg, "FETCH inode: %lu dir_size: %lu st_nlink: %lu",
		inode->ino, inode->stat.st_size, inode->stat.st_nlink);

	if (!err) {
		inode->stat.st_blksize = inode->ci->bk_attrs.chunk_size;
		inode->stat.st_size = s;
		inode->stat.st_nlink = n;
		inode->stat.st_blocks = b;
	}

out:
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);
	return err;
}

int
ccow_fsio_dir_set_attr(ccowfs_inode * inode)
{
	int err = 0;
	char value[MAX_ATTR_VALUE_SIZE];
	struct iovec iov[2];
	void *encoded_attrs = NULL;
	uint64_t encoded_attrs_len = 0;

	log_trace(fsio_lg, "%s inode: %lu", __func__, inode->ino);

	if (inode->deleted) {
		log_debug(fsio_lg, "Already deleted inode: %lu", inode->ino);
		err = ENOENT;
		goto out;
	}

	ccow_t tc;

	err = tc_pool_get_tc(inode->ci->tc_pool_handle, inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
		    err);
		goto out;
	}

	err = __encode_dir_attrs(inode, &encoded_attrs, &encoded_attrs_len);
	if (err)
		goto out;

	assert(encoded_attrs && encoded_attrs_len);
	iov[0].iov_base = FSIO_DIR_ENCODED_ATTR;
	iov[0].iov_len = strlen(FSIO_DIR_ENCODED_ATTR) + 1;
	iov[1].iov_base = encoded_attrs;
	iov[1].iov_len = encoded_attrs_len;

	/*
	 * We insert the FSIO_DIR_ENCODED_ATTR key evertime we set attrs.
	 * * Allow overwrite for this key
	 */
	err = ccow_sharded_list_put_v2(tc, inode->ci->bid, inode->ci->bid_size,
	    inode->dir_list_context, iov,
	    2, CCOW_CONT_F_INSERT_LIST_OVERWRITE);
	if (err) {
		log_error(fsio_lg, "%s ccow_sharded_list_put_v2 gave err: %d",
		    __func__, err);
		goto out;
	}

	/*
	 * set attr should not change link count, size and blocks used for directory.
	 */
out:
	if (encoded_attrs)
		je_free(encoded_attrs);

	if (err && (err != ENOENT))
		log_error(fsio_lg,
		    "%s failed for bucket: %s inode: %lu err: %d", __func__,
		    inode->ci->bid, inode->ino, err);

	log_debug(fsio_lg, "completed %s for inode: %lu", __func__,
	    inode->ino);
	return err;
}

int
ccow_fsio_dir_context_create(ccowfs_inode * inode)
{
	int err = 0;

	log_trace(fsio_lg, "%s for inode: %lu", __func__, inode->ino);

	assert(inode->oid != NULL);
	assert(inode->dir_list_context == NULL);

	err = ccow_shard_context_create(inode->oid, inode->oid_size,
	    FSIO_DIR_SHARD_COUNT, &inode->dir_list_context);
	if (err) {
		log_error(fsio_lg, "ccow_shard_context_create return error %d",
		    err);
		goto out;
	}

	/*
	 * Attributes are always overwritten but the directory entries cannot
	 * be overwritten.
	 */
	ccow_shard_context_set_overwrite(inode->dir_list_context, 0);

	/*
	 * Directories are eventual in our model if X-MH-ImmDir == 0 (default).
	 */
	if (ccow_mh_immdir == 0) {
		log_trace(fsio_lg, "%s context set eventual", __func__);
		ccow_shard_context_set_eventual(inode->dir_list_context, 1);
	}

out:
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);
	return err;
}

int
ccow_fsio_dir_create(ccowfs_inode * inode)
{
	int err = 0;
	struct timespec time;
	ccow_completion_t c;

	log_trace(fsio_lg, "%s for inode: %lu", __func__, inode->ino);

	assert(inode->dir_list_context);
	ccow_t tc;

	err = tc_pool_get_tc(inode->ci->tc_pool_handle, inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
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

	err = __set_times(inode,
	    FSIO_DIR_ATIME_FLAG | FSIO_DIR_MTIME_FLAG | FSIO_DIR_CTIME_FLAG, 1);
	if (err) {
		log_error(fsio_lg, "%s __set_times gave err: %d",
		    __func__, err);
		goto out;
	}

	err = __init_default_attributes(inode);
	if (err) {
		log_error(fsio_lg, "%s __init_default_attributes gave err: %d",
		    __func__, err);
		goto out;
	}

out:
	if (err) {
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    inode->ci->bid, inode->ino, err);

		if (inode->dir_list_context) {
			ccow_sharded_list_destroy(tc, inode->ci->bid,
			    inode->ci->bid_size, inode->dir_list_context);
			ccow_shard_context_destroy(&inode->dir_list_context);
			inode->dir_list_context = NULL;
		}
	}

	log_debug(fsio_lg, "completed inode: %lu", inode->ino);
	return err;
}

int
ccow_fsio_dir_delete(ccowfs_inode * inode)
{
	int err = 0;

	log_trace(fsio_lg, "%s inode: %lu", __func__, inode->ino);

	assert(atomic_get_uint64(&inode->deleted));

	ccow_t tc;

	err = tc_pool_get_tc(inode->ci->tc_pool_handle, inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
		    err);
		goto out;
	}
	if (inode->dir_list_context) {
		ccow_sharded_list_delete(tc, inode->ci->bid,
		    inode->ci->bid_size, inode->dir_list_context, ".",
		    strlen(".") + 1);
		ccow_sharded_list_destroy(tc, inode->ci->bid,
		    inode->ci->bid_size, inode->dir_list_context);
		log_debug(fsio_lg,
		    "ccow_shard_context_destroy dir_list for dir %ju",
		    inode->ino);
		ccow_shard_context_destroy(&inode->dir_list_context);
		inode->dir_list_context = NULL;
	}

	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

out:
	return err;
}

int
ccow_fsio_dir_is_empty(ccowfs_inode * inode)
{
	int is_empty = 0;

	log_trace(fsio_lg, "%s inode: %lu", __func__, inode->ino);

	ccowfs_inode_lock(inode);

	is_empty = __is_dir_empty(inode);

	ccowfs_inode_unlock(inode);

	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

	return is_empty;
}

int
ccow_fsio_dir_mark_deleted(ccowfs_inode * inode)
{
	int err = 0;

	log_trace(fsio_lg, "%s inode: %lu", __func__, inode->ino);

	ccowfs_inode_lock(inode);

	log_debug(fsio_lg, "Marking dir %ju as deleted", inode->ino);

	ccowfs_inode_mark_deleted(inode);

	ccowfs_inode_unlock(inode);
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

	return err;
}

int
ccow_fsio_dir_if_empty_mark_deleted(ccowfs_inode * inode)
{
	int err = 0;

	log_trace(fsio_lg, "%s inode: %lu", __func__, inode->ino);

	ccowfs_inode_lock(inode);

	if (!__is_dir_empty(inode)) {
		log_debug(fsio_lg,
		    "Marking dir %ju as deleted failed as ENOTEMPTY",
		    inode->ino);
		err = ENOTEMPTY;
		goto out;
	}

	log_debug(fsio_lg, "Marking dir %ju as deleted", inode->ino);

	ccowfs_inode_mark_deleted(inode);

out:
	ccowfs_inode_unlock(inode);
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);

	return err;
}

int
ccow_fsio_dir_add_entry(ci_t * ci, ccowfs_inode * parent_inode,
    char *name, ccowfs_inode * child_inode, int link_add)
{
	int err = 0;
	struct iovec iov[2];
	nfs_directory_table_attrs attrs;
	void *encoded_attrs = NULL;
	size_t encoded_attrs_len = 0;
	int link_delta = abs(link_add);

	log_trace(fsio_lg, "bucket: %s, parent_inode: %lu, "
	    "name: %s, child_inode: %lu, link_add: %d",
	    ci->bid, parent_inode->ino, name, child_inode->ino, link_add);

	ccow_t tc;

	err = tc_pool_get_tc(ci->tc_pool_handle, parent_inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
		    err);
		goto out_nolock;
	}

	ccowfs_inode_lock_shared(parent_inode);
	if (parent_inode->deleted) {
		log_debug(fsio_lg, "Already deleted inode: %lu", parent_inode->ino);
		err = ENOENT;
		goto out;
	}

	attrs.ver = 3;
	attrs.ino = child_inode->ino;
	err = encode_nfs_attrs(&attrs, &encoded_attrs, &encoded_attrs_len);
	if (err) {
		log_error(fsio_lg, "encode_nfs_attrs failed. err: %d", err);
		goto out;
	}

	iov[0].iov_base = name;
	iov[0].iov_len = strlen(name) + 1;
	iov[1].iov_base = encoded_attrs;
	iov[1].iov_len = encoded_attrs_len;

	/* add entry always adds to size and link count */
	err = ccow_sharded_list_put_with_md(tc, ci->bid, ci->bid_size,
		parent_inode->dir_list_context,
		parent_inode->oid, parent_inode->oid_size,
		name, strlen(name) + 1,
		iov, 2, ENTRY_SIZE, link_delta, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_sharded_list_put_with_md fail for "
		    "Add entry: %s to dir:%lu", name, parent_inode->ino);

		if (err == EEXIST || err == -EEXIST) {
			inode_t tmp_ino = 0;
			int err1 = ccow_fsio_dir_lookup(ci, parent_inode, name, &tmp_ino);
			log_debug(fsio_lg,
				"ccow_fsio_dir_lookup found name :%s with ino:%lu with err: %d",
				name, tmp_ino, err1);
			if (err1 != 0)
				goto out;
		} else
			goto out;
	}

	atomic_add64((unsigned long *) &(parent_inode->stat.st_size),
	    ENTRY_SIZE);

	log_debug(fsio_lg, "ADD inode: %lu new dir_size: %lu",
		parent_inode->ino, parent_inode->stat.st_size);

	if (link_delta > 0) {
		atomic_add64(&(parent_inode->stat.st_nlink), link_delta);
		log_debug(fsio_lg, "ADD inode: %lu new st_nlink: %lu",
			parent_inode->ino, atomic_get_uint64(&parent_inode->stat.st_nlink));
	}

	err = __set_times(parent_inode, FSIO_DIR_MTIME_FLAG |
	    FSIO_DIR_CTIME_FLAG, 0);

out:
	ccowfs_inode_unlock_shared(parent_inode);

out_nolock:
	if (encoded_attrs)
		je_free(encoded_attrs);

	if (err) {
		ci->ccow_err = err;

		if (err == -EEXIST || err == -EFAULT)
			err = EEXIST;
		else {
			log_error(fsio_lg, "failed for bucket: %s inode: %lu "
			    "name: %s err: %d", ci->bid, parent_inode->ino,
			    name, err);
		}
	}

	log_debug(fsio_lg,
	    "completed bucket: %s, parent_inode: %lu, name: %s, "
	    "child_inode: %lu", ci->bid, parent_inode->ino, name,
	    child_inode->ino);
	return err;
}

int
ccow_fsio_dir_remove_entry(ci_t * ci, ccowfs_inode * parent_inode,
    char *name, int link_subtract)
{
	int err = 0;
	int link_delta = abs(link_subtract);

	log_trace(fsio_lg, "Bucket: %s Remove entry: %s from dir: %lu, "
	    "link_subtract: %d", ci->bid, name, parent_inode->ino, link_subtract);

	ccow_t tc;

	err = tc_pool_get_tc(ci->tc_pool_handle, parent_inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
		    err);
		goto out_nolock;
	}

	ccowfs_inode_lock_shared(parent_inode);
	if (parent_inode->deleted) {
		log_debug(fsio_lg, "Already deleted inode: %lu", parent_inode->ino);
		err = ENOENT;
		goto out;
	}

	/* remove entry always subtracts from size and link count */
	err = ccow_sharded_list_delete_with_md(tc, ci->bid, ci->bid_size,
	    parent_inode->dir_list_context, parent_inode->oid, parent_inode->oid_size,
	    name, strlen(name) + 1, -1 * ENTRY_SIZE, -1 * link_delta, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_sharded_list_delete_with_md fail");
		goto out;
	}

	atomic_sub64((unsigned long *) &(parent_inode->stat.st_size),
	    ENTRY_SIZE);

	log_debug(fsio_lg, "SUB inode: %lu new dir_size: %lu",
		parent_inode->ino, parent_inode->stat.st_size);

	if (link_delta > 0) {
		atomic_sub64(&(parent_inode->stat.st_nlink), link_delta);
		log_debug(fsio_lg, "SUB inode: %lu new st_nlink: %lu",
			parent_inode->ino, atomic_get_uint64(&parent_inode->stat.st_nlink));
	}

	err =
	    __set_times(parent_inode,
		FSIO_DIR_MTIME_FLAG | FSIO_DIR_CTIME_FLAG, 0);

out:
	ccowfs_inode_unlock_shared(parent_inode);

out_nolock:
	if (err) {
		ci->ccow_err = err;
		if (err == -ENOENT)
			err = ENOENT;
		else {
			log_error(fsio_lg, "failed for bucket: %s inode: %lu "
			    "name: %s err: %d", ci->bid, parent_inode->ino,
			    name, err);
		}
	}

	log_debug(fsio_lg, "completed bucket: %s, parent_inode: %lu, name: %s",
	    ci->bid, parent_inode->ino, name);
	return err;
}

int
ccow_fsio_dir_lookup(ci_t * ci, ccowfs_inode * parent_inode, char *name,
    inode_t * out_ino)
{
	int err = 0;
	struct iovec iov[1] = { 0 };
	inode_t ino;

	log_trace(fsio_lg, "Lookup: bucket: %s name: %s in dir: %lu",
	    ci->bid, name, parent_inode->ino);

	ccow_t tc;

	err = tc_pool_get_tc(ci->tc_pool_handle, parent_inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
		    err);
		goto out;
	}

	ccowfs_inode_lock_shared(parent_inode);
	if (parent_inode->deleted) {
		log_debug(fsio_lg, "Already deleted inode: %lu", parent_inode->ino);
		err = ENOENT;
		goto out;
	}

	if (!parent_inode->dir_list_context) {
		log_warn(fsio_lg, "parent_inode dir_list_context is not loaded yet");
		err = ENOENT;
		goto out;
	}

	err = ccow_sharded_list_get(tc, ci->bid, ci->bid_size,
	    parent_inode->dir_list_context, name, strlen(name) + 1, iov, 1);
	if (err) {
		if (err == -ENOENT)
			err = ENOENT;
		if (err != ENOENT) {
			log_error(fsio_lg,
			    "ccow_sharded_list_get return error %d for dir: %lu name: %s",
			    err, parent_inode->ino, name);
		}
		goto out;
	}

	err = __set_times(parent_inode, FSIO_DIR_ATIME_FLAG, 0);
	if (err) {
		log_error(fsio_lg, "__set_times return error %d", err);
		goto out;
	}

	if (iov->iov_base) {
		if (!strcmp(".", iov->iov_base)) {
			*out_ino = parent_inode->ino;
		} else {
			err =
			    parse_nfs_inode(iov->iov_base, iov->iov_len,
			    out_ino);
			if (err) {
				log_error(fsio_lg,
				    "parse_nfs_inode return error %d", err);
				goto out;
			}
		}
	} else
		err = ENOENT;

out:
	ccowfs_inode_unlock_shared(parent_inode);
	if (iov->iov_base)
		je_free(iov->iov_base);

	if (err) {
		if (err == -ENOENT || err == ENOENT)
			err = ENOENT;
		else {
			ci->ccow_err = err;
			log_error(fsio_lg, "failed for bucket: %s inode: %lu "
			    "name: %s err: %d", ci->bid, parent_inode->ino,
			    name, err);
		}
	}

	log_debug(fsio_lg,
	    "completed bucket: %s, parent_inode: %lu, name: %s, "
	    "out_ino: %lu", ci->bid, parent_inode->ino, name, *out_ino);
	return err;
}

static int
__update_parent(ccowfs_inode * child_inode, ccowfs_inode * oldparent_inode,
    ccowfs_inode * newparent_inode)
{
	int err = 0;

	log_trace(fsio_lg, "child_inode %lu, oldparent_inode %lu, "
	    "newparent_inode %lu", child_inode->ino, oldparent_inode->ino,
	    newparent_inode->ino);

	ccowfs_inode_lock_shared(child_inode);

	err = ccow_fsio_dir_remove_entry(child_inode->ci, child_inode, "..", 0);
	if (err) {
		log_error(fsio_lg,
		    "ccow_fsio_dir_remove_entry return error %d", err);
		goto out;
	}

	err = ccow_fsio_dir_add_entry(child_inode->ci, child_inode, "..",
	    newparent_inode, 0);
	if (err) {
		log_error(fsio_lg, "ccow_fsio_dir_add_entry return error %d",
		    err);
		goto out;
	}
out:
	ccowfs_inode_unlock_shared(child_inode);
	if (err) {
		/*
		 * Possible FS inconsistency
		 */
		log_error(fsio_lg,
		    "failed for bucket: %s inode: %lu err: %d",
		    child_inode->ci->bid, child_inode->ino, err);
	}

	log_debug(fsio_lg, "completed child_inode %lu, oldparent_inode %lu, "
	    "newparent_inode %lu", child_inode->ino, oldparent_inode->ino,
	    newparent_inode->ino);

	return err;
}

int
ccow_fsio_dir_move(ci_t * ci, ccowfs_inode * oldparent_inode, char *oldname,
    ccowfs_inode * newparent_inode, char *newname)
{
	inode_t child_ino;
	inode_t destination_ino;
	ccowfs_inode *destination_inode = NULL;
	ccowfs_inode *child_inode = NULL;
	int err = 0, err1 = 0, parent_link_update = 0;

	log_trace(fsio_lg,
	    "Move: Bucket: %s dir: %lu name: %s to dir: %lu name: %s", ci->bid,
	    oldparent_inode->ino, oldname, newparent_inode->ino, newname);

	ccowfs_inode_lock_shared(oldparent_inode);
	ccowfs_inode_lock_shared(newparent_inode);

	err = ccow_fsio_dir_lookup(ci, oldparent_inode, oldname, &child_ino);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_fsio_dir_lookup failed");
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, child_ino, &child_inode);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_get_by_ino return error %d",
		    err);
		goto out;
	}

	if (child_inode->snap_count != 0) {
		/*
		 * Not allowed to delete file which has active snapshots
		 */
		err = EPERM;
		log_softerror(fsio_lg, err, "%s has active snapshots", oldname);
		goto out;
	}

	/*
	 * If newname is present and is file - delete it
	 */
	err = ccow_fsio_dir_lookup(ci, newparent_inode, newname,
	    &destination_ino);
	if (!err) {
		/*
		 * Namespace entry present at destination. If it is not dir
		 * then delete it.
		 */
		if (INODE_IS_DISK_DIR(destination_ino)) {
			err = EEXIST;
			goto out;
		} else {
			err = ccowfs_inode_get_by_ino(ci, destination_ino,
			    &destination_inode);
			if (err) {
				log_error(fsio_lg,
				    "ccowfs_inode_get_by_ino return error %d",
				    err);
				goto out;
			}

			if (destination_inode->snap_count != 0) {
				/*
				 * Not allowed to delete file which has active
				 * snapshots
				 */
				err = EPERM;
				log_softerror(fsio_lg, err, "%s has active snapshots",
				    oldname);
				goto out;
			}

			/* Add inode to the recovery table for delete */
			err = ccowfs_recovery_insert_deleted(destination_inode,
			    newparent_inode, newname);
			if (err) {
				log_error(fsio_lg,
				    "ccowfs_recovery_insert_deleted return "
				    "error %d", err);
				goto out;
			}

			err = ccow_fsio_dir_remove_entry(ci, newparent_inode,
			    newname, 0);
			if (err) {
				log_error(fsio_lg,
				    "ccow_fsio_dir_remove_entry return error %d",
				    err);
				goto out;
			}

			err = ccowfs_inode_unlink(destination_inode);
			if (err) {
				log_error(fsio_lg,
				    "ccowfs_inode_unlink return error %d",
				    err);
				goto out;
			}

			ccowfs_inode_put(destination_inode);
			destination_inode = NULL;
		}
	}

	/*
	 * If oldname is dir and we are changing parents
	 */
	if (oldparent_inode->ino != newparent_inode->ino &&
	    INODE_IS_DISK_DIR(child_ino))
		parent_link_update = 1;

	/* add inode to the recovery table in case ganesha aborts mid move */
	err = ccowfs_recovery_insert_moved(child_inode, oldparent_inode,
		oldname, newparent_inode, newname);

	if (err) {
		log_error(fsio_lg,
		    "ccowfs_recovery_insert_moved return error %d", err);
		goto out;
	}

	/*
	 * delete the namespace entry, drop the link count for old parent if needed
	 */
	err = ccow_fsio_dir_remove_entry(ci, oldparent_inode, oldname,
	    parent_link_update);
	if (err) {
		log_error(fsio_lg,
		    "ccow_fsio_dir_remove_entry return error %d", err);
		goto out;
	}

	/*
	 * oldname is dir and we are changing parents, update the ".." entry
	 */
	if (parent_link_update) {
		err = __update_parent(child_inode, oldparent_inode,
		    newparent_inode);
		if (err) {
			log_error(fsio_lg, "__update_parent return error %d",
			    err);
			goto out;
		}
	}

	/*
	 * namespace addition, add to the link count if needed
	 */
	err = ccow_fsio_dir_add_entry(ci, newparent_inode, newname,
	    child_inode, parent_link_update);
	if (err) {
		log_error(fsio_lg, "ccow_fsio_dir_add_entry return error %d",
		    err);
		goto out;
	}

	/* remove from the recovery table */
	err1 = ccowfs_recovery_remove(child_inode);
	if (err1) {
		log_softerror(fsio_lg, err1, "ccowfs_recovery_remove failed for "
		    "inode: %lu", child_inode->ino);
	}
out:
	if (err && (err != ENOENT)) {
		log_error(fsio_lg, "failed for bucket: %s inode: %lu name: %s"
		    " inode: %lu name:%s err: %d", ci->bid,
		    oldparent_inode->ino, oldname, newparent_inode->ino,
		    newname, err);
	}

	if (destination_inode)
		ccowfs_inode_put(destination_inode);

	if (child_inode)
		ccowfs_inode_put(child_inode);

	ccowfs_inode_unlock_shared(oldparent_inode);
	ccowfs_inode_unlock_shared(newparent_inode);

	log_debug(fsio_lg,
	    "Completed Move: Bucket: %s dir: %lu name: %s to dir: %lu name: %s done "
	    "with error: %d", ci->bid, oldparent_inode->ino, oldname,
	    newparent_inode->ino, newname, err);

	return err;
}

int
ccow_fsio_dir_readdir_cb4(ci_t * ci, inode_t parent_ino, char *start,
    ccow_fsio_readdir_cb4_t cb, void *ptr, bool *eofptr)
{
	int err = 0;
	ccowfs_inode *parent_inode = NULL;
	fsio_dir_entry *dir_entry = NULL;
	char marker[MAX_NAME_LEN];
	char last_marker[MAX_NAME_LEN];
	int eof = 0;
	inode_t child_ino;
	struct iovec iov[1] = { 0 };

	log_trace(fsio_lg, "readdir Bucket: %s, parent_inode: %lu start %s",
	    ci->bid, parent_ino, (start ? start : ""));

	DEBUG_START_CALL(ci, READDIR_CB4);

	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_get_by_ino return error %d",
		    err);
		goto out;
	}

	dir_entry =
	    je_calloc(1,
	    (MAX_READIR_ENTRIES_AT_A_TIME + 16) * sizeof(fsio_dir_entry));
	if (!dir_entry) {
		err = ENOMEM;
		goto out;
	}

	/*
	 * Set the first marker ee empty string
	 */
	strcpy(marker, "");

	if (start) {
		strcpy(marker, start);
		log_trace(fsio_lg, "Start from %s", marker);
	}
	strcpy(last_marker, marker);

	ccow_t tc;

	err = tc_pool_get_tc(ci->tc_pool_handle, parent_ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
		    err);
		goto out;
	}

	ccowfs_inode_lock_shared(parent_inode);

	while (err == 0 && !eof) {
		int read_count = 0;
		struct ccow_metadata_kv *kv = NULL;
		ccow_lookup_t iter = NULL;
		int pos = 0;
		int dot_found = 0;

		memset(dir_entry, 0,
		    MAX_READIR_ENTRIES_AT_A_TIME * sizeof(fsio_dir_entry));

		log_debug(fsio_lg, "search from marker %s", marker);

		err = ccow_sharded_get_list(tc, parent_inode->ci->bid,
		    parent_inode->ci->bid_size,
		    parent_inode->dir_list_context,
		    marker, strlen(marker) + 1,
		    NULL, MAX_READIR_ENTRIES_AT_A_TIME, &iter);
		if (err) {
			log_error(fsio_lg,
			    "ccow_sharded_list_get return error %d", err);
		}

		if (iter != NULL) {
			while ((kv =
				ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
				    pos++)) != NULL && read_count < MAX_READIR_ENTRIES_AT_A_TIME) {

				if (kv->value == NULL || kv->key == NULL) {
					continue;
				}

				/*
				 * Update the marker with the last entry read
				 */
				strncpy(marker, kv->key, MAX_NAME_LEN);

				if (strcmp(kv->key, last_marker) <= 0)
					continue;

				if (!dot_found
				    && (!strcmp(".", (char *) kv->key))) {
					child_ino = parent_ino;
					dot_found = 1;
				} else {
					err =
					    parse_nfs_inode(kv->value,
					    kv->value_size, &child_ino);
					if (err) {
						log_error(fsio_lg,
						    "parse_nfs_inode return error %d",
						    err);
						ccow_lookup_release(iter);
						goto out;
					}
				}

				log_debug(fsio_lg, "dir key: %s child_ino %lu",
				    kv->key, child_ino);

				dir_entry[read_count].name =
				    je_strdup(kv->key);
				dir_entry[read_count].inode = child_ino;
				read_count++;

				/*
				 * Fetch the inode in cache if not present already.
				 * We don't pass out_inode. So we don't take any ref on the inode.
				 * inode fetch from the disk will be triggered in async mode.
				 * This is done to speedup the possible lookup on this inode.
				 */
				ccowfs_inode_get_by_ino(ci, child_ino, NULL);

				/*
				 * Don't check the error here.
				 * We cannot fail the readdir at this point.
				 * If there is some real error, it will fail at time of lookup.
				 * If fetching inode fails at this time, it will happen during lookup.
				 */

			}
			ccow_lookup_release(iter);
			iter = NULL;

			eof = (strcmp(last_marker, marker) == 0);
			strcpy(last_marker, marker);
			if (eof) {
				for (int i = 0; i < read_count; i++) {
					je_free(dir_entry[i].name);
					dir_entry[i].name = NULL;
					dir_entry[i].inode = 0;
				}
				break;
			}

			if (read_count) {
				log_debug(fsio_lg, "calling cb: parent_ino %lu read_count %d",
				    parent_ino, read_count);

				int rc = cb(parent_ino, dir_entry, read_count, ptr);

				for (int i = 0; i < read_count; i++) {
					je_free(dir_entry[i].name);
					dir_entry[i].name = NULL;
					dir_entry[i].inode = 0;
				}

				if (rc != 0) {
					log_debug(fsio_lg, "calling cb: rc = %d", rc);
					break;
				}
			}
		}
	}

	if (!err)
		*eofptr = (bool)eof;

out:
	if (dir_entry)
		je_free(dir_entry);

	if (parent_inode) {
		__set_times(parent_inode, FSIO_DIR_ATIME_FLAG, 0);
		ccowfs_inode_unlock_shared(parent_inode);
		ccowfs_inode_put(parent_inode);
	}

	if (err) {
		ci->ccow_err = err;
		if (err != ENOENT)
			log_error(fsio_lg,
			    "failed for bucket: %s inode: %lu err: %d",
			    ci->bid, parent_ino, err);

		if (err == -ENOENT || err == ENOENT)
			err = ENOENT;
	}
	DEBUG_END_CALL(ci, READDIR_CB4, err);

	log_debug(fsio_lg,
	    "completed readdir Bucket: %s, parent_inode: %lu with err: %d eof: %d",
	    ci->bid, parent_inode->ino, err, *eofptr);
	return err;
}

int
ccow_fsio_add_list_cache(ci_t * ci, inode_t parent, inode_t child, char *name)
{
	if (!ci) {
		return -EINVAL;
	}
	if (!ci->fsio_list_cache.fsio_list_cache_entry_ht) {
		return -ENOMEM;
	}

	fsio_list_cache_entry_t fsio_list_cache_entry;
	int err = fsio_list_cache_entry_init(&fsio_list_cache_entry, parent, child, name);
	if (err) {
		return err;
	}

	err = fsio_list_cache_put(&ci->fsio_list_cache, &fsio_list_cache_entry);
	return err;
}

int
ccow_fsio_dir_find(ci_t * ci, inode_t parent_ino, inode_t ino, char *res, int res_max)
{
	int err = 0;
	ccowfs_inode *parent_inode = NULL;
	char marker[MAX_NAME_LEN];
	char last_marker[MAX_NAME_LEN];
	int eof = 0;
	int res_found = 0;
	inode_t child_ino;
	struct iovec iov[1] = { 0 };

	log_trace(fsio_lg, "dir_find look in cluster bucket: %s, parent_inode: %lu",
	    ci->bid, parent_ino);

	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_get_by_ino return error %d",
		    err);
		goto out;
	}

	/*
	 * Set the first marker ee empty string
	 */
	strcpy(marker, "");
	strcpy(last_marker, marker);

	ccow_t tc;

	err = tc_pool_get_tc(ci->tc_pool_handle, parent_ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__,
		    err);
		goto out;
	}

	ccowfs_inode_lock_shared(parent_inode);

	while (err == 0 && !eof) {
		int read_count = 0;
		struct ccow_metadata_kv *kv = NULL;
		ccow_lookup_t iter = NULL;
		int pos = 0;
		int dot_found = 0;

		log_debug(fsio_lg, "search from marker %s", marker);

		err = ccow_sharded_get_list(tc, parent_inode->ci->bid,
		    parent_inode->ci->bid_size,
		    parent_inode->dir_list_context,
		    marker, strlen(marker) + 1,
		    NULL, MAX_READIR_ENTRIES_AT_A_TIME, &iter);
		if (err) {
			log_error(fsio_lg,
			    "ccow_sharded_list_get return error %d", err);
		}

		if (iter != NULL) {
			while ((kv =
				ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
				    pos++)) != NULL && read_count < MAX_READIR_ENTRIES_AT_A_TIME) {

				if (kv->value == NULL || kv->key == NULL) {
					continue;
				}

				/*
				 * Update the marker with the last entry read
				 */
				strncpy(marker, kv->key, MAX_NAME_LEN);

				if (strcmp(kv->key, last_marker) <= 0)
					continue;

				if (!dot_found
				    && (!strcmp(".", (char *) kv->key))) {
					child_ino = parent_ino;
					dot_found = 1;
				} else {
					err =
					    parse_nfs_inode(kv->value,
					    kv->value_size, &child_ino);
					if (err) {
						log_error(fsio_lg,
						    "parse_nfs_inode return error %d",
						    err);
						ccow_lookup_release(iter);
						goto out;
					}
				}

				if (ino == child_ino) {
					log_debug(fsio_lg, "found dir key: %s child_ino %lu",
						kv->key, child_ino);
					strncpy(res, kv->key, res_max);
					res_found = 1;
					break;
				}
				read_count++;
			}
			ccow_lookup_release(iter);
			iter = NULL;

			if (res_found)
				break;

			eof = (strcmp(last_marker, marker) == 0);
			strcpy(last_marker, marker);
			if (eof) {
				break;
			}
		}
	}

out:

	if (err) {
		ci->ccow_err = err;
		if (err != ENOENT)
			log_error(fsio_lg,
			    "find failed for bucket: %s parent inode: %lu err: %d",
			    ci->bid, parent_ino, err);

		if (err > 0)
			err = -err;
	}

	if (parent_inode) {
		__set_times(parent_inode, FSIO_DIR_ATIME_FLAG, 0);
		ccowfs_inode_unlock_shared(parent_inode);
		ccowfs_inode_put(parent_inode);
	}

	log_debug(fsio_lg,
	    "completed dir find bucket: %s, parent_inode: %lu with err: %d",
	    ci->bid, parent_inode->ino, err);
	return err;
}


int
testonly_dir_add_entry(ci_t *ci, inode_t parent_ino, char *name,
    inode_t child_ino, int link_count)
{
	ccowfs_inode *parent_inode = NULL;
	ccowfs_inode *child_inode = NULL;
	int err = 0;

	log_trace(fsio_lg, "ci: %p, parent_ino: %lu, "
	    "name: %s, child_ino: %lu, link_count: %d",
	    ci, parent_ino, name, child_ino, link_count);

	/* get parent */
	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return: %d for inode: %lu",
		    err, parent_ino);
		goto out;
	}

	/* get child */
	err = ccowfs_inode_get_by_ino(ci, child_ino, &child_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return: %d for inode: %lu",
		    err, child_ino);
		goto out;
	}

	ccowfs_namespace_inode_lock(parent_inode);

	err = ccow_fsio_dir_add_entry(ci, parent_inode, name, child_inode, link_count);
	if (err) {
		log_error(fsio_lg,
		    "ccow_fsio_dir_add_entry return: %d, parent_ino: %lu, name: %s, "
		    "child_ino: %lu, link_count: %d",
		    err, parent_ino, name, child_ino, link_count);
	}

	ccowfs_namespace_inode_unlock(parent_inode);

out:

	if (child_inode)
		ccowfs_inode_put(child_inode);
	if (parent_inode)
		ccowfs_inode_put(parent_inode);

	log_debug(fsio_lg, "ci: %p, parent_ino: %lu, "
	    "name: %s, child_ino: %lu, link_count: %d",
	    ci, parent_ino, name, child_ino, link_count);

	return err;
}

int
testonly_dir_remove_entry(ci_t *ci, inode_t parent_ino, char *name, int link_count)
{
	ccowfs_inode *parent_inode = NULL;
	int err = 0;

	log_trace(fsio_lg, "ci: %p, parent_ino: %lu, name: %s, link_count: %d",
	    ci, parent_ino, name, link_count);

	/* get parent */
	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return: %d for inode: %lu",
		    err, parent_ino);
		goto out;
	}

	ccowfs_namespace_inode_lock(parent_inode);

	err = ccow_fsio_dir_remove_entry(ci, parent_inode, name, link_count);
	if (err) {
		log_error(fsio_lg,
		    "ccow_fsio_dir_remove_entry return: %d, parent_ino: %lu, name %s, "
		    "link_count: %d", err, parent_ino, name, link_count);
	}

	ccowfs_namespace_inode_unlock(parent_inode);

out:

	if (parent_inode)
		ccowfs_inode_put(parent_inode);

	log_debug(fsio_lg, "ci: %p, parent ino: %lu, name: %s, link_count: %d",
	    ci, parent_inode->ino, name, link_count);

	return err;
}
