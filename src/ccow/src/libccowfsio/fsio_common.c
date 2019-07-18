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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <lfq.h>

#include <ccow.h>
#include <ccowfsio.h>

#include "replicast.h"

#include "fsio_flusher.h"
#include "fsio_s3_transparency.h"
#include "fsio_system.h"
#include "fsio_inode.h"
#include "fsio_common.h"
#include "tc_pool.h"

#define CREATE_COMPLETION_RETRY_COUNT 5

int
set_btree(ccow_completion_t c, ccow_lookup_t iter)
{
	int err,order;

	log_trace(fsio_lg,"c: %p, iter: %p", c, iter);
	/*
	 * NFS max name length is 255b. Reference Entry in CCOW Manifest is 84
	 * bytes. Value up to 256b. Additional metadata we will allow is up to 4K.
	 *
	 * This should be ~ 96*(255+84+256)+4096 = 61216 max and will fit into
	 * UDP datagram. Keep in mind that we currenty do not support messages
	 * larger then single UDP datagram. 
	 */
	order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_NFSDIR;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *) &order, NULL);

	if (err)
		return err;

	return ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *) "btree_key_val", iter);
}

int
parse_nfs_inode(void *value, uint64_t value_size, inode_t * ino)
{
	int err = 0;
	nfs_directory_table_attrs attrs;

	log_trace(fsio_lg,"value: %p, value_size: %lu, ino: %p",
	    value, value_size, ino);
	err = decode_nfs_attrs(value, value_size, &attrs);
	if (err) {
		log_error(fsio_lg,
		    "ccow_attr_modify_default return %d", err);
		goto out;
	}

	assert(attrs.ver == 3);
	*ino = attrs.ino;

out:
	log_debug(fsio_lg,"completed value: %p, value_size: %lu, "
	    "ino: %p", value, value_size, ino);
	return err;
}

int
ccow_fsio_is_dir(ci_t * ci, inode_t inode)
{
	struct stat stat;
	int err = 0;

	log_trace(fsio_lg,"ci: %p, inode: %lu", ci, inode);

	err = ccow_fsio_get_file_stat(ci, inode, &stat);
	if (err == ENOENT) {
		log_debug(fsio_lg, "ccow_fsio_get_file_stat return %d", err);
		err = 0;
		goto out;
	}
	if (err != 0) {
		log_error(fsio_lg, "ccow_fsio_get_file_stat return %d", err);
		err = 0;
		goto out;
	}
	if (S_ISDIR(stat.st_mode)) {
		log_debug(fsio_lg, "ci: %p, inode: %lu, return %d",
		    ci, inode, 1);
		err = 1;
	}

out:
	log_debug(fsio_lg,"completed ci: %p, inode: %lu", ci, inode);

	return (err);
}

void
ccow_fsio_free(ci_t * ci, void *obj)
{

	log_trace(fsio_lg,"ci: %p, obj: %p", ci, obj);

	je_free(obj);
}

int
ccow_fsio_err(ci_t * ci)
{
	int err;

	log_trace(fsio_lg,"ci: %p", ci);
	err = ci->ccow_err;

	log_debug(fsio_lg,"completed ci: %p", ci);
	return err;
}

int
list_remove(ccow_t tc, const char *cid, size_t cid_size,
    const char *tid, size_t tid_size,
    const char *bid, size_t bid_size, char *obj_name, char *key)
{
	int err = 0;
	ccow_completion_t c = NULL;
	struct iovec iov[1] = { 0 };

	log_trace(fsio_lg,"tc: %p, cid: %p, cid_size: %lu, "
	    "tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "obj_name: \"%s\", key: \"%s\"", tc, cid, cid_size, tid, tid_size,
	    bid, bid_size, obj_name, key);

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccow_create_completion return %d", err);
		goto out;
	}

	err = set_btree(c, NULL);
	if (err) {
		log_error(fsio_lg, "set_btree return %d", err);
		goto out;
	}

	iov[0].iov_base = key;
	iov[0].iov_len = strlen(key) + 1;

	err = ccow_container_update_list(cid, cid_size,
	    tid, tid_size,
	    bid, bid_size,
	    obj_name, strlen(obj_name) + 1, c, iov, 1, CCOW_DELETE_LIST);
	if (err) {
		log_error(fsio_lg,
		    "ccow_container_update_list return %d", err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err && err != -ENOENT) {
		log_error(fsio_lg, "ccow_wait return %d", err);
		goto out;
	}

	c = NULL;
out:
	if (c)
		ccow_release(c);

	if (err == -ENOENT || err == ENOENT)
		err = 0;

	log_debug(fsio_lg,"completed tc: %p, cid: %p, "
	    "cid_size: %lu, tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "obj_name: \"%s\", key: \"%s\"", tc, cid, cid_size, tid, tid_size,
	    bid, bid_size, obj_name, key);

	return err;
}

int
list_insert(ccow_t tc, const char *cid, size_t cid_size,
    const char *tid, size_t tid_size,
    const char *bid, size_t bid_size,
    char *obj_name, char *key, const char *value)
{
	int err = 0;
	ccow_completion_t c = NULL;
	struct iovec iov[2] = { {0}, {0} };
	char *val;

	log_trace(fsio_lg,"tc: %p, cid: %p, cid_size: %lu, tid: %p,"
	    " tid_size: %lu, bid: %p, bid_size: %lu, obj_name: \"%s\", "
	    "key: \"%s\", value: %p", tc, cid, cid_size, tid, tid_size, bid,
	    bid_size, obj_name, key, value);

	val = je_strdup(value);
	/*
	 * Insert the key value pair in the btree.
	 * * Ignore if the key is already present
	 */
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccow_fsio_get_file_stat return %d", err);
		goto out;
	}

	int c_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
	ccow_stream_flags(c, &c_flags);

	err = set_btree(c, NULL);
	if (err) {
		log_error(fsio_lg, "set_btree return %d", err);
		goto out;
	}

	iov[0].iov_base = key;
	iov[0].iov_len = strlen(key) + 1;
	iov[1].iov_base = val;
	iov[1].iov_len = strlen(value) + 1;

	/*
	 * Use SOP operation to add the server id 
	 */
	err = ccow_container_update_list(cid, cid_size, tid, tid_size, bid,
	    bid_size, obj_name, strlen(obj_name) + 1, c, iov, 2,
	    CCOW_INSERT_LIST);
	if (err) {
		log_error(fsio_lg,
		    "ccow_container_update_list return %d", err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_error(fsio_lg, "ccow_wait return %d", err);
		goto out;
	}

	c = NULL;
out:
	if (val)
		je_free(val);

	if (c)
		ccow_release(c);

	log_debug(fsio_lg,"completed tc: %p, cid: %p, "
	    "cid_size: %lu, tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "obj_name: \"%s\", key: \"%s\", value: %p", tc, cid, cid_size,
	    tid, tid_size, bid, bid_size, obj_name, key, value);

	return err;
}

int
ccowfs_create_completion(ci_t * ci, void *cb_arg, ccow_callback_t cb_complete,
    inode_t ino, ccow_completion_t * c)
{
	int err = 0;
	int retry_count = CREATE_COMPLETION_RETRY_COUNT;
	ccow_t tc;

	log_trace(fsio_lg, "ci: %p, cb_arg: %p, cb_complete: %p, c: %p", ci,
	    cb_arg, cb_complete, c);

	err = tc_pool_get_tc(ci->tc_pool_handle, ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}

	while (retry_count) {
		err = ccow_create_completion(tc, cb_arg, cb_complete, 1, c);
		if (err == -ENOSPC) {
			ccowfs_inode_flusher(ci, MEM_PRESSURE,
			    OOR_FLUSH_COUNT);
			sleep(3);
		} else
			break;
		retry_count--;
	}

	log_debug(fsio_lg, "completed ci: %p, cb_arg: %p, cb_complete: %p, "
	    "c: %p", ci, cb_arg, cb_complete, c);

out:
	return err;
}

int
ccowfs_create_stream_completion(ci_t *ci, char *oid, size_t oid_size,
    uint64_t *genid, uint64_t op_count, inode_t ino,
    ccow_completion_t *c, ccow_lookup_t *iter)
{
	int err = 0;
	int flags = CCOW_CONT_F_SKIP_TRLOG_UPDATE;
	int retry_count = CREATE_COMPLETION_RETRY_COUNT;
	ccow_t tc;

	log_trace(fsio_lg,"ci: %p, oid: \"%s\", oid_size: %lu, genid: %p, "
	    "op_count: %lu, c: %p", ci, oid, oid_size, genid, op_count, c);

	err = tc_pool_get_tc(ci->tc_pool_handle, ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}

	while (retry_count) {
		err = ccow_create_stream_completion(tc, NULL, NULL,
		    op_count, c,
		    ci->bid, strlen(ci->bid) + 1,
		    oid, oid_size, genid, &flags, iter);
		if (err == -ENOSPC) {
			ccowfs_inode_flusher(ci, MEM_PRESSURE,
			    OOR_FLUSH_COUNT);
			sleep(3);
		} else
			break;
		retry_count--;
	}

	log_debug(fsio_lg,"completed ci: %p, oid: \"%s\", oid_size: %lu, genid: %p, "
	    "op_count: %lu, c: %p", ci, oid, oid_size, genid, op_count, c);
out:
	return err;
}

