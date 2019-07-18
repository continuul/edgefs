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

#include <ccow.h>
#include <ccowfsio.h>

#include "fsio_inode.h"
#include "fsio_cache.h"
#include "fsio_debug.h"
#include "fsio_system.h"
#include "fsio_common.h"
#include "fsio_file.h"
#include "tc_pool.h"

int
ccow_fsio_openi(ci_t *ci, inode_t ino, ccow_fsio_file_t **file, int openflags)
{
	ccow_fsio_file_t *f = NULL;
	ccowfs_inode *inode = NULL;
	int err = 0;

	log_trace(fsio_lg, "ci: %p, ino: %lu, f: %p, openflags: %d",
		ci, ino, f, openflags);

	DEBUG_START_CALL(ci, OPEN);

	f = (ccow_fsio_file_t *) je_calloc(sizeof(ccow_fsio_file_t), 1);
	if (f == NULL) {
		err = ENOMEM;
		goto out;
	}

	/* Take a ref on the inode. This must be relesed when we close the file. */
	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_softerror(fsio_lg, err,
		    "ccowfs_inode_get_by_ino fail");
		goto out;
	}

	if (inode->read_only && (openflags & (O_WRONLY | O_RDWR | O_APPEND))) {
		err = EPERM;
		goto out;
	}

	f->inode = (void *) inode;
	*file = f;

out:
	if (err) {
		if (err != ENOENT) {
			ci->ccow_err = err;
			log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
				ci->bid, ino, err);
		}
		if (inode)
			ccowfs_inode_put(inode);
		if (f)
			je_free(f);
		*file = NULL;
	}

	DEBUG_END_CALL(ci, OPEN, err);

	log_debug(fsio_lg, "completed ci: %p, ino: %lu, file: %p, openflags: %d",
	    ci, ino, file, openflags);

	return err;
}

int
ccow_fsio_open(ci_t * ci, char *path, ccow_fsio_file_t **file, int openflags)
{
	inode_t inode;
	int err;

	log_trace(fsio_lg, "ci: %p, path: \"%s\", file: %p, openflags: %d",
	    ci, path, file, openflags);

	err = ccow_fsio_find(ci, path, &inode);
	if (err) {
		if (err != ENOENT) {
			log_error(fsio_lg, "ccow_fsio_find failed for path: %s with err :%d",
				path, err);
		}
		return err;
	}

	err = ccow_fsio_openi(ci, inode, file, openflags);

	log_debug(fsio_lg, "completed ci: %p, path: \"%s\", file: %p, "
	    "openflags: %d", ci, path, file, openflags);

	return err;
}

int
ccow_fsio_close(ccow_fsio_file_t *file)
{
	ccowfs_inode *file_inode = NULL;
	int err = 0;
	ci_t *ci = NULL;
	inode_t ino;

	log_trace(fsio_lg, "file: %p", file);

	if (file == NULL) {
		err = EINVAL;
		log_error(fsio_lg, "Wrong argument");
		goto out;
	}

	file_inode = (ccowfs_inode *) file->inode;
	ci = file_inode->ci;
	ino = file_inode->ino;

	DEBUG_START_CALL(ci, CLOSE);

	err = ccowfs_inode_sync(file_inode, 0);
	if (err) {
		log_error(fsio_lg,  "ccowfs_inode_sync return %d", err);
		goto out;
	}

	/* Put the inode ref taken during open */
	ccowfs_inode_put(file_inode);

	if (file)
		je_free(file);

out:
	if (err && ci) {
		ci->ccow_err = err;
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    ci->bid, ino, err);
	}
	if (ci)
		DEBUG_END_CALL(ci, CLOSE, err);

	log_debug(fsio_lg, "completed file: %p", file);

	return (err);
}

int
ccow_fsio_read(ccow_fsio_file_t *file, size_t offset, size_t buffer_size,
    void *buffer, size_t *read_amount, int *eof)
{
	ccowfs_inode *file_inode = NULL;
	int err;

	log_trace(fsio_lg,"file: %p, offset: %lu, "
	    "buffer_size: %lu, buffer: %p, read_amount: %p, eof: %p",
		file, offset, buffer_size, buffer, read_amount, eof);

	memset(buffer, 0, buffer_size);
	*read_amount = 0;
	*eof = 0;

	if (file == NULL) {
		log_error(fsio_lg, "Wrong argument");
		return EINVAL;
	}
	file_inode = (ccowfs_inode *)file->inode;

	DEBUG_START_CALL(file_inode->ci, READ);
	err = fsio_buffer_cache_read(file_inode, offset, buffer_size,
			buffer, read_amount, eof);
	DEBUG_END_CALL(file_inode->ci, READ, err);

	if (err) {
		log_error(fsio_lg,
			"fsio_buffer_cache_read failed for inode: %lu with err: %d",
			file_inode->ino, err);
		goto out;
	}

	ccowfs_inode_lock(file_inode);
	ccowfs_inode_update_atime_locked(file_inode);
	ccowfs_inode_mark_dirty(file_inode);
	ccowfs_inode_unlock(file_inode);

out:
	log_debug(fsio_lg, "completed file: %p, offset: %lu, buffer_size: %lu, "
	    "buffer: %p, read_amount: %lu, eof: %d", file, offset, buffer_size,
	    buffer, *read_amount, *eof);

	return err;
}

int
ccow_fsio_write(ccow_fsio_file_t *file, size_t offset, size_t buffer_size,
    void *buffer, size_t *write_amount)
{
	int err;
	ccowfs_inode *file_inode;

    log_trace(fsio_lg, "file: %p, offset: %lu, "
        "buffer_size: %lu, buffer: %p, write_amount: %p", file, offset,
        buffer_size, buffer, write_amount);

	*write_amount = 0;

	if (file == NULL) {
		log_error(fsio_lg, "Wrong argument");
		err = EINVAL;
		goto out;
	}
	file_inode = (ccowfs_inode *) file->inode;

	if (file_inode->read_only) {
		err = EPERM;
		log_error(fsio_lg,  "Write for RDONLY inode: %lu err: %d",
			file_inode->ino, err);
		goto out;
	}

	err = fsio_buffer_cache_write(file_inode, offset, buffer_size, buffer);
	if (err) {
		log_error(fsio_lg,
			"fsio_buffer_cache_write failed for inode: %ju with err: %d",
			file_inode->ino, err);
		goto out;
	}
	*write_amount = buffer_size;

	ccowfs_inode_lock(file_inode);
	ccowfs_inode_mark_dirty(file_inode);
	ccowfs_inode_unlock(file_inode);

out:
    log_debug(fsio_lg, "completed file: %p, offset: %lu, buffer_size: %lu, "
        "buffer: %p, write_amount: %lu", file, offset, buffer_size, buffer,
        *write_amount);

	return err;
}

int
ccow_fsio_get_size(ccow_fsio_file_t * file, size_t * size)
{
	ccowfs_inode *file_inode;

	log_trace(fsio_lg, "file: %p, size: %p", file, size);

	file_inode = (ccowfs_inode *) file->inode;
	ccowfs_inode_get_size(file_inode, size);

	log_debug(fsio_lg, "completed file: %p, size: %p", file,
	    size);

	return 0;
}

int
ccow_fsio_flush(ccow_fsio_file_t * file)
{
	ccowfs_inode *file_inode;
	int err;

	log_trace(fsio_lg, "file: %p", file);

	file_inode = (ccowfs_inode *) file->inode;
	err = ccowfs_inode_sync(file_inode, 1);

	log_debug(fsio_lg, "completed file: %p", file);

	return err;
}

int
ccow_fsio_query_lock(ci_t * ci, inode_t ino, uint8_t lock_type,
			uint64_t off, uint64_t len,
			struct flock *flk)
{
	struct flock lk_query;
	uint8_t mode;
	uint64_t req_len;
	char ino_str[22];
	ccow_t tc;
	int err;

	/* Get tenant context */
	err = tc_pool_get_tc(ci->tc_pool_handle, ino, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		return err;
	}

	sprintf(ino_str, "%" PRIu64, (uint64_t)ino);
	/* This is a blocking call */
	err = ccow_get_posix_lock(tc, ci->bid, ci->bid_size,
				ino_str, strlen(ino_str) + 1,
				&lk_query, flk);
	log_debug(fsio_lg, "ccow_get_posix_lock fetch lock. err: %d", err);

	return err;
}

int
ccow_fsio_lock(ci_t * ci, inode_t ino, uint8_t mode,
		uint64_t off, uint64_t len)
{
	struct flock lk;
	ccow_t tc;
	char ino_str[22];
	int err;

	/* Get tenant context */
	err = tc_pool_get_tc(ci->tc_pool_handle, ino, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		return err;
	}

	sprintf(ino_str, "%" PRIu64, (uint64_t)ino);
	memset(&lk, 0, sizeof(lk));
	lk.l_type = mode;
	lk.l_start = off;
	lk.l_len = len;

	return ccow_set_posix_lock(tc, ci->bid, ci->bid_size,
			ino_str, strlen(ino_str) + 1, &lk);
}
