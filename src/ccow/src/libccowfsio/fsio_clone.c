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
#include <libgen.h>

#include <ccow.h>
#include <ccowfsio.h>

#include <fsio_system.h>
#include <fsio_common.h>
#include <fsio_inode.h>
#include <fsio_namespace.h>
#include <fsio_s3_transparency.h>

int
ccow_fsio_clone_file(char *cid, char *tid, char *src_bid, char *dest_bid,
    char *src_path, char *dest_path, uint32_t flags)
{
	int err = 0;
	inode_t src_parent, dest_parent;
	ci_t *src_ci = NULL;
	ci_t *dest_ci = NULL;

	char *src_path_dir = je_strdup(src_path);
	char *src_path_base = je_strdup(src_path);
	char *dest_path_dir = je_strdup(dest_path);
	char *dest_path_base = je_strdup(dest_path);

	char *src_parent_name = dirname(src_path_dir);
	char *dest_parent_name = dirname(dest_path_dir);
	char *src_name = basename(src_path_base);
	char *dest_name = basename(dest_path_base);

	log_trace(fsio_lg,"cid: \"%s\", tid: \"%s\", "
	    "src_bid: \"%s\", dest_bid: \"%s\", src_path: \"%s\", "
	    "dest_path: \"%s\", flags: %u", cid, tid, src_bid, dest_bid,
	    src_path, dest_path, flags);
	/*
	 * Cross-bucket operation, so we use common logger.
	 */
	err = ccow_fsio_find_export(cid, strlen(cid) + 1, tid, strlen(tid) + 1,
	    src_bid, strlen(src_bid) + 1, &src_ci);
	if (err) {
		log_error(fsio_lg,
		    "ccow_fsio_find_export return error %d", err);
		goto out;
	}

	err = ccow_fsio_find_export(cid, strlen(cid) + 1, tid, strlen(tid) + 1,
	    dest_bid, strlen(dest_bid) + 1, &dest_ci);
	if (err) {
		log_error(fsio_lg,
		    "ccow_fsio_find_export return error %d", err);
		goto out;
	}

	err = ccow_fsio_find(src_ci, src_parent_name, &src_parent);
	if (err) {
		log_error(fsio_lg, "ccow_fsio_find src return error %d",
		    err);
		goto out;
	}

	err = ccow_fsio_find(dest_ci, dest_parent_name, &dest_parent);
	if (err) {
		log_error(fsio_lg, "ccow_fsio_find dst return error %d",
		    err);
		goto out;
	}

	err = fsio_namespace_clone(src_ci, src_parent, src_name,
	    dest_ci, dest_parent, dest_name, flags);
	if (err) {
		log_error(fsio_lg, "ccow_fsio_find src return error %d",
		    err);
		goto out;
	}

	/*
	 * Invalidate the directory inode cache from Ganesha.
	 */
	if (dest_ci->up_cb) {
		err = dest_ci->up_cb(dest_ci->up_cb_args, dest_parent, 0);
		if (err) {
			log_error(fsio_lg,
			    "dest_ci->up_cb return error %d", err);
		}
	}

out:
	if (src_path_dir)
		je_free(src_path_dir);
	if (src_path_base)
		je_free(src_path_base);
	if (dest_path_dir)
		je_free(dest_path_dir);
	if (dest_path_base)
		je_free(dest_path_base);

	log_debug(fsio_lg,"completed cid: \"%s\", tid: \"%s\", "
	    "src_bid: \"%s\", dest_bid: \"%s\", src_path: \"%s\", "
	    "dest_path: \"%s\", flags: %u", cid, tid, src_bid, dest_bid,
	    src_path, dest_path, flags);

	return err;
}
