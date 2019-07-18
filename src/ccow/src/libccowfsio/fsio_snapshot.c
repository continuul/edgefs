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
#include <stdio.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <unistd.h>

#include <ccow.h>
#include <ccowfsio.h>
#include "fsio_inode.h"
#include "fsio_system.h"
#include "fsio_snapshot.h"
#include "tc_pool.h"

static int
__get_system_snap_name(char *path, char *user_snap_name,
    char **system_snap_name)
{
	/*
	 * Use the snapshot name as: "file_path\nuser_snap_name"
	 */
	int err = 0;
	char *name = NULL;
	int sz;

	log_trace(fsio_lg, "path: \"%s\", user_snap_name: \"%s\", "
	    "system_snap_name: %p", path, user_snap_name, system_snap_name);

	sz = strlen(path) + 1 + strlen(user_snap_name) + 1;

	name = (char *) je_calloc(1, sz);
	if (name == NULL) {
		log_error(fsio_lg, "Failed to allocate memory");
		err = ENOMEM;
		goto out;
	}

	snprintf(name, sz, "%s\n%s", path, user_snap_name);

out:
	*system_snap_name = name;

	log_debug(fsio_lg, "completed path: \"%s\", "
	    "user_snap_name: \"%s\", *system_snap_name: %p", path,
	    user_snap_name, system_snap_name);

	return err;
}

static int
__get_user_snap_name(char *system_snap_name, char **user_snap_name)
{
	int err = 0;
	char *c = NULL;

	log_trace(fsio_lg, "system_snap_name: \"%s\", "
	    "user_snap_name: %p", system_snap_name, user_snap_name);
	/*
	 * The system snap name is of the format : "path\nuser_snap_name\n"
	 * * Parse it to get the nuser_snap_name
	 */
	for (c = system_snap_name; *c != '\0'; c++) {
		if (*c == '\n')
			break;
	}

	*user_snap_name = je_strdup(c + 1);
	if (*user_snap_name == NULL) {
		log_error(fsio_lg, "Failed to allocate memory");
		err = ENOMEM;
		goto out;
	}

out:
	log_debug(fsio_lg, "completed system_snap_name: \"%s\", "
	    "user_snap_name: %p", system_snap_name, user_snap_name);

	return err;
}

static int
__is_snapshot_present(ci_t * ci, char *path, char *system_snap_name)
{
	int err;
	struct ccow_metadata_kv *kv = NULL;
	ccow_lookup_t iter = NULL;

	log_trace(fsio_lg, "ci: %p, path: \"%s\", system_snap_name: \"%s\"",
	    ci, path, system_snap_name);

	ccow_t tc;
	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}

	err = ccow_snapshot_lookup(tc, ci->sv_handle,
	    system_snap_name, strlen(system_snap_name) + 1, 1, &iter);
	if (err) {
		log_softerror(fsio_lg, err,
		    "ccow_snapshot_lookup failed");
		goto out;
	}

	assert(iter != NULL);

	kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, 0);
	if (kv->type == CCOW_KVTYPE_RAW && !strcmp(kv->key, system_snap_name)) {
		/*
		 * Snapshot with exact name is present
		 */
		err = 0;
		goto out;
	}
	err = ENOENT;
	log_debug(fsio_lg, "item not found");

out:
	log_debug(fsio_lg, "completed ci: %p, path: \"%s\", "
	    "system_snap_name: \"%s\"", ci, path, system_snap_name);

	return err;
}

int
fsio_snapshot_init(ci_t * ci)
{
	int err;

	log_trace(fsio_lg, "ci: %p", ci);
	/*
	 * Populate ci->sv_handle.
	 * * Create the SNAPVIEW object for the export if not present already.
	 */
	assert(ci->sv_handle == NULL);

	ccow_t tc;
	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}

	err = ccow_snapview_create(tc, &ci->sv_handle,
	    ci->bid, ci->bid_size, SNAPVIEW_OID, strlen(SNAPVIEW_OID) + 1);
	if (err == -EEXIST)
		err = 0;

	log_debug(fsio_lg, "completed ci: %p", ci);

out:
	return err;
}

int
fsio_snapshot_term(ci_t * ci)
{
	int err;
	log_trace(fsio_lg, "ci: %p", ci);
	/*
	 * Freeup ci->sv_handle
	 */
	ccow_t tc;
	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}
	ccow_snapview_destroy(tc, ci->sv_handle);
	ci->sv_handle = NULL;

	log_debug(fsio_lg, "completed ci: %p", ci);

out:
	return err;
}

int
fsio_snapshot_create(ci_t * ci, char *path, char *user_snap_name)
{
	int err;
	inode_t ino, ino_verify;
	char *system_snap_name = NULL;
	ccowfs_inode *inode = NULL;

	log_trace(fsio_lg, "ci: %p, path: \"%s\", user_snap_name: \"%s\"", ci,
	    path, user_snap_name);

	err = ccow_fsio_find(ci, path, &ino);
	if (err) {
		log_softerror(fsio_lg, err,
		    "ccow_fsio_find fail for path: %s", path);
		goto out;
	}

	if (!INODE_IS_FILE(ino)) {
		/*
		 * snapshots supported only for regular files.
		 */
		err = EISDIR;
		log_softerror(fsio_lg, err,
		    "Can't do snapshot for directory");
		goto out;
	}

	err = __get_system_snap_name(path, user_snap_name, &system_snap_name);
	if (err) {
		log_error(fsio_lg,
		    "__get_system_snap_name return %d", err);
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d", err);
		goto out;
	}

	ccowfs_inode_lock(inode);
	err = disk_worker_freez(inode->ci, &(inode->disk_worker), 0);
	if (err) {
		log_error(fsio_lg,
		    "disk_worker_freez return %d", err);
		goto out;
	}
	/*
	 * We have paused any MD or IO to the inode. We own it now.
	 */

	ccow_t tc;
	err = tc_pool_get_tc(ci->tc_pool_handle, inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}
	err = ccow_snapshot_create(tc, ci->sv_handle,
	    ci->bid, ci->bid_size,
	    inode->oid, strlen(inode->oid) + 1,
	    system_snap_name, strlen(system_snap_name) + 1);
	if (err == -EEXIST)
		err = EEXIST;

	disk_worker_unfreez(inode->ci, &(inode->disk_worker));
	if (err) {
		ccowfs_inode_unlock(inode);
		goto out;
	}

	err = ccowfs_inode_inc_snap_count(inode);
	ccowfs_inode_unlock(inode);
	if (err)
		goto __delete;

    err = ccowfs_inode_sync(inode, 1);
    if (err) {
        log_softerror(fsio_lg, err, "ccowfs_inode_sync fail for inode: %lu",
            inode->ino);
        goto __delete;
    }

	/**
	 * Make sure the path is still pointing to the same inode.
	 * We don't have lock on the path. The namespace entry could get
	 * removed meanwhile. Once we have set the snap_count on inode, the
	 * namespace entry will not go away as we don't allow file to be
	 * deleted if it has active snapshot(s).
	 */
	err = ccow_fsio_find(ci, path, &ino_verify);
	if (err || (ino_verify != ino)) {
		/*
		 * The namespace entry has gone away.
		 * Remove the snapshot and the snap_count set on the inode.
		 */
		ccowfs_inode_lock(inode);
		ccowfs_inode_dec_snap_count(inode);
		ccowfs_inode_unlock(inode);

		err = ccowfs_inode_sync(inode, 1);
		if (err) {
			log_error(fsio_lg, "ccowfs_inode_sync return %d for inode: %lu",
				err, inode->ino);
			goto __delete;
		}

		err = ENOENT;
		goto __delete;
	} else {
		/*
		 * All is well
		 */
		goto out;
	}

__delete:
	/*
	 * Something went wrong after we created the snapshot.
	 * delete the just created snapshot.
	 */
	ccow_snapshot_delete(tc, ci->sv_handle,
	    system_snap_name, strlen(system_snap_name) + 1);

out:
	if (inode)
		ccowfs_inode_put(inode);

	if (system_snap_name)
		je_free(system_snap_name);

	log_debug(fsio_lg, "completed ci: %p, path: \"%s\", "
	    "user_snap_name: \"%s\"", ci, path, user_snap_name);

	return err;
}

int
fsio_snapshot_delete(ci_t * ci, char *path, char *user_snap_name)
{
	int err;
	char *system_snap_name = NULL;
	ccowfs_inode *inode = NULL;
	inode_t ino;

	log_trace(fsio_lg, "ci: %p, path: \"%s\", user_snap_name: \"%s\"", ci,
	    path, user_snap_name);

	err = __get_system_snap_name(path, user_snap_name, &system_snap_name);
	if (err) {
		log_error(fsio_lg,
		    "ccow_snapshot_create return %d", err);
		goto out;
	}

	err = __is_snapshot_present(ci, path, system_snap_name);
	if (err) {
		log_error(fsio_lg,
		    "__is_snapshot_present return %d", err);
		goto out;
	}

	err = ccow_fsio_find(ci, path, &ino);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_fsio_find fail");
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d", err);
		goto out;
	}

	ccow_t tc;
	err = tc_pool_get_tc(ci->tc_pool_handle, ino, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		goto out;
	}
	err = ccow_snapshot_delete(tc, ci->sv_handle, system_snap_name,
	    strlen(system_snap_name) + 1);
	if (err) {
		log_softerror(fsio_lg, err,
		    "ccow_snapshot_delete fail");
		goto out;
	}

	ccowfs_inode_lock(inode);
	err = ccowfs_inode_dec_snap_count(inode);
	ccowfs_inode_unlock(inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_dec_snap_count return %d", err);
		goto out;
	}

	err = ccowfs_inode_sync(inode, 1);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_sync return %d for inode: %lu",
			err, inode->ino);
		goto out;
	}
out:
	if (system_snap_name)
		je_free(system_snap_name);

	if (inode)
		ccowfs_inode_put(inode);

	log_debug(fsio_lg, "completed ci: %p, path: \"%s\", "
	    "user_snap_name: \"%s\"", ci, path, user_snap_name);

	return err;
}

int
fsio_snapshot_list(ci_t * ci, char *path, uint64_t * snap_count,
    char ***snap_list)
{
	int err = 0;
	ccow_lookup_t iter = NULL;
	char *pattern = NULL;
	int sz;
	char **snaps = NULL;
	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	ccowfs_inode *inode = NULL;
	inode_t ino;
	uint32_t count = 0;
	uint32_t lookup_count;

	log_trace(fsio_lg, "ci: %p, path: \"%s\", snap_count: %p, snap_list: %p",
	    ci, path, snap_count, snap_list);
	/*
	 * Need to append '\n' to the path
	 * * This makes sure that we search for the exact matching path.
	 */
	sz = strlen(path) + 2;

	pattern = (char *) je_calloc(1, sz);
	if (pattern == NULL) {
		err = ENOMEM;
		goto out;
	}

	snprintf(pattern, sz, "%s\n", path);

	err = ccow_fsio_find(ci, path, &ino);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_fsio_find fail");
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d", err);
		goto out;
	}

	ccowfs_inode_lock_shared(inode);
	lookup_count = inode->snap_count;
	ccowfs_inode_unlock_shared(inode);

	ccow_t tc;
	err = tc_pool_get_tc(ci->tc_pool_handle, ino, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		goto out;
	}
	err = ccow_snapshot_lookup(tc, ci->sv_handle, pattern, sz,
	    lookup_count, &iter);
	if (err) {
		log_softerror(fsio_lg, err,
		    "ccow_snapshot_lookup fail");
		goto out;
	}

	snaps = (char **) je_calloc(1, lookup_count);
	if (snaps == NULL) {
		log_error(fsio_lg, "Failed to allocate memory");
		err = ENOMEM;
		goto out;
	}

	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++))) {
		if (kv->type == CCOW_KVTYPE_RAW) {
			err = __get_user_snap_name(kv->key, &snaps[count]);
			if (err) {
				log_error(fsio_lg,
				    "__get_user_snap_name return %d", err);
				goto out;
			}
			count++;
			if (count == lookup_count) {
				/*
				 * In possible race case, wheere we are listing
				 * snaps and new snap is created.
				 * Read only lookup_count snaps as we have
				 * allocated space for lookup_count.
				 * This is okay even in race condition as we
				 * cannot confirm the operation order.
				 * The new snap will be listed in case the
				 * snap_list is called again.
				 */
				break;
			}
		}
	}

	*snap_list = snaps;
	*snap_count = count;

out:
	if (inode)
		ccowfs_inode_put(inode);

	if (iter)
		ccow_lookup_release(iter);

	if (err && snaps) {
		while (count) {
			je_free(snaps[count]);
		}
		je_free(snaps);
	}

	if (err == -ENOENT || err == ENOENT) {
		/*
		 * No snapshots available for the path.
		 */
		err = 0;
		*snap_list = NULL;
		*snap_count = 0;
	}

	log_debug(fsio_lg, "completed ci: %p, path: \"%s\", snap_count: %p, "
	    "snap_list: %p", ci, path, snap_count, snap_list);

	return err;
}

int
fsio_snapshot_rollback(ci_t * ci, char *path, char *user_snap_name)
{
	char *system_snap_name = NULL;
	ccowfs_inode *inode = NULL;
	inode_t ino;
	uint32_t bk_snap_count;
	nlink_t bk_st_nlink;
	int err, locked = 0;

	log_trace(fsio_lg, "ci: %p, path: \"%s\", user_snap_name: \"%s\"", ci,
	    path, user_snap_name);

	err = __get_system_snap_name(path, user_snap_name, &system_snap_name);
	if (err) {
		log_error(fsio_lg,
		    "__get_system_snap_name return %d", err);
		goto out;
	}

	err = ccow_fsio_find(ci, path, &ino);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_fsio_find fail");
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d", err);
		goto out;
	}

	ccowfs_inode_lock(inode);
	locked = 1;
	err = disk_worker_freez(inode->ci, &(inode->disk_worker), 0);
	if (err) {
		log_error(fsio_lg,
		    "disk_worker_freez return %d", err);
		goto out;
	}
	/*
	 * We have paused any MD or IO to the inode. We own it now.
	 */

	/*
	 * We don't want to rollback all the attributes.
	 * * backup the onec which we will overwrite after rollback.
	 */
	bk_snap_count = inode->snap_count;
	bk_st_nlink = inode->stat.st_nlink;

	ccow_t tc;
	err = tc_pool_get_tc(ci->tc_pool_handle, inode->ino, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}
	err = ccow_snapshot_rollback(tc, ci->sv_handle, system_snap_name,
	    strlen(system_snap_name) + 1);
	if (err)
		goto out;

	/*
	 * We have rollbacked the object. We can start the IO on it.
	 */
	disk_worker_unfreez(inode->ci, &(inode->disk_worker));

	/*
	 * Object on disk is changed. We must refresh the in memory inode
	 */
	err = ccowfs_inode_refresh_locked(inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_refresh_locked return %d", err);
		goto out;
	}

	/*
	 * Restore the special parameters
	 */
	if (inode->snap_count != bk_snap_count ||
	    inode->stat.st_nlink != bk_st_nlink) {
		struct stat master_stat;
		memcpy(&master_stat, &(inode->stat), sizeof(struct stat));

		/*
		 * We need to flush the special attributes as they are different
		 * Rollback cannot restore the snap count and link count.
		 */
		inode->snap_count = bk_snap_count;
		master_stat.st_nlink = bk_st_nlink;
		ccowfs_inode_master_set_attr_locked(inode, &master_stat);
	}

	/*
	 * Invalidate the inode cache from Ganesha
	 */
	if (ci->up_cb)
		err = ci->up_cb(ci->up_cb_args, ino, 0);

out:

	if (inode) {
		if (locked)
			ccowfs_inode_unlock(inode);

		err = ccowfs_inode_sync(inode, 1);
		if (err) {
			log_error(fsio_lg, "ccowfs_inode_sync return %d for inode: %lu",
				err, inode->ino);
		}
		ccowfs_inode_put(inode);
	}

	if (system_snap_name)
		je_free(system_snap_name);

	log_debug(fsio_lg, "completed ci: %p, path: \"%s\", "
	    "user_snap_name: \"%s\"", ci, path, user_snap_name);

	return err;
}

