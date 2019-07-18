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
#include "fsio_inode.h"
#include "fsio_debug.h"
#include "fsio_s3_transparency.h"
#include "fsio_system.h"
#include "fsio_common.h"
#include "fsio_listcache.h"
#include "fsio_namespace.h"
#include "fsio_dir.h"
#include "fsio_recovery.h"

/** FSIO NAMESPACE
 * Implements all the namespace related functions :
 *      mkdir, rename, touch, rmdir, link, unlink, delete etc..
 */

int
fsio_link_internal(ci_t * ci, inode_t parent_ino, char *name,
    inode_t child_ino, uint8_t link_count)
{
	ccowfs_inode *parent_inode = NULL;
	ccowfs_inode *child_inode = NULL;
	int err, err1;

	log_trace(fsio_lg, "%s: parent_ino: %lu, name: \"%s\", "
	    "child_ino: %lu", __func__, parent_ino, name, child_ino);

	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return: %d for inode: %lu",
			err, parent_ino);
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, child_ino, &child_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return: %d for inode: %lu",
			err, child_ino);
		goto out;
	}

	/*
	 * Add namespace entry.
	 */
	err = ccow_fsio_dir_add_entry(ci, parent_inode, name, child_inode, link_count);
	/*[TEMP PATCH - NED-5916] START{ */
	if (err == EEXIST) {
		if (parent_inode->ino == child_inode->ino &&
			child_inode->ino == CCOW_FSIO_ROOT_INODE &&
			! strcmp(name, "..")){
			/** We are adding ".." entry for root object.
			 *  Treat this as success even if the entry is already present
			 */
			log_debug(fsio_lg, "HIT PATCH FOR NED-5916");
			err = 0;
		}
	}
	/*[TEMP PATCH - NED-5916] END }*/

	if (err) {
		if (err != EEXIST)
			log_error(fsio_lg,
			    "ccow_fsio_dir_add_entry return: %d for parent: %lu",
				err, parent_ino);
		goto out;
	}

out:
	if (child_inode)
		ccowfs_inode_put(child_inode);
	if (parent_inode)
		ccowfs_inode_put(parent_inode);

	if (err) {
		ci->ccow_err = err;
		if (err != EEXIST)
			log_error(fsio_lg,
			    "failed for bucket: %s inode: %lu name: %s err: %d",
			    ci->bid, parent_ino, name, err);
	}

	log_debug(fsio_lg, "completed %s: parent_ino: %lu, name: \"%s\", "
	    "child_ino: %lu", __func__, parent_ino, name, child_ino);

	return err;
}

static int
__create_node(ci_t * ci, inode_t parent_ino, char *name,
    uint16_t mode, uint16_t uid, uint16_t gid,
    inode_t * newnode_ino, char *link)
{
	ccowfs_inode *child_inode = NULL;
	ccowfs_inode *parent_inode = NULL;
	int err, err1;
	inode_t child_ino;
	int64_t parent_link_count = 0;

	log_trace(fsio_lg, "%s: parent_ino: %lu, name: \"%s\", mode: %u, "
	    "uid: %u, gid: %u, link: \"%s\"",
		__func__, parent_ino, name, mode, uid, gid, link);

	if (parent_ino == CCOW_FSIO_S3OBJ_DIR_INODE) {
		err = EPERM;
		goto out_nolock;
	}

	/*
	 * Get a ref on parent inode.
	 */
	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_softerror(fsio_lg, err,
		    "ccowfs_inode_get_by_ino return error for inode: %lu",
		    parent_ino);
		goto out_nolock;
	}

	if (parent_inode->read_only) {
		err = EPERM;
		goto out_nolock;
	}

	ccowfs_namespace_inode_lock(parent_inode);

	/*
	 * Verify that directory doesn't contain this name just yet
	 */
	inode_t tmp_ino = 0;
	err = ccow_fsio_dir_lookup(ci, parent_inode, name, &tmp_ino);
	if (err == 0) {
		err = EEXIST;
		if (newnode_ino)
			*newnode_ino = tmp_ino;
		goto out;
	} else if (err != ENOENT) {
		goto out;
	}

	/*
	 * Create new inode.
	 */
	err = ccowfs_inode_create_new_get(ci, 0, mode, uid, gid,
	    link, &child_inode, &child_ino);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_create_new_get return %d", err);
		goto out;
	}

	assert(child_inode->stat.st_size == 0);

	if ((mode & S_IFMT) == S_IFDIR) {
		/* initial link count for child directory is passed in here,
		 * include 1 for self + 1 for "."
		 */
		err = ccow_fsio_dir_add_entry(ci, child_inode, "..", parent_inode, 2);
		if (err) {
			log_error(fsio_lg,
			    "ccow_fsio_dir_add_entry return %d for inode: %lu",
				err, child_ino);
			goto out;
		}
		/* increment link count for parent dir for the "..",
		 * handled when we insert child dir below */
		parent_link_count = 1;
	}

	err = ccow_fsio_dir_add_entry(ci, parent_inode, name, child_inode, parent_link_count);
	if (err) {
		if (err != EEXIST)
			log_error(fsio_lg, "ccow_fsio_dir_add_entry return %d for inode: %lu",
			    err, parent_ino);
		if (err == EEXIST && newnode_ino)
			 *newnode_ino = child_ino;
		goto out;
	}

	if (newnode_ino)
		*newnode_ino = child_ino;

	/*
	 * Success in creating new noode.
	 */
out:
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

	log_debug(fsio_lg, "completed %s: parent_ino: %lu, name: \"%s\", "
	    "mode: %u, uid: %u, gid: %u, newnode_ino: %lu, link: \"%s\"",
	    __func__, parent_ino, name, mode, uid, gid, child_ino, link);

	return err;
}

static int
__delete_internal(ci_t * ci, inode_t parent_ino, char *name)
{
	ccowfs_inode *parent_inode = NULL;
	ccowfs_inode *child_inode = NULL;
	inode_t child_ino;
	int err = 0;
	int empty = 0;
	int child_locked = 0;

	log_trace(fsio_lg, "%s: parent_ino: %lu, name: \"%s\"",
		__func__, parent_ino, name);

	if (parent_ino == CCOW_FSIO_S3OBJ_DIR_INODE) {
		err = EPERM;
		log_softerror(fsio_lg, err,
		    "Can't delete files inside S3OBJ dir");
		goto out_nolock;
	}

	/*
	 * Get a ref on parent inode.
	 */
	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return: %d for inode: %lu",
		    err, parent_ino);
		goto out_nolock;
	}

	if (parent_inode->read_only) {
		err = EPERM;
		goto out_nolock;
	}

	ccowfs_namespace_inode_lock(parent_inode);

	err = ccow_fsio_lookup(ci, parent_ino, name, &child_ino);
	if (err) {
		if (err != ENOENT)
			log_error(fsio_lg,
			    "ccow_fsio_lookup return %d parent: %lu name: %s",
			    err, parent_ino, name);
		goto out;
	}

	if (child_ino == CCOW_FSIO_S3OBJ_DIR_INODE) {
		err = EPERM;
		log_softerror(fsio_lg, err, "Can't delete S3OBJ Dir");
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, child_ino, &child_inode);
	if (err) {
		if (err == ENOENT) {
			log_error(fsio_lg, "Remove stale dir entry");
			err = ccow_fsio_dir_remove_entry(ci, parent_inode, name, 0);
			if (err)
				log_error(fsio_lg, "Fail to remove stale entry");
		}

		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return: %d for inode: %lu",
			err, child_ino);
		goto out;
	}

	if (INODE_IS_DISK_DIR(child_ino)) {

		ccowfs_namespace_inode_lock(child_inode);
		child_locked = 1;

		/* Check if the dir is empty */
		if (!ccow_fsio_dir_is_empty(child_inode)) {
			log_debug(fsio_lg,
			     "Delete dir %lu failed as ENOTEMPTY", child_ino);
			err = ENOTEMPTY;
			goto out;
		}

		/* Insert into the recovery table */
		ccowfs_recovery_insert_deleted(child_inode, parent_inode, name);

		/* Remove the child entry from the parent
		 * We will decrement parent link count for the ".."
		 */
		err = ccow_fsio_dir_remove_entry(ci, parent_inode, name, 1);
		if (err) {
			if (err != ENOENT)
				log_error(fsio_lg,
				    "ccow_fsio_dir_remove_entry return %d parent: %lu name: %s",
				    err, parent_ino, name);
			goto out;
		}

		/* Remove ".." from child dir, and pro-actively decrement its
		 * link count for both "." and itself
		 */
		err = ccow_fsio_dir_remove_entry(ci, child_inode, "..", 2);
		if (err) {
			log_error(fsio_lg, "failed to remove '..' entry "
			    "bucket: %s inode: %lu err: %d",
			    ci->bid, child_inode->ino, err);
			goto out;
		}

		/* Now mark directory as deleted and delete the on disk
		 * directory. The inode will go away when the last ref is put.
		 * Recovery table handled at time of deletion.
		 */
		err = ccow_fsio_dir_mark_deleted(child_inode);
		if (err) {
			log_error(fsio_lg,
			    "ccow_fsio_dir_mark_deleted return %d for inode: %lu",
			    err, child_ino);
		}

	} else if (child_inode->snap_count != 0) {
		/*
		 * Not allowed to delete file which has active snapshots
		 * Directories cannot have snapshot.
		 */
		err = EPERM;
		goto out;
	} else {
		/* Insert into the recovery table */
		ccowfs_recovery_insert_deleted(child_inode, parent_inode, name);

		/* Remove the child entry from the parent */
		err = ccow_fsio_dir_remove_entry(ci, parent_inode, name, 0);
		if (err) {
			if (err != ENOENT)
				log_error(fsio_lg,
				    "ccow_fsio_dir_remove_entry return %d parent: %lu name: %s",
				    err, parent_ino, name);
			goto out;
		}

		/* Drop the link count for the file.
		 * The inode will be deleted if the link count turns 0
		 * and when the last ref is put. Recovery table handled
		 * at time of deletion.
		 */
		log_debug(fsio_lg, "decreasing link count for name: %s inode:%lu",
		    name, child_inode->ino);
		err = ccowfs_inode_unlink(child_inode);
	}

out:
	if (child_locked)
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
ccow_fsio_readdir_cb4(ci_t * ci, inode_t parent_ino,
    ccow_fsio_readdir_cb4_t cb, char *start, void *ptr, bool *eofptr)
{
	int err;
	int eof = 0;
	ccowfs_inode *parent_inode = NULL;
	fsio_dir_entry *dir_entry = NULL;
	char filter[MAX_NAME_LEN], marker[MAX_NAME_LEN], tmpMarker[MAX_NAME_LEN],
		newMarker[MAX_NAME_LEN], dirMarker[MAX_NAME_LEN];
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	struct s3dir *s3;

	log_trace(fsio_lg, "%s: parent_ino: %lu, cb: %p, start: %s, "
	    "ptr: %p", __func__, parent_ino, cb, start, ptr);

	if (!INODE_IS_DIR(parent_ino) && !(parent_ino & FSIO_INODE_MEMONLY)) {
		/*
		 * Not a directory.
		 */
		log_error(fsio_lg, "%lu Not a directory", parent_ino);
		return (EINVAL);
	}

	if (parent_ino != CCOW_FSIO_S3OBJ_DIR_INODE && !(parent_ino &
	    FSIO_INODE_MEMONLY)) {
		err = ccow_fsio_dir_readdir_cb4(ci, parent_ino, start, cb, ptr, eofptr);
		return err;
	}

	DEBUG_START_CALL(ci, READDIR_CB4);
	assert(parent_ino == CCOW_FSIO_S3OBJ_DIR_INODE || (parent_ino &
	    FSIO_INODE_MEMONLY));

	dir_entry = je_calloc(1, (MAX_READIR_ENTRIES_AT_A_TIME + 16) *
	    sizeof(fsio_dir_entry));
	if (!dir_entry) {
		err = ENOMEM;
		goto out;
	}

	if (parent_ino & FSIO_INODE_MEMONLY) {
		if (!find_cached_s3dir_by_ino(ci, parent_ino, &s3)) {
			/* TODO handle case when no parent info found. */
			return (ENOENT);
		}
	}

	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d for inode: %lu",
			err, parent_ino);
		goto out;
	}

	/**
	 * S3OBJ_DIR is in memory directory. There is no representation on disk.
	 * Add "." and ".." entries
	 */
	int count = 0;
	dir_entry[count].name = je_strdup(".");
	dir_entry[count].inode = CCOW_FSIO_S3OBJ_DIR_INODE;
	count++;
	dir_entry[count].name = je_strdup("..");
	dir_entry[count].inode = CCOW_FSIO_ROOT_INODE;
	count++;

	cb(parent_ino, dir_entry, count, ptr);
	for (int i = 0; i < count; i++) {
		je_free(dir_entry[i].name);
		dir_entry[i].name = NULL;
		dir_entry[i].inode = 0;
	}

	int plen = 0;
	/*
	 * Set the first marker as empty string.
	 * In case of pseudo S3 subdir marker is parent dir path + slash.
	 */
	if (parent_ino & FSIO_INODE_MEMONLY) {
		plen = strlen(s3->path) + 1;
		strncpy(marker, s3->path, MAX_NAME_LEN);
		marker[plen - 1] = '/';
		marker[plen] = '\0';
		strcat(marker, start ? start : "");
	} else {
		strncpy(marker, start ? start : "", MAX_NAME_LEN);
	}
	strncpy(filter, marker, MAX_NAME_LEN);
	strncpy(newMarker, marker, MAX_NAME_LEN);

	while (err == 0 && !eof) {
		int read_count = 0;
		int dir_count = 0;
		int entries_count = 0;
		struct ccow_metadata_kv *kv = NULL;
		int pos = 0;
		int dot_found = 0;
		struct iovec iov[1];
		char *e = NULL;
		char *name = NULL;
		inode_t child_ino;
		char s3_encoded_name[MAX_NAME_LEN];

		err = ccowfs_create_completion(ci, NULL, NULL, parent_ino, &c);
		if (err) {
			log_error(fsio_lg,
				"ccowfs_create_completion return %d", err);
			goto out;
		}
		err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
			(void *) "btree_key_val", NULL);
		if (err) {
			log_error(fsio_lg,
				"ccow_attr_modify_default return %d", err);
			goto out;
		}

		iov[0].iov_base = marker;
		iov[0].iov_len = strlen(marker) + 1;

		memset(dir_entry, 0, MAX_READIR_ENTRIES_AT_A_TIME *
		    sizeof(fsio_dir_entry));

		assert(iter == NULL);
		err = ccow_get_list(ci->bid, ci->bid_size, parent_inode->oid,
		    parent_inode->oid_size, c, (struct iovec *) &iov, 1,
		    MAX_READIR_ENTRIES_AT_A_TIME, &iter);
		if (err) {
			log_error(fsio_lg, "ccow_get_list return %d for inode: %lu",
			    err, parent_ino);
			goto out;
		}
		err = ccow_wait(c, 0);
		if (err) {
			log_softerror(fsio_lg, err,
			    "ccow_wait fail for ccow_get_list on inode: %lu",
			    parent_ino);
			if (err == -ENOENT) {
				eof = 1;
				err = 0;
				break;
			}
			goto out;
		}
		c = NULL;

		if (iter != NULL) {
			while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
			    pos++)) != NULL && read_count < MAX_READIR_ENTRIES_AT_A_TIME) {
				struct stat s3_obj_stat;

				entries_count++;

				if (kv->value == NULL || kv->key == NULL) {
					continue;
				}

				/*
				 * Received entry must be greater than marker.
				 * Ignore if not.
				 */
				if (strcmp(kv->key, newMarker) <= 0) {
					continue;
				}

				/* last read element can be our new marker */
				if (kv->key_size > 0 && kv->key_size < MAX_NAME_LEN) {
					memcpy(tmpMarker, kv->key, kv->key_size);
					tmpMarker[kv->key_size] = 0;
					if (strcmp(tmpMarker, newMarker) > 0) {
						strncpy(newMarker, tmpMarker, MAX_NAME_LEN);
					}
				}

				if (kv->key_size > 2 &&
				    *(uint8_t *)kv->key == 0xEF &&
				    *((uint8_t *)kv->key + 1) == 0xBF &&
				    *((uint8_t *)kv->key + 2) == 0xBF) {
					log_debug(fsio_lg, "Found end of object list");
					eof = 1;
					break;
				}
				if (plen && strncmp(kv->key, filter, plen) != 0) {
					log_debug(fsio_lg, "Found end of dir "
					    "object list by prefix key: %s", (char *)kv->key);
					eof = 1;
					break;
				}
				struct s3dir *d = NULL;
				char *slash = strchr(kv->key + plen, '/');
				if (slash) {
					int len = slash - (kv->key + plen);
					strncpy(s3_encoded_name, kv->key + plen,
					    len);
					s3_encoded_name[len] = '\0';

					strncpy(dirMarker, kv->key, plen+len+1);
					dirMarker[plen+len+1] = 0xFF;
					dirMarker[plen+len+2] = '\0';
					if (strcmp(dirMarker, newMarker) > 0) {
						strncpy(newMarker, dirMarker, MAX_NAME_LEN);
						log_debug(fsio_lg, "Updated marker: %s, by dir key: %s",
							newMarker, (char *)kv->key);
					}

					/* Try to cache subdir name. */
					err = s3dir_add(ci, parent_ino,
					    s3_encoded_name, &d);
					dir_count++;
					if (err) {
						int skip = 0;
						if (err == EEXIST) {
							/* additionally, find in direntry */
							for (int i = 0; i < read_count; i++) {
								if (strcmp(dir_entry[i].name, d->name) == 0) {
									skip = 1;
									break;
								}
							}
							err = 0;
						} else
							skip = 1;
						/* Skip entries for subdir. */
						if (skip) {
							log_debug(fsio_lg, "Skip dir entry %s",
							    (char *)kv->key);
							continue;
						}
					}
				}

				log_debug(fsio_lg, "Parsing object %s marker %s",
				    (char *)kv->key, newMarker);
				err = parse_s3_obj_stats(ci, kv->value,
				    kv->value_size, &s3_obj_stat);
				if (err) {
					log_error(fsio_lg, "parse_s3_obj_stats "
					    "failed. %s err: %d",
					    (char *)kv->value, err);
					goto out;
				}

				child_ino = d ? d->ino : s3_obj_stat.st_ino;

				dir_entry[read_count].name = je_strdup(
				    d ? d->name : kv->key + plen);
				dir_entry[read_count].inode = child_ino;
				log_debug(fsio_lg, "Adding object name: %s inode: %lu",
				        dir_entry[read_count].name, dir_entry[read_count].inode);
				read_count++;

				/*
				* Optimization to speed up first time S3 object readdir.
				* In case of S3 objects, we already have the inode stats.
				* Do not fetch the object attributes again.
				* If the inode is not presetn in the cache, then add it.
				*/
				ccowfs_inode_cache_s3_inode(ci, child_ino, &s3_obj_stat);

				/*
				 * Don't check the error here.
				 * We cannot fail the readdir at this point.
				 * If there is some real error, it will fail at time of
				 * lookup.
				 * If fetching inode fails at this time, it will happen
				 * during lookup.
				 */
			}

			ccow_lookup_release(iter);
			iter = NULL;

			eof = eof || (strcmp(marker, newMarker) == 0);
			strncpy(marker, newMarker, MAX_NAME_LEN);

			if (read_count) {
				/*
				 * assert(read_count <= MAX_READIR_ENTRIES_AT_A_TIME);
				 * There is pseudo dirs also now, so we don't
				 * know how big it is.
				 */
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
					eof = 0;
					break;
				}
			}

			if (eof)
				break;
		}
	}

	if (!err)
		*eofptr = (bool)eof;

out:
	if (dir_entry)
		je_free(dir_entry);
	if (parent_inode)
		ccowfs_inode_put(parent_inode);
	if (iter)
		ccow_lookup_release(iter);
	if (c)
		ccow_release(c);
	if (err) {
		ci->ccow_err = err;
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    ci->bid, parent_ino, err);

		if (err == -ENOENT || err == ENOENT)
			err = 0; /* ENOENT means directory is empty. Ignore the error */
	}
	DEBUG_END_CALL(ci, READDIR_CB4, err);
	log_debug(fsio_lg, "completed %s: parent_ino: %lu, cb: %p, "
	    "start: %s, ptr: %p", __func__, parent_ino, cb, start, ptr);

	return err;
}

int
ccow_fsio_find_list(ci_t * ci, inode_t parent_ino, inode_t ino, char *res, int res_max)
{
	int err;
	int eof = 0;
	ccowfs_inode *parent_inode = NULL;
	char filter[MAX_NAME_LEN], marker[MAX_NAME_LEN], tmpMarker[MAX_NAME_LEN],
		newMarker[MAX_NAME_LEN], dirMarker[MAX_NAME_LEN];
	char buf[MAX_NAME_LEN];
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	struct s3dir *s3;
	char *key;

	log_trace(fsio_lg, "find_list parent_ino: %lu, ino: %lu", parent_ino, ino);

	// Look at cache
	fsio_list_cache_clean(&ci->fsio_list_cache);
	key = build_list_key(parent_ino, ino, buf);
	err = fsio_list_cache_get(&ci->fsio_list_cache, key, res, res_max);
	if (!err) {
		log_trace(fsio_lg, "find_list found in cache bucket: %s, inode: %lu, key: %s",
			ci->bid, ino, key);
		return 1;
	}
	log_info(fsio_lg, "find_list miss in cache bucket: %s, key: %s",
			ci->bid, key);

	if (!INODE_IS_DIR(parent_ino) && !(parent_ino & FSIO_INODE_MEMONLY)) {
		log_error(fsio_lg, "%lu Not a directory", parent_ino);
		return -EINVAL;
	}

	if (parent_ino != CCOW_FSIO_S3OBJ_DIR_INODE && !(parent_ino &
	    FSIO_INODE_MEMONLY)) {
		err = ccow_fsio_dir_find(ci, parent_ino, ino, res, res_max);
		return err;
	}

	assert(parent_ino == CCOW_FSIO_S3OBJ_DIR_INODE || (parent_ino &
	    FSIO_INODE_MEMONLY));


	if (parent_ino & FSIO_INODE_MEMONLY) {
		if (!find_cached_s3dir_by_ino(ci, parent_ino, &s3)) {
			/* TODO handle case when no parent info found. */
			return -ENOENT;
		}
	}

	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d for inode: %lu",
			err, parent_ino);
		goto out;
	}


	int plen = 0;
	int res_found = 0;
	/*
	 * Set the first marker as empty string.
	 * In case of pseudo S3 subdir marker is parent dir path + slash.
	 */
	if (parent_ino & FSIO_INODE_MEMONLY) {
		plen = strlen(s3->path) + 1;
		strncpy(marker, s3->path, MAX_NAME_LEN);
		marker[plen - 1] = '/';
		marker[plen] = '\0';
	} else {
		strcpy(marker, "");
	}
	strncpy(filter, marker, MAX_NAME_LEN);
	strncpy(newMarker, marker, MAX_NAME_LEN);

	while (err == 0 && !eof) {
		int read_count = 0;
		int dir_count = 0;
		int entries_count = 0;
		struct ccow_metadata_kv *kv = NULL;
		int pos = 0;
		int dot_found = 0;
		struct iovec iov[1];
		char *e = NULL;
		char *name = NULL;
		inode_t child_ino;
		char s3_encoded_name[MAX_NAME_LEN];

		err = ccowfs_create_completion(ci, NULL, NULL, parent_ino, &c);
		if (err) {
			log_error(fsio_lg,
				"ccowfs_create_completion return %d", err);
			goto out;
		}
		err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
			(void *) "btree_key_val", NULL);
		if (err) {
			log_error(fsio_lg,
				"ccow_attr_modify_default return %d", err);
			goto out;
		}

		iov[0].iov_base = marker;
		iov[0].iov_len = strlen(marker) + 1;

		assert(iter == NULL);
		err = ccow_get_list(ci->bid, ci->bid_size, parent_inode->oid,
		    parent_inode->oid_size, c, (struct iovec *) &iov, 1,
		    MAX_READIR_ENTRIES_AT_A_TIME, &iter);
		if (err) {
			log_error(fsio_lg, "ccow_get_list return %d for inode: %lu",
			    err, parent_ino);
			goto out;
		}
		err = ccow_wait(c, 0);
		if (err) {
			log_softerror(fsio_lg, err,
			    "ccow_wait fail for ccow_get_list on inode: %lu",
			    parent_ino);
			if (err == -ENOENT) {
				eof = 1;
				err = 0;
				break;
			}
			goto out;
		}
		c = NULL;

		if (iter != NULL) {
			while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
			    pos++)) != NULL && read_count < MAX_READIR_ENTRIES_AT_A_TIME) {
				struct stat s3_obj_stat;

				entries_count++;

				if (kv->value == NULL || kv->key == NULL) {
					continue;
				}

				/*
				 * Received entry must be greater than marker.
				 * Ignore if not.
				 */
				if (strcmp(kv->key, newMarker) <= 0) {
					continue;
				}

				/* last read element can be our new marker */
				if (kv->key_size > 0 && kv->key_size < MAX_NAME_LEN) {
					memcpy(tmpMarker, kv->key, kv->key_size);
					tmpMarker[kv->key_size] = 0;
					if (strcmp(tmpMarker, newMarker) > 0) {
						strncpy(newMarker, tmpMarker, MAX_NAME_LEN);
					}
				}

				if (kv->key_size > 2 &&
				    *(uint8_t *)kv->key == 0xEF &&
				    *((uint8_t *)kv->key + 1) == 0xBF &&
				    *((uint8_t *)kv->key + 2) == 0xBF) {
					log_debug(fsio_lg, "Found end of object list");
					eof = 1;
					break;
				}
				if (plen && strncmp(kv->key, filter, plen) != 0) {
					log_debug(fsio_lg, "Found end of dir "
					    "object list by prefix key: %s", (char *)kv->key);
					eof = 1;
					break;
				}
				struct s3dir *d = NULL;
				char *slash = strchr(kv->key + plen, '/');
				if (slash) {
					int len = slash - (kv->key + plen);
					strncpy(s3_encoded_name, kv->key + plen,
					    len);
					s3_encoded_name[len] = '\0';

					strncpy(dirMarker, kv->key, plen+len+1);
					dirMarker[plen+len+1] = 0xFF;
					dirMarker[plen+len+2] = '\0';
					if (strcmp(dirMarker, newMarker) > 0) {
						strncpy(newMarker, dirMarker, MAX_NAME_LEN);
						log_debug(fsio_lg, "Updated marker: %s, by dir key: %s",
							newMarker, (char *)kv->key);
					}

					/* Try to cache subdir name. */
					err = s3dir_add(ci, parent_ino,
					    s3_encoded_name, &d);
					dir_count++;
					if (err) {
						int skip = 0;
						if (err == EEXIST) {
							err = 0;
						} else
							skip = 1;
						/* Skip entries for subdir. */
						if (skip) {
							log_debug(fsio_lg, "Skip dir entry %s",
							    (char *)kv->key);
							continue;
						}
					}
				}

				err = parse_s3_obj_stats(ci, kv->value,
				    kv->value_size, &s3_obj_stat);
				if (err) {
					log_error(fsio_lg, "parse_s3_obj_stats "
					    "failed. %s err: %d",
					    (char *)kv->value, err);
					goto out;
				}

				child_ino = d ? d->ino : s3_obj_stat.st_ino;
				log_debug(fsio_lg, "Parsing object %s ino: %lu",
				    (char *)kv->key, child_ino);

				read_count++;

				if (ino == child_ino) {
					strncpy(res, d ? d->name : kv->key + plen, res_max);
					log_debug(fsio_lg, "found s3 dir key: %s child_ino %lu",
						res, child_ino);
					res_found = 1;
					break;
				}
			}

			ccow_lookup_release(iter);
			iter = NULL;

			if (res_found)
				break;

			eof = eof || (strcmp(marker, newMarker) == 0);
			strncpy(marker, newMarker, MAX_NAME_LEN);

			if (eof)
				break;
		}
	}


out:
	if (parent_inode)
		ccowfs_inode_put(parent_inode);
	if (iter)
		ccow_lookup_release(iter);
	if (c)
		ccow_release(c);
	if (err) {
		ci->ccow_err = err;
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    ci->bid, parent_ino, err);

		if (err > 0)
			err = -err;
	}
	log_debug(fsio_lg,
	    "completed s3 dir find bucket: %s, parent_inode: %lu inode: %lu with err: %d",
	    ci->bid, parent_ino, ino, err);

	return err;
}


int
ccow_fsio_readsymlink(ci_t * ci, inode_t ino, char **link)
{
	struct ccow_metadata_kv *kv;
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	ccowfs_inode *inode = NULL;
	int err, found, pos;

	log_trace(fsio_lg, "%s: ino: %lu, *link: \"%s\"", __func__, ino, *link);
	DEBUG_START_CALL(ci, READSYMLINK);

	if (! INODE_IS_SYMLINK(ino)){
		log_error(fsio_lg, "%lu Not a symlink", ino);
		err = EINVAL;
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, ino, &inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d for inode: %lu",
		    err, ino);
		goto out;
	}

	err = ccowfs_create_completion(ci, NULL, NULL, ino, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_create_completion return %d", err);
		goto out;
	}

	err = ccow_get(ci->bid, ci->bid_size, inode->oid, inode->oid_size, c,
	    NULL, 0, 10000, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_get return %d for inode: %lu",
		    err, inode->ino);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_wait for ccow_get fail for "
		    "inode: %lu",
		    inode->ino);
		goto out;
	}

	c = NULL;

	found = pos = 0;
	if (iter != NULL) {
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_ALL, pos++))) {
			if (strcmp(kv->key, X_FILE_SYMLINK) == 0) {
				*link = je_strdup(kv->value);
				found = 1;
			}
		}
	}
	if (found == 0) {
		log_error(fsio_lg, "%lu symlink which does not point anywhere",
		    inode->ino);
	}

out:
	if (inode)
		ccowfs_inode_put(inode);

	if (iter)
		ccow_lookup_release(iter);

	if (c)
		ccow_release(c);

	if (err) {
		ci->ccow_err = err;
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    ci->bid, ino, err);

		if (err == -ENOENT || err == ENOENT)
			err = ENOENT;
	}

	DEBUG_END_CALL(ci, READSYMLINK, err);
	log_debug(fsio_lg, "completed %s: ino: %lu, *link: \"%s\"",
	    __func__, ino, *link);

	return err;
}

int ccowfs_inode_create_mem_s3dir(ci_t * ci,  uint16_t mode, uint16_t uid,
    uint16_t gid, ccowfs_inode **new_inode, inode_t *new_ino);

static int
__s3_lookup(ci_t * ci, ccowfs_inode * parent_inode, char *name,
    inode_t * out_ino, bool try_dir)
{
	struct ccow_metadata_kv *kv;
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	struct iovec iov[2];
	int err = 0;
	inode_t ino;
	char s3_decoded_name[MAX_NAME_LEN];
	char *obj_name = name;
	struct s3dir *d = NULL;

	log_trace(fsio_lg, "%s: parent_inode: %lu, parent oid: %s, try_dir: %d, name: \"%s\"",
	    __func__, parent_inode->ino, parent_inode->oid, try_dir, name);

	if (! strcmp(name, ".")){
		*out_ino = CCOW_FSIO_S3OBJ_DIR_INODE;
		goto out;
	}
	else if (! strcmp(name, "..")) {
		*out_ino = CCOW_FSIO_ROOT_INODE;
		goto out;
	}


	/*
	 * S3 objects can have "/" in the names. Encode the received
	 * name to allow "/" in it.
	 */
	err = decode_s3_name(name, strlen(name),
	    s3_decoded_name, MAX_NAME_LEN);
	if (err) {
		log_error(fsio_lg,
		    "decode_s3_name return %d for name :%s", err, name);
		goto out;
	}
	obj_name = s3_decoded_name;
	if (try_dir) {
		int l = strlen(obj_name);
		obj_name[l++] = '/';
		obj_name[l++] = '\0';
		ccowfs_inode_get(parent_inode);
	}
	if (parent_inode->ino != CCOW_FSIO_S3OBJ_DIR_INODE &&
	    parent_inode->ino & FSIO_INODE_MEMONLY) {
		err = find_cached_s3dir_by_ino(ci, parent_inode->ino,
		    &d);
		if (!err)
			log_error(fsio_lg, "Can't find cached parent "
			    "s3dir. ino: %lu, err: %d",
			    parent_inode->ino, err);
		sprintf(obj_name, "%s/%s", d->path, name);
	}

	err = ccowfs_create_completion(ci, NULL, NULL, parent_inode->ino, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_create_completion return %d", err);
		goto out;
	}

	iov[0].iov_base = obj_name;
	iov[0].iov_len = (obj_name != NULL) ? (strlen(obj_name) + 1) : 0;

	err = ccow_get_list(ci->bid, ci->bid_size,
	    parent_inode->oid, parent_inode->oid_size,
	    c, iov, 1, 100, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_get_list return %d for inode :%lu",
		    err, parent_inode->ino);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_softerror(fsio_lg, err,
		    "ccow_wait fail for ccow_get_list on inode: %lu",
		    parent_inode->ino);
		goto out;
	}

	c = NULL;

	if (iter != NULL) {
		int pos = 0;

		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
			    pos++)) != NULL) {

			if (try_dir && obj_name && strncmp(obj_name, kv->key,
			    strlen(obj_name)) == 0) {
				err = s3dir_add(ci, parent_inode->ino, name,
				    &d);
				if (err && err != EEXIST) {
					log_error(fsio_lg, "fail to add new "
					    "pseudo node %s to parent: %lu, "
					    "err: %d", name, parent_inode->ino,
					    err);
					goto out;
				}
				err = 0;
				if (out_ino) {
					*out_ino = d->ino;
				}
				goto out;
			}
			if (obj_name && strcmp(obj_name, kv->key) == 0) {
				err = parse_s3_obj_inode(kv->value,
				    kv->value_size, &ino);
				if (err) {
					log_error(fsio_lg,
					    "parse_s3_obj_inode return %d inode :%lu",
					    err, parent_inode->ino);
					goto out;
				}
				if (out_ino) {
					*out_ino = ino;
				}

				goto out;
			}
		}
		log_debug(fsio_lg, "%s Not found in %lu", name, parent_inode->ino);
		err = ENOENT;
	}

out:
	if (iter)
		ccow_lookup_release(iter);
	if (c)
		ccow_release(c);
	if (err) {
		ci->ccow_err = err;

		if (err == -ENOENT || err == ENOENT)
			err = ENOENT;
		else {
			log_error(fsio_lg,
			    "failed for bucket: %s inode: %lu name: %s err: %d",
			    ci->bid, parent_inode->ino, name, err);
		}
	}
	log_debug(fsio_lg, "completed %s: parent_inode: %lu, name: \"%s\" found inode: %lu",
	    __func__, parent_inode->ino, name, *out_ino);

	return err;
}

int
ccow_fsio_lookup(ci_t * ci, inode_t parent_ino, char *name, inode_t * ino)
{
	int err;
	ccowfs_inode *parent_inode = NULL;

	log_trace(fsio_lg, "%s: parent_ino: %lu, name: \"%s\"",
		__func__, parent_ino, name);
	DEBUG_START_CALL(ci, LOOKUP);

	assert(parent_ino >= CCOW_FSIO_ROOT_INODE);

	err = ccowfs_inode_get_by_ino(ci, parent_ino, &parent_inode);
	if (err) {
		log_softerror(fsio_lg, err,
		    "ccowfs_inode_get_by_ino return error for inode :%lu",
			parent_ino);
		goto out;
	}

	if (parent_ino == CCOW_FSIO_S3OBJ_DIR_INODE || (parent_ino & FSIO_INODE_MEMONLY)) {
		err = __s3_lookup(ci, parent_inode, name, ino, false);
		if (err && err != ENOENT)
			log_error(fsio_lg, "__s3_lookup return %d for name: %s "
			    "in inode: %lu", err, name, parent_ino);

		if (err == ENOENT) {
			/* Maybe it is dir. */
			err = __s3_lookup(ci, parent_inode, name, ino, true);
			if (err && err != ENOENT)
				log_error(fsio_lg, "__s3_lookup return %d for "
				    "name: %s in inode: %lu", err, name,
				    parent_ino);
		}
	} else {
		err = ccow_fsio_dir_lookup(ci, parent_inode, name, ino);
		if (err && err != ENOENT)
			log_error(fsio_lg, "ccow_fsio_dir_lookup return %d "
			    "for name: %s in inode: %lu", err, name, parent_ino);
	}

out:
	if (err && err != ENOENT) {
		ci->ccow_err = err;
		log_error(fsio_lg, "failed for bucket: %s inode: %lu err: %d",
		    ci->bid, parent_ino, err);
	}

	if (parent_inode)
		ccowfs_inode_put(parent_inode);

	DEBUG_END_CALL(ci, LOOKUP, err);
	log_debug(fsio_lg, "completed %s: parent_ino: %lu, name: \"%s\" ino: %lu",
	    __func__, parent_ino, name, *ino);

	return err;
}

int
ccow_fsio_link(ci_t * ci, inode_t parent_ino, char *name, inode_t child_ino)
{
	int err;

	log_trace(fsio_lg, "%s: parent_ino: %lu, name: \"%s\", "
	    "child_ino: %lu", __func__, parent_ino, name, child_ino);

	DEBUG_START_CALL(ci, LINK);
	err = fsio_link_internal(ci, parent_ino, name, child_ino, 1);
	if (err && err != EEXIST)
		log_error(fsio_lg, "fsio_link_internal return %d",
		    err);
	DEBUG_END_CALL(ci, LINK, err);

	log_debug(fsio_lg, "completed %s: parent_ino: %lu, name: \"%s\", "
	    "child_ino: %lu", __func__, parent_ino, name, child_ino);

	return err;
}

int
ccow_fsio_delete(ci_t * ci, inode_t parent_ino, char *name)
{
	int err;

	log_trace(fsio_lg, "%s: parent_ino: %lu, name: \"%s\"",
		__func__, parent_ino, name);

	DEBUG_START_CALL(ci, DELETE);
	err = __delete_internal(ci, parent_ino, name);
	if (err && err != ENOENT && err != ENOTEMPTY)
		log_error(fsio_lg,
			"__delete_internal return %d for inode: %lu, name: %s",
		    err, parent_ino, name);
	DEBUG_END_CALL(ci, DELETE, err);

	log_debug(fsio_lg, "completed %s: parent_ino: %lu, name: \"%s\"",
	    __func__, parent_ino, name);

	return err;
}

int
ccow_fsio_unlink(ci_t * ci, inode_t parent_ino, char *name)
{
	int err;

	log_trace(fsio_lg, "%s: parent_ino: %lu, name: \"%s\"",
		__func__, parent_ino, name);

	DEBUG_START_CALL(ci, UNLINK);
	err = ccow_fsio_delete(ci, parent_ino, name);
	if (err)
		log_softerror(fsio_lg, err, "ccow_fsio_delete fail for "
		    "inode: %lu name: %s", parent_ino, name);
	DEBUG_END_CALL(ci, UNLINK, err);

	log_debug(fsio_lg, "completed %s: parent_ino: %lu, name: \"%s\"",
	    __func__, parent_ino, name);

	return err;
}

int
ccow_fsio_mkdir(ci_t * ci, inode_t parent, char *name, uint16_t mode,
    uint16_t uid, uint16_t gid, inode_t * newnode)
{
	int err;

	DEBUG_START_CALL(ci, MKDIR);
	err = __create_node(ci, parent, name, S_IFDIR | (mode & 07777),
	    uid, gid, newnode, NULL);
	if (err)
		log_softerror(fsio_lg, err, "__create_node fail for inode: %lu name :%s",
			parent, name);
	DEBUG_END_CALL(ci, MKDIR, err);

	return err;
}

int
ccow_fsio_touch(ci_t * ci, inode_t parent, char *name, uint16_t mode,
    uint16_t uid, uint16_t gid, inode_t * newnode)
{
	int err;

	DEBUG_START_CALL(ci, TOUCH);
	err = __create_node(ci, parent, name, S_IFREG | (mode & 07777),
	    uid, gid, newnode, NULL);
	if (err && err != EEXIST)
		log_softerror(fsio_lg, err,
		    "__create_node return error for inode: %lu name :%s",
		    parent, name);
	DEBUG_END_CALL(ci, TOUCH, err);

	return err;
}

int
ccow_fsio_mksymlink(ci_t * ci, inode_t parent, char *name, uint16_t mode,
    uint16_t uid, uint16_t gid, inode_t * newnode, char *link)
{
	int err;

	DEBUG_START_CALL(ci, MKSYMLINK);
	err = __create_node(ci, parent, name, S_IFLNK | (mode & 07777),
	    uid, gid, newnode, link);
	if (err)
		log_softerror(fsio_lg, err, "__create_node fail for inode: %lu name :%s",
			parent, name);
	DEBUG_END_CALL(ci, MKSYMLINK, err);

	return err;
}

int
ccow_fsio_find(ci_t * ci, char *path, inode_t * inode)
{
	inode_t parent, child;
	char *name = NULL;
	char *p = NULL;
	char *sp = NULL;
	int err = 0;

	log_trace(fsio_lg, "%s: path: \"%s\"", __func__, path);
	DEBUG_START_CALL(ci, FIND);
	if (path == NULL) {
		err = EINVAL;
		log_error(fsio_lg, "%s NULL Path. Wrong argument", __func__);
		goto out;
	}

	if (path[0] == '\0') {
		*inode = CCOW_FSIO_ROOT_INODE;
		log_debug(fsio_lg, "inode is root node");
		goto out;
	}

	if (path[0] != '/') {
		err = EINVAL;
		log_error(fsio_lg,
			"%s Path: %s not starting with '/'. Wrong argument",
			__func__, path);
		goto out;
	}

	if (path[1] == '\0') {		/* path == "/" */
		*inode = CCOW_FSIO_ROOT_INODE;
		log_debug(fsio_lg, "inode is root node");
		goto out;
	}

	parent = CCOW_FSIO_ROOT_INODE;
	p = je_strdup(path);
	if (p == NULL) {
		log_error(fsio_lg, "%s Failed to allocate memory", __func__);
		goto out;
	}
	sp = NULL;
	name = strtok_r(p, "/", &sp);
	while (name != NULL) {
		err = ccow_fsio_lookup(ci, parent, name, &child);
		if (err != 0) {
			log_softerror(fsio_lg, err,
			    "ccow_fsio_lookup fail for inode: %lu name: %s",
				parent, name);
			je_free(p);
			p = NULL;
			goto out;
		}
		parent = child;
		name = strtok_r(NULL, "/", &sp);
	}

	*inode = child;

out:
	if (p)
		je_free(p);

	DEBUG_END_CALL(ci, FIND, err);
	log_debug(fsio_lg, "completed %s: path: \"%s\", inode: %lu",
		__func__, path, *inode);

	return err;
}

int
ccow_fsio_move(ci_t * ci, inode_t oldparent_ino, char *oldname,
    inode_t newparent_ino, char *newname)
{
	inode_t child_ino;
	ccowfs_inode *oldparent_inode = NULL;
	ccowfs_inode *newparent_inode = NULL;
	int err;

	log_trace(fsio_lg, "%s: oldparent: %lu, oldname: \"%s\", "
	    "newparent: %lu, newname: \"%s\"", __func__,
		oldparent_ino, oldname, newparent_ino, newname);

	DEBUG_START_CALL(ci, MOVE);

	pthread_mutex_lock(&ci->rename_mutex);

	if (oldparent_ino == CCOW_FSIO_S3OBJ_DIR_INODE ||
	    newparent_ino == CCOW_FSIO_S3OBJ_DIR_INODE) {
		err = EPERM;
		log_softerror(fsio_lg, err,
		    "Source or destination node is S3OBJ");
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, oldparent_ino, &oldparent_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d for inode :%lu",
			err, oldparent_ino);
		goto out;
	}

	if (oldparent_inode->read_only) {
		err = EPERM;
		goto out;
	}

	err = ccowfs_inode_get_by_ino(ci, newparent_ino, &newparent_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d for inode :%lu",
			err, newparent_ino);
		goto out;
	}

	if (newparent_inode->read_only) {
		err = EPERM;
		goto out;
	}

	/*
	 * oldname must esixt in oldparent and no other error.
	 */
	err = ccow_fsio_dir_lookup(ci, oldparent_inode, oldname, &child_ino);
	if (err) {
		log_softerror(fsio_lg, err,
			"ccow_fsio_dir_lookup fail for inoe: %lu name: %s",
		    oldparent_ino, oldname);
		goto out;
	}

	if (child_ino == CCOW_FSIO_S3OBJ_DIR_INODE) {
		err = EPERM;
		goto out;
	}

	err = ccow_fsio_dir_move(ci, oldparent_inode, oldname, newparent_inode,
	    newname);
out:
	if (err) {
		log_softerror(fsio_lg, err,
		    "failed for bucket: %s inode: %lu name: %s inode: %lu "
		    "name:%s", ci->bid, oldparent_ino, oldname,
		    newparent_ino, newname);
	}

	if (oldparent_inode)
		ccowfs_inode_put(oldparent_inode);
	if (newparent_inode)
		ccowfs_inode_put(newparent_inode);

	pthread_mutex_unlock(&ci->rename_mutex);
	DEBUG_END_CALL(ci, MOVE, err);
	log_debug(fsio_lg, "completed %s: oldparent: %lu, "
	    "oldname: \"%s\", newparent: %lu, newname: \"%s\"", __func__,
	    oldparent_ino, oldname, newparent_ino, newname);

	return err;
}

int
ccow_fsio_exists(ci_t * ci, char *path)
{
	int err;
	inode_t inode;

	log_trace(fsio_lg, "%s: path: \"%s\"", __func__, path);

	err = ccow_fsio_find(ci, path, &inode);
	err = (err == 0) ? 1 : 0;

	log_debug(fsio_lg, "completed %s: path: \"%s\"", __func__, path);

	return err;
}

int
fsio_namespace_init(ci_t * ci)
{
	int err;

	log_trace(fsio_lg, "%s", __func__);

	err = pthread_mutex_init(&ci->rename_mutex, NULL);
	if (err) {
		log_error(fsio_lg, "pthread_mutex_init error %d\n", err);
		ci->ccow_err = err;
	}

	log_debug(fsio_lg, "completed %s", __func__);

	return err;
}

int
fsio_namespace_term(ci_t * ci)
{
	log_trace(fsio_lg, "%s", __func__);
	return 0;
}

int
fsio_namespace_clone(ci_t * src_ci, inode_t src_parent_ino, char *src_name,
    ci_t * dest_ci, inode_t dest_parent_ino, char *dest_name, uint32_t flags)
{
	int err;
	inode_t src_ino;
	ccowfs_inode *src_inode = NULL;
	ccowfs_inode *dest_inode = NULL;
	int delete_dest = 0;
	inode_t dest_ino;

	log_trace(fsio_lg, "%s: src_bucket: %s src_parent_ino: %lu, "
	    "src_name: \"%s\",  dest_bucket: %s dest_parent_ino: %lu, "
	    "dest_name: \"%s\", flags: %u", __func__,
		src_ci->bid, src_parent_ino, src_name,
	    dest_ci->bid, dest_parent_ino, dest_name, flags);

	err = ccow_fsio_lookup(src_ci, src_parent_ino, src_name, &src_ino);
	if (err) {
		log_softerror(fsio_lg, err,
		    "ccow_fsio_lookup fail for parent: %lu name :%s",
			src_parent_ino, src_name);
		goto out;
	}

	/*
	 * Allow clone operation of regular files only.
	 */
	if (!INODE_IS_FILE(src_ino)) {
		log_error(fsio_lg, "%lu is not a file", src_ino);
		err = EISDIR;
		goto out;
	}

	err = ccowfs_inode_get_by_ino(src_ci, src_ino, &src_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d for inode: %lu",
			err, src_ino);
		goto out;
	}

	/*
	 * Handle the flags
	 *
	 * CLONE_FILE_FLAG_GUARDED  : Donot delete the destination file if this
	 *				flag is set.
	 * CLONE_FILE_FLAG_LAZY     : We anyway don't take long for cloning.
	 *				This flag is ignored.
	 *                            May consider to add this in futurre.
	 * CLONE_FILE_FLAG_DRYRUN   : Donot actually perform the operation,
	 *				just check if we can perform it.
	 * CLONE_FILE_FLAG_SKIPZEROES : We anyway don't copy actual data for
	 *				clone. So ignore this flag.
	 */

	/*
	 * Check if destination name is present.
	 */
	err = ccow_fsio_lookup(dest_ci, dest_parent_ino, dest_name, &dest_ino);
	if (!err) {
		/*
		 * Destination fille is present.
		 */
		if (flags & CLONE_FILE_FLAG_GUARDED) {
			/*
			 * Not allowed to delete the destination file.
			 */
			err = EEXIST;
			log_error(fsio_lg,
			    "Node with name \"%s\" already exist", dest_name);
			goto out;
		}
		delete_dest = 1;
	} else
		err = 0;

	if (!(flags & CLONE_FILE_FLAG_DRYRUN)) {
		/*
		 * It is not a dry run. Actually perform the clone operatio.
		 */

		if (delete_dest) {
			/*
			 * Destination file is present and should be deleted.
			 */
			err = ccow_fsio_delete(dest_ci, dest_parent_ino,
			    dest_name);
			if (err) {
				log_softerror(fsio_lg, err,
				    "ccow_fsio_delete fail for inode: %lu name: %s",
					dest_parent_ino, dest_name);
				goto out;
			}
		}

		/*
		 * Create a clone of the object as new file.
		 * Get a ref on the new inode.
		 * Once done, add the inode to the namespace.
		 */
		err = ccowfs_inode_clone_get(src_inode, dest_ci, &dest_inode);
		if (err) {
			log_error(fsio_lg,
			    "clone_get return %d for src: %s inode: %lu dest:%s",
				err, src_ci->bid, src_inode->ino, dest_ci->bid);
			goto out;
		}

		err = fsio_link_internal(dest_ci, dest_parent_ino, dest_name,
		    dest_inode->ino, 0);
		if (err)
			log_softerror(fsio_lg, err,
				"fsio_link_internal fail for inode: %lu name: %s",
				dest_parent_ino, dest_name);
			goto out;
	}

out:
	if (err)
		log_softerror(fsio_lg, err,
		    "failed for src_bucket: %s to dest_bicket: %s inode: %lu "
		    "name: %s inode: %lu name:%s",
		    src_ci->bid, dest_ci->bid, src_parent_ino,
		    src_name, dest_parent_ino, dest_name);

	if (src_inode)
		ccowfs_inode_put(src_inode);

	/*
	 * If we hit error after we have created the new inode -
	 * It will be deleted as we drop the last ref. (since the link count
	 * will be zero)
	 */
	if (dest_inode)
		ccowfs_inode_put(dest_inode);

	log_debug(fsio_lg, "completed %s: src_bucket:%s src_parent_ino: %lu, "
	    "src_name: \"%s\", dest_bucket: %s, dest_parent_ino: %lu, "
	    "dest_name: \"%s\", flags: %u", __func__,
		src_ci->bid, src_parent_ino, src_name,
	    dest_ci->bid, dest_parent_ino, dest_name, flags);

	return err;
}
