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
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <lfq.h>

#include <ccow.h>
#include <ccowfsio.h>

#include "fsio_inode.h"
#include "fsio_dir.h"
#include "fsio_system.h"
#include "fsio_common.h"
#include "fsio_recovery.h"
#include "tc_pool.h"

#define UNKNOWN_OPERATION -1

int
__encode_recovery_entry(recovery_table_entry *entry, void **value,
    size_t * value_size)
{
	int err = 0;
	msgpack_p *p = msgpack_pack_init();
	uv_buf_t uv_b;

	log_trace(fsio_lg, "entry: %p, value: %p, value_size: %p",
	    entry, value, value_size);

	assert(entry->ver == RECOVERY_TABLE_VERSION_CURRENT);

	err = msgpack_pack_uint8(p, entry->ver);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint8 return %d",
		    err);
		return err;
	}

	err = msgpack_pack_uint8(p, (uint8_t) entry->optype);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint8 return %d",
		    err);
		return err;
	}

	err = msgpack_pack_uint64(p, entry->time);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d",
		    err);
		return err;
	}

	err = msgpack_pack_uint64(p, entry->ino);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d",
		    err);
		return err;
	}

	err = msgpack_pack_uint64(p, entry->source_ino);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d",
		    err);
		return err;
	}

	err = msgpack_pack_uint64(p, entry->dest_ino);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d",
		    err);
		return err;
	}

	err = msgpack_pack_str(p, entry->name);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_str return %d",
		    err);
		return err;
	}

	err = msgpack_pack_str(p, entry->new_name);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_str return %d",
		    err);
		return err;
	}

	err = msgpack_pack_uint64(p, entry->nlink);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d",
		    err);
		return err;
	}

	msgpack_get_buffer(p, &uv_b);

	*value = je_calloc(1, uv_b.len);
	if (!*value) {
		log_error(fsio_lg, "Failed to allocate memory");
		err = ENOMEM;
		goto out;
	}

	memcpy(*value, uv_b.base, uv_b.len);
	*value_size = uv_b.len;

out:
	if (p)
		msgpack_pack_free(p);

	log_debug(fsio_lg, "completed entry: %p, value: %p, "
	    "value_size: %p", entry, value, value_size);

	return err;
}

int
__decode_recovery_entry(void *value, size_t value_size,
    recovery_table_entry *entry)
{
	int err = 0;
	uint8_t optype;
	msgpack_u *u;

	log_trace(fsio_lg, "value: %p, value_size: %lu, entry: %p",
	    value, value_size, entry);

	u = msgpack_unpack_init(value, value_size, 0);
	err = msgpack_unpack_uint8(u, &entry->ver);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint8 return %d",
		    err);
		goto out;
	}

	if (entry->ver == RECOVERY_TABLE_VERSION_CURRENT) {
		err = msgpack_unpack_uint8(u, &optype);
		if (err) {
			log_error(fsio_lg, "msgpack_pack_uint8 return %d",
			    err);
			goto out;
		}
		entry->optype = optype;

		err = msgpack_unpack_uint64(u, &entry->time);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}

		err = msgpack_unpack_uint64(u, &entry->ino);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}

		err = msgpack_unpack_uint64(u, &entry->source_ino);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}

		err = msgpack_unpack_uint64(u, &entry->dest_ino);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}

		err = msgpack_unpack_str(u, entry->name, MAX_NAME_LEN);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_str return %d", err);
			goto out;
		}

		err = msgpack_unpack_str(u, entry->new_name, MAX_NAME_LEN);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_str return %d", err);
			goto out;
		}

		err = msgpack_unpack_uint64(u, &entry->nlink);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}

	} else {
		log_error(fsio_lg, "Unsupported entry version %d", entry->ver);
		err = EIO;
	}

out:
	if (u)
		msgpack_unpack_free(u);

	log_debug(fsio_lg, "completed value: %p, value_size: %lu, "
	    "entry: %p", value, value_size, entry);

	return err;
}

int
__insert_recovery_entry(ci_t *ci, fsio_api type, char *ino_str,
    inode_t ino, inode_t source_ino, inode_t dest_ino,
    char *name, char *new_name, nlink_t linkcount, uint64_t timestamp)
{
	int err = 0;
	recovery_table_entry entry;
	void *encoded_entry = NULL;
	size_t encoded_entry_len = 0;
	struct iovec iov[2];

	ccow_t tc;
	err = tc_pool_get_tc(ci->tc_pool_handle, ino, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		goto out;
	}

	entry.ver = RECOVERY_TABLE_VERSION_CURRENT;
	entry.optype = type;
	entry.ino = ino;
	entry.source_ino = source_ino;
	strncpy(entry.name, name, MAX_NAME_LEN);
	entry.name[MAX_NAME_LEN - 1] = '\0';
	entry.nlink = linkcount;

	if (timestamp > 0)
		entry.time = timestamp;
	else
		entry.time = get_nondecreasing_timestamp_us();

	if (type == MOVE) {
		entry.dest_ino = dest_ino;
		strncpy(entry.new_name, new_name, MAX_NAME_LEN);
		entry.new_name[MAX_NAME_LEN - 1] = '\0';
	} else if (type == DELETE) {
		entry.dest_ino = 0;
		entry.new_name[0] = '\0';
	} else {
		log_error(fsio_lg, "Unsupported operation type %d, for inode: "
		    "%lu", type, ino);
		err = EPERM;
		goto out;
	}

	err = __encode_recovery_entry(&entry, &encoded_entry,
	    &encoded_entry_len);
	if (err) {
		log_error(fsio_lg, "__encode_recovery_entry failed. err: %d",
		    err);
		goto out;
	}

	iov[0].iov_base = ino_str;
	iov[0].iov_len = strlen(ino_str) + 1;
	iov[1].iov_base = encoded_entry;
	iov[1].iov_len = encoded_entry_len;

	err = ccow_sharded_list_put(tc, ci->bid, ci->bid_size,
	     ci->recovery_context, iov, 2);
	if (err) {
		log_error(fsio_lg, "ccow_sharded_list_put failed. err: %d", err);
	}

out:
	if (encoded_entry)
		je_free(encoded_entry);

	return err;
}

int
__remove_recovery_entry(ci_t *ci, char *ino_str, inode_t ino)
{
	int err = 0;
	ccow_t tc;

	log_trace(fsio_lg, "%s inode: %s", __func__, ino_str);

	err = tc_pool_get_tc(ci->tc_pool_handle, ino, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		goto out;
	}

	err = ccow_sharded_list_delete(tc, ci->bid, ci->bid_size,
	    ci->recovery_context, ino_str, strlen(ino_str) + 1);
	if (err) {
		if (err == -ENOENT || err == ENOENT)
			err = ENOENT;

		if (err != ENOENT)
			log_error(fsio_lg, "ccow_sharded_list_delete failed, "
		   	    "inode: %s, err: %d", ino_str, err);
	}
out:
	log_debug(fsio_lg, "completed inode: %s", ino_str);
	return err;
}

int
ccowfs_recovery_insert_deleted(ccowfs_inode *inode, ccowfs_inode *parent_inode,
    char *name)
{
	int err = 0;

	err = __insert_recovery_entry(inode->ci, DELETE, inode->ino_str,
	    inode->ino, parent_inode->ino, 0, name, NULL,
	    atomic_get_uint64(&inode->stat.st_nlink), 0);

	return err;
}

int
ccowfs_recovery_insert_moved(ccowfs_inode *inode,
    ccowfs_inode *oldparent_inode, char *oldname,
    ccowfs_inode *newparent_inode, char *newname)
{
	int err = 0;

	err = __insert_recovery_entry(inode->ci, MOVE, inode->ino_str,
	    inode->ino, oldparent_inode->ino, newparent_inode->ino, oldname,
	    newname, atomic_get_uint64(&inode->stat.st_nlink), 0);

	return err;
}

int
ccowfs_recovery_remove(ccowfs_inode *inode)
{
	int err = 0;

	err = __remove_recovery_entry(inode->ci, inode->ino_str, inode->ino);
	if (err == ENOENT) {
		/* ignore if it doesn't exist */
		err = 0;
	}

	return err;
}

int
__add_to_lost_and_found(ccowfs_inode *inode, char *name)
{
	int err = 0, link_count = 0;
	ccowfs_inode *lf_inode = NULL;
	inode_t lookup = 0;

	log_trace(fsio_lg, "ci: %p, bid: %s, inode: %lu, name: %s", inode->ci,
	    inode->ci->bid, inode->ino, name);

	/* Note: Assumes inode has already been removed from old parent by
	 * __recover_move if needed.
	 */

	/* Get the .lost+found inode */
	err = ccowfs_inode_get_by_ino(inode->ci, CCOW_FSIO_LOST_FOUND_DIR_INODE,
	    &lf_inode);
	if (err) {
		log_error(fsio_lg, "ccowfs_inode_get_by_ino failure for "
		    ".lost+found inode: %d err: %d",
		    CCOW_FSIO_LOST_FOUND_DIR_INODE, err);
		goto out_nolock;
	}

	ccowfs_inode_lock_shared(lf_inode);

	if (INODE_IS_DISK_DIR(inode->ino))  {
		/* check ".." */
		link_count = 1;
		err = ccow_fsio_dir_lookup(inode->ci, inode, "..", &lookup);
		if (err == ENOENT) {
			/* add ".." link to parent .lost+found */
			err = ccow_fsio_dir_add_entry(inode->ci, inode, "..",
			    lf_inode, 0);
			if (err) {
				log_error(fsio_lg, "ccow_fsio_dir_add_entry "
				    "failure for .. inode: %lu, err: %d",
				    inode->ino, err);
				goto out;
			}
		} else if (err) {
			log_error(fsio_lg, "ccow_fsio_dir_lookup failure for "
			    ".. inode: %lu err: %d", inode->ino, err);
			goto out;
		}
	}

	/* Check if already in .lost+found */
	err = ccow_fsio_dir_lookup(inode->ci, lf_inode, name, &lookup);
	if (err == ENOENT) {
		err = ccow_fsio_dir_add_entry(inode->ci, lf_inode, name, inode,
		    link_count);
		if (err) {
			log_error(fsio_lg, "ccow_fsio_dir_add_entry "
			    "failure to .lost+found for inode: %lu, err: %d",
			    inode->ino, err);
		}
	}

out:
	ccowfs_inode_unlock_shared(lf_inode);

	ccowfs_inode_put(lf_inode);

out_nolock:

	log_debug(fsio_lg, "completed ci: %p, bid: %s, inode: %lu, name: %s",
	    inode->ci, inode->ci->bid, inode->ino, name);

	return err;
}

int
__recover_delete(ccowfs_inode *inode, recovery_table_entry *entry)
{
	int err = 0;
	int parent_exists = 0;
	int child_namespace_locked = 0;
	inode_t lookup = 0;

	ccowfs_inode *parent_inode = NULL;

	log_trace(fsio_lg, "ci: %p, bid %s, DELETE recovery for inode: %lu "
	    "name: %s source_ino: %lu nlink: %lu", inode->ci, inode->ci->bid,
	    inode->ino, entry->name, entry->source_ino, entry->nlink);

	/* Get the parent inode */
	err = ccowfs_inode_get_by_ino(inode->ci, entry->source_ino, &parent_inode);
	if (err == 0) {
		parent_exists = 1;
	} else {
		if (err != ENOENT) {
			log_error(fsio_lg, "ccowfs_inode_get_by_ino failure "
			    "inode: %lu err: %d", entry->source_ino, err);
			goto out_nolock;
		}
		/* If err was ENOENT, parent doesn't exist but continue
		 * on anyway to see if we can finish delete
		 */
		err = 0;
	}

	if (parent_exists) {
		ccowfs_namespace_inode_lock(parent_inode);

		err = ccow_fsio_dir_lookup(inode->ci, parent_inode,
		    entry->name, &lookup);

		/* Still exists in the old parent, so the delete failed right
		 * after the recovery entry was added, but before any real work
		 * was done. Make the client just re-execute the delete.
		 */
		if (err == 0 && lookup == inode->ino) {
			log_trace(fsio_lg,
			    "inode %lu still in old parent directory %lu",
			    entry->ino, parent_inode->ino);
			__remove_recovery_entry(inode->ci, inode->ino_str,
			    entry->ino);
			goto out;
		}

		/* Not ENOENT means other lookup error */
		if (err && err != ENOENT) {
			log_error(fsio_lg, "ccow_fsio_dir_lookup failure "
			    "inode: %lu, parent_inode: %lu, name: %s, "
			    "err: %d", inode->ino, parent_inode->ino,
			    entry->name, err);
			goto out;
		}

		/* ENOENT means delete failed after remove from old parent */
		err = 0;
	}

	if (INODE_IS_DISK_DIR(inode->ino))  {
		ccowfs_namespace_inode_lock(inode);
		child_namespace_locked = 1;

		/* Check on the ".." */
		lookup = 0;
		err = ccow_fsio_dir_lookup(inode->ci, inode, "..", &lookup);

		if (err && err != ENOENT) {
			log_error(fsio_lg, "ccow_fsio_dir_lookup failure .. in "
			    "inode: %lu, err %d", inode->ino, err);
			goto out;
		}

		/* ".." exists, the delete failed before ".." removed */
		if (err == 0) {
			/*
			 * Remove the ".." and decrement inode link count
			 */
			err = ccow_fsio_dir_remove_entry(inode->ci, inode,
			    "..", 2);
			if (err) {
				log_error(fsio_lg, "ccow_fsio_dir_remove_entry "
				    "failure .. inode: %lu, err: %d",
				    inode->ino, err);
				goto out;
			}
		}

		/* Otherwise is ENOENT and delete failed after removal of "..",
		 * or we just removed the ".."
		 */

		/* Mark directory as deleted and delete the on disk
		 * directory. The inode will go away when the last ref
		 * is put.
		 */
		err = ccow_fsio_dir_mark_deleted(inode);
		if (err) {
			log_error(fsio_lg,
			    "ccow_fsio_dir_mark_deleted return %d for inode: %lu",
			    err, inode->ino);
		}
	} else {
		/* TODO: This code goes along with existing logic for hard
		 * link support, even though that is currently disabled.
		 * Re-visit this when hard link added-- we can compare against
		 * the link count stored in recovery table entry.
		 */

		/* Check the link count. If link count > 0 then we failed
		 * before the unlink. Either way, the delete doesn't happen
		 * until the reference put in ccowfs_inode_put, and recovery
		 * entry will be deleted then as well.
		 */
		ccowfs_inode_lock(inode);
		if (inode->stat.st_nlink > 0) {
			/* Delete failed before the unlink. Drop the link
			 * count for the file. The inode will get marked
			 * deleted by the unlink.
			 */
			log_debug(fsio_lg, "Decreasing link count for inode: %lu "
			    "name: %s", inode->ino, entry->name);
			err = ccowfs_inode_unlink_locked(inode);
			if (err) {
				log_error(fsio_lg, "ccowfs_inode_unlink failure "
				    "inode: %lu err: %d", inode->ino, err);
				ccowfs_inode_unlock(inode);
				goto out;
			}
			ccowfs_inode_unlock(inode);
			err = ccowfs_inode_sync(inode, 1);
			if (err) {
				log_error(fsio_lg, "ccowfs_inode_sync return "
				    "%d for inode: %lu", err, inode->ino);
				goto out;
			}
		} else {
			/* Mark the inode deleted */
			log_debug(fsio_lg, "Marking deleted for inode: %lu "
			    "name: %s", inode->ino, entry->name);
			ccowfs_inode_mark_deleted(inode);
			ccowfs_inode_unlock(inode);
		}
	}

	log_trace(fsio_lg, "completed DELETE recovery ci: %p, bid %s, "
	    "inode: %lu", inode->ci, inode->ci->bid, inode->ino);

out:
	if (child_namespace_locked)
		ccowfs_namespace_inode_unlock(inode);
	if (parent_exists)
		ccowfs_namespace_inode_unlock(parent_inode);

out_nolock:
	if (parent_exists)
		ccowfs_inode_put(parent_inode);

	log_debug(fsio_lg, "ci: %p, bid %s, inode %lu, name: %s source_ino: "
	    "%lu nlink: %lu", inode->ci, inode->ci->bid, inode->ino,
	    entry->name, entry->source_ino, entry->nlink);

	return err;
}

int
__recover_move(ccowfs_inode *inode, recovery_table_entry *entry)
{
	int err = 0, err1 = 0;
	int source_exists = 0, dest_exists = 0, removed = 0;
	int parent_link_update = 0, child_locked = 0;
	ccowfs_inode *parent_inode = NULL;
	ccowfs_inode *dest_inode = NULL;
	inode_t lookup = 0, dotdot_ino = 0;

	log_trace(fsio_lg, "ci: %p, bid %s, MOVE recovery for inode: %lu "
	    "name: %s, source_ino: %lu, dest_ino: %lu, new_name: %s",
	    inode->ci, inode->ci->bid, inode->ino, entry->name,
	    entry->source_ino, entry->dest_ino, entry->new_name);

	pthread_mutex_lock(&inode->ci->rename_mutex);

	/* Get the source parent inode */
	err = ccowfs_inode_get_by_ino(inode->ci, entry->source_ino, &parent_inode);
	if (err == 0) {
		source_exists = 1;
	} else if (err != ENOENT) {
		log_error(fsio_lg, "ccowfs_inode_get_by_ino failure inode: %lu "
		    "err: %d", entry->source_ino, err);
		goto out_nolock;
	}
	/* If err was ENOENT, old parent doesn't exist but continue on anyway */

	/* Get the destination parent inode */
	err = ccowfs_inode_get_by_ino(inode->ci, entry->dest_ino, &dest_inode);
	if (err == 0) {
		dest_exists = 1;
	} else if (err != ENOENT) {
		log_error(fsio_lg, "ccowfs_inode_get_by_ino failure inode: %lu, "
		    "err %d", entry->dest_ino, err);
		goto out_nolock;
	}

	if (dest_exists)
		ccowfs_inode_lock_shared(dest_inode);

	if (source_exists) {
		ccowfs_inode_lock_shared(parent_inode);

		err = ccow_fsio_dir_lookup(inode->ci, parent_inode,
		    entry->name, &lookup);

		/* Still exists in the old parent, so the move failed right
		 * after the recovery entry was added, but before any real work
		 * was done. Make the client just re-execute the move.
		 */
		if (err == 0 && lookup == inode->ino) {
			log_trace(fsio_lg,
			    "inode %lu still in old parent directory %lu",
			    entry->ino, parent_inode->ino);
			/* go to remove entry */
			goto cleanup;
		}

		/* ENOENT means move failed after remove from old parent */

		/* Not ENOENT means other lookup error */
		if (err && err != ENOENT) {
			log_error(fsio_lg, "ccow_fsio_dir_lookup failure "
			    "inode: %lu, parent_inode: %lu, name: %s, "
			    "err: %d", inode->ino, parent_inode->ino,
			    entry->name, err);
			goto out;
		}
	}

	if (entry->source_ino != entry->dest_ino &&
	    INODE_IS_DISK_DIR(inode->ino))  {

		parent_link_update = 1;

		ccowfs_inode_lock_shared(inode);
		child_locked = 1;

		/* what is the status of the ".." */
		err = ccow_fsio_dir_lookup(inode->ci, inode, "..", &dotdot_ino);

		if (err && err != ENOENT) {
			log_error(fsio_lg, "ccow_fsio_dir_lookup failure .. in "
			    "inode: %lu, err %d", inode->ino, err);
			goto out;
		}

		/* The move failed after the remove entry,
		 * ".." exists but still points to old parent
		 */
		if (err == 0 && dotdot_ino == entry->source_ino) {
			err1 = ccow_fsio_dir_remove_entry(inode->ci, inode,
			    "..", 0);
			if (err1) {
				log_error(fsio_lg, "ccow_fsio_dir_remove_entry "
				    "failure .. inode: %lu, err: %d",
				    inode->ino, err);
				err = err1;
				goto out;
			}
			removed = 1;
		}

		/* The ".." doesn't exist,
		 *    move failed after unlink from old parent
		 * or we just unlinked it above from old parent
		 */
		if ((err == ENOENT || removed) && dest_exists) {
			err = ccow_fsio_dir_add_entry(inode->ci, inode, "..",
			    dest_inode, 0);
			if (err) {
				log_error(fsio_lg, "ccow_fsio_dir_add_entry "
				    "failure .. inode: %lu, dest_inode: %lu, "
				    "err: %d", inode->ino, dest_inode->ino, err);
				goto out;
			}
		}
	}

	if (dest_exists) {
		/* Add to new parent if needed */
		err = ccow_fsio_dir_lookup(inode->ci, dest_inode,
		    entry->new_name, &lookup);
		if (err == ENOENT) {
			err = ccow_fsio_dir_add_entry(inode->ci, dest_inode,
			    entry->new_name, inode, parent_link_update);
			if (err) {
				log_error(fsio_lg,
				    "ccow_fsio_dir_add_entry failure "
				    "inode: %lu, dest_inode: %lu, new_name: %s, "
				    "err: %d", inode->ino, dest_inode->ino,
				    entry->new_name, err);
				goto out;
			}
		} else if (err) {
			/* some other lookup error */
			log_error(fsio_lg, "ccow_fsio_dir_lookup inode: %lu, "
			    "dest_inode: %lu, new_name: %s, err: %d",
			    inode->ino, dest_inode->ino, entry->new_name, err);
			goto out;
		}
	} else {
		log_warn(fsio_lg, "Move destination does not exist, adding to "
		    ".lost+found, inode: %lu, name: %s, dest_inode: %lu",
		    inode->ino, entry->new_name, entry->dest_ino);
		err = __add_to_lost_and_found(inode, entry->new_name);
		if (err) {
			log_error(fsio_lg, "__add_to_lost_and_found failure "
			    "inode: %lu err: %d", inode->ino, err);
			goto out;
		}
	}

cleanup:
	/* Clean up, ignore error on remove recovery entry */
	ccowfs_recovery_remove(inode);
	log_trace(fsio_lg, "completed MOVE recovery ci: %p, bid %s, inode: %lu",
	    inode->ci, inode->ci->bid, inode->ino);

out:
	if (child_locked)
		ccowfs_inode_unlock_shared(inode);
	if (parent_inode)
		ccowfs_inode_unlock_shared(parent_inode);
	if (dest_inode)
		ccowfs_inode_unlock_shared(dest_inode);

out_nolock:
	if (parent_inode)
		ccowfs_inode_put(parent_inode);
	if (dest_inode)
		ccowfs_inode_put(dest_inode);

	pthread_mutex_unlock(&inode->ci->rename_mutex);

	log_debug(fsio_lg, "ci: %p, bid %s, inode %lu, name: %s, "
	    "source_ino: %lu, dest_ino: %lu, new_name: %s",
	    inode->ci, inode->ci->bid, inode->ino, entry->name,
	    entry->source_ino, entry->dest_ino, entry->new_name);

	return err;
}

int
__recover_orphan_inode(ci_t *ci, char *ino_str, recovery_table_entry *entry)
{
	int err = 0;
	ccowfs_inode *inode = NULL;

	if (entry->ver == RECOVERY_TABLE_VERSION_CURRENT) {

		/* Get the inode of entry. We use special api to
		 * for recovery that allows us to get inodes with 0
		 * link count, which may be the case for orphaned deletes.
		 */
		err = ccowfs_inode_get_by_ino_for_recovery(ci, entry->ino,
		    &inode);
		if (err) {
			if (err == ENOENT) {
				 /* Doesn't exist anymore */
				log_warn(fsio_lg, "inode: %lu no longer exists",
				    entry->ino);
				__remove_recovery_entry(ci, ino_str, entry->ino);
			} else {
				log_error(fsio_lg,
				    "ccowfs_inode_get_by_ino failure "
				    "inode: %lu, err %d", entry->ino, err);
			}
			goto out;
		}

		if (entry->optype == MOVE) {
			err = __recover_move(inode, entry);
			if (err) {
				log_error(fsio_lg, "recovery failed inode: %lu, "
				    "err: %d", inode->ino, err);
			}
		} else if (entry->optype == DELETE) {
			err = __recover_delete(inode, entry);
			if (err) {
				log_error(fsio_lg, "recovery failed inode: %lu, "
				    "err: %d", inode->ino, err);
			}
		} else {
			log_error(fsio_lg, "Unsupported recovery operation %d",
			    entry->optype);
			err = EPERM;
		}
	} else {
		log_error(fsio_lg, "Unsupported entry version %d", entry->ver);
		err = EIO;
	}

out:
	if (inode)
		ccowfs_inode_put(inode);

	return err;
}

int
ccowfs_recovery_handler(ci_t *ci)
{
	int err = 0;
	struct iovec iov[1];
	uint64_t current_time;
	recovery_table_entry entry;
	ccow_lookup_t iter = NULL;
	ccow_t tc;

	log_trace(fsio_lg, "ci: %p, bid %s", ci, ci->bid);

	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		goto out;
	}


	iov[0].iov_base = NULL;
	iov[0].iov_len = 0;

	err = ccow_sharded_get_list(tc, ci->bid, ci->bid_size,
	    ci->recovery_context, NULL, 0, NULL,
	    RECOVERY_HANDLER_MAX_ENTRIES, &iter);
	if (err) {
		log_error(fsio_lg,
		    "ccow_sharded_list_get return error %d", err);       
	}           

	if (iter != NULL) {
		struct ccow_metadata_kv *kv = NULL;
		int pos = 0;
		current_time = get_nondecreasing_timestamp_us();
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
			    pos++)) != NULL) {

			if (kv->key == NULL || kv->value == NULL) {
				continue;
			}

			memset(iov, 0, sizeof(iov));

			if (kv->value_size) {
				iov[0].iov_len = kv->value_size;
				iov[0].iov_base = je_malloc(kv->value_size);
				memcpy(iov[0].iov_base, kv->value, kv->value_size);

				err = __decode_recovery_entry(iov->iov_base,
				    iov->iov_len, &entry);
				if (err) {
					log_error(fsio_lg,
					    "__decode_recovery_entry failed. "
					    "key: %s, err: %d", kv->key, err);
				} else {
					/* 
					 * We only attempt recovery of orphan
					 * after RECOVERY_HANDLER_THRESHHOLD
					 * amount of time has elapsed
					 */
					if (current_time - entry.time >
					    RECOVERY_HANDLER_THRESHHOLD) {
						__recover_orphan_inode(ci, kv->key, &entry);
					}
				}
				je_free(iov[0].iov_base);
			}
		}
	}

out:
	if (iter)
		ccow_lookup_release(iter);

	if (err) {
		ci->ccow_err = err;

		if (err == -ENOENT || err == ENOENT)
			err = ENOENT;

		if (err != ENOENT)
			log_error(fsio_lg,
			    "%s failed for bucket: %s err: %d",
			    __func__, ci->bid, err);
	}

	log_debug(fsio_lg,
		"completed recovery Bucket: %s, err: %d", ci->bid, err);

	return err;
}

int
testonly_recovery_entry_exists(ci_t *ci, inode_t ino, int type)
{
	int err = 0, ret = 0;
	recovery_table_entry entry;
	char ino_str[22];
	struct iovec iov[1];

	log_trace(fsio_lg, "ci: %p, ino: %lu", ci, ino);

	entry.ver = 0;
	entry.optype = UNKNOWN_OPERATION;
	entry.ino = 0;
	entry.dest_ino = 0;
	iov[0].iov_len = 0;
	iov[0].iov_base = NULL;

	ccow_t tc;
	
	err = tc_pool_get_tc(ci->tc_pool_handle, ino, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		goto out;
	}

	sprintf(ino_str, "%" PRIu64, (uint64_t)ino);
	err = ccow_sharded_list_get(tc, ci->bid, ci->bid_size,
	    ci->recovery_context, ino_str, strlen(ino_str) + 1, iov, 1);

	if (err) {
		if (err == ENOENT || err == -ENOENT) {
			err = ENOENT;
		}
		if (err != ENOENT)
			log_error(fsio_lg,
			    "ccow_sharded_list_get failed. err: %d", err);
		goto out;
	}

	if (iov[0].iov_len && iov[0].iov_base) {
		err = __decode_recovery_entry(iov[0].iov_base, iov[0].iov_len,
		    &entry);
		log_debug(fsio_lg, "recovery entry ver: %d, optype: %d, "
		    "time: %lu, ino: %lu, source_ino: %lu, dest_ino: %lu, "
		    "name: %s, new_name: %s", entry.ver, entry.optype,
		    entry.time, entry.ino, entry.source_ino, entry.dest_ino,
		    entry.name, entry.new_name);
		if (!err && entry.optype == (fsio_api) type)
			ret = 1;
		je_free(iov[0].iov_base);
		iov[0].iov_base = NULL;
	}

out:
	log_debug(fsio_lg, "completed ci: %p, ino: %lu", ci, ino);

	return ret;
}

int
testonly_recovery_insert_moved(ci_t *ci, inode_t child_ino,
    inode_t src_ino, char *old_name, inode_t dest_ino, char *new_name,
    nlink_t linkcount, uint64_t timestamp)
{
	int err;
	char ino_str[22];
	
	log_trace(fsio_lg, "ci: %p, ino: %lu, src_ino: %lu, dest_ino: %lu, "
	    "old_name: %s, new_name: %s, linkcount: %lu, timestamp: %lu", ci,
	    child_ino, src_ino, dest_ino, old_name, new_name, linkcount,
	    timestamp);

	sprintf(ino_str, "%" PRIu64, (uint64_t)child_ino);
	err = __insert_recovery_entry(ci, MOVE, ino_str, child_ino, src_ino,
	    dest_ino, old_name, new_name, linkcount, timestamp);
	if (err) {
		log_error(fsio_lg, "__insert_recovery_entry returned %d, "
		    "ino: %lu", err, child_ino);
	}

	log_debug(fsio_lg, "completed ci: %p, ino: %lu", ci, child_ino);

	return err;
}

int
testonly_recovery_insert_deleted(ci_t *ci, inode_t ino, inode_t parent_ino,
    char *name, nlink_t linkcount, uint64_t timestamp)
{
	int err;
	char ino_str[22];
	
	log_trace(fsio_lg, "ci: %p, ino: %lu, parent_ino: %lu, name: %s, "
	    "linkcount: %lu, timestamp: %lu", ci, ino, parent_ino, name,
	    linkcount, timestamp);

	sprintf(ino_str, "%" PRIu64, (uint64_t)ino);
	err = __insert_recovery_entry(ci, DELETE, ino_str, ino, parent_ino,
	    0, name, NULL, linkcount, timestamp);
	if (err) {
		log_error(fsio_lg, "__insert_recovery_entry returned %d, "
		    "ino: %lu", err, ino);
	}

	log_debug(fsio_lg, "completed ci: %p, ino: %lu", ci, ino);

	return err;
}

int
testonly_recovery_remove_entry(ci_t *ci, inode_t ino)
{
	char ino_str[22];
	sprintf(ino_str, "%" PRIu64, (uint64_t)ino);
	
	return __remove_recovery_entry(ci, ino_str, ino);
}

int
testonly_recovery_handler(ci_t *ci)
{
	return ccowfs_recovery_handler(ci);
}
