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
#include <stdlib.h>
#include <lfq.h>

#include <ccow.h>
#include <ccowfsio.h>

#include <fsio_system.h>
#include <fsio_common.h>
#include <fsio_inode.h>
#include <fsio_namespace.h>
#include <fsio_s3_transparency.h>
#include <fsio_snapshot.h>
#include <fsio_dir.h>
#include <fsio_recovery.h>
#include <tc_pool.h>

/* [TBD] At presetn adding and removing to the export list is not guarded by
 * any lock.
 * The addExport and removeExport happen in Ganesha dBus thread.
 * We are safe as there is one dBus thread in Ganesha.
 * Will need to revisit this if and when this changes.
 */
QUEUE nedge_fsio_export_list;
Logger fsio_lg = NULL;
void *control_thread_handle;
int ccow_mh_immdir = 0;


/**
 * Implements system related interfaces.
 *  Init, term
 * Manages the on disk system related objects (otherwise hidden from user)
 *  obj_root, s3obj_root, deleted_inode_table, server_id and inode master
 * Responsible for generating unique inode number
 */

static int
__lookup_server_id(ccow_t tc, const char *cid, size_t cid_size,
    const char *tid, size_t tid_size,
    const char *bid, size_t bid_size,
    const char *server_id_str, uint64_t * inode_server_id)
{
	int err;
	struct ccow_metadata_kv *kv = NULL;
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	struct iovec iov[1];
	char *e;

	iov[0].iov_base = NULL;
	iov[0].iov_len = 0;

	log_trace(fsio_lg, "tc: %p, cid: %p, cid_size: %lu, "
	    "tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "server_id_str: %p, inode_server_id: %p", tc, cid, cid_size, tid,
	    tid_size, bid, bid_size, server_id_str, inode_server_id);

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccow_create_completion return err=%d", err);
		goto out;
	}

	err = set_btree(c, NULL);
	if (err) {
		log_error(fsio_lg, "set_btree return err=%d", err);
		goto out;
	}

	err = ccow_get_list(bid, bid_size, INODE_MASTER_STR,
	    strlen(INODE_MASTER_STR) + 1, c,
	    (struct iovec *) &iov, 1, MAX_SERVER_ID, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_get_list return err=%d",
		    err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_error(fsio_lg,
		    "ccow_create_completion return %d", err);
		goto out;
	}

	c = NULL;

	if (iter != NULL) {
		int pos = 0;

		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
		    pos++)) != NULL) {
			if (kv->key && kv->value
			    && strcmp(server_id_str, kv->value) == 0) {
				*inode_server_id = strtoull(kv->key, &e, 0);
				assert(*e == '\0');
				assert(*inode_server_id <= MAX_SERVER_ID);
				goto out;
			}
		}
		err = ENOENT;
	} else
		err = ENOENT;

out:
	if (iter)
		ccow_lookup_release(iter);

	if (c)
		ccow_release(c);

	log_debug(fsio_lg, "completed tc: %p, cid: %p, "
	    "cid_size: %lu, tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "server_id_str: %p, inode_server_id: %p", tc, cid, cid_size, tid,
	    tid_size, bid, bid_size, server_id_str, inode_server_id);

	return err;
}

static int
__get_free_server_id_index(ccow_t tc, const char *cid, size_t cid_size,
    const char *tid, size_t tid_size,
    const char *bid, size_t bid_size,
    const char *server_id_str, uint64_t * new_server_id)
{
	int err, i;
	struct ccow_metadata_kv *kv = NULL;
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	struct iovec iov[1];
	uint64_t used_id_list[MAX_SERVER_ID + 1] = { 0 };
	uint64_t used_id = 0;
	char *e;

	iov[0].iov_base = NULL;
	iov[0].iov_len = 0;

	log_trace(fsio_lg, "tc: %p, cid: %p, cid_size: %lu, "
	    "tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, server_id_str: %p,"
	    " new_server_id: %p", tc, cid, cid_size, tid, tid_size, bid,
	    bid_size, server_id_str, new_server_id);

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

	err = ccow_get_list(bid, bid_size, INODE_MASTER_STR,
	    strlen(INODE_MASTER_STR) + 1, c,
	    (struct iovec *) &iov, 1, MAX_SERVER_ID, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_get_list return %d", err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_error(fsio_lg, "ccow_wait return %d", err);
		goto out;
	}

	c = NULL;

	if (iter != NULL) {
		int pos = 0;

		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
		    pos++)) != NULL) {
			if (kv->key && kv->value) {
				used_id = strtoull(kv->key, &e, 0);
				assert(*e == '\0');
				assert(used_id <= MAX_SERVER_ID);

				used_id_list[used_id] = 1;
			}
		}
	}

	for (i = 0; i <= MAX_SERVER_ID; i++) {
		if (used_id_list[i] == 0) {
			/*
			 * Found unused server is
			 */
			*new_server_id = i;
			goto out;
		}
	}

	/*
	 * No free server id
	 */
	assert(0);
out:
	if (iter)
		ccow_lookup_release(iter);

	if (c)
		ccow_release(c);

	log_debug(fsio_lg, "completed tc: %p, cid: %p, "
	    "cid_size: %lu, tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "server_id_str: %p, new_server_id: %p", tc, cid, cid_size, tid,
	    tid_size, bid, bid_size, server_id_str, new_server_id);

	return err;
}

static int
__inode_master_create(ccow_t tc, const char *cid, size_t cid_size,
    const char *tid, size_t tid_size, const char *bid, size_t bid_size)
{
	int err;
	ccow_completion_t c = NULL;
	struct iovec iov[2];

	log_trace(fsio_lg, "tc: %p, cid: %p, cid_size: %lu, "
	    "tid: %p, tid_size: %lu, bid: %p, bid_size: %lu", tc, cid,
	    cid_size, tid, tid_size, bid, bid_size);
	/*
	 * Create the INODE_MASTER_STR object if note present
	 * ccow_put_notrlog will create it if it is not present, acts like noop
	 * otherwise.
	 */
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

	err = ccow_put_notrlog(bid, bid_size, INODE_MASTER_STR,
	    strlen(INODE_MASTER_STR) + 1, c, NULL, 0, 0);
	if (err) {
		log_error(fsio_lg, "ccow_put_notrlog return %d",
		    err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err && err != -EEXIST) {
		log_error(fsio_lg, "ccow_wait return %d", err);
		goto out;
	}

	c = NULL;

	/*
	 * Insert one dummy entry in the btree. This is done for two reasons:
	 * 1. To reserver the server id 0 for future use
	 * 2. Sometimes the ccow_get_list() fails if we have never inserted any
	 * entry in the list.
	 */
	err = list_insert(tc, cid, cid_size, tid, tid_size, bid, bid_size,
	    INODE_MASTER_STR, "0", "0");
	if (err == -EEXIST || err == EEXIST)
		err = 0;

out:
	if (c)
		ccow_release(c);

	log_debug(fsio_lg, "completed tc: %p, cid: %p, "
	    "cid_size: %lu, tid: %p, tid_size: %lu, bid: %p, bid_size: %lu",
	    tc, cid, cid_size, tid, tid_size, bid, bid_size);

	return err;
}

static int
__create_deleted_inode_table(ci_t *ci, ccow_t tc)
{
	int err;
	ccow_lookup_t iter;
	ccow_completion_t c;

	log_trace(fsio_lg, "ci: %p, cid: %p, cid_size: %lu, "
	    "tid: %p, tid_size: %lu, bid: %p, bid_size: %lu", ci, ci->cid,
	    ci->cid_size, ci->tid, ci->tid_size, ci->bid, ci->bid_size);

	/*
	 * Create the RECOVERY_TABLE_STR object if not present
	 */

	/* create a sharded table context */
	err = ccow_shard_context_create(
	    RECOVERY_TABLE_STR, strlen(RECOVERY_TABLE_STR) + 1,
	    RECOVERY_TABLE_SHARD_COUNT, &ci->recovery_context);
	if (err) {
		log_error(fsio_lg, "ccow_shard_context_create return error %d",
		    err);
		goto out;
	}

	/* allow overwrite of table entries */
	ccow_shard_context_set_overwrite(ci->recovery_context,
	    CCOW_CONT_F_INSERT_LIST_OVERWRITE);

	ccow_shard_context_set_inline_flag(ci->recovery_context,
		RT_INLINE_DATA_TYPE_NFS_AUX);


	c = NULL;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(fsio_lg, "ccow_create_completion failed. err: %d", err);
		goto out;
	}

	iter = NULL;
	err = ccow_get(ci->bid, ci->bid_size, RECOVERY_TABLE_STR,
	    strlen(RECOVERY_TABLE_STR) + 1, c, NULL, 0, 0, &iter);
	if (err || !iter) {
		log_error(fsio_lg, "ccow_get failed. err: %d", err);
		goto out;
	}

	err = ccow_wait(c, -1);
	if (err == ENOENT || err == -ENOENT) {
		/* create the table */

		err = ccow_sharded_list_create(tc, ci->bid, ci->bid_size,
		    ci->recovery_context);
		if (err) {
			log_error(fsio_lg, "ccow_sharded_list_create return "
			    "error %d", err);
			goto out;
		}
		log_trace(fsio_lg, "Recovery table created for bucket: %s",
		    ci->bid);
		err = 0;
	} else if (err) {
		log_error(fsio_lg, "ccow_wait failed. err: %d", err);
	}
out:
	if (iter)
		ccow_lookup_release(iter);
	if (c)
		ccow_release(c);

	if (err) {
		log_error(fsio_lg, "failed for bucket: %s, err: %d",
		    ci->bid, err);

		if (ci->recovery_context) {
			ccow_shard_context_destroy(&ci->recovery_context);
			ci->recovery_context = NULL;
		}
	}

	log_debug(fsio_lg, "completed ci: %p, cid: %p, cid_size: %lu, tid: %p, "
	    "tid_size: %lu, bid: %p, bid_size: %lu", ci, ci->cid, ci->cid_size,
	    ci->tid, ci->tid_size, ci->bid, ci->bid_size);

	return err;
}

static int
__inode_master_get_server_id(ccow_t tc, const char *cid, size_t cid_size,
    const char *tid, size_t tid_size,
    const char *bid, size_t bid_size,
    const char *server_id_str, uint64_t * inode_server_id)
{
	int err;
	uint64_t my_server_id;
	uint64_t retry_count = MAX_SERVER_ID;
	char __server_id[MAX_SERVER_ID_STR] = { 0 };

	log_trace(fsio_lg, "tc: %p, cid: %p, cid_size: %lu, "
	    "tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "server_id_str: %p, inode_server_id: %p", tc, cid, cid_size, tid,
	    tid_size, bid, bid_size, server_id_str, inode_server_id);
	/*
	 * Check if the server id is alread present on the inode master
	 */
	err = __lookup_server_id(tc, cid, cid_size, tid, tid_size,
	    bid, bid_size, server_id_str, inode_server_id);
	if (!err) {
		/*
		 * Found the server id
		 */
		goto out;
	}

	while (retry_count) {
		err = __get_free_server_id_index(tc, cid, cid_size, tid,
		    tid_size, bid, bid_size, server_id_str, &my_server_id);
		if (err) {
			log_error(fsio_lg,
			    "__get_free_server_id_index return %d", err);
			goto out;
		}

		/*
		 * Add it to the server master
		 */
		snprintf(__server_id, MAX_SERVER_ID_STR, "%ju", my_server_id);

		err = list_insert(tc, cid, cid_size, tid, tid_size,
		    bid, bid_size, INODE_MASTER_STR, __server_id,
		    server_id_str);
		if (err) {
			if (err == -EEXIST || err == EEXIST) {
				retry_count--;
				continue;
			}
			goto out;
		} else
			break;
	}

	/*
	 * Read the server id from the inode master again to be sure.
	 */
	err = __lookup_server_id(tc, cid, cid_size, tid, tid_size,
	    bid, bid_size, server_id_str, inode_server_id);
	if (!err) {
		/*
		 * Found the server id.
		 */
		goto out;
	}

	/*
	 * We canot do anything if we don't get a server_id
	 */
	nassert(0);

out:
	log_debug(fsio_lg, "completed tc: %p, cid: %p, "
	    "cid_size: %lu, tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "server_id_str: %p, inode_server_id: %p", tc, cid, cid_size, tid,
	    tid_size, bid, bid_size, server_id_str, inode_server_id);

	return err;
}

static int
__get_bucket_attrs(ci_t * ci)
{
	ccow_completion_t c = NULL;
	struct ccow_metadata_kv *kv;
	ccow_lookup_t iter = NULL;
	int err, pos = 0;
	struct iovec iov;

	log_trace(fsio_lg, "ci: %p", ci);

	err = ccowfs_create_completion(ci, NULL, NULL, 0, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_create_completion return %d", err);
		goto out;
	}

	iov.iov_base = NULL;
	iov.iov_len = 0;

	err = ccow_get(ci->bid, ci->bid_size, "", 1, c, (struct iovec *) &iov,
	    0, 0, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_get return %d", err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_wait fail");
		goto out;
	}

	c = NULL;

	if (iter == NULL)
		goto out;

	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, pos++))) {
		if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0)
			ci->bk_attrs.chunk_size = *((uint32_t *) kv->value);
		else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_BTREE_MARKER) == 0)
			ci->bk_attrs.chunkmap_btree_marker =
			    *((uint8_t *) kv->value);
		else if (strcmp(kv->key, RT_SYSKEY_SYNC_PUT) == 0)
			ci->bk_attrs.sync_put = *((uint8_t *) kv->value);
		else if (strcmp(kv->key, RT_SYSKEY_REPLICATION_COUNT) == 0)
			ci->bk_attrs.replication_count =
			    *((uint8_t *) kv->value);
		else if (strcmp(kv->key, RT_SYSKEY_EC_ENABLED) == 0)
			ci->bk_attrs.ec_enabled = *((uint8_t *) kv->value);
		else if (strcmp(kv->key, RT_SYSKEY_EC_DATA_MODE) == 0)
			ci->bk_attrs.ec_data_mode = *((uint32_t *) kv->value);
		else if (strcmp(kv->key, RT_SYSKEY_EC_TRG_POLICY) == 0)
			ci->bk_attrs.ec_trg_policy = *((uint64_t *) kv->value);
		else if (strcmp(kv->key,
		    RT_SYSKEY_FILE_OBJECT_TRANSPARANCY) == 0)
			ci->bk_attrs.file_object_transparency =
			    *((uint8_t *) kv->value);
	}

	if (ci->bk_attrs.chunk_size == 0) {
		err = EIO;
		log_error(fsio_lg, "Invalid bucket chunkmap_chunk_size "
		    "attribute. Value: 0");
	}

out:
	if (iter)
		ccow_lookup_release(iter);

	if (c)
		ccow_release(c);

	if (err) {
		ci->ccow_err = err;
	}
	log_debug(fsio_lg, "completed ci: %p", ci);

	return err;
}

static int
__get_inode_master(ccow_t tc, const char *cid, size_t cid_size,
    const char *tid, size_t tid_size,
    const char *bid, size_t bid_size,
    const char *server_id_str, uint64_t * inode_server_id)
{
	int err;

	log_trace(fsio_lg, "tc: %p, cid: %p, cid_size: %lu, "
	    "tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "server_id_str: %p, inode_server_id: %p", tc, cid, cid_size, tid,
	    tid_size, bid, bid_size, server_id_str, inode_server_id);

	err = __inode_master_create(tc, cid, cid_size, tid, tid_size,
	    bid, bid_size);
	if (err) {
		log_error(fsio_lg,
		    "__inode_master_create return %d", err);
		goto out;
	}

	err = __inode_master_get_server_id(tc, cid, cid_size, tid, tid_size,
	    bid, bid_size, server_id_str, inode_server_id);
	if (err) {
		log_error(fsio_lg,
		    "__inode_master_get_server_id return %d", err);
		goto out;
	}

	assert(*inode_server_id <= MAX_SERVER_ID);

	/*
	 * We want to export same bucket from multiple instances of Ganesha
	 * server.
	 *  [inode number generation]
	 *      -  inode number can be 64 bit max. It needs to be unique across
	 *         all the servers running Ganesha service.
	 *      -  Higher 4 bits are reserved for other usage
	 *      -  Middle 9 bits are reserved for server_id. This means we can
	 *         have maximum 512 servers running Ganesha service at a time.
	 *      -  Lower 51 bits are used for timestamp. This will wrap around
	 *         in about 70 years.
	 *
	 *  [Maintain uniqueness]
	 *      - We will create hidden object in the NFS exported bucker as
	 *        INODE_MASTER_STR
	 *      - This object will be BTREE.
	 *      - Ganesha service will add the key:value entry in this BTEE.
	 *        key: unique_9_bit_number value: ccow_serverid
	 *        If the ccow_serverid is already present, it will just use the
	 *        9_bit value as the serverid part of inode. (ci->inode_serverid)
	 *        If key is not present, then it will check all the key:values
	 *        used by other servers and add unique number.
	 *        e.g. server "4EF572BBD089FBF4A0AB0607354FB1A4" can get the
	 *        index 5.
	 *             Then Ganesha running on this server will use "5" as part
	 *        of the inode when creating any newinode
	 *        This way we can guaranty that, the inode number generated by
	 *        multiple servers are unique for minimum ~70 years.
	 */

out:
	log_debug(fsio_lg, "completed tc: %p, cid: %p, "
	    "cid_size: %lu, tid: %p, tid_size: %lu, bid: %p, bid_size: %lu, "
	    "server_id_str: %p, inode_server_id: %p", tc, cid, cid_size, tid,
	    tid_size, bid, bid_size, server_id_str, inode_server_id);

	return err;
}

static int
__create_root_obj(ci_t * ci)
{
	ccowfs_inode *root_inode = NULL;
	uint16_t mode = S_IFDIR | (07755);
	inode_t lookup = 0;
	int err, create = 0;

	log_trace(fsio_lg, "ci: %p", ci);
	/*
	 * Check if object with name ROOT_INODE_STR is present.
	 * Create it if not present.
	 *
	 * Use the special interface for recovery, to allow retrieval of
	 * inode even if link count is 0, as in the case of an unclean
	 * shutdown. Then we can recover inode and finish creation.
	 */
	err = ccowfs_inode_get_by_ino_for_recovery(ci, CCOW_FSIO_ROOT_INODE,
	    &root_inode);
	if (err == ENOENT) {
		log_info(fsio_lg, "Creating FSIO root for bucket: %s",
		    ci->bid);

		err = ccowfs_inode_create_new_get(ci, CCOW_FSIO_ROOT_INODE,
		    mode, 0, 0, NULL, &root_inode, NULL);
		if (err) {
			log_error(fsio_lg,
			    "ccowfs_inode_create_new_get return %d", err);
			goto out;
		}
		create = 1;
	} else if (err) {
		log_error(fsio_lg, "ccowfs_inode_get_by_ino_for_recovery "
		    "return %d", err);
		goto out;
	}

	/* Check for namespace ".." */
	err = ccow_fsio_dir_lookup(ci, root_inode, "..", &lookup);
	if (err == ENOENT) {
		/* Link count for both self and "." (2) is passed in here */
		err = ccow_fsio_dir_add_entry(ci, root_inode, "..",
		    root_inode, 2);
		if (err) {
			log_error(fsio_lg,
			    "ccow_fsio_dir_add_entry for \"..\", return %d",
			    err);
			goto out;
		}
		err = 0;
	}

out:
	if (err) {
		log_error(fsio_lg, "failed for cid: %s tid :%s bid: %s err: %d",
			ci->cid, ci->tid, ci->bid, err);
		if (create) {
			/* Cleanup the root object */
			err = ccow_fsio_dir_if_empty_mark_deleted(root_inode);
			if (err) {
				log_error(fsio_lg,
				    "ccow_fsio_dir_if_empty_mark_deleted return "
				    "%d for inode: %lu", err, root_inode->ino);
			}
		}
	}
	if (root_inode)
		ccowfs_inode_put(root_inode);

	log_debug(fsio_lg, "completed ci: %p", ci);

	return err;
}

/**
 * Create the on disk layout.
 * We just create the hidden objects required for the FS functionality.
 * If the hidden objects are already present, do nothing.
 */
static int
__mkfs(ci_t * ci)
{
	int ccow_fd, err;

	log_trace(fsio_lg, "ci: %p", ci);
	char srv_path[PATH_MAX];
	snprintf(srv_path, sizeof(srv_path), SERVERID_CACHE_FILE, nedge_path());

	if ((ccow_fd = open(srv_path, O_RDONLY)) < 0) {
		log_error(fsio_lg, "Cannot open SERVERID cache file: %s",
		    strerror(errno));
		err = -1;
		goto out;
	}

	memset(ci->ccow_serverid, 0, UINT128_BYTES * 2 + 1);
	if (read(ccow_fd, ci->ccow_serverid, UINT128_BYTES * 2 + 1) < 0) {
		log_error(fsio_lg, "Cannot read SERVERID cache: %s",
		    strerror(errno));
		close(ccow_fd);
		err = -1;
		goto out;
	}
	close(ccow_fd);

	err = __get_bucket_attrs(ci);
	if (err) {
		if (err == -ENOENT)
			goto out;
		log_error(fsio_lg, "__get_bucket_attrs return %d", err);
		goto out;
	}

	ccow_t tc;
	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}

	err = __get_inode_master(tc, ci->cid, ci->cid_size,
	    ci->tid, ci->tid_size,
	    ci->bid, ci->bid_size, ci->ccow_serverid, &ci->inode_serverid);
	if (err) {
		/*
		 * We cannot go ahead without the inode_server_id
		 */
		log_error(fsio_lg,
		    "Failed to get inode_server_id, err: %d", err);
		goto out;
	}

	/*
	 * Maintain directory like object to keep track of ALL inodes marked
	 * for delete or move.
	 *
	 * When any file is deleted, we set the on disk st_nlink to zero,
	 * however, the object delete actually happen when the last ref goes
	 * away.
	 *
	 * For bugs or unclean shutdown, we may not get chance to finish the
	 * actual object delete/move. In general, objects are removed from
	 * directory entries as the first step, which results in orphaned
	 * inodes if ganesha fails after this point.
	 *
	 * Any potentially orphaned objects can be found and processed
	 * using this table.
	 *
	 */
	err = __create_deleted_inode_table(ci, tc);

	if (err) {
		log_error(fsio_lg,
		    "__create_deleted_inode_table return %d", err);
		goto out;

	}

out:
	log_debug(fsio_lg, "completed ci: %p", ci);

	return err;
}

static int
__create_lost_and_found(ci_t * ci)
{
	int err = 0;
	ccowfs_inode *root_inode = NULL;
	ccowfs_inode *lf_inode = NULL;
	inode_t ino, dotdot_ino;
	uint16_t mode = LOST_FOUND_DIR_MODE;

	/* Create a special lost and found directory to store orphaned
	 * inodes if recovery fails. Currently supported for the case of a
	 * failed move, where the destination directory no longer exists
	 *
	 * TODO: Currently the LOST_FOUND_DIR_MODE is wide open, owned by
	 * root. On a failed move, the object will retain it's original
	 * ownership/perms in .lost+found. Consider in the future adding
	 * sticky bit to .lost+found, that would prevent users from being
	 * able to delete files/dirs in .lost+found that they do not own.
	 */

	log_trace(fsio_lg, "ci: %p, bucket: %s", ci, ci->bid);

	/* Check for root */
	err = ccowfs_inode_get_by_ino(ci, CCOW_FSIO_ROOT_INODE, &root_inode);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino return %d", err);
		goto out;
	}

	/*
	 * Check if object for inode CCOW_FSIO_LOST_FOUND_DIR_INODE is present.
	 * Create it if not present.
	 *
	 * Use the special interface for recovery, to allow retrieval of
	 * inode even if link count is 0, as in the case if an unclean
	 * shutdown occurred after creation. Then we can recover inode and
	 * finish creation.
	 */
	err = ccowfs_inode_get_by_ino_for_recovery(ci,
	    CCOW_FSIO_LOST_FOUND_DIR_INODE, &lf_inode);
	if (err == ENOENT) {
		/* Create it */
		log_info(fsio_lg, "Creating FSIO .lost+found for bucket: %s",
		    ci->bid);

		err = ccowfs_inode_create_new_get(ci,
		    CCOW_FSIO_LOST_FOUND_DIR_INODE, mode, 0, 0, NULL,
		    &lf_inode, NULL);
		if (err) {
			log_error(fsio_lg,
			    "ccowfs_inode_create_new_get return %d", err);
			goto out;
		}
	} else if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_get_by_ino_for_recovery return %d", err);
		goto out;
	}

	/*
	 * Check ".." entry
	 */
	err = ccow_fsio_dir_lookup(ci, lf_inode, "..", &dotdot_ino);
	if (err == ENOENT) {
		/* Add ".." link to root, set link count at same time */
		err = ccow_fsio_dir_add_entry(ci, lf_inode, "..", root_inode, 2);
		if (err) {
			log_error(fsio_lg,
			    "ccow_fsio_dir_add_entry return err: %d", err);
			goto out;
		}
	} else if (err) {
		log_error(fsio_lg, "ccow_fsio_dir_lookup return err: %d", err);
		goto out;
	}

	/*
	 * Check dir entry under root
	 */
	err = ccow_fsio_dir_lookup(ci, root_inode, LOST_FOUND_DIR_NAME, &ino);
	if (err == ENOENT) {
		/* Add to root, increment link count for root */
		err = ccow_fsio_dir_add_entry(ci, root_inode,
		    LOST_FOUND_DIR_NAME, lf_inode, 1);
	} else if (err) {
		log_error(fsio_lg, "ccow_fsio_dir_lookup return err: %d", err);
	}

out:
	if (err)
		log_error(fsio_lg, "failed for cid: %s tid :%s bid: %s err: %d",
			ci->cid, ci->tid, ci->bid, err);

	if (lf_inode)
		ccowfs_inode_put(lf_inode);
	if (root_inode)
		ccowfs_inode_put(root_inode);

	log_debug(fsio_lg, "completed ci: %p, bucket: %s", ci, ci->bid);

	return err;
}

static uint64_t
__get_core_count(void)
{
#define DEFAULT_CORE_COUNT 8
	int cores;
	char *core_limit = getenv("SVC_CPU_LIMIT");

	/** If CPU limit has been specified by the host then use it.
	 *  Else use the available core count.
	 */
	log_debug(fsio_lg, "%s core_limit :%s", __func__, core_limit);

	if (core_limit)
		cores = atoi(core_limit);
	else
		cores = sysconf(_SC_NPROCESSORS_ONLN);

	if (cores <= 0 || cores > DEFAULT_CORE_COUNT)
		cores = DEFAULT_CORE_COUNT;

	log_debug(fsio_lg, "%s cores: %d", __func__, cores);
	return (uint64_t) cores;
}

ci_t *
ccow_fsio_ci_alloc()
{
	ci_t *ci;

	ci = (ci_t *) je_calloc(1, sizeof(ci_t));
	QUEUE_INIT(&ci->export_list_q);
	QUEUE_INIT(&ci->s3dirs_head);

	return (ci);
}

void
ccow_fsio_ci_free(ci_t * ci)
{
	if (ci) {
		if (ci->root_obj_dir_name)
			je_free(ci->root_obj_dir_name);
		je_free(ci);
	}
}


int
ccow_fsio_init()
{
	int err;

	/*
	 * Maintina a list of all FSIO exports
	 * * This is needed to find the export (ci) based on bucket name.
	 */
	fsio_lg = Logger_create("libccowfsio");
	/*
	 * Logger_init (called from Logger_create) fetch
	 * CCOW_LOG_STDOUT
	 * CCOW_LOG_LEVEL
	 * CCOW_LOG_COLORS
	 * CCOW_LOG_AUTOFLUSH
	 * from environment variables.
	 * To set default log level from code -
	 * log_set_level(fsio_lg, LOG_LEVEL_DEBUG);
	 */

	log_info(fsio_lg, "Init FSIO");

	char* mh = getenv("CCOW_MH_IMMDIR");
	if (mh != NULL && strcmp(mh, "0") == 0) {
		ccow_mh_immdir = 0;
		log_trace(fsio_lg, "Context set eventual");
	} else {
		ccow_mh_immdir = 1;
		log_trace(fsio_lg, "Context set immediate");
	}

	QUEUE_INIT(&nedge_fsio_export_list);
	tc_pool_init();

	err = fsio_control_thread_start(&control_thread_handle);
	if (err) {
		log_error(fsio_lg, "Failed to start control thread: %d",
		    err);
		/*
		 * Continue even with this error
		 */
	}

	return 0;
}

int
ccow_fsio_term()
{
	log_info(fsio_lg, "Term FSIO");

	fsio_control_thread_stop(control_thread_handle);
	tc_pool_term();
	Logger_destroy(fsio_lg);

	return 0;
}

static int
ccow_fsio_get_bucket_info(ci_t * ci, ccow_t tc, char *bi)
{
	struct ccow_metadata_kv *kv;
	int err, hash_size, pos;
	ccow_completion_t c;
	ccow_lookup_t iter;

	log_trace(fsio_lg, "ci: %p", ci);
	assert(ci != NULL);

	c = NULL;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(fsio_lg, "ccow_create_completion failed. err: %d", err);
		return err;
	}

	iter = NULL;
	err = ccow_get(ci->bid, ci->bid_size, "", 1, c, NULL, 0, 0, &iter);
	if (err || !iter) {
		log_error(fsio_lg, "ccow_get failed. err: %d", err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, -1);
	if (err) {
		log_error(fsio_lg, "ccow_wait failed. err: %d", err);
		ccow_release(c);
		return err;
	}

	pos = 0;
	uint512_t nhid = uint512_null;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA |
	    CCOW_MDTYPE_CUSTOM, pos++))) {
		if (strcmp(kv->key, RT_SYSKEY_NAME_HASH_ID) == 0) {
			memcpy(&nhid, kv->value, sizeof(uint512_t));
			uint512_dump(&nhid, bi, UINT512_BYTES*2+1);
			bi[UINT512_BYTES*2+1] = '\0';
			ccow_lookup_release(iter);
			ccow_release(c);
			return 0;
		}
	}

	ccow_lookup_release(iter);
	ccow_release(c);

	return ESRCH;

}

static int
ccow_fsio_get_export_quota(ci_t * ci)
{
	struct ccow_metadata_kv *kv;
	int err, hash_size, pos;
	ccow_completion_t c;
	ccow_lookup_t iter;
	ccow_t tc;
	char nhid_str[1024];

	log_trace(fsio_lg, "ci: %p", ci);
	assert(ci != NULL);

	/* Get metadata of object named cluster/tenant/bucket/bucket_nhid. */
	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		return err;
	}

	/* Get bucket's NHID */
	err = ccow_fsio_get_bucket_info(ci, tc, nhid_str);
	if (err == ESRCH) {
		/* NHID not found. */
		return 0;
	} else if (err) {
		log_error(fsio_lg, "Failed to get NHID of bucket \"%s/%s/%s\"."
		    " err: %d", ci->cid, ci->tid, ci->bid, err);
		return err;
	}

	c = NULL;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(fsio_lg, "ccow_create_completion failed. err: %d",
		    err);
		return err;
	}

	iter = NULL;
	err = ccow_get(ci->bid, ci->bid_size, nhid_str, strlen(nhid_str) + 1,
	    c, NULL, 0, 0, &iter);
	if (err || !iter) {
		log_error(fsio_lg, "ccow_get failed. err: %d", err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, -1);
	if (err == ENOENT || err == -ENOENT) {
		if (iter)
			ccow_lookup_release(iter);
		/* No bucket attributes object. Allowed. */
		ccow_release(c);
		return 0;
	} else if (err) {
		if (iter)
			ccow_lookup_release(iter);
		log_error(fsio_lg, "ccow_wait failed. err: %d", err);
		ccow_release(c);
		return err;
	}

	pos = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA |
	    CCOW_MDTYPE_CUSTOM, pos++))) {
		if (strcmp(kv->key, "x-container-meta-quota-bytes") == 0) {
			ci->quota_bytes = (uint64_t) ccow_kvconvert_to_int64(kv);
		} else if (strcmp(kv->key, "x-container-meta-quota-count") == 0) {
			ci->quota_count = (uint64_t) ccow_kvconvert_to_int64(kv);
		}
	}

	if (ci->quota_bytes || ci->quota_count) {
		log_info(fsio_lg, "Bucket \"%s/%s/%s\" quota enabled. "
		    "Bytes: %lu, count: %lu", ci->cid, ci->tid, ci->bid,
		    ci->quota_bytes, ci->quota_count);
	}

	ccow_lookup_release(iter);
	ccow_release(c);

	return err;

}

int
ccow_fsio_create_export(ci_t * ci, char *uri, char *ccow_config,
    int chunk_size, fsio_up_callback up_cb, void *up_cb_args)
{
	int64_t dummy;
	ccow_t tc;
	int err = 0, nonfatal_err = 0, locked = 0;

	log_trace(fsio_lg, "ci: %p, uri: \"%s\", "
	    "ccow_config: \"%s\", chunk_size: %d, up_cb: %p, up_cb_args: %p",
	    ci, uri, ccow_config, chunk_size, up_cb, up_cb_args);
	assert(ci != NULL);

	/*
	 * Logger_init (called from Logger_create) fetch
	 * CCOW_LOG_STDOUT
	 * CCOW_LOG_LEVEL
	 * CCOW_LOG_COLORS
	 * CCOW_LOG_AUTOFLUSH
	 * from environment variables.
	 */

	log_info(fsio_lg, "Init FSIO export: %s", uri);

	if (sscanf(uri, "%2047[^/]/%2047[^/]/%2047[^\n]", ci->cid, ci->tid,
		ci->bid) < 3) {
		log_error(fsio_lg, "open error: wrong ccowbd backing store "
		    "format");
		err = EINVAL;
		goto out;
	}
	ci->cid_size = strlen(ci->cid) + 1;
	ci->tid_size = strlen(ci->tid) + 1;
	ci->bid_size = strlen(ci->bid) + 1;
	ci->up_cb = up_cb;
	ci->up_cb_args = up_cb_args;

	tc_pool_find_handle(ci->cid, ci->tid, &ci->tc_pool_handle);
	if (! ci->tc_pool_handle){
		uint64_t max_tc_count = __get_core_count();

		log_debug(fsio_lg, "Creating TC pool for %s/%s count:%lu",
			ci->cid, ci->tid, max_tc_count);

		err = tc_pool_create(ccow_config, ci->cid, ci->tid,
				max_tc_count, &ci->tc_pool_handle);
		if (err) {
			log_error(fsio_lg, "Failed to create TC for %s/%s err: %d",
				ci->cid, ci->tid, err);
			goto out;
		}
	}
	assert(ci->tc_pool_handle);

	err = ccow_fsio_get_export_quota(ci);
	if (err) {
		log_error(fsio_lg, "Failed to get bucket \"%s/%s/%s\" "
		    "attributes. Check if bucket present. err %d", ci->cid,
		    ci->tid, ci->bid, err);
		ci->ccow_err = err;
		goto out;
	}

	err = __mkfs(ci);
	if (err) {
		log_warn(fsio_lg, "Could not create/init file system. err %d", err);
		ci->ccow_err = err;
		goto out;
	}
	err = ccow_shard_context_create(FLUSHER_STAT_OBJ,
	    strlen(FLUSHER_STAT_OBJ)+1, 1, &ci->stats_list_context);
	if (err) {
		log_error(fsio_lg, "ccow_shard_context_create failed, err %d",
		    err);
		goto out;
	}

	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		goto out;
	}

	err = ccow_range_lock(tc, ci->bid, ci->bid_size, "", 1, 0, 1, CCOW_LOCK_EXCL);
	if (err) {
		log_error(fsio_lg, "Failed to get fsio bucket lock. err: %d", err);
		goto out;
	}
	locked = 1;

	atomic_set_uint64((uint64_t *)&ci->used_bytes_diff, 0ULL);
	atomic_set_uint64((uint64_t *)&ci->used_count_diff, 0ULL);
	err = ccow_sharded_attributes_get(tc, ci->bid, ci->bid_size,
	    ci->stats_list_context, &ci->used_bytes, &ci->used_count, &dummy);
	if (err == ENOENT || err == -ENOENT) {
		err = ccow_sharded_list_create(tc, ci->bid, ci->bid_size,
		    ci->stats_list_context);
		if (err) {
			log_error(fsio_lg, "ccow_sharded_list_create failed, "
			    "err %d", err);
			goto out;
		}
		err = ccow_sharded_attributes_put(tc, ci->bid, ci->bid_size,
		    ci->stats_list_context, FLUSHER_STAT_OBJ,
		    strlen(FLUSHER_STAT_OBJ)+1, 0, 0, 0);
		if (err) {
			log_error(fsio_lg, "ccow_sharded_attributes_put "
			    "failed, err %d", err);
			goto out;
		}
		err = ccow_sharded_attributes_get(tc, ci->bid, ci->bid_size,
		    ci->stats_list_context, &ci->used_bytes, &ci->used_count, &dummy);
		if (err) {
			log_error(fsio_lg, "ccow_sharded_attributes_get "
			    "failed, err %d", err);
			goto out;
		}
	} else if (err != 0) {
		log_error(fsio_lg, "Failed to get/create bucket \"%s/%s/%s\" "
		    "FS stats attributes. err %d", ci->cid,
		    ci->tid, ci->bid, err);
		ci->ccow_err = err;
		goto out;
	}

	err = ccowfs_inode_cache_init(ci);
	if (err) {
		log_error(fsio_lg, "Cannot initialize fsio_inode");
		goto out;
	}
	assert(ci->inode_cache.init_done == 1);

	err = fsio_list_cache_create(&ci->fsio_list_cache);
	if (err) {
		log_error(fsio_lg, "Cannot initialize fsio_list_cache");
		goto out;
	}

	err = __create_root_obj(ci);
	if (err) {
		log_error(fsio_lg, "Cannot create root object");
		goto out;
	}

	err = fsio_namespace_init(ci);
	if (err) {
		log_error(fsio_lg, "Cannot initialize fsio_namespace");
		goto out;
	}

	err = s3_transparency_init(ci);
	if (err) {
		log_error(fsio_lg, "Cannot initialize s3_transparency");
		goto out;
	}

#ifdef NOT_YET
	err = fsio_snapshot_init(ci);
	if (err) {
		log_error(fsio_lg, "Cannot initialize file snapshot");
		goto out;
	}
#endif

	err = __create_lost_and_found(ci);
	if (err) {
		log_error(fsio_lg, "Cannot create .lost+found");
		goto out;
	}

	/*
	 * Add the ci to the export list.
	 */
	assert(QUEUE_EMPTY(&ci->export_list_q));
	QUEUE_INSERT_TAIL(&nedge_fsio_export_list, &ci->export_list_q);

	/*
	 * Attempt recovery of any orphaned inodes in the event of an
	 * unclean shutdown.
	 */
	nonfatal_err = ccowfs_recovery_handler(ci);
	if (nonfatal_err) {
		log_error(fsio_lg, "Error in processing inode recovery table %d",
		    nonfatal_err);
	}
out:
	assert(err || ci->inode_cache.inode_table);

	if (locked) {
		err = ccow_range_lock(tc, ci->bid, ci->bid_size, "", 1, 0, 1, CCOW_LOCK_UNLOCK);
		if (err) {
			log_error(fsio_lg, "Failed to unlock fsio bucket. err: %d", err);
		}
	}

	log_debug(fsio_lg, "completed ci: %p, uri: \"%s\", "
	    "ccow_config: \"%s\", chunk_size: %d, up_cb: %p, up_cb_args: %p",
	    ci, uri, ccow_config, chunk_size, up_cb, up_cb_args);
	return err;
}

void
ccow_fsio_delete_export(ci_t * ci)
{

	log_trace(fsio_lg, "ci: %p", ci);
	assert(ci != NULL);

	log_info(fsio_lg, "Terminate FSIO export: %s", ci->bid);

#ifdef NOT_YET
	fsio_snapshot_term(ci);
#endif
	ccowfs_inode_cache_term(ci);

	fsio_list_cache_destroy(&ci->fsio_list_cache);

	/* Sync last stats changes. */
	flusher_sync_fsstat(ci);

	fsio_namespace_term(ci);
	ccow_shard_context_destroy(&ci->stats_list_context);
	ccow_shard_context_destroy(&ci->recovery_context);

	/*
	 * Remove the ci from the export list.
	 */
	assert(!QUEUE_EMPTY(&ci->export_list_q));
	QUEUE_REMOVE(&ci->export_list_q);
}

int ccowfs_inode_create_root_obj_lite(ccow_t tc, ci_t * ci);

static int
_bucket_uri_to_ci(ci_t * ci, const char *uri, Logger lg)
{
	int err;

	err = 0;

	if (sscanf(uri, "%2047[^/]/%2047[^/]/%2047[^\n]", ci->cid, ci->tid,
		ci->bid) < 3) {
		log_error(lg, "open error: wrong ccowbd backing store format\n");
		return (EINVAL);
	}
	ci->cid_size = strlen(ci->cid) + 1;
	ci->tid_size = strlen(ci->tid) + 1;
	ci->bid_size = strlen(ci->bid) + 1;

	return (err);
}

/*
 * Generic bucket serving interface.
 * Use 3 methods:
 * 	o int ccow_fsio_create_bucket(ccow_t tc, const char *bucket_uri, Logger lg);
 * 	o int ccow_fsio_delete_bucket(ccow_t tc, const char *bucket_uri, Logger lg);
 * 	o int ccow_fsio_is_not_empty(ccow_t tc, const char *bucket_uri, Logger lg);
 *
 * create/delete doesn't actualy create/delete bucket, but just act on NFS
 * special objects.
 */

int
ccow_fsio_create_bucket(ccow_t tc, const char *bucket_uri, Logger lgarg)
{
	int err;
	ccow_shard_context_t *shard_context;
	ccow_snapview_t sv_hdl;
	ci_t * ci;

	ci = NULL;
	fsio_lg = (lgarg == NULL)?lg:lgarg;
	/* CCOW_FSIO_ROOT_INODE */
	/* Emulate ci_t structure. */
	ci = je_malloc(sizeof(ci_t));
	/* Parse URI to parts. */
	err = _bucket_uri_to_ci(ci, bucket_uri, lg);
	if (err) {
		log_error(lg, "_bucket_uri_to_ci return %d", err);
		goto out;
	}

	err = ccowfs_inode_create_root_obj_lite(tc, ci);
	if (err) {
		log_error(lg,
		    "ccowfs_inode_create_root_obj_lite return %d", err);
		goto out;
	}

	err = ccow_bucket_inode_ref_create(tc, ci->bid, ci->bid_size,
		INODE_OBJECT_LOOKUP, strlen(INODE_OBJECT_LOOKUP) + 1);
	if (err) {
		log_error(lg,
		    "ccow_bucket_inode_ref_create return %d", err);
		goto out;
	}

	/* INODE_MASTER_STR */
	err = __inode_master_create(tc, ci->cid, ci->cid_size, ci->tid,
	    ci->tid_size, ci->bid, ci->bid_size);
	if (err) {
		log_error(lg, "__inode_master_create return %d",
		    err);
		goto out;
	}

	/* RECOVERY_TABLE_STR */
	/*
	 * Maintain directory like object to keep track of ALL inodes marked
	 * for delete or move.
	 *
	 * When any file is deleted, we set the on disk st_nlink to zero,
	 * however, the object delete actually happen when the last ref goes
	 * away.
	 *
	 * For bugs or unclean shutdown, we may not get chance to finish the
	 * actual object delete/move. In general, objects are removed from
	 * directory entries as the first step, which results in orphaned
	 * inodes if ganesha fails after this point.
	 *
	 * Any potentially orphaned objects can be found and processed
	 * using this table.
	 */
	err = __create_deleted_inode_table(ci, tc);
	if (err) {
		log_error(lg, "__create_deleted_inode_table return %d",
		    err);
		goto out;

	}

	/* FLUSHER_STAT_OBJ */
	err = ccow_shard_context_create(FLUSHER_STAT_OBJ,
	    strlen(FLUSHER_STAT_OBJ) + 1, 1, &ci->stats_list_context);
	if (err) {
		log_error(lg, "ccow_shard_context_create failed, err %d",
		    err);
		goto out;
	}
	ccow_shard_context_set_inline_flag(ci->stats_list_context,
		RT_INLINE_DATA_TYPE_NFS_AUX);

	err = ccow_sharded_list_create(tc, ci->bid, ci->bid_size,
	    ci->stats_list_context);
	if (err) {
		log_error(lg, "ccow_sharded_list_create failed, err %d",
		    err);
		goto out;
	}

	/* TODO: For .lost+found, do we need a "lightweight" creation ?
	 * Currently creation is in the export create
	 */

#ifdef NOT_YET
	/* SNAPVIEW_OID */
	err = ccow_snapview_create(tc, &sv_hdl, ci->bid, ci->bid_size,
	    SNAPVIEW_OID, strlen(SNAPVIEW_OID) + 1);
	if (err == -EEXIST)
		err = 0;
	ccow_snapview_destroy(tc, sv_hdl);
#endif

out:
	if (ci->stats_list_context)
		ccow_shard_context_destroy(&ci->stats_list_context);
	if (ci)
		je_free(ci);

	return (err);
}


int
ccow_fsio_delete_bucket(ccow_t tc, const char *bucket_uri, Logger lgarg)
{
	ccow_shard_context_t list_shard_context;
	ccow_completion_t c;
	ci_t *ci;
	int err;

	err = 0;
	c = NULL;
	ci = NULL;
	fsio_lg = (lgarg == NULL)?lg:lgarg;

	err = ccow_fsio_is_not_empty(tc, bucket_uri, lg);
	if (err) {
		log_error(lg, "Bucket has a NFS non-special objects. "
		    "Can't continue to delete");
		return (err);
	}
	/* Emulate ci_t structure. */
	ci = je_malloc(sizeof(ci_t));
	/* Parse URI to parts. */
	err = _bucket_uri_to_ci(ci, bucket_uri, lg);

#ifdef NOT_YET
	/* SNAPVIEW_OID */
#endif
	/* FLUSHER_STAT_OBJ */
	err = ccow_shard_context_create(FLUSHER_STAT_OBJ,
	    strlen(FLUSHER_STAT_OBJ) + 1, 1, &ci->stats_list_context);
	if (err) {
		log_error(lg, "ccow_shard_context_create failed, err %d",
		    err);
		goto out;
	}

	err = ccow_sharded_list_destroy(tc, ci->bid, ci->bid_size,
	    ci->stats_list_context);
	if (err && err != -ENOENT) {
		log_error(lg, "ccow_sharded_list_delete failed, err %d",
		    err);
		goto out;
	}

	/* RECOVERY_TABLE_STR */
	err = ccow_shard_context_create(RECOVERY_TABLE_STR,
	    strlen(RECOVERY_TABLE_STR) + 1, RECOVERY_TABLE_SHARD_COUNT,
	    &ci->recovery_context);
	if (err) {
		log_error(lg, "ccow_shard_context_create failed, err %d",
		    err);
		goto out;
	}

	err = ccow_sharded_list_destroy(tc, ci->bid, ci->bid_size,
	    ci->recovery_context);
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
	err = ccow_delete_notrlog(ci->bid, ci->bid_size,
		INODE_OBJECT_LOOKUP, strlen(INODE_OBJECT_LOOKUP) + 1, c);
	err = ccow_wait(c, -1);
	if (err) {
		log_error(lg, "ccow_wait failed, err %d", err);
		goto out;
	}

	/* INODE_MASTER_STR */
	err = ccow_delete_notrlog(ci->bid, ci->bid_size, INODE_MASTER_STR,
	    strlen(INODE_MASTER_STR) + 1, c);
	if (err) {
		log_error(lg, "ccow_delete failed, err %d", err);
		goto out;
	}

	err = ccow_wait(c, -1);
	if (err) {
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

	err = ccow_sharded_list_destroy(tc, ci->bid, ci->bid_size,
	    list_shard_context);
	if (err) {
		log_error(lg, "ccow_sharded_list_destroy failed, err %d", err);
		goto out;
	}

	ccow_shard_context_destroy(&list_shard_context);

	/* CCOW_FSIO_LOST_FOUND_DIR_INODE */

	err = ccow_shard_context_create(LOST_FOUND_INODE_STR,
	    strlen(LOST_FOUND_INODE_STR) + 1, FSIO_DIR_SHARD_COUNT,
	    &list_shard_context);
	if (err) {
		log_error(lg, "ccow_shard_context_create failed, err %d", err);
		goto out;
	}

	err = ccow_sharded_list_destroy(tc, ci->bid, ci->bid_size,
	    list_shard_context);
	if (err && err != -ENOENT) {
		log_error(lg, "ccow_sharded_list_destroy failed, err %d", err);
	}

	if (err == -ENOENT) {
		err = 0;
	}

	ccow_shard_context_destroy(&list_shard_context);

out:
	if (c)
		ccow_release(c);
	if (ci->stats_list_context)
		ccow_shard_context_destroy(&ci->stats_list_context);
	if (ci)
		je_free(ci);

	return (err);
}


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


/*
 * int ccow_fsio_is_not_empty(ccow_t tc, const char *bucket_name)
 * 	return 0 - if success and empty
 * 	return 1 - if not empty
 * 	return -err - if err
 *
 */
int
ccow_fsio_is_not_empty(ccow_t tc, const char *bucket_uri, Logger lgarg)
{
	ccow_shard_context_t dir_list_context;
	int64_t s, n, b;
	ci_t *ci;
	int err;

	err = 0;

	fsio_lg = (lgarg == NULL)?lg:lgarg;
	/* Emulate ci_t structure. */
	ci = je_malloc(sizeof(ci_t));
	/* Parse URI to parts. */
	err = _bucket_uri_to_ci(ci, bucket_uri, lg);
	/* Check number of children of CCOW_FSIO_ROOT_INODE. */

	err = test_root(tc, ci->bid, ci->bid_size);
	if (err == -EPERM) {
		log_error(lg, "NFS root not empty %d",  err);
		goto out;
	}

	/* check if the .lost+found directory is empty */
	s = 0;
	err = ccow_shard_context_create(LOST_FOUND_INODE_STR,
	    strlen(LOST_FOUND_INODE_STR) + 1, FSIO_DIR_SHARD_COUNT,
	    &dir_list_context);
	if (err) {
		log_error(lg, "ccow_shard_context_create return error %d",
		    err);
		goto out;
	}

	err = ccow_sharded_attributes_get(tc, ci->bid, ci->bid_size,
	    dir_list_context, &s, &n, &b);

	ccow_shard_context_destroy(&dir_list_context);

	if (err == -ENOENT) {
		err = 0;
		goto out;
	}

	if (err) {
		log_error(lg, "failed to GET .lost+found dir size, err: %d",
		    err);
		goto out;
	}

	if (s > (off_t) (EMPTY_DIR_SIZE)) {
		err = 1;
		goto out;
	}

#ifdef NOT_YET
	/* Check number of snapshots. */
#endif

out:
	if (ci)
		je_free(ci);

	return (err);
}

int
ccow_fsio_fsinfo(ci_t *ci, fsio_fsinfo_t *fsinfo)
{
	int64_t quota_bytes, quota_count, b, c;

	log_trace(fsio_lg, "ci: %p, fsinfo: %p", ci, fsinfo);
	assert(ci != NULL);
	assert(fsinfo != NULL);

	quota_bytes = (ci->quota_bytes != 0)?(ci->quota_bytes):
		(512ULL * 1024 * 1024 * 1024 * 1024);
	quota_count = (ci->quota_count != 0)?(ci->quota_count):
		(1 * 1024 * 1024 * 1024ULL);

	/*
	 * Since fsinfo fields uint64_t, we can't show overquota usage. only 0.
	 */
	fsinfo->total_bytes = quota_bytes;
	b = quota_bytes - ci->used_bytes -
	    atomic_get_int64(&ci->used_bytes_diff);
	fsinfo->free_bytes = MAX(b, 0);
	fsinfo->avail_bytes = fsinfo->free_bytes;
	fsinfo->total_files = quota_count;
	c = quota_count - ci->used_count -
	    atomic_get_int64(&ci->used_count_diff);
	fsinfo->free_files = MAX(c, 0);
	fsinfo->avail_files = fsinfo->free_files;

	return 0;
}

int
ccow_fsio_get_new_inode_number(ci_t * ci,
    ccow_fsio_inode_type type, uint64_t * inode_number)
{
	inode_t ino = 0;
	inode_t server_id_part = ci->inode_serverid << 51;
	uint64_t inode_type = (uint64_t) type;
	uint64_t current_ts;

	log_trace(fsio_lg, "ci: %p, type: %u, inode_number: %p", ci, type,
	    inode_number);
	assert(inode_type < 4);
	/*
	 *  [inode number generation]
	 * 0         1         2         3         4         5         6
	 * 0123456789012345678901234567890123456789012345678901234567890123
	 * TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTSSSSSSSSSttrP
	 *      -  inode number can be 64 bit max. It needs to be unique across
	 *         all the servers running Ganesha service.
	 *      -  P - Pseudo object, 1 bit flag, mem-only
	 *      -  r - 1 bit reserved for other usage
	 *      -  t - Next 2 bits are used for type
	 *      -  S - Next 9 bits are reserved for server_id. This means we can
	 *         have maximum 512 servers running Ganesha service at a time.
	 *      -  T - Lower 51 bits are used for timestamp. This will wrap
	 *         around in about 70 years.
	 */

	ino = ino | (inode_type << 60);
	/*
	 * Get the last 51 bits of timestamp.
	 */
	pthread_mutex_lock(&ci->inode_gen_mutex);
	/**
	 * We use timestamp in microsecond as unique inode number (lower 51 bits)
	 * This means we can generate max one inode per microsecond.
	 * We can get create requests for multiple inodes in the same microsecond,
	 *  it is required to block them here and allow only one create per microsecond.
	 * Other option: increase the ci->last_inode_ts
	 *				 and allow multiple creates in same microsecond.
	 *				 This can take ci->last_inode_ts way ahead of real timestamp.
	 *				 It adds risk of duplicate inode creation in case of crash.
	 * At present we don't allow ci->last_inode_ts to go ahead of the real timestamp.
	 */
retry:
	current_ts = get_nondecreasing_timestamp_us();
	if (unlikely(ci->last_inode_ts == current_ts)){
		/* Block here to let the real time go ahead by 1 microsecond.*/
		usleep(1);
		goto retry;
	}
	assert(ci->last_inode_ts < current_ts);
	ci->last_inode_ts = current_ts;
	ino = ino | (ci->last_inode_ts & 0x7FFFFFFFFFFFFULL);
	pthread_mutex_unlock(&ci->inode_gen_mutex);

	/*
	 * Add the server id 9 bits.
	 */
	server_id_part = server_id_part & 0xFF8000000000000ULL;
	ino = ino | server_id_part;

	*inode_number = ino;
	log_debug(fsio_lg, "completed ci: %p, type: %u, inode_number: %p", ci,
	    type, inode_number);

	return 0;
}

int
ccow_fsio_find_export(char *cid, size_t cid_size, char *tid, size_t tid_size,
    char *bid, size_t bid_size, ci_t ** out_ci)
{
	int err = 0;
	QUEUE *q;
	ci_t *ci = NULL;

	*out_ci = NULL;

	log_trace(fsio_lg, "cid: \"%s\", cid_size: %lu, "
	    "tid: \"%s\", tid_size: %lu, bid: \"%s\", bid_size: %lu, "
	    "out_ci: %p", cid, cid_size, tid, tid_size, bid, bid_size, out_ci);

	QUEUE_FOREACH(q, &nedge_fsio_export_list) {
		ci = QUEUE_DATA(q, ci_t, export_list_q);

		if (!strcmp(ci->bid, bid) && !strcmp(ci->tid, tid) &&
		    !strcmp(ci->cid, cid)) {
			/*
			 * Found the matching export.
			 */
			*out_ci = ci;
			break;
		}
	}

	log_debug(fsio_lg, "completed cid: \"%s\", cid_size: %lu, "
	    "tid: \"%s\", tid_size: %lu, bid: \"%s\", bid_size: %lu, "
	    "out_ci: %p", cid, cid_size, tid, tid_size, bid, bid_size, out_ci);

	return err;
}
