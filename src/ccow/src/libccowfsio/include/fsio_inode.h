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
#ifndef __CCOW_FSIO_INODE_H__
#define __CCOW_FSIO_INODE_H__

#include <hashtable.h>
#include <ccowfsio.h>
#include <replicast.h>
#include "fsio_disk.h"

#define APPROX_BTREE_DEPTH 3
#define ENTRY_SIZE (APPROX_BTREE_DEPTH *(sizeof(struct refentry)))

/** Empty directory contains only one entry ".""
 *	The "." entry is abstract and holds the dir attributes.
 *	  it is not counted for dir size.
 */
#define EMPTY_DIR_SIZE (ENTRY_SIZE)

/** In memory inode life cycle
 *      Inode can enter in hash table in two ways:
 *      1. When new file/symlink/dir is created
 *      2. When we get first access for existing inode, we fetch it from disk.
 *  The hash table gats the first ref on the inode,
 *  which is maintained as long as the inode is in the hash table.
 *
 *  During unlink, if the link count goes to zero:
 *      We need not give any more new ref on the inode. But still have to serve refs already taken.
 *      Set the link count as zero on the on disk object.
 *      Set the deleted flag on the inode as true
 *
 *      If new request comes for this inode,
 *          Check for the deleted flag
 *          Also, the disk inode has link count set to zero.
 *          So we treat this as ENOENT.
 *
 *      When the last ref goes away, and link count is zero - we delete the on disk object.
 *      At this time, the inode is not in the hash table. So we don't worry about concurrent access.
 *
 */
typedef struct __inode_cache__
{
	int init_done;
	pthread_rwlock_t hash_table_rwlock;
	hashtable_t *inode_table;
	QUEUE cached_inode_list;
	uint64_t count;
} libccowfsio_inode_cache;


/* There are two LRU like lists for the inode cache
 * 1. ccow_info.open_files_head
 *      This list maintain all the inodes which have unflushed data.
 *      Usually, the inode will be opened as file.
 *      We flush the data from this list via flusher thread.
 *      These inodes have open completions associated with them to server ccow_put_cont
 *      In case of pressure on available completions:
 *          we flush the inodes from this list and release the completions
 *
 * 2. libccowfsio_inode_cache.cached_inode_list
 *      This list maintains ALL cached inodes.
 *      Flush and un-cache inodes from this list on memory pressure.
 *      We can maintain MAX_INODE_TO_CACHE inodes in the cache.
 *      If there are more inodes, then flush the inodes based on LRU
 *      If inode has refcount as 1, then it is only hash table ref and we can un-cache the inode.
 *
 *      In rare but cornet case, if there are MAX_INODE_TO_CACHE inodes with refcount > 1
 *      then either we have a bug or we have MAX_INODE_TO_CACHE open files from NFS.
 *      We allow the inode cache to grow and try to un-cache the inodes whenever possible.
 *      Eventually, we can fail with eNOMEM
 *      MAX_INODE_TO_CACHE is not a hard limit.
 */

/** inode.h
 *  API to perform inode operations.
 *  The namespace related operations are handled separately.
 *  We use hash table to maintain the inode cache.
        Key=inode_no; value=(ccowfs_inode *)
 *  All but two interfaces work on the (ccowfs_inode *) structure, which is in memory inode.
    There are two interfaces to get a (ccowfs_inode *) structure.
    a. ccowfs_inode_create_new_get() : (mkdir and create calls)
    b. ccowfs_inode_get_by_ino() : (get_attr, set_attr, open, lookup calls)
 *  This layer is responsible for -
        a. Maintains the inode cache.
        b. Maintain inode locking.
        c. Perform inode operations like - set_attr, link, unlink
 */


/**
 * The object id is just string version of the inode number.
 */
#define INODE_STR_MAX_SIZE 32

#ifndef    CCOW_STREAM_PREALLOC
#define    CCOW_STREAM_PREALLOC    512
#endif

#define MAX_INODE_TO_CACHE (1000000)
#define MAX_INODES_TO_CLEAN (5000)

/**
 * For dir sharded will be created to hold the attrs and btee.
 *	Shard name is same as <oid>
 */

/** Lock sequence to avoid deadlock.
 *  Available locks:
 *      ccowfs_inode->rwlock   : Safeguard in memory inode structure and serialize the disk access.
 *      queue_mutex            : Lock the dirty LRU
 *
 *  To add the inode to dirty list:
 *      Take the queue_mutex and add the inode to dirty list (if not present)
 *
 *  Flusher thread:
 *      loop:
            Take the queue_mutex
            TRY-LOCK rwlock from the first inode from dirty list.
            If got the lock, then remove the inode from dirty list
             drop queue_mutex
            Flush the inode.
            release rwlock
 *
 *  When we get OOR for create completion:
        Call Flusher thread for N inodes and then try.
        In this casse flusher thread will not check the dirty_time.
 */

/* In memory inode structure */
typedef struct __ccowfs_inode__
{
	/**
	 * ci, ino, ino_str, oid, oid_size, read_only  are not protected by the lock
	 *  as they are set during create and RO after that.
	 *
	 * ready flag is set when the inode fetch from disk is complete.
	 * When we start to fetch inode from disk,
	 *      the incomplete inode is added in the hash table
	 *      this is done, so we don't initiate multiple fetch for the same inode.
	 */
	ci_t *ci;
	inode_t ino;
	char ino_str[INODE_STR_MAX_SIZE];
	char *oid;
	size_t oid_size;
	uint8_t read_only;
	uint64_t ready;
	uint64_t deleted;
	ccow_shard_context_t dir_list_context;

	pthread_mutex_t buffer_cache_mutex;
	QUEUE buffer_cache_q;
	uint64_t cached_chunks;
	uint64_t dirty_chunks;

	/* Used only for S3 objects*/
	uint64_t multipart;	/* Set if the S3 object is multi part object */
	uint64_t json_size; /* The size of the main object which contains JSON map*/
	void *json_handle;
	pthread_mutex_t json_handle_mutex;

	/*
	 * The disk_worker is NOT guarded by the rwlock.
	 * * It has its own locking mechanism.
	 * * Any thread using disk_worker must have a ref on the inode struct.
	 * * ALL inode related read/write calls must be done using disk_worker API.
	 */
	disk_worker_md disk_worker;

	pthread_rwlock_t rwlock;
	pthread_rwlock_t namespace_rwlock;

	/*
	 * All fields below are guarded by rwlock
	 */

	unsigned long refcount;
	struct stat stat;
	int dirty;
	uint64_t genid;
	uint32_t snap_count;
	uint64_t logical_size;;
	uint64_t prev_logical_size;;

	/* in-memory inode expiration marker and genid */
	uint64_t expire_us;

	/*
	 * For us, dirty inode means inodde which has open completion.
	 *   When there is resourse crunch, we will finalize the open completion based on LRU.
	 *   The open completion does not always implay unflushed data, as it can be opened for reading.
	 * flusher thread will
	 *      - If dirty_time is older than specific interval
	 *          - finalize the completion
	 *          - remove the inode from dirty list
	 */
	uint64_t dirty_time;
	QUEUE dirty_q;

	/*
	 * For the list of all inodes. This is protected by the hashtable lock
	 * * When inode is created it is added to this list.
	 * * It will leave the list only when it is removed from the hash table
	 */
	QUEUE list_q;

} ccowfs_inode;

/**  ccowfs_inode_cache_init:
 *      Init the inode cache.
 *      This must be called from ccow_fsio_init()
 *      There is only one instance of inode cache, so we don't return any context.
 */
int ccowfs_inode_cache_init(ci_t * ci);

/** ccowfs_inode_cache_term:
 *      Terminate the inode cache.
 *      It does not check any locks / references on iode. Just free up the memory.
 *      This must be called from ccow_fsio_fini()
 */
int ccowfs_inode_cache_term(ci_t * ci);

/** ccowfs_inode_create_new_get:
 *        Allocate new inode number.
 *        Create on disk inode object with the attrs.
 *        Take a ref on the new node and return it.
 */
int
ccowfs_inode_create_new_get(ci_t * ci, inode_t ino, uint16_t mode,
    uint16_t uid, uint16_t gid, char *link, ccowfs_inode ** new_inode,
    inode_t * new_ino);

/** ccowfs_inode_link:
 *      Caller must have a ref on the inode and no lock.
 *  Increment link count
 *      This is inode only operation and does not consider namespace operation.
 */
int ccowfs_inode_link(ccowfs_inode * inode);
int ccowfs_inode_link_locked(ccowfs_inode * inode);

/** ccowfs_inode_unlink:
 *        Caller must have a ref on the inode and no lock.
 *        Decrement the link count.
 *        On disk inode deletion will happen when last reference is dropped.
 *        This is inode only operation and does not consider namespace operation.
 */
int ccowfs_inode_unlink(ccowfs_inode * inode);
int ccowfs_inode_unlink_locked(ccowfs_inode * inode);

/** ccowfs_inode_get:
 *        Get reference on the inode.
 */
int ccowfs_inode_get_impl(ccowfs_inode * inode);
#define ccowfs_inode_get(_ino) do { \
	log_trace(fsio_lg, "%s put inode: %lu, ref: %lu", __func__, (_ino)->ino, atomic_get_uint64(&(_ino)->refcount)); \
	ccowfs_inode_get_impl((_ino)); \
} while (0)


/** ccowfs_inode_put:
 *        Put one reference from the inode.
 *        If it is the last reference, and link count is zero:
 *            then delete the on disk inode.
 */
int ccowfs_inode_put_impl(ccowfs_inode * inode);
#define ccowfs_inode_put(_ino) do { \
	log_trace(fsio_lg, "%s get inode: %lu, ref: %lu", __func__, (_ino)->ino, atomic_get_uint64(&(_ino)->refcount)); \
	ccowfs_inode_put_impl((_ino)); \
} while (0)


/** ccowfs_inode_get_inode_no:
 *    Get inode number
 */
int ccowfs_inode_get_inode_no(ccowfs_inode * inode, inode_t * ino);

/** ccowfs_inode_get_by_ino:
 *        If the inode is present in cache
 *            return it.
 *        If it is not present in cache
 *             fetch it from disk and return it.
 *        ENOENT otherwise.
 *        if out_inode is not NULL,
 *              then inode is always returned with additional reference on it.
 *        if out_inode is NULL,
 *              then, this API loads the inode in memory in async mode.
 *              It does not wait for the actual inode load.
 *  Caller must call ccowfs_inode_put() to release the ref.
 *
 *  ccowfs_inode_get_by_ino_for_recovery:
 *         Same as ccowfs_inode_get_by_ino, but special interface for
 *         the recovery handlers to allow retrieval of inodes that have
 *         link count 0. If these inodes have corresponding recovery table
 *         entries for DELETE operations, they are orphans which need to
 *         to have deletion finished.
 */
int ccowfs_inode_get_by_ino(ci_t * ci, inode_t inode_no,
    ccowfs_inode ** out_inode);
int ccowfs_inode_get_by_ino_for_recovery(ci_t * ci, inode_t inode_no,
    ccowfs_inode ** out_inode);

/**
 * Optimization for readdir on S3 object dir.
 * The object attributes are present in the directory btree
 * We don't need to perform another fetch_inode to read the attributes.
 * This call is specilly for readdit to pass on the inode attributes.
 * If the inode is already in cache, we do nothing.
 * Otherwise cache the inode with passed stat inofrmation.
 * No actual disk operation.
 */
int ccowfs_inode_cache_s3_inode(ci_t * ci, inode_t inode_no,
    struct stat *stat);

/** ccowfs_namespace_inode_lock:
  *        Take write lock on the inode at namespace level.
 */
int
ccowfs_namespace_inode_lock(ccowfs_inode * inode);

/** ccowfs_namespace_inode_unlock:
 *        Release the namespace write lock.
 */
int
ccowfs_namespace_inode_unlock(ccowfs_inode * inode);

/** ccowfs_inode_lock:
  *        Take write lock on the inode.
 */
int ccowfs_inode_lock(ccowfs_inode * inode);

/** ccowfs_inode_unlock:
 *        Release the write lock.
 */
int ccowfs_inode_unlock(ccowfs_inode * inode);

/** ccowfs_inode_lock_shared:
 *        Take read lock on the inode.
 */
int ccowfs_inode_lock_shared(ccowfs_inode * inode);


/** ccowfs_inode_unlock_shared:
 *        Release the read lock.
 */
int ccowfs_inode_unlock_shared(ccowfs_inode * inode);

/** ccowfs_inode_get_attr_locked
 *    Get stats from the inode.
 *      Caller must have read or write lock on the inode.
 *      Returns the stat from in memory inode.
 */
int ccowfs_inode_get_attr_locked(ccowfs_inode * inode, struct stat *stat);

/** ccowfs_inode_set_attr
 *    Set stats on the inode.
 */
int ccowfs_inode_set_attr(ccowfs_inode * inode, struct stat *stat);

/**
 * ccowfs_inode_set_attr does not allow to set all the attributes
 *            like snap_count, link count
 * this is special interface to set ALL the stats on the inode.
 * it will be used by functions like snapshot rollback.
 */
int
ccowfs_inode_master_set_attr_locked(ccowfs_inode *inode, struct stat *stat);

/** ccowfs_inode_sync
 *    Flush the inode metadata and data to disk
 *  flush is set to 1 if the sync request is initiated by client. 0 otherwise.
 */
int ccowfs_inode_sync(ccowfs_inode * inode, int client_flush);

/** ccowfs_inode_mark_dirty
 *      IO happened on the inode, add it to the dirty list.
 *      If already present in the dirty list, then move it to the tail.
 */
int ccowfs_inode_mark_dirty(ccowfs_inode * inode);

/** ccowfs_inode_mark_dirty
 *      Remove the inode from dirty list.
 */
int ccowfs_inode_mark_clean(ccowfs_inode * inode);

/** ccowfs_inode_flusher
 *      Try to flush max_count inodes from dirty list.
 *      This is to be called directly if there is resourse crunch for completion.
 */
int ccowfs_inode_flusher(ci_t * ci, int mem_pressure, int max_count);

/** ccowfs_inode_timed_flusher
 *      Flusher thread function to flush inodes from dirty list.
 */
void *ccowfs_inode_timed_flusher(void *arg);

/**
 * Increase and decrease snap_count for the inode.
 * The caller must hold lock on the inode.
 */
int ccowfs_inode_inc_snap_count(ccowfs_inode * inode);
int ccowfs_inode_dec_snap_count(ccowfs_inode * inode);
int ccowfs_inode_clone_get(ccowfs_inode * src_inode, ci_t * dest_ci,
    ccowfs_inode ** dest_inode);

/**
 * Refresh the in-memory inode frome disk.
 */
int ccowfs_inode_refresh_locked(ccowfs_inode * inode);

int
ccowfs_inode_mark_deleted(ccowfs_inode *inode);

/**
 *	Update size only if new size is greater than current size.
 */
int
ccowfs_inode_update_size(ccowfs_inode * inode, uint64_t new_size);

int
ccowfs_inode_update_atime_locked(ccowfs_inode *inode);

int
ccowfs_inode_get_size(ccowfs_inode *inode, size_t *size);

int
ccowfs_inode_parse_s3_multipart_json(ccowfs_inode *inode, uint64_t chunk_size);

#endif /*__CCOW_FSIO_INODE_H__*/
