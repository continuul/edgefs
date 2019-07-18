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

#include <ccowfsio.h>
#include "fsio_system.h"
#include "fsio_flusher.h"
#include "fsio_inode.h"
#include "fsio_dir.h"
#include "tc_pool.h"

#define TIMER_INTERVAL 5
#define FLUSHER_STAT_INTERVAL 60

void
flusher_sync_fsstat(ci_t * ci)
{
	int err, len;
	int64_t dummy, bd, cd;
	ccow_t tc;

	log_trace(fsio_lg, "ci: %p", ci);
	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "Failed to get TC. err: %d", err);
		goto out;
	}

	bd = atomic_get_int64(&ci->used_bytes_diff);
	cd = atomic_get_int64(&ci->used_count_diff);

	if (bd || cd) {

		/* Submit collected stats. */
		err = ccow_sharded_attributes_put(tc, ci->bid, ci->bid_size,
		    ci->stats_list_context, FLUSHER_STAT_OBJ,
		    strlen(FLUSHER_STAT_OBJ)+1, bd, cd, 0);
		if (err) {
			log_error(fsio_lg, "ccow_sharded_attributes_put failed, err %d",
			    err);
			goto out;
		}
		/* If success, subtract submitted amount. */
		atomic_add64((unsigned long *) &(ci->used_bytes_diff), -bd);
		atomic_add64((unsigned long *) &(ci->used_count_diff), -cd);
	}

	/* get fresh stats from cluster. */
	err = ccow_sharded_attributes_get(tc, ci->bid, ci->bid_size,
	    ci->stats_list_context, &bd, &cd, &dummy);
	if (err) {
		log_warn(fsio_lg, "ccow_sharded_attributes_get failed, err %d",
		    err);
		goto out;
	}
	ci->used_bytes = bd;
	ci->used_count = cd;

out:
	log_debug(fsio_lg, "completed ci: %p", ci);
	return;
}


static void *
flusher_main(void *arg)
{
	int flusher_stat_counter;
	ci_t *ci;

	flusher_stat_counter = 0;
	ci = (ci_t *) arg;

	log_trace(fsio_lg, "arg: %p", arg);

	while (ci->flusher_run) {
		sleep(TIMER_INTERVAL);
		ccowfs_inode_flusher(ci, 0, 0);
		if (flusher_stat_counter > (FLUSHER_STAT_INTERVAL /
		    TIMER_INTERVAL)) {
			log_trace(fsio_lg, "arg: %p", arg);
			flusher_sync_fsstat(ci);
			flusher_stat_counter = 0;
		} else
			flusher_stat_counter++;
	}

	log_debug(fsio_lg, "completed arg: %p", arg);

	return NULL;
}

static ccowfs_inode *
__get_locked_inode_to_flush(ci_t * ci, int mem_pressure)
{
	uint64_t ts;
	QUEUE *q;
	QUEUE *tmp_q;
	ccowfs_inode *q_inode = NULL;
	int found = 0;

	log_trace(fsio_lg, "Bucket: %s, mem_pressure: %d",
		ci->bid, mem_pressure);

	ts = get_timestamp_us();

	if (!QUEUE_EMPTY(&ci->open_files_head)) {
		QUEUE_FOREACH(q, &ci->open_files_head) {
			q_inode = QUEUE_DATA(q, ccowfs_inode, dirty_q);

			/*
			 * We can get called from timer or from other op if
			 * there is memory pressure.
			 * If we get called from __io_setup_locke , the caller
			 * will hold lock on the inode.
			 * We must not lock the inode here, instead just skip
			 * the specific inode.
			 * Hence trylock to lock inode and skip it if we cannot
			 * lock it.
			 *
			 * Read lock is enough as we are not changing in
			 * memory structure.
			 */
			if (pthread_rwlock_tryrdlock(&q_inode->rwlock))
				continue;

			/*
			 * We got the lock on inode. 
			 */

			if (mem_pressure
			    && !disk_worker_is_dirty(ci,
				&(q_inode->disk_worker))) {
				/*
				 * In case of mem_pressure, return inodes which
				 * have open completion.
				 * Skip this specific inode.
				 */
				pthread_rwlock_unlock(&q_inode->rwlock);
				continue;
			}

			if (q_inode->dirty == 0) {
				/*
				 * Nothing to flush for this inode.
				 * Still return it so we can remove it from
				 * dirty queue.
				 * No need to check the timestamp as this is
				 * just cleanup and no actual flush to disk.
				 */
				QUEUE_REMOVE(q);
				QUEUE_INIT(&q_inode->dirty_q);
				found = 1;
				log_debug(fsio_lg, "Nothing to flush");
				goto out;
			}

			if (mem_pressure || (q_inode->dirty_time +
				TIMER_INTERVAL * 1000000) < ts) {
				/*
				 * If timesamp of first not flashed write +
				 * 5sec become less than current time, flush
				 * stream.
				 * Also flush the inode if we have
				 * resourse pressure.
				 */
				QUEUE_REMOVE(q);
				QUEUE_INIT(&q_inode->dirty_q);
				found = 1;
				goto out;
			} else
				pthread_rwlock_unlock(&q_inode->rwlock);
		}
	}

out:
	if (found) {
		log_debug(fsio_lg, "found node %lu", q_inode->ino);
		return q_inode;
	}

	log_debug(fsio_lg, "completed Bucket: %s, mem_pressure: %d",
		ci->bid, mem_pressure);

	return NULL;
}

int
ccowfs_inode_flusher(ci_t * ci, int mem_pressure, int max_count)
{
	int err = 0;
	int flushed = 0;
	int dirty = 0;
	ccowfs_inode *q_inode = NULL;

	/*
	 * If mem_pressure is true, then don't check the ts
	 * Flush only max_count inodes. If max_count is 0 then flush all
	 * possible inodes
	 */

	while (1) {
		if (max_count && (flushed > max_count)) {
			/*
			 * We have flushed required number of inodes.
			 */
			break;
		}

		/*
		 * Get one inode, which can be flushed.
		 * Release the queue_mutex while we are flushing the inode.
		 * Drop the dirty queue ref without holding the queue mutex.
		 */
		q_inode = NULL;
		pthread_mutex_lock(&ci->queue_mutex);
		q_inode = __get_locked_inode_to_flush(ci, mem_pressure);
		pthread_mutex_unlock(&ci->queue_mutex);

		if (q_inode) {
			uint8_t flush = 0;
			if (q_inode->dirty) {
				/*
				 * Inode can be dirty if :
				 * 1. Metadata is changed
				 * 2. It has open completion (metadata is also
				 * changed in this case like atime, mtime, size)
				 * 3. There are chunk buffers in inode cache
				 */
				q_inode->dirty = 0;

				/* Flush the inode after dropping the inode lock */
				flush = 1;
			}
			pthread_rwlock_unlock(&q_inode->rwlock);

			if (flush) {
				if (INODE_IS_DISK_DIR(q_inode->ino) || INODE_IS_DIR(q_inode->ino)) {
					log_debug(fsio_lg, "Flushing directory inode %lu attributes", q_inode->ino);
					err = ccow_fsio_dir_set_attr(q_inode);
					if (err) {
						log_softerror(fsio_lg, err,
						    "ccow_fsio_dir_set_attr flush error");
						/*
						 * Cannot do much or Fail.
						 * Just continue.
						 */
						err = 0;
					}
				} else {
					err = ccowfs_inode_sync(q_inode, 0);
					if (err) {
						log_error(fsio_lg,
						    "ccowfs_inode_sync return %d",
						    err);
						/*
						 * Cannot do much or Fail.
						 * Just continue.
						 */
						err = 0;
					}
				}
				flushed++;
			}
			/*
			 * Put the dirty queue ref.
			 */
			ccowfs_inode_put(q_inode);
		} else	/*No more inodes in the queue which can be flushed */
			break;
	}

	log_debug(fsio_lg, "completed Bucket: %s, mem_pressure: %d, max_count: %d",
	    ci->bid, mem_pressure, max_count);

	return err;
}

int
ccowfs_inode_mark_dirty(ccowfs_inode * inode)
{
	int found = 0;
	int err = 0;
	QUEUE *q = NULL;
	ccowfs_inode *q_inode = NULL;

	log_trace(fsio_lg, "inode: %lu", inode->ino);
	/*
	 * find (or create if not found) queue entry for inode
	 */
	inode->dirty = 1;

	pthread_mutex_lock(&inode->ci->queue_mutex);

	/*
	 * Check if inode is part of the LRU queue
	 */
	if (QUEUE_EMPTY(&inode->dirty_q)) {
		/*
		 * Inode is not part of the LRU. Insert it at the end
		 */
		inode->dirty_time = get_timestamp_us();
		QUEUE_INSERT_TAIL(&inode->ci->open_files_head,
		    &inode->dirty_q);

		/*
		 * Get additional ref on the inode for the dirty queue.
		 */
		ccowfs_inode_get(inode);
		log_debug(fsio_lg, "Queue is empty");
		goto out;
	}

	/*
	 * Inode must be present in the queue. Move it at the end.
	 */
	QUEUE_REMOVE(&inode->dirty_q);
	QUEUE_INSERT_TAIL(&inode->ci->open_files_head, &inode->dirty_q);

out:
	pthread_mutex_unlock(&inode->ci->queue_mutex);
	log_debug(fsio_lg, "completed inode: %lu", inode->ino);
	return err;
}

int
ccowfs_inode_mark_clean(ccowfs_inode * inode)
{

	log_trace(fsio_lg, "inode: %lu", inode->ino);
	/*
	 * Remove the inode from dirty list.
	 */
	pthread_mutex_lock(&inode->ci->queue_mutex);

	if (!QUEUE_EMPTY(&inode->dirty_q)) {
		QUEUE_REMOVE(&inode->dirty_q);
		QUEUE_INIT(&inode->dirty_q);

		/*
		 * Put the dirty queue ref.
		 */
		ccowfs_inode_put(inode);
	}

	pthread_mutex_unlock(&inode->ci->queue_mutex);

	log_debug(fsio_lg, "completed inode: %lu", inode->ino);
	return 0;
}

int
fsio_flusher_init(ci_t * ci)
{
	int err = 0;

	log_trace(fsio_lg, "Bucket: %s", ci->bid);

	ci->flusher_run = 1;
	err = pthread_create(&ci->flusher_thread, NULL, flusher_main, ci);
	if (err) {
		log_error(fsio_lg, "ccow_set_usertimer_callback return %d\n",
		    err);
		ci->ccow_err = err;
		goto out;
	}

out:
	log_debug(fsio_lg, "completed Bucket: %s", ci->bid);
	return err;
}

int
fsio_flusher_term(ci_t * ci)
{

	log_trace(fsio_lg, "Bucket: %s", ci->bid);

	ci->flusher_run = 0;
	pthread_join(ci->flusher_thread, NULL);

	log_debug(fsio_lg, "completed Bucket: %s", ci->bid);
	return 0;
}

