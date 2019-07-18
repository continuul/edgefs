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
#include <string.h>

#include <ccow.h>
#include <ccowfsio.h>
#include <queue.h>

#include "fsio_inode.h"
#include "fsio_debug.h"
#include "fsio_system.h"
#include "fsio_common.h"
#include "fsio_cache.h"
#include "fsio_file.h"
#include "fsio_s3_transparency.h"

/**
 *	There are two locks for serialization -
 *		1. Cache lock: Mutex which guards the cache for specific inode.
 *		2. Chunk lock : This guards specific chunk.
 *
 *	Any thread (READ, WRITE, FLUSH) needs to lock the chunks of interest.
 *	Before taking any chunk lock, the thread must acquire the cache mutex.
 *	The cache mutex must be hold only till we get the chunk lock.
 *
 *	The chunk lock acts as region lock and locks one chunk at a time.
 *	The chunks are kept in cache list in sorted order.
 *	This guards against any possible deadlock.
 *
 *	Write thread:
 *		Take the cache mutex
 *		Take lock on the chunks of interest. Write lock is taken for all chunks.
 *		Drop the cache mutex so -
 *			any READ/WRITE to other part of the file can go ahead.
 *			any READ/WRITE to same chunks will be blocked.
 *		If any chunks have empty buffer, then fetch them from CCOW first.
 *		Update the chunks with new data.
 *		Drop the chunk locks.
 *
 *	Read thread:
 *		Take the cache mutex
 *		Take lock on the chunks of interest.
 *			Chunks which are already present in cache will be READ locked.
 *			Chunks which we need to fetch from CCOW will be write locked.
 *		Drop the cache mutex so -
 *			any READ/WRITE to other part of the file can go ahead.
 *			any READ/WRITE to same chunks will be blocked.
 *		If any chunks have empty buffer, then fetch them from CCOW first.
 *		Update the caller buffer from the chunks data.
 *		Drop the chunk locks.
 *		Note: As Read threads also populate the cache and will add chunks to the cache,
 *			 we need mutex for cache and RW lock cannot be used.
 *
 *	Flusher thread:
 *		Take the cache mutex
 *		Take Write lock on all the chunks.
 *		Write only the dirty chunks to CCOW
 *		Remove locked chunks from cache and then drop all chunk locks.
 *		Drop the cache mutex
 *		NOTE: while the cache flush is in progress, we hold the cache mutex.
 *			  any READ/WRITE during this time is blocked.
 *
 */

typedef enum __chunk_lock_type__
{
	CHUNK_READ = 0,
	CHUNK_WRITE,
	CHUNK_FLUSH
} chunk_lock_type;

typedef struct __fsio_chunk_buffer__
{
	uint64_t chunk_no;
	char	*buff;
	size_t	data_size;
	uint64_t chunk_size;
	uint8_t	dirty;
	QUEUE	buffer_q;
	pthread_rwlock_t chunk_rwlock;
} fsio_chunk_buff;

#define	FETCH_FLAGS_READ		(0)
#define	FETCH_FLAGS_WRITE		(1)
#define	FETCH_FLAGS_FIRST_CHUNK_ALIGNED	(1 << 1)
#define	FETCH_FLAGS_LAST_CHUNK_ALIGNED	(1 << 2)

#define IOV_WRITE_MAX	8	/* How many chunks can be written in parallel */

static void
map_chunk_to_file(ccowfs_inode *inode, uint64_t chunk_size,
	uint64_t chunk_no, uint64_t chunk_offset, uint64_t *file_offset)
{
	*file_offset = chunk_size * chunk_no + chunk_offset;
}

static void
map_file_offset_to_chunk(ccowfs_inode *inode, uint64_t chunk_size,
	uint64_t file_offset, uint64_t *chunk_no, uint64_t *chunk_offset)
{
	*chunk_no = file_offset / chunk_size;
	*chunk_offset = file_offset % chunk_size;
}

static void
map_file_to_chunk_range(ccowfs_inode *inode, uint64_t chunk_size,
	uint64_t file_offset, uint64_t data_size,
	uint64_t *first_chunk, uint64_t *last_chunk,
	uint64_t *first_chunk_offset)
{
	*first_chunk = file_offset / chunk_size;
	*first_chunk_offset = file_offset % chunk_size;

	*last_chunk = (file_offset + data_size - 1) / chunk_size;
}

static void
get_last_chunk(ccowfs_inode *inode, uint64_t chunk_size,
	uint64_t *last_chunk, uint64_t *last_chunk_size)
{
	size_t file_size;
	ccowfs_inode_get_size(inode, &file_size);

	if (file_size == 0) {
		*last_chunk = 0;
		*last_chunk_size = 0;
	}
	else {
		*last_chunk = file_size / chunk_size;
		*last_chunk_size = file_size % chunk_size;
	}
}

static int
chunk_init(uint64_t chunk_no, char *buff, size_t data_size,
	fsio_chunk_buff **out_chunk)
{
	int err;
	fsio_chunk_buff *new_chunk;

	new_chunk = (fsio_chunk_buff *)je_calloc(1, sizeof(fsio_chunk_buff));
	if (new_chunk == NULL) {
		log_error(fsio_lg, "failed to allocate memory");
		err = ENOMEM;
		goto out;
	}

	new_chunk->chunk_no = chunk_no;
	new_chunk->buff = buff;
	new_chunk->data_size = data_size;

	err = pthread_rwlock_init(&(new_chunk->chunk_rwlock), NULL);
	if (err) {
		log_error(fsio_lg, "pthread_rwlock_init return %d", err);
		je_free(new_chunk);
		new_chunk = NULL;
	}

out:
	*out_chunk = new_chunk;

	return err;
}

static int
chunk_term(fsio_chunk_buff *chunk)
{
	if (chunk) {
		log_trace(fsio_lg, "chunk_no: %lu",
			chunk->chunk_no);

		assert(chunk->buff == NULL);
		assert(chunk->dirty == 0);
		pthread_rwlock_destroy(&(chunk->chunk_rwlock));

		je_free(chunk);
	}
	return 0;
}

static void
chunk_lock(ccowfs_inode *inode, fsio_chunk_buff *chunk,
	chunk_lock_type lock_type)
{
	/** For flush take READ lock.
	 *	After flush, we mark the chunk as not dirty.
	 *  The non dirty chunks are removed from cache separately.
	 */
	log_trace(fsio_lg, "chunk_no: %lu lock_type: %d",
		chunk->chunk_no, lock_type);

	if (lock_type != CHUNK_WRITE)
		 pthread_rwlock_rdlock(&(chunk->chunk_rwlock));
	else
		pthread_rwlock_wrlock(&(chunk->chunk_rwlock));
}

static fsio_chunk_buff *
cache_find_chunk(ccowfs_inode *inode, uint64_t chunk_no)
{
	QUEUE *q;
	fsio_chunk_buff *chunk = NULL;
	fsio_chunk_buff *found_chunk = NULL;

	log_trace(fsio_lg, "chunk_no: %lu",
		chunk_no);

	QUEUE_FOREACH(q, &inode->buffer_cache_q) {
		chunk = QUEUE_DATA(q, fsio_chunk_buff, buffer_q);
		if (chunk->chunk_no == chunk_no) {
			found_chunk = chunk;
			break;
		}
		if (chunk->chunk_no > chunk_no) {
			/* List of sorted chunks. Required chunk is not present. */
			break;
		}
	}

	return found_chunk;
}

static void
cache_add_new_chunk(ccowfs_inode *inode, fsio_chunk_buff *chunk)
{
	/** Add the new chunk to buffer cache.
	 *	Always insert in sorted order based on chunk number.
	 *	It will help in taking chunk locks in sorted order.
	 */
	QUEUE *q;
	fsio_chunk_buff *chk;

	QUEUE_FOREACH(q, &inode->buffer_cache_q) {
		chk = QUEUE_DATA(q, fsio_chunk_buff, buffer_q);
		assert(chk->chunk_no != chunk->chunk_no);
		if (chk->chunk_no > chunk->chunk_no) {
			break;
		}
	}

	/** If cache is empty, q will be the head of the list.
	 *	Always add the chunk before q.
	 */
	QUEUE_INSERT_BEFORE(q, &chunk->buffer_q);
	atomic_inc64(&inode->cached_chunks);
}

static fsio_chunk_buff *
chunk_lock_by_number(ccowfs_inode *inode, uint64_t chunk_no, chunk_lock_type lock_type)
{
	fsio_chunk_buff *chunk = cache_find_chunk(inode, chunk_no);

	log_trace(fsio_lg, "inode: %lu chunk_no: %lu",
		inode->ino, chunk_no);

	if (chunk)
		chunk_lock(inode, chunk, lock_type);
	else {
		/** Chunk not present in cache.
		 *	Create chunk head with NULL buff and add it to cache.
		 *	This thread will maintain the write lock and on the chunk
		 *		and eventually fetch it from CCOW.
		 */
		chunk_init(chunk_no, NULL, 0, &chunk);
		if (!chunk)
			goto out;

		/* Take write lock on the chunk before adding it to cache */
		pthread_rwlock_wrlock(&(chunk->chunk_rwlock));
		cache_add_new_chunk(inode, chunk);
	}
out:
	return chunk;
}

static void
chunk_unlock(ccowfs_inode *inode, fsio_chunk_buff *chunk)
{
	pthread_rwlock_unlock(&(chunk->chunk_rwlock));
}

static int
chunk_write_data(ccowfs_inode *inode, char *buffer,
	size_t file_offset, size_t data_size, uint64_t chunk_size,
	fsio_chunk_buff **chunk_list, uint64_t cnt)
{
	/** New data is received in the buffer.
	 *	This data needs to be written at file_offset.
	 *	The specific chunk(s) for the file reagion are already locked.
	 *	The start and/or end of the data may not be chunk aligned.
	 */
	int err = 0;
	uint64_t sz_done = 0;
	uint64_t buffer_offset = 0;
	uint64_t chunk_no, chunk_offset, chunk_copy_sz, chunk_remaining_sz;

	log_trace(fsio_lg, "inode: %lu file_offset : %lu, data_size :%lu",
		inode->ino, file_offset, data_size);

	for (uint64_t i=0; i<cnt; i++) {
		/** Zero buffer must already be allocated if chunk is outside the file size.
		 *	We expect all data buffers are to be already allocatd.
		 */
		assert(chunk_list[i]->buff);

		/* Determine the buffer and chunk offsets for the data copy */
		map_file_offset_to_chunk(inode, chunk_size, file_offset+sz_done,
			&chunk_no, &chunk_offset);

		assert(chunk_no == chunk_list[i]->chunk_no);
		assert(chunk_offset < chunk_size);
		assert(buffer_offset < data_size);

		chunk_remaining_sz = chunk_size - chunk_offset;
		chunk_copy_sz = MIN(chunk_remaining_sz, (data_size - sz_done));

		log_debug(fsio_lg,
			"Copy data inode :%lu chunk: %lu chunk_off: %lu "
			"cp_sz: %lu, buffer_offset :%lu",
			inode->ino, chunk_no, chunk_offset,
			chunk_copy_sz, buffer_offset);

		/* Copy part of the data to the chunk buffer */
		memcpy(chunk_list[i]->buff+chunk_offset, buffer+buffer_offset, chunk_copy_sz);
		buffer_offset += chunk_copy_sz;
		sz_done += chunk_copy_sz;

		if (! chunk_list[i]->dirty) {
			atomic_inc64(&inode->dirty_chunks);
			chunk_list[i]->dirty = 1;
		}

		/*If chunk now contains more data tahn before, update the data size */
		if (chunk_offset+chunk_copy_sz > chunk_list[i]->data_size) {
			log_debug(fsio_lg,
				"inode :%lu chunk: %lu data_size: %lu new data_size: %lu",
				inode->ino, chunk_no, chunk_list[i]->data_size,
				chunk_offset+chunk_copy_sz);
			chunk_list[i]->data_size = chunk_offset+chunk_copy_sz;
		}
	}
	assert(sz_done == data_size);

	return err;
}

static int
chunk_read_data(ccowfs_inode *inode, char *buffer,
	size_t file_offset, size_t data_size, uint64_t chunk_size,
	fsio_chunk_buff **chunk_list, uint64_t cnt)
{
	uint64_t sz_done = 0;
	uint64_t buffer_offset = 0;
	uint64_t chunk_no, chunk_offset, chunk_copy_sz, chunk_remaining_sz;

	log_trace(fsio_lg, "inode: %lu file_offset: %lu data_size: %lu",
		inode->ino, file_offset, data_size);

	for (uint64_t i=0; i<cnt; i++) {
		assert(chunk_list[i]->buff && chunk_list[i]->data_size);

		/* Determine the buffer and chunk offset for the data copy */
		map_file_offset_to_chunk(inode, chunk_size, file_offset+sz_done,
			&chunk_no, &chunk_offset);

		assert(chunk_no == chunk_list[i]->chunk_no);
		assert(chunk_offset < chunk_size);
		assert(buffer_offset < data_size);

		chunk_remaining_sz = chunk_size - chunk_offset;
		chunk_copy_sz = MIN(chunk_remaining_sz, (data_size - sz_done));

		log_debug(fsio_lg,
			"Copy data inode :%lu chunk: %lu chunk_off: %lu "
			"cp_sz: %lu buffer_offset :%lu",
			inode->ino, chunk_no, chunk_offset, chunk_copy_sz, buffer_offset);

		memcpy(buffer + buffer_offset, (chunk_list[i]->buff) + chunk_offset, chunk_copy_sz);
		buffer_offset += chunk_copy_sz;
		sz_done += chunk_copy_sz;
	}
	assert(sz_done == data_size);

	return 0;
}

/**
 * Read ALL chunks from chunk_fetch_list from CCOW layer
 * Addd the data buffe for the chunks.
 */
static int
chunk_fetch_multiple(ccowfs_inode *inode, int flags, uint64_t chunk_size,
	fsio_chunk_buff **chunk_fetch_list, uint64_t fetch_cnt,
	uint64_t last_chunk, uint64_t last_chunk_size,
	ccow_completion_t c, int *last_io)
{
	int err = 0;
	struct iovec *iov = NULL;
	uint64_t mask = chunk_size;
	mask--;

	log_trace(fsio_lg, "inode: %lu fetch_cnt: %lu ",
		inode->ino, fetch_cnt);

	iov = (struct iovec *) je_calloc(fetch_cnt, sizeof(struct iovec));
	if (!iov){
		err = ENOMEM;
		goto out;
	}

	/* Schedule multiple ccow_put_cont. One for each chunk. */
	uint64_t offset;
	for (uint64_t i = 0; i < fetch_cnt; i++) {
		log_debug(fsio_lg,
			"Allocating buff for iov. chunk: %lu for inode: %lu ",
			chunk_fetch_list[i]->chunk_no, inode->ino);

		iov[i].iov_base = (void *)je_calloc(1, chunk_size);
		if (!iov[i].iov_base){
			err = ENOMEM;
			goto out;
		}
		iov[i].iov_len = chunk_size;
		map_chunk_to_file(inode, chunk_size, chunk_fetch_list[i]->chunk_no,
			0, &offset);

		if ((flags & FETCH_FLAGS_WRITE) == FETCH_FLAGS_WRITE) {
			if (!(i == 0 &&
			    (flags & FETCH_FLAGS_FIRST_CHUNK_ALIGNED) !=
			    FETCH_FLAGS_FIRST_CHUNK_ALIGNED) &&
			    /* if not first unaligned chunk and ... */
			    !(i == (fetch_cnt - 1) &&
			    (flags & FETCH_FLAGS_LAST_CHUNK_ALIGNED) !=
			    FETCH_FLAGS_LAST_CHUNK_ALIGNED)) {
			    /* ... not last unaligned chunk. */
			    /*
			     * Will fetch #0 also, if single chunk with
			     * unaligned tail.
			     */
				log_trace(fsio_lg, "Skipping read of aligned "
				    "chunk. inode %lu at offset: %lu "
				    "chunk: %lu (i: %lu of %lu, %saligned/%saligned)", inode->ino, offset,
				    chunk_fetch_list[i]->chunk_no, i, fetch_cnt,
				    (flags & FETCH_FLAGS_FIRST_CHUNK_ALIGNED)?"":"un",
				    (flags & FETCH_FLAGS_LAST_CHUNK_ALIGNED)?"":"un");
				continue;
			} else {
				log_trace(fsio_lg, "Fetching of unaligned "
				    "chunk. inode %lu at offset: %lu "
				    "chunk: %lu (i: %lu of %lu, %saligned/%saligned)", inode->ino, offset,
				    chunk_fetch_list[i]->chunk_no, i, fetch_cnt,
				    (flags & FETCH_FLAGS_FIRST_CHUNK_ALIGNED)?"":"un",
				    (flags & FETCH_FLAGS_LAST_CHUNK_ALIGNED)?"":"un");
			}
		}

		log_debug(fsio_lg,
			"ccow_get_cont for inode: %lu offset: %lu chunk: %lu",
			inode->ino, offset, chunk_fetch_list[i]->chunk_no);

		err = ccow_get_cont(c, &(iov[i]), 1, offset & (~mask), 1, last_io);
		if (err) {
			log_error(fsio_lg,  "ccow_get_cont return %d", err);
			goto out;
		}

		assert(*last_io < MAX_OP_COUNT);

		log_debug(fsio_lg, "ccow_wait for index :%d for inode: %lu",
			*last_io, inode->ino);

		err = ccow_wait(c, *last_io);
		if (err) {
			log_error(fsio_lg,
				"inode: %lu ccow_wait return %d for chunk-no: %lu",
				inode->ino, err, chunk_fetch_list[i]->chunk_no);
			goto out;
		}
	}

	/** Assign the iov buffers to the respective chunks
	 *	The buffer ownership is transfered to the chunk and buffer cache.
	 */
	for (uint64_t i=0; i<fetch_cnt; i++) {
		assert(iov[i].iov_base);
		assert(chunk_fetch_list[i]->buff == NULL);

		chunk_fetch_list[i]->buff = iov[i].iov_base;
		iov[i].iov_base = NULL;
		chunk_fetch_list[i]->chunk_size = chunk_size;

		/** Fetching chunk beyound the file size
		 *		- The data_size for this chunk is always zero
		 *	Fetching last chunk of the file
		 *		- The data size depends on the file size and hence offset in the chunk.
		 *	Fetching non-last chunk of the file
		 *		- The data size is always same as full chunk size.
		 */
		if (last_chunk > chunk_fetch_list[i]->chunk_no)
			chunk_fetch_list[i]->data_size = chunk_size;
		else if (last_chunk == chunk_fetch_list[i]->chunk_no)
			chunk_fetch_list[i]->data_size = last_chunk_size;
		else {
			/* Should not fetch chunks beyound the file size */
			assert(0);
		}

		log_debug(fsio_lg,
			"chunk takes buff from iov. chunk: %lu for inode: %lu data_size: %lu",
			chunk_fetch_list[i]->chunk_no, inode->ino, chunk_fetch_list[i]->data_size);
	}

out:

	if (iov) {
		for (uint64_t i=0; i<fetch_cnt; i++) {
			if (iov[i].iov_base) {
				/** In no error case -
				 * the chunk and buffer cache shuld take the buffer ownership.
				 * As we have the iov buffer we expect this to be error case.
				 */
				assert(err);
				je_free(iov[i].iov_base);

				log_debug(fsio_lg,
					"Free iov buff %lu for inode: %lu err: %d",
					i, inode->ino, err);
			}
		}
		je_free(iov);
	}

	return err;
}

/**
 * Confirm that the chunks from the chunk_list have data buffer.
 * If required read chunk data from CCOW or allocate zero buffer.
 */
static int
cache_populate_chunks_data(ccowfs_inode *inode, int flags,
	fsio_chunk_buff **chunk_list, uint64_t cnt,
	uint64_t chunk_size, ccow_completion_t c, int *last_io)
{
	int err = 0;
	uint64_t fetch_cnt = 0;
	fsio_chunk_buff **chunk_fetch_list = NULL;

	log_trace(fsio_lg, "inode: %lu cnt: %lu ",
		inode->ino, cnt);

	chunk_fetch_list = (fsio_chunk_buff **) je_calloc(cnt, sizeof(fsio_chunk_buff *));
	if (!chunk_fetch_list) {
		err = ENOMEM;
		goto out;
	}

	/**
	 *	All the required chunks are present in cache (with or without data buffer).
	 *	The caller has write lock on the required chunks.
	 *	Some chunks may already have buffer associated with them.
	 *	No need to fetch such chunks as cache data is always latest.
	 */
	uint64_t last_chunk, last_chunk_size;
	get_last_chunk(inode, chunk_size, &last_chunk, &last_chunk_size);

	for (uint32_t i=0; i<cnt; i++) {
		/* If buffer is present. Don't fetch the chunk */
		if (chunk_list[i]->buff) {
			assert(chunk_list[i]->chunk_size == chunk_size);
			continue;
		}

		/** If chunk is outside the file size, just allocate zero buffer.
		 *	Need this to handle writes outside the file end.
		 */
		if (chunk_list[i]->chunk_no > last_chunk) {
			log_debug(fsio_lg,
				"Skipping fetch outside file. chunk_no: %lu last_chunk :%lu",
				chunk_list[i]->chunk_no, last_chunk);

			chunk_list[i]->buff = (void *)je_calloc(1, chunk_size);
			if (!chunk_list[i]->buff) {
				err = ENOMEM;
				goto out;
			}
			chunk_list[i]->data_size = 0;
			chunk_list[i]->chunk_size = chunk_size;
			continue;
		}

		log_debug(fsio_lg, "inode: %lu marking chunk :%lu for fetching",
			inode->ino, chunk_list[i]->chunk_no);

		/* Need to fetch this chunk */
		chunk_fetch_list[fetch_cnt] = chunk_list[i];
		fetch_cnt++;
	}

	assert(fetch_cnt <= cnt);

	if (fetch_cnt) {
		err = chunk_fetch_multiple(inode, flags, chunk_size,
			chunk_fetch_list, fetch_cnt,
			last_chunk, last_chunk_size,
			c, last_io);
		if (err) {
			log_error(fsio_lg,
			"chunk_fetch_multiple return %d for %lu chunks", err, fetch_cnt);
		}
		goto out;
	}

out:
	if (chunk_fetch_list)
		je_free(chunk_fetch_list);

	return err;
}

static void
cache_lock_multiple_chunks(ccowfs_inode *inode,
	uint64_t first_chunk, uint64_t last_chunk,
	chunk_lock_type lock_type,
	fsio_chunk_buff **chunk_list, uint64_t count)
{
	uint64_t cnt = 0;

	log_trace(fsio_lg, "inode: %lu first_chunk: %lu last_chunk: %lu",
		inode->ino, first_chunk, last_chunk);

	assert(first_chunk <= last_chunk);

	pthread_mutex_lock(&(inode->buffer_cache_mutex));
	for (uint64_t i=first_chunk; i<=last_chunk; i++) {
		log_debug(fsio_lg,
			"inode: %lu locking chunk_no: %lu",
			inode->ino, i);
		chunk_list[cnt] = chunk_lock_by_number(inode, i, lock_type);
		cnt++;
	}
	assert(cnt == count);
	pthread_mutex_unlock(&(inode->buffer_cache_mutex));
}

static void
cache_unlock_and_free_chunk(ccowfs_inode *inode, fsio_chunk_buff *chunk)
{
	log_debug(fsio_lg, "inode: %lu chunk_no: %lu",
		inode->ino, chunk->chunk_no);

	assert(!chunk->dirty);

	QUEUE_REMOVE(&chunk->buffer_q);
	QUEUE_INIT(&chunk->buffer_q);
	atomic_dec64(&inode->cached_chunks);

	if (chunk->buff){
		log_debug(fsio_lg, "Free buffer for inode: %lu chunk_no: %lu",
			inode->ino, chunk->chunk_no);
		je_free(chunk->buff);
		chunk->buff = NULL;
	}
	pthread_rwlock_unlock(&chunk->chunk_rwlock);
	chunk_term(chunk);
}

static void
cache_unlock_and_free_multiple_chunks(ccowfs_inode *inode, fsio_chunk_buff **chunk_list,
	uint64_t count)
{
	fsio_chunk_buff *chunk;

	log_debug(fsio_lg, "inode: %lu, count: %lu cached_chunks:%lu ",
		inode->ino, count, atomic_get_uint64(&inode->cached_chunks));

	for (uint64_t i=0; i<count; i++) {
		if (chunk_list[i]){
			chunk = chunk_list[i];
			assert(! chunk->dirty);
			cache_unlock_and_free_chunk(inode, chunk);
			chunk_list[i] = NULL;
		}
	}

	log_debug(fsio_lg, "inode: %lu cached_chunks: %lu",
		inode->ino, atomic_get_uint64(&inode->cached_chunks));
}

static void
cache_lock_multiple_dirty_chunks(ccowfs_inode *inode, chunk_lock_type lock_type,
	fsio_chunk_buff **chunk_list, uint64_t count, uint64_t *found_dirty)
{
	QUEUE *q;
	fsio_chunk_buff *chunk;
	uint64_t locked_count = 0;

	log_trace(fsio_lg, "inode: %lu count: %lu ",
		inode->ino, count);

	pthread_mutex_lock(&(inode->buffer_cache_mutex));
	QUEUE_FOREACH(q, &inode->buffer_cache_q) {
		chunk = QUEUE_DATA(q, fsio_chunk_buff, buffer_q);
		chunk_lock(inode, chunk, lock_type);
		if (chunk->dirty) {
			chunk_list[locked_count] = chunk;
			locked_count++;
		}
		else
			chunk_unlock(inode, chunk);

		if(locked_count == count)
			break;
	}
	pthread_mutex_unlock(&(inode->buffer_cache_mutex));

	*found_dirty = locked_count;
}

static void
cache_unlock_multiple_chunks(ccowfs_inode *inode,
	fsio_chunk_buff **chunk_list, uint64_t cnt)
{
	log_trace(fsio_lg, "inode: %lu cnt: %lu",
		inode->ino, cnt);

	for (uint64_t i=0; i<cnt; i++)
		pthread_rwlock_unlock(&(chunk_list[i]->chunk_rwlock));
}

static void
cache_lock_all_chunks(ccowfs_inode *inode, chunk_lock_type lock_type)
{
	QUEUE *q;
	fsio_chunk_buff *chk;

	log_trace(fsio_lg, "inode: %lu",
		inode->ino);

	QUEUE_FOREACH(q, &inode->buffer_cache_q) {
		chk = QUEUE_DATA(q, fsio_chunk_buff, buffer_q);
		chunk_lock(inode, chk, lock_type);
	}
}

static void
cache_unlock_all_chunks(ccowfs_inode *inode)
{
	QUEUE *q;
	fsio_chunk_buff *chk;

	log_trace(fsio_lg, "inode: %lu",
		inode->ino);

	QUEUE_FOREACH(q, &inode->buffer_cache_q) {
		chk = QUEUE_DATA(q, fsio_chunk_buff, buffer_q);
		pthread_rwlock_unlock(&(chk->chunk_rwlock));
	}
}

static int
cache_flush_locked_chunks(ccowfs_inode *inode, fsio_chunk_buff **chunk_list,
	uint64_t count, ccow_completion_t c, int *last_io)
{
	int err;
	struct iovec *iov = NULL;
	QUEUE *q;
	fsio_chunk_buff *chunk;
	ci_t *ci = inode->ci;
	uint64_t file_offset;
	uint64_t mask;
	uint64_t chunk_size = 0;
	size_t iovcnt = 0;

	assert(count < MAX_OP_COUNT);

	iov = je_calloc(count, sizeof(struct iovec));
	if (!iov){
		err = ENOMEM;
		goto out;
	}

	disk_worker_get_chunk_size(ci, &(inode->disk_worker), &chunk_size);

	uint64_t chunk_offset_prev = 0;
	uint64_t chunk_offset_start = 0;
	int writes = 0;
	mask = chunk_size;
	mask--;
	for (uint64_t i=0; i<count; i++) {

		chunk = chunk_list[i];
		assert(chunk->dirty);
		assert(chunk->chunk_size == chunk_size);

		log_debug(fsio_lg,
			"inode: %lu chunk_no: %lu size: %lu",
			inode->ino, chunk->chunk_no, chunk->data_size);

		map_chunk_to_file(inode, chunk_size, chunk->chunk_no, 0, &file_offset);
		uint64_t chunk_offset = file_offset & (~mask);
		if (iovcnt == 0) {
			chunk_offset_start = chunk_offset;
		}

		int adjacent = (chunk_offset_prev + chunk_size == chunk_offset);

		log_debug(fsio_lg, "Map chunk[%lu]: %lu to offset: %lu adjacent: %d",
			iovcnt, chunk->chunk_no, file_offset, adjacent);

		if (!adjacent && iovcnt > 0) {
			err = ccow_put_cont(c, &(iov[0]), iovcnt, chunk_offset_start, 1, last_io);
			if (err) {
				log_error(fsio_lg, "ccow_put_cont return %d", err);
				goto out;
			}

			err = ccow_wait(c, *last_io);
			if (err != 0) {
				log_error(fsio_lg, "ccow_wait return %d", err);
				goto out;
			}

			log_debug(fsio_lg,
				"inode: %lu flushed %lu vectors, startoff=%lu, i=%lu, count=%lu",
				inode->ino, iovcnt, chunk_offset_start, i, count);

			chunk_offset_start = chunk_offset;
			iovcnt = 0;
			writes++;
		}
		chunk_offset_prev = chunk_offset;

		iov[iovcnt].iov_base = chunk->buff;
		if (inode->stat.st_size == (int64_t)(chunk_offset + chunk->data_size))
			/* last chunk in file - no need to write full len */
			iov[iovcnt].iov_len = chunk->data_size;
		else
			iov[iovcnt].iov_len = chunk_size;
		iovcnt++;

		if (iovcnt == IOV_WRITE_MAX || i + 1 == count) {

			err = ccow_put_cont(c, &(iov[0]), iovcnt, chunk_offset_start, 1, last_io);
			if (err) {
				log_error(fsio_lg, "ccow_put_cont return %d", err);
				goto out;
			}

			err = ccow_wait(c, *last_io);
			if (err != 0) {
				log_error(fsio_lg, "ccow_wait return %d", err);
				goto out;
			}

			log_debug(fsio_lg,
				"inode: %lu adjacent flushed %lu vectors, startoff=%lu, i=%lu, count=%lu",
				inode->ino, iovcnt, chunk_offset_start, i, count);

			iovcnt = 0;
			writes++;
		}

		chunk->dirty = 0;
		atomic_dec64(&inode->dirty_chunks);
	}

	log_debug(fsio_lg,
		"inode: %lu flushed in %d writes as asked to flush %lu chunks",
		inode->ino, writes, count);

	assert((*last_io != DEFAULT_LAST_IO) && (*last_io < MAX_OP_COUNT));

out:
	if (iov)
		je_free(iov);

	return err;
}

static void
cache_free_all_clean_chunks(ccowfs_inode *inode)
{
	QUEUE *q, *tmp_q;
	fsio_chunk_buff *chunk;

	pthread_mutex_lock(&(inode->buffer_cache_mutex));

    QUEUE_FOREACH_SAFE(q, tmp_q, &inode->buffer_cache_q) {
        chunk = QUEUE_DATA(q, fsio_chunk_buff, buffer_q);
		if (! chunk->dirty) {
			/** We want to free the chunk. Take WRITE lock */
			chunk_lock(inode, chunk, CHUNK_WRITE);

			/* confirm again after taking the lock */
			if (! chunk->dirty)
				cache_unlock_and_free_chunk(inode, chunk);
			else
				chunk_unlock(inode, chunk);
		}
    }

	pthread_mutex_unlock(&(inode->buffer_cache_mutex));
}

static void
chunk_replace_buff(ccowfs_inode *inode, fsio_chunk_buff *chunk,
	char *buffer, size_t data_size)
{

	log_trace(fsio_lg, "inode: %lu chunk_no: %lu data_size: %lu",
		inode->ino, chunk->chunk_no, data_size);

	pthread_rwlock_wrlock(&(chunk->chunk_rwlock));

	if (chunk->buff)
		je_free(chunk->buff);

	/* Take ownership for the new buffer */
	chunk->buff = buffer;
	chunk->data_size = data_size;

	if (! chunk->dirty){
		chunk->dirty = 1;
		atomic_inc64(&inode->dirty_chunks);
	}

	pthread_rwlock_unlock(&(chunk->chunk_rwlock));
}

static void
cache_add_chunk(ccowfs_inode *inode, fsio_chunk_buff *chunk)
{
	log_trace(fsio_lg, "inode: %lu chunk_no: %lu ",
		inode->ino, chunk->chunk_no);

	pthread_mutex_lock(&(inode->buffer_cache_mutex));

	fsio_chunk_buff *existing_chunk = cache_find_chunk(inode, chunk->chunk_no);
	if (existing_chunk) {
		assert(existing_chunk != chunk);

		chunk_replace_buff(inode, existing_chunk, chunk->buff, chunk->data_size);

		/** Free up the new chunk as it is not needed any more
		 *	Buffer is now owned by the existing chunk from cache.
		 */
		chunk->buff = NULL;
		chunk_term(chunk);
		chunk = NULL;
	}
	else {
		/** New chunk cannot be dirty.
		 *	No need for chunk lock - it is not in buffer cache yet.
		 */
		assert(!chunk->dirty && chunk->buff && chunk->data_size);

		/* Insert new chunk to the buffer cache and mark it as dirty */
		chunk->dirty = 1;
		cache_add_new_chunk(inode, chunk);
		atomic_inc64(&inode->dirty_chunks);
	}

	pthread_mutex_unlock(&(inode->buffer_cache_mutex));
}

int
fsio_buffer_cache_write(ccowfs_inode *inode, size_t file_offset, size_t data_size,
	void *buffer)
{
	int err = 0;
	ci_t *ci = inode->ci;
	fsio_chunk_buff **chunk_list = NULL;
	uint64_t first_chunk, last_chunk, first_chunk_offset;
	int last_io = DEFAULT_LAST_IO;
	ccow_completion_t c = NULL;
	uint8_t locked = 0;

	log_trace(fsio_lg, "inode: %lu file_offset: %lu data_size: %lu",
		inode->ino, file_offset, data_size);

	/** We can write only to regular files and not S3 objects.
	 *	Regular files are not expected to change chunk_size.
	 *	Assume the file chunk size is same as the bucket chunk size.
	 *	We have asserts further down in the code path to verrify this.
	 */
	assert(! inode->read_only);
	uint64_t chunk_size = inode->ci->bk_attrs.chunk_size;

	map_file_to_chunk_range(inode, chunk_size, file_offset, data_size,
		&first_chunk, &last_chunk, &first_chunk_offset);
	uint64_t cnt = last_chunk - first_chunk + 1;

	/** Case 1: buffer represents exactly one chunk
	 *			Just add the chunk to cache.
	 */
	if (first_chunk_offset == 0 && data_size == chunk_size) {
		log_debug(fsio_lg,
			"Aligned write. inode: %lu offset: %lu chunk_no: %lu",
			inode->ino, file_offset, first_chunk);

		assert(first_chunk == last_chunk);

		/**
		* The buffer represents exactly one chunk.
		* Use the same buffer in cache.
		* If the same chunk is present in cache, replace the chunk buffer with new one.
		*/
		fsio_chunk_buff *chunk = NULL;
		chunk_init(first_chunk, (char *)buffer, data_size, &chunk);
		if (!chunk)
			goto out;

		chunk->chunk_size = chunk_size;
		cache_add_chunk(inode, chunk);

		/* Even though we are replacing buffer, we could be appending data. */
		err = ccowfs_inode_update_size(inode, file_offset + data_size);

		/** Take ownership for buffer. It will be freed once we write it to disk
		 *	The buffer must be accessed as part of the chunk.
		 *	The chunk must be accessed as part of the cache QUEUE.
		 */
		chunk = NULL;
		buffer = NULL;
		goto out;
	}

	/* Case 2: Buffer represents more then one chunks and/or un-aligned data */
	log_debug(fsio_lg,
		"Un-aligned write. inode: %lu offset: %lu buffer size: %lu"
		"first_chunk: %lu last_chunk :%lu",
		inode->ino, file_offset, data_size, first_chunk, last_chunk);

	chunk_list = (fsio_chunk_buff **) je_calloc(1, sizeof(fsio_chunk_buff *) * cnt);
	if (!chunk_list) {
		log_error(fsio_lg, "Failed to allocate memory");
		err = ENOMEM;
		goto out;
	}

	/** The actual data write does not happen in this thread.
	 *	Just add the data to cache are return.
	 *	The data write will happen via flusher thread
	 *		and/or when there are not enough completion OPs
	 *	un-aligned case:
	 *		Need to read chunks in cache and then update the in-memory chunks.
	 *		So take read ref on the completion.
	 *
	 *	[TODO]
	 *		un-aligned case:
	 *			Need to read only the first and last chunk.
	 *			The intermediatte chunks can be overwritte completely.
	 *			No need to fetch them from disk.
	 *			Fetching all the chunks from disk at present.
	 */
	err = disk_worker_get_read_ref(inode->ci, &(inode->disk_worker),
		file_offset, data_size, &c);
	if (err) {
		log_error(fsio_lg,
		"disk_worker_get_read_ref return %d", err);
		goto out;
	}

	/** The completion is open now. we know the exact chunk size on object.
	 * Confirm that it is same as we assumed.
	 */
	uint64_t completion_chunk_size;
	disk_worker_get_chunk_size(inode->ci, &(inode->disk_worker), &completion_chunk_size);
	assert(chunk_size == completion_chunk_size);

	/** Read completion will update the chunk data.
	 * Need to take WRITE lock on all the chunks which are getting fetched.
	 */
	cache_lock_multiple_chunks(inode, first_chunk, last_chunk,
		CHUNK_WRITE, chunk_list, cnt);
	locked = 1;

	/*
	 * Do not do pre-read if start offset and end offset are aligned to
	 * chunk_size.
	 */
	int flags = FETCH_FLAGS_WRITE;
	flags |= ((file_offset % chunk_size) == 0) ?
	    FETCH_FLAGS_FIRST_CHUNK_ALIGNED : 0;
	flags |= (((file_offset + data_size) % chunk_size) == 0) ?
	    FETCH_FLAGS_LAST_CHUNK_ALIGNED : 0;

	if (flags & (FETCH_FLAGS_FIRST_CHUNK_ALIGNED|
	    FETCH_FLAGS_LAST_CHUNK_ALIGNED))
		log_debug(fsio_lg, "Do not fetch aligned chunks for inode: %lu at offset %lu size %lu",
			inode->ino, file_offset, data_size);
	/** We have write lock on chunks from first_chunk to last_chunk
	 *	May need to fetch these chunks if they are not in cache.
	 */
	err = cache_populate_chunks_data(inode, flags, chunk_list, cnt,
		chunk_size, c, &last_io);
	if (err) {
		inode->ci->ccow_err = err;
		log_error(fsio_lg, "Failed to fetch chunks for inode: %lu with err: %d",
			inode->ino, err);
		goto out;
	}

	/**
	 *	Releasing the disk_worker read ref here.
	 *	We are done fetching the data from CCOW and have write locks on the chunks of interest.
	 *	Releasing the completion may allow read/write to other part of the file.
	 */
	err = disk_worker_put_read_ref(inode->ci, &(inode->disk_worker),
		last_io);
	c = NULL;
	if (err) {
		log_error(fsio_lg,
			"disk_worker_put_read_ref return %d", err);
		disk_worker_flush(inode->ci, &(inode->disk_worker), 0);
		goto out;
	}

	/** All the required chunks are now present in cache and are write locked.
	 *	As inpput buffer does not represent exact chunk, need to do data copy.
	 *	If any other thread comes in to read/write/flush the cache -
	 *		It will block at the first locked chunk.
	 *	Read/Write to any other areas of the file will continue as is.
	 */
	err = chunk_write_data(inode, buffer, file_offset, data_size,
			chunk_size, chunk_list, cnt);
	if (err) {
		inode->ci->ccow_err = err;
		log_error(fsio_lg,
			"chunk_write_data failed for inode: %lu with err: %d",
			inode->ino, err);
		goto out;
	}

	/** It is important to update the size while holding the chunk locks.
	 *	If chunnk locks are released, then the cached dirty pages can get flushed.
	 *	We want to flush the page along with the related metadata like 'file size'
	 */
	err = ccowfs_inode_update_size(inode, file_offset + data_size);
	if (err) {
		log_error(fsio_lg, "update_size failed for inode: %lu with err: %d",
			inode->ino, err);
		goto out;
	}

out:
	if (locked)
		cache_unlock_multiple_chunks(inode, chunk_list, cnt);

	if (c) {
		assert(err);

		int err1;
		err1 = disk_worker_put_read_ref(inode->ci, &(inode->disk_worker),
			last_io);
		if (err1) {
			log_error(fsio_lg,
				"disk_worker_put_read_ref return %d", err1);

			disk_worker_flush(inode->ci, &(inode->disk_worker), 0);
		}
	}

	if (buffer)
		je_free(buffer);
	if (chunk_list)
		je_free(chunk_list);

	log_debug(fsio_lg, "Completed inode: %lu file_offset: %lu data_size: %lu",
		inode->ino, file_offset, data_size);
	return err;
}

/** Given a part map -
 *		Read the data from object part in the buffer
 *		The buffer must have enough size.
 */
static int
read_s3_object_part(ci_t *ci, s3_object_parts_maps *part_map, char *buffer)
{
	int err = 0;
	ccow_completion_t c = NULL;
	uint64_t genid = 0;
	uint64_t chunk_size = 0;
	uint64_t sz_read = 0;
	uint64_t chunk_count;
	uint64_t chunks_to_read = 0;
	uint64_t current_offset = part_map->offset;
	struct iovec *iov = NULL;
	char *key;
	struct ccow_metadata_kv *kv;

	while (sz_read < part_map->size) {
		ccow_lookup_t iter = NULL;

		if (c) {
			ccow_cancel(c);
			c = NULL;
		}

		err = ccowfs_create_stream_completion(ci,
			part_map->name, strlen(part_map->name)+1,
			&genid, MAX_OP_COUNT, 0, &c, &iter);
		if (err) {
			log_error(fsio_lg, "ccowfs_create_stream_completion return %d",
				err);
			goto out;
		}

		int pos = 0;
		if (iter) {
			while ((kv = ccow_lookup_iter(iter,
				         CCOW_MDTYPE_METADATA | CCOW_MDTYPE_CUSTOM, pos++))) {
				key = kv->key;
				if (strcmp(key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
					ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv,
						&chunk_size);
					break;
				}
			}
		}
		else {
			err = -EIO;
			goto out;
		}

		log_debug(fsio_lg, "obj part: %s chunk_size:%lu", part_map->name, chunk_size);
		uint64_t first_chunk = current_offset / chunk_size;
		uint64_t last_chunk =
			(current_offset + (part_map->size - sz_read - 1)) / chunk_size;

		chunk_count = last_chunk - first_chunk + 1;
		chunks_to_read = MIN(chunk_count, MAX_OP_COUNT);

		log_debug(fsio_lg, "obj part: %lu read chunks: %lu from: %lu to %lu",
			part_map->number, chunks_to_read, first_chunk, last_chunk);

		iov = (struct iovec *) je_calloc(chunks_to_read, sizeof(struct iovec));
		if (!iov){
			err = ENOMEM;
			goto out;
		}

		for (uint64_t i=0; i<chunks_to_read; i++){
			iov[i].iov_base = (void *)je_calloc(1, chunk_size);
			if (!iov[i].iov_base){
				err = ENOMEM;
				goto out;
			}
			iov[i].iov_len = chunk_size;
		}

		uint64_t mask = chunk_size;
		int last_io;
		mask--;
		err = ccow_get_cont(c, iov, chunks_to_read,
				current_offset & (~mask), 1, &last_io);
		if (err) {
			log_error(fsio_lg, "ccow_get_cont return %d", err);
			goto out;
		}

		err = ccow_wait(c, last_io);
		if (err) {
			log_softerror(fsio_lg, err, "ccow_wait fail");
			goto out;
		}

		err = ccow_cancel(c);
		if (err) {
			log_softerror(fsio_lg, err, "ccow_wait fail");
			goto out;
		}
		c = NULL;

		/** Copy the read data to client buffer */
		for (uint64_t i=0; i<chunks_to_read; i++) {
			uint64_t chunk_offset = current_offset % chunk_size;
			uint64_t chunk_data_sz =
				MIN(chunk_size - chunk_offset, part_map->size - sz_read);

			memcpy(buffer+sz_read, (char *)(iov[i].iov_base) + chunk_offset, chunk_data_sz);
			sz_read += chunk_data_sz;
			current_offset += chunk_data_sz;

			log_debug(fsio_lg, "Reading chunk :%lu offset: %lu sz: %lu",
				i, chunk_offset, chunk_data_sz);
		}

		log_debug(fsio_lg, "obj part: read size: %lu", sz_read);
	}
	assert(sz_read == part_map->size);

out:
	if (c)
		ccow_cancel(c);
	if (iov) {
		for (uint64_t i=0; i<chunks_to_read; i++){
			if (iov[i].iov_base)
				je_free(iov[i].iov_base);
		}
		je_free(iov);
	}

	return err;
}

int
fsio_buffer_cache_read(ccowfs_inode *inode, size_t file_offset, size_t data_size,
    void *buffer, size_t *read_amount, int *eof)
{
	int err = 0;
	ccow_completion_t c = NULL;
	int last_io = DEFAULT_LAST_IO;
	ci_t *ci = inode->ci;
	fsio_chunk_buff **chunk_list = NULL;
	size_t file_size;
	uint64_t first_chunk = 0, last_chunk = 0, cnt = 0, first_chunk_offset = 0;
	uint8_t locked = 0;
	uint64_t chunk_size = 0;
	uint64_t part_count = 0;
	s3_object_parts_maps *multipart_map = NULL;

	log_trace(fsio_lg, "inode: %lu file_offset: %lu data_size: %lu",
		inode->ino, file_offset, data_size);

	/* Do not read beyound the file size */
	ccowfs_inode_get_size(inode, &file_size);
	if (file_offset >= file_size) {
		*read_amount = 0;
		*eof = 1;
		goto out;
	}
	if (file_offset + data_size >= file_size) {
		data_size = file_size - file_offset;
		*eof = 1;
	}

	/** Get completion read ref on the object
	 *	Confirms enough completion OPs are available to read required chunks.
	 */
	err = disk_worker_get_read_ref(inode->ci, &(inode->disk_worker),
		file_offset, data_size, &c);
	if (err) {
		log_error(fsio_lg,
		"disk_worker_get_read_ref return %d", err);
		goto out;
	}

	disk_worker_get_chunk_size(ci, &(inode->disk_worker), &chunk_size);

	if (INODE_IS_S3OBJ(inode->ino)) {
		/* Check if it is multipart object. Fetch and parse the JSON if it is */
		disk_worker_get_multipart_attr(ci, &(inode->disk_worker),
			&inode->multipart, &inode->json_size);
		if (inode->multipart) {
			log_debug(fsio_lg, "inode: %lu multipart object. JSON size: %lu",
				inode->ino, inode->json_size);

			err = ccowfs_inode_parse_s3_multipart_json(inode, chunk_size);
			if (err) {
				log_error(fsio_lg,
					"inode: %lu prepare_s3_multi_part failed with err: %d",
					inode->ino, err);
				goto out;
			}
		}
	}

	if (! INODE_IS_S3OBJ(inode->ino) || ! inode->multipart) {
		/* Read for regular files as well as for single part s3 objects */

		map_file_to_chunk_range(inode, chunk_size, file_offset, data_size,
			&first_chunk, &last_chunk, &first_chunk_offset);
		cnt = last_chunk - first_chunk + 1;

		chunk_list = (fsio_chunk_buff **) je_calloc(cnt, sizeof(fsio_chunk_buff *));
		if (!chunk_list) {
			log_error(fsio_lg, "Failed to allocate memory");
			err = ENOMEM;
			goto out;
		}

		log_debug(fsio_lg,
			"inode: %lu first_chunk: %lu last_chunk :%lu "
			"offset:%lu data size :%lu", inode->ino,
			first_chunk, last_chunk, file_offset, data_size);

		/** Read completion will update the chunk data.
		 * Need to take WRITE lock on all the chunks which are getting fetched.
		 */
		cache_lock_multiple_chunks(inode, first_chunk, last_chunk, CHUNK_WRITE,
			chunk_list, cnt);
		locked = 1;

		if (INODE_IS_S3OBJ(inode->ino)) {
			/** For S3 objects -
			 *		It is not possible to have chunk data before fetching it.
			 *		The data is maintained in cache only during the read.
			 */
			for (uint64_t i=0; i<cnt; i++)
				assert(chunk_list[i]->buff == NULL);
		}

		/** We have write lock on chunks from first_chunk to last_chunk
		 *	May need to fetch these chunks if they are not in cache.
		 */
		err = cache_populate_chunks_data(inode, FETCH_FLAGS_READ, chunk_list, cnt,
			chunk_size, c, &last_io);
		if (err) {
			inode->ci->ccow_err = err;
			log_error(fsio_lg, "Failed to fetch chunks for inode: %lu with err: %d",
				inode->ino, err);
			goto out;
		}
	}
	else {
		/** Given file offset and data size to read -
		 *	get the corrosponding part name and offsets
		 */
		err = get_s3_multipart_parts(inode,
			file_offset, data_size,
			&multipart_map, &part_count);
		if (err) {
			inode->ci->ccow_err = err;
			log_error(fsio_lg, "Failed to fetch multipart map inode: %lu with err: %d",
				inode->ino, err);
			goto out;
		}

		log_debug(fsio_lg, "inode: %lu file_offset: %lu size:%lu part_count: %lu",
			inode->ino, file_offset, data_size, part_count);
		for (uint64_t i=0; i<part_count; i++) {
			log_debug(fsio_lg, "part no: %lu offset: %lu size: %lu",
				multipart_map[i].number,
				multipart_map[i].offset,
				multipart_map[i].size);
		}

		/** Read all the parts from different sub objects
		 *	Reading   without going to the buffer cache.
		 *	It is okay as we don't really maintain cache for S3 objects.
		 *	[TODO] Reading the parts serially. This can be changed to read in parallel
		 */
		uint64_t sz_read = 0;
		for (uint64_t i=0; i<part_count; i++) {
			err = read_s3_object_part(inode->ci, &multipart_map[i],
				(char *)buffer + sz_read);
			if (err) {
				log_error(fsio_lg,
				"Failed to read object part. inode :%lu part: %lu offset:%lu size: %lu",
				inode->ino, multipart_map[i].number,
				multipart_map[i].offset, multipart_map[i].size);
				goto out;
			}
			sz_read += multipart_map[i].size;
		}
		assert(sz_read == data_size);
	}

	/**
	 *	Releasing the disk_worker read ref here.
	 *	We are done fetching the data from CCOW and have write locks on the chunks of interest.
	 *	Releasing the completion may allow read/write to other part of the file.
	 */
	err = disk_worker_put_read_ref(inode->ci, &(inode->disk_worker),
		last_io);
	c = NULL;
	if (err) {
		log_error(fsio_lg,
			"disk_worker_put_read_ref return %d", err);
		disk_worker_flush(inode->ci, &(inode->disk_worker), 0);
		goto out;
	}

	if (! INODE_IS_S3OBJ(inode->ino) || ! inode->multipart) {
		/** All the required chunks are now present in cache and are write locked.
		 *	Perform data copy to the caller's buffer
		 *	[TODO]
		 *		The WRITE lock on the chunks is no more needed.
		 *		No easy way though to downgrade the WRITE lock to READ.
		 */
		err = chunk_read_data(inode, buffer, file_offset, data_size,
				chunk_size, chunk_list, cnt);
		if (err) {
			inode->ci->ccow_err = err;
			log_error(fsio_lg,
				"chunk_read_data failed for inode: %lu with err: %d",
				inode->ino, err);
			goto out;
		}
	}

out:

	if (multipart_map) {
		for (uint64_t i=0; i<part_count; i++) {
			if (multipart_map[i].name)
				je_free(multipart_map[i].name);
		}
		je_free(multipart_map);
	}

	if (locked) {
		if (INODE_IS_S3OBJ(inode->ino)) {
			/** Cannot maintain S3 object data in cache.
			 *	There is no way to detect changes in object data.
			 *	Free-up the chunk buffers as we have the chunk locks.
			 *	Let the chunk heads be in the list as we don't have the list lock.
			 *	Chunk heads will be removed as part of flush.
			 */
			for (uint64_t i=0; i<cnt; i++) {
				je_free(chunk_list[i]->buff);
				chunk_list[i]->buff = NULL;
				chunk_list[i]->data_size = 0;
				chunk_list[i]->chunk_size = 0;
				chunk_list[i]->dirty = 0;
			}
		}
		cache_unlock_multiple_chunks(inode, chunk_list, cnt);
	}

	if (c) {
		assert(err);

		int err1;
		err1 = disk_worker_put_read_ref(inode->ci, &(inode->disk_worker),
			last_io);
		if (err1) {
			log_error(fsio_lg,
				"disk_worker_put_read_ref return %d", err1);

			disk_worker_flush(inode->ci, &(inode->disk_worker), 0);
		}
	}

	if (!err)
		*read_amount = data_size;

	if (chunk_list)
		je_free(chunk_list);

	log_debug(fsio_lg,
		"Completed inode: %lu file_offset: %lu data_size: %lu read_amount: %lu",
		inode->ino, file_offset, data_size, *read_amount);
	return err;
}

int
fsio_buffer_cache_flush(ccowfs_inode *inode, int client_flush)
{
	int err = 0;
	int last_io = DEFAULT_LAST_IO;
	ccow_completion_t c = NULL;
	fsio_chunk_buff **chunk_list = NULL;
	uint8_t locked = 0;
	uint64_t chunk_list_sz = (MAX_OP_COUNT - MIN_FREE_OPS_REQUIRED);
	uint64_t found_dirty;

	log_trace(fsio_lg, "inode: %lu client_flush: %d",
		inode->ino, client_flush);

	/** Only flush dirty chunks from regular files.
	 *	No need to flush anything for S3 objects.
	 */
	if (! inode->read_only) {
		assert(! INODE_IS_S3OBJ(inode->ino));


		uint64_t dirty_count = atomic_get_uint64(&inode->dirty_chunks);
		log_debug(fsio_lg, "inode: %lu dirty_count: %lu",
			inode->ino, dirty_count);

		/** It is possible to get more than MAX_OP_COUNT dirty chunks in cache
		 *	We allow parallel writes to different regions of the file (only to cache)
		 *	and hence end up having more than MAX_OP_COUNT dirty chunks in the cache
		 *	Create multiple completions in loop
		 *	write max MAX_DIRTY_CHUNK_COUNT using each completion instance.
		 *	At a time only one completion will be opened.
		 */
		dirty_count = MIN(dirty_count, (MAX_OP_COUNT - MIN_FREE_OPS_REQUIRED));

		/** Allocate reusable chunk_list.
		 *	Flush (MAX_OP_COUNT - MIN_FREE_OPS_REQUIRED) max chunks using every completion.
		 */
		chunk_list = (fsio_chunk_buff **)
			je_calloc(chunk_list_sz, sizeof(fsio_chunk_buff *));
		if (!chunk_list) {
			err = ENOMEM;
			goto out;
		}

		while(dirty_count) {
			log_debug(fsio_lg, "Flushing %lu chunks for inode: %lu",
				dirty_count, inode->ino);

			/** Get completion write ref on the object
			 *	Confirms enough completion OPs are available to flush dirty_count chunks.
			 */
			err = disk_worker_get_write_ref(inode->ci, &(inode->disk_worker),
				dirty_count, &c);
			if (err) {
				log_error(fsio_lg,
				"disk_worker_get_write_ref return %d", err);
				goto out;
			}

			/** Flush first dirty_count dirty chunks from cache.
			 *  Lock and get first dirty_count number of dirty chunks.
			 *	It is okay if there are less than dirty_count dirty chunks.
			 */
			cache_lock_multiple_dirty_chunks(inode, CHUNK_FLUSH,
				chunk_list, dirty_count, &found_dirty);
			locked = 1;

			/** If some other thread ends up flushing some chunks -
			 * found_dirty can be less than dirty_count
			 */
			assert(found_dirty <= dirty_count);

			if (found_dirty) {
				err = cache_flush_locked_chunks(inode, chunk_list,
					found_dirty, c, &last_io);
				if (err) {
					log_error(fsio_lg,
					"cache_flush_locked_chunks return %d", err);
					goto out;
				}
			}
			cache_unlock_multiple_chunks(inode,
				chunk_list, found_dirty);
			locked = 0;

			assert(last_io < MAX_OP_COUNT);
			err = disk_worker_put_write_ref(inode->ci, &(inode->disk_worker),
				last_io);
			c = NULL;
			if (err) {
				log_error(fsio_lg, "disk_worker_put_write_ref return %d",
					err);
				goto out;
			}

			dirty_count = atomic_get_uint64(&inode->dirty_chunks);
			dirty_count = MIN(dirty_count, (MAX_OP_COUNT - MIN_FREE_OPS_REQUIRED));

			memset(chunk_list, 0, chunk_list_sz * sizeof(fsio_chunk_buff *));
		}
	}

	cache_free_all_clean_chunks(inode);

out:
	if (c) {
		assert(err);

		int err1 = disk_worker_put_write_ref(inode->ci, &(inode->disk_worker),
			last_io);
		if (err1) {
			log_error(fsio_lg, "disk_worker_put_write_ref return %d",
				err);
		}
	}
	if (locked) {
		assert(err);

		for (uint64_t i=0; i<(chunk_list_sz); i++) {
			if (chunk_list[i])
				chunk_unlock(inode, chunk_list[i]);
		}
	}
	if (chunk_list)
		je_free(chunk_list);

	disk_worker_flush(inode->ci, &(inode->disk_worker), client_flush);

	return err;
}
