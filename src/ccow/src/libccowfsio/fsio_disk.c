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
#include <signal.h>
#include <lfq.h>

#include <ccow.h>
#include <ccowfsio.h>
#include "fsio_debug.h"
#include "fsio_inode.h"
#include "fsio_disk.h"
#include "fsio_common.h"
#include "fsio_system.h"

/**
 * Requirements :
 * 1. Allow multiple threads to read from same inode in parallel.
 *   This required sharing the same completion across multiple read threads.
 * 2. Allow only one thread to write to the file at a time.
 *    Multiple threads can READ in parallel while one thread is writting to it.
 * 3. Use ccow_put_cont() and ccow_get_cont() for data WRITE and READ.
 * 4. Use the same stream completion to write Metadata.
 * 5. No need to block READ/WRITE thread to update MD.
 *	  Allow only one MD thread at a time
 * 6. Even for stream read ccow_get_cont() -
 *      Tt is required to finalize the completion once OP index reaches to the max.
 * 7. Flusher thread -
 *      Must be able to finalize the completion.
 *      If here are no READ/WRITE OPs in progress for the completion.
 *		Allow option to block till actual flush is done.
 * 8. Need a way to block all write and MD updates for snapshots/clone functions (freez).
 *    Read may be allowed during this.
 */

static int
__parse_object_attrs(ci_t *ci, disk_worker_md *disk_worker, ccow_lookup_t iter)
{
	int err = 0;
	int pos = 0;
	int chunk_size_found = 0;
	char *key;
	struct ccow_metadata_kv *kv;

	if (iter) {
		while ((kv = ccow_lookup_iter(iter,
				CCOW_MDTYPE_METADATA | CCOW_MDTYPE_CUSTOM,
				pos++))) {
			key = kv->key;
			if (strcmp(key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
				uint32_t tmp;
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv, &tmp);
				disk_worker->attrs.chunk_size = tmp;
				log_debug(fsio_lg, "iter chunk_size found: %lu",
					disk_worker->attrs.chunk_size);
				chunk_size_found = 1;
			}
			else if (strcmp(key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv,
				    &disk_worker->attrs.json_size);
				log_debug(fsio_lg, "iter json_size found: %lu",
					disk_worker->attrs.json_size);
			}
			else if (strcmp(key, "multipart") == 0) {
				disk_worker->attrs.multipart = (*((char *)kv->value) == '2');
				log_debug(fsio_lg, "iter multipart found: %lu",
					disk_worker->attrs.multipart);
			}
		}
	}

	/** No attr found Or no chunk_size specified on the object
	 *  Fallback to default chunk size from bucket
	 */
	if (!chunk_size_found || disk_worker->attrs.chunk_size == 0)
		disk_worker->attrs.chunk_size = ci->bk_attrs.chunk_size;

	return err;
}

static int
__create_completion(ci_t *ci, disk_worker_md *disk_worker)
{
	int err = 0;
	ccow_lookup_t iter = NULL;

	log_trace(fsio_lg, "ci: %p, disk_worker: %p", ci, disk_worker);

	assert(disk_worker->comp == NULL);
	assert(disk_worker->available_op_count == 0);

	err = ccowfs_create_stream_completion(ci, disk_worker->oid,
	    disk_worker->oid_size, &(disk_worker->genid), MAX_OP_COUNT,
	    disk_worker->ino, &disk_worker->comp, &iter);
	if (err) {
		log_error(fsio_lg, "ccowfs_create_stream_completion return %d",
		    err);
		if (err == EIO || err == -EIO)
			err = EBUSY; /* Don't forward EIO to client. */
		goto out;
	}

	ccow_attr_modify_default(disk_worker->comp, CCOW_ATTR_BTREE_MARKER,
		(void *) &ci->bk_attrs.chunkmap_btree_marker, NULL);

	disk_worker->available_op_count = MAX_OP_COUNT - 1;
	disk_worker->last_io = DEFAULT_LAST_IO;

	__parse_object_attrs(ci, disk_worker, iter);

out:
	if (err) {
		ci->ccow_err = err;
		log_error(fsio_lg, "failed for bucket: %s err: %d", ci->bid,
		    err);
		if (iter)
			ccow_lookup_release(iter);
	}

	log_debug(fsio_lg, "completed ci: %p, disk_worker: %p", ci, disk_worker);

	return err;
}

int64_t
get_size_diff(ccow_lookup_t iter)
{
	struct ccow_metadata_kv *kv;
	uint64_t cur, prev;
	int found, pos;

	kv = NULL;
	found = pos = 0;

	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, pos++))) {
		if (kv->type == CCOW_KVTYPE_UINT64) {
			if (strncmp(kv->key, RT_SYSKEY_LOGICAL_SIZE, kv->key_size) == 0) {
				cur = *(uint64_t *)kv->value;
				found |= 1;
			} else if (strncmp(kv->key, RT_SYSKEY_PREV_LOGICAL_SIZE, kv->key_size) == 0) {
				prev = *(uint64_t *)kv->value;
				found |= 2;
			}
		}
	}
	if (found == 3) {
		return ((int64_t)cur - (int64_t)prev);
	} /* XXX not sure if have to fail otherwise. */

	return (0);
}

static int
__finalize_completion(ci_t * ci, disk_worker_md * disk_worker, int client_flush)
{
	ccow_lookup_t iter = NULL;
	int err = 0;

	log_trace(fsio_lg,"ci: %p, disk_worker: %p last_io: %d",
		ci, disk_worker, disk_worker->last_io);

	if (disk_worker->comp == NULL)
		goto out;

	err = ccow_finalize(disk_worker->comp, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_finalize return %d", err);
		goto out;
	}

	if (iter)
		atomic_add64((unsigned long *) &(ci->used_bytes_diff),
		    get_size_diff(iter));

	disk_worker->available_op_count = 0;
	disk_worker->comp = NULL;
	disk_worker->needs_flush = 0;
	disk_worker->last_io = DEFAULT_LAST_IO;

	/* Attrs are not valid once we finalize the completion */
	memset(&(disk_worker->attrs), 0, sizeof(disk_worker->attrs));

	assert(disk_worker->in_flight_ops == 0);

out:
	if (iter)
		ccow_lookup_release(iter);
	log_trace(fsio_lg, "completed ci: %p, disk_worker: %p", ci,
	    disk_worker);

	return err;
}

int
disk_worker_freez(ci_t * ci, disk_worker_md * disk_worker, int client_flush)
{
	int err = 0;

	log_trace(fsio_lg,"ci: %p, disk_worker: %p, client_flush: %d", ci,
	    disk_worker, client_flush);

	pthread_mutex_lock(&disk_worker->worker_mutex);

	/*
	 * Make sure no new READ or WRITE OPs are started.
	 */
	disk_worker->available = 0;

	while (1) {
		/*
		 * If completion is present. We need to finalize it
		 * No new ops will be started on this completion
		 */
		if (disk_worker->comp) {
			if  (disk_worker->in_flight_ops == 0  && disk_worker->md_update_in_flght == 0) {
				err = __finalize_completion(ci, disk_worker, client_flush);
				if (err) {
					log_error(fsio_lg,
					    "__finalize_completion return %d", err);
					goto out;
				}
				break;
			} else {
				/*
				 * Wait for in flight OPs to complete and then
				 * retry.
				 */
				pthread_cond_wait(&disk_worker->
				    in_flight_ops_cond,
				    &disk_worker->worker_mutex);
				continue;
			}
		} else
			break;
	}

	assert(disk_worker->comp == NULL);
	assert(disk_worker->in_flight_ops == 0 && disk_worker->md_update_in_flght == 0);
	assert(disk_worker->available == 0);

out:
	pthread_mutex_unlock(&disk_worker->worker_mutex);

	log_debug(fsio_lg, "completed ci: %p, disk_worker: %p, client_flush: %d",
	    ci, disk_worker, client_flush);

	return err;
}

int
disk_worker_unfreez(ci_t * ci, disk_worker_md * disk_worker)
{
	int err = 0;

	log_trace(fsio_lg, "ci: %p, disk_worker: %p", ci, disk_worker);

	pthread_mutex_lock(&disk_worker->worker_mutex);

	assert(disk_worker->comp == NULL);
	assert(disk_worker->in_flight_ops == 0 && disk_worker->md_update_in_flght == 0);
	assert(disk_worker->available == 0);

	disk_worker->available = 1;

	pthread_cond_broadcast(&disk_worker->available_condition);

	pthread_mutex_unlock(&disk_worker->worker_mutex);

	log_debug(fsio_lg, "completed ci: %p, disk_worker: %p", ci, disk_worker);

	return err;
}

int
disk_worker_init(ci_t * ci, disk_worker_md * disk_worker,
    char *oid, size_t oid_size, inode_t ino)
{
	int err = 0;

	log_trace(fsio_lg,"ci: %p, disk_worker: %p, oid: \"%s\", "
	    "oid_size: %lu", ci, disk_worker, oid, oid_size);

	assert(disk_worker != NULL);

	memset(disk_worker, 0, sizeof(disk_worker_md));

	err = pthread_cond_init(&disk_worker->in_flight_ops_cond, NULL);
	if (err) {
		log_error(fsio_lg, "pthread_cond_init return %d",
		    err);
		goto out;
	}

	err = pthread_cond_init(&disk_worker->available_condition, NULL);
	if (err) {
		log_error(fsio_lg, "pthread_cond_init return %d",
		    err);
		goto out;
	}

	err = pthread_mutex_init(&disk_worker->worker_mutex, NULL);
	if (err) {
		log_error(fsio_lg, "pthread_mutex_init return %d",
		    err);
		goto out;
	}

	err = pthread_mutex_init(&disk_worker->write_mutex, NULL);
	if (err) {
		log_error(fsio_lg, "pthread_mutex_init return %d",
		    err);
		goto out;
	}
	disk_worker->ino = ino;
	disk_worker->oid = oid;
	disk_worker->oid_size = oid_size;
	disk_worker->available = 1;

out:
	log_debug(fsio_lg,"completed ci: %p, disk_worker: %p, oid: \"%s\", "
	    "oid_size: %lu", ci, disk_worker, oid, oid_size);

	return err;
}

int
disk_worker_term(ci_t * ci, disk_worker_md * disk_worker)
{
	int err = 0;

	log_trace(fsio_lg,"ci: %p, disk_worker: %p", ci, disk_worker);

	err = pthread_cond_destroy(&disk_worker->available_condition);
	if (err) {
		log_error(fsio_lg, "pthread_cond_destroy return %d",
		    err);
		goto out;
	}

	err = pthread_cond_destroy(&disk_worker->in_flight_ops_cond);
	if (err) {
		log_error(fsio_lg, "pthread_cond_destroy return %d",
		    err);
		goto out;
	}

	err = pthread_mutex_destroy(&disk_worker->worker_mutex);
	if (err) {
		log_error(fsio_lg, "pthread_mutex_destroy return %d", err);
		goto out;
	}

	err = pthread_mutex_destroy(&disk_worker->write_mutex);
	if (err) {
		log_error(fsio_lg, "pthread_mutex_destroy return %d", err);
		goto out;
	}
out:
	log_debug(fsio_lg,"completed ci: %p, disk_worker: %p", ci, disk_worker);

	return err;
}

static uint64_t
__get_ops_required(disk_worker_md *disk_worker, disk_op_type type,
	size_t file_offset, size_t data_size)
{
	uint64_t from_chunk = file_offset / disk_worker->attrs.chunk_size;
	uint64_t to_chunk = (file_offset + data_size - 1) / disk_worker->attrs.chunk_size;

	assert(type == DISK_WRITE || type == DISK_READ);

	return (to_chunk - from_chunk + 1);
}

static int
disk_worker_get_ref(ci_t *ci, disk_worker_md *disk_worker, disk_op_type type,
	size_t file_offset, size_t data_size, uint64_t op_count,
	ccow_completion_t *out_completion)
{
	int err = 0;
	uint64_t ops_required = 0;

	log_trace(fsio_lg,"ci: %p, disk_worker: %p, type: %d, "
	    "out_completion: %p", ci, disk_worker, type, out_completion);

	*out_completion = NULL;

	/*Allow only one write thread at a time */
	if (type == DISK_WRITE)
		pthread_mutex_lock(&disk_worker->write_mutex);

	/*
	 * Only one write thread can go ahead at a time.
	 * This is controlled by the buffer cache and no need to handle here.
	 */
	pthread_mutex_lock(&disk_worker->worker_mutex);

	while (1) {
		if (!disk_worker->available) {
			/**
			 *  The completion is not available.
			 *  This can happen if we are in freez state.
			 */
			pthread_cond_wait(&disk_worker->available_condition,
			    &disk_worker->worker_mutex);

			/*
			 * Retry as the completion should be available now.
			 */
			continue;
		}
		assert(disk_worker->available);

		if (disk_worker->comp == NULL) {
			 /* Completion is not present, create new one */
			assert(disk_worker->in_flight_ops == 0 && disk_worker->md_update_in_flght == 0);
			assert(disk_worker->available_op_count == 0);

			err = __create_completion(ci, disk_worker);
			if (err) {
				log_error(fsio_lg,
				    "__create_completion return %d", err);
				goto out;
			}
		} else if (ccow_completion_released(disk_worker->comp))
			continue;

		if (type == DISK_MD) {
			/**
			 * For MD update, FSIO uses the ccow_attr_modify_* APIs
			 * These APIs are not thread safe.
			 *  so allow only one thread to update MD at a time.
			 */
			if(disk_worker->md_update_in_flght != 0){
				pthread_cond_wait(&disk_worker->
					in_flight_ops_cond,
					&disk_worker->worker_mutex);
				continue;
			}
			assert(disk_worker->md_update_in_flght == 0);
			disk_worker->md_update_in_flght = 1;
			break;
		}
		else if (type == DISK_READ && disk_worker->available_op_count) {
			/* The completion is available. Check if it has enough required OPs */
			ops_required =
				__get_ops_required(disk_worker, type, file_offset, data_size);
		}
		else if (type == DISK_WRITE && disk_worker->available_op_count) {
			ops_required = op_count;
		}

		if (disk_worker->available_op_count &&
		    disk_worker->available_op_count >= ops_required) {
			/*
			 * The current completion has enough OPs remaining.
			 * Use the same completion.
			 */
			assert(disk_worker->comp != NULL);
			disk_worker->available_op_count -= ops_required;
			disk_worker->in_flight_ops += 1;
			break;
		} else {
			/* Not enough OPs available on the completion
			 * We can finalize and create new one if no other threads are in flight.
			 */
			if (disk_worker->in_flight_ops == 0 && disk_worker->md_update_in_flght == 0) {
				err = __finalize_completion(ci, disk_worker, 0);
				if (err) {
					log_error(fsio_lg,
						"__finalize_completion return %d",
						err);
					goto out;
				}
				continue;
			} else {
				/* Wait for other thread */
				assert(disk_worker->in_flight_ops != 0 || disk_worker->md_update_in_flght != 0);
				pthread_cond_wait(&disk_worker->
					in_flight_ops_cond,
					&disk_worker->worker_mutex);

				/*
				 * Retry as there are no in flight OPs now.
				 * We can finalize the completion if required.
				 */
				continue;
			}
		}
	}
	*out_completion = disk_worker->comp;
	assert(disk_worker->comp != NULL);

out:
	pthread_mutex_unlock(&disk_worker->worker_mutex);

	log_debug(fsio_lg,"completed ci: %p, disk_worker: %p, type: %d, "
	    "out_completion: %p", ci, disk_worker, type, out_completion);

	return err;
}

static int
disk_worker_put_ref(ci_t * ci, disk_worker_md * disk_worker,
    disk_op_type type, int last_io)
{
	int err = 0;

	log_trace(fsio_lg, "ci: %p, disk_worker: %p, type: %d, last_io: %d",
	    ci, disk_worker, type, last_io);

	/** if last_io is DEFAULT_LAST_IO:
	 *		That means no IO was scheduled with the completion.
	 *		No completion OPs are actually used.
	 */
	assert(last_io < MAX_OP_COUNT || last_io == DEFAULT_LAST_IO);

	pthread_mutex_lock(&disk_worker->worker_mutex);
	if (type == DISK_MD){
		assert(disk_worker->md_update_in_flght == 1);
		disk_worker->md_update_in_flght = 0;
		pthread_cond_broadcast(&disk_worker->in_flight_ops_cond);
	}
	else {
		assert(disk_worker->in_flight_ops > 0);
		disk_worker->in_flight_ops -= 1;
		if (last_io != DEFAULT_LAST_IO)
			disk_worker->last_io = last_io;
	}

	/*
	 * If we don't have enought free OPs and this is the last thread in
	 * flight, then flush the completion.
	 */
	if (disk_worker->in_flight_ops == 0 && disk_worker->md_update_in_flght == 0) {
		if (disk_worker->last_io >= (MAX_OP_COUNT - MIN_FREE_OPS_REQUIRED)
		    || disk_worker->needs_flush) {
			err = __finalize_completion(ci, disk_worker, 0);
			if (err) {
				log_error(fsio_lg,
				    "__finalize_completion return %d", err);
				goto out;
			}
			assert(disk_worker->comp == NULL);
		}

		/*
		 * Tell the world that there are no in flight OPs
		 */
		pthread_cond_broadcast(&disk_worker->in_flight_ops_cond);
	}

out:
	pthread_mutex_unlock(&disk_worker->worker_mutex);

	if (type == DISK_WRITE)
		pthread_mutex_unlock(&disk_worker->write_mutex);

	log_debug(fsio_lg, "completed ci: %p, disk_worker: %p, type: %d, "
	    "last_io: %d", ci, disk_worker, type, last_io);

	return err;
}

int
disk_worker_get_md_ref(ci_t *ci, disk_worker_md *disk_worker,
	ccow_completion_t *out_completion)
{
	return disk_worker_get_ref(ci, disk_worker, DISK_MD,
		0, 0, 0, out_completion);
}

int
disk_worker_put_md_ref(ci_t *ci, disk_worker_md *disk_worker)
{
	return disk_worker_put_ref(ci, disk_worker, DISK_MD, 0);
}

int
disk_worker_get_read_ref(ci_t *ci, disk_worker_md *disk_worker,
	size_t file_offset, size_t data_size,
	ccow_completion_t *out_completion)
{
	return disk_worker_get_ref(ci, disk_worker, DISK_READ,
		file_offset, data_size, 0, out_completion);
}


int
disk_worker_put_read_ref(ci_t *ci, disk_worker_md *disk_worker, int last_io)
{
	return disk_worker_put_ref(ci, disk_worker, DISK_READ, last_io);
}

int
disk_worker_get_write_ref(ci_t *ci, disk_worker_md *disk_worker,
	uint64_t op_count, ccow_completion_t *out_completion)
{
	return disk_worker_get_ref(ci, disk_worker, DISK_WRITE,
		0, 0, op_count, out_completion);
}

int
disk_worker_put_write_ref(ci_t *ci, disk_worker_md *disk_worker, int last_io)
{
	return disk_worker_put_ref(ci, disk_worker, DISK_WRITE, last_io);
}

int
disk_worker_flush(ci_t * ci, disk_worker_md * disk_worker, int client_flush)
{
	int err = 0;

	log_trace(fsio_lg, "ci: %p, disk_worker: %p", ci, disk_worker);

	pthread_mutex_lock(&disk_worker->worker_mutex);
	while (1) {
		if (disk_worker->comp) {
			if (disk_worker->in_flight_ops == 0 && disk_worker->md_update_in_flght == 0) {
				err = __finalize_completion(ci, disk_worker, client_flush);
				if (err) {
					log_error(fsio_lg, "__finalize_completion return %d",
						err);
					goto out;
				}
				break;
			} else {
				if (client_flush) {
					/* Need to block till the completion is flushed */
					pthread_cond_wait(&disk_worker->
						in_flight_ops_cond,
						&disk_worker->worker_mutex);
					continue;
				}
				else {
					/*
					 * Mark the completion for flush. This will be flushed when
					 * last in flight OP goes away.
					 */
					disk_worker->needs_flush = 1;
					break;
				}
			}
		}
		else
			break;
	}

out:
	pthread_mutex_unlock(&disk_worker->worker_mutex);

	log_debug(fsio_lg, "completed ci: %p, disk_worker: %p", ci, disk_worker);

	return err;
}

int
disk_worker_is_dirty(ci_t * ci, disk_worker_md * disk_worker)
{
	int dirty = 0;

	log_trace(fsio_lg, "ci: %p, disk_worker: %p", ci, disk_worker);

	/*
	 * Treat the completion as dirty if we have it open. (as it needs to be
	 * finalized)
	 *
	 * It is also dirty "hack" guys! Calling it from memory pressure leaves
	 * us no choice in current logic but to trylock mostly to avoid deadlock!
	 */
	if (pthread_mutex_trylock(&disk_worker->worker_mutex) == 0) {
		if (disk_worker->comp)
			dirty = 1;
		pthread_mutex_unlock(&disk_worker->worker_mutex);
	} else if (disk_worker->comp)
			dirty = 1;

	log_debug(fsio_lg, "completed ci: %p, disk_worker: %p", ci, disk_worker);

	return dirty;
}

int disk_worker_get_chunk_size(ci_t *ci, disk_worker_md *disk_worker,
        uint64_t *chunk_size)
{
	*chunk_size = atomic_get_uint64(&(disk_worker->attrs.chunk_size));

	return 0;
}

int disk_worker_get_multipart_attr(ci_t *ci, disk_worker_md *disk_worker,
        uint64_t *multipart, uint64_t *json_size)
{
	*multipart = atomic_get_uint64(&(disk_worker->attrs.multipart));
	*json_size = atomic_get_uint64(&(disk_worker->attrs.json_size));

	return 0;
}
