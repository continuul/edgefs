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
#ifndef __FSIO_DISK_H__
#define __FSIO_DISK_H__

#include <ccowfsio.h>

#define MAX_OP_COUNT 1024
#define DEFAULT_LAST_IO (-2)

typedef enum __disk_op_type__
{
	DISK_READ = 0,
	DISK_WRITE,
	DISK_MD
}disk_op_type;

#define MIN_FREE_OPS_REQUIRED   5

typedef struct __disk_object_attrs__
{
	uint64_t	chunk_size;

	/* For S3 objects only */
	uint64_t	multipart;
	uint64_t	json_size;

}disk_obj_attrs;

/**
 * Holds the inode specific stream completion.
 * This completion is used by read write threads.
 * At presetnt we allow multiple read threads to operate at a time.
 * But only one write thread can operate on the inode.
 * It is allowed to have multiple read and one write threads at a time.
 * When all the ops are used up -
 *  we finalize the completion and create a new one.
 */
typedef struct __disk_worker__
{
	pthread_mutex_t worker_mutex;	/* Guards this complete structure */
	pthread_mutex_t write_mutex;	/* Allow only one write thread at a time  */
	pthread_cond_t in_flight_ops_cond;
	uint32_t in_flight_ops;		/* Number of OPs in progress */
	uint32_t available_op_count;	/* Available ops with current comp */
	uint8_t md_update_in_flght;  /*Set if MD update is in progress */

	uint8_t available;		/* false if completion is marked for flush or metadata OP is in progress */
	pthread_cond_t available_condition;	/* Wait for comp to become available. */

	uint8_t needs_flush;		/*set if the completion must be flushed when there are no in flight ops */
	ccow_completion_t comp;		/* Stream completion */

	/** Attrs hold the relevant object attrs received from completion open
	 *	The attrs are valid and read only while the completion is open
	 *	When there is no completion, the attrs are invalid.
	 */
	disk_obj_attrs attrs;

	inode_t ino;
	size_t oid_size;
	char *oid;
	uint64_t genid;
	int last_io;
} disk_worker_md;

/**
 * Initialize the disk_worker
 * Memory must be allocated by the caller.
 */
int disk_worker_init(ci_t * ci, disk_worker_md * disk_worker,
    char *oid, size_t oid_size, inode_t ino);

/**
 * Terminate the disk_worker
 * Memory s owned by the caller.
 */
int disk_worker_term(ci_t * ci, disk_worker_md * disk_worker);

int
disk_worker_get_md_ref(ci_t *ci, disk_worker_md *disk_worker,
    ccow_completion_t *out_completion);
int
disk_worker_put_md_ref(ci_t *ci, disk_worker_md *disk_worker);
int
disk_worker_get_read_ref(ci_t *ci, disk_worker_md *disk_worker,
    size_t file_offset, size_t data_size,
    ccow_completion_t *out_completion);
int
disk_worker_put_read_ref(ci_t *ci, disk_worker_md *disk_worker, int last_io);
int
disk_worker_get_write_ref(ci_t *ci, disk_worker_md *disk_worker,
    uint64_t op_count, ccow_completion_t *out_completion);
int
disk_worker_put_write_ref(ci_t *ci, disk_worker_md *disk_worker, int last_io);

/**
 * Block any new ref on the stream completion.
 * Wait till last in flight stream OP is complete.
 * client_flush is set if the client is requesting flush of the data.
 */
int disk_worker_freez(ci_t * ci, disk_worker_md * disk_worker,
    int client_flush);

/**
 * Allow creating new stream completion and hence read/write or MD update
 */
int disk_worker_unfreez(ci_t * ci, disk_worker_md * disk_worker);

/**
 * Check if completion is open.
 * returns 1 : if it has associated ccow_completion_t
 *         0:  if there is no associated ccow_completion_t
 */
int disk_worker_is_dirty(ci_t * ci, disk_worker_md * disk_worker);

/**
 * Finalize the comp.
 *      If there are inflight ops, then mark it for finalize.
 *      it will be finalized when last op goes away.
 */
int disk_worker_flush(ci_t * ci, disk_worker_md * disk_worker, int client_flush);

int disk_worker_get_chunk_size(ci_t *ci, disk_worker_md *disk_worker,
		uint64_t *chunk_size);

int disk_worker_get_multipart_attr(ci_t *ci, disk_worker_md *disk_worker,
		uint64_t *multipart, uint64_t *json_size);
#endif /* __FSIO_DISK_H__ */
