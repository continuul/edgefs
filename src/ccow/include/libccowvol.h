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

#ifndef __LIBCCOWVOL_H_
#define __LIBCCOWVOL_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include "queue.h"
#include "ccow.h"

#define CCOW_VOL_OP_CNT 512

typedef struct ccow_info {
	ccow_t tctx;
	int blk_size;
	uint32_t chunk_size;
	size_t size;
	char cid[2048], tid[2048], bid[2048], oid[2048];
	size_t cid_size, tid_size, bid_size, oid_size;
	ccow_completion_t c;
	int io_count;
	int stream_broken;
	uint64_t genid;
	int writes;

	QUEUE ci_lnk;

	pthread_rwlock_t user_lck;
	pthread_mutex_t sync_mutex;
	pthread_mutex_t ci_mutex;
	pthread_cond_t ci_cond_var;
	void* index_table[CCOW_VOL_OP_CNT + 2];
} ccow_info_t;

enum
{
	CCOW_VOL_LIO_NOP,
	CCOW_VOL_LIO_READ,
	CCOW_VOL_LIO_WRITE,
	CCOW_VOL_LIO_WRITE_SAME,
	CCOW_VOL_LIO_UNMAP,
	CCOW_VOL_LIO_SYNC
};

enum
{
  CCOW_VOL_SIGEV_NONE,		/* Get status by aio_return      */
  CCOW_VOL_SIGEV_THREAD,	/* Deliver via thread creation.  */
};

enum
{
  CCOW_VOL_STATUS_UNKNOWN = 0,
  CCOW_VOL_STATUS_NEW,
  CCOW_VOL_STATUS_IN_PROGRESS,
  CCOW_VOL_STATUS_COMPLETE,
  CCOW_VOL_STATUS_COMPLETE_WITH_ERRORS,
  CCOW_VOL_STATUS_CANCELED
};

enum
{
  CCOW_VOL_CANCELED,
  CCOW_VOL_NOTCANCELED,
  CCOW_VOL_ALLDONE
};

struct ccow_aio {
	struct ccow_info * ci;	/* ccow descriptor */
	size_t	aio_offset;		/* object offset */
	void  *	aio_buf;		/* location of buffer, unmap doesn't need it*/
	size_t	aio_nbytes;     /* Length of transfer */
	size_t  aio_in_size;	/* Length of input buffer, used by write same */
	int		aio_sigevent;   /* Option to get result */
	void  * (*aio_cbfunction)(void *); /* call back function for completion*/
	void *	aio_cbargs;     /* call back parameter */
	int		aio_lio_opcode; /* Operation  for ccow_lio_listio() */
	int		aio_errno;		/* error code */
	/* private */
	int		aio_status;

	QUEUE item;
	struct iovec *iov;
	size_t iovcnt;
	int ci_index;
	struct ccow_rmw_context chctx;
};

typedef struct ccow_aio * ccow_aio_t;

int ccow_vol_add_to_queue(ccow_aio_t);

/**
 * Enqueue a read request
 * @param pointer to aio control block
 */
int ccow_vol_read(ccow_aio_t);

/**
 *  Enqueue a write request
 *  @param pointer to aio control block
 */
int ccow_vol_write(ccow_aio_t);

/**
 *  Enqueue a write_same request
 *  @param aio control block
 */
int ccow_vol_write_same(ccow_aio_t);

/**
 *  Enqueue a write request
 *  @param aio control block
 */
int ccow_vol_unmap(ccow_aio_t);

/**
 *  Enqueue multiple I/O requests using a single function call
 *  @param array of control blocks
 *  @param number of blocks in the array
 */
int ccow_vol_listio(ccow_aio_t lio[], int n);

/**
 *  Obtain status of an enqueued I/O request
 *  @param pointer to aio control block
 */
int ccow_vol_error(ccow_aio_t);

/**
 *  Obtain the return status of a completed I/O request
 *  @param pointer to aio control block
 */
ssize_t ccow_vol_return(ccow_aio_t);

/**
 *  Suspend the called thread till at list one of the requests
 *  from the functuion arguments is completed
 *  @param array of control blocks that is waited
 *  @param number of blocks in the array
 *  @param time which thread is suspended if no request is completed
 */
int ccow_vol_suspend(ccow_aio_t aiocb_list[],
                       int nitems, const struct timespec *timeout);

/** Cancel an outstanding asynchronous I/O request
 * 	@param pointer to ccow structure corresponding to file/object
 * 	@param pointer to aio control block.
 * 	If aio == NULL, cancel all outstanding aio for that ci
 */
int ccow_vol_cancel(struct ccow_info * ci, ccow_aio_t aio);

/** Enqueue a sync request for the I/O operations on the object aio belongs
 *  NOTE: it does not block
 */
int ccow_vol_fsync(ccow_aio_t);

/**
 * Initialize ccow object for I/O operations
 * @param pointer to memory allocated for ccow structure storage
 * @param string with the id of object to work with.
 *		(cluster/tenant/bucket/object format)
 * @param unused
 * @param uint64 that gets ccow parameter X-volsize
 */
int ccow_vol_open(struct ccow_info *ci, char *uri, int *fd, uint64_t * vol_size);

/**
 * De-initialize ccow object
 * @param pointer to used ccow structure
 */
void ccow_vol_close(struct ccow_info *ci);

/**
 * Synchroize by flushinig IO streams.
 * NOTE: it does block till flush
 * use ccow_vol_fsync if don't want blocking
 */
int ccow_vol_synchronize(ccow_aio_t);

/**
 * Stop IO stream. Use only if you want bypass libccowvol
 * to use underlying libccow API. Don't forget ccow_vol_start_stream
 * to restore libccowvol operation
 */
int ccow_vol_stop_stream(ccow_aio_t);

/**
 * Start IO stream to restore libccowvol operation
 * after ccow_vol_stop_stream
 */
int ccow_vol_start_stream(ccow_aio_t);

#ifdef	__cplusplus
}
#endif

#endif /* __LIBCCOWVOL_H_ */
