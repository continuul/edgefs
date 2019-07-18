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
#include <stdlib.h>

#include "ccowutil.h"
#include "pthread.h"
#include "ccow.h"
#include "libccowvol.h"

/* idle I/O thread timeout - 10ms */
#define CCOW_VOL_THREAD_TIMEOUT_NSEC (10 * 1000000L)

/* idle I/O thread retry - exit after 5s of idle */
#define CCOW_VOL_THREAD_POLL_MAX (500)

#define CCOW_VOL_CHUNK_SIZE_MAX (8 * 1024 * 1024)


QUEUE ccow_objects = QUEUE_INIT_STATIC(ccow_objects);
pthread_rwlock_t object_queue_rwlock = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP;

struct object_link {
	QUEUE ccow_object;
	QUEUE aio;
	struct ccow_info * ol_ci;
	pthread_t io_thread;
	pthread_mutex_t io_mutex;
	pthread_cond_t io_cond_var;
	int new_cmd;
};

void * ccow_vol_io_task(void * arg);
static int ccow_vol_finalize(struct ccow_info *ci, int flush);
static void ccow_vol_reset_ephemeral(struct ccow_info *ci);
static int ccow_vol_chunk(struct ccow_info *ci, uint64_t offset,  char *buf,
		size_t length, uint64_t buf_mask, struct iovec **iov, size_t *iovcnt,
		uint write, struct ccow_rmw_context *ch_ctx);

int
ccow_vol_add_to_queue(ccow_aio_t aio)
{
	QUEUE *q, *qn;
	struct object_link *ol;
	int err = 0;
	pthread_attr_t io_thread_attr;

	if (aio->aio_lio_opcode != CCOW_VOL_LIO_READ &&
	    aio->aio_lio_opcode != CCOW_VOL_LIO_SYNC)
		aio->ci->writes++;

	if (aio->aio_lio_opcode == CCOW_VOL_LIO_UNMAP) {
		aio->chctx.buf = je_calloc(2, aio->ci->chunk_size);
		if (aio->chctx.buf == NULL) {
			log_error(lg, "memory allocation for unmap buffer failed");
			return -ENOMEM;
		}
	}

	if (aio->aio_lio_opcode == CCOW_VOL_LIO_WRITE_SAME) {
		size_t buf_len;
		char * dst;
		if (aio->aio_nbytes % aio->aio_in_size != 0) {
			log_error(lg, "aio_nbytes should be multiple of aio_in_size");
			return -EINVAL;
		}
		if (aio->aio_in_size & (aio->aio_in_size - 1) ) {
			log_error(lg, "invalid aio_in_size parameters, it should be power of 2");
			return -EINVAL;
		}

		/* allocate new buffers for chunking.
		 * The size of the buffer is doubled for unaligned chunk
		 */
		if (aio->aio_in_size > aio->ci->chunk_size) {
			buf_len = 2 * aio->aio_in_size;
		}
		else {
			buf_len = 2 * aio->ci->chunk_size;
		}
		aio->chctx.buf = je_malloc(buf_len);
		if (aio->chctx.buf == NULL) {
			log_error(lg, "memory allocation of WRITE_SAME buffer failed");
			return -ENOMEM;
		}

		dst = aio->chctx.buf;
		while ( dst < (char *)aio->chctx.buf + buf_len) {
			memcpy(dst, aio->aio_buf, aio->aio_in_size);
			dst += aio->aio_in_size;
		}
	}
repeat_add2q:
	pthread_rwlock_rdlock(&object_queue_rwlock);
	QUEUE_FOREACH_SAFE(q, qn, &ccow_objects) {
		ol = QUEUE_DATA(q, struct object_link, ccow_object);
		/* check if there is an object with same ccow_info descriptor
		 * and add aio control block to the work list*/
		if (ol->ol_ci == aio->ci) {
			pthread_mutex_lock(&ol->io_mutex);
			aio->aio_status = CCOW_VOL_STATUS_NEW;
			QUEUE_INIT(&aio->item);
			QUEUE_INSERT_TAIL(&ol->aio, &aio->item);
			/* signal to the thread working with this ccow object*/
			ol->new_cmd = 1;
			pthread_cond_signal(&ol->io_cond_var);
			pthread_mutex_unlock(&ol->io_mutex);
			pthread_rwlock_unlock(&object_queue_rwlock);
			return 0;
		}
	}

	if (aio->aio_lio_opcode == CCOW_VOL_LIO_SYNC) {
		/* there is no queue for the object, so there is nothing to sync.
		 * or it's too late, queue was completed and removed */
		pthread_rwlock_unlock(&object_queue_rwlock);
		return -EBADF;
	}

	/* create a new object_link, enqueue first aio control block,
	 * and create thread that will work with it */
	pthread_rwlock_unlock(&object_queue_rwlock);

	ol = je_calloc(1, sizeof(struct object_link));
	if (ol == NULL) {
		return -ENOMEM;
	}

	/// === re-aquire wr lock

	pthread_rwlock_wrlock(&object_queue_rwlock);
	QUEUE_FOREACH(q, &ccow_objects) {
		/* repeat if other thread added some (same) object */
		struct object_link *ol_i = QUEUE_DATA(q, struct object_link, ccow_object);
		if (ol_i->ol_ci == aio->ci) {
			pthread_rwlock_unlock(&object_queue_rwlock);
			je_free(ol);
			goto repeat_add2q;
		}
	}
	pthread_mutex_init(&ol->io_mutex, NULL);
	pthread_cond_init(&ol->io_cond_var, NULL);
	ol->ol_ci = aio->ci;
	aio->aio_status = CCOW_VOL_STATUS_NEW;
	ol->new_cmd = 1;
	QUEUE_INIT(&ol->aio);
	QUEUE_INSERT_TAIL(&ol->aio, &aio->item);
	QUEUE_INSERT_TAIL(&ccow_objects, &ol->ccow_object);
	/* create thread */
	log_debug(lg,"create ccow_vol_io_task ci %p ol %p, oid %s",
	    aio->ci, ol, ol->ol_ci->oid);

	err = pthread_attr_init(&io_thread_attr);
	if (err) {
		log_error(lg, "pthread_attr_init returned err = %d", err);
		QUEUE_REMOVE(&ol->ccow_object);
		QUEUE_INIT(&ol->ccow_object);
		je_free(ol);
		return -err;
	}

	err = pthread_attr_setdetachstate(&io_thread_attr, PTHREAD_CREATE_DETACHED);
	if (err) {
		log_error(lg, "pthread_attr_setdetachstate returned err = %d", err);
		QUEUE_REMOVE(&ol->ccow_object);
		QUEUE_INIT(&ol->ccow_object);
		je_free(ol);
		return -err;
	}

	err = pthread_create(&ol->io_thread, &io_thread_attr, ccow_vol_io_task, &ol->ccow_object);
	if (err) {
		log_error(lg, "pthread_create returned err = %d", err);
		QUEUE_REMOVE(&ol->ccow_object);
		QUEUE_INIT(&ol->ccow_object);
		je_free(ol);
	}

	pthread_rwlock_unlock(&object_queue_rwlock);
	return -err;

}
static void
completion_cb(ccow_completion_t comp, void *arg, int index, int status)
{
	struct ccow_info * ci = (struct ccow_info *) arg;
	ccow_aio_t aio;

	log_debug(lg,"asnc_cb, index %i status %d", index, status);

	pthread_mutex_lock(&ci->ci_mutex);
	if (index == 0) {
		log_debug(lg, "index = 0, skip user callback");
		goto cb_exit;
	}
	if (!ci) {
		log_debug(lg, "call back argument is absent. Index  %d", index);
		goto cb_exit;
	}

	aio = (ccow_aio_t)ci->index_table[index];
	if (!aio) {
		/* aio is missed for ccow_get_cont originated from ccow_vol_chunk */
		log_debug(lg, "aio is missed for index %d", index);
		goto cb_exit;
	}
	log_debug(lg,"got aio %p aio_status %d ci_index %d", aio, aio->aio_status, aio->ci_index);
	assert(aio->ci_index == index);
	ci->index_table[index] = NULL;
	if (aio->chctx.ma_bufs) {
		if (aio->aio_lio_opcode == CCOW_VOL_LIO_READ) {
			if (aio->chctx.l0 > 0) {
				char *base = (char *)aio->iov[0].iov_base + aio->chctx.s0;
				memcpy(aio->chctx.buf, base, aio->chctx.l0);
			}

			if (aio->chctx.l2 > 0) {
				char *base = aio->iov[aio->iovcnt - 1].iov_base;
				memcpy(aio->chctx.buf + aio->chctx.l0 + aio->chctx.l1,
				    base, aio->chctx.l2);
			}
		}
		je_free(aio->chctx.ma_bufs);
	}
	if (aio->iov)
		je_free(aio->iov);
	else
		log_error(lg, "iov is null, index %d", index);

	if (aio->aio_lio_opcode == CCOW_VOL_LIO_WRITE_SAME
			|| aio->aio_lio_opcode == CCOW_VOL_LIO_UNMAP) {
		je_free(aio->chctx.buf);
	}
	if (status) {
		aio->aio_status = CCOW_VOL_STATUS_COMPLETE_WITH_ERRORS;
		log_error(lg, "io completed with an error, index %d", index);
	}
	else {
		aio->aio_status = CCOW_VOL_STATUS_COMPLETE;
	}
	aio->aio_errno = -status;

	if (aio->aio_sigevent == CCOW_VOL_SIGEV_NONE) {
		pthread_cond_broadcast(&ci->ci_cond_var);
		goto cb_exit;
	}
	if (aio->aio_cbfunction) {
		pthread_mutex_unlock(&ci->ci_mutex);
		aio->aio_cbfunction(aio->aio_cbargs);
		pthread_mutex_lock(&ci->ci_mutex);
	}

cb_exit:
	pthread_mutex_unlock(&ci->ci_mutex);
}

#define BILLION 1000000000
static struct timespec
time_add_nsec(struct timespec t1, long nsec_add)
{
	long sec = t1.tv_sec;
	long nsec = t1.tv_nsec + nsec_add;
	if (nsec >= BILLION) {
		nsec -= BILLION;
		sec++;
	}
	return (struct timespec){ .tv_sec = sec, .tv_nsec = nsec };
}

void *
ccow_vol_io_task(void * arg)
{
	struct object_link * ol = (struct object_link *) arg;
	struct ccow_info * ci = ol->ol_ci;
	QUEUE *q;
	QUEUE *qn;
	struct ccow_aio * aio;
	struct timespec ts;
	int err = 1, poll_cnt;
	pthread_t cb_thread;
	pthread_attr_t cb_thread_attr;

	while (1) {
		poll_cnt = 0;
		pthread_mutex_lock(&ol->io_mutex);
		while (!ol->new_cmd) {
			clock_gettime(CLOCK_REALTIME, &ts);
			ts = time_add_nsec(ts, CCOW_VOL_THREAD_TIMEOUT_NSEC);
			err = pthread_cond_timedwait(&ol->io_cond_var, &ol->io_mutex, &ts);
			if (!ol->ol_ci) {
				QUEUE_FOREACH_SAFE(q, qn, &ol->aio) {
					aio = QUEUE_DATA(q, struct ccow_aio, item);
					aio->aio_status = CCOW_VOL_STATUS_CANCELED;
					if (aio->aio_sigevent == CCOW_VOL_SIGEV_THREAD) {
						QUEUE_REMOVE(q);
						QUEUE_INIT(q);
						if (aio->aio_cbfunction)
							aio->aio_cbfunction(aio->aio_cbargs);
					}
				}
				goto vol_io_task_exit;
			}
			if (err == ETIMEDOUT) {
				if (ol->new_cmd || !QUEUE_EMPTY(&ol->aio)) {
					break;
				}
				if (QUEUE_EMPTY(&ol->aio)) {
vol_io_task_exit:
					pthread_mutex_unlock(&ol->io_mutex);
					/// === NO LOCK - need to re-check queue ===
					pthread_rwlock_wrlock(&object_queue_rwlock);
					pthread_mutex_lock(&ol->io_mutex);
					if (!QUEUE_EMPTY(&ol->aio) ||
					    (poll_cnt++ < CCOW_VOL_THREAD_POLL_MAX)) {
						pthread_mutex_unlock(&ol->io_mutex);
						pthread_rwlock_unlock(&object_queue_rwlock);
						/// === RE-LOCK
						pthread_mutex_lock(&ol->io_mutex);
						continue;
					}
					pthread_mutex_unlock(&ol->io_mutex);
					QUEUE_REMOVE(&ol->ccow_object);
					QUEUE_INIT(&ol->ccow_object);

					if (ol->ol_ci) {
						err = ccow_vol_finalize(ol->ol_ci, 0);
						if (err)
							log_error(lg, "ccow_vol_finalize error %d", err);
					}

					pthread_rwlock_unlock(&object_queue_rwlock);

					log_debug(lg, "exit ccow_vol_io_task ol %p, oid %s, io_count %i",
									ol, ci->oid, ci->io_count);
					je_free(ol);
					pthread_exit(NULL);
				}
			}
		}
		ol->new_cmd = 0;
		QUEUE_FOREACH_SAFE(q, qn, &ol->aio) {
			aio = QUEUE_DATA(q, struct ccow_aio, item);
			if (aio->aio_status != CCOW_VOL_STATUS_NEW) {
				if (aio->aio_sigevent == CCOW_VOL_SIGEV_THREAD) {
					QUEUE_REMOVE(q);
					QUEUE_INIT(q);
					log_error(lg, "REMOVED %p aio %p", q, aio);
					log_error(lg, "OL %p %p", ol->aio[0], ol->aio[1]);
				}
				continue;
			}
			aio->aio_status = CCOW_VOL_STATUS_IN_PROGRESS;
			aio->iov = NULL;
			aio->chctx.ma_bufs = NULL;
			int sigevent = aio->aio_sigevent;
			if (aio->aio_lio_opcode == CCOW_VOL_LIO_NOP) {
				pthread_mutex_lock(&ci->ci_mutex);
				goto bcp_free;
			}
			if (aio->aio_lio_opcode == CCOW_VOL_LIO_SYNC ||
						ci->io_count >= CCOW_VOL_OP_CNT - 6) {
				pthread_mutex_unlock(&ol->io_mutex);
				err = ccow_vol_finalize(ci, aio->aio_lio_opcode == CCOW_VOL_LIO_SYNC);
				pthread_mutex_lock(&ol->io_mutex);
				if (err) {
					log_error(lg, "ccow_vol_finalize returned error %d", err);
					pthread_mutex_lock(&ci->ci_mutex);
					goto bcp_free;
				}
				if (aio->aio_lio_opcode == CCOW_VOL_LIO_SYNC) {
					aio->aio_status = CCOW_VOL_STATUS_COMPLETE;
					pthread_mutex_lock(&ci->ci_mutex);
					goto bcp_free;
				}
			}
			uint64_t mask = ci->chunk_size;
			mask--;
			uint64_t buf_mask = ~0;
			if (aio->aio_lio_opcode == CCOW_VOL_LIO_UNMAP) {
				buf_mask = mask;
			}
			if (aio->aio_lio_opcode == CCOW_VOL_LIO_WRITE_SAME) {
				if (aio->aio_in_size > ci->chunk_size)
					buf_mask = aio->aio_in_size;
				else
					buf_mask = ci->chunk_size;
				buf_mask--;
			}
			pthread_mutex_lock(&ci->ci_mutex);
			pthread_mutex_lock(&ci->sync_mutex);
			if (aio->aio_lio_opcode == CCOW_VOL_LIO_UNMAP
					|| aio->aio_lio_opcode == CCOW_VOL_LIO_WRITE_SAME) {
				err = ccow_vol_chunk(ci, aio->aio_offset, aio->chctx.buf,
						aio->aio_nbytes, buf_mask, &aio->iov, &aio->iovcnt,
						1, &aio->chctx);
			}
			else {
				err = ccow_vol_chunk(ci, aio->aio_offset, aio->aio_buf,
					aio->aio_nbytes, buf_mask, &aio->iov, &aio->iovcnt,
					aio->aio_lio_opcode == CCOW_VOL_LIO_READ ? 0 : 1, &aio->chctx);
			}
			pthread_mutex_unlock(&ci->sync_mutex);
			if (err) {
				log_error(lg, "write: ccow_vol_chunk returned error %d", err);
				goto bcp_free;
			}

			pthread_mutex_lock(&ci->sync_mutex);
			if (aio->aio_lio_opcode == CCOW_VOL_LIO_WRITE ||
			    aio->aio_lio_opcode == CCOW_VOL_LIO_WRITE_SAME ||
			    aio->aio_lio_opcode == CCOW_VOL_LIO_UNMAP) {

				if (aio->chctx.ma_bufs) {
					err = ccow_mod_put_cont(ci->c, aio->iov, aio->iovcnt,
						aio->aio_offset & (~mask), 0, &aio->chctx, &ci->io_count);
				}
				else {
					err = ccow_put_cont(ci->c, aio->iov, aio->iovcnt,
						aio->aio_offset & (~mask), 0, &ci->io_count);
				}
			}
			else if (aio->aio_lio_opcode == CCOW_VOL_LIO_READ) {
				err = ccow_get_cont(ci->c, aio->iov, aio->iovcnt,
						aio->aio_offset & (~mask), 0, &ci->io_count);
			}
			pthread_mutex_unlock(&ci->sync_mutex);
			if (err) {
				log_error(lg, "Error on I/O submit (%d): %d",
				    aio->aio_lio_opcode, err);
				goto bcp_free;
			}

			log_debug(lg, "scheduled aio %p tctx %p io_count %d",
			    aio, ci->tctx, ci->io_count);
			assert(ci->index_table[ci->io_count] == 0);
			ci->index_table[ci->io_count] = aio;
			aio->ci_index = ci->io_count;

bcp_free:
			if (sigevent == CCOW_VOL_SIGEV_THREAD) {
				QUEUE_REMOVE(q);
				QUEUE_INIT(q);
			}
			if (err) {
				aio->aio_status = CCOW_VOL_STATUS_COMPLETE_WITH_ERRORS;
				je_free(aio->iov);
				je_free(aio->chctx.ma_bufs);
				if ((aio->aio_lio_opcode == CCOW_VOL_LIO_UNMAP)
						|| (aio->aio_lio_opcode == CCOW_VOL_LIO_WRITE_SAME)) {
					je_free(aio->chctx.buf);
				}
			}
			if (err || aio->aio_lio_opcode == CCOW_VOL_LIO_SYNC) {
				if (sigevent == CCOW_VOL_SIGEV_NONE) {
					pthread_cond_broadcast(&ci->ci_cond_var);
				}
				if (sigevent == CCOW_VOL_SIGEV_THREAD) {
					if (aio->aio_cbfunction) {
						pthread_mutex_unlock(&ci->ci_mutex);
						aio->aio_cbfunction(aio->aio_cbargs);
						pthread_mutex_lock(&ci->ci_mutex);
					}
				}
			}
			pthread_mutex_unlock(&ci->ci_mutex);
		}
		pthread_mutex_unlock(&ol->io_mutex);
	}
}


int ccow_vol_read(ccow_aio_t aio)
{
	aio->aio_lio_opcode = CCOW_VOL_LIO_READ;
	return ccow_vol_add_to_queue(aio);
}

int ccow_vol_write(ccow_aio_t aio)
{
	aio->aio_lio_opcode = CCOW_VOL_LIO_WRITE;
	return ccow_vol_add_to_queue(aio);
}

int ccow_vol_write_same(ccow_aio_t aio)
{
	aio->aio_lio_opcode = CCOW_VOL_LIO_WRITE_SAME;
	return ccow_vol_add_to_queue(aio);
}

int ccow_vol_unmap(ccow_aio_t aio)
{
	aio->aio_lio_opcode = CCOW_VOL_LIO_UNMAP;
	return ccow_vol_add_to_queue(aio);
}

/* Use ccow_vol_start_stream only in pair with ccow_vol_stop_stream
 * and only after ccow_vol_stop_stream. It will prevent breaking
 * mutex logic and resource leaking.
 */
int ccow_vol_start_stream(ccow_aio_t aio)
{
	struct ccow_info  * ci = aio->ci;
	int err;

	/* Verify that sync_mutex is locked to inform about
	 * misuse of ccow_vol_start_stream
	 */
	err = pthread_mutex_trylock(&ci->sync_mutex);
	if (err != EBUSY) {
		if (err) {
			log_error(lg, "error %d trying sync_mutex", err);
			return err;
		}
		else {
			log_error(lg, "stream is already started");
			pthread_mutex_unlock(&ci->sync_mutex);
			return EEXIST;
		}
	}

	ci->io_count = 0;
	memset(ci->index_table, 0, sizeof (ci->index_table));

	int flags = CCOW_CONT_F_EPHEMERAL;
	err = ccow_create_stream_completion(ci->tctx, ci, completion_cb,
			CCOW_VOL_OP_CNT, &ci->c, ci->bid, ci->bid_size,
			ci->oid, ci->oid_size, &ci->genid, &flags, NULL);
	if (err) {
		log_error(lg, "cannot cleanly create new stream, err = %d", err);
		pthread_mutex_unlock(&ci->sync_mutex);
		/* release mutex, allow another attempt beginning from stop */
		return err;
	}
	/* unlock sync_mutex to allow ccow_vol_stop_stream again */
	pthread_mutex_unlock(&ci->sync_mutex);

	return 0;
}

/* Don't forget ccow_vol_start_stream to restore libccowvol operation
 * after ccow_vol_stop_stream
 */
int ccow_vol_stop_stream(ccow_aio_t aio)
{
	struct ccow_info *ci = aio->ci;
	int err;

	/* sync_mutex prevents concurrent execution of stop / start stream.
	 * As long as ccow_vol_stop_stream should always precede
	 * ccow_vol_start_stream this mutex is also prevent concurrent
	 * execution of ccow_vol_start_stream (and ccow_vol_finalize too)
	 */
	pthread_mutex_lock(&ci->sync_mutex);
	ccow_vol_reset_ephemeral(ci);
	err = ccow_finalize(ci->c, NULL);
	if (err) {
		pthread_mutex_unlock(&ci->sync_mutex);
		log_error(lg, "cannot cleanly finalize stream, err = %d", err);
		return err;
	}
	ci->writes = 0;

	return 0;
}

int ccow_vol_fsync(ccow_aio_t aio)
{
	int err;
	aio->aio_lio_opcode = CCOW_VOL_LIO_SYNC;
	err = ccow_vol_add_to_queue(aio);
	if (err == -EBADF)
		return 0;
	return err;
}

int ccow_vol_synchronize(ccow_aio_t aio)
{
	int err = 0;
	ssize_t nbytes = 0;

	aio->aio_lio_opcode = CCOW_VOL_LIO_SYNC;
	aio->aio_sigevent = CCOW_VOL_SIGEV_NONE;
	err = ccow_vol_add_to_queue(aio);
	if (err) {
		if (err == -EBADF)
			return 0;
		return err;
	}

	err = ccow_vol_error(aio);
	if (err == 0) {
		nbytes = ccow_vol_return(aio);
		if (nbytes < 0) {
			err = nbytes;
		} else if ((size_t)nbytes == aio->aio_nbytes) {
			err = 0;
		} else {
			err = EIO;
			goto rb_exit;
		}
	} else if (err == EINPROGRESS) {
		err = -EINPROGRESS;
	}

	while (err == -EINPROGRESS) {
		err = ccow_vol_suspend(&aio, 1, NULL);
		if (err != 0)
			goto rb_exit;
		nbytes = ccow_vol_return(aio);
		if (nbytes < 0) {
			err = nbytes;
		} else if ((size_t)nbytes == aio->aio_nbytes) {
			err = 0;
			break;
		} else {
			err = EIO;
			goto rb_exit;
		}
	}

rb_exit:
	log_trace(lg, "sync error %i", err);
	return err;
}


int ccow_vol_listio(ccow_aio_t lio[], int n)
{
	int res;
	int cnt;
	for (cnt = 0; cnt < n; cnt++) {
		res = ccow_vol_add_to_queue(lio[cnt]);
		if (res != 0)
			return res;
	}
	return 0;
}


int
ccow_vol_error(ccow_aio_t aio)
{
	QUEUE *q1, *q2;
	struct object_link *ol;
	ccow_aio_t aio_in_queue;

	pthread_rwlock_rdlock(&object_queue_rwlock);
	QUEUE_FOREACH(q1, &ccow_objects) {
		ol = QUEUE_DATA(q1, struct object_link, ccow_object);
		if (ol->ol_ci == aio->ci) {
			pthread_mutex_lock(&ol->io_mutex);
			QUEUE_FOREACH(q2, &ol->aio) {
				aio_in_queue = QUEUE_DATA(q2, struct ccow_aio, item);
				if (aio_in_queue == aio) {
					pthread_mutex_unlock(&ol->io_mutex);
					pthread_rwlock_unlock(&object_queue_rwlock);
					if (aio_in_queue->aio_status == CCOW_VOL_STATUS_COMPLETE) {
						return 0;
					}
					else if (aio_in_queue->aio_status ==
								CCOW_VOL_STATUS_COMPLETE_WITH_ERRORS) {
						return aio_in_queue->aio_errno;
					}
					else if (aio_in_queue->aio_status ==
											CCOW_VOL_STATUS_CANCELED) {
						return ECANCELED;
					}
					else return EINPROGRESS;
				}
			}
			pthread_mutex_unlock(&ol->io_mutex);
		}
	}
	pthread_rwlock_unlock(&object_queue_rwlock);
	return EINVAL;
}


ssize_t ccow_vol_return(ccow_aio_t aio)
{
	QUEUE *q1, *q2, *qn;
	struct object_link *ol;
	ccow_aio_t aio_in_queue;

	pthread_rwlock_rdlock(&object_queue_rwlock);
	QUEUE_FOREACH(q1, &ccow_objects) {
		ol = QUEUE_DATA(q1, struct object_link, ccow_object);
		if (ol->ol_ci == aio->ci) {
			pthread_mutex_lock(&ol->io_mutex);
			QUEUE_FOREACH_SAFE(q2, qn, &ol->aio) {
				aio_in_queue = QUEUE_DATA(q2, struct ccow_aio, item);
				if (aio_in_queue == aio
						&& aio->aio_sigevent == CCOW_VOL_SIGEV_NONE) {
					if (aio_in_queue->aio_status == CCOW_VOL_STATUS_COMPLETE) {
						QUEUE_REMOVE(q2);
						QUEUE_INIT(q2);
						pthread_mutex_unlock(&ol->io_mutex);
						pthread_rwlock_unlock(&object_queue_rwlock);
						return aio->aio_nbytes;
					}
					else if (aio_in_queue->aio_status ==
								CCOW_VOL_STATUS_COMPLETE_WITH_ERRORS) {
						QUEUE_REMOVE(q2);
						QUEUE_INIT(q2);
						pthread_mutex_unlock(&ol->io_mutex);
						pthread_rwlock_unlock(&object_queue_rwlock);
						return -aio_in_queue->aio_errno;
					}
					else if (aio_in_queue->aio_status ==
								CCOW_VOL_STATUS_CANCELED) {
						QUEUE_REMOVE(q2);
						QUEUE_INIT(q2);
						pthread_mutex_unlock(&ol->io_mutex);
						pthread_rwlock_unlock(&object_queue_rwlock);
						return -ECANCELED;
					}
					else {
						pthread_mutex_unlock(&ol->io_mutex);
						pthread_rwlock_unlock(&object_queue_rwlock);
						return -EINPROGRESS;
					}
				}
			}
			pthread_mutex_unlock(&ol->io_mutex);
		}
	}
	pthread_rwlock_unlock(&object_queue_rwlock);
	return -EINVAL;
}

/* attention!! don't mix different ci in the same aiocb_list[]*/
int
ccow_vol_suspend(ccow_aio_t aiocb_list[],
                       int nitems, const struct timespec *timeout)
{
	int i;
	struct ccow_info *ci;
	int wait_set = -1;

	for (i = 0; i < nitems; i++) {
		if (aiocb_list[i]->aio_sigevent == CCOW_VOL_SIGEV_NONE) {
			if (aiocb_list[i]->aio_status == CCOW_VOL_STATUS_IN_PROGRESS ||
					aiocb_list[i]->aio_status == CCOW_VOL_STATUS_NEW) {
				if (wait_set == -1)
					wait_set = i;
			}
			else {
				return 0;
			}
		}
	}
	if (wait_set == -1)
		return -1;
		/* didn't find something to suspend?
		 * doesn't call ccow_vol_suspend if aio_sigevent != CCOW_VOL_SIGEV_NONE
		 */

	/* attention!! don't mix different ci in the same aiocb_list[] */
	ci = aiocb_list[wait_set]->ci;

	pthread_mutex_lock(&ci->ci_mutex);
	if (timeout && !(timeout->tv_sec == 0 && timeout->tv_nsec == 0))
		pthread_cond_timedwait(&ci->ci_cond_var, &ci->ci_mutex, timeout);
	else {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_nsec += 1*1000000; // 1ms if we missed
		pthread_cond_timedwait(&ci->ci_cond_var, &ci->ci_mutex, &ts);
	}
	/* Spurious wake up isn't an issue there,
	 * because we have the loop around whole ccow_vol_suspend
	 */
	pthread_mutex_unlock(&ci->ci_mutex);
	return 0;
}


int
ccow_vol_cancel(struct ccow_info * ci, ccow_aio_t aio)
{
	QUEUE *q1, *q2, *qn;
	struct object_link *ol;
	ccow_aio_t aio_in_queue;
	int notcanceled = 0;
	int alldone = 1;

	log_debug(lg, "ccow_vol_cancel ci %p, aio %p ", ci, aio);

	if (!ci)
		return CCOW_VOL_NOTCANCELED;

	pthread_rwlock_rdlock(&object_queue_rwlock);
	QUEUE_FOREACH(q1, &ccow_objects) {
		ol = QUEUE_DATA(q1, struct object_link, ccow_object);
		if (ol->ol_ci == ci) {
			QUEUE_FOREACH_SAFE(q2, qn, &ol->aio) {
				aio_in_queue = QUEUE_DATA(q2, struct ccow_aio, item);
				if (aio_in_queue == aio || aio == NULL) {
					if (aio_in_queue->aio_status == CCOW_VOL_STATUS_NEW) {
						if (aio_in_queue->aio_sigevent == CCOW_VOL_SIGEV_THREAD) {
							pthread_mutex_lock(&ol->io_mutex);
							QUEUE_REMOVE(q2);
							QUEUE_INIT(q2);
							pthread_mutex_unlock(&ol->io_mutex);
							aio_in_queue->aio_status = CCOW_VOL_STATUS_CANCELED;
							if (aio_in_queue->aio_cbfunction)
								aio_in_queue->aio_cbfunction(aio_in_queue->aio_cbargs);
							alldone = 0;
							if (aio)
								break;
						}
						else {
							pthread_mutex_lock(&ci->ci_mutex);
							aio_in_queue->aio_status = CCOW_VOL_STATUS_CANCELED;
							pthread_cond_broadcast(&ci->ci_cond_var);
							pthread_mutex_unlock(&ci->ci_mutex);
							alldone = 0;
							if (aio)
								break;
						}
					}
					else {
						if (aio_in_queue->aio_status == CCOW_VOL_STATUS_COMPLETE ||
							aio_in_queue->aio_status ==
									CCOW_VOL_STATUS_COMPLETE_WITH_ERRORS) {
							if (aio)
								break;
						}
						else {
							notcanceled = 1;
							if (aio)
								break;
						}
					}
				}
			}
			pthread_rwlock_unlock(&object_queue_rwlock);
			if (notcanceled)
				return CCOW_VOL_NOTCANCELED;
			if (alldone)
				return CCOW_VOL_ALLDONE;
			return CCOW_VOL_CANCELED;
		}
	}
	pthread_rwlock_unlock(&object_queue_rwlock);
	return CCOW_VOL_NOTCANCELED;
}

static void
ccow_vol_reset_ephemeral(struct ccow_info *ci)
{
	int flags = 0;
	ccow_stream_flags(ci->c, &flags);
	flags &= ~CCOW_CONT_F_EPHEMERAL;
	ccow_stream_flags(ci->c, &flags);
}

static int
ccow_vol_finalize(struct ccow_info *ci, int flush)
{
	int err;

	if (!ci->c) {
		log_error(lg, "completion isn't available");
		return -EINVAL;
	}

	/* sync_mutex prevents concurrent execution of ccow_finalize and,
	 * more important, ccow_create_stream_completion. This helps
	 * prevent resource leakage (particularly comp_lfq)
	 */
	pthread_mutex_lock(&ci->sync_mutex);

	if (!ci->io_count) {
		pthread_mutex_unlock(&ci->sync_mutex);
		return 0;
	}

	if (flush)
		ccow_vol_reset_ephemeral(ci);
	err = ccow_finalize(ci->c, NULL);
	if (err) {
		log_error(lg, "cannot cleanly finalize stream, err = %d", err);
		pthread_mutex_unlock(&ci->sync_mutex);
		return err;
	}

	if (flush)
		ci->writes = 0;
	ci->io_count = 0;
	memset(ci->index_table, 0, sizeof (ci->index_table));

	int flags = CCOW_CONT_F_EPHEMERAL;
	err = ccow_create_stream_completion(ci->tctx, ci, completion_cb,
			CCOW_VOL_OP_CNT, &ci->c, ci->bid, ci->bid_size,
			ci->oid, ci->oid_size, &ci->genid, &flags, NULL);
	if (err) {
		log_error(lg, "cannot cleanly create new stream, err = %d", err);
	}

	pthread_mutex_unlock(&ci->sync_mutex);
	return err;
}

static int
ccow_vol_chunk(struct ccow_info *ci, uint64_t offset,  char *buf,
		size_t length, uint64_t buf_mask, struct iovec **iov, size_t *iovcnt,
		uint write, struct ccow_rmw_context *ch_ctx)
{
	int err = 0;
	uint64_t s0 = 0, s1 = 0, s2 = 0;
	size_t l0 = 0, l1 = 0, l2 = 0;
	size_t t = 0;
	size_t cnt = 0;
	size_t iov_idx = 0;

	uint64_t mask = ci->chunk_size;
	mask--;

	/*
	 * start and length of region 0. this is the unaligned region at the
	 * beginning of the request.  length may be zero if the offset is
	 * page aligned.
	 */

	log_debug(lg, "offset = %"PRIx64" : mask = %"PRIx64" : chunk_size = %d",
	    offset, mask, ci->chunk_size);

	s0 = offset & mask;

	if (s0 == 0) {
		l0 = 0;
	} else {
		if (ci->chunk_size - s0 < length) {
			l0 = ci->chunk_size - s0;
		} else {
			l0 = length;
		}

		t += l0;
	}

	/*
	 * start and length of region 1. this is the aligned region in the
	 * middle of the request. length may be zero.
	 */
	s1 = s0 + l0;
	if (t < length) {
		l1 = (length - l0) & ~(mask);
		t += l1;
	}

	/*
	 * start and length of region 2. this is the sub-page sized region at
	 * the end of the request.
	 */
	s2 = s1 + l1;
	if (t < length) {
		l2 = length - t;
	}

	ch_ctx->s0 = s0;
	ch_ctx->s1 = s1;
	ch_ctx->s2 = s2;
	ch_ctx->l0 = l0;
	ch_ctx->l1 = l1;
	ch_ctx->l2 = l2;
	ch_ctx->buf = buf;

	log_debug(lg, "s0 : 0x%"PRIx64"", s0);
	log_debug(lg, "s1 : 0x%"PRIx64"", s1);
	log_debug(lg, "s2 : 0x%"PRIx64"", s2);
	log_debug(lg, "l0 : 0x%"PRIx64"", l0);
	log_debug(lg, "l1 : 0x%"PRIx64"", l1);
	log_debug(lg, "l2 : 0x%"PRIx64"", l2);

	/* adjust l1 for operation that use buffer shorter that length parameter
	 * that is used by unaligned unmap and write_same
	 */
	ch_ctx->l1 = l1 & buf_mask;

	/* allocate extra buffers if r/w misaligned */
	if (l0 || l2) {
		ch_ctx->ma_bufs = je_malloc(2 * ci->chunk_size);
		if (ch_ctx->ma_bufs == NULL) {
			return -ENOMEM;
		}
	}
	else
		ch_ctx->ma_bufs = NULL;
	cnt = l1 / ci->chunk_size;
	if (l0 > 0) cnt++;
	if (l2 > 0) cnt++;
	/*
	 * initialize io vector
	 */
	struct iovec *v = je_calloc(cnt, sizeof (struct iovec));

	if (v == NULL) {
		*iovcnt = 0;
		return -ENOMEM;
	}

	*iov = v;
	*iovcnt = cnt;

	if (write)	{
		/*
		 * writes may require read/modify/write on unaligned pages
		 */
		if (l0 > 0) {

			v[iov_idx].iov_base = &ch_ctx->ma_bufs[0];
			v[iov_idx++].iov_len = ci->chunk_size;

			err = ccow_get_cont(ci->c, &v[0], 1, offset & ~(mask), 0,
					&ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get, %m");
				return err;
			}
			log_trace(lg, "rmw l0 %li, offset %li, index %i",
						l0, offset & ~(mask), ci->io_count);
		}

		if (l2 > 0) {
			size_t last_iov = iov_idx + l1/ci->chunk_size;
			v[last_iov].iov_base = &ch_ctx->ma_bufs[ci->chunk_size];
			v[last_iov].iov_len = ci->chunk_size;

			err = ccow_get_cont(ci->c, &v[last_iov], 1, offset + l0 + l1, 0,
					&ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get2, %m");
				return err;
			}

			log_debug(lg, "scheduled aio tctx %p rmw l2 %li, offset %li, io_count %i",
			    ci->tctx, l2, offset + l0 + l1, ci->io_count);
		}

		size_t off = l0;

		while (l1 > 0) {
			v[iov_idx].iov_base = buf + (off & buf_mask);
			v[iov_idx].iov_len = ci->chunk_size;

			off += ci->chunk_size;
			iov_idx++;
			l1 -= ci->chunk_size;
		}

	}
	else {
		/*
		 * reads may require alignment adjustment for unaligned pages
		 */

		if (l0 > 0) {
			v[iov_idx].iov_base = &ch_ctx->ma_bufs[0];
			v[iov_idx++].iov_len = ci->chunk_size;
		}

		if (l2 > 0) {
			v[iov_idx + l1/ci->chunk_size].iov_base =
				&ch_ctx->ma_bufs[ci->chunk_size];
			v[iov_idx + l1/ci->chunk_size].iov_len = ci->chunk_size;
		}

		char * base = buf + l0;

		while (l1 > 0) {
			v[iov_idx].iov_base = base;
			v[iov_idx].iov_len = ci->chunk_size;

			base += ci->chunk_size;
			iov_idx++;
			l1 -= ci->chunk_size;
		}

	}
	return err;
}

int
ccow_vol_open(struct ccow_info *ci, char *uri, int *fd, uint64_t *vol_size)
{
	int err;

	if (!lg)
		lg = Logger_create("libccowvol");

	if (sscanf(uri, "%2047[^/]/%2047[^/]/%2047[^/]/%2047[^\n]",
		    ci->cid, ci->tid, ci->bid, ci->oid) < 4) {
		log_error(lg, "open error: wrong object path format");
		return -1;
	}
	ci->cid_size = strlen(ci->cid) + 1;
	ci->tid_size = strlen(ci->tid) + 1;
	ci->bid_size = strlen(ci->bid) + 1;
	ci->oid_size = strlen(ci->oid) + 1;

	pthread_mutexattr_t attr;
	err = pthread_mutexattr_init(&attr);
	assert(err == 0);

	err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
	assert(err == 0);

	pthread_mutex_init(&ci->ci_mutex, &attr);
	pthread_cond_init(&ci->ci_cond_var, NULL);
	pthread_mutex_init(&ci->sync_mutex, NULL);
	pthread_rwlock_init(&ci->user_lck, NULL);

	char ccow_path[PATH_MAX];
	snprintf(ccow_path, sizeof(ccow_path), "%s/etc/ccow/ccow.json", nedge_path());
	int ccow_fd = open(ccow_path, O_RDONLY);
	if (ccow_fd < 0) {
		log_error(lg, "ccow.json open error: %s", strerror(errno));
		goto _rm_evt_exit;
	}

	char buf[16384];
	err = read(ccow_fd, buf, 16383);
	if (err < 0) {
		log_error(lg, "ccow.json read error: %s", strerror(errno));
		close(ccow_fd);
		goto _rm_evt_exit;
	}
	close(ccow_fd);
	buf[err] = 0;

	err = ccow_tenant_init(buf, ci->cid, ci->cid_size, ci->tid,
	    ci->tid_size, &ci->tctx);
	if (err) {
		log_error(lg, "ccow_tenant_init error: %s", strerror(err));
		goto _rm_evt_exit;
	}

	ccow_completion_t c;
	err = ccow_create_completion(ci->tctx, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "ccow_create_completion error on init: %d", err);
		goto _rm_evt_exit;
	}

	ccow_lookup_t iter;
	err = ccow_get(ci->bid, ci->bid_size, ci->oid, ci->oid_size, c, NULL,
	    0, 0, &iter);
	if (err) {
		ccow_release(c);
		log_error(lg, "ccow_get error on init: %d", err);
		goto _rm_evt_exit;
	}

	err = ccow_wait(c, -1);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		log_error(lg, "ccow_wait error on init: %d", err);
		goto _rm_evt_exit;
	}

	*vol_size = 0;
	ci->chunk_size = 0;
	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_CUSTOM |
			    CCOW_MDTYPE_METADATA, -1))) {
		if (strcmp(kv->key, "X-volsize") == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, vol_size);
		} else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv,
			    &ci->chunk_size);
		}
	}
	ccow_lookup_release(iter);

	if (!*vol_size) {
		log_error(lg, "attribute X-volsize not found on init");
		goto _rm_evt_exit;
	}

	if (!ci->chunk_size || (ci->chunk_size % 512 != 0) ||
	    ci->chunk_size > CCOW_VOL_CHUNK_SIZE_MAX) {
		log_error(lg, "attribute %s not found or incorrect (%d) on init",
		    RT_SYSKEY_CHUNKMAP_CHUNK_SIZE, ci->chunk_size);
		goto _rm_evt_exit;
	}

	ci->size = *vol_size;

	/* this is Initiator's configured block size */
	/* ci->blk_size = 1U << lu->blk_shift; seems not in use */

	ci->io_count = 0;
	memset(ci->index_table, 0, sizeof (ci->index_table));
	ci->genid = 0;

	int flags = CCOW_CONT_F_EPHEMERAL;
	err = ccow_create_stream_completion(ci->tctx, ci, completion_cb,
	    CCOW_VOL_OP_CNT, &ci->c, ci->bid, ci->bid_size, ci->oid,
	    ci->oid_size, &ci->genid, &flags, NULL);
	if (err) {
		log_error(lg, "cannot initialize stream on init (%d)", err);
		goto _rm_evt_exit;
	}

	return 0;

_rm_evt_exit:
	return -1;
}


void ccow_vol_close(struct ccow_info *ci)
{
	int err;
	QUEUE *q;
	struct object_link *ol = NULL;

	ccow_vol_cancel(ci, NULL);
	pthread_rwlock_wrlock(&object_queue_rwlock);
	QUEUE_FOREACH(q, &ccow_objects) {
		ol = QUEUE_DATA(q, struct object_link, ccow_object);
		if (ol->ol_ci == ci) {
			/* release ccow_vol_io_task */
			pthread_mutex_lock(&ol->io_mutex);
			ol->ol_ci = NULL;
			pthread_cond_signal(&ol->io_cond_var);
			pthread_mutex_unlock(&ol->io_mutex);
			break;
		}
	}
	pthread_rwlock_unlock(&object_queue_rwlock);
	ccow_vol_reset_ephemeral(ci);
	err = ccow_finalize(ci->c, NULL);
	if (err) {
		log_error(lg, "warning: cannot finalize stream on close (%d)", err);
	}
	ci->writes = 0;
	ci->c = NULL;
	ccow_tenant_term(ci->tctx);
	pthread_mutex_destroy(&ci->ci_mutex);
	pthread_mutex_destroy(&ci->sync_mutex);
	pthread_cond_destroy(&ci->ci_cond_var);
	pthread_rwlock_destroy(&ci->user_lck);
}

