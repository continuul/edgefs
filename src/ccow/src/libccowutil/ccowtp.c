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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <queue.h>
#include "lfq.h"
#include "ccowutil.h"
#include "ccowtp.h"

struct ccowtp_je;
struct ccowpt_worker_priv;
static uint64_t g_total_size;

struct ccowtp_wh {
	size_t size;
	struct ccowpt_worker_priv* thr_arg;
	QUEUE idle_queue;
	uint64_t idle_len;
	pthread_mutex_t lock;
};

struct ccowtp {
	uv_loop_t* loop;
	uv_async_t async;
	size_t size;
	volatile int term;
	struct ccowtp_job_config jobcfg[CCOWTP_JOBTYPE_MAX];
	uint64_t wabs[CCOWTP_JOBTYPE_MAX]; /* Number of workers per job type, absolute value */
	uint64_t wminj[CCOWTP_JOBTYPE_MAX]; /* Number of reserved workers per job type , absolute value */
	uint16_t n_jobs; /* number of job types */
	uint8_t wh_shared;
	struct ccowtp_wh* wh;
	QUEUE reqdone_queue; /* A queue of finished requests waiting for done callback */
	pthread_mutex_t reqdone_queue_lock;
	QUEUE* pending_queue; /* queues of pending jobs, one queue per job type */
	pthread_mutex_t pending_queue_lock;
	uint64_t total_pending;
	uint64_t total_busy;
	struct ccowtp_stat stat;
	struct avg_ring prop_latency_ring;
	struct avg_ring full_latency_ring;
	pthread_mutex_t sched_lock;
	volatile uint64_t sched_repeat;
};

/* thread pool job entry */
struct ccowtp_je {
	QUEUE item;
	int prio;
	struct ccowtp* tp;
	ccowtp_work_cb work;
	ccowtp_after_work_cb after_work;
	void* arg;
	struct ccowtp_job_config* cfg;
	uint64_t prop_latency; /* Scheduler to worker propagation latency */
	uint64_t full_latency; /* enqueue to worker latency */
};

enum {
	CCOWTPW_IDLE,
	CCOWTPW_BUSY,
	CCOWTPW_TERM
};

enum {
	CCOWTP_TERM_WAIT = 1,
	CCOWTP_TERM_CANCEL,
	CCOWTP_TERM_FINISH
};

struct ccowpt_worker_priv {
	QUEUE item;
	size_t index;
	int state;
	pthread_cond_t cond;
	pthread_mutex_t lock;
	pthread_t thr;
	struct ccowtp_je* je;
	uint64_t ref_cnt;
};

static void exec_async(uv_async_t* handle, int status);
static void ccowtp_sched(struct ccowtp* tp);
static void* ccowtp_worker_work(void* arg);

struct ccowtp_wh*
ccowtp_create_wh(size_t n) {
	int err = 0;
	struct ccowtp_wh* wh = je_calloc(1, sizeof(*wh));
	if (!wh)
		return NULL;
	wh->size = n;

	wh->thr_arg = je_calloc(n, sizeof(struct ccowpt_worker_priv));
	if (!wh->thr_arg)
		goto _err_exit;

	QUEUE_INIT(&wh->idle_queue);
	pthread_mutex_init(&wh->lock, NULL);
	wh->idle_len = 0;

	for (size_t i = 0; i < n; i++) {
		struct ccowpt_worker_priv* e = wh->thr_arg + i;
		e->index = i;
		e->je = NULL;
		e->state = CCOWTPW_IDLE;
		e->ref_cnt = 1;
		pthread_cond_init(&e->cond, NULL);
		pthread_mutex_init(&e->lock, NULL);
		err = pthread_create(&e->thr, NULL, ccowtp_worker_work, e);
		if (err) {
			err = -ENOENT;
			goto _err_exit;
		}
		QUEUE_INIT(&e->item);
		QUEUE_INSERT_TAIL(&wh->idle_queue, &e->item);
	}
	wh->idle_len = n;
	g_total_size += n;
	return wh;

_err_exit:
	if (wh->thr_arg) {
		if (err == ENOENT) {
			for (size_t i = 0; i < n; i++)
				if (wh->thr_arg[i].index == i) {
					struct ccowpt_worker_priv* w = wh->thr_arg + i;
					pthread_mutex_lock(&w->lock);
					w->state = CCOWTPW_TERM;
					pthread_cond_signal(&w->cond);
					pthread_join(w->thr, NULL);
					pthread_mutex_unlock(&w->lock);
				}
		}
		je_free(wh->thr_arg);
	}
	je_free(wh);
	return NULL;
}

void
ccowtp_destroy_wh(struct ccowtp_wh* wh) {
	for (size_t i = 0; i < wh->size; i++) {
		struct ccowpt_worker_priv* w = wh->thr_arg + i;
		pthread_mutex_lock(&w->lock);
		w->state = CCOWTPW_TERM;
		pthread_cond_signal(&w->cond);
		pthread_mutex_unlock(&w->lock);
		pthread_join(w->thr, NULL);
	}
	je_free(wh->thr_arg);
	g_total_size -= wh->size;
	je_free(wh);
}

static void
ccowtp_cancel_cb(void* arg) {
	abort();
}

static void
ccowtp_async_send(struct ccowtp* tp) {
	if (tp->loop)
		uv_async_send(&tp->async);
}

static void*
ccowtp_worker_work(void* arg) {
	struct ccowpt_worker_priv* priv = arg;
	struct ccowtp_je* je;
	int err = 0;
	struct sched_param params = {.__sched_priority = 0 };
	struct timespec ts;
	int term = 0;

	/* Loop for ever */
	while(!term) {
		pthread_mutex_lock(&priv->lock);
		/* Waiting for a new assignment */
		uint64_t state;
		while((state = priv->state) == CCOWTPW_IDLE)
			pthread_cond_wait(&priv->cond, &priv->lock);
		pthread_mutex_unlock(&priv->lock);

		if (state == CCOWTPW_TERM) {
			if (priv->je)
				je_free(priv->je);
			priv->je = NULL;
			break;
		}
		assert(priv->ref_cnt == 0);
		priv->je->prop_latency = get_timestamp_us() - priv->je->prop_latency;
		priv->je->full_latency = get_timestamp_us() - priv->je->full_latency;
		/* At this point we should have priv->je pointing
		 * to a new job assignment
		 */
		je = priv->je;
		assert(je);
		assert(je->cfg);
		assert(je->tp);
		struct ccowtp* tp = je->tp;
		int prio = je->prio;
		if (je->work != ccowtp_cancel_cb) {
			params.sched_priority = je->cfg->prio;
			pthread_setschedparam(pthread_self(), je->cfg->sched, &params);
			/* Invoke the worker */
			je->work(je->arg);
		}
		atomic_inc64(&tp->stat.finished);
		/* Change state to idle */
		pthread_mutex_lock(&priv->lock);
		state = priv->state;
		priv->state = CCOWTPW_IDLE;
		pthread_mutex_unlock(&priv->lock);
		if (state != CCOWTPW_TERM) {
			assert(state == CCOWTPW_BUSY);
		} else
			term = 1;
		/*
		 * Adding the request to "request done" queue
		 * and invoke an async call
		 */
		pthread_mutex_lock(&tp->reqdone_queue_lock);
		QUEUE_INSERT_TAIL(&tp->reqdone_queue, &je->item);
		pthread_mutex_unlock(&tp->reqdone_queue_lock);
		priv->je = NULL;

		/* Notify the work is done */
		if (tp->term != CCOWTP_TERM_FINISH)
			ccowtp_async_send(tp);
		atomic_inc64(&priv->ref_cnt);
		pthread_mutex_lock(&tp->wh->lock);
		QUEUE_INSERT_TAIL(&tp->wh->idle_queue, &priv->item);
		atomic_inc64(&tp->wh->idle_len);
		pthread_mutex_unlock(&tp->wh->lock);
		atomic_dec64(&tp->total_busy);
		atomic_dec64(tp->stat.busy + prio);
	}
	return NULL;
}

static struct ccowtp*
ccowtp_create_internal(uv_loop_t* loop, struct ccowtp_job_config* cfg,
	size_t n_cfgs, size_t pool_size, struct ccowtp_wh* ext_heap) {
	int err = 0;
	struct ccowtp* tp = je_calloc(1, sizeof(*tp));
	if (!tp)
		return NULL;
	tp->n_jobs = n_cfgs;
	tp->stat.prio_total = n_cfgs;
	memcpy(tp->jobcfg, cfg, sizeof(*cfg)*n_cfgs);

	if (ext_heap) {
		tp->wh_shared = 1;
		tp->wh = ext_heap;
	} else {
		tp->wh_shared = 0;
		tp->wh = ccowtp_create_wh(pool_size);
		if (!tp->wh)
			goto _err_exit;
	}
	tp->size = tp->wh->size;

	for (size_t i = 0 ; i < tp->n_jobs; i++) {
		/* Estimate number of workers for each job type */
		assert(tp->jobcfg[i].weight >= 0);
		assert(tp->jobcfg[i].weight <= 100);
		tp->wabs[i] = tp->size * tp->jobcfg[i].weight / 100;
		/*
		 * Number of reserved workers per type
		 * We guarantee at least one worker reserved
		 */
		assert(tp->jobcfg[i].min >= 0);
		assert(tp->jobcfg[i].min <= 100);
		tp->wminj[i] = tp->wabs[i] * tp->jobcfg[i].min / 100;
		if (!tp->wminj[i] && tp->jobcfg[i].min)
			tp->wminj[i] = 1;
	}

	QUEUE_INIT(&tp->reqdone_queue);

	tp->pending_queue = je_calloc(n_cfgs, sizeof(QUEUE));
	if (!tp->pending_queue)
		goto _err_exit;
	for (size_t i = 0; i < n_cfgs; i++) {
		QUEUE_INIT(tp->pending_queue + i);
	}
	tp->loop = loop;
	uv_async_init(loop, &tp->async, exec_async);
	tp->async.data = tp;
	tp->sched_repeat = 0;

	pthread_mutex_init(&tp->pending_queue_lock, NULL);
	pthread_mutex_init(&tp->reqdone_queue_lock, NULL);
	pthread_mutex_init(&tp->sched_lock, NULL);

	log_debug(lg, "Create new TP size %lu, total %lu", tp->size,
		g_total_size);
	return tp;

_err_exit:
	tp->term = CCOWTP_TERM_FINISH;
	if (tp->wh && !tp->wh_shared)
		ccowtp_destroy_wh(tp->wh);

	if (tp->pending_queue)
		je_free(tp->pending_queue);

	je_free(tp);
	return NULL;
}

struct ccowtp*
ccowtp_create(uv_loop_t* loop, struct ccowtp_job_config* cfg,
	size_t n_cfgs, size_t pool_size) {
	return ccowtp_create_internal(loop, cfg, n_cfgs, pool_size, NULL);
}

struct ccowtp*
ccowtp_create_shared(uv_loop_t* loop, struct ccowtp_job_config* cfg,
	size_t n_cfgs, struct ccowtp_wh* ext_heap) {
	return ccowtp_create_internal(loop, cfg, n_cfgs, 0, ext_heap);
}

static void
ccowtp_sched_safe(struct ccowtp* tp, int no_wait);

int
ccowtp_work_queue(struct ccowtp* tp, int prio, ccowtp_work_cb work_cb,
	ccowtp_after_work_cb after_work_cb, void* arg) {

	if (prio >= tp->n_jobs)
		return -ENOENT;

	if (tp->term)
		return -ENODEV;

	struct ccowtp_je* e = je_calloc(1, sizeof(*e));
	if (!e)
		return -ENOMEM;
	e->after_work = after_work_cb;
	e->work = work_cb;
	e->cfg = tp->jobcfg + prio;
	e->tp = tp;
	e->arg = arg;
	e->prio = prio;
	e->full_latency = get_timestamp_us();
	QUEUE_INIT(&e->item);
	pthread_mutex_lock(&tp->pending_queue_lock);
	QUEUE_INSERT_TAIL(tp->pending_queue + prio, &e->item);
	pthread_mutex_unlock(&tp->pending_queue_lock);
	atomic_inc64(tp->stat.pending + prio);
	atomic_inc64(&tp->total_pending);
	atomic_inc64(&tp->stat.submited);
	ccowtp_sched_safe(tp, 0);
	return 0;
}


/* Proportional job distributor with workers reservation and a resiliency factor
 *
 * struct ccowtp_job_config::weight is relative job weight expressed in %.
 *	The sum of all weights of all jobs must not exceed 100%. Maximum number
 *	of worker spawn for a job Np = weight*100/total_workers (if resiliency is 0)
 *
 * struct ccowtp_job_config::min is a worker reservation value, % from the weight.
 *      Nr = Np*min/100. The distributor will keep Nr number of workers free
 *      unless number of running working for this job type exceed Nr. Example:
 *      Nr=3 and 1 worker is executing. In this case 2 workers are ready for
 *      immediate start if new job request is scheduled.
 *
 * struct ccowtp_job_config::resiliency worker resiliency factor. It it's non-zero,
 *      then number of spawned job may exceed the job weight. Nr = Np + Nres;
 *      Nres = weight*pending_queue_size*resiliency/100000 That is, than more
 *      entries are waiting in the pending queue, than more workers
 *      will be allocated for the job type.
 */
static void
ccowtp_distribute(struct ccowtp* tp, uint64_t max_jobs, uint64_t* dist_row) {

	uint64_t total = tp->size;
	uint64_t* pqs = tp->stat.pending;
	uint64_t* bqs = tp->stat.busy;
	int64_t wres[CCOWTP_JOBTYPE_MAX];
	/*
	 * Estimate resiliency factor and reserve workers
	 * according to min. field in the configuration.
	 */
	for (size_t i = 0 ; i < tp->n_jobs; i++) {
		wres[i] = tp->jobcfg[i].weight*pqs[i]*tp->jobcfg[i].resiliency/100000L;
		dist_row[i] = 0;
		if (tp->wminj[i] && tp->wminj[i] > bqs[i]) {
			uint64_t t = tp->wminj[i] - bqs[i];
			if (max_jobs > t)
				max_jobs -= t;
			else {
				t = max_jobs;
				max_jobs = 0;
			}
			if (pqs[i]) {
				dist_row[i] = t < pqs[i] ? t : pqs[i];
			}
		}
	}
	/* Calculate number of workers per job con sidering resiliency */
	for (int i = 0 ; i < tp->n_jobs && max_jobs; i++) {
		uint64_t n = 0;
		int64_t lt = i == 0 ? 0 : ((wres[i] - wres[i-1])/2);
		int64_t rt = i == tp->n_jobs - 1 ? 0 : ((wres[i] - wres[i+1])/2);
		n = tp->wabs[i] + lt + rt;
		if (n <= bqs[i])
			n = 0;
		else {
			n -= bqs[i];
			if (n > pqs[i])
				n = pqs[i];
			if (n >= max_jobs) {
				n = max_jobs;
				max_jobs = 0;
			} else {
				max_jobs -= n;
			}
		}
		dist_row[i] = n > dist_row[i] ? n : dist_row[i];
	}
}

static void
ccowtp_sched(struct ccowtp* tp) {
	uint64_t dist_row[CCOWTP_JOBTYPE_MAX] = {0};
	uint64_t max_jobs = tp->wh->idle_len;
	/* Distribute pending jobs among free workers */
	ccowtp_distribute(tp, max_jobs, dist_row);
#if 0
	printf("#PRIO\t#BUSY\t#PEND\t#DIST\n");
	for (size_t i = 0 ; i < tp->n_jobs; i++) {
		printf("[%lu]\t%lu\t%lu\t%lu\n", i, tp->busy_queue_size[i],
			tp->pending_queue_size[i], dist_row[i]);
	}
#endif
	uint64_t new_jobs_total = 0;
	for (size_t i = 0; i < tp->n_jobs; i++)
		new_jobs_total += dist_row[i];
	assert(new_jobs_total <= max_jobs);
	/* Transfer jobs to workers */
	size_t pos = 0;
	for (size_t i = 0 ; i < tp->n_jobs; i++) {
		assert(dist_row[i] <= tp->stat.pending[i]);
		for (size_t j = 0; j < dist_row[i]; j++) {
			/* Getting a free worker */
			QUEUE *q = NULL;
			struct ccowpt_worker_priv* w = NULL;
			if(!QUEUE_EMPTY(&tp->wh->idle_queue)) {
				pthread_mutex_lock(&tp->wh->lock);
				q = QUEUE_HEAD(&tp->wh->idle_queue);
				QUEUE_REMOVE(q);
				atomic_dec64(&tp->wh->idle_len);
				pthread_mutex_unlock(&tp->wh->lock);
				w = QUEUE_DATA(q, struct ccowpt_worker_priv, item);
			}
			if (!w) {
				if (tp->wh_shared)
					return;
				else
					assert(0);
			}
			assert(w->ref_cnt == 1);
			atomic_dec64(&w->ref_cnt);
			q = NULL;
			pthread_mutex_lock(&tp->pending_queue_lock);
			if (!QUEUE_EMPTY(tp->pending_queue + i)) {
				q = QUEUE_HEAD(tp->pending_queue + i);
				QUEUE_REMOVE(q);
			}
			pthread_mutex_unlock(&tp->pending_queue_lock);
			/* The queue can be emptied by ccowtp_stop() call */
			if (!q) {
				pthread_mutex_lock(&tp->wh->lock);
				QUEUE_INIT(&w->item);
				QUEUE_INSERT_TAIL(&tp->wh->idle_queue, &w->item);
				atomic_inc64(&tp->wh->idle_len);
				pthread_mutex_unlock(&tp->wh->lock);
				break;
			}
			struct ccowtp_je *e = QUEUE_DATA(q, struct ccowtp_je, item);
			assert(e);
			int prio = e->prio;
			w->je = e;
			atomic_dec64(&tp->total_pending);
			atomic_inc64(&tp->total_busy);
			atomic_inc64(&tp->stat.dequed);
			atomic_dec64(tp->stat.pending + prio);
			atomic_inc64(tp->stat.busy + prio);
			uint64_t tmp = atomic_get_uint64(tp->stat.busy + prio);
			if (tp->stat.busy_max[prio] < tmp)
				tp->stat.busy_max[prio] = tmp;
			uint64_t state = 0;
			e->prop_latency = get_timestamp_us();
			pthread_mutex_lock(&w->lock);
			state = w->state;
			if (state == CCOWTPW_TERM) {
				pthread_mutex_unlock(&w->lock);
				break;
			}
			w->state = CCOWTPW_BUSY;
			pthread_cond_signal(&w->cond);
			pthread_mutex_unlock(&w->lock);
			assert(state == CCOWTPW_IDLE);
		}
	}
}


static void
ccowtp_sched_safe(struct ccowtp* tp, int no_wait) {
	if (tp->term > CCOWTP_TERM_WAIT)
		return;
	/*
	 *  Postpone the scheduler call if it's busy now
	 */
	if (no_wait) {
		/* No wait if called from inside of uv_loop's thread.
		 * Just increment repeat counter so that the blocking thread
		 * can repeat the scheduler call.
		 */
		int rc = pthread_mutex_trylock(&tp->sched_lock);
		if (rc) {
			atomic_inc64(&tp->sched_repeat);
			return;
		}
	} else
		pthread_mutex_lock(&tp->sched_lock);
	do {
		ccowtp_sched(tp);
		if (tp->sched_repeat)
			atomic_dec64(&tp->sched_repeat);
	} while (tp->sched_repeat);
	pthread_mutex_unlock(&tp->sched_lock);
}

static void
exec_async(uv_async_t* handle, int status) {
	struct ccowtp* tp = handle->data;
	if (!tp)
		return;

	if (tp->term == CCOWTP_TERM_FINISH) {
		handle->data = NULL;
		uv_close((uv_handle_t*)handle, NULL);
		return;
	}
	/* Execute done callback and free finished requests */
	while (!QUEUE_EMPTY(&tp->reqdone_queue)) {
		pthread_mutex_lock(&tp->reqdone_queue_lock);
		QUEUE* q = QUEUE_TAIL(&tp->reqdone_queue);
		QUEUE_REMOVE(q);
		pthread_mutex_unlock(&tp->reqdone_queue_lock);
		struct ccowtp_je *e = QUEUE_DATA(q, struct ccowtp_je, item);
		if (e->after_work) {
			if (e->work == ccowtp_cancel_cb)
				e->after_work(e->arg, -EINTR);
			else
				e->after_work(e->arg, 0);
		}

		if (e->prop_latency > tp->stat.prop_latency_max)
			tp->stat.prop_latency_max = e->prop_latency;
		tp->stat.prop_latency_avg = avg_ring_update_limited(
			&tp->prop_latency_ring, e->prop_latency, 0);

		if (e->full_latency > tp->stat.full_latency_max)
			tp->stat.full_latency_max = e->full_latency;

		tp->stat.full_latency_avg = avg_ring_update_limited(
			&tp->full_latency_ring, e->full_latency, 0);

		je_free(e);
		atomic_inc64(&tp->stat.freed);
	}
	ccowtp_sched_safe(tp, 1);
}

int
ccowtp_cancel(struct ccowtp* tp, void* arg) {
	struct ccowtp_je *e = NULL;
	for (size_t i = 0 ; i < tp->n_jobs; i++) {
		pthread_mutex_lock(&tp->pending_queue_lock);
		QUEUE *q = NULL;
		QUEUE_FOREACH(q, tp->pending_queue + i) {
			e = QUEUE_DATA(q, struct ccowtp_je, item);
			if (e->arg == arg) {
				e->work = ccowtp_cancel_cb;
				break;
			} else
				e = NULL;
		}
		pthread_mutex_unlock(&tp->pending_queue_lock);
		if (e)
			break;
	}
	return e ? 0 : -ENOENT;
}

void
ccowtp_stop(struct ccowtp* tp, int wait_done) {
	if (!tp->term) {
		tp->term = wait_done ? CCOWTP_TERM_WAIT : CCOWTP_TERM_CANCEL;
		uint64_t rq_empty = 0;
		if (wait_done) {
			do {
				usleep(100);
				pthread_mutex_lock(&tp->reqdone_queue_lock);
				rq_empty = QUEUE_EMPTY(&tp->reqdone_queue);
				pthread_mutex_unlock(&tp->reqdone_queue_lock);
			} while(atomic_get_uint64(&tp->total_busy) ||
				atomic_get_uint64(&tp->total_pending) ||
				!rq_empty);
		} else {
			/* Empty the pending queue */
			QUEUE *q = NULL;
			pthread_mutex_lock(&tp->pending_queue_lock);
			for (size_t i = 0 ; i < tp->n_jobs; i++) {
				while (!QUEUE_EMPTY(tp->pending_queue + i)) {
					q = QUEUE_HEAD(tp->pending_queue + i);
					QUEUE_REMOVE(q);
					QUEUE_INIT(q);
					struct ccowtp_je *e = QUEUE_DATA(q, struct ccowtp_je, item);
					je_free(e);
				}
			}
			pthread_mutex_unlock(&tp->pending_queue_lock);
			/* Wait until all the being processed requests are finished */
			do {
				usleep(100);
				pthread_mutex_lock(&tp->reqdone_queue_lock);
				rq_empty = QUEUE_EMPTY(&tp->reqdone_queue);
				pthread_mutex_unlock(&tp->reqdone_queue_lock);
			} while(atomic_get_uint64(&tp->total_busy) || !rq_empty);
		}
		usleep(100000);
		tp->term = CCOWTP_TERM_FINISH;
		ccowtp_async_send(tp);
		log_debug(lg, "Stopped a thread pool, total threads in all "
			"pools %lu", g_total_size);
	}
}

void
ccowtp_free(struct ccowtp* tp) {
	if (!tp->wh_shared)
		ccowtp_destroy_wh(tp->wh);

	if (tp->pending_queue)
		je_free(tp->pending_queue);
	je_free(tp);
}

void
ccowtp_stat(struct ccowtp* tp, struct ccowtp_stat* stat) {
	for (size_t i = 0; i < tp->n_jobs; i++) {
		tp->stat.busy_ratio[i] =
			tp->stat.busy[i] * 100 / tp->wabs[i];
		tp->stat.busy_max_ratio[i] =
			tp->stat.busy_max[i] *100 / tp->wabs[i];
	}
	*stat = tp->stat;
}

uint64_t
ccowtp_pending(struct ccowtp* tp) {
	return tp->total_pending;
}
