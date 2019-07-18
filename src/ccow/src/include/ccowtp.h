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

#ifndef SRC_INCLUDE_CCOWTP_H_
#define SRC_INCLUDE_CCOWTP_H_

#include <uv.h>
#define CCOWTP_JOBTYPE_MAX	16

struct ccowtp;
struct ccowtp_wh;

typedef void (*ccowtp_work_cb)(void* arg);
typedef void (*ccowtp_after_work_cb)(void* arg, int status);

struct ccowtp_stat {
	uint64_t submited; /* Number of sbumitted jobs */
	uint64_t dequed; /* Number of jobs scheduled for execution */
	uint64_t finished; /* Number of finished jobs */
	uint64_t freed; /* number of freed jobs */
	uint64_t prio_total; /* Number of job types (priorities) current thread pool has */
	uint64_t pending[CCOWTP_JOBTYPE_MAX]; /* Pending queue size per job type */
	uint64_t busy[CCOWTP_JOBTYPE_MAX]; /* Number of worker in progress per job type */
	uint64_t busy_ratio[CCOWTP_JOBTYPE_MAX]; /* Workers utilization per job type */
	uint64_t busy_max[CCOWTP_JOBTYPE_MAX]; /* Maximum number of parallel workers seen */
	uint64_t busy_max_ratio[CCOWTP_JOBTYPE_MAX]; /* Maximum number of parallel workers seen, % */
	uint64_t full_latency_avg; /* Average enqueue to worker latency, us */
	uint64_t full_latency_max; /* Maximum enqueue to worker latency, us */
	uint64_t prop_latency_avg; /* Aerage enqueue to worker latency, us */
	uint64_t prop_latency_max; /* Maximum scheduler to worker latency, us */
};

struct ccowtp_job_config {
	int sched; /* pthread shedulert type */
	int prio;  /* pthread priority */
	int weight; /* worker weight, 0..100% */
	int resiliency; /* worker expansion factor in range 0..999 */
	int min;   /* minimal number of worker reserved for this kind of job, 0..100% */
};

/**
 * Create workers heap.
 * It can be used later to create shared thread pools.
 *
 * @param n number of workers in the heap
 * @return pointer to a new workers heap. Or NULL if failed
 *
 */
struct ccowtp_wh*
ccowtp_create_wh(size_t n);

/**
 * Destroy workers heap
 */
void
ccowtp_destroy_wh(struct ccowtp_wh* wh);

/**
 * Create new thread pool
 *
 * @param loop      libuv's loop
 * @param cfg       pointer to array of job configuration items
 * @param n_cfg     number of job configurations
 * @param pool_size number of threads in the pool
 * @returns         new thread pool's handler
 *
 * Create a new thread pool with a special job distribution.
 * A proportional job distributor with workers reservation and a resiliency factor
 *
 * struct ccowtp_job_config::weight is relative job weight expressed in %.
 *	The sum of all weights of all jobs must not exceed 100%. Maximum number
 *	of worker spawn for a job Np = weight*100/total_workers (if resiliency is 0)
 *
 * struct ccowtp_job_config::min is a worker reservation value, % from the weight.
 *      Nr = Np*min/100. The distributor will keep Nr number of workers free
 *      unless number of running working for this job type exceed Nr. Example:
 *      Nr=3 and 1 worker is executing. In this case 2 workers are ready for
 *      immediate start if new job request is scheduled regardles of its weight
 *
 * struct ccowtp_job_config::resiliency worker resiliency factor. If it's non-zero,
 *      then number of spawned job may exceed the job weight. Nr = Np + Nres;
 *      Nres = weight*pending_queue_size*resiliency/100000 That is, than more
 *      entries are waiting in the pending queue, than more workers
 *      will be allocated for this job type.
 */
struct ccowtp*
ccowtp_create(uv_loop_t* loop, struct ccowtp_job_config* cfg, size_t n_cfgs,
	size_t pool_size);

/**
 * Create new workers thread pool using pre-created workers heap.
 *
 * @param loop      libuv's loop
 * @param cfg       pointer to array of job configuration items
 * @param n_cfg     number of job configurations
 * @param ext_heap  external thread pool pointer
 * @returns         new thread pool's handler
 *
 *
 * The workers can be shared between several thread pools. Similar to libuv's
 * implementation. Can be used to reduce number of workers in a thread pools set.
 * Each of TP in a shared set supposed to have a one job type. If sum of weight
 * of every jobs in each thread pool from a set exceed 100%, then work queue
 * requests will compete for free workers.
 *
 * NOTE: Workers reservation isn't guaranteed.
 *
 */
struct ccowtp*
ccowtp_create_shared(uv_loop_t* loop, struct ccowtp_job_config* cfg,
	size_t n_cfgs, struct ccowtp_wh* ext_heap);
/**
 * Add a new job to the queue
 *
 * @param tp       a thread pool's handle
 * @param prio     a job priority which is an index of an entry in the job configuration array
 * @param work_cb  pointer to a function which will be executed by a worker in an assigned thread
 * @param after_work_cb  pointer to a function called when worker execution is done.
 *        Always performed in libuv's thread context
 * @param arg      worker argument
 * @return 0 on success
 */
int
ccowtp_work_queue(struct ccowtp* tp, int prio, ccowtp_work_cb work_cb,
	ccowtp_after_work_cb after_work_cb, void* arg);

/**
 * Stop the thread pool
 *
 * @param tp a thread pool handle
 * @param wait_done wait for jobs to finish. If set to 0, the the thread pool
 *                  will be stopped when all currently busy workers are done.
 *                  If set to non-zero value, then the function wait until all
 *                  entries in the pending queue are handled.
 */
void
ccowtp_stop(struct ccowtp* tp, int wait_done);

/**
 * Destroy the thread pool
 *
 * @param tp a thread pool handle
 *
 * The thread pool termination sequence should be as follow:
 * 1. Invoke ccowtp_stop(..) in a thread different from libuv event loop one
 * 2. Place ccowtp_free(..) after a function uv_run() in a libuv event loop
 */
void
ccowtp_free(struct ccowtp* tp);

/**
 * Get thread pool statistics
 *
 * @param tp a thread pool handle
 * @param stat[in] pointer to stat structure the callee will fill up
 *
 */
void
ccowtp_stat(struct ccowtp* tp, struct ccowtp_stat* stat);

/**
 * Discard a scheduled job
 *
 * @param tp a thread pool handle
 * @param arg an worker argument. It's used to identify worker
 * @return 0 on success, -ENOENT if request hasn't been found in the pending queue
 *
 * A job can be canceled only if it's in a pending queue.
 * It's impossible to cancels an executing job
 */
int
ccowtp_cancel(struct ccowtp* tp, void* arg);


/**
 * Total number of pending jobs
 *
 */
uint64_t
ccowtp_pending(struct ccowtp* tp);


#endif /* SRC_INCLUDE_CCOWTP_H_ */
