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
/*
 * reptrans_bg_job.h
 *
 *  Created on: Jan 25, 2016
 *      Author: root
 */

#ifndef SRC_LIBREPTRANS_REPTRANS_BG_SCHED_H_
#define SRC_LIBREPTRANS_REPTRANS_BG_SCHED_H_
#include <uv.h>

/*
 * An implementation of priority-based background job scheduler.
 * The scheduler creates a jobs sequence according to their priority and
 * timing parameters defined in ccowd.json and rt-lfs.json.
 * Each job has own priority in range 0..BG_TOTAL-1. Highest value means
 * highest priority. The higher priority job(s) preempts one(s) with lower priority.
 * They goes to PAUSE state and will be resumed as soon as high priority job(s) exit.
 * The job of equal priority can be executed simultaneously (flag "exlusive" == 0)
 * or sequentially (flag "exlusive" == 1).
 * An execution order is defined by *start_ms values, an interval
 * is calculated according to *timer_ms values.
 * All the API functions have to be called in a per-device thread context,
 * except bg_job_wait_resume() which is thread-safe.
 **/

typedef enum {
	BG_INCOMING_BATCH,
	BG_VERIFICATION,
	BG_REPLICATION,
	BG_SPACE_RECLAIM,
	BG_GARBAGE_COLLECTOR,
	BG_SCRUB,
	BG_EC_ENCODER,
	BG_TRANSACTION_LOGGER,
	BG_GW_CACHE,
	BG_ROWUSAGE,
	BG_TOTAL
} bg_job_t;

typedef enum {
	BG_STATUS_NONE, /* Not initialized */
	BG_STATUS_PROGRESS, /* active, running */
	BG_STATUS_PAUSED,   /* active, paused */
	BG_STATUS_PREEMPTED,   /* active, preempted */
	BG_STATUS_DONE,     /* inactive, ready for start */
	BG_STATUS_TERMINATION, /* termination requested, in progress */
	BG_STATUS_STOPPED /* de-initialized */
} bg_status_t;

typedef enum {
	BG_CMD_NONE,
	BG_CMD_START,
	BG_CMD_PAUSE,
	BG_CMD_RESUME,
	BG_CMD_PREEMPT,
	BG_CMD_TERM,
	BG_CMD_ABORT /* Abort current job */
} bg_cmd_t;

struct bg_job_entry;
struct bg_sched;

typedef int	(*bg_init_t) (struct bg_job_entry*, void**);
typedef void	(*bg_work_t) (struct bg_job_entry*, void*);
typedef int	(*bg_progress_t)(struct bg_job_entry*);

#define BG_MAX_COUNTERS		5
#define BG_PRIO_RT		-1 /* The highest priority jobs */

struct bg_counter {
	const char* id;
	int64_t	 counter;
	int64_t  delta;
};

struct bg_sched {
	struct bg_job_entry* jobs[BG_TOTAL];/* BG jobs list*/
	uv_timer_t	timer; /* BG scheduler timer */
	struct repdev* dev;
	uint64_t timestamp;
	uint8_t  suspended; /* suspended from outside */
};

struct bg_job_entry {
	/* Following have to be filled up BG job creation code */
	int64_t		start;	/* initial start delay */
	int64_t		interval; /* BG execution interval */
	int8_t		priority; /* BG job priority, 0 .. BG_TOTAL-1 or -1 for RT */
	uint8_t		exclusive; /* BG job request exclusive execution */

	/* BG job must provide 3 operations */
	bg_init_t	init; /* BG init, called before starting worker */
	bg_work_t	work; /*The job worker (main function)*/
	bg_work_t	work_done; /* worker done callback */
	bg_progress_t	progress; /* Worker execution progress, %*10 */

	/* BG internal */
	uint64_t	scheduled_at; /* next execution time point */
	struct bg_sched* sched; /* scheduler */
	bg_cmd_t	cmd; /* latest accepted command */
	bg_status_t status; /* job status */
	void*		data; /* worker private data */
	void*		handle; /* worker's handle */
	uv_cond_t	cond; /* condver used to signal "cmd sent" */
	uv_mutex_t	cmd_mutex;
	uint64_t nopreempt_duration; /* Duration of a run without preemption */

	/* Generic counters/data support*/
	struct bg_counter counter[BG_MAX_COUNTERS];
	uint16_t n_counters;

	/* time measurement */
	uint64_t started_at; /* timestamp of the iteration  start */
	uint64_t job_duration; /* Full cycle (job) duration (including sleeps) */
	volatile uint64_t job_sleep_duration; /* Sleep time */
	uint64_t total_duration; /* total job duration */
	uint64_t chunk_counter; /* per-cycle chunk counter */
	uint64_t chunks_total; /* Number of chunks to be iterated */
	void* state; /* Pointer to an optional job state data */
};

void
bg_replicast_delay(struct repdev* dev, uint32_t delay_max, struct bg_job_entry* entry);

void
bg_has_slept_ms(uint32_t delay, struct bg_job_entry* entry);

void
bg_set_default_config (struct repdev_bg_config* cfg);

int
bg_job_wait_resume_internal(struct bg_job_entry* entry, uint64_t max_delay_us,
	const char* file, int line);

#define bg_job_wait_resume(entry, delay) (bg_job_wait_resume_internal((entry), \
	(delay),  __FILE__,__LINE__))

void
bg_sched_set_counter(struct bg_job_entry* job, int64_t counter, size_t index);

void
bg_sched_register_counters(struct bg_job_entry* job, size_t n_counters,
	const char** names);
void
bg_sched_destroy(struct bg_sched* sched);

void
bg_sched_destroy_finished(struct bg_sched* sched);

void
bg_sched_terminate(struct bg_sched* sched);

int
bg_sched_start(struct bg_sched* sched);

struct bg_sched*
bg_sched_create(struct repdev* dev);

int
bg_sched_register_job(struct bg_sched* sched, struct bg_job_entry* job,
	bg_job_t jid);

int
bg_sched_suspend(struct bg_sched* sched, uint8_t suspend);

int
bg_force_job(struct bg_sched* sched, bg_job_t jid);

int
bg_job_is_term_forced(struct bg_job_entry* entry);

int
bg_sched_is_terminated(struct bg_sched* sched);

int
bg_set_job_prio(struct bg_sched* sched, bg_job_t jid, int prio);

int
bg_get_job_prio(struct bg_sched* sched, bg_job_t jid);

bg_status_t
bg_get_job_status(struct bg_sched* sched, bg_job_t jid);

int
bg_get_job_progress(struct bg_sched* sched, bg_job_t jid);

int
bg_job_restart(struct bg_sched* sched, bg_job_t jid);


#endif /* SRC_LIBREPTRANS_REPTRANS_BG_SCHED_H_ */
