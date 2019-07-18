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
#include "ccowutil.h"
#include "queue.h"
#include "reptrans.h"
#include "ccow.h"
#include "erasure-coding.h"
#include "reptrans_bg_sched.h"
#include "ccowd-impl.h"
#include "probes.h"

static uint64_t
bg_timestamp_ms(struct repdev* dev) {
	return uv_now(dev->loop);
}

static const char* bg_job_name[] = {
		"BG_INCOMING_BATCH",
		"BG_VERIFICATION",
		"BG_REPLICATION",
		"BG_SPACE_RECLAIM",
		"BG_GARBAGE_COLLECTOR",
		"BG_SCRUB",
		"BG_EC_ENCODER",
		"BG_TRANSACTION_LOGGER",
		"BG_GW_CACHE",
		"BG_ROWUSAGE",
		"BG_INVALID"
};

static int
bg_job_index(struct bg_job_entry* job);

static void
bg_trace_done(struct bg_job_entry* job) {
	int index = bg_job_index(job);
	switch (index) {
	case BG_INCOMING_BATCH:
		if (BG_DONE_IBATCH_ENABLED())
			DTRACE_PROBE8 (bg, done_ibatch, job->sched->dev->name,
				job->job_duration, job->chunk_counter,
				job->counter[0].counter, job->counter[1].counter,
				job->counter[2].counter, job->counter[3].counter,
				job->counter[4].counter);
	break;
	case BG_VERIFICATION:
		if (BG_DONE_VERIFICATION_ENABLED())
			DTRACE_PROBE8 (bg, done_verification, job->sched->dev->name,
				job->job_duration, job->chunk_counter,
				job->counter[0].counter, job->counter[1].counter,
				job->counter[2].counter, job->counter[3].counter,
				job->counter[4].counter);
	break;
	case BG_REPLICATION:
		if (BG_DONE_REPLICATION_ENABLED())
			DTRACE_PROBE8 (bg, done_replication, job->sched->dev->name,
				job->job_duration, job->chunk_counter,
				job->counter[0].counter, job->counter[1].counter,
				job->counter[2].counter, job->counter[3].counter,
				job->counter[4].counter);
	break;
	case BG_SPACE_RECLAIM:
		if (BG_DONE_SR_ENABLED())
			DTRACE_PROBE8 (bg, done_sr, job->sched->dev->name,
				job->job_duration, job->chunk_counter,
				job->counter[0].counter, job->counter[1].counter,
				job->counter[2].counter, job->counter[3].counter,
				job->counter[4].counter);
	break;
	case BG_GARBAGE_COLLECTOR:
		if (BG_DONE_GC_ENABLED())
			DTRACE_PROBE8 (bg, done_gc, job->sched->dev->name,
				job->job_duration, job->chunk_counter,
				job->counter[0].counter, job->counter[1].counter,
				job->counter[2].counter, job->counter[3].counter,
				job->counter[4].counter);
	break;
	case BG_SCRUB:
		if (BG_DONE_SCRUB_ENABLED())
			DTRACE_PROBE8 (bg, done_scrub, job->sched->dev->name,
				job->job_duration, job->chunk_counter,
				job->counter[0].counter, job->counter[1].counter,
				job->counter[2].counter, job->counter[3].counter,
				job->counter[4].counter);
	break;
	case BG_EC_ENCODER:
		if (BG_DONE_ECENC_ENABLED())
			DTRACE_PROBE8 (bg, done_ecenc, job->sched->dev->name,
				job->job_duration, job->chunk_counter,
				job->counter[0].counter, job->counter[1].counter,
				job->counter[2].counter, job->counter[3].counter,
				job->counter[4].counter);
	break;
	default:
		break;
	}
}


void
bg_set_default_config (struct repdev_bg_config* cfg) {
	cfg->backref_verify_timer_ms = DEV_BACKREF_VERIFY_TIMER_MS;
	cfg->backref_verify_start_ms = DEV_BACKREF_VERIFY_START_TIMER_MS;
	cfg->verify_priority = VERIFY_PRIORITY;
	cfg->verify_exlusive = VERIFY_EXCLUSIVE;
	cfg->incoming_batch_timer_ms = DEV_INCOMING_BATCH_TIMER_MS;
	cfg->incoming_batch_start_ms = DEV_INCOMING_BATCH_START_TIMER_MS;
	cfg->incoming_batch_priority = INCOMING_BATCH_PRIORITY;
	cfg->incoming_batch_exclusive = INCOMING_BATCH_EXCLUSIVE;
	cfg->space_reclaim_timer_ms = DEV_SPACE_RECLAIM_TIMER_MS;
	cfg->space_reclaim_start_ms = DEV_SPACE_RECLAIM_START_TIMER_MS;
	cfg->space_reclaim_priority = SPACE_RECLAIM_PRIORITY;
	cfg->space_reclaim_exclusive = SPACE_RECLAIM_EXCLUSIVE;
	cfg->replication_timer_ms = DEV_REPLICATION_TIMER_MS;
	cfg->replication_start_ms = DEV_REPLICATION_START_TIMER_MS;
	cfg->replication_priority = REPLICATION_PRIORITY;
	cfg->replication_exclusive = REPLICATION_EXCLUSIVE;
	cfg->gc_timer_ms = DEV_GC_TIMER_MS;
	cfg->gc_start_ms = DEV_GC_START_TIMER_MS;
	cfg->gc_exclusive = GC_EXCLUSIVE;
	cfg->gc_priority = GC_PRIORITY;
	cfg->speculative_backref_timeout = SPECULATIVE_BACKREF_TIMEOUT;
	cfg->speculative_backref_timeout_min = SPECULATIVE_BACKREF_TIMEOUT;
	cfg->version_quarantine_timeout = VERSION_QUARANTINE_TIMEOUT;
	cfg->dev_utilization_threshold_low = DEV_UTILIZATION_THRESHOLD_LOW;
	cfg->dev_utilization_threshold_high = DEV_UTILIZATION_THRESHOLD_HIGH;
	cfg->dev_capacity_limit = REPDEV_CAPACITY_LIMIT;
	cfg->dev_capacity_max_data = REPDEV_CAPACITY_MAX_DATA;
	cfg->dev_capacity_max_full = REPDEV_CAPACITY_MAX_FULL;
	cfg->scrub_timer_ms = DEV_SCRUB_TIMER_MS;
	cfg->scrub_start_ms = DEV_SCRUB_START_TIMER_MS;
	cfg->scrub_priority = SCRUB_PRIORITY;
	cfg->scrub_exclusive = SCRUB_EXCLUSIVE;
	cfg->ec_encoder_timer_ms = DEV_EC_ENCODER_TIMER_MS;
	cfg->ec_encoder_start_ms = DEV_EC_ENCODER_START_TIMER_MS;
	cfg->ec_encoder_priority = EC_ENCODER_PRIORITY;
	cfg->ec_encoder_exclusive = EC_ENCODER_EXCLUSIVE;
	cfg->trlog_start_ms = DEV_TRLOG_START_TIMER_MS;
	cfg->trlog_delete_after_hours = TRLOG_DELETE_AFTER_HOURS;
	cfg->gw_cache_start_ms = DEV_GW_CACHE_START_TIMER_MS;
	cfg->gw_cache_timer_ms = DEV_GW_CACHE_TIMER_MS;
	cfg->gw_cache_exclusive = GW_CACHE_EXCLUSIVE;
	strcpy(cfg->scrubber_log_name, "scrubber");
	cfg->compact_on_boot = COMPACTIFY_ON_BOOT;
	cfg->flush_threshold_timeout = FLUSH_TIMEOUT_THRESHOLD;
	cfg->tenant_pool_sz = REPDEV_DEFAULT_POOL_SZ;
	cfg->gw_cache_hw_mark = DEV_GW_CACHE_HW_MARK;
	cfg->gw_cache_lw_mark = DEV_GW_CACHE_LW_MARK;
	cfg->gw_cache_chids_in_mem = DEV_GW_CACHE_CHIDS_IN_MEM;
	cfg->rowusage_start_ms = DEV_ROWUSAGE_START_TIMER_MS;
	cfg->rowusage_timer_ms = DEV_ROWUSAGE_TIMER_MS;
	cfg->rowusage_exclusive = DEV_ROWUSAGE_EXCLUSIVE;
	cfg->thread_pool_size = REPTRANS_VDEV_THREAD_POOL_SIZE;
	cfg->tenant_thread_pool_size = REPDEV_TC_TP_DEFAULT_SZ;
	cfg->tp_low_weight = DEV_TP_LOW_WEIGHT;
	cfg->tp_low_reserved = DEV_TP_LOW_RESERVED;
	cfg->tp_low_resiliency = DEV_TP_LOW_RESILIENCY;
	cfg->tp_mid_weight = DEV_TP_MID_WEIGHT;
	cfg->tp_mid_reserved = DEV_TP_MID_RESERVED;
	cfg->tp_mid_resiliency = DEV_TP_MID_RESILIENCY;
	cfg->tp_hi_weight = DEV_TP_HI_WEIGHT;
	cfg->tp_hi_reserved = DEV_TP_HI_RESERVED;
	cfg->tp_hi_resiliency =DEV_TP_HI_WEIGHT;
	cfg->elru_hits_count = DEV_ELRU_HIT_COUNTER;
	cfg->elru_touch_ratio = DEV_ELRU_TOUCH_RATIO;
}

#define FOREACH_BG(sched, job) \
	struct bg_job_entry* job; \
	size_t job_iter_##job; \
	for (job_iter_##job = 0, job=(sched)->jobs[0]; job; \
		++job_iter_##job < BG_TOTAL ? \
		(job=(sched)->jobs[job_iter_##job]) : (job = NULL))

static void
reptrans_bg_schedule(struct bg_sched* sched, struct bg_job_entry* done_job);

/**
 * Get job index within schduler's jobs list
 * internal
 */
static int
bg_job_index(struct bg_job_entry* job) {
	 FOREACH_BG(job->sched, _job) {
		 if (_job == job) {
			 return job_iter__job;
		 }
	 }
	 return -1;
}

/**
 * Send a command to job
 * @param entry is a pointer to job-related data
 * @param cmd - command to be sent to the job
 */
static void
bg_job_send_cmd(struct bg_job_entry* entry, bg_cmd_t cmd) {
	uv_mutex_lock(&entry->cmd_mutex);
	entry->cmd = cmd;
	uv_cond_signal(&entry->cond);
	uv_mutex_unlock(&entry->cmd_mutex);
}

/**
 *
 * Check if scheduler has been terminated
 * @param sched pointer to a shceduler instance
 * @returns 1 if terminated, 0 otherwise
 */
int
bg_sched_is_terminated(struct bg_sched* sched) {
	FOREACH_BG(sched, job) {
		if (job->status != BG_STATUS_STOPPED) {
			return 0;
		}
	}
	return 1;
}

int bg_job_is_term_forced(struct bg_job_entry* entry) {
	return entry->cmd == BG_CMD_TERM;
}

static int
bg_job_handle_cmd(struct bg_job_entry* job, bg_cmd_t cmd);

static void
bg_job_activate(struct bg_sched* sched, bg_job_t jid);

static void
bg_job_preempt_trg__async(struct repdev_call *c) {
	struct bg_job_entry* entry = (struct bg_job_entry*)c->args[0];
	struct bg_sched* sched = entry->sched;
	struct bg_job_entry* new_entry = NULL;
	struct repdev* dev = sched->dev;
	uint64_t dt_best = 0;
	int jid = 0;
	assert(sched);
	repdev_status_t status = reptrans_dev_get_status(dev);
	if (sched->suspended || status == REPDEV_STATUS_UNAVAILABLE) {
		return;
	}

	/* Looking for a job which can preempt current */
	uint64_t now = bg_timestamp_ms(sched->dev);
	FOREACH_BG(sched, job) {
		if (entry == job)
			continue;
		if (job->priority == entry->priority && (job->exclusive || entry->exclusive)
			&& job->scheduled_at <= now) {
			new_entry = job;
			jid = job_iter_job;
			break;
		}
	}
	if (new_entry) {
		log_debug(lg, "Dev(%s) %s -> %s preempted", dev->path,
			bg_job_name[(bg_job_index(entry))], bg_job_name[jid]);
		bg_job_handle_cmd(entry, BG_CMD_PREEMPT);
		entry->scheduled_at = bg_timestamp_ms(sched->dev) + BG_PREEMPTION_TIME;
		bg_job_activate(sched, jid);
	} else {
		log_debug(lg, "Dev(%s) %s preempting job not found", dev->path,
			bg_job_name[(bg_job_index(entry))]);
	}
}

int
bg_job_preempt_trg(struct bg_job_entry* entr) {
	if (entr) {
		struct repdev_call	*call =
			je_calloc(1, sizeof(struct repdev_call));
		if (call == NULL) {
			return -ENOMEM;
		}
		call->method = bg_job_preempt_trg__async;
		call->args[0] = (void*)entr;
		QUEUE_INIT(&call->item);
		uv_mutex_lock(&entr->sched->dev->call_mutex);
		QUEUE_INSERT_TAIL(&entr->sched->dev->call_queue, &call->item);
		uv_mutex_unlock(&entr->sched->dev->call_mutex);
		uv_async_send(&entr->sched->dev->call_async);
		log_debug(lg, "Dev(%s) %s preemption triggered", entr->sched->dev->path,
			bg_job_name[(bg_job_index(entr))]);
	}
	return 0;
}

void
bg_replicast_delay(struct repdev* dev, uint32_t delay_max, struct bg_job_entry* entry) {
	uint64_t sleep_time = 0;
	if (entry)
		sleep_time = bg_timestamp_ms(dev);
	reptrans_replicast_delay(dev, delay_max);
	if (entry)
		entry->job_sleep_duration +=  bg_timestamp_ms(dev) - sleep_time;
}

void
bg_has_slept_ms(uint32_t delay, struct bg_job_entry* entry) {
	entry->job_sleep_duration += delay;
}
/**
 * Waits until job get will be forced out of PAUSE state
 *
 * @param entry pointer to a job entry
 *
 * Has to be called by each BG job at beginning of iteration
 * Returns 1 if job has been terminated while waiting, 0 otherwise
 */

int bg_job_wait_resume_internal(struct bg_job_entry* entry, uint64_t delay_max,
	const char* file, int line) {
	struct repdev* dev = entry->sched->dev;
	uv_mutex_lock(&entry->cmd_mutex);
	uint64_t iter_duration = bg_timestamp_ms(dev) - entry->started_at;
	entry->nopreempt_duration += iter_duration;
	if (iter_duration > 30000) {
		log_warn(lg, "Dev(%s) %s iteration took %lu mS", dev->path,
			bg_job_name[(bg_job_index(entry))], iter_duration);
	}
	entry->job_duration += bg_timestamp_ms(dev) - entry->started_at;
	if (entry->priority != BG_PRIO_RT && entry->nopreempt_duration > BG_PREEMPTION_TIME) {
		bg_job_preempt_trg(entry);
		entry->nopreempt_duration = 0;
	}
	while (!dev->terminating && (entry->cmd == BG_CMD_PAUSE || entry->cmd == BG_CMD_PREEMPT)) {
		uv_cond_timedwait(&entry->cond, &entry->cmd_mutex, 1000000000UL);
	}
	uv_mutex_unlock(&entry->cmd_mutex);
	int rc =  dev->terminating ||
		entry->cmd == BG_CMD_TERM ||
		entry->cmd == BG_CMD_ABORT ||
		reptrans_replicast_delay_internal(entry->sched->dev, delay_max,
			file, line);
	entry->started_at = bg_timestamp_ms(dev);
	return rc;
}

/**
 * Destroy an job instance
 * Internal
 */
static void
bg_job_destroy(struct bg_job_entry* job) {
	job->status = BG_STATUS_STOPPED;
	/*
	 * The last terminated BG stops the timer
	 */
	if (bg_sched_is_terminated(job->sched) && job->sched->timer.data) {
		job->sched->timer.data = NULL;
		uv_timer_stop(&job->sched->timer);
		uv_close((uv_handle_t*)&job->sched->timer, NULL);
	}
}
/*
 * Called by UV worker done
 * Internal
 */
static void
bg_done(void* arg, int status) {
	struct bg_job_entry* job = (struct bg_job_entry*) arg;

	uint64_t now = bg_timestamp_ms(job->sched->dev);
	job->work_done(job, job->data);
	if (job->interval > 0)
		job->scheduled_at = now + job->interval;
	else
		job->scheduled_at = ~0UL;
	job->status = BG_STATUS_DONE;
	job->job_duration += now - job->started_at;
	job->total_duration += job->job_duration;
	bg_trace_done(job);
	log_info(lg, "Dev(%s) %s DONE in %lu mS, sleep time %lu mS, chunks: %lu, mS/chunk: %.2f",
			job->sched->dev->path, bg_job_name[bg_job_index(job)],
			job->job_duration, job->job_sleep_duration, job->chunk_counter,
			job->chunk_counter ?
			(double)job->job_duration/job->chunk_counter : 0.0);
	for (size_t n = 0 ; n < job->n_counters; n++) {
		log_info(lg, "Dev(%s) %s %s: %lu", job->sched->dev->path,
				bg_job_name[bg_job_index(job)],
				job->counter[n].id, job->counter[n].counter);
	}
	if (job->cmd != BG_CMD_TERM)
		reptrans_bg_schedule(job->sched, job);
	else {
		bg_job_destroy(job);
	}
}
/*
 * BJ job's worker wrapper
 * internal
 */
static void
bg_work(void* arg) {
	struct bg_job_entry* job = (struct bg_job_entry*) arg;
	job->job_duration = 0;
	job->job_sleep_duration = 0;
	job->started_at = bg_timestamp_ms(job->sched->dev);
	job->chunk_counter = 0;
	job->nopreempt_duration = 0;
	job->work(job, job->data);
}
/*
 * Send a command to a job
 * @param job pointer to a job-related data
 * @param cmd command to be sent
 * @return 0 if success, error code otherwise
 */
static int
bg_job_handle_cmd(struct bg_job_entry* job, bg_cmd_t cmd) {
	int stale = 0;
	switch (cmd) {
	case BG_CMD_START:
		SERVER_FLEXHASH_SAFE_CALL(stale = flexhash_is_stale(SERVER_FLEXHASH), FH_LOCK_READ);
		if (stale) {
			log_debug(lg, "Dev(%s): couldn't start BG job %s: flexhash is stale",
			    job->sched->dev->path, bg_job_name[bg_job_index(job)]);
			return -ENODEV;
		}
		if (job->status == BG_STATUS_DONE) {
			int rc = job->init(job, &job->data);
			if (rc) {
				log_error(lg,
					"Dev(%s): couldn't init %s job: %d",
					job->sched->dev->path,
					bg_job_name[bg_job_index(job)], rc);
				return rc;
			}
			job->started_at =  bg_timestamp_ms(job->sched->dev);
			job->handle = job;
			/* high priority thread pool (competes w/ front I/O reads/writes) */
			if (strcmp(bg_job_name[bg_job_index(job)], "BG_TRANSACTION_LOGGER") == 0 ||
			    strcmp(bg_job_name[bg_job_index(job)], "BG_INCOMING_BATCH") == 0)
				rc = ccowtp_work_queue(job->sched->dev->tp, REPTRANS_TP_PRIO_HI,
				    bg_work, bg_done, job->handle);
			/* normal priority thread pool (competes w/ front I/O writes) */
			else if (strcmp(bg_job_name[bg_job_index(job)], "BG_VERIFICATION") == 0)
				rc = ccowtp_work_queue(job->sched->dev->tp, REPTRANS_TP_PRIO_MID,
				    bg_work, bg_done, job->handle);
			/* low priority thread pool */
			else
				rc = ccowtp_work_queue(job->sched->dev->tp, REPTRANS_TP_PRIO_LOW,
				    bg_work, bg_done, job->handle);
			if (rc) {
				log_error(lg,
					"Dev(%s): couldn't spawn %s job: %d",
					job->sched->dev->path,
					bg_job_name[bg_job_index(job)], rc);
				return rc;
			}
			job->cmd = cmd;
			job->status = BG_STATUS_PROGRESS;
			log_info(lg, "Dev(%s) %s STARTED",job->sched->dev->path,
					bg_job_name[bg_job_index(job)]);

		}
		break;

	case BG_CMD_TERM:
		/* Basically has to be handled by worker */
		if (job->status == BG_STATUS_PROGRESS ||
				job->status == BG_STATUS_PAUSED ||
				job->status == BG_STATUS_PREEMPTED) {

			bg_job_send_cmd(job, BG_CMD_TERM);
			job->status = BG_STATUS_TERMINATION;
			log_info(lg, "Dev(%s) %s TERM",job->sched->dev->path,
					bg_job_name[bg_job_index(job)]);

		} else {
			bg_job_destroy(job);
		}
		break;


	case BG_CMD_ABORT:
		/* Signall current job to terminate its execution  */
		if (job->status == BG_STATUS_PROGRESS ||
				job->status == BG_STATUS_PAUSED ||
				job->status == BG_STATUS_PREEMPTED) {

			bg_job_send_cmd(job, BG_CMD_ABORT);
			log_info(lg, "Dev(%s) %s ABORT",job->sched->dev->path,
					bg_job_name[bg_job_index(job)]);

		}
		break;

	case BG_CMD_PAUSE:
		/*
		 * To handle pause properly the BG worker has to call
		 * bg_job_wait_resume() at the beginning of each iteration
		 */
		if (job->status == BG_STATUS_PROGRESS) {
			bg_job_send_cmd(job, BG_CMD_PAUSE);
			job->status = BG_STATUS_PAUSED;
			log_info(lg, "Dev(%s) %s PAUSED",job->sched->dev->path,
					bg_job_name[bg_job_index(job)]);

		}
		break;

	case BG_CMD_PREEMPT:
		/*
		 * To handle preemption properly the BG worker has to call
		 * bg_job_wait_resume() at the beginning of each iteration
		 */
		if (job->status == BG_STATUS_PROGRESS) {
			bg_job_send_cmd(job, BG_CMD_PREEMPT);
			job->status = BG_STATUS_PREEMPTED;
			log_info(lg, "Dev(%s) %s PREEMPTED",job->sched->dev->path,
					bg_job_name[bg_job_index(job)]);

		}
		break;

	case BG_CMD_RESUME:
		if (job->status == BG_STATUS_PAUSED ||
			job->status == BG_STATUS_PREEMPTED) {
			bg_job_send_cmd(job, BG_CMD_RESUME);
			job->status = BG_STATUS_PROGRESS;
			log_info(lg, "Dev(%s) %s RESUMED",job->sched->dev->path,
					bg_job_name[bg_job_index(job)]);
		} else {
			log_debug(lg, "Dev(%s) cannot RESUME BG with status %d",
				job->sched->dev->path, job->status);
			return -ENOEXEC;
		}
		break;

	default:
		break;
	}
	return 0;
}
/**
 * Suspend low priority jobs
 *
 * @param sched pointer to a scheduler
 * @param prio BG jobs which have smaller priority than the @param
 * 		  have to be paused
 */
static void
bg_pause_low_prio(struct bg_sched* sched, int prio, int new_jid) {
	FOREACH_BG(sched, job) {
		if (job->priority != BG_PRIO_RT && job->priority < prio
			&& (job->status == BG_STATUS_PROGRESS)) {
			bg_job_handle_cmd(job, BG_CMD_PAUSE);
		}
	}
}
/**
 * Get the first job which is in progress
 * internal
 */
static struct bg_job_entry*
bg_get_active(struct bg_sched* sched, int prio) {
	FOREACH_BG(sched, job) {
		if (job->priority == prio &&
		job->status == BG_STATUS_PROGRESS)
			return job;
	}
	return NULL;
}
/**
 * Activate BG job, e.g. start if it was stopped
 * or resume if it was paused.
 * internal
 */
static void
bg_job_activate(struct bg_sched* sched, bg_job_t jid) {
	struct bg_job_entry* job = sched->jobs[jid];
	switch (job->status) {
		case BG_STATUS_DONE:
			bg_job_handle_cmd(job, BG_CMD_START);
			break;

		case BG_STATUS_PAUSED:
		case BG_STATUS_PREEMPTED:
			bg_job_handle_cmd(job, BG_CMD_RESUME);
			break;

		default:
			break;
	}
}
/**
 * The schduler's timer callback function
 * internal
 */
static void
reptrans_bg_timer_callback (uv_timer_t* handle, int status) {
	struct bg_sched* sched = (struct bg_sched*)handle->data;
	assert(sched);
	reptrans_bg_schedule(sched, NULL);
}
/**
 * Schedule and start next BG job(s)
 * internal
 */
static void
reptrans_bg_schedule(struct bg_sched* sched, struct bg_job_entry* done_job) {

	bg_job_t jids[BG_TOTAL] = {0};
	size_t job_count = 0;
	int j_prio = 0;
	struct repdev *dev = sched->dev;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (sched->suspended || status == REPDEV_STATUS_UNAVAILABLE) {
		return;
	}
	uv_timer_stop(&sched->timer);
	uint64_t now = bg_timestamp_ms(sched->dev);
	/*
	 * Look for pending job with highest priority
	 * this can be finished, paused or running job
	 */
	FOREACH_BG(sched, job) {
		if (job->status == BG_STATUS_DONE
			|| job->status == BG_STATUS_PAUSED
			|| job->status == BG_STATUS_PROGRESS
			|| job->status == BG_STATUS_PREEMPTED) {
			if (job->scheduled_at <= now) {
				int n = job_iter_job;
				if (job->priority == BG_PRIO_RT) {
					bg_job_activate(sched, n);
				} else {
					if (job->priority > j_prio) {
						job_count = 1;
						jids[0] = n;
						j_prio = job->priority;
					} else if (job->priority == j_prio) {
						jids[job_count++] = n;
					}
				}
			}
		}
	}

	uint64_t earliest = now;
	if (job_count > 0) {
		if (job_count == 1) {
			/* stop low priority tasks if any */
			bg_pause_low_prio(sched, j_prio, jids[0]);
			/*
			 * If there is a job with highest prio in progress,
			 * then it's definitely the one we just found
			 */
			bg_job_activate(sched, jids[0]);
		} else {
			/* Have multiple items, calc resulting policy */
			uint8_t exclusive = 0;
			bg_job_t latest_jid = -1;
			/*
			 * Exclusive mode requires only one job to be run at a time.
			 * Run the job exclusively if at least one flag is set
			 * The exclusive job will be the one with the latest time point
			 */
			for (size_t i = 0; i < job_count; i++) {
				exclusive |= sched->jobs[jids[i]]->exclusive;
				int64_t dt = now - sched->jobs[jids[i]]->scheduled_at;
				log_debug(lg, "Dev(%s) JOB[%lu] %s dT=%ld, earliest dT %ld",
					dev->name, i, bg_job_name[jids[i]], dt, now - earliest);
				if (sched->jobs[jids[i]]->scheduled_at <= earliest) {
					earliest = sched->jobs[jids[i]]->scheduled_at;
					latest_jid = jids[i];
				}
			}
			assert(latest_jid != (uint32_t)-1);
			bg_pause_low_prio(sched, j_prio, latest_jid);
			if (exclusive) {
				if (!bg_get_active(sched, j_prio))
					bg_job_activate(sched, latest_jid);
			} else {
				/*
				 * In a cooperative (non-exclusive) mode run
				 * simultaneously all pending jobs of highest priority
				 */
				for (size_t i = 0; i < job_count; i++) {
					bg_job_activate(sched, jids[i]);
				}
			}
		}
	}
	/*
	 * look for a job in the nearest future
	 * and charge the timer
	 */
	earliest = 0;
	FOREACH_BG(sched, _job) {
		if (_job->scheduled_at != ~0UL && _job->scheduled_at > now) {
			if (!earliest) {
				earliest = _job->scheduled_at;
			}
			else if (_job->scheduled_at <= earliest) {
				earliest = _job->scheduled_at;
			}
		}
	}

	if (earliest > now) {
		uv_timer_start(&sched->timer, reptrans_bg_timer_callback,
				earliest - now, 0);
	}
}

static void
bg_force_job__async(struct repdev_call *c) {
	struct bg_sched* sched = (struct bg_sched*)c->args[0];
	bg_job_t jid = (bg_job_t)c->args[1];
	assert(sched);
	sched->jobs[jid]->scheduled_at = bg_timestamp_ms(sched->dev);
	reptrans_bg_schedule(sched, NULL);
}

bg_status_t
bg_get_job_status(struct bg_sched* sched, bg_job_t jid) {
	return sched->jobs[jid]->status;
}

int
bg_force_job(struct bg_sched* sched, bg_job_t jid) {
	if (sched) {
		struct repdev_call	*call =
			je_calloc(1, sizeof(struct repdev_call));
		if (call == NULL) {
			return -ENOMEM;
		}
		call->method = bg_force_job__async;
		call->args[0] = sched;
		call->args[1] = (void *)jid;
		QUEUE_INIT(&call->item);
		uv_mutex_lock(&sched->dev->call_mutex);
		QUEUE_INSERT_TAIL(&sched->dev->call_queue, &call->item);
		uv_mutex_unlock(&sched->dev->call_mutex);
		uv_async_send(&sched->dev->call_async);
	}
	return 0;
}

static void
bg_sched_suspend__async(struct repdev_call *c) {
	struct bg_sched* sched = (struct bg_sched*)c->args[0];
	long suspend = (long)c->args[1];
	if (sched->suspended && !suspend) {
		FOREACH_BG(sched, _job) {
			bg_job_handle_cmd(_job, BG_CMD_RESUME);
		}
		sched->suspended = 0;
		log_info(lg, "Dev(%s) BG jobs RESUMED", sched->dev->path);
		reptrans_bg_schedule(sched, NULL);
	} else if (!sched->suspended && suspend) {
		sched->suspended = 1;
		log_info(lg, "Dev(%s) BG jobs SUSPENDED", sched->dev->path);
		FOREACH_BG(sched, _job) {
			bg_job_handle_cmd(_job, BG_CMD_PAUSE);
		}
		reptrans_bg_schedule(sched, NULL);
	}
}
/**
 * Suspend execution of all background jobs
 * @param sched pointe to a scheduler
 * @param suspend suspend (1) or resume (0) BG jobs
 *
 */
int
bg_sched_suspend(struct bg_sched* sched,
		uint8_t suspend) {
	if (sched && !sched->dev->terminating) {
		struct repdev_call	*call =
			je_calloc(1, sizeof(struct repdev_call));
		if (call == NULL) {
			return -ENOMEM;
		}
		call->method = bg_sched_suspend__async;
		call->args[0] = sched;
		call->args[1] = (void *)(long)suspend;
		QUEUE_INIT(&call->item);
		uv_mutex_lock(&sched->dev->call_mutex);
		QUEUE_INSERT_TAIL(&sched->dev->call_queue, &call->item);
		uv_mutex_unlock(&sched->dev->call_mutex);
		uv_async_send(&sched->dev->call_async);
	}
	return 0;
}

static void
bg_set_job_prio__async(struct repdev_call *c) {
	struct bg_sched* sched = (struct bg_sched*)c->args[0];
	bg_job_t jid = (bg_job_t)c->args[1];
	int prio = (uint64_t)c->args[2];
	sched->jobs[jid]->priority = prio;
}


int
bg_set_job_prio(struct bg_sched* sched, bg_job_t jid, int prio) {
	if (sched) {
		struct repdev_call	*call =
			je_calloc(1, sizeof(struct repdev_call));
		if (call == NULL) {
			return -ENOMEM;
		}
		call->method = bg_set_job_prio__async;
		call->args[0] = sched;
		call->args[1] = (void *)jid;
		call->args[2] = (void *)((uint64_t)prio);
		QUEUE_INIT(&call->item);
		uv_mutex_lock(&sched->dev->call_mutex);
		QUEUE_INSERT_TAIL(&sched->dev->call_queue, &call->item);
		uv_mutex_unlock(&sched->dev->call_mutex);
		uv_async_send(&sched->dev->call_async);
	}
	return 0;
}

int
bg_get_job_prio(struct bg_sched* sched, bg_job_t jid) {
	return sched->jobs[jid]->priority;
}

/**
 * Set value of a generic counter
 *
 * @param job  job pointer
 * @param counter value of the counter
 * @param index counter index
 *
 */
void
bg_sched_set_counter(struct bg_job_entry* job, int64_t counter,
	size_t index) {
	assert(job);
	assert(index < job->n_counters);

	job->counter[index].delta = counter -
		job->counter[index].counter;
	job->counter[index].counter = counter;
}

/**
 * Register generic counters attached to the BG job
 *
 * @param job pointer to a BG-related data
 * @param n_counters number of counters to be used
 * @param names array of counter names to be displayed in log
 */
void
bg_sched_register_counters(struct bg_job_entry* job, size_t n_counters,
	const char** names) {
	assert(job);
	assert(n_counters <= BG_MAX_COUNTERS);

	if (job->n_counters)
		return;

	for (size_t i = 0; i < n_counters; i++) {
		job->counter[i].id = names[i];
	}
	job->n_counters = n_counters;
}

/**
 * Register a BG job in shcduler
 * @param sched pointer to a background jobs scheduler
 * @param job pointer to a job entry, has to allocated dynamically by caller
 * @jid BG job id
 * @returns 0 if success, -1 if the job has been already registered
 */
int
bg_sched_register_job(struct bg_sched* sched, struct bg_job_entry* job,
	bg_job_t jid) {

	if (sched->jobs[jid]) {
		log_error(lg, "Dev(%s) BG sched: job %s already registered",
			sched->dev->path, bg_job_name[jid]);
		return -1;
	}

	job->sched = sched;
	job->cmd = BG_CMD_NONE;
	job->status = BG_STATUS_DONE;
	if (job->start > 0) {
		uint64_t now = bg_timestamp_ms(sched->dev);
		job->scheduled_at = now + job->start;
		job->scheduled_at += (rand() % job->start)/5;
	}
	else {
		job->scheduled_at = ~0UL;
	}
	job->data = NULL;
	uv_cond_init(&job->cond);
	uv_mutex_init(&job->cmd_mutex);
	sched->jobs[jid] = job;
	return 0;
}

/**
 * Allocate instance of BG jobs shceduler
 *
 * @param dev pointer to a repdev device new scheduler will be attached to
 * @returns new sheduler data pointer
 */
struct bg_sched*
bg_sched_create(struct repdev* dev) {
	struct bg_sched* sched = je_calloc(1, sizeof(struct bg_sched));
	sched->dev = dev;
	uv_timer_init(dev->loop, &sched->timer);
	sched->timer.data = sched;
	return sched;
}

/**
 *
 * Start a sheduler
 *
 * @param sched pointer to a scheduler
 * @returns 0 if success, error code if the scheduler hasn't been
 *		    initialized properly
 */
int
bg_sched_start(struct bg_sched* sched) {
	FOREACH_BG(sched, job) {
		if (!job) {
			return -EFAULT;
		}
	}
	log_info(lg, "Dev(%s) starting BG", sched->dev->path);
	sched->timestamp = bg_timestamp_ms(sched->dev);
	reptrans_bg_schedule(sched, NULL);
	return 0;
}

/**
 * Send termination command to a BG scheduler and its jobs
 *
 * @param sched pointer to a scheduler
 */
void
bg_sched_terminate(struct bg_sched* sched) {
	FOREACH_BG(sched, job) {
		bg_job_handle_cmd(job, BG_CMD_TERM);
	}
}

/**
 * Destroy a scheduler which was stopped before
 */
void
bg_sched_destroy(struct bg_sched* sched) {
	if (bg_sched_is_terminated(sched)) {
		uint64_t total = bg_timestamp_ms(sched->dev) - sched->timestamp;
		FOREACH_BG(sched, job) {
			log_info(lg, "Dev(%s) %s took %.3f s, rate: %.3f",
				sched->dev->path, bg_job_name[bg_job_index(job)],
				job->total_duration/1000.0,
				job->total_duration/(double)total);
			if (job->state)
				je_free(job->state);
			je_free(job);
		}
	}
}

/**
 * free a scheduler which was stopped and destroyed before
 */
void
bg_sched_destroy_finished(struct bg_sched* sched) {
	   je_free(sched);
}

int
bg_get_job_progress(struct bg_sched* sched, bg_job_t jid)
{
	double rc = -1;
	struct bg_job_entry* e = sched->jobs[jid];
	if (e->progress)
		rc = e->progress(e);
	else if (e->status == BG_STATUS_PROGRESS ||
		e->status == BG_STATUS_PAUSED ||
		e->status == BG_STATUS_PREEMPTED)
			rc = 1000;
	return rc;
}

int
bg_job_restart(struct bg_sched* sched, bg_job_t jid)
{
	struct repdev* dev = sched->dev;
	struct bg_job_entry* e = sched->jobs[jid];
	if (e->status == BG_STATUS_PROGRESS ||
		e->status == BG_STATUS_PAUSED ||
		e->status == BG_STATUS_PREEMPTED)
	{
		bg_job_send_cmd(e, BG_CMD_ABORT);
		size_t cnt = 120;
		while (e->status != BG_STATUS_DONE && --cnt)
			usleep(1000000);
		if (!cnt) {
			log_warn(lg, "Dev(%s) cound't terminate BG job %s",
				dev->name, bg_job_name[jid]);
			return -EBUSY;
		}
		log_info(lg, "Dev(%s) BG job %s aborted", dev->name,
			bg_job_name[jid]);
	}
	return bg_force_job(sched, jid);
}
