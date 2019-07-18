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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>

#include "cmocka.h"
#include "ccowutil.h"
#include "ccowtp.h"
#include "queue.h"

void uv_print_all_handles(uv_loop_t* loop);

Logger lg;

struct loop_ctx {
	uv_loop_t* loop;
	int term;
	pthread_t thr;
	struct ccowtp* tp;
};

struct ccowtp_arg1 {
	uint64_t n_cbs;
	uint64_t n_after_cbs;
};

static void*
ccowtp_test_loop_thread(void* arg) {
	struct loop_ctx* ctx = arg;
	struct sched_param params = {.__sched_priority = 1 };
	pthread_setschedparam(pthread_self(), SCHED_RR, &params);
	uv_run(ctx->loop, UV_RUN_DEFAULT);
	uv_loop_delete(ctx->loop);
	return NULL;
}

static struct loop_ctx*
test_create_loop() {
	struct loop_ctx* ctx = je_calloc(1, sizeof(*ctx));
	assert_non_null(ctx);
	ctx->loop = uv_loop_new();
	return ctx;
}

static void
test_start_loop(struct loop_ctx* ctx) {
	pthread_create(&ctx->thr, NULL, ccowtp_test_loop_thread, ctx);
}

static void
test_stop_loop(struct loop_ctx* ctx) {
	ctx->term = 1;
	pthread_join(ctx->thr, NULL);
}

static void
ccowtp_test1_work_cb(void* arg) {
	struct ccowtp_arg1* p = arg;
	atomic_inc64(&p->n_cbs);
	usleep(random() % 10000);

}
static void ccowtp_test1_after_work_cb(void* arg, int status) {
	struct ccowtp_arg1* p = arg;
	atomic_inc64(&p->n_after_cbs);
}


static void
ccowtp_start_wait_done_test() {
	size_t iters = 100;
	struct ccowtp_job_config cfg = {
		.sched = SCHED_FIFO,
		.prio = 1,
		.weight = 100,
		.min = 1
	};
	struct ccowtp_arg1 arg = {0, 0};
	struct loop_ctx* ctx = test_create_loop();
	assert_non_null(ctx);
	ctx->tp = ccowtp_create(ctx->loop, &cfg, 1, 2);
	assert_non_null(ctx->tp);
	test_start_loop(ctx);
	for (size_t i = 0; i < iters; i++) {
		ccowtp_work_queue(ctx->tp, 0, ccowtp_test1_work_cb,
			ccowtp_test1_after_work_cb, &arg);
	}
	struct ccowtp_stat tpstat;
	ccowtp_stop(ctx->tp, 1);
	ccowtp_stat(ctx->tp, &tpstat);
	assert_int_equal(tpstat.submited, iters);
	assert_int_equal(tpstat.dequed, iters);
	assert_int_equal(tpstat.finished, iters);
	assert_int_equal(tpstat.freed, iters);
	assert_int_equal(arg.n_after_cbs, iters);
	assert_int_equal(arg.n_cbs, iters);
	test_stop_loop(ctx);
	ccowtp_free(ctx->tp);
	je_free(ctx);
}

static void
ccowtp_start_stop_test() {
	size_t iters = 1000;
	struct ccowtp_job_config cfg = {
		.sched = SCHED_FIFO,
		.prio = 1,
		.weight = 100,
		.min = 1
	};
	struct ccowtp_arg1 arg = {0, 0};
	struct loop_ctx* ctx = test_create_loop();
	assert_non_null(ctx);
	ctx->tp = ccowtp_create(ctx->loop, &cfg, 1, 2);
	assert_non_null(ctx->tp);
	test_start_loop(ctx);
	for (size_t i = 0; i < iters; i++) {
		ccowtp_work_queue(ctx->tp, 0, ccowtp_test1_work_cb,
			ccowtp_test1_after_work_cb, &arg);
	}
	struct ccowtp_stat tpstat;
	sleep(1);
	ccowtp_stop(ctx->tp, 0);
	ccowtp_stat(ctx->tp, &tpstat);
	assert_int_equal(tpstat.submited, iters);
	assert_true(tpstat.dequed > 0);
	assert_true(tpstat.finished > 0);
	assert_true(tpstat.freed > 0);
	assert_true(tpstat.dequed < iters);
	assert_true(tpstat.finished < iters);
	assert_true(tpstat.freed < iters);
	assert_true(arg.n_cbs > 0);
	assert_true(arg.n_cbs < iters);
	assert_true(arg.n_after_cbs > 0);
	assert_true(arg.n_after_cbs < iters);

	test_stop_loop(ctx);
	ccowtp_free(ctx->tp);
	je_free(ctx);
}

struct ccowtp_latency_arg {
	uint64_t latency_cb;
	uint64_t latency_after_cb;
	uint64_t ts;
	uint64_t ts_done;
};

static void
ccowtp_latency_work_cb(void* arg) {
	struct ccowtp_latency_arg* p = arg;
	p->latency_cb = get_realtime_ns() - p->ts;
}

static void ccowtp_latency_after_work_cb(void* arg, int status) {
	struct ccowtp_latency_arg* p = arg;
	p->ts_done = get_realtime_ns();
	p->latency_after_cb =  p->ts_done - p->ts;
}


static void
ccowtp_latency_test() {
	size_t iters = 100000;
	struct ccowtp_job_config cfg = {
		.sched = SCHED_RR,
		.prio = 1,
		.weight = 100,
		.min = 1
	};
	struct ccowtp_latency_arg* arg = je_calloc(iters, sizeof(struct ccowtp_latency_arg));
	assert_non_null(arg);
	struct loop_ctx* ctx = test_create_loop();
	assert_non_null(ctx);
	ctx->tp = ccowtp_create(ctx->loop, &cfg, 1, 384);
	assert_non_null(ctx->tp);
	test_start_loop(ctx);
	uint64_t submit_avg = 0, submit_max = 0, submit_min = 1000000000000;
	for (size_t i = 0; i < iters; i++) {
		arg[i].ts = get_realtime_ns();
		ccowtp_work_queue(ctx->tp, 0, ccowtp_latency_work_cb,
			ccowtp_latency_after_work_cb, arg + i);
		uint64_t dur = get_realtime_ns() - arg[i].ts;
		submit_avg += dur;
		if (dur > submit_max)
			submit_max = dur;
		if (dur < submit_min)
			submit_min = dur;
	}
	struct ccowtp_stat tpstat;
	ccowtp_stop(ctx->tp, 1);
	ccowtp_stat(ctx->tp, &tpstat);
	assert_int_equal(tpstat.submited, iters);
	uint64_t latency_min = 10000000000000000;
	uint64_t latency_max = 0;
	uint64_t latency_avg = 0;
	for (size_t i = 0; i < iters; i++) {
		if (arg[i].latency_cb < latency_min)
			latency_min = arg[i].latency_cb;
		if (arg[i].latency_cb > latency_max)
			latency_max = arg[i].latency_cb;
		latency_avg += arg[i].latency_cb;
	}
	latency_avg /= iters;
	printf("Prop latency avg (native) %lu/%lu uS\n", tpstat.prop_latency_avg, tpstat.prop_latency_max);
	printf("Propagation latency min/avg/max: %lu/%lu/%lu nS\n", latency_min, latency_avg, latency_max);
	printf("Submit duration min/avg/max: %lu/%lu/%lu nS\n", submit_min, submit_avg/iters, submit_max);
	printf("Test duration %lu uS\n", (arg[iters-1].ts_done - arg[0].ts)/1000UL);

	test_stop_loop(ctx);
	ccowtp_free(ctx->tp);
	je_free(ctx);
	je_free(arg);
}

static void
uv_latency_work_cb(uv_work_t* w) {
	struct ccowtp_latency_arg* p = w->data;
	p->latency_cb = get_realtime_ns() - p->ts;

}
static void uv_latency_after_work_cb(uv_work_t* w, int status) {
	struct ccowtp_latency_arg* p = w->data;
	p->ts_done = get_realtime_ns();
	p->latency_after_cb =  p->ts_done - p->ts;
	je_free(w);
}

static void
uv_workers_latency_test() {
	size_t iters = 100000;
	uv_async_t at;
	struct ccowtp_latency_arg* arg = je_calloc(iters, sizeof(struct ccowtp_latency_arg));
	assert_non_null(arg);
	struct loop_ctx* ctx = test_create_loop();
	assert_non_null(ctx);
	uv_async_init(ctx->loop, &at, NULL);
	test_start_loop(ctx);
	uint64_t submit_avg = 0, submit_max = 0, submit_min = 1000000000000;
	for (size_t i = 0; i < iters; i++) {
		uv_work_t* wr = je_malloc(sizeof(*wr));
		wr->data =arg + i;
		arg[i].ts = get_realtime_ns();
		uv_queue_work(ctx->loop, wr, uv_latency_work_cb,
			uv_latency_after_work_cb);
		uint64_t dur = get_realtime_ns() - arg[i].ts;
		submit_avg += dur;
		if (dur > submit_max)
			submit_max = dur;
		if (dur < submit_min)
			submit_min = dur;
	}
	sleep(1);
	uv_close((uv_handle_t*)&at, NULL);
	uint64_t latency_min = 10000000000000000;
	uint64_t latency_max = 0;
	uint64_t latency_avg = 0;
	for (size_t i = 0; i < iters; i++) {
		if (arg[i].latency_cb < latency_min)
			latency_min = arg[i].latency_cb;
		if (arg[i].latency_cb > latency_max)
			latency_max = arg[i].latency_cb;
		latency_avg += arg[i].latency_cb;
	}
	latency_avg /= iters;
	printf("Propagation latency min/avg/max: %lu/%lu/%lu nS\n", latency_min, latency_avg, latency_max);
	printf("Submit duration min/avg/max: %lu/%lu/%lu nS\n", submit_min, submit_avg/iters, submit_max);
	printf("Test duration %lu uS\n", (arg[iters-1].ts_done - arg[0].ts)/1000UL);
	je_free(ctx);
	je_free(arg);
}
static void
ccowtp_test1() {
	size_t iters = 30000;
	struct ccowtp_job_config cfg[] = {
		{
			.sched = SCHED_FIFO,
			.prio = 1,
			.weight = 60,
			.min = 10,
			.resiliency = 1000
		},
		{
			.sched = SCHED_FIFO,
			.prio = 1,
			.weight = 30,
			.min = 20,
			.resiliency = 100
		},
		{
			.sched = SCHED_FIFO,
			.prio = 1,
			.weight = 10,
			.min = 20,
			.resiliency = 100
		}
	};
	for (size_t delay_max = 3; delay_max < 30000; delay_max *= 10) {
		printf("Testing delay_max %lu\n", delay_max);
		struct loop_ctx* ctx = test_create_loop();
		assert_non_null(ctx);

		ctx->tp = ccowtp_create(ctx->loop, cfg, 3, 20);
		assert_non_null(ctx->tp);

		test_start_loop(ctx);
		struct ccowtp_arg1 arg = {0, 0};
		for (size_t i = 0; i < iters; i++) {
			int prio = i % 10;
			prio = prio < 6 ? 0 : prio < 9 ? 1 : 2;
			ccowtp_work_queue(ctx->tp, prio, ccowtp_test1_work_cb,
				ccowtp_test1_after_work_cb, &arg);
			usleep(random() % delay_max);
		}
		ccowtp_stop(ctx->tp, 1);
		test_stop_loop(ctx);
		ccowtp_free(ctx->tp);
		je_free(ctx);
	}
}

struct test_item {
	QUEUE item;
	int index;
};

static void
ccowtp_cancel_test() {
	size_t iters = 100;
	struct ccowtp_job_config cfg = {
		.sched = SCHED_RR,
		.prio = 1,
		.weight = 100,
		.min = 1
	};
	struct ccowtp_latency_arg* arg = je_calloc(iters, sizeof(struct ccowtp_latency_arg));
	assert_non_null(arg);
	struct loop_ctx* ctx = test_create_loop();
	assert_non_null(ctx);
	ctx->tp = ccowtp_create(ctx->loop, &cfg, 1, 2);
	assert_non_null(ctx->tp);
	test_start_loop(ctx);
	for (size_t i = 0; i < iters; i++) {
		arg[i].ts = get_realtime_ns();
		ccowtp_work_queue(ctx->tp, 0, ccowtp_latency_work_cb,
			ccowtp_latency_after_work_cb, arg + i);
		if (i % 2 == 0) {
			int err = ccowtp_cancel(ctx->tp, arg + i);
			assert_true(err == 0 || err == -2);
		}
	}
	ccowtp_stop(ctx->tp, 1);
	test_stop_loop(ctx);
	ccowtp_free(ctx->tp);
	je_free(ctx);
	je_free(arg);
}

static void
ccowtp_shared_test() {
	size_t iters = 30000;
	size_t n_tps = 5;
	struct ccowtp_job_config cfg[] = {
		{
			.sched = SCHED_FIFO,
			.prio = 1,
			.weight = 100/n_tps,
			.min = 0,
			.resiliency = 0
		},
		{
			.sched = SCHED_FIFO,
			.prio = 1,
			.weight = 50,
			.min = 10,
			.resiliency = 500
		},
		{
			.sched = SCHED_FIFO,
			.prio = 1,
			.weight = 100,
			.min = 10
		},

	};
	for (size_t k = 0; k < sizeof(cfg)/sizeof(cfg[0]); k++) {
	for (size_t delay_max = 3; delay_max < 30000; delay_max *= 10) {
		struct ccowtp_stat tpstat[n_tps];
		printf("Testing delay_max %lu\n", delay_max);
		struct loop_ctx* ctx[n_tps];
		struct ccowtp_wh* shared_tp = ccowtp_create_wh(100);
		assert_non_null(shared_tp);
		for (size_t n = 0; n < n_tps; n++) {
			ctx[n] = test_create_loop();
			assert_non_null(ctx[n]);
			ctx[n]->tp = ccowtp_create_shared(ctx[n]->loop, cfg + k, 1, shared_tp);
			assert_non_null(ctx[n]->tp);
			test_start_loop(ctx[n]);
		}

		struct ccowtp_arg1 arg = {0, 0};
		for (size_t i = 0; i < iters; i++) {
			ccowtp_work_queue(ctx[i % n_tps]->tp, 0, ccowtp_test1_work_cb,
				ccowtp_test1_after_work_cb, &arg);
			usleep(random() % delay_max);
		}
		uint64_t submited_total = 0;
		uint64_t queued_total = 0;
		uint64_t finished_total = 0;
		uint64_t freed_total = 0;
		for (size_t n = 0; n < n_tps; n++) {
			ccowtp_stop(ctx[n]->tp, 1);
			ccowtp_stat(ctx[n]->tp, tpstat + n);
			submited_total += tpstat[n].submited;
			queued_total += tpstat[n].dequed;
			finished_total += tpstat[n].finished;
			freed_total += tpstat[n].freed;
			assert_int_equal(tpstat[n].submited, tpstat[n].dequed);
			assert_int_equal(tpstat[n].submited, tpstat[n].finished);
			assert_int_equal(tpstat[n].submited, tpstat[n].freed);
			test_stop_loop(ctx[n]);
			ccowtp_free(ctx[n]->tp);
		}
		assert_int_equal(submited_total, iters);
		assert_int_equal(queued_total, iters);
		assert_int_equal(finished_total, iters);
		assert_int_equal(freed_total, iters);
		for (size_t n = 0; n < n_tps; n++)
			je_free(ctx[n]);
		ccowtp_destroy_wh(shared_tp);
	}
	}
}

int
main(int argc, char **argv)
{
	lg =  Logger_create("ccowtp_log.txt");

	const UnitTest tests[] = {
		unit_test(ccowtp_cancel_test),
		unit_test(ccowtp_latency_test),
		unit_test(uv_workers_latency_test),
		unit_test(ccowtp_start_wait_done_test),
		unit_test(ccowtp_start_stop_test),
		unit_test(ccowtp_test1),
		unit_test(ccowtp_shared_test)
	};

	return run_tests(tests);
}
