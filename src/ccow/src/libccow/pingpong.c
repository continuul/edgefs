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
#include <uv.h>

#include "ccowutil.h"
#include "flexhash.h"
#include "ccow.h"
#include "ccow-impl.h"

struct pingpong_req {
	CCOW_CLASS_FIELDS
	struct state state;
	fhrow_t rowid;
	struct ccow_network *netobj;
	char *message;
	uint32_t message_size;
	void (*cb)(void *);
	void *cb_data;
};

static int pingpong_create(struct ccow *tc, fhrow_t rowid, char *message,
			   uint32_t size, void (*cb)(void *), void *cb_data);

#define PINGPONG_MAX_RETRY	3
#define PINGPONG_TIMEOUT_MS	500

/*
 * =======================================================================
 *     Default arguments
 * =======================================================================
 */
#define PINGPONG_MSG_SIZE	16384
#define PINGPONG_MEASURE_MAX	10000

struct pingpong_baton {
	volatile int compl;
	volatile uint64_t last_us;
	int max;
	uv_barrier_t b_end;
};

static void
pingpong_ack(void *data)
{
	struct pingpong_baton *btn = data;

	btn->last_us = uv_hrtime();
	if (++btn->compl == btn->max)
		uv_barrier_wait(&btn->b_end);
}

static int
measure_row_rtt(struct ccow *tc, fhrow_t row, uint64_t *rtt)
{
	int err = -ENOMEM;
	uint64_t before;
	uint64_t after;
	char *msg;
	struct pingpong_baton btn;

	msg = je_malloc(PINGPONG_MSG_SIZE);
	if (msg == NULL)
		goto _out;

	memset(&btn, 0, sizeof (btn));
	btn.max = PINGPONG_MEASURE_MAX;

	uv_barrier_init(&btn.b_end, 2);
	before = uv_hrtime();
	for (int i = 0; i < PINGPONG_MEASURE_MAX; i++) {
		err = pingpong_create(tc, row, msg, PINGPONG_MSG_SIZE,
				      pingpong_ack, &btn);
		if (err != 0)
			goto _error;
	}
	uv_barrier_wait(&btn.b_end);
	after = uv_hrtime();
	*rtt =  after - before;

_error:
	je_free(msg);
	uv_barrier_destroy(&btn.b_end);
_out:
	return err;
}

static void
print_raw_results(fhrow_t row, unsigned int bytes_xfer,
		  double trips, double rttime)
{
	printf("Row: %d\n %s stats (async): %.2fs (%lu/s)\nAvg Latency: "
	       "%.2fus @ %d Bytes: %.2fMB/sec\n", row,
	       fmt(trips), rttime, (unsigned long)(trips / rttime),
	       1 / (trips / rttime) * 1e6, PINGPONG_MSG_SIZE,
	       ((double)bytes_xfer) / rttime );
}

#define ROW_BUF_SZ 512

static void
print_json_results(fhrow_t row, unsigned int bytes_xfer,
		  double trips, double rttime, int last)
{
	char buf[ROW_BUF_SZ];

	buf[0] = '\0';
	sprintf(buf, "\t\t{\n"
		"\t\t\t\"rownum\": %d,\n"
		"\t\t\t\"message count\": \"%s\",\n"
		"\t\t\t\"message size\": %d,\n"
		"\t\t\t\"rtt(sec)\": %.2f,\n"
		"\t\t\t\"messages/sec\": %lu,\n"
		"\t\t\t\"avg latency(us)\": %.2f,\n"
		"\t\t\t\"data rate(MB/sec)\": %.2f\n"
		"\t\t}%s\n",
		row, fmt(trips), PINGPONG_MSG_SIZE,
		rttime, (unsigned long)(trips / rttime),
		1 / (trips / rttime) * 1e6,
		((double)bytes_xfer) / rttime, last ? "" : ",");
	json_buf_put(stdout, buf);
}

static void
print_rows_rtt(uint64_t *rtt, fhrow_t maxrows, uint8_t jsonout)
{
	fhrow_t row;
	double  trips = (double)PINGPONG_MEASURE_MAX;
	volatile double  rttime;
	unsigned int bytes_xfer = PINGPONG_MSG_SIZE * PINGPONG_MEASURE_MAX;

	/* Convert to MiBs */
	bytes_xfer >>= 20;

	if (jsonout) {
		json_file_buf_prepare();
		json_buf_put(stdout, "{\n\t\"rows\": [\n");
	}
	for (row = 0; row < maxrows; row++) {
		rttime = rtt[row] / 1e9;
		if(jsonout)
			print_json_results(row, bytes_xfer,trips, rttime,
					   row == maxrows - 1);
		else
			print_raw_results(row, bytes_xfer, trips, rttime);
	}
	if (jsonout) {
		json_buf_put(stdout, "\t]\n}\n");
		json_buf_flush(stdout);
	}
	fflush(stdout);
}

int
ccow_pingpong(struct ccow *tc, uint8_t jsonout)
{
	int err;
	fhrow_t row;
	fhrow_t maxrows;
	uint64_t  *rtt;

	maxrows = flexhash_numrows(tc->flexhash);
	rtt = je_malloc(sizeof(uint64_t) * maxrows);
	if (rtt == NULL)
		return -ENOMEM;

	/* do the pingpong multi-message round-trip measurement */
	for (row = 0; row < maxrows; row++) {
		err = measure_row_rtt(tc, row, &rtt[row]);
		if (err != 0)
			goto _error;
	}
	print_rows_rtt(rtt, maxrows, jsonout);
_error:
	je_free(rtt);
	return err;
}

/*
 * State machine functions;
 */

/*
 * ACTION: unblock caller and report error
 */
static void
pingpong__error(struct state *st) {
	struct pingpong_req *r = st->data;
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
}

/*
 * ACTION: process ack
 */
static void
pingpong__ack(struct state *st)
{
	struct pingpong_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	int err;

	struct repmsg_pingpong_ack *msg =
		(struct repmsg_pingpong_ack *)wqe->msg;

}

static void
pingpong_timeout(uv_timer_t *req, int status)
{
	struct state *st = req->data;
	struct pingpong_req *r = st->data;
	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	req->data = NULL;
	log_warn(lg, "PINGPONG request timeout after %d attempts "
	    "seqid:%d.%d", r->retry + 1, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);
	state_event(st, EV_TIMEOUT);
}

static void
pingpong__send(struct state *st)
{
	int err;
	struct pingpong_req *r = st->data;
	struct ccow_network *netobj = r->netobj;
	int rows;
	fhrow_t rowid;
	struct sockaddr_in6 mcast_addr;

	struct repmsg_pingpong msg;
	memset(&msg, 0, sizeof (msg));
	msg.message_size = r->message_size;
	msg.message = r->message;

	flexhash_get_rowaddr(r->tc->flexhash, r->rowid, &mcast_addr);

	if (r->tc->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		msg.hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;
		r->ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	r->inexec++;
	err = replicast_send(netobj->robj[0], r->ctx, RT_PINGPONG,
	    (struct repmsg_generic *)&msg, NULL, NULL, 0,
	    &mcast_addr, replicast_send_done_generic, st, NULL);
	if (err) {
		r->inexec--;
		state_next(st, EV_ERR);
		return;
	}

	assert(r->timer_req->data == NULL);

	/*
	 * Timeout in SERVER_LIST_GET_TIMEOUT_MS mss..
	 */
	r->timer_req->data = st;
	uv_timer_start(r->timer_req, pingpong_timeout, PINGPONG_TIMEOUT_MS, 0);
}

/*
 * GUARD: check for retry < MAX_RETRY
 */
static int
pingpong__retry(struct state *st)
{
	struct pingpong_req *r = st->data;

	if (++r->retry < PINGPONG_MAX_RETRY)
		return 1; // ok

	log_error(lg, "PINGPONG request timeout after %d attempts "
	    "seqid:%d.%d", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

	state_next(st, EV_ERR);
	return 0; // fail
}

static void
pingpong__init(struct state *st)
{
	struct pingpong_req *r = st->data;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;

	r->ctx = repctx_init(netobj->robj[0]);
	if (!r->ctx) {
		log_error(lg, "repctx alloc: out of memory: -ENOMEM");
		state_next(st, EV_ERR);
		return;
	}
	r->ctx->state = st;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		repctx_destroy(r->ctx);
		state_next(st, EV_ERR);
		return;
	}
	r->timer_req->data = NULL;
	uv_timer_init(tc->loop, r->timer_req);

	state_next(st, EV_SEND);
}

static void
pingpong_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
pingpong__term(struct state *st)
{
	struct pingpong_req *r = st->data;

	assert(r->inexec >= 0);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	uv_close((uv_handle_t *)r->timer_req, pingpong_timer_close_cb);
	repctx_destroy(r->ctx);
	r->cb(r->cb_data);
	je_free(r);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, &pingpong__init, ST_INIT, NULL },
{ ST_INIT, EV_SEND, &pingpong__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, &pingpong__send, ST_WAIT, &pingpong__retry },
{ ST_WAIT, RT_PINGPONG_ACK, &pingpong__ack, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &pingpong__error, ST_TERM, NULL }
};


static int
pingpong_create(struct ccow *tc, fhrow_t rowid, char *message,
		uint32_t size, void (*cb)(void *), void *cb_data)
{
	int err;

	struct pingpong_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		err = - ENOMEM;
		log_error(lg, "PINGPONG request alloc error: %d", err);
		return err;
	}
	r->tc = tc;
	r->rowid = rowid;
	r->netobj = tc->netobj;
	r->message = message;
	r->message_size = size;
	r->cb = cb;
	r->cb_data = cb_data;

	r->state.table = trans_tbl;
	r->state.cur = ST_INIT;
	r->state.max = sizeof (trans_tbl) / sizeof (*trans_tbl);
	r->state.term_cb = pingpong__term;
	r->state.data = r;
	r->state.io = NULL;

	while (lfqueue_enqueue(tc->api_lfq, &r->state) != 0) {
		usleep(250);
	}
	uv_async_send(&tc->api_call);

	return 0;
}
