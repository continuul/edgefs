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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <ifaddrs.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "connbroker.h"

uv_loop_t *cloop, *sloop;
struct connbroker cconn, sconn;
char addr[INET6_ADDRSTRLEN];
int cport = 12000, sport = 13000;
uv_thread_t cthread_id, sthread_id;
uv_timer_t ctimer, stimer;
int cterm, sterm;
int clreq;
int domain = AF_INET;;

static char *request = "Sample request";
static char *response = "Sample response";

#define BUFSIZE_128	128
#define BUFSIZE_4K	(4 * 1024)
#define BUFSIZE_64K	(64 * 1024)
#define BUFSIZE_256K	(256 * 1024)
#define BUFSIZE_1M	(1 * 1024 * 1024)

char randbuf1[BUFSIZE_4K];
char randbuf2[BUFSIZE_64K];
char randbuf3[BUFSIZE_256K];
char randbuf4[BUFSIZE_1M];

//-------------------------------------------------------------------
//CLIENT STATE MACHINE

struct cl_test_request
{
	struct connbroker *cbr;
	struct connbroker_context brx;
	uv_buf_t buf;
	rt_connect_cb cb;
	void *cb_data;
	replicast_send_cb send_cb;
	void *send_cb_data;
	int inexec;
	struct state state;
	uv_timer_t watch_timer;
	uint32_t data_len;
};

static void
cl_term(struct state *st)
{
	struct cl_test_request *r = st->data;
	struct repctx *ctx = r->brx.ctx;
	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
			r, r->inexec);
		return;
	}

	log_debug(lg, "Terminating request %p", r);
	uv_close((uv_handle_t *)&r->watch_timer, NULL);
	if (ctx) {
		repctx_drop(ctx);
		repctx_destroy(ctx);
	}

	je_free(r);
}

static void
cl_error(struct state *st)
{
}

static void
cl_recv(struct state *st)
{
	struct cl_test_request *r = st->data;
	struct repctx *ctx = r->brx.ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_sg_chunkput_response *msg;
	uv_buf_t payload = {0};

	msg = (struct repmsg_sg_chunkput_response *) wqe->msg;

	memset(&payload, 0, sizeof(uv_buf_t));
	if (msg->hdr.data_len) {
		payload.base = repwqe_payload(wqe);
		payload.len = repwqe_payload_len(wqe);
	}

	log_debug(lg, "Response received: buflen %lu", payload.len);

	// Verification
	if (clreq == 1) {
		printf("Client received: %s\n", payload.base);
		assert_string_equal(payload.base, response);
		clreq++;
	} else if (clreq == 2) {
		assert_memory_equal(payload.base, randbuf1, BUFSIZE_4K);
		clreq++;
	} else if (clreq == 3) {
		assert_memory_equal(payload.base, randbuf2, BUFSIZE_64K);
		clreq++;
	} else if (clreq == 4) {
		assert_memory_equal(payload.base, randbuf3, BUFSIZE_256K);
		clreq++;
	} else if (clreq == 5) {
		assert_memory_equal(payload.base, randbuf4, BUFSIZE_1M);
		clreq++;
		cterm = 1;
	}

	state_next(st, EV_DONE);
}

static void
cl_send_timeout(uv_timer_t *req, int status)
{
	struct state *st = req->data;
	state_event(st, EV_TIMEOUT);
}

static void
cl_send_cb(void *data, int err, int ctx_valid)
{
	struct state *st = data;
	struct cl_test_request *r = st->data;

	uv_timer_stop(&r->watch_timer);
	r->inexec--;
	if (err) {
		log_error(lg, "Error %d while sending cbr request", err);
		state_event(st, EV_ERR);
		return;
	}
}

static void
cl_send(struct state *st)
{
	struct cl_test_request *r = st->data;

	printf("cl_send buflen %lu\n", r->buf.len);
	struct repmsg_sg_chunkput msg;
	memset(&msg, 0, sizeof (msg));

	r->inexec++;
	int err = cbr_request_send(&r->brx, st, RT_SG_CHUNKPUT,
		(struct repmsg_generic *)&msg, &r->buf, 1, cl_send_cb,
		st, NULL);
	if (err) {
		r->inexec--;
		log_error(lg, "Failed to send replicast");
		state_next(st, EV_ERR);
		return;
	}

	r->watch_timer.data = st;
	uv_timer_start(&r->watch_timer, cl_send_timeout, 10000, 0);
}

static void
cl_connect_cb(void *data, int status)
{
	struct cl_test_request *r = data;
	struct state *st = &r->state;

	if (status) {
		log_error(lg, "Failed to connect");
		state_event(st, EV_ERR);
		return;
	}

	state_event(st, EV_SEND);
}

static void
cl_connect(struct state *st)
{
	struct cl_test_request *r = st->data;

	int err = cbr_connect(&r->brx, cl_connect_cb, r);
	if (err == -EEXIST) {
		state_next(st, EV_SEND);
		return;
	}

	if (err) {
		log_error(lg, "Failed to connect");
		state_next(st, EV_ERR);
		return;
	}
}

static const struct transition cl_trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_START, &cl_connect, ST_INIT, NULL },
{ ST_INIT, EV_SEND, &cl_send, ST_WAIT, NULL },
{ ST_WAIT, RT_SG_CHUNKPUT_RESPONSE, &cl_recv, ST_WAIT, NULL },
{ ST_ANY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_TIMEOUT, &cl_error, ST_TERM, NULL },
{ ST_ANY, EV_ERR, &cl_error, ST_TERM, NULL },
};

int
cl_init(struct connbroker *cbr, uv_buf_t *buf)
{
	int i, err;
	struct cl_test_request *r;
	struct endpoint *rep = NULL;

	r = je_calloc(1, sizeof(*r));
	if (r == NULL) {
		log_error(lg, "Failed to allocate memory");
		return -ENOMEM;
	}

	cbr_init_context(&r->brx, cbr);
	r->cbr = cbr;
	r->buf = *buf;
	r->cb = cl_connect_cb;
	r->send_cb = cl_send_cb;
	uv_timer_init(cbr->loop, &r->watch_timer);

	memset(&r->state, 0, sizeof(struct state));
	r->state.table = cl_trans_tbl;
	r->state.cur = ST_INIT;
	r->state.max = sizeof(cl_trans_tbl) / sizeof(*cl_trans_tbl);
	r->state.term_cb = cl_term;
	r->state.data = r;

	state_event(&r->state, EV_START);

	return 0;
}

//-------------------------------------------------------------------
//SERVER STATE MACHINE

struct srv_test_request
{
	struct replicast *robj;
	uv_buf_t bufs[2];
	unsigned int nbufs;
	struct repctx *ctx;
	int inexec;
};

static void
srv_term(struct state *st)
{
	struct srv_test_request *s = st->data;
	if (s->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
			s, s->inexec);
		return;
	}

	log_debug(lg, "Terminating request %p", s);
	repctx_drop(s->ctx);
	repctx_destroy(s->ctx);
	je_free(s);
}

static void
srv_error(struct state *st)
{
}

static void
srv_send_cb(void *data, int err, int ctx_valid)
{
	struct state *st = data;
	struct srv_test_request *s = st->data;

	s->inexec--;
	if (err) {
		log_error(lg, "Error %d while sending srv_test_request", err);
		state_event(st, EV_ERR);
		return;
	}

	state_event(st, EV_DONE);
}

static void
srv_send(struct state *st)
{
	struct srv_test_request *s = st->data;
	struct repctx *ctx = s->ctx;
	struct repwqe *wqe = ctx->wqe_in;

	struct repmsg_sg_chunkput_response rsp;
	memset(&rsp, 0, sizeof(rsp));

	s->inexec++;
	int err = cbr_response_send(s->robj, s->ctx, RT_SG_CHUNKPUT_RESPONSE,
		(struct repmsg_generic *)&rsp, wqe->msg, s->bufs, s->nbufs,
		srv_send_cb, st, NULL);
	if (err) {
		s->inexec--;
		log_error(lg, "Failed to send RT_SEGMENT_RESPONSE");
		state_next(st, EV_ERR);
	}
}

static void
srv_recv(struct state *st)
{
	struct srv_test_request *s = st->data;
	struct repctx *ctx = s->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_sg_chunkput *msg;
	int err;
	assert(wqe);

	uv_buf_t payload = {0};
	msg = (struct repmsg_sg_chunkput *) wqe->msg;
	if (msg->hdr.data_len) {
		payload.base = repwqe_payload(wqe);
		payload.len = repwqe_payload_len(wqe);
	}

	printf("Server: Request received buflen %u\n", msg->hdr.data_len);

	// Verification
	if (clreq == 1) {
		printf("Server received: %s\n", payload.base);
		assert_string_equal(payload.base, request);
		s->bufs[0].base = je_calloc(1, 128);
		s->bufs[0].len = 128;
		s->nbufs = 1;
		strncpy(s->bufs[0].base, response, 128);
	}

	if (clreq == 2) {
		assert_memory_equal(payload.base, randbuf1, BUFSIZE_4K);
		s->bufs[0].base = randbuf1;
		s->bufs[0].len = BUFSIZE_4K;
		s->nbufs = 1;
	}

	if (clreq == 3) {
		assert_memory_equal(payload.base, randbuf2, BUFSIZE_64K);
		s->bufs[0].base = randbuf2;
		s->bufs[0].len = BUFSIZE_64K;
		s->nbufs = 1;
	}

	if (clreq == 4) {
		assert_memory_equal(payload.base, randbuf3, BUFSIZE_256K);
		s->bufs[0].base = randbuf3;
		s->bufs[0].len = BUFSIZE_256K;
		s->nbufs = 1;
	}

	if (clreq == 5) {
		assert_memory_equal(payload.base, randbuf4, BUFSIZE_1M);
		s->bufs[0].base = randbuf4;
		s->bufs[0].len = BUFSIZE_1M;
		s->nbufs = 1;
	}

	state_next(st, EV_SEND);
}

static const struct transition srv_trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, RT_SG_CHUNKPUT, &srv_recv, ST_WAIT, NULL },
{ ST_WAIT, EV_SEND, &srv_send, ST_WAIT, NULL },
{ ST_ANY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ERR, &srv_error, ST_TERM, NULL }
};

int
srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state)
{
	struct srv_test_request *s = je_calloc(1, sizeof(*s));
	if (s == NULL) {
		log_error(lg, "Failed to allocate srv_test_request");
		return -ENOMEM;
	}

	s->ctx = ctx;
	s->robj = robj;
	state->table = srv_trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(srv_trans_tbl) / sizeof(*srv_trans_tbl);
	state->term_cb = srv_term;
	state->data = s;

	return 0;
}

//-------------------------------------------------------------------
static int
get_local_addr(char *addr)
{
	int err = -1;
	struct ifaddrs *iflist, *tif;
	assert_int_equal(getifaddrs(&iflist), 0);

	struct sockaddr_in *p;
	struct sockaddr_in6 *q;
	tif = iflist;

	while (tif) {
		if (tif->ifa_addr->sa_family == AF_INET && domain == AF_INET) {
			p = (struct sockaddr_in *) tif->ifa_addr;
			inet_ntop(AF_INET, &p->sin_addr, addr, INET_ADDRSTRLEN);
			err = 0;
			break;
		}
		if (tif->ifa_addr->sa_family == AF_INET6 && domain == AF_INET6) {
			q = (struct sockaddr_in6 *) tif->ifa_addr;
			inet_ntop(AF_INET6, &q->sin6_addr, addr, INET6_ADDRSTRLEN);
			err = 0;
			break;
		}
		tif = tif->ifa_next;
	}
	freeifaddrs(iflist);
	return err;
}

static void
server_thread(void *arg)
{
	uv_run(sloop, UV_RUN_DEFAULT);
	printf("Server thread finished.\n");
}

static void
client_thread(void *arg)
{
	uv_run(cloop, UV_RUN_DEFAULT);
	printf("Client thread finished.\n");
}

static int
serve_1(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	return srv_init(robj, ctx, state);
}

static void
stimer_1(uv_timer_t *req, int status)
{
	if (clreq == 6 && sterm++ == 2) {
		printf("Terminating server\n");
		cbr_stop_server(&sconn);
		return;
	}

	uv_timer_start(&stimer, stimer_1, 1000, 0);
}

static void
ctimer_1(uv_timer_t *treq, int status)
{
	static int once;
	once++;

	if (cterm) {
		printf("Terminating client\n");
		cbr_stop_client(&cconn);
		return;
	}

	if (once == 2)
		clreq = 1;

	if (clreq == 1) {
		uv_buf_t payload;
		payload.base = je_malloc(128);
		payload.len = 128;
		assert(payload.base != NULL);
		strncpy(payload.base, request, 128);
		assert_int_equal(cl_init(&cconn, &payload), 0);
	}

	if (clreq == 2) {
		uv_buf_t payload;
		payload.base = randbuf1;
		payload.len = BUFSIZE_4K;
		assert_int_equal(cl_init(&cconn, &payload), 0);
	}

	if (clreq == 3) {
		uv_buf_t payload;
		payload.base = randbuf2;
		payload.len = BUFSIZE_64K;
		assert_int_equal(cl_init(&cconn, &payload), 0);
	}

	if (clreq == 4) {
		uv_buf_t payload;
		payload.base = randbuf3;
		payload.len = BUFSIZE_256K;
		assert_int_equal(cl_init(&cconn, &payload), 0);
	}

	if (clreq == 5) {
		uv_buf_t payload;
		payload.base = randbuf4;
		payload.len = BUFSIZE_1M;
		assert_int_equal(cl_init(&cconn, &payload), 0);
	}

	uv_timer_start(&ctimer, ctimer_1, 1000, 0);
}

static void
libconn_test_1(void **state)
{
	struct endpoint ep;
	memset(&ep, 0, sizeof(ep));
	strncpy(ep.addr, addr, INET6_ADDRSTRLEN);
	assert_int_equal(cbr_get_endpoint_info(&ep), 0);
	ep.port = 16000;

	printf("Addr: %s port: %d scopeid: %d\n", ep.addr, ep.port, ep.scopeid);

	cloop = uv_loop_new();
	assert(cloop != NULL);
	assert_int_equal(cbr_init(&cconn, cloop, "client", NULL), 0);
	assert_int_equal(cbr_add_remote_endpoint(&cconn, ep.addr, ep.port,
		ep.domain, ep.scopeid), 0);
	assert_int_equal(cbr_start_client(&cconn), 0);
	uv_timer_init(cloop, &ctimer);
	uv_timer_start(&ctimer, ctimer_1, 1000, 0);
	uv_thread_create(&cthread_id, client_thread, NULL);

	sloop = uv_loop_new();
	assert(sloop != NULL);
	assert_int_equal(cbr_init(&sconn, sloop, "server", NULL), 0);
	assert_int_equal(cbr_add_local_endpoint(&sconn, ep.addr, ep.port,
		ep.domain, ep.scopeid, ep.ifspeed), 0);
	assert_int_equal(cbr_start_server(&sconn), 0);
	cbr_register_callback(&sconn, RT_SG_CHUNKPUT, serve_1);
	uv_timer_init(sloop, &stimer);
	uv_timer_start(&stimer, stimer_1, 1000, 0);
	uv_thread_create(&sthread_id, server_thread, NULL);

	uv_thread_join(&cthread_id);
	uv_thread_join(&sthread_id);

	uv_loop_delete(cloop);
	uv_loop_delete(sloop);
}

static void
libconn_test_setup(void **state)
{
	lg = Logger_create("libconnbroker_test");
	assert(lg != NULL);
	assert_int_equal(get_local_addr(addr), 0);

	int fd = open("/dev/urandom", O_RDONLY);
	assert(fd > 0);
	int err = read(fd, randbuf1, BUFSIZE_4K);
	assert(err > 0);
	err = read(fd, randbuf2, BUFSIZE_64K);
	assert(err > 0);
	err = read(fd, randbuf3, BUFSIZE_256K);
	assert(err > 0);
	err = read(fd, randbuf4, BUFSIZE_1M);
	assert(err > 0);
	close(fd);
}

static void
libconn_test_teardown(void **state)
{
	Logger_destroy(lg);
}

int
main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "-6") == 0)
		domain = AF_INET6;

	const UnitTest tests[] = {
		unit_test(libconn_test_setup),
		unit_test(libconn_test_1),
		unit_test(libconn_test_teardown),
	};
	return run_tests(tests);
}

