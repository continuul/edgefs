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
#include "ccow-impl.h"
#include "blob-lookup.h"
#include "state.h"

struct blob_lookup_req {
	CCOW_CLASS_FIELDS
	struct ccow_network *netobj;
	uint512_t blob_chid;
	uint8_t ttag;
	uint8_t hash_type;
	uint128_t* vdevs;
	size_t* n_vdevs;
	int status;
};

/*
 * ACTION: unblock caller and report error
 */
static void
blr_state__error(struct state *st) {
	struct blob_lookup_req *r = st->data;
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
}

/*
 * ACTION: process response
 */
static void
blr_state__response(struct state *st)
{
	struct blob_lookup_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	int err;

	struct repmsg_blob_lookup_ack *msg =
		(struct repmsg_blob_lookup_ack *)wqe->msg;
	uint8_t n_vdevs = msg->ndevs > *r->n_vdevs ? *r->n_vdevs : msg->ndevs;
	msgpack_u *u = msgpack_unpack_init(repwqe_payload(wqe), repwqe_payload_len(wqe), 0);
	err = replicast_unpack_uvbuf_vdevs(u, n_vdevs, r->vdevs);
	if (err) {
		*r->n_vdevs = 0;
		r->status = err;
		msgpack_unpack_free(u);
		log_error(lg, "repmsg_blob_lookup_ack unpack error");
		return;

	}
	r->status = 0;
	*r->n_vdevs = n_vdevs;
	msgpack_unpack_free(u);
}

static void
blr_send_timeout(uv_timer_t *req, int status)
{
	struct state *st = req->data;
	struct blob_lookup_req *r = st->data;
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	log_warn(lg, "BLOB LOOKUP request timeout after %d attempts "
	    "seqid:%d.%d", r->retry + 1, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);
	state_event(st, EV_TIMEOUT);
}

/*
 * ACTION: Prepare and send RT_BLOB_LOOKUP
 */
static void
blr_state__send(struct state *st)
{
	int err;
	struct blob_lookup_req *r = st->data;
	struct ccow_network *netobj = r->netobj;

	struct repmsg_blob_lookup msg;
	memset(&msg, 0, sizeof (msg));
	msg.chid = r->blob_chid;
	msg.ttag = r->ttag;
	msg.hash_type = r->hash_type;

	r->inexec++;
	err = replicast_send(netobj->robj[0], r->ctx, RT_BLOB_LOOKUP,
	    (struct repmsg_generic *)&msg, NULL, NULL, 0,
	    &netobj->server_sockaddr, replicast_send_done_generic, st, NULL);
	if (err) {
		r->inexec--;
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	/*
	 * Timeout in BLOB_LOOKUP_TIMEOUT_MS mss..
	 */
	r->timer_req->data = st;
	uv_timer_start(r->timer_req, blr_send_timeout,
	    BLOB_LOOKUP_TIMEOUT_MS, 0);
}

/*
 * GUARD: check for retry < MAX_RETRY
 */
static int
blr_guard__retry(struct state *st)
{
	struct blob_lookup_req *r = st->data;

	if (++r->retry < BLOB_LOOKUP_MAX_RETRY)
		return 1; // ok

	log_error(lg, "BLOB LOOKUP request timeout after %d attempts "
	    "seqid:%d.%d", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

	ccow_fail_io(st->io, -EIO);
	state_next(st, EV_ERR);
	return 0; // fail
}

static void
blr_state__init(struct state *st)
{
	struct blob_lookup_req *r = st->data;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;

	r->ctx = repctx_init(netobj->robj[0]);
	if (!r->ctx) {
		log_error(lg, "repctx alloc: out of memory: -ENOMEM");
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->ctx->state = st;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		repctx_destroy(r->ctx);
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->timer_req->data = NULL;
	uv_timer_init(tc->loop, r->timer_req);

	state_next(st, EV_SEND);
}

static void
blr_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
blr_state__term(struct state *st)
{
	struct blob_lookup_req *r = st->data;
	struct ccow_io *io = (struct ccow_io *)st;

	assert(r->inexec >= 0);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	uv_close((uv_handle_t *)r->timer_req, blr_timer_close_cb);
	repctx_destroy(r->ctx);
	ccow_complete_io(io);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, &blr_state__init, ST_INIT, NULL },
{ ST_INIT, EV_SEND, &blr_state__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, &blr_state__send, ST_WAIT, &blr_guard__retry },
{ ST_WAIT, RT_BLOB_LOOKUP_ACK, &blr_state__response, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &blr_state__error, ST_TERM, NULL }
};

/*
 * Initiate RT_BLOB_LOOKUP
 *
 */
int ccow_blob_lookup_request(struct ccow_network *netobj, const uint512_t* chid, uint8_t ttag,
	uint8_t hash_type, struct ccow_completion *c, uint128_t* vdevs_out, size_t* n_vdev_max)
{
	int err;
	struct ccow *tc = netobj->tc;

	struct blob_lookup_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		log_error(lg, "blob_lookup_request: out of memory: -ENOMEM");
		return -ENOMEM;
	}
	r->netobj = netobj;
	r->blob_chid = *chid;
	r->ttag = ttag;
	r->hash_type = hash_type;
	r->vdevs = vdevs_out;
	r->n_vdevs = n_vdev_max;

	struct ccow_op *blob_lookup_op;
	err = ccow_operation_create(c, CCOW_RING, &blob_lookup_op);
	if (err) {
		ccow_release(c);
		je_free(r);
		return err;
	}

	struct ccow_io *io;
	err = ccow_create_io(c, blob_lookup_op, CCOW_RING, trans_tbl,
	    sizeof (trans_tbl) / sizeof (*trans_tbl), r, blr_state__term, &io);
	if (err) {
		ccow_operation_destroy(blob_lookup_op, 1);
		ccow_release(c);
		je_free(r);
		return err;
	}

	err = ccow_start_io(io);
	return err;
}
