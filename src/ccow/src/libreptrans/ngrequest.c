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
#include "ccowd-impl.h"
#include "state.h"

extern struct ccowd *ccow_daemon;

struct ngrequest_srv_req {
	REQ_CLASS_FIELDS
	struct repmsg_ngrequest rsp;
	uint8_t status;
};

static void
ngrequest__error(struct state *st)
{
	struct ngrequest_srv_req *req = st->data;

	log_trace(lg, "st %p", st);
}

static void
ngrequest__term(struct state *st)
{
	struct ngrequest_srv_req *req = st->data;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p inexec %d", st, req->inexec);

	assert(req->inexec >= 0);
	repctx_drop(req->ctx);

	assert(req->inexec != ~0L);
	if (req->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    req, req->inexec);
		return;
	}

	req->inexec = ~0L;
	reptrans_dev_ctxfree_one(dev, req->ctx);
}

static void
ngrequest_send_done(void *data, int err, int ctx_valid)
{
	struct ngrequest_srv_req *req = data;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
	    data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;
	if (state_check(st, ST_TERM)) {
		ngrequest__term(st);
		return;
	}

	if (err) {
		log_error(lg, "Error %d while sending ngrequst response", err);
		state_event(st, EV_ERR);
		return;
	}

	state_event(st, EV_DONE);
}

static void
ngrequest_done(void *arg, int status)
{
	struct ngrequest_srv_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;
	struct repwqe *wqe = ctx->wqe_in;
	int err;

	log_trace(lg, "warg %p, status %d inexec %d", arg, status, req->inexec);

	req->inexec--;

	if (state_check(st, ST_TERM)) {
		ngrequest__term(st);
		return;
	}

	if (status != 0) {
		log_error(lg, "NGREQ(%s): transport returned non-zero "
		    "status %d", dev->name, status);
		state_event(ctx->state, EV_ERR);
		return;
	}

	req->rsp.message = &req->status;
	req->rsp.message_size = sizeof (uint8_t);

	uv_buf_t uvb = { .base = (char*)&req->status, .len = sizeof (uint8_t) };
	req->inexec++;
	err = reptrans_ng_send(RT_PROT_NGREQUEST, dev->robj, NULL,
		RT_NGREQUEST_ACK, (struct repmsg_generic *)wqe->msg, &uvb, 1,
		NULL, ngrequest_send_done, req);
	if (err) {
		req->inexec--;
		state_event(ctx->state, EV_ERR);
		return;
	}
}

static void
ngrequest_exec(void *arg)
{
	struct ngrequest_srv_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	int err;

	log_trace(lg, "warg %p", arg);

	/* FIXME: call the per-device background processor */
	log_debug(lg, "Requesting batch enqueue");

	req->status = reptrans_enqueue_batch(dev, req->rsp.message,
		req->rsp.message_size);
	if (req->status) {
		log_warn(lg, "Dev(%s) batch enqueue failed,"
			" the disk might be full %d", dev->name, req->status);
	}
}

int
ngrequest_unpack(msgpack_u* u, void* dptr) {
	struct repmsg_ngrequest* msg = (struct repmsg_ngrequest*)dptr;

	int err = msgpack_unpack_raw(u, (void*)&msg->message, &msg->message_size);
	if (!err) {
		err = msgpack_unpack_uint16(u, &msg->fhrow);
	}
	return err;
}
/*
 * ACTION: process RT_NGREQUEST request
 *
 * Return same message back to a caller
 */
static void
ngrequest__req(struct state *st)
{
	struct ngrequest_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	log_trace(lg, "st %p, inexec %d", st, req->inexec);

	if (req->inexec) {
		state_next(st, EV_ERR);
		return;
	}

	int err = reptrans_ng_recv_unpack(RT_PROT_NGREQUEST, wqe, &req->rsp,
		ngrequest_unpack);

	if (err) {
		if (err < 0)
			log_error(lg, "ng reptrans buffer corrupted: %d", err);
		else {
			log_error(lg, "Incompatible ngreques protocol version: "
				"expected %d vs got %d",
				reptrans_get_ngproto_version(RT_PROT_NGREQUEST), err);
		}
		state_next(st, EV_ERR);
		return;
	}

	int found = 0;
	SERVER_FLEXHASH_SAFE_CALL(found = flexhash_is_rowmember_fhrow(
		SERVER_FLEXHASH, &dev->vdevid, req->rsp.fhrow), FH_LOCK_READ);
	if (!found) {
		log_error(lg, "Dev(%s) VDEV %016lX%016lX is not a member of row %d, port %u. Ignoring",
			dev->name, dev->vdevid.u, dev->vdevid.l, req->rsp.fhrow, dev->listen_port);
		state_next(st, EV_ERR);
		return;

	}

	req->inexec++;
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_MID, ngrequest_exec,
		ngrequest_done, req);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_NGREQUEST, &ngrequest__req, ST_WAIT, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &ngrequest__error, ST_TERM, NULL }
};

int
ngrequest_init(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	if(dev->terminating)
		return -ENODEV;

	struct ngrequest_srv_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = ngrequest__term;
	ctx->stat_cnt = &robj->stats.ngrequest_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	return 0;
}
