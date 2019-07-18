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
#include "reptrans.h"
#include "ccowd-impl.h"
#include "state.h"
#include "getres_server.h"
#include "rt_locks.h"

static void
resget_srv__error(struct state *st)
{
	struct getres_srv_req *req = st->data;
	log_trace(lg, "st %p", st);
}

static void
getres_terminate(struct state *st)
{
	struct getres_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p seqid %d.%d, inexec %d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, req->inexec);

	assert(ctx->opcode_in == RT_RES_GET);
	assert(req->inexec >= 0);

	repctx_drop(req->ctx);
	assert(req->inexec != ~0L);
	if (req->inexec) {
		log_debug(lg, "request inexec %d, cannot terminate op %d",
		    req->inexec, ctx->opcode_in == RT_RES_GET);
		return;
	}

	if (req->rb_reply) {
		rtbuf_destroy((rtbuf_t *)req->rb_reply);
		req->rb_reply = NULL;
	}

	reptrans_dev_ctxfree_one(dev, req->ctx);
}

static void
res_reply_onsend(void *data, int status, int ctx_valid)
{
	struct getres_srv_req *req = data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;

	log_trace(lg, "data %p, status %d, ctx_valid %d seqid %d.%d", data,
		status, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;
	assert(req->inexec >= 0);

	if (state_check(ctx->state, ST_TERM)) {
		getres_terminate(ctx->state);
		return;
	}

	if (status != 0) {
		req->status = RT_ERR_EIO;
		state_event(ctx->state, EV_ERR);
		return;
	}
	state_event(ctx->state, EV_DONE);
}

static void
resget_srv__errsend(struct getres_srv_req *r, enum replicast_opcode opcode,
		    int error)
{
	struct repctx *ctx = r->ctx;
	struct repdev *dev = r->dev;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_error errmsg;
	int err;

	memset(&errmsg, 0, sizeof(errmsg));
	errmsg.num_datagrams = 1;
	errmsg.vdevid = dev->vdevid;
	errmsg.error = error;

	struct repmsg_res_get *last_msg = (struct repmsg_res_get *)wqe->msg;
	log_debug(lg, "req %p sending error %d", r, error);
	r->inexec++;
	err = replicast_send(dev->robj, ctx, opcode,
				(struct repmsg_generic *) &errmsg,
				(struct repmsg_generic *) last_msg,
				NULL, 0, NULL, res_reply_onsend, r, NULL);
	if (err) {
		r->inexec--;
		r->status = RT_ERR_EIO;
		if (!state_check(ctx->state, ST_TERM))
			state_event(ctx->state, EV_ERR);
	}
}

static void
resget_srv__replysend(struct getres_srv_req *r, enum replicast_opcode opcode)
{
	struct repctx *ctx = r->ctx;
	struct repdev *dev = r->dev;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_res_get_response *msg = &r->resget_rsp;
	uv_buf_t *bufs = r->rb_reply ? r->rb_reply->bufs : NULL;
	unsigned int nbufs = r->rb_reply ? r->rb_reply->nbufs : 0;
	int err;

	struct repmsg_res_get *last_msg = (struct repmsg_res_get *)wqe->msg;

	msg->object_name.name_hash_id = last_msg->object_name.name_hash_id;
	msg->res_maj_id = last_msg->res_maj_id;
	msg->res_min_id = last_msg->res_min_id;
	msg->immediate_content_length = r->rb_reply ? rtbuf_len(r->rb_reply) : 0;

	log_debug(lg, "Get lock reply opcode %u", opcode);
	r->inexec++;
	err = replicast_send(dev->robj, ctx, opcode,
				(struct repmsg_generic *) msg,
				(struct repmsg_generic *) last_msg,
				bufs, nbufs, NULL, res_reply_onsend, r, NULL);
	if (err) {
		r->inexec--;
		r->status = RT_ERR_EIO;
		if (!state_check(ctx->state, ST_TERM))
			state_event(ctx->state, EV_ERR);
	}
}

/*
 * ACTION: process RT_RES_GET request
 */
static void
resget_srv__request(struct state *st)
{
	struct getres_srv_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repdev *dev = r->dev;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_obj_lock lk_req, *cur_lk = NULL;
	msgpack_p *p = NULL;
	msgpack_u *u = NULL;
	uv_buf_t buf;
	uint512_t *ngroup;
	enum replicast_opcode opcode = RT_ERROR;
	struct replicast_object_name *ron;
	char	vdevstr[UINT128_BYTES*2+1],
		fh_vdevstr[UINT128_BYTES*2+1],
		tgt_vdevstr[UINT128_BYTES*2+1];
	struct repmsg_res_get *msg;
	int err;
	int errnum = -EINVAL;

	log_trace(lg, "st %p", st);
	log_trace(lg, "req %p wqe %p msg %p\n", r, wqe, wqe ? wqe->msg : NULL);

	if (!wqe) {
		state_next(st, EV_ERR);
		return;
	}

	msg = (struct repmsg_res_get *)wqe->msg;

	/* Currently only lock reource is supported */
	if (msg->res_maj_id != CCOW_SR_MAJ_LOCK) {
		/* Send RT_ERROR */
		log_debug(lg, "Unkown op id : %d\n", msg->res_maj_id);
		errnum = -EPROTO;
		goto _out;
	}

	if (uint128_cmp(&msg->tgt_vdevid, &uint128_null) == 0) {
		log_debug(lg, "Received null device id");
		goto _out;
	}

	uint128_dump(&dev->vdevid, vdevstr, UINT128_BYTES*2+1);
	uint128_dump(&msg->tgt_vdevid, tgt_vdevstr, UINT128_BYTES*2+1);
	log_debug(lg, "Lock device: %s, This device: %s\n",
			tgt_vdevstr, vdevstr);

	if (uint128_cmp(&dev->vdevid, &msg->tgt_vdevid) != 0) {
		state_next(st, EV_ERR);
		return;
	}

	log_debug(lg, "Matching lock device found");
	ngroup = &msg->object_name.name_hash_id;


	/* Check for flexhash changes */
	uint128_t target_vdev;
	ccowd_fhready_lock(FH_LOCK_READ);
	uint16_t row = HASHROWID(ngroup, SERVER_FLEXHASH);
	err = flexhash_find_master(SERVER_FLEXHASH, ngroup, 0, &target_vdev);
	ccowd_fhready_unlock(FH_LOCK_READ);
	if (err != 0) {
		log_error(lg, "No lock server VDEV %s", tgt_vdevstr);
		errnum = -EAGAIN;
		goto _out;
	}
	uint128_to_buffer(&target_vdev, fh_vdevstr);
	log_debug(lg, "Lock server check VDEV %s in row: %u",
			tgt_vdevstr, row);
	if (uint128_cmp(&target_vdev, &msg->tgt_vdevid) != 0) {
		log_warn(lg, "Lock server vdev changed to %s", fh_vdevstr);
		errnum = -EBADF;
		goto _out;
	}
	log_debug(lg, "Lock server found VDEV %s", tgt_vdevstr);

	/* Get the request data */
	r->req_payload.len = msg->immediate_content_length;
	r->req_payload.base = repwqe_payload(wqe);

	u = msgpack_unpack_init(r->req_payload.base, r->req_payload.len, 0);
	if (!u) {
		errnum = -ENOMEM;
		goto _out;
	}

	err = ccow_unpack_lock(u, &lk_req);
	if (err == 0) {
		lk_req.lk_nhid = msg->object_name.name_hash_id;
		char nhid_buf[UINT512_BYTES * 2 + 1];
		uint512_dump(&lk_req.lk_nhid, nhid_buf, UINT512_BYTES * 2 + 1);

		/*
		 * TODO: Need to queue this into SOP queue to
		 * avoid use of locks
		 */
		cur_lk = rt_get_lock(dev, &lk_req);
		if (cur_lk) {
			p = msgpack_pack_init();
			err = ccow_pack_lock(p, cur_lk);
			if (err == 0) {
				msgpack_get_buffer(p, &buf);
				r->rb_reply = rtbuf_init_mapped(&buf, 1);
				opcode = RT_RES_GET_RESPONSE;
			} else
				log_trace(lg, "Failed to unpack lock");
		} else {
			log_trace(lg, "Failed to find lock [%" PRIu64 \
					",%" PRIu64 ") mode: %u",
				lk_req.lk_region.off,
                                lk_req.lk_region.len, lk_req.lk_mode);
			errnum = -ENOENT;
			goto _out;
		}
	}

_out:
	if (u)
		msgpack_unpack_free(u);

	if (opcode == RT_ERROR)
		resget_srv__errsend(r, opcode, errnum);
	else
		resget_srv__replysend(r, opcode);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_RES_GET, &resget_srv__request, ST_READY, NULL },
{ ST_READY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_READY, EV_ANY, &resget_srv__error, ST_TERM, NULL }
};

int
resget_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state)
{
	int err;
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct getres_srv_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = getres_terminate;
	ctx->stat_cnt = &robj->stats.resget_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	return 0;
}

