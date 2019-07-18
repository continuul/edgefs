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
#include "erasure-coding.h"

struct recovery_req {
	REQ_CLASS_FIELDS
	int status;
	uint512_t chid;
	uint512_t nhid;
	rtbuf_t* refs;
	type_tag_t tt;
	uint64_t ts;
	int flags;
};

static void
recovery__error(struct state *st)
{
	struct recovery_req *req = st->data;

	log_trace(lg, "st %p", st);
}

static void
recovery__term(struct state *st)
{
	struct recovery_req *req = st->data;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p inexec %d", st, req->inexec);

	assert(req->inexec >= 0);
	repctx_drop(req->ctx);

	if (req->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    req, req->inexec);
		return;
	}
	reptrans_dev_ctxfree_one(dev, req->ctx);
}


static int
recovery_send_ack(struct state *st, replicast_send_cb cb) {
	struct recovery_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;

	struct repmsg_recovery_ack reply_msg;
	memset(&reply_msg, 0, sizeof(reply_msg));
	reply_msg.content_hash_id = req->chid;
	reply_msg.status = req->status;
	reply_msg.vdevid = dev->vdevid;

	fhrow_t row;
	uint512_t* pchid = req->tt == TT_CHUNK_MANIFEST ? &req->chid : &req->nhid;
	int ngcount;
	int err = 0;
	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
		pchid, &row, &ngcount), FH_LOCK_READ);
	if (err < 0) {
		if (err != -EAGAIN)
			log_error(lg, "Unable to retrieve ngcount, "
				"skip current RT_RECOVERY_ACK");
		return err;
	}
	if (!ngcount) {
		log_error(lg, "Wrong NG count value %d, "
			"skip current RT_RECOVERY_ACK", reply_msg.ngcount);
		return -ENODEV;
	}
	reply_msg.ngcount = ngcount;
	err = replicast_send(dev->robj, ctx, RT_RECOVERY_ACK,
		(struct repmsg_generic *)&reply_msg,
		(struct repmsg_generic *)wqe->msg,
		NULL, 0, NULL, cb, st, NULL);
	if (err)
		log_error(lg, "RT_RECOVERY_ACK operation error %d on send", err);
	return err;
}

static void
recovery_send_ack__done(void *data, int err, int ctx_valid) {
	struct state *st = data;
	struct recovery_req *req = st->data;
	struct repctx *ctx = req->ctx;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
	    data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;
	if (state_check(st, ST_TERM)) {
		recovery__term(st);
		return;
	}

	if (err) {
		log_error(lg, "Error %d while sending recovery ack",
		    err);
		assert(err < 0);
		req->status = err;
		state_event(st, EV_ERR);
		return;
	}
	state_event(st, EV_DONE);
}

static void
recovery_send_progress_ack__done(void *data, int err, int ctx_valid) {
	struct state *st = data;
	struct recovery_req *req = st->data;
	struct repctx *ctx = req->ctx;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
		data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);
}

static void
recover_work__cb(void* w) {
	struct state *st = w;
	struct recovery_req *req = st->data;
	struct repctx *ctx = req->ctx;

	req->status = ec_recover_manifest_exec(req->dev, &req->chid,
		req->tt, &req->nhid, req->refs, req->flags);

}

static void
recover_work_check__cb(void* w) {
	struct state *st = w;
	struct recovery_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;

	ccowd_fhready_lock(FH_LOCK_READ);
	if (!flexhash_is_pristine(SERVER_FLEXHASH)) {
		req->status = MANIFEST_RECOVERY_BUSY;
		ccowd_fhready_unlock(FH_LOCK_READ);
		return;
	}
	ccowd_fhready_unlock(FH_LOCK_READ);
	int status = ec_recover_manifest_check(dev, &req->chid, req->tt,
		&req->nhid, &req->refs);
	if (!status) {
		if (uv_sem_trywait(&dev->recover_sem)) {
			req->status = MANIFEST_RECOVERY_BUSY;
		} else
			req->status = MANIFEST_PROCESSING;
	} else
		req->status = status;

	if (lg->level <= LOG_LEVEL_DEBUG) {
		char chidstr[UINT512_BYTES*2+1];
		char vdevstr[UINT128_BYTES*2+1];
		uint512_dump(&req->chid, chidstr, UINT512_BYTES*2+1);
		uint128_dump(&dev->vdevid, vdevstr, UINT128_BYTES*2+1);
		log_debug(lg, "Dev(%s) VDEV %s manifest %s check status %d",
			dev->path, vdevstr, chidstr, req->status);
	}
}

static void
recovery_finished__cb(void* w, int wstat);

static void
recovery_work_check_done__cb(void* w, int wstat) {
	struct state *st = w;
	struct recovery_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;

	if (req->status != MANIFEST_PROCESSING) {
		/* Manifest cannot be recovered on this VDEV or it's busy
		 * Send a negative ack in either case
		 */
		recovery_finished__cb(w, 0);
	} else {
		/*
		 * Two stages recovery confirmation.
		 * if a manifest recovery is about to start we are sending
		 * the first ack. Second one will be sent when recovery is done.
		 **/
		int err = recovery_send_ack(st, recovery_send_progress_ack__done);
		if (err) {
			req->inexec--;
			req->status = err;
			state_event(st, EV_ERR);
			return;
		}
		if (lg->level <= LOG_LEVEL_DEBUG) {
			char chidstr[UINT512_BYTES*2+1];
			char vdevstr[UINT128_BYTES*2+1];
			uint512_dump(&req->chid, chidstr, UINT512_BYTES*2+1);
			uint128_dump(&dev->vdevid, vdevstr, UINT128_BYTES*2+1);
			log_debug(lg, "Dev(%s) VDEV %s manifest %s sent first ACK",
				dev->path, vdevstr, chidstr);
		}
		ccowtp_work_queue(dev->tp,REPTRANS_TP_PRIO_MID, recover_work__cb,
			recovery_finished__cb, w);
	}
}

static void
recovery_finished__cb(void* w, int wstat)
{
	struct state *st = w;
	struct recovery_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;

	if (req->status > 0 && req->status != MANIFEST_RECOVERY_BUSY)
		uv_sem_post(&dev->recover_sem);

	if (lg->level <= LOG_LEVEL_DEBUG) {
		char chidstr[UINT512_BYTES*2+1];
		char vdevstr[UINT128_BYTES*2+1];
		uint512_dump(&req->chid, chidstr, UINT512_BYTES*2+1);
		uint128_dump(&dev->vdevid, vdevstr, UINT128_BYTES*2+1);
		uint64_t dt = get_timestamp_us(dev) - req->ts;
		log_debug(lg, "Dev(%s) VDEV %s manifest %s recovery took %f sec,"
			"status %d", dev->path, vdevstr, chidstr, dt / 1000000.0f,
			req->status);
	}

	int err = recovery_send_ack(st, recovery_send_ack__done);
	if (err) {
		req->inexec--;
		req->status = err;
		state_event(st, EV_ERR);
	}
}

static void
recovery__req(struct state *st)
{
	struct recovery_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	char chidstr[UINT512_BYTES*2+1];

	log_trace(lg, "Dev(%s): st %p, inexec %d", dev->name,
	    st, req->inexec);

	if (req->inexec) {
		if (req->status == MANIFEST_PROCESSING) {
			int err = recovery_send_ack(st, recovery_send_progress_ack__done);
			if (err) {
				req->inexec--;
				req->status = err;
				state_next(st, EV_ERR);
			}
		} else
			state_next(st, EV_ERR);
		return;
	}

	req->inexec++;

	struct repmsg_recovery *msg =
		(struct repmsg_recovery *)wqe->msg;
	uint512_dump(&msg->content_hash_id, chidstr, UINT512_BYTES*2+1);
	type_tag_t tt = attr_to_type_tag(msg->hdr.attributes);
	log_debug(lg, "Dev(%s) recover request CHID %s type %s\n", dev->path,
		chidstr, type_tag_name[tt]);

	req->chid = msg->content_hash_id;
	req->tt = tt;
	req->ts = get_timestamp_us(dev);
	req->nhid = tt == TT_VERSION_MANIFEST ? msg->name_hash_id : uint512_null;
	req->flags = RECOVER_FAST;
	req->flags |= msg->hdr.attributes & RD_ATTR_RECOVERY_LAST ? RECOVER_FINAL : 0;
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_MID, recover_work_check__cb,
		recovery_work_check_done__cb, st);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_RECOVERY, recovery__req, ST_WAIT, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, recovery__error, ST_TERM, NULL }
};

int
recovery_request_init(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct recovery_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;
	req->status = -1;

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = recovery__term;
	ctx->stat_cnt = &robj->stats.recovery_active;
	reptrans_lock_ref(dev->robj_lock, ctx->stat_cnt);
	return 0;
}
