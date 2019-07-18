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

struct ngrequest_count_req {
	REQ_CLASS_FIELDS
	struct repmsg_ngrequest_count rsp;
};

static void
ngrequest__error(struct state *st)
{
	struct ngrequest_count_req *req = st->data;

	log_trace(lg, "st %p", st);
}

static void
ngrequest__term(struct state *st)
{
	struct ngrequest_count_req *req = st->data;
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
	struct ngrequest_count_req *req = data;
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
		log_error(lg, "Error %d while sending ngrequst-count response",
		    err);
		state_event(st, EV_ERR);
		return;
	}

	state_event(st, EV_DONE);
}

static int
ngrequest_count_ack_pack (msgpack_p* p, void* data) {
	struct repmsg_ngrequest_count* msg =
		(struct repmsg_ngrequest_count*)data;
	int err = msgpack_pack_int32(p, msg->count);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->vdev);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->generation);
	return err;
}

static void
ngrequest_done(void *arg, int status)
{
	struct ngrequest_count_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;
	struct repwqe *wqe = ctx->wqe_in;
	int err;
	char vdevstr[UINT128_BYTES*2+1];
	uint128_dump(&dev->vdevid, vdevstr, UINT128_BYTES*2+1);

	log_trace(lg, "Dev(%s) VDEV %s: warg %p, status %d inexec %d, isterm %d "
	    "cnt %d chid %lX", dev->name, vdevstr, arg, status, req->inexec,
	    state_check(st, ST_TERM), req->rsp.count, req->rsp.chid.u.u.u);

	req->inexec--;
	if (state_check(st, ST_TERM)) {
		ngrequest__term(st);
		return;
	}

	if (status != 0) {
		log_error(lg, "Dev(%s): transport returned non-zero "
		    "status %d", dev->name, status);
		state_event(ctx->state, EV_ERR);
		return;
	}

	req->inexec++;
	err = reptrans_ng_send_pack(RT_PROT_NGREQUEST_COUNT, dev->robj,
		NULL, RT_NGREQUEST_COUNT_ACK, (struct repmsg_generic *)wqe->msg,
		&req->rsp, ngrequest_count_ack_pack, NULL, ngrequest_send_done, req);

	if (err) {
		req->inexec--;
		state_event(ctx->state, EV_ERR);
		return;
	}
}

static void
ngrequest_exec(void *arg)
{
	struct ngrequest_count_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	int err;

	log_trace(lg, "warg %p", arg);

	req->rsp.count = 0;
	req->rsp.vdev = dev->vdevid;

	if (req->rsp.chunk_type != TT_NAMEINDEX) {
		struct blob_stat bstat;
		int status = reptrans_blob_stat(dev, req->rsp.chunk_type,
			req->rsp.hash_type, &req->rsp.chid, &bstat);
		if (status < 0) {
			req->rsp.count = status;
		} else if (bstat.size > 0) {
			req->rsp.count = 1;
		}
		return;
	}

	/*
	 * Get latest generation for the requested NHID
	 */
	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation = 0
	};
	rtbuf_t *rb_vers = NULL;
	err = reptrans_get_versions(dev, &req->rsp.nhid, &query, &rb_vers);
	if (err == -ENOENT) {
		req->rsp.generation = 0;
		req->rsp.count = err;
		log_debug(lg, "Get(%s): name index not found ENOENT", dev->name);
		return;
	} else if (err) {
		req->rsp.generation = 0;
		req->rsp.count = err;
		if (err != EBUSY)
			log_error(lg, "Get(%s): error (%d) while reading versions",
				dev->name, err);
		return;
	}
	assert(rb_vers);
	assert(rb_vers->nbufs >= 1);
	/*
	 * When the requested generation is 0, then it wants the latest GenID.
	 */
	req->rsp.count = req->rsp.generation == 0 ? 1 : 0;
	if (req->rsp.generation) {
		/* If a requested generation matches a local "stable version",
		 * then inform the peer about it.
		 */
		uint64_t sv_gen = 0, sv_ts;
		int err = reptrans_stable_version_get(dev, &req->rsp.nhid,
			&sv_gen, &sv_ts);
		if (!err && sv_gen == req->rsp.generation) {
			req->rsp.count |= STABLE_VERSION_FLAG;
		}
	}
	uint64_t gen_max = 0;
	for (size_t i = 0; i < rb_vers->nbufs; i++) {
		struct vlentry* vl = (struct vlentry*)rtbuf(rb_vers,i).base;
		if (vl->generation == req->rsp.generation)
			req->rsp.count = 1;
		if (gen_max < vl->generation)
			gen_max = vl->generation;
	}
	req->rsp.generation = gen_max;
	rtbuf_destroy(rb_vers);
}


static int
ngrequest_count_unpack(msgpack_u* u, void* dptr) {
	struct repmsg_ngrequest_count* msg =
		(struct repmsg_ngrequest_count*)dptr;

	int err = msgpack_unpack_uint8(u, &msg->hash_type);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->chid);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->nhid);
	if (err)
		return err;
	err = msgpack_unpack_int32(u, &msg->chunk_type);
	if (!err && msg->chunk_type == TT_NAMEINDEX)
		err = msgpack_unpack_uint64(u, &msg->generation);
	else
		msg->generation = 0;
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
	struct ngrequest_count_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	log_trace(lg, "Dev(%s): st %p, inexec %d, chid %lX", dev->name,
	    st, req->inexec, req->rsp.chid.u.u.u);

	if (req->inexec) {
		state_next(st, EV_ERR);
		return;
	}

	int err = reptrans_ng_recv_unpack(RT_PROT_NGREQUEST_COUNT, wqe,
	    &req->rsp, ngrequest_count_unpack);

	if (err) {
		if (err < 0)
			log_error(lg, "Dev(%s): ng reptrans buffer corrupted: "
			    "%d", dev->name, err);
		else {
			log_error(lg, "Dev(%s): Incompatible ngreques-count "
			    "protocol version: expected %d vs got %d", dev->name,
			    reptrans_get_ngproto_version(RT_PROT_NGREQUEST), err);
		}
		state_next(st, EV_ERR);
		return;
	}

	uint512_t *ngroup = &req->rsp.chid;
	if (req->rsp.chunk_type == TT_VERSION_MANIFEST ||
	    req->rsp.chunk_type == TT_NAMEINDEX ||
	    ((req->rsp.chunk_type == TT_PARITY_MANIFEST) &&
		(uint512_cmp(&req->rsp.nhid, &uint512_null))))
		ngroup = &req->rsp.nhid;

	int found = 0;
	SERVER_FLEXHASH_SAFE_CALL(found = flexhash_is_rowmember(SERVER_FLEXHASH,
	    &dev->vdevid, ngroup), FH_LOCK_READ);
	if (!found) {
		fhrow_t row = HASHROWID(ngroup, ccow_daemon->flexhash);
		log_trace(lg, "Dev(%s): Not a member of row: %d. Ignoring. "
		    "Chid: %lX", dev->name, row, req->rsp.chid.u.u.u);
		state_next(st, EV_ERR);
		return;

	}

	/*
	 * Need to verify that this row NGCOUNT is reasonable
	 */
	if (req->rsp.chunk_type == TT_NAMEINDEX) {
		fhrow_t row;
		int ngcount;
		int err = 0;
		SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
			ngroup, &row, &ngcount), FH_LOCK_READ);
		if (err < 0)  {
			if (err != -EAGAIN)
				log_error(lg, "Get(%s): row (%d) error (%d) while "
					"reading versions", dev->name, row, err);
			state_next(st, EV_ERR);
			return;
		}
		if (!ngcount) {
			err = -ENODEV;
			log_error(lg, "Get(%s): row (%d) ngcount (%d) error "
			    "(%d) while reading versions", dev->name, row,
			    ngcount, err);
			state_next(st, EV_ERR);
			return;
		}

	}

	req->rsp.count = 0;
	uint64_t outsize;
	int maybe_exists = reptrans_blob_query(dev, req->rsp.chunk_type, req->rsp.hash_type,
	    req->rsp.chunk_type == TT_NAMEINDEX ? &req->rsp.nhid : &req->rsp.chid,
	    &outsize);
	if (!maybe_exists) {
		/* defientely not found - do not schedule worker */
		req->rsp.vdev = dev->vdevid;
		req->rsp.count = -ENOENT;
	}
	if (maybe_exists != -1 && is_keycache_tt(req->rsp.chunk_type)) {
		req->rsp.vdev = dev->vdevid;
		if (maybe_exists == -EEXIST)
			req->rsp.count = 1;
		else
			req->rsp.count = -ENOENT;
	}

	req->inexec++;
	if (req->rsp.count) {
		/* got result */
		ngrequest_done(req, 0);
		return;
	}
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, ngrequest_exec, ngrequest_done, req);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_NGREQUEST_COUNT, ngrequest__req, ST_WAIT, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, ngrequest__error, ST_TERM, NULL }
};

int
ngrequest_count_init(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct ngrequest_count_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = ngrequest__term;
	ctx->stat_cnt = &robj->stats.ngrequest_count_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	return 0;
}
