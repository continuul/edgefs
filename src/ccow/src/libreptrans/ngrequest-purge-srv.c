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

struct ngrequest_purge_req {
	REQ_CLASS_FIELDS
	struct repmsg_ngrequest_purge rsp;
};

static void
ngrequest__error(struct state *st)
{
	struct ngrequest_req *req = st->data;

	log_trace(lg, "st %p", st);
}

static void
ngrequest__term(struct state *st)
{
	struct ngrequest_purge_req *req = st->data;
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
ngrequest_done(void* arg, int status)
{
	struct ngrequest_purge_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;
	struct repwqe *wqe = ctx->wqe_in;
	int err;

	log_trace(lg, "Dev(%s): wreq %p, inexec %d, isterm %d "
	    "status %d", dev->name, req, req->inexec,
	    state_check(st, ST_TERM), req->rsp.status);

	req->inexec--;
	if (state_check(st, ST_TERM)) {
		ngrequest__term(st);
		return;
	}
}

static void
ngrequest_exec(void* arg)
{
	struct ngrequest_purge_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	int err;

	log_trace(lg, "arg %p", arg);
	log_debug(lg,
		"dev %s nhid %lX hi_version %ld  low_version: %ld version_uvid_timestamp: %lu hash_type %s msg->status %d istrlog %d",
		dev->name, req->rsp.nhid.u.u.u, req->rsp.hi_version, req->rsp.low_version, req->rsp.version_uvid_timestamp,
		hash_type_name[req->rsp.hash_type], req->rsp.status, req->rsp.is_trlog_obj);

	req->rsp.status = reptrans_purge_versions(dev, &req->rsp.nhid,
		req->rsp.hi_version, req->rsp.low_version,
		req->rsp.version_uvid_timestamp, req->rsp.hash_type,
		req->rsp.is_trlog_obj);
}

int
ngrequest_purge_unpack(msgpack_u* u, void* dptr) {
	struct repmsg_ngrequest_purge* msg = (struct repmsg_ngrequest_purge*)dptr;
	int err = replicast_unpack_uint512(u, &msg->nhid);
	if (!err) {
		err = msgpack_unpack_uint64(u, &msg->hi_version);
		if (err)
			return err;
		err = msgpack_unpack_uint64(u, &msg->low_version);
		if (err)
			return err;
		err = msgpack_unpack_uint64(u, &msg->version_uvid_timestamp);
		if (err)
			return err;
		err = msgpack_unpack_uint8(u, &msg->is_trlog_obj);
		if (err)
			return err;
		err = msgpack_unpack_uint8(u, &msg->hash_type);
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
	struct ngrequest_purge_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	log_trace(lg, "Dev(%s): st %p, inexec %d, nhid %lX", dev->name,
	    st, req->inexec, req->rsp.nhid.u.u.u);

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (req->inexec || status == REPDEV_STATUS_UNAVAILABLE) {
		state_next(st, EV_ERR);
		return;
	}

	int err = reptrans_ng_recv_unpack(RT_PROT_NGREQUEST_PURGE, wqe,
	    &req->rsp, ngrequest_purge_unpack);

	if (err) {
		if (err < 0)
			log_error(lg, "ng reptrans buffer corrupted: %d", err);
		else {
			log_error(lg, "Incompatible ngreques-purge protocol version: "
				"expected %d vs got %d",
				reptrans_get_ngproto_version(RT_PROT_NGREQUEST_PURGE), err);
		}
		state_next(st, EV_ERR);
		return;
	}

	uint512_t *ngroup = &req->rsp.nhid;

	int found = 0;
	SERVER_FLEXHASH_SAFE_CALL(found = flexhash_is_rowmember(SERVER_FLEXHASH,
	    &dev->vdevid, ngroup), FH_LOCK_READ);
	if (!found) {
		fhrow_t row = HASHROWID(ngroup, ccow_daemon->flexhash);
		log_trace(lg, "Dev(%s): Not a member of row: %d. Ignoring. "
		    "Chid: %lX", dev->name, row, req->rsp.nhid.u.u.u);
		state_next(st, EV_ERR);
		return;

	}
	req->rsp.status = 0;
	req->inexec++;

	uint64_t outsize;
	int maybe_exists = reptrans_blob_query(dev, TT_NAMEINDEX, req->rsp.hash_type,
	    &req->rsp.nhid, &outsize);
	if (!maybe_exists) {
		/* defientely not found - do not schedule worker */
		ngrequest_done(req, 0);
		return;
	}
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_MID, ngrequest_exec, ngrequest_done, req);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_NGREQUEST_PURGE, ngrequest__req, ST_TERM, NULL },
{ ST_ANY, EV_ANY, ngrequest__error, ST_TERM, NULL }
};

int
ngrequest_purge_init(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct ngrequest_purge_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = ngrequest__term;
	ctx->stat_cnt = &robj->stats.ngrequest_purge_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	return 0;
}
