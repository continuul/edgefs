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
#include "rowevac-srv.h"

extern struct ccowd *ccow_daemon;

struct ngrequest_locate_req {
	struct repctx *ctx;
	struct repdev *dev;
	int inexec;
	struct repmsg_ngrequest_locate rsp;
};

static void
ngrequest__error(struct state *st)
{
	struct ngrequest_locate_req *req = st->data;

	log_trace(lg, "st %p", st);
}

static void
ngrequest__term(struct state *st)
{
	struct ngrequest_locate_req *req = st->data;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p inexec %d", st, req->inexec);

	assert(req->inexec >= 0);
	repctx_drop(req->ctx);

	if (req->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    req, req->inexec);
		return;
	}

	if (req->rsp.chids)
		je_free(req->rsp.chids);
	if (req->rsp.count)
		je_free(req->rsp.count);
	if (req->rsp.hash_type)
		je_free(req->rsp.hash_type);
	if (req->rsp.chunk_type)
		je_free(req->rsp.chunk_type);
	if (req->rsp.n_vbrs)
		je_free(req->rsp.n_vbrs);
	if (req->rsp.flags)
		je_free(req->rsp.flags);

	reptrans_dev_ctxfree_one(dev, req->ctx);
}

static void
ngrequest_send_done(void *data, int err, int ctx_valid)
{
	struct ngrequest_locate_req *req = data;
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
		log_error(lg, "Error %d while sending ngrequst-locate response",
		    err);
		state_event(st, EV_ERR);
		return;
	}

	state_event(st, EV_DONE);
}

static int
ngrequest_locate_ack_pack (msgpack_p* p, void* data) {
	struct repmsg_ngrequest_locate* msg =
		(struct repmsg_ngrequest_locate*)data;

	int err = msgpack_pack_uint16(p, msg->seq_num);
	if (err)
		return err;

	err = replicast_pack_uint128(p, &msg->vdev);
	if (err)
		return err;

	err = msgpack_pack_uint32(p, msg->n_chids);
	if (err)
		return err;

	for (size_t i = 0; i < msg->n_chids; i++) {
		err = msgpack_pack_uint8(p, msg->count[i]);
		if (err)
			return err;
		err = msgpack_pack_uint64(p, msg->n_vbrs[i]);
		if (err)
			return err;
		err = msgpack_pack_uint8(p, msg->flags[i]);
		if (err)
			return err;
	}
	return err;
}

static int
ngrequest_send_ack(struct state *st)
{
	struct ngrequest_locate_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	int err;

	req->inexec++;
	err = reptrans_ng_send_pack(RT_PROT_NGREQUEST_LOCATE, dev->robj,
		NULL, RT_NGREQUEST_LOCATE_ACK, (struct repmsg_generic *)wqe->msg,
		&req->rsp, ngrequest_locate_ack_pack, NULL, ngrequest_send_done, req);

	if (err) {
		req->inexec--;
	}
	return err;
}

static void
ngrequest_done(void *arg, int status)
{
	struct ngrequest_locate_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;
	struct repwqe *wqe = ctx->wqe_in;
	int err;

	log_trace(lg, "Dev(%s): warg %p, status %d inexec %d, isterm %d ",
		dev->name, arg, status, req->inexec, state_check(st, ST_TERM));

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

	err = ngrequest_send_ack(st);
	if (err)
		state_event(ctx->state, EV_ERR);
}

static void
ngrequest_exec(void *arg)
{
	struct ngrequest_locate_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	int err;

	log_trace(lg, "warg %p", arg);

	for (size_t i = 0; i < req->rsp.n_chids; i++) {
		req->rsp.count[i] = 0;
		/* CHID definitely not found */
		if (!req->rsp.chid_status[i])
			continue;
		if (req->rsp.chid_status[i] != -EEXIST) {
			struct blob_stat bstat;
			int status = reptrans_blob_stat(dev,
				req->rsp.chunk_type[i],
				req->rsp.hash_type[i],
				req->rsp.chids + i,
				&bstat);
			if (status || !bstat.size)
				continue;
		}/* Else CHID definitely found */
		req->rsp.count[i] = 1;
		if (rowevac_is_in_progress(dev, req->rsp.fhrow))
			req->rsp.flags[i] |= LOCATE_FLAG_ROWEVAC;
		if (req->rsp.op_mode & LOCATE_MATCH_VBR) {
			/* Only one CHID is supported for an entire VBR lookup */
			assert(i == 0);
			struct backref vbr;
			vbr.attr = req->rsp.attr_value;
			vbr.name_hash_id = req->rsp.name_hash_id;
			vbr.ref_chid = req->rsp.ref_chid;
			vbr.generation = req->rsp.generation;
			vbr.uvid_timestamp = req->rsp.uvid_timestamp;
			vbr.ref_type = req->rsp.ref_type;
			vbr.ref_hash = req->rsp.ref_hash;
			vbr.rep_count = req->rsp.rep_count;

			err = reptrans_vbr_stat(dev, req->rsp.hash_type[i],
				req->rsp.chids + i, &vbr);
			if (err < 0 && err != -ENOENT) {
				log_error(lg, "Dev(%s) VBR stat error %d",
					dev->name, err);
			}
			req->rsp.n_vbrs[i] = err ? 0 : 1;
		} else {
			/* Compute number of VBRs */
			const uint512_t* ref_chid =
				(req->rsp.op_mode & LOCATE_MATCH_REFCHID) ?
					&req->rsp.ref_chid : NULL;
			uint64_t attr_mask = 0;
			uint64_t* attr_value = NULL;

			if (req->rsp.op_mode & LOCATE_MATCH_VBR_ATTR) {
				attr_mask = req->rsp.attr_mask;
				attr_value = &req->rsp.attr_value;
			}
			if (ref_chid || attr_value) {
				/* In extended mode we consider only VBRs that meet
				 * required criteria(s). Max. number of VBRs is defined
				 * by a client in nvbrs_max field. Than bigger value,
				 * than slower processing is.
				 */
				int nvbrs = retrans_count_vbrs_all_repcount(dev,
					req->rsp.chids + i, req->rsp.hash_type[i],
					ref_chid, attr_mask, attr_value,
					req->rsp.nvbrs_max);
				if (nvbrs < 0)
					nvbrs = 0;
				req->rsp.n_vbrs[i] = nvbrs;
				if ((req->rsp.op_mode & LOCATE_SKIP_WO_VBRS) && !nvbrs)
					req->rsp.count[i] = 0;
			} else {
				/* This is faster. The fastest way is to set nvbrs_max = ~0UL.
				 * In this case number of VBRs can be a little bit bigger
				 * than the real number.
				 */
				size_t countp = 0;
				if (req->rsp.nvbrs_max == ~0UL)
					err = reptrans_get_depcount_coarse(dev, TT_VERIFIED_BACKREF,
						req->rsp.hash_type[i], req->rsp.chids + i, 0, &countp);
				else
					err = reptrans_get_chunk_count_limited(dev, req->rsp.hash_type[i],
						TT_VERIFIED_BACKREF, req->rsp.chids + i,
						req->rsp.nvbrs_max, &countp);
				if (err)
					countp = 0;
				req->rsp.n_vbrs[i] = countp;
				if ((req->rsp.op_mode & LOCATE_SKIP_WO_VBRS) && !countp)
					req->rsp.count[i] = 0;
			}
		}
		if ((LOCATE_FLAG_HAS_PM & req->rsp.op_mode) &&
			(req->rsp.chunk_type[i] == TT_CHUNK_MANIFEST
				|| req->rsp.chunk_type[i] == TT_VERSION_MANIFEST)) {
			struct blob_stat bs = {.size = 0 };
			err = reptrans_blob_stat(dev, TT_PARITY_MANIFEST,
				req->rsp.hash_type[i], req->rsp.chids + i, &bs);
			if (!err && bs.size)
				req->rsp.flags[i] |= LOCATE_FLAG_HAS_PM;
		}
	}
	je_free(req->rsp.chid_status);
}


static int
ngrequest_count_unpack(msgpack_u* u, void* dptr) {
	struct repmsg_ngrequest_locate* msg =
		(struct repmsg_ngrequest_locate*)dptr;

	uint32_t hdr = 0;
	int err = msgpack_unpack_uint32(u, &hdr);
	if (err)
		return err;
	msg->op_mode = hdr & 0xFFFF;
	msg->seq_num = hdr >> 16;

	if (msg->op_mode & LOCATE_MATCH_VBR) {
		struct backref vbr;
		err = reptrans_unpack_vbr(u, &vbr);
		if (err)
			return err;
		msg->attr_value = vbr.attr;
		msg->name_hash_id = vbr.name_hash_id;
		msg->ref_chid = vbr.ref_chid;
		msg->generation = vbr.generation;
		msg->uvid_timestamp = vbr.uvid_timestamp;
		msg->ref_type = vbr.ref_type;
		msg->ref_hash = vbr.ref_hash;
		msg->rep_count = vbr.rep_count;
	} else {
		if (msg->op_mode & LOCATE_MATCH_REFCHID) {
			err = replicast_unpack_uint512(u, &msg->ref_chid);
			if (err)
				return err;
		}
		if (msg->op_mode & LOCATE_MATCH_VBR_ATTR) {
			err = msgpack_unpack_uint64(u, &msg->attr_mask);
			if (err)
				return err;
			err = msgpack_unpack_uint64(u, &msg->attr_value);
			if (err)
				return err;
		}
	}

	err = msgpack_unpack_uint64(u, &msg->nvbrs_max);
	if (err)
		return err;

	err = msgpack_unpack_uint16(u, &msg->fhrow);
	if (err)
		return err;

	err = msgpack_unpack_uint32(u, &msg->n_chids);
	if (err)
		return err;

	msg->chids = je_calloc(msg->n_chids, sizeof(uint512_t));
	if (!msg->chids)
		return -ENOMEM;
	msg->hash_type = je_calloc(msg->n_chids, sizeof(uint8_t));
	if (!msg->hash_type) {
		err = -ENOMEM;
		goto _error;
	}
	msg->chunk_type = je_calloc(msg->n_chids, sizeof(uint8_t));
	if (!msg->chunk_type) {
		err = -ENOMEM;
		goto _error;
	}
	msg->count = je_calloc(msg->n_chids, sizeof(uint8_t));
	if (!msg->count) {
		err = -ENOMEM;
		goto _error;
	}
	msg->n_vbrs = je_calloc(msg->n_chids, sizeof(uint64_t));
	if (!msg->n_vbrs) {
		err = -ENOMEM;
		goto _error;
	}

	msg->flags = je_calloc(msg->n_chids, sizeof(uint8_t));
	if (!msg->flags) {
		err = -ENOMEM;
		goto _error;
	}

	for (size_t i = 0; i < msg->n_chids; i++) {
		err = replicast_unpack_uint512(u, msg->chids + i);
		if (err)
			goto _error;
		err = msgpack_unpack_uint8(u, msg->hash_type + i);
		if (err)
			goto _error;
		err = msgpack_unpack_uint8(u, msg->chunk_type + i);
		if (err)
			goto _error;
	}
	return err;

_error:
	if (msg->count)
		je_free(msg->count);
	if (msg->chunk_type)
		je_free(msg->chunk_type);
	if (msg->hash_type)
		je_free(msg->hash_type);
	if (msg->chids)
		je_free(msg->chids);
	if (msg->n_vbrs)
		je_free(msg->n_vbrs);
	if (msg->flags)
		je_free(msg->flags);
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
	struct ngrequest_locate_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	uint32_t not_found_nr = 0;
	assert(wqe);

	int err = reptrans_ng_recv_unpack(RT_PROT_NGREQUEST_LOCATE, wqe, &req->rsp,
		ngrequest_count_unpack);

	if (err) {
		if (err < 0)
			log_error(lg, "ng reptrans buffer corrupted: %d", err);
		else {
			log_error(lg, "Incompatible ngreques-locate protocol version: "
				"expected %d vs got %d",
				reptrans_get_ngproto_version(RT_PROT_NGREQUEST_LOCATE), err);
		}
		state_next(st, EV_ERR);
		return;
	}

	log_trace(lg, "Dev(%s): st %p, inexec %d", dev->name, st, req->inexec);

	if (req->inexec)
		return;

	int found = 0;
	SERVER_FLEXHASH_SAFE_CALL(found = flexhash_is_rowmember_fhrow(
		SERVER_FLEXHASH, &dev->vdevid, req->rsp.fhrow), FH_LOCK_READ);

	if (!found) {
		log_trace(lg, "Dev(%s): Not a member of row: %d. Ignoring. ",
			  dev->name, req->rsp.fhrow);
		state_next(st, EV_ERR);
		return;

	}

	req->rsp.chid_status = je_calloc(req->rsp.n_chids, sizeof (int));
	if (!req->rsp.chid_status) {
		log_trace(lg, "Dev(%s): OOM", dev->name);
		state_next(st, EV_ERR);
		return;
	}
	for (size_t i = 0; i < req->rsp.n_chids; i++) {
		uint64_t bsz = 0ULL;
		req->rsp.chid_status[i] =
			reptrans_blob_query(dev, req->rsp.chunk_type[i],
					    req->rsp.hash_type[i],
					    req->rsp.chids + i, &bsz);

		if (!req->rsp.chid_status[i])
			not_found_nr++;
	}

	req->rsp.vdev = dev->vdevid;
	/* None of the CHIDs found - return back */
	if (req->rsp.n_chids == not_found_nr) {
		je_free(req->rsp.chid_status);
		log_trace(lg, "Dev(%s): None of the CHIDs found", dev->name);
		err = ngrequest_send_ack(st);
		if (err)
			state_next(st, EV_ERR);
		return;
	}

	req->inexec++;
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, ngrequest_exec,
		ngrequest_done, req);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_NGREQUEST_LOCATE, ngrequest__req, ST_WAIT, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, ngrequest__error, ST_TERM, NULL }
};

int
ngrequest_locate_init(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct ngrequest_locate_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = ngrequest__term;
	ctx->stat_cnt = &robj->stats.ngrequest_locate_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	return 0;
}
