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
#include "ccowd-impl.h"
#include "state.h"

extern struct ccowd *ccow_daemon;

struct ngrequest_count_req {
	REQ_CLASS_FIELDS
	uv_timer_t *timer_req;
	uint512_t chid;
	uint512_t nhid;
	uint8_t hash_type;
	int32_t rep_count;
	type_tag_t chunk_type;
	fhrow_t row;
	int ndev;
	int retry;
	uint128_t *vdevs;
	uint128_t *vdevs_asked;
	int32_t n_acks;
	int32_t n_blobs;
	int stable_version;
	int (*cb)(void *, int32_t count, uint128_t *vdevs,
	    uint64_t generation_max, int stable_version);
	void *cb_data;
	int status;
	uint64_t generation;
};

#define NGREQUEST_MAX_RETRY		120
#define NGREQUEST_TIMEOUT_MS		2000
#define NGREQUEST_TIMEOUT_FIN_MS	5
#define NGREQUEST_MAX_REPLIES		REPLICAST_PROPOSALS_MAX

/*
 * ACTION: unblock caller and report error
 */
static void
ngrequest__error(struct state *st) {
	struct ngrequest_count_req *r = st->data;

	log_trace(lg, "st %p", st);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
}

struct repmsg_count_ack {
	int32_t count;
	uint128_t vdev;
	uint64_t generation;
};

static int
ngrequest_count_ack_unpack(msgpack_u* u, void* dptr) {
	struct repmsg_count_ack* msg =
		(struct repmsg_count_ack*)dptr;

	int err = msgpack_unpack_int32(u, &msg->count);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->vdev);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->generation);
	return err;
}

static void
ngrequest_timeout(uv_timer_t *treq, int status)
{
	struct state *st = treq->data;
	struct ngrequest_count_req *r = st->data;

	log_trace(lg, "treq %p, status %d", treq, status);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	if (r->status == 0) {
		state_event(st, EV_DONE);
		return;
	}
	if (r->inexec) {
		log_warn(lg, "NGREQUEST_COUNT in progress, re-schedule timeout seqid:%d.%d",
			r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt - 1);
		/* The request is in progress still, restart timeout */
		r->timer_req->data = st;
		uv_timer_start(r->timer_req, ngrequest_timeout,
			NGREQUEST_TIMEOUT_MS, 0);
		return;
	}
	log_warn(lg, "NGREQUEST_COUNT request timeout seqid:%d.%d, will retry %d",
		r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt - 1, r->retry + 1);
	state_event(st, EV_TIMEOUT);
}

/*
 * GUARD: process ack and check if we are done
 */
static int
ngrequest__ack(struct state *st)
{
	struct ngrequest_count_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_count_ack msg;
	struct repdev *dev = r->dev;

	assert(wqe);

	if (r->inexec)
		return 1;

	int err = reptrans_ng_recv_unpack(RT_PROT_NGREQUEST_COUNT, wqe, &msg,
		ngrequest_count_ack_unpack);

	if (err) {
		if (err < 0) {
			log_error(lg, "ng reptrans buffer corrupted: %d", err);
		} else {
			log_error(lg, "Incompatible ngrequest-count protocol version: "
				"expected %d vs got %d",
				reptrans_get_ngproto_version(RT_PROT_NGREQUEST), err);
		}
		/* wait for more or timeout */
		return 1;
	}
	if (r->n_acks >= NGREQUEST_MAX_REPLIES) {
		log_error(lg, "Dev(%s) ngrequest-count unexpected number of "
			"replies, max. allowed %d", dev->name,
			NGREQUEST_MAX_REPLIES);
		r->status = -ERANGE;
		state_next(st, EV_ERR);
		return 0;
	}
	/* Filter out duplicates */
	for (int i = 0 ; i < r->n_acks; i++) {
		if (!uint128_cmp(&msg.vdev, r->vdevs_asked + i))
			return 1;
	}
	r->vdevs_asked[r->n_acks] = msg.vdev;

	char vdevstr[64];
	uint128_dump(&msg.vdev, vdevstr, 64);

	log_debug_vbr(lg, "Reply(%s): st %p n_acks %d ndev %d n_blobs %d "
	    "rep_count %d row %d tt %s chid %lX", vdevstr, st, r->n_acks,
	    r->ndev, r->n_blobs, r->rep_count, r->row,
	    type_tag_name[r->chunk_type], r->chid.u.u.u);

	r->n_acks++;

	if (r->chunk_type != TT_NAMEINDEX) {
		/* negative count is blob stat error */
		if (msg.count > 0 && r->n_blobs < r->ndev) {
			r->vdevs[r->n_blobs++] = msg.vdev;
		}

		if (r->n_blobs >= r->rep_count) {
			/* Optimization: we got more positives than rep_count.*/
			r->status = 0;

			/*
			 * In CCOW design, over-replication is not as critical
			 * and in fact improves reliability and performance. The
			 * only concern is freeing up space at some point which
			 * we need to enforce when we getting closer to
			 * configurable threshold.
			 */
			double utilization =
			    (double)dev->stats.used / (double)dev->stats.capacity;
			if (utilization < dev->bg_config->dev_utilization_threshold_low) {
				state_next(st, EV_DONE);
				return 0;
			}

			/* Adjust timer to 5ms to collect a bit more answers. */
			if (r->timer_req->data)
				uv_timer_stop(r->timer_req);
			r->timer_req->data = st;
			uv_timer_start(r->timer_req, ngrequest_timeout,
			    NGREQUEST_TIMEOUT_FIN_MS, 0);
			/* wait for few more milliseconds */
			return 1;
		}
	} else if (msg.count > 0 && r->n_blobs < r->ndev) {
			if (msg.count & STABLE_VERSION_FLAG)
				r->stable_version = 1;
			if (msg.count & 1)
				r->vdevs[r->n_blobs++] = msg.vdev;
	}

	/* building concensus for any types of requests */
	if (r->n_acks < r->ndev) {
		if (r->generation < msg.generation)
			r->generation = msg.generation;
		/* keep waiting for more acks */
		return 1;
	}

	/* We got all acks we were waiting for */
	state_next(st, EV_DONE);
	r->status = 0;
	return 0;
}

static void
ngrequest_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
ngrequest__term(struct state *st)
{
	struct ngrequest_count_req *r = st->data;
	struct repdev *dev = r->dev;

	log_trace(lg, "st %p", st);

	assert(r->inexec >= 0);
	repctx_drop(r->ctx);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
			r, r->inexec);
		return;
	}

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	uv_close((uv_handle_t *)r->timer_req, ngrequest_timer_close_cb);

	char strbuf[UINT512_BYTES * 2 + 1];
	if (unlikely((lg->level <= LOG_LEVEL_DEBUG))) {
		uint512_dump(r->chunk_type == TT_NAMEINDEX ?  &r->nhid : &r->chid,
		    strbuf, UINT512_BYTES * 2 + 1);

		log_debug_vbr(lg,
			"counted %d vdevs holding blob %s, type: %s, "
			"hashType: %s, acks: %d, ndev: %d, rep_cnt: %d, "
			"retry: %d, status: %d",
			r->n_blobs, strbuf, type_tag_name[r->chunk_type],
			hash_type_name[r->hash_type], r->n_acks, r->ndev, r->rep_count,
			r->retry, r->status);
	}

	/*
	 * On timeout we still should set  n_blobs to != 0 to avoid
	 * deletion of a backref due to a temporary network outage
	 */
	if (r->status < 0) {
		uint512_dump(r->chunk_type == TT_NAMEINDEX ?  &r->nhid : &r->chid,
		    strbuf, UINT512_BYTES * 2 + 1);
		log_warn(lg, "NG request error %d: "
			"counted %d vdevs holding blob %s, type: %s, "
			"hashType: %s, acks: %d, ndev: %d, rep_cnt: %d, "
			"retry: %d", r->status,
			r->n_blobs, strbuf, type_tag_name[r->chunk_type],
			hash_type_name[r->hash_type], r->n_acks, r->ndev,
			r->rep_count, r->retry);
		r->n_blobs = r->status;
	}

	if (!dev->terminating)
		r->cb(r->cb_data, r->n_blobs, r->vdevs, r->generation, r->stable_version);
	else
		je_free(r->vdevs);
	je_free(r->vdevs_asked);
	reptrans_dev_ctxfree_one(dev, r->ctx);
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
		log_error(lg, "Error %d while sending ngrequst-count request",
		    err);
		assert(err < 0);
		req->status = err;
		state_event(st, EV_ERR);
		return;
	}
}

static int
ngrequest_count_pack (msgpack_p* p, void* data) {
	struct ngrequest_count_req* r =
		(struct ngrequest_count_req*)data;
	int err = msgpack_pack_uint8(p, r->hash_type);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &r->chid);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &r->nhid);
	if (err)
		return err;
	err = msgpack_pack_int32(p, r->chunk_type);
	if (!err && r->chunk_type == TT_NAMEINDEX)
		err = msgpack_pack_uint64(p, r->generation);
	return err;
}

static void
ngrequest__send(struct state *st)
{
	int err;
	struct ngrequest_count_req *r = st->data;
	struct repdev *dev = r->dev;

	log_trace(lg, "st %p", st);

	if (r->inexec)
		return;

	struct sockaddr_in6 send_addr;
	ccowd_fhready_lock(FH_LOCK_READ);
	flexhash_get_rowaddr(SERVER_FLEXHASH, r->row, &send_addr);
	ccowd_fhready_unlock(FH_LOCK_READ);
	send_addr.sin6_scope_id = ccow_daemon->if_indexes[0];

	if (ccow_daemon->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		r->ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	r->inexec++;
	err = reptrans_ng_send_pack(RT_PROT_NGREQUEST_COUNT, dev->robj, r->ctx,
		RT_NGREQUEST_COUNT, NULL, r, ngrequest_count_pack, &send_addr,
		ngrequest_send_done, r);

	if (err) {
		r->inexec--;
		assert(err < 0);
		r->status = err;
		state_next(st, EV_ERR);
		return;
	}

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	/*
	 * Timeout in NGREQUEST_TIMEOUT_MS mss..
	 */
	r->timer_req->data = st;
	uv_timer_start(r->timer_req, ngrequest_timeout, NGREQUEST_TIMEOUT_MS,
	    0);
}

/*
 * GUARD: check for retry < MAX_RETRY
 */
static int
ngrequest__retry(struct state *st)
{
	struct ngrequest_count_req *r = st->data;

	log_trace(lg, "st %p", st);

	if (r->dev->terminating) {
		r->status = -ENODEV;
		goto err_out;
	}

	if (++r->retry < NGREQUEST_MAX_RETRY) {
		/* flexhash might have changed since last retry */
		int ndev_new;
		int err = 0;
		int vm_parity_manifest = (r->chunk_type == TT_PARITY_MANIFEST) &&
			uint512_cmp(&r->nhid, &uint512_null);
		SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
			(r->chunk_type == TT_VERSION_MANIFEST ||
			r->chunk_type == TT_NAMEINDEX ||
			vm_parity_manifest) ? &r->nhid : &r->chid,
			&r->row, &ndev_new), FH_LOCK_READ);
		if (err < 0 || !ndev_new) {
			r->status = -EAGAIN;
			goto err_out;
		}

		if (ndev_new != r->ndev) {
			log_info(lg, "Dev(%s) NG %u: number of peers has"
				" changed (%d vs %d) ttag %s, adjusting", r->dev->path,
				r->row, r->ndev, ndev_new, type_tag_name[r->chunk_type]);
			r->ndev = ndev_new;
		}
		r->n_acks = 0;
		r->n_blobs = 0;
		repctx_reset(r->ctx);
		return 1; // ok
	}

	log_warn(lg, "NGREQUEST_COUNT request timeout after %d attempts "
	    "seqid:%d.%d", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);
	r->status = -ETIME;
err_out:
	memset(r->vdevs, 0, sizeof(uint128_t));
	state_next(st, EV_ERR);
	return 0; // fail
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_SEND, ngrequest__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, ngrequest__send, ST_WAIT, ngrequest__retry },
{ ST_WAIT, RT_NGREQUEST_COUNT_ACK, NULL, ST_WAIT, ngrequest__ack },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, ngrequest__error, ST_TERM, NULL }
};

/*
 * Count replicas in negotiating group.
 *
 * Stop when @rep_count + 1 is reached, or when all members responded,
 * or when timeout is reached.
 *
 * Call cb passing in cb_data and the number of replicas and
 * dev id's where they are.
 */
int
ngrequest_count(struct repdev *dev, uint8_t hash_type, const uint512_t *chid,
	const uint512_t *nhid, int32_t rep_count, type_tag_t ttype, uint64_t generation,
	int (*cb)(void *, int32_t, uint128_t *vdevs, uint64_t generation_max, int stable_version),
	void *cb_data)
{
	int err;

	log_trace(lg, "dev %p rep_count %d, cb %p, cb_data %p",
		dev, rep_count, cb, cb_data);

	assert(cb);
	nassert(dev->loop_thrid == uv_thread_self());

	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct ngrequest_count_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		err = -ENOMEM;
		log_error(lg, "NGREQUEST request alloc error: %d", err);
		return err;
	}
	r->dev = dev;
	r->chid = *chid;
	assert(nhid);
	r->nhid = *nhid;
	r->hash_type = hash_type;
	r->rep_count = rep_count;
	r->chunk_type = ttype;
	r->generation = generation;
	int vm_parity_manifest = (ttype == TT_PARITY_MANIFEST) &&
		uint512_cmp(nhid, &uint512_null);

	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
		(ttype == TT_VERSION_MANIFEST || ttype == TT_NAMEINDEX ||
		vm_parity_manifest) ? nhid : chid,
		&r->row, &r->ndev), FH_LOCK_READ);
	if (err < 0) {
		log_warn(lg, "NGREQUEST request for row (%d) error: %d errmsg:%s",
		    r->row, err, strerror(err));
		je_free(r);
		return err;
	}
	if (!r->ndev) {
		err = -ENODEV;
		log_warn(lg, "NGREQUEST request for row (%d) ngcount (%d) "
		    "error: %d", r->row, r->ndev, err);
		je_free(r);
		return err;
	}
	if (r->ndev < 0) {
		err = r->ndev;
		log_warn(lg, "flexhash changed while in batch send");
		je_free(r);
		return err;
	}
	r->vdevs = je_calloc(NGREQUEST_MAX_REPLIES, sizeof(uint128_t));
	if (!r->vdevs) {
		je_free(r);
		err = -ENOMEM;
		log_error(lg, "r->vdevs alloc: out of memory");
		return err;
	}
	r->vdevs_asked = je_calloc(NGREQUEST_MAX_REPLIES, sizeof(uint128_t));
	if (!r->vdevs_asked) {
		je_free(r);
		err = -ENOMEM;
		log_error(lg, "r->vdevs_asked alloc: out of memory");
		return err;
	}

	r->n_acks = 0;
	r->cb = cb;
	r->cb_data = cb_data;
	r->status = -1;

	r->state.table = trans_tbl;
	r->state.cur = ST_INIT;
	r->state.max = sizeof (trans_tbl) / sizeof (*trans_tbl);
	r->state.term_cb = ngrequest__term;
	r->state.data = r;
	r->state.io = NULL;

	r->ctx = repctx_init(dev->robj);
	if (!r->ctx) {
		je_free(r->vdevs);
		je_free(r);
		log_error(lg, "repctx alloc: out of memory");
		return -ENOMEM;
	}
	r->ctx->state = &r->state;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		repctx_destroy(r->ctx);
		je_free(r->vdevs);
		je_free(r);
		return -ENOMEM;
	}
	r->timer_req->data = NULL;
	uv_timer_init(dev->loop, r->timer_req);
	r->ctx->stat_cnt = &dev->robj->stats.ngrequest_count_active;
	reptrans_lock_ref(r->dev->robj_lock, r->ctx->stat_cnt);
	state_event(&r->state, EV_SEND);
	return 0;
}
