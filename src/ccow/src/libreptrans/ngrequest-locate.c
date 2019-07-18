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
#include "erasure-coding.h"
#include "state.h"

#define REQ_BATCH_SIZE	650

extern struct ccowd *ccow_daemon;

struct ngrequest_locate_req {
	REQ_CLASS_FIELDS
	uv_timer_t* timer_req;
	rtbuf_t* chunk_info;
	uint64_t nvbrs_max;
	uint32_t rep_count; /* expected replication count */
	uint128_t* vdevs_asked;
	uint32_t   n_acks;
	fhrow_t row;
	uint32_t ndev; /* Number of devices in a row*/
	uint512_t nhid;
	uint32_t from;
	uint32_t to;
	uint32_t op_mode;
	struct backref vbr;
	uint64_t attr_mask;
	uint16_t seq_num;
	int retry;
	int (*cb)(void *, int32_t status, rtbuf_t* cinfo);
	void *cb_data;
	int status;
};
/*
 * ACTION: unblock caller and report error
 */
static void
ngrequest__error(struct state *st) {
	struct ngrequest_locate_req *r = st->data;

	log_trace(lg, "st %p", st);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	if (!r->status)
		r->status = -EIO;
}

struct repmsg_locate_ack {
	uint16_t  seq_num;
	uint128_t vdev;
	uint32_t n_counts;
	uint8_t* counts;
	uint64_t* n_vbrs;
	uint8_t* flags;
};

static int
ngrequest_locate_ack_unpack(msgpack_u* u, void* dptr) {
	struct repmsg_locate_ack* msg =
		(struct repmsg_locate_ack*)dptr;
	int err = msgpack_unpack_uint16(u, &msg->seq_num);
	if (err)
		return err;

	err = replicast_unpack_uint128(u, &msg->vdev);
	if (err)
		return err;

	err = msgpack_unpack_uint32(u, &msg->n_counts);
	if (err)
		return err;

	for (size_t i = 0; i < msg->n_counts; i++) {
		uint8_t aux;
		err = msgpack_unpack_uint8(u, msg->counts + i);
		if (err)
			return err;

		err = msgpack_unpack_uint64(u, msg->n_vbrs + i);
		if (err)
			return err;

		err = msgpack_unpack_uint8(u, &aux);
		if (err)
			return err;
		msg->flags[i] = aux;
	}
	return err;
}
/*
 * GUARD: process ack and check if we are done
 */
static int
ngrequest__ack(struct state *st)
{
	struct ngrequest_locate_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_locate_ack msg;

	assert(wqe);

	log_trace(lg, "st %p n_acks %d rep_count %d row %d",
	    st, r->n_acks, r->rep_count, r->row);

	if (r->dev->terminating) {
		r->status = -ENODEV;
		state_next(st, EV_ERR);
		return 1;
	}

	msg.counts = je_calloc(r->to - r->from + 1, sizeof(uint8_t));
	if (!msg.counts) {
		log_error(lg, "Memory allocation error");
		r->status = -ENOMEM;
		state_next(st, EV_ERR);
		return 1;
	}

	msg.n_vbrs = je_calloc(r->to - r->from + 1, sizeof(uint64_t));
	if (!msg.n_vbrs) {
		log_error(lg, "Memory allocation error");
		r->status = -ENOMEM;
		state_next(st, EV_ERR);
		je_free(msg.counts);
		return 1;
	}

	msg.flags = je_calloc(r->to - r->from + 1, sizeof(uint8_t));
	if (!msg.flags) {
		log_error(lg, "Memory allocation error");
		r->status = -ENOMEM;
		state_next(st, EV_ERR);
		je_free(msg.n_vbrs);
		je_free(msg.counts);
		return 1;
	}


	int err = reptrans_ng_recv_unpack(RT_PROT_NGREQUEST_LOCATE, wqe, &msg,
		ngrequest_locate_ack_unpack);

	if (err) {
		if (err < 0)
			log_error(lg, "ng reptrans buffer corrupted: %d", err);
		else {
			log_error(lg, "Incompatible ngrequest-count protocol version: "
				"expected %d vs got %d",
				reptrans_get_ngproto_version(RT_PROT_NGREQUEST_LOCATE), err);
		}
		je_free(msg.counts);
		je_free(msg.n_vbrs);
		je_free(msg.flags);
		r->status = err;
		state_next(st, EV_ERR);
		return 1;
	}

	if (msg.seq_num != r->seq_num) {
		return 1;
	}
	if (r->n_acks >= NGREQUEST_MAX_REPLIES) {
		je_free(msg.counts);
		je_free(msg.n_vbrs);
		r->status = -ERANGE;
		state_next(st, EV_ERR);
		return 1;
	}
	/* Filter out duplicates */
	for (uint32_t i = 0 ; i < r->n_acks; i++) {
		if (!uint128_cmp(&msg.vdev, r->vdevs_asked + i))
			return 1;
	}
	r->vdevs_asked[r->n_acks] = msg.vdev;

	assert (msg.n_counts == r->to - r->from);
	size_t n_ready = 0;
	for (size_t i = r->from; i < r->to; i++) {
		int pos = i - r->from;
		struct chunk_info* info = chinfo(r->chunk_info, i);
		if (info->n_vdevs < r->ndev && msg.counts[pos] > 0 &&
				info->n_vdevs < REPTRANS_NREPLICAS_MAX) {
			info->vdevs[info->n_vdevs] = msg.vdev;
			if (info->n_vbrs_max < msg.n_vbrs[pos])
				info->n_vbrs_max = msg.n_vbrs[pos];
			if (info->n_vbrs_min > msg.n_vbrs[pos])
				info->n_vbrs_min = msg.n_vbrs[pos];
			info->nvbrs[info->n_vdevs] = msg.n_vbrs[pos];
			info->flags |= msg.flags[pos];
			info->n_vdevs++;
		}
		if (r->rep_count && r->rep_count < info->n_vdevs)
			n_ready++;
	}
	r->n_acks++;
	je_free(msg.counts);
	je_free(msg.n_vbrs);
	je_free(msg.flags);

	if (n_ready == r->to -r->from || r->n_acks >= r->ndev) {
		/* We got all acks we were waiting for */
		struct chunk_info* info = chinfo(r->chunk_info, 0);
		log_trace(lg, "ng-locate done, info %p, n_acks=%u, n_ready=%lu,"
			"n_vdevs=%u, rep_count=%u, n_vbrs_min=%lu,  n_vbrs_max=%lu",
			info, r->n_acks, n_ready, info->n_vdevs, r->rep_count,
			info->n_vbrs_min, info->n_vbrs_max);
		if (r->to < r->chunk_info->nbufs) {
			r->n_acks = 0;
			r->retry = 0;
			r->from = r->to;
			r->to += REQ_BATCH_SIZE;
			if (r->to > r->chunk_info->nbufs)
				r->to = r->chunk_info->nbufs;
			r->seq_num++;
			state_next(st, EV_SEND);
		} else
			state_next(st, EV_DONE);
		return 0;
	}
	return 1;
}

static void
ngrequest_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
ngrequest__term(struct state *st)
{
	struct ngrequest_locate_req *r = st->data;
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

	if (!dev->terminating) {
		for (size_t i = 0; i < r->chunk_info->nbufs; i++) {
			struct chunk_info* info = chinfo(r->chunk_info, i);
			if (info->n_vdevs == 0) {
				info->n_vbrs_max = info->n_vbrs_min = 0;
			}
		}
		r->cb(r->cb_data, r->status, r->chunk_info);
	}

	if (r->vdevs_asked)
		je_free(r->vdevs_asked);

	uint32_t *stat_cnt = r->ctx->stat_cnt;
	reptrans_dev_ctxfree_one(dev, r->ctx);
}

static void
ngrequest_timeout(uv_timer_t *treq, int status)
{
	struct state *st = treq->data;
	struct ngrequest_locate_req *r = st->data;

	log_trace(lg, "treq %p, status %d", treq, status);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	if (r->dev->terminating) {
		r->status = -ENODEV;
		state_event(st, EV_ERR);
	} else {
		if (r->inexec) {
			log_warn(lg, "NGREQUEST_LOCATE is in progress "
				"seqid:%d.%d, restarting timeout",
				r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt - 1);
			r->timer_req->data = st;
			uv_timer_start(r->timer_req, ngrequest_timeout,
				NGREQUEST_TIMEOUT_MS, 0);
			return;
		}
		log_warn(lg, "NGREQUEST_LOCATE request timeout seqid:%d.%d, will retry %d",
			r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt - 1, r->retry + 1);
		state_event(st, EV_TIMEOUT);
	}
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
		log_error(lg, "Error %d while sending ngrequst-count request",
		    err);
		req->status = err;
		state_event(st, EV_ERR);
		return;
	}
}

static int
ngrequest_locate_pack (msgpack_p* p, void* data) {
	struct ngrequest_locate_req* r =
		(struct ngrequest_locate_req*)data;
	uint32_t hdr = (((uint32_t)r->seq_num) << 16) | r->op_mode;
	int err = msgpack_pack_uint32(p, hdr);
	if (err)
		return err;
	if (r->op_mode & LOCATE_MATCH_VBR) {
		err = reptrans_pack_vbr(p, &r->vbr);
		if (err)
			return err;
	} else {
		if (r->op_mode & LOCATE_MATCH_REFCHID) {
			err = replicast_pack_uint512(p, &r->vbr.ref_chid);
			if (err)
				return err;
		}
		if (r->op_mode & LOCATE_MATCH_VBR_ATTR) {
			err = msgpack_pack_uint64(p, r->attr_mask);
			if (err)
				return err;

			err = msgpack_pack_uint64(p, r->vbr.attr);
			if (err)
				return err;
		}
	}
	err = msgpack_pack_uint64(p, r->nvbrs_max);
	if (err)
		return err;

	err = msgpack_pack_uint16(p, r->row);
	if (err)
		return err;

	err = msgpack_pack_uint32(p, r->to - r->from);
	if (err)
		return err;

	for (size_t i = r->from; i < r->to; i++) {
		struct chunk_info* info = chinfo(r->chunk_info, i);
		err = replicast_pack_uint512(p, &info->chid);
		if (err)
			return err;
		err = msgpack_pack_uint8(p, info->hash_type);
		if (err)
			return err;
		err = msgpack_pack_uint8(p, info->ttype);
		if (err)
			return err;
	}
	return err;
}

static void
ngrequest__send(struct state *st)
{
	int err;
	struct ngrequest_locate_req *r = st->data;
	struct repdev *dev = r->dev;

	log_trace(lg, "st %p", st);

	struct sockaddr_in6 send_addr;

	ccowd_fhready_lock(FH_LOCK_READ);
	flexhash_get_rowaddr(SERVER_FLEXHASH, r->row, &send_addr);
	ccowd_fhready_unlock(FH_LOCK_READ);
	send_addr.sin6_scope_id = ccow_daemon->if_indexes[0];

	if (ccow_daemon->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		r->ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	r->inexec++;
	err = reptrans_ng_send_pack(RT_PROT_NGREQUEST_LOCATE, dev->robj, r->ctx,
		RT_NGREQUEST_LOCATE, NULL, r, ngrequest_locate_pack, &send_addr,
		ngrequest_send_done, r);

	if (err) {
		r->inexec--;
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
	struct ngrequest_locate_req *r = st->data;

	log_trace(lg, "st %p", st);
	repdev_status_t status = reptrans_dev_get_status(r->dev);
	if(r->dev->terminating || status == REPDEV_STATUS_UNAVAILABLE) {
		r->status = -ENODEV;
		goto err_out;
	}

	if (++r->retry < NGREQUEST_MAX_RETRY) {
		/* Flexhash might have changed since last retry */
		struct chunk_info* pinfo = chinfo(r->chunk_info, 0);
		int nh = uint512_cmp(&r->nhid, &uint512_null);
		int ndevs_new;
		int err = 0;
		SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
			(nh ? &r->nhid : &pinfo->chid), &r->row, &ndevs_new), FH_LOCK_READ);
		if (err < 0) {
			if (err != -EAGAIN)
				log_error(lg, "NGREQUEST_LOCATE unable to get ngcount err: %d",
					err);
			r->status = -EAGAIN;
			goto err_out;
		}
		if (!ndevs_new) {
			log_error(lg, "NGREQUEST_LOCATE wrong ngcount %d",
				r->ndev);
			r->status = -EAGAIN;
			goto err_out;
		}
		if ((uint32_t)ndevs_new != r->ndev) {
			log_notice(lg, "Dev(%s) NG %u: number of peers has"
				"changed (%d vs %d), adjusting", r->dev->path,
				r->row, r->ndev, ndevs_new);
			r->ndev = ndevs_new;
		}
		r->n_acks = 0;
		for (size_t i = r->from; i < r->to; i++) {
			struct chunk_info* pinfo = chinfo(r->chunk_info, i);
			pinfo->n_vdevs = 0;
		}
		repctx_reset(r->ctx);
		pthread_yield();
		return 1; // ok
	}

	log_error(lg, "NGREQUEST_LOCATE request timeout after %d attempts "
	    "seqid:%d.%d", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);
	r->status = -ENOENT;
err_out:
	state_next(st, EV_ERR);
	return 0; // fail
}

static void
ngrequest_rterr(struct state *st) {
	struct ngrequest_locate_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repdev *dev = r->dev;
	struct repmsg_error* msg = (struct repmsg_error*)wqe->msg;
	log_warn(lg, "ngrequest_rterr: RT_ERROR received, errcode: %d",
		msg->error);
	r->status = -EAGAIN;
	state_next(st, EV_ERR);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_SEND, ngrequest__send, ST_WAIT, NULL },
{ ST_WAIT, EV_SEND, ngrequest__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, ngrequest__send, ST_WAIT, ngrequest__retry },
{ ST_WAIT, RT_NGREQUEST_LOCATE_ACK, NULL, ST_WAIT, ngrequest__ack },
{ ST_WAIT, RT_ERROR, ngrequest_rterr, ST_TERM, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, ngrequest__error, ST_TERM, NULL }
};

void
ngrequest_locate__async (struct repdev_call *c) {
	int err = 0;
	struct ngrequest_locate_req *r =  c->args[0];
	assert(r);
	assert(r->cb);
	assert(r->chunk_info);
	assert(r->dev);
	nassert(r->dev->loop_thrid == uv_thread_self());
	/*
	 * to establish NG we use the first CHID is used as they all belong
	 * to the same NG
	 */
	int use_nhid = uint512_cmp(&r->nhid, &uint512_null);
	struct chunk_info* pinfo = chinfo(r->chunk_info, 0);
	int ngcount;

	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
			(use_nhid ? &r->nhid : &pinfo->chid), &r->row, &ngcount), FH_LOCK_READ);
	if (err < 0) {
		log_warn(lg, "NGREQUEST-LOCATE request for row (%d) error: %d",
		    r->row, err);
		goto _exit_at_error;

	}
	if (!ngcount) {
		err = -EAGAIN;
		log_warn(lg, "NGREQUEST-LOCATE request for row (%d) ngcount (%d) "
		    "error: %d", r->row, ngcount, err);
		goto _exit_at_error;
	}
	r->ndev = ngcount;
	r->vdevs_asked = je_calloc(NGREQUEST_MAX_REPLIES, sizeof(uint128_t));
	if (!r->vdevs_asked) {
		err = -ENOMEM;
		goto _exit_at_error;
	}
	for (size_t i = 0; i < r->chunk_info->nbufs; i++) {
		struct chunk_info* pinfo = chinfo(r->chunk_info, i);
		pinfo->n_vbrs_min = ~0UL;
		pinfo->n_vbrs_max = 0;
		pinfo->n_vdevs = 0;
	}
	r->from = 0;
	r->to = r->chunk_info->nbufs > REQ_BATCH_SIZE ? REQ_BATCH_SIZE :r->chunk_info->nbufs;

	r->state.table = trans_tbl;
	r->state.cur = ST_INIT;
	r->state.max = sizeof (trans_tbl) / sizeof (*trans_tbl);
	r->state.term_cb = ngrequest__term;
	r->state.data = r;
	r->state.io = NULL;

	r->ctx = repctx_init(r->dev->robj);
	if (!r->ctx) {
		err = -ENOMEM;
		log_error(lg, "repctx alloc: out of memory");
		goto _exit_at_error;
	}
	r->ctx->state = &r->state;
	r->timer_req = je_calloc(1, sizeof(*r->timer_req));
	uv_timer_init(r->dev->loop, r->timer_req);

	r->ctx->stat_cnt = &r->dev->robj->stats.ngrequest_locate_active;
	reptrans_lock_ref(r->dev->robj_lock, r->ctx->stat_cnt);
	state_event(&r->state, EV_SEND);
	return;

_exit_at_error:
	if (r->vdevs_asked)
		je_free(r->vdevs_asked);
	if (r->cb)
		r->cb(r->cb_data, err, NULL);
	je_free(r);
	return;
}

int
ngrequest_locate(struct repdev *dev, rtbuf_t* chunk_info, int32_t rep_count,
	const uint512_t *nhid, size_t n_vbrs_max, ng_locate_cb_t cb, void *cb_data) {

	ccowd_wait_for_fhrebuild_term(&dev->terminating);

	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct ngrequest_locate_req *r = je_calloc(1, sizeof (*r));
	if (!r)
		return -ENOMEM;
	struct repdev_call *call = je_calloc(1, sizeof(struct repdev_call));

	if (call == NULL) {
		je_free(r);
		return -ENOMEM;
	}
	r->op_mode = 0;
	r->chunk_info = chunk_info;
	r->dev = dev;
	r->rep_count = rep_count;
	r->nhid = nhid ? *nhid : uint512_null;
	r->cb = cb;
	r->cb_data = cb_data;
	r->nvbrs_max = n_vbrs_max;
	call->method = ngrequest_locate__async;
	call->args[0] = r;
	QUEUE_INIT(&call->item);
	uv_mutex_lock(&dev->call_mutex);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	uv_mutex_unlock(&dev->call_mutex);
	uv_async_send(&dev->call_async);
	return 0;
}

int
ngrequest_locate_ext(struct repdev *dev, rtbuf_t* chunk_info, int32_t rep_count,
	const uint512_t *nhid, struct backref* vbr, uint64_t attr_mask,
	size_t n_vbrs_max, uint32_t mode, ng_locate_cb_t cb, void *cb_data) {

	int err = 0;
	ccowd_wait_for_fhrebuild_term(&dev->terminating);

	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct ngrequest_locate_req *r = je_calloc(1, sizeof (*r));
	if (!r)
		return -ENOMEM;
	struct repdev_call *call = je_calloc(1, sizeof(struct repdev_call));

	if (call == NULL) {
		je_free(r);
		return -ENOMEM;
	}
	r->op_mode = 0;
	r->chunk_info = chunk_info;
	r->dev = dev;
	r->rep_count = rep_count;
	r->nhid = nhid ? *nhid : uint512_null;
	r->op_mode = mode;
	if (mode & LOCATE_MATCH_VBR) {
		r->vbr = *vbr;
	} else {
		if (mode & LOCATE_MATCH_REFCHID)
			r->vbr.ref_chid = vbr->ref_chid;

		if (mode & LOCATE_MATCH_VBR_ATTR) {
			r->vbr.attr = vbr->attr;
			r->attr_mask = attr_mask;
		}
	}
	r->cb = cb;
	r->cb_data = cb_data;
	r->nvbrs_max = n_vbrs_max;

	call->method = ngrequest_locate__async;
	call->args[0] = r;
	QUEUE_INIT(&call->item);
	uv_mutex_lock(&dev->call_mutex);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	uv_mutex_unlock(&dev->call_mutex);
	uv_async_send(&dev->call_async);
	return 0;
}
