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

struct ngrequest_purge_req {
	REQ_CLASS_FIELDS
	uv_timer_t *timer_req;
	uint512_t nhid;
	uint64_t hi_version;
	uint64_t low_version;
	uint64_t version_uvid_timestamp;
	uint8_t is_trlog_obj;
	crypto_hash_t hash_type;
	int status;
	int retry;
};

#define NGREQUEST_MAX_RETRY	120
#define NGREQUEST_TIMEOUT_MS	250

static void
ngrequest_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

/*
 * ACTION: unblock caller and report error
 */
static void
ngrequest__error(struct state *st) {
	struct ngrequest_purge_req *r = st->data;
	log_trace(lg, "st %p", st);

	// free timer if not yet
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	r->status = -1;
}

static void
ngrequest__term(struct state *st)
{
	struct ngrequest_purge_req *r = st->data;
	struct repdev *dev = r->dev;

	log_trace(lg, "st %p", st);

	assert(r->inexec >= 0);
	repctx_drop(r->ctx);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	// free timer if not yet
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)r->timer_req, ngrequest_timer_close_cb);

	reptrans_dev_ctxfree_one(dev, r->ctx);
}

static void
ngrequest_send_done(void *data, int err, int ctx_valid)
{
	struct ngrequest_purge_req *req = data;
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
		log_error(lg, "Error %d while sending ngrequst-purge request",
		    err);
		state_event(st, EV_ERR);
		return;
	}
}

static int
ngrequest_purge_pack(msgpack_p* p, void* data) {
	struct ngrequest_purge_req* r =
		(struct ngrequest_purge_req*)data;
	int err = replicast_pack_uint512(p, &r->nhid);
	if (!err) {
		err = msgpack_pack_uint64(p, r->hi_version);
		if (err)
			return err;
		err = msgpack_pack_uint64(p, r->low_version);
		if (err)
			return err;
		err = msgpack_pack_uint64(p, r->version_uvid_timestamp);
		if (err)
			return err;
		err = msgpack_pack_uint8(p, r->is_trlog_obj);
		if (err)
			return err;
		err = msgpack_pack_uint8(p, r->hash_type);
	}
	return err;
}

static void
ngrequest_timeout(uv_timer_t *treq, int status)
{
	struct state *st = treq->data;
	struct ngrequest_purge_req *r = st->data;

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	state_event(st, EV_TIMEOUT);
}

static int
ngrequest__check(struct state *st)
{
	struct ngrequest_purge_req *r = st->data;

	ccowd_fhready_lock(FH_LOCK_READ);
	int fh_ready = flexhash_is_pristine(SERVER_FLEXHASH);
	ccowd_fhready_unlock(FH_LOCK_READ);
	if (fh_ready) {
		return 1; // ok
	}

	// check retry
	if (r->retry > NGREQUEST_MAX_RETRY) {
		log_error(lg, "Reached max retry : %d", r->retry);
		state_next(st, EV_ERR);
		return 0; // fail
	}
	r->retry++;

	// schedule timer for 250ms
	r->timer_req->data = st;
	uv_timer_start(r->timer_req, ngrequest_timeout, NGREQUEST_TIMEOUT_MS, 0);

	return 0; // fail
}

static void
ngrequest__init(struct state *st)
{
	int err;
	struct ngrequest_purge_req *r = st->data;
	struct repdev *dev = r->dev;

	log_trace(lg, "st %p", st);
	if (r->inexec)
		return;

	struct sockaddr_in6 send_addr;

	SERVER_FLEXHASH_SAFE_CALL(flexhash_get_hashaddr(SERVER_FLEXHASH,
		&r->nhid, &send_addr), FH_LOCK_READ);
	send_addr.sin6_scope_id = ccow_daemon->if_indexes[0];

	if (ccow_daemon->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		r->ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	r->inexec++;
	err = reptrans_ng_send_pack(RT_PROT_NGREQUEST_PURGE, dev->robj, r->ctx,
		RT_NGREQUEST_PURGE, NULL, r, ngrequest_purge_pack, &send_addr,
		ngrequest_send_done, r);

	if (err) {
		r->inexec--;
		state_next(st, EV_ERR);
	}
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_SEND, ngrequest__init, ST_TERM, ngrequest__check },
{ ST_INIT, EV_TIMEOUT, ngrequest__init, ST_TERM, NULL },
{ ST_ANY, EV_ANY, ngrequest__error, ST_TERM, NULL }
};


static void
reptrans_dev_async_call__purge(struct repdev_call *c)
{
	struct repdev *dev = (struct repdev *)c->args[0];
	uint8_t hash_type = (uint8_t)((uint64_t)c->args[1] & 0xff);
	uint512_t *nhid = (uint512_t *)c->args[2];
	uint64_t hi_version = (uint64_t)c->args[3];
	uint64_t low_version = (uint64_t)c->args[4];
	uint64_t version_uvid_timestamp = (uint64_t)c->args[5];
	uint8_t is_trlog_obj = (uint8_t)((uint64_t)c->args[6] & 0xff);

	assert(dev);
	assert(nhid);
	nassert(dev->loop_thrid == uv_thread_self());

	struct ngrequest_purge_req *r = je_calloc(1, sizeof (*r));
	int err = 0;
	if (!r) {
		err = - ENOMEM;
		log_error(lg, "NGREQUEST request alloc error: %d", err);
		return;
	}
	r->dev = dev;
	r->nhid = *nhid;
	je_free(nhid);
	r->hi_version = hi_version;
	r->low_version = low_version;
	r->version_uvid_timestamp = version_uvid_timestamp;
	r->is_trlog_obj = is_trlog_obj;
	r->hash_type = hash_type;

	log_debug(lg,
		"dev %s nhid %lX hi_version %ld low_version %ld version_uvid_timestamp %lu hash_type %s msg->status %d",
		dev->name, r->nhid.u.u.u, r->hi_version, r->low_version, r->version_uvid_timestamp,
		hash_type_name[r->hash_type], r->status);
	r->state.table = trans_tbl;
	r->state.cur = ST_INIT;
	r->state.max = sizeof (trans_tbl) / sizeof (*trans_tbl);
	r->state.term_cb = ngrequest__term;
	r->state.data = r;
	r->state.io = NULL;
	r->retry = 0;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		je_free(r);
		err = -ENOMEM;
		log_error(lg, "repctx alloc: out of memory");
		return;
	}
	r->timer_req->data = NULL;
	uv_timer_init(r->dev->loop, r->timer_req);

	r->ctx = repctx_init(dev->robj);
	if (!r->ctx) {
		je_free(r);
		err = -ENOMEM;
		log_error(lg, "repctx alloc: out of memory");
		return;
	}
	r->ctx->state = &r->state;

	r->ctx->stat_cnt = &dev->robj->stats.ngrequest_purge_active;
	reptrans_lock_ref(dev->robj_lock, r->ctx->stat_cnt);
	state_event(&r->state, EV_SEND);
	return;
}

/*
 * Send purge request to all devices in negotiation group.
 * Do not wait for an ack or for status.
 */
int
ngrequest_purge(struct repdev *dev, uint8_t hash_type, const uint512_t *nhid,
	uint64_t hi_version, uint64_t low_version, uint64_t version_uvid_timestamp,
	uint8_t is_trlog_obj)
{
	int err;
	if (unlikely((lg->level <= LOG_LEVEL_TRACE))) {
		char nhidstr[UINT512_BYTES * 2 + 1];
		uint512_dump(nhid, nhidstr, UINT512_BYTES * 2 + 1);
		log_trace(lg, "dev %s hash_type %s, hi_version %lu, low_version %lu, version_uvid_timestamp %lu, nhid %s",
			dev->name, hash_type_name[hash_type], hi_version, low_version, version_uvid_timestamp, nhidstr);
	}

	struct repdev_call *call = je_calloc(1, sizeof(struct repdev_call));
	if (call == NULL)
		return -ENOMEM;

	call->method = reptrans_dev_async_call__purge;
	call->args[0] = dev;
	call->args[1] = (void *)(uint64_t)hash_type;
	uint512_t *nhid_copy = je_malloc(sizeof(uint512_t));
	if (nhid_copy == NULL) {
		je_free(call);
		return -ENOMEM;
	}
	*nhid_copy = *nhid;
	call->args[2] = (void *)nhid_copy;
	call->args[3] = (void *)hi_version;
	call->args[4] = (void *)low_version;
	call->args[5] = (void *)version_uvid_timestamp;
	call->args[6] = (void *)(uint64_t)is_trlog_obj;

	QUEUE_INIT(&call->item);
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE) {
		je_free(call);
		je_free(nhid_copy);
		return -ENODEV;
	}


	uv_mutex_lock(&dev->call_mutex);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	uv_mutex_unlock(&dev->call_mutex);
	uv_async_send(&dev->call_async);

	return 0;
}
