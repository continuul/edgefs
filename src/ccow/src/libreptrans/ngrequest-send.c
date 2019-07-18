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

struct ngrequest_req {
	REQ_CLASS_FIELDS
	uv_timer_t *timer_req;
	fhrow_t fhrow;
	char *message;
	ngrequest_send_cb_t cb;
	void *cb_data;
	uint32_t message_size;
	int n_acks;
	int ndev;
	int retry;
	int status;
	uint128_t target_vdev;
};
#define NGREQUEST_MAX_RETRY	120
#define NGREQUEST_TIMEOUT_MS	10000

/*
 * ACTION: unblock caller and report error
 */
static void
ngrequest__error(struct state *st) {
	struct ngrequest_req *r = st->data;

	log_trace(lg, "st %p", st);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
}

static void
ngrequest_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
ngrequest__term(struct state *st)
{
	struct ngrequest_req *r = st->data;
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

	if(!dev->terminating)
		r->cb(r->cb_data, r->status);

	je_free(r->message);

	reptrans_dev_ctxfree_one(dev, r->ctx);
}

/*
 * ACTION: process ack
 */
static int
ngrequest__ack(struct state *st)
{
	struct ngrequest_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	int err = 0;

	log_trace(lg, "st %p", st);

	if (r->inexec)
		return 1;

	rtbuf_t* rtb = NULL;
	err = reptrans_ng_recv(RT_PROT_NGREQUEST, wqe, &rtb);
	if (err) {
		if ( err == -EINVAL)
			log_error(lg, "ng reptrans buffer corrupted: %d", err);
		else {
			log_error(lg, "Incompatible ngreques protocol version: "
				"expected %d vs got %d",
				reptrans_get_ngproto_version(RT_PROT_NGREQUEST), err);
		}
		/* wait for more or timeout */
		return 1;
	}

	int status;
	if (rtb->bufs[0].len != sizeof (int8_t)) {
		status = -EBADF;
		log_error(lg, "received incorrect ngrequest response %d", status);
	} else {
		r->n_acks++;
		status = *(int8_t *)rtb->bufs[0].base;
		if (status) {
			log_warn(lg, "Dev(%s) ngrequest got response %d",
				r->dev->name, status);
			r->status = status;
			state_next(st, EV_DONE);
			rtbuf_destroy(rtb);
			return 0;
		}
	}
	rtbuf_destroy(rtb);

	/* building concensus for payload responses */
	if (r->n_acks < r->ndev) {
		/* keep waiting for more acks */
		return 1;
	}
	log_debug(lg, "Dev(%s) ngrequest done, n_acks %d, ndev %d, NG %u, "
		"retries %d, status %d, genid %lu", r->dev->name, r->n_acks, r->ndev,
		r->fhrow, r->retry, status, SERVER_FLEXHASH->genid);
	/* We got all acks we were waiting for */
	state_next(st, EV_DONE);
	r->status = 0; /* success */
	return 0;
}

static void
ngrequest_timeout(uv_timer_t *treq, int status)
{
	struct state *st = treq->data;
	struct ngrequest_req *r = st->data;

	log_trace(lg, "treq %p, status %d", treq, status);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		treq->data = NULL;
	}
	if (r->status == 0) {
		state_event(st, EV_DONE);
		return;
	}
	if (r->inexec) {
		log_warn(lg, "NGREQUEST request is in progress, restart timeout"
		    "seqid:%d.%d", r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt - 1);
		r->timer_req->data = st;
		uv_timer_start(r->timer_req, ngrequest_timeout, NGREQUEST_TIMEOUT_MS,
		    0);
		return;
	}
	log_warn(lg, "NGREQUEST request timeout after %d attempts (message_size=%u) "
	    "seqid:%d.%d", r->retry + 1, r->message_size, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);
	state_event(st, EV_TIMEOUT);
}

static void
ngrequest_send_done(void *data, int err, int ctx_valid)
{
	struct ngrequest_req *req = data;
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

}

static int
ngrequest_pack (msgpack_p* p, void* data) {
	struct ngrequest_req* r =
		(struct ngrequest_req*)data;
	int err = msgpack_pack_raw(p, r->message, r->message_size);
	if (!err) {
		err = msgpack_pack_uint16(p, r->fhrow);
	}
	return err;
}

static void
ngrequest__send(struct state *st)
{
	int err;
	struct ngrequest_req *r = st->data;
	struct repdev *dev = r->dev;

	log_trace(lg, "st %p", st);

	if (r->inexec)
		return;

	struct sockaddr_in6 send_addr = {.sin6_port = 0 };
	if (uint128_cmp(&r->target_vdev, &uint128_null) == 0) {
		/* Sending multicast to the negotiation group */
		ccowd_fhready_lock(FH_LOCK_READ);
		flexhash_get_rowaddr(SERVER_FLEXHASH, r->fhrow, &send_addr);
		ccowd_fhready_unlock(FH_LOCK_READ);
		if (ccow_daemon->unicastio == REPLICAST_UNICAST_UDP_MCPROXY)
			r->ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
		else if (ccow_daemon->unicastio == REPLICAST_UNICAST_TCP)
			r->ctx->attributes = RD_ATTR_UNICAST_TCP;
	} else {
		/* Sending to a target VDEV by means of an unicast message */
		struct dlist *dl = NULL;
		ccowd_fhready_lock(FH_LOCK_READ);

		dl = flexhash_devicelist(SERVER_FLEXHASH, r->fhrow);
		if (!dl) {
			ccowd_fhready_unlock(FH_LOCK_READ);
			log_error(lg, "Dev(%s) empty dl list for row %u",
				dev->name, r->fhrow);
				state_next(st, EV_ERR);
				return;
		}

		struct fhdev *fhdevptr = dl->devlist;
		while (fhdevptr != NULL) {
			struct lvdev *list_vdev = fhdevptr->vdev;
			fhdevptr = fhdevptr->next;
			if (!uint128_cmp(&list_vdev->vdevid, &r->target_vdev)) {
				if (list_vdev->state == VDEV_STATE_DEAD) {
					ccowd_fhready_unlock(FH_LOCK_READ);
					log_error(lg, "Dev(%s) the target VDEV %016lX%016lX is DEAD",
						dev->name, r->target_vdev.u, r->target_vdev.l);
					state_next(st, EV_ERR);
					return;
				}
				struct fhserver *server = list_vdev->server;
				memcpy((void *) &send_addr.sin6_addr, &server->ipaddr, 16);
				send_addr.sin6_family = AF_INET6;
				struct lvdev *lvdev = vdevstore_get_lvdev(SERVER_FLEXHASH->vdevstore, &r->target_vdev);
				if (!lvdev) {
					ccowd_fhready_unlock(FH_LOCK_READ);
					log_error(lg, "Dev(%s) cannot fetch lvdev for %016lX%016lX",
						dev->name, r->target_vdev.u, r->target_vdev.l);
					state_next(st, EV_ERR);
					return;
				}
				send_addr.sin6_port = htons(lvdev->port);

#if 0
				/* TODO: remove conditional when it's fully tested */
				char dst[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &send_addr.sin6_addr, dst, INET6_ADDRSTRLEN);

				log_debug(lg, "Dev(%s) sending tgt prop to VDEV %016lX%016lX SRV %016lX%016lX IPv6 %s IPID %016lx%016lX row %u port %u",
					dev->name, r->target_vdev.u, r->target_vdev.l, server->id.u, server->id.l,
					dst, server->ipaddr.u, server->ipaddr.l, r->fhrow, ntohs(send_addr.sin6_port));
#endif
				break;
			}
		}
		ccowd_fhready_unlock(FH_LOCK_READ);
		if (ccow_daemon->unicastio == REPLICAST_UNICAST_TCP)
			r->ctx->attributes = RD_ATTR_UNICAST_TCP;
	}
	send_addr.sin6_scope_id = ccow_daemon->if_indexes[0];

	if (!send_addr.sin6_port) {
		log_error(lg, "Dev(%s) couldn't find target VDEV", dev->name);
		state_next(st, EV_ERR);
		return;
	}

	r->inexec++;
	err = reptrans_ng_send_pack(RT_PROT_NGREQUEST, dev->robj, r->ctx,
		RT_NGREQUEST, NULL, r, ngrequest_pack, &send_addr,
		ngrequest_send_done, r);

	if (err) {
		r->inexec--;
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
	struct ngrequest_req *r = st->data;

	if (r->dev->terminating) {
		goto err_out;
	}

	log_trace(lg, "st %p", st);

	if (++r->retry < NGREQUEST_MAX_RETRY) {
		r->n_acks = 0;
		repctx_reset(r->ctx);
		return 1; // ok
	}

	log_error(lg, "NGREQUEST request timeout after %d attempts "
	    "seqid:%d.%d", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

err_out:
	r->status = -ETIME;
	state_next(st, EV_ERR);
	return 0; // fail
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_SEND, ngrequest__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, ngrequest__send, ST_WAIT, ngrequest__retry },
{ ST_WAIT, RT_NGREQUEST_ACK, NULL, ST_WAIT, ngrequest__ack },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, ngrequest__error, ST_TERM, NULL }
};

void
ngrequest_send_async__callback(struct repdev_call *c)
{
	struct repdev* dev = (struct repdev *) c->args[0];
	uint16_t fhrow = (long) c->args[1];
	char *message = (char *) c->args[2];
	uint32_t size = (unsigned long) c->args[3];
	ngrequest_send_cb_t cb = (ngrequest_send_cb_t)c->args[4];
	void *cb_data = c->args[5];
	uint128_t* tgt = c->args[6];

	log_trace(lg, "dev %p, fhrow %d, message %p, size %u, cb %p, "
	    "cb_data %p", dev, fhrow, message, size, cb, cb_data);

	assert(cb);
	nassert(dev->loop_thrid == uv_thread_self());

	struct ngrequest_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		if (cb)
			cb(cb_data, -ENOMEM);
		log_error(lg, "NGREQUEST request alloc error");
		return;
	}
	r->dev = dev;
	r->fhrow = fhrow;
	int err = 0;
	if (tgt) {
		r->target_vdev = *tgt;
		je_free(tgt);
		r->ndev = 1;
	} else {
		SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
			NULL, &fhrow, &r->ndev), FH_LOCK_READ);
		if (err < 0) {
			if (err != -EAGAIN)
				log_error(lg, "Unable to retrieve ngcount row(%d) err(%d): %s",
					fhrow, err, strerror(err));
			if (cb)
				cb(cb_data, err);

			je_free(r);
			return;
		}
	}
	if (!r->ndev && !tgt) {
		if (cb)
			cb(cb_data, -ENODEV);
		if (r->ndev > 0)
			log_error(lg, "NGREQUEST request for row (%d) ngcount (%d) "
			    " less than expected", fhrow, r->ndev);
		je_free(r);
		return;
	}
	r->status = -1;
	r->message = message;
	r->message_size = size;
	r->cb = cb;
	r->cb_data = cb_data;

	r->state.table = trans_tbl;
	r->state.cur = ST_INIT;
	r->state.max = sizeof (trans_tbl) / sizeof (*trans_tbl);
	r->state.term_cb = ngrequest__term;
	r->state.data = r;
	r->state.io = NULL;

	r->ctx = repctx_init(dev->robj);
	if (!r->ctx) {
		if (cb)
			cb(cb_data, -ENOMEM);
		log_error(lg, "repctx alloc: out of memory");
		je_free(r);
		return;
	}
	r->ctx->state = &r->state;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		if (cb)
			cb(cb_data, -ENOMEM);
		repctx_destroy(r->ctx);
		je_free(r);
		return;
	}
	r->timer_req->data = NULL;
	uv_timer_init(dev->loop, r->timer_req);

	r->ctx->stat_cnt = &dev->robj->stats.ngrequest_send_active;
	reptrans_lock_ref(dev->robj_lock, r->ctx->stat_cnt);
	state_event(&r->state, EV_SEND);
	return;
}

int
ngrequest_send(struct repdev *dev, uint16_t fhrow, char *message,
    uint32_t size, ngrequest_send_cb_t cb, void *cb_data)
{
	ccowd_wait_for_fhrebuild_term(&dev->terminating);

	struct repdev_call *call = je_calloc(1, sizeof(struct repdev_call));

	if (call == NULL)
		return -ENOMEM;
	uint8_t *msgbuf = je_malloc(size * sizeof(uint8_t));
	if (msgbuf == NULL) {
		je_free(call);
		return -ENOMEM;
	}

	memcpy(msgbuf, message, size);

	call->method = ngrequest_send_async__callback;
	call->args[0] = dev;
	call->args[1] = (void *)(long)fhrow;
	call->args[2] = (void *)msgbuf;
	call->args[3] = (void *)(unsigned long)size;
	call->args[4] = (void *)cb;
	call->args[5] = (void *)cb_data;
	call->args[6] = (void *)NULL;
	QUEUE_INIT(&call->item);
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE) {
		je_free(msgbuf);
		je_free(call);
		return -ENODEV;
	}
	uv_mutex_lock(&dev->call_mutex);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	uv_mutex_unlock(&dev->call_mutex);
	uv_async_send(&dev->call_async);

	return 0;
}

int
ngrequest_send_targeted(struct repdev *dev, uint16_t fhrow, const uint128_t* tgt_vdev,
	char *message, uint32_t size, ngrequest_send_cb_t cb, void *cb_data)
{
	ccowd_wait_for_fhrebuild_term(&dev->terminating);

	struct repdev_call *call = je_calloc(1, sizeof(struct repdev_call));

	if (call == NULL)
		return -ENOMEM;
	uint8_t *msgbuf = je_malloc(size * sizeof(uint8_t));
	if (msgbuf == NULL) {
		je_free(call);
		return -ENOMEM;
	}

	memcpy(msgbuf, message, size);

	uint128_t* tgt = (uint128_t*)je_memdup((const char*)tgt_vdev, sizeof(uint128_t));
	if (!tgt) {
		je_free(msgbuf);
		je_free(call);
		return -ENOMEM;
	}

	call->method = ngrequest_send_async__callback;
	call->args[0] = dev;
	call->args[1] = (void *)(long)fhrow;
	call->args[2] = (void *)msgbuf;
	call->args[3] = (void *)(unsigned long)size;
	call->args[4] = (void *)cb;
	call->args[5] = (void *)cb_data;
	call->args[6] = (void *)tgt;
	QUEUE_INIT(&call->item);
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE) {
		je_free(msgbuf);
		je_free(call);
		return -ENODEV;
	}
	uv_mutex_lock(&dev->call_mutex);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	uv_mutex_unlock(&dev->call_mutex);
	uv_async_send(&dev->call_async);

	return 0;
}
