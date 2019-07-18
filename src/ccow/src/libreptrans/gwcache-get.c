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

#include "getcommon_server.h"
#include "gwcache.h"
#include "flexhash.h"

extern gwcache_stats_t gw_stats;
extern volatile unsigned long gw_cache_throttle;

static void
gwcachedget_srv__error(struct state *st)
{
	struct getcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repmsg_unnamed_chunk_get *msg = &req->msg_in.unnamed_get;
	struct repmsg_generic *reply;
	int err;

	log_error(lg, "st %p prev state: %d prev event: %d\n",
		   st, st->prev, st->ev_prev);

	req->err.num_datagrams = 1;
	req->err.error = req->status;
	req->err.vdevid = dev->vdevid;
	reply = (struct repmsg_generic *) &req->err;


	req->inexec++;
	err = replicast_send(dev->robj, ctx, RT_ERROR, reply,
	    (struct repmsg_generic *)msg, NULL, 0, NULL,
	    srv_getcommon_send_done, req, NULL);
	if (err) {
		req->inexec--;
		assert(req->inexec >= 0);
	}
	state_event(st, EV_DONE);
}

static void
gwcachedget_srv_done(void* arg, int status)
{
	struct getcommon_srv_req *req = arg;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;
	struct repdev *dev = req->dev;
	struct repmsg_unnamed_chunk_get *msg = &req->msg_in.unnamed_get;
	int err;

	log_trace(lg, "arg %p, status %d", arg, status);

	req->inexec--;
	assert(req->inexec >= 0);
	dev->get_disk_qdepth--;

	if (state_check(st, ST_TERM)) {
		srv_getcommon_terminate(st);
		return;
	}

	if (status != 0) {
		log_error(lg, "Get(%s): transport returned non-zero "
		    "status %d", dev->name, status);
		state_event(ctx->state, EV_ERR);
		return;
	}

	enum replicast_opcode reply_opcode;
	struct repmsg_generic *reply;
	uv_buf_t *bufs = NULL;
	int nbufs = 0;

	if (req->status == 0) {
		req->unnamed_rsp.num_datagrams = 1;
		reply = (struct repmsg_generic *)&req->unnamed_rsp;
		reply_opcode = RT_UNNAMED_CHUNK_GET_RESPONSE;

		if (!req->rtproposed) {
			if (req->rb_reply) {
				bufs = req->rb_reply->bufs;
				nbufs = req->rb_reply->nbufs;
				assert(nbufs != 0);
				assert(bufs != NULL);
			}
		}
	} else {
		req->err.num_datagrams = 1;
		req->err.error = req->status;
		req->err.vdevid = dev->vdevid;
		reply = (struct repmsg_generic *) &req->err;
		reply_opcode = RT_ERROR;
	}
	req->inexec++;
	err = replicast_send(dev->robj, ctx, reply_opcode, reply,
	    (struct repmsg_generic *)msg, bufs, nbufs, NULL,
	    srv_getcommon_send_done, req, NULL);
	if (err) {
		req->inexec--;
		assert(req->inexec >= 0);
		state_event(ctx->state, EV_ERR);
		return;
	}
	gw_lru_update(&msg->content_hash_id);
	state_event(st, EV_DONE);
}

static void
gwcachedget_srv_exec(void *arg)
{
	struct getcommon_srv_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repmsg_unnamed_chunk_get *msg = &req->msg_in.unnamed_get;
	char chidstr[UINT512_BYTES*2+1];
	uint512_t *chid;
	int err, len, in_cache;
	rtbuf_t *rb;
	uint64_t attrs;

	crypto_hash_t hash_type = msg->hdr.hash_type;
	attrs = msg->hdr.attributes;
	type_tag_t tt = attr_to_type_tag(attrs);

	log_trace(lg, "arg %p: tt %d", arg, tt);

	if (tt != TT_CHUNK_PAYLOAD && tt != TT_CHUNK_MANIFEST) {
		req->status = RT_ERROR;
		return;
	}

	chid = &msg->content_hash_id;
	uint512_dump(chid, chidstr, UINT512_BYTES*2+1);

	/* Check CHID on the device */
	err = reptrans_get_blob(dev, tt, hash_type, chid, &rb);
	if (err) {
		log_debug(lg, "GW-cache chid %s NOT found on device err: %d",
		    chidstr, err);
		gwcachedget_fetch_chid(dev, attrs, req->chunk_offset, chid, hash_type);
		gw_stats.misses++;
		return;
	} else {
		log_debug(lg, "GW-cache chid %s found on device err: %d",
		    chidstr, err);
		gw_stats.hits++;
	}

	req->reqtype = GET_REQ_TYPE_UNNAMED;
	req->unnamed_rsp.content_hash_id = msg->content_hash_id;
	memcpy(&req->unnamed_rsp.vdevid, &dev->vdevid, sizeof (uint128_t));
	req->unnamed_rsp.num_datagrams = 1;
	req->unnamed_rsp.content_length = rtbuf_len(rb);
	req->unnamed_rsp.hdr.data_len = req->unnamed_rsp.content_length;
	req->unnamed_rsp.immediate_content_length
		= req->unnamed_rsp.content_length;
	req->rb_reply = rb;
	req->status = 0;
}

static void
gwcachedget_srv__request(struct state *st)
{
	struct getcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repwqe *wqe = ctx->wqe_in;

	log_trace(lg, "st %p", st);

	unsigned long tmp = atomic_aaf(&gw_cache_throttle, 1);

	if (tmp >= 1024) {
		state_next(st, EV_DONE);
		atomic_dec(&gw_cache_throttle);
		return;
	}

	struct repmsg_unnamed_chunk_get *msg =
		(struct repmsg_unnamed_chunk_get *)wqe->msg;
	req->select_time_avg = msg->select_time_avg;
	req->hash_type = msg->hdr.hash_type;
	req->attributes = msg->hdr.attributes;
	req->tt = attr_to_type_tag(msg->hdr.attributes);
	req->chunk_offset = msg->chunk_offset;
	memcpy(&req->msg_in.unnamed_get, wqe->msg, sizeof (req->msg_in.unnamed_get));

	req->inexec++;
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, gwcachedget_srv_exec,
			gwcachedget_srv_done, req);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_UNNAMED_CHUNK_GET, &gwcachedget_srv__request, ST_READY, NULL },
{ ST_READY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_READY, EV_ERR, &gwcachedget_srv__error, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &gwcachedget_srv__error, ST_TERM, NULL }
};

int
gwcachedget_srv_init(struct replicast *robj, struct repctx *ctx,
		   struct state *state)
{
	int err;
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct getcommon_srv_req *req = je_calloc(1, sizeof (*req));
	if (req == NULL)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	req->start_timer_req = je_malloc(sizeof (*req->start_timer_req));
	if (!req->start_timer_req) {
		je_free(req);
		return -ENOMEM;
	}

	req->timer_req = je_malloc(sizeof (*req->timer_req));
	if (!req->timer_req) {
		je_free(req->start_timer_req);
		je_free(req);
		return -ENOMEM;
	}

	req->start_timer_fd = uv_hpt_timer_init(req->dev->loop,
						req->start_timer_req);
	if (req->start_timer_fd < 0) {
		err = req->start_timer_fd;
		je_free(req->timer_req);
		je_free(req->start_timer_req);
		je_free(req);
		log_error(lg, "Cached GET hpt start init error: %d", err);
		return err;
	}
	uv_timer_init(req->dev->loop, req->timer_req);

	state_init(ctx->state, trans_tbl, sizeof(trans_tbl)/sizeof(*trans_tbl),
		   req, srv_getcommon_terminate);
	ctx->stat_cnt = &robj->stats.cacheget_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	return 0;
}

