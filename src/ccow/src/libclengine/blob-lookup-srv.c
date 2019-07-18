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
#define MAX_VDEVS	10

struct blob_lookup_req {
	struct repctx *ctx;
	uv_mutex_t req_lock;
	int inexec;
	int numnodes;
	int count;
	struct repmsg_blob_lookup rsp;
	struct repmsg_blob_lookup_ack *rsp_ack;
	uint128_t vdevs[MAX_VDEVS];

};

static void
blob_lookup_result_send_done(void *data, int status, int ctx_valid) {
	struct blob_lookup_req *req = (struct blob_lookup_req*)data;
	state_event(req->ctx->state, EV_DONE);
}

static void
blob_lookup_result_done(void* arg, int status) {
	struct blob_lookup_req *req = (struct blob_lookup_req*)arg;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	int ndevs = req->rsp_ack->ndevs;
	uv_buf_t payload;
	payload.base = je_calloc(1, sizeof(uint128_t) * ndevs + 3 * ndevs);
	if (!payload.base) {
		state_next(ctx->state, EV_ERR);
		return;
	}
	payload.len = sizeof(uint128_t) * ndevs + 3 * ndevs;

	msgpack_p p;
	msgpack_pack_init_p(&p, payload);
	int err = replicast_pack_uvbuf_vdevs(&p, req->vdevs, ndevs);
	if (err)
		state_next(ctx->state, EV_ERR);

	err = replicast_send(ccow_daemon->robj[0], ctx, RT_BLOB_LOOKUP_ACK,
		(struct repmsg_generic *)req->rsp_ack, (struct repmsg_generic *)&req->rsp,
		&payload, 1, NULL, blob_lookup_result_send_done, req, NULL);

	if (err)
		state_next(ctx->state, EV_ERR);
	je_free(payload.base);
}

static void
blob_lookup_result_exec(void* arg) {
	struct blob_lookup_req *req = arg;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;

	log_trace(lg, "warg %p", arg);
}

static void
blob_lookup_exec(void *arg) {
	struct blob_lookup_req *req = arg;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct cl_node* nodes = NULL;

	log_trace(lg, "warg %p", arg);
	int err = 0;

	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_nodes(SERVER_FLEXHASH,
		&nodes, &req->numnodes, FH_NOGOOD_HC), FH_LOCK_READ);
	if (err) {
		log_error(lg, "Blob lookup request error: %d", err);
		goto err;
	}
	struct sockaddr_in6 *ip = &ccow_daemon->robj[0]->msg_origin_udpaddr;
	err = clengine_blob_lookup_request(req->rsp.ttag, req->rsp.hash_type,
			&req->rsp.chid, (uint128_t *) &ip->sin6_addr, ip->sin6_scope_id, ccow_daemon->robj[0]->udp_recv_port, req->rsp.hdr.transaction_id.sequence_num,
			req->rsp.hdr.transaction_id.sub_sequence_num, req->rsp.hdr.transaction_id.txcookie);
	if (err) {
		log_error(lg, "Blob lookup request error: %d", err);
	}
err:
	req->inexec--;
}

static void
blob_lookup_done_cb(void* arg, int status) {

}
/*
 * ACTION: process RT_BLOB_LOOKUP request
 *
 * Return same message back to a caller
 */
static void
blob_lookup__req(struct state *st)
{
	struct blob_lookup_req* req = (struct blob_lookup_req*)st->data;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	struct repmsg_blob_lookup *msg =
		(struct repmsg_blob_lookup *)wqe->msg;

	if (req->inexec) {
		return;
	}
	req->rsp.chid = msg->chid;
	req->rsp.hash_type = msg->hash_type;
	req->rsp.ttag = msg->ttag;
	req->rsp = *(struct repmsg_blob_lookup *)wqe->msg;
	req->inexec++;
	ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_NORMAL, blob_lookup_exec, blob_lookup_done_cb,
		req);
}

static void
blob_lookup__result(struct state *st)
{
	struct blob_lookup_req* req = (struct blob_lookup_req*)st->data;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;

	assert(wqe);

	struct repmsg_blob_lookup_result *msg =
		(struct repmsg_blob_lookup_result *)wqe->msg;

	if (req->inexec) {
		return;
	}
	uv_mutex_lock(&req->req_lock);
	ctx->sub_sequence_cnt--;
	req->numnodes--;
	msgpack_u *u = msgpack_unpack_init(repwqe_payload(wqe), repwqe_payload_len(wqe), 0);
	int err = replicast_unpack_uvbuf_vdevs(u, msg->ndevs, req->vdevs + req->count);
	if (err) {
		msgpack_unpack_free(u);
		state_next(ctx->state, EV_ERR);
		return;
	}
	msgpack_unpack_free(u);
	req->count += msg->ndevs;

	if (req->numnodes == 0) {
		req->rsp_ack = je_calloc(1, sizeof(struct repmsg_blob_lookup_ack));
		if (!req->rsp_ack) {
			log_error(lg, "blob_lookup_result alloc: out of memory: -ENOMEM");
			state_next(st, EV_ERR);
			return;
		}
		req->rsp_ack->ndevs = req->count;

		req->inexec++;
		ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_NORMAL, blob_lookup_result_exec,
			blob_lookup_result_done, req);
	}
	uv_mutex_unlock(&req->req_lock);
}

static void
blob_lookup__term(struct state *st)
{
	struct blob_lookup_req* req = (struct blob_lookup_req*)st->data;
	st->data = NULL;
	if (!req)
		return;
	struct repctx *ctx = req->ctx;
	repctx_drop(ctx);
	req->inexec--;
	je_free(req->rsp_ack);
	repctx_destroy(ctx);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_BLOB_LOOKUP, &blob_lookup__req, ST_WAIT, NULL },
{ ST_ANY, RT_BLOB_LOOKUP_RESULT, &blob_lookup__result, ST_WAIT, NULL },
{ ST_ANY, EV_ANY, &blob_lookup__term, ST_TERM, NULL }
};

int
blob_lookup_srv_init(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	struct blob_lookup_req* req = je_calloc(1, sizeof(struct blob_lookup_req));
	if (!req)
		return -ENOMEM;
	req->ctx = ctx;
	req->inexec = 0;
	req->count = 0;
	uv_mutex_init(&req->req_lock);
	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = blob_lookup__term;
	return 0;
}
