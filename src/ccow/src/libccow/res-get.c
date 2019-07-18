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
#include <stdlib.h>
#include <string.h>

#include "ccow.h"
#include "ccow-impl.h"
#include "hashtable.h"


#define CLIENT_RESGET_MAX_RETRY 5
#define CLIENT_RESGET_TIMEOUT	10000000

/*
 * ACTION: unblock caller and report error
 */
static void
resget__error(struct state *st) {
	struct getres_client_req *r = st->data;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_error *msg = (struct repmsg_error *)wqe->msg;

	log_trace(lg, "st %p seqid %d.%d error %d",
			st, ctx->sequence_cnt, ctx->sub_sequence_cnt,
			op->status);
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	if (uint128_cmp(&msg->vdevid, &r->tgt_vdevid) == 0) {
		log_debug(lg, "Could not get resource err %d\n", msg->error);
		op->status = msg->error;
		ccow_fail_io(io, msg->error);
		state_next(st, EV_DONE);
	} else
		log_debug(lg, "Received error from NON target. It's ok");
}

void
getres_timeout(uv_timer_t *treq, int status)
{
	struct state *st = treq->data;
	struct getres_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;

	log_trace(lg, "treq %p, status %d seqid %d.%d", treq, status,
		ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (r->timer_req->data) {
		uv_timer_stop(treq);
		r->timer_req->data = NULL;
	}
	tc->get_retry_cnt++;
	state_event(st, EV_TIMEOUT);
}

/*
 * ACTION: process RES GET response
 */
static void
resget__ack(struct state *st)
{
	int err;
	int ev = EV_DONE;
	struct getres_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct ccow_completion *comp = op->comp;
	struct ccow *tc = comp->tc;

	assert(op->optype);
	assert(wqe);

	struct repmsg_res_get_response *msg =
		(struct repmsg_res_get_response *)wqe->msg;

	log_trace(lg, "st %p: imm_len %d io %p seqid %u.%u, %s", st,
	    msg->immediate_content_length, io, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, ccow_op2str(op->optype));

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	/* We expect RES data to be immediate */
	if (msg->immediate_content_length) {
		op->status = 0;
		r->in_payload.bufs[0].len = msg->immediate_content_length;
		r->in_payload.bufs[0].base  = repwqe_payload(wqe);
	}

	state_next(st, ev);
}

static int
resget_guard_retry(struct state *st)
{
	struct getres_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;

	r->retry++;
	if (r->retry < CLIENT_RESGET_MAX_RETRY) {
		if (tc->abort) {
			ccow_fail_io(r->io, -EINTR);
			state_next(st, EV_ERR);
			return 0;
		}
		return 1;
	}
	log_error(lg, "RES GET request timed out after %d attempts"
			" seqid %d.%d", r->retry,
			r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt - 1);
	ccow_fail_io(r->io, -ETIME);
	state_next(st, EV_ERR);
	return 0;
}

static void
resget__send(struct state *st)
{
	struct getres_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = io->comp;
	struct ccow_network *netobj = tc->netobj;
	struct sockaddr_in6 to_addr = { 0 };
	char dest[INET6_ADDRSTRLEN + 1] = { 0 };
	uint128_t target_vdevid;
	char vdevstr[UINT128_BYTES*2+1];
	char namestr[UINT512_BYTES*2+1];
	uint16_t row;
	int err, new_timeout;

	log_trace(lg, "st %p attr 0x%lu seqid %d.%d", st, io->attributes,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	struct repmsg_res_get msg;
	memset(&msg, 0, sizeof (msg));

	row = HASHROWID(&c->vm_name_hash_id, tc->flexhash);

	if (flexhash_find_master(tc->flexhash, &c->vm_name_hash_id,
				 c->shard_index, &target_vdevid) != 0) {
		log_debug(lg, "Could not find master VDEV in row %d", row);
		ccow_fail_io(st->io, -EIO);
		state_next(st, EV_ERR);
		return;
	}

	r->tgt_vdevid = target_vdevid;
	uint128_dump(&target_vdevid, vdevstr, UINT128_BYTES*2+1);

	/*
	 * We have to use multicast. We cannot use unicast because
	 * we don't know the device port no.
	 */
	struct lvdev *lvdev;
	lvdev = flexhash_get_lvdev(tc->flexhash, row, &target_vdevid);
	if (!lvdev) {
		log_debug(lg, "Could not find master VDEV in row %d", row);
		ccow_fail_io(st->io, -EIO);
		state_next(st, EV_ERR);
		return;
	}
	memcpy(&to_addr.sin6_addr, &lvdev->server->ipaddr, 16);
	to_addr.sin6_port = htons(lvdev->server->port);
	to_addr.sin6_family = AF_INET6;

	/* for resources associated with NHID */
	msg.object_name.name_hash_id = c->vm_name_hash_id;
	msg.res_maj_id = r->maj_res;
	msg.res_min_id = r->minor_res;
	msg.tgt_vdevid = r->tgt_vdevid;
	msg.immediate_content_length = rtbuf_len(&r->out_payload);
	uint512_dump(&c->vm_name_hash_id, namestr, UINT512_BYTES * 2 + 1);
	log_trace(lg, "Name hash id : %s", namestr);

	/* For debugging */
	uv_ip6_name(&to_addr, dest, INET6_ADDRSTRLEN);
	log_debug(lg, "Connecting to lock server %s.%d", dest,
			ntohs(to_addr.sin6_port));

	r->inexec++;
	msg.hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;
	err = replicast_udp_send(netobj->robj[0], ctx, RT_RES_GET,
		(struct repmsg_generic *) &msg, NULL,
		r->out_payload.bufs, r->out_payload.nbufs,
		&to_addr, 1, replicast_send_done_generic, NULL, st,
		NULL, row);
	if (err) {
		r->inexec--;
		log_error(lg, "RES GET operation error %d on send", err);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);

	r->timer_req->data = st;
	new_timeout = CLIENT_RESGET_TIMEOUT;
	uv_timer_start(r->timer_req, getres_timeout, new_timeout, 0);
}

static void
resget__init(struct state *st)
{
	struct getres_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;

	log_trace(lg, "st %p", st);

	r->ctx = repctx_init(netobj->robj[0]);
	if (!r->ctx) {
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		repctx_destroy(r->ctx);
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}

	r->ctx->state = st;
	r->timer_req->data = NULL;
	uv_timer_init(tc->loop, r->timer_req);

	resget__send(st);
}

static void
resget__terminate(struct state *st)
{
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct getres_client_req *r = st->data;

	repctx_drop(r->ctx);
	ccow_complete_io(io);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, resget__init, ST_READY, NULL },
{ ST_READY, EV_TIMEOUT, resget__send, ST_READY, resget_guard_retry },
{ ST_READY, RT_RES_GET_RESPONSE, resget__ack, ST_READY, NULL },
{ ST_READY, RT_ERROR, resget__error, ST_READY, NULL },
{ ST_READY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, NULL, ST_TERM, NULL }
};

int
ccow_resget_create(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, getres_client_callback_t done_cb,
    ccow_op_t optype, struct ccow_op **pop, struct ccow_io **pio)
{
	int err;
	struct ccow_completion *c = comp;

	assert(optype == CCOW_GET_RES);

	log_trace(lg, "cid %p, cid_size %ld, tid %p, tid_size %ld, "
	    "bid %p, bid_size %ld, oid %p, oid_size %ld, comp %p, "
	    "done_cb %p, %s, pop %p, pio %p",
	    cid, cid_size, tid, tid_size, bid, bid_size, oid, oid_size,
	    comp, done_cb, ccow_op2str(optype), pop, pio);

	struct getres_client_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		err = -ENOMEM;
		log_error(lg, "RES GET request alloc error: %d", err);
		return err;
	}

	*pop = NULL;
	*pio = NULL;

	r->tc = c->tc;
	r->done_cb = done_cb;

	err = ccow_operation_create(c, optype, pop);
	if (err) {
		log_error(lg, "RES GET request operation alloc error: %d", err);
		goto _err_exit;
	}
	(*pop)->cid = je_memdup(cid, cid_size);
	if (!(*pop)->cid) {
		err = -ENOMEM;
		goto _err_exit;
	}
	(*pop)->tid = je_memdup(tid, tid_size);
	if (!(*pop)->cid) {
		err = -ENOMEM;
		goto _err_exit;
	}
	(*pop)->bid = je_memdup(bid, bid_size);
	if (!(*pop)->cid) {
		err = -ENOMEM;
		goto _err_exit;
	}
	(*pop)->oid = je_memdup(oid, oid_size);
	if (!(*pop)->cid) {
		err = -ENOMEM;
		goto _err_exit;
	}
	(*pop)->cid_size = cid_size;
	(*pop)->tid_size = tid_size;
	(*pop)->bid_size = bid_size;
	(*pop)->oid_size = oid_size;

	(*pop)->uvid_timestamp = get_timestamp_us();
	(*pop)->shard_index = c->shard_index;

	err = ccow_create_io(c, *pop, optype, trans_tbl,
	    sizeof (trans_tbl) / sizeof (*trans_tbl), r,
	    resget__terminate, pio);
	if (err) {
		goto _err_exit;
	}
	r->io = *pio;
	err = ccow_build_name_hashes(comp, (*pop));
	if (err)
		goto _err_exit;

	c->vm_name_hash_id = (*pop)->name_hash_id;
	return 0;

_err_exit:
	if (*pop)
		ccow_operation_destroy(*pop, 1);
	if (*pio)
		ccow_destroy_io(*pio); /* this will free "r" */
	else
		je_free(r);
	return err;
}
