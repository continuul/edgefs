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
#include "ccow-impl.h"
#include "opp-status.h"
#include "state.h"

struct opp_status_req {
	CCOW_CLASS_FIELDS
	struct ccow_network *netobj;
	uint512_t vmchid;
	uint512_t nhid;
	opp_status_t* result;
	int32_t flags;
};

/*
 * ACTION: unblock caller and report error
 */
static void
opps_state__error(struct state *st) {
	struct opp_status_req *r = st->data;
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
}

/*
 * ACTION: process response
 */
static void
opps_state__response(struct state *st)
{
	struct opp_status_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	int err;

	struct repmsg_opps_result *msg =
		(struct repmsg_opps_result *)wqe->msg;
	if (msg->status) {
		log_error(lg, "OPP STATUS ended up with error code %d",
			msg->status);
		ccow_fail_io(st->io, msg->status);
		state_next(st, EV_ERR);
		return;
	}

	r->result->n_cm_tl = msg->n_cm_tl;
	r->result->n_cm_zl = msg->n_cm_zl;
	r->result->n_cp = msg->n_cp;
	r->result->n_cpar = msg->n_cpar;
	r->result->n_cm_zl_verified = msg->n_cm_zl_verified;
	r->result->n_cm_tl_verified = msg->n_cm_tl_verified;
	r->result->n_cp_verified = msg->n_cp_verified;
	r->result->n_cpar_verified = msg->n_cpar_verified;
	r->result->n_cm_zl_1vbr = msg->n_cm_zl_1vbr;
	r->result->n_cm_tl_1vbr = msg->n_cm_tl_1vbr;
	r->result->n_cp_1vbr = msg->n_cp_1vbr;
	r->result->n_cm_zl_lost = msg->n_cm_zl_lost;
	r->result->n_cm_tl_lost = msg->n_cm_tl_lost;
	r->result->n_cp_lost = msg->n_cp_lost;
	r->result->n_cpar_lost = msg->n_cpar_lost;
	r->result->n_cm_zl_pp = msg->n_cm_zl_pp;
	r->result->n_cm_zl_erc_err = msg->n_cm_zl_erc_err;
	r->result->n_cm_tl_erc_err = msg->n_cm_tl_erc_err;
	r->result->pp_algo = msg->pp_algo;
	r->result->pp_data_number = msg->pp_data_number;
	r->result->pp_parity_number = msg->pp_parity_number;
	r->result->pp_domain = msg->pp_domain;
	r->result->n_vdevs = msg->n_vdevs;
	r->result->vdevs_usage = msg->vdevs_usage;
	r->result->hostid = msg->hostid;
}

static void
opps_send_timeout(uv_timer_t *req, int status)
{
	struct state *st = req->data;
	struct opp_status_req *r = st->data;
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	log_warn(lg, "OOP STATUS request timeout after %d attempts "
	    "seqid:%d.%d", r->retry + 1, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);
	state_event(st, EV_TIMEOUT);
}

/*
 * ACTION: Prepare and send OPPS_STATUS request
 */
static void
opps_state__send(struct state *st)
{
	int err;
	struct opp_status_req *r = st->data;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;

	struct repmsg_opps msg;
	memset(&msg, 0, sizeof (msg));
	msg.vmchid = r->vmchid;
	msg.nhid = r->nhid;
	msg.flags = r->flags;

	if (tc->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		r->ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
		msg.hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	struct sockaddr_in6 send_addr;
	flexhash_get_hashaddr(tc->flexhash, &r->nhid, &send_addr);
	send_addr.sin6_scope_id = netobj->if_indexes[0];
	r->inexec++;
	err = replicast_send(netobj->robj[0], r->ctx, RT_OPP_STATUS,
		(struct repmsg_generic *)&msg, NULL, NULL, 0,
		&send_addr, replicast_send_done_generic, st, NULL);
	if (err) {
		r->inexec--;
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	/*
	 * Timeout in OPP_STATUS_TIMEOUT_MS mss..
	 */
	r->timer_req->data = st;
	uv_timer_start(r->timer_req, opps_send_timeout, OPP_STATUS_TIMEOUT_MS, 0);
}

/*
 * GUARD: check for retry < MAX_RETRY
 */
static int
opps_guard__retry(struct state *st)
{
	struct opp_status_req *r = st->data;

	if (++r->retry < OPP_STATUS_MAX_RETRY)
		return 1; // ok

	log_error(lg, "BLOB LOOKUP request timeout after %d attempts "
	    "seqid:%d.%d", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

	ccow_fail_io(st->io, -EIO);
	state_next(st, EV_ERR);
	return 0; // fail
}

static void
opps_state__init(struct state *st)
{
	struct opp_status_req *r = st->data;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;

	r->ctx = repctx_init(netobj->robj[0]);
	if (!r->ctx) {
		log_error(lg, "repctx alloc: out of memory: -ENOMEM");
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->ctx->state = st;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		repctx_destroy(r->ctx);
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->timer_req->data = NULL;
	uv_timer_init(tc->loop, r->timer_req);

	state_next(st, EV_SEND);
}

static void
blr_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
opps_state__term(struct state *st)
{
	struct opp_status_req *r = st->data;
	struct ccow_io *io = (struct ccow_io *)st;

	assert(r->inexec >= 0);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	uv_close((uv_handle_t *)r->timer_req, blr_timer_close_cb);
	repctx_destroy(r->ctx);
	ccow_complete_io(io);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, &opps_state__init, ST_INIT, NULL },
{ ST_INIT, EV_SEND, &opps_state__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, &opps_state__send, ST_WAIT, &opps_guard__retry },
{ ST_WAIT, RT_OPP_STATUS_ACK, &opps_state__response, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &opps_state__error, ST_TERM, NULL }
};

/*
 * Initiate RT_OPP_STATUS
 *
 */
int ccow_opp_satus_request(struct ccow *tc, const uint512_t* vmchid,
	const uint512_t* nhid, struct ccow_completion *c, int flags,
	opp_status_t* pp_status)
{
	int err;
	struct ccow_network *netobj = tc->netobj;
	assert(vmchid);
	assert(nhid);

	struct opp_status_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		log_error(lg, "blob_lookup_request: out of memory: -ENOMEM");
		return -ENOMEM;
	}
	r->netobj = netobj;
	r->vmchid = *vmchid;
	r->nhid = *nhid;
	r->result = pp_status;
	r->flags = flags;

	struct ccow_op *opp_status_op;
	err = ccow_operation_create(c, CCOW_OPP_STATUS, &opp_status_op);
	if (err) {
		ccow_release(c);
		je_free(r);
		return err;
	}

	struct ccow_io *io;
	err = ccow_create_io(c, opp_status_op, CCOW_OPP_STATUS, trans_tbl,
	    sizeof (trans_tbl) / sizeof (*trans_tbl), r, opps_state__term, &io);
	if (err) {
		ccow_operation_destroy(opp_status_op, 1);
		ccow_release(c);
		je_free(r);
		return err;
	}

	err = ccow_start_io(io);
	return err;
}
