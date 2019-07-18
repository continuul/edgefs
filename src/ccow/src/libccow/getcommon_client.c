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
#include "ccowutil.h"
#include "state.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "getcommon_client.h"

extern ifvbuf_t *ifvbuf;
extern struct ccow_shm_process *myproc;

void
client_getcommon_init(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;
	int err;

	log_trace(lg, "st %p ", st);

	r->ctx = repctx_init(netobj->robj[0]);
	if (!r->ctx) {
		log_error(lg, "GETCOMMON repctx alloc error: out of memory"
		    ": -ENOMEM");
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->ctx->state = st;
	r->retry = 0;
	r->reply_count = 0;
	r->obj_found = 0;
	r->max_generation = 0;
	r->max_vmm_gen_id = 0;
	r->n_error_consensus = 0;
	r->error_consensus_max = 1;
	r->recovery_cnt = CCOW_RECOVERY_RETRY_CNT;
	r->recovery_busy_cnt = CCOW_RECOVERY_BUSY_CNT;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		repctx_destroy(r->ctx);
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->timer_req->data = NULL;
	uv_timer_init(tc->loop, r->timer_req);

	r->rttimer_req = je_malloc(sizeof (*r->rttimer_req));
	if (!r->rttimer_req) {
		je_free(r->timer_req);
		repctx_destroy(r->ctx);
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->rttimer_req->data = NULL;
	uv_timer_init(tc->loop, r->rttimer_req);

	r->delayed_start_timer_req = je_malloc(sizeof (*r->delayed_start_timer_req));
	if (!r->delayed_start_timer_req) {
		je_free(r->timer_req);
		je_free(r->rttimer_req);
		repctx_destroy(r->ctx);
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->delayed_start_timer_req->data = NULL;
	r->delayed_start_fd = uv_hpt_timer_init(tc->loop, r->delayed_start_timer_req);
}

static void
getcommon_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

void
client_getcommon_terminate(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = (struct ccow_io *)st;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	assert(r->inexec >= 0);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	if (r->vbuf_allocated > 0) {
		// FIXME: find the correct interface
		struct repvbuf *vbuf = &myproc->vbuf[0];
		replicast_free_vbuf(vbuf, r->content_length);
		r->vbuf_allocated = 0;
	}

	if ((io->comp->cont_generation) && (*io->comp->cont_generation == 0)) {
		/* cont_generation becomes output */
		*io->comp->cont_generation = (io->attributes & RD_ATTR_QUERY) ?
			r->max_generation - 1 : r->max_generation;
	}

	if (r->delayed_start_timer_req->data) {
		uv_hpt_timer_stop(r->delayed_start_fd, r->delayed_start_timer_req);
		r->delayed_start_timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)r->delayed_start_timer_req,
	    getcommon_timer_close_cb);
	if (r->delayed_start_fd > 0) {
		uv_hpt_timer_close(r->delayed_start_fd, r->delayed_start_timer_req);
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	uv_close((uv_handle_t *)r->timer_req, getcommon_timer_close_cb);

	if (r->rttimer_req->data)
		uv_timer_stop(r->rttimer_req);
	uv_close((uv_handle_t *)r->rttimer_req, getcommon_timer_close_cb);

	if (r->done_cb)
		r->done_cb(r);
	if (r->rb) {
		rtbuf_destroy(r->rb);
		r->rb = NULL;
	}
	if (r->rb_cached) {
		assert(r->nbufs == 1);
		je_free(r->payload[0].base);
	}
	if (r->one_payload.base)
		je_free(r->one_payload.base);
	if (r->ctx)
		repctx_destroy(r->ctx);
	if (r->reqtype == GET_REQ_TYPE_UNNAMED ||
	    r->reqtype == GET_REQ_TYPE_UNNAMED_RT) {
		if (r->cm_reflist) {
			rtbuf_destroy(r->cm_reflist);
			r->cm_reflist = NULL;
		}
	}
	ccow_complete_io((struct ccow_io *)st);
}


void
client_getcommon_send_proposal(struct state *st,
    enum replicast_opcode opcode, void *msg)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = io->comp;
	struct ccow_network *netobj = tc->netobj;
	int err;

	log_trace(lg, "st %p, opcode %d, msg %p seqid %d.%d", st, opcode,
	    msg, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	struct sockaddr_in6 send_addr;
	flexhash_get_hashaddr(tc->flexhash, &r->ng_chid, &send_addr);
	send_addr.sin6_scope_id = netobj->if_indexes[0];

	uint512_logdump(lg, "Get NG CHID", &r->ng_chid);

	ctx->attributes = 0;
	if (r->tc->unicastio == REPLICAST_UNICAST_TCP)
		((struct repmsg_generic *)msg)->hdr.attributes |= RD_ATTR_UNICAST_TCP;
	else if (r->tc->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		((struct repmsg_generic *)msg)->hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;
		ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	r->inexec++;
	err = replicast_send(netobj->robj[0], ctx, opcode,
	    (struct repmsg_generic *) msg, NULL, NULL, 0, &send_addr,
	    replicast_send_done_generic, st, NULL);
	if (err) {
		r->inexec--;
		log_error(lg, "GET operation error %d on send", err);
		state_next(st, EV_TIMEOUT);
		return;
	}

	if (io && (io->attributes & RD_ATTR_GET_CONSENSUS)) {
		tc->last_consensus_send_time = get_timestamp_us();
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	r->timer_req->data = st;

	int new_timeout = 0;
	if ((r->reqtype == GET_REQ_TYPE_UNNAMED ||
		r->reqtype == GET_REQ_TYPE_UNNAMED_RT) &&
		(io->attributes & RD_ATTR_CM_LEAF_WRITE)) {
		new_timeout = CLIENT_UNENCODE_TIMEOUT_MAX;
	} else {
		/*
		 * Setting up timer for Chunk GET
		 */
		uint64_t select_time_avg = 0;
		if (r->reqtype == GET_REQ_TYPE_NAMED ||
		    r->reqtype == GET_REQ_TYPE_NAMED_RT) {
			select_time_avg =  flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
			    FH_MSG_NAMEDGET_SELECT, 4096);
			select_time_avg /= 1000;
			if (r->retry >= 3)
				select_time_avg += CLIENT_GETCOMMON_NAMEDGET_TIMEOUT_MS;
		} else if (r->reqtype == GET_REQ_TYPE_UNNAMED ||
			r->reqtype == GET_REQ_TYPE_UNNAMED_RT) {
			select_time_avg =  flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
			    FH_MSG_UNNAMEDGET_SELECT, 4096);
			select_time_avg /= 1000;
			if (r->retry >= 3)
				select_time_avg += CLIENT_GETCOMMON_UNNAMEDGET_TIMEOUT_MS;
// TODO : gwc		} else if (r->reqtype == GET_REQ_TYPE_CACHE) {
// TODO : gwc		select_time_avg = CLIENT_GETCOMMON_UNNAMEDGET_TIMEOUT_MS;
		} else
			assert(0);

		new_timeout = ccow_retry_log2(select_time_avg, r->retry);

		log_debug(lg, "select_time_avg %ldms new_timeout %dms",
		    select_time_avg, new_timeout);

		if (new_timeout > CLIENT_GETCOMMON_TIMEOUT_MS) {
			new_timeout = CLIENT_GETCOMMON_TIMEOUT_MS;
		}
		if (new_timeout < CLIENT_GETCOMMON_TIMEOUT_MIN_MS) {
			new_timeout = CLIENT_GETCOMMON_TIMEOUT_MIN_MS;
		}
	}
	uv_timer_start(r->timer_req, client_getcommon_timeout, new_timeout, 0);

}

int
client_getcommon_guard_retry(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = (struct ccow_io *)st;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	/*
	 * If request to GW timed out, resume request to cluster.
	 */
	r->retry++;

	uint64_t accept_timeout = r->accept_timeout;
	uint64_t delta_time = r->selected_proposal ?
		r->selected_proposal->delta_time : 0;
	int rtselected = r->rtselected;
	client_getcommon_reset(r);

	if (r->retry > CLIENT_GETCOMMON_MAX_RETRY_FAILFAST &&
	    ((r->reqtype == GET_REQ_TYPE_UNNAMED ||
	      r->reqtype == GET_REQ_TYPE_UNNAMED_RT)) &&
	    !rtselected &&
	    !(io->attributes & RD_ATTR_GET_CONSENSUS)) {
		/*
		 * Fail fast logic would trigger UnnamedGet Concensus on
		 * a chunk in proposals stage.
		 */
		io->attributes |= RD_ATTR_GET_CONSENSUS;
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(&r->chid, chidstr, UINT512_BYTES*2+1);
		log_warn(lg, "Enabled Full Concensus on GET for CHID=%s", chidstr);
	}

	if (r->retry < CLIENT_GETCOMMON_MAX_RETRY) {
		struct ccow *tc = r->tc;

		if (tc->abort) {
			ccow_fail_io(r->io, -EINTR);
			state_next(st, EV_ERR);
			return 0; // fail
		}

		log_warn(lg, "GET (RT=%d) request timed out "
		    "(len = %ld est = %ldus acc_timeout=%ldms) after %d attempts"
		    " reqtype %d seqid %d.%d", rtselected, r->content_length,
		    delta_time, accept_timeout, r->retry, r->reqtype, r->ctx->sequence_cnt,
		    r->ctx->sub_sequence_cnt - 1);
		return 1;
	}

	log_error(lg, "GET request timed out after %d attempts"
	    " seqid %d.%d. Failing I/O.", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

	ccow_fail_io(r->io, -EIO);
	state_next(st, EV_ERR);
	return 0; // fail
}

void
client_getcommon_timeout(uv_timer_t *treq, int status)
{
	struct state *st = treq->data;
	struct getcommon_client_req *r = st->data;
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

void
client_getcommon_sendaccept_timeout(uv_timer_t *treq, int status)
{
	struct state *st = treq->data;
	struct getcommon_client_req *r = st->data;
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

static void
client_getcommon_consesus_timer_cb(uv_timer_t* handle, int status)
{
	struct state *st = (struct state *)handle->data;
	struct getcommon_client_req *r = st->data;
	if (handle->data) {
		uv_timer_stop(handle);
		handle->data = NULL;
	}
	state_event(st, EV_TIMEOUT);
}
// return 0, don't go to the next function
// return 1, go to process the error received.
// if the # of errors received is the same as the
// replica count, then we consider it an error ,
// other wise the timer should kick in and retry will continue.
//
int
client_getcommon_error_consensus(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow *tc = r->tc;
	struct repwqe *wqe = ctx->wqe_in;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (io && (io->attributes & RD_ATTR_GET_CONSENSUS)) {
		tc->last_consensus_recv_time = get_timestamp_us();
	}

	/*
	 * The request was sent to GW cache. If there was error then
	 * GW cache does not have data.
	 */
	struct repmsg_error *msg = (struct repmsg_error *)wqe->msg;
        if (msg->is_gwcache)
		return 1;

	for (int i = 0; i < r->err_count; i++) {
		if (!uint128_cmp(r->err_vdevs + i, &msg->vdevid)) {
			if (unlikely((lg->level <= LOG_LEVEL_DEBUG))) {
				char chidstr[UINT512_BYTES*2+1];
				char vdevstr[UINT128_BYTES*2+1];
				uint128_dump(&msg->vdevid, vdevstr, UINT128_BYTES*2+1);
				uint512_dump(&r->chid, chidstr, UINT512_BYTES*2+1);
				log_debug(lg, "RT_ERROR reply from VDEV ID %s already "
					"received, chid %s", vdevstr, chidstr);
			}
			return 0;
		}
	}

	if (msg->error == RT_ERR_BAD_NGCOUNT) {
		/* The request was answered during FH rebuild.
		 * The ngcount is unknown at the moment. It's better to
		 * restart the request after a while.
		 */
		uint64_t timeout = 500 + r->badng_retry++ * 50;
		if (r->timer_req->data)
			uv_timer_stop(r->timer_req);
		r->timer_req->data = st;
		uv_timer_start(r->timer_req,
		    client_getcommon_consesus_timer_cb, timeout, 0);
		return 0;
	}
	r->badng_retry = 0;
	// if we have received errors only we count them
	// upto the count od members of the negotiating group
	r->ngcount = msg->ngcount;
	if (!r->fddelta)
		r->fddelta = msg->fddelta;

	r->err_vdevs[r->err_count] = msg->vdevid;
	r->err_count++;

	if (io->attributes & RD_ATTR_CM_LEAF_WRITE) {
		return 1;
	}
	/* did we get enough errors? bail out if so */
	if (REPLIES_CNT(r) - r->reply_count >= r->ngcount) {
		if ((io->attributes & RD_ATTR_CHUNK_LOOKUP) || (++r->n_error_consensus >= r->error_consensus_max)) {
			log_debug(lg, "Error count reached reply_count=%d err_count=%d"
			    " fddelta=%d ngcount=%d seqid %d.%d", r->reply_count,
			    r->err_count, r->fddelta, r->ngcount, ctx->sequence_cnt,
			    ctx->sub_sequence_cnt);
			return 1;
		} else {
			if (r->timer_req->data) {
				uv_timer_stop(r->timer_req);
			}
			r->timer_req->data = st;
			uv_timer_start(r->timer_req,
			    client_getcommon_consesus_timer_cb, 100, 0);
			return 0;
		}
	}

	log_debug(lg, "GET Error received.  reply_count: %d err_count: %d "
	    " ngcount: %d fddelta: %d", r->reply_count, r->err_count,
	    r->ngcount, r->fddelta);

	if ((r->reqtype == GET_REQ_TYPE_NAMED ||
		r->reqtype == GET_REQ_TYPE_NAMED_RT) &&
		REPLIES_CNT(r) >= r->ngcount) {
		/* if we're in rt, avoid the payload processing
		* because rt is not done. let it timeout if it has to */
		if ((r->rtselected) && (!r->rttransferred))
			return 0;
		return 1;
	}

	return 0;
}

int
client_getcommon_find_window(struct getcommon_client_req *r)
{
	uint64_t now = get_timestamp_us();
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow *tc = r->tc;
	struct repctx *ctx = r->ctx;
	struct replicast_rendezvous_proposal
		*selected_proposals[REPLICAST_PROPOSALS_MAX];

	log_trace(lg, "r %p seqid %d.%d r->proposed_count: %d optype: %s", r, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, r->proposed_count, ccow_op2str(op->optype));

	uint64_t max_generation_uvid = 0;
	for (int k = 0; k < r->proposed_count; k++) {
		if (r->proposed_generations[k] == r->max_generation &&
		    r->proposed_uvids[k] > max_generation_uvid) {
			max_generation_uvid = r->proposed_uvids[k];
		}
	}

	int j = 0, i;
	for (i = 0; i < r->proposed_count; i++) {

		/* This is because we want to filter the proposed list by the
		 * max generation and uvid. e.g. List may receive generation 3
		 * and later get 4 (uvid=1) and 4 (uvid=2). Max would
		 * be 4 (uvid=2) but 3 would still be in the list
		 */
		if (r->proposed_generations[i] < r->max_generation ||
		    (r->proposed_generations[i] == r->max_generation &&
		     r->proposed_uvids[i] < max_generation_uvid) ||
		    (r->proposed_generations[i] == r->max_generation &&
		     r->proposed_vmm_gen_ids[i] < r->max_vmm_gen_id))
			continue;

		struct replicast_rendezvous_proposal *proposal = &r->proposals[i];

		uint64_t start =  proposal->start_time;
		uint64_t end = start + proposal->delta_time;

		if (end < now) {
			log_debug(lg, "Received expired proposal: %lu us", now - end);
			end = now;
		}

		/* for TCP do only essential checks */
		if (end >= now || r->tc->unicastio == REPLICAST_UNICAST_TCP) {

			/*
			 * Check if this vdev is valid in flexhash. Skip
			 * otherwise ...
			 */
			if (!flexhash_validate_vdev(CLIENT_FLEXHASH,
				    &r->proposed_vdevs[i])) {
				char out[64];
				uint128_dump(&r->proposed_vdevs[i], out, 64);
				log_warn(lg, "vdev not found : %s seqid %d.%d",
				    out, ctx->sequence_cnt, ctx->sub_sequence_cnt);
				continue;
			}

			/*
			 * Check to see if this vdev had mismatched checksum
			 * last time we transfered... If so, skip and try to
			 * find another one.
			 */
			int excluded = -1;
			for (int k = 0; k < r->excluded_count; k++) {
				if (uint128_cmp(&r->proposed_vdevs[i],
					    &r->excluded_vdevs[k]) == 0) {
					excluded = k;
					break;
				}
			}
			if (excluded != -1 &&
			    r->excluded_vdevs_errcnt[excluded] >=
			    EXCLUDED_VDEVS_ERRCNT_MAX) {
				char out[64];
				uint128_dump(&r->proposed_vdevs[i], out, 64);
				log_warn(lg, "vdev excluded : %s seqid %d.%d",
				    out, ctx->sequence_cnt, ctx->sub_sequence_cnt);
				continue;
			}

			r->selected_vdevs[j] = r->proposed_vdevs[i];
			r->selected_vdevip = &r->vdevip[i];
			r->selected_proposal = proposal;

			/* we do not know CHID in case of NAMED requests */
			if ((r->reqtype == GET_REQ_TYPE_NAMED) ||
			    (r->reqtype == GET_REQ_TYPE_NAMED_RT))
				r->chid = r->proposed_chids[i];

			/* we just need at least one for sending a get accept. */
			if (++j >= 1) {
				goto exit_found;
			}

		}
		// FIXME: implement...
		//		proposal.xmit_bandwidth;
	}

	/* wait for more */
	return 0;

exit_found:;
	if (unlikely(LOG_LEVEL_DEBUG >= lg->level)) {
		char out[64];
		uint128_dump(&r->selected_vdevs[0], out, 64);
		log_debug(lg, "selected proposal from vdev: %s "
		    "seqid %d.%d with max_generation %"PRIu64" "
		    "vmm_gen_id %"PRIu64,
		    out, ctx->sequence_cnt, ctx->sub_sequence_cnt,
		    r->proposed_generations[i],
		    r->max_vmm_gen_id);
	}

	/* unlike put, here we do the delayed start to the start offset of
	 * the selected proposal . we select the first one everytime
	 */
	uint64_t max_start = 0;
	struct replicast_rendezvous_proposal *p = r->selected_proposal;
	max_start = p->start_time;

	/*
	 * we still delay for at least 1 millisecond here to give accept/ack
	 * at least some room for cleanups
	 */
	uint64_t max_start_abs = op->uvid_timestamp + max_start;
	r->delayed_start_us = max_start_abs <= now ? 1000 : now - max_start_abs;
	assert(r->delayed_start_us);

	return 1;
}

int
client_getcommon_guard_resp(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;
	int err;
	char vdevstr[64];
	void *lmsg;
	// here we determine if this is rt or not.
	assert(wqe);

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (io && (io->attributes & RD_ATTR_GET_CONSENSUS)) {
		tc->last_consensus_recv_time = get_timestamp_us();
	}

	/*
	 * Got the response from GW cache.
	 */
	struct repmsg_unnamed_chunk_get_response *msg =
		(struct repmsg_unnamed_chunk_get_response *)wqe->msg;

	if ((io->attributes & RD_ATTR_CHUNK_LOOKUP) && (r->reqtype == GET_REQ_TYPE_UNNAMED)) {
		/* Just count replies until its number reaches a threshold or ngcount */
		int64_t rc = (int64_t)r->chunkmap_data;
		r->reply_count++;
		if ((rc && r->reply_count >= rc) || (REPLIES_CNT(r) >= msg->ngcount)) {
			r->chunkmap_data = (void*)((int64_t)r->reply_count);
			state_next(st, EV_DONE);
		}
		return 0;
	}


	if ((msg->hdr.transaction_id.opcode == RT_UNNAMED_CHUNK_GET) ||
	    (msg->hdr.transaction_id.opcode == RT_UNNAMED_CHUNK_GET_RESPONSE)) {
		assert((msg->is_gwcache == 0) || (msg->is_gwcache == 1));
		if (msg->is_gwcache) {
			return 1;
		}
	}

	// do the rtt calculation right away on the reply
	flexhash_update_rtt(CLIENT_FLEXHASH, &r->ng_chid, FH_MSG_UNSOLICITED,
	    r->req_start, get_timestamp_us(), 4096);

	int wait_consensus = io->comp->ec_enabled &&
		(io->attributes & RD_ATTR_CM_LEAF_WRITE) &&
		((r->reqtype == GET_REQ_TYPE_UNNAMED ||
		  r->reqtype == GET_REQ_TYPE_UNNAMED_RT));

	if (r->rtselected && !wait_consensus) {
		log_debug(lg, "RT already selected");
		return 0;
	}

	if (r->proposed_count > REPLICAST_PROPOSALS_MAX) {
		log_error(lg, "Received %d proposals, max permitted: %d",
		    r->proposed_count, REPLICAST_PROPOSALS_MAX);
		// don't allow more. let it timeout if not done
		return 0;
	}

	if (r->reqtype == GET_REQ_TYPE_UNNAMED ||
	    r->reqtype == GET_REQ_TYPE_UNNAMED_RT) {
		struct repmsg_unnamed_chunk_get_response *msg =
			(struct repmsg_unnamed_chunk_get_response *)wqe->msg;

		if (msg->immediate_content_length != 0) {
			return 1;
		}
		r->reqtype = GET_REQ_TYPE_UNNAMED_RT;

		r->vdevip[r->proposed_count].vdevid = msg->vdevid;
		r->vdevip[r->proposed_count].saddr.sin6_port =
			htons(msg->hdr.transaction_id.source_port);
		memcpy(&r->vdevip[r->proposed_count].saddr.sin6_addr,
		    &msg->hdr.transaction_id.source_addr,
		    sizeof(struct in6_addr));
		r->vdevip[r->proposed_count].saddr.sin6_family = AF_INET6;
		r->vdevip[r->proposed_count].saddr.sin6_flowinfo =  0;
		r->vdevip[r->proposed_count].saddr.sin6_scope_id =
			netobj->if_indexes[0];

		r->proposals[r->proposed_count] = msg->rendezvous_proposal;
		r->proposed_vdevs[r->proposed_count] = msg->vdevid;
		r->proposed_count++;
		r->content_length = msg->content_length;

		uint128_dump(&msg->vdevid, vdevstr, 64);
		log_debug(lg, "GET RT selected from vdev: %s seqid %d.%d",
		    vdevstr, ctx->sequence_cnt, ctx->sub_sequence_cnt);

		r->selected_vdevs[0] = msg->vdevid;
		r->selected_proposal = &r->proposals[0];
		r->selected_vdevip = &r->vdevip[0];
		flexhash_get_hashaddr(tc->flexhash, &r->ng_chid,
		    &r->selected_ngaddr);
		r->selected_ngaddr.sin6_scope_id = netobj->if_indexes[0];
		r->rtselected = 1;

		struct lvdev *lvdev =
			vdevstore_get_lvdev(CLIENT_FLEXHASH->vdevstore, &msg->vdevid);

		if (!lvdev) {
			log_debug(lg, "Unknown vdevid: %s seqid %d.%d "
			    " fhgenid: %ld ", vdevstr,
			    ctx->sequence_cnt, ctx->sub_sequence_cnt,
			    flexhash_genid(CLIENT_FLEXHASH));
			return 1;
		}

		// do the rtt calculation right away on the reply
		if (!wait_consensus)
			flexhash_update_rtt(CLIENT_FLEXHASH, &r->ng_chid,
			    FH_MSG_UNNAMEDGET_SELECT, r->req_start,
			    get_timestamp_us(), 4096);
		r->reply_count++;
		if (wait_consensus && REPLIES_CNT(r) < msg->ngcount) {
			if (unlikely((lg->level <= LOG_LEVEL_DEBUG))) {
				char chidstr[UINT512_BYTES*2+1];
				uint512_dump(&r->chid, chidstr, UINT512_BYTES*2+1);
				log_debug(lg,"CM %s ngcount %d n_replies %d", chidstr,
				    msg->ngcount, REPLIES_CNT(r));
			}
			return 0;
		}
		return 1;

	} else if (r->reqtype == GET_REQ_TYPE_NAMED ||
	    r->reqtype == GET_REQ_TYPE_NAMED_RT) {
		struct repmsg_named_chunk_get_response *msg =
			(struct repmsg_named_chunk_get_response *)wqe->msg;


		uint128_dump(&msg->vdevid, vdevstr, 64);

		// check if this is a valid vdev in the row
		if (!flexhash_is_rowmember(tc->flexhash, &msg->vdevid,
			    &r->ng_chid)) {
			uint16_t row = HASHROWID(&r->ng_chid, tc->flexhash);
			log_debug(lg, "GET_RESPONSE from vdev: %s not in row: %d",
			    vdevstr, row);
			return 0;
		}

		if (io->comp->version_vm_content_hash_id) {
			if (uint512_cmp(&msg->content_hash_id, io->comp->version_vm_content_hash_id)) {
				log_trace(lg, "GET_RESPONSE versions collision %" PRIu64, msg->object_name.generation);
				return 0;
			}
		}

		r->reply_count++;
		if ((io->comp->cont_generation) && (*io->comp->cont_generation)) {
			/* drop all other responses if we want only one */
			if (r->ngcount == 1)
				return 0;
			r->ngcount = 1;
		} else {
			r->ngcount = msg->ngcount;
		}
		if (!r->fddelta)
			r->fddelta = msg->fddelta;

		/* unsolicited gets */
		if (msg->immediate_content_length != 0) {
			if (io->attributes & RD_ATTR_QUERY) {
				if ((msg->object_name.generation > r->max_generation) ||
				    ((msg->object_name.generation == r->max_generation) &&
				     (msg->object_name.vmm_gen_id > r->max_vmm_gen_id)))
				{
					log_debug(lg, "GET Query: generation id: %" PRIu64
					    " ngcount: %d imm content_length: %d "
					    "content_length: %d reply: %d err_count: %d",
					    msg->object_name.generation, r->ngcount,
					    msg->immediate_content_length,
					    msg->content_length, r->reply_count,
					    r->err_count);
					r->max_generation = msg->object_name.generation;
					r->max_vmm_gen_id = msg->object_name.vmm_gen_id;
					r->chid = msg->content_hash_id;
					op->coordinated_uvid_timestamp = msg->object_name.uvid_timestamp;
					if (msg->content_length > 0) {
						r->payload[0].len = msg->content_length;
						r->payload[0].base = repwqe_payload(wqe);
						r->nbufs = 1;
					}
				}
				if (REPLIES_CNT(r) >= r->ngcount) {
					log_debug(lg, "GET Query count reached. reply:"
					    " %d err: %d ngcount: %d max_generation: %" PRIu64,
					    r->reply_count, r->err_count, r->ngcount,
					    r->max_generation);
					return 1;
				}
				/* Wait for some more */
				return 0;
			}
			if (io->attributes & RD_ATTR_VERSIONS_QUERY) {
				log_debug(lg, "GET VERSIONS imm content_length:"
				    " %d generation id: %" PRIu64,
				    msg->immediate_content_length,
				    msg->object_name.generation);
				r->chid = msg->content_hash_id;
				if (msg->object_name.generation > r->max_generation) {
					r->max_generation = msg->object_name.generation;
				}

				r->payload[r->nbufs].len = msg->immediate_content_length;
				r->payload[r->nbufs].base = repwqe_payload(wqe);
				r->nbufs++;
				if ((r->reply_count + r->err_count) >= r->ngcount) {
					log_debug(lg, "GET VERSIONS imm content_length: %d"
					    " count reached. reply: %d err: %d ngcount:"
					    " %d", msg->immediate_content_length,
					    r->reply_count, r->err_count, r->ngcount);
					return 1;
				}
				log_info(lg, "Get VERSIONS: %" PRIu64,
				    msg->object_name.generation);
				return 0;
			}
			if ((msg->object_name.generation > r->max_generation) ||
			    ((msg->object_name.generation == r->max_generation) &&
			     (msg->object_name.vmm_gen_id > r->max_vmm_gen_id))) {
				log_debug(lg, "GET Object imm content_length:"
				    " %d generation id: %" PRIu64,
				    msg->immediate_content_length,
				    msg->object_name.generation);

				r->max_generation = msg->object_name.generation;
				r->max_vmm_gen_id = msg->object_name.vmm_gen_id;
				r->chid = msg->content_hash_id;
				r->payload[0].len = msg->content_length;
				r->payload[0].base = repwqe_payload(wqe);
				r->nbufs = 1;
			}
			if (REPLIES_CNT(r) >= r->ngcount) {
				log_debug(lg, "GET Object imm content_length: %d"
				    " count reached. reply: %d err: %d ngcount:"
				    " %d", msg->immediate_content_length,
				    r->reply_count, r->err_count, r->ngcount);
				return 1;
			}
			log_info(lg, "Get Object generation: %" PRIu64,
			    msg->object_name.generation);
			return 0;
		}
		r->rt_inprogress = 1;
		/* solicited gets */
		if (io->attributes & RD_ATTR_QUERY) {
			if ((msg->object_name.generation > r->max_generation) ||
			    ((msg->object_name.generation == r->max_generation) &&
			     (msg->object_name.vmm_gen_id > r->max_vmm_gen_id))) {
				log_debug(lg, "GET RT Query: generation id: %" PRIu64
				    " ngcount: %d imm content_length: %d "
				    "content_length: %d reply: %d err_count: %d",
				    msg->object_name.generation, r->ngcount,
				    msg->immediate_content_length,
				    msg->content_length, r->reply_count,
				    r->err_count);
				r->max_generation = msg->object_name.generation;
				r->max_vmm_gen_id = msg->object_name.vmm_gen_id;
				r->chid = msg->content_hash_id;
				op->coordinated_uvid_timestamp = msg->object_name.uvid_timestamp;

				/* we go into RT only if there is content
				*/

				if (msg->content_length > 0) {
					r->proposals[r->proposed_count] = msg->rendezvous_proposal;
					r->proposed_vdevs[r->proposed_count] = msg->vdevid;
					r->proposed_generations[r->proposed_count] = msg->object_name.generation;
					r->proposed_vmm_gen_ids[r->proposed_count] = msg->object_name.vmm_gen_id;
					r->proposed_uvids[r->proposed_count] = msg->object_name.uvid_timestamp;
					r->proposed_chids[r->proposed_count] = msg->content_hash_id;
					r->content_length = msg->content_length;
					uint128_dump(&msg->vdevid, vdevstr, 64);
					log_debug(lg, "QUERY i=%d vdevstr %s, generation %"PRIu64", vmm_gen_id %"PRIu64", NUVID %"PRIu64,
					    r->proposed_count, vdevstr, msg->object_name.generation, msg->object_name.vmm_gen_id,
					    msg->object_name.uvid_timestamp);
					uint512_logdump(lg, "QUERY vdevstr content_hash_id", &r->chid);
					r->vdevip[r->proposed_count].vdevid = msg->vdevid;
					r->vdevip[r->proposed_count].saddr.sin6_port =
						htons(msg->hdr.transaction_id.source_port);
					memcpy(&r->vdevip[r->proposed_count].saddr.sin6_addr,
					    &msg->hdr.transaction_id.source_addr,
					    sizeof(struct in6_addr));
					r->vdevip[r->proposed_count].saddr.sin6_family = AF_INET6;
					r->vdevip[r->proposed_count].saddr.sin6_flowinfo =  0;
					r->vdevip[r->proposed_count].saddr.sin6_scope_id =
						netobj->if_indexes[0];
					r->proposed_count++;
					r->reqtype = GET_REQ_TYPE_NAMED_RT;
				}
			}
			/* query request for specific generation? - done */
			if ((io->comp->cont_generation)
			    && (*io->comp->cont_generation)) {
				return 1;
			}

			if (REPLIES_CNT(r) >= r->ngcount) {
				log_debug(lg, "GET RT Query count reached. reply:"
				    " %d err: %d ngcount: %d max_generation: %" PRIu64,
				    r->reply_count, r->err_count, r->ngcount,
				    r->max_generation);
				return 1;
			}
			/* wait for some more */
			return 0;
		}

		log_debug(lg, "GET RT Object imm content_length: %d"
		    " reply: %d err: %d ngcount: %d generation: %" PRIu64,
		    msg->immediate_content_length,
		    r->reply_count, r->err_count, r->ngcount,
		    msg->object_name.generation);

		/* consider only the proposals with generation numbers == or above. reject the
		 * lower values
		 */
		if ((msg->object_name.generation < r->max_generation) ||
		    ((msg->object_name.generation == r->max_generation) &&
		     (msg->object_name.vmm_gen_id < r->max_vmm_gen_id)))
		{
			log_debug(lg, "VMM : msg->object_name.generation = %"PRId64" "
			    ": r->max_generation = %"PRId64" "
			    ": msg->object_name.vmm_gen_id = %"PRId64" "
			    ": r->max_vmm_gen_id = %"PRId64"",
			    msg->object_name.generation, r->max_generation,
			    msg->object_name.vmm_gen_id, r->max_vmm_gen_id);

			if (REPLIES_CNT(r) >= r->ngcount) {
				log_debug(lg, "GET RT Received all RT responses");
				return 1;
			}
			return 0;
		}

		r->max_generation = msg->object_name.generation;
		r->max_vmm_gen_id = msg->object_name.vmm_gen_id;

		if (msg->rendezvous_proposal.delta_time == 0) {
			log_error(lg, "invalid proposal received from vdev: %s",
			    vdevstr);
			return 0;
		}

		r->reqtype = GET_REQ_TYPE_NAMED_RT;
		r->proposals[r->proposed_count] = msg->rendezvous_proposal;
		r->proposed_vdevs[r->proposed_count] = msg->vdevid;
		r->proposed_generations[r->proposed_count] = msg->object_name.generation;
		r->proposed_vmm_gen_ids[r->proposed_count] = msg->object_name.vmm_gen_id;
		r->proposed_uvids[r->proposed_count] = msg->object_name.uvid_timestamp;
		r->proposed_chids[r->proposed_count] = msg->content_hash_id;
		r->vdevip[r->proposed_count].vdevid = msg->vdevid;
		r->vdevip[r->proposed_count].saddr.sin6_port =
			htons(msg->hdr.transaction_id.source_port);
		memcpy(&r->vdevip[r->proposed_count].saddr.sin6_addr,
		    &msg->hdr.transaction_id.source_addr,
		    sizeof(struct in6_addr));
		r->vdevip[r->proposed_count].saddr.sin6_family = AF_INET6;
		r->vdevip[r->proposed_count].saddr.sin6_flowinfo =  0;
		r->vdevip[r->proposed_count].saddr.sin6_scope_id =
			netobj->if_indexes[0];
		r->content_length = msg->content_length;
		r->chid = msg->content_hash_id;
		uint128_dump(&msg->vdevid, vdevstr, 64);
		log_debug(lg, "RT i=%d vdevstr %s, generation %"PRIu64" NUVID %"PRIu64,
		    r->proposed_count, vdevstr, msg->object_name.generation, msg->object_name.uvid_timestamp);
		uint512_logdump(lg, "RT vdevstr content_hash_id", &r->chid);
		r->proposed_count++;
	} else {
		assert(0);
	}

	// we're in rt.
	if (r->rtselected) {
		log_info(lg, "GET RT already selected. Ignoring vdev; %s",
		    vdevstr);
		return 0;
	}
	log_debug(lg, "GET RT requested from vdev: %s reply_count: %d"
	    " err_count: %d ngcount: %d seqid %d.%d", vdevstr, r->reply_count,
	    r->err_count, r->ngcount, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	r->rt_inprogress = 1;
	if (REPLIES_CNT(r) >= r->ngcount) {
		log_debug(lg, "GET RT Received all RT responses");
		flexhash_update_rtt(CLIENT_FLEXHASH, &r->ng_chid, FH_MSG_NAMEDGET_SELECT,
		    r->req_start, get_timestamp_us(), 4096);
		return 1;
	}

	/* wait for some more */
	return 0;
}

int
client_getcommon_send_accept_guard(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;


	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	int window_found = client_getcommon_find_window(r);
	log_debug(lg, "Get Proposed state: %d.%d seqid %d.%d", r->proposed_count,
	    window_found, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (!window_found) {
		log_warn(lg, "Get Proposed window are not acceptable");
		return 1;
	}

	/*
	 * Get NG address
	 */
	flexhash_get_hashaddr(tc->flexhash, &r->ng_chid, &r->selected_ngaddr);
	r->selected_ngaddr.sin6_scope_id = netobj->if_indexes[0];
	r->rtselected = 1;

	return 1;
}

int
client_getcommon_reset(struct getcommon_client_req *r)
{
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;

	repctx_reset(ctx);

	log_trace(lg, "r %p seqid %d.%d new txcookie %" PRIx64,
	    r, ctx->sequence_cnt, ctx->sub_sequence_cnt, ctx->txcookie);

	r->proposed_count = 0;
	memset(r->proposals, 0, sizeof (r->proposals));
	memset(r->proposed_vdevs, 0, sizeof (r->proposed_vdevs));
	r->delayed_start_us = 0;
	memset(&r->selected_ngaddr, 0, sizeof (struct sockaddr_in6));
	r->ngcount = 0;
	r->fddelta = 0;
	r->rtselected = 0;
	r->obj_found = 0;
	r->err_count = 0;
	r->reply_count = 0;
	r->nbufs = 0;
	r->hashuncomp_threaded = 0;
	memset(r->proposed_generations, 0, sizeof (r->proposed_generations));
	memset(r->proposed_vmm_gen_ids, 0, sizeof (r->proposed_vmm_gen_ids));
	memset(r->proposed_uvids, 0, sizeof (r->proposed_uvids));
	memset(r->proposed_chids, 0, sizeof (r->proposed_chids));
	r->selected_proposal = NULL;
	r->rttransferred = 0;
	r->rt_inprogress = 0;
	r->req_start = 0;
	r->max_generation = 0;
	r->max_vmm_gen_id = 0;
	r->accept_timeout = 0;
	r->recovery_flags = 0;
	if (r->vbuf_allocated > 0) {
		// FIXME: find the correct interface
		struct repvbuf *vbuf = &myproc->vbuf[0];
		replicast_free_vbuf(vbuf, r->content_length);
		r->vbuf_allocated = 0;
	}
	if (!uint256_cmp(&r->dgram_idx, &uint256_null))
		repctx_wqe_reset(ctx);
	return 0;
}

void
client_getcommon_rttransfer(struct state *st)
{
	struct getcommon_client_req *req = st->data;
	struct ccow *tc = req->tc;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = req->io;
	struct ccow_op *op = io->op;

	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (!req->rtselected) {
		log_debug(lg, "RT Not in progress, rejecting this transfer");
		return;
	}

	/* retransmit case - drop */
	if (req->rttransferred) {
		log_debug(lg, "RT is all transfered. Retransmit case drop");
		return;
	}

	int idx = wqe->msg->hdr.datagram_num - 1;
	if (idx >= wqe->msg->num_datagrams) {
		req->error = RT_ERR_EIO;
		ccow_fail_io(st->io, req->error);
		state_next(ctx->state, EV_ERR);
		return;
	}

	req->payload[idx].len = repwqe_payload_len(wqe);
	req->payload[idx].base = repwqe_payload(wqe);

	// now update the mask for the ones we have received
	uint256_bset(&req->dgram_idx, idx);

	if (unlikely(lg->level <= LOG_LEVEL_DUMP)) {
		/* place this datagram into receiving buffer */
		log_debug(lg, "%s idx: %d num_datagrams: %d"
		    " datagram_num: %d content_length: %d"
		    " nread: %ld seqid %d.%d",
		    replicast_opcode_str[msg->hdr.transaction_id.opcode],
		    idx, msg->num_datagrams, wqe->msg->hdr.datagram_num,
		    msg->content_length, wqe->nread, ctx->sequence_cnt,
		    ctx->sub_sequence_cnt);

		uint512_t cchid;
		char cchidstr[UINT512_BYTES*2 + 1];

		int err = crypto_hash_with_type((crypto_hash_t)1,
		    (uint8_t *)req->payload[idx].base,
		    req->payload[idx].len, (uint8_t *)&cchid);
		uint512_dump(&cchid, cchidstr, UINT512_BYTES*2 + 1);

		log_debug(lg, "datagram: %d chid: %s seqid %d.%d",
		    wqe->msg->hdr.datagram_num, cchidstr, ctx->sequence_cnt,
		    ctx->sub_sequence_cnt);
	}

	if (uint256_hweight(&req->dgram_idx) < msg->num_datagrams) {
		/* wait for more datagrams */
		return;
	}


	log_debug(lg, "All datagrams %d received seqid %d.%d",
	    msg->num_datagrams, ctx->sequence_cnt, ctx->sub_sequence_cnt);
	req->nbufs = msg->num_datagrams;

	if (req->timer_req->data) {
		uv_timer_stop(req->timer_req);
		req->timer_req->data = NULL;
	}

	req->rttransferred = 1;
	if (req->reqtype == GET_REQ_TYPE_NAMED_RT) {
		req->obj_found = 1;
		op->txid_generation = req->max_generation;
		namedget_process_payload(st);
	} else {
		flexhash_update_rtt(CLIENT_FLEXHASH, &req->ng_chid,
			FH_MSG_GET_SOLICITED, req->rt_req_start,
			get_timestamp_us(), req->content_length);
		unnamedget_process_payload(st);
	}
}



static void
UV_HPT_TIMER_CB(client_getcommon_delayed_timeout, *treq)
{
	struct state *st = treq->data;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "st %p seqid %d.%d", st,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (r->delayed_start_timer_req->data) {
		uv_hpt_timer_stop(r->delayed_start_fd, r->delayed_start_timer_req);
		r->delayed_start_timer_req->data = NULL;
	}
	// check if we have enough vbuf buffers
	// FIXME: find the right interface instead of using 0
	struct repvbuf *vbuf = &ifvbuf->pvbuf[0];
	int err = replicast_check_avail_vbuf(vbuf, r->content_length);
	if (err) {
		// if we do not have enough buffers, kick off the timer again
		log_warn(lg, "Not enough vbuf to receive the GET Transfers"
		    " reserved: %ld req_len: %ld", vbuf->reserved, r->content_length);
		r->delayed_start_us = 1000;
		r->delayed_start_timer_req->data = st;
		uv_hpt_timer_start(r->delayed_start_fd, r->delayed_start_timer_req,
			r->delayed_start_us, client_getcommon_delayed_timeout);
		return;
	}
	// if we do, send out the accept using send_accept_rt
	client_getcommon_send_accept_rt(st);
}

void
client_getcommon_send_accept(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;

	log_trace(lg, "st %p seqid %d.%d", st,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (r->delayed_start_timer_req->data) {
		uv_hpt_timer_stop(r->delayed_start_fd, r->delayed_start_timer_req);
		r->delayed_start_timer_req->data = NULL;
	}

	// FIXME: find the right interface instead of using 0
	struct repvbuf *vbuf = &ifvbuf->pvbuf[0];
	int err = replicast_check_avail_vbuf(vbuf, r->content_length);
	if (err) {
		log_warn(lg, "Not enough vbuf to receive the GET Transfers"
		    " reserved: %ld req_len: %ld", vbuf->reserved, r->content_length);
		uint64_t new_timeout = 1000;
		r->delayed_start_timer_req->data = st;
		uv_hpt_timer_start(r->delayed_start_fd, r->delayed_start_timer_req,
		    new_timeout, client_getcommon_delayed_timeout);
		return;
	}
	client_getcommon_send_accept_rt(st);
}

static void
client_send_tcp_accept(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct sockaddr_in6 *dev_addr;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "st %p seqid %d.%d inexec: %d", st,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt, r->inexec);

	struct repmsg_rendezvous_transfer msg;
	memset(&msg, 0, sizeof (msg));
	msg.num_datagrams = 1;
	msg.hdr.attributes |= RD_ATTR_UNICAST_TCP;
	ctx->attributes = RD_ATTR_UNICAST_TCP;

	dev_addr = &r->selected_vdevip->saddr;
	assert(dev_addr != NULL);
	r->inexec++;

	int err = replicast_send(netobj->robj[0], ctx,
				 RT_GET_RENDEZVOUS_TRANSFER,
				 (struct repmsg_generic *)&msg, NULL,
				 NULL, 0, dev_addr,
				 replicast_send_done_generic, st, NULL);
	ctx->attributes = 0;
	if (err) {
		r->inexec--;
		log_error(lg, "GET operation error %d on send", err);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}
}

static void
client_getcommon_connect_cb(void *data, int status)
{
	struct state *st = (struct state *)data;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;

	log_trace(lg, "st %p seqid %d.%d inexec: %d", st,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt, r->inexec);

	r->inexec--;
	/* Log notice printed by sender_connect_cb() */
	if (status != 0) {
		if (errno == EAGAIN) {
			if (r->tcp_retry++ > CLIENT_GETCOMMON_TCP_RETRY_MAX) {
				log_error(lg, "Reached max tcp connect retries %d times", r->tcp_retry);
				state_event(st, EV_ERR);
				return;
			}
			struct sockaddr_in6 *dev_addr;
			dev_addr = &r->selected_vdevip->saddr;
			int err = replicast_tcp_connect(netobj->robj[0], dev_addr,
			    client_getcommon_connect_cb, (void *)st);
			if (err != 0) {
				log_error(lg, "Error on retry tcp connect. err=%d", err);
				state_event(st, EV_ERR);
				return;
			}

		} else {
			log_error(lg, "Error on tcp connect error: %d : %s", errno, strerror(errno));
			state_event(st, EV_ERR);
			return;
		}
	}
	client_send_tcp_accept(st);
}

void
client_getcommon_tcp_connect(struct state *st)
{
	int err;
	struct getcommon_client_req *r = st->data;
	struct ccow_network *netobj = r->tc->netobj;
	struct sockaddr_in6 *dev_addr;

	/* Only one device is selected for GET */
	dev_addr = &r->selected_vdevip->saddr;
	assert(dev_addr != NULL);

	/* For debugging */
	char dest[INET6_ADDRSTRLEN + 1] = { 0 };
	uv_ip6_name((struct sockaddr_in6 *)dev_addr, dest, INET6_ADDRSTRLEN);
	log_debug(lg, "Connecting to %s.%d", dest, ntohs(dev_addr->sin6_port));

	r->inexec++;
	err = replicast_tcp_connect(netobj->robj[0], dev_addr,
				    client_getcommon_connect_cb, (void *)st);
	if (err != 0 && err != -EAGAIN && err != -EEXIST) {
		r->inexec--;
		log_error(lg, "GET operation error %d on connect", err);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}

	if (err == 0 || err == -EAGAIN) {
		log_debug(lg, "waiting to establish connection");
		return;
	}

	r->inexec--;
	if (err == -EEXIST) {
		client_send_tcp_accept(st);
		return;
	}
}

static void
client_gecommon_send_accept_rt_done(void *data, int err, int ctx_valid)
{
	struct state *st = data;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
	    data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	r->inexec--;
	if (state_check(st, ST_TERM)) {
		st->term_cb(st);
		return;
	}

	if (err) {
		log_error(lg, "Error %d while sending ccow request for ev %d",
		    err, st->ev_cur);
		state_event(st, EV_ERR);
		return;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	r->timer_req->data = NULL;

	if (r->tc->unicastio != REPLICAST_UNICAST_TCP) {
		log_debug(lg, "Send GET ACCEPT: timeout %ldms delta_time %ldus",
		    r->accept_timeout, r->selected_proposal->delta_time);
		r->timer_req->data = st;
		uv_timer_start(r->timer_req, client_getcommon_sendaccept_timeout,
				r->accept_timeout, 0);
	}
}

void
client_getcommon_send_accept_rt(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;
	int err = 0;

	log_trace(lg, "st %p seqid %d.%d inexec: %d", st,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt, r->inexec);

	if (!r->rtselected) {
		state_next(st, EV_TIMEOUT);
		return;
	}

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	/* FIXME: there is FSM bug (or misuse) which is causing ACCEPT to be
	 *        sent twice.*/
	if (!r->vbuf_allocated) {
		// FIXME: find the appropriate interface instead of 0
		struct repvbuf *vbuf = &myproc->vbuf[0];
		replicast_alloc_vbuf(vbuf, r->content_length, VBUF_STAT_FALSE);
		r->vbuf_allocated = 1;
	}

	struct repmsg_accept_proposed_rendezvous accept;
	memset(&accept, 0, sizeof (accept));
	accept.num_datagrams = 1;
	accept.vdevid = r->selected_vdevs[0];

	assert(r->selected_proposal);

	accept.rendezvous_proposal.start_time
		= r->selected_proposal->start_time;
	accept.rendezvous_proposal.delta_time
		= r->selected_proposal->delta_time;
	accept.dgram_idx = r->dgram_idx;

	ctx->attributes = 0;
	if (r->tc->unicastio == REPLICAST_UNICAST_TCP)
		accept.hdr.attributes |= RD_ATTR_UNICAST_TCP;
	else if (r->tc->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		accept.hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;
		ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	r->inexec++;
	uint64_t avg_rtt;
	if (r->reqtype == GET_REQ_TYPE_UNNAMED_RT) {
		err = replicast_send(netobj->robj[0], ctx, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS,
		    (struct repmsg_generic *) &accept, NULL,
		    NULL, 0, &r->selected_ngaddr, client_gecommon_send_accept_rt_done, st, NULL);
		avg_rtt =  flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
		    FH_MSG_UNNAMEDGET_SELECT, 4096);
	} else if (r->reqtype == GET_REQ_TYPE_NAMED_RT) {
		err = replicast_send(netobj->robj[0], ctx, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS,
		    (struct repmsg_generic *) &accept, NULL,
		    NULL, 0, &r->selected_ngaddr, client_gecommon_send_accept_rt_done, st, NULL);
		avg_rtt =  flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
		    FH_MSG_NAMEDGET_SELECT, 4096);
	} else
		assert(0);
	if (err) {
		r->inexec--;
		ccow_fail_io(io, err);
		state_next(st, EV_ERR);
		return;
	}

	if (r->tc->unicastio == REPLICAST_UNICAST_TCP) {
		r->nbufs = 1;
		state_next(st, RT_INIT_TCP_CONNECT);
		return;
	}
	// based on the content length we figure out how many datagrams
	// we are supposed to receive
	r->nbufs = (r->content_length/BUF_CHUNK_SIZE);
	r->nbufs += ((r->content_length % BUF_CHUNK_SIZE) > 0) ? 1 : 0;

	r->rt_req_start = get_timestamp_us() + (avg_rtt >> 1);

	uint64_t adj_timeout = 4 * r->selected_proposal->delta_time +
		r->nbufs * avg_rtt + CLIENT_LOOP_DELAY_FACTOR * tc->io_rate * avg_rtt;
	if (adj_timeout < 1000)
		adj_timeout = 1000;

	uint64_t new_timeout = ccow_retry_log2(adj_timeout/1000, r->retry);
	if (new_timeout > CLIENT_GETCOMMON_TIMEOUT_MS) {
		new_timeout = CLIENT_GETCOMMON_TIMEOUT_MS;
	}

	r->accept_timeout = new_timeout;
}

void
client_getcommon_nack_rcvd(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
							ctx->sub_sequence_cnt);

	if (state_check(st, ST_TERM)) {
		return;
	}

	log_error(lg, "RENDEZVOUS TRANSFER NACK received retry: %d seqid %d.%d",
	    r->retry, r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt - 1);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	client_getcommon_reset(r);
	r->retry = 0;
	state_next(st, EV_TIMEOUT);
}
