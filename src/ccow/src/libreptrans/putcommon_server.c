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
#include "putcommon_server.h"

void putcommon_srv__term(struct state *st);

void
putcommon_srv_send_done(void *data, int err, int ctx_valid)
{
	struct putcommon_srv_req *req = data;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;

	req->inexec--;

	log_trace(lg, "data %p, st %p, err %d, ctx_valid %d seqid %d.%d inexec %d"
		      " state %d", data, st, err, ctx_valid, ctx->sequence_cnt,
				   ctx->sub_sequence_cnt, req->inexec, st->cur);

	if (state_check(st, ST_TERM)) {
		putcommon_srv__term(st);
		return;
	}

	if (err) {
		log_error(lg, "Error %d while sending putcommon response for ev %d",
		    err, st->ev_cur);
		state_event(st, EV_ERR);
		return;
	}

	/*
	 * Sometimes, the state machine does not reach the ST_TERM state for
	 * some of the events. Make sure it terminates on these events.
	 */
	if (st->ev_cur == RT_NAMED_PAYLOAD_ACK || st->ev_cur == RT_ACCEPT_NOT_NOW ||
	    st->ev_cur == RT_RENDEZVOUS_NACK ||
	    (req->serial_err && st->ev_cur == EV_DONE)) {
		req->inexec++;
		state_event(st, EV_SEND);
		return;
	}
}

void
putcommon_srv_rtfree(struct state *st)
{
	struct putcommon_srv_req *r = st->data;
	struct repdev *dev = r->dev;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	int err = -1;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	ctx->attributes = 0;
	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;
	if (msg->hdr.attributes & RD_ATTR_UNICAST_TCP && ctx->tcp_handle)
		ctx->attributes = RD_ATTR_UNICAST_TCP;

	struct repmsg_rendezvous_nack nack;
	memset(&nack, 0, sizeof (nack));
	nack.hdr.attributes = msg->hdr.attributes;

	/* Timeout: now send a nack back to the client so
	 * and close out this state machine so the client
	 * can start again
	 */

	if (r->reqtype == PUT_REQ_TYPE_NAMED_RT) {
		struct repmsg_named_chunk_put_proposal *msg_pp = r->msg_pp;
		memcpy(&nack.content_hash_id,&msg_pp->content_hash_id,
		    sizeof (nack.content_hash_id));
		r->inexec++;
		err = replicast_send(dev->robj, ctx, RT_RENDEZVOUS_NACK,
		    (struct repmsg_generic *)&nack,
		    (struct repmsg_generic *)msg_pp,
		    NULL, 0, NULL, putcommon_srv_send_done, r, NULL);
		if (err)
			r->inexec--;

	} else if (r->reqtype == PUT_REQ_TYPE_UNNAMED_RT) {
		struct repmsg_unnamed_chunk_put_proposal *msg_pp = r->msg_pp;
		memcpy(&nack.content_hash_id,&msg_pp->content_hash_id,
		    sizeof (nack.content_hash_id));
		r->inexec++;
		err = replicast_send(dev->robj, ctx, RT_RENDEZVOUS_NACK,
		    (struct repmsg_generic *)&nack,
		    (struct repmsg_generic *)msg_pp,
		    NULL, 0, NULL, putcommon_srv_send_done, r, NULL);
		if (err)
			r->inexec--;
	}

	ctx->attributes = 0;

	if (r->vbuf_allocated) {
		replicast_free_vbuf(&dev->robj->rvbuf, r->req_len);
		replicast_free_vbuf(&ccow_daemon->robj[0]->rvbuf, r->req_len);
		r->vbuf_allocated--;
	}

	r->error = err;
	log_trace(lg, "st %p seqid %d.%d sending NACK err: %d", st,
		  ctx->sequence_cnt, ctx->sub_sequence_cnt, err);
}


void
putcommon_srv__exists(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repmsg_generic *msg = (struct repmsg_generic *)req->msg_pp;
	int err;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	struct repmsg_accept_content_already_stored exists;
	memset(&exists, 0, sizeof (exists));
	// indicate the vdevid of this particular device
	exists.vdevid = dev->vdevid;
	exists.num_datagrams = 1;
	exists.ngcount = req->ngcount;

	req->inexec++;
	err = replicast_send(dev->robj, NULL, req->status,
	    (struct repmsg_generic *)&exists, msg, NULL, 0, NULL,
	    putcommon_srv_send_done, req, NULL);
	if (err) {
		req->inexec--;
		log_trace(lg, "Failed to send RT_ACCEPT_CONTENT_ALREADY_STORED");
		state_next(ctx->state, EV_ERR);
		return;
	}

	/* TODO:
	 * Do not terminate the state machine.
	 * Cleanup backreferences on accept
	 */
}

static void
UV_HPT_TIMER_CB(putcommon_srv_rtfree_timeout, *treq)
{
	struct state *st = treq->data;
	struct putcommon_srv_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repdev *dev = r->dev;
	struct repwqe *wqe = ctx->wqe_in;
	uint64_t now = get_timestamp_us();

	log_trace(lg, "treq %p, seqid %d.%d", treq, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (r->rtfree_timer_req->data) {
		uv_hpt_timer_stop(r->rtfree_timer_fd, r->rtfree_timer_req);
		r->rtfree_timer_req->data = NULL;
	}

	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;
	if (r->rt_acked) {
		log_warn(lg, "RT Free Timeout (rt_acked %d) reached after %ldus seqid %d.%d",
		     r->rt_acked, r->rtfree_timeout,
		     r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt);
		if (PUTCOMMON_RT_TIMER_ENABLE_NACK == 0) {
			r->error = -ESRCH;
			if (!(msg->hdr.attributes & RD_ATTR_UNICAST_TCP)) {
				state_event(ctx->state, EV_ERR);
				return;
			}
		}
	} else {
		log_debug(lg, "Releasing RT Free timer after %ldus seqid %d.%d",
		     r->rtfree_timeout, r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt);
		r->error = -ESRCH;
		if (!(msg->hdr.attributes & RD_ATTR_UNICAST_TCP)) {
			state_event(ctx->state, EV_ERR);
			return;
		}
	}

	state_event(st, EV_TIMEOUT);
}

void
putcommon_srv__send_accept(struct state *st)
{
	struct putcommon_srv_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repdev *dev = r->dev;
	struct repmsg_generic *msg = (struct repmsg_generic *) r->msg_pp;
	int err;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	struct repmsg_accept_proposed_rendezvous accept;
	memset(&accept, 0, sizeof (accept));
	accept.num_datagrams = 1;
	accept.vdevid = dev->vdevid;

	// create a window for the client
	uint64_t genid_delta = 0;
	uint64_t genid = 0;
	uint512_t *ngroup = NULL;

	int qdepth_factor = 1;

	uint64_t part;
	uint64_t select_time_avg;
	if (r->reqtype == PUT_REQ_TYPE_UNNAMED_RT) {
		struct repmsg_unnamed_chunk_put_proposal *pp
			= (struct repmsg_unnamed_chunk_put_proposal *) r->msg_pp;
		struct replicast_object_name *ron = &pp->object_name;
		select_time_avg = pp->select_time_avg;
		genid_delta = pp->genid_delta;
		genid = pp->object_name.uvid_timestamp;
		if (!(msg->hdr.attributes & (RD_ATTR_COMPOUND | RD_ATTR_TARGETED |
			RD_ATTR_COMPOUND_TARGETED | RD_ATTR_VM_MARKER)))
				ngroup = &pp->content_hash_id;
		else
			ngroup = &ron->name_hash_id;
		part = PLEVEL_HASHCALC(ngroup, (dev->plevel - 1));
		if (((dev->flushing & (1 << TT_CHUNK_PAYLOAD)) ||
		    (dev->flushing & (1 << TT_CHUNK_MANIFEST))) &&
		    (dev->flushing_part & (1 < part)))
			qdepth_factor = 2;
	} else if (r->reqtype == PUT_REQ_TYPE_NAMED_RT) {
		struct repmsg_named_chunk_put_proposal *pp
			= (struct repmsg_named_chunk_put_proposal *) r->msg_pp;
		struct replicast_object_name *ron = &pp->object_name;
		select_time_avg = pp->select_time_avg;
		genid_delta = pp->genid_delta;
		genid = pp->object_name.uvid_timestamp;
		ngroup = &ron->name_hash_id;
		part = PLEVEL_HASHCALC(ngroup, (dev->plevel - 1));
		if ((dev->flushing & (1 << TT_VERSION_MANIFEST)) &&
		    (dev->flushing_part & (1 < part)))
			qdepth_factor = 2;
	} else
		assert(0);

	// save this for later
	memcpy(&r->chid, ngroup, sizeof(uint512_t));

	fhrow_t row;
	int ngcount=0;
	ccowd_fhready_lock(FH_LOCK_READ);
	err = flexhash_get_ngcount(SERVER_FLEXHASH, ngroup, &row, &ngcount);
	if (err < 0) {
		if (err != -EAGAIN) {
			ccowd_fhready_unlock(FH_LOCK_READ);
			accept.ngcount = 0;
			log_error(lg, "Put(%s): row (%d) error (%d) while "
				"reading versions: %s", dev->name, row, err, strerror(err));
			state_next(st, EV_ERR);
			return;
		}
	}
	if (ngcount <= 0)
		accept.ngcount = 0;
	else
		accept.ngcount = ngcount;
	if (!ngcount) {
		ccowd_fhready_unlock(FH_LOCK_READ);
		err = -ENODEV;
		log_error(lg, "Put(%s): row (%d) ngcount (%d) error (%d) while "
		    "reading versions", dev->name, row, accept.ngcount, err);
		state_next(st, EV_ERR);
		return;
	}
	r->ngcount = accept.ngcount;

	int found = flexhash_is_rowmember(SERVER_FLEXHASH,
	    &dev->vdevid, ngroup);
	ccowd_fhready_unlock(FH_LOCK_READ);
	if (!found) {
		fhrow_t row = HASHROWID(ngroup, ccow_daemon->flexhash);
		log_debug(lg, "Not a member of row: %d. Ignoring", row);
		state_next(st, EV_ERR);
		return;

	}

	// check to see if we have enough vbuf for this request
	err = replicast_check_avail_vbuf(&ccow_daemon->robj[0]->rvbuf, r->req_len);
	if (err) {
		log_warn(lg, "Not enough vbuf for this request"
		    " requested: %"PRIu64" avail: %"PRIu64" ",
		    r->req_len, replicast_get_avail_vbuf(&ccow_daemon->robj[0]->rvbuf));
		state_next(st, EV_ERR);
		return;
	}

	ccowd_fhready_lock(FH_LOCK_READ);
	uint64_t put_weight = flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
				dev, FH_IOTYPE_PUT);
	assert(put_weight);
	uint64_t get_weight = flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
				dev, FH_IOTYPE_GET);
	assert(get_weight);

	uint64_t now = get_timestamp_us();
	uint64_t start_time = flexhash_estimate_client_start(genid, genid_delta,
	    now, r->pp_rcvd_time);

	/* Networking delay required for a transfer to replay with RCVD messages. We do use
	 * latency here due to lack of gathered statistics on the server side */
	int journaled = (r->reqtype == PUT_REQ_TYPE_UNNAMED_RT &&
		dev->journal && r->req_len < dev->journal_maxchunksize);
	r->rt_delta_timeout
		= flexhash_estimate_delta_time(SERVER_FLEXHASH,
		    &dev->vdevid, r->req_len, journaled ?
		    FH_IOTYPE_PUT_J : FH_IOTYPE_PUT,
		    journaled ? dev->stats.put4k_latency_j : dev->stats.put4k_latency,
		    journaled ? dev->stats.put64k_latency_j : dev->stats.put64k_latency,
		    journaled ? dev->stats.put512k_latency_j : dev->stats.put512k_latency);
	ccowd_fhready_unlock(FH_LOCK_READ);
	if (r->rt_delta_timeout == (uint64_t)-1) {
		/* will not participate */
		char vdevstr[64];
		uint128_dump(&dev->vdevid, vdevstr, 64);
		log_trace(lg, "%s device will not participate", vdevstr);
		state_next(st, EV_ERR);
		return;
	}

	double std_value;
	if (r->req_len < 65536)
		std_value = avg_ring_std(journaled ?  &dev->put4k_avg_samples_j :
			&dev->put4k_avg_samples);
	else if (r->req_len < 524288)
		std_value = avg_ring_std(journaled ?  &dev->put64k_avg_samples_j :
			&dev->put64k_avg_samples);
	else
		std_value = avg_ring_std(journaled ?  &dev->put512k_avg_samples_j :
			&dev->put512k_avg_samples);
	r->rt_delta_timeout += (uint64_t)std_value;

	r->client_start_time = (uint64_t)std_value * qdepth_factor;
	start_time += r->client_start_time;
	accept.rendezvous_proposal.start_time = start_time;

	accept.rendezvous_proposal.delta_time = r->rt_delta_timeout;
	// accept.rendezvous_proposal.xmit_bandwidth;

	 // now compute the weight based on capacity, QD and other parameters
	accept.rendezvous_proposal.weight_io = put_weight + get_weight;
	accept.rendezvous_proposal.weight_io *= qdepth_factor;

	ccowd_fhready_lock(FH_LOCK_READ);
	accept.rendezvous_proposal.avail_space
		= flexhash_estimate_vdev_avail_pct(SERVER_FLEXHASH, dev);
	ccowd_fhready_unlock(FH_LOCK_READ);

	r->inexec++;
	err = replicast_send(dev->robj, ctx, RT_ACCEPT_PROPOSED_RENDEZVOUS,
	    (struct repmsg_generic *)&accept, msg,
	    NULL, 0, NULL, putcommon_srv_send_done, r, NULL);
	if (err) {
		r->inexec--;
		log_trace(lg, "Failed to send RT_ACCEPT_PROPOSED_RENDEZVOUS");
		state_next(st, EV_ERR);
		return;
	}

	if (r->rtfree_timer_req->data)
		uv_hpt_timer_stop(r->rtfree_timer_fd, r->rtfree_timer_req);
	r->rtfree_timer_req->data = st;

	if (msg->hdr.attributes & RD_ATTR_UNICAST_TCP) {
		r->rtfree_timeout = PUTCOMMON_SELECT_TIME_TCP;
	} else {
		/* take delayed start into account */
		r->rtfree_timeout = select_time_avg * accept.ngcount;
		if (r->rtfree_timeout < PUTCOMMON_SELECT_TIME_MIN)
			r->rtfree_timeout = PUTCOMMON_SELECT_TIME_MIN;
		if (r->rtfree_timeout > PUTCOMMON_SELECT_TIME_MAX)
			r->rtfree_timeout = PUTCOMMON_SELECT_TIME_MAX;
	}
	err = uv_hpt_timer_start(r->rtfree_timer_fd, r->rtfree_timer_req,
	    r->rtfree_timeout, putcommon_srv_rtfree_timeout);
	if (err) {
		r->rtfree_timer_req->data = NULL;
		log_error(lg, "UNNAMED PUT operation error %d on rendezvous "
		    "accept send due to end timer creation", err);
		state_next(st, EV_ERR);
		return;
	}
}

static int
putcommon_multicast_join(struct repdev *dev, struct repctx *ctx,
			 struct repmsg_rendezvous_ack *ack)
{
	char mcgrp[INET6_ADDRSTRLEN];
	struct in6_addr rtaddr;
	memcpy(&rtaddr, &ack->rendezvous_group, 16);
	inet_ntop(AF_INET6, &rtaddr, mcgrp, INET6_ADDRSTRLEN);

	uint32_t if_index = ccow_daemon->if_indexes[0];
	int err = replicast_join_throttle(dev);
	if (err)
		return err;

	err = replicast_join(dev->robj, mcgrp, if_index);
	if (err)
		return err;

	replicast_join_cache_update(dev, mcgrp, if_index);

	return 0;
}

static int
putcommon_set_min_and_check(struct putcommon_srv_req *r,
    uint128_t *group_members)
{
	struct repdev *dev = r->dev;
	uint128_t z128;
	uint128_set64(&z128, 0, 0);

	uint128_t min = dev->vdevid;
	int min_idx = -1;

	r->min = 0;

	for (int i = 0; i < REPLICAST_REPLICATION_COUNT_MAX; i++) {
		int rv = uint128_cmp(&group_members[i], &z128);
		if (rv == 0) {
			continue;
		}

		rv = uint128_cmp(&group_members[i], &min);
		if (rv <= 0) {
			min = group_members[i];
			min_idx = i;
		}

	}

	int found = 0;
	int fnd_idx = -1;

	for (int i = 0; i < REPLICAST_REPLICATION_COUNT_MAX; i++) {
		if (uint128_cmp(&dev->vdevid, &group_members[i]) == 0) {
			found = 1;
			fnd_idx = i;
			break;
		}
	}
	if (!found) {
		/* we will free reservations and
		 * also, we close this state machine at this time */
		if (r->vbuf_allocated) {
			replicast_free_vbuf(&dev->robj->rvbuf, r->req_len);
			replicast_free_vbuf(&ccow_daemon->robj[0]->rvbuf, r->req_len);
			r->vbuf_allocated--;
		}
		return 0;
	}

	if ((min_idx != -1) && (min_idx == fnd_idx)) {
		r->min = 1;
	}
	return 1;
}

void putcommon_srv_rt_ack(struct state *st)
{
	struct putcommon_srv_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repdev *dev = r->dev;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_rendezvous_ack *ack =
		(struct repmsg_rendezvous_ack *)wqe->msg;
	int err;

	log_trace(lg, "st %p seqid %d.%d inexec %d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, r->inexec);

	/* we've received ack: disarm ongoing timer */
	if (r->rtfree_timer_req->data) {
		uv_hpt_timer_stop(r->rtfree_timer_fd, r->rtfree_timer_req);
		r->rtfree_timer_req->data = NULL;
	}

	if (r->rt_acked)
		return;
	r->rt_acked = 1;

	int found = putcommon_set_min_and_check(r, ack->group_members);
	if (!found) {
		char vdevstr[64];
		uint128_dump(&dev->vdevid, vdevstr, 64);
		log_debug(lg, "ACK %p seqid %d.%d dev %s not in the group",
				st, ctx->sequence_cnt, ctx->sub_sequence_cnt,
				vdevstr);
		state_next(st, EV_ERR);
		return;
	}

	if (ack->hdr.attributes & RD_ATTR_MC_LAZY_JOIN) {
		err = putcommon_multicast_join(dev, ctx, ack);
		if (err != 0) {
			/* FIXME: should we free vbuf here? */
			log_trace(lg, "%p seqid %d.%d failed to join MC", st,
				  ctx->sequence_cnt, ctx->sub_sequence_cnt);
			state_next(st, EV_ERR);
			return;
		}

	}

	replicast_alloc_vbuf(&dev->robj->rvbuf, r->req_len, VBUF_STAT_TRUE);

	err = replicast_alloc_vbuf(&ccow_daemon->robj[0]->rvbuf, r->req_len, VBUF_STAT_FALSE);
	if (err) {
		replicast_free_vbuf(&dev->robj->rvbuf, r->req_len);
		log_warn(lg, "Cannot allocate vbuf for %"PRId64 " Rendezvous"
		    " Transfer err=%d avail: %"PRIu64" ", r->req_len, err,
		    replicast_get_avail_vbuf(&ccow_daemon->robj[0]->rvbuf));
		state_next(st, EV_ERR);
		return;
	}
	r->vbuf_allocated++;

	r->rt_delta_timeout += ack->join_delay;

	if (r->rtfree_timer_req->data)
		uv_hpt_timer_stop(r->rtfree_timer_fd, r->rtfree_timer_req);
	r->rtfree_timer_req->data = st;

	if (ack->hdr.attributes & RD_ATTR_UNICAST_TCP) {
		r->rtfree_timeout = PUTCOMMON_SELECT_TIME_TCP;
	} else {
		r->rtfree_timeout = r->client_start_time +
			PUTCOMMON_RT_TIMER_NACK_FACTOR * r->rt_delta_timeout;
		if (r->rtfree_timeout < PUTCOMMON_RT_FREE_TIME_MIN)
			r->rtfree_timeout = PUTCOMMON_RT_FREE_TIME_MIN;
		if (r->rtfree_timeout > PUTCOMMON_RT_FREE_TIME_MAX)
			r->rtfree_timeout = PUTCOMMON_RT_FREE_TIME_MAX;
	}

	log_debug(lg, "RENDEZVOUS_TRANSFER Timer started with "
	    "%ldus seqid %d.%d", r->rtfree_timeout, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt);

	err = uv_hpt_timer_start(r->rtfree_timer_fd, r->rtfree_timer_req,
	    r->rtfree_timeout, putcommon_srv_rtfree_timeout);
	if (err) {
		r->rtfree_timer_req->data = NULL;
		log_error(lg, "UNNAMED PUT operation error %d on rendezvous "
		    "accept send due to end timer creation", err);
		state_next(st, EV_ERR);
		return;
	}
}

void
putcommon_srv_payload_ack(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repwqe *wqe = ctx->wqe_in;
	int err = 0;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;
	if (ctx->attributes == RD_ATTR_UNICAST_TCP) {
		assert(msg->hdr.attributes & RD_ATTR_UNICAST_TCP);
		if (ctx->tcp_handle == NULL) {
			log_trace(lg, "Unexpected NULL TCP handle");
			state_next(ctx->state, EV_ERR);
			return;
		}
	}

	req->inexec++;
	if ((req->reqtype == PUT_REQ_TYPE_NAMED)
	    || (req->reqtype == PUT_REQ_TYPE_NAMED_RT)) {
		struct repmsg_named_chunk_put_proposal *msg =
			(struct repmsg_named_chunk_put_proposal *) req->msg_pp;
		struct repmsg_named_payload_ack ack;
		memset(&ack, 0, sizeof (ack));
		ack.hdr.attributes = msg->hdr.attributes;
		ack.num_datagrams = 1;
		ack.content_hash_id = msg->content_hash_id;
		ack.object_name = msg->object_name;

		if (msg->hdr.attributes & RD_ATTR_SERIAL_OP) {
			ack.object_name.generation = req->sop_generation;
		}

		ack.vdevid = dev->vdevid;
		err = replicast_send(dev->robj, ctx, RT_NAMED_PAYLOAD_ACK,
		    (struct repmsg_generic *)&ack, (struct repmsg_generic *)msg,
		    NULL, 0, NULL, putcommon_srv_send_done, req, NULL);

	} else if ((req->reqtype == PUT_REQ_TYPE_UNNAMED)
	    || (req->reqtype == PUT_REQ_TYPE_UNNAMED_RT)) {
		struct repmsg_unnamed_chunk_put_proposal *msg =
			(struct repmsg_unnamed_chunk_put_proposal *) req->msg_pp;
		struct repmsg_unnamed_payload_ack ack;
		memset(&ack, 0, sizeof (ack));
		ack.hdr.attributes = msg->hdr.attributes;
		ack.num_datagrams = 1;
		ack.content_hash_id = msg->content_hash_id;

		ack.vdevid = dev->vdevid;
		err = replicast_send(dev->robj, ctx, RT_UNNAMED_PAYLOAD_ACK,
		    (struct repmsg_generic *)&ack, (struct repmsg_generic *)msg,
		    NULL, 0, NULL, putcommon_srv_send_done, req, NULL);
	} else
		assert(0);

	ctx->attributes = 0;
	if (err) {
		req->inexec--;
		log_trace(lg, "Failed to send PAYLOAD_ACK");
		state_next(ctx->state, EV_ERR);
		return;
	}

	/* if this was a RT request, free up the timer */

	if ((req->reqtype == PUT_REQ_TYPE_NAMED_RT)
	    || (req->reqtype == PUT_REQ_TYPE_UNNAMED_RT)) {

		if (req->rtfree_timer_req->data) {
			uv_hpt_timer_stop(req->rtfree_timer_fd, req->rtfree_timer_req);
			req->rtfree_timer_req->data = NULL;
		}
	}
}

void
putcommon_srv__busy(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_named_chunk_put_proposal *msg =
		(struct repmsg_named_chunk_put_proposal *)wqe->msg;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	struct repmsg_accept_not_now busy;
	memset(&busy, 0, sizeof (busy));
	busy.num_datagrams = 1;
	busy.ngcount = req->ngcount;
	// busy.earliest_suggested_retry = 0 FIXME: implement
	busy.error = req->error;
	busy.vdevid = dev->vdevid;

	req->inexec++;
	int err = replicast_send(dev->robj, NULL, RT_ACCEPT_NOT_NOW,
	    (struct repmsg_generic *)&busy, (struct repmsg_generic *)msg, NULL,
	    0, NULL, putcommon_srv_send_done, req, NULL);
	if (err) {
		req->inexec--;
		log_trace(lg, "Failed to send RT_ACCEPT_NOT_NOW");
		state_next(ctx->state, EV_ERR);
		return;
	}
}

void
putcommon_srv__error(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_named_chunk_put_proposal *msg =
		(struct repmsg_named_chunk_put_proposal *)wqe->msg;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (req->error && req->error != -EEXIST && req->error != -ESRCH) {
		log_debug(lg, "Put(%s): FSM %p: prev %d ev_prev:ev_next %d:%d => "
		    "cur %d err %d", dev->name, st, st->prev, st->ev_prev,
		    st->ev_next, st->cur, req->error);
	}
}

void
putcommon_srv_transfer(struct state *st, ccowtp_work_cb work_cb,
		       ccowtp_after_work_cb after_work_cb )
{
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repwqe *wqe = ctx->wqe_in;
	int err;
	int event;

	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;

	dev->put_net_rx++;
	log_trace(lg, "st %p, work_cb %p after_work_cb %p seqid %d.%d", st,
	    work_cb, after_work_cb, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (msg->hdr.attributes & RD_ATTR_UNICAST_TCP)
	    ctx->attributes = RD_ATTR_UNICAST_TCP;

	/* get the array index as the datagram numbering starts at 1 */
	int idx = wqe->msg->hdr.datagram_num - 1;
	if (idx >= wqe->msg->num_datagrams) {
		log_error(lg, "Corrupt RT put: %s idx: %d >= num_datagrams: %d",
		    replicast_opcode_str[wqe->msg->hdr.transaction_id.opcode],
		    idx, wqe->msg->num_datagrams);
		req->error = RT_ERR_EIO;
		dev->put_net_rx--;
		event = msg->hdr.attributes & RD_ATTR_UNICAST_TCP ?
			RT_RENDEZVOUS_NACK : EV_ERR;
		state_next(ctx->state, event);
		return;
	}

	if (req->payload[idx].base) {
		/*
		 * Already got this one, skip and wait for more
		 * datagrams
		 */
		log_warn(lg, "Duplicate: %s idx: %d num_datagrams: %d"
		    " rcvd: %d datagram_num: %d content_length: %d"
		    " nread: %ld seqid %d.%d",
		    replicast_opcode_str[msg->hdr.transaction_id.opcode],
		    idx, msg->num_datagrams,
		    req->dgrams_rcvd, wqe->msg->hdr.datagram_num,
		    msg->content_length, wqe->nread,
		    ctx->sequence_cnt, ctx->sub_sequence_cnt);

		dev->put_net_rx--;
		return;
	}

	req->payload[idx].len = repwqe_payload_len(wqe);
	req->payload[idx].base = repwqe_payload(wqe);

	/* place this datagram into receiving buffer */
	log_debug(lg, "%s idx: %d num_datagrams: %d"
	    " rcvd: %d datagram_num: %d content_length: %d"
	    " nread: %ld seqid %d.%d",
	    replicast_opcode_str[msg->hdr.transaction_id.opcode],
	    idx, msg->num_datagrams,
	    req->dgrams_rcvd, wqe->msg->hdr.datagram_num,
	    msg->content_length, wqe->nread,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);


	if (msg->num_datagrams != ++req->dgrams_rcvd) {
		/* wait for more datagrams */
		dev->put_net_rx--;
		return;
	}

	/* we've received ack: disarm ongoing timer */
	if (req->rtfree_timer_req->data) {
		uv_hpt_timer_stop(req->rtfree_timer_fd, req->rtfree_timer_req);
		req->rtfree_timer_req->data = NULL;
	}

	if (!req->rt_acked) {
		req->rt_acked = 1;

		int found = putcommon_set_min_and_check(req, msg->group_members);
		if (!found) {
			char vdevstr[64];
			uint128_dump(&dev->vdevid, vdevstr, 64);
			log_error(lg, "RT %p seqid %d.%d dev %s not in "
				      "the group", st, ctx->sequence_cnt,
				      ctx->sub_sequence_cnt, vdevstr);
			dev->put_net_rx--;
			event = msg->hdr.attributes & RD_ATTR_UNICAST_TCP ?
				RT_RENDEZVOUS_NACK : EV_ERR;
			state_next(st, event);
			return;
		}
	}

	log_debug(lg, "All datagrams %d of %d received seqid %d.%d",
	    req->dgrams_rcvd, msg->num_datagrams,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);
	req->nbufs = req->dgrams_rcvd;
	dev->put_disk_qdepth++;

	/* we free up the vbufs immediately as we have completed the network IO */
	if (req->vbuf_allocated) {
		replicast_free_vbuf(&dev->robj->rvbuf, req->req_len);
		replicast_free_vbuf(&ccow_daemon->robj[0]->rvbuf, req->req_len);
		req->vbuf_allocated--;
	}
	// Now we tell the client we have received all so they can re-arm their
	// timers when waiting for the final payload_ack
	struct repmsg_payload_rcvd rcvd_ack;
	memset(&rcvd_ack, 0, sizeof (rcvd_ack));
	memcpy(&rcvd_ack.vdevid, &dev->vdevid, sizeof (uint128_t));
	rcvd_ack.ngcount = req->ngcount;
	rcvd_ack.fddelta = ccowd_get_fddelta();
	if (ctx->attributes == RD_ATTR_UNICAST_TCP)
		rcvd_ack.hdr.attributes = RD_ATTR_UNICAST_TCP;

	int journaled = (req->reqtype == PUT_REQ_TYPE_UNNAMED_RT &&
		dev->journal && req->req_len < dev->journal_maxchunksize);

	ccowd_fhready_lock(FH_LOCK_READ);
	rcvd_ack.put_delta
		= flexhash_estimate_90th(SERVER_FLEXHASH,
		    &dev->vdevid, req->req_len,
		    journaled ? dev->stats.put90th_4k_latency_j : dev->stats.put90th_4k_latency,
		    journaled ? dev->stats.put90th_64k_latency_j : dev->stats.put90th_64k_latency,
		    journaled ? dev->stats.put90th_512k_latency_j : dev->stats.put90th_512k_latency);

	uint64_t put_weight = flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
				dev, FH_IOTYPE_PUT);
	ccowd_fhready_unlock(FH_LOCK_READ);
	assert(put_weight);

	/* NamedPut is heavy, and UnnamedPut also does SBR, so account for it */
	if (req->reqtype == PUT_REQ_TYPE_NAMED_RT)
		rcvd_ack.put_delta *= 4;
	else
		rcvd_ack.put_delta *= 2;
	rcvd_ack.put_delta *= put_weight;
	rcvd_ack.put_delta *= (dev->flushing ? 4 : 1);

	req->inexec++;
	err = replicast_send(dev->robj, ctx, RT_PAYLOAD_RCVD,
	    (struct repmsg_generic *)&rcvd_ack, (struct repmsg_generic *)msg,
	    NULL, 0, NULL, putcommon_srv_send_done, req, NULL);
	if (err) {
		log_error(lg, "Failed to send RT_NAMED_PAYLOAD_RCVD back to the "
		    " client ");
		dev->put_disk_qdepth--;
		dev->put_net_rx--;
		req->inexec--;
		state_next(ctx->state, EV_ERR);
		return;
	}

	/* add this to the local cache so we can respond to GET requests
	 * in case the client sends out immediate GETs

	  In the named case we do not check as the CHIDS for named objects
	  are unique and since we have one device loop they will arrive in
	  sequence. The behaviour is implied

	 */
	if ( !(msg->hdr.attributes & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED)) &&
		((req->reqtype == PUT_REQ_TYPE_UNNAMED) ||
		( req->reqtype == PUT_REQ_TYPE_UNNAMED_RT)) )
			reptrans_addto_rcvd_cache(dev->rcvd_cache, &req->chid,
				req);

	req->inexec++;
	assert(after_work_cb);

	/*
	 *  For SOP we do not schedule work. Process SOP first, then schedule
	 *  it separately.
	 */
	if (msg->hdr.attributes & RD_ATTR_SERIAL_OP) {
		assert(!(msg->hdr.attributes & RD_ATTR_VM_MARKER));
		dev->put_disk_qdepth--;
		dev->put_net_rx--;
		work_cb(wqe);
		after_work_cb(wqe, 0);
		return;
	}

	/* For VMM we do not schedule. qdepth has to be incremented */
	req->vmm = 0;
	if (msg->hdr.attributes & RD_ATTR_VM_MARKER) {
		req->vmm = 1;
		work_cb(wqe);
		after_work_cb(wqe, 0);
		return;
	}

	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_MID, work_cb, after_work_cb, wqe);
}

static void
putcommon_rtfree_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
putcommon_pp_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

void putcommon_srv__term(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p inexec %d seqid %d.%d", st, req->inexec,
			ctx->sequence_cnt, ctx->sub_sequence_cnt);

	assert(ctx->opcode_in == RT_NAMED_CHUNK_PUT_PROPOSAL ||
	    ctx->opcode_in == RT_UNNAMED_CHUNK_PUT_PROPOSAL);
	assert(req->inexec >= 0);

	repctx_drop(req->ctx);

	assert(req->inexec != ~0L);
	if (req->inexec) {
		log_debug(lg, "req %p request inexec %d, st %p cannot terminate",
		    req, req->inexec, st);
		return;
	}

	reptrans_rmfrom_rcvd_cache(dev->rcvd_cache, &req->chid);

	if (req->vbuf_allocated) {
		replicast_free_vbuf(&dev->robj->rvbuf, req->req_len);
		replicast_free_vbuf(&ccow_daemon->robj[0]->rvbuf, req->req_len);
		req->vbuf_allocated--;
	}

	if (req->rtfree_timer_req->data) {
		uv_hpt_timer_stop(req->rtfree_timer_fd, req->rtfree_timer_req);
		req->rtfree_timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)req->rtfree_timer_req,
	    putcommon_rtfree_timer_close_cb);

	if (req->rtfree_timer_fd > 0) {
		uv_hpt_timer_close(req->rtfree_timer_fd, req->rtfree_timer_req);
	}

	if (req->pp_timer_req->data) {
		uv_timer_stop(req->pp_timer_req);
		req->pp_timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)req->pp_timer_req, putcommon_pp_timer_close_cb);

	req->inexec = ~0L;
	reptrans_dev_ctxfree_one(dev, req->ctx);
}

