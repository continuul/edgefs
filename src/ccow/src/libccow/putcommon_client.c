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
#include <sys/param.h>
#include "ccowutil.h"
#include "state.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "putcommon_client.h"

static void
client_putcommon_update_needed_replicas(struct putcommon_client_req *r)
{
	ccow_t tc = r->tc;
	int fd = tc->failure_domain;
	uint16_t row = HASHROWID(&r->ng_chid, tc->flexhash);
	if (fd == FD_ZONE) {
		r->zonecount = flexhash_row_zonecount(CLIENT_FLEXHASH, row);
		if (r->needed_replicas > r->zonecount) {
			r->needed_replicas = (r->zonecount > tc->sync_put_fd_min ?
				r->zonecount : tc->sync_put_fd_min);
		}
	} else if (fd == FD_SERVER) {
		r->servercount = flexhash_row_servercount(CLIENT_FLEXHASH, row);
		if (r->needed_replicas > r->servercount) {
			r->needed_replicas = (r->servercount > tc->sync_put_fd_min ?
				r->servercount : tc->sync_put_fd_min);
		}
	}
}

int
client_putcommon_guard_rt_retry(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "st %p seqid %d.%d rt_retry %d , req %p", st,
		ctx->sequence_cnt, ctx->sub_sequence_cnt, r->rt_retry, r);

	if (r->rt_retry++ < CLIENT_PUTCOMMON_MAX_RETRY)
		return 1; // ok

	log_error(lg, "PUT RT timed out after %d attempts "
	    "seq id: %d.%d. Failing I/O", r->rt_retry - 1, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt - 1);

	ccow_fail_io(r->io, -EIO);
	state_next(st, EV_ERR);
	return 0; // fail
}

static void
UV_HPT_TIMER_CB(client_putcommon_rtsend_timeout, *treq)
{
	struct state *st = treq->data;
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;

	log_trace(lg, "treq %p, seqid %d.%d", treq, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	log_warn(lg, "RENDEZVOUS_TRANSFER %s Timeout reached after %" PRIu64 "us"
	    " rt_retry: %d delayed_start_us: %ld seqid %d.%d, payload_rcvd (delta) %ldus",
	    r->rcvd_max_delta ? "Payload Wait" : "Payload Rcvd",
	    r->rt_delta_timeout, r->rt_retry, r->delayed_start_us,
	    r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt,
	    r->rcvd_max_delta);

	if (r->rtsend_timer_req->data) {
		uv_hpt_timer_stop(r->rtsend_timer_fd, r->rtsend_timer_req);
		r->rtsend_timer_req->data = NULL;
	}

	/*
	 * If rtsend timed out, restart the entire sequence, starting from
	 * PUT PROPOSAL again.
	 */
	state_event(st, EV_TIMEOUT);
}

/*
 * This timer is started only for UDP.
 */
static void
start_rt_timer(struct putcommon_client_req *r, struct state *st)
{
	int err;

	assert(r->tc->unicastio != REPLICAST_UNICAST_TCP);

	if (r->rtsend_timer_req->data)
		uv_hpt_timer_stop(r->rtsend_timer_fd, r->rtsend_timer_req);
	r->rtsend_timer_req->data = st;

	err = uv_hpt_timer_start(r->rtsend_timer_fd, r->rtsend_timer_req,
	    r->rt_delta_timeout, client_putcommon_rtsend_timeout);
	if (err) {
		r->rtsend_timer_req->data = NULL;
		log_error(lg, "PUT operation error %d on hpt timer start", err);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}
}

void
client_putcommon_process_busy(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_op *op = r->io->op;
	uint512_t *nhid = &op->name_hash_id;
	ccow_t tc = r->tc;
	fhrow_t row;
	struct repmsg_accept_not_now *msg = (struct repmsg_accept_not_now *)wqe->msg;
	int ngcount = msg->ngcount;
	int i;
        log_trace(lg, "st %p seqid %d.%d rt_retry %d , req %p, op %p, ngcount %i", st,
                ctx->sequence_cnt, ctx->sub_sequence_cnt, r->rt_retry, r, op, ngcount);

	if (msg->error == RT_ERR_NO_SPACE) {
		uint128_logdump(lg, "ENOSPC vdevid", &msg->vdevid);

		int found = 0;
		/* Eliminate duplicates */
		for (i = 0; i < r->out_of_space_count; i++) {
			if (uint128_cmp(&r->out_of_space_vdevs[i],
					&msg->vdevid) == 0) {
				found = 1;
				break;
			}
		}
		if (found)
			return;

		r->out_of_space_vdevs[r->out_of_space_count++] = msg->vdevid;

		if ((r->out_of_space_count != 0 && r->out_of_space_count >
			ngcount - r->needed_replicas) ||
			(r->io->attributes & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED))) {
			log_error(lg, "Out of space on %i devices, ngcount %i, needed replicas %i, retries %i",
				r->out_of_space_count, ngcount, r->needed_replicas, r->rt_retry);
			ccow_fail_io(r->io, -ENOSPC);
			state_next(st, EV_ERR);
			return;
		}
	} else if (r->rtselected) {
		/* TODO: How to distinguish between RT and PP ACCEPT_NOT_NOW? */
		/* RT_ACCEPT_NOT_NOW received in RT phase (is this enough?)*/
		r->rt_busy_count++;
		/* Not all devices are ready - retry the PUT op */
		if (r->rt_busy_count + r->ack_count >= r->selected_count) {
			if (r->terminated) {
				log_debug(lg, "Terminating %p\n", st);
				state_override(st, ST_TERM);
				return;
			}
			log_debug(lg, "Retrying ... busy=%d ack=%d selected=%d",
				r->rt_busy_count, r->ack_count, r->selected_count);

			if (r->tc->unicastio != REPLICAST_UNICAST_TCP) {
				r->rt_delta_timeout = ccow_retry_log2(
				    CLIENT_PUTCOMMON_REARM_NOTNOW_MS * 1000, r->rt_retry);
				start_rt_timer(r, st);
			} else
				state_next(st, EV_TIMEOUT);
		}
		return;
	} else {
		/* RT_ACCEPT_NOT_NOW received in proposal phase */
		r->pp_busy_count++;
	}

	if (r->pp_busy_count == ngcount ||
	    (r->selected_count < r->needed_replicas &&
	     r->proposed_count + r->already_stored_count + r->pp_busy_count +
	     r->out_of_space_count >= ngcount)) {
		if (r->terminated) {
			log_debug(lg, "Terminating %p\n", st);
			state_override(st, ST_TERM);
			return;
		}
		log_debug(lg, "Retrying ... busy=%d ngcount=%d selected=%d RO=%d",
			r->pp_busy_count, ngcount, r->selected_count,
			r->out_of_space_count);

		if (r->tc->unicastio != REPLICAST_UNICAST_TCP) {
			r->rt_delta_timeout = ccow_retry_log2(
			    CLIENT_PUTCOMMON_REARM_NOTNOW_MS * 1000, r->retry);
			start_rt_timer(r, st);
		} else
			state_next(st, EV_TIMEOUT);
	}
}

static struct sockaddr_in6 *
get_unicast_addr(struct putcommon_client_req *r, uint128_t vdevid)
{
	uint8_t idx;
	int rc;
	struct sockaddr_in6 *in6 = NULL;

	for (idx = 0; idx < REPLICAST_PROPOSALS_MAX; idx++) {
		rc = memcmp(&vdevid, &r->vdevip[idx].vdevid, sizeof(vdevid));
		if (rc == 0) {
			in6 = &r->vdevip[idx].saddr;
			break;
		}
	}
	return in6;
}

static void
send_unicast(struct state *st, int unicastio)
{
	int err;
	int wait = 0;
	uint8_t srv;
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_network *netobj = r->tc->netobj;
	rtbuf_t *payload = r->payload;
	struct ccow *tc = r->tc;
	size_t len = rtbuf_len(payload);

	log_trace(lg, "st %p payload %p len %lu seqid %d.%d", st, payload, len,
		ctx->sequence_cnt, ctx->sub_sequence_cnt);

	r->rt_req_start = get_timestamp_us();
	/*
	 * We will send IO to all the selected devices/servers. The devices
	 * have been already selected as per policy (until we reach here)
	 * If we are able to send IO to only few of the selected device/servers,
	 * putcomon_srv_rt_ack will do the cleanup.
	 */
	for (srv = 0; srv < r->selected_count; srv++) {
		/*
		 * Prepare Rendezvous Transfer
		 */
		struct repmsg_rendezvous_transfer msg;
		memset(&msg, 0, sizeof (msg));
		msg.hdr.attributes = io->attributes;
		msg.hdr.hash_type = r->hash_type;

		ctx->attributes = 0;
		if (unicastio == REPLICAST_UNICAST_UDP) {
			msg.hdr.attributes &= ~RD_ATTR_UNICAST_UDP_MCPROXY;
			msg.hdr.attributes |= RD_ATTR_UNICAST_UDP;
		} else if (unicastio == REPLICAST_UNICAST_TCP) {
			msg.hdr.attributes |= RD_ATTR_UNICAST_TCP;
			/* Set transport attribute */
			ctx->attributes = RD_ATTR_UNICAST_TCP;
		}

		int j = 0;
		for (int i = 0; i < r->selected_count; i++) {
			if (uint128_cmp(&r->selected_vdevs[i], &uint128_null) == 0)
				continue;
			msg.group_members[j] = r->selected_vdevs[i];
			uint128_logdump(lg, "RT ACK selected_vdevid",
			    &r->selected_vdevs[i]);
			j++;
		}

		msg.content_length = msg.hdr.data_len = len;
		msg.content_hash_id = r->chid;

		r->inexec++;
		struct sockaddr_in6 *dev_addr;
		dev_addr = get_unicast_addr(r, r->selected_vdevs[srv]);
		assert(dev_addr != NULL);
		err = replicast_send(netobj->robj[0], ctx,
		    RT_RENDEZVOUS_TRANSFER,
		    (struct repmsg_generic *)&msg, NULL,
		    payload->bufs, payload->nbufs, dev_addr,
		    replicast_send_done_generic, st, NULL);
		if (err) {
			r->inexec--;
			log_error(lg, "PUT operation error %d on send", err);
		}
		/* Reset back transport attribute */
		ctx->attributes = 0;
	}
}

int
client_putcommon_guard_tcp_connect(struct state *st)
{
	struct putcommon_client_req *r = st->data;

	if (r->tcp_conn_wait_count == r->tcp_connected_count)
		return 1;

	r->tcp_connected_count++;
	log_debug(lg, "st: %p tcp-connect-wait: %d tcp-connected: %d",
		  st, r->tcp_conn_wait_count, r->tcp_connected_count);

	return r->tcp_conn_wait_count == r->tcp_connected_count;
}

void
client_connect_cb(void *data, int status)
{
	struct put_tcp_cb_data *cb_data = (struct put_tcp_cb_data *)data;
	struct state *st = cb_data->st;
	struct putcommon_client_req *r = st->data;
	struct ccow_network *netobj = r->tc->netobj;
	int err;

	/* Log notice printed by sender_connect_cb() */
	if (status != 0) {
		if (errno == EAGAIN) {
			if (r->tcp_retry++ > CLIENT_PUTCOMMON_TCP_RETRY_MAX) {
				log_error(lg, "Reached max tcp connect retries "
					      "%d times", r->tcp_retry);
				state_event(st, EV_ERR);
				return;
			}
			err = replicast_tcp_connect(netobj->robj[0],
						    cb_data->dest,
						    client_connect_cb,
						    (void *)cb_data);
			if (err != 0) {
				log_error(lg, "Error on retry tcp connect. "
					      "err=%d", err);
				state_event(st, EV_ERR);
				return;
			}

		} else {
			log_error(lg, "Error on tcp connect error: %d : %s",
				  errno, strerror(errno));
			state_event(st, EV_ERR);
			return;
		}
	} else
		state_event(st, RT_TCP_CONNECT_SUCCESS);
}

void
client_putcommon_tcp_connect(struct state *st)
{
	int err;
	uint8_t srv;
	struct putcommon_client_req *r = st->data;
	struct ccow_network *netobj = r->tc->netobj;
	struct ccow *tc = r->tc;

	assert(r->tcp_conn_wait_count == 0);

	/* Check connection status */
	for (srv = 0; srv < r->selected_count; srv++) {
		struct sockaddr_in6 *dev_addr;
		dev_addr = get_unicast_addr(r, r->selected_vdevs[srv]);

		/* For debugging */
		char dest[INET6_ADDRSTRLEN + 1] = { 0 };
		uv_ip6_name((struct sockaddr_in6 *)dev_addr,
			    dest, INET6_ADDRSTRLEN);
		log_debug(lg, "Connecting to %s.%d", dest,
			  ntohs(dev_addr->sin6_port));

		r->cb_data[srv].dest = dev_addr;
		r->cb_data[srv].st = st;
		err = replicast_tcp_connect(netobj->robj[0], dev_addr,
					    client_connect_cb,
					    (void *)&r->cb_data[srv]);
		if (err != 0 && err != -EAGAIN && err != -EEXIST) {
			log_error(lg, "PUT operation error %d on connect", err);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return;
		}
		/*
		 * We want to connect to all devs - hence don't break
		 * the loop
		 */
		if (err == 0 || err == -EAGAIN) {
			log_debug(lg, "waiting to establish connection: err=%d", err);
			r->tcp_conn_wait_count++;
		} else {
			log_debug(lg, "connection exists: err=%d", err);
		}
	}

	/* All connnections exist, send data */
	if (r->tcp_conn_wait_count == 0) {
		log_debug(lg, "All connections already established");
		state_next(st, RT_TCP_CONNECT_SUCCESS);
	}
}

static void
send_multicast(struct state *st)
{
	int err;
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_network *netobj = r->tc->netobj;
	rtbuf_t *payload = r->payload;
	size_t len = rtbuf_len(payload);

	log_trace(lg, "st %p payload %p len %lu seqid %d.%d", st, payload, len,
		ctx->sequence_cnt, ctx->sub_sequence_cnt);

	/*
	 * Prepare Rendezvous Transfer
	 */
	r->rt_req_start = get_timestamp_us();
	struct repmsg_rendezvous_transfer msg;
	memset(&msg, 0, sizeof (msg));
	msg.hdr.attributes = io->attributes;
	msg.hdr.hash_type = r->hash_type;

	msg.content_length = msg.hdr.data_len = len;
	msg.content_hash_id = r->chid;

	int i, j = 0;
	for (i = 0; i < r->selected_count; i++) {
		if (uint128_cmp(&r->selected_vdevs[i], &uint128_null) == 0)
			continue;
		msg.group_members[j] = r->selected_vdevs[i];
		j++;
	}

	// FIXME: broker has to spread out requests among multiple net ports
	r->selected_rtaddr.sin6_scope_id = netobj->if_indexes[0];
	r->inexec++;

	err = replicast_send(netobj->robj[0], ctx, RT_RENDEZVOUS_TRANSFER,
	    (struct repmsg_generic *)&msg, NULL,
	    payload->bufs, payload->nbufs, &r->selected_rtaddr,
	    replicast_send_done_generic, st, NULL);
	if (err) {
		r->inexec--;
		log_error(lg, "PUT operation error %d on send", err);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}
}

void
client_putcommon_rtsend(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct ccow *tc = r->tc;
	int unicastio = tc->unicastio;

	if (r->io->attributes & RD_ATTR_SERIAL_OP &&
	    r->req_type == CL_PUT_REQ_TYPE_NAMED) {
		/* Temporarily override unicastio */
		if (!unicastio)
			unicastio = REPLICAST_UNICAST_UDP;
	}

	switch(unicastio) {
	case REPLICAST_UNICAST_TCP:
		r->tcp_conn_wait_count = r->tcp_connected_count = 0;
		/* No break. Falls through to send_unicast() */
	case REPLICAST_UNICAST_UDP:
	case REPLICAST_UNICAST_UDP_MCPROXY:
		send_unicast(st, REPLICAST_UNICAST_UDP);
		break;
	default:
		send_multicast(st);
		break;
	}

	if (unicastio != REPLICAST_UNICAST_TCP) {
		log_debug(lg, "RENDEZVOUS_TRANSFER Payload Rcvd Timer started for %"
				PRIu64 "us " " retry: %d seqid %d.%d",
				r->rt_delta_timeout, r->rt_retry,
				r->ctx->sequence_cnt,
				r->ctx->sub_sequence_cnt - 1);
		start_rt_timer(r, st);
	}
}

int
client_putcommon_guard_nack_consensus(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "st %p: ack_count %d nack_count %d seqid %d.%d", st,
	    r->ack_count, r->nack_count, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if ((r->ack_count + (++r->nack_count)) < r->needed_replicas) {
		return 0;	/* no need to retry for any hosts */
	}
	return 1;
}


void
client_putcommon_nack_rcvd(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;
	int err;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
						ctx->sub_sequence_cnt);

	log_debug(lg, "RENDEZVOUS TRANSFER NACK received retry: %d "
	    "seqid %d.%d", r->rt_retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

	if (r->rtsend_timer_req->data) {
		uv_hpt_timer_stop(r->rtsend_timer_fd, r->rtsend_timer_req);
		r->rtsend_timer_req->data = NULL;
	}

	if (r->start_timer_req->data) {
		uv_hpt_timer_stop(r->start_timer_fd, r->start_timer_req);
		r->start_timer_req->data = NULL;
	}

	/*
	 * Restart the entire sequence, starting from PUT PROPOSAL again.
	 */
	state_next(st, EV_TIMEOUT);
}

static void
client_putcommon_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

void
client_put_common_terminate(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
						ctx->sub_sequence_cnt);

	if (r->terminated)
		return;

	assert(r->inexec >= 0);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	if (r->rtsend_timer_req->data) {
		uv_hpt_timer_stop(r->rtsend_timer_fd, r->rtsend_timer_req);
		r->rtsend_timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)r->rtsend_timer_req,
	    client_putcommon_timer_close_cb);
	if (r->rtsend_timer_fd > 0)
		uv_hpt_timer_close(r->rtsend_timer_fd, r->rtsend_timer_req);

	if (r->start_timer_req->data) {
		uv_hpt_timer_stop(r->start_timer_fd, r->start_timer_req);
		r->start_timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)r->start_timer_req,
	    client_putcommon_timer_close_cb);
	if (r->start_timer_fd > 0)
		uv_hpt_timer_close(r->start_timer_fd, r->start_timer_req);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)r->timer_req, client_putcommon_timer_close_cb);

	if (r->done_cb)
		r->done_cb(r);
	if (r->ctx)
		repctx_destroy(r->ctx);
	/* If serial op is blocked on server don't complete IO */
	if (!(io->attributes & RD_ATTR_SERIAL_OP &&
	      op->status == -EWOULDBLOCK)) {
		r->terminated = 1;
		ccow_complete_io((struct ccow_io *)st);
	} else
		log_debug(lg, "st %p serial op blocked. IO completion deferred",
			  st);
}

void
client_putcommon_payload_rcvd(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	struct repmsg_payload_rcvd *msg =
		(struct repmsg_payload_rcvd *)wqe->msg;

	if (r->rtsend_timer_req->data)
		uv_hpt_timer_stop(r->rtsend_timer_fd, r->rtsend_timer_req);

	if ((!tc->sync_put_commit_wait) &&
	    (r->req_type == CL_PUT_REQ_TYPE_UNNAMED)) {
		r->rtsend_timer_req->data = NULL;
		state_override(st, ST_TERM);
	} else {
		if ((r->io->attributes & RD_ATTR_SERIAL_OP) &&
		    (r->req_type == CL_PUT_REQ_TYPE_NAMED)) {
			r->rt_delta_timeout = CLIENT_MAX_SERIALOP_TIMEOUT_MS * 1000;
		} else {
			uint64_t low_bound = 1000 * CLIENT_PUTCOMMON_DELTA2_MIN_MS;
			if (r->rcvd_max_delta > low_bound)
				r->rt_delta_timeout = r->rcvd_max_delta;
			else
				r->rt_delta_timeout = low_bound;
			if (r->rt_delta_timeout > CLIENT_MAX_RETRY2_TIMEOUT_MS * 1000) {
				r->rt_delta_timeout = CLIENT_MAX_RETRY2_TIMEOUT_MS * 1000;
			}
		}
		r->rtsend_timer_req->data = st;

		log_debug(lg, "RENDEZVOUS_TRANSFER Payload Wait Timer started for %"
				PRIu64 "us " " retry: %d seqid %d.%d",
				r->rt_delta_timeout, r->rt_retry,
				r->ctx->sequence_cnt,
				r->ctx->sub_sequence_cnt - 1);
		int err = uv_hpt_timer_start(r->rtsend_timer_fd, r->rtsend_timer_req,
		    r->rt_delta_timeout, client_putcommon_rtsend_timeout);
		if (err) {
			r->rtsend_timer_req->data = NULL;
			log_error(lg, "PUT operation error %d on hpt timer start", err);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return;
		}
	}
}

int client_putcommon_guard_rcvd_consensus(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow *tc = r->tc;

	uint128_t *vdevid;
	struct repmsg_payload_rcvd *msg =
		(struct repmsg_payload_rcvd *)wqe->msg;
	vdevid = &msg->vdevid;

	int found = -1;
	for (int i = 0; i < r->selected_count; i++) {
		if (uint128_cmp(vdevid, &r->selected_vdevs[i]) == 0) {
			found = i;
			break;
		}
	}
	if (found == -1) {
		char vdevstr[64];
		uint128_dump(vdevid, vdevstr, 64);
		log_debug(lg, "Received Payload Rcvd from unexpected vdev: %s",
		    vdevstr);
		return 0;
	}

	r->rcvd_max_delta
		= (r->rcvd_max_delta > msg->put_delta) ? r->rcvd_max_delta : msg->put_delta;
	if (++r->rcvd_count >= r->selected_count) {
		log_debug(lg, "Built RCVD concensus (selected_count=%d): rcvd_max_delta=%ld",
		    r->selected_count, r->rcvd_max_delta);
		return 1;
	}

	return 0;
}


void
client_putcommon_payload_ack(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (r->rtsend_timer_req->data) {
		uv_hpt_timer_stop(r->rtsend_timer_fd, r->rtsend_timer_req);
		r->rtsend_timer_req->data = NULL;
	}

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	// FIXME: finalize concensus or re-try...

	struct repwqe *wqe = ctx->wqe_in;
	if (wqe) {
		struct repmsg_unnamed_payload_ack *msg =
			(struct repmsg_unnamed_payload_ack *)wqe->msg;
		if (msg->hdr.transaction_id.opcode == RT_ERROR) {
			struct repmsg_error *msg =
				(struct repmsg_error *)wqe->msg;
			log_error(lg, "Rendezvous Payload NACK with error: %d",
			    msg->error);
			return;
		}
	}
}

int client_putcommon_guard__ack_consensus(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow *tc = r->tc;
	int count = 0;
	assert(wqe);

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	uint128_t *vdevid;
	if (r->req_type == CL_PUT_REQ_TYPE_UNNAMED) {
		struct repmsg_unnamed_payload_ack *msg =
			(struct repmsg_unnamed_payload_ack *)wqe->msg;
		vdevid = &msg->vdevid;
	} else {
		struct repmsg_named_payload_ack *msg =
			(struct repmsg_named_payload_ack *)wqe->msg;
		vdevid = &msg->vdevid;
		/* For SOP, pass genid back to the caller */
		if ((io->attributes & RD_ATTR_SERIAL_OP) &&
		    (io->attributes & RD_ATTR_EVENTUAL_SOP)) {
			struct ccow_completion* c = op->comp;
			assert(c->sop_generation);
			*c->sop_generation = msg->object_name.generation;
		}
	}
	int found = -1;
	for (int i = 0; i < r->selected_count; i++) {
		if (uint128_cmp(vdevid, &r->selected_vdevs[i]) == 0) {
			found = i;
			break;
		}
	}
	if (found == -1) {
		char vdevstr[64];
		uint128_dump(vdevid, vdevstr, 64);
		log_debug(lg, "Received Payload Ack from unexpected vdev: %s",
		    vdevstr);
		return 0;
	}

	r->acked_count[found]++;

	if (st->ev_cur != RT_ERROR)
		r->ack_count++;

	// for successful ack, update the rtt for solicited traffic
	if (r->rt_req_start) {
		size_t len = rtbuf_len(r->payload);
		flexhash_update_rtt(CLIENT_FLEXHASH, &r->ng_chid,
		    FH_MSG_PUT_SOLICITED, r->rt_req_start,
		    get_timestamp_us(), len);
	}
	log_debug(lg, "ACK concensus state: already_stored: %d ack_count: %d"
	    " rc: %d", r->already_stored_selected, r->ack_count, r->needed_replicas);

	if (r->rtselected <= 0) {
		/* Immediate content ACK case */
		log_warn(lg, "Received Payload Ack : rtselected: %d immediate case", r->rtselected);
		if (r->req_type == CL_PUT_REQ_TYPE_UNNAMED &&
		    !(r->io->attributes & RD_ATTR_COMPOUND) && tc->sync_put_ack_min &&
		    r->already_stored_count + r->proposed_count >= tc->sync_put_ack_min)
			goto _exit;
		if (r->already_stored_count + r->proposed_count >= r->needed_replicas) {
			goto _exit;
		}
	}

	if (r->ack_count + r->already_stored_selected < r->needed_replicas) {
		if (r->req_type == CL_PUT_REQ_TYPE_UNNAMED &&
		    !(r->io->attributes & RD_ATTR_COMPOUND) && tc->sync_put_ack_min &&
		    (r->ack_count + r->already_stored_selected >= tc->sync_put_ack_min)) {
			goto _exit;
		}
		return 0; /* not reached, keep on waiting */
	}

_exit:
	for (int i = 0; i < r->selected_count; i++) {
		if (r->acked_count[i] > 0)
			count++;
	}
	/* We have received all ACKs and busy counts */
	if (r->rt_busy_count && r->rt_busy_count + count == r->selected_count) {
		state_event(st, EV_TIMEOUT);
		return 1;
	}
	if (tc->sync_put_ack_min && count >= tc->sync_put_ack_min)
		return 1;
	if (count + r->already_stored_selected >= r->needed_replicas)
		return 1;

	return 0;
}


void
client_putcommon_error(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repmsg_error *msg = ctx->wqe_in ? (struct repmsg_error *)ctx->wqe_in->msg : NULL;
	int err = 0;

	log_trace(lg, "st %p", st);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	/* case where status is not set by any of the logic - "catch all" */
	if (!op->status) {
		if (io->attributes & RD_ATTR_SERIAL_OP && msg) {
			log_error(lg, "Client err: %d\n", msg->error);
			switch(msg->error) {
			case RT_ERR_BLOCKED:
				log_debug(lg, "st %p Serial operation blocked "
						"at server", st);
				op->status = err = -EWOULDBLOCK;
				break;
			case RT_ERR_NOT_EMPTY:
				log_debug(lg, "st %p Serial operation resource"
						" exists", st);
				op->status = err = -EEXIST;
				break;
			case RT_ERR_NO_RESOURCES:
				log_debug(lg, "st %p Serial operation no such"
						" resource", st);
				op->status = err = -ENOENT;
				break;
			case RT_ERR_NO_ACCESS:
				op->status = err = -EPERM;
				break;
			case -EEXIST:
				log_debug(lg, "st %p Serial operation resource"
						" exists", st);
				op->status = err = -EEXIST;
				break;
			case -ENOENT:
				log_debug(lg, "st %p Serial operation no such"
						" resource", st);
				op->status = err = -ENOENT;
				break;
			default:
				err = -EIO; /* Unexpected error */
				log_error(lg, "Unexpected SOP error: %u",
						msg->error);
				break;
			}
		} else {
			if (msg) {
				switch(msg->error) {
				case -ENOENT:
				case -EEXIST:
					err = msg->error;
					break;
				case RT_ERR_NO_SPACE:
					log_error(lg, "st %p NO_SPACE", st);
					uint128_logdump(lg, "ENOSPC vdevid", &msg->vdevid);
					err = -ENOSPC; /* retryable */
					break;
				default:
					log_error(lg, "Networking extended error: %u, continue", msg->error);
					break;
				}
			} else {
				err = -EAGAIN; /* retryable */
				log_error(lg, "Unknown networking protocol error");
			}
			op->status = err;
		}

		if (err)
			ccow_fail_io(io, err);
		else {
			state_override(st, ST_WAIT);
			state_next(st, EV_TIMEOUT);
		}
	}
}

void
client_putcommon_busy(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	// FIXME: select other server out of respondents and re-send via
	//	  unicast datagram
}

void
client_putcommon_send_timeout(uv_timer_t *treq, int status)
{
	struct state *st = treq->data;
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;

	log_trace(lg, "treq %p seqid %d.%d", treq, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (treq->data) {
		uv_timer_stop(treq);
		treq->data = NULL;
	}

	if (r->rtselected < 0) {
		r->rtselected = -2;
		state_event(st, RT_ACCEPT_PROPOSED_RENDEZVOUS);
		return;
	}

	tc->put_retry_cnt++;

	state_event(st, EV_TIMEOUT);
}

typedef struct vdev_comp {
	uint128_t vdevid;
	struct replicast_rendezvous_proposal *proposal;
} vdev_comp;

int
cmp_proposal_weight(const void *p1, const void *p2)
{
	vdev_comp **v1 = (vdev_comp **)p1;
	vdev_comp **v2 = (vdev_comp **)p2;

	uint64_t l = (*v1)->proposal->weight_io * (*v1)->proposal->delta_time;
	uint64_t r = (*v2)->proposal->weight_io * (*v2)->proposal->delta_time;
	return (l < r ? -1 : (l > r ? 1 : 0) );
}

int
cmp_proposal_space(const void *p1, const void *p2)
{
	vdev_comp **v1 = (vdev_comp **)p1;
	vdev_comp **v2 = (vdev_comp **)p2;
	uint64_t l = (*v1)->proposal->avail_space;
	uint64_t r = (*v2)->proposal->avail_space;
	return (l > r ? -1 : (l < r ? 1 : 0) );
}

int
client_putcommon_select_policy(struct putcommon_client_req *r)
{
	uint64_t now = get_timestamp_us();
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow *tc = r->tc;
	struct repctx *ctx = r->ctx;
	struct replicast_rendezvous_proposal
		*selected_proposals[REPLICAST_PROPOSALS_MAX];
        vdev_comp vdev_compare[REPLICAST_PROPOSALS_MAX];
        vdev_comp *pvdev_compare[REPLICAST_PROPOSALS_MAX];

	int policy_check;
	char vdevstr[UINT128_BYTES*2+1];

	log_trace(lg, "r %p seqid %d.%d select_policy: %d", r, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, r->select_policy);

	if (r->select_policy > 0) {
		if (r->select_policy & CCOW_SELECT_POLICY_WINDOW) {
			log_debug(lg, "selected policy: window ");
			int j = 0;
			/* this is just a check to make sure that we make sure that
			 * only proposals with valid start times are selected
			 */
			for (int i = 0; i < r->proposed_count; i++) {
				struct replicast_rendezvous_proposal *proposal = &r->proposals[i];
				uint64_t start = proposal->start_time;
				uint64_t end = start + proposal->delta_time;

				if (start > now) {
					r->selected_vdevs[j] = r->proposed_vdevs[i];
					selected_proposals[j++] = proposal;
				} else
					log_warn(lg, "not selecting because leased transfer "
					    "interval has ended: %" PRIu64 " us ago", now - end);
				// FIXME: implement...
				//		proposal.xmit_bandwidth;
			}
			r->selected_count = j;
		}


		for (int i = 0; i < r->proposed_count; i++) {
			vdev_compare[i].proposal = &r->proposals[i];
			vdev_compare[i].vdevid = r->proposed_vdevs[i];
			pvdev_compare[i] = &vdev_compare[i];
		}
		if (r->select_policy & CCOW_SELECT_POLICY_SPACE) {
			log_debug(lg, "selected policy: space r->proposed_count %d", r->proposed_count);
			qsort(pvdev_compare, r->proposed_count,
				sizeof (pvdev_compare[0]),
				cmp_proposal_space);
			int j = 0;
			for (int i = 0; i < r->proposed_count; i++) {
				uint128_dump(&pvdev_compare[i]->vdevid, vdevstr, UINT128_BYTES*2+1);
				log_debug(lg, "(space) proposal%d: %" PRIu64 " vdevid: %s", i,
					pvdev_compare[i]->proposal->avail_space, vdevstr);
				r->selected_vdevs[j] = pvdev_compare[i]->vdevid;
				selected_proposals[j++] = pvdev_compare[i]->proposal;
			}
			r->selected_count = j;
		}

		if (r->select_policy & CCOW_SELECT_POLICY_QDEPTH) {
			log_debug(lg, "selected policy: qdepth r->proposed_count %d", r->proposed_count);
			qsort(pvdev_compare, r->proposed_count,
				sizeof (pvdev_compare[0]),
				cmp_proposal_weight);
			int j = 0;
			for (int i = 0; i < r->proposed_count; i++) {
				uint128_dump(&r->proposed_vdevs[i], vdevstr, UINT128_BYTES*2+1);
				log_debug(lg, "(qdepth) proposal%d: %ld vdevid: %s", i,
					pvdev_compare[i]->proposal->weight_io * pvdev_compare[i]->proposal->delta_time, vdevstr);
				r->selected_vdevs[j] = pvdev_compare[i]->vdevid;
				selected_proposals[j++] = pvdev_compare[i]->proposal;
			}
			r->selected_count = j;
		}
	} else {
		log_debug(lg, "selected policy: none ");
		int j = 0;
		for (int i = 0; i < r->proposed_count; i++) {
			struct replicast_rendezvous_proposal *proposal = &r->proposals[i];
			r->selected_vdevs[j] = r->proposed_vdevs[i];
			selected_proposals[j++] = proposal;
		}
		r->selected_count = j;
	}

	policy_check = client_putcommon_check_policy(CLIENT_FLEXHASH,
	    op->metadata.failure_domain, r->needed_replicas, r);

	log_debug(lg, "Proposed state: already_stored: %d proposed_count: "
	    "%d policy_check: %d seqid %d.%d", r->already_stored_count,
	    r->proposed_count, policy_check, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (!policy_check) {
		/* wait for more */
		return 0;
	}

	/*
	 * To accommodate networking reservation logic, find the max of the
	 * start times and use that as a delayed timeout, in microseconds.
	 */
	uint64_t max_start = 0, max_rt_delta_timeout = 0;
	int remaining = r->needed_replicas > r->already_stored_selected ?
		(r->needed_replicas - r->already_stored_selected) : 0;
	for (int i = 0; i < remaining; i++) {
		struct replicast_rendezvous_proposal *p = selected_proposals[i];
		if (p->start_time > max_start) {
			max_start = p->start_time;
		}
		if (p->delta_time > max_rt_delta_timeout)
			max_rt_delta_timeout = p->delta_time;
	}

	size_t req_len = rtbuf_len(r->payload);
	uint64_t avg_rtt = flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
					    FH_MSG_PUT_SOLICITED, req_len);

	/*
	 * If we struggling with receiving, we monothonically increasing
	 * RT timeout, so, to give servers a chance to complete transfers.
	 */
	r->rt_delta_timeout = max_rt_delta_timeout;
	if (r->rt_delta_timeout) {
		r->rt_delta_timeout = r->rt_delta_timeout +
			10 * (1 + r->rt_retry) + 10 * tc->io_rate +
			r->selected_count * avg_rtt;
	}

	/*
	 * Lower bound cap
	 */
	uint32_t delta_timeout_min = 1000 * CLIENT_PUTCOMMON_DELTA_MIN_MS *
		r->selected_count;
	if (r->rt_delta_timeout < delta_timeout_min)
		r->rt_delta_timeout = delta_timeout_min;

	/*
	 * Upper bound cap
	 */
	if (r->rt_delta_timeout > CLIENT_MAX_RETRY_TIMEOUT_MS * 1000) {
		r->rt_delta_timeout = CLIENT_MAX_RETRY_TIMEOUT_MS * 1000;
	}

	if ((r->io->attributes & RD_ATTR_SERIAL_OP) &&
	    (r->req_type == CL_PUT_REQ_TYPE_NAMED)) {
		r->rt_delta_timeout = CLIENT_MAX_SERIALOP_RCVD_TIMEOUT_MS * 1000;
	}

	/*
	 * we still delay for at least 1 microsecond here to give accept/ack
	 * at least some room for cleanups
	 */
	uint64_t max_start_abs = max_start;
	r->delayed_start_us = max_start_abs <= now ? FH_MIN_DELAYED_START : max_start_abs - now;
	assert(r->delayed_start_us);

	/* upper bound cap */
	if (r->delayed_start_us > CLIENT_DELAYED_START_MAX_TIMEOUT_MS * 1000)
		r->delayed_start_us = CLIENT_DELAYED_START_MAX_TIMEOUT_MS * 1000;

	log_debug(lg, "Accept Final: delayed_start %ld delta_timeout %ld:%ld io_rate %d "
	    "avg_rtt %ld seqid %d.%d", r->delayed_start_us, max_rt_delta_timeout,
	    r->rt_delta_timeout, tc->io_rate, avg_rtt, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	return 1;

}

static void
UV_HPT_TIMER_CB(client_putcommon_delayed_start_timeout, *treq)
{
	struct state *st = treq->data;
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "treq %p, seqid %d.%d", treq, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (r->start_timer_req->data) {
		uv_hpt_timer_stop(r->start_timer_fd, r->start_timer_req);
		r->start_timer_req->data = NULL;
	}
	r->retry = 0; /* new timer */
	state_event(st, RT_RENDEZVOUS_TRANSFER);
}


static uint128_t *
find_target_in_proposal(struct putcommon_client_req *r, uint128_t target_vdev) {
	uint128_t *res = NULL;
	/* Search for min in proposed array */
	for (int i = 0; i < r->proposed_count; i++) {
		uint128_t *pvdevid = &r->proposed_vdevs[i];

		if (uint128_cmp(pvdevid, &uint128_null) == 0)
			continue;

		if (uint128_cmp(pvdevid, &target_vdev) != 0)
			continue;

		res = pvdevid;
		break;
	}

	if (!res) {
		/* And if not found, search for min in AS array */
		for (int i = 0; i < r->already_stored_count; i++) {
			uint128_t *as_vdevid = &r->already_stored_vdevs[i];

			if (uint128_cmp(as_vdevid, &uint128_null) == 0)
				continue;

			if (uint128_cmp(as_vdevid, &target_vdev) != 0)
				continue;

			res = as_vdevid;
			break;
		}
	}
	return res;
}


int
client_putcommon_guard_proposed(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;
	int err;
	char buf[256];
	uint64_t targeted_op = io->attributes & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED);
	uint64_t serial_op = (r->io->attributes & RD_ATTR_SERIAL_OP &&
							r->req_type == CL_PUT_REQ_TYPE_NAMED);
	uint128_t *found_target = NULL;

	/* in case of serial op, we still need to wait for "master" vdev */
	if (serial_op) {
		r->needed_replicas = 1;
		r->select_policy = CCOW_SELECT_POLICY_NONE;
		log_debug(lg, "SOP expect response from target VDEV %s", uint128_to_buffer(&r->target_vdev, buf));
	}

	assert(wqe);
	struct repmsg_accept_proposed_rendezvous *msg =
		(struct repmsg_accept_proposed_rendezvous *)wqe->msg;

	log_trace(lg, "st %p rtselected %d seqid %d.%d", st, r->rtselected,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (tc->unicastio == REPLICAST_UNICAST_TCP && r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	/* guard against requests AFTER combination is "locked" */
	if (r->rtselected > 0)
		return 0;
	else if (r->rtselected == -2)
		goto _rtselect_ready;

	// do the rtt calculation right away on the reply
	if (r->req_start) {
		flexhash_update_rtt(CLIENT_FLEXHASH, &r->ng_chid,
		    FH_MSG_UNSOLICITED, r->req_start, get_timestamp_us(), 4096);
	}

	if (r->proposed_count >= REPLICAST_PROPOSALS_MAX) {
		log_error(lg, "Received %d proposals, max permitted: %d",
		    r->proposed_count + 1, REPLICAST_PROPOSALS_MAX);
		// don't allow more. let it timeout if not done
		return 0;
	}

	uint128_t *proposed_vdevid;
	int proposed_ngcount;
	if (st->ev_cur != RT_ACCEPT_CONTENT_ALREADY_STORED) {
		r->proposals[r->proposed_count] = msg->rendezvous_proposal;
		r->proposed_vdevs[r->proposed_count] = msg->vdevid;
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
		proposed_ngcount = msg->ngcount;
		proposed_vdevid = &msg->vdevid;

		/* for 10 x DGRAM size chunks, or selected policy space, wait for more responses */
		int req_len = rtbuf_len(r->payload);
		if (!targeted_op && !serial_op && (req_len > 10 * REPLICAST_DGRAM_MAXLEN ||
		    r->select_policy & CCOW_SELECT_POLICY_SPACE ) &&
		    (r->proposed_count + r->already_stored_count) < (proposed_ngcount / 2) + 1) {
			log_debug(lg, "Policy wait (%d): proposed %d already_stored %d req_len %d",
			    r->select_policy, r->proposed_count, r->already_stored_count, req_len);
			return 0;
		}
	} else {
		struct repmsg_accept_content_already_stored *as_msg =
			(struct repmsg_accept_content_already_stored *)wqe->msg;

		r->already_stored_vdevs[r->already_stored_count++] = as_msg->vdevid;
		proposed_ngcount = as_msg->ngcount;
		proposed_vdevid = &as_msg->vdevid;
	}

	int compound_nresp = proposed_ngcount > r->needed_replicas + 2 ?
		proposed_ngcount - 2 : proposed_ngcount;
	if (!targeted_op && !serial_op && (io->attributes & RD_ATTR_COMPOUND) &&
		(r->proposed_count + r->already_stored_count + r->pp_busy_count +
			r->out_of_space_count) < compound_nresp) {
		/* non-targeted compound put is used for replication. To do it
		 * in a best way we should collect as many replies as we can.
		 * However, full consensus is too time-expensive, so waiting
		 * ngcount - 2 replies.
		 */
		log_debug(lg, "compound put: ngcount %d, proposed %d, as %d, busy %d ro %d"
			" waiting more", proposed_ngcount, r->proposed_count,
			r->already_stored_count, r->pp_busy_count, r->out_of_space_count);
		return 0;
	}

	// check if this is a valid vdev in the row
	if (!flexhash_is_rowmember(tc->flexhash, proposed_vdevid, &r->ng_chid)) {
		char vdevstr[64];
		uint128_dump(proposed_vdevid, vdevstr, 64);
		uint16_t row = HASHROWID(&r->ng_chid, tc->flexhash);
		log_debug(lg, " ACCEPT_PROPOSED from vdev: %s not in row: %d",
		    vdevstr, row);
		return 0;
	}

	int put_extra = tc->sync_put_extra ?
		tc->sync_put_extra : (proposed_ngcount / 2 - r->needed_replicas);
	if (put_extra < 0 || (io->attributes & RD_ATTR_CHUNK_MANIFEST))
		put_extra = 0;

	int window_found = client_putcommon_select_policy(r);
	if (window_found) {
		if (serial_op) {
			found_target = find_target_in_proposal(r, r->target_vdev);
			if (found_target != NULL) {
				log_debug(lg, "SOP: master found");
				goto _rtselect_ready;
			} else {
				log_debug(lg, "SOP: master not found");
			}
		} else if (r->already_stored_selected >= r->needed_replicas) {
			goto _rtselect_ready;
		}
	}

	/* collection of extra reply gives us a chance to select better */
	if (!targeted_op && !serial_op && (proposed_ngcount >= r->needed_replicas + put_extra) &&
	    (r->proposed_count + r->already_stored_count + r->pp_busy_count +
		r->out_of_space_count) < r->needed_replicas + put_extra) {
		log_debug(lg, "Policy delay one (%d): proposed %d already_stored %d"
				" busy count %d RO count %d", r->select_policy,
				r->proposed_count, r->already_stored_count,
				r->pp_busy_count, r->out_of_space_count);

		log_debug(lg, "proposed_ngcount = %d : put_extra = %d : r->needed_replicas = %d"
		    " : r->proposed_count = %d : r->already_stored_count = %d",
		    proposed_ngcount, put_extra, r->needed_replicas, r->proposed_count,
		    r->already_stored_count);
#if 0
		// FIXME: timer start causing stack smashing in longevity tests...
		if ((r->proposed_count + r->already_stored_count) >= r->needed_replicas) {
			if (r->rtselected)
				return 0;
			r->rtselected = -1;
			if (r->timer_req->data)
				uv_timer_stop(r->timer_req);
			r->timer_req->data = st;
			uv_timer_start(r->timer_req, client_putcommon_send_timeout,
			    tc->sync_put_extra_wait, 0);
		}
#endif
		return 0;
	}

	if (!window_found) {

		/*
		 * We reached max number of possible proposals, re-arm
		 * our timer to smaller value so that we will timeout
		 * and retry propsal negotiations sooner.
		 */
		if (r->proposed_count + r->pp_busy_count + r->out_of_space_count
			< proposed_ngcount) {
			log_debug(lg, "Window not found: proposed %d busy_count: %d already_stored %d out_of_space_count %d ngcount: %d",
				    r->proposed_count, r->pp_busy_count, r->already_stored_count, r->out_of_space_count, proposed_ngcount);
			return 0;
		}

		/*
		 * Re-arm the timer to timeout sooner. This will trigger retry.
		 */
		if (r->timer_req->data)
			uv_timer_stop(r->timer_req);
		r->timer_req->data = st;

		int new_timeout = CLIENT_PUTCOMMON_TIMEOUT_PP_FAST_MS;
		uv_timer_start(r->timer_req, client_putcommon_send_timeout,
		    new_timeout, 0);

		log_debug(lg, "Window wait: proposed %d already_stored %d "
		    "new_timeout %d", r->proposed_count, r->already_stored_count,
		    new_timeout);
		return 0; /* not reached, keep on waiting */
	}

_rtselect_ready:

	/* in case of serial op, we still need to wait for "master" vdev */
	if (serial_op) {
		uint16_t row = HASHROWID(&r->ng_chid, tc->flexhash);

		if (!found_target) {
			int new_timeout = CLIENT_PUTCOMMON_TIMEOUT_PP_FASTSOP_MS;
			log_debug(lg, "SOP: still waiting for master VDEV in row %d "
			    "to reply. Starting timer timeout %d", row, new_timeout);
			/* wait for more */
			r->timer_req->data = st;
			uv_timer_start(r->timer_req, client_putcommon_send_timeout,
				       new_timeout, 0);

			return 0;
		}

		r->selected_vdevs[0] = *found_target;
		r->selected_count = 1;
		r->needed_replicas = 1;
		r->already_stored_selected = 0;

		log_debug(lg, "SOP: RT selected master VDEV %s for row %d",
				uint128_to_buffer(found_target, buf), row);
	}

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	/*
	 * Ready to transfer
	 */
	r->rtselected = 1;

	if (r->already_stored_selected >= r->needed_replicas) {
		state_override(st, ST_TERM);
		return 1;
	}

	/* Enough busy count to retry PUT op - Does not apply to serial OP */
	if (!serial_op  &&
	    r->pp_busy_count && r->selected_count + r->already_stored_count < r->needed_replicas &&
	    r->selected_count + r->already_stored_count + r->pp_busy_count >= r->needed_replicas) {
		state_override(st, EV_TIMEOUT);
		return 1;
	}

	/* Keep selected in a user-provided container */
	if (r->io->comp && r->io->comp->usel) {
		int pos = r->io->comp->usel->len;
		for (int i = 0; i < r->selected_count; i++) {
			int found = 0;
			if (uint128_cmp(&r->selected_vdevs[i], &uint128_null) == 0)
				continue;
			for (int j = 0; j < pos; j++) {
				if (!uint128_cmp(r->selected_vdevs + i, r->io->comp->usel->vdevs + j)) {
					found = 1;
					break;
				}
			}
			if (found)
				continue;
			r->io->comp->usel->vdevs[pos++] = r->selected_vdevs[i];
		}
		r->io->comp->usel->len = pos;
	}

	/*
	 * Get NG address
	 */
	flexhash_get_hashaddr(tc->flexhash, &r->ng_chid, &r->selected_ngaddr);
	r->selected_ngaddr.sin6_scope_id = netobj->if_indexes[0];

	/*
	 * Select RT address for delayed Rendezvous Transfer
	 */
	r->selected_rtaddr = r->selected_ngaddr;
	r->selected_rtaddr.sin6_addr.__in6_u.__u6_addr16[5] = 0;
	flexhash_set_rtaddr(CLIENT_FLEXHASH, r->selected_vdevs,
	    r->selected_count, &r->selected_rtaddr);

	if (r->req_start) {
		flexhash_update_rtt(CLIENT_FLEXHASH, &r->ng_chid,
		    FH_MSG_PUT_SELECT, r->req_start,
		    get_timestamp_us(), 4096);
		uint64_t max_proposal_weight = 0;
		for (int i = 0; i < r->proposed_count; i++) {
			struct replicast_rendezvous_proposal *proposal = &r->proposals[i];
			if (proposal->weight_io > max_proposal_weight)
				max_proposal_weight = proposal->weight_io;
		}
		tc->avg_put_weight = avg_ring_update(&tc->avg_put_weight_ring,
		    max_proposal_weight);
	}

	/*
	 * Send Rendezvous Ack
	 */
	struct repmsg_rendezvous_ack ack;
	memset(&ack, 0, sizeof(ack));
	ack.content_hash_id = r->chid;
	ack.hdr.attributes = io->attributes;

	if (tc->unicastio == REPLICAST_UNICAST_TCP)
		ack.hdr.attributes |= RD_ATTR_UNICAST_TCP;
	else if (tc->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		ack.hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;
		ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	/* check to see if we have already sent to this rt address
	 * if it is not in the cache then the servers need a little more
	 * time for the multicast join to take place. In this case we
	 * add some more time to the delayed start for the RT_TRANSFER
	 */

	uint64_t hvalue = r->selected_rtaddr.sin6_addr.__in6_u.__u6_addr32[3];
	int found = flexhash_client_rthash_exists(CLIENT_FLEXHASH, hvalue);
	if (!found) {
		r->delayed_start_us += tc->join_delay;
		ack.join_delay = tc->join_delay;
		// we add the join delay here to the delta as well
		r->rt_delta_timeout += tc->join_delay;
		if (!tc->unicastio)
			ack.hdr.attributes |= RD_ATTR_MC_LAZY_JOIN;
	}

	log_debug(lg, "RT ACK hvalue=0x%" PRIx64 " found %d", hvalue, found);

	memcpy(&ack.rendezvous_group, &r->selected_rtaddr.sin6_addr, 16);
	int j = 0;
	for (int i = 0; i < r->selected_count; i++) {
		if (uint128_cmp(&r->selected_vdevs[i], &uint128_null) == 0)
			continue;
		ack.group_members[j] = r->selected_vdevs[i];
		uint128_logdump(lg, "RT ACK selected_vdevid",
		    &r->selected_vdevs[i]);
		j++;
	}
	r->inexec++;
	err = replicast_send(netobj->robj[0], ctx, RT_RENDEZVOUS_ACK,
	    (struct repmsg_generic *)&ack, NULL, NULL, 0, &r->selected_ngaddr,
	    replicast_send_done_generic, st, NULL);
	if (err) {
		r->inexec--;
		log_error(lg, "PUT operation error %d on rendezvous "
		    "ack send", err);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return 1;
	}


	/* since there is no reply to the RT_RENDEZVOUS_ACK, we assume
	 * optimistically that the servers did the join.
	 * we now keep track of this rt address
	 */
	if (r->start_timer_req->data) {
		uv_hpt_timer_stop(r->start_timer_fd, r->start_timer_req);
		r->start_timer_req->data = NULL;
	}
	if (!found) {
		flexhash_client_rthash_add(CLIENT_FLEXHASH, hvalue);
	}


	/* If TCP, initiate connections now */
	if (tc->unicastio == REPLICAST_UNICAST_TCP) {
		state_next(st, RT_INIT_TCP_CONNECT);
		return 1;
	/* Not doing it for NamedPut */
	} else if (r->delayed_start_us >= CLIENT_DELAYED_START_LOW_MS * 1000 &&
	    r->req_type != CL_PUT_REQ_TYPE_NAMED) {
		r->start_timer_req->data = st;
		err = uv_hpt_timer_start(r->start_timer_fd,
				r->start_timer_req,
				r->delayed_start_us,
				client_putcommon_delayed_start_timeout);
		if (err) {
			r->start_timer_req->data = NULL;
			log_error(lg, "Delayed start error %d on hpt "
				      "timer start", err);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
		}
		return 1;
	}

	/* we do not have hpt, so start right away */
	r->retry = 0; /* new timer */
	state_next(st, RT_RENDEZVOUS_TRANSFER);
	return 1;
}

int
client_putcommon_policy_anyfirst(volatile struct flexhash *fhtable, uint8_t rc,
    struct putcommon_client_req *r)
{
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;
	uint128_t vdevlist[FLEXHASH_MAX_SERVERS];
	int vdevcount = 0;
	struct lvdev *lvdev = NULL;

	for (int i = 0; i < r->selected_count; i++) {
		lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &r->selected_vdevs[i]);
		if (!lvdev) {
			char vdevstr[64];
			uint128_dump(&r->selected_vdevs[i], vdevstr, 64);
			log_debug(lg, "flexhash unknown vdevid: %s seqid %d.%d "
			    " idx: %d vdevcount: %d fhgenid: %ld selected_count: %d", vdevstr,
			    ctx->sequence_cnt, ctx->sub_sequence_cnt, i,
			    vdevcount, flexhash_genid(fhtable), r->selected_count);
			continue;
		}
		int found = 0;
		int j = 0;

		for (j = 0; j < vdevcount; j++) {
			if (uint128_cmp(&r->selected_vdevs[i], &vdevlist[j]) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			vdevlist[vdevcount++] = r->selected_vdevs[i];
			if ((uint8_t) vdevcount >= rc)
				break;
		}

	}

	r->selected_count = vdevcount;
	for (int i = 0; i < vdevcount; i++) {
		r->selected_vdevs[i] = vdevlist[i];
	}

	log_debug(lg, "policy-anyfirst: selected_count %d alread_stored %d rc %d",
	    r->selected_count, r->already_stored_count, r->needed_replicas);

	if ((r->selected_count + r->already_stored_count) >= r->needed_replicas) {
		r->already_stored_selected = r->already_stored_count;
		r->selected_count = r->needed_replicas > r->already_stored_count ?
			(r->needed_replicas - r->already_stored_count) : 0;
		return 1;
	}
	else
		return 0;

}

int
client_putcommon_policy_serverdomain(volatile struct flexhash *fhtable, uint8_t rc,
    struct putcommon_client_req *r)
{
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_completion* c = op->comp;

	int retval;
	uint128_t serveridlist[FLEXHASH_MAX_SERVERS];
	uint128_t as_serveridlist[FLEXHASH_MAX_SERVERS];
	struct lvdev *lvdev = NULL;
	int servercount = 0;
	int as_servercount = 0;
	uint128_t rvdevs[r->selected_count];
	int vcount = 0;

	for (int i = 0; i < r->already_stored_count; i++) {
		lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &r->already_stored_vdevs[i]);
		if (!lvdev) {
			char vdevstr[64];
			uint128_dump(&r->already_stored_vdevs[i], vdevstr, 64);
			log_debug(lg, "flexhash unknown vdevid: %s seqid %d.%d "
			    " idx: %d servercount: %d fhgenid: %ld selected_count: %d", vdevstr,
			    ctx->sequence_cnt, ctx->sub_sequence_cnt, i,
			    servercount, flexhash_genid(fhtable), r->selected_count);
			continue;
		}
		struct fhserver *fhserver = lvdev->server;
		int j = 0;
		if (fhserver) {
			int as_found = 0;
			for (int k = 0; k < as_servercount; k++) {
				if (uint128_cmp(&fhserver->id, &as_serveridlist[k]) == 0) {
					as_found = 1;
					break;
				}
			}
			if (!as_found) {
				as_serveridlist[as_servercount++] = fhserver->id;
				if ((uint8_t) as_servercount >= rc)
					goto _as_satisfied;
			}
		}
	}

	/*
	 * Now go through the list of new proposals and see
	 * if we have found the servers
	 */
	for (int i = 0; i < r->selected_count; i++) {
		lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &r->selected_vdevs[i]);
		if (!lvdev) {
			char vdevstr[64];
			uint128_dump(&r->selected_vdevs[i], vdevstr, 64);
			log_debug(lg, "flexhash unknown vdevid: %s seqid %d.%d "
			    " idx: %d servercount: %d fhgenid: %ld selected_count: %d", vdevstr,
			    ctx->sequence_cnt, ctx->sub_sequence_cnt, i,
			    servercount, flexhash_genid(fhtable), r->selected_count);
			continue;
		}
		struct fhserver *fhserver = lvdev->server;
		if (fhserver) {
			int as_found = 0;
			for (int k = 0; k < as_servercount; k++) {
				if (uint128_cmp(&fhserver->id, &as_serveridlist[k]) == 0) {
					as_found = 1;
					break;
				}
			}
			int found = 0;
			for (int j = 0; j < servercount; j++) {
				if (uint128_cmp(&fhserver->id, &serveridlist[j]) == 0) {
					found = 1;
					break;
				}
			}
			if (!as_found && !found) {
				serveridlist[servercount] = fhserver->id;
				rvdevs[servercount++] = lvdev->vdevid;
				if ((uint8_t) (as_servercount + servercount) >= rc)
					goto _as_satisfied;
			}
		}
	}

_as_satisfied:
	r->already_stored_selected = as_servercount;
	/* If EC enabled, all the replicas to be created, we also do not
	 * apply dedup_min optimization if we retrying PUT */
	int sync_put_dedup_min = (r->retry || r->rt_retry || c->ec_enabled ||
		tc->sync_put_dedup_min == 0) ?
		r->needed_replicas : tc->sync_put_dedup_min;
	log_debug(lg, "policy-serverdomain: as_servercount %d servercount %d rc %d",
	    as_servercount, servercount, rc);
	if (r->req_type == CL_PUT_REQ_TYPE_UNNAMED && sync_put_dedup_min &&
	    as_servercount && (as_servercount >= sync_put_dedup_min)) {
		log_debug(lg, "as servercount: %d reached sync_put_dedup_min: %d",
		    as_servercount, sync_put_dedup_min);
		r->needed_replicas = sync_put_dedup_min;
		tc->stats.ccow.dedupe_hits++;
		return 1;
	}

	if ((uint8_t) (as_servercount + servercount) < rc) {
		/* wait for more */
		return 0;
	}

	if (servercount > 0) {
		memcpy(&r->selected_vdevs[0],&rvdevs[0],servercount*sizeof(uint128_t));
		r->selected_count = MIN(rc, servercount);

		assert((r->selected_count+as_servercount) >= rc);

		log_debug(lg, "distinct servers: %d seqid %d.%d", servercount,
		    ctx->sequence_cnt, ctx->sub_sequence_cnt);
	}
	return 1;


}

int
client_putcommon_policy_zone(volatile struct flexhash *fhtable, uint8_t rc,
    struct putcommon_client_req *r)
{
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_completion* c = op->comp;
	uint32_t zcount[FLEXHASH_MAX_ZONES];
	uint32_t as_zonelist[FLEXHASH_MAX_ZONES];
	int zonecount = 0;
	int as_zonecount = 0;

	struct lvdev *lvdev = NULL;
	uint128_t rvdevs[r->selected_count];

	for (int i = 0; i < r->already_stored_count; i++) {
		lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &r->already_stored_vdevs[i]);
		if (!lvdev) {
			char vdevstr[64];
			uint128_dump(&r->selected_vdevs[i], vdevstr, 64);
			log_debug(lg, "flexhash unknown vdevid: %s seqid %d.%d "
			    " idx: %d servercount: %d fhgenid: %ld", vdevstr,
			    ctx->sequence_cnt, ctx->sub_sequence_cnt, i,
			    zonecount, flexhash_genid(fhtable));
			continue;
		}
		struct fhserver *fhserver = lvdev->server;
		if (fhserver) {
			int as_found = 0;
			for (int k = 0; k < as_zonecount; k++) {
				if (fhserver->zone ==  as_zonelist[k]) {
					as_found = 1;
					break;
				}
			}
			if (!as_found) {
				as_zonelist[as_zonecount++] = fhserver->zone;
				if ((uint8_t) as_zonecount >= rc)
					goto _as_satisfied;
			}
		}
	}

	/*
	 * Now go through the list of new proposals and see
	 * if we have found the zones
	 */
	for (int i = 0; i < r->selected_count; i++) {
		lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &r->selected_vdevs[i]);
		if (!lvdev) {
			char vdevstr[64];
			uint128_dump(&r->selected_vdevs[i], vdevstr, 64);
			log_debug(lg, "flexhash unknown vdevid: %s seqid %d.%d "
			    " idx: %d servercount: %d fhgenid: %ld", vdevstr,
			    ctx->sequence_cnt, ctx->sub_sequence_cnt, i,
			    zonecount, flexhash_genid(fhtable));
			continue;
		}
		struct fhserver *fhserver = lvdev->server;
		/* Read-only VDEV may accept PUT proposal with LOGICAL_DELETE flag set.
		 * So let a server make decision whether to participate or not.
		 * Unless it is dead.
		 */
		if ((lvdev->state != VDEV_STATE_DEAD) && (fhserver)) {
			int as_found = 0;
			for (int k = 0; k < as_zonecount; k++) {
				if (fhserver->zone ==  as_zonelist[k]) {
					as_found = 1;
					break;
				}
			}
			int found = 0;
			for (int j = 0; j < zonecount; j++) {
				if (fhserver->zone == zcount[j]) {
					found = 1;
					break;
				}
			}
			if (!as_found && !found) {
				rvdevs[zonecount] = lvdev->vdevid;
				zcount[zonecount++] = fhserver->zone;
				if ((uint8_t) (as_zonecount + zonecount) >= rc)
					goto _as_satisfied;
			}
		}
	}

_as_satisfied:
	r->already_stored_selected = as_zonecount;
	/* If EC enabled, all the replicas to be created, we also do not
	 * apply dedup_min optimization if we retrying PUT */
	int sync_put_dedup_min = (r->retry || r->rt_retry || c->ec_enabled ||
		tc->sync_put_dedup_min == 0) ?
		r->needed_replicas : tc->sync_put_dedup_min;
	log_debug(lg, "policy-zone: as_zonecount %d zonecount %d rc %d",
	    as_zonecount, zonecount, rc);
	if (r->req_type == CL_PUT_REQ_TYPE_UNNAMED && sync_put_dedup_min &&
	    as_zonecount && (as_zonecount >= sync_put_dedup_min)) {
		log_debug(lg, "as zonecount: %d reached sync_put_dedup_min: %d",
		    as_zonecount, sync_put_dedup_min);
		r->needed_replicas = sync_put_dedup_min;
		tc->stats.ccow.dedupe_hits++;
		return 1;
	}
	if ((uint8_t) (as_zonecount + zonecount) < rc) {
		log_debug(lg, "Not reached waiting for more ");
		/* wait for more */
		return 0;
	}

	if (zonecount > 0) {
		memcpy(&r->selected_vdevs[0],&rvdevs[0],zonecount*sizeof(uint128_t));
		r->selected_count = MIN(rc, zonecount);

		assert((r->selected_count+as_zonecount) >= rc);

		log_debug(lg, "Distinct zones: %d seqid %d.%d\n",
		    zonecount, ctx->sequence_cnt, ctx->sub_sequence_cnt);
	}
	return 1;
}

int
client_putcommon_check_policy(volatile struct flexhash *fhtable, uint8_t policy,
        uint8_t rc, struct putcommon_client_req *r)
{
	int ret = 0;
	uint8_t fd_policy = policy;
	struct ccow *tc = r->tc;

	// if there is only one zone left or one server left but we still
	// want to satisfy the replica count.
	int fd_downgrade = tc->sync_put_fd_min - 1;
	if (((fd_policy == FD_ZONE && r->zonecount <= fd_downgrade)
	 || (fd_policy == FD_SERVER && r->servercount <= fd_downgrade))
	 && (rc > fd_downgrade)) {
		fd_policy = FD_ANY_FIRST;
	}

	switch (fd_policy) {
		case FD_ANY_FIRST:
			ret = client_putcommon_policy_anyfirst(fhtable, rc, r);
			break;
		case FD_SERVER:
			ret = client_putcommon_policy_serverdomain(fhtable, rc, r);
			break;
		case FD_ZONE:
			ret = client_putcommon_policy_zone(fhtable, rc, r);
			break;
		default:
			ret = -1;
			break;
	};
	return ret;
}

int
client_putcommon_reset(struct putcommon_client_req *r)
{
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;

	repctx_reset(ctx);

	log_trace(lg, "r %p seqid %d.%d new txcookie %" PRIx64,
	    r, ctx->sequence_cnt, ctx->sub_sequence_cnt, ctx->txcookie);

	r->selected_count = 0;
	r->proposed_count = 0;
	r->already_stored_count = 0;
	r->already_stored_selected = 0;
	r->pp_busy_count = 0;
	r->rt_busy_count = 0;
	r->out_of_space_count = 0;
	memset(r->proposals, 0, sizeof (r->proposals));
	memset(r->proposed_vdevs, 0, sizeof (r->proposed_vdevs));
	memset(r->already_stored_vdevs, 0, sizeof (r->already_stored_vdevs));
	memset(r->acked_count, 0, sizeof (r->acked_count));
	memset(r->out_of_space_vdevs, 0, sizeof (r->out_of_space_vdevs));
	r->delayed_start_us = 0;
	r->rt_delta_timeout = 0;
	r->rt_req_start = 0;
	r->req_start = 0;
	r->rcvd_max_delta = 0;
	r->rcvd_count = 0;
	memset(&r->selected_rtaddr, 0, sizeof (struct sockaddr_in6));
	r->rtselected = 0;
	repctx_wqe_reset(ctx);
	client_putcommon_update_needed_replicas(r);

	return 0;
}


int
client_putcommon_guard_retry(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	r->retry++;

	client_putcommon_reset(r);

	if (r->retry < CLIENT_PUTCOMMON_MAX_RETRY) {
		struct ccow *tc = r->tc;

		if (tc->abort ||
		    ((io->attributes & RD_ATTR_RETRY_FAILFAST) &&
		     r->retry > CLIENT_PUTCOMMON_MAX_RETRY_FAILFAST)) {
			ccow_fail_io(r->io, -EINTR);
			state_next(st, EV_ERR);
			return 0; // fail
		}

		log_warn(lg, "PUT PROPOSAL request timeout after %d attempts "
		    "seq id: %d.%d", r->retry, r->ctx->sequence_cnt,
		    r->ctx->sub_sequence_cnt - 1);
		return 1; // ok, re-send
	}

	log_error(lg, "PUT PROPOSAL request timed out after %d attempts "
	    "seq id: %d.%d. Failing I/O", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

	ccow_fail_io(r->io, -EIO);
	state_next(st, EV_ERR);
	return 0; // fail


}

int
client_putcommon_send_proposal(struct state *st,
    enum replicast_opcode opcode,
    void *msg, int isrt)
{
	int err;
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_network *netobj = tc->netobj;
	rtbuf_t *payload = r->payload;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	struct sockaddr_in6 send_addr;
	flexhash_get_hashaddr(tc->flexhash, &r->ng_chid, &send_addr);
	send_addr.sin6_scope_id = netobj->if_indexes[0];
	uint512_logdump(lg, "Put NG CHID", &r->ng_chid);
	uint512_logdump(lg, "Put CHID", &r->chid);

	if (tc->unicastio == REPLICAST_UNICAST_TCP)
		((struct repmsg_generic *)msg)->hdr.attributes |= RD_ATTR_UNICAST_TCP;
	else if (tc->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		((struct repmsg_generic *)msg)->hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;
		ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	r->ack_count = 0; /* new attempt, new concensus... */
	r->nack_count = 0;
	r->inexec++;
	if (isrt) {
		/* we cannot be called without payload pre-set */
		if (!(io->attributes & (RD_ATTR_PARITY_ENCODE|RD_ATTR_ONDEMAMD_PIN|
			RD_ATTR_ONDEMAND_UNPIN|RD_ATTR_ONDEMAND_PERSIST)))
			assert(payload);
		err = replicast_send(netobj->robj[0], ctx,
		    opcode, (struct repmsg_generic *) msg, NULL,
		    NULL, 0, &send_addr, replicast_send_done_generic, st, NULL);
	} else {
		err = replicast_send(netobj->robj[0], ctx,
		    opcode, (struct repmsg_generic *) msg, NULL,
		    payload->bufs, payload->nbufs, &send_addr,
		    replicast_send_done_generic, st, NULL);
	}

	if (err) {
		r->inexec--;
		log_error(lg, "Error sending %s err=%d",
		    replicast_opcode_str[opcode], err);
		return err;
	}

	/*
	 * Timeout in CLIENT_PUTCOMMON_TIMEOUT_MS
	 */
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
	}
	r->timer_req->data = st;

	uint64_t select_time_avg = flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
					    FH_MSG_PUT_SELECT, 4096);
	select_time_avg *= tc->avg_put_weight;
	if (select_time_avg < 1000)
		select_time_avg = 1000;
	int fixed_timeout = r->select_policy & CCOW_SELECT_POLICY_SPACE ?
		CLIENT_PUTCOMMON_TIMEOUT_PP_SPACE_MS : CLIENT_PUTCOMMON_TIMEOUT_PP_MS;
	int new_timeout = ccow_retry_log2(
	    select_time_avg / 10 + fixed_timeout, r->retry);
	if (new_timeout > CLIENT_MAX_RETRY_TIMEOUT_MS) {
		new_timeout = CLIENT_MAX_RETRY_TIMEOUT_MS;
	}
	uv_timer_start(r->timer_req, client_putcommon_send_timeout,
	    new_timeout, 0);

	return 0;
}

int client_putcommon_init(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = io->comp;
	int err;

	log_trace(lg, "st %p ", st);

	r->ctx = repctx_init(netobj->robj[0]);
	if (!r->ctx) {
		err = -ENOMEM;
		log_error(lg, "PUT repctx alloc error: %d", err);
		goto _error;
	}
	r->ctx->state = st;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		err = -ENOMEM;
		repctx_destroy(r->ctx);
		goto _error;
	}
	r->timer_req->data = NULL;
	uv_timer_init(tc->loop, r->timer_req);

	r->rtsend_timer_req = je_malloc(sizeof (*r->rtsend_timer_req));
	if (!r->rtsend_timer_req) {
		je_free(r->timer_req);
		err = -ENOMEM;
		repctx_destroy(r->ctx);
		goto _error;
	}
	r->rtsend_timer_req->data = NULL;
	r->rtsend_timer_fd = uv_hpt_timer_init(tc->loop, r->rtsend_timer_req);
	if (r->rtsend_timer_fd < 0) {
		err = r->rtsend_timer_fd;
		log_error(lg, "PUT hpt rtsend init error: %d", err);
		repctx_destroy(r->ctx);
		goto _error;
	}

	r->start_timer_req = je_malloc(sizeof (*r->start_timer_req));
	if (!r->start_timer_req) {
		je_free(r->timer_req);
		je_free(r->rtsend_timer_req);
		err = -ENOMEM;
		repctx_destroy(r->ctx);
		goto _error;
	}
	r->start_timer_req->data = NULL;
	r->start_timer_fd = uv_hpt_timer_init(tc->loop, r->start_timer_req);
	if (r->start_timer_fd < 0) {
		uv_hpt_timer_close(r->rtsend_timer_fd, r->rtsend_timer_req);
		err = r->start_timer_fd;
		log_error(lg, "PUT hpt start init error: %d", err);
		repctx_destroy(r->ctx);
		goto _error;
	}

	/*
	 * op->metadata.replication_count is set only for continus operations.
	 * for chunk operations only competion has required replication count
	 * (if set by calling ccow_attr_modify_default())
	 * At the moment the hack is limited to compound put only
	 */
	if (r->req_type == CL_PUT_REQ_TYPE_UNNAMED) {
		if (r->io->attributes & RD_ATTR_COMPOUND)
			r->needed_replicas = c->replication_count;
		else {
			r->needed_replicas = op->metadata.sync_put ?
			    op->metadata.sync_put : op->metadata.replication_count;
		}
	} else {
		r->needed_replicas = tc->sync_put_named;
	}

	client_putcommon_update_needed_replicas(r);

	r->select_policy = c->select_policy;

	return 0;

_error:
	ccow_fail_io(st->io, err);
	state_next(st, EV_ERR);
	return err;
}

