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
#include "server-list.h"
#include "state.h"
#include "replicast.h"

struct server_list_get_req {
	CCOW_CLASS_FIELDS
	struct ccow_network *netobj;
	uint128_t serverid;
	struct cl_node *node;
	uint32_t flags;
	int nbufs;
	uv_buf_t payload[REPLICAST_DGRAM_MAX];
	uv_buf_t onebuf;
};

/*
 * ACTION: unblock caller and report error
 */
static void
slg_state__error(struct state *st) {
	struct server_list_get_req *r = st->data;
	log_debug(lg, "error detected while fetching FH");
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
}

int
cltopo_count_numdevices(struct cl_node *node, int nr_nodes)
{
	int count = 0;
	struct cl_node *nodeptr;
	for (int i = 0; i < nr_nodes; i++) {
		nodeptr = &node[i];
		count += nodeptr->nr_vdevs;
	}
	return count;
}

static void
slg_state__assemble_payload(struct state *st)
{
	struct server_list_get_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_server_list_response *msg;
	int err;

	assert(wqe);
	msg = (struct repmsg_server_list_response *)wqe->msg;

	if (msg->hdr.fh_genid == 1) {
		log_warn(lg, "Ignore fh_genid=1 (incomplete) response");
		/* let it timeout */
		return;
	}

	int idx = msg->hdr.datagram_num - 1;
	if (idx >= msg->num_datagrams) {
		log_error(lg, "Corrupt RT: %s idx: %d >= num_datagrams: %d",
		    replicast_opcode_str[msg->hdr.transaction_id.opcode],
		    idx, msg->num_datagrams);
		/* let it timeout */
		return;
	}

	log_debug(lg, "%s idx: %d num_datagrams: %d rcvd: %d datagram_num: %d"
	    " nread: %ld seqid %d.%d",
	    replicast_opcode_str[msg->hdr.transaction_id.opcode],
	    idx, msg->num_datagrams, req->nbufs, msg->hdr.datagram_num,
	    wqe->nread, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (req->payload[idx].base) {
		log_warn(lg, "Duplicate: %s idx: %d",
		    replicast_opcode_str[msg->hdr.transaction_id.opcode], idx);
		/* let it timeout */
		return;
	}

	req->payload[idx].len = repwqe_payload_len(wqe);
	req->payload[idx].base = repwqe_payload(wqe);

	if (msg->num_datagrams != ++req->nbufs) {
		/* let it timeout */
		return;
	}

	log_debug(lg, "All datagrams %d of %d received seqid %d.%d",
	    req->nbufs, msg->num_datagrams,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	err = replicast_uvbuf_integrate(req->payload, req->nbufs, &req->onebuf);
	if (err) {
		/* let it timeout */
		return;
	}

	log_debug(lg, "slg payload size %lu", req->onebuf.len);
	state_next(st, EV_DONE);
}

/*
 * ACTION: process response
 *
 * Build tree of serverid/vdevid
 */
static void
slg_state__response(struct state *st)
{
	struct server_list_get_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	struct cl_node *rnode;
	int err;

	struct repmsg_server_list_response *msg =
		(struct repmsg_server_list_response *)wqe->msg;

	err = replicast_unpack_uvbuf_nodes(&r->onebuf, msg->nr_members, &rnode,
	    NULL, 0);
	if (err) {
		/* let it timeout */
		return;
	}

	msg->members = rnode;

	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &msg->mcbase_ip6addr, dst, INET6_ADDRSTRLEN);
	log_info(lg, "RT_SERVER_LIST_RESPONSE mcbase_addr %s.%d",
	    dst, msg->mcbase_port);

	char out[64];
	if (uint128_cmp(&msg->parent_serverid, &uint128_null) == 0) {
		/* this means that the payload contains all servers and
		 * all vdevs
		 */
		uint128_dump(&msg->parent_serverid, out, 64);
		log_info(lg, "RT_SERVER_LIST_RESPONSE with missing "
		    "parent_serverid = %s fh_genid = %ld", out, msg->hdr.fh_genid);

		flexhash_dump_repnode(msg->members, msg->nr_members);
		volatile struct flexhash *newfhtable = flexhash_table_create(
		    msg->checkpoint_numdevices, FH_CLIENT_SIDE);
		if (!newfhtable) {
			log_error(lg, "Unable to create flexhash table for %d devices",
			    msg->checkpoint_numdevices);
			replicast_free_repnodelist((struct cl_node *) msg->members,
			    (int) msg->nr_members);
			/* let it timeout */
			return;
		}

		int numdevices = cltopo_count_numdevices((struct cl_node *) msg->members,
					(int) msg->nr_members);
		newfhtable->numdevices = numdevices;
		newfhtable->checkpoint_numdevices = msg->checkpoint_numdevices;
		newfhtable->ckpread = msg->ckpread;

		flexhash_set_genid(newfhtable, msg->hdr.fh_genid);
		err = flexhash_assign_mcbase(newfhtable, &msg->mcbase_ip6addr,
		    msg->mcbase_port);
		if (err) {
			log_warn(lg, "Unable to add multicast base address %s.%d: %d",
			    dst, msg->mcbase_port, err);
			replicast_free_repnodelist((struct cl_node *) msg->members,
			    (int) msg->nr_members);
			/* let it timeout */
			return;
		}
		flexhash_lock(newfhtable);
		flexhash_add_serverlist(newfhtable, (struct cl_node *)msg->members,
		    (int) msg->nr_members, FH_NO_REBUILD);
		flexhash_unlock(newfhtable);

		volatile struct flexhash *tmpfh = CLIENT_FLEXHASH;
		tc->flexhash = newfhtable;
		flexhash_table_destroy(tmpfh);

		log_info(lg, "Flexhash genid: %ld actual numdevices: %d",
		    flexhash_genid(CLIENT_FLEXHASH), CLIENT_FLEXHASH->numdevices);
		log_info(lg, "Flags %d ckpread %d msg %d", r->flags, CLIENT_FLEXHASH->ckpread, msg->ckpread);
		if ( (r->flags == SERVER_LIST_GET_CHECKPOINT) && \
		    ( (CLIENT_FLEXHASH->ckpread == FH_CKPREAD_DISK) || (msg->ckpread == FH_CKPREAD_SKIP))) {
			flexhash_disk_dump(CLIENT_FLEXHASH, "flexhash-checkpoint.json", 0, "Cluster Fetched");
		} else {
			flexhash_dump(CLIENT_FLEXHASH, 1);
		}

	} else {
		/* case 2: parent_serverid is  available
		 * only one specific server and it's vdevs should be
		 * received
		 */
		if (msg->nr_members > 1) {
			log_warn(lg, "Expected single server , received %d",
				msg->nr_members);
			/* let it timeout */
			return;
		}

		uint128_dump(&msg->parent_serverid, out, 64);
		log_info(lg, "RT_SERVER_LIST_RESPONSE with"
				"parent_serverid = %s", out);
		err = flexhash_add_server(tc->flexhash,
			(struct cl_node *)msg->members, FH_TABLE_JOIN,
			FH_NOGOOD_HC, FH_NO_REBUILD);
		if (err)
			log_error(lg, "Unable to add server %s to the flexhash"
					" err=%d", out, err);

		if (r->node) {
			*(r->node) = *rnode;
			msg->nr_members = 0;
		}
	}

	// free the memory allocated by unpack in replicast
	replicast_free_repnodelist((struct cl_node *) msg->members,
					(int) msg->nr_members);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	state_override(st, ST_TERM);
}

static void
slg_send_timeout(uv_timer_t *req, int status)
{
	struct state *st = req->data;
	struct server_list_get_req *r = st->data;
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	log_warn(lg, "SERVER LIST GET request timeout after %d attempts "
	    "seqid:%d.%d", r->retry + 1, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);
	state_event(st, EV_TIMEOUT);
}

/*
 * ACTION: Prepare and send SERVER_LIST_GET
 *
 * At startup we will try to retrieve list of servers currently
 * known to the cluster. This is unicast datagram sent to
 * a CCOW server specified via ccow-ip6addr/ccow-port configuration
 * parameters.
 */
static void
slg_state__send(struct state *st)
{
	int err;
	struct server_list_get_req *r = st->data;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;

	struct repmsg_server_list_get msg;
	memset(&msg, 0, sizeof (msg));
	msg.maximum_immediate_content_size = REPLICAST_DGRAM_MAXLEN;
	msg.maximum_number_of_delegated_gets = REPLICAST_GETS_MAX;
	msg.reception_window = 0; // FIXME
	msg.parent_serverid = r->serverid;
	msg.sender_flags = r->flags;

	if (netobj->unix_socket_addr)
		r->ctx->attributes = RD_ATTR_UNICAST_UNIXSOCK;

	r->inexec++;
	err = replicast_send(netobj->robj[0], r->ctx, RT_SERVER_LIST_GET,
	    (struct repmsg_generic *)&msg, NULL, NULL, 0,
	    &netobj->server_sockaddr, replicast_send_done_generic, st, NULL);
	if (err) {
		r->inexec--;
		log_warn(lg, "replicast_send failure err: %d, retrying", err);
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	/*
	 * Timeout in SERVER_LIST_GET_TIMEOUT_MS mss..
	 */
	r->timer_req->data = st;
	uv_timer_start(r->timer_req, slg_send_timeout,
	    tc->slg_timeout, 0);
}

/*
 * called if SLG returns RT_ERROR
 */
static void
slg_state__rt_error(struct state *st)
{
	struct server_list_get_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	struct repmsg_error *msg = (struct repmsg_error *)wqe->msg;

	if (msg->error == -EAGAIN) {
		log_warn(lg, "Received SERVER LIST GET RESPONSE (%d): retrying "
		    "seqid:%d.%d after %d ms delay", msg->error,
		    r->ctx->sequence_cnt, r->ctx->sub_sequence_cnt - 1,
		    SERVER_LIST_GET_ERROR_RETRY_TIMEOUT_MS);

		if (r->timer_req->data)
			uv_timer_stop(r->timer_req);
		r->timer_req->data = st;
		uv_timer_start(r->timer_req, slg_send_timeout,
				SERVER_LIST_GET_ERROR_RETRY_TIMEOUT_MS, 0);
		return;
	}

	log_error(lg, "Received SERVER LIST GET RESPONSE error %d "
	    "seqid:%d.%d", msg->error, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

	ccow_fail_io(st->io, msg->error);
	state_next(st, EV_ERR);
}

/*
 * GUARD: check for retry < MAX_RETRY
 */
static int
slg_guard__retry(struct state *st)
{
	struct server_list_get_req *r = st->data;

	if (++r->retry < SERVER_LIST_GET_MAX_RETRY) {
		/* reset payload */
		if ((r->onebuf.base) && r->onebuf.len > 0) {
			je_free(r->onebuf.base);
			r->onebuf.base = NULL;
			r->onebuf.len = 0;
		}
		for (int i = 0; i < REPLICAST_DGRAM_MAX; i++) {
			r->payload[i].base = NULL;
			r->payload[i].len = 0;
		}
		r->nbufs = 0;
		return 1; // ok
	}

	log_error(lg, "SERVER LIST GET request timeout after %d attempts "
	    "seqid:%d.%d", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

	ccow_fail_io(st->io, -EIO);
	state_next(st, EV_ERR);
	return 0; // fail
}

static void
slg_state__init(struct state *st)
{
	struct server_list_get_req *r = st->data;
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
slg_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
slg_state__term(struct state *st)
{
	struct server_list_get_req *r = st->data;
	struct ccow_io *io = (struct ccow_io *)st;

	assert(r->inexec >= 0);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	if ((r->onebuf.base) && r->onebuf.len > 0) {
		je_free(r->onebuf.base);
		r->onebuf.base = NULL;
		r->onebuf.len = 0;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	uv_close((uv_handle_t *)r->timer_req, slg_timer_close_cb);

	r->netobj->tc->slg_in_progress = 0;
	repctx_destroy(r->ctx);
	ccow_complete_io(io);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, &slg_state__init, ST_INIT, NULL },
{ ST_INIT, EV_SEND, &slg_state__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, &slg_state__send, ST_WAIT, &slg_guard__retry },
{ ST_READY, EV_TIMEOUT, &slg_state__send, ST_WAIT, &slg_guard__retry },
{ ST_WAIT, RT_ERROR, &slg_state__rt_error, ST_WAIT, NULL },
{ ST_WAIT, RT_SERVER_LIST_RESPONSE, &slg_state__assemble_payload, ST_READY, NULL },
{ ST_READY, RT_SERVER_LIST_RESPONSE, &slg_state__assemble_payload, ST_READY, NULL },
{ ST_READY, EV_DONE, &slg_state__response, ST_WAIT, NULL },
{ ST_ANY, EV_ANY, &slg_state__error, ST_TERM, NULL }
};

/*
 * Initiate RT_SERVER_LIST_GET
 *
 * Learn wrt. serverids/devids parent/child relationship from
 * our cluster neighbours. As such, each CCOW server while
 * joining will have a complete and up to date collection
 * of ServerIDs associated with physical nodes and devices
 * it is managing.
 *
 * CONTEXT: API thread. Processing of the call needs to be scheduled for
 * tc->loop via using uv_async.
 */
int
server_list_get_init(struct ccow_network *netobj, struct ccow_completion *c,
    uint128_t serverid, struct cl_node *node, uint32_t flags)
{
	int err;
	struct ccow *tc = netobj->tc;

	if (tc->slg_in_progress)
		return -EBUSY;

	log_info(lg, "fetching latest FlexHash");

	struct server_list_get_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		ccow_release(c);
		log_error(lg, "server_list_get: out of memory: -ENOMEM");
		return -ENOMEM;
	}

	r->netobj = netobj;
	r->serverid = serverid;
	r->node = node;
	r->flags = flags;

	struct ccow_op *list_get_op;
	err = ccow_operation_create(c, CCOW_RING, &list_get_op);
	if (err) {
		log_error(lg, "Error creating op. err: %d", err);
		ccow_release(c);
		je_free(r);
		return err;
	}

	struct ccow_io *io;
	err = ccow_create_io(c, list_get_op, CCOW_RING, trans_tbl,
	    sizeof (trans_tbl) / sizeof (*trans_tbl), r, slg_state__term, &io);
	if (err) {
		log_error(lg, "Error creating io. err: %d", err);
		ccow_operation_destroy(list_get_op, 1);
		ccow_release(c);
		je_free(r);
		return err;
	}

	tc->slg_in_progress = 1;
	err = ccow_start_io(io);
	return err;
}

static void
server_list_async_cb(ccow_completion_t c, void *arg, int index, int err)
{
	if (err) {
		log_warn(lg, "RT_SERVER_LIST_GET async fetch err %d", err);
	}
}

int
server_list_async_fetch(struct replicast *robj,
    struct repctx *ctx, struct state *state)
{
	struct ccow *tc = robj->client_ctx;

	if (tc->slg_in_progress)
		return -EBUSY;

	/*
	 * Issue RT_SERVER_LIST_GET asynchronously
	 */
	struct ccow_completion *c;
	int err = ccow_create_completion(tc, NULL, server_list_async_cb, 1,
	    (ccow_completion_t *)&c);
	if (err) {
		log_error(lg, "Error creating completion. err: %d", err);
		return err;
	}

	uint64_t fh_genid_prev = flexhash_get_genid(FH_GENID_CLIENT, tc);
	flexhash_reset_genid(FH_GENID_CLIENT, tc);
	err = server_list_get_init(tc->netobj, c, uint128_null, 0, 0);
	if (err) {
		flexhash_set_genid(tc->flexhash, fh_genid_prev);
		return err;
	}

	return 0;
}
