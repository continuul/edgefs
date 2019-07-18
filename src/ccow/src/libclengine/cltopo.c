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
#include "cltopo.h"
#include "clengine.h"
#include "ccowd-impl.h"
#include "state.h"

struct server_list_get_req {
	struct state state; /* Notice: position matters here */
	struct repctx *ctx;
	struct cl_node node;
	int nr_nodes;
	int getallnodes;
	uv_timer_t *start_req;
	uv_timer_t *timer_req;
	struct repmsg_server_list_get *msg_req;
	struct cluster_engine *ceng;
	int retry;
	int inexec;
	int nbufs;
	uv_buf_t payload[REPLICAST_DGRAM_MAX];
	uv_buf_t onebuf;
};

static void
cltopo_state__error(struct state *st)
{
	struct server_list_get_req *r = st->data;
	log_trace(lg, "st %p", st);
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	if (r->start_req->data) {
		uv_timer_stop(r->start_req);
		r->start_req->data = NULL;
	}
	cl_node_set_state(&r->node.serverid, CL_NODE_QUERY_FAILED);
}

static void
cltopo_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
cltopo_state__term(struct state *st)
{
	struct server_list_get_req *r = st->data;
	log_trace(lg, "st %p", st);

	assert(r->inexec >= 0);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	if ((r->onebuf.base) && (r->onebuf.len > 0)) {
		je_free(r->onebuf.base);
		r->onebuf.base = NULL;
		r->onebuf.len = 0;
	}

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)r->timer_req, cltopo_timer_close_cb);

	if (r->start_req->data) {
		uv_timer_stop(r->start_req);
		r->start_req->data = NULL;
	}
	uv_close((uv_handle_t *)r->start_req, cltopo_timer_close_cb);

	repctx_drop(r->ctx);
	repctx_destroy(r->ctx);
	je_free(r);
}

static void
cltopo_send_timeout(uv_timer_t *req, int status)
{
	struct server_list_get_req *r = req->data;
	log_trace(lg, "req %p", r);
	struct repctx *ctx = r->ctx;

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	state_event(ctx->state, EV_TIMEOUT);
}

static void
cltopo_send_done(void *data, int err, int ctx_valid)
{
	struct server_list_get_req *req = data;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
	    data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;
	if (state_check(st, ST_TERM)) {
		cltopo_state__term(st);
		return;
	}

	if (err) {
		log_error(lg, "Error %d while sending cltopo request", err);
		state_event(st, EV_ERR);
		return;
	}
}

/*
 * ACTION: Prepare and send SERVER_LIST_GET to a clengine's node
 */
static void
cltopo_state__send(struct state *st)
{
	struct server_list_get_req *r = st->data;
	struct repctx *ctx = r->ctx;
	int err;
	struct repmsg_server_list_get msg;
	memset(&msg, 0, sizeof (msg));
	msg.maximum_immediate_content_size = REPLICAST_DGRAM_MAXLEN;
	msg.maximum_number_of_delegated_gets = REPLICAST_GETS_MAX;
	msg.reception_window = 0; // FIXME

	void *copied_vdevs = NULL;
	if (r->getallnodes) {
		/* zeroed parent id means we get everything */
		memset(&msg.parent_serverid, 0, sizeof(uint128_t));
		/* for GW - get checkpoint as well */
		if (server_get()->numdisks == 0)
			msg.sender_flags |= SLG_SENDER_GETCHECKPOINT;
	} else {
		/* specify parent's serverid to get child info */
		msg.parent_serverid = r->node.serverid;
		err = clengine_copy_mynodeinfo(&msg);
		if (err) {
			log_error(lg, "Unable to retrieve my node info err=%d", err);
			state_next(ctx->state, EV_ERR);
			return;
		}
		copied_vdevs = msg.vdevs;
	}
	/* use parent's addr/port to send this request to */
	struct sockaddr_in6 addr;
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(r->node.port);
	memcpy((uint8_t *)addr.sin6_addr.s6_addr,
	    (uint8_t *)&r->node.addr, 16);
	addr.sin6_flowinfo = 0;
	addr.sin6_scope_id = ccow_daemon->if_indexes[0];

	r->inexec++;
	err = replicast_send(ccow_daemon->robj[0], ctx, RT_SERVER_LIST_GET,
	    (struct repmsg_generic *)&msg, NULL, NULL, 0, &addr,
	    cltopo_send_done, r, NULL);
	if (err) {
		r->inexec--;
		if (copied_vdevs)
			je_free(copied_vdevs);
		char out[64];
		uint128_dump(&r->node.serverid, out, 64);
		log_warn(lg, "Cannot send RT_SERVER_LIST_GET to "
		    "parent serverid %s, err: %d", out, err);
		state_next(ctx->state, EV_ERR);
		return;
	}
	if (copied_vdevs)
		je_free(copied_vdevs);

	/*
	 * Timeout in 1s if no response...
	 */
	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	r->timer_req->data = r;
	uv_timer_start(r->timer_req, cltopo_send_timeout,
	    SERVER_LIST_GET_TIMEOUT_MS, 0);
}

/*
 * GUARD: check for retry < MAX_RETRY
 */
static int
cltopo_guard__retry(struct state *st)
{
	struct server_list_get_req *r = st->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "st %p seqcnt: %d", st, ctx->sequence_cnt);
	if (r->retry++ < SERVER_LIST_GET_MAX_RETRY)
		return 1; // ok

	char serverstr[64];
	uint128_dump(&r->node.serverid, serverstr, 64);
	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &r->node.addr, dst, INET6_ADDRSTRLEN);
	log_error(lg, "Timeout retrieving server %s addr=%s[%d] info, retry: %d"
	    " timeout: %d", serverstr, dst, r->node.port, r->retry, SERVER_LIST_GET_TIMEOUT_MS);

	state_next(ctx->state, EV_ERR);
	return 0; // fail
}

static void
cltopo_state__assemble_payload(struct state *st)
{
	struct server_list_get_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_server_list_response *msg;
	int err;

	assert(wqe);
	msg = (struct repmsg_server_list_response *)wqe->msg;

	int idx = msg->hdr.datagram_num - 1;
	if (idx >= msg->num_datagrams) {
		log_error(lg, "Corrupt RT: %s idx: %d >= num_datagrams: %d",
		    replicast_opcode_str[msg->hdr.transaction_id.opcode],
		    idx, msg->num_datagrams);
		state_next(st, EV_ERR);
		return;
	}

	log_warn(lg, "%s idx: %d num_datagrams: %d rcvd: %d datagram_num: %d"
	    " nread: %ld seqid %d.%d",
	    replicast_opcode_str[msg->hdr.transaction_id.opcode],
	    idx, msg->num_datagrams, req->nbufs, msg->hdr.datagram_num,
	    wqe->nread, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (req->payload[idx].base) {
		log_warn(lg, "Duplicate: %s idx: %d",
		    replicast_opcode_str[msg->hdr.transaction_id.opcode], idx);
		return;
	}

	req->payload[idx].len = repwqe_payload_len(wqe);
	req->payload[idx].base = repwqe_payload(wqe);

	if (msg->num_datagrams != ++req->nbufs)
		return;

	log_debug(lg, "All datagrams %d of %d received seqid %d.%d",
	    req->nbufs, msg->num_datagrams,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	err = replicast_uvbuf_integrate(req->payload, req->nbufs, &req->onebuf);
	if (err) {
		state_next(st, EV_ERR);
		return;
	}

	log_debug(lg, "slg payload size %lu", req->onebuf.len);
	state_next(st, EV_DONE);
}

/* TODO: Remove this function?? Not called from anywhere */
int
add_node_to_flexhash(struct flexhash *fhtable, struct cl_node *node)
{
	struct fhserver *fhserver;
	char out[64];

	uint128_dump(&node->serverid, out, 64);
	flexhash_lock(fhtable);
	fhserver = flexhash_get_fhserver(fhtable, &node->serverid);
	if (fhserver) {
		log_warn(lg, "rebuild : server %s already exists", out);
		flexhash_unlock(fhtable);
		return -1;
	}
	flexhash_unlock(fhtable);
	int err = flexhash_add_server(fhtable, node, FH_TABLE_JOIN,
	    FH_GOOD_HC, FH_REBUILD_NEXT);
	if (err) {
		log_error(lg, "Unable to update new "
			"flexhash for %s err=%d", out, err);
		return err;
	}
	return 0;
}

/*
 * ACTION: process response
 *
 * Build tree of serverid/vdevid
 */
static void
cltopo_state__response(struct state *st)
{
	struct server_list_get_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	struct cl_node *rnode;
	int err;

	log_trace(lg, "st %p ", st);
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	struct repmsg_server_list_response *msg =
		(struct repmsg_server_list_response *)wqe->msg;

	char *checkpoint = je_malloc(REPLICAST_CHUNK_SIZE_MAX);
	*checkpoint = 0;
	err = replicast_unpack_uvbuf_nodes(&r->onebuf, msg->nr_members, &rnode,
	    checkpoint, REPLICAST_CHUNK_SIZE_MAX);
	if (err) {
		state_next(st, EV_ERR);
		return;
	}

	msg->members = rnode;

	char out[64];
	uint128_dump(&msg->parent_serverid, out, 64);
	if (uint128_cmp(&msg->parent_serverid, &uint128_null) == 0) {
		/* Update the entire flexhash */
		err = clengine_fh_update_full(out, msg->members,
					      msg->nr_members,
					      msg->hdr.fh_genid,
					      msg->checkpoint_numdevices);
		if (err < 0) {
			if (err == -ETIME)
				state_next(ctx->state, EV_TIMEOUT);
			/*
			 * TODO: Should we transition with EV_ERR
			 * if err == -ENOMEM
			 */
			goto cltopo_response_done;
		}

		if (*checkpoint) {
			err = flexhash_save_checkpoint(checkpoint);
			if (err) {
				log_error(lg, "Failed to save checkpoint received.err: %d",
				    err);
				je_free(checkpoint);
				goto cltopo_response_done;
			}
		}
	} else {
		log_info(lg, "RT_SERVER_LIST_RESPONSE with parent_serverid"
				" = %s", out);
		/* TODO: Do we expect more than ONE node? */
		assert(msg->nr_members == 1);
		err = clengine_fh_update(out,
					 (struct cl_node *)msg->members);
		if (err)
			goto cltopo_response_done;
	}
cltopo_response_done:
	if (checkpoint)
		je_free(checkpoint);
	replicast_free_repnodelist((struct cl_node *) msg->members,
					(int) msg->nr_members);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, EV_START, &cltopo_state__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, &cltopo_state__send, ST_WAIT, &cltopo_guard__retry },
{ ST_WAIT, RT_ERROR, NULL, ST_WAIT, &cltopo_guard__retry },
{ ST_WAIT, RT_SERVER_LIST_RESPONSE, &cltopo_state__assemble_payload, ST_READY, NULL },
{ ST_READY, RT_SERVER_LIST_RESPONSE, &cltopo_state__assemble_payload, ST_READY, NULL },
{ ST_READY, EV_DONE, &cltopo_state__response, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &cltopo_state__error, ST_TERM, NULL }
};

static void
cltopo_delayed_start(uv_timer_t *req, int status)
{
	struct server_list_get_req *r = req->data;
	struct repctx *ctx = r->ctx;

	if (r->start_req->data) {
		uv_timer_stop(r->start_req);
		r->start_req->data = NULL;
	}

	state_event(ctx->state, EV_START);
}

/*
 * Send SERVER_LIST_GET to all the members
 *
 * At join time we will retrieve list of child vdevs currently
 * known to the cluster. This is unicast datagram sent to each
 * CCOW server specified via addr/port in cl_node. Completed
 * join process will have hierarhy of servers presented as:
 *
 *	+---------------------+
 *	|    Node ServerID    |
 *	+---------------------+
 *	   +----------------+
 *	   |  Child vdevid  |
 *	   +----------------+
 *		   .
 *		   .
 *	   +----------------+
 *	   |  Child vdevid  |
 *	   +----------------+
 *
 * Such organization would provide scalability beyound limit of
 * single size UDP datagram. Node ServerID plays "proxy server role"
 * while Child vdevid represents actual storage device(s).
 */
int
cltopo_learn(struct cl_node *cn, int nr_nodes, int getallnodes, struct cluster_engine *ceng)
{
	size_t i;

	nassert(ccow_daemon->loop_thrid == uv_thread_self());

	struct server_list_get_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		log_error(lg, "slg_req alloc: out of memory: -ENOMEM");
		return -ENOMEM;
	}
	r->node = *cn;
	r->state.table = trans_tbl;
	r->state.cur = ST_INIT;
	r->state.max = sizeof (trans_tbl)/sizeof (*trans_tbl);
	r->state.data = r;
	r->state.term_cb = cltopo_state__term;
	r->getallnodes = getallnodes;
	r->ceng = ceng;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		je_free(r);
		return -ENOMEM;
	}
	r->timer_req->data = NULL;
	uv_timer_init(ccow_daemon->loop, r->timer_req);

	r->start_req = je_malloc(sizeof (*r->start_req));
	if (!r->timer_req) {
		je_free(r->timer_req);
		je_free(r);
		return -ENOMEM;
	}

	r->ctx = repctx_init(ccow_daemon->robj[0]);
	if (!r->ctx) {
		je_free(r->start_req);
		je_free(r->timer_req);
		je_free(r);
		r = NULL;
		log_error(lg, "repctx alloc: out of memory: -ENOMEM");
		return -ENOMEM;
	}
	r->ctx->state = &r->state;

	/*
	 * Spread out requests within START_DELAY_MAX_MS mss range.
	 */
	r->start_req->data = r;
	uv_timer_init(ccow_daemon->loop, r->start_req);
	uv_timer_start(r->start_req, cltopo_delayed_start,
	    rand() % START_DELAY_MAX_MS, 0);

	return 0;
}


