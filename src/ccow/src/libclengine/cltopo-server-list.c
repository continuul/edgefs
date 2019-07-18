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
#include "flexhash.h"
#include "state.h"

extern struct ccowd *ccow_daemon;
struct cl_req {
	struct repctx *ctx;
	struct cl_node *node_reply;
	int nr_nodes;
	int error;
	int inexec;
	uv_buf_t payload;
	rtbuf_t *checkpoint_payload;
};

static void
nedge_debug_slg_response(struct cl_req *req,
    struct repmsg_server_list_get *msg,
    struct repmsg_server_list_response *rsp)
{
	struct cl_node *nodes;
	struct cl_vdev *vdevptr;
	uint32_t nr_nodes, nd, x, y;

	if (!(msg->sender_flags & SLG_SENDER_DEBUG))
		return;

	// Decode number of nodes and devices to send back
	msg->sender_flags &= ~SLG_SENDER_DEBUG;
	x = (msg->sender_flags >> 10) & 0x3FF;
	y = msg->sender_flags >> 22;

	nr_nodes = (x > FLEXHASH_MAX_SERVERS) ? FLEXHASH_MAX_SERVERS : x;
	nr_nodes = (x == 0) ? 1 : x;
	nd = FLEXHASH_MAX_VDEVS / nr_nodes;
	nd = (y < nd) ? y : nd;
	nd = (y == 0) ? 1 : y;

	nodes = je_calloc(nr_nodes, sizeof(struct cl_node));
	if (!nodes)
		goto _err;

	for (uint32_t i = 0; i < nr_nodes; i++) {
		vdevptr = je_calloc(nd, sizeof(struct cl_vdev));
		if (!vdevptr)
			goto _err;
		nodes[i].vdevs = vdevptr;
		nodes[i].nr_vdevs = nd;
	}

	char server_name[] = "server-debug";
	char device_name[] = "/data/debug";
	char name[512];
	int err;

	uint32_t numrows = flexhash_hashrowcount(nd * nr_nodes);
	for (uint32_t i = 0; i < nr_nodes; i++) {
		snprintf(name, 512, "%s-%u", server_name, i);
		err = crypto_hash(CRYPTO_BLAKE2B, 16, (const uint8_t *)name,
		    strlen(name), (uint8_t *)&nodes[i].serverid);
		if (err)
			goto _err;

		for (uint32_t j = 0; j < nodes[i].nr_vdevs; j++) {
			vdevptr = &nodes[i].vdevs[j];
			snprintf(name, 512, "%s-%u-%u", device_name, i, j);
			err = crypto_hash(CRYPTO_BLAKE2B, 16,
			    (const uint8_t *)name, strlen(name),
			    (uint8_t *)&vdevptr->vdevid);
			if (err)
				goto _err;

			vdevptr->size = i + j;
			vdevptr->avail = j;
			vdevptr->activerows = 0;
			vdevptr->numrows = numrows;
			flexhash_sumsquares_seeded(&vdevptr->vdevid,
			    vdevptr->hashcount, vdevptr->numrows);
		}
	}

	log_debug(lg, "Generated nodes:%u disks:%u numrows:%u",
	    nr_nodes, nd, numrows);

	clengine_destroy_cl_node(req->node_reply, req->nr_nodes);
	req->node_reply = nodes;
	req->nr_nodes = nr_nodes;
	rsp->nr_members = nr_nodes;

	return;

_err:
	log_error(lg, "%s failed", __FUNCTION__);
	for (uint32_t i = 0; i < nr_nodes; i++) {
		if (nodes[i].vdevs)
			je_free(nodes[i].vdevs);
	}

	je_free(nodes);
}

#ifdef NEDGE_NDEBUG
#define NEDGE_DEBUG_SLG_RESPONSE(req, msg, rsp)
#else
#define NEDGE_DEBUG_SLG_RESPONSE(req, msg, rsp) \
	nedge_debug_slg_response(req, msg, rsp)
#endif

static void
cltopo_server_list_state__term(struct state *st)
{
	struct cl_req *req = (struct cl_req *)(st->data);

	log_trace(lg, "st %p inexec %d", st, req->inexec);

	assert(req->inexec >= 0);

	repctx_drop(req->ctx);
	if (req->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    req, req->inexec);
		return;
	}

	if ((req->payload.base) && (req->payload.len > 0)) {
		je_free(req->payload.base);
		req->payload.base = NULL;
		req->payload.len = 0;
	}

	if (req->node_reply) {
		clengine_destroy_cl_node(req->node_reply, req->nr_nodes);
		req->node_reply = NULL;
	}

	repctx_destroy(req->ctx);
	je_free(req);
}

static void
cltopo_error_onsend(void *data, int err, int ctx_valid)
{
	struct cl_req *req = (struct cl_req *)data;
	struct state *st = req->ctx->state;

	log_trace(lg, "st %p", st);
	if (err)
		log_error(lg, "Error %d while sending cltopo slg error", err);

	req->inexec--;
	state_event(st, EV_DONE);
}

static void
cltopo_server_list_state__error(struct state *st)
{
	struct cl_req *req = (struct cl_req *)(st->data);
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	int err;

	log_trace(lg, "st %p", st);
	assert(req->error != 0);

	struct repmsg_error errmsg;
	memset(&errmsg, 0, sizeof(errmsg));
	errmsg.num_datagrams = 1;
	errmsg.error = req->error;

	if (wqe->msg->hdr.peer_sock)
		ctx->attributes = RD_ATTR_UNICAST_UNIXSOCK;

	req->inexec++;
	err = replicast_send(ccow_daemon->robj[0], ctx, RT_ERROR,
	    (struct repmsg_generic *)&errmsg,
	    (struct repmsg_generic *)wqe->msg, NULL,
	    0, NULL, cltopo_error_onsend, req, NULL);

	if (err) {
		req->inexec--;
		log_error(lg, "Unable to send RT_ERROR back to the client ");
		state_next(st, EV_DONE);
	}
}

static void
cltopo_server_onsend(void *data, int err, int ctx_valid)
{
	struct cl_req *req = (struct cl_req *)data;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
	    data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;
	if (err) {
		log_error(lg, "Error %d while sending cltopo slg response", err);
		req->error = err;
		state_event(st, EV_ERR);
		return;
	}

	state_event(st, EV_DONE);
}

static int
cltopo_pack_payload(struct cl_req *req)
{
	int err;

	if (req->payload.base) {
		log_debug(lg, "Duplicate cltopo slg response");
		return 0;
	}

	err = replicast_pack_uvbuf_nodes(req->node_reply, req->nr_nodes,
	    &req->payload, req->checkpoint_payload);
	if (err) {
		log_error(lg, "Failed to pack nodes");
		return err;
	}

	log_debug(lg, "slg payload size %lu", req->payload.len);

	return 0;
}

/*
 * ACTION: process RT_SERVER_LIST_GET request
 *
 * Return known serverids or vdevs.
 */
static void
cltopo_server_list_state__get(struct state *st)
{
	struct cl_req *req = (struct cl_req *)(st->data);
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	int err;
	log_trace(lg, "st %p", st);

	if (req->inexec)
		return;

	struct repmsg_server_list_get *msg =
		(struct repmsg_server_list_get *)wqe->msg;
	struct repmsg_server_list_response rsp;

	memset(&rsp, 0, sizeof (rsp));
	rsp.parent_serverid = msg->parent_serverid;

	struct sockaddr_in6 saddr;
	if (ccow_daemon->mcbase_ip4addr) {
		struct sockaddr_in addr4;
		inet_pton(AF_INET, ccow_daemon->mcbase_ip4addr, &addr4.sin_addr);
		replicast_ip4_encap(&addr4, &saddr);
	} else {
		inet_pton(AF_INET6, ccow_daemon->mcbase_ip6addr, &saddr.sin6_addr);
	}
	memcpy((uint8_t *)&rsp.mcbase_ip6addr,
	    (uint8_t *)saddr.sin6_addr.s6_addr, 16);
	rsp.mcbase_port = ccow_daemon->mcbase_port;

	req->checkpoint_payload = NULL;

	char out[64];
	if (uint128_cmp(&rsp.parent_serverid, &uint128_null) == 0) {
		/* here we return all possible nodes, vdevs and checkpoint for server */
		uint128_dump(&rsp.parent_serverid, out, 64);
		log_info(lg, "RT_SERVER_LIST_REQUEST with missing "
		    "parent_serverid = %s", out);

		err = flexhash_get_nodes(ccow_daemon->flexhash,
				    &req->node_reply, &req->nr_nodes, FH_GOOD_HC);
		if (err) {
			req->error = err;
			state_next(ctx->state, EV_ERR);
			return;
		}
		if (msg->sender_flags & SLG_SENDER_GETCHECKPOINT) {
			rtbuf_t *rb;
			err = flexhash_get_checkpoint(&rb);
			if (!err) {
				req->checkpoint_payload = rb;
			}
		}
		rsp.nr_members = req->nr_nodes;
		rsp.checkpoint_numdevices = ccow_daemon->flexhash->checkpoint_numdevices;

		/* if we booted from a checkpoint mark it as ckpread = 1
		 * from the flexhash that was booted up
		 * */
		if (ccow_daemon->flexhash->ckpread)
			rsp.ckpread = ccow_daemon->flexhash->ckpread;
		else {
			/* if we did not boot up from a checkpoint but
			 * we do have one that was created later
			 * then we indicate this by returning 2
			 */
			int found = flexhash_checkpoint_exists();
			if (found)
				rsp.ckpread = FH_CKPREAD_SKIP;
		}

	} else {
		/* here we return only the requested server and it's vdevs */
		uint128_dump(&rsp.parent_serverid, out, 64);
		log_info(lg, "RT_SERVER_LIST_REQUEST with "
		    "parent_serverid = %s", out);

		if (uint128_cmp(&msg->sender_serverid, &uint128_null) != 0) {
			/* first we populate the flexhash with the sender's
			 * node info. */
			struct cl_node node;

			node.serverid = msg->sender_serverid;
			node.addr = msg->sender_recv_addr;
			node.port = msg->sender_recv_port;
			node.nr_vdevs = msg->nr_vdevs;
			node.vdevs = msg->vdevs;
			node.zone = msg->zone;
			err = flexhash_add_server(ccow_daemon->flexhash, &node,
				FH_TABLE_JOIN, FH_NOGOOD_HC, FH_NO_REBUILD);
			if (err) {
				char sout[64];
				uint128_dump(&node.serverid, sout, 64);
				log_warn(lg, "Server %s already exists", sout);
			}
			if (msg->vdevs) {
				je_free(msg->vdevs);
				msg->vdevs = NULL;
			}
		}

		err = clengine_get_node(&msg->parent_serverid, &req->node_reply);
		if (err == -ENOENT) {
			req->error = -ENOENT;
			log_error(lg, "serverid: %s not found", out);
			msg->vdevs = NULL;
			state_next(ctx->state, EV_ERR);
			return;
		}
		if (!req->node_reply) {
			req->error = -ENOMEM;
			log_error(lg, "Node not allocated");
			state_next(ctx->state, EV_ERR);
			return;
		}

		req->nr_nodes = 1;
		rsp.nr_members = 1;
		rsp.checkpoint_numdevices = ccow_daemon->flexhash->checkpoint_numdevices;
		rsp.ckpread = ccow_daemon->flexhash->ckpread;
	}
	NEDGE_DEBUG_SLG_RESPONSE(req, msg, &rsp);

	err = cltopo_pack_payload(req);
	if (err) {
		req->error = err;
		log_error(lg, "Error packing server_list_response");
		state_next(ctx->state, EV_ERR);
		return;
	}

	if (req->checkpoint_payload) {
		rtbuf_destroy(req->checkpoint_payload);
		req->checkpoint_payload = NULL;
	}

	if (wqe->msg->hdr.peer_sock)
		ctx->attributes = RD_ATTR_UNICAST_UNIXSOCK;

	req->inexec++;
	err = replicast_send(ccow_daemon->robj[0], ctx, RT_SERVER_LIST_RESPONSE,
	    (struct repmsg_generic *)&rsp,
	    (struct repmsg_generic *)wqe->msg, &req->payload, 1,
	    NULL, cltopo_server_onsend, req, NULL);
	if (err) {
		req->inexec--;
		state_next(ctx->state, EV_ERR);
	}
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, RT_SERVER_LIST_GET, &cltopo_server_list_state__get, ST_WAIT, NULL },
{ ST_INIT, EV_ERR, &cltopo_server_list_state__error, ST_WAIT, NULL },
{ ST_WAIT, EV_ERR, &cltopo_server_list_state__error, ST_WAIT, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, NULL, ST_TERM, NULL }
};

int
cltopo_server_list_init(struct replicast *robj, struct repctx *ctx,
    struct state *state)
{
	struct cl_req *req = je_calloc(1, sizeof (struct cl_req));
	if (!req)
		return -ENOMEM;
	req->ctx = ctx;
	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof (trans_tbl)/sizeof (*trans_tbl);
	state->data = req;
	state->term_cb = cltopo_server_list_state__term;
	return 0;
}
