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

#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "putcommon_client.h"


static void
unnamedput__send(struct state *st)
{
	int err;
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = io->comp;
	struct ccow_network *netobj = tc->netobj;
	rtbuf_t *payload = r->payload;

	/* we cannot be called without payload pre-set */
	assert(payload);

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	/*
	 * Prepare Put Proposal
	 */
	struct repmsg_unnamed_chunk_put_proposal msg;
	memset(&msg, 0, sizeof (msg));
	msg.object_name.generation = op->txid_generation;
	msg.object_name.uvid_timestamp = op->uvid_timestamp;
	msg.object_name.name_hash_id = op->name_hash_id;
	msg.object_name.parent_hash_id = op->parent_hash_id;
	msg.hdr.attributes = io->attributes;
	msg.hdr.hash_type = r->hash_type;

	if (RD_ATTR_VM_MARKER & msg.hdr.attributes) {
		msg.object_name.vmm_gen_id = c->vmm_gen_id;
	} else {
		msg.object_name.vmm_gen_id = 0;
	}

	if (io->attributes & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED)) {
		msg.vdev = r->target_vdev;
	}

	/* NG group will be selected based on Payload CHID
	 * The compound and VMM put put installs the ng_chid itself via
	 * simulated op->name_hash_id
	 */
	if (!(io->attributes & (RD_ATTR_COMPOUND | RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED)) &&
	    !(msg.hdr.attributes & RD_ATTR_VM_MARKER))
		r->ng_chid = r->chid;
	else
		r->ng_chid = op->name_hash_id;

	size_t len = rtbuf_len(payload);
	io->network_payload_len = msg.content_length = msg.hdr.data_len = len;
	msg.immediate_content_length = 0;
	msg.content_hash_id = r->chid;

	r->req_start = get_timestamp_us();
	uint64_t avg_rtt = flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
					    FH_MSG_UNSOLICITED, 4096);
	msg.genid_delta = (r->req_start - op->uvid_timestamp) + (avg_rtt >> 1);

	uint64_t select_time_avg = flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
					    FH_MSG_PUT_SELECT, 4096);
	if (select_time_avg < 1000)
		select_time_avg = 1000;
	msg.select_time_avg = 1000 * tc->loop->active_handles + select_time_avg;

	int isrt = (msg.immediate_content_length == 0) ? 1 : 0;
	err = client_putcommon_send_proposal(st, RT_UNNAMED_CHUNK_PUT_PROPOSAL,
				&msg, isrt);
	if (err) {
		log_error(lg, "put proposal error on send err=%d", err);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}
}

static void
unnamedput__init(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct ccow *tc = r->tc;

	log_trace(lg, "st %p ", st);

	r->req_type = CL_PUT_REQ_TYPE_UNNAMED;
	int err = client_putcommon_init(st);
	if (err) {
		log_error(lg, "Error in initialization err=%d", err);
		return;
	}

	unnamedput__send(st);
}

static void
unnamedput__term(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);
	client_put_common_terminate(st);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, &unnamedput__init, ST_WAIT, NULL },
{ ST_WAIT, EV_CALL, &unnamedput__send, ST_WAIT, NULL },
{ ST_READY, EV_CALL, &unnamedput__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, &unnamedput__send, ST_WAIT, &client_putcommon_guard_retry },
{ ST_READY, EV_TIMEOUT, &unnamedput__send, ST_READY, &client_putcommon_guard_retry },
{ ST_WAIT, RT_ACCEPT_NOT_NOW, &client_putcommon_process_busy, ST_WAIT, NULL },
{ ST_READY, RT_ACCEPT_NOT_NOW, &client_putcommon_process_busy, ST_READY, NULL },
{ ST_WAIT, RT_ACCEPT_CONTENT_ALREADY_STORED, NULL, ST_READY,
	&client_putcommon_guard_proposed },
{ ST_READY, RT_ACCEPT_CONTENT_ALREADY_STORED, NULL, ST_READY,
	&client_putcommon_guard_proposed },
/* For UDP only */
{ ST_READY, RT_RENDEZVOUS_TRANSFER, &client_putcommon_rtsend, ST_READY,
	&client_putcommon_guard_rt_retry },
{ ST_READY, RT_INIT_TCP_CONNECT, &client_putcommon_tcp_connect, ST_READY, NULL },
/* For TCP only */
{ ST_READY, RT_TCP_CONNECT_SUCCESS, &client_putcommon_rtsend, ST_READY,
	&client_putcommon_guard_tcp_connect },
{ ST_WAIT, RT_ACCEPT_PROPOSED_RENDEZVOUS, NULL, ST_READY,
	&client_putcommon_guard_proposed },
{ ST_READY, RT_ACCEPT_PROPOSED_RENDEZVOUS, NULL, ST_READY,
	&client_putcommon_guard_proposed },
{ ST_WAIT, RT_UNNAMED_PAYLOAD_ACK, &client_putcommon_payload_ack, ST_TERM,
	&client_putcommon_guard__ack_consensus },
{ ST_WAIT, RT_ERROR, &client_putcommon_payload_ack, ST_TERM,
	&client_putcommon_guard__ack_consensus },
{ ST_READY, RT_UNNAMED_PAYLOAD_ACK, &client_putcommon_payload_ack, ST_TERM,
	&client_putcommon_guard__ack_consensus },
{ ST_WAIT, RT_RENDEZVOUS_NACK, &client_putcommon_nack_rcvd, ST_WAIT,
	&client_putcommon_guard_nack_consensus },
{ ST_READY, RT_RENDEZVOUS_NACK, &client_putcommon_nack_rcvd, ST_READY,
	&client_putcommon_guard_nack_consensus },
{ ST_WAIT, RT_PAYLOAD_RCVD, &client_putcommon_payload_rcvd, ST_READY,
	&client_putcommon_guard_rcvd_consensus },
{ ST_READY, RT_PAYLOAD_RCVD, &client_putcommon_payload_rcvd, ST_READY,
	&client_putcommon_guard_rcvd_consensus },
{ ST_OFFLINE, EV_ERR, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &client_putcommon_error, ST_TERM, NULL }
};

int
ccow_unnamedput_create_common(ccow_completion_t comp,
    putcommon_client_callback_t done_cb, struct ccow_op *op,
    struct ccow_io **pio, struct ccow_io *parent_io, uint8_t detached)
{
	int err;
	struct ccow_completion *c = comp;

	log_trace(lg, "comp %p, done_cb %p, op %p, pio %p, parent_io %p",
	    comp, done_cb, op, pio, parent_io);

	struct putcommon_client_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		log_error(lg, "UNNAMED PUT request alloc error: -ENOMEM");
		return -ENOMEM;
	}

	r->tc = c->tc;
	r->done_cb = done_cb;
	r->hash_type = HASH_TYPE_DEFAULT;

	err = ccow_create_io(c, op, CCOW_PUT, trans_tbl,
			sizeof (trans_tbl) / sizeof (*trans_tbl), r,
			unnamedput__term, pio);
	if (err) {
		je_free(r);
		return err;
	}
	r->io = *pio;
	r->io->parent_io = parent_io;

	log_debug(lg, "r = %p : r->io = %p : op = %p", r, r->io, op);

	ccow_io_lock(r->io);
	if (!detached) {
		if (parent_io) {
			log_debug(lg, "Scheduling %p with parent %p", r->io, parent_io);
			r->io->cont_op = parent_io->cont_op;
			ccow_parallel_io(op, r->io);
		} else
			ccow_chain_io(op, r->io);
	} else {
		if (parent_io) {
			r->io->cont_op = parent_io->cont_op;
			QUEUE_INSERT_TAIL(&parent_io->p_busy_queue, &r->io->p_item);
		}
	}
	ccow_io_unlock(r->io);

	return 0;
}

int
ccow_unnamedput_create(ccow_completion_t comp, putcommon_client_callback_t done_cb,
    struct ccow_op *op, struct ccow_io **pio, struct ccow_io *parent_io)
{
	int err = 0;
	err = ccow_unnamedput_create_common(comp, done_cb, op, pio, parent_io, 0);
	return err;
}

int
ccow_unnamedput_create_detached(ccow_completion_t comp, putcommon_client_callback_t done_cb,
    struct ccow_op *op, struct ccow_io **pio, struct ccow_io *parent_io)
{
	int err = 0;
	err = ccow_unnamedput_create_common(comp, done_cb, op, pio, parent_io, 1);
	return err;
}
