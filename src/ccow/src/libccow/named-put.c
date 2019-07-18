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
#include "getcommon_client.h"


static void
namedput__send(struct state *st)
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
	char buf[256];

	log_trace(lg, "st %p generation %" PRIu64 " seqid %d.%d io %p status %d",
	    st, op->txid_generation,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt, io, c->status);

	if (c->status != 0) {
		/* do not send proposal for version manifest if completion
		 * already in failed state! */
		ccow_fail_io(st->io, c->status);
		state_next(st, EV_ERR);
		return;
	}

	if (!(io->attributes & (RD_ATTR_PARITY_ENCODE | RD_ATTR_ONDEMAMD_PIN |
		RD_ATTR_ONDEMAND_UNPIN | RD_ATTR_ONDEMAND_PERSIST)))
		assert(payload);

	/*
	 * Create new version of object.
	 */
	struct repmsg_named_chunk_put_proposal msg;
	memset(&msg, 0, sizeof (msg));
	if (io->attributes & RD_ATTR_EXPUNGE_OBJECT_VERSION) {
		msg.object_name.generation = op->metadata.txid_generation;
		msg.object_name.uvid_timestamp = op->metadata.uvid_timestamp;
	} else {
		msg.object_name.generation = op->txid_generation;
		msg.object_name.uvid_timestamp = op->coordinated_uvid_timestamp;
	}

	if (io->attributes & RD_ATTR_SERIAL_OP) {
		uint128_t target_vdevid;
		uint16_t row = HASHROWID(&op->name_hash_id, tc->flexhash);

		log_debug(lg, "SOP put for chid: %s", hash_id_to_buffer(&op->name_hash_id, buf));
		if (flexhash_find_master(tc->flexhash, &op->name_hash_id, c->shard_index, &target_vdevid) != 0) {
			log_debug(lg, "SOP put could not find master VDEV in row %d", row);
			ccow_fail_io(st->io, -EIO);
			state_next(st, EV_ERR);
			return;
		}

		log_debug(lg, "SOP put target VDEV %s Shard: %d in row %d",
		    uint128_to_buffer(&target_vdevid, buf), c->shard_index, row);

		r->target_vdev = target_vdevid;

		msg.hdr.orig_id.source_addr = r->target_vdev;
		msg.hdr.orig_id.source_port = (uint16_t) op->shard_index;
	}

	/*
	 * In case of RD_ATTR_OBJECT_REPLACE, distinguish two case which would
	 * need to be treated by TRLOG as "create":
	 *
	 * Case1: insert - delete - insert
	 * Case2: very first insert
	 */
	msg.hdr.attributes = io->attributes;

	if ((c->was_object_deleted && io->attributes & RD_ATTR_OBJECT_REPLACE) ||
	    (io->attributes & RD_ATTR_OBJECT_REPLACE && op->txid_generation == 1)) {
		msg.hdr.attributes &= ~RD_ATTR_OBJECT_REPLACE;
		msg.hdr.attributes |= RD_ATTR_OBJECT_REPLACE_INSERT;
		log_trace(lg, "Setting ATTR as RD_ATTR_OBJECT_REPLACE_INSERT: %lx", msg.hdr.attributes);
	}
	if (c->cont_flags & CCOW_CONT_F_EPHEMERAL) {
		msg.hdr.attributes |= RD_ATTR_EPHEMERAL_VERSION;
		log_trace(lg, "Setting ATTR as RD_ATTR_EPHEMERAL_VERSION: %lx", msg.hdr.attributes);
	}
	msg.hdr.hash_type = r->hash_type;
	msg.object_name.name_hash_id = op->name_hash_id;
	msg.object_name.parent_hash_id = op->parent_hash_id;

	size_t len = 0;
	if (io->attributes & (RD_ATTR_PARITY_ENCODE | RD_ATTR_ONDEMAMD_PIN |
		RD_ATTR_ONDEMAND_UNPIN | RD_ATTR_ONDEMAND_PERSIST)) {
		for (size_t i = 0; i < op->iovcnt_in; ++i)
			len += op->iov_in[i].iov_len;
		msg.content_hash_id = r->chid = c->vm_content_hash_id;
		if (io->attributes & RD_ATTR_PARITY_ENCODE) {
			msg.ec_algorithm = GET_CODECID(c->ec_data_mode);
			FROM_CODECFMT(c->ec_data_mode, msg.ec_width, msg.ec_parity);
			msg.ec_domain = c->tc->failure_domain;
		}
	} else {
		/* we cannot be called without payload pre-set */
		assert(payload);

		/*
		 * Note: If Version Manifest is large... we will spend lots of CPU
		 *       cycles on the event loop contex. However, thread deferred
		 *       hashing approuch would add extra processing latency.
		 *
		 * Justification: We do not update version manifest too often and
		 *                as such the impact on tenant context is not
		 *                significant as compared to chunk manifests...
		 *
		 * Calculate payload w/o MD overrides first
		 */
		err = rtbuf_hash(payload, HASH_TYPE_DEFAULT, &msg.content_hash_id);
		if (err) {
			log_error(lg, "NAMED PUT error while calculating "
			    "payload hash value: %d", err);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return;
		}


		if (c->md_overrides && !c->md_overrides_added) {
			/*
			 * Add md overrides to vm payload
			 */
			r->payload = ccow_add_md_overrides_to_payload(c, r->payload);
			if (r->payload == NULL) {
				ccow_fail_io(st->io, err);
				state_next(st, EV_ERR);
				return;
			}

			payload = r->payload;
			len = rtbuf_len(payload);
		} else {
			len = rtbuf_len(payload);
		}

		/* VM payload, store it in completion as well so that object
		 * gateways can construct fast ETag by simply pointing to vm_chid
		 */
		c->vm_content_hash_id = r->chid = msg.content_hash_id;
	}
	io->network_payload_len = msg.content_length = msg.hdr.data_len = len;
	msg.immediate_content_length = 0;
	/* CHID to select NG from, it is NHID in case of NamedPut */
	r->ng_chid = op->name_hash_id;

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
	err = client_putcommon_send_proposal(st, RT_NAMED_CHUNK_PUT_PROPOSAL,
				&msg, isrt);
	if (err) {
		log_error(lg, "put proposal error on send err=%d", err);
		state_event(st, EV_TIMEOUT);
		return;
	}

}

static void
namedput__init_continued(struct state *st, int ev_context)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = io->comp;

	op->namedget_io = r->io;

	int err = op->chm->update(op->chm_handle, op,
	    (bt_overwrite_cb) ccow_ucache_evict_overwrite, (void *) r->tc->ucache);
	if (err) {
		ccow_fail_io(st->io, err);
		if (ev_context)
			state_next(st, EV_ERR);
		else
			state_event(st, EV_ERR);
		return;
	}

	ccow_io_lock(io);
	if (QUEUE_EMPTY(&io->p_queue)) {
		ccow_io_unlock(io);
		if (ev_context)
			state_next(st, EV_DONE);
		else
			state_event(st, EV_DONE);
		ccow_io_lock(io);
	} else {
		while (!QUEUE_EMPTY(&io->p_queue)) {
			QUEUE *q = QUEUE_HEAD(&io->p_queue);
			struct ccow_io *cio = QUEUE_DATA(q, struct ccow_io, p_item);

			err = ccow_start_io(cio);
			if (err) {
				ccow_io_unlock(io);
				if (ev_context)
					state_next(st, EV_ERR);
				else
					state_event(st, EV_ERR);
				return;
			}
			QUEUE_REMOVE(q);
			QUEUE_INIT(q);
			QUEUE_INSERT_TAIL(&io->p_busy_queue, &cio->p_item);
		}
	}
	ccow_io_unlock(io);
	/* wait for EV_DONE from the last parallel I/O */
}

static void
vm_unencode_callback(ccow_completion_t comp, void *arg,
		    int index, int status) {
	struct state *st = arg;
	struct putcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow* cl = op->comp->tc;

	if (status) {
		log_error(lg, "VM unencode processing error: %d", status);
		ccow_fail_io(st->io, status);
		state_event(st, EV_ERR);
		return;
	}
	if (op->optype == CCOW_CONT)
		namedput__init_continued(st, 0);
	else
		namedput__send(st);
}

static int
vm_unencode_request(struct state *st) {
	struct putcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow* cl = op->comp->tc;
	int err = 0;

	struct ccow_op *ug_op = NULL;
	struct ccow_io *get_io = NULL;
	/* To unencoded VM a unnamed get is to be invoke prior the named put */
	ccow_completion_t c;
	err = ccow_create_completion(cl, st, vm_unencode_callback, 1, &c);
	if (err)
		return err;
	err = ccow_operation_create(c, CCOW_CLONE, &ug_op);
	if (err) {
		ccow_release(c);
		return err;
	}
	err = ccow_unnamedget_create(c, NULL, ug_op, &get_io, NULL);
	if (err) {
		ccow_operation_destroy(ug_op, 1);
		ccow_release(c);
		log_error(lg, "error returned by ccow_unnamedget_create: %d",
		err);
		return err;
	}
	ug_op->iov_in = NULL;
	ug_op->iovcnt_in = 0;
	ug_op->offset = 0;
	get_io->attributes = RD_ATTR_VERSION_MANIFEST | RD_ATTR_CM_LEAF_WRITE;

	struct getcommon_client_req *req = CCOW_IO_REQ(get_io);

	req->chid = op->vmchid;
	req->offset = 0;
	req->hash_type = op->metadata.hash_type;
	req->compress_type = op->metadata.compress_type;
	req->ng_chid = op->metadata.nhid;

	err = ccow_start_io(get_io);

	if (err) {
		ccow_operation_destroy(ug_op, 1);
		ccow_release(c);
	}
	return err;
}

static void
namedput__init(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = io->comp;

	log_trace(lg, "st %p, cont_flags 0x%x", st, c->cont_flags);

	r->req_type = CL_PUT_REQ_TYPE_NAMED;
	int err = client_putcommon_init(st);
	if (err) {
		log_error(lg, "Error in initialization err=%d", err);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}

	if (op->optype == CCOW_CONT) {
		if (c->canceled) {
			ccow_fail_io(st->io, -EINTR);
			state_next(st, EV_ERR);
			return;
		}

		if (!c->needs_final_put || !op->chm_handle || !op->chunks) {
			state_override(st, ST_TERM);
			return;
		}
	}

	if (op->optype == CCOW_CLONE || op->optype == CCOW_CONT) {
		int leaf = op->vm_leaf && *op->vm_leaf;
		if (!op->vm_leaf && op->vm_reflist->nbufs) {
			struct refentry* e = (struct refentry*)rtbuf(op->vm_reflist, 0).base;
			if (e && RT_REF_LEAF(e))
				leaf = 1;
		}
		if ((!op->chm || !strcmp(op->chm->name, "btree_map")) &&
			leaf && ccow_ec_timeout_expired(&op->metadata)) {
			/*
			 * The previous VM is a leaf manfiest and it's parity protected.
			 * Before overwriting or cloning it's required to restore
			 * number of replicas for each refEntry as if they were
			 * replicas-protected.
			 */
			log_debug(lg, "Restoring a number of replicas for a leaf VM %lX\n",
				op->vmchid.u.u.u);
			err = vm_unencode_request(st);
			if (err) {
				ccow_fail_io(st->io, -err);
				state_next(st, EV_ERR);
			}
			return;
		}
	}
	if (op->optype == CCOW_CONT) {
		namedput__init_continued(st, 1);
		return;
	}

	namedput__send(st);
}

static void
namedput__encode_ack(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);
}

static void
namedput__pin_ack(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (wqe) {
		struct repmsg_persistency_ack *msg =
			(struct repmsg_persistency_ack*)wqe->msg;

		r->persistent_replies++;
		if (msg->error == RT_ERR_NOT_FOUND)
			r->persistent_nacks++;

		log_debug(lg, "PERS ACK: VDEV %016lX%016lX error %d, replies %u, nacks %u, ngcount %u",
			msg->vdevid.u,  msg->vdevid.l, msg->error, r->persistent_replies,
			r->persistent_nacks, msg->ngcount);
		if (msg->error && msg->error != RT_ERR_NOT_FOUND) {
			ccow_fail_io(st->io, -msg->error);
			state_next(st, EV_ERR);
			return;
		}
		if (r->persistent_replies >= msg->ngcount) {
			if (r->persistent_nacks == msg->ngcount) {
				ccow_fail_io(st->io, -ENOENT);
				state_next(st, EV_ERR);
			} else
				state_override(st, ST_TERM);
		}
	}
}

static void
namedput__term(struct state *st)
{
	struct putcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = io->comp;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (c->status == 0 && r->payload && r->payload->nbufs == 1 &&
	    !(io->attributes & RD_ATTR_SERIAL_OP))
		ccow_ucache_put(tc->ucache, &r->chid, &r->payload->bufs[0], 1);
	client_put_common_terminate(st);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, namedput__init, ST_WAIT, NULL },
{ ST_WAIT, EV_DONE, namedput__send, ST_WAIT, NULL }, /* CONT done case */
{ ST_WAIT, EV_CALL, namedput__send, ST_WAIT, NULL },
{ ST_READY, EV_CALL, namedput__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, namedput__send, ST_WAIT, client_putcommon_guard_retry },
{ ST_READY, EV_TIMEOUT, namedput__send, ST_READY, client_putcommon_guard_retry },
{ ST_WAIT, RT_ENCODE_ACK, namedput__encode_ack, ST_TERM, NULL },
{ ST_READY, RT_ENCODE_ACK, namedput__encode_ack, ST_TERM, NULL },

{ ST_WAIT, RT_ONDEMAND_POLICY_ACK, namedput__pin_ack, ST_WAIT, NULL },
{ ST_READY, RT_ONDEMAND_POLICY_ACK, namedput__pin_ack, ST_READY, NULL },

{ ST_WAIT, RT_ACCEPT_NOT_NOW, &client_putcommon_process_busy, ST_WAIT, NULL },
{ ST_READY, RT_ACCEPT_NOT_NOW, &client_putcommon_process_busy, ST_READY, NULL },
{ ST_WAIT, RT_ACCEPT_CONTENT_ALREADY_STORED, NULL, ST_READY,
	&client_putcommon_guard_proposed },
{ ST_READY, RT_ACCEPT_CONTENT_ALREADY_STORED, NULL, ST_READY,
	&client_putcommon_guard_proposed },
{ ST_READY, RT_INIT_TCP_CONNECT, &client_putcommon_tcp_connect, ST_READY, NULL },
/* For TCP only */
{ ST_READY, RT_TCP_CONNECT_SUCCESS, &client_putcommon_rtsend, ST_READY,
	&client_putcommon_guard_tcp_connect },
/* For UDP only */
{ ST_READY, RT_RENDEZVOUS_TRANSFER, &client_putcommon_rtsend, ST_READY,
	&client_putcommon_guard_rt_retry },
{ ST_WAIT, RT_ACCEPT_PROPOSED_RENDEZVOUS, NULL, ST_READY,
	&client_putcommon_guard_proposed },
{ ST_READY, RT_ACCEPT_PROPOSED_RENDEZVOUS, NULL, ST_READY,
	&client_putcommon_guard_proposed },
{ ST_WAIT, RT_NAMED_PAYLOAD_ACK, &client_putcommon_payload_ack, ST_TERM,
	&client_putcommon_guard__ack_consensus },
{ ST_WAIT, RT_ERROR, &client_putcommon_payload_ack, ST_TERM,
	&client_putcommon_guard__ack_consensus },
{ ST_READY, RT_NAMED_PAYLOAD_ACK, &client_putcommon_payload_ack, ST_TERM,
	&client_putcommon_guard__ack_consensus },
{ ST_WAIT, RT_RENDEZVOUS_NACK, &client_putcommon_nack_rcvd, ST_WAIT,
	&client_putcommon_guard_nack_consensus  },
{ ST_READY, RT_RENDEZVOUS_NACK, &client_putcommon_nack_rcvd, ST_READY,
	&client_putcommon_guard_nack_consensus },
{ ST_WAIT, RT_PAYLOAD_RCVD, &client_putcommon_payload_rcvd, ST_READY,
	&client_putcommon_guard_rcvd_consensus },
{ ST_READY, RT_PAYLOAD_RCVD, &client_putcommon_payload_rcvd, ST_READY,
	&client_putcommon_guard_rcvd_consensus },
{ ST_ANY, EV_ANY, &client_putcommon_error, ST_TERM, NULL }
};

int
ccow_namedput_create(ccow_completion_t comp, putcommon_client_callback_t done_cb,
    struct ccow_op *op, struct ccow_io **pio)
{
	int err;
	struct ccow_completion *c = comp;

	log_trace(lg, "comp %p, done_cb %p, op %p(%s), pio %p", comp,
	    done_cb, op, ccow_op2str(op->optype), pio);

	struct putcommon_client_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		log_error(lg, "NAMED PUT request alloc error: -ENOMEM");
		return -ENOMEM;
	}

	r->tc = c->tc;
	r->done_cb = done_cb;
	r->hash_type = HASH_TYPE_DEFAULT;

	err = ccow_create_io(c, op, CCOW_PUT, trans_tbl,
	    sizeof (trans_tbl) / sizeof (*trans_tbl), r, namedput__term, pio);
	if (err) {
		je_free(r);
		return err;
	}
	r->io = *pio;

	if (op->optype != CCOW_CONT) {
		ccow_io_lock(r->io);
		ccow_chain_io(op, r->io);
		ccow_io_unlock(r->io);
	}

	return 0;
}
