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
#include <stdio.h>
#include "reptrans.h"
#include "ccowd-impl.h"
#include "state.h"
#include "putcommon_server.h"
#include "vmm_cache.h"
#include "ccow-impl.h"
#include "serial_op.h"

/* Forward declarations */
static void namedput_srv_exec(void* arg);
static void namedput_srv_done_txfr(void *arg, int status);

static void
namedput_srv__error(struct state *st)
{
	log_trace(lg, "st %p", st);
	putcommon_srv__error(st);
}

/*
 * ACTION: response with NAMED PAYLOAD ACK
 */
static void
namedput_srv__payload_ack(struct state *st)
{
	log_trace(lg, "st %p", st);
	putcommon_srv_payload_ack(st);
}

static void
namedput_srv__rtfree(struct state *st)
{
	log_trace(lg, "st %p", st);
	putcommon_srv_rtfree(st);
}

/*
 * ACTION: response with ACCEPTED RENDEZVOUS
 */
static void
namedput_srv__send_accept(struct state *st)
{
	log_trace(lg, "st %p", st);
	putcommon_srv__send_accept(st);
}

/*
 * ACTION: response with NOT NOW
 */
static void
namedput_srv__busy(struct state *st)
{
	log_trace(lg, "st %p", st);
	putcommon_srv__busy(st);
}

/*
 * ACTION: response with CONTENT ALREADY STORED
 */
static void
namedput_srv__exists(struct state *st)
{
	log_trace(lg, "st %p", st);
	putcommon_srv__exists(st);
}

/*
 * ACTION: response with RD_ATTR_MDONLY_PERSIST
 */
static void
namedput_srv__persist_ack(struct state *st)
{
	log_trace(lg, "st %p", st);
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repmsg_generic *msg = (struct repmsg_generic *)req->msg_pp;
	int err;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	struct repmsg_persistency_ack ack;
	memset(&ack, 0, sizeof (ack));
	// indicate the vdevid of this particular device
	ack.vdevid = dev->vdevid;
	ack.ngcount = req->ngcount;
	ack.error = req->error;
	req->inexec++;
	log_debug(lg, "Dev(%s) sending %s, error %d", dev->name,
		replicast_opcode_str[req->status], ack.error);
	err = replicast_send(dev->robj, NULL, req->status,
	    (struct repmsg_generic *)&ack, msg, NULL, 0, NULL,
	    putcommon_srv_send_done, req, NULL);
	if (err) {
		req->inexec--;
		log_trace(lg, "Failed to send %s", replicast_opcode_str[req->status]);
		state_next(ctx->state, EV_ERR);
		return;
	}
}

static void
namedput_send_err(struct repctx *ctx, int error, int opcode,
		  struct repmsg_generic *msg)
{
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repmsg_error errmsg;
	int err;

	memset(&errmsg, 0, sizeof(errmsg));
	errmsg.num_datagrams = 1;
	errmsg.error = error;
	log_debug(lg, "st %p sending error %d", st, error);
	req->inexec++;
	err = replicast_send(dev->robj, ctx, opcode, (struct repmsg_generic *)&errmsg,
			     msg, NULL, 0, NULL, putcommon_srv_send_done, req, NULL);
	if (err) {
		log_error(lg, "Failed to send error message" "st : %p", st);
		req->inexec--;
	}
}

/* PUT operation complete */
void
namedput_srv_common_done(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_rendezvous_transfer *msg;
	int event;

	log_trace(lg, "st %p inexec %d req->status %d: seqid %d.%d",
			st, req->inexec, req->status,
			ctx->sequence_cnt, ctx->sub_sequence_cnt);
	req->inexec--;
	assert(req->inexec >= 0);

	if (state_check(st, ST_TERM)) {
		putcommon_srv__term(st);
		return;
	}

	msg = (struct repmsg_rendezvous_transfer *)wqe->msg;
	if (req->status <= 0) {
		if (req->serial_err)
			namedput_send_err(ctx, req->error, req->status,
					  (struct repmsg_generic *)msg);
		else {
			event = msg->hdr.attributes & RD_ATTR_UNICAST_TCP ?
					RT_RENDEZVOUS_NACK : EV_ERR;
			log_error(lg, "%p processing error %d next event %d", st,
					req->status, event);
			if (!(st->ev_cur == EV_DONE && event == EV_ERR))
				state_event(ctx->state, event);
		}
		return;
	}

	assert(req->status);
	if (req->status != RT_RENDEZVOUS_TRANSFER) {
		log_debug(lg, "%p event %d state %d", st, req->status, st->cur);
		state_event(ctx->state, req->status);
	}
}

static void namedput_srv_done(void *arg, int status)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;

	log_trace(lg, "arg %p, st %p inexec %d status %d req->status "
		      "%d: seqid %d.%d", arg, st, req->inexec, status,
		      req->status, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	namedput_srv_common_done(st);
}

static void
namedput_srv_serial_done_txfr(void *arg, int status)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;

	log_trace(lg, "%s st %p inexec %d seqid %d.%d", dev->name, st, req->inexec,
			ctx->sequence_cnt, ctx->sub_sequence_cnt);
	assert(msg->hdr.attributes & RD_ATTR_SERIAL_OP);

	if (req->error) {
		req->inexec--;
		state_event(st, EV_DONE);
	} else
		req->sop_state |= NAMEDPUT_SOP_STATE_SCHEDULED;
	return;
}

static void
namedput_srv_serial_exec(void *arg)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;
	int err = 0;

	log_trace(lg, "Scheduling serial operation st: %p dev: %s", st, dev->name);

	assert(msg->hdr.attributes & RD_ATTR_SERIAL_OP);

	/* Get the serial op payload */
	req->payload[0].len = msg->content_length;
	req->payload[0].base = repwqe_payload(wqe);
	rtbuf_t *rb = rtbuf_init_mapped(&req->payload[0], req->nbufs);
	if (!rb) {
		log_error(lg, "NamedPut(%s): st: %p out of memory during "
			      "serial op", dev->name, st);
		rtbuf_destroy(rb);
		req->error = RT_ERR_NO_RESOURCES;
		req->status = RT_ERROR;
		return;
	}

	/* Schedule serial operation */
	uv_buf_t *buf = &rb->bufs[0];
	err = namedput_schedule_serial_op(wqe, buf);
	if (err) {
		log_error(lg, "dev: %s st: %p Cannot schedule serial operation",
				dev->name, st);
		/*
		 * If there is error, namedput_schedule_serial_op() will set
		 * appropriate status and erro code in the request.
		 */
	}

	rtbuf_destroy(rb);
}

static void
namedput_srv_done_txfr(void *arg, int status)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;

	log_trace(lg, "%s st %p inexec %d seqid %d.%d", dev->name, st, req->inexec,
			ctx->sequence_cnt, ctx->sub_sequence_cnt);
	dev->put_disk_qdepth--;
	dev->put_net_rx--;
	namedput_srv_done(arg, status);
}

static void init_vreq(struct verification_request *vreq, uint8_t vtype,
	struct putcommon_srv_req *req)
{
	struct repmsg_named_chunk_put_proposal *msg_pp =
		(struct repmsg_named_chunk_put_proposal *) req->msg_pp;

	uint512_t *vmchid = &msg_pp->content_hash_id;
	struct replicast_object_name *ron = &msg_pp->object_name;
	/*
	 * Verify VM backref
	 */
	struct verification_request v = {
		.vtype = vtype,
		.chid = *vmchid,
		.ttag = TT_VERSION_MANIFEST,
		.htype = HASH_TYPE_DEFAULT,
		.nhid = ron->name_hash_id,
		.uvid_timestamp = 0,
		.generation = ron->generation,
		.width = msg_pp->ec_width,
		.n_parity = msg_pp->ec_parity,
		.domain = msg_pp->ec_domain,
		.algorithm = msg_pp->ec_algorithm,
		.vbr = {
			.generation = ron->generation,
			.uvid_timestamp = req->md.uvid_timestamp,
			.name_hash_id = ron->name_hash_id,
			.ref_type = TT_NAMEINDEX,
			.ref_chid = ron->name_hash_id,
			.ref_hash = HASH_TYPE_DEFAULT,
			.rep_count = req->md.replication_count,
			.attr = VBR_ATTR_VM
		}
	};
	uint16_t mdonly_policy = RT_ONDEMAND_GET(req->md.inline_data_flags);
	if (mdonly_policy != ondemandPolicyLocal)
		v.vbr.attr |= VBR_ATTR_CACHED;
	*vreq = v;
}

static void
put_proposal(struct putcommon_srv_req *req)
{
	struct repmsg_named_chunk_put_proposal *msg_pp =
		(struct repmsg_named_chunk_put_proposal *) req->msg_pp;
	uint512_t *vmchid = &msg_pp->content_hash_id;
	char vmchidstr[UINT512_BYTES * 2 + 1];
	int err;
	struct replicast_object_name *ron = &msg_pp->object_name;

	struct blob_stat bstat;
	err = reptrans_blob_stat(req->dev, TT_VERSION_MANIFEST,
		req->hash_type, vmchid, &bstat);
	if (err == 0) {
		/*
		 * Impossible case, because VMs carring
		 * different content of MD including tie
		 * breaker when sent from two different
		 * tenant contexts.
		 *
		 * I.e. VMs not dedupable...
		 *
		 * Unless, of course, it's an encode request
		 */
		req->error = -EEXIST;
		req->status = RT_ACCEPT_CONTENT_ALREADY_STORED;
		if ((msg_pp->hdr.attributes & RD_ATTR_PARITY_ENCODE) &&
			msg_pp->ec_algorithm != ECA_NONE) {
			uint512_dump(vmchid, vmchidstr, UINT512_BYTES * 2 + 1);
			vmchidstr[31] = 0;
			log_debug(lg, "Dev(%s) EC req VM %s algo %d"
				" width %d parity %d domain %d",
				req->dev->path, vmchidstr, msg_pp->ec_algorithm,
				msg_pp->ec_width, msg_pp->ec_parity,
				msg_pp->ec_domain);
			/*
			 * Request encoding
			 */
			struct verification_request vbreq;
			init_vreq(&vbreq, RT_VERIFY_PARITY |
				RT_VERIFY_NORMAL, req);
			vbreq.generation--;
			vbreq.vbr.generation--;
			err = reptrans_request_encoding(req->dev,
				&vbreq);
			req->error = 0;
			req->status = RT_ENCODE_ACK;
		} else if (msg_pp->hdr.attributes & (RD_ATTR_ONDEMAMD_PIN |
			RD_ATTR_ONDEMAND_UNPIN | RD_ATTR_ONDEMAND_PERSIST)) {
			rtbuf_t* rb = NULL;
			struct vmmetadata md;
			uint512_dump(vmchid, vmchidstr, UINT512_BYTES * 2 + 1);

			if (ccow_daemon->fddelta < 0) {
				req->status = RT_ONDEMAND_POLICY_ACK;
				req->error = RT_ERR_SPLIT;
				log_error(lg, "Dev(%s) VM %s persistency change "
					"isn't allowed in SPLIT %d",
					req->dev->name, vmchidstr,
					ccow_daemon->fddelta);
				return;
			}

			uint16_t mdonly_policy_new = ondemandPolicyLocal;
			if (msg_pp->hdr.attributes & RD_ATTR_ONDEMAMD_PIN)
				mdonly_policy_new = ondemandPolicyPin;
			else if (msg_pp->hdr.attributes & RD_ATTR_ONDEMAND_UNPIN)
				mdonly_policy_new = ondemandPolicyUnpin;
			else if (msg_pp->hdr.attributes & RD_ATTR_ONDEMAND_PERSIST)
				mdonly_policy_new = ondemandPolicyPersist;
			assert(mdonly_policy_new != ondemandPolicyLocal);

			err =reptrans_get_blob(req->dev, TT_VERSION_MANIFEST,
				HASH_TYPE_DEFAULT, vmchid, &rb);
			if (err || !rb || !rb->nbufs) {
				req->status = RT_ONDEMAND_POLICY_ACK;
				req->error = RT_ERR_NOT_FOUND;
				log_error(lg, "Dev(%s) VM %s not found",
					req->dev->name, vmchidstr);
				return;
			}

			err = replicast_get_metadata(rb, &md);
			if (err) {
				log_error(lg, "Dev(%s) VM %s get metadata error %d",
					req->dev->name, vmchidstr, err);
				req->status = RT_ONDEMAND_POLICY_ACK;
				req->error = RT_ERR_EIO;
				rtbuf_destroy(rb);
				return;
			}
			uint16_t mdonly_policy_prev = RT_ONDEMAND_GET(md.inline_data_flags);
			uint16_t ondemand_type = RT_ONDEMAND_GET_TYPE(md.inline_data_flags);
			if (mdonly_policy_prev == ondemandPolicyLocal) {
				req->status = RT_ONDEMAND_POLICY_ACK;
				req->error = RT_ERR_NONCACHEABLE;
				log_error(lg, "Dev(%s) VM %s persistency change isn't "
					"allowed for a non-cacheable object",
					vmchidstr, req->dev->name);
				rtbuf_destroy(rb);
				return;
			}
			if (mdonly_policy_prev == ondemandPolicyPersist &&
				(mdonly_policy_new == ondemandPolicyPin ||
					mdonly_policy_new == ondemandPolicyUnpin)) {
				req->status = RT_ONDEMAND_POLICY_ACK;
				req->error = RT_ERR_NONCACHEABLE;
				log_error(lg, "Dev(%s) VM %s ondemand policy change is NOT "
					"allowed for a persistent object",
					vmchidstr, req->dev->name);
				rtbuf_destroy(rb);
				return;
			}
			verification_request_t vbreq = {
				.chid = *vmchid,
				.nhid = md.nhid,
				.target_vdevid = uint128_null,
				.uvid_timestamp = md.uvid_timestamp,
				.generation = md.txid_generation,
				.vtype = RT_VERIFY_NORMAL,
				.ttag = TT_VERSION_MANIFEST,
				.htype = HASH_TYPE_DEFAULT,
				.vbr = {
					.generation = md.txid_generation,
					.uvid_timestamp = md.uvid_timestamp,
					.name_hash_id =  md.nhid,
					.ref_type = TT_NAMEINDEX,
					.ref_chid =  md.nhid,
					.ref_hash = HASH_TYPE_DEFAULT,
					.rep_count = md.replication_count,
					.attr = VBR_ATTR_VM | VBR_ATTR_CACHED
				}
			};
			rtbuf_t* vm_new = NULL;
			uint16_t value = RT_ONDEMAND_VALUE(ondemand_type, mdonly_policy_new);
			err = ccow_edit_md_overrides(rb, RT_SYSKEY_ONDEMAND, value, &vm_new);
			rtbuf_destroy(rb);
			if (err || !vm_new) {
				req->status = RT_ONDEMAND_POLICY_ACK;
				req->error = RT_ERR_EIO;
				log_error(lg, "Dev(%s) VM %s override error %d",
					req->dev->name, vmchidstr, err);
				return;
			}
			err = reptrans_put_blob_with_attr_opts(req->dev,
				TT_VERSION_MANIFEST,
				HASH_TYPE_DEFAULT, vm_new, vmchid, 0,
				reptrans_get_timestamp(req->dev),
				REPDEV_PUT_OPT_OVERWRITE);
			if (err) {
				log_error(lg, "Dev(%s) couldn't store pinned VM %s",
					req->dev->name, vmchidstr);
				req->status = RT_ONDEMAND_POLICY_ACK;
				req->error = RT_ERR_EIO;
			} else {
				uint32_t n = 0;
				if (mdonly_policy_new == ondemandPolicyUnpin && ondemand_type == RT_ONDEMAND_TYPE_MDONLY)
					VTYPE_SET_ONDEMAND(vbreq.vtype, VTYPE_ONDEMAND_MDONLY);
				else if (mdonly_policy_new == ondemandPolicyUnpin && ondemand_type == RT_ONDEMAND_TYPE_VMONLY)
					VTYPE_SET_ONDEMAND(vbreq.vtype, VTYPE_ONDEMAND_VMONLY);
				else
					VTYPE_SET_ONDEMAND(vbreq.vtype, VTYPE_ONDEMAND_PIN);
				reptrans_verify_one_request(req->dev, &vbreq, &n, 0);
				req->status = RT_ONDEMAND_POLICY_ACK;
				req->error = 0;
				log_debug(lg, "Dev(%s) VM %s %s", req->dev->name,
					vmchidstr, mdonly_policy_new == ondemandPolicyUnpin ? "unpin":
						mdonly_policy_new == ondemandPolicyPin ? "pin": "persist");
			}
			rtbuf_destroy(vm_new);
		}
	} else if (msg_pp->hdr.attributes & RD_ATTR_PARITY_ENCODE) {
		req->error = -ENOENT;
		req->status = RT_ENCODE_ACK;
	} else if (msg_pp->hdr.attributes & (RD_ATTR_ONDEMAMD_PIN |
		RD_ATTR_ONDEMAND_UNPIN | RD_ATTR_ONDEMAND_PERSIST)) {
		req->error = RT_ERR_NOT_FOUND;
		req->status = RT_ONDEMAND_POLICY_ACK;
	} else {
		req->error = 0;
		req->status = RT_ACCEPT_PROPOSED_RENDEZVOUS;
	}
}

static void
namedput_srv_exec(void *arg)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	verification_type_t vtype = RT_VERIFY_NORMAL;

	struct repmsg_named_chunk_put_proposal *msg_pp =
		(struct repmsg_named_chunk_put_proposal *) req->msg_pp;

	uint512_t *vmchid = &msg_pp->content_hash_id;

	int err;
	struct replicast_object_name *ron = &msg_pp->object_name;

	log_trace(lg, "Exec(%s): arg %p: seqid %d.%d", dev->name, arg,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (msg_pp->immediate_content_length == 0) {
		if (wqe->msg->hdr.transaction_id.opcode ==
		    RT_NAMED_CHUNK_PUT_PROPOSAL) {
			put_proposal(req);
			return;
		}
	} else {
		/*
		 * Immediate content case.
		 */
		assert(msg_pp->immediate_content_length == msg_pp->content_length);
		/*
		 * Put Payload CHUNK blob. If operation fails at any further
		 * moment, blob will be deleted immediately in terms of to
		 * avoid creation of orphans.
		 *
		 * Note: immediate payload cannot be larger then IP payload,
		 * so it is always going to fit into one UDP datagram.
		 */
		req->payload[0].len = msg_pp->content_length;
		req->payload[0].base = repwqe_payload(wqe);
		req->nbufs = 1;
	}

	rtbuf_t *rb = NULL;
	if (req->nbufs > 1) {
		uv_buf_t one_payload;
		err = rtbuf_serialize_bufs(&req->payload[0], req->nbufs, &one_payload);
		if (!err)
			rb = rtbuf_init(&one_payload, 1);
	} else
		rb = rtbuf_init_mapped(&req->payload[0], req->nbufs);
	if (!rb) {
		log_error(lg, "NamedPut(%s): out of memory while named put blob",
		    dev->name);
		req->error = RT_ERR_NO_RESOURCES;
		req->status = RT_ERROR;
		return;
	}


	/*
	 * All content was transfered as unsolicited payload.
	 * Finalize named chunk right away... we are done.
	 *
	 * What this entales:
	 *
	 * 1) Write Version Manifest payload (with length). Payload contains
	 * key-value style metadata and reference list with optional inlined
	 * payload. But this is transparent to us, so we simply put the
	 * entire content as is.
	 *
	 * 2) Update Version List payload. Payload contains object metadata and
	 * new version entry (NUVID + Generation -> CHID) added at the top of
	 * an array
	 *
	 * 3) After (1) and (2) completed, write Name Index with value which
	 * consists of CHID of VL and CHID of current Version Manifest
	 */

	/*
	 * Check for OBJECT_DELETED metadata flag and apply appropriate
	 * function.
	 */
	err = replicast_get_metadata(rb, &req->md);
	if (err) {
		log_error(lg, "NamedPut(%s): error unpacking md: %d",
		    dev->name, err);
		rtbuf_destroy(rb);
		req->status = RT_ACCEPT_NOT_NOW;
		return;
	}

	// Get object metadata
	char *etag = NULL;
	char *content_type = NULL;
	char *owner = NULL;
	char *srcip = NULL;
	uint64_t multipart_size = 0;
	err = replicast_object_metadata(rb, &etag, &content_type, &multipart_size, &owner, &srcip);
	if (err) {
		log_error(lg, "NamedPut(%s): error unpacking objmd: %d",
		    dev->name, err);
		rtbuf_destroy(rb);
		req->status = RT_ACCEPT_NOT_NOW;
		return;
	}

	if (req->md.object_deleted == RT_DELETED_EXPUNGED) {
		/*
		 * Expunge: send a purge request for ALL versions
		 */
		err = ngrequest_purge(dev, req->hash_type, &ron->name_hash_id,
			~0UL, 0, 0, 0);
		if (err) {
			log_error(lg, "NamedPut(%s): object purge error: %d",
			    dev->name, err);
			rtbuf_destroy(rb);
			req->error = RT_ERR_EIO;
			req->status = RT_ACCEPT_NOT_NOW;
			return;
		}

		/*
		 * Write the transaction log
		 */
		err = reptrans_put_trlog(dev, &req->md, vmchid, msg_pp->hdr.attributes,
				etag, content_type, multipart_size, owner, srcip);
		if (etag) {
			je_free(etag);
			etag = NULL;
		}
		if (content_type) {
			je_free(content_type);
			content_type = NULL;
		}
		if (owner) {
			je_free(owner);
			owner = NULL;
		}
		if (srcip) {
			je_free(srcip);
			srcip = NULL;
		}
		if (err) {
			log_error(lg, "NamedPut(%s), Expunge error writing transaction log. "
				"%d", dev->name, err);
			rtbuf_destroy(rb);
			req->error = RT_ERR_EIO;
			req->status = RT_ACCEPT_NOT_NOW;
			return;
		}

		/* At this point EXPUNGE scheduled and later regular space
		 * reclaiming procedure will delete remains of the object. */
		goto _ack_exit;
	}

	if (req->md.object_deleted == RT_DELETED_EXPUNGED_VERSION) {
		/*
		 * Expunge one version:
		 */
		log_trace(lg, "Expunge version ngrequest_purge (%s) generation: %" PRIu64 " uvid_timestamp: %lu\n",
				dev->name, ron->generation, ron->uvid_timestamp);

		err = ngrequest_purge(dev, req->hash_type, &ron->name_hash_id,
		    ron->generation, ron->generation, ron->uvid_timestamp, 0);
		if (err) {
			log_error(lg, "NamedPut(%s): error deleting version: %ld error: %d",
			    dev->name, ron->generation, err);
			rtbuf_destroy(rb);
			req->error = RT_ERR_EIO;
			req->status = RT_ACCEPT_NOT_NOW;
			return;
		}


		/*
		 * Write the transaction log
		 */
		vmchid->u.u.u = ron->generation;
		vmchid->u.u.l = ron->uvid_timestamp;
		err = reptrans_put_trlog(dev, &req->md, vmchid, msg_pp->hdr.attributes,
				etag, content_type, multipart_size, owner, srcip);
		if (etag) {
			je_free(etag);
			etag = NULL;
		}
		if (content_type) {
			je_free(content_type);
			content_type = NULL;
		}
		if (owner) {
			je_free(owner);
			owner = NULL;
		}
		if (srcip) {
			je_free(srcip);
			srcip = NULL;
		}
		if (err) {
			log_error(lg, "NamedPut(%s), Expunge version error writing transaction log. "
				"%d", dev->name, err);
			rtbuf_destroy(rb);
			req->error = RT_ERR_EIO;
			req->status = RT_ACCEPT_NOT_NOW;
			return;
		}

		goto _ack_exit;
	}

	if (req->md.sync_put && req->min &&
		(req->md.replication_count - req->md.sync_put) > 0)
		vtype |= RT_VERIFY_REPLICATE;

	if (dev->verify_chid) {
		uint512_t calculated_vmchid;
		err = rtbuf_hash(rb, req->hash_type, &calculated_vmchid);

		if (!err) {
			err = uint512_cmp(vmchid, &calculated_vmchid);
		}

		if (err) {
			log_error(lg,
			    "NamedPut(%s): payload verification error detected "
			    "seqid %d.%d", dev->name, ctx->sequence_cnt,
			    ctx->sub_sequence_cnt);
			uint512_logdump(lg, "content_hash_id", vmchid);
			uint512_logdump(lg, "calculated_vmchid", &calculated_vmchid);
			rtbuf_destroy(rb);
			req->status = RT_ACCEPT_NOT_NOW;
			return;
		}
	}

	if (!ron->generation) {
		log_error(lg, "NamedPut(%s): protocol error, missing generation",
		    dev->name);
		rtbuf_destroy(rb);
		req->error = RT_ERR_EIO;
		req->status = RT_ACCEPT_NOT_NOW;
		return;
	}

	/*
	 * Write VM with current timestamp.
	 * This will automatically place a speculative hold on it.
	 */

	err = reptrans_put_blob_with_attr(dev, TT_VERSION_MANIFEST,
	    req->hash_type, rb, vmchid, 0, reptrans_get_timestamp(dev));
	if (err) {
		log_error(lg, "NamedPut(%s), Error adding VM blob: %d",
		    dev->name, err);
		rtbuf_destroy(rb);
		req->error = RT_ERR_EIO;
		req->status = RT_ACCEPT_NOT_NOW;
		return;
	}

	if (unlikely(lg->level <= LOG_LEVEL_DEBUG)) {
		uint16_t n_groups = 0;
		SERVER_FLEXHASH_SAFE_CALL(n_groups = flexhash_numrows(ccow_daemon->flexhash), FH_LOCK_READ);
		uint16_t ng = HASHCALC(&msg_pp->content_hash_id, n_groups - 1);
		char chidstr[UINT512_BYTES * 2 + 1];
		uint512_dump(vmchid, chidstr, sizeof (chidstr));
		chidstr[16] = 0;
		log_debug(lg, "Dev(%s): named put %s %s %s ng %u", dev->name,
		    type_tag_name[TT_VERSION_MANIFEST],
		    hash_type_name[req->hash_type], chidstr, ng);

		log_debug(lg, "generation %" PRId64 " UVID %" PRId64,
		    ron->generation, ron->uvid_timestamp);
	}

	uint512_logdump(lg, "NAMED-PUT NHID", &ron->name_hash_id);
	uint512_logdump(lg, "VERSION-MANIFEST", vmchid);


	/*
	 * Verify VM backref
	 */
	uint512_t vbreq_key;
	struct verification_request vbreq;
	init_vreq(&vbreq, vtype, req);
	if (req->md.object_deleted &&
	    (req->md.object_deleted == RT_DELETED_LOGICALLY ||
	     req->md.object_deleted == RT_DELETED_VERSION)) {
		/*
		 * In case of any delete VM comes without ref entries,
		 * therefore there is no need for further verification.
		 */
		err = reptrans_put_backref(dev, vmchid, HASH_TYPE_DEFAULT,
		    &vbreq.vbr);
		if (err) {
			rtbuf_destroy(rb);
			reptrans_delete_blob(dev, TT_VERSION_MANIFEST,
			    req->hash_type, vmchid);
			char vmchidstr[UINT512_BYTES * 2 + 1];
			uint512_dump(vmchid, vmchidstr, UINT512_BYTES * 2 + 1);
			if (err != -EACCES)
				log_error(lg, "Put(%s): "
					"cannot put verified back reference %s",
					dev->name, vmchidstr);
			else
				log_warn(lg, "Put(%s): "
					"cannot put verified back reference %s,"
					" disk might be full", dev->name, vmchidstr);
			req->error = RT_ERR_EIO;
			req->status = RT_ACCEPT_NOT_NOW;
			return;
		}
	} else {
		uint16_t mdonly_policy = RT_ONDEMAND_GET(req->md.inline_data_flags);
		if (mdonly_policy != ondemandPolicyLocal) {
			/* cacheable objects have to bypass quarantine */
			vbreq.vtype |= RT_VERIFY_NO_QUARANTINE;
		} else if (dev->bg_config->version_quarantine_timeout &&
			req->md.number_of_versions <= 1) {
			/* The "verification quarantine" technique allows to reduce
			 * number of verifications in case of intensive version overwrite.
			 * The "stable version" allows us to avoid data loss when the
			 * "verification quarantine" is used. A stable version has to be created
			 * if current NHID hasn't been verified for a long while
			 */
			uint64_t sv_gen = 0, sv_ts, cur_ts = get_timestamp_us();
			int err = reptrans_stable_version_get(dev, &ron->name_hash_id,
				&sv_gen, &sv_ts);
			if (err && err == -ENOENT) {
				/* Stable version entry isn't created yet, adding */
				err = reptrans_stable_version_set(dev, &ron->name_hash_id, 0, cur_ts);
				if (err)
					log_error(lg, "Dev(%s) stable version put error %d",
						dev->name, err);
			} else if (err) {
				log_error(lg, "Dev(%s) stable version get error %d",
					dev->name, err);
			} else if ((cur_ts - sv_ts) >
				(uint64_t)dev->bg_config->speculative_backref_timeout_min / 4) {
				vbreq.vtype |= RT_VERIFY_NO_QUARANTINE;
				err = reptrans_stable_version_set(dev, &ron->name_hash_id,
					ron->generation, cur_ts);
				if (err)
					log_error(lg, "Dev(%s) stable version set error %d",
						dev->name, err);
				log_info(lg, "Dev(%s) stable version NHID %lX %s/%s/%s/%s"
					" gen %lu has been pushed to the verification "
					" queue", dev->name, ron->name_hash_id.u.u.u,
					req->md.cid, req->md.tid, req->md.bid, req->md.oid,
					ron->generation);
			}
		} else if(!(msg_pp->hdr.attributes & RD_ATTR_EPHEMERAL_VERSION)
			|| ron->generation == 1)
			vbreq.vtype |= RT_VERIFY_NO_QUARANTINE;
		else /* Ephemeral version, skip verification */
			goto _next;

		/* Force VBR top-down propagation for a clonned object */
		if (msg_pp->hdr.attributes & RD_ATTR_ONDEMAND_CLONE)
			VTYPE_SET_ONDEMAND(vbreq.vtype, VTYPE_ONDEMAND_PIN);
		/*
		 * Enqueue verification request. Notice that purge is processed
		 * separately.
		 */
		err = reptrans_request_verification(dev, &vbreq, &vbreq_key);
		if (err) {
			if (err != -EACCES)
				log_error(lg, "Dev(%s): couldn't add TT_VERSION_MANIFEST"
					" to ver. queue: %d", dev->name, err);
			else
				log_warn(lg, "Dev(%s): couldn't add TT_VERSION_MANIFEST"
					" to ver. queue: %d", dev->name, err);

			reptrans_delete_blob(dev, TT_VERSION_MANIFEST,
			    req->hash_type, vmchid);
			req->error = RT_ERR_EIO;
			req->status = RT_ACCEPT_NOT_NOW;
			return;
		}
		/* Check and enqueue VM for EC */
		err = reptrans_enqueue_vm_encoding(dev, vmchid, &req->md);
		if (err) {
			log_error(lg, "Error requesting object encoding");
		}
	}

_next:
	/*
	 * Finally add new version
	 */
	err = reptrans_put_version(dev, &req->md, vmchid, (uint32_t) rtbuf_len(rb));
	if (err) {
		log_error(lg, "NamedPut(%s), Error adding new version: %d",
		    dev->name, err);
		rtbuf_destroy(rb);
		reptrans_delete_blob(dev, TT_VERSION_MANIFEST, req->hash_type,
		    vmchid);
		if (!req->md.object_deleted) {
			reptrans_delete_blob(dev, TT_VERIFICATION_QUEUE,
			    HASH_TYPE_DEFAULT, &vbreq_key);
		}
		req->error = RT_ERR_EIO;
		req->status = RT_ACCEPT_NOT_NOW;
		return;
	}
	if (lg->level <= LOG_LEVEL_DEBUG) {
		char nhidstr[UINT512_BYTES*2+1];
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(vmchid, chidstr,UINT512_BYTES*2+1);
		uint512_dump(&req->md.nhid, nhidstr,UINT512_BYTES*2+1);
		log_debug(lg, "Dev(%s) aded a new version %s gen %lu, VM %s",
			dev->name, nhidstr, req->md.txid_generation, chidstr);
	}

	/*
	 * Write the transaction log
	 */
	if (!(msg_pp->hdr.attributes & RD_ATTR_NO_TRLOG)) {
		err = reptrans_put_trlog(dev, &req->md, vmchid,
		    msg_pp->hdr.attributes, etag, content_type, multipart_size, owner, srcip);
		if (etag) {
			je_free(etag);
			etag = NULL;
		}
		if (content_type) {
			je_free(content_type);
			content_type = NULL;
		}
		if (owner) {
			je_free(owner);
			owner = NULL;
		}
		if (srcip) {
			je_free(srcip);
			srcip = NULL;
		}
		if (err) {
			log_error(lg, "NamedPut(%s), Error writing transaction log. "
			    "%d", dev->name, err);
			reptrans_delete_version(dev, &req->md, vmchid, (uint32_t) rtbuf_len(rb));
			rtbuf_destroy(rb);
			reptrans_delete_blob(dev, TT_VERSION_MANIFEST, req->hash_type,
				vmchid);
			if (!req->md.object_deleted) {
				reptrans_delete_blob(dev, TT_VERIFICATION_QUEUE,
					HASH_TYPE_DEFAULT, &vbreq_key);
			}
			req->error = RT_ERR_EIO;
			req->status = RT_ACCEPT_NOT_NOW;
			return;
		}

		/*
		 * Slow down NamedPut if TRLOG contains too many entries. Throttle...
		 */
		int slowdown_factor =
			dev->stats.ttag_entries[TT_TRANSACTION_LOG] / TRLOG_TSOBJ_MAX_ENTRIES;
		if (slowdown_factor > 20) slowdown_factor = 20;
		if (slowdown_factor > 1) {
			log_debug(lg, "TRLOG throttling for %dms", slowdown_factor);
			usleep(slowdown_factor * 1000);
		}

	}

	/*
	 * Now we need to schedule replication if this is a delegated put case
	 */
	if (vtype & RT_VERIFY_REPLICATE) {
		err = enqueue_replication__dpc(dev, TT_VERSION_MANIFEST,
		    HASH_TYPE_DEFAULT, vmchid, &ron->name_hash_id,
		    req->md.replication_count);
		if (err) {
			/* Not fatal, BG replication will eventually fix this */
			log_warn(lg, "Dev(%s): cannot enqueue replication "
			    "request, err %d", dev->name, err);
			err = 0;
		}
	}

_ack_exit:
	/*
	 * If there is a limit on the number of back versions,
	 * delete excessive ones.
	 */

	if (!(msg_pp->hdr.attributes & RD_ATTR_PARITY_ENCODE) &&
		!(req->md.object_deleted == RT_DELETED_EXPUNGED_VERSION) &&
	    (req->md.number_of_versions > 0) &&
	    (ron->generation > req->md.number_of_versions)) {
		int is_trlog_obj = (req->md.tid_size >= strlen(TRLOG_TID_PREFIX) &&
		    strncmp(req->md.tid, TRLOG_TID_PREFIX, strlen(TRLOG_TID_PREFIX)) == 0);
		err = ngrequest_purge(dev, req->hash_type, &req->md.nhid,
		    ron->generation - req->md.number_of_versions, 0, 0, is_trlog_obj);
		if (err) {
			/* Not fatal, BG verification will eventually fix this */
			log_warn(lg, "Dev(%s): cannot purge request, err %d",
			    dev->name, err);
			err = 0;
		}
	}

	rtbuf_destroy(rb);

	/*
	 * Immediate content can be ack'ed immediately
	 */
	req->status = RT_NAMED_PAYLOAD_ACK;
	assert(req->inexec);
}

static void
namedput_srv__transfer(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;

	log_trace(lg, "st %p seqid %d.%d", st,
				ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (msg->hdr.attributes & RD_ATTR_SERIAL_OP) {
		putcommon_srv_transfer(st, namedput_srv_serial_exec,
					   namedput_srv_serial_done_txfr);
	} else
		putcommon_srv_transfer(st, namedput_srv_exec,
					   namedput_srv_done_txfr);
}


/*
 * ACTION: process RT_NAMED_CHUNK_PUT_PROPOSAL request
 */
static void
namedput_srv__proposal(struct state *st)
{

	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repdev *dev = req->dev;
	struct repmsg_named_chunk_put_proposal *msg =
		(struct repmsg_named_chunk_put_proposal *) wqe->msg;
	int err;
	char buf[256];

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	uint512_t *ngroup;
	struct replicast_object_name *ron = &msg->object_name;
	ngroup = &ron->name_hash_id;

	if (msg->hdr.attributes & RD_ATTR_SERIAL_OP) {
		if (uint128_cmp(&msg->hdr.orig_id.source_addr, &uint128_null) != 0) {
			log_debug(lg, "SOP target for chid: %s", hash_id_to_buffer(ngroup, buf));
			int shard = (int) msg->hdr.orig_id.source_port;
			log_debug(lg, "SOP target VDEV %s Shard index: %d",
					uint128_to_buffer(&msg->hdr.orig_id.source_addr, buf),
					shard);

			if (uint128_cmp(&dev->vdevid, &msg->hdr.orig_id.source_addr) != 0) {
				state_next(st, EV_ERR);
				return;
			}

			// Check for flexhash changes
			uint128_t target_vdev;
			ccowd_fhready_lock(FH_LOCK_READ);
			uint16_t row = HASHROWID(ngroup, SERVER_FLEXHASH);
			err = flexhash_find_master(SERVER_FLEXHASH, ngroup, shard, &target_vdev);
			ccowd_fhready_unlock(FH_LOCK_READ);
			if (err != 0) {
				log_error(lg, "SOP target VDEV %s Shard index: %u not found",
						uint128_to_buffer(&msg->hdr.orig_id.source_addr, buf),
						msg->hdr.orig_id.source_port);
				state_next(st, EV_ERR);
				return;
			}
			log_debug(lg, "SOP target check VDEV %s in row: %u", uint128_to_buffer(&target_vdev, buf), row);
			if (uint128_cmp(&target_vdev, &msg->hdr.orig_id.source_addr) != 0) {
				log_warn(lg, "SOP target vdev changed to %s", uint128_to_buffer(&target_vdev, buf));
				state_next(st, EV_ERR);
				return;
			}
			log_debug(lg, "SOP target found VDEV %s", uint128_to_buffer(&target_vdev, buf));
		}
	}
	/*
	 * Do not participate in NamedPut proposals if we readonly
	 */
	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE ||
		status == REPDEV_STATUS_INIT ||
		status == REPDEV_STATUS_READONLY_FORCED ||
		status == REPDEV_STATUS_READONLY_FAULT ||
		((status == REPDEV_STATUS_READONLY_DATA ||
			status == REPDEV_STATUS_READONLY_ROWEVAC ||
			status == REPDEV_STATUS_READONLY_FULL) &&
			!(msg->hdr.attributes & RD_ATTR_LOGICAL_DELETE))) {
		log_warn(lg, "Dev(%s): state %s don't participate", dev->name,
			repdev_status_name[dev->status]);
		state_next(st, EV_ERR);
		return;
	}

	if (req->inexec) {
		log_debug(lg, "Cannot execute PUT PROPOSAL while in exec");
		state_next(st, EV_ERR);
		return;
	}

	if (msg->immediate_content_length == 0) {
		req->reqtype = PUT_REQ_TYPE_NAMED_RT;
	} else {
		req->reqtype = PUT_REQ_TYPE_NAMED;
	}

	ccowd_fhready_lock(FH_LOCK_READ);
	int found = flexhash_is_rowmember(SERVER_FLEXHASH,
	    &dev->vdevid, ngroup);
	if (!found) {
		fhrow_t row = HASHROWID(ngroup, ccow_daemon->flexhash);
		ccowd_fhready_unlock(FH_LOCK_READ);
		log_debug(lg, "Not a member of row: %d. Ignoring", row);
		state_next(st, EV_ERR);
		return;

	}

	fhrow_t row;
	int ngcount;
	err = flexhash_get_ngcount(SERVER_FLEXHASH, ngroup, &row, &ngcount);
	ccowd_fhready_unlock(FH_LOCK_READ);
	if (err < 0) {
		/* no need to fail PP for normal I/O */
		if (err != -EAGAIN) {
			log_error(lg, "Put(%s): row (%d) error (%d): %s",
			    dev->name, row, err, strerror(err));
			state_next(st, EV_ERR);
			return;
		}
	}
	if (ngcount < 0)
		req->ngcount = 0;
	else
		req->ngcount = ngcount;
	if (!ngcount) {
		err = -ENODEV;
		log_warn(lg, "Put(%s): row (%d) ngcount (%d) error (%d)",
		    dev->name, row, req->ngcount, err);
		state_next(st, EV_ERR);
		return;
	}

#if 0
	/*
	 * check if background job for row data transfer is in-progress
	 * if so , return a NOT_NOW for a put, so we are read-only
	 */
	int rrbal = flexhash_row_rebalance(&dev->rowusage_list, row, ngcount);
	if (rrbal == 0) {
		log_debug(lg,"Put(%s): row (%d) in read-only", dev->name, row);
		req->status = RT_ACCEPT_NOT_NOW;
		state_next(st, RT_ACCEPT_NOT_NOW);
		return;
	}
#endif

	req->msg_pp = (struct repmsg_named_chunk_put_proposal *) wqe->msg;
	req->hash_type = msg->hdr.hash_type;
	req->dev = dev;
	req->pp_rcvd_time = get_timestamp_us();
	req->req_len = msg->content_length;
	req->inexec++;
	log_debug(lg, "Dev(%s): proposal: scheduled namedput_srv_exec",
	    dev->name);
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_MID, namedput_srv_exec,
		namedput_srv_done, wqe);
}

/*
 * ACTION: process RT_RENDEZVOUS_ACK request
 */
static void
namedput_srv__rendezvous_ack(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_generic *msg = wqe->msg;
	struct repdev *dev = req->dev;

	/* FIXME: implement... need to commit rtbufs to KVDEVs here */
	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);
	putcommon_srv_rt_ack(st);

	/*
	 * remove NHID from VMM hash table
	 */
	struct repmsg_named_chunk_put_proposal *msg_pp =
		(struct repmsg_named_chunk_put_proposal *) req->msg_pp;
	struct replicast_object_name *ron = &msg_pp->object_name;
	ccow_vmmcache_remove(dev->vmm_ht, &ron->name_hash_id);
}

static void
namedput_srv__term(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);
	putcommon_srv__term(st);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_NAMED_CHUNK_PUT_PROPOSAL, &namedput_srv__proposal, ST_WAIT,
	NULL },
{ ST_WAIT, RT_ACCEPT_PROPOSED_RENDEZVOUS, &namedput_srv__send_accept, ST_READY,
	NULL},
{ ST_READY, RT_RENDEZVOUS_ACK, &namedput_srv__rendezvous_ack, ST_READY, NULL},
{ ST_READY, RT_RENDEZVOUS_TRANSFER, &namedput_srv__transfer, ST_READY, NULL},
{ ST_READY, EV_TIMEOUT, &namedput_srv__rtfree, ST_TERM, NULL},
{ ST_READY, RT_RENDEZVOUS_NACK, &namedput_srv__rtfree, ST_TERM, NULL},
{ ST_WAIT, RT_ACCEPT_CONTENT_ALREADY_STORED, &namedput_srv__exists, ST_TERM,
	NULL},
{ ST_WAIT, RT_ENCODE_ACK, &namedput_srv__exists, ST_TERM, NULL},
{ ST_WAIT, RT_ONDEMAND_POLICY_ACK, &namedput_srv__persist_ack, ST_TERM, NULL},
{ ST_READY, RT_ACCEPT_NOT_NOW, &namedput_srv__busy, ST_TERM, NULL },
{ ST_WAIT, RT_ACCEPT_NOT_NOW, &namedput_srv__busy, ST_TERM, NULL },
{ ST_WAIT, RT_NAMED_PAYLOAD_ACK, &namedput_srv__payload_ack, ST_TERM, NULL},
{ ST_READY, RT_NAMED_PAYLOAD_ACK, &namedput_srv__payload_ack, ST_TERM, NULL},
{ ST_READY, EV_SEND, NULL, ST_TERM, NULL},
{ ST_READY, EV_DONE, &namedput_srv_common_done, ST_TERM, NULL},
{ ST_ANY, EV_ANY, &namedput_srv__error, ST_TERM, NULL }
};

int
namedput_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state)
{
	int err;
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct putcommon_srv_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	req->pp_timer_req = je_malloc(sizeof (*req->pp_timer_req));
	if (!req->pp_timer_req) {
		je_free(req);
		return -ENOMEM;
	}
	req->pp_timer_req->data = NULL;
	uv_timer_init(dev->loop, req->pp_timer_req);

	req->rtfree_timer_req = je_malloc(sizeof (*req->rtfree_timer_req));
	if (!req->rtfree_timer_req) {
		je_free(req->pp_timer_req);
		je_free(req);
		return -ENOMEM;
	}
	req->rtfree_timer_req->data = NULL;

	req->rtfree_timer_fd = uv_hpt_timer_init(req->dev->loop,
	    req->rtfree_timer_req);
	if (req->rtfree_timer_fd < 0) {
		err = req->rtfree_timer_fd;
		je_free(req->pp_timer_req);
		je_free(req);
		log_error(lg, "PUT hpt rtfree init error: %d", err);
		return err;
	}

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = namedput_srv__term;
	ctx->stat_cnt = &robj->stats.namedput_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	reptrans_io_avg(dev);
	return 0;
}
