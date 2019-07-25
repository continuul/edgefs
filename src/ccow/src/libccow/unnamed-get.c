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
#include <net/if.h>

#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "getcommon_client.h"
#include "probes.h"
#include "lfq.h"
#include "ccow-dynamic-fetch.h"

/*
 * These events are used to process dynamic fetch response
 */
enum dfetch_decode_event {
	RT_DFETCH_DONE = 1,
	RT_DFETCH_ERROR
};

#undef THREADED_CM_VERIFY

volatile unsigned long gw_cache_throttle = 0;

static inline int
unnamgedget_is_btn(struct ccow_io *io)
{
	struct ccow_op *op = io->op;
	struct ccow_completion *c = op->comp;

	return (memcmp_safe(op->metadata.chunkmap_type, strlen(op->metadata.chunkmap_type),
		    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX,
		    strlen(RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX)) == 0 ||
		memcmp_safe(c->chunkmap_type, strlen(c->chunkmap_type),
			RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX,
			strlen(RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX)) == 0);
}

/*
 * ACTION: unblock caller and report error
 */
static void
unnamedget__error(struct state *st) {
	struct getcommon_client_req *r = st->data;
	struct ccow_io *io = (struct ccow_io *)st;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
			ctx->sub_sequence_cnt);
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	if (r->isgw_fsm_hanlde) {
		ccow_isgw_dynamic_fetch_cancel(r->isgw_fsm_hanlde);
		r->isgw_fsm_hanlde = NULL;
	}
	/*
	 * If compression thread still running, and wait for it to finish
	 */
	if (r->hashuncomp_inexec) {
		state_override(st, ST_BUSY);
		return;
	}

	// FIXME: any error will cause drop of context for now...
	//	  need to implement concensus
}

static void
unnamedget_hashuncomp_done(void *arg, int status)
{
	int ev = EV_DONE;
	struct state *st = arg;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "arg %p, status %d seqid %d.%d inexec %d", arg, status,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt, r->hashuncomp_inexec);

	int threaded = r->hashuncomp_threaded;

	if (threaded)
		r->hashuncomp_inexec--;

	if (status) {

		/* if rb is UCACHE'd but we still hit error here, log error and
		 * try to fetch chunk off network */
		if (r->rb_cached != 0) {
			log_error(lg, "UCACHE: element entry is dirty, re-fetching");
			assert(r->nbufs == 1);
			je_free(r->payload[0].base);
			r->rb_cached = 0;
		}

		/* Payload corruption detected.
		 *
		 * Reset dgram_idx as we do not know which one is broken.
		 * This will trigger full re-transmit */
		r->dgram_idx = uint256_null;

		/*
		 * Exclude this vdev and retry. We re-using timeout logic,
		 * which essentially it is.. we have to re-negotiate I/O yet
		 * exclude vdev which did not transfer data to us correctly.
		 */
		if (r->excluded_count < REPLICAST_PROPOSALS_MAX) {
			int excluded = -1;
			for (int k = 0; k < r->excluded_count; k++) {
				if (uint128_cmp(&r->proposed_vdevs[0],
					    &r->excluded_vdevs[k]) == 0) {
					excluded = k;
					break;
				}
			}
			if (excluded == -1) {
				/* new device */
				r->excluded_vdevs_errcnt[r->excluded_count] += 1;
				r->excluded_vdevs[r->excluded_count++] = r->selected_vdevs[0];
			} else {
				/* existing device, just increment counter */
				r->excluded_vdevs_errcnt[excluded] += 1;
			}
		}
		ev = EV_TIMEOUT;
	}

	if (threaded)
		state_event(st, ev);
	else
		state_next(st, ev);
}

#ifdef THREADED_CM_VERIFY
static void
unnamedget_cm_verify(uv_work_t *wreq)
{
	int err;
	struct getcommon_client_req *r = wreq->data;
	struct ccow_io *io = (struct ccow_io *)r->ctx->state;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = op->comp;

	/*
	 * The received data can have delayed hashing verification enabled
	 * by the tenant configuration, as there is already a CRC32 on the line.
	 */
	uint512_t tmp_chid;
	err = rtbuf_hash(r->rb, HASH_TYPE_DEFAULT, &tmp_chid);
	if (err < 0) {
		log_error(lg, "Error calculating hash on unnamedget: %d",
		    err);
		r->cm_verify_status = err;
		return;
	}
	if (uint512_cmp(&r->chid, &tmp_chid) != 0) {
		r->cm_verify_status = RT_ERR_BAD_CRED;
		log_error(lg, "CM fingerprint verification error: %d",
		    r->cm_verify_status);
		uint512_logdump(lg, "Calculated CHID: ", &tmp_chid);
		uint512_logdump(lg, "Expected CHID: ", &r->chid);
		return;
	}

	/*
	 * Read Chunk Reference list (Payload CHID + Offset + Length)
	 */
	err = replicast_unpack_cm_refs(r->rb, &r->cm_reflist, 0);
	if (err) {
		log_error(lg, "UNNAMED GET chunk reference list "
		    "error: %d", err);
		r->cm_verify_status = err;
		return;
	}
}

static void
unnamedget_cm_verify_after(uv_work_t *wreq, int status)
{
	struct getcommon_client_req *r = wreq->data;
	struct state *st = r->ctx->state;

	if (r->cm_verify_status == 0) {
		/* transition to ST_TERM */
		state_event(st, EV_DONE);
	} else {
		ccow_fail_io(st->io, r->cm_verify_status);
		state_event(st, EV_ERR);
	}
}
#endif

void
unnamedget_process_payload(struct state *st)
{
	int err;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct ccow_completion *comp = op->comp;
	struct ccow *tc = comp->tc;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
						ctx->sub_sequence_cnt);

	if(io->attributes & RD_ATTR_VERSION_MANIFEST) {
		rtbuf_t *tmp = NULL;
		if (r->nbufs > 1) {
			uv_buf_t one_payload;
			err = rtbuf_serialize_bufs(&r->payload[0], r->nbufs, &one_payload);
			if (!err)
				tmp = rtbuf_init(&one_payload, 1);
		} else
			tmp = rtbuf_init_mapped(&r->payload[0], r->nbufs);
		if (!tmp) {
			log_error(lg, "Get: out of memory while get blob");
			ccow_fail_io(st->io, -ENOMEM);
			state_next(st, EV_ERR);
			return;
		}
		if (tc->verify_chid && !r->rb_cached) {
			uint512_t tmp_chid;
			err = rtbuf_hash(tmp, HASH_TYPE_DEFAULT, &tmp_chid);
			if (err < 0) {
				log_error(lg, "Error calculating VM hash on unnamedget: %d",
				    err);
				rtbuf_destroy(tmp);
				ccow_fail_io(st->io, err);
				state_next(st, EV_ERR);
				return;
			}
			if (uint512_cmp(&r->chid, &tmp_chid) != 0) {
				err = RT_ERR_BAD_CRED;
				log_warn(lg, "VM (len=%ld nbufs=%ld) fingerprint "
				    "verification error: %d", rtbuf_len(tmp),
				    tmp->nbufs, err);
				uint512_logdump(lg, "Calculated CHID: ", &tmp_chid);
				uint512_logdump(lg, "Expected CHID: ", &r->chid);

				rtbuf_destroy(tmp);

				r->excluded_vdevs[r->excluded_count++] = r->selected_vdevs[0];
				client_getcommon_reset(r);
				state_next(st, EV_TIMEOUT);
				return;
			}
		}
		r->rb = rtbuf_clone_bufs(tmp);
		if (!r->rb) {
			rtbuf_destroy(tmp);
			log_error(lg, "Get: out of memory while get blob");
			ccow_fail_io(st->io, -ENOMEM);
			state_next(st, EV_ERR);
			return;
		}
		if (!r->rb_cached)
			io->network_payload_len = r->rb->bufs[0].len;
		rtbuf_destroy(tmp);
		err = replicast_get_metadata(r->rb, &op->metadata);
		if (err) {
			log_error(lg, "UNNAMED GET VM metadata error: %d", err);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return;
		}

		/* transition to ST_TERM */
		state_next(st, EV_DONE);
	} else if (io->attributes & RD_ATTR_CHUNK_MANIFEST) {
		r->rb = NULL;
		if (r->nbufs > 1) {
			uv_buf_t one_payload;
			err = rtbuf_serialize_bufs(&r->payload[0], r->nbufs, &one_payload);
			if (!err)
				r->rb = rtbuf_init(&one_payload, 1);
		} else
			r->rb = rtbuf_init_mapped(&r->payload[0], r->nbufs);
		if (!r->rb) {
			log_error(lg, "Get: out of memory while get blob");
			ccow_fail_io(st->io, -ENOMEM);
			state_next(st, EV_ERR);
			return;
		}
		if (tc->verify_chid && !r->rb_cached) {
#ifdef THREADED_CM_VERIFY
			/*
			 * In our experimentation threaded version had excess
			 * overhead when the system was lightly loaded.
			 *
			 * This requires more research...
			 */
			r->cm_wreq.data = r;
			uv_queue_work(tc->loop, &r->cm_wreq,
			    unnamedget_cm_verify, unnamedget_cm_verify_after);
			repctx_drop(r->ctx);
			return;
#else
			/*
			 * The received data can have delayed hashing verification enabled
			 * by the tenant configuration, as there is already a CRC32 on the line.
			 */
			uint512_t tmp_chid;
			err = rtbuf_hash(r->rb, HASH_TYPE_DEFAULT, &tmp_chid);
			if (err < 0) {
				log_error(lg, "Error calculating hash on unnamedget: %d",
				    err);
				ccow_fail_io(st->io, err);
				state_next(st, EV_ERR);
				return;
			}
			if (uint512_cmp(&r->chid, &tmp_chid) != 0) {
				err = RT_ERR_BAD_CRED;
				log_warn(lg, "CM fingerprint verification error: %d",
				    err);
				uint512_logdump(lg, "Calculated CHID: ", &tmp_chid);
				uint512_logdump(lg, "Expected CHID: ", &r->chid);

				unnamedget_hashuncomp_done(st, err);
				return;
			}
#endif
		}
		if (!r->rb_cached && unnamgedget_is_btn(io)) {
			/* add BTN CM to ucache */
			assert(r->rb->nbufs == 1);
			ccow_ucache_put(tc->ucache, &r->chid, &r->rb->bufs[0], 1);
		}
		io->network_payload_len = r->rb->bufs[0].len;

		/*
		 * Read Chunk Reference list (Payload CHID + Offset + Length)
		 */
		err = replicast_unpack_cm_refs(r->rb, &r->cm_reflist, 0);
		if (err) {
			log_error(lg, "UNNAMED GET chunk reference list "
			    "error: %d", err);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return;
		}
		/* transition to ST_TERM */
		state_next(st, EV_DONE);
	} else if (io->attributes &
		(RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_PARITY_MAP | RD_ATTR_PARITY_MAP_VM)) {
		/*
		 * Decompress the payload and put it into op->chunks,
		 * which someone should eventually free...
		 */
		r->rb = rtbuf_init_mapped(&r->payload[0], r->nbufs);
		if (!r->rb) {
			log_error(lg, "Get: out of memory while get blob");
			ccow_fail_io(st->io, -ENOMEM);
			state_next(st, EV_ERR);
			return;
		}

		struct ccow_op *dest_op = op;
		if (io->parent_io && io->parent_io->cont_op)
			dest_op = io->parent_io->cont_op;

		if (io->attributes & RD_ATTR_NCOMP) {
			int err = 0;
			io->network_payload_len = 0;
			if (dest_op->chunks && r->nbufs) {
				if (io->attributes & RD_ATTR_VERIFY_PAYLOAD) {
					uint512_t chid;
					rtbuf_hash(r->rb, r->hash_type, &chid);
					err = uint512_cmp(&r->chid, &chid);
				}
				if (!err) {
					size_t off = 0;
					io->network_payload_len = rtbuf_len(r->rb);
					assert(dest_op->chunks->bufs->len >= io->network_payload_len);
					for(int n = 0; n < r->nbufs; n++) {
						memcpy(dest_op->chunks->bufs->base + off,
							r->rb->bufs[n].base,
							r->rb->bufs[n].len);
						off += r->rb->bufs[n].len;
					}
					dest_op->chunks->bufs->len = io->network_payload_len;
				}
			}
			unnamedget_hashuncomp_done(st, err);
			return;
		}

		if (r->nbufs) {
			io->network_payload_len = rtbuf_len(r->rb);
			if (io->network_payload_len <= tc->comphash_threshold_size) {
				ssize_t i = hashuncomp_find_idx(dest_op->chunks,
				    dest_op->offset, r->offset);
				if (i < 0) {
					err = i;
					log_error(lg, "Cannot find chunk offset");
					ccow_fail_io(st->io, err);
					state_next(st, EV_ERR);
					return;
				}

				struct hashuncomp ch;
				ch.status = 0;
				ch.chunk = &rtbuf(dest_op->chunks, i);
				ch.data_in = &rtbuf(r->rb, 0);
				ch.compress_type = r->compress_type;
				ch.nbufs = r->nbufs;
				ch.chid_in = &r->chid;
				ch.hash_type = r->hash_type;
				ch.op = dest_op;
				ch.verify_chid = tc->verify_chid;
				ch.rb_cached = r->rb_cached;
				hashuncomp_one(&ch);
				err = ch.status;

				unnamedget_hashuncomp_done(st, err);
				return;
			}
		} else {
			io->network_payload_len = 0;
			/*
			 * if no IOVs supplied, be done immediately!
			 */
			unnamedget_hashuncomp_done(st, 0);
			return;
		}

		/*
		 * This will prevent state machine from termination if
		 * uncompression is in progress while reporting error.
		 */
		r->hashuncomp_threaded = 1;
		r->hashuncomp_inexec++;
		err = ccow_hashuncomp_compute(dest_op,
		    unnamedget_hashuncomp_done, st, r->rb, &r->chid, r->offset,
		    r->hash_type, r->compress_type, r->rb_cached);
		if (err) {
			r->hashuncomp_inexec--;
			log_error(lg, "UNNAMED GET chunk uncompress "
			    "error: %d", err);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return;
		}
	}
}

/*
 * ACTION: process UNNAMED GET response
 */
static void
unnamedget__ack(struct state *st)
{
	int err;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;

	assert(wqe);

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	/*
	 * If we already processing "good" playload then avoid storm
	 * of Get replies from the server and simply skip.
	 * We will be done when hashuncomp finishes
	 */
	if (r->hashuncomp_inexec)
		return;

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	struct repmsg_unnamed_chunk_get_response *msg =
		(struct repmsg_unnamed_chunk_get_response *)wqe->msg;

	if (msg->is_gwcache == 1) {
		log_debug(lg, "msg: Cache flag is enabled");
	}

	// if we are in RT we just bail from here so we can
	// wait  for other replies
	if (msg->immediate_content_length == 0) {
		state_next(st, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS);
		return;
	}

	r->payload[0].len = msg->content_length;
	r->payload[0].base = repwqe_payload(wqe);
	r->nbufs = 1;

	unnamedget_process_payload(st);
}

static void
unnamedget__send(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_network *netobj = tc->netobj;
	struct ccow_completion *c = op->comp;

	log_trace(lg, "st %p seqid %d.%d io: %p, req: %p", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, io, r);

	if (((io->attributes & RD_ATTR_CHUNK_PAYLOAD) && c->ec_enabled) ||
		(io->attributes & (RD_ATTR_CM_LEAF_WRITE | RD_ATTR_ISGW_ONDEMAND))) {
		/*
		 * Get proposal acknowledgment optimization.
		 * Don't send ENOENT if we don't need a consensus
		 */
		io->attributes |= RD_ATTR_GET_CONSENSUS;
	} else
		io->attributes |= RD_ATTR_GET_ANY;

	struct repmsg_unnamed_chunk_get msg;
	memset(&msg, 0, sizeof (msg));
	msg.maximum_immediate_content_size = 0; // FIXME
	msg.reception_window = 0; // FIXME
	msg.hdr.attributes |= io->attributes;
	msg.hdr.hash_type = r->hash_type;
	msg.content_hash_id = r->chid;
	msg.object_name.uvid_timestamp = op->uvid_timestamp;

	/*
	 * In case of VM, we have to use its NHID to calculate NG group.
	 * Caller has to pre-set req->ng_chid.
	 */
	if(io->attributes & (RD_ATTR_VERSION_MANIFEST | RD_ATTR_TARGETED |
		RD_ATTR_COMPOUND_TARGETED | RD_ATTR_PARITY_MAP_VM))
			msg.object_name.name_hash_id = r->ng_chid;
	else
		r->ng_chid = r->chid;

	if (unlikely((lg->level <= LOG_LEVEL_DEBUG) &&
		(io->attributes & RD_ATTR_CM_LEAF_WRITE))) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(&r->chid, chidstr, UINT512_BYTES*2+1);
		chidstr[31] = 0;
		log_debug(lg, "Leaf manifest overwrite, sending un-encode "
			"request to CM %s", chidstr);
	}
	if (CCOW_UNENCODE_REQUEST_ENABLED() &&
		(io->attributes & RD_ATTR_CM_LEAF_WRITE)) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(&r->chid, chidstr, UINT512_BYTES*2+1);
		CCOW_UNENCODE_REQUEST(chidstr);
	}

	memcpy(&msg.receive_tenant_addr, &tc->tenant_recvaddr.sin6_addr, 16);
	msg.receive_tenant_port = tc->tenant_recvport;

	r->req_start = get_timestamp_us();
	uint64_t avg_rtt = flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
					    FH_MSG_UNNAMEDGET_SELECT, 4096);
	msg.genid_delta = (r->req_start - op->uvid_timestamp) + (avg_rtt >> 1);
	msg.select_time_avg = avg_rtt;
	client_getcommon_send_proposal(st, RT_UNNAMED_CHUNK_GET, &msg);
}

static void
gwcacheget__send(struct state *st)
{
	char gw_addr[INET6_ADDRSTRLEN + 1];

	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_network *netobj = tc->netobj;
	struct ccow_completion *c = op->comp;
	int err;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (((io->attributes & RD_ATTR_CHUNK_PAYLOAD) && c->ec_enabled) ||
		(io->attributes & RD_ATTR_CM_LEAF_WRITE)) {
		/*
		 * Get proposal acknowledgment optimization.
		 * Don't send ENOENT if we don't need a consensus
		 */
		io->attributes |= RD_ATTR_GET_CONSENSUS;
	}

	struct repmsg_unnamed_chunk_get msg;
	memset(&msg, 0, sizeof (msg));
	msg.maximum_immediate_content_size = 0; // FIXME
	msg.reception_window = 0; // FIXME
	msg.hdr.attributes |= io->attributes;
	msg.hdr.hash_type = r->hash_type;
	msg.content_hash_id = r->chid;
	msg.object_name.uvid_timestamp = op->uvid_timestamp;
	msg.chunk_offset = r->chunk_offset;

	/*
	 * In case of VM, we have to use its NHID to calculate NG group.
	 * Caller has to pre-set req->ng_chid.
	 */
	if(io->attributes & (RD_ATTR_VERSION_MANIFEST | RD_ATTR_TARGETED |
		RD_ATTR_COMPOUND_TARGETED | RD_ATTR_PARITY_MAP_VM))
			msg.object_name.name_hash_id = r->ng_chid;
	else
		r->ng_chid = r->chid;

	if (unlikely((lg->level <= LOG_LEVEL_DEBUG) &&
		(io->attributes & RD_ATTR_CM_LEAF_WRITE))) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(&r->chid, chidstr, UINT512_BYTES*2+1);
		chidstr[31] = 0;
		log_debug(lg, "Leaf manifest overwrite, sending un-encode "
			"request to CM %s", chidstr);
	}

	memcpy(&msg.receive_tenant_addr, &tc->tenant_recvaddr.sin6_addr, 16);
	msg.receive_tenant_port = tc->tenant_recvport;

	memset(gw_addr, 0, INET6_ADDRSTRLEN + 1);
	get_gwcache_addr(&tc->this_serverid, gw_addr, INET6_ADDRSTRLEN, NULL);

	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_scope_id = netobj->if_indexes[0];
	addr.sin6_port = htons(CCOW_GW_CACHE_PORT);
	err = inet_pton(AF_INET6, gw_addr, &addr.sin6_addr);
	if (err <= 0)
		return;

	r->inexec++;
	err = replicast_send(netobj->robj[0], ctx, RT_UNNAMED_CHUNK_GET,
		(struct repmsg_generic *) &msg, NULL, NULL, 0, &addr,
		replicast_send_done_generic, st, NULL);
	if (err) {
		r->inexec--;
		/* Send to cache failed, try replicast GET */
	} else {
		uv_timer_start(r->timer_req, client_getcommon_timeout,
				CLIENT_GETCOMMON_TIMEOUT_MS, 0);
		r->timer_req->data = st;
	}
}

static void
unnamedget__init(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;

	log_trace(lg, "st %p io: %p, req: %p", st, io, r);

	r->reqtype = GET_REQ_TYPE_UNNAMED;
	client_getcommon_init(st);

	/* Payload or BTN CM can be in ucache - check */
	if (io->attributes & RD_ATTR_CHUNK_PAYLOAD ||
	    (io->attributes & RD_ATTR_CHUNK_MANIFEST && unnamgedget_is_btn(io))) {
		r->rb_cached = ccow_ucache_get(tc->ucache, &r->chid, &r->payload[0]);
		if (r->rb_cached) {
			r->nbufs = 1;
			unnamedget_process_payload(st);
			return;
		}
	}
	if (op->isgw_dfetch && RT_ONDEMAND_GET(op->metadata.inline_data_flags) != ondemandPolicyLocal) {
		io->attributes |= RD_ATTR_ISGW_ONDEMAND;
		if (op->comp && (op->comp->cont_flags & CCOW_CONT_F_PREFETCH_TOUCH))
			io->attributes |= RD_ATTR_ONDEMAND_PREFETCH;
	}

	if ((tc->gw_cache) && (!r->gw_cache)) {
		gwcacheget__send(st);
	}
	unnamedget__send(st);
}

#define RECOVERY_FLAG_BUSY (1<<0)
#define RECOVERY_FLAG_PROGRESS (1<<1)

static void
unnamed_get_schedule_recovery__cb(uv_timer_t* handle, int status)
{
	struct state *st = handle->data;
	assert(st);
	struct getcommon_client_req *r = st->data;
	assert(r);
	struct ccow_recovery_item* ri = &r->ri;
	assert(ri);

	uv_timer_stop(r->timer_req);
	r->timer_req->data = NULL;
	ri->timeout_counter = 0;
	client_getcommon_reset(r);
	r->error_consensus_max = CCOW_EC_GET_RETRY_MAX;
	r->n_error_consensus = 0;
	state_event(st, EV_TIMEOUT);
}

static void
unnamed_get_schedule_recovery(struct state *st) {
	struct getcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	r->timer_req->data = st;
	uint64_t delay = 0;
	if (r->recovery_flags & RECOVERY_FLAG_BUSY) {
		delay =  (CCOW_RECOVERY_BUSY_CNT - r->recovery_busy_cnt + 1)*100L;
		r->recovery_busy_cnt--;
	} else {
		delay = (CCOW_RECOVERY_RETRY_CNT - r->recovery_cnt + 1)*100L;
		r->recovery_cnt--;
	}
	uv_timer_start(r->timer_req, unnamed_get_schedule_recovery__cb,
		delay, 0);
}

static void
unnamedget_recovery_ack_timeout_cb(uv_timer_t* handle, int status)
{
	struct state *st = handle->data;
	assert(st);
	struct getcommon_client_req *r = st->data;
	assert(r);
	struct ccow_recovery_item* ri = &r->ri;
	assert(ri);
	struct ccow_io* io = st->io;

	uint32_t max_timer_ticks = r->recovery_flags & RECOVERY_FLAG_PROGRESS ?
		CCOW_EC_RECOVERY_TIMEOUT_MS/100 :
		CCOW_EC_CONSENSUS_TIMEOUT_MS/100;
	if (io->comp->failed) {
		uv_timer_stop(handle);
		handle->data = NULL;
		state_event(st, EV_ERR);
	} else if (++ri->timeout_counter > max_timer_ticks) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(&ri->mchid, chidstr, UINT512_BYTES*2+1);
		log_debug(lg, "Manifest %s recovery ACK TIMEOUT", chidstr);
		unnamed_get_schedule_recovery(st);
	}
}

static int
unnamedget_send_recovery_request(struct state* st) {
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;
	struct ccow_recovery_item* ri = &r->ri;
	assert(ri);
	struct repmsg_recovery msg;
	memset(&msg, 0, sizeof (msg));
	msg.hdr.attributes = ri->is_cm ? RD_ATTR_CHUNK_MANIFEST : RD_ATTR_VERSION_MANIFEST;
	msg.hdr.attributes |= r->recovery_cnt == 1 ? RD_ATTR_RECOVERY_LAST : 0;
	msg.hdr.hash_type = HASH_TYPE_DEFAULT;
	msg.content_hash_id = ri->mchid;
	msg.name_hash_id = op->name_hash_id;

	if (tc->unicastio == REPLICAST_UNICAST_TCP)
		msg.hdr.attributes |= RD_ATTR_UNICAST_TCP;
	else if (tc->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		msg.hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;
		ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	struct sockaddr_in6 send_addr;
	flexhash_get_hashaddr(tc->flexhash,
		ri->is_cm ? &ri->mchid : &op->name_hash_id,
		&send_addr);
	send_addr.sin6_scope_id = netobj->if_indexes[0];
	r->inexec++;
	int err = replicast_send(netobj->robj[0], ctx,
		RT_RECOVERY, (struct repmsg_generic *) &msg, NULL,
		NULL, 0, &send_addr, replicast_send_done_generic, st,
		NULL);
	if (err) {
		r->inexec--;
		log_error(lg, "RT_UNNAMED_CHUNK_GET_RECOVER operation "
			"error %d on send", err);
	} else {
		/* RT_RECVOERY_ACK response timeout handling */
		if (r->timer_req->data) {
			uv_timer_stop(r->timer_req);
		}
		r->timer_req->data = st;
		r->reply_count = 0;
		uv_timer_start(r->timer_req, unnamedget_recovery_ack_timeout_cb,
			100, 100);
	}
	return err;
}

static int
unnamedget_start_recovery(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;
	struct ccow_network *netobj = tc->netobj;
	char mchidstr[UINT512_BYTES*2+1];
	char chidstr[UINT512_BYTES*2+1];
	assert(wqe);
	int err = 0;
	/* Find out what is going to be recovered VM or CM */
	int is_cm = !!uint512_cmp(&r->mchid, &uint512_null);
	int is_vm = !is_cm && !!uint512_cmp(&op->vmchid, &uint512_null);
	/*
	 * Recovery can be applied only if the request comes from btree,
	 * that is, only RD_ATTR_CHUNK_PAYLOAD is set
	 */
	if (((io->attributes & (RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_GET_CONSENSUS)) == io->attributes)
		&& (is_cm || is_vm)) {
		/* Define what CHID to use */
		uint512_t rchid = is_cm ? r->mchid : op->vmchid;
		uint512_dump(&rchid, mchidstr, UINT512_BYTES*2+1);
		uint512_dump(&r->chid, chidstr, UINT512_BYTES*2+1);
		/* Preparing a recovery request */

		log_debug(lg, "Chunk %s UGET failed, requesting recovery of the "
			"manifest %s", chidstr, mchidstr);
		/* append original request to the recovery list */
		r->ri.mchid = rchid;
		r->ri.is_cm = is_cm;
		r->ri.ngcount = 0;
		/* Sending request */
		err = unnamedget_send_recovery_request(st);
		if (err) {
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return err;
		}
		return 0;
	 }

	return -EINVAL;
}


static void
unnamedget_dynfetch_request_cb(void *data, int status, void *rsp) {
	struct state* st = NULL;
	struct getcommon_client_req *r = data;
	r->isgw_fsm_hanlde = NULL;
	if (r->isgw_priv) {
		struct dynfetch_data* p = r->isgw_priv;
		je_free(p->chids);
		je_free(p);
		r->isgw_priv = NULL;
	}
	st = (struct state*)r->io;
	if (!status)
		tc_marshal_call(st, r->tc, RT_DFETCH_DONE);
	else
		tc_marshal_call(st, r->tc, RT_DFETCH_ERROR);
}

static void
unnamedget_dynfetch_request(struct state *st) {
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;

	char mchidstr[UINT512_BYTES*2+1];
	uint512_dump(&r->chid, mchidstr, UINT512_BYTES*2+1);

	if (!strlen(op->isgw_addr_last)) {
		uint16_t mdonly_policy = ondemandPolicyLocal;
		if (op)
			mdonly_policy = RT_ONDEMAND_GET(op->metadata.inline_data_flags);
		/*
		 * The ISGW for dynamic fetch isn't chosen or failed.
		 * Trying to find another
		 */
		int found = 0;
		if (QUEUE_EMPTY(&op->isgw_srv_list)) {
			(void)ccow_bucket_isgw_lookup(op->cid, op->tid, op->bid,
				&op->isgw_srv_list);
			if (QUEUE_EMPTY(&op->isgw_srv_list)) {
				log_error(lg,"Payload %s Get error, MDOnly attribute set, but ISGW list is empty", mchidstr);
				ccow_fail_io(st->io, -EIO);
				state_next(st, EV_ERR);
				return;
			}
			/* Trying to find default ISGW */
			if (op->metadata.uvid_src_guid.l != 0) {
				QUEUE *q;
				QUEUE_FOREACH(q, &op->isgw_srv_list) {
					struct iswg_addr_item* e = QUEUE_DATA(q, struct iswg_addr_item, item);
					/* Make sure the ISGW is able to serve the object */
					int match = (mdonly_policy != ondemandPolicyLocal) || (e->mode == eIsgwFTypeFull);
					if (match && e->seg_uid == op->metadata.uvid_src_guid.l) {
						/*
						 * Always start from default ISGW
						 */
						strcpy(op->isgw_addr_default, e->addr);
						strcpy(op->isgw_addr_last, e->addr);
						op->isgw_flags |= CCOWOP_DEFAULT_ISGW_FOUND;
						found = 1;
						log_notice(lg, "Found default ISGW %s for SegUID %016lX",
							e->addr, e->seg_uid);
						break;
					}
				}
			}
		}

		while (!found) {
			/* Pick the next ISGW address from the list */
			if (!r->isgw_list_pos)
				r->isgw_list_pos = QUEUE_HEAD(&op->isgw_srv_list);
			else {
				if (QUEUE_NEXT(r->isgw_list_pos) == &op->isgw_srv_list) {
					log_error(lg, "No more ISGW servers, payload %s fetch failed", mchidstr);
					ccow_fail_io(st->io, -ENOENT);
					state_next(st, EV_ERR);
					return;
				} else
					r->isgw_list_pos = QUEUE_NEXT(r->isgw_list_pos);
			}

			struct iswg_addr_item* e = QUEUE_DATA(r->isgw_list_pos, struct iswg_addr_item, item);

			int offline = 0;
			(void)ccow_isgw_is_offline(e->addr, &offline);
			if (!offline) {
				/*
				 * Only ISGW with X-ISGW-Emergency-Lookup can server
				 * objects whose origin is this site.
				 */
				int match = (mdonly_policy != ondemandPolicyLocal) || (e->mode == eIsgwFTypeFull);
				if (match && (!(op->isgw_flags & CCOWOP_DEFAULT_ISGW_FOUND) ||
					strcmp(e->addr, op->isgw_addr_default))) {
					strcpy(op->isgw_addr_last, e->addr);
					found = 1;
				}
			}
		}
	}
	assert(strlen(op->isgw_addr_last));

	struct dynfetch_data* d = je_calloc(1, sizeof(*d));
	if (!d) {
		log_error(lg, "Out of memory");
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	d->flags = eIsgwReqPayload;
	d->ref = r->ref;
	d->chids = je_calloc(3, sizeof(uint512_t));
	if (!d->chids) {
		je_free(d);
		log_error(lg, "Out of memory");
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	d->chids[0] = op->vmchid;
	d->chids[1] = op->name_hash_id;
	d->n_chids = 2;
	if (uint512_cmp(&r->mchid, &uint512_null)) {
		d->chids[2] = r->mchid;
		d->n_chids = 3;
	}
	log_debug(lg, "Payload %s: a dynamic fetch  request to ISGW %s SegUID %016lX",
		mchidstr, op->isgw_addr_last, op->metadata.uvid_src_guid.l);
	snprintf(d->obj_path, sizeof(d->obj_path), "%s/%s/%s/%s",
		op->cid, op->tid, op->bid,op->oid);
	r->inexec++;
	int err = ccow_isgw_dynamic_fetch_init(op->isgw_addr_last, d,
		unnamedget_dynfetch_request_cb, r, &r->isgw_fsm_hanlde);
	if (err) {
		r->inexec--;
		je_free(d->chids);
		je_free(d);
		ccow_fail_io(st->io, -EIO);
		state_next(st, EV_ERR);
	}
	r->isgw_priv = d;
}

static void
unnamed_get_dfetch_done(struct state *st) {
	struct getcommon_client_req *r = st->data;
	char chidstr[UINT512_STR_BYTES];
	uint512_dump(&r->chid, chidstr, UINT512_STR_BYTES);
	log_debug(lg, "Payload %s dynamic fetch done", chidstr);

	assert(r->inexec >= 1);
	r->inexec--;

	client_getcommon_reset(r);
	r->error_consensus_max = 1;
	r->n_error_consensus = 0;
	state_event(st, EV_TIMEOUT);
}

static void
unnamed_get_dfetch_error(struct state *st) {
	struct getcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;

	char chidstr[UINT512_STR_BYTES];
	uint512_dump(&r->chid, chidstr, UINT512_STR_BYTES);
	log_warn(lg, "Payload %s dynamic fetch error", chidstr);

	assert(r->inexec >= 1);
	r->inexec--;

	/**
	 * Try to send a request to another ISGW. Or fail the IO
	 */
	if (((op->isgw_flags & (CCOWOP_DEFAULT_ISGW_FOUND | CCOWOP_DEFAULT_ISGW_FAILED))
		== CCOWOP_DEFAULT_ISGW_FOUND) &&
		(!strcmp(op->isgw_addr_last, op->isgw_addr_default))) {
		op->isgw_flags |= CCOWOP_DEFAULT_ISGW_FAILED;
	}
	op->isgw_addr_last[0] = 0;
	unnamedget_dynfetch_request(st);
	return;
}

static void
unnamedget_error_rcvd(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct repwqe *wqe = ctx->wqe_in;
	char mchidstr[UINT512_BYTES*2+1];

	struct ccow_op *op = io->op;
	struct ccow_completion *c = op->comp;
	assert(wqe);

	log_trace(lg, "st %p seqid %d.%d io: %p, req: %p", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, io, r);

	/*
	 * Local GW cache does not have chunk. Try cluster now.
	 */
	struct repmsg_error *msg = (struct repmsg_error *)wqe->msg;

	if (msg->is_gwcache) {
		return;
	}

	/* RD_ATTR_CM_LEAF_WRITE can only be set for EC enabled objects */

	if (io->attributes & RD_ATTR_CM_LEAF_WRITE) {
		/* Special case: manifest unencoded by btree, check error code */
		if (msg->error == RT_ERR_UNENCODE) {
			uint512_dump(&r->chid, mchidstr, UINT512_BYTES*2+1);
			log_warn(lg,"Manifest %s un-encode error, retrying",
				mchidstr);
		} else if (msg->error == RT_ERR_NO_RESOURCES) {
			uint512_dump(&r->chid, mchidstr, UINT512_BYTES*2+1);
			log_warn(lg,"Manifest %s unencode device busy, retrying",
				mchidstr);
		} else if (REPLIES_CNT(r) >= r->ngcount && r->rtselected) {
			/* We are waiting for full consensus.
			 * This request is the latest. Proceed only if
			 * there was at least one positive response
			 */
			if (r->timer_req->data) {
				uv_timer_stop(r->timer_req);
				r->timer_req->data = NULL;
			}
			state_next(st, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS);
		}
		return;
	}
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	if (io->attributes & RD_ATTR_CHUNK_LOOKUP) {
		r->chunkmap_data = (void*)((int64_t)r->reply_count);
		state_next(st, EV_DONE);
		return;
	}

	/* did we get enough errors? bail out if so */
	if (REPLIES_CNT(r) - r->reply_count >= r->ngcount) {
		int ret = -EIO;

		if (io->attributes & RD_ATTR_MULTISITE) {
			log_trace(lg, "MSITE chunk not found io: %p, req: %p", io, r);
			ret = -ENOENT;
			ccow_fail_io(st->io, ret);
			state_next(st, EV_ERR);
			return;
		}

		if (r->reply_count == 0 && !c->ec_enabled) {
			if (op->isgw_dfetch) {
				/* Sending a dynamic fetch request */
				unnamedget_dynfetch_request(st);
			} else if (r->fddelta >= 0) {
				/*
				 * fail fast if there is no SPLIT
				 * for payloads, just return error
				 */
				if (io->attributes & RD_ATTR_CHUNK_PAYLOAD) {
					uint512_dump(&r->chid, mchidstr, UINT512_BYTES*2+1);
					log_error(lg,"Payload %s Get error, failfast is ON", mchidstr);
				/* for manifests, provide zero manifest */
				} else {
					uint512_dump(&r->chid, mchidstr, UINT512_BYTES*2+1);
					log_error(lg,"Manifest %s Get error, failfast is ON", mchidstr);
				}
				ccow_fail_io(st->io, ret);
				state_next(st, EV_ERR);
			}
			return;
		}

		if (r->recovery_cnt && c->ec_enabled)
			ret = unnamedget_start_recovery(st);
		if (ret) {
			uint512_dump(&r->mchid, mchidstr, UINT512_BYTES*2+1);
			log_error(lg, "Affected manifest %s, ret: %d, recovery_cnt: %d",
				mchidstr, ret, r->recovery_cnt);
			ccow_fail_io(st->io, ret);
			state_next(st, EV_ERR);
		}
		return;
	}

	if (msg->hdr.orig_id.opcode == RT_UNNAMED_CHUNK_GET &&
	    msg->error == -ENOENT) {
		/* not found error processed in the term callback */
		log_debug(lg, "GET received error %s",
		    replicast_error_str[msg->error]);
		state_next(st, EV_DONE);
		return;
	}

	log_error(lg, "GET received unknown error %s",
		replicast_error_str[msg->error]);

	ccow_fail_io(st->io, msg->error);
	state_next(st, EV_ERR);
}

static void
unnamedget_recovery_ack(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow *tc = r->tc;
	struct ccow_recovery_item* ri = &r->ri;
	char chidstr[UINT512_BYTES*2+1];
	char vdevstr[UINT128_BYTES*2+1];

	struct repmsg_recovery_ack *msg = (struct repmsg_recovery_ack*)wqe->msg;
	assert(msg);
	uint512_dump(&msg->content_hash_id, chidstr, UINT512_BYTES*2+1);
	uint128_dump(&msg->vdevid, vdevstr, UINT128_BYTES*2+1);

	if (!ri->ngcount)
		ri->ngcount = msg->ngcount;
	else if (msg->ngcount != ri->ngcount) {
		/* NG count has changed since the last reply.
		 * Flexhash might have changed. Drop all received info.
		 * In this way either a positive reply or timeout will
		 * define the further actions
		 */
		log_debug(lg, "Manifest %s, ngcount changed: %d vs %d",
			chidstr, ri->ngcount, msg->ngcount);
		ri->ngcount = msg->ngcount;
		r->reply_count = 0;
	}

	if (msg->status == MANIFEST_PROCESSING) {
		/*
		 * This affects on recovery timeout
		 * which is different for consensus and recovery
		 */
		r->recovery_flags |= RECOVERY_FLAG_PROGRESS;
		return;
	}

	for (int i = 0; i < r->reply_count; i++) {
		/* skip duplicates */
		if (!uint128_cmp(ri->vdev_ack + i, &msg->vdevid))
			return;
	}

	ri->vdev_ack[r->reply_count] = msg->vdevid;

	/* We interested only in status >= 0. Such a status is produced
	 * on a device where recovery was actually done */
	r->reply_count++;
	int busy = msg->status == MANIFEST_RECOVERY_BUSY;
	if (msg->status < 0 || busy) {
		log_debug(lg, "Manifest %s recovery skipped on VDEV %s, "
			"status: %d, reply_count: %d, ngcount: %d",
			chidstr, vdevstr, msg->status, r->reply_count,
			msg->ngcount);
		if (busy)
			r->recovery_flags |= RECOVERY_FLAG_BUSY;
		if (busy || r->reply_count >= msg->ngcount) {
			/* Haven't gotten any recovery acknowledgment.
			 * Keep trying to recover
			 */
			if (r->timer_req->data) {
				uv_timer_stop(r->timer_req);
				r->timer_req->data = NULL;
			}
			log_warn(lg, "Nobody can recover manifest %s at the moment"
				"recovery_cnt: %d, retrying", chidstr,
				r->recovery_cnt);
			if (!io->comp->failed) {
				unnamed_get_schedule_recovery(st);
			}
		}
		return;
	}

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	/* Try to get the chunk again if recovery is done */
	if (msg->status == MANIFEST_RECOVERY_SUCCESS ||
	    msg->status == MANIFEST_RECOVERY_PART) {
		log_notice(lg, "Manifest %s is %s on a VDEV %s", chidstr,
			(msg->status == MANIFEST_RECOVERY_PART ?
			"partially recovered":"recovered"), vdevstr);
		client_getcommon_reset(r);
		r->error_consensus_max = CCOW_EC_GET_RETRY_MAX;
		r->n_error_consensus = 0;
		state_event(st, EV_TIMEOUT);
	} else {
		log_warn(lg,"Cannot recovery the manifest %s, status %d, "
			"VDEV ID %s, reply_cnt: %d, ngcount: %d, try again",
			chidstr, msg->status, vdevstr, r->reply_count,
			r->ngcount);
		unnamed_get_schedule_recovery(st);
	}
}

static void
unnamedget_term(struct state *st) {
	struct getcommon_client_req *r = st->data;
	client_getcommon_terminate(st);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, unnamedget__init, ST_WAIT, NULL },
{ ST_READY, EV_TIMEOUT, unnamedget__send, ST_READY, client_getcommon_guard_retry },
{ ST_WAIT, EV_TIMEOUT, unnamedget__send, ST_READY, client_getcommon_guard_retry },
{ ST_WAIT, RT_UNNAMED_CHUNK_GET_RESPONSE, unnamedget__ack, ST_READY,
	client_getcommon_guard_resp },
{ ST_READY, RT_UNNAMED_CHUNK_GET_RESPONSE, unnamedget__ack, ST_READY,
	client_getcommon_guard_resp },
{ ST_WAIT, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS, client_getcommon_send_accept,
	ST_READY, NULL },
{ ST_READY, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS, client_getcommon_send_accept,
	ST_READY, NULL },
{ ST_READY, RT_INIT_TCP_CONNECT, &client_getcommon_tcp_connect, ST_READY, NULL },
{ ST_WAIT, RT_ERROR, unnamedget_error_rcvd, ST_READY,
	client_getcommon_error_consensus },
{ ST_READY, RT_ERROR,unnamedget_error_rcvd, ST_READY,
	client_getcommon_error_consensus },
{ ST_READY, RT_RECOVERY_ACK, unnamedget_recovery_ack, ST_READY, NULL },
{ ST_READY, RT_GET_RENDEZVOUS_TRANSFER, &client_getcommon_rttransfer,
	ST_READY, NULL},
{ ST_READY, RT_RENDEZVOUS_NACK, &client_getcommon_nack_rcvd, ST_READY, NULL },
{ ST_READY, RT_DFETCH_DONE, &unnamed_get_dfetch_done, ST_READY, NULL },
{ ST_WAIT, RT_DFETCH_DONE, &unnamed_get_dfetch_done, ST_WAIT, NULL },
{ ST_ANY, RT_DFETCH_ERROR, &unnamed_get_dfetch_error, ST_READY, NULL },
{ ST_INIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_READY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_BUSY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_OFFLINE, EV_ERR, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, unnamedget__error, ST_TERM, NULL }
};

int
ccow_unnamedget_create(ccow_completion_t comp, getcommon_client_callback_t done_cb,
    struct ccow_op *op, struct ccow_io **pio, struct ccow_io *parent_io)
{
	int err;
	struct ccow_completion *c = comp;

	log_trace(lg, "comp %p, done_cb %p, op %p, pio %p", comp,
	    done_cb, op, pio);

	struct getcommon_client_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		log_error(lg, "UNNAMED GET request alloc error: out of memory"
		    ": -ENOMEM");
		return -ENOMEM;
	}

	r->tc = c->tc;
	r->done_cb = done_cb;
	r->hash_type = HASH_TYPE_DEFAULT;

	err = ccow_create_io(c, op, CCOW_GET, trans_tbl,
	    sizeof (trans_tbl) / sizeof (*trans_tbl), r,
	    unnamedget_term, pio);
	if (err) {
		je_free(r);
		return err;
	}
	r->io = *pio;
	r->io->parent_io = parent_io;
	r->chunk_offset = op->offset;
	ccow_io_lock(r->io);
	if (parent_io) {
		r->io->cont_op = parent_io->cont_op;

		ccow_parallel_io(op, r->io);
	} else {
		if (op->namedget_io)
			ccow_chain_io(op, r->io);
		else
			op->namedget_io = r->io;
	}
	ccow_io_unlock(r->io);

	return 0;
}
