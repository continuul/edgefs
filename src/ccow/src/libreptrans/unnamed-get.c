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
#include "reptrans.h"
#include "ccowd-impl.h"
#include "state.h"
#include "getcommon_server.h"
#include "erasure-coding.h"
#include "reptrans-flex.h"

#define PP_ADJ_WEIGHT			3
#define PP_ADJ_WEIGHT_MAX		512
#define PP_WEIGHT_DELAY_MAX_US		10000

static int
unnamedget_create_proposal(uint64_t genid, uint64_t genid_delta,
				struct getcommon_srv_req *req, type_tag_t ttag)
{
	struct repmsg_unnamed_chunk_get_response *rsp = &req->unnamed_rsp;
	struct replicast_rendezvous_proposal *proposal
		= &rsp->rendezvous_proposal;
	struct repdev *dev = req->dev;
	uint128_t *vdevid = &dev->vdevid;

	log_trace(lg, "req %p", req);
	int err = srv_getcommon_find_window(vdevid, req->content_length,
				proposal, genid, genid_delta, req, ttag);
	if (err) {
		log_warn(lg, "UnnamedGet(%s): Unable to determine a window",
		    dev->name);
		return err;
	}

	if (proposal->weight_io > PP_ADJ_WEIGHT_MAX) {
		log_warn(lg, "UnnamedGet(%s): Unable to schedule request due "
		    "to way too deep device queue", dev->name);
		err = -EBUSY;
		return err;
	}

	if (dev->gw_cache)
		rsp->is_gwcache = 1;
	/*
	 * There is no point in replying back to initiator with a proposal
	 * immediately as it selects based on first in. By introducing adaptive
	 * delay in response we enabling natural selection of most optimal VDEV.
	 */
	if (proposal->weight_io > PP_ADJ_WEIGHT) {
		uint64_t delta_pct = req->delta_time_est / 100;
		uint64_t delay_us = (proposal->weight_io - PP_ADJ_WEIGHT) * delta_pct;
		delay_us /= 10;
		if (delay_us > 0 && delay_us < PP_WEIGHT_DELAY_MAX_US) {
			log_debug(lg, "weight_io delay %luus", delay_us);
			usleep(delay_us);
		}
	}

	memcpy(&rsp->vdevid, &dev->vdevid, sizeof (uint128_t));
	return 0;
}

static void
unnamedget_srv__error(struct state *st)
{
	struct getcommon_srv_req *req = st->data;
	/* FIXME: provide previous event/state info in the log error */

	log_trace(lg, "st %p", st);
}

static void
unnamedget_prefetch(void *arg)
{
	srv_getcommon_rtsend_exec(arg);
}

static void
unnamedget_prefetch_done(void *arg, int status)
{
	struct getcommon_srv_req *req = arg;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;
	struct repdev *dev = req->dev;

	req->inexec--;
	dev->get_disk_qdepth--;
	req->prefetching--;
	if (req->prefetching)
		req->prefetching--;
	assert(req->inexec >= 0);

	if (state_check(st, ST_TERM)) {
		srv_getcommon_terminate(st);
		return;
	}

	if (status != 0) {
		log_error(lg, "Get(%s): transport returned non-zero "
		    "status %d", dev->name, status);
		state_event(ctx->state, EV_ERR);
		return;
	}

	if (req->prefetching) {
		req->inexec++;
		dev->get_disk_qdepth++;
		srv_getcommon_rtsend_done(arg, status);
	}
}

static void
unnamedget_srv_done(void* arg, int status)
{
	struct getcommon_srv_req *req = arg;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;
	struct repdev *dev = req->dev;
	struct repmsg_unnamed_chunk_get *msg = &req->msg_in.unnamed_get;
	int err;

	log_trace(lg, "arg %p, status %d", arg, status);

	req->inexec--;
	assert(req->inexec >= 0);

	dev->get_disk_qdepth--;

	if (state_check(st, ST_TERM)) {
		srv_getcommon_terminate(st);
		return;
	}

	if (status != 0) {
		log_error(lg, "Get(%s): transport returned non-zero "
		    "status %d", dev->name, status);
		state_event(ctx->state, EV_ERR);
		return;
	}

	enum replicast_opcode reply_opcode;
	struct repmsg_generic *reply;
	uv_buf_t *bufs = NULL;
	int nbufs = 0;

	struct repctx *lctx = (req->rtproposed) ? ctx : NULL;
	if (req->status == 0) {
		req->unnamed_rsp.num_datagrams = 1;
		reply = (struct repmsg_generic *)&req->unnamed_rsp;
		reply_opcode = RT_UNNAMED_CHUNK_GET_RESPONSE;

		if (!req->rtproposed) {
			if (req->rb_reply) {
				bufs = req->rb_reply->bufs;
				nbufs = req->rb_reply->nbufs;
			}
		}
	} else {
		req->err.num_datagrams = 1;
		req->err.error = req->status;
		req->err.vdevid = dev->vdevid;
		req->err.is_gwcache = dev->gw_cache;
		reply = (struct repmsg_generic *) &req->err;
		reply_opcode = RT_ERROR;
	}
	req->inexec++;
	err = replicast_send(dev->robj, lctx, reply_opcode, reply,
	    (struct repmsg_generic *)msg, bufs, nbufs, NULL,
	    srv_getcommon_send_done, req, NULL);
	if (err) {
		req->inexec--;
		assert(req->inexec >= 0);
		log_error(lg, "Error sending %d st %p error %d", reply_opcode,
			  st, err);
		state_event(ctx->state, EV_ERR);
		return;
	}

	/* prefetch while waiting for accept */
	/* FIXME: disabled */
	if (0 && !req->rb_reply) {
		req->prefetching++;
		req->inexec++;
		dev->get_disk_qdepth++;
		ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, unnamedget_prefetch,
		    unnamedget_prefetch_done, req);
	}
}

static void
unnamedget_srv_exec(void* arg)
{
	struct getcommon_srv_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repmsg_unnamed_chunk_get *msg = &req->msg_in.unnamed_get;
	int err, len;
	int hash_type = msg->hdr.hash_type;

	type_tag_t tt = attr_to_type_tag(msg->hdr.attributes);
	log_trace(lg, "arg %p: tt %d", arg, tt);

	/* prepare ngcount for errors */
	fhrow_t row;
	struct replicast_object_name *ron = &msg->object_name;
	req->err.fddelta = ccowd_get_fddelta();
	int ngcount=0;
	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
	    (msg->hdr.attributes & (RD_ATTR_VERSION_MANIFEST |
		RD_ATTR_TARGETED | RD_ATTR_PARITY_MAP_VM | RD_ATTR_COMPOUND_TARGETED)) ?
	    &ron->name_hash_id : &msg->content_hash_id, &row, &ngcount), FH_LOCK_READ);
	if (err < 0) {
		/* no need to fail GP for normal I/O */
		if (err != -EAGAIN || (msg->hdr.attributes & RD_ATTR_GET_CONSENSUS)) {
			req->status = RT_ERR_BAD_NGCOUNT;
			log_error(lg, "Get(%s): row (%d) error (%d) while "
			    "executing blob read: %s", dev->name, row, err, strerror(err));
			return;
		}
	}
	if (ngcount <= 0 )
		req->err.ngcount = 0;
	else
		req->err.ngcount = ngcount;

	/*
	 * Do a stat first and determine if we do an immediate reply
	 * or do a RT transfer
	 */
	struct blob_stat bstat;
	if (!req->found_in_key_cache_size) {

		err = reptrans_blob_stat(dev, tt, hash_type, &msg->content_hash_id,
		    &bstat);
		if (err) {
			char chidstr[UINT512_BYTES * 2 + 1];
			uint512_dump(&msg->content_hash_id, chidstr,
			    UINT512_BYTES * 2 + 1);
			log_debug(lg, "UnnamedGet(%s): chunk %s not found err=%d "
			    "tt=%d ht=%d", dev->name, chidstr, err, tt, hash_type);
			req->status = -ENOENT;
			return;
		}
	} else {
		bstat.size = req->found_in_key_cache_size;
	}

	if (msg->hdr.attributes & RD_ATTR_ISGW_ONDEMAND) {
		if (msg->hdr.attributes & RD_ATTR_ONDEMAND_PREFETCH) {
			/*
			 * A prefetch operation requires an immediate chunk touch
			 * to avoid chunk verify/delete collision
			 */
			err = reptrans_touch_blob(dev, tt, hash_type,
				&msg->content_hash_id);
			if (err) {
				log_error(lg, "Dev(%s) blob touch error ttag %s: %d",
					dev->name, type_tag_name[tt], err);
				err = 0;
			}
		} else
			srv_getcommon_touch_blob_enqueue(dev, tt, hash_type,
				&msg->content_hash_id);
	}

	req->content_length = bstat.size;
	if (bstat.size > 0) {
		req->rtproposed = 1;
		req->reqtype = GET_REQ_TYPE_UNNAMED_RT;
		req->unnamed_rsp.immediate_content_length = 0;
		req->unnamed_rsp.content_length = bstat.size;
		err = unnamedget_create_proposal(msg->object_name.uvid_timestamp,
						msg->genid_delta, req, tt);
		if (err) {
			char chidstr[UINT512_BYTES * 2 + 1];
			uint512_dump(&msg->content_hash_id, chidstr,
			    UINT512_BYTES * 2 + 1);
			log_debug(lg, "UnnamedGet(%s): unable to create proposal"
			    " chunk: %s err=%d tt=%d ht=%d", dev->name,
			    chidstr, err, tt, hash_type);
			req->status = RT_ERR_UNKNOWN;
			return;
		}
		if (msg->hdr.attributes & RD_ATTR_CM_LEAF_WRITE) {
			struct blob_stat bstat = {.size = 0};
			/* Check presence of parity manifest and
			 * start recovery */
			err = reptrans_blob_stat(dev, TT_PARITY_MANIFEST,
				HASH_TYPE_DEFAULT, &msg->content_hash_id,
				&bstat);

			if (!err && bstat.size > 0) {
				char chidstr[UINT512_BYTES * 2 + 1];
				uint512_dump(&msg->content_hash_id, chidstr,
					UINT512_BYTES * 2 + 1);
				log_debug(lg, "UnnamedGet(%s): unencode request"
					" received %s", dev->name,
					chidstr);
				uint512_t nhid = uint512_null;
				rtbuf_t* refs = NULL;

				err = ec_recover_manifest_check(dev,
					&msg->content_hash_id, tt, &nhid, &refs);
				if (!err) {
					if (uv_sem_trywait(&dev->recover_sem))
						err = -EBUSY;
					else {
						err = ec_recover_manifest_exec(
							dev,
							&msg->content_hash_id,
							tt, &nhid, refs,
							RECOVER_REPLICATE);
						uv_sem_post(&dev->recover_sem);
					}
				}
				if (refs)
					rtbuf_destroy(refs);
				if (err == -EBUSY) {
					req->status = RT_ERR_NO_RESOURCES;
					log_debug(lg, "UnnamedGet(%s): %s device "
						"busy", dev->name, chidstr);
					return;
				} else if (err == MANIFEST_RECOVERY_UNENCODE_SUCCESS ||
					err < 0) {
					/* Parity manifest absent, skipped or
					 * successfully un-encoded.
					 * Proceed  with a regular response
					 */
					log_debug(lg, "UnnamedGet(%s): unencode "
						"request SUCCESS %s", dev->name,
						chidstr);
				} else if (err) {
					log_error(lg, "UnnamedGet(%s): "
						"CM %s recovery error %d",
						dev->name, chidstr, err);
					req->status = RT_ERR_UNENCODE;
					return;
				}
			}
		}
		req->chid = msg->content_hash_id;
		req->hash_type = hash_type;
		req->tt = tt;
		req->unnamed_rsp.content_hash_id = msg->content_hash_id;
		req->unnamed_rsp.num_datagrams = 1;

		// extract the address from the message. RT_TRANSFER is later
		// sent to this address.
		memcpy(&req->client_addr.sin6_addr,
					&msg->receive_tenant_addr, 16);
		req->client_addr.sin6_family = AF_INET6;
		req->client_addr.sin6_flowinfo = 0;
		req->client_addr.sin6_port = htons(msg->receive_tenant_port);
		req->client_addr.sin6_scope_id = ccow_daemon->if_indexes[0];

		req->rb_reply = NULL;
		req->status = 0;
		if (bstat.size <= DEV_PREFETCH_SIZE && !req->found_in_key_cache_size) {
			/*
			 * This also will override req->status in case of if
			 * verification fails or other error.
			 */
			srv_getcommon_rtsend_exec(arg);
		}
		return;
	} else {
		/*
		 * Retrieve CHID of supplied Name Hash ID
		 */
		rtbuf_t *rb;
		err = reptrans_get_blob(dev, tt, hash_type,
						&msg->content_hash_id, &rb);
		if (err == -ENOENT) {
			log_warn(lg, "Get(%s): chunk not found ENOENT", dev->name);
			uint512_logdump(lg, "CHID: ", &msg->content_hash_id);
			req->status = -ENOENT;
			return;
		} else if (err) {
			log_error(lg, "Get(%s): chunk: unknown error"
			    " RT_ERR_UNKNOWN", dev->name);
			uint512_logdump(lg, "NHID: ", &msg->content_hash_id);
			req->status = RT_ERR_UNKNOWN;
			return;
		}
		req->reqtype = GET_REQ_TYPE_UNNAMED;
		req->unnamed_rsp.content_hash_id = msg->content_hash_id;
		memcpy(&req->unnamed_rsp.vdevid, &dev->vdevid, sizeof (uint128_t));
		// unsolicited should fit into a datagram
		req->unnamed_rsp.num_datagrams = 1;
		req->unnamed_rsp.content_length = rtbuf_len(rb);
		req->unnamed_rsp.immediate_content_length
			= req->unnamed_rsp.content_length;
		req->rb_reply = rb;
		req->status = 0;
	}
}


static void
unnamedget_send_error(struct state *st, int status)
{
	struct getcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repmsg_unnamed_chunk_get *msg = &req->msg_in.unnamed_get;
	struct repmsg_generic *reply;
	int err = 0;

	fhrow_t row;
	struct replicast_object_name *ron = &msg->object_name;
	int ngcount = 0;
	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
	    (msg->hdr.attributes & (RD_ATTR_VERSION_MANIFEST | RD_ATTR_TARGETED
		| RD_ATTR_PARITY_MAP_VM | RD_ATTR_COMPOUND_TARGETED)) ?
	    &ron->name_hash_id : &msg->content_hash_id, &row, &ngcount), FH_LOCK_READ);
	if (err < 0 && err != -EAGAIN) {
		log_error(lg, "Unable to retrieve ngcount. err (%d): %s", err,
		    strerror(err));
	}
	if (ngcount <= 0)
		req->err.ngcount = 0;
	else
		req->err.ngcount = ngcount;

	if (!err)
		err = status;
	switch(err) {
	case -EINVAL:
		req->err.error = RT_ERR_NO_ACCESS;
		break;
	case -ENOENT:
	case -EEXIST:
		req->err.error = err;
		break;
	case -ENOMEM:
		req->err.error = RT_ERR_NO_RESOURCES;
		break;
	case -ENODEV:
		req->err.error = RT_ERR_BAD_NGCOUNT;
		break;
	default:
		req->err.error = RT_ERR_UNKNOWN;
		break;
	}

	req->err.num_datagrams = 1;
	req->err.vdevid = dev->vdevid;
	req->err.fddelta = ccowd_get_fddelta();
	reply = (struct repmsg_generic *) &req->err;
	req->inexec++;
	err = replicast_send(dev->robj, 0, RT_ERROR, reply,
	    (struct repmsg_generic *)msg, NULL, 0, NULL,
	    srv_getcommon_send_done, req, NULL);
	if (err) {
		req->inexec--;
		assert(req->inexec >= 0);
		log_error(lg, "Error sending %d st %p error %d", RT_ERROR, st, err);
	}
}

/*
 * ACTION: process RT_UNNAMED_CHUNK_GET request
 */
static void
unnamedget_srv__request(struct state *st)
{
	struct getcommon_srv_req *req = st->data;
	struct repmsg_unnamed_chunk_get *msg = &req->msg_in.unnamed_get;
	log_trace(lg, "st %p", st);
	int err = srv_getcommon_proposal_work(st, unnamedget_srv_exec,
			unnamedget_srv_done);
	if (err) {
		req->proposal_failed = 1;
		log_debug(lg, "Error starting proposal work st %p error %d",
			  st, err);
		/* Don't send -ENOENT if we aren't building a consensus */
		if (err == -ENOENT && !(msg->hdr.attributes & RD_ATTR_GET_CONSENSUS))
			state_next(st, EV_DONE);
		else {
			unnamedget_send_error(st, err);
			state_next(st, EV_ERR);
		}
	}
}

static void
unnamedget_srv__rtsend(struct state *st)
{
	struct getcommon_srv_req *req = st->data;

	log_trace(lg, "st %p", st);

	/* Request arrived from client via TCP */
	if (!req->accept_rcvd) {
		req->accept_rcvd = 1;
		srv_getcommon_setup_dummy_accept(req);
	}

	if (req->ctx->tcp_handle != NULL)
		req->client_addr = *(struct sockaddr_in6 *)&req->ctx->tcp_handle->toaddr;

	int err = srv_getcommon_rtsend_work(st, srv_getcommon_rtsend_exec,
					srv_getcommon_rtsend_done);
	if (err) {
		log_error(lg, "Error starting rtsend work st %p error %d",
			  st, err);
		state_next(st, EV_ERR);
	}
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_UNNAMED_CHUNK_GET, &unnamedget_srv__request, ST_WAIT, NULL },
{ ST_WAIT, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS, &srv_getcommon_accept_rcvd,
	ST_READY, NULL},
{ ST_READY, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS, &srv_getcommon_accept_rcvd,
	ST_READY, NULL},
{ ST_READY, RT_GET_RENDEZVOUS_TRANSFER, &unnamedget_srv__rtsend, ST_READY,
	&srv_getcommon_guard_rt_retry },
{ ST_WAIT, RT_GET_RENDEZVOUS_TRANSFER, &unnamedget_srv__rtsend, ST_READY,
	&srv_getcommon_guard_rt_retry },
{ ST_READY, EV_TIMEOUT, &srv_getcommon__rtfree, ST_READY, NULL},
{ ST_READY, RT_RENDEZVOUS_NACK, &srv_getcommon__rtfree, ST_TERM, NULL},
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_READY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &unnamedget_srv__error, ST_TERM, NULL }
};


int
unnamedget_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state)
{
	int err;
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct getcommon_srv_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	req->start_timer_req = je_malloc(sizeof (*req->start_timer_req));
	if (!req->start_timer_req) {
		je_free(req);
		return -ENOMEM;
	}
	req->start_timer_req->data = NULL;

	req->timer_req = je_malloc(sizeof (*req->timer_req));
	if (!req->timer_req) {
		je_free(req->start_timer_req);
		je_free(req);
		return -ENOMEM;
	}
	req->timer_req->data = NULL;

	req->start_timer_fd = uv_hpt_timer_init(req->dev->loop,
	    req->start_timer_req);
	if (req->start_timer_fd < 0) {
		err = req->start_timer_fd;
		je_free(req->timer_req);
		je_free(req->start_timer_req);
		je_free(req);
		log_error(lg, "PUT hpt start init error: %d", err);
		return err;
	}

	uv_timer_init(req->dev->loop, req->timer_req);

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = srv_getcommon_terminate;
	ctx->stat_cnt = &robj->stats.unnamedget_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	reptrans_io_avg(dev);
	return 0;
}
