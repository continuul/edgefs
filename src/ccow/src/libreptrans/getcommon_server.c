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
#include "getcommon_server.h"
#include "putcommon_server.h"
#include "rcvd_cache.h"

void
srv_getcommon_touch_blob_enqueue(struct repdev* dev, type_tag_t ttag,
	crypto_hash_t ht, const uint512_t* chid) {

	struct touch_queue_entry* e = lfqueue_dequeue(dev->tchq_free);
	if (!e)
		log_info(lg, "Dev(%s) touch queue is out of entries", dev->name);

	e->chid = *chid;
	e->ttag = ttag;
	e->hash_type = ht;

	int err = lfqueue_enqueue(dev->tchq_inprog, e);
	if (err)
		log_error(lg, "Dev(%s) couldn't add an entry to the touch queue: %d",
			dev->name, err);
	reptrans_process_touch_queue(dev);
}


int srv_getcommon_proposal_work(struct state *st, ccowtp_work_cb work_cb,
	ccowtp_after_work_cb after_work_cb )
{
	struct getcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repwqe *wqe = ctx->wqe_in;
	uint512_t *ngroup = NULL;

	log_trace(lg, "st %p, wrk_cb %p after_wrk_cb %p seqid %d.%d ", st,
	    work_cb, after_work_cb, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (req->inexec) {
		log_debug(lg, "Cannot send GET response while in exec");
		return -1;
	}

	/*
	 * Do not participate in Gets proposals if we unavail...
	 */
	repdev_status_t status = reptrans_dev_get_status(dev);

	if (status == REPDEV_STATUS_UNAVAILABLE) {
		log_warn(lg, "Dev(%s): unavailable", dev->name);
		return -EINVAL;
	}

	/*
	 * Check to see if this vdev should participate in this
	 * row get or not based on the flexhash
	 */
	uint512_t *cache_lookup_chid;
	uint64_t need_generation = 0;
	if (ctx->opcode_in == RT_NAMED_CHUNK_GET) {
		struct repmsg_named_chunk_get *msg =
			(struct repmsg_named_chunk_get *)wqe->msg;
		req->select_time_avg = msg->select_time_avg;
		req->hash_type = msg->hdr.hash_type;
		assert(req->hash_type == HASH_TYPE_DEFAULT);
		req->attributes = msg->hdr.attributes;
		req->tt = attr_to_type_tag(msg->hdr.attributes);
		struct replicast_object_name *ron = &msg->object_name;
		ngroup = &ron->name_hash_id;
		need_generation = ron->generation;
		cache_lookup_chid = ngroup;
		memcpy(&req->msg_in.named_get, wqe->msg, sizeof (req->msg_in.named_get));
	} else if (ctx->opcode_in == RT_UNNAMED_CHUNK_GET) {
		struct repmsg_unnamed_chunk_get *msg =
			(struct repmsg_unnamed_chunk_get *)wqe->msg;
		req->select_time_avg = msg->select_time_avg;
		req->hash_type = msg->hdr.hash_type;
		req->attributes = msg->hdr.attributes;
		req->tt = attr_to_type_tag(msg->hdr.attributes);
		struct replicast_object_name *ron = &msg->object_name;
		ngroup = (msg->hdr.attributes & (RD_ATTR_VERSION_MANIFEST |
			RD_ATTR_TARGETED | RD_ATTR_PARITY_MAP_VM | RD_ATTR_COMPOUND_TARGETED)) ?
			&ron->name_hash_id : &msg->content_hash_id;
		cache_lookup_chid = &msg->content_hash_id;
		memcpy(&req->msg_in.unnamed_get, wqe->msg, sizeof (req->msg_in.unnamed_get));
	} else
		assert(0);
	ccowd_fhready_lock(FH_LOCK_READ);
	int found = flexhash_is_rowmember(SERVER_FLEXHASH, &dev->vdevid, ngroup);
	fhrow_t row;
	if (!found) {
		row = HASHROWID(ngroup, ccow_daemon->flexhash);
		log_warn(lg, "Get(%s): not a member of the row: %d . "
		    "Temporarily allow ", dev->name, row);
		req->row_nonmember = 1;
	}

	int ngcount;
	int err = flexhash_get_ngcount(SERVER_FLEXHASH, ngroup, &row, &ngcount);
	ccowd_fhready_unlock(FH_LOCK_READ);
	if (err < 0) {
		if (err != -EAGAIN ||
		    (!need_generation && ctx->opcode_in == RT_NAMED_CHUNK_GET)) {
			log_warn(lg, "Get(%s): Flexhash rebalancing going on, "
			    "delaying NAMED_GET", dev->name);
			return -EINVAL;
		}
	}
	req->unnamed_rsp.ngcount = ngcount;
	req->found_in_key_cache_size = 0;
	/* Check if we have it in recvd cache (NVDRAM) */
	struct putcommon_srv_req *preq = NULL;
	req->ent = NULL;

	if ( (req->reqtype == GET_REQ_TYPE_UNNAMED)
		|| ( req->reqtype == GET_REQ_TYPE_UNNAMED_RT) )
		preq = reptrans_lookup_rcvd_cache(dev->rcvd_cache, ngroup);
	if (preq) {
		req->found_in_key_cache_size = preq->req_len;
		assert(req->found_in_key_cache_size);
		log_debug(lg, "Get(%s): Found in RCVD cache len: %ld",
			dev->name, req->found_in_key_cache_size);
		req->rcvd_cache_rb = rtbuf_init_alloc(&preq->payload[0], preq->nbufs);
	} else if (ctx->opcode_in == RT_NAMED_CHUNK_GET && !need_generation &&
		   ccow_vmmcache_get(dev->vmm_ht, cache_lookup_chid, &req->ent)) {
		/* pass-through */
	} else if (ctx->opcode_in == RT_UNNAMED_CHUNK_GET ||
	    !(req->attributes & (RD_ATTR_QUERY|RD_ATTR_VERSIONS_QUERY))) {
		/* Check if we do not have it. Non-blocking bloom-filter call */
		int ttag = (ctx->opcode_in == RT_UNNAMED_CHUNK_GET) ? req->tt : TT_NAMEINDEX;

#if 0 /* For MDOnly debug purpose */
		if ((ttag == TT_CHUNK_PAYLOAD) && (req->attributes & RD_ATTR_ISGW_MDONLY)) {
			if (0 == (rand() % 128)) {
				printf("Dropped payload chunk\n");
				/* defientely not found, force ISGW to lookup */
				return -ENOENT;
			}
		}
#endif
		uint64_t blobsize;
		int maybe_exists = reptrans_blob_query(dev, ttag,
		    req->hash_type, cache_lookup_chid, &blobsize);
		if (!maybe_exists) {
			log_debug(lg, "Get(%s): %lX ttag=%s definitely not found - done",
			    dev->name, ngroup->u.u.u, type_tag_name[ttag]);
			/* defientely not found - do not schedule worker */
			return -ENOENT;
		}
		if (maybe_exists != -1 && is_keycache_tt(req->tt)) {
			if (maybe_exists != -EEXIST) {
				log_debug(lg, "Get(%s): chunk not found - done",
				    dev->name);
				return -ENOENT;
			}
			req->found_in_key_cache_size = blobsize;
			assert(blobsize);
			log_debug(lg, "Get(%s): %lX ttag=%s found, maybe_exists %d,  size %lu",
			    dev->name, cache_lookup_chid->u.u.u, type_tag_name[ttag],
			    maybe_exists, blobsize);
		}
	}

	req->req_rcvd_time = get_timestamp_us();

	if (req->attributes & RD_ATTR_UNICAST_TCP) {
		req->accept_timeout = SRV_GET_ACCEPT_TIMEOUT_TCP;
	} else {
		uint64_t weight = flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
		    dev, FH_IOTYPE_PUT);
		weight += flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
		    dev, FH_IOTYPE_GET);

		req->accept_timeout = ngcount *
			(SERVER_ALPHA_FACTOR + req->select_time_avg +
			 DEV_LOOP_DELAY_FACTOR * weight);
	}
	req->inexec++;
	dev->get_disk_qdepth++;
	assert(after_work_cb);
	if (req->ent || ((req->found_in_key_cache_size) && preq
	    && (ctx->opcode_in == RT_UNNAMED_CHUNK_GET)
	    && !(req->attributes & (RD_ATTR_CM_LEAF_WRITE | RD_ATTR_ONDEMAND_PREFETCH)))) {
		work_cb(req);
		after_work_cb(req, 0);
		return 0;
	}
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, work_cb, after_work_cb, req);
	return 0;
}

static void
getcommon_start_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
getcommon_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

void srv_getcommon_terminate(struct state *st)
{
	struct getcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p seqid %d.%d, inexec %d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, req->inexec);

	assert(ctx->opcode_in == RT_UNNAMED_CHUNK_GET ||
	    ctx->opcode_in == RT_NAMED_CHUNK_GET);
	assert(req->inexec >= 0);

	repctx_drop(req->ctx);
	assert(req->inexec != ~0L);
	if (req->inexec) {
		log_debug(lg, "request inexec %d, cannot terminate op %d",
		    req->inexec, ctx->opcode_in == RT_NAMED_CHUNK_GET);
		return;
	}

	assert(req->prefetching == 0);

	if (req->start_timer_req->data) {
		uv_hpt_timer_stop(req->start_timer_fd, req->start_timer_req);
		req->start_timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)req->start_timer_req,
	    getcommon_start_timer_close_cb);

	if (req->start_timer_fd > 0) {
		uv_hpt_timer_close(req->start_timer_fd, req->start_timer_req);
	}

	if (req->timer_req->data) {
		uv_timer_stop(req->timer_req);
		req->timer_req->data = NULL;
	}
	uv_close((uv_handle_t *)req->timer_req, getcommon_timer_close_cb);

	if (req->rb_reply) {
		rtbuf_destroy((rtbuf_t *)req->rb_reply);
		req->rb_reply = NULL;
	}

	req->inexec = ~0L;
	reptrans_dev_ctxfree_one(dev, req->ctx);
}

static void
srv_getcommon_accept_timeout(uv_timer_t *treq, int status)
{
	struct getcommon_srv_req *r = treq->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "treq %p, status %d seqid %d.%d", treq, status,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	log_debug(lg, "GET ACCEPT response timeout: %"PRIu64"  ",
			r->accept_timeout);

	if (treq->data) {
		uv_timer_stop(treq);
		treq->data = NULL;
	}

	// FIXME: Free up reservations?
	//
	state_event(ctx->state, EV_DONE);
}

void
srv_getcommon_send_done(void *data, int err, int ctx_valid)
{
	struct getcommon_srv_req *req = data;
	struct repctx *ctx = req->ctx;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
	    data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;
	assert(req->inexec >= 0);

	if (state_check(ctx->state, ST_TERM)) {
		srv_getcommon_terminate(ctx->state);
		return;
	}

	if (err) {
		log_error(lg, "Error %d while responding to named get",
		    err);
		if (ctx->attributes == RD_ATTR_UNICAST_TCP)
			state_event(ctx->state, RT_RENDEZVOUS_NACK);
		else
			state_event(ctx->state, EV_ERR);
		return;
	}

	/*
	 * If this is not RT, we want to be done.
	 * For named gets we also have rb_reply read - done.
	 */
	if (!req->rtproposed) {
		state_event(ctx->state, EV_DONE);
	} else {
		// need to wait for RT ACCEPT or abort request
		if (req->timer_req->data)
			uv_timer_stop(req->timer_req);
		req->timer_req->data = req;
		if (req->accept_timeout < SRV_GET_ACCEPT_TIMEOUT_MIN)
			req->accept_timeout = SRV_GET_ACCEPT_TIMEOUT_MIN;
		if (!(req->attributes & RD_ATTR_UNICAST_TCP) &&
		    req->accept_timeout > SRV_GET_ACCEPT_TIMEOUT_MAX)
			req->accept_timeout = SRV_GET_ACCEPT_TIMEOUT_MAX;
		req->accept_timeout /= 1000;
		uv_timer_start(req->timer_req, srv_getcommon_accept_timeout,
		    req->accept_timeout, 0);
	}
}

int
srv_getcommon_find_window(uint128_t *vdevid, uint64_t req_len,
		struct replicast_rendezvous_proposal *proposal, uint64_t genid, 
		uint64_t genid_delta, struct getcommon_srv_req *req, type_tag_t ttag)
{
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;

	log_trace(lg, "vdevid %p, req_len %ld, proposal %p, seqid %d.%d",
	    vdevid, (long)req_len, proposal, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	proposal->start_time = flexhash_estimate_client_start( genid,
					genid_delta, get_timestamp_us(),
					req->req_rcvd_time);

	// now compute the weight based on capacity, QD and other parameters
	uint64_t weight = flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
	    dev, FH_IOTYPE_GET);
	proposal->weight_io = weight;

	ccowd_fhready_lock(FH_LOCK_READ);
	req->delta_time_est = flexhash_estimate_delta_time(SERVER_FLEXHASH,
		vdevid, req_len, (ttag == TT_CHUNK_MANIFEST && dev->metadata_mask & 2) ?
			FH_IOTYPE_GET_M : FH_IOTYPE_GET,
		(ttag == TT_CHUNK_MANIFEST && dev->metadata_mask & 2) ?
			dev->stats.get4k_req_latency_m : dev->stats.get4k_req_latency,
		(ttag == TT_CHUNK_MANIFEST && dev->metadata_mask & 2) ?
			dev->stats.get64k_req_latency_m : dev->stats.get64k_req_latency,
		(ttag == TT_CHUNK_MANIFEST && dev->metadata_mask & 2) ?
			dev->stats.get512k_req_latency_m : dev->stats.get512k_req_latency);
	ccowd_fhready_unlock(FH_LOCK_READ);
	if (proposal->delta_time == (uint64_t)-1) {
		// do not participate
		log_debug(lg, "Unable to determine a valid delta time");
		return -1;
	}
	proposal->delta_time = req->delta_time_est + DEV_LOOP_DELAY_FACTOR * weight +
		proposal->weight_io * SERVER_ALPHA_FACTOR;
	if (dev->payload_put_min_kb && ttag == TT_CHUNK_PAYLOAD &&
	    req_len >= dev->payload_put_min_kb * 1024) {
		proposal->delta_time += 1000000UL;
	}

	req->delayed_start_us = req->select_time_avg;

	return 0;
}



static void
UV_HPT_TIMER_CB(srv_getcommon_delayed_start_timeout, *treq)
{
	struct state *st = treq->data;
	struct getcommon_srv_req *r = st->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "treq %p, seqid %d.%d", treq,
			ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (r->start_timer_req->data) {
		r->start_timer_req->data = NULL;
		uv_hpt_timer_stop(r->start_timer_fd, r->start_timer_req);
	}

	r->retry = 0; /* new timer */
	state_event(st, RT_GET_RENDEZVOUS_TRANSFER);
}


void
srv_getcommon_setup_dummy_accept(struct getcommon_srv_req *req)
{
	struct repwqe *wqe = req->ctx->wqe_in;

	if (req->timer_req->data) {
		uv_timer_stop(req->timer_req);
		req->timer_req->data = NULL;
	}

	if (req->start_timer_req->data) {
		req->start_timer_req->data = NULL;
		uv_hpt_timer_stop(req->start_timer_fd,
				  req->start_timer_req);
	}
	/*
	 * Build a dummy acccept message if
	 * RT_GET_RENDEZVOUS_TRANSFER is received via TCP earlier than
	 * RT_GET_ACCEPT_PROPOSED_RENDEZVOUS
	 */
	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;

	memset(&req->last_msg, 0, sizeof(req->last_msg));
	req->last_msg.num_datagrams = 1;
	req->last_msg.vdevid = req->dev->vdevid;
	req->last_msg.hdr = msg->hdr;
	assert(req->last_msg.hdr.attributes & RD_ATTR_UNICAST_TCP);

	assert(req->ctx->tcp_handle != NULL);
}

void
srv_getcommon_accept_rcvd(struct state *st)
{
	struct getcommon_srv_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repdev *dev = r->dev;
	struct repwqe *wqe = ctx->wqe_in;
	char vdevstr[64];
	int err;

	struct repmsg_accept_proposed_rendezvous *msg
		= (struct repmsg_accept_proposed_rendezvous *) wqe->msg;

	uint128_dump(&msg->vdevid, vdevstr, 64);
	log_trace(lg, "st %p seqid %d.%d selected vdevid %s",
		  st, ctx->sequence_cnt, ctx->sub_sequence_cnt, vdevstr);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	if (r->start_timer_req->data) {
		r->start_timer_req->data = NULL;
		uv_hpt_timer_stop(r->start_timer_fd, r->start_timer_req);
	}

	if (r->accept_rcvd) {
		log_debug(lg, "Accept already received ");
		return;
	}
	// if this is not us ( based on the vdev ) simply terminate
	if (uint128_cmp(&msg->vdevid, &dev->vdevid) != 0) {
		uint128_dump(&dev->vdevid, vdevstr, 64);
		log_debug(lg, "Device (%s-%s) not selected. dropping RT"
		    " negotiations", dev->name, vdevstr);
		state_next(st, EV_DONE);
		return;
	}
	// otherwise, do a delayed start for rt transfer
	// based on what we proposed.

	r->accept_rcvd = 1;
	r->last_msg = *msg;
	r->retry = 0;

	/* If TCP, initiate connections now */
	if (msg->hdr.attributes & RD_ATTR_UNICAST_TCP) {
		return;
	}

	if (r->delayed_start_us < 10000) {
		state_next(st, RT_GET_RENDEZVOUS_TRANSFER);
		return;
	}

	log_debug(lg, "GET Accept received kicking off delayed start %ld",
		  r->delayed_start_us);
	r->start_timer_req->data = st;
	err = uv_hpt_timer_start(r->start_timer_fd, r->start_timer_req,
				 r->delayed_start_us,
				 srv_getcommon_delayed_start_timeout);
	if (err) {
		r->start_timer_req->data = NULL;
		log_error(lg, "GET operation error %d on rendezvous accept send"
		    " due to delayed timer creation ", err);
		state_next(st, EV_ERR);
		return;
	}
}

static void
srv_getcommon_rtsend_onsend(void *data, int status, int ctx_valid)
{
	struct getcommon_srv_req *req = data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;

	log_trace(lg, "data %p, status %d, ctx_valid %d seqid %d.%d", data,
	    status, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	dev->get_net_tx--;
	req->inexec--;
	assert(req->inexec >= 0);

	if (state_check(ctx->state, ST_TERM)) {
		srv_getcommon_terminate(ctx->state);
		return;
	}

	if (status != 0) {
		log_error(lg, "GET send error %d on RT_TRANSFER", status);
		if (ctx->attributes == RD_ATTR_UNICAST_TCP) {
			int event;
			if (errno == EAGAIN || errno == EPIPE) {
				log_error(lg, "Reconnecting TCP");
				event = RT_INIT_TCP_CONNECT;
			} else {
				log_error(lg, "Sending NACK");
				/* TCP send error. Use UDP to send NACK */
				ctx->attributes = 0;
				event = RT_RENDEZVOUS_NACK;
			}
			state_event(ctx->state, event);
			return;
		} else {
			req->status = RT_ERR_EIO;
			state_event(ctx->state, EV_ERR);
			return;
		}
	}

	/*
	 * Calculating GET request averages now. It includes both disks,
	 * network as well as how fast we typically schedule the events.
	 */
	if (!req->prefetching && req->req_rtsend_start) {
		size_t reqlen = req->content_length;
		uint64_t delta = (uv_hrtime() - req->req_rtsend_start) / 1000;
		if (req->tt == TT_CHUNK_MANIFEST && dev->metadata_mask & 2) {
			if (reqlen < 65536) {
				uint64_t norm4k_latency = reptrans_normalized_latency(delta, reqlen, 4096);
				if (norm4k_latency > DEV_AVGLAT4K_MIN && norm4k_latency < DEV_AVGLAT4K_MAX)
					dev->stats.get4k_req_latency_m = avg_ring_update(&dev->get4k_req_avg_samples_m, norm4k_latency);
			} else if (reqlen < 524288) {
				uint64_t norm64k_latency = reptrans_normalized_latency(delta, reqlen, 65536);
				if (norm64k_latency > DEV_AVGLAT64K_MIN && norm64k_latency < DEV_AVGLAT64K_MAX)
					dev->stats.get64k_req_latency_m = avg_ring_update(&dev->get64k_req_avg_samples_m, norm64k_latency);
			} else {
				uint64_t norm512k_latency = reptrans_normalized_latency(delta, reqlen, 524288);
				if (norm512k_latency > DEV_AVGLAT512K_MIN && norm512k_latency < DEV_AVGLAT512K_MAX)
					dev->stats.get512k_req_latency_m = avg_ring_update(&dev->get512k_req_avg_samples_m, norm512k_latency);
			}
		} else {
			if (reqlen < 65536) {
				uint64_t norm4k_latency = reptrans_normalized_latency(delta, reqlen, 4096);
				if (norm4k_latency > DEV_AVGLAT4K_MIN && norm4k_latency < DEV_AVGLAT4K_MAX)
					dev->stats.get4k_req_latency = avg_ring_update(&dev->get4k_req_avg_samples, norm4k_latency);
			} else if (reqlen < 524288) {
				uint64_t norm64k_latency = reptrans_normalized_latency(delta, reqlen, 65536);
				if (norm64k_latency > DEV_AVGLAT64K_MIN && norm64k_latency < DEV_AVGLAT64K_MAX)
					dev->stats.get64k_req_latency = avg_ring_update(&dev->get64k_req_avg_samples, norm64k_latency);
			} else {
				uint64_t norm512k_latency = reptrans_normalized_latency(delta, reqlen, 524288);
				if (norm512k_latency > DEV_AVGLAT512K_MIN && norm512k_latency < DEV_AVGLAT512K_MAX)
					dev->stats.get512k_req_latency = avg_ring_update(&dev->get512k_req_avg_samples, norm512k_latency);
			}
		}
	}
	state_event(ctx->state, EV_DONE);
}

void
srv_getcommon_rtsend(struct getcommon_srv_req *req)
{
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	int err;

	log_trace(lg, "req %p seqid %d.%d rb %p", req, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, req->rb_reply);

	if (req->inexec) {
		log_debug(lg, "Cannot send GET RT TRANSFER while in exec");
		return;
	}

	struct repmsg_rendezvous_transfer msg;
	memset(&msg, 0, sizeof (msg));
	msg.hdr.hash_type = req->hash_type;
	msg.hdr.attributes = req->last_msg.hdr.attributes;
	msg.content_length = msg.hdr.data_len = req->content_length;
	msg.content_hash_id = req->chid;

	// replicast will internally chunk it to 64K. datagrams

	struct sockaddr_in6 *addrp = NULL;
	if ((msg.hdr.attributes & (RD_ATTR_UNICAST_UDP | RD_ATTR_UNICAST_TCP)))
		addrp = &req->client_addr;

	if (msg.hdr.attributes & RD_ATTR_UNICAST_TCP)
		ctx->attributes = RD_ATTR_UNICAST_TCP;

	struct repmsg_accept_proposed_rendezvous *accept_msg =
		(struct repmsg_accept_proposed_rendezvous *)&req->last_msg;
	req->inexec++;
	dev->get_net_tx++;

	err = replicast_send(dev->robj, ctx, RT_GET_RENDEZVOUS_TRANSFER,
		(struct repmsg_generic *) &msg,
		(struct repmsg_generic *) &req->last_msg,
		req->rb_reply->bufs, req->rb_reply->nbufs, addrp,
		srv_getcommon_rtsend_onsend, req, &accept_msg->dgram_idx);
	if (err) {
		log_error(lg, "GET Operation error %d on sending RT_TRANSFER",
		    err);
		dev->get_net_tx--;
		req->inexec--;
		assert(req->inexec >= 0);
		req->status = RT_ERR_EIO;
		if (ctx->attributes == RD_ATTR_UNICAST_TCP) {
			ctx->attributes = 0;
			state_event(ctx->state, RT_RENDEZVOUS_NACK);
		} else
			state_event(ctx->state, EV_ERR);
		return;
	}
	ctx->attributes = 0;
	req->status = 0;
}

void
srv_getcommon_rtsend_done(void *arg, int status)
{
	struct getcommon_srv_req *req = arg;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p wreq %p, req->status %d seqid %d.%d", st, arg,
		  req->status, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	dev->get_disk_qdepth--;
	req->inexec--;
	assert(req->inexec >= 0);

	if (state_check(st, ST_TERM)) {
		srv_getcommon_terminate(st);
		return;
	}


	if (req->status != 0) {
		state_event(st, RT_RENDEZVOUS_NACK);
		return;
	}

	if (!req->rb_reply) {
		log_error(lg, "Error st %p rb_reply %p", st, req->rb_reply);
		state_event(ctx->state, EV_ERR);
		return;
	}

	srv_getcommon_rtsend(req);
}

void
srv_getcommon_rtsend_exec(void* arg)
{
	struct getcommon_srv_req *r = arg;
	struct repctx *ctx = r->ctx;
	struct repdev *dev = r->dev;
	int err = 0;

	log_trace(lg, "wreq %p seqid %d.%d", arg, ctx->sequence_cnt,
						ctx->sub_sequence_cnt);

	// read the data from reptrans and send it to the one we received
	// accept from. blob_stat was already done when the GET request
	// was first received.

	uint512_logdump(lg, "rtsend_exec chid", &r->chid);

	if (r->reqtype != GET_REQ_TYPE_UNNAMED_RT) {
		r->status = 0;
		return;
	}

	rtbuf_t *rb;
	if (r->rcvd_cache_rb) {
		log_debug(lg, "Using the rtbuf from RCVD cache");
		rb = r->rcvd_cache_rb;
	} else {
		err = reptrans_get_blob(dev, r->tt, r->hash_type, &r->chid, &rb);
		// FIXME: all error cases send out a NACK
		if (err ==-ENOENT) {
			log_warn(lg, "Blob %lX disappeared", r->chid.u.u.u);
			r->status = -ENOENT;
			return;
		} else if (err) {
			log_error(lg, "Error reading the blob: %d", err);
			r->status = RT_ERR_EIO;
			return;
		}
		if (dev->verify_chid == 2 && r->tt != TT_PARITY_MANIFEST) {
			uint512_t tmp_chid;
			err = rtbuf_hash(rb, r->hash_type, &tmp_chid);
			if (err < 0) {
				log_error(lg, "Error calculating hash on blob get: %d",
				    err);
				rtbuf_destroy(rb);
				r->status = RT_ERR_BAD_CRED;
				return;
			}
			if (uint512_cmp(&r->chid, &tmp_chid) != 0) {
				rtbuf_destroy(rb);
				log_error(lg,
					"Get(%s): payload verification error detected "
					"seqid %d.%d", dev->name, ctx->sequence_cnt,
					ctx->sub_sequence_cnt);
				uint512_logdump(lg, "content_hash_id", &r->chid);
				uint512_logdump(lg, "read_chid", &tmp_chid);
				r->status = RT_ERR_BAD_CRED;
				return;
			}
		}

		if (ccow_daemon->enc_ctx && r->tt == TT_CHUNK_PAYLOAD &&
		    CRYPTO_ENC_EN(r->hash_type)) {
			rb = ccowd_host_decrypt(ccow_daemon->enc_ctx, rb);
		}
	}

	r->rb_reply = rb;
	r->status = 0;
}

int
srv_getcommon_rtsend_work(struct state *st, ccowtp_work_cb work_cb,
	ccowtp_after_work_cb after_work_cb )
{
	struct getcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p, wrk_cb %p after_wrk_cb %p seqid %d.%d", st,
	    work_cb, after_work_cb, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (req->inexec) {
		log_debug(lg, "Cannot execute GET while in exec %d",
			  req->inexec);
		return -1;
	}


	dev->get_disk_qdepth++;
	req->inexec++;
	assert(after_work_cb);

	if (req->rb_reply) {
		/* was successfully pre-fetched at proposal time - done */
		after_work_cb(req, 0);
		return 0;
	}

	if (req->prefetching) {
		/* increment to trigger rtsend_done */
		req->prefetching++;
		return 0;
	}

	req->req_rtsend_start = uv_hrtime();
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, work_cb, after_work_cb, req);
	return 0;
}

int
srv_getcommon_reset(struct getcommon_srv_req *r)
{
	struct repctx *ctx = r->ctx;
	log_trace(lg, "r %p seqid %d.%d", r, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);
	r->delayed_start_us = 0;
	r->proposal_failed = 0;
	return 0;
}

int
srv_getcommon_guard_rt_retry(struct state *st)
{
	struct getcommon_srv_req *r = st->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
						ctx->sub_sequence_cnt);
	r->retry++;

	if (r->retry > 1) {
		r->dev->stats.num_retransmit++;
		log_warn(lg, "GET RT TRANSFER attempt: %d"
		    " seqid %d.%d", r->retry, r->ctx->sequence_cnt,
		    r->ctx->sub_sequence_cnt - 1);
	}

	srv_getcommon_reset(r);

	if (r->retry < SRV_GETCOMMON_MAX_RETRY)
		return 1;

	log_error(lg, "GET RT TRANSFER timed out after %d attempts",
				r->retry);
	state_next(st, EV_TIMEOUT);
	return 0;
}

static void
srv_getcommon_nack_onsend(void *data, int status, int ctx_valid)
{
	struct getcommon_srv_req *req = data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;

	log_trace(lg, "data %p, status %d, ctx_valid %d seqid %d.%d", data,
	    status, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	dev->get_net_tx--;
	req->inexec--;
	assert(req->inexec >= 0);

	if (state_check(ctx->state, ST_TERM)) {
		srv_getcommon_terminate(ctx->state);
		return;
	}

	if (status != 0) {
		log_error(lg, "GET send error %d on RT_NACK", status);
		req->status = RT_ERR_EIO;
		state_event(ctx->state, EV_ERR);
		return;
	}

	state_event(ctx->state, EV_DONE);
}

void
srv_getcommon__rtfree(struct state *st)
{
	struct getcommon_srv_req *r = st->data;
	struct repdev *dev = r->dev;
	struct repctx *ctx = r->ctx;
	int err;
	struct repmsg_accept_proposed_rendezvous *msg;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	struct repmsg_rendezvous_nack nack;
	memset(&nack, 0, sizeof (nack));

	msg = &r->last_msg;
	memcpy(&nack.content_hash_id, &r->chid, sizeof (nack.content_hash_id));

	r->inexec++;
	dev->get_net_tx++;
	err = replicast_send(dev->robj, ctx, RT_RENDEZVOUS_NACK,
			(struct repmsg_generic *)&nack,
			(struct repmsg_generic *)msg,
			NULL, 0, NULL, srv_getcommon_nack_onsend, r, NULL);
	if (err) {
		r->inexec--;
		dev->get_net_tx--;
		log_error(lg, "Error sending NACK st %p seqid %d.%d", st,
			  ctx->sequence_cnt, ctx->sub_sequence_cnt);
		state_next(ctx->state, EV_ERR);
	}
}
