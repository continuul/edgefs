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
#ifndef _GETCOMMON_H__
#define _GETCOMMON_H__

#include "reptrans.h"
#include "ccowd-impl.h"
#include "state.h"
#include "vmm_cache.h"
#include "rt_tcp.h"
#include "reptrans-flex.h"

enum get_req_type {
	GET_REQ_TYPE_UNKNOWN	= 0,
	GET_REQ_TYPE_NAMED	= 1,
	GET_REQ_TYPE_NAMED_RT	= 2,
	GET_REQ_TYPE_UNNAMED	= 3,
	GET_REQ_TYPE_UNNAMED_RT = 4
};

struct getcommon_srv_req {
	REQ_CLASS_FIELDS
	crypto_hash_t hash_type;
	struct vmmetadata md;
	struct repmsg_named_chunk_get_response named_rsp;
	struct repmsg_unnamed_chunk_get_response unnamed_rsp;
	struct repmsg_error err;
	volatile rtbuf_t *rb_reply;
	vmmc_entry_t *ent;
	int status;
	int prefetching;
	// added after rt was introduced
	uint64_t content_length;
	int rtproposed;
	int start_timer_fd;
	int retry;
	int proposal_failed;
	struct repmsg_accept_proposed_rendezvous last_msg;
	union {
		struct repmsg_unnamed_chunk_get unnamed_get;
		struct repmsg_named_chunk_get named_get;
	} msg_in;
	uint64_t delayed_start_us;
	UV_HPT_TIMER_T *start_timer_req;
	uv_timer_t *timer_req;
	type_tag_t tt;
	uint512_t chid;
	uint64_t attributes;
	struct sockaddr_in6 client_addr;
	enum get_req_type reqtype;
	uint64_t req_rcvd_time;
	uint64_t accept_timeout;
	uint64_t select_time_avg;
	uint64_t req_rtsend_start;
	uint64_t delta_time_est;
	uint8_t tcp_conn_wait_count;
	uint8_t tcp_connected_count;
	int accept_rcvd;
	uint8_t row_nonmember;
	uint64_t found_in_key_cache_size;
	uint64_t chunk_offset;
	rtbuf_t *rcvd_cache_rb;
};

#define SRV_GETCOMMON_MAX_RETRY		5
#define SRV_GET_RT_TIMEOUT_MS		75
#define SRV_GET_ACCEPT_TIMEOUT_MIN	3000000		/* UDP only */
#define SRV_GET_ACCEPT_TIMEOUT_MAX	10000000	/* UDP only */
#define GETCOMMON_DEFAULT_EST		50000

#define SRV_GET_ACCEPT_TIMEOUT_TCP	(30 * 1000000)	/* TCP: 30 secs cleanup */

int srv_getcommon_proposal_work(struct state *st, ccowtp_work_cb work_cb,
	ccowtp_after_work_cb after_work_cb );

void srv_getcommon_send_done(void *data, int err, int ctx_valid);

void srv_getcommon_terminate(struct state *st);

int srv_getcommon_send_response(struct state *st);

void srv_getcommon_accept_rcvd(struct state *st);

int srv_getcommon_find_window(uint128_t *vdevid, uint64_t req_len,
		struct replicast_rendezvous_proposal *proposal, uint64_t genid,
		uint64_t genid_delta, struct getcommon_srv_req *req, type_tag_t ttag);


void srv_getcommon_rtsend_exec(void* arg);

void srv_getcommon_rtsend_done(void* arg, int status);

void srv_getcommon__rtfree(struct state *st);

int srv_getcommon_reset(struct getcommon_srv_req *r);

int srv_getcommon_rtsend_work(struct state *st, ccowtp_work_cb work_cb,
		ccowtp_after_work_cb after_work_cb);

void srv_getcommon_setup_dummy_accept(struct getcommon_srv_req *req);

void srv_getcommon_rtsend(struct getcommon_srv_req *req);

int srv_getcommon_guard_rt_retry(struct state *st);

void srv_getcommon_rtsend_timeout(uv_timer_t *req, int status);

void srv_getcommon_tcp_connect(struct state *st);

void srv_getcommon_tcp_rtsend(struct state *st);

int srv_getcommon_guard_tcp_connect(struct state *st);

void srv_getcommon_touch_blob_enqueue(struct repdev* dev, type_tag_t ttag,
	crypto_hash_t ht, const uint512_t* chid);

#endif /* _GETCOMMON_H__ */

