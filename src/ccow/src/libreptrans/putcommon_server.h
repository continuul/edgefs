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
#ifndef _PUTCOMMON_SERVER_H__
#define _PUTCOMMON_SERVER_H__

#include "reptrans.h"
#include "ccowd-impl.h"
#include "state.h"
#include "rcvd_cache.h"
#include  "reptrans-flex.h"

enum put_req_type {
	PUT_REQ_TYPE_UNKNOWN	= 0,
	PUT_REQ_TYPE_NAMED	= 1,
	PUT_REQ_TYPE_NAMED_RT	= 2,
	PUT_REQ_TYPE_UNNAMED	= 3,
	PUT_REQ_TYPE_UNNAMED_RT = 4
};

#define NAMEDPUT_SOP_STATE_SCHEDULED	0x1
#define NAMEDPUT_SOP_STATE_DONE		0x2

struct putcommon_srv_req {
	REQ_CLASS_FIELDS
	crypto_hash_t hash_type;
	uint64_t rt_delta_timeout; /* proposed estimate, also used for rt timeout */
	uint64_t client_start_time; /* proposed to client */
	uint64_t pp_rcvd_time; /* server view of when the pp was received */
	uint64_t req_len;
	int vbuf_allocated;
	int vbuf_queued;
	int rt_acked;
	int rtfree_timer_fd;
	UV_HPT_TIMER_T *rtfree_timer_req;
	uv_timer_t *pp_timer_req;
	int pp_timer_retry;
	uint64_t rtfree_timeout;
	volatile int error;
	void *msg_pp;
	uv_buf_t payload[REPLICAST_DGRAM_MAX];
	int nbufs;
	int dgrams_rcvd;
	rtbuf_t *rb;
	struct vmmetadata md;
	volatile int status;
	enum put_req_type reqtype;
	int min;
	uint16_t ngcount;
	uint8_t vmm;
	volatile uint8_t serial_err;		/* send RT_ERROR for serial op error */
	int sop_state;			/* Indicates that serial operation
					 * is in progress */
	uint64_t sop_generation;	/* updated generation, passed to client via ACK */
	uint512_t chid;
};

#define PUTCOMMON_SELECT_TIME_MIN	60000		/* UDP only */
#define PUTCOMMON_SELECT_TIME_MAX	120000		/* UDP only */
#define PUTCOMMON_SELECT_TIME_TCP	(30 * 1000000)	/* TCP: 30secs cleanup */
#define PUTCOMMON_RT_FREE_TIME_MIN	500000
#define PUTCOMMON_RT_FREE_TIME_MAX	2000000
#define PUTCOMMON_RT_TIMER_NACK_FACTOR	24
#define PUTCOMMON_RT_TIMER_ENABLE_NACK	0

static inline void
putcommon_srv_set_req_status(struct putcommon_srv_req *req, int err, int status)
{
	req->serial_err = err ? 1 : 0;
	req->error = err;
	req->status = status;
}

void putcommon_srv__term(struct state *st);

void putcommon_srv_transfer(struct state *st, ccowtp_work_cb work_cb,
					ccowtp_after_work_cb after_work_cb );

void putcommon_srv__busy(struct state *st);

void putcommon_srv__error(struct state *st);

void putcommon_srv_payload_ack(struct state *st);

void putcommon_srv_rt_ack(struct state *st);

void putcommon_srv__send_accept(struct state *st);

void putcommon_srv__exists(struct state *st);

void putcommon_srv_rtfree(struct state *st);

void putcommon_srv_send_done(void *data, int err, int ctx_valid);

#endif  /* _PUTCOMMON_SERVER_H__ */


