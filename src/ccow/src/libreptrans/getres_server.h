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
#ifndef _GETRES_H__
#define _GETRES_H__

#include "reptrans.h"
#include "ccowd-impl.h"
#include "state.h"
#include "rt_tcp.h"

struct getres_srv_req {
	REQ_CLASS_FIELDS
	struct repmsg_res_get_response resget_rsp;
	struct repmsg_error err;
	int status;
	rtbuf_t *rb_reply;
	uv_buf_t req_payload;
	uv_timer_t *timer_req;
	uint8_t tcp_conn_wait_count;
	uint8_t tcp_connected_count;
};

#define SRV_GETRES_MAX_RETRY		5
#define SRV_GET_RT_TIMEOUT_MS		75

#endif /* _GETRES_H__ */

