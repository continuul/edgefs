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
#ifndef _PUT_COMMON__H
#define _PUT_COMMON__H

#include "state.h"
#include "replicast.h"
#include "ccow-impl.h"

#define CLIENT_PUTCOMMON_TCP_RETRY_MAX	9

int client_putcommon_init(struct state *st);

int client_putcommon_send_proposal(struct state *st,
				enum replicast_opcode opcode,
				void *msg, int isrt);

int client_putcommon_guard_retry(struct state *st);
int client_putcommon_reset(struct putcommon_client_req *r);
int client_putcommon_guard_proposed(struct state *st);

int client_putcommon_find_window(struct putcommon_client_req *r);

void client_putcommon_send_timeout(uv_timer_t *req, int status);

void client_putcommon_error(struct state *st);

void client_putcommon_busy(struct state *st);

void client_putcommon_process_busy(struct state *st);

int client_putcommon_guard__ack_consensus(struct state *st);

void client_putcommon_payload_ack(struct state *st);

void client_putcommon_payload_rcvd(struct state *st);

int client_putcommon_guard_rcvd_consensus(struct state *st);

void client_put_common_terminate(struct state *st);

void client_putcommon_nack_rcvd(struct state *st);

int client_putcommon_guard_nack_consensus(struct state *st);

int client_putcommon_guard_rt_retry(struct state *st);

void client_putcommon_rtsend(struct state *st);

int client_putcommon_check_policy(volatile struct flexhash *fhtable, uint8_t policy,
        uint8_t rc, struct putcommon_client_req *r);

void client_putcommon_tcp_rtsend(struct state *st);

void client_putcommon_tcp_connect(struct state *st);

int client_putcommon_guard_tcp_connect(struct state *st);

#endif /* _PUT_COMMON__H */
