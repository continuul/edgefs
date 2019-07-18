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
#ifndef _GETCOMMON_CLIENT_H__
#define _GETCOMMON_CLIENT_H__

#define CLIENT_GETCOMMON_TCP_RETRY_MAX	5

/*
 * Calculate reply count for Named Get concensus.
 * Only if fddelta => 0 we optimize concensus building logic with formula:
 *
 *    Nreplies + SyncNamed - 2 >= NGcount
 *
 * Where SyncNamed (i.e. sync_put_named) is cluster global parameter to
 * ensure how many Version Manifests copies has to be created.
 *
 * In case of active object replacements we may end up in a situation where
 * one of the disks purged old version entry while new disk not yet placed
 * new one. To workaround this corner case we alway require extra reply,
 * hence (Syncnamed - 2).
 *
 * Where Nreplies is sum of replies with latest generation ids and replies
 * with error, i.e. negative replies from VDEVs where NHID is not found in
 * its Name Index table.
 *
 * Where fddelta represents consistency bit. If less then zero then we missing
 * few failure domains, hence optimization logic must be disabled.
 */
#define REPLIES_CNT(_r) ( \
    (_r)->reply_count + (_r)->err_count + \
    (((_r)->reqtype == GET_REQ_TYPE_NAMED && \
     (_r)->fddelta >= 0 && (_r)->reply_count > 0 && (_r)->ngcount > 1) ? \
     ((_r)->tc->sync_put_named - 2) : 0))

void client_getcommon_init(struct state *st);

void client_getcommon_terminate(struct state *st);

void client_getcommon_send_proposal(struct state *st,
    enum replicast_opcode opcode, void *msg);

int client_getcommon_accept_response(struct state *st);

void client_getcommon_send_accept(struct state *st);

int client_getcommon_rcv_chunk(struct state *st);

int client_getcommon_guard_retry(struct state *st);

void client_getcommon_timeout(uv_timer_t *req, int status);

void client_getcommon_rttimeout(uv_poll_t *treq, int status, int events);

void client_getcommon_rttransfer(struct state *st);

int client_getcommon_reset(struct getcommon_client_req *r);

int client_getcommon_guard_resp(struct state *st);

int client_getcommon_find_window(struct getcommon_client_req *r);

void client_getcommon_send_timeout(uv_timer_t *req, int status);

int client_getcommon_guard_nack_consensus(struct state *st);

void client_getcommon_nack_rcvd(struct state *st);

void client_getcommon_process_payload(struct state *st);

void client_getcommon_tcp_connect(struct state *st);

void namedget_process_payload(struct state *st);

void unnamedget_process_payload(struct state *st);

int client_getcommon_error_consensus(struct state *st);

int client_getcommon_send_accept_guard(struct state *st);


#endif /* _GETCOMMON_CLIENT_H__ */
