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
#ifndef __CONNBROKER_H__
#define __CONNBROKER_H__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "json.h"
#include "rtbuf.h"
#include "ccowutil.h"
#include "replicast.h"
#include "rt_tcp.h"

#define CONNBROKER_ENDPOINT_MAX	16
#define CONNBROKER_TTL_DEFAULT	64

#define CBR_REMOTE_FAILURE_TIMEOUT	1000	/* MS */
#define TCP_SERVER_INIT_TIMEOUT 200 /* Server connection timeout in sec */

#define CONNBROKER_NAMESIZE		REPLICAST_NAME_MAXSIZE

#define CBR_UNINIT	0	
#define CBR_INIT	1
#define CBR_CONNECTING	2
#define CBR_CONNECTED	3
#define CBR_SERVE	4
#define CBR_FIN		5 /* Finalize a client. Wait until all connection are closed */

// Connbroker chooses a local endpoint from the pool and
// uses it to transport data to one of the remote endpoints.

struct endpoint
{
	char ifname[IFNAMSIZ];
	char addr[INET6_ADDRSTRLEN];
	int port;
	int domain;
	int scopeid;
	uint32_t ifspeed;
};

struct replicast_broker
{
	struct endpoint lep;	/* Local IPV6 address, port */
	struct endpoint rep;	/* Remote IPV6 address, port */
	struct replicast *robj;	/* Replicast object */
	int robj_ref;		/* Replicast object reference counter */
	int state;		/* connection state */
	int index;		/* Index in the connbroker array */
	struct connbroker *cbr;
	int repindex;		/* Index of rep in the repcount array */
	uint64_t avg_rt;	/* Average response time */
	int failed;		/* True if local bind failed */
	uint64_t ts;		/* Last used timestamp */
	uint64_t fts;		/* Failure timestamp */
};

struct remoteinfo
{
	uint64_t avg_rt;	/* Average response time */
	int failed;		/* True if remote failed */
	uint64_t ts;		/* Last used timestamp */
	uint64_t fts;		/* Failure timestamp */
};

struct connbroker
{
	uv_loop_t *loop;
	char name[CONNBROKER_NAMESIZE];

	/* Array of local endpoints */
	struct endpoint lep[CONNBROKER_ENDPOINT_MAX];
	int lepcount;

	/* Array of remote endpoints */
	struct endpoint rep[CONNBROKER_ENDPOINT_MAX];
	struct remoteinfo rinfo[CONNBROKER_ENDPOINT_MAX];
	int repcount;
	int scopeid_status;

	/* Replicast specific data for client/server */
	struct replicast_broker rbroker[CONNBROKER_ENDPOINT_MAX];

	/* True if server */
	int is_server;

	/* Points to the upper layer */
	void *owner;

	/* Round-robin selection of remote endpoint */
	int rrindex;
};

struct connbroker_context
{
	struct connbroker *cbr;
	struct replicast_broker *rbroker;	/* Selected broker */
	rt_connect_cb conn_cb;			/* Connect callback */
	void *conn_cb_data;
	struct repctx *ctx;			/* Replicast context */
	replicast_send_cb send_cb;		/* Send callback */
	void *send_cb_data;
};

struct connbroker_stat
{
	struct endpoint lep;
	struct endpoint rep;
	int state;
	int failed;
};

// Public interfaces
int cbr_init(struct connbroker *cbr, uv_loop_t *loop, char *name, void *owner);
void cbr_destroy(struct connbroker *cbr);

int cbr_add_local_endpoint(struct connbroker *cbr, char *addr, int port,
    int domain, int scopeid, uint32_t ifspeed);
int cbr_add_remote_endpoint(struct connbroker *cbr, char *addr, int port,
    int domain, int scopeid);

int cbr_start_server(struct connbroker *cbr);
void cbr_stop_server(struct connbroker *cbr);

void cbr_register_callback(struct connbroker *cbr, enum replicast_opcode opcode,
    repstate_init_func_t func);
void *cbr_get_owner(struct replicast *robj);

int cbr_start_client(struct connbroker *cbr);
void cbr_stop_client(struct connbroker *cbr);

int cbr_init_context(struct connbroker_context *brx, struct connbroker *cbr);
void cbr_destroy_context(struct connbroker_context *brx);

int cbr_connect(struct connbroker_context *brx, rt_connect_cb cb, void *cb_data);

int cbr_request_send(struct connbroker_context *brx, struct state *st, 
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    const uv_buf_t *bufs, unsigned int nbufs, replicast_send_cb cb,
    void *data, uint256_t *dgram_idx);

int cbr_response_send(struct replicast *robj, struct repctx *ctx,
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    struct repmsg_generic *omsg, const uv_buf_t *bufs, unsigned int nbufs,
    replicast_send_cb cb, void *data, uint256_t *dgram_idx);

void cbr_update_response_time(struct connbroker_context *brx, uint64_t deltams);

int cbr_get_client_stat(struct connbroker *cbr, struct connbroker_stat *cs);

int cbr_get_server_stat(struct connbroker *cbr, struct connbroker_stat *cs);

int cbr_get_endpoint_info(struct endpoint *ep);

void
cbr_destroy_replicast_client(struct replicast_broker *rbroker);

void
cbr_unref_replicast_client(struct replicast_broker *rbroker);


// Private interfaces
struct replicast_broker *cbr_select_replicast_broker(
    struct connbroker_context *brx);

struct replicast *replicast_init_tcp_server(const char *name, uv_loop_t *loop,
    const char *listen_addr, const uint16_t listen_port, int domain,
    int scopeid, uint32_t ifspeed, const int ttl, void *data);
void replicast_destroy_tcp_server(struct replicast *robj);
struct replicast *replicast_init_tcp_client(const char *name, uv_loop_t *loop,
    int domain, const int ttl, void *priv);
void replicast_destroy_tcp_client(struct replicast *robj);

int replicast_tcp_connect2(struct replicast_broker *rbroker,
    const char *addr, const uint16_t port, int domain, int scopeid,
    rt_connect_cb cb, void *cb_data);
int replicast_tcp_send2(struct replicast *robj, struct repctx *ctx,
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    struct repmsg_generic *omsg, const uv_buf_t bufs[], unsigned int nbufs,
    replicast_send_cb cb, void *cb_data);

#endif

