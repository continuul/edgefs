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
#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <uv.h>

#include "ccowutil.h"
#include "replicast.h"
#include "queue.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define CCOW_NETWORK_MC_TTL	4	/* default multicast TTL value */
#define CCOW_NETWORK_PORT	10400	/* default CCOW server port */
#define CCOW_BROKER_PORT	50005	/* default CCOW broker port */
#define CCOW_GW_CACHE_PORT	60001	/* default CCOW broker port */

struct ccow;
struct ccow_network;

struct mc_group_server {
	QUEUE item;
	uint128_t serverid;
	uint128_t addr;
};

struct mc_group {
	QUEUE item;
	QUEUE servers;
	int num;
	struct ccow_network *netobj;
};

struct ccow_network {
	QUEUE groups;
	struct ccow *tc;
	char *unix_socket_addr;
	uv_pipe_t unix_socket;
	char *server_ip6addr;
	char *server_ip4addr;
	char *broker_interfaces;
	char *broker_ip4addr;
	int server_port;
	int server_if_index;
	struct sockaddr_in6 server_sockaddr;
	struct replicast *robj[REPLICAST_SRV_INTERFACES_MAX];
	char broker_ip6addr[REPLICAST_SRV_INTERFACES_MAX][NI_MAXHOST];
	int if_indexes[REPLICAST_SRV_INTERFACES_MAX];
	uint32_t if_speeds[REPLICAST_SRV_INTERFACES_MAX];
	int if_indexes_count;
	int broker_port;
	int mc_ttl;
};

int ccow_network_server_list_get(struct ccow_network *netobj);
struct ccow_network *ccow_network_init(struct ccow *tc);
void ccow_network_destroy(struct ccow_network *netobj);
void ccow_network_finish_destroy(struct ccow_network *netobj);
int client_notification_init(struct replicast *robj, struct repctx *ctx,
    struct state *state);
uint64_t lost_response_delay_ms(struct ccow_network *netobj);

#ifdef	__cplusplus
}
#endif

#endif
