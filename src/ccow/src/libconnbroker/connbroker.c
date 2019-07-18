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

#include <linux/limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>
#include <ctype.h>
#include <limits.h>

#include "connbroker.h"

int
cbr_init(struct connbroker *cbr, uv_loop_t *loop, char *name, void *owner)
{
	memset(cbr, 0, sizeof(*cbr));
	cbr->loop = loop;
	cbr->lepcount = 0;
	cbr->repcount = 0;
	snprintf(cbr->name, CONNBROKER_NAMESIZE, "%s", name);
	cbr->owner = owner;
	cbr->rrindex = 0;
	srandom((unsigned int) time(NULL));
	return 0;
}

void
cbr_destroy(struct connbroker *cbr)
{
	for (int i = 0; i < cbr->repcount; i++) {
		cbr_destroy_replicast_client(cbr->rbroker + i);
	}
}

int
cbr_add_local_endpoint(struct connbroker *cbr, char *addr, int port,
    int domain, int scopeid, uint32_t ifspeed)
{
	int index = cbr->lepcount;
	if (index >= CONNBROKER_ENDPOINT_MAX) {
		log_error(lg, "Broker: Maximum supported local endpoints: %d",
			CONNBROKER_ENDPOINT_MAX);
		return -EINVAL;
	}

	struct endpoint *ep = &cbr->lep[index];
	snprintf(ep->addr, INET6_ADDRSTRLEN, "%s", addr);
	ep->port = port;
	ep->domain = domain;
	ep->scopeid = scopeid;
	ep->ifspeed = ifspeed;
	cbr->lepcount++;
	return 0;
}

int
cbr_add_remote_endpoint(struct connbroker *cbr, char *addr, int port,
    int domain, int scopeid)
{
	if (cbr->repcount >= CONNBROKER_ENDPOINT_MAX) {
		log_error(lg, "Broker: Maximum supported remote endpoints: %d",
			CONNBROKER_ENDPOINT_MAX);
		return -EINVAL;
	}

	struct endpoint *ep = &cbr->rep[cbr->repcount];
	snprintf(ep->addr, INET6_ADDRSTRLEN, "%s", addr);
	ep->port = port;
	ep->domain = domain;
	ep->scopeid = scopeid;
	cbr->repcount++;
	return 0;
}

static int
cbr_init_replicast_server(struct replicast_broker *rbroker,
    struct connbroker *cbr, struct endpoint *lep)
{

	rbroker->cbr = cbr;
	rbroker->lep = *lep;
	rbroker->state = CBR_UNINIT;
	rbroker->robj = NULL;

	log_info(lg, "Broker(%s): Initializing replicast server (%d) %s:%d",
		rbroker->cbr->name, rbroker->index,
		rbroker->lep.addr,rbroker->lep.port);

	int retry_sec = 0;
	while (rbroker->robj == NULL && retry_sec < TCP_SERVER_INIT_TIMEOUT) {
		rbroker->robj = replicast_init_tcp_server(cbr->name, cbr->loop,
			lep->addr, lep->port, lep->domain, lep->scopeid,
			lep->ifspeed, CONNBROKER_TTL_DEFAULT, rbroker);
		if (rbroker->robj == NULL) {
			if (retry_sec == 0) {
				log_warn(lg, "Broker: IP address %s not available for bind. Adjusting to 0.0.0.0", lep->addr);
				strcpy(lep->addr, "0.0.0.0");
				retry_sec += 5;
				continue;
			}
			usleep(5000000);
			retry_sec += 5;
		}
	}
	if (rbroker->robj == NULL) {
		log_error(lg, "Broker: Failed to initialize replicast server");
		return -EINVAL;
	}

	rbroker->state = CBR_SERVE;
	return 0;
}

static void
cbr_destroy_replicast_server(struct replicast_broker *rbroker)
{
	if (rbroker->state == CBR_SERVE) {
		log_info(lg, "Broker(%s): Destroying replicast server (%d) %s:%d",
			rbroker->cbr->name, rbroker->index, rbroker->lep.addr, rbroker->lep.port);
		replicast_destroy_tcp_server(rbroker->robj);
	}
	rbroker->state = CBR_UNINIT;
}

int
cbr_start_server(struct connbroker *cbr)
{
	struct replicast_broker *rbroker;
	int i, err;

	for (i = 0; i < cbr->lepcount; i++) {
		rbroker = &cbr->rbroker[i];
		rbroker->index = i;

		err = cbr_init_replicast_server(rbroker, cbr, &cbr->lep[i]);
		if (err) {
			cbr_stop_server(cbr);
			return err;
		}
	}

	cbr->is_server = 1;
	return 0;
}

void
cbr_stop_server(struct connbroker *cbr)
{
	for (int i = 0; i < cbr->lepcount; i++)
		cbr_destroy_replicast_server(&cbr->rbroker[i]);
}

void
cbr_register_callback(struct connbroker *cbr, enum replicast_opcode opcode,
	repstate_init_func_t func)
{
	assert(cbr->is_server == 1);
	for (int i = 0; i < cbr->lepcount; i++)
		replicast_state_init(cbr->rbroker[i].robj, opcode, func);
}

void *cbr_get_owner(struct replicast *robj)
{
	struct replicast_broker *rbroker = robj->priv_data;
	return rbroker->cbr->owner;
}

int cbr_response_send(struct replicast *robj, struct repctx *ctx,
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    struct repmsg_generic *omsg, const uv_buf_t *bufs, unsigned int nbufs,
    replicast_send_cb cb, void *data, uint256_t *dgram_idx)
{
	return replicast_tcp_send2(robj, ctx, opcode, msg, omsg, bufs, nbufs,
		cb, data);
}

static int
cbr_init_replicast_client(struct replicast_broker *rbroker,
    struct connbroker *cbr, int domain)
{
	rbroker->cbr = cbr;
	rbroker->state = CBR_UNINIT;
	rbroker->robj = NULL;
	rbroker->avg_rt = 0;

	log_debug(lg, "Broker(%s): Initializing replicast client (%d)",
		cbr->name, rbroker->index);

	rbroker->robj = replicast_init_tcp_client(cbr->name, cbr->loop,
		domain, CONNBROKER_TTL_DEFAULT, rbroker);
	if (rbroker->robj == NULL) {
		log_error(lg, "Broker: Failed to initialize replicast client");
		return -EINVAL;
	}

	rbroker->robj->loop_thrid = uv_thread_self();

	rbroker->state = CBR_INIT;
	return 0;
}

void
cbr_unref_replicast_client(struct replicast_broker *rbroker) {
	if (rbroker->robj_ref > 0)
		rbroker->robj_ref--;

	log_debug(lg, "Unref Broker(%s) state: %d ref %d",
			rbroker->cbr->name, rbroker->state, rbroker->robj_ref);

	if (rbroker->state == CBR_FIN && !rbroker->robj_ref) {
		assert(rbroker->robj);
		je_free(rbroker->robj);
		rbroker->state = CBR_UNINIT;
	}
}

void
cbr_destroy_replicast_client(struct replicast_broker *rbroker)
{
	if (rbroker->state == CBR_INIT ||
	    rbroker->state == CBR_CONNECTING ||
	    rbroker->state == CBR_CONNECTED) {
		log_debug(lg, "Broker(%s) rbroker: %p state: %d,  Destroying replicast client (%d)",
			rbroker->cbr->name, rbroker, rbroker->state, rbroker->index);
		replicast_destroy_tcp_client(rbroker->robj);
		if (!rbroker->robj_ref) {
			je_free(rbroker->robj);
			rbroker->robj = NULL;
			rbroker->state = CBR_UNINIT;
		} else
			rbroker->state = CBR_FIN;
	}
}

int
cbr_start_client(struct connbroker *cbr)
{
	struct replicast_broker *rbroker;
	int i, err;

	cbr->lepcount = cbr->repcount;
	for (i = 0; i < cbr->lepcount; i++) {
		rbroker = &cbr->rbroker[i];
		rbroker->index = i;

		err = cbr_init_replicast_client(rbroker, cbr, cbr->rep[i].domain);
		if (err) {
			cbr_stop_client(cbr);
			return err;
		}
	}

	cbr->is_server = 0;
	return 0;
}

void
cbr_stop_client(struct connbroker *cbr)
{
	for (int i = 0; i < cbr->lepcount; i++)
		cbr_destroy_replicast_client(&cbr->rbroker[i]);
}

static void
cbr_connect_cb(void *data, int status)
{
	struct connbroker_context *brx = data;
	struct replicast_broker *rbroker = brx->rbroker;
	struct remoteinfo *rinfo = &brx->cbr->rinfo[rbroker->repindex];

	if (status) {
		log_warn(lg, "Broker: Connect failed. status %d", status);
		rinfo->fts = get_timestamp_us();
		rinfo->failed = 1;
		brx->conn_cb(brx->conn_cb_data, status);
		cbr_destroy_replicast_client(rbroker);
		return;
	}

	rbroker->state = CBR_CONNECTED;
	brx->conn_cb(brx->conn_cb_data, status);
}

int cbr_connect(struct connbroker_context *brx, rt_connect_cb cb, void *cb_data)
{
	struct replicast_broker *rb;

	rb = cbr_select_replicast_broker(brx);
	if (rb == NULL) {
		log_warn(lg, "Broker: No replicast connection available");
		return -EAGAIN;
	}

	brx->rbroker = rb;
	brx->conn_cb = cb;
	brx->conn_cb_data = cb_data;

	log_debug(lg, "Broker: Connecting replicast client(%d) rbroker: %p to %s:%d",
		rb->repindex, rb, rb->rep.addr, rb->rep.port);

	int err = replicast_tcp_connect2(rb, rb->rep.addr, rb->rep.port,
		rb->robj->ipv4, rb->rep.scopeid, cbr_connect_cb, brx);
	log_debug(lg, "Broker %p: Connect result: %d",	rb, err);
	if (err == -EEXIST) {
		return -EEXIST;
	}
	if (err) {
	    log_debug(lg, "Broker %p: destroying replicust client",	rb);
		cbr_destroy_replicast_client(rb);
		return err;
	}

	rb->state = CBR_CONNECTING;
	return 0;
}

static void
cbr_request_send_cb(void *data, int status, int ctx_valid)
{
	struct connbroker_context *brx = data;
	if (status) {
		log_warn(lg, "Broker %p: Send failed. status %d", brx->rbroker, status);
		brx->send_cb(brx->send_cb_data, status, ctx_valid);
		return;
	}

	log_debug(lg, "Broker %p: Request sent.", brx->rbroker);
	brx->send_cb(brx->send_cb_data, status, ctx_valid);
}

int
cbr_request_send(struct connbroker_context *brx, struct state *st,
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    const uv_buf_t *bufs, unsigned int nbufs, replicast_send_cb cb,
    void *data, uint256_t *dgram_idx)
{
	struct replicast_broker *rbroker = brx->rbroker;

	log_debug(lg, "Send: rbroker %p, state: %d, rbroker->robj: %p",
		rbroker, rbroker->state, rbroker->robj);

	struct repctx *ctx = repctx_init(rbroker->robj);
	if (ctx == NULL) {
		log_error(lg, "Broker: Failed to initialize replicast context");
		return -ENOMEM;
	}
	rbroker->robj_ref++;
	ctx->state = st;

	brx->ctx = ctx;
	brx->send_cb = cb;
	brx->send_cb_data = data;

	int err = replicast_tcp_send2(rbroker->robj, ctx, opcode, msg, NULL,
		bufs, nbufs, cbr_request_send_cb, brx);
	if (err) {
		log_error(lg, "Broker(%s): Failed to send request", rbroker->cbr->name);
		return err;
	}

	return 0;
}

int
cbr_init_context(struct connbroker_context *brx, struct connbroker *cbr)
{
	memset(brx, 0, sizeof(*brx));
	brx->cbr = cbr;
	return 0;
}

void
cbr_destroy_context(struct connbroker_context *brx)
{
}

void
cbr_update_response_time(struct connbroker_context *brx, uint64_t deltams)
{
	struct replicast_broker *rb = brx->rbroker;
	struct remoteinfo *rf = &brx->cbr->rinfo[rb->repindex];

	rb->avg_rt = (rb->avg_rt == 0) ? deltams : (rb->avg_rt + deltams) / 2;
	rf->avg_rt = (rf->avg_rt == 0) ? deltams : (rf->avg_rt + deltams) / 2;
}

static void
cbr_update_remote_failed(struct connbroker *cbr)
{
	struct remoteinfo *rinfo;
	uint64_t curts, delta;
	for (int i = 0; i < cbr->repcount; i++) {
		rinfo = &cbr->rinfo[i];
		if (!rinfo->failed)
			continue;
		curts = get_timestamp_us();
		delta = (curts - rinfo->fts) / 1000;
		if (delta < CBR_REMOTE_FAILURE_TIMEOUT)
			continue;
		log_warn(lg, "Broker(%s): Restoring failed remote connection %s:%d",
			cbr->name, cbr->rep[i].addr, cbr->rep[i].port);
		rinfo->failed = 0;
	}
}

static void
cbr_check_remote_failed(struct connbroker *cbr)
{
	struct replicast_broker *rb;
	struct remoteinfo *rinfo;
	rt_tcp_t *rtsock;
	struct sockaddr_in6 to_addr;
	int i, idx;

	for (i = 0; i < cbr->lepcount; i++) {
		rb = &cbr->rbroker[i];
		if (rb->state != CBR_CONNECTED) {
			log_debug(lg, "Broker(%s) rbroker: %p state: %d: Not connected", cbr->name, rb, rb->state);
			continue;
		}
		if (QUEUE_EMPTY(&rb->robj->rtsock_queue)) {
			// Connection is terminated by server
			log_warn(lg, "Broker(%s) rbroker: %p: Remote site %s:%d terminated "
			    "connection", cbr->name, rb, rb->rep.addr, rb->rep.port);
			idx = rb->repindex;
			cbr_destroy_replicast_client(rb);
			log_debug(lg, "Broker(%s) rbroker: %p: terminated state: %d"
			    "connection", cbr->name, rb, rb->state);
			rinfo = &cbr->rinfo[idx];
			rinfo->failed = 1;
			rinfo->fts = get_timestamp_us();
		}
	}
}

struct replicast_broker *
cbr_select_replicast_broker(struct connbroker_context *brx)
{
	struct connbroker *cbr = brx->cbr;
	struct replicast_broker *rb;
	struct remoteinfo *rinfo;
	struct endpoint *rep;
	int i, err, idx, found = 0;

	cbr_check_remote_failed(cbr);
	cbr_update_remote_failed(cbr);

	for (i = 0; i < cbr->repcount; i++) {
		idx = (i + cbr->rrindex) % cbr->repcount;
		rinfo = &cbr->rinfo[idx];
		if (rinfo->failed)
			continue;

		rb = &cbr->rbroker[idx];
		log_debug(lg, "Select Broker(%s) idx: %d, state: %d ref: %d",
			cbr->name, idx, rb->state, rb->robj_ref);
		if (rb->state == CBR_FIN && !rb->robj_ref) {
			assert(rb->robj);
			je_free(rb->robj);
			rb->state = CBR_UNINIT;
		}
		if (rb->state == CBR_UNINIT) {
			log_debug(lg, "Reconect Broker(%s) idx: %d", cbr->name, idx);
			rb->index = idx;
			rb->robj = NULL;
			rb->cbr = cbr;
			err = cbr_init_replicast_client(rb, cbr, cbr->rep[i].domain);
			if (err)
				continue;
		}

		if (rb->state != CBR_INIT && rb->state != CBR_CONNECTED)
			continue;

		rb->rep = cbr->rep[idx];
		rb->repindex = idx;
		found = 1;
		break;
	}

	if (!found)
		return NULL;

	cbr->rrindex = (idx + 1) % cbr->repcount;
	log_debug(lg, "Broker: Remote index: %d address selected %s:%d",
		idx, cbr->rep[idx].addr, cbr->rep[idx].port);
	return rb;
}

int
cbr_get_endpoint_info(struct endpoint *ep)
{
	struct ifaddrs *iflist, *p;
	int err, found = 0, scopeid = 0, domain;

	err = getifaddrs(&iflist);
	if (err) {
		log_error(lg, "getifaddrs failed");
		return -1;
	}

	char addr[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *t;
	struct sockaddr_in *s;
	p = iflist;
	while (p) {
		if (!p->ifa_addr) {
			p = p->ifa_next;
			continue;
		} else if (p->ifa_addr->sa_family == AF_INET) {
			s = (struct sockaddr_in *) p->ifa_addr;
			inet_ntop(AF_INET, &s->sin_addr, addr, INET_ADDRSTRLEN);
			domain = AF_INET;
		} else if (p->ifa_addr->sa_family == AF_INET6) {
			t = (struct sockaddr_in6 *) p->ifa_addr;
			inet_ntop(AF_INET6, &t->sin6_addr, addr, INET6_ADDRSTRLEN);
			scopeid = t->sin6_scope_id;
			domain = AF_INET6;
		} else {
			p = p->ifa_next;
			continue;
		}

		if (ep->ifname[0] != 0) {
			if ((strcmp(p->ifa_name, ep->ifname) == 0) &&
			    domain == ep->domain) {
				snprintf(ep->addr, INET6_ADDRSTRLEN, "%s", addr);
				ep->scopeid = scopeid;
				ep->domain = domain;
				found = 1;
				break;
			}
		} else if (ep->addr[0] != 0) {
			if (strcmp(addr, ep->addr) == 0) {
				strncpy(ep->ifname, p->ifa_name, IFNAMSIZ);
				ep->scopeid = scopeid;
				ep->domain = domain;
				found = 1;
				break;
			}
		}
		p = p->ifa_next;
	}
	freeifaddrs(iflist);

	if (!found) {
		log_warn(lg, "Failed to find interface info: %s, fallback to defaults",
			(ep->ifname[0] != 0) ? ep->ifname : ep->addr);
		if (ep->ifname[0] == 0)
			strncpy(ep->ifname, "eth0", IFNAMSIZ);
		ep->scopeid = 0;
		ep->domain = AF_INET;
		ep->ifspeed = 10000UL;
		return 0;
	}

	uint8_t duplex;
	uint8_t link_status;
	uint32_t ifspeed;
	int mtu;

	err = ethtool_info(ep->ifname, &ifspeed, &duplex, &link_status, &mtu);
	if (err) {
		log_error(lg, "Failed to find interface info: %s", ep->ifname);
		return -EINVAL;
	}

	if (duplex < 1) {
		log_error(lg, "Duplex mode required: %s", ep->ifname);
		return -EINVAL;
	}

	if (link_status == 0) {
		log_error(lg, "Link is down: %s", ep->ifname);
		return -EINVAL;
	}

	ep->ifspeed = ifspeed;
	return 0;
}

int
cbr_get_client_stat(struct connbroker *cbr, struct connbroker_stat *cs)
{
	struct replicast_broker *rb;
	struct remoteinfo *rinfo;

	if (cbr->lepcount == 0)
		return -EINVAL;

	for (int i = 0; i < cbr->lepcount; i++) {
		rb = &cbr->rbroker[i];
		rinfo = &cbr->rinfo[i];
		cs[i].state = rb->state;
		cs[i].lep = rb->lep;
		cs[i].rep = rb->rep;
		cs[i].failed = rinfo->failed;
	}

	return cbr->lepcount;
}

int
cbr_get_server_stat(struct connbroker *cbr, struct connbroker_stat *cs)
{
	struct replicast_broker *rb;

	if (cbr->lepcount == 0)
		return -EINVAL;

	for (int i = 0; i < cbr->lepcount; i++) {
		rb = &cbr->rbroker[i];
		cs[i].state = rb->state;
		cs[i].lep = rb->lep;
	}

	return cbr->lepcount;
}
