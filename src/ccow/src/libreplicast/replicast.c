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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libgen.h>
#include <net/if.h>
#include <uv.h>

#include "msgpackalt.h"

#include "ccowutil.h"
#include "queue.h"
#include "logger.h"
#include "replicast.h"
#include "rt_tcp.h"
#include "reptrans.h"

#define TCP_EN 0
#undef DEBUG_CTX

char *replicast_opcode_str[] = {
	"RT_ERROR",
	"RT_SERVER_LIST_GET",
	"RT_SERVER_LIST_RESPONSE",
	"RT_NAMED_CHUNK_GET",
	"RT_NAMED_CHUNK_GET_RESPONSE",
	"RT_UNNAMED_CHUNK_GET",
	"RT_UNNAMED_CHUNK_GET_RESPONSE",
	"RT_RECOVERY",
	"RT_RECOVERY_ACK",
	"RT_NAMED_CHUNK_PUT_PROPOSAL",
	"RT_UNNAMED_CHUNK_PUT_PROPOSAL",
	"RT_NAMED_PAYLOAD_ACK",
	"RT_UNNAMED_PAYLOAD_ACK",
	"RT_ACCEPT_PROPOSED_RENDEZVOUS",
	"RT_GET_ACCEPT_PROPOSED_RENDEZVOUS",
	"RT_ACCEPT_CONTENT_ALREADY_STORED",
	"RT_ACCEPT_NOT_NOW",
	"RT_RENDEZVOUS_TRANSFER",
	"RT_GET_RENDEZVOUS_TRANSFER",
	"RT_RENDEZVOUS_ACK",
	"RT_RENDEZVOUS_NACK",
	"RT_PINGPONG",
	"RT_PINGPONG_ACK",
	"RT_NGREQUEST",
	"RT_NGREQUEST_ACK",
	"RT_NGREQUEST_COUNT",
	"RT_NGREQUEST_COUNT_ACK",
	"RT_NGREQUEST_PURGE",
	"RT_NGREQUEST_PURGE_ACK",
	"RT_NGREQUEST_LOCATE",
	"RT_NGREQUEST_LOCATE_ACK",
	"RT_BLOB_LOOKUP",
	"RT_BLOB_LOOKUP_ACK",
	"RT_BLOB_LOOKUP_RESULT",
	"RT_ENCODE_ACK",
	"RT_INIT_TCP_CONNECT",
	"RT_TCP_CONNECT_SUCCESS",
	"RT_PAYLOAD_RCVD",
	"RT_CLIENT_NOTIFICATION",
	"RT_SG_LOOKUP",
	"RT_SG_LOOKUP_RESPONSE",
	"RT_SG_CHUNKPUT",
	"RT_SG_CHUNKPUT_RESPONSE",
	"RT_SG_VMPUT",
	"RT_SG_VMPUT_RESPONSE",
	"RT_SG_SSPUT",
	"RT_SG_SSPUT_RESPONSE",
	"RT_OPP_STATUS",
	"RT_OPP_STATUS_ACK",
	"RT_ROWEVAC",
	"RT_ROWEVAC_ACK",
	"RT_SG_PING_PONG",
	"RT_SG_PING_PONG_RESPONSE",
	"RT_SG_EXPUNGE",
	"RT_SG_EXPUNGE_RESPONSE",
	"RT_SG_DYN_FETCH",
	"RT_SG_DYN_FETCH_RESP",
	"RT_RES_GET",
	"RT_RES_GET_RESPONSE",
	"RT_SG_CHUNKGET",
	"RT_SG_CHUNKGET_RESPONSE",
	"RT_MDONLY_PIN_ACK"
};

char *replicast_error_str[] = {
	"RT_OK",
	"RT_ERR_UNKNOWN",
	"RT_ERR_WRONG_OPCODE",
	"RT_ERR_EIO",
	"RT_ERR_NO_SPACE",
	"RT_ERR_BAD_CRED",
	"RT_ERR_NO_ACCESS",
	"RT_ERR_UNREACHABLE",
	"RT_ERR_NO_RESOURCES",
	"RT_ERR_NOT_EMPTY",
	"RT_ERR_BAD_NGCOUNT",
	"RT_ERR_STALE_FLEXHASH"
};

#define REP_IS_IP4(s) (!!strchr((s), '.') && !strchr((s), ':'))

int
replicast_pack_reptrans_ng(msgpack_p *p, struct repmsg_ng *msg);

int
replicast_unpack_reptrans_ng(msgpack_u *u, struct repmsg_ng *msg);

typedef int (*replicast_pack_func_t)(msgpack_p *, void *);

static replicast_pack_func_t replicast_pack_func[] = {
	(replicast_pack_func_t)replicast_pack_error,
	(replicast_pack_func_t)replicast_pack_server_list_get,
	(replicast_pack_func_t)replicast_pack_server_list_response,
	(replicast_pack_func_t)replicast_pack_named_chunk_get,
	(replicast_pack_func_t)replicast_pack_named_chunk_get_response,
	(replicast_pack_func_t)replicast_pack_unnamed_chunk_get,
	(replicast_pack_func_t)replicast_pack_unnamed_chunk_get_response,
	(replicast_pack_func_t)replicast_pack_recovery,
	(replicast_pack_func_t)replicast_pack_recovery_ack,
	(replicast_pack_func_t)replicast_pack_named_chunk_put_proposal,
	(replicast_pack_func_t)replicast_pack_unnamed_chunk_put_proposal,
	(replicast_pack_func_t)replicast_pack_named_payload_ack,
	(replicast_pack_func_t)replicast_pack_unnamed_payload_ack,
	(replicast_pack_func_t)replicast_pack_accept_proposed_rendezvous,
	(replicast_pack_func_t)replicast_pack_accept_proposed_rendezvous,
	(replicast_pack_func_t)replicast_pack_accept_content_already_stored,
	(replicast_pack_func_t)replicast_pack_accept_not_now,
	(replicast_pack_func_t)replicast_pack_rendezvous_transfer,
	(replicast_pack_func_t)replicast_pack_rendezvous_transfer,
	(replicast_pack_func_t)replicast_pack_rendezvous_ack,
	(replicast_pack_func_t)replicast_pack_rendezvous_nack,
	(replicast_pack_func_t)replicast_pack_pingpong,
	(replicast_pack_func_t)replicast_pack_pingpong,
	(replicast_pack_func_t)replicast_pack_reptrans_ng,
	(replicast_pack_func_t)replicast_pack_reptrans_ng,
	(replicast_pack_func_t)replicast_pack_reptrans_ng,
	(replicast_pack_func_t)replicast_pack_reptrans_ng,
	(replicast_pack_func_t)replicast_pack_reptrans_ng,
	(replicast_pack_func_t)replicast_pack_reptrans_ng,
	(replicast_pack_func_t)replicast_pack_reptrans_ng,
	(replicast_pack_func_t)replicast_pack_reptrans_ng,
	(replicast_pack_func_t)replicast_pack_blob_lookup,
	(replicast_pack_func_t)replicast_pack_blob_lookup_ack,
	(replicast_pack_func_t)replicast_pack_blob_lookup_result,
	(replicast_pack_func_t)replicast_pack_accept_content_already_stored,
	NULL,
	NULL,
	(replicast_pack_func_t)replicast_pack_payload_rcvd,
	(replicast_pack_func_t)replicast_pack_notification,
	(replicast_pack_func_t)replicast_pack_sg_lookup,
	(replicast_pack_func_t)replicast_pack_sg_lookup_response,
	(replicast_pack_func_t)replicast_pack_sg_chunkput,
	(replicast_pack_func_t)replicast_pack_sg_chunkput_response,
	(replicast_pack_func_t)replicast_pack_sg_vmput,
	(replicast_pack_func_t)replicast_pack_sg_vmput_response,
	(replicast_pack_func_t)replicast_pack_sg_ssput,
	(replicast_pack_func_t)replicast_pack_sg_ssput_response,
	(replicast_pack_func_t)replicast_pack_opp_status,
	(replicast_pack_func_t)replicast_pack_opp_status_result,
	(replicast_pack_func_t)replicast_pack_rowevac,
	(replicast_pack_func_t)replicast_pack_rowevac,
	(replicast_pack_func_t)replicast_pack_sg_ping_pong,
	(replicast_pack_func_t)replicast_pack_sg_ping_pong_response,
	(replicast_pack_func_t)replicast_pack_sg_expunge,
	(replicast_pack_func_t)replicast_pack_sg_expunge_response,
	(replicast_pack_func_t)replicast_pack_sg_dynfetch,
	(replicast_pack_func_t)replicast_pack_sg_dynfetch_response,
	(replicast_pack_func_t)replicast_pack_resget,
	(replicast_pack_func_t)replicast_pack_resget_response,
	(replicast_pack_func_t)replicast_pack_sg_chunkget,
	(replicast_pack_func_t)replicast_pack_sg_chunkget_response,
	(replicast_pack_func_t)replicast_pack_persistency_ack,
};

typedef int (*replicast_unpack_func_t)(msgpack_u *, void *);

static replicast_unpack_func_t replicast_unpack_func[] = {
	(replicast_unpack_func_t)replicast_unpack_error,
	(replicast_unpack_func_t)replicast_unpack_server_list_get,
	(replicast_unpack_func_t)replicast_unpack_server_list_response,
	(replicast_unpack_func_t)replicast_unpack_named_chunk_get,
	(replicast_unpack_func_t)replicast_unpack_named_chunk_get_response,
	(replicast_unpack_func_t)replicast_unpack_unnamed_chunk_get,
	(replicast_unpack_func_t)replicast_unpack_unnamed_chunk_get_response,
	(replicast_unpack_func_t)replicast_unpack_recovery,
	(replicast_unpack_func_t)replicast_unpack_recovery_ack,
	(replicast_unpack_func_t)replicast_unpack_named_chunk_put_proposal,
	(replicast_unpack_func_t)replicast_unpack_unnamed_chunk_put_proposal,
	(replicast_unpack_func_t)replicast_unpack_named_payload_ack,
	(replicast_unpack_func_t)replicast_unpack_unnamed_payload_ack,
	(replicast_unpack_func_t)replicast_unpack_accept_proposed_rendezvous,
	(replicast_unpack_func_t)replicast_unpack_accept_proposed_rendezvous,
	(replicast_unpack_func_t)replicast_unpack_accept_content_already_stored,
	(replicast_unpack_func_t)replicast_unpack_accept_not_now,
	(replicast_unpack_func_t)replicast_unpack_rendezvous_transfer,
	(replicast_unpack_func_t)replicast_unpack_rendezvous_transfer,
	(replicast_unpack_func_t)replicast_unpack_rendezvous_ack,
	(replicast_unpack_func_t)replicast_unpack_rendezvous_nack,
	(replicast_unpack_func_t)replicast_unpack_pingpong,
	(replicast_unpack_func_t)replicast_unpack_pingpong,
	(replicast_unpack_func_t)replicast_unpack_reptrans_ng,
	(replicast_unpack_func_t)replicast_unpack_reptrans_ng,
	(replicast_unpack_func_t)replicast_unpack_reptrans_ng,
	(replicast_unpack_func_t)replicast_unpack_reptrans_ng,
	(replicast_unpack_func_t)replicast_unpack_reptrans_ng,
	(replicast_unpack_func_t)replicast_unpack_reptrans_ng,
	(replicast_unpack_func_t)replicast_unpack_reptrans_ng,
	(replicast_unpack_func_t)replicast_unpack_reptrans_ng,
	(replicast_unpack_func_t)replicast_unpack_blob_lookup,
	(replicast_unpack_func_t)replicast_unpack_blob_lookup_ack,
	(replicast_unpack_func_t)replicast_unpack_blob_lookup_result,
	(replicast_unpack_func_t)replicast_unpack_accept_content_already_stored,
	NULL,
	NULL,
	(replicast_unpack_func_t)replicast_unpack_payload_rcvd,
	(replicast_unpack_func_t)replicast_unpack_notification,
	(replicast_unpack_func_t)replicast_unpack_sg_lookup,
	(replicast_unpack_func_t)replicast_unpack_sg_lookup_response,
	(replicast_unpack_func_t)replicast_unpack_sg_chunkput,
	(replicast_unpack_func_t)replicast_unpack_sg_chunkput_response,
	(replicast_unpack_func_t)replicast_unpack_sg_vmput,
	(replicast_unpack_func_t)replicast_unpack_sg_vmput_response,
	(replicast_unpack_func_t)replicast_unpack_sg_ssput,
	(replicast_unpack_func_t)replicast_unpack_sg_ssput_response,
	(replicast_unpack_func_t)replicast_unpack_opp_status,
	(replicast_unpack_func_t)replicast_unpack_opp_status_result,
	(replicast_unpack_func_t)replicast_unpack_rowevac,
	(replicast_unpack_func_t)replicast_unpack_rowevac,
	(replicast_unpack_func_t)replicast_unpack_sg_ping_pong,
	(replicast_unpack_func_t)replicast_unpack_sg_ping_pong_response,
	(replicast_unpack_func_t)replicast_unpack_sg_expunge,
	(replicast_unpack_func_t)replicast_unpack_sg_expunge_response,
	(replicast_unpack_func_t)replicast_unpack_sg_dynfetch,
	(replicast_unpack_func_t)replicast_unpack_sg_dynfetch_response,
	(replicast_unpack_func_t)replicast_unpack_resget,
	(replicast_unpack_func_t)replicast_unpack_resget_response,
	(replicast_unpack_func_t)replicast_unpack_sg_chunkget,
	(replicast_unpack_func_t)replicast_unpack_sg_chunkget_response,
	(replicast_unpack_func_t)replicast_unpack_persistency_ack,
};

struct repsend {
	struct replicast_transaction_id id;
	struct replicast *robj;
	struct repctx *ctx;
	struct repwqe *wqe;
	struct repmsg_generic *msg;
	struct repmsg_generic *omsg;
	replicast_send_cb cb;
	void *data;
	replicast_send_free_cb free_cb;
	msgpack_p *p;
	uv_buf_t *new_buf;
	uv_buf_t *outbufs;
	int outnum;
	unsigned int nbufs;
	struct sockaddr_in6 *to_addr;
	int to_addr_arrlen;
	int to_addr_sent;
	uint16_t num_datagrams;
	uint16_t datagram_num;
	int ctx_valid;
	int *sentcount;
};

int replicast_datagram_send(struct repsend *rsend, struct sockaddr_in6 *to_addr,
			    int dgram_num);
static void replicast_on_unixsock_connect(uv_connect_t *req, int status);

void
replicast_join_cache_cleanup(void *data)
{
	struct repdev *dev = data;
	struct mcjoin_queue_entry *entry;
	QUEUE *q;

	log_info(lg, "Dev(%s): Cleaning up IO replicast joins", dev->name);
	while (!QUEUE_EMPTY(&dev->mcjoin_queue)) {
		q = QUEUE_HEAD(&dev->mcjoin_queue);
		entry = QUEUE_DATA(q, struct mcjoin_queue_entry, item);
		QUEUE_REMOVE(q);
		replicast_leave(dev->robj, entry->mcgrp, entry->if_index);
		je_free(entry);
		dev->mcjoin_size--;
	}
}

void
replicast_join_cache_update(void *data, char *mcgrp, uint32_t if_index)
{
	struct repdev *dev = data;
	struct mcjoin_queue_entry *entry;
	QUEUE *q;
	QUEUE_FOREACH(q, &dev->mcjoin_queue) {
		entry = QUEUE_DATA(q, struct mcjoin_queue_entry, item);
		if (strcmp(entry->mcgrp, mcgrp) == 0) {
			log_debug(lg, "Dev(%s): Marking LRU MC %s",
				dev->name, mcgrp);
			entry->timestamp = get_timestamp_us();
			QUEUE_REMOVE(q);
			QUEUE_INIT(q);
			QUEUE_INSERT_TAIL(&dev->mcjoin_queue, q);
			return;
		}
	}

	entry = je_calloc(1, sizeof(*entry));
	if (!entry) {
		log_error(lg, "Failed to allocate LRU entry");
		return;
	}

	log_debug(lg, "Dev(%s): Inserting LRU MC %s", dev->name, mcgrp);
	QUEUE_INIT(&entry->item);
	strncpy(entry->mcgrp, mcgrp, INET6_ADDRSTRLEN);
	entry->if_index = if_index;
	entry->timestamp = get_timestamp_us();
	QUEUE_INSERT_TAIL(&dev->mcjoin_queue, &entry->item);
	dev->mcjoin_size++;
	return;
}

#define REPLICAST_JOIN_SIZE		100
#define REPLICAST_MAX_JOIN_SIZE		500
#define REPLICAST_LEAVE_MIN_TIMESPAN	60	/* Seconds */

int
replicast_join_throttle(void *data)
{
	struct repdev *dev = data;
	struct mcjoin_queue_entry *entry;
	uint64_t dt;
	QUEUE *q;

	if (dev->mcjoin_size < REPLICAST_JOIN_SIZE)
		return 0;

	log_debug(lg, "Dev(%s): LRU size %u, leaving stale replicast joins",
		dev->name,dev->mcjoin_size);
	q = QUEUE_HEAD(&dev->mcjoin_queue);
	while(q != &dev->mcjoin_queue) {
		entry = QUEUE_DATA(q, struct mcjoin_queue_entry, item);
		q = QUEUE_NEXT(q);

		dt = (get_timestamp_us() - entry->timestamp) / 1000000;
		if (dt < REPLICAST_LEAVE_MIN_TIMESPAN) {
			log_debug(lg, "Not leaving in-use MC %s", entry->mcgrp);
			break;
		}

		QUEUE *stale = QUEUE_PREV(q);
		QUEUE_REMOVE(stale);
		replicast_leave(dev->robj, entry->mcgrp, entry->if_index);
		je_free(entry);
		dev->mcjoin_size--;
	}

	if (dev->mcjoin_size > REPLICAST_MAX_JOIN_SIZE) {
		log_error(lg, "Dev(%s): Replicast join size exceeded max "
		    "allowed limit %u ", dev->name, REPLICAST_MAX_JOIN_SIZE);
		return -ECONNABORTED;
	}

	return 0;
}

static void
usock_close(uv_handle_t *handle)
{
	je_free(handle);
}

/*
 * Join receiver on a socket to a specified multicast group
 */
int
replicast_socket_join(uv_udp_t *socket, const char *mcgrp, uint32_t if_index,
    struct sockaddr_in6 *recv_addr)
{
	int err;

	if (recv_addr) {
		char ipv4_ifaddr[INET_ADDRSTRLEN + 1];
		char mcgrp4[INET_ADDRSTRLEN + 1];
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;

		replicast_ip4_decap(recv_addr, &addr4);
		inet_ntop(AF_INET, &addr4.sin_addr, ipv4_ifaddr, INET_ADDRSTRLEN);

		err = replicast_getaddrinfo(mcgrp, &addr6, 0);
		if (!err) {
			replicast_ip4_decap(&addr6, &addr4);
			inet_ntop(AF_INET, &addr4.sin_addr, mcgrp4, INET_ADDRSTRLEN);
			err = uv_udp_set_membership(socket, mcgrp4, ipv4_ifaddr, UV_JOIN_GROUP);
		} else
			log_error(lg, "Cannot get addr info : %d (%s)",
				    err, strerror(errno));
	} else {
		struct if_nameindex *if_ni = if_nameindex(), *i;
		assert(if_index);
		if (!if_ni) {
			log_error(lg, "if_nameindex error: cannot join receiver "
			    "multicast group: %s err=%d", mcgrp, errno);
			return -errno;
		}
		for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
			if (i->if_index == if_index)
				break;
		}
		err = uv_udp_set_membership(socket, mcgrp, i->if_name, UV_JOIN_GROUP);
		if_freenameindex(if_ni);
	}
	if (err) {
		if (err == -EADDRINUSE) {
			log_warn(lg, "Joined already.  mcgroup: %s ifidx %d",
			    mcgrp, if_index);
			err = 0;
		} else
			log_error(lg, "Cannot join multicast group %s ifidx %d err=%d",
			    mcgrp, if_index, err);
		return err;
	}
	log_debug(lg, "Joined successfully. mcgroup: %s if: %d",
	    mcgrp, if_index);
	return err;
}

/*
 * Join receiver to a specified multicast group
 */
int
replicast_join(struct replicast *robj, const char *mcgrp, uint32_t if_index)
{
	uv_udp_t *usock;
	int err;
	size_t n;

	usock = hashtable_get(robj->mc_recv_sockets, (void *) mcgrp,
		strlen(mcgrp), &n);
	if (usock) {
		log_debug(lg, "Rendezvous mcgrp %s already joined", mcgrp);
		return 0;
	}

	usock = je_malloc(sizeof (*usock));
	if (!usock)
		return -ENOMEM;

	err = replicast_start_listener(usock, robj, mcgrp, robj->mc_recv_port,
		if_index, robj->mc_ttl);
	if (err) {
		je_free(usock);
		log_error(lg, "Cannot start multicast listener: %d", err);
		return err;
	}

	log_info(lg, "Replicast(%s) listens on MC %s.%d usock %p", robj->name,
		mcgrp, robj->mc_recv_port, usock);

	err = replicast_socket_join(usock, mcgrp, if_index,
	    robj->ipv4 ? &robj->recv_addr : NULL);
	if (err)
		goto _exit;

	err = hashtable_put(robj->mc_recv_sockets, (char *)mcgrp, strlen(mcgrp),
		usock, sizeof (void *));
	if (err < 0) {
		log_error(lg, "Unable to insert usock into hashtable");
		goto _exit;
	}

	return 0;

_exit:
	(void) uv_udp_recv_stop(usock);
	uv_close((uv_handle_t *)usock, usock_close);
	return err;
}

/*
 * Leave multicast group
 */
int
replicast_socket_leave(uv_udp_t *socket, const char *mcgrp, uint32_t if_index,
    struct sockaddr_in6 *recv_addr)
{
	int err = 0;

	if (recv_addr) {
		char ipv4_ifaddr[INET_ADDRSTRLEN];
		char mcgrp4[INET_ADDRSTRLEN];
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;

		replicast_ip4_decap(recv_addr, &addr4);
		inet_ntop(AF_INET, &addr4.sin_addr, ipv4_ifaddr, INET_ADDRSTRLEN);

		err = replicast_getaddrinfo(mcgrp, &addr6, 0);
		if (!err) {
			replicast_ip4_decap(&addr6, &addr4);
			inet_ntop(AF_INET, &addr4.sin_addr, mcgrp4, INET_ADDRSTRLEN);
			err = uv_udp_set_membership(socket, mcgrp4, ipv4_ifaddr, UV_LEAVE_GROUP);
		} else
			log_error(lg, "Cannot get addr info : %d (%s)",
				    err, strerror(errno));
	} else {
		struct if_nameindex *if_ni = if_nameindex(), *i;
		assert(if_index);
		if (!if_ni) {
			log_error(lg, "if_nameindex error: cannot leave receiver "
			    "multicast group: %d", -errno);
			return -errno;
		}
		for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
			if (i->if_index == if_index)
				break;
		}
		err = uv_udp_set_membership(socket, mcgrp, i->if_name, UV_LEAVE_GROUP);
		if_freenameindex(if_ni);
	}
	if (err) {
		log_warn(lg, "Cannot leave receiver multicast group: %s "
		    "err: %d", mcgrp, err);
		return err;
	}

	return err;
}

int
replicast_leave(struct replicast *robj, const char *mcgrp, uint32_t if_index)
{
	size_t n;
	uv_udp_t *usock = hashtable_get(robj->mc_recv_sockets, (char *)mcgrp,
		strlen(mcgrp), &n);
	if (!usock) {
		log_warn(lg, "Cannot find MC address %s, never joined", mcgrp);
		return -ENOENT;
	}

	log_info(lg, "Replicast(%s) stopping MC %s.%d usock %p", robj->name,
		mcgrp, robj->mc_recv_port, usock);

	hashtable_remove(robj->mc_recv_sockets, (char *)mcgrp, strlen(mcgrp));

	int err = replicast_socket_leave(usock, mcgrp, if_index,
	    robj->ipv4 ? &robj->recv_addr : NULL);
	if (err)
		return err;

	err = uv_udp_recv_stop(usock);
	if (err) {
		log_error(lg, "Failed to stop socket err %d", err);
		return err;
	}

	uv_close((uv_handle_t *)usock, usock_close);
	return 0;
}

static int
replicast_add_wqe(struct repsend *rsend)
{
	struct repctx *ctx;
	int err = 0;

	assert(rsend != NULL);
	rsend->ctx_valid = 0;
	if (rsend->ctx) {
		/*
		 * Verify that context still valid. Its possible that
		 * objects can be freed at this point due to errors
		 * and as such we have to verify if swork->ctx pointer
		 * still found in ctxq.
		 */
		struct replicast *robj = rsend->robj;

		rsend->ctx_valid = repctx_is_ctx_valid(robj, rsend->ctx);
		if (rsend->ctx_valid &&
		    rsend->ctx->sequence_cnt == rsend->id.sequence_num) {
			/* create a new wqe, and add it to ctx->wq */
			rsend->wqe = repctx_wqe_init(rsend->ctx,
			    &rsend->id,
			    rsend->omsg ? &rsend->omsg->hdr.transaction_id : NULL,
			    rsend->data);
			if (!rsend->wqe) {
				err = -1;
				log_error(lg, "Send(%s): WQE: out of memory"
					      ": -ENOMEM", robj->name);
			}
		}
	}
	return err;
}

/* call back for every datagram-buffer send */
static void
on_datagram_send(struct repsend *rsend, int status)
{
	struct replicast *robj = rsend->robj;
	int err = 0;
	int ctx_valid = 0;

	if (status != 0) {
		log_debug(lg, "Send(%s): Failure status: %d datagram %d"
		    " of %d error= %s", robj->name,
		    status, rsend->datagram_num, rsend->num_datagrams,
		    strerror(errno));
		if (rsend->wqe) {
			repctx_wqe_destroy(rsend->wqe);
			rsend->wqe = NULL;
		}
	}

	int final = 1;
	if (rsend->to_addr_arrlen) {
		rsend->to_addr_sent++;
		final = rsend->to_addr_sent == rsend->to_addr_arrlen;
	}
	if (final && rsend->free_cb)
		rsend->free_cb(rsend, status, rsend->ctx_valid);
}

static void
on_udp_send(uv_handle_t *req, int status)
{
	log_trace(lg, "req %p, status %d", req, status);
	on_datagram_send(((uv_udp_send_t *)req)->data, status);
	je_free((uv_udp_send_t *)req);
}

static void
robj_rm_tcp_handle(uv_handle_t *peer)
{
	rt_tcp_t *rtsock = (rt_tcp_t *)peer;
	rt_tcp_t *temp, *handle;

	assert(peer != NULL);
	handle = rtsock->robj ? rtsock->robj->tcp_handles : NULL;

	if (handle != NULL && handle == (rt_tcp_t *)peer) {
		temp = handle;
		rtsock->robj->tcp_handles = temp->next;
		temp->robj = NULL;
	} else {
		while (handle != NULL) {
			if (handle->next != NULL &&
			    handle->next == (rt_tcp_t *)peer) {
				temp = handle->next;
				handle->next = temp->next;
				temp->robj = NULL;
				break;
			}
			handle = handle->next;
		}
	}
}

static int
robj_exists_tcp_handle(uv_handle_t *peer)
{
	rt_tcp_t *rtsock = (rt_tcp_t *)peer;
	rt_tcp_t *handle;

	assert(peer != NULL);
	handle = rtsock->robj ? rtsock->robj->tcp_handles : NULL;

	for(; handle != NULL; handle = handle->next)
		if (handle == rtsock)
			return 1;

	return 0;
}

/* Invoke flag would be used at termination */
static void
rtsock_finalize(rt_tcp_t *rtsock, int invoke_cb)
{
	rt_cbctx_t *tcp_cb;

	while((tcp_cb = lfqueue_dequeue(rtsock->cb_lfq)) != NULL) {
		/* Invoke with error as the connection is still pending */
		if (invoke_cb && tcp_cb->cb)
			tcp_cb->cb(tcp_cb->cb_data, -1);
		je_free(tcp_cb);
	}
	lfqueue_destroy(rtsock->cb_lfq);
	uv_mutex_destroy(&rtsock->conn_lock);
	je_free(rtsock);
}

static void
on_tcp_close(uv_handle_t *req)
{
	rt_tcp_t *rtsock = req->data;
	rtsock_finalize(rtsock, 1);
}

static void
on_tcp_shutdown(uv_shutdown_t *req, int status)
{
	log_trace(lg, "req %p, status %d", req, status);

	if (status) {
		log_error(lg, "Failed to shutdown TCP connection");
		return;
	}

	rt_tcp_t *rtsock = req->data;
	uv_read_stop((uv_stream_t *)&rtsock->tchandle);
	rt_tcp_sbuf_fini(&rtsock->stream.pbuf);
	rtsock->tchandle.data = rtsock;
	uv_close((uv_handle_t *)&rtsock->tchandle, on_tcp_close);
}

static void
shut_tcp_conn(rt_tcp_t *rtsock)
{
	log_debug(lg, "Shutting connection: %p", rtsock);

	robj_rm_tcp_handle((uv_handle_t *)rtsock);

	uv_shutdown_t *shutdown_req = &rtsock->sreq;
	shutdown_req->data = rtsock;
	uv_shutdown(shutdown_req, (uv_stream_t *)&rtsock->tchandle, on_tcp_shutdown);
}

static void
on_tcp_send(uv_handle_t *req, int status)
{
	uv_stream_t *stream = ((uv_write_t *)req)->handle;

	log_trace(lg, "req %p, status %d", req, status);
	on_datagram_send(((uv_write_t *)req)->data, status);
	if (status != 0) {
		/* Check if connection had been shutdown already */
		log_error(lg, "Error while sending TCP data %d", errno);
		int exists = robj_exists_tcp_handle((uv_handle_t *)stream);
		if (exists) {
			robj_rm_tcp_handle((uv_handle_t *)stream);
			uv_read_stop(stream);
			/*
			 * We can use shut_tcp_conn() after confirming that
			 * req is same as rt_tcp_t.
			 */
			uv_shutdown_t *req = je_malloc(sizeof *req);
			if (!req) {
				log_error(lg, "OOM on tcp send close");
				uv_close((uv_handle_t *)stream,
					  on_tcp_close);
			} else
				uv_shutdown(req, stream, on_tcp_shutdown);
		}
	}
	je_free((uv_write_t *)req);
}

static int
tcp_write(rt_tcp_t *rtsock, struct repsend *rsend)
{
	uv_stream_t *stream = (uv_stream_t *)&rtsock->tchandle;
	struct replicast *robj = rsend->robj;

	log_trace(lg, "tcp_write sending data stream %p, rsend %p",
			stream, rsend);

	uv_write_t *write_req = je_malloc(sizeof (*write_req));
	if (!write_req) {
		log_error(lg, "Send(%s): out of memory: -ENOMEM", robj->name);
		return -ENOMEM;
	}
	write_req->data = rsend;

	return uv_write(write_req, stream, rsend->outbufs, rsend->outnum,
			(uv_write_cb)on_tcp_send);
}

static void
on_unixsock_reopen(uv_handle_t *req)
{
	struct replicast *robj = req->data;
	uv_pipe_init(robj->loop, &robj->unixsock, 0);
	robj->unixsock_req.data = robj;
	robj->unixsock.data = robj;
	uv_pipe_connect(&robj->unixsock_req, &robj->unixsock, robj->listen_unixsock,
	    replicast_on_unixsock_connect);
	log_info(lg, "unixsocket %s reopened", robj->listen_unixsock);
}

/* replicast_send calls out to this function for each daatagram
 *
 */
int
replicast_datagram_send(struct repsend *rsend, struct sockaddr_in6 *to_addr,
    int dgram_num)
{
	struct replicast *robj = rsend->robj;
	struct repctx *ctx = rsend->ctx;
	struct repmsg_generic *msg = rsend->msg;
	struct repmsg_generic *omsg = rsend->omsg;
	enum replicast_opcode opcode = msg->hdr.transaction_id.opcode;
	int err = 0;

	assert(robj);

	/* use source_addr from original message as a recepient */
	struct sockaddr_in6 o_addr;
	if (omsg && !to_addr &&
			(!ctx ||
			(ctx && ctx->attributes != RD_ATTR_UNICAST_UNIXSOCK))) {
		o_addr.sin6_family = AF_INET6;
		o_addr.sin6_port = htons(omsg->hdr.transaction_id.source_port);
		memcpy(&o_addr.sin6_addr,
		    &omsg->hdr.transaction_id.source_addr, 16);
		o_addr.sin6_flowinfo = 0;
		o_addr.sin6_scope_id = robj->recv_addr.sin6_scope_id;
		to_addr = &o_addr;
	}

	if (unlikely(lg->level <= LOG_LEVEL_DUMP)) {
		char dst[INET6_ADDRSTRLEN], src[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &msg->hdr.transaction_id.source_addr, src, INET6_ADDRSTRLEN);

		int nwrite = 0;
		for (int i = 0; i < rsend->outnum; i++)
			nwrite += rsend->outbufs[i].len;

		if (ctx && ctx->attributes == RD_ATTR_UNICAST_UNIXSOCK) {

			log_debug(lg, "Send(%s,UNIXSOCK): %s ctx %p txcookie %" PRIx64 " seqid %d.%d "
			    "orig_id %d.%d orig.txcookie %" PRIx64 " from %s.%d to unixsock datagram %d num_datagrams: %d nwrite: %d",
			    robj->name, replicast_opcode_str[opcode], ctx, ctx ? ctx->txcookie : 0,
			    msg->hdr.transaction_id.sequence_num,
			    msg->hdr.transaction_id.sub_sequence_num,
			    msg->hdr.orig_id.sequence_num,
			    msg->hdr.orig_id.sub_sequence_num,
			    msg->hdr.orig_id.txcookie, src, msg->hdr.transaction_id.source_port,
			    dgram_num, msg->num_datagrams, nwrite);

		} else if (rsend->to_addr_arrlen) {

			for (int i = 0; i < rsend->to_addr_arrlen; i++) {
				inet_ntop(AF_INET6, &to_addr[i].sin6_addr, dst, INET6_ADDRSTRLEN);
				log_debug(lg, "Send(%s,UDP_MCPROXY): %s ctx %p txcookie %" PRIx64 " seqid %d.%d "
				    "orig_id %d.%d orig.txcookie %" PRIx64 " from %s.%d to %s.%d.%d datagram %d num_datagrams: %d nwrite: %d",
				    robj->name, replicast_opcode_str[opcode], ctx, ctx ? ctx->txcookie : 0,
				    msg->hdr.transaction_id.sequence_num,
				    msg->hdr.transaction_id.sub_sequence_num,
				    msg->hdr.orig_id.sequence_num,
				    msg->hdr.orig_id.sub_sequence_num,
				    msg->hdr.orig_id.txcookie, src, msg->hdr.transaction_id.source_port, dst,
				    ntohs(to_addr[i].sin6_port), robj->recv_addr.sin6_scope_id,
				    dgram_num, msg->num_datagrams, nwrite);
			}
		} else {

			inet_ntop(AF_INET6, &to_addr->sin6_addr, dst, INET6_ADDRSTRLEN);

			log_debug(lg, "Send(%s,UDP): %s ctx %p txcookie %" PRIx64 " seqid %d.%d "
			    "orig_id %d.%d orig.txcookie %" PRIx64 " from %s.%d to %s.%d.%d datagram %d num_datagrams: %d nwrite: %d",
			    robj->name, replicast_opcode_str[opcode], ctx, ctx ? ctx->txcookie : 0,
			    msg->hdr.transaction_id.sequence_num,
			    msg->hdr.transaction_id.sub_sequence_num,
			    msg->hdr.orig_id.sequence_num,
			    msg->hdr.orig_id.sub_sequence_num,
			    msg->hdr.orig_id.txcookie, src, msg->hdr.transaction_id.source_port, dst,
			    ntohs(to_addr->sin6_port), to_addr->sin6_scope_id,
			    dgram_num, msg->num_datagrams, nwrite);
		}

		if ((opcode == RT_RENDEZVOUS_TRANSFER)
		    || (opcode == RT_GET_RENDEZVOUS_TRANSFER)) {
			int j = (rsend->outnum == 2) ? 1 : 0;
			uint512_t cchid;
			char cchidstr[UINT512_BYTES*2 + 1];

			err = crypto_hash_with_type((crypto_hash_t)msg->hdr.hash_type,
			    (uint8_t *)rsend->outbufs[j].base, rsend->outbufs[j].len,
			    (uint8_t *)&cchid);
			uint512_dump(&cchid, cchidstr, UINT512_BYTES*2 + 1);

			log_debug(lg, "datagram: %d chid: %s", dgram_num,
			    cchidstr);
		}
	}

	/* uv_udp_send6 returns -1 with errno set to 11 or 17.
	 * unclear of this random error code return, we retry
	 */
	int udp_retry = REPLICAST_UDP6_SEND_RETRY;
	int arr_send_cont = 0;
	while (udp_retry > 0) {
		if (udp_retry <= REPLICAST_UDP6_SEND_RETRY-1)
			log_warn(lg, "Send(%s): uv_udp_send6 retry %d"
			    " last_errno=%d", robj->name, udp_retry, errno);
		if (!robj->send_socket.loop) {
			err = -EINVAL;
			break;
		}

		if (rsend->to_addr_arrlen) {

			for (int i = arr_send_cont; i < rsend->to_addr_arrlen; i++) {

				uv_udp_send_t *req = je_malloc(sizeof (*req));
				if (!req) {
					log_error(lg, "Send(%s): out of memory: -ENOMEM", robj->name);
					return -ENOMEM;
				}
				req->data = rsend;

				if (REP_IS_4OVER6(&to_addr[i])) {
					struct sockaddr_in to_addr4;
					replicast_ip4_decap(&to_addr[i], &to_addr4);
					to_addr4.sin_port = to_addr[i].sin6_port;
					if (unlikely(lg->level <= LOG_LEVEL_DUMP)) {
						char dst[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &to_addr4.sin_addr, dst, INET_ADDRSTRLEN);
						log_debug(lg, "Send(%s,4OVER6): %s to %s:%d",
						    robj->name, replicast_opcode_str[opcode], dst, ntohs(to_addr[i].sin6_port));
					}
					err = uv_udp_send(req, &robj->send_socket, rsend->outbufs,
					    rsend->outnum, to_addr4, (uv_udp_send_cb)on_udp_send);
				} else {
					/* assign scope_id for outcoming message */
					to_addr[i].sin6_scope_id = robj->recv_addr.sin6_scope_id;

					err = uv_udp_send6(req, &robj->send_socket, rsend->outbufs,
					    rsend->outnum, to_addr[i], (uv_udp_send_cb)on_udp_send);
				}
				if (err) {
					arr_send_cont = i;
					je_free(req);
					break;
				}
			}
		} else {

			if (!ctx || ctx->attributes != RD_ATTR_UNICAST_UNIXSOCK) {

				uv_udp_send_t *req = je_malloc(sizeof (*req));
				if (!req) {
					log_error(lg, "Send(%s): out of memory: -ENOMEM", robj->name);
					return -ENOMEM;
				}
				req->data = rsend;

				if (REP_IS_4OVER6(to_addr)) {
					struct sockaddr_in to_addr4;
					replicast_ip4_decap(to_addr, &to_addr4);
					to_addr4.sin_port = to_addr->sin6_port;
					if (unlikely(lg->level <= LOG_LEVEL_DUMP)) {
						char dst[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &to_addr4.sin_addr, dst, INET_ADDRSTRLEN);
						log_debug(lg, "Send(%s,4OVER6): %s to %s:%d",
						    robj->name, replicast_opcode_str[opcode], dst, ntohs(to_addr->sin6_port));
					}
					err = uv_udp_send(req, &robj->send_socket, rsend->outbufs,
					    rsend->outnum, to_addr4, (uv_udp_send_cb)on_udp_send);
				} else {
					err = uv_udp_send6(req, &robj->send_socket, rsend->outbufs,
					    rsend->outnum, *to_addr, (uv_udp_send_cb)on_udp_send);
				}
				if (err)
					je_free(req);
			} else if (ctx) {

				uv_write_t *req = je_malloc(sizeof (uv_write_t));
				if (!req) {
					log_error(lg, "Send(%s): out of memory: -ENOMEM", robj->name);
					return -ENOMEM;
				}
				req->data = rsend;

				if (omsg && omsg->hdr.peer_sock) {
					err = uv_write(req, (uv_stream_t*)omsg->hdr.peer_sock,
						rsend->outbufs, rsend->outnum, (uv_write_cb)on_udp_send);
				} else {
					err = uv_write(req, (uv_stream_t*)&robj->unixsock,
						rsend->outbufs, rsend->outnum, (uv_write_cb)on_udp_send);
				}
				if (err)
					je_free(req);
			}
		}
		if (err == 0)
			break;
		else
			usleep(1);
		udp_retry--;
	}
	if (err) {
		log_warn(lg, "Send(%s): UDP send error: %d errno=%d",
			  robj->name, err, errno);

		/* attempt to recover unixsock */
		if (opcode == RT_SERVER_LIST_GET &&
		    ctx && ctx->attributes == RD_ATTR_UNICAST_UNIXSOCK) {
			if (robj->unixsock.data)
				uv_close((uv_handle_t *)&robj->unixsock, on_unixsock_reopen);
			else {
				/* socket already closed - reopen now */
				robj->unixsock.data = robj;
				on_unixsock_reopen((uv_handle_t *)&robj->unixsock);
			}
		}
	}
	return err;
}

static int
replicast_prepare_header(struct replicast *robj, struct repctx *ctx,
			 enum replicast_opcode opcode,
			 struct repmsg_generic *msg,
			 struct repmsg_generic *omsg, msgpack_p **out_p,
			 uint32_t *datagram_num_byte,
			 uint32_t *num_datagrams_byte, uint16_t fhrow)
{
	int err;

	if (out_p == NULL)
		return -EINVAL;

	/*
	 * Message Packer will dynamically allocate memory for
	 * the messages and as such we will simply point to the
	 * result buffer as outbufs[0] and increment nbufs by 1.
	 */
	msgpack_p *p = msgpack_pack_init();
	if (!p) {
		log_error(lg, "Send(%s): out of memory: -ENOMEM", robj->name);
		return -ENOMEM;
	}

	/*
	 * Prepare Replicast generic header
	 */
	msg->hdr.transaction_id.opcode = opcode;
	msg->hdr.transaction_id.txcookie = ctx ? ctx->txcookie : 0;
	if (ctx && ctx->attributes == RD_ATTR_UNICAST_TCP) {
		msg->hdr.transaction_id.source_port = robj->tcp_recv_port;
		memcpy(&msg->hdr.transaction_id.source_addr,
		    &robj->msg_origin_tcpaddr.sin6_addr, 16);
	} else {
		msg->hdr.transaction_id.source_port = robj->udp_recv_port;
		memcpy(&msg->hdr.transaction_id.source_addr,
			&robj->msg_origin_udpaddr.sin6_addr, 16);
	}
	msg->hdr.transaction_id.sequence_num = ctx ?
		ctx->sequence_cnt : robj->sequence_cnt++;
	msg->hdr.transaction_id.sub_sequence_num = ctx ?
		ctx->sub_sequence_cnt : 1;
	if (omsg) {
		memcpy(&msg->hdr.orig_id, &omsg->hdr.transaction_id,
		    sizeof (msg->hdr.orig_id));
	}

	if (robj->client_ctx) {
		msg->hdr.fh_genid = flexhash_get_genid(FH_GENID_CLIENT,
							robj->client_ctx);
	} else if (robj->server_ctx) {
		msg->hdr.fh_genid = flexhash_get_genid(FH_GENID_SERVER,
							robj->server_ctx);
	}

	msg->hdr.transaction_id.protocol_version = REPLICAST_PROTOCOL_VERSION;
	msg->hdr.transaction_id.fhrow = fhrow;

	/*
	 * Pack Replicast message
	 */
	err = replicast_pack_generic(p, msg, datagram_num_byte,
				     num_datagrams_byte);
	if (err) {
		msgpack_pack_free(p);
		log_error(lg, "Send(%s): error %d while packing generic %s",
		    robj->name, err, replicast_opcode_str[opcode]);
		return err;
	}
	err = replicast_pack_func[opcode](p, msg);
	if (err) {
		msgpack_pack_free(p);
		log_error(lg, "Send(%s): error %d while packing message %s",
		    robj->name, err, replicast_opcode_str[opcode]);
		return err;
	}
	*out_p = p;
	return 0;
}

uv_buf_t
alloc_buffer(uv_handle_t *UNUSED(handle), size_t suggested_size)
{
	uv_buf_t buf;

	/* cannot fail here, so the best we can do is wait */
_again:
	buf.base = je_malloc(suggested_size + sizeof (struct repmsg));
	if (!buf.base) {
		usleep(100000);
		goto _again;
	}
	buf.len = suggested_size + sizeof (struct repmsg);
	return buf;
}

void
replicast_tcp_get_addr(rt_tcp_t *rtsock, char *src, char *dst,
    int *src_port, int *dst_port, int *scopeid)
{
	struct replicast *robj = rtsock->robj;

	if (robj->ipv4) {
		struct sockaddr_in *p = (struct sockaddr_in *)&rtsock->fromaddr;
		struct sockaddr_in *q = (struct sockaddr_in *)&rtsock->toaddr;
		inet_ntop(AF_INET, &p->sin_addr, src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &q->sin_addr, dst, INET_ADDRSTRLEN);
		*src_port = p->sin_port;
		*dst_port = q->sin_port;
	} else {
		struct sockaddr_in6 *p = (struct sockaddr_in6 *)&rtsock->fromaddr;
		struct sockaddr_in6 *q = (struct sockaddr_in6 *)&rtsock->toaddr;
		inet_ntop(AF_INET6, &p->sin6_addr, src, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &q->sin6_addr, dst, INET6_ADDRSTRLEN);
		*src_port = p->sin6_port;
		*dst_port = q->sin6_port;
		*scopeid = q->sin6_scope_id;
	}
}

static void
replicast_process_tcp_stream(rt_stream_t *stream, uv_buf_t buf,
			     size_t nread)
{
	struct state *st = &stream->st;

	log_debug(lg, "%p nread: %lu", st, nread);
	/*
	 * Set received buffer in stream. It will be processed by state
	 * machine.
	 */
	rt_tcp_sbuf_init(&stream->nbuf, buf, nread);
	state_event(st, RT_STREAM_UPDATED);
	while (state_check(st, ST_READY))
		stream->wait ? state_event(st, RT_STREAM_DECODE_WAIT) :
			       state_event(st, RT_STREAM_DECODE);
}

static rt_tcp_t *
robj_get_tcp_handle(rt_tcp_t *head, struct sockaddr_in6 *addr)
{
	rt_tcp_t *handle = head;
	while (handle != NULL) {
		if (memcmp(&handle->toaddr, addr,
			   sizeof(struct sockaddr_in6)) == 0)
			break;
		handle = handle->next;
	}
	return handle;
}

static inline void
robj_add_tcp_handle(rt_tcp_t **head, rt_tcp_t *new)
{
	assert(head != NULL);
	rt_tcp_t *handle = *head;
	int found = 0;
	while ( handle != NULL) {
		if (memcmp(&handle->toaddr, &new->toaddr,
			    sizeof(struct sockaddr_in6)) == 0) {
			found = 1;
			break;
		}
		handle = handle->next;
	}
	if (!found) {
		new->next = *head;
		*head = new;
	}
}

static void
on_tcp_peer_read(uv_stream_t *handle, ssize_t nread, uv_buf_t buf)
{
	/* Error or EOF? */
	if (nread < 0) {
		if (buf.base)
			je_free(buf.base);

		uv_err_code ec = uv_last_error(handle->loop).code;
		if (ec == UV_EOF) {
			log_debug(lg, "TCP EOF");
		} else {
			log_error(lg, "Error reading TCP stream %p bytes: %ld "
				"error: %d ", handle, nread, ec);
		}

		uv_read_stop(handle);
		/* Check handle to protect from multiple read calls */
		int exists = robj_exists_tcp_handle((uv_handle_t *)handle);
		if (!exists) {
			log_debug(lg, "TCP stream %p not in the list. Removed?",
				  handle);
			return;
		}

		rt_tcp_t *rtsock = (rt_tcp_t *) handle;
		log_debug(lg, "TCP read rtsock shutdown %p", rtsock);
		shut_tcp_conn(rtsock);
		return;
	}

	if (nread == 0) {
		/* Everything OK, but nothing read. */
		log_debug(lg, "Error reading TCP stream bytes: %lu", nread);
		if (buf.base)
			je_free(buf.base);
		return;
	}

	log_debug(lg, "nread: %ld buf-len: %lu", nread, buf.len);
	/*
	 * Drives the replicast TCP stream machine until the buffer
	 * is exhausted and not enough buffer is available for processing.
	 */
	replicast_process_tcp_stream(handle->data, buf, nread);

}

static inline void
rtsock_call_on_connect(rt_tcp_t *rtsock, int status)
{
	rt_cbctx_t *tcp_cb;

	while((tcp_cb = lfqueue_dequeue(rtsock->cb_lfq)) != NULL) {
		if (tcp_cb->cb)
			tcp_cb->cb(tcp_cb->cb_data, status);
		je_free(tcp_cb);
	}
}

static inline void
rtsock_set_state(rt_tcp_t *rtsock, enum rt_tcp_state new_state)
{
	uv_mutex_lock(&rtsock->conn_lock);
	rtsock->state = new_state;
	uv_mutex_unlock(&rtsock->conn_lock);
}

/* Sender side connect callback */
static void
sender_connect_cb(uv_connect_t *req, int status)
{
	int err;

	log_trace(lg, "connect handle: %p status: %d", req, status);
	if (status == -1)
		log_error(lg, "connect callback : %d:%s",
			  errno, strerror(errno));

	rt_tcp_t *rtsock = (rt_tcp_t *)req->data;
	assert(rtsock != NULL);

	/* If terminating, terminate the connection */
	if (rtsock->term) {
		rtsock_call_on_connect(rtsock, -EACCES);
		shut_tcp_conn(rtsock);
		return;
	}

	if (status) {
		log_notice(lg, "failed connect handle: %p status: %d",
			   req, status);
		rtsock_set_state(rtsock, RT_TCP_FAILED);
		robj_rm_tcp_handle((uv_handle_t *)rtsock);
		rtsock_call_on_connect(rtsock, status);
		rtsock_finalize(rtsock, 0);
		return;

	}

	int namelen;
	if (rtsock->robj->ipv4) {
		namelen = sizeof(struct sockaddr_in);
		err = uv_tcp_getsockname(&rtsock->tchandle,
		    (struct sockaddr *)&rtsock->fromaddr, &namelen);
	} else {
		namelen = sizeof(struct sockaddr_in6);
		err = uv_tcp_getsockname(&rtsock->tchandle,
		    (struct sockaddr *)&rtsock->fromaddr, &namelen);
	}

	if (err) {
		log_error(lg, "Failed to get source address");
		robj_rm_tcp_handle((uv_handle_t *)rtsock);
		rtsock_call_on_connect(rtsock, err);
		rtsock->tchandle.data = rtsock;
		shut_tcp_conn(rtsock);
		return;
	}

	rt_stream_t *pstream = &rtsock->stream;
	rt_tcp_stream_init(pstream);
	rtsock->tchandle.data = pstream;
	pstream->robj = rtsock->robj;
	pstream->tcp_handle = rtsock;

	err = uv_read_start((uv_stream_t *)&rtsock->tchandle,
		    alloc_buffer, on_tcp_peer_read);
	if(err) {
		robj_rm_tcp_handle((uv_handle_t *)rtsock);
		rtsock_call_on_connect(rtsock, err);
		rtsock->tchandle.data = rtsock;
		shut_tcp_conn(rtsock);
		return;
	}

	rtsock_set_state(rtsock, RT_TCP_CONNECTED);
	/* Ignore return code from these functions */
	uv_tcp_nodelay(&rtsock->tchandle, 0);
	uv_tcp_keepalive(&rtsock->tchandle, 1, REPLICAST_TCP_KEEPALIVE);
	rtsock_call_on_connect(rtsock, status);
}

static int
rtsock_add_tcp_cb(rt_tcp_t *rtsock, rt_connect_cb cb, void *cb_data)
{
	rt_cbctx_t *tcp_cb;
	int err;

	tcp_cb = je_malloc(sizeof(*tcp_cb));
	if (tcp_cb == NULL) {
		log_error(lg, "out of memory: -ENOMEM");
		return -ENOMEM;
	}
	tcp_cb->cb = cb;
	tcp_cb->cb_data = cb_data;
	err = lfqueue_enqueue(rtsock->cb_lfq, tcp_cb);
	if (err)
		log_error(lg, "Failed to queue callback on waiting connection");

	return err;
}

static int
rtsock_initialize(rt_tcp_t **rtsock)
{
	rt_tcp_t *sock;

	assert(rtsock != NULL);
	*rtsock = NULL;

	sock = je_calloc(1, sizeof(*sock));
	if (sock == NULL) {
		log_error(lg, "out of memory: -ENOMEM");
		return -ENOMEM;
	}
	sock->cb_lfq = lfqueue_create(SOMAXCONN);
	if (sock->cb_lfq == NULL) {
		log_error(lg, "out of memory: -ENOMEM");
		je_free(sock);
		return -ENOMEM;
	}
	uv_mutex_init(&sock->conn_lock);
	sock->state = RT_TCP_IN_PROGRESS;
	*rtsock = sock;
	return 0;
}

int
replicast_tcp_connect(struct replicast *robj, struct sockaddr_in6 *to_addr,
    rt_connect_cb cb, void *cb_data)
{
	int err;
	rt_tcp_t *rtsock;
	size_t n = sizeof(*rtsock);

	rtsock = robj_get_tcp_handle(robj->tcp_handles, to_addr);
	if (rtsock != NULL) {
		uv_mutex_lock(&rtsock->conn_lock);
		if (rtsock->state == RT_TCP_IN_PROGRESS) {
			err = rtsock_add_tcp_cb(rtsock, cb, cb_data);
			err = err ? err : -EAGAIN;
		} else {
			err = rtsock->state == RT_TCP_FAILED ?
				-ENETUNREACH : -EEXIST;
		}
		uv_mutex_unlock(&rtsock->conn_lock);
		return err;
	}

	log_trace(lg, "%s connecting to %p", robj->name, to_addr);

	err = rtsock_initialize(&rtsock);
	if (err) {
		log_error(lg, "Send(%s): Failed to initialize TCP connection",
			  robj->name);
		return err;
	}

	err = rtsock_add_tcp_cb(rtsock, cb, cb_data);
	if (err) {
		rtsock_finalize(rtsock, 0);
		return err;
	}

	err = uv_tcp_init(robj->loop, &rtsock->tchandle);
	if (err) {
		rtsock_finalize(rtsock, 0);
		log_error(lg, "Send(%s): TCP init error: %d errno=%d",
		    robj->name, err, errno);
		return -err;
	}

	rtsock->connect_req.data = rtsock;
	rtsock->robj = robj;
	memcpy(&rtsock->toaddr, to_addr, sizeof(*to_addr));

	err = uv_tcp_connect6(&rtsock->connect_req, &rtsock->tchandle,
				*to_addr, (uv_connect_cb)sender_connect_cb);
	if (err) {
		rtsock_finalize(rtsock, 0);
		log_error(lg, "Send(%s): TCP connect error: %d errno=%d",
		    robj->name, err, errno);
		return -err;
	}

	robj_add_tcp_handle(&robj->tcp_handles, rtsock);
	return 0;
}

static int
replicast_tcp_send(struct replicast *robj, struct repctx *ctx,
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    struct repmsg_generic *omsg, const uv_buf_t bufs[],
    unsigned int nbufs, struct sockaddr_in6 *to_addr,
    replicast_send_cb cb, replicast_send_free_cb free_cb,
    void *data, uint256_t *dgram_idx)
{
	int err;
	int *sentcount;
	uint32_t datagram_num_byte;
	uint32_t num_datagrams_byte;
	msgpack_p *p;
	uv_connect_t *connect_req;
	rt_tcp_t *rtsock;
	rt_tcp_header_t *tcp_header;
	size_t n = sizeof(*rtsock);

	log_trace(lg, "opcode %d data len: %u nbufs: %u",
	    opcode, msg->hdr.data_len, nbufs);
	assert(nbufs ? msg->hdr.data_len > 0 : msg->hdr.data_len == 0);

	/*
	 * Check if there is TCP peer handle in the context
	 * This is useful when previous message (request) is received over
	 * TCP and this message (response) is also going over TCP.
	 */
	if (ctx->tcp_handle) {
		rtsock = ctx->tcp_handle;
	} else {
		rtsock = robj_get_tcp_handle(robj->tcp_handles, to_addr);
		if (rtsock == NULL)
			return -ENODEV;
		ctx->tcp_handle = rtsock;
	}

	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	int src_port, dst_port, scopeid = 0;
	replicast_tcp_get_addr(rtsock, src, dst, &src_port, &dst_port, &scopeid);

	struct sockaddr_in6 o_addr;
	if (omsg && !to_addr) {
		o_addr.sin6_family = AF_INET6;
		o_addr.sin6_port = htons(omsg->hdr.transaction_id.source_port);
		memcpy(&o_addr.sin6_addr,
		    &omsg->hdr.transaction_id.source_addr, 16);
		o_addr.sin6_flowinfo = 0;
		o_addr.sin6_scope_id = robj->recv_addr.sin6_scope_id;
		to_addr = &o_addr;
	}

	if (unlikely(lg->level <= LOG_LEVEL_DUMP)) {
		log_debug(lg, "Send(%s,TCP): %s ctx %p txcookie %" PRIx64 " seqid %d.%d "
		    "orig_id %d.%d orig.txcookie %" PRIx64 " from %s.%d to %s.%d.%d nbufs: %d nwrite: %d",
		    robj->name, replicast_opcode_str[opcode], ctx, ctx ? ctx->txcookie : 0,
		    msg->hdr.transaction_id.sequence_num,
		    msg->hdr.transaction_id.sub_sequence_num,
		    msg->hdr.orig_id.sequence_num,
		    msg->hdr.orig_id.sub_sequence_num,
		    msg->hdr.orig_id.txcookie, src, ntohs(src_port), dst, ntohs(dst_port),
		    scopeid, nbufs, msg->hdr.data_len);
	}

	sentcount = je_malloc(sizeof(int));
	if (sentcount == NULL) {
		log_error(lg, "Send(%s): out of memory: -ENOMEM", robj->name);
		return -ENOMEM;
	}

	assert(ctx != NULL && ctx->attributes == RD_ATTR_UNICAST_TCP);
	assert(msg->hdr.attributes & RD_ATTR_UNICAST_TCP);
	err = replicast_prepare_header(robj, ctx, opcode, msg, omsg, &p,
	    &datagram_num_byte, &num_datagrams_byte, 0);
	if (err != 0) {
		je_free(sentcount);
		return err;
	}

	struct repsend *rsend = je_calloc(1, sizeof (*rsend));
	if (!rsend) {
		log_error(lg, "Send(%s): out of memory: -ENOMEM", robj->name);
		je_free(sentcount);
		msgpack_pack_free(p);
		return -ENOMEM;
	}
	uv_buf_t *new_buf = je_calloc(nbufs + 2, sizeof (uv_buf_t));
	if (!new_buf) {
		je_free(sentcount);
		je_free(rsend);
		msgpack_pack_free(p);
		return -ENOMEM;
	}

	tcp_header = je_malloc(sizeof(*tcp_header));
	if (!tcp_header) {
		je_free(new_buf);
		je_free(sentcount);
		je_free(rsend);
		msgpack_pack_free(p);
		return -ENOMEM;
	}

	msgpack_get_buffer(p, &new_buf[1]);
	*(new_buf[1].base + datagram_num_byte) = 1;
	msg->num_datagrams = *(new_buf[1].base + num_datagrams_byte) = 1;

	tcp_header->tcp_magic = htonl(RT_TCP_MAGIC);
	tcp_header->msg_len = htonl(new_buf[1].len);
	assert(tcp_header->msg_len != 0);
	new_buf[0] = uv_buf_init((char *)tcp_header, sizeof(*tcp_header));

	log_debug(lg, "destination: %s op: %s seqid: %u nbufs: %u, msgsz: %lu "
	    "datasz: %u totalsz: %lu", dst,
	    replicast_opcode_str[opcode], msg->hdr.transaction_id.sequence_num,
	    nbufs, new_buf[1].len, msg->hdr.data_len,
	    new_buf[0].len + new_buf[1].len + msg->hdr.data_len);

	for (unsigned int i = 0; i < nbufs; i++) {
		new_buf[i + 2] = bufs[i];
	}

	rsend->id = msg->hdr.transaction_id;
	rsend->robj = robj;
	rsend->ctx = ctx;
	rsend->msg = msg;
	rsend->omsg = omsg;
	rsend->cb = cb;
	rsend->free_cb = free_cb;
	rsend->data = data;
	rsend->p = p;
	rsend->to_addr = to_addr;
	rsend->new_buf = new_buf;
	rsend->outbufs = new_buf;
	rsend->outnum = nbufs + 2;
	rsend->datagram_num = 1;
	rsend->num_datagrams = 1;
	*sentcount = 1;
	rsend->sentcount = sentcount;

	err = replicast_add_wqe(rsend);
	if (err != 0) {
		je_free(tcp_header);
		je_free(sentcount);
		je_free(new_buf);
		je_free(rsend);
		msgpack_pack_free(p);
		return -ENOMEM;
	}

	err = tcp_write(rtsock, rsend);
	if (err != 0) {
		je_free(tcp_header);
		je_free(sentcount);
		je_free(new_buf);
		if (rsend->wqe)
			repctx_wqe_destroy(rsend->wqe);
		je_free(rsend);
		msgpack_pack_free(p);
	}
	return err;
}

static void
replicast_tcp_send_cb(void *data, int status, int ctx_valid)
{
	struct repsend *rsend = data;

	/* free the entire new_buf and msgpack if this is the last datagram */
	(*rsend->sentcount)--;
	if (*rsend->sentcount == 0) {
		msgpack_pack_free(rsend->p);
		if (rsend->new_buf) {
			if (rsend->new_buf[0].base)
				je_free(rsend->new_buf[0].base);
			je_free(rsend->new_buf);
		}
		if (rsend->cb)
			rsend->cb(rsend->data, status, ctx_valid);
		je_free(rsend->sentcount);
	}
	je_free(rsend);
}

void
replicast_udp_send_cb(void *data, int status, int ctx_valid)
{
	struct repsend *rsend = data;

	/* free the header element contents for this rsend */
	if (rsend->num_datagrams > 1) {
		int hdr_idx = (2 * rsend->datagram_num) - 2;
		je_free(rsend->new_buf[hdr_idx].base);
	}
	/* free the entire new_buf and msgpack if this is the last datagram */
	(*rsend->sentcount)--;
	if (*rsend->sentcount == 0) {
		msgpack_pack_free(rsend->p);
		if (rsend->new_buf) {
			if ((rsend->num_datagrams == 1) &&
			    (rsend->new_buf[0].base))
				je_free(rsend->new_buf[0].base);
			je_free(rsend->new_buf);
		}

		if (rsend->cb)
			rsend->cb(rsend->data, status, ctx_valid);
		je_free(rsend->sentcount);
	}
	je_free(rsend);
}

int
replicast_udp_send(struct replicast *robj, struct repctx *ctx,
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    struct repmsg_generic *omsg, const uv_buf_t bufs[],
    unsigned int nbufs, struct sockaddr_in6 *to_addr, int to_addr_arrlen,
    replicast_send_cb cb, replicast_send_free_cb free_cb,
    void *data, uint256_t *dgram_idx, uint16_t fhrow)
{
	int err;
	unsigned int i, j;
	uint32_t datagram_num_byte;
	uint32_t num_datagrams_byte;
	msgpack_p *p;

	assert(robj);
	if(msg->hdr.attributes & RD_ATTR_UNICAST_TCP)
		assert(opcode != RT_GET_RENDEZVOUS_TRANSFER &&
			opcode != RT_RENDEZVOUS_TRANSFER);

	err = replicast_prepare_header(robj, ctx, opcode, msg, omsg, &p,
					&datagram_num_byte,
					&num_datagrams_byte, fhrow);
	if (err != 0)
		return err;

	uv_buf_t hdr_buf;
	msgpack_get_buffer(p, &hdr_buf);
	*(hdr_buf.base + datagram_num_byte) = 1;
	msg->num_datagrams = *(hdr_buf.base + num_datagrams_byte) = 1;

	if (hdr_buf.len >= REPLICAST_DGRAM_MAXLEN) {
		msgpack_pack_free(p);
		log_error(lg, "Send(%s): Very large UDP packet header. "
		    "Size = %lu", robj->name, hdr_buf.len);
		return -EMSGSIZE;
	}

	size_t buflen = 0;
	if ((bufs != NULL) && (nbufs > 0)) {
		for (i = 0; i < nbufs; i++)
			buflen += bufs[i].len;
	}

	int *sentcount = je_malloc(sizeof (int));
	if (!sentcount) {
		msgpack_pack_free(p);
		return -ENOMEM;
	}
	*sentcount = 0;

	int datagram_count = 1;
	if (buflen > 0) {

		log_debug(lg, "Send(%s): %s buflen: %ld seqid %d.%d orig_id "
		    " %d.%d BUF_CHUNK_SIZE max: %d",
		    robj->name, replicast_opcode_str[opcode], buflen,
		    msg->hdr.transaction_id.sequence_num,
		    msg->hdr.transaction_id.sub_sequence_num,
		    msg->hdr.orig_id.sequence_num,
		    msg->hdr.orig_id.sub_sequence_num, BUF_CHUNK_SIZE);

		if (buflen > BUF_CHUNK_SIZE) {
			msg->num_datagrams = buflen/BUF_CHUNK_SIZE;
			msg->num_datagrams +=
				((buflen % BUF_CHUNK_SIZE) > 0) ? 1 : 0;
		} else {
			msg->num_datagrams = 1;
		}
		*(hdr_buf.base + num_datagrams_byte)
			= (uint8_t)msg->num_datagrams;
		if (msg->num_datagrams > MAX_DGRAM_COUNT) {
			log_error(lg, "num_datagrams %d > %d",
			    msg->num_datagrams, MAX_DGRAM_COUNT);
			msgpack_pack_free(p);
			je_free(sentcount);
			return -EINVAL;
		}

		uv_buf_t *new_buf = je_calloc(2 * msg->num_datagrams,
							sizeof (uv_buf_t));
		if (!new_buf) {
			msgpack_pack_free(p);
			je_free(sentcount);
			return -ENOMEM;
		}

		size_t remlen = 0;
		size_t rem = buflen;
		char *baseptr = bufs[0].base;
		i = 0;
		while (rem > 0) {
			remlen = (rem < BUF_CHUNK_SIZE) ? rem : BUF_CHUNK_SIZE;
			rem -= remlen;
			int skip_dgram = dgram_idx && uint256_bcheck(dgram_idx,
				datagram_count - 1);
			if (!skip_dgram && remlen <= BUF_CHUNK_SIZE) {

				j = i + 1;
				new_buf[j].base = baseptr;
				new_buf[j].len = remlen;

				struct repsend *rsend =
						je_calloc(1, sizeof (*rsend));
				if (!rsend) {
					log_error(lg, "Send(%s): out of "
					    "memory: -ENOMEM", robj->name);
					je_free(new_buf);
					msgpack_pack_free(p);
					return -ENOMEM;
				}

				rsend->id = msg->hdr.transaction_id;
				rsend->robj = robj;
				rsend->ctx = ctx;
				rsend->msg = msg;
				rsend->omsg = omsg;
				rsend->cb = cb;
				rsend->free_cb = free_cb;
				rsend->data = data;
				rsend->p = p;
				rsend->to_addr = to_addr;
				rsend->to_addr_arrlen = to_addr_arrlen;
				rsend->to_addr_sent = 0;
				rsend->new_buf = new_buf;
				rsend->outbufs = &new_buf[i];
				rsend->outnum = 2;
				rsend->num_datagrams = msg->num_datagrams;
				rsend->datagram_num = datagram_count;
				rsend->sentcount = sentcount;
				*(hdr_buf.base + datagram_num_byte)
					= datagram_count;

				new_buf[i].base = je_malloc(hdr_buf.len);
				if (!new_buf[i].base) {
					je_free(rsend);
					je_free(new_buf);
					msgpack_pack_free(p);
					return -ENOMEM;
				}
				memcpy(new_buf[i].base, hdr_buf.base,
				    hdr_buf.len);
				new_buf[i].len = hdr_buf.len;

				err = replicast_add_wqe(rsend);
				if (err != 0) {
					je_free(new_buf[i].base);
					je_free(rsend);
					je_free(new_buf);
					msgpack_pack_free(p);
					return -ENOMEM;
				}

				err = replicast_datagram_send(rsend, to_addr,
							      datagram_count);
				(*sentcount)++;
				if (err) {
					if (rsend->wqe) {
						repctx_wqe_destroy(rsend->wqe);
						rsend->wqe = NULL;
					}
					je_free(new_buf[i].base);
					je_free(rsend);
					je_free(new_buf);
					msgpack_pack_free(p);
					log_error(lg, "Send(%s): UDP Datagram"
					    "(%d of %d) send error: %d",
					    robj->name, datagram_count,
					    msg->num_datagrams, err);
					return err;
				}
			}
			baseptr += remlen;
			datagram_count++;
			i += 2;
		}
	} else {
		struct repsend *rsend = je_calloc(1, sizeof (*rsend));
		if (!rsend) {
			log_error(lg, "Send(%s): out of memory: -ENOMEM",
			    robj->name);
			je_free(sentcount);
			return -ENOMEM;
		}

		rsend->id = msg->hdr.transaction_id;
		rsend->robj = robj;
		rsend->ctx = ctx;
		rsend->msg = msg;
		rsend->omsg = omsg;
		rsend->cb = cb;
		rsend->free_cb = free_cb;
		rsend->data = data;
		rsend->p = p;
		rsend->to_addr = to_addr;
		rsend->to_addr_arrlen = to_addr_arrlen;
		rsend->to_addr_sent = 0;
		rsend->outbufs = &hdr_buf;
		rsend->outnum = 1;
		rsend->num_datagrams = msg->num_datagrams;
		rsend->datagram_num = datagram_count;
		rsend->sentcount = sentcount;

		err = replicast_add_wqe(rsend);
		if (err != 0) {
			je_free(rsend);
			msgpack_pack_free(p);
			return -ENOMEM;
		}

		err = replicast_datagram_send(rsend, to_addr, datagram_count);
		(*sentcount)++;
		if (err) {
			je_free(rsend);
			msgpack_pack_free(p);
			log_warn(lg, "Send(%s): UDP Datagram(%d of %d) send"
			    "error: %d", robj->name, datagram_count,
			    msg->num_datagrams, err);
			return err;
		}
	}
	return err;
}

/*
 * Send message
 */
int
replicast_send(struct replicast *robj, struct repctx *ctx,
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    struct repmsg_generic *omsg, const uv_buf_t bufs[],
    unsigned int nbufs, struct sockaddr_in6 *to_addr,
    replicast_send_cb cb, void *data, uint256_t *dgram_idx)
{
	int err;

	/* Use TCP/IP for TX requests */
	if (ctx && ctx->attributes == RD_ATTR_UNICAST_TCP) {
		err =  replicast_tcp_send(robj, ctx, opcode, msg, omsg,
					  bufs, nbufs, to_addr, cb,
					  replicast_tcp_send_cb,
					  data, dgram_idx);
	} else if (ctx && ctx->attributes == RD_ATTR_UNICAST_UNIXSOCK) {
	/* Use Unix Socket TX requests */
		err =  replicast_udp_send(robj, ctx, opcode, msg, omsg,
					  bufs, nbufs, NULL, 0, cb,
					  replicast_udp_send_cb,
					  data, dgram_idx, 0);
	/* Proxy MC TX requests */
	} else if (ctx && ctx->attributes == RD_ATTR_UNICAST_UDP_MCPROXY) {

		struct sockaddr_in6 addrs[REPLICAST_DEVROW_MAX];
		int addrs_len = 0;
		uint16_t fhrow = flexhash_get_addr_fhrow(to_addr);
		err = flexhash_get_row_server_addrs(robj->client_ctx != NULL,
		    robj->client_ctx ? robj->client_ctx : robj->server_ctx,
		    fhrow, addrs, &addrs_len);
		if (err)
			return err;

		err =  replicast_udp_send(robj, ctx, opcode, msg, omsg,
					  bufs, nbufs, addrs, addrs_len, cb,
					  replicast_udp_send_cb,
					  data, dgram_idx, fhrow);
		if (!err)
			robj->stats.last_send_time = get_timestamp_us();
	/* Unicast or Multicast TX requests */
	} else {
		err =  replicast_udp_send(robj, ctx, opcode, msg, omsg,
					  bufs, nbufs, to_addr, 0, cb,
					  replicast_udp_send_cb,
					  data, dgram_idx, 0);
		if (!err)
			robj->stats.last_send_time = get_timestamp_us();
	}

	return err;
}

/*
 * Matching context for unicast replies (only client)
 * ==================================================
 *
 * Find associated transaction id to confirm that this client is expecting to
 * receive a completion.  We loop through the list of "known" contexts and see
 * if there is matching WQE.
 *
 * Note that RT_GET_RENDEZVOUS_TRANSFER is also will be matching as unicast
 * receive.
 */
static struct repctx *
replicast_match_client(struct replicast *robj,
    struct replicast_transaction_id *msg_id,
    struct replicast_transaction_id *orig_id, struct repwqe **wqe_out)
{
	struct repctx *ctx = NULL;
	struct repwqe *wqe = NULL, *recv_wqe = NULL;
	unsigned int opcode = msg_id->opcode;

	if (!orig_id->sequence_num) {
		log_error(lg, "Recv(%s): client received opcode %s with sequence_num not set",
		    robj->name, replicast_opcode_str[opcode]);
		return NULL;
	}
	if (!orig_id->txcookie) {
		log_warn(lg, "Recv(%s): client received opcode %s with txcookie not set",
		    robj->name, replicast_opcode_str[opcode]);
		return NULL;
	}

	struct repctx *ctx_next = NULL;
	uint64_t ctxid = orig_id->sequence_num ^ orig_id->txcookie;
#ifdef DEBUG_CTX
	log_debug(lg, "CLIENT: searching for ctxid=%lx : %d.%d %d.%d %d^%lx\n", ctxid,
		    msg_id->sequence_num, msg_id->sub_sequence_num,
		    orig_id->sequence_num, orig_id->sub_sequence_num,
		    orig_id->sequence_num, orig_id->txcookie);
#endif
	HASH_FIND_INT64(robj->ctxq, &ctxid, ctx_next);
	if (ctx_next) {

#ifdef DEBUG_CTX
		log_debug(lg, "=== CLIENT: opcode %s ctx %p ctxid %lx seqid %d.%d Incoming: msgid %d.%d orig_id %d.%d ===",
		    replicast_opcode_str[opcode], ctx_next, ctxid, ctx_next->sequence_cnt, ctx_next->sub_sequence_cnt,
		    msg_id->sequence_num, msg_id->sub_sequence_num,
		    orig_id->sequence_num, orig_id->sub_sequence_num);
#endif

		QUEUE *w;
		QUEUE_FOREACH(w, &ctx_next->wq) {
			struct repwqe *wqe_next = QUEUE_DATA(w, struct repwqe,
			    item);

#ifdef DEBUG_CTX
			log_debug(lg, "   + ctx %p wqe %p sub_sequence_cnt %d id seqid %d.%d",
			    wqe_next->ctx, wqe_next, wqe_next->sub_sequence_cnt,
			    wqe_next->id.sequence_num, wqe_next->id.sub_sequence_num);
#endif

			/* Unicast/Multicast client matching
			 *    (RT_GET_RENDEZVOUS_TRANSFER) matching on the client */
			if (wqe_next->id.sequence_num == orig_id->sequence_num &&
			    wqe_next->id.sub_sequence_num == orig_id->sub_sequence_num &&
			    wqe_next->id.txcookie == orig_id->txcookie) {
				wqe = wqe_next;
				log_debug(lg, "Recv(%s): %s found seqid %d.%d orig.txcookie %" PRIx64,
				    robj->name, replicast_opcode_str[opcode], wqe->id.sequence_num,
				    wqe->id.sub_sequence_num, orig_id->txcookie);

				/* client side OPCODE verification vs. FSM */
				if (state_verify_opcode(ctx_next->state, opcode))
					break;

				log_error(lg, "Recv(%s): matched wrong opcode %s",
				    robj->name, replicast_opcode_str[opcode]);
			}
		}
		if (!wqe)
			goto _exit;

		recv_wqe = repctx_wqe_recv(ctx_next, &wqe->id,
		    &wqe->orig_id, wqe->data);
		if (!recv_wqe) {
			log_error(lg, "Recv(%s): WQE: out of memory",
			    robj->name);
			wqe = NULL;
			goto _exit;
		}
		recv_wqe->ctx = ctx_next;
		ctx = ctx_next;
		ctx->wqe_in = recv_wqe;
		QUEUE_INSERT_TAIL(&wqe->recv_wq, &recv_wqe->recv_item);
	}

_exit:
	*wqe_out = recv_wqe;
	return ctx;
}

/*
 * Matching context for multicast replies (can only be server)
 * ===========================================================
 *
 * Find associated transaction id to confirm that this client is expecting to
 * receive a completion.  We loop through the list of "known" contexts and see
 * if there is matching WQE.
 */
static struct repctx *
replicast_match_server(struct replicast *robj,
    struct replicast_transaction_id *msg_id,
    struct replicast_transaction_id *orig_id, struct repwqe **wqe_out)
{
	struct repctx *ctx = NULL;
	struct repwqe *wqe = NULL, *recv_wqe = NULL;
	unsigned int opcode = msg_id->opcode;
	uint32_t lookup_cnt = 0;

	if (!msg_id->sequence_num) {
		log_error(lg, "Recv(%s): server received opcode %s with sequence_num not set",
		    robj->name, replicast_opcode_str[opcode]);
		return NULL;
	}
	if (!msg_id->txcookie) {
		log_error(lg, "Recv(%s): server received opcode %s with txcookie not set",
		    robj->name, replicast_opcode_str[opcode]);
		return NULL;
	}

	struct repctx *ctx_next = NULL;
	uint64_t ctxid = msg_id->sequence_num ^ msg_id->txcookie;
#ifdef DEBUG_CTX
	log_debug(lg, "SERVER: searching for ctxid=%lx : %d.%d %d.%d %d^%lx\n", ctxid,
		    msg_id->sequence_num, msg_id->sub_sequence_num,
		    orig_id->sequence_num, orig_id->sub_sequence_num,
		    msg_id->sequence_num, msg_id->txcookie);
#endif
	HASH_FIND_INT64(robj->ctxq_recv, &ctxid, ctx_next);
	if (ctx_next) {

#ifdef DEBUG_CTX
		log_debug(lg, "=== MULTICAST: opcode %s ctx %p ctxid %lx seqid %d.%d Incoming: msgid %d.%d orig_id %d.%d ===",
		    replicast_opcode_str[opcode], ctx_next, ctxid, ctx_next->sequence_cnt, ctx_next->sub_sequence_cnt,
		    msg_id->sequence_num, msg_id->sub_sequence_num,
		    orig_id->sequence_num, orig_id->sub_sequence_num);
#endif

		QUEUE *w;
		QUEUE_FOREACH(w, &ctx_next->wq) {
			struct repwqe *wqe_next = QUEUE_DATA(w, struct repwqe,
			    item);
			lookup_cnt++;

#ifdef DEBUG_CTX
			log_debug(lg, "   + ctx %p wqe %p sub_sequence_cnt %d id seqid %d.%d",
			    wqe_next->ctx, wqe_next, wqe_next->sub_sequence_cnt,
			    wqe_next->id.sequence_num, wqe_next->id.sub_sequence_num);
#endif

			if (opcode == RT_RENDEZVOUS_ACK ||
			    opcode == RT_RENDEZVOUS_TRANSFER ||
			    opcode == RT_GET_RENDEZVOUS_TRANSFER ||
			    opcode == RT_GET_ACCEPT_PROPOSED_RENDEZVOUS) {
				if (wqe_next->id.sequence_num == msg_id->sequence_num &&
				    wqe_next->id.txcookie == msg_id->txcookie) {

					wqe = wqe_next;

					log_debug(lg, "Recv(%s): found MC seqid %d.%d seqcnt %d",
					    robj->name, wqe->id.sequence_num,
					    wqe->id.sub_sequence_num, ctx_next->sequence_cnt);

					/* client side OPCODE verification vs. FSM */
					if (state_verify_opcode(ctx_next->state, opcode))
						break;

					log_error(lg, "Recv(%s): matched wrong opcode %s",
					    robj->name, replicast_opcode_str[opcode]);
				}
			}
		}
		if (!wqe)
			goto _exit;

		recv_wqe = repctx_wqe_recv(ctx_next, &wqe->id,
		    &wqe->orig_id, wqe->data);
		if (!recv_wqe) {
			log_error(lg, "Recv(%s): WQE: out of memory",
			    robj->name);
			wqe = NULL;
			goto _exit;
		}
		recv_wqe->ctx = ctx_next;
		ctx = ctx_next;
		ctx->wqe_in = recv_wqe;
		QUEUE_INSERT_TAIL(&wqe->recv_wq, &recv_wqe->recv_item);
	}

_exit:
	*wqe_out = recv_wqe;
	return ctx;
}

static struct repctx *
replicast_match_device(struct replicast *robj,
    struct replicast_transaction_id *msg_id,
    struct replicast_transaction_id *orig_id, struct repwqe **wqe_out)
{
	struct repctx *ctx = NULL;
	struct repwqe *wqe = NULL, *recv_wqe = NULL;
	unsigned int opcode = msg_id->opcode;

	if (!orig_id->sequence_num) {
		log_error(lg, "Recv(%s): server received opcode %s with sequence_num not set",
		    robj->name, replicast_opcode_str[opcode]);
		return NULL;
	}
	if (!orig_id->txcookie) {
		log_error(lg, "Recv(%s): server received opcode %s with txcookie not set",
		    robj->name, replicast_opcode_str[opcode]);
		return NULL;
	}

	struct repctx *ctx_next = NULL;
	uint64_t ctxid = orig_id->sequence_num ^ orig_id->txcookie;
	HASH_FIND_INT64(robj->ctxq_recv, &ctxid, ctx_next);
	if (ctx_next) {

#ifdef DEBUG_CTX
		log_debug(lg, "=== MULTICAST: opcode %s ctx %p ctxid %lx seqid %d.%d Incoming: msgid %d.%d orig_id %d.%d ===",
		    replicast_opcode_str[opcode], ctx_next, ctxid, ctx_next->sequence_cnt, ctx_next->sub_sequence_cnt,
		    msg_id->sequence_num, msg_id->sub_sequence_num,
		    orig_id->sequence_num, orig_id->sub_sequence_num);
#endif

		QUEUE *w;
		QUEUE_FOREACH(w, &ctx_next->wq) {
			struct repwqe *wqe_next = QUEUE_DATA(w, struct repwqe,
			    item);

#ifdef DEBUG_CTX
			log_debug(lg, "   + ctx %p wqe %p sub_sequence_cnt %d id seqid %d.%d",
			    wqe_next->ctx, wqe_next, wqe_next->sub_sequence_cnt,
			    wqe_next->id.sequence_num, wqe_next->id.sub_sequence_num);
#endif

			if (((opcode == RT_GET_RENDEZVOUS_TRANSFER) || (opcode == RT_BLOB_LOOKUP_RESULT)) &&
				wqe_next->id.sequence_num ==
				orig_id->sequence_num) {
				wqe = wqe_next;
				if (state_verify_opcode(ctx_next->state,
							opcode))
					break;
			}
		}
		if (!wqe)
			goto _exit;

		recv_wqe = repctx_wqe_recv(ctx_next, &wqe->id,
		    &wqe->orig_id, wqe->data);
		if (!recv_wqe) {
			log_error(lg, "Recv(%s): WQE: out of memory",
			    robj->name);
			wqe = NULL;
			goto _exit;
		}
		recv_wqe->ctx = ctx_next;
		ctx = ctx_next;
		ctx->wqe_in = recv_wqe;
		QUEUE_INSERT_TAIL(&wqe->recv_wq, &recv_wqe->recv_item);
	}

_exit:
	*wqe_out = recv_wqe;
	return ctx;
}

static struct repctx *
replicast_get_context(struct replicast *robj, enum replicast_opcode opcode,
		      uint32_t attr,
		      struct replicast_transaction_id *msg_id,
		      struct replicast_transaction_id *orig_id,
		      struct repwqe **wqe_out)
{
	struct repctx *ctx = NULL;

	switch (opcode) {
	case RT_RENDEZVOUS_ACK:
	case RT_RENDEZVOUS_TRANSFER:
	case RT_GET_ACCEPT_PROPOSED_RENDEZVOUS:
		ctx = replicast_match_server(robj, msg_id, orig_id, wqe_out);
		break;

	case RT_GET_RENDEZVOUS_TRANSFER:
		if (robj->dev_ctx) {
			if (attr & RD_ATTR_UNICAST_TCP ||
			    attr & RD_ATTR_UNICAST_UDP ||
			    attr & RD_ATTR_UNICAST_UDP_MCPROXY)
				ctx = replicast_match_server(robj, msg_id,
							     orig_id, wqe_out);
			else
				ctx = replicast_match_device(robj, msg_id,
							     orig_id, wqe_out);
		} else if (robj->client_ctx)
			ctx = replicast_match_client(robj, msg_id,
						     orig_id, wqe_out);

		break;

	case RT_SERVER_LIST_RESPONSE:
	case RT_NAMED_CHUNK_GET_RESPONSE:
	case RT_UNNAMED_CHUNK_GET_RESPONSE:
	case RT_RECOVERY_ACK:
	case RT_NAMED_PAYLOAD_ACK:
	case RT_UNNAMED_PAYLOAD_ACK:
	case RT_ACCEPT_PROPOSED_RENDEZVOUS:
	case RT_ACCEPT_CONTENT_ALREADY_STORED:
	case RT_ACCEPT_NOT_NOW:
	case RT_RENDEZVOUS_NACK:
	case RT_ERROR:
	case RT_PINGPONG_ACK:
	case RT_NGREQUEST_ACK:
	case RT_NGREQUEST_COUNT_ACK:
	case RT_NGREQUEST_LOCATE_ACK:
	case RT_BLOB_LOOKUP_ACK:
	case RT_OPP_STATUS_ACK:
	case RT_ROWEVAC_ACK:
	case RT_ENCODE_ACK:
	case RT_PAYLOAD_RCVD:
	case RT_CLIENT_NOTIFICATION:
	case RT_SG_LOOKUP_RESPONSE:
	case RT_SG_CHUNKPUT_RESPONSE:
	case RT_SG_VMPUT_RESPONSE:
	case RT_SG_SSPUT_RESPONSE:
	case RT_SG_PING_PONG_RESPONSE:
	case RT_SG_EXPUNGE_RESPONSE:
	case RT_SG_DYN_FETCH_RESP:
	case RT_RES_GET_RESPONSE:
	case RT_SG_CHUNKGET_RESPONSE:
	case RT_ONDEMAND_POLICY_ACK:
		ctx = replicast_match_client(robj, msg_id, orig_id, wqe_out);
		break;
	case RT_BLOB_LOOKUP_RESULT:
		ctx = replicast_match_device(robj, msg_id,
				orig_id, wqe_out);
		break;
	case RT_SG_LOOKUP:
	case RT_SG_CHUNKPUT:
	case RT_SG_VMPUT:
	case RT_SG_SSPUT:
	case RT_SG_PING_PONG:
	case RT_SG_EXPUNGE:
	case RT_SG_DYN_FETCH:
	case RT_SG_CHUNKGET:
	default:
		break;
	}
	return ctx;

}

static inline void
free_buf_cb(void *data, int err, int ctx_valid)
{
	je_free(data);
}

static inline void
free_ctx_cb(void *data, int err, int ctx_valid)
{
	struct repctx *ctx = data;
	struct repreq_common *req = ctx->state->data;
	req->inexec--;
	state_event(ctx->state, EV_ERR);
}

void
send_err_on_tcp(struct replicast *robj, enum replicast_error err,
		struct repmsg_generic *msg, rt_tcp_t *tcp_handle, void *data)
{
	struct repmsg_error errmsg;
	struct repctx ctx;
	unsigned int opcode;
	struct replicast_transaction_id *msg_id = &msg->hdr.transaction_id;
	struct replicast_transaction_id *orig_id = &msg->hdr.orig_id;

	opcode = msg->hdr.transaction_id.opcode;

	log_error(lg, "(%s): sending RT_ERROR for unsolicited message over"
		      " TCP - %s seqdid %d.%d orig_id %d.%d txcookie %" PRIx64,
		      robj->name, replicast_opcode_str[opcode],
		      msg_id->sequence_num, msg_id->sub_sequence_num,
		      orig_id->sequence_num, orig_id->sub_sequence_num,
		      msg_id->txcookie);
	memset(&ctx, 0, sizeof (ctx));
	ctx.attributes = RD_ATTR_UNICAST_TCP;
	ctx.tcp_handle = tcp_handle;

	memset(&errmsg, 0, sizeof (errmsg));
	errmsg.error = RT_ERR_UNREACHABLE;
	errmsg.hdr.attributes |= RD_ATTR_UNICAST_TCP;

	replicast_send(robj, &ctx, RT_ERROR, (struct repmsg_generic *)&errmsg,
	    (struct repmsg_generic *)msg, NULL,
	    0, NULL, free_buf_cb, data, NULL);
	ctx.attributes = 0;
}

void
replicast_process_recv(struct replicast *robj, const uv_buf_t buf,
			ssize_t nread, char *sender, rt_tcp_t *tcp_handle,
			uv_pipe_t *peer_sock)
{
	int err;

	/*
	 * Unpack generic portion of the message at the end of the incoming
	 * buffer. Maximum size of replicast message is sizeof (struct repmsg).
	 */
	msgpack_u *u = msgpack_unpack_init(buf.base, nread, 0);
	struct repmsg *msg = (struct repmsg *)((char *)buf.base + buf.len -
	    sizeof (struct repmsg));

	err = replicast_unpack_generic(u, (struct repmsg_generic *)msg);
	if (err) {
		log_error(lg, "Recv(%s): datagram unpack error %d",
			    robj->name, err);
		msgpack_unpack_free(u);
		je_free(buf.base);
		return;
	}
	msg->hdr.peer_sock = peer_sock;
	struct replicast_transaction_id *msg_id = &msg->hdr.transaction_id;
	struct replicast_transaction_id *orig_id = &msg->hdr.orig_id;
	uint64_t attr = msg->hdr.attributes;

	unsigned int opcode = msg_id->opcode;
	log_debug(lg, "opcode %u nread %lu datagrams %d attr 0x%lx",
			opcode, nread, msg->num_datagrams, attr);

	if (opcode >= RT_END) {
		log_error(lg, "Recv(%s): wrong opcode error %u",
		    robj->name, opcode);

		struct repmsg_error errmsg;
		memset(&errmsg, 0, sizeof (errmsg));
		errmsg.error = RT_ERR_WRONG_OPCODE;

		replicast_send(robj, NULL, RT_ERROR,
		    (struct repmsg_generic *)&errmsg,
		    (struct repmsg_generic *)msg, NULL, 0, NULL, free_buf_cb,
		    buf.base, NULL);

		msgpack_unpack_free(u);
		je_free(buf.base);
		return;
	}

	if (robj->mcproxy_func && attr & RD_ATTR_UNICAST_UDP_MCPROXY) {
		robj->mcproxy_func(robj, msg_id->fhrow, buf, nread, sender);
		msgpack_unpack_free(u);
		je_free(buf.base);
		return;
	}

	QUEUE *recv_queue;
	struct repwqe *wqe = NULL;
	struct repctx *ctx = NULL;

	ctx = replicast_get_context(robj, opcode, attr, msg_id, orig_id, &wqe);

	if (ctx) {
		wqe->u = u;
		wqe->msg = (struct repmsg_generic *)msg;
		wqe->nread = nread;
		if (tcp_handle)
			ctx->tcp_handle = tcp_handle;
	}

	/*
	 * Unpack the rest of the Replicast message
	 */
	err = replicast_unpack_func[opcode](u, msg);
	if (err) {
		log_error(lg, "Recv(%s): error while unpacking message %s "
		    "err = %d seq id %d.%d", robj->name,
		    replicast_opcode_str[opcode], err, msg_id->sequence_num,
		    msg_id->sub_sequence_num);
		msgpack_unpack_free(u);
		je_free(buf.base);
		if (ctx)
			ctx->wqe_in->u = NULL;
		return;
	}

	log_debug(lg, "Recv(%s): %s seqid %d.%d orig_id %d.%d txcookie %" PRIx64
	    " from %s nread %ld", robj->name, replicast_opcode_str[opcode],
	    msg_id->sequence_num, msg_id->sub_sequence_num,
	    orig_id->sequence_num, orig_id->sub_sequence_num, msg_id->txcookie,
	    sender, nread);

	if (opcode == RT_ERROR) { // client receives error message on a version mismatch
		struct repmsg_error *errmsg =
			(struct repmsg_error *)msg;
		if (errmsg->error == RT_ERR_VERSION_MISMATCH) {
			log_error(lg, "Recv(%s): version mismatch received (orig_id.opcode=%s): v.%x"
			    " self: v.%x", robj->name,
			    replicast_opcode_str[msg->hdr.orig_id.opcode],
			    msg->hdr.transaction_id.protocol_version,
			    REPLICAST_PROTOCOL_VERSION);

			msgpack_unpack_free(u);
			je_free(buf.base);
			if (ctx)
				ctx->wqe_in->u = NULL;

			return;

		}
		// server does a version check, we support prior versions coming
		// into the server
	} else if (msg->hdr.transaction_id.protocol_version > REPLICAST_PROTOCOL_VERSION) {
		log_error(lg, "Recv(%s): version mismatch received: (orig_id.opcode=%s) v.%x"
		    " self: v.%x", robj->name,
		    replicast_opcode_str[msg->hdr.orig_id.opcode],
		    msg->hdr.transaction_id.protocol_version, REPLICAST_PROTOCOL_VERSION);

		struct repmsg_error errmsg;
		memset(&errmsg, 0, sizeof (errmsg));
		errmsg.error = RT_ERR_VERSION_MISMATCH;

		replicast_send(robj, NULL, RT_ERROR,
		    (struct repmsg_generic *)&errmsg,
		    (struct repmsg_generic *)msg, NULL, 0, NULL, free_buf_cb,
		    buf.base, NULL);

		msgpack_unpack_free(u);
		if (ctx)
			ctx->wqe_in->u = NULL;

		return;
	}
	/*
	 * This is unsolicited message. Create new context. It can be temporary
	 * i.e. to handle immediate payload, in which case it will be garbage
	 * collected at some idle time or freed explicitly in case of ack.
	 */
	int new_ctx = 0;
	if (!ctx) {
		new_ctx = 1;
		if (opcode == RT_ERROR) {
			struct repmsg_error *errmsg =
				(struct repmsg_error *)msg;
			log_debug(lg, "Recv(%s): protocol error %s (%d): dropped "
			    "seq id %d.%d", robj->name,
			    (errmsg->error < 0 || errmsg->error >= RT_ERR_END) ?
			        "UNKOWN" : replicast_error_str[errmsg->error],
			    errmsg->error, msg_id->sequence_num,
			    msg_id->sub_sequence_num);
			msgpack_unpack_free(u);
			je_free(buf.base);
			return;
		}

		/*
		 * If the unsolicited message is received over TCP, send
		 * error message back otherwise the remote will keep waiting.
		 */
		if (!robj->repstate_init_func[opcode]) {
			log_debug(lg, "Recv(%s): unknown state %s: dropped "
			    "seq id %d.%d", robj->name,
			    replicast_opcode_str[opcode],
			    msg_id->sequence_num, msg_id->sub_sequence_num);
			msgpack_unpack_free(u);
			if (tcp_handle)
				send_err_on_tcp(robj, -ENOENT,
				    (struct repmsg_generic *) msg,
				    tcp_handle, buf.base);
			else
				je_free(buf.base);
			return;
		}
		ctx = repctx_recv(robj, msg_id);
		if (!ctx) {
			log_error(lg, "Recv(%s): ctx out of memory: dropped",
			    robj->name);
			msgpack_unpack_free(u);
			je_free(buf.base);
			return;
		}
		wqe = repctx_wqe_init(ctx, msg_id, orig_id, NULL);
		if (!wqe) {
			log_error(lg, "Recv(%s): wqe out of memory: dropped",
			    robj->name);
			repctx_destroy(ctx);
			msgpack_unpack_free(u);
			je_free(buf.base);
			return;
		}
		wqe->u = u;
		wqe->nread = nread;
		wqe->msg = (struct repmsg_generic *)msg;
		wqe->ctx = ctx;
		ctx->wqe_in = wqe;
		ctx->state = &ctx->state_in;
		ctx->opcode_in = opcode;
		ctx->tcp_handle = tcp_handle;
		err = robj->repstate_init_func[opcode](robj, ctx, ctx->state);
		if (err) {
			if (err != -ENODEV)
				log_warn(lg, "Recv(%s): state init error: %d",
				    robj->name, err);
			repctx_destroy(ctx);
			return;
		}
	} else {
		if (opcode == RT_ERROR && robj->client_ctx) {
			/* client (or initiator) side only from FSM standpoint */
			struct repmsg_error *errmsg =
				(struct repmsg_error *)msg;
			if (errmsg->error == RT_ERR_STALE_FLEXHASH) {
				/* compare if this context already has "correct" genid! */
				uint64_t fh_genid_prev = flexhash_get_genid(FH_GENID_CLIENT, robj->client_ctx);
				if (errmsg->hdr.fh_genid != fh_genid_prev) {
					log_warn(lg, "Recv(%s): RT_ERROR with RT_ERR_STALE_FLEXHASH - scheduling FH fetch",
					    robj->name);
					err = robj->repstate_init_func[RT_SERVER_LIST_GET](robj, NULL, NULL);
					if (err && err != -EBUSY) {
						log_error(lg, "Recv(%s): SLG state init error: %d",
						    robj->name, err);
					}
				}
				return;
			}
		}
	}

	/* in a regular SLG from leader to follower, it makes no sense to do
	 * the genid comparision as it will be different, hence we skip the
	 * RT_SERVER_LIST_RESPONSE in the server context
	 */
	if (robj->server_ctx
	    && opcode != RT_ERROR
	    && opcode != RT_SERVER_LIST_RESPONSE
	    && opcode != RT_SERVER_LIST_GET
	    && (!(msg->hdr.attributes & RD_ATTR_GET_ANY) ||
		 (msg->hdr.attributes & (RD_ATTR_GET_CONSENSUS | RD_ATTR_SERIAL_OP)))) {
		/* genid passed in the message must match the one the flexhash has
		 * genid created at boot time is always 1 indicative of the fact
		 * that flexhash syncronization is not complete
		 */
		uint64_t fh_genid = flexhash_get_genid(FH_GENID_SERVER, robj->server_ctx);
		if ((fh_genid != 1)
		     && flexhash_is_fhready(FH_GENID_SERVER, robj->server_ctx)) {
			if (msg->hdr.fh_genid != fh_genid) {
				log_warn(lg, "flexhash genid mismatch opcode %s "
				    "txcookie %" PRIx64 " seqid %d.%d received: %ld "
				    "expected: %ld", replicast_opcode_str[opcode],
				    msg->hdr.transaction_id.txcookie, msg->hdr.transaction_id.sequence_num,
				    msg->hdr.transaction_id.sub_sequence_num, msg->hdr.fh_genid, fh_genid);

				struct repmsg_error errmsg;
				memset(&errmsg, 0, sizeof (errmsg));
				errmsg.error = RT_ERR_STALE_FLEXHASH;
				/* An error cannot be send by means of UDP MCPROXY*/
				if (ctx && (ctx->attributes & RD_ATTR_UNICAST_UDP_MCPROXY))
					ctx->attributes &= ~RD_ATTR_UNICAST_UDP_MCPROXY;

				if (new_ctx) {
					struct repreq_common *req = ctx->state->data;
					req->inexec++;
					/* FSM not started yet */
					err = replicast_send(robj, ctx, RT_ERROR,
					    (struct repmsg_generic *)&errmsg,
					    (struct repmsg_generic *)msg, NULL,
					    0, NULL, free_ctx_cb, ctx, NULL);
					if (err) {
						req->inexec--;
					}
				} else {
					replicast_send(robj, ctx, RT_ERROR,
					    (struct repmsg_generic *)&errmsg,
					    (struct repmsg_generic *)msg, NULL,
					    0, NULL, NULL /*free_buf_cb*/, buf.base, NULL);
				}
				return;
			}
		}
	}

	state_event(ctx->state, opcode);
}

static void
on_recv(uv_udp_t *req, ssize_t nread, const uv_buf_t buf,
    struct sockaddr *from_addr, unsigned UNUSED(flags))
{
	struct replicast *robj = req->data;
	robj->stats.last_receive_time = get_timestamp_us();

	log_trace(lg, "req %p, nread %ld, from_addr %p", req, nread, from_addr);

	/// @warning we can have valid datagram with 'nread == 0'
	if (nread <= 0) {
		je_free(buf.base);
		return;
	}

	char sender[INET6_ADDRSTRLEN + 1] = { 0 };
	if (from_addr) {
		if (from_addr->sa_family == AF_INET6)
			uv_ip6_name((struct sockaddr_in6 *)from_addr, sender, INET6_ADDRSTRLEN);
		else {
			struct sockaddr_in6 addr6;
			replicast_ip4_encap((struct sockaddr_in *)from_addr, &addr6);
			uv_ip6_name(&addr6, sender, INET6_ADDRSTRLEN);
		}
	}

	replicast_process_recv(robj, buf, nread, sender, NULL, NULL);

}

static void
replicast_set_default_priority(int fd)
{
	int err;
	int cos = 7; /* highest */

	if (getuid() != 0)
		return;

	err = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &cos, sizeof(cos));
	if (err < 0) {
		log_warn(lg, "setting CoS socket %d pri to %d failed (%s)",
		    fd, cos, strerror(errno));
	}
}

void
replicast_state_init(struct replicast *robj, enum replicast_opcode opcode,
    repstate_init_func_t func)
{
	assert(opcode < RT_END && func);
	robj->repstate_init_func[opcode] = func;
}

void
replicast_mcproxy_init(struct replicast *robj, replicast_mcproxy_func_t func)
{
	robj->mcproxy_func = func;
}

int
replicast_getaddrinfo(const char *addr, struct sockaddr_in6 *inaddr,
		      uint32_t flag)
{
	int err;
	int stype = flag == RD_ATTR_UNICAST_TCP ? SOCK_STREAM : SOCK_DGRAM;
	int proto = flag == RD_ATTR_UNICAST_TCP ? IPPROTO_TCP : IPPROTO_UDP;
	int ipv4 = REP_IS_IP4(addr);

	struct addrinfo hints = {
		.ai_family	= ipv4 ? AF_INET : AF_INET6,
		.ai_socktype	= stype,
		.ai_protocol	= proto,
		.ai_flags	= AI_NUMERICHOST
	}, *result = NULL;
	err = getaddrinfo(addr, NULL, &hints, &result);
	if (err)
		log_error(lg, "Cannot get addr info : %d (%s)",
			    err, strerror(errno));
	else {
		if (ipv4)
			replicast_ip4_encap((struct sockaddr_in *)result->ai_addr, inaddr);
		else
			memcpy(inaddr, result->ai_addr, result->ai_addrlen);
		freeaddrinfo(result);
	}
	return err;
}

int
replicast_bind_range(uv_handle_t *socket, uint32_t socket_type,
    const char *listen_addr, uint16_t *listen_port, int scope_id,
    uint16_t port_range, struct sockaddr_in6 *inaddr)
{
	int err = 0;

	err = replicast_getaddrinfo(listen_addr, inaddr, socket_type);
	if (err)
		return err;

	if (REP_IS_4OVER6(inaddr)) {
		struct sockaddr_in inaddr4;
		replicast_ip4_decap(inaddr, &inaddr4);
		while (*listen_port < *listen_port + port_range) {
			inaddr4.sin_port = htons(*listen_port);
			err = socket_type == RD_ATTR_UNICAST_TCP ?
				uv_tcp_bind((uv_tcp_t *)socket, inaddr4) :
				uv_udp_bind((uv_udp_t *)socket, inaddr4, 0);
			if (!err)
				break;
			++*listen_port;
		}
	} else {
		inaddr->sin6_scope_id = scope_id;
		while (*listen_port < *listen_port + port_range) {
			inaddr->sin6_port = htons(*listen_port);
			err = socket_type == RD_ATTR_UNICAST_TCP ?
				uv_tcp_bind6((uv_tcp_t *)socket, *inaddr) :
				uv_udp_bind6((uv_udp_t *)socket, *inaddr, 0);
			if (!err)
				break;
			++*listen_port;
		}
	}
	if (err)
		log_error(lg, "Cannot bind addr %s to TCP/UDP socket: %d (%s)",
		    listen_addr, err, strerror(errno));
	return err;
}

int
replicast_bind(uv_handle_t *socket, uint32_t socket_type,
	       const char *listen_addr, const uint16_t listen_port, int scope_id)
{
	int err;
	struct sockaddr_in6 inaddr;

	err = replicast_getaddrinfo(listen_addr, &inaddr, socket_type);
	if (err)
		return err;

	if (REP_IS_4OVER6(&inaddr)) {
		struct sockaddr_in inaddr4;
		inaddr4.sin_port = htons(listen_port);
		replicast_ip4_decap(&inaddr, &inaddr4);
		err = socket_type == RD_ATTR_UNICAST_TCP ?
			uv_tcp_bind((uv_tcp_t *)socket, inaddr4) :
			uv_udp_bind((uv_udp_t *)socket, inaddr4, 0);
	} else {
		inaddr.sin6_port = htons(listen_port);
		inaddr.sin6_scope_id = scope_id;
		err = socket_type == RD_ATTR_UNICAST_TCP ?
			uv_tcp_bind6((uv_tcp_t *)socket, inaddr) :
			uv_udp_bind6((uv_udp_t *)socket, inaddr, 0);
	}
	if (err)
		log_error(lg, "Cannot bind addr %s:%d to socket: %d",
			  listen_addr, listen_port, err);
	return err;
}

int
replicast_udp_listen(uv_udp_t *socket, struct replicast *robj)
{
	int err;
	int no = 0;

	/*
	 * We use SO_REUSEPORT instead (see comment above)
	 */
	err = setsockopt(socket->io_watcher.fd, SOL_SOCKET, SO_REUSEADDR,
			 &no, sizeof (no));
	if (err) {
		log_debug(lg, "Cannot set SO_REUSEADDR: %d", err);
	}

	err = uv_udp_recv_start(socket, alloc_buffer, on_recv);
	if (err)
		log_error(lg, "Recv start error %d", err);
	return err;
}

/* Receiver (listener) connect request callback */
static void
on_tcp_connect(uv_stream_t *req, int status)
{
	int err;
	int addrlen;
	struct replicast *robj = req->data;
	rt_tcp_t* rtsock;

	log_trace(lg, "Received connection request on: %p", req);

	if (status) {
		log_error(lg, "connect error %d", uv_last_error(req->loop).code);
		return;
	}

	err = rtsock_initialize(&rtsock);
	if (err) {
		log_error(lg, "OOM on connect");
		return;
	}

	rt_stream_t *pstream = &rtsock->stream;

	uv_tcp_init(req->loop, &rtsock->tchandle);
	err = uv_tcp_nodelay(&rtsock->tchandle, 0) ?:
		uv_tcp_keepalive(&rtsock->tchandle, 1, REPLICAST_TCP_KEEPALIVE);
	err = err ?: uv_accept(req, (uv_stream_t *)&rtsock->tchandle);
	if (err) {
		rtsock_finalize(rtsock, 0);
		log_error(lg, "accept error %d", uv_last_error(req->loop).code);
		return;
	}

	rtsock->tchandle.data = req;
	addrlen = sizeof (struct sockaddr_in6);
	err = uv_tcp_getpeername(&rtsock->tchandle,
				 (struct sockaddr *)&rtsock->toaddr,
				 &addrlen);
	if (err) {
		log_error(lg, "failed to get peer name %d",
			  uv_last_error(req->loop).code);
		uv_close((uv_handle_t *)&rtsock->tchandle, on_tcp_close);
		return;
	}

	/* Initialize TCP stream processing state machine */
	rt_tcp_stream_init(pstream);

	rtsock->tchandle.data = pstream;
	rtsock->robj = robj;
	pstream->robj = req->data;
	pstream->tcp_handle = rtsock;

	log_trace(lg, "Starting to read on: %p", pstream);
	err = uv_read_start((uv_stream_t *)&rtsock->tchandle, alloc_buffer,
			    on_tcp_peer_read);
	if (err) {
		log_error(lg, "Accept error %d", uv_last_error(req->loop).code);
		rtsock->tchandle.data = NULL;
		shut_tcp_conn(rtsock);
		return;
	}
	/* Else add to tcp handles list for closing at termination */
	robj_add_tcp_handle(&robj->tcp_handles, rtsock);
}

int
replicast_tcp_listen(uv_tcp_t *socket, struct replicast *robj)
{
	int err;
	int no = 0;

	/*
	 * We use SO_REUSEPORT instead (see comment above)
	 */
	err = setsockopt(socket->io_watcher.fd, SOL_SOCKET, SO_REUSEADDR,
			 &no, sizeof (no));
	if (err) {
		log_debug(lg, "Cannot set SO_REUSEADDR: %d", err);
	}

	socket->data = robj;
	err = uv_listen((uv_stream_t*)socket, SOMAXCONN, on_tcp_connect);
	if (err)
		log_warn(lg, "Recv listen error %s", strerror(errno));
	else
		uv_tcp_simultaneous_accepts(socket, 1);
	return err;
}

int
replicast_bind_n_listen(uv_handle_t *socket, uint32_t socket_type,
			struct replicast *robj, const char *listen_addr,
			const uint16_t listen_port, int scope_id)
{
	int err;

	err = replicast_bind(socket, socket_type,
			     listen_addr, listen_port, scope_id);
	return err ? err : (socket_type == RD_ATTR_UNICAST_TCP ?
			    replicast_tcp_listen((uv_tcp_t *)socket, robj) :
			    replicast_udp_listen((uv_udp_t *)socket, robj));
}

int
replicast_socket_setopts(uv_udp_t *socket, uv_os_sock_t sock,
		 int *scope_id, const int ttl, int reuse_port, int ipv4)
{
	int err;
	int yes = 1;

	replicast_set_default_priority(sock);

	/*
	 * New feature in Linux 3.9 which is helping to avoid port
	 * hijacking problem assosiated with SO_REUSEADDR. With that
	 * incoming packets will be distributed across cores more
	 * evenly, without cached thread variables trashing..
	 */
	if (reuse_port) {
		err = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,
				 &yes, sizeof (yes));
		if (err) {
			log_error(lg, "Cannot set SO_REUSEPORT: %d (%s)",
			    err, strerror(errno));
			return err;
		}
	}

	if (ipv4)
		return 0;

	err = setsockopt(socket->io_watcher.fd, IPPROTO_IPV6,
			 IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
	if (err) {
		log_error(lg, "Cannot set IPv6 hops: %d (%s)",
		    err, strerror(errno));
		return err;
	}

	err = setsockopt(socket->io_watcher.fd, IPPROTO_IPV6,
			 IPV6_MULTICAST_LOOP, &yes, sizeof(yes));
	if (err) {
		log_error(lg, "Cannot set IPv6 loop: %d (%s)",
		    err, strerror(errno));
		return err;
	}

	err = setsockopt(socket->io_watcher.fd, SOL_IPV6, IPV6_MULTICAST_IF,
			 scope_id, sizeof (*scope_id));
	if (err) {
		log_error(lg, "Cannot select IF for UDP socket: %d (%s)",
				err, strerror(errno));
		return err;
	}
	return err;
}

int
replicast_udp_socket_init(uv_udp_t *handle, uv_os_sock_t *sock, uv_loop_t *loop,
    int ipv4)
{
	int err;

	*sock = socket(ipv4 ? AF_INET : AF_INET6,
	    SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
	if (*sock < 0) {
		log_error(lg, "Cannot create UDP socket: %s", strerror(errno));
		return errno;
	}

	err = uv_udp_init(loop, handle);
	if (err) {
		close(*sock);
		log_error(lg, "Cannot initialize UDP socket: %d", err);
		return err;
	}
	handle->data = (void*)1;

	err = uv_udp_open(handle, *sock);
	if (err) {
		close(*sock);
		log_error(lg, "Cannot open UDP socket: %d (%s)",
		    err, strerror(errno));
		return err;
	}
	return err;
}

int
replicast_tcp_socket_init(uv_tcp_t *handle, uv_os_sock_t *sock, uv_loop_t *loop,
    int domain)
{
	int err;

	*sock = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       IPPROTO_TCP);
	if (*sock < 0) {
		log_error(lg, "Cannot create TCP socket: %s", strerror(errno));
		return errno;
	}

	err = uv_tcp_init(loop, handle);
	if (err) {
		close(*sock);
		log_error(lg, "Cannot initialize TCP socket: %d", err);
		return err;
	}

	err = uv_tcp_open(handle, *sock);
	if (err) {
		close(*sock);
		log_error(lg, "Cannot open TCP socket: %d (%s)",
		    err, strerror(errno));
		return err;
	}
	return err;
}

int
replicast_start_listener(uv_udp_t *handle, struct replicast *robj,
			 const char *listen_addr, const uint16_t listen_port,
			 int if_index, const int ttl)
{
	int err;
	int scope_id = if_index;
	uv_os_sock_t sock;

	err = replicast_udp_socket_init(handle, &sock, robj->loop, robj->ipv4);
	if (handle->data)
		handle->data = robj;
	if (err) {
		log_error(lg, "Cannot initialize UDP socket: %d", err);
		return err;
	}

	err = replicast_socket_setopts(handle, sock, &scope_id, ttl, 1, robj->ipv4);
	if (err) {
		close(sock);
		log_error(lg, "Cannot set initialize UDP socket options: %d",
			  err);
		return err;
	}
	err = replicast_bind_n_listen((uv_handle_t *)handle, RD_ATTR_UNICAST_UDP,
				      robj, listen_addr, listen_port, scope_id);
	if (err) {
		log_error(lg, "Cannot bind to UDP socket : %d", err);
		return err;
	}

	return 0;
}

static void
replicast_mcproxy__on_call(uv_async_t *handle, int status)
{
	struct replicast *robj = container_of(handle, struct replicast, mcproxy_async);
	QUEUE* q;

	do {
		uv_mutex_lock(&robj->mcproxy_mutex);
		if (QUEUE_EMPTY(&robj->mcproxy_queue)) {
			uv_mutex_unlock(&robj->mcproxy_mutex);
			return;
		}
		q = QUEUE_HEAD(&robj->mcproxy_queue);
		struct replicast_mcproxy_call *c =
			QUEUE_DATA(q, struct replicast_mcproxy_call, item);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		uv_mutex_unlock(&robj->mcproxy_mutex);

		c->method(c);
		je_free(c);
	} while (1);
}

void
replicast_mcproxy_recv(struct replicast_mcproxy_call *c)
{
	struct replicast *robj = (struct replicast *)c->args[0];
	uv_buf_t buf = { .base = (char *)c->args[1], .len = (size_t)(long)c->args[2] };
	ssize_t nread = (ssize_t)(long)c->args[3];
	char *sender = (char *)c->args[4];

	robj->stats.last_receive_time = get_timestamp_us();

	replicast_process_recv(robj, buf, nread, sender, NULL, NULL);

	je_free(sender);
}

static void
replicast_on_unix_client_recv(uv_stream_t *req, ssize_t nread, uv_buf_t buf)
{
	struct replicast *robj = req->data;

	log_trace(lg, "req %p, nread %lu", req, nread);
	if (nread > 0) {
		replicast_process_recv(robj, buf, nread, "serverPipe", NULL, (uv_pipe_t *)req);
	}
	else {
		if (buf.base)
			je_free(buf.base);
		if (nread < 0) {
			uv_close((uv_handle_t*)req, NULL);
			req->data = NULL;
			if (uv_last_error(req->loop).code != UV_EOF)
				log_error(lg, "Error while reading from unix socket: %s", uv_strerror(uv_last_error(req->loop)));
		}
	}
}

static void
replicast_on_unixsock_connect(uv_connect_t *req, int status)
{
	if (status) {
		log_warn(lg, "Error while connecting to unix socket: %d", status);
		uv_close((uv_handle_t*)req->handle, NULL);
		req->handle->data = NULL;
		return;
	}
	uv_read_start((uv_stream_t*) req->handle, alloc_buffer, replicast_on_unix_client_recv);
}

static void
replicast_on_unix_peer_socket_close(uv_handle_t* handle) {
	char key_str[32] = {0};
	struct replicast *robj = handle->data;
	sprintf(key_str, "%p", handle);
	hashtable_remove(robj->unix_socket_hash, key_str, strlen(key_str) + 1);
	je_free(handle);
}

static void
replicast_on_unix_peer_recv(uv_stream_t *req, ssize_t nread, uv_buf_t buf)
{
	struct replicast *robj = req->data;

	log_trace(lg, "req %p, nread %lu", req, nread);
	if (nread > 0) {
		replicast_process_recv(robj, buf, nread, "clientPipe", NULL, (uv_pipe_t *)req);
	}
	else {
		if (buf.base)
			je_free(buf.base);
		if (nread < 0) {
			if (uv_last_error(req->loop).code != UV_EOF)
				log_error(lg, "Error while reading from unix socket: %s", uv_strerror(uv_last_error(req->loop)));
			uv_close((uv_handle_t*)req, replicast_on_unix_peer_socket_close);
		}
	}
}



static void
replicast_on_unixsock_new_connection(uv_stream_t *server, int status)
{
	int result;
	int err;
	char key_str[32] = {0};
	if (status) {
		log_error(lg, "Error while accepting unix socket: %d", status);
		return;
	}

	struct replicast *robj = (struct replicast *)server->data;

	uv_pipe_t *client_req = (uv_pipe_t*) je_malloc(sizeof(uv_pipe_t));
	if (!client_req) {
		log_error(lg, "OOM on unix socket new conn: %d", -ENOMEM);
		return;
	}

	uv_pipe_init(robj->loop, client_req, 0);

	result = uv_accept(server, (uv_stream_t *)client_req);

	if (result == 0) {
		client_req->data = robj;
		sprintf(key_str, "%p", client_req);
		err = hashtable_put(robj->unix_socket_hash, key_str, strlen(key_str) + 1, client_req, sizeof(uv_handle_t));
		if (err) {
			log_error(lg, "Cannot add item into unix sockets hash table: %d", -err);
			return;
		}
		uv_read_start((uv_stream_t*) client_req, alloc_buffer, replicast_on_unix_peer_recv);
	} else {
		uv_close((uv_handle_t *)client_req, replicast_on_unix_peer_socket_close);
	}
}

/*
 * 1. listen_*                 - Unicast listen address, port and unixsock. This
 *				 is usually set to "::" on server and
 *				 to broker-ip on client.
 * 2. msg_origin_addr	       - This (binary form) is passed into header
 *				 of the message. This helps the receiver to
 *				 reply back. The port is same as listen port.
 *				 When listen_addr != "::", msg_origin_addr =
 *				 listen_addr. Unicast IO is the current
 *				 use-case.
 *				 Don't have to listen on msg_origin_addr because
 *				 either listen_addr == msg_origin_addr or
 *				 we are listening on every IP ("::").
 * 3. mc_addr, mc_port	       - Multicast listen address and port.
 */
struct replicast *
replicast_init(const char *name, uv_loop_t *loop, const char *listen_addr,
    const uint16_t listen_port, const char *listen_unixsock,
    const char *msg_origin_addr, const char *mc_addr, const uint16_t mc_port,
    const int mc_ttl, void *priv)
{
	int err, retry;
	struct replicast *robj;
	uv_os_sock_t udp_sock, tcp_sock;

	robj = je_calloc(1, sizeof (*robj));
	if (!robj) {
		log_error(lg, "Cannot allocate memory for replicast: -ENOMEM");
		return NULL;
	}
	robj->ipv4 = REP_IS_IP4(listen_addr);
	robj->loop = loop;
	robj->priv_data = priv;
	strcpy(robj->name, name);
	robj->sequence_cnt = 1;
	robj->mc_ttl = mc_ttl;

	QUEUE_INIT(&robj->mcproxy_queue);
	uv_mutex_init(&robj->mcproxy_mutex);
	uv_async_init(robj->loop, &robj->mcproxy_async, replicast_mcproxy__on_call);

	int scope_id = 0;
	char *zone_idx = strchr(listen_addr, '%');
	if (zone_idx) {
		*zone_idx = '\0';
		scope_id = if_nametoindex(zone_idx + 1);
	}

	if (mc_addr) {
		robj->mc_recv_port = mc_port;
		robj->mc_recv_sockets = hashtable_create(REPLICAST_DEVROW_MAX,
			HT_VALUE_CONST, 0.05);
		if (!robj->mc_recv_sockets) {
			log_error(lg, "Cannot create MC sockets hashtable");
			return NULL;
		}
	}

	if (listen_unixsock) {
		int err;
		if (strncmp(name, "client", 6) == 0) {
			uv_pipe_init(loop, &robj->unixsock, 0);

			robj->unixsock_req.data = robj;
			robj->unixsock.data = robj;
			uv_pipe_connect(&robj->unixsock_req, &robj->unixsock, listen_unixsock,
			    replicast_on_unixsock_connect);
		} else if (strncmp(name, "daemon", 6) == 0) {
			if (access(listen_unixsock, F_OK) == 0 ) {
				unlink(listen_unixsock);
			}
			uv_pipe_init(loop, &robj->unixsock, 0);
			robj->unixsock.data = robj;
			char *sock_dir1 = je_strdup(listen_unixsock);
			char *sock_dir2 = dirname(sock_dir1);
			mkdir(sock_dir2, 0775); sock_dir2 = NULL;
			je_free(sock_dir1); sock_dir1 = NULL;
			err = uv_pipe_bind(&robj->unixsock, listen_unixsock);
			if (err) {
				log_error(lg, "Error binding unix socket '%s': %d (%m)",
						listen_unixsock, -errno);
				uv_close((uv_handle_t *)&robj->unixsock, NULL);
				robj->unixsock.data = NULL;
				return NULL;
			}

			if (chmod(listen_unixsock, 0777) != 0)
				log_error(lg, "Error changing permissions on unixsocket: %d", -errno);

			robj->unix_socket_hash = hashtable_create(16, HT_VALUE_CONST, 0.5);
			if (!robj->unix_socket_hash) {
				log_error(lg, "Cannot create unix sockets hashtable");
				uv_close((uv_handle_t *)&robj->unixsock, NULL);
				robj->unixsock.data = NULL;
				return NULL;
			}

			err = uv_listen((uv_stream_t*)&robj->unixsock, 128, replicast_on_unixsock_new_connection);
			if (err) {
				log_error(lg, "Error listening unix socket: %d", -errno);
				hashtable_destroy(robj->unix_socket_hash);
				robj->unix_socket_hash = NULL;
				uv_close((uv_handle_t *)&robj->unixsock, NULL);
				robj->unixsock.data = NULL;
				return NULL;
			}
			log_info(lg, "Listening on unixsock %s", listen_unixsock);
		}
		robj->listen_unixsock = je_strdup(listen_unixsock);
	}

#if TCP_EN
	/* Initialize TCP socket */
	tcp_sock = -1;
	err = replicast_tcp_socket_init(&robj->recv_tcp_socket, &tcp_sock,
					robj->loop, ipv4 ? AF_INET : AF_INET6);
	if (err) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "Cannot initialize TCP recv socket: %d",
			  uv_last_error(loop).code);
		return NULL;
	}

	/*
	 * uv_tcp_bind6()  may not return error when bound to the same port that
	 * is in use. uv_listen() will return an error if the port is in use.
	 */
	robj->tcp_recv_port = listen_port;
	do {
		err =
		replicast_bind_n_listen((uv_handle_t *)&robj->recv_tcp_socket,
					RD_ATTR_UNICAST_TCP, robj, listen_addr,
					robj->tcp_recv_port, scope_id);
		if (err != 0) {
			retry = 1;
			robj->tcp_recv_port++;
			if (robj->tcp_recv_port > listen_port + 4095)
				break;
		} else
			retry = 0;
	} while (retry);
	log_info(lg, "Replicast(%s) listens on TCP %s.%d, origin %s, "
		     "scope_id=%d", name, listen_addr, robj->tcp_recv_port,
		     msg_origin_addr, scope_id);
#endif

	/* Initialize UDP socket */
	udp_sock = -1;
	err = replicast_udp_socket_init(&robj->recv_socket, &udp_sock,
					robj->loop, robj->ipv4);
	if (robj->recv_socket.data)
		robj->recv_socket.data = robj;
	if (err) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "Cannot initialize UDP recv socket: %d",
			  uv_last_error(loop).code);
		return NULL;
	}
	/*
	 * Ensure that all unicast trafic has its own port.
	 */
	robj->udp_recv_port = listen_port;
	err = replicast_bind_range((uv_handle_t *)&robj->recv_socket,
				   RD_ATTR_UNICAST_UDP, listen_addr,
				   &robj->udp_recv_port, scope_id,
				   4096, &robj->recv_addr);
	if (err) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "Cannot bind addr %s to UDP socket: %d (%s)",
		    listen_addr, err, strerror(errno));
		return NULL;
	}

	replicast_set_default_priority(udp_sock);
	err = replicast_udp_listen(&robj->recv_socket, robj);
	if (err) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "Cannot bind to UDP recv socket : %d",
			  uv_last_error(loop).code);
		return NULL;
	}
	log_info(lg, "Replicast(%s) listens on UDP %s.%d, origin %s, "
		     "scope_id=%d", name, listen_addr, robj->udp_recv_port,
		      msg_origin_addr, scope_id);

	zone_idx = strchr(msg_origin_addr, '%');
	if (zone_idx) {
		*zone_idx = '\0';
		if (!scope_id)
			scope_id = if_nametoindex(zone_idx + 1);
	}
	if (scope_id == 0 && strncmp(msg_origin_addr, "fe80:", 5) == 0) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "Invalid scope for link-local IPv6 address: %s",
			  msg_origin_addr);
		return NULL;
	}
	err = replicast_getaddrinfo(msg_origin_addr, &robj->msg_origin_udpaddr,
				    RD_ATTR_UNICAST_UDP);
	if (err) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "IPv6 address: %s error: %s",
			  msg_origin_addr, gai_strerror(err));
		return NULL;
	}
	robj->msg_origin_udpaddr.sin6_port = htons(robj->udp_recv_port);
	robj->msg_origin_udpaddr.sin6_scope_id = scope_id;
	robj->msg_origin_udpaddr.sin6_family = robj->ipv4 ? AF_INET : AF_INET6;
	robj->msg_origin_udpaddr.sin6_flowinfo = 0;

	err = replicast_getaddrinfo(msg_origin_addr, &robj->msg_origin_tcpaddr,
				    RD_ATTR_UNICAST_TCP);
	if (err) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "IPv6 address: %s error: %s",
			  msg_origin_addr, gai_strerror(err));
		return NULL;
	}
	robj->msg_origin_tcpaddr.sin6_port = htons(robj->tcp_recv_port);
	robj->msg_origin_tcpaddr.sin6_scope_id = scope_id;
	robj->msg_origin_tcpaddr.sin6_family = robj->ipv4 ? AF_INET : AF_INET6;
	robj->msg_origin_tcpaddr.sin6_flowinfo = 0;

	if (err) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "Cannot bind to TCP recv socket : %d",
			  uv_last_error(loop).code);
		return NULL;
	}

	udp_sock = -1;
	err = replicast_udp_socket_init(&robj->send_socket, &udp_sock,
					robj->loop, robj->ipv4);
	if (robj->send_socket.data)
		robj->send_socket.data = robj;
	if (err) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "Cannot initialize UDP send socket: %d",
			  uv_last_error(loop).code);
		return NULL;
	}

	replicast_set_default_priority(udp_sock);

	err = replicast_socket_setopts(&robj->send_socket, udp_sock,
					&scope_id, mc_ttl, 0, robj->ipv4);
	if (err) {
		replicast_destroy(robj);
		replicast_finish_destroy(robj);
		log_error(lg, "Cannot set initialize UDP send socket"
			      " options: %d", uv_last_error(loop).code);
		return NULL;
	}

	/* these have to be externally initialized depending on the context */
	robj->server_ctx = NULL;
	robj->client_ctx = NULL;

	return robj;
}

void
replicast_finish_destroy(struct replicast *robj)
{
	if (robj->mc_recv_sockets)
		hashtable_destroy(robj->mc_recv_sockets);

	if (robj->unix_socket_hash)
		hashtable_destroy(robj->unix_socket_hash);

	je_free(robj);
}

int
replicast_destroy(struct replicast *robj)
{
	int err;
	unsigned int num_usock_keys;
	unsigned int i;
	char **usock_keys;
	uv_handle_t * hndl;

#if TCP_EN
	uv_read_stop((uv_stream_t *)&robj->recv_tcp_socket);
	uv_close((uv_handle_t *)&robj->recv_tcp_socket, NULL);
#endif

	if (robj->recv_socket.data) {
		err = uv_udp_recv_stop(&robj->recv_socket);
		if (err < 0) {
			log_error(lg, "Cannot stop UDP receiver %s",
			    robj->name);
			return err;
		}
		uv_close((uv_handle_t *)&robj->recv_socket, NULL);
		robj->recv_socket.data = NULL;
	}

	if (robj->send_socket.data) {
		uv_close((uv_handle_t *)&robj->send_socket, NULL);
		robj->send_socket.data = NULL;
	}

	if (robj->unixsock.data) {
		uv_close((uv_handle_t *)&robj->unixsock, NULL);
		robj->unixsock.data = NULL;
		if (robj->unix_socket_hash) {
			usock_keys = (char**)hashtable_keys(robj->unix_socket_hash, &num_usock_keys);
			for (i = 0; i < num_usock_keys; i++) {
				hndl = (uv_handle_t *)hashtable_get(robj->unix_socket_hash, usock_keys[i], strlen(usock_keys[i]) + 1, NULL);
				uv_close(hndl, replicast_on_unix_peer_socket_close);
			}
			je_free(usock_keys);
		}
		je_free(robj->listen_unixsock);
	}

	rt_tcp_t *temp, *handle = robj->tcp_handles;
	while (handle != NULL) {
		temp = handle;
		handle = handle->next;
		uv_mutex_lock(&temp->conn_lock);
		switch (temp->state) {
		case RT_TCP_IN_PROGRESS:
			temp->term = 1;
			uv_mutex_unlock(&temp->conn_lock);
			break;
		case RT_TCP_CONNECTED:
			uv_mutex_unlock(&temp->conn_lock);
			uv_read_stop((uv_stream_t *)&temp->tchandle);
			shut_tcp_conn(temp);
			break;
		default:
			uv_mutex_unlock(&temp->conn_lock);
			uv_read_stop((uv_stream_t *)&temp->tchandle);
			robj_rm_tcp_handle((uv_handle_t *)temp);
			uv_close((uv_handle_t *)&temp->tchandle, on_tcp_close);
			break;
		}
	}

	uv_close((uv_handle_t *)&robj->mcproxy_async, NULL);
	uv_mutex_destroy(&robj->mcproxy_mutex);

	return 0;
}

int
replicast_pack_uint128(msgpack_p *p, const uint128_t *v)
{
	int err;

	err = msgpack_pack_array(p, 2);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, uint128_lo(v));
	if (err)
		return err;
	err = msgpack_pack_uint64(p, uint128_hi(v));
	return err;
}

int
replicast_unpack_uint128(msgpack_u *u, uint128_t *v)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != 2)
		return -EBADF;
	err = msgpack_unpack_uint64(u, &uint128_lo(v));
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &uint128_hi(v));
	return err;
}

static inline int
replicast_pack_uint256(msgpack_p *p, const uint256_t *v)
{
	int err;

	err = msgpack_pack_array(p, 2);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &uint256_lo(v));
	if (err)
		return err;
	err = replicast_pack_uint128(p, &uint256_hi(v));
	return err;
}

static inline int
replicast_unpack_uint256(msgpack_u *u, uint256_t *v)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != 2)
		return -EBADF;
	err = replicast_unpack_uint128(u, &uint256_lo(v));
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &uint256_hi(v));
	return err;
}

int
replicast_pack_uint512(msgpack_p *p, const uint512_t *v)
{
	int err;

	err = msgpack_pack_array(p, 2);
	if (err)
		return err;
	err = replicast_pack_uint256(p, &uint512_lo(v));
	if (err)
		return err;
	err = replicast_pack_uint256(p, &uint512_hi(v));
	return err;
}

int
replicast_unpack_uint512(msgpack_u *u, uint512_t *v)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != 2)
		return -EBADF;
	err = replicast_unpack_uint256(u, &uint512_lo(v));
	if (err)
		return err;
	err = replicast_unpack_uint256(u, &uint512_hi(v));
	return err;
}

static inline int
replicast_pack_transaction_id(msgpack_p *p,
    struct replicast_transaction_id *msg)
{
	int err;

	err = msgpack_pack_int32(p, msg->opcode);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->protocol_version);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->fhrow);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->txcookie);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->source_port);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->source_addr);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->sequence_num);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->sub_sequence_num);
	return err;
}

static inline int
replicast_unpack_transaction_id(msgpack_u *u,
	struct replicast_transaction_id *msg)
{
	int err;

	err = msgpack_unpack_int32(u, (int32_t *)&msg->opcode);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->protocol_version);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->fhrow);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->txcookie);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->source_port);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->source_addr);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->sequence_num);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->sub_sequence_num);
	return err;
}

static inline int
replicast_pack_datagram_hdr(msgpack_p *p, struct replicast_datagram_hdr *msg,
    uint32_t *datagram_num_byte)
{
	int err;

	err = replicast_pack_transaction_id(p, &msg->transaction_id);
	if (err)
		return err;
	err = replicast_pack_transaction_id(p, &msg->orig_id);
	if (err)
		return err;
	if (msg->datagram_num > 256)
		return -EBADF;
	err = msgpack_pack_uint16(p, msg->datagram_num);
	if (err)
		return err;
	*datagram_num_byte = msgpack_get_len(p) - 1;
	err = msgpack_pack_uint64(p, msg->attributes);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->hash_type);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->fh_genid);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->data_len);
	return err;
}

int
replicast_unpack_datagram_hdr(msgpack_u *u, struct replicast_datagram_hdr *msg)
{
	int err;

	err = replicast_unpack_transaction_id(u, &msg->transaction_id);
	if (err)
		return err;
	err = replicast_unpack_transaction_id(u, &msg->orig_id);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->datagram_num);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->attributes);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->hash_type);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->fh_genid);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->data_len);
	return err;
}

int
replicast_pack_generic(msgpack_p *p, struct repmsg_generic *msg,
    uint32_t *datagram_num_byte, uint32_t *num_datagrams_byte)
{
	int err;

	err = replicast_pack_datagram_hdr(p,
	    (struct replicast_datagram_hdr *)msg, datagram_num_byte);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->num_datagrams);
	if (err)
		return err;
	*num_datagrams_byte = msgpack_get_len(p) - 1;

	return err;
}

int
replicast_unpack_generic(msgpack_u *u, struct repmsg_generic *msg)
{
	int err;

	err = replicast_unpack_datagram_hdr(u,
	    (struct replicast_datagram_hdr *)msg);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->num_datagrams);
	return err;
}

static inline int
replicast_pack_object_name(msgpack_p *p, struct replicast_object_name *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->name_hash_id);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &msg->parent_hash_id);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->uvid_timestamp);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->generation);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->vmm_gen_id);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->version_uvid_timestamp);
	return err;
}

static inline int
replicast_unpack_object_name(msgpack_u *u, struct replicast_object_name *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->name_hash_id);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->parent_hash_id);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->uvid_timestamp);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->generation);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->vmm_gen_id);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->version_uvid_timestamp);
	return err;
}

/*
 * Common reptrans NG request pack/unpack
 * It holds payload's hashID in the header
 */
int
replicast_pack_reptrans_ng(msgpack_p *p, struct repmsg_ng *msg) {
	int err = msgpack_pack_uint16(p, msg->attr);
	if (!err)
		err = msgpack_pack_uint64(p, msg->hashID);
	return err;
}

int
replicast_unpack_reptrans_ng(msgpack_u *u, struct repmsg_ng *msg) {
	int err = msgpack_unpack_uint16(u, &msg->attr);
	if (!err)
		err = msgpack_unpack_uint64(u, &msg->hashID);
	return err;
}

/*
 * Pack: PING-PONG
 */
int
replicast_pack_pingpong(msgpack_p *p, struct repmsg_pingpong *msg)
{
	int err;

	err = msgpack_pack_uint32(p, msg->message_size);
	if (err)
		return err;
	err = msgpack_pack_raw(p, msg->message, msg->message_size);
	if (err)
		return err;
	return err;
}

/*
 * Unpack: PING-PONG
 */
int
replicast_unpack_pingpong(msgpack_u *u, struct repmsg_pingpong *msg)
{
	int err;

	err = msgpack_unpack_uint32(u, &msg->message_size);
	if (err)
		return err;
	unsigned int n;
	err = msgpack_unpack_raw(u, (const uint8_t **)&msg->message, &n);
	if (err)
		return err;
	if (n != msg->message_size)
		return -EBADF;
	return err;
}

int
replicast_pack_blob_lookup(msgpack_p *p, struct repmsg_blob_lookup *msg) {
	int err;
	err = replicast_pack_uint512(p, &msg->chid);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->ttag);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->hash_type);
	return err;
}

int
replicast_unpack_blob_lookup(msgpack_u *u, struct repmsg_blob_lookup *msg) {
	int err;
	err = replicast_unpack_uint512(u, &msg->chid);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->ttag);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->hash_type);
	return err;
}

int
replicast_pack_blob_lookup_result(msgpack_p *p, struct repmsg_blob_lookup_result *msg) {
	int err;
	err = msgpack_pack_uint8(p, msg->ndevs);
	return err;
}

int
replicast_pack_blob_lookup_ack(msgpack_p *p, struct repmsg_blob_lookup_ack *msg) {
	int err;
	err = msgpack_pack_uint8(p, msg->ndevs);
	return err;
}

int
replicast_unpack_blob_lookup_result(msgpack_u *u, struct repmsg_blob_lookup_result *msg) {
	int err;
	err = msgpack_unpack_uint8(u, &msg->ndevs);
	return err;
}

int
replicast_unpack_blob_lookup_ack(msgpack_u *u, struct repmsg_blob_lookup_ack *msg) {
	int err;
	err = msgpack_unpack_uint8(u, &msg->ndevs);
	return err;
}

int replicast_pack_uvbuf_vdevs(msgpack_p *p, uint128_t *vdevs, int n_vdevs)
{
	int err;
	for (int i = 0; i < n_vdevs; i++) {
		err = replicast_pack_uint128(p, vdevs + i);
		if (err) {
			log_notice(lg, "pack error %d", err);
			return err;
		}
	}

	return 0;
}

int replicast_unpack_uvbuf_vdevs(msgpack_u *u, int n_vdevs,
    uint128_t *vdevs)
{
	int err;
	for (int i = 0; i < n_vdevs; i++) {
		err = replicast_unpack_uint128(u, &vdevs[i]);
		if (err) {
			log_notice(lg, "unpack error %d", err);
			return err;
		}
	}
	return 0;
}
/*
 * Pack: ERROR
 */
int
replicast_pack_error(msgpack_p *p, struct repmsg_error *msg)
{
	int err;
	uint32_t datagram_num_byte;

	err = replicast_pack_datagram_hdr(p, &msg->hdr, &datagram_num_byte);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->num_datagrams);
	if (err)
		return err;
	err = msgpack_pack_int32(p, msg->error);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->ngcount);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->is_gwcache);
	if (err)
		return err;
	err = msgpack_pack_int32(p, msg->fddelta);
	return err;
}

/*
 * Unpack: ERROR
 */
int
replicast_unpack_error(msgpack_u *u, struct repmsg_error *msg)
{
	int err;
	err = replicast_unpack_datagram_hdr(u, &msg->hdr);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->num_datagrams);
	if (err)
		return err;
	err = msgpack_unpack_int32(u, &msg->error);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->ngcount);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->is_gwcache);
	if (err)
		return err;
	err = msgpack_unpack_int32(u, &msg->fddelta);
	return err;
}

int replicast_pack_payload_rcvd(msgpack_p *p, struct repmsg_payload_rcvd *msg)
{
	int err;
	uint32_t datagram_num_byte;

	err = replicast_pack_datagram_hdr(p, &msg->hdr, &datagram_num_byte);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->ngcount);
	if (err)
		return err;
	err = msgpack_pack_int32(p, msg->fddelta);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->put_delta);
	return err;
}


int replicast_unpack_payload_rcvd(msgpack_u *u, struct repmsg_payload_rcvd *msg)
{
	int err;
	err = replicast_unpack_datagram_hdr(u, &msg->hdr);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->ngcount);
	if (err)
		return err;
	err = msgpack_unpack_int32(u, &msg->fddelta);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->put_delta);
	return err;
}


/*
 * Pack: RECOVERY
 */
int
replicast_pack_recovery(msgpack_p *p, struct repmsg_recovery *msg)
{
	int err;
	uint32_t datagram_num_byte;

	err = replicast_pack_datagram_hdr(p, &msg->hdr, &datagram_num_byte);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &msg->name_hash_id);
	return err;
}

/*
 * Unpack: RECOVERY
 */
int
replicast_unpack_recovery(msgpack_u *u, struct repmsg_recovery *msg)
{
	int err;
	err = replicast_unpack_datagram_hdr(u, &msg->hdr);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->name_hash_id);
	return err;
}

/*
 * Pack: RECOVERY ACK
 */
int
replicast_pack_recovery_ack(msgpack_p *p, struct repmsg_recovery_ack *msg)
{
	int err;
	uint32_t datagram_num_byte;
	err = replicast_pack_datagram_hdr(p, &msg->hdr, &datagram_num_byte);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_pack_int32(p, msg->status);
	if (err)
		return err;
	err = msgpack_pack_int32(p, msg->ngcount);
	return err;
}
/*
 * Unpack: RECOVERY ACK
 */
int
replicast_unpack_recovery_ack(msgpack_u *u, struct repmsg_recovery_ack *msg)
{
	int err;
	err = replicast_unpack_datagram_hdr(u, &msg->hdr);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_unpack_int32(u, &msg->status);
	if (err)
		return err;
	err = msgpack_unpack_int32(u, &msg->ngcount);
	return err;
}
/*
 * Pack: SERVER_LIST_GET
 */
int
replicast_pack_server_list_get(msgpack_p *p, struct repmsg_server_list_get *msg)
{
	int err;

	err = replicast_pack_uint128(p, &msg->parent_serverid);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->maximum_immediate_content_size);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->maximum_number_of_delegated_gets);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->reception_window);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->sender_serverid);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->sender_recv_addr);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->sender_recv_port);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->sender_flags);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->zone);
	if (err)
		return err;
	if (msg->sender_flags & SLG_SENDER_SERVER) {
		uint32_t ndevs = msg->nr_vdevs;
		err = msgpack_pack_uint32(p, msg->nr_vdevs);
		if (err)
			return err;
		if (ndevs > 0) {
			err = replicast_pack_repvdev(p, msg->vdevs,
			    msg->nr_vdevs, 0);
			if (err)
				return err;
		}
	}
	return 0;
}

/*
 * Unpack: SERVER_LIST_GET
 */
int
replicast_unpack_server_list_get(msgpack_u *u,
	struct repmsg_server_list_get *msg)
{
	int err; uint32_t n;
	struct cl_vdev *vdevlist;

	err = replicast_unpack_uint128(u, &msg->parent_serverid);
	if (err) {
		return err;
	}
	err = msgpack_unpack_uint32(u, &msg->maximum_immediate_content_size);
	if (err) {
		return err;
	}
	err = msgpack_unpack_uint32(u, &msg->maximum_number_of_delegated_gets);
	if (err) {
		return err;
	}
	err = msgpack_unpack_uint32(u, &msg->reception_window);
	if (err) {
		return err;
	}
	err = replicast_unpack_uint128(u, &msg->sender_serverid);
	if (err) {
		return err;
	}
	err = replicast_unpack_uint128(u, &msg->sender_recv_addr);
	if (err) {
		return err;
	}
	err = msgpack_unpack_uint16(u, &msg->sender_recv_port);
	if (err) {
		return err;
	}
	err = msgpack_unpack_uint32(u, &msg->sender_flags);
	if (err) {
		return err;
	}
	err = msgpack_unpack_uint16(u, &msg->zone);
	if (err) {
		return err;
	}
	if (msg->sender_flags & SLG_SENDER_SERVER) {
		err = msgpack_unpack_uint32(u, &msg->nr_vdevs);
		if (err) {
			return err;
		}
		if (msg->nr_vdevs > 0) {
			err = msgpack_unpack_array(u, &n);
			if (err) {
				return err;
			}
			if (n != msg->nr_vdevs) {
				return -EBADF;
			}
			msg->vdevs = je_calloc(n, sizeof (struct cl_vdev));
			if (!msg->vdevs) {
				return -ENOMEM;
			}
			err = replicast_unpack_repvdev(u, msg->vdevs,
			    msg->nr_vdevs, 0);
			if (err) {
				je_free(msg->vdevs);
				return err;
			}
		} else {
			msg->vdevs = NULL;
		}

	}
	return 0;
}

/*
 * Usually hashcount table contains lots of 1's during initialization
 * and lots of 0's once flexhash table is generated.
 * This algorithm sends the sparse 0 or 1 followed by row numbers.
 * Presently this algorithm is not used.
 */
static uint16_t
replicast_s_compress_hashcount(uint16_t *hashcount, uint32_t numrows,
    uint16_t *comphash, uint32_t *complen)
{
	uint32_t i, j = 0;
	uint32_t count0 = 0, count1;

	for (i = 0; i < numrows; i++)
		if (hashcount[i] == 0)
			count0++;

	count1 = numrows - count0;
	if (count0 < count1) {
		for (i = 0; i < numrows; i++)
			if (hashcount[i] == 0)
				comphash[j++] = i;
	} else {
		for (i = 0; i < numrows; i++)
			if (hashcount[i] != 0)
				comphash[j++] = i;
	}

	*complen = j;
	return (count0 < count1) ? 0 : 1;
}

static void
replicast_s_decompress_hashcount(uint16_t *hashcount, uint32_t numrows,
    uint16_t *comphash, uint32_t complen, uint16_t bit)
{
	uint32_t i, j;
	for (i = 0; i < numrows; i++)
		hashcount[i] = ~(bit) & 0x1;

	for (i = 0; i < complen; i++) {
		j = comphash[i];
		hashcount[j] = bit;
	}
}

/*
 * This algorithm compresses each byte into 1 bit.
 * Hashcount values used 0 or 1.
 */
#define FLEXCOUNT_BITMAP_LENGTH	(FLEXCOUNT_TAB_LENGTH >> 3)

#define GET_BIT(bitmap, n) \
	(bitmap[n >> 3] >> (n % 8)) & 0x1

#define SET_BIT(bitmap, n, val) \
	bitmap[n >> 3] |= ((val & 0x1) << (n % 8))

static int
replicast_pack_hashcount(msgpack_p *p, uint16_t *hashcount, uint32_t numrows)
{
	uint16_t bitmap[FLEXCOUNT_BITMAP_LENGTH];
	uint32_t maplen, i, bit;
	int err;

	if (numrows > FLEXCOUNT_TAB_LENGTH)
		return -EBADF;

	memset(bitmap, 0, FLEXCOUNT_BITMAP_LENGTH * sizeof(uint16_t));
	for (i = 0; i < numrows; i++) {
		bit = (hashcount[i] == 0) ? 0 : 1;
		SET_BIT(bitmap, i, bit);
	}

	maplen = numrows >> 3;

	err = msgpack_pack_array(p, maplen);
	if (err)
		return err;

	for (i = 0; i < maplen; i++) {
		err = msgpack_pack_uint16(p, bitmap[i]);
		if (err)
			return err;
	}

	return 0;
}

static int
replicast_unpack_hashcount(msgpack_u *u, uint16_t *hashcount, uint32_t numrows)
{
	uint16_t bitmap[FLEXCOUNT_BITMAP_LENGTH];
	uint32_t maplen, i, hashlen;
	int err;

	memset(bitmap, 0, FLEXCOUNT_BITMAP_LENGTH * sizeof(uint16_t));
	err = msgpack_unpack_array(u, &maplen);
	if (err)
		return err;

	if (((maplen << 3) != numrows) || (numrows > FLEXCOUNT_TAB_LENGTH))
		return -EBADF;

	for (uint32_t i = 0; i < maplen; i++) {
		err = msgpack_unpack_uint16(u, &bitmap[i]);
		if (err)
			return err;
	}

	for (uint32_t i = 0; i < numrows; i++)
		hashcount[i] = GET_BIT(bitmap, i);

	return 0;
}

int
replicast_pack_repvdev(msgpack_p *p, struct cl_vdev *vdevs,
    uint32_t nr_vdevs, int validhc)
{
	int err;
	uint32_t j;
	struct cl_vdev *vdev = vdevs;

	err = msgpack_pack_array(p, nr_vdevs);
	if (err)
		return err;
	for (j = 0; j < nr_vdevs; j++) {
		err = msgpack_pack_array(p, 7);
		if (err)
			return err;
		err = replicast_pack_uint128(p, &vdev->vdevid);
		if (err)
			return err;
		err = msgpack_pack_uint16(p, vdev->port);
		if (err)
			return err;
		err = msgpack_pack_uint64(p, vdev->size);
		if (err)
			return err;
		err = msgpack_pack_uint64(p, vdev->avail);
		if (err)
			return err;
		err = msgpack_pack_uint16(p, vdev->activerows);
		if (err)
			return err;
		err = msgpack_pack_uint16(p, vdev->numrows);
		if (err)
			return err;
		err = msgpack_pack_uint8(p, vdev->state);
		if (err)
			return err;
		if (validhc) {
			err = replicast_pack_hashcount(p, vdev->hashcount,
			    vdev->numrows);
			if (err)
				return err;
		}

		vdev++;
	}
	return 0;
}


int
replicast_pack_repnode(msgpack_p *p,
	    struct cl_node *node)
{
	int err;
	struct cl_vdev *vdevlist;
	char str[64];

	err = msgpack_pack_array(p, 5);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &node->serverid);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &node->addr);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, node->port);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, node->zone);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, node->gateway);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, node->fdmode);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, node->ckpread);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, node->nr_vdevs);
	if (err)
		return err;
	if (node->nr_vdevs == 0) {
		uint128_dump(&node->serverid, str, 64);
		log_debug(lg, "serverid %s contains 0 devices", str);
		return 0;
	}

	vdevlist = node->vdevs;
	err = replicast_pack_repvdev(p, vdevlist, node->nr_vdevs, 1);
	if (err)
		return err;

	return 0;
}

int
replicast_unpack_repvdev(msgpack_u *u, struct cl_vdev *vdevs,
    uint32_t nr_vdevs, int validhc)
{
	int err;
	uint32_t j, n;
	struct cl_vdev *vdev = vdevs;

	for (j = 0; j < nr_vdevs; j++) {
		err = msgpack_unpack_array(u, &n);
		if (err)
			return err;
		if (n != 7)
			return -EBADF;
		err = replicast_unpack_uint128(u, &vdev->vdevid);
		if (err)
			return err;
		err = msgpack_unpack_uint16(u, &vdev->port);
		if (err)
			return err;
		err = msgpack_unpack_uint64(u, &vdev->size);
		if (err)
			return err;
		err = msgpack_unpack_uint64(u, &vdev->avail);
		if (err)
			return err;
		err = msgpack_unpack_uint16(u, &vdev->activerows);
		if (err)
			return err;
		err = msgpack_unpack_uint16(u, &vdev->numrows);
		if (err)
			return err;
		err = msgpack_unpack_uint8(u, &vdev->state);
		if (err)
			return err;
		if (validhc) {
			err = replicast_unpack_hashcount(u, vdev->hashcount,
			   vdev->numrows);
			if (err)
				return err;
		}
		vdev++;
	}

	return 0;
}


int
replicast_unpack_repnode(msgpack_u *u,
	    struct cl_node **rnode)
{
	int err;
	struct cl_vdev *vdev;
	uint32_t n;
	struct cl_node *node = *rnode;
	char str[64];

	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != 5)
		return -EBADF;
	err = replicast_unpack_uint128(u, &node->serverid);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &node->addr);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &node->port);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &node->zone);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &node->gateway);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &node->fdmode);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &node->ckpread);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &node->nr_vdevs);
	if (err)
		return err;

	if (node->nr_vdevs == 0) {
		uint128_dump(&node->serverid, str, 64);
		log_warn(lg, "Received 0 devices from serverid %s", str);
		return 0;
	}

	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != node->nr_vdevs)
		return -EBADF;

	node->vdevs = je_calloc(node->nr_vdevs, sizeof (struct cl_vdev));
	if (!node->vdevs)
		return -ENOMEM;

	err = replicast_unpack_repvdev(u, node->vdevs, node->nr_vdevs, 1);
	if (err) {
		je_free(node->vdevs);
		return err;
	}

	return 0;
}
/*
 * Pack: SERVER_LIST_RESPONSE
 */
int
replicast_pack_server_list_response(msgpack_p *p,
	struct repmsg_server_list_response *msg)
{
	int err;
	size_t i;

	err = replicast_pack_uint128(p, &msg->parent_serverid);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->mcbase_ip6addr);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->mcbase_port);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->nr_members);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->checkpoint_numdevices);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->ckpread);
	if (err)
		return err;
	return 0;
}

/*
 * Unpack: SERVER_LIST_RESPONSE
 */
int
replicast_unpack_server_list_response(msgpack_u *u,
	struct repmsg_server_list_response *msg)
{
	int err;
	size_t i;

	err = replicast_unpack_uint128(u, &msg->parent_serverid);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->mcbase_ip6addr);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->mcbase_port);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->nr_members);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->checkpoint_numdevices);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->ckpread);
	if (err)
		return err;
	return 0;
}

/*
 * the list allocated by the unpack calls above must be freed using this
 * function
 */
void
replicast_free_repnodelist(struct cl_node *node, int numnodes)
{
	for (int i = 0; i < numnodes; i++) {
		struct cl_node *vnode = &node[i];
		je_free(vnode->vdevs);
	}
	je_free(node);
}

/*
 * Pack: NAMED_CHUNK_GET
 */
int
replicast_pack_named_chunk_get(msgpack_p *p,
	struct repmsg_named_chunk_get *msg)
{
	int err;

	err = replicast_pack_object_name(p,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->maximum_immediate_content_size);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->maximum_number_of_delegated_gets);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->reception_window);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->receive_tenant_addr);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->receive_tenant_port);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->genid_delta);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->select_time_avg);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->avg_put_latency);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->avg_get_latency);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->put_iops);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->get_iops);
	/* ignore error if svcinfo not specified */
	if (msgpack_pack_uint64(p, msg->put_bw) == 0)
		if (msgpack_pack_uint64(p, msg->get_bw) == 0)
			msgpack_pack_uint512(p, &msg->svcinfo);
	return err;
}

/*
 * Unpack: NAMED_CHUNK_GET
 */
int
replicast_unpack_named_chunk_get(msgpack_u *u,
	struct repmsg_named_chunk_get *msg)
{
	int err;

	err = replicast_unpack_object_name(u,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->maximum_immediate_content_size);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->maximum_number_of_delegated_gets);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->reception_window);
	if (err)
		return err;
	err =  replicast_unpack_uint128(u, &msg->receive_tenant_addr);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->receive_tenant_port);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->genid_delta);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->select_time_avg);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->avg_put_latency);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->avg_get_latency);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->put_iops);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->get_iops);
	/* ignore error if svcinfo not specified */
	msg->put_bw = msg->get_bw = 0;
	msg->svcinfo = uint512_null;
	if (msgpack_unpack_uint64(u, &msg->put_bw) == 0)
		if (msgpack_unpack_uint64(u, &msg->get_bw) == 0)
			msgpack_unpack_uint512(u, &msg->svcinfo);
	return err;
}

/*
 * Pack: NAMED_CHUNK_GET_RESPONSE
 */
int
replicast_pack_named_chunk_get_response(msgpack_p *p,
	struct repmsg_named_chunk_get_response *msg)
{
	int err;

	err = replicast_pack_uint128(p, &msg->vdevid);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_pack_object_name(p,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->delivery_rate);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->content_length);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->immediate_content_length);
	if (err)
		return err;
	err = replicast_pack_rendezvous_proposal(p, &msg->rendezvous_proposal);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->ngcount);
	if (err)
		return err;
	err = msgpack_pack_int32(p, msg->fddelta);
	return err;
}

/*
 * Unpack: NAMED_CHUNK_GET_RESPONSE
 */
int
replicast_unpack_named_chunk_get_response(msgpack_u *u,
	struct repmsg_named_chunk_get_response *msg)
{
	int err;

	err = replicast_unpack_uint128(u, &msg->vdevid);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_unpack_object_name(u,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->delivery_rate);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->content_length);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->immediate_content_length);
	if (err)
		return err;
	err = replicast_unpack_rendezvous_proposal(u, &msg->rendezvous_proposal);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->ngcount);
	if (err)
		return err;
	err = msgpack_unpack_int32(u, &msg->fddelta);
	return err;
}

/*
 * Pack: UNNAMED_CHUNK_GET
 */
int
replicast_pack_unnamed_chunk_get(msgpack_p *p,
	struct repmsg_unnamed_chunk_get *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->maximum_immediate_content_size);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->reception_window);
	if (err)
		return err;
	err = replicast_pack_object_name(p, &msg->object_name);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->receive_tenant_addr);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->receive_tenant_port);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->genid_delta);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->select_time_avg);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->chunk_offset);
	return err;
}

/*
 * Unpack: UNNAMED_CHUNK_GET
 */
int
replicast_unpack_unnamed_chunk_get(msgpack_u *u,
	struct repmsg_unnamed_chunk_get *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->maximum_immediate_content_size);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->reception_window);
	if (err)
		return err;
	err = replicast_unpack_object_name(u, &msg->object_name);
	if (err)
		return err;
	err =  replicast_unpack_uint128(u, &msg->receive_tenant_addr);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->receive_tenant_port);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->genid_delta);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->select_time_avg);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->chunk_offset);
	return err;
}

/*
 * Pack: UNNAMED_CHUNK_GET_RESPONSE
 */
int
replicast_pack_unnamed_chunk_get_response(msgpack_p *p,
	struct repmsg_unnamed_chunk_get_response *msg)
{
	int err;

	err = replicast_pack_uint128(p, &msg->vdevid);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->delivery_rate);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->content_length);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->immediate_content_length);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->ngcount);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->is_gwcache);
	if (err)
		return err;
	err = replicast_pack_rendezvous_proposal(p, &msg->rendezvous_proposal);
	return err;
}

/*
 * Unpack: UNNAMED_CHUNK_GET_RESPONSE
 */
int
replicast_unpack_unnamed_chunk_get_response(msgpack_u *u,
	struct repmsg_unnamed_chunk_get_response *msg)
{
	int err;

	err = replicast_unpack_uint128(u, &msg->vdevid);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->delivery_rate);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->content_length);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->immediate_content_length);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->ngcount);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->is_gwcache);
	if (err)
		return err;
	err = replicast_unpack_rendezvous_proposal(u, &msg->rendezvous_proposal);
	return err;
}

/*
 * Pack: NAMED_CHUNK_PUT_PROPOSAL
 */
int
replicast_pack_named_chunk_put_proposal(msgpack_p *p,
	struct repmsg_named_chunk_put_proposal *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_pack_object_name(p,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->content_length);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->immediate_content_length);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->override_content_length);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->genid_delta);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->select_time_avg);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->ec_algorithm);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->ec_width);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->ec_parity);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, msg->ec_domain);
	return err;
}

/*
 * Unpack: NAMED_CHUNK_PUT_PROPOSAL
 */
int
replicast_unpack_named_chunk_put_proposal(msgpack_u *u,
	struct repmsg_named_chunk_put_proposal *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_unpack_object_name(u,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->content_length);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->immediate_content_length);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->override_content_length);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->genid_delta);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->select_time_avg);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->ec_algorithm);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->ec_width);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->ec_parity);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->ec_domain);
	return err;
}

/*
 * Pack: UNNAMED_CHUNK_PUT_PROPOSAL
 */
int
replicast_pack_unnamed_chunk_put_proposal(msgpack_p *p,
	struct repmsg_unnamed_chunk_put_proposal *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_pack_object_name(p,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->content_length);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->immediate_content_length);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->reserved);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->genid_delta);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->select_time_avg);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->vdev);
	return err;
}

/*
 * Unpack: UNNAMED_CHUNK_PUT_PROPOSAL
 */
int
replicast_unpack_unnamed_chunk_put_proposal(msgpack_u *u,
	struct repmsg_unnamed_chunk_put_proposal *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_unpack_object_name(u,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->content_length);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->immediate_content_length);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->reserved);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->genid_delta);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->select_time_avg);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->vdev);
	return err;
}

/*
 * Pack: NAMED_PAYLOAD_ACK
 */
int
replicast_pack_named_payload_ack(msgpack_p *p,
	struct repmsg_named_payload_ack *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->vdevid);
	if (err)
		return err;
	err = replicast_pack_object_name(p,
		(struct replicast_object_name *)&msg->object_name);
	return err;
}

/*
 * Unpack: NAMED_PAYLOAD_ACK
 */
int
replicast_unpack_named_payload_ack(msgpack_u *u,
	struct repmsg_named_payload_ack *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->vdevid);
	if (err)
		return err;
	err = replicast_unpack_object_name(u,
		(struct replicast_object_name *)&msg->object_name);
	return err;
}

/*
 * Pack: NAMED_PAYLOAD_ACK
 */
int
replicast_pack_unnamed_payload_ack(msgpack_p *p,
	struct repmsg_unnamed_payload_ack *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->vdevid);
	return err;
}

/*
 * Unpack: NAMED_PAYLOAD_ACK
 */
int
replicast_unpack_unnamed_payload_ack(msgpack_u *u,
	struct repmsg_unnamed_payload_ack *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->vdevid);
	return err;
}

int replicast_pack_rendezvous_proposal(msgpack_p *p,
	struct replicast_rendezvous_proposal *msg)
{
	int err;

	err = msgpack_pack_uint64(p, msg->start_time);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->delta_time);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->weight_io);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->avail_space);
	return err;
}

int replicast_unpack_rendezvous_proposal(msgpack_u *u,
	struct replicast_rendezvous_proposal *msg)
{
	int err;

	err = msgpack_unpack_uint64(u, &msg->start_time);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->delta_time);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->weight_io);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->avail_space);
	return err;
}

/*
 * Pack: ACCEPT_PROPOSED_RENDEZVOUS
 */
int
replicast_pack_accept_proposed_rendezvous(msgpack_p *p,
	struct repmsg_accept_proposed_rendezvous *msg)
{
	int err;

	err = replicast_pack_uint128(p, &msg->vdevid);
	if (err)
		return err;
	err = replicast_pack_rendezvous_proposal(p, &msg->rendezvous_proposal);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->ngcount);
	if (err)
		return err;
	err = replicast_pack_uint256(p, &msg->dgram_idx);
	return err;
}

/*
 * Unpack: ACCEPT_PROPOSED_RENDEZVOUS
 */
int
replicast_unpack_accept_proposed_rendezvous(msgpack_u *u,
	struct repmsg_accept_proposed_rendezvous *msg)
{
	int err;

	err = replicast_unpack_uint128(u, &msg->vdevid);
	if (err)
		return err;
	err = replicast_unpack_rendezvous_proposal(u, &msg->rendezvous_proposal);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->ngcount);
	if (err)
		return err;
	err = replicast_unpack_uint256(u, &msg->dgram_idx);
	return err;
}

/*
 * Pack: ACCEPT_NOT_NOW
 */
int
replicast_pack_accept_not_now(msgpack_p *p,
	struct repmsg_accept_not_now *msg)
{
	int err;
	uint32_t datagram_num_byte;

	err = replicast_pack_datagram_hdr(p, &msg->hdr, &datagram_num_byte);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->num_datagrams);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->ngcount);
	if (err)
		return err;
	err = msgpack_pack_int32(p, msg->error);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->vdevid);
	return err;
}

/*
 * Unpack: ACCEPT_NOT_NOW
 */
int
replicast_unpack_accept_not_now(msgpack_u *u,
	struct repmsg_accept_not_now *msg)
{
	int err;
	err = replicast_unpack_datagram_hdr(u, &msg->hdr);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->num_datagrams);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->ngcount);
	if (err)
		return err;
	err = msgpack_unpack_int32(u, &msg->error);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->vdevid);

	return err;
}

/*
 * Pack: NOTIFICATION
 */
int
replicast_pack_notification(msgpack_p *p, struct repmsg_notification *msg)
{
	int err;

	err = msgpack_pack_int32(p, msg->error);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->major_opcode);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->minor_opcode);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->io_cookie);
	if (err)
		return err;

	return err;
}

/*
 * Unpack: NOTIFICATION
 */
int
replicast_unpack_notification(msgpack_u *u, struct repmsg_notification *msg)
{
	int err;

	err = msgpack_unpack_int32(u, &msg->error);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->major_opcode);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &msg->minor_opcode);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->io_cookie);
	if (err)
		return err;

	return err;
}

/*
 * Pack: ACCEPT_CONTENT_ALREADY_STORED
 */
int
replicast_pack_accept_content_already_stored(msgpack_p *p,
	struct repmsg_accept_content_already_stored *msg)
{
	int err = 0;
	err = replicast_pack_uint128(p, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->num_datagrams);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->ngcount);
	return err;
}

/*
 * Unpack: ACCEPT_CONTENT_ALREADY_STORED
 */
int
replicast_unpack_accept_content_already_stored(msgpack_u *u,
	struct repmsg_accept_content_already_stored *msg)
{
	int err = 0;
	err = replicast_unpack_uint128(u, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->num_datagrams);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->ngcount);
	return err;
}

int replicast_pack_persistency_ack(msgpack_p *p,
	struct repmsg_persistency_ack *msg) {
	int err = 0;
	err = replicast_pack_uint128(p, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_pack_int32(p, msg->error);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->ngcount);
	return err;
}

int replicast_unpack_persistency_ack(msgpack_u *u,
	struct repmsg_persistency_ack *msg) {
	int err = 0;
	err = replicast_unpack_uint128(u, &msg->vdevid);
	if (err)
		return err;
	err = msgpack_unpack_int32(u, &msg->error);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->ngcount);
	return err;
}

/*
 * Pack: RENDEZVOUS_TRANSFER
 */
int
replicast_pack_rendezvous_transfer(msgpack_p *p,
	struct repmsg_rendezvous_transfer *msg)
{
	int err;

	err = msgpack_pack_array(p, REPLICAST_REPLICATION_COUNT_MAX);
	if (err)
		return err;
	for (int i = 0; i < REPLICAST_REPLICATION_COUNT_MAX; i++) {
		err = replicast_pack_uint128(p, &msg->group_members[i]);
		if (err)
			return err;
	}
	err = msgpack_pack_uint32(p, msg->delivery_rate);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->content_length);
	if (err)
		return err;
	return err;
}

/*
 * Unpack: RENDEZVOUS_TRANSFER
 */
int
replicast_unpack_rendezvous_transfer(msgpack_u *u,
	struct repmsg_rendezvous_transfer *msg)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != REPLICAST_REPLICATION_COUNT_MAX)
		return -EBADF;
	for (int i = 0; i < REPLICAST_REPLICATION_COUNT_MAX; i++) {
		err = replicast_unpack_uint128(u, &msg->group_members[i]);
		if (err)
			return err;
	}
	err = msgpack_unpack_uint32(u, &msg->delivery_rate);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->content_length);
	if (err)
		return err;
	return err;
}

/*
 * Pack: RENDEZVOUS_ACK
 */
int
replicast_pack_rendezvous_ack(msgpack_p *p, struct repmsg_rendezvous_ack *msg)
{
	int err;

	err = replicast_pack_uint128(p, &msg->rendezvous_group);
	if (err)
		return err;
	err = msgpack_pack_array(p, REPLICAST_REPLICATION_COUNT_MAX);
	if (err)
		return err;
	for (int i = 0; i < REPLICAST_REPLICATION_COUNT_MAX; i++) {
		err = replicast_pack_uint128(p, &msg->group_members[i]);
		if (err)
			return err;
	}
	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->join_delay);

	return err;
}

/*
 * Unpack: RENDEZVOUS_ACK
 */
int
replicast_unpack_rendezvous_ack(msgpack_u *u, struct repmsg_rendezvous_ack *msg)
{
	int err;

	err = replicast_unpack_uint128(u, &msg->rendezvous_group);
	if (err)
		return err;
	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != REPLICAST_REPLICATION_COUNT_MAX)
		return -EBADF;
	for (int i = 0; i < REPLICAST_REPLICATION_COUNT_MAX; i++) {
		err = replicast_unpack_uint128(u, &msg->group_members[i]);
		if (err)
			return err;
	}
	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->join_delay);

	return err;
}

/*
 * Pack: RENDEZVOUS_NACK
 */
int
replicast_pack_rendezvous_nack(msgpack_p *p, struct repmsg_rendezvous_nack *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->content_hash_id);
	if (err)
		return err;
	return err;
}

/*
 * Unpack: RENDEZVOUS_NACK
 */
int
replicast_unpack_rendezvous_nack(msgpack_u *u, struct repmsg_rendezvous_nack *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->content_hash_id);
	if (err)
		return err;
	return err;
}

/*
 * Pack: RES_GET
 */
int
replicast_pack_resget(msgpack_p *p, struct repmsg_res_get *msg)
{
	int err;

	err = replicast_pack_object_name(p,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err =  replicast_pack_uint128(p, &msg->tgt_vdevid);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->res_maj_id);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->res_min_id);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->immediate_content_length);
	return err;
}

/*
 * Unpack: RES_GET
 */
int
replicast_unpack_resget(msgpack_u *u, struct repmsg_res_get *msg)
{
	int err;

	err = replicast_unpack_object_name(u,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err =  replicast_unpack_uint128(u, &msg->tgt_vdevid);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->res_maj_id);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->res_min_id);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->immediate_content_length);
	return err;
}

/*
 * Pack: RES_GET_RESPONSE
 */
int
replicast_pack_resget_response(msgpack_p *p,
				struct repmsg_res_get_response *msg)
{
	int err;

	err = replicast_pack_object_name(p,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->res_maj_id);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->res_min_id);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, msg->immediate_content_length);
	return err;
}

/*
 * Unpack: RES_GET_RESPONSE
 */
int
replicast_unpack_resget_response(msgpack_u *u,
				struct repmsg_res_get_response *msg)
{
	int err;

	err = replicast_unpack_object_name(u,
		(struct replicast_object_name *)&msg->object_name);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->res_maj_id);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->res_min_id);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &msg->immediate_content_length);
	return err;
}


int
replicast_pack_vlentry(msgpack_p *p, struct vlentry *ent)
{
	int err;

	err = msgpack_pack_array(p, 8);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, ent->uvid_timestamp);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, ent->generation);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, ent->uvid_src_cookie);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &ent->uvid_src_guid);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &ent->content_hash_id);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, ent->object_deleted);
	if (err)
	    return err;
	err = msgpack_pack_uint64(p, ent->logical_size);
	if (err)
	    return err;
	err = msgpack_pack_uint32(p, ent->vm_packed_length);
	return err;
}

int
replicast_unpack_vlentry(msgpack_u *u, struct vlentry *ent)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != 8)
		return -EBADF;
	err = msgpack_unpack_uint64(u, &ent->uvid_timestamp);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &ent->generation);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, &ent->uvid_src_cookie);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &ent->uvid_src_guid);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &ent->content_hash_id);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &ent->object_deleted);
	if (err)
	    return err;
    err = msgpack_unpack_uint64(u, &ent->logical_size);
	if (err)
		return err;
    err = msgpack_unpack_uint32(u, &ent->vm_packed_length);
	return err;
}

int
replicast_pack_aclentry(msgpack_p *p, struct aclentry *ent)
{
	int err;

	err = msgpack_pack_array(p, 2);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, ent->acl_type);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, ent->permissions);
	return err;
}

int
replicast_unpack_aclentry(msgpack_u *u, struct aclentry *ent)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != 2)
		return -EBADF;
	err = msgpack_unpack_uint8(u, &ent->acl_type);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &ent->permissions);
	return err;
}

static int
replicast_pack_refentry_internal(msgpack_p *p, struct refentry *ent, int noinline_data)
{
	int err;
	int has_inl = !noinline_data && RT_REF_TYPE_INLINE(ent);
	int has_nhid = (RT_REF_TYPE(ent) == RT_REF_TYPE_INLINE_VERSION);

	err = msgpack_pack_array(p, 6 + has_nhid + has_inl);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, ent->ref_attr);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, ent->map_attr);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, ent->offset);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, ent->length);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, ent->compressed_length);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &ent->content_hash_id);
	if (err)
		return err;
	if (has_nhid) {
		err = replicast_pack_uint512(p, &ent->name_hash_id);
		if (err)
			return err;
	}
	if (has_inl)
		err = msgpack_pack_raw(p, ent->data, ent->compressed_length);
	return err;
}

int
replicast_pack_refentry(msgpack_p *p, struct refentry *ent) {
	return replicast_pack_refentry_internal(p, ent, 0);
}

int
replicast_pack_refentry_dfetch(msgpack_p *p, struct refentry *ent) {
	return replicast_pack_refentry_internal(p, ent, 1);
}

static int
replicast_unpack_refentry_internal(msgpack_u *u, struct refentry *ent, int noinline_data)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n < 6 && n > 8)
		return -EBADF;
	err = msgpack_unpack_uint16(u, &ent->ref_attr);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &ent->map_attr);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &ent->offset);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &ent->length);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &ent->compressed_length);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &ent->content_hash_id);
	if (err)
		return err;
	if (RT_REF_TYPE(ent) == RT_REF_TYPE_INLINE_VERSION) {
		err = replicast_unpack_uint512(u, &ent->name_hash_id);
		if (err)
			return err;
	}
	if (!noinline_data && RT_REF_TYPE_INLINE(ent)) {
		/*
		 * Unpack raw will simply re-point, it will not actually
		 * copy anything. As such, we will get ent->data with
		 * compressed inlined content.
		 *
		 * Caller may use it immediately but should make sure that
		 * msgpack_u *u isn't freed in the middle...
		 */
		err = msgpack_unpack_raw(u, (const uint8_t **)&ent->data, &n);
		if (err)
			return err;
		if (n != ent->compressed_length)
			return -EBADF;
	} else
		ent->data = NULL;
	return err;
}

int
replicast_unpack_refentry(msgpack_u *u, struct refentry *ent) {
	return replicast_unpack_refentry_internal(u, ent, 0);
}

int
replicast_unpack_refentry_dfetch(msgpack_u *u, struct refentry *ent) {
	return replicast_unpack_refentry_internal(u, ent, 1);
}

static int
replicast_unpack_kv(msgpack_u *u, ccow_kvtype_t type, void *dst,
    size_t *dst_size)
{
	int err;

	switch (type) {
		case CCOW_KVTYPE_RAW: {
			uint32_t raw_size = 0;
			err = msgpack_unpack_raw(u, (const uint8_t **)dst,
			    &raw_size);
			*dst_size = raw_size;
			break;
		}
		case CCOW_KVTYPE_STR:
			err = msgpack_unpack_str(u, (char *)dst,
			    REPLICAST_STR_MAXLEN);
			break;
		case CCOW_KVTYPE_UINT64:
			err = msgpack_unpack_uint64(u, dst);
			break;
		case CCOW_KVTYPE_UINT512:
			err = replicast_unpack_uint512(u, dst);
			break;
		case CCOW_KVTYPE_UINT128:
			err = replicast_unpack_uint128(u, dst);
			break;
		case CCOW_KVTYPE_UINT32:
			err = msgpack_unpack_uint32(u, dst);
			break;
		case CCOW_KVTYPE_UINT16:
			err = msgpack_unpack_uint16(u, dst);
			break;
		case CCOW_KVTYPE_UINT8:
			err = msgpack_unpack_uint8(u, dst);
			break;
		default:
			return MSGPACK_TYPEERR;
	}
	return err;
}

int
replicast_unpack_vmmetadata(msgpack_u *u, struct vmmetadata *md)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_map(u, &n);
	if (err)
		return err;

	memset(md, 0, sizeof (*md));

	void *keys[] = {
		/* Common Metadata */
		(void *)RT_SYSKEY_CLUSTER_IDX, &md->cid,
			(void *)CCOW_KVTYPE_RAW, &md->cid_size,
		(void *)RT_SYSKEY_TENANT_IDX, &md->tid,
			(void *)CCOW_KVTYPE_RAW, &md->tid_size,
		(void *)RT_SYSKEY_BUCKET_IDX, &md->bid,
			(void *)CCOW_KVTYPE_RAW, &md->bid_size,
		(void *)RT_SYSKEY_OBJECT_IDX, &md->oid,
			(void *)CCOW_KVTYPE_RAW, &md->oid_size,
		(void *)RT_SYSKEY_CLUSTER_HASH_ID_IDX, &md->chid,
			(void *)CCOW_KVTYPE_UINT512, NULL,
		(void *)RT_SYSKEY_NAME_HASH_ID_IDX, &md->nhid,
			(void *)CCOW_KVTYPE_UINT512, NULL,
		(void *)RT_SYSKEY_PARENT_HASH_ID_IDX, &md->phid,
			(void *)CCOW_KVTYPE_UINT512, NULL,
		(void *)RT_SYSKEY_TENANT_HASH_ID_IDX, &md->thid,
			(void *)CCOW_KVTYPE_UINT512, NULL,
		(void *)RT_SYSKEY_BUCKET_HASH_ID_IDX, &md->bhid,
			(void *)CCOW_KVTYPE_UINT512, NULL,
		(void *)RT_SYSKEY_OBJECT_HASH_ID_IDX, &md->ohid,
			(void *)CCOW_KVTYPE_UINT512, NULL,
		(void *)RT_SYSKEY_OBJECT_DELETED_IDX, &md->object_deleted,
			(void *)CCOW_KVTYPE_UINT8, NULL,
		(void *)RT_SYSKEY_LOGICAL_SIZE_IDX, &md->logical_size,
			(void *)CCOW_KVTYPE_UINT64, NULL,
		(void *)RT_SYSKEY_PREV_LOGICAL_SIZE_IDX, &md->prev_logical_size,
			(void *)CCOW_KVTYPE_UINT64, NULL,
		(void *)RT_SYSKEY_OBJECT_COUNT_IDX, &md->object_count,
			(void *)CCOW_KVTYPE_UINT64, NULL,
		(void *)RT_SYSKEY_CREATION_TIME_IDX, &md->creation_time,
			(void *)CCOW_KVTYPE_UINT64, NULL,

		/* Misc */
		(void *)RT_SYSKEY_FAILURE_DOMAIN_IDX, &md->failure_domain,
			(void *)CCOW_KVTYPE_UINT8, NULL,
		(void *)RT_SYSKEY_SYNC_PUT_IDX, &md->sync_put,
			(void *)CCOW_KVTYPE_UINT8, NULL,
		(void *)RT_SYSKEY_SELECT_POLICY_IDX, &md->select_policy,
			(void *)CCOW_KVTYPE_UINT8, NULL,
		(void *)RT_SYSKEY_REPLICATION_COUNT_IDX, &md->replication_count,
			(void *)CCOW_KVTYPE_UINT8, NULL,
		(void *)RT_SYSKEY_HASH_TYPE_IDX, &md->hash_type,
			(void *)CCOW_KVTYPE_UINT8, NULL,
		(void *)RT_SYSKEY_COMPRESS_TYPE_IDX, &md->compress_type,
			(void *)CCOW_KVTYPE_UINT8, NULL,
		(void *)RT_SYSKEY_ESTIMATED_USED_IDX, &md->estimated_used,
			(void *)CCOW_KVTYPE_UINT64, NULL,
		(void *)RT_SYSKEY_INLINE_DATA_FLAGS_IDX, &md->inline_data_flags,
			(void *)CCOW_KVTYPE_UINT16, NULL,
		(void *)RT_SYSKEY_NUMBER_OF_VERSIONS_IDX, &md->number_of_versions,
			(void *)CCOW_KVTYPE_UINT16, NULL,
		(void *)RT_SYSKEY_TRACK_STATISTICS_IDX, &md->track_statistics,
			(void *)CCOW_KVTYPE_UINT16, NULL,
		(void *)RT_SYSKEY_IOPS_RATE_LIM_IDX, &md->iops_rate_lim,
			(void *)CCOW_KVTYPE_UINT32, NULL,
		(void *)RT_SYSKEY_EC_ENABLED_IDX, &md->ec_enabled,
			(void *)CCOW_KVTYPE_UINT8, NULL,
		(void *)RT_SYSKEY_EC_DATA_MODE_IDX, &md->ec_data_mode,
			(void *)CCOW_KVTYPE_UINT32, NULL,
		(void *)RT_SYSKEY_EC_TRG_POLICY_IDX, &md->ec_trg_policy,
			(void *)CCOW_KVTYPE_UINT64, NULL,
        (void *)RT_SYSKEY_FILE_OBJECT_TRANSPARANCY_IDX, &md->file_object_transparency,
		    (void *)CCOW_KVTYPE_UINT8, NULL,
        (void *)RT_SYSKEY_OBJECT_DELETE_AFTER_IDX, &md->object_delete_after,
			    (void *)CCOW_KVTYPE_UINT64, NULL,

		/* NUVID */
		(void *)RT_SYSKEY_UVID_TIMESTAMP_IDX, &md->uvid_timestamp,
			(void *)CCOW_KVTYPE_UINT64, NULL,
		(void *)RT_SYSKEY_TX_GENERATION_ID_IDX, &md->txid_generation,
			(void *)CCOW_KVTYPE_UINT64, NULL,
		(void *)RT_SYSKEY_UVID_SRC_COOKIE_IDX, &md->uvid_src_cookie,
			(void *)CCOW_KVTYPE_UINT32, NULL,
		(void *)RT_SYSKEY_UVID_SRC_GUID_IDX, &md->uvid_src_guid,
			(void *)CCOW_KVTYPE_UINT128, NULL,

		/* Chunkmap */
		(void *)RT_SYSKEY_CHUNKMAP_TYPE_IDX, &md->chunkmap_type,
			(void *)CCOW_KVTYPE_STR, NULL,
		(void *)RT_SYSKEY_CHUNKMAP_BTREE_ORDER_IDX, &md->chunkmap_btree_order,
			(void *)CCOW_KVTYPE_UINT16, NULL,
		(void *)RT_SYSKEY_CHUNKMAP_BTREE_MARKER_IDX, &md->chunkmap_btree_marker,
			(void *)CCOW_KVTYPE_UINT8, NULL,
		(void *)RT_SYSKEY_CHUNKMAP_CHUNK_SIZE_IDX, &md->chunkmap_chunk_size,
			(void *)CCOW_KVTYPE_UINT32, NULL,
	};
	uint16_t keyidx;
	uint32_t i;
	for (i = 0; i < n; i++) {
		err = msgpack_unpack_uint16(u, &keyidx);
		if (err) {
			/* this buf isn't a map with string key, error case */
			break;
		}

		uint32_t j;
		for (j = 0; j < sizeof (keys) / sizeof (void *); j++) {
			uint16_t idx = (unsigned long)keys[j++];
			if (keyidx != idx)
				continue;
			void *dst = keys[j++];
			ccow_kvtype_t type = (unsigned long)keys[j++];
			size_t *dst_size = keys[j];
			err = replicast_unpack_kv(u, type, dst, dst_size);
			if (err)
				return err;
			break;
		}
	}

	return err;
}

static int
replicast_map_unwind(msgpack_u *u, int sectidx)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_map(u, &n);
	if (err) {
	/* this buf isn't a map, skip it */
		return err;
	}
	if (n == 0)
		return -EBADF;

	/* unpack jump table */
	uint16_t keyidx;
	err = msgpack_unpack_uint16(u, &keyidx);
	if (err) {
		return err;
	}
	if (keyidx != RT_SYSKEY_HEADER_IDX) {
		/* incorrect stream */
		return -EBADF;
	}
	unsigned int hdr_len;
	const uint8_t *hdr;
	err = msgpack_unpack_raw(u, &hdr, &hdr_len);
	if (err) {
		/* incorrect stream, expecting hdr info to be first value */
		return err;
	}
	if (hdr_len != RT_HDR_JUMPTBL_SIZE) {
		/* incorrect stream - wrong hdr len */
		return -EBADF;
	}
	msgpack_u hdr_u;
	memset(&hdr_u, 0, sizeof (hdr_u));
	msgpack_unpack_init_b(&hdr_u, hdr, hdr_len, 0);

	/* find section offset */
	uint32_t offset = 0;
	for (int i = 0; i <= sectidx; i++) {
		err = msgpack_unpack_uint32(&hdr_u, &offset);
		if (err) {
			/* incorrect stream */
			return err;
		}
	}

	if (offset > u->max) {
		/* wrong offset */
		return -EBADF;
	}

	/* jump right to the beginning of the section */
	msgpack_unpack_setpos(u, offset);

	/* skip section name */
	err = msgpack_unpack_skip(u);
	if (err < 0) {
		return -EBADF;
	}
	return 0;
}

int
replicast_unpack_cm_refs(rtbuf_t *in, rtbuf_t **out, int keep_mod_bit)
{
	int err;

	*out = NULL;

	/* we do not support fragmented reads at the moment... */
	assert(in->nbufs == 1);

	msgpack_u u;
	(void) msgpack_unpack_init_b(&u, rtbuf(in, 0).base, rtbuf(in, 0).len, 0);

	/* empty cm refs array is NOT ok */
	uint32_t n;
	err = msgpack_unpack_array(&u, &n);
	if (err)
		return err;

	size_t j;
	for (j = 0; j < n; j++) {
		struct refentry *e = je_malloc(sizeof (struct refentry));
		if (!e) {
			if (*out) {
				rtbuf_destroy(*out);
				*out = NULL;
			}
			return -ENOMEM;
		}
		uv_buf_t ent;
		ent.base = (char *)e;
		ent.len = sizeof (struct refentry);
		err = replicast_unpack_refentry(&u, e);
		if (err) {
			je_free(e);
			if (*out) {
				rtbuf_destroy(*out);
				*out = NULL;
			}
			return err;
		}

		if (!keep_mod_bit)
			RT_REF_MOD_SET(e, 0);

		if (*out == NULL) {
			*out = rtbuf_init(NULL, n);
			if (!*out) {
				je_free(e);
				return -ENOMEM;
			}
		}
		rtbuf_set(*out, j, &ent, 1);
	}

	if (n == 0) {
		*out = rtbuf_init_empty();
		if (!*out)
			return -ENOMEM;
	}

	return 0;
}

/*
 * Retrieve chunk references list
 *
 * Reflist organized into msgpack map entry pointing to array of struct refentry
 * elements.
 *
 * References stored in TT_VERSION_MANIFEST and its update changing version of
 * the object.
 *
 * Inlined segments placed into separate "next" buf.
 */
int
replicast_get_refs(rtbuf_t *in, rtbuf_t **out, int keep_mod_bit)
{
	int err;

	*out = NULL;

	/* we do not support fragmented reads at the moment... */
	assert(in->nbufs == 1);

	msgpack_u u;
	(void) msgpack_unpack_init_b(&u, rtbuf(in, 0).base, rtbuf(in, 0).len, 0);

	err = replicast_map_unwind(&u, RT_SYSKEY_REFERENCE_LIST_SECTIDX);
	if (err)
		return err;

	/* empty refs array (i.e. n == 0) is ok */
	uint32_t n;
	err = msgpack_unpack_array(&u, &n);
	if (err)
		return err;

	size_t j;
	for (j = 0; j < n; j++) {
		struct refentry *e = je_malloc(sizeof (struct refentry));
		if (!e) {
			if (*out) {
				rtbuf_destroy(*out);
				*out = NULL;
			}
			return -ENOMEM;
		}
		uv_buf_t ent;
		ent.base = (char *)e;
		ent.len = sizeof (struct refentry);
		err = replicast_unpack_refentry(&u, e);
		if (err) {
			je_free(e);
			if (*out) {
				rtbuf_destroy(*out);
				*out = NULL;
			}
			return err;
		}
		if (!keep_mod_bit)
			RT_REF_MOD_SET(e, 0);
		if (*out == NULL) {
			*out = rtbuf_init(NULL, n);
			if (!*out) {
				je_free(e);
				return -ENOMEM;
			}
		}
		rtbuf_set(*out, j, &ent, 1);
	}

	if (n == 0) {
		*out = rtbuf_init_empty();
		if (!*out)
			return -ENOMEM;
	}

	return 0;
}

void
refentry_dump(Logger l, char *debug_desc, struct refentry *re)
{
	log_debug(lg, "%s: 0x%0x %ld:%ld:%ld", debug_desc,
	    re->ref_attr, re->offset, re->length, re->compressed_length);
}

/*
 * Retrieve object's ACLs
 *
 * ACLs organized into msgpack map entry pointing to array of struct aclentry
 * elements.
 *
 * @returns 0 and non-NULL out if found. It is possible that it will return 0
 * but out is still NULL, i.e. the case when array of length 0 is packed.
 */
int
replicast_get_acls(rtbuf_t *in, rtbuf_t **out)
{
	int err;

	*out = NULL;

	/* we do not support fragmented reads at the moment... */
	assert(in->nbufs == 1);

	msgpack_u *u = msgpack_unpack_init_p(&rtbuf(in, 0), 0);
	if (!u)
		return -ENOMEM;

	err = replicast_map_unwind(u, RT_SYSKEY_ACL_LIST_SECTIDX);
	if (err) {
		msgpack_unpack_free(u);
		return err;
	}

	/* empty ACL (i.e. n == 0) is ok */
	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err) {
		msgpack_unpack_free(u);
		return err;
	}

	size_t j;
	for (j = 0; j < n; j++) {
		struct aclentry *e = je_malloc(sizeof (struct aclentry));
		if (!e) {
			msgpack_unpack_free(u);
			return -ENOMEM;
		}
		uv_buf_t ent;
		ent.base = (char *)e;
		ent.len = sizeof (struct aclentry);
		err = replicast_unpack_aclentry(u, e);
		if (err) {
			je_free(e);
			msgpack_unpack_free(u);
			if (*out)
				rtbuf_destroy(*out);
			return err;
		}
		if (*out == NULL) {
			*out = rtbuf_init(NULL, n);
			if (!*out) {
				je_free(e);
				msgpack_unpack_free(u);
				return -ENOMEM;
			}
		}
		rtbuf_set(*out, j, &ent, 1);
	}
	msgpack_unpack_free(u);

	return 0;
}

/*
 * Retrieve ccow-custom-metadata section of Version Manifest payload
 */
int
replicast_get_custom_metadata(rtbuf_t *in, rtbuf_t **out)
{
	int err;
	*out = NULL;

	/* we do not support fragmented reads at the moment... */
	assert(in->nbufs == 1);

	msgpack_u *u = msgpack_unpack_init(rtbuf(in, 0).base,
	    rtbuf(in, 0).len, 0);
	if (!u)
		return -ENOMEM;

	err = replicast_map_unwind(u, RT_SYSKEY_CUSTOM_METADATA_SECTIDX);
	if (err) {
		msgpack_unpack_free(u);
		return err;
	}
	/*
	 * If custom_md is empty we will have a section for custom md in the
	 * msgpack but it will have no entries and will instead point to the
	 * refentry lists. Since we do not pack array type in custom_md, we
	 * can safely check for this.
	 *
	 * FIXME : should we pack a NULL for empty customMD instead ?
	 */
	int type = msgpack_unpack_peek(u);
	if (type == MSGPACK_ARRAY) {
		msgpack_unpack_free(u);
		*out = rtbuf_init_empty();
		if (!*out) {
			return -ENOMEM;
		}
		return 0;
	}

	uint32_t n;
	err = msgpack_unpack_map(u, &n);
	if (err) {
		msgpack_unpack_free(u);
		log_error(lg, "Failing custom_md unpack map: \
		    Looking for %s, found %s", RT_SYSKEY_CUSTOM_METADATA,
		    (char *)u->p);
		return err;
	}
	*out = rtbuf_init(NULL, n);
	if (!*out) {
		msgpack_unpack_free(u);
		return -ENOMEM;
	}
	for (size_t i = 0; i < n; i++) {
		uv_buf_t buf;

		buf.base = (char *)u->p;
		buf.len = 0;
		err = msgpack_unpack_skip(u);
		if (err < 0) {
			msgpack_unpack_free(u);
			rtbuf_destroy(*out);
			*out = NULL;
			return err;
		}
		buf.len += err;
		err = msgpack_unpack_skip(u);
		if (err < 0) {
			msgpack_unpack_free(u);
			rtbuf_destroy(*out);
			*out = NULL;
			return err;
		}
		buf.len += err;
		err = rtbuf_set_alloc(*out, i, &buf, 1);
		if (err) {
			msgpack_unpack_free(u);
			rtbuf_destroy(*out);
			*out = NULL;
			return err;
		}
	}

	msgpack_unpack_free(u);
	return 0;
}

/*
 * Get object cloud provider specific metadata fields of Version Manifest payload
 */
int
replicast_object_cloud_provider_metadata(rtbuf_t *in, char **provier_type,
    char **provider_origin, char **user_key, char **provider_region)
{
	int err;
	int code;

	// initialize
	*provier_type = NULL;
	*provider_origin = NULL;
	*user_key = NULL;
	*provider_region = NULL;


	/* we do not support fragmented reads at the moment... */
	assert(in->nbufs == 1);

	msgpack_u *u = msgpack_unpack_init(rtbuf(in, 0).base,
	    rtbuf(in, 0).len, 0);
	if (!u)
		return -ENOMEM;

	err = replicast_map_unwind(u, RT_SYSKEY_CUSTOM_METADATA_SECTIDX);
	if (err) {
		msgpack_unpack_free(u);
		return err;
	}
	/*
	 * If custom_md is empty we will have a section for custom md in the
	 * msgpack but it will have no entries and will instead point to the
	 * refentry lists. Since we do not pack array type in custom_md, we
	 * can safely check for this.
	 *
	 * FIXME : should we pack a NULL for empty customMD instead ?
	 */
	int type = msgpack_unpack_peek(u);
	if (type == MSGPACK_ARRAY) {
		msgpack_unpack_free(u);
		return 0;
	}

	uint32_t n;
	err = msgpack_unpack_map(u, &n);
	if (err) {
		msgpack_unpack_free(u);
		log_error(lg, "Failing custom_md unpack map: \
		    Looking for %s, found %s", RT_SYSKEY_CUSTOM_METADATA,
		    (char *)u->p);
		return err;
	}

	int found = 0;
	for (size_t i = 0; i < n; i++) {
		const uint8_t *payload;
		uint32_t size = 0;
		char key[64] = { 0 };

		code = msgpack_unpack_peek(u);
		if (code != MSGPACK_RAW) {
			err = -ENOEXEC;
			goto _err;
		}

		err = msgpack_unpack_raw(u, &payload, &size);
		if (err < 0) {
			goto _err;
		}
		if (size > 0 && size < 32) {
			strncpy(key, (char *)payload, size);
		}

		if (strcmp(key,"x-cloud-provider") == 0) {
			code = msgpack_unpack_peek(u);
			if (code != MSGPACK_RAW) {
				err = -ENOEXEC;
				goto _err;
			}
			err = msgpack_unpack_raw(u, &payload, &size);
			if (err < 0) {
				goto _err;
			}
			*provier_type = (char *) je_calloc(size+1, sizeof(char));
			if (!*provier_type) {
				err = -ENOMEM;
				goto _err;
			}
			strncpy(*provier_type, (char *)payload, size);
			found++;
			if (found == 5)
				break;
			else
			    continue;
		}


		if (strcmp(key,"x-cloud-origin") == 0) {
			code = msgpack_unpack_peek(u);
			if (code != MSGPACK_RAW) {
				err = -ENOEXEC;
				goto _err;
			}
			err = msgpack_unpack_raw(u, &payload, &size);
			if (err < 0) {
				goto _err;
			}
			*provider_origin = (char *) je_calloc(size+1, sizeof(char));
			if (!*provider_origin) {
				err = -ENOMEM;
				goto _err;
			}
			strncpy(*provider_origin, (char *)payload, size);
			found++;
			if (found == 5)
				break;
			else
			    continue;
		}

		if (strcmp(key,"x-cloud-key") == 0) {
			code = msgpack_unpack_peek(u);
			if (code != MSGPACK_RAW) {
				err = -ENOEXEC;
				goto _err;
			}
			err = msgpack_unpack_raw(u, &payload, &size);
			if (err < 0) {
				goto _err;
			}
			*user_key = (char *) je_calloc(size+1, sizeof(char));
			if (!*user_key) {
				err = -ENOMEM;
				goto _err;
			}
			strncpy(*user_key, (char *)payload, size);
			found++;
			if (found == 5)
				break;
			else
			    continue;
		}


		if (strcmp(key,"x-cloud-region") == 0) {
			code = msgpack_unpack_peek(u);
			if (code != MSGPACK_RAW) {
				err = -ENOEXEC;
				goto _err;
			}
			err = msgpack_unpack_raw(u, &payload, &size);
			if (err < 0) {
				goto _err;
			}
			*provider_region = (char *) je_calloc(size+1, sizeof(char));
			if (!*provider_region) {
				err = -ENOMEM;
				goto _err;
			}
			strncpy(*provider_region, (char *)payload, size);
			found++;
			if (found == 5)
				break;
			else
			    continue;
		}

		// skip unused
		err = msgpack_unpack_skip(u);
		if (err < 0) {
			goto _err;
		}

	}

	msgpack_unpack_free(u);
	return 0;

_err:
    msgpack_unpack_free(u);
    if (*provier_type) {
	je_free(*provier_type);
	*provier_type = NULL;
    }
    if (*provider_origin) {
	je_free(*provider_origin);
	*provider_origin = NULL;
    }
    if (*user_key) {
	je_free(*user_key);
	*user_key = NULL;
    }
    if (*provider_region) {
	je_free(*provider_region);
	*provider_region = NULL;
    }
    return err;
}

/*
 * Get object specific metadata fields of Version Manifest payload
 */
int
replicast_object_metadata(rtbuf_t *in, char **etag, char **content_type, uint64_t *multipart_size, char **owner, char **srcip)
{
	int err;
	int code;

	// initialize
	*etag = NULL;
	*content_type = NULL;
	*multipart_size = 0;
	*owner = NULL;
	*srcip = NULL;


	/* we do not support fragmented reads at the moment... */
	assert(in->nbufs == 1);

	msgpack_u *u = msgpack_unpack_init(rtbuf(in, 0).base,
	    rtbuf(in, 0).len, 0);
	if (!u)
		return -ENOMEM;

	err = replicast_map_unwind(u, RT_SYSKEY_CUSTOM_METADATA_SECTIDX);
	if (err) {
		msgpack_unpack_free(u);
		return err;
	}
	/*
	 * If custom_md is empty we will have a section for custom md in the
	 * msgpack but it will have no entries and will instead point to the
	 * refentry lists. Since we do not pack array type in custom_md, we
	 * can safely check for this.
	 *
	 * FIXME : should we pack a NULL for empty customMD instead ?
	 */
	int type = msgpack_unpack_peek(u);
	if (type == MSGPACK_ARRAY) {
		msgpack_unpack_free(u);
		return 0;
	}

	uint32_t n;
	err = msgpack_unpack_map(u, &n);
	if (err) {
		msgpack_unpack_free(u);
		log_error(lg, "Failing custom_md unpack map: \
		    Looking for %s, found %s", RT_SYSKEY_CUSTOM_METADATA,
		    (char *)u->p);
		return err;
	}

	int found = 0;
	for (size_t i = 0; i < n; i++) {
		const uint8_t *payload;
		uint32_t size = 0;
		char key[64] = { 0 };

		code = msgpack_unpack_peek(u);
		if (code != MSGPACK_RAW) {
			err = -ENOEXEC;
			goto _err;
		}

		err = msgpack_unpack_raw(u, &payload, &size);
		if (err < 0) {
			goto _err;
		}
		if (size > 0 && size < 32) {
			strncpy(key, (char *)payload, size);
		}

		if (strcmp(key,"ETag") == 0) {
			code = msgpack_unpack_peek(u);
			if (code != MSGPACK_RAW) {
				err = -ENOEXEC;
				goto _err;
			}
			err = msgpack_unpack_raw(u, &payload, &size);
			if (err < 0) {
				goto _err;
			}
			*etag = (char *) je_calloc(size+1, sizeof(char));
			if (!*etag) {
				err = -ENOMEM;
				goto _err;
			}
			strncpy(*etag, (char *)payload, size);
			found++;
			if (found == 5)
				break;
			else
			    continue;
		}


		if (strcmp(key,"content-type") == 0) {
			code = msgpack_unpack_peek(u);
			if (code != MSGPACK_RAW) {
				err = -ENOEXEC;
				goto _err;
			}
			err = msgpack_unpack_raw(u, &payload, &size);
			if (err < 0) {
				goto _err;
			}
			*content_type = (char *) je_calloc(size+1, sizeof(char));
			if (!*content_type) {
				err = -ENOMEM;
				goto _err;
			}
			strncpy(*content_type, (char *)payload, size);
			// remove encoding if available
			char *sp;
			char *token = strtok_r(*content_type, " ;", &sp);
			if (token) {
				bcopy(token, *content_type, strlen(token) + 1);
			}
			found++;
			if (found == 5)
				break;
			else
			    continue;
		}



		if (strcmp(key,"multipart_size") == 0) {
			code = msgpack_unpack_peek(u);
			if (code == MSGPACK_UINT8) {
				uint8_t u8 = 0;
				err = msgpack_unpack_uint8(u, &u8);
				if (err < 0) {
					goto _err;
				}
				*multipart_size = u8;
			} else if (code == MSGPACK_FIX) {
					int8_t i8 = 0;
					err = msgpack_unpack_fix(u, &i8);
					if (err < 0) {
						goto _err;
					}
					*multipart_size = (uint64_t) i8;
			} else if (code == MSGPACK_UINT16) {
				uint16_t u16 = 0;
				err = msgpack_unpack_uint16(u, &u16);
				if (err < 0) {
					goto _err;
				}
				*multipart_size = u16;
			} else if (code == MSGPACK_UINT32) {
				uint32_t u32 = 0;
				err = msgpack_unpack_uint32(u, &u32);
				if (err < 0) {
					goto _err;
				}
				*multipart_size = u32;
			} else if (code == MSGPACK_UINT64) {
				err = msgpack_unpack_uint64(u, multipart_size);
				if (err < 0) {
					goto _err;
				}
			}
			found++;
			if (found == 5)
				break;
			else
			    continue;
		}

		if (strcmp(key,"x-owner") == 0) {
			code = msgpack_unpack_peek(u);
			if (code != MSGPACK_RAW) {
				err = -ENOEXEC;
				goto _err;
			}
			err = msgpack_unpack_raw(u, &payload, &size);
			if (err < 0) {
				goto _err;
			}
			*owner = (char *) je_calloc(size+1, sizeof(char));
			if (!*owner) {
				err = -ENOMEM;
				goto _err;
			}
			strncpy(*owner, (char *)payload, size);
			found++;
			if (found == 5)
				break;
			else
			    continue;
		}


		if (strcmp(key,"x-source") == 0) {
			code = msgpack_unpack_peek(u);
			if (code != MSGPACK_RAW) {
				err = -ENOEXEC;
				goto _err;
			}
			err = msgpack_unpack_raw(u, &payload, &size);
			if (err < 0) {
				goto _err;
			}
			*srcip = (char *) je_calloc(size+1, sizeof(char));
			if (!*srcip) {
				err = -ENOMEM;
				goto _err;
			}
			strncpy(*srcip, (char *)payload, size);
			found++;
			if (found == 5)
				break;
			else
			    continue;
		}

		// skip unused
		err = msgpack_unpack_skip(u);
		if (err < 0) {
			goto _err;
		}

	}

	msgpack_unpack_free(u);
	return 0;

_err:
    msgpack_unpack_free(u);
    if (*etag) {
	je_free(*etag);
	*etag = NULL;
    }
    if (*content_type) {
	je_free(*content_type);
	*content_type = NULL;
    }
    if (*owner) {
	je_free(*owner);
	*owner = NULL;
    }
    if (*srcip) {
	je_free(*srcip);
	*srcip = NULL;
    }
    return err;
}


/*
 * Get object specific metadata fields of Version Manifest payload
 */
int
replicast_object_metadata_field(rtbuf_t *in, char *name, uint64_t *res)
{
	int err;
	int code;

	// initialize
	*res = 0;

	msgpack_u *u = msgpack_unpack_init(rtbuf(in, 0).base,
	    rtbuf(in, 0).len, 0);
	if (!u)
		return -ENOMEM;

	err = replicast_map_unwind(u, RT_SYSKEY_CUSTOM_METADATA_SECTIDX);
	if (err) {
		msgpack_unpack_free(u);
		return err;
	}

	int type = msgpack_unpack_peek(u);
	if (type == MSGPACK_ARRAY) {
		msgpack_unpack_free(u);
		return -ENOENT;
	}

	uint32_t n;
	err = msgpack_unpack_map(u, &n);
	if (err) {
		msgpack_unpack_free(u);
		log_error(lg, "Failing custom_md unpack map: \
		    Looking for %s, found %s", RT_SYSKEY_CUSTOM_METADATA,
		    (char *)u->p);
		return err;
	}

	int found = 0;
	for (size_t i = 0; i < n; i++) {
		const uint8_t *payload;
		uint32_t size = 0;
		char key[64] = { 0 };

		code = msgpack_unpack_peek(u);
		if (code != MSGPACK_RAW) {
			err = -ENOEXEC;
			goto _err;
		}

		err = msgpack_unpack_raw(u, &payload, &size);
		if (err < 0) {
			goto _err;
		}
		if (size > 0 && size < 32) {
			strncpy(key, (char *)payload, size);
		}


		if (strcmp(key, name) == 0) {
			code = msgpack_unpack_peek(u);
			if (code == MSGPACK_UINT8) {
				uint8_t u8 = 0;
				err = msgpack_unpack_uint8(u, &u8);
				if (err < 0) {
					goto _err;
				}
				*res = u8;
				found = 1;
			} else if (code == MSGPACK_FIX) {
					int8_t i8 = 0;
					err = msgpack_unpack_fix(u, &i8);
					if (err < 0) {
						goto _err;
					}
					*res = (uint64_t) i8;
					found = 1;
			} else if (code == MSGPACK_UINT16) {
				uint16_t u16 = 0;
				err = msgpack_unpack_uint16(u, &u16);
				if (err < 0) {
					goto _err;
				}
				*res = u16;
				found = 1;
			} else if (code == MSGPACK_UINT32) {
				uint32_t u32 = 0;
				err = msgpack_unpack_uint32(u, &u32);
				if (err < 0) {
					goto _err;
				}
				*res = u32;
				found = 1;
			} else if (code == MSGPACK_UINT64) {
				err = msgpack_unpack_uint64(u, res);
				if (err < 0) {
					goto _err;
				}
				found = 1;
			} else if (code == MSGPACK_RAW) {
				const uint8_t *payload = NULL;
				const char *str;
				uint32_t size;
				err = msgpack_unpack_raw(u, &payload, &size);
				if (err < 0) {
					goto _err;
				}
				str = (char *)payload;
				*res = (uint64_t) atol(str);
				found = 1;
			}
		    break;
		}


		// skip unused
		err = msgpack_unpack_skip(u);
		if (err < 0) {
			goto _err;
		}

	}

	if (!found) {
		err = -ENOENT;
	} else {
		err = 0;
	}

_err:
    msgpack_unpack_free(u);
    return err;
}



/*
 * Retrieve ccow-metadata section of Version Manifest payload
 */
int
replicast_get_metadata(rtbuf_t *in, struct vmmetadata *out)
{
	int err;

	/* we do not support fragmented reads at the moment... */
	assert(in->nbufs == 1);

	msgpack_u *u = msgpack_unpack_init(rtbuf(in, 0).base,
	    rtbuf(in, 0).len, 0);
	if (!u)
		return -ENOMEM;

	err = replicast_map_unwind(u, RT_SYSKEY_METADATA_SECTIDX);
	if (err) {
		msgpack_unpack_free(u);
		return err;
	}
	err = replicast_unpack_vmmetadata(u, out);
	if (err) {
		msgpack_unpack_free(u);
		return err;
	}
	msgpack_unpack_free(u);

	if (rtbuf_is_override(in)) {
		uv_buf_t marker = rtbuf(in, in->nbufs - 1);
		uv_buf_t override;

		if (marker.len < override_marker_size)
			goto _exit;
		void *marker_start = marker.base + marker.len - override_marker_size;

		uint32_t override_initial_length;
		uint32_t override_content_length;
		uint32_t override_num;

		memcpy(&override_initial_length, marker_start, 4);
		memcpy(&override_content_length, (uint8_t *)marker_start+4, 4);
		memcpy(&override_num, (uint8_t *)marker_start + 8, 4);

		if (!override_initial_length || !override_content_length || !override_num)
			goto _exit;

		if (marker.len < (override_marker_size + override_content_length))
			goto _exit;
		override.base = (marker.base +
		    (marker.len - override_marker_size - override_content_length));
		override.len =  override_content_length;
		if (override.len < 8)
			goto _exit;

		uint8_t ver;
		u = msgpack_unpack_init(override.base, override.len, 0);
		err = msgpack_unpack_uint8(u, &ver);
		if (!err && ver == 1) {
			for (uint16_t n=0; n<override_num; n++) {
				const uint8_t *data;
				uint64_t value;
				uint32_t nout;
				err = msgpack_unpack_raw(u, &data, &nout);
				if (err)
					break;
				err = msgpack_unpack_uint64(u, (uint64_t *) &value);
				if (err)
					break;
				if (strncmp((char *)data, RT_SYSKEY_REPLICATION_COUNT, nout) == 0) {
					if (value > 0 && value <= 9) {
						out->replication_count = (uint8_t)value;
					}
				} else if (strncmp((char *)data, RT_SYSKEY_NUMBER_OF_VERSIONS, nout) == 0) {
					if (value > 0) {
						out->number_of_versions = (uint16_t)value;
					}
				} else if (strncmp((char *)data, RT_SYSKEY_EC_ENABLED, nout) == 0) {
					out->ec_enabled = (uint8_t)value;
				} else if (strncmp((char *)data, RT_SYSKEY_EC_DATA_MODE, nout) == 0) {
					out->ec_data_mode = (uint32_t)value;
				} else if (strncmp((char *)data, RT_SYSKEY_EC_TRG_POLICY, nout) == 0) {
					out->ec_trg_policy = (uint64_t)value;
				} else if (strncmp((char *)data, RT_SYSKEY_ONDEMAND, nout) == 0) {
					RT_ONDEMAND_SET(out->inline_data_flags, (uint16_t)value);
				}
			}
		}
		msgpack_unpack_free(u);
	}

_exit:
	return 0;
}

/*
 * Search for the version(s).
 *
 * Versions organized into msgpack map entry pointing to array of
 * struct vlentry elements.
 *
 * Supplied buffers order is important. Found version(s) will be returned
 * back to the caller as a newly allocated rtbuf_t.
 *
 * If vlentry->uvid_timestamp == 0, return latest version from the top of
 * the list.
 *
 * Special case: if query == NULL, simply unpack all entries.
 *
 */
int
replicast_get_versions(rtbuf_t *in, struct vlentry *query, rtbuf_t **out)
{
	int err;

	/* we do not support fragmented reads at the moment... */
	assert(in->nbufs == 1);

	*out = NULL;

	msgpack_u *u = msgpack_unpack_init(rtbuf(in, 0).base,
	    rtbuf(in, 0).len, 0);
	if (!u)
		return -ENOMEM;

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err) {
		msgpack_unpack_free(u);
		return err;
	}
	/* at least one version must be present */
	if (n == 0) {
		msgpack_unpack_free(u);
		return -ENOENT;
	}

	int found = 0;
	size_t j;
	for (j = 0; j < n; j++) {
		struct vlentry *e = je_malloc(sizeof (struct vlentry));
		if (!e) {
			found = -ENOMEM;
			goto _exit;
		}
		uv_buf_t ent;
		ent.base = (char *)e;
		ent.len = sizeof (struct vlentry);
		err = replicast_unpack_vlentry(u, e);
		if (err) {
			found = err;
			je_free(e);
			goto _exit;
		}

		/* request for the latest UVID? */
		if (query && query->uvid_timestamp == 0) {
			if (!query->generation) {
				found = 1;
			}
			if (e->generation == query->generation) {
				found = 1;
			}
			if (found) {
				*out = rtbuf_init(&ent, 1);
				if (!*out) {
					found = err = -ENOMEM;
					je_free(e);
					goto _exit;
				}
				break;
			}
		}

		/*
		 * This implements search by UVID. Function may return
		 * more then one vlentry if UVIDs not unique. In which
		 * case SourceID must be used as a tie breaker.
		 *
		 * FIXME: implement search by SourceID and by both..
		 */
		if (!query ||
			query->uvid_timestamp == e->uvid_timestamp) {
			if (!*out) {
				*out = rtbuf_init(NULL, n);
				if (!*out) {
					found = err = -ENOMEM;
					je_free(e);
					goto _exit;
				}
			}
			rtbuf_set(*out, found, &ent, 1);
			found++;
		}
	}

	/* adjust output rtbuf because it can be less then "n" */
	(*out)->nbufs = found;

_exit:
	msgpack_unpack_free(u);
	if (found <= 0 && *out) {
		rtbuf_destroy(*out);
		*out = NULL;
	}
	return found;
}

/*
 * vbuf reserved allocation
 * return 0 if successful
 * return -ERROR otherwise
 */
int replicast_alloc_vbuf(struct repvbuf *vbuf, uint64_t req_len, int stat)
{
	int err = replicast_check_avail_vbuf(vbuf, req_len);
	if (err && !stat) {
		return err;
	}
	atomic_add(&vbuf->reserved, req_len);
	return 0;
}

/*
 * free previously allocated vbuf
 */
void replicast_free_vbuf(struct repvbuf *vbuf, uint64_t req_len)
{
	if (req_len == 0 || vbuf->reserved < req_len) {
		return;
	}
	atomic_sub(&vbuf->reserved, req_len);
}

/*
 * allocate the vbuf as queued but not allocated
 */
int replicast_alloc_vbuf_queued(struct repvbuf *vbuf, uint64_t req_len)
{
	if (req_len == 0) {
		return -EINVAL;
	}
	atomic_add(&vbuf->queued, req_len);
	return 0;
}


/*
 * free the previously queued allocation
 */
void replicast_free_vbuf_queued(struct repvbuf *vbuf, uint64_t req_len)
{
	if (req_len == 0) {
		return;
	}
	atomic_sub(&vbuf->queued, req_len);
}

/*
 * retrieve how much of the vbuf is currently available
 *
 */
uint64_t replicast_get_avail_vbuf(struct repvbuf *vbuf)
{
	long avail_buf = vbuf->total - (vbuf->queued + vbuf->reserved);
	if (avail_buf > 0)
		return avail_buf;
	else
		return 0;
}

/*
 * retrieve how much of the vbuf is currently reserved (bytes)
 */
uint64_t replicast_get_reserved_vbuf(struct repvbuf *vbuf)
{
	return vbuf->reserved;
}

/*
 * check of the space is available for allocation
 * returns 0 - if space available
 * returns -ERROR - if no space evailable
 */
int replicast_check_avail_vbuf(struct repvbuf *vbuf, uint64_t req_len)
{
	uint64_t avail = replicast_get_avail_vbuf(vbuf);
	if (avail < req_len)
		return -ENOSPC;
	return 0;
}

void replicast_vbuf_link_update(struct repvbuf *vbuf, uint32_t if_speed)
{
	assert(if_speed);
	vbuf->total = (if_speed / 8LU) * 1024LU * 1024LU;
}

void replicast_vbuf_init(struct repvbuf *vbuf, uint32_t if_speed)
{
	replicast_vbuf_link_update(vbuf, if_speed);
	vbuf->queued = 0;
	vbuf->reserved = 0;
}

int replicast_uvbuf_integrate(uv_buf_t *buf, int nbufs, uv_buf_t *onebuf)
{
	uint32_t len = 0;
	char *p;

	for (int i = 0; i < nbufs; i++)
		len += buf[i].len;

	onebuf->base = je_calloc(1, len);
	if (!onebuf->base) {
		log_error(lg, "%s: Memory allocation failed.", __FUNCTION__);
		return -ENOMEM;
	}

	onebuf->len = len;
	p = onebuf->base;
	for (int i = 0; i < nbufs; i++) {
		memcpy(p, buf[i].base, buf[i].len);
		p += buf[i].len;
	}

	return 0;
}

int replicast_pack_uvbuf_nodes(struct cl_node *members, uint32_t nr_members,
    uv_buf_t *payload, rtbuf_t *checkpoint_payload)
{
	int err;

	msgpack_p *np = msgpack_pack_init();
	if (!np) {
		log_error(lg, "%s: out of memory", __FUNCTION__);
		return -1;
	}

	err = msgpack_pack_array(np, nr_members);
	if (err) {
		msgpack_pack_free(np);
		return -1;
	}

	struct cl_node *node = members;
	for (uint32_t i = 0; i < nr_members; i++) {
		log_debug(lg, "Packing node %u vdevs %u", i, node->nr_vdevs);
		err = replicast_pack_repnode(np, node);
		if (err) {
			msgpack_pack_free(np);
			return -1;
		}

		node++;
	}

	err = msgpack_pack_str(np, checkpoint_payload ? checkpoint_payload->bufs[0].base : "");
	if (err) {
		msgpack_pack_free(np);
		return -1;
	}

	msgpack_get_buffer(np, payload);
	msgpack_pack_free_p(np);

	return 0;
}

int replicast_unpack_uvbuf_nodes(uv_buf_t *payload, uint32_t nr_members,
    struct cl_node **members, char *checkpoint, int checkpoint_len)
{
	struct cl_node *node, *rnode;
	msgpack_u mu;
	uint32_t n;
	int err;

	msgpack_unpack_init_b(&mu, payload->base, payload->len, 0);

	err = msgpack_unpack_array(&mu, &n);
	if (err) {
		log_error(lg, "%s: msgpack_unpack_array failed.", __FUNCTION__);
		return err;
	}

	if(n != nr_members) {
		log_error(lg, "%s: No of sent nodes mismatch.", __FUNCTION__);
		return -EINVAL;
	}

	log_debug(lg, "Received %u nodes", nr_members);

	node = je_calloc(nr_members, sizeof(struct cl_node));
	if (!node) {
		log_error(lg, "%s: Unable to allocate memory", __FUNCTION__);
		return -ENOMEM;
	}

	rnode = node;
	for (uint32_t i = 0; i < nr_members; i++) {
		err = replicast_unpack_repnode(&mu, &node);
		if (err) {
			replicast_free_repnodelist(rnode, i);
			return err;
		}

		log_debug(lg, "Received %u vdevs", node->nr_vdevs);
		node++;
	}

	if (checkpoint) {
		err = msgpack_unpack_str(&mu, checkpoint, checkpoint_len);
		if (err) {
			if (nr_members)
				replicast_free_repnodelist(rnode, nr_members);
			return err;
		}
	}

	*members = rnode;
	return 0;
}

ifvbuf_t *
replicast_ifvbuf_init(ifvbuf_t *ifvbuf, uint32_t if_speeds[], int if_count)
{
	ifvbuf->if_count = if_count;
	for (int i = 0; i < if_count; i++) {
		struct repvbuf *vbuf = &ifvbuf->pvbuf[i];
		replicast_vbuf_init(vbuf, if_speeds[i]);
	}
	return ifvbuf;
}

int
replicast_pack_uvbuf(msgpack_p *p, uv_buf_t *ub)
{
	int err;

	err = msgpack_pack_uint64(p, ub->len);
	if (err)
		return err;

	err = msgpack_pack_raw(p, ub->base, (uint32_t) ub->len);
	if (err)
		return err;

	return 0;
}

int
replicast_unpack_uvbuf(msgpack_u *u, uv_buf_t *ub)
{
	uint64_t len;
	uint32_t n;
	int err;

	err = msgpack_unpack_uint64(u, &len);
	if (err)
		return err;

	ub->len = len;
	err = msgpack_unpack_raw(u, (const uint8_t **)&ub->base, &n);
	if (err)
		return err;
	if (len != n)
		return -EBADF;

	return 0;
}

int
replicast_pack_rtbuf(msgpack_p *p, rtbuf_t *rb)
{
	unsigned int i;
	int err;

	err = msgpack_pack_uint64(p, rb->nbufs);
	if (err)
		return err;

	for (i = 0; i < rb->nbufs; i++) {
		err = replicast_pack_uvbuf(p, &rtbuf(rb, i));
		if (err)
			return err;
	}

	return 0;
}

int
replicast_unpack_rtbuf(msgpack_u *u, rtbuf_t **rbuf)
{
	int err;
	rtbuf_t *rb;
	uint64_t i, n;

	err = msgpack_unpack_uint64(u, &n);
	if (err)
		return err;

	if (n > 0) {
		uv_buf_t ub[n];
		for (i = 0; i < n; i++) {
			err = replicast_unpack_uvbuf(u, &ub[i]);
			if (err)
				return err;
		}
		rb = rtbuf_init_alloc(ub, n);
	} else {
		rb = rtbuf_init_empty();
	}
	if (!rb) {
		return -ENOMEM;
	}

	*rbuf = rb;
	return 0;
}

int
replicast_pack_sg_lookup(msgpack_p *p, struct repmsg_sg_lookup *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->chid);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &msg->nhid);
	if (err)
		return err;

	err = msgpack_pack_uint32(p, msg->attr);
	if (err)
		return err;

	return 0;
}

int
replicast_unpack_sg_lookup(msgpack_u *u, struct repmsg_sg_lookup *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->chid);
	if (err)
		return err;

	err = replicast_unpack_uint512(u, &msg->nhid);
	if (err)
		return err;

	err = msgpack_unpack_uint32(u, &msg->attr);
	if (err)
		return err;

	return 0;
}

int
replicast_pack_sg_lookup_response(msgpack_p *p, struct repmsg_sg_lookup_response *msg)
{
	int err;

	err = msgpack_pack_uint32(p, msg->present);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, msg->genid);
	if (err)
		return err;

	err = msgpack_pack_int32(p, msg->status);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &msg->vmchid);
	if (err)
		return err;

	return 0;
}

int
replicast_unpack_sg_lookup_response(msgpack_u *u, struct repmsg_sg_lookup_response *msg)
{
	int err;

	err = msgpack_unpack_uint32(u, &msg->present);
	if (err)
		return err;

	err = msgpack_unpack_uint64(u, &msg->genid);
	if (err)
		return err;

	err = msgpack_unpack_int32(u, &msg->status);
	if (err)
		return err;

	err = replicast_unpack_uint512(u, &msg->vmchid);
	if (err)
		return err;

	return 0;
}

int
replicast_pack_sg_chunkput(msgpack_p *p, struct repmsg_sg_chunkput *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->chid);
	if (err)
		return err;

	err = msgpack_pack_uint32(p, msg->attr);
	if (err)
		return err;

	return 0;
}

int
replicast_unpack_sg_chunkput(msgpack_u *u, struct repmsg_sg_chunkput *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->chid);
	if (err)
		return err;

	err = msgpack_unpack_uint32(u, &msg->attr);
	if (err)
		return err;

	return 0;
}

int
replicast_pack_sg_chunkput_response(msgpack_p *p, struct repmsg_sg_chunkput_response *msg)
{
	return msgpack_pack_int32(p, msg->status);
}

int
replicast_unpack_sg_chunkput_response(msgpack_u *u, struct repmsg_sg_chunkput_response *msg)
{
	return msgpack_unpack_int32(u, &msg->status);
}


int
replicast_pack_sg_chunkget(msgpack_p *p, struct repmsg_sg_chunkget *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->chid);
	if (err)
		return err;

	err = msgpack_pack_uint32(p, msg->attr);
	if (err)
		return err;

	return 0;
}

int
replicast_unpack_sg_chunkget(msgpack_u *u, struct repmsg_sg_chunkget *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->chid);
	if (err)
		return err;

	err = msgpack_unpack_uint32(u, &msg->attr);
	if (err)
		return err;

	return 0;
}

int
replicast_pack_sg_chunkget_response(msgpack_p *p, struct repmsg_sg_chunkget_response *msg)
{
	return msgpack_pack_int32(p, msg->status);
}

int
replicast_unpack_sg_chunkget_response(msgpack_u *u, struct repmsg_sg_chunkget_response *msg)
{
	return msgpack_unpack_int32(u, &msg->status);
}




int
replicast_pack_sg_vmput(msgpack_p *p, struct repmsg_sg_vmput *msg)
{
	int err;

	err = replicast_pack_uint512(p, &msg->phid);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &msg->nhid);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &msg->vmchid);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, msg->timestamp);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, msg->generation);
	if (err)
		return err;

	return 0;
}

int
replicast_unpack_sg_vmput(msgpack_u *u, struct repmsg_sg_vmput *msg)
{
	int err;

	err = replicast_unpack_uint512(u, &msg->phid);
	if (err)
		return err;

	err = replicast_unpack_uint512(u, &msg->nhid);
	if (err)
		return err;

	err = replicast_unpack_uint512(u, &msg->vmchid);
	if (err)
		return err;

	err = msgpack_unpack_uint64(u, &msg->timestamp);
	if (err)
		return err;

	err = msgpack_unpack_uint64(u, &msg->generation);
	if (err)
		return err;

	return 0;
}

int replicast_pack_sg_vmput_response(msgpack_p *p, struct repmsg_sg_vmput_response *msg)
{
	return msgpack_pack_int32(p, msg->status);
}

int replicast_unpack_sg_vmput_response(msgpack_u *u, struct repmsg_sg_vmput_response *msg)
{
	return msgpack_unpack_int32(u, &msg->status);
}

int
replicast_pack_sg_ssput(msgpack_p *p, struct repmsg_sg_ssput *msg)
{
	return msgpack_pack_uint32(p, msg->magic);
}

int
replicast_unpack_sg_ssput(msgpack_u *u, struct repmsg_sg_ssput *msg)
{
	return msgpack_unpack_uint32(u, &msg->magic);
}

int
replicast_pack_sg_ssput_response(msgpack_p *p, struct repmsg_sg_ssput_response *msg)
{
	return msgpack_pack_int32(p, msg->status);
}

int
replicast_unpack_sg_ssput_response(msgpack_u *u, struct repmsg_sg_ssput_response *msg)
{
	return msgpack_unpack_int32(u, &msg->status);
}

/*
 * Pack/unpack: ISGW Expunge
 */
int
replicast_pack_sg_expunge(msgpack_p *p, struct repmsg_sg_expunge *msg)
{
	return msgpack_pack_uint32(p, msg->magic);
}

int
replicast_unpack_sg_expunge(msgpack_u *u, struct repmsg_sg_expunge *msg)
{
	return msgpack_unpack_uint32(u, &msg->magic);
}

int
replicast_pack_sg_expunge_response(msgpack_p *p, struct repmsg_sg_expunge_response *msg)
{
	return msgpack_pack_int32(p, msg->status);
}

int
replicast_unpack_sg_expunge_response(msgpack_u *u, struct repmsg_sg_expunge_response *msg)
{
	return msgpack_unpack_int32(u, &msg->status);
}

int
replicast_pack_sg_dynfetch(msgpack_p *p, struct repmsg_sg_dynfetch* msg) {
	assert(msg);
	return msgpack_pack_uint8(p, msg->version);
}

int
replicast_unpack_sg_dynfetch(msgpack_u *u, struct repmsg_sg_dynfetch* msg) {
	assert(msg);
	return msgpack_unpack_uint8(u, &msg->version);
}

int
replicast_pack_sg_dynfetch_response(msgpack_p *p, struct repmsg_sg_dynfetch_resp* msg) {
	return msgpack_pack_int64(p, msg->status);
}
int
replicast_unpack_sg_dynfetch_response(msgpack_u *u, struct repmsg_sg_dynfetch_resp* msg) {
	return msgpack_unpack_int64(u, &msg->status);
}


/*
 * Pack: ISGW PING-PONG
 */
int
replicast_pack_sg_ping_pong(msgpack_p *p, struct repmsg_sg_ping_pong *msg)
{
	int err;

	err = msgpack_pack_uint32(p, msg->message_size);
	if (err)
		return err;
	err = msgpack_pack_raw(p, msg->message, msg->message_size);
	if (err)
		return err;
	return err;
}

/*
 * Unpack: ISGW PING-PONG
 */
int
replicast_unpack_sg_ping_pong(msgpack_u *u, struct repmsg_sg_ping_pong *msg)
{
	int err;

	err = msgpack_unpack_uint32(u, &msg->message_size);
	if (err)
		return err;
	unsigned int n;
	err = msgpack_unpack_raw(u, (const uint8_t **)&msg->message, &n);
	if (err)
		return err;
	if (n != msg->message_size)
		return -EBADF;
	return err;
}

/*
 * Pack: ISGW PING-PONG RESPONSE
 */
int
replicast_pack_sg_ping_pong_response(msgpack_p *p, struct repmsg_sg_ping_pong_response *msg)
{
	int err;

	err = msgpack_pack_uint32(p, msg->message_size);
	if (err)
		return err;
	err = msgpack_pack_raw(p, msg->message, msg->message_size);
	if (err)
		return err;
	return err;
}

/*
 * Unpack: ISGW PING-PONG RESPONSE
 */
int
replicast_unpack_sg_ping_pong_response(msgpack_u *u, struct repmsg_sg_ping_pong_response *msg)
{
	int err;

	err = msgpack_unpack_uint32(u, &msg->message_size);
	if (err)
		return err;
	unsigned int n;
	err = msgpack_unpack_raw(u, (const uint8_t **)&msg->message, &n);
	if (err)
		return err;
	if (n != msg->message_size)
		return -EBADF;
	return err;
}


int replicast_pack_opp_status(msgpack_p *p, struct repmsg_opps *msg) {
	int err = msgpack_pack_int32(p, msg->flags);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &msg->nhid);
	if (err)
		return err;
	return replicast_pack_uint512(p, &msg->vmchid);
}
int replicast_unpack_opp_status(msgpack_u *u, struct repmsg_opps *msg) {
	int err = msgpack_unpack_int32(u, &msg->flags);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &msg->nhid);
	if (err)
		return err;
	return replicast_unpack_uint512(u, &msg->vmchid);
}

int replicast_pack_opp_status_result(msgpack_p *p, struct repmsg_opps_result *msg) {
	int err = replicast_pack_uint512(p, &msg->vmchid);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_zl);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_tl);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cp);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cpar);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_zl_verified);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_tl_verified);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cp_verified);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cpar_verified);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_zl_1vbr);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_tl_1vbr);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cp_1vbr);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_zl_lost);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_tl_lost);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cp_lost);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cpar_lost);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_zl_pp);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_tl_erc_err);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->n_cm_zl_erc_err);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->pp_algo);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->pp_data_number);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->pp_parity_number);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->pp_domain);
	if (err)
		return err;
	err = msgpack_pack_int16(p, msg->status);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->hostid);
	if (err)
		return err;
	err = msgpack_pack_int16(p, msg->n_vdevs);
	if (err)
		return err;
	for (int i = 0; i < msg->n_vdevs; i++) {
		err = msgpack_pack_uint64(p, msg->vdevs_usage[i]);
		if (err)
			return err;
	}
	return err;
}

int replicast_unpack_opp_status_result(msgpack_u *u, struct repmsg_opps_result *msg) {
	int err = replicast_unpack_uint512(u, &msg->vmchid);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_zl);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_tl);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cp);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cpar);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_zl_verified);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_tl_verified);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cp_verified);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cpar_verified);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_zl_1vbr);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_tl_1vbr);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cp_1vbr);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_zl_lost);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_tl_lost);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cp_lost);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cpar_lost);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_zl_pp);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_tl_erc_err);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->n_cm_zl_erc_err);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->pp_algo);
	if (err)
			return err;
	err = msgpack_unpack_uint16(u, &msg->pp_data_number);
	if (err)
			return err;
	err = msgpack_unpack_uint16(u, &msg->pp_parity_number);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->pp_domain);
	if (err)
		return err;
	err = msgpack_unpack_int16(u, &msg->status);
	if (err)
		return err;

	err = replicast_unpack_uint128(u, &msg->hostid);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->n_vdevs);
	if (err)
		return err;
	if (msg->n_vdevs) {
		msg->vdevs_usage = je_calloc(msg->n_vdevs, sizeof(uint64_t));
		if (!msg->vdevs_usage)
			return -ENOMEM;
		for (int i = 0; i < msg->n_vdevs; i++) {
			err = msgpack_unpack_uint64(u, msg->vdevs_usage + i);
			if (err)
				return err;
		}
	}
	return err;
}

int replicast_pack_rowevac(msgpack_p *p, struct repmsg_rowevac *msg) {
	int err = msgpack_pack_uint8(p, msg->opcode);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->id);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->flags);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, msg->amount);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->src_vdev);
	if (err)
		return err;
	err = replicast_pack_uint128(p, &msg->dest_vdev);
	if (err)
		return err;
	err = msgpack_pack_uint16(p, msg->row);
	if (err)
		return err;
	err = msgpack_pack_int8(p, msg->status);
	return err;
}

int replicast_unpack_rowevac(msgpack_u *u, struct repmsg_rowevac *msg) {
	int err = msgpack_unpack_uint8(u, &msg->opcode);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->id);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->flags);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &msg->amount);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->src_vdev);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &msg->dest_vdev);
	if (err)
		return err;
	err = msgpack_unpack_uint16(u, &msg->row);
	if (err)
		return err;
	err = msgpack_unpack_int8(u, &msg->status);
	return err;
}
