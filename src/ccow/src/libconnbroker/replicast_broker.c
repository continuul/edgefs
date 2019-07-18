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
#include "replicast.h"
#include "rt_tcp.h"
#include "connbroker.h"

static void
rtsock_log_addr(rt_tcp_t *rtsock)
{
	struct replicast *robj = rtsock->robj;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	int src_port, dst_port, scopeid = 0;

	replicast_tcp_get_addr(rtsock, src, dst, &src_port, &dst_port, &scopeid);

	log_debug(lg, "Replicast(%s): From %s:%d To %s:%d (%d)",
		robj->name, src, ntohs(src_port), dst, ntohs(dst_port), scopeid);
}

static void
stream_close(rt_tcp_t *rtsock)
{
	rt_stream_t *stream = &rtsock->stream;
	state_event(&stream->st, EV_DONE);
}

static int
stream_read(rt_tcp_t *rtsock, ssize_t nread, uv_buf_t buf)
{
	rt_stream_t *stream = &rtsock->stream;
	rt_tcp_sbuf_init(&stream->nbuf, buf, nread);
	state_event(&stream->st, RT_STREAM_UPDATED);
	if (stream->error)
		return stream->error;

	while (state_check(&stream->st, ST_READY)) {
		stream->wait ? state_event(&stream->st, RT_STREAM_DECODE_WAIT) :
			       state_event(&stream->st, RT_STREAM_DECODE);
		if (stream->error)
			return stream->error;
	}
	return 0;
}

static void
handle_close_cb(uv_handle_t *handle)
{
	if (handle->data)
		je_free(handle->data);
}

void
replicast_tcp_socket_close(uv_tcp_t *tcp_handle)
{
	uv_close((uv_handle_t *)tcp_handle, handle_close_cb);
}

void
rtsock_close(rt_tcp_t *rtsock)
{
	uv_close((uv_handle_t *)&rtsock->tchandle, handle_close_cb);
}

static void
rtsock_shutdown_cb(uv_shutdown_t *req, int status)
{
	if (status) {
		log_error(lg, "TCP shutdown failed, handle %p", req->data);
		return;
	}

	rt_tcp_t *rtsock = req->data;
	rtsock_close(rtsock);
}

static void
rtsock_shutdown(rt_tcp_t *rtsock)
{
	uv_tcp_t *handle = &rtsock->tchandle;
	struct replicast *robj = rtsock->robj;

	log_debug(lg, "Replicast(%s): TCP shutdown", rtsock->robj->name);
	uv_read_stop((uv_stream_t *)handle);
	stream_close(rtsock);
	QUEUE_REMOVE(&rtsock->item);
	rtsock->sreq.data = rtsock;
	uv_shutdown(&rtsock->sreq, (uv_stream_t *)handle, rtsock_shutdown_cb);
}

static void
replicast_tcp_read(uv_stream_t *handle, ssize_t nread, uv_buf_t buf)
{
	rt_tcp_t *rtsock = handle->data;

	if (nread < 0) {
		if (buf.base)
			je_free(buf.base);

		uv_err_code ec = uv_last_error(handle->loop).code;
		if (ec != UV_EOF)
			log_error(lg, "Error reading TCP stream %p, err %d",
				handle, ec);
		rtsock_shutdown(rtsock);
		return;
	}

	if (nread == 0) {
		if (buf.base)
			je_free(buf.base);
		return;
	}

	int err = stream_read(rtsock, nread, buf);
	if (err)
		rtsock_shutdown(rtsock);
}

static int
replicast_tcp_accept(struct replicast *robj, rt_tcp_t *rtsock)
{
	int err = uv_tcp_init(robj->loop, &rtsock->tchandle);
	if (err) {
		log_error(lg, "Failed to initialize tcp");
		je_free(rtsock);
		return err;
	}

	uv_stream_t *sstream = (uv_stream_t *)&robj->recv_tcp_socket;
	uv_stream_t *cstream = (uv_stream_t *)&rtsock->tchandle;

	err = uv_accept(sstream, cstream);
	if (err) {
		log_error(lg, "Replicast(%s): Failed to accept tcp", robj->name);
		je_free(rtsock);
		return err;
	}

	err = uv_read_start(cstream, alloc_buffer, replicast_tcp_read);
	if (err) {
		log_error(lg, "Replicast(%s): Failed to read from client", robj->name);
		rtsock_shutdown(rtsock);
		return err;
	}

	return 0;
}

static void
replicast_tcp_serve(uv_stream_t *req, int status)
{
	struct replicast *robj = req->data;

	if (status) {
		log_error(lg, "TCP server error %d", uv_last_error(req->loop).code);
		return;
	}

	rt_tcp_t *rtsock = je_calloc(1, sizeof(*rtsock));
	if (rtsock == NULL) {
		log_error(lg, "Failed to allocate rtsock");
		return;
	}

	rtsock->robj = robj;
	rtsock->tchandle.data = rtsock;
	QUEUE_INIT(&rtsock->item);
	rt_tcp_stream_init(&rtsock->stream);
	rtsock->stream.robj = robj;
	rtsock->stream.tcp_handle = rtsock;

	int err = replicast_tcp_accept(robj, rtsock);
	if (err)
		return;

	int namelen;
	if (robj->ipv4) {
		namelen = sizeof(struct sockaddr_in);
		err = uv_tcp_getpeername(&rtsock->tchandle,
		    (struct sockaddr *)&rtsock->toaddr, &namelen);
		memcpy(&rtsock->fromaddr, &robj->server_addr,
		    sizeof(struct sockaddr_in));
	} else {
		namelen = sizeof(struct sockaddr_in6);
		err = uv_tcp_getpeername(&rtsock->tchandle,
		    (struct sockaddr *)&rtsock->toaddr, &namelen);
		memcpy(&rtsock->fromaddr, &robj->recv_addr,
		    sizeof(struct sockaddr_in6));
	}

	if (err) {
		log_error(lg, "Replicast(%s): Failed to get peername", robj->name);
		rtsock_shutdown(rtsock);
		return;
	}

	rtsock_log_addr(rtsock);
	log_info(lg, "Replicast(%s): Connection accepted.", robj->name);
	QUEUE_INSERT_TAIL(&robj->rtsock_queue, &rtsock->item);
}

struct replicast *
replicast_init_tcp_server(const char *name, uv_loop_t *loop,
    const char *addr, const uint16_t port, int domain,
    int scopeid, uint32_t ifspeed, const int ttl, void *data)
{
	struct replicast *robj = je_calloc(1, sizeof (*robj));
	if (!robj) {
		log_error(lg, "Cannot allocate memory for replicast");
		return NULL;
	}

	robj->loop = loop;
	robj->priv_data = data;
	snprintf(robj->name, REPLICAST_NAME_MAXSIZE, "%s", name);
	robj->sequence_cnt = 1;
	robj->mc_ttl = ttl;
	robj->ipv4 = domain == AF_INET;
	QUEUE_INIT(&robj->rtsock_queue);

	uv_tcp_t *handle = &robj->recv_tcp_socket;
	handle->data = robj;

	int tcp_sock = -1;
	int err = replicast_tcp_socket_init(handle, &tcp_sock, robj->loop, domain);
	if (err) {
		je_free(robj);
		log_error(lg, "Cannot initialize TCP recv socket: %d, %s.%d", err, addr, port);
		return NULL;
	}

	robj->tcp_recv_port = port;

	if (domain == AF_INET) {
		robj->server_addr = uv_ip4_addr(addr, port);
		err = uv_tcp_bind(handle, robj->server_addr);
	} else {
		robj->recv_addr = uv_ip6_addr(addr, port);
		robj->recv_addr.sin6_scope_id = scopeid;
		err = uv_tcp_bind6(handle, robj->recv_addr);
	}

	if (err) {
		log_warn(lg, "Failed to bind to socket %s.%d", addr, port);
		replicast_tcp_socket_close(handle);
		return NULL;
	}

	int no = 0;
	err = setsockopt(handle->io_watcher.fd, SOL_SOCKET, SO_REUSEADDR,
		&no, sizeof (no));
	if (err)
		log_debug(lg, "Failed to set SO_REUSEADDR %d, %s.%d", err, addr, port);

	err = uv_listen((uv_stream_t*)handle, SOMAXCONN, replicast_tcp_serve);
	if (err) {
		log_error(lg, "Cannot listen over TCP socket: %d, %s.%d", err, addr, port);
		replicast_tcp_socket_close(handle);
		return NULL;
	}

	log_info(lg, "Replicast(%s) listens on TCP %s.%d, scope_id=%d",
	    name, addr, port, scopeid);

	return robj;
}

void
replicast_destroy_tcp_server(struct replicast *robj)
{
	QUEUE *q;
	rt_tcp_t *rtsock;

	while (!QUEUE_EMPTY(&robj->rtsock_queue)) {
		q = QUEUE_NEXT(&robj->rtsock_queue);
		rtsock = QUEUE_DATA(q, rt_tcp_t, item);
		rtsock_shutdown(rtsock);
	}

	uv_read_stop((uv_stream_t *)&robj->recv_tcp_socket);
	replicast_tcp_socket_close(&robj->recv_tcp_socket);
}

int
replicast_tcp_send2(struct replicast *robj, struct repctx *ctx,
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    struct repmsg_generic *omsg, const uv_buf_t bufs[], unsigned int nbufs,
    replicast_send_cb cb, void *cb_data)
{
	if (ctx->tcp_handle == NULL) {
		if (QUEUE_EMPTY(&robj->rtsock_queue)) {
			log_error(lg, "Socket queue empty");
			return -EIO;
		}
		QUEUE *q = QUEUE_NEXT(&robj->rtsock_queue);
		ctx->tcp_handle = QUEUE_DATA(q, rt_tcp_t, item);
	} else {
		/* Make sure the connection is still alive */
		QUEUE* q = NULL, *tmp_q = NULL;
		int found = 0;
		QUEUE_FOREACH_SAFE(q,tmp_q,&robj->rtsock_queue) {
			if (ctx->tcp_handle == QUEUE_DATA(q, rt_tcp_t, item)) {
				found = 1;
				break;
			}
		}
		if (!found) {
			log_error(lg, "Socket must be closed");
			return -EIO;
		}
	}

	ctx->attributes = RD_ATTR_UNICAST_TCP;
	msg->hdr.attributes |= RD_ATTR_UNICAST_TCP;
	msg->hdr.data_len = 0;

	for (uint32_t i = 0; i < nbufs; i++)
		msg->hdr.data_len += bufs[i].len;

	struct sockaddr_in6 unused;
	return replicast_send(robj, ctx, opcode, msg, omsg, bufs, nbufs,
		&unused, cb, cb_data, NULL);
}

static void
replicast_client_connect_cb(uv_connect_t *req, int status)
{
	rt_tcp_t *rtsock = req->data;
	struct replicast *robj = rtsock->robj;

	if (status) {
		log_warn(lg, "Replicast(%s): Failed to connect", robj->name);
		rtsock->cbctx.cb(rtsock->cbctx.cb_data, status);
		rtsock_close(rtsock);
		return;
	}

	QUEUE_INSERT_TAIL(&robj->rtsock_queue, &rtsock->item);

	int err, namelen;
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
		log_error(lg, "Failed to get local address");
	}

	uv_stream_t *cstream = (uv_stream_t *)&rtsock->tchandle;

	err = uv_read_start(cstream, alloc_buffer, replicast_tcp_read);
	if (err) {
		log_error(lg, "Failed to read from client");
		rtsock->cbctx.cb(rtsock->cbctx.cb_data, err);
		return;
	}

	rtsock_log_addr(rtsock);
	log_info(lg, "Replicast(%s): Client connected.", robj->name);
	rtsock->cbctx.cb(rtsock->cbctx.cb_data, status);
}

int
replicast_tcp_connect2(struct replicast_broker *rbroker,
    const char *addr, const uint16_t port, int domain, int scopeid,
    rt_connect_cb cb, void *cb_data)
{
	rt_tcp_t *rtsock;
	struct replicast *robj = rbroker->robj;

	if (!QUEUE_EMPTY(&robj->rtsock_queue)) {
		QUEUE *q = QUEUE_NEXT(&robj->rtsock_queue);
		rtsock = QUEUE_DATA(q, rt_tcp_t, item);
		rtsock_log_addr(rtsock);
		log_debug(lg, "Replicast(%s): Already connected.", robj->name);
		return -EEXIST;
	}

	rtsock = je_calloc(1, sizeof(*rtsock));
	if (rtsock == NULL) {
		log_error(lg, "Failed to allocate rtsock");
		return -ENOMEM;
	}

	int err = uv_tcp_init(robj->loop, &rtsock->tchandle);
	if (err) {
		log_error(lg, "Failed to initialize tcp");
		je_free(rtsock);
		return err;
	}

	rtsock->robj = robj;
	rtsock->tchandle.data = rtsock;
	QUEUE_INIT(&rtsock->item);
	rt_tcp_stream_init(&rtsock->stream);
	rtsock->stream.robj = robj;
	rtsock->stream.tcp_handle = rtsock;
	rtsock->cbctx.cb = cb;
	rtsock->cbctx.cb_data = cb_data;
	rtsock->connect_req.data = rtsock;

	if (robj->ipv4) {
		struct sockaddr_in p;
		p = uv_ip4_addr(addr, port);
		memcpy(&rtsock->toaddr, &p, sizeof(p));
		err = uv_tcp_connect(&rtsock->connect_req, &rtsock->tchandle,
			p, replicast_client_connect_cb);
	} else {
		struct sockaddr_in6 q;
		q = uv_ip6_addr(addr, port);
		q.sin6_scope_id = scopeid;
		memcpy(&rtsock->toaddr, &q, sizeof(q));
		err = uv_tcp_connect6(&rtsock->connect_req, &rtsock->tchandle,
			q, replicast_client_connect_cb);
	}

	if (err) {
		log_error(lg, "Replicast(%s): Failed to connect", robj->name);
		je_free(rtsock);
		return err;
	}

	return 0;
}

struct replicast *
replicast_init_tcp_client(const char *name, uv_loop_t *loop,
    int domain, const int ttl, void *data)
{
	struct replicast *robj = je_calloc(1, sizeof (*robj));
	if (!robj) {
		log_error(lg, "Cannot allocate memory for replicast");
		return NULL;
	}

	robj->loop = loop;
	robj->priv_data = data;
	snprintf(robj->name, REPLICAST_NAME_MAXSIZE, "%s", name);
	robj->sequence_cnt = 1;
	robj->mc_ttl = ttl;
	robj->ipv4 = domain == AF_INET;
	QUEUE_INIT(&robj->rtsock_queue);

	return robj;
}

void
replicast_destroy_tcp_client(struct replicast *robj)
{
	rt_tcp_t *rtsock;
	QUEUE *q;

	if (!QUEUE_EMPTY(&robj->rtsock_queue)) {
		q = QUEUE_NEXT(&robj->rtsock_queue);
		rtsock = QUEUE_DATA(q, rt_tcp_t, item);
		rtsock_shutdown(rtsock);
	}
}

