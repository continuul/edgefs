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
#ifndef __RT_TCP_H__
#define __RT_TCP_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <uv.h>
#include "replicast.h"

#define RT_TCP_MAGIC	0xCAFEFEED

/*
 * These events are used to process incoming TCP stream.
 * Sometimes events and decode phases will be used interchangeably.
 */
enum replicast_decode_event {
	RT_STREAM_UPDATED = 1,
	RT_STREAM_DECODE_WAIT,
	RT_STREAM_DECODE,
};

enum rt_tcp_state {
	RT_TCP_IN_PROGRESS = 1,
	RT_TCP_CONNECTED,
	RT_TCP_FAILED,
};

typedef struct {
	uint32_t tcp_magic;	/* Magic number for RT TCP messages */
	uint32_t msg_len;	/* RT message length */
}rt_tcp_header_t;

typedef struct {
	uv_buf_t ubuf;
	char	 *cursor;	/* Cursor in the buffer */
	size_t	 cursor_len;	/* Bytes available in the cursor - valid data */
} stream_buf_t;

typedef void (*rt_connect_cb)(void *, int);

typedef struct {
	rt_connect_cb		cb;
	void			*cb_data;
}rt_cbctx_t;

typedef struct replicast_tcp_stream {
	struct state st;	/* Stream state machine */
	struct replicast *robj; /* Replicast object for this stream */
	stream_buf_t pbuf;	/* This buffer is processed */
	stream_buf_t nbuf;	/* Received buf from libuv */
				/* RT header - after decoding */
	struct replicast_datagram_hdr hdr;
				/* TCP handle for this stream */
	rt_tcp_t	*tcp_handle;
	int error;		/* error at any decoding stage */
	uint8_t wait;		/* Wait flag for decoding */
} rt_stream_t;

typedef struct rt_tcp_s {
	uv_tcp_t		tchandle;	/* TCP Connection handle */
	uv_connect_t		connect_req;
	uv_mutex_t		conn_lock;	/* Lock to protect state */
	enum rt_tcp_state	state;
	struct replicast	*robj;
	struct sockaddr_storage	fromaddr;
	struct sockaddr_storage	toaddr;
	struct rt_tcp_s		*next;
	lfqueue_t		cb_lfq;		/* Queue of callbacks */
	uint8_t			term;
	uv_shutdown_t		sreq;
	QUEUE			item;
	rt_stream_t		stream;
	rt_cbctx_t		cbctx;
}rt_tcp_t;

void rt_tcp_stream_init(rt_stream_t *pstream);

static inline void
rt_tcp_sbuf_init(stream_buf_t *sbuf, uv_buf_t buf, size_t cur_len)
{
	sbuf->ubuf = buf;
	sbuf->cursor = buf.base;
	sbuf->cursor_len = cur_len;
}

static inline void
rt_tcp_sbuf_fini(stream_buf_t *sbuf)
{
	if (sbuf->ubuf.base)
		je_free(sbuf->ubuf.base);
	sbuf->cursor = sbuf->ubuf.base = NULL;
	sbuf->cursor_len = sbuf->ubuf.len = 0;
}

static inline int
rt_tcp_sbuf_copy(stream_buf_t *dest, stream_buf_t *src)
{
	assert(dest->ubuf.len >= dest->cursor_len);
	size_t rem = dest->ubuf.len - dest->cursor_len;

	if (rem > 0 && src->cursor_len <= rem) {
		memcpy(dest->cursor + dest->cursor_len, src->cursor,
			src->cursor_len);
		dest->cursor_len += src->cursor_len;
		return 0;
	}
	return -ENOSPC;
}

static inline void
rt_tcp_sbuf_mv_cursor(stream_buf_t *buf, size_t move_by)
{
	buf->cursor += move_by;
	buf->cursor_len -= move_by;
}

#ifdef  __cplusplus
}
#endif

#endif
