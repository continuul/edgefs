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

#include "rt_tcp.h"

static void
stream_term(struct state *st)
{
	rt_stream_t *stream = st->data;

	log_debug(lg, "terminating stream %p st: %p", stream, st);
	/* Finalize the buffers */
	rt_tcp_sbuf_fini(&stream->pbuf);
	rt_tcp_sbuf_fini(&stream->nbuf);
}

static void
stream_error(struct state *st)
{
	log_debug(lg, "stream error stream: %p st: %p", st->data, st);
}

static void
stream_decode(struct state *st)
{
	rt_stream_t *stream = st->data;
	size_t rt_msg_sz;
	size_t total_msg_sz; /* rt_msg_sz + sizeof(unint32_t) */
	rt_tcp_header_t tcp_hdr;
	size_t tcp_hdr_sz = sizeof(tcp_hdr);

	log_debug(lg, "st: %p begin decode cursor len: %lu",
		  st, stream->pbuf.cursor_len);

	/* Check if enough bytes are present to interpret RT TCP header */
	if (stream->pbuf.cursor_len < tcp_hdr_sz) {
		stream->wait = 1;
		return;
	}

	/*
	 * TODO: Ideal unpacking should take iterator.
	 *       Iterator will have ability to go through array or list
	 *       or queue of uv_buf_t.
	 */
	stream->wait = 0;
	/*
	 * We do not advance cursor until we are sure we are not going to enter
	 * wait state (until full message can be decoded).
	 */
	tcp_hdr.tcp_magic = ntohl(*(uint32_t *)stream->pbuf.cursor);
	tcp_hdr.msg_len = ntohl(*(uint32_t *)(stream->pbuf.cursor +
					      sizeof(uint32_t)));
	if (tcp_hdr.tcp_magic != RT_TCP_MAGIC) {
		log_notice(lg, "Corrupt RT TCP header - dropping packet");
		rt_tcp_sbuf_fini(&stream->pbuf);
		stream->error = -EINVAL;
		return;
	}

	/* Check if enough bytes are present to interpret RT message header */
	if (stream->pbuf.cursor_len < tcp_hdr.msg_len + tcp_hdr_sz) {
		stream->wait = 1;
		return;
	}
	msgpack_u *u = msgpack_unpack_init(stream->pbuf.cursor + tcp_hdr_sz,
					   stream->pbuf.cursor_len, 0);

	stream->error = u ?  replicast_unpack_datagram_hdr(u, &stream->hdr) :
			-ENOMEM;
	if (stream->error != 0) {
		log_notice(lg, "Could not decode RT header: %d", stream->error);
		rt_tcp_sbuf_fini(&stream->pbuf);
		return;
	}
	msgpack_unpack_free(u);
	rt_msg_sz = tcp_hdr.msg_len + stream->hdr.data_len;
	total_msg_sz = rt_msg_sz + tcp_hdr_sz;
	assert(stream->hdr.attributes & RD_ATTR_UNICAST_TCP);

	/* Check if enough bytes are present for entire RT message */
	if (stream->pbuf.cursor_len < total_msg_sz) {
		stream->wait = 1;
		return;
	}

	/* Reserve space for decoding repmsg */
	size_t msglen = rt_msg_sz + sizeof(struct repmsg);
	char *msg = je_malloc(msglen);
	if (msg == NULL) {
		log_notice(lg, "Failed to allocate memory for "
				"message processing");
		stream->error = -ENOMEM;
		return;
	}
	memcpy(msg, stream->pbuf.cursor + tcp_hdr_sz, rt_msg_sz);
	/* buf-len = msg + data + repmsg */
	uv_buf_t msgbuf = uv_buf_init(msg, msglen);
	replicast_process_recv(stream->robj, msgbuf,
				rt_msg_sz, "",
				stream->tcp_handle, NULL);
	rt_tcp_sbuf_mv_cursor(&stream->pbuf, total_msg_sz);
	if (stream->pbuf.cursor_len == 0) {
		rt_tcp_sbuf_fini(&stream->pbuf);
		stream->wait = 1;
	} else {
		log_debug(lg, "st: %p bytes left in cursor: %lu",
			  st, stream->pbuf.cursor_len);
	}
}

static void
stream_update(struct state *st)
{
	rt_stream_t *stream = st->data;
	stream_buf_t *pbuf;
	char *newb;
	size_t bufsz;
	int ret;

	log_debug(lg, "st: %p pstream: %p old buf len: %lu new buf len: %lu",
			st, stream, stream->pbuf.cursor_len,
			stream->nbuf.cursor_len);
	stream->wait = 0;
	bufsz = stream->nbuf.cursor_len + stream->pbuf.cursor_len;
	newb = je_malloc(bufsz);
	if (newb != NULL) {
		stream_buf_t ubuf; /* update buffer */
		uv_buf_t nuv_buf;

		nuv_buf = uv_buf_init(newb, bufsz);
		/*
		 * Cursor length is valid data length.
		 * New buffer has no useful data. Hence cursor length is 0.
		 */
		rt_tcp_sbuf_init(&ubuf, nuv_buf, 0);

		/* Retain old data */
		if (stream->pbuf.cursor_len != 0) {
			ret = rt_tcp_sbuf_copy(&ubuf, &stream->pbuf);
			assert(ret == 0);
		}

		/* Copy new tcp data */
		ret = rt_tcp_sbuf_copy(&ubuf, &stream->nbuf);
		assert(ret == 0);

		/* Finalize old buffers */
		rt_tcp_sbuf_fini(&stream->pbuf);
		rt_tcp_sbuf_fini(&stream->nbuf);

		/* Update stream process buffer */
		stream->pbuf = ubuf;

		log_debug(lg, "After update cursor len: %lu",
				stream->pbuf.cursor_len);
	} else {
		log_notice(lg, "Failed to allocate memory for TCP stream buffer");
		stream->error = -ENOMEM;
		/* Finalize the buffers. RT protocol will timeout */
		rt_tcp_sbuf_fini(&stream->pbuf);
		rt_tcp_sbuf_fini(&stream->nbuf);
	}
}

static const struct transition str_trans_tbl[] = {
	/* State, Event, Action, Next State, condition evaluation */
	{ ST_INIT, RT_STREAM_UPDATED, &stream_update, ST_READY, NULL },
	{ ST_WAIT, RT_STREAM_UPDATED, &stream_update, ST_READY, NULL },
	{ ST_READY, RT_STREAM_DECODE, &stream_decode, ST_READY, NULL },
	{ ST_READY, RT_STREAM_DECODE_WAIT, NULL, ST_WAIT, NULL },
	{ ST_READY, EV_ERR, &stream_error, ST_TERM, NULL },
	{ ST_ANY, EV_DONE, NULL, ST_TERM, NULL }
};

void
rt_tcp_stream_init(rt_stream_t *pstream)
{
	log_debug(lg, "stream: %p", pstream);
	/* Initialize state machine for TCP stream processing */
	state_init(&pstream->st, str_trans_tbl,
		   sizeof(str_trans_tbl)/sizeof(*str_trans_tbl),
		   pstream, stream_term);
}
