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
#include <uv.h>

#include "ccowutil.h"
#include "fastlzlib.h"
#include "crypto.h"
#include "ccow.h"
#include "ccow-impl.h"

static int ccow_comphash_batch(struct ccow_op *op, comphash_cb_t cb, void *arg);

/*
 * Cancellation functionality to dequeue any existing wqe's after any
 * failure
 */
void
ccow_comphash_cancel(struct ccow_op *op)
{
	QUEUE *q;

	QUEUE_FOREACH(q, &op->comphash_queue) {
		struct comphash *e = QUEUE_DATA(q, struct comphash, item);
		e->status = -100;
		ccowtp_cancel(op->comp->tc->tp, e);
	}
}

static void
comphash_done(void *arg, int status)
{
	struct comphash *ch = arg;
	struct ccow_op *op = ch->op;

	QUEUE_REMOVE(&ch->item);

	/*
	 * Because comphash is an aggregate of multi-chunk tasks we have
	 * to use op->status to hold an aggregate result.
	 */
	if (status)
		op->status = status;
	else if (ch->status)
		op->status = ch->status;

	op->comphash_completed++;

	if (op->comphash_completed < op->iovcnt_in) {
		if (op->status && op->status != -100) {
			ccow_comphash_cancel(op);
		} else if (ccow_comphash_batch(op, ch->cb, ch->arg) != 0) {
			ccow_comphash_cancel(op);
		}
		/* wait for others to complete */
		je_free(ch);
		return;
	}

	/*
	 * callback
	 */
	ch->cb(ch->arg, op->status);

	je_free(ch);
}

/*
 * Init the compression library, compress the data, then process the
 * hash on the compressed data.  Returns the data compressed in the chunk
 * and the chid of the data to the pre-allocated chid pool.
 */
void
comphash_one(struct comphash *ch)
{
	int err = 0;
	struct ccow_op *op = ch->op;
	struct ccow_completion *comp = op->comp;
	struct ccow *tc = comp->tc;
	zfast_stream stream;
	zfast_stream_state state;
	struct ccow_io* io = (struct ccow_io*)ch->arg;

	if (io && (io->attributes & RD_ATTR_NCOMP)) {
		uv_buf_t *chunk = &rtbuf(op->chunks, ch->idx);
		chunk->base = je_malloc(ch->iov_in->iov_len);
		if (!chunk->base) {
			ch->status = -ENOMEM;
			log_error(lg, "Error in compression out alloc: %d", ch->status);
			return;
		}
		memcpy(chunk->base, ch->iov_in->iov_base, ch->iov_in->iov_len);
		chunk->len = ch->iov_in->iov_len;
		/* Reset Mapped Flag to the selected comp type */
		rtbuf_attr(op->chunks, ch->idx) &= ~RTBUF_ATTR_MMAP;
		RTBUF_ATTR_COMP_TYPE_SET(rtbuf_attr(op->chunks, ch->idx), COMPRESSOR_NUL);
		return;
	}

	/*
	 * Init the compression algorithms based on ccow_completion context.
	 * If however chunk length is smaller then threshold then fall back
	 * to NUL (i.e. memcpy) method.
	 */
	int method = ch->iov_in->iov_len < COMPRESS_LOW_WATERMARK ?
	    COMPRESSOR_NUL : comp->compress_type;

_restart:
	memset(&stream, 0, sizeof(stream));

	err = fastlzlibCompressInit(&stream, &state);
        if (err) {
		log_error(lg, "Error in compress init: %d", err);
		ch->status = err;
		return;
	}

	err = fastlzlibSetCompressor(&stream, method);
        if (err) {
		log_error(lg, "Error in compress set method: %d", err);
		ch->status = err;
		return;
	}

	/*
	 *  Compress the incoming iovec, the outgoing iovec chunk must
	 *  be pre-allocated to fit the compressed data, it will be
	 *  preallocated with the same size as the input iovec.
	 */
	uv_buf_t *chunk = &rtbuf(op->chunks, ch->idx);
	chunk->base = je_malloc(ch->iov_in->iov_len + COMPRESSOR_NUL_HEADLEN);
	if (!chunk->base) {
		ch->status = -ENOMEM;
		log_error(lg, "Error in compression out alloc: %d", ch->status);
		return;
	}

	int have = 0, success;
	stream.next_in = ch->iov_in->iov_base;
	stream.avail_in = ch->iov_in->iov_len;
	do {
		stream.next_out = (uint8_t *)chunk->base + have;
		int left = (ch->iov_in->iov_len + COMPRESSOR_NUL_HEADLEN) - have;
		stream.avail_out = left;

		success = fastlzlibCompress(&stream, Z_FINISH);

		have += left - stream.avail_out;

		if (success == Z_STREAM_END) {
			/* premature EOF before end of stream */
			if (stream.avail_in > 0) {
				ch->status = -ENFILE;
				log_error(lg, "Compression error: method: %d "
				    "ret: %d", method, ch->status);
				je_free(chunk->base);
				return;
			}
		}
	} while (success == Z_OK);

	/* Z_BUF_ERROR means that we need to feed more, yet this is impossible
	 * case because we have whole chunk being passed to us from a user */
	if (success == Z_BUF_ERROR) {
		/* premature end of stream */
		if (stream.avail_out != 0) {
			ch->status = -EFBIG;
			log_error(lg, "Compression error: method: %d ret: %d",
			    method, ch->status);
			je_free(chunk->base);
			return;
		}
	}

	/* other stream error */
	if (success < 0) {
		ch->status = success;
		log_error(lg, "Compression error: method: %d ret: %d",
		    method, ch->status);
		je_free(chunk->base);
		return;
	}

	fastlzlibEnd(&stream);

	if (method != COMPRESSOR_NUL && stream.total_out > ch->iov_in->iov_len) {
		method = COMPRESSOR_NUL;
		je_free(chunk->base);
		chunk->base = NULL;
		goto _restart;
	}

	/* save compressed size */
	chunk->len = stream.total_out;

	log_debug(lg, "ch->idx = %d method = %d iovlen %ld csize %ld", ch->idx,
	    method, ch->iov_in->iov_len, chunk->len);

	/*
	 * Compute the hash of the compressed data and return in the
	 * pre-allocated CHID pool supplied by the user buffers.
	 */
	uint512_t *chid = &op->chids[ch->idx];
	if (ch->idx > 0 || !(op->namedget_io && op->namedget_io->attributes & RD_ATTR_COMPOUND)) {
		err = crypto_hash_with_type((crypto_hash_t)comp->hash_type,
			(uint8_t *)chunk->base, chunk->len, (uint8_t *)chid);
		if (err) {
			log_error(lg, "Error Hashing : %d ", err);
			je_free(chunk->base);
			ch->status = err;
			return;
		}

		/* add chunk to ucache now */
		ccow_ucache_put(tc->ucache, chid, chunk, 1);
	}

	/* Reset Mapped Flag to the selected comp type */
	rtbuf_attr(op->chunks, ch->idx) &= ~RTBUF_ATTR_MMAP;
	RTBUF_ATTR_COMP_TYPE_SET(rtbuf_attr(op->chunks, ch->idx), method);

	return;
}

static void
comphash_exec(void *arg)
{
	int err = 0;
	struct comphash *ch = arg;
	comphash_one(ch);
}

/*
 * this function will post any remaining (i.e. not yet posted) requests.
 */
static int
ccow_comphash_batch(struct ccow_op *op, comphash_cb_t cb, void *arg)
{
	int err;
	struct ccow_completion *c = op->comp;
	struct ccow *tc = c->tc;
	struct iovec *iov_in = op->iov_in;
	size_t iovcnt_in = op->iovcnt_in;

	log_trace(lg, "op %p, cb %p, arg %p", op, cb, arg);

	while ((op->comphash_idx - op->comphash_completed < tc->comphash_bulk_max) &&
	       (op->comphash_idx < op->iovcnt_in)) {

		struct comphash *ch = je_calloc(1, sizeof (struct comphash));
		if (!ch) {
			if (op->comphash_idx > 0) {
				ccow_comphash_cancel(op);
				return 0;
			}
			return -ENOMEM;
		}

		ch->idx = op->comphash_idx;
		ch->op = op;
		ch->iov_in = &iov_in[op->comphash_idx];
		ch->cb = cb;
		ch->arg = arg;
		QUEUE_INIT(&ch->item);
		QUEUE_INSERT_TAIL(&op->comphash_queue, &ch->item);

		ccowtp_work_queue(tc->tp, 0, comphash_exec, comphash_done, ch);

		op->comphash_idx++;
	}

	return 0;
}

/*
 * @comphash_compute
 * driver for the parallel computation of the compressed data and hash algthms.
 * User supplies pre-allocated :
 * 1. iovecs :  iov_in + chid pool
 *
 * Scope: PRIVATE
 */
int
ccow_comphash_compute(struct ccow_op *op, comphash_cb_t cb, void *arg)
{
	log_trace(lg, "op %p, cb %p, arg %p", op, cb, arg);

	QUEUE_INIT(&op->comphash_queue);
	op->comphash_idx = 0;
	op->comphash_completed = 0;

	return ccow_comphash_batch(op, cb, arg);
}
