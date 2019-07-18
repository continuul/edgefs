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

static void
hashuncomp_done(void *arg, int status)
{
	struct hashuncomp *ch = arg;

	if (status)
		ch->status = status;

	/* call callback */
	ch->cb(ch->arg, ch->status);
	je_free(ch);
}

static int
hashuncomp_payloadhash(crypto_hash_t hash_type, uv_buf_t *buf,
    int nbufs, uint512_t *chid)
{
	int err = 0;

	if (!buf || !chid)
		return -EBADF;

	crypto_state_t S;
	err = crypto_init_with_type(&S, hash_type);
	if (err) {
		log_error(lg, "crypto_init: payload buffer err=%d", err);
		return err;
	}
	for (int i = 0; i < nbufs; i++) {
		err = crypto_update(&S, (uint8_t *) buf[i].base, buf[i].len);
		if (err) {
			log_error(lg, "crypto_update: payload buffer %d", err);
			return err;
		}
	}
	err = crypto_final(&S, (uint8_t *) chid);
	if (err) {
		log_error(lg, "crypto_final: payload buffer %d", err);
		return err;
	}

	return err;
}

void
hashuncomp_one(struct hashuncomp *ch)
{
	int err = 0;
	struct ccow_op *op = ch->op;
	struct ccow_completion *comp = op->comp;
	struct ccow *tc = comp->tc;
	uv_buf_t *chunk = ch->chunk;
	zfast_stream stream;
	zfast_stream_state state;

	/*
	 * The received data can have delayed hashing verification enabled
	 * by the tenant configuration, as there is already a CRC32 on the line.
	 */
	if (ch->verify_chid &&
		!(op->namedget_io->attributes & RD_ATTR_COMPOUND) &&
		!ch->rb_cached) {
		uint512_t chid;
		err = hashuncomp_payloadhash(ch->hash_type, ch->data_in,
		    ch->nbufs, &chid);
		if (err) {
			log_error(lg, "Error Hashing: %d", err);
			ch->status = err;
			return;
		}

		if (uint512_cmp(&chid, ch->chid_in) != 0) {
			ch->status = -EIO;
			log_warn(lg, "Chunk fingerprint verification error: %d",
			    ch->status);
			uint512_logdump(lg, "Calculated CHID: ", &chid);
			uint512_logdump(lg, "Expected CHID: ", ch->chid_in);
			return;
		}
	}

	if (!ch->rb_cached) {
		/* add chunk to ucache now */
		ccow_ucache_put(tc->ucache, ch->chid_in, &ch->data_in[0],
		    ch->nbufs);
	}

	/*
	 * Init the compression algorithms based on chunk's compress_type
	 */
	memset(&stream, 0, sizeof(stream));
	err = fastlzlibDecompressInit(&stream, &state);
        if (err) {
		log_error(lg, "Error in compress init: %d", err);
		ch->status = err;
		return;
	}

	err = fastlzlibSetCompressor(&stream, ch->compress_type);
        if (err) {
		log_error(lg, "Error in compress method %d set: %d",
		    ch->compress_type, err);
		ch->status = err;
		return;
	}

	/* decompress data_in */
	int have = 0;
	for (int i = 0; i < ch->nbufs; i++) {

		int is_eof = (i == ch->nbufs - 1);
		int success;
		stream.next_in = (uint8_t *)ch->data_in[i].base;
		stream.avail_in = ch->data_in[i].len;
		do {
			stream.next_out = (uint8_t *)chunk->base + have;
			int left = chunk->len - have;
			stream.avail_out = left;

			success = fastlzlibDecompress(&stream);

			have += left - stream.avail_out;

			if (success == Z_STREAM_END) {
				if (stream.avail_in > 0 || !is_eof) {
					ch->status = -EPIPE;
					log_error(lg, "Error Uncompresssing: "
					    "premature EOF before end of stream: %d",
					    ch->status);
					return;
				}
			}

		} while (success == Z_OK && stream.avail_in > 0);

		/* Z_BUF_ERROR means that we need to feed more */
		if (success == Z_BUF_ERROR) {
			if (is_eof && stream.avail_out != 0) {
				ch->status = -EFBIG;
				log_error(lg, "Error Uncompresssing: "
				    "premature end of stream: %d",
				    ch->status);
				return;
			}
			continue;
		}

		/* other stream error */
		if (success < 0) {
			ch->status = success;
			log_error(lg, "Error Uncompresssing: %d", ch->status);
			return;
		}
	}

	fastlzlibEnd(&stream);
	return;
}

static void
hashuncomp_exec(void *arg)
{
	struct hashuncomp *ch = arg;
	hashuncomp_one(ch);
}

/*
 * Find the destination chunk by the offset supplied
 */
ssize_t
hashuncomp_find_idx(rtbuf_t *chunks, uint64_t start_offset, uint64_t offset)
{
	size_t i = 0;
	uint64_t off = start_offset;

	if (!chunks) {
		log_error(lg, "!! Received NULL chunks to uncompress !!");
		assert(chunks);
		return -1;
	}

	do {
		if (off == offset)
			break;
		off += rtbuf(chunks, i).len;
	} while (++i < chunks->nbufs);

	if (i == chunks->nbufs) {
		/* can be an assert here */
		int err = -ENOENT;
		log_error(lg, "Error queueing hashuncomp work: %d", err);
		return err;
	}
	return i;
}

/*
 * @hashuncomp_compute
 *
 * Driver to do fingerprinting & decompression of incoming chunk
 *
 * Scope: PRIVATE
 */
int
ccow_hashuncomp_compute(struct ccow_op *op, hashuncomp_cb_t cb, void *arg,
    rtbuf_t *payload, uint512_t *chid_in, uint64_t offset, uint8_t hash_type,
    uint8_t compress_type, int rb_cached)
{
	int err;
	struct ccow_completion *c = op->comp;
	struct ccow *tc = c->tc;
	rtbuf_t *chunks = op->chunks;

	log_trace(lg, "op %p, cb %p, arg %p, payload %p, chid_in %p, "
	    "offset 0x%" PRIx64, op, cb, arg, payload, chid_in, op->offset);

	/* find the destination chunk by the offset supplied */
	ssize_t i = hashuncomp_find_idx(chunks, op->offset, offset);
	if (i < 0) {
		err = i;
		return err;
	}

	struct hashuncomp *ch = je_calloc(1, sizeof (struct hashuncomp));
	if (!ch) {
		err = -ENOMEM;
		log_error(lg, "Error queueing hashuncomp work: %d", err);
		return err;
	}

	ch->chunk = &rtbuf(chunks, i);
	ch->data_in = &rtbuf(payload, 0);
	ch->nbufs = payload->nbufs;
	ch->chid_in = chid_in;
	ch->compress_type = compress_type;
	ch->op = op;
	ch->cb = cb;
	ch->arg = arg;
	ch->verify_chid = tc->verify_chid;
	ch->hash_type = hash_type;
	ch->rb_cached = rb_cached;

	ccowtp_work_queue(tc->tp, 0, hashuncomp_exec, hashuncomp_done, ch);

	return 0;
}
