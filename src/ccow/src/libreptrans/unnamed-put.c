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
#include <fastlzlib.h>
#include <sys/param.h>
#include "reptrans.h"
#include "ccowd-impl.h"
#include "state.h"
#include "putcommon_server.h"

#include "ccow-impl.h"
#include "ccow.h"
#include "vmm_cache.h"
#include "erasure-coding.h"
#include "reptrans-flex.h"

#define UNCOMP_ALLOC_SIZE	(512*1024)
#define PP_WEIGHT_PAUSE		32
#define PP_WEIGHT_PAUSE_MS	64
#define PP_FLUSH_DELAY_MS	5

static int
hashuncomp_compound(const rtbuf_t* in_buf, uv_buf_t* out_buf, uint8_t comp_type)
{
	int err = 0;
	zfast_stream stream;
	zfast_stream_state state;

	out_buf->base = je_malloc(UNCOMP_ALLOC_SIZE);
	if (!out_buf->base) {
		return -ENOMEM;
	}
	out_buf->len = UNCOMP_ALLOC_SIZE;

	/*
	 * Init the compression algorithms based on compress_type
	 */
	memset(&stream, 0, sizeof(stream));
	err = fastlzlibDecompressInit(&stream, &state);
        if (err) {
		log_error(lg, "Error in compress init: %d", err);
		return err;
	}

	err = fastlzlibSetCompressor(&stream, comp_type);
        if (err) {
		log_error(lg, "Error in compress method %d set: %d",
				comp_type, err);
		return err;
	}

	/* decompress in_buf */
	int have = 0;
	for (size_t i = 0; i < in_buf->nbufs; i++) {

		int is_eof = (i == in_buf->nbufs - 1);
		int success;
		stream.next_in = (uint8_t *)in_buf->bufs[i].base;
		stream.avail_in = in_buf->bufs[i].len;
		do {
			int left = out_buf->len - have;
			if (left <= 0) {
				char* prev_base = out_buf->base;
				size_t prev_len = out_buf->len;
				out_buf->len *= 2;
				out_buf->base = je_calloc(1, out_buf->len);
				if (!out_buf->base) {
					je_free(prev_base);
					return -ENOMEM;
				}
				memcpy(out_buf->base, prev_base, prev_len);
				je_free(prev_base);
				left = out_buf->len - have;
			}
			stream.next_out = (uint8_t *)out_buf->base + have;
			stream.avail_out = left;

			success = fastlzlibDecompress(&stream);

			have += left - stream.avail_out;

			if (success == Z_BUF_ERROR && stream.avail_out == 0) {
				continue;
			}

			if (success == Z_STREAM_END) {
				if (stream.avail_in > 0 || !is_eof) {
					log_error(lg, "Error Uncompresssing: "
						"premature EOF before end of stream");
					return -EPIPE;
				}
			}
		} while (success == Z_OK && stream.avail_in > 0);

		/* Z_BUF_ERROR means that we need to feed more */
		if (success == Z_BUF_ERROR) {
			if (is_eof && stream.avail_out != 0) {
				log_error(lg, "Error Uncompresssing: "
					"premature end of stream");
				return -EFBIG;
			}
			continue;
		}

		/* other stream error */
		if (success < 0) {
			log_error(lg, "Error Uncompresssing: %d", success);
			return success;
		}
	}

	fastlzlibEnd(&stream);

	if(out_buf->len > (size_t)have)
		out_buf->len = have;
	return 0;
}


static void
unnamedput_srv_done(void *arg, int status)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;

	struct repmsg_unnamed_chunk_put_proposal *msg_pp = req->msg_pp;

	log_trace(lg, "arg %p, status %d seqid %d.%d", arg, status,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;

	if (state_check(st, ST_TERM)) {
		putcommon_srv__term(st);
		return;
	}

	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;
	if (req->status <= 0) {
		int event = msg->hdr.attributes & RD_ATTR_UNICAST_TCP ?
				RT_RENDEZVOUS_NACK : EV_ERR;
		log_error(lg, "%p processing error %d next event %d", st,
				status, event);
		if (req->vmm)
			state_next(ctx->state, event);
		else
			state_event(ctx->state, event);
		return;
	}

	if (req->status != RT_RENDEZVOUS_TRANSFER) {
		log_debug(lg, "%p transitioning to state %d", st, req->status);
		if (req->vmm)
			state_next(ctx->state, req->status);
		else
			state_event(ctx->state, req->status);
	}

}

static void
unnamedput_srv_done_txfr(void *arg, int status)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;

	dev->put_disk_qdepth--;
	dev->put_net_rx--;
	unnamedput_srv_done(arg, status);
}


static int
unnamedput_srv_one_blob(struct putcommon_srv_req *req, struct repctx *ctx,
	struct repwqe *wqe)
{
	struct repdev *dev = req->dev;
	type_tag_t tt = TT_LAST;
	struct repmsg_unnamed_chunk_put_proposal *msg_pp = req->msg_pp;
	int err;
	struct replicast_object_name *ron = &msg_pp->object_name;

	log_trace(lg, "Exec(%s): inexec %d seqid %d.%d", dev->name,
	    req->inexec, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	tt = attr_to_type_tag(msg_pp->hdr.attributes);
	assert(tt != TT_LAST);
	int is_delete = (msg_pp->hdr.attributes &
			(RD_ATTR_TARGETED | RD_ATTR_TARGETED_DELETE)) ==
			(RD_ATTR_TARGETED | RD_ATTR_TARGETED_DELETE);

	rtbuf_t *rb = NULL;
	if (req->nbufs > 1 && (msg_pp->hdr.attributes & RD_ATTR_VM_MARKER)) {
		uv_buf_t one_payload;
		err = rtbuf_serialize_bufs(&req->payload[0], req->nbufs, &one_payload);
		if (!err)
			rb = rtbuf_init(&one_payload, 1);
	} else
		rb = rtbuf_init_mapped(&req->payload[0], req->nbufs);
	if (!rb) {
		log_error(lg, "Put(%s): out of memory while named put blob",
		    dev->name);
		req->error = RT_ERR_NO_RESOURCES;
		req->status = RT_ERROR;
		return -ENOMEM;
	}

	if (rtbuf_len(rb) == 0) {
		log_error(lg, "Put(%s): empty buffer ", dev->name);
		uint512_logdump(lg, "content_hash_id", &msg_pp->content_hash_id);
		rtbuf_destroy(rb);
		req->error = RT_ERR_EIO;
		req->status = RT_ERROR;
		return -EIO;
	}

	if (dev->verify_chid &&
	    !(msg_pp->hdr.attributes & (RD_ATTR_PARITY_MAP | RD_ATTR_PARITY_MAP_VM)) &&
	    !is_delete) {
		uint512_t calculated_chid;
		err = rtbuf_hash(rb, req->hash_type, &calculated_chid);
		if(!err) {
			err = uint512_cmp(&msg_pp->content_hash_id, &calculated_chid);
		}
		if(err) {
			log_error(lg,
			    "UnnamedPut(%s): payload verification error detected "
			    "seqid %d.%d tt %d ht %d", dev->name,
			    ctx->sequence_cnt, ctx->sub_sequence_cnt, tt,
			    req->hash_type);
			uint512_logdump(lg, "content_hash_id",
			    &msg_pp->content_hash_id);
			uint512_logdump(lg, "calculated_chid", &calculated_chid);
			req->error = RT_ERR_BAD_CRED;
			req->status = RT_ERROR;
			rtbuf_destroy(rb);
			return -EPERM;
		}
	}

	if (is_delete) {
		/* Special case: remove the chunk along with its VBRs (if any)*/
		err = reptrans_delete_blob(dev, tt, req->hash_type,
		    &msg_pp->content_hash_id);
		if (err) {
			log_error(lg, "Put(%s): error deleting parity manifest: %d",
				dev->name, err);
			rtbuf_destroy(rb);
			req->error = RT_ERR_EIO;
			req->status = RT_ERROR;
			return err;
		}
		/* remove all VBRs protecting just removed chunk */
		if (tt != TT_PARITY_MANIFEST) {
			char chidstr[UINT512_BYTES * 2 + 1];
			uint512_dump(&msg_pp->content_hash_id, chidstr,
				sizeof (chidstr));
			chidstr[16] = 0;
			err = reptrans_delete_blob(dev, TT_VERIFIED_BACKREF,
				req->hash_type, &msg_pp->content_hash_id);
			if (err) {
				log_error(lg, "Dev(%s): targeted delete %s %s "
					"%s error: %d", dev->name,
					type_tag_name[tt],
					hash_type_name[req->hash_type],
					chidstr, err);
			} else {
				log_debug(lg, "De(%s) removed chunk %s %s and"
					"its VBRs",dev->name,
					type_tag_name[tt], chidstr);
			}
		}
	} else {
		/*
		 * store version manifest marker in hash table and return.
		 */
		if (req->vmm) {
			vmmc_entry_t ent;

			/* has to be called in ev loop context! */
			nassert(dev->loop_thrid == uv_thread_self());

			ent.vmm_gen_id = ron->vmm_gen_id;
			ent.generation = ron->generation - 1;
			ent.vm_chid = msg_pp->content_hash_id;
			ent.rb = rtbuf_clone_bufs(rb);
			if (!ent.rb) {
				log_error(lg, "Put(%s): out of memory while named put blob",
				    dev->name);
				req->error = RT_ERR_NO_RESOURCES;
				req->status = RT_ERROR;
				return -ENOMEM;
			}

			ccow_vmmcache_put(dev->vmm_ht, &ron->name_hash_id, &ent);

			req->error = 0;
			req->status = RT_UNNAMED_PAYLOAD_ACK;
			rtbuf_destroy(rb);
			return 0;
		}

		if (ccow_daemon->enc_ctx && tt == TT_CHUNK_PAYLOAD &&
		    CRYPTO_ENC_EN(req->hash_type)) {
			rb = ccowd_host_encrypt(ccow_daemon->enc_ctx, rb);
		}
		if (tt == TT_CHUNK_PAYLOAD && dev->payload_put_min_kb &&
		    !req->min && dev->payload_put_min_kb * 1024 <= rtbuf_len(rb)) {
			/* If this device is not "min" then we not suppose to
			 * actually write payload but we need to create a
			 * placeholder in the local vdev */
			uv_buf_t empty_buf = { .base = NULL, .len = rtbuf_len(rb) };
			rtbuf_destroy(rb);
			rb = rtbuf_init(&empty_buf, 1);
		}
		err = reptrans_put_blob_with_attr(dev, tt, req->hash_type, rb,
		    &msg_pp->content_hash_id, 0, reptrans_get_timestamp(dev));
		if (err) {
			log_error(lg, "Put(%s): error adding blob: %d",
				dev->name, err);
			rtbuf_destroy(rb);
			req->error = err == -ENOSPC ? RT_ERR_NO_SPACE :
						      RT_ERR_EIO;
			req->status = RT_ACCEPT_NOT_NOW;
			return err;
		}
		if (unlikely(lg->level <= LOG_LEVEL_DEBUG)) {
			uint16_t n_groups = 0;
			SERVER_FLEXHASH_SAFE_CALL(n_groups =
				flexhash_numrows(SERVER_FLEXHASH), FH_LOCK_READ);
			uint16_t ng = HASHCALC(&msg_pp->content_hash_id,
				n_groups - 1);
			char chidstr[UINT512_BYTES * 2 + 1];
			uint512_dump(&msg_pp->content_hash_id, chidstr,
			    sizeof (chidstr));
			chidstr[16] = 0;
			log_debug(lg, "Dev(%s): unnamed put %s %s %s ng %u",
				dev->name, type_tag_name[tt],
				hash_type_name[req->hash_type], chidstr, ng);
		}
	}
	rtbuf_destroy(rb);
	return 0;
}

static int
unnamedput_srv_compound(struct putcommon_srv_req *req) {
	struct repdev *dev = req->dev;
	struct repmsg_unnamed_chunk_put_proposal *msg_pp = req->msg_pp;
	char chidstr[UINT512_BYTES * 2 + 1];
	int err;
	uint32_t i;
	uv_buf_t buf;
	if ((msg_pp->hdr.attributes & RD_ATTR_NCOMP) == 0) {
		/*
		 * The compound has been encoded/compressed on client side.
		 */
		ccow_t cl =  reptrans_get_tenant_context(dev->rt, 0);
		if (!cl) {
			log_error(lg, "Compound put: couldn't get tenant context");
			req->error = RT_ERR_NO_RESOURCES;
			req->status = RT_ERROR;
			return -EIO;
		}
		uint8_t comp_type = cl->compress_type;
		reptrans_put_tenant_context(dev->rt, cl);
		rtbuf_t* encoded = rtbuf_init_mapped(req->payload, req->nbufs);
		err = hashuncomp_compound(encoded, &buf, comp_type);
		rtbuf_destroy(encoded);
		if (err) {
			log_error(lg, "Compound uncomp failed %d", err);
			req->error = RT_ERR_NO_RESOURCES;
			req->status = RT_ERROR;
			rtbuf_destroy(encoded);
			if (err != -ENOMEM)
				je_free(buf.base);
			return err;
		}
	} else {
		buf.len = 0;
		for (int n = 0; n < req->nbufs; n++)
			buf.len += req->payload[n].len;
		buf.base = je_malloc(buf.len);
		if (!buf.base) {
			log_error(lg, "Memory allocation error");
			return -ENOMEM;
		}
		size_t pos = 0;
		for (int n = 0; n < req->nbufs; n++) {
			memcpy(buf.base + pos, req->payload[n].base, req->payload[n].len);
			pos += req->payload[n].len;
		}
	}
	msgpack_u *u = msgpack_unpack_init(buf.base, buf.len, 0);

	uint512_t chid;
	uint8_t hash_type;
	type_tag_t tt_main;
	uint64_t compound_flags = 0;
	struct vmmetadata md;
	uint32_t vm_packed_length = 0;
	uint64_t count = 0;
	int need_version = 0 ;
	uint32_t comp_vers = 0;
	uint64_t ts = get_timestamp_us();

	/* Unpacking the header */
	err = msgpack_unpack_uint32(u, &comp_vers);
	if (err) {
		log_error(lg, "Dev(%s) compound put: version unpack error %d",
			dev->name, err);
		return err;
	}
	if (comp_vers != RT_PROT_COMPOUND_VERSION) {
		log_error(lg, "Dev(%s) compound put invalid version: %u vs %u",
			dev->name, comp_vers, RT_PROT_COMPOUND_VERSION);
		return -EINVAL;
	}

	err = msgpack_unpack_uint64(u, &compound_flags);
	if (err) {
		log_error(lg, "Dev(%s) compound put: flags unpack error %d",
			dev->name, err);
		return err;
	}
	need_version = compound_flags & COMPOUND_FLAG_NEED_VERSION ? 1 : 0;

	err = msgpack_unpack_uint8(u, &hash_type);
	if (err) {
		log_error(lg, "Dev(%s) compound put: hash_type unpack error %d",
			dev->name, err);
		goto _exit;
	}

	err = replicast_unpack_uint512(u, &chid);
	if (err) {
		log_error(lg, "Dev(%s) compound put: chid unpack error %d",
			dev->name, err);
		goto _exit;
	}
	uint64_t time_to_trigger = 0;
	uint8_t width = 0;
	uint8_t parity = 0;
	uint8_t ec_domain = 0;
	uint8_t ec_algo = 0;
	if (compound_flags & COMPOUND_FLAG_REQUEST_EC) {
		err = msgpack_unpack_uint64(u, &time_to_trigger);
		if (err) {
			log_error(lg, "Dev(%s) compound put: EC trigger timeout unpack error %d",
				dev->name, err);
			goto _exit;
		}
		err = msgpack_unpack_uint8(u, &width);
		if (err) {
			log_error(lg, "Dev(%s) compound put: EC width unpack error %d",
				dev->name, err);
			goto _exit;
		}
		err = msgpack_unpack_uint8(u, &parity);
		if (err) {
			log_error(lg, "Dev(%s) compound put: EC parity unpack error %d",
				dev->name, err);
			goto _exit;
		}
		err = msgpack_unpack_uint8(u, &ec_domain);
		if (err) {
			log_error(lg, "Dev(%s) compound put: EC domain unpack error %d",
				dev->name, err);
			goto _exit;
		}
		err = msgpack_unpack_uint8(u, &ec_algo);
		if (err) {
			log_error(lg, "Dev(%s) compound put: EC algorithm unpack error %d",
				dev->name, err);
			goto _exit;
		}
	}
	err = msgpack_unpack_uint64(u, &count);
	if (err) {
		log_error(lg, "Dev(%s) compound put: chunk count unpack error %d",
			dev->name, err);
		goto _exit;
	}

	if (msg_pp->hdr.attributes & RD_ATTR_CHUNK_PAYLOAD)
		tt_main = TT_CHUNK_PAYLOAD;
	else if (msg_pp->hdr.attributes & RD_ATTR_CHUNK_MANIFEST)
		tt_main = TT_CHUNK_MANIFEST;
	else if (msg_pp->hdr.attributes & RD_ATTR_VERSION_MANIFEST)
		tt_main = TT_VERSION_MANIFEST;
	else {
		log_error(lg, "Dev(%s) compound put: unsupported ttag", dev->name);
		err = -EINVAL;
		goto _exit;
	}
	uint512_dump(&chid, chidstr, UINT512_BYTES * 2 + 1);

	if (tt_main == TT_VERSION_MANIFEST) {
		log_debug(lg, "Dev(%s) processing replication VM %s %s",
			dev->name, chidstr, need_version ? "with" : "WITHOUT");
	}


	if (!(compound_flags & COMPOUND_FLAG_PRIMARY_PUT)) {
		/* This is secondary compound put, make sure the main chunk exists */
		struct blob_stat bs = {.size = 0};
		err = reptrans_blob_stat(dev, tt_main, hash_type, &chid, &bs);
		if (err) {
			log_error(lg, "Dev(%s) compound put: main chunk %s %s doesn't exists",
				dev->name, chidstr, type_tag_name[tt_main]);
			err = -EINVAL;
			goto _exit;
		}
	}
	size_t n_vbrs = 0;
	int need_ec = (compound_flags & COMPOUND_FLAG_REQUEST_EC) &&
		(tt_main == TT_CHUNK_MANIFEST || tt_main == TT_VERSION_MANIFEST);
	struct verification_request ec_req = {
		.vtype = RT_VERIFY_PARITY | RT_VERIFY_NORMAL,
		.chid = chid,
		.ttag = tt_main,
		.htype = hash_type,
		.uvid_timestamp = time_to_trigger + reptrans_get_timestamp(dev)/1000000,
		.width = width,
		.n_parity = parity,
		.domain = ec_domain,
		.algorithm = ec_algo,
		.nhid = uint512_null
	};
	for (i = 0; i < count; ++i) {
		uint8_t ttag = 0;
		uv_buf_t ub = {.len = 0};
		int err = msgpack_unpack_uint8(u, &ttag);
		if (err) {
			log_error(lg, "Dev(%s) compound put: chunk ttag unpack error %d",
				dev->name, err);
			goto _exit;
		}

		assert( ttag > 0 && ttag < TT_LAST);
		uint32_t len = 0;
		err = msgpack_unpack_uint32(u, &len);
		if (err) {
			log_error(lg, "Dev(%s) compound put: chunk size unpack error %d",
				dev->name, err);
			goto _exit;
		}
		uint32_t len1 = 0;
		err = msgpack_unpack_raw(u, (const uint8_t **)&ub.base, &len1);
		if (err) {
			log_error(lg, "Dev(%s) compound put: chunk unpack error %d",
				dev->name, err);
			goto _exit;
		}
		assert(len == len1);
		ub.len = len;

		rtbuf_t *rb = rtbuf_init_mapped(&ub, 1);
		/*
		 * A compound contains several blobs.
		 * The primary compound contains the main chunks and optional VBRs/PM
		 * The secondary compound(s) are optional and can carry VBRs for primary chunks
		 */
		if (ttag == TT_VERIFIED_BACKREF) {
			struct backref vbr;

			msgpack_u *uu =
			    msgpack_unpack_init(rtbuf(rb, 0).base,
				    rtbuf(rb, 0).len, 0);
			err = reptrans_unpack_vbr(uu, &vbr);
			msgpack_unpack_free(uu);
			if (err) {
				log_error(lg,
					"dev %s Compound put chid %s:"
					" backref unpack error",
					dev->path, chidstr);
				rtbuf_destroy(rb);
				break;
			}
			if (need_ec)
				ec_req.vbr = vbr;
			if ((compound_flags & COMPOUND_FLAG_SKIP_EC_VBRS) && (vbr.attr & VBR_ATTR_EC)) {
				rtbuf_destroy(rb);
				continue;
			}

			if (msg_pp->hdr.attributes & RD_ATTR_TARGETED) {
				assert(vbr.rep_count > 0);
				err = reptrans_put_blob(dev, ttag, hash_type, rb,
					&chid, 0);
				if (err) {
					log_error(lg,
						"dev %s PUT couldn't put"
						" blob VBRs: %s, type: %s\n",
						dev->path, chidstr,
						type_tag_name[ttag]);
					rtbuf_destroy(rb);
					break;
				}
				if (!(COMPOUND_FLAG_KEEP_ALL_VBRS & compound_flags)) {
					int n_del = 0;
					err = reptrans_delete_old_vbrs(dev, &chid,
						hash_type, &vbr, &n_del);
					if (err && err != -ENOENT) {
						log_error(lg, "dev %s PUT couldn't delete"
							" blobs old VBRs: %s, type: %s, "
							"err: %d\n", dev->path, chidstr,
							type_tag_name[ttag], err);
					}
				}
				err = 0;
			} else {
				err = reptrans_put_blob(dev, ttag, hash_type, rb,
					&chid, 0);
				if (err) {
					log_error(lg,
						"dev %s PUT couldn't put"
						" blob VBRs: %s, type: %s\n",
						dev->path, chidstr,
						type_tag_name[ttag]);
					rtbuf_destroy(rb);
					break;
				}
			}
			n_vbrs++;
		} else if (ttag == TT_PARITY_MANIFEST) {
			struct ec_pset* pset = NULL;
			int n_sets = 0;
			int32_t domain = 0;
			uint32_t algo = 0, fmt = 0;
			msgpack_u *uu =
				msgpack_unpack_init(rtbuf(rb, 0).base,
				rtbuf(rb, 0).len, 0);
			err = ec_unpack_parity_map(uu, &pset, &n_sets,
				&domain, &algo, &fmt);
			msgpack_unpack_free(uu);
			if (err) {
				log_error(lg,
					"dev %s Compound put chid %s:"
					" parity manifest unpack error",
					dev->path, chidstr);
				rtbuf_destroy(rb);
				break;
			}
			ec_clean_parity_sets(pset, n_sets);
			reptrans_delete_blob(dev, ttag, hash_type,
				&chid);
			err = reptrans_put_blob_with_attr(dev,ttag, hash_type,
				rb, &chid, 0, reptrans_get_timestamp(dev));
			if (err) {
				log_error(lg,
					"dev %s Compound put chid %s:"
					" parity manifest put error %d",
					dev->path, chidstr, err);
				rtbuf_destroy(rb);
				break;
			}
		} else {
			if (is_data_tt(ttag)) {
				uint512_t calculated_chid;
				err = rtbuf_hash(rb, hash_type,
					&calculated_chid);
				if (!err)
					err = uint512_cmp(&chid,
						&calculated_chid);
				if (err) {
					uint512_dump(&chid, chidstr,
						UINT512_BYTES * 2 + 1);
					log_error(lg,
						"dev %s Compound put chid %s:"
						" hash ID verification error",
						dev->path, chidstr);
					rtbuf_destroy(rb);
					break;
				}
			}
			/* Prepare metadata for further use */
			if (ttag == TT_VERSION_MANIFEST) {
				err = replicast_get_metadata(rb, &md);
				if (err) {
					uint512_dump(&chid, chidstr,
						UINT512_BYTES * 2 + 1);
					log_error(lg,
						"dev %s PUT VM chid %s: "
						"couldn't extract metadata\n",
						dev->path, chidstr);
					rtbuf_destroy(rb);
					break;
				}
				vm_packed_length = rtbuf_len(rb);
				if (need_ec) {
					ec_req.nhid = md.nhid;
					ec_req.generation = md.txid_generation;
				}
			}
			if (ccow_daemon->enc_ctx && ttag == TT_CHUNK_PAYLOAD &&
			    CRYPTO_ENC_EN(hash_type)) {
				rb = ccowd_host_encrypt(ccow_daemon->enc_ctx, rb);
			}
			if (ttag == TT_CHUNK_PAYLOAD && dev->payload_put_min_kb &&
			    !req->min && dev->payload_put_min_kb * 1024 <= rtbuf_len(rb)) {
				/* If this device is not "min" then we not suppose to
				 * actually write payload but we need to create a
				 * placeholder in the local vdev */
				uv_buf_t empty_buf = { .base = NULL, .len = rtbuf_len(rb) };
				rtbuf_destroy(rb);
				rb = rtbuf_init(&empty_buf, 1);
			}
			err = reptrans_put_blob_with_attr(dev, ttag,
			    hash_type, rb, &chid, 0,
			    reptrans_get_timestamp(dev));
			if (err) {
				uint512_dump(&chid, chidstr,
					UINT512_BYTES * 2 + 1);
				log_error(lg,
					"dev %s PUT couldn't put"
					" blob chid: %s, type: %s\n",
					dev->path, chidstr,
					type_tag_name[ttag]);
				rtbuf_destroy(rb);
				break;
			}
		}

		/*
		 * For VM add an index entry also
		 */
		if (need_version == 1 && vm_packed_length) {
			err = reptrans_put_version(dev, &md, &chid, vm_packed_length);
			if (err) {
				uint512_dump(&chid, chidstr,
					UINT512_BYTES * 2 + 1);
				log_error(lg, "dev %s PUT VM chid %s: "
					"couldn't put index\n",
					dev->path, chidstr);
				rtbuf_destroy(rb);
				reptrans_delete_blob(dev,
					TT_VERSION_MANIFEST, hash_type,
				    &chid);
				break;
			}
			if ((md.number_of_versions > 0) &&
				(md.txid_generation >
				 md.number_of_versions)) {
				err = ngrequest_purge(dev,
					HASH_TYPE_DEFAULT, &md.nhid,
					md.txid_generation -
					md.number_of_versions,
					0, 0, 0);
				/* ignore error */
			}
			err =  reptrans_enqueue_vm_encoding(dev, &chid, &md);
			need_version = 2;
			log_debug(lg, "Dev(%s) replication add a version for VM %s",
				dev->name, chidstr);
		}
		rtbuf_destroy(rb);
	}
	if (n_vbrs) {
		uint512_dump(&chid, chidstr, UINT512_BYTES * 2 + 1);
		log_debug(lg, "Dev(%s) added %lu VBRs, total chunks %lu, "
			"CHID %s ttag_main %s, duration %lu uS",
			dev->name, n_vbrs, count, chidstr, type_tag_name[tt_main],
			get_timestamp_us() - ts);
	}

	if (!err && need_ec) {
		err = reptrans_request_encoding(dev, &ec_req);
		if (err) {
			log_error(lg, "Error requesting object encoding");
		} else {
			char chidstr[UINT512_BYTES*2+1];
			uint512_dump(&chid, chidstr, UINT512_BYTES*2+1);
			log_debug(lg, "Dev(%s) manifest %s encoding enqueued by replication",
				dev->name, chidstr);
		}
	}
_exit:
	je_free(buf.base);;
	msgpack_unpack_free(u);
	if (err) {
		req->error = RT_ERR_EIO;
		req->status = RT_ERROR;
	}
	return err;
}

static void
unnamedput_srv_exec(void *arg)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repmsg_unnamed_chunk_put_proposal *msg_pp = req->msg_pp;
	char chidstr[UINT512_BYTES * 2 + 1];
	int err, i;

	log_trace(lg, "Exec(%s): arg %p: inexec %d seqid %d.%d", dev->name,
		arg, req->inexec, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	type_tag_t tt = attr_to_type_tag(msg_pp->hdr.attributes);
	assert (tt != TT_LAST);

	/*
	 * version manifest marker
	 */
	if (req->vmm) {
		if (unlikely((lg->level <= LOG_LEVEL_DEBUG))) {
			uint512_dump(&msg_pp->content_hash_id, chidstr,
			    UINT512_BYTES * 2 + 1);
			log_debug(lg, "Dev(%s): received VMM put chid %s", dev->name,
			    chidstr);
		}
		err = unnamedput_srv_one_blob(req, ctx, wqe);
		return;
	}

	/*
	 * Its either immediate or rendezvous. We cannot mix types of transfer.
	 */
	if (msg_pp->immediate_content_length == 0) {
		/* Put proposal? just check if chunk already stored... */
		if (wqe->msg->hdr.transaction_id.opcode ==
			RT_UNNAMED_CHUNK_PUT_PROPOSAL) {

			err = reptrans_touch_blob(dev, tt, req->hash_type,
				&msg_pp->content_hash_id);
			if (req->error == -EEXIST) {
				return;
			}
			if (err == 0) {
				if (msg_pp->hdr.attributes & RD_ATTR_COMPOUND) {
					if (unlikely((lg->level <= LOG_LEVEL_DEBUG))) {
						uint512_dump(&msg_pp->content_hash_id, chidstr,
						    UINT512_BYTES * 2 + 1);
						log_debug(lg, "Dev(%s): Compound put chid %s: "
						    "exists at destination", dev->path, chidstr);
					}
				}

				req->error = -EEXIST;
				req->status = RT_ACCEPT_CONTENT_ALREADY_STORED;
				return;
			}
			req->status = RT_ACCEPT_PROPOSED_RENDEZVOUS;
			return;
		}

	} else {
		/*
		 * Immediate content case.
		 */
		if (msg_pp->immediate_content_length ==
			msg_pp->content_length) {
			log_error(lg, "Immediate put: wrong content length");
			req->error = RT_ERR_EIO;
			req->status = RT_ERROR;
			return;
		}

		/*
		 * Put Payload CHUNK blob. If operation fails at any further
		 * moment, blob will be deleted immediately in terms of to
		 * avoid creation of orphans.
		 *
		 * Note: immediate payload cannot be larger then IP payload,
		 * so it is always going to fit into one UDP datagram.
		 */
		req->payload[0].len = msg_pp->content_length;
		req->payload[0].base = repwqe_payload(wqe);
		req->nbufs = 1;
	}

	if (msg_pp->hdr.attributes & RD_ATTR_COMPOUND) {
		if(unnamedput_srv_compound(req))
			return;
	} else if (unnamedput_srv_one_blob(req, ctx, NULL)) {
		return;
	}
	/*
	 * Immediate content can be ack'ed immediately
	 */
	req->status = RT_UNNAMED_PAYLOAD_ACK;
	assert(req->inexec);
}

/*
 * ACTION: process RT_RENDEZVOUS_TRANSFER request
 */
static void
unnamedput_srv__transfer(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	log_trace(lg, "st %p", st);
	putcommon_srv_transfer(st, unnamedput_srv_exec, unnamedput_srv_done_txfr);
}

static void
unnamedput_srv__pp_busy_timeout(uv_timer_t *treq, int status)
{
	struct putcommon_srv_req *req = treq->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;

	if (req->pp_timer_req->data) {
		uv_timer_stop(treq);
		req->pp_timer_req->data = NULL;
	}

	uint64_t weight = flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
				dev, FH_IOTYPE_PUT);

	req->pp_timer_retry++;

	log_debug(lg, "executing PUT PROPOSAL from timer weight=%ld retry %d",
	    weight, req->pp_timer_retry);

	ctx->state->cur = ST_INIT;
	state_event(ctx->state, RT_UNNAMED_CHUNK_PUT_PROPOSAL);
}

/*
 * ACTION: process RT_NAMED_CHUNK_PUT_PROPOSAL request
 */
static void
unnamedput_srv__put_proposal(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;
	struct repdev *dev = req->dev;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_unnamed_chunk_put_proposal *msg =
		(struct repmsg_unnamed_chunk_put_proposal *)wqe->msg;
	int err;

	log_trace(lg, "st %p seqid %d.%d pp_retry %d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt, req->pp_timer_retry);

	if (req->pp_timer_req->data) {
		/* already processing, skip this request */
		return;
	}

	if (dev->terminating) {
		log_debug(lg, "Dev(%s) terminating", dev->path);
		state_next(st, EV_ERR);
		return;
	}

	if (msg->immediate_content_length == 0) {
		req->reqtype = PUT_REQ_TYPE_UNNAMED_RT;
	} else {
		req->reqtype = PUT_REQ_TYPE_UNNAMED;
	}

	uint512_t *ngroup;
	struct replicast_object_name *ron = &msg->object_name;
	if (!(msg->hdr.attributes & (RD_ATTR_COMPOUND | RD_ATTR_TARGETED |
		RD_ATTR_VM_MARKER | RD_ATTR_COMPOUND_TARGETED)))
			ngroup = &msg->content_hash_id;
	else
		ngroup = &ron->name_hash_id;

	ccowd_fhready_lock(FH_LOCK_READ);
	int found = flexhash_is_rowmember(SERVER_FLEXHASH,
	    &dev->vdevid, ngroup);
	if (!found) {
		fhrow_t row = HASHROWID(ngroup, SERVER_FLEXHASH);
		ccowd_fhready_unlock(FH_LOCK_READ);
		log_debug(lg, "Dev(%s) Not a member of row: %d. Ignoring",
		    dev->path, row);
		state_next(st, EV_ERR);
		return;

	}

	fhrow_t row;
	int ngcount;
	err = flexhash_get_ngcount(SERVER_FLEXHASH, ngroup, &row, &ngcount);
	ccowd_fhready_unlock(FH_LOCK_READ);
	if (err < 0) {
		/* no need to fail PP for normal I/O */
		if (err != -EAGAIN || (msg->hdr.attributes & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED))) {
			log_error(lg, "Put(%s): row (%d) error (%d): %s",
			    dev->name, row, err, strerror(err));
			state_next(st, EV_ERR);
			return;
		}
	}
	if (ngcount < 0)
		req->ngcount = 0;
	else
		req->ngcount = ngcount;
	if (!ngcount) {
		err = -ENODEV;
		log_warn(lg, "Put(%s): row (%d) ngcount (%d) error (%d)",
		    dev->name, row, req->ngcount, err);
		state_next(st, EV_ERR);
		return;
	}

	/* in targeted put participates only a repdev
	 * with provided vdevid */
	if (msg->hdr.attributes & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED)) {
		if (uint128_cmp(&req->dev->vdevid, &msg->vdev)) {
			state_next(st, EV_ERR);
			char vdev1_str[UINT128_BYTES*2+1];
			char vdev2_str[UINT128_BYTES*2+1];
			uint128_dump(&req->dev->vdevid, vdev1_str, UINT128_BYTES*2+1);
			uint128_dump(&msg->vdev, vdev2_str, UINT128_BYTES*2+1);
			log_debug(lg, "Dev(%s) RD_ATTR_TARGETED put VDEV doesn't match: %s vs %s",
				req->dev->path, vdev1_str, vdev2_str);
			state_next(st, EV_ERR);
			return;
		}
	}
	/*
	 * Do not participate in UnnamedPut proposals if we readonly...
	 */
	 repdev_status_t vdev_status = reptrans_dev_get_status(dev);
	int pm_put_allowed = (msg->hdr.attributes & RD_ATTR_PARITY_MAP)
		&& vdev_status == REPDEV_STATUS_READONLY_DATA;
	if ((vdev_status != REPDEV_STATUS_ALIVE) && !pm_put_allowed) {
		req->error = vdev_status== REPDEV_STATUS_UNAVAILABLE ?
			RT_ERR_EIO : RT_ERR_NO_SPACE;
		req->status = RT_ACCEPT_NOT_NOW;
		state_next(st, RT_ACCEPT_NOT_NOW);
		return;
	}

	if (req->inexec) {
		log_debug(lg, "Cannot execute PUT PROPOSAL while in exec");
		state_next(st, EV_ERR);
		return;
	}

	uint64_t weight = flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
				dev, FH_IOTYPE_PUT);
	if (!req->pp_timer_retry && weight > PP_WEIGHT_PAUSE) {
		req->pp_timer_req->data = req;
		uv_timer_start(req->pp_timer_req,
		    unnamedput_srv__pp_busy_timeout, PP_WEIGHT_PAUSE_MS, 0);
		return;
	}

	req->msg_pp = msg;
	req->hash_type = msg->hdr.hash_type;
	req->dev = dev;
	req->req_len = msg->content_length;

	if (!req->pp_timer_retry)
		req->pp_rcvd_time = get_timestamp_us();

	type_tag_t tt = attr_to_type_tag(msg->hdr.attributes);
	uint64_t part = PLEVEL_HASHCALC(&msg->content_hash_id, (dev->plevel - 1));
	assert (tt != TT_LAST);

	/* FIXME: can be not safe, need to check if client commit_wait == 0 */
#if 0
	if (msg->immediate_content_length == 0) {
		/* Check if we have it in recvd cache (NVDRAM) then we say
		 * it is already stored "in memory" */
		struct putcommon_srv_req *preq;
		preq = reptrans_lookup_rcvd_cache(dev->rcvd_cache, ngroup);
		if (preq) {
			log_debug(lg, "Put(%s): Found in RCVD cache ", dev->name);
			req->error = -EEXIST;
			req->status = RT_ACCEPT_CONTENT_ALREADY_STORED;
			state_next(ctx->state, req->status);
			return;
		}
	}
#endif

	/* Check if we do not have it. Non-blocking blob query call */
	if (msg->immediate_content_length == 0 &&
	    wqe->msg->hdr.transaction_id.opcode == RT_UNNAMED_CHUNK_PUT_PROPOSAL) {
		if (msg->hdr.attributes & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED)) {
			/* Targeted operations are always accepted */
			log_debug(lg, "Dev(%s) parity manifest removal request",
				dev->path);
			state_next(ctx->state, RT_ACCEPT_PROPOSED_RENDEZVOUS);
			return;
		}
		if (msg->hdr.attributes & RD_ATTR_VM_MARKER) {
			/* VMM operations are always accepted */
			log_debug(lg, "Dev(%s) received VMM proposal request",
			    dev->name);
			state_next(ctx->state, RT_ACCEPT_PROPOSED_RENDEZVOUS);
			return;
		}
		uint64_t outsize;
		int maybe_exists = reptrans_blob_query(dev, tt, req->hash_type,
			&msg->content_hash_id, &outsize);
		if (!maybe_exists) {
			uint32_t weight_hiwat = 32, flush_delay = 0;
			if (dev->stats.rotational) {
				if (dev->journal) {
					weight_hiwat = 4;
				} else {
					weight_hiwat = 2;
				}
				flush_delay = PP_FLUSH_DELAY_MS;
			}
			if (!req->pp_timer_retry && (dev->flushing & (1 << tt)) &&
			    (dev->flushing_part & (1 < part)) && flush_delay) {
				if (req->pp_timer_req->data)
					uv_timer_stop(req->pp_timer_req);
				req->pp_timer_req->data = req;
				uv_timer_start(req->pp_timer_req,
				    unnamedput_srv__pp_busy_timeout, flush_delay, 0);
				return;
			}

			if (!req->pp_timer_retry && weight > weight_hiwat) {
				/* polling while busy queue */
				int delay_ms;
				if (req->req_len < 65536) {
					delay_ms = (MAX(dev->stats.put90th_4k_latency,
						dev->stats.put90th_4k_latency_j)) / 1000;
				} else if (req->req_len < 131072) {
					delay_ms = (MAX(dev->stats.put90th_64k_latency,
						dev->stats.put90th_64k_latency_j)) / 1000;
				} else {
					delay_ms = (MAX(dev->stats.put90th_512k_latency,
						dev->stats.put90th_512k_latency_j)) / 1000;
				}
				if (delay_ms) {
					if (req->pp_timer_req->data)
						uv_timer_stop(req->pp_timer_req);
					req->pp_timer_req->data = req;
					uv_timer_start(req->pp_timer_req,
					    unnamedput_srv__pp_busy_timeout, delay_ms, 0);
					log_debug(lg, "PP (weight=%ld len=%ld) delayed by %dms",
						weight, req->req_len, delay_ms);
					return;
				}
			}

			/* definetely not found */
			log_debug(lg, "Put(%s): definitely not found - participate",
			    dev->path);
			state_next(ctx->state, RT_ACCEPT_PROPOSED_RENDEZVOUS);
			return;
		} else if (maybe_exists == -EEXIST) {
			/* definetely found */

			if (msg->hdr.attributes & RD_ATTR_COMPOUND) {
				if (unlikely((lg->level <= LOG_LEVEL_DEBUG))) {
					char chidstr[UINT512_BYTES * 2 + 1];
					uint512_dump(&msg->content_hash_id, chidstr,
					    UINT512_BYTES * 2 + 1);
					log_debug(lg, "Dev(%s): Compound put chid %s: "
					    "exists at destination", dev->path, chidstr);
				}
			}
			req->error = -EEXIST;
			req->status = RT_ACCEPT_CONTENT_ALREADY_STORED;
			state_next(ctx->state, req->status);

			/* pass through - we need to touch the blob, but also
			 * would like to send response back to the client and
			 * as such we will be transitioning to
			 * RT_ACCEPT_CONTENT_ALREADY_STORED and will send
			 * response back to a client while blob_touch() will
			 * happen in a background, asynchronously.*/
		}
	}

	req->inexec++;
	log_debug(lg, "Dev(%s): proposal: scheduled unnamedput_srv_exec",
	    dev->name);
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_MID, unnamedput_srv_exec,
	    unnamedput_srv_done, wqe);
}

static void
unnamedput_srv__term(struct state *st)
{
	struct putcommon_srv_req *req = st->data;
	log_trace(lg, "st %p", st);

	putcommon_srv__term(st);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_UNNAMED_CHUNK_PUT_PROPOSAL,
	&unnamedput_srv__put_proposal, ST_WAIT, NULL },
{ ST_WAIT, RT_ACCEPT_PROPOSED_RENDEZVOUS,
	&putcommon_srv__send_accept, ST_READY, NULL},
{ ST_READY, RT_RENDEZVOUS_ACK, &putcommon_srv_rt_ack, ST_READY, NULL},
{ ST_READY, RT_RENDEZVOUS_TRANSFER, &unnamedput_srv__transfer, ST_READY, NULL},
{ ST_READY, RT_RENDEZVOUS_NACK, &putcommon_srv_rtfree, ST_TERM, NULL},
{ ST_WAIT, RT_ACCEPT_CONTENT_ALREADY_STORED,
	&putcommon_srv__exists, ST_TERM, NULL },
{ ST_WAIT, RT_ACCEPT_NOT_NOW, &putcommon_srv__busy, ST_TERM, NULL },
{ ST_READY, RT_ACCEPT_NOT_NOW, &putcommon_srv__busy, ST_TERM, NULL },
{ ST_WAIT, RT_UNNAMED_PAYLOAD_ACK,
	&putcommon_srv_payload_ack, ST_TERM, NULL },
{ ST_READY, RT_UNNAMED_PAYLOAD_ACK,
	&putcommon_srv_payload_ack, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &putcommon_srv__error, ST_TERM, NULL }
};

int
unnamedput_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state)
{
	int err;
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct putcommon_srv_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	req->pp_timer_req = je_malloc(sizeof (*req->pp_timer_req));
	if (!req->pp_timer_req) {
		je_free(req);
		return -ENOMEM;
	}
	req->pp_timer_req->data = NULL;
	uv_timer_init(dev->loop, req->pp_timer_req);

	req->rtfree_timer_req = je_malloc(sizeof (*req->rtfree_timer_req));
	if (!req->rtfree_timer_req) {
		je_free(req->pp_timer_req);
		je_free(req);
		return -ENOMEM;
	}
	req->rtfree_timer_req->data = NULL;

	req->rtfree_timer_fd = uv_hpt_timer_init(req->dev->loop,
	    req->rtfree_timer_req);
	if (req->rtfree_timer_fd < 0) {
		err = req->rtfree_timer_fd;
		je_free(req->pp_timer_req);
		je_free(req);
		log_error(lg, "PUT hpt rtfree init error: %d", err);
		return err;
	}

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof (trans_tbl)/sizeof (*trans_tbl);
	state->data = req;
	state->term_cb = unnamedput_srv__term;
	ctx->stat_cnt = &robj->stats.unnamedput_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	reptrans_io_avg(dev);
	return 0;
}
