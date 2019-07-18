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
#include <stdlib.h>
#include <string.h>

#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "getcommon_client.h"
#include "hashtable.h"
#include "ccow-dynamic-fetch.h"


/*
 * ACTION: unblock caller and report error
 */
static void
namedget__error(struct state *st) {
	struct getcommon_client_req *r = st->data;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
							ctx->sub_sequence_cnt);
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
}

/*
 * ACTION: process NAMED GET final Ack response
 */
static void
namedget__final_ack(struct state *st)
{
	int err;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct ccow_completion *comp = op->comp;
	struct ccow *tc = comp->tc;

	assert(op->optype);
	assert(wqe);

	log_trace(lg, "st %p: generation %" PRIu64 " vmm_genid %" PRIu64 " io %p "
	    "seqid %u.%u, %s", st, r->max_generation, r->max_vmm_gen_id,
	    io, ctx->sequence_cnt, ctx->sub_sequence_cnt, ccow_op2str(op->optype));

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	op->txid_generation = r->max_generation;
	if (op->txid_generation == 0) {
		log_error(lg, "NAMED GET TxID generation cannot be 0");
		ccow_fail_io(st->io, -EBADF);
		state_next(st, EV_ERR);
		return;
	}

	if (io->attributes & RD_ATTR_QUERY) {

		if (io->attributes & RD_ATTR_LOGICAL_DELETE) {
			/*
			 * This is a request to delete a non-existant obj,
			 * Fail the I/O.
			 */
			if (op->txid_generation == 1 && !r->obj_found) {
				ccow_fail_io(st->io, -ENOENT);
				repctx_drop(ctx);
				state_next(st, EV_ERR);
				return;
			}
			/*
			 * Else continue with the namedput.
			 */
		}
		if (r->rt_inprogress && op->txid_generation == 1 &&
		    r->max_vmm_gen_id == 0) {
			repctx_drop(ctx);
			comp->cont_flags &= ~CCOW_CONT_F_EXIST;
			state_next(st, EV_DONE);
			return;
		}
	}


	if (r->rt_inprogress) {
		/* received all RT proposals so move on to evaulate and send
		 * accept
		 */
		if (REPLIES_CNT(r) >= r->ngcount) {
			r->rb_cached = ccow_ucache_get(tc->ucache, &r->chid, &r->payload[0]);
			if (r->rb_cached) {
				r->rtselected = 1;
				r->rt_inprogress = 1;
				r->obj_found = 1;
				r->nbufs = 1;

				if (r->delayed_start_timer_req->data) {
					uv_hpt_timer_stop(r->delayed_start_fd, r->delayed_start_timer_req);
					r->delayed_start_timer_req->data = NULL;
				}
				namedget_process_payload(st);
				return;
			}
			state_next(st, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS);
		}
		return;
	}

	if ((r->reply_count + r->err_count) >= r->ngcount) {
		r->obj_found = 1;
		namedget_process_payload(st);
		return;
	}

}

/*
 * ACTION: process NAMED GET Error responses
 */
void
namedget_error_rcvd(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_io *io = r->io;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	log_trace(lg, "st %p seqid %d.%d", st, ctx->sequence_cnt,
	    ctx->sub_sequence_cnt);

	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}

	struct repmsg_error *msg = (struct repmsg_error *)wqe->msg;
	if (msg->is_gwcache)
		return;

	/* did we get enough errors? bail out if so */
	if (REPLIES_CNT(r) - r->reply_count >= r->ngcount) {
		ccow_fail_io(st->io, msg->error);
		state_next(st, EV_ERR);
		return;
	}

	if (REPLIES_CNT(r) >= r->ngcount) {
		namedget__final_ack(st);
		return;
	}

	if ((msg->hdr.transaction_id.opcode == RT_UNNAMED_CHUNK_GET_RESPONSE
	    || msg->hdr.transaction_id.opcode == RT_NAMED_CHUNK_GET_RESPONSE)
	     && msg->error == -ENOENT) {
		/* not found error processed in the term callback */
		log_debug(lg, "GET received error %s",
		    replicast_error_str[msg->error]);
		state_next(st, EV_DONE);
		return;
	}

	log_error(lg, "GET received unknown error %s",
	    replicast_error_str[msg->error]);

	ccow_fail_io(st->io, msg->error);
	state_next(st, EV_ERR);
}

static int
unpack_vlentries(struct getcommon_client_req *r, int nbuf, hashtable_t *version_table) {
	int err = 0;
	msgpack_u *u = NULL;
	struct vlentry *e = NULL;
	struct ccow_metadata_kv *kv = NULL;
	size_t value_size;


	u = msgpack_unpack_init(r->payload[nbuf].base, r->payload[nbuf].len, 0);
	if (!u) {
		err = -ENOMEM;
		goto _exit;
	}

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err) {
		goto _exit;
	}

	/* at least one version must be present */
	if (n == 0) {
		err = -ENOENT;
		goto _exit;
	}

	e = je_malloc(sizeof (struct vlentry));
	if (!e) {
		err = -ENOMEM;
		goto _exit;
	}

	char skey[256];
	char svalue[1024];
	size_t j, key_size;
	for (j = 0; j < n; j++) {
		err = replicast_unpack_vlentry(u, e);
		if (err) {
			goto _exit;
		}

		int64_t generation = (int64_t) e->generation;
		if (e->object_deleted) {
			generation = -generation;
		}
		sprintf(skey,"%" PRIu64 "|%" PRId64, e->uvid_timestamp, generation);
		key_size = strlen(skey) + 1;


		if (hashtable_get(version_table, skey, key_size, &value_size)) {
			continue;
		}

		// Create metadata entry
		struct ccow_metadata_kv *kv = je_calloc(1, sizeof(*kv));
		if (!kv) {
			err = -ENOMEM;
			goto _exit;
		}

		kv->mdtype = CCOW_MDTYPE_VERSIONS;
		kv->key_size = key_size;
		kv->key = je_calloc(1, kv->key_size);
		if (!kv->key) {
			je_free(kv);
			err = -ENOMEM;
			goto _exit;
		}
		strcpy(kv->key, skey);

		sprintf(svalue, "%" PRIu64 "|", e->logical_size);
		uint512_dump(&e->content_hash_id, svalue + strlen(svalue), UINT512_BYTES * 2 + 1);

		kv->type = CCOW_KVTYPE_STR;

		kv->value_size = strlen(svalue)+1;
		kv->value = je_malloc(kv->value_size);
		if (!kv->value) {
			je_free(kv->key);
			je_free(kv);
			err = -ENOMEM;
			goto _exit;
		}
		strcpy(kv->value, svalue);

		int err = hashtable_put(version_table, kv->key, kv->key_size, kv, sizeof(*kv));
		if (err) {
			je_free(kv->value);
			je_free(kv->key);
			je_free(kv);
			goto _exit;
		}
	}

_exit:
	if (e)
		je_free(e);
	if (u)
		msgpack_unpack_free(u);
	return err;
}

int version_compare(const void *p1, const void *p2)
{
   char **pkey1 = (char **)p1;
   char **pkey2 = (char **)p2;
   return -strcmp(*pkey1, *pkey2);
}

static int
pack_versions(hashtable_t *version_table, struct ccow_lookup *iter) {
	int err = 0;
	unsigned int version_number;
	void **keys = hashtable_keys(version_table, &version_number);
	if (!keys) {
		return -ENOMEM;
	}

	uv_buf_t *uv_b = je_calloc(version_number, sizeof(uv_buf_t));
	if (!uv_b) {
		err = -ENOMEM;
		goto _exit;
	}

	struct ccow_metadata_kv *kv = NULL;
	size_t value_size;
	char *key;

	// Sort keys
	if (version_number > 1) {
	    qsort(keys, version_number, sizeof(char *), version_compare);
	}

	for (unsigned int i = 0; i < version_number; i++) {
		key = (char *) keys[i];
		kv = hashtable_get(version_table, key, strlen(key) + 1, &value_size);
		uv_b[i].base = (void *) kv;
		uv_b[i].len  = sizeof(*kv);
	}

	iter->versions = rtbuf_init(uv_b, version_number);
	if (!iter->versions) {
		err = -ENOMEM;
	}

_exit:
	if (uv_b)
		je_free(uv_b);
	if (keys)
		je_free(keys);
	return err;
}

void
namedget_process_versions_payload(struct state *st)
{
	int err;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct ccow_completion *comp = op->comp;
	struct ccow *tc = comp->tc;
	struct ccow_lookup *iter = op->iter;

	struct repmsg_named_chunk_get_response *msg =
		(struct repmsg_named_chunk_get_response *)wqe->msg;

	log_trace(lg, "st %p r %p: nbufs %d seqid %d.%d", st, r, r->nbufs,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	log_debug(lg, "process versions payload: reply: %d err: %d ngcount: %d "
			"max generation: %" PRIu64, r->reply_count, r->err_count,
			r->ngcount, r->max_generation);

	if (r->nbufs <= 0) {
		log_error(lg, "NAMED GET VERSION: no input: nbufs == 0");
		ccow_fail_io(st->io, -ENOENT);
		state_next(st, EV_ERR);
		return;
	}

	hashtable_t *version_table = hashtable_create(r->nbufs, HT_KEY_CONST | HT_VALUE_CONST, 0.05);
	if (!version_table) {
		log_error(lg, "NAMED GET VERSION: out of memory on versions table");
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		goto _cleanup;
	}

	// Unpack vlenties
	for (int i=0; i < r->nbufs; i++) {
		err = unpack_vlentries(r,  i,  version_table);
		if (err) {
			log_error(lg, "NAMED GET VERSION: unpack error: %d", err);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			goto _cleanup;
		}
	}

	// Pack output
	err = pack_versions(version_table, iter);
	if (err) {
		log_error(lg, "PACK VERSIONS: out of memory: -ENOMEM");
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		goto _cleanup;
	}

	comp->vm_content_hash_id = r->chid;
	comp->vm_txid_generation = op->txid_generation;

	ccow_copy_inheritable_md_to_comp(&op->metadata, op->comp);

	repctx_drop(r->ctx);
	state_next(st, EV_DONE);

_cleanup:
	if (version_table)
		hashtable_destroy(version_table);
}


void
namedget_process_payload(struct state *st)
{
	int err;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct ccow_io *io = (struct ccow_io *)st;

	if (io->attributes & RD_ATTR_VERSIONS_QUERY) {
		namedget_process_versions_payload(st);
		return;
	}

	struct ccow_op *op = io->op;
	struct ccow_completion *comp = op->comp;
	struct ccow *tc = comp->tc;

	struct repmsg_named_chunk_get_response *msg =
		(struct repmsg_named_chunk_get_response *)wqe->msg;
	log_trace(lg, "st %p: nbufs %d seqid %d.%d", st, r->nbufs,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	log_debug(lg, "process payload: reply: %d err: %d ngcount: %d "
			"max generation: %" PRIu64, r->reply_count, r->err_count,
			r->ngcount, r->max_generation);

	rtbuf_t *rb = NULL;
	if (!comp->ver_rb) {
		if (r->nbufs > 1) {
			err = rtbuf_serialize_bufs(&r->payload[0], r->nbufs, &r->one_payload);
			if (!err)
				rb = rtbuf_init_mapped(&r->one_payload, 1);
		} else
			rb = rtbuf_init_mapped(&r->payload[0], r->nbufs);
	} else
		rb = comp->ver_rb;
	if (!rb) {
		log_error(lg, "NAMED GET: out of memory: -ENOMEM");
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}

	/*
	 * If comp->ver_rb is set than it is snapview in progress and it was
	 * already verified as a part of unnamed get.
	 */
	if (tc->verify_chid && rb != comp->ver_rb) {
		/*
		 * The received data can have delayed hashing verification enabled
		 * by the tenant configuration, as there is already a CRC32 on the line.
		 */
		uint512_t tmp_chid;
		err = rtbuf_hash(rb, HASH_TYPE_DEFAULT, &tmp_chid);
		if (err < 0) {
			log_error(lg, "Error calculating VM hash on namedget: %d",
			    err);
			rtbuf_destroy(rb);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return;
		}
		if (uint512_cmp(&r->chid, &tmp_chid) != 0) {
			err = RT_ERR_BAD_CRED;
			log_warn(lg, "VM (len=%ld nbufs=%ld) fingerprint "
			    "verification error: %d", rtbuf_len(rb), rb->nbufs, err);
			uint512_logdump(lg, "Calculated CHID: ", &tmp_chid);
			uint512_logdump(lg, "Expected CHID: ", &r->chid);

			rtbuf_destroy(rb);

			r->excluded_vdevs[r->excluded_count++] = r->selected_vdevs[0];
			client_getcommon_reset(r);
			state_next(st, EV_TIMEOUT);
			return;
		}
	}

	if (!r->rb_cached)
		io->network_payload_len = rb->bufs[0].len;
	else
		io->network_payload_len = 0;


	/* Copy the vm_content_hash_id, etc. to completion */
	comp->vm_content_hash_id = r->chid;
	comp->vm_txid_generation = op->txid_generation;

	/*
	 * Read Version Mainifest metadata
	 */
	err = replicast_get_metadata(rb, &op->metadata);
	if (err) {
		log_error(lg, "NAMED GET metadata error: %d", err);
		rtbuf_destroy(rb);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}
	comp->was_object_deleted = op->metadata.object_deleted;

	if (rb != comp->ver_rb && !r->rb_cached) {
		/* add VM to ucache */
		assert(rb->nbufs == 1);
		ccow_ucache_put(tc->ucache, &r->chid, &rb->bufs[0], 1);
	}

	if (op->metadata.object_deleted) {
		log_debug(lg, "L-Deleted object received at generation: %ld "
		    "attr %lu", r->max_generation, io->attributes);
		if (io->attributes & RD_ATTR_QUERY) {
			rtbuf_destroy(rb);
			if (io->attributes & RD_ATTR_LOGICAL_DELETE &&
				!(io->attributes & RD_ATTR_EXPUNGE_OBJECT_VERSION)) {
				ccow_fail_io(st->io, -ENOENT);
				state_next(st, EV_ERR);
				return;
			}
			repctx_drop(r->ctx);
			comp->cont_flags &= ~CCOW_CONT_F_EXIST;
			state_next(st, EV_DONE);
			return;
		} else if (!(io->attributes & RD_ATTR_PSEUDO_GET)) {
			rtbuf_destroy(rb);
			ccow_fail_io(st->io, -ENOENT);
			state_next(st, EV_ERR);
			return;
		}
		log_debug(lg, "Continue processing L-Deleted object");
	}

	if (io->attributes & RD_ATTR_NO_OVERWRITE && op->txid_generation > 1) {
		rtbuf_destroy(rb);
		ccow_fail_io(st->io, -EEXIST);
		state_next(st, EV_ERR);
		return;
	}

	/*
	 * Read Chunk Reference list (Payload CHID + Offset + Length)
	 */
	err = replicast_get_refs(rb, &op->vm_reflist, 0);
	if (err) {
		log_error(lg, "NAMED GET chunk reference list error: %d", err);
		rtbuf_destroy(rb);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}

	if (op->iter) {
		struct ccow_lookup *iter = op->iter;

		iter->metadata = je_malloc(sizeof (struct vmmetadata));
		if (!iter->metadata) {
			err = -ENOMEM;
			log_error(lg, "NAMED GET metadata error: %d", err);
			rtbuf_destroy(rb);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return;
		}
		memcpy(iter->metadata, &op->metadata,
		    sizeof (struct vmmetadata));
		iter->metadata->cid = je_memdup(op->metadata.cid, op->metadata.cid_size);
		iter->metadata->cid_size = op->metadata.cid_size;
		iter->metadata->tid = je_memdup(op->metadata.tid, op->metadata.tid_size);
		iter->metadata->tid_size = op->metadata.tid_size;
		iter->metadata->bid = je_memdup(op->metadata.bid, op->metadata.bid_size);
		iter->metadata->bid_size = op->metadata.bid_size;
		iter->metadata->oid = je_memdup(op->metadata.oid, op->metadata.oid_size);
		iter->metadata->oid_size = op->metadata.oid_size;

		err = replicast_get_custom_metadata(rb, &iter->custom_md);
		if (err) {
			log_error(lg, "NAMED GET custom metadata error: %d",
			    err);
			je_free(iter->metadata->cid);
			je_free(iter->metadata->tid);
			je_free(iter->metadata->bid);
			je_free(iter->metadata);
			iter->metadata = NULL;
			rtbuf_destroy(rb);
			ccow_fail_io(st->io, err);
			state_next(st, EV_ERR);
			return;
		}


		/*
		 * When supplying custom md attrs to a new object or an object
		 * w/o MD, its rtbuf_t* will not have been allocated because it
		 * does not contain any custom md, copy the new attrs from the
		 * iter.
		 */
		if (op->comp->custom_md == NULL)
			op->comp->custom_md = rtbuf_clone_bufs(iter->custom_md);
	}

	/**
	* For ISGW and MDOnly buckets. If the dynamic fetch enabled,
	* then just allocate data structure. Its content will be filled upon
	* payload fetch request
	*/
	if (strcmp(op->tid, RT_SYSVAL_TENANT_SVCS) && !op->isgw_dfetch &&
		ccow_bucket_isgw_lookup(op->cid, op->tid, op->bid, NULL) == 0)
		op->isgw_dfetch = 1;
	/*
	 * Preset some of completion defaults for comp-hash while
	 * doing stream or normal (below) PUTs
	 */
	if (op->copy_opts && op->copy_opts->md_override) {
		ccow_copy_inheritable_comp_to_md(op->comp, &op->metadata);
	} else
		ccow_copy_inheritable_md_to_comp(&op->metadata, op->comp);
	if (rb != comp->ver_rb)
		rtbuf_destroy(rb);

	repctx_drop(r->ctx);
	state_next(st, EV_DONE);
}

static void
namedget__send(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow *tc = r->tc;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = io->comp;
	struct ccow_network *netobj = tc->netobj;
	uint64_t need_generation = (c->cont_generation ) ? *c->cont_generation : 0;

	log_trace(lg, "st %p attr 0x%lu genid %lu seqid %d.%d", st, io->attributes,
	    need_generation, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	struct repmsg_named_chunk_get msg;
	memset(&msg, 0, sizeof (msg));
	msg.maximum_immediate_content_size = 0; // FIXME
	msg.maximum_number_of_delegated_gets = 0; // FIXME
	msg.reception_window = 0; // FIXME
	msg.hdr.attributes |= io->attributes;
	msg.hdr.hash_type = r->hash_type;
	msg.object_name.name_hash_id = op->name_hash_id;
	msg.object_name.parent_hash_id = op->parent_hash_id;
	msg.object_name.generation = need_generation;
	if (io->attributes & (RD_ATTR_PARITY_ENCODE | RD_ATTR_ONDEMAMD_PIN |
		RD_ATTR_ONDEMAND_UNPIN | RD_ATTR_ONDEMAND_PERSIST))
		msg.object_name.generation = c->vm_txid_generation;
	msg.object_name.uvid_timestamp = op->uvid_timestamp;
	if (msg.object_name.generation > 0)
		msg.object_name.version_uvid_timestamp = c->version_uvid_timestamp;
	else {
		msg.object_name.version_uvid_timestamp = 0;
		io->attributes |= RD_ATTR_GET_CONSENSUS;
	}
	memcpy(&msg.receive_tenant_addr, &tc->tenant_recvaddr.sin6_addr, 16);
	msg.receive_tenant_port = tc->tenant_recvport;

	msg.avg_put_latency = tc->avg_put_latency;
	msg.avg_get_latency = tc->avg_get_latency;
	msg.put_iops = tc->put_iops;
	msg.get_iops = tc->get_iops;
	msg.put_bw = tc->put_bw;
	msg.get_bw = tc->get_bw;
	msg.svcinfo = tc->svcinfo;

	/* CHID to select NG from, it is NHID in case of NamedGet */
	r->ng_chid = op->name_hash_id;

	r->req_start = get_timestamp_us();
	uint64_t avg_rtt = flexhash_get_rtt(CLIENT_FLEXHASH, &r->ng_chid,
					    FH_MSG_NAMEDGET_SELECT, 4096);
	msg.genid_delta = (r->req_start - op->uvid_timestamp) + (avg_rtt >> 1);
	msg.select_time_avg = avg_rtt;
	client_getcommon_send_proposal(st, RT_NAMED_CHUNK_GET, &msg);
}

static void
namedget_comphash_done(void *arg, int status)
{
	struct state *st = arg;
	struct getcommon_client_req *r = st->data;
	struct repctx *ctx = r->ctx;

	log_trace(lg, "arg %p, status %d seqid %d.%d", arg, status,
	    ctx->sequence_cnt, ctx->sub_sequence_cnt);

	if (status) {
		ccow_fail_io(st->io, status);
		client_getcommon_terminate(st);
		return;
	}

	if (state_check(st, ST_TERM))
		client_getcommon_terminate(st);
}

static void
namedget__init(struct state *st)
{
	struct getcommon_client_req *r = st->data;
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;

	log_trace(lg, "st %p", st);

	r->reqtype = GET_REQ_TYPE_NAMED;
	client_getcommon_init(st);

	namedget__send(st);
}

static void
namedget__terminate(struct state *st)
{
	struct ccow_io *io = (struct ccow_io *)st;
	struct ccow_op *op = io->op;
	struct getcommon_client_req *r = st->data;

	if (!op->status && op->namedput_io && op->iovcnt_in &&
	    op->optype == CCOW_PUT && !op->comphash_started) {
		/*
		 * Only for CCOW_PUT. Start Async Compression/Fingerprint.
		 */
		repctx_drop(r->ctx);
		op->comphash_started = 1;
		int err = ccow_comphash_compute(op, namedget_comphash_done, st);
		if (err) {
			op->comphash_started = 0;
			ccow_fail_io(io, err);
		} else
			return;
	}
	if (!op->comphash_started)
		client_getcommon_terminate(st);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, namedget__init, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, namedget__send, ST_WAIT, client_getcommon_guard_retry },
{ ST_READY, EV_TIMEOUT, namedget__send, ST_READY, client_getcommon_guard_retry },
{ ST_WAIT, RT_NAMED_CHUNK_GET_RESPONSE, namedget__final_ack, ST_READY,
	client_getcommon_guard_resp },
{ ST_READY, RT_NAMED_CHUNK_GET_RESPONSE, namedget__final_ack, ST_READY,
	client_getcommon_guard_resp },
{ ST_WAIT, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS, client_getcommon_send_accept,
	ST_READY, client_getcommon_send_accept_guard },
{ ST_READY, RT_INIT_TCP_CONNECT, &client_getcommon_tcp_connect, ST_READY, NULL },
{ ST_READY, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS, client_getcommon_send_accept,
	ST_READY, client_getcommon_send_accept_guard },
{ ST_WAIT, RT_ERROR, namedget_error_rcvd, ST_READY,
	client_getcommon_error_consensus },
{ ST_READY, RT_ERROR, namedget_error_rcvd, ST_READY,
	client_getcommon_error_consensus },
{ ST_READY, RT_GET_RENDEZVOUS_TRANSFER, &client_getcommon_rttransfer,
	ST_READY, NULL},
{ ST_READY, RT_RENDEZVOUS_NACK, &client_getcommon_nack_rcvd, ST_READY, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_READY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, namedget__error, ST_TERM, NULL }
};

int
ccow_namedget_create(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, getcommon_client_callback_t done_cb,
    ccow_op_t optype, struct ccow_op **pop, struct ccow_io **pio)
{
	int err;
	struct ccow_completion *c = comp;

	log_trace(lg, "cid %p, cid_size %ld, tid %p, tid_size %ld, "
	    "bid %p, bid_size %ld, oid %p, oid_size %ld, comp %p, "
	    "done_cb %p, %s, pop %p, pio %p",
	    cid, cid_size, tid, tid_size, bid, bid_size, oid, oid_size,
	    comp, done_cb, ccow_op2str(optype), pop, pio);

	struct getcommon_client_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		err = -ENOMEM;
		log_error(lg, "NAMED GET request alloc error: %d", err);
		return err;
	}

	*pop = NULL;
	*pio = NULL;

	r->tc = c->tc;
	r->done_cb = done_cb;
	r->hash_type = HASH_TYPE_DEFAULT;

	/*
	 * Named Get is an operation which will be called at the beginning of
	 * each CCOW I/O. We use this place to initialize CCOW operation and
	 * add it to the completion pipe-line.
	 */
	err = ccow_operation_create(c, optype, pop);
	if (err) {
		log_error(lg, "NAMED GET request operation alloc error: %d", err);
		goto _err_exit;
	}
	(*pop)->cid = je_memdup(cid, cid_size);
	if (!(*pop)->cid) {
		err = -ENOMEM;
		goto _err_exit;
	}
	(*pop)->tid = je_memdup(tid, tid_size);
	if (!(*pop)->cid) {
		err = -ENOMEM;
		goto _err_exit;
	}
	(*pop)->bid = je_memdup(bid, bid_size);
	if (!(*pop)->cid) {
		err = -ENOMEM;
		goto _err_exit;
	}
	(*pop)->oid = je_memdup(oid, oid_size);
	if (!(*pop)->cid) {
		err = -ENOMEM;
		goto _err_exit;
	}
	(*pop)->cid_size = cid_size;
	(*pop)->tid_size = tid_size;
	(*pop)->bid_size = bid_size;
	(*pop)->oid_size = oid_size;

	/* used for client side calculation, however, for NamedPut and
	 * metadata we use coordinated_uvid_timestamp to ensure ordered
	 * TRLOG insertions */
	(*pop)->uvid_timestamp = get_timestamp_us();

	(*pop)->shard_index = c->shard_index;

	/*
	 * This will drive the destruction of the iterator on any error case
	 * from the I/O through ccow_operation_destroy().
	 */
	err = ccow_create_io(c, *pop, optype, trans_tbl,
	    sizeof (trans_tbl) / sizeof (*trans_tbl), r,
	    namedget__terminate, pio);
	if (err) {
		goto _err_exit;
	}
	r->io = *pio;

	if ((optype == CCOW_CLONE || optype == CCOW_PUT ||
	     optype == CCOW_CONT || optype == CCOW_INSERT_LIST ||
	     optype == CCOW_DELETE_LIST ||
	     optype == CCOW_INSERT_LIST_WITH_MD ||
	     optype == CCOW_DELETE_LIST_WITH_MD) && !c->custom_md) {
		(*pop)->iter = ccow_lookup_create(c, CCOW_LOOKUP_CLASS_OBJECT);
		if (!(*pop)->iter) {
			err = -ENOMEM;
			goto _err_exit;
		}
	}

	/*
	 * Keep pointer to the starting I/O in ccow_op. It will be used by
	 * chunkmap algorithms for I/O chaining.
	 */
	(*pop)->namedget_io = r->io;
	(*pop)->tail_io = r->io;

	if (*oid && *cid == 0 && *tid == 0 && *bid == 0 &&
	    memcmp_quick(oid, oid_size, ".journal", 9) != 0) {
		assert(oid_size == UINT512_BYTES * 2 + 1);
		/* oid is nhid_str */
		uint512_fromhex((char *)oid, UINT512_BYTES * 2 + 1,
		    &(*pop)->name_hash_id);

		/* Note: we do not allow override for CCOW_GET_LIST due to
		 *       the way bucket update logic in auditserv structured */
		if (optype == CCOW_GET)
			r->io->attributes |= RD_ATTR_PSEUDO_GET;
	} else {
		if (optype == CCOW_GET_VERSIONS) {
			r->io->attributes |= RD_ATTR_VERSIONS_QUERY;
		}
		if (optype == CCOW_GET_TEST) {
			r->io->attributes |= RD_ATTR_PSEUDO_GET;
		}
		err = ccow_build_name_hashes(comp, (*pop));
		if (err) {
			goto _err_exit;
		}
	}

	c->vm_name_hash_id = (*pop)->name_hash_id;

	return 0;

_err_exit:
	if (*pop)
		ccow_operation_destroy(*pop, 1);
	if (*pio)
		ccow_destroy_io(*pio); /* this will free "r" */
	else
		je_free(r);
	return err;
}
