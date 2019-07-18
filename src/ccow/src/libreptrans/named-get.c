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
#include "reptrans.h"
#include "ccowd-impl.h"
#include "state.h"
#include "getcommon_server.h"
#include "vmm_cache.h"

#define PP_ADJ_WEIGHT			3
#define PP_ADJ_WEIGHT_MAX		512
#define PP_WEIGHT_DELAY_MAX_US		10000

static int
namedget_create_proposal(uint64_t genid, uint64_t genid_delta,
				struct getcommon_srv_req *req)
{
	struct repmsg_named_chunk_get_response *rsp = &req->named_rsp;
	struct replicast_rendezvous_proposal *proposal
		= &rsp->rendezvous_proposal;
	struct repdev *dev = req->dev;
	uint128_t *vdevid = &dev->vdevid;

	log_trace(lg, "req %p", req);
	int err = srv_getcommon_find_window(vdevid, req->content_length,
		proposal, genid, genid_delta, req,
		dev->metadata_mask & 1 ? TT_CHUNK_MANIFEST : TT_CHUNK_PAYLOAD);
	if (err) {
		log_warn(lg, "NmedGet(%s): Unable to determine a window",
		    dev->name);
		return err;
	}

	if (proposal->weight_io > PP_ADJ_WEIGHT_MAX) {
		log_warn(lg, "NamedGet(%s): Unable to schedule request due "
		    "to way too deep device queue", dev->name);
		err = -EBUSY;
		return err;
	}

	/*
	 * There is no point in replying back to initiator with a proposal
	 * immediately as it selects based on first in. By introducing adaptive
	 * delay in response we enabling natural selection of most optimal VDEV.
	 */
	if (proposal->weight_io > PP_ADJ_WEIGHT) {
		uint64_t delta_pct = req->delta_time_est / 100;
		uint64_t delay_us = (proposal->weight_io - PP_ADJ_WEIGHT) * delta_pct;
		delay_us /= 10;
		if (delay_us > 0 && delay_us < PP_WEIGHT_DELAY_MAX_US) {
			log_debug(lg, "weight_io delay %luus", delay_us);
			usleep(delay_us);
		}
	}

	memcpy(&rsp->vdevid, vdevid, sizeof (uint128_t));
	return 0;
}

static void
namedget_srv__error(struct state *st)
{
	struct getcommon_srv_req *req = st->data;
	/* FIXME: provide previous event/state info in the log error */

	log_trace(lg, "st %p", st);
}


static void
namedget_srv_done(void* arg, int status)
{
	struct getcommon_srv_req *req = arg;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;
	struct repdev *dev = req->dev;
	struct repmsg_named_chunk_get *msg = &req->msg_in.named_get;
	struct replicast_object_name *ron = &msg->object_name;

	int err;

	log_trace(lg, "arg %p, status %d", arg, status);

	req->inexec--;
	dev->get_disk_qdepth--;

	if (state_check(st, ST_TERM)) {
		srv_getcommon_terminate(st);
		return;
	}

	if (status != 0) {
		log_error(lg, "Get(%s): transport returned non-zero "
		    "status %d", dev->name, status);
		goto _out;
	}

	enum replicast_opcode reply_opcode;
	struct repmsg_generic *reply;
	uv_buf_t *bufs = NULL;
	int nbufs = 0;

	struct repctx *lctx = (req->rtproposed) ? ctx : NULL;
	if (req->status == 0) {
		req->named_rsp.num_datagrams = 1;
		req->named_rsp.immediate_content_length =
			(req->rtproposed) ?  0 : req->named_rsp.content_length;

		reply = (struct repmsg_generic *)&req->named_rsp;
		reply_opcode = RT_NAMED_CHUNK_GET_RESPONSE;

		if (!req->rtproposed) {
			if (req->rb_reply) {
				bufs = req->rb_reply->bufs;
				nbufs = req->rb_reply->nbufs;
			}
		}
	} else if (ron->generation) {
		log_debug(lg, "Error st %p generation %" PRIu64, st, ron->generation);
		goto _out;
	} else if (req->row_nonmember == 1) {
		log_warn(lg, "Get(%s): Not a member of row, no RT_ERROR.", dev->name);
		goto _out;
	} else {
		req->err.num_datagrams = 1;
		req->err.error = req->status;
		req->err.vdevid = dev->vdevid;
		reply = (struct repmsg_generic *)&req->err;
		reply_opcode = RT_ERROR;
	}

	req->inexec++;
	err = replicast_send(dev->robj, lctx, reply_opcode, reply,
	    (struct repmsg_generic *)msg, bufs, nbufs, NULL,
	    srv_getcommon_send_done, req, NULL);
	if (err) {
		req->inexec--;
		log_error(lg, "Error sending %d st %p error %d",
			  reply_opcode, st, err);
		goto _out;
	}

	return;

_out:
	if (req->proposal_failed)
		state_next(ctx->state, EV_ERR);
	else
		state_event(ctx->state, EV_ERR);
}


static void
namedget_exec_versions(void* arg)
{
	struct getcommon_srv_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repmsg_named_chunk_get *msg = &req->msg_in.named_get;
	struct replicast_object_name *ron = &msg->object_name;
	int err, len;
	int hash_type = msg->hdr.hash_type;

	struct replicast_transaction_id *msg_id = &msg->hdr.transaction_id;
	struct replicast_transaction_id *orig_id = &msg->hdr.orig_id;

	log_trace(lg, "dev: %s arg %p seqid %d.%d orig_id %d.%d", dev->name,
	    arg, msg_id->sequence_num, msg_id->sub_sequence_num,
	    orig_id->sequence_num, orig_id->sub_sequence_num);

	fhrow_t row;
	int ngcount;
	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
		&ron->name_hash_id, &row, &ngcount), FH_LOCK_READ);
	if (err < 0) {
		req->status = RT_ERR_BAD_NGCOUNT;
		if (err != -EAGAIN)
			log_error(lg, "Get(%s): row (%d) error (%d) while "
				"reading versions: %s", dev->name, row, err,
				strerror(err));
		return;
	}
	req->named_rsp.ngcount = ngcount;
	req->err.ngcount = req->named_rsp.ngcount;
	req->named_rsp.fddelta = req->err.fddelta = ccowd_get_fddelta();
	req->err.vdevid = dev->vdevid;

	uint512_t vm_chid;
	rtbuf_t *rb_vers = NULL;
	struct vlentry **vers = NULL;
	msgpack_p *p = NULL;

	/*
	 * Get all versions.
	 */
	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation =  0ULL
	};

	err = reptrans_get_versions(dev, &ron->name_hash_id, &query, &rb_vers);
	if (err == -ENOENT) {
		if (ron->generation != 0) {
			req->status = -1;
			goto _cleanup;
		}

		log_debug(lg, "Get(%s): name index not found ENOENT", dev->name);
		uint512_logdump(lg, "NHID: ", &ron->name_hash_id);
		req->status = -ENOENT;
		goto _cleanup;
	} else if (err) {
		if (err != -EACCES) {
			log_error(lg, "Get(%s): error (%d) while reading versions",
			    dev->name, err);
			uint512_logdump(lg, "NHID: ", &ron->name_hash_id);
		}
		req->status = ron->generation ? -1 : RT_ERR_UNKNOWN;
		goto _cleanup;
	}

	if (rb_vers->nbufs < 1) {
		log_debug(lg, "Get(%s): name index not found ENOENT", dev->name);
		uint512_logdump(lg, "NHID: ", &ron->name_hash_id);
		req->status = -ENOENT;
		goto _cleanup;
	}

	// Navigare versions
	vers = je_malloc(sizeof(struct vlentry *) * rb_vers->nbufs);
	if (!vers) {
		log_error(lg, "Allocate versions  buffer error while reading versions");
		req->status = RT_ERR_UNKNOWN;
		goto _cleanup;
	}

	// Pack
	p = msgpack_pack_init();
	if (!p) {
		log_error(lg, "Allocate msgpack buffer error while reading versions");
		req->status = RT_ERR_UNKNOWN;
		goto _cleanup;
	}

	/* Pack all user supplied ref entries */
	err = msgpack_pack_array(p, rb_vers->nbufs);
	if (err) {
		log_error(lg, "Allocate msgpack erray error while reading versions");
		req->status = RT_ERR_UNKNOWN;
		goto _cleanup;
	}


	size_t i;
	for (i = 0; i < rb_vers->nbufs; ++i) {
		vers[i] = (struct vlentry *)rtbuf(rb_vers, i).base;

		err = replicast_pack_vlentry(p, vers[i]);
		if (err) {
			log_error(lg, "Pack vlentry error while reading versions");
			req->status = RT_ERR_UNKNOWN;
			goto _cleanup;
		}
	}
	uv_buf_t uv_b;
	// Copy buffer to uv_b
	msgpack_get_buffer(p, &uv_b);
	rtbuf_t *rbx = rtbuf_init(&uv_b, 1);


	// found
	struct vlentry *found = vers[0];
	assert(found->generation);
	log_debug(lg, "using generation: %" PRId64 ", query generation %" PRId64,
	    found->generation, ron->generation);

	req->named_rsp.object_name.uvid_timestamp = found->uvid_timestamp;
	req->named_rsp.object_name.name_hash_id = ron->name_hash_id;
	req->named_rsp.object_name.parent_hash_id = ron->parent_hash_id;
	req->named_rsp.object_name.generation = found->generation;

	vm_chid = found->content_hash_id;

	uint512_logdump(lg, "VERSION-MANIFEST", &vm_chid);

	size_t content_length = rtbuf_len(rbx);

	req->reqtype = GET_REQ_TYPE_NAMED;
	req->chid = vm_chid;
	req->hash_type = hash_type;
	req->tt = TT_NAMEINDEX;
	req->named_rsp.content_hash_id = vm_chid;
	req->named_rsp.content_length = content_length;
	req->named_rsp.immediate_content_length	= content_length;
	req->named_rsp.content_hash_id = vm_chid;
	req->named_rsp.num_datagrams = 1;
	req->named_rsp.vdevid = dev->vdevid;

	req->rb_reply = rbx;
	req->status = 0;

	// Cleanup
_cleanup:
	if (p)
	   msgpack_pack_free_p(p);
	if (vers)
	   je_free(vers);
	if (rb_vers)
	   rtbuf_destroy(rb_vers);
}


static void
namedget_exec(void *arg)
{
	struct getcommon_srv_req *req = arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repmsg_named_chunk_get *msg = &req->msg_in.named_get;
	struct replicast_object_name *ron = &msg->object_name;
	int err, len;

	int hash_type = msg->hdr.hash_type;

	struct replicast_transaction_id *msg_id = &msg->hdr.transaction_id;
	struct replicast_transaction_id *orig_id = &msg->hdr.orig_id;

	if (msg->hdr.attributes & RD_ATTR_VERSIONS_QUERY) {
		log_trace(lg,"namedget_exec RD_ATTR_VERSIONS_QUERY\n");
		namedget_exec_versions(arg);
		return;
	}

	log_trace(lg, "dev: %s wreq %p seqid %d.%d orig_id %d.%d", dev->name,
	    arg, msg_id->sequence_num, msg_id->sub_sequence_num,
	    orig_id->sequence_num, orig_id->sub_sequence_num);

	fhrow_t row;
	int ngcount=0;
	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
		&ron->name_hash_id, &row, &ngcount), FH_LOCK_READ);
	if (err < 0) {
		if (err != -EAGAIN || !ron->generation) {
			req->status = RT_ERR_BAD_NGCOUNT;
			log_warn(lg, "Get(%s): row (%d) error (%d) while "
			    "reading versions: %s", dev->name, row, err, strerror(err));
			return;
		}
	}
	if (ngcount <= 0)
		req->named_rsp.ngcount = 0;
	else
		req->named_rsp.ngcount = ngcount;
	req->err.ngcount = req->named_rsp.ngcount;
	req->named_rsp.fddelta = req->err.fddelta = ccowd_get_fddelta();
	req->err.vdevid = dev->vdevid;

	rtbuf_t *rb = NULL;
	uint512_t vm_chid;
	vmmc_entry_t *ent = req->ent;
	if (ent) {

		/* has to be called in ev loop context! */
		nassert(dev->loop_thrid == uv_thread_self());

		log_debug(lg, "using VMM generation: %" PRId64
		    ", vmm_genid %" PRId64 "", ent->generation, ent->vmm_gen_id);

		if (!ent->rb || !ent->rb->bufs) {
			log_debug(lg, "Get(%s): inconsistent vmm cache entry removed: %"PRIu64,
			    dev->name, ent->generation);
			ccow_vmmcache_remove(dev->vmm_ht, &ron->name_hash_id);
			req->status = -1;
			return;
		}

		rb = rtbuf_clone_bufs(ent->rb);
		assert(rb); // FIXME: need to unroll
		vm_chid = ent->vm_chid;
		req->content_length = rtbuf_len(rb);
		req->named_rsp.object_name.vmm_gen_id = ent->vmm_gen_id;
		req->named_rsp.object_name.name_hash_id = ron->name_hash_id;
		req->named_rsp.object_name.parent_hash_id = ron->parent_hash_id;
		if (msg->hdr.attributes & RD_ATTR_QUERY) {
			/* new write about to start */
			req->named_rsp.object_name.uvid_timestamp = COORDINATED_TS();
			req->named_rsp.object_name.generation = ent->generation + 1;
		} else {
			req->named_rsp.object_name.uvid_timestamp = 0;
			if (ent->generation == 0)
				/* initial creation, recovery */
				req->named_rsp.object_name.generation = 1;
			else
				/* continuation, recovery */
				req->named_rsp.object_name.generation = ent->generation;
		}
		goto _vmm_return;
	}

	/*
	 * Get version. There are two cases here:
	 *
	 * - latest VM CHID, i.e. UVID == 0 and generation == 0
	 *
	 * - specified latest VM CHID with generation as specified, i.e.
	 *   UVID == 0 and generation != 0
	 */
	struct vlentry query = {
		.uvid_timestamp = (ron->version_uvid_timestamp > 0 ? ron->version_uvid_timestamp : ~0ULL),
		.generation = ron->generation ? ron->generation : ~0ULL
	};
	rtbuf_t *rb_vers;
	err = reptrans_get_versions(dev, &ron->name_hash_id, &query, &rb_vers);
	if (err == -ENOENT) {
		if (ron->generation != 0 &&
			!(msg->hdr.attributes & (RD_ATTR_PARITY_ENCODE |
				RD_ATTR_ONDEMAMD_PIN |
				RD_ATTR_ONDEMAND_UNPIN |
				RD_ATTR_ONDEMAND_PERSIST))) {
			req->status = -1;
			return;
		}

		/*
		 * PUT query? - new object is about to be created...
		 */
		if (msg->hdr.attributes & RD_ATTR_QUERY) {
			req->named_rsp.object_name.uvid_timestamp = COORDINATED_TS();
			req->named_rsp.object_name.generation = 1;
			req->named_rsp.content_length = 0;
			memcpy(&req->named_rsp.vdevid, &dev->vdevid, sizeof (uint128_t));
			return;
		}
		log_debug(lg, "Get(%s): name index not found ENOENT", dev->name);
		uint512_logdump(lg, "NHID: ", &ron->name_hash_id);
		req->status = -ENOENT;
		return;
	} else if (err) {
		if (err != -EACCES && err != EBUSY) {
			log_error(lg, "Get(%s): error (%d) while reading versions",
			    dev->name, err);
			uint512_logdump(lg, "NHID: ", &ron->name_hash_id);
		}
		req->status = ron->generation ? -1 : RT_ERR_UNKNOWN;
		return;
	}

	assert(rb_vers->nbufs == 1);

	struct vlentry *found = (struct vlentry *)rtbuf(rb_vers, 0).base;
	assert(found->generation);
	log_debug(lg, "using generation: %" PRId64 ", query generation %" PRId64,
	    found->generation, ron->generation);
	req->named_rsp.object_name.uvid_timestamp = found->uvid_timestamp;
	req->named_rsp.object_name.name_hash_id = ron->name_hash_id;
	req->named_rsp.object_name.parent_hash_id = ron->parent_hash_id;
	req->named_rsp.object_name.generation = found->generation;
	req->content_length = found->vm_packed_length;

	/*
	 * Check to see if it is a query for NUVID and generation only, in
	 * which case it is a request for new PUT transaction and we must
	 * return generation + 1.
	 */
	if (msg->hdr.attributes & RD_ATTR_QUERY) {
		req->named_rsp.object_name.uvid_timestamp = COORDINATED_TS();
		if (req->named_rsp.object_name.uvid_timestamp <= found->uvid_timestamp) {
			req->named_rsp.object_name.uvid_timestamp = found->uvid_timestamp + 1;
		}
		req->named_rsp.object_name.generation = found->generation + 1;
	}
	if (found->object_deleted == RT_DELETED_LOGICALLY) {
		uint512_logdump(lg, "L-Deleted NHID: ", &ron->name_hash_id);
	}
	vm_chid = found->content_hash_id;

	uint512_logdump(lg, "NAMED-PUT NHID", &ron->name_hash_id);
	uint512_logdump(lg, "VERSION-MANIFEST", &vm_chid);

	rtbuf_destroy(rb_vers);


_vmm_return:
	if (req->content_length >  0) {
		req->rtproposed = 1;
		req->reqtype = GET_REQ_TYPE_NAMED_RT;
		req->named_rsp.immediate_content_length = 0;
		req->named_rsp.content_length = req->content_length;
		err = namedget_create_proposal(msg->object_name.uvid_timestamp,
		    msg->genid_delta, req);
		if (err) {
			req->status = RT_ERR_UNKNOWN;
			return;
		}

		req->chid = vm_chid;
		req->hash_type = hash_type;
		req->tt = TT_NAMEINDEX;
		req->named_rsp.content_hash_id = vm_chid;
		req->named_rsp.num_datagrams = 1;

		// extract the address from the message. RT_TRANSFER is later
		// sent to this address.
		memcpy(&req->client_addr.sin6_addr,
		    &msg->receive_tenant_addr, 16);
		req->client_addr.sin6_family = AF_INET6;
		req->client_addr.sin6_flowinfo = 0;
		req->client_addr.sin6_port = htons(msg->receive_tenant_port);
		req->client_addr.sin6_scope_id = ccow_daemon->if_indexes[0];
	} else {
		req->reqtype = GET_REQ_TYPE_NAMED;
		req->chid = vm_chid;
		req->hash_type = hash_type;
		req->tt = TT_NAMEINDEX;
		req->named_rsp.content_hash_id = vm_chid;
		req->named_rsp.content_length = rtbuf_len(rb);
		req->named_rsp.immediate_content_length
			= req->named_rsp.content_length;
		req->named_rsp.num_datagrams = 1;
	}

	// RT transfer later picks up the rtbuf read here
	// this is becuase (unlike unnamed rt) we have no way to do
	// a blob_stat on the version manifest to know the
	// size upfront.
	req->rb_reply = rb;
	req->status = 0;
}


/*
 * ACTION: process RT_NAMED_CHUNK_GET request
 */
static void
namedget_srv__request(struct state *st)
{
	struct getcommon_srv_req *req = st->data;

	log_trace(lg, "st %p", st);

	int err = srv_getcommon_proposal_work(st,
				namedget_exec, namedget_srv_done);
	if (err) {
		req->proposal_failed = 1;
		if (err == -ENOENT) {
			struct repmsg_named_chunk_get *msg = &req->msg_in.named_get;
			struct replicast_object_name *ron = &msg->object_name;
			struct repdev *dev = req->dev;
			fhrow_t row;
			int ngcount=0;

			/* send reply as not found, important for concensus */

			req->named_rsp.fddelta = req->err.fddelta = ccowd_get_fddelta();
			req->err.vdevid = dev->vdevid;
			SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_ngcount(SERVER_FLEXHASH,
				&ron->name_hash_id, &row, &ngcount), FH_LOCK_READ);
			if (err < 0) {
				/* ngcount error */
				req->status = RT_ERR_BAD_NGCOUNT;
			} else {
				if (ngcount <= 0)
					req->named_rsp.ngcount = 0;
				else
					req->named_rsp.ngcount = ngcount;
				req->err.ngcount = req->named_rsp.ngcount;
				/* not found */
				req->status = -ENOENT;
			}

			req->inexec++;
			dev->get_disk_qdepth++;
			namedget_srv_done(req, 0);
			return;
		}
		log_warn(lg, "Error starting proposal work st %p error %d",
			  st, err);
		state_next(st, EV_ERR);
	}
}

/*
 * Read version manifest work
 */
static void
vm_read_work(void* arg) {
	struct getcommon_srv_req *req = (struct getcommon_srv_req*) arg;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repmsg_named_chunk_get *msg = &req->msg_in.named_get;
	int hash_type = msg->hdr.hash_type;
	int err = 0;
	rtbuf_t *rb = NULL;


	err = reptrans_get_blob(dev, TT_VERSION_MANIFEST, hash_type, &req->chid,
		&rb);
_remove_bad_blob:
	if (err == -ENOENT) {
		char chidstr[UINT512_BYTES*2+1];
		char nhidstr[UINT512_BYTES*2+1];
		uint512_dump(&req->named_rsp.object_name.name_hash_id, nhidstr,
			UINT512_BYTES*2+1);

		uint64_t lookup_gen = req->named_rsp.object_name.generation;
		if (msg->hdr.attributes & RD_ATTR_QUERY)
			lookup_gen--;

		uint512_dump(&req->chid, chidstr, UINT512_BYTES*2+1);
		log_error(lg, "Get(%s): version manifest VMCHID %s NHID %s "
			"GEN %lu not found ht=%d err=%d", dev->name, chidstr,
			nhidstr, lookup_gen, hash_type, err);
		/*
		 * NED-5699 workaround.
		 * Could be races with purge. If there is a corresponding
		 * version entry - remove it.
		 */
		rtbuf_t* rb_ver = NULL;
		struct vlentry query = { .uvid_timestamp = ~0ULL,
			.generation = lookup_gen
		};
		err = reptrans_get_versions(dev,&req->named_rsp.object_name.name_hash_id,
			&query, &rb_ver);
		if (!err && rb_ver && rb_ver->nbufs) {
			struct vlentry* vle = (struct vlentry*)rb_ver->bufs->base;
			err = reptrans_delete_version_entry(dev, HASH_TYPE_DEFAULT,
				&req->named_rsp.object_name.name_hash_id, vle);
			if (err) {
				log_error(lg, "Dev(%s) version delete error %d",
					dev->name, err);
			} else
				log_notice(lg, "Dev(%s) removed version without VM,"
					" NHID %s GEN %lu", dev->name, nhidstr,
					lookup_gen);
			rtbuf_destroy(rb_ver);
		}
		req->status = -ENOENT;
		return;
	} else if (err) {
		log_error(lg, "Get(%s): version manifest: unknown error: %d",
			dev->name, err);
		uint512_logdump(lg, "NHID: ", &req->named_rsp.object_name.name_hash_id);
		uint512_logdump(lg, "VMCHID: ", &req->chid);
		req->status = RT_ERR_UNKNOWN;
		return;
	}

	if (dev->verify_chid == 2) {
		uint512_t tmp_chid;
		err = rtbuf_hash(rb, hash_type, &tmp_chid);
		if (err < 0) {
			log_error(lg, "Error calculating hash on namedget: %d",
				err);
			rtbuf_destroy(rb);
			req->status = RT_ERR_BAD_CRED;
			return;
		}
		if (uint512_cmp(&req->chid, &tmp_chid) != 0) {
			log_error(lg,
				"Get(%s): payload verification error detected "
				"seqid %d.%d", dev->name, ctx->sequence_cnt,
				ctx->sub_sequence_cnt);
			rtbuf_destroy(rb);
			uint512_logdump(lg, "content_hash_id", &req->chid);
			uint512_logdump(lg, "read_chid", &tmp_chid);
			if (ccow_daemon->keep_corrupted < 2) {
				err = -ENOENT;
				goto _remove_bad_blob;
			}
			req->status = RT_ERR_BAD_CRED;
			return;
		}
		log_debug(lg, "req %p VM chid verified, rb=%p", req, rb);
	}
	/*
	 * Read Version Mainifest metadata
	 */
	err = replicast_get_metadata(rb, &req->md);
	if (err) {
		log_error(lg, "Get(%s): metadata read error: %d", dev->name, err);
		rtbuf_destroy(rb);
		if (ccow_daemon->keep_corrupted < 2) {
			err = -ENOENT;
			goto _remove_bad_blob;
		}
		req->status = RT_ERR_UNKNOWN;
		return;
	}

	/* Track statistics */
	if (*req->md.oid && (req->md.track_statistics || ccow_daemon->track_statistics) &&
	    !trlog_skip(dev, &req->md)) {
		/* For performance reasons, collect only four max stats per device,
		 * two for GET and two for PUT */
		struct reptrans_devinfo_req *stat = &dev->stats;
		struct reptrans_gw_stats *gw_stats = NULL;
		if (msg->get_bw > stat->gw_stats_get_bw.get_bw)
			gw_stats = &stat->gw_stats_get_bw;
		else if (msg->put_bw > stat->gw_stats_put_bw.put_bw)
			gw_stats = &stat->gw_stats_put_bw;
		else if (msg->get_iops > stat->gw_stats_get_iops.get_iops)
			gw_stats = &stat->gw_stats_get_iops;
		else if (msg->put_iops > stat->gw_stats_put_iops.put_iops)
			gw_stats = &stat->gw_stats_put_iops;
		else if (msg->avg_get_latency > stat->gw_stats_get_lat.avg_get_latency)
			gw_stats = &stat->gw_stats_get_lat;
		else if (msg->avg_put_latency > stat->gw_stats_put_lat.avg_put_latency)
			gw_stats = &stat->gw_stats_put_lat;
		if (gw_stats) {
			uv_mutex_lock(&stat->gw_stat_mutex);
			memcpy(gw_stats->cid, req->md.cid, req->md.cid_size);
			memcpy(gw_stats->tid, req->md.tid, req->md.tid_size);
			memcpy(gw_stats->bid, req->md.bid, req->md.bid_size);
			memcpy(gw_stats->oid, req->md.oid, req->md.oid_size);
			gw_stats->put_iops = msg->put_iops;
			gw_stats->get_iops = msg->get_iops;
			gw_stats->put_bw = msg->put_bw;
			gw_stats->get_bw = msg->get_bw;
			gw_stats->avg_put_latency = msg->avg_put_latency;
			gw_stats->avg_get_latency = msg->avg_get_latency;
			gw_stats->svcinfo = msg->svcinfo;
			gw_stats->timestamp = get_timestamp_us();
			gw_stats->uvid_src_guid = req->md.uvid_src_guid;
			gw_stats->uvid_src_cookie = req->md.uvid_src_cookie;
			gw_stats->name_hash_id = req->named_rsp.object_name.name_hash_id;
			uv_mutex_unlock(&stat->gw_stat_mutex);
		}
	}

	req->content_length = rtbuf_len(rb);
	req->rb_reply = rb;
}

/*
 * Read version manifest work done
 */
static void
vm_read_work_done(void* arg, int status) {
	struct getcommon_srv_req *req = (struct getcommon_srv_req*) arg;
	struct repctx *ctx = req->ctx;
	struct state *st = ctx->state;


	if (!req->rb_reply) {
		log_error(lg, "Error st %p rb_reply %p", st, req->rb_reply);
		state_event(ctx->state, EV_ERR);
		return;
	}

	/* Request arrived from client via TCP */
	if (!req->accept_rcvd) {
		req->accept_rcvd = 1;
		srv_getcommon_setup_dummy_accept(req);
	}

	if (req->ctx->tcp_handle != NULL)
		req->client_addr = *(struct sockaddr_in6 *)&req->ctx->tcp_handle->toaddr;

	srv_getcommon_rtsend(req);
}

static void
namedget_srv__rtsend(struct state *st)
{
	struct getcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p", st);


	/*
	 * Start Version Manifest work if needed
	 */
	if (!req->rb_reply) {
		ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, vm_read_work,
			vm_read_work_done, req);
		return;
	}

	/* Request arrived from client via TCP */
	if (!req->accept_rcvd) {
		req->accept_rcvd = 1;
		srv_getcommon_setup_dummy_accept(req);
	}

	if (req->ctx->tcp_handle != NULL)
		req->client_addr = *(struct sockaddr_in6 *)&req->ctx->tcp_handle->toaddr;

	srv_getcommon_rtsend(req);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_NAMED_CHUNK_GET, &namedget_srv__request, ST_WAIT, NULL },
{ ST_WAIT, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS, &srv_getcommon_accept_rcvd,
	ST_READY, NULL},
{ ST_READY, RT_GET_ACCEPT_PROPOSED_RENDEZVOUS, &srv_getcommon_accept_rcvd,
	ST_READY, NULL},
{ ST_WAIT, RT_GET_RENDEZVOUS_TRANSFER, &namedget_srv__rtsend, ST_READY,
	&srv_getcommon_guard_rt_retry },
{ ST_READY, RT_GET_RENDEZVOUS_TRANSFER, &namedget_srv__rtsend, ST_READY,
	&srv_getcommon_guard_rt_retry },
{ ST_READY, EV_TIMEOUT, &srv_getcommon__rtfree, ST_READY, NULL},
{ ST_READY, RT_RENDEZVOUS_NACK, &srv_getcommon__rtfree, ST_TERM, NULL},
{ ST_READY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &namedget_srv__error, ST_TERM, NULL }
};

int
namedget_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state)
{
	int err;
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	struct getcommon_srv_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	req->start_timer_req = je_malloc(sizeof (*req->start_timer_req));
	if (!req->start_timer_req) {
		je_free(req);
		return -ENOMEM;
	}
	req->start_timer_req->data = NULL;

	req->timer_req = je_malloc(sizeof (*req->timer_req));
	if (!req->timer_req) {
		je_free(req->start_timer_req);
		je_free(req);
		return -ENOMEM;
	}
	req->timer_req->data = NULL;
	uv_timer_init(req->dev->loop, req->timer_req);

	req->start_timer_fd = uv_hpt_timer_init(req->dev->loop,
	    req->start_timer_req);
	if (req->start_timer_fd < 0) {
		err = req->start_timer_fd;
		je_free(req->timer_req);
		je_free(req->start_timer_req);
		je_free(req);
		log_error(lg, "PUT hpt start init error: %d", err);
		return err;
	}

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = srv_getcommon_terminate;
	ctx->stat_cnt = &robj->stats.namedget_active;
	reptrans_lock_ref(req->dev->robj_lock, ctx->stat_cnt);
	reptrans_io_avg(dev);
	return 0;
}
