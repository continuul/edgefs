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
#include "ccowd-impl.h"
#include "ccow-impl.h"
#include "state.h"
#include "opp-status.h"
#include "reptrans.h"
#include "erasure-coding.h"
#include "opp-status-srv.h"

extern struct ccowd *ccow_daemon;

struct opps_req {
	REQ_CLASS_FIELDS
	opp_status_t res;
	int status;
};

static void
opps__error(struct state *st)
{
	struct opps_req *req = st->data;
	log_trace(lg, "st %p", st);
}

static void
opps__term(struct state *st)
{
	struct opps_req *req = st->data;
	struct repdev *dev = req->dev;

	log_trace(lg, "st %p inexec %d", st, req->inexec);

	assert(req->inexec >= 0);
	repctx_drop(req->ctx);

	if (req->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    req, req->inexec);
		return;
	}

	reptrans_dev_ctxfree_one(dev, req->ctx);
}

static void
opps_send_ack__done(void *data, int err, int ctx_valid) {
	struct state *st = data;
	struct opps_req *req = st->data;
	struct repctx *ctx = req->ctx;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
	    data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;
	if (state_check(st, ST_TERM)) {
		opps__term(st);
		return;
	}
	if (req->res.vdevs_usage)
		je_free(req->res.vdevs_usage);

	if (err) {
		log_error(lg, "Error %d while sending OPP STATUS ACK",
			err);
		assert(err < 0);
		req->status = err;
		state_event(st, EV_ERR);
		return;
	}
	state_event(st, EV_DONE);
}

static void
opps_done(void *arg, int status) {
	struct state *st = arg;
	struct opps_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_opps *msg =
		(struct repmsg_opps *)wqe->msg;

	if (req->status == -EPERM || req->status == -ENOENT) {
		req->inexec--;
		/* Request is not for us, skiping*/
		state_event(st, EV_DONE);
		return;
	}
	struct repmsg_opps_result reply_msg;
	memset(&reply_msg, 0, sizeof(reply_msg));
	reply_msg.status = req->status;
	if (!req->status) {
		reply_msg.vmchid = msg->vmchid;
		reply_msg.n_cm_tl = req->res.n_cm_tl;
		reply_msg.n_cm_zl = req->res.n_cm_zl;
		reply_msg.n_cp = req->res.n_cp;
		reply_msg.n_cpar = req->res.n_cpar;
		reply_msg.n_cm_zl_verified = req->res.n_cm_zl_verified;
		reply_msg.n_cm_tl_verified = req->res.n_cm_tl_verified;
		reply_msg.n_cp_verified = req->res.n_cp_verified;
		reply_msg.n_cpar_verified = req->res.n_cpar_verified;
		reply_msg.n_cm_zl_1vbr = req->res.n_cm_zl_1vbr;
		reply_msg.n_cm_tl_1vbr = req->res.n_cm_tl_1vbr;
		reply_msg.n_cp_1vbr = req->res.n_cp_1vbr;
		reply_msg.n_cm_zl_lost = req->res.n_cm_zl_lost;
		reply_msg.n_cm_tl_lost = req->res.n_cm_tl_lost;
		reply_msg.n_cp_lost = req->res.n_cp_lost;
		reply_msg.n_cpar_lost = req->res.n_cpar_lost;
		reply_msg.n_cm_zl_pp = req->res.n_cm_zl_pp;
		reply_msg.n_cm_zl_erc_err = req->res.n_cm_zl_erc_err;
		reply_msg.n_cm_tl_erc_err = req->res.n_cm_tl_erc_err;
		reply_msg.pp_algo = req->res.pp_algo;
		reply_msg.pp_data_number = req->res.pp_data_number;
		reply_msg.pp_parity_number = req->res.pp_parity_number;
		reply_msg.pp_domain = req->res.pp_domain;
		reply_msg.hostid = req->res.hostid;
		reply_msg.n_vdevs = req->res.n_vdevs;
		reply_msg.vdevs_usage = req->res.vdevs_usage;
	}
	int err = replicast_send(dev->robj, ctx, RT_OPP_STATUS_ACK,
		(struct repmsg_generic *)&reply_msg,
		(struct repmsg_generic *)wqe->msg,
		NULL, 0, NULL, opps_send_ack__done, st,
		NULL);
	if (err) {
		req->inexec--;
		log_error(lg, "RT_RECOVERY_ACK operation error %d on send", err);
		req->status = err;
		state_event(st, EV_ERR);
	}
}

static void
opps_get_chunk_manifest_cb(struct getcommon_client_req *r)
{
	if (r->rb) {
		rtbuf_t *rbcopy = rtbuf_init_alloc(r->rb->bufs, r->rb->nbufs);
		rtbuf_t **rbuf = r->chunkmap_data;
		*rbuf = rbcopy;
	}
}

static int
opps_get_chunk_manifest(ccow_t cl, const uint512_t* chid, rtbuf_t **rbuf) {
	int err;
	struct ccow_op *get_op;
	struct ccow_io *get_io;
	ccow_completion_t c;

	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err)
		return err;

	err = ccow_operation_create(c, CCOW_GET, &get_op);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_unnamedget_create(c, opps_get_chunk_manifest_cb,
		get_op, &get_io, NULL);
	if (err) {
		ccow_operation_destroy(get_op, 1);
		ccow_release(c);
		return err;
	}

	get_io->attributes |= RD_ATTR_CHUNK_MANIFEST;

	struct getcommon_client_req *req = CCOW_IO_REQ(get_io);
	rtbuf_t *rb = NULL;

	req->chid = *chid;
	req->hash_type = HASH_TYPE_DEFAULT;
	req->chunkmap_data = &rb;

	err = ccow_start_io(get_io);
	if (err) {
		ccow_operation_destroy(get_op, 1);
		ccow_release(c);
		return err;
	}
	err = ccow_timed_wait(c, 0, 5000);
	if (err) {
		if (err == -EBUSY) {
			uv_mutex_lock(&c->operations_mutex);
			req->done_cb = NULL;
			uv_mutex_unlock(&c->operations_mutex);
		}
		return err;
	}

	if (rb == NULL)
		return -ENOMEM;

	*rbuf = rb;
	return 0;
}

static int
opps_get_manifest_chids(struct repdev* dev, ccow_t cl, const struct refentry* e,
	type_tag_t ttag, rtbuf_t* zl_chids, rtbuf_t* tl_chids, rtbuf_t* cp_chids,
	crypto_hash_t* cp_ht) {
	rtbuf_t* refs = NULL;
	rtbuf_t* rbc = NULL;
	int n_payload_refs = 0;
	int err = 0;

	assert(cp_ht);
	if (ttag == TT_VERSION_MANIFEST) {
		err = reptrans_get_blob(dev, ttag, HASH_TYPE_DEFAULT,
			&e->content_hash_id, &rbc);
		if (err) {
			log_error(lg, "Dev(%s) VM get error (local)", dev->name);
			return -ENOENT;
		}
	} else {
		/* Fetch the manifest from remote*/
		int err = opps_get_chunk_manifest(cl, &e->content_hash_id, &rbc);
		if (err) {
			log_error(lg, "Error fetching manifest: %d", err);
			return err;
		}
	}
	/* Extract references */
	err = ttag == TT_CHUNK_MANIFEST ?
		replicast_unpack_cm_refs(rbc, &refs, 0) :
		replicast_get_refs(rbc, &refs, 0);
	if (err) {
		log_error(lg, "Manifest unpack error");
		goto _exit;
	}
	assert(refs);
	/* For each non-payload reference start refs lookup (recursive) */
	for (size_t i = 0; i < refs->nbufs; ++i) {
		struct refentry* le = (struct refentry *)rtbuf(refs, i).base;
		int refType = RT_REF_TYPE(le);
		if (refType == RT_REF_TYPE_NORMAL) {
			n_payload_refs++;
			*cp_ht = RT_REF_HASH_TYPE(le);
			if (cp_chids) {
				uint512_t* cpChid = je_calloc(1, sizeof(uint512_t));
				if (!cpChid) {
					log_error(lg, "Memory allocation error");
					err = -ENOMEM;
					goto _exit;
				}
				*cpChid = le->content_hash_id;
				uv_buf_t uv_chid = {.len = sizeof(uint512_t),
					.base = (char*)cpChid };
				rtbuf_add(cp_chids, &uv_chid, 1);
			}
		} else if (refType == RT_REF_TYPE_MANIFEST) {
			err = opps_get_manifest_chids(dev, cl, le,
				TT_CHUNK_MANIFEST, zl_chids, tl_chids, cp_chids,
				cp_ht);
			if (err)
				goto _exit;
		}
	}

	if (ttag != TT_VERSION_MANIFEST) {
		uint512_t* refChid = je_calloc(1, sizeof(uint512_t));
		if (!refChid) {
			log_error(lg, "Memory allocation error");
			err = -ENOMEM;
			goto _exit;
		}
		*refChid = e->content_hash_id;
		uv_buf_t uv_chid = {	.len = sizeof(uint512_t),
					.base = (char*)refChid };
		if (n_payload_refs)
			err = rtbuf_add(zl_chids, &uv_chid, 1);
		else
			err = rtbuf_add(tl_chids, &uv_chid, 1);
	}

_exit:
	if (refs)
		rtbuf_destroy(refs);
	if (rbc)
		rtbuf_destroy(rbc);
	return err;
}

struct nglocate_cb_data {
	struct repdev *dev;
	volatile int completed;
	int status;
	uv_cond_t wait_cond;
	uv_mutex_t wait_mutex;
};

static int
opps_cm_get_info__callback(void *data, int32_t status, rtbuf_t* rb)
{
    struct nglocate_cb_data *rd = (struct nglocate_cb_data *)data;
    assert(rd != NULL);
    uv_mutex_lock(&rd->wait_mutex);
    rd->status = status;
    rd->completed++;
    uv_cond_signal(&rd->wait_cond);
    uv_mutex_unlock(&rd->wait_mutex);
    return 0;
}

static int
opps_cm_get_info(struct repdev* dev, rtbuf_t* chids, type_tag_t tt, crypto_hash_t ht,
	struct chunk_info** out, int* n_infos_out) {
	int err = 0;
	int n_infos = 0;
	struct chunk_info* res = je_calloc(chids->nbufs, sizeof(struct chunk_info));
	if (!res)
		return -ENOMEM;
	ccowd_fhready_lock(FH_LOCK_READ);
	size_t numrows = flexhash_numrows(SERVER_FLEXHASH);
	rtbuf_t* infos[numrows];
	memset(infos, 0, sizeof(rtbuf_t*)*numrows);
	/* Sort and create chunk_infos according to NG */
	for (size_t i = 0; i < chids->nbufs; i++) {
		const uint512_t* chid = (const uint512_t*)rtbuf(chids, i).base;
		fhrow_t row = HASHROWID(chid, SERVER_FLEXHASH);
		assert(row < numrows);
		struct chunk_info* einfo = res + n_infos++;
		einfo->chid = *chid;
		einfo->hash_type = ht;
		einfo->ttype = tt;

		uv_buf_t ub;
		ub.len = sizeof(struct chunk_info);
		ub.base = (char*)einfo;
		if (!infos[row]) {
			infos[row] = rtbuf_init_mapped(&ub, 1);
		} else {
			err = rtbuf_add_mapped(infos[row], &ub ,1);
			if (err) {
				ccowd_fhready_unlock(FH_LOCK_READ);
				goto _error_cleanup;
			}
		}
	}
	ccowd_fhready_unlock(FH_LOCK_READ);
	/* collecting NG-count requests */
	struct nglocate_cb_data cb_data;
	cb_data.completed = 0;
	cb_data.dev = dev;
	cb_data.status = 0;
	uv_cond_init(&cb_data.wait_cond);
	uv_mutex_init(&cb_data.wait_mutex);
	int err_status = 0;
	int64_t err_delay = NGREQUEST_TIMEOUT_MS/100 + 20;

	int n_reqs = 0;
	for (size_t i = 0; i < numrows; i++) {
		if (infos[i]) {
			n_reqs++;
			assert(infos[i]->nbufs <= (size_t)n_infos);
			err = ngrequest_locate(dev, infos[i], 0, NULL, 1,
				opps_cm_get_info__callback, &cb_data);
			if (err) {
				log_error(lg, "Error %d "
				"while sending ngcount request for row %lu",
				err, i);
				goto _error_cleanup;
			}
		}
	}
	/* Wait for ngrequest_locate() result */
	uv_mutex_lock(&cb_data.wait_mutex);
	while ((cb_data.completed < n_reqs) && !dev->terminating) {
		uv_cond_timedwait(&cb_data.wait_cond,
			&cb_data.wait_mutex, 100000000LL);
		/* If error was detected, then wait for a while
		 * and interrupt the loop
		 */
		if (cb_data.status < 0 && !err_status) {
			err_status = cb_data.status;
		}
		if (err_status && --err_delay == 0)
			break;
	}
	uv_mutex_unlock(&cb_data.wait_mutex);
	uv_mutex_destroy(&cb_data.wait_mutex);
	uv_cond_destroy(&cb_data.wait_cond);

	if (dev->terminating) {
		err = -ENODEV;
		goto _error_cleanup;
	} else if (cb_data.status) {
		log_error(lg, "Error %d processing ngrequest-locate",
		cb_data.status);
		err = cb_data.status;
		goto _error_cleanup;
	}

	for (size_t i = 0; i < numrows; i++) {
		if (infos[i])
			rtbuf_destroy(infos[i]);
	}
	*n_infos_out = n_infos;
	*out = res;
	return 0;

_error_cleanup:
	for (size_t i = 0; i < numrows; i++) {
		if (infos[i])
			rtbuf_destroy(infos[i]);
	}
	je_free(res);
	return err;
}

static int
opps_append_parity_chids(struct repdev* dev, ccow_t cl, const uint512_t* cmchid,
	const uint512_t* nhid, rtbuf_t* cpar, int32_t* domain, uint32_t* algo,
	uint32_t* fmt) {
	uv_buf_t pm_ub = { .len = 64*1024 };
	char chidstr[UINT512_BYTES*2+1];
	uint512_dump(cmchid, chidstr, UINT512_BYTES*2+1);
	struct ec_pset* psets = NULL;
	int n_sets = 0;

	pm_ub.base = je_calloc(1, pm_ub.len);
	if (!pm_ub.base)
		return -ENOMEM;
	uint64_t attr = RD_ATTR_NCOMP;
	attr |= nhid ? RD_ATTR_PARITY_MAP_VM : RD_ATTR_PARITY_MAP;
	int err = ec_unnamed_get_chunk(cl, cmchid, nhid,
		(nhid ? engcNHID : engcCHID), attr,
		HASH_TYPE_DEFAULT, cl->compress_type,
		&pm_ub);
	if (err) {
		log_error(lg, "Error unpacking parity manifest");
		goto _exit;
	}
	/* Unpack parity manifest */
	msgpack_u* u = msgpack_unpack_init(pm_ub.base, pm_ub.len, 0);
	if (!u) {
		log_error(lg, "Dev(%s) manifest %s err unpacking manifest",
			dev->name, chidstr);
		err = -ENOMEM;
		goto _exit;
	}
	err = ec_unpack_parity_map(u, &psets, &n_sets, domain, algo, fmt);
	msgpack_unpack_free(u);
	if (err) {
		log_error(lg, "Dev(%s) manifest %s err unpacking manifest",
			dev->name, chidstr);
		err = -EINVAL;
		goto _exit;
	}
	/* We may want to fetch only encoding parameters */
	if (!cpar)
		goto _exit;
	for (int i = 0; i < n_sets; i++) {
		struct ec_pset* e = psets + i;
		for (int j = 0; j < e->n_parity; j++) {
			uint512_t* pch = je_calloc(1, sizeof(uint512_t));
			if (!pch) {
				err = -ENOMEM;
				goto _exit;
			}
			uv_buf_t ub = { .base = (char*)pch, .len = sizeof(uint512_t) };
			*pch = e->parity[j].chid;
			err = rtbuf_add(cpar,&ub, 1);
			if (err)
				goto _exit;
		}
	}
_exit:
	if (psets)
		ec_clean_parity_sets(psets, n_sets);
	if (pm_ub.base)
		je_free(pm_ub.base);
	return err;
}

struct obj_chids {
	rtbuf_t* zl; /* Zero level anifests's CHIDs */
	rtbuf_t* tl; /* 1..top level manifest CHIDs */
	rtbuf_t* cp; /* CHIDs of chunk payloads */
	rtbuf_t* cpar; /* CHIDs of parity chunks */
	crypto_hash_t cp_ht;
};

static void
opps_exec(void *arg) {
	struct state *st = arg;
	struct opps_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	char chidstr[UINT512_BYTES*2+1];
	struct chunk_info* infos = NULL;
	struct vmmetadata md;
	size_t vm_len  = 0;
	int n_infos = 0;
	struct repmsg_opps *msg =
		(struct repmsg_opps *)wqe->msg;
	ccow_t cl = NULL;
	struct obj_chids oc = { .zl = NULL, .tl = NULL,
				.cp = NULL , .cpar = NULL};
	msgpack_u* u = NULL;
	struct ec_pset* psets = NULL;
	int n_sets = 0;
	int32_t domain = 0;
	uint32_t algo = 0;
	uint32_t fmt = 0;
	uv_buf_t pm_ub = { .len = 16384, .base = NULL };
	crypto_hash_t cp_ht = HASH_TYPE_DEFAULT;

	struct chunk_info vminfo = {
			.chid = msg->vmchid,
			.hash_type = HASH_TYPE_DEFAULT,
			.ttype = TT_VERSION_MANIFEST,
	};

	uint512_dump(&msg->vmchid, chidstr, UINT512_BYTES*2+1);
	/* Get VM to ensure it exists on current VDEV and
	 * to extract metadata
	 */
	rtbuf_t* rb = NULL;
	int err = reptrans_get_blob(dev, TT_VERSION_MANIFEST,
		HASH_TYPE_DEFAULT, &msg->vmchid, &rb);
	if (err) {
		if (err != -ENOENT)
			req->status = -EIO;
		else
			req->status = err;
		goto _exit;
	}
	err = replicast_get_metadata(rb, &md);
	if (err) {
		rtbuf_destroy(rb);
		req->status = -EIO;
		goto _exit;
	}
	vm_len = rtbuf_len(rb);
	rtbuf_destroy(rb);
	/* Handle request only on a device with minimal VDEV ID */
	memset(&req->res, 0, sizeof(req->res));
	err = ec_locate_chunk(dev, &vminfo, &md.nhid, 0);
	if (err) {
		log_error(lg, "Dev(%s) VM %s ngrequest_locate error",
			dev->name, chidstr);
		req->status = err;
		goto _exit;
	}
	for (size_t i = 0; i < vminfo.n_vdevs; i++) {
		if (uint128_cmp(&dev->vdevid, vminfo.vdevs + i) > 0) {
			log_debug(lg, "Dev(%s) VM %s skipped due to ID weight",
				dev->name, chidstr);
			req->status = -EPERM;
			goto _exit;
		}
	}
	/* Requesting object's CHIDs */
	cl = reptrans_get_tenant_context(dev->rt, 0);
	if (!cl) {
		req->status = -ENODEV;
		goto _exit;
	}
	/* Look up in a per object hash table first,
	 * If not found, fetch object CHIDs
	 */
	uv_mutex_lock(&dev->rt->opps_lock);
	if (hashtable_contains(dev->rt->chids_ht, &msg->vmchid,
		sizeof(msg->vmchid))){
		size_t sz = 0;
		struct obj_chids* c = NULL;
		c = hashtable_get(dev->rt->chids_ht, &msg->vmchid,
			sizeof(msg->vmchid), &sz);
		assert(sz == sizeof(struct obj_chids));
		oc = *c;
	} else {
		oc.zl = rtbuf_init_empty();
		if (!oc.zl) {
			req->status = -ENOMEM;
			goto _exit_unlock;
		}
		oc.tl = rtbuf_init_empty();
		if (!oc.tl) {
			req->status = -ENOMEM;
			goto _exit_unlock;
		}
		oc.cp = rtbuf_init_empty();
		if (!oc.cp) {
			req->status = -ENOMEM;
			goto _exit_unlock;
		}
		oc.cpar = rtbuf_init_empty();
		if (!oc.cpar) {
			req->status = -ENOMEM;
			goto _exit_unlock;
		}
		struct refentry e = {
			.content_hash_id = msg->vmchid,
			.name_hash_id = msg->nhid,
			.length = vm_len
		};
		err = opps_get_manifest_chids(dev, cl, &e, TT_VERSION_MANIFEST, oc.zl,
			oc.tl, oc.cp, &oc.cp_ht);
		if (err) {
			log_error(lg, "Dev(%s) error locating object's manifest",
				dev->name);
			req->status = -ENODEV;
			goto _exit_unlock;
		}
		err = hashtable_put(dev->rt->chids_ht, &msg->vmchid,
			sizeof(msg->vmchid), &oc, sizeof(oc));
		if (err) {
			log_error(lg, "Error adding new VM to a chids HT");
			req->status = -ENOENT;
			goto _exit_unlock;
		}
	}
	req->res.n_cm_tl = oc.tl->nbufs;
	req->res.n_cm_zl = oc.zl->nbufs;
	req->res.n_cp = oc.cp->nbufs;
	rtbuf_free(oc.cpar);
	if (!req->res.n_cm_tl && !req->res.n_cm_zl) {
		/* VM is the only manifest in the object.
		 * Consider it as a ZL manifest
		 */
		struct chunk_info vmppinfo = {
				.chid = msg->vmchid,
				.hash_type = HASH_TYPE_DEFAULT,
				.ttype = TT_PARITY_MANIFEST,
		};
		err = ec_locate_chunk(dev, &vmppinfo, &md.nhid, 2);
		if (err) {
			log_error(lg, "Error locating VM's parity manifest");
			req->status = -ENOENT;
			goto _exit_unlock;
		}

		if (vmppinfo.n_vdevs > 0) {
			err = opps_append_parity_chids(dev, cl,
				&msg->vmchid, &md.nhid, oc.cpar, &domain, &algo, &fmt);
			if(err) {
				log_error(lg, "Error adding parity chids: %d\n", err);
				goto _exit_unlock;
			}
			req->res.n_cm_zl_pp++;
		}
		req->res.n_cm_zl = 1;
		if (vminfo.n_vbrs_min) {
			req->res.n_cm_zl_verified++;
		}
		if (vminfo.n_vbrs_max) {
			req->res.n_cm_zl_1vbr++;
		}
	} else {
		/* Adding version manifest info */
		if (vminfo.n_vbrs_min) {
			req->res.n_cm_tl_verified++;
		}
		if (vminfo.n_vbrs_max) {
			req->res.n_cm_tl_1vbr++;
		}
		req->res.n_cm_tl++;
		/* Calculate erasure coding process status */
		err = opps_cm_get_info(dev, oc.zl, TT_PARITY_MANIFEST,
			HASH_TYPE_DEFAULT, &infos, &n_infos);
		if (err) {
			log_error(lg, "Dev(%s) error locating parity manifests",
				dev->name);
			req->status = err;
			goto _exit_unlock;
		}
		assert(infos);
		uint512_t* pm_chid = NULL;
		for (int i = 0; i < n_infos; i++) {
			if (infos[i].n_vdevs > 0) {
				req->res.n_cm_zl_pp++;
				err = opps_append_parity_chids(dev, cl,
					&infos[i].chid, NULL, oc.cpar, &domain, &algo,
					&fmt);
				if(err) {
					log_error(lg, "Error adding parity chids: %d\n", err);
					goto _exit_unlock;
				}
			} else if (msg->flags & OPP_STATUS_FLAG_NOPM) {
				uint512_dump(&infos[i].chid, chidstr,
					UINT512_BYTES*2+1);
				log_notice(lg, "NOPM %s", chidstr);
			}
		}
	}
	req->res.n_cpar = oc.cpar->nbufs;
	req->res.pp_algo = algo;
	FROM_CODECFMT(fmt, req->res.pp_data_number, req->res.pp_parity_number);
	req->res.pp_domain = domain;

	if (msg->flags & OPP_STATUS_FLAG_VERIFY) {
		/* request verification status */
		if (infos) {
			ec_clean_chunk_infos(infos, n_infos);
			infos = NULL;
		}
		err = opps_cm_get_info(dev, oc.zl, TT_CHUNK_MANIFEST,
			HASH_TYPE_DEFAULT, &infos, &n_infos);
		if (err) {
			log_error(lg, "Dev(%s) error locating chunk manifests",
				dev->name);
			req->status = err;
			goto _exit_unlock;
		}
		assert(infos);
		for (int i = 0; i < n_infos; i++) {
			if (!infos[i].n_vdevs) {
				req->res.n_cm_zl_lost++;
				if (msg->flags & OPP_STATUS_FLAG_LERR) {
					uint512_dump(&infos[i].chid, chidstr,
						UINT512_BYTES*2+1);
					log_error(lg, "CMZL LOST %s", chidstr);
				}
			}
			if (infos[i].n_vbrs_min > 0) {
				req->res.n_cm_zl_verified++;
			} else if (msg->flags & OPP_STATUS_FLAG_MISSVBR) {
				uint512_dump(&infos[i].chid, chidstr,
					UINT512_BYTES*2+1);
				log_notice(lg, "MISSVBR ZL %s", chidstr);
			}
			if (infos[i].n_vbrs_max > 0) {
				req->res.n_cm_zl_1vbr++;
			} else if (msg->flags & OPP_STATUS_FLAG_LACKVBR) {
				uint512_dump(&infos[i].chid, chidstr,
					UINT512_BYTES*2+1);
				log_notice(lg, "LACKVBR ZL %s", chidstr);
			}
			/* Calculate ERC */
			if (msg->flags & OPP_STATUS_FLAG_ERC) {
				int erc;
				SERVER_FLEXHASH_SAFE_CALL(erc =
					reptrans_get_effective_rep_count(
					infos[i].vdevs, infos[i].n_vdevs,
					cl->failure_domain), FH_LOCK_READ);
				if (erc < md.replication_count) {
					req->res.n_cm_zl_erc_err++;
					if (msg->flags & OPP_STATUS_FLAG_LERR) {
						uint512_dump(&infos[i].chid, chidstr,
							UINT512_BYTES*2+1);
						log_error(lg, "CMZL ERC ERR %s",
							chidstr);
					}
				}
			}
		}
		if (infos) {
			ec_clean_chunk_infos(infos, n_infos);
			infos = NULL;
		}
		err = opps_cm_get_info(dev, oc.tl, TT_CHUNK_MANIFEST,
			HASH_TYPE_DEFAULT, &infos, &n_infos);
		if (err) {
			log_error(lg, "Dev(%s) error locating chunk manifests",
				dev->name);
			req->status = err;
			goto _exit_unlock;
		}
		assert(infos);
		for (int i = 0; i < n_infos; i++) {
			if (!infos[i].n_vdevs) {
				req->res.n_cm_tl_lost++;
				if (msg->flags & OPP_STATUS_FLAG_LERR) {
					uint512_dump(&infos[i].chid, chidstr,
						UINT512_BYTES*2+1);
					log_error(lg, "CMTL LOST %s",
						chidstr);
				}
			}
			if (infos[i].n_vbrs_min > 0) {
				req->res.n_cm_tl_verified++;
			}else if (msg->flags & OPP_STATUS_FLAG_MISSVBR) {
				uint512_dump(&infos[i].chid, chidstr,
					UINT512_BYTES*2+1);
				log_notice(lg, "MISSVBR TL %s", chidstr);
			}
			if (infos[i].n_vbrs_max > 0) {
				req->res.n_cm_tl_1vbr++;
			} else if (msg->flags & OPP_STATUS_FLAG_LACKVBR) {
				uint512_dump(&infos[i].chid, chidstr,
					UINT512_BYTES*2+1);
				log_notice(lg, "LACKVBR TL %s", chidstr);
			}
			if (msg->flags & OPP_STATUS_FLAG_ERC) {
				int erc;
				SERVER_FLEXHASH_SAFE_CALL(erc =
					reptrans_get_effective_rep_count(
					infos[i].vdevs, infos[i].n_vdevs,
					cl->failure_domain), FH_LOCK_READ);
				if (erc < md.replication_count) {
					if (msg->flags & OPP_STATUS_FLAG_LERR) {
						uint512_dump(&infos[i].chid, chidstr,
							UINT512_BYTES*2+1);
						log_error(lg, "CMZL ERC ERR %s",
							chidstr);
					}
					req->res.n_cm_tl_erc_err++;
				}
			}
		}
		if (infos) {
			ec_clean_chunk_infos(infos, n_infos);
			infos = NULL;
		}
		err = opps_cm_get_info(dev, oc.cp, TT_CHUNK_PAYLOAD, oc.cp_ht, &infos,
			&n_infos);
		if (err) {
			log_error(lg, "Dev(%s) error locating chunk manifests",
				dev->name);
			req->status = err;
			goto _exit_unlock;
		}
		assert(infos);
		for (int i = 0; i < n_infos; i++) {
			if (!infos[i].n_vdevs) {
				req->res.n_cp_lost++;
				if (msg->flags & OPP_STATUS_FLAG_LERR) {
					uint512_dump(&infos[i].chid, chidstr,
						UINT512_BYTES*2+1);
					log_error(lg, "CP LOST %s", chidstr);
				}
			}
			if (infos[i].n_vbrs_min > 0) {
				req->res.n_cp_verified++;
			} else if (msg->flags & OPP_STATUS_FLAG_MISSVBR) {
				uint512_dump(&infos[i].chid, chidstr,
					UINT512_BYTES*2+1);
				log_notice(lg, "MISSVBR CP %s", chidstr);
			}
			if (infos[i].n_vbrs_max > 0) {
				req->res.n_cp_1vbr++;
			} else if (msg->flags & OPP_STATUS_FLAG_LACKVBR) {
				uint512_dump(&infos[i].chid, chidstr,
					UINT512_BYTES*2+1);
				log_notice(lg, "LACKVBR CP %s", chidstr);
			}
		}

		if ((msg->flags & OPP_STATUS_FLAG_CPAR) && oc.cpar) {
			if (infos) {
				ec_clean_chunk_infos(infos, n_infos);
				infos = NULL;
			}
			err = opps_cm_get_info(dev, oc.cpar, TT_CHUNK_PAYLOAD,
				PARITY_CHUNK_HASH_TYPE, &infos, &n_infos);
			if (err) {
				log_error(lg, "Dev(%s) error parity chunks",
					dev->name);
				req->status = err;
				goto _exit_unlock;
			}
			assert(infos);
			for (int i = 0; i < n_infos; i++) {
				if (!infos[i].n_vdevs) {
					req->res.n_cpar_lost++;
					if (msg->flags & OPP_STATUS_FLAG_LERR) {
						uint512_dump(&infos[i].chid, chidstr,
							UINT512_BYTES*2+1);
						log_error(lg, "PAR LOST %s",
							chidstr);
					}
				}
				if (infos[i].n_vbrs_min > 0) {
					req->res.n_cpar_verified++;
				}
			}
		}
	}
	/* Adding stats */
	req->res.hostid = server_get()->id;
	err = reptrans_get_vdevs_usage(&req->res.vdevs_usage);
	if (err < 0) {
		req->res.n_vdevs = 0;
	} else
		req->res.n_vdevs = err;

_exit_unlock:
	uv_mutex_unlock(&dev->rt->opps_lock);

_exit:
	if (u)
		msgpack_unpack_free(u);

	if (pm_ub.base)
		je_free(pm_ub.base);
	if (infos)
		ec_clean_chunk_infos(infos, n_infos);
	if (psets)
		ec_clean_parity_sets(psets, n_sets);
	if (cl)
		reptrans_put_tenant_context(dev->rt, cl);
}

void
opps_ht_destroy(struct reptrans* rt) {
	if (!rt->chids_ht)
		return;
	uv_mutex_lock(&rt->opps_lock);
	unsigned int n_keys = 0;
	uint512_t** keys = (uint512_t**)hashtable_keys(rt->chids_ht, &n_keys);
	for (unsigned int i = 0; i < n_keys; i++) {
		struct obj_chids* c = NULL;
		size_t vs = 0;
		c =  hashtable_get(rt->chids_ht, keys[i], sizeof(uint512_t),
			&vs);
		assert(c);
		assert(c->tl);
		assert(c->zl);
		rtbuf_destroy(c->zl);
		rtbuf_destroy(c->tl);
		rtbuf_destroy(c->cp);
		rtbuf_destroy(c->cpar);
	}
	hashtable_destroy(rt->chids_ht);
	if (keys)
		je_free(keys);
	uv_mutex_unlock(&rt->opps_lock);;
}

static void
opps__req(struct state *st) {
	struct opps_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	char chidstr[UINT512_BYTES*2+1];

	log_trace(lg, "Dev(%s): st %p, inexec %d", dev->name,
	    st, req->inexec);

	if (req->inexec) {
		state_next(st, EV_ERR);
		return;
	}

	struct repmsg_opps *msg =
		(struct repmsg_opps *)wqe->msg;

	uint512_dump(&msg->vmchid, chidstr, UINT512_BYTES*2+1);
	log_debug(lg, "Dev(%s) parity protection status request CHID %s\n",
		dev->path, chidstr);

	req->inexec++;
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_LOW, opps_exec, opps_done, st);

}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_OPP_STATUS, opps__req, ST_WAIT, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, opps__error, ST_TERM, NULL }
};

int
opps_request_init(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;
	struct opps_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb = opps__term;
	ctx->stat_cnt = &robj->stats.opp_status_active;
	reptrans_lock_ref(dev->robj_lock, ctx->stat_cnt);
	return 0;
}
