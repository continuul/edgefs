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
#include <uv.h>
#include <netinet/in.h>
#include <sys/user.h>
#include <wchar.h>
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>

#include "ccowutil.h"
#include "queue.h"
#include "reptrans.h"
#include "reptrans_bg_sched.h"
#include "replicast.h"
#include "json.h"
#include "clengine.h"
#include "ccowd-impl.h"
#include "ccow-impl.h"
#include "auditd.h"
#include "skiplist.h"
#include "erasure-coding.h"

static int
backref_blob_filter(void *arg, void **data, size_t *size, int set);

int reptrans_enqueue_batch(struct repdev *dev, char *msg, size_t msg_len)
{
	assert(dev != NULL);
	uint64_t ts = COORDINATED_TS();

	msgpack_u u;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || (status == REPDEV_STATUS_UNAVAILABLE ||
		status == REPDEV_STATUS_READONLY_FULL ||
		status == REPDEV_STATUS_READONLY_FORCED ||
		status == REPDEV_STATUS_READONLY_FAULT))
		return -ENODEV;
	msgpack_unpack_init_b(&u, msg, msg_len, 0);
	int err = msgpack_unpack_uint64(&u, &ts);
	if (err) {
		log_error(lg, "Dev(%s) batch TS unpack error", dev->name);
		return err;
	}

	log_debug(lg, "Dev(%s) adding incoming batch cts %lu", dev->name,
		ts);

	uint512_t key = uint512_null;
	key.u.u.u = ts;
	key.u.u.l = get_timestamp_us(dev);

	uv_buf_t data = { .base = msg, .len = msg_len };
	rtbuf_t *rb = rtbuf_init_mapped(&data, 1);
	assert(rb);

	err = reptrans_put_blob(dev, TT_BATCH_INCOMING_QUEUE,
		HASH_TYPE_DEFAULT, rb, &key, 0);
	rtbuf_destroy(rb);
	return err;
}

static void
update_hold_timeout(struct repdev *dev)
{
	int64_t vt = dev->verify_batch_delay;
	if (dev->verify_queue_delay > vt)
		vt = dev->verify_queue_delay;

	log_debug(lg, "Dev(%s) verify_batch_delay %ld verify_queue_delay %ld vt: %ld",
		dev->name, dev->verify_batch_delay, dev->verify_queue_delay, vt);

	int64_t new_timeout = dev->bg_config->speculative_backref_timeout_min + vt + vt;

	log_trace(lg, "Dev(%s) verification time %ld timeout %ld new_timeout: %ld",
		dev->name, vt, dev->bg_config->speculative_backref_timeout, new_timeout);

	dev->bg_config->speculative_backref_timeout = new_timeout;
}

int
reptrans_enqueue_batch_request(struct repdev *dev, uint512_t *nhid,
	struct verification_request *vreq)
{
	msgpack_p *p = msgpack_pack_init();
	assert(p);

	uint512_t orig_nhid = vreq->nhid;
	if (nhid)
		vreq->nhid = *nhid;

	int err = pack_batch_entry(p, vreq);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}

	if (nhid)
		vreq->nhid = orig_nhid;

	uint16_t n_groups = 0;
	SERVER_FLEXHASH_SAFE_CALL(n_groups = flexhash_numrows(SERVER_FLEXHASH), FH_LOCK_READ);
	uint512_t *nghid = (vreq->ttag == TT_VERSION_MANIFEST) ?
		(nhid ? nhid : &vreq->nhid) : &vreq->chid;
	uint16_t ng = HASHCALC(nghid, n_groups - 1);
	uint512_t batch_key = uint512_null;
	batch_key.u.u.u = NG_TO_KEY(ng);
	uv_buf_t batch_buf;
	msgpack_get_buffer(p, &batch_buf);
	rtbuf_t *batch_rb = rtbuf_init_mapped(&batch_buf, 1);
	assert(batch_rb);

	err = reptrans_put_blob(dev, TT_BATCH_QUEUE,
		HASH_TYPE_DEFAULT, batch_rb, &batch_key, 0);

	msgpack_pack_free(p);
	rtbuf_destroy(batch_rb);

	return err;
}

static int
reptrans_put_batch_request(struct repdev *dev, struct refentry *e,
	struct verification_request *vreq)
{
	uint8_t ref_ttag = ref_to_ttag[RT_REF_TYPE(e)];
	if (ref_ttag == TT_INVALID)
		return 0;
	if (uint512_cmp(&e->content_hash_id, &uint512_null) == 0)
		return 0;

	vreq->chid = e->content_hash_id;
	vreq->ttag = ref_ttag;
	vreq->htype = RT_REF_HASH_TYPE(e);

	uint64_t attr = reptrans_backref_ttag2attr(ref_ttag);
	BACKREF_SET_TTAG(&vreq->vbr, attr);

	uint512_t *nhid = NULL;
	if (RT_REF_TYPE(e) == RT_REF_TYPE_INLINE_VERSION)
		nhid = &e->name_hash_id;

	return reptrans_enqueue_batch_request(dev, nhid, vreq);
}

static int
reptrans_propagate_verification_request(struct repdev *dev,
	struct verification_request *vreq, uint64_t cts)
{
	rtbuf_t *refs = NULL;
	rtbuf_t *rbc = NULL;

	assert(vreq->ttag == TT_CHUNK_MANIFEST ||
		vreq->ttag == TT_VERSION_MANIFEST);

	uint64_t ts = get_timestamp_us();
	int err = reptrans_get_blob_verify(dev, vreq->ttag, HASH_TYPE_DEFAULT,
	    &vreq->chid, &rbc);

	char chidstr[UINT512_BYTES * 2 + 1];
	char ref_chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(&vreq->chid, chidstr, UINT512_BYTES * 2 + 1);
	uint512_dump(&vreq->vbr.ref_chid, ref_chidstr, UINT512_BYTES * 2 + 1);
	chidstr[16] = 0;
	ref_chidstr[16] = 0;

	if (err || rbc == NULL) {
		log_error(lg,
		    "Dev(%s): couldn't fetch manifest CHID: %s,"
		    " type: %s, err: %d\n", dev->name, chidstr,
		    type_tag_name[vreq->ttag], err);
		if (!(vreq->vtype & RT_VERIFY_DELETE)) {
			/* Undo verification - manifest is corrupt */
			err = reptrans_delete_blob(dev, TT_VERIFIED_BACKREF,
			    HASH_TYPE_DEFAULT, &vreq->chid);
			if (err) {
				log_debug(lg,
				    "Dev(%s): couldn't delete VBR CHID: %s",
				    dev->name, chidstr);
			} else {
				log_debug(lg,
				    "Dev(%s): gen %lu del VBR %s -> %s",
				    dev->name, vreq->generation, chidstr,
				    ref_chidstr);
			}
		}
		err = 0;
		goto _out;
	}

	/*
	 * Extract chunk references
	 */
	err = vreq->ttag == TT_CHUNK_MANIFEST ?
		replicast_unpack_cm_refs(rbc, &refs, 0) :
		replicast_get_refs(rbc, &refs, 0);
	if (err) {
		log_debug(lg,
		    "Corr. mainifest in ver. queue, CHID: %s, "
		    "type: %s, dev: %p\n",
		    chidstr, type_tag_name[vreq->ttag], dev);
		if (!(vreq->vtype & RT_VERIFY_DELETE)) {
			/* Undo verification - manifest is corrupt */
			err = reptrans_delete_blob(dev, TT_VERIFIED_BACKREF,
			    HASH_TYPE_DEFAULT, &vreq->chid);
			if (err) {
				log_debug(lg,
				    "Dev(%s): couldn't delete VBR CHID: %s",
				    dev->name, chidstr);
			} else {
				log_debug(lg,
				    "Dev(%s): gen %lu del VBR %s -> %s",
				    dev->name, vreq->generation, chidstr,
				    ref_chidstr);
			}
		}
		err = 0;
		goto _out;
	}

	assert(refs != NULL);
	/*
	 * At this point we set VBR at level N and now moving to level N+1.
	 * Re-using same VBREQ's vbr.
	 */
	vreq->vbr.ref_type = vreq->ttag;
	vreq->vbr.ref_chid = vreq->chid;
	vreq->vbr.ref_hash = HASH_TYPE_DEFAULT;
	/*
	 * Here backref points at
	 * - a version,
	 * - a version manifest or
	 * - a chunk manifest
	 * For versions, we need name hash id, generation and uvid.
	 * For version manifest we need its chid, name hash id and offset.
	 * For chunk manifest we need its chid and offset.
	 */
	if (vreq->vbr.ref_type != TT_NAMEINDEX) {
		vreq->vbr.generation = 0ULL;
		vreq->vbr.uvid_timestamp = 0ULL;
		if (vreq->vbr.ref_type != TT_VERSION_MANIFEST)
			memset(&vreq->vbr.name_hash_id, 0, sizeof(uint512_t));
		else {
			/* Always use VM's NHID */
			struct vmmetadata md;
			err = replicast_get_metadata(rbc, &md);
			if (err) {
				log_error(lg, "Dev(%s): cannot fetch metadata"
				    " from VM %s: %d", dev->name, chidstr, err);
				goto _out;
			}
			vreq->vbr.name_hash_id = md.nhid;
		}
	}
	rtbuf_destroy(rbc);
	rbc = NULL;
	uint512_dump(&vreq->vbr.ref_chid, ref_chidstr, UINT512_BYTES * 2 + 1);
	ref_chidstr[16] = 0;
	uint32_t i;
	for (i = 0; i < refs->nbufs; ++i) {

		struct refentry *e =
		    (struct refentry *)rtbuf(refs, i).base;

		uint512_dump(&e->content_hash_id, chidstr,
			UINT512_BYTES * 2 + 1);
		chidstr[16] = 0;
		err = reptrans_put_batch_request(dev, e, vreq);
		if (err) {
			log_error(lg, "Dev(%s): "
				"cannot add %s to batch, err %d\n",
				dev->name, chidstr, err);
			goto _out;
		}
		log_debug(lg,
			"Dev(%s): add gen %lu %s VBR %s -> %s to batch ref_cts %lu",
			dev->name, vreq->generation,
			(vreq->vtype & RT_VERIFY_DELETE) ? "del" : "put",
			chidstr, ref_chidstr, cts);
#if !VERIFY_NO_DELAYS
		if (job)
			bg_replicast_delay(dev, 0, job);
#endif
	}
_out:
	if (refs)
		rtbuf_destroy(refs);
	if (rbc)
		rtbuf_destroy(rbc);
	return err;
}


int
reptrans_verify_one_request(struct repdev *dev, struct verification_request *vbreq,
    uint32_t *n_verified, uint64_t cts)
{
	int err = 0;
	char chidstr[UINT512_BYTES * 2 + 1];
	char ref_chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(&vbreq->chid, chidstr, UINT512_BYTES * 2 + 1);
	uint512_dump(&vbreq->vbr.ref_chid, ref_chidstr, UINT512_BYTES * 2 + 1);
	chidstr[16] = 0;
	ref_chidstr[16] = 0;

	if (vbreq->ttag != TT_VERSION_MANIFEST &&
		vbreq->ttag != TT_CHUNK_MANIFEST &&
		vbreq->ttag != TT_CHUNK_PAYLOAD) {
		log_error(lg, "Dev(%s): wrong vbreq->ttag %d, corrupt vbreq?",
			dev->name, vbreq->ttag);
		return -EINVAL;
	}
	if (vbreq->vbr.ref_type != TT_CHUNK_MANIFEST &&
		vbreq->vbr.ref_type != TT_VERSION_MANIFEST &&
		vbreq->vbr.ref_type != TT_NAMEINDEX) {
		log_error(lg,
			"Dev(%s): wrong vbreq->vbr.ref_type %d, corrupt vbr?",
			dev->name, vbreq->vbr.ref_type);
		return -EINVAL;
	}

	/*
	 * Check if the chunk is stored locally
	 */
	uint64_t blob_size = 0;
	uint64_t blob_ts = 0;
	int maybe_exists = reptrans_blob_query(dev, vbreq->ttag, vbreq->htype,
		&vbreq->chid, &blob_size);
	if (maybe_exists)
		err = reptrans_get_blob_ts(dev, vbreq->ttag, vbreq->htype,
		    &vbreq->chid, &blob_ts);

	if (!maybe_exists || err) {
		log_debug(lg, "Dev(%s): gen %lu VBR %s cts %lu not local",
		    dev->name, vbreq->generation, chidstr, cts);
		return 0;
	}
	/*
	 * Check if this is a targeted request, and if yes if we are the target
	 */
	if (vbreq->target_vdevid.u != 0UL && vbreq->target_vdevid.l != 0UL) {
		log_debug(lg, "Dev(%s): target %lx%lx vdev %lx%lx", dev->name,
			vbreq->target_vdevid.u, vbreq->target_vdevid.l,
			dev->vdevid.u, dev->vdevid.l);

		if (vbreq->target_vdevid.u != dev->vdevid.u ||
			vbreq->target_vdevid.l != dev->vdevid.l)
			return 0;

		if (vbreq->vtype & RT_VERIFY_SKIP_UNVERIFIED) {
			/*
			 * This code is used to avoid VBR replication for chunk
			 * replicas which don't have a VBR yet.
			 * We are unsure why there are no VBRs: either because
			 * it's scheduled for deletion or not verified yet.
			 * In either case we postpone VBR replication until it
			 * gets verified in context of the object it was put within.
			 */
			size_t nvbrs = 0;
			err = reptrans_get_chunk_count_limited(dev, vbreq->htype,
			    TT_VERIFIED_BACKREF, &vbreq->chid, 1, &nvbrs);
			if (err || !nvbrs) {
				log_debug(lg, "Dev(%s) targeted propagation "
					"skipped due to lack of VBR(s): %s %016lX",
					dev->name, type_tag_name[vbreq->ttag],
					vbreq->chid.u.u.u);
				return 0;
			}

			struct backref br_ec = vbreq->vbr;
			br_ec.rep_count = 1;
			br_ec.attr |= VBR_ATTR_EC;
			err = reptrans_vbr_stat(dev, vbreq->htype, &vbreq->chid, &br_ec);
			if (!err) {
				log_debug(lg, "Dev(%s) targeted propagation "
					"skipped because there is an EC VBR with the same RefCHID: %s %016lX",
					dev->name, type_tag_name[vbreq->ttag],
					vbreq->chid.u.u.u);
				return 0;
			}
		}
		/*
		 * Targeted request is used to replace/remove VBR on
		 * a specified VDEV.
		 * 1. if (rep_count > 0 && !RT_VERIFY_DELETE) -> put new/remove old VBR(s) for this ref_Chid
		 * 2. if (rep_count > 0 && RT_VERIFY_DELETE) -> delete a backref with corresponding ref_chid and attr
		 * 3. if (rep_count == 0 && RT_VERIFY_DELETE) -> remove all VBRs for this ref_chid
		 */
		if (vbreq->vbr.rep_count > 0 && (vbreq->vtype & RT_VERIFY_NORMAL)) {
			err = reptrans_put_backref(dev, &vbreq->chid,
				vbreq->htype, &vbreq->vbr);
			if (err) {
				if (err != -EACCES)
					log_error(lg,
						"Dev(%s) couldn't put"
						" VBRs: %s, type: %s\n",
						dev->path, chidstr,
						type_tag_name[vbreq->vbr.ref_type]);
				else
					log_warn(lg,
						"Dev(%s) couldn't put"
						" VBRs: %s, type: %s, "
						"disk might be full\n",
						dev->path, chidstr,
						type_tag_name[vbreq->vbr.ref_type]);
				return err;
			}
			int n_del = 0;
			err = reptrans_delete_old_vbrs(dev, &vbreq->chid,
				vbreq->htype, &vbreq->vbr, &n_del);
			if (err && err != -ENOENT) {
				log_error(lg, "Dev(%s) couldn't delete"
					" old VBRs: %s, type: %s, "
					"err: %d\n", dev->path, chidstr,
					type_tag_name[vbreq->vbr.ref_type], err);
				return 0;
			}
			if (n_del)
				reptrans_touch_blob(dev, vbreq->ttag, vbreq->htype,
					&vbreq->chid);
			log_debug_vbr(lg, "Dev(%s): gen %lu tgt VBR %s -> %s,"
				"rep_cnt %u, attr %lu, ndel %d", dev->name, vbreq->generation,
				chidstr, ref_chidstr, vbreq->vbr.rep_count,
				vbreq->vbr.attr, n_del);
		} else if (vbreq->vbr.rep_count > 0 && (vbreq->vtype & RT_VERIFY_DELETE)) {
			int n_del = 0;
			err = reptrans_delete_vbrs_by_attr(dev, &vbreq->chid,
				vbreq->htype, &vbreq->vbr, &n_del);
			if (err && err != -ENOENT) {
				log_error(lg, "Dev(%s) couldn't delete"
					"q VBR: %s, type: %s, "
					"err: %d\n", dev->path, chidstr,
					type_tag_name[vbreq->vbr.ref_type], err);
				return 0;
			} else if (err != -ENOENT)
				log_debug_vbr(lg, "Dev(%s): gen %lu tgt attr_delete VBR %s -> %s,"
					"rep_cnt %u, attr %lu, ndel %d", dev->name, vbreq->generation,
					chidstr, ref_chidstr, vbreq->vbr.rep_count,
					vbreq->vbr.attr, n_del);
		} if (!vbreq->vbr.rep_count && (vbreq->vtype & RT_VERIFY_DELETE)) {
			int n_del = 0;
			err = reptrans_delete_vbrs_all_repcounts(dev, &vbreq->chid,
				vbreq->htype, &vbreq->vbr, &n_del);
			if (err && err != -ENOENT) {
				log_error(lg, "Dev(%s) couldn't delete"
					"q VBR: %s, type: %s, "
					"err: %d\n", dev->path, chidstr,
					type_tag_name[vbreq->vbr.ref_type], err);
				return 0;
			} else if (err != -ENOENT)
				log_debug_vbr(lg, "Dev(%s): gen %lu tgt attr_delete VBR %s -> %s,"
					"rep_cnt %u, attr %lu, ndel %d", dev->name, vbreq->generation,
					chidstr, ref_chidstr, vbreq->vbr.rep_count,
					vbreq->vbr.attr, n_del);
		}
		return 0;
	}

	/*
	 * Here we need to check if this is an encoding request
	 */
	if (vbreq->vtype & RT_VERIFY_PARITY) {
		err = reptrans_request_encoding(dev, vbreq);
		if (err || vbreq->ttag != TT_VERSION_MANIFEST)
			return err;
		vbreq->vtype &= ~RT_VERIFY_PARITY;
	}

	/*
	 * TODO: Consider moving pre/post count down to the driver.
	 * Ideally, an atomic put/delete operation should return them.
	 */
	size_t pre_ref_count = 0;
	size_t post_ref_count = 0;
	err = reptrans_get_chunk_count_limited(dev, vbreq->htype,
	    TT_VERIFIED_BACKREF, &vbreq->chid, 2, &pre_ref_count);
	if (err) {
		if (err != -ENOENT) {
			log_error(lg, "Dev(%s): gen %lu count"
			    " VBR %s failed %d", dev->name,
			    vbreq->generation, chidstr, err);
		} else {
			log_debug(lg, "Dev(%s): gen %lu count"
			    " VBR %s cts %lu failed %d", dev->name,
			    vbreq->generation, chidstr, cts, err);
			err = 0;
		}
	}
	post_ref_count = pre_ref_count;
	uint8_t ondemand_vtype = VTYPE_GET_ONDEMAND(vbreq->vtype);
	if (vbreq->vtype & RT_VERIFY_DELETE) {
		if (pre_ref_count) {
			/*
			 * Remove required VBR(s)
			 */
			int nvbrs = 0;
			err = reptrans_delete_vbrs_all_repcounts(dev, &vbreq->chid,
				vbreq->htype, &vbreq->vbr, &nvbrs);
			if (err) {
				log_error(lg, "Dev(%s): gen %lu del VBR %s -> "
					"%s, err %d", dev->name,
					vbreq->generation, chidstr, ref_chidstr,
					err);
				return err;
			}
			post_ref_count -= nvbrs;
			if (nvbrs)
				reptrans_touch_blob(dev, vbreq->ttag, vbreq->htype,
					&vbreq->chid);
			(*n_verified)++;
			log_debug_vbr(lg, "Dev(%s): gen %lu del VBR %s -> %s cts %lu",
			    dev->name, vbreq->generation, chidstr, ref_chidstr, cts);
		}
	} else {
		assert(vbreq->vbr.rep_count > 0);
		/* VMs can have different replication count */
		uint8_t tmp = vbreq->vbr.rep_count;
		if (vbreq->ttag == TT_VERSION_MANIFEST) {
			vbreq->vbr.rep_count =
				vbreq->vbr.rep_count > ccow_daemon->sync_put_named ?
					vbreq->vbr.rep_count : ccow_daemon->sync_put_named;
		} else if (ondemand_vtype == VTYPE_ONDEMAND_MDONLY || ondemand_vtype == VTYPE_ONDEMAND_VMONLY) {
			if (!pre_ref_count) {
				/* must be vmonly to mdonly conversion, adding a CM VBR */
				if (ondemand_vtype == VTYPE_ONDEMAND_MDONLY && !pre_ref_count && vbreq->ttag == TT_CHUNK_MANIFEST) {
					/* Add a new backref */
					err = reptrans_put_backref(dev, &vbreq->chid, vbreq->htype,
					    &vbreq->vbr);
				}
			} else {
				if ((ondemand_vtype == VTYPE_ONDEMAND_MDONLY && vbreq->ttag == TT_CHUNK_PAYLOAD) ||
					(ondemand_vtype == VTYPE_ONDEMAND_VMONLY && (vbreq->ttag == TT_CHUNK_PAYLOAD || vbreq->ttag == TT_CHUNK_MANIFEST))) {
					int nvbrs = 0;
					err = reptrans_delete_vbrs_all_repcounts(dev, &vbreq->chid,
						vbreq->htype, &vbreq->vbr, &nvbrs);
					if (err) {
						log_error(lg, "Dev(%s): gen %lu del VBR %s -> "
							"%s, err %d", dev->name,
							vbreq->generation, chidstr, ref_chidstr,
							err);
						return err;
					}
					if (nvbrs)
						reptrans_touch_blob(dev, vbreq->ttag, vbreq->htype,
							&vbreq->chid);
					(*n_verified)++;
					log_debug_vbr(lg, "Dev(%s): gen %lu unpers del VBR %s -> %s cts %lu",
					    dev->name, vbreq->generation, chidstr, ref_chidstr, cts);
				}
				if (pre_ref_count > 1) {
					/*
					 * mdonly and vmonly requests must be stopped at the first
					 * manifest which have more than 1 VBRs
					 */
					log_debug_vbr(lg, "Dev(%s): gen %lu unpin VBR %s not propagating",
					    dev->name, vbreq->generation, chidstr);
					return 0;

				}
			}
			goto _propagate;
		}
		/* Add a new backref */
		err = reptrans_put_backref(dev, &vbreq->chid, vbreq->htype,
		    &vbreq->vbr);
		vbreq->vbr.rep_count = tmp;
		if (err) {
			log_error(lg,
			    "Dev(%s): gen %lu put VBR %s -> %s, err %d",
			    dev->name, vbreq->generation, chidstr,
				ref_chidstr, err);
			return err;
		}
		(*n_verified)++;
		post_ref_count++;
		log_debug_vbr(lg, "Dev(%s): gen %lu put VBR %s -> %s cts %lu",
		    dev->name, vbreq->generation, chidstr, ref_chidstr, cts);
	}

_propagate:
	/* Propagating only manifest and only if number of theirs VBRs
	 * has been changed. Always propagate PERSIST/UNPERSIST requests
	 */
	if ((vbreq->ttag == TT_VERSION_MANIFEST || vbreq->ttag == TT_CHUNK_MANIFEST) &&
		(((vbreq->vtype & RT_VERIFY_DELETE) && pre_ref_count == 1
			&& post_ref_count == 0) ||
			(pre_ref_count == 0 && post_ref_count == 1) ||
			ondemand_vtype == VTYPE_ONDEMAND_PIN ||
			ondemand_vtype == VTYPE_ONDEMAND_MDONLY ||
			ondemand_vtype == VTYPE_ONDEMAND_VMONLY)) {
		const char* act = "put";
		if (vbreq->vtype & RT_VERIFY_DELETE)
			act = "del";
		else if (ondemand_vtype == VTYPE_ONDEMAND_PIN)
			act = "pin";
		else if (ondemand_vtype == VTYPE_ONDEMAND_MDONLY)
			act = "mdonly";
		else if (ondemand_vtype == VTYPE_ONDEMAND_VMONLY)
			act = "vmonly";
		else
			act = "unknown";
		log_debug_vbr(lg, "Dev(%s): gen %lu %s VBR %s cts %lu propagating",
		    dev->name, vbreq->generation, act, chidstr, cts);
		/* Propagation changes the request, give it a local copy */
		struct verification_request *preq = je_malloc(sizeof(*preq));
		if (!preq)
			return -ENOMEM;
		*preq = *vbreq;
		err = reptrans_propagate_verification_request(dev, preq, cts);
		je_free(preq);
		if (vbreq->vtype & RT_VERIFY_REPLICATE) {
			assert(!(vbreq->vtype & RT_VERIFY_DELETE));
			err = enqueue_replication(dev, vbreq->ttag,
			    vbreq->htype, &vbreq->chid, &vbreq->nhid,
			    vbreq->vbr.rep_count);
			if (err) {
				log_debug(lg, "Dev(%s): gen %lu %s VBR %s "
				    "replication request failed %d", dev->name,
				    vbreq->generation,
				    type_tag_name[vbreq->ttag], chidstr, err);
				err = 0; /* Not fatal */
			} else {
				log_debug_vbr(lg, "Dev(%s): gen %lu %s VBR %s "
				    "requested replication", dev->name,
				    vbreq->generation,
				    type_tag_name[vbreq->ttag], chidstr);
			}
		}
	} else {
		log_debug_vbr(lg, "Dev(%s): gen %lu %s VBR %s not propagating",
		    dev->name, vbreq->generation,
		    (vbreq->vtype & RT_VERIFY_DELETE) ? "del" : "put", chidstr);
	}
	return err;
}

static int
reptrans_process_one_batch(struct repdev *dev, char *msg, size_t msg_len,
	incoming_batch_work_t *work)
{
	assert(dev != NULL);
	assert(work != NULL);

	msgpack_u *u = msgpack_unpack_init(msg, msg_len, 0);
	if (u == NULL) {
		log_error(lg, "Cannot unpack batch: %d", -ENOMEM);
		return -ENOMEM;
	}
	uint64_t cts = 0;
	int err = msgpack_unpack_uint64(u, &cts);
	if (err) {
		log_error(lg, "Dev(%s) batch TS unpack error: %d", dev->name,
			err);
		return err;
	}
	struct verification_request vbreq;

	log_debug(lg, "Dev(%s) processing incoming batch cts %lu", dev->name,
		cts);
	int n = 0;
	ibatch_state_t* ibs = work->job->state;
	if (ibs->last_rep_count) {
		log_info(lg, "Dev(%s) batch queue processing resumed: %d, cts %lu",
			dev->name, ibs->last_rep_count, cts);
	}
	while (msgpack_unpack_len(u)) {
		/*
		 * Extract ver. queue entry
		 */
		uint64_t ts = 0;
		err = unpack_batch_entry(u, &vbreq, &ts);
		if (err) {
			log_error(lg, "Dev(%s) unpack_batch_entry failed %d",
				dev->name, err);
			break;
		}
		/* Skip already processed entries */
		if (ibs->last_entry_index > n) {
			n++;
			continue;
		}
		ibs->last_entry_index = 0;
		ibs->last_rep_count = 0;
		if (!dev->ibq_cleaned && (vbreq.vtype & RT_VERIFY_DELETE))
			continue;

		if (!(vbreq.vbr.attr & VBR_ATTR_EC) && vbreq.vbr.rep_count) {
			if(ccowd_get_fddelta() + (int)vbreq.vbr.rep_count <= 0) {
				/* Critical split.
				 * Stop processing, store state and return
				 */
				assert(ibs);
				ibs->last_entry_index = n;
				ibs->last_rep_count = vbreq.vbr.rep_count;
				msgpack_unpack_free(u);
				log_info(lg, "Dev(%s) batch queue processing "
					"interrupted, entry index %d, split "
					"level %d, rep_count %u, cts %lu", dev->name, n,
					ccowd_get_fddelta(), ibs->last_rep_count, cts);
				return -EAGAIN;
			}
		}
		if (dev->terminating) {
			msgpack_unpack_free(u);
			return -EAGAIN;
		}
#if !VERIFY_NO_DELAYS
		bg_replicast_delay(dev, 3000, work->job);
#endif
		err = reptrans_verify_one_request(dev, &vbreq, &work->n_verified, ts);
		if (err)
			log_error(lg, "Dev(%s): verify one request failed %d",
				dev->name, err);
		work->n_refs++;
		n++;
	}

	if (msgpack_unpack_len(u)) {
		/*
		 * Something went wrong, probably a bad request?
		 */
		log_error(lg, "Dev(%s): error during ngrequest unpack, err: %d,"
			" len: %u", dev->name, err, msgpack_unpack_len(u));
	} else {
		log_trace(lg, "Dev(%s): ngrequest: received %u refs, "
			"verified: %u, enqueud: %u", dev->name, work->n_refs,
			work->n_verified, work->n_queued);
	}

	msgpack_unpack_free(u);
	return err;
}

static int reptrans_enqueue_request(struct repdev *dev, type_tag_t ttag,
    struct verification_request *vbreq, uint512_t *vbreq_key)
{
	assert(dev != NULL);
	assert(dev->loop != NULL);;
	assert(vbreq != NULL);
	assert(vbreq->ttag == TT_VERSION_MANIFEST
		|| vbreq->ttag == TT_CHUNK_MANIFEST);
	assert(vbreq->vbr.ref_hash == HASH_TYPE_DEFAULT);

	uv_buf_t uvb = {
		.base = (char *)vbreq,
		.len = sizeof (struct verification_request)
	};
	rtbuf_t* rb = rtbuf_init_mapped(&uvb, 1);
	if (!rb)
		return -ENOMEM;

	int err = 0;

	uint512_t key = uint512_null;
	key.u.u.u = vbreq->vbr.name_hash_id.u.u.u;
	key.u.u.l = vbreq->generation;
	key.u.l.u = !!(vbreq->vtype & RT_VERIFY_DELETE);
	key.u.l.l = COORDINATED_TS();

	char keystr[UINT512_BYTES * 2 + 1];
	uint512_dump(&key, keystr, UINT512_BYTES * 2 + 1);
	keystr[32] = 0;

	err = reptrans_put_blob(dev, ttag, HASH_TYPE_DEFAULT, rb, &key, 0);
	if (err) {
		if (err != -EACCES)
			log_error(lg, "Dev(%s): Couldn't add entry %s to ver. queue: %d",
				dev->name, keystr, err);
		else
			log_warn(lg, "Dev(%s): Couldn't add entry %s to ver. queue: %d,"
				" disk might be full", dev->name, keystr, err);
	} else
		log_debug(lg, "Dev(%s): Added entry %s to ver. queue",
		    dev->name, keystr);

	if (!err && vbreq_key)
		*vbreq_key = key;

	char chidstr[UINT512_BYTES * 2 + 1];
	char ref_chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(&vbreq->chid, chidstr, UINT512_BYTES * 2 + 1);
	uint512_dump(&vbreq->vbr.ref_chid, ref_chidstr, UINT512_BYTES * 2 + 1);
	chidstr[16] = 0;
	ref_chidstr[16] = 0;

	log_debug_vbr(lg, "Dev(%s): req queued gen %lu %s VBR %s -> %s",
	    dev->name, vbreq->generation,
	    (vbreq->vtype & RT_VERIFY_DELETE) ? "del" : "put",
	    chidstr, ref_chidstr);

	if (rb)
		rtbuf_destroy(rb);
	return err;
}

int reptrans_request_verification(struct repdev *dev,
    struct verification_request *vbreq, uint512_t *vbreq_key)
{
	return reptrans_enqueue_request(dev, TT_VERIFICATION_QUEUE, vbreq,
	    vbreq_key);
}

int reptrans_request_encoding(struct repdev *dev,
    struct verification_request *vbreq)
{
	uv_buf_t ub = { .base = (char*)vbreq, .len = sizeof(*vbreq)};
	rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
	if (!rb)
		return -ENOMEM;
	int err =  reptrans_put_blob(dev, TT_ENCODING_QUEUE, HASH_TYPE_DEFAULT,
		rb, &vbreq->chid, 0);
	rtbuf_destroy(rb);
	return err;
}

static int
reptrans_verify_queue__callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param)
{
	int err = 0;
	uint32_t i = 0;
	struct verification_request *vbreq;
	verify_work_t* work = (verify_work_t *) param;
	rtbuf_t *rb = NULL;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE ||
		status == REPDEV_STATUS_READONLY_FULL ||
		status == REPDEV_STATUS_READONLY_FAULT ||
		status == REPDEV_STATUS_READONLY_FORCED)
		return -EACCES;

	if (work->verify_queue_items == 0) {
		int64_t  delta = (int64_t) (COORDINATED_TS() - key->u.l.l);
		log_debug(lg, "Dev(%s) verify queue delta: %ld", dev->name, delta);
		dev->verify_queue_delay = delta;
		update_hold_timeout(dev);
	}


	if (bg_job_wait_resume(work->job, 1000))
		return -ENODEV;

	/* We don't ask iterator for a blob, load it ourself */
	err = reptrans_get_blob(dev, ttag, hash_type, key, &rb);
	if (err) {
		log_error(lg, "Dev(%s) error reading verification queue entry: %d",
			dev->name, err);
		return 0;
	}
	assert(rb);
	work->verify_queue_items++;
	vbreq = (struct verification_request *)rb->bufs->base;

	char chidstr[UINT512_BYTES * 2 + 1];
	char ref_chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(&vbreq->chid, chidstr, UINT512_BYTES * 2 + 1);
	uint512_dump(&vbreq->vbr.ref_chid, ref_chidstr, UINT512_BYTES * 2 + 1);
	chidstr[16] = 0;
	ref_chidstr[16] = 0;

	assert(vbreq->ttag == TT_VERSION_MANIFEST ||
	    vbreq->ttag == TT_CHUNK_MANIFEST);
	assert(vbreq->vbr.ref_hash == HASH_TYPE_DEFAULT);
	assert(vbreq->vbr.ref_type == TT_CHUNK_MANIFEST ||
	    vbreq->vbr.ref_type == TT_VERSION_MANIFEST ||
	    vbreq->vbr.ref_type == TT_NAMEINDEX);

	if (!(vbreq->vtype & RT_VERIFY_DELETE) &&
		(vbreq->ttag == TT_VERSION_MANIFEST) &&
		(vbreq->vbr.ref_type == TT_NAMEINDEX)) {

		if (!(vbreq->vtype & RT_VERIFY_NO_QUARANTINE) &&
		    dev->bg_config->version_quarantine_timeout) {
			/* Do not verify VMs which are scheduled for purge */
			int has_version = reptrans_has_version(dev, HASH_TYPE_DEFAULT,
				&vbreq->vbr.name_hash_id, vbreq->vbr.generation);
			if(has_version <= 0) {
				log_info(lg, "Dev(%s) skipping verification of NHID.u.u.u %lX"
					" generation %lu", dev->name, vbreq->vbr.name_hash_id.u.u.u,
					vbreq->vbr.generation);
				goto _del_entry;
			}

			/* If application syncing too often, and there is a race with
			 * purge logic, there is no point in rushing on verification
			 * of this version, verify it later */
			if (key->u.l.l > (COORDINATED_TS() - dev->bg_config->version_quarantine_timeout)) {
				log_debug(lg, "Dev(%s) delaying verification of NHID.u.u.u %lX"
				    " generation %lu due to quarantine remaining %lds", dev->name,
				    vbreq->vbr.name_hash_id.u.u.u, vbreq->vbr.generation,
				    (key->u.l.l - (COORDINATED_TS() - dev->bg_config->version_quarantine_timeout))/1000000L);
				err = 0;
				goto _skip;
			}

			/* Remove "stable version" entry if a version has passed
			 * the quarantine */
			reptrans_stable_version_delete(dev, &vbreq->nhid);
			log_info(lg, "Dev(%s) object NHID %lX "
				" gen %lu has passed quarantine", dev->name,
				vbreq->vbr.name_hash_id.u.u.u, vbreq->generation);
		}
	}

	err = reptrans_verify_one_request(dev, vbreq, &work->n_verified, 0);
	if (err) {
		log_error(lg, "Dev(%s): verify gen %lu %s %s -> %s failed %d",
		    dev->name, vbreq->generation,
		    (vbreq->vtype & RT_VERIFY_DELETE) ? "del" : "put",
		    chidstr, ref_chidstr, err);
		err = 0;
	}

_del_entry:
	/*
	 * remove ver. queue entry
	 */
	err = reptrans_delete_blob(dev, ttag, HASH_TYPE_DEFAULT, key);
	if (err) {
		log_error(lg, "Couldn't remove entry from ver. queue\n");
		err = 0;
	}

	log_debug_vbr(lg, "Dev(%s): deleted req gen %lu %s %s -> %s",
	    dev->name, vbreq->generation,
	    (vbreq->vtype & RT_VERIFY_DELETE) ? "del" : "put",
	    chidstr, ref_chidstr);

_skip:
	if (rb)
		rtbuf_destroy(rb);

	return err;
}

typedef struct sbd_data {
	struct repdev *dev;
	uv_mutex_t wait_mutex;
	uv_cond_t wait_cond;
	volatile int completed;
	int status;
} sbd_data_t;

static void
send_batch_done(void *cb_data, int status)
{
	assert(cb_data != NULL);
	sbd_data_t *data = (sbd_data_t *)cb_data;

	nassert(data->dev->loop_thrid == uv_thread_self());

	uv_mutex_lock(&data->wait_mutex);
	data->status = status;
	data->completed = 1;
	uv_cond_signal(&data->wait_cond);
	uv_mutex_unlock(&data->wait_mutex);
}

static int
reptrans_verify_send_one_batch(verify_work_t *work, uint16_t ng, msgpack_p *p,
	uint32_t n_entries) {
	int err;
	struct repdev* dev = work->dev;

	nassert(dev->loop_thrid != uv_thread_self());

	sbd_data_t done_data;
	done_data.dev = dev;
	done_data.status = 0;
	done_data.completed = 0;
	uv_cond_init(&done_data.wait_cond);
	uv_mutex_init(&done_data.wait_mutex);

#if !VERIFY_NO_DELAYS
	/* go sleep to not create network storm */
	usleep(dev->verify_delay_avg*n_entries);
#endif

	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);
	uint64_t ts = get_timestamp_us();

	err = ngrequest_send(dev, ng, buf.base, buf.len,
		send_batch_done, &done_data);
	if (err) {
		log_error(lg, "Dev(%s): error sending ngrequest: %d", dev->name,
		    err);
		goto _exit;
	} else {
		log_trace(lg, "Dev(%s): sent ngrequest, ng: %d, len: %lu",
		    dev->name, ng, buf.len);
	}

	/* wait for batch send complete */
	uv_mutex_lock(&done_data.wait_mutex);
	while (!done_data.completed && !bg_job_is_term_forced(work->job))
		uv_cond_timedwait(&done_data.wait_cond, &done_data.wait_mutex,
			100000000LL);
	uv_mutex_unlock(&done_data.wait_mutex);

	ts = get_timestamp_us() - ts;

	if (bg_job_is_term_forced(work->job))
		err = -ENODEV;
	else
		err = done_data.status;

_exit:
	uv_mutex_destroy(&done_data.wait_mutex);
	uv_cond_destroy(&done_data.wait_cond);

#if !VERIFY_NO_DELAYS
	/* calculate entry verification time */
	uint64_t entry_delay = ts / n_entries;
	/* limit the delay value */
	if (VERIFY_MAX_DELAY_US < entry_delay)
		entry_delay = VERIFY_MAX_DELAY_US;

	/* average entry verification time */
	dev->verify_delay_avg = avg_ring_update(&dev->verify_avg_samples,
	    entry_delay);
#endif

	return err;
}


static int
reptrans_send_verification_batch_targeted(struct repdev* dev, uint16_t ng,
	const uint128_t* tgt_vdev, uv_buf_t data_buf) {
	int err;

	nassert(dev->loop_thrid != uv_thread_self());

	sbd_data_t done_data;
	done_data.dev = dev;
	done_data.status = 0;
	done_data.completed = 0;
	uv_cond_init(&done_data.wait_cond);
	uv_mutex_init(&done_data.wait_mutex);

	err = ngrequest_send_targeted(dev, ng, tgt_vdev, data_buf.base, data_buf.len,
		send_batch_done, &done_data);
	if (err) {
		log_error(lg, "Dev(%s): error sending targeted ngrequest: %d",
			dev->name, err);
		goto _exit;
	} else {
		log_trace(lg, "Dev(%s): sent targeted ngrequest, ng: %d, len: %lu",
		    dev->name, ng, data_buf.len);
	}

	/* wait for batch send complete */
	uv_mutex_lock(&done_data.wait_mutex);
	while (!done_data.completed && !dev->terminating)
		uv_cond_timedwait(&done_data.wait_cond, &done_data.wait_mutex,
			100000000LL);
	uv_mutex_unlock(&done_data.wait_mutex);

	if (dev->terminating)
		err = -ENODEV;
	else
		err = done_data.status;

_exit:
	uv_mutex_destroy(&done_data.wait_mutex);
	uv_cond_destroy(&done_data.wait_cond);
	return err;
}

int
reptrans_propagate_verification_request_targeted(struct repdev* dev,
	const uint128_t* tgt_vdev, struct verification_request* vreq) {

	msgpack_p* p = msgpack_pack_init();
	uint64_t ts = COORDINATED_TS();
	int err = msgpack_pack_uint64(p, ts);
	if (err)
		return err;

	err = pack_batch_entry(p, vreq);
	if (err)
		return err;
	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);
	uint16_t n_groups = 0;
	SERVER_FLEXHASH_SAFE_CALL(n_groups = flexhash_numrows(SERVER_FLEXHASH), FH_LOCK_READ);
	const uint512_t *nghid = (vreq->ttag == TT_VERSION_MANIFEST) ?
		&vreq->nhid : &vreq->chid;
	uint16_t ng = HASHCALC(nghid, n_groups - 1);

	err = reptrans_send_verification_batch_targeted(dev, ng, tgt_vdev, buf);
	msgpack_pack_free(p);
	return err;
}

static int
reptrans_verify_batch_all_filter(void *arg, void **data, size_t *size, int set)
{
	struct bg_job_entry* job = (struct bg_job_entry *)arg;
#if !VERIFY_NO_DELAYS
	bg_replicast_delay(job->sched->dev, 10000, job);
#endif
	return 1;
}
#define MAX_BATCH_SIZE 100000
#define MAX_BATCH_LIMIT_SSD 1000
#define MAX_BATCH_LIMIT_HDD 200
#define MAX_PACKET_SIZE (48 * 1024 - 40)
#define MAX_VERQ_LIMIT 10000

int
reptrans_verify_queue(verify_work_t *work)
{
	int err = -ENOMEM;
	assert(work != NULL);
	struct repdev *dev = work->dev;
	assert(dev != NULL);

	if (!dev->__vtbl)
		return -EPERM;

	err = reptrans_iterate_blobs_strict_order_limited(dev, TT_VERIFICATION_QUEUE,
	    reptrans_verify_queue__callback, work, 0, MAX_VERQ_LIMIT);

	if (err && (err == -ENODEV || err == -EACCES)) {
		return 0;
	}

	work->bytes_sent = 0;
	verify_state_t* vs = work->job->state;
	if (vs->rep_count_min) {
		log_info(lg, "Dev(%s) verification resumed", dev->name);
	}
	vs->rep_count_min = 0;
	uint64_t ng;
	uint16_t n_groups = flexhash_numrows(ccow_daemon->flexhash);
	for (ng = 0; ng < n_groups; ++ng) {
		uint512_t batch_key = uint512_null;
		batch_key.u.u.u = NG_TO_KEY(ng);
		rtbuf_t *rb = NULL;

		repdev_status_t status = reptrans_dev_get_status(dev);
		if (status == REPDEV_STATUS_UNAVAILABLE)
			return -EACCES;

		if (bg_job_is_term_forced(work->job))
			break;
#if !VERIFY_NO_DELAYS
		bg_replicast_delay(dev, 3000, work->job);
#endif

		err = dev->__vtbl->get_blob(dev, TT_BATCH_QUEUE,
		    HASH_TYPE_DEFAULT, GBF_FLAG_ALL, &batch_key, &rb,
		    MAX_BATCH_SIZE, reptrans_verify_batch_all_filter,
		    work->job);
		if (err) {
			if (err != -ENOENT)
				log_debug(lg, "Dev(%s): get_blob failed %lu: %d",
				    dev->name, ng, err);
			err = 0;
			continue;
		}

		if (!rb || !rb->nbufs) {
			if (rb)
				rtbuf_destroy(rb);
			continue;
		}

		log_debug(lg, "Dev(%s): found work in BATCH_QUEUE for NG %lu "
		    "nbufs %ld", dev->name, ng, rb->nbufs);

		msgpack_p *p = NULL;
		unsigned int j_prev = 0, j = 0;
		p = msgpack_pack_init();
		assert(p);
		uint64_t ts = COORDINATED_TS();
		err = msgpack_pack_uint64(p, ts);
		assert(!err);
		uint64_t bts = 0, bts_prev = 0;
		int min_rc = 0XFFFFF; /* Any value bigger than max possible repcount */
		for (j = 0; !err && j < rb->nbufs; j++) {

			struct verification_request vreq;
			msgpack_u* u = msgpack_unpack_init(rtbuf(rb, j).base,
				rtbuf(rb, j).len, 0);
			if (!u) {
				log_error(lg, "Dev(%s) malloc error", dev->name);
				continue;
			}
			err = unpack_batch_entry(u, &vreq, &bts);
			msgpack_unpack_free(u);
			if (err) {
				log_error(lg, "Dev(%s): corrupt batch request,"
				    " skipping", dev->name);
				continue;
			}
			/* Don't continue batch creation if we are in
			 * a critical split
			 */
			if (!(vreq.vbr.attr & VBR_ATTR_EC) &&
				vreq.vbr.rep_count &&
				min_rc > vreq.vbr.rep_count) {
				min_rc = vreq.vbr.rep_count;
			}
			if (dev->terminating) {
				msgpack_pack_free(p);
				return -ENODEV;
			}

			if (bts < bts_prev) {
				log_error(lg, "Dev(%s) batch timestamp out of "
					"order: %lu vs %lu", dev->name, bts,
					bts_prev);
			}
			bts_prev = bts;
			if (!dev->bq_cleaned && (vreq.vtype & RT_VERIFY_DELETE)) {
				/*
				 * Skip propagation of delete request at the
				 * first BG job pass. An outdated removal
				 * request can damage the next object generation
				 * or an affiliated object.
				 */
				continue;
			}
			if ((msgpack_get_len(p) + rtbuf(rb, j).len) <=
				MAX_PACKET_SIZE) {
				err = msgpack_put_buffer(p, &rb->bufs[j]);
				assert(!err);
				log_debug(lg, "Dev(%s) VBR %lX -> %lX added to batch row %u cts %lu",
					dev->name, vreq.chid.u.u.u, vreq.vbr.ref_chid.u.u.u, j, ts);
				continue;
			}
#if !VERIFY_NO_DELAYS
			bg_replicast_delay(dev, 3000, work->job);
#endif
			ccowd_fhready_lock(FH_LOCK_READ);
			uint64_t fh_gen = SERVER_FLEXHASH->genid;
			/* Stop batch entries propagation in a critical split */
			int fhp = flexhash_is_pristine(SERVER_FLEXHASH);
			if (!fhp || (ccowd_get_fddelta() && ccowd_get_fddelta() + min_rc <= 0)) {
				ccowd_fhready_unlock(FH_LOCK_READ);
				msgpack_pack_free(p);
				if (fhp)
					vs->rep_count_min = min_rc;
				log_info(lg, "Dev(%s) verification interrupted "
					"due to critical split %d, fh pristine: %d",
					dev->name, ccowd_get_fddelta(), fhp);
				return 0;
			}
			ccowd_fhready_unlock(FH_LOCK_READ);
			log_debug(lg, "Dev(%s) sending batch with cts %lu, fddelta %d, genig %lu",
				dev->name, ts, ccowd_get_fddelta(), fh_gen);

			err = reptrans_verify_send_one_batch(work, ng, p, j-j_prev);
			if (err || fh_gen != SERVER_FLEXHASH->genid ||
				!flexhash_is_pristine(SERVER_FLEXHASH)) {
				if (err != -ENODEV)
					log_warn(lg, "Dev(%s): Cannot send batch"
						" to NG %lu", dev->name, ng);
				if (rb)
					rtbuf_destroy(rb);
				msgpack_pack_free(p);
				return 0;
			}
			bg_has_slept_ms(dev->verify_delay_avg, work->job);
			work->batches_sent++;
			work->bytes_sent += msgpack_get_len(p);
			err = reptrans_delete_blob_value(dev,
			    TT_BATCH_QUEUE, HASH_TYPE_DEFAULT, &batch_key,
			    &rb->bufs[j_prev], j - j_prev);
			if (err) {
				log_warn(lg, "Dev(%s): cannot delete batch: %d",
				    dev->name, err);
				err = 0;
			}

			j_prev = j;
			msgpack_pack_free(p);
			p = msgpack_pack_init();
			assert(p);
			ts = COORDINATED_TS();
			err = msgpack_pack_uint64(p, ts);
			assert(!err);
			err = msgpack_put_buffer(p, &rb->bufs[j]);
			assert(!err);
		}

		if (err) {
			if (rb)
				rtbuf_destroy(rb);
			msgpack_pack_free(p);
			if (err != -ENODEV)
				continue;
			else
				break;
		}
#if !VERIFY_NO_DELAYS
		bg_replicast_delay(dev, 3000, work->job);
#endif
		ccowd_fhready_lock(FH_LOCK_READ);
		uint64_t fh_gen = SERVER_FLEXHASH->genid;
		/* Stop batch entries propagation in a critical split */
		int fhp = flexhash_is_pristine(SERVER_FLEXHASH);
		if (!fhp || (ccowd_get_fddelta() && ccowd_get_fddelta() + min_rc <= 0)) {
			ccowd_fhready_unlock(FH_LOCK_READ);
			if (rb)
				rtbuf_destroy(rb);
			msgpack_pack_free(p);
			if (fhp)
				vs->rep_count_min = min_rc;
			log_info(lg, "Dev(%s) verification interrupted "
				"due to critical split %d, fh pristine: %d",
				dev->name, ccowd_get_fddelta(), fhp);
			return 0;
		}
		ccowd_fhready_unlock(FH_LOCK_READ);
		log_debug(lg, "Dev(%s) sending batch with cts %lu, fddelta %d, "
			"genig %lu", dev->name, ts, ccowd_get_fddelta(), fh_gen);
		err = reptrans_verify_send_one_batch(work, ng, p, j-j_prev);
		if (err || fh_gen != SERVER_FLEXHASH->genid ||
			!flexhash_is_pristine(SERVER_FLEXHASH)) {
			if (err != -ENODEV)
				log_warn(lg, "Dev(%s): Cannot send batch"
					" to NG %lu", dev->name, ng);
			if (rb)
				rtbuf_destroy(rb);
			msgpack_pack_free(p);
			return 0;
		}
		work->batches_sent++;
		work->bytes_sent += msgpack_get_len(p);
		err = reptrans_delete_blob_value(dev, TT_BATCH_QUEUE,
		    HASH_TYPE_DEFAULT, &batch_key, &rb->bufs[j_prev],
		    j - j_prev);
		if (rb)
			rtbuf_destroy(rb);
		msgpack_pack_free(p);
		if (err) {
			log_warn(lg, "Dev(%s): cannot delete batch: %d",
			    dev->name, err);
			continue;
		}
	}
	return err;
}

static int
reptrans_process_batches__callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param)
{
	int err = 0;
	incoming_batch_work_t *work = (incoming_batch_work_t *)param;
	rtbuf_t* rb = NULL;

	if (work->n_batches == 0) {
		int64_t  delta = (int64_t) (COORDINATED_TS() - key->u.u.u);
		log_debug(lg, "Dev(%s) batches delta: %ld", dev->name, delta);
		dev->verify_batch_delay = delta;
		update_hold_timeout(dev);
	}
	/* Incoming batch queue processing involves all operation types:
	 * get, put an delete. So make sure we are allowed to perform them
	 */
	err = reptrans_refresh_status(dev, TT_BATCH_INCOMING_QUEUE, ioTypeWrite);
	if (err)
		return err;

	if (bg_job_wait_resume(work->job, 1000))
		return -ENODEV;

	/*
	 * Batch queue are ordered according to coordinated timestamp.
	 * An entry is removed when properly processed. So that, the currently
	 * processed entry is the last one in the queue. To store job state
	 * it's enough to keep an index of entry within a batch.
	 */
	err = reptrans_get_blob(dev, ttag, hash_type, key, &rb);
	if (err) {
		log_error(lg, "Dev(%s) error getting incoming batch queue entry: %d",
			dev->name, err);
		return 0;
	}
	assert(rb);
	assert(rb->nbufs);
	assert(rb->bufs);

	err = reptrans_process_one_batch(dev, rb->bufs->base, rb->bufs->len, work);
	if (err) {
		if (err != -EAGAIN)
			log_error(lg, "Couldn't process batch\n");
		else
			goto _out;
	} else
		++work->n_batches;
	/*
	 * remove batch incoming queue entry
	 */
	err = reptrans_delete_blob(dev, TT_BATCH_INCOMING_QUEUE,
		HASH_TYPE_DEFAULT, key);
	if (err) {
		log_error(lg,
			"Couldn't remove entry from batch incoming queue\n");
		err = 0;
	}
_out:
	if (rb)
		rtbuf_destroy(rb);
	pthread_yield();
	return err;
}

int
reptrans_process_batches(incoming_batch_work_t *work)
{
	int err = -ENOMEM;
	assert(work != NULL);
	struct repdev *dev = work->dev;
	assert(dev != NULL);
	ibatch_state_t* ibs = work->job->state;
	assert(ibs);

	if (ibs->last_rep_count && ccowd_get_fddelta() + ibs->last_rep_count <= 0)
		return 0;

	uint64_t ts = get_timestamp_us();
	uint32_t n_batches_cnt = 0;

	do {
		work->n_batches = 0;
		err = reptrans_iterate_blobs_strict_order_limited(dev, TT_BATCH_INCOMING_QUEUE,
				reptrans_process_batches__callback, work, 0,
				dev->stats.rotational ? MAX_BATCH_LIMIT_HDD : MAX_BATCH_LIMIT_SSD);
		n_batches_cnt += work->n_batches;
		/* keep processing if configured time/2 allows (in ms) */
	} while (!err && work->n_batches &&
	    ((get_timestamp_us() - ts)/1000UL) < 2*(uint64_t)dev->bg_config->incoming_batch_timer_ms / 3);
	work->n_batches = n_batches_cnt;
	dev->ibq_cleaned = 1;
	return err;
}
