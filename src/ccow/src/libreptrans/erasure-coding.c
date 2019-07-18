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

#include "clengine.h"
#include "ccow-impl.h"
#include "ccowd-impl.h"
#include "auditd.h"
#include "ccow.h"
#include "erasure-coding.h"
#include "reptrans_bg_sched.h"

#define EC_DEBUG 0

#if EC_DEBUG
#undef log_debug
#undef log_info
#undef log_trace
#define log_debug log_notice
#define log_info log_notice
#define log_trace log_notice
#endif

#define EC_GET_TIMEOUT	60000

extern struct ccowd *ccow_daemon;
QUEUE all_ec_codecs = QUEUE_INIT_STATIC(all_ec_codecs);

struct nglocate_cb_data {
    struct repdev *dev;
    volatile int completed;
    int status;
    uv_cond_t wait_cond;
    uv_mutex_t wait_mutex;
};

static int
nglocate__callback(void *data, int32_t status, rtbuf_t* rb)
{
    struct nglocate_cb_data *rd = (struct nglocate_cb_data *)data;
    assert(rd != NULL);
    uv_mutex_lock(&rd->wait_mutex);
    rd->status = status;
    rd->completed=1;
    uv_cond_signal(&rd->wait_cond);
    uv_mutex_unlock(&rd->wait_mutex);
    return 0;
}

int
ec_locate_chunk_ext(struct repdev* dev, struct chunk_info* info, uint512_t* nhid,
	struct backref* vbr, uint64_t attr_mask, size_t vbrs_max, uint32_t mode)
{
	struct nglocate_cb_data cb_data;
	char chidstr[UINT512_BYTES*2+1];
	uint512_dump(&info->chid, chidstr, UINT512_BYTES*2+1);
	chidstr[21] = 0;

	uv_buf_t ub = {.base = (char*)info, .len = sizeof(struct chunk_info)};
	rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
	cb_data.completed = 0;
	cb_data.dev = dev;
	cb_data.status = 0;
	uv_cond_init(&cb_data.wait_cond);
	uv_mutex_init(&cb_data.wait_mutex);

	int err = ngrequest_locate_ext(dev, rb, 0, nhid, vbr, attr_mask,
		vbrs_max, mode, nglocate__callback, &cb_data);
	if (err) {
		log_error(lg,
			"Error %d while sending nglocate request for CHID %s",
			err, chidstr);
		goto _cleanup;
	}

	/* Wait for ngrequest_locate() result */
	uv_mutex_lock(&cb_data.wait_mutex);
	while (!cb_data.completed && !dev->terminating)
		uv_cond_timedwait(&cb_data.wait_cond, &cb_data.wait_mutex,
			100000000LL);
	uv_mutex_unlock(&cb_data.wait_mutex);
	if (dev->terminating) {
		err = -ENODEV;
	} else if (cb_data.status) {
		err = cb_data.status;
	}

_cleanup:
	uv_mutex_destroy(&cb_data.wait_mutex);
	uv_cond_destroy(&cb_data.wait_cond);
	rtbuf_destroy(rb);
	return err;
}

int
ec_locate_chunk(struct repdev* dev, struct chunk_info* info, const uint512_t* nhid, size_t vbrs_max)
{
    struct nglocate_cb_data cb_data;
    char chidstr[UINT512_BYTES*2+1];
    uint512_dump(&info->chid, chidstr, UINT512_BYTES*2+1);
    chidstr[21] = 0;

    uv_buf_t ub = {.base = (char*)info, .len = sizeof(struct chunk_info)};
    rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
    cb_data.completed = 0;
    cb_data.dev = dev;
    cb_data.status = 0;
    uv_cond_init(&cb_data.wait_cond);
    uv_mutex_init(&cb_data.wait_mutex);

    int err = ngrequest_locate(dev, rb, 0, nhid, vbrs_max,
                    nglocate__callback, &cb_data);
    if (err) {
        log_error(lg,
            "Error %d while sending nglocate request for CHID %s",
            err, chidstr);
        goto _cleanup;
    }

    /* Wait for ngrequest_locate() result */
    uv_mutex_lock(&cb_data.wait_mutex);
    while (!cb_data.completed && !dev->terminating)
        uv_cond_timedwait(&cb_data.wait_cond, &cb_data.wait_mutex,
        100000000LL);
    uv_mutex_unlock(&cb_data.wait_mutex);
    if (dev->terminating) {
        err = -ENODEV;
    } else if (cb_data.status) {
        log_warn(lg,
            "Error %d after sending nglocate request for CHID %s",
            cb_data.status, chidstr);
        err = cb_data.status;
    }

    _cleanup:
    uv_mutex_destroy(&cb_data.wait_mutex);
    uv_cond_destroy(&cb_data.wait_cond);
    rtbuf_destroy(rb);
    return err;
}

#define EAGAIN_N_RETRIES	5

int
ec_locate_chunk_retry(struct repdev* dev, struct chunk_info* info, uint512_t* nhid,
	size_t vbrs_max) {
	int err = 0;
	int err_cnt = EAGAIN_N_RETRIES;
	int n_missing_match = 0;
	ccowd_wait_for_fhrebuild_term(&dev->terminating);
	if (dev->terminating)
		return -ENODEV;
	err = ec_locate_chunk(dev, info, nhid, vbrs_max);
	while ((err && err_cnt--)|| (!info->n_vdevs && n_missing_match < 3)) {
		ccowd_wait_for_fhrebuild_term(&dev->terminating);
		if (dev->terminating)
			return -ENODEV;
		usleep(100000);
		err = ec_locate_chunk(dev, info, nhid, vbrs_max);
		if (!err) {
			if (!info->n_vdevs)
				n_missing_match++;
			else
				n_missing_match = 0;
		} else
			n_missing_match = 0;
	}
	if (err_cnt < EAGAIN_N_RETRIES) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(&info->chid, chidstr, UINT512_BYTES*2+1);
		log_info(lg, "ec_locate_chunk_retry waited %d cycles,"
			"error code %d chunk %s, type %s",
			EAGAIN_N_RETRIES - err_cnt, err,
			chidstr, type_tag_name[info->ttype]);
	}
	return err;
}

static int
ec_get_chunk_info__callback(void *data, int32_t status, rtbuf_t* rb)
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

static int ref_chid_compare(const void *a, const void *b) {
	uv_buf_t* ab = (uv_buf_t*)a;
	uv_buf_t* bb = (uv_buf_t*)b;
	struct refentry* ea = (struct refentry*)ab->base;
	struct refentry* eb = (struct refentry*)bb->base;
	return uint512_cmp(&ea->content_hash_id, &eb->content_hash_id);
}

int
ec_get_chunk_info(struct repdev* dev, rtbuf_t* refs, struct backref* vbr, uint64_t attr_mask,
	size_t vbrs_max, uint32_t mode, struct chunk_info** out, int* n_infos_out) {
	int err = 0;
	int n_infos = 0;
	struct chunk_info* res = je_calloc(refs->nbufs, sizeof(struct chunk_info));
	if (!res)
		return -ENOMEM;

	ccowd_fhready_lock(FH_LOCK_READ);
	size_t numrows = flexhash_numrows(SERVER_FLEXHASH);
	assert(numrows);
	assert(numrows < 65536);
	rtbuf_t** infos = je_calloc(numrows, sizeof(rtbuf_t*));
	if (!infos) {
		je_free(res);
		return -ENOMEM;
	}

	/* Sort refs according to their CHIDs */
	uint512_t chid_prev = uint512_null;
	qsort(refs->bufs, refs->nbufs, sizeof(uv_buf_t), ref_chid_compare);

	/* Sort and create chunk_infos according to NG */
	for (size_t i = 0; i < refs->nbufs; i++) {
		struct refentry* e = (struct refentry*)rtbuf(refs, i).base;
		if (RT_REF_TYPE(e) != RT_REF_TYPE_NORMAL)
			continue;
		/* Skipping duplicates */
		if (!uint512_cmp(&chid_prev, &e->content_hash_id))
			continue;
		chid_prev = e->content_hash_id;
		fhrow_t row =
			HASHROWID(&e->content_hash_id, SERVER_FLEXHASH);
		assert(row < numrows);
		struct chunk_info* einfo = res + n_infos++;
		einfo->chid = e->content_hash_id;
		einfo->hash_type = RT_REF_HASH_TYPE(e);
		einfo->ttype = TT_CHUNK_PAYLOAD;
		einfo->size = e->compressed_length;

		uv_buf_t ub;
		ub.len = sizeof(struct chunk_info);
		ub.base = (char*)einfo;
		if (!infos[row]) {
			infos[row] = rtbuf_init_mapped(&ub, 1);
			if (!infos[row]) {
				log_error(lg, "Memory allocation error");
				ccowd_fhready_unlock(FH_LOCK_READ);
				goto _error_cleanup;
			}
		} else {
			err = rtbuf_add_mapped(infos[row], &ub ,1);
			if (err) {
				log_error(lg, "Memory allocation error");
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
			err = ngrequest_locate_ext(dev, infos[i], 0, NULL,
				vbr, attr_mask, vbrs_max, mode,
				ec_get_chunk_info__callback, &cb_data);
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

		if (cb_data.status < 0 && !err_status) {
			err_status = cb_data.status;
		}
	}
	uv_mutex_unlock(&cb_data.wait_mutex);
	uv_mutex_destroy(&cb_data.wait_mutex);
	uv_cond_destroy(&cb_data.wait_cond);

	if (dev->terminating) {
		err = -ENODEV;
		goto _error_cleanup;
	} else if (err_status) {
		log_error(lg, "Error %d processing ngrequest-locate",
			err_status);
		err = err_status;
		goto _error_cleanup;
	}
	for (size_t i = 0; i < numrows; i++) {
		if (infos[i])
			rtbuf_destroy(infos[i]);
	}
	*n_infos_out = n_infos;
	*out = res;
	if (infos)
		je_free(infos);
	return 0;

_error_cleanup:
	for (size_t i = 0; i < numrows; i++) {
		if (infos[i])
			rtbuf_destroy(infos[i]);
	}
	je_free(res);
	if (infos)
		je_free(infos);
	return err;
}

static int
ec_calc_missing_chunks(struct chunk_info* infos, int n_infos) {
	int ret = 0;
	for (int i = 0; i < n_infos; i++) {
		if (!infos[i].n_vdevs)
			ret++;
	}
	return ret;
}

int
ec_get_chunk_info_retry(struct repdev* dev, const uint512_t* mchid, rtbuf_t* refs,
	struct backref* vbr, uint64_t attr_mask, size_t vbrs_max, uint32_t mode,
	struct chunk_info** out, int* n_infos_out) {

	int err = 0;
	int n_missing = 0, n_missing_prev = 0;
	int n_missing_match_cnt = 0;
	int err_cnt = EAGAIN_N_RETRIES;
	struct chunk_info* infos = NULL;
	int n_infos = 0;

	ccowd_wait_for_fhrebuild_term(&dev->terminating);
	if (dev->terminating)
		return -ENODEV;
	/* For split safety we are going to repeat the chunk_info request
	 * several times until we get repeated number of missing chunks.
	 * We also repeat the request if an error occurs */
	err = ec_get_chunk_info(dev, refs, vbr, attr_mask, vbrs_max, mode,
		&infos, &n_infos);
	if (!err) {
		n_missing = ec_calc_missing_chunks(infos, n_infos);
	}
	while ((err && err_cnt--) || (n_missing != 0 && n_missing_match_cnt < 3)) {
		/* Wait for flexhash rebuild and repeat */
		ccowd_wait_for_fhrebuild_term(&dev->terminating);
		if (dev->terminating)
			return -ENODEV;
		if (infos) {
			ec_clean_chunk_infos(infos, n_infos);
			infos = NULL;
			n_infos = 0;
		}
		usleep(100000);
		err = ec_get_chunk_info(dev, refs, vbr, attr_mask, vbrs_max,
			mode, &infos, &n_infos);
		if (!err) {
			n_missing = ec_calc_missing_chunks(infos, n_infos);
			if (!n_missing)
				n_missing_match_cnt = 0;
			else if (n_missing == n_missing_prev)
				n_missing_match_cnt++;
			else
				n_missing_match_cnt = 0;
			n_missing_prev = n_missing;
		}
	}
	if (err_cnt < EAGAIN_N_RETRIES) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(mchid, chidstr, UINT512_BYTES*2+1);
		log_info(lg, "ec_get_chunk_info_retry waited %d cycles,"
			"error code %d manifest %s", EAGAIN_N_RETRIES - err_cnt,
			err, chidstr);
	}
	if (err) {
		ec_clean_chunk_infos(infos, n_infos);
		infos = NULL;
		n_infos = 0;
	}
	*out = infos;
	*n_infos_out = n_infos;
	return err;
}

int
ec_unnamed_put_chunk(ccow_t cl, const uv_buf_t* chunk,
    uint8_t rep_count, uint32_t attr, crypto_hash_t hash_type,
    const uint512_t* chid, void* vdev_nhid, uint512_t* out_chid) {

    ccow_completion_t c = NULL;
    
    int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
    if (err)
            return err;

    uint8_t select_policy = attr & RD_ATTR_TARGETED ?
                    CCOW_SELECT_POLICY_NONE : CCOW_SELECT_POLICY_SPACE;
    err = ccow_attr_modify_default(c, CCOW_ATTR_SELECT_POLICY,
        (void *)&select_policy, NULL);
    if (err) {
        log_error(lg, "ec_unnamed_put_chunk: set policy, err %d", err);
        ccow_release(c);
        return err;
    }

    if (attr & RD_ATTR_TARGETED)
    	rep_count = 1;

    err = ccow_attr_modify_default(c, CCOW_ATTR_REPLICATION_COUNT,
        (void *)&rep_count, NULL);
    if (err) {
        log_error(lg, "ec_unnamed_put_chunk: set repcnt, err %d", err);
        ccow_release(c);
        return err;
    }

    uint8_t ht = hash_type;
    err = ccow_attr_modify_default(c, CCOW_ATTR_HASH_TYPE, (void *)&ht, NULL);

    if (err) {
        log_error(lg, "ec_unnamed_put_chunk: set hash type, err %d", err);
        ccow_release(c);
        return err;
    }

    attr |= RD_ATTR_RETRY_FAILFAST;

    err = ccow_admin_pseudo_put_chunks((struct iovec*)chunk, 1, attr,
        (const char*)chid, (const char*)vdev_nhid, c);

    if (!err) {
	err = ccow_wait(c, -1);
	if (err) {
		type_tag_t tt = attr_to_type_tag(attr);
		if (attr & RD_ATTR_TARGETED) {
			char vdevstr[UINT128_BYTES*2+1];
			char chidstr[UINT512_BYTES*2+1];
			uint128_t* vdev = (uint128_t*)vdev_nhid;
			uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
			uint128_dump(vdev, vdevstr, UINT128_BYTES*2+1);
			log_error(lg, "Targeted put error CHID %s type %s VDEV %s: %d",
				chidstr, type_tag_name[tt], vdevstr, err);
		} else
			log_error(lg, "%s put failed: %d\n", type_tag_name[tt], err);
	}
    } else
	ccow_release(c);
    return err;
}

int
ec_unnamed_put_chunk_retry(ccow_t cl, const uv_buf_t* chunk,
    uint8_t rep_count, uint32_t attr, crypto_hash_t hash_type,
    const uint512_t* chid, void* vdev_nhid, uint512_t* out_chid) {
	int r_cnt = EAGAIN_N_RETRIES;
	int err = ec_unnamed_put_chunk(cl, chunk, rep_count, attr, hash_type,
		chid, vdev_nhid, out_chid);
	while (err && (err == -EBUSY || err == -EAGAIN) && r_cnt--) {
		struct ccow *tc = cl;
		ccowd_wait_for_fhrebuild_term(&tc->abort);
		usleep(100000);
		err = ec_unnamed_put_chunk(cl, chunk, rep_count, attr, hash_type,
				chid, vdev_nhid, out_chid);
	}
	if (r_cnt < EAGAIN_N_RETRIES) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
		log_info(lg, "ec_unnamed_put_chunk_retry waited %d cycles,"
			"error code %d chunk %s",
			EAGAIN_N_RETRIES - r_cnt, err,
			chidstr);
	}
	return err;

}

struct ec_get_cb_arg {
	uv_cond_t cond;
	uv_mutex_t lock;
	int   status;
	volatile int done;
};

static void
ec_unnamed_get_chunk_cb(struct getcommon_client_req *r) {
	uv_buf_t* ub = (uv_buf_t*)r->data;
	if (!r->io->op->chunks)
		return;
	memcpy(ub->base, r->io->op->chunks->bufs->base,
		r->io->op->chunks->bufs->len);
	ub->len = r->io->op->chunks->bufs->len;
}

int
ec_unnamed_get_chunk(ccow_t cl, const uint512_t* chid, const void* ng_arg,
	ecNgCalcMode ngMode, uint64_t attr, crypto_hash_t hash_type,
	uint8_t comp_type, uv_buf_t* result ) {

	struct ccow_op *ug_op;
	struct ccow_io *get_io;
	int err = 0;

	uint512_t ng_chid = uint512_null;
	if (ngMode == engcCHID)
		ng_chid = *chid;
	else if (ngMode == engcNHID) {
		assert(ng_arg);
		ng_chid = *(uint512_t*)ng_arg;
	} else if (ngMode == engcVDEV) {
		/* In targeted mode we generate a synthetic NHID based
		 * on NG number
		 */
		assert(ng_arg);
		fhrow_t ng = 0;
		SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_vdev_row(SERVER_FLEXHASH,
			(uint128_t *)ng_arg, &ng), FH_LOCK_READ);
		if (err) {
			char vdevstr [UINT128_BYTES*2 + 1];
			uint128_dump((const uint128_t *)ng_arg, vdevstr,
				UINT128_BYTES*2 + 1);
			log_error(lg, "Flexhash couldn't find VDEV ID %s", vdevstr);
			return -ENODEV;
		}
		ng_chid.u.u.u = ng;
	} else
		ng_chid.u.u.u = *(fhrow_t*)ng_arg;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err)
		return err;
	err = ccow_operation_create(c, CCOW_CLONE, &ug_op);
	if (err) {
		ccow_release(c);
		return err;
	}
	err = ccow_unnamedget_create(c, ec_unnamed_get_chunk_cb, ug_op,
		&get_io, NULL);
	if (err) {
		ccow_operation_destroy(ug_op, 1);
		ccow_release(c);
		log_error(lg, "error returned by ccow_unnamedget_create: %d",
		err);
		return err;
	}
	ug_op->iov_in = NULL;
	ug_op->iovcnt_in = 0;
	ug_op->offset = 0;
	ug_op->chunks = rtbuf_init_alloc_one(result->len);
	get_io->attributes = attr;

	struct getcommon_client_req *req = CCOW_IO_REQ(get_io);

	req->chid = *chid;
	req->offset = 0;
	req->hash_type = hash_type;
	req->compress_type = comp_type;
	req->data = result;
	req->ng_chid = ng_chid;

	err = ccow_start_io(get_io);

	if (err) {
		ccow_operation_destroy(ug_op, 1);
		ccow_release(c);
	} else {
		err = ccow_timed_wait(c, -1, EC_GET_TIMEOUT);
		if (err == -EBUSY) {
			uv_mutex_lock(&c->operations_mutex);
			req->done_cb = NULL;
			uv_mutex_unlock(&c->operations_mutex);
		}
		if (err)
			log_error(lg,"get chunk error: %d", err);
	}
	return err;
}

static int
ec_targeted_delete(ccow_t cl, const uint512_t* chid, type_tag_t tt,
	crypto_hash_t ht, const uint128_t* vdev) {
	char aux;
	uv_buf_t ub_fake = { .len = 1, .base = &aux };
	uint32_t attr = type_tag_to_attr(tt);
	attr |= RD_ATTR_NCOMP |
		RD_ATTR_TARGETED_DELETE |
		RD_ATTR_TARGETED;
	int err = ec_unnamed_put_chunk_retry(cl, &ub_fake, 1, attr, ht, chid,
		(uint128_t*)vdev, NULL);
	return err;
}

static int
ec_enqueue_batch(struct repdev* dev, struct verification_request* vbreq,
		volatile struct flexhash* fh);

static int
ec_targeted_propagate_vbr(struct repdev* dev, const uint512_t* chid, type_tag_t tt,
	crypto_hash_t ht, const uint128_t* vdev, struct backref* vbr, uint8_t vtype) {
	struct verification_request vreq = {
		.vtype = vtype,
		.chid = *chid,
		.nhid = uint512_null,
		.target_vdevid = *vdev,
		.uvid_timestamp = 0,
		.generation = 0,
		.ttag = tt,
		.htype = ht,
		.vbr = *vbr
	};
	return ec_enqueue_batch(dev, &vreq, SERVER_FLEXHASH);
}

void
reptrans_manifest_unlock(struct repdev* dev, struct manifest_lock_entry *re,
	manifest_lock_status_t status) {
	uv_mutex_lock(&re->cond_lock);
	re->status = status;
	uv_cond_signal(&re->cond_var);
	uv_mutex_unlock(&re->cond_lock);
	uv_mutex_lock(&dev->rt->recovery_queue_mutex);
	re->stale = 1;
	re->ref_cnt--;
	if (!re->ref_cnt && re->stale) {
		QUEUE_REMOVE(&re->item);
		je_free(re);
	}
	uv_mutex_unlock(&dev->rt->recovery_queue_mutex);
}

struct manifest_lock_entry *
reptrans_manifest_trylock(struct repdev* dev, const uint512_t* chid) {
	struct manifest_lock_entry* re = NULL;
	QUEUE *q = NULL;

	uv_mutex_lock(&dev->rt->recovery_queue_mutex);
	QUEUE_FOREACH(q, &dev->rt->recovery_queue) {
		re = QUEUE_DATA(q, struct manifest_lock_entry, item);
		if (!re->stale && !uint512_cmp(&re->chid, chid)) {
			uv_mutex_unlock(&dev->rt->recovery_queue_mutex);
			return NULL;
		}
	}
	re = je_calloc(1, sizeof(*re));
	if (!re) {
		uv_mutex_unlock(&dev->rt->recovery_queue_mutex);
		return NULL;
	}
	re->chid = *chid;
	uv_mutex_init(&re->cond_lock);
	uv_cond_init(&re->cond_var);
	re->ref_cnt = 1;
	re->stale = 0;
	re->status = MANIFEST_PROCESSING;
	QUEUE_INIT(&re->item);
	QUEUE_INSERT_TAIL(&dev->rt->recovery_queue, &re->item);
	uv_mutex_unlock(&dev->rt->recovery_queue_mutex);
	return re;
}

struct manifest_lock_entry *
reptrans_manifest_lock_or_wait(struct repdev* dev, const uint512_t* chid,
	manifest_lock_status_t* status) {
	QUEUE *q = NULL;
	struct manifest_lock_entry* re = NULL;
	uv_mutex_lock(&dev->rt->recovery_queue_mutex);
	QUEUE_FOREACH(q, &dev->rt->recovery_queue) {
		re = QUEUE_DATA(q, struct manifest_lock_entry, item);
		if (!re->stale && !uint512_cmp(&re->chid, chid)) {
			manifest_lock_status_t st;
			uv_mutex_lock(&re->cond_lock);
			re->ref_cnt++;
			uv_mutex_unlock(&dev->rt->recovery_queue_mutex);
			while((st = re->status) == MANIFEST_PROCESSING)
				uv_cond_timedwait(&re->cond_var, &re->cond_lock,
					100000000LL);
			uv_mutex_unlock(&re->cond_lock);
			*status = st;
			uv_mutex_lock(&dev->rt->recovery_queue_mutex);
			re->ref_cnt--;
			if (!re->ref_cnt && re->stale) {
				QUEUE_REMOVE(&re->item);
				je_free(re);
			}
			uv_mutex_unlock(&dev->rt->recovery_queue_mutex);
			return NULL;
		}
	}

	re = je_calloc(1, sizeof(*re));
	if (!re) {
		*status = -ENOMEM;
		goto _exit;
	}
	re->chid = *chid;
	uv_mutex_init(&re->cond_lock);
	uv_cond_init(&re->cond_var);
	re->ref_cnt = 1;
	re->stale = 0;
	re->status = MANIFEST_PROCESSING;
	QUEUE_INIT(&re->item);
	QUEUE_INSERT_TAIL(&dev->rt->recovery_queue, &re->item);
_exit:
	uv_mutex_unlock(&dev->rt->recovery_queue_mutex);
	return re;
}

/*
 * EC-dedicated ccache customization.
 */

static void
ec_cc_ub_free_cb(void *value, size_t len, void *data)
{
	uv_buf_t* ub = (uv_buf_t *)value;
	je_free(ub->base);
	ub->base = NULL;
	ub->len = 0;
	je_free(ub);
}

static void *
ec_cc_ub_copyout_cb(void *value, size_t len, void *data)
{
	uv_buf_t* ub = (uv_buf_t *)value;
	uv_buf_t* ub_out = je_calloc(1, sizeof(uv_buf_t));
	if (ub_out) {
		*ub_out = *ub;
	}
	return (void*)ub_out;
}

static void *
ec_cc_ub_copyin_cb(void *value, size_t len, void *data)
{
	uv_buf_t* ub = (uv_buf_t *)value;
	uv_buf_t* ub_out = je_calloc(1, sizeof(uv_buf_t));
	if (ub_out) {
		*ub_out = *ub;
	}
	return (void*)ub_out;
}

ccache_t*
ec_ccache_create(size_t cachesz) {
	ccache_t* ret = ccache_create(cachesz, ec_cc_ub_free_cb, ec_cc_ub_copyout_cb,
		ec_cc_ub_copyin_cb);
	if (ret)
		ccache_set_override(ret, 0);
	return ret;
}

/*
 * Returns:
 * 0 if chunk isn't found
 * 1 if (found)
 * less that 0 in case of error
 */
static int
ec_ccache_get_mapped(ccache_t* cc, uint512_t* chid, uv_buf_t* out) {
	uv_buf_t* ub = NULL;
	int chit = ccache_get(cc, chid, (void**)&ub);
	if (chit && ub) {
		*out = *ub;
		je_free(ub);
	} else if (chit && !ub)
		chit = -ENOMEM;
	return chit;
}

static int
ec_ccache_get(ccache_t* cc, uint512_t* chid, uv_buf_t* out) {
	uv_buf_t ub = { .len = 0, .base = NULL };
	int chit = ec_ccache_get_mapped(cc, chid, &ub);
	if (chit > 0) {
		out->base = je_malloc(ub.len);
		if (!out->base) {
			chit = -ENOMEM;
		} else {
			memcpy(out->base, ub.base, ub.len);
		}
	}
	return chit;
}

/* takes ownership on a provided chunk*/
static int
ec_ccache_put_mapped(ccache_t* cc, uint512_t* chid, uv_buf_t* chunk) {
	return ccache_put(cc, chid, chunk);
}

/* Creates a copy of provided chunk */
static int
ec_ccache_put(ccache_t* cc, uint512_t* chid, uv_buf_t* chunk) {
	uv_buf_t ub = *chunk;
	ub.base = je_malloc(ub.len);
	if (!ub.base)
		return -ENOMEM;
	memcpy(ub.base, chunk->base, ub.len);
	return ccache_put(cc, chid, &ub);
}

struct ec_cm_entry {
	QUEUE			item;
	codec_handle_t		handle;
	struct ec_codec_vtbl*	vtbl;
	void*			instance;
};
static QUEUE handle_queue;
static int cm_inited = 0;
volatile long unsigned int handle_index = 0;
static uv_mutex_t ec_cm_rb_lock;

int
ec_cm_init() {
	if (cm_inited)
		return 0;
	if (QUEUE_EMPTY(&all_ec_codecs)) {
		log_error(lg, "EC codec list is empty!");
		return -ENOENT;
	}
	QUEUE_INIT(&handle_queue);
	handle_index = 0;
	uv_mutex_init(&ec_cm_rb_lock);
	struct ec_codec_vtbl* codec = NULL;
	QUEUE* q = NULL;
	QUEUE_FOREACH(q, &all_ec_codecs) {
		codec = QUEUE_DATA(q, struct ec_codec_vtbl, item);
		codec->init();
	}
	cm_inited = 1;
	return 0;
}

void
ec_cm_exit() {
	if (!cm_inited)
		return;
	cm_inited = 0;
	uv_mutex_lock(&ec_cm_rb_lock);
	while (!QUEUE_EMPTY(&handle_queue)) {
		QUEUE *d = QUEUE_HEAD(&handle_queue);
		struct ec_cm_entry* e =
			QUEUE_DATA(d, struct ec_cm_entry, item);
		assert(e);
		assert(e->vtbl);
		assert(e->instance);
		e->vtbl->destroy(e->instance);
		QUEUE_REMOVE(d);
		QUEUE_INIT(d);
	}
	QUEUE_INIT(&handle_queue);
	uv_mutex_unlock(&ec_cm_rb_lock);
	uv_mutex_destroy(&ec_cm_rb_lock);
	struct ec_codec_vtbl* codec = NULL;
	QUEUE* q = NULL;
	QUEUE_FOREACH(q, &all_ec_codecs) {
		codec = QUEUE_DATA(q, struct ec_codec_vtbl, item);
		codec->exit();
	}
}

static struct ec_codec_vtbl*
ec_get_codec_by_id(ec_codec_id id) {
	QUEUE* q = NULL;
	struct ec_codec_vtbl* codec = NULL;
	struct ec_codec_info* info = NULL;
	QUEUE_FOREACH(q, &all_ec_codecs) {
		codec = QUEUE_DATA(q, struct ec_codec_vtbl, item);
		int err = codec->info(&info);
		if (err)
			continue;
		if (info->id != id)
			continue;
		return codec;
	}
	return NULL;
}

static struct ec_cm_entry*
ec_cm_get_entry(codec_handle_t h) {
	QUEUE* q = NULL;
	struct ec_cm_entry* entry = NULL;
	QUEUE_FOREACH(q, &handle_queue) {
		entry = QUEUE_DATA(q, struct ec_cm_entry, item);
		if (entry->handle == h)
			return entry;
	}
	return NULL;
}

int
ec_cm_codec_info(ec_codec_id id, struct ec_codec_info** info) {
	if (!cm_inited)
		return -EPERM;
	assert(info);
	struct ec_codec_vtbl* codec = ec_get_codec_by_id(id);
	if (!codec)
		return -ENOENT;
	int err = codec->info(info);
	return err;
}

int
ec_cm_create_instance(ec_codec_id id, ec_codec_format format,
	codec_handle_t* handle) {
	if (!cm_inited)
		return -EPERM;
	assert(handle);
	void* instance = NULL;
	struct ec_codec_vtbl* codec = ec_get_codec_by_id(id);
	if (!codec)
	    return -ENOENT;
	struct ec_cm_entry* e = je_calloc(1, sizeof(*e));
	int err = codec->create(format, &instance);
	if (err) {
		je_free(e);
		return err;
	}
	e->vtbl = codec;
	e->instance = instance;
	uv_mutex_lock(&ec_cm_rb_lock);
	e->handle = atomic_inc(&handle_index);
	QUEUE_INSERT_TAIL(&handle_queue, &e->item);
	uv_mutex_unlock(&ec_cm_rb_lock);
	*handle = e->handle;
	return 0;
}

int
ec_cm_encode(codec_handle_t handle, struct ec_fragment* data,
	struct ec_fragment* parity, uv_buf_t* context) {
	if (!cm_inited)
		return -EPERM;
	assert(data);
	assert(parity);
	assert(context);
	uv_mutex_lock(&ec_cm_rb_lock);
	struct ec_cm_entry* e = ec_cm_get_entry(handle);
	uv_mutex_unlock(&ec_cm_rb_lock);
	if (!e)
	    return -EINVAL;
	assert(e->vtbl);
	int err = e->vtbl->encode(e->instance, data, parity, context);
	return err;
}

int
ec_cm_recover(codec_handle_t handle, struct ec_fragment* fragments,
	 uv_buf_t* context) {
	if (!cm_inited)
		return -EPERM;
	assert(fragments);
	assert(context);
	uv_mutex_lock(&ec_cm_rb_lock);
	struct ec_cm_entry* e = ec_cm_get_entry(handle);
	uv_mutex_unlock(&ec_cm_rb_lock);
	if (!e)
	    return -EINVAL;
	assert(e->vtbl);
	int err = e->vtbl->recover(e->instance, fragments, context);
	return err;
}

int
ec_cm_destroy_instance(codec_handle_t handle) {
	if (!cm_inited)
		return -EPERM;
	uv_mutex_lock(&ec_cm_rb_lock);
	struct ec_cm_entry* e = ec_cm_get_entry(handle);
	uv_mutex_unlock(&ec_cm_rb_lock);
	if (!e)
	    return -EINVAL;
	assert(e->vtbl);
	int err = e->vtbl->destroy(e->instance);
	uv_mutex_lock(&ec_cm_rb_lock);
	QUEUE_REMOVE(&e->item);
	QUEUE_INIT(&e->item);
	je_free(e);
	uv_mutex_unlock(&ec_cm_rb_lock);
	return 0;
}

/* Implementation of EC coder-related functions */

static int
ec_fetch_devinfo(struct ec_dev_info **devices, int* n_devices, int row_id) {
	struct cl_node* nodes = NULL;
	int n_vdevs = 0, ret = 0;
	int numnodes = 0, vdev_idx = 0;
	struct ec_dev_info* devs = NULL;

	ccowd_fhready_lock(FH_LOCK_READ);
	int err = flexhash_get_nodes(SERVER_FLEXHASH, &nodes, &numnodes, FH_NOGOOD_HC);
	if (!flexhash_is_pristine(SERVER_FLEXHASH)) {
		ccowd_fhready_unlock(FH_LOCK_READ);
		return -EINVAL;
	}
	if (err) {
		ccowd_fhready_unlock(FH_LOCK_READ);
		return err;
	}
	/* Calculate number of VDEVs */
	for (int i = 0; i < numnodes; i++) {
		n_vdevs += nodes[i].nr_vdevs;
	}
	devs = je_calloc(n_vdevs, sizeof(struct ec_dev_info));
	if (!devs) {
		ret = -ENOMEM;
		goto _exit;
	}
	/* Generate output array */
	for (int i = 0; i < numnodes; i++) {
		for (uint32_t j = 0; j < nodes[i].nr_vdevs; j++) {
			struct lvdev *ld = vdevstore_get_lvdev(SERVER_FLEXHASH->vdevstore,
				&nodes[i].vdevs[j].vdevid);
			/* Skip dead */
			if (!ld)
				continue;
			int skip = 1;
			for (uint16_t n = 0; n < FLEXHASH_MAX_TAB_LENGTH; n++) {
				if (ld->hashcount[n]) {
					skip = 0;
					break;
				}
			}
			if (skip)
				continue;
			if (row_id >= 0 && !flexhash_is_rowmember_fhrow(SERVER_FLEXHASH,
				&nodes[i].vdevs[j].vdevid, row_id))
					continue;
			devs[vdev_idx].zoneid = nodes[i].zone;
			devs[vdev_idx].hostid = nodes[i].serverid;
			devs[vdev_idx].usage = (double)(ld->size - ld->avail)/ld->size;
			devs[vdev_idx].state = ld->state;
			devs[vdev_idx++].vdevid = nodes[i].vdevs[j].vdevid;
		}
	}
	*devices = devs;
	*n_devices = vdev_idx;

_exit:
	ccowd_fhready_unlock(FH_LOCK_READ);
	for (int i = 0; i < numnodes; i++)
		je_free(nodes[i].vdevs);
	je_free(nodes);
	return ret;
}

/* Some auxiliary functions */

static int
in_array(int a[], int n, int e) {
	for (int i = 0; i < n; i++)
		if (a[i] == e)
			return 1;
	return 0;
}

static int
in_array_uint32(uint32_t a[], int n, uint32_t e) {
	for (int i = 0; i < n; i++)
		if (a[i] == e)
			return 1;
	return 0;
}

static int
in_array_uint128(uint128_t a[], int n, uint128_t *e) {
	for (int i = 0; i < n; i++)
		if (!uint128_cmp(&a[i], e))
			return 1;
	return 0;
}

static int
find_max_not_in_array(int a[], int na, int b[], int nb) {
	int max_idx = -1;
	int max_val = 0;
	for(int i = 0; i < na; i++)
		if (a[i] > max_val && !in_array(b, nb, i)) {
			max_idx = i; max_val = a[i];
		}

	return max_idx;
}

static int
find_max_in_array(int a[], int na) {
	int max_idx = -1;
	int max_val = 0;
	for(int i = 0; i < na; i++)
		if (a[i] > max_val) {
			max_idx = i;
			max_val = a[i];
		}
	return max_idx;
}

static int
build_zones(struct ec_dev_info *devices, int n_devs, uint32_t zones[]) {
	int i, j, n = 0;
	for(i = 0; i < n_devs; i++) {
		if (!in_array_uint32(zones, n, devices[i].zoneid))
			zones[n++] = devices[i].zoneid;
	}
	return n;
}

static int
build_hosts(struct ec_dev_info *devices, int n_devs, uint128_t hosts[]) {
	int i, j, n = 0;
	for(i = 0; i < n_devs; i++) {
		if (!in_array_uint128(hosts, n, &devices[i].hostid))
			uint128_set(&hosts[n++], &devices[i].hostid);
	}
	return n;
}

static struct ec_dev_info *
find_device(struct ec_dev_info devs[], int n_devs, uint128_t *vdevid) {
	for(int i = 0; i < n_devs; i++)
		if (!uint128_cmp(&devs[i].vdevid, vdevid))
			return devs + i;
	return NULL;
}

static int
find_idx_of_zones(struct ec_dev_info *dev, uint32_t zones[], int n) {
	for (int d = 0; d < n; d++)
		if (zones[d] == dev->zoneid)
			return d;
	return -1;
}

static int
find_idx_of_hosts(struct ec_dev_info *dev, uint128_t hosts[], int n) {
	for (int d = 0; d < n; d++)
		if (!uint128_cmp(&hosts[d], &dev->hostid))
			return d;
	return -1;
}

static int
find_idx_of_devices(struct ec_dev_info *dev, struct ec_dev_info devices[], int n) {
	for (int d = 0; d < n; d++)
		if (!uint128_cmp(&devices[d].vdevid, &dev->vdevid))
			return d;
	return -1;
}

static int
find_idx_of_vdevs_by_vdevid(uint128_t a[], int n, uint128_t *e) {
	int i;
	for(i = 0; i < n; i++)
		if (!uint128_cmp(&a[i], e))
			return i;
	return -1;
}

static int
find_idx_of_vdevs_by_zone(struct ec_dev_info *dev[], int n, uint32_t zone) {

	for (int d = 0; d < n; d++) {
		if (!dev[d])
			continue;
		if (zone == dev[d]->zoneid)
			return d;
	}
	return -1;

}

static int
find_idx_of_vdevs_by_host(struct ec_dev_info *dev[], int n, uint128_t *host) {

	for (int d = 0; d < n; d++) {
		if (!dev[d])
			continue;
		if (!uint128_cmp(host, &dev[d]->hostid))
			return d;
	}
	return -1;

}

static int
devs_in_zone(struct ec_dev_info dev[], int n_devs, uint32_t zone) {
	int count = 0;
	for (int i = 0; i < n_devs; i++)
		if (zone == dev[i].zoneid)
			count++;

	return count;

}

static int
devs_in_host(struct ec_dev_info dev[], int n_devs, uint128_t *host) {
	int count = 0;
	for (int i = 0; i < n_devs; i++)
		if (!uint128_cmp(host, &dev[i].hostid))
			count++;

	return count;
}

static int
ndev_in_zone(struct ec_dev_info dev[], int n_devs, uint32_t zone, int n) {
	int count = 0;
	for (int i = 0; i < n_devs; i++) {
		if (zone == dev[i].zoneid) {
			if (count++ == n)
				return i;
		}

	}
	return -1;
}

static int
ndev_in_host(struct ec_dev_info dev[], int n_devs, uint128_t *host, int n) {
	int count = 0;
	for (int i = 0; i < n_devs; i++) {
		if (!uint128_cmp(host, &dev[i].hostid)) {
			if (count++ == n)
				return i;
		}

	}
	return -1;
}

static void
build_zone_to_ng_map(struct ec_dev_info dev[], int n_devs, uint32_t zone,
	uint32_t hc[]) {
	int nrows = SERVER_FLEXHASH->numrows;
	for (int i = 0; i < n_devs; i++) {
		if (dev[i].state != VDEV_STATE_ALIVE)
			continue;
		if (zone == dev[i].zoneid) {
			for (uint16_t ng = 0; ng < nrows; ng++) {
				hc[ng] = flexhash_is_rowmember_fhrow(
					SERVER_FLEXHASH, &dev[i].vdevid, ng);
			}
		}
	}
}

static void
build_host_to_ng_map(struct ec_dev_info dev[], int n_devs, uint128_t* host_id,
	uint32_t hc[]) {
	int nrows = SERVER_FLEXHASH->numrows;
	for (int i = 0; i < n_devs; i++) {
		if (dev[i].state != VDEV_STATE_ALIVE)
			continue;
		if (!uint128_cmp(host_id, &dev[i].hostid)) {
			for (uint16_t ng = 0; ng < nrows; ng++) {
				hc[ng] = flexhash_is_rowmember_fhrow(
					SERVER_FLEXHASH, &dev[i].vdevid, ng);
			}
		}
	}
}

static int
select_vdev_in_host_by_usage(struct ec_dev_info dev[], int n_devs, uint128_t *host) {
	int last_pos = -1;
	double last_usage = 1.0;
	for (int i = 0; i < n_devs; i++) {
		if (dev[i].state != VDEV_STATE_ALIVE)
			continue;
		if (uint128_cmp(host, &dev[i].hostid))
			continue;
		if (dev[i].usage < last_usage) {
			last_pos = i;
			last_usage = dev[i].usage;
		}
	}
	return last_pos;
}

static int
select_vdev_in_zone_by_usage(struct ec_dev_info dev[], int n_devs, uint32_t zone) {
	int last_pos = -1;
	double last_usage = 1.0;
	for (int i = 0; i < n_devs; i++) {
		if (dev[i].state != VDEV_STATE_ALIVE)
			continue;
		if (zone != dev[i].zoneid)
			continue;
		if (dev[i].usage < last_usage) {
			last_pos = i;
			last_usage = dev[i].usage;
		}
	}
	return last_pos;
}

#define MAX_VDEVS	FLEXHASH_MAX_VDEVS
#define MAX_ZONE	FLEXHASH_MAX_ZONES
#define MAX_HOST	FLEXHASH_MAX_SERVERS

static int
is_invalid_pset(struct ec_pset* p, uint8_t n_parity) {
	return (p->n_parity == n_parity && p->n_entries >= p->n_parity);
}

int chunk_sort_cmp (const void * a, const void * b)
{
	const struct chunk_info **c1 = (const struct chunk_info**)a;
	const struct chunk_info **c2 = (const struct chunk_info**)b;

	return ((*c1)->size > (*c2)->size) ? 1 : -1;
}

int vdevs_sort_cmp (const void * a, const void * b)
{
	const uint128_t *c1 = a;
	const uint128_t *c2 = b;

	return uint128_cmp(a, b);
}

static int
fd_cmp_cb(const void *a, const void *b, void *arg) {
	int *fd_weight = arg;
	const int* ia = a;
	const int* ib = b;
	return fd_weight[*ia] - fd_weight[*ib];
}


static void
ec_dump_fd_weight(int *fd_weight, int n_fd) {
#if EC_DEBUG
	printf("FD weight:\n");
	for (int i = 0; i < n_fd; i++) {
		printf("FD[%d]=%d\n", i, fd_weight[i]);
	}
#endif
}

int
ec_build_parity_sets(struct ec_dev_info *devices, int n_devs,
        struct chunk_info *chunks, int n_chunks, uint8_t width,
        uint8_t n_parity, ec_domain_t domain, uint8_t rep_cnt,
	struct ec_pset **psets, int *n_psets)
{
	int i, j, d, k = 0, e, err = 0;
	int max_value;
	int max_idx;
	int n_zones, n_hosts, n;
	int pset[n_chunks/width + (0 != n_chunks % width)][width];
	int n_chunk_replicas[n_chunks];
	struct ec_pset* res = NULL;
	int n_sets = n_chunks/width + (0 != n_chunks % width);

	uint32_t* zones = je_calloc(MAX_ZONE, sizeof(uint32_t));
	if (!zones)
		return -ENOMEM;
	uint128_t* hosts = je_calloc(MAX_HOST, sizeof(uint128_t));
	if (!hosts) {
		je_free(zones);
		return -ENOMEM;
	}

	ccowd_fhready_lock(FH_LOCK_READ);
	n = reptrans_get_fd_targets_number_unsafe(domain);
	uint32_t fd2ng_map[n][SERVER_FLEXHASH->numrows];
	struct ec_dev_info *chunks_to_devs[n_chunks][rep_cnt*2];
	int chunk2fd[n_chunks][n];
	int fd_weight[n];
	int fd_idx[n];
	struct chunk_info *pchunks[n_chunks];

	for(i = 0; i < n_chunks; i++) {
		pchunks[i] = &chunks[i];
	}

	/* Sort chunks by size */
	qsort(pchunks, n_chunks, sizeof(struct chunk_info*), chunk_sort_cmp);

	/* Sort vdevs */
	for(i = 0; i < n_chunks; i++) {
		if (chunks[i].n_vdevs > rep_cnt) {
			qsort(chunks[i].vdevs, chunks[i].n_vdevs, sizeof(uint128_t), vdevs_sort_cmp);
		}
	}

	/* Build Chunk to Device association */
	for(i = 0; i < n_chunks; i++) {
		int n_vdevs = (pchunks[i]->n_vdevs > rep_cnt) ? rep_cnt : pchunks[i]->n_vdevs;
		for(j = 0; j < n_vdevs; j++) {
			chunks_to_devs[i][j] = find_device(devices, n_devs, &pchunks[i]->vdevs[j]);
		}
	}

	switch(domain) {
		case EC_DOMAIN_VDEV:
			n = n_devs;
			break;
		case EC_DOMAIN_HOST:
			n_hosts = build_hosts(devices, n_devs, hosts);
			for (int i = 0; i < n; i++)
				build_host_to_ng_map(devices, n_devs, hosts + i,
					fd2ng_map[i]);
			if (n != n_hosts) {
				log_error(lg, "Calculated number of hosts %d, "
					"FH reported %d. FH inconsistency,"
					"will try later", n_hosts, n);
				err = -EAGAIN;
				goto _err;
			}
			n = n_hosts;
			break;
		case EC_DOMAIN_ZONE:
			n_zones = build_zones(devices, n_devs, zones);
			for (int i = 0; i < n; i++)
				build_zone_to_ng_map(devices, n_devs, zones[i],
					fd2ng_map[i]);
			if (n != n_zones) {
				log_error(lg, "Calculated number of zones %d, "
					"FH reported %d. FH inconsistency,"
					"will try later", n_zones, n);
				err = -EAGAIN;
				goto _err;
			}
			n = n_zones;
			break;
		default:
			log_error(lg,"ec_build_parity_sets: invalid domain %d",
			    domain);
			err = -EINVAL;
			goto _err;
			break;
	}

	if (n < width + n_parity) {
		log_error(lg, "ec_build_parity_sets: n(%d) < width(%u) + n_parity(%u)", n, width, n_parity);
		err = -EINVAL;
		goto _err;
	}

	res = je_calloc(n_sets, sizeof(struct ec_pset));
	if (!res) {
		err = -ENOMEM;
		goto _err;
	}

	memset(fd_weight, 0, sizeof(fd_weight[0]) * n);
	memset(chunk2fd, 0, sizeof(int) * n * n_chunks);
	memset(n_chunk_replicas, 0, sizeof(n_chunk_replicas[0]) * n_chunks);
	memset(pset, 0, sizeof(pset[0][0]) * n_sets * width);

	/* Fill Sort Matrix */
	for(i = 0; i < n_chunks; i++) {
		int n_vdevs = (pchunks[i]->n_vdevs > rep_cnt) ? rep_cnt : pchunks[i]->n_vdevs;
		for(j = 0; j < n_vdevs; j++) {
			if (!chunks_to_devs[i][j] || chunks_to_devs[i][j]->state == VDEV_STATE_DEAD)
				continue;
			e = -1;
			switch(domain) {
				case EC_DOMAIN_VDEV:
					e = find_idx_of_devices(chunks_to_devs[i][j], devices, n);
					break;
				case EC_DOMAIN_HOST:
					e = find_idx_of_hosts(chunks_to_devs[i][j], hosts, n);
					break;
				case EC_DOMAIN_ZONE:
					e = find_idx_of_zones(chunks_to_devs[i][j], zones, n);
					break;
				default:
					log_error(lg, "ec_build_parity_sets: invalid domain %d\n",
					    domain);
					err = -EINVAL;
					goto _err;
			}
			if (e >= 0) {
				chunk2fd[i][e]++;
				n_chunk_replicas[i]++;
				fd_weight[e]++;
			}
		}
	}
	/* Remove repeating chunks */
	for(i = 0; i < n_chunks; i++) {
		while(n_chunk_replicas[i] > 1) {
			max_value = -1; max_idx = -1;
			for(j = 0; j < n; j++)
				if (chunk2fd[i][j])
					if (max_value < fd_weight[j]) {
						max_value = fd_weight[j];
						max_idx = j;
					}
			chunk2fd[i][max_idx]--;
			n_chunk_replicas[i]--;
			fd_weight[max_idx]--;
		}
	}
	/* Reorder chunks
	 * Sord fd_weight[] indexes according of FD weight
	 * fd_idx[0] has an index of FD with minimal weight
	 * fd_idx[n-1] has an index of FD with maximal weight
	 */
	for (int i=0; i < n; i++)
		fd_idx[i] = i;
	int last_reloc[3] = {-1,-1,-1};
	int cycl_count = n*10;
	do {
		if (domain == EC_DOMAIN_VDEV)
			break;
		qsort_r(fd_idx, n, sizeof(int), fd_cmp_cb, fd_weight);
		int dW = fd_weight[fd_idx[n-1]] - fd_weight[fd_idx[0]];
		/*
		 * Number of chunks per FD has to be steady in order to create
		 * good parity sets. If the values differ by more than one,
		 * we will re-balance FD weight.
		 */
		if (dW <= 1)
			break;
		int fd_min_idx = 0, fd_max_idx = n - 1;
		int relocated = 0;
		int reloc_iter_mode = 0;
		while(!relocated && fd_min_idx < fd_max_idx) {
			/* Pick a chunk from a max weight FD and try to relocate it
			 * to a FD with min. weight. If there are no targets in min. FD,
			 * then try another chunk. If all chunks were tried without success,
			 * then change the FD next to min FD.
			 */
			for(d = 0; d < n_chunks; d++)
				if (chunk2fd[d][fd_idx[fd_max_idx]] > 0) {
					uint16_t row = HASHROWID(&pchunks[d]->chid,
						SERVER_FLEXHASH);
					if (!fd2ng_map[fd_idx[fd_min_idx]][row])
						continue;
					/* protection against cyclic relocation */
					if (last_reloc[0] == d &&
						last_reloc[1] == fd_min_idx &&
						last_reloc[2] == fd_max_idx) {
						reloc_iter_mode = !reloc_iter_mode;
						continue;
					}
					last_reloc[0] = d;
					last_reloc[1] = fd_max_idx;
					last_reloc[2] = fd_min_idx;
					chunk2fd[d][fd_idx[fd_max_idx]]--;
					chunk2fd[d][fd_idx[fd_min_idx]]++;
					fd_weight[fd_idx[fd_max_idx]]--;
					fd_weight[fd_idx[fd_min_idx]]++;
					relocated = 1;
					break;
				}
			if (!relocated) {
				if (fd_weight[fd_idx[fd_max_idx-1]] > fd_weight[fd_idx[fd_min_idx]]) {
					if(!reloc_iter_mode)
						fd_max_idx--;
					else
						fd_min_idx++;
				} else {
					if(!reloc_iter_mode)
						fd_min_idx++;
					else
						fd_max_idx--;
				}
			}
		}
		if (!relocated)
			break;
	} while(cycl_count--);
	ec_dump_fd_weight(fd_weight, n);
	/*
	 * Here we should have an uniform FDs weight (+/-1).
	 * Build parity sets.
	 */
	i = 0; e = 0; j = 0; k = 0;
	while(k < n_sets) {
		if (!res[k].entries) {
			res[k].entries = je_calloc(width, sizeof(struct ec_pset_entry));
			if (!res[k].entries) {
				err = -ENOMEM;
				goto _err;
			}
			res[k].parity = je_calloc(n_parity, sizeof(struct ec_parity_chunk));
			if (!res[k].parity) {
				err = -ENOMEM;
				goto _err;
			}

			res[k].n_parity = n_parity;
		}
		j = 0;
		int n_entries = 0;
		while(j < width) {
			/* First lookup for existing FD target */
			i = find_max_not_in_array(fd_weight, n, pset[k], j);
			if (i < 0) {
				pset[k][j] = -1;
				j++;
				continue;
			}
			for(d = 0; d < n_chunks; d++)
				if (chunk2fd[d][i] > 0) {
					pset[k][j] = i;
					res[k].entries[n_entries].info = pchunks[d];
					res[k].entries[n_entries].tgt_vdev = uint128_null;
					int n_vdevs = (pchunks[d]->n_vdevs > rep_cnt) ? rep_cnt : pchunks[d]->n_vdevs;
					int idx = 0;
					switch(domain) {
					case EC_DOMAIN_VDEV:
						res[k].entries[n_entries].tgt_vdev = devices[i].vdevid;
						break;
					case EC_DOMAIN_HOST:
						idx = find_idx_of_vdevs_by_host(chunks_to_devs[d], n_vdevs, &hosts[i]);
						if (idx >= 0)
							res[k].entries[n_entries].tgt_vdev = chunks_to_devs[d][idx]->vdevid;
						else {
							/* Look for new VDEV for the chunk */
							double usage = 1.0;
							for (int x = 0; x < n_devs; x++) {
								if (uint128_cmp(&devices[x].hostid, hosts + i))
									continue;
								if (devices[x].state != VDEV_STATE_ALIVE)
									continue;
								if (!flexhash_is_rowmember(SERVER_FLEXHASH, &devices[x].vdevid,
									&pchunks[d]->chid))
									continue;
								if (devices[x].usage < usage) {
									res[k].entries[n_entries].tgt_vdev = devices[x].vdevid;
									usage = devices[x].usage;
								}
							}
						}
						break;
					case EC_DOMAIN_ZONE:
						idx = find_idx_of_vdevs_by_zone(chunks_to_devs[d], n_vdevs, zones[i]);
						if (idx >= 0)
							res[k].entries[n_entries].tgt_vdev = chunks_to_devs[d][idx]->vdevid;
						else {
							double usage = 1.0;
							for (int x = 0; x < n_devs; x++) {
								if (devices[x].zoneid != zones[i])
									continue;
								if (devices[x].state != VDEV_STATE_ALIVE)
									continue;
								if (!flexhash_is_rowmember(SERVER_FLEXHASH, &devices[x].vdevid,
									&pchunks[d]->chid))
									continue;
								if (devices[x].usage < usage) {
									res[k].entries[n_entries].tgt_vdev = devices[x].vdevid;
									usage = devices[x].usage;
								}
							}
						}
						break;
					default:
						log_error(lg, "ec_build_parity_sets: invalid domain %d",
							domain);
						err = -EINVAL;
						goto _err;
					}
					if (!uint128_cmp(&res[k].entries[n_entries].tgt_vdev, &uint128_null)) {
						/* We couldn't find a new target for the chunk.
						 * Possibly all VDEVs are dead or RO
						 */
						char chidstr[UINT512_BYTES*2+1];
						uint512_dump(&res[k].entries[n_entries].chid, chidstr, UINT512_BYTES*2+1);
						pset[k][j] = -1;
						log_debug(lg, "Couldn't find a new target for chunk %s\n", chidstr);
					} else {
						fd_weight[i]--;
						chunk2fd[d][i]--;
						n_entries++;
					}
					j++;
					break;
				}
		}
		res[k].n_entries = n_entries;
		for(e = 0; e < n_parity; e++) {
			int pfd = 0;
			int fd_min = -1;
			double used_min = 1.0;
			uint128_t vdev_min = uint128_null;
			res[k].parity[e].vdevid = uint128_null;
			/* Look for a VDEV with the minimal usage among all
			 * available VDEVs on each unused FD
			 */
			for (pfd = 0; pfd < n; pfd++) {
				/* Skip already used FDs */
				if (in_array(pset[k], n_entries + e, pfd))
					continue;
				switch(domain) {
					case EC_DOMAIN_VDEV:
						if (devices[pfd].usage < used_min) {
							used_min = devices[pfd].usage;
							fd_min = pfd;
							vdev_min = devices[pfd].vdevid;
						}
						break;
					case EC_DOMAIN_HOST:
						{
							int idx = select_vdev_in_host_by_usage(devices, n_devs, hosts + pfd);
							if (idx < 0)
								break;
							if (devices[idx].usage < used_min) {
								used_min = devices[idx].usage;
								fd_min = pfd;
								vdev_min = devices[idx].vdevid;
							}
						}
						break;
					case EC_DOMAIN_ZONE:
						{
							int idx = select_vdev_in_zone_by_usage(devices, n_devs, zones[pfd]);
							if (idx < 0)
								break;
							if (devices[idx].usage < used_min) {
								used_min = devices[idx].usage;
								fd_min = pfd;
								vdev_min = devices[idx].vdevid;
							}
						}
						break;
					default:
						log_error(lg, "ec_build_parity_sets: invalid domain %d",
						    domain);
						err = -EINVAL;
						goto _err;
				}
			}
			if (fd_min < 0) {
				log_debug(lg, "Couldn't find a target for"
					" parity chunk, skipping");
				break;
			} else {
				pset[k][n_entries + e] = fd_min;
				res[k].parity[e].vdevid = vdev_min;
				res[k].n_parity = e + 1;
			}
		}
		if (is_invalid_pset(&res[k], n_parity)) {
			/* verify protection level */
			struct ec_pset* p = res + k;
			int n = p->n_entries + p->n_parity;
			uint128_t* vl = je_calloc(n, sizeof(uint128_t));
			for (int i = 0; i < p->n_entries; i++)
				vl[i] = p->entries[i].tgt_vdev;
			for (int i = 0; i < p->n_parity; i++)
				vl[i+p->n_entries] = p->parity[i].vdevid;
			int erc = reptrans_get_effective_rep_count(vl, n, domain);
			je_free(vl);
			if(erc != n) {
				log_error(lg, "Parity set protection level ins't"
					" respected: %d vs %d, must be VDEVs became RO", erc, n);
				err = -ERANGE;
				goto _err;
			}
			k++;
		} else {
			n_sets--;
			if (k == n_sets) {
				je_free(res[k].entries);
				je_free(res[k].parity);
			}
		}
	}
	*psets = res;
	*n_psets = n_sets;
_err:
	ccowd_fhready_unlock(FH_LOCK_READ);
	if (err) {
		for(i = 0; i < k; i++) {
			if (res[i].parity)
				je_free(res[i].parity);
			if (res[i].entries)
				je_free(res[i].entries);
		}
		je_free(res);
	}
	if (zones)
		je_free(zones);
	if (hosts)
		je_free(hosts);
	return err;
}

struct get_map{
	uint512_t* chid;
	uv_buf_t buf;
};


static int
ec_get_data_chunks(ccow_t cl, struct repdev* dev, struct ec_pset* set, rtbuf_t** out,
	ccache_t* cc) {
	rtbuf_t* rb = rtbuf_init_empty();
	ccow_completion_t c = NULL;
	int err = 0;
	int op_index = 0;
	*out = NULL;
	int n_chunks = 0;
	for (int i = 0; i < set->n_entries; i++) {
		if (set->entries[i].status == ECS_MISSING)
			continue;
		n_chunks++;
	}
	struct ccow_op **ug_op = je_calloc(n_chunks, sizeof(struct ccow_op*));
	if (!ug_op)
		return -ENOMEM;
	struct ccow_io **get_io = je_calloc(n_chunks, sizeof(struct ccow_io*));
	if (!get_io) {
		je_free(ug_op);
		return -ENOMEM;
	}
	struct getcommon_client_req **req = je_calloc(n_chunks,
		sizeof(struct getcommon_client_req*));
	if (!req) {
		je_free(ug_op);
		je_free(get_io);
		return -ENOMEM;
	}

	struct get_map* chids_map = je_calloc(n_chunks, sizeof(struct get_map));
	if (!chids_map) {
		je_free(ug_op);
		je_free(get_io);
		je_free(req);
		return -ENOMEM;
	}
	err = ccow_create_completion(cl, NULL, NULL, n_chunks, &c);
	if (err)
		goto _cleanup;
	for (int i = 0; i < set->n_entries; i++) {
		if (set->entries[i].status != ECS_PRESENT)
			continue;
		struct chunk_info* info = set->entries[i].info;
		int cc_hit = 0;
		/* Lookup in ccache first (if present) */
		uv_buf_t ub = {.base = NULL, .len = 0};
		cc_hit = ec_ccache_get_mapped(cc, &info->chid, &ub);
		if (cc_hit > 0) {
			assert(ub.base);
			err = rtbuf_add_mapped(rb, &ub, 1);
		} else if (cc_hit < 0)
			err = -ENOMEM;
		if (err) {
			ccow_release(c);
			goto _cleanup;
		}
		/* Couldn't find the cache, try to get it */
		if (!cc_hit) {
			err = ccow_operation_create(c, CCOW_CLONE, ug_op + op_index);
			if (err) {
				ccow_release(c);
				return err;
			}
			err = ccow_unnamedget_create(c, ec_unnamed_get_chunk_cb, ug_op[op_index],
				get_io+op_index, NULL);
			if (err) {
				ccow_operation_destroy(ug_op[op_index], 1);
				ccow_release(c);
				log_error(lg, "error returned by ccow_unnamedget_create: %d",
				err);
				return err;
			}
			ug_op[op_index]->iov_in = NULL;
			ug_op[op_index]->iovcnt_in = 0;
			ug_op[op_index]->offset = 0;
			ug_op[op_index]->chunks = rtbuf_init_alloc_one(info->size);
			get_io[op_index]->attributes = RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_NCOMP | RD_ATTR_VERIFY_PAYLOAD;
			req[op_index] = CCOW_IO_REQ(get_io[op_index]);
			req[op_index]->chid = info->chid;
			req[op_index]->offset = 0;
			req[op_index]->hash_type = info->hash_type;
			req[op_index]->compress_type = cl->compress_type;
			chids_map[op_index].buf.len = info->size;
			chids_map[op_index].buf.base = je_calloc(1, info->size);
			if (!chids_map[op_index].buf.base) {
				ccow_release(c);
				err = -ENOMEM;
				goto _cleanup;
			}
			req[op_index]->data = &chids_map[op_index].buf;
			rtbuf_add_mapped(rb, &chids_map[op_index].buf, 1);
			assert(get_io[op_index]->comp);
			req[op_index]->ng_chid = info->chid;
			chids_map[op_index].chid = &info->chid;
			op_index++;
		}
	}

	if (op_index) {
		for (int i = 0; i < op_index; i++) {
			assert(get_io[i]->comp);
			err = ccow_start_io(get_io[i]);
			assert (err == 0);
		}

		err = ccow_timed_wait(c, -1, EC_GET_TIMEOUT);
		if (err == -EBUSY) {
			uv_mutex_lock(&c->operations_mutex);
			for (int i = 0; i < op_index; i++)
				req[i]->done_cb = NULL;
			uv_mutex_unlock(&c->operations_mutex);
		} else if (!err && c->busy_ops) {
			/* we don't expect any further activities, release it */
			c->busy_ops = 0;
			ccow_release(c);
		}

		if (!err) {
			for (int i = 0; i < op_index; i++) {
				/* Add to cache, it takes ownership on the buffer */
				err = ec_ccache_put_mapped(cc, chids_map[i].chid,
					&chids_map[i].buf);
				if (err && err != -EEXIST) {
					/* Couldn't update cache. Not a big deal, but
					 * let's notify user
					 */
					log_error(lg, "Couldn't put to ccache");
					goto _cleanup;
				}
			}
			*out = rb;
		} else {
			log_error(lg,"Get chunks error: %d", err);
			for (int i = 0; i < op_index; i++) {
				je_free(chids_map[i].buf.base);
				chids_map[i].buf.base = NULL;
			}
		}
	} else {
		ccow_release(c);
	}
_cleanup:

	if (*out == NULL && chids_map) {
		for (int i = 0; i < op_index; i++) {
			if (chids_map[i].buf.base)
				je_free(chids_map[i].buf.base);
		}
	}
	if (chids_map)
		je_free(chids_map);
	if (rb && *out == NULL)
		rtbuf_destroy(rb);
	if (req)
		je_free(req);
	if (get_io)
		je_free(get_io);
	if (ug_op)
		je_free(ug_op);
	return err;
}

static int
ec_cache_data_chunks(ccow_t cl, struct repdev* dev, struct chunk_info* infos,
	int n_infos, ccache_t* cc) {
	ccow_completion_t c = NULL;
	int err = 0, from = 0;
	int op_index = 0;

	/*
	 * Number of chunks per manifest limited by the max btree order.
	 * It's set to 640. But for any chance, make sure it didn't grow up
	 * above the threshold.
	 */
	assert(n_infos < CCOW_IOVCNT_MAX_EMBEDDED);

	struct ccow_op **ug_op = je_calloc(n_infos, sizeof(struct ccow_op*));
	if (!ug_op)
		return -ENOMEM;
	struct ccow_io **get_io = je_calloc(n_infos, sizeof(struct ccow_io*));
	if (!get_io) {
		je_free(ug_op);
		return -ENOMEM;
	}
	struct getcommon_client_req **req = je_calloc(n_infos,
		sizeof(struct getcommon_client_req*));
	if (!req) {
		je_free(ug_op);
		je_free(get_io);
		return -ENOMEM;
	}

	struct get_map* chids_map = je_calloc(n_infos, sizeof(struct get_map));
	if (!chids_map) {
		je_free(ug_op);
		je_free(get_io);
		je_free(req);
		return -ENOMEM;
	}

	err = ccow_create_completion(cl, NULL, NULL, n_infos, &c);
	if (err)
		goto _cleanup;
	for (int i = 0; i < n_infos; i++) {
		struct chunk_info* info = infos + i;
		if (!info->n_vdevs)
			continue;
		if (!ccache_has(cc, &info->chid)) {
			/* Couldn't find in cache, try to get it */
			err = ccow_operation_create(c, CCOW_CLONE, ug_op + op_index);
			if (err) {
				ccow_release(c);
				return err;
			}
			err = ccow_unnamedget_create(c, ec_unnamed_get_chunk_cb, ug_op[op_index],
				get_io+op_index, NULL);
			if (err) {
				ccow_operation_destroy(ug_op[op_index], 1);
				ccow_release(c);
				log_error(lg, "error returned by ccow_unnamedget_create: %d",
				err);
				return err;
			}
			ug_op[op_index]->iov_in = NULL;
			ug_op[op_index]->iovcnt_in = 0;
			ug_op[op_index]->offset = 0;
			ug_op[op_index]->chunks = rtbuf_init_alloc_one(info->size);
			get_io[op_index]->attributes = RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_NCOMP | RD_ATTR_VERIFY_PAYLOAD;
			req[op_index] = CCOW_IO_REQ(get_io[op_index]);
			req[op_index]->chid = info->chid;
			req[op_index]->offset = 0;
			req[op_index]->hash_type = info->hash_type;
			req[op_index]->compress_type = cl->compress_type;
			chids_map[op_index].buf.len = info->size;
			chids_map[op_index].buf.base = je_calloc(1, info->size);
			if (!chids_map[op_index].buf.base) {
				ccow_release(c);
				err = -ENOMEM;
				goto _cleanup;
			}
			req[op_index]->data = &chids_map[op_index].buf;
			assert(get_io[op_index]->comp);
			req[op_index]->ng_chid = info->chid;
			chids_map[op_index].chid = &info->chid;
			op_index++;
		}
	}

	if (op_index) {
		for (int i = 0; i < op_index; i++) {
			assert(get_io[i]->comp);
			err = ccow_start_io(get_io[i]);
			assert (err == 0);
		}
		err = ccow_timed_wait(c, -1, EC_GET_TIMEOUT);
		if (err == -EBUSY) {
			uv_mutex_lock(&c->operations_mutex);
			for (int i = 0; i < op_index; i++)
				req[i]->done_cb = NULL;
			uv_mutex_unlock(&c->operations_mutex);
		} if (!err && c->busy_ops) {
			/* we don't expect any further activities, release it */
			c->busy_ops = 0;
			ccow_release(c);
		}
		if (err)
			log_error(lg,"Cache chunks error: %d", err);
		if (!err) {
			for (from = 0; from < op_index; from++) {
				/* Add to cache, it takes ownership on the buffer */
				err = ec_ccache_put_mapped(cc, chids_map[from].chid,
					&chids_map[from].buf);
				if (err && err != -EEXIST) {
					/* Couldn't update cache. Not a big deal, but
					 * let's notify user
					 */
					log_error(lg, "Couldn't put to ccache");
					goto _cleanup;
				}
			}
		}
	} else
		ccow_release(c);
_cleanup:

	for (int i = from; i < op_index; i++) {
		if (chids_map[i].buf.base)
			je_free(chids_map[i].buf.base);
	}
	if (chids_map)
		je_free(chids_map);
	if (req)
		je_free(req);
	if (get_io)
		je_free(get_io);
	if (ug_op)
		je_free(ug_op);
	return err;
}


void
ec_clean_chunk_infos(struct chunk_info* infos, int n_infos) {
	je_free(infos);
}

void
ec_clean_parity_sets(struct ec_pset* pset, int n_sets) {
	for (int i = 0; i < n_sets; i++) {
		struct ec_pset* item = pset + i;
		if (item->entries)
			je_free(item->entries);
		if (item->parity) {
			for (int j = 0; j < item->n_parity; j++) {
				if (item->parity[j].compound)
					msgpack_pack_free(item->parity[j].compound);
			}
			je_free(item->parity);
		}
	}
	je_free(pset);
}

static int
ec_enqueue_batch(struct repdev* dev, struct verification_request* vbreq,
		volatile struct flexhash* fh) {
	msgpack_p *p = msgpack_pack_init();
	assert(p);
	int err = pack_batch_entry(p, vbreq);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}
	uint16_t n_groups = flexhash_numrows(fh);
	uint16_t ng = HASHCALC(&vbreq->chid, n_groups - 1);
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

static void
ec_dump_parity_sets(struct repdev* dev, const uint512_t* chid,
	struct ec_pset* psets, int n_sets, volatile struct flexhash* fh) {
	char chidstr[UINT512_BYTES*2+1];
	char vdevstr[UINT128_BYTES*2+1];
	uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
	chidstr[31] = 0;
	printf("Dev(%s) parity set for manifest %s:\n",
		(dev ? dev->name : "NONE"), chidstr);
	for (int i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		printf("\t SET[%d]:\n", i);
		for (int j = 0; j < set->n_entries; j++) {
			struct ec_pset_entry* ent = set->entries + j;
			uint512_dump(&ent->info->chid, chidstr,
					UINT512_BYTES*2+1);
			uint128_dump(&ent->tgt_vdev, vdevstr, UINT128_BYTES*2+1);
			chidstr[31] = 0;
			fhrow_t row;
			int ndev;
			int err = flexhash_get_ngcount(fh, &ent->info->chid, &row, &ndev);
			printf("\t\tDATA[%d] CHID %s, VDEV %s, SIZE %lu, STATUS: %d, ROW: %d, NDEV: %d\n", j,
				chidstr, vdevstr, ent->info->size, ent->status, row, ndev);
		}

		for (int j = 0; j < set->n_parity; j++) {
			struct ec_parity_chunk* ent = set->parity + j;
			if (!ent->info) {
				uint512_dump(&ent->chid, chidstr, UINT512_BYTES*2+1);
				uint128_dump(&ent->vdevid, vdevstr, UINT128_BYTES*2+1);
				chidstr[31] = 0;
				fhrow_t row;
				int ndev;
				int err = flexhash_get_ngcount(fh, &ent->chid, &row, &ndev);
				if (err < 0) {
					printf("Unable to get ngcount. err: %d errmsg: %s", err, strerror(err));
				}
				SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_vdev_row(SERVER_FLEXHASH,
						&ent->vdevid, &row), FH_LOCK_READ);
				printf("\t\tPARI[%d] CHID %s, VDEV %s, SIZE %lu, STATUS: %d, ROW: %d, NDEV: %d\n", j,
					chidstr, vdevstr, ent->chunk.len, ent->status, row, ndev);
			} else {
				uint512_dump(&ent->info->chid, chidstr,
						UINT512_BYTES*2+1);
				uint128_dump(ent->info->vdevs, vdevstr,
					UINT128_BYTES*2+1);
				chidstr[31] = 0;
				fhrow_t row;
				int ndev;
				int err = flexhash_get_ngcount(fh, &ent->info->chid, &row, &ndev);
				printf("\t\tPARI[%d] CHID %s, VDEV %s, SIZE %lu, STATUS: %d, ROW: %d, NDEV: %d\n", j,
					chidstr, vdevstr, ent->info->size, ent->status, row, ndev);
			}
		}
		printf("\t\tCtx size %lu\n", set->context.len);
	}
}

static int
ec_encoding_propagate(struct repdev* dev, rtbuf_t *refs,
    struct verification_request *vreq)
{
	struct verification_request vbreq = *vreq;
	int err = 0;

	vbreq.vbr.uvid_timestamp = 0;
	vbreq.vbr.generation = 0;
	memset(&vbreq.vbr.name_hash_id, 0, sizeof(uint512_t));
	vbreq.vbr.ref_chid = vbreq.chid;
	vbreq.vbr.attr = VBR_ATTR_CM;
	for (size_t i = 0; i < refs->nbufs; i++) {
		struct refentry* e = (struct refentry*)rtbuf(refs, i).base;
		uint8_t ref_ttag = ref_to_ttag[RT_REF_TYPE(e)];
		if (ref_ttag != TT_CHUNK_MANIFEST)
			continue;
		/* Probably the manifest is local and already encoded
		 * Skip it then
		 */
		blob_stat_t st = {.size = 0};
		err = reptrans_blob_stat(dev, TT_PARITY_MANIFEST,
			HASH_TYPE_DEFAULT, &e->content_hash_id, &st);
		if (!err && st.size > 0)
			continue;
		vbreq.chid = e->content_hash_id;
		vbreq.nhid = e->name_hash_id;
		vbreq.htype = RT_REF_HASH_TYPE(e);
		vbreq.ttag = TT_CHUNK_MANIFEST;
		vbreq.uvid_timestamp = 0;
		SERVER_FLEXHASH_SAFE_CALL(err = ec_enqueue_batch(dev, &vbreq,
			SERVER_FLEXHASH), FH_LOCK_READ);
		if (err) {
			char chidstr[UINT512_BYTES * 2 + 1];
			uint512_dump(&vbreq.chid, chidstr,
			    UINT512_BYTES * 2 + 1);
			chidstr[16] = 0;
			log_error(lg, "Dev(%s) cannot enqueue batch %s\n",
			    dev->name, chidstr);
		}
	}
	return err;
}

static int
ec_prepare_compound(const uint512_t* m_chid, type_tag_t m_ttag,
	const uint512_t* chid, const uint512_t* nhid, crypto_hash_t htype,
	uv_buf_t* chunk, uint8_t rep_cnt, uint8_t vbr_attr, uv_buf_t* compound,
	int is_parity) {
	int err = 0;
	uv_buf_t ub_vbr, ub_comp;
	msgpack_p* p_comp = NULL, *pvbr = NULL;
	/* VBR */
	struct backref vbr = {
		.generation = 0,
		.uvid_timestamp = 0,
		.name_hash_id = m_ttag == TT_VERSION_MANIFEST ? (*nhid) : uint512_null,
		.ref_hash = HASH_TYPE_DEFAULT,
		.ref_type = is_parity ? TT_PARITY_MANIFEST : m_ttag,
		.ref_chid = *m_chid,
		.rep_count = rep_cnt,
		.attr = vbr_attr
	};
	pvbr = msgpack_pack_init();
	if (pvbr)
		err = reptrans_pack_vbr(pvbr, &vbr);
	if (!pvbr || err) {
		err = -ENOMEM;
		goto __out;
	}
	msgpack_get_buffer(pvbr, &ub_vbr);
	/* Prepare compound */
	struct iovec iov[2];
	iov[0].iov_base = chunk->base;
	iov[0].iov_len = chunk->len;
	iov[1].iov_base = ub_vbr.base;
	iov[1].iov_len = ub_vbr.len;
	type_tag_t tts[2] = { TT_CHUNK_PAYLOAD, TT_VERIFIED_BACKREF };
	err = reptrans_pack_compound(iov, 2, tts, chid, &p_comp,
		htype, COMPOUND_FLAG_PRIMARY_PUT);
	if (err)
		goto __out;

	msgpack_get_buffer(p_comp, &ub_comp);
	compound->len = ub_comp.len;
	compound->base = je_calloc(1, compound->len);
	memcpy(compound->base, ub_comp.base, compound->len);
__out:
	if (p_comp)
		msgpack_pack_free(p_comp);
	if (pvbr)
		msgpack_pack_free(pvbr);

	return err;
}

static int
ec_vbr_iterator_cb(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, uv_buf_t* vbr_buf, const struct backref* vbr,
	void* arg) {
	int* erc = (int*)arg;
	if (vbr->rep_count > *erc)
		*erc = vbr->rep_count;
	return 0;
}

int
ec_encode_manifest(struct repdev* dev, struct verification_request* vreq,
	struct bg_job_entry* job) {

	uint512_t* chid = &vreq->chid;
	char chidstr[UINT512_BYTES*2+1];
	uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
	chidstr[31] = 0;

	ec_domain_t domain = vreq->domain;
	ec_codec_id algo = vreq->algorithm;
	ec_codec_format fmt = TO_CODECFMT(vreq->width, vreq->n_parity);
	type_tag_t ttype = vreq->ttag;
	crypto_hash_t hash_type = vreq->htype;
	codec_handle_t chdl = 0;
	int fmt_found = 0;
	struct vmmetadata *md = NULL;
	int n_data = vreq->width;
	int n_parity = vreq->n_parity;
	struct ec_fragment* fragments = NULL;
	msgpack_p *pvbr = NULL, *p = NULL;
	uv_buf_t ub_vbr = { .base = NULL, .len = 0};
	struct ec_codec_info* codec_info = NULL;
	rtbuf_t* rb = NULL, *refs = NULL, *rb_pmap = NULL;
	struct chunk_info* cinfos = NULL;
	struct ec_dev_info* devinfo = NULL;
	struct ec_pset* psets = NULL;
	int ndev = 0, npsets = 0, n_infos = 0;
	int err = 0;
	int rep_count = 0;
	ccache_t* cc = NULL;
	uint64_t gen_id = 0;
	SERVER_FLEXHASH_SAFE_CALL(gen_id = flexhash_genid(SERVER_FLEXHASH), FH_LOCK_READ);

	/* request manifest info */
	struct chunk_info manifest_info = {
		.chid = *chid,
		.hash_type = hash_type,
		.ttype = ttype,
		.n_vdevs = 0
	};
	/* Don't even try to encode if there is no quorum */
	int n_tgts = reptrans_get_fd_targets_number(domain);
	if (n_tgts < n_data + n_parity) {
		/* We should decide whether we in a split or the setup has
		 * insufficient number of failure domain. In the last case remove
		 * manifest from the encoding queue.
		 */
		int try_again = 1;
		if (ccowd_get_fddelta() < 0) {
			/* Split, calculate expected number of FDs */
			int n_tgts_total = n_tgts - ccowd_get_fddelta();
			if (n_tgts_total < n_data + n_parity)
				try_again = 0;
		}
		if (!try_again)
			log_info(lg, "Dev(%s) setup has insufficient number of "
				"targets: %d instead of %d, skipping",
				dev->path, n_tgts, n_data + n_parity);
		else
			log_debug(lg, "Dev(%s) got %d target instead of %d,"
				"try later", dev->path, n_tgts,
				n_data + n_parity);
		return try_again ? -EAGAIN : -EINVAL;
	}
	log_info(lg, "Dev(%s) try encode manifest chid %s "
		"type %s", dev->path, chidstr, type_tag_name[ttype]);

	FROM_CODECFMT(fmt, n_data, n_parity);
	ccow_t cl = reptrans_get_tenant_context(dev->rt, 0);
	if (!cl) {
		log_debug(lg, "Dev(%s) missing TC, exiting", dev->path);
		return -EAGAIN;
	}

	err = reptrans_get_blob(dev, ttype, hash_type, chid, &rb);
	if (err || !rb) {
		log_debug(lg, "Dev(%s): couldn't find a manifest CHID %s type %s",
		    dev->path, chidstr, type_tag_name[ttype]);
		reptrans_put_tenant_context(dev->rt, cl);
		return 0;
	}

	/* Extract manifest's refentries */
	err = ttype == TT_CHUNK_MANIFEST ?
		replicast_unpack_cm_refs(rb, &refs, 0) :
		replicast_get_refs(rb, &refs, 0);
	if (err || !refs) {
		log_error(lg, "Dev(%s) error unpacking manifest chid %s type "
			"%s: %d", dev->path, chidstr, type_tag_name[ttype],
			err);
		if (!err)
			err = -EINVAL;
		goto _out;
	}
	if (!refs->nbufs) {
		log_debug(lg, "Dev(%s) manifest chid %s doesn't have refentries,"
			"skipping", dev->path, chidstr);
		err = 0;
		goto _out;
	}
	/* In embedded mode we will NOT encode a manifest whose refentries
	 * size greater than 48M
	 */
	if (is_embedded()) {
		size_t data_size = 0;
		for (size_t i = 0; i < refs->nbufs; i++) {
			struct refentry* e = (struct refentry*)rtbuf(refs, i).base;
			uint8_t ref_ttag = ref_to_ttag[RT_REF_TYPE(e)];
			if (ref_ttag == TT_CHUNK_PAYLOAD)
				data_size += e->compressed_length;
		}
		if (data_size > EC_PAYLOAD_SIZE_MAX_EMBEDDED) {
			log_notice(lg, "Dev(%s) manifest chid %s refentries size %lu MB "
				"exceeded absolute maximum in the embedded mode,"
				"encoding skipped", dev->path, chidstr,
				EC_PAYLOAD_SIZE_MAX_EMBEDDED/(1024UL*1024UL));
			err = 0;
			goto _out;
		}
	}

	/* Check is the codec available and support requested format */
	err = ec_cm_codec_info(algo, &codec_info);
	if (err || !codec_info) {
		log_error(lg, "Dev(%s) manifest CHID %s type %s requested "
			"unsupported codec ID %d", dev->path, chidstr,
			type_tag_name[ttype], algo);
		goto _out;
	}

	for (int i = 0; i < codec_info->n_formats; i++) {
		if (codec_info->formats[i] == fmt) {
			fmt_found = 1;
			break;
		}
	}
	if (!fmt_found) {
		log_error(lg, "Dev(%s) manifest CHID %s type %s codec %s "
			"doesn't support format %d", dev->path, chidstr,
			type_tag_name[ttype], codec_info->name, fmt);
		err = 0;
		goto _out;
	}
	/* Create codec instance */
	err = ec_cm_create_instance(algo, fmt, &chdl);
	if (err) {
		log_warn(lg, "Dev(%s) manifest CHID %s type %s couldn't "
			"create instance of codec %s: %d", dev->path, chidstr,
			type_tag_name[ttype], codec_info->name, err);
		err = -EAGAIN;
		goto _out;
	}
	/* Store NHID of the VM */
	if (ttype == TT_VERSION_MANIFEST) {
		md = je_calloc(1, sizeof(*md));
		if (!md) {
			err = -EAGAIN;
			goto _out;
		}
		err = replicast_get_metadata(rb, md);
		if (err) {
			log_error(lg, "Dev(%s) error reading metadata CHID %s "
				"type %s: %d", dev->path, chidstr,
				type_tag_name[ttype], err);
			goto _out;
		}
	}
	/* Shared parity chunk's VBR */
	struct backref vbr = {
		.generation = 0,
		.uvid_timestamp = 0,
		.ref_hash = hash_type,
		.ref_type = TT_PARITY_MANIFEST,
		.ref_chid = *chid,
		.rep_count = 1,
		.attr = VBR_ATTR_EC | VBR_ATTR_CP,
		.name_hash_id = md ? md->nhid : uint512_null
	};
	pvbr = msgpack_pack_init();
	if (pvbr)
		err = reptrans_pack_vbr(pvbr, &vbr);
	if (!pvbr || err) {
		log_warn(lg, "Dev(%s) manifest CHID %s type %s couldn't "
			"allocate memory", dev->path, chidstr,
			type_tag_name[ttype]);
		err = -EAGAIN;
		goto _out;
	}
	msgpack_get_buffer(pvbr, &ub_vbr);

	err = ec_locate_chunk_retry(dev, &manifest_info,
		vreq->ttag == TT_VERSION_MANIFEST ? &md->nhid : NULL, 1);

	if (err) {
		log_warn(lg, "Dev(%s) error locating manifest chid %s "
			"type %s: %d", dev->path, chidstr,
			type_tag_name[ttype], err);
		err = -EAGAIN;
		goto _out;
	}
	if (!manifest_info.n_vbrs_min) {
		log_warn(lg, "Dev(%s) not all replicas of manifest %s "
			"type %s were verified, postponing",
			dev->path, chidstr, type_tag_name[ttype]);
		err = -EAGAIN;
		goto _out;
	}

	/* Encode manifest only on a VDEV with lowest ID */
	for (size_t i = 0; i < manifest_info.n_vdevs; i++) {
		if (uint128_cmp(&dev->vdevid, manifest_info.vdevs+i) > 0) {
			log_debug(lg, "Dev(%s) manifest CHID %s type %s skipped "
				"due to VDEV cmp", dev->path, chidstr,
				type_tag_name[ttype]);
			err = -EINVAL;
			goto _out;
		}
	}

	/* We don't want to encode already encoded manifest */
	struct blob_stat stat = { .size = 0 };
	err = reptrans_blob_stat(dev, TT_PARITY_MANIFEST, hash_type, chid, &stat);
	if (!err || stat.size > 0) {
		log_debug(lg, "Dev(%s) manifest CHID %s type %s already encoded",
				dev->path, chidstr,
				type_tag_name[ttype]);
		err = -EEXIST;
		goto _out;
	}
	/*
	 *  Ensure we can store parity manifests on required VDEVs
	 *
	 */
	for (uint32_t i=0; i < manifest_info.n_vdevs; i++) {
		vdevstate_t vstate = 0;
		SERVER_FLEXHASH_SAFE_CALL(
			err = vdevstore_get_state(SERVER_FLEXHASH->vdevstore,
				manifest_info.vdevs + i, &vstate), FH_LOCK_READ);
		if (vstate != VDEV_STATE_ALIVE) {
			char vdevstr[UINT128_BYTES*2+1];
			uint128_dump(manifest_info.vdevs + i, vdevstr,
				UINT128_BYTES*2+1);
			log_debug(lg, "Dev(%s) cannot store a PM on a VDEV %s, "
				"state %d,try later", dev->name, vdevstr, vstate);
			err = -EAGAIN;
			goto _out;
		}
	}

	/* Requesting manifest entries location */
	struct backref br = {
		.ref_chid = *chid,
		.attr = 0
	};
	err = ec_get_chunk_info_retry(dev, chid, refs, &br, 1, VBR_ATTR_EC,
		LOCATE_MATCH_VBR_ATTR | LOCATE_MATCH_REFCHID | LOCATE_SKIP_WO_VBRS,
		&cinfos, &n_infos);
	if (err) {
		log_warn(lg, "Dev(%s) error locating manifest refentries,"
			"CHID %s type %s: %d", dev->path, chidstr,
			type_tag_name[ttype], err);
		err = -EAGAIN;
		goto _out;
	}
	bg_replicast_delay(dev, 10000, job);
	err = ec_encoding_propagate(dev, refs, vreq);
	if (err) {
		log_warn(lg, "Dev(%s) ec_encoding_propagate failed,"
			"CHID %s type %s: %d", dev->path, chidstr,
			type_tag_name[ttype], err);
		err = -EAGAIN;
		goto _out;

	}
	/* Skip propagation error for now */
	if (n_infos) {
		/* Looks like a zero-level manifest, check if it has
		 * expected ERC and VBRs
		 */
		if (!manifest_info.n_vbrs_min) {
			log_debug(lg, "Dev(%s) manifest CHID %s type %s isn't protected",
				dev->path, chidstr, type_tag_name[ttype]);
			err = -EAGAIN;
			goto _out;
		}

		int erc;
		SERVER_FLEXHASH_SAFE_CALL(erc = reptrans_get_effective_rep_count(
			manifest_info.vdevs, manifest_info.n_vdevs, domain), FH_LOCK_READ);

		err = reptrans_vbrs_iterate(dev, chid, hash_type,
			ec_vbr_iterator_cb, &rep_count);
		if (err) {
			if (err == -ENOMEM)
				err = -EAGAIN;
			goto _out;
		}

		if (erc < n_parity + 1) {
			/* ERC less than expected, check VBR. If RC >= ERC,
			 * then we can wait for "eventual consistency".
			 * Otherwise drop the manifest.
			 */
			if (rep_count < n_parity + 1) {
				log_debug(lg, "Dev(%s) manifest CHID %s type %s"
					" isn't going to have enough copies, dropping",
					dev->path, chidstr, type_tag_name[ttype]);
				err = -EINVAL;
			} else {
				log_debug(lg, "Dev(%s) manifest CHID %s type %s"
					" doesn't have enough copies yet, keep trying",
					dev->path, chidstr, type_tag_name[ttype]);
				err = -EAGAIN;
			}
			goto _out;
		}
	} else {
		/* This manifest doesn't have any entries to be encoded */
		err = 0;
		goto _out;
	}
	/* v2.1.3FP3 for rowevac:
	 * We must skip encoding if at least one chunk replica can be evacuated
	 * while the encoding is in progress.
	 */
	for (int n = 0; n < n_infos; n++) {
		if (cinfos[n].flags & LOCATE_FLAG_ROWEVAC) {
			log_info(lg, "Dev(%s) at least one affected VDEV has an "
				"rowevac job in progress, "
				"encoding is postponed", dev->name);
			err = -EAGAIN;
			goto _out;
		} else if (cinfos[n].n_vbrs_max == 0) {
			// Make sure there is at least one verified chunk replica
			log_info(lg, "Dev(%s) at least one data chunk doesn't have a VBR, "
				"encoding is postponed", dev->name);
			err = -EAGAIN;
			goto _out;
		}
	}

	log_debug(lg, "Dev(%s) start encoding ttype %s, hash_type %s,"
		"chid %s", dev->name, type_tag_name[ttype],
		hash_type_name[hash_type], chidstr);
	/* Creating parity sets */
	err = ec_fetch_devinfo(&devinfo, &ndev, -1);
	if (err) {
		log_warn(lg, "Dev(%s) error fetching VDEVs info: %d",
			dev->path, err);
		err = -EAGAIN;
		goto _out;
	}
	bg_replicast_delay(dev, 30000, job);
	err = ec_build_parity_sets(devinfo, ndev, cinfos, n_infos, n_data,
		n_parity, domain, rep_count, &psets, &npsets);
	if (err) {
		log_error(lg, "Dev(%s) manifest CHID %s type %s error during "
			"parity sets creation: %d", dev->path, chidstr,
			type_tag_name[ttype], err);
		err = -EAGAIN;
		goto _out;
	}
	if (!npsets) {
		/* Couldn't create any parity sets, exiting */
		log_debug(lg, "Dev(%s) manifest CHID %s type %s"
			" couldn't create sets, n_infos %d, skipping",
			dev->path, chidstr, type_tag_name[ttype], n_infos);
		/* There could be cluster-wide RO condition.
		 * So we should retry the encoding later.
		 * But only if we have enough data chunk.
		 */
		if (n_infos >= n_parity)
			err = -EAGAIN;
		else
			err = -EINVAL;
		goto _out;
	}

	fragments = je_calloc(n_data+n_parity, sizeof(struct ec_fragment));
	if (!cc)
		cc = ec_ccache_create(n_infos*2);
	/* Generating parity chunks */
	for (int i = 0; i < npsets; i++) {
		struct ec_pset* set = psets + i;
		rtbuf_t* rb_data = NULL;
		if (set->n_entries != n_data || set->n_parity != n_parity) {
			log_debug(lg, "CM %s SET %d scheme mismatch: %d:%d vs %d:%d",
				chidstr, i, n_data, n_parity, set->n_entries,
				set->n_parity);
		}
		/* Retrieving data chunks */
		bg_replicast_delay(dev, 10000, job);
		err = ec_get_data_chunks(cl, dev, set, &rb_data, cc);
		if (err) {
			log_warn(lg, "Dev(%s) error fetching data chunks: %d",
				dev->path, err);
			err = -EAGAIN;
			goto _out;
		}
		/* Add zero buffers, if required */
		while (rb_data->nbufs < (size_t)n_data) {
			uv_buf_t ub = { .len = rtbuf(rb_data, 0).len };
			ub.base = je_calloc(1, ub.len);
			err = rtbuf_add(rb_data, &ub, 1);
			if (err) {
				log_warn(lg, "Dev(%s) memory allocation error",
					dev->path);
				err = -EAGAIN;
				goto _out;
			}
		}
		/* Preparing fragments */
		for (int k = 0; k < n_data+n_parity; k++) {
			if (k < n_data)
				fragments[k].buf = rtbuf(rb_data, k);
			else {
				fragments[k].buf.len = 0;
				fragments[k].buf.base = NULL;
			}
			fragments[k].index = k;
		}
		/* creating parity chunks */
		err =  ec_cm_encode(chdl, fragments, fragments+n_data,
			&set->context);
		if (err) {
			log_error(lg, "Dev(%s) manifest %s type %s coding error"
				" %d", dev->path, chidstr, type_tag_name[ttype],
				err);
			rtbuf_destroy(rb_data);
			err = -EAGAIN;
			goto _out;
		}
		bg_replicast_delay(dev, 10000, job);
		/* calculate parity CHIDs, create compounds */
		for (int k = 0; k < n_parity; k++) {
			/* Adding padding to parity data.
			 * It will be used to adjust CHID according to NG
			 */
			set->parity[k].chunk.len = fragments[n_data+k].buf.len +
				sizeof(uint64_t);
			set->parity[k].chunk.base =
					je_calloc(1, set->parity[k].chunk.len);
			if (!set->parity[k].chunk.base) {
				rtbuf_destroy(rb_data);
				err = -EAGAIN;
				goto _out;
			}
			memcpy(set->parity[k].chunk.base,
				fragments[n_data+k].buf.base,
				fragments[n_data+k].buf.len);
			set->parity[k].padding = 0;
			fhrow_t ng = 0, row = 0;
			/* Establish row number for the caclulated VDEV */
			SERVER_FLEXHASH_SAFE_CALL(err = flexhash_get_vdev_row(
				SERVER_FLEXHASH, &set->parity[k].vdevid, &ng), FH_LOCK_READ);
			if (err) {
				char vdevstr [UINT128_BYTES*2 + 1];
				uint128_dump(&set->parity[k].vdevid, vdevstr,
					UINT128_BYTES*2 + 1);
				log_warn(lg, "Flexhash couldn't find VDEV ID %s", vdevstr);
				err = -EAGAIN;
				rtbuf_destroy(rb_data);
				goto _out;
			}
			rtbuf_t* rb_hash =
				rtbuf_init_mapped(&set->parity[k].chunk, 1);
			if (!rb_hash) {
				log_error(lg, "rtbuf alloc error");
				err = -EAGAIN;
				rtbuf_destroy(rb_data);
				goto _out;
			}
			char* base = set->parity[k].chunk.base +
				fragments[n_data+k].buf.len;
			/* Changing padding value trying to get parity's
			 * CHID corresponding to NG
			 **/
			uint64_t ht_lookup_ts = get_timestamp_us();
			do {
				memcpy(base, &set->parity[k].padding,
					sizeof(set->parity[k].padding));
				err = rtbuf_hash(rb_hash, PARITY_CHUNK_HASH_TYPE,
					&set->parity[k].chid);
				assert(err == 0);
				SERVER_FLEXHASH_SAFE_CALL(
					row = HASHROWID(&set->parity[k].chid,
					SERVER_FLEXHASH), FH_LOCK_READ);
			} while (ng != row && set->parity[k].padding++ < (1LL<<60));
			rtbuf_destroy(rb_hash);
			if (ng != row) {
				log_error(lg, "Coulnd't find a good padding pattern");
				err = -EINVAL;
				je_free(set->parity[k].chunk.base);
				rtbuf_destroy(rb_data);
				goto _out;
			} else {
				log_debug(lg, "Dev(%s) padding found within %.2f sec after %lu iterations",
					dev->name, (get_timestamp_us() - ht_lookup_ts)/1000000.0,
					set->parity[k].padding);
			}
			/* Prepare compound */
			struct iovec iov[2];
			iov[0].iov_base = set->parity[k].chunk.base;
			iov[0].iov_len = set->parity[k].chunk.len;
			iov[1].iov_base = ub_vbr.base;
			iov[1].iov_len = ub_vbr.len;
			type_tag_t tts[2] = {TT_CHUNK_PAYLOAD, TT_VERIFIED_BACKREF};
			err = reptrans_pack_compound(iov, 2, tts,
				&set->parity[k].chid, &set->parity[k].compound,
				PARITY_CHUNK_HASH_TYPE, COMPOUND_FLAG_PRIMARY_PUT);
			if (err) {
				log_warn(lg, "Dev(%s) manifest %s type %s "
					"error creating compound %d", dev->path,
					chidstr, type_tag_name[ttype], err);
				rtbuf_destroy(rb_data);
				err = -EAGAIN;
				goto _out;
			}
			je_free(set->parity[k].chunk.base);
			bg_replicast_delay(dev, 10000, job);
		}
		rtbuf_destroy(rb_data);
	}
	uint512_t nhid = ttype == TT_VERSION_MANIFEST ?
			md->nhid : uint512_null;

	uint64_t cur_genid = 0;
	SERVER_FLEXHASH_SAFE_CALL(cur_genid = flexhash_genid(SERVER_FLEXHASH),
		FH_LOCK_READ);
	if (cur_genid != gen_id) {
		log_debug(lg, "Dev(%s) FH GenID changed, encoding postponed",
			dev->name);
		err = -EAGAIN;
		goto _out;
	}
	/* Got here when all is prepared, start spreading */
	for (int i = 0; i < npsets; i++) {
		/*
		 * Send parity chunks to calculated VDEVs
		 * Use targeted unnamed put of compound without compression
		 */
		uv_buf_t buf;
		struct ec_pset* set = psets + i;
		for (int k = 0; k < set->n_parity; k++) {
			/* Ensure the VDEV is alive */
			struct ec_dev_info * devi = find_device(devinfo, ndev,
				&set->parity[k].vdevid);
			if (devi->state != VDEV_STATE_ALIVE) {
				log_warn(lg, "Dev(%s) manifest %s VDEV %lX status "
					"has changed to %d, parity sets aren't valid, "
					"retrying", dev->name, chidstr,
					set->parity[k].vdevid.u,devi->state);
				err = -EAGAIN;
				goto _out;
			}
			msgpack_get_buffer(set->parity[k].compound, &buf);
			/* Sending compound using unnamed put */
			uint32_t attr =
				RD_ATTR_CHUNK_PAYLOAD |
				RD_ATTR_COMPOUND |
				RD_ATTR_TARGETED |
				RD_ATTR_NCOMP;
			err = ec_unnamed_put_chunk_retry(cl, &buf, 1, attr,
				PARITY_CHUNK_HASH_TYPE, &set->parity[k].chid,
				&set->parity[k].vdevid, NULL);
			if (!err && dev->terminating)
				err = -ENODEV;
			if (err) {
				log_warn(lg, "Dev(%s) manifest %s type %s error "
					"sending compound %d", dev->path, chidstr,
					type_tag_name[ttype], err);
				err = -EAGAIN;
				goto _out;
			}
			SERVER_FLEXHASH_SAFE_CALL(cur_genid = flexhash_genid(SERVER_FLEXHASH),
				FH_LOCK_READ);
			if (cur_genid != gen_id) {
				log_debug(lg, "Dev(%s) FH GenID changed, encoding postponed",
					dev->name);
				err = -EAGAIN;
				goto _out;
			}
		}
		/* relocate data chunks */
		for (int k = 0; k < set->n_entries; k++) {
			struct ec_pset_entry* e = set->entries + k;
			int relocate = 1;
			/*
			 * If target VDEV isn't among existing replicas,
			 * then do relocation: put new chunk replica to the target,
			 * old copies will be removed later in this function.
			 */
			for (size_t i = 0; i < e->info->n_vdevs; i++)
				if (!uint128_cmp(e->info->vdevs + i, &e->tgt_vdev)) {
					relocate = 0;
					break;
				}
			if (!relocate)
				continue;

			/* Ensure the VDEV is alive */
			struct ec_dev_info * devi = find_device(devinfo, ndev,
				&e->tgt_vdev);
			if (devi->state != VDEV_STATE_ALIVE) {
				log_warn(lg, "Dev(%s) manifest %s VDEV %lX status "
					"has changed to %d, parity sets aren't valid, "
					"retrying", dev->name, chidstr, e->tgt_vdev.u,
					devi->state);
				err = -EAGAIN;
				goto _out;
			}
			err = 0;
			uv_buf_t chunk = { .len = 0, .base = NULL };
			int hit = ec_ccache_get_mapped(cc, &e->info->chid, &chunk);
			assert(hit);
			uv_buf_t ub_comp = {0};
			err = ec_prepare_compound(chid, ttype, &e->info->chid,
				&nhid, e->info->hash_type, &chunk, 1, VBR_ATTR_EC | VBR_ATTR_CP,
				&ub_comp, 0);
			if (err) {
				log_warn(lg, "Dev(%s) manifest %s type %s failed "
					"to prepare compound for relocation: %d",
					dev->path, chidstr, type_tag_name[ttype],
					err);
				err = -EAGAIN;
				goto _out;
			}
			/* Sending compound using unnamed put */
			uint32_t attr = RD_ATTR_CHUNK_PAYLOAD |
					RD_ATTR_COMPOUND |
					RD_ATTR_TARGETED |
					RD_ATTR_NCOMP;
			err = ec_unnamed_put_chunk_retry(cl, &ub_comp, 1, attr,
				e->info->hash_type, &e->info->chid, &e->tgt_vdev,
				NULL);
			je_free(ub_comp.base);
			if (err) {
				log_warn(lg, "Dev(%s) manifest %s type %s error "
					"relocating data chunk %d",
					dev->path, chidstr, type_tag_name[ttype],
					err);
				err = -EAGAIN;
				goto _out;
			}
			SERVER_FLEXHASH_SAFE_CALL(cur_genid = flexhash_genid(SERVER_FLEXHASH),
				FH_LOCK_READ);
			if (cur_genid != gen_id) {
				log_debug(lg, "Dev(%s) FH GenID changed, encoding postponed",
					dev->name);
				err = -EAGAIN;
				goto _out;
			}
		}
	}
	/*
	 * Create parity manifest
	 */
	p = msgpack_pack_init();
	err = ec_pack_parity_map(p, psets, npsets, domain, algo, fmt);
	if (err) {
		log_error(lg, "Dev(%s) manifest %s type %s error packing "
			"parity map %d", dev->path, chidstr,
			type_tag_name[ttype], err);
		err = -EAGAIN;
		goto _out;
	}
	uv_buf_t ub_pmap;
	msgpack_get_buffer(p, &ub_pmap);
#if EC_DEBUG
	ec_dump_parity_sets(dev, chid, psets, npsets, SERVER_FLEXHASH);
#endif
	rb_pmap = rtbuf_init_mapped(&ub_pmap, 1);
	if (!rb_pmap) {
		log_warn(lg, "Dev(%s) manifest %s type %s malloc error",
			dev->path, chidstr, type_tag_name[ttype]);
		err = -EAGAIN;
		goto _out;
	}
	/* Store the manifest on a local and remote devices */
	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_ALIVE)
	{
		err = reptrans_put_blob_with_attr(dev, TT_PARITY_MANIFEST,
			HASH_TYPE_DEFAULT, rb_pmap, chid, 0,
			reptrans_get_timestamp(dev));
		if (err) {
			log_error(lg, "Dev(%s) manifest %s type %s parity map put "
				"error(local) %d", dev->path, chidstr,
				type_tag_name[ttype], err);
			err = -EAGAIN;
			goto _out;
		}
	} else {
		log_error(lg, "Dev(%s) manifest %s type %s parity map put: "
			"VDEV isn't ready to store",dev->path, chidstr,
			type_tag_name[ttype]);
		err = -EAGAIN;
		goto _out;
	}

	for (uint32_t i=0; i < manifest_info.n_vdevs; i++) {
		if (!uint128_cmp(manifest_info.vdevs + i, &dev->vdevid))
			continue;

		struct ec_dev_info * devi = find_device(devinfo, ndev,
			manifest_info.vdevs + i);

		if (!devi || devi->state != VDEV_STATE_ALIVE) {
			/* We cannot put a parity manifest (PM) to dead to RO VDEV.
			 * Skipp it. Later the space reclaim remove CM/VM without
			 * a PM and create a new replica of CM/VM+PM pair.
			 */
			continue;
		}
		SERVER_FLEXHASH_SAFE_CALL(cur_genid = flexhash_genid(SERVER_FLEXHASH),
			FH_LOCK_READ);
		if (cur_genid != gen_id) {
			log_debug(lg, "Dev(%s) FH GenID changed, encoding postponed",
				dev->name);
			err = -EAGAIN;
			goto _out;
		}
		uint32_t attr = RD_ATTR_PARITY_MAP |
				RD_ATTR_NCOMP |
				RD_ATTR_TARGETED;
		err =  ec_unnamed_put_chunk_retry(cl, &ub_pmap, 1, attr,
			HASH_TYPE_DEFAULT, chid, manifest_info.vdevs + i, NULL);
		if (!err && dev->terminating)
			err = -ENODEV;
		if (err) {
			char vdevstr[UINT128_BYTES*2+1];
			uint128_dump(manifest_info.vdevs + i, vdevstr,
				UINT128_BYTES*2+1);
			log_warn(lg, "Dev(%s) manifest %s type %s error "
				"sending parity map to a VDEV %s: %d",
				dev->path, chidstr, type_tag_name[ttype],
				vdevstr, err);
			err = -EAGAIN;
			goto _out;
		}
	}

	for (int i = 0; i < npsets; i++) {
		struct ec_pset* set = psets + i;
		/* REmoving or updating VBRs */
		for (int k = 0; k < set->n_entries; k++) {
			SERVER_FLEXHASH_SAFE_CALL(cur_genid = flexhash_genid(SERVER_FLEXHASH),
				FH_LOCK_READ);
			if (cur_genid != gen_id) {
				log_debug(lg, "Dev(%s) FH GenID changed, encoding postponed",
					dev->name);
				err = -EAGAIN;
				goto _out;
			}
			struct ec_pset_entry* e = set->entries + k;
			struct backref vbr_e = {
					.generation = 0,
					.uvid_timestamp = 0,
					.rep_count = 0,
					.ref_chid = *chid,
					.ref_hash = hash_type,
					.ref_type = ttype,
					.name_hash_id = ttype == TT_VERSION_MANIFEST ?
						md->nhid : uint512_null,
					.attr = VBR_ATTR_EC | VBR_ATTR_CP
			};
			for (uint32_t j = 0; j < e->info->n_vdevs; j++) {
				struct ec_dev_info * devi = find_device(devinfo,
					ndev, e->info->vdevs + j);
				if (devi->state == VDEV_STATE_DEAD) {
					err = -ENODEV;
					goto _out;
				}
				vbr_e.rep_count = !uint128_cmp(&e->tgt_vdev, e->info->vdevs + j);
				/* if rep_count == 0, then all VBRs will be removed */
				err = ec_targeted_propagate_vbr(dev, &e->info->chid,
					TT_CHUNK_PAYLOAD, e->info->hash_type,
					e->info->vdevs + j, &vbr_e,
					vbr_e.rep_count ? RT_VERIFY_NORMAL : RT_VERIFY_DELETE);
				if (!err && dev->terminating)
					err = -ENODEV;
				if (err) {
					err = -EAGAIN;
					goto _out;
				}
			}
		}
	}
_out:
	reptrans_put_tenant_context(dev->rt, cl);
	if (rb_pmap)
		rtbuf_destroy(rb_pmap);
	if (p)
		msgpack_pack_free(p);
	if (chdl)
		ec_cm_destroy_instance(chdl);
	if (devinfo)
		je_free(devinfo);
	if (fragments)
		je_free(fragments);
	if (cinfos)
		ec_clean_chunk_infos(cinfos, n_infos);
	if (psets)
		ec_clean_parity_sets(psets, npsets);
	if (pvbr)
		msgpack_pack_free(pvbr);
	if (rb)
		rtbuf_destroy(rb);
	if (refs)
		rtbuf_destroy(refs);
	if (md)
		je_free(md);
	if (cc)
		ccache_free(cc);
	return err;
}

typedef struct ec_enc_work{
	struct repdev *dev;
	uint64_t n_skipped;
} ec_enc_work_t;

static int
reptrans_ec_encode_queue__cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {

	struct verification_request* vbreq;
	struct bg_job_entry* job = (struct bg_job_entry*) param;
	ec_enc_work_t* work = (ec_enc_work_t*) job->data;
	int err = 0;

	if (bg_job_wait_resume(job, 1000000))
		return -EINVAL;

	if (!is_cluster_healthy(dev->rt, 1))
		return -ENODEV;

	assert(ccow_daemon);
	assert(SERVER_FLEXHASH);
	assert(val->len == sizeof(struct verification_request));
	vbreq = (struct verification_request*)val->base;

	if (vbreq->ttag == TT_VERSION_MANIFEST) {
		/* Do not encode VMs which are scheduled for purge */
		int has_version = reptrans_has_version(dev, HASH_TYPE_DEFAULT,
			&vbreq->vbr.name_hash_id, vbreq->vbr.generation);
		if(has_version <= 0) {
			char nhidstr[UINT512_BYTES*2+1];
			uint512_dump(&vbreq->vbr.name_hash_id, nhidstr,
				UINT512_BYTES*2+1);
			log_debug(lg, "Dev(%s) skipping encoding of NHID %s"
				" generation %lu", dev->name, nhidstr,
				vbreq->vbr.generation);
			work->n_skipped++;
			goto _del_entry;
		}
	}
	if (vbreq->uvid_timestamp &&
		vbreq->uvid_timestamp > reptrans_get_timestamp(dev)/1000000) {
		/* Skip it since timeout isn't expired */
		work->n_skipped++;
		return 0;
	}
	if (EC_BG_MAX > dev->rt->active_ec_bg)
		atomic_inc64(&dev->rt->active_ec_bg);
	else
		return -EBUSY;
	/* Lock the manifest */
	manifest_lock_status_t rst;
	struct manifest_lock_entry* re = NULL;
	do {
		re = reptrans_manifest_lock_or_wait(dev, key, &rst);
	} while (!re);
	/* Encode */
	err = ec_encode_manifest(dev, vbreq, job);
	/* Unlock manifest*/
	reptrans_manifest_unlock(dev, re, ENCODING_DONE);
	atomic_dec(&dev->rt->active_ec_bg);

_del_entry:
	if (!err || err != -EAGAIN) {
		/* Encoding finished or got a critical error
		 * remove entry
		 */
		if (err) {
			char chidstr[UINT512_BYTES*2+1];
			uint512_dump(&vbreq->chid, chidstr, UINT512_BYTES*2+1);
			log_debug(lg, "EC encoding of manifest %s skipped: %d",
				chidstr, err);
		}
		err = reptrans_delete_blob(dev, TT_ENCODING_QUEUE,
			hash_type, key);
		if (err) {
			log_error(lg, "Dev(%s) cannot delete encoding queue "
				"entry: %d", dev->path, err);
		}
	}
	job->chunk_counter++;
	return 0;
}

static void
bg_ec_encoder_work(struct bg_job_entry* job, void* data)
{
	assert(data != NULL);

	ec_enc_work_t *work = (ec_enc_work_t *)data;
	assert(work != NULL);
	struct repdev *dev = work->dev;
	assert(dev != NULL);

	reptrans_set_thrname(dev, "ecenc");

	int err = reptrans_iterate_blobs(dev, TT_ENCODING_QUEUE,
		reptrans_ec_encode_queue__cb, job, 1);
	if (err && err != -ENODEV)
		log_debug(lg, "Dev(%s) ec encode queue callback returned %d",
			work->dev->path, err);
}

static void
bg_ec_encoder_done(struct bg_job_entry* job, void* data) {
	assert(data != NULL);

	ec_enc_work_t *work = (ec_enc_work_t *)data;
	assert(work != NULL);
	bg_sched_set_counter(job, work->n_skipped, 0);
	je_free(work);
}

static int
bg_ec_encoder_init(struct bg_job_entry* job, void** pdata) {
	ec_enc_work_t *work = je_calloc(1, sizeof(ec_enc_work_t));
	assert(work != NULL);
	static const char* str[] = {"SKIPPED"};
	work->dev = job->sched->dev;
	*pdata = work;
	bg_sched_register_counters(job, 1, str);
	return 0;
}

void
ec_fill_encoder_bg_calls(struct bg_job_entry* job) {
	assert(job);
	job->init = bg_ec_encoder_init;
	job->work = bg_ec_encoder_work;
	job->work_done = bg_ec_encoder_done;
}


/* EC recovery -related functions */
static struct chunk_info*
ec_chid2info(const uint512_t* chid, struct chunk_info* infos, int n_infos) {
	struct chunk_info* rc = NULL;
	assert(chid);
	assert(infos);
	assert(n_infos);
	for (int i = 0; i < n_infos; i++) {
		if (!uint512_cmp(chid, &infos[i].chid)) {
			rc = infos + i;
			break;
		}
	}
	return rc;
}

static int
ec_recover_parity_set(struct ec_pset* set, ccache_t* cc, ec_codec_id id,
	ec_codec_format fmt, int* n_rec_data_out, int* n_rec_parity_out) {
	assert(set);
	int n_data = 0, n_parity = 0, n_rec_d = 0, n_rec_p = 0;
	codec_handle_t chdl = -1;

	FROM_CODECFMT(fmt, n_data, n_parity);

	struct ec_fragment* frgs = je_calloc(n_data+n_parity,
		sizeof(struct ec_fragment));
	if (!frgs)
		return -ENOMEM;

	/* try to create codec instance */
	int err = ec_cm_create_instance(id, fmt, &chdl);
	if (err) {
		log_error(lg, "Error create codec %d instance: %d\n", id, err);
		je_free(frgs);
		return err;
	}

	/* Preparing fragments */
	for (int i = 0; i < n_data + n_parity; i++) {
		rtbuf_t* rb_data = NULL;
		frgs[i].index = i;
		if (i < n_data) {
			if (i < set->n_entries) {
				if (set->entries[i].status == ECS_MISSING) {
					frgs[i].buf.base = NULL;
					frgs[i].buf.len = set->entries[i].info->size;
				} else {
					int chit = ec_ccache_get_mapped(cc,
						&set->entries[i].info->chid,
						&frgs[i].buf);
					if (chit <= 0) {
						err = -EFAULT;
						goto __exit;
					}
				}
			} else {
				frgs[i].buf.len = set->entries[0].info->size;
				frgs[i].buf.base = je_calloc(1, frgs[i].buf.len);
			}
		} else {
			int p_idx = i - n_data;
			if (set->parity[p_idx].status == ECS_MISSING) {
				frgs[i].buf.base = NULL;
				frgs[i].buf.len = set->parity[p_idx].chunk.len;
			} else {
				int chit = ec_ccache_get_mapped(cc,
					&set->parity[p_idx].chid, &frgs[i].buf);
				if (chit <= 0) {
					err = -EFAULT;
					goto __exit;
				}
			}
			/* Remove padding size */
			frgs[i].buf.len -= sizeof(uint64_t);
		}
	}
	err = ec_cm_recover(chdl, frgs, &set->context);
	if (!err) {
		uint512_t calc_chid;
		char str[UINT512_BYTES*2+1];
		/* Update data/parity chunks */
		for (int i = 0; i < set->n_entries; i++) {
			if (set->entries[i].status != ECS_MISSING)
				continue;
			assert(frgs[i].buf.base);
			/* The chunk is recovered.
			 * Verify it and put to ccache
			 */
			uint512_t chid_calc;
			rtbuf_t* rt = rtbuf_init_mapped(&frgs[i].buf, 1);
			if (!rt) {
				log_error(lg, "Cannot create rtbuf");
				err = -ENOMEM;
				goto __exit;
			}
			rtbuf_hash(rt, set->entries[i].info->hash_type,
				&chid_calc);
			rtbuf_destroy(rt);
			err = uint512_cmp(&set->entries[i].info->chid, &chid_calc);
			if (!err) {
				err = ec_ccache_put(cc,
					&set->entries[i].info->chid,
					&frgs[i].buf);
				if (err && err != -EEXIST) {
					log_error(lg, "Cannot put to ccache");
					err = -ENOMEM;
					goto __exit;
				}
				err = 0;
				set->entries[i].status = ECS_RECOVERED;
				uint512_dump(&set->entries[i].info->chid, str,
					UINT512_BYTES*2+1);
				log_debug(lg, "Data chunk %s is recovered", str);
				n_rec_d++;
			} else {
				uint512_dump(&set->entries[i].info->chid, str,
					UINT512_BYTES*2+1);
				log_error(lg, "Chunk %s hash verification error", str);
				err = -EINVAL;
				goto __exit;
			}
		}
		for (int i = 0; i < set->n_parity; i++) {
			if (set->parity[i].status != ECS_MISSING)
				continue;
			int idx = i + n_data;

			assert(frgs[idx].buf.base);
			uv_buf_t ub = { 0 };
			/* Extend a parity chunk with padding */
			ub.base = je_calloc(1, frgs[idx].buf.len + sizeof(uint64_t));
			if (!ub.base) {
				err = -ENOMEM;
				goto __exit;
			}
			memcpy(ub.base, frgs[idx].buf.base, frgs[idx].buf.len);
			memcpy(ub.base + frgs[idx].buf.len,
				&set->parity[i].padding, sizeof(uint64_t));
			ub.len = frgs[idx].buf.len + sizeof(uint64_t);
			/* Adding chunk to ccache */
			err = ec_ccache_put_mapped(cc, &set->parity[i].chid, &ub);
			if (err && err != -EEXIST) {
				log_error(lg, "Cannot put to ccache");
				err = -ENOMEM;
				goto __exit;
			}
			err = 0;
			set->parity[i].status = ECS_RECOVERED;
			uint512_dump(&set->parity[i].info->chid, str,
				UINT512_BYTES*2+1);
			log_debug(lg, "Parity chunk %s is recovered", str);
			n_rec_p++;
		}
		*n_rec_data_out = n_rec_d;
		*n_rec_parity_out = n_rec_p;
	}
__exit:
	if (err) {
		for (int i = 0; i < set->n_entries; i++) {
			if (set->entries[i].status != ECS_RECOVERED)
				continue;
			set->entries[i].status = ECS_MISSING;
		}
		for (int i = 0; i < set->n_parity; i++) {
			if (set->parity[i].status != ECS_RECOVERED)
				continue;
			set->parity[i].status = ECS_MISSING;
		}
	}
	for (int i = set->n_entries; i < n_data; i++) {
		if (frgs[i].buf.base)
			je_free(frgs[i].buf.base);
	}
	ec_cm_destroy_instance(chdl);
	je_free(frgs);
	return err;
}

static int
ec_put_recovered_chunk(ccow_t cl, ccache_t* cc, const uint512_t* m_chid,
	const uint512_t* nhid, type_tag_t m_ttag, uint512_t* chid,
	crypto_hash_t htype, uint8_t rep_count, uint8_t vbr_attr,
	uint8_t n_copies, int is_parity) {
	int err = 0;
	uv_buf_t chunk = { .len = 0, .base = NULL };
	int hit = ec_ccache_get_mapped(cc, chid, &chunk);
	if (hit <= 0) {
		return -EINVAL;
	}
	uv_buf_t ub_comp = {0};
	err = ec_prepare_compound(m_chid, m_ttag, chid, nhid, htype, &chunk,
		rep_count, vbr_attr, &ub_comp, is_parity);
	if (err)
		goto __out;
	/* Sending compound using unnamed put */
	uint32_t attr = RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_COMPOUND | RD_ATTR_NCOMP;
	err = ec_unnamed_put_chunk_retry(cl, &ub_comp, n_copies, attr,
		htype, chid, (void*)chid, NULL);

__out:
	if (ub_comp.base)
		je_free(ub_comp.base);
	return err;
}

static int
ec_is_pset_recoverable(struct ec_pset* set) {
	return set->n_missing_data + set->n_missing_parity <= set->n_parity;
}

static int
ec_restore_unencode(ccow_t cl, struct repdev* dev, struct ec_pset* psets, size_t n_sets,
	const uint512_t* m_chid, type_tag_t m_tt, const uint512_t* nhid,
	int rep_count, ccache_t* cc) {
	int err = 0, ret = 0;
	/* This approach doing manifest recovery trough unencoding.
	 * Most time expensive approach.
	 */
	for (size_t i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		if (!ec_is_pset_recoverable(set))
			continue;
		for (int j = 0; j < set->n_entries; j++) {
			struct ec_pset_entry* e = set->entries + j;
			if (e->status == ECS_MISSING)
				continue;
			/* Store recovered or replicate already stored chunks */
			err =  ec_put_recovered_chunk(cl, cc, m_chid, nhid, m_tt,
				&e->info->chid, e->info->hash_type, rep_count,
				VBR_ATTR_CP, rep_count, 0);
			if (err) {
				char refchidstr[UINT512_BYTES * 2 + 1];
				uint512_dump(&e->info->chid, refchidstr,
					UINT512_BYTES * 2 + 1);
				refchidstr[31] = 0;
				log_error(lg, "Dev(%s) error putting recovered"
					" chunk %s: %d", dev->path, refchidstr,
					err);
				ret = err;
				continue;
			}
			if (e->status == ECS_RECOVERED)
				e->status = ECS_RESTORED;

			if (e->status != ECS_PRESENT)
				continue;
			/* For already stored chunks remove VBR with RC=1,
			 * replace with expected RC. Using targeted unnamed put
			 * without a data chunk, only VBRs*/
			for (size_t n = 0; n < e->info->n_vdevs; n++) {
				struct backref vbr_e = {
						.generation = 0,
						.uvid_timestamp = 0,
						.rep_count = rep_count,
						.ref_chid = *m_chid,
						.ref_hash = HASH_TYPE_DEFAULT,
						.ref_type = m_tt,
						.attr = VBR_ATTR_CP
				};
				err = ec_targeted_propagate_vbr(dev, &e->info->chid,
					TT_CHUNK_PAYLOAD, HASH_TYPE_DEFAULT,
					e->info->vdevs + n, &vbr_e, RT_VERIFY_NORMAL);
				if (err) {
					char mchidstr[UINT512_BYTES*2+1];
					uint512_dump(m_chid, mchidstr, UINT512_BYTES*2+1);
					log_error(lg, "Dev(%s) manifest %s type "
						"%s error changing VBR %d",
						dev->path, mchidstr,
						type_tag_name[m_tt], err);
					ret = err;
				}
			}
		}
		/* remove parity chunks using targeted delete*/
		for (int j = 0; j < set->n_parity; j++) {
			struct ec_parity_chunk* pi = set->parity + j;
			if (pi->status != ECS_PRESENT)
				continue;
			assert(pi->info);
			for (size_t n = 0; n < pi->info->n_vdevs; n++) {
				struct backref vbr_e = {
						.generation = 0,
						.uvid_timestamp = 0,
						.rep_count = 0,
						.ref_chid = *m_chid,
						.ref_hash = HASH_TYPE_DEFAULT,
						.ref_type = m_tt,
						.attr = VBR_ATTR_EC | VBR_ATTR_CP
				};
				err = ec_targeted_propagate_vbr(dev, &pi->chid,
					TT_CHUNK_PAYLOAD, HASH_TYPE_DEFAULT,
					pi->info->vdevs + n, &vbr_e, RT_VERIFY_DELETE);
				if (err) {
					char mchidstr[UINT512_BYTES*2+1];
					uint512_dump(m_chid, mchidstr, UINT512_BYTES*2+1);
					log_error(lg, "Dev(%s) manifest %s type "
						"%s error removing parity %d",
						dev->path, mchidstr,
						type_tag_name[m_tt], err);
					ret = err;
				}
			}
		}
	}
	/* remove parity manifests */
	struct chunk_info minfo = {
		.chid = *m_chid,
		.hash_type = HASH_TYPE_DEFAULT,
		.ttype = m_tt,
	};
	err = ec_locate_chunk_retry(dev, &minfo,
		m_tt == TT_VERSION_MANIFEST ? (uint512_t*)nhid : NULL, 0);
	if (err) {
		log_error(lg, "Cannot remove parity manifest,"
			"locate error %d", err);
		ret = err;
		goto _cleanup;
	}
	if (!minfo.n_vdevs) {
		log_error(lg, "Something wen't wrong: counldn't find any copies"
			" of the parity manifest");
		ret = -ENODEV;
		goto _cleanup;
	}
	for (uint32_t i = 0; i < minfo.n_vdevs; i++) {
		err = ec_targeted_delete(cl, m_chid, TT_PARITY_MANIFEST,
			HASH_TYPE_DEFAULT, minfo.vdevs + i);
		if (err) {
			ret = err;
			log_error(lg, "Error removing parity manifest");
		}
	}
_cleanup:
	return ret;
}

static int
ec_restore_replicate(ccow_t cl, struct repdev* dev, struct ec_pset* psets, size_t n_sets,
	const uint512_t* m_chid, type_tag_t m_tt, const uint512_t* nhid,
	int rep_count, ccache_t* cc) {
	int err = 0, ret = 0;
	/* This approach restores original replicas of data chunks without VBRs.
	 * It's used instead of un-encoding in case of CM/VM overwrite.
	 */
	for (size_t i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		if (!ec_is_pset_recoverable(set))
			continue;
		for (int j = 0; j < set->n_entries; j++) {
			struct ec_pset_entry* e = set->entries + j;
			if (e->status == ECS_MISSING)
				continue;
			uv_buf_t chunk = { .len = 0, .base = NULL };
			int hit = ec_ccache_get_mapped(cc, &e->info->chid, &chunk);
			if (hit <= 0) {
				return -EINVAL;
			}
			/* Restoring number of chunk replicas */
			uint32_t attr = RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_NCOMP;
			err = ec_unnamed_put_chunk_retry(cl, &chunk, rep_count,
				attr, e->info->hash_type, &e->info->chid,
				&e->info->chid, NULL);
			if (err) {
				char refchidstr[UINT512_BYTES * 2 + 1];
				uint512_dump(&e->info->chid, refchidstr,
					UINT512_BYTES * 2 + 1);
				refchidstr[31] = 0;
				log_error(lg, "Dev(%s) error putting recovered"
					" chunk %s: %d", dev->path, refchidstr,
					err);
				ret = err;
				continue;
			}
			if (e->status == ECS_RECOVERED)
				e->status = ECS_RESTORED;

			if (e->status != ECS_PRESENT)
				continue;
		}
	}
	return ret;
}

static int
ec_restore_to_remote_vdev(ccow_t cl, struct repdev* dev, struct ec_pset* psets, size_t n_sets,
	const uint512_t* m_chid, type_tag_t m_tt, const uint512_t* nhid,
	ccache_t* cc, int is_parity) {
	/* This approach tries to put recovered data chunk to a first matching
	 * local VDEV
	 */
	int err = 0, ret = 0;
	for (size_t i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		if (!ec_is_pset_recoverable(set))
			continue;
		for (int j = 0; j < set->n_entries; j++) {
			struct ec_pset_entry* e = set->entries + j;
			if (e->status != ECS_RECOVERED)
				continue;
			uint512_t* chid = &e->info->chid;
			crypto_hash_t ht = e->info->hash_type;
			/* Put 2 copies. One to be removed later */
			err = ec_put_recovered_chunk(cl, cc, m_chid,
				nhid, m_tt, chid, ht, 1, VBR_ATTR_EC | VBR_ATTR_CP, 2,
				is_parity);
			if (err) {
				char chidstr[UINT512_BYTES*2+1];
				uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
				log_error(lg, "Erorr putting recovered data chunk %s: %d",
					chidstr, err);
				ret = err;
				continue;
			}
			e->status = ECS_RESTORED;
		}
	}
	return ret;
}

static int
find_fd_vdevs_qsort_fd_cb (const void* a, const void* b, void* arg) {
	int *p_fd = arg;
	const struct lvdev* la = a;
	const struct lvdev* lb = a;
	if (*p_fd == FD_ANY_FIRST) {
		return uint128_cmp(&la->vdevid, &lb->vdevid);
	} else if (*p_fd == FD_SERVER) {
		return uint128_cmp(&la->server->id, &lb->server->id);
	}
	return (int)la->server->zone - (int)lb->server->zone;
}

static int
ec_find_fd_vdevs(uint128_t* exists_vdevs, size_t n_exists_vdevs, int fd,
	const uint512_t* ng, uint128_t* new_vdevs, size_t n_new_vdevs) {

	size_t fd_item_count = reptrans_get_fd_targets_number(fd);
	if (n_exists_vdevs + n_new_vdevs > fd_item_count) {
		return -ENOENT;
	}
	ccowd_fhready_lock(FH_LOCK_READ);
	int fh_n_vdevs = SERVER_FLEXHASH->vdevstore->lvdevcount;
	struct lvdev* lvs = je_calloc(fh_n_vdevs, sizeof(struct lvdev));
	if (!lvs) {
		ccowd_fhready_unlock(FH_LOCK_READ);
		return -ENOMEM;
	}
	int n_lvs = 0;
	/*
	 * Collects all VDEVs which doesn't belong to dev/host/zones the
	 * exists_vdevs belong to.
	 */
	for (int i = 0; i < fh_n_vdevs; i++) {
		struct lvdev* lv = SERVER_FLEXHASH->vdevstore->lvdevlist + i;
		if (lv->state != VDEV_STATE_ALIVE)
			continue;
		int skip = 1;
		for (uint16_t n = 0; n < FLEXHASH_MAX_TAB_LENGTH; n++) {
			if (lv->hashcount[n]) {
				skip = 0;
				break;
			}
		}
		if (skip)
			continue;
		int in_fd_already = 0;
		for (size_t j = 0; j < n_exists_vdevs; j++) {
			if (fd == FD_ANY_FIRST) {
				in_fd_already = uint128_cmp(exists_vdevs + j,
					&lv->vdevid) == 0;
				if (in_fd_already)
					break;
				else
					continue;
			}
			struct lvdev* lf = vdevstore_get_lvdev(
				SERVER_FLEXHASH->vdevstore, exists_vdevs + j);
			if (!lf) {
				char vdevstr[UINT128_BYTES*2+1];
				uint128_dump(exists_vdevs + j, vdevstr,
					UINT128_BYTES*2+1);
				log_error(lg, "VDEV find error: VDEV %s is absent",
					vdevstr);
				ccowd_fhready_unlock(FH_LOCK_READ);
				return -ENODEV;
			}
			if (fd == FD_SERVER) {
				in_fd_already = uint128_cmp(&lf->server->id,
					&lv->server->id) == 0;
			} else if (fd == FD_ZONE) {
				in_fd_already = lf->server->zone == lv->server->zone;
			}
			if (in_fd_already)
				break;
		}
		if (!in_fd_already) {
			int add = 1;
			if (ng) {
				add = flexhash_is_rowmember(SERVER_FLEXHASH,
					&lv->vdevid, ng);
			}
			if (add)
				lvs[n_lvs++] = *lv;
		}
	}
	if (n_lvs < 2) {
		if (n_lvs == 1) {
			new_vdevs[0] = lvs->vdevid;
		}
		je_free(lvs);
		ccowd_fhready_unlock(FH_LOCK_READ);
		return n_lvs;
	}
	/* Sort proposed VDEVs according to FD */
	qsort_r(lvs, n_lvs, sizeof(struct lvdev), find_fd_vdevs_qsort_fd_cb, &fd);
	size_t n_fd_proposed = 1;
	new_vdevs[0] = lvs->vdevid;
	for (int i = 1; i < n_lvs; i++) {
		if (n_fd_proposed >= n_new_vdevs)
			break;
		if (fd == FD_SERVER && uint128_cmp(&lvs[i].server->id,
			&lvs[i-1].server->id)) {
			new_vdevs[n_fd_proposed++] = lvs[i].vdevid;
		} else if (fd == FD_ZONE && lvs[i].server->zone != lvs[i-1].server->zone) {
			new_vdevs[n_fd_proposed++] = lvs[i].vdevid;
		} else {
			new_vdevs[n_fd_proposed++] = lvs[i].vdevid;
		}
	}
	je_free(lvs);
	ccowd_fhready_unlock(FH_LOCK_READ);
	return n_fd_proposed;
}

static int
ec_get_pset_vdevs(struct ec_pset* set, uint128_t* vdevs_out, int max_vdevs) {
	int ret = 0;
	for (int i = 0; i < set->n_entries; i++) {
		if (set->entries[i].status != ECS_MISSING) {
			int ndevs = set->entries[i].info->n_vdevs;
			if (ret + ndevs > max_vdevs)
				ndevs = max_vdevs - ret;
			memcpy(vdevs_out + ret, set->entries[i].info->vdevs,
				ndevs*sizeof(uint128_t));
			ret += ndevs;
		}
	}
	for (int i = 0; i < set->n_parity && ret < max_vdevs; i++) {
		if (set->parity[i].status != ECS_MISSING) {
			int ndevs = set->parity[i].info->n_vdevs;
			if (ret + ndevs > max_vdevs)
				ndevs = max_vdevs - ret;
			memcpy(vdevs_out + ret, set->parity[i].info->vdevs,
				ndevs*sizeof(uint128_t));
			ret += ndevs;
		}
	}
	return ret;
}

static int
ec_put_recovered_chunk_targeted(ccow_t cl, uv_buf_t* chunk, const uint512_t* m_chid,
	const uint512_t* nhid, const uint128_t* target_vdev, type_tag_t m_ttag,
	uint512_t* chid, crypto_hash_t htype, int is_parity) {
	int err = 0;
	uv_buf_t ub_comp = {0};
	err = ec_prepare_compound(m_chid, m_ttag, chid, nhid, htype, chunk,
		1, VBR_ATTR_EC | VBR_ATTR_CP, &ub_comp, is_parity);
	if (err)
		goto __out;
	/* Sending compound using targeted unnamed put */
	uint32_t attr = RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_COMPOUND | RD_ATTR_TARGETED | RD_ATTR_NCOMP;
	err = ec_unnamed_put_chunk_retry(cl, &ub_comp, 1, attr,
		htype, chid, (void*)target_vdev, NULL);

__out:
	if (ub_comp.base)
		je_free(ub_comp.base);
	return err;
}

static int
ec_restore_to_fd(ccow_t cl, struct repdev* dev, struct ec_pset* psets, size_t n_sets,
	const uint512_t* m_chid, type_tag_t m_tt, const uint512_t* nhid,
	int domain, ccache_t* cc, int put_parity) {
	int ret = 0;
	char chidstr[UINT512_BYTES*2+1];
	uint128_t* vdevs = je_calloc(100, sizeof(uint128_t));
	if (!vdevs)
		return -ENOMEM;
	uint128_t new_vdev;

	for (size_t i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		if (!ec_is_pset_recoverable(set))
			continue;
		int set_size = set->n_parity + set->n_entries;
		int ndev = ec_get_pset_vdevs(set, vdevs, 100);
		assert(ndev > 0);

		for (int j = 0; j < set->n_entries; j++) {
			struct ec_pset_entry* pe = set->entries + j;
			if (pe->status != ECS_RECOVERED)
				continue;
			int n_new_vdevs = ec_find_fd_vdevs(vdevs, ndev, domain,
				&pe->info->chid, &new_vdev, 1);
			if (n_new_vdevs <= 0) {
				uint512_dump(&pe->info->chid,
					chidstr, UINT512_BYTES*2+1);
				log_debug(lg,"Couldn't find FD VDEV to put "
					"data chunk %s", chidstr);
				ret = -ENODEV;
				continue;
			}
			uv_buf_t chunk = { .len = 0, .base = NULL };
			int hit = ec_ccache_get_mapped(cc, &pe->info->chid, &chunk);
			if (hit <= 0) {
				return -EINVAL;
			}

			int err = ec_put_recovered_chunk_targeted(cl, &chunk,
				m_chid, nhid, &new_vdev, m_tt,
				&pe->info->chid,
				pe->info->hash_type, 0);
			if (err) {
				ret = err;
				uint512_dump(&pe->info->chid,
					chidstr, UINT512_BYTES*2+1);
				log_error(lg, "Error putting recovered chunk %s: %d",
					chidstr, err);
			} else {
				pe->status = ECS_RESTORED;
				vdevs[ndev++] = new_vdev;
				uint512_dump(&pe->info->chid,
					chidstr, UINT512_BYTES*2+1);
				log_debug(lg, "Data chunk %s restored",
					chidstr);
			}
		}
		if (!put_parity)
			continue;
		for (int j = 0; j < set->n_parity; j++) {
			struct ec_parity_chunk* pi = set->parity + j;
			if (pi->status != ECS_RECOVERED)
				continue;
			assert(pi->info);
			/* Look for new VDEV */
			int n_new_vdevs = ec_find_fd_vdevs(vdevs, ndev, domain,
				&pi->chid, &new_vdev, 1);
			if (n_new_vdevs <= 0) {
				uint512_dump(&pi->chid,
					chidstr, UINT512_BYTES*2+1);
				log_debug(lg,"Couldn't find FD VDEV to put "
					"parity chunk %s", chidstr);
				ret = -ENODEV;
				continue;
			}
			uv_buf_t chunk = { .len = 0, .base = NULL };
			int hit = ec_ccache_get_mapped(cc, &pi->chid, &chunk);
			if (hit <= 0) {
				return -EINVAL;
			}
			/* Veriy chid */
			rtbuf_t* rb = rtbuf_init_mapped(&chunk, 1);
			assert(rb);
			uint512_t nchid;
			int err = rtbuf_hash(rb, PARITY_CHUNK_HASH_TYPE, &nchid);
			assert(!err);
			rtbuf_destroy(rb);
			if (uint512_cmp(&nchid, &pi->chid)) {
				uint512_dump(&pi->chid,
					chidstr, UINT512_BYTES*2+1);
				log_error(lg, "Parity chunk CHID %s doesn't match, "
					"size: %lu, padding: %lu",chidstr,
					chunk.len, pi->padding);
				ret = -EINVAL;
				goto _exit;
			}
			/* Store the parity chunk */
			err = ec_put_recovered_chunk_targeted(cl, &chunk,
				m_chid, nhid, &new_vdev, m_tt,
				&pi->chid,
				pi->info->hash_type, 1);
			if (err) {
				ret = err;
				char chidstr[UINT512_BYTES*2+1];
				uint512_dump(&pi->info->chid,
					chidstr, UINT512_BYTES*2+1);
				log_error(lg, "Error putting recovered chunk %s: %d",
					chidstr, err);
			} else {
				pi->status = ECS_RESTORED;
				vdevs[ndev++] = new_vdev;
				uint512_dump(&pi->info->chid,
					chidstr, UINT512_BYTES*2+1);
				log_debug(lg, "Parity chunk %s restored",
					chidstr);
			}
			je_free(chunk.base);
		}
	}
_exit:
	je_free(vdevs);
	return ret;
}

/* Collect information about a parity protected manifest */
int
ec_pm_collect_info(struct repdev* dev, const uint512_t* mchid,
	const uint512_t* nhid, type_tag_t ttag, rtbuf_t* refs,
	struct ec_pset** psets_out, int* n_psets, int* domain,
	uint32_t* algo, uint32_t* fmt, struct chunk_info** infos_out,
	int* n_infos_out, int strict) {

	char mchidstr[UINT512_BYTES*2+1];
	rtbuf_t* pm_rb = NULL;
	msgpack_u* u = NULL;
	struct ec_pset* psets = NULL;
	struct chunk_info* infos = NULL;
	int n_sets = 0;
	int n_infos = 0;
	uint512_dump(mchid, mchidstr, UINT512_BYTES*2+1);

	/* Ensure the manifest is protected */
	int err = reptrans_get_blob(dev, TT_PARITY_MANIFEST, HASH_TYPE_DEFAULT,
		mchid, &pm_rb);

	if (err || !pm_rb)
		return -ENFILE;

	u = msgpack_unpack_init(pm_rb->bufs->base, pm_rb->bufs->len, 0);
	if (!u) {
		log_error(lg, "Dev(%s) manifest %s err unpacking manifest",
			dev->name, mchidstr);
		err = -ENOMEM;
		goto _exit;
	}
	err = ec_unpack_parity_map(u, &psets, &n_sets, domain, algo, fmt);
	if (err) {
		log_error(lg, "Dev(%s) manifest %s err unpacking manifest",
			dev->name, mchidstr);
		err = -EINVAL;
		goto _exit;
	}
	/* Adding parity chunks */
	for (int i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		for (int j = 0; j < set->n_parity; j++) {
			struct refentry* e = je_calloc(1, sizeof(*e));
			if (!e) {
				err = -ENOMEM;
				log_error(lg, "Memory allocation error");
				goto _exit;
			}
			e->content_hash_id = set->parity[j].chid;
			e->compressed_length = set->parity[j].chunk.len;
			RT_REF_HASH_TYPE_SET(e, PARITY_CHUNK_HASH_TYPE);
			RT_REF_TYPE_SET(e, RT_REF_TYPE_NORMAL);
			uv_buf_t ub = { .len = sizeof(struct refentry),
					.base = (char*)e };
			rtbuf_add(refs, &ub, 1);
		}
	}

	ccowd_wait_for_fhrebuild_term(&dev->terminating);
	/* lookup for data chunk location */
	struct backref br = {
		.ref_chid = *mchid,
		.attr = VBR_ATTR_EC
	};
	if (strict)
		err = ec_get_chunk_info(dev, refs, &br, VBR_ATTR_EC, 1,
			LOCATE_MATCH_VBR_ATTR | LOCATE_MATCH_REFCHID | LOCATE_SKIP_WO_VBRS,
			&infos, &n_infos);
	else
		err = ec_get_chunk_info(dev, refs, NULL, 0, 1, 0, &infos, &n_infos);
	if (err) {
		log_error(lg, "Dev(%s) manifest %s err getting chunk infos",
			dev->name, mchidstr);
		err = -EAGAIN;
		goto _exit;
	}
	/* Merge parity sets with corresponding info */
	for (int i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		assert(set);
		for (uint8_t j = 0; j < set->n_entries; j++) {
			struct ec_pset_entry* entry = set->entries + j;
			assert(entry);
			struct chunk_info* info =
				ec_chid2info(&entry->chid, infos, n_infos);
			if (!info) {
				char refstr[UINT512_BYTES*2+1];
				uint512_dump(&entry->chid, refstr,
					UINT512_BYTES*2+1);
				log_error(lg, "Dev(%s) cannot find a refentry"
					"for refChid %s, manifest %s",
					 dev->name, refstr, mchidstr);
				err = -EINVAL;
				goto _exit;
			}
			assert(info);
			entry->info = info;
			if (info->n_vdevs)
				entry->status = ECS_PRESENT;
			else {
				entry->status = ECS_MISSING;
				set->n_missing_data++;
				char chstr[UINT512_BYTES*2+1];
				uint512_dump(&entry->info->chid, chstr,
					UINT512_BYTES*2+1);
				chstr[31] = 0;
				log_debug(lg, "Dev(%s) Data chunk %s is lost",
					dev->name, chstr);
			}
		}

		for (uint8_t j = 0; j < set->n_parity; j++) {
			struct ec_parity_chunk* entry = set->parity + j;
			assert(entry);
			struct chunk_info* info =
				ec_chid2info(&entry->chid, infos, n_infos);
			if (!info) {
				char refstr[UINT512_BYTES*2+1];
				uint512_dump(&entry->chid, refstr,
					UINT512_BYTES*2+1);
				log_error(lg, "Cannot find a refentry"
					"for refChid %s, manifest %s",
					 refstr, mchidstr);
				err = -EINVAL;
				goto _exit;
			}
			assert(info);
			entry->info = info;
			if (info->n_vdevs)
				entry->status = ECS_PRESENT;
			else {
				entry->status = ECS_MISSING;
				set->n_missing_parity++;
				char chstr[UINT512_BYTES*2+1];
				uint512_dump(&entry->chid, chstr,
					UINT512_BYTES*2+1);
				chstr[31] = 0;
				log_debug(lg, "Dev(%s) parity chunk %s is lost",
					dev->name, chstr);
			}
		}
	}
	err = 0;
	*psets_out = psets;
	*n_psets = n_sets;
	if (infos_out)
		*infos_out = infos;
	if (n_infos_out)
		*n_infos_out = n_infos;
_exit:
	if (err) {
		if (psets)
			ec_clean_parity_sets(psets, n_sets);
		if (infos)
			ec_clean_chunk_infos(infos, n_infos);
	}
	if (u)
		msgpack_unpack_free(u);
	if (pm_rb)
		rtbuf_destroy(pm_rb);
	return err;
}

struct cr_item {
	uint128_t row_vdev;
	int	vdev_index;
	int	weigth;
	uint128_t tgt_id;
};

struct cr_list {
	struct chunk_info* info;
	struct cr_item* wa;
	void* data;
	int pos;
};

static void
ec_fill_cr_items (struct cr_list* crl, int set_width, int fd_total, int domain) {
	ccowd_fhready_lock(FH_LOCK_READ);
	struct vdevstore *vs = SERVER_FLEXHASH->vdevstore;
	for (int i = 0; i < vs->lvdevcount; i++) {
		struct lvdev* lv = vs->lvdevlist + i;
		if (lv->state != VDEV_STATE_ALIVE)
			continue;
		int skip = 1;
		for (uint16_t n = 0; n < FLEXHASH_MAX_TAB_LENGTH; n++) {
			if (lv->hashcount[n]) {
				skip = 0;
				break;
			}
		}
		if (skip)
			continue;
		uint128_t tid = uint128_null;
		if (domain == FD_ZONE)
			tid.l = lv->server->zone;
		else if (domain == FD_SERVER)
			tid = lv->server->id;
		/* Calc tgt index */
		int tidx = 0;
		for (int n = 0; n < fd_total; n++) {
			if (!uint128_cmp(&crl[0].wa[n].tgt_id, &tid)) {
				tidx = n;
				break;
			}
			if (!uint128_cmp(&crl[0].wa[n].tgt_id, &uint128_null)) {
				for (int k = 0; k < set_width; k++)
					crl[k].wa[n].tgt_id = tid;
				tidx = n;
				break;
			}
		}
		/* Fill up cr_items
		 * Weight:
		 * 0 - tgt doesn't have VDEVs for current CHID
		 * 1 - tgt has VDEVs for current chid, but there is no chunk copies on it
		 * 2 - tgt has a chunk copy on it
		 */
		for (int n = 0; n < set_width; n++) {
			struct cr_item* item = crl[n].wa + tidx;
			if (item->weigth == 2)
				continue;
			int ret =  flexhash_is_rowmember(SERVER_FLEXHASH,
				&lv->vdevid, &crl[n].info->chid);
			if (ret) {
				if (!item->weigth) {
					item->weigth = 1;
					item->row_vdev = lv->vdevid;
				}
				for (size_t m = 0; m < crl[n].info->n_vdevs; m++) {
					if (!uint128_cmp(crl[n].info->vdevs + m,
						&lv->vdevid)) {
						item->vdev_index = m;
						item->weigth = 2;
						item->row_vdev = lv->vdevid;
						break;
					}
				}
			}
		}
	}
#if EC_DEBUG
	char chidstr[UINT512_BYTES*2+1];
	char vdevstr[UINT128_BYTES*2+1];
	printf("\t\t\tCHIDS:\t");
	for (int i = 0; i < set_width; i++) {
		uint512_dump(&crl[i].info->chid, chidstr, UINT512_BYTES*2+1);
		chidstr[31] = 0;
		printf("%s\t\t", chidstr);
	}
	printf("\n");
	for (int i = 0; i < fd_total; i++) {
		uint128_dump(&crl[0].wa[i].tgt_id, vdevstr,
			UINT128_BYTES*2+1);
		printf("%s\t\t", vdevstr);
		for (int j = 0; j < set_width; j++) {
			printf("%d\t\t\t", crl[j].wa[i].weigth);
		}
		printf("\n");
	}
#endif
	ccowd_fhready_unlock(FH_LOCK_READ);
}

#define CRL_CURPOS_WEIGHT(i) (crl[(i)].wa[crl[(i)].pos].weigth)

static int
ec_crl_fd_wrong(struct cr_list* crl, int index) {
	int ret = CRL_CURPOS_WEIGHT(index) == 0;
	if (!ret) {
		for (int n = 0; n < index; n++) {
			ret = crl[n].pos == crl[index].pos;
			if (ret)
				break;
		}
	}
	return ret;
}

static int
ec_crl_fd_weight(struct cr_list* crl, int len) {
	int ret = 1;
	for (int i = 0; i < len; i++) {
		ret *= CRL_CURPOS_WEIGHT(i);
		if(!ret)
			break;
	}
	return ret;
}

static int
ec_pset_rearrange(struct repdev* dev, ccow_t cl, struct ec_pset* set,
	int domain, const uint512_t* m_chid,
	type_tag_t m_tt, const uint512_t* nhid, ccache_t* cc) {
	int fd_total = 0, err = 0;
	int skip_removal = 0;
	char chidstr[UINT512_BYTES*2+1];
	char vdevstr[UINT128_BYTES*2+1];
	int set_width = set->n_entries + set->n_parity;
	struct cr_list* crl = je_calloc(set_width, sizeof(*crl));
	if(!crl)
		return -ENOMEM;
	fd_total = reptrans_get_fd_targets_number(domain);
	for (int i = 0; i < set_width; i++) {
		crl[i].wa = je_calloc(fd_total, sizeof(struct cr_item));
		if (i < set->n_entries) {
			crl[i].info = set->entries[i].info;
			crl[i].data = set->entries + i;
		} else {
			crl[i].info = set->parity[i-set->n_entries].info;
			crl[i].data = set->parity + i - set->n_entries;
		}
		for (int n = 0; n < fd_total; n++) {
			crl[i].wa[n].vdev_index = -1;
		}
	}
	/* For each VDEV create a weight mark which defines how suitable it
	 * is for a particular chunk
	 * 0 - not suitable, VDEV doesn't belong to CHID's NG
	 * 1 - better, can be used
	 * 2 - the best, chunk is already there
	 */
	ec_fill_cr_items(crl, set_width, fd_total, domain);
	/* Trying to restore PSET protection level.
	 * Find FD combination with the biggest weight
	 **/
	int idx = 0;
	int w_max = 0;
	int shot[set_width];
	do {
		if (crl[idx].pos >= fd_total) {
			crl[idx].pos = 0;
			if (idx) {
				idx--;
				crl[idx].pos++;
				continue;
			}
			else
				break;
		}
		int wrong = ec_crl_fd_wrong(crl, idx);
		if (!wrong) {
			if (idx < set_width - 1) {
				idx++;
			} else {
				int w = ec_crl_fd_weight(crl, set_width);
				if (w > w_max) {
					w_max = w;
					for (int n = 0; n < set_width; n++)
						shot[n] = crl[n].pos;
				}
				crl[idx].pos++;
			}
		} else
			crl[idx].pos++;
	} while (1);

	if (!w_max) {
		/*
		 * Current cluster configuration doesn't allow
		 * to restore full protection of the parity set.
		 * Do the best effort.
		 */
		uint512_dump(m_chid, chidstr, UINT512_BYTES*2+1);
		log_warn(lg," Can't restore full protection of PSET,"
			"manifest %s, trying the best effort", chidstr);
		w_max = 1;
		for (int i = 0; i < set_width; i++) {
			shot[i] = -1;
			int w = 0;
			for (int j = 0 ; j < fd_total; j++) {
				if (crl[i].wa[j].weigth > w) {
					w = crl[i].wa[j].weigth;
					shot[i] = j;
				}
			}
			if (!w) {
				log_error(lg, "Couldn't heal manifest %s",
					chidstr);
				err = -EINVAL;
				goto _exit;
			}
			w_max *= w;
		}
	}
	struct cr_item* item = NULL;
#if EC_DEBUG
	char tgtstr[UINT128_BYTES*2+1];
	printf("Set re-arranged, weight %d:\n", w_max);
	for (int n = 0; n < set_width; n++) {
		crl[n].pos = shot[n];
		item = crl[n].wa + crl[n].pos;
		uint512_dump(&crl[n].info->chid, chidstr, UINT512_BYTES*2+1);
		uint128_dump(&item->row_vdev, vdevstr, UINT128_BYTES*2+1);
		uint128_dump(&item->tgt_id, tgtstr, UINT128_BYTES*2+1);
		chidstr[31] = 0;
		printf("[%d] CHID %s VDEV %s TGT %s\n", n, chidstr, vdevstr, tgtstr);
	}
#endif
	for (int n = 0; n < set_width; n++) {
		item = crl[n].wa + shot[n];
		int parity = n >= set->n_entries;
		if (item->weigth == 1) {
			/* New location. Put chunks, remove previous */
			uv_buf_t chunk = { .len = 0, .base = NULL };
			int hit = ec_ccache_get_mapped(cc, &crl[n].info->chid,
				&chunk);
			if (hit <= 0) {
				log_error(lg, "ccache lookup error");
				err = -EINVAL;
				goto _exit;
			}
			if (parity) {
				struct ec_parity_chunk* pi = crl[n].data;
				/* Verify chid */
				rtbuf_t* rb = rtbuf_init_mapped(&chunk, 1);
				assert(rb);
				uint512_t nchid;
				int err = rtbuf_hash(rb, PARITY_CHUNK_HASH_TYPE, &nchid);
				assert(!err);
				rtbuf_destroy(rb);
				if (uint512_cmp(&nchid, &pi->chid)) {
					uint512_dump(&pi->chid, chidstr,
						UINT512_BYTES*2+1);
					log_error(lg, "Parity chunk CHID %s doesn't "
						"match, size: %lu, "
						"padding: %lu",chidstr,chunk.len,
						pi->padding);
					err = -EINVAL;
					goto _exit;
				}
			}
			/* Putting recovered */
			err = ec_put_recovered_chunk_targeted(cl, &chunk,
				m_chid, nhid, &item->row_vdev, m_tt,
				&crl[n].info->chid,
				crl[n].info->hash_type, parity);
			uint512_dump(&crl[n].info->chid, chidstr, UINT512_BYTES*2+1);
			if (err) {
				log_error(lg, "Error putting recovered chunk %s: %d",
					chidstr, err);
				skip_removal = 1;
			} else {
				if (parity) {
					struct ec_parity_chunk* pi = crl[n].data;
					if (pi->status == ECS_MISSING ||
						pi->status == ECS_RECOVERED)
						pi->status = ECS_RESTORED;
				} else {
					struct ec_pset_entry* pi = crl[n].data;
					if (pi->status == ECS_MISSING ||
						pi->status == ECS_RECOVERED)
						pi->status = ECS_RESTORED;
				}
				log_debug(lg, "Chunk %s restored",chidstr);
			}
		}
		/* Remove old if any */
		for (size_t m = 0; !skip_removal && m < crl[n].info->n_vdevs; m++) {
			if (!uint128_cmp(crl[n].info->vdevs + m, &item->row_vdev))
					continue;
			struct backref vbr_e = {
					.generation = 0,
					.uvid_timestamp = 0,
					.rep_count = 10, /* Remove VBT by the attr field */
					.ref_chid = *m_chid,
					.ref_hash = HASH_TYPE_DEFAULT,
					.ref_type = m_tt,
					.attr = VBR_ATTR_EC | VBR_ATTR_CP
			};
			err = ec_targeted_propagate_vbr(dev, &crl[n].info->chid,
				TT_CHUNK_PAYLOAD, HASH_TYPE_DEFAULT,
				crl[n].info->vdevs + m, &vbr_e, RT_VERIFY_DELETE);
			uint512_dump(&crl[n].info->chid, chidstr,
				UINT512_BYTES*2+1);
			uint128_dump(crl[n].info->vdevs + m, vdevstr,
				UINT128_BYTES*2+1);

			if (err) {
				log_error(lg, "Dev(%s) VBR propagation error %s: %d",
					dev->name, chidstr, err);
				goto _exit;
			} else
				log_debug(lg, "Dev(%s) removed old VBR %s from VDEV %s",
					dev->name, chidstr, vdevstr);
		}
	}
_exit:
	if (crl) {
		for (int i = 0; i < set_width; i++) {
			if (crl[i].wa)
				je_free(crl[i].wa);
		}
		je_free(crl);
	}
	return err;
}

static int
ec_remove_redundant(ccow_t cl, struct repdev* dev, const uint512_t* mchid,
	type_tag_t ttag, struct ec_pset* psets, int n_sets, struct bg_job_entry* job) {
	struct chunk_info* noec_infos = NULL, *ec_infos = NULL;
	int noec_n_infos = 0, ec_n_infos = 0, err = 0;
	uint64_t vbr_attr = 0;
	rtbuf_t* refs = NULL;
	/**
	 * Sometimes unnamed put adds new replicas of already protected manifests
	 * and its chunk payloads. Such chunks after verification have VBRs with
	 * attr field set to zero. They to be removed cause we don't want to have
	 * addition replicas of protected data chunks.
	 */
	char chidstr[UINT512_BYTES*2+1];
	uint512_dump(mchid, chidstr, UINT512_BYTES*2+1);

	refs = rtbuf_init_empty();
	if (!refs)
		return -ENOENT;

	for (int i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		if (!ec_is_pset_recoverable(set))
			continue;
		for (int j = 0; j < set->n_entries; j++) {
			struct refentry* e = je_calloc(1, sizeof(*e));
			if (!e) {
				err = -ENOMEM;
				log_error(lg, "Memory allocation error");
				goto _exit;
			}
			e->content_hash_id = set->entries[j].info->chid;
			RT_REF_HASH_TYPE_SET(e, set->entries[j].info->hash_type);
			RT_REF_TYPE_SET(e, RT_REF_TYPE_NORMAL);
			uv_buf_t ub = { .len = sizeof(struct refentry),
					.base = (char*)e };
			err = rtbuf_add(refs, &ub, 1);
			if (err) {
				err = -ENOMEM;
				log_error(lg, "Memory allocation error");
				goto _exit;
			}
		}
	}
	struct backref br = {
		.ref_chid = *mchid,
		.attr = VBR_ATTR_EC
	};
	err = ec_get_chunk_info(dev, refs, &br, VBR_ATTR_EC, 1,
		LOCATE_MATCH_VBR_ATTR | LOCATE_MATCH_REFCHID | LOCATE_SKIP_WO_VBRS,
		&ec_infos, &ec_n_infos);
	if (err) {
		log_error(lg, "Dev(%s) manifest %s err getting chunk infos (EC)",
			dev->name, chidstr);
		goto _exit;
	}
	bg_replicast_delay(dev, 50000, job);
	br.attr = 0;
	err = ec_get_chunk_info(dev, refs, &br, VBR_ATTR_EC, 1,
		LOCATE_MATCH_VBR_ATTR | LOCATE_MATCH_REFCHID | LOCATE_SKIP_WO_VBRS,
		&noec_infos, &noec_n_infos);
	if (err) {
		log_error(lg, "Dev(%s) manifest %s err getting chunk infos (noEC)",
			dev->name, chidstr);
		goto _exit;
	}
	assert(ec_n_infos == noec_n_infos);

	struct backref vbr_e = {
			.generation = 0,
			.uvid_timestamp = 0,
			.rep_count = 10, /* remove VBRs with corresponding attr */
			.ref_chid = *mchid,
			.ref_hash = HASH_TYPE_DEFAULT,
			.ref_type = ttag,
			.attr = VBR_ATTR_CP
	};
	for (int i = 0; i < noec_n_infos; i++) {
		struct chunk_info* e = noec_infos + i;
		struct chunk_info* e_ec = ec_infos + i;
		assert(uint512_cmp(&e->chid, &e_ec->chid) == 0);
		/*
		 * We could lose protection due to unexpected termination of
		 * encoding. In such a case some parity sets may not have EC VBRs.
		 * If so, then leave them as is for now. Otherwise,
		 * if there are both EC and non-EC VBR for this refchid, then
		 * remove non-EC VBRs
		 * TODO: re-arrange parity set.
		 */
		if (!e_ec->n_vdevs)
			continue;
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(&e->chid, chidstr, UINT512_BYTES*2+1);
		char vdevstr[UINT128_BYTES*2+1];
		for (size_t n = 0; n < e->n_vdevs; n++) {
			if(!uint128_cmp(e_ec->vdevs, e->vdevs + n))
				continue;
			uint128_dump(e->vdevs + n, vdevstr, UINT128_BYTES*2+1);
			err = ec_targeted_propagate_vbr(dev, &e->chid,
				TT_CHUNK_PAYLOAD, e->hash_type,
				e->vdevs + n, &vbr_e, RT_VERIFY_DELETE);
			if (err) {
				log_error(lg, "Dev(%s) VBR propagation error %s: %d",
					dev->name, chidstr, err);
				goto _exit;
			}
			log_debug(lg, "Del redundant VBR %s VDEV %s", chidstr, vdevstr);
			bg_replicast_delay(dev, 10000, job);
		}
	}
_exit:
	if (ec_infos) {
		ec_clean_chunk_infos(ec_infos, ec_n_infos);
	}
	if (noec_infos) {
		ec_clean_chunk_infos(noec_infos, noec_n_infos);
	}
	if (refs)
		rtbuf_destroy(refs);
	return err;
}

#define BG_MODE_DELAY(x) if(flags & RECOVER_HEAL) bg_replicast_delay(dev,(x), job)
/*
 * Do recovery job. Only data chunks are recovered.
 */
int
ec_recover_manifest_from_refs(struct repdev* dev, const uint512_t* chid,
	const uint512_t* nhid, type_tag_t ttag, rtbuf_t* refs, uint8_t flags,
	struct ec_recovery_stat* pstat, int n_retry, struct bg_job_entry* job) {

	char chidstr[UINT512_BYTES*2+1];
	struct ec_recovery_stat rstat = {0};
	ccache_t* cc = NULL;
	struct ec_pset* psets = NULL;
	int err = 0, n_sets = 0;
	int32_t domain = EC_DOMAIN_VDEV;
	uint32_t algo = 0, fmt = 0;
	int n_data = 0, n_parity = 0;
	int should_retry = 0;
	int n_retry_orig = n_retry;
	struct chunk_info* infos = NULL;
	int n_infos = 0;
	int n_skipped_sets = 0;
	uint64_t t_prep = 0, t_info = 0, t_cache = 0, t_recover = 0, t_restore = 0;
	uint64_t now = 0;
	int final_pass = 0;

_start:
	now = get_timestamp_us(dev);
	final_pass = (flags & RECOVER_FINAL) && (n_retry == 1);
	assert(dev);
	assert(chid);
	assert(refs);
	should_retry = 0;
	memset(&rstat, 0, sizeof(rstat));
	uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
	if (!refs->nbufs) {
		log_debug(lg, "Dev(%s) minifest %s doesn't require recovery",
			dev->name, chidstr);
		if(pstat)
			*pstat = rstat;
		return 0;
	}

	ccow_t cl = reptrans_get_tenant_context(dev->rt, 0);
	if (!cl) {
		if(pstat)
			*pstat = rstat;
		log_error(lg, "Error getting TC");
		return -ENODEV;
	}

	log_info(lg, "Dev(%s) starting %d attempt to recovery of %s %s\n",
		dev->name, n_retry_orig - n_retry, type_tag_name[ttag], chidstr);
	/* Collect an info about parity protected manifest */
	err = ec_pm_collect_info(dev, chid, nhid, ttag, refs, &psets, &n_sets,
		&domain, &algo, &fmt, &infos, &n_infos, 0);
	if (err) {
		if (err == -EAGAIN)
			should_retry = 1;
		goto _cleanup;
	}
	t_info += get_timestamp_us(dev) - now;
	now =  get_timestamp_us(dev);
	assert(n_sets > 0);
	assert(psets);
	assert(algo != EC_CID_NONE);
	assert(algo < EC_CID_TOTAL);
	FROM_CODECFMT(fmt, n_data, n_parity);
	BG_MODE_DELAY(50000);
	/* Creating chunk cache
	 * Might have some chunks from previous attempt
	 */
	if (!cc) {
		cc = ec_ccache_create(refs->nbufs * 3);
		if (!cc) {
			log_error(lg, "Error creating ccache");
			err = -ENOMEM;
			goto _cleanup;
		}
	}
#if	EC_DEBUG
	ec_dump_parity_sets(NULL, chid, psets, n_sets, SERVER_FLEXHASH);
#endif
	for (int i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		rstat.data_mising += set->n_missing_data;
		rstat.parity_missing += set->n_missing_parity;
	}

	if ((flags & RECOVER_FAST) && !rstat.data_mising) {
		log_debug(lg, "Dev(%s) manifest %s doesn't require fast recovery",
			dev->name, chidstr);
		err = 0;
		goto _cleanup;
	}
	/* Load all the data/parity to ccache */
	err = ec_cache_data_chunks(cl, dev, infos, n_infos, cc);
	if (err) {
		log_error(lg, "Dev(%s) error getting manifest %s data,"
			"attempt %d", dev->name, chidstr, n_retry);
		should_retry = 1;
		goto _cleanup;
	}

	t_cache += get_timestamp_us(dev) - now;
	now =  get_timestamp_us(dev);
	for (int i = 0; i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		assert(set);
		int n_r_data = 0, n_r_parity = 0;
		if (!ec_is_pset_recoverable(set)) {
			/* we cannot recover this manifest,
			 * Probably FH is rebuilt, try again
			 */
			log_error(lg, "Dev(%s) parity set %d of manifest %s "
				"cannot be recovered (%d+%d>%d), skipping",
				dev->path, i, chidstr, set->n_missing_data,
				set->n_missing_parity, n_parity);
			n_skipped_sets++;
			continue;
		}
		if (!set->n_missing_data && !set->n_missing_parity)
			continue;
		/*
		 * If we are going to un-encode object, then there is
		 * no point in recovering parity chunks
		 */
		if (!set->n_missing_data && (flags & (RECOVER_UNENCODE | RECOVER_REPLICATE)))
			continue;
		/* Trying to recover */
		err = ec_recover_parity_set(set, cc, algo, fmt, &n_r_data,
			&n_r_parity);
		if (err) {
			log_error(lg, "Recovery error %d, exiting...", err);
			goto _cleanup;
		}
	}

	t_recover += get_timestamp_us(dev) - now;
	now =  get_timestamp_us(dev);
	if (n_skipped_sets == n_sets) {
		/* Skip whole recovery */
		err = -ENOEXEC;
		should_retry = 1;
		goto _cleanup;
	}
	log_debug(lg, "Dev(%s) manifest %s has %u missing data chunks and %d"
		" missing parity", dev->path, chidstr, rstat.data_mising,
		rstat.parity_missing);

	BG_MODE_DELAY(50000);
	/* Store recovered data using different strategies */
	if (flags & RECOVER_UNENCODE) {
		/* Restore by un-encoding. Transforming parity
		 * to replicas protected object */
		err = ec_restore_unencode(cl, dev, psets, n_sets, chid,
			ttag, nhid, n_parity+1, cc);
		if (err) {
			log_error(lg, "Error unencoding the object: %d\n", err);
			should_retry = 1;
			goto _cleanup;
		}
	} else 	if (flags & RECOVER_REPLICATE) {
		/* Restore number of replicase of data chunks */
		err = ec_restore_replicate(cl, dev, psets, n_sets, chid,
			ttag, nhid, n_parity+1, cc);
		if (err) {
			log_error(lg, "Data chunk replication error: %d\n", err);
			should_retry = 1;
			goto _cleanup;
		}
	} else if (flags & (RECOVER_FAST | RECOVER_HEAL)){
		/* First try to restore chunks according to failure domain */
		err = ec_restore_to_fd(cl, dev, psets, n_sets,
			chid, ttag, nhid, domain, cc, 0);
		if (err)
		/* If failed, restore data to any 2 VDEVs with corresponding NG */
			err = ec_restore_to_remote_vdev(cl, dev, psets, n_sets,
				chid, ttag, nhid, cc, 0);
		if (err) {
			should_retry = 1;
			goto _report;
		}
	}
	t_restore += get_timestamp_us(dev) - now;

	if (!err && (flags & RECOVER_HEAL)) {
		/* Don't heal recently encoded manifests.
		 * Give them a room to get consistent.
		 */
		uint64_t ts = 0;
		err = reptrans_get_blob_ts(dev, TT_PARITY_MANIFEST,
			HASH_TYPE_DEFAULT, chid, &ts);
		if (err)
			goto _cleanup;
		if (ts + 3600LL*1000000LL > reptrans_get_timestamp(dev))
			goto _report;
		/* Establish total number of FD targets */
		int re_encode = 0;
		int tgt_total = reptrans_get_fd_targets_number(domain);
		if (tgt_total >= n_data + n_parity) {
			struct chunk_info* heal_infos = NULL;
			struct ec_pset* heal_psets = NULL;
			int n_heal_sets = 0, n_heal_infos = 0;

			err = ec_pm_collect_info(dev, chid, nhid, ttag, refs,
				&heal_psets, &n_heal_sets, &domain, &algo,
				&fmt, &heal_infos, &n_heal_infos, 1);
			if (err)
				goto _report;
			BG_MODE_DELAY(50000);
			for (int i = 0; i < n_heal_sets; i++) {
				struct ec_pset* set = heal_psets + i;
				if (!ec_is_pset_recoverable(set))
					continue;
				err = ec_pset_rearrange(dev, cl, set, domain, chid,
					ttag, nhid, cc);
				if (err)
					log_error(lg, "Dev(%s) HEAL: couldn't "
						"re-arrange manifest %s",
						dev->name, chidstr);
				BG_MODE_DELAY(10000);
			}
			/*
			 * Finally we want to remove chunks if they have our
			 * ref_chid in VBR, but haven't marked as EC-participant
			 */
			BG_MODE_DELAY(10000);
			err =  ec_remove_redundant(cl, dev, chid, ttag,
				heal_psets, n_heal_sets, job);
			if (err) {
				log_error(lg, "Dev(%s) HEAL: error while "
					"removing redundant chunks: %d\n",
					dev->name, err);
				err = 0;
			}
			ec_clean_parity_sets(heal_psets, n_heal_sets);
			ec_clean_chunk_infos(heal_infos, n_heal_infos);
		}
	}

_report:
	/* Log the recovery info */
	for (int i = 0; psets && i < n_sets; i++) {
		struct ec_pset* set = psets + i;
		for (int j = 0; j < set->n_entries; j++) {
			struct ec_pset_entry* e = set->entries + j;
			char refchidstr[UINT512_BYTES * 2 + 1];
			uint512_dump(&e->info->chid, refchidstr,
				UINT512_BYTES * 2 + 1);
			if (final_pass && e->status == ECS_MISSING) {
				log_error(lg, "Lost chunk DEV: %s, "
					"CHID: %s, REF_CHID: %s, REF_TYPE: %s",
					dev->name, refchidstr, chidstr,
					type_tag_name[ttag]);

				log_add_flush_f(dev->rt->scrub_lg, LOG_LEVEL_ERROR,
					"Lost chunk DEV: %s, CHID: %s,"
					"REF_CHID: %s, REF_TYPE: %s",dev->name,
					refchidstr, chidstr,type_tag_name[ttag]);
			} else if (e->status == ECS_RESTORED) {
				log_notice(lg, "Recovered chunk DEV: %s, "
					"CHID: %s, REF_CHID: %s, REF_TYPE: %s",
					dev->name, refchidstr, chidstr,
					type_tag_name[ttag]);

				log_add_flush_f(dev->rt->scrub_lg, LOG_LEVEL_NOTICE,
					"Recovered chunk DEV: %s, CHID: %s,"
					"REF_CHID: %s, REF_TYPE: %s",dev->name,
					refchidstr, chidstr,type_tag_name[ttag]);
				rstat.data_restored++;
			}
		}
	}
_cleanup:
	if(pstat)
		*pstat = rstat;
	reptrans_put_tenant_context(dev->rt, cl);
	if (psets)
		ec_clean_parity_sets(psets, n_sets);
	if (infos)
		ec_clean_chunk_infos(infos, n_infos);
	infos = NULL;
	psets = NULL;
	if (cc) {
		ccache_free(cc);
		cc = NULL;
	}
	if ((should_retry || n_skipped_sets) && --n_retry) {
		/* Retry the recovery one more time */
		ccowd_wait_for_fhrebuild_term(&dev->terminating);
		if (!dev->terminating) {
			sleep(3);
			goto _start;
		}
	}
	log_debug(lg, "Manifest %s recovery/unencode time: collect_info: "
		"%.3f, cache_get: %.3f, recover: %.3f, restore: %.3f, retry: %d",
		chidstr, t_info/1000000.0, t_cache/1000000.0, t_recover/1000000.0,
		t_restore/1000000.0, n_retry_orig - n_retry);
	return err;
}

int
ec_recover_manifest_heal(struct repdev* dev, const uint512_t* chid,
	const uint512_t* nhid, type_tag_t ttag, rtbuf_t* refs,
	struct ec_recovery_stat* rstat, struct bg_job_entry* job) {

	manifest_lock_status_t st = MANIFEST_PROCESSING;
	struct manifest_lock_entry* re = NULL;
	do {
		re = reptrans_manifest_lock_or_wait(dev, chid, &st);
	} while (!re);

	int err = ec_recover_manifest_from_refs(dev, chid, nhid, ttag, refs,
		RECOVER_HEAL | RECOVER_FINAL, rstat, 5, job);
	reptrans_manifest_unlock(dev, re, SCRUBBER_DONE);
	return err;
}


/* Check if the manifest can be recovered on current VDEV.
 *
 * @param nhid (out) VM's NHID
 * @refs_out CM/VM (out) refentries
 *
 */
int
ec_recover_manifest_check(struct repdev* dev, const uint512_t* chid,
	type_tag_t tt, uint512_t* nhid, rtbuf_t **refs_out) {
	rtbuf_t* mrb = NULL;
	char chidstr[UINT512_BYTES*2+1];
	struct vmmetadata md;
	int status = 0;
	struct chunk_info* manifest_info = je_calloc(1, sizeof(*manifest_info));
	rtbuf_t* refs= NULL;

	manifest_info->chid = *chid;
	manifest_info->hash_type = HASH_TYPE_DEFAULT;
	manifest_info->ttype = TT_PARITY_MANIFEST;
	manifest_info->n_vdevs = 0;
	uint512_dump(chid, chidstr, UINT512_BYTES*2+1);

	/* Load manifest */
	int err = reptrans_get_blob(dev, tt, HASH_TYPE_DEFAULT, chid, &mrb);
	if (err || !mrb) {
		status = -ENOENT;
		goto _exit;
	}

	if (tt == TT_VERSION_MANIFEST) {
		/* Unpack metadata */
		err = replicast_get_metadata(mrb, &md);
		if (err) {
			status = -EINVAL;
			goto _exit;
		}
		*nhid=md.nhid;
	}
	/* Starting recovery only on device with minimal VDEV */
	err = ec_locate_chunk(dev, manifest_info,
		tt == TT_VERSION_MANIFEST ? &md.nhid : NULL, 0);
	if (err) {
		log_warn(lg, "Dev(%s) manifest locate error CHID %s "
			"type %s: %d", dev->path, chidstr,
			type_tag_name[tt], err);
		status = -EIO;
		goto _exit;
	}
	if (!manifest_info->n_vdevs) {
		/* Parity manifest is absent, exiting */
		log_debug(lg, "Dev(%s) manifest %s "
			"type %s lack of parity manifest",
			dev->path, chidstr, type_tag_name[tt]);
		status = -EEXIST;
		goto _exit;
	}
	int me = 0;
	for (uint32_t i = 0; i < manifest_info->n_vdevs; i++) {
		int cmp = uint128_cmp(manifest_info->vdevs + i, &dev->vdevid);
		if (!cmp)
			me = 1;
		if (cmp < 0) {
			log_debug(lg, "Dev(%s) manifest %s "
				"type %s recovery_ASYNC skipped, ndevs %u",
				dev->path, chidstr, type_tag_name[tt],
				manifest_info->n_vdevs);
			status = -EACCES;
			goto _exit;
		}
	}
	if (!me) {
		/*
		 * Situation when current VDEV has the smallest VDEV ID,
		 * but dosen't have a parity manifest
		 */
		log_debug(lg, "Dev(%s) manifest %s "
			"type %s doesn't have a parity manifest on current VDEV",
			dev->path, chidstr, type_tag_name[tt]);
		status = -EEXIST;
		goto _exit;
	}
	/* Unpack manifest */
	err = tt == TT_CHUNK_MANIFEST ?
		replicast_unpack_cm_refs(mrb, &refs, 0) :
		replicast_get_refs(mrb, &refs, 0);
	if (err || !refs)
		status = err;

_exit:
	if (status < 0 && refs)
		rtbuf_destroy(refs);
	else if(refs_out && refs) {
		*refs_out = refs;
	}
	if (mrb)
		rtbuf_destroy(mrb);
	if (manifest_info)
		je_free(manifest_info);
	return status;
}

int
ec_recover_manifest_exec(struct repdev* dev, const uint512_t* chid,
	type_tag_t tt, uint512_t* nhid, rtbuf_t *refs, uint8_t flags) {
	int err = 0;
	int status = MANIFEST_PROCESSING;
	manifest_lock_status_t st = MANIFEST_PROCESSING;
	struct manifest_lock_entry* re = NULL;
	do {
		re = reptrans_manifest_lock_or_wait(dev, chid, &st);
		if (!re) {
			/* We are a waiter. Check status.
			 * Try to lock and start recovery/unencoding
			 */
			if (st == ENCODING_DONE ||
				st == SCRUBBER_DONE ||
				st == SPACE_RECLAIM_DONE ||
				st == ROW_EVAC_DONE ||
				st == REPLICATION_DONE)
				continue;
			if ((flags & (RECOVER_UNENCODE | RECOVER_REPLICATE)) &&
				(st == MANIFEST_RECOVERY_SUCCESS))
				continue;
			status = st;
			goto _exit;
		}
	} while (!re);
	/* Lock master, starting the recovery */
	struct ec_recovery_stat rstat = { 0 };
	err = ec_recover_manifest_from_refs(dev, chid, nhid, tt,
		refs, flags, &rstat, 3, NULL);

	if (err && err != -ENFILE) {
		st = MANIFEST_RECOVERY_FAILED;
	} else {
		if (rstat.data_mising > rstat.data_restored) {
			if (rstat.data_restored)
				st = MANIFEST_RECOVERY_PART;
			else
				st = MANIFEST_RECOVERY_FAILED;
		} else
			st = flags & (RECOVER_UNENCODE | RECOVER_REPLICATE)?
				MANIFEST_RECOVERY_UNENCODE_SUCCESS :
				MANIFEST_RECOVERY_SUCCESS;
	}
	status = st;
	/* Release lock and notify waiters */
	reptrans_manifest_unlock(dev, re, st);

_exit:
	return status;
}

int
ec_recover_manifest(struct repdev* dev, const uint512_t* chid,
	type_tag_t tt, uint8_t flags) {
	int status = 0;
	uint512_t nhid = uint512_null;
	rtbuf_t* refs = NULL;

	status = ec_recover_manifest_check(dev, chid, tt, &nhid, &refs);
	if (!status)
		status = ec_recover_manifest_exec(dev, chid, tt, &nhid, refs,
			flags);
	return status;
}
