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
#include <sys/types.h>
#include <uv.h>
#include <errno.h>
#include "replicast.h"
#include "flexhash.h"
#include "ccowd-impl.h"
#include "erasure-coding.h"
#include "reptrans.h"
#include "reptrans-data.h"
#include "ccowutil.h"

#define RT_CMP_EMU 0

#if RT_CMP_EMU
static inline int
repdev_cmp_emu() {
	if (0 == rand() % 128)
		return -5;
	else
		return 0;
}
#else
static inline int
repdev_cmp_emu() {
	return 0;
}
#endif

int
is_dupsort_tt(type_tag_t ttag)
{
	switch (ttag) {
		case TT_NAMEINDEX:
		case TT_VERIFIED_BACKREF:
		case TT_BATCH_QUEUE:
			return 1;
		default:
			return 0;
	}
}

int
is_data_type_tag(type_tag_t ttag)
{
	return	ttag == TT_CHUNK_PAYLOAD ||
		ttag == TT_VERSION_MANIFEST ||
		ttag == TT_CHUNK_MANIFEST;
}

int
is_hashcount_data_type_tag(type_tag_t ttag)
{
	return	ttag == TT_NAMEINDEX ||
		ttag == TT_CHUNK_PAYLOAD ||
		ttag == TT_CHUNK_MANIFEST;
}

int
is_rowusage_data_type_tag(type_tag_t ttag)
{
	return	ttag == TT_PARITY_MANIFEST ||
		ttag == TT_CHUNK_PAYLOAD ||
		ttag == TT_CHUNK_MANIFEST;
}

int
is_mdoffload_tt(struct repdev *dev, type_tag_t ttag)
{
	switch (ttag) {
		/* always OK */
		case TT_NAMEINDEX:
		case TT_TRANSACTION_LOG:
			return 1;

		case TT_BATCH_QUEUE:
		case TT_VERIFICATION_QUEUE:
			if (dev->metadata_mask & DEV_METADATA_BGQ_MIN)
				return 1;
			return 0;

		case TT_VERIFIED_BACKREF:
			if (dev->metadata_mask & DEV_METADATA_VBR)
				return 1;
			return 0;

		case TT_BATCH_INCOMING_QUEUE:
			if (dev->metadata_mask & DEV_METADATA_BGQ_VER)
				return 1;
			return 0;

		case TT_REPLICATION_QUEUE:
			if (dev->metadata_mask & DEV_METADATA_BGQ_REP)
				return 1;
			return 0;

		case TT_ENCODING_QUEUE:
			if (dev->metadata_mask & DEV_METADATA_BGQ_ENC)
				return 1;
			return 0;

		case TT_VERSION_MANIFEST:
			if (dev->metadata_mask & DEV_METADATA_VM)
				return 1;
			return 0;

		case TT_CHUNK_MANIFEST:
			if (dev->metadata_mask & DEV_METADATA_CM)
				return 1;
			return 0;

		case TT_PARITY_MANIFEST:
			if (dev->metadata_mask & DEV_METADATA_PM)
				return 1;
			return 0;

		default:
			return 0;
	}
}

int
is_mdcache_tt(struct repdev* dev, type_tag_t ttag)
{
	int rc = 0;
	switch (ttag) {

		case TT_VERSION_MANIFEST:
			if (!(dev->metadata_mask & DEV_METADATA_VM))
				rc = 1;
			break;

		case TT_CHUNK_MANIFEST:
			if (!(dev->metadata_mask & DEV_METADATA_CM))
				rc = 1;
			break;
		default:
			break;
	}
	return rc;
}

int
reptrans_pack_vbr(msgpack_p *p, struct backref *vbr)
{
	int err;

	err = msgpack_pack_array(p, 8);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, vbr->uvid_timestamp);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, vbr->generation);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &vbr->name_hash_id);
	if (err)
		return err;
	err = replicast_pack_uint512(p, &vbr->ref_chid);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, vbr->ref_type);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, vbr->ref_hash);
	if (err)
		return err;
	err = msgpack_pack_uint8(p, vbr->rep_count);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, vbr->attr);
	return err;
}

int
reptrans_unpack_vbr(msgpack_u *u, struct backref *vbr)
{
	int err;

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != 8)
		return -EBADF;
	memset(vbr, 0, sizeof(struct backref));
	err = msgpack_unpack_uint64(u, &vbr->uvid_timestamp);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &vbr->generation);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &vbr->name_hash_id);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &vbr->ref_chid);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbr->ref_type);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbr->ref_hash);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbr->rep_count);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, &vbr->attr);
	return err;
}

int
trlog_cmp_keys(const uint512_t* k1, const uint512_t* k2) {
	/*
	 * key.u.u.u = VMCHID;
	 * key.u.u.l = timestamp;
	 */
	/* compare timestamps */
	if (k1->u.u.l < k2->u.u.l)
		return -1;
	if (k1->u.u.l > k2->u.u.l)
		return 1;

	/* compare parts of VMCHIDs */
	if (k1->u.u.u < k2->u.u.u)
		return -1;
	if (k1->u.u.u > k2->u.u.u)
		return 1;

	return 0;
}

/** Compare two trlog items */
int trlog_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err)
{
	int err;
	uint32_t u_ttag;
	uint8_t u_hash_type;
	msgpack_u ua, ub;
	uint512_t a_key, b_key;

	int rc = repdev_cmp_emu();
	if (rc) {
		fprintf(stderr, "trlog emulated error\n");
		*cmp_err = -1;
		return 0;
	}

	msgpack_unpack_init_b(&ua, a_data, a_size, 0);
	msgpack_unpack_init_b(&ub, b_data, b_size, 0);

	err = msgpack_unpack_uint32(&ua, &u_ttag);
	if(err || u_ttag != TT_TRANSACTION_LOG) {
		fprintf(stderr, "trlog ttag_a unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}

	err = msgpack_unpack_uint8(&ua, &u_hash_type);
	if(err || u_hash_type != HASH_TYPE_DEFAULT) {
		fprintf(stderr, "trlog u_hash_type unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}

	/* a chid */
	err = replicast_unpack_uint512(&ua, &a_key);
	if(err) {
		fprintf(stderr, "trlog key_a unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}

	err = msgpack_unpack_uint32(&ub, &u_ttag);
	if(err || u_ttag != TT_TRANSACTION_LOG) {
		fprintf(stderr, "trlog ttag_b unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}

	err = msgpack_unpack_uint8(&ub, &u_hash_type);
	if(err || u_hash_type != HASH_TYPE_DEFAULT) {
		fprintf(stderr, "trlog ht_b unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}

	/* b chid */
	err = replicast_unpack_uint512(&ub, &b_key);
	if(err) {
		fprintf(stderr, "trlog key_b unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}
	*cmp_err = 0;
	return trlog_cmp_keys(&a_key, &b_key);
}

/** Compare two backref-like items */
int vbr_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err)
{
	int err, result;

	msgpack_u ua, ub;
	msgpack_unpack_init_b(&ua, a_data, a_size, 0);
	msgpack_unpack_init_b(&ub, b_data, b_size, 0);
	struct backref bra, brb;
	int rc = repdev_cmp_emu();
	if (rc) {
		fprintf(stderr, "vbr_cmp emulated error\n");
		*cmp_err = -1;
		return 0;
	}

	err = reptrans_unpack_vbr(&ua, &bra);
	if(err) {
		fprintf(stderr, "vbr_cmp vbr_a unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}

	err = reptrans_unpack_vbr(&ub, &brb);
	if(err) {
		fprintf(stderr, "vbr_cmp vbr_b unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}

	/* compare ref_types */
	if (bra.ref_type < brb.ref_type)
		return -1;
	if (bra.ref_type > brb.ref_type)
		return 1;

	if (bra.ref_type == TT_NAMEINDEX) {
		/* Here we compare nhid, uvid_timestamp and generation */

		/* compare name_hash_ids */
		result = uint512_cmp(&bra.name_hash_id, &brb.name_hash_id);
		if (result)
			return result;
		/* compare UVIDs */
		if (bra.uvid_timestamp < brb.uvid_timestamp)
			return -1;
		if (bra.uvid_timestamp > brb.uvid_timestamp)
			return 1;
		/* compare generations */
		if (bra.generation < brb.generation)
			return -1;
		if (bra.generation > brb.generation)
			return 1;
	} else {
		/* Here we compare ref_chid, ref_hash and offset */

		/* compare ref_chids */
		result = uint512_cmp(&bra.ref_chid, &brb.ref_chid);
		if (result)
			return result;
		/* compare ref_hashs */
		if (bra.ref_hash < brb.ref_hash)
			return -1;
		if (bra.ref_hash > brb.ref_hash)
			return 1;
	}
	/* compare rep_count */
	if (bra.rep_count < brb.rep_count)
		return -1;
	if (bra.rep_count > brb.rep_count)
		return 1;

	/* compare attr */
	if (bra.attr < brb.attr)
		return -1;
	if (bra.attr > brb.attr)
		return 1;

	return 0;
}

/** Check integrity of backref-like items */
int vbr_chk(const void *a_data, const size_t a_size)
{
	int err, result;

	msgpack_u ua;
	msgpack_unpack_init_b(&ua, a_data, a_size, 0);
	struct backref bra;

	err = reptrans_unpack_vbr(&ua, &bra);
	return err;
}

/** Pack batch entry */
int
pack_batch_entry(msgpack_p *p, struct verification_request *vbreq)
{
	int err;

	err = msgpack_pack_array(p, 15);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &vbreq->nhid);
	if (err)
		return err;

	err = replicast_pack_uint128(p, &vbreq->target_vdevid);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, get_timestamp_us());
	if (err)
		return err;

	err = msgpack_pack_uint64(p, vbreq->uvid_timestamp);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, vbreq->generation);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &vbreq->chid);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &vbreq->vbr.ref_chid);
	if (err)
		return err;

	uint8_t vtype = (uint8_t)vbreq->vtype;
	err = msgpack_pack_uint8(p, vtype);
	if (err)
		return err;

	uint8_t ttag = (uint8_t)vbreq->ttag;
	err = msgpack_pack_uint8(p, ttag);
	if (err)
		return err;

	uint8_t htype = (uint8_t)vbreq->htype;
	err = msgpack_pack_uint8(p, htype);
	if (err)
		return err;

	err = msgpack_pack_uint8(p, vbreq->algorithm);
	if (err)
		return err;

	err = msgpack_pack_uint8(p, vbreq->width);
	if (err)
		return err;

	err = msgpack_pack_uint8(p, vbreq->n_parity);
	if (err)
		return err;

	err = msgpack_pack_uint8(p, vbreq->domain);
	if (err)
		return err;

	err = reptrans_pack_vbr(p, &vbreq->vbr);

	return err;
}

int
unpack_batch_entry(msgpack_u *u, struct verification_request *vbreq, uint64_t* ts)
{
	int err = 0;
	uint32_t n;

	assert(u);
	assert(vbreq);

	err = msgpack_unpack_array(u, &n);
	if (err || n != 15)
		return -EBADF;
	err = replicast_unpack_uint512(u, &vbreq->nhid);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, &vbreq->target_vdevid);
	if (err)
		return err;

	err = msgpack_unpack_uint64(u, ts);
	if (err)
		return err;
	uint64_t uvid;
	err = msgpack_unpack_uint64(u, &vbreq->uvid_timestamp);
	if (err)
		return err;
	uint64_t genid;
	err = msgpack_unpack_uint64(u, &vbreq->generation);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &vbreq->chid);
	if (err)
		return err;
	err = replicast_unpack_uint512(u, &vbreq->vbr.ref_chid);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbreq->vtype);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbreq->ttag);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbreq->htype);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbreq->algorithm);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbreq->width);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbreq->n_parity);
	if (err)
		return err;
	err = msgpack_unpack_uint8(u, &vbreq->domain);
	if (err)
		return err;
	err = reptrans_unpack_vbr(u, &vbreq->vbr);

	return err;
}

/** Compare two batch items */
int batch_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err)
{
	int err, res;
	struct verification_request vbreqa, vbreqb;

	msgpack_u ua, ub;
	msgpack_unpack_init_b(&ua, a_data, a_size, 0);
	msgpack_unpack_init_b(&ub, b_data, b_size, 0);
	uint64_t ts_a = 0, ts_b = 0;

	int rc = repdev_cmp_emu();
	if (rc) {
		fprintf(stderr, "batch_cmp emulated error\n");
		*cmp_err = -1;
		return 0;
	}

	err = unpack_batch_entry(&ua, &vbreqa, &ts_a);
	if(err) {
		fprintf(stderr, "batch_cmp vbreq_a unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}
	err = unpack_batch_entry(&ub, &vbreqb, &ts_b);
	if(err) {
		fprintf(stderr, "batch_cmp vbreq_b unpack error %d\n", err);
		*cmp_err = -1;
		return 0;
	}

	if (ts_a < ts_b)
		return -1;
	if (ts_a > ts_b)
		return 1;

	res = uint512_cmp(&vbreqa.nhid, &vbreqb.nhid);
	if (res)
		return res;

	res = uint128_cmp(&vbreqa.target_vdevid, &vbreqb.target_vdevid);
	if (res)
		return res;

	if (vbreqa.generation < vbreqb.generation)
		return -1;
	if (vbreqa.generation > vbreqb.generation)
		return 1;

	res = uint512_cmp(&vbreqa.chid, &vbreqb.chid);
	if (res)
		return res;

	res = uint512_cmp(&vbreqa.vbr.ref_chid, &vbreqb.vbr.ref_chid);
	if (res)
		return res;

	if (vbreqa.vbr.rep_count < vbreqb.vbr.rep_count)
		return -1;
	if (vbreqa.vbr.rep_count > vbreqb.vbr.rep_count)
		return 1;

	return 0;
}

/** Check batch item integrity */
int batch_chk(const void *a_data, const size_t a_size, uint64_t* ts)
{
	int err;

	if (a_size > 2 * sizeof(struct verification_request))
		return -1;
	msgpack_u ua;
	msgpack_unpack_init_b(&ua, a_data, a_size, 0);

	uint32_t n;
	err = msgpack_unpack_array(&ua, &n);
	if (err)
		return err;
	if (n < 6)
		return -1;

	/* 1. NHID of object we protecting */
	uint512_t nhid_a;
	err = replicast_unpack_uint512(&ua, &nhid_a);
	if (err)
		return err;

	/* 1.1 Target vdev */
	uint128_t vdev_a;
	err = replicast_unpack_uint128(&ua, &vdev_a);
	if (err)
		return err;

	/* 1.5 timestamp of the operation */
	err = msgpack_unpack_uint64(&ua, ts);
	if (err)
		return err;

	/* 2. UVID */
	uint64_t uvid_a;
	err = msgpack_unpack_uint64(&ua, &uvid_a);
	if (err)
		return err;

	/* 3. Object generations */
	uint64_t gen_a;
	err = msgpack_unpack_uint64(&ua, &gen_a);
	if (err)
		return err;

	/* 4. CHID of chunk we protecting */
	uint512_t chid_a;
	err = replicast_unpack_uint512(&ua, &chid_a);
	if (err)
		return err;

	/* 5. CHID of chunk parent it referencing to */
	uint512_t ref_chid_a;
	err = replicast_unpack_uint512(&ua, &ref_chid_a);

	return err;
}

int
verqueue_cmp_keys(const uint512_t* k1, const uint512_t* k2) {
	/*
	 * key.u.u.u = NHID;
	 * key.u.u.l = generation;
	 * key.u.l.u = verification type;
	 * key.u.l.l = time stamp (global);
	 */
	/* Compare globally synchronized timestamps */
	if (k1->u.l.l > k2->u.l.l)
		return 1;
	if (k1->u.l.l < k2->u.l.l)
		return -1;

	/* Compare NHIDs */
	if (k1->u.u.u > k2->u.u.u)
		return 1;
	if (k1->u.u.u < k2->u.u.u)
		return -1;

	/* Compare generation */
	if (k1->u.u.l > k2->u.u.l)
		return 1;
	if (k1->u.u.l < k2->u.u.l)
		return -1;

	/* Compare verification type */
	if (k1->u.l.u > k2->u.l.u)
		return 1;
	if (k1->u.l.u < k2->u.l.u)
		return -1;
	return 0;
}

/** compare two TT_VERIFICATION_QUEUE keys where UVID and GenID embeeded
 *  into CHID */
int verqueue_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err)
{
	int err;
	uint32_t u_ttag;
	uint8_t u_hash_type;
	msgpack_u ua, ub;
	uint512_t a_key, b_key;

	int rc = repdev_cmp_emu();
	if (rc) {
		fprintf(stderr, "verqueue_cmp emulated error\n");
		*cmp_err = -1;
		return 0;
	}

	msgpack_unpack_init_b(&ua, a_data, a_size, 0);
	msgpack_unpack_init_b(&ub, b_data, b_size, 0);

	err = msgpack_unpack_uint32(&ua, &u_ttag);
	if (err || u_ttag != TT_VERIFICATION_QUEUE) {
		fprintf(stderr,"verqueue_cmp ttag_a unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	err = msgpack_unpack_uint8(&ua, &u_hash_type);
	if (err || u_hash_type != HASH_TYPE_DEFAULT) {
		fprintf(stderr,"verqueue_cmp ht_a unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	/* a chid */
	err = replicast_unpack_uint512(&ua, &a_key);
	if (err) {
		fprintf(stderr,"verqueue_cmp key_a unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	err = msgpack_unpack_uint32(&ub, &u_ttag);
	if (err || u_ttag != TT_VERIFICATION_QUEUE) {
		fprintf(stderr,"verqueue_cmp ttag_b unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	err = msgpack_unpack_uint8(&ub, &u_hash_type);
	if (err || u_hash_type != HASH_TYPE_DEFAULT) {
		fprintf(stderr,"verqueue_cmp ht_b unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	/* b chid */
	err = replicast_unpack_uint512(&ub, &b_key);
	if (err) {
		fprintf(stderr,"verqueue_cmp key_b unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}
	return verqueue_cmp_keys(&a_key, &b_key);
}

/**
 * compare two TT_BATCH_INCOMING_QUEUE keys where coordinated and local time
 * stamps are embedded into
 */
static int
incomig_queue_cmp_key(const uint512_t* a, const uint512_t* b) {
	/*
	 * key.u.u.u = coordinated timestemp;
	 * key.u.u.l = local timestamp;
	 */
	/* Compare globally synchronized timestamps */
	if (a->u.u.u > b->u.u.u)
		return 1;
	if (a->u.u.u < b->u.u.u)
		return -1;

	/* Compare local timestamp */
	if (a->u.u.l > b->u.u.l)
		return 1;
	if (a->u.u.l < b->u.u.l)
		return -1;
	return 0;
}

int incomig_queue_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err)
{
	int err;
	uint32_t u_ttag;
	uint8_t u_hash_type;
	uint512_t a_key, b_key;
	msgpack_u ua, ub;
	msgpack_unpack_init_b(&ua, a_data, a_size, 0);
	msgpack_unpack_init_b(&ub, b_data, b_size, 0);

	int rc = repdev_cmp_emu();
	if (rc) {
		fprintf(stderr, "incomig_queue_cmp emulated error\n");
		*cmp_err = -1;
		return 0;
	}

	err = msgpack_unpack_uint32(&ua, &u_ttag);
	if (err || u_ttag != TT_BATCH_INCOMING_QUEUE) {
		fprintf(stderr,"incomig_queue_cmp ttag_a unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	err = msgpack_unpack_uint8(&ua, &u_hash_type);
	if (err || u_hash_type != HASH_TYPE_DEFAULT) {
		fprintf(stderr,"incomig_queue_cmp ht_a unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	/* a chid */
	err = replicast_unpack_uint512(&ua, &a_key);
	if (err) {
		fprintf(stderr,"incomig_queue_cmp key_a unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	err = msgpack_unpack_uint32(&ub, &u_ttag);
	if (err || u_ttag != TT_BATCH_INCOMING_QUEUE) {
		fprintf(stderr,"incomig_queue_cmp ttag_b unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	err = msgpack_unpack_uint8(&ub, &u_hash_type);
	if (err || u_hash_type != HASH_TYPE_DEFAULT) {
		fprintf(stderr,"incomig_queue_cmp ht_b unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	/* b chid */
	err = replicast_unpack_uint512(&ub, &b_key);
	if (err) {
		fprintf(stderr,"incomig_queue_cmp key_b unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}
	return incomig_queue_cmp_key(&a_key, &b_key);
}


/** Compare two TT_NAMEINDEX items, match UVIDs and GenIDs in reverse order */
int nameindex_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err)
{
	int err;

	msgpack_u ua, ub;
	msgpack_unpack_init_b(&ua, a_data, a_size, 0);
	msgpack_unpack_init_b(&ub, b_data, b_size, 0);

	int rc = repdev_cmp_emu();
	if (rc) {
		fprintf(stderr, "nameindex_cmp emulated error\n");
		*cmp_err = -1;
		return 0;
	}

	uint32_t n;
	err = msgpack_unpack_array(&ua, &n);
	if (err || n != 8) {
		fprintf(stderr,"nameindex_cmp array_a unpack error %d, n %u\n", err, n);
		*cmp_err = 1;
		return 0;
	}

	err = msgpack_unpack_array(&ub, &n);
	if (err || n != 8) {
		fprintf(stderr,"nameindex_cmp array_b unpack error %d, n %u\n", err, n);
		*cmp_err = 1;
		return 0;
	}

	uint64_t uvid_ts_a;
	err = msgpack_unpack_uint64(&ua, &uvid_ts_a);
	if (err) {
		fprintf(stderr,"nameindex_cmp uvid_ts_a unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	uint64_t uvid_ts_b;
	err = msgpack_unpack_uint64(&ub, &uvid_ts_b);
	if (err) {
		fprintf(stderr,"nameindex_cmp uvid_ts_b unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	uint64_t gen_a;
	err = msgpack_unpack_uint64(&ua, &gen_a);
	if (err) {
		fprintf(stderr,"nameindex_cmp gen_a unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	uint64_t gen_b;
	err = msgpack_unpack_uint64(&ub, &gen_b);
	if (err) {
		fprintf(stderr,"nameindex_cmp gen_b unpack error %d\n", err);
		*cmp_err = 1;
		return 0;
	}

	/* match version generations in reverse order */
	if (gen_a < gen_b)
		return 1;
	if (gen_a > gen_b)
		return -1;

	/* match uvid_timestamp */
	if (uvid_ts_a < uvid_ts_b)
		return 1;
	if (uvid_ts_a > uvid_ts_b)
		return -1;
	return 0;
}


/** Compare two items lexically */
int generic_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int *cmp_err)
{
	int diff;
	ssize_t len_diff;
	unsigned int len;

	int rc = repdev_cmp_emu();
	if (rc) {
		fprintf(stderr, "generic_cmp emulated error\n");
		*cmp_err = -1;
		return 0;
	}

	*cmp_err = 0;

	len = a_size;
	len_diff = (ssize_t) a_size - (ssize_t) b_size;
	if (len_diff > 0) {
		len = b_size;
		len_diff = 1;
	}

	diff = memcmp(a_data, b_data, len);
	return diff ? diff : (len_diff < 0 ? -1 : len_diff);
}

int
ec_pack_parity_map(msgpack_p *p, struct ec_pset* pset, int n_sets,
	int32_t domain, uint32_t algo, uint32_t fmt)
{
	int err;
	err = msgpack_pack_int32(p, domain);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, fmt);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, algo);
	if (err)
		return err;

	err = msgpack_pack_array(p, n_sets);
	if (err)
		return err;
	/* For each parity set pack CHIDs of data chunks */
	for (int i = 0;i < n_sets; i++) {
		struct ec_pset* set = pset + i;
		err = msgpack_pack_array(p, set->n_entries);
		if (err)
			return err;
		for (int j = 0; j < set->n_entries; j++) {
			err = replicast_pack_uint512(p,
				&set->entries[j].info->chid);
			if (err)
				return err;
		}
		err = msgpack_pack_array(p, set->n_parity);
		if (err)
			return err;
		/*
		 * For  each parity chunk store its CHID, VDEV's NG it resided on
		 * and size
		 */
		for (int j = 0; j < set->n_parity; j++) {
			fhrow_t row;
			err = replicast_pack_uint512(p, &set->parity[j].chid);
			if (err)
				return err;
			err = msgpack_pack_uint64(p, set->parity[j].padding);
			if (err)
				return err;
			err = msgpack_pack_uint64(p, set->parity[j].chunk.len);
		}
		/* Adding metadata (if exists)
		 * If absent, put raw zero buffer
		 **/
		if (!pset->context.len && !pset->context.base)
			err = msgpack_pack_raw(p, &err, 0);
		else
			err = msgpack_pack_raw(p, pset->context.base,
				pset->context.len);
		if (err)
			return err;
	}
	return err;
}

int
ec_unpack_parity_map(msgpack_u *u, struct ec_pset** pset_out, int* n_sets_out,
	int32_t* domain, uint32_t* algo, uint32_t* fmt) {
	int err;
	uint32_t n_sets = 0;
	struct ec_pset* pset = NULL;

	err = msgpack_unpack_int32(u, domain);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, fmt);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, algo);
	if (err)
		return err;

	err = msgpack_unpack_array(u, &n_sets);
	if (err || !n_sets)
		return err;

	pset = je_calloc(n_sets, sizeof(struct ec_pset));
	if (!pset)
		return -ENOMEM;

	for (uint32_t i = 0; i < n_sets; i++) {
		struct ec_pset* set = pset + i;
		uint32_t aux = 0;
		err = msgpack_unpack_array(u, &aux);
		if (aux > 255)
			err = -EINVAL;
		if (err)
			goto _clean;

		set->n_entries = aux;
		set->entries = je_calloc(set->n_entries,
			sizeof(struct ec_pset_entry));
		if (!set->entries) {
			err = -ENOMEM;
			goto _clean;
		}
		for (size_t j = 0; j < set->n_entries; j++) {
			err = replicast_unpack_uint512(u,
				&set->entries[j].chid);
			if (err)
				goto _clean;
		}
		err = msgpack_unpack_array(u, &aux);
		if (aux > 255)
			err = -EINVAL;
		if (err)
			goto _clean;

		set->n_parity = aux;
		set->parity = je_calloc(set->n_parity,
			sizeof(struct ec_parity_chunk));
		if (!set->parity) {
			err = -ENOMEM;
			goto _clean;
		}
		/*
		 * For  each parity chunk store its CHID, VDEV it resided on
		 * and size
		 */
		for (uint32_t j = 0; j < set->n_parity; j++) {
			err = replicast_unpack_uint512(u, &set->parity[j].chid);
			if (err)
				goto _clean;
			err = msgpack_unpack_uint64(u, &set->parity[j].padding);
			if (err)
				goto _clean;
			err = msgpack_unpack_uint64(u, &set->parity[j].chunk.len);
			if (err)
				goto _clean;
		}
		/* Unpacking metadata (if exists) */
		const uint8_t *data = NULL;
		aux = 0;
		err = msgpack_unpack_raw(u, &data, &aux);
		if (err)
			goto _clean;
		pset->context.len = aux;
		if (aux) {
			pset->context.base = je_malloc(aux);
			if (!pset->context.base) {
				err = -ENOMEM;
				goto _clean;
			}
			memcpy(pset->context.base, data, aux);
		}
	}
	*n_sets_out = n_sets;
	*pset_out = pset;
	return 0;

_clean:
	ec_free_parity_map(pset, n_sets);
	return err;
}

void
ec_free_parity_map(struct ec_pset* pset, int n_sets) {
	if (pset) {
		for (int i = 0; i < n_sets; i++) {
			struct ec_pset* set = pset + i;
			if (set->entries)
				je_free(set->entries);
			if (set->parity)
				je_free(set->parity);
			if (set->context.len)
				je_free(set->context.base);
		}
		je_free(pset);
	}
}

int
reptrans_pack_compound(struct iovec *iov, size_t count, type_tag_t* tt,
    const uint512_t *chid, msgpack_p **p, uint8_t hash_type,
    uint64_t compound_flags)
{
	*p = msgpack_pack_init();
	if (*p == NULL)
		return -ENOMEM;

	int err = msgpack_pack_uint32(*p, RT_PROT_COMPOUND_VERSION);
	if (err)
		return err;

	err = msgpack_pack_uint64(*p, compound_flags);
	if (err)
		return err;
	err = msgpack_pack_uint8(*p, hash_type);
	if (err)
		return err;

	err = replicast_pack_uint512(*p, chid);
	if (err)
		return err;

	err = msgpack_pack_uint64(*p, count);
	if (err)
		return err;

	for (size_t i = 0; i < count; i++) {
		int err = msgpack_pack_uint8(*p, tt[i]);
		if (err)
			return err;

		err = msgpack_pack_uint32(*p, iov[i].iov_len);
		if (err)
			return err;;

		err = msgpack_pack_raw(*p, iov[i].iov_base, iov[i].iov_len);
		if (err)
			return err;;
	}
	return 0;
}

int
reptrans_unpack_compound(msgpack_u *u, struct iovec **iov, uint32_t *count,
        type_tag_t** tt, uint512_t *chid, uint8_t* hash_type, uint8_t* need_version)
{
	assert(u != NULL);
	assert(iov != NULL);
	assert(count != NULL);
	assert(chid != NULL);
	assert(tt != NULL);
	assert(chid != NULL);
	assert(hash_type != NULL);

	uint32_t nn;
	int err = msgpack_unpack_array(u, &nn);
	if (err)
		return err;
	if (nn != 4)
		return -EBADF;

	uint8_t aux = 0;
	err = msgpack_unpack_uint8(u, &aux);
	if (err)
		return err;
	*hash_type = aux;
	aux = 0;
	err = msgpack_unpack_uint8(u, &aux);
	if (err)
		return err;
	*need_version = aux;

	err = replicast_unpack_uint512(u, chid);
	if (err)
		return err;

	uint32_t len, i, n;
	uint8_t *data = NULL;

	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (!n)
		return -EBADF;

	*iov = (struct iovec *)je_calloc(n, sizeof(struct iovec));
	if (*iov == NULL)
		return -ENOMEM;

	*tt = (type_tag_t*)je_calloc(n, sizeof(type_tag_t));
	if (*tt == NULL)
		return -ENOMEM;

	for (i = 0; i < n; ++i) {

		err = msgpack_unpack_uint8(u, &aux);
		if (err)
			return err;
		(*tt)[i] = aux;

		err = msgpack_unpack_array(u, &nn);
		if (err)
			return err;
		if (nn != 2)
			return -EBADF;

		err = msgpack_unpack_uint32(u, &len);
		if (err)
			return err;
		(*iov)[i].iov_len = len;
		err = msgpack_unpack_raw(u, (const uint8_t **)&data, &len);
		if (err)
			return err;
		if (len != (*iov)[i].iov_len || !data)
			return -EBADF;
		(*iov)[i].iov_base = data;
	}
	*count = n;
	return err;
}

void
rt_chid_swap_trlog(const uint512_t* chid, uint512_t* chid_out, crypto_hash_t* ht) {
	*chid_out = *chid;
	chid_out->u.u.u = chid->u.u.l;
	chid_out->u.u.l = chid->u.u.u;
	if (ht)
		*ht = HASH_TYPE_XXHASH_128;
}

void
rt_chid_unswap_trlog(const uint512_t* chid, uint512_t* chid_out) {
	*chid_out = *chid;
	chid_out->u.u.u = chid->u.u.l;
	chid_out->u.u.l = chid->u.u.u;
}


/*
	if (dev->key_format == RT_KEY_FORMAT_MSGPACK) {
		key.u.u.u = vbreq->vbr.name_hash_id.u.u.u;
		key.u.u.l = vbreq->generation;
		key.u.l.u = !!(vbreq->vtype & RT_VERIFY_DELETE);
		key.u.l.l = COORDINATED_TS();
	} else {
		key.u.u.u = COORDINATED_TS();
		key.u.u.l = vbreq->vbr.name_hash_id.u.u.u;
		key.u.l.u = vbreq->generation;
		key.u.l.l = !!(vbreq->vtype & RT_VERIFY_DELETE);
	}
*/
void
rt_chid_swap_verqueue(const uint512_t* chid, uint512_t* chid_out, crypto_hash_t* ht) {
	*chid_out = *chid;
	chid_out->u.u.u = chid->u.l.l;
	chid_out->u.u.l = chid->u.u.u;
	chid_out->u.l.u = chid->u.u.l;
	chid_out->u.l.l = chid->u.l.u;
	if (ht)
		*ht = HASH_TYPE_XXHASH_256;
}

void
rt_chid_unswap_verqueue(const uint512_t* chid, uint512_t* chid_out) {
	*chid_out = *chid;
	chid_out->u.u.u = chid->u.u.l;
	chid_out->u.u.l = chid->u.l.u;
	chid_out->u.l.u = chid->u.l.l;
	chid_out->u.l.l = chid->u.u.u;
}

struct imsort_entry {
	uint512_t key;
	crypto_hash_t ht;
	uv_buf_t data;
};

struct rt_imsort {
	struct repdev* 	dev;
	type_tag_t 	ttag;
	void*		params;
	struct mlist_node* current;
    struct mlist_node* tail;
	rtbuf_t* lists;
};

static int
imsort_compare_incoming_batch(void *d1, void *d2) {
	struct imsort_entry* e1 = d1;
	struct imsort_entry* e2 = d2;
	return incomig_queue_cmp_key(&e1->key, &e2->key);
}

static int
imsort_compare_verqueue(void *d1, void *d2) {
	struct imsort_entry* e1 = d1;
	struct imsort_entry* e2 = d2;
	return verqueue_cmp_keys(&e1->key, &e2->key);
}

static int
imsort_compare_trlog(void *d1, void *d2) {
	struct imsort_entry* e1 = d1;
	struct imsort_entry* e2 = d2;
	return trlog_cmp_keys(&e1->key, &e2->key);
}

static int
imsort_compare_generic(void *d1, void *d2) {
	struct imsort_entry* e1 = d1;
	struct imsort_entry* e2 = d2;
	return uint512_cmp(&e1->key, &e2->key);
}

static msort_compare_fn
imsort_get_comparator(type_tag_t ttag) {
	if (ttag == TT_BATCH_INCOMING_QUEUE)
		return imsort_compare_incoming_batch;
	else if (ttag == TT_VERIFICATION_QUEUE)
		return imsort_compare_verqueue;
	else if (ttag == TT_TRANSACTION_LOG)
		return imsort_compare_trlog;
	else
		return imsort_compare_generic;
}

static struct mlist_node*
imsort_create_node(crypto_hash_t hash_type, uint512_t* key, uv_buf_t* val) {
	struct mlist_node* rc = je_calloc(1, sizeof(*rc));
	if (!rc)
		return NULL;
	struct imsort_entry* e = je_calloc(1, sizeof(*e));
	if (!e) {
		je_free(rc);
		return NULL;
	}
	if (val && val->base && val->len) {
		e->data.base = je_calloc(1, val->len);
		if(!e->data.base) {
			je_free(e);
			je_free(rc);
			return NULL;
		}
		memcpy(e->data.base, val->base, val->len);
		e->data.len = val->len;
	}
	e->ht = hash_type;
	e->key = *key;
	rc->data = e;
	rc->next = NULL;
	return rc;
}

static void
imsort_free_node(struct mlist_node* node) {
	if (node->data) {
		struct imsort_entry* e = node->data;
		if (e->data.base)
			je_free(e->data.base);
		je_free(e);
	}
	je_free(node);
}

static void
imsort_dup_cb(void* arg, struct mlist_node *node) {
	int* cnt = arg;
	imsort_free_node(node);
	(*cnt)++;
}

int
reptrans_imsort_create(struct repdev* dev, type_tag_t ttag, void* params,
	struct rt_imsort** handle) {
	struct rt_imsort* rc = je_calloc(1, sizeof(struct rt_imsort));
	if (!rc)
		return -ENOMEM;
	rc->dev = dev;
	rc->ttag = ttag;
	rc->params = params;
	rc->lists = rtbuf_init_empty();
	rc->current = NULL;
	rc->tail = NULL;
	if (!rc->lists) {
		je_free(rc);
		return -ENOMEM;
	}
	*handle = rc;
	return 0;
}

int
reptrans_imsort_destroy(struct rt_imsort* handle) {
	assert(handle);
	if (handle->current) {
		struct mlist_node* m = handle->current;
		while (m) {
			struct mlist_node* tmp = m;
			m = m->next;
			imsort_free_node(tmp);
		}
		handle->current = NULL;
	    handle->tail = NULL;
	}
	if (handle->lists) {
		for (size_t i = 0; i < handle->lists->nbufs; i++) {
			struct mlist_node* m = (struct mlist_node*)rtbuf(handle->lists, i).base;
			while (m) {
				struct mlist_node* tmp = m;
				m = m->next;
				imsort_free_node(tmp);
			}
		}
		rtbuf_destroy(handle->lists);
		handle->lists = NULL;
	}
	je_free(handle);
	return 0;
}

int
reptrans_imsort_add_kv(struct rt_imsort* handle, crypto_hash_t hash_type,
	uint512_t* key, uv_buf_t* val, int new_part) {
	struct mlist_node* node = imsort_create_node(hash_type, key, val);
	if (!node)
		return -ENOMEM;
	if (new_part) {
		if (handle->current) {
			uv_buf_t ub = {
				.base = (char*)handle->current,
				.len = sizeof(struct mlist_node)};
			int err = rtbuf_add_mapped(handle->lists, &ub, 1);
			if (err)
				return -ENOMEM;
		}
		handle->current = node;
		handle->tail = node;
	} else {
		struct mlist_node* m = handle->tail;
		m->next = node;
		handle->tail = node;
	}
	return 0;
}

int
reptrans_imsort_iterate(struct rt_imsort* handle, reptrans_blob_callback callback, int key_format) {
	int err = 0;
	if (!handle->current)
		return 0;
	struct repdev* dev = handle->dev;
	if (handle->lists && handle->lists->nbufs) {
		/* Do merge-sort first */
		int dup_count = 0;
		msort_compare_fn cmp = key_format == RT_KEY_FORMAT_MSGPACK ?
			imsort_get_comparator(handle->ttag) : imsort_compare_generic;
		for (size_t i = 0; i < handle->lists->nbufs; i++) {
			struct mlist_node* m = (struct mlist_node*)rtbuf(handle->lists, i).base;
			handle->current = msort_merge_lists_nodup(handle->current, m,
				cmp, imsort_dup_cb, &dup_count);
		}
		rtbuf_clean(handle->lists);
		handle->lists = NULL;
	}
	/* Iterate entries */
	struct mlist_node* m = handle->current;
	for (; m; m = m->next) {
		struct imsort_entry* e = m->data;
		uint512_t chid = e->key;
		if (key_format == RT_KEY_FORMAT_LINEAR) {
			/* Do an inplace chid conversion for ttags sensitive to chid format */
			if (handle->ttag == TT_TRANSACTION_LOG)
				rt_chid_unswap_trlog(&e->key, &chid);
			else if (handle->ttag == TT_VERIFICATION_QUEUE)
				rt_chid_unswap_verqueue(&e->key, &chid);
		}

		err = callback(handle->dev, handle->ttag, e->ht, &chid, &e->data,
			handle->params);
		if (err)
			break;
	}
	return err;
}

int
rt_lhtbl_hahs(void* buf, size_t len, uint64_t* out) {
	uint512_t digest;
	crypto_hash_with_type(HASH_TYPE_XXHASH_64, (uint8_t *)buf, len,
		(uint8_t*)&digest);
	*out = digest.u.u.u;
	return 0;
}

static int
rt_lhtbl_u64_cmp(const void* a, const void* b) {
	uint64_t a_val = *((uint64_t*)a);
	uint64_t b_val = *((uint64_t*)b);
	if (a_val < b_val)
		return -1;
	else if (a_val > b_val)
		return 1;
	return 0;
}

struct rt_lhtbl*
rt_lhtbl_create(size_t init_size) {
	struct rt_lhtbl* hm = je_calloc(1, sizeof(*hm));
	if (!hm)
		return NULL;
	hm->init_size = init_size;
	hm->limit = init_size;
	hm->value_hash = je_malloc(hm->limit*sizeof(uint64_t));
	if (!hm->value_hash) {
		je_free(hm);
		return NULL;
	}
	hm->bloom = je_calloc(1, LHTBL_BLOOM_SIZE(hm)*sizeof(uint8_t));
	if (!hm->bloom) {
		je_free(hm->value_hash);
		je_free(hm);
		return NULL;
	}
	hm->size = 0;
	return hm;
}

void
rt_lhtbl_destroy(struct rt_lhtbl* hm) {
	je_free(hm->bloom);
	je_free(hm->value_hash);
	je_free(hm);
}

int
rt_lhtbl_insert(struct rt_lhtbl* ht, void* buf, size_t size) {
	assert(ht);
	if (ht->size >= ht->limit)
	{
		uint64_t* new_table = je_malloc(2*ht->limit*sizeof(uint64_t));
		if (!new_table)
			return -ENOSPC;
		memcpy(new_table, ht->value_hash, ht->limit*sizeof(uint64_t));
		je_free(ht->value_hash);
		ht->value_hash = new_table;
		ht->limit *= 2;
	}
	/* Calculate hash ID and append it to array */
	uint64_t hash = 0;
	int err = rt_lhtbl_hahs(buf, size, &hash);
	if (err)
		return err;
	ht->value_hash[ht->size] = hash;
	/* Push to bloom filter */
	ht->bloom[hash & LHTBL_BLOOM_MASK(ht)] = 1;
	ht->size++;
	return 0;
}

void
rt_lhtbl_sort(struct rt_lhtbl* ht) {
	/* To be called before invoking rd_lhtbl_query() */
	assert(ht);
	if (ht->size > 1)
		qsort(ht->value_hash, ht->size, sizeof(ht->value_hash[0]),
			rt_lhtbl_u64_cmp);
}

int
rt_lhtbl_query(struct rt_lhtbl* ht, void* buf, size_t size) {
	assert(ht);
	assert(buf);
	int first = 0;
	int last = ht->size - 1;
	int middle = (first+last)/2;
	uint64_t hash = 0;
	uint64_t bvalue = 0;

	if (!size || !ht->size)
		return -ENOENT;
	/* Calculate hash and check the bloom */
	int err = rt_lhtbl_hahs(buf, size, &hash);
	if (err)
		return err;

	if (!ht->bloom[hash & LHTBL_BLOOM_MASK(ht)])
		return -ENOENT;
	/*
	 * Maybe exist. Looking in the hash value array
	 * using binary search
	 */
	while (first <= last) {
		if (ht->value_hash[middle] < hash)
			first = middle + 1;
		else if (ht->value_hash[middle] == hash)
			return 0;
		else
			last = middle - 1;
		middle = (first + last)/2;
	}
	return -ENOENT;
}

int
rt_duplist_add(struct mlist_node** head, void* data, size_t size, int mapped) {
	struct mlist_node* node = je_calloc(1, sizeof(*node));
	if (!node)
		return -ENOMEM;
	uv_buf_t* buf = je_calloc(1, sizeof(uv_buf_t));
	if (!buf) {
		je_free(node);
		return -ENOMEM;
	}
	buf->len = size;
	if (!mapped)
		buf->base = je_memdup(data, size);
	else
		buf->base = data;
	node->data = buf;
	node->next = *head;
	*head = node;
	return 0;
}

static int rt_duplist_batch_cmp(void *d1, void *d2) {
	uv_buf_t* ub1 = (uv_buf_t*)d1;
	uv_buf_t* ub2 = (uv_buf_t*)d2;
	int err = 0;
	return -batch_cmp(ub1->base, ub1->len, ub2->base, ub2->len, &err);
}

static int rt_duplist_vbr_cmp(void *d1, void *d2) {
	uv_buf_t* ub1 = (uv_buf_t*)d1;
	uv_buf_t* ub2 = (uv_buf_t*)d2;
	int err = 0;
	return -vbr_cmp(ub1->base, ub1->len, ub2->base, ub2->len, &err);
}

static int rt_duplist_nameindex_cmp(void *d1, void *d2) {
	uv_buf_t* ub1 = (uv_buf_t*)d1;
	uv_buf_t* ub2 = (uv_buf_t*)d2;
	int err = 0;
	return -nameindex_cmp(ub1->base, ub1->len, ub2->base, ub2->len, &err);
}

static msort_compare_fn
rt_duplist_get_cmp(type_tag_t ttag) {
	switch(ttag) {
		case TT_NAMEINDEX:
			return rt_duplist_nameindex_cmp;
			break;
		case TT_BATCH_QUEUE:
			return rt_duplist_batch_cmp;
			break;

		case TT_VERIFIED_BACKREF:
			return rt_duplist_vbr_cmp;
			break;
		default:
			break;
	}
	return NULL;
}

struct rt_duplist_dup_cb_arg {
	int counter;
	int mapped;
};

static void
rt_duplist_dup_cb(void* arg, struct mlist_node *node) {
	struct rt_duplist_dup_cb_arg *p = arg;
	assert(p);
	p->counter++;
	if (node) {
		if (node->data) {
			if (!p->mapped) {
				uv_buf_t* ub = (uv_buf_t*)node->data;
				assert(ub->base);
				je_free(ub->base);
			}
			je_free(node->data);
		}
		je_free(node);
	}
}

int
rt_duplist2rtbuf(type_tag_t ttag, struct mlist_node* head1, size_t len1,
	struct mlist_node* head2, size_t len2, rtbuf_t* rb, int mapped) {
	struct mlist_node* res = NULL;
	size_t len = 0;

	if (!rb)
		goto _exit;

	if (head1 && !head2) {
		res = head1;
		len = len1;
	} else if (!head1 && head2) {
		res = head2;
		len = len2;
	} else if (is_dupsort_tt(ttag)) {
		len = len1 + len2;

		struct rt_duplist_dup_cb_arg arg = { .counter = 0, .mapped = mapped };
		msort_compare_fn cmp = rt_duplist_get_cmp(ttag);
		if (!cmp)
			return -EINVAL;
		res = msort_merge_lists_nodup(head1, head2, cmp, rt_duplist_dup_cb,
			&arg);
		if (!res)
			return -ENOENT;
		len -= arg.counter;
	}
	assert(res);
	int err = rtbuf_expand(rb, len);
	if (err)
		return err;
	size_t n = len - 1;
	for (struct mlist_node* node = res; node; node=node->next,n--) {
		uv_buf_t* buf = (uv_buf_t*)node->data;
		rb->bufs[n] = *buf;
		if (mapped)
			rb->attrs[n] |= RTBUF_ATTR_MMAP;
		je_free(buf);
	};
_exit:

	if (res)
		msort_free_list(res, NULL);
	else {
		if (head1)
			msort_free_list(head1, NULL);
		if (head2)
			msort_free_list(head2, NULL);
	}
	return 0;
}

