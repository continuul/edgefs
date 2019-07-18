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

#include "ccow.h"
#include "ccow-impl.h"
#include "chunk.h"

struct unnamedput_chunk_req {
	struct ccow *tc;
	struct ccow_io *io;
	struct ccow_io *up_io;
	int chid_provided;
	int nhid_provided;
};

static void
unnamedput_chunk__term(struct state *st)
{
	struct unnamedput_chunk_req *r = st->data;

	log_trace(lg, "st %p", st);

	ccow_complete_io(r->io);
}

static void
unnamedput_chunk_comphash_done(void *arg, int status)
{
	int err;
	struct state *st = arg;
	struct unnamedput_chunk_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_io *up_io = r->up_io;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = op->comp;
	struct ccow *tc = c->tc;

	log_trace(lg, "arg %p, status %d", arg, status);

	if (status) {
		ccow_fail_io(io, status);
		state_event(st, EV_ERR);
		return;
	}

	nassert(tc->loop_thrid == uv_thread_self());

	/* if CHID is not provided */
	struct putcommon_client_req *req = CCOW_IO_REQ(r->up_io);
	if (!r->chid_provided)
		req->chid = op->chids[0];

	if (!r->nhid_provided)
		op->name_hash_id = op->chids[0];

	state_event(st, EV_DONE);
}

static void
unnamedput_chunk__init(struct state *st)
{
	int err;
	struct unnamedput_chunk_req *r = st->data;
	struct ccow_io *io = r->io;

	log_trace(lg, "st %p", st);

	/*
	 * Start Async Compression/Fingerprint. Children I/O is blocked until
	 * compression & hashing is complete.
	 */
	err = ccow_comphash_compute(io->op, unnamedput_chunk_comphash_done, io);
	if (err) {
		state_next(st, EV_ERR);
		return;
	}
}

/*
 * unnamedput_chunk_done
 *
 * called on completion of a put for a chunk payload.
 */
static void
unnamedput_chunk_done(struct putcommon_client_req *r)
{
	log_trace(lg, "r %p", r);
}

/*
 * Perform an unnamed put of chunk(s) of data as admin.
 */
int ccow_admin_pseudo_put_chunks(struct iovec *iov, size_t iovcnt,
    uint64_t attributes, const char* chid,  const char *nhid_vdev,
	ccow_completion_t comp)
{
	int err;
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	struct ccow_op *put_op;
	struct ccow_io *up_io;

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Permission Denied, not admin");
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		return -EPERM;
	}
       //
       // Support only single iovec for non-compound function due to necessity
       // to recompute the RT groups
       //
       if ((!chid && iovcnt > 1) && (!(attributes & RD_ATTR_COMPOUND))) {
	       log_error(lg, "Single input iovec only for non-compound put_chunks().");
	       return -ENOTSUP;
       }
       /* do not support larger then currently configured chunks + tailroom */
       for (size_t i = 0; i < iovcnt; i++) {
	       if (iov[i].iov_len > REPLICAST_CHUNK_SIZE_MAX + 32768) {
		       log_error(lg, "Chunk size %lu too big, idx=%ld",
			   iov[i].iov_len, i);
		       return -E2BIG;
	       }
       }
       /* in targeted mode we need to calc NG by VDEV ID */
       uint512_t target_nhid = uint512_null;
       if (attributes & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED)) {
	   if (!nhid_vdev) {
		   log_error(lg, "Targeted unnamed put requires a VDEV");
		   return -EINVAL;
	   }
	   fhrow_t ng = 0;
	   err = flexhash_get_vdev_row(tc->flexhash,
				(uint128_t *)nhid_vdev, &ng);
	   if (err) {
		   char vdevstr [UINT128_BYTES*2 + 1];
		   uint128_dump((const uint128_t *)nhid_vdev, vdevstr,
			  UINT128_BYTES*2 + 1);
		   log_error(lg, "Flexhash couldn't find VDEV ID %s", vdevstr);
		   return -ENODEV;
	   }
	   target_nhid.u.u.u = ng;
	   uint8_t syn_put = 1;
	   err = ccow_attr_modify_default(c, CCOW_ATTR_SYNC_PUT,
		    (void *)&syn_put, NULL);
	   if (err) {
		   log_error(lg, "Targeted_put: couldn't modify sync put value");
		   return -EIO;
	   }

       }
	/* Pre-process the comphash calculations prior to scheduling the I/O */
	static const struct transition trans_tbl[] = {
		// FROM, EVENT, ACTION, TO, GUARD
		// -----------------------------------------------------------
		{ ST_INIT, EV_CALL, &unnamedput_chunk__init, ST_WAIT, NULL },
		{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
		{ ST_ANY, EV_ANY, NULL, ST_TERM, NULL }
	};

	/* Create an op */
	err = ccow_operation_create(c, CCOW_PUT, &put_op);
	if (err)
		return err;

	struct unnamedput_chunk_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		err = -ENOMEM;
		ccow_operation_destroy(put_op, 1);
		log_error(lg, "UNNAMED PUT CHUNK request alloc error: %d", err);
		return err;
	}
	r->tc = c->tc;
	/* Create the dummy op for comphash to execute. */
	err = ccow_create_io(c, put_op, CCOW_PUT_CONT, trans_tbl,
			sizeof (trans_tbl) / sizeof (*trans_tbl), r,
			unnamedput_chunk__term, &r->io);
	if (err) {
		ccow_operation_destroy(put_op, 1);
		if (r->io)
			ccow_destroy_io(r->io);
		je_free(r);
		return err;
	}
	/* FIXME: ccow_chain_io needs to learn how to chain w/o op->ng_io. */
	put_op->namedget_io = r->io;

	/* Create the actual up I/O op. */
	err = ccow_unnamedput_create(comp, unnamedput_chunk_done, put_op,
	    &r->up_io, NULL);
	if (err) {
		ccow_operation_destroy(put_op, 1);
		if (r->io)
			ccow_destroy_io(r->io);
		je_free(r);
		return err;
	}

	ccow_io_lock(r->io);
	ccow_chain_io(put_op, r->up_io);

	put_op->chunks = rtbuf_init_mapped((uv_buf_t *)iov, iovcnt);
	if (!put_op->chunks) {
		ccow_io_unlock(r->io);
		ccow_operation_destroy(put_op, 1);
		ccow_destroy_io(r->io);
		ccow_destroy_io(r->up_io);
		je_free(r);
		return -ENOMEM;
	}
	put_op->chids = je_calloc(iovcnt, sizeof (uint512_t));
	if (!put_op->chids) {
		ccow_io_unlock(r->io);
		ccow_operation_destroy(put_op, 1);
		ccow_destroy_io(r->io);
		ccow_destroy_io(r->up_io);
		je_free(r);
		return -ENOMEM;
	}

	struct putcommon_client_req *req = CCOW_IO_REQ(r->up_io);
	req->payload = put_op->chunks;
	req->hash_type = c->hash_type;

	if (attributes & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED)) {
		r->nhid_provided = 1;
		put_op->name_hash_id = target_nhid;
		req->target_vdev = *((uint128_t*)nhid_vdev);
	} else if (nhid_vdev) {
		r->nhid_provided = 1;
		put_op->name_hash_id = *((uint512_t*)nhid_vdev);
	}

	put_op->iov_in = iov;
	put_op->iovcnt_in = iovcnt;
	ccow_copy_inheritable_comp_to_md(c, &put_op->metadata);
	put_op->copy_opts = NULL;
	r->up_io->attributes = attributes;
	r->io->attributes = attributes;
	if (chid) {
		r->chid_provided = 1;
		put_op->chids[0] = *(uint512_t *)chid;
		/*
		 * CHID in the request has to be set in order to let
		 * row member filter do job (libreptrans/putcommon_server.c:200)
		 */
		req->chid = *(uint512_t *)chid;
	}
	err = ccow_start_io(r->io);
	ccow_io_unlock(r->io);
	return err;
}

/*
 * Packs metadata only. Chunk reference list will be added dynamically
 * via chunkmap algorithms.
 */
static msgpack_p *
ccow_pack_metadata_common(struct putcommon_client_req *r, rtbuf_t *rl_root)
{
	int err;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->op;
	struct ccow_completion *c = io->comp;
	struct replicast *robj = tc->netobj->robj[0];
	struct vmmetadata *md = &op->metadata;
	int is_btree_map = memcmp_quick(md->chunkmap_type, strlen(md->chunkmap_type),
		    RT_SYSVAL_CHUNKMAP_BTREE, strlen(RT_SYSVAL_CHUNKMAP_BTREE)) == 0;

	msgpack_p hdr;
	char hdr_data[RT_HDR_JUMPTBL_SIZE];
	uv_buf_t hdr_buf = { .base = (char *)hdr_data,
		.len = RT_HDR_JUMPTBL_SIZE };
	msgpack_pack_init_p(&hdr, hdr_buf);

	msgpack_p *p = msgpack_pack_init();
	if (!p)
		return NULL;
	MCHK(err, msgpack_pack_map(p, 5), goto _mexit);

	/* Section lookup jump table, always goes first */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_HEADER_IDX), goto _mexit);
	uint32_t jumptbl_off;
	MCHK(err, msgpack_pack_raw_reserve(p, RT_HDR_JUMPTBL_SIZE,
		    &jumptbl_off), goto _mexit);

	uint32_t flags_rsvd = 0;
	MCHK(err, msgpack_pack_uint32(&hdr, flags_rsvd), goto _mexit);

	/* (1) Pack object metadata */
	uint32_t s_len = msgpack_get_len(p);
	MCHK(err, msgpack_pack_uint32(&hdr, s_len), goto _mexit);
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_METADATA_IDX), goto _mexit);

	/*
	 * NOTE: when adding new metadata please make sure to increment
	 *       number of elements in array below.
	 */
	MCHK(err, msgpack_pack_map(p, 39), goto _mexit);

	/* (key-value 1.1) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_CLUSTER_IDX), goto _mexit);
	MCHK(err, msgpack_pack_raw(p, op->cid, op->cid_size),
	    goto _mexit);

	/* (key-value 1.2) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_TENANT_IDX), goto _mexit);
	MCHK(err, msgpack_pack_raw(p, op->tid, op->tid_size), goto _mexit);

	/* (key-value 1.3) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_BUCKET_IDX), goto _mexit);
	MCHK(err, msgpack_pack_raw(p, op->bid, op->bid_size), goto _mexit);

	/* (key-value 1.4) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_OBJECT_IDX), goto _mexit);
	MCHK(err, msgpack_pack_raw(p, op->oid, op->oid_size), goto _mexit);

	/* (key-value 1.5) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_CLUSTER_HASH_ID_IDX),
	    goto _mexit);
	MCHK(err, replicast_pack_uint512(p, &op->cluster_hash_id), goto _mexit);

	/* (key-value 1.6) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_NAME_HASH_ID_IDX),
	    goto _mexit);
	MCHK(err, replicast_pack_uint512(p, &op->name_hash_id), goto _mexit);

	/* (key-value 1.7) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_TENANT_HASH_ID_IDX),
	    goto _mexit);
	MCHK(err, replicast_pack_uint512(p, &op->tenant_hash_id), goto _mexit);

	/* (key-value 1.8) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_BUCKET_HASH_ID_IDX),
	    goto _mexit);
	MCHK(err, replicast_pack_uint512(p, &op->bucket_hash_id), goto _mexit);

	/* (key-value 1.9) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_OBJECT_HASH_ID_IDX),
	    goto _mexit);
	MCHK(err, replicast_pack_uint512(p, &op->object_hash_id), goto _mexit);

	/* (key-value 1.10) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_PARENT_HASH_ID_IDX),
	    goto _mexit);
	MCHK(err, replicast_pack_uint512(p, &op->parent_hash_id), goto _mexit);

	/* handling creation_time
	 * NOTE: need to process it before updating md->object_deleted */
	int just_created = 0;
	if ((md->object_deleted &&
	     !(op->namedget_io->attributes & RD_ATTR_LOGICAL_DELETE)) ||
	    op->txid_generation == 1 ||
	    (op->namedget_io->attributes & RD_ATTR_OBJECT_REPLACE) ||
	    op->optype == CCOW_CLONE )
		just_created = 1;

	if (op->namedget_io->attributes & RD_ATTR_LOGICAL_DELETE) {
		if (op->namedget_io->attributes & RD_ATTR_EXPUNGE_OBJECT) {
			md->object_deleted = RT_DELETED_EXPUNGED;
		} else if (op->namedget_io->attributes & RD_ATTR_EXPUNGE_OBJECT_VERSION) {
			md->object_deleted = RT_DELETED_EXPUNGED_VERSION;
		} else if (op->namedget_io->attributes & RD_ATTR_DELETE_OBJECT_VERSION) {
			md->object_deleted = RT_DELETED_VERSION;
	    } else
			md->object_deleted = RT_DELETED_LOGICALLY;
	} else
		md->object_deleted = RT_DELETED_NOT;

	/* (key-value 1.11) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_OBJECT_DELETED_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->object_deleted), goto _mexit);

	/* (key-value 1.12) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_CREATION_TIME_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, just_created ?
		    op->coordinated_uvid_timestamp : md->creation_time),
	    goto _mexit);

	/* Add chunkmap metadata */

	/* (key-value 1.13) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_CHUNKMAP_TYPE_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_str(p, md->chunkmap_type), goto _mexit);

	/* (key-value 1.14) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_CHUNKMAP_BTREE_ORDER_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint16(p, md->chunkmap_btree_order),
	    goto _mexit);

	/* (key-value 1.15) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_CHUNKMAP_BTREE_MARKER_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->chunkmap_btree_marker),
	    goto _mexit);

	/* (key-value 1.16) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint32(p, md->chunkmap_chunk_size),
	    goto _mexit);

	/* Add NUVID data */

	/* (key-value 1.17) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_UVID_TIMESTAMP_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, op->coordinated_uvid_timestamp), goto _mexit);

	/* (key-value 1.18) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_TX_GENERATION_ID_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, op->txid_generation), goto _mexit);

	/* (key-value 1.19) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_UVID_SRC_COOKIE_IDX),
	    goto _mexit);
	uint32_t uvid_src_cookie = tc->unicastio == REPLICAST_UNICAST_TCP ?
				   robj->tcp_recv_port : robj->udp_recv_port;
	uvid_src_cookie ^= tc->loop_thrid;
	uvid_src_cookie ^= getpid();
	MCHK(err, msgpack_pack_uint32(p, uvid_src_cookie), goto _mexit);

	uint128_t obj_guid = tc->this_guid;
	if (!just_created) {
		/* preserve source segment guid for ISGW and cloud-provider
		 * delete paths */
		obj_guid.l = md->uvid_src_guid.l;
	}

	/* (key-value 1.20) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_UVID_SRC_GUID_IDX), goto _mexit);
	MCHK(err, replicast_pack_uint128(p, &obj_guid), goto _mexit);

	/* (key-value 1.21) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_LOGICAL_SIZE_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, md->logical_size), goto _mexit);

	/* (key-value 1.22) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_OBJECT_COUNT_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, md->object_count), goto _mexit);

	/* (key-value 1.23) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_PREV_LOGICAL_SIZE_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, md->prev_logical_size), goto _mexit);

	/* (key-value 1.24) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_HASH_TYPE_IDX), goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->hash_type), goto _mexit);

	/* (key-value 1.25) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_COMPRESS_TYPE_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->compress_type), goto _mexit);

	/* (key-value 1.26) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_REPLICATION_COUNT_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->replication_count), goto _mexit);

	/* (key-value 1.27) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_SYNC_PUT_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->sync_put), goto _mexit);

	/* (key-value 1.28) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_SELECT_POLICY_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->select_policy), goto _mexit);

	/* (key-value 1.29) */
	MCHK(err, msgpack_pack_uint64(p, RT_SYSKEY_ESTIMATED_USED_IDX),
	    goto _mexit);
	uint64_t est_used = md->estimated_used;
	if (*op->bid && (is_btree_map || op->oid_size < 2)) {
		double factor = used_factor(md->replication_count, md->ec_enabled, md->ec_data_mode);
		est_used =  (uint64_t) (md->logical_size * factor);
	}
	MCHK(err, msgpack_pack_uint64(p, est_used), goto _mexit);

	/* (key-value 1.30) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_FAILURE_DOMAIN_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->failure_domain), goto _mexit);

	/* (key-value 1.31) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_NUMBER_OF_VERSIONS_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint16(p, md->number_of_versions), goto _mexit);

	/* (key-value 1.32) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_TRACK_STATISTICS_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint16(p, md->track_statistics), goto _mexit);

	/* (key-value 1.33) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_IOPS_RATE_LIM_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint32(p, md->iops_rate_lim), goto _mexit);

	/* (key-value 1.34) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_EC_ENABLED_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->ec_enabled), goto _mexit);

	/* (key-value 1.35) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_EC_DATA_MODE_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint32(p, md->ec_data_mode), goto _mexit);

	/* (key-value 1.36) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_EC_TRG_POLICY_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, md->ec_trg_policy), goto _mexit);

	/* (key-value 1.37) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_FILE_OBJECT_TRANSPARANCY_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, md->file_object_transparency), goto _mexit);

	/* (key-value 1.38) */
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_OBJECT_DELETE_AFTER_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, md->object_delete_after), goto _mexit);

	/* (key-value 1.39) */
	if (c->cont_flags & CCOW_CONT_F_MDONLY) {
		RT_ONDEMAND_SET(md->inline_data_flags,
			RT_ONDEMAND_VALUE(RT_ONDEMAND_TYPE_MDONLY, ondemandPolicyUnpin));
	}
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_INLINE_DATA_FLAGS_IDX),
	    goto _mexit);
	MCHK(err, msgpack_pack_uint16(p, md->inline_data_flags), goto _mexit);

	/* (2) Pack ACL LIST */
	s_len = msgpack_get_len(p);
	MCHK(err, msgpack_pack_uint32(&hdr, s_len), goto _mexit);
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_ACL_LIST_IDX), goto _mexit);
	MCHK(err, msgpack_pack_array(p, 0), goto _mexit);

	/* (3) Pack Custom Metadata */
	s_len = msgpack_get_len(p);
	MCHK(err, msgpack_pack_uint32(&hdr, s_len), goto _mexit);
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_CUSTOM_METADATA_IDX),
	    goto _mexit);
	if (c->custom_md) {
		MCHK(err, msgpack_pack_map(p, c->custom_md->nbufs),
		    goto _mexit);
		for (size_t i = 0; i < c->custom_md->nbufs; i++) {
			MCHK(err, msgpack_put_buffer(p,
				    &rtbuf(c->custom_md, i)), goto _mexit);
		}
	} else
		MCHK(err, msgpack_pack_array(p, 0), goto _mexit);

	/* (4) Pack chunk reference list */
	s_len = msgpack_get_len(p);
	MCHK(err, msgpack_pack_uint32(&hdr, s_len), goto _mexit);
	MCHK(err, msgpack_pack_uint16(p, RT_SYSKEY_REFERENCE_LIST_IDX),
	    goto _mexit);

	/* Pack all user supplied ref entries */
	MCHK(err, msgpack_pack_array(p, rl_root->nbufs), goto _mexit);

	if (!md->object_deleted) {
		for (uint32_t i = 0; i < rl_root->nbufs; i++) {
			struct refentry *re = (struct refentry *)rtbuf(rl_root, i).base;

			MCHK(err, replicast_pack_refentry(p, re), goto _mexit);

			refentry_dump(lg, "VM Refentry packed", re);
			uint512_logdump(lg, "VM Refentry CHID", &re->content_hash_id);
		}
	}

	/* update header with section info */
	if (!msgpack_copy_to(&hdr, p->buffer + jumptbl_off,
		    RT_HDR_JUMPTBL_SIZE)) {
		goto _mexit;
	}

	return p;

_mexit:
	log_error(lg, "NAMED PUT: metadata packing error %d", err);
	msgpack_pack_free(p);
	return NULL;
}

void
ccow_namedput_done(struct putcommon_client_req *r)
{
	struct ccow_io *put_io = (struct ccow_io *)r->io;
	struct ccow_op *op = put_io->op;
	struct ccow_completion *c = put_io->comp;
	int err;

	if (c->needs_final_md) {
		struct vmmetadata newmd;

		err = replicast_get_metadata(r->payload, &newmd);
		assert(!err);

		assert(op == c->init_op);
		assert(op->iter);
		struct ccow_lookup *iter = op->iter;

		/* new obj? populate final md */
		if (op->txid_generation == 1) {
			je_free(iter->metadata->cid);
			je_free(iter->metadata->tid);
			je_free(iter->metadata->bid);
			je_free(iter->metadata->oid);

			memcpy(iter->metadata, &newmd, sizeof (struct vmmetadata));
			iter->metadata->cid = je_memdup(newmd.cid, newmd.cid_size);
			iter->metadata->cid_size = newmd.cid_size;
			iter->metadata->tid = je_memdup(newmd.tid, newmd.tid_size);
			iter->metadata->tid_size = newmd.tid_size;
			iter->metadata->bid = je_memdup(newmd.bid, newmd.bid_size);
			iter->metadata->bid_size = newmd.bid_size;
			iter->metadata->oid = je_memdup(newmd.oid, newmd.oid_size);
			iter->metadata->oid_size = newmd.oid_size;
		} else
			ccow_iter_update_md(iter, &newmd);
	}

	if (r->metadata) {
		msgpack_pack_free(r->metadata);
		r->metadata = NULL;
	}
	if (r->serial_data) {
		msgpack_pack_free(r->serial_data);
		r->serial_data = NULL;
	}
	if (r->payload) {
		rtbuf_destroy(r->payload);
		r->payload = NULL;
	}
}

int
ccow_vmpack(struct ccow_io *put_io, rtbuf_t *rl_root)
{
	int err;
	struct putcommon_client_req *r = CCOW_IO_REQ(put_io);
	struct ccow_op *op = put_io->op;
	struct vmmetadata *md = &op->metadata;
	struct ccow_completion *c = put_io->comp;
	int is_btree_map = memcmp_quick(md->chunkmap_type, strlen(md->chunkmap_type),
		    RT_SYSVAL_CHUNKMAP_BTREE, strlen(RT_SYSVAL_CHUNKMAP_BTREE)) == 0;

	log_trace(lg, "put_io %p : rl_root %p) is_btree_map: %d",
			put_io, rl_root, is_btree_map);

	if (!rl_root)
		return -EINVAL;

	if (rl_root->nbufs > 0 && is_btree_map) {
		/* Initialize the vm->logical_size in case the VM is rl-full without CM's */
		uint64_t max_logical_size = 0;
		uint32_t i = rl_root->nbufs - 1;

		struct refentry *re = (struct refentry *)rtbuf(rl_root, i).base;
		/*
		 * Calculate the logical size based on input ref entries,
		 * any entry that is larger than the max size stored in VM will
		 * update the VM which w(ill be packed with vmpack at && c->object_count == 0) the end.
		 */
		if (re->offset + re->length > max_logical_size && RT_REF_TYPE(re) != RT_REF_TYPE_MANIFEST)
			max_logical_size = re->offset + re->length;

		if (max_logical_size > md->logical_size)
			md->logical_size = max_logical_size;
	}

	// FIXME: what happens when we get back to zero size on the bucket?
	// and how do we detect that instead of initially empty bucket?
	if (c->object_count_mod) {
		md->object_count = c->object_count;
	}
	if (c->logical_sz_mod) {
		md->prev_logical_size = md->logical_size;
		md->logical_size = c->logical_sz;
	}
	if (c->used_sz_mod) {
		md->estimated_used = c->used_sz;
	}

	/*
	 * Pack metadata and reflist
	 */
	msgpack_p *p = ccow_pack_metadata_common(r, rl_root);
	if (!p)
		return -ENOMEM;

	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);


	/* Map reflist to payload */
	if (!(put_io->attributes & RD_ATTR_SERIAL_OP)) {
		r->payload = rtbuf_init_mapped(&buf, 1);
		if (!r->payload) {
			msgpack_pack_free(p);
			return -ENOMEM;
		}
	}
	r->metadata = p;

	return 0;
}

int
ccow_cmpack(struct ccow_io *io, rtbuf_t *rl)
{
	int err;
	struct putcommon_client_req *r = CCOW_IO_REQ(io);
	struct ccow_op *op = io->op;
	struct vmmetadata *md = &op->metadata;
	int is_btree_map = memcmp_quick(md->chunkmap_type, strlen(md->chunkmap_type),
		    RT_SYSVAL_CHUNKMAP_BTREE, strlen(RT_SYSVAL_CHUNKMAP_BTREE)) == 0;

	log_trace(lg, "io %p : rl %p) is_btree_map: %d", io, rl, is_btree_map);

	if (!rl)
		return -EINVAL;

	msgpack_p *p = msgpack_pack_init();
	if (!p)
		return -ENOMEM;

	/* Pack all user supplied ref entries */
	err = msgpack_pack_array(p, rl->nbufs);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}
//
// Skip this in case of container object
//
	uint64_t max_logical_size = 0;
	for (uint32_t i = 0; i < rl->nbufs && op->oid != NULL; i++) {
		struct refentry *re = (struct refentry *)rtbuf(rl, i).base;
		/* FIXME: This logic can be optimized by looking at the last
		 * op->chunks manifest only.
		 *
		 * Calculate the logical size based on input ref entries,
		 * any entry that is larger than the max size stored in VM will
		 * update the VM which will be packed with vmpack at the end.
		 */
		if (re->offset + re->length > max_logical_size && RT_REF_TYPE(re) != RT_REF_TYPE_MANIFEST)
			max_logical_size = re->offset + re->length;
		err = replicast_pack_refentry(p, re);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}

		refentry_dump(lg, "CM Refentry packed", re);
		uint512_logdump(lg, "CM Refentry CHID", &re->content_hash_id);
	}
	/* Salt the manifest */
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME_COARSE, &tp);
	err = msgpack_pack_uint64(p, tp.tv_nsec);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}

	if (is_btree_map && max_logical_size > md->logical_size)
		md->logical_size = max_logical_size;

	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);

	/* Map reflist to payload */
	r->payload = rtbuf_init_mapped(&buf, 1);
	if (!r->payload) {
		msgpack_pack_free(p);
		return -ENOMEM;
	}

	err = rtbuf_hash(r->payload, HASH_TYPE_DEFAULT, &r->chid);
	if (err) {
		log_error(lg, "UNNAMED PUT error while calculating "
		    "payload hash value: %d", err);
		msgpack_pack_free(p);
		rtbuf_destroy(r->payload);
		return err;
	}

	r->packed_data = p;

	return 0;
}

static inline void
ccow_namedget_set_default_md(struct getcommon_client_req *r)
{
	struct ccow_io *get_io = (struct ccow_io *)r->io;
	struct ccow_op *op = get_io->op;
	struct vmmetadata *md = &op->metadata;
	struct ccow_completion *c = get_io->comp;

	if (*op->oid == 0) {
		/* insertion into the non-existing bucket or bucket deletion has
		 * to set chunkmap type to bucket default, i.e. key-value
		 * name index */
		strcpy(md->chunkmap_type, RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX);
	} else {
		strcpy(md->chunkmap_type, c->chunkmap_type);
	}

	log_trace(lg, "oid %s chunkmap_type: %s", op->oid, md->chunkmap_type);

	// In the case where the object needs to pass in creation-only params and it
	// had previously existed we're going to key off of the NG QUERY flag to return
	// the previous object's MD and see if it was just deleted, in which case it
	// should be safe to change creation-only params.
	// NOTE: it is possible if keep_versions is > 1 that there may be inadvertant over
	// replication of an object if the old version had rep count 3 and the new version
	// has rep count < 3 AND the data is deduped because the SBR + VBR may reerence
	// the same CM.. this will clean itself up with garbage cleanup over time IF
	// you create new version of the object > n+keep_versions
	if ((op->txid_generation == 1 || md->object_deleted) || op->optype != CCOW_CONT) {
		ccow_copy_inheritable_comp_to_md(c, md);
	}

	/* sanity check */
	assert(c->hash_type > HASH_TYPE_BEGIN);

	if (op->iter) {
		struct ccow_lookup *iter = op->iter;

		if (iter->metadata) {
			je_free(iter->metadata->cid);
			je_free(iter->metadata->tid);
			je_free(iter->metadata->bid);
			je_free(iter->metadata->oid);
			je_free(iter->metadata);
		}

		iter->metadata = je_calloc(1, sizeof (struct vmmetadata));
		if (!iter->metadata) {
			log_error(lg, "NAMED GET metadata out of mem on new PUT");
			return;
		}

		memcpy(iter->metadata, md, sizeof (struct vmmetadata));
		iter->metadata->cid = je_memdup(op->cid, op->cid_size);
		iter->metadata->cid_size = op->cid_size;
		iter->metadata->tid = je_memdup(op->tid, op->tid_size);
		iter->metadata->tid_size = op->tid_size;
		iter->metadata->bid = je_memdup(op->bid, op->bid_size);
		iter->metadata->bid_size = op->bid_size;
		iter->metadata->oid = je_memdup(op->oid, op->oid_size);
		iter->metadata->oid_size = op->oid_size;
	}
}

static int
ccow_pack_serial_op(ccow_sr_mj_opcode_t major, ccow_sr_mn_opcode_t minor,
		    msgpack_p **pack)
{
	int err;
	assert(pack != NULL);
	*pack = NULL;

	msgpack_p *p = msgpack_pack_init();
	if (!p)
		return -ENOMEM;

	MCHK(err, msgpack_pack_uint8(p, major), goto _exit);
	MCHK(err, msgpack_pack_uint8(p, minor), goto _exit);
	*pack = p;
	return 0;

_exit:
	msgpack_pack_free(p);
	return err;
}

static inline ccow_sr_mj_opcode_t
get_container_code(struct ccow_op *op)
{
	return op->oid_size != 1 ? CCOW_SR_MAJ_OBJECT_UPDATE :
		op->bid_size != 1 ? CCOW_SR_MAJ_BUCKET_UPDATE :
		op->tid_size != 1 ? CCOW_SR_MAJ_TENANT_UPDATE :
		op->cid_size != 1 ? CCOW_SR_MAJ_CLUSTER_UPDATE :
		CCOW_SR_MAJ_SYS_UPDATE;
}

/*
 * convert a list of iovec entries into a fully ref list of hierarchy
 */
static int
ccow_iov_to_reflist(msgpack_p *p, struct ccow_op *op,
		    struct iovec *iov, size_t iovcnt)
{
	int err = 0;
	struct iovec *new_iovec = NULL;
	size_t new_iovcnt;
	size_t i, start_index;
	ccow_sr_mj_opcode_t maj;

	maj = get_container_code(op);
	assert(maj >= CCOW_SR_MAJ_SYS_UPDATE && maj <= CCOW_SR_MAJ_OBJECT_UPDATE);
	start_index = (size_t)(maj - CCOW_SR_MAJ_SYS_UPDATE);

	if (start_index) {
		new_iovcnt = iovcnt + start_index;
		new_iovec = je_calloc(new_iovcnt, sizeof(*new_iovec));
		if (!new_iovec)
			return -ENOMEM;
	}

	switch (start_index) {
	case 4:
		assert(op->oid_size > 1);
		new_iovec[3].iov_base = op->oid;
		new_iovec[3].iov_len = op->oid_size;
	case 3:
		assert(op->bid_size > 1);
		new_iovec[2].iov_base = op->bid;
		new_iovec[2].iov_len = op->bid_size;
	case 2:
		assert(op->tid_size > 1);
		new_iovec[1].iov_base = op->tid;
		new_iovec[1].iov_len = op->tid_size;
	case 1:
		new_iovec[0].iov_base = op->cid;
		new_iovec[0].iov_len = op->cid_size;
		break;
	case 0:
		new_iovec = iov;
		new_iovcnt = iovcnt;
		break;
	default:
		break;
	}


	if (start_index)
		for (i = start_index; i < new_iovcnt; i++)
			new_iovec[i] = iov[i - start_index];

	MCHK(err, msgpack_pack_map(p, new_iovcnt), goto _nexit);
	for (size_t i = 0; i < new_iovcnt; i++) {
		MCHK(err, msgpack_pack_raw(p, new_iovec[i].iov_base,
					   new_iovec[i].iov_len),
		    goto _nexit);

	}
	if (start_index)
		je_free(new_iovec);
	return 0;

_nexit:
	je_free(new_iovec);
	if (p)
		msgpack_pack_free(p);
	return err;
}

int
ccow_pack_lock(msgpack_p *p, struct ccow_obj_lock *ccow_lk)
{
	int err;

	MCHK(err, replicast_pack_uint512(p, &ccow_lk->lk_nhid), goto _mexit);
	MCHK(err, msgpack_pack_uint8(p, ccow_lk->lk_mode), goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, ccow_lk->lk_region.off), goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, ccow_lk->lk_region.len), goto _mexit);
	MCHK(err, replicast_pack_uint128(p, &ccow_lk->lk_client_addr), goto _mexit);
	MCHK(err, msgpack_pack_uint16(p, ccow_lk->lk_client_port), goto _mexit);
	MCHK(err, msgpack_pack_uint64(p, ccow_lk->lk_io_cookie), goto _mexit);
	MCHK(err, msgpack_pack_int32(p, ccow_lk->lk_ref_count), goto _mexit);

_mexit:
	return err;
}

int
ccow_unpack_lock(msgpack_u *u, struct ccow_obj_lock *ccow_lk)
{
	int err;

	MCHK(err, replicast_unpack_uint512(u, &ccow_lk->lk_nhid), goto _mexit);
	MCHK(err, msgpack_unpack_uint8(u, &ccow_lk->lk_mode), goto _mexit);
	MCHK(err, msgpack_unpack_uint64(u, &ccow_lk->lk_region.off), goto _mexit);
	MCHK(err, msgpack_unpack_uint64(u, &ccow_lk->lk_region.len), goto _mexit);
	MCHK(err, replicast_unpack_uint128(u, &ccow_lk->lk_client_addr),
	     goto _mexit);
	MCHK(err, msgpack_unpack_uint16(u, &ccow_lk->lk_client_port),
	     goto _mexit);
	MCHK(err, msgpack_unpack_uint64(u, &ccow_lk->lk_io_cookie), goto _mexit);
	MCHK(err, msgpack_unpack_int32(u, &ccow_lk->lk_ref_count), goto _mexit);

_mexit:
	return err;
}

/* Set payload for the serial operation */
static int
ccow_set_sop_payload(struct getcommon_client_req *r)
{
	int err = -ENOEXEC;
	struct ccow_io *get_io = (struct ccow_io *)r->io;
	struct ccow_op *op = get_io->op;
	struct ccow_completion *c = get_io->comp;
	struct ccow_obj_lock *lk;
	struct ccow *tc = c->tc;
	struct replicast *robj = tc->netobj->robj[0];

	struct putcommon_client_req *req = CCOW_IO_REQ(op->namedput_io);

	if (req == NULL) {
		log_debug(lg, "Oops!! putio NULL getio :%p tc: %p\n", get_io, tc);
		return -ENOEXEC;
	}

	/* TODO: Convert it to table later */
	msgpack_p *p;
	uint16_t major_op, minor_op;
	assert(op->namedput_io->attributes & RD_ATTR_SERIAL_OP);

	if (c->cont_flags & CCOW_CONT_F_EVENTUAL_SOP) {
		op->namedput_io->attributes |= RD_ATTR_EVENTUAL_SOP;
	}

	switch (op->optype) {
	case CCOW_INSERT_LIST:
		major_op = get_container_code(op);
		assert(major_op >= CCOW_SR_MAJ_SYS_UPDATE &&
		       major_op <= CCOW_SR_MAJ_OBJECT_UPDATE);
		if (c->cont_flags && (c->cont_flags & CCOW_CONT_F_INSERT_LIST_OVERWRITE)) {
			minor_op = CCOW_SR_UPDATE_LIST;
		} else {
			minor_op = CCOW_SR_INSERT_LIST;
		}
		break;
	case CCOW_INSERT_MD:
		major_op = get_container_code(op);
		assert(major_op >= CCOW_SR_MAJ_SYS_UPDATE &&
		       major_op <= CCOW_SR_MAJ_OBJECT_UPDATE);
		minor_op = CCOW_SR_INSERT_MD;
		break;
	case CCOW_INSERT_LIST_WITH_MD:
		major_op = get_container_code(op);
		assert(major_op >= CCOW_SR_MAJ_SYS_UPDATE &&
			major_op <= CCOW_SR_MAJ_OBJECT_UPDATE);
		minor_op = CCOW_SR_INSERT_LIST_WITH_MD;
		break;
	case CCOW_DELETE_LIST:
		major_op = get_container_code(op);
		assert(major_op >= CCOW_SR_MAJ_SYS_UPDATE &&
		       major_op <= CCOW_SR_MAJ_OBJECT_UPDATE);
		minor_op = CCOW_SR_DELETE_LIST;
		break;
	case CCOW_DELETE_MD:
		major_op = get_container_code(op);
		assert(major_op >= CCOW_SR_MAJ_SYS_UPDATE &&
		       major_op <= CCOW_SR_MAJ_OBJECT_UPDATE);
		minor_op = CCOW_SR_DELETE_MD;
		break;
	case CCOW_DELETE_LIST_WITH_MD:
		major_op = get_container_code(op);
		assert(major_op >= CCOW_SR_MAJ_SYS_UPDATE &&
			major_op <= CCOW_SR_MAJ_OBJECT_UPDATE);
		minor_op = CCOW_SR_DELETE_LIST_WITH_MD;
		break;
	case CCOW_UPDATE_MD:
		major_op = get_container_code(op);
		assert(major_op >= CCOW_SR_MAJ_SYS_UPDATE &&
		       major_op <= CCOW_SR_MAJ_OBJECT_UPDATE);
		minor_op = CCOW_SR_UPDATE_MD;
		break;
	case CCOW_SOP_FLUSH:
		major_op = get_container_code(op);
		assert(major_op >= CCOW_SR_MAJ_SYS_UPDATE &&
		       major_op <= CCOW_SR_MAJ_OBJECT_UPDATE);
		minor_op = CCOW_SR_FLUSH;
		break;
	case CCOW_LOCK:
		major_op = CCOW_SR_MAJ_LOCK;
		minor_op = CCOW_SR_MINOR_ANY;
		break;
	default:
		major_op = 0;
		break;
	}

	if (major_op != 0) {
		err = ccow_pack_serial_op(major_op, minor_op, &p);
		if (err)
			return -ENOEXEC;

		switch (op->optype) {
		case CCOW_INSERT_LIST:
		case CCOW_DELETE_LIST:
		case CCOW_INSERT_MD:
		case CCOW_UPDATE_MD:
		case CCOW_DELETE_MD:
		case CCOW_INSERT_LIST_WITH_MD:
		case CCOW_DELETE_LIST_WITH_MD:
		case CCOW_SOP_FLUSH:
			err = ccow_iov_to_reflist(p, op,
						  op->iov_in, op->iovcnt_in);
			break;
		case CCOW_LOCK:
			lk = (struct ccow_obj_lock *)op->iov_in->iov_base;
			lk->lk_nhid = c->vm_name_hash_id;
			lk->lk_io_cookie = (uint64_t)op->namedput_io;
			if (tc->unicastio &&
			    tc->unicastio  == REPLICAST_UNICAST_TCP) {
				memcpy(&lk->lk_client_addr,
				       &robj->msg_origin_tcpaddr.sin6_addr,
				       sizeof(lk->lk_client_addr));
				lk->lk_client_port =
					robj->msg_origin_tcpaddr.sin6_port;
			} else {
				memcpy(&lk->lk_client_addr,
				       &robj->msg_origin_udpaddr.sin6_addr,
				       sizeof(lk->lk_client_addr));
				lk->lk_client_port =
					robj->msg_origin_udpaddr.sin6_port;
			}
			char nhidstr[UINT512_BYTES*2+1];
			uint512_dump(&lk->lk_nhid, nhidstr, UINT512_BYTES*2+1);
			char addrstr[INET6_ADDRSTRLEN + 1] = { 0 };
			inet_ntop(AF_INET6, &lk->lk_client_addr, addrstr,
				  INET6_ADDRSTRLEN);
			log_trace(lg, "Client %p Lock req: region [%" PRIu64
				      ",%" PRIu64 ") mode %x nhid %s client "
				      "addr %s ref count %u ioptr %p", tc,
				      lk->lk_region.off, lk->lk_region.len,
				      lk->lk_mode, nhidstr, addrstr,
				      lk->lk_ref_count, op->namedput_io);
			err = ccow_pack_lock(p, lk);
			break;
		default:
			/* Shoud not reach here */
			assert(0);
			break;
		}
		if (err) {
			msgpack_pack_free(p);
			return -ENOEXEC;
		}
		uv_buf_t buf;
		msgpack_get_buffer(p, &buf);
		req->payload = rtbuf_init_mapped(&buf, 1);
		if (!req->payload) {
			msgpack_pack_free(p);
			return -ENOMEM;
		}
		req->serial_data = p;
		req->chid = c->vm_name_hash_id;
	}
	op->namedput_io->attributes |= RD_ATTR_SERIAL_OP;
	return err;
}

/**
 * Pre-fetch an object before pinning/cloning
 * NOTE: an object size and a chunk size need to be known in advance,
 * e.g. as a result of named get.
 */
static int
ccow_prefetch(ccow_t tc, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, uint64_t generation, size_t len, size_t chunk_size,
	int comp_flags) {

	struct iovec iov[4];
	size_t batch_len = sizeof(iov)/sizeof(iov[0]);
	char* buf = je_malloc(batch_len*chunk_size);
	for (size_t i = 0; i < batch_len; i++) {
		iov[i].iov_base = buf + i*chunk_size;
		iov[i].iov_len = chunk_size;
	}

	size_t n_chunks = len/chunk_size + !!(len % chunk_size);
	uint64_t genid = generation;
	ccow_completion_t c;

	int err = ccow_create_stream_completion(tc, NULL, NULL, 1+n_chunks, &c,
		bid, bid_size, oid, oid_size, &genid, &comp_flags, NULL);
	uint32_t bs = chunk_size;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
		(void *)&bs, NULL);
	assert(!err);
	int cnt = 0;
	size_t pos = 0;
	while (pos < n_chunks) {
		size_t iolen = batch_len;
		if (pos + iolen > n_chunks)
			iolen = n_chunks - pos;

		err = ccow_get_cont(c, iov, batch_len, pos*chunk_size, 1, &cnt);

		if (!err)
			err = ccow_wait(c, cnt);

		if (err) {
			log_error(lg, "ccow_prefetch failed: ccow_wait error %d", err);
			break;
		}
		pos += iolen;
	}
	je_free(buf);
	return err;
}

void
ccow_namedget_query_done(struct getcommon_client_req *r)
{
	int err;
	struct ccow_io *get_io = (struct ccow_io *)r->io;
	struct ccow_op *op = get_io->op;
	struct ccow_completion *c = get_io->comp;
	struct vmmetadata *md = &op->metadata;

	log_trace(lg, "r %p: optype %s", r, ccow_op2str(op->optype));

	if (op->status != 0) {
		ccow_release(c);
		return;
	}

	op->vmchid = r->chid;
	op->namedput_io->attributes = get_io->attributes;
	/* Piggyback on ng_get_default_md will reset prev_logical_size */
	uint64_t temp_prev_size = 0;
	if (get_io->attributes & RD_ATTR_OBJECT_REPLACE) {
		temp_prev_size = md->logical_size;
	}

	if (get_io->attributes & (RD_ATTR_ONDEMAMD_PIN | RD_ATTR_ONDEMAND_UNPIN |
		RD_ATTR_ONDEMAND_PERSIST)) {
		if (r->fddelta < 0) {
			log_error(lg, "Cannot pin/un-pin in a SPLIT, fddelta %d",
				r->fddelta);
			ccow_fail_io(get_io, -EPERM);
			ccow_release(c);
			return;
		}
		uint16_t ondemand_policy = RT_ONDEMAND_GET(md->inline_data_flags);
		if (ondemand_policy == ondemandPolicyLocal) {
			log_error(lg, "Cannot pin/un-pin an uncacheable object");
			ccow_fail_io(get_io, -EPERM);
			ccow_release(c);
			return;
		}

		if (ondemand_policy == ondemandPolicyPersist) {
			log_error(lg, "Cannot pin/un-pin a persistent cacheable object");
			ccow_fail_io(get_io, -EPERM);
			ccow_release(c);
			return;
		}

		if ((get_io->attributes & RD_ATTR_ONDEMAMD_PIN) &&
			(ondemand_policy == ondemandPolicyPin)) {
			log_error(lg, "The object is pinned already");
			ccow_fail_io(get_io, -EEXIST);
			ccow_release(c);
			return;
		}

		if ((get_io->attributes & RD_ATTR_ONDEMAND_UNPIN) &&
			(ondemand_policy == ondemandPolicyUnpin)) {
			log_error(lg, "The object is MDonly already");
			ccow_fail_io(get_io, -EEXIST);
			ccow_release(c);
			return;
		}
	}
	if (get_io->attributes & RD_ATTR_ONDEMAND_CLONE) {
		/* Cloned cacheable object must be local */
		uint16_t type = RT_ONDEMAND_GET_TYPE(md->inline_data_flags);
		uint16_t value = RT_ONDEMAND_VALUE(type, ondemandPolicyLocal);
		RT_ONDEMAND_SET(md->inline_data_flags, value);
	}
	/* new object? || replace */
	if (op->txid_generation == 1 ||
	    (get_io->attributes & RD_ATTR_OBJECT_REPLACE)) {
		ccow_namedget_set_default_md(r);
		if (get_io->attributes & RD_ATTR_OBJECT_REPLACE) {
			md->object_delete_after = 0;

			// replace operates on btm objects only atm
			md->inline_data_flags = 0;
		}
	}

	/* If this is a replace request, drop the vm_reflist */
	// TODO: Check to see if there are references to this data struct yet..
	if ((get_io->attributes & RD_ATTR_OBJECT_REPLACE) && op->vm_reflist) {
		rtbuf_destroy(op->vm_reflist);
		op->vm_reflist = NULL;
		md->logical_size = 0;
	}

	if (!op->vm_reflist) {
		op->vm_reflist = rtbuf_init_empty();
		if (!op->vm_reflist) {
			ccow_fail_io(get_io, -ENOMEM);
			ccow_release(c);
			return;
		}
	}

	if (get_io->attributes & (RD_ATTR_PARITY_ENCODE | RD_ATTR_ONDEMAMD_PIN |
		RD_ATTR_ONDEMAND_UNPIN | RD_ATTR_ONDEMAND_PERSIST)) {
		op->metadata.txid_generation = op->txid_generation =
		    c->vm_txid_generation;
		op->metadata.prev_logical_size = op->metadata.logical_size;
		op->metadata.tid = op->tid;
		op->metadata.bid = op->bid;
		op->metadata.oid = op->oid;
		op->metadata.tid_size = op->tid_size;
		op->metadata.bid_size = op->bid_size;
		op->metadata.oid_size = op->oid_size;
		op->metadata.prev_logical_size = 0;
		err = ccow_build_name_hashes(c, op);
		if (err) {
			ccow_fail_io(get_io, -ENOMEM);
			ccow_release(c);
			return;
		}
		return;
	}

	// Setup target version for ccow_copy operation
	if (c->dst_txid_generation < ~0ULL) {
		op->txid_generation = c->dst_txid_generation + 1;
	}

	/* If this is an object copy case. */
	if (op->copy_opts) {
		/* point operation to the dst object */
		if (op->tid)
			je_free(op->tid);
		if (op->bid)
			je_free(op->bid);
		if (op->oid)
			je_free(op->oid);
		op->tid = op->copy_opts->tid;
		op->bid = op->copy_opts->bid;
		op->oid = op->copy_opts->oid;
		op->tid_size = op->copy_opts->tid_size;
		op->bid_size = op->copy_opts->bid_size;
		op->oid_size = op->copy_opts->oid_size;

		/* store it in metadata as well so that put will be using
		 * new object ids */
		op->metadata.tid = op->tid;
		op->metadata.bid = op->bid;
		op->metadata.oid = op->oid;
		op->metadata.tid_size = op->tid_size;
		op->metadata.bid_size = op->bid_size;
		op->metadata.oid_size = op->oid_size;
		op->metadata.prev_logical_size = 0;
		op->metadata.object_delete_after = 0;
		err = ccow_build_name_hashes(c, op);
		if (err) {
			ccow_fail_io(get_io, -ENOMEM);
			ccow_release(c);
			return;
		}
	} else {
		if (get_io->attributes & RD_ATTR_OBJECT_REPLACE) {
			// Don't use size of deleted object
			if (op->metadata.object_deleted) {
				op->metadata.logical_size = 0;
				op->metadata.prev_logical_size = 0;
			} else {
				op->metadata.prev_logical_size = temp_prev_size;
			}
		} else {
			op->metadata.prev_logical_size = op->metadata.logical_size;
		}
	}

	/* no need to traverse chunks if none provided and not INIT case */
	if (!op->iovcnt_in && op->optype != CCOW_CONT) {
		err = ccow_vmpack(op->namedput_io, op->vm_reflist);
		if (err) {
			ccow_fail_io(get_io, -ENOMEM);
			ccow_release(c);
		}
		return;
	}

	if (get_io->attributes & RD_ATTR_SERIAL_OP) {
		log_debug(lg, "Packing a serial operation");
		assert(op->iov_in != NULL);
		err = ccow_set_sop_payload(r);
		if (err) {
			log_debug(lg, "Could not set serial op : %d", err);
			ccow_fail_io(get_io, err);
			ccow_release(c);
		}
		return;
	}

	op->chm = chunkmap_find(op->metadata.chunkmap_type);
	if (!op->chm) {
		ccow_fail_io(get_io, -ENOENT);
		ccow_release(c);
		return;
	}

	err = op->chm->create(op, ccow_vmpack, ccow_cmpack, &op->chm_handle);
	if (err) {
		ccow_fail_io(get_io, err);
		ccow_release(c);
		return;
	}

	if (op->optype == CCOW_CONT) {
		/* No need to update chunking lib yet */
		return;
	}

	err = op->chm->update(op->chm_handle, NULL,
	    (bt_overwrite_cb) ccow_ucache_evict_overwrite, (void  *) c->tc->ucache);
	if (err) {
		ccow_fail_io(get_io, err);
		ccow_release(c);
		return;
	}

	if (op->iter) {
		ccow_lookup_release(op->iter);
		op->iter = NULL;
	}
	/*
	 * At this point I/O pipe line can execute chunkmap created
	 * I/Os if any... See ccow_compete_io() for details.
	 */

}

struct unnamedput_cont_req {
	struct ccow *tc;
	struct ccow_io *io;
	int inexec;
};

static void
unnamedput_cont_comphash_done(void *arg, int status)
{
	int err, ev = EV_DONE;
	struct state *st = arg;
	struct unnamedput_cont_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_completion *c = io->comp;
	struct ccow_op *op = c->init_op;

	log_trace(lg, "arg %p, status %d", arg, status);

	r->inexec--;

	if (status) {
		ccow_fail_io(io, status);
		ev = EV_ERR;
		goto _exit;
	}
	/*
	 * Continue chunking processing for this object now. I.e. schedule
	 * Unnamed Get/Put's..
	 */

	struct ccow * tc = r->tc;
	assert(tc != NULL);
	ucache_t * ucache = tc->ucache;
	assert(ucache != NULL);

	err = op->chm->update(op->chm_handle, io->cont_op,
	    (bt_overwrite_cb) ccow_ucache_evict_overwrite, (void *) r->tc->ucache);
	if (err) {
		ccow_fail_io(io, err);
		ev = EV_ERR;
		goto _exit;
	}

	ccow_io_lock(io);
	if (QUEUE_EMPTY(&io->p_queue)) {
		ev = EV_START;
	} else {
		while (!QUEUE_EMPTY(&io->p_queue)) {
			QUEUE *q = QUEUE_HEAD(&io->p_queue);
			struct ccow_io *cio = QUEUE_DATA(q, struct ccow_io, p_item);

			err = ccow_start_io(cio);
			if (err) {
				ccow_io_unlock(io);
				ev = EV_ERR;
				goto _exit;
			}

			QUEUE_REMOVE(q);
			QUEUE_INIT(q);
			QUEUE_INSERT_TAIL(&io->p_busy_queue, &cio->p_item);
		}
	}
	ccow_io_unlock(io);

_exit:
	if (state_check(st, ST_INIT))
		state_next(st, ev);
	else
		state_event(st, ev);
}

CCOW_EI_TAG_DEFINE(unnamedput_cont__init, 10);

static void
unnamedput_cont__init(struct state *st)
{
	int err;
	struct unnamedput_cont_req *r = st->data;
	struct ccow *tc = r->tc;
	struct ccow_io *io = r->io;
	struct ccow_op *op = io->cont_op;

	log_trace(lg, "st %p", st);

#if CCOW_EI
	CCOW_EI_TAG_INC(unnamedput_cont__init, err, 911);

	if (err != 0) {
		log_debug(lg, "Inserting error %d in unnamedput_cont__init", err);
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}
#endif

	r->inexec++;

	if ((op->iovcnt_in) && (op->optype != CCOW_INSERT_LIST_CONT &&
		    op->optype != CCOW_DELETE_LIST_CONT)) {
		size_t len = 0, i = 0;

		while (len <= tc->comphash_threshold_size && i < op->iovcnt_in)
			len += op->iov_in[i++].iov_len;

		if (len <= tc->comphash_threshold_size) {
			for (i = 0; i < op->iovcnt_in; i++) {
				struct comphash ch;
				ch.status = 0;
				ch.idx = i;
				ch.op = op;
				ch.iov_in = &op->iov_in[i];
				ch.arg = NULL;
				comphash_one(&ch);
				err = ch.status;
				if (err)
					break;
			}

			unnamedput_cont_comphash_done(st, err);
			return;
		}
	} else {
		/*
		 * if no IOVs supplied, be done immediately!
		 */
		unnamedput_cont_comphash_done(st, 0);
		return;
	}

	/*
	 * Start Async Compression/Fingerprint. Children I/O is blocked until
	 * compression & hashing is complete.
	 */
	err = ccow_comphash_compute(op, unnamedput_cont_comphash_done, io);
	if (err) {
		r->inexec--;
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}
}

static void
unnamedput_cont__term(struct state *st)
{
	struct unnamedput_cont_req *r = st->data;

	log_trace(lg, "st %p", st);

	assert(r->inexec >= 0);
	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	ccow_complete_io((struct ccow_io *)st);
}

/*
 * Initiate CCOW_PUT_CONT
 *
 * Scope: PUBLIC
 */
int
ccow_put_cont(struct ccow_completion *c, struct iovec *iov, size_t iovcnt,
    uint64_t off, int need_wait, int *index)
{
	int err = ccow_put_type_cont(c, iov, iovcnt, off, need_wait, NULL, index,
			CCOW_PUT_CONT);
	return err;
}

/*
 * Initiate CCOW_PUT_CONT with pre-read content
 *
 * Scope: PUBLIC
 */

int
ccow_mod_put_cont(struct ccow_completion *c, struct iovec *iov, size_t iovcnt,
    uint64_t off, int need_wait, struct ccow_rmw_context *rmw_ctx, int *index)
{
	int err = ccow_put_type_cont(c, iov, iovcnt, off, need_wait, rmw_ctx,
			index, CCOW_PUT_CONT);
	return err;
}



int
ccow_put_type_cont(struct ccow_completion *c, struct iovec *iov,
    size_t iovcnt, uint64_t off, int need_wait,
	struct ccow_rmw_context *rmw_ctx, int *index, int optype)
{
	int err;

	if (!c->init_op) {
		log_error(lg, "ccow_put_cont called on uninitialized ccow_completion, "
		    "c->init_op = NULL");
		return -EINVAL;
	}

	struct ccow_op *op = c->init_op;
	struct ccow *tc = c->tc;
	int is_btree_map = memcmp_quick(op->metadata.chunkmap_type, strlen(op->metadata.chunkmap_type),
	    RT_SYSVAL_CHUNKMAP_BTREE, strlen(RT_SYSVAL_CHUNKMAP_BTREE)) == 0;

	if (is_btree_map && (off % (uint64_t)op->metadata.chunkmap_chunk_size) != 0) {
		log_error(lg, "Chunks start offset %lu isn't chunk size %u aligned (ignored)",
		    off, op->metadata.chunkmap_chunk_size);
	}

	for (size_t i = 0; i < iovcnt; i++) {
		/* check against object's current chunk size, except the last one */
		if (is_btree_map && i + 1 < iovcnt && iov[i].iov_len != op->metadata.chunkmap_chunk_size) {
			log_error(lg, "Chunk idx=%ld buffer length %lu isn't chunk size %u aligned (ignored)",
			    i, iov[i].iov_len, op->metadata.chunkmap_chunk_size);
		}
		if (is_btree_map) {
			if (iov[i].iov_len > REPLICAST_CHUNK_SIZE_MAX) {
				log_error(lg, "Chunk size %lu too big, idx=%ld",
					iov[i].iov_len, i);
				return -E2BIG;
			}
		} else { // not btree_map
			size_t max_size = (REPLICAST_CHUNK_SIZE_MAX/8)*7/op->metadata.chunkmap_btree_order;
			if (iov[i].iov_len > max_size) {
				log_error(lg, "Chunk size %lu > %lu too big, idx=%ld",
					iov[i].iov_len, max_size, i);
				return -E2BIG;
			}
		}
	}

	c->needs_final_put = 1;
	c->vmm_gen_id++;

	tc->stats.ccow.put_conts++;

	/* cannot be called from tenant's event loop context! */
	nassert(tc->loop_thrid != uv_thread_self());

	if (c->status != 0) {
		log_error(lg, "ccow_put_cont called on invalid ccow_completion, "
		    "c->status = %d", c->status);
		return -EINVAL;
	}

	uv_mutex_lock(&c->operations_mutex);
	if (op->completed || op->finalizing) {
		log_error(lg, "ccow_put_cont gets called after init operation "
		    "completed or finalizing");
		uv_mutex_unlock(&c->operations_mutex);
		return -EINVAL;
	}
	uv_mutex_unlock(&c->operations_mutex);

	log_debug(lg, "===> PutCont %lu vector(s) at 0x%" PRIx64, iovcnt, off);
	log_hexdump(lg, "CID:", (char *)op->cid, op->cid_size);
	log_hexdump(lg, "TID:", (char *)op->tid, op->tid_size);
	log_hexdump(lg, "BID:", (char *)op->bid, op->bid_size);
	log_hexdump(lg, "OID:", (char *)op->oid, op->oid_size);

	struct ccow_op *cont_op;
	err = ccow_operation_create_cont(c, optype, &cont_op, index);

	if (err) {
		log_error(lg, "PUT Unnamed request operation alloc error: %d",
		    err);
		return err;
	}

	cont_op->need_wait = need_wait;

	static const struct transition trans_tbl[] = {
		// FROM, EVENT, ACTION, TO, GUARD
		// -----------------------------------------------------------
		{ ST_INIT, EV_CALL, &unnamedput_cont__init, ST_WAIT, NULL },
		{ ST_INIT, EV_DONE, NULL, ST_READY, NULL },
		{ ST_WAIT, EV_DONE, NULL, ST_READY, NULL },
		{ ST_READY, EV_DONE, NULL, ST_TERM, NULL },
		{ ST_INIT, EV_START, NULL, ST_TERM, NULL },
		{ ST_WAIT, EV_START, NULL, ST_TERM, NULL },
		{ ST_ANY, EV_ANY, NULL, ST_TERM, NULL }
	};

	struct unnamedput_cont_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		err = -ENOMEM;
		log_error(lg, "memory allocation failure");
		ccow_operation_destroy(cont_op, 1);
		log_error(lg, "UNNAMED PUT CONT request alloc error: %d", err);
		return err;
	}
	r->inexec = 0;
	r->tc = c->tc;

	err = ccow_create_io(c, op, CCOW_PUT_CONT, trans_tbl,
			sizeof (trans_tbl) / sizeof (*trans_tbl), r,
			unnamedput_cont__term, &r->io);
	if (err) {
		log_error(lg, "ccow_create_io returned err = %d", err);
		ccow_operation_destroy(cont_op, 1);
		je_free(r);
		return err;
	}
	r->io->cont_op = cont_op;

	/*
	 * Prepare outputs for comphash
	 *
	 * NOTICE: we allocate actual output (chunk->base) in comphash.
	 */
	cont_op->chunks = rtbuf_init_mapped((uv_buf_t *)iov, iovcnt);
	if (!cont_op->chunks) {
		log_error(lg, "memory allocation failure");
		ccow_operation_destroy(cont_op, 1);
		je_free(r);
		return -ENOMEM;
	}

	cont_op->chids = je_calloc(iovcnt, sizeof (uint512_t));
	if (!cont_op->chids) {
		je_free(r);
		log_error(lg, "memory allocation failure");
		ccow_operation_destroy(cont_op, 1);
		return -ENOMEM;
	}

	r->io->rmw_ctx = rmw_ctx;
	/*
	 * Remember request arguments
	 */
	cont_op->iov_in = iov;
	cont_op->iovcnt_in = iovcnt;
	cont_op->offset = off;

	cont_op->namedget_io = r->io;
	atomic_inc(&cont_op->busy_cnt);

	/*
	 * Chain continuation I/O into CCOW_CONT (e.g. init_op)
	 */
	ccow_io_lock(r->io);

	ccow_chain_io(op, r->io);

	if (op->busy_cnt == 0) {
		err = ccow_start_io(r->io);
		if (err != 0) {
			ccow_io_unlock(r->io);
			log_error(lg, "ccow_start_io returned error %d", err);
			ccow_operation_destroy(cont_op, 1);
			je_free(r);
			return err;
		}
	} else {
		log_debug(lg, "io %p: deferred start", r->io);
	}
	ccow_io_unlock(r->io);

	return 0;
}

/*
 * Initiate CCOW PUT/INIT
 *
 * Scope: PRIVATE
 */
int
ccow_tenant_put(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, struct ccow_completion *c, struct iovec *iov,
    size_t iovcnt, uint64_t off, ccow_op_t optype,
    struct ccow_copy_opts *copy_opts, int64_t get_io_attributes)
{
	int err;

	assert(optype);
	assert(cid && cid_size > 0);
	assert(tid && tid_size > 0);
	assert(bid && bid_size > 0);
	assert(oid && oid_size > 0);

	/*
	 * Any PUT operation at c/t/b level considered serial. Hence mark
	 * it with SOP flag. That is to skip insert/delete while processing
	 * TRLOG.
	 */
	if (optype == CCOW_PUT && *oid == 0)
		get_io_attributes |= RD_ATTR_TRLOG_SOP;

	if (*cid == 0 && strncmp(tid, RT_SYSVAL_TENANT_ADMIN,
	          sizeof (RT_SYSVAL_TENANT_ADMIN)) == 0) {
		tid = RT_SYSVAL_TENANT_SVCS;
		tid_size = sizeof (RT_SYSVAL_TENANT_SVCS);
	}

	if (!copy_opts) {
		log_debug(lg, "===> Put/Init %lu vector(s) at 0x%" PRIx64, iovcnt, off);
		log_escdump(lg, "CID:", (char *)cid, cid_size);
		log_escdump(lg, "TID:", (char *)tid, tid_size);
		log_escdump(lg, "BID:", (char *)bid, bid_size);
		log_escdump(lg, "OID:", (char *)oid, oid_size);
	} else {
		assert(copy_opts->tid && copy_opts->tid_size > 0);
		assert(copy_opts->bid && copy_opts->bid_size > 0);
		assert(copy_opts->oid && copy_opts->oid_size > 0);

		log_debug(lg, "===> Clone %lu vector(s) at 0x%" PRIx64, iovcnt, off);
		log_hexdump(lg, "CID:", (char *)cid, cid_size);
		log_hexdump(lg, "TID:", (char *)tid, tid_size);
		log_hexdump(lg, "BID:", (char *)bid, bid_size);
		log_hexdump(lg, "OID:", (char *)oid, oid_size);
		log_hexdump(lg, "copy to TID:", (char *)copy_opts->tid,
		    copy_opts->tid_size);
		log_hexdump(lg, "copy to BID:", (char *)copy_opts->bid,
		    copy_opts->bid_size);
		log_hexdump(lg, "copy to OID:", (char *)copy_opts->oid,
		    copy_opts->oid_size);
	}

	if (oid_size > REPLICAST_STR_MAXLEN) {
		return -EINVAL;
	} else if (bid_size > REPLICAST_STR_MAXLEN) {
		return -EINVAL;
	} else if (tid_size > REPLICAST_STR_MAXLEN) {
		return -EINVAL;
	} else if (cid_size > REPLICAST_STR_MAXLEN) {
		return -EINVAL;
	}


	/*
	 * Allocate Named Get IO.
	 *
	 * Each CCOW PUT transaction starts with Named Get with RT_ATTR_QUERY
	 * flag set. As a result we will receive TxID generation.
	 */
	struct ccow_io *get_io;
	struct ccow_op *put_op;

	// RTBUF custom_md needs to be add_alloc()'d from completion into op
	// so it can be freed
	err = ccow_namedget_create(cid, cid_size, tid, tid_size, bid, bid_size,
	    oid, oid_size, c, ccow_namedget_query_done, optype, &put_op,
	    &get_io);
	if (err)
		return err;
	get_io->attributes |= get_io_attributes | RD_ATTR_QUERY;
	/*
	 * Prepare outputs for comphash
	 *
	 * NOTICE: we allocate actual output (chunk->base) in comphash.
	 */
	put_op->chunks = rtbuf_init_mapped((uv_buf_t *)iov, iovcnt);
	if (!put_op->chunks) {
		ccow_operation_destroy(put_op, 1);
		ccow_destroy_io(get_io);
		return -ENOMEM;
	}
	put_op->chids = je_calloc(iovcnt, sizeof (uint512_t));
	if (!put_op->chids) {
		ccow_operation_destroy(put_op, 1);
		ccow_destroy_io(get_io);
		return -ENOMEM;
	}

	/*
	 * Remember request arguments
	 */
	put_op->iov_in = iov;
	put_op->iovcnt_in = iovcnt;
	put_op->offset = off;
	put_op->copy_opts = copy_opts;

	/*
	 * Allocate Named Put IO.
	 *
	 * At the end of CCOW PUT transaction we will need to use Named Put to
	 * create new Version Manifest.
	 */

	struct ccow_io *put_io;
	err = ccow_namedput_create(c, ccow_namedput_done, put_op, &put_io);
	if (err) {
		ccow_operation_destroy(put_op, 1);
		ccow_destroy_io(get_io);
		return err;
	}
	if (get_io_attributes & RD_ATTR_PARITY_ENCODE)
		put_io->attributes |= RD_ATTR_PARITY_ENCODE;

	if (get_io_attributes & RD_ATTR_ONDEMAMD_PIN)
		put_io->attributes |= RD_ATTR_ONDEMAMD_PIN;

	if (get_io_attributes & RD_ATTR_ONDEMAND_UNPIN)
		put_io->attributes |= RD_ATTR_ONDEMAND_UNPIN;

	if (get_io_attributes & RD_ATTR_ONDEMAND_PERSIST)
		put_io->attributes |= RD_ATTR_ONDEMAND_PERSIST;


	if (get_io_attributes & RD_ATTR_OBJECT_REPLACE)
		put_io->attributes |= RD_ATTR_OBJECT_REPLACE;

	if (get_io_attributes & RD_ATTR_TRLOG_SOP)
		put_io->attributes |= RD_ATTR_TRLOG_SOP;


	/* no need to traverse chunks if none provided and not INIT case */

	/*
	 * There is only one named put per operation. Chunkmap will use this
	 * pointer to complete chunk reference list packing.
	 */
	put_op->namedput_io = put_io;
	if (optype == CCOW_CONT) {
		c->init_op = put_op;
		ccow_copy_inheritable_comp_to_md(c, &c->init_op->metadata);
	}

	if (get_io_attributes & RD_ATTR_SERIAL_OP) {
		/* See named_put.c where we select targeted VDEV on PP,
		 * we only need to send single request, targeted.. */
		uint8_t syn_put = 1;
		err = ccow_attr_modify_default(c, CCOW_ATTR_SYNC_PUT,
		    (void *)&syn_put, NULL);
		if (err) {
			log_error(lg, "SOP_put: couldn't modify sync_put value, err: %d", err);
			return -EIO;
		}
	}


	/*
	 * We start compression & fingerprint threads in parallel with
	 * Named Get I/O. If I/O completes prior to comphash_done, we wait in
	 * case of success and cancel comphash tasks in case of error.
	 */

	/*
	 * Start Async I/O sequence and compression/fingerprinting...
	 */
	err = ccow_start_io(get_io);

	return err;
}


/*
 * Copy a Tenant/Bucket/Object, creating a new object with same md.
 *
 * Scope: PUBLIC
 */
int
ccow_clone(ccow_completion_t comp, const char *tid_src, size_t tid_src_size,
    const char *bid_src, size_t bid_src_size, const char *oid_src,
    size_t oid_src_size, struct ccow_copy_opts *copy_opts)
{
	int err = 0;
	int exists = 0, copy_to_self = 0;
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	uint64_t ioattr = 0;

	log_hexdump(lg, "TID:", (char *)tid_src, tid_src_size);
	log_hexdump(lg, "BID:", (char *)bid_src, bid_src_size);
	log_hexdump(lg, "OID:", (char *)oid_src, oid_src_size);

	// Set generation id
	if (copy_opts->genid) {
		c->cont_generation = copy_opts->genid;
		c->version_uvid_timestamp = (*copy_opts->genid > 0 ? copy_opts->version_uvid_timestamp : 0);
	}

	if (copy_opts->version_vm_content_hash_id) {
		c->version_vm_content_hash_id = (uint512_t *) je_malloc(sizeof(uint512_t));
		if (!c->version_vm_content_hash_id) {
			err = -ENOMEM;
			log_error(lg, "ccow_clone returned error %d", err);
			ccow_release(c);
			return err;
		}
		uint512_fromhex(copy_opts->version_vm_content_hash_id, (UINT512_BYTES * 2 + 1), c->version_vm_content_hash_id);
	} else {
		c->version_vm_content_hash_id = NULL;
	}


	char *tid_dst = copy_opts->tid;
	size_t tid_dst_size = copy_opts->tid_size;
	char *bid_dst = copy_opts->bid;
	size_t bid_dst_size = copy_opts->bid_size;
	char *oid_dst = copy_opts->oid;
	size_t oid_dst_size = copy_opts->oid_size;

	assert(tid_src && tid_src_size > 0);
	assert(bid_src && bid_src_size > 0);
	assert(oid_src && oid_src_size > 0);

	assert(tid_dst && tid_dst_size > 0);
	assert(bid_dst && bid_dst_size > 0);
	assert(oid_dst && oid_dst_size > 0);

	/* Tenant Copy case. */
	if (*bid_src == 0 && *oid_src == 0 && *bid_dst == 0 && *oid_dst == 0) {
		/* Verify Admin. */
		if (memcmp_quick(tid_src, tid_src_size, RT_SYSVAL_TENANT_ADMIN,
			    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
			log_error(lg, "Only Admin may modify tenants.");
			return -EPERM;
		}
		return -ENOTSUP;
	}

	/* Bucket Copy case. */
	/* FIXME: Implement ACL to check Tenant perms. */
	if (*bid_src && *bid_dst && *oid_src == 0 && *oid_dst == 0) {
		if (memcmp_quick(bid_src, bid_src_size, bid_dst,
			    bid_dst_size) == 0)
			return -EBADF;
		return -ENOTSUP;
	}

	/* Bucket Copy case. */
	/* FIXME: Implement ACL to check Tenant/Bucket perms */
	if (!(*bid_src && *bid_dst && *oid_src && *oid_dst))
		return -EBADF;

	/* Copy of Object onto itself. */
	if (memcmp_quick(bid_src, bid_src_size, bid_dst, bid_dst_size) == 0 &&
	    memcmp_quick(oid_src, oid_src_size, oid_dst, oid_dst_size) == 0)
		copy_to_self = 1;

	if (memcmp_quick(tid_src, tid_src_size, tid_dst, tid_dst_size) != 0 &&
	    memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0)
		return -EPERM;

	struct ccow_completion *check_c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &check_c);
	if (err)
		return err;

	/* Check to see if destination object exists. */
	err = ccow_tenant_get(tc->cid, tc->cid_size, tid_dst, tid_dst_size,
	    bid_dst, bid_dst_size, oid_dst, oid_dst_size, check_c, NULL, 0, 0,
	    CCOW_GET, NULL);
	if (err) {
		ccow_release(check_c);
		return err;
	}

	exists = 1;
	err = ccow_wait(check_c, 0);
	if (err == -ENOENT)
		exists = 0;
	else if (err)
		return err;

	/* Save the destination generation in completion field 'dst_txid_generation'  */
	c->dst_txid_generation = ((exists || check_c->vm_txid_generation > 0) ? check_c->vm_txid_generation : 0);

	if (oid_src_size > 1) {
		/* Check to see if source object exists and fetch MDOnly-related info */
		err = ccow_create_completion(tc, NULL, NULL, 1, &check_c);
		if (err)
			return err;

		ccow_lookup_t iter;
		err = ccow_tenant_get(tc->cid, tc->cid_size, tid_src, tid_src_size,
		    bid_src, bid_src_size, oid_src, oid_src_size, check_c, NULL, 0, 0,
		    CCOW_GET, &iter);
		if (err) {
			ccow_release(check_c);
			return err;
		}

		err = ccow_wait(check_c, -1);
		if (err) {
			log_error(lg, "source object query failed: ccow_wait error %d", err);
			return err;
		}

		uint64_t size = 0;
		uint32_t chunk_size = 0;
		uint16_t inl = 0;
		struct ccow_metadata_kv *kv = NULL;
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
			if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &size);
			} else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv,
				    &chunk_size);
			} else if (strcmp(kv->key, RT_SYSKEY_INLINE_DATA_FLAGS) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT16, kv, &inl);
			}
		}
		ccow_lookup_release(iter);
		uint16_t mdoonly_policy = RT_ONDEMAND_GET(inl);
		if (mdoonly_policy != ondemandPolicyLocal) {
			/* Reset on-demand attribute of the dst object */
			ioattr |= RD_ATTR_ONDEMAND_CLONE;
			if (mdoonly_policy != ondemandPolicyPersist) {
				/* Source object needs to be converted to persistent */
				uint64_t gen = copy_opts->genid ? *copy_opts->genid : 0;
				if (mdoonly_policy == ondemandPolicyUnpin) {
					/* The object is cacheable, but not pinned. Doing pre-fetch */
					err = ccow_prefetch(tc, bid_src, bid_src_size, oid_src,
						oid_src_size, gen, size, chunk_size, CCOW_CONT_F_PREFETCH_TOUCH);
					if (err)
						return err;
				}
				err = ccow_create_completion(tc, NULL, NULL, 1, &check_c);
				if (err) {
					log_error(lg, "ccow_pin failed: Completion create error %d", err);
					return err;
				}
				err = ccow_ondemand_policy_change_request(bid_src, bid_src_size, oid_src, oid_src_size,
					gen, ondemandPolicyPersist, check_c);
				if (err) {
					ccow_release(check_c);
					log_error(lg, "ccow_clone failed: ccow_mdonly_policy_change_request error %d", err);
					return err;
				}
				err = ccow_wait(check_c, -1);
				if (err) {
					log_error(lg, "ccow_clone failed: ccow_wait error %d", err);
					return err;
				}
			}
		}
	}


	struct ccow_copy_opts *opts = je_malloc(sizeof (*opts));
	if (!opts) {
		return -ENOMEM;
	}
	opts->tid = je_memdup(tid_dst, tid_dst_size);
	if (!opts->tid) {
		je_free(opts);
		return -ENOMEM;
	}
	opts->bid = je_memdup(bid_dst, bid_dst_size);
	if (!opts->bid) {
		je_free(opts->tid);
		je_free(opts);
		return -ENOMEM;
	}
	opts->oid = je_memdup(oid_dst, oid_dst_size);
	if (!opts->oid) {
		je_free(opts->tid);
		je_free(opts->bid);
		je_free(opts);
		return -ENOMEM;
	}
	opts->tid_size = tid_dst_size;
	opts->bid_size = bid_dst_size;
	opts->oid_size = oid_dst_size;
	opts->md_override = 1;

	err = ccow_tenant_put(tc->cid, tc->cid_size, tid_src, tid_src_size,
	    bid_src, bid_src_size, oid_src, oid_src_size, c, NULL,
	    0, 0, (copy_to_self && exists) ? CCOW_PUT : CCOW_CLONE,
	    (copy_to_self && exists) ? NULL : opts, ioattr);
	if ((err && err != -EEXIST) || (copy_to_self && exists)) {
		je_free(opts->tid);
		je_free(opts->bid);
		je_free(opts->oid);
		je_free(opts);
		return err;
	}

	return 0;
}

/*
 * Initiate CCOW PUT
 *
 * Scope: PUBLIC
 */
int
ccow_replace(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, struct iovec *iov, size_t iovcnt)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, iov, iovcnt, 0,
	    CCOW_PUT, NULL, RD_ATTR_OBJECT_REPLACE);
}

/*
 * Initiate CCOW PUT
 *
 * Scope: PUBLIC
 */
int
ccow_put(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, struct iovec *iov, size_t iovcnt, uint64_t off)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	tc->stats.ccow.puts++;

	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, iov, iovcnt, off,
	    CCOW_PUT, NULL, 0);
}

/*
 * Initiate CCOW PUT without entry in TRLOG
 *
 * Scope: PUBLIC
 */
int
ccow_put_notrlog(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, struct iovec *iov, size_t iovcnt, uint64_t off)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	tc->stats.ccow.puts++;

	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, iov, iovcnt, off,
	    CCOW_PUT, NULL, RD_ATTR_TRLOG_SOP);
}

/*
 * Initiate CCOW INSERT LIST
 *
 * Scope: PUBLIC
 */
int
ccow_insert_list(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, struct iovec *iov, size_t iovcnt)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	int err;

	err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, iov, iovcnt, 0,
	    CCOW_INSERT_LIST, NULL, 0);
	return err;
}

/*
 * Update container in serialsed fashion
 *
 * Scope: PUBLIC
 */
int
ccow_container_update_list(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, struct ccow_completion *c, struct iovec *iov,
    size_t iovcnt, ccow_op_t optype)
{
	return ccow_tenant_put(cid, cid_size, tid, tid_size, bid, bid_size,
				oid, oid_size, c, iov, iovcnt, 0,
				optype, NULL, RD_ATTR_SERIAL_OP);
}

/*
 * Initiate CCOW DELETE LIST CONT
 *
 * Scope: PUBLIC
 */
int
ccow_delete_list_cont(ccow_completion_t comp, struct iovec *iov, size_t iovcnt,
    int need_wait, int *index)
{
	int err = ccow_put_type_cont(comp, iov, iovcnt, 0, need_wait, NULL, index,
	    CCOW_DELETE_LIST_CONT);
	return err;
}

/*
 * Initiate CCOW INSERT LIST CONT
 *
 * Scope: PUBLIC
 */
int
ccow_insert_list_cont(ccow_completion_t comp, struct iovec *iov, size_t iovcnt,
    int need_wait, int *index)
{
	int err = ccow_put_type_cont(comp, iov, iovcnt, 0, need_wait, NULL, index,
	    CCOW_INSERT_LIST_CONT);
	return err;
}

int
ccow_insert_chid(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, struct iovec *iov, size_t iovcnt)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	log_trace(lg, "c: %p oid: %s/%s", c, bid, oid);

	if (iovcnt < 2)
		return -EINVAL;
	if (iov[1].iov_len != UINT512_BYTES)
		return -EINVAL;
	/* Add the object to the snapview */
	int err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, iov, iovcnt, 0,
	    CCOW_INSERT_LIST, NULL, RD_ATTR_CHUNK_MANIFEST);
	return err;
}

int
ccow_are_parts_aligned(const char *bid, size_t bid_size, struct iovec *iov, int total_parts,
    int *aligned, ccow_t cl)
{
	int err = 0;
	uint32_t chunk_size = 0;
	uint64_t size = 0;
	ccow_lookup_t iter;
	ccow_completion_t c;
	struct ccow_metadata_kv *kv = NULL;
	*aligned = 1;

	for (int i = 0; i < total_parts; i++) {
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		if (err)
			return err;
		err = ccow_get(bid, bid_size, (char*)iov[i].iov_base, iov[i].iov_len,
		    c, NULL, 0, 0, &iter);
		if (err)
			return err;
		err = ccow_wait(c, -1);
		if (err) {
			if (iter)
				ccow_lookup_release(iter);
			return err;
		}

		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
			if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0)
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &size);
			if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0)
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv, &chunk_size);
		}
		if (iter)
			ccow_lookup_release(iter);
		int rem_bytes = size % chunk_size;

		if (rem_bytes) {
			*aligned = 0;
			break;
		}
	}
	return err;
}

int
ccow_copy_aligned(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *dst_oid,
    size_t dst_oid_size, struct iovec *iov1, int total_parts, ccow_t cl)
{
	int err = 0;
	size_t iovcnt=0;
	uint32_t chunk_size = 0;
	uint64_t offset = 0;
	uint64_t size = 0;
	struct ccow_metadata_kv *kv = NULL;
	ccow_lookup_t iter;
	ccow_completion_t c;

	for (int part = 0; part < total_parts; part++) {
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		if (err)
			return err;
		err = ccow_get(bid, bid_size, (char*)iov1[part].iov_base, iov1[part].iov_len,
		    c, NULL, 0, 0, &iter);
		if (err)
			return err;
		err = ccow_wait(c, -1);
		if (err) {
			if (iter)
				ccow_lookup_release(iter);
			return err;
		}

		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
			if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0)
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &size);
			if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0)
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv, &chunk_size);
		}
		if (iter)
			ccow_lookup_release(iter);

		iovcnt = size / chunk_size + !!(size % chunk_size);
		char *iob = je_malloc(iovcnt * chunk_size);
		if (!iob)
			return -ENOMEM;
		struct iovec *iov = je_malloc(iovcnt * sizeof(struct iovec));
		if (!iov) {
			je_free(iob);
			return -ENOMEM;
		}

		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		if (err) {
			je_free(iob);
			je_free(iov);
			return err;
		}

		for (unsigned int i = 0; i < iovcnt; i++) {
			iov[i].iov_len = chunk_size;
			iov[i].iov_base = iob + i * chunk_size;
		}
		err = ccow_get(bid, bid_size, (char*)iov1[part].iov_base, iov1[part].iov_len, c, iov,
				iovcnt, 0, NULL);
		if (err) {
			ccow_release(c);
			log_error(lg, "ccow_get error: %d", err);
			je_free(iob);
			je_free(iov);
			return err;
		}
		err = ccow_wait(c, -1);
		if (err) {
			if (iter)
				ccow_lookup_release(iter);
			log_error(lg, "ccow_wait error: %d", err);
			je_free(iov);
			je_free(iob);
			return err;
		}
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		if (err) {
			je_free(iov);
			je_free(iob);
			return err;
		}

		err = ccow_tenant_put(c->tc->cid, c->tc->cid_size, c->tc->tid,
		    c->tc->tid_size, bid, bid_size, dst_oid, dst_oid_size, c, iov, iovcnt, offset,
		    CCOW_PUT, NULL, RD_ATTR_CHUNK_MANIFEST);

		if (err) {
			ccow_release(c);
			je_free(iov);
			je_free(iob);
			return err;
		}
		err = ccow_wait(c, -1);
		if (err) {
			log_error(lg, "ccow_wait error: %d", err);
			je_free(iov);
			je_free(iob);
			return err;
		}
		offset += iovcnt * chunk_size;

		je_free(iov);
		je_free(iob);
	}
	return err;
}

static int
read_part(const char *bid, size_t bid_size, const char *part,
     struct iovec riov, ccow_t cl, uint64_t offset)
{
	unsigned int k=0;
	uint64_t bytesread = 0;
	ccow_lookup_t iter;
	struct ccow_metadata_kv *kv = NULL;
	ccow_completion_t c;

	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err)
		return err;

	err = ccow_get(bid, bid_size, part, strlen(part) + 1,
	          c, &riov, 1, offset, NULL);
	if (err) {
		ccow_release(c);
		log_error(lg, "ccow_get error: %d", err);
		return err;
	}
	err = ccow_wait(c, -1);
	if (err) {
		log_error(lg, "ccow_wait error: %d", err);
		return err;
	}

	return bytesread;
}

static int
write_part(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *dst_oid,
    size_t dst_oid_size, struct iovec riov, struct iovec wiov, uint64_t *woffset, ccow_t cl)
{
	assert(cl != NULL);
	ccow_completion_t comp;


	int err = ccow_create_completion(cl, NULL, NULL, 1, &comp);
	if (err)
		return err;
	err = ccow_tenant_put(cid, cid_size, tid,
	    tid_size, bid, bid_size, dst_oid, dst_oid_size, comp, &wiov, 1, *woffset,
	    CCOW_PUT, NULL, RD_ATTR_CHUNK_MANIFEST);
	if (err) {
		log_error(lg, "ccow_append_objects error: %d", err);
		return err;
	}
	err = ccow_wait(comp, -1);
	if (err) {
		log_error(lg, "ccow_wait error: %d", err);
		return err;
	}
	*woffset += wiov.iov_len;

	return err;
}

int
ccow_copy_unaligned(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *dst_oid,
    size_t dst_oid_size, struct iovec *iov, int total_parts, ccow_t cl)
{
	int err = 0;
	uint64_t bytes_read = 0;
	uint64_t curr_bytes = 0;
	uint64_t offset = 0;
	uint64_t woffset = 0;
	uint64_t rem_bytes = 0;
	uint32_t chunk_size;
	uint64_t size = 0;
	uint64_t bytes = 0;
	struct ccow_metadata_kv *kv = NULL;
	ccow_lookup_t iter;
	ccow_completion_t c;

	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err)
		return err;
	err = ccow_get(bid, bid_size, (char*)iov[0].iov_base, iov[0].iov_len,
	          c, NULL, 0, 0, &iter);
	if (err)
		return err;
	err = ccow_wait(c, -1);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		return err;
	}

	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
		if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0)
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv, &chunk_size);
	}

	if (iter)
		ccow_lookup_release(iter);
	char *rdbuf = je_malloc(chunk_size);
	if (!rdbuf)
		return -ENOMEM;
	char *wrbuf = je_malloc(chunk_size);
	if (!wrbuf) {
		je_free(rdbuf);
		return -ENOMEM;
	}

	struct iovec riov = { .iov_base = rdbuf, .iov_len = chunk_size };
	struct iovec wiov = { .iov_base = wrbuf, .iov_len = 0 };
	char *wptr = wiov.iov_base;

	for (int i = 0; i < total_parts; i++ ) {
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		if (err) {
			je_free(wrbuf);
			je_free(rdbuf);
			return err;
		}
		err = ccow_get(bid, bid_size, (char*)iov[i].iov_base, iov[i].iov_len,
	            c, NULL, 0, 0, &iter);
		if (err) {
			je_free(wrbuf);
			je_free(rdbuf);
			return err;
		}
		err = ccow_wait(c, -1);
		if (err) {
			if (iter)
				ccow_lookup_release(iter);
			je_free(wrbuf);
			je_free(rdbuf);
			return err;
		}
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
			if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0)
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &size);
		}
		if (iter)
			ccow_lookup_release(iter);
		while (offset <= size) {
			err = read_part(bid, bid_size, (char*)iov[i].iov_base, riov, cl, offset);
			if (err) {
				je_free(wrbuf);
				je_free(rdbuf);
				return err;
			}
			bytes = chunk_size;

			/* Last chunk of file which may be less than chunksize */
			if ((offset + bytes) > size)
				bytes = size - offset;
			/* Check for the bytes already stored in write buf */
			if (wiov.iov_len) {
				curr_bytes = chunk_size - wiov.iov_len;
				if (curr_bytes > bytes)
					curr_bytes = bytes;

				memcpy(wptr, riov.iov_base, curr_bytes);
				wptr += curr_bytes;
				offset = (size > offset + chunk_size) ? offset + chunk_size : 0;
			} else if (bytes < chunk_size) {
				curr_bytes = bytes;
				memcpy(wptr, riov.iov_base, curr_bytes);
				wptr += curr_bytes;
				/* Current object reading is finished */
				offset = 0;
			} else {
				/* Read next chunk */
				curr_bytes = chunk_size;
				memcpy(wptr, riov.iov_base, curr_bytes);
				offset = (size > offset + chunk_size) ? offset + chunk_size : 0;
			}
			wiov.iov_len += curr_bytes;

			if (bytes >= curr_bytes)
				bytes -= curr_bytes;

			if (bytes)
				rem_bytes = bytes;

			if (wiov.iov_len == chunk_size) {
				err = write_part(cid, cid_size, tid, tid_size, bid, bid_size,
				    dst_oid, dst_oid_size, riov, wiov, &woffset, cl);
				if (err) {
					je_free(wrbuf);
					je_free(rdbuf);
					return err;
				}

				wptr = wiov.iov_base;
				wiov.iov_len = 0;
				memset(&wrbuf, 0, sizeof(wrbuf));

				if(rem_bytes) {
					char *rptr = riov.iov_base;
					rptr += curr_bytes;
					memcpy(wptr, rptr, rem_bytes);
					wptr += rem_bytes;
					wiov.iov_len += rem_bytes;
				}
			}
			if (offset == 0)
				break;
		}
	}
	if (wiov.iov_len)
		err = write_part(cid, cid_size, tid, tid_size, bid, bid_size,
	            dst_oid, dst_oid_size, riov, wiov, &woffset, cl);

	je_free(wrbuf);
	je_free(rdbuf);

	return err;
}

/*
 * Initiate CCOW COPY Objects
 *
 * Scope: PRIVATE
 */

int
ccow_copy_objects(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *dst_oid,
    size_t dst_oid_size, struct iovec *iov, int total_parts, ccow_t cl)
{
	int err = 0;
	int aligned = 0;
	unsigned int k = 0;
	uint32_t last_fileptr = 0;
	uint64_t file_read = 0;
	uint32_t chunk_size = 0;
	ccow_lookup_t iter;
	struct ccow_metadata_kv *kv = NULL;
	ccow_completion_t c;

	assert(total_parts!=0);

	err = ccow_create_completion(cl, NULL, NULL, 1,  &c);

	err = ccow_get(bid, bid_size, iov[0].iov_base, iov[0].iov_len,
			c, NULL, 0, 0, &iter);
	if (err) {
		ccow_release(c);
		return err;
	}
	err = ccow_wait(c, -1);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		return err;
	}

	if (iter)
		ccow_lookup_release(iter);

	err = ccow_are_parts_aligned(bid, bid_size, iov, total_parts, &aligned, cl);
	if (err)
		return err;

	if (aligned) {
	        /* parts are aligned */
		err = ccow_copy_aligned(cid, cid_size, tid, tid_size, bid, bid_size,
		    dst_oid, dst_oid_size, iov, total_parts, cl);
	} else {
	        /* parts are not aligned */
		err = ccow_copy_unaligned(cid, cid_size, tid, tid_size, bid, bid_size,
		    dst_oid, dst_oid_size, iov, total_parts, cl);
	}
	return err;
}

/*
 * Initiate CCOW DELETE LIST
 *
 * Scope: PUBLIC
 */
int
ccow_delete_list(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, struct iovec *iov, size_t iovcnt)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	int err;

	err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, iov,
	    iovcnt, 0, CCOW_DELETE_LIST, NULL, 0);
	return err;
}

/*
 * Initiate CCOW EXPUNGE
 *
 * Scope: PUBLIC
 */
int
ccow_expunge(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	if (flexhash_split(tc->flexhash) && (tc->expunge_onsplit == 1)) {
		return -EPERM;
	}

	/* logical delete + expunge object */
	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, NULL, 0,
	    0, CCOW_PUT, NULL, RD_ATTR_LOGICAL_DELETE | RD_ATTR_EXPUNGE_OBJECT);
}

/*
 * Initiate CCOW EXPUNGE_VERSION
 *
 * Scope: PUBLIC
 */
int
ccow_expunge_version(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
		uint64_t *genid, uint64_t version_uvid_timestamp, const char *version_vm_content_hash_id, ccow_completion_t comp)
{
	int err = 0;
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	if (flexhash_split(tc->flexhash) && (tc->expunge_onsplit == 1)) {
		return -EPERM;
	}

	// Set version related fields
	c->cont_generation = genid;
	c->version_uvid_timestamp = (genid && *genid > 0 ? version_uvid_timestamp : 0);

	if (version_vm_content_hash_id) {
		c->version_vm_content_hash_id = (uint512_t *) je_malloc(sizeof(uint512_t));
		if (!c->version_vm_content_hash_id) {
			err = -ENOMEM;
			log_error(lg, "ccow_expunge_version returned error %d", err);
			ccow_release(c);
			return err;
		}
		uint512_fromhex(version_vm_content_hash_id, (UINT512_BYTES * 2 + 1), c->version_vm_content_hash_id);
	} else {
		c->version_vm_content_hash_id = NULL;
	}

	/* logical delete + expunge object */
	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, NULL, 0,
		0, CCOW_PUT, NULL,
		RD_ATTR_LOGICAL_DELETE | RD_ATTR_EXPUNGE_OBJECT_VERSION);
}


/*
 * Initiate CCOW DELETE
 *
 * Scope: PUBLIC
 */
int
ccow_delete(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	/* try to delete object */
	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, NULL, 0,
	    0, CCOW_PUT, NULL, RD_ATTR_LOGICAL_DELETE);
}

/*
 * Initiate CCOW DELETE without adding entry to TRLOG
 *
 * Scope: PUBLIC
 */
int
ccow_delete_notrlog(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	/* try to delete object */
	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, NULL, 0,
	    0, CCOW_PUT, NULL, RD_ATTR_LOGICAL_DELETE | RD_ATTR_TRLOG_SOP);
}

/*
 * Initiate CCOW DELETE with versioning support
 *
 * Scope: PUBLIC
 */
int
ccow_delete_versioning(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	/* try to delete object */
	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, NULL, 0,
	    0, CCOW_PUT, NULL, RD_ATTR_LOGICAL_DELETE | RD_ATTR_DELETE_OBJECT_VERSION);
}



/*
 * Initiate ERASURE ENCODE
 *
 * Scope: PUBLIC
 */
int
ccow_erasure_encode(const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, uint64_t generation, uint8_t codec_id, uint8_t width,
	uint8_t parity, ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	/* (Re-)calculate parity protection of the object */
	c->ec_data_mode = TO_CODECFMT(width, parity);
	SET_CODECID(c->ec_data_mode, codec_id);
	c->vm_txid_generation = generation;

	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, NULL, 0, 0,
	    CCOW_PUT, NULL, RD_ATTR_PARITY_ENCODE);
}


/*
 * Initiate PIN/UNPINT/PERSIST operation
 *
 * Scope: PUBLIC
 */

int
ccow_ondemand_policy_change_request(const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, uint64_t generation, ondemand_policy_t pol,
	ccow_completion_t comp) {

	struct ccow *tc = comp->tc;
	assert(pol < ondemandPolicyTotal);
	assert(pol >= 0);
	uint64_t attr = pol == ondemandPolicyPin ? RD_ATTR_ONDEMAMD_PIN :
			pol == ondemandPolicyUnpin ? RD_ATTR_ONDEMAND_UNPIN :
				RD_ATTR_ONDEMAND_PERSIST;

	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, comp, NULL, 0, 0,
	    CCOW_PUT, NULL, attr);
}

int
ccow_ondemand_policy_change(ccow_t tc, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, uint64_t generation, ondemand_policy_t pol) {

	/* Get object metadata to figure out whether the object cacheable/pinnable */
	ccow_completion_t c;
	int err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;
	ccow_lookup_t iter;
	err = ccow_get(bid, bid_size, oid, oid_size, c, NULL, 0, 0, &iter);
	if (err) {
		ccow_release(c);
		log_error(lg, "ccow_pin failed: ccow_get error %d", err);
		return err;
	}
	err = ccow_wait(c, -1);
	if (err) {
		log_error(lg, "ccow_pin failed: ccow_wait error %d", err);
		return err;
	}

	uint64_t size = 0;
	uint32_t chunk_size = 0;
	uint16_t inl = 0;
	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
		if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &size);
		} else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv,
			    &chunk_size);
		} else if (strcmp(kv->key, RT_SYSKEY_INLINE_DATA_FLAGS) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT16, kv, &inl);
		}
	}
	ccow_lookup_release(iter);
	uint16_t src_mdonly_policy = RT_ONDEMAND_GET(inl);
	if (src_mdonly_policy == ondemandPolicyLocal) {
		log_error(lg, "ccow_pin failed: object isn't cacheable");
		return -EPERM;
	}
	if (src_mdonly_policy == ondemandPolicyPersist &&
		(pol == ondemandPolicyPin || pol == ondemandPolicyUnpin)) {
		log_error(lg, "ccow_pin failed: cannot (un)pin a persistent object");
		return -EBADE;
	}
	if (src_mdonly_policy == ondemandPolicyPin && pol == ondemandPolicyPin) {
		log_error(lg, "ccow_pin failed: object is pinned already");
		return -EACCES;
	} else if (src_mdonly_policy == ondemandPolicyUnpin && pol == ondemandPolicyUnpin) {
		log_error(lg, "ccow_pin failed: object is unpinned already");
		return -EACCES;
	} else if (src_mdonly_policy == ondemandPolicyPersist && pol == ondemandPolicyPersist) {
		log_error(lg, "ccow_pin failed: object is persistent already");
		return -EACCES;
	}

	if ((pol == ondemandPolicyPersist || pol == ondemandPolicyPin) &&
		(src_mdonly_policy == ondemandPolicyUnpin)) {
		/* To pin/persist an object it needs to be pre-fetched */
		err = ccow_prefetch(tc, bid, bid_size, oid, oid_size, generation,
			size, chunk_size, CCOW_CONT_F_PREFETCH_TOUCH);
		if (err)
			return err;
	}
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "ccow_pin failed: Completion create error %d", err);
		return err;
	}
	err = ccow_ondemand_policy_change_request(bid, bid_size, oid, oid_size,
		generation, pol, c);
	if (err) {
		ccow_release(c);
		log_error(lg, "ccow_pin failed: ccow_pin_request error %d", err);
		return err;
	}
	return ccow_wait(c, -1);
}

/*
 * Get lock on the object
 *
 * Scope: PUBLIC
 */
int
ccow_lock(ccow_t tc, const char *bid, size_t bid_size,
	  const char *oid, size_t oid_size, struct ccow_obj_lock *ccow_lk)
{
	int err;
	ccow_completion_t c;

	assert(ccow_lk != NULL);
	assert(ccow_lk->lk_mode != 0);

	if (ccow_lk->lk_mode & CCOW_LOCK_SHARED &&
	    ccow_lk->lk_mode & CCOW_LOCK_EXCL)
		return -EINVAL;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	struct iovec iov;
	iov.iov_base = ccow_lk;
	iov.iov_len = sizeof (*ccow_lk);

	err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, c, &iov, 1, 0,
	    CCOW_LOCK, NULL, RD_ATTR_SERIAL_OP);

	if (err)
		ccow_release(c);
	else
		err = ccow_wait(c, -1);

	log_debug(lg, "ccow_lock returning err: %d", err);
	return err;
}

/*
 * Get/Set lock on the object, with range
 *
 * Scope: PUBLIC
 */
int ccow_range_lock(ccow_t tc, const char *bid, size_t bid_size,
    const char *oid, size_t oid_size, uint64_t off, uint64_t len, int mode)
{
	struct iovec iov;
	struct ccow_obj_lock lk;

	memset(&lk, 0, sizeof(lk));
	lk.lk_mode = mode;
	lk.lk_region.off = off;
	lk.lk_region.len = len;
	lk.lk_ref_count = 0;

	iov.iov_base = &lk;
	iov.iov_len = sizeof(iov);

	/* ccow_lock blocks */
	return ccow_lock(tc, bid, strlen(bid) + 1, oid, strlen(oid) + 1, &lk);
}

int
ccow_set_posix_lock(ccow_t tc, const char *bid, size_t bid_size,
    const char *oid, size_t oid_size, struct flock *flk)
{
	/* 0 length means entire file */
	uint64_t req_len = flk->l_len ? flk->l_len : ~0;
	int mode;

	if (flk->l_type & LOCK_NB)
		mode = CCOW_LOCK_NON_BLOCK;

	switch (flk->l_type) {
	case LOCK_SH:
		mode |= CCOW_LOCK_SHARED;
		break;
	case LOCK_EX:
		mode |= CCOW_LOCK_EXCL;
		break;
	case LOCK_UN:
		mode |= CCOW_LOCK_UNLOCK;
		break;
	default:
		break;
	}

	return ccow_range_lock(tc, bid, bid_size, oid, oid_size,
			flk->l_start, req_len, mode);
}

static ccow_default_attr_t
get_attr_type(const char *attr_str)
{
	/* TODO: Add more attr strings */
	if (!strcmp(attr_str, RT_SYSKEY_CHUNKMAP_BTREE_ORDER))
		return CCOW_ATTR_BTREE_ORDER;
	else if (!strcmp(attr_str, RT_SYSKEY_HASH_TYPE))
		return CCOW_ATTR_HASH_TYPE;
	else if (!strcmp(attr_str, RT_SYSKEY_FAILURE_DOMAIN))
		return CCOW_ATTR_FAILURE_DOMAIN;
	else if (!strcmp(attr_str, RT_SYSKEY_REPLICATION_COUNT))
		return CCOW_ATTR_REPLICATION_COUNT;
	else if (!strcmp(attr_str, RT_SYSKEY_TRACK_STATISTICS))
		return CCOW_ATTR_TRACK_STATISTICS;
	else if (!strcmp(attr_str, RT_SYSKEY_IOPS_RATE_LIM))
		return CCOW_ATTR_IOPS_RATE_LIM;
	else if (!strcmp(attr_str, RT_SYSKEY_COMPRESS_TYPE))
		return CCOW_ATTR_COMPRESS_TYPE;
	else if (!strcmp(attr_str, RT_SYSKEY_SYNC_PUT))
		return CCOW_ATTR_SYNC_PUT;
	else if (!strcmp(attr_str, RT_SYSKEY_SELECT_POLICY))
		return CCOW_ATTR_SELECT_POLICY;
	else if (!strcmp(attr_str, RT_SYSKEY_CHUNKMAP_TYPE))
		return CCOW_ATTR_CHUNKMAP_TYPE;
	else if (!strcmp(attr_str, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE))
		return CCOW_ATTR_CHUNKMAP_CHUNK_SIZE;
	else if (!strcmp(attr_str, RT_SYSKEY_CHUNKMAP_BTREE_MARKER))
		return CCOW_ATTR_BTREE_MARKER;
	else if (!strcmp(attr_str, RT_SYSKEY_NUMBER_OF_VERSIONS))
		return CCOW_ATTR_NUMBER_OF_VERSIONS;
	else if (!strcmp(attr_str, RT_SYSKEY_EC_DATA_MODE))
		return CCOW_ATTR_EC_ALGORITHM;
	else if (!strcmp(attr_str, RT_SYSKEY_EC_ENABLED))
		return CCOW_ATTR_EC_ENABLE;
	else if (!strcmp(attr_str, RT_SYSKEY_EC_TRG_POLICY))
		return CCOW_ATTR_EC_TRG_POLICY;
	else if (!strcmp(attr_str, RT_SYSKEY_FILE_OBJECT_TRANSPARANCY))
		return CCOW_ATTR_FILE_OBJECT_TRANSPARANCY;
	else if (!strcmp(attr_str, RT_SYSKEY_OBJECT_DELETE_AFTER))
		return CCOW_ATTR_OBJECT_DELETE_AFTER;
	else if (!strcmp(attr_str, RT_SYSKEY_LOGICAL_SIZE))
		return CCOW_ATTR_LOGICAL_SZ;
	else if (!strcmp(attr_str, RT_SYSKEY_PREV_LOGICAL_SIZE))
		return CCOW_ATTR_PREV_LOGICAL_SZ;
	else if (!strcmp(attr_str, RT_SYSKEY_OBJECT_COUNT))
		return CCOW_ATTR_OBJECT_COUNT;
	else
		return CCOW_ATTR_UNKNOWN;
}

int
modify_attrs(ccow_completion_t c, ccow_lookup_t iter, ccow_op_t optype,
	     ccow_metadata_kv_t attrs[], uint32_t attr_nr)
{
	uint32_t i;
	uint64_t sz = 0, obj_cnt, used = 0;
	uint64_t prev_sz;
	int err = 0;
	int val_sz;
	void *val;
	ccow_default_attr_t atype;
	struct ccow_metadata_kv *kv = NULL;

	if (!c->needs_final_put) {
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
			if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0)
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &sz);
			if (strcmp(kv->key, RT_SYSKEY_OBJECT_COUNT) == 0)
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &obj_cnt);
			if (strcmp(kv->key, RT_SYSKEY_ESTIMATED_USED) == 0)
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &used);
		}
	} else {
		sz = c->logical_sz;
		obj_cnt = c->object_count;
		used = c->used_sz;
	}

	// In this case obj_cnt should be a delta
	/* Modify the attributes */
	for (i = 0; i < attr_nr; i++) {
		kv = attrs[i];
		switch (kv->mdtype) {
		case CCOW_MDTYPE_METADATA:
			if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
				prev_sz = sz;
				uint64_t delta = *(uint64_t *)kv->value;
				if (optype == CCOW_INSERT_MD ||
				    optype == CCOW_INSERT_LIST_WITH_MD) {
					sz += delta;
				} else {
					if (sz < delta) {
						// prevent underflow
						sz = 0;
					} else {
						sz -= delta;
					}
				}
				err = ccow_attr_modify_default(c,
					CCOW_ATTR_LOGICAL_SZ, &sz, NULL);
				if (err == 0)
					err = ccow_attr_modify_default(c,
						CCOW_ATTR_PREV_LOGICAL_SZ, &prev_sz,
						iter);
				log_debug(lg, "New size: %"PRIu64" Old size: %lu", sz, prev_sz);
			} else if (strcmp(kv->key, RT_SYSKEY_OBJECT_COUNT) == 0) {
				uint64_t new_cnt = 0;
				if (optype == CCOW_INSERT_MD ||
				    optype == CCOW_INSERT_LIST_WITH_MD)
					new_cnt = obj_cnt +
						  *(uint64_t *)kv->value;
				else if (optype == CCOW_DELETE_MD ||
					 optype == CCOW_DELETE_LIST_WITH_MD) {
					if (obj_cnt < *(uint64_t *)kv->value) {
						new_cnt = 0;
					} else {
						new_cnt = obj_cnt - *(uint64_t *)kv->value;
					}
				}
				err = ccow_attr_modify_default(c,
					CCOW_ATTR_OBJECT_COUNT, &new_cnt, iter);
				log_debug(lg, "optype: %s new_cnt: %lu old_cnt: %lu",
						ccow_op2str(optype), new_cnt, obj_cnt);
				if (err)
					return err;
			} else if (strcmp(kv->key, RT_SYSKEY_ESTIMATED_USED) == 0) {
				uint64_t new_used = used;
				uint64_t delta_used = *(uint64_t *)kv->value;
				if (optype == CCOW_INSERT_MD ||
				    optype == CCOW_INSERT_LIST_WITH_MD)
					new_used +=  delta_used;
				else if (optype == CCOW_DELETE_MD) {
					if (new_used < delta_used) {
						new_used = 0;
					} else {
						new_used  -= delta_used;
					}
				}
				log_debug(lg, "optype: %s new_used: %lu old_used: %lu, delta_used: %lu",
						ccow_op2str(optype), new_used, used, delta_used);
				err = ccow_attr_modify_default(c, CCOW_ATTR_ESTIMATED_USED, &new_used, iter);
				if (err) {
					return err;
				}
			} else {
				atype = get_attr_type(kv->key);
				assert(atype != CCOW_ATTR_UNKNOWN);
				err = ccow_attr_modify_default(c, atype,
					attrs[i]->value, iter);
			}
			if (err)
				return err;
			break;
		case CCOW_MDTYPE_CUSTOM:
			val = optype == CCOW_DELETE_MD ? NULL : attrs[i]->value;
			val_sz = optype == CCOW_DELETE_MD ? 0 :
				 attrs[i]->value_size;
			err = ccow_attr_modify_custom(c, attrs[i]->type,
						      attrs[i]->key,
						      attrs[i]->key_size,
						      val, val_sz, iter);
			if (err)
				return err;
			break;
		default:
			err = -EINVAL;
			log_notice(lg, "Unsupported metadata type");
			break;
		}
		if (err)
			break;
	}
	return err;
}

int
ccow_put_attrs_unsafe(ccow_t tc, const char *cid, size_t cid_size,
		      const char *tid, size_t tid_size, const char *bid,
		      size_t bid_size, const char *oid, size_t oid_size,
		      ccow_op_t optype, ccow_metadata_kv_t attrs[],
		      uint32_t attr_nr, struct iovec *iov, size_t iovcnt)
{
	int err;
	ccow_completion_t c;
	ccow_lookup_t iter;
	ccow_op_t op = CCOW_INSERT_LIST;

	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	if (err)
		return err;

	/* Fetch the item */
	err = ccow_tenant_get(cid, cid_size, tid, tid_size, bid, bid_size,
			      oid, oid_size, c, NULL, 0, 0, CCOW_GET, &iter);
	if (err) {
		ccow_drop(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		log_error(lg, "Error: %d Failed to GET %s/%s/%s/%s",
				err, cid, tid, bid, oid);
		ccow_drop(c);
		return err;
	}

	err = modify_attrs(c, iter, optype, attrs, attr_nr);
	if (err) {
		ccow_drop(c);
		return err;
	}
	if (optype == CCOW_DELETE_LIST_WITH_MD)
		op = CCOW_DELETE_LIST;

	/* Write the item attributes */
	err = ccow_tenant_put(cid, cid_size, tid, tid_size, bid, bid_size,
			      oid, oid_size, c, iov, iovcnt, 0,
			      op, NULL, 0);
	if (err) {
		log_error(lg, "Failed to PUT %s/%s/%s/%s", cid, tid, bid, oid);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, -1);
	if (iter)
		ccow_lookup_release(iter);
	return err;
}
