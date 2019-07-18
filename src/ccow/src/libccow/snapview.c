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
#include "ccowutil.h"
#include "ccow-impl.h"


/*
 * Handle for snapview objects.
 */
struct ccow_snapview {
	const char *ss_name;		/* Custom Name for Snapshot. */
	size_t ss_name_size;
	const char *sv_tid;		/* Snapview Object. */
	const char *sv_bid;
	const char *sv_oid;
	size_t sv_tid_size;
	size_t sv_bid_size;
	size_t sv_oid_size;
	uint512_t sv_vm_chid;	/* VM-CHID tagged for each object.(BR) */
	uint512_t sv_vm_nhid;	/* VM-NHID tagged for each object.(BR) */
} ccow_snapview;

/*
 * SCOPE: Public
 *
 * Create a snapview object with tid/bid/oid
 * @param sv_hdl snapview handle
 * Take a snapview tid/bid/oid/chid
 * Return zero on success, error otherwise.
 */
int
ccow_snapshot_create(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    const char *name, size_t name_size)
{
	int err;
	struct ccow *tc = tctx;
	struct ccow_snapview *sv = (struct ccow_snapview *)sv_hdl;
	sv_hdl->ss_name = name;
	sv_hdl->ss_name_size = name_size;

	/*
	 * Stage 1 : Tenant Get on the new object and retrieve its VM-CHID.
	 */
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	if (err)
		return err;
	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    bid, bid_size, oid, oid_size, c, NULL, 0, 0, CCOW_GET, NULL);
	if (err) {
		ccow_drop(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		ccow_drop(c);
		return err;
	}

	if (uint512_cmp(&c->vm_content_hash_id, &uint512_null) == 0)
		assert(0);
	uint512_logdump(lg, "found vm_content_hash_id", &c->vm_content_hash_id);

	/*
	 * Stage 2 : call ccow_insert_chid on the SV object with VM-CHID of
	 * input object.
	 */
	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	char buf2[UINT512_BYTES];
	char buf3[UINT512_BYTES];
	struct iovec iov[3];
	/* key */
	iov[0].iov_base = buf;
	iov[0].iov_len = sv_hdl->ss_name_size;
	memcpy(iov[0].iov_base, sv_hdl->ss_name, sv_hdl->ss_name_size);
	/* val */
	iov[1].iov_base = buf2;
	iov[1].iov_len = UINT512_BYTES;
	memcpy(iov[1].iov_base, &c->vm_name_hash_id, UINT512_BYTES);
	/* CHID */
	iov[2].iov_base = buf3;
	iov[2].iov_len = UINT512_BYTES;
	memcpy((char *)iov[2].iov_base, &c->vm_content_hash_id, UINT512_BYTES);

	err = ccow_insert_chid(sv_hdl->sv_bid, sv_hdl->sv_bid_size,
	    sv_hdl->sv_oid, sv_hdl->sv_oid_size, c, iov, 3);
	if (err) {
		ccow_release(c);
		return err;
	}
	err = ccow_wait(c, -1);
	return err;
}


/*
 * Post-Process the unnamed-get payload and reconstruct the VM of this object
 * for processing by the namedput which executes as the next I/O.
 */
static void
clone_unnamed_get_cb(struct getcommon_client_req *r)
{
	struct ccow_op *op = r->io->op;
	struct ccow_completion *c = op->comp;
	struct vmmetadata *md = &op->metadata;

	if (op->status != 0) {
		ccow_release(c);
		return;
	}

	/* Unnamed_get processes the payload */

	/* r->rb now has a copy of the metadata store in op->metadata */
	/* Copy the MD info into the operation */
	c->ver_name = je_calloc(1, sizeof (struct ccow_copy_opts));
	if (!c->ver_name) {
		log_error(lg, "Error allocating c->ver_name");
		ccow_fail_io(r->io, -ENOMEM);
		ccow_release(c);
		return;
	}
	c->ver_name->tid = je_memdup(md->tid, md->tid_size);
	c->ver_name->bid = je_memdup(md->bid, md->bid_size);
	c->ver_name->oid = je_memdup(md->oid, md->oid_size);
	c->ver_name->tid_size = md->tid_size;
	c->ver_name->bid_size = md->bid_size;
	c->ver_name->oid_size = md->oid_size;

	c->ver_rb = rtbuf_clone_bufs(r->rb);
	if (!c->ver_rb) {
		log_error(lg, "Error allocating c->ver_rb");
		ccow_fail_io(r->io, -ENOMEM);
		ccow_release(c);
		return;
	}
	return;
}

/*
 * Grab a CHID from the BT-Name Index, return NULL on error;
 *
 * Scope: PRIVATE
 */
static int
ccow_snapview_get_chid_by_name(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *ss_name, size_t ss_name_size)
{
	int err;
	struct ccow *tc = (struct ccow *)tctx;
	struct ccow_snapview *sv = (struct ccow_snapview *)sv_hdl;

	ccow_lookup_t iter;
	err = ccow_snapshot_lookup(tc, sv, ss_name, ss_name_size, 1, &iter);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		log_warn(lg, "Snapshot %s does not exist!", ss_name);
		return err;
	}

	struct ccow_metadata_kv *kv = NULL;
	kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, 0);
	if (!kv) {
		log_error(lg, "Cannot iterate over snapshot %s metadata, or "
		    "empty snapview", ss_name);
		ccow_lookup_release(iter);
		return -ENOENT;
	}
	assert(kv->type == CCOW_KVTYPE_RAW);
	if (kv->key) {
		if (memcmp_quick(kv->key, kv->key_size, ss_name, ss_name_size) == 0) {
			sv_hdl->sv_vm_chid = *(uint512_t *)kv->chid;
			sv_hdl->sv_vm_nhid = *(uint512_t *)kv->value;
			if (uint512_cmp(&sv_hdl->sv_vm_chid, &uint512_null) == 0)
				assert(0);
			uint512_logdump(lg, "found sv_vm_chid", &sv_hdl->sv_vm_chid);
			ccow_lookup_release(iter);
			return 0;
		}
	}

	ccow_lookup_release(iter);
	return -ENOENT;
}

/*
 * Clone an object from a snapshot handle.
 *
 * Scope: PUBLIC
 */
int
ccow_clone_snapview_object(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *ss_name, size_t ss_name_size, const char *tid_dst,
    size_t tid_dst_size, const char *bid_dst, size_t bid_dst_size,
    const char *oid_dst, size_t oid_dst_size)
{
	int err;
	struct ccow *tc = (struct ccow *)tctx;
	struct ccow_snapview *sv = (struct ccow_snapview *)sv_hdl;

	/*
	 * Phase 1:  unnamed_get on the CHID of the sv_hdl->vm_chid, this will
	 * return a req->payload which is the actual version manifest.
	 */

	err = ccow_snapview_get_chid_by_name(tctx, sv_hdl, ss_name,
	    ss_name_size);
	if (err)
		return err;

	struct ccow_op *ug_op;
	struct ccow_io *get_io;
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	if (err)
		return err;

	c->vm_name_hash_id = sv->sv_vm_nhid;

	err = ccow_operation_create(c, CCOW_CLONE, &ug_op);
	if (err) {
		ccow_drop(c);
		return err;
	}

	err = ccow_unnamedget_create(c, clone_unnamed_get_cb, ug_op, &get_io,
	    NULL);
	if (err) {
		ccow_operation_destroy(ug_op, 1);
		ccow_drop(c);
		log_error(lg, "error returned by ccow_unnamedget_create: %d",
		    err);
		return err;
	}
	ug_op->iov_in = NULL;
	ug_op->iovcnt_in = 0;
	ug_op->offset = 0;

	get_io->attributes |= RD_ATTR_VERSION_MANIFEST;

	struct getcommon_client_req *req = CCOW_IO_REQ(get_io);

	/* Calculated above by ccow_snapview_get_chid_by_name */
	req->ng_chid = sv->sv_vm_nhid;
	req->chid = sv->sv_vm_chid;
	req->offset = 0;

	/*
	 * Phase 2:  post-process the unnamedget payload in the cb and
	 * use this to construct the VM/MD/CM/RL to be passed to the copy
	 * operation.
	 */

	err = ccow_start_io(get_io);
	if (err) {
		ccow_operation_destroy(ug_op, 1);
		ccow_drop(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		ccow_drop(c);
		return err;
	}

	struct ccow_copy_opts copy_opts;
	copy_opts.tid = (char *)tid_dst;
	copy_opts.bid = (char *)bid_dst;
	copy_opts.oid = (char *)oid_dst;
	copy_opts.tid_size = tid_dst_size;
	copy_opts.bid_size = bid_dst_size;
	copy_opts.oid_size = oid_dst_size;
	copy_opts.genid = NULL;
	copy_opts.version_uvid_timestamp = 0;
	copy_opts.version_vm_content_hash_id = NULL;

	/* gather tid/bid/oid/src from the payload*/
	char *tid_src = c->ver_name->tid;
	char *bid_src = c->ver_name->bid;
	char *oid_src = c->ver_name->oid;
	size_t tid_src_size = c->ver_name->tid_size;
	size_t bid_src_size = c->ver_name->bid_size;
	size_t oid_src_size = c->ver_name->oid_size;

	/* In case of Rollback we've passed NULL/NULL/NULL, so use the same
	 * tid/bid/oid as the src which is completed by the ccow_wait on UG. */
	if (!tid_dst && !bid_dst && !oid_dst) {
		copy_opts.tid = tid_src;
		copy_opts.tid_size = tid_src_size;
		copy_opts.bid = bid_src;
		copy_opts.bid_size = bid_src_size;
		copy_opts.oid = oid_src;
		copy_opts.oid_size = oid_src_size;
	}
	/* Issue Clone! */
	err = ccow_clone(c, tid_src, tid_src_size, bid_src, bid_src_size,
	    oid_src, oid_src_size, &copy_opts);
	if (err) {
		ccow_release(c);
		log_error(lg, "CCOW_CLONE scheduling failure: %d", err);
		return err;
	}

	err = ccow_wait(c, 1);
	if (err) {
		log_error(lg, "snapview_clone returned failure: %d", err);
		return err;
	}

	return 0;
}

/*
 * SCOPE: Public
 *
 * Rollback an object to the version specified as CHID in Snapview.
 * Returns zero on success, error otherwise.
 */
int
ccow_snapshot_rollback(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *ss_name, size_t ss_name_size)
{
	/* Get the CHID via get_list() */
	/* sv_hdl->vm_chid = CHID */
	return ccow_clone_snapview_object(tctx, sv_hdl, ss_name, ss_name_size,
	    NULL, 0, NULL, 0, NULL, 0);
}

/*
 * SCOPE: Public
 *
 * Create a snapview object with tid/bid/oid
 * @param sv_hdl snapview handle
 * @param sv_bid snapview bucket object name
 * @param sv_bid_size snapview bucket object name size
 * @param sv_oid snapview object name
 * @param sv_oid_size snapview object name size
 * Return zero on success, error otherwise.
 */
int
ccow_snapview_create(ccow_t tctx, ccow_snapview_t *sv_hdl,
    const char *sv_bid, size_t sv_bid_size, const char *sv_oid, size_t sv_oid_size)
{
	int err;
	struct ccow *tc = tctx;
	struct ccow_snapview *sv = je_malloc(sizeof(struct ccow_snapview));
	if (!sv)
		return -ENOMEM;
	/* Create the new SV Object */
	sv->sv_bid = sv_bid;
	sv->sv_bid_size = sv_bid_size;
	sv->sv_oid = sv_oid;
	sv->sv_oid_size = sv_oid_size;

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		je_free(sv);
		return err;
	}

	/* create new+empty snapview object with key-value type */
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
	if (err) {
		je_free(sv);
		return err;
	}

	uint16_t flags = RT_INLINE_DATA_TYPE_SNAPVIEW;
	err = ccow_attr_modify_default(c, CCOW_ATTR_INLINE_DATA_FLAGS,
	    (void *)&flags, NULL);
	if (err) {
		je_free(sv);
		return err;
	}

	/* we keep only one version of snapview object to make sure
	 * space reclaimed on snapshot delete */
	uint16_t num_vers = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	if (err) {
		je_free(sv);
		return err;
	}

	/* we can change snapview btree order for test purpose */
	const char* btree_order_str = getenv("NEDGE_SV_BTREE_ORDER");
	if (btree_order_str) {
		uint16_t order = 0;
		int n = sscanf(btree_order_str, "%"SCNu16, &order);
		if (n == 1 && RT_SYSVAL_CHUNKMAP_BTREE_ORDER_DEFAULT >= order
			&& order >= 4) {
			err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
			    (void *)&order, NULL);
			if (err) {
				je_free(sv);
				return err;
			}
		}
	}

	err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    sv->sv_bid, sv->sv_bid_size, sv->sv_oid, sv->sv_oid_size, c, NULL,
	    0, 0, CCOW_PUT, NULL, RD_ATTR_NO_OVERWRITE);
	if (err) {
		ccow_release(c);
		je_free(sv);
		return err;
	}

	*sv_hdl = sv;
	err = ccow_wait(c, 0);
	if (err && err != -EEXIST) {
		log_error(lg, "Cannot create snapview object: %d", err);
	}
	return err;
}


/*
 * SCOPE: Public
 *
 * Delete a snapshot from within a snapview object.
 * @param sv_hdl snapview handle
 * @param name name of the snapshot to delete
 * @param name_size name size in bytes
 * Return zero on success, error otherwise.
 */
int
ccow_snapshot_delete(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *name, size_t name_size)
{
	int err;
	struct ccow *tc = tctx;
	struct ccow_snapview *sv = (struct ccow_snapview *)sv_hdl;

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	struct iovec iov = { .iov_base = buf };
	memcpy(iov.iov_base, name, name_size);
	iov.iov_len = name_size;
	err = ccow_tenant_put(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    sv_hdl->sv_bid, sv_hdl->sv_bid_size, sv_hdl->sv_oid,
	    sv_hdl->sv_oid_size, c, &iov, 1, 0, CCOW_DELETE_LIST, NULL, 0);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	return err;
}

/*
 * SCOPE: Public
 *
 * Destroy a snapview handle.
 * @param sv_hdl snapview handle
 * Return zero on success, error otherwise.
 */
void
ccow_snapview_destroy(ccow_t tctx, ccow_snapview_t sv_hdl)
{
	assert(sv_hdl);
	je_free(sv_hdl);
	return;
}

/*
 * SCOPE: Public
 *
 * List the stored contents of a snapview.
 * @param sv_hdl snapview handle
 * Return zero on success, error otherwise.
 */
int
ccow_snapshot_lookup(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *pattern, size_t p_size, size_t count, ccow_lookup_t *iter)
{
	assert(sv_hdl);

	int err;
	struct ccow *tc = tctx;
	ccow_completion_t c;

	if (pattern && p_size == 0)
		return -EINVAL;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	struct iovec iov = { .iov_base = buf };
	memcpy(iov.iov_base, pattern, p_size);
	iov.iov_len = p_size;
	err = ccow_get_list(sv_hdl->sv_bid, sv_hdl->sv_bid_size, sv_hdl->sv_oid,
	    sv_hdl->sv_oid_size, c, &iov, 1, count, iter);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, -1);
	if (err) {
		if (iter && *iter) {
			ccow_lookup_release(*iter);
			*iter = NULL;
		}
		log_error(lg, "Error while reading snapview object %d", err);
	}
	return err;
}


/*
 * SCOPE: Public
 *
 * Delete a snapview object, and all snapshots within it.
 * @param sv_hdl snapview handle
 * Return zero on success, error otherwise.
 */
int
ccow_snapview_delete(ccow_t tctx, ccow_snapview_t sv_hdl)
{
	int err;
	struct ccow *tc = tctx;
	struct ccow_snapview *sv = (struct ccow_snapview *)sv_hdl;

	/*
	 * Phase 1: Mark the SV_obj deleted.
	 */
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;
	err = ccow_delete(sv_hdl->sv_bid, sv_hdl->sv_bid_size, sv_hdl->sv_oid,
	    sv_hdl->sv_oid_size, c);
	if (err) {
		ccow_release(c);
		return err;
	}
	return ccow_wait(c, 0);
}

