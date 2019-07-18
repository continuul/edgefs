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
#include <stdio.h>

#include "rtbuf.h"
#include "ccow-impl.h"
#include "chunk.h"
#include "btree.h"
#include "btreecom.h"

static int
btc_cm_reflist(btc_cm_fetch_ctx_t *ctx, rtbuf_t *chunks)
{
	int err = 0;
	bt_node_t *node   = ctx->pos.node;

	for (int i = 0; i < ctx->pos.node->nr_active; i++) {
		uv_buf_t buf;
		bt_key_val_t *kv = node->key_vals[i];

		btc_data_t *data  = (btc_data_t*) kv->kv_val;
		struct refentry *re = &data->re;

		buf.len  = sizeof(struct refentry);
		buf.base = (void *) re;

		err = rtbuf_add_alloc(chunks, &buf, 1);
		if (err != 0) {
			log_error(lg, "%s: rtbuf_add returned error %d",
			    __FUNCTION__, err);
			rtbuf_destroy(chunks);
			return err;
		}

	}
	return err;
}

/*
 * btc_node_verify
 *
 * verify the correctness of a btree node.  useful for debugging.
 */
static inline void
btc_node_verify(bt_node_t * node)
{
	int i = 0;
	uint8_t mask8 = 0;
	uint32_t mask32 = 0;

	mask8 = ~(BN_FLAG_DIRTY);
	assert((node->bn_flags & mask8) == 0);

	for (i = 0; i < node->nr_active; i++) {
		bt_key_val_t *kv = node->key_vals[i];
		btc_data_t *data  = (btc_data_t*) kv->kv_val;
		struct refentry *re = &data->re;

		if (node->leaf) {
			assert((RT_REF_TYPE(re) == RT_REF_TYPE_NORMAL) ||
			    (RT_REF_TYPE(re) == RT_REF_TYPE_ZEROBLOCK));
		} else {
			assert(RT_REF_TYPE(re) == RT_REF_TYPE_MANIFEST);
		}

	}
}

/*
 * btc_uint512_dump: prints a uint512_t to a buffer.
 * useful for debugging.
 */
char *
btc_uint512_dump(uint512_t *pv)
{
	static char buff[UINT512_BYTES * 2 + 1];
	memset(buff, 0, UINT512_BYTES * 2 + 1);
	uint512_dump(pv, buff, UINT512_BYTES * 2 + 1);
	return buff;
}

/* forward declarations */
static int btc_cm_fetch_by_key(btc_cm_fetch_ctx_t *ctx, int *done);
void btc_destroy(chunkmap_handle_t chm_handle);

static int btc_cm_fetch_cache_hit(btc_cm_fetch_ctx_t *ctx, rtbuf_t *rl, int *done);

static void
btc_put_vmm_done(struct putcommon_client_req *r)
{
	assert(r->io != NULL);
	struct ccow_io *io = r->io;
	assert(io->op != NULL);
	struct ccow_op *op = io->op;

	if (op->status != 0)
		ccow_fail_io(op->namedget_io, op->status);

	assert(r->metadata != NULL);
	assert(r->packed_data == NULL);

	msgpack_pack_free(r->metadata);
	rtbuf_destroy(r->payload);
}

static void
btc_put_cm_done(struct putcommon_client_req *r)
{
	assert(r->io != NULL);
	struct ccow_io *io = r->io;
	assert(io->op != NULL);
	struct ccow_op *op = io->op;

	int status = op->status;

	assert(r->btree != NULL);
	btree_t * btree = r->btree;

	btree->cb_done_cnt++;
	if (status != 0) {
		btree->cb_error_cnt++;
		ccow_fail_io(op->namedget_io, status);
	}

	log_debug(lg, "cb_pending_cnt = %3.3lu : cb_done_cnt = %3.3lu : "
	    "cb_error_cnt = %3.3lu : cb_node_cnt = %3.3lu : "
	    "cb_chnk_cnt = %3.3lu",
	    btree->cb_pending_cnt, btree->cb_done_cnt, btree->cb_error_cnt,
	    btree->cb_node_cnt, btree->cb_chnk_cnt);

	if (status == 0 && btree->cb_pending_cnt == btree->cb_done_cnt) {
		btc_update_get_vm_cb(btree, btree->cb_node, btree->cb_parent,
		    btree->cb_context);
	}

	msgpack_pack_free(r->packed_data);
	rtbuf_destroy(r->payload);
}

void btc_unnamed_get_cb(struct getcommon_client_req *r)
{
	assert(r->io != NULL);
	struct ccow_io *io = r->io;
	assert(io->op != NULL);
	struct ccow_op *op = io->op;
	int status = op->status;

	if (status != 0)
		ccow_fail_io(op->namedget_io, status);
}

void btc_unnamed_put_cb(struct putcommon_client_req *r)
{
	int err;

	assert(r->btree != NULL);
	btree_t * btree = r->btree;
	assert(r->io != NULL);
	struct ccow_io *io = r->io;
	assert(io->op != NULL);
	struct ccow_op *op = io->op;

	int status = op->status;

	btree->cb_done_cnt++;
	if (status != 0) {
		ccow_fail_io(op->namedget_io, status);
		btree->cb_error_cnt++;
	}

	log_debug(lg, "cb_pending_cnt = %3.3lu : cb_done_cnt = %3.3lu : "
	    "cb_error_cnt = %3.3lu : cb_node_cnt = %3.3lu : "
	    "cb_chnk_cnt = %3.3lu",
	    btree->cb_pending_cnt, btree->cb_done_cnt, btree->cb_error_cnt,
	    btree->cb_node_cnt, btree->cb_chnk_cnt);

	if (status == 0 && btree->cb_pending_cnt == btree->cb_done_cnt) {
		btc_update_get_vm_cb(btree, btree->cb_node, btree->cb_parent,
		    btree->cb_context);
	}

	msgpack_pack_free(r->packed_data);
	rtbuf_destroy(r->payload);
}

/**
 * Find and return the index of the node within the parent based on the
 * child pointer.
 */
uint32_t
btc_get_index_from_node(bt_node_t *node, bt_node_t *parent)
{
	int i = 0;

	for (i = 0; i <= parent->nr_active; i++) {
		if (node == parent->children[i])
			break;
	}

	return i;
}

/**
 * Find and return the index of node within the parent based on the
 * key.
 */
uint32_t
btc_get_index_from_key(btree_t *btree, bt_node_t *node, void *key)
{
	int c, j;

	bt_key_val_t kv;
	kv.kv_key = key;
	kv.kv_val = NULL;
	kv.kv_flags = 0;

	c = btree_bin_search(btree, &kv, node, &j);

	if (c == 0) {
		return j;
	} else if ((c == 1) && (j == (node->nr_active - 1))) {
		return j + 1;
	} else {
		return -1;
	}
}

/**
 * Copy the contents of the srs_re to the dst_re.  This needs to be done when
 * entries in the manifest change.
 */
void
btc_copy_refentry(bt_node_t *node, uint32_t index, struct refentry *src_re)
{
	bt_key_val_t *kv = node->key_vals[index];
	btc_data_t *data = (btc_data_t*) kv->kv_val;
	struct refentry *dst_re = &data->re;

	*dst_re = *src_re;
}

/*
 * btc_create_prev_good_vm
 */
static int
btc_create_prev_good_vm(btree_t * btree, bt_node_t * node, void *context)
{
	int err;
	bt_node_t * root = btree->root;
	get_node_cb_context_t *ctx = (get_node_cb_context_t *) context;
	struct btreemap *btc = (struct btreemap *) ctx->hdl;
	struct ccow_op *op = btc->op;
	struct ccow_completion *comp = op->comp;

	if ((node != NULL) && (node->level != (root->level - 1))) {
		/*
		 * don't bother when node is not a direct child of the root.
		*/
		return 0;
	}

	if (btree->cb_error_cnt > 0) {
		/*
		 * don't bother if an error has occured
		 */
		return 0;
	}

	/*
	 * initialize a new, empty, rtbuf
	 */
	rtbuf_t * chunks = rtbuf_init_empty();
	if (chunks == NULL) {
		log_debug(lg, "Memory allocation failure.");
		return -ENOMEM;
	}

	/*
	 * add each keyval in the btree node to the "chunks" rtbuf list
	 * keyval value
	 */
	for (int i = 0; i < root->nr_active; i++) {
		uv_buf_t buf;
		bt_key_val_t *kv = root->key_vals[i];

		btc_data_t *data  = (btc_data_t*) kv->kv_val;
		struct refentry *re = &data->re;

		BT_REF_LEAF_SET(re, root->leaf);
		BT_REF_LEVEL_SET(re, root->level);

		if (root->leaf) {
			RT_REF_HASH_TYPE_SET(re, comp->hash_type);
			RT_REF_TYPE_SET(re, RT_REF_TYPE_NORMAL);
		} else {
			RT_REF_HASH_TYPE_SET(re, HASH_TYPE_DEFAULT);
			RT_REF_TYPE_SET(re, RT_REF_TYPE_MANIFEST);
		}

		buf.len  = sizeof(struct refentry);
		buf.base = (void *) re;

		err = rtbuf_add_alloc(chunks, &buf, 1);
		if (err != 0) {
			log_error(lg, "%s: rtbuf_add returned error %d",
			    __FUNCTION__, err);
			rtbuf_destroy(chunks);
			return err;
		}
	}

	/*
	 * save a reference to the known good vm
	 */
	if (btree->cb_prev_good_vm != NULL)
		rtbuf_destroy(btree->cb_prev_good_vm);

	btree->cb_prev_good_vm = chunks;

	return 0;
}

/*
 * btc_verify_dirty_bit
 *
 * verify dirty bit in node is set for all relevant nodes. intended for redebug
 * only.
 */
static void
btc_verify_dirty_bit(btree_t * btree, uint64_t offset)
{
	bt_node_t * node = btree->root;

	while (1)
	{
		uint8_t dirty = BN_FLAG(node, BN_FLAG_DIRTY);
		assert(dirty == 1);

		if (node->leaf)
			break;

		int i = 0;
		while(i < node->nr_active) {
			uint64_t o = *((uint64_t *) node->key_vals[i]->kv_key);
			if (offset < o)
				break;
			i++;
		}

		assert(i < node->nr_active);
		node = node->children[i];
	}
}

/*
 * btc_leaf_put_chunk
 *
 * do an unnamed put on one of the children of the leaf node.
 *
 */
int
btc_leaf_put_chunk(btree_t *btree, bt_node_t *node, bt_node_t *parent,
    void *context)
{
	int err = 0;

	get_node_cb_context_t *ctx = (get_node_cb_context_t *) context;

	struct btreemap *btc   = (struct btreemap *) ctx->hdl;
	struct ccow_op *op     = btc->op;
	struct ccow_op *cont_op = ctx->cont_op;
	vmpack_cb_t vmpack_cb  = ctx->vmpack_cb;
	cmpack_cb_t cmpack_cb  = ctx->cmpack_cb;
	struct ccow_completion *comp = op->comp;

	/* the node has to be a leaf node */
	assert(node->leaf);

	log_trace(lg, "btree: %p node %p parent %p", btree, node, parent);

	/*
	 * find the index into the node for the current key
	 */

	uint32_t idx;
	idx = btc_get_index_from_key(btree, node, ctx->cur_op_key);

	bt_key_val_t *ow_kv = node->key_vals[idx];
	btc_data_t *ow_data = (btc_data_t*) ow_kv->kv_val;
	struct refentry *ow_re = &ow_data->re;

	void *arg = ctx->ow_cb_arg;
	ctx->ow_cb(ctx->ow_cb_arg, (void *) &ow_re->content_hash_id);

	struct iovec *iov_in = &cont_op->iov_in[ctx->cur_op_idx];

	uint64_t off =*((uint64_t*) ctx->cur_op_key);
	// btc_verify_dirty_bit(btree, off);

	uv_buf_t *chunk = &rtbuf(cont_op->chunks, ctx->cur_op_idx);
	int chunk_comp_type =
		RTBUF_ATTR_COMP_TYPE(rtbuf_attr(cont_op->chunks, ctx->cur_op_idx));
	uint512_t *chid = &cont_op->chids[ctx->cur_op_idx];
	int nonzb = zeroblock_cmp(comp->hash_type, iov_in->iov_len, chid);
	int skip = (comp->cont_flags & CCOW_CONT_F_MDONLY) ||
		(RT_ONDEMAND_GET(cont_op->metadata.inline_data_flags) != ondemandPolicyLocal);

	/* create the io */
	struct ccow_io *up_io;

	assert((ctx->flags & FLAG_GET_NODE_COMMIT) == 0);

	if (nonzb && !skip) {
		err = ccow_unnamedput_create(comp,
					     btc_unnamed_put_cb,
					     op, &up_io, cont_op->namedget_io);
		if (err != 0) {
			log_error(lg, "%s: error returned by ccow_unnamedput_create, "
				  "error = %d \n",
				  __FUNCTION__, err);
			return err;
		}

		up_io->attributes |= RD_ATTR_CHUNK_PAYLOAD;

		struct putcommon_client_req *req = CCOW_IO_REQ(up_io);
		req->hash_type = comp->hash_type;
		req->btree = btree;
		req->chid = *chid;
		req->payload = rtbuf_init_mapped(chunk, 1);

		if (!req->payload) {
			ccow_destroy_io(up_io);
			return -ENOMEM;
		}
	} else {
		btree->cb_done_cnt++;
		if (!skip) {
			log_debug(lg, "ZEROBLOCK, not issuing put");
			comp->tc->stats.ccow.zeroblock_put_hits++;
		}
	}

	// FIXME: single threaded.. so no need to do atomic ops here
	btree->cb_pending_cnt++;
	btree->cb_chnk_cnt++;

	bt_key_val_t *tmp_kv = node->key_vals[idx];
	btc_data_t *tmp_data = (btc_data_t*) tmp_kv->kv_val;
	struct refentry *tmp_re = &tmp_data->re;

	tmp_re->offset = ctx->cur_op_off;

	ctx->cur_op_off += iov_in->iov_len;

	tmp_re->length = iov_in->iov_len;
	tmp_re->compressed_length = chunk->len;

	tmp_re->content_hash_id = *chid;
	BT_REF_MOD_SET(tmp_re, 1);

	RT_REF_COMPRESS_TYPE_SET(tmp_re, chunk_comp_type);
	RT_REF_HASH_TYPE_SET(tmp_re, comp->hash_type);
	if (nonzb)
		RT_REF_TYPE_SET(tmp_re, RT_REF_TYPE_NORMAL);
	else
		RT_REF_TYPE_SET(tmp_re, RT_REF_TYPE_ZEROBLOCK);

	return err;
}

/*
 * btc_update_parent_chid
 *
 * update the chid reference for the node in its parent.
 */
void
btc_update_parent_chid(bt_node_t *node, bt_node_t *parent, uint512_t *chid)
{
	int i;

	if (parent == NULL) return;

	/*
	 *  get the ref-entry of the node within the parent
	 */
	for (i = 0; i < parent->nr_active; i++) {
		if (parent->children[i] == node) {
			break;
		}
	}
	assert(i < parent->nr_active);

	bt_key_val_t *par_kv = parent->key_vals[i];
	assert(par_kv != NULL);

	btc_data_t *par_data = (btc_data_t*) par_kv->kv_val;
	assert(par_data != NULL);

	struct refentry *par_re = &par_data->re;
	assert(par_re != NULL);

	/*
	 * copy the content hash id
	 */
	log_debug(lg, "node = %p : parent = %p : i = %d", node, parent, i);
	uint512_logdump(lg, "par_re->content_hash_id", &par_re->content_hash_id);
	uint512_logdump(lg, "chid", chid);
	if (uint512_cmp(&par_re->content_hash_id, chid) != 0) {
		/*
		 * set the modified bit in the parent refentry for this node
		 */
		BT_REF_MOD_SET(par_re, 1);
	}
	par_re->content_hash_id = *chid;
}

int
btc_get_parent_chid(bt_node_t *node, bt_node_t *parent, uint512_t *chid)
{
	int i;

	if (parent == NULL) return -ENOENT;

	/*
	 *  get the ref-entry of the node within the parent
	 */
	for (i = 0; i < parent->nr_active; i++) {
		if (parent->children[i] == node) {
			break;
		}
	}
	assert(i < parent->nr_active);

	bt_key_val_t *par_kv = parent->key_vals[i];
	assert(par_kv != NULL);

	btc_data_t *par_data = (btc_data_t*) par_kv->kv_val;
	assert(par_data != NULL);

	struct refentry *par_re = &par_data->re;
	assert(par_re != NULL);

	/*
	 * copy the content hash id
	 */
	*chid = par_re->content_hash_id;
	return 0;
}
/*
 * btc_update_get_vm_cb
 *
 * callback for version manifests, called by btc_update_get_node_cb or
 * one of unnamed put callbacks.
 */
int
btc_update_get_vm_cb(btree_t *btree, bt_node_t *node, bt_node_t *parent,
    void *context)
{
	log_trace(lg, "(%p, %p, %p, %p)", btree, node, parent, context);

	int err;
	get_node_cb_context_t *ctx = (get_node_cb_context_t *) context;
	vmpack_cb_t vmpack_cb  = ctx->vmpack_cb;
	cmpack_cb_t cmpack_cb  = ctx->cmpack_cb;
	struct ccow_op *op = btree->cb_op;
	struct ccow_op *cont_op = ctx->cont_op;
	rtbuf_t *chunks = btree->cb_chunks;

	/*
	 * this is the root; it needs to be packaged as a version
	 * manifest.
	 */

	/*
	 * pack the version manifest
	 */
	if (btree->cb_error_cnt > 0) {
		if (btree->cb_chunks) {
			rtbuf_destroy(chunks);
			btree->cb_chunks = NULL;
		}
		chunks = btree->cb_prev_good_vm;
	}

	log_debug(lg, "ctx->flags = %2.2x cb_error_cnt %ld", ctx->flags,
	    btree->cb_error_cnt);

	if (!(ctx->flags & FLAG_GET_NODE_NO_COMMIT) && chunks) {
		err = vmpack_cb(op->namedput_io, chunks);
		if (err != 0) {
			rtbuf_destroy(chunks);
			log_error(lg, "%s: vmpack_cb returned error %d",
			    __FUNCTION__, err);
			return err;
		}
	} else {
		if (op->comp->chunkmap_btree_marker && chunks) {

			if (btree->cb_pending_cnt != btree->cb_done_cnt) {
				return 0;
			}

			/*
			 * FIXME: we need a vmpack like API for the marker
			 * case.
			 */
			char nhid_str[UINT512_BYTES*2+1];
			uint512_dump(&op->name_hash_id, nhid_str,
			    UINT512_BYTES*2+1);

			cont_op->metadata.replication_count = op->metadata.replication_count;

			struct ccow_io *up_io;
			err = ccow_unnamedput_create_detached(cont_op->comp,
			    btc_put_vmm_done, op, &up_io, cont_op->namedget_io);
			if (err != 0) {
				log_error(lg, "%s: error returned by ccow_unnamedput_create_detached, "
				    "error = %d \n",
				    __FUNCTION__, err);
				return err;
			}

			up_io->attributes |= (RD_ATTR_VM_MARKER | RD_ATTR_VERSION_MANIFEST);

			int err = vmpack_cb(up_io, chunks);
			if (err != 0) {
				rtbuf_destroy(chunks);
				log_error(lg, "%s: vmpack_cb returned error %d",
				    __FUNCTION__, err);
				return err;
			}

			struct putcommon_client_req *req = CCOW_IO_REQ(up_io);

			err = rtbuf_hash(req->payload, HASH_TYPE_DEFAULT, &req->chid);
			if (err) {
				log_error(lg, "VMM PUT error while calculating "
				    "payload hash value: %d", err);
				msgpack_pack_free(req->metadata);
				rtbuf_destroy(req->payload);
				return err;
			}

			req->hash_type = HASH_TYPE_DEFAULT;
			req->btree = btree;
			req->ng_chid = op->name_hash_id;

			ccow_start_io(up_io);
		}
	}

	if (btree->cb_chunks) {
		rtbuf_destroy(btree->cb_chunks);
		btree->cb_chunks = NULL;
	}

	return 0;
}

/*
 * btc_update_get_node_cb
 *
 * callback from btree traversal on update. called once for each node in the
 * in-memory btree. nodes will be processed in a depth first manner.
 */
int
btc_update_get_node_cb(btree_t *btree, bt_node_t *node, bt_node_t *parent,
    void *context)
{
	log_trace(lg, "(%p, %p, %p, %p)", btree, node, parent, context);

	int i = 0, err = 0;
	uint64_t k;

	if (node != btree->root) {
		btree->cb_pending_cnt++;
		btree->cb_node_cnt++;
	}

	get_node_cb_context_t *ctx = (get_node_cb_context_t *) context;

	log_debug(lg, "ctx = %p : ctx->flags = 0x%2.2x", ctx, ctx->flags);

	struct btreemap *btc   = (struct btreemap *) ctx->hdl;
	struct ccow_op *op     = btc->op;
	struct ccow_op *cont_op = ctx->cont_op;
	vmpack_cb_t vmpack_cb  = ctx->vmpack_cb;
	cmpack_cb_t cmpack_cb  = ctx->cmpack_cb;
	struct ccow_completion *comp = op->comp;

	/* this btree implementation has all leaf nodes at level 0 */
	if (node->level == 0) assert(node->leaf == TRUE);
	if (node->leaf == TRUE) assert(node->level == 0);
	if (node->level != 0) assert(node->leaf == FALSE);
	if (node->leaf == FALSE) assert(node->level != 0);

	if (node == btc->btree->root) {
		/*
		 * this is the root; it needs to be packaged as a version
		 * manifest ... but first wait for unnamed puts to finish.
		 */

		/*
		 * initialize a new, empty, rtbuf.
		 */
		rtbuf_t *chunks = rtbuf_init_empty();

		/*
		 * add each keyval in the btree node to the root (version
		 * manifest).  note that refentry needs to be constructed from
		 * keyval value
		 */

		for (int i = 0; i < node->nr_active; i++) {
			uv_buf_t buf;
			bt_key_val_t *kv = node->key_vals[i];

			btc_data_t *data  = (btc_data_t*) kv->kv_val;
			struct refentry *re = &data->re;

			if (node->leaf) {
				if (RT_REF_TYPE(re) != RT_REF_TYPE_NORMAL &&
				    RT_REF_TYPE(re) != RT_REF_TYPE_ZEROBLOCK)
					RT_REF_TYPE_SET(re, RT_REF_TYPE_NORMAL);
				RT_REF_HASH_TYPE_SET(re, comp->hash_type);
			} else {
				RT_REF_HASH_TYPE_SET(re, HASH_TYPE_DEFAULT);
				RT_REF_TYPE_SET(re, RT_REF_TYPE_MANIFEST);
			}

			BT_REF_LEAF_SET(re, node->leaf);
			BT_REF_LEVEL_SET(re, node->level);

			buf.len  = sizeof(struct refentry);
			buf.base = (void *) re;

			err = rtbuf_add_alloc(chunks, &buf, 1);
			if (err != 0) {
				log_error(lg, "%s: rtbuf_add returned error %d",
				    __FUNCTION__, err);
				rtbuf_destroy(chunks);
				return err;
			}

			if (node->leaf) {
				log_debug(lg, "ctx->flags = 0x%2.2x", ctx->flags);
				ctx->cur_op_key = kv->kv_key;

				uint64_t off = *((uint64_t*) kv->kv_key);

				if ((ctx->cur_op_off <= off) &&
				    (ctx->cur_op_rem > 0)) {
					err = btc_leaf_put_chunk(btree, node,
					    parent, context);
					if (err != 0) {
						rtbuf_destroy(chunks);
						return err;
					}

					ctx->cur_op_rem--;
					ctx->cur_op_idx++;
				}
			} else {
				RT_REF_HASH_TYPE_SET(re, HASH_TYPE_DEFAULT);
				RT_REF_TYPE_SET(re, RT_REF_TYPE_MANIFEST);
			}
		}

		btree->cb_node = node;
		btree->cb_parent = parent;
		btree->cb_chunks = chunks;
		btree->cb_op = op;

		log_debug(lg, "cb_pending_cnt = %3.3lu : cb_done_cnt = %3.3lu : "
		    "cb_error_cnt = %3.3lu : cb_node_cnt = %3.3lu : "
		    "cb_chnk_cnt = %3.3lu",
		    btree->cb_pending_cnt, btree->cb_done_cnt, btree->cb_error_cnt,
		    btree->cb_node_cnt, btree->cb_chnk_cnt);

		if (btree->cb_pending_cnt == btree->cb_done_cnt) {
			btc_update_get_vm_cb(btree, node, parent, ctx);
		}

		return 0;
	} else {

		assert(node->nr_active >= btc->btree->order);
		assert(node->nr_active <= btc->btree->order * 2);

		/*
		 * this is NOT the root; it needs to be packaged as a chunk
		 * manifest
		 */
		static uint64_t total_cnt = 0;
		static uint64_t dirty_cnt = 0;
		static uint64_t clean_cnt = 0;
		uint8_t dirty = BN_FLAG(node, BN_FLAG_DIRTY);

		total_cnt++;

		if (dirty)
			dirty_cnt++;
		else
			clean_cnt++;
#if 0
		if ((total_cnt % 1000) == 0) {
			printf("_DBG : %s : %s : %d : "
			    "total = %" PRId64 " : "
			    "dirty = %" PRId64 " : "
			    "clean = %" PRId64 " \n",
			    __FUNCTION__, __FILE__, __LINE__,
			    total_cnt, dirty_cnt, clean_cnt);
		}
#endif
		if (!dirty) {
			btree->cb_done_cnt++;
			return 0;
		}

		if (op != cont_op && !comp->chunkmap_btree_marker && !(ctx->flags & FLAG_GET_NODE_COMMIT)) {
			for (int i = 0; i < node->nr_active; i++) {
				uv_buf_t buf;

				bt_key_val_t *kv = node->key_vals[i];
				assert (kv != NULL);

				btc_data_t *data  = (btc_data_t*) kv->kv_val;
				assert(data != NULL);

				if (node->leaf) {
					log_debug(lg, "ctx->flags = 0x%2.2x", ctx->flags);
					ctx->cur_op_key = kv->kv_key;

					uint64_t off = *((uint64_t*) kv->kv_key);

					if ((ctx->cur_op_off <= off) &&
					    (ctx->cur_op_rem > 0)) {
						err = btc_leaf_put_chunk(btree, node,
						    parent, context);
						if (err != 0) {
							return err;
						}

						ctx->cur_op_rem--;
						ctx->cur_op_idx++;
					}
				}
			}
			btree->cb_node = node;
			btree->cb_parent = parent;
			btree->cb_chunks = NULL;
			btree->cb_op = op;
			btree->cb_done_cnt++;
			return 0;
		}

		/* initialize a new, empty, rtbuf */
		rtbuf_t *chunks = rtbuf_init_empty();

		/*
		 * add each keyval in the btree node to the chunk manifest
		 * note that refentry needs to be constructed from keyval value
		 */
		for (int i = 0; i < node->nr_active; i++) {
			uv_buf_t buf;

			bt_key_val_t *kv = node->key_vals[i];
			assert (kv != NULL);

			btc_data_t *data  = (btc_data_t*) kv->kv_val;
			assert(data != NULL);

			struct refentry *re = &data->re;
			assert(re != NULL);

			if (node->leaf) {
				if (RT_REF_TYPE(re) != RT_REF_TYPE_NORMAL &&
				    RT_REF_TYPE(re) != RT_REF_TYPE_ZEROBLOCK)
					RT_REF_TYPE_SET(re, RT_REF_TYPE_NORMAL);
				RT_REF_HASH_TYPE_SET(re, comp->hash_type);
			} else {
				RT_REF_HASH_TYPE_SET(re, HASH_TYPE_DEFAULT);
				RT_REF_TYPE_SET(re, RT_REF_TYPE_MANIFEST);
			}

			buf.len  = sizeof(struct refentry);
			buf.base = (void *) re;

			BT_REF_LEAF_SET(re, node->leaf);
			BT_REF_LEVEL_SET(re, node->level);

			err = rtbuf_add_alloc(chunks, &buf, 1);
			if (err != 0) {
				rtbuf_destroy(chunks);
				log_error(lg, "%s: rtbuf_add returned error %d",
				    __FUNCTION__, err);
				return err;
			}

			if (node->leaf) {
				log_debug(lg, "ctx->flags = 0x%2.2x", ctx->flags);
				ctx->cur_op_key = kv->kv_key;

				uint64_t off = *((uint64_t*) kv->kv_key);

				if ((ctx->cur_op_off <= off) &&
				    (ctx->cur_op_rem > 0)) {
					err = btc_leaf_put_chunk(btree, node,
					    parent, context);
					if (err != 0) {
						rtbuf_destroy(chunks);
						return err;
					}

					ctx->cur_op_rem--;
					ctx->cur_op_idx++;
				}
			} else {
				RT_REF_HASH_TYPE_SET(re, HASH_TYPE_DEFAULT);
				RT_REF_TYPE_SET(re, RT_REF_TYPE_MANIFEST);
			}
		}

		BN_FLAG_CLR(node, BN_FLAG_DIRTY);
		/*
		 * schedule to send chunk as unnamed put I/O
		 */
		log_debug(lg, "op = %p : cont_op = %p", op, cont_op);

		struct ccow_io *up_io;

		if (ctx->flags & FLAG_GET_NODE_COMMIT) {
			/*
			 * finalize case.  namedget may be done at this
			 * point and only namedput is available as
			 * parent.
			 */
			err = ccow_unnamedput_create(comp, btc_put_cm_done,
			    op, &up_io, cont_op->namedput_io);
		} else {
			/*
			 * non-cont case where only namedget may be
			 * used as parent.
			 */
			err = ccow_unnamedput_create(comp, btc_put_cm_done,
			    op, &up_io, cont_op->namedget_io);
		}
		if (err) {
			rtbuf_destroy(chunks);
			return err;
		}

		up_io->attributes |= RD_ATTR_CHUNK_MANIFEST;

		int err = cmpack_cb(up_io, chunks);
		if (err != 0) {
			rtbuf_destroy(chunks);
			log_error(lg, "%s: cmpack_cb returned error %d",
			    __FUNCTION__, err);
			return err;
		}

		log_debug(lg, "up_io = %p : chunks = %p", up_io, chunks);

		/*
		 * update the CHID in the parent ref-entry for this manifest.
		 */
		struct putcommon_client_req *up_req = CCOW_IO_REQ(up_io);
		up_req->btree = btree;

		log_debug(lg, "up_io = %p : up_req = %p", up_io, up_req);
		uint512_logdump(lg, "up_req->chid", &up_req->chid);
		btc_update_parent_chid(node, parent, &up_req->chid);

		BT_CACHE_PUT(op->op_cmcache, &up_req->chid, chunks);
		rtbuf_destroy(chunks);

		err = btc_create_prev_good_vm(btree, node, context);
		if (err != 0) {
			return err;
		}

		btree->cb_node = node;
		btree->cb_parent = parent;
		btree->cb_chunks = NULL;
		btree->cb_op = op;
	}
	return 0;
}

/*
 * btc_traverse_get_node_cb
 *
 * called once per each node in the in-memory btree.  this function is called
 * after the partial btree is constructed in memory.
 */
static int
btc_traverse_get_node_cb(btree_t *btree,
			 bt_node_t *node,
			 bt_node_t *parent,
			 void *context)
{
	int err = 0;
	uint32_t i;
	uint64_t k;

	log_trace(lg, "btree %p parent %p node %p", btree, parent, node);

	// btc_node_verify(node);

	get_node_cb_context_t *ctx = (get_node_cb_context_t *) context;

	struct btreemap *btc   = (struct btreemap *) ctx->hdl;
	struct ccow_op *op     = btc->op;
	struct ccow_op *cont_op = ctx->cont_op;
	vmpack_cb_t vmpack_cb  = ctx->vmpack_cb;
	cmpack_cb_t cmpack_cb  = ctx->cmpack_cb;
	struct ccow_completion *comp = op->comp;

	/*
	 * this btree implementation has all leaf nodes at level 0
	 */
	if (node->level == 0) assert(node->leaf == TRUE);
	if (node->leaf == TRUE) assert(node->level == 0);
	if (node->level != 0) assert(node->leaf == FALSE);
	if (node->leaf == FALSE) assert(node->level != 0);

	if (node->leaf) {
		/*
		 * this is a leaf. a "get" operation is needed for the
		 * required chunks.
		 */
		while (TRUE) {
			struct iovec *iov_in = &cont_op->iov_in[ctx->cur_op_idx];
			DBG_PRINT("ctx->cur_op_off = %"PRIu64"",
			    ctx->cur_op_off);

			int node_idx = btc_get_index_from_key(btree,
			    node, &ctx->cur_op_off);

			DBG_PRINT("ctx->cur_op_off = %"PRIu64" : "
			    "ctx->cur_op_idx = %"PRIu64"",
			    ctx->cur_op_off, ctx->cur_op_idx);

			if (node_idx == node->nr_active) {
				/*
				 * the op key (offset) is greater than all the
				 * keys in the node.  in this case, return and
				 * look for it in subsequent leaf nodes.
				 */
				return 0;
			}

			if (node_idx == -1) {
				/*
				 * this op key (offset) is not found in the
				 * leaf node, ignore this one and proceed with
				 * the next.
				 */
				comp->tc->stats.ccow.thin_read_hits++;
				if (++ctx->cur_op_idx >= cont_op->iovcnt_in) {
					/*
					 * no more op keys (offsets); done
					 */
					DBG_PRINT("ctx->cur_op_idx = %"PRIu64"",
					    ctx->cur_op_idx);
					return 0;
				}
				DBG_PRINT("ctx->cur_op_idx = %"PRIu64"",
				    ctx->cur_op_idx);
				DBG_PRINT("op->iovcnt_in   = %zu",
				    cont_op->iovcnt_in);

				ctx->cur_op_off += iov_in->iov_len;
				continue;
			}

			/*
			 * the key (offset) was found in the node. create an
			 * unnamed get to read the contents.
			 */

			bt_key_val_t *tmp_kv = node->key_vals[node_idx];
			btc_data_t *tmp_data = (btc_data_t*) tmp_kv->kv_val;
			struct refentry *tmp_re = &tmp_data->re;

			/*
			 * create the io
			 */
			if (RT_REF_TYPE(tmp_re) == RT_REF_TYPE_NORMAL) {
				struct ccow_io *get_io;
				struct ccow *tc = op->comp->tc;

				int hit = ccow_ucache_get_uncomp(tc->ucache,
				    &tmp_re->content_hash_id, op,
				    tc->verify_chid, RT_REF_HASH_TYPE(tmp_re),
				    RT_REF_COMPRESS_TYPE(tmp_re), iov_in);
				if (!hit) {
					err = ccow_unnamedget_create(comp, btc_unnamed_get_cb,
					    op, &get_io, cont_op->namedget_io);
					if (err != 0) {
						log_error(lg, "%s: error returned by "
							  "ccow_unnamedget_create, "
							  "error = %d \n",
							  __FUNCTION__, err);
						btc_destroy((chunkmap_handle_t) btc);
						return err;
					}

					get_io->attributes |= RD_ATTR_CHUNK_PAYLOAD;

					/*
					 * get the request to set chid/offset
					 */
					struct getcommon_client_req *req = CCOW_IO_REQ(get_io);

					req->hash_type = comp->hash_type;
					req->compress_type = RT_REF_COMPRESS_TYPE(tmp_re);
					req->chid = tmp_re->content_hash_id;
					req->offset = ctx->cur_op_off;
					req->mchid = uint512_null;
					req->ref = *tmp_re;
					btc_get_parent_chid(node, parent, &req->mchid);
				} else {
					log_debug(lg, "direct ucache hit");
				}
			} else {
				log_debug(lg, "ZEROBLOCK, not issuing get");
				assert(RT_REF_TYPE(tmp_re) == RT_REF_TYPE_ZEROBLOCK);
				memset(iov_in->iov_base, 0, iov_in->iov_len);
				comp->tc->stats.ccow.zeroblock_get_hits++;
			}

			if (++ctx->cur_op_idx == cont_op->iovcnt_in) {
				/*
				 * no more op keys (offsets); done
				 */
				return 0;
			}
			DBG_PRINT("ctx->cur_op_idx = %"PRIu64"",
			    ctx->cur_op_idx);
			DBG_PRINT("op->iovcnt_in   = %zu",
			    cont_op->iovcnt_in);

			assert (ctx->cur_op_idx < cont_op->iovcnt_in);

			ctx->cur_op_off += iov_in->iov_len;
		}
	}

	return err;
}

/*
 * btc_update_fetches_done
 *
 * called when all the fetches for an update have completed.  update the btree
 * with entries from the ops's chunk list.
 */
static int
btc_update_fetches_done(btc_cm_fetch_ctx_t *ctx, int *done)
{
	assert(*done == FALSE);

	chunkmap_handle_t *hdl = ctx->hdl;
	struct btreemap   *btc = (struct btreemap*) hdl;
        struct ccow_op    *op  = btc->op;
        struct ccow_op *cont_op = ctx->cont_op;
	struct ccow_completion *comp = op->comp;
        rtbuf_t *chunks = cont_op->chunks;
        rtbuf_t *rl_root = op->vm_reflist;

	int err = 0;

	log_trace(lg, "cont_op %p", cont_op);

	/*
	 * update the btree by adding entries from the chunk list
	 */

	uint64_t off = cont_op->offset;
	for (uint16_t i = 0; i < chunks->nbufs; i++) {
		struct iovec *iov_in = &cont_op->iov_in[i];
		uv_buf_t *chunk = &rtbuf(chunks, i);
		int chunk_comp_type =
			RTBUF_ATTR_COMP_TYPE(rtbuf_attr(chunks, i));
		uint512_t *chid = &cont_op->chids[i];

		bt_key_val_t *kv = BT_CALLOC(1, sizeof(*kv));
		if (!kv) {
			log_error(lg, "%s: memory allocation failure\n",
				__FUNCTION__);
			btree_destroy(btc->btree);
			BT_FREE(btc);
			return -ENOMEM;
		}

		/*
		 * add new chunk reference
		 */
		btc_data_t *data = BT_CALLOC(1, sizeof(*data));
		if (!data) {
			log_error(lg, "%s: memory allocation failure \n",
				  __FUNCTION__);
			btree_destroy(btc->btree);
			BT_FREE(kv);
			BT_FREE(btc);
			return -ENOMEM;
		}
		struct refentry *re = &data->re;

		re->offset = off;
		re->length = iov_in->iov_len;
		re->compressed_length = chunk->len;
		re->content_hash_id = *chid;

		RT_REF_COMPRESS_TYPE_SET(re, chunk_comp_type);
		RT_REF_HASH_TYPE_SET(re, comp->hash_type);
		if (zeroblock_cmp(comp->hash_type, iov_in->iov_len, chid) != 0)
			RT_REF_TYPE_SET(re, RT_REF_TYPE_NORMAL);
		else
			RT_REF_TYPE_SET(re, RT_REF_TYPE_ZEROBLOCK);

		kv->kv_key = &re->offset;
		assert(kv->kv_val == NULL);
		kv->kv_val = data;

		/*
		 * note: btree_insert_key takes ownership of kv and
		 * responsibility for freeing kv
		 */

		err = btree_insert_key(btc->btree, kv, TRUE);
		if (err != 0) {
			if (err != EEXIST) {
				log_error(lg,
					"%s: btree_insert_key returned error %d \n",
					__FUNCTION__, err);
			}
			btree_destroy(btc->btree);
			BT_FREE(data);
			BT_FREE(kv);
			BT_FREE(btc);
			return -err;
		}

		btc->btree->free_key_val(btc->btree, kv);
		kv = NULL;

		off += iov_in->iov_len;
	}


	if (btc->btree->cb_context == NULL) {
		btc->btree->cb_context =
			je_malloc(sizeof(get_node_cb_context_t));
		if (btc->btree->cb_context == NULL) {
			log_error(lg, "memory allocation failure.");
			btree_destroy(btc->btree);
			return -ENOMEM;
		}
	}

	memset(btc->btree->cb_context, 0 , sizeof(get_node_cb_context_t));
	get_node_cb_context_t *cb = btc->btree->cb_context;

	cb->op            = op;
	cb->cont_op       = cont_op;
	cb->vmpack_cb     = btc->vmpack_cb;
	cb->cmpack_cb     = btc->cmpack_cb;
	cb->hdl           = (chunkmap_handle_t *) btc;
	cb->cur_chunk_idx = 0;
	cb->cur_op_idx    = 0;
	cb->cur_op_off    = cont_op->offset;
	cb->cur_op_rem    = cont_op->chunks->nbufs;
	cb->cur_op_key    = &cont_op->offset;
	cb->flags         = 0;

	cb->ow_cb	  = ctx->ow_cb;
	cb->ow_cb_arg	  = ctx->ow_cb_args;

	if (ctx->flags & FLAG_FETCH_COMMIT)
		cb->flags |= FLAG_GET_NODE_COMMIT;

	if (ctx->flags & FLAG_FETCH_NO_COMMIT)
		cb->flags |= FLAG_GET_NODE_NO_COMMIT;

	err = btree_get_nodes(btc->btree, (void*) cb, btc_update_get_node_cb);
	if (err != 0) {
		log_error(lg, "%s: error returned by btree_get_nodes, error = %d \n",
			  __FUNCTION__, err);
		return err;
	}

	// FIXME: assert(btc->btree->cb_pending_cnt != btc->btree->cb_done_cnt);

	assert(ctx != NULL);
	BT_FREE(ctx);
	*done = TRUE;

	return err;
}

/*
 * btc_traverse_fetches_done
 *
 * all nodes of the subtree required for the get operation have been fetched
 * into memory.  it is now time to traverse that subtree.
 */
static int
btc_traverse_fetches_done(btc_cm_fetch_ctx_t *ctx, int *done)
{
	assert(*done == FALSE);

	chunkmap_handle_t *hdl = ctx->hdl;
	struct btreemap   *btc = (struct btreemap*) hdl;
        struct ccow_op    *op  = btc->op;
        struct ccow_op *cont_op = ctx->cont_op;
	struct ccow_completion *comp = op->comp;
        rtbuf_t *chunks = cont_op->chunks;
        rtbuf_t *rl_root = op->vm_reflist;

	int err = 0;

	if (btc->btree->cb_context == NULL) {
		 btc->btree->cb_context =
			 je_malloc(sizeof(get_node_cb_context_t));
		if (btc->btree->cb_context == NULL) {
			log_error(lg, "memory allocation failure.");
			btree_destroy(btc->btree);
			return -ENOMEM;
		}
	}

	memset(btc->btree->cb_context, 0, sizeof(get_node_cb_context_t));
	get_node_cb_context_t *cb = btc->btree->cb_context;

	cb->op            = op;
	cb->cont_op       = cont_op;
	cb->vmpack_cb     = btc->vmpack_cb;
	cb->cmpack_cb     = btc->cmpack_cb;
	cb->hdl           = (chunkmap_handle_t *) btc;
	cb->cur_chunk_idx = 0;
	cb->cur_op_idx    = 0;
	cb->cur_op_off    = cont_op->offset;
	cb->cur_op_rem    = 0;
	cb->cur_op_key    = &cont_op->offset;
	cb->flags         = 0;

	err = btree_get_nodes(btc->btree, (void*) cb, btc_traverse_get_node_cb);
	if (err != 0) {
		log_error(lg, "%s: error returned by btree_get_nodes, error = %d \n",
			  __FUNCTION__, err);
		return err;
	}

	assert(ctx != NULL);
	BT_FREE(ctx);
	*done = TRUE;

	return err;
}

/*
 * btc_cm_fetch_finish
 *
 * called when the chunk manifest has been either retrieved from cache or
 * read in as a result of a unnamed get request.  this function will perform
 * operations common to both cases, such has loading the btree node from the
 * chunk manifest's reflist.
 */
static int
btc_cm_fetch_finish(btc_cm_fetch_ctx_t *ctx, rtbuf_t * rl, int *done)
{
	assert(ctx != NULL);

	int err = 0;
	uint32_t i = 0;

	struct ccow_op *op = ctx->op;
	struct ccow_op *cont_op = ctx->cont_op;
	struct ccow_io *io = cont_op->namedget_io;
	struct btreemap *btc = (struct btreemap *) ctx->hdl;

	bt_node_t *node = NULL;

	assert(op != NULL);
	assert(cont_op != NULL);
	assert(io != NULL);
	assert(btc != NULL);

	node_pos_t parent = ctx->pos;

	/*
	 * this function is called when the get (fetch) of a chunk manifest has
	 * completed. the tree needs to be updated with a new node based on the
	 * chunk manifest data.
	 */
	assert(rl->nbufs <= (uint32_t) (btc->btree->order * 2));

	if (ctx->type == BTN) {
		if  (rl->nbufs == 0) {
			/*
			 *  special case: leaf nodes may be empty if all the keys have
			 *  been deleted.  in this case, insert an empty node into the
			 *  tree.
			 */
			err = btree_load_kv(btc->btree, parent, &node, 1, 0, NULL);

			log_error(lg, "btree_load_kv err = %d parent.node = %p node = %p",
			    err, parent.node , node);

			if (err != 0) {
				btc_destroy((chunkmap_handle_t) btc);
				ccow_fail_io(io, err);
				return err;
			}
		}
	} else {
		if (cont_op->completed) {
			/*
			 * the only way that this can happen is if the op has
			 * been destroyed, likely due to error.
			 */
			log_error(lg, "operation completed. cont_op->status = %d",
			    cont_op->status);
			assert(cont_op->chunks == NULL);
			return -EIO;
		}

		if(cont_op->chunks == NULL) {
			assert(cont_op->completed);
		}
	}

	/*
	 *  normal case: insert each key from the chunk manifest into the
	 *  b-tree.
	 */
	for (i = 0; i < rl->nbufs; i++) {
		uv_buf_t *buf = &rl->bufs[i];

		assert(buf->base != NULL);
		assert(buf->len == sizeof(btc_data_t));

                struct refentry *re = (struct refentry *) buf->base;
		struct refentry *new_re = NULL;

		bt_key_val_t *kv = BT_CALLOC(1, sizeof(*kv));
		if (!kv) {
			log_error(lg, "%s: memory allocation failure \n",
				  __FUNCTION__);
			btc_destroy((chunkmap_handle_t) btc);
			ccow_fail_io(io, -ENOMEM);
			return -ENOMEM;
		}

		new_re = BT_CALLOC(1, sizeof(struct refentry));
		if (!new_re) {
			log_error(lg, "memory allocation failure");
			btc_destroy((chunkmap_handle_t) btc);
			ccow_fail_io(io, -ENOMEM);
			return -ENOMEM;
		}

		memcpy(new_re, re, sizeof(struct refentry));

		switch (ctx->type) {
		case BTN:
			kv->kv_key = BT_MALLOC(re->compressed_length);
			if (kv->kv_key == NULL) {
				ccow_fail_io(io, -ENOMEM);
				return -ENOMEM;
			}

			memcpy(kv->kv_key, new_re->data, new_re->compressed_length);
			assert(kv->kv_val == NULL);
			kv->kv_val = new_re;
			break;

		case BTM:
			assert(kv->kv_val == NULL);
			kv->kv_key = &new_re->offset;
			kv->kv_val = new_re;
			break;

		default:
			assert(0);
			break;
		}

		err = btree_load_kv(btc->btree, parent, &node,
		    BT_REF_LEAF(re), BT_REF_LEVEL(re), kv);

		log_debug(lg, "btree_load_kv err = %d parent.node = %p node = %p",
		    err, parent.node , node);

		if (err == -EINVAL) {
			/* this node has previously been loaded.  this is a
			 * condition created by parallel reads. */
			je_free(kv);
			kv = NULL;

			je_free(new_re);
			new_re = NULL;

			err = 0;
			break;
		}

		if (err != 0) {
			log_error(lg, "%s: returned error %d \n",
				  __FUNCTION__, err);
			ccow_fail_io(io, err);
			return err;
		}
	}

	/*
	 * it is not known if there are more chunk manifests that
	 * need to be fetched, so try again.
	 */
	switch (ctx->fetch_type) {

	case FETCH_BY_KEY:
		switch (ctx->type) {

		case BTM:
			*done = FALSE;
			err = btc_cm_fetch_by_key(ctx, done);

			if (*done) {
				return 0;
			}

			switch (err) {

			case 0:
				ctx->fetch_type = FETCH_BY_POS;
				break;

			case -EAGAIN:
				ctx->fetch_type = FETCH_BY_KEY;
				break;

			case -ENODATA:
				ctx->fetch_type = FETCH_BY_POS;
				err = 0;
				break;

			default:
				log_error(lg,"btc_cm_fetch_by_key returned error %d", err);
				return err;
				break;
			}
			break;

		case BTN:
			*done = FALSE;
			err = btc_cm_fetch_by_key(ctx, done);

			if (*done) {
				return 0;
			}

			switch (err) {
			case 0:
				ctx->fetch_type = FETCH_BY_POS;
				break;

			case -EAGAIN:
				ctx->fetch_type = FETCH_BY_KEY;
				err = 0;
				break;

			case -ENODATA:
				assert(ctx->fetch_rem == 1);
				ctx->fetch_rem = 0;

				if (ctx->update)
					ctx->fetches_done(ctx, done);
				break;

			default:
				assert(0);
				break;
			};

			break;

		default:
			assert(0);
			break;
		}
		break;

	case FETCH_BY_POS:
		if (ctx->fetch_rem > 0) {
			*done = FALSE;
			err = btc_cm_fetch_by_pos(ctx, done);
		} else {
			if (ctx->update) {
				btc_update_fetches_done(ctx, done);
			} else {
				btc_traverse_fetches_done(ctx, done);
			}
		}
		break;

	default:
		assert(0);
		break;
	}

	if ((err != 0) && (err != 1) && (err != -EAGAIN)) {
		assert(0);
		log_error(lg, "%s: returned error %d \n",
			  __FUNCTION__, err);
		ccow_fail_io(io, err);
	}

	return err;
}

/*
 * btc_cm_fetch_done
 *
 * called with the unnamed get of a chunk manifest (btree node)
 * has completed.  at this point, part of the tree is loaded into memory
 * but there may be more to fetch.
 */
void
btc_cm_fetch_done(struct getcommon_client_req *r)
{
	int err = 0;
	uint32_t i = 0;
	btc_cm_fetch_ctx_t *ctx = (btc_cm_fetch_ctx_t *) r->chunkmap_data;
	struct btreemap *btc = (struct btreemap *) ctx->hdl;
	int done = FALSE;

	FETCH_GET_END(ctx);

	bt_map_type_t map_type = ctx->type;
	assert((map_type == BTM) || (map_type == BTN));

	struct ccow_io *io        = r->io;
	struct ccow_completion *c = io->comp;
	struct ccow_op *op        = ctx->op;
	struct ccow_op *cont_op   = ctx->cont_op;
	node_pos_t parent         = ctx->pos;

	if (c->status == 0) {
		/* success */
		if (cont_op->chunks == NULL) {
			log_error(lg, "cont_op->chunks == NULL \n");
			ccow_fail_io(io, -EIO);
			return;
		}
	} else {
		/* error */
		if (cont_op->chunks != NULL) {
			log_error(lg, "cont_op->chunks != NULL \n");
		}

		log_error(lg, "c->status = %d \n", c->status);
		assert(op->status == c->status);
		ccow_fail_io(op->namedget_io, op->status);
		return;
	}


	/*
	 * if the caller supplied a cm_fetch_done callback then call it.  this
	 * call back is called whenenver a chunk manifest has been read
	 */

	if (ctx->cm_fetch_done != NULL) {
		rtbuf_t *chunks = rtbuf_init_empty();
		err = btc_cm_reflist(ctx, chunks);
		if (err) {
		    log_error(lg, "%s: cm_reflist returned error %d",
		    __FUNCTION__, err);
		    return;
		}
		ctx->cm_fetch_done(chunks, ctx->traverse_cb_data);
		return;
	}

	if ((op->status == 0) && (r->cm_reflist == NULL)) {
		/*
		 *  cm_reflist may be null if the chunk manifest had zero
		 *  ref-entries at the time of the put.  this is a valid
		 *  scenario.
		 */

		r->cm_reflist = rtbuf_init_empty();
		if (r->cm_reflist == NULL) {
			ccow_fail_io(io, -ENOMEM);
			return;
		}
	} else {
		if (op->status != 0) {
			/*
			 * failure status
			 */

			ccow_fail_io(io, op->status);
			return;
		}
	}

	if (map_type == BTM) {
		if ((cont_op->optype == CCOW_GET_CONT) || (op->optype == CCOW_GET)) {
			BT_CACHE_PUT(op->op_cmcache, &r->chid, r->cm_reflist);
		}
	}

	err = btc_cm_fetch_finish(ctx, r->cm_reflist, &done);
	if ((err != 0) && (err != -EAGAIN)) {
		ccow_fail_io(r->io, err);
	}

	rtbuf_destroy(r->cm_reflist);
	r->cm_reflist = NULL;
}

/*
 * btc_cm_fetch_by_pos_done
 *
 * called when the unnamed get of a chunk manifest (btree node) has completed.
 * at this point, part of the tree is loaded into memory, but there may be more
 * to fetch.
 */
static void
btc_cm_fetch_pos_done(struct getcommon_client_req *r)
{
	int err = 0;
	int done = FALSE;
	uint32_t i = 0;
	btc_cm_fetch_ctx_t *ctx = (btc_cm_fetch_ctx_t *) r->chunkmap_data;

	FETCH_GET_END(ctx);

	struct btreemap *btc      = (struct btreemap *) ctx->hdl;
	struct ccow_io *io        = r->io;
	struct ccow_completion *c = io->comp;
	struct ccow_op *op        = ctx->op;
	struct ccow_op *cont_op   = ctx->cont_op;
	node_pos_t parent         = ctx->pos;

	if (op->status != 0) {
		ccow_fail_io(io, -EIO);
		return;
	}

	if (!r->cm_reflist) {
		r->cm_reflist = rtbuf_init_empty();
		if (r->cm_reflist == NULL) {
			ccow_fail_io(io, -ENOMEM);
			return;
		}
	}

	/*
	 *  put the ref-list into the cmcache so that we have a relatively
	 *  persistent copy
	 */
	if ((cont_op->optype == CCOW_GET_CONT) || (op->optype == CCOW_GET)) {
		BT_CACHE_PUT(op->op_cmcache, &r->chid, r->cm_reflist);
	}

	/*
	 * this function is called when the get (fetch) of a chunk manifest has
	 * completed. the tree needs to be updated with a new node based on the
	 * chunk manifest data.
	 */
	bt_node_t *node = NULL;

	for (i = 0; i < r->cm_reflist->nbufs; i++) {
		uv_buf_t *buf = &r->cm_reflist->bufs[i];

		assert(buf->base != NULL);
		assert(buf->len == sizeof(btc_data_t));

		struct refentry *re = BT_CALLOC(1, sizeof(struct refentry));
		if (!re) {
			log_error(lg, "memory allocation failure");
			btc_destroy((chunkmap_handle_t) btc);
			ccow_fail_io(io, -ENOMEM);
			return;
		}
		memcpy(re, buf->base, sizeof(struct refentry));

		bt_key_val_t *kv  = NULL;

		switch (ctx->type) {

		case BTN:
			kv = BT_CALLOC(1, sizeof(*kv));
			if (!kv) {
				log_error(lg, "%s: memory allocation failure \n",
					  __FUNCTION__);
				btc_destroy((chunkmap_handle_t) btc);
				ccow_fail_io(io, -ENOMEM);
				return;
			}

			kv->kv_key = BT_MALLOC(re->compressed_length);
			if (kv->kv_key == NULL) {
				BT_FREE(kv);
				kv = NULL;
				log_error(lg, "%s: memory allocation failure \n",
					  __FUNCTION__);
				btc_destroy((chunkmap_handle_t) btc);
				ccow_fail_io(io, -ENOMEM);
				return;
			}

			memcpy(kv->kv_key, re->data, re->compressed_length);
			assert(kv->kv_val == NULL);
			kv->kv_val = re;
			break;

		case BTM:
			kv = BT_CALLOC(1, sizeof(*kv));
			if (!kv) {
				log_error(lg, "%s: memory allocation failure \n",
					  __FUNCTION__);
				btc_destroy((chunkmap_handle_t) btc);
				ccow_fail_io(io, -ENOMEM);
				return;
			}

			kv->kv_key = &re->offset;
			assert(kv->kv_val == NULL);
			kv->kv_val = re;
			break;

		default:
			assert(0);
			break;
		}

		err = btree_load_kv(btc->btree, parent, &node,
		    BT_REF_LEAF(re), BT_REF_LEVEL(re), kv);

		if (err == -EINVAL) {
			/* this node has previously been loaded.  this is a
			 * condition created by parallel reads. */
			je_free(kv);
			kv = NULL;

			err = 0;
			break;
		}

		if (err != 0) {
			log_error(lg, "%s: returned error %d \n",
				  __FUNCTION__, err);
			ccow_fail_io(io, err);
		}
	}

	/*
	 * it is not known if there are more chunk manifests that
	 * need to be fetched, so try again.
	 */
	if (ctx->fetch_rem > 0) {
		ctx->fetch_type = FETCH_BY_POS;
		err = btc_cm_fetch_by_pos(ctx, &done);
		if (err != 0) {
			log_error(lg, "%s: returned error %d \n",
			    __FUNCTION__, err);
			ccow_fail_io(io, err);
		}

		rtbuf_destroy(r->cm_reflist);
		r->cm_reflist = NULL;

	} else {
		if (ctx->update) {
			btc_update_fetches_done(ctx, &done);
		} else {
			btc_traverse_fetches_done(ctx, &done);
		}
	}
}

/*
 * btc_cm_fetch_by_pos
 *
 * fetches the btree nodes required for the index, as specified in context
 * parameter, from storage (via chunk manifests).  when loading a btree into
 * memory, the first fetch will be done by key, subsequent fetches will be
 * done by the index.  this is done since some implementations of btree
 * (e.g. btree name index) lack the ability to programmitcally calculate the
 * next key value.
 */
int
btc_cm_fetch_by_pos(btc_cm_fetch_ctx_t *ctx, int *done)
{
	assert(ctx != NULL);
	assert(ctx->fetch_rem > 0);
	assert(ctx->fetch_type == FETCH_BY_POS);
	int err = 0;

	while (TRUE) {
		/*
		 * look for the chunk in the tree
		 */
		struct btreemap *btc = (struct btreemap *) ctx->hdl;

		assert(ctx->pos.node != NULL);
		assert(ctx->pos.index < ctx->pos.node->nr_active);

		err = bt_get_node_pos_by_pos(btc->btree, &ctx->pos,
		    &ctx->stack);

		if (err == -EAGAIN) {
			/*
			 * not all needed btree nodes have been fetched into memory.
			 * the missing ones will need to be fetched from chunk
			 * manifests.
			 */
			bt_node_t *node   = ctx->pos.node;
			int index         = ctx->pos.index;

			bt_key_val_t *kv   = node->key_vals[index];
			btc_data_t *data   = (btc_data_t*) kv->kv_val;

			struct refentry *re = &data->re;

			if ((ctx->type == BTM) &&
			    !(node->level == 1 && ctx->update &&
				ccow_ec_timeout_expired(&ctx->op->metadata))) {
				/*
				 * for btree map, look in cache
				 */
				rtbuf_t * rl =  NULL;
				struct ccow_op *op = ctx->op;
				uint512_t chid = re->content_hash_id;
				int is_update = ctx->update;

				BT_CACHE_GET(op->op_cmcache, &chid, &rl, err);

				if (err == 1) {
					assert(rl != NULL);
					err = btc_cm_fetch_cache_hit(ctx, rl, done);
					rtbuf_destroy(rl);
					rl = NULL;
					log_debug(lg, "fetch_by_pos cache hit");
					/* evict overwrite */
					if (is_update)
						BT_CACHE_PUT(op->op_cmcache, &chid, NULL);
					return err;
				} else {
					/*
					 * not found in cache;
					 * fall through to fetch
					 */
					assert(rl == NULL);
				}
			}

			/*
			 * schedule request to get the node (chunk manifest)
			 */
			FETCH_GET_START(ctx);

			struct ccow_io *cm_io;
			err = ccow_unnamedget_create(ctx->op_comp,
			    btc_cm_fetch_pos_done, ctx->op, &cm_io,
			    ctx->cont_op->namedget_io);
			if (err) {
				return err;
			}

			cm_io->attributes |= RD_ATTR_CHUNK_MANIFEST;

			if ((ctx->type == BTM) && (node->level == 1) &&
				ctx->update &&
				ccow_ec_timeout_expired(&ctx->op->metadata)) {
				cm_io->attributes |= RD_ATTR_CM_LEAF_WRITE;
			} else {
				cm_io->attributes &= ~RD_ATTR_CM_LEAF_WRITE;
			}

			struct getcommon_client_req *r = CCOW_IO_REQ(cm_io);

			ctx->fetch_req   = r;
			r->chunkmap_data = ctx;
			r->chid          = re->content_hash_id;
			r->ref           = *re;

			break;

		} else if (err == -ENODATA) {
			/*
			 * all chunks have been fetched.
			 */
			switch (ctx->type) {

			case BTN:
				assert(ctx->fetches_done != NULL);
				err = ctx->fetches_done(ctx, done);
				break;

			case BTM:
				assert(ctx->fetches_done == NULL);

				ctx->fetch_rem = 0;

				if (ctx->update) {
					err = btc_update_fetches_done(ctx, done);
				} else {
					err = btc_traverse_fetches_done(ctx, done);
				};
				break;

			default:
				assert(0);
				break;
			}
			break;

		} else if (err == 0) {
			/*
			 * the subtree for the specified position has been
			 * successfully swapped in.
			 */
			if (--ctx->fetch_rem > 0) {
				/*
				 * there are still chunks to be fetched.
				 * get the next.
				 */
				continue;
			} else {
				/*
				 * all chunks have been fetched.
				 */
				if (ctx->type == BTN) {
					 assert(ctx->fetches_done != NULL);
					 err = ctx->fetches_done(ctx, done);
					 break;
				 }

				if (ctx->update) {
					err = btc_update_fetches_done(ctx, done);
				} else
					err = btc_traverse_fetches_done(ctx, done);
				break;
			}

		} else {
			assert(0);
			log_error(lg, "%s: get_btree_node_pos returned error %d",
			    __FUNCTION__, err);
			return err;
		}
	}

	return err;
}

/*
 * btc_cm_fetch_by_key_done
 *
 * called when the the first key has been processed and all the related parts
 * of the subtree have been build.  subsequent entries will be added based on
 * position and not key.
 */
static int
btc_cm_fetch_by_key_done(struct _btc_cm_fetch_ctx_ *ctx, int *done)
{
	assert(ctx != NULL);
	assert(ctx->hdl != NULL);
	assert(*done == FALSE);

	struct btreemap *btc      = (struct btreemap *) ctx->hdl;
	struct ccow_op *op        = btc->op;
	struct ccow_op *cont_op   = ctx->cont_op;
	struct ccow_completion *c = op->comp;

	int err = 0;

	/*
	 * decrement count of remaining fetches
	 */
	if (ctx->fetch_rem > 0)
		ctx->fetch_rem--;

	if ((ctx->fetch_rem == 0) || (ctx->pos.node == NULL)) {
		/*
		 * all fetches have been completed. call the appropriate
		 * "fetches done" function.
		 */

		if (ctx->update) {
			err = btc_update_fetches_done(ctx, done);
		} else {
			err = btc_traverse_fetches_done(ctx, done);
		}
	} else {
		/*
		 * subsequent fetches will be done based on position, not key.
		 */
		ctx->fetch_type = FETCH_BY_POS;
		err = btc_cm_fetch_by_pos(ctx, done);
	}

	return err;
}

/*
 * btc_cm_fetch_by_key
 *
 * fetches the btree nodes required for the key, as specified
 * in the context parameter, from storage (via chunk manifests).
 */
static int
btc_cm_fetch_by_key(btc_cm_fetch_ctx_t *ctx, int *done)
{
	assert(ctx != NULL);
	assert(ctx->type);

	struct btreemap *btc = (struct btreemap *) ctx->hdl;

	int err;

	while(TRUE) {
		/*
		 * look for the chunk in the tree
		 */
		err = bt_get_node_pos_by_key(btc->btree, ctx->key, &ctx->pos,
		    &ctx->stack, ctx->update, FALSE, FALSE);

		assert(err != -ENOMEM);

		if (err == -EAGAIN) {
			/*
			 * not all needed btree nodes have been fetched into memory.
			 * the missing ones will need to be fetched from chunk
			 * manifests.
			 */

			node_pos_t *parent = &ctx->pos;
			bt_node_t  *node   = ctx->pos.node;
			int index          = ctx->pos.index;
			bt_key_val_t *kv   = node->key_vals[index];
			btc_data_t *data   = (btc_data_t*) kv->kv_val;
			struct refentry *re = &data->re;

			ctx->fetch_type = FETCH_BY_KEY;

			// FIXME: get cache to work for BTN as well ?

			if ((ctx->type == BTM) &&
			    !(node->level == 1 && ctx->update &&
				ccow_ec_timeout_expired(&ctx->op->metadata))) {

				rtbuf_t * rl =  NULL;
				struct ccow_op *op = ctx->op;
				uint512_t chid = re->content_hash_id;
				int is_update = ctx->update;

				BT_CACHE_GET(op->op_cmcache, &chid, &rl, err);

				if (err == 1) {
					assert(rl != NULL);
					err = btc_cm_fetch_cache_hit(ctx, rl, done);
					rtbuf_destroy(rl);
					rl = NULL;
					log_debug(lg, "fetch_by_key cache hit");
					/* evict overwrite */
					if (is_update)
						BT_CACHE_PUT(op->op_cmcache, &chid, NULL);
					return err;
				} else {
					/*
					 * not found in cache;
					 * fall through to fetch
					 */
					assert(rl == NULL);
				}
			}

			/*
			 * schedule request to get the node (chunk manifest)
			 */
			FETCH_GET_START(ctx);

			struct ccow_io *cm_io;
			err = ccow_unnamedget_create(ctx->op_comp,
			    btc_cm_fetch_done, ctx->op, &cm_io,
			    ctx->cont_op->namedget_io);

			if (err) {
				return err;
			}

			cm_io->attributes |= RD_ATTR_CHUNK_MANIFEST;

			if ((ctx->type == BTM) && (node->level == 1) &&
				ctx->update &&
				ccow_ec_timeout_expired(&ctx->op->metadata)) {
				cm_io->attributes |= RD_ATTR_CM_LEAF_WRITE;
			} else {
				cm_io->attributes &= ~RD_ATTR_CM_LEAF_WRITE;
			}

			struct getcommon_client_req *r = CCOW_IO_REQ(cm_io);

			ctx->fetch_req   = r;
			r->chunkmap_data = ctx;
			r->offset        = ctx->off;
			r->chid          = re->content_hash_id;
			r->ref            = *re;

			err = -EAGAIN;

			break;

		} else if (err == -ENODATA) {
			/*
			 * if the caller supplied a fetches_done callback then
			 * call it. this call back is called whenenver all the
			 * chunks have been read
			 */
			if (ctx->fetches_done != NULL) {
				ctx->fetches_done(ctx, done);
				return 0;
			}

			/*
			 * the subtree has completely been swapped in
			 */
			err = btc_cm_fetch_by_key_done(ctx, done);
			break;

		} else if (err == 0) {
			/*
			 * if the caller supplied a fetches_done callback then call it.
			 * this call back is called whenenver all the chunks have been
			 * read
			 */
			if (ctx->fetches_done != NULL) {
				ctx->fetches_done(ctx, done);
				return 0;
			}
			if (ctx->cm_fetch_done != NULL) {
				rtbuf_t *chunks = rtbuf_init_empty();
				err = btc_cm_reflist(ctx, chunks);
				if (err) {
				    log_error(lg, "%s: cm_reflist returned error %d",
				    __FUNCTION__, err);
				    return err;
				}
				ctx->cm_fetch_done(chunks, ctx->traverse_cb_data);
				return 0;
			}

			/* the subtree has completely been swapped in */
			err = btc_cm_fetch_by_key_done(ctx, done);
			break;

		} else {

			log_error(lg, "%s: get_btree_node_pos returned error %d",
			    __FUNCTION__, err);
			return err;
		}
	}

	return err;
}

/*
 * btc_cm_fetch_cache_hit
 *
 * called when the IO to fetch in a chunk manifest is bypassed due to a cache
 * hit.
 */
static int
btc_cm_fetch_cache_hit(btc_cm_fetch_ctx_t *ctx, rtbuf_t * rl, int *done)
{
	int err;
	err = btc_cm_fetch_finish(ctx, rl, done);
	return err;
}

/*
 * btc_cm_fetch
 *
 * fetches the btree nodes required for the key, as specified in the
 * context parameter, from storage (via chunk manifests).  the algorithm first
 * does a single fetch using the key. then the rest of the fetches are done by
 * incrementing pos.
 */
int
btc_cm_fetch(btc_cm_fetch_ctx_t *ctx)
{
	struct btreemap *btc   = (struct btreemap *) ctx->hdl;
	int done = FALSE;

	int err = btc_cm_fetch_by_key(ctx, &done);
	/*
	 * the call to btc_cm_fetch will return to either btn_traverse or
	 * btn_update.  -EAGAIN or -ENODATA should have kicked off a fetch
	 * process in another thread.  complete this call with SUCCESS in that
	 * case.
	 */
	if ((err == -EAGAIN) || (err == -ENODATA)) {
		err = 0;
	}

	return err;
}

/*
 * btc_destroy
 *
 * delete the btree chunk map and associated btree.  free all memory
 */
void
btc_destroy(chunkmap_handle_t chm_handle)
{
	struct btreemap *bt_map = (struct btreemap *) chm_handle;

	if (bt_map->btree != NULL) {
		bt_map->op->vm_leaf = NULL;

		if (bt_map->btree->cb_context != NULL) {
			BT_FREE(bt_map->btree->cb_context);
			bt_map->btree->cb_context = NULL;
		}
		btree_destroy(bt_map->btree);
		bt_map->btree = NULL;
	}

	BT_FREE(bt_map);
}

