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

#include "rtbuf.h"
#include "ccow-impl.h"
#include "chunk.h"
#include "btree.h"
#include "btreecom.h"
#include "btreemap.h"

void btm_destroy(chunkmap_handle_t chm_handle);

uint64_t
btreemap_btree_value(void * key)
{
	return *((uint64_t *)key);
}

uint64_t
btreemap_btree_keysize(void * key)
{
	return sizeof(uint64_t);
}

uint64_t
btreemap_btree_datasize(void * data)
{
	return sizeof(uint64_t);
}

/*
 * Free the memory associated with the key-val.
 */
static int btreemap_free_key_val(btree_t *btree, bt_key_val_t *kv)
{
	if (kv->kv_val != NULL) {
		BT_FREE(kv->kv_val);
	}
	BT_FREE(kv);
	return 0;
}

/*
 * Allocate memory for key-val and data for the destination.  Then copy source
 * to the destination.
 */
static int
btreemap_copy_key_val(btree_t *btree, bt_key_val_t *src, bt_key_val_t **dst)
{
	int err = 0;
	bt_key_val_t *dst_kv = NULL;
	btm_data_t *src_val = NULL;
	btm_data_t *dst_val = NULL;

	if (*dst != NULL) {
		btreemap_free_key_val(btree, *dst);
		*dst = NULL;
	}

	*dst = BT_CALLOC(1, sizeof(bt_key_val_t));
	if (*dst == NULL)
		return -ENOMEM;

	dst_kv = *dst;

	assert(dst_kv->kv_val == NULL);
	dst_kv->kv_val = BT_CALLOC(1, sizeof(btm_data_t));
	if (dst_kv->kv_val == NULL) {
		BT_FREE(*dst);
		*dst = NULL;
		return -ENOMEM;
	}

	dst_val = dst_kv->kv_val;
	src_val = src->kv_val;

	bcopy(src_val, dst_val, sizeof(btm_data_t));

	assert(dst_kv->kv_key == NULL);
	dst_kv->kv_key = &dst_val->re.offset;
	dst_kv->kv_flags = src->kv_flags;

	return err;
}

/**
* Compare two keys.
*/
int
btreemap_cmp_keys(void *key1, void *key2)
{
	uint64_t k1 = *((uint64_t*) key1);
	uint64_t k2 = *((uint64_t*) key2);

	if (k1 < k2) return -1;
	if (k1 > k2) return  1;
	return 0;
}

/*
 * btm_copy_val
 */
static int
btm_copy_val(void *dst, void *src)
{
	memcpy(dst, src, sizeof(struct refentry));
	return 0;
}

/*
 * btm_copy_key
 *
 * copy a key
 */
int
btm_copy_key(void **dst, void *src)
{
	uint64_t *d64 = *dst;
	uint64_t s64  = *((uint64_t *) src);

	*d64 = s64;
	return 0;
}

/*
 * btm_print_key
 *
 * print a key
 */
static char *
btm_print_key(void *key, int prt)
{
	static char buf[640];

	sprintf(buf, "%"PRIu64"", *((uint64_t *) key));

	if (prt) {
		printf( "%s", buf);
	}

	return buf;
}

/*
 * btm_print_val
 *
 * print a val (from a key-val pair)
 */
static void
btm_print_val(void *val)
{
	btm_data_t *data = val;
	struct refentry *re = &data->re;

	char buf[256];
	memset(buf, 0, 256);
	uint512_dump(&re->content_hash_id, buf, 256);

	printf( "{0x%2.2x, %s}", re->map_attr, buf);
}

/*
 * btm_free_node
 *
 * free all memory associated with btree node.
 */
static int
btm_free_node(struct _btree_ *btree, bt_node_t *node, node_pos_t parent_pos)
{
	int i, err = 0;
	uv_buf_t buf;

	struct btreemap *btm = btree->btcm;
	assert(btm != NULL);
	struct ccow_op *op = btm->op;
	assert(op != NULL);

	for (i = 0; i < node->nr_active; i++) {
		btreemap_free_key_val(btree, node->key_vals[i]);
		node->key_vals[i] = NULL;
	}

	BT_FREE(node->key_vals);
	BT_FREE(node->children);
	BT_FREE(node);

	assert(err == 0);
	return err;
}

void btm_unnamed_get_cb(struct getcommon_client_req *r)
{
}

void btm_unnamed_put_cb(struct putcommon_client_req *r)
{
}

/*
 * Find and return the index of the node within the parent based on the
 * child pointer.
 */
uint32_t
btreemap_get_index_from_node(bt_node_t *node, bt_node_t *parent)
{
	int i = 0;

	for (i = 0; i <= parent->nr_active; i++) {
		if (node == parent->children[i])
			break;
	}

	return i;
}

/*
 * Find and return the index of node within the parent based on the
 * offset.
 */
uint32_t
btreemap_get_index_from_offset(bt_node_t *node, uint64_t offset)
{
	int i = 0;
	for (i = 0; i < node->nr_active - 1; i++) {
		if (offset > *((uint64_t *) node->key_vals[i]->kv_key))
			continue;
		else
			break;
	}
	return i;
}

/*
 * Copy the contents of the srs_re to the dst_re.  This needs to be done when
 * entries in the manifest change.
 */
void
btreemap_copy_refentry(bt_node_t *node, uint32_t index, struct refentry *src_re)
{
	bt_key_val_t *kv = node->key_vals[index];
	btm_data_t *data = (btm_data_t*) kv->kv_val;
	struct refentry *dst_re = &data->re;

	*dst_re = *src_re;
}

/*
 * btm_create
 *
 * call the btc_create function to create a btree chunk map of type
 * BTM_TYPE_MAP.
 */
CCOW_EI_TAG_DEFINE(btm_create_01, 1);

int
btm_create(struct ccow_op *op, vmpack_cb_t vmpack_cb,
	cmpack_cb_t cmpack_cb, chunkmap_handle_t *hdl)
{
	rtbuf_t *rl_root = op->vm_reflist;
	struct ccow_completion *comp = op->comp;

	uint16_t order = op->metadata.chunkmap_btree_order;
	int err = 0;

	struct btreemap *btm = BT_CALLOC(1, sizeof (*btm));
	CCOW_EI_TAG_ALLOC_INC(btm_create_01, btm);

	if (!btm) {
		log_error(lg, "%s: failed to allocate betreemap structure \n",
		    __FUNCTION__);
		return -ENOMEM;
	}
	btm->type = BTM_TYPE_MAP;

	btm->op = op;
	btm->vmpack_cb = vmpack_cb;
	btm->cmpack_cb = cmpack_cb;

	if (rl_root->nbufs > order) {
		log_error(lg, "btreemap_create: nbufs in root (%zu) exceeds btree "
		    "order (%d) \n", rl_root->nbufs, order);
		assert(0);
	}

	/* create the in-memory btree data structure. adjust for the order of
	 * the in-memory btree being defined as 1/2 the fannout. */
	btm->btree = btree_create(order/2);

	if (!btm->btree) {
		log_error(lg, "%s: failed to create btree data structure \n",
		    __FUNCTION__);
		BT_FREE(btm);
		return -ENOMEM;
	}

	btm->btree->copy_val     = btm_copy_val;
	btm->btree->copy_key     = btm_copy_key;
	btm->btree->copy_key_val = btreemap_copy_key_val;
	btm->btree->free_key_val = btreemap_free_key_val;
	btm->btree->cmp_keys     = btreemap_cmp_keys;
	btm->btree->print_key    = btm_print_key;
	btm->btree->print_val    = btm_print_val;
	btm->btree->free_node    = btm_free_node;
	btm->btree->btcm	 = btm;

	/* populate the root node of the btree with the data from the version
	   manifest (a.k.a. the root) */
	bt_node_t *node = NULL;

	assert(rl_root->nbufs <= order);

	int leaf  = TRUE;
	int level = 0;
	for (uint16_t i = 0; i < rl_root->nbufs; i++) {
		/* allocate a btm data structure, which will contain refentry
		 * and other data*/
		btm_data_t *data = BT_CALLOC(1, sizeof(*data));

		if (!data) {
			log_error(lg, "%s: memory allocation failure \n",
			    __FUNCTION__);
			btm_destroy((chunkmap_handle_t) btm);
			return -ENOMEM;
		}

		/* bt_key_val_t will contain pointers to the key (chid)
		 * and value (btm_data_t) */
		bt_key_val_t *kv = BT_CALLOC(1, sizeof(*kv));
		if (!kv) {
			log_error(lg, "%s: memory allocation failure \n",
			    __FUNCTION__);
			BT_FREE(data);
			btm_destroy((chunkmap_handle_t) btm);
			return -ENOMEM;
		}

		/* the rtbuf entry will be a refentry within the rl_root, this
		 * refentry will be written to the btree root in the version
		 * manifest */
		struct refentry *re = (struct refentry *) rtbuf(rl_root, i).base;
		data->re = *re;

		leaf  = BT_REF_LEAF(re);
		level = BT_REF_LEVEL(re);

		/* note: btree_insert_key and/or btree_load_kv take ownership of
		 * kv and responsibility for freeing kv */
		kv->kv_key = &re->offset;
		assert(kv->kv_val == NULL);
		kv->kv_val = data;

		node_pos_t parent = {.node = NULL, .index = i};

		err = btree_load_kv(btm->btree, parent, &node, leaf,
		    level, kv);
		if (err != 0) {
			log_error(lg, "%s: failed to insert btree key, err = %d",
			    __FUNCTION__, err);
			BT_FREE(data);
			BT_FREE(kv);
			btm_destroy((chunkmap_handle_t) btm);
			return err;
		}

		/* the btree takes ownership of the kv */
		kv = NULL;
		btm->op->vm_leaf = (int*)&btm->btree->root->leaf;
	}

	*hdl = btm;
	return 0;
}

/*
 * btm_traverse
 *
 * called when a get request has been issued.  fetch enough of the
 * tree to cover the request.
 */
int
btm_traverse(chunkmap_handle_t chm_handle, struct ccow_op *cont_op,
	     bt_traverse_done_cb_t traverse_cb, void *traverse_cb_data)
{
	int err;
	struct btreemap *btm = (struct btreemap*) chm_handle;
	struct ccow_op *op = btm->op;
	struct ccow_completion *comp = op->comp;

	nassert(comp->tc->loop_thrid == uv_thread_self());

	if (!cont_op)
		cont_op = op;

	if (cont_op->completed) {
		log_error(lg, "btm_traverse called on completed op. "
		    "cont_op = %p", cont_op);
		return -EBADF;
	}

	if (!cont_op->chunks) {
		log_error(lg, "cont_op has NULL chunks."
		    "cont_op = %p", cont_op);
		return -EBADF;
	}

	DBG_PRINT("MAP : TRAVERSE : op = %p : op->offset = %"PRIu64" : "
	    "cont_op = %p : cont_op->offset = %"PRIu64"", op, op->offset,
	    cont_op, cont_op->offset);

	rtbuf_t *op_chunks = cont_op->chunks;

	btc_cm_fetch_ctx_t *ctx = BT_CALLOC(1, sizeof(*ctx));
	if (ctx == NULL) {
		log_error(lg, "%s: memory allocation failure \n",
		    __FUNCTION__);
		btm_destroy((chunkmap_handle_t) btm);
		return -ENOMEM;
	}

	/*
	 * fill in the context structure
	 */

	ctx->hdl       = chm_handle;
	ctx->type      = BTM;
	ctx->pos.node  = NULL;
	ctx->pos.index = 0;
	ctx->op        = op;
	ctx->op_comp   = comp;
	ctx->btc_cm_fetch_done = NULL;
	ctx->update     = 0;
	ctx->op_buf_idx = 0;
	ctx->nbufs      = op_chunks->nbufs;
	ctx->cont_op    = cont_op;
	ctx->fetch_rem  = op_chunks->nbufs;
	ctx->key        = &cont_op->offset;
	ctx->cm_fetch_done  = traverse_cb;
	ctx->traverse_cb_data = traverse_cb_data;

	err = btc_cm_fetch(ctx);
	if ((err != 0) && (err != 1)) {
		log_error(lg, "%s: btc_cm_fetch returned error %d \n",
		    __FUNCTION__, err);
		return err;
	}

	return 0;
}

static int
btc_cm_leaf_remove_cb(struct _btree_ *btree,      // Callback for node iteration
			   bt_node_t *node,
			   bt_node_t *parent,
			   void *context) {
	if (!parent || !node->leaf)
		return 0;
	for (int i = 0; i < parent->nr_active; i++) {
		if(parent->children[i] == node) {
			node_pos_t pos = { .node = parent, .index = i};
			btree_destroy_node(btree, node, pos);
			parent->children[i] = NULL;
			break;
		}
	}
	return 0;
}

/*
 * btm_update
 *
 * called when put is requested on an object mapped by a btreemap
 * chunk map.
 *
 * Usage:
 *
 * Case 1. Immediate commit:
 *
 * update & commit: btm_update(hdl, NULL)
 *
 * Case 2. Cont update/read with following commit:
 *
 * update: btm_update(hdl, cont_op)
 * update: btm_traverse(hdl, cont_op)
 * update: btm_update(hdl, cont_op)
 * commit: btm_update(hdl, btm->op)
 */
CCOW_EI_TAG_DEFINE(btm_update_01, 1);
CCOW_EI_TAG_DEFINE(btm_update_02, 1);

int
btm_update(chunkmap_handle_t chm_handle, struct ccow_op *cont_op,
    bt_overwrite_cb ow_cb, void *ow_cb_args)
{
	int err;

	log_debug(lg, "btm_update : chm__handle = %p", chm_handle);
	assert(chm_handle != NULL);

	struct btreemap *btm         = (struct btreemap*) chm_handle;
	struct ccow_op *op           = btm->op;
	struct ccow_completion *comp = op->comp;

	nassert(comp->tc->loop_thrid == uv_thread_self());

	if (cont_op != op) {
		if (cont_op != NULL) {
			DBG_PRINT("MAP : UPDATE : op = %p : op->offset = %"PRIu64" : "
			    "cont_op = %p : cont_op->offset = %"PRIu64"", op, op->offset,
			    cont_op, cont_op->offset);
		} else {
			DBG_PRINT("MAP : UPDATE : op = %p : op->offset = %"PRIu64"",
			    op, op->offset);
		}

		/*
		 * Case 1:
		 *	FETCH/PUT AND COMMIT
		 *
		 * Case 2:
		 *	FETCH ONLY AND PUT PAYLOAD CHUNKS
		 */
		btc_cm_fetch_ctx_t *ctx = BT_CALLOC(1, sizeof(*ctx));
		CCOW_EI_TAG_ALLOC_INC(btm_update_01, ctx);

		if (ctx == NULL) {
			log_error(lg, "%s: memory allocation failure \n",
			    __FUNCTION__);
			return -ENOMEM;
		}

		if (cont_op == NULL) {
			/* Case 1. */
			cont_op = op;
			ctx->flags = 0;
		} else {
			/* Case 2. */
			ctx->flags = FLAG_FETCH_NO_COMMIT;
		}

		/* fill in the context structure */
		ctx->hdl       = chm_handle;
		ctx->type      = BTM;
		ctx->pos.node  = NULL;
		ctx->pos.index = 0;
		ctx->op        = op;
		ctx->op_comp   = comp;
		ctx->btc_cm_fetch_done = NULL;
		ctx->update     = 1;
		ctx->op_buf_idx = 0;
		ctx->nbufs      = cont_op->chunks->nbufs;
		ctx->cont_op    = cont_op;
		ctx->fetch_rem  = cont_op->chunks->nbufs;
		ctx->key        = &cont_op->offset;

		ctx->ow_cb	= ow_cb;
		ctx->ow_cb_args	= ow_cb_args;

		if (!(comp->cont_flags & CCOW_CONT_F_REPLACE) &&
			!ctx->flags &&
			ccow_ec_timeout_expired(&op->metadata)) {
			/*
			 * On a EC-protected object overwrite we need to restore
			 * number of replicas of data chunks whose manifest
			 * are about to be replaced. For that, we use an unnamed
			 * put with RD_ATTR_CM_LEAF_WRITE attribute set.
			 * Since the btree might have those manifests pre-fetched,
			 * we going to remove corresponding leaf nodes before
			 * the commit.
			 */
			btree_get_nodes(btm->btree, NULL, btc_cm_leaf_remove_cb);
		}
		err = btc_cm_fetch(ctx);
		CCOW_EI_TAG_INC(btm_update_02, err, -EIO);

		if ((err != 0) && (err != 1)) {
			log_error(lg, "%s: btc_cm_fetch returned error %d \n",
			    __FUNCTION__, err);
			return err;
		}

	} else {
		/*
		 * Case 2: NamedPut case
		 *
		 *	COMMIT ONLY
		 */

		get_node_cb_context_t * cb;
		if (btm->btree->cb_context == NULL) {
			btm->btree->cb_context =
				je_malloc(sizeof(get_node_cb_context_t));
		}
		cb = btm->btree->cb_context;
		assert(cb != NULL);

		cb->op = op;
		cb->cont_op = cont_op;
		cb->vmpack_cb = btm->vmpack_cb;
		cb->cmpack_cb = btm->cmpack_cb;
		cb->hdl = (chunkmap_handle_t *) btm;
		cb->cur_chunk_idx = 0;
		cb->cur_op_idx = 0;
		cb->cur_op_off = cont_op->offset;
		cb->cur_op_rem = cont_op->chunks->nbufs;
		cb->cur_op_key = &cont_op->offset;
		cb->flags = FLAG_GET_NODE_COMMIT;

		err = btree_get_nodes(btm->btree,
		    (void*) cb, btc_update_get_node_cb);
		if (err != 0) {
			log_error(lg, "%s: error returned by btree_get_nodes,"
			    " error = %d \n",
			    __FUNCTION__, err);
			return err;
		}
	}

	return 0;
}

/**
 * btm_destroy: destroy btree map
 */
void
btm_destroy(chunkmap_handle_t chm_handle)
{
	btc_destroy(chm_handle);
}

/**
 * dispatch table
 */
struct chunkmap btreemap = {
	.name		= "btree_map",
	.create		= btm_create,
	.destroy	= btm_destroy,
	.traverse       = btm_traverse,
	.update         = btm_update
};

chunkmap_register(btreemap);
