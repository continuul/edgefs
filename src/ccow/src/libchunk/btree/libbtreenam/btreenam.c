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
#include <pthread.h>

#include "rtbuf.h"
#include "ccow-impl.h"
#include "chunk.h"
#include "btree.h"
#include "btreecom.h"
#include "btreenam.h"

static char * btn_print_key(void *key, int prt);

static int btn_traverse_fetches_done_01(btc_cm_fetch_ctx_t *ctx, int *done);

/*
 * btn_put_cm_done
 *
 * called on completion of a put for a chunk manifest.
 */
static void
btn_put_cm_done(struct putcommon_client_req *r)
{
	assert(r->io != NULL);
	struct ccow_io *io = r->io;
	assert(io->op != NULL);
	struct ccow_op *op = io->op;

	int status = op->status;

	if (status != 0)
		ccow_fail_io(op->namedget_io, status);

	msgpack_pack_free(r->packed_data);
	rtbuf_destroy(r->payload);
}

/*
 * btn_copy_val
 *
 * copy (in place) val
 */
static int
btn_copy_val(void * dst, void * src)
{
	struct refentry *dst_re = (struct refentry *) dst;
	struct refentry *src_re = (struct refentry *) src;

	uint8_t *tmp = dst_re->data;

	memcpy(dst_re, src_re, sizeof(struct refentry));

	dst_re->data = tmp;

	return 0;
}

/*
 * btn_copy_key_val
 *
 * allocate memory for key-val and data for the destination.
 * then copy source to the destination. this function is registered with the
 * in memory btree at creation.
 */
static int
btn_copy_key_val(btree_t *btree, bt_key_val_t *src, bt_key_val_t **dst)
{
	bt_key_val_t *src_kv = src;
	bt_key_val_t *dst_kv = *dst;

	assert(dst != NULL);


#if 0 // DEBUG
	printf("_DBG : %s : %d : src = {%p, %p, %p} : dst = %p : *dst = %p \n",
	    __FUNCTION__, __LINE__, src, src->kv_key, src->kv_val, dst, *dst);
#endif
	if (dst_kv != NULL) {

		if (dst_kv->kv_key != NULL) {
			BT_FREE(dst_kv->kv_key);
			dst_kv->kv_key = NULL;
		}

		if (dst_kv->kv_val != NULL) {
			BT_FREE(dst_kv->kv_val);
			dst_kv->kv_val = NULL;
		}

		BT_FREE(dst_kv);
		dst_kv = NULL;
	}

	dst_kv = BT_CALLOC(1, sizeof(bt_key_val_t));

	if (dst_kv == NULL) {
		assert(0);
		return -ENOMEM;
	}

	btn_key_t *src_key = (btn_key_t *) src_kv->kv_key;
	btn_data_t *src_val = (btn_data_t *) src_kv->kv_val;

	btn_key_t *dst_key = (btn_key_t *) dst_kv->kv_key;
	btn_data_t *dst_val = (btn_data_t *) dst_kv->kv_val;

	assert(src_key != NULL);

	size_t sz = sizeof(btn_key_t) + src_key->len + src_key->val_len;

	dst_key = BT_CALLOC(1, sz);
	if (dst_key == NULL) {
		return -ENOMEM;
	}

	dst_val = BT_CALLOC(1, sizeof(btn_data_t));
	if (dst_val == NULL) {
		BT_FREE(dst_key);
		dst_key = NULL;
		return -ENOMEM;
	}

	bcopy(src_key, dst_key, sz);
	bcopy(src_val, dst_val, sizeof(btn_data_t));
	*dst = dst_kv;
	(*dst)->kv_key = dst_key;
	(*dst)->kv_val = dst_val;
#if 0 // DEBUG
	printf("_DBG : %s : %s : %d : dst = {%p, %p, %p} \n",
	    __FUNCTION__, __FILE__, __LINE__, *dst, (*dst)->kv_key,
	    (*dst)->kv_val);
#endif
	return 0;
}

/*
 * btn_free_key_val
 *
 * free the memory associated with the key-val. this function is registered
 * with the in memory btree on creation.
 */
int btn_free_key_val(btree_t *btree, bt_key_val_t *kv)
{
	if (kv != NULL) {
		if (kv->kv_val != NULL)
			BT_FREE(kv->kv_val);
		if (kv->kv_key != NULL)
			BT_FREE(kv->kv_key);
		BT_FREE(kv);
	}
	return 0;
}

/*
 * btn_cmp_keys
 *
 * compare two keys.
 *
 * return:
 *     negative if key1 < key2
 *     positive if key1 > key2
 *     0 if key1 == key2
 *
 * this function is registered with the in memory btree on creation.
 */
int
btn_cmp_keys(void *key1, void *key2)
{
	btn_key_t * k1 = (btn_key_t *) key1;
	btn_key_t * k2 = (btn_key_t *) key2;

	int rv = memcmp_safe(k1->key, k1->len, k2->key, k2->len);

	if (rv != 0)
		return rv;
	else {
		if (k1->len == k2->len)
			return 0;
		else if (k1->len < k2->len)
			return -1;
		else
			return 1;
	}
}

/*
 * btn_copy_keys
 *
 * copy keys.
 */
static int
btn_copy_keys(void **dst, void *src)
{
	btn_key_t *s = (btn_key_t *) src;
	btn_key_t **d = (btn_key_t **) dst;

	size_t sz = sizeof(*s) + s->len;

	if (*d == NULL) {
		*d = BT_CALLOC(1, sz);
		assert(*d != NULL);
	} else if (s->len != (*d)->len) {
		BT_FREE(*d);
		(*d) = BT_CALLOC(1, sz);
		assert(*d != NULL);
	}

	memcpy((*d)->key, s->key, s->len);
	(*d)->len = s->len;
	return 0;
}


/*
 * btn_print_key
 *
 * print the specified key. used for debugging and possibly logging. this
 * function is registered with the in memory btree on creation.
 *
 * NOTE! caller is responsible for memory deallocation!
 */
static char *
btn_print_key(void *key, int prt)
{
	assert( key != NULL);
	btn_key_t *k = key;

	char * buf = BT_MALLOC(k->len + 1);

	snprintf(buf, k->len + 1, "%s", k->key);

	if (prt)
		printf( "{%d, %s}", k->len, buf);

	return buf;
}

/*
 * btn_free_node
 *
 * free all memory associated with btree node.
 */
static int
btn_free_node(struct _btree_ *btree, bt_node_t *node, node_pos_t parent_pos)
{
	assert(node != NULL);
	int i;

	// FIXME:
	for (i = 0; i < node->nr_active; i++) {
		if (node->key_vals[i]->kv_key != NULL) {
			BT_FREE(node->key_vals[i]->kv_key);
			node->key_vals[i]->kv_key = NULL;
		}

		if (node->key_vals[i]->kv_val != NULL) {
			BT_FREE(node->key_vals[i]->kv_val);
			node->key_vals[i]->kv_val = NULL;
		}

		if (node->key_vals[i] != NULL) {
			BT_FREE(node->key_vals[i]);
			node->key_vals[i] = NULL;
		}
	}
	if (node->key_vals != NULL)
		BT_FREE(node->key_vals);
	if (node->children != NULL)
		BT_FREE(node->children);
	BT_FREE(node);

	return 0;
}

/*
 * btn_destroy
 *
 * destroy a btree, freeing memory for the btree data structure.
 */
static void
btn_destroy(chunkmap_handle_t chm_handle)
{
	btc_destroy(chm_handle);
}

/*
 * btn_create
 *
 * create a btree chunk map of type BTM_TYPE_NAM.
 */
int
btn_create(struct ccow_op *op, vmpack_cb_t vmpack_cb,
	cmpack_cb_t cmpack_cb, chunkmap_handle_t *hdl)
{
	rtbuf_t *rl_root = op->vm_reflist;
	struct ccow_completion *comp = op->comp;

	uint16_t nbufs = 0;
	uint16_t order = op->metadata.chunkmap_btree_order;
	int err = 0;

	struct btreemap *btn = BT_CALLOC(1, sizeof (*btn));
	if (!btn) {
		log_error(lg, "%s: failed to allocate betreemap structure \n",
				__FUNCTION__);
		return -ENOMEM;
	}

	comp->chunkmap_ctx = btn;

	btn->type = BTM_TYPE_NAM;

	btn->op = op;

	btn->vmpack_cb = vmpack_cb;
	btn->cmpack_cb = cmpack_cb;

	if (rl_root != NULL) {
		if (rl_root->nbufs > order) {
			log_error(lg, "btn_create: nbufs in root (%zu) "
				"exceeds btree order (%d) \n",
				rl_root->nbufs, order);
			assert(0);
		}
	}

	/*
	 * create the in-memory btree data structure. adjust for the order of
	 * the in-memory btree being defined as 1/2 the fannout.
	 */
	btn->btree = btree_create(order/2);
	if (!btn->btree) {
		log_error(lg, "%s: failed to create btree data structure \n",
			__FUNCTION__);
		BT_FREE(btn);
		return -ENOMEM;
	}

	btn->btree->copy_val     = btn_copy_val;
	btn->btree->copy_key_val = btn_copy_key_val;
	btn->btree->free_key_val = btn_free_key_val;
	btn->btree->cmp_keys     = btn_cmp_keys;
	btn->btree->copy_key     = btn_copy_keys;
	btn->btree->print_key    = btn_print_key;
	btn->btree->print_val    = NULL;
	btn->btree->free_node    = btn_free_node;
	btn->btree->btcm	 = btn;

	/*
	 * populate the root node of the btree with the data from the version
	 * manifest (a.k.a. the root)
	 */
	bt_node_t *node = NULL;

	if (rl_root != NULL) {
		assert(rl_root->nbufs <= order);
		nbufs = rl_root->nbufs;
	}

	int leaf  = TRUE;
	int level = 0;

	for (uint16_t i = 0; i < nbufs; i++) {
		/*
		 * allocate a btn data structure, which will contain refentry
		 * and other data
		 */
		assert(btn->btree->print_val == NULL);
		btn_data_t *data = BT_CALLOC(1, sizeof(*data));
		if (!data) {
			log_error(lg, "%s: memory allocation failure \n",
				__FUNCTION__);
			btn_destroy((chunkmap_handle_t) btn);
			return -ENOMEM;
		}

		/*
		 * bt_key_val_t will contain pointers to the key (chid)
		 * and value (btn_data_t)
		 */
		assert(btn->btree->print_val == NULL);
		bt_key_val_t *kv = BT_CALLOC(1, sizeof(*kv));
		if (!kv) {
			log_error(lg, "%s: memory allocation failure \n",
				__FUNCTION__);
			BT_FREE(data);
			btn_destroy((chunkmap_handle_t) btn);
			return -ENOMEM;
		}

		/*
		 * the rtbuf entry will be a refentry within the rl_root, this
		 * refentry will be written to the btree root in the version
		 * manifest
		 */
		struct refentry *re = (struct refentry *) rtbuf(rl_root, i).base;
		assert(btn->btree->print_val == NULL);
		data->re = *re;

		leaf  = BT_REF_LEAF(re);
		level = BT_REF_LEVEL(re);

		/*
		 * note: btree_insert_key and/or btree_load_kv take ownership
		 * of kv and responsibility for freeing kv
		 */
		size_t sz = sizeof(btn_key_t) + re->length;
		assert(btn->btree->print_val == NULL);
		btn_key_t *key = BT_CALLOC(1, sz);
		if (key == NULL) {
			log_error(lg, "%s: memory allocation failure \n",
				__FUNCTION__);
			BT_FREE(data);
			BT_FREE(kv);
			btn_destroy((chunkmap_handle_t) btn);
			return -ENOMEM;
		}

		assert(re->data != NULL);
		assert(re->length == re->compressed_length);

		memcpy(key, re->data, re->length);

		assert(btn->btree->print_val == NULL);

		kv->kv_key = key;
		assert(kv->kv_val == NULL);
		kv->kv_val = data;

		node_pos_t parent = {.node = NULL, .index = i};

		err = btree_load_kv(btn->btree, parent, &node,
			leaf, level, kv);
		if (err != 0) {
			log_error(lg, "%s: failed to insert btree key, err = %d",
				  __FUNCTION__, err);
			BT_FREE(data);
			BT_FREE(kv->kv_key);
			BT_FREE(kv);
			btn_destroy((chunkmap_handle_t) btn);
			return err;
		}

		/* the btree takes ownership of the kv */
		assert(btn->btree->print_val == NULL);
		kv = NULL;
	}

	*hdl = btn;

	assert(btn->btree->print_val == NULL);

	return 0;
}

/*
 * btn_update_get_node_cb
 *
 * callback from btree traversal on update.  called on each node in the btree.
 * callbacks for nodes in the tree are done in a depth manner.
 */
static int
btn_update_get_node_cb(btree_t *btree, bt_node_t *node, bt_node_t *parent,
    void *context)
{
	int err = 0;
	uint32_t i;
	uint64_t k;
	int par_idx = 0;

	get_node_cb_context_t *ctx = (get_node_cb_context_t *) context;

	struct btreemap *btn   = (struct btreemap *) ctx->hdl;
	struct ccow_op *op     = btn->op;
	struct ccow_op *cont_op = ctx->cont_op;
	vmpack_cb_t vmpack_cb  = ctx->vmpack_cb;
	cmpack_cb_t cmpack_cb  = ctx->cmpack_cb;
	struct ccow_completion *comp = op->comp;

	/* this btree implementation has all leaf nodes at level 0 */
	if (node->level == 0) assert(node->leaf == TRUE);
	if (node->leaf == TRUE) assert(node->level == 0);
	if (node->level != 0) assert(node->leaf == FALSE);
	if (node->leaf == FALSE) assert(node->level != 0);

	if (node == btree->root)
		assert(parent == NULL);
	else
		assert(parent != NULL);

	if (comp->chunkmap_flags & CCOW_STREAM) {
		if (comp->chunkmap_flags & CCOW_FINAL) {
			assert(comp->chunkmap_flags & BTN_CHUNKMAP_FINALIZE);
		}
	}

	if ((comp->chunkmap_flags & CCOW_STREAM) &&
	    (!(comp->chunkmap_flags & BTN_CHUNKMAP_FINALIZE))) {
		return 0;
	}

	/*
	 * Always commit version manifest for BTN, even if not dirty
	 */
	if (!BN_FLAG(node, BN_FLAG_DIRTY) && (node != btree->root)) {
		return 0;
	}

	/*
	 *  there are several constraints here:
	 *  1: the root node must be packed as a version manifest
	 *  2: non-root nodes must be packed as chunk manifests
	 *  3: nodes ref-entries must be of type RT_REF_TYPE_INLINE()
	 */

	/*
	 * find the index into the parent's children array for this node
	 * FIXME: this needs to/can be more efficient
	 */
	if (parent != NULL) {
		for (par_idx = 0; par_idx < parent->nr_active; par_idx++) {
			if (node == parent->children[par_idx])
				break;
		}
		assert(par_idx < parent->nr_active);
	}

	/*
	 * create a reflist for the entries in the node the ref-list
	 */
	rtbuf_t *rl = rtbuf_init_empty();
	if (rl == NULL) {
		btree_destroy(btn->btree);
		BT_FREE(btn);
		BT_FREE(ctx);
		ccow_fail_io(op->namedget_io, -ENOMEM);
		return -ENOMEM;
	}

	/*
	 * add each keyval in the btree node to the ref entry list
	 */
	for (int i = 0; i < node->nr_active; i++) {

		uv_buf_t buf;
		bt_key_val_t *kv = node->key_vals[i];

		btc_data_t *data  = (btc_data_t*) kv->kv_val;
		struct refentry *re = &data->re;

		BT_REF_LEAF_SET(re, node->leaf);
		BT_REF_LEVEL_SET(re, node->level);

		btn_key_t *k = kv->kv_key;

		if (!node->leaf) {
			k->val_len = 0;
		}

		re->data = (void *)k;
		re->length = re->compressed_length = k->len + k->val_len +
			sizeof (k->len) + sizeof (k->val_len);

		if (uint512_cmp(&re->content_hash_id, &uint512_null) == 0)
			RT_REF_TYPE_SET(re, RT_REF_TYPE_INLINE_PAYLOAD);
		else if (node->leaf)
			RT_REF_TYPE_SET(re, RT_REF_TYPE_INLINE_VERSION);
		else
			RT_REF_TYPE_SET(re, RT_REF_TYPE_INLINE_MANIFEST);
		RT_REF_HASH_TYPE_SET(re, HASH_TYPE_DEFAULT);

		buf.len  = sizeof(struct refentry);
		buf.base = (void *) re;

		err = rtbuf_add_alloc(rl, &buf, 1);
		if (err != 0) {
			log_error(lg, "%s: rtbuf_add returned error %d",
			    __FUNCTION__, err);
			ccow_fail_io(op->namedget_io, err);
			btree_destroy(btn->btree);
			BT_FREE(ctx);
			return err;
		}
	}

	if (node != btree->root) {
		/*
		 *  schedule to send as an unnamed put IO
		 */
		BN_FLAG_CLR(node, BN_FLAG_DIRTY);

		struct ccow_io *up_io;

		err = ccow_unnamedput_create(comp, btn_put_cm_done, op,
		    &up_io, cont_op->namedget_io);
		if (err != 0) {
			ccow_fail_io(op->namedget_io, err);
			return err;
		}

		up_io->attributes |= RD_ATTR_CHUNK_MANIFEST;

		struct putcommon_client_req *r = CCOW_IO_REQ(up_io);

		/*
		 *  this node is not the root, so its chid must be stored in
		 *  the parent.
		 */

		bt_key_val_t *par_kv = parent->key_vals[par_idx];
		btc_data_t *par_data = (btc_data_t*) par_kv->kv_val;
		struct refentry *par_re = &par_data->re;

		/*
		 *  pack it as chunk manifest
		 */
		err = cmpack_cb(up_io, rl);
		if (err != 0) {
			log_error(lg, "%s: cmpack_cb returned error %d",
			    __FUNCTION__, err);
			ccow_fail_io(op->namedget_io, err);
			return err;
		}

		par_re->content_hash_id = r->chid;
	} else {
		/*
		 *  pack it as a version manifest
		 */
		if (((comp->chunkmap_flags & CCOW_STREAM) == 0) ||
		    ((comp->chunkmap_flags & BTN_CHUNKMAP_FINALIZE) != 0)) {

			BN_FLAG_CLR(node, BN_FLAG_DIRTY);

			if (op->status != 0) {
				log_warn(lg, "%s: failing io : op->status = %d ",
				    __FUNCTION__, op->status);
				ccow_fail_io(op->namedget_io, op->status);
				rtbuf_destroy(rl);
				return op->status;
			}

			err = vmpack_cb(op->namedput_io, rl);

			if (err != 0) {
				log_error(lg, "%s: vmpack_cb returned error %d",
				    __FUNCTION__, err);
				ccow_fail_io(op->namedget_io, err);
				rtbuf_destroy(rl);
				return err;
			}
		}
	}

	rtbuf_destroy(rl);

	return 0;
}

/*
 * btn_update_insert_key_val
 *
 * insert key/val into the btree.  this is called on optype of
 * CCOW_INSERT_LIST.
 */
static int
btn_update_insert_key_val(btree_t * btree, bt_key_val_t * key_val, int overwrite)
{
	int err = 0;

	/*
	 * insert the key/val. note: btree_insert_key takes ownership of kv and
	 * responsibility for freeing kv
	 */

#if 0 // FIXME : DEBUG
	print("_DBG : %s : %s : %d : key_val = {%p, %p, %p} \n",
	    __FUNCTION__, __FILE__, __LINE__, key_val, key_val->kv_key,
	    key_val->kv_val);
	BTREE_DUMP(btree);
#endif
	err = btree_insert_key(btree, key_val, overwrite);

	if (err != 0) {
		if (err != -EEXIST)
			log_error(lg, "%s: btree_insert_key returned error %d",
			    __FUNCTION__, err);
		return err;
	}

#if 0 // FIXME : DEBUG
	BTREE_DUMP(btree);
#endif
	return err;
}

/*
 * btn_update_delete_key_val
 *
 * delete key/val delete the btree. this function is called
 * on optype of CCOW_DELETE_LIST.
 */
static int
btn_update_delete_key_val(btree_t * btree, bt_key_val_t * key_val)
{
	int err = 0;

	/*
	 * delete the key/val
	 */
	err = btree_delete_key(btree, key_val);

	if (err != 0) {
		if (err != -ENOENT)
			log_error(lg, "%s: btree_delete_key returned error %d",
			    __FUNCTION__, err);
	}

	btn_free_key_val(btree, key_val);

	return err;
}

/*
 * btn_update_fetches_done
 *
 * called when all the required btree nodes have been retrieved from persistent
 * storage.
 */
static int
btn_update_fetches_done(btc_cm_fetch_ctx_t *ctx, int *done)
{
	chunkmap_handle_t *hdl = ctx->hdl;
	struct btreemap *btn = (struct btreemap*) hdl;
	struct ccow_op *op = ctx->cont_op;
	struct ccow_completion *comp = op->comp;
	rtbuf_t *op_chunks = op->chunks;
	rtbuf_t *rl_root = op->vm_reflist;

	int err = 0, err1 = 0;

	/* FIXME: We need to support multiple chunks.. so we can handle the multi
	 * iovec case. */

	/* for btree name index, the most that can be updated on a single put
	 * call is 1 entry of 3 iovecs key, val (optional) and chid (optional). */
	assert(op_chunks->nbufs <= 3);

	/* update the btree by adding entries from the op's chunk list,  */
	for (uint16_t i = 0; i < op_chunks->nbufs; i++) {
		struct iovec *iov_in   = &op->iov_in[i];
		uv_buf_t     *op_chunk = &rtbuf(op_chunks, i);
		uint512_t    *op_chid  = &op->chids[i];
		struct iovec *iov_in_val = (op->iovcnt_in >= 2) ?
				&op->iov_in[++i] : NULL;
		uint512_t    *parent_chid = (op->iovcnt_in == 3) ?
				(uint512_t *)op->iov_in[++i].iov_base : NULL;

		if (op->iovcnt_in == 3)
			uint512_logdump(lg, "INSERTING INTO BTN: ", parent_chid);

		bt_key_val_t *kv = BT_CALLOC(1, sizeof(*kv));

		if (!kv) {
			log_error(lg, "%s: memory allocation failure\n",
			    __FUNCTION__);
			btree_destroy(btn->btree);
			BT_FREE(btn);
			return -ENOMEM;
		}

		/*
		 * add new name index
		 */
		uint32_t val_len = iov_in_val ? iov_in_val->iov_len : 0;
		size_t sz = sizeof(btn_key_t) + iov_in->iov_len + val_len;
		btn_key_t *key = BT_CALLOC(1, sz);
		if (key == NULL) {
			log_error(lg, "%s: memory allocation failure\n",
			    __FUNCTION__);
			btree_destroy(btn->btree);
			BT_FREE(btn);
			BT_FREE(kv);
			return -ENOMEM;
		}

		/* copy key */
		key->len = iov_in->iov_len;
		memcpy(key->key, iov_in->iov_base, key->len);

		/* copy val */
		key->val_len = val_len;
		if (iov_in_val)
			memcpy(key->key + key->len, iov_in_val->iov_base, val_len);

		assert(key != NULL);
		assert(memcmp_quick(key->key, key->len,
			    ((btn_key_t *) ctx->key)->key, op_chunk->len) == 0);

		btn_data_t *data = BT_CALLOC(1, sizeof(btn_data_t));
		if (!data) {
			log_error(lg, "%s: memory allocation failure \n",
			    __FUNCTION__);
			btree_destroy(btn->btree);
			BT_FREE(btn);
			BT_FREE(ctx);
			BT_FREE(kv);
			return -ENOMEM;
		}
		struct refentry *re = &data->re;

		re->offset            = 0;
		re->length            = sz;
		re->compressed_length = sz;

		if (op->iovcnt_in > 2)
			RT_REF_TYPE_SET(re, RT_REF_TYPE_INLINE_VERSION);
		else
			RT_REF_TYPE_SET(re, RT_REF_TYPE_INLINE_PAYLOAD);
		RT_REF_HASH_TYPE_SET(re, HASH_TYPE_DEFAULT);

		re->data = (uint8_t *) key;

		if (op->iovcnt_in > 2) {
			re->content_hash_id = *parent_chid;
			assert(val_len == UINT512_BYTES);
			memcpy(&re->name_hash_id, iov_in_val->iov_base, val_len);
		}

		kv->kv_key = (void *) key;
		assert(kv->kv_val == NULL);
		kv->kv_val = data;
		data = NULL;

		int overwrite = comp->cont_flags & CCOW_CONT_F_INSERT_LIST_OVERWRITE;

		switch (op->optype) {

		case CCOW_INSERT_LIST:
		case CCOW_INSERT_MD:
		case CCOW_UPDATE_MD:
		case CCOW_INSERT_LIST_CONT:
			err = btn_update_insert_key_val(btn->btree, kv, overwrite);
			if (err == -EEXIST && CCOW_INSERT_LIST_CONT) {
				op->status = err;
				err = 0;
			}

			if (err == 0) {
				BT_FREE(kv->kv_key);
				BT_FREE(kv->kv_val);
				BT_FREE(kv);
				kv = NULL;
				data = NULL;
			}

			btn_free_key_val(btn->btree, kv);
			kv = NULL;
			break;

		case CCOW_DELETE_LIST:
		case CCOW_DELETE_MD:
		case CCOW_DELETE_LIST_CONT:
			err = btn_update_delete_key_val(btn->btree, kv);
			if (err == -ENOENT) {
				op->status = err;
				err = 0;
			}

			break;

		default:
			log_error(lg, "Illegal optype (%d) ", op->optype);
			assert(0);
			break;
		}

		if (err != 0) {
			if (kv != NULL) {
				if (kv->kv_key != NULL)
					BT_FREE(kv->kv_key);
				if (kv->kv_val != NULL)
					BT_FREE(kv->kv_val);
				BT_FREE(kv);
				kv = NULL;
				data = NULL;
			}

			if (ctx != NULL) {
				if (ctx->key != NULL) {
					BT_FREE(ctx->key);
					ctx->key = NULL;
				}
				BT_FREE(ctx);
				ctx = NULL;
			}

			ccow_fail_io(op->namedget_io, err);
			return err;
		}

		kv = NULL;
	}

	get_node_cb_context_t cb = {
		.op = op,
		.cont_op = op,
		.vmpack_cb = btn->vmpack_cb,
		.cmpack_cb = btn->cmpack_cb,
		.hdl = hdl,
		.cur_chunk_idx = 0,
		.cur_op_idx = 0,
		.cur_op_off = op->offset,
		.cur_op_rem = op->chunks->nbufs
	};

	err = btree_get_nodes(btn->btree, (void*) &cb, btn_update_get_node_cb);

	if (err != 0) {
		log_warn(lg, "%s: error returned by btree_get_nodes, error = %d ",
		    __FUNCTION__, err);
	}

	assert(*done == FALSE);
	assert(ctx != NULL);
	assert(ctx->key != NULL);

	BT_FREE(ctx->key);
	BT_FREE(ctx);
	*done = TRUE;

	return err;
}

/*
 * btn_update
 *
 * called on insert_list or delete_list requests to update the btree.
 * this function initiates the process of fetching the btree nodes into
 * memory.
 */
static int
btn_update(chunkmap_handle_t chm_handle, struct ccow_op *cont_op,
    bt_overwrite_cb ow_cb, void *ow_cb_args)
{
	int err = 0;
	struct btreemap *btn = (struct btreemap*) chm_handle;
	struct ccow_op *op = btn->op;

	struct ccow_completion *comp = op->comp;
        rtbuf_t *op_chunks = (cont_op == NULL) ? op->chunks : cont_op->chunks;

	nassert(comp->tc->loop_thrid == uv_thread_self());

	assert((op_chunks->nbufs > 0) || (btn->op == cont_op));
	assert(op_chunks->nbufs <= 3);

	/* in namedput__init_continued() we pass current operation and that
	 * signals us that we in a final commit stage, initialized by
	 * ccow_finalize() */
	if (btn->op == cont_op) {
		/*
		 * this update call must be due to a ccow_finalize.
		 */
		assert((comp->chunkmap_flags & CCOW_STREAM) != 0);
		assert(comp->chunkmap_ctx != NULL);

		comp->chunkmap_flags |= BTN_CHUNKMAP_FINALIZE;

		get_node_cb_context_t * ctx = je_calloc(1,
		    sizeof(get_node_cb_context_t));
		if (ctx == NULL) {
			return -ENOMEM;
		}

		memset(ctx, 0, sizeof(get_node_cb_context_t));

		ctx->hdl	= chm_handle;
		ctx->op		= op;
		ctx->cont_op    = cont_op;
		ctx->vmpack_cb	= btn->vmpack_cb;
		ctx->cmpack_cb	= btn->cmpack_cb;

		if (comp->chunkmap_flags & CCOW_STREAM) {
			err = btree_get_nodes(btn->btree, ctx, btn_update_get_node_cb);
			assert(!err);
		} else {
			btn_update_get_node_cb(btn->btree, btn->btree->root, NULL, ctx);
		}

		je_free(ctx);
		ctx = NULL;

		return 0;
	}

	/*
	 * insert_list and delete_list are restricted to a single
	 * key/val + chid for now
	 */

	/*
	 * initialize context structure for fetch(es).
	 */
	btc_cm_fetch_ctx_t *ctx = BT_CALLOC(1, sizeof(*ctx));

	if (ctx == NULL) {
		log_error(lg, "%s: memory allocation failure \n",
			__FUNCTION__);
		btn_destroy((chunkmap_handle_t) btn);
		return -ENOMEM;
	}

	uint32_t val_len = op_chunks->nbufs >= 2 ? op_chunks->bufs[1].len : 0;
	size_t sz = sizeof(btn_key_t) + op_chunks->bufs[0].len + val_len;

	btn_key_t *key = BT_CALLOC(1, sz);
	if (key == NULL) {
		log_error(lg, "%s: memory allocation failure \n",
			  __FUNCTION__);
		BT_FREE(ctx);
		btn_destroy((chunkmap_handle_t) btn);
		return -ENOMEM;
	}

	key->len = op_chunks->bufs[0].len;
	memcpy(key->key, op_chunks->bufs[0].base, op_chunks->bufs[0].len);

	if (val_len) {
		key->val_len = val_len;
		memcpy(key->key + key->len, op_chunks->bufs[1].base, val_len);
	}

	if (cont_op == NULL) {
		/* Case 1. */
		cont_op = op;
		ctx->flags = 0;
	} else {
		/* Case 2. */
		ctx->flags = FLAG_FETCH_NO_COMMIT;
	}

	ctx->hdl            = chm_handle;
	ctx->type	    = BTN;
	ctx->pos.node       = NULL;
	ctx->pos.index      = 0;
	ctx->op             = op;
	ctx->op_comp        = comp;
	ctx->update         = 1;
	ctx->op_buf_idx     = 0;
	ctx->nbufs          = op_chunks->nbufs;
	ctx->cont_op        = cont_op;
	ctx->fetch_rem      = op_chunks->nbufs;
	ctx->fetches_done   = btn_update_fetches_done;
	ctx->cm_fetch_done  = NULL;
	ctx->key            = key;

	/*
	 *  call btc_cm_fetch which will fetch the required parts of the btree
	 *  from object storage.
	 */
	err = btc_cm_fetch(ctx);
	if (err != 0) {
		BT_FREE(key);
		BT_FREE(ctx);
		log_error(lg, "%s: btc_cm_fetch returned error %d \n",
			  __FUNCTION__, err);
		return err;
	}

	return 0;
}

/*
 * btn_add_to_lookup
 *
 * add the key found in the specified position to the lookup.
 */
static int
btn_add_to_lookup(struct ccow_lookup *iter, node_pos_t *pos)
{
	/*
	 * initialize rtbuf list if not already done.
	 */

	if (iter->name_index == NULL) {
		iter->name_index = rtbuf_init_empty();
		if (iter->name_index == NULL)
			return -ENOMEM;
	}

	/*
	 * initialize the key and ccow_metadata_kv structures that will be added
	 * to the lookup.
	 */

	btn_key_t *key = pos->node->key_vals[pos->index]->kv_key;
	size_t len = key->len;
	/*
	 * Retrieve Value (CHID)
	 */
	char *md_k = BT_MALLOC(len);
	if (md_k == NULL)
		return -ENOMEM;
	memcpy(md_k, key->key, len);

	struct ccow_metadata_kv *md_kv = BT_CALLOC(1, sizeof(*md_kv));
	if (md_kv == NULL)
	{
		BT_FREE(md_k);
		return -ENOMEM;
	}

	md_kv->mdtype = CCOW_MDTYPE_NAME_INDEX;
	md_kv->key = md_k;
	md_kv->key_size = len;
	md_kv->type = CCOW_KVTYPE_RAW;

	if (key->val_len) {
		char *md_v = BT_MALLOC(key->val_len);
		if (md_v == NULL) {
			BT_FREE(md_kv);
			BT_FREE(md_k);
			return -ENOMEM;
		}
		memcpy(md_v, key->key + key->len, key->val_len);

		md_kv->value = md_v;
		md_kv->value_size = key->val_len;
	}

	/* copy the CHID */
	btc_data_t *data  = (btc_data_t*) pos->node->key_vals[pos->index]->kv_val;
	struct refentry *re = &data->re;
	memcpy(md_kv->chid, &re->content_hash_id, UINT512_BYTES);

	uv_buf_t uv_b;
	uv_b.base = (void *) md_kv;
	uv_b.len  = sizeof(*md_kv);

	rtbuf_add(iter->name_index, &uv_b, 1);
	return 0;
}


/*
 * btn_traverse_fetches_done
 *
 * called when the partial btree needed for this traverse request has been
 * fetched into memory.
 *
 * this function will search the btree for the specified key, if it is not
 * found, the next greater key will be selected. the selected key will be
 * added to the lookup iterator referenced by the op.
 *
 */
static int
btn_traverse_fetches_done_02(btc_cm_fetch_ctx_t *ctx, int *done)
{
	assert(ctx != NULL);
	assert(ctx->hdl != NULL);
	chunkmap_handle_t *hdl = ctx->hdl;
	struct btreemap *btn = (struct btreemap*) hdl;
	assert(btn->btree != NULL);
	btree_t *btree = btn->btree;
	int err = 0;

	err = btn_traverse_fetches_done_01(ctx, done);
	return err;
}

static int
btn_traverse_fetches_done_01(btc_cm_fetch_ctx_t *ctx, int *done)
{
	chunkmap_handle_t *hdl = ctx->hdl;
	struct btreemap *btn = (struct btreemap*) hdl;
        struct ccow_op *op = btn->op;
	struct ccow_completion *comp = op->comp;
        rtbuf_t *op_chunks = op->chunks;
        rtbuf_t *rl_root = op->vm_reflist;
	int err;

	ctx->fetch_rem = op->offset;

	struct ccow_lookup *iter = op->iter;

	node_pos_t pos = { .node  = NULL,
			   .index = 0 };

	BT_STACK_CLEAR(&ctx->stack);

	/* initialize the search key */
	btn_key_t *ctx_key = ctx->key;
	size_t sz = sizeof(btn_key_t) + ctx_key->len + ctx_key->val_len;
	btn_key_t *key = BT_CALLOC(1, sz);
	if (key == NULL) {
		assert(0);
	}

	key->len = ctx_key->len;
	memcpy(key->key, ctx_key->key, ctx_key->len + ctx_key->val_len);

	/* search the tree for the key */
	err = bt_get_node_pos_by_key(btn->btree, key, &pos, &ctx->stack,
	    ctx->update, FALSE, FALSE);
	BT_FREE(key);

	if ((err == -ENODATA) && (pos.node != NULL)) {
		/*
		 * err of ENODATA and non-null pos.node is an indication that
		 * the key was not found, but the next larger key exists,
		 * so use it
		 */
		err = 0;
	}

	switch (err) {

		case 0:
			/*
			 * key found.
			 */
			if (iter != NULL) {
				while (ctx->fetch_rem-- > 0) {

					err = btn_add_to_lookup(iter, &pos);
					assert(err == 0);

					ctx->fetch_type = FETCH_BY_POS;
					err = bt_get_node_pos_by_pos(btn->btree,
					    &pos, &ctx->stack);

					if (ctx->fetch_rem == 0 && err == -EAGAIN) {
						break;
					}

					if (err == 0) {
						continue;
					} else if (err == -ENODATA) {
						break;
					} else if (err == -ENOMEM) {
						break;
					} else {
						assert(0);
					}
				}

				/* success */
				BT_FREE(ctx->key);
				BT_FREE(ctx);
				*done = TRUE;
				return 0;

			} else {
				/*
				 * no list provided, so complete with success
				 */

				if (ctx->key != NULL) {
					BT_FREE(ctx->key);
					ctx->key = NULL;
				}

				BT_FREE(ctx);
				*done = TRUE;
				return 0;
			}

			break;

	case -ENODATA:
		/*
		 * there is no next higher key, fail the IO.
		 */
		ccow_fail_io(op->namedget_io, -ENOENT);
		BT_FREE(ctx->key);
		BT_FREE(ctx);
		*done = TRUE;
		return -ENODATA;

		break;

	default:
		/* any other status is a bug */
		log_error(lg, "bt_get_node_pos_by_key returned unexpected "
			  " error %d \n", err);
		assert(0);
		return err;
		break;
	}

	assert(0);
	return 0;
}

static int
btn_traverse_fetches_done(btc_cm_fetch_ctx_t *ctx, int *done)
{

	assert(ctx != NULL);
	assert(ctx->hdl != NULL);
	chunkmap_handle_t *hdl = ctx->hdl;
	struct btreemap *btn = (struct btreemap*) hdl;
	assert(btn->btree != NULL);
	btree_t *btree = btn->btree;
	bt_node_t *node = NULL;

	int err = 0;

	if ((ctx->fetch_rem == 1) || (ctx->pos.node == NULL)) {
		err = btn_traverse_fetches_done_01(ctx, done);
		return err;
	}

	assert(ctx->pos.node != NULL);
	node = ctx->pos.node;

	if (ctx->pos.index + ctx->fetch_rem <= node->nr_active) {
		err = btn_traverse_fetches_done_01(ctx, done);
		return err;
	}

	ctx->fetches_done = btn_traverse_fetches_done_02;

	ctx->fetch_type = FETCH_BY_POS;
	err = btc_cm_fetch_by_pos(ctx, done);
	return err;
}

/*
 * btn_traverse
 *
 * called on get oro get list request to retrieve data from the btree.
 * this function initiates the fetching of btree nodes into memory.
 */
static int
btn_traverse(chunkmap_handle_t chm_handle, struct ccow_op *cont_op,
	     bt_traverse_done_cb_t traverse_cb, void *traverse_cb_data)
{
	int err;
	struct btreemap *btn = (struct btreemap*) chm_handle;
        struct ccow_op *op = btn->op;
	struct ccow_completion *comp = op->comp;
        rtbuf_t *op_chunks = op->chunks;

	nassert(comp->tc->loop_thrid == uv_thread_self());

	btc_cm_fetch_ctx_t *ctx = BT_CALLOC(1, sizeof(*ctx));
	if (ctx == NULL) {
		log_error(lg, "%s: memory allocation failure \n",
			  __FUNCTION__);
		btc_destroy((chunkmap_handle_t) btn);
		return -ENOMEM;
	}

	DBG_PRINT("alloc : ctx = %p", ctx);

	size_t sz = sizeof(btn_key_t) + op_chunks->bufs[0].len;
	btn_key_t *key = BT_CALLOC(1, sz);
	if (key == NULL) {
		log_error(lg, "%s: memory allocation failure \n",
			  __FUNCTION__);
		BT_FREE(ctx);
		btn_destroy((chunkmap_handle_t) btn);
		return -ENOMEM;
	}

	key->len = op_chunks->bufs[0].len;
	memcpy(key->key, op_chunks->bufs[0].base, op_chunks->bufs[0].len);

	/*
	 * fill in the context structure
	 */

	ctx->hdl        = chm_handle;
	ctx->type       = BTN;
	ctx->pos.node   = NULL;
	ctx->pos.index  = 0;
	ctx->op         = op;
	ctx->op_comp    = comp;
	ctx->update     = 0;
	ctx->op_buf_idx = 0;
	ctx->nbufs      = op->offset;
	ctx->cont_op    = op; /* cont semantics not used in btn */
	ctx->fetch_rem  = op->offset;
	ctx->fetches_done   = btn_traverse_fetches_done;
	ctx->cm_fetch_done  = traverse_cb;
	ctx->traverse_cb_data = traverse_cb_data;
	ctx->key = key;

	/*
	 * initiate the fetch of the btree nodes into memory
	 */

	err = btc_cm_fetch(ctx);
	if (err != 0) {
		log_error(lg, "%s: btc_cm_fetch returned error %d \n",
			  __FUNCTION__, err);
		BT_FREE(ctx);
		BT_FREE(key);
		return err;
	}

	return(0);
}

/*
 * dispatch table
 */

struct chunkmap btreenam = {
	.name		= "btree_key_val",
	.create		= btn_create,
	.destroy	= btn_destroy,
	.traverse       = btn_traverse,
	.update         = btn_update
};

chunkmap_register(btreenam);
