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
#ifndef __BTREECOM_H__
#define __BTREECOM_H__

#ifdef	__cplusplus
extern "C" {
#endif

char * btc_uint512_dump(uint512_t *pv);

#if 1
#define BTC_BREAK							\
	asm volatile ("int3;");
#else
#define BTC_BREAK
#endif

#if 1

#define BT_CACHE_GET(_cmcache, _chid, _reflist, _err)			\
	_err = ccow_cmcache_get(_cmcache, _chid, _reflist);

#define BT_CACHE_PUT(_cmcache, _chid, _reflist)				\
	ccow_cmcache_put(_cmcache, _chid, _reflist);

#else

#define BT_CACHE_GET(_cmcache, _chid, _reflist,  _err)			\
	printf("BT_CACHE_GET : %s : %s : %d"				\
        " : cmcache = %p"						\
        " : chid = %s"							\
        " : reflist = %p \n",						\
	    __FUNCTION__, __FILE__, __LINE__, _cmcache,			\
	    btc_uint512_dump(_chid), _reflist);				\
	_err = ccow_cmcache_get(_cmcache, _chid, _reflist);

#define BT_CACHE_PUT(_cmcache, _chid, _reflist)				\
	printf("BT_CACHE_PUT : %s : %s : %d"				\
        " : cmcache = %p"						\
        " : chid = %s"							\
        " : reflist = %p",						\
	    __FUNCTION__, __FILE__, __LINE__, _cmcache,			\
	    btc_uint512_dump(_chid), _reflist);				\
	ccow_cmcache_put(_cmcache, _chid, _reflist);

#endif

#if 0
#define FETCH_GET_START(_ctx)						\
	printf("FETCH_GET_START : %s : %s : %d : ctx->num_ios = %d\n",	\
	    __FUNCTION__, __FILE__, __LINE__, _ctx->num_ios);		\
	BTC_BREAK;							\
    ++_ctx->num_ios;                    \
    assert(_ctx->num_ios == 1);

#define FETCH_GET_END(_ctx)						\
	printf("FETCH_GET_START : %s : %s : %d : ctx->num_ios = %d\n",	\
	    __FUNCTION__, __FILE__, __LINE__, _ctx->num_ios);		\
	BTC_BREAK;							\
    --_ctx->num_ios;                    \
	assert(_ctx->num_ios == 0);
#else
#define FETCH_GET_START(_ctx)
#define FETCH_GET_END(_ctx)
#endif

#define BT_REF_LEAF(_re) (((_re)->map_attr & 0x80) >> 7)
#define BT_REF_LEAF_SET(_re, _leaf) \
	(_re)->map_attr = (((_re)->map_attr & 0x7F) | _leaf << 7)

#define BT_REF_LEVEL(_re) (((_re)->map_attr) & 0x3F)
#define BT_REF_LEVEL_SET(_re, _level) \
	(_re)->map_attr = (((_re)->map_attr & (~0x3F)) | _level)

#define BT_REF_MOD(_re) (((_re)->map_attr & 0x40) >> 6)
#define BT_REF_MOD_SET(_re, _mod) \
	(_re)->map_attr = (((_re)->map_attr & (~0x40)) | _mod << 6)

#define BTM_TYPE_MAP            1
#define BTM_TYPE_NAM            2

struct btreemap {
	uint8_t type;
	struct ccow_op *op;
	vmpack_cb_t vmpack_cb;
	cmpack_cb_t cmpack_cb;
	btree_t *btree;
};

typedef struct _btc_data_
{
	struct refentry re;
// FIXME:	uv_buf_t chunk;
} btc_data_t;

#define FLAG_GET_NODE_COMMIT	0x00000001
#define FLAG_GET_NODE_NO_COMMIT	0x00000002

typedef struct get_node_cb_context {
	chunkmap_handle_t *hdl;
	struct ccow_op *op;
	struct ccow_op *cont_op;
	vmpack_cb_t vmpack_cb;
	cmpack_cb_t cmpack_cb;

	uint64_t cur_chunk_idx;
	uint64_t cur_op_idx;
	uint64_t cur_op_rem;

	uint64_t cur_op_off;
	void     *cur_op_key;

	uint32_t   flags;

	bt_overwrite_cb ow_cb;
	void *ow_cb_arg;

} get_node_cb_context_t;

/*
 * btc_cm_fetch_ctx
 *
 * structure used to track the state and context of the chunk manifest fetch
 * algorithm.
 */
typedef enum {
	BT_INVALID,		// invalid
	BTN,			// btree name index
	BTM			// btree map
} bt_map_type_t;

typedef struct _btc_cm_fetch_ctx_ {
	chunkmap_handle_t   hdl;
	bt_map_type_t	    type;

	void (*btc_cm_fetch_done)(struct _btc_cm_fetch_ctx_ **ctx);

	struct ccow_op *op;
	struct ccow_io *io;
	struct ccow_op *cont_op;
	struct ccow_completion *op_comp;
	struct getcommon_client_req  *fetch_req;

	uint32_t   op_buf_idx;
	uint32_t   nbufs;
	uint64_t   off;

#define FETCH_UNKNOWN   0
#define FETCH_BY_KEY    1
#define FETCH_BY_POS    2

	uint8_t    fetch_type;
	uint8_t    update;

	void       *key;
	int        fetch_rem;
	node_pos_t pos;
	bt_stack_t stack;

	uint32_t   num_ios;

#define FLAG_FETCH_COMMIT	0x00000001
#define FLAG_FETCH_NO_COMMIT	0x00000002
	uint32_t   flags;
	void	   *traverse_cb_data;

	/* caller supplied completion callbacks */
	int (*fetches_done)(struct _btc_cm_fetch_ctx_ *ctx, int *done);
	bt_traverse_done_cb_t cm_fetch_done;

	bt_overwrite_cb ow_cb;
	void *ow_cb_args;

} btc_cm_fetch_ctx_t;

#ifdef	__cplusplus
}
#endif

extern void btc_destroy(chunkmap_handle_t chm_handle);

extern int btc_create(struct ccow_op *op, vmpack_cb_t vmpack_cb,
		      cmpack_cb_t cmpack_cb, chunkmap_handle_t *hdl,
		      uint8_t type);

extern int btc_cm_fetch(btc_cm_fetch_ctx_t *ctx);

extern int btc_update_get_node_cb(btree_t *btree, bt_node_t *node,
    bt_node_t *parent, void *context);

extern int btc_update_get_vm_cb(btree_t *btree, bt_node_t *node,
    bt_node_t *parent, void *context);

extern int btc_cm_fetch_by_pos(btc_cm_fetch_ctx_t *ctx, int *done);
#endif
