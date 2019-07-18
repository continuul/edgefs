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
#ifndef __CHUNK_H__
#define __CHUNK_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "queue.h"
#include "ccowutil.h"
#include "rtbuf.h"

struct ccow_op;
struct ccow_io;

/* Forward declaration */
struct _btc_cm_fetch_ctx_;

typedef void * chunkmap_handle_t;
typedef int (*vmpack_cb_t)(struct ccow_io *io, rtbuf_t *rl_root);
typedef int (*cmpack_cb_t)(struct ccow_io *io, rtbuf_t *rl);
typedef void (*bt_traverse_done_cb_t)(rtbuf_t *rb, void *cb_data);
typedef void (*bt_overwrite_cb)(void *arg, uint512_t *chid);

struct chunkmap {
	QUEUE item;

	/*
	 * Chunk Map name
	 */
	char *name;

	/**
	 * Create and initialize chunkmap algorithm
	 *
	 * @param op pointer to the I/O operation
	 * @returns chm_handle pointer to the private structure or NULL
	 */
	int (*create)(struct ccow_op *op, vmpack_cb_t vmpack_cb,
	    cmpack_cb_t cmpack_cb, chunkmap_handle_t *hdl);

	/**
	 * Deinitialize and free memory
	 *
	 * @param chm_handle pointer to the private structure
	 */
	void (*destroy)(chunkmap_handle_t chm_handle);

	/**
	 * Read version/chunk manifests and issue unnamed chunk GETs
	 */
	int (*traverse)(chunkmap_handle_t hdl, struct ccow_op *cont_op,
			 bt_traverse_done_cb_t cb, void *cb_data);

	/**
	 * Read version/chunk manifests and issue unnamed chunk PUTs
	 */
	int (*update)(chunkmap_handle_t hdl, struct ccow_op *cont_op,
	    bt_overwrite_cb ow_cb, void *ow_cb_arg);
};

extern QUEUE chunkmaps;

#define chunkmap_register(map) \
	static void __attribute__((constructor)) regist_ ## map(void) { \
		if (!map.create) \
			panic("the chunk map '%s' is incomplete\n", map.name); \
		QUEUE_INIT(&map.item); \
		QUEUE_INSERT_TAIL(&chunkmaps, &map.item); \
	}

/* API */
struct chunkmap *chunkmap_find(const char *name);

#ifdef	__cplusplus
}
#endif

#endif
