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

#ifndef SRC_LIBREPTRANS_RTKVS_KVS_BACKEND_H_
#define SRC_LIBREPTRANS_RTKVS_KVS_BACKEND_H_

#ifdef REPTRANS_KVS_C
#include <uv.h>
#define iobuf_t uv_buf_t
#else
#include <stddef.h>
/* A re-definition of uv_buf_t to avoid inclusion of a libuv header */
typedef struct {
	char* base;
	size_t len;
} iobuf_t;
#endif

#include <string.h>
#include <json.h>
#include <logger.h>

/* Backend information required by rtkvs */
typedef struct kvs_backend_info {
	size_t capacity; /* Backend instance capacity, bytes */
	size_t put_bulk_size; /*( Maximum size of a put bulk */
	size_t del_bulk_size; /* Maximum size of a delete bulk */
	size_t min_value_size; /* Minimal KV value size */
} kvs_backend_info_t;

typedef void* kvs_backend_handle_t;

/* An abstract backend interface */
typedef struct kvs_backend {
	/* Backend name string */
	const char* name;

	/**
	 * Initialize a backend instance
	 *
	 * @param path   [in] is a path to KV device
	 * @param opts   [in] backend configuration options
	 * @param handle [out] a created instance handle
	 *
	 * @returns 0 on success or error code otherwise
	 *
	 * JSON option object is optional and can be NULL. Options are defined
	 * in rt-kvs.json
	 */
	int (*init) (const char* path, json_value *opts, kvs_backend_handle_t* handle);

	/**
	 * Retrieve backend information.
	 *
	 * @param handle [in]   a backend handle
	 * @param bm_info [out] a backend information
	 * @returns 0 on success or error code otherwise
	 */
	int (*info) (kvs_backend_handle_t handle, kvs_backend_info_t* info);

	/**
	 * De-initialize the backend instance
	 * To be called only once to destroy the provided backend instance.
	 * The handle isn't valid anymore after the call.
	 *
	 * @param handle [in] a backend handle.
	 *
	 */
	void (*exit) (kvs_backend_handle_t handle);

	/*
	 * Get a KV value by a key
	 *
	 * @param handle [in]  a backend handle
	 * @param ttag   [in]  a type tag
	 * @param key    [in]  value's key
	 * @param value  [out] output value
	 *
	 * NOTE: value memory buffer to be allocated by a caller
	 */
	int (*get) (kvs_backend_handle_t handle, int8_t ttag, iobuf_t key,
		iobuf_t* value);

	/*
	 * Put a number of KV pairs to the store
	 *
	 * @param handle [in] a backend handle
	 * @param ttag   [in] type tag
	 * @param keys   [in] array of rtkvs keys
	 * @param values [in] array of rtkvs values
	 * @param n_entries [in[ keys/values array size
	 * @returns 0 on success or error code otherwise
	 *
	 * The call must guarantee atomicity: no KV pairs will be kept in a store
	 * if at least one put fails.
	 */
	int (*put) (kvs_backend_handle_t handle, int8_t ttag, iobuf_t* keys,
		iobuf_t* values, size_t n_entries);

	/**
	 * Delete a number of KV pairs
	 *
	 * @param handle    [in] a backend handle
	 * @param ttag      [in] a type tag
	 * @param keys      [in] an array of backend keys to be deleted
	 * @param n_entries [in] keys array size
	 * @returns 0 on success or error code otherwise
	 */
	int (*remove)(kvs_backend_handle_t h, int8_t ttag, iobuf_t* keys,
		size_t n_entries);

	/**
	 * Destroy the backend content
	 *
	 * @param handle [in] a backend handle
	 * @returns 0 on success or error code otherwise
	 */
	int (*erase) (kvs_backend_handle_t handle);
} kvs_backend_t;
#endif /* SRC_LIBREPTRANS_RTKVS_KVS_BACKEND_H_ */
