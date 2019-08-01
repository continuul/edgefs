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
#ifndef objio_h
#define objio_h

#ifdef __cplusplus
extern "C" {
#endif

#include "ccow.h"
#include "param.h"

#define CCOW_STREAMSESSION_MAXOPTS 10000

#define CCOW_O_REPLACE 1
#define CCOW_O_CREATE  2

#define MAX_ITEM_SIZE 2048

typedef struct objio_info {
	ccow_t tc;
	int kv;
	uint32_t chunk_size;
	uint16_t btree_order;
	uint16_t num_vers;
	uint8_t rep_count;
	uint8_t sync_put;
	uint64_t expiration;
	int oflags;
	int autocommit;
	size_t logical_size;
	char chunk_map[32];
	char key[MAX_ITEM_SIZE];
	size_t key_size;
	char tid_cid[MAX_ITEM_SIZE];
	char cid[MAX_ITEM_SIZE];
	char bid[MAX_ITEM_SIZE], oid[MAX_ITEM_SIZE];
	int tid_cid_size, cid_size, bid_size, oid_size;
	ccow_lookup_t start_iter;
	ccow_completion_t c;
	int io_count;
	int multipart;
	int file;
	int max_io_count;
	int cont_flags;
	uint64_t genid;
	uint64_t size;
	uint64_t multipart_size;
	uint64_t file_size;
	uint8_t deleted;
	uint64_t quota_bytes;
	uint64_t quota_count;
	uint64_t object_count;
	int writes;
	char content_type[MAX_ITEM_SIZE];
	char etag[MAX_ITEM_SIZE];
	uint64_t uvid;
	uint512_t nhid;
	uint512_t vmchid;
	char vmchid_str[UINT512_BYTES*2+1];
	param_vector *attrs;
} objio_info_t;

int objio_create(ccow_t tc, char *tid_cid, int tid_cid_size, char *bid, int bid_size, char *oid, int oid_size,
		int max_io_count, objio_info_t **ci_out);

void objio_destroy(objio_info_t *ci);

int objio_create_new(objio_info_t *ci, int replace, param_vector *attrs);

int objio_open(objio_info_t *ci);

void objio_close(objio_info_t *ci, int cancel);

int objio_pread(objio_info_t *ci, char *buf, size_t len, uint64_t off);

int objio_pwrite(objio_info_t *ci, void *buf, uint32_t length, uint64_t off);

int objio_kvput(objio_info_t *ci, void *key, uint64_t key_len,  void *value, uint64_t value_len);

int objio_kvput_ext(objio_info_t *ci, void *key, uint64_t key_len, void *value, uint64_t value_len,
	char *timestamp, char *content_type);

int objio_kvdel(objio_info_t *ci, void *key, uint64_t key_len);

int objio_kvlist(objio_info_t *ci, char *prefix, char *marker, char **key, char **value, uint32_t *count, uint32_t *total);

int objio_kvlist_keys(objio_info_t *ci, char *prefix, char *marker, char **key, uint32_t *count, uint32_t *total);

int objio_kvget(objio_info_t *ci, char *key, void *arg, char *(*alloc_buf)(void *arg, uint32_t size),
	char **value, uint32_t *nout, char *content_type, uint32_t content_max);

int objio_delete(objio_info_t *ci);

int objio_bucket_create(objio_info_t *ci, param_vector *attrs);

int objio_bucket_delete(objio_info_t *ci);

int objio_bucket_head(objio_info_t *ci);

int objio_get_attributes(objio_info_t *ci, char *bid, int bid_size, char* oid, int oid_size);

uint64_t trlog_marker_timestamp(char *cluster);

#ifdef __cplusplus
}
#endif

#endif
