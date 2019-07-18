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
#ifndef __TRLOG_H__
#define __TRLOG_H__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#include "json.h"
#include "ccowutil.h"
#include "msort.h"
#include "ccow.h"
#include "hashtable.h"
#include "msgpackalt.h"

#define TRLOG_MARKER_MAXSIZE	(1 * 1024 * 1024)
#define MARKER_RECORD_MAXSIZE	1024

#define	TRLOG_OBJ_CREATE	0x0001
#define TRLOG_OBJ_DELETE	0x0002
#define TRLOG_OBJ_UPDATE	0x0004
#define TRLOG_DIR_CREATE	0x0010
#define TRLOG_DIR_DELETE	0x0020
#define TRLOG_DIR_UPDATE	0x0040
#define TRLOG_SKIP_BTN_UPDATE	0x0100
#define TRLOG_VERSION_EXPUNGE	0x0200
#define TRLOG_EXPUNGE		0x0400
#define TRLOG_ISGW_UPDATE	0x1000

#define SHARD_LEADER_PREFIX		"shard.leader."

#define TRLOG_INTERVAL_DEFAULT_US	10000000UL // 10s
#define TRLOG_PROCESSING_QUARANTINE	1  // Number of trlog processing quarantine delays
#define TRLOG_PROCESSING_QUARANTINE_MAX	8

#define TRLOG_OLD_RESULT_MAX		64

#ifdef	__cplusplus
extern "C" {
#endif

struct trlog_data {
	uint128_t serverid;
	uint128_t vdevid;
	uint32_t trtype;
	uint512_t nhid;
	uint512_t phid;
	uint512_t vmchid;
	uint64_t timestamp;
	uint64_t generation;
	int64_t deltasize;
	char *cid;
	char *tid;
	char *bid;
	char *oid;
	uint64_t size;
	uint8_t object_deleted;
	char *etag;
	char *content_type;
	uint64_t multipart_size;
	uint64_t inode;
	char *owner;
	char *srcip;
};
int trlog_pack(msgpack_p *p, struct trlog_data *data);
int trlog_unpack(msgpack_u *u, struct trlog_data *data);
int trlog_extract_key(char *key, int len, struct trlog_data *data, int partial);

#define MEMFREE_TRLOG_DATA(_rec) \
	if (_rec.cid) \
		je_free(_rec.cid); \
	if (_rec.tid) \
		je_free(_rec.tid); \
	if (_rec.bid) \
		je_free(_rec.bid); \
	if (_rec.oid) \
		je_free(_rec.oid); \
	if (_rec.etag) \
		je_free(_rec.etag); \
	if (_rec.content_type) \
		je_free(_rec.content_type); \
	if (_rec.owner) \
		je_free(_rec.owner); \
	if (_rec.srcip) \
		je_free(_rec.srcip); \
	_rec.cid = _rec.tid = _rec.bid = _rec.oid = _rec.etag = _rec.content_type = _rec.owner = _rec.srcip = NULL;


#define TRLOG_KEY_LEN	32768
#define TRLOG_TSOBJ_MAX_ENTRIES	(is_embedded() ? 30000 : CCOW_IOVCNT_MAX_EMBEDDED)

struct trlog_handle
{
	hashtable_t *old_result_ht;
	int old_result_cnt;
	struct mlist_node *old_result_head;
	struct mlist_node *old_result_last;
	struct mlist_node *back[TRLOG_PROCESSING_QUARANTINE_MAX];
	int back_cnt;
};

typedef int (*trlog_phid_check_cb_t)(uint512_t *phid, void *arg);

void trlog_init(struct trlog_handle *hdl);

void trlog_destroy(struct trlog_handle *hdl);

int trlog_mlist_get(struct trlog_handle *hdl, ccow_t tc, uint64_t batch_seq_ts,
    struct mlist_node **final_result_head, uint64_t *count,
    trlog_phid_check_cb_t check_func, void *check_func_phid);

void trlog_mlist_done(struct trlog_handle *hdl, ccow_t tc,
    struct mlist_node *result_head, int no_add);

int trlog_read_marker(ccow_t tc, char *name, char **marker_arr,
    int *marker_arr_len);

int trlog_write_marker(ccow_t tc, char *name, char **marker_arr,
    int marker_arr_len);

int trlog_mlist_ht_exists(struct trlog_handle *hdl, struct mlist_node *node);

typedef void* trlog_search_t;

void trlog_search_free(trlog_search_t handle);

int trlog_search(ccow_t tc, uint64_t trlog_increment_ms,
    const char *tenant_uri, const char *userid, uint64_t cts_from, uint64_t cts_to,
    int max_batches, struct iovec **iov, size_t *iovcnt, trlog_search_t *handle);

int trlog_mlist_compare(void *d1, void *d2);
uint64_t trlog_mlist_count(struct mlist_node *head);
int trlog_mlist_msort(struct mlist_node *list[], int num,
	msort_compare_fn compare_cb, struct mlist_node **merge_head);
void trlog_mlist_log(char *header, struct mlist_node *head);

int
trlog_parse_marker(const char *errmsg_prefix, const char *marker_name,
		char **marker_arr, int marker_arr_len,
		uint64_t *batch_seq_ts, uint64_t *batch_seq_prev_ts);

int trlog_read_marker_seq_tss(ccow_t tc,
		const char *errmsg_prefix, char *marker_name,
		uint64_t *batch_seq_ts, uint64_t *batch_seq_prev_ts);
int trlog_write_marker_seq_tss(ccow_t tc, char *marker_name,
		uint64_t batch_seq_ts, uint64_t batch_seq_prev_ts);


#ifdef	__cplusplus
}
#endif

#endif
