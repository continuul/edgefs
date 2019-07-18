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
#ifndef __FSIO_COMMON_H__
#define __FSIO_COMMON_H__

#define    MAX(a, b) (((a) > (b))?(a):(b))
#define    MIN(a, b) (((a) < (b))?(a):(b))

struct chunk_context {
	char *ma_bufs;
	uint64_t s0;
	uint64_t s1;
	uint64_t s2;
	size_t l0;
	size_t l1;
	size_t l2;
	char *buf;
};

int set_btree(ccow_completion_t c, ccow_lookup_t iter);
int parse_nfs_inode(void *value, size_t value_size, inode_t *ino);
int ccow_fsio_is_dir(ci_t *ci, inode_t inode);
void ccow_fsio_free(ci_t *ci, void *obj);
int ccow_fsio_err(ci_t *ci);
int list_remove(ccow_t tc, const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, char *obj_name,
    char *key);
int list_insert(ccow_t tc, const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, char *obj_name,
    char *key, const char *value);

/**
 * ccowfs_create_completion
 *  Helper function to retry completion creation after flushing open completions
 */
int ccowfs_create_completion(ci_t *ci, void *cb_arg,
    ccow_callback_t cb_complete, inode_t ino, ccow_completion_t *c);
int ccowfs_create_stream_completion(ci_t *ci, char *oid, size_t oid_size,
    uint64_t *genid, uint64_t op_count, inode_t ino,
	ccow_completion_t *c, ccow_lookup_t *iter);
void flusher_sync_fsstat(ci_t * ci);

#endif /* __FSIO_COMMON_H__ */
