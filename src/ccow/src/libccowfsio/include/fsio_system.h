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
#ifndef __FSIO_SYSTEM_H__
#define __FSIO_SYSTEM_H__

#define SERVERID_CACHE_FILE "%s/var/run/serverid.cache"
#define MAX_SERVER_ID_STR 32
#define MAX_SERVER_ID 0x1FF


#define MAX_NAME_LEN 256
#define MAX_PATH_LEN 1024
/* Read MAX_READIR_ENTRIES_AT_A_TIME and call readdir callback. */
#define MAX_READIR_ENTRIES_AT_A_TIME 64

#include "fsio_debug.h"
#include "fsio_inode.h"
#include "fsio_listcache.h"

/* Bucket attributes used.
 * Except for the file_object_transparency all are inherited by the objects.
 */
typedef struct __bucket_attrs__
{
	uint32_t    chunk_size;
	uint8_t     chunkmap_btree_marker;
	uint8_t     replication_count;
	uint8_t     sync_put;
	uint8_t     file_object_transparency;
	uint8_t     ec_enabled;
	uint32_t    ec_data_mode;
	uint64_t    ec_trg_policy;
}bucket_attrs;


/**
 * In memory super block for the filesystem.
 */
struct fsio_super {
	char ccow_serverid[UINT128_BYTES * 2 + 1];
	uint64_t inode_serverid;
	uint64_t last_inode_ts;
	pthread_mutex_t inode_gen_mutex;
	char *root_obj_dir_name;
	char cid[2048], tid[2048], bid[2048];
	size_t cid_size, tid_size, bid_size;
	void *tc_pool_handle;
	fsio_up_callback up_cb;
	void *up_cb_args;
	QUEUE export_list_q;
	bucket_attrs bk_attrs;
	ccow_snapview_t sv_handle;
	uint64_t objects_genid;

	api_stats api_debug_stats[MAX_FSIO_API];

	/* Quota support bytes limit and objects limit */
	uint64_t quota_bytes, quota_count;
	int64_t used_bytes, used_count;
	int64_t used_bytes_diff, used_count_diff;
	ccow_shard_context_t stats_list_context;

	/*
	 * Shard context for inode recovery table, whose entries log
	 * inodes orphaned during move/delete operations
	 */
	ccow_shard_context_t recovery_context;

	/*
	 * Unexpected errors from ccow calls returned as EIO, but actual
	 * return value have to be stored in ccow_err. Can be read, by
	 * ccow_fsio_err().
	 */
	int ccow_err;

	/* In memory inode cache, open FDs and flusher thread related stuff */
	QUEUE open_files_head;
	pthread_mutex_t queue_mutex;

	libccowfsio_inode_cache inode_cache;
	pthread_mutex_t rename_mutex;

	fsio_list_cache_t fsio_list_cache;

	pthread_t flusher_thread;
	int flusher_run;

	QUEUE s3dirs_head; /* List of pseudo dirs for S3. */
};

struct s3dir {
	char *path;	/* From S3 root to this dir, w/o ending slash. */
	char *name;	/* Just pointer to last path chunk. */
	uint64_t expire_us; /* Expiration time after each we need to drop cache */
	inode_t ino;	/* Inode number. */
	ccowfs_inode *inode;
	inode_t parent_ino; /* Parent S3 dir inode number */
	QUEUE q_fld;
};

extern Logger fsio_lg;
extern void *tc_pool_handle;
extern int ccow_mh_immdir;

/**
 * Get new unique inode number
 */
int ccow_fsio_get_new_inode_number(ci_t *ci, ccow_fsio_inode_type type,
    uint64_t *inode_number);

/**
 * Find existing FSIO export based on the cluster/tenent/bucket
 * out_ci is set to NULL if the export is not present.
 */
int ccow_fsio_find_export(char *cid, size_t cid_size, char *tid,
    size_t tid_size, char *bid, size_t bid_size, ci_t **out_ci);

/**
 * Start and stop control thread.
 */
int fsio_control_thread_start(void **handle);
int fsio_control_thread_stop(void *handle);

static int64_t
atomic_get_int64(int64_t *x)
{
	return ((int64_t)atomic_get_uint64((uint64_t *)x));
}

int s3dir_mkpath(ci_t *ci, inode_t parent_ino, char *name, char **path);
int find_cached_s3dir_by_ino(ci_t *ci, inode_t ino, struct s3dir **s3dir);
int find_cached_s3dir_by_path(ci_t *ci, const char *path, struct s3dir **s3dir);
int s3dir_add(ci_t *ci, inode_t parent_ino, char *name, struct s3dir **out_s3dir);
int s3dir_expire_check(struct s3dir *d);
void s3dir_invalidate_all(ci_t *ci);
int s3dir_free_cache(ci_t *ci);

#endif /* __FSIO_SYSTEM_H__ */
