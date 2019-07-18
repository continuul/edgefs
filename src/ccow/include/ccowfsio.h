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

#ifndef __LIBCCOWFSIO_H_
#define __LIBCCOWFSIO_H_

#ifdef	__cplusplus
extern "C"
{
#endif

#define	CCOW_FSIO_ROOT_INODE 2
#define CCOW_FSIO_S3OBJ_DIR_INODE 3
#define CCOW_FSIO_LOST_FOUND_DIR_INODE 4
#define ROOT_INODE_STR (".nexenta_nedge_nfs_root_2")
#define LOST_FOUND_INODE_STR (".nexenta_nedge_nfs_lost_found_4")
#define LOST_FOUND_DIR_NAME (".lost+found")
#define S3OBJECTS_DIR_NAME (".objects")
#define LOST_FOUND_DIR_MODE (S_IFDIR | (00777))
#define FSIO_DIR_SHARD_COUNT 4
#define	FLUSHER_STAT_OBJ ".nexenta_nedge_nfs_stat_counter"
#define RECOVERY_TABLE_STR (".nexenta_nedge_nfs_inode_recovery")
#define RECOVERY_TABLE_SHARD_COUNT 16
#define INODE_OBJECT_LOOKUP (".nexenta_inode2oid")
#define INODE_MASTER_STR (".nexenta_nedge_nfs_inode_master")
#define SNAPVIEW_OID (".nexenta_nedge_nfs_snapview")
#define NULL_OID ("(null)")


#define	X_FILE_MODE	"X-file-mode"
#define	X_FILE_UID	"X-file-uid"
#define	X_FILE_GID	"X-file-gid"
#define	X_FILE_SYMLINK	"X-file-symlink"
#define	X_FILE_SIZE	"X-file-size"
#define	X_FILE_REFCOUNT	"X-file-recount"
#define	X_LAST_INODE	"X-last-inode"
#define	X_FILE_ATIME	"X-file-atime"
#define	X_FILE_CTIME	"X-file-ctime"
#define	X_FILE_MTIME	"X-file-mtime"
#define X_FILE_SNAP_COUNT "X-file-snap-count"

#include "ccow.h"
#include "ccowutil.h"
#include "queue.h"

#define SNAP_CREATE_PARAM_COUNT     5
#define SNAP_DELETE_PARAM_COUNT     5
#define SNAP_LIST_PARAM_COUNT       4
#define SNAP_ROLLBACK_PARAM_COUNT   5
#define CLONE_FILE_PARAM_COUNT      7
#define LOG_STATS_PARAM_COUNT       3
#define SET_LOG_LEVEL_PARAM_COUNT	2

/* Control flags for clone */
#define CLONE_FILE_FLAG_GUARDED                 0x01
#define CLONE_FILE_FLAG_LAZY                    0x02
#define CLONE_FILE_FLAG_SRCDATASTORE_VALID      0x04
#define CLONE_FILE_FLAG_DRYRUN                  0x08
#define CLONE_FILE_FLAG_SKIPZEROES              0x10

typedef enum __control_commnds__
{
	PING = 0,
	SNAP_CREATE,
	SNAP_DELETE,
	SNAP_LIST,
	SNAP_ROLLBACK,
	CLONE_FILE,
	LOG_PERFORMANCE_STATS,
	SET_LOG_LEVEL,

	MAX_CONTORL_COMMANDS
} fsio_control_cmds;

typedef enum __ccow_fsio_inode_type
{
	FSIO_INODE_FILE = 0,
	FSIO_INODE_DIR,
	FSIO_INODE_SYMINK,
	FSIO_INODE_S3OBJ
} ccow_fsio_inode_type;

#define	FSIO_INODE_MEMONLY	(1ULL << 63)

typedef struct fsio_super ci_t;

/* [TODO] We may not need ccow_fsio_file_t. Just map it to inode */
typedef struct
{
	void *inode;
} ccow_fsio_file_t;

typedef uint64_t inode_t;

typedef struct
{
	char *name;
	inode_t inode;
} fsio_dir_entry;

typedef struct __fsio_fsinfo__ {
	uint64_t total_bytes;
	uint64_t free_bytes;
	uint64_t avail_bytes;
	uint64_t total_files;
	uint64_t free_files;
	uint64_t avail_files;
} fsio_fsinfo_t;

typedef int (*ccow_fsio_readdir_cb4_t) (inode_t, fsio_dir_entry *, uint64_t,
    void *ptr);

/* Forward declaration. */
struct LOGGER;
typedef struct LOGGER* Logger;

/* Allocate ci structure to user, since its size is not visible. */
ci_t *ccow_fsio_ci_alloc(void);

/* Free ci structure. */
void ccow_fsio_ci_free(ci_t *);

/**
 * FSIO init
 * Must be called just after the lib is loaded
 */
int ccow_fsio_init();

/**
 * FSIO term
 * Must be called just before the lib is unloaded
 */
int ccow_fsio_term();

typedef int (*fsio_up_callback) (void *cb_args, inode_t inode,
    uint64_t ccow_fsio_up_flags);

/**
 * CLone file on server side.
 * Create new namespace entry and new object same as the existing one.
 */
int ccow_fsio_clone_file(char *cid, char *tid, char *src_bid,
    char *dest_bid, char *src_path, char *dest_path, uint32_t flags);
/**
 * create export
 *
 * @param ci storage for struct ccow_info, to hold session info.
 * @param uri URI to bucket in form cluster/tenant/bucket.
 * @param ccow_config	path to ccow.json config file.
 * @param chunk_size	default block size (should be power of 2).
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_create_export(ci_t * ci, char *uri, char *ccow_config,
    int chunk_size, fsio_up_callback up_cb, void *up_cb_args);
/**
 *  delete export
 *
 * Terminate the session assiciated with the export.
 * Data for the export is untouched.
 * @param ci (struct ccow_info) current session params.
 */
void ccow_fsio_delete_export(ci_t * ci);

/**
 *  Get dynamic FS info.
 *
 * Get current usage of filesystem.
 * @param ci (struct ccow_info) current session params.
 * @param fsinfo (fsio_fsinfo_t *) existing structure to fill info.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_fsinfo(ci_t *ci, fsio_fsinfo_t *fsinfo);

/**
 * Get last error from CCOW layer.
 *
 * @param ci (struct ccow_info) current session params.
 * @returns CCOW error code.
 */
int ccow_fsio_err(ci_t * ci);

/**
 * Prepare to file Read/Write.
 *
 * @param ci (struct ccow_info) current session params.
 * @param path to file subject of Read/Write operations.
 * @param file pointer.
 * @param openflags flags defining desired access and behaviour (unused yet).
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_open(ci_t * ci, char *path, ccow_fsio_file_t ** file,
    int openflags);

/**
 * Prepare to file Read/Write.
 *
 * @param ci (struct ccow_info) current session params.
 * @param inode to file subject of Read/Write operations.
 * @param file pointer to get new .
 * @param openflags flags defining desired access and behaviour (unused yet).
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_openi(ci_t * ci, inode_t inode, ccow_fsio_file_t ** file,
    int openflags);


/**
 * Get file size
 */
int ccow_fsio_get_size(ccow_fsio_file_t * file, size_t * size);

/**
 * Perform file read.
 *
 * @param file pointer.
 * @param offset from which to start read.
 * @param buffer_size size of buffer to receive data.
 * @param buffer pointer to memory where to copy received data.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_read(ccow_fsio_file_t * file, size_t offset,
    size_t buffer_size, void *buffer, size_t * read_amount, int *eof);

/**
 * Perform file write.
 *
 * @param file pointer.
 * @param offset position at which to start write.
 * @param buffer_size size of data buffer to write.
 * @param buffer pointer to memory where is data located.
 * @param write_amount pointer to size_t integer which will get amount of received data.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_write(ccow_fsio_file_t * file, size_t offset,
    size_t buffer_size, void *buffer, size_t * write_amount);
/**
 * Perform file IO sync.
 *
 * @param file pointer.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_flush(ccow_fsio_file_t * file);

/**
 * End file Read/Write.
 *
 * @param file pointer.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_close(ccow_fsio_file_t * file);

/**
 * Check if file with path "path" exists.
 *
 * @param ci (struct ccow_info) current session params.
 * @param path to file.
 * @returns 1 if exists, 0 otherwise.
 */
int ccow_fsio_exists(ci_t * ci, char *path);

/**
 * Check if node is derectory.
 *
 * @param ci (struct ccow_info) current session params.
 * @param inode unique file identifier.
 * @returns 1 if directory, 0 otherwise.
 */
int ccow_fsio_is_dir(ci_t * ci, inode_t inode);

/**
 * Apply file info from data in struct stat.
 *
 * @param ci (struct ccow_info) current session params.
 * @param inode unique file identifier.
 * @param stat pointer to struct stat.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_set_file_stat(ci_t * ci, inode_t inode, struct stat *stat);

/**
 * Get file info into struct stat.
 *
 * @param ci (struct ccow_info) current session params.
 * @param inode unique file identifier.
 * @param stat pointer to struct stat.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_get_file_stat(ci_t * ci, inode_t inode, struct stat *stat);

/**
 * Find inode of file named "name" inside directory "dir".
 *
 * @param ci (struct ccow_info) current session params.
 * @param dir directory's unique identifier.
 * @param name of file to find.
 * @param inode pointer for unique file identifier of file if found.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_lookup(ci_t * ci, inode_t dir, char *name, inode_t * inode);

/**
 * Traverse directory referenced by "inode", and call callback "cb" on each entry
 * with parent inode, entry inode and entry's name as argument, starting from
 * position "start".
 *
 * @param ci (struct ccow_info) current session params.
 * @param parent directory's unique file identifier.
 * @param cb pointer to callback function of type
 *	(ccow_fsio_readdir_cb4_t type).
 * @param start name of entry to contine from.
 * @param ptr pointer to user data supplied to callback function as 4th arg.
 * @param eof pointer to EOF flag
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_readdir_cb4(ci_t * ci, inode_t parent,
    ccow_fsio_readdir_cb4_t cb, char *start, void *ptr, bool *eof);

/**
 * Find cached list entry name referenced by "parent_ino" and child ino.
 *
 * @param ci (struct ccow_info) current session params.
 * @param parent_ino directory's unique file identifier.
 * @param ino child inode.
 * @param res result output buffer.
 * @param res_max res maximum size
 * @returns 1 - entry found in cache, 0 - entry found i cluster, -ENOENT entry not found, < 0  search error.
 */
int ccow_fsio_find_list(ci_t * ci, inode_t parent_ino, inode_t ino, char *res, int res_max);


/**
 * Add entry to list cache referenced by "parent_ino" and child ino.
 *
 * @param ci (struct ccow_info) current session params.
 * @param parent directory's unique file identifier.
 * @param child - child inode.
 * @param name - name to cache.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_add_list_cache(ci_t * ci, inode_t parent, inode_t child, char *name);

/**
 * Delete directory "parent" entry with name "name" and delete object pointed
 * by "name" entry if no other names pinting to that object (refcount == 0).
 *
 * @param ci (struct ccow_info) current session params.
 * @param parent directory unique file identifier.
 * @param name of file to delete.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_delete(ci_t * ci, inode_t parent, char *name);

/**
 * Create new node of type directory inside directory "parent".
 *
 * @param ci (struct ccow_info) current session params.
 * @param parent directory unique file identifier.
 * @param name of new directory.
 * @param mode access mode of new directory.
 * @param uid owner ID of new directory.
 * @param gid group ID of new directory.
 * @param inode pointer to unique file identifier of newly created node.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_mkdir(ci_t * ci, inode_t parent, char *name,
    uint16_t mode, uint16_t uid, uint16_t gid, inode_t * newnode);
/**
 * Create new node of type regular file inside directory "parent".
 *
 * @param ci (struct ccow_info) current session params.
 * @param parent directory unique file identifier.
 * @param name of new file.
 * @param mode access mode of new file.
 * @param uid owner ID of new file.
 * @param gid group ID of new file.
 * @param inode pointer to unique file identifier of newly created node.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_touch(ci_t * ci, inode_t parent, char *name,
    uint16_t mode, uint16_t uid, uint16_t gid, inode_t * newnode);
/**
 * Create new node of type symbolic link inside directory "parent".
 *
 * @param ci (struct ccow_info) current session params.
 * @param parent directory unique file identifier.
 * @param name of new symlink.
 * @param mode access mode of new symlink.
 * @param uid owner ID of new symlink.
 * @param gid group ID of new symlink.
 * @param inode pointer to unique file identifier of newly created node.
 * @param link path to linked node.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_mksymlink(ci_t * ci, inode_t parent, char *name,
    uint16_t mode, uint16_t uid, uint16_t gid, inode_t * newnode, char *link);
/**
 * Read symbolic link content.
 *
 * @param ci (struct ccow_info) current session params.
 * @param inode of the symlink file.
 * @param link pointer to set.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_readsymlink(ci_t * ci, inode_t inode, char **link);

/**
 * Free ccow_fsio allocated object.
 * Used in pair with ccow_fsio_readsymlink, since it return allocated object.
 *
 * @param ci (struct ccow_info) current session params.
 * @param obj to free.
 */
void ccow_fsio_free(ci_t * ci, void *obj);

/**
 * Find file by its full path.
 *
 * @param ci (struct ccow_info) current session params.
 * @param path full path to file.
 * @param inode pointer to unique file identifier if found.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_find(ci_t * ci, char *path, inode_t * inode);

/**
 * Change node's name and/or parent directory.
 *
 * @param ci (struct ccow_info) current session params.
 * @param oldparent unique file identifier of source parent directory.
 * @param oldname old name of file inside source parent directory.
 * @param newparent unique file identifier of destenation parent directory.
 * @param newname name of file inside destenation parent directory.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_move(ci_t * ci, inode_t oldparent, char *oldname,
    inode_t newparent, char *newname);
/**
 * Delete directory "parent" entry with name "name".
 *
 * @param ci (struct ccow_info) current session params.
 * @param parent directory unique file identifier.
 * @param name of file which link to delete.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_unlink(ci_t * ci, inode_t oldparent, char *oldname);

/**
 * Create new link (name) of node "inode" with name "newname" under directory
 * with ID "newparent".
 *
 * @param ci (struct ccow_info) current session params.
 * @param parent directory unique file identifier.
 * @param name new name of file.
 * @param inode of existing object.
 * @returns 0 on success, or standard error code (errno(3)) if fail.
 */
int ccow_fsio_link(ci_t * ci, inode_t newparent, char *newname, inode_t inode);


/**
 * Create object to maintain server id string to numberic server id map.
 */
int ccow_fsio_get_inode_master(ccow_t tc, const char *cid, size_t cid_size,
    const char *tid, size_t tid_size, const char *bid, size_t bid_size,
    const char *server_id_str, uint64_t * inode_server_id);

int ccow_fsio_create_bucket(ccow_t tc, const char *bucket_uri, Logger fsio_lg);
int ccow_fsio_delete_bucket(ccow_t tc, const char *bucket_uri, Logger fsio_lg);
int ccow_fsio_is_not_empty(ccow_t tc, const char *bucket_uri, Logger fsio_lg);

int testonly_remove_inode_from_cache(ci_t * ci, inode_t inode);
int testonly_remove_inode_from_cache_by_ref(ci_t * ci, void *inode_ref);
int testonly_get_inode_ref(ci_t * ci, inode_t ino, void **inode_ref);
int testonly_put_inode_ref(ci_t * ci, void *inode_ref);
int testonly_fetch_inode(ci_t * ci, inode_t ino, int sync);
int testonly_refresh_inode(ci_t *ci, inode_t inode);
int testonly_create_inode(ci_t* ci, inode_t parent_ino, char *name, uint16_t mode,
    uint16_t uid, uint16_t gid, inode_t * newnode_ino, char *link);
int testonly_dir_add_entry(ci_t *ci, inode_t parent_ino, char *name,
    inode_t child_ino, int link_count);
int testonly_dir_remove_entry(ci_t *ci, inode_t parent_ino, char *name,
    int link_count);
int testonly_inode_mark_deleted(ci_t *ci, inode_t ino);
int testonly_inode_delete_unsafe(ci_t *ci, inode_t parent_ino, char *name,
    inode_t child_ino);
int testonly_inode_unlink_by_ref(ci_t *ci, void *inode_ref, int mark_deleted,
    int do_flush);
int testonly_inode_purge_by_ref(ci_t *ci, void *inode_ref);
int testonly_get_inode_ref_for_recovery(ci_t * ci, inode_t ino,
    void **inode_ref);
int testonly_recovery_entry_exists(ci_t *ci, inode_t ino, int type);
int testonly_recovery_insert_moved(ci_t *ci, inode_t child_ino,
    inode_t src_ino, char *old_name, inode_t dest_ino, char *new_name,
    nlink_t linkcount, uint64_t timestamp);
int testonly_recovery_insert_deleted(ci_t *ci, inode_t ino, inode_t parent_ino,
    char *name, nlink_t linkcount, uint64_t timestamp);
int testonly_recovery_remove_entry(ci_t *ci, inode_t ino);
int testonly_recovery_handler(ci_t *ci);

#define INODE_IS_DISK_DIR(inode_number)	\
    ((((inode_number) & 0x3000000000000000ULL) >> 60) == FSIO_INODE_DIR || \
    inode_number == CCOW_FSIO_ROOT_INODE || \
    inode_number == CCOW_FSIO_LOST_FOUND_DIR_INODE)
#define INODE_IS_DIR(inode_number)	\
    ((((inode_number) & 0x3000000000000000ULL) >> 60) == FSIO_INODE_DIR || \
    inode_number == CCOW_FSIO_ROOT_INODE || \
    inode_number == CCOW_FSIO_S3OBJ_DIR_INODE || \
    inode_number == CCOW_FSIO_LOST_FOUND_DIR_INODE)
#define INODE_IS_FILE(inode_number)	\
    ((((inode_number) & 0x3000000000000000ULL) >> 60) == FSIO_INODE_FILE && \
    (inode_number != CCOW_FSIO_ROOT_INODE) && \
    (inode_number != CCOW_FSIO_S3OBJ_DIR_INODE) && \
    (inode_number != CCOW_FSIO_LOST_FOUND_DIR_INODE))
#define INODE_IS_SYMLINK(inode_number)	\
    ((((inode_number) & 0x3000000000000000ULL) >> 60) == FSIO_INODE_SYMINK && \
    (inode_number != CCOW_FSIO_ROOT_INODE) && \
    (inode_number != CCOW_FSIO_S3OBJ_DIR_INODE) && \
    (inode_number != CCOW_FSIO_LOST_FOUND_DIR_INODE))
#define INODE_IS_S3OBJ(inode_number)	\
    ((((inode_number) & 0x3000000000000000ULL) >> 60) == FSIO_INODE_S3OBJ)

#ifdef	__cplusplus
}
#endif
#endif /* __LIBCCOWFSIO_H_ */
