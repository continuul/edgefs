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
#ifndef __CCOW_FSIO_DIR_H__
#define __CCOW_FSIO_DIR_H__

/**
 *
 * Create two sharded lists per directory.
 *   [dir_list] To maintain the list of children. Key is the file name and
 *	value is the inode number.
 *   [dir_attr] Second object to maintain the attributes.
 * Attributes will be maintained in two separate ways.
 *   [A] Attributes which must be overwritten or are read only.
 *       uid, gid, mode, atime, mtime, ctime
 *       device id, rdev, inode number, block_size
 *       These are saved as btree key:value entries on the [dir_attr] shard.
 *   [B] Attributes which are increased/decreased.
 *       link count, size, blocks_used (this is actually function of size)
 *       These are saved as  metadata on the [dir_attr] shard.
 *       These attributes have API to increase, decrease the attr value.
 *      Three metadata attributes are already supported by sharded list.
 *       object_count :  maintain the link count of the directory.
 *       size : to maintain the directory size (This is a function of number of
 *           entries in the directory)
 *       blocks_used: Unused for FSIO directories. We derive the blocks used
 *           from the size attribute.
 * Locking:
 *     No need to lock the shard for parallel add/remove children and changing
 *     the attributes.  It is still required to guard the shard across
 *     add/remove children and the specific directory delete itself.  Take the
 *     inode lock in shared mode for all operations except for the directory
 *     delete.  For directory delete take the inode lock in exclusive mode.
 *     The attributes which are increased/decreased (link count, size) must be
 *     some using atomic functions.
 * get_attr/set_attr:
 *     Fetching the attributes from disk happens only when the inode is not
 *     present in cache.  Set attr on directory is not frequent, and it can
 *     change multiple attributes at atime.  Take inode lock in exclusive mode
 *     for get/set attrs from/to disk.  Since set attr can update multiple
 *     attributes, we need to serialize multiple parallel set attrs.  Since
 *     same lock is used, at present we serialize set attr with any
 *     inserts/deletes too.  This is safer and anyway setattr on directory is
 *     not that frequent.
 * Directory empty:
 *     The object count is not maintained on the directory. The directory size
 *     is function of number of children.  The directory size is used to
 *     determine if directory is empty or not.
 * [TBD]
 * 1. ccow_sharded_list_put() supports adding only one key:value pair at a time.
 *    When this changes, we can set multiple attributes at a time.
 * 2. Re-validate the locking for rename.
 */


/**
 * Create directory shards
 */
int ccow_fsio_dir_create(ccowfs_inode *inode);

/**
 * Add the file/sub-dir entry in the shard list
 * Increment link count of parent_inode by link_add
 */
int ccow_fsio_dir_add_entry(ci_t *ci, ccowfs_inode *parent_inode, char *name,
    ccowfs_inode *child_inode, int link_add);

/**
 * Remove the child entry from the shard list
 * Decrement link count of parent_inode by link_subtract
 */
int ccow_fsio_dir_remove_entry(ci_t *ci, ccowfs_inode *parent_inode,
    char *name, int link_subtract);

/**
 * Rename
 */
int ccow_fsio_dir_move(ci_t *ci, ccowfs_inode *oldparent_inode, char *oldname,
    ccowfs_inode *newparent_inode, char *newname);

/**
 * rmdir
 */
int ccow_fsio_dir_delete(ccowfs_inode *inode);

int ccow_fsio_dir_lookup(ci_t *ci, ccowfs_inode *parent_inode, char *name,
    inode_t *out_ino);

/**
 * Push the in memory inode stats to disk
 */
int ccow_fsio_dir_set_attr(ccowfs_inode *inode);

/**
 * Populate the in memory inode stats based on on disk attributes.
 */
int ccow_fsio_dir_fetch_attr(ccowfs_inode *inode);

/**
 * The directory is deleted.
 * The shard will be deleted when the last ref goes away.
 *
 * ccow_fsio_dir_if_empty_mark_deleted
 * includes the check for empty directory
 */
int ccow_fsio_dir_mark_deleted(ccowfs_inode *inode);

int ccow_fsio_dir_is_empty(ccowfs_inode * inode);

int ccow_fsio_dir_if_empty_mark_deleted(ccowfs_inode *inode);

/**
 * Update the in memory inode with the shard context
 * Create the shard names based on the inode number.
 */
int ccow_fsio_dir_context_create(ccowfs_inode *inode);

/**
 * readdir
 */
int ccow_fsio_dir_readdir_cb4(ci_t *ci, inode_t parent_ino, char *start,
    ccow_fsio_readdir_cb4_t cb, void *ptr, bool *eofptr);
int ccow_fsio_dir_find(ci_t * ci, inode_t parent_ino, inode_t ino, char *res, int res_max);
int ccow_fsio_add_list_cache(ci_t * ci, inode_t parent, inode_t child, char *name);


#endif /* __CCOW_FSIO_DIR_H__ */
