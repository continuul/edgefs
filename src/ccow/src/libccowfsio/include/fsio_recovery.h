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
#ifndef __CCOW_FSIO_RECOVERY_H__
#define __CCOW_FSIO_RECOVERY_H__

#define RECOVERY_TABLE_VERSION_2_2 1
#define RECOVERY_TABLE_VERSION_CURRENT RECOVERY_TABLE_VERSION_2_2

/* TODO: hard-coded arbitrary limit for now, change later */
#define RECOVERY_HANDLER_MAX_ENTRIES 1000
/* 80 seconds = default ganesha grace period 90 - 10 */
#define RECOVERY_HANDLER_THRESHHOLD (80 * 1000000)

typedef struct __recovery_table_entry__
{
	/* version of this entry format */
	uint8_t ver;
	/* operation executing at time of failure */
	fsio_api optype;
	/* timestamp of insertion in microseconds */
	uint64_t time;
	/* inode being operated on -- the potential orphan */
	inode_t ino;
	/* inode of parent directory */
	inode_t source_ino;
	/* inode of destination parent if operation was a move */
	inode_t dest_ino;
	/* name under parent */
	char name[MAX_NAME_LEN];
	/* new name under dest parent if operation was a move */
	char new_name[MAX_NAME_LEN];
	/* link count of inode being operated on--
	 * to be used in future for hard link support
	 */
	nlink_t nlink;
} recovery_table_entry;

int ccowfs_recovery_insert_deleted(ccowfs_inode *inode,
	ccowfs_inode *parent_inode, char *name);
int ccowfs_recovery_insert_moved(ccowfs_inode *inode,
	ccowfs_inode *oldparent_inode, char *oldname,
	ccowfs_inode *newparent_inode, char *newname);
int ccowfs_recovery_remove(ccowfs_inode *inode);
int ccowfs_recovery_handler(ci_t *ci);
#endif /*__CCOW_FSIO_RECOVERY_H__*/
