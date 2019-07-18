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
#ifndef __CCOW_FSIO_CACHE_H__
#define __CCOW_FSIO_CACHE_H__

#include "fsio_disk.h"

/** Use single completion to flush all dirty pages related to an inode.
 *	Each completion can support max MAX_OP_COUNT OPs
 *	The cached pages may or may not be continuous.
 *	Each chunk takes one OP from the completion.
 *	So, not recommended to use (MAX_DIRTY_CHUNK_COUNT > MAX_OP_COUNT)
 */
#define MAX_DIRTY_CHUNK_COUNT (16)

/** The data write is always through buffer cache.
 *
 *  The buffer will be flushed on following conditions -
 *  1.  Client and/or FSAL sends commit
 *      In case of sync NFS write, then FSAL will simulate commit call.
 *  2.  There are MAX_DIRTY_CHUNK_COUNT chunks in the Buffer Cache for the inode.
 *      If there is no slot in the cache, then first the cache will be flushed.
 *  3.  The flusher thread finds the dirty pages and decides to flush them.
 */
int
fsio_buffer_cache_write(ccowfs_inode *inode, size_t offset, size_t buffer_size,
	void *buffer);

/**
 *	Read brings required pages in cache.
 *	This helps to maintain the chunk locks within the cache
 *		and allow region locking for READ/WRITE.
 *
 *  If required data is present in cache -
 *      then read will be served from cache.
 *  If Partial data is present in cache -
 *      then cache will read remaingin data and serve complete read.
 *  If no data is present in cache -
 *      then cache will read from ccow layer.
 *
 */
int
fsio_buffer_cache_read(ccowfs_inode *inode, size_t offset, size_t buffer_size,
    void *buffer, size_t *read_amount, int *eof);

/**	Flush all the dirty pages from cache.
 *	All cached pages for the inode are flushed.
 *	Cached is empty after this call.
 *
 *	client_flush is used to identify if the flush is requested by client.
 */
int
fsio_buffer_cache_flush(ccowfs_inode *inode, int client_flush);

#endif /* __CCOW_FSIO_CACHE_H__ */
