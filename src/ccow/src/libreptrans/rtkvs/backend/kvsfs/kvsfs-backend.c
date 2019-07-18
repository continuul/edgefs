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

#ifndef SRC_LIBREPTRANS_RTRD_FS_OFFLOAD_C_
#define SRC_LIBREPTRANS_RTRD_FS_OFFLOAD_C_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <kvs-backend.h>


#define KVSFS_MIN_VALUE_SIZE 1
#define KVSFS_DEL_BULK_SIZE 128
#define KVSFS_PUT_BULK_SIZE 128
#define KVSFS_RESERVED_BLOCKS 5 /* number of reserved blocks for root, % */

struct kvsfs_handle {
	volatile int term;
	char* path;
	size_t capacity;
};

typedef struct kvsfs_handle* kvsfs_handle_t;

int
kvsfs_init(const char* path, json_value *o, kvs_backend_handle_t* handle) {
	struct stat st;
	struct statvfs vstat;
	if (!path || !strlen(path)) {
		log_error(lg, "Directory path is void");
		return -ENOENT;
	}

	int err = stat(path, &st);
	if (err && err != ENOENT)
		return -err;
	if (!err) {
		if (!S_ISDIR(st.st_mode)) {
			log_error(lg, "Specified path %s isn't a directory", path);
			return -EINVAL;
		}
	} else {
		/* Folder doesn't exist, trying to create */
		err = mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		if (err) {
			log_error(lg, "Cannot create storage folder: %s(%d)", strerror(err), err);
			return -err;
		}
	}

	err = statvfs(path, &vstat);
	if (err) {
		log_error(lg, "statvfs error: %s(%d)", strerror(err), err);
		return -err;
	}

	kvsfs_handle_t h = calloc(1, sizeof(*h));
	if (!h)
		return -ENOMEM;
	h->path = strdup(path);
	h->capacity = vstat.f_bsize * vstat.f_blocks;
	h->capacity = h->capacity - KVSFS_RESERVED_BLOCKS*h->capacity/100;
	h->term = 0;
	*handle = h;
	return 0;
}


static int
kvsfs_compose_key(int8_t ttag, iobuf_t key, iobuf_t* key_out) {
	uint8_t hdr[2] = {0};
	hdr[0] = ttag;
	char* new_key = malloc(key.len+2);
	if (!new_key)
		return -ENOMEM;
	new_key[0] = hdr[0];
	new_key[1] = hdr[1];
	memcpy(new_key+sizeof(hdr), key.base, key.len);
	key_out->base = new_key;
	key_out->len = key.len + sizeof(hdr);
	return 0;
}

#if 0
static int
kvsfs_decompose_key(int8_t* ttag, iobuf_t key, iobuf_t* key_out) {
	char* new_key = malloc(key.len-2);
	if (!new_key)
		return -ENOMEM;
	memcpy(new_key, key.base+2, key.len-2);
	*ttag = key.base[0] & 0x0F;
	key_out->base = new_key;
	key_out->len = key.len - 2;
	return 0;
}
#endif

char*
kvsfs_keytostr(iobuf_t key) {
	static const char hex_lookup[] = "0123456789ABCDEF";
	char* buff = malloc(key.len*2+1);
	char* ptr = buff;
	for (size_t i = 0; i < key.len; i++) {
		uint8_t val = key.base[i];
		*ptr++ = hex_lookup[val >> 4];
		*ptr++ = hex_lookup[val & 0x0F];
	}
	*ptr = 0;
	return buff;
}

/* IMPORTANT: for ADI API compatibility value buffer must be allocated by caller and
 * blob size is to be know in advance
 */
static int
kvsfs_get(kvs_backend_handle_t handle, int8_t ttag, iobuf_t key,
	iobuf_t* value) {
	kvsfs_handle_t h = handle;
	if (h->term)
		return -ENODEV;
	iobuf_t full_key;
	char filepath[PATH_MAX];
	int rc = kvsfs_compose_key(ttag, key, &full_key);
	assert(rc == 0);
	char* key_str = kvsfs_keytostr(full_key);
	sprintf(filepath, "%s/%s.bin", h->path, key_str);
	int fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		log_error(lg, "Cannot open blob file %s", filepath);
		return fd;
	}
	rc = read(fd, value->base, value->len);
	if (rc < 0) {
		printf("blob read error: %s (%d)\n", strerror(errno), errno);
	} else
		rc = 0;
	close(fd);
	free(key_str);
	return rc;
}

static int
kvsfs_put(kvs_backend_handle_t handle, int8_t ttag, iobuf_t* keys,
	iobuf_t* values, size_t n_entries) {
	iobuf_t full_key;
	char filepath[PATH_MAX];
	kvsfs_handle_t h = handle;
	if (h->term)
		return -ENODEV;
	int rc = 0;
	for (size_t i = 0; i < n_entries; i++) {
		int rc = kvsfs_compose_key(ttag, keys[i], &full_key);
		assert(rc == 0);
		char* key_str = kvsfs_keytostr(full_key);
		sprintf(filepath, "%s/%s.bin", h->path, key_str);
		int fd = open(filepath, O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH);
		if (fd < 0) {
			log_error(lg, "Cannot create blob file %s", filepath);
			return fd;
		}
		rc = write(fd, values[i].base, values[i].len);
		if (rc != (int)values[i].len) {
			log_error(lg, "blob file %s write error: %d\n", filepath, rc);
			rc = -EIO;
			break;
		} else
			rc = 0;
		close(fd);
		free(key_str);
	}
	return rc;
}

/* Upper layer has to know chunk size in advance and provide it for delete call */
static int
kvsfs_delete(kvs_backend_handle_t handle, int8_t ttag, iobuf_t* keys, size_t n_entries) {
	char filepath[PATH_MAX];
	iobuf_t full_key;
	kvsfs_handle_t h = handle;

	if (h->term)
		return -ENODEV;
	int rc = 0;
	for (size_t i = 0; i < n_entries; i++) {
		int rc = kvsfs_compose_key(ttag, keys[i], &full_key);
		assert(rc == 0);
		const char* key_str = kvsfs_keytostr(full_key);
		sprintf(filepath, "%s/%s.bin", h->path, key_str);
		rc = unlink(filepath);
		if (rc  < 0 && errno != ENOENT) {
			log_error(lg, "blob file %s delete error: %s(%d)", filepath, strerror(errno), errno);
			break;
		}
		rc = 0;
	}
	return rc;
}

static void
kvsfs_exit(kvs_backend_handle_t handle) {
	kvsfs_handle_t h = handle;
	if (h->term)
		return;
	free(h->path);
	free(h);
}

static int
kvsfs_info(kvs_backend_handle_t handle, kvs_backend_info_t* info) {
	kvsfs_handle_t h = handle;
	info->capacity = h->capacity;
	info->del_bulk_size = KVSFS_DEL_BULK_SIZE;
	info->put_bulk_size = KVSFS_PUT_BULK_SIZE;
	info->min_value_size = KVSFS_MIN_VALUE_SIZE;
	return 0;
}


static int
kvsfs_erase(kvs_backend_handle_t handle) {
	char cmd[1024];
	struct stat st;
	int err = -ENOENT;

	kvsfs_handle_t h = handle;
	if (!stat(h->path, &st)) {
		sprintf(cmd, "find %s -name \"*\" -print0 | xargs -0 rm -rf;", h->path);
		err = system(cmd);
		if (err)
			log_error(lg, "Dev(%s) error while cleaning up: %d",
				h->path, err);
	}
	return err;
}

kvs_backend_t kvsfs_vtbl = {
	.name = "kvsfs",
	.init = kvsfs_init,
	.info = kvsfs_info,
	.exit = kvsfs_exit,
	.get = kvsfs_get,
	.put = kvsfs_put,
	.remove = kvsfs_delete,
	.erase = kvsfs_erase
};



#endif /* SRC_LIBREPTRANS_RTRD_FS_OFFLOAD_C_ */
