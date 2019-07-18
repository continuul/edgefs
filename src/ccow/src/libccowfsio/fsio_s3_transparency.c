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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <lfq.h>

#include <ccow.h>
#include <json.h>
#include <ccowfsio.h>
#include <msgpackalt.h>

#include "fsio_inode.h"
#include "fsio_system.h"
#include "fsio_common.h"
#include "fsio_namespace.h"
#include "fsio_s3_transparency.h"
#include "tc_pool.h"


#define MAX_OID_SIZE 2048
#define S3_OBJ_ROOT_DIR_NAME ".objects"

typedef struct __s3_obj_attrs__
{
	uint8_t ver;
	uint64_t timestamp;
	uint64_t generation;
	uint64_t size;
	uint512_t vmchid;
	char etag[64];
	char content_type[128];
	uint8_t object_deleted;
	inode_t ino;

} s3_obj_attrs;

int
get_object_root_dir(ci_t * ci, char **name)
{
	int err = 0;

	log_trace(fsio_lg, "ci: %p, *name: \"%s\"", ci, *name);
	*name = je_strdup(S3_OBJ_ROOT_DIR_NAME);

	if (*name == NULL)
		err = 1;

	log_debug(fsio_lg, "completed ci: %p, *name: \"%s\"", ci, *name);

	return err;
}

static int
__parse_s3_obj_attrs(void *value, size_t value_size, s3_obj_attrs * attrs)
{
	int err;
	msgpack_u *u;
	char *e;

	log_trace(fsio_lg, "value: %p, value_size: %lu, attrs: %p",
	    value, value_size, attrs);

	/*
	 * Parse the value and get inode number for S3 objects.
	 */
	if (value_size == 0 || !value) {
		log_debug(fsio_lg, "Empty value");
		return 0;
	}

	u = msgpack_unpack_init(value, value_size, 0);
	err = msgpack_unpack_uint8(u, &attrs->ver);
	if (err) {
		log_error(fsio_lg,
		    "msgpack_unpack_uint8 return %d", err);
		goto out;
	}

	if (attrs->ver == 1) {
		err = msgpack_unpack_uint8(u, &attrs->object_deleted);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint8 return %d", err);
			goto out;
		}

		err = msgpack_unpack_uint64(u, &attrs->timestamp);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}

		err = msgpack_unpack_uint64(u, &attrs->generation);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}

		err = msgpack_unpack_uint512(u, &attrs->vmchid);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint512 return %d", err);
			goto out;
		}

		err = msgpack_unpack_str(u, attrs->etag, 64);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_str return %d", err);
			goto out;
		}

		err = msgpack_unpack_str(u, attrs->content_type, 128);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_str return %d", err);
			goto out;
		}

		err = msgpack_unpack_uint64(u, &attrs->size);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}

		err = msgpack_unpack_uint64(u, &attrs->ino);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}
	}

out:
	if (u)
		msgpack_unpack_free(u);

	log_debug(fsio_lg, "completed value: %p, value_size: %lu, "
	    "attrs: %p", value, value_size, attrs);

	return err;
}

int
parse_s3_obj_inode(void *value, size_t value_size, inode_t * ino)
{
	int err;
	s3_obj_attrs attrs = { 0 };

	log_trace(fsio_lg, "value: %p, value_size: %lu, ino: %p",
	    value, value_size, ino);
	err = __parse_s3_obj_attrs(value, value_size, &attrs);
	if (err) {
		log_error(fsio_lg,
		    "__parse_s3_obj_attrs return %d", err);
		goto out;
	}

	*ino = attrs.ino;
	assert(INODE_IS_S3OBJ(*ino));

out:
	log_debug(fsio_lg, "completed value: %p, value_size: %lu, "
	    "ino: %p", value, value_size, ino);

	return err;
}

int
parse_s3_obj_stats(ci_t * ci, void *value, size_t value_size,
    struct stat *stat)
{
	int err;
	struct timespec time;
	s3_obj_attrs attrs = { 0 };

	log_trace(fsio_lg, "ci: %p, value: %p, value_size: %lu, stat: %p", ci,
	    value, value_size, stat);
	err = __parse_s3_obj_attrs(value, value_size, &attrs);
	if (err) {
		log_error(fsio_lg,
		    "__parse_s3_obj_attrs return %d", err);
		goto out;
	}

	stat->st_mode = S_IFREG | (0444);
	stat->st_uid = 0;
	stat->st_gid = 0;
	stat->st_nlink = 1;
	stat->st_blksize = ci->bk_attrs.chunk_size;

	stat->st_size = attrs.size;
	stat->st_ino = attrs.ino;
	stat->st_blocks = (stat->st_size + S_BLKSIZE - 1) / S_BLKSIZE;

	time.tv_sec = attrs.timestamp / (1000 * 1000);

	stat->st_atime = time.tv_sec;
	stat->st_mtime = time.tv_sec;
	stat->st_ctime = time.tv_sec;

	assert(INODE_IS_S3OBJ(stat->st_ino));

out:
	log_debug(fsio_lg, "completed ci: %p, value: %p, value_size: %lu, "
	    "stat: %p", ci, value, value_size, stat);

	return err;
}

static int
__parse_s3_obj_name(void *value, size_t value_size, char **name)
{
	int err;
	uint8_t ver = 0;
	char *buf = NULL;
	msgpack_u *u = NULL;

	log_trace(fsio_lg, "value: %p, value_size: %lu, name: %p",
	    value, value_size, name);

	/*
	 * Parse the value and get inode object name.
	 */
	if (value_size == 0 || !value) {
		err = ENOENT;
		goto out;
	}

	u = msgpack_unpack_init(value, value_size, 0);
	err = msgpack_unpack_uint8(u, &ver);
	if (err) {
		log_error(fsio_lg,
		    "msgpack_unpack_uint8 return %d", err);
		goto out;
	}

	if (ver == 2) {
		buf = je_calloc(1, MAX_OID_SIZE);
		if (!buf) {
			log_error(fsio_lg,
			    "Failed to allocate memory");
			err = ENOMEM;
			goto out;
		}
		err = msgpack_unpack_str(u, buf, MAX_OID_SIZE);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_str return %d", err);
			goto out;
		}
		*name = je_strdup(buf);
		err = 0;
	}
out:
	if (u)
		msgpack_unpack_free(u);

	if (buf)
		je_free(buf);

	log_debug(fsio_lg, "completed value: %p, value_size: %lu, "
	    "name: %p", value, value_size, name);

	return err;
}

int
get_s3_index_genid(ci_t * ci, uint64_t *genid)
{
	int err;
	struct ccow_metadata_kv *kv = NULL;
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	ccow_t tc;

	log_trace(fsio_lg, "ci: %p, invalidating genid", ci);

	*genid = 0;

	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccow_create_completion return %d", err);
		goto out;
	}

	err = ccow_get_list(ci->bid, ci->bid_size, INODE_OBJECT_LOOKUP,
	    strlen(INODE_OBJECT_LOOKUP) + 1, c, NULL, 0, 1, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_get_list return %d", err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_wait return error");
		goto out;
	}
	c = NULL;

	if (iter != NULL) {
		struct ccow_metadata_kv *kv = NULL;
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
			if (strcmp(kv->key, RT_SYSKEY_TX_GENERATION_ID) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, genid);
				if (*genid == 0)
					break;
				goto out;
			}
		}
	}
	log_debug(fsio_lg, "invalidation error");
	err = ENOENT;

out:
	if (c)
		ccow_release(c);

	if (iter)
		ccow_lookup_release(iter);

	log_debug(fsio_lg, "invalidation completed ci: %p, genid: %ld", ci, *genid);

	return err;
}

int
get_s3_obj_name(ci_t * ci, char *ino_str, char **oid)
{
	int err;
	struct ccow_metadata_kv *kv = NULL;
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	struct iovec iov[1];
	ccow_t tc;

	log_trace(fsio_lg, "ci: %p, ino_str: \"%s\", oid: %p", ci, ino_str, oid);

	iov[0].iov_base = ino_str;
	iov[0].iov_len = strlen(ino_str) + 1;

	err = tc_pool_get_tc(ci->tc_pool_handle, 0, &tc);
	if (err) {
		log_error(fsio_lg, "%s: Failed to get TC. err: %d", __func__, err);
		goto out;
	}

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccow_create_completion return %d", err);
		goto out;
	}

	err = ccow_get_list(ci->bid, ci->bid_size, INODE_OBJECT_LOOKUP,
	    strlen(INODE_OBJECT_LOOKUP) + 1, c,
	    (struct iovec *) &iov, 1, 255, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_get_list return %d", err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_error(fsio_lg, "ccow_wait return %d", err);
		goto out;
	}
	c = NULL;

	if (iter != NULL) {
		uint64_t genid = 0;
		struct ccow_metadata_kv *kv = NULL;
		int pos = 0;

		int found_key = 0;
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX | CCOW_MDTYPE_METADATA,
			    pos++)) != NULL) {
			/* key */
			if (!found_key && kv->key && kv->value && strcmp(ino_str, kv->key) == 0) {
				err = __parse_s3_obj_name(kv->value, kv->value_size, oid);
				found_key = 1;
			}
			/* genid */
			if (!genid && kv->key && kv->value && strcmp(kv->key, RT_SYSKEY_TX_GENERATION_ID) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &genid);
			}
			if (found_key && genid) {
				/* if found - store latest genid of our index */
				ci->objects_genid = genid;
				goto out;
			}
		}
		if (found_key)
			goto out;
	}
	log_debug(fsio_lg, "item not found");
	err = ENOENT;

out:
	if (err)
		ci->ccow_err = err;

	if (c)
		ccow_release(c);

	if (iter)
		ccow_lookup_release(iter);

	log_debug(fsio_lg, "completed ci: %p, ino_str: \"%s\", oid: %p", ci,
	    ino_str, oid);

	return err;
}

int
get_s3_obj_stats(ci_t * ci, char *ino_str, struct stat *stat)
{
	int err;
	struct ccow_metadata_kv *kv = NULL;
	ccow_completion_t c = NULL;
	ccow_lookup_t iter = NULL;
	char *e = NULL;
	char *name = NULL;
	int pos = 0;
	struct iovec iov;
	char *obj_name = NULL;

	log_trace(fsio_lg, "ci: %p, ino_str: \"%s\", stat: %p", ci, ino_str,
	    stat);

	/*
	 * Get the obj name and then looup for the attrs
	 */
	err = get_s3_obj_name(ci, ino_str, &obj_name);
	if (err) {
		log_error(fsio_lg, "get_s3_obj_name return %d",
		    err);
		goto out;
	}

	err = ccowfs_create_completion(ci, NULL, NULL, 0, &c);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_create_completion return %d", err);
		goto out;
	}

	iov.iov_base = obj_name;
	iov.iov_len = strlen(obj_name) + 1;

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *) "btree_key_val", NULL);
	if (err) {
		log_error(fsio_lg,
		    "ccow_attr_modify_default return %d", err);
		goto out;
	}

	err = ccow_get_list(ci->bid, ci->bid_size,
	    CCOW_FSIO_S3OBJ_DIR_OID, strlen(CCOW_FSIO_S3OBJ_DIR_OID) + 1,
	    c, (struct iovec *) &iov, 1, 256, &iter);
	if (err) {
		log_error(fsio_lg, "ccow_get_list return %d", err);
		goto out;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_softerror(fsio_lg, err, "ccow_wait fail");
		goto out;
	}

	c = NULL;

	if (iter != NULL) {
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
			    pos++)) != NULL) {
			if (kv->value == NULL || kv->key == NULL) {
				continue;
			}
			if (strcmp(kv->key, obj_name) == 0) {
				err = parse_s3_obj_stats(ci, kv->value,
					kv->value_size, stat);
				goto out;
			}
		}
	}
	log_debug(fsio_lg, "item not found");
	err = ENOENT;

out:
	if (obj_name)
		je_free(obj_name);

	if (iter)
		ccow_lookup_release(iter);
	if (err)
		ci->ccow_err = err;

	if (c)
		ccow_release(c);

	log_debug(fsio_lg, "completed ci: %p, ino_str: \"%s\", stat: %p", ci,
	    ino_str, stat);

	return err;
}

int
encode_nfs_attrs(nfs_directory_table_attrs * attrs, void **value,
    size_t * value_size)
{
	int err;
	msgpack_p *p = msgpack_pack_init();
	uv_buf_t uv_b;

	log_trace(fsio_lg, "attrs: %p, value: %p, value_size: %p",
	    attrs, value, value_size);

	assert(attrs->ver == 3);
	err = msgpack_pack_uint8(p, attrs->ver);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint8 return %d",
		    err);
		return err;
	}

	err = msgpack_pack_uint64(p, attrs->ino);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint64 return %d",
		    err);
		return err;
	}

	msgpack_get_buffer(p, &uv_b);

	*value = je_calloc(1, uv_b.len);
	if (!*value) {
		log_error(fsio_lg, "Failed to allocate memory");
		err = ENOMEM;
		goto out;
	}

	memcpy(*value, uv_b.base, uv_b.len);
	*value_size = uv_b.len;

out:
	if (p)
		msgpack_pack_free(p);

	log_debug(fsio_lg, "completed attrs: %p, value: %p, "
	    "value_size: %p", attrs, value, value_size);

	return err;
}

int
decode_nfs_attrs(void *value, size_t value_size,
    nfs_directory_table_attrs * attrs)
{
	int err;
	msgpack_u *u;

	log_trace(fsio_lg, "value: %p, value_size: %lu, attrs: %p",
	    value, value_size, attrs);

	u = msgpack_unpack_init(value, value_size, 0);
	err = msgpack_unpack_uint8(u, &attrs->ver);
	if (err) {
		log_error(fsio_lg, "msgpack_pack_uint8 return %d",
		    err);
		goto out;
	}

	if (attrs->ver == 3) {
		err = msgpack_unpack_uint64(u, &attrs->ino);
		if (err) {
			log_error(fsio_lg,
			    "msgpack_unpack_uint64 return %d", err);
			goto out;
		}
	} else {
		log_error(fsio_lg, "Wronf node attr version");
		err = -EIO;
	}

out:
	if (u)
		msgpack_unpack_free(u);

	log_debug(fsio_lg, "completed value: %p, value_size: %lu, "
	    "attrs: %p", value, value_size, attrs);

	return err;
}

int
encode_s3_name(char *decoded_name, size_t decoded_name_len,
    char *encoded_name, size_t max_encoded_name_len)
{
	/*
	 * Replace "/" from object name with "%2F"
	 */
	int i = 0;
	size_t size = 0;

	log_trace(fsio_lg, "decoded_name: \"%s\", "
	    "decoded_name_len: %lu, encoded_name: \"%s\", "
	    "max_encoded_name_len: %lu", decoded_name, decoded_name_len,
	    encoded_name, max_encoded_name_len);

	for (; *decoded_name; decoded_name++) {
		if (*decoded_name == '/' && (max_encoded_name_len - size) > 3) {
			sprintf(encoded_name + size, "%%%02X", *decoded_name);
			size += 3;
		} else if ((max_encoded_name_len - size) > 1)
			encoded_name[size++] = *decoded_name;
		else
			break;
	}

	encoded_name[size] = '\0';

	assert(size < max_encoded_name_len);

	log_debug(fsio_lg, "completed decoded_name: \"%s\", "
	    "decoded_name_len: %lu, encoded_name: \"%s\", "
	    "max_encoded_name_len: %lu", decoded_name, decoded_name_len,
	    encoded_name, max_encoded_name_len);

	return 0;
}

int
decode_s3_name(char *encoded_name, size_t encoded_name_len,
    char *decoded_name, size_t max_decoded_name_len)
{
	/*
	 * Replace "%2F" from object name with "/"
	 */
	char *src = encoded_name;
	char *res = decoded_name;

	log_trace(fsio_lg, "encoded_name: \"%s\", "
	    "encoded_name_len: %lu, decoded_name: \"%s\", "
	    "max_decoded_name_len: %lu", encoded_name, encoded_name_len,
	    decoded_name, max_decoded_name_len);

	for (; src < encoded_name + encoded_name_len; src++) {
		if ((size_t) (res - decoded_name) == max_decoded_name_len)
			break;

		if (*src == '%' && *(src + 1) == '2' && *(src + 2) == 'F') {
			*res = '/';
			src += 2;
		} else
			*res = *src;
		res++;
	}

	*res = '\0';

	log_debug(fsio_lg, "completed encoded_name: \"%s\", "
	    "encoded_name_len: %lu, decoded_name: \"%s\", "
	    "max_decoded_name_len: %lu", encoded_name, encoded_name_len,
	    decoded_name, max_decoded_name_len);

	return 0;
}

static int
__create_s3obj_root(ci_t * ci)
{
	int err;
	ccowfs_inode *objdir_inode = NULL;
	uint16_t mode = S_IFDIR | (0555);

	log_trace(fsio_lg, "ci: %p", ci);
	/*
	 * Create in memory directory to list all S3 objects.
	 * dir name: ci->root_obj_dir_name
	 * dir inode : CCOW_FSIO_S3OBJ_DIR_INODE
	 * dir oid : CCOW_FSIO_S3OBJ_DIR_OID
	 */
	err = ccowfs_inode_create_new_get(ci, CCOW_FSIO_S3OBJ_DIR_INODE, mode,
	    0, 0, NULL, &objdir_inode, NULL);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_create_new_get return %d", err);
		goto out;
	}

	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	objdir_inode->stat.st_atim = time;
	objdir_inode->stat.st_ctim = time;
	objdir_inode->stat.st_mtim = time;

	objdir_inode->stat.st_nlink = 2;

	/*Set size for "." and ".." entries */
	objdir_inode->stat.st_size = 2 * ENTRY_SIZE;

	err = fsio_link_internal(ci, CCOW_FSIO_ROOT_INODE,
	    ci->root_obj_dir_name, CCOW_FSIO_S3OBJ_DIR_INODE, 0);

out:
	if (err == EEXIST)
		err = 0;

	if (err) {
		log_error(fsio_lg, "failed for bucket: %s ", ci->bid);
	}

	log_debug(fsio_lg, "completed ci: %p", ci);

	return err;
}

int
create_s3obj_dir(ci_t * ci, char *name, inode_t ino, inode_t parent, ccowfs_inode *objdir_inode)
{
	int err;
//	ccowfs_inode *objdir_inode = NULL;
	uint16_t mode = S_IFDIR | (0555);

	log_trace(fsio_lg, "ci: %p", ci);
	/*
	 * Create in memory directory to list all S3 objects.
	 * dir name: ci->root_obj_dir_name
	 * dir inode : CCOW_FSIO_S3OBJ_DIR_INODE
	 * dir oid : CCOW_FSIO_S3OBJ_DIR_OID
	 */
	err = ccowfs_inode_create_new_get(ci, ino, mode,
	    0, 0, NULL, &objdir_inode, NULL);
	if (err) {
		log_error(fsio_lg,
		    "ccowfs_inode_create_new_get return %d", err);
		goto out;
	}

	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	objdir_inode->stat.st_atim = time;
	objdir_inode->stat.st_ctim = time;
	objdir_inode->stat.st_mtim = time;

	objdir_inode->stat.st_nlink = 2;

	/*Set size for "." and ".." entries */
	objdir_inode->stat.st_size = 2 * ENTRY_SIZE;

	err = fsio_link_internal(ci, parent, name, ino, 0);

out:
	if (err == EEXIST)
		err = 0;

	if (err) {
		log_error(fsio_lg, "failed for bucket: %s ", ci->bid);
	}

	log_debug(fsio_lg, "completed ci: %p", ci);

	return err;
}

struct part_info
{
	uint64_t part_number;
	char *name;
	uint64_t size;
};

struct multipart_info
{
	uint64_t count;
	struct part_info parts[0];
};

int
get_s3_json_handle(const char *jsons_string, void **json_handle)
{
	int err = 0;
	struct multipart_info *multi_parts = NULL;

	/* Given a JSON string parse it */
	json_value *opts = json_parse(jsons_string, strlen(jsons_string));
	if (opts == NULL || opts->type != json_array) {
		log_error(fsio_lg, "Failed to parse json string %s",
			jsons_string);
		err = EINVAL;
		goto out;
	}

	log_debug(fsio_lg, "JSON: object parts count: %u",
		opts->u.array.length);

	if (! opts->u.array.length) {
		log_error(fsio_lg, "Got zero parts for multipart object");
		err = EINVAL;
		goto out;
	}

	multi_parts = (struct multipart_info *) je_calloc(1,
		sizeof(struct multipart_info) +
		opts->u.array.length * sizeof(struct part_info));
	if (! multi_parts){
		err = ENOMEM;
		goto out;
	}

	multi_parts->count = opts->u.array.length;

	for (uint64_t i=0; i<opts->u.array.length; i++) {
		/* Traverse for all parts*/
		json_value *tmp = opts->u.array.values[i];

		for (uint64_t j=0; j<tmp->u.object.length; j++) {
			/* Traverse for all attributes for the part */
			if (strcmp("part", tmp->u.object.values[j].name) == 0)
				multi_parts->parts[i].part_number = tmp->u.object.values[j].value->u.integer;
			else if (strcmp("name", tmp->u.object.values[j].name) == 0)
				multi_parts->parts[i].name = je_strdup(tmp->u.object.values[j].value->u.string.ptr);
			else if (strcmp("size", tmp->u.object.values[j].name) == 0)
				multi_parts->parts[i].size = tmp->u.object.values[j].value->u.integer;
		}
		if (! multi_parts->parts[i].name) {
			err = ENOMEM;
			goto out;
		}

		log_debug(fsio_lg, "part_number: %lu name: %s size: %lu",
			multi_parts->parts[i].part_number,
			multi_parts->parts[i].name,
			multi_parts->parts[i].size);
	}

out:
	if (err) {
		log_error(fsio_lg, "Failed to parse JSON eith err: %d", err);
		if (multi_parts)
			put_s3_json_handle((void *)multi_parts);
	}
	else
		*json_handle = (void *) multi_parts;

	if (opts)
		json_value_free(opts);

	return err;
}

int
put_s3_json_handle(void *json_handle)
{
	struct multipart_info *multi_parts = (struct multipart_info *) json_handle;
	if (multi_parts){
		for(uint64_t i=0; i<multi_parts->count; i++) {
			if(multi_parts->parts[i].name)
				je_free(multi_parts->parts[i].name);
		}
		je_free(multi_parts);
	}

	return 0;
}

int
get_s3_multipart_parts(ccowfs_inode *inode, size_t file_offset, size_t data_size,
    s3_object_parts_maps **multipart_map, uint64_t *count)
{
	int err = 0;
	uint64_t required_parts = 0;
	uint64_t part_start, part_end, part_offset, part_size;
	s3_object_parts_maps *map = NULL;

	log_trace(fsio_lg, "file_offset: %lu data_size :%lu",
		file_offset, data_size);

	pthread_mutex_lock(&inode->json_handle_mutex);

	if (inode->json_handle == NULL) {
		log_error(lg, "Conflicting attempt to parse S3 parts in parallel");
		err = -EINVAL;
		goto out;
	}

	struct multipart_info *multi_parts = (struct multipart_info *) inode->json_handle;
	if (! multi_parts){
		err = -EINVAL;
		goto out;
	}

	map = (s3_object_parts_maps *) je_calloc(multi_parts->count,
	    sizeof(s3_object_parts_maps));
	if (! map){
		err = ENOMEM;
		goto out;
	}

	/** Get count of parts which are of our interest
	 *  Assuming that the parts are in sequence.
	 */
	part_start = 0;
	for (uint64_t i =0; i<multi_parts->count; i++) {
		part_end = part_start + multi_parts->parts[i].size;

		log_debug(fsio_lg, "part: %lu start :%lu end :%lu",
			i, part_start, part_end);

		if (file_offset >= part_end || file_offset+data_size <= part_start){
			/* Required data not present in this part*/
			log_debug(fsio_lg, "skipping part: %lu", i);

			/* Set correct part_start for next part */
			part_start = part_end;
			continue;
		}
		log_debug(fsio_lg, "part of interest : %lu", i);

		/* Find offset and size within this part */
		if (part_start >= file_offset)
			part_offset = 0;
		else
			part_offset = file_offset - part_start;

		if (part_end <= file_offset+data_size)
			part_size = part_end - (part_start + part_offset);
		else
			part_size = (file_offset + data_size) - (part_start + part_offset);

		assert(part_offset < (part_end - part_start));
		assert(part_size <= multi_parts->parts[i].size);


		log_debug(fsio_lg, "part: %lu offset: %lu size :%lu",
			i, part_offset, part_size);

		map[required_parts].number = multi_parts->parts[i].part_number;
		map[required_parts].offset = part_offset;
		map[required_parts].size = part_size;
		map[required_parts].name = je_strdup(multi_parts->parts[i].name);

		required_parts++;

		/* Set correct part_start for next part */
		part_start = part_end;
	}

out:
	if (err) {
		if (map) {
			for (uint64_t i=0; i<required_parts; i++) {
				if (map[i].name) {
					je_free(map[i].name);
					map[i].name = NULL;
				}
			}
			je_free(map);
			map = NULL;
			required_parts = 0;
		}
	}

	*multipart_map = map;
	*count = required_parts;

	pthread_mutex_unlock(&inode->json_handle_mutex);

	return err;
}

int
s3_transparency_init(ci_t * ci)
{
	int err = 0;

	log_trace(fsio_lg, "ci: %p", ci);

	if (ci->bk_attrs.file_object_transparency) {
		/*
		 * Get the dir name for the S3 objects
		 */
		get_object_root_dir(ci, &ci->root_obj_dir_name);

		/*
		 * Create in memory dir for s3 obj root
		 */
		err = __create_s3obj_root(ci);
		if (err) {
			log_error(fsio_lg,
			    "__create_s3obj_root return %d", err);
		}
	}

	log_debug(fsio_lg, "completed ci: %p", ci);

	return err;
}
