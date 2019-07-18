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
#ifndef MSGPACKCCOW_H
#define MSGPACKCCOW_H

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <msgpackalt.h>
#include <ccow.h>


/*
 * AWS S3 Key and value are max 1024 (UTF-8 encoded)
 */
#define CCOW_KV_STR_MAX		1024 + 1

/**
 * Pack/unpack metadata to/from msgpack
 *
 * @returns 0 on success, negative error code on failure
 */
static inline int
ccow_pack_kv(msgpack_p *p, const char *key, int key_size,
	     void *value, int val_size, ccow_kvtype_t type)
{
	int err = 0;

	if (value != NULL || ((type == CCOW_KVTYPE_RAW) && val_size > 0)) {
		/* This is a MD modify request, Pack Key. */
		assert(key != NULL && key_size > 0);
		MCHK(err, msgpack_pack_str(p, key), goto _exit);
		switch (type) {
		case CCOW_KVTYPE_STR:
			MCHK(err, msgpack_pack_str(p, (char *)value),
			    goto _exit);
			break;
		case CCOW_KVTYPE_RAW:
			MCHK(err, msgpack_pack_raw(p, (char *)value, val_size),
			    goto _exit);
			break;
		case CCOW_KVTYPE_UINT64:
			MCHK(err, msgpack_pack_uint64(p, *(uint64_t *)value),
			    goto _exit);
			break;
		case CCOW_KVTYPE_INT64:
			MCHK(err, msgpack_pack_int64(p, *(int64_t *)value),
			    goto _exit);
			break;
		case CCOW_KVTYPE_UINT32:
			MCHK(err, msgpack_pack_uint32(p, *(uint32_t *)value),
			    goto _exit);
			break;
		case CCOW_KVTYPE_INT32:
			MCHK(err, msgpack_pack_int32(p, *(int32_t *)value),
			    goto _exit);
			break;
		case CCOW_KVTYPE_UINT16:
			MCHK(err, msgpack_pack_uint16(p, *(uint16_t *)value),
			    goto _exit);
			break;
		case CCOW_KVTYPE_INT16:
			MCHK(err, msgpack_pack_int16(p, *(int16_t *)value),
			    goto _exit);
			break;
		case CCOW_KVTYPE_UINT8:
			MCHK(err, msgpack_pack_uint8(p, *(uint8_t *)value),
			    goto _exit);
			break;
		case CCOW_KVTYPE_INT8:
			MCHK(err, msgpack_pack_int8(p, *(int8_t *)value),
			    goto _exit);
			break;
		default:
			err = -EINVAL;
			log_warn(lg, "%s err packing new value: %d\n",
			    __func__, __LINE__);
			goto _exit;
		}
	}

_exit:
	return err;
}

static inline int
ccow_unpack_kv(msgpack_u *u, ccow_metadata_kv_t attr)
{
	int err = -EINVAL;
	const uint8_t *raw_payload;
	uint32_t raw_size;

	attr->value = attr->key = NULL;
	attr->key = (char *) je_malloc(CCOW_KV_STR_MAX);
	if (!attr->key)
		return -ENOMEM;

	MCHK(err, msgpack_unpack_str(u, attr->key, CCOW_KV_STR_MAX),
		goto _exit);
	attr->key_size = strlen(attr->key) + 1;

	switch (attr->type) {
	case CCOW_KVTYPE_STR:
		attr->value = je_malloc(CCOW_KV_STR_MAX);
		if (!attr->value)
			return -ENOMEM;
		MCHK(err, msgpack_unpack_str(u, (char *)attr->value,
				CCOW_KV_STR_MAX), goto _exit);
		attr->value_size = strlen((char *)attr->value) + 1;
		break;
	case CCOW_KVTYPE_RAW:
		MCHK(err, msgpack_unpack_raw(u, &raw_payload, &raw_size), goto _exit);
		attr->value = je_memdup((char *)raw_payload, raw_size);
		if (!attr->value)
			return -ENOMEM;
		attr->value_size = raw_size;
		break;
	case CCOW_KVTYPE_UINT64:
		attr->value = je_malloc(sizeof (uint64_t));
		if (!attr->value)
			return -ENOMEM;
		MCHK(err, msgpack_unpack_uint64(u, (uint64_t *)attr->value),
						goto _exit);
		attr->value_size = sizeof (uint64_t);
		break;
	case CCOW_KVTYPE_INT64:
		attr->value = je_malloc(sizeof (int64_t));
		if (!attr->value)
			return -ENOMEM;
		MCHK(err, msgpack_unpack_int64(u, (int64_t *)attr->value),
						goto _exit);
		attr->value_size = sizeof (int64_t);
		break;
	case CCOW_KVTYPE_UINT32:
		attr->value = je_malloc(sizeof (uint32_t));
		if (!attr->value)
			return -ENOMEM;
		MCHK(err, msgpack_unpack_uint32(u, (uint32_t *)attr->value),
						goto _exit);
		attr->value_size = sizeof (uint32_t);
		break;
	case CCOW_KVTYPE_INT32:
		attr->value = je_malloc(sizeof (int32_t));
		if (!attr->value)
			return -ENOMEM;
		MCHK(err, msgpack_unpack_int32(u, (int32_t *)attr->value),
						goto _exit);
		attr->value_size = sizeof (int32_t);
		break;
	case CCOW_KVTYPE_UINT16:
		attr->value = je_malloc(sizeof (uint16_t));
		if (!attr->value)
			return -ENOMEM;
		MCHK(err, msgpack_unpack_uint16(u, (uint16_t *)attr->value),
						goto _exit);
		attr->value_size = sizeof (uint16_t);
		break;
	case CCOW_KVTYPE_INT16:
		attr->value = je_malloc(sizeof (int16_t));
		if (!attr->value)
			return -ENOMEM;
		MCHK(err, msgpack_unpack_int16(u, (int16_t *)attr->value),
						goto _exit);
		attr->value_size = sizeof (int16_t);
		break;
	case CCOW_KVTYPE_UINT8:
		attr->value = je_malloc(sizeof (uint8_t));
		if (!attr->value)
			return -ENOMEM;
		MCHK(err, msgpack_unpack_uint8(u, (uint8_t *)attr->value),
						goto _exit);
		attr->value_size = sizeof (uint8_t);
		break;
	case CCOW_KVTYPE_INT8:
		attr->value = je_malloc(sizeof (int8_t));
		if (!attr->value)
			return -ENOMEM;
		MCHK(err, msgpack_unpack_int8(u, (int8_t *)attr->value),
						goto _exit);
		attr->value_size = sizeof (int8_t);
		break;
	default:
		log_warn(lg, "%s err unpacking value: %d\n",
		    __func__, __LINE__);
		break;
	}
	return err;

_exit:
	if (attr->key) {
		je_free(attr->key);
		attr->key = NULL;
	}
	if (attr->value) {
		je_free(attr->value);
		attr->value = NULL;
	}
	return err;
}


static inline int
ccow_pack_mdkv(ccow_metadata_kv_t attr, msgpack_p **out)
{
	int err;
	uint32_t i;
	msgpack_p *p = NULL;

	if (out == NULL)
		return -EINVAL;

	*out = NULL;
	p = msgpack_pack_init();
	if (p == NULL)
		return -ENOMEM;

	MCHK(err, msgpack_pack_int32(p, attr->mdtype), goto _exit);
	MCHK(err, msgpack_pack_int32(p, attr->type), goto _exit);
	err = ccow_pack_kv(p, attr->key, attr->key_size,
			   attr->value, attr->value_size,
			   attr->type);
	if (err)
		goto _exit;

	*out = p;
	return 0;
_exit:
	msgpack_pack_free(p);
	return err;
}

static inline int
ccow_unpack_mdkv(msgpack_u *u, ccow_metadata_kv_t attr)
{
	int err;
	uint32_t i;

	MCHK(err, msgpack_unpack_int32(u, (int32_t *)&attr->mdtype), goto _exit);
	MCHK(err, msgpack_unpack_int32(u, (int32_t *)&attr->type), goto _exit);
	err = ccow_unpack_kv(u, attr);

_exit:
	return err;
}

static inline int
ccow_pack_free(msgpack_p *p)
{
	if (p)
		msgpack_pack_free(p);
	return 0;
}

static inline int
list_kv_unpack_value(void *value, size_t value_size, char *buf, size_t buf_size) {
	    if (value_size == 0 || !value) {
		   return 0;
	    }
	    int err = 0;
		uint8_t ver=0;
		uint64_t timestamp = 0;
		uint64_t generation = 0;
		uint64_t size = 0;
		uint64_t inode = 0;
		uint512_t vmchid;
		char etag[CCOW_KV_STR_MAX] = "";
		char content_type[CCOW_KV_STR_MAX] = "";
		char owner[CCOW_KV_STR_MAX] = "";
		char srcip[CCOW_KV_STR_MAX] = "";
		uint8_t object_deleted = 0;
		msgpack_u *u = msgpack_unpack_init(value, value_size, 0);
		err = msgpack_unpack_uint8(u, &ver);
		if (err) {
			goto _exit;
		}
		if (ver == 1) {
			err = msgpack_unpack_uint8(u, &object_deleted);
			if (err) {
				goto _exit;
			}
			err = msgpack_unpack_uint64(u, &timestamp);
			if (err) {
				goto _exit;
			}
			err = msgpack_unpack_uint64(u, &generation);
			if (err) {
				goto _exit;
			}
			err = msgpack_unpack_uint512(u, &vmchid);
			if (err) {
				goto _exit;
			}
			err = msgpack_unpack_str(u, etag, CCOW_KV_STR_MAX);
			if (err) {
				goto _exit;
			}
			err = msgpack_unpack_str(u, content_type, CCOW_KV_STR_MAX);
			if (err) {
				goto _exit;
			}
			err = msgpack_unpack_uint64(u, &size);
			if (err) {
				goto _exit;
			}
			err = msgpack_unpack_uint64(u, &inode);
			if (err) {
				goto _exit;
			}
			err = msgpack_unpack_str(u, owner, CCOW_KV_STR_MAX);
			if (err) {
				goto _exit;
			}
			err = msgpack_unpack_str(u, srcip, CCOW_KV_STR_MAX);
			if (err) {
				goto _exit;
			}
			char vmchid_buf[UINT512_BYTES * 2 + 1] = "";
			uint512_dump(&vmchid, vmchid_buf, UINT512_BYTES * 2 + 1);
			sprintf(buf,"%lu;%lu;%s;%s;%s;%lu;%u;%lu;%s;%s", timestamp, generation,
				vmchid_buf, etag, content_type, size, object_deleted, inode, owner, srcip);
			goto _exit;
		}
		if (ver == 2) {
			err = msgpack_unpack_str(u, buf, buf_size);
			goto _exit;
		}
		if (ver == 3) {
			err = msgpack_unpack_uint64(u, &inode);
			if (err)
				goto _exit;
         uint8_t type = (inode >> 60) & 3;
			sprintf(buf,"%lu;%u", inode, type);
			goto _exit;
		}
		if (ver == 4) {
			uint32_t st_mode, st_uid, st_gid;
			uint64_t st_dev, st_rdev, tv_sec;
			uint64_t st_atim_tv_sec, st_atim_tv_nsec;
			uint64_t st_mtim_tv_sec, st_mtim_tv_nsec;
			uint64_t st_ctim_tv_sec, st_ctim_tv_nsec;
			err = msgpack_unpack_uint32(u, &st_mode);
			if (err)
				goto _exit;
			err = msgpack_unpack_uint32(u, &st_uid);
			if (err)
				goto _exit;
			err = msgpack_unpack_uint32(u, &st_gid);
			if (err)
				goto _exit;
			err = msgpack_unpack_uint64(u, &st_dev);
			if (err)
				goto _exit;
			err = msgpack_unpack_uint64(u, &st_rdev);
			if (err)
				goto _exit;
			err =
			    msgpack_unpack_uint64(u,
			    (uint64_t *) &st_atim_tv_sec);
			if (err)
				goto _exit;
			err =
			    msgpack_unpack_uint64(u,
			    (uint64_t *) & st_atim_tv_nsec);
			if (err)
				goto _exit;
			err =
			    msgpack_unpack_uint64(u,
			    (uint64_t *) & st_mtim_tv_sec);
			if (err)
				goto _exit;
			err =
			    msgpack_unpack_uint64(u,
			    (uint64_t *) & st_mtim_tv_nsec);
			if (err)
				goto _exit;
			err =
			    msgpack_unpack_uint64(u,
			    (uint64_t *) & st_ctim_tv_sec);
			if (err)
				goto _exit;
			err =
			    msgpack_unpack_uint64(u,
			    (uint64_t *) & st_ctim_tv_nsec);
			if (err)
				goto _exit;
			sprintf(buf,"%u;%u;%u;%lu;%lu;%lu;%lu;%lu;%lu",
					st_mode, st_uid, st_gid,
					st_atim_tv_sec, st_atim_tv_nsec,
					st_mtim_tv_sec, st_mtim_tv_nsec,
					st_ctim_tv_sec, st_ctim_tv_nsec);
			goto _exit;
		}
		if (ver == 5) {
			const uint8_t *data;
			uint32_t nout;
			err = msgpack_unpack_raw(u, &data, &nout);
			if (!err)
			    memcpy(buf, data, nout);
			goto _exit;
		}

_exit:
		msgpack_unpack_free(u);
		return err;
}

static inline int
list_kv_pack_str(msgpack_p * p, char *cvalue) {
	int err;

	uint8_t ver = 2;
	err = msgpack_pack_uint8(p, ver);
	if (err)
	   return err;

	err = msgpack_pack_str(p, (cvalue ? cvalue : ""));
	return err;
}


#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif /* MSGPACKCCOW_H */
