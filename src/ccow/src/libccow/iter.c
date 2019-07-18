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
#include "msgpackalt.h"
#include "ccow-impl.h"
#include "replicast.h"


/*
 * Take an input KVTYPE from user and typecast+copy the data to usr data var.
 */
void
ccow_iterator_kvcast(ccow_kvtype_t dtype, struct ccow_metadata_kv *kv,
    void *data)
{
	int dsize;
	uint64_t v = 0;

	switch (kv->type) {
	case CCOW_KVTYPE_UINT64: {
		v = *(uint64_t *)kv->value;
	}
	break;
	case CCOW_KVTYPE_UINT32: {
		v = *(uint32_t *)kv->value;
	}
	break;
	case CCOW_KVTYPE_UINT16: {
		v = *(uint16_t *)kv->value;
	}
	break;
	case CCOW_KVTYPE_UINT8: {
		v = *(uint8_t *)kv->value;
	}
	break;
	case CCOW_KVTYPE_INT64: {
		v = *(int64_t *)kv->value;
	}
	break;
	case CCOW_KVTYPE_INT32: {
		v = *(int32_t *)kv->value;
	}
	break;
	case CCOW_KVTYPE_INT16: {
		v = *(int16_t *)kv->value;
	}
	break;
	case CCOW_KVTYPE_INT8: {
		v = *(int8_t *)kv->value;
	}
	break;
	default:
	break;
	}

	switch (dtype) {
	case CCOW_KVTYPE_UINT64: {
		*(uint64_t *)data = v;
	}
	break;
	case CCOW_KVTYPE_UINT32: {
		*(uint32_t *)data = v;
	}
	break;
	case CCOW_KVTYPE_UINT16: {
		*(uint16_t *)data = v;
	}
	break;
	case CCOW_KVTYPE_UINT8: {
		*(uint8_t *)data = v;
	}
	break;
	case CCOW_KVTYPE_INT64: {
		*(int64_t *)data = v;
	}
	break;
	case CCOW_KVTYPE_INT32: {
		*(int32_t *)data = v;
	}
	break;
	case CCOW_KVTYPE_INT16: {
		*(int16_t *)data = v;
	}
	break;
	case CCOW_KVTYPE_INT8: {
		*(int8_t *)data = v;
	}
	break;
	default:
	break;
	}

}


static int64_t convert_raw(struct ccow_metadata_kv *kv) {
	if (kv->value_size == 0)
		return 0;
	char buf[128];
	memcpy(buf, kv->value, kv->value_size);
	buf[kv->value_size] = '\0';
	int64_t v = 0;
	sscanf(buf, "%ld", &v);
	return v;
}

static int64_t convert_str(struct ccow_metadata_kv *kv) {
	if (kv->value_size == 0)
		return 0;
	char buf[128];
	memcpy(buf, kv->value, kv->value_size);
	buf[kv->value_size] = '\0';
	int64_t v = 0;
	sscanf(buf, "%ld", &v);
	return v;
}

static int64_t convert_uint64(struct ccow_metadata_kv *kv) {
	return *(uint64_t *)kv->value;
}

static int64_t convert_uint32(struct ccow_metadata_kv *kv) {
	return *(uint32_t *)kv->value;
}

static int64_t convert_uint16(struct ccow_metadata_kv *kv) {
	return *(uint16_t *)kv->value;
}

static int64_t convert_uint8(struct ccow_metadata_kv *kv) {
	return *(uint8_t *)kv->value;
}

static int64_t convert_int64(struct ccow_metadata_kv *kv) {
	return *(int64_t *)kv->value;
}

static int64_t convert_int32(struct ccow_metadata_kv *kv) {
	return *(int32_t *)kv->value;
}

static int64_t convert_int16(struct ccow_metadata_kv *kv) {
	return *(int16_t *)kv->value;
}

static int64_t convert_int8(struct ccow_metadata_kv *kv) {
	return *(int8_t *)kv->value;
}

static int64_t (*convertor_table[])(struct ccow_metadata_kv *) = {
		NULL,
		convert_raw, // 1
		convert_str, // 2
		NULL,
		NULL,
		convert_uint64, // 5
		convert_uint32, // 6
		convert_uint16, // 7
		convert_int8,  // 8
		convert_int64, // 9
		convert_int32, // 10
		convert_int16, // 11
		convert_int8   // 12
};

int64_t
ccow_kvconvert_to_int64(struct ccow_metadata_kv *kv) {
	if (!kv)
		return 0;
	int64_t (*converter)(struct ccow_metadata_kv *) = convertor_table[kv->type];
	if (!converter)
		return 0;
	return converter(kv);
}

/*
 * Helper function to iteratively free the contents of an rtbuf that has
 * sub-allocations within the key-value pointers that represent each buf
 * in the rtbuf_t.
 *
 * Scope: PRIVATE
 */
void
ccow_iter_free_rtbuf(rtbuf_t *rb)
{
	assert(rb);

	/* Iterate through the KV pairs and free any allocated memory. */
	for (size_t i = 0; i < rb->nbufs; i++)
	{
		struct ccow_metadata_kv *kv =
			(struct ccow_metadata_kv *)rtbuf(rb, i).base;
		assert(kv);
		if (kv->value)
			je_free(kv->value);
		if (kv->key)
			je_free(kv->key);
	}
}

static int
ccow_decode_custom_md(ccow_lookup_t iter)
{
	int err;
	struct ccow_lookup *i = (struct ccow_lookup *)iter;

	/* nothing to do? */
	if (!i->custom_md || i->custom_md->nbufs == 0) {
		/* additionally check if completion has some */
		uv_mutex_lock(&i->comp->operations_mutex);
		if (i->comp->custom_md) {
			if (i->custom_md) {
				/* Destroy the custom_md msgpack copies. */
				rtbuf_destroy(i->custom_md);
			}
			i->custom_md = rtbuf_clone_bufs(i->comp->custom_md);
			if (i->rb_cmd) {
				rtbuf_destroy(i->rb_cmd);
				i->rb_cmd = NULL;
			}
		} else {
			uv_mutex_unlock(&i->comp->operations_mutex);
			return 0;
		}
		uv_mutex_unlock(&i->comp->operations_mutex);
	}

	rtbuf_t *md = i->custom_md;
	uint32_t size  = CCOW_OBJECT_CHUNK_SIZE;

	if (!i->rb_cmd)
		i->rb_cmd = rtbuf_init_empty();

	struct ccow_metadata_kv *kv;
	uv_buf_t buf[md->nbufs];
	size_t j = 0;
	for (j = 0; j < md->nbufs; j++) {
		const uint8_t *payload = NULL;
		msgpack_u *u = msgpack_unpack_init_p(&rtbuf(md, j), 0);
		if (!u)
			goto _exit_free;
		buf[j].len = sizeof (*kv);
		kv = je_calloc(1, sizeof (*kv));
		buf[j].base = (void *)kv;
		if (!kv) {
			msgpack_unpack_free(u);
			goto _exit_free;
		}
		kv->mdtype = CCOW_MDTYPE_CUSTOM;
		msgpack_unpack_raw(u, &payload, &size);
		kv->key = je_memdup((char *)payload, size);
		kv->key_size = size;
		int code = msgpack_unpack_peek(u);
		switch (code) {
			case MSGPACK_FIX: {
				kv->type = CCOW_KVTYPE_INT8;
				kv->value = je_malloc(sizeof (int8_t));
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				err = msgpack_unpack_fix(u,
				    (int8_t *)kv->value);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
			}
			break;
			case MSGPACK_RAW: {
				kv->type = CCOW_KVTYPE_RAW;
				err = msgpack_unpack_raw(u, &payload, &size);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				kv->value = je_memdup((char *)payload, size);
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				kv->value_size = size;
			}
			break;
			case MSGPACK_UINT64: {
				kv->type = CCOW_KVTYPE_UINT64;
				kv->value = je_malloc(sizeof (uint64_t));
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				err = msgpack_unpack_uint64(u,
				    (uint64_t *)kv->value);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
			}
			break;
			case MSGPACK_UINT32: {
				kv->type = CCOW_KVTYPE_UINT32;
				kv->value = je_malloc(sizeof (uint32_t));
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				err = msgpack_unpack_uint32(u,
				    (uint32_t *)kv->value);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
			}
			break;
			case MSGPACK_UINT16: {
				kv->type = CCOW_KVTYPE_UINT16;
				kv->value = je_malloc(sizeof (uint16_t));
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				err = msgpack_unpack_uint16(u,
				    (uint16_t *)kv->value);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
			}
			break;
			case MSGPACK_UINT8: {
				kv->type = CCOW_KVTYPE_UINT8;
				kv->value = je_malloc(sizeof (uint8_t));
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				err = msgpack_unpack_uint8(u,
				    (uint8_t *)kv->value);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
			}
			break;
			case MSGPACK_INT64: {
				kv->type = CCOW_KVTYPE_INT64;
				kv->value = je_malloc(sizeof (int64_t));
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				err = msgpack_unpack_int64(u,
				    (int64_t *)kv->value);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
			}
			break;
			case MSGPACK_INT32: {
				kv->type = CCOW_KVTYPE_INT32;
				kv->value = je_malloc(sizeof (int32_t));
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				err = msgpack_unpack_int32(u,
				    (int32_t *)kv->value);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
			}
			break;
			case MSGPACK_INT16: {
				kv->type = CCOW_KVTYPE_INT16;
				kv->value = je_malloc(sizeof (int16_t));
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				err = msgpack_unpack_int16(u,
				    (int16_t *)kv->value);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
			}
			break;
			case MSGPACK_INT8: {
				kv->type = CCOW_KVTYPE_INT8;
				kv->value = je_malloc(sizeof (int8_t));
				if (!kv->value) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
				err = msgpack_unpack_int8(u,
				    (int8_t *)kv->value);
				if (err) {
					msgpack_unpack_free(u);
					goto _exit_free;
				}
			}
			break;
			default:
				log_error(lg, "INVALID MSG_TYPE \
				    0x%x:0x%x nbuf:%d:%d\n", code, MSGPACK_RAW,
				    (int)md->nbufs, (int)j);
				break;
		}
		msgpack_unpack_free(u);
	}

	err = rtbuf_add(i->rb_cmd, buf, j);
	if (err)
		goto _exit_free;
	err = rtbuf_add_mapped(i->rb, buf, j);
	if (err)
		goto _exit_free;
	return 0;

_exit_free:
	for (size_t x = 0; x < j; x++) {
		kv = (struct ccow_metadata_kv *)buf[x].base;
		je_free(kv->key);
		je_free(kv->value);
		je_free(kv);
	}
	return -ENOMEM;
}



#define ALLOC_KV_BASE_SET_MD(_kvtype, _type, _idx) \
	buf[i].len = sizeof (*kv); \
	kv = je_calloc(1, sizeof (*kv)); \
	if (!kv) \
		goto _exit_free; \
	buf[i].base = (void *)kv; \
	kv->mdtype = CCOW_MDTYPE_METADATA; \
	kv->type = (_kvtype); \
	kv->key = je_strdup((_type)); \
	if (!kv->key) { \
		je_free(kv); \
		goto _exit_free; \
	} \
	kv->key_size = strlen(kv->key); \
	kv->idx = _idx;

#define ERR_CHK(_key) \
	if (!(_key)) \
		goto _exit_free;

#define DEFAULT_MD_ITEMS 40

/*
 * Unpack the vmmetadata structure and return it as a new rtbuf to the
 * iterator.
 */
int
ccow_decode_default_md(ccow_lookup_t iter)
{

	assert(iter);
	struct ccow_lookup *li = (struct ccow_lookup *)iter;
	struct vmmetadata *md = li->metadata;
	struct ccow_metadata_kv *kv;
	uv_buf_t buf[DEFAULT_MD_ITEMS];
	int i = 0;

	/* nothing to do? */
	if (!md)
		return 0;

	if (!li->rb_md)
		li->rb_md = rtbuf_init_empty();
	/* cid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_RAW, RT_SYSKEY_CLUSTER,
	    RT_SYSKEY_CLUSTER_IDX);
	kv->value = (char *)je_memdup(md->cid, md->cid_size);
	ERR_CHK(kv->value);
	kv->value_size = md->cid_size;
	i++;

	/* tid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_RAW, RT_SYSKEY_TENANT,
	    RT_SYSKEY_TENANT_IDX);
	kv->value = (char *)je_memdup(md->tid, md->tid_size);
	ERR_CHK(kv->value)
	kv->value_size = md->tid_size;
	i++;

	/* bid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_RAW, RT_SYSKEY_BUCKET,
	    RT_SYSKEY_BUCKET_IDX);
	kv->value = (char *)je_memdup(md->bid, md->bid_size);
	ERR_CHK(kv->value)
	kv->value_size = md->bid_size;
	i++;

	/* oid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_RAW, RT_SYSKEY_OBJECT,
	    RT_SYSKEY_OBJECT_IDX);
	kv->value = (char *)je_memdup(md->oid, md->oid_size);
	ERR_CHK(kv->value)
	kv->value_size = md->oid_size;
	i++;

	/* phid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT512, RT_SYSKEY_PARENT_HASH_ID,
	    RT_SYSKEY_PARENT_HASH_ID_IDX);
	kv->value = (uint512_t *)je_calloc(1, sizeof(uint512_t));
	ERR_CHK(kv->value);
	*(uint512_t *)kv->value = md->phid;
	i++;

	/* chid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT512, RT_SYSKEY_CLUSTER_HASH_ID,
	    RT_SYSKEY_CLUSTER_HASH_ID_IDX);
	kv->value = (uint512_t *)je_calloc(1, sizeof(uint512_t));
	ERR_CHK(kv->value);
	*(uint512_t *)kv->value = md->chid;
	i++;

	/* nhid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT512, RT_SYSKEY_NAME_HASH_ID,
	    RT_SYSKEY_NAME_HASH_ID_IDX);
	kv->value = (uint512_t *)je_calloc(1, sizeof(uint512_t));
	ERR_CHK(kv->value);
	*(uint512_t *)kv->value = md->nhid;
	i++;

	/* thid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT512, RT_SYSKEY_TENANT_HASH_ID,
	    RT_SYSKEY_TENANT_HASH_ID_IDX);
	kv->value = (uint512_t *)je_calloc(1, sizeof(uint512_t));
	ERR_CHK(kv->value);
	*(uint512_t *)kv->value = md->thid;
	i++;

	/* bhid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT512, RT_SYSKEY_BUCKET_HASH_ID,
	    RT_SYSKEY_BUCKET_HASH_ID_IDX);
	kv->value = (uint512_t *)je_calloc(1, sizeof(uint512_t));
	ERR_CHK(kv->value);
	*(uint512_t *)kv->value = md->bhid;
	i++;

	/* ohid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT512, RT_SYSKEY_OBJECT_HASH_ID,
	    RT_SYSKEY_OBJECT_HASH_ID_IDX);
	kv->value = (uint512_t *)je_calloc(1, sizeof(uint512_t));
	ERR_CHK(kv->value);
	*(uint512_t *)kv->value = md->ohid;
	i++;

	/* vm_chid */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT512, RT_SYSKEY_VM_CONTENT_HASH_ID,
	    RT_SYSKEY_VM_CONTENT_HASH_ID_IDX);
	kv->value = (uint512_t *)je_calloc(1, sizeof(uint512_t));
	ERR_CHK(kv->value);
	*(uint512_t *)kv->value = li->comp->vm_content_hash_id;
	i++;

	/* uint128_t uvid_src_guid; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT128, RT_SYSKEY_UVID_SRC_GUID,
	    RT_SYSKEY_UVID_SRC_GUID_IDX);
	kv->value = (uint128_t *)je_calloc(1, sizeof(uint128_t));
	ERR_CHK(kv->value);
	*(uint128_t *)kv->value = md->uvid_src_guid;
	i++;

	/* uint64_t logical_size; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT64, RT_SYSKEY_LOGICAL_SIZE,
	    RT_SYSKEY_LOGICAL_SIZE_IDX);
	kv->value = (uint64_t *)je_calloc(1, sizeof(uint64_t));
	ERR_CHK(kv->value);
	*(uint64_t *)kv->value = md->logical_size;
	i++;

	/* uint64_t logical_size; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT64, RT_SYSKEY_PREV_LOGICAL_SIZE,
	    RT_SYSKEY_PREV_LOGICAL_SIZE_IDX);
	kv->value = (uint64_t *)je_calloc(1, sizeof(uint64_t));
	ERR_CHK(kv->value);
	*(uint64_t *)kv->value = md->prev_logical_size;
	i++;

	/* uint64_t object_count; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT64, RT_SYSKEY_OBJECT_COUNT,
	    RT_SYSKEY_OBJECT_COUNT_IDX);
	kv->value = (uint64_t *)je_calloc(1, sizeof(uint64_t));
	ERR_CHK(kv->value);
	*(uint64_t *)kv->value = md->object_count;
	i++;

	/* uint16_t uvid_src_cookie; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT32, RT_SYSKEY_UVID_SRC_COOKIE,
	    RT_SYSKEY_UVID_SRC_COOKIE_IDX);
	kv->value = (uint32_t *)je_calloc(1, sizeof(uint32_t));
	ERR_CHK(kv->value);
	*(uint32_t *)kv->value = md->uvid_src_cookie;
	i++;

	/* uint64_t uvid_timestamp; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT64, RT_SYSKEY_UVID_TIMESTAMP,
	    RT_SYSKEY_UVID_TIMESTAMP_IDX);
	kv->value = (uint64_t *)je_calloc(1, sizeof(uint64_t));
	ERR_CHK(kv->value);
	*(uint64_t *)kv->value = md->uvid_timestamp;
	i++;

	/* uint64_t creation_time; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT64, RT_SYSKEY_CREATION_TIME,
	    RT_SYSKEY_CREATION_TIME_IDX);
	kv->value = (uint64_t *)je_calloc(1, sizeof(uint64_t));
	ERR_CHK(kv->value);
	*(uint64_t *)kv->value = md->creation_time;
	i++;

	/* uint64_t txid_generation; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT64, RT_SYSKEY_TX_GENERATION_ID,
	    RT_SYSKEY_TX_GENERATION_ID_IDX);
	kv->value = (uint64_t *)je_calloc(1, sizeof(uint64_t));
	ERR_CHK(kv->value);
	*(uint64_t *)kv->value = md->txid_generation;
	i++;

	/* uint8_t object_deleted; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_OBJECT_DELETED,
	    RT_SYSKEY_OBJECT_DELETED_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->object_deleted;
	i++;

	/* char chunkmap_type[REPLICAST_CHUNKMAP_MAXLEN]; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_STR, RT_SYSKEY_CHUNKMAP_TYPE,
	    RT_SYSKEY_CHUNKMAP_TYPE_IDX);
	kv->value = (char *)je_strdup(md->chunkmap_type);
	ERR_CHK(kv->value);
	kv->value_size = strlen(kv->value) + 1;
	i++;

	/* uint32_t chunkmap_chunk_size */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT32, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE,
	    RT_SYSKEY_CHUNKMAP_CHUNK_SIZE_IDX);
	kv->value = (uint32_t *)je_calloc(1, sizeof(uint32_t));
	ERR_CHK(kv->value);
	*(uint32_t *)kv->value = md->chunkmap_chunk_size;
	i++;

	/* uint16_t chunkmap_btree_order; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT16,
	    RT_SYSKEY_CHUNKMAP_BTREE_ORDER, RT_SYSKEY_CHUNKMAP_BTREE_ORDER_IDX);
	kv->value = (uint16_t *)je_calloc(1, sizeof(uint16_t));
	ERR_CHK(kv->value);
	*(uint16_t *)kv->value = md->chunkmap_btree_order;
	i++;

	/* uint8_t chunkmap_btree_marker */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_CHUNKMAP_BTREE_MARKER,
	    RT_SYSKEY_CHUNKMAP_BTREE_MARKER_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->chunkmap_btree_marker;
	i++;

	/* uint8_t hash_type; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_HASH_TYPE,
	    RT_SYSKEY_HASH_TYPE_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->hash_type;
	i++;

	/* uint8_t compress_type; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_COMPRESS_TYPE,
	    RT_SYSKEY_COMPRESS_TYPE_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->compress_type;
	i++;

	/* uint64_t estimated_used; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT64, RT_SYSKEY_ESTIMATED_USED,
	    RT_SYSKEY_ESTIMATED_USED_IDX);
	kv->value = (uint64_t *)je_calloc(1, sizeof(uint64_t));
	ERR_CHK(kv->value);
	*(uint64_t *)kv->value = md->estimated_used;
	i++;

	/* uint8_t replication_count; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_REPLICATION_COUNT,
	    RT_SYSKEY_REPLICATION_COUNT_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->replication_count;
	i++;

	/* uint8_t sync_put; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_SYNC_PUT,
	    RT_SYSKEY_SYNC_PUT_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->sync_put;
	i++;

	/* uint8_t select_policy; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_SELECT_POLICY,
	    RT_SYSKEY_SELECT_POLICY_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->select_policy;
	i++;

	/* uint8_t failure_domain; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_FAILURE_DOMAIN,
	    RT_SYSKEY_FAILURE_DOMAIN_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->failure_domain;
	i++;

	/* uint16_t number_of_versions; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT16, RT_SYSKEY_NUMBER_OF_VERSIONS,
	    RT_SYSKEY_NUMBER_OF_VERSIONS_IDX);
	kv->value = (uint16_t *)je_calloc(1, sizeof(uint16_t));
	ERR_CHK(kv->value);
	*(uint16_t *)kv->value = md->number_of_versions;
	i++;

	/* uint16_t track_statistics */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT16, RT_SYSKEY_TRACK_STATISTICS,
	    RT_SYSKEY_TRACK_STATISTICS_IDX);
	kv->value = (uint16_t *)je_calloc(1, sizeof(uint16_t));
	ERR_CHK(kv->value);
	*(uint16_t *)kv->value = md->track_statistics;
	i++;

	/* uint32_t iops_rate_lim */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT16, RT_SYSKEY_IOPS_RATE_LIM,
	    RT_SYSKEY_IOPS_RATE_LIM_IDX);
	kv->value = (uint32_t *)je_calloc(1, sizeof(uint32_t));
	ERR_CHK(kv->value);
	*(uint32_t *)kv->value = md->iops_rate_lim;
	i++;

	/* uint8_t ec_enabled */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_EC_ENABLED,
	    RT_SYSKEY_EC_ENABLED_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->ec_enabled;
	i++;

	/* uint64_t ec_data_mode */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT32, RT_SYSKEY_EC_DATA_MODE,
	    RT_SYSKEY_EC_DATA_MODE_IDX);
	kv->value = (uint32_t *)je_calloc(1, sizeof(uint32_t));
	ERR_CHK(kv->value);
	*(uint32_t *)kv->value = md->ec_data_mode;
	i++;

	/* uint64_t ec_trg_policy */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT64, RT_SYSKEY_EC_TRG_POLICY,
	    RT_SYSKEY_EC_TRG_POLICY_IDX);
	kv->value = (uint64_t *)je_calloc(1, sizeof(uint64_t));
	ERR_CHK(kv->value);
	*(uint64_t *)kv->value = md->ec_trg_policy;
	i++;

	/* uint8_t file_object_transparency */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT8, RT_SYSKEY_FILE_OBJECT_TRANSPARANCY,
			RT_SYSKEY_FILE_OBJECT_TRANSPARANCY_IDX);
	kv->value = (uint8_t *)je_calloc(1, sizeof(uint8_t));
	ERR_CHK(kv->value);
	*(uint8_t *)kv->value = md->file_object_transparency;
	i++;

	/* uint64_t object_delete_after */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT64, RT_SYSKEY_OBJECT_DELETE_AFTER,
			RT_SYSKEY_OBJECT_DELETE_AFTER_IDX);
	kv->value = (uint64_t *)je_calloc(1, sizeof(uint64_t));
	ERR_CHK(kv->value);
	*(uint64_t *)kv->value = md->object_delete_after;
	i++;

	/* uint16_t inline_data_flags; */
	ALLOC_KV_BASE_SET_MD(CCOW_KVTYPE_UINT16, RT_SYSKEY_INLINE_DATA_FLAGS,
	    RT_SYSKEY_INLINE_DATA_FLAGS_IDX);
	kv->value = (uint16_t *)je_calloc(1, sizeof(uint16_t));
	ERR_CHK(kv->value);
	*(uint16_t *)kv->value = md->inline_data_flags;
	i++;

	/*
	 * We need to set i->rb to encapsulate kv[0-n] in bufs.
	 */
	int err = rtbuf_add(li->rb_md, buf, DEFAULT_MD_ITEMS);
	if (err)
		goto _exit_free;
	err = rtbuf_add_mapped(li->rb, buf, DEFAULT_MD_ITEMS);
	if (err)
		goto _exit_free;

	return 0;

_exit_free:
	for (int j = 0; j < i; j++) {
		kv = (struct ccow_metadata_kv *)buf[j].base;
		je_free(kv->key);
		je_free(kv->value);
		je_free(kv);
	}
	return -ENOMEM;
}

static int
ccow_decode_name_index(ccow_lookup_t iter)
{
	struct ccow_lookup *li = (struct ccow_lookup *)iter;
	rtbuf_t *rb_ni = li->name_index;

	if (!rb_ni)
		return 0;
	return rtbuf_add_mapped(li->rb, rb_ni->bufs, rb_ni->nbufs);
}

static int
ccow_decode_versions(ccow_lookup_t iter)
{
	struct ccow_lookup *li = (struct ccow_lookup *)iter;
	rtbuf_t *rb_ver = li->versions;

	if (!rb_ver)
		return 0;
	return rtbuf_add_mapped(li->rb, rb_ver->bufs, rb_ver->nbufs);
}


int
ccow_iter_update_md(ccow_lookup_t iter, struct vmmetadata *md)
{
	struct ccow_lookup *li = (struct ccow_lookup *)iter;

	/* nothing to do? */
	if (!li->rb_md)
		return 0;
	rtbuf_t *rb = li->rb_md;

	assert(li->metadata);

	for (size_t i = 0; i < rb->nbufs; i++) {
		struct ccow_metadata_kv *kv =
			(struct ccow_metadata_kv *)rtbuf(rb, i).base;
		switch (kv->idx) {
		case RT_SYSKEY_LOGICAL_SIZE_IDX:
			*(uint64_t *)kv->value = md->logical_size;
			break;
		case RT_SYSKEY_PREV_LOGICAL_SIZE_IDX:
			*(uint64_t *)kv->value = md->prev_logical_size;
			break;
		case RT_SYSKEY_VM_CONTENT_HASH_ID_IDX:
			*(uint512_t *)kv->value = li->comp->vm_content_hash_id;
			break;
		case RT_SYSKEY_UVID_SRC_COOKIE_IDX:
			*(uint32_t *)kv->value = md->uvid_src_cookie;
			break;
		case RT_SYSKEY_UVID_TIMESTAMP_IDX:
			*(uint64_t *)kv->value = md->uvid_timestamp;
			break;
		case RT_SYSKEY_CREATION_TIME_IDX:
			*(uint64_t *)kv->value = md->creation_time;
			break;
		case RT_SYSKEY_TX_GENERATION_ID_IDX:
			*(uint64_t *)kv->value = md->txid_generation;
			break;
		default:;
		};
	}

	return 0;
}

/*
 * Create new lookup object
 *
 * Scope: PRIVATE
 */
struct ccow_lookup *
ccow_lookup_create(struct ccow_completion *comp, ccow_lookup_class_t type)
{
	struct ccow_lookup *lp = je_calloc(1, sizeof (*lp));
	if (!lp)
		return NULL;
	lp->comp = comp;
	lp->rb = rtbuf_init_empty();
	if (!lp->rb) {
		je_free(lp);
		return NULL;
	}
	lp->type = type;

	return lp;
}

/*
 * Iterate over lookup object
 *
 * Scope: PUBLIC
 */
void *
ccow_lookup_iter(ccow_lookup_t clp, int mdtype, int start)
{
	assert(clp != NULL);

	struct ccow_lookup *lp = clp;
	rtbuf_t *rb = lp->rb;

	if (!lp->unpacked || rb->nbufs == 0) {
		int err;

		/*
		 * Hitting either of these error cases means the calling
		 * function was sending corrupt md.
		 */
		if (mdtype & CCOW_MDTYPE_METADATA) {
			err = ccow_decode_default_md(lp);
			if (err)
				return NULL;
		}

		if (mdtype & CCOW_MDTYPE_CUSTOM) {
			err = ccow_decode_custom_md(lp);
			if (err)
				return NULL;
		}

		if (mdtype & CCOW_MDTYPE_NAME_INDEX) {
			err = ccow_decode_name_index(lp);
			if (err)
				return NULL;
		}

		if (mdtype & CCOW_MDTYPE_VERSIONS) {
			err = ccow_decode_versions(lp);
			if (err)
				return NULL;
		}

		lp->unpacked = 1;
	}

	if (start >= 0)
		lp->pos = start;
	if (rb->nbufs <= lp->pos)
		return NULL;
	void *ent = rtbuf(lp->rb, lp->pos).base;
	lp->pos++;
	return ent;
}

/*
 * Release previously allocated lookup object.
 *
 * Scope: PUBLIC
 */
void
ccow_lookup_release(ccow_lookup_t clp)
{
	struct ccow_lookup *lp = clp;

	if (lp->metadata) {
		if (lp->metadata->cid)
			je_free(lp->metadata->cid);
		if (lp->metadata->tid)
			je_free(lp->metadata->tid);
		if (lp->metadata->bid)
			je_free(lp->metadata->bid);
		if (lp->metadata->oid)
			je_free(lp->metadata->oid);
		je_free(lp->metadata);
		/*
		 * When metadata exists but lookup_iter wasnt called by user
		 * to populate lp->rb_md.
		 */
		if (lp->rb_md) {
			ccow_iter_free_rtbuf(lp->rb_md);
			rtbuf_destroy(lp->rb_md);
			lp->rb_md = NULL;
		}
	}
	/* Free the key-value pairs stored in rb_cmd. */
	if (lp->comp)
		uv_mutex_lock(&lp->comp->operations_mutex);
	if (lp->rb_cmd) {
		ccow_iter_free_rtbuf(lp->rb_cmd);
		rtbuf_destroy(lp->rb_cmd);
	}
	if (lp->custom_md) {
		/* Destroy the custom_md msgpack copies. */
		rtbuf_destroy(lp->custom_md);
		if (lp->custom_md == lp->comp->custom_md)
			lp->comp->custom_md = NULL;
	}
	if (lp->comp)
		uv_mutex_unlock(&lp->comp->operations_mutex);
	if (lp->acl) {
		ccow_iter_free_rtbuf(lp->acl);
		rtbuf_destroy(lp->acl);
	}
	if (lp->name_index) {
		ccow_iter_free_rtbuf(lp->name_index);
		rtbuf_destroy(lp->name_index);
	}
	if (lp->versions) {
		ccow_iter_free_rtbuf(lp->versions);
		rtbuf_destroy(lp->versions);
	}
	if (lp->rb)
		rtbuf_destroy_safe(lp->rb);

	je_free(lp);
}

/*
 * Get number of key-value pairs
 *
 * Scope: PUBLIC
 */
size_t
ccow_lookup_length(ccow_lookup_t clp, int mdtype)
{
	struct ccow_lookup *lp = clp;
	/* Initialize the lookup iter if necessary. */
	ccow_lookup_iter(lp, mdtype, -1);
	if (lp->rb)
		return lp->rb->nbufs;
	return 0;
}


/*
 * mdtype is a bitmask defined as :
 * #define CCOW_MDTYPE_METADATA		0x1
 * #define CCOW_MDTYPE_CUSTOM		0x2
 * #define CCOW_MDTYPE_ACL		0x4
 * #define CCOW_MDTYPE_NAME_INDEX	0x8
 * #define CCOW_MDTYPE_ALL		0xFF
 */
void
ccow_dump_iter_to_logger(ccow_lookup_t iter, int mdtype)
{
	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter, mdtype, pos++))) {
		if (kv->type == CCOW_KVTYPE_INT8)
			log_warn(lg, "%s: %d\n", kv->key, *(int8_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_INT16)
			log_warn(lg, "%s: %d\n", kv->key, *(int16_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_INT32)
			log_warn(lg, "%s: %d\n", kv->key, *(int32_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_INT64)
			log_warn(lg, "%s: %ld\n", kv->key, *(int64_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT8)
			log_warn(lg, "%s: %" PRIu8 "\n", kv->key, *(uint8_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT16)
			log_warn(lg, "%s: %" PRIu16 "\n", kv->key, *(uint16_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT64)
			log_warn(lg, "%s: %" PRIu64"\n", kv->key, *(uint64_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT32)
			log_warn(lg, "%s: %" PRIu32 "\n", kv->key, *(uint32_t*)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT128) {
			char vv[sizeof (uint128_t) * 2 + 1];
			uint128_dump((uint128_t *)kv->value, vv, sizeof (uint128_t) * 2 + 1);
			log_warn(lg, "%s: %s\n", kv->key, vv);
		}
		if (kv->type == CCOW_KVTYPE_UINT512) {
			char vv[sizeof (uint512_t) * 2 + 1];
			uint512_dump((uint512_t *)kv->value, vv, sizeof (uint512_t) * 2 + 1);
			log_warn(lg, "%s: %s\n", kv->key, vv);
		}
		if (kv->type == CCOW_KVTYPE_STR) {
			char *b = je_malloc(kv->key_size + 1);
			assert(b);
			char *c = je_malloc(kv->value_size + 1);
			assert(c);
			if (kv->key)
				memcpy(b, kv->key, kv->key_size);
			b[kv->key_size] = '\0';
			if (kv->value)
				memcpy(c, kv->value, kv->value_size);
			c[kv->value_size] = '\0';
			log_warn(lg, "%s: %s\n", b, c);
			je_free(b);
			je_free(c);
		}
		if (kv->type == CCOW_KVTYPE_RAW) {
			char *b = je_malloc(kv->key_size + 1);
			assert(b);
			char *c = je_malloc(kv->value_size + 1);
			assert(c);
			if (kv->key)
				memcpy(b, kv->key, kv->key_size);
			b[kv->key_size] = '\0';
			if (kv->value)
				memcpy(c, kv->value, kv->value_size);
			c[kv->value_size] = '\0';
			log_warn(lg, "%s: %s\n", b, c);
			je_free(b);
			je_free(c);
		}
	}
	assert(!kv);
}

