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
#ifndef __REPTRANS_DATA__H__
#define __REPTRANS_DATA__H__

#include <sys/types.h>
#include <uv.h>
#include <errno.h>
#include "replicast.h"
#include "msort.h"

#ifdef  __cplusplus
extern "C" {
#if 0
}
#endif
#endif

struct ec_pset;
struct flexhash;
struct repdev;

typedef enum {
	TT_INVALID, /* 0 is reserved value */
	TT_NAMEINDEX = 1,
	TT_CHUNK_PAYLOAD,
	TT_VERSION_MANIFEST,
	TT_CHUNK_MANIFEST,
	TT_HASHCOUNT,
	TT_VERIFICATION_QUEUE,
	TT_VERIFIED_BACKREF,
	TT_REPLICATION_QUEUE,
	TT_BATCH_QUEUE,
	TT_BATCH_INCOMING_QUEUE,
	TT_PARITY_MANIFEST,
	TT_ENCODING_QUEUE,
	TT_TRANSACTION_LOG,
	TT_LAST
} type_tag_t;

static char *type_tag_name[] = {
	"TT_INVALID",
	"TT_NAMEINDEX",
	"TT_CHUNK_PAYLOAD",
	"TT_VERSION_MANIFEST",
	"TT_CHUNK_MANIFEST",
	"TT_HASHCOUNT",
	"TT_VERIFICATION_QUEUE",
	"TT_VERIFIED_BACKREF",
	"TT_REPLICATION_QUEUE",
	"TT_BATCH_QUEUE",
	"TT_BATCH_INCOMING_QUEUE",
	"TT_PARITY_MANIFEST",
	"TT_ENCODING_QUEUE",
	"TT_TRANSACTION_LOG",
	"TT_INVALID"
};

static type_tag_t ref_to_ttag[] = {
	TT_INVALID,
	TT_CHUNK_PAYLOAD,       /* RT_REF_TYPE_NORMAL = 1, */
	TT_CHUNK_MANIFEST,      /* RT_REF_TYPE_MANIFEST, */
	TT_INVALID,             /* RT_REF_TYPE_ZEROBLOCK, */
	TT_INVALID,             /* RT_REF_TYPE_INLINE_PAYLOAD, */
	TT_VERSION_MANIFEST,    /* RT_REF_TYPE_INLINE_VERSION */
	TT_CHUNK_MANIFEST       /* RT_REF_TYPE_INLINE_MANIFEST */
};

static type_tag_t
attr_to_type_tag(uint64_t attrs)
{
	return attrs & RD_ATTR_CHUNK_PAYLOAD ? TT_CHUNK_PAYLOAD :
	       attrs & RD_ATTR_CHUNK_MANIFEST ? TT_CHUNK_MANIFEST :
	       attrs & RD_ATTR_VERSION_MANIFEST ? TT_VERSION_MANIFEST :
	       attrs & RD_ATTR_VM_MARKER ? TT_VERSION_MANIFEST :
	       attrs & RD_ATTR_PARITY_MAP ? TT_PARITY_MANIFEST :
	       attrs & RD_ATTR_PARITY_MAP_VM ? TT_PARITY_MANIFEST : 0;
}

static uint64_t
type_tag_to_attr(type_tag_t tt) {
	return tt == TT_CHUNK_PAYLOAD ? RD_ATTR_CHUNK_PAYLOAD :
		   tt == TT_CHUNK_MANIFEST ? RD_ATTR_CHUNK_MANIFEST :
		   tt == TT_VERSION_MANIFEST ? RD_ATTR_VERSION_MANIFEST :
		   tt == TT_PARITY_MANIFEST ? RD_ATTR_PARITY_MAP : 0;
}

/*
 * Unified structure for back references.
 * Used for speculative and verified back references.
 *
 * Field constraints:
 *
 * ref_type  -  reffering chunk type
 *              TT_NAMEINDEX for chunks reffered to by index entries
 *              TT_VERSION_MANIFEST for chunks reffered to by VM
 *		TT_CHUNK_MANIFEST for chunks reffered to by CM
 */
#define VBR_ATTR_EC       (1<<0) /* The chunk is a member of parity set */
/**
 * Introduced since v 2.2:
 * Bits[1..3] of the struct backref::attr define the ttag of a protected chunk.
 * 0 - VBR has an old (< 2.2) format, chunk's ttag is unknown
 * 1 - payload chunk
 * 2 - chunk manifest
 * 3 - version manifest
 *
 */
#define VBR_ATTR_CP       (1<<1) /* The VBR protects a payload chunk */
#define VBR_ATTR_CM       (2<<1) /* The VBR protects a chunk manifest */
#define VBR_ATTR_VM       (3<<1) /* The VBR protects a version manifest */
#define VBR_ATTR_CACHED   (1<<4) /* The object is a chaced one */

#define VBR_TTAG_MASK ~(7UL << 1)

#define BACKREF_SET_TTAG(pvbr, attr) ((pvbr)->attr = ((pvbr)->attr & VBR_TTAG_MASK) | (attr))

static inline uint64_t
reptrans_backref_ttag2attr(type_tag_t ttag) {
	uint64_t attr = 0;
	if (ttag == TT_VERSION_MANIFEST)
		attr = VBR_ATTR_VM;
	else if (ttag == TT_CHUNK_MANIFEST)
		attr = VBR_ATTR_CM;
	else if (ttag == TT_CHUNK_PAYLOAD)
		attr = VBR_ATTR_CP;
	else
		assert(0);
	return attr;
}

static inline type_tag_t
reptrans_backref_attr2ttag(uint64_t attr) {
	type_tag_t ttag = TT_INVALID;
	uint64_t attr_masked = attr & ~VBR_TTAG_MASK;
	if (attr_masked == VBR_ATTR_VM)
		ttag = TT_VERSION_MANIFEST;
	else if (attr_masked & VBR_ATTR_CM)
		ttag = TT_CHUNK_MANIFEST;
	else if (attr_masked & VBR_ATTR_CP)
		ttag = TT_CHUNK_PAYLOAD;
	return ttag;
}

typedef struct backref {
	uint512_t name_hash_id;		/* Object name hash id */
	uint512_t ref_chid;		/* Referring chunk hash id */
	uint64_t generation;		/* Object generation */
	uint64_t uvid_timestamp;	/* Object UVID */
	uint8_t ref_type;		/* Referring chunk type */
	uint8_t ref_hash;		/* Referring chunk hash type */
	uint8_t rep_count;		/* Chunk replication count */
	uint64_t attr;			/* Attributes */
} backref_t;

typedef enum verification_type {
	RT_VERIFY_NORMAL    = 0x01, /* Just verify back reference */
	RT_VERIFY_DELETE    = 0x02, /* Delete back reference for
				       deleted version (expunge/purge/tgt delete
				       case)*/
	RT_VERIFY_REPLICATE = 0x04, /* Verify and start replication for
				       delegated put of a version */
	RT_VERIFY_SKIP_UNVERIFIED = 0x08, /* Verify only if there are some VBR(s) already */
	RT_VERIFY_PARITY    = 0x10, /* Propagation of EC encoding request */
	RT_VERIFY_NO_QUARANTINE = 0x20, /* Current version has to be verified immediately */
	/* Bits 6 and 7 are reserved for ONDEMAND propagation type */
} verification_type_t;

#define VTYPE_ONDEMAND_LOCAL    0
#define VTYPE_ONDEMAND_MDONLY   1
#define VTYPE_ONDEMAND_VMONLY   2
#define VTYPE_ONDEMAND_PIN      3

#define VTYPE_GET_ONDEMAND(vtype) (((vtype)>>6) & 3)
#define VTYPE_SET_ONDEMAND(vtype, mode) ((vtype) = (vtype & 0x3F) | ((mode & 3)<<6))

typedef struct verification_request {
	uint512_t chid;
	uint512_t nhid;
	uint128_t target_vdevid;
	uint64_t uvid_timestamp;
	uint64_t generation;
	struct backref vbr;
	uint8_t vtype;
	uint8_t ttag;
	uint8_t htype;
	uint8_t width;
	uint8_t n_parity;
	uint8_t domain;
	uint8_t algorithm;
} verification_request_t;

int is_dupsort_tt(type_tag_t ttag);
int is_data_type_tag(type_tag_t ttag);
int is_hashcount_data_type_tag(type_tag_t ttag);
int is_rowusage_data_type_tag(type_tag_t ttag);

int reptrans_pack_vbr(msgpack_p *p, struct backref *vbr);
int reptrans_unpack_vbr(msgpack_u *u, struct backref *vbr);

/** Compare two backref-like items */
int vbr_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err);

/** Compare two items with timestamp and thread ids fields at the top */
int ts_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size);

/** Pack batch entry */
int pack_batch_entry(msgpack_p *p, struct verification_request *vbreq);
/** Unpack batch entry */
int unpack_batch_entry(msgpack_u *u, struct verification_request *vbreq, uint64_t* ts);

/** Compare two batch items */
int batch_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err);

int
trlog_cmp_keys(const uint512_t* k1, const uint512_t* k2);

int trlog_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err);

int batch_chk(const void *a_data, const size_t a_size, uint64_t* ts);

int
verqueue_cmp_keys(const uint512_t* k1, const uint512_t* k2);

/** compare two TT_VERIFICATION_QUEUE keys where UVID and GenID embeeded
 *  into CHID */
int verqueue_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err);

/**
 * compare two TT_BATCH_INCOMING_QUEUE keys where coordinated and local time
 * stamps are embedded into
 */
int incomig_queue_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err);

/** Compare two TT_NAMEINDEX items, match UVIDs and GenIDs in reverse order */
int nameindex_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err);

int generic_cmp(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err);

int
ec_unpack_parity_map(msgpack_u *u, struct ec_pset** pset_out, int* n_sets_out,
	int32_t* domain, uint32_t* algo, uint32_t* fmt);
int
ec_pack_parity_map(msgpack_p *p, struct ec_pset* pset, int n_sets,
	int32_t domain, uint32_t algo, uint32_t fmt);

void
ec_free_parity_map(struct ec_pset* pset, int n_sets);
int
reptrans_pack_compound(struct iovec *iov, size_t count, type_tag_t* tt,
	const uint512_t *chid, msgpack_p **p, uint8_t hash_type,
	uint64_t compound_flags);

int
reptrans_unpack_compound(msgpack_u *u, struct iovec **iov, uint32_t *count,
        type_tag_t** tt, uint512_t *chid, uint8_t* hash_type,
        uint8_t* need_version);

typedef int (*reptrans_cmp_method)(const void *a_data, const size_t a_size,
	const void *b_data, const size_t b_size, int* cmp_err);

static inline reptrans_cmp_method get_cmp_method_by_ttag(type_tag_t ttag)
{
	assert(is_dupsort_tt(ttag));
	switch (ttag) {
		case TT_NAMEINDEX:
			return nameindex_cmp;
		case TT_VERIFIED_BACKREF:
			return vbr_cmp;
		case TT_BATCH_QUEUE:
		case TT_ENCODING_QUEUE:
			return batch_cmp;
		default:
			return generic_cmp;
	}
}

static inline int is_ccow_data_tt(type_tag_t ttag)
{
	switch (ttag) {
	/*
	 * the TT_VERSION_MANIFEST isn't included since we want a user
	 * to be able to free some disk space by removing objects
	 * which create new versions and thus, version manifests
	 */
		case TT_CHUNK_MANIFEST:
		case TT_CHUNK_PAYLOAD:
			return 1;
		default:
			return 0;
	}
}

static const char* repdev_status_name[] = {
	"ALIVE",
	"INIT",
	"READONLY_DATA",
	"READONLY_FULL",
	"READONLY_ROWEVAC",
	"READONLY_FORCED",
	"READONLY_FAULT",
	"UNAVAILABLE"
};

typedef enum {
	/*
	 * The VDEV is fully operational.
	 * Any IO types are allowed.
	 */
	REPDEV_STATUS_ALIVE = 0,
	/*
	 * Temporary state during VDEV initialization.
	 */
	REPDEV_STATUS_INIT,
	/*
	 * The VDEV almost full. It doesn't allow placement of payloads and CM.
	 * Can be "upgraded" to the ALIVE if some space is freed.
	 * Deletes are accepted
	 */
	REPDEV_STATUS_READONLY_DATA,
	/*
	 * The disk is full, neither data type are accepted.
	 * Can be "upgraded" to the ALIVE if some space is freed
	 * Deletes are accepted
	 * */
	REPDEV_STATUS_READONLY_FULL,
	/*
	 * The device is read-only due to the row evacuation job.
	 * Changed to ALIVE when the job is done.
	 * Deletes are accepted
	 * */
	REPDEV_STATUS_READONLY_ROWEVAC,
	/*
	 * The read-only state is requested from outside,
	 * e.g. to perform disk maintenance.
	 * Can be changed to any other state.
	 * Deletes are NOT accepted.
	 */
	REPDEV_STATUS_READONLY_FORCED,
	/*
	 * This state is introduced by underlying key-value backend which cannot
	 * store data anymore, but is able to do reads.
	 * E.g. the LMDB goes out of memory map due to a huge free list which
	 * it cannot reuse. The DBIs are relatively small an VDEV utilization doesn't
	 * exceed REPDEV_STATUS_READONLY_DATA threshold. However, the LMDB env
	 * cannot accept new data and requires maintenance.
	 * Deletes are NOT accepted as well.
	 * This state can be changed only to REPDEV_STATUS_UNAVAILABLE
	 */
	REPDEV_STATUS_READONLY_FAULT,
	/*
	 * Read/write/delete operations are disabled.
	 * The VDEV is usually detached from its KV backends.
	 * This state is immutable except external open request.
	 * If succeeded, is sets the VDEV alive.
	 */
	REPDEV_STATUS_UNAVAILABLE
} repdev_status_t;

/* Expiration time for certain (currently just READONLY) states */
#define REPDEV_STATE_EXPIRATION_TIMEOUT_US	(300ULL*1000*1000)

static inline int is_data_tt(type_tag_t ttag)
{
	switch (ttag) {
		case TT_VERSION_MANIFEST:
		case TT_CHUNK_MANIFEST:
		case TT_CHUNK_PAYLOAD:
		case TT_PARITY_MANIFEST:
			return 1;
		default:
			return 0;
	}
}

static inline int
is_keycache_tt(type_tag_t ttag)
{
	switch (ttag) {
		case TT_VERSION_MANIFEST:
		case TT_CHUNK_MANIFEST:
		case TT_CHUNK_PAYLOAD:
			return 1;
		default:
			return 0;
	}
}

static inline int
is_bloom_tt(type_tag_t ttag)
{
	return is_keycache_tt(ttag) || (ttag == TT_NAMEINDEX);
}

#define DEV_METADATA_VM		0x01
#define DEV_METADATA_CM		0x02
#define DEV_METADATA_BGQ_MIN	0x04 /* TT_BATCH_QUEUE | TT_VERIFICATION_QUEUE */
#define DEV_METADATA_BGQ_VER	0x08 /* TT_BATCH_INCOMING_QUEUE */
#define DEV_METADATA_BGQ_REP	0x10 /* TT_REPLICATION_QUEUE */
#define DEV_METADATA_BGQ_ENC	0x20 /* TT_ENCODING_QUEUE */
#define DEV_METADATA_VBR	0x40 /* TT_VERIFIED_BACKREF */
#define DEV_METADATA_PM		0x80 /* TT_PARITY_MANIFEST */

#define DEV_METADATA_MIN_VBR	(DEV_METADATA_BGQ_MIN|DEV_METADATA_VBR)
#define DEV_METADATA_BG_ALL	(DEV_METADATA_MIN_VBR|DEV_METADATA_BGQ_VER|DEV_METADATA_BGQ_REP|DEV_METADATA_BGQ_ENC)
#define DEV_METADATA_ALL	(DEV_METADATA_BG_ALL|DEV_METADATA_VM|DEV_METADATA_CM|DEV_METADATA_PM)
#define DEV_METADATA_DEFAULT	(DEV_METADATA_BG_ALL|DEV_METADATA_VM)

int
is_mdcache_tt(struct repdev* dev, type_tag_t ttag);

static inline int
is_tempmd_tt(type_tag_t ttag)
{
	switch (ttag) {
	case TT_VERIFICATION_QUEUE:
	case TT_BATCH_QUEUE:
	case TT_BATCH_INCOMING_QUEUE:
	case TT_ENCODING_QUEUE:
	case TT_REPLICATION_QUEUE:
	case TT_TRANSACTION_LOG:
			return 1;
		default:
			return 0;
	}
}


int is_dontneed_tt(type_tag_t ttag);

struct rt_imsort;
struct repdev;

/* Two function below are used to convert CHID format to be correctly compared by memcmp */
void
rt_chid_swap_trlog(const uint512_t* chid, uint512_t* chid_out, crypto_hash_t* ht);

void
rt_chid_unswap_trlog(const uint512_t* chid, uint512_t* chid_out);

void
rt_chid_swap_verqueue(const uint512_t* chid, uint512_t* chid_out, crypto_hash_t* ht);

void
rt_chid_unswap_verqueue(const uint512_t* chid, uint512_t* chid_out);

int
is_mdoffload_tt(struct repdev *dev, type_tag_t ttag);

int
reptrans_imsort_create(struct repdev* dev, type_tag_t ttag, void* params,
	struct rt_imsort** handle);

int
reptrans_imsort_destroy(struct rt_imsort* handle);

int
reptrans_imsort_add_kv(struct rt_imsort* handle, crypto_hash_t hash_type,
	uint512_t* key, uv_buf_t* val, int new_part);

int
reptrans_imsort_iterate(struct rt_imsort*,
	int (*)(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	uint512_t *key, uv_buf_t *val, void *param), int key_format);

#define LHTBL_BLOOM_SIZE(hm) ((hm)->init_size*64)
#define LHTBL_BLOOM_MASK(hm) (LHTBL_BLOOM_SIZE((hm)) - 1)

struct rt_lhtbl {
	size_t limit;
	size_t init_size;
	uint64_t* value_hash;
	uint8_t* bloom;
	size_t size;
};

int
rt_lhtbl_hahs(void* buf, size_t len, uint64_t* out);

struct rt_lhtbl*
rt_lhtbl_create(size_t hm_max_size);

void
rt_lhtbl_destroy(struct rt_lhtbl* hm);

int
rt_lhtbl_insert(struct rt_lhtbl* ht, void* buf, size_t size);

void
rt_lhtbl_sort(struct rt_lhtbl* ht);

int
rt_lhtbl_query(struct rt_lhtbl* ht, void* buf, size_t size);

int
rt_duplist_add(struct mlist_node** head, void* data, size_t size, int mapped);

int
rt_duplist2rtbuf(type_tag_t ttag, struct mlist_node* head1, size_t len1,
	struct mlist_node* head2, size_t len2, rtbuf_t* rb, int mapped);


#ifdef  __cplusplus
#if 0
extern "C" {
#endif
}
#endif
#endif /* __REPTRANS_DATA__H__ */
