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


#ifndef SRC_LIBREPTRANS_ERASURE_CODING_H_
#define SRC_LIBREPTRANS_ERASURE_CODING_H_

#include "reptrans-data.h"
#include "ccowutil.h"
#include "replicast.h"
#include "ccache.h"
#include "ccow.h"
#include "flexhash.h"
#include "ec-common.h"

struct repdev;
struct flexhash;
struct bg_job_entry;

#define REPTRANS_NREPLICAS_MAX	32 /* Maximum expected number of replicas */
#define NGREQUEST_MAX_RETRY	100
#define NGREQUEST_TIMEOUT_MS	3000
#define NGREQUEST_MAX_REPLIES	REPLICAST_PROPOSALS_MAX
#define PARITY_CHUNK_HASH_TYPE	HASH_TYPE_XXHASH_256
#define EC_PAYLOAD_SIZE_MAX_EMBEDDED (48*1024UL*1024UL)

/**
 * @internal
 */
struct chunk_info {
        uint512_t  chid;       /* chunk's CHID */
        uint8_t    hash_type;  /* chunk's hash type */
        type_tag_t ttype;      /* chunk's type tag */
        size_t     size;       /* size allocated on a disk (from manifest)*/
        uint128_t  vdevs[REPTRANS_NREPLICAS_MAX]; /* ID of VDEVs where chunks reside */
        uint64_t   nvbrs[REPTRANS_NREPLICAS_MAX]; /* Number of VBRs per replica */
        uint32_t   n_vdevs;    /* Number of VDEVs */
        uint64_t    n_vbrs_min; /* Minimum number of VBRs protecting the chunk */
        uint64_t    n_vbrs_max; /* Maximum number of VBRs protecting the chunk */
        uint8_t    flags;    /* Additional context-depended flags*/
};

#define chinfo(rb,i) ((struct chunk_info*)rtbuf((rb),(i)).base)

/**
 * Callback used by ngrequest_locate to notify caller when request is done
 * @param arg    callback's data provided on ngrequest_locate call
 * @param status request status. 0 in case of success, error code otherwise
 * @param cinfo  is an container of struct chunk_info entries provided upon
 *                ngrequest_locate call and filled up with VDEVs and VBRs info.
 *                Allocates memory for struct chunk_info::vdevs which has to be
 *                freed by caller.
 */
typedef int (*ng_locate_cb_t)(void* arg, int32_t status, rtbuf_t* cinfo);

/**
 * Query negotiating group for chunks and count positive answers
 *
 * @param dev        repdev a request is performed on behalf of
 * @param chunk_info a container (array) of struct chunk_info entries.
 *                   Each entry must be filled with chunk's CHID, hash type
 *                   and type tag. Other info will is collected by the request.
 *                   Important: all the chunks have to belong to the same NG.
 * @param rep_count  expected replication count. Used for performance
 *                   optimization. When non-zero a request collects only first
 *                   rep_count number for chunks.
 * @param nhid name hash ID. Used for NG calculation.
 * @param n_vbrs_max maximum number of VBRs to count. 0 don't count, ~0UL calc all fast, but coarse
 * @param cb done callback
 * @param cb_data user data injected as a callback's parameter.
 */
int
ngrequest_locate(struct repdev *dev, rtbuf_t* chunk_info, int32_t rep_count,
        const uint512_t *nhid, size_t n_vbrs_max, ng_locate_cb_t cb, void *cb_data);

/**
 * Query negotiating group for chunks and count positive answers.
 * Extended version allows to considers only locations where exist VBR(s)
 * that meet a criteria: ref_chid match and (or) attr match
 *
 * @param dev        repdev a request is performed on behalf of
 * @param chunk_info a container (array) of struct chunk_info entries.
 *                   Each entry must be filled with chunk's CHID, hash type
 *                   and type tag. Other info will is collected by the request.
 *                   Important: all the chunks have to belong to the same NG.
 * @param rep_count  expected replication count. Used for performance
 *                   optimization. When non-zero a request collects only first
 *                   rep_count number for chunks.
 * @param nhid name hash ID. Used for NG calculation.
 * @param vbr  used to locate a specific VBR or a VBR with some attributes
 * @param attr_mask  applied to to VBR's attribute field before comparison with value
 * @param n_vbrs_max maximum number of VBRs to count. 0 don't count, ~0UL calc all fast, but coarse
 * @param mode operation mode flags
 * @param cb done callback
 * @param cb_data user data injected as a callback's parameter.
 *
 * Operation mode flags:
 *
 * 1. mode |= LOCATE_MATCH_VBR_ATTR
 *  Locate a chunk and check if it has a VBR with specific bitmask. The VBR's
 *  presence will be reported if its attributes match the following condition:
 *  (vbr.attr & attr_mask) == attr_value
 *  The attr_mask is an function argument, attr_value will be taken from vbr->attr
 *
 * 2. mode |= LOCATE_MATCH_REFCHID
 *  Locate a chunk whose refChid matches the one specified in vbr->ref_chid
 *
 * 3. mode |= LOCATE_MATCH_VBR
 *  Locate a chunk that corresponds the  vbr, that is, all its fields match.
 *
 * 4. mode |= LOCATE_FLAG_HAS_PM
 *  The server check for parity manifest when processing the requests.
 *  Can be used for with manifest locate requests only. In a response,
 *  the struct chunk_info::flags has LOCATE_FLAG_HAS_PM bit set if
 *  the parity manifest exists.
 *
 *  LOCATE_MATCH_VBR and (LOCATE_MATCH_VBR_ATTR | LOCATE_MATCH_REFCHID) are
 *  mutually exclusive. User either can locate an entire VBR or a VBR with
 *  refchid/attr fields.
 *
 *  LOCATE_FLAG_ROWEVAC bit is set in struct chunk_info::flags if there is an
 *  evacuation background in progress on the VDEV where a chunk replica resides.
 *
 */
int
ngrequest_locate_ext(struct repdev *dev, rtbuf_t* chunk_info, int32_t rep_count,
		const uint512_t *nhid, struct backref* vbr, uint64_t attr_mask,
		size_t n_vbrs_max, uint32_t mode, ng_locate_cb_t cb, void *cb_data);
/**
 * Locate a single chunk
 *
 * @apram dev  is a repdev the request is performed on behalf of
 * @param info contains chunk information: CHID, hash type, tag type
 * @param nhid chunk Name Hash ID (optional)
 *
 * Note: NG is calculated according to CHID
 */
int
ec_locate_chunk(struct repdev* dev, struct chunk_info* info, const uint512_t* nhid,
	size_t vbrs_max);

/**
 * Locate a single chunk trying several times if FH rebuild in progress
 */
int
ec_locate_chunk_retry(struct repdev* dev, struct chunk_info* info, uint512_t* nhid,
	size_t vbrs_max);

/**
 * Collect chunk information based on manifest's refentry
 *
 * The function filters out refentries which are manifests
 *
 * @param dev     (in)  repdev pointer
 * @param refs    (in)  an array of instances of the struct refentry
 *                      retrieved by unpacking a manifest
 * @param infos   (out) arrays of chunk information entries
 * @param n_infos (out) number of chunk info entries
 */
int
ec_get_chunk_info(struct repdev* dev, rtbuf_t* refs, struct backref* vbr,
	uint64_t attr_mask, size_t vbrs_max, uint32_t mode,
	struct chunk_info** out, int* n_infos_out);

/*
* The erasure coding introduces several new attributes:
*
* RD_ATTR_NCOMP operation is performed without compression,
*               that is the chunk will be stored as is. Expected that the
*               provided CHID is calculated by sender according to hash type.
*               The only exception is the TT_PARITY_MANIFEST which is a resource
*               fork and will be put/gotten using hash ID of the main manifest
*               (chunk or version).
*
* RD_ATTR_TARGETED  put/get will be done on a specified VDEV only.
*                   The @param vdev_nhid has to point to valid VDEV ID.
*                   Replication count will be forced to 1.
*
* RD_ATTR_PARITY_MAP   content type is TT_PARITY_MAP
* RD_ATTR_CHUNK_PARITY content type is TT_CHUNK_PARITY
*
* See replicast.h for definitions
*/


/*
 * Unnamed put implementation used in erasure coding. Synchronous call.
 *
 * @param cl        (in)  cluster object
 * @param chunk     (in)  the chunk to be sent
 * @param rep_count (in)  replication count
 * @param attr      (in)  the unnamed put attributes
 * @param hash_type (in)  chunk hash type
 * @param chid      (in)  CHID to be used in the RT
 * @param vdev_nhid (in)  a pointer to NHID or VDEV, depending on operation type
 *                        Used to calculate NG
 * @param out_chid  (out) the CHID calculated during unnamed put.
 *                        Optional parameter, it's ignored if @param attr has
 *                        RD_ATTR_NCOMP bit is set.
 */
int
ec_unnamed_put_chunk(ccow_t cl, const uv_buf_t* chunk,
        uint8_t rep_count, uint32_t attr, crypto_hash_t hash_type,
        const uint512_t* chid, void* vdev_nhid, uint512_t* out_chid);


typedef enum {
	engcCHID, /* NG has to calculated according to CHID */
	engcNHID, /* NG is calculate using provided NHID */
	engcVDEV, /* NG is calculated using provided VDEV ID (targeted mode) */
	engcNG	/* NG is provided */
} ecNgCalcMode;

/*
 * Unnamed get implementation used in erasure coding. Synchronous call.
 *
 * @param cl        (in)  cluster object
 * @param chid      (in)  CHID of the chunk to be retrieved
 * @param ng_arg    (in)  a pointer to NHID, VDEV or NG, depending on operation type
 *                        Used to calculate NG
 * @param ngMode    (in)  NG calculation mode
 * @param attr      (in)  the unnamed get attributes
 * @param hash_type (in)  chunk hash type
 * @param comp_type (in)  compression type
 * @param result    (out) required chunk
 */
int
ec_unnamed_get_chunk(ccow_t cl, const uint512_t* chid, const void* ng_arg,
	ecNgCalcMode ngMode, uint64_t attr, crypto_hash_t hash_type,
        uint8_t comp_type, uv_buf_t* result);
/*
 * Device info - contains device location information
 */
typedef struct ec_dev_info {
        uint128_t       vdevid;
        uint128_t       hostid;
        uint32_t        zoneid;
        vdevstate_t	state;
        double          usage;
} ec_dev_info_t;


/*
 * Parity set entry
 * For data chubk:
 *   @chunk pointer points to @chunk_info
 *   @vdev_idx is the index in @devices array in @chunk_info
 * For empty chunk,
 *   @chunk pointer is NULL,
 *   @vdev_idx is (uint8_t)(-1)
 *   
 */
typedef enum {
	ECS_PRESENT = 0,
	ECS_MISSING,
	ECS_RECOVERED, /* Chunk is recovered, kept in RAM */
	ECS_RESTORED /* Chunk recovered and stored on disk */
} ec_chunk_status;

typedef struct ec_pset_entry {
	union {
		struct {
			struct chunk_info 	*info;
			uint128_t		tgt_vdev;
			ec_chunk_status		status;
		};
		uint512_t chid;
	};
} ec_pset_entry_t;

/*
 * Parity chunk decription
 *   @chid    content hash id
 *   @vdevid  target device
 */
typedef struct ec_parity_chunk {
	uint512_t	chid;
	uint128_t	vdevid;
	uint64_t	padding;
	uv_buf_t	chunk;
	msgpack_p*	compound;
	struct chunk_info* info;
	ec_chunk_status	status;
} ec_parity_chunk_t;

/*
 * Parity set
 * Each parity set contains n_parity parity chunks
 * All parity chunks are of the same size which is the max of chunk sizes
 * For each parity chunk, @struct @ec_parity_chunk is stored
 * Other chunks are either real, or empty and are represented by @entries
 */
typedef struct ec_pset {
	struct ec_pset_entry    *entries;
	struct ec_parity_chunk	*parity;
	uint8_t			n_parity;
	uint8_t			n_entries;
	uv_buf_t		context;
	uint32_t		n_missing_data;
	uint32_t		n_missing_parity;
} ec_pset_t;

/*
 * Build parity sets
 *
 * @param devices  (in)  dev info array (one per device)
 * @param n_devs   (in)  number of devices
 * @param chunks   (in)  chunk info array (one per device)
 * @param n_chunks (in)  number of chunks
 * @param width    (in)  parity set width
 * @param n_parity (in)  number of parity sets per chunk
 * @param domain   (in)  failure domain
 * @param psets    (out) parity sets
 * @param n_psets  (out) number of parity sets
 *
 */
int
ec_build_parity_sets(struct ec_dev_info *devices, int n_devs,
        struct chunk_info *chunks, int n_chunks, uint8_t width,
        uint8_t n_parity, ec_domain_t domain, uint8_t rep_cnt,
        struct ec_pset **psets, int *n_psets);

/*
 * Erasure coding front-end and back-end definition
 */
#define EC_CM_TEST	0

/* The codec back-end information */
struct ec_codec_info {
	ec_codec_id	  id; /* Coded ID */
	ec_codec_format*  formats; /* Supported formats array */
	int		  n_formats; /* number of supported formats */
	const char*	  name; /* Codedc's unique name */
};

/* Data fragment. Represent data/parity chunk */
struct ec_fragment {
	int 	index; /* Index of fragment within parity set */
	uv_buf_t buf;  /* Data buffer */
};

typedef long unsigned int codec_handle_t;

/**
 * Init codec manager
 */
int
ec_cm_init();

/*
 * Destroy code manager
 */
void
ec_cm_exit();

/**
 * Get codec information.
 *
 * @param id	(in)  coded ID
 * @param info	(out) pointer to codec info instance
 * @returns	0 on success, error code otherwise
 */
int
ec_cm_codec_info(ec_codec_id id, struct ec_codec_info** info);

/**
 * Create an instance of a codec.
 *
 * @param id		(in)  codec ID
 * @param format	(in)  desired coding/decoding format
 * @param handle	(out) codec instance's handle
 * @returns		      0 on success, error code otherwise
 */
int
ec_cm_create_instance(ec_codec_id id, ec_codec_format format,
	codec_handle_t* handle);

/**
 * Encode data and created parity fragments.
 *
 * @param handle	(in) codec handle
 * @param data		(in) fragments to be encoded.
 * @param parity	(out) ouput parity fragments. Caller doesn't have to
 * 			destroy allocated buffers!
 * "@param context	(out) pointer to a buffer where the method stores
 * 			codec context. It must be provided when
 * 			ec_cm_recovery() is called to restore the chunk(s) of
 * 			this set.
 *  @returns		0 on success, error code otherwise
 */

int
ec_cm_encode(codec_handle_t handle, struct ec_fragment* data,
	struct ec_fragment* parity, uv_buf_t* context);
/**
 * Recovery data/parity chunks from known fragments
 *
 * @param handle	(in) codec handle
 * @param fragments	(in/out) data/parity fragments to be used to recover
 * 			lost fragments  (see also ec_codec_vtbl::recovery)
 * @param context	(in) codec context
 * @returns		0 on success, error code otherwise
 */
int
ec_cm_recover(codec_handle_t handle, struct ec_fragment* fragments,
	 uv_buf_t* context);

/**
 * Destroy codec instance
 * @param handle	codec handle
 * @returns		0 on success, error code otherwise
 */
int
ec_cm_destroy_instance(codec_handle_t handle);

/* Erasure coding back-end abstraction layer*/
struct ec_codec_vtbl {
	QUEUE item;
	/**
	 * Initialize codec's static data.
	 * Has to be called first.
	 *
	 * @return 0 on success
	 */
	int (*init)(void);
	/**
	 * De-initialize dodec's static data
	 * Has to be called last.
	 */
	void (*exit)(void);
	/**
	 * Get codec information.
	 * Static method
	 *
	 * @param info (out) required codec info
	 * @return 	0 on success, error code otherwise
	 */
	int (*info)(struct ec_codec_info** info);

	/**
	 * Create codec instance
	 *
	 * @param format	(in) codec format
	 * @param instance	(out) codec instance to be used in subsequent
	 * 			encode/recovery/destroy calls
	 * @returns 		0 on success, error code otherwise
	 */
	int (*create)(ec_codec_format format, void** instance);

	/**
	 * Encode data fragments and create parity fragments
	 *
	 * @param instance	(in) encoder instance
	 * @param data		(int) array of data fragments. Array size is
	 * 			according to encoding format
	 * @param parity	(out) pointer to array of parity fragments.
	 * 			Array is according to encoding format
	 * @param context	(out) pointer to codec context. It must be
	 * 			provided on recovery() call. Backends that
	 * 			doesn't require context support, must force
	 * 			context->len to 0.
	 * @returns 		0 on success, error code otherwise
	 *
	 * A fragment is a codec's operation entity. It contains a pointer to
	 * data or parity chunk, additionally it provides index of a fragment
	 * within data/parity set. Certain backends require this info.
	 * For m data chunks and n parity chunks, indexes of data chunks
	 * are 0..m-1, indexes of parity chunks are m..(m+n-1).
	 *
	 * The method allocates memory for parity chunks and which will be
	 * destroyed upon destroy() call. Caller must not free them cause
	 * backend can use different allocators.
	 */
	int (*encode)(void* instance, struct ec_fragment* data,
		struct ec_fragment* parity, uv_buf_t* context);

	/**
	 * Recovery data/parity chunk(s) from fragments (if possible)
	 *
	 * @param instance	(in) encoder instance
	 * @param fragments	(in/out) data/parity fragments. Important to
	 * 			use correct fragment indexes provided by
	 * 			encode()
	 * @param context	(in) pointer to codec context generated by
	 * 			the encode() method
	 *
	 *  Order of fragments isn't important, but memory has to be allocated
	 *  by caller for all (m+n) fragments. Source buffers have to be
	 *  allocated by caller. Output buffers will be allocated by the
	 *  recover() call, but caller MUST provide their length in
	 *  struct ec_fragment::buf.len and struct ec_fragment::buf.base has to
	 *  be NULL
	 */
	int (*recover)(void* instance, struct ec_fragment* fragments,
		 uv_buf_t* context);
	/**
	 * Destroy encoder instance and associated data.
	 *
	 * @param instance	(in) encoder instance
	 *
	 * The method must destroy all the data chunks it has allocated before.
	 * Pointers must be held by codec instance
	 */
	int (*destroy)(void* instance);
};

extern QUEUE all_ec_codecs;

#define ec_codec_register(codec) \
	static void __attribute__((constructor)) regist_ ## codec(void) { \
		if (!codec.info) \
			panic("the codec '%s' is incomplete\n", #codec); \
		QUEUE_INIT(&codec.item); \
		QUEUE_INSERT_TAIL(&all_ec_codecs, &codec.item); \
	}

/**
 * Check if manifest is going to be encoded.
 *
 * @param dev 		reptrans device instance
 * @param arg 		user supplied argument
 * @param manifest_info	manifest info
 * @param refs_info 	array of infos of entries the manifest has references to
 * @param n_refs  	array size
 */
typedef int (*ec_predicate_t)(struct repdev* dev, void* arg,
	struct chunk_info* manifest_info, struct chunk_info* refs_info,
	int n_refs);

/**
 * Propagate erasure encoding down to manifests.
 *
 * @param dev		reptrans device instance
 * @param refs		chunk/manifest refs
 * @param vbreq		original request for propagation
 * @param rb		original manifest
 * @param fh		flexhash
 */
typedef int (*ec_propagate_t)(struct repdev* dev, rtbuf_t *refs,
    struct verification_request *vbreq, rtbuf_t *rb,
    volatile struct flexhash *fh);

/**
 * Encode a manifest.
 *
 * @param dev		reptrans device instance
 * @param domain	failure domain
 * @param algo		encoding algorithm ID
 * @param fmt		encoding format
 * @param chid		manifest's context hash ID
 * @param ttype		manifest tag type
 */
int
ec_encode_manifest(struct repdev* dev, struct verification_request* vbreq,
	struct bg_job_entry* job);

void
ec_fill_encoder_bg_calls(struct bg_job_entry* job);

void
ec_clean_chunk_infos(struct chunk_info* infos, int n_infos);

struct ec_recovery_stat {
	uint32_t	data_restored; /* Number of restored chunks */
	uint32_t	data_mising; /* Still missing data chunks number */
	uint32_t	parity_missing; /* Still missing parity chunks */
};

#define RECOVER_UNENCODE  (1 << 0) /* transform parity protected to replicas-protected */
#define RECOVER_FAST      (1 << 1) /* Just recovery lost data chunks */
#define RECOVER_HEAL      (1 << 2) /* Recovery data/parity chunks, re-encode if required */
#define RECOVER_FINAL	  (1 << 3) /* Final recovery attempt */
#define RECOVER_REPLICATE (1 << 4) /* Restore number of replicas of data chunks */

int
ec_recover_manifest_from_refs(struct repdev* dev, const uint512_t* chid,
	const uint512_t* nhid, type_tag_t ttag, rtbuf_t* refs, uint8_t flags,
	struct ec_recovery_stat* pstat, int n_retry, struct bg_job_entry* job);

int
ec_recover_manifest_heal(struct repdev* dev, const uint512_t* chid,
	const uint512_t* nhid, type_tag_t ttag, rtbuf_t* refs,
	struct ec_recovery_stat* rstat, struct bg_job_entry* job);

typedef void (*recover_cb_t)(void* arg, int status);

int
ec_recover_manifest_check(struct repdev* dev, const uint512_t* chid,
	type_tag_t tt, uint512_t* nhid, rtbuf_t **refs_out);

int
ec_recover_manifest_exec(struct repdev* dev, const uint512_t* chid,
	type_tag_t tt, uint512_t* nhid, rtbuf_t *refs, uint8_t flags);

int
ec_recover_manifest(struct repdev* dev, const uint512_t* chid, type_tag_t tt,
	uint8_t flags);

/**
 * Server-side manifest locking approach. Only to be used within a host.
 */
struct manifest_lock_entry {
	QUEUE item;
	uint512_t chid;	/* Manifest CHID */
	volatile manifest_lock_status_t status; /* Status of the recovery */
	uv_mutex_t cond_lock;
	uv_cond_t cond_var; /* Status changed conditional variable */
	volatile int ref_cnt;
	volatile int stale;
};

struct manifest_lock_entry *
reptrans_manifest_lock_or_wait(struct repdev* dev, const uint512_t* chid,
	manifest_lock_status_t* status);

void
reptrans_manifest_unlock(struct repdev* dev, struct manifest_lock_entry *re,
	manifest_lock_status_t status);

struct manifest_lock_entry *
reptrans_manifest_trylock(struct repdev* dev, const uint512_t* chid);


void
ec_clean_parity_sets(struct ec_pset* pset, int n_sets);

int
ec_locate_chunk_ext(struct repdev* dev, struct chunk_info* info, uint512_t* nhid,
		struct backref* vbr, uint64_t attr_mask, size_t vbrs_max, uint32_t mode);

#endif /* SRC_LIBREPTRANS_ERASURE_CODING_H_ */
