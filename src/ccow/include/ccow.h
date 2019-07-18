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
#ifndef __CCOW_H__
#define __CCOW_H__

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

/** struct iovec is defined here.
 *  @warning DO NOT REMOVE */
#include <sys/uio.h>

/**
 * @addtogroup libccow
 * @{
 * @file
 * @author Nexenta Systems, Inc
 * @version 1.0
 *
 * @ref license
 */

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @typedef ccow_tenant_stats_t
 *
 * Structure for collecting + aggregating a tenant's accounting data.
 */
struct ccow_tenant_stats {
	uint64_t	tenant_logical_size;	/* Total used logical size */
	uint64_t	tenant_objects;		/* Total number of objects in tenant */
	uint64_t	tenant_buckets;		/* Total number of buckets in tenant */
};
typedef struct ccow_tenant_stats *ccow_tenant_stats_t;

/**
 * @typedef ccow_cluster_stats_t
 *
 * Structure for collecting + aggregating a cluster's accounting data.
 */
struct ccow_cluster_stats {
	uint64_t	cluster_logical_size;	/* Total used logical size */
	uint64_t	cluster_objects;	/* Total number of objects in cluster */
	uint64_t    cluster_estimated_used; /* Cluster estimated used space */
	uint64_t	cluster_tenants;	/* Total number of tenants in cluster */
};
typedef struct ccow_cluster_stats *ccow_cluster_stats_t;


/**
 * @typedef ccow_stats_t
 *
 * Structure for collecting performance-related statistics.
 */
struct ccow_stats {

	struct {
		uint64_t puts;
		uint64_t gets;
		uint64_t put_conts;
		uint64_t get_conts;
		uint64_t zeroblock_get_hits;
		uint64_t zeroblock_put_hits;
		uint64_t thin_read_hits;
		uint64_t dedupe_hits;
	} ccow;

	struct {
		uint64_t cmc_hash_size;	/* number of entries in hash table */
		uint64_t cmc_lru_hiwat;	/* hi limit on the number of LRU entries */
		uint64_t cmc_lru_max;	/* maximum number of entries in LRU queue */
		uint64_t cmc_lru_count;	/* count of entries in the LRU queue */
		uint64_t cmc_lru_lowat;	/* low watermark of entries in the LRU */
					/* queue, prvent evicts below this mark */
		size_t cmc_size_max;	/* maximum used size of cmcache in bytes */
		size_t cmc_size;	/* current size of cmcache in bytes */
		uint64_t cmc_hits;	/* cache hits */
		uint64_t cmc_misses;	/* cache misses */
		uint64_t cmc_put_hits;
		uint64_t cmc_put_misses;
		uint64_t cmc_evicts;
		uint64_t cmc_overwr_evicts;
	} cmcache;

	struct {
		uint64_t puts;
		uint64_t gets;
		size_t ucsize_max;	/* maximum size of ucache in bytes */
		size_t ucsize_lim;
		size_t mem_limit;	/* user defined limit for both CM/U caches */
		size_t ucsize;		/* current size of ucache in bytes */
		size_t total_ram;
		size_t free_ram;
		uint64_t put_hits;
		uint64_t put_misses;
		uint64_t put_evicts;
		uint64_t hits;		/* cache hits */
		uint64_t misses;	/* cache misses */
		uint64_t expand_nomem;
		uint64_t expands;	/* cache expansions */
		uint64_t shrinks;	/* cache shrinks */
		uint64_t inprogs;
		uint64_t size_cur;
		uint64_t size_inc;
		uint64_t size_min;
		uint64_t size_max;
		uint64_t lru_count;
		uint64_t overwr_evicts;
	} ucache;

	struct {
		uint64_t disabled;
		uint64_t enabled;
		uint64_t sequential;
		uint64_t non_sequential;
		uint64_t detected;
		uint64_t not_detected;
		uint64_t factored;
		uint64_t not_factored;
	} read_ahead;
};

typedef struct ccow_stats *ccow_stats_t;

/**
 * @typedef ccow_t
 *
 * A handle for interacting with a CCOW cluster. It encapsulates all
 * CCOW client configuration, including username, key for
 * authentication, logging, and debugging. Talking to different clusters
 * -- or to the same cluster with different users -- requires
 * different cluster handles.
 */
struct ccow;
typedef struct ccow *ccow_t;


/**
 * @typedef ccow_shard_context_t
 *
 * A sharding context structure used for passing shard definition to the sharding methods
 */
struct ccow_shard_context;
typedef struct ccow_shard_context *ccow_shard_context_t;


/*
 * Prefix of tenant ID used to keep track of server's global transaction log
 */
#define	TRLOG_TID_PREFIX	"TRLOG-"
#define TRLOG_DELETE_AFTER_HOURS		(24*7)

#define RT_EXABYTE 1024LU * 1024 * 1024 * 1024* 1024 * 1024
#define RT_PETABYTE 1024LU * 1024 * 1024* 1024 * 1024
#define RT_TERABYTE 1024LU * 1024* 1024 * 1024
/*
 * System keys used to build on-disk JSON-like representations
 */
#define RT_SYSKEY_METADATA		"ccow-metadata"
#define RT_SYSKEY_CLUSTER		"ccow-cluster-id"
#define RT_SYSKEY_TENANT		"ccow-tenant-id"
#define RT_SYSKEY_BUCKET		"ccow-bucket-id"
#define RT_SYSKEY_OBJECT		"ccow-object-id"
#define RT_SYSKEY_CLUSTER_HASH_ID	"ccow-cluster-hash-id"
#define RT_SYSKEY_NAME_HASH_ID		"ccow-name-hash-id"
#define RT_SYSKEY_PARENT_HASH_ID	"ccow-parent-hash-id"
#define RT_SYSKEY_TENANT_HASH_ID	"ccow-tenant-hash-id"
#define RT_SYSKEY_BUCKET_HASH_ID	"ccow-bucket-hash-id"
#define RT_SYSKEY_OBJECT_HASH_ID	"ccow-object-hash-id"
#define RT_SYSKEY_VM_CONTENT_HASH_ID	"ccow-vm-content-hash-id"
#define RT_SYSKEY_VERSION_LIST		"ccow-version-list"
#define RT_SYSKEY_ACL_LIST		"ccow-acl-list"
#define RT_SYSKEY_REFERENCE_LIST	"ccow-reference-list"
#define RT_SYSKEY_OBJECT_DELETED	"ccow-object-deleted"
#define RT_SYSKEY_UVID_TIMESTAMP	"ccow-uvid-timestamp"
#define RT_SYSKEY_UVID_SRC_COOKIE	"ccow-uvid-src-cookie"
#define RT_SYSKEY_UVID_SRC_GUID		"ccow-uvid-src-guid"
#define RT_SYSKEY_TX_GENERATION_ID	"ccow-tx-generation-id"
#define RT_SYSKEY_CREATION_TIME		"ccow-creation-time"
#define RT_SYSKEY_TENANT_CTYPE		"ccow-tenant-ctype"
#define RT_SYSKEY_CHUNKMAP_TYPE		"ccow-chunkmap-type"
#define RT_SYSKEY_CHUNKMAP_CHUNK_SIZE	"ccow-chunkmap-chunk-size"
#define RT_SYSKEY_CHUNKMAP_BTREE_ORDER	"ccow-chunkmap-btree-order"
#define RT_SYSKEY_CHUNKMAP_BTREE_MARKER "ccow-chunkmap-btree-marker"
#define RT_SYSKEY_LOGICAL_SIZE		"ccow-logical-size"
#define RT_SYSKEY_OBJECT_COUNT		"ccow-object-count"
#define RT_SYSKEY_TENANT_STATUS		"ccow-tenant-status"
#define RT_SYSKEY_CUSTOM_METADATA	"ccow-custom-metadata"
#define RT_SYSKEY_INLINE_DATA_FLAGS	"ccow-inline-data-flags"
#define RT_SYSKEY_REPLICATION_COUNT	"ccow-replication-count"
#define RT_SYSKEY_FAILURE_DOMAIN	"ccow-failure-domain"
#define RT_SYSKEY_ESTIMATED_USED	"ccow-estimated-used"
#define RT_SYSKEY_SYNC_PUT		"ccow-sync-put"
#define RT_SYSKEY_SELECT_POLICY		"ccow-select-policy"
#define RT_SYSKEY_HASH_TYPE		"ccow-hash-type"
#define RT_SYSKEY_COMPRESS_TYPE		"ccow-compress-type"
#define RT_SYSKEY_PREV_LOGICAL_SIZE	"ccow-prev-logical-size"
#define RT_SYSKEY_NUMBER_OF_VERSIONS	"ccow-number-of-versions"
#define RT_SYSKEY_TRACK_STATISTICS	"ccow-track-statistics"
#define RT_SYSKEY_IOPS_RATE_LIM		"ccow-iops-rate-lim"
#define RT_SYSKEY_EC_ENABLED		"ccow-ec-enabled"
#define RT_SYSKEY_EC_DATA_MODE		"ccow-ec-data-mode"
#define RT_SYSKEY_EC_TRG_POLICY		"ccow-ec-trigger-policy"
#define RT_SYSKEY_FILE_OBJECT_TRANSPARANCY "ccow-file-object-transparency"
#define RT_SYSKEY_OBJECT_DELETE_AFTER "ccow-object-delete-after"
#define RT_SYSKEY_ONDEMAND		"ccow-ondemand"

/** Just an empty string. Using it can simplify debugging */
extern const char ccow_empty_str[1];

/*
 * System object custom metadata
 */
#define RT_SYSKEY_SYSTEM_GUID		"X-system-guid"
#define RT_SYSKEY_LICENSE		"X-system-license"

#define CCOW_MDTYPE_METADATA	0x1
#define CCOW_MDTYPE_CUSTOM	0x2
#define CCOW_MDTYPE_ACL		0x4
#define CCOW_MDTYPE_NAME_INDEX	0x8
#define CCOW_MDTYPE_VERSIONS	0x10
#define CCOW_MDTYPE_ALL		0xFF

typedef enum {
	CCOW_KVTYPE_BEGIN,
	CCOW_KVTYPE_RAW,
	CCOW_KVTYPE_STR,
	CCOW_KVTYPE_UINT512,
	CCOW_KVTYPE_UINT128,
	CCOW_KVTYPE_UINT64,
	CCOW_KVTYPE_UINT32,
	CCOW_KVTYPE_UINT16,
	CCOW_KVTYPE_UINT8,
	CCOW_KVTYPE_INT64,
	CCOW_KVTYPE_INT32,
	CCOW_KVTYPE_INT16,
	CCOW_KVTYPE_INT8,
	CCOW_KVTYPE_END
} ccow_kvtype_t;

/*
 * RT_ERR_EIO indicates the operation failed because the VDEV experienced a
 * failure trying to access the object. The most common source of these errors
 * is media errors, but other internal errors might cause this as well.
 *
 * RT_ERR_NO_SPACE indicates the operation failed because the VDEV ran out of
 * free capacity during the operation. Edge controlled load balancer would
 * typically hide this error from the client.
 *
 * RT_ERR_BAD_CRED indicates the security parameters are not valid. The
 * primary cause of this is that the capability has expired.
 *
 * RT_ERR_NO_ACCESS indicates the capability does not allow the requested
 * operation.
 *
 * RT_ERR_UNREACHABLE indicates the VDEV did not complete the I/O operation at
 * the VDEV due to a communication failure. Whether the I/O operation was
 * executed by the VDEV or not is undetermined.
 *
 * RT_ERR_NO_RESOURCES indicates the VDEV did not issue the I/O operation due
 * to a local problem, e.g., when running out of memory.
 */
enum replicast_error {
	RT_ERR_UNKNOWN = 1,
	RT_ERR_WRONG_OPCODE,
	RT_ERR_EIO,
	RT_ERR_NO_SPACE,
	RT_ERR_BAD_CRED,
	RT_ERR_NO_ACCESS,
	RT_ERR_UNREACHABLE,
	RT_ERR_NO_RESOURCES,
	RT_ERR_NOT_EMPTY,
	RT_ERR_BAD_NGCOUNT,
	RT_ERR_STALE_FLEXHASH,
	RT_ERR_VERSION_MISMATCH,
	RT_ERR_BLOCKED,
	RT_ERR_UNENCODE,
	RT_ERR_SPLIT, /* A split condition detected */
	RT_ERR_NONCACHEABLE,/* The object is non-cacheable and cannot be (un)pinned */
	RT_ERR_NOT_FOUND, /* Object not found */
	RT_ERR_END
};


/**
 * @typedef ccow_completion_t
 *
 * Represents the state of an asynchronous operation - it contains the
 * return value once the operation completes, and can be used to block
 * until the operation is complete.
 */
struct ccow_completion;
typedef struct ccow_completion *ccow_completion_t;

/**
 * @typedef ccow_metadata_kv_t
 *
 * A handle for holding object metadata key-value pairs.
 * It encapsulates 4 items
 *
 * @item mdtype	Metadata, Custom Metadata, ACL
 * @item type	Data type to dereference value
 * @item key	Pointer to NULL terminated string representing key
 * @item key_size Length of the key
 * @item value	Value
 */
struct ccow_metadata_kv {
	int mdtype;
	ccow_kvtype_t type;
	uint16_t key_size;	/* Size of the key in bytes */
	char *key;
	void *value;
	size_t value_size;	/* Size of the value in bytes */

	/* private */
	int idx;
	char chid[64];
};
typedef struct ccow_metadata_kv *ccow_metadata_kv_t;

struct ccow_lookup;
typedef struct ccow_lookup *ccow_lookup_t;

struct ccow_rmw_context {
	char * ma_bufs;
	uint64_t s0;
	uint64_t s1;
	uint64_t s2;
	size_t l0;
	size_t l1;
	size_t l2;
	char *buf;
};

/**
 * Iterate over lookup object
 *
 * @param clp lookup object
 * @param mdtype filter results by metadata type
 * @param start start position or ignore if it < 0
 * @returns next object or NULL at the end
 */
void *ccow_lookup_iter(ccow_lookup_t clp, int mdtype, int start);

/**
 * Return a formatted and typecast value from iterator.
 *
 * @param type CCOW_KVTYPE_* you want for this key.
 * @param kv pointer to the kv element.
 * @param data space to store the resulting typecast value
 */
void ccow_iterator_kvcast(ccow_kvtype_t type, struct ccow_metadata_kv *kv,
    void *data);

/**
 * Return a formatted and typecast value from iterator.
 *
 * @param type CCOW_KVTYPE_* you want for this key.
 * @param kv pointer to the kv element.
 * @param data space to store the resulting typecast value
 */
void ccow_iterator_kvcast(ccow_kvtype_t type, struct ccow_metadata_kv *kv,
    void *data);

/**
 * Returns int64_t representation of metadata value.
 *
 * @param kv pointer to the kv element.
 * @returns int64_t value or zero
 */
int64_t ccow_kvconvert_to_int64(struct ccow_metadata_kv *kv);

/**
 * Return number of metadata key-value pairs
 *
 * @param clp lookup object
 * @returns number of metadata key-value pairs
 */
size_t ccow_lookup_length(ccow_lookup_t clp, int mdtype);

/**
 * Release previously allocated iterator object
 *
 * @param clp lookup object
 */
void ccow_lookup_release(ccow_lookup_t clp);


/**
 * @typedef ccow_bucket_t
 *
 * A bucket encapsulates information with regards to CCOW bucket. The
 * closest analogy to CCOW bucket is pool and/or container. Bucket aggregates
 * multiple objects together, hence the name "bucket".
 */
struct ccow_bucket;
typedef struct ccow_bucket *ccow_bucket_t;

/**
 * Mount and initialize bucket
 *
 * Tenant will receive dynamic update notifications
 *
 * @param tctx which tenant cluster context the bucket is in
 * @param bid bucket id as a NULL terminated string
 * @param bkctx output created bucket context
 * @returns 0 on success, negative error code on failure
 */
int ccow_bucket_init(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_bucket_t *bkctx);

/**
 * Unmount and de-initialize bucket
 *
 * Tenant will stop receiving dynamic update notifications
 *
 * @param bkctx output created bucket context
 * @returns 0 on success, negative error code on failure
 */
void ccow_bucket_term(ccow_bucket_t bkctx);

/**
 * Get the buckets
 *
 * Lookup for bucket name pattern and retrieve an iterator as a result.
 * Iterator has to be released if not NULL.
 *
 * @param tctx which tenant cluster context the bucket is in
 * @param pattern the tenant name pattern to lookup for
 * @param count the maximum number of elements to return via iterator
 * @param iter output lookup iterator
 * @returns 0 on success, negative error code on failure
 *
 * See ccow_lookup_iter() ccow_lookup_release() on how to use lookup iterators.
 */
int ccow_bucket_lookup(ccow_t tctx, const char *pattern, size_t p_len,
    size_t count, ccow_lookup_t *iter);

/**
 * Create a bucket with default settings
 *
 * @post New bucket will be created within embedded tenant personality scope.
 * See ccow_tenant_init() for more details on configuration.
 *
 * @param tctx the tenant cluster context in which the bucket will be created
 * @param bucket_name the name of the new bucket
 * @param c_in optional_completion preloaded with default_attrs for creation
 * based on the supplied policy
 * @returns 0 on success, negative error code on failure
 */
int ccow_bucket_create(ccow_t tctx, const char *bucket_name, size_t bid_size,
    ccow_completion_t c_in);

/**
 * Delete a bucket and all data inside it
 *
 * The bucket is removed from the cluster immediately,
 * but the actual data is deleted in the background.
 *
 * @param tctx the tenant cluster context the bucket is in
 * @param bucket_name which bucket to delete
 * @returns 0 on success, negative error code on failure
 */
int ccow_bucket_delete(ccow_t tctx, const char *bucket_name, size_t bid_size);


/**
* Create a bucket inode reference object
*
* @post New object will be created in the bucket.
*
* @param tctx the tenant cluster context in which the bucket will be created
* @param bucket_name
* @returns 0 on success, negative error code on failure
*/
int ccow_bucket_inode_ref_create(ccow_t tctx, const char *bid, size_t bid_size,
               const char *oid, size_t oid_size);



/**
 * @typedef ccow_snapview_t
 *
 * A handle for SnapView objects to create and add snapshots with.
 */
struct ccow_snapview;
typedef struct ccow_snapview *ccow_snapview_t;

/**
 * Clone a snapview object.
 *
 * @param tctx tenant context
 * @param sv_hdl snapview handle
 * @param ss_name snapshot name
 * @param ss_name_size size in bytes of ss_name
 * @param tid_dst tenant_id to copy
 * @param bid_dst bucket_id to copy
 * @param oid_dst object_id to copy
 * @returns 0 on success, error on failure
 *
 */
int ccow_clone_snapview_object(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *ss_name, size_t ss_name_size,
    const char *tid_dst, size_t tid_dst_size, const char *bid_dst,
    size_t bid_dst_size, const char *oid_dst, size_t oid_dst_size);

/**
 * Rollback an object to its snapshot version.
 *
 * @param tctx tenant context handle
 * @param sv_hdl snapview handle
 * @param ss_name snapshot name
 * @param ss_name_size size in bytes of ss_name
 * Return zero on success, error otherwise.
 */
int ccow_snapshot_rollback(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *ss_name, size_t ss_name_size);

/**
 * Create a snapview object with bid/oid
 *
 * @param tctx tenant context handle
 * @param sv_hdl snapview handle
 * @param sv_bid snapview bucket object name
 * @param sv_bid_size snapview bucket object name size
 * @param sv_oid snapview object name
 * @param sv_oid_size snapview object name size
 * Return 0 on success, error otherwise.
 */
int ccow_snapview_create(ccow_t tctx, ccow_snapview_t *sv_hdl,
    const char *sv_bid, size_t sv_bid_size, const char *sv_oid,
    size_t sv_oid_size);

/**
 * Delete a snapview object, and all snapshots within it.
 *
 * @param tctx tenant context handle
 * @param sv_hdl snapview handle
 * Return 0 on success, error otherwise.
 */
int ccow_snapview_delete(ccow_t tctx, ccow_snapview_t sv_hdl);

/**
 * Destroy a snapview handle, must be called to clean up the handle.
 *
 * @param sv_hdl snapview handle
 * Return 0 on success, error otherwise.
 */
void ccow_snapview_destroy(ccow_t tctx, ccow_snapview_t sv_hdl);

/**
 * List the contents of a snapview.
 *
 * @param tctx tenant context handle
 * @param sv_hdl snapview handle
 * @param pattern the tenant name pattern to lookup for
 * @param count the maximum number of elements to return via iterator
 * @param iter output lookup iterator
 * @returns 0 on success, negative error code on failure
 */
int ccow_snapshot_lookup(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *pattern, size_t p_len, size_t count, ccow_lookup_t *iter);
/**
 * Create a snapshot of object bid/oid with snapshot name and add it to
 * the SnapView handle
 *
 * @param tctx tenant context
 * @param sv_hdl snapview handle
 * @param bid bucket name
 * @param bid_size bucket name size
 * @param oid object name
 * @param oid_size object name size
 * @param name snapshot name
 * @param name_size snapshot name size in bytes
 * Return 0 on success, error otherwise.
 */
int ccow_snapshot_create(ccow_t tctx, ccow_snapview_t sv_hdl,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    const char *name, size_t name_size);

/**
 * Delete a snapshot from within a snapview object.
 *
 * @param tctx tenant context handle
 * @param sv_hdl snapview handle
 * @param name name of the snapshot to delete
 * @param name_size name size in bytes
 * Return 0 on success, error otherwise.
 */
int ccow_snapshot_delete(ccow_t tctx, ccow_snapview_t sv_hdl, const char *name,
    size_t name_size);

/**
 * @typedef ccow_callback_t
 *
 * Callbacks for asynchronous operations take three parameters:
 * - comp the completion that has finished
 * - arg application defined data made available to the callback function
 * - index index for the completion callback to track outstanding ops
 * - status return code, 0 - success
 */
typedef void (*ccow_callback_t)(ccow_completion_t comp, void *arg,
    int index, int status);

/**
 * Constructs a completion to use with asynchronous operations
 *
 * The complete callback corresponds to operations being acked or committed,
 * based on type of IO request.
 *
 * @param tctx the tenant cluster context to create completion for.
 * @param cb_arg application-defined data passed to the callback function.
 * @param cb_complete the function to be called when the operation is
 * in memory on all replicas or when operation is on stable storage on all
 * replicas or completion on read.
 * @param operations_num the number of inline operations planned for this
 * completion used for asynchronous ops.
 * @param pcomp where to store the completion
 * @returns 0
 */
int ccow_create_completion(ccow_t tctx, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp);

#define CCOW_CONT_F_EXIST                 0x01	/* out - object exists on start */
#define CCOW_CONT_F_REPLACE               0x02	/* in  - request for object replace */
#define CCOW_CONT_F_EPHEMERAL             0x04	/* in  - finalize with temporary version */
#define CCOW_CONT_F_INSERT_LIST_OVERWRITE 0x08	/* in  - overwrite keys in btreenam */
#define CCOW_CONT_F_SKIP_TRLOG_UPDATE     0x10	/* do not insert/delete into a bucket via TRLOG */
#define CCOW_CONT_F_EVENTUAL_SOP          0x20	/* eventual sop call, with small delay */
#define CCOW_CONT_F_PREFETCH_TOUCH        0x40	/* Do an immediate blob touch */
#define CCOW_CONT_F_MDONLY                0x80	/* Fetch only object's metadata */


/**
 * Set/Get stream flags
 *
 * @param int flag to be set
 */
void ccow_stream_flags(ccow_completion_t comp, int *flags);

/**
 * Verifies if completion is released
 *
 * @param comp previously allocated completion
 * @returns 0 or 1
 */
int ccow_completion_released(ccow_completion_t comp);

/**
 * Constructs a completion to use with asynchronous unnamed operations
 *
 * The complete callback corresponds to operations being acked or committed,
 * based on type of IO request.
 *
 * @param tctx the tenant cluster context to create completion for.
 * @param cb_arg application-defined data passed to the callback function.
 * @param cb_complete the function to be called when the operation is
 * in memory on all replicas or when operation is on stable storage on all
 * replicas or completion on read.
 * @param operations_num the number of inline operations planned for this
 * completion used for asynchronous ops.
 * @param pcomp where to store the completion
 * @param bid bucket name holding the object
 * @param bid_size bucket name size
 * @param oid object name to be used for stream operation
 * @param oid_size object name size
 * @param genid generation ID to request as a start of stream
 * @param flags if provided then it will serve as in/out flags for operation
 * @param iter return temporary pointer to MD iterator. Application must not
 * attempt to release it as it will be cleaned up by finalize() or release()
 * @returns 0
 *
 * Application has to supply non-zero genid parameter in order to initialize
 * stream and close stream with ccow_finalize()
 *
 * If specified genid is zero then stream will be initialized with the current
 * maximum generation ID and genid will be used as an output argument.
 *
 * If specified version_vm_content_hash_id the addition check will be done
 * on the GET operations. If version_vm_content_hash_id is NULL the parameter is ignored.
 */
int
ccow_create_stream_completion(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    uint64_t *genid, int *flags, ccow_lookup_t *iter);

/**
 * Constructs a completion to use with asynchronous unnamed operations
 *
 * The complete callback corresponds to operations being acked or committed,
 * based on type of IO request.
 *
 * @param tctx the tenant cluster context to create completion for.
 * @param cb_arg application-defined data passed to the callback function.
 * @param cb_complete the function to be called when the operation is
 * in memory on all replicas or when operation is on stable storage on all
 * replicas or completion on read.
 * @param operations_num the number of inline operations planned for this
 * completion used for asynchronous ops.
 * @param pcomp where to store the completion
 * @param cid cluster name holding the object
 * @param cid_size cluster name size
 * @param tid tenant name to be used for stream operation
 * @param tid_size tenant name size
 * @param bid bucket name holding the object
 * @param bid_size bucket name size
 * @param oid object name to be used for stream operation
 * @param oid_size object name size
 * @param genid generation ID to request as a start of stream
 * @param flags if provided then it will serve as in/out flags for operation
 * @param iter return temporary pointer to MD iterator. Application must not
 * attempt to release it as it will be cleaned up by finalize() or release()
 * @returns 0
 *
 * Application has to supply non-zero genid parameter in order to initialize
 * stream and close stream with ccow_finalize()
 *
 * If specified genid is zero then stream will be initialized with the current
 * maximum generation ID and genid will be used as an output argument.
 *
 * If specified version_vm_content_hash_id the addition check will be done
 * on the GET operations. If version_vm_content_hash_id is NULL the parameter is ignored.
 */
int
ccow_admin_pseudo_create_stream_completion(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp,
    const char *cid, size_t cid_size, const char *tid, size_t tid_size,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
	uint64_t *genid, int *flags, ccow_lookup_t *iter);

/**
 * Constructs a completion to use with asynchronous unnamed operations
 *
 * The complete callback corresponds to operations being acked or committed,
 * based on type of IO request.
 *
 * @param tctx the tenant cluster context to create completion for.
 * @param cb_arg application-defined data passed to the callback function.
 * @param cb_complete the function to be called when the operation is
 * in memory on all replicas or when operation is on stable storage on all
 * replicas or completion on read.
 * @param operations_num the number of inline operations planned for this
 * completion used for asynchronous ops.
 * @param pcomp where to store the completion
 * @param bid bucket name holding the object
 * @param bid_size bucket name size
 * @param oid object name to be used for stream operation
 * @param oid_size object name size
 * @param genid generation ID to request as a start of stream
 * @param version_uvid_timestamp the version timestamp or 0
 * @param version_vm_content_hash_id the vm_content_hash_id of requested version or NULL
 * @param flags if provided then it will serve as in/out flags for operation
 * @param iter return temporary pointer to MD iterator. Application must not
 * attempt to release it as it will be cleaned up by finalize() or release()
 * @returns 0
 *
 * Application has to supply non-zero genid parameter in order to initialize
 * stream and close stream with ccow_finalize()
 *
 * If specified genid is zero then stream will be initialized with the current
 * maximum generation ID and genid will be used as an output argument.
 *
 * If specified version_vm_content_hash_id the addition check will be done
 * on the GET operations. If version_vm_content_hash_id is NULL the parameter is ignored.
 */
int
ccow_create_stream_completion_versioned(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    uint64_t *genid, uint64_t version_uvid_timestamp,
    const char *version_vm_content_hash_id, int *flags, ccow_lookup_t *iter);


/**
 * Constructs a completion to use with asynchronous unnamed operations
 *
 * The complete callback corresponds to operations being acked or committed,
 * based on type of IO request.
 *
 * @param tctx the tenant cluster context to create completion for.
 * @param cb_arg application-defined data passed to the callback function.
 * @param cb_complete the function to be called when the operation is
 * in memory on all replicas or when operation is on stable storage on all
 * replicas or completion on read.
 * @param operations_num the number of inline operations planned for this
 * completion used for asynchronous ops.
 * @param pcomp where to store the completion
 * @param cid cluster name holding the object
 * @param cid_size cluster name size
 * @param tid tenant name to be used for stream operation
 * @param tid_size tenant name size
 * @param bid bucket name holding the object
 * @param bid_size bucket name size
 * @param oid object name to be used for stream operation
 * @param oid_size object name size
 * @param genid generation ID to request as a start of stream
 * @param version_uvid_timestamp the version timestamp or 0
 * @param version_vm_content_hash_id the vm_content_hash_id of requested version or NULL
 * @param flags if provided then it will serve as in/out flags for operation
 * @param iter return temporary pointer to MD iterator. Application must not
 * attempt to release it as it will be cleaned up by finalize() or release()
 * @returns 0
 *
 * Application has to supply non-zero genid parameter in order to initialize
 * stream and close stream with ccow_finalize()
 *
 * If specified genid is zero then stream will be initialized with the current
 * maximum generation ID and genid will be used as an output argument.
 *
 * If specified version_vm_content_hash_id the addition check will be done
 * on the GET operations. If version_vm_content_hash_id is NULL the parameter is ignored.
 */
int
ccow_admin_pseudo_create_stream_completion_versioned(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp,
    const char *cid, size_t cid_size, const char *tid, size_t tid_size,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    uint64_t *genid, uint64_t version_uvid_timestamp,
    const char *version_vm_content_hash_id, int *flags, ccow_lookup_t *iter);

/**
 * Set custom object parameter for an object PUT operation
 *
 * @param comp operation to set specific parameters for
 * @param name NULL terminated string of object parameter to set
 * @param value object's parameter value
 * @param val_size number of bytes passed in value for CCOW_KVTYPE_RAW,
 * ignored in all other cases.
 * @param iter iterator to pass to put, initialized via get request on object,
 * which is required to modify the metadata.
 * @returns 0 on success, negative error code on failure
 *
 * X-<KEY>:<VALUE>
 *
 */
int ccow_attr_modify_custom(ccow_completion_t comp, ccow_kvtype_t type,
    char *key, int key_size, void *value, int val_size,
    ccow_lookup_t iter);


/**
 * Set md overrides
 *
 * @param comp operation to set specific override parameters
 * @param name NULL terminated string of object parameter to set
 * @param value object's parameter value
 * @returns 0 on success, negative error code on failure
 *
 */
int ccow_attr_modify_md_overrides(ccow_completion_t comp, char *key, uint64_t value);

/**
 * @typedef ccow_attr_t
 *
 * Attribute list to be used with the ccow_attr_modify*() functions.
 * Careful attention should be paid to the R/W or Create-Only status.
 */
typedef enum ccow_default_attr {
	CCOW_ATTR_UNKNOWN,
	CCOW_ATTR_REPLICATION_COUNT,		/* READ-WRITE */
	CCOW_ATTR_SYNC_PUT,			/* READ-WRITE */
	CCOW_ATTR_SELECT_POLICY,		/* READ-WRITE */
	CCOW_ATTR_NUMBER_OF_VERSIONS,		/* READ-WRITE */
	CCOW_ATTR_COMPRESS_TYPE,		/* READ-WRITE */

	CCOW_ATTR_FAILURE_DOMAIN,		/* CREATE-ONLY */
	CCOW_ATTR_HASH_TYPE,			/* CREATE-ONLY */
	CCOW_ATTR_CHUNKMAP_TYPE,		/* CREATE-ONLY */

	CCOW_ATTR_FIXEDMAP_DEPTH,		/* CREATE-ONLY */
	CCOW_ATTR_FIXEDMAP_WIDTH,		/* CREATE-ONLY */
	CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,		/* CREATE-ONLY */

	CCOW_ATTR_BTREE_ORDER,			/* CREATE-ONLY */
	CCOW_ATTR_BTREE_MARKER,

	CCOW_ATTR_EC_ENABLE,			/* CREATE-ONLY */
	CCOW_ATTR_EC_ALGORITHM,			/* CREATE-ONLY */
	CCOW_ATTR_EC_TRG_POLICY,		/* CREATE-ONLY */
	CCOW_ATTR_FILE_OBJECT_TRANSPARANCY,	/* CREATE-ONLY */
	CCOW_ATTR_OBJECT_DELETE_AFTER,		/* READ-WRITE */

	CCOW_ATTR_TRACK_STATISTICS,		/* READ-WRITE */
	CCOW_ATTR_IOPS_RATE_LIM,		/* READ-WRITE */

	CCOW_ATTR_LOGICAL_SZ,			/* Logical Size */
	CCOW_ATTR_PREV_LOGICAL_SZ,		/* Previous Logical Size */
	CCOW_ATTR_OBJECT_COUNT,			/* Object Count */
	CCOW_ATTR_ESTIMATED_USED,		/* Estimated used */

	CCOW_ATTR_INLINE_DATA_FLAGS,		/* READ-WRITE */

	CCOW_ATTR_END
} ccow_default_attr_t;

/*
 * selection policy for the proposals
 */
#define CCOW_SELECT_POLICY_NONE		0x0
#define CCOW_SELECT_POLICY_WINDOW	0x1
#define CCOW_SELECT_POLICY_SPACE	0x2
#define CCOW_SELECT_POLICY_QDEPTH	0x4

/*
 * Data types for key-value databases
 */
#define RT_INLINE_DATA_TYPE_KV		0x0000		/* system kv */
#define RT_INLINE_DATA_TYPE_SNAPVIEW	0x0001		/* snapview kv */
#define RT_INLINE_DATA_TYPE_NFS_DIR	0x0002		/* NFS dirs kv databases */
#define RT_INLINE_DATA_TYPE_NFS_AUX	0x0004		/* NFS aux kv databases */
#define RT_INLINE_DATA_TYPE_SVC		0x0008		/* Services kv databases */
#define RT_INLINE_DATA_TYPE_TRLOG	0x0010		/* Transaction Log kv databases */
#define RT_INLINE_DATA_TYPE_BUCKET	0x0020		/* Backet kv database */
#define RT_INLINE_DATA_TYPE_USER_KV	0x0040		/* User defined kv database */

/*
 * Data flags for ondemand objects. See ondemand_policy_t
 */

#define RT_ONDEMAND_GET(attr) (((attr) >> 12) & 3)
#define RT_ONDEMAND_GET_TYPE(attr) (((attr) >> 14) & 1)
#define RT_ONDEMAND_VALUE(t, mode) (((mode) & 3) | (((t)&1)<<2))
#define RT_ONDEMAND_SET(attr, value) ((attr) = ((attr) & ~(0x7000U)) | value<<12)

#define RT_ONDEMAND_TYPE_MDONLY   0
#define RT_ONDEMAND_TYPE_VMONLY   1


/**
 * Modify the default tenant object settings for this object.
 *
 * @param comp operation to set specific parameters for
 * @param name NULL terminated string of object parameter to set
 * @param value object's parameter value
 * @param iter iterator to pass to put, initialized via get request on object,
 * which is required to modify the metadata.
 * @returns 0 on success, negative error code on failure
 *
 * This function will modify the default tenant settings that get associated
 * with each newly created object, as outlined in ccow_attr_t, careful
 * attention must be paid not to modify any settings listed as
 * CREATE-ONLY past creation time as it will induce undefined behaviour within
 * the system.
 */
int ccow_attr_modify_default(ccow_completion_t comp, ccow_default_attr_t attr,
    void *value, ccow_lookup_t iter);

/**
 * Force the cmcache to flush all cached entries.
 *
 * @param comp ccow completion for this context
 * @param tid  tenant id for cmcache for this object
 * @param bid  bucket id for cmcache for this object
 * @param oid  object id for cmcache for this object
 * @returns 0 on success
 *
 * This function will look up the cmcache based on tenant, bucket and
 * object IDs.
 */
int ccow_cmcache_flush(ccow_completion_t comp, const char *tid, size_t tid_size,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size);

/**
 * Block until an operation completes
 *
 * @param comp operation to wait for
 * @param index index of op to wait for, or -1 to wait for all ops to complete.
 * @returns 0
 */
int ccow_wait(ccow_completion_t comp, int index);

int
ccow_timed_wait(ccow_completion_t comp, int index, uint32_t timeout_ms);

/**
 * Release completion
 *
 * Call this when you no longer need the completion. It may not be
 * freed immediately if the operation is not acked.
 *
 * @param comp completion to release
 */
void ccow_release(ccow_completion_t comp);

/**
 * Drop completion
 *
 * Call this when you no longer need the completion and made sure that
 * no I/O is executed using it (i.e. nothing is scheduled).
 * Completion will be released immediately.
 *
 * @param comp completion to drop and release
 */
void ccow_drop(ccow_completion_t comp);

/**
 * Chunk buffer into I/O vectors of suggested size
 *
 * @param buf incoming data buffer
 * @param len length of incoming data buffer
 * @param size desirable chunk size
 * @param iov output data buffers to send as an array
 * @param iovcnt output number of buffers in an array to send
 * @returns 0 on success, negative error code on failure
 *
 * This function will not allocate or change parameters of incoming buffer.
 * Its purpose is to provide a convenient way to chunk incoming data into
 * scatter-gather list of I/O vectors to be supplied for transmission later
 * via ccow_put()
 */
int ccow_chunk(const char *buf, uint64_t len, size_t size, struct iovec **iov,
    size_t *iovcnt);

/**
 * Write new version with new payload
 *
 * Queues a write operation which will create a new version of an object
 * asynchronously; all of the payload is provided as new content.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to put
 * @param comp what to do when the write is complete
 * @param iov data buffers to send as an array
 * @param iovcnt number of buffers in an array to send
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents preallocated buffer receiver for exactly one chunk.
 * This function expects logically contiguous vectors from offset 0
 * to be provided by an application.
 *
 * If given bid/oid is NULL then it will direct hash function to use 0x0 hash
 * result accordingly. To address bucket as an object, oid argument needs to
 * be NULL. To address system object, both arguments need to be NULL.
 */
int ccow_replace(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, struct iovec *iov, size_t iovcnt);

/**
 * Write new version with optionally partial new payload
 *
 * Queues a write operation which will create a new version of an object
 * asynchronously, where only a portion of the payload is provided as
 * new content.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to put
 * @param comp what to do when the write is complete
 * @param iov data buffers to send as an array
 * @param iovcnt number of buffers in an array to send
 * @param off byte offset of the newly supplied payload in the object to begin
 *           writing at. Non supplied payload is inherited from a prior version
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents preallocated buffer receiver for exactly one chunk.
 * This function expects logically contiguous vectors from specified offset
 * to be provided by an application.
 *
 * If given bid/oid is NULL then it will direct hash function to use 0x0 hash
 * result accordingly. To address bucket as an object, oid argument needs to
 * be NULL. To address system object, both arguments needs to be NULL.
 *
 * ccow_put_notrlog allows to create an object in local namespace without
 * propagating it through the transaction log
 */
int ccow_put(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, struct iovec *iov, size_t iovcnt, uint64_t off);

int ccow_put_notrlog(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, struct iovec *iov, size_t iovcnt, uint64_t off);

/**
 * Write data using open stream to an object asynchronously
 *
 * Queues the unnamed put operation as a continuation of a stream where only a
 * portion of the payload is provided as a new content.
 *
 * @param comp what to do when the write is complete
 * @param iov data buffers to send as an array
 * @param iovcnt number of buffers in an array to send
 * @param off byte offset in the object to begin writing at
 * @param need_wait flag intention to use ccow_wait() or not
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents preallocated buffer receiver for exactly one chunk.
 * This function expects an array of logically contiguous vectors from specified
 * offset to be provided by an application.
 *
 * This operation requires completion to be allocated with
 * ccow_create_stream_completion(). It can be called multiple times and can
 * be intermixed with ccow_finalize().
 */
int ccow_put_cont(ccow_completion_t comp, struct iovec *iov,
    size_t iovcnt, uint64_t off, int need_wait, int *index);

/**
 * Write data using open stream to an object asynchronously
 * while part of the data is pre-loaded by ccow_get_cont
 * That is useful when read-modify-write is needed

 * @param comp what to do when the write is complete
 * @param iov data buffers to send as an array
 * @param iovcnt number of buffers in an array to send
 * @param off byte offset in the object to begin writing at
 * @param need_wait flag intention to use ccow_wait() or not
 * @param rmw_ctx pointer to context of read-modify feature
 * @returns 0 on success, negative error code on failure
 *
 * see also comments for ccow_put_cont
 */

int ccow_mod_put_cont(ccow_completion_t comp, struct iovec *iov,
    size_t iovcnt, uint64_t off, int need_wait,
	struct ccow_rmw_context *rmw_ctx, int *index);


int ccow_put_type_cont(ccow_completion_t comp, struct iovec *iov,
    size_t iovcnt, uint64_t off, int need_wait,
	struct ccow_rmw_context *rmw_ctx, int *index, int optype);

/**
 * Read data using open stream from an object asynchronously
 *
 * Queues the unnamed get operation as a continuation of a stream.
 *
 * @param comp what to do when the read is complete
 * @param iov data buffers to receive as an array
 * @param iovcnt number of buffers in an array to receive
 * @param off byte offset in the object to begin reading from
 * @param need_wait flag intention to use ccow_wait() or not
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents preallocated buffer receiver for exactly one chunk.
 * This function expects an array of logically contiguous vectors from specified
 * offset to be provided by an application.
 *
 * This operation requires completion to be allocated with
 * ccow_create_stream_completion(). It can be called multiple times and can
 * be intermixed with ccow_finalize().
 */
#define READ_AHEAD_FACTOR   4
#define READ_AHEAD_DETECT   3

int ccow_get_cont(ccow_completion_t comp, struct iovec *iov,
    size_t iovcnt, uint64_t off, int need_wait, int *index);

/**
 * Complete unwritten outstanding I/O and finalize new transaction
 *
 * @param comp what to do when the write is complete
 * @param iter output lookup iterator
 * @returns 0 on success, negative error code on failure
 *
 * This operation requires completion to be allocated with
 * ccow_create_stream_completion(). It has to be called once at the very
 * end of stream operation so that new object will be created.
 *
 * If iter parameter is not NULL then it will be filled in with final
 * object's metadata. It is the responsibility of the user to free it up
 * with ccow_lookup_release().
 */
int ccow_finalize(ccow_completion_t comp, ccow_lookup_t *iter);

/**
 * Aborts unwritten outstanding I/O and cancels transaction
 *
 * @param comp what to do when the write is complete
 * @returns 0 on success, negative error code on failure
 *
 * This operation requires completion to be allocated with
 * ccow_create_stream_completion(). It has to be called once at the very
 * end of stream operation in the cases when application isn't willing to
 * continue with transaction finalization.
 */
int ccow_cancel(ccow_completion_t comp);

/**
 * Asynchronously delete an object
 *
 * Queues the delete operation and returns.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to delete
 * @param comp what to do when the remove is safe and complete
 * @returns 0 on success, negative error code on failure
 *
 * ccow_delete_notrlog allows to delete an object in local namespace without
 * propagating it through the transaction log
 */
int ccow_delete(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp);

int ccow_delete_notrlog(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp);

/**
 * Delete an object in case of versioning support
 *
 * The operation adds the new VM with ccow-object-deleted flag equal to 1.
 * In contrary to ccow_delete this operation does not initiate the name index removal.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to delete
 * @param comp what to do when the remove is safe and complete
 * @returns 0 on success, negative error code on failure
 */
int ccow_delete_versioning(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp);


/**
 * Asynchronously and permanently expunge an object
 *
 * Remove the object and all versions of it physically from all drives in cluster.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to expunge
 * @param comp what to do when the remove is safe and complete
 * @returns 0 on success, negative error code on failure
 */
int ccow_expunge(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp);

/**
 * Permanently expunge an object version
 *
 * Remove the object version from all drives in cluster.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to expunge
 * @param genid the generation id pointer
 * @param comp what to do when the remove is safe and complete
 * @returns 0 on success, negative error code on failure
 */
int ccow_expunge_version(const char *bid, size_t bid_size, const char *oid,
		size_t oid_size, uint64_t *genid, uint64_t version_uvid_timestamp, const char *version_vm_content_hash_id, ccow_completion_t comp);



/**
 * Asynchronously parity-(re-)encode object
 *
 * Initiate (re-)encoding of the object for parity protection
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to expunge
 * @param algorithm parity-encoding algorithm index
 * @param width stripe width for parity encoding
 * @param parity number of parity bits
 * @param comp what to do when the encoding is scheduled
 * @returns 0 on success, negative error code on failure
 */
int ccow_erasure_encode(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, uint64_t generation, uint8_t algorithm, uint8_t width,
    uint8_t parity, ccow_completion_t comp);

typedef enum {
	/**
	 * The object is local. It doesn't belong to an ondemand bucket and
	 * any other ondemand policy cannot by applied to it
	 */
	ondemandPolicyLocal = 0,

	/**
	 * Object with ondemandPolicyUnpin policy keeps locally only VM or CMs+VM
	 * Payload chunks will be fetched from remote on demand and will be removed
	 * after a while.
	 */
	ondemandPolicyUnpin,

	 /**
	  * Pin a cacheable (mdonly or vmonly) object.
	  * All the manifests and payload chunks will be fetched from remote
	  * and kept locally. Policy can be changed to ondemandPolicyUnpin
          * unless it was cloned/modified.
	  */
	ondemandPolicyPin,

	/**
	 * Object is persistent and its policy cannot be changed anymore.
	 * It's used to indicate that object's origin is an ondemand bucket.
	 * A cacheable object's policy will be set to ondemandPolicyPersist
	 * upon clone operation.
	 */
	ondemandPolicyPersist,

	ondemandPolicyTotal
} ondemand_policy_t;

/**
 * Asynchronously trigger a cacheable object's policy change
 *
 * @param bid bucket name id of the bucket
 * @param bid_size of bucket name ID
 * @param oid object ID string
 * @param oid_size sizeof of the object ID
 * @param generation object version ID
 * @param pol policy change value
 * @param comp operation completion to wait on
 */
int
ccow_ondemand_policy_change_request(const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, uint64_t generation, ondemand_policy_t pol,
	ccow_completion_t comp);



/**
 * Change a cacheable (mdonly) object's policy. Blocking call.
 *
 * @param bid bucket name id of the bucket
 * @param bid_size of bucket name ID
 * @param oid object ID string
 * @param oid_size sizeo of the object ID
 * @param generation object version ID
 * @param pol object policy to be set
 */
int
ccow_ondemand_policy_change(ccow_t tc, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, uint64_t generation, ondemand_policy_t pol);

/**
 * Asynchronously read data from an object
 *
 * Queues the get operation and returns.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to read from
 * @param comp what to do when the read is complete
 * @param iov where to store the results
 * @param iovcnt number of iov buffers supplied
 * @param off the offset to start reading from in the object
 * @returns number of bytes read on success, negative error code on failure
 *
 * Each IO vector represents buffer with the data to send for exactly one chunk.
 * This function expects logically contiguous vectors from specified offset
 * to be provided by an application.
 *
 * If given bid/oid is NULL then it will direct hash function to use 0x0 hash
 * result accordingly. To address bucket as an object, oid argument needs to
 * be NULL. To address system object, both arguments need to be NULL.
 */
int ccow_get(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, struct iovec *iov, size_t iovcnt, uint64_t off,
    ccow_lookup_t *iter);

/**
 * Test that object exist
 *
 * Check that at least one VM exists (deleted or not).
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to test
 * @param comp what to do when the read is complete
 * @returns 0 - object exist, ENOENT - object VM not found, err code other vice
 *
 */
int ccow_get_test(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp);

/*
 * Get versions list
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size the bid size
 * @param oid the NULL terminated string of name id of the object
 * @param oid_size the oid size
 * @param comp what to do when the read is complete
 * @param iter we will return versions list as iter->versions
 * @returns 0 on success, negative error code on failure
 *
 * Scope: PUBLIC
 */
int ccow_get_versions(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, ccow_lookup_t *iter);

/**
 * Copy an object/bucket/tenant one at a time.
 * @param comp  completion
 * @param tid_src tenant_id to copy
 * @param bid_src bucket_id to copy
 * @param oid_src object_id to copy
 * @param tid_dst tenant_id to copy
 * @param bid_dst bucket_id to copy
 * @param oid_dst object_id to copy
 * @param copy_opts could include source generation and source vm hash id for version copy
 * @returns 0 on success, negative error code on failure
 *
 */
struct ccow_copy_opts;	/* defined below */
int ccow_clone(ccow_completion_t comp, const char *tid_src, size_t tid_src_size,
    const char *bid_src, size_t bid_src_size, const char *oid_src,
    size_t oid_src_size, struct ccow_copy_opts *copy_opts);


/**
 * Insert key/val to an object asynchronously
 *
 * Queues the insert_list operation and returns.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to put
 * @param comp what to do when the write is complete
 * @param iov data buffers to send as an array
 * @param iovcnt number of buffers in an array to send
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents preallocated key/val buffer receiver for exactly
 * one key/val.
 *
 * If given bid/oid is NULL then it will direct hash function to use 0x0 hash
 * result accordingly. To address bucket as an object, oid argument needs to
 * be NULL. To address system object, both arguments need to be NULL.
 */
int ccow_insert_list(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, struct iovec *iov, size_t iovcnt);

/**
 * Insert key/val using open stream to an object asynchronously
 *
 * Queues the insert_list operation and returns.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to put
 * @param comp what to do when the write is complete
 * @param iov data buffers to send as an array
 * @param iovcnt number of buffers in an array to send
 * @param need_wait flag intention to use ccow_wait() or not
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents preallocated key/val buffer receiver for exactly
 * one key/val.
 *
 * If given bid/oid is NULL then it will direct hash function to use 0x0 hash
 * result accordingly. To address bucket as an object, oid argument needs to
 * be NULL. To address system object, both arguments need to be NULL.
 */
int ccow_insert_list_cont(ccow_completion_t comp, struct iovec *iov,
    size_t iovcnt, int need_wait, int *index);

/**
 * Delete key/val using open stream to an object asynchronously
 *
 * Queues the insert_list operation and returns.
 *
 * @param comp what to do when the write is complete
 * @param iov data buffers to send as an array
 * @param iovcnt number of buffers in an array to send
 * @param need_wait flag intention to use ccow_wait() or not
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents preallocated key/val buffer receiver for exactly
 * one key/val.
 *
 */

int ccow_delete_list_cont(ccow_completion_t comp, struct iovec *iov,
    size_t iovcnt, int need_wait, int *index);

/**
 * Get status of the cont operation
 *
 * Should be called after ccow_wait
 *
 * @param comp what to do when the write is complete
 * @param index - operation index starting from 1
 * @returns 0 on success, error code on failure
 *
 */
int ccow_list_cont_status(ccow_completion_t comp, int index);

/**
 * Delete key/val from an object asynchronously
 *
 * Queues the delete_list operation and returns.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to put
 * @param comp what to do when the write is complete
 * @param iov data buffers to send as an array
 * @param iovcnt number of buffers in an array to send
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents preallocated key/val buffer receiver for exactly
 * one key/val.
 *
 * If given bid/oid is NULL then it will direct hash function to use 0x0 hash
 * result accordingly. To address bucket as an object, oid argument needs to
 * be NULL. To address system object, both arguments need to be NULL.
 */
int ccow_delete_list(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, struct iovec *iov, size_t iovcnt);

/**
 * Asynchronously read key/val from an object
 *
 * Queues the get operation and returns.
 *
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to read from
 * @param comp what to do when the read is complete
 * @param iov where to store the results
 * @param iovcnt number of iov buffers supplied
 * @param count the maximum number of elements to return via iterator
 * @param iter output lookup iterator
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents buffer with the data to send for exactly one chunk.
 * This function expects logically contiguous vectors from specified offset
 * to be provided by an application.
 *
 * If given bid/oid is NULL then it will direct hash function to use 0x0 hash
 * result accordingly. To address bucket as an object, oid argument needs to
 * be NULL. To address system object, both arguments need to be NULL.
 */
int ccow_get_list(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, struct iovec *iov, size_t iovcnt,
    size_t count, ccow_lookup_t *iter);



/**
 * Create shard context
 *
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @param shard_context - shard context pointer
 * @returns 0 on success, negative error code on failure
 */
int
ccow_shard_context_create(char *shard_name, size_t shard_name_size, int shard_count,
		ccow_shard_context_t *shard_context);

/**
 * Destroy shard context, release memory
 *
 * @param shard_context - shard context pointer
 */
void
ccow_shard_context_destroy(ccow_shard_context_t *shard_context);


/**
 * Set overwrite flag for shard_context.
 */
int
ccow_shard_context_set_overwrite(ccow_shard_context_t shard_context, int overwrite);

/**
 * Set eventual flag for shard_context.
 */
int
ccow_shard_context_set_eventual(ccow_shard_context_t shard_context, int eventual);

/**
 * Set inline data flag for shard_context.
 */
int
ccow_shard_context_set_inline_flag(ccow_shard_context_t shard_context, uint16_t flag);

/**
 * Create sharded list
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_list_create(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context);

/**
 * Create sharded attributes
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_attributes_create(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context);

/**
 * Destroy sharded list
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_list_destroy(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context);

/**
 * Destroy sharded attributes
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_attributes_destroy(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context);


/**
 * Insert key/val into the sharded list
 *
 * Each IO vector represents preallocated key/val buffer receiver for exactly
 * one key/val.
 *
 * ccow_sharded_list_put() -
 *             Uses shard_context->overwrite flag to check if overwrite is allowed
 * ccow_sharded_list_put_v2() -
 *             Uses overwrite argument to check if overwrite is allowed
 * ccow_sharded_list_put_with_md() -
 *             A compound operation for both insert and directory attribute update
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @param iov - io buffer
 * @param iov_count - io buffer element count
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_list_put(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context,
		struct iovec *iov, size_t iovcnt);

int
ccow_sharded_list_put_v2(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context,
		struct iovec *iov, size_t iovcnt, int overwrite);

int
ccow_sharded_list_put_with_md(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context,
		char *parent_key, size_t parent_key_size,
		char *child_key, size_t child_key_size,
		struct iovec *iov, size_t iovcnt,
		int64_t delta_size, int64_t delta_objs, int64_t delta_used);

/**
 * Delete key from the sharded list
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @param key key value
 * @param key_size  key size
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_list_delete(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context,
        char *key, size_t key_size);

int ccow_sharded_list_delete_with_md(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context,
		char *parent_key, size_t parent_key_size,
		char *child_key, size_t child_key_size,
		int64_t delta_size, int64_t delta_objs, int64_t delta_used);

/**
 * Get value by key from the sharded list
 *
 * Each IO vector represents preallocated key/val buffer receiver for exactly
 * one key/val.
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @param iov - io buffer
 * @param iov_count - io buffer element count
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_list_get(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context,
		char *key, size_t key_size, struct iovec *iov, size_t iovcnt);


/**
 * Get value list from the sharded list
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @param marker value, the list results are greater then marker
 * @param marker_size  marker size
 * @param end_marker the end marker, the list results are greater or equal then end_marker
 * @param count - maximum number of the list items
 * @param iter output lookup iterator
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_get_list(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context,
		char *marker, size_t marker_size,
		char *end_marker, int count, ccow_lookup_t *iter);

/**
 * Put sharded attributes
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @param key key value
 * @param delta_size size delta > 0 for insert, < 0 for delete
 * @param delta_objs object count delta > 0 for insert, < 0 for delete
 * @param delta_used estimated used size delta > 0 for insert, < 0 for delete
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_attributes_put(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context,
		char *key, size_t key_size,
		int64_t delta_size, int64_t delta_objs, int64_t delta_used);

/**
 * Get sharded attributes
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket id size
 * @param shard_name the NULL terminated string of shard name id
 * @param shard_name_size shard name size
 * @param shard_count shard count should be 2^n
 * @param key key value
 * @param logical_size sharded logical size
 * @param object_count sharded object count
 * @param estimated_used sharded estimated used size
 * @returns 0 on success, negative error code on failure
 */
int
ccow_sharded_attributes_get(ccow_t tctx, const char *bid, size_t bid_size,
		ccow_shard_context_t shard_context,
        int64_t *logical_size, int64_t *object_count, int64_t *estimated_used);


/* Test function */
void
test_get_shard_name(char *dir_name, char *dentry,
		    char *shard_name, int shard_count);

/**
 * Insert name/value into the users list
 *
 * @param tctx the tenant cluster context
 * @param iov - io buffers iov[0] -> name, iov[1] -> value
 * @returns 0 on success, negative error code on failure
 */
int
ccow_user_put(ccow_t tctx, struct iovec *iov);


/**
 * Delete user from the tenant
 *
 * @param tctx the tenant cluster context
 * @param name user's name
 * @param name_size  user's name size
 * @returns 0 on success, negative error code on failure
 */
int
ccow_user_delete(ccow_t tctx, char *name, size_t name_size);


/**
 * Get user's values by name
 *
 *
 * @param tctx the tenant cluster context
 * @param name user's value
 * @param name_size  user's name size
 * @param iov - output io buffer, at least one element
 * @returns 0 on success, negative error code on failure
 */
int
ccow_user_get(ccow_t tctx, char *name, size_t name_size,
    struct iovec *iov);


/**
 * Get user's list
 *
 * @param tctx the tenant cluster context
 * @param marker value, the list results are greater then marker
 * @param marker_size  marker size
 * @param count - maximum number of the list items
 * @param iter output lookup iterator
 * @returns 0 on success, negative error code on failure
 */
int
ccow_user_list(ccow_t tctx, char *marker, size_t marker_size,
    int count, ccow_lookup_t *iter);


// ACLs api

/**
 * Insert acl
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size the bid size
 * @param oid the NULL terminated string of name id of the object
 * @param oid_size the oid size
 * @param uvid_timestamp - object timestamp or 0
 * @param iov - io buffer iov[0] -> value
 * @returns 0 on success, negative error code on failure
 */
int
ccow_acl_put(ccow_t tctx, const char *bid, size_t bid_size, const char *oid,
        size_t oid_size, uint64_t uvid_timestamp, struct iovec *iov_value);

/**
 * Get acl's value
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size the bid size
 * @param oid the NULL terminated string of name id of the object
 * @param oid_size the oid size
 * @param uvid_timestamp - object timestamp or 0
 * @param iov - io buffer, at least one element to keep result value
 * @returns 0 on success, negative error code on failure
 */
int
ccow_acl_get(ccow_t tctx, const char *bid, size_t bid_size, const char *oid,
        size_t oid_size, uint64_t uvid_timestamp,  struct iovec *iov);


/**
 * Delete acl key from the tenant
 *
 * @param tctx the tenant cluster context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size the bid size
 * @param oid the NULL terminated string of name id of the object
 * @param oid_size the oid size
 * @param uvid_timestamp - object timestamp or 0
 * @returns 0 on success, negative error code on failure
 */
int
ccow_acl_delete(ccow_t tctx, const char *bid, size_t bid_size, const char *oid,
        size_t oid_size, uint64_t uvid_timestamp);


/**
 * Create a handle for communicating with a CCOW cluster.
 *
 * JSON configuration allows to preset personality scope, also
 * known as multi-tenancy.
 *
 * @post If this succeeds, any function in libccow may be used
 *
 * @param jsonstr buffer with JSON configuration for the cluster
 * @param clname the NULL terminated string of cluster
 * @param tid the NULL terminated string of tenant id
 * @param ptctx where to store the handle
 * @returns 0 on success, negative error code on failure
 *
 * clname and tid are required parameters. Parameter tid must not be admin
 * user "root". See ccow_admin_init().
 */
int ccow_tenant_init(const char *jsonstr, const char *clname, size_t cl_len,
    const char *tid, size_t tid_size, ccow_t *ptctx);

/**
 * Create a handle for communicating with a CCOW cluster using
 * default configuration file
 *
 * @post If this succeeds, any function in libccow may be used
 *
 * @param cid the NULL terminated string of cluster name
 * @param tid the NULL terminated string of tenant id
 * @param ptctx where to store the handle
 * @returns 0 on success, negative error code on failure
 *
 * clname and tid are required parameters. Parameter tid must not be admin
 * user "root". See ccow_admin_init().
 */
int
ccow_default_tenant_init(const char *cid, size_t cid_size,
    const char *tid, size_t tid_size, ccow_t *ptctx);

/**
 * Create a admin handle for communicating with a CCOW cluster.
 *
 * JSON configuration allows to preset personality scope, also
 * known as multi-tenancy.
 *
 * @post If this succeeds, any function in libccow may be used
 *
 * @param jsonstr buffer with JSON configuration for the cluster
 * @param clname the NULL terminated string of cluster
 * @param ptctx where to store the handle
 * @returns 0 on success, negative error code on failure
 */
int ccow_admin_init(const char *jsonstr, const char *clname, size_t cl_len,
    ccow_t *ptctx);

typedef enum {
	CCOW_CONT = 1,
	CCOW_PUT_CONT,
	CCOW_PUT,
	CCOW_GET_CONT,
	CCOW_GET,
	CCOW_RING,
	CCOW_CLONE,
	CCOW_INSERT_LIST_CONT,
	CCOW_INSERT_LIST,
	CCOW_INSERT_MD,
	CCOW_DELETE_LIST_CONT,
	CCOW_DELETE_LIST,
	CCOW_DELETE_MD,
	CCOW_GET_LIST,
	CCOW_GET_VERSIONS,
	CCOW_GET_TEST,
	CCOW_LOCK,
	CCOW_OPP_STATUS,
	CCOW_ROWEVAC,
	CCOW_UPDATE_MD,
	CCOW_INSERT_LIST_WITH_MD,
	CCOW_DELETE_LIST_WITH_MD,
	CCOW_SOP_FLUSH,
	CCOW_GET_RES,
	CCOW_MAX_OP_TYPE
} ccow_op_t;

static inline const char*
ccow_op2str(ccow_op_t op)
{
	switch(op) {
	case CCOW_CONT:                return "CCOW_CONT";
	case CCOW_PUT_CONT:            return "CCOW_PUT_CONT";
	case CCOW_PUT:                 return "CCOW_PUT";
	case CCOW_GET_CONT:            return "CCOW_GET_CONT";
	case CCOW_GET:                 return "CCOW_GET";
	case CCOW_RING:                return "CCOW_RING";
	case CCOW_CLONE:               return "CCOW_CLONE";
	case CCOW_INSERT_LIST_CONT:    return "CCOW_INSERT_LIST_CONT";
	case CCOW_INSERT_LIST:         return "CCOW_INSERT_LIST";
	case CCOW_INSERT_MD:           return "CCOW_INSERT_MD";
	case CCOW_DELETE_LIST_CONT:    return "CCOW_DELETE_LIST_CONT";
	case CCOW_DELETE_LIST:         return "CCOW_DELETE_LIST";
	case CCOW_DELETE_MD:           return "CCOW_DELETE_MD";
	case CCOW_GET_LIST:            return "CCOW_GET_LIST";
	case CCOW_GET_VERSIONS:        return "CCOW_GET_VERSIONS";
	case CCOW_GET_TEST:            return "CCOW_GET_TEST";
	case CCOW_LOCK:                return "CCOW_LOCK";
	case CCOW_OPP_STATUS:          return "CCOW_OPP_STATUS";
	case CCOW_ROWEVAC:             return "CCOW_ROWEVAC";
	case CCOW_UPDATE_MD:           return "CCOW_UPDATE_MD";
	case CCOW_INSERT_LIST_WITH_MD: return "CCOW_INSERT_LIST_WITH_MD";
	case CCOW_DELETE_LIST_WITH_MD: return "CCOW_DELETE_LIST_WITH_MD";
	case CCOW_SOP_FLUSH:            return "CCOW_SOP_FLUSH";
	case CCOW_GET_RES:            return "CCOW_GET_RES";
	case CCOW_MAX_OP_TYPE:         return "CCOW_MAX_OP_TYPE";
	default: return "CCOW_???";
	}
}

/*
 * Major and minor types for serial operations
 */
typedef enum {
	CCOW_SR_MAJ_LOCK = 1,
	/* The following 5 codes should be together */
	CCOW_SR_MAJ_SYS_UPDATE,		/* Update system with clusters */
	CCOW_SR_MAJ_CLUSTER_UPDATE,	/* Update cluster with tenants */
	CCOW_SR_MAJ_TENANT_UPDATE,	/* Update tenant with buckets */
	CCOW_SR_MAJ_BUCKET_UPDATE,	/* Update bucket with objects */
	CCOW_SR_MAJ_OBJECT_UPDATE,	/* Update object*/
} ccow_sr_mj_opcode_t;

/* TODO: We may not need minor opcodes. Kept right now for future expansion */
typedef enum {
	CCOW_SR_MINOR_ANY = 1, /* Wildcard */
	CCOW_SR_INSERT_LIST,
        CCOW_SR_UPDATE_LIST,
	CCOW_SR_DELETE_LIST,
	CCOW_SR_LOCK_GRANTED,
	CCOW_SR_INSERT_MD,
	CCOW_SR_UPDATE_MD,
	CCOW_SR_DELETE_MD,
	CCOW_SR_INSERT_LIST_WITH_MD,
	CCOW_SR_DELETE_LIST_WITH_MD,
	CCOW_SR_FLUSH	/* Flush object queue */
} ccow_sr_mn_opcode_t;

struct ccow_copy_opts {
	char *tid;
	char *bid;
	char *oid;
	size_t tid_size;
	size_t bid_size;
	size_t oid_size;
	uint64_t *genid;  /* Source generation id (optional) */
	uint64_t version_uvid_timestamp; /* Source version timestamp (optional) */
	char *version_vm_content_hash_id; /* Source vm hash id (optional) */
	char *vm_chid;		/* pointer to 512bit VM CHID */
	uint8_t md_override; /* Don't inherit source's default metadata */
};

/*
 * Perform a generic put as tenant.
 */
int
ccow_pseudo_put(const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t off,
	ccow_op_t optype, struct ccow_copy_opts *copy_opts,
	ccow_completion_t comp, int64_t attrs);

/*
 * Admin put on behalf of provided tenant.
 */
int ccow_admin_pseudo_put(const char *cid, size_t cid_size, const char *tid,
	size_t tid_size, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t off,
	ccow_op_t optype, struct ccow_copy_opts *copy_opts,
	ccow_completion_t comp);

/*
 * Admin put hidden object (no TRLOG entry) on behalf of provided tenant.
 */
int ccow_admin_pseudo_put_notrlog(const char *cid, size_t cid_size, const char *tid,
	size_t tid_size, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t off,
	ccow_op_t optype, struct ccow_copy_opts *copy_opts,
	ccow_completion_t comp);

/*
 * Perform a generic get as tenant.
 */
int
ccow_pseudo_get(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t offset,
    ccow_op_t optype, ccow_completion_t comp, ccow_lookup_t *i);

/*
 * Perform a get as admin on behalf of a tenant.
 */
int
ccow_admin_pseudo_get(const char *cid, size_t cid_size, const char *tid,
	size_t tid_size, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t offset,
    ccow_op_t optype, ccow_completion_t comp, ccow_lookup_t *i);

/*
 * Perform a getobj as admin on behalf of a tenant.
 */
int ccow_admin_pseudo_getobj(const char *nhid, struct iovec *iov,
    size_t iovcnt, uint64_t offset, ccow_op_t optype, ccow_completion_t comp,
    ccow_lookup_t *i);

/*
 * Perform an unnamed put of chunk(s) of data as admin.
 */
int ccow_admin_pseudo_put_chunks(struct iovec *iov, size_t iovcnt,
    uint64_t attributes, const char* chid,  const char *ng_chid,
	ccow_completion_t comp);

/*
 * Perform a delete as admin on behalf of a tenant.
 */
int ccow_admin_pseudo_delete(const char *cid, size_t cid_size, const char *tid,
	size_t tid_size, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, ccow_completion_t comp);

/**
 * Creates new tenant Id
 *
 * @param tctx the tenant cluster context to deinitialize
 * @param tid tenant id to create
 * @param c_in optional_completion preloaded with default_attrs for creation
 * @returns 0 on success, negative error code on failure
 *
 * The "root" tenant id is a reserved word.
 */
int ccow_tenant_create(ccow_t tctx, const char *tid, size_t tid_size,
    ccow_completion_t c_in);

/**
 * Get tenant objects.
 *
 * Lookup for tenant name pattern and retrieve an iterator as a result.
 * Iterator has to be released if not NULL.
 *
 * @param tctx the tenant cluster context to use
 * @param clname the cluster name to lookup for or NULL to use context
 * @param clsize size of cluster name
 * @param pattern the tenant name pattern to lookup for
 * @param count the maximum number of elements to return via iterator
 * @param iter output lookup iterator
 * @returns 0 on success, negative error code on failure
 *
 * See ccow_lookup_iter() ccow_lookup_release() on how to use lookup iterators.
 */
int ccow_tenant_lookup(ccow_t tctx, const char *clname, size_t clsize,
    const char *pattern, size_t p_len, size_t count, ccow_lookup_t *iter);

/**
 * Logically delete tenant object but keep the data
 *
 * The tenant is removed from the cluster immediately, but the actual data is
 * not touched. Use ccow_expunge() to actually remove the tenant's data.
 *
 * @param tctx the root tenant cluster context
 * @param tid which tenant to delete
 * @returns 0 on success, negative error code on failure
 */
int ccow_tenant_delete(ccow_t tctx, const char *tid, size_t tid_size);

/**
 * Disconnects from the cluster and deinitializes tenant cluster context.
 *
 * For clean up, this is only necessary after ccow_tenant_init() has
 * succeeded.
 *
 * @warning This does not guarantee any asynchronous writes have
 * completed. To do that, you must call ccow_flush() on all open
 * transactional objects.
 *
 * @post the cluster context handle cannot be used again
 *
 * @param tctx the tenant cluster context to deinitialize
 */
void ccow_tenant_term(ccow_t tctx);

/**
 * Aborts all outstanding I/O.
 *
 * This call may speed up I/O canceling in cases where context termination
 * isn't immediately desirable.
 *
 * @warning This does not guarantee any asynchronous writes have
 * completed. To do that, you must call ccow_flush() on all open
 * transactional objects.
 *
 * @param tctx the tenant cluster context to abort
 */
void ccow_tenant_abort(ccow_t tctx);

/**
 * Iterate lookup over root system object to view clusters. Iterator has
 * to be released if not NULL.
 *
 * @param tctx the tenant cluster context to use
 * @param pattern the tenant name pattern to lookup for
 * @param count the maximum number of elements to return via iterator
 * @param iter output lookup iterator
 * @returns next object or NULL at the end
 */
int ccow_cluster_lookup(ccow_t tctx, const char *pattern, size_t p_len,
    size_t count, ccow_lookup_t *iter);

/**
 * Initialize cluster to the default and initial state
 *
 * @param admin_tctx the context to use to initialize cluster in
 * @param clname the NULL terminated string of cluster name
 * @param c_in optional_completion preloaded with default_attrs for creation
 * @returns 0 on success, negative error code on failure
 *
 * This function has to be called once. As the result it will create
 * cluster object which holds important cluster "root" information.
 *
 * Cluster context needs to correspond to admin context.
 */
int ccow_cluster_create(ccow_t admin_tctx, const char *clname, size_t cl_len,
    ccow_completion_t c_in);

/**
 * Logically delete cluster object but keep the data
 *
 * The cluster is removed from the system immediately, but the actual data is
 * not touched. Use ccow_expunge() to actually remove the cluster's data.
 *
 * @param tctx the root tenant cluster context
 * @param cid which cluster to delete
 * @returns 0 on success, negative error code on failure
 */
int ccow_cluster_delete(ccow_t tctx, const char *cid, size_t cid_size);

/**
 * Initialize system object with OID 0x0
 *
 * @param admin_tctx the admin context to be used
 * @returns 0 on success, negative error code on failure
 *
 * This function has to be called once. As the result it will create
 * system object which holds important system wide "root" information.
 */
int ccow_system_init(ccow_t admin_tctx);

/**
 * Return the systemguid formatted without hyphens.
 *
 * @param admin_tctx the admin context to be used
 * @returns success, GUID returned
 */
char *ccow_get_system_guid_formatted(ccow_t admin_tctx);

/**
 * Get ccow statistics.
 *
 * @param tctx the root tenant cluster context
 * @param stats
 *
 */
int ccow_get_stats(ccow_t tctx, ccow_stats_t *stats);

/**
 * Print ccow statistics
 *
 * @param stats
 *
 */
void ccow_print_stats(ccow_stats_t stats);

/**
 * Collect Tenant Accounting
 *
 * @param tctx tenant cluster context
 * @param pattern bucket name pattern
 * @param size of buffer in bytes
 * @param count of buckets to return data for, 0 -> ALL
 * @param data returned accounting data must be preallocated
 * err = ccow_tenant_accounting(cl, "", 1, 0, &data) will return all buckets data
 *
 */
int ccow_tenant_accounting(struct ccow *tc, const char *bucket_pattern,
    size_t pattern_size, size_t count, struct ccow_tenant_stats *data);

/**
 * Collect Cluster Accounting
 *
 * @param tctx tenant cluster context
 * @param clname - cluster name or NULL to take from context
 * @param clsize - cluster name size or 0
 * @param tenant_pattern tenant name pattern
 * @param pattern_size in bytes
 * @param count of tenants to return data for, 0 -> ALL
 * @param data returned accounting data must be preallocated
 * err = ccow_cluster_accounting(cl, "", 1, 0, &data) will return all tenants data
 *
 */
int
ccow_cluster_accounting(struct ccow *tc, char *clname,  size_t clsize,
	const char *tenant_pattern, size_t pattern_size,
	size_t count, struct ccow_cluster_stats *data);


/**
 * Copy the parts to the object.
 *
 * @param cid the NULL terminated string of cluster id
 * @param tid the NULL terminated string of tenant id
 * @param bid the NULL terminated string of name id of the bucket
 * @param dst_oid the NULL terminated string of name id of the object to append the object
 * @param parts part names to append to dst_oid
 * @returns 0 on success, negative error code on failure
 *
*/
int
ccow_copy_objects(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *dst_oid,
    size_t dst_oid_size, struct iovec *iov, int total_parts,
    ccow_t cl);


/**
 * Insert key/val using open stream to an object asynchronously and *serially*
 *
 * Queues the insert_list operation and returns.
 *
 * @param cid the NULL terminated string of name id of the cluster
 * @param tid the NULL terminated string of name id of the tenant
 * @param bid the NULL terminated string of name id of the bucket
 * @param oid the NULL terminated string of name id of the object to put
 * @param comp what to do when the write is complete
 * @param iov data buffers to send as an array
 * @param iovcnt number of buffers in an array to send
 * @param optype type of operation such as CCOW_INSERT_LIST
 * @returns 0 on success, negative error code on failure
 *
 * Each IO vector represents preallocated key/val buffer receiver for exactly
 * one key/val.
 *
 */
int ccow_container_update_list(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, struct ccow_completion *c, struct iovec *iov,
    size_t iovcnt, ccow_op_t optype);



void ccow_hup_lg(void);

/**
 * Set user timer callback function.
 *
 * @param tctx tenant cluster context
 * @param cb user callback function
 * @param arg void pointer passwd to user callback as second argument
 * Return 0 on success or EBUSY if already set.
 */
typedef	void (*ccow_usertimer_cb_t)(struct ccow *, void *);
int ccow_set_usertimer_callback(struct ccow *tctx, ccow_usertimer_cb_t cb, void *arg);

/**
 * Reset user timer callback function.
 *
 * @param tctx tenant cluster context
 * Return 0 on success or EBUSY if already set.
 */
int ccow_clear_usertimer_callback(struct ccow *tctx);


/**
 * Create nhid based inode number
 *
 * @param nhid name hash id
 * @param nhid_size name hash id size
 * @param inode_number - output inode number pointer
 * @returns 0 on success, negative error code on failure
 */
int ccow_object_inode_number(void *nhid, size_t nhid_size, uint64_t *inode_number);

void ccow_ucache_evict_overwrite(void *ucache, void *chid);

/**
 * Get delay of UDP lost response
 *
 * @param tc - tenant context
 * @returns 0 if last response was not lost, delay in ms from last send that had not got the response
 */
uint64_t ccow_lost_response_delay_ms(struct ccow *tc);

/**
 * Get delay of consensus lost response
 *
 * @param tc - tenant context
 * @returns 0 if consensus response was not lost, delay in ms from last send that had not got the response
 */
uint64_t ccow_consensus_delay_ms(struct ccow *tc);

/**
 * Accessors to completion fields */
uint32_t ccow_chunk_size(ccow_completion_t c);
uint64_t ccow_logical_size(ccow_completion_t c);

/**
 * Accessors to tenant context fields */
uint64_t ccow_trlog_quarantine(struct ccow *tc);
uint64_t ccow_trlog_interval_us(struct ccow *tc);

/**
 * Evict outdated records from SOP cache
 *
 * @param tc - tenant context
 * @returns 0 on success, error code otherwise
 */
int evict_sop_cache(struct ccow *tc);

#define CCOW_LOCK_SHARED	0x01	/* Shared mode */
#define CCOW_LOCK_EXCL		0x02	/* Exclusive lock */
#define CCOW_LOCK_NON_BLOCK	0x04	/* Don't block to acquire lock */
#define CCOW_LOCK_UNLOCK	0x08	/* Unlock the lock */
#define CCOW_LOCK_CANCEL	0x10	/* Cancel the lock */

/**
 * Lock a CCOW object
 * Operation executed in the cluster and do not persist.
 *
 * @param tc - tenant context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket name size
 * @param oid the NULL terminated string of name id of the object to lock
 * @param oid_size object name size
 * @param off offset into the object
 * @param len length of the region in object from the off-set
 * @param mode CCOW_LOCK_* mask
 * @returns 0 on success, error code otherwise
 */
int ccow_range_lock(ccow_t tc, const char *bid, size_t bid_size,
    const char *oid, size_t oid_size, uint64_t off, uint64_t len, int mode);

/**
 * Lock a CCOW object
 * Operation executed in the cluster and do not persist.
 *
 * @param tc - tenant context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket name size
 * @param oid the NULL terminated string of name id of the object to lock
 * @param oid_size object name size
 * @param flk Unix file lock structure
 * @returns 0 on success, error code otherwise
 */
int ccow_set_posix_lock(ccow_t tc, const char *bid, size_t bid_size,
    const char *oid, size_t oid_size, struct flock *flk);

/**
 * Query lock on a CCOW object
 * Operation executed in the cluster and do not persist.
 *
 * @param tc - tenant context
 * @param bid the NULL terminated string of name id of the bucket
 * @param bid_size bucket name size
 * @param oid the NULL terminated string of name id of the object to lock
 * @param oid_size object name size
 * @param query_lock Unix file lock structure containing the query
 * @param result_lock Unix file lock structure containing the result, if any
 * @returns 0 on success, error code otherwise
 */
int ccow_get_posix_lock(ccow_t tc, const char *bid, size_t bid_size,
    const char *oid, size_t oid_size, struct flock *query_lock, struct flock *result_lock);

/**
 * Get default object attribute set in a completion
 *
 * @param c  completion object
 * @param attr attribute ID
 * @param val  requested parameter's value (output)
 * @returns 0 on success, error code otherwise
 */
int
ccow_get_default_attribute(ccow_completion_t c, ccow_default_attr_t attr, void* val);

/**
 * Returns this segment GUID
 *
 * @param tc - tenant context
 * @returns segment GUID
 */
uint64_t ccow_get_segment_guid(ccow_t tc);

#ifdef	__cplusplus
}
#endif

/** \} */

#endif
