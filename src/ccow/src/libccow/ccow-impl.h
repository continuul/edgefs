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
#ifndef __CCOW_IMPL_H__
#define __CCOW_IMPL_H__

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include <sys/sysinfo.h>

#include "ccow.h"
#include "json.h"
#include "crypto.h"
#include "queue.h"
#include "network.h"
#include "state.h"
#include "lfq.h"
#include "rtbuf.h"
#include "chunk.h"
#include "hashtable.h"
#include "cmcache.h"
#include "flexhash.h"
#include "ec-common.h"
#include "ccowtp.h"
#include "replicast.h"
#include "msgpackccow.h"
#include "sop_cache.h"


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * How many API I/O requests can be scheduled for submission in
 * parallel.
 */
#define CCOW_API_DEPTH		2048

/*
 * How many API Completions requests can be scheduled for submission
 * in parallel. Each completion tracks N number of PUT/GETs in flight.
 */
#define CCOW_COMPL_LFQ_DEPTH	256

/**
 * An embedded usage puts a strict limit on RAM utilization
 */
#define CCOW_API_DEPTH_EMBEDDED		128
#define CCOW_COMPL_LFQ_DEPTH_EMBEDDED	48
#define CCOW_IOVCNT_MAX_EMBEDDED	2000
/*
 * How many I/O requests can be issued in parallel.
 */
#define CCOW_IO_LFQ_DEPTH(tc)	((32 + (tc)->compl_lfq_depth) * (tc)->api_depth)

/*
 * How many high priority I/O requests can be issued in parallel.
 */
#define CCOW_IO_LFQ_HP_DEPTH	(128)

/*
 * For how long user thread has to be blocked (in seconds) if I/O queue is full?
 */
#define CCOW_IO_USER_THROTTLE_MAX	5

/*
 * For how long user thread has to be blocked (in seconds) if Completion queue
 * is full?
 */
#define CCOW_COMP_USER_THROTTLE_MAX	60

/*
 * Maximum parallel I/O.
 *
 * This parameter regulates how many outstanding I/Os can be on the tenant
 * context at the time. It throttles down in case of retransmits.
 */
#define CCOW_IO_RATE_MAX		16
#define CCOW_IO_RATE_MAX_LOW		1
#define CCOW_IO_RATE_MAX_HI		128
#define CCOW_IO_RATE_MAX_EMBEDDED	4
#define CCOW_IO_RATE_DELAY_NS		10
#define CCOW_IOPS_RATE_LIM_DELAY_NS	10000
#define CCOW_TP_SIZE_MIN		32
#define CCOW_TP_SIZE_DEFAULT		(CCOW_TP_SIZE_MIN > get_nprocs() ? \
	CCOW_TP_SIZE_MIN : get_nprocs())

#define BUCKET_DELETE_MAX_RETRY		3
#define BUCKET_CREATE_MAX_RETRY		3
#define BUCKET_PUT_TIMEOUT_MS		250
#define BUCKET_GET_TIMEOUT_MS		250

/*
 * Number of elements in the ucache context cache.
 */
#define CCOW_UCACHE_SIZE	(4 * 1024)
#define CCOW_UCACHE_SIZE_MAX	(1024 * 1024)

/*
 * Tenant object configuration
 */
#define	CCOW_TENANT_FIXEDMAP_DEPTH	1
#define	CCOW_TENANT_FIXEDMAP_WIDTH	512
#define	CCOW_TENANT_CHUNK_SIZE		8192

/*
 * Bucket object configuration
 */
#define	CCOW_BUCKET_FIXEDMAP_DEPTH	1
#define	CCOW_BUCKET_FIXEDMAP_WIDTH	512
#define	CCOW_BUCKET_CHUNK_SIZE		8192

/*
 * Object object configuration
 */
#define	CCOW_OBJECT_FIXEDMAP_DEPTH	1
#define	CCOW_OBJECT_FIXEDMAP_WIDTH	512
#define	CCOW_OBJECT_CHUNK_SIZE		8192

/*
 * Cluster object configuration
 */
#define	CCOW_CLUSTER_FIXEDMAP_DEPTH	1
#define	CCOW_CLUSTER_FIXEDMAP_WIDTH	512
#define	CCOW_CLUSTER_CHUNK_SIZE		8192

/* max string size of a 64 bit number */
#define CCOW_MAX_STRLEN_64	20

/* offline ISGW delay before re-sending a request */
#define CCOW_ISGW_BACKOFF_TIME	(30*1000)


struct ccow_recovery_item {
	uint512_t mchid; /* manifest's CHID */
	uint8_t is_cm; /* CM or VM flag */
	int32_t ngcount;
	uint32_t timeout_counter;
	uint128_t vdev_ack[REPLICAST_PROPOSALS_MAX];
};

struct ccow_op {
	QUEUE item;			/* link to queue of reqs per comp */
	QUEUE comphash_queue;
	size_t comphash_idx;
	size_t comphash_completed;
	ccow_op_t optype;
	struct ccow_completion *comp;
	struct iovec *iov_in;
	size_t iovcnt_in;
	rtbuf_t *chunks;
	uint512_t *chids;
	uint64_t offset;
	uint64_t txid_generation;
	struct chunkmap *chm;
	chunkmap_handle_t chm_handle;
	int* vm_leaf; /* Ponter to root node's leaf property, btreemap only */
	rtbuf_t *vm_reflist;		/* result of namedget */
	struct ccow_io *namedput_io;
	struct ccow_io *namedget_io;
	struct vmmetadata metadata;
	uint512_t vmchid; /* manifest chid, EC recovery requires it */
	cmcache_t *op_cmcache;
	char *cid;
	char *tid;
	char *bid;
	char *oid;
	size_t cid_size;
	size_t tid_size;
	size_t bid_size;
	size_t oid_size;
	uint512_t name_hash_id;
	uint512_t cluster_hash_id;
	uint512_t tenant_hash_id;
	uint512_t bucket_hash_id;
	uint512_t object_hash_id;
	uint512_t parent_hash_id;
	uint64_t uvid_timestamp;
	uint64_t coordinated_uvid_timestamp;
	int status;
	int index;
	struct ccow_lookup *iter;
	volatile unsigned long busy_cnt;
	uv_cond_t wait_cond;
	struct ccow_copy_opts *copy_opts;
	int completed;
	int finalizing;
	int need_wait;
	int comphash_started;
	int isgw_dfetch;
	struct iovec * seq_iov_in;
	size_t seq_iovcnt_in;

	int shard_index;

	struct ccow_io * tail_io;
	bt_traverse_done_cb_t traverse_cb;
	char isgw_addr_last[64]; /* The Last known good ISGW address for dynamic fetch */
	char isgw_addr_default[64]; /* The ISGW whose SegmentUIG matches object's one */
	QUEUE isgw_srv_list; /* List of ISGW serving the object */

#define CCOWOP_DEFAULT_ISGW_FOUND 	(1<<0)
#define CCOWOP_DEFAULT_ISGW_FAILED	(1<<1)

	int isgw_flags; /* Flags related to ISGWs */
};

struct ccow_io {
	struct state state;		/* NOTICE: position is important! */
	struct ccow_op *op;		/* parent operation */
	struct ccow_op *cont_op;	/* corresponding cont operation */
	ccow_op_t optype;
	struct ccow_completion *comp;
	struct ccow_io *next;		/* chained I/O for compound ops */
	QUEUE p_queue;
	QUEUE p_busy_queue;
	QUEUE p_item;
	QUEUE inprog_item;
	struct ccow_io *parent_io;	/* Parallel IO's ptr. or NULL */
	uint64_t attributes;		/* replicast attribute field */
	uint64_t network_payload_len;
	uint8_t started;
	uint8_t done;
	uint8_t parallel_io;
	uint64_t start_timestamp;	/* Timestamps for record keeping */
	uint64_t latency;		/* 4KB normalized latency for this io */
	rtbuf_t *cm_reflist;
	QUEUE pio_queue;
	QUEUE pio_item;
	struct ccow_rmw_context *rmw_ctx;
};

struct ccow_region {
	uint64_t off;	/* offset into the object */
	uint64_t len;	/* length of the region in object from the off-set */
};

typedef struct ccow_region *ccow_region_t;

/* Region opersations */
int ccow_region_subset(ccow_region_t this_region, ccow_region_t new_region);
int ccow_is_region_empty(ccow_region_t this_region);
int ccow_region_intersects(ccow_region_t this_region, ccow_region_t new_region);
void ccow_region_intersection(ccow_region_t a, ccow_region_t b, ccow_region_t in);
void ccow_region_diff(ccow_region_t a, ccow_region_t b,
		      ccow_region_t left_region, ccow_region_t right_region);

struct ccow_obj_lock {
	QUEUE	lk_link;		/* Link to the queue */
	uint512_t lk_nhid;		/* Object nhid for lock request */
	uint8_t	lk_mode;		/* lock mode flag */
	struct ccow_region lk_region;	/* Object region to be locked */
	/* TODO: Consolidate client parameters in client id */
	uint128_t lk_client_addr;	/* Client IP address */
	uint16_t lk_client_port;	/* Client port */
	uint64_t lk_io_cookie;		/* IO cookie. */
	int32_t lk_ref_count;		/* No. of users of this region-lock */
};

int ccow_lock(ccow_t tc, const char *bid, size_t bid_size,
	      const char *oid, size_t oid_size, struct ccow_obj_lock *ccow_lk);

int ccow_pack_lock(msgpack_p *p, struct ccow_obj_lock *ccow_lk);
int ccow_unpack_lock(msgpack_u *u, struct ccow_obj_lock *ccow_lk);

#define CCOW_IO_REQ(_io) (_io)->state.data
#define CCOW_IO_NEXT_REQ(_io) (_io)->next->state.data

#define CCOW_STREAM	0x01
#define CCOW_FINAL	0x04

struct vdev_sel {
	uint128_t vdevs[RT_SYSVAL_REPLICATION_COUNT*10];
	uint32_t  len;
};

struct ccow_completion {
	struct ccow *tc;
	volatile unsigned long released;
	volatile unsigned long busy_ops;
	lfqueue_t done_lfq;		/* FIFO queue for completed I/O's */
	ccow_callback_t comp_cb;
	void *comp_arg;
	struct ccow_op **operations;
	struct ccow_op **operations_done;
	unsigned long operations_num;
	unsigned long operations_end;
	uv_mutex_t io_mutex;
	uv_mutex_t operations_mutex;
	int status;
	uint8_t failed;
	uint8_t canceled;

	uint8_t object_count_mod;	/* mod bits for size modifications */
	uint8_t logical_sz_mod;		/* mod bits for size modifications */
	uint8_t used_sz_mod;		/* mod bits for size modifications */
	uint8_t hash_type;		/* replicast payload hash type */
	uint8_t compress_type;		/* replicast payload compress type */
	uint64_t estimated_used;	/* calculated estimated used */
	uint8_t replication_count;	/* default replication cnt for compl */
	uint8_t sync_put;		/* default sync put cnt for compl */
	uint8_t select_policy;		/* default selection policy */
	uint8_t failure_domain;		/* default failure domain */
	uint16_t inline_data_flags;	/* default flags, used by kv types */
	uint16_t number_of_versions;	/* default number of versions to keep */
	uint32_t chunkmap_chunk_size;	/* maximum chunk size for compl */
	uint16_t chunkmap_btree_order;	/* default B-Tree order */
	uint8_t chunkmap_btree_marker;  /* default B-Tree marker */
	uint16_t track_statistics;	/* Enable per-object stats collection
					   on client side. */
	uint64_t logical_sz;		/* logical size of the object */
	uint64_t object_count;		/* object_cnt if a container */
	uint64_t used_sz;		   /* used size of the object */
	uint64_t prev_logical_sz;	/* last logical size before update */
	uint32_t iops_rate_lim;		/* per-object iops rate limiting */
	uint8_t ec_enabled;		/* per-object ec enabled */
	uint32_t ec_data_mode;		/* per-object ec mode */
	uint64_t ec_trg_policy;		/* per-object EC triggering policy */
	uint8_t file_object_transparency;	/* file object transparency enabled */
	uint64_t object_delete_after;		/* Expunge object after this time */
	char *chunkmap_type;		/* replicast chunkmap algorithm type */
	rtbuf_t *custom_md;		/* custom md */
	uint8_t custom_md_mod_attr_ok;	/* Flag for custom_md modification on
					 * nonexistant object.
					 */
	rtbuf_t *md_overrides;		/* md overrides */
	uint8_t md_overrides_added; /* md overrides added to request payload */
	uint8_t cached_nhid;		/* Pre-built NHID/PHID provided. */
	uint512_t parent_hash_id;
	uint512_t vm_content_hash_id;
	uint512_t vm_name_hash_id;
	uint64_t vm_txid_generation;
	uint64_t dst_txid_generation; /* destination TxId generation used for cloning */
	struct ccow_op *init_op;	/* Init op for unnamed IO */
	struct ccow_copy_opts *ver_name;/* T/B/OID used for sv and clone ops */
	rtbuf_t *ver_rb;		/* Snapshot clone VM payload rb */

	uint64_t *sop_generation;	/* Holds current SOP returned I/O generation */
	uint64_t *cont_generation;	/* Holds current stream I/O generation */
	uint64_t version_uvid_timestamp;	/* Holds uvid_timestamp for a version */
	uint512_t *version_vm_content_hash_id; /* Holds vm_content_hash_id for a version */
	uint8_t was_object_deleted; /* Holds deleted flag of the last version */
	int cont_flags;			/* Stream flags on start */
	uint8_t cont;
	uint8_t needs_final_put;	/* True if stream needs put on finalize */
	uint8_t needs_final_md;		/* True if stream needs MD on finalize */
	int wait_count;

	uint8_t chunkmap_flags;		/* chunkmap specific flags */
	void * chunkmap_ctx;		/* chunkmap specific context */

	uint64_t seq_cnt;
	uint64_t seq_off;
	uint64_t seq_len;
	ccow_callback_t seq_cb;

	int shard_index;       /* shard index */

	uint64_t vmm_gen_id;		/* version manifest marker gen id */
	struct ccow_io vmm_io;
	struct vdev_sel* usel; /* An optional user-provided array to keep selected VDEVs */
};

static inline void
ccow_io_lock(struct ccow_io *io)
{
	uv_mutex_lock(&io->comp->operations_mutex);
}

static inline void
ccow_io_unlock(struct ccow_io *io)
{
	uv_mutex_unlock(&io->comp->operations_mutex);
}

/* Iterator/Lookup Functionality */
typedef enum {
	CCOW_LOOKUP_CLASS_OBJECT = 1,
	CCOW_LOOKUP_CLASS_BUCKET,
	CCOW_LOOKUP_CLASS_TENANT
} ccow_lookup_class_t;

struct ccow_lookup {
	rtbuf_t *rb;
	ccow_lookup_class_t type;	/* Class Type : Object, Bucket, Tenant */
	size_t pos;
	uint8_t unpacked;		/* Status bit for lookup_iterate */
	struct vmmetadata *metadata;	/* copy of the default metadata */
	rtbuf_t *custom_md;		/* msgpack of the custom_metadata */
	rtbuf_t *acl;			/* copy of the ACLs */
	rtbuf_t *name_index;		/* name-index for btree lookups */
	rtbuf_t *rb_md;			/* rtbuf of alloc default metadata kv */
	rtbuf_t *rb_cmd;		/* rtbuf of alloc custom metadata kv */
	rtbuf_t *versions;		/* rtbuf of alloc versions kv */
	struct ccow_completion *comp;	/* pointer to holding completion */
};

struct ccow_lookup *ccow_lookup_create(struct ccow_completion *comp,
    ccow_lookup_class_t type);

struct ccow_bucket {
	struct ccow *tc;
	int sub_fd;			/* auditd subscription fd */
	uv_poll_t sub_req;		/* notification callback req */
};

struct ccow;

/*
 * L1 unnamed chunk cache: consists of an LRU list which is a doubly linked
 * list of queue entries sorted by LRU. plus a hash table to make lookups
 * effecient.
 *
 * cost of lookup is O(1), as is cost of finding LRU entry.
 */

typedef struct {
	union {
		struct {
			volatile uint64_t count;
		};
		char filler[512];
	};
} ucache_share_t;

typedef struct {
	uint512_t key;
	uv_buf_t value;

	QUEUE col_link;					// collision link
	QUEUE lru_link;					// lru link

} ucache_entry_t;

typedef struct {
	uint64_t count;
	QUEUE hdr;
} ucache_hdr_t;

typedef struct {
	struct ccow *tc;
	int uc_inprog;
	uv_mutex_t uc_pos_mutex;

	uint64_t size_cur;
	uint64_t size_inc;
	uint64_t size_min;
	uint64_t size_max;
	ucache_hdr_t *cache;

	uint64_t timer_count;
	uint64_t lru_count;
	QUEUE lru_q;

	uint64_t uc_mi_e_lcl;
} ucache_t;

// FIXME: TBD: times
#define UCACHE_TIMER_TIMEOUT	3000
#define UCACHE_TIMER_REPEAT	500

#define UCACHE_FREE_SPACE_LIM	30
#define UCACHE_EVICT_COUNT	8

#define UCACHE_SIZE_LIM		75

#define UCACHE_MEMLIMIT_EMBEDDED (32*1024UL*1024UL)

ucache_t* ccow_ucache_create(struct ccow *tc);
void ccow_ucache_free(struct ccow *tc);
void ccow_ucache_put(ucache_t *uc, uint512_t *chid, uv_buf_t *bufs, int nbufs);
int ccow_ucache_get(ucache_t *uc, uint512_t *chid, uv_buf_t *buf);
int ccow_ucache_get_uncomp(ucache_t *uc, uint512_t *chid, struct ccow_op *op,
    int verify_chid, uint8_t hash_type, uint8_t compress_type,
    struct iovec *iov_out);
void ccow_ucache_expand(ucache_t *uc, unsigned long fp);
void ccow_ucache_shrink(ucache_t *uc, unsigned long fp);
void ccow_ucache_evict(ucache_t *uc, unsigned long fp);
int ccow_ucache_idx(ucache_t *uc, uint512_t *chid);

#define CCOW_TRCV_MCBASE_ADDR	"FF02::D:0:0:0"	/* default Mulit-Cast base */
#define CCOW_TRCV_MCBASE_PORT	10398		/* default CCOW MC port */

struct ccow_internal_log {
	hashtable_t	*devicelist;
	int		iocount;
};

/*
 * Implementation of ccow_t
 */
extern int ucache_test;

struct ccow {
	uv_loop_t *loop;		/* cluster event loop */
	uv_thread_t main_thread;	/* thread where we loop */
	json_value *opts;		/* parsed cluster configuration */
	void (*opts_override)(struct ccow *); /* override opts programmatically */
	uv_barrier_t main_barrier;	/* syncrhonization on start */
	uv_async_t enter_handle;	/* enter handler */
	uv_async_t exit_handle;		/* exit handler */
	lfqueue_t api_lfq;		/* lockless FIFO queue for API calls */
	lfqueue_t api_lfq_hp;		/* high priority queue for API calls */
	lfqueue_t comp_lfq;		/* preallocated queue for compls */
	lfqueue_t released_lfq;		/* queue for released compls */
	cmcache_t *cmcache;		/* per-tenant Unnamed Chunk cache */
	uint64_t tenant_ucache_size;	/* number of ucache payload bufs */
	uint64_t tenant_ucache_size_max;
	ucache_t *ucache;		/* per-tenant Unnamed Chunk cache */
	struct ccow_completion *reserved_comp; /* ring comp can be allocated w/o sleep */
	struct ccow_completion* completions;
	lfqueue_t ios_lfq;		/* preallocated queue for I/Os */
	struct ccow_network *netobj;	/* network object */
	char *cid;			/* selected cluster name */
	size_t cid_size;		/* cid size in bytes */
	char *tid;			/* selected TID */
	size_t tid_size;		/* tid size in bytes */
	uint512_t sysobj_hash_id;	/* crypto hash value of sysobj */
	uint512_t cluster_hash_id;	/* crypto hash value of cid */
	uint512_t tenant_hash_id;	/* crypto hash of CID/TID */
	uv_poll_t sub_req;		/* notification callback req */
	int startup_err;		/* main_loop init err */
	unsigned long loop_thrid;	/* main loop thread id */
	int sub_fd;			/* auditd subscription fd */
	char junk[4];			/* Unused */
	uint128_t this_serverid;	/* broker's this serverid */
	uint128_t this_guid;		/* global resulting GUID including this serverid */
	uint512_t svcinfo;		/* service info this context belongs to */

	uint64_t put_retry_cnt;		/* incremented on each put retry to */
	uint64_t get_retry_cnt;		/* incremented on each get retry to */
	uint64_t put_retry_prev;
	uint64_t get_retry_prev;
	struct avg_ring avg_put_weight_ring;
	struct avg_ring avg_put_lat_ring;
	struct avg_ring avg_get_lat_ring;
	uint64_t avg_put_weight;	/* Avg PUT weight */
	uint64_t avg_put_latency;	/* Avg PUT latency normalized to 4KB */
	uint64_t avg_get_latency;	/* Avg GET latency normalized to 4KB */
	uint64_t stats_refresh_timer;
	uint64_t put_iops_cnt;
	uint64_t get_iops_cnt;
	uint64_t put_bw_cnt;
	uint64_t get_bw_cnt;
	uint64_t put_iops;
	uint64_t get_iops;
	uint64_t put_bw;
	uint64_t get_bw;

	int expunge_onsplit;
	int sync_put_ack_min;
	int sync_put_dedup_min;
	int sync_put_extra;
	int sync_put_extra_wait;
	int io_rate_max;
	int io_rate_lim;
	int io_rate;
	int io_adjust_period;
	uint64_t iops_rate_adjust;
	int congest_timerfd;
	uv_poll_t congest_req;

	QUEUE mtc_item;			/* Link to MTC */

	QUEUE inprog_queue;		/* IOs which are curr. in progress */

	/* per-tenant configuration */
	crypto_hash_t hash_type;	/* selected hash method */
	int compress_type;		/* selected compression method */
	uint8_t replication_count;	/* selected default replication cnt */
	uint8_t sync_put;		/* selected sync put cnt */
	uint8_t sync_put_fd_min;	/* selected sync put failure domain min */
	uint8_t sync_put_commit_wait;	/* wait for all PAYLOAD_ACKs or PAYLOAD_RCVD */
	uint8_t sync_put_named;		/* selected sync put named cnt */
	uint8_t select_policy;		/* selected balancing policy */
	uint8_t failure_domain;		/* selected failure domain */
	uint16_t inline_data_flags;	/* cannot be set, specific for object levels only */
	uint16_t number_of_versions;	/* selected number of versions */
	uint32_t chunkmap_chunk_size;	/* selected default chunk size */
	uint16_t chunkmap_btree_order;	/* selected B-Tree order */
	uint8_t chunkmap_btree_marker;	/* selected B-Tree marker */
	char *chunkmap_type;		/* selected chunkmap algorithm type */
	uint8_t unicastio;		/* check if unicast IO is set (boolean
					 * for now, could be bit-flag/int in
					 * future)
					 */
	uint32_t tp_size;		/* Thread pool size */
	uint64_t slg_timeout;		/* force override for slg timeout */
	uint8_t ec_enabled;		/* Erasure Coding enable/disbale flag */
	uint32_t ec_data_mode;		/* Erasure coding configuration. Bitfield */
	uint64_t ec_trg_policy;		/* Erasure coding triggering policy */
	uint8_t file_object_transparency;	/* file object transparency enabled flag */
	uint64_t object_delete_after;		/* Expunge object after this time */
	uint16_t track_statistics;	/* Enable per-object stats collection
					   on client side. */
	uint32_t iops_rate_lim;		/* per object rate-limiting, in IOPS */
	uint32_t api_depth;		/* How many API I/O requests can be scheduled for submission in
 					 * parallel.*/
	uint32_t compl_lfq_depth;	/* How many API Completions requests can be scheduled for submission
					* in parallel. Each completion tracks N number of PUT/GETs in flight.
					*/
	/* local broker configuration */
	int tenant_schedprio;		/* selected tenant scheduler priority */

	volatile struct flexhash *flexhash;	/* Flexhash table */
	int slg_in_progress;		/* flexhash stale. server list get in progress */
	int rcv_joined;			/* true = 1 if the mc join succeeded */
	struct sockaddr_in6 tenant_recvaddr;
					/* mc address to receive rt get */
	uint16_t tenant_recvport;
	uint8_t verify_chid;		/* Flag to enable recv side chid hash
					 * verification */
	int join_delay;		/* induced delay for join to complete */
	uv_async_t api_call;		/* trigger API call */
	struct ccow_io* ios;

	uint32_t comphash_bulk_max;
	uint32_t comphash_threshold_size;
	uint32_t ucache_size_limit;
	uint8_t disable_read_ahead;
	uint32_t read_ahead_factor;
	uint32_t read_ahead_detect;


	/* ucache timer */
	uv_timer_t *ucache_timer_req;

	int ucache_work_inprog;
	volatile uint8_t ucache_terminate_worker;
	uv_barrier_t ucache_term_bar;
	volatile int abort;

	/* cmcache */
	uint64_t cmcache_lru_hiwat;
	uint64_t cmcache_lru_lowat;
	uint64_t cmcache_hash_size;
	uint64_t cmcache_timer_timeout;
	uint64_t cmcache_timer_repeat;

	/* GE cache configured? */
	uint8_t gw_cache;

	/* TRLOG globals (copy) */
	uint64_t trlog_interval_us;
	uint64_t trlog_quarantine;

	/* Sharded list cache */
	sop_shard_table *shard_cache;
	int shard_cache_inprog;
	int shard_cache_timer_cnt;

	/* stats */
	struct ccow_stats stats;

	/* timer to scan the shared memory for multiple client processes */
	uv_timer_t *timer_process_scan;
	uv_mutex_t pscan_timer_lock;
	int pscan_work_inprog;
	volatile uint8_t pscan_terminate_worker;
	uv_barrier_t pscan_term_bar;
	ccow_usertimer_cb_t user_timer_cb;
	void *user_timer_arg;
	struct ccowtp* tp;
	uint64_t tp_stat_counter;

	uint64_t last_consensus_send_time;      /* The last consensus send time */
	uint64_t last_consensus_recv_time;      /* The last consensus receive time */
	uint64_t isgw_backoff_time; /* Time of ignorance of an offline ISGW */
};

/**
 * A sharding context structure used for passing shard definition to the sharding methods
 */
struct ccow_shard_context {
	char *shard_name;
	size_t shard_name_size;
	int shard_count;
	int encryption;
	int overwrite;
	int eventual;
	uint16_t inline_data_flag;
};


#define CLIENT_FLEXHASH	tc->flexhash

/*
 * Internal admin init with ability to override context parameters
 * on startup programmatically
 */
int
ccow_admin_init_override(const char *jsonstr, const char *clname, size_t cl_len,
    ccow_t *ptctx, void (*opts_override)(struct ccow *));

/*
 * Internal per-tenant put
 */
int
ccow_tenant_put(const char *cid, size_t cid_size, const char *tid, size_t tid_size,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    struct ccow_completion *c, struct iovec *iov, size_t iovcnt, uint64_t off,
    ccow_op_t optype, struct ccow_copy_opts *copy_opts, int64_t get_io_attributes);

/*
 * Internal per-tenant get
 */
int ccow_tenant_get(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, struct ccow_completion *c, struct iovec *iov,
    size_t iovcnt, uint64_t off, ccow_op_t optype, ccow_lookup_t *iter);

/*
 * Internal per-tenant get by nhid_str
 */
int ccow_tenant_getobj(const char *nhid_str, struct ccow_completion *c,
    struct iovec *iov, size_t iovcnt, uint64_t off, ccow_op_t optype,
    ccow_lookup_t *iter);

/*
 * Internal insertion of BT key-val with CHID for backreferences on snapview.
 * inside iov defined as:
 * iov[0] -> key/val
 * iov[1] -> chid (UINT512)
 */
int ccow_insert_chid(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, struct iovec *iov, size_t iovcnt);

/*
 * Internal structure of completion pipe-line presented as:
 *
 * CCOW completion == 1:N ==> CCOW operation == 1:N ==> CCOW I/O
 *
 * This way we can aggregate multiple CCOW I/Os per operation and build complex
 * completion pipe-line such that user APIs calls ccow_put(), ccow_get(), etc
 * can be executed as one transaction.
 *
 * @param c pointer to existing I/O completion object
 * @param pop pointer to the I/O operation object (output)
 * @returns 0 on success
 * @internal
 */
int ccow_operation_create_cont(struct ccow_completion *c, ccow_op_t optype,
    struct ccow_op **pop, int *index);

int ccow_operation_create(struct ccow_completion *c, ccow_op_t optype,
    struct ccow_op **pop);

/*
 * Removes I/O operation object from the completion request queue and freeing
 * memory.
 *
 * @param op pointer to the I/O operation object
 * @param unsafe set if internal lock is needed
 * @internal
 */
void ccow_operation_destroy(struct ccow_op *op, int unsafe);

/*
 * Dequeue I/O from cluster's pool of I/Os, call main event loop door
 * bell and start corresponding I/O state machine.
 *
 * @param c pointer to existing I/O completion object
 * @param op pointer to existing I/O operation object
 * @param trans_tbl pointer to the table with state transitions
 * @param trans_max maximum number of state transitions
 * @param data state object private data
 * @param term_cb callback to be called at ST_TERM or NULL
 * @param io where to store the I/O object
 * @returns 0 on success
 * @internal
 */
int ccow_create_io(struct ccow_completion *c, struct ccow_op *op,
    ccow_op_t iotype, const struct transition *trans_tbl, int trans_max,
    void *data, state_term_t term_cb, struct ccow_io **pio);

/*
 * Release I/O back to completion release queue
 *
 * @param comp completion object
 * @param unsafe use locks if set
 * @internal
 */
void ccow_release_internal(ccow_completion_t comp, int unsafe);

/*
 * Enqueue I/O back to the cluster's pool of I/Os and call state machine
 * end call back to free out object's resources.
 *
 * @param io I/O object previously created with ccow_create_io()
 * @inrernal
 */
void ccow_destroy_io(struct ccow_io *io);

/*
 * Start an I/O previously created with ccow_create_io(). Unless started,
 * created I/O will hold completion from being released.
 *
 * @param io an I/O object to start
 * @returns 0 on success
 * @internal
 */
int ccow_start_io(struct ccow_io *io);

/*
 * Chain I/O with the end of the current chain or Named Put
 *
 * @param op pointer to existing I/O operation object
 * @param io an I/O add to the chain
 * @internal
 */
void ccow_chain_io(struct ccow_op *op, struct ccow_io *io);

/*
 * Add an item to the parallel IO queue.
 *
 * @param op pointer to existing I/O operation object
 * @param io an I/O add to the chain
 * @internal
 */
void ccow_parallel_io(struct ccow_op *op, struct ccow_io *io);

/*
 * Enqueue I/O back to cluster's pool of I/Os, unblock waiters in case of
 * syncrhonous operations and calls completion callback.
 *
 * @param io an I/O object to complete
 * @returns 0 on success
 * @internal
 */
int ccow_complete_io(struct ccow_io *io);

/*
 * Format and log to the logger the object path, hash id's and flexhash data
 * in the case of errors.
 *
 * @param io the I/O object to print
 * @param log_level   (warn or error)
 * @internal
 */
void ccow_error_fmt(struct ccow_io *io, int log_level);

/*
 * Mark outstanding I/O as failed.
 *
 * @param io an I/O object to complete
 * @param err error code to be set for an operation
 * @returns 0 on success
 * @internal
 *
 * Subsequent ccow_fail_io() calls may override error code.
 */
void ccow_fail_io_notrace(struct ccow_io *io, int err);
int ccow_fail_io_warn_level(struct ccow_io *io, int err);
#define ccow_fail_io(fail_io, err) do { \
	if (ccow_fail_io_warn_level(fail_io, err)) { \
		log_debug(lg, "failing I/O %p type %d error %d: status %d", \
		    fail_io, fail_io->optype, err, (fail_io->comp)->status); \
	} else { \
		ccow_error_fmt(fail_io, LOG_LEVEL_ERROR); \
		log_error(lg, "failing I/O %p type %d error %d: status %d", \
		    fail_io, fail_io->optype, err, (fail_io->comp)->status); \
	} \
	ccow_fail_io_notrace(fail_io, err); \
} while (0)

typedef void (*comphash_cb_t)(void *arg, int status);

/*
 * For a given operation compress incoming I/O vectors and correspondingly
 * fingerprint.
 *
 * @param op pointer to existing I/O operation object
 * @param cb callback to be called on success or error
 * @param arg argument to be passed to callback
 * @returns 0 on success, error on failure
 * @internal
 *
 * Implementation uses threadpool for parallel computations. Error strategy:
 * all or nothing. Callback will not be called until all tasks have completed.
 */
int ccow_comphash_compute(struct ccow_op *op, comphash_cb_t cb, void *arg);

typedef void (*hashuncomp_cb_t)(void *arg, int status);

/*
 * For a given operation compress incoming I/O vectors and correspondingly
 * fingerprint.
 *
 * @param op pointer to existing I/O operation object
 * @param cb callback to be called on success or error
 * @param arg argument to be passed to callback
 * @param payload received payload input to be uncompressed
 * @param offset an offset of the destination chunk
 * @param compress_type chunk selected compress type to use
 * @param rb_cached flag set if rb is cache retrieved
 * @returns 0 on success, error on failure
 * @internal
 *
 * Implementation uses threadpool for parallel computations. Error strategy:
 * all or nothing. Callback will not be called until all tasks have completed.
 */
int ccow_hashuncomp_compute(struct ccow_op *op, hashuncomp_cb_t cb, void *arg,
    rtbuf_t *payload, uint512_t *chid_in, uint64_t offset, uint8_t hash_type,
    uint8_t compress_type, int rb_cached);

/*
 * In cases when Named Get completes with err prior to comphash_exec for the
 * whole op we need to cancel outstanding requests to comphash for this op
 * Walk through the queue of outstanding comphash tasks and cancel any
 * which have not started yet, ignore all others.
 *
 * @param op pointer to existing I/O operation object
 * @returns 0 on success, error on failure
 * @internal
 */
void ccow_comphash_cancel(struct ccow_op *op);

/*
 * Maximum number of chunks threaded to be compute in parallel.
 */
#define COMPHASH_BULK_MAX		8

/*
 * Low watermark - 16K, requested I/O is greater, use threaded comphash and
 * hashuncomp
 */
#define COMPHASH_THRESHOLD_SIZE		32768

struct comphash {
	QUEUE item;
	struct ccow_op *op;
	struct iovec *iov_in;		/* input */
	int idx;			/* index to op->chids, op->chunks */
	comphash_cb_t cb;
	void *arg;
	int status;
	int type;			/* compress+hash or decompress */
};

struct hashuncomp {
	uv_work_t wreq;
	struct ccow_op *op;
	uint512_t *chid_in;		/* SHA to verify */
	uv_buf_t *data_in;		/* input */
	int nbufs;			/* nbufs in the data_in array */
	uint8_t hash_type;		/* selected hash_type */
	uv_buf_t *chunk;		/* output */
	uint8_t compress_type;
	hashuncomp_cb_t cb;
	int status;
	void *arg;
	int rb_cached;
	uint8_t verify_chid;		/* Flag to bypass recv side hash */
};

/*
 * Compute single chunk and store results in struct comphash or hashuncomp
 */
void comphash_one(struct comphash *ch);
void hashuncomp_one(struct hashuncomp *ch);

/* helper function */
ssize_t hashuncomp_find_idx(rtbuf_t *chunks, uint64_t start_offset, uint64_t offset);

#define CCOW_CLASS_FIELDS	\
	struct ccow *tc;	\
	struct ccow_io *io;	\
	struct repctx *ctx;	\
	uv_timer_t *timer_req;	\
	int retry;		\
	int inexec;		\
	uint512_t chid;		\
	uint512_t ng_chid;	\
	void * btree;

/* base class for easy access and common primitives */
struct class_req {
	CCOW_CLASS_FIELDS
};

struct vdevipaddr {
	uint128_t vdevid;
	struct sockaddr_in6 saddr;
};

typedef enum _put_req_type {
	CL_PUT_REQ_TYPE_UNKNOWN = 0,
	CL_PUT_REQ_TYPE_UNNAMED=  1,
	CL_PUT_REQ_TYPE_NAMED =  2
} put_req_type;

struct put_tcp_cb_data {
	struct sockaddr_in6	*dest;
	struct state		*st;
};

/* the common put request
 *
 */
struct putcommon_client_req;
typedef void (*putcommon_client_callback_t) (struct putcommon_client_req *r);
struct putcommon_client_req {
	CCOW_CLASS_FIELDS
	rtbuf_t	*payload;
	msgpack_p *packed_data;
	msgpack_p *metadata;
	msgpack_p *serial_data;
	uint8_t ack_count;
	uint8_t already_stored_count;
	uint8_t already_stored_selected;
	uint8_t nack_count;
	uint8_t hash_type;
	uint64_t delayed_start_us;
	uint8_t proposed_count;
	uint8_t selected_count;
	uint8_t rt_busy_count;
	uint8_t pp_busy_count;
	uint8_t out_of_space_count;
	uint8_t needed_replicas;
	struct replicast_rendezvous_proposal proposals[REPLICAST_PROPOSALS_MAX];
	uint128_t proposed_vdevs[REPLICAST_PROPOSALS_MAX];
	uint128_t selected_vdevs[REPLICAST_PROPOSALS_MAX];
	uint128_t already_stored_vdevs[REPLICAST_PROPOSALS_MAX];
	uint128_t out_of_space_vdevs[REPLICAST_PROPOSALS_MAX];
	uint128_t target_vdev;
	uint8_t acked_count[REPLICAST_PROPOSALS_MAX];
	struct vdevipaddr vdevip[REPLICAST_PROPOSALS_MAX];
	struct put_tcp_cb_data cb_data[REPLICAST_PROPOSALS_MAX];
	struct sockaddr_in6 selected_ngaddr;
	struct sockaddr_in6 selected_rtaddr;
	uint8_t tcp_conn_wait_count;
	uint8_t tcp_connected_count;
	int rt_retry;
	int rtselected;
	int rcvd_count;
	uint64_t rcvd_max_delta;
	uint64_t rt_delta_timeout;
	int rtsend_timer_fd;
	int start_timer_fd;
	UV_HPT_TIMER_T *rtsend_timer_req;
	UV_HPT_TIMER_T *start_timer_req;
	uint64_t req_start;
	uint64_t rt_req_start;
	putcommon_client_callback_t	done_cb;
	uint8_t select_policy;
	uint8_t tcp_retry;
	put_req_type req_type;
	uint8_t	terminated;
	uint8_t persistent_replies;
	uint8_t persistent_nacks;
	int zonecount;
	int servercount;
};


int ccow_namedput_create(ccow_completion_t comp,
    putcommon_client_callback_t done_cb, struct ccow_op *op,
    struct ccow_io **pio);

int ccow_unnamedput_create(ccow_completion_t comp,
    putcommon_client_callback_t done_cb, struct ccow_op *op,
    struct ccow_io **pio, struct ccow_io *parent_op);

int ccow_unnamedput_create_detached(ccow_completion_t comp,
    putcommon_client_callback_t done_cb, struct ccow_op *op,
    struct ccow_io **pio, struct ccow_io *parent_op);

#define CLIENT_PUTCOMMON_MAX_RETRY		200
#define CLIENT_PUTCOMMON_MAX_RETRY_FAILFAST	20
#define CLIENT_PUTCOMMON_ENOSPC_RETRY		3
#define CLIENT_PUTCOMMON_DELTA_MIN_MS		40
#define CLIENT_PUTCOMMON_DELTA2_MIN_MS		3000
#define CLIENT_PUTCOMMON_TIMEOUT_PP_MS		750
#define CLIENT_PUTCOMMON_TIMEOUT_PP_SPACE_MS	(CLIENT_PUTCOMMON_TIMEOUT_PP_MS*15/10)
#define CLIENT_PUTCOMMON_TIMEOUT_PP_FAST_MS	150
#define CLIENT_PUTCOMMON_TIMEOUT_PP_FASTSOP_MS	10
#define CLIENT_MAX_RETRY_TIMEOUT_MS		3000
#define CLIENT_MAX_RETRY2_TIMEOUT_MS		8000
#define CLIENT_MAX_SERIALOP_TIMEOUT_MS		60000 /* 1min */
#define CLIENT_MAX_SERIALOP_RCVD_TIMEOUT_MS	5000 /* 5s */
#define CLIENT_DELAYED_START_LOW_MS		5
#define CLIENT_DELAYED_START_MAX_TIMEOUT_MS	25
#define CLIENT_PUTCOMMON_REARM_TRANSFER_MS	75
#define CLIENT_PUTCOMMON_REARM_NOTNOW_MS	50

/*
 * NAMED/UNNAMED GET class
 */


enum get_req_type {
	GET_REQ_TYPE_UNKNOWN	= 0,
	GET_REQ_TYPE_NAMED	= 1,
	GET_REQ_TYPE_NAMED_RT	= 2,
	GET_REQ_TYPE_UNNAMED	= 3,
	GET_REQ_TYPE_UNNAMED_RT = 4,
	GET_REQ_TYPE_QUERY	= 5
};

struct getcommon_client_req;
typedef void (*getcommon_client_callback_t)(struct getcommon_client_req *r);
struct getcommon_client_req {
	CCOW_CLASS_FIELDS
	uv_buf_t payload[REPLICAST_DGRAM_MAX];
	uv_buf_t one_payload;
	uint256_t dgram_idx;
	int nbufs;
	rtbuf_t *rb;
	int rb_cached;
	int cm_verify_status;
	void* data;
	rtbuf_t *cm_reflist;
	uint8_t compress_type;
	uint64_t offset;
	uint8_t hash_type;
	void *chunkmap_data;
	getcommon_client_callback_t done_cb;
	int hashuncomp_threaded;
	int hashuncomp_inexec;
	enum get_req_type reqtype;
	uint128_t tenant_mcaddress;
	uint512_t mchid;
	// rt related fields below
	int err_count;
	int reply_count;
	int ngcount;
	int fddelta;
	int excluded_count;
	int proposed_count;
	int excluded_vdevs_errcnt[REPLICAST_PROPOSALS_MAX];
	uint128_t excluded_vdevs[REPLICAST_PROPOSALS_MAX];
	uint128_t proposed_vdevs[REPLICAST_PROPOSALS_MAX];
	uint128_t selected_vdevs[REPLICAST_PROPOSALS_MAX];
	uint64_t proposed_generations[REPLICAST_PROPOSALS_MAX];
	uint64_t proposed_vmm_gen_ids[REPLICAST_PROPOSALS_MAX];
	uint64_t proposed_uvids[REPLICAST_PROPOSALS_MAX];
	uint512_t proposed_chids[REPLICAST_PROPOSALS_MAX];
	struct replicast_rendezvous_proposal proposals[REPLICAST_PROPOSALS_MAX];
	struct vdevipaddr vdevip[REPLICAST_PROPOSALS_MAX];
	struct replicast_rendezvous_proposal *selected_proposal;
	struct vdevipaddr *selected_vdevip;
	uint64_t delayed_start_us;
	struct sockaddr_in6 selected_ngaddr;
	int rtselected;
	int rttransferred;
	int rt_inprogress;
	uint64_t content_length;
	int error;
	uv_timer_t *rttimer_req;
	uint64_t req_start;
	uint64_t rt_req_start;
	int obj_found;
	uint64_t max_generation;
	uint64_t max_vmm_gen_id;
	uint64_t accept_timeout;
	int delayed_start_fd;
	UV_HPT_TIMER_T *delayed_start_timer_req;
	int vbuf_allocated;
	uint8_t tcp_retry;
	uint32_t n_error_consensus;
	uint32_t error_consensus_max;
	uint32_t recovery_cnt;
	uint32_t recovery_busy_cnt;
	uint32_t recovery_flags;
	uint128_t err_vdevs[REPLICAST_PROPOSALS_MAX];
	struct ccow_recovery_item ri;
	uint64_t chunk_offset;
	int badng_retry;
	uint8_t gw_cache;
	void* isgw_priv;
	void* isgw_fsm_hanlde;
	QUEUE* isgw_list_pos;
	struct refentry ref;

};

struct getres_client_req;
typedef void (*getres_client_callback_t)(struct getres_client_req *r);
struct getres_client_req {
	CCOW_CLASS_FIELDS
	ccow_sr_mj_opcode_t maj_res;
	ccow_sr_mn_opcode_t minor_res;
	uint128_t tgt_vdevid;
	rtbuf_t in_payload;
	rtbuf_t out_payload;
	getres_client_callback_t done_cb;
};

#define CCOW_MAX_PROCESS 1024
#define CCOW_PROC_DEAD 0
#define CCOW_PROC_ALIVE 1

struct ccow_shm_process {
	int             pid;    /* process id */
	uint64_t        ts;     /* last known timestamp */
	uint16_t        if_count;    /* number of interfaces */
	struct repvbuf  vbuf[REPLICAST_SRV_INTERFACES_MAX]; /* vbuf per interface */
	uint8_t		alive;   /* known dead/alive */
};

void ccow_glock();
void ccow_gunlock();

static inline void
replicast_send_done_generic(void *data, int err, int ctx_valid)
{
	struct state *st = data;
	struct class_req *req = st->data;
	struct repctx *ctx = req->ctx;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
	    data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;
	if (state_check(st, ST_TERM)) {
		st->term_cb(st);
		return;
	}

	if (err) {
		log_error(lg, "Error %d while sending ccow request for ev %d",
		    err, st->ev_cur);
		state_event(st, EV_ERR);
		return;
	}
}

/**
 *  Calculate used factor
 */
static inline double used_factor(uint8_t rc, uint8_t ec_enabled, uint32_t ec_data_mode) {
	double res = rc;
	if (!ec_enabled || !ec_data_mode) {
	   return res;
	}
	int k = (ec_data_mode >> 8) & 0xFF;
	int m = (ec_data_mode & 0xFF);
	if (k <= 0 || m <= 0) {
		return res;
	}
	res = (k + m);
	res /= k;
	return res;
}


/**
 * Prebuild the hash index for an object.
 *
 * @param comp ccow completion for this context
 * @param bid  bucket id for cmcache for this object
 * @param bid_size bucket id size in bytes
 * @param oid  object id for cmcache for this object
 * @param oid_size object id size in bytes
 * @param nhid_out  output pre-allocated 64byte nhid for object.
 * @param parent_out output pre-allocated 64byte parent hash id.
 * @returns 0 on success
 *
 * This function will prebuild the named hash index and cache it within the
 * tenant context allowing lower latency operations at the expense of locking
 * this tenant context to a single object.  Useful in cases such as volumes.
 *
 */
int ccow_prebuild_hashes(ccow_completion_t comp, const char *bid,
    size_t bid_size, const char *oid, size_t oid_size, void *nhid_out,
    void *parent_out);

int ccow_namedget_create(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, getcommon_client_callback_t done_cb,
    ccow_op_t optype, struct ccow_op **pop, struct ccow_io **pio);

int ccow_resget_create(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, getres_client_callback_t done_cb,
    ccow_op_t optype, struct ccow_op **pop, struct ccow_io **pio);

int ccow_unnamedget_create(ccow_completion_t comp,
    getcommon_client_callback_t done_cb, struct ccow_op *op,
    struct ccow_io **pio, struct ccow_io *parent_io);

void ccow_namedget_query_done(struct getcommon_client_req *r);
void ccow_namedput_done(struct putcommon_client_req *r);

int ccow_get_res(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t c,
    ccow_sr_mj_opcode_t mjr_res, ccow_sr_mn_opcode_t mnr_res,
    struct iovec *in_iov, size_t in_iovcnt,
    struct iovec *out_iov, size_t out_iovcnt);

int ccow_get_chids(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, const uint512_t *vmchid, uint64_t chid_type,
    struct ccow_completion *c, struct iovec *iov, size_t iovcnt, rtbuf_t **rb,
    ccow_lookup_t *iter);

int ccow_put_attrs_unsafe(ccow_t tc, const char *cid, size_t cid_size,
			  const char *tid, size_t tid_size, const char *bid,
			  size_t bid_size, const char *oid, size_t oid_size,
			  ccow_op_t optype, ccow_metadata_kv_t attrs[],
			  uint32_t attr_nr, struct iovec *iov, size_t iovcnt);
int ccow_verify_mdop(ccow_op_t optype, ccow_metadata_kv_t attrs[],
		     uint32_t attr_nr);
int modify_attrs(ccow_completion_t c, ccow_lookup_t iter, ccow_op_t optype,
	     ccow_metadata_kv_t attrs[], uint32_t attr_nr);

#define CLIENT_GETCOMMON_MAX_RETRY	200
#define CLIENT_GETCOMMON_MAX_RETRY_FAILFAST	3
#define CLIENT_LOOP_DELAY_FACTOR	50
#define CLIENT_GETCOMMON_NAMEDGET_TIMEOUT_MS	5000
#define CLIENT_GETCOMMON_UNNAMEDGET_TIMEOUT_MS	2000
#define CLIENT_GETCOMMON_TIMEOUT_MS	10000
#define CLIENT_GETCOMMON_TIMEOUT_MIN_MS	1000
#define CLIENT_UNENCODE_TIMEOUT_MAX	60*1000

/*
 * Number of transfer attempts before we conclude that this device has
 * indeed a copy of broken chunk and this is not a networking issue
 */
#define EXCLUDED_VDEVS_ERRCNT_MAX		3

/*
 * build a new set of named hashes.
 */
int ccow_build_name_hashes(struct ccow_completion *c, struct ccow_op *op);

int ccow_tenant_assign_mcbase(struct ccow *tc, char *tenant_rcv_mcbase,
					uint16_t port);
int ccow_tenant_leave_rcvaddr(struct ccow *tc);
int ccow_tenant_join_rcvaddr(struct replicast *robj, struct ccow *tc,
							uint32_t if_index);
int ccow_pingpong(struct ccow *tc, uint8_t jsonout);

static inline uint32_t
ccow_retry_log2(int delay_ms, int retry) {
	uint32_t ret = -1;
	while (retry != 0) {
		retry >>= 1;
		ret++;
	}
	if ((int)ret <= 0)
		ret = 1;
	int n = ret > 1 ? ret / 2 : 1;
	return delay_ms * ret * n;
}

/*
 * mdtype is a bitmask defined as :
 * #define CCOW_MDTYPE_METADATA		0x1
 * #define CCOW_MDTYPE_CUSTOM		0x2
 * #define CCOW_MDTYPE_ACL		0x4
 * #define CCOW_MDTYPE_NAME_INDEX	0x8
 * #define CCOW_MDTYPE_VERSIONS	0x10
 * #define CCOW_MDTYPE_ALL		0xFF
 */
void ccow_dump_iter_to_logger(ccow_lookup_t iter, int mdtype);

/* need by vmpack */
int ccow_iter_update_md(ccow_lookup_t iter, struct vmmetadata *md);

/* used for inheritance on obj create */
int ccow_copy_inheritable_md(ccow_completion_t comp_in,
    ccow_completion_t comp_out);

int ccow_init_shmseg();
int ccow_add_proc(uint32_t if_speeds[], int if_count);
void ccow_pscan_timer_cb(uv_timer_t* handle, int status);
#define PSCAN_TIMER_TIMEOUT	250
#define PSCAN_TIMER_REPEAT	100
void client_getcommon_send_accept_rt(struct state *st);

void ccow_copy_inheritable_md_to_comp(struct vmmetadata *md_from,
    struct ccow_completion *comp_to);

void ccow_copy_inheritable_comp_to_md(struct ccow_completion *comp_from,
    struct vmmetadata *md_to);

void ccow_copy_inheritable_tc_to_comp(struct ccow *tc_from,
    struct ccow_completion *comp_to);

void ccow_copy_inheritable_md_to_tc(struct vmmetadata *md_from,
    struct ccow *tc_to);

int ccow_ec_timeout_expired(const struct vmmetadata *md);

/**
 * Skip special tenants check
 *
 * @param tid tenant name
 * @param tid_size tenant name size
 * @returns 1 should skip
 */
int accounting_tid_skip(char *tid, size_t tid_size);

int ccow_cmpack(struct ccow_io *io, rtbuf_t *rl);
int ccow_vmpack(struct ccow_io *put_io, rtbuf_t *rl_root);

/**
 * Add md overrides to vm payload
 *
 * @param comp operation with specific override parameters
 * @param payload vm payload
 * @returns updated payload on success, NULL on failure
 *
 */
rtbuf_t *
ccow_add_md_overrides_to_payload(ccow_completion_t comp, rtbuf_t *payload);


/**
 * Edit single VM md override entry or create one.
 *
 * @param src_vm    the source vm blob
 * @param key       a key to edit/set
 * @param new_value a value to be set instead of the old one
 * @param tgt_vm    output vm with new overrides
 * @returns         0 on success, error code otherwise
 */
int
ccow_edit_md_overrides(rtbuf_t* src_vm, char *key, uint64_t new_value,
	rtbuf_t** tgt_vm);

static inline int
ccow_completion_keep_selected(struct ccow_completion* c, struct vdev_sel* sel) {
	assert(c);
	assert(sel);
	c->usel = sel;
	return 0;
}

/**
 * Lookup for a manifest/payload chunks.
 *
 * @param c          is a completion for this context
 * @param chid       is a hashID of a chunk to look for
 * @param ngchid     is hashID for a negotiation group the chunk resides in.
 *                   Use @param chid for CM or payload or a name hashID for VM
 * @param hash_type  chunk hash type
 * @param attr       attribute to be used in a GET request:
 *                   RD_ATTR_CHUNK_PAYLOAD, RD_ATTR_CHUNK_MANIFEST,
 *                   RD_ATTR_VERSION_MANIFEST
 * @param repCnt     maximum number of chunk replicas to wait for.
 *                   Use 0 to wait for all.
 *
 * @returns 0 on success, an error code otherwise.
 */

int
ccow_chunk_lookup(ccow_completion_t c, const uint512_t* chid, const uint512_t* ngchid,
	int hash_type, uint64_t attr, int repCnt);


void
tc_marshal_call(struct state* tgt_st, ccow_t tgt_tc, int event);

void
ccow_assign_this_guid(ccow_t tc, char *system_guid, size_t system_guid_size);

#ifdef	__cplusplus
}
#endif

#endif
