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
#ifndef __REPTRANS_H__
#define __REPTRANS_H__

#include "queue.h"
#include "ccowutil.h"
#include "json.h"
#include "crypto.h"
#include "auditc.h"
#include "replicast.h"
#include "rtbuf.h"
#include "flexhash.h"
#include "ccow.h"
#include "vmm_cache.h"
#include <sys/time.h>
#include <sys/sysinfo.h>
#include "reptrans-data.h"
#include "reptrans-device.h"
#include "trlog.h"
#include "ccowtp.h"
#include "sop_list.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Maximum number of vdevs managed by one server node. Note that
 * vdev theoretically can be preresented with 2+ devices, e.g. ZFS mirror
 * or RAID-Z* or EJBOD aggregator.
 *
 * FIXME: make it configurable
 */
#define REPTRANS_MAX_VDEVS	2048

#define REPTRANS_MAX_DEVNAME	128
#define VERIFY_NO_DELAYS	1
#define REPTRANS_VDEV_THREAD_POOL_MIN 48
#define REPTRANS_VDEV_THREAD_POOL_SIZE	(get_nprocs() > REPTRANS_VDEV_THREAD_POOL_MIN ? \
	get_nprocs() : REPTRANS_VDEV_THREAD_POOL_MIN)
#define REPTRANS_TP_PRIO_HI	0
#define REPTRANS_TP_PRIO_MID	1
#define REPTRANS_TP_PRIO_LOW	2
#define REPDEV_TC_TP_MAX_SZ	256
#define REPDEV_TC_TP_MIN_SZ	32
#define REPDEV_TC_TP_DEFAULT_SZ	(get_nprocs() > REPDEV_TC_TP_MIN_SZ ? \
	get_nprocs() : REPDEV_TC_TP_MIN_SZ)
#define NGCOUNT_OPS_LIMIT	100 /* Maximum number of ngcount requests per second */


typedef enum {
	RT_KEY_FORMAT_MSGPACK = 0, /* reptrans keys are packed/unpacked by means of a dedicated compare function */
	RT_KEY_FORMAT_LINEAR = 1, /* reptrans keys must be formed in a way compatible with memcmp-base comparator */
} key_format_t;

struct reptrans;
struct repdev;
struct reptrans_lock;

/* enum() callbacks */
typedef void (*reptrans_done_cb_t)(struct repdev *dev, void *arg, int status);
typedef int  (*reptrans_enum_cb_t)(struct repdev *dev, void *arg);

struct reptrans_call {
	QUEUE item;
	struct repdev *dev;
	void *arg;
	int status;
	reptrans_done_cb_t method;
};

/*
 * RTLFS driver will use 0, 16 and 24 bits offests of .u.u.u word
 */
#define NG_TO_KEY(ng) (((ng) & 0xFFFF) | (((ng) & 0xFF) << 16) | (((ng) & 0xFF) << 24))

#define COMPACTIFY_STATUS_FILE	"%s/var/run/compaction-status.json"

struct mcjoin_queue_entry {
	QUEUE item;
	char mcgrp[INET6_ADDRSTRLEN];
	uint32_t if_index;
	uint64_t timestamp;
};

#define BG_PREEMPTION_TIME			60000
#define	DEV_PERFMON_TIMER_MS			5000
#define	DEV_PERFMON_START_TIMER_MS		5000
#define	DEV_BACKREF_VERIFY_TIMER_MS		(60 * 1000)
#define	DEV_BACKREF_VERIFY_START_TIMER_MS	(60 * 1000)
#define	DEV_INCOMING_BATCH_TIMER_MS		(120 * 1000)
#define	DEV_INCOMING_BATCH_START_TIMER_MS	(120 * 1000)
#define	DEV_SPACE_RECLAIM_TIMER_MS		(30 * 60 * 1000)
#define	DEV_SPACE_RECLAIM_START_TIMER_MS	(30 * 60 * 1000)
#define DEV_REPLICATION_START_TIMER_MS		(15 * 60 * 1000)
#define DEV_REPLICATION_TIMER_MS		(15 * 60 * 1000)
#define DEV_GC_START_TIMER_MS			(2 * 3600 * 1000)
#define DEV_GC_TIMER_MS				(2 * 3600 * 1000)
#define DEV_SCRUB_START_TIMER_MS		(24 * 3600 * 1000)
#define DEV_SCRUB_TIMER_MS			(24 * 3600 * 1000)
#define DEV_EC_ENCODER_START_TIMER_MS		(15 * 1000)
#define DEV_EC_ENCODER_TIMER_MS			(15 * 1000)
#define DEV_TRLOG_START_TIMER_MS		(15 * 1000)
#define DEV_GW_CACHE_START_TIMER_MS		(1 * 3600 * 1000)
#define DEV_GW_CACHE_TIMER_MS			(1 * 3600 * 1000)
#define DEV_GW_CACHE_HW_MARK			80
#define DEV_GW_CACHE_LW_MARK			30
#define DEV_GW_CACHE_CHIDS_IN_MEM		1000000
#define GW_CACHE_EXCLUSIVE			1
#define MAX_REPTRANS_RECV_EVENT_RETRY		12
#define DEV_NUM_LOCKS_DEFAULT			256
#define DEV_UTILIZATION_THRESHOLD_LOW		0.01
#define DEV_UTILIZATION_THRESHOLD_HIGH		0.75
#define SPECULATIVE_BACKREF_TIMEOUT		(24 * 3600 * 1000000L)
#define VERSION_QUARANTINE_TIMEOUT		(600 * 1000000L)
#define DELETE_QUARANTINE_TIMEOUT		(24 * 3600 * 1000000L)
#define INCOMING_BATCH_PRIORITY			4
#define VERIFY_PRIORITY				3
#define SPACE_RECLAIM_PRIORITY			1
#define REPLICATION_PRIORITY			2
#define GC_PRIORITY				1
#define EC_ENCODER_PRIORITY			2
#define SCRUB_PRIORITY				1
#define VERIFY_EXCLUSIVE			1
#define INCOMING_BATCH_EXCLUSIVE		1
#define SPACE_RECLAIM_EXCLUSIVE			1
#define REPLICATION_EXCLUSIVE			0
#define GC_EXCLUSIVE				0
#define EC_ENCODER_EXCLUSIVE			0
#define SCRUB_EXCLUSIVE				1
#define COMPACTIFY_ON_BOOT			0
#define TIMESTAMP_TIMER_MS			10000
#define EC_DEFAULT_CODEC			1 /* XOR */
#define EC_DEFAULT_WIDTH			3
#define EC_DEFAULT_NPARITY			1  /* Note: XOR supports only N:1 coding scheme */
#define EC_DEFAULT_STATE			0 /* Disabled */
#define FLUSH_TIMEOUT_THRESHOLD		(5e9)
#define CHIDS_HASHTABLE_SIZE		1024
#define CLUSTER_HEALTHY_INTERVAL	(60*1000)
#define PARITY_MANIFEST_LAG_TIME	(1800*1000)
#define EC_BG_MAX			2
#define DEV_ROWUSAGE_START_TIMER_MS		(1 * 3600 * 1000)
#define DEV_ROWUSAGE_TIMER_MS			(1 * 3600 * 1000)
#define DEV_ROWUSAGE_EXCLUSIVE			1
#define DEV_TP_LOW_WEIGHT			30
#define DEV_TP_LOW_RESERVED			50
#define DEV_TP_LOW_RESILIENCY			500
#define DEV_TP_MID_WEIGHT			30
#define DEV_TP_MID_RESERVED			25
#define DEV_TP_MID_RESILIENCY			1000
#define DEV_TP_HI_WEIGHT			40
#define DEV_TP_HI_RESERVED			25
#define DEV_TP_HI_RESILIENCY			5000
#define DEV_DETACH_TIMEOUT			(10UL*60UL*1000UL*1000UL)
#define DEV_MDONLY_TOUCH_TABLE_SIZE		(16UL*1024UL*1024UL)
#define DEV_MDONLY_TOUCH_TABLE_SIZE_EMBEDDED	(2UL*1024UL*1024UL)
#define DEV_ELRU_HIT_COUNTER			2
#define DEV_ELRU_TOUCH_RATIO			1 /* 0.1% */

/*
 * control flags for reptrans_flush()
 */

#define RD_FLUSH_TIMEOUT (1 << 0)
#define RD_FLUSH_FORCE	(1 << 1)
#define RD_FLUSH_BATCH_QUEUE (1 << 2)
#define RD_FLUSH_SYNC (1 << 3)

/* Replication BG control flags */
#define REPLICATE_OPTIONAL_VBR     (1<<0) /* Replicate chunks even if there is no VBRs */
#define REPLICATE_EC_VBR           (1<<1) /* Replicate VBRs that protect EC chunks*/
#define REPLICATE_CHECK_PARENT     (1<<2) /* Don't replicate chunks without parent */
#define REPLICATE_NO_VBR_OWERWRITE (1<<3) /* Don't overwrite VBRs if there any with other RC (much faster) */

#define COMPOUND_FLAG_SKIP_EC_VBRS	(1<<0) /* Don't replicate EC VBRs */
#define COMPOUND_FLAG_NEED_VERSION	(1<<1) /* Server has to create a version entry based on VM */
#define COMPOUND_FLAG_PRIMARY_PUT	(1<<2) /* This compound has a primary chunk */
#define COMPOUND_FLAG_OVERRIDE_SELECTED (1<<3) /* Keep putting secondary compounds even if primary chunk has enough replicas */
#define COMPOUND_FLAG_KEEP_ALL_VBRS	(1<<4) /* Don't delete existing VBRs */
#define COMPOUND_FLAG_REQUEST_EC	(1<<5) /* For manifests only: create an encoding entry in the queue */

#define COMPOUND_HDR_RESERVED	1024
#define COMPOUND_HDR_SIZE	128
#define COMPOUND_MAX_CHUNKS	5*1024
#define COMPOUND_SIZE_MAX	(REPLICAST_CHUNK_SIZE_MAX-COMPOUND_HDR_SIZE) /* TODO: figure out why 8Mb+65536 bytes doesn't work */

struct repdev_bg_config {
	int64_t backref_verify_timer_ms;
	int64_t backref_verify_start_ms;
	uint8_t verify_priority;
	uint8_t verify_exlusive;
	int64_t incoming_batch_timer_ms;
	int64_t incoming_batch_start_ms;
	uint8_t incoming_batch_priority;
	uint8_t incoming_batch_exclusive;
	int64_t space_reclaim_timer_ms;
	int64_t space_reclaim_start_ms;
	uint8_t space_reclaim_priority;
	uint8_t space_reclaim_exclusive;
	int64_t replication_timer_ms;
	int64_t replication_start_ms;
	uint8_t replication_exclusive;
	uint8_t replication_priority;
	int64_t gc_timer_ms;
	int64_t gc_start_ms;
	uint8_t gc_priority;
	uint8_t gc_exclusive;
	int64_t scrub_timer_ms;
	int64_t scrub_start_ms;
	uint8_t scrub_priority;
	uint8_t scrub_exclusive;
	uint64_t ec_encoder_timer_ms;
	uint64_t ec_encoder_start_ms;
	uint8_t ec_encoder_priority;
	uint8_t ec_encoder_exclusive;
	uint64_t trlog_start_ms;
	uint64_t trlog_delete_after_hours;
	uint8_t trlog_priority;
	uint8_t trlog_exclusive;
	uint64_t gw_cache_start_ms;
	uint64_t gw_cache_timer_ms;
	uint8_t gw_cache_priority;
	uint8_t gw_cache_exclusive;
	int64_t speculative_backref_timeout_min;
	int64_t speculative_backref_timeout;
	int64_t version_quarantine_timeout;
	volatile uint8_t long_verification;
	double dev_utilization_threshold_low;
	double dev_utilization_threshold_high;
	double dev_capacity_limit;
	double dev_capacity_max_data;
	double dev_capacity_max_full;
	char scrubber_log_name[64];
	uint8_t	compact_on_boot;
	uint64_t flush_threshold_timeout; // to prevent flush avalanche
	uint8_t tenant_pool_sz;
	uint8_t gw_cache_hw_mark;	/* High water mark (percentage) for GW cache */
	uint8_t gw_cache_lw_mark;	/* High water mark (percentage) for GW cache */
	uint64_t gw_cache_chids_in_mem; /* Number of CHIDS tracked by RAM */
	uint64_t rowusage_start_ms;
	uint64_t rowusage_timer_ms;
	uint8_t rowusage_exclusive;
	uint32_t thread_pool_size;
	uint32_t tenant_thread_pool_size;
	uint32_t tp_low_weight;
	uint32_t tp_low_reserved;
	uint32_t tp_low_resiliency;
	uint32_t tp_mid_weight;
	uint32_t tp_mid_reserved;
	uint32_t tp_mid_resiliency;
	uint32_t tp_hi_weight;
	uint32_t tp_hi_reserved;
	uint32_t tp_hi_resiliency;
	uint32_t elru_touch_ratio; /* %*10 of speculative_backref_timeout_min */
	uint32_t elru_hits_count; /* Number of chunk hits prior first touch */
};

#define REPDEV_CAPACITY_LIMIT			0.87
#define REPDEV_CAPACITY_MAX_DATA		0.90
#define REPDEV_CAPACITY_MAX_FULL		0.98

#define VERIFY_MAX_DELAY_US			50000
#define NGCOUNT_MAX_DELAY_US			50000
#define DEV_DEAD_THRESHOLD_FACTOR		30
#define DEV_PREFETCH_SIZE			0

#define DEV_AVGLAT4K_MIN			10
#define DEV_AVGLAT64K_MIN			25
#define DEV_AVGLAT512K_MIN			50
#define DEV_AVGLAT4K_MAX			12000
#define DEV_AVGLAT64K_MAX			32000
#define DEV_AVGLAT512K_MAX			64000

#define DEV_LOOP_DELAY_FACTOR			25
#define DEV_RECOVER_INPROG_MAX			2

#define DEV_MAX_SOPS				32	/* Max parallel serial ops */
#define DEV_SOPS_QDEPTH				10000   /* Max serial ops queue length */
#define DEV_SOPS_BATCH				256     /* Serial ops batch length */
#define DEV_MAX_WAIT_LOCKS			256	/* Max waiting locks */


struct ngrequest_perf_limiter
{
	uint64_t io_rate_max; /* Maximum allowed performance, IOPs */
	uint64_t interval; /* Throttling interval, uS */
	uint64_t ts_begin; /* Timestamp of an interval start */
	uint64_t ops; /* Number of operations executed sine interval start */
	uv_mutex_t lock;
};

void
reptrans_perf_limiter_create(struct ngrequest_perf_limiter* pb, uint64_t rate_iops,
	uint64_t interval_us);

size_t
reptrans_perf_limiter_update(struct ngrequest_perf_limiter* pb);

void
reptrans_perf_set_iops_max(struct ngrequest_perf_limiter* pb,
	uint64_t rate_iops);

struct touch_queue_entry {
	type_tag_t ttag;
	crypto_hash_t hash_type;
	uint512_t chid;
};

struct touch_table_entry {
	uint512_t chid;
	uint64_t ts; /* Last touch timestamp */
	uint16_t hits; /* Number of hits the chunk got */
	UT_hash_handle hh;
};


#define REPDEV_TOUCH_QUEUE_SIZE (16UL*1024*1024)
#define REPDEV_TOUCH_QUEUE_SIZE_EMBEDDED (2UL*1024*1024)

struct repdev {
	QUEUE item;
	QUEUE rtfree_timer_queue;
	QUEUE reqfree_queue;		/* queue with requests to be cleaned up */
	uv_thread_t thread_id;
	uv_loop_t *loop;
	unsigned long loop_thrid;	/* device loop thread id */
	struct reptrans *rt;
	struct replicast *robj;
	struct reptrans_lock* robj_lock;	/* lock for replicast object */
	uint16_t listen_port;
	volatile int terminating;	/* terminating dev thread */
	struct repdev_bg_config* bg_config; /* repdev configuration */
	struct bg_sched*	bg_sched;
	volatile repdev_status_t status;		/* device state */
	volatile repdev_status_t prev_status;	/* device previous state */
	volatile int status_changed;		/* State changed flag */
	volatile uint64_t status_changed_expires;	/* State changed expiration */
	volatile uint32_t flushing;	/* device is flushing ttag mask */
	volatile uint64_t flushing_part;/* device is flushing part mask */
	hashtable_t *vmm_ht;		/* per-device VMM hash table */

	/* I/O path detection states - process will exit if we stuck! */
#define DEV_READ_LAST_FAIL_MAX_NS	(120 * 1000 * 1000 * 1000ULL)
#define DEV_WRITE_LAST_FAIL_MAX_NS	(300 * 1000 * 1000 * 1000ULL)
	uint64_t read_inprog;
	uint64_t read_last;
	uint64_t write_inprog;
	uint64_t write_last;

	uv_async_t exit_handle;		/* exit handler */
	uv_async_t call_async;		/* trigger reptrans call */
	uv_mutex_t call_mutex;		/* to protect reptrans call arguments */
	QUEUE call_queue;		/* incoming queue of reptrans calls */
					/* Parallel serial op queues */
	sop_list_ht *sop_queues;
	uv_mutex_t	sop_list_mutex;
	uv_mutex_t	lk_mutex;	/* to protect lock_q */
	int32_t		lk_wait_nr;	/* Number of locks blocked/waiting */
	QUEUE		lock_q;		/* waiting queue of blocked locks */

	char *name;			/* Device name */
	char *path;			/* Device root path */
	char *journal;			/* Device journal name to use */
	int wal_disabled;		/* Device will not create WAL at all */
	int bcache;			/* Device will enable use of bcache */
	uint32_t journal_maxchunksize;	/* Device journal's maxchunksize */
	uint32_t journal_maxentries;	/* Device journal's maxentries */
	char *metadata;			/* Device metadata name to use */
	int metadata_mask;		/* Extra metadata TTs to use */
	uint128_t vdevid;		/* 16-byte formatted VDEV GUID */
	uint32_t payload_put_min_kb;	/* If set, driver requests min vdev put of size in kb */

	/*
	 * Metafile info
	 */
	int created_timestamp;		/* When VDEV was created */
	void *device_lfs;		/* Device specific lfs */
	int plevel;			/* LFS specific - # of parts */

	/*
	 * Cached stats
	 */
	struct reptrans_devinfo_req stats;

	/*
	 * Done callback:
	 *	triggered by uv_async_send from device thread,
	 *	but executed in transport main thread if not NULL
	 */
	reptrans_done_cb_t done_cb;
	uv_mutex_t done_cb_mutex;	/* to protect done callback */

	/*
	 * Virtual table
	 */
	struct repdev_vtbl *__vtbl;

	/*
	 * File descriptor and uv_poll_t used for subscriptions
	 */
	int sub_fd;
	uv_poll_t sub_req;

	/*
	 * timer for enum stat
	 */
	uv_timer_t	vdevstats_timer;

	/* Heartbeat counter */
	unsigned long	hb;

	/*
	 * perfmon work in progress flag
	 */
	int		perfmon_wip;
	/*
	 * compactify worker handler and in-progress flag
	 */
	int		comp_wip;

	/*
	 * Verify chid in put/get
	 */
	int verify_chid;

	/*
	 * FIR samples
	 */
	uint64_t verify_delay_avg;
	struct avg_ring verify_avg_samples;

	uint64_t num_ios_avg;
	struct avg_ring io_avg_samples;

	uint64_t incoming_batch_delay_avg;
	struct avg_ring incoming_batch_avg_samples;

	uint64_t ngcount_delay_avg;
	struct avg_ring ngcount_avg_samples;
	uint64_t ngcount_delay;

	struct avg_ring put4k_avg_samples;
	struct avg_ring put64k_avg_samples;
	struct avg_ring put512k_avg_samples;
	struct avg_ring put4k_avg_samples_j;
	struct avg_ring put64k_avg_samples_j;
	struct avg_ring put512k_avg_samples_j;
	struct avg_ring get4k_req_avg_samples;
	struct avg_ring get64k_req_avg_samples;
	struct avg_ring get512k_req_avg_samples;
	struct avg_ring get4k_req_avg_samples_m;
	struct avg_ring get64k_req_avg_samples_m;
	struct avg_ring get512k_req_avg_samples_m;
	struct avg_ring get4k_avg_samples;
	struct avg_ring get64k_avg_samples;
	struct avg_ring get512k_avg_samples;
	struct avg_ring get4k_avg_samples_m;
	struct avg_ring get64k_avg_samples_m;
	struct avg_ring get512k_avg_samples_m;
	struct avg_ring delete_avg_samples;

	/*
	 * Is this device a GW cache?
	 */
	uint8_t gw_cache;

	/* keep track of the get/put count
	 * of the current IO to account for the current depth
	 * for the disk portion
	 */
	uint64_t get_disk_qdepth;
	uint64_t put_disk_qdepth;

	/* keep count of the get/put of the current I/O
	 * for the network portion
	*/
	uint64_t get_net_tx;
	uint64_t put_net_rx;
	/* Stored storage's timestamp */
	uint64_t timestamp;
	uint64_t sync_timestamp;
	uv_work_t *ts_work;
	int reptrans_ts_sync_inprog;

	int joined_rows[FH_MAX_JOINED_ROWS];
	QUEUE mcjoin_queue;
	uint32_t mcjoin_size;
	int trlog_bucket_ready;

	/* Hashtable for locks */
	hashtable_t *lock_tbl;

	uint8_t bloom_enabled;
	uint8_t keycache_enabled;
	/* cached payload for payload_rcvd acks */
	hashtable_t *rcvd_cache;
	uint32_t keycache_size_max;
	/* hash count flushing flag */
	int hc_flush;
	/* Limit number of simultaneous recoveries */
	uv_sem_t recover_sem;
	uv_mutex_t hc_mutex;	/* to protect hc put work */
	uint8_t bq_cleaned; /* batch queue first run flag */
	uint8_t ibq_cleaned; /* incoming batch queue first run flag */
	uint8_t	bg_prioriry_inverted;

	 /* this list is based on incoming messages for background */
	rowusage_xfer_t rowusage_list;
	uint8_t	evac_inprog;
	uint8_t	evac_cancel;

	/* keep track of statistics here */
	uint64_t	stat_blob_put[TT_LAST+1];
	uint64_t	stat_blob_get[TT_LAST+1];
	/* Stable version hashtable and locks */
	hashtable_t *stab_versions_map;
	uv_rwlock_t stab_versions_lock;
	struct ccowtp* tp; /* Thread pool */
	uv_rwlock_t term_lock;
	struct ngrequest_perf_limiter ngcount_limiter;
	uv_timer_t ts_store_timer;

	int64_t verify_batch_delay;
	int64_t verify_queue_delay;

	/* Touch queue for MDOnly option */
	struct touch_queue_entry* tchqs; /* Array of pre-allocated touch queue entries */
	lfqueue_t tchq_free; /* A queue of free touch queue entries */
	lfqueue_t tchq_inprog; /* A queue of in-progress touch queue entries */
	struct touch_table_entry* ttable; /* A table to be used as a cache of recently touched chunks */
	uint64_t tchd_work_ts;
	uint64_t tchd_work_inprog; /* The work-in-progress */
};

#define STABLE_VERSION_FLAG	2

int
reptrans_stable_version_init(struct repdev* dev);

void
reptrans_stable_version_destroy(struct repdev* dev);

int
reptrans_stable_version_set(struct repdev* dev, const uint512_t* nhid,
	uint64_t gen, uint64_t ts);

int
reptrans_stable_version_get(struct repdev* dev, uint512_t* nhid,
	uint64_t* gen, uint64_t* ts);

int
reptrans_stable_version_delete(struct repdev* dev, const uint512_t* nhid);

#define REPDEV_MAX_POOL_SZ	32
#define REPDEV_DEFAULT_POOL_SZ	8

/* Simulation run, no disk IOs */
#define RD_ERASE_FLAG_NOIO		(1<<0)

/* Format WAL(s) only. Doesn't affect main partitions or mdoffload */
#define RD_ERASE_FLAG_WAL_ONLY		(1<<1)

/* Restore metaloc record to available status, do NOT zap */
#define RD_ERASE_FLAG_RESTORE_ML	(1<<2)

/*
 * For capacity mode only. Disk format destroy HDD's partition table.
 * it mustn't be used when a format is performed while ccow-daemon is running
 */
#define RD_REASE_FLAG_GPT_DESTROY	(1<<3)

typedef struct erase_opt {
	const char* name; /* VDEV name */
	const char* journal_group; /* journal group name */
	int plevel; /* plevel index */
	uint64_t flags; /* bitmask of special options */
} erase_opt_t;

typedef enum {
	/**
	 * Detach a VDEV from its key-value backend(s)
	 * Force device unavailable state and preserve it.
	 */
	vdevCtlDetach,
	/**
	 * Attach a VDEV to its key-value backend(s)
	 * Force device alive state, but DO NOT preserve it
	 */
	vdevCtlAttach,
	/**
	 * Flush caches
	 */
	vdevCtlFlush,
	/**
	 * Discover new devices
	 * Use cases:
	 * - replace a detached/faulted device
	 * - probe new devices added to a transport configuration on-the-fly
	 */
	vdevCtlDiscover
} eVdevCtl;

struct vdevCtlDiscoverArg {
	const char* name;
	json_value* cfg;
};

struct reptrans {
	QUEUE item;

	/*
	 * List of attached VDEVs
	 */
	QUEUE devices;
	uint32_t ndevs;
	uv_rwlock_t devlock;
	struct repdev_bg_config dev_bg_config; /* shared configuration */

	Logger scrub_lg;	/* Scrub error reporting log */

	/*
	 * Transport name
	 */
	char *name;

	/*
	 * Device async call
	 */
	uv_async_t call_async;		/* trigger device call */
	uv_mutex_t call_mutex;		/* to protect device call arguments */
	QUEUE call_queue;		/* incoming queue of device calls */

	uv_mutex_t	comp_mutex; /* compactify mutex */
	uv_mutex_t  comp_stat_mutex; /* compactify status update mutex */
	struct compactify_status* comp_stat; /* compactification status storage */
	uint16_t	max_comp_entries;	/* max. number of compact. entries */
	uint16_t	comp_entries; /* current number of compact. entries */

	uv_mutex_t	trlog_mutex;	/* protects creation of trlog hierarhy */
	uv_mutex_t	tc_mutex;	/* tenant context mutex */
	volatile uint8_t tc_term; /* do not create context again when tc_term set */
	struct ccow	*tc_pool[REPDEV_MAX_POOL_SZ];	/* tenant context pool */
	uint32_t	tc_ref[REPDEV_MAX_POOL_SZ]; /* TC reference counter */
	uint8_t		tc_cursor;	/* Current tc, from pool, being used */
	uint8_t		tc_pool_sz;	/* tenant context pool size */

	/* When set, the devices are allowed to create storage*/
#define RT_FLAG_CREATE		(1<<0)
	/* When set, only READ operations are allowed */
#define RT_FLAG_RDONLY		(1<<1)
	/* When set, ccowd-free init mode is expected */
#define RT_FLAG_STANDALONE	(1<<2)
	/* Used by rdhold utility to minimize memory allocations */
#define RT_FLAG_RDHOLD		(1<<3)
	/* Used by FIO engine */
#define RT_FLAG_ALLOW_OVERWRITE	(1<<4)
	/* Check current driver version and converts data if required */
#define RT_FLAG_VERSION_CHECK	(1<<5)
	uint32_t	flags;		/* reptrans flags */
	void *handle;	/* dlopen handle */

	uint64_t ts_offset; /* timestamp offset compensation */
	int ts_suspended; /* reptrans clock suspended flag */
	uv_mutex_t ts_mutex; /* reptrans clock access mutext */

	uv_mutex_t recovery_queue_mutex; /* to protect recovery queue */
	QUEUE recovery_queue; /* queue of manifests being recovered */

	hashtable_t * chids_ht; /* Table holds chids of object
				   parity/verification status was request
				   for recently */
	uv_mutex_t  opps_lock;

	int fd_delta_prev; /* Previous FD delta value */
	uv_rwlock_t cl_healthy_lock;/* Synchronize access to cluster healthy vars */
	uint64_t fd_delta_valid_time; /* number of FD delta steady states*/
	volatile int terminating;
	uint64_t  active_ec_bg;
	unsigned long  active_ec_bg_limit;
	struct ccowtp_wh* tc_wh;

	void* init_traits;

	/**
	 * Probe transport driver. Create repdevs's related structures
	 * regardless of theirs internal state. Do not open.
	 *
	 * @param opts JSON encoded configuration
	 * @returns on success, this function returns >= 0, on error,
	 * returns -1
	 *
	 */
	int (*probe)(struct _json_value *opts, struct reptrans *rt);

	/**
	 * Open a discovered repdev.
	 *
	 * @param dev is a pointer to repdev taken from the rt::devices queue.
	 * @returns 0 on success, an error code otherwise
	 */
	int (*dev_open)(struct repdev *dev);

	/**
	 * Control device's internal state
	 * @param op  operation code. Each must implement ones from enum eVdevCtl,
	 *            other codes are specific to reptrans implementation
	 * @param arg is a pointer to data structure related to the operation
	 * @returns 0 on success or error code otherwise
	 */
	int (*dev_ctl)(struct repdev *dev, int op, void* arg);

	/**
	 * Close a VDEV.
	 *
	 * It usually detaches a device from its key-value drivers,
	 * but keeps the VDEV-related data structure alive.
	 */
	int (*dev_close)(struct repdev *dev);

	/**
	 * Destroy previously initialized VDEV
	 *
	 * The VDEV has to be closed already.
	 */
	void (*dev_free)(struct repdev *dev);

	/**
	 * Deinitialize transport driver and all active VDEVs
	 */
	int (*destroy)();

	/**
	 * Enumerate transport VDEV's
	 *
	 * For each VDEV of the transport, call cb.
	 * Cancel outstanding cb's after timeout ms if timeout > 0.
	 * Call done if not NULL for each device on completion of cb or
	 * on timeout.
	 *
	 * @param cb callback to call for VDEV
	 * @param arg (optional) argument to pass into cb
	 * @param done (optional) completion callback
	 * @param timeout (optional) number of ms before timeout
	 * @returns 0 on success, -1 on timeout
	 *
	 */
	int (*dev_enum)(struct reptrans *rt, reptrans_enum_cb_t cb, void *arg,
	    reptrans_done_cb_t done, uint64_t timeout);


	int (*erase)(struct reptrans *rt, struct _json_value *cfg, const erase_opt_t* opts);

};

typedef struct evac_link {
	int sock_in;
	lfqueue_t msg_lfq;
} evac_link_t;

enum evac_opcode {
	EM_ERROR,
	EM_SUMMARY_REQ,
	EM_SUMMARY_REP,
	EM_ROW_STATUS_REQ,
	EM_ROW_STATUS_REP,
	EM_JOB_STATUS_REQ,
	EM_JOB_STATUS_REP,
	EM_JOB_CANCEL_REQ,
	EM_JOB_CANCEL_REP,
	EM_MOVE_REQ,
	EM_MOVE_REP,
	EM_TEST_MEDIAN_CANDIDATES_REQ,
	EM_TEST_MEDIAN_CANDIDATES_REP,
	EM_END
};

typedef struct evac_msg_hdr {
#define EM_PROTO_VER	1
	uint16_t		em_proto_ver;
	enum evac_opcode	em_op;
	uint128_t		em_src_devid;
	int			em_src_row;
	uint128_t		em_dest_devid;
	int			em_dest_row;
	unsigned long		em_job_id;
} evac_msg_hdr_t;

#define REQ_CLASS_FIELDS	\
	struct state state;	\
	struct repctx *ctx;	\
	struct repdev *dev;	\
	QUEUE reqfree_item;	\
	uint64_t reqfree_ts;	\
	int inexec;

struct repreq_common {
	REQ_CLASS_FIELDS
};

extern QUEUE all_rts;

#define reptrans_register(rt) \
	static void __attribute__((constructor)) regist_ ## rt(void) { \
		if (!rt.init) \
			panic("the rt '%s' is incomplete\n", rt.name); \
		QUEUE_INIT(&rt.item); \
		QUEUE_INSERT_TAIL(&all_rts, &rt.item); \
	}

struct cl_node;
struct cl_vdev;

int reptrans_init(uint64_t timeout, struct cl_node *this_node,
	const struct repdev_bg_config* cfg, uint32_t flags,
	int transport_count, char *transport_name[], void* params);
int reptrans_init_common(uint64_t timeout, struct cl_node *this_node,
	uint32_t flags, const struct repdev_bg_config* cfg, void* rt_params);

int reptrans_flush(uint32_t flags);
int reptrans_robj_mcproxy(struct replicast *robj, uint16_t fhrow,
    const uv_buf_t buf, ssize_t nread, char *sender);
void reptrans_compactify();

int reptrans_gw_cache_gc(void);

int reptrans_destroy(void);
int reptrans_enum(reptrans_enum_cb_t cb, void *arg,
    reptrans_done_cb_t done, uint64_t timeout);
int reptrans_enum_stat(reptrans_devinfo_req_type_t req,
    reptrans_stat_cb_t stats_cb, uint64_t timeout);

struct reptrans *reptrans_find(const char *name);
int reptrans_get_vdevs(uint128_t **vdevs, size_t *nr_vdevs);
int reptrans_enum_stat_helper(struct repdev *dev, void *arg);

int reptrans_hashcount_init(struct reptrans_hashcount *hc, int n_dev);
void reptrans_hashcount_destroy(struct reptrans_hashcount *hc);

uint64_t reptrans_normalized_latency(uint64_t delta, size_t size,
    size_t factor);

int reptrans_put_blob(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid, int compute);
int reptrans_put_blob_with_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid, int compute,
    uint64_t attr);
int reptrans_put_blob_with_attr_opts(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid, int compute,
    uint64_t attr, uint64_t options);
int reptrans_put_blob_nohc(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid, int compute);
int reptrans_put_blob_with_attr_nohc(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid, int compute,
    uint64_t attr);
int reptrans_touch_blob(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid);
int reptrans_get_blob(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, rtbuf_t **rb);
int reptrans_get_blob_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uint64_t *attr);
int reptrans_get_blob_ts(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uint64_t *ts);
int reptrans_set_blob_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uint64_t attr);
int reptrans_set_blob_ts(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uint64_t ts);
int reptrans_get_blob_verify(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, rtbuf_t **rb);
int reptrans_get_blobs(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, rtbuf_t **rb,
	int max_num, reptrans_blob_filter filter_cb, void *arg);

int reptrans_delete_blob(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid);

int
reptrans_delete_blob_value(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, uv_buf_t *val,
	size_t len);

int reptrans_list_blob_chids(struct repdev *dev, type_tag_t ttag,
    uint64_t ng, uint64_t mask, int max, uint512_t *chids);
int reptrans_blob_stat(struct repdev *dev, type_tag_t ttag,
        crypto_hash_t hash_type, const uint512_t *key, struct blob_stat *stat);
int reptrans_blob_query(struct repdev *dev, type_tag_t ttag,
        crypto_hash_t hash_type, const uint512_t *key, uint64_t *outsize);
int reptrans_iterate_blobs(struct repdev *dev, type_tag_t ttag,
	reptrans_blob_callback callback, void *param, int want_values);
int
reptrans_iterate_blobs_strict_order(struct repdev *dev, type_tag_t ttag,
	reptrans_blob_callback callback, void *param, int want_values);
int
reptrans_iterate_blobs_strict_order_limited(struct repdev *dev, type_tag_t ttag,
	reptrans_blob_callback callback, void *param, int want_values, int max_blobs);

int reptrans_delete_index(struct repdev *dev, crypto_hash_t hash_type,
	uint512_t *key);
int  reptrans_number_of_versions(struct repdev *dev, crypto_hash_t hash_type,
	uint512_t *key);

void
reptrans_bump_hashcount(struct repdev *dev, const uint512_t *chid, size_t hc_cnt);

void
reptrans_drop_hashcount(struct repdev *dev, const uint512_t *chid, size_t hc_cnt);

void
reptrans_bump_rowusage(struct repdev *dev, const uint512_t *chid, size_t size);

void
reptrans_drop_rowusage(struct repdev *dev, const uint512_t *chid, size_t size);


void reptrans_request_space_reclaim(struct repdev *dev);
int reptans_request_space_reclaim__async(struct repdev* dev);

int enqueue_replication(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, const uint512_t *nhid,
	uint8_t rep_count);

int enqueue_replication__dpc(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, const uint512_t *nhid,
	uint8_t rep_count);

int
reptrans_replicate_chunk(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, uint64_t attr,
	const void *nhid_vdevid, uint8_t rep_count, int optional_vbrs);
/*
 * Context constructors
 */
int namedput_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state);
int unnamedput_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state);
int namedget_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state);
int unnamedget_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state);
int gwcachedget_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state);
int resget_srv_init(struct replicast *robj, struct repctx *ctx,
    struct state *state);

/*
 * Encodes ttag, hash_type, chid => typekey
 *
 * @param dev pointer to struct repdev
 * @param hash_type hash algorithm type to sign blob with
 * @param ttag type tag of the blob to be put
 * @param chid precalculated Content Hash ID of blob
 * @param packed_typekey msgpack packed typekey result
 * @returns 0 on success, negative error code on failure
 *
 * @internal
 *
 */
int reptrans_key_encode(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, msgpack_p **packed_typekey);

/*
 * Decodes buffer (typekey) into chid, verifies ttag and hash_type
 *
 * @param dev pointer to struct repdev
 * @param buffer msgpack packed typekey
 * @param buflen length of the buffer
 * @param ttag type tag of the blob
 * @param hash_type hash algorithm type blob was signed with
 * @param chid resultant chid
 * @returns 0 on success, negative error code on failure
 *
 * @internal
 *
 */
int
reptrans_key_decode(struct repdev *dev, const char *buffer, int buflen,
    type_tag_t *ttag, crypto_hash_t *hash_type, uint512_t *chid);

typedef int (*reptrans_notify_delete_entry)(struct repdev *dev,
	crypto_hash_t hash_type, void *entry);

/*
 * @internal
 */
int reptrans_put_version(struct repdev *dev, struct vmmetadata *md,
    uint512_t *vmchid, uint32_t vm_packed_length);

int reptrans_purge_versions(struct repdev *dev, const uint512_t *nhid,
	uint64_t from_version, uint64_t to_version,
	uint64_t version_uvid_timestamp, crypto_hash_t hash_type,
	int trlog_object);

/*
 * @internal
 */
int trlog_skip(struct repdev *dev, struct vmmetadata *md);

/*
 * @internal
 */
int reptrans_get_versions(struct repdev *dev, const uint512_t *nhid,
    struct vlentry *query, rtbuf_t **out);

/*
 * @internal
 */
int
reptrans_delete_version_entry(struct repdev *dev, crypto_hash_t hash_type,
    const uint512_t *chid, struct vlentry *ver);

/*
 * @internal
 */
int
reptrans_delete_version(struct repdev *dev, struct vmmetadata *md,
    uint512_t *vmchid, uint32_t vm_packed_length);

/*
 * @internal
 */
int
reptrans_put_backref(struct repdev *dev, const uint512_t *chid,
    crypto_hash_t hash_type, struct backref *sbr);

int
reptrans_del_backref(struct repdev *dev, const uint512_t *chid,
    crypto_hash_t hash_type, struct backref *br);

/*
 * @internal
 */
int
reptrans_vbr_stat(struct repdev* dev, crypto_hash_t hash_type,
	const uint512_t* chid, struct backref* vbr);
/*
 * @internal
 */
int
reptrans_check_speculative_hold(struct repdev *dev,
    crypto_hash_t hash_type, type_tag_t ttag, const uint512_t *chid);

/*
 * @internal
 */
int
reptrans_delete_verified_backref(struct repdev *dev, crypto_hash_t hash_type,
    type_tag_t ttag, uint512_t *chid, struct backref *vbr);

/*
 * @internal
 */
int reptrans_get_verified_backrefs(struct repdev *dev, crypto_hash_t hash_type,
    const uint512_t *key, int *nrefs, struct backref **refs);

/*
 * @internal
 */
void reptrans_subscribe_events(struct repdev *dev);

/*
 * @internal
 */
void reptrans_unsubscribe_events(struct repdev *dev);

/*
 * @internal
 */
int reptrans_request_verification(struct repdev *dev,
    struct verification_request *req, uint512_t *vbr_key);

/*
 * @internal
 */
int reptrans_put_trlog(struct repdev *dev, struct vmmetadata *md,
    uint512_t *vmchid, uint64_t attrs, char *etag, char *content_type,
	uint64_t multipart_size, char *owner, char *srcip);

/*
 * @internal
 */
int
pingpong_init(struct replicast *robj, struct repctx *ctx, struct state *state);

/*
 * @internal
 */
int
ngrequest_init(struct replicast *robj, struct repctx *ctx, struct state *state);

/*
 * @internal
 */
int
ngrequest_count_init(struct replicast *robj, struct repctx *ctx, struct state *state);

/*
 * @internal
 */
int
ngrequest_purge_init(struct replicast *robj, struct repctx *ctx, struct state *state);

/*
 * @internal
 */
int
ngrequest_locate_init(struct replicast *robj, struct repctx *ctx, struct state *state);

/*
 * @internal
 */
int
recovery_request_init(struct replicast *robj, struct repctx *ctx, struct state *state);
/*
 * @internal
 */
int ngcount_chunks(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid, const uint512_t *nhid, int rep_count,
	uint128_t** vdevs, uint64_t generation, uint64_t* generation_max_out,
	int* stable_version);


typedef void (*ngrequest_send_cb_t)(void *, int);
/*
 * Send up to 64k message into the selected negotiating group
 *
 * @internal
 */
int
ngrequest_send(struct repdev *dev, uint16_t fhrow, char *message,
    uint32_t size, ngrequest_send_cb_t cb, void *cb_data);


int
ngrequest_send_targeted(struct repdev *dev, uint16_t fhrow, const uint128_t* tgt_vdev,
	char *message, uint32_t size, ngrequest_send_cb_t cb, void *cb_data);

int
reptrans_propagate_verification_request_targeted(struct repdev* dev,
	const uint128_t* tgt_vdev, struct verification_request* vreq);
/*
 * Query negotiating group for a blob and count positive answers
 *
 * @internal
 */
int
ngrequest_count(struct repdev *dev, uint8_t hash_type, const uint512_t *chid,
	const uint512_t *nhid, int32_t rep_count, type_tag_t ttype, uint64_t generation,
	int (*cb)(void *, int32_t, uint128_t *vdevs, uint64_t generation_max,
	int stable_version), void *cb_data);

/*
 * Request for max generation for given NHID
 *
 * @internal
 */
int
ngcount_generations(struct repdev *dev, const uint512_t *nhid,
    uint64_t *generation_max);

/*
 * Tell all devices in negotiation group to purge old versions
 *
 * @internal
 */
int
ngrequest_purge(struct repdev *dev, uint8_t hash_type, const uint512_t *nhid,
	uint64_t from_version, uint64_t to_version, uint64_t version_uvid_timestamp,
	uint8_t is_trlog_obj);

/*
 * Remove a manifest along with its parity manifest
 */
int
reptrans_delete_manifest(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid);

int
reptrans_delete_old_vbrs(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const struct backref* vbr, int* n_del);

int
reptrans_delete_vbrs_all_repcounts(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const struct backref* vbr, int* n_del);

int
reptrans_delete_vbrs_by_attr(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const struct backref* vbr, int* n_del);

int
reptrans_has_vbr(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const struct backref* vbr);

int
reptrans_has_ec_vbr(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const struct backref* vbr);
int
retrans_count_vbrs_all_repcount(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const uint512_t* ref_chid, uint64_t attr_mask,
	uint64_t* attr_value, int vbrs_max);

typedef int (*vbr_iterator_cb_t) (struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, uv_buf_t* vbr_buf, const struct backref* vbr,
	void* arg);

int
reptrans_vbrs_iterate(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, vbr_iterator_cb_t cb, void* arg);

int
reptrans_notify_delete_version(struct repdev *dev, crypto_hash_t hash_type,
	const uint512_t *nhid, void *entry);

/**
 * clengine_reptrans_notify() to be called every time a server
 * leave or join the cluster. It will be used to suspend
 * BG jobs ASAP.
 */
void
clengine_reptrans_notify(int leave_join, int nr_members);
/*
 * Get repdev's storage life time, uS
 * Only on-line time is considered
 */
uint64_t
reptrans_get_timestamp(struct repdev *dev);
/*
 * @internal
 */
#define MAX_BATCH_REQUESTS	256
typedef struct verify_work {
	struct repdev *dev;
	struct bg_job_entry* job;
	uint64_t  batches_sent;
	uint64_t verify_queue_items;
	uint64_t bytes_sent;
	uint64_t verify_entries;
	uint32_t n_verified;
} verify_work_t;

typedef struct space_reclaim_work {
	struct repdev *dev;
	struct bg_job_entry* job;
	uint64_t n_removed;
	uint64_t n_replicated;
	uint64_t n_erc;
} space_reclaim_work_t;

typedef struct replication_work {
	struct repdev *dev;
	struct bg_job_entry* job;
	uint64_t n_vers_purged;
	uint64_t n_garbage_chunks;
} replication_work_t;

typedef struct gc_work {
	struct repdev *dev;
	struct bg_job_entry* job;
	uint64_t n_vers_purged;
	uint64_t n_garbage_chunks;
} gc_work_t;

typedef struct scrub_work {
	struct repdev *dev;
	struct bg_job_entry* job;
	uint64_t n_refs;
	uint64_t n_refs_prev;
	uint64_t n_lost_chunks;
	uint64_t n_recovered;
	uint64_t n_corrupted_manifests;
	uint64_t n_recovered_manifests;
} scrub_work_t;

typedef struct incoming_batch_work {
	struct repdev *dev;
	struct bg_job_entry* job;
	uint32_t n_batches;
	uint32_t n_verified;
	uint32_t n_queued;
	uint32_t n_refs;
	uint32_t n_skipped;
} incoming_batch_work_t;

typedef struct {
	int last_entry_index; /* Index of the last processed entry */
	int last_rep_count; /* Replication count of the last batch entry */
} ibatch_state_t;

typedef struct {
	int rep_count_min; /* The minimal replication count detected */
} verify_state_t;

typedef struct trlog_work {
	struct repdev *dev;
	struct bg_job_entry *job;
	uint512_t chid;
	struct trlog_data data;
	struct ccow *tc;
	struct ccow_daemon *ccowd;
	uint64_t batch_seq_prev_ts;
	uint64_t batch_seq_ts;
	ccow_completion_t c;
	int index;
	int stale;
	char *oid;
	uint512_t* processed_vmchids;
	uint512_t* stale_vmchids;
} trlog_work_t;

/* gw_cache */
typedef struct gw_cache_work {
	uint64_t hw;
	uint64_t lw;
	struct repdev *dev;
} gw_cache_work_t;

/* rowusage */
typedef struct rowusage_work {
	struct repdev *dev;
	struct bg_job_entry* job;
	uint64_t chunks_evacuated[FLEXHASH_MAX_TAB_LENGTH];
	uint64_t repeat_count[FLEXHASH_MAX_TAB_LENGTH];
} rowusage_work_t;


typedef struct reptrans_lock {
	uint32_t count;		/* replicast context counters */
	uint64_t last_change;
	uv_mutex_t mutex;
	uv_cond_t condvar;
} reptrans_lock_t;
#define REPTRANS_LOCK_LASTCHANGE_EXPIRE_US	(60ULL*1000*1000)

/*
 * Simple reference counting implementation
 * It's used to lock/unlock/wait reptran's shared objects,
 * like replicast
 */
static inline void
reptrans_lock_init(reptrans_lock_t* p) {
	p->count = 0;
	p->last_change = 0;
	uv_mutex_init(&p->mutex);
	uv_cond_init(&p->condvar);
}

static inline reptrans_lock_t*
reptrans_lock_create() {
	reptrans_lock_t* p = je_malloc(sizeof(*p));
	reptrans_lock_init(p);
	return p;
}

static inline void
reptrans_lock_ref(reptrans_lock_t* p, uint32_t *stat_cnt) {
	uv_mutex_lock(&p->mutex);
	p->count++;
	if (stat_cnt)
		(*stat_cnt) += 1;
	p->last_change = get_timestamp_us();
	uv_mutex_unlock(&p->mutex);
}

static inline void
reptrans_lock_unref(reptrans_lock_t* p, uint32_t *stat_cnt) {
	uv_mutex_lock(&p->mutex);
	if (!--p->count) {
		uv_cond_signal(&p->condvar);
	}
	if (stat_cnt) {
		assert(*stat_cnt > 0);
		(*stat_cnt) -= 1;
	}
	p->last_change = get_timestamp_us();
	uv_mutex_unlock(&p->mutex);
}

static inline void
reptrans_lock_wait_unref(reptrans_lock_t* p) {
	uv_mutex_lock(&p->mutex);
	/* Exit logic doesn't want to wait for too long */
	while (p->count &&
	    p->last_change + REPTRANS_LOCK_LASTCHANGE_EXPIRE_US > get_timestamp_us()) {
		/* timed to 100ms */
		uv_cond_timedwait(&p->condvar, &p->mutex, 100ULL * 1000000ULL);
	}
	uv_mutex_unlock(&p->mutex);
}

static inline uint32_t
reptrans_lock_check_unref(reptrans_lock_t* p) {
	uint32_t rc = 0;
	uv_mutex_lock(&p->mutex);
	rc = p->count;
	uv_mutex_unlock(&p->mutex);
	return rc;
}
static inline uint32_t
reptrans_lock_get_ref(reptrans_lock_t* p) {
	return p->count;
}

static inline void
reptrans_lock_destroy(reptrans_lock_t* p) {
	uv_mutex_destroy(&p->mutex);
	uv_cond_destroy(&p->condvar);
	je_free(p);
}

enum rt_proto_id {
	RT_PROT_NGREQUEST = 1,
	RT_PROT_NGREQUEST_COUNT,
	RT_PROT_NGREQUEST_PURGE,
	RT_PROT_NGREQUEST_LOCATE
};

#define RT_PROT_NGREQUEST_VERSION          1
#define RT_PROT_NGREQUES_COUNT_VERSION     1
#define RT_PROT_NGREQUEST_PURGE_VERSION    1
#define RT_PROT_NGREQUEST_LOCATE_VERSION   2
#define RT_PROT_COMPOUND_VERSION           1

static inline int
reptrans_get_ngproto_version(enum rt_proto_id id) {
	int rc = -1;
	switch (id) {
		case RT_PROT_NGREQUEST:
			rc = RT_PROT_NGREQUEST_VERSION;
			break;

		case RT_PROT_NGREQUEST_COUNT:
			rc = RT_PROT_NGREQUES_COUNT_VERSION;
			break;

		case RT_PROT_NGREQUEST_PURGE:
			rc = RT_PROT_NGREQUEST_PURGE_VERSION;
			break;

		case RT_PROT_NGREQUEST_LOCATE:
			rc = RT_PROT_NGREQUEST_LOCATE_VERSION;
			break;

		default:
			rc = -1;
			break;
	}
	return rc;
}

/**
 * repmsg_ng::attr structure:
 *
 * [7..0] - protocol version
 * [12..8] - protocol ID (enum rt_proto_id)
 * [15..13] - reserved
 */
struct repmsg_ng {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
#define RT_PROTO_ID(_msg) (((_msg)->attr >> 8) & 0x1f)
#define RT_PROTO_VER(_msg) ((_msg)->attr & 0xff)
	uint16_t attr; /* protocol ID, version and etc */
	uint64_t hashID;	/*payload's hashID, hash type is HASH_TYPE_XXHASH_64*/
};

typedef int (rt_ng_unpack_cb) (msgpack_u* u, void* data);
typedef int (rt_ng_pack_cb) (msgpack_p* p, void* data);

int
reptrans_ng_send(enum rt_proto_id id, struct replicast *robj,
	struct repctx *ctx, enum replicast_opcode opcode,
	struct repmsg_generic *omsg, uv_buf_t bufs[], unsigned int nbufs,
	struct sockaddr_in6 *to_addr, replicast_send_cb cb, void *data);

int
reptrans_ng_send_pack(enum rt_proto_id id, struct replicast *robj,
	struct repctx *ctx, enum replicast_opcode opcode,
	struct repmsg_generic *omsg, void* dptr, rt_ng_pack_cb pack_cb,
	struct sockaddr_in6 *to_addr, replicast_send_cb cb, void *data);
int
reptrans_ng_recv(enum rt_proto_id id, struct repwqe *wqe,
	rtbuf_t** rt_out);
int
reptrans_ng_recv_unpack(enum rt_proto_id id, struct repwqe *wqe,
	void* dptr, rt_ng_unpack_cb cb);

int
reptrans_verify_queue(verify_work_t *work);

int
reptrans_send_batch(verify_work_t *work, uint64_t ngroup);

uint64_t
reptrans_get_flexcount(struct repdev *dev, uint16_t ngnum, int numrows);

size_t
reptrans_get_rowusage(struct repdev *dev, uint16_t ngnum, int fhnumrows);

int
reptrans_enqueue_batch(struct repdev *dev, char *msg, size_t msg_len);

int
reptrans_notify_membership_change(struct repdev *dev, int join,
	const char *mcgrp, uint32_t if_index);

void
reptrans_on_flexhash_rebuild_done(volatile struct flexhash *fhtable, int join);

void
reptrans_bgjobs_restart();

int
reptrans_copy_hashcount(int rt_num, struct cl_node *node);

ccow_t
reptrans_get_tenant_context(struct reptrans *rt, uint64_t key);

void
reptrans_put_tenant_context(struct reptrans *rt, ccow_t tc);

int
reptrans_parse_bg_jobs_config(const struct _json_value* obj, struct repdev_bg_config* cfg,
	size_t* n_opts);

repdev_status_t
reptrans_dev_set_status(struct repdev *dev, repdev_status_t status);

repdev_status_t
reptrans_dev_override_status(struct repdev *dev, repdev_status_t status);

static inline repdev_status_t
reptrans_dev_get_status(struct repdev *dev) {
	return dev->status;
}

int
reptrans_process_batches(incoming_batch_work_t *work);

int
reptrans_blob_lookup(type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t* chid, uint128_t** vdevs, uint16_t* ndevs);

int
reptrans_replicast_delay_internal(struct repdev *dev, uint32_t delay_max,
	const char* file, int line);

#define reptrans_replicast_delay(dev, delay_max) reptrans_replicast_delay_internal(dev, delay_max, __FILE__, __LINE__)

void
reptrans_start_scrub();

static inline void
reptrans_set_thrname(struct repdev *dev, char *prefix5c)
{
	char trname[16];
	if (strlen(dev->name) < 8)
		sprintf(trname, "%s_%s", prefix5c, dev->name);
	else
		sprintf(trname, "%s_%s", prefix5c,
		    &dev->name[strlen(dev->name) - 8]);
	pthread_setname_np(pthread_self(), trname);
}

int reptrans_get_chunk_rep_count(struct repdev *dev, crypto_hash_t hash_type,
	uint512_t *chid);

int reptrans_get_chunk_count(struct repdev *dev, crypto_hash_t hash_type,
    type_tag_t ttag, uint512_t *chid, size_t *countp);

int
reptrans_get_chunk_count_limited(struct repdev *dev, crypto_hash_t hash_type,
    type_tag_t ttag, uint512_t *chid, int n_max, size_t *countp);

int
reptrans_get_depcount_coarse(struct repdev *dev,  type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *chid, int n_max, size_t *countp);

void reptrans_dev_ctxfree_one(struct repdev* dev, struct repctx *ctx);

int reptrans_enqueue_batch_request(struct repdev *dev, uint512_t *nhid,
	struct verification_request *vreq);

int reptrans_request_encoding(struct repdev *dev,
    struct verification_request *vbreq);

int
reptrans_get_effective_rep_count(const uint128_t* vdev_ids, size_t n_ids,
	int failure_domain);

int
reptrans_get_vdevs_usage(uint64_t** usage);

int
is_cluster_healthy(struct reptrans* rt, int rep_cnt);

int
reptrans_has_version(struct repdev *dev, crypto_hash_t hash_type,
	uint512_t *key, uint64_t generation);

int reptrans_put_hashcount(struct repdev *dev);

int
reptrans_enqueue_vm_encoding(struct repdev* dev, const uint512_t* vmchid,
	const struct vmmetadata* md);

void
reptrans_io_avg(struct repdev* dev);

int
repdev_generate_name(struct repdev* dev);

void
reptrans_close_all_rt();

int
reptrans_get_vm_nhid(struct repdev* dev, const uint512_t* vmchid, uint512_t* nhid);
void
reptrans_destroy_device_rowusage(struct repdev* dev);

static inline double
reptrans_get_utilization(struct repdev* dev) {
	uint64_t used = atomic_get_uint64(&dev->stats.used);
	uint64_t capacity = atomic_get_uint64(&dev->stats.capacity);
	return (double)used/(double)capacity;
}

void
reptrans_fddelta_update(uint64_t period_ms);

enum {
	ioTypeRead,
	ioTypeWrite,
	ioTypeDelete
};

int
reptrans_refresh_status(struct repdev *dev, type_tag_t ttag, int optType);

int
reptrans_estimate_row_usage(struct repdev* dev, uint16_t row, int numrows,
	size_t* n_estimated);

typedef int (*foreach_vdev_cb_t)(struct repdev* dev, void* arg);

int
reptrans_foreach_vdev(foreach_vdev_cb_t cb, void* arg);

void
reptrans_dev_change_membership(volatile struct flexhash *fhtable, struct repdev *dev,
	int join);

void
reptrans_add_vdev(struct reptrans* rt, struct repdev* dev);

void
reptrans_process_touch_queue(struct repdev* dev);

int
reptrans_verify_one_request(struct repdev *dev, struct verification_request *vbreq,
    uint32_t *n_verified, uint64_t cts);

int
reptrans_get_fd_targets_number_unsafe(int domain);

int
reptrans_get_fd_targets_number(int domain);

#define log_debug_vbr log_debug

#ifdef	__cplusplus
}
#endif

#endif
