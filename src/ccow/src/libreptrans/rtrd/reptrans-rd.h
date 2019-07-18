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

#ifndef NEDGE_REPTRANS_RD_H
#define NEDGE_REPTRANS_RD_H
#include <lmdb.h>
#include <uthash.h>
#include <linux/limits.h>
/*
 * This is header files contains private definitions and is considered
 * unstable.
 *
 * Minimal size allocated for journal partitions calculated as:
 *
 * DEV_RD_PARTS * DEV_RD_JPART_MINSIZE * DEV_LOGID_MAX
 *
 * Reasonable size has to be with in 8GB so that it can fit sufficient amount
 * of entries prior to flush.
 */

#define DEV_RD_FLUSH_ERROR_MAX	10
#define DEV_CREATED_TIMESTAMP "created-timestamp"
#define DEV_METADATA ".device-metadata"
#define DEV_RD_MAGIC_OFFSET (2032 * 512)
#define DEV_PARTS_DIR "parts"
#define DEV_MAGIC "NEFMT1"
#define DEV_LMDB_MAXREADERS 512 /* LMDB default is 126 */
#define DEV_RD_VERSION 7        /* current version of the rd */
#define DEV_RD_VERSION_EXT_METALOC 7 /* RTRD version at which metaloc was extended */
#define DEV_RD_PSIZE 32768      /* LMDB page size */
#define DEV_RD_MDPSIZE 8192     /* LMDB page size for MD device */
#define DEV_RD_HEADROOM 2048UL  /* start sector offset (disk sectors) */
#define DEV_RD_JPART_TAILROOM 65536    /* tailroom for WAL journal (bytes) */
#define DEV_RD_JPART_MINSIZE(_plevel) \
	((_plevel) > 2 ? (512UL * 1024UL * 1024UL) : (2UL * 1024UL * 1024UL * 1024UL))
#define DEV_RD_DEL_BUKL 1024 /* Maximum allowed number of deletion per transaction*/
#define DEV_RD_DEL_DEFERRED_BULK DEV_RD_DEL_BUKL
#define DUPSORT_DEL_MAGIC "neDGe_duPSort_deLEte"
#define DUPSORT_DEL_MAGIC_SIZE (strlen(DUPSORT_DEL_MAGIC) + 1)
#define IS_DUPSORT_DEL(p) (strcmp((p), DUPSORT_DEL_MAGIC) == 0)


/* Maximum number of entries before we will start flushing into main TT
 * tables. Too low numbers will affect performance. Too high numbers will
 * increase flushing time and may introduce I/O drops. */
#define DEV_LMDB_LOG_MAXENTRIES 32
#define DEV_LMDB_LOG_DUPSORT_MAXENTRIES (DEV_LMDB_LOG_MAXENTRIES*32)
#define DEV_LMDB_LOG_TT_MAXENTRIES(ttag, dev) \
	(is_dupsort_tt(ttag) ? DEV_LMDB_LOG_DUPSORT_MAXENTRIES : (dev)->journal_maxentries)

/* Maximum chunk size will be put into the LOG as a record rather then
 * directly into main TT data store. We add 128 bytes to account for
 * uncompressable chunks. */
#define DEV_LMDB_LOG_MAXCHUNKSIZE (8UL * 1024UL * 1024UL + 128UL)
#define RT_RD_HDD_LATENCY_US 200000
#define RT_RD_SSD_LATENCY_US 50000
#define RT_RD_PLEVEL_MAX	64
#define RT_RD_PLEVEL_EMBEDDED 4

struct repdev_db;

#define SHARD_HASHCALC(k, m) (((k)->u.u.u >> 16) & (m))
#define LOGID_HASHCALC(k, m) (((k)->u.u.u >> 16) & (m))
#define DEV_SHARDS_MASK 0x0
#define DEV_SHARDS_MAX (DEV_SHARDS_MASK + 1)
#define DEV_SHARD_A(_db, _tt, _n) ((_db)->shards[(_tt) *DEV_SHARDS_MAX + (_n)])
#define DEV_SHARD(_db, _tt, _n) ({ \
    MDB_dbi ret; \
    if ((_db)->dev->journal && is_mdoffload_tt((_db)->dev, (_tt))) \
	ret = ((struct repdev_rd *)(_db)->dev->device_lfs)->mdoffload_dbi[(_tt)]; \
    else \
	ret = DEV_SHARD_A(_db, _tt, _n); \
    ret; \
})
#define DEV_SHARD_MAX(_db, _tt) (((_db)->dev->journal && is_mdoffload_tt((_db)->dev, (_tt))) \
	? 1 : DEV_SHARDS_MAX)

#define DEV_LOGID_MASK 0x0
#define DEV_LOGID_MAX (DEV_LOGID_MASK + 1)
#define DEV_LOGID(_db, _n) ((_db)->log[(_n)])

#define DEV_PARTS_MAX 255
#define DEV_JOURNALS_MAX 15
#define DEV_JMEMBERS_MAX 10
#define DEV_RD_MAXNUM 128
#define DEV_RD_PREFERED_PART_SIZE (512UL*1024UL*1024UL*1024UL)

#define BLOOM_STORE_OK "BLOOM_STORE_OK"

/*
 * we want to have an approximate cache size of 64MB
 * the structure key_cache_entry_t is 12 bytes
 */
#define KEY_CACHE_MAX (64*1024*1024) / sizeof(key_cache_entry_t)

/* Average size of Chunk Manifest. MDCACHE using this value to calculate
 * hash table size. The smaller value the better SSD utilization will be */
#define MDCACHE_CM_SIZE		16384
#define MDCACHE_RESERVED_PCT	60

/* As we sharing mdcache with some additional metadata, this is how many entries
 * will be evicted if it gets closer to MAX percent */
#define MDCACHE_ADJUST_MAX	75
#define MDCACHE_ADJUST_EVICT	256
#define MDCACHE_QUEUE_SIZE	1024

#define BCACHE_CACHE_MODE	1 /* writearound is our default */
#define BCACHE_WBC_PERCENT	20
#define BCACHE_WBC_DELAY	30
#define BCACHE_WBC_THRESHOLD_MB 256
#define BCACHE_WBC_FLUSH_MB	32
#define BCACHE_BUCKET_SIZE_KB	512
#define BCACHE_SEQUENTIAL_CUTOFF (1024*1024)
#define MEDIA_READAHEAD		4
#define HDD_READAHEAD		256

typedef enum partition_walk {
    PART_WALK_CONTINUE,
    PART_WALK_TERMINATE,
    PART_WALK_COMPLETED
} part_walk_action_t;

/* generic callback to walk partitions of a given device */
typedef part_walk_action_t (*partition_walk_f)(struct repdev_db *db, void *arg);

part_walk_action_t rd_partition_walk(struct repdev *dev,
                                         partition_walk_f func, void *arg);


/* MD offload uses separate environment */
#define DEV_ENVS 2
#define DEV_ENV(_db, _ttag) ((_db)->env[(_db)->dev->journal && is_mdoffload_tt((_db)->dev, (_ttag))])

enum rdLockOps { lopNone, lopRead, lopWrite };

/* do we need a ref count for these? */
typedef struct key_cache_entry {
    uint64_t key;
    uint32_t size;
    uint8_t  ttag;
    UT_hash_handle hh;
} key_cache_entry_t;

typedef struct key_cache {
    uint32_t c; // capacity
    key_cache_entry_t *entries;
    uv_rwlock_t lock;
    key_cache_stat_t stats;
    void (*free_entry) (void *element); //cb to free items; optional
} key_cache_t;

typedef struct mdcache_entry {
    uint64_t key;
    uint32_t size;
    UT_hash_handle hh;
} mdcache_entry_t;

typedef struct mdcache_queue_entry {
    uint64_t key;
    uint32_t size;
    type_tag_t ttag;
    void* buf;
} mdcache_queue_entry_t;

typedef struct mdcache {
    uint32_t c; // capacity
    mdcache_entry_t *entries;
    struct repdev *dev;
    uv_rwlock_t lock;
    mdcache_stat_t stats;
    lfqueue_t insert_queue;
    void (*free_entry) (void *element); //cb to free items; optional
} mdcache_t;

struct blkio_info {
        unsigned int rd_ios;
        unsigned int rd_merges;
        unsigned long long rd_sectors;
        unsigned int rd_ticks;
        unsigned int wr_ios;
        unsigned int wr_merges;
        unsigned long long wr_sectors;
        unsigned int wr_ticks;
        unsigned int ticks;
        unsigned int aveq;
};

struct cpu_info {
        unsigned long long user;
        unsigned long long system;
        unsigned long long idle;
        unsigned long long iowait;
};

#define RD_METALOC_ERROR_MAX 32
#define RD_METALOC_SIZE      1024
#define RD_METALOC_PATH_MAX  512

struct rd_fault_signature {
	/*
	 * The last error code LMDB returned upon fault (if applicable)
	 */
	int error;

	/* Error source:
	 *  'm' - main partition
	 *  'l' - WAL partition
	 *  'o' - mdoffload partition
	 *  'c' - last maintenance command has failed
	 *  'e' - external fault request, e.g. for maintenance
	 */
	char source;

	/*
	 * Affected plevel for WAL or main part (if applicable)
	 * 0 - affected whole device (or mdoffload partition)
	 * 1..#plevel - affected a plevel
	 */
	int plevel;
};

typedef enum {
	/*
	 * The drive is in a consistent state. Only this state gives a permeation
	 * for VDEV to go online.
	 */
	rdstateOk = 0,
	/*
	 * The drive has faulted. Operations disabled.
	 */
	rdstateFault,
	/*
	 * The device is read-only due to previous write/delete error
	 */
	rdstateReadOnly,
	/*
	 * Some maintenance need to be done prior disk initialization.
	 * The metaloc has a dedicated command string for it.
	 */
	rdstateMaintenance
} rdStateEnum;

/*
 * Upon start the VDEV has to read the metalloc and have to act according to
 * rd_metaloc::state:
 * a) rdstateOk normal flow, init the disk and attach
 * b) rdstateFault the disk is faulted. Further initialization is forbidden.
 * c) rdstateMaintenance. The disk requires certain maintenance action.
 *    The rd_metaloc::maintenance_cmd[] is an activity ID string. If a process,
 *    which is able to execute required maintenance task, detects the rd_metaloc::pid == 0
 *    or a process with rd_metaloc::pid doesn't exists, then the activity can be
 *    safely started by the process persisting its PID in rd_metaloc::pid. When
 *    maintenance is done, the process has to change rd_metaloc::state to
 *    rdstateOk or rdstateFault, set rd_metaloc::pid to 0 and overwrite the
 *    metaloc record.
 */
struct rd_metaloc {
	uint64_t timestamp;
	int plevel;

	/* main disk name, e.g. scsi-35000c500842a615b */
	char device[RD_METALOC_PATH_MAX];

	/* Index of a the first journal partition */
	int  first_journal_part;

	/* journal name, e.g. ata-SanDisk_SD6SB2M512G1022I_140751401308*/
	char journal[RD_METALOC_PATH_MAX];

	/* mdoffload partition, e.g. ata-SanDisk_SD6SB2M512G1022I_140751401308-part10*/
	char mdoffload[RD_METALOC_PATH_MAX];

	/* The previous device name. Used for disk replacement */
	char oldname[RD_METALOC_PATH_MAX];

	uint128_t vdev_id;

	/* RTRD version */
	int version;

	/* Mask of metadata types situated on the mdoffload SSD partition */
	int metamask;

	/* bcache enable (1) or disable (0) */
	int bcache;

	/* write-ahead load enabled(1) or disabled(0) */
	int wal;

	/* LMDB environment's page size, main partitions */
	int psize;

	/* LMDB environment's page size, mdoffload partition*/
	int mdpsize;

	/*
	 * An array of faults signature. Each fault's handler has to add
	 * there an entry. The array is cleared when all faults are recovered.
	 */
	struct rd_fault_signature faults[RD_METALOC_ERROR_MAX];

	/* Number of faults detected since last recovery */
	int n_faults;

	/* Current VDEV state, see the rdStateEnum */
	int state;

	/*
	 * An arrays of maintenance command IDs. It can be the last performed activity
	 * (state == rdstateOk) or pending/running one (state == rdstateMaintenance).
	 */
	char maintenance_cmd[RT_RD_PLEVEL_MAX][32];

	/* Number of pending commands */
	int n_cmds;
	/*
	 *  PID of a process which is running the maintenance job.
	 * 0 if no such a process,
	 * Non-zero if there is (was) a process trying to execute the required
	 * maintenance job
	 */
	pid_t pid;

	/*
	 * Number of times the maintenance was started,
	 * but not finished (interrupted, crashed). Used to avoid
	 * endless maintenance loop. The disk must be marked as faulted after a
	 * number of attempts
	 */
	int retries;
};

struct repdev_rd {
    struct repdev_db *db;
    int opened; /* Set when the VDEV has all environment opened */
    struct rd_metaloc metaloc;
    MDB_env *mdcache_env;
    MDB_dbi mdcache_dbi[TT_LAST];
    MDB_dbi keys_dbi[TT_LAST];
    MDB_dbi mdoffload_dbi[TT_LAST];
    mdcache_t *mdcache;
    volatile uint64_t flushed_bytes;
    uint64_t hashcount_last;
    uint64_t smart_read_ts;
    uint64_t iostat_read_ts;
    int smart_selftest_scheduled;
    struct blkio_info old_blkio;
    struct cpu_info old_cpu;
    /* hashcount last flush timestamp */
    int zerocopy;
    int sync;
    int readahead;
    int hdd_readahead;
    int writemap;
    uint64_t bcache_wbc_threshold_mb;
    uint64_t bcache_wbc_flush_mb;
    int direct;
    int plevel;
    int mdcache_enable;
    uint64_t bloom_ttag_put_counter;
    pthread_rwlock_t guard;
};

struct repdev_log {
    int id;
    MDB_env *env;
    MDB_dbi dbi[TT_LAST];
    char path[PATH_MAX];
    struct repdev_db *db;
    struct repdev *dev;
    pthread_t flush_thread;
    rtbuf_t *delete_rbkeys;
    type_tag_t ttag;
    uint64_t flushed_timestamp;
    pthread_rwlock_t access_lock;
    pthread_mutex_t  repair_lock;
};

struct repdev_db {
    int part;
    MDB_env *env[DEV_ENVS];
    MDB_dbi shards[TT_LAST * DEV_SHARDS_MAX];
    struct repdev_log log[DEV_LOGID_MAX];
    struct repdev *dev;
    uint8_t *bloom;
    hashtable_t *keyht[TT_LAST];
    pthread_t bloom_load_thread;
    uv_rwlock_t bloom_lock;
    long bloom_loaded;
    unsigned long log_flush_cnt;
    type_tag_t log_flushed_ttag;
    uv_mutex_t log_flush_lock;
    uv_cond_t log_flush_condvar;
    uint16_t flush_error_count[TT_LAST];
    key_cache_t *key_cache;
};

int key_cache_ini(key_cache_t **cache, const uint32_t c,
                  void (*free_entry)(void *element));

int key_cache_fini(key_cache_t *cache);

int key_cache_insert(key_cache_t *c, uint64_t *key, type_tag_t ttag,
                     uint32_t size);

int key_cache_lookup(key_cache_t *c, uint64_t *key, type_tag_t ttag,
                     uint64_t *size);

int key_cache_remove(key_cache_t *c, uint64_t *key, type_tag_t ttag);

int mdcache_ini(mdcache_t **cache, struct repdev *dev,
    const uint32_t c, void (*free_entry)(void *element));

int mdcache_fini(mdcache_t *cache);

int mdcache_insert(mdcache_t *c, type_tag_t ttag, MDB_txn *ext_txn,
    uint64_t *key, void *data, uint32_t size);

int mdcache_lookup(mdcache_t *c, type_tag_t ttag, uint64_t *key,
    void **data, uint64_t *size);

int mdcache_remove(mdcache_t *c, type_tag_t ttag, MDB_txn *ext_txn, uint64_t *key);

int rd_config(struct repdev *dev, dev_cfg_op op,
              const uv_buf_t *key, uv_buf_t *value);

int rd_dev_load_bloom(struct repdev *rdev);

int rd_dev_quiesce_bloom(struct repdev *rdev);
#endif // NEDGE_REPTRANS_RD_H
