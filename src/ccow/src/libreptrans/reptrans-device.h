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
#ifndef __REPTRANS_DEVICE__H__
#define __REPTRANS_DEVICE__H__

#include "reptrans-data.h"

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif

struct repdev;

extern __thread volatile void* _tls_vdev_ptr;

static inline void
rt_set_thread_vdev_context(struct repdev* dev) {
	_tls_vdev_ptr = dev;
}

static inline struct repdev*
rt_get_thread_vdev_context() {
	return (struct repdev*)_tls_vdev_ptr;
}


/* dev_stat() */
typedef enum reptrans_devinfo_req_type {
	STAT_REQ_CACHED = 0,
	STAT_REG_DEVICE
} reptrans_devinfo_req_type_t;

#define HASHCOUNT_KEY_LENGTH	11
#define HASHCOUNT_TAB_LENGTH	(1 << HASHCOUNT_KEY_LENGTH)
#define HASHCOUNT_MASK		(HASHCOUNT_TAB_LENGTH - 1)
#define HASHCOUNT_BLOB_KEY	"HASHCOUNT_BLOB"
#define ROWUSAGE_BLOB_KEY	"ROWUSAGE_BLOB"
#define TIMESTAMP_KEY "TIMESTAMP"
#define PLEVEL_HASHCALC(k, m)	(((k)->u.u.u >> 24) & (m))

typedef struct key_cache_stat {
    uint32_t hit;
    uint32_t miss;
    uint32_t evicted;
} key_cache_stat_t;

typedef struct mdcache_stat {
    uint32_t hit;
    uint32_t miss;
    uint32_t evicted;
    size_t total;
    size_t mdcache_used;
    size_t mdcache_entries;
    size_t keydb_used;
    size_t keydb_entries;
    size_t mdoffload_used;
    size_t mdoffload_entries;
} mdcache_stat_t;

typedef struct smart_stat {
	/* Common */
	uint32_t smart_status;
	uint32_t temperature_current;

	/* Typical SAS */
	uint64_t non_medium_error_count;
	uint64_t percentage_used_endurance_indicator;
	uint64_t total_uncorrected_read_errors;
	uint64_t total_uncorrected_write_errors;

	/* ATA/SATA */
	uint64_t current_pending_sector;
	uint64_t ecc_uncorr_error_count;
	uint64_t end_to_end_error;
	uint64_t offline_uncorrectable;
	uint64_t reallocated_event_count;
	uint64_t reallocated_sector_ct;
	uint64_t reported_uncorrect;
	uint64_t soft_read_error_rate;
	uint64_t spin_retry_count;
	uint64_t total_pending_sectors;
	uint64_t unc_soft_read_err_rate;
	uint64_t raw_read_error_rate;
} smart_stat_t;

typedef struct iostat_stat {
        unsigned int r_merges;
        unsigned int w_merges;
        unsigned int r_ios;
        unsigned int w_ios;
        unsigned long long r_sectors;
        unsigned long long w_sectors;
	double busy;
	double svc_t_us;
	double wait_us;
	double size_kb;
	double queue;
} iostat_stat_t;

#define MAX_ROW_EVAC_DEV	10

struct reptrans_gw_stats
{
	char cid[REPLICAST_STR_MAXLEN + 1];
	char tid[REPLICAST_STR_MAXLEN + 1];
	char bid[REPLICAST_STR_MAXLEN + 1];
	char oid[REPLICAST_STR_MAXLEN + 1];
	uint128_t uvid_src_guid;
	uint32_t uvid_src_cookie;
	uint512_t name_hash_id;
	uint512_t svcinfo;
	uint64_t put_iops;
	uint64_t get_iops;
	uint64_t put_bw;
	uint64_t get_bw;
	uint64_t avg_put_latency;
	uint64_t avg_get_latency;
	uint64_t timestamp;
};

struct reptrans_devinfo_req {
	uv_mutex_t stat_mutex;		/* Protects devinfo */
	uv_mutex_t gw_stat_mutex;	/* Protects gw_stats devinfo */
	uint64_t physical_capacity;	/* In bytes, total capacity */
	uint64_t capacity;		/* In bytes, data only */
	uint64_t used;			/* In bytes, data only */
	uint64_t bytes_out_snap;
	uint64_t bytes_in_snap;
	uint64_t writes_snap;
	uint64_t reads_snap;
	uint64_t write_bw;		/* Current write bandwidth */
	uint64_t read_bw;		/* Current read bandwidth */
	uint64_t write_iops;		/* Current write IOPS */
	uint64_t read_iops;		/* Current read IOPS */
	uint64_t writes;		/* Total writes */
	uint64_t reads;			/* Total reads */
	uint64_t bytes_out;		/* Total bytes written to vdev */
	uint64_t bytes_in;		/* Total bytes read from vdev */
	uint64_t metadata_vdev_capacity;                /* In bytes */
	uint64_t metadata_vdev_used;                    /* In bytes */
	uint64_t metadata_vdev_max_blob_size;           /* In bytes */
	uint64_t put4k_latency;		/* avg normalized to 4k */
	uint64_t put64k_latency;	/* avg normalized to 64k */
	uint64_t put512k_latency;	/* avg normalized to 512k */
	uint64_t put4k_latency_j;
	uint64_t put64k_latency_j;
	uint64_t put512k_latency_j;
	uint64_t put90th_4k_latency;	/* 90th percetile normalized to 4K */
	uint64_t put90th_64k_latency;	/* 90th percetile normalized to 64K */
	uint64_t put90th_512k_latency;  /* 90th percetile normalized to 512K */
	uint64_t put90th_4k_latency_j;
	uint64_t put90th_64k_latency_j;
	uint64_t put90th_512k_latency_j;
	uint64_t get4k_latency;
	uint64_t get64k_latency;
	uint64_t get512k_latency;
	uint64_t get4k_latency_m;
	uint64_t get64k_latency_m;
	uint64_t get512k_latency_m;
	uint64_t get4k_req_latency;
	uint64_t get64k_req_latency;
	uint64_t get512k_req_latency;
	uint64_t get4k_req_latency_m;
	uint64_t get64k_req_latency_m;
	uint64_t get512k_req_latency_m;
	uint64_t delete_latency;
	uint32_t rotational;		/* HDD or SSD */
	uint32_t window_size;		/* max # of samples */
	uint32_t n_samples;		/* # of samples */
	uint64_t hashcount[HASHCOUNT_TAB_LENGTH + 1];	/* hash counts */
	uint64_t rowusage[HASHCOUNT_TAB_LENGTH + 1];	/* usage of each row, bytes*/
	uint64_t num_objects;		/* # of entries in TT_NAMEINDEX */
					/* all objects in index */
	uint64_t nominal_latency;	/* In ms, based on device type */
	uint64_t num_retransmit;

	uint64_t ttag_entries[TT_LAST];
	uint64_t ttag_size[TT_LAST];

	struct reptrans_gw_stats gw_stats_get_lat;
	struct reptrans_gw_stats gw_stats_put_lat;
	struct reptrans_gw_stats gw_stats_get_iops;
	struct reptrans_gw_stats gw_stats_put_iops;
	struct reptrans_gw_stats gw_stats_get_bw;
	struct reptrans_gw_stats gw_stats_put_bw;

	struct key_cache_stat keycache;
	struct mdcache_stat mdcache;
	struct smart_stat smart;
	struct iostat_stat iostat;
};

struct repdev_hashcount {
	uint128_t vdevid;
	uint64_t hashcount[HASHCOUNT_TAB_LENGTH];
};

struct reptrans_hashcount {
	int n_dev;
	struct repdev_hashcount *dev_hashcount;
};

typedef void (*reptrans_stat_cb_t)(struct repdev *dev,
    struct reptrans_devinfo_req *stat, int status);

struct repdev_call {
	QUEUE item;
	void (*method)(struct repdev_call *c);
	void *args[8];
	void *done;
	int rc;
};

#define GBF_FLAG_ONE		0x1
#define GBF_FLAG_ALL		0x2
#define GBF_FLAG_DUPCOUNT	0x4
#define GBF_FLAG_NO_WAL		0x8
#define GBF_FLAG_DUPCOUNT_ROUGH	0x10 /* Fast but coarse dupsort count */

typedef struct blob_stat {
	uint64_t	size;
	time_t		ctime;
} blob_stat_t;

typedef enum {
	COMPACT_ST_IDLE,
	COMPACT_ST_PROGRESS,
	COMPACT_ST_ERROR
} comp_state_t;

typedef enum {
	CFG_READ = 0,
	CFG_WRITE
} dev_cfg_op;

struct compactify_status {
	struct repdev*	dev;
	comp_state_t	state;
	uint16_t	progress;
	size_t		orig_size_kb;
	size_t		comp_size_kb;
	time_t		started_at;
	time_t		done_at;
};

typedef int  (*reptrans_blob_callback)(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param);

typedef int (*reptrans_blob_filter)(void *arg, void **data,
    size_t *size, int set);

typedef void (*comp_cb_t)(const struct compactify_status*);

/**
 * Put modifiers
 *
 * REPDEV_PUT_OPT_OVERWRIGHT allows chunk overwrite. Disabled by default
 */

#define REPDEV_PUT_OPT_OVERWRITE (1<<0)

struct repdev_vtbl {
	int (*stat_refresh)(struct repdev* dev);
	/**
	 * @addtogroup libreptrans
	 * @{
	 * @file
	 * @author Nexenta Systems, Inc
	 * @version 1.0
	 *
	 * @ref license
	 */

	/**
	 * Saves data blob somewhere on the key-value VDEV
	 *
	 * @param[in] dev pointer to struct repdev
	 * @param[in] ttag type tag of the blob to be put
	 * @param[in] hash_type hash algorithm type to sign blob with
	 * @param[in] rb pointer to prepared rtbuf_t carrying on replicast buffers
	 * to be put
	 * @param[in/out] chid pre/post-calculated Content Hash ID of to be/written blob
	 * @returns 0 on success, negative error code on failure
	 *
	 * Device should store data as one monolithic blob. On successful
	 * return CHID of written blob will be compared by the host against
	 * replicast message supplied CHID.
	 *
	 * Devices may elect to optimize index placement (TT_NAMEINDEX).
	 * Indexed access may speed up Name Hash ID lookups, especially for
	 * sort/filter operations.
	 *
	 * In case of TT_NAMEINDEX chid must be pre-calculated.
	 */
	int (*put_blob)(struct repdev *dev, type_tag_t ttag,
		crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid);

	/**
	 * Saves data blob with attribute somewhere on the key-value VDEV
	 *
	 * @param[in] dev pointer to struct repdev
	 * @param[in] ttag type tag of the blob to be put
	 * @param[in] hash_type hash algorithm type to sign blob with
	 * @param[in] rb pointer to prepared rtbuf_t carrying on replicast
	 * buffer sto be put
	 * @param[in/out] chid pre/post-calculated Content Hash ID of to
	 * be/written blob
	 * @param[in] attr blob attribute
	 * @param[in] options put modifiers (see REPDEV_PUT_OPT_OWERRIGHT)
	 * @returns 0 on success, negative error code on failure
	 *
	 * Device should store data as one monolithic blob. On successful
	 * return CHID of written blob will be compared by the host against
	 * replicast message supplied CHID.
	 *
	 * Devices may elect to optimize index placement (TT_NAMEINDEX).
	 * Indexed access may speed up Name Hash ID lookups, especially for
	 * sort/filter operations.
	 *
	 * In case of TT_NAMEINDEX chid must be pre-calculated.
	 */
	int (*put_blob_with_attr)(struct repdev *dev, type_tag_t ttag,
		crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid,
		uint64_t attr, uint64_t options);

	/**
	 * Retrieves data blob previously put
	 *
	 * @param[in] dev pointer to struct repdev
	 * @param[in] ttag type tag of the blob to be retrieved
	 * @param[in] hash_type hash algorithm type to sign blob with
	 * @param[in] chid precalculated Content Hash ID of blob
	 * @param[out] rb output pointer to allocated rtbuf_t with read buffers
	 * @param[in] max_num maximum number of entries, 0 for no limit
	 * @returns 0 on success, negative error code on failure
	 */
	int (*get_blob)(struct repdev *dev, type_tag_t ttag,
		crypto_hash_t hash_type, int flags, const uint512_t *chid,
		rtbuf_t **rb, int max_num, reptrans_blob_filter filter_cb,
		void *arg);

	/**
	 * Retrieves data blob attribute
	 *
	 * @param[in] dev pointer to struct repdev
	 * @param[in] ttag type tag of the blob to be retrieved
	 * @param[in] hash_type hash algorithm type to sign blob with
	 * @param[in] chid precalculated Content Hash ID of blob
	 * @param[out] attr blob timestamp
	 * @returns 0 on success, negative error code on failure
	 */
	int (*get_blob_attr)(struct repdev *dev, type_tag_t ttag,
		crypto_hash_t hash_type, const uint512_t *chid, uint64_t *attr);

	/**
	 * Set data blob attribute
	 *
	 * @param[in] dev pointer to struct repdev
	 * @param[in] ttag type tag of the blob to be retrieved
	 * @param[in] hash_type hash algorithm type to sign blob with
	 * @param[in] chid precalculated Content Hash ID of blob
	 * @param[in] attr blob timestamp
	 * @returns 0 on success, negative error code on failure
	 */
	int (*set_blob_attr)(struct repdev *dev, type_tag_t ttag,
		crypto_hash_t hash_type, const uint512_t *chid, uint64_t attr);

	/**
	 * Deletes the data blob
	 *
	 * @param[in] dev pointer to struct repdev
	 * @param[in] ttag type tag of the blob to be retrieved
	 * @param[in] hash_type hash algorithm type to sign blob with
	 * @param[in] chid precalculated Content Hash ID of blob
	 * @returns 0 on success, negative error code on failure
	 *
	 * The host is responsible for deleting of all references to a blob and
	 * coordination with other hosts possibly sharing the VDEV.
	 */
	int (*delete_blob)(struct repdev *dev, type_tag_t ttag,
		crypto_hash_t hash_type, const uint512_t *chid);

	/**
	 * Deletes value(s) from the given blob
	 *
	 * @param[in] dev pointer to struct repdev
	 * @param[in] ttag type tag of the blob to be retrieved
	 * @param[in] hash_type hash algorithm type to sign blob with
	 * @param[in] chid precalculated Content Hash ID of blob
	 * @param[in] val pointer to an array of values to be deleted
	 * @param[in] len number of values in val array
	 * @returns 0 on success, negative error code on failure
	 *
	 * Fast delete of values in one transaction from the given blob key
	 */
	int (*delete_blob_value)(struct repdev *dev, type_tag_t ttag,
		crypto_hash_t hash_type, const uint512_t *chid, uv_buf_t *val,
		size_t len);

	/**
	 * Lists hash IDs by provided NG number and mask
	 *
	 * @param dev pointer to struct repdev
	 * @param ttag type tag of the blob to be retrieved
	 * @param hash_type hash algorithm type to sign blob with
	 * @param chid precalculated Content Hash ID of start blob
	 * @param max maximum number of Content Hash IDs stored after the
	 * supplied Content Hash ID. Order is repeatable, but arbitrary
	 * @param chidlist null terminated string list of Content Hash IDs
	 * @returns actual length of the CHID list on success, or negative error
	 * code on failure
	 *
	 * The host is responsible for freeing chidlist strings.
	 */
	int (*list_blob_chids)(struct repdev *dev, type_tag_t ttag,
	    uint64_t ng, uint64_t mask, int max, uint512_t *chids);

	/**
	 * Iterate over all chids in specific TT
	 */
	int (*iterate_blobs)(struct repdev *dev, type_tag_t ttag,
		reptrans_blob_callback, void *param, int want_values,
		int strict_order, int max_blobs);

	/**
	 * Compactify the storage
	 */
	int (*compactify)(struct repdev* dev, type_tag_t ttag_req,
		size_t thd_mb, comp_cb_t cb);

	/**
	 * Synchronous request to the key-value driver to query if a blob with
	 * supplied key/ht exists or maybe exists.
	 *
	 * Return values:
	 *
	 *  0        - definetly not found
	 *  1        - maybe exists
	 * -1        - cannot say for sure, likely some error occured like
	 *             bloom filter is not loaded
	 * -EEXIST   - definetly exists
	 */
	int (*query_blob)(struct repdev *dev, type_tag_t ttag,
		crypto_hash_t hash_type, const uint512_t *key, uint64_t *outsize);

	int (*stat_blob)(struct repdev *dev, type_tag_t ttag,
		crypto_hash_t hash_type, const uint512_t *key,
		struct blob_stat *blob_stat);
	/**
     * Configuration read/write.
     * At the moment the configuation holds hashcount, object_size
     * and repdev's lifetime
     */
	int (*config)(struct repdev *dev, dev_cfg_op op,
		const uv_buf_t* key, uv_buf_t* value);
};


#ifdef __cplusplus
#if 0
extern "C" {
#endif
}
#endif
#endif /* __REPTRANS_DEVICE__H__ */
