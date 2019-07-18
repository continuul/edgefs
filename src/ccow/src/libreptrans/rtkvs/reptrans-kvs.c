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
#define REPTRANS_KVS_C	1

#include <stdio.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/xattr.h>
#include <linux/limits.h>
#include <uv.h>
#include <lmdb.h>
#include <fts.h>
#include <libgen.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <dlfcn.h>
#include <errno.h>
#include <mntent.h>
#include <endian.h>
#include <uthash.h>

#include "ccowutil.h"
#include "serverid.h"
#include "crypto.h"
#include "json.h"
#include "reptrans.h"
#include "reptrans-data.h"
#include "ccowd-impl.h"
#include <kvs-backend.h>


#define DEV_CREATED_TIMESTAMP "created-timestamp"
#define DEV_METADATA ".device-metadata"
#define DEV_HASHCOUNT_DIR "hashcount"
#define DEV_HASHCOUNT_PART_SIZE (8 * 1024 * 1024)
#define DEV_PARTS_DIR "parts"
#define DEV_PARTS_LEVEL_64	0x04
#define DEV_PARTS_LEVEL_128	0x08
#define DEV_PARTS_LEVEL_256	0x10
#define DEV_PARTS_LEVEL_512	0x10
#define DEV_PARTS_LEVEL_1024	0x10
#define DEV_PARTS_LEVEL_2048	0x10
#define DEV_PARTS_LEVEL_4096	0x10
#define DEV_PARTS_LEVEL_8192	0x20
#define DEV_PARTS_LEVEL_MAX	0x20
#define DEV_MAGIC "NEFMT1"
#define DEV_LMDB_MAXREADERS	512		/* LMDB default is 126 */
#define DEV_LMDB_LOG_MAPSIZE		(128ULL * 1024ULL * 1024ULL)
#define DEV_KVS_VERSION		1 /* current version of the lfs */

/* Maximum number of entries before we will start flushing into main TT
 * tables. Too low numbers will affect performance. Too high numbers will
 * increase flushing time and may introduce I/O drops. */
#define DEV_LMDB_LOG_MAXENTRIES		32

/* Maximum chunk size will be put into the LOG as a record rather then
 * directly into main TT data store. */
#define DEV_LMDB_LOG_MAXCHUNKSIZE	(6 * 1024 * 1024)

#define RT_LFS_HDD_LATENCY_US	200000
#define RT_LFS_SSD_LATENCY_US	50000

struct repdev_db;

#define BLOOM_STORE_OK "BLOOM_STORE_OK"

#define KEY_CACHE_MAX (64*1024*1024) / sizeof(key_cache_entry_t)

#define KVS_NO_FREE_SPACE(err) (err == MDB_MAP_FULL || err == -ENOSPC || err == MDB_MAP_RESIZED)

typedef enum {
	WAL_MODE_FULL = 0, /* All typetags goes trough WAL */
	WAL_MODE_SSD = 1, /* Only non-kvs typetags on SSD */
	WAL_MODE_DISABLED = 2 /* Don't use a WAL */
} kvs_wal_mode_t;

/* MD offload uses separate environment */
#define DEV_ENVS 2

/* do we need a ref count for these? */
typedef struct key_cache_entry {
	uint64_t key;
	uint32_t size;
	uint8_t ttag;
	UT_hash_handle hh;
} key_cache_entry_t;

typedef struct key_cache {
	uint32_t c; // capacity
	key_cache_entry_t *entries;
	uv_rwlock_t lock;
	key_cache_stat_t stats;
	void (*free_entry) (void *element); //cb to free items; optional
} key_cache_t;

struct repdev_db;
struct repdev_log
{
	MDB_env *env;
	MDB_dbi dbi[TT_LAST];
	char path[PATH_MAX];
	struct repdev_db *db;
	struct repdev *dev;
	pthread_t flush_thread;
	rtbuf_t *delete_rbkeys;
	type_tag_t ttag;
	uint64_t flushed_timestamp;
};

struct repdev_db
{
	int part;
	MDB_env *env;
	MDB_dbi dbi[TT_LAST];
	struct repdev_log log;
	struct repdev *dev;
	uint8_t *bloom;
	hashtable_t *keyht[TT_LAST];
	pthread_t bloom_load_thread;
	uv_rwlock_t bloom_lock;
	volatile long bloom_loaded;
	unsigned long log_flush_cnt;
	uv_mutex_t log_flush_lock;
	uv_cond_t log_flush_condvar;
	key_cache_t *key_cache;
	size_t size[TT_LAST];
	size_t entries[TT_LAST];
};

struct repdev_kvs
{
	struct repdev_db *db;
	uint64_t hashcount_last;	/* hashcount last flush timestamp */
	int newdev;
	int zerocopy;
	int sync;
	int readahead;
	int direct;
	int plevel;
	size_t ssd_part_size;
	uint64_t bloom_ttag_put_counter;
	kvs_backend_handle_t be_inst;
	kvs_backend_t* backend;
	kvs_backend_info_t be_info;
};

/*
 * Im very sorry for this but at the moment we dont have a common
 * part of libreptrans e.g a libreptrans/rdcommon. This results
 * in some duplicate code and in certain cases double effort when adding
 * new features. we should really think about spending some time and create
 * a proper abstraction to avoid duplicate code between the drivers
 */

typedef enum partition_walk {
	PART_WALK_CONTINUE,
	PART_WALK_TERMINATE,
	PART_WALK_COMPLETED
} part_walk_action_t;

/* generic callback to walk partitions of a given device */
typedef part_walk_action_t (*partition_walk_f)(struct repdev_db *db, void *arg);

part_walk_action_t kvs_partition_walk(struct repdev *dev,
				 partition_walk_f func, void *arg);

int key_cache_ini(key_cache_t **cache, const uint32_t c,
				  void (*free_entry)(void *element));

int key_cache_fini(key_cache_t *cache);

int key_cache_insert(key_cache_t *c, uint64_t *key, type_tag_t ttag,
					 uint32_t size);

int key_cache_lookup(key_cache_t *c, uint64_t *key, type_tag_t ttag, uint64_t *result);

int key_cache_remove(key_cache_t *c, uint64_t *key, type_tag_t ttag);

int
kvs_dev_load_bloom(struct repdev *rdev);

int
kvs_dev_quiesce_bloom(struct repdev *rdev);


#include <errno.h>
#include "kvs-backend.h"

static void *kvs_lib_handle = NULL;

static kvs_backend_t*
kvs_backend_get(const char* name) {
	char lib_name[256];
	char sym_name[256];

	kvs_backend_t* res = NULL;
	sprintf(lib_name, "lib%s_backend.so", name);
	kvs_lib_handle = dlopen(lib_name, RTLD_LAZY | RTLD_LOCAL);
	if (!kvs_lib_handle) {
		char *errstr = dlerror();
		log_error(lg, "Cannot open backend library %s", lib_name);
		return NULL;
	}
	sprintf(sym_name, "%s_vtbl", name);
	res = dlsym(kvs_lib_handle, sym_name);
	if (!res)
		log_error(lg, "Cannot export a vtbl from %s", lib_name);
	if (strcmp(res->name, name))
		log_warn(lg, "Backend name mismatch: %s vs %s", name, res->name);
	return res;
}

static void
kvs_bm_exit() {
	if (kvs_lib_handle)
		dlclose(kvs_lib_handle);
}

static void
uint128_serialize(const uint128_t* val, uint8_t* buf) {
	*(uint64_t*)buf = htobe64(val->u);
	*((uint64_t*)buf + 1) = htobe64(val->l);
}

static void
uint128_deserialize(const uint8_t* buf, uint128_t* val) {
	val->u = be64toh(*(uint64_t*)buf);
	val->l = be64toh(*((uint64_t*)buf+1));
}

static void
uint256_serialize(const uint256_t* val, uint8_t* buf) {
	uint128_serialize(&val->u, buf);
	uint128_serialize(&val->l, buf + sizeof(uint64_t)*2);
}

static void
uint256_deserialize(const uint8_t* buf, uint256_t* val) {
	uint128_deserialize(buf, &val->u);
	uint128_deserialize(buf + sizeof(uint64_t)*2, &val->l);
}

static void
uint512_serialize(const uint512_t* val, uint8_t* buf) {
	uint256_serialize(&val->u, buf);
	uint256_serialize(&val->l, buf + sizeof(uint64_t)*4);
}

static void
uint512_deserialize(const uint8_t* buf, uint512_t* val) {
	uint256_deserialize(buf, &val->u);
	uint256_deserialize(buf + sizeof(uint64_t)*4, &val->l);
}

#define KVS_KEY_HDR_SIZE 2
static int
kvs_key_serialize(const uint512_t* chid, crypto_hash_t ht, const uint64_t* dupkey,
	uv_buf_t* keybuf) {
	/**
	* The key has a 2 bytes header:
	* byte0:
	*  bit[0] - Dupsort key support: 0 -> non-dupsort key, 1 -> dupsort
	*  bits[1..4] - hash type
	 *
	 */
	uint8_t hdr[KVS_KEY_HDR_SIZE] = {0};
	unsigned char chid_buf[sizeof(uint512_t)];
	size_t chid_size = 0;
	switch(ht) {
		case HASH_TYPE_BLAKE2B_512:
		case HASH_TYPE_SHA_512:
		case HASH_TYPE_EDONR_512:
		case HASH_TYPE_BLAKE2BP_512:
			uint512_serialize(chid, chid_buf);
			chid_size = sizeof(uint512_t);
			break;

		case HASH_TYPE_BLAKE2B_256:
		case HASH_TYPE_SHA_256:
		case HASH_TYPE_EDONR_256:
		case HASH_TYPE_XXHASH_256:
		case HASH_TYPE_BLAKE2BP_256:
			uint256_serialize(&chid->u, chid_buf);
			chid_size = sizeof(uint256_t);
			break;

		case HASH_TYPE_XXHASH_128:
			uint128_serialize(&chid->u.u, chid_buf);
			chid_size = sizeof(uint128_t);
			break;

		case HASH_TYPE_XXHASH_64:
			*(uint64_t*)chid_buf = htobe64(chid->u.u.u);
			chid_size = sizeof(uint64_t);
			break;

		default:
			return -EINVAL;
	}
	/* Compressed key size */
	/* Prepare a header */
	if (dupkey)
		hdr[0] |= 1;
	hdr[0] |= ht << 1;
	/* Serialize */
	keybuf->len = KVS_KEY_HDR_SIZE + (dupkey ? sizeof(uint64_t) : 0) + chid_size;
	keybuf->base = je_malloc(keybuf->len);
	if (!keybuf->base)
		return -ENOMEM;
	memcpy(keybuf->base, hdr, KVS_KEY_HDR_SIZE);
	memcpy(keybuf->base+KVS_KEY_HDR_SIZE, chid_buf, chid_size);
	if (dupkey) {
		uint64_t dk_be = htobe64(*dupkey);
		memcpy(keybuf->base+KVS_KEY_HDR_SIZE+chid_size, &dk_be, sizeof(uint64_t));
	}
	return 0;
}

static int
kvs_key_deserialize(uv_buf_t keybuf, uint512_t* chid_out, crypto_hash_t* ht_out, uint64_t* dupkey_out) {
	uint8_t hdr = keybuf.base[0];
	uint512_t chid = {0};
	size_t chid_size = 0;
	crypto_hash_t ht = 0x0f & (hdr >> 1);
	switch(ht) {
		case HASH_TYPE_BLAKE2B_512:
		case HASH_TYPE_SHA_512:
		case HASH_TYPE_EDONR_512:
		case HASH_TYPE_BLAKE2BP_512:
			uint512_deserialize((uint8_t*)keybuf.base + KVS_KEY_HDR_SIZE, &chid);
			chid_size = sizeof(uint512_t);
			break;

		case HASH_TYPE_BLAKE2B_256:
		case HASH_TYPE_SHA_256:
		case HASH_TYPE_EDONR_256:
		case HASH_TYPE_XXHASH_256:
		case HASH_TYPE_BLAKE2BP_256:
			uint256_deserialize((uint8_t*)keybuf.base + KVS_KEY_HDR_SIZE, &chid.u);
			chid_size = sizeof(uint256_t);
			break;

		case HASH_TYPE_XXHASH_128:
			uint128_deserialize((uint8_t*)keybuf.base + KVS_KEY_HDR_SIZE, &chid.u.u);
			chid_size = sizeof(uint128_t);
			break;

		case HASH_TYPE_XXHASH_64:
			chid.u.u.u = be64toh(*(uint64_t*)(keybuf.base + KVS_KEY_HDR_SIZE));
			chid_size = sizeof(uint64_t);
			break;

		default:
			return -EINVAL;
	}
	if (dupkey_out && (hdr & 1))
		*dupkey_out = be64toh(*(uint64_t*)(keybuf.base + KVS_KEY_HDR_SIZE + chid_size));
	*chid_out = chid;
	*ht_out = ht;
	return 0;
}

static int
is_kvs_offload_tt(type_tag_t ttag) {
	int rc = 0;
	switch (ttag) {
		case TT_VERSION_MANIFEST:
		case TT_CHUNK_MANIFEST:
		case TT_CHUNK_PAYLOAD:
		case TT_PARITY_MANIFEST:
			rc = 1;
			break;

		default:
			rc = 0;
	}
	return rc;
}

static inline int
is_log_tt(struct repdev *dev, type_tag_t ttag)
{
	if (dev->wal_disabled == WAL_MODE_DISABLED)
		return 0;
	else if (dev->wal_disabled == WAL_MODE_SSD)
		return is_kvs_offload_tt(ttag) == 0;
	else switch (ttag) {
		case TT_NAMEINDEX:
		case TT_VERIFIED_BACKREF:
		case TT_VERIFICATION_QUEUE:
		case TT_REPLICATION_QUEUE:
		case TT_BATCH_QUEUE:
		case TT_BATCH_INCOMING_QUEUE:
		case TT_VERSION_MANIFEST:
		case TT_CHUNK_MANIFEST:
		case TT_CHUNK_PAYLOAD:
		case TT_TRANSACTION_LOG:
		case TT_PARITY_MANIFEST:
		case TT_ENCODING_QUEUE:
			return 1;
		default:
			return 0;
	}
}

/** Compare two backref-like items */
static int
kvs_lmdb_vbr_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return vbr_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}


/** Compare two batch items */
static int
kvs_lmdb_batch_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return batch_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}


/** Compare two TT_NAMEINDEX items, match UVIDs and GenIDs in reverse order */
static int
kvs_lmdb_nameindex_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return nameindex_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** Compare two items lexically */
static int
kvs_lmdb_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return generic_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

static inline MDB_cmp_func*
kvs_lmdb_cmp_ttag(type_tag_t ttag) {
	assert(is_dupsort_tt(ttag));
	switch (ttag) {
		case TT_NAMEINDEX:
			return kvs_lmdb_nameindex_cmp;
		case TT_VERIFIED_BACKREF:
			return kvs_lmdb_vbr_cmp;
		case TT_BATCH_QUEUE:
			return kvs_lmdb_batch_cmp;
		default:
			return kvs_lmdb_cmp;
	}
}


static int
kvs_get_mountpoint_by_name(const char* disk_name, char* mount_point, size_t max_len) {
	struct mntent *ent;
	struct mntent mnt;
	FILE *aFile;
	char path[PATH_MAX];
	int rc = -ENOTDIR;
	sprintf(path, "/dev/disk/by-id/%s", disk_name);
	char* realPath = realpath(path, NULL);
	if (!realPath) {
		log_error(lg, "Cannot resolve kernel device name for %s", disk_name);
		return -ENOENT;
	}

	aFile = setmntent("/proc/mounts", "r");
	if (aFile == NULL) {
		free(realPath);
		return -ENOENT;
	}

	while (NULL != (ent = getmntent_r(aFile, &mnt, path, sizeof(path)))) {
		if (!strcmp(ent->mnt_fsname, realPath)) {
			strncpy(mount_point, ent->mnt_dir, max_len);
			rc = 0;
			break;
		}
	}
	endmntent(aFile);
	free(realPath);
	return rc;
}

static void
kvs_bloom_wait(struct repdev_db *db)
{
	/* let bloom load threads finish. */
	uv_rwlock_rdlock(&db->bloom_lock);
	while (db->bloom_load_thread && !db->bloom_loaded) {
		uv_rwlock_rdunlock(&db->bloom_lock);
		usleep(100);
		uv_rwlock_rdlock(&db->bloom_lock);
	}
	uv_rwlock_rdunlock(&db->bloom_lock);
}

static inline void
kvs_bloom_insert(struct repdev_db *db, uint64_t key)
{
	uv_rwlock_wrlock(&db->bloom_lock);
	KEY_BLOOM_ADD(db->bloom, (uint32_t)(key>>32U));
	uv_rwlock_wrunlock(&db->bloom_lock);
}

static inline int
kvs_bloom_query(struct repdev_db *db, uint64_t key)
{
	int rc;

	if (db->bloom_loaded <= 0)
		return -1;

	uv_rwlock_rdlock(&db->bloom_lock);
	rc = KEY_BLOOM_TEST(db->bloom, (uint32_t)(key>>32U));
	uv_rwlock_rdunlock(&db->bloom_lock);

	return rc;
}

int
key_cache_ini(key_cache_t **cache, const uint32_t c,
			  void (*free_entry)(void *element)) {

	assert(c != 0);
	key_cache_t *new = NULL;

	if (cache == NULL)
		return -EINVAL;
	if ((new = je_malloc(sizeof(*new))) == NULL)
		return -ENOMEM;
	if (uv_rwlock_init(&new->lock) != 0) {
		je_free(new);
		return -ENOMEM;
	}

	new->c = c;
	new->entries = NULL;
	new->free_entry = free_entry;
	new->stats.hit = 0;
	new->stats.miss = 0;
	new->stats.evicted = 0;
	*cache = new;
	return 0;
}

int
key_cache_fini(key_cache_t *cache) {

	key_cache_entry_t *entry, *tmp = NULL;

	if (cache == NULL)
		return -EINVAL;

	uv_rwlock_wrlock(&cache->lock);

	HASH_ITER(hh, cache->entries, entry, tmp) {
		HASH_DEL(cache->entries, entry);
		je_free(entry);
	}

	uv_rwlock_wrunlock(&cache->lock);
	uv_rwlock_destroy(&cache->lock);
	je_free(cache);
	return 0;
}

int
key_cache_insert(key_cache_t *c, uint64_t *key, type_tag_t ttag,
				 uint32_t size) {

	key_cache_entry_t *t = NULL;
	key_cache_entry_t *e = NULL;

	if (c == NULL)
		return -EINVAL;

	uv_rwlock_wrlock(&c->lock);
	HASH_FIND_INT64(c->entries, key, t);

	if (t != NULL) {
		uv_rwlock_wrunlock(&c->lock);
		return -EEXIST;
	}

	if ((e = je_malloc(sizeof(*e))) == NULL) {
		uv_rwlock_wrunlock(&c->lock);
		return -ENOMEM;
	}

	e->key = *key;
	e->size = size;
	e->ttag = ttag;

	HASH_ADD_INT64(c->entries, key, e);

	if (HASH_COUNT(c->entries) >= c->c) {
		HASH_ITER(hh, c->entries, e, t) {
			HASH_DELETE(hh, c->entries, e);
			je_free(e);
			c->stats.evicted++;
			break;
		}
	}
	uv_rwlock_wrunlock(&c->lock);
	return 0;
}

int
key_cache_lookup(key_cache_t *c, uint64_t *key, type_tag_t ttag,
				 uint64_t *result) {

	key_cache_entry_t *e = NULL;
	int rv = 0;

	if (c == NULL || key == NULL || result == NULL)
		return -EINVAL;

	uv_rwlock_wrlock(&c->lock);

	HASH_FIND_INT64(c->entries, key, e);

	if (e != NULL && e->ttag == ttag) {
		/* LRUing by deleting and re-inserting it to head */
		HASH_DELETE(hh, c->entries, e);
		HASH_ADD_INT64(c->entries, key, e);
		/* because of macro magic */
		*result = e->size;
		c->stats.hit++;
	} else {
		*result = 0;
		c->stats.miss++;
		rv = -ENOENT;
	}

	uv_rwlock_wrunlock(&c->lock);
	return rv;
}

int
key_cache_remove(key_cache_t *c, uint64_t *key, type_tag_t ttag) {

	key_cache_entry_t *e = NULL;
	int rc = 0;

	if (c == NULL)
		return -EINVAL;
	uv_rwlock_wrlock(&c->lock);
	HASH_FIND_INT64(c->entries, key, e);

	if (e != NULL && e->ttag == ttag) {
		HASH_DELETE(hh, c->entries, e);
		je_free(e);
	} else {
		rc = -ENOENT;
	}
	uv_rwlock_wrunlock(&c->lock);
	return rc;
}

static inline void
kvs_keycache_insert(struct repdev_db *db, uint64_t key, type_tag_t ttag, uint64_t size)
{
	int err;

	if (!db->dev->keycache_enabled)
		return;

	uv_rwlock_wrlock(&db->bloom_lock);
	err = hashtable_put(db->keyht[ttag], &key, sizeof (uint64_t), &size, sizeof(uint64_t));
	uv_rwlock_wrunlock(&db->bloom_lock);
	assert(err == 0);
}

static inline void
kvs_keycache_remove(struct repdev_db *db, uint64_t key, type_tag_t ttag)
{
	if (!db->dev->keycache_enabled)
		return;

	uv_rwlock_wrlock(&db->bloom_lock);
	hashtable_remove(db->keyht[ttag], &key, sizeof (uint64_t));
	uv_rwlock_wrunlock(&db->bloom_lock);
}

static inline int
kvs_keycache_query(struct repdev_db *db, uint64_t key, type_tag_t ttag, uint64_t *outsize)
{
	uv_rwlock_rdlock(&db->bloom_lock);
	size_t value_size;
	void *value = hashtable_get(db->keyht[ttag], &key, sizeof (uint64_t), &value_size);
	if (value)
		*outsize = *(uint64_t *) value;
	else
		*outsize = 0;
	uv_rwlock_rdunlock(&db->bloom_lock);
	return value ? -EEXIST : 0;
}

static int kvs_log_flush(struct repdev_log *log, type_tag_t ttag);
static void kvs_log_flush_wait(struct repdev_db *db, type_tag_t ttag);

void
kvs_keyht_func32(const void *key, int length, uint32_t seed, void *out)
{
	/* keyht is 64bit hash already, so just convert it to 32bit */
	*(uint32_t *)out = *(uint64_t *)key;
}

static void *
kvs_partition_flush(void *arg) {

	struct repdev_db *db = arg;
	struct repdev *dev = db->dev;
	int err = 0;
	uint64_t before = uv_hrtime();

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return NULL;

	for (type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ++ttag) {

		if (dev->terminating)
			break;

		/*
		 * Flush this TT on start...
		 */
		err = 0;
		if (is_log_tt(dev, ttag)) {
			struct repdev_log *log = &db->log;
			err = kvs_log_flush(log, ttag);
			if (!err) {
				kvs_log_flush_wait(db, ttag);
				status = reptrans_dev_get_status(dev);
				if (status == REPDEV_STATUS_UNAVAILABLE)
					err = -ENODEV;
			}
			if (err)
				break;
		}
		if (err) {
			/* device is marked as readonly or unavail */
			if (status == REPDEV_STATUS_UNAVAILABLE)
				break;
		}
	}

	log_info(lg, "Dev(%s/%02d): flushed log"
			" (took ~ %"
			PRIu64
			" ms), err: %d", dev->name, db->part,
			(uv_hrtime() - before) / 1000000, err);

	return NULL;
}

/*
 * Compact encoded key into 64bit unique value.
 *
 * @param key      in/out. Will hash it, and will set it back to a new value
 * @param out      temporary uint64_t as a holder for a key buffer
 * @return 0 success, failure otherwise
 */
static inline int
kvs_keyhash(struct repdev *dev, MDB_val *key, MDB_val *key_out, uint64_t *out)
{
	int err;
	uint512_t chid;
	crypto_hash_t key_hash_type;
	type_tag_t key_ttag;
	uv_buf_t uk = {.base = key->mv_data, .len = key->mv_size};

	err = kvs_key_deserialize(uk, &chid, &key_hash_type, NULL);
	if (err)
		return err;

	*out = chid.u.u.u;
	key_out->mv_data = out;
	key_out->mv_size = sizeof (uint64_t);
	return 0;
}

static void *
kvs_bloom_load(void *arg)
{
	struct repdev_db *db = arg;
	struct repdev *dev = db->dev;
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;
	int err = 0;
	uint64_t entries = 0;
	uint64_t before = uv_hrtime();

	for (type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ++ttag) {

		if (dev->terminating)
			break;
		if (dev->rt->init_traits) {
			struct ccowd_params* params = dev->rt->init_traits;
			if (params->log_flush)
				continue;
		}

		if (!dev->bloom_enabled) {
			db->bloom_loaded = -1;
			continue;
		}

		if (!is_keycache_tt(ttag) && ttag != TT_NAMEINDEX)
			continue;

		MDB_env *env = db->env;

		MDB_dbi dbi = db->dbi[ttag];

		err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
		if (err) {
			log_error(lg, "Get(%s): cannot begin txn bloom_load: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			goto _exit;
		}

		err = mdb_cursor_open(txn, dbi, &cursor);
		if (err) {
			log_error(lg, "Get(%s): cannot open cursor bloom_load: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			goto _exit;
		}

		int op = MDB_FIRST;
		MDB_val key;
		MDB_val val;
		MDB_val* vptr = is_kvs_offload_tt(ttag) ? &val : NULL;
		db->size[ttag] = 0;
		db->entries[ttag] = 0;
		while ((err = mdb_cursor_get(cursor, &key, vptr, op)) == 0) {
			op = (ttag == TT_NAMEINDEX) ? MDB_NEXT_NODUP : MDB_NEXT;
			MDB_val keyhv;
			uint64_t kh;
			err = kvs_keyhash(dev, &key, &keyhv, &kh);
			if (err)
				goto _exit;

			kvs_bloom_insert(db, kh);
			entries++;

			if (vptr) {
				uint64_t size = 0;
				assert(vptr->mv_size == sizeof(uint64_t));
				memcpy(&size, vptr->mv_data, vptr->mv_size);
				db->size[ttag] += size;
				db->entries[ttag]++;
			}
			if (dev->terminating)
				break;

			if (is_hashcount_data_type_tag(ttag)) {
				uint512_t chid = uint512_null;
				chid.u.u.u = kh;
				size_t hc_cnt = 1;
				if (ttag == TT_NAMEINDEX)
					mdb_cursor_count(cursor, &hc_cnt);
				reptrans_bump_hashcount(dev, &chid, hc_cnt);
			}
		}

		mdb_cursor_close(cursor);
		cursor = NULL;

		mdb_txn_abort(txn);
		txn = NULL;
		err = 0;
	}

_exit:
	if (cursor)
		mdb_cursor_close(cursor);
	if (txn)
		mdb_txn_abort(txn);

	log_debug(lg, "Dev(%s/%02d): loaded %ld bloom filter keys"
	    " (took ~ %"PRIu64" ms), err: %d", dev->name, db->part, entries,
	    (uv_hrtime() - before) / 1000000, err);

	if (!err && db->bloom_loaded == 0 && !dev->terminating) {
		db->bloom_loaded = 1;
	} else {
		log_error(lg, "bloom loading failed, no bloom available for "
			"Dev(%s)", dev->name);
		db->bloom_loaded = -1;
	}

	return NULL;
}

static void
kvs_lmdb_close(struct repdev_db *db);

static int
kvs_log_open(struct repdev *dev, const char *path, struct repdev_db *db)
{
	int err;
	struct stat st;
	MDB_txn *txn;
	struct repdev_kvs *kvs = dev->device_lfs;
	struct repdev_log *log = &db->log;

	assert(!log->env);

	sprintf(log->path, "%s.mdb", path);

	/*
	 * Journal log key/value data store (small footprint)
	 */
	err = mdb_env_create(&log->env);
	if (err) {
		log_error(lg, "Dev(%s): cannot create log mdb env: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	mdb_env_set_mapsize(log->env, DEV_LMDB_LOG_MAPSIZE);
	mdb_env_set_maxreaders(log->env, DEV_LMDB_MAXREADERS);

	err = mdb_env_set_maxdbs(log->env, TT_LAST);
	if (err) {
		log_error(lg, "Dev(%s): cannot set maxdbs: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	int rt_flags = dev->rt->flags;
	int sync_flag = kvs->sync == 0 ? MDB_NOSYNC :
		(kvs->sync == 1 ? MDB_NOSYNC :
		 (kvs->sync == 2 ? MDB_NOMETASYNC : 0));
	int env_opt = MDB_NOTLS | sync_flag \
		      | MDB_NOSUBDIR | MDB_NORDAHEAD;
	if (rt_flags & RT_FLAG_RDONLY)
		env_opt |= MDB_RDONLY;
	else {
		char fname[PATH_MAX];
		sprintf(fname, "rm -f %s-lock", log->path);
		err = system(fname);
	}
#ifdef CCOW_VALGRIND
	if (RUNNING_ON_VALGRIND) {
		env_opt &= ~MDB_NOMEMINIT;
	}
#endif

	err = mdb_env_open(log->env, log->path, env_opt, 0664);
	if (err) {
		log_error(lg, "Dev(%s): cannot open log, path=%s "
		    "mdb env: (%d) %s", dev->name, log->path,
		    err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	/*
	 * Initialize/Open journal log data store now
	 */

	err = mdb_txn_begin(log->env, NULL,
			rt_flags & RT_FLAG_RDONLY ? MDB_RDONLY : 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot begin mdb txn: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	for(type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		int flags = 0;
		char dbi_name[8];

		if (!is_log_tt(dev, ttag))
			continue;

		if (!(rt_flags & RT_FLAG_RDONLY) && (rt_flags & RT_FLAG_CREATE))
			flags = MDB_CREATE;

		if (is_dupsort_tt(ttag))
			flags |= MDB_DUPSORT;

		sprintf(dbi_name, "%d", ttag);
		err = mdb_dbi_open(txn, dbi_name, flags, &log->dbi[ttag]);
		if (err) {
			mdb_txn_abort(txn);
			log_error(lg, "Dev(%s): cannot open mdb: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
		log->db = db;
		log->dev = dev;

		if (is_dupsort_tt(ttag)) {
			err = mdb_set_dupsort(txn, log->dbi[ttag],
			    kvs_lmdb_cmp_ttag(ttag));
			assert(err == 0);
		}
	}

	err = mdb_txn_commit(txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot commit changes to log %s: (%d) %s",
		    dev->name, log->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	mdb_env_sync(log->env, 1);

	return 0;

_exit:
	kvs_lmdb_close(db);
	return err;
}

static void
kvs_log_close(struct repdev *dev, struct repdev_db *db)
{
	struct repdev_log *log = &db->log;

	for (int ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (!is_log_tt(dev, ttag))
			continue;
		if (log->dbi[ttag]) {
			mdb_dbi_close(log->env, log->dbi[ttag]);
			log->dbi[ttag] = 0;
		}
	}
	if (log->env) {
		mdb_env_close(log->env);
		log->env = NULL;
	}
}

static void
kvs_log_flush_wait(struct repdev_db *db, type_tag_t ttag)
{
	/* let flush threads finish. */
	uv_mutex_lock(&db->log_flush_lock);

	while (db->log_flush_cnt != 0)
		uv_cond_wait(&db->log_flush_condvar, &db->log_flush_lock);

	uv_mutex_unlock(&db->log_flush_lock);
}

static void
kvs_log_flush_barrier(struct repdev_db *db, type_tag_t ttag, int set)
{
	uv_mutex_lock(&db->log_flush_lock);
	if (set) {
		/*
		 * Trying to acquire the lock
		 * let flush threads finish.
		 * */
		while (db->log_flush_cnt != 0)
			uv_cond_wait(&db->log_flush_condvar,
			    &db->log_flush_lock);
		db->log_flush_cnt = 1;
	} else {
		/* Got here if we set the lock previously */
		assert(db->log_flush_cnt);
		db->log_flush_cnt = 0;
		/* Inform we are done */
		uv_cond_broadcast(&db->log_flush_condvar);
	}
	uv_mutex_unlock(&db->log_flush_lock);
}

static void
kvs_lmdb_close(struct repdev_db *db)
{
	int i;
	struct repdev *dev = db->dev;

	for (i = TT_NAMEINDEX; i < TT_LAST; ++i) {
		if (db->dbi[i]) {
			if (is_log_tt(dev, i))
				kvs_log_flush_wait(db, i);
			mdb_dbi_close(db->env, db->dbi[i]);
		}
		if (db->keyht[i])
			hashtable_destroy(db->keyht[i]);
	}
	mdb_env_close(db->env);
	db->env = NULL;
	if (dev->wal_disabled != WAL_MODE_DISABLED) {
		kvs_log_close(dev, db);
	}
	uv_rwlock_destroy(&db->bloom_lock);
	je_free(db->bloom);
	key_cache_fini(db->key_cache);
}

static int
kvs_lmdb_oomfunc(MDB_env *env, int pid, void* thread_id, size_t txn, unsigned gap,
    int retry)
{
	log_notice(lg, "Detected laggard reader PID=%d TID=%p TXN=%lu GAP=%u retry=%d",
	    pid, thread_id, txn, gap, retry);
	return 0;
}

static int
kvs_lmdb_init(struct repdev_kvs *kvs, char* path, struct repdev_db *db, uint64_t part_size,
	uint32_t rt_flags) {
	struct repdev* dev = db->dev;
	char fname[PATH_MAX];
	int err = 0;
	MDB_txn *main_txn = NULL;

	if (!db->env) {
		/*
		 * Main key/value data store
		 */
		err = mdb_env_create(&db->env);
		if (err) {
			log_error(lg, "Dev(%s): cannot create mdb env: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}

		mdb_env_set_mapsize(db->env, part_size);

		mdb_env_set_maxreaders(db->env, DEV_LMDB_MAXREADERS);

		err = mdb_env_set_maxdbs(db->env, TT_LAST);
		if (err) {
			log_error(lg, "Dev(%s): cannot set maxdbs: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}

		mdb_env_set_oomfunc(db->env, kvs_lmdb_oomfunc);

		int sync_flag = kvs->sync == 0 ? MDB_NOSYNC :
			(kvs->sync == 1 ? (kvs->direct ? MDB_NOSYNC : MDB_NOMETASYNC) :
			 (kvs->sync == 2 ? MDB_NOMETASYNC : 0));
		int rdahead_flag = kvs->readahead ? 0 : MDB_NORDAHEAD;
		int direct_flag = kvs->direct ? MDB_DIRECT : 0;
		int env_opt = MDB_COALESCE | MDB_LIFORECLAIM | MDB_NOTLS | sync_flag \
			      | MDB_NOSUBDIR | rdahead_flag | direct_flag;
		if (rt_flags & RT_FLAG_RDONLY)
			env_opt |= MDB_RDONLY;
		else {
			sprintf(fname, "rm -f %s/main/%s/%02x/main.mdb-lock", path, DEV_PARTS_DIR, db->part);
			err = system(fname);
		}
#ifdef CCOW_VALGRIND
		if (RUNNING_ON_VALGRIND) {
			env_opt &= ~MDB_NOMEMINIT;
		}
#endif

		sprintf(fname, "%s/main/%s/%02x/main.mdb", path, DEV_PARTS_DIR, db->part);
		err = mdb_env_open(db->env, fname, env_opt, 0664);
		if (err) {
			log_error(lg, "Dev(%s): cannot open, path=%s "
			    "mdb env: (%d) %s", dev->name, fname,
			    err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
	}

	/*
	 * Initialize/Open main data store now
	 */
	err = mdb_txn_begin(db->env, NULL,
		rt_flags & RT_FLAG_RDONLY ? MDB_RDONLY : 0, &main_txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot begin mdb txn: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	for (type_tag_t ttag = TT_NAMEINDEX;  ttag < TT_LAST; ++ttag) {
		int flags = 0;
		MDB_txn* txn = main_txn;

		if (!(rt_flags & RT_FLAG_RDONLY) && (rt_flags & RT_FLAG_CREATE))
			flags = MDB_CREATE;

		if (is_dupsort_tt(ttag))
			flags |= MDB_DUPSORT;

		MDB_dbi* pdbi = &db->dbi[ttag];

		err = mdb_dbi_open(txn, type_tag_name[ttag], flags, pdbi);
		if (err) {
			log_error(lg, "Dev(%s): cannot open mdb: %s (%d) %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
			err = -EIO;
			break;
		}

		if (is_dupsort_tt(ttag)) {
			err = mdb_set_dupsort(txn, db->dbi[ttag],
			    kvs_lmdb_cmp_ttag(ttag));
			assert(err == 0);
		}
	}
	if (!err) {
		if (main_txn) {
			err = mdb_txn_commit(main_txn);
			if (err) {
				log_error(lg, "Dev(%s): cannot commit to mdb: (%d) %s",
				    dev->name, err, mdb_strerror(err));
				err = -EIO;
				goto _exit;
			}
		}
		mdb_env_sync(db->env, 1);
	} else {
		if (main_txn)
			mdb_txn_abort(main_txn);
		goto _exit;
	}


	return 0;

_exit:
	kvs_lmdb_close(db);
	return err;
}


static int
kvs_lmdb_metacheck(struct repdev_kvs *kvs, char *devname, uv_buf_t *mbuf,
    int formatted, uint32_t flags)
{
	int err;
	MDB_txn *txn;
	MDB_val key, data;
	struct repdev_db *db = kvs->db;

	if (formatted) {
		/*
		 * Read metadata and compare to the one in metadata file
		 */

		err = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn);
		if (err) {
			log_error(lg, "metacheck mdb_txn_begin: (%d) %s\n", err,
				mdb_strerror(err));
			return -EIO;
		}

		key.mv_size = strlen(DEV_METADATA);
		key.mv_data = DEV_METADATA;

		err = mdb_get(txn ,db->dbi[TT_HASHCOUNT], &key, &data);
		if (err == MDB_NOTFOUND) {
			mdb_txn_abort(txn);
			if (kvs->newdev)
				log_error(lg, "Dev(%s): data store not fully "
					"initialized: can't find hashcount/TT_HASHCOUNT.mdb file",
					devname);
			else
				log_error(lg, "Dev(%s): data store corrupted "
					"or not initialized: (%d) %s", devname, err,
					mdb_strerror(err));
			return -ENOENT;
		}

		if (strncmp(DEV_MAGIC, data.mv_data, strlen(DEV_MAGIC)) != 0) {
			mdb_txn_abort(txn);
			log_error(lg, "Dev(%s): wrong index magic", devname);
			err = -EBADF;
			return err;
		}

		mdb_txn_abort(txn);

		log_info(lg, "Dev(%s): data store ready", devname);
		return 0;
	}

	if ((flags & RT_FLAG_RDONLY) || !(flags & RT_FLAG_CREATE))
		return -EACCES;

	err = mdb_txn_begin(db->env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): mdb_txn_begin: (%d) %s",
			devname, err, mdb_strerror(err));
		return -EIO;
	}

	key.mv_size = strlen(DEV_METADATA);
	key.mv_data = DEV_METADATA;
	data.mv_size = strlen(DEV_MAGIC) + mbuf->len + 1;

	err = mdb_put(txn, db->dbi[TT_HASHCOUNT], &key, &data, MDB_RESERVE);
	if (err) {
		mdb_txn_abort(txn);
		log_error(lg, "Dev(%s): %s mdb_put: (%d) %s", devname,
			type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err));
		return -EIO;
	}

	strcpy(data.mv_data, DEV_MAGIC);
	memcpy((char *)data.mv_data + strlen(DEV_MAGIC) + 1, mbuf->base,
		mbuf->len);

	err = mdb_txn_commit(txn);
	if (err) {
		log_error(lg, "Dev(%s): %s mdb_txn_commit: (%d) %s",
			devname, type_tag_name[TT_HASHCOUNT], err,
			mdb_strerror(err));
		return -EIO;
	}

	mdb_env_sync(db->env, 1);

	return 0;
}

static int
kvs_lmdb_stat(struct repdev *dev)
{
	int err = 0;
	MDB_txn *main_txn;
	struct repdev_db *db = NULL;
	struct repdev_kvs *kvs = dev->device_lfs;

	uint64_t rep_entries = 0;
	uint64_t ver_entries = 0;
	uint64_t entries = 0;
	uint64_t used_space = 0;
	uint64_t free_space = 0;
	uint64_t data_used_space = 0;
	uint64_t physical_capacity = 0;
	uint64_t capacity = 0;

	struct statvfs s;

	repdev_status_t status;
	status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;



	physical_capacity = kvs->ssd_part_size * kvs->plevel;
	capacity += kvs->be_info.capacity;
	physical_capacity += kvs->be_info.capacity;

	key_cache_stat_t keycache_stats_aggr = { 0, 0, 0 };
	size_t ttag_entries[TT_LAST] = {0};
	size_t ttag_size[TT_LAST] = {0};

	for (int j = 0; j < kvs->plevel; ++j) {
		db = kvs->db + j;


		keycache_stats_aggr.hit += db->key_cache->stats.hit;
		keycache_stats_aggr.miss += db->key_cache->stats.miss;
		keycache_stats_aggr.evicted += db->key_cache->stats.evicted;

		int rc = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &main_txn);
		if (rc) {
			err = -EIO;
			break;
		}

		for (size_t tt = TT_NAMEINDEX; !err && tt < TT_LAST; tt++) {
			if (is_kvs_offload_tt(tt)) {
				ttag_size[tt] += db->size[tt];
				ttag_entries[tt] += db->entries[tt];
				continue;
			}
			MDB_stat mst;
			MDB_txn* txn = main_txn;
			if (!is_kvs_offload_tt(tt)) {
				rc = mdb_stat(txn, db->dbi[tt], &mst);
				if (rc)
					err = -EIO;
				else {
					ttag_entries[tt] += mst.ms_entries;
					ttag_size[tt] +=  mst.ms_psize *
						(mst.ms_branch_pages + mst.ms_leaf_pages +
						mst.ms_overflow_pages);
				}
			}
		}
		mdb_txn_abort(main_txn);
	}
	for (size_t tt = TT_NAMEINDEX; tt < TT_LAST; tt++)
		if (is_kvs_offload_tt(tt))
			data_used_space += ttag_size[tt];

	memcpy(dev->stats.ttag_entries, ttag_entries, sizeof(ttag_entries));
	memcpy(dev->stats.ttag_size, ttag_size, sizeof(ttag_size));
	atomic_set_uint64(&dev->stats.physical_capacity, physical_capacity);
	atomic_set_uint64(&dev->stats.capacity, capacity);
	atomic_set_uint64(&dev->stats.used, data_used_space);
	dev->stats.keycache = keycache_stats_aggr;
	dev->stats.num_objects = ttag_entries[TT_NAMEINDEX];
	dev->stats.keycache = keycache_stats_aggr;

	return err;
}

static int
kvs_adjust_ssd(struct repdev *dev, char *kdevname)
{
	char rPath[2048];
	int err;
	char *hdd_cfq = getenv("DEV_RD_HDD_CFQ");
	struct repdev_kvs *kvs = dev->device_lfs;

	if (hdd_cfq) {
		snprintf(rPath, 2048, "echo cfq 2>/dev/null > /sys/block/%s/queue/scheduler", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 128 2>/dev/null > /sys/block/%s/queue/nr_requests", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo %d 2>/dev/null > /sys/block/%s/queue/read_ahead_kb", kvs->readahead, kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 10000 2>/dev/null > /sys/block/%s/queue/iosched/fifo_expire_async", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 250 2>/dev/null > /sys/block/%s/queue/iosched/fifo_expire_sync", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 80 2>/dev/null > /sys/block/%s/queue/iosched/slice_async", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 1 2>/dev/null > /sys/block/%s/queue/iosched/low_latency", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 6 2>/dev/null > /sys/block/%s/queue/iosched/quantum", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 5 2>/dev/null > /sys/block/%s/queue/iosched/slice_async_rq", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 3 2>/dev/null > /sys/block/%s/queue/iosched/slice_idle", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 100 2>/dev/null > /sys/block/%s/queue/iosched/slice_sync", kdevname);
		err = system(rPath);
		goto _exit;
	}

	snprintf(rPath, 2048, "echo deadline 2>/dev/null > /sys/block/%s/queue/scheduler", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 100 2>/dev/null > /sys/block/%s/queue/iosched/read_expire 2>/dev/null", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 4 2>/dev/null > /sys/block/%s/queue/iosched/writes_starved 2>/dev/null", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 512 2>/dev/null > /sys/block/%s/queue/nr_requests 2>/dev/null", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 0 2>/dev/null > /sys/block/%s/queue/add_random 2>/dev/null", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo %d 2>/dev/null > /sys/block/%s/queue/read_ahead_kb 2>/dev/null", kvs->readahead, kdevname);
	err = system(rPath);
_exit:
	log_info(lg, "Dev(%s): rotational HDD /dev/%s adjusted to optimal values",
	    dev->name, kdevname);
	return err;
}

static int
kvs_dev_stat_refresh(struct repdev *dev)
{
	assert(dev != NULL);
	assert(dev->path != NULL);

	rt_set_thread_vdev_context(dev);
	int err = kvs_lmdb_stat(dev);
	if (err) {
		log_debug(lg, "LDBM stats returned error: %d", err);
		return err;
	}
	char rBuf[8];
	char rPath[2048];
	char devPath[2048];
	/* check device type to calculate latency */
	if (dev->stats.nominal_latency == 0) {
		dev->stats.nominal_latency = RT_LFS_HDD_LATENCY_US;
		memset(rBuf, 0, 8);
		memset(rPath, 0, 2048);
		memset(devPath, 0, 2048);
		sprintf(devPath, "/dev/disk/by-id/%s", dev->journal);
		char *con_path = realpath(devPath, NULL);
		if (!con_path) {
			log_warn(lg, "Dev(%s): unable to resolve kdevname: %s",
			    dev->name, strerror(errno));
			return -errno;
		}
		char *kdevname = con_path + strlen("/dev/");

		/*
		 * Looking for :
		 * /sys/block/[dev_from_id]/queue/rotational
		 * Build the string for fopen
		 */
		sprintf(rPath, "/sys/block/%s/queue/rotational", kdevname);

		FILE *fp = fopen(rPath, "r");
		if (!fp) {
			free(con_path);
			return -errno;
		}

		int bytes = fread(rBuf, 1, 1, fp);
		fclose(fp);
		if (bytes != 1) {
			free(con_path);
			return -errno;
		}
		int rotational = atoi(rBuf);

		if (rotational) {
			free(con_path);
			dev->stats.rotational = 1;
		} else {
			/* Adjust SSD parameters to optimal */
			kvs_adjust_ssd(dev, kdevname);
			free(con_path);
			dev->stats.nominal_latency = RT_LFS_SSD_LATENCY_US;
		}
	}
	return 0;
}

static int
kvs_key_encode(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid, uv_buf_t *keybuf, struct repdev_db **db_out,
	MDB_dbi *dbi_out, struct repdev_log **log_out)
{
	int err;
	struct repdev_kvs *kvs = dev->device_lfs;
	struct repdev_db* db;

	err = kvs_key_serialize(chid, hash_type, NULL, keybuf);

	if (err) {
		log_error(lg, "TypedKey(%s): cannot encode CHID", dev->name);
		return err;
	}

	/* get part environment */
	int j = PLEVEL_HASHCALC(chid, (kvs->plevel - 1));
	db = kvs->db + j;
	*db_out = db;

	/* get DBI shard within partition */
	*dbi_out = db->dbi[ttag];

	/* get LOG */
	*log_out = &db->log;

	return 0;
}

static int
kvs_del_hashcount_entry(struct repdev *dev)
{
	int err;
	MDB_txn *txn;
	struct repdev_kvs *kvs = dev->device_lfs;
	struct repdev_db *db = kvs->db;
	MDB_val key = { .mv_size = strlen(HASHCOUNT_BLOB_KEY) + 1,
			.mv_data = HASHCOUNT_BLOB_KEY };

	if(dev->rt->flags & RT_FLAG_RDONLY)
		return 0;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return -EPERM;

	err = mdb_txn_begin(db->env, NULL, 0, &txn);
	if (err) {
		log_error(lg,
		    "Dev(%s): rd_del_hashcount_entry mdb_txn_begin: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		return -EIO;
	}

	err = mdb_del(txn, db->dbi[TT_HASHCOUNT], &key, NULL);
	if (err) {
		mdb_txn_abort(txn);
		log_warn(lg, "Dev(%s): %s mdb_del: (%d) %s", dev->name,
		    type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err));
		return -EIO;
	}

	err = mdb_txn_commit(txn);
	if (err) {
		log_error(lg, "Dev(%s): %s mdb_txn_commit: (%d) %s",
		    dev->name, type_tag_name[TT_HASHCOUNT], err,
		    mdb_strerror(err));
		return -EIO;
	}

	return 0;
}

static int
kvs_put_hashcount_entry(struct repdev *dev, MDB_val* key, MDB_val* data)
{
	int err;
	MDB_txn *txn;
	struct repdev_kvs *kvs = dev->device_lfs;
	struct repdev_db *db = kvs->db;
	void *data_ptr = data->mv_data;

	if(dev->rt->flags & RT_FLAG_RDONLY)
		return 0;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE ||
		status == REPDEV_STATUS_READONLY_FULL ||
		status == REPDEV_STATUS_READONLY_FORCED ||
		status == REPDEV_STATUS_READONLY_FAULT)
		return -EPERM;

	err = mdb_txn_begin(db->env, NULL, 0, &txn);
	if (err) {
		log_error(lg,
		    "Dev(%s): kvs_put_hashcount_entry mdb_txn_begin: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		return -EIO;
	}

	err = mdb_put(txn, db->dbi[TT_HASHCOUNT], key, data, MDB_RESERVE);
	if (err) {
		mdb_txn_abort(txn);
		log_error(lg, "Dev(%s): %s mdb_put: (%d) %s", dev->name,
		    type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err));
		return -EIO;
	}

	memcpy((char *)data->mv_data, data_ptr, data->mv_size);

	err = mdb_txn_commit(txn);
	if (err) {
		log_error(lg, "Dev(%s): %s mdb_txn_commit: (%d) %s",
		    dev->name, type_tag_name[TT_HASHCOUNT], err,
		    mdb_strerror(err));
		return -EIO;
	}

	return 0;
}

static int
kvs_get_hashcount_entry(struct repdev *dev, MDB_val* key, MDB_val* data)
{
	int err;
	MDB_txn *txn;
	struct repdev_kvs *kvs = dev->device_lfs;
	struct repdev_db *db = kvs->db;

	err = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn);
	if (err) {
		log_error(lg, "kvs_get_hashcount_entry mdb_txn_begin: (%d) %s", err,
		    mdb_strerror(err));
		return -EIO;
	}

	err = mdb_get(txn, db->dbi[TT_HASHCOUNT], key, data);
	if (err == MDB_NOTFOUND) {
		mdb_txn_abort(txn);
		return -ENOENT;
	} else if (err) {
		log_error(lg, "kvs_get_hashcount_entry mdb_get: (%d) %s", err,
		    mdb_strerror(err));
		err = -EIO;
	}

	mdb_txn_abort(txn);
	return err;
}

static int
kvs_config(struct repdev *dev, dev_cfg_op op,
	const uv_buf_t* key, uv_buf_t* value) {
	MDB_val mdb_key, mdb_value;
	int err = 0;

	assert(key->base);
	assert(key->len);

	rt_set_thread_vdev_context(dev);
	mdb_key.mv_data = key->base;
	mdb_key.mv_size = key->len;

	if (op == CFG_READ) {
		mdb_value.mv_data = NULL;
		mdb_value.mv_size = 0;
		err = kvs_get_hashcount_entry(dev, &mdb_key, &mdb_value);
		if (!err) {
			value->base = mdb_value.mv_data;
			value->len = mdb_value.mv_size;
		}
	} else {
		mdb_value.mv_data = value->base;
		mdb_value.mv_size = value->len;
		err = kvs_put_hashcount_entry(dev, &mdb_key, &mdb_value);
	}
	return err;
}

#define DEV_DELETE_DEFERRED_BULK 1024

static void
kvs_log_delete_deferred(void *arg)
{
	struct repdev_log *log = arg;
	struct repdev_db *db = log->db;
	MDB_env *log_env = log->env;
	type_tag_t ttag = log->ttag;
	MDB_dbi log_dbi = log->dbi[ttag];
	rtbuf_t *rbkeys = log->delete_rbkeys;
	struct repdev *dev = log->dev;
	struct repdev_lfs *lfs = dev->device_lfs;
	MDB_txn *log_txn = NULL;
	int err;
	uint64_t start_ns = uv_hrtime();
	size_t nbuf_cur = 0;

_repeat:
	/* start log txn */
	err = mdb_txn_begin(log_env, NULL, 0, &log_txn);
	if (err) {
		log_error(lg, "Get(%s): cannot begin log_delete %s log_txn: (%d) %s",
		    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	size_t i;
	if (is_dupsort_tt(ttag)) {
		/* dupsort case, delete key and data */
		for (i = nbuf_cur; i < rbkeys->nbufs; i += 2) {
			uv_buf_t *k = &rtbuf(rbkeys, i);
			MDB_val key = { .mv_size = k->len, .mv_data = k->base };
			uv_buf_t *v = &rtbuf(rbkeys, i + 1);
			MDB_val data = { .mv_size = v->len, .mv_data = v->base };
			err = mdb_del(log_txn, log_dbi, &key, &data);
			if (err && err != MDB_NOTFOUND)
				break;
			err = 0;
			if (i > nbuf_cur + DEV_DELETE_DEFERRED_BULK)
				break;
		}
	} else {
		/* non-dupsort case */
		for (i = nbuf_cur; i < rbkeys->nbufs; i++) {
			uint64_t attr = 0, attr_g = 0;
			/*
			 * Delete only matching key/attribute pair cause
			 * the key could be overwritten during a flush
			 */
			uv_buf_t *k = &rtbuf(rbkeys, i);
			MDB_val key = { .mv_size = k->len, .mv_data = k->base  };
			memcpy(&attr, k->base + k->len, sizeof(uint64_t));

			err = mdb_get_attr(log_txn, log_dbi, &key, NULL, &attr_g);
			if (err)
				break;
			if (attr != attr_g)
				continue;

			err = mdb_del(log_txn, log_dbi, &key, NULL);
			if (err && err != MDB_NOTFOUND)
				break;
			err = 0;
			if (i > nbuf_cur + DEV_DELETE_DEFERRED_BULK)
				break;
		}
	}
	nbuf_cur = i + 1;

	log_debug(lg, "Dev(%s): LOG DEL: %s, deleted=%ld took=%ldus", dev->name,
	    type_tag_name[ttag], rbkeys->nbufs, (uv_hrtime() - start_ns) / 1000);

	err = mdb_txn_commit(log_txn);
	log_txn = NULL;
	if (err) {
		log_error(lg, "Dev(%s): log_delete rbkeys=%ld %s mdb_txn_commit: (%d) %s",
		    dev->name, rbkeys->nbufs, type_tag_name[ttag], err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	if (nbuf_cur < rbkeys->nbufs)
		goto _repeat;

_exit:
	if (log_txn)
		mdb_txn_abort(log_txn);
	je_free(log);
}

static void
kvs_log_flush_thread(void *arg)
{
	struct repdev_log *log = arg;
	int err = 0;
	MDB_val key, data;
	int flushed = 0;
	MDB_cursor *log_cursor = NULL;
	MDB_txn *log_txn = NULL;
	struct repdev *dev = log->dev;
	struct repdev_db *db = log->db;
	MDB_env *log_env = log->env;
	type_tag_t ttag = log->ttag;
	MDB_dbi log_dbi = log->dbi[ttag];
	MDB_txn *main_txn = NULL;
	MDB_cursor *main_cursor = NULL;
	struct repdev_kvs *kvs = dev->device_lfs;
	rtbuf_t *rbkeys = NULL;
	rtbuf_t* rbv = NULL;
	rtbuf_t* rbk = NULL;
	uint32_t rbkeys_i = 0;
	uint32_t rbvals_i = 0;
	uint64_t start_us = uv_hrtime();
	int force_readonly = 0;
	int force_unavail = 0;
	size_t n_log_entries = 0;

	repdev_status_t status = reptrans_dev_get_status(dev);
	int cant_flush = status == REPDEV_STATUS_READONLY_FORCED ||
		status == REPDEV_STATUS_READONLY_FAULT ||
		status == REPDEV_STATUS_UNAVAILABLE;

	uv_mutex_lock(&db->log_flush_lock);
	if (dev->terminating || cant_flush) {
		db->log_flush_cnt = 0;
		uv_cond_broadcast(&db->log_flush_condvar);
		uv_mutex_unlock(&db->log_flush_lock);
		return;
	}

	db->log_flush_cnt = pthread_self();
	uv_mutex_unlock(&db->log_flush_lock);

	dev->flushing |= (1 << ttag);
	dev->flushing_part |= (1 << db->part);

_repeat:

	/* start log txn */
	err = mdb_txn_begin(log_env, NULL, MDB_RDONLY, &log_txn);
	if (err) {
		log_error(lg, "Get(%s): cannot begin mdb log_flush log_txn: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	MDB_stat mstat;
	err = mdb_stat(log_txn, log_dbi, &mstat);
	if (err) {
		log_error(lg, "Get(%s): cannot begin mdb log_flush mdb_stat: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}
	n_log_entries = mstat.ms_entries;

	/* open log cursor */
	err = mdb_cursor_open(log_txn, log_dbi, &log_cursor);
	if (err) {
		log_error(lg, "Get(%s): cannot open mdb log_flush log_cursor: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	/* start main TT txn */
	err = mdb_txn_begin(db->env, NULL, 0, &main_txn);
	if (err) {
		log_error(lg, "Get(%s): cannot begin mdb log_flush main_txn: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}
	/* Number of entries per commit limited by a backend */
	size_t commit_len = is_kvs_offload_tt(ttag) ? n_log_entries > kvs->be_info.put_bulk_size ?
		kvs->be_info.put_bulk_size : n_log_entries : n_log_entries;

	/* size: dupsort allocates twice more */
	rbkeys = rtbuf_init(NULL, 2 * commit_len);
	if (!rbkeys) {
		err = -ENOMEM;
		goto _exit;
	}

	rbv = rtbuf_init(NULL, commit_len);
	if (!rbv) {
		err = -ENOMEM;
		goto _exit;
	}

	rbk = rtbuf_init(NULL, commit_len);
	if (!rbk) {
		err = -ENOMEM;
		goto _exit;
	}


	/* walk all log records for this TT */
	int op = MDB_FIRST;
	while ((err = mdb_cursor_get(log_cursor, &key, &data, op)) == 0 &&
	       rbkeys_i < (is_dupsort_tt(ttag) ? 2 * commit_len : commit_len)) {
		op = MDB_NEXT;

		MDB_val keyhv;
		uint64_t kh;
		uint64_t attr = 0;
		if (!is_dupsort_tt(ttag)) {
			err = mdb_cursor_get_attr(log_cursor, &key, &data, &attr);
			if (err) {
				log_error(lg, "Get(%s): cannot read attr in log_flush: %s (%d)",
				    dev->name, mdb_strerror(err), err);
				force_unavail = 1;
				err = -EIO;
				goto _exit;
			}
			/* add non-dupsort key to a list for deferred delete */
			rbkeys->bufs[rbkeys_i].base = je_malloc(key.mv_size + sizeof(attr));
			if (!rbkeys->bufs[rbkeys_i].base) {
				err = -ENOMEM;
				goto _exit;
			}
			memcpy(rbkeys->bufs[rbkeys_i].base, key.mv_data, key.mv_size);
			memcpy(rbkeys->bufs[rbkeys_i].base + key.mv_size, &attr, sizeof(attr));
			/* Atrribute size will be considered on deferred delete.
			 * Keep original key size here for backend put
			 */
			rbkeys->bufs[rbkeys_i].len = key.mv_size;
			rbkeys_i++;
		}

		/* get shard location */
		uint512_t chid;
		crypto_hash_t key_hash_type;
		uv_buf_t uk = {.base = key.mv_data, .len = key.mv_size};

		err = kvs_key_deserialize(uk, &chid, &key_hash_type, NULL);

		if (err) {
			log_error(lg, "log_flush key decode failed %d, "
				"ttag %d(%s)", err, ttag, type_tag_name[ttag]);
			err = -EIO;
			goto _exit;
		}
		MDB_dbi main_dbi = db->dbi[ttag];

		/* open shard's cursor if not yet */
		if (!main_cursor) {
			err = mdb_cursor_open(main_txn, main_dbi, &main_cursor);
			if (err) {
				log_error(lg, "Get(%s): cannot open mdb log_flush cursor: (%d) %s",
				    dev->name, err, mdb_strerror(err));
				err = -EIO;
				goto _exit;
			}
		}

		if (!is_dupsort_tt(ttag)) {
			if (is_keycache_tt(ttag)) {
				err = kvs_keyhash(dev, &key, &keyhv, &kh);
				if (err) {
					log_error(lg, "Get(%s): cannot keyhash in log_flush: (%d)",
					    dev->name, err);
					goto _exit;
				}
			}

			if (is_data_tt(ttag) && attr == 0)
				assert(0);

			if (data.mv_size != 0) {
				int subst  = is_kvs_offload_tt(ttag) ? 1 : 0;
				MDB_val data_out = { .mv_data = NULL,
					.mv_size = subst ? sizeof(data.mv_size) : data.mv_size };
				unsigned int flags = MDB_SETATTR | MDB_RESERVE;
				flags |= (dev->rt->flags & RT_FLAG_ALLOW_OVERWRITE) ?
						 0 : MDB_NOOVERWRITE;
				err = mdb_cursor_put_attr(main_cursor, &key, &data_out, attr, flags);
				if (!err) {
					if (subst) {
						memcpy((char *)data_out.mv_data, &data.mv_size, sizeof(data.mv_size));
						/* Keeps values for further use */
						rbv->bufs[rbvals_i].base = data.mv_data;
						rbv->bufs[rbvals_i].len = data.mv_size;
						rbk->bufs[rbvals_i].base = rbkeys->bufs[rbkeys_i-1].base;
						rbk->bufs[rbvals_i++].len = rbkeys->bufs[rbkeys_i-1].len;
					} else
						memcpy((char *)data_out.mv_data, data.mv_data, data.mv_size);
				}
				if (!err && is_keycache_tt(ttag)) {
					kvs_bloom_insert(db, kh);
					key_cache_insert(db->key_cache, &kh, ttag, data.mv_size);
				} else if (err == MDB_KEYEXIST && attr) {
					err = mdb_set_attr(main_txn, main_dbi, &key, NULL, attr);
				}
			} else {
				err = mdb_set_attr(main_txn, main_dbi, &key, NULL, attr);
			}
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (err == MDB_NOTFOUND) {
				log_warn(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (KVS_NO_FREE_SPACE(err)) {
				/* fatal error - move dev to readonly */
				force_readonly = 1;
				log_warn(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
				goto _exit;
			} else if (err) {
				/* fatal error - move dev to unavailable */
				force_unavail = 1;
				log_error(lg, "Dev(%s): log_flush %s mdb_put (ksize=%ld vsize=%ld: (%d) %s",
				    dev->name, type_tag_name[ttag], key.mv_size, data.mv_size, err, mdb_strerror(err));
				err = -EIO;
				goto _exit;
			}

			/* non-dupsort done */
			continue;
		}

		/* set key to a first element and load data */
		err = mdb_cursor_get(log_cursor, &key, &data, MDB_FIRST_DUP);
		if (err) {
			/* fatal error - move dev to unavailable */
			force_unavail = 1;
			log_error(lg, "Dev(%s): log_flush %s mdb_cursor_get (ksize=%ld dsize=%ld: (%d) %s",
			    dev->name, type_tag_name[ttag], key.mv_size, data.mv_size, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}

		/* flush all dupsorts for this key */
		do {
			if (rbkeys_i >= 2 * commit_len)
				break;
			/* add dupsort key to a list for deferred delete */
			rbkeys->bufs[rbkeys_i].base = je_memdup(key.mv_data, key.mv_size);
			if (!rbkeys->bufs[rbkeys_i].base) {
				err = -ENOMEM;
				goto _exit;
			}
			rbkeys->bufs[rbkeys_i].len = key.mv_size;
			rbkeys_i++;

			/* add dupsort data to a list for deferred delete */
			rbkeys->bufs[rbkeys_i].base = je_memdup(data.mv_data, data.mv_size);
			if (!rbkeys->bufs[rbkeys_i].base) {
				err = -ENOMEM;
				goto _exit;
			}
			rbkeys->bufs[rbkeys_i].len = data.mv_size;
			rbkeys_i++;

			/* allow unique key/data inserts only */
			err = mdb_cursor_put(main_cursor, &key, &data, MDB_NODUPDATA);
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (KVS_NO_FREE_SPACE(err)) {
				/* fatal error - move dev to readonly */
				force_readonly = 1;
				log_warn(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
				goto _exit;
			} else if (err) {
				/* fatal error - move dev to unavailable */
				force_unavail = 1;
				log_error(lg, "Dev(%s): log_flush %s mdb_put (ksize=%ld dsize=%ld: (%d) %s",
				    dev->name, type_tag_name[ttag], key.mv_size, data.mv_size, err, mdb_strerror(err));
				err = -EIO;
				goto _exit;
			}

		} while ((err = mdb_cursor_get(log_cursor, &key, &data, MDB_NEXT_DUP)) == 0);
	}

	if (main_cursor) {
		mdb_cursor_close(main_cursor);
		main_cursor = NULL;
	}
	mdb_cursor_close(log_cursor);
	log_cursor = NULL;

	mdb_txn_abort(log_txn);
	log_txn = NULL;

	if (rbkeys_i > 0) {
		if (is_kvs_offload_tt(ttag) && rbvals_i) {
			err = kvs->backend->put(kvs->be_inst, ttag, rbk->bufs, rbv->bufs, rbvals_i);
			if (err)
				goto _exit;
			atomic_add64(db->entries + ttag, rbvals_i);
			for (size_t i = 0; i < rbvals_i; i++)
				atomic_add64(db->size + ttag, rbv->bufs[i].len);
		}
		err = mdb_txn_commit(main_txn);
		main_txn = NULL;
		if (err) {
			force_unavail = 1;
			log_error(lg, "Dev(%s): log_flush %s mdb_txn_commit: (%d) %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
	} else {
		mdb_txn_abort(main_txn);
		main_txn = NULL;
		err = 0;
	}

	flushed = 1;

_exit:
	if (main_cursor)
		mdb_cursor_close(main_cursor);

	if (main_txn)
		mdb_txn_abort(main_txn);
	if (log_cursor)
		mdb_cursor_close(log_cursor);
	if (log_txn)
		mdb_txn_abort(log_txn);

	if (flushed && rbkeys_i == 0) {
		rtbuf_destroy(rbkeys);
		rbkeys = NULL;
	} else if (flushed) {

		/* adjust rbkeys array len */
		rbkeys->nbufs = rbkeys_i;

		struct repdev_log *thr_log = je_malloc(sizeof (*thr_log));
		if (thr_log) {
			*thr_log = *log;
			thr_log->delete_rbkeys = rbkeys;
			thr_log->ttag = ttag;
			kvs_log_delete_deferred((void *)thr_log);
		}
		uint64_t  flushed_ts = uv_hrtime();
		log_debug(lg, "%s journal flushed %u records (%ldus)",
		    type_tag_name[ttag], rbkeys_i, (flushed_ts - start_us) / 1000);
		log->flushed_timestamp = flushed_ts;

	}

	if (rbkeys)
		rtbuf_destroy(rbkeys);
	if (rbv)
		rtbuf_clean(rbv);
	if (rbk)
		rtbuf_clean(rbk);

	if (force_unavail) {
		reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
	} else if (force_readonly)
		reptrans_dev_set_status(dev, REPDEV_STATUS_READONLY_FAULT);
	else if (flushed && rbkeys_i < n_log_entries) {
		rbkeys_i = 0;
		rbvals_i = 0;
		goto _repeat;
	}

	dev->flushing &= ~(1 << ttag);
	dev->flushing_part &= ~(1 << db->part);

	je_free(log);

	uv_mutex_lock(&db->log_flush_lock);
	db->log_flush_cnt = 0;
	uv_cond_broadcast(&db->log_flush_condvar);
	uv_mutex_unlock(&db->log_flush_lock);
}

static int
kvs_log_flush(struct repdev_log *log, type_tag_t ttag)
{
	struct repdev *dev = log->dev;
	struct repdev_db *db = log->db;
	int err;

	if(dev->rt->flags & RT_FLAG_RDONLY)
		return 0;

	struct repdev_log *thr_log = je_malloc(sizeof (*thr_log));

	if (thr_log == NULL)
		return -ENOMEM;

	/* block writers for this partition */
	uv_mutex_lock(&db->log_flush_lock);

	int wait_cnt = 0;
	while (db->log_flush_cnt != 0) {
		uv_cond_wait(&db->log_flush_condvar, &db->log_flush_lock);
	}

	db->log_flush_cnt = pthread_self();

	*thr_log = *log;
	thr_log->ttag = ttag;
	pthread_attr_t attr;
	err = pthread_attr_init(&attr);
	if (!err)
		err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (!err)
		err = pthread_create(&thr_log->flush_thread, &attr,
			(void *)&kvs_log_flush_thread, (void *)thr_log);
	if (err) {
		log_error(lg, "Dev(%s): log_flush_thread create %s: (%d) %s",
		    dev->name, type_tag_name[ttag], err, strerror(err));
		err = 0;
		db->log_flush_cnt = 0;
		uv_cond_broadcast(&db->log_flush_condvar);
		je_free(thr_log);
	}
	pthread_attr_destroy(&attr);
	uv_mutex_unlock(&db->log_flush_lock);
	return err;
}

static int
kvs_log_append(struct repdev *dev, struct repdev_log *log, type_tag_t ttag,
		crypto_hash_t hash_type, uv_buf_t *keybuf, const rtbuf_t *rb,
		uint64_t attr)
{
	int err = 0;
	MDB_txn *txn;
	MDB_val key, data;
	struct repdev_lfs *lfs = dev->device_lfs;
	struct repdev_db *db = log->db;
	MDB_dbi dbi = log->dbi[ttag];
	size_t len = rtbuf_len(rb);

	/*
	 * Journal on disk organization.
	 *
	 * As we do not depend on order of writes LOG entries can be inserted
	 * randomly and with only minimal serialization.
	 *
	 * Reads from journal log only done at device initialization time. All
	 * other lookups are in-memory lookups done via LMDB memory mapped
	 * structures. So, essentially journal log is an extra small append-only
	 * transactional store with durability guarantee. Durability level is
	 * configurable and can be beneficial when SSD are combined with HDDs
	 * and SSDs used as a holders of journal. See "sync" rt-lfs.json flag.
	 *
	 * Journal stores keys as is, i.e. without keyhash! That is so that we
	 * can implement sharded log_flush() later on..
	 */
	err = mdb_txn_begin(log->env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): log_append mdb_txn_begin: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	key.mv_size = keybuf->len;
	key.mv_data = keybuf->base;
	data.mv_size = len;

	if (is_dupsort_tt(ttag)) {
		assert(rb->nbufs == 1);
		assert(data.mv_size < 511);
		data.mv_data = rtbuf(rb, 0).base;

		err = mdb_put(txn, dbi, &key, &data, MDB_NODUPDATA);
		if (err) {
			mdb_txn_abort(txn);
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (KVS_NO_FREE_SPACE(err)) {
				log_warn(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
			} else {
				reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
				log_error(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -EIO;
			}
			goto _exit;
		}
	} else {

		data.mv_data = NULL; /* MDB_RESERVE */

		unsigned int flags = MDB_RESERVE;
		flags |= (dev->rt->flags & RT_FLAG_ALLOW_OVERWRITE) ?
				 0 : MDB_NOOVERWRITE;
		err = mdb_put_attr(txn, dbi, &key, &data, attr, flags);
		if (err == MDB_KEYEXIST && attr) {
			err = mdb_set_attr(txn, dbi, &key, NULL, attr);
			data.mv_data = NULL;
		}
		if (err) {
			mdb_txn_abort(txn);
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (KVS_NO_FREE_SPACE(err)) {
				log_warn(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
			} else {
				reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
				log_error(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -EIO;
			}
			goto _exit;
		}

		if (data.mv_data) {
			size_t copied = 0;
			for (int i = 0; i < (int)rb->nbufs; i++) {
				memcpy((char *)data.mv_data + copied, rtbuf(rb, i).base,
				    rtbuf(rb, i).len);
				copied += rtbuf(rb, i).len;
			}
		}
	}

	MDB_stat stat;
	err = mdb_stat(txn, dbi, &stat);
	if (err) {
		log_error(lg, "Dev(%s): log_append %s mdb_stat: (%d) %s",
		    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
		err = 0;
	}

	err = mdb_txn_commit(txn);
	if (err) {
		if (KVS_NO_FREE_SPACE(err)) {
			log_warn(lg, "Dev(%s): log_append %s mdb_txn_commit: (%d) %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
			err = -ENOSPC;
		} else {
			log_error(lg, "Dev(%s): log_append %s mdb_txn_commit: (%d) %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
			err = -EIO;
		}
		goto _exit;
	}

_exit:
	if (!err) {
		if ((is_keycache_tt(ttag) || ttag == TT_NAMEINDEX) && data.mv_size) {
			MDB_val keyhv;
			uint64_t kh;
			err = kvs_keyhash(dev, &key, &keyhv, &kh);
			if (err)
				goto _exit;

			kvs_bloom_insert(db, kh);
			if (ttag != TT_NAMEINDEX)
				key_cache_insert(db->key_cache, &kh, ttag, data.mv_size);

		}

		size_t log_size = stat.ms_psize * (stat.ms_branch_pages +
		    stat.ms_leaf_pages + stat.ms_overflow_pages);
		if (log_size > DEV_LMDB_LOG_MAPSIZE/8ULL || //16mb
		    stat.ms_entries > dev->journal_maxentries) {
			err = kvs_log_flush(log, ttag);
			return err;
		}
	}
	return err;
}

static int
kvs_put_blob_with_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid_in,
    uint64_t attr, uint64_t options)
{
	int err = 0, mdb_err = 0;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	MDB_val keyhv;
	uint64_t kh;
	size_t len = rtbuf_len(rb);
	int bloom_insert = 0;
	MDB_txn *txn = NULL;
	uv_buf_t keybuf = { .base = NULL, .len = 0 };
	uint512_t chid = *chid_in;
	struct repdev_kvs *kvs = dev->device_lfs;
	int overwrite = options & REPDEV_PUT_OPT_OVERWRITE;

	assert (ttag != TT_HASHCOUNT);

	rt_set_thread_vdev_context(dev);

	/* Do an inplace chid conversion for ttags sensitive to chid format */
	if (ttag == TT_TRANSACTION_LOG)
		rt_chid_swap_trlog(chid_in, &chid, &hash_type);
	else if (ttag == TT_VERIFICATION_QUEUE)
		rt_chid_swap_verqueue(chid_in, &chid, &hash_type);

	err = kvs_key_encode(dev, ttag, hash_type, &chid, &keybuf, &db, &dbi, &log);
	if (err)
		return err;

	if (is_bloom_tt(ttag))
		atomic_inc64(&kvs->bloom_ttag_put_counter);


	if (!overwrite && is_log_tt(dev, ttag) &&
		(rtbuf_len(rb) < dev->journal_maxchunksize)) {
		err = kvs_log_append(dev, log, ttag, hash_type, &keybuf, rb,
		    attr);
		assert (err != -EEXIST);
		if (!err && is_hashcount_data_type_tag(ttag)) {
			/* NOTE: EEXIST at log flush time can be a problem, yes.
			 * We however worried more about missing insert rather
			 * do count extra. Again, relying on vdevinspect tool
			 * here to recover if bad things happens to HC.. */
			reptrans_bump_hashcount(dev, &chid, 1);
		}
		if (err != -ENOSPC)
			goto _exit;
		/*
		 * instead of returning error, need to try to add this
		 * entry to the main TT store, so we will fall through..
		 */
	}

	/*
	 * Place this chunk directly into main TT data store
	 */
	err = mdb_txn_begin(db->env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): put_blob mdb_txn_begin: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	MDB_val key, data;
	key.mv_size = keybuf.len;
	key.mv_data = keybuf.base;
	data.mv_size = len;

	if (is_dupsort_tt(ttag)) {
		assert(rb->nbufs == 1);
		assert(data.mv_size < 511);
		data.mv_data = rtbuf(rb, 0).base;

		err = mdb_put(txn, dbi, &key, &data, MDB_NODUPDATA);
		if (err) {
			mdb_err = err;
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): put_blob_with_attr %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (KVS_NO_FREE_SPACE(err)) {
				reptrans_dev_set_status(dev, REPDEV_STATUS_READONLY_FAULT);
				log_warn(lg, "Dev(%s): put_blob_with_attr %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
			} else {
				reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
				log_error(lg, "Dev(%s): put_blob_with_attr %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -EIO;
			}
			goto _exit;
		}
	} else {

		data.mv_data = NULL; /* MDB_RESERVE */

		if (is_keycache_tt(ttag)) {
			err = kvs_keyhash(dev, &key, &keyhv, &kh);
			if (err)
				goto _exit;

			bloom_insert = 1;
		}
		if (overwrite) {
			MDB_txn* log_txn = NULL;
			err = mdb_txn_begin(log->env, NULL, 0, &log_txn);
			if (err) {
				log_error(lg, "Dev(%s): log_del mdb_txn_begin: (%d) %s",
				    dev->name, err, mdb_strerror(err));
				err = -EIO;
				goto _exit;
			}
			err = mdb_del(log_txn, log->dbi[ttag], &key, NULL);
			if (!err)
				err = mdb_txn_commit(log_txn);
			else
				mdb_txn_abort(log_txn);

			if (err && err != MDB_NOTFOUND) {
				log_error(lg, "Dev(%s): log delete mdb_txn_commit: (%d) %s log_env %s",
				    dev->name, err, mdb_strerror(err), log->path);
				goto _exit;
			}
			err = 0;
		}
		unsigned int flags = MDB_RESERVE;
		flags |= overwrite ? 0 : MDB_NOOVERWRITE;
		if (is_kvs_offload_tt(ttag)) {
			/* For KVS type tags keep locally only size */
			data.mv_size = sizeof(data.mv_size);
		}
		err = mdb_put_attr(txn, dbi, &key, &data, attr, flags);
		if (err == MDB_KEYEXIST && attr) {
			err = mdb_set_attr(txn, dbi, &key, NULL, attr);
			data.mv_data = NULL;
		}
		if (err) {
			mdb_err = err;
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): "
					"put_blob %s mdb_put: (%d) %s",
					dev->name, type_tag_name[ttag],
					err, mdb_strerror(err));
				err = 0;
			} else if (KVS_NO_FREE_SPACE(err)) {
				reptrans_dev_set_status(dev, REPDEV_STATUS_READONLY_FAULT);
				log_warn(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
					dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
			} else {
				reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
				log_error(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
					dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -EIO;
			}
			goto _exit;
		}

		if (data.mv_data) {
			if (is_kvs_offload_tt(ttag)) {
				size_t sz = 0;
				rtbuf_t* flat = rtbuf_serialize((rtbuf_t*)rb);
				assert(flat);
				uv_buf_t uk = { .base = key.mv_data, .len = key.mv_size };
				uv_buf_t* uv = flat->bufs;
				err = kvs->backend->put(kvs->be_inst, ttag, &uk, uv, 1);
				if (err) {
					goto _exit;
				}
				memcpy((char *)data.mv_data, &len, sizeof(data.mv_size));
			} else {
				size_t copied = 0;
				for (int i = 0; i < (int)rb->nbufs; i++) {
					memcpy((char *)data.mv_data + copied, rtbuf(rb, i).base,
					    rtbuf(rb, i).len);
					copied += rtbuf(rb, i).len;
				}
			}
		}
	}

	err = mdb_txn_commit(txn);
	txn = NULL;
	if (err) {
		log_error(lg, "Dev(%s): put_blob %s mdb_txn_commit: (%d) %s",
		    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	} else if (!mdb_err && is_hashcount_data_type_tag(ttag)) {
		reptrans_bump_hashcount(dev, &chid, 1);
	}

_exit:

	if (!err && (bloom_insert || ttag == TT_NAMEINDEX)) {
		kvs_bloom_insert(db, kh);
		if (ttag != TT_NAMEINDEX)
			key_cache_insert(db->key_cache, &kh, ttag, len);
	}

	if (txn)
		mdb_txn_abort(txn);
	if (keybuf.base)
		je_free(keybuf.base);
	if (is_bloom_tt(ttag))
		atomic_dec64(&kvs->bloom_ttag_put_counter);
	return err;
}

static int
kvs_put_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const rtbuf_t *rb, uint512_t *chid)
{
	return kvs_put_blob_with_attr(dev, ttag, hash_type, rb, chid, 2, 0);
}

static int
kvs_set_blob_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid_in, uint64_t attr)
{
	int err;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi_main;
	uv_buf_t keybuf = { .base = NULL, .len = 0 };
	MDB_val keyhv;
	uint64_t kh;
	uint512_t chid = *chid_in;
	struct repdev_kvs *kvs = dev->device_lfs;

	rt_set_thread_vdev_context(dev);

	/* Do an inplace chid conversion for ttags sensitive to chid format */
	if (ttag == TT_TRANSACTION_LOG)
		rt_chid_swap_trlog(chid_in, &chid, &hash_type);
	else if (ttag == TT_VERIFICATION_QUEUE)
		rt_chid_swap_verqueue(chid_in, &chid, &hash_type);

	err = kvs_key_encode(dev, ttag, hash_type, &chid, &keybuf, &db, &dbi_main,
	    &log);
	if (err)
		return err;

	if (is_bloom_tt(ttag))
		atomic_inc64(&kvs->bloom_ttag_put_counter);


	MDB_txn *txn;
	MDB_val key;
	key.mv_size = keybuf.len;
	key.mv_data = keybuf.base;

	if (is_keycache_tt(ttag)) {
		err = kvs_keyhash(dev, &key, &keyhv, &kh);
		if (err)
			goto _exit;

		if (!kvs_bloom_query(db, kh)) {
			err = -ENOENT;
			goto _exit;
		}
	}


	if (is_log_tt(dev, ttag) && !is_dupsort_tt(ttag)) {
		rtbuf_t rb = { .bufs = NULL, .nbufs = 0 };
		err = kvs_log_append(dev, log, ttag, hash_type, &keybuf, &rb,
		    attr);
		assert (err != -EEXIST);
		if (err != -ENOSPC)
			goto _exit;
		/*
		 * instead of returning error, need to try to add attribute
		 * directly into the main TT store, so we will fall through..
		 */
	}

	/*
	 * Set attribute to the chunk directly into main TT data store
	 */
	err = mdb_txn_begin(db->env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): put_blob mdb_txn_begin: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	err = mdb_set_attr(txn, dbi_main, &key, NULL, attr);
	if (err) {
		mdb_txn_abort(txn);
		if (err == MDB_NOTFOUND) {
			err = -ENOENT;
		} else if (KVS_NO_FREE_SPACE(err)) {
			reptrans_dev_set_status(dev, REPDEV_STATUS_READONLY_FAULT);
			log_warn(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
			err = -ENOSPC;
		} else {
			reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
			log_error(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
			err = -EIO;
		}
		goto _exit;
	}

	err = mdb_txn_commit(txn);
	if (err) {
		log_error(lg, "Dev(%s): put_blob %s mdb_txn_commit: (%d) %s",
		    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

_exit:
	if (keybuf.base)
		je_free(keybuf.base);
	if (is_bloom_tt(ttag))
		atomic_dec64(&kvs->bloom_ttag_put_counter);
	return err;
}

static int
kvs_stat_filter(void *arg, void **data, size_t *size, int set)
{
	struct blob_stat *bs = arg;

	if (set)
		return 0;

	if (bs)
		bs->size = *size;
	return 0;
}

struct kvs_lookup_stat {
	size_t n_ht_log; /* Number of values added to skip array */
	size_t n_log;	/* Number of valid values in the log */
	size_t n_dup_main; /* number of valid entries found in main table */
	size_t n_skip_main; /* number of entries skipped in main table */
};

static int
kvs_log_lookup(struct repdev *dev, struct repdev_db *db, struct repdev_log *log,
    MDB_dbi dbi_main, int ttag, int flags, const uint512_t *chid, uv_buf_t *keybuf,
    crypto_hash_t hash_type, rtbuf_t *rb, int max_num, reptrans_blob_filter filter_cb,
    void *arg, uint64_t *attrp)
{
	int err = 0;
	MDB_val key, data = { .mv_size = 0, .mv_data = NULL };
	MDB_val usr_data = { .mv_size = 0, .mv_data = NULL };
	struct repdev_kvs *kvs = dev->device_lfs;
	MDB_cursor *cursor = NULL;
	MDB_txn *txn = NULL;
	MDB_env *env;
	MDB_dbi dbi;
	int found = 0, repeat;
	MDB_val keyhv;
	uint64_t kh;
	size_t dupcount = 0;


	/* For dupsort TT we keep a hash table for blobs scheduled for removal
	 * and a two linked list of values (log and main) in order to merge
	 * them later and create ordered de-duplicated array of values.
	 */
	struct mlist_node *list_main = NULL;
	size_t main_count = 0;
	struct mlist_node *list_log = NULL;
	size_t log_count = 0;
	int mapped = kvs->zerocopy >= 2;

	struct kvs_lookup_stat st = {.n_log = 0};
	struct rt_lhtbl* ht = NULL;
	if (is_dupsort_tt(ttag)) {
		ht = rt_lhtbl_create(DEV_LMDB_LOG_MAXENTRIES);
		if (!ht)
			return -ENOMEM;
	}

	if (filter_cb)
		filter_cb(arg, &usr_data.mv_data, &usr_data.mv_size, 1);

	if (is_log_tt(dev, ttag) && !(flags & GBF_FLAG_NO_WAL)) {
		/*
		 * Lookup in journal log first (in memory lookup) then in
		 * TT main db.
		 */
		env = log->env;
		dbi = log->dbi[ttag];
		repeat = 0;
	} else {
		/*
		 * This is direct TT main lookup.
		 */
		env = db->env;
		dbi = dbi_main;
		repeat = 1;
	}

	key.mv_size = keybuf->len;
	key.mv_data = keybuf->base;

_repeat:
	data = usr_data;
	if (is_keycache_tt(ttag)) {
		err = kvs_keyhash(dev, &key, &keyhv, &kh);
		if (err)
			goto _exit;

		if (!kvs_bloom_query(db, kh)) {
			err = -ENOENT;
			goto _exit;
		}

		uint64_t outsize;
		err = key_cache_lookup(db->key_cache, &kh, ttag, &outsize);
		if (!err && filter_cb == kvs_stat_filter) {
			/* found and we doing just stat_blob() - done */
			filter_cb(arg, NULL, &outsize, 0);
			return 0;
		} else
			err = 0;
	}

	err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (err) {
		log_error(lg, "Get(%s): cannot begin mdb log_lookup txn: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	if (!is_dupsort_tt(ttag)) {

		assert(!(flags & GBF_FLAG_DUPCOUNT));

		err = attrp ? mdb_get_attr(txn, dbi, &key, &data, attrp) :
			mdb_get(txn, dbi, &key, &data);
		if (err) {
			if (err == MDB_NOTFOUND) {
				err = -ENOENT;
			} else {
				log_error(lg, "Get(%s): cannot get value from "
				    "mdb: (%d) %s", dev->name, err, mdb_strerror(err));
				err = -EIO;
			}
			goto _exit;
		} else if (attrp) {
		       /* found touch record - return */
		       goto _exit;
		} else if (!repeat && !data.mv_size) {
			/* Log has a touch record, but we need it from main DB */
			err = -ENOENT;
			goto _exit;
		}
		uint64_t reallen = 0;
		uv_buf_t ent;
		if (repeat && is_kvs_offload_tt(ttag)) {
			/* The main TT for KVS offload type tags keeps only real chunk size */
			assert(data.mv_size == sizeof(reallen));
			memcpy(&reallen, data.mv_data, sizeof(reallen));
			assert(reallen < DEV_LMDB_LOG_MAXCHUNKSIZE);
			assert(reallen > 0);
			/* Get real chunk */
			ent.len = reallen > kvs->be_info.min_value_size ? reallen : kvs->be_info.min_value_size;
			ent.base = je_malloc(ent.len);
			uv_buf_t uk = { .base = key.mv_data, .len = key.mv_size };
			err = kvs->backend->get(kvs->be_inst, ttag, uk, &ent);
			if (err)
				goto _exit;
			ent.len = reallen;
		} else {
			ent.len = data.mv_size;
			ent.base = data.mv_data;
		}
		if (!err && filter_cb) {
			/* skip entry if filter has failed */
			err = filter_cb(arg, (void **)&ent.base, &ent.len, 0);
			if (err < 0)
				goto _exit;
		}
		if (!err && rb) {
			if (kvs->zerocopy >= 1)
				err = rtbuf_add_mapped(rb, &ent, 1);
			else
				err = rtbuf_add_alloc(rb, &ent, 1);
			if (err)
				err = -ENOMEM;
		}
		if (reallen && !kvs->zerocopy)
			je_free(ent.base);
		if (err) {
			log_error(lg, "Get(%s): unexpected error on log_lookup: %d",
			    dev->name, err);
			goto _exit;
		}

		found = 1;

		goto _exit;
	}

	err = mdb_cursor_open(txn, dbi, &cursor);
	if (err) {
		log_error(lg, "Get(%s): cannot open mdb log_lookup cursor: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	int op = (data.mv_data && ttag == TT_VERIFIED_BACKREF) ?
		MDB_GET_BOTH : MDB_SET_KEY;

	if (repeat)
		rt_lhtbl_sort(ht);
	int skip_main = 0;
	while ((err = mdb_cursor_get(cursor, &key, &data, op)) == 0) {
		op = MDB_NEXT_DUP;

		/* Skip entries scheduled for removal */
		if (!repeat) {
			/*
			 * Use the hash map to filter out duplicates if DUPCOUNT flag is set.
			 * In normal mode duplicates will be filtered out by
			 * the msort_nodup() which is faster.
			 */
			if (flags & GBF_FLAG_DUPCOUNT) {
				err = rt_lhtbl_insert(ht, data.mv_data, data.mv_size);
				assert(!err);
				st.n_ht_log++;
			}
			st.n_log++;
		} else  {
			if ((flags & GBF_FLAG_DUPCOUNT) &&
				!rt_lhtbl_query(ht, data.mv_data, data.mv_size)) {
				/*
				 * Skip already collected values
				 * when looking in main TT
				 */
				st.n_skip_main++;
				continue;

			}
			st.n_dup_main++;
		}
		dupcount++;
		if (flags & GBF_FLAG_DUPCOUNT) {
			if (max_num && max_num <= (int)dupcount) {
				skip_main = 1;
				break;
			}
			continue;
		}

		if (filter_cb) {
			/* The filter can return:
			 * == 0 - skip the entry
			 * > 0 append entry to buffer
			 * < 0 internal error, finish the call
			 */
			err = filter_cb(arg, &data.mv_data, &data.mv_size, 0);
			if (!err) {
				if (filter_cb == kvs_stat_filter) {
					skip_main = 1;
					err = 0;
					goto _exit;
				}
				continue;

			}
			if (err < 0)
				goto _exit;
		}

		uv_buf_t ent = { .len = data.mv_size, .base = data.mv_data };

		if (rb) {
			if (!repeat) {
				err = rt_duplist_add(&list_log, data.mv_data, data.mv_size, mapped);
				if (err)
					break;
				log_count++;
			} else {
				err = rt_duplist_add(&list_main, data.mv_data, data.mv_size, mapped);
				if (err)
					break;
				main_count++;
			}
		}
		if (err) {
			log_error(lg,
				"Get(%s): out of memory on log_lookup: %d",
				dev->name, err);
			goto _exit;
		}
		found++;
		/*
		 * Requested entry found in the log. Done.
		 */
		if ((flags & GBF_FLAG_ONE) || (max_num && found >= max_num)) {
			skip_main = 1;
			break;
		}
	}
	if (skip_main && !repeat)
		repeat = 1;

	if (err) {
		if (err == MDB_NOTFOUND) {
			if (((flags & GBF_FLAG_DUPCOUNT) || !rb) && repeat && dupcount)
				err = 0; /* found somewhere */
			else if (!rb || !rb->nbufs)
				err = -ENOENT;
			else
				found = 1;
		} else {
			log_error(lg, "mdb_cursor_get() returned %d\n", err);
			err = -EIO;
		}
	}

	if (repeat && (main_count || log_count)) {
		err = rt_duplist2rtbuf(ttag, list_log,log_count, list_main,
			main_count, rb, mapped);
		if (err) {
			log_error(lg, "Dev(%s) dupsort merge error %d\n",
				dev->name, err);
			found = 0;
		}
	}

_exit:
	if (cursor)
		mdb_cursor_close(cursor);
	if (txn)
		mdb_txn_abort(txn);
	if (found)
		err = 0;
	if (((!found && err == -ENOENT) || (flags & GBF_FLAG_ALL))
		&& !repeat) {
		/* now lookup in main TT */
		env = db->env;
		dbi = dbi_main;
		cursor = NULL;
		txn = NULL;
		repeat++;
		goto _repeat;
	}
	if (ht)
		rt_lhtbl_destroy(ht);
	if (!err && (flags & GBF_FLAG_DUPCOUNT) && arg)
		*(size_t *)arg = dupcount;
#if 0
	printf("#log %lu, #ht %lu, #skip %lu, #main %lu, #bufs %lu\n",
		st.n_log, st.n_ht_log, st.n_skip_main,
		st.n_dup_main, rb ? rb->nbufs : 0);
#endif
	return err;
}

static int
kvs_get_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	int flags, const uint512_t *chid_in, rtbuf_t **rb, int max_num,
	reptrans_blob_filter filter_cb, void *arg)
{
	int err = 0;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	uint512_t chid = *chid_in;
	uv_buf_t keybuf = { .base = NULL, .len = 0 };;

	assert (ttag != TT_HASHCOUNT);

	*rb = NULL;

	/* Do an inplace chid conversion for ttags sensitive to chid format */
	if (ttag == TT_TRANSACTION_LOG)
		rt_chid_swap_trlog(chid_in, &chid, &hash_type);
	else if (ttag == TT_VERIFICATION_QUEUE)
		rt_chid_swap_verqueue(chid_in, &chid, &hash_type);

	rt_set_thread_vdev_context(dev);
	err = kvs_key_encode(dev, ttag, hash_type, &chid, &keybuf, &db, &dbi,
	    &log);
	if (err)
		return err;

	*rb = rtbuf_init_empty();
	if (!*rb) {
		log_error(lg, "Get(%s): out of memory", dev->name);
		err = -ENOMEM;
		goto _exit;
	}

	err = kvs_log_lookup(dev, db, log, dbi, ttag, flags, &chid, &keybuf,
	    hash_type, *rb, max_num, filter_cb, arg, NULL);
	if (err) {
		rtbuf_destroy(*rb);
		*rb = NULL;
	} else {
		if (is_keycache_tt(ttag)) {
			MDB_val key;
			key.mv_size = keybuf.len;
			key.mv_data = keybuf.base;

			MDB_val keyhv;
			uint64_t kh;
			err = kvs_keyhash(dev, &key, &keyhv, &kh);
			if (!err)
				key_cache_insert(db->key_cache, &kh, ttag, rtbuf_len(*rb));
			else
				err = 0;
		}
	}
_exit:
	if (keybuf.base)
		je_free(keybuf.base);
	return err;
}

static int
kvs_get_blob_attr(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid_in, uint64_t *attrp)
{
	int err = 0;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	uint512_t chid = *chid_in;
	uv_buf_t keybuf = { .base = NULL, .len = 0 };;

	rt_set_thread_vdev_context(dev);
	/* Do an inplace chid conversion for ttags sensitive to chid format */
	if (ttag == TT_TRANSACTION_LOG)
		rt_chid_swap_trlog(chid_in, &chid, &hash_type);
	else if (ttag == TT_VERIFICATION_QUEUE)
		rt_chid_swap_verqueue(chid_in, &chid, &hash_type);

	err = kvs_key_encode(dev, ttag, hash_type, &chid, &keybuf, &db, &dbi, &log);
	if (err)
		return err;

	err = kvs_log_lookup(dev, db, log, dbi, ttag, GBF_FLAG_ONE, &chid, &keybuf,
	    hash_type, NULL, 1, NULL, NULL, attrp);

	if (keybuf.base)
		je_free(keybuf.base);
	return err;
}

static int
kvs_delete_blob_value(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid_in, uv_buf_t *val, size_t len)
{
	int err;
	MDB_txn *txn = NULL;
	MDB_val key, data;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi, dbi_main;
	MDB_env* env;
	uv_buf_t keybuf = { .base = NULL, .len = 0 };
	uint512_t chid = *chid_in;
	struct repdev_kvs* kvs = dev->device_lfs;
	int repeat, deleted = 0;

	assert(is_dupsort_tt(ttag));

	rt_set_thread_vdev_context(dev);
	/* Do an inplace chid conversion for ttags sensitive to chid format */
	if (ttag == TT_TRANSACTION_LOG)
		rt_chid_swap_trlog(chid_in, &chid, &hash_type);
	else if (ttag == TT_VERIFICATION_QUEUE)
		rt_chid_swap_verqueue(chid_in, &chid, &hash_type);

	err = kvs_key_encode(dev, ttag, hash_type, &chid, &keybuf, &db, &dbi_main,
	    &log);
	if (err) {
		log_error(lg, "Dev(%s): delete_blob kvs_key_encode: (%d) %s",
		    dev->name, err, strerror(err));
		return err;
	}

	kvs_log_flush_barrier(db, ttag, 1);

	if (is_log_tt(dev, ttag)) {
		/*
		 * Lookup in journal log first (in memory lookup) then in
		 * TT main db.
		 */
		env = log->env;
		dbi = log->dbi[ttag];
		repeat = 0;

	} else {
		/*
		 * This is direct TT main lookup.
		 */
		env = db->env;
		dbi = dbi_main;
		repeat = 1;
	}
	key.mv_data = keybuf.base;
	key.mv_size = keybuf.len;

_repeat:
	err = mdb_txn_begin(env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): delete_blob mdb_txn_begin: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	size_t nameindex_cnt = 0;
	size_t value_size = 0;
	if (val) {
		for (size_t i = 0; !err && val && i < len; ++i) {
			data.mv_data = val[i].base;
			data.mv_size = val[i].len;
			err = mdb_del(txn, dbi, &key, &data);
			if (err == MDB_NOTFOUND)
				err = 0;
			else if (!err)
				deleted++;
		}
	} else {
		if (ttag == TT_NAMEINDEX || (is_kvs_offload_tt(ttag) && repeat)) {
			MDB_cursor *cnt_cursor;
			err = mdb_cursor_open(txn, dbi, &cnt_cursor);
			if (err) {
				log_error(lg, "Get(%s): cannot open mdb delete_blob "
					"cursor: (%d) %s", dev->name, err,
					mdb_strerror(err));
				err = -EIO;
				goto _exit;
			}
			MDB_val data_empty = { .mv_size = 0, .mv_data = NULL };
			err = mdb_cursor_get(cnt_cursor, &key, &data_empty, MDB_SET_KEY);
			if (!err) {
				if (!is_kvs_offload_tt(ttag))
					mdb_cursor_count(cnt_cursor, &nameindex_cnt);
				else {
					assert(data_empty.mv_size == sizeof(value_size));
					memcpy(&value_size, data_empty.mv_data, data_empty.mv_size);
				}
			}
			mdb_cursor_close(cnt_cursor);
			if (err) {
				if (err == MDB_NOTFOUND)
					err = 0;
				goto _check_err;
			}
		}
		err = mdb_del(txn, dbi, &key, NULL);
		if (err == MDB_NOTFOUND)
			err = 0;
		else if (!err) {
			if (repeat && is_kvs_offload_tt(ttag)) {
				err = kvs->backend->remove(kvs->be_inst, ttag, &keybuf, 1);
				assert(err == 0);
				atomic_sub64(db->size + ttag, value_size);
				atomic_dec64(db->entries + ttag);
			}
			size_t del_cnt = (ttag == TT_NAMEINDEX) ? nameindex_cnt : 1;
			deleted += del_cnt;
		}
	}

_check_err:
	if (err) {
		log_error(lg, "Dev(%s): delete_blob mdb_del: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		mdb_txn_abort(txn);
	} else {
		err = mdb_txn_commit(txn);
		if (err) {
			log_error(lg, "Dev(%s): cannot commit delete "
			    "transaction: %d, %s", dev->name, err,
			    mdb_strerror(err));
			err = -EIO;
		}
	}

_exit:
	if ((!err || err == -ENOENT) && !repeat) {
		/* now delete from main TT */
		env = db->env;
		dbi = dbi_main;
		txn = NULL;
		repeat++;
		goto _repeat;
	}
	if ((!err || err == -ENOENT) && is_hashcount_data_type_tag(ttag) && deleted)
		reptrans_drop_hashcount(dev, &chid, deleted);

	kvs_log_flush_barrier(db, ttag, 0);
	if (keybuf.base)
		je_free(keybuf.base);
	log_debug(lg, "Dev(%s): %s delete_blob_value deleted=%d entries, err=%d",
	    dev->name, type_tag_name[ttag], deleted, err);
	return err;
}

static int
kvs_delete_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
    const uint512_t *chid_in)
{
	int err;
	MDB_txn *txn = NULL;
	MDB_val key;
	struct repdev_db *db, *db_lock = NULL;
	struct repdev_log *log;
	MDB_dbi dbi;
	MDB_dbi dbi_main;
	MDB_env* env;
	uint512_t chid = *chid_in;
	uv_buf_t keybuf = { .base = NULL, .len = 0 };
	int repeat = 0;

	struct repdev_kvs *kvs = dev->device_lfs;

	rt_set_thread_vdev_context(dev);
	/* Do an inplace chid conversion for ttags sensitive to chid format */
	if (ttag == TT_TRANSACTION_LOG)
		rt_chid_swap_trlog(chid_in, &chid, &hash_type);
	else if (ttag == TT_VERIFICATION_QUEUE)
		rt_chid_swap_verqueue(chid_in, &chid, &hash_type);

	err = kvs_key_encode(dev, ttag, hash_type, &chid, &keybuf, &db, &dbi_main,
	    &log);
	if (err) {
		log_error(lg, "Dev(%s): delete_blob kvs_key_encode: (%d) %s",
		    dev->name, err, strerror(err));
		return err;
	}

	if (is_log_tt(dev, ttag)) {
		/*
		 * Lookup in journal log first (in memory lookup) then in
		 * TT main db.
		 */
		env = log->env;
		dbi = log->dbi[ttag];
		repeat = 0;
	} else {
		/*
		 * This is direct TT main lookup.
		 */
		env = db->env;
		dbi = dbi_main;
		repeat = 1;
	}


_repeat:;

	MDB_val keyhv;
	uint64_t kh;

	key.mv_data = keybuf.base;
	key.mv_size = keybuf.len;
	db_lock = db;
	kvs_log_flush_barrier(db_lock, ttag, 1);

	err = mdb_txn_begin(env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): delete_blob mdb_txn_begin: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	if (is_keycache_tt(ttag)) {
		/*
		 * If we deleting from the log (repeat == 0) then we
		 * do not want to change original key, so we using
		 * tmpkey here. Notice: kvs_keyhash() will update key
		 */
		err = kvs_keyhash(dev, &key, &keyhv, &kh);
		if (err)
			goto _exit;

		key_cache_remove(db->key_cache, &kh, ttag);
	}

	size_t nameindex_cnt = 0;
	size_t value_size = 0;
	if (ttag == TT_NAMEINDEX || (repeat && is_kvs_offload_tt(ttag))) {
		MDB_cursor *cnt_cursor;
		err = mdb_cursor_open(txn, dbi, &cnt_cursor);
		if (err) {
			log_error(lg, "Get(%s): cannot open mdb delete_blob "
				"cursor: (%d) %s", dev->name, err,
				mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
		MDB_val data_empty = { .mv_size = 0, .mv_data = NULL };
		err = mdb_cursor_get(cnt_cursor, &key, &data_empty, MDB_SET_KEY);
		if (!err) {
			if (!is_kvs_offload_tt(ttag))
				mdb_cursor_count(cnt_cursor, &nameindex_cnt);
			else {
				assert(data_empty.mv_size == sizeof(value_size));
				memcpy(&value_size, data_empty.mv_data, data_empty.mv_size);
			}
		}
		mdb_cursor_close(cnt_cursor);
		if (err)
			goto _exit;
	}

	err = mdb_del(txn, dbi, &key, NULL);
	if (err) {
		log_debug(lg, "Dev(%s): delete_blob %s mdb_del: (%d) %s",
		    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
		/* No blob? No problem, we are deleting it anyway */
		if (err == MDB_NOTFOUND)
			err = 0;
		else
			err = -EIO;
	} else  {
		if (is_hashcount_data_type_tag(ttag)) {
			size_t del_cnt = (ttag == TT_NAMEINDEX) ? nameindex_cnt : 1;
			if (del_cnt)
				reptrans_drop_hashcount(dev, &chid, del_cnt);
		}
		if (repeat && is_kvs_offload_tt(ttag)) {
			err = kvs->backend->remove(kvs->be_inst, ttag, &keybuf, 1);
			assert(err == 0);
			atomic_sub64(db->size + ttag, value_size);
			atomic_dec64(db->entries + ttag);
		}
	}
	kvs_log_flush_barrier(db_lock, ttag, 0);
	db_lock = NULL;
_exit:
	if (err) {
		if (err == MDB_NOTFOUND)
			err = -ENOENT;
		if (txn)
			mdb_txn_abort(txn);
	} else if (txn) {
		err = mdb_txn_commit(txn);
		if (err) {
			log_error(lg, "Dev(%s): delete_blob %s mdb_txn_commit: (%d) %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
		}
	}
	if (db_lock) {
		kvs_log_flush_barrier(db_lock, ttag, 0);
	}
	if ((!err || err == -ENOENT) && !repeat) {
		/* now delete from main TT */
		env = db->env;
		dbi = dbi_main;
		txn = NULL;
		repeat++;
		goto _repeat;
	}
	if (keybuf.base)
		je_free(keybuf.base);
	return err;
}

static int
kvs_log_fetch_entries(struct repdev* dev, struct repdev_db *db, type_tag_t ttag,
	int want_values, struct rt_imsort* sh) {
	MDB_txn* log_txn = NULL;

	assert(is_dupsort_tt(ttag) == 0);

	int err = 0;
	if (is_log_tt(dev, ttag)) {
		MDB_val key, data;
		MDB_cursor* log_cursor = NULL;
		struct repdev_log *log = &db->log;
		err = mdb_txn_begin(log->env, NULL, MDB_RDONLY, &log_txn);
		if (err) {
			log_error(lg, "Get(%s): cannot begin log mdb "
			    "iterate_blobs txn: (%d) %s", dev->name,
			    err, mdb_strerror(err));
			err = -EIO;
			goto _exit;;
		}

		MDB_stat db_stat;
		err = mdb_stat(log_txn, log->dbi[ttag], &db_stat);
		if (err) {
			log_error(lg, "Get(%s): cannot open stat log mdb "
				": (%d) %s", dev->name,
				err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
		if (!db_stat.ms_entries) {
			mdb_txn_abort(log_txn);
			return 0;
		}
		err = mdb_cursor_open(log_txn, log->dbi[ttag], &log_cursor);
		if (err) {
			log_error(lg, "Get(%s): cannot open log mdb "
			    "iterate_blobs cursor: (%d) %s", dev->name,
			    err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
		int op = MDB_FIRST;
		int new_etry = 1;
		while ((err = mdb_cursor_get(log_cursor, &key, &data, op)) == 0) {
			op = MDB_NEXT;
			uint64_t attr = 0;
			err = mdb_cursor_get_attr(log_cursor, &key, &data, &attr);
			if (err) {
				log_error(lg, "Get(%s): cannot read attr in log_flush: %s (%d)",
				    dev->name, mdb_strerror(err), err);
				err = -EIO;
				goto _exit;
			}
			if (attr && sh) {
				type_tag_t ltt;
				crypto_hash_t ht;
				uint512_t chid;
				uv_buf_t uk = {.base = key.mv_data, .len = key.mv_size};

				err = kvs_key_deserialize(uk, &chid, &ht, NULL);
				if (err) {
					log_error(lg, "Dev(%s) couldn't decode key %s: %d",
						dev->name, type_tag_name[ttag], err);
				} else {
					uv_buf_t val = {.len = data.mv_size, .base = data.mv_data };
					err = reptrans_imsort_add_kv(sh, ht, &chid,
						want_values ? &val : NULL, new_etry);
					new_etry = 0;
					if (err) {
						log_error(lg, "Dev(%s) cannot append log's data to imsort: %d",
							dev->name, err);
						goto _exit;
					}
				}
			}
		}
		err = 0;
	}

_exit:
	if (log_txn)
		mdb_txn_abort(log_txn);
	return err;
}

#define ITERATOR_BATCH_NUM 256


static int
kvs_iterate_blobs_shard(struct repdev *dev, type_tag_t ttag,
    reptrans_blob_callback callback, void *param, int want_values,
    long max_blobs, int jpart, struct rt_imsort* sh)
{
	int err = 0;
	MDB_cursor *cursor = NULL;
	MDB_txn *txn = NULL;
	struct repdev_db *db = NULL;
	struct repdev_kvs* kvs = dev->device_lfs;

	int batched;
	long k;
	int new_part = 1;

	rtbuf_t *rbl;

	db = kvs->db + jpart;

	k = 0;
	rbl = rtbuf_init_empty();
	if (!rbl)
		return -ENOMEM;

	do {
		batched = 0;
		err = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn);
		if (err) {
			log_error(lg, "Get(%s): cannot begin mdb "
			    "iterate_blobs txn: (%d) %s", dev->name,
			    err, mdb_strerror(err));
			err = -EIO;
			continue;
		}

		MDB_dbi dbi_last = db->dbi[ttag];
		err = mdb_cursor_open(txn, dbi_last, &cursor);
		if (err) {
			mdb_txn_abort(txn);
			log_error(lg, "Get(%s): cannot open mdb "
			    "iterate_blobs cursor: (%d) %s", dev->name,
			    err, mdb_strerror(err));
			err = -EIO;
			continue;
		}

		rtbuf_t *rb = rtbuf_init(NULL, ITERATOR_BATCH_NUM);
		if (!rb) {
			mdb_cursor_close(cursor);
			mdb_txn_abort(txn);
			continue;
		}

		MDB_val key = {0, NULL}, data = {0, NULL};
		MDB_val *pdata = &data;
		rtbuf_t *rbv = NULL;
		if (want_values) {
			rbv = rtbuf_init(NULL, ITERATOR_BATCH_NUM);
			if (!rbv) {
				rtbuf_destroy(rb);
				mdb_cursor_close(cursor);
				mdb_txn_abort(txn);
				continue;
			}
		} else if (!is_dupsort_tt(ttag)) {
			pdata = NULL;
		}
		int op = MDB_FIRST;
		if( k ) {
			key.mv_size = rtbuf(rbl, 0).len;
			key.mv_data = rtbuf(rbl, 0).base;
			if (is_dupsort_tt(ttag)) {
				op = MDB_GET_BOTH_RANGE;
				data.mv_size = rtbuf(rbl, 1).len;
				data.mv_data = rtbuf(rbl, 1).base;
			} else {
				op = MDB_SET_RANGE;
			}
		}
		while ((err = mdb_cursor_get(cursor, &key, pdata, op)) == 0) {
			op = MDB_NEXT; // FIXME: why not MDB_NEXT_DUP in case of dup?

			/* skip last key as it was processed in
			 * the previous batch and if it wasn't deleted */
			if (batched == 0 && k && !is_dupsort_tt(ttag) &&
			    rtbuf(rbl, 0).len == key.mv_size &&
			    (key.mv_size == 0 || !memcmp(rtbuf(rbl, 0).base, key.mv_data, key.mv_size)))
				continue;
			if (batched == 0 && k && is_dupsort_tt(ttag) &&
			    rtbuf(rbl, 1).len == data.mv_size &&
			    (data.mv_size == 0 || !memcmp(rtbuf(rbl, 1).base, data.mv_data, data.mv_size)))
				continue;

			uv_buf_t bufkey = {
				.len = key.mv_size,
				.base = key.mv_data
			};

			uv_buf_t bufdata = {
				.len = data.mv_size,
				.base = data.mv_data
			};

			uint64_t realsize = 0;
			if (want_values && pdata && is_kvs_offload_tt(ttag)) {
				assert(pdata->mv_size == sizeof(realsize));
				memcpy(&realsize, pdata->mv_data, pdata->mv_size);
				bufdata.len = realsize > kvs->be_info.min_value_size ?
					realsize : kvs->be_info.min_value_size;
				bufdata.base = je_malloc(bufdata.len);
				if (!bufdata.base) {
					log_error(lg, "memory allocation error");
					err = -ENOMEM;
					break;
				}
				err = kvs->backend->get(kvs->be_inst, ttag, bufkey, &bufdata);
				if (err) {
					je_free(bufdata.base);
					break;
				}
				bufdata.len = realsize;
			}
			err = rtbuf_set_alloc(rb, batched, &bufkey, 1);
			if (err) {
				log_error(lg, "rtbuf_add failed %d\n",
				    err);
				break;
			}

			if (rbv) {
				err = rtbuf_set_alloc(rbv, batched, &bufdata, 1);
				if (err) {
					log_error(lg,
					    "rtbuf_add failed %d\n",
					    err);
					rtbuf_free_one(rb, --rb->nbufs);
					break;
				}
				if (realsize)
					je_free(bufdata.base);
			}
			batched++;

			if (batched == ITERATOR_BATCH_NUM) {
				if (rbl->nbufs > 0) {
					rtbuf_destroy(rbl);
					rbl = rtbuf_init_empty();
					if (!rbl)
						break;
				}
				err = rtbuf_add_alloc(rbl, &bufkey, 1);
				if (err) {
					rtbuf_destroy(rbl);
					rbl = NULL;
					break;
				}
				if (is_dupsort_tt(ttag)) {
					err = rtbuf_add_alloc(rbl,
					    &bufdata, 1);
					if (err) {
						rtbuf_destroy(rbl);
						rbl = NULL;
						break;
					}
				}
				break;
			}
		}

		/* adjust rb/v sizes */
		rb->nbufs = batched;
		if (rbv)
			rbv->nbufs = batched;

		/* Why we need rbl?
		 *
		 * we do NOT keep cursor open while calling iterators
		 * callback but we have to keep last element in memory
		 * so that we can jump to the place where we stopped
		 * hence why we need rbl */

		mdb_cursor_close(cursor);
		mdb_txn_abort(txn);

		if (!rbl) {
			rtbuf_destroy(rb);
			if (rbv)
				rtbuf_destroy(rbv);
			break;
		}

		for (size_t i = 0; i < rb->nbufs; i++) {
			uint512_t chid;
			crypto_hash_t key_hash_type;
			type_tag_t key_ttag;

			err = kvs_key_deserialize(rb->bufs[i], &chid, &key_hash_type, NULL);

			if (err || (rbv && !rbv->nbufs))
				continue;

			err = reptrans_imsort_add_kv(sh,
			    key_hash_type, &chid,
			    rbv ? &rbv->bufs[i] : NULL,
			    new_part);
			if (err) {
				log_error(lg, "Dev(%s) error adding imsort entry: %d",
				    dev->name, err);
				rtbuf_destroy(rb);
				if (rbv)
					rtbuf_destroy(rbv);
				rtbuf_destroy(rbl);
				return err;
			}
		}

		rtbuf_destroy(rb);
		if (rbv)
			rtbuf_destroy(rbv);

		k += batched;
		if (max_blobs != -1 && k >= max_blobs)
			break;
	} while (batched == ITERATOR_BATCH_NUM);

	if (rbl)
		rtbuf_destroy(rbl);

	return err;
}


static int
kvs_iterate_blobs_strict(struct repdev *dev, type_tag_t ttag,
    reptrans_blob_callback callback, void *param, int want_values,
    int max_blobs)
{
	int err = 0;
	MDB_cursor *cursor = NULL;
	MDB_txn *txn = NULL;
	struct repdev_kvs *kvs = dev->device_lfs;
	struct repdev_db *db = NULL;
	struct rt_imsort* sh = NULL;

	err = reptrans_imsort_create(dev, ttag, param, &sh);
	if (err) {
		log_error(lg, "Dev(%s) cannot create imsort instance: %d",
		    dev->name, err);
		return err;
	}

	int max_blobs_adj = max_blobs;
	if (max_blobs != -1) {
		max_blobs_adj = max_blobs / kvs->plevel;
		max_blobs_adj = max_blobs_adj + max_blobs_adj / 8;
		if (max_blobs_adj < 64)
			max_blobs_adj = 64;
	}

	for (int j = 0; j < kvs->plevel; j++) {
		db = kvs->db + j;

		if (is_dupsort_tt(ttag) && is_log_tt(dev, ttag)) {
			struct repdev_log *log = &db->log;
			err = kvs_log_flush(log, ttag);
			if (err)
				break;
			if (err)
				return err;
			kvs_log_flush_wait(db, ttag);
		} else {
			err = kvs_log_fetch_entries(dev, db, ttag, want_values, sh);
			if (err)
				break;
		}

		err = kvs_iterate_blobs_shard(dev, ttag,
		    callback, param, want_values,
		    max_blobs_adj, j, sh);
		if (err && err != MDB_NOTFOUND)
			log_error(lg, "Get(%s): cannot load part %d, err: %d",
			    dev->name, j, err);
	}

	err = reptrans_imsort_iterate(sh, callback, RT_KEY_FORMAT_LINEAR);
	reptrans_imsort_destroy(sh);

	return err;
}



static int
kvs_iterate_blobs_nonstrict(struct repdev *dev, type_tag_t ttag,
    reptrans_blob_callback callback, void *param, int want_values)
{
	int err = 0;
	MDB_cursor *cursor = NULL;
	MDB_txn *txn = NULL;
	struct repdev_kvs *kvs = dev->device_lfs;
	struct repdev_db *db = NULL;
	struct rt_imsort* sh = NULL;
	int batched;
	long k;
	for (int j = 0; j < kvs->plevel; j++) {
		rtbuf_t *rbl;

		db = kvs->db + j;

		if (is_log_tt(dev, ttag) && is_dupsort_tt(ttag)) {
			struct repdev_log *log = &db->log;
			err = kvs_log_flush(log, ttag);
			if (err)
				break;
			if (err)
				return err;
			kvs_log_flush_wait(db, ttag);
		}

		k = 0;
		rbl = rtbuf_init_empty();
		if (!rbl)
			return -ENOMEM;

		do {
			batched = 0;
			err = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn);
			if (err) {
				log_error(lg, "Get(%s): cannot begin mdb "
				    "iterate_blobs txn: (%d) %s", dev->name,
				    err, mdb_strerror(err));
				err = -EIO;
				continue;
			}

			MDB_dbi dbi_last = db->dbi[ttag];
			err = mdb_cursor_open(txn, dbi_last, &cursor);
			if (err) {
				mdb_txn_abort(txn);
				log_error(lg, "Get(%s): cannot open mdb "
				    "iterate_blobs cursor: (%d) %s", dev->name,
				    err, mdb_strerror(err));
				err = -EIO;
				continue;
			}

			rtbuf_t *rb = rtbuf_init(NULL, ITERATOR_BATCH_NUM);
			if (!rb) {
				mdb_cursor_close(cursor);
				mdb_txn_abort(txn);
				continue;
			}

			MDB_val key = {0, NULL}, data = {0, NULL};
			MDB_val *pdata = &data;
			rtbuf_t *rbv = NULL;
			if (want_values) {
				rbv = rtbuf_init(NULL, ITERATOR_BATCH_NUM);
				if (!rbv) {
					rtbuf_destroy(rb);
					mdb_cursor_close(cursor);
					mdb_txn_abort(txn);
					continue;
				}
			} else if (!is_dupsort_tt(ttag)) {
				pdata = NULL;
			}
			int op = MDB_FIRST;
			if( k ) {
				key.mv_size = rtbuf(rbl, 0).len;
				key.mv_data = rtbuf(rbl, 0).base;
				if (is_dupsort_tt(ttag)) {
					op = MDB_GET_BOTH_RANGE;
					data.mv_size = rtbuf(rbl, 1).len;
					data.mv_data = rtbuf(rbl, 1).base;
				} else {
					op = MDB_SET_RANGE;
				}
			}
			while ((err = mdb_cursor_get(cursor, &key, pdata, op)) == 0) {
				op = MDB_NEXT; // FIXME: why not MDB_NEXT_DUP in case of dup?

				/* skip last key as it was processed in
				 * the previous batch and if it wasn't deleted */
				if (batched == 0 && k && !is_dupsort_tt(ttag) &&
				    rtbuf(rbl, 0).len == key.mv_size &&
				    (key.mv_size == 0 || !memcmp(rtbuf(rbl, 0).base, key.mv_data, key.mv_size)))
					continue;
				if (batched == 0 && k && is_dupsort_tt(ttag) &&
				    rtbuf(rbl, 1).len == data.mv_size &&
				    (data.mv_size == 0 || !memcmp(rtbuf(rbl, 1).base, data.mv_data, data.mv_size)))
					continue;

				uv_buf_t bufkey = {
					.len = key.mv_size,
					.base = key.mv_data
				};

				uv_buf_t bufdata = {
					.len = data.mv_size,
					.base = data.mv_data
				};

				uint64_t realsize = 0;
				if (want_values && pdata && is_kvs_offload_tt(ttag)) {
					assert(pdata->mv_size == sizeof(realsize));
					memcpy(&realsize, pdata->mv_data, pdata->mv_size);
					bufdata.len = realsize > kvs->be_info.min_value_size ?
						realsize : kvs->be_info.min_value_size;
					bufdata.base = je_malloc(bufdata.len);
					if (!bufdata.base) {
						log_error(lg, "memory allocation error");
						err = -ENOMEM;
						break;
					}
					err = kvs->backend->get(kvs->be_inst, ttag, bufkey, &bufdata);
					if (err) {
						je_free(bufdata.base);
						break;
					}
					bufdata.len = realsize;
				}

				err = rtbuf_set_alloc(rb, batched, &bufkey, 1);
				if (err) {
					log_error(lg, "rtbuf_add failed %d\n",
					    err);
					break;
				}

				if (rbv) {
					err = rtbuf_set_alloc(rbv, batched, &bufdata, 1);
					if (err) {
						log_error(lg,
						    "rtbuf_add failed %d\n",
						    err);
						rtbuf_free_one(rb, --rb->nbufs);
						break;
					}
					if (realsize)
						je_free(bufdata.base);
				}
				batched++;

				if (batched == ITERATOR_BATCH_NUM) {
					if (rbl->nbufs > 0) {
						rtbuf_destroy(rbl);
						rbl = rtbuf_init_empty();
						if (!rbl)
							break;
					}
					err = rtbuf_add_alloc(rbl, &bufkey, 1);
					if (err) {
						rtbuf_destroy(rbl);
						rbl = NULL;
						break;
					}
					if (is_dupsort_tt(ttag)) {
						err = rtbuf_add_alloc(rbl,
						    &bufdata, 1);
						if (err) {
							rtbuf_destroy(rbl);
							rbl = NULL;
							break;
						}
					}
					break;
				}
			}

			/* adjust rb/v sizes */
			rb->nbufs = batched;
			if (rbv)
				rbv->nbufs = batched;

			/* Why we need rbl?
			 *
			 * we do NOT keep cursor open while calling iterators
			 * callback but we have to keep last element in memory
			 * so that we can jump to the place where we stopped
			 * hence why we need rbl */

			mdb_cursor_close(cursor);
			mdb_txn_abort(txn);

			if (!rbl) {
				rtbuf_destroy(rb);
				if (rbv)
					rtbuf_destroy(rbv);
				break;
			}

			for (size_t i = 0; i < rb->nbufs; i++) {
				uint512_t chid, chid_conv;
				crypto_hash_t key_hash_type;

				err = kvs_key_deserialize(rb->bufs[i], &chid, &key_hash_type, NULL);

				if (err || (rbv && !rbv->nbufs))
					continue;
				chid_conv = chid;
				/* Do an inplace chid conversion for ttags sensitive to chid format */
				if (ttag == TT_TRANSACTION_LOG)
					rt_chid_unswap_trlog(&chid, &chid_conv);
				else if (ttag == TT_VERIFICATION_QUEUE)
					rt_chid_unswap_verqueue(&chid, &chid_conv);

				err = callback(dev, ttag, key_hash_type, &chid_conv,
				    rbv ? &rbv->bufs[i] : NULL, param);
				if (err) {
					char chidbuf[UINT512_BYTES * 2 + 1];
					uint512_dump(&chid, chidbuf,
					    UINT512_BYTES * 2 + 1);
					if (err != -ENOSPC) {
						log_debug(lg, "dev %s: ttag %s, CHID %s, err %d",
						    dev->name, type_tag_name[ttag], chidbuf, err);
					}
					rtbuf_destroy(rb);
					if (rbv)
						rtbuf_destroy(rbv);
					rtbuf_destroy(rbl);
					return err;
				}
			}

			rtbuf_destroy(rb);
			if (rbv)
				rtbuf_destroy(rbv);

			k += batched;
		} while (batched == ITERATOR_BATCH_NUM);

		if (rbl)
			rtbuf_destroy(rbl);
	}
	err = 0;
	return err;
}


static int
kvs_iterate_blobs(struct repdev *dev, type_tag_t ttag,
    reptrans_blob_callback callback, void *param, int want_values,
    int strict_order, int max_blobs)
{
	rt_set_thread_vdev_context(dev);
	if (strict_order) {
		return kvs_iterate_blobs_strict(dev, ttag,
		    callback, param, want_values, max_blobs);
	}
	return kvs_iterate_blobs_nonstrict(dev, ttag,
	    callback, param, want_values);
}


struct list_chids_param {
	uint512_t *chids;
	uint64_t mask;
	uint64_t ng;
	int max;
	int current;
};

static int
list_blob_chids_iter(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *chid, uv_buf_t *val, void *arg)
{
	struct list_chids_param *param = (struct list_chids_param *)arg;
	assert(param != NULL);
	if (param->current >= param->max) {
		return -ENOSPC;
	}

	if (param->mask == 0 || (HASHCALC(chid, param->mask)) == param->ng) {
		param->chids[param->current++] = *chid;
	}
	return 0;
}

static int
kvs_list_blob_chids(struct repdev *dev, type_tag_t ttag, uint64_t ng,
	const uint64_t mask, int max, uint512_t *chids)
{
	struct list_chids_param param = {
		.chids = chids,
		.max = max,
		.current = 0,
		.ng = ng,
		.mask = mask
	};

	rt_set_thread_vdev_context(dev);
	int err = kvs_iterate_blobs(dev, ttag, list_blob_chids_iter, &param, 0,
		0, -1);
	if (err) {
		if (err == -ENOSPC) {
			return param.current;
		}
		return err;
	}
	return param.current;
}

static int
kvs_stat_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid_in, struct blob_stat *bs)
{
	int err = 0;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	uv_buf_t keybuf = { .base = NULL, .len = 0 };

	assert(ttag != TT_HASHCOUNT);

	rt_set_thread_vdev_context(dev);
	uint512_t chid = *chid_in;

	/* Do an inplace chid conversion for ttags sensitive to chid format */
	if (ttag == TT_TRANSACTION_LOG)
		rt_chid_swap_trlog(chid_in, &chid, &hash_type);
	else if (ttag == TT_VERIFICATION_QUEUE)
		rt_chid_swap_verqueue(chid_in, &chid, &hash_type);

	err = kvs_key_encode(dev, ttag, hash_type, &chid, &keybuf, &db, &dbi, &log);
	if (err)
		return err;

	err = kvs_log_lookup(dev, db, log, dbi, ttag, GBF_FLAG_ONE, &chid, &keybuf,
		hash_type, NULL, 1, kvs_stat_filter, bs, NULL);
	if (err) {
		log_debug(lg, "Stat(%s): cannot stat blob from mdb: %d",
		    dev->name, err);
		if (bs)
			bs->size = 0;
	}
	if (keybuf.base)
		je_free(keybuf.base);
	return err;
}

static int
kvs_query_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid, uint64_t *outsize)
{
	int err = 0;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	uv_buf_t keybuf = { .base = NULL, .len = 0 };

	rt_set_thread_vdev_context(dev);
	if (!is_keycache_tt(ttag) && ttag != TT_NAMEINDEX)
		return 1;

	err = kvs_key_encode(dev, ttag, hash_type, chid, &keybuf, &db, &dbi, &log);
	if (err)
		return err;

	MDB_val key;
	key.mv_size = keybuf.len;
	key.mv_data = keybuf.base;

	MDB_val keyhv;
	uint64_t kh;
	err = kvs_keyhash(dev, &key, &keyhv, &kh);
	if (err)
		goto _exit;

	if (!db->dev->keycache_enabled) {
		err = kvs_bloom_query(db, kh);
		if (err)
			err = -1; /* to signify that direct match disabled */
	} else {
		err = kvs_bloom_query(db, kh);
		if (err != 0 && ttag != TT_NAMEINDEX) {
			/* maybe exists */
			err = key_cache_lookup(db->key_cache, &kh, ttag, outsize);
			if (!err) {
				/* definetely exists */
				err = -EEXIST;
				goto _exit;
			} else
				err = -1;
		}
	}

_exit:
	if (keybuf.base)
		je_free(keybuf.base);
	return err;
}

static int
kvs_compactify(struct repdev* dev, type_tag_t ttag_req, size_t thd_mb,
	comp_cb_t cb) {
	return 0;
}

struct repdev_vtbl kvs_dev_vtbl = {
	.stat_refresh = kvs_dev_stat_refresh,
	.put_blob = kvs_put_blob,
	.put_blob_with_attr = kvs_put_blob_with_attr,
	.get_blob = kvs_get_blob,
	.get_blob_attr = kvs_get_blob_attr,
	.set_blob_attr = kvs_set_blob_attr,
	.delete_blob = kvs_delete_blob,
	.delete_blob_value = kvs_delete_blob_value,
	.iterate_blobs = kvs_iterate_blobs,
	.list_blob_chids = kvs_list_blob_chids,
	.stat_blob = kvs_stat_blob,
	.query_blob = kvs_query_blob,
	.config = kvs_config,
	.compactify = kvs_compactify
};


static int
kvs_is_mountpoint(char *file_name)
{
	struct stat file_stat;
	struct stat parent_stat;
	char *parent_name = je_strdup(file_name);

	/* get the parent directory of the file */
	parent_name = dirname(parent_name);

	/* get the file's stat info */
	if (-1 == stat(file_name, &file_stat))
		goto _fail;

	/* determine whether the supplied file is a directory
	 * if it isn't, then it can't be a mountpoint. */
	if (!(file_stat.st_mode & S_IFDIR))
		goto _fail;

	/* get the parent's stat info */
	if (-1 == stat(parent_name, &parent_stat))
		goto _fail;

	/* if file and parent have different device ids,
	 * then the file is a mount point */
	if (file_stat.st_dev == parent_stat.st_dev)
		goto _fail;

	je_free(parent_name);
	return 1;

_fail:
	je_free(parent_name);
	return 0;
}

struct kvs_arg {
	pthread_t th;
	struct repdev *dev;
	int init;
	int plevel_override;
	int sync;
	int readahead;
	int direct;
	int zerocopy;
	int err;
	size_t j_size;
	struct repdev_bg_config *bg_cfg;
	const char* backend_name;
	json_value* backend_opts;
	int n_dev;
};

static void *
kvs_dev_init(void *kvs_arg)
{
	struct kvs_arg *arg = kvs_arg;
	int err;
	struct stat st;
	struct repdev *dev = arg->dev;
	int sync = arg->sync;
	int readahead = arg->readahead;
	int direct = arg->direct;
	int plevel_override = arg->plevel_override;
	uint32_t flags = dev->rt->flags;
	char fname[PATH_MAX];
	struct repdev_db *db = NULL;
	struct repdev_kvs *kvs = NULL;
	int all_bloom_loaded = 0;
	unsigned int parts_count = 0;
	DIR *dirp = NULL;
	struct dirent *entry = NULL;
	size_t j_size = arg->j_size;

	assert(dev->journal);

	/* main and journal DBI are located on the same disk */
	char mp[PATH_MAX];
	err = kvs_get_mountpoint_by_name(dev->journal, mp, sizeof(mp));

	if (err) {
		arg->err = err;
		return NULL;
	}

	if (dev->rt->init_traits) {
		struct ccowd_params* params = dev->rt->init_traits;
		if ((params->log_flush || params->log_recovery) &&
		    strcmp(dev->name, params->name)) {
			log_info(lg, "Dev(%s): skipped", dev->name);
			arg->err = -ENODEV;
			return NULL;
		}
	}

	struct statvfs s;
	if (statvfs(mp, &s) != 0) {
		log_error(lg, "Can't access device path %s: %d", dev->path,
		    -errno);
		arg->err = -errno;
		return NULL;
	}

	dev->stats.physical_capacity = 1024UL*1024UL*1024UL*1024UL;
	/* We use journal name suffixed by VDEV name */
	strcat(mp, "/");
	strcat(mp, dev->name);
	err = mkdir(mp, S_IRWXU);
	if (err && errno != EEXIST) {
		log_error(lg, "Dev(%s) couldn't create folder %s: %d (%s)",
			dev->name, mp, errno, strerror(errno));
		arg->err = -err;
		return NULL;
	}

	sprintf(fname, "%s/%s", mp, DEV_METADATA);
	int formatted = !stat(fname, &st);
	int plevel = 0;
	int version = -1;

	uv_buf_t mbuf;
	if (formatted) {
		int fd = open(fname, O_RDONLY);
		if (fd < 0) {
			log_error(lg, "Cannot open file for read: %s", fname);
			arg->err = -errno;
			return NULL;
		}

		mbuf.len = st.st_size;
		mbuf.base = je_malloc(mbuf.len);
		if (!mbuf.base) {
			close(fd);
			log_error(lg, "Out of memory while reading: %s", fname);
			arg->err = -ENOMEM;
			return NULL;
		}

		err = read(fd, mbuf.base, mbuf.len);
		if (err == -1) {
			close(fd);
			je_free(mbuf.base);
			log_error(lg, "Cannot read file %s", fname);
			arg->err = -errno;
			return NULL;
		}
		close(fd);
	} else if (!(flags & RT_FLAG_RDONLY) && (flags & RT_FLAG_CREATE)) {
		int fd = open(fname, O_SYNC | O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
		if (fd < 0) {
			log_error(lg, "Cannot create file: %s", fname);
			arg->err = -errno;
			return NULL;
		}

		mbuf.base = je_malloc(4096);
		if (!mbuf.base) {
			close(fd);
			log_error(lg, "Out of memory while reading: %s", fname);
			arg->err = -ENOMEM;
			return NULL;
		}

		int plevel_calc = plevel_override ? plevel_override : 1;

		char s_serverid[SERVER_ID_MAXLEN];
		serverid_dump(s_serverid, SERVER_ID_MAXLEN);

		/* create new metafile */
		sprintf(mbuf.base, "{\n"
		    "\t\"created-timestamp\" : %u,\n"
		    "\t\"plevel\" : %d,\n"
		    "\t\"devpath\" : \"%s\",\n"
		    "\t\"serverid\" : \"%s\",\n"
		    "\t\"version\" : %d\n"
		    "}\n",
		    (unsigned)time(NULL), plevel_calc, dev->path, s_serverid, DEV_KVS_VERSION);
		mbuf.len = strlen(mbuf.base);
		err = write(fd, mbuf.base, mbuf.len);
		if (err < 0) {
			close(fd);
			je_free(mbuf.base);
			log_error(lg, "Cannot write to file: %s", fname);
			arg->err = -errno;
			return NULL;
		}
		close(fd);
	} else {
		log_error(lg, "Permissions denied, flags=0x%X", flags);
		arg->err = -EACCES;
		return NULL;
	}

	/* read metafile */
	json_value *o = json_parse(mbuf.base, mbuf.len);
	if (!o) {
		log_error(lg, "Cannot parse file: %s", fname);
		je_free(mbuf.base);
		arg->err = -EBADF;
		return NULL;
	}

	if (o->type != json_object) {
		log_error(lg, "Syntax error: metafile not a JSON object");
		json_value_free(o);
		je_free(mbuf.base);
		arg->err = -2;
		return NULL;
	}

	/* read JSON and update device structure */
	size_t i;
	for (i = 0; i < o->u.object.length; i++) {
		if (strncmp(o->u.object.values[i].name,
			    DEV_CREATED_TIMESTAMP,
			    strlen(DEV_CREATED_TIMESTAMP)) == 0) {
			dev->created_timestamp =
				o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,
			    "plevel", 6) == 0) {
			plevel = o->u.object.values[i].value->u.integer;
		}  else if (strncmp(o->u.object.values[i].name,
			    "version", 7) == 0) {
			version = o->u.object.values[i].value->u.integer;
		}
	}
	json_value_free(o);

	/* We assume the unversioned LFS is fully compatible with the latest */
	if (version < 0) {
		log_notice(lg, "Dev(%s): couldn't detect LFS version, "
		    "force it to #%d", dev->name, DEV_KVS_VERSION);
		version = DEV_KVS_VERSION;
	}

	/*
	 * LFS doesn't work with the LFS version higher than current.
	 * If the read LFS version is lower than current, then there
	 * are 2 options: either add backward compatibility support or
	 * exit with error.
	 */
	if (version != DEV_KVS_VERSION) {
		log_error(lg, "Error: unknown LFS version %d, expected %d",
		    version, DEV_KVS_VERSION);
		err = -EINVAL;
		goto _exit;
	}
	/*
	 * Availability of metafile would assume that layout of the
	 * root filesystem is prepared in advanced. That means upper
	 * management layer needs to build filesystems and assign right
	 * properties to it.
	 */
	if (!plevel) {
		log_error(lg, "Syntax error: can't find correct 'plevel' key "
		    "in metafile");
		err = -ENOENT;
		goto _exit;
	}

	dev->status = dev->prev_status = REPDEV_STATUS_INIT;
	uint64_t part_size = (j_size - DEV_LMDB_LOG_MAPSIZE) / plevel;

	kvs = je_calloc(1, sizeof(*kvs));
	if (!kvs) {
		err = -ENOMEM;
		goto _exit;
	}
	kvs->db = je_calloc(plevel, sizeof(struct repdev_db));
	if (!kvs->db) {
		err = -ENOMEM;
		goto _exit;
	}
	dev->device_lfs = kvs;
	dev->plevel = kvs->plevel = plevel;
	kvs->sync = sync;
	kvs->readahead = readahead;
	kvs->direct = direct;
	kvs->ssd_part_size = j_size;

	sprintf(fname, "%s/main/%s", mp, DEV_PARTS_DIR);
	if (stat(fname, &st) != 0) {
		if ((flags & RT_FLAG_RDONLY) && !(flags & RT_FLAG_CREATE)) {
			log_error(lg, "Permissions denied, flags=0x%X", flags);
			err = -EACCES;
			goto _exit;
		}
	}

	sprintf(fname, "mkdir -p %s/main/%s", mp, DEV_PARTS_DIR);
	err = system(fname);
	if (err)
		goto _exit;

	/* Initialize key-value backend driver */
	kvs->backend = kvs_backend_get(arg->backend_name);
	if (!kvs->backend) {
		log_error(lg, "Dev(%s) couldn't find backed %s", dev->name, arg->backend_name);
		goto _exit;
	}

	err = kvs->backend->init(dev->path, arg->backend_opts, &kvs->be_inst);
	if (err) {
		log_error(lg, "Dev(%s) couldn't create an instance of backed %s: %d",
			dev->name, arg->backend_name, err);
		goto _exit;

	}
	log_notice(lg, "Dev(%s) using the %s key-value backend", dev->name, arg->backend_name);

	err = kvs->backend->info(kvs->be_inst, &kvs->be_info);
	if (err) {
		log_error(lg, "Dev(%s) backend error %d", dev->name, err);
		goto _exit;
	}

	/*
	 * Parts location initialization
	 */
	if (is_embedded())
		dev->keycache_size_max /= arg->n_dev * plevel;

	for (int j = 0; j < plevel; ++j) {
		char envpath[PATH_MAX];

		db = kvs->db + j;
		db->part = j;
		db->dev = dev;
		sprintf(fname, "%s/main/%s/%02x", mp, DEV_PARTS_DIR, j);
		if (stat(fname, &st) != 0) {
			if (!(flags & RT_FLAG_RDONLY) && (flags & RT_FLAG_CREATE)) {
				err = mkdir(fname, S_IRWXU);
				if (err && errno != EEXIST) {
					log_error(lg, "Cannot create part location: %s",
					    strerror(errno));
					goto _exit;
				}
			} else {
				log_error(lg, "Permissions denied, flags=0x%X", flags);
				err = -EACCES;
				goto _exit;
			}
		}

		/*
		 * Initialize/Open write log file
		 */

		sprintf(envpath, "mkdir -p %s/journal/%s/%02x", mp, DEV_PARTS_DIR, j);
		err = system(envpath);
		if (err)
			goto _exit;
		sprintf(envpath, "%s/journal/%s/%02x/journal", mp, DEV_PARTS_DIR, j);

		struct ccowd_params* params = dev->rt->init_traits;

		if (dev->wal_disabled != WAL_MODE_DISABLED) {
			if (params && params->log_recovery) {
				char path[PATH_MAX];
				sprintf(path, "%s.mdb", envpath);
				params->log_err = unlink(path);
				err = -ENODEV;
				goto _exit;
			}
			err = kvs_log_open(dev, envpath, db);
			if (err)
				goto _exit;
		}
		if (params && params->log_recovery)
			goto _exit;

		log_debug(lg, "Dev(%s): journal (%u maxentries %u maxchunk) "
		    "initialized", dev->name, dev->journal_maxentries,
		    dev->journal_maxchunksize);

		/* Allocate table, each entry is one bit; these are packed into
		 * uint32_t.  When allocating we must round the length up to the
		 * nearest integer. */
		db->bloom = je_calloc(1, KEY_BLOOM_BYTELEN);
		if (!db->bloom) {
			err = -ENOMEM;
			goto _exit;
		}
		uv_rwlock_init(&db->bloom_lock);

		if (dev->keycache_enabled == 1) {
			if (key_cache_ini(&db->key_cache, dev->keycache_size_max, NULL) != 0)
				log_error(lg, "Failed to init LRU key cache for dev: %s",
						dev->name);
			else
				log_info(lg, "key cache initialized for dev: %s max size %d",
						dev->name,
						dev->keycache_size_max);
		} else {
			log_info(lg, "key cache disabled for dev %s", dev->name);
			kvs->db->key_cache = NULL;
		}

		/*
		 * LMDB initialization
		 */
		err = kvs_lmdb_init(kvs, mp, db, part_size, flags);
		if (err) {
			err = -EIO;
			goto _exit;
		}
	}

	err = kvs_lmdb_metacheck(kvs, dev->name, &mbuf, formatted, flags);
	if (err)
		goto _exit;
	/*
	 * the order of loading is important:
	 *
	 * 1) try to load bloom from lmdb
	 * 2) flush logs
	 * 3) if (1) failed, async load bloom
	 *
	 * this is because (1) overwrites whats in the filter
	 * where as (3) augments.
	 */

	int need_bloom = kvs_dev_load_bloom(dev);

	/* need to load HC table as flush will possibly update it */
	uv_buf_t u_key, u_val;
	u_key.len = strlen(HASHCOUNT_BLOB_KEY) + 1;
	u_key.base = HASHCOUNT_BLOB_KEY;
	u_val.len = 0;
	u_val.base = NULL;

	err = kvs_config(dev, CFG_READ, &u_key, &u_val);
	if (!err && u_val.len == sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH) {
		memcpy(&dev->stats.hashcount, u_val.base,
			sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH);
		dev->stats.hashcount[HASHCOUNT_TAB_LENGTH] = 0;
	} else if (err == -ENOENT) {
		dev->stats.hashcount[HASHCOUNT_TAB_LENGTH] = 1;
		err = 0;
	}

	/* flush logs */
	for (int j = 0; j < plevel; ++j) {
		db = kvs->db + j;

		err = pthread_create(&db->bloom_load_thread, NULL,
		    &kvs_partition_flush, (void *)db);
		if (err) {
			log_warn(lg, "Dev(%s): cannot start flush thread: (%d) %s",
			    dev->name, err, strerror(err));
		}
	}

	/* wait for flushing to complete */
	for (int j = 0; j < plevel; ++j) {
		db = kvs->db + j;
		pthread_join(db->bloom_load_thread, NULL);
	}

	db->bloom_load_thread = 0;

	if (need_bloom) {

		log_info(lg, "needed to take bloom load slow path");
		for (int j = 0; j < plevel; ++j) {
			pthread_attr_t attr;

			db = kvs->db + j;

			err = pthread_attr_init(&attr);
			if (!err)
				err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

			err = pthread_create(&db->bloom_load_thread, NULL,
					&kvs_bloom_load, (void *) db);
			if (err) {
				log_warn(lg, "Dev(%s): cannot start bloom thread: (%d) %s",
						dev->name, err, strerror(err));
			}

			pthread_attr_destroy(&attr);
		}
	}

	/* finaly, update HC table again so that upper layer can read
	 * it correctly upon successful recovery */

	MDB_val hc_key = { .mv_size = strlen(HASHCOUNT_BLOB_KEY) + 1,
			   .mv_data = HASHCOUNT_BLOB_KEY };
	MDB_val hc_data = { .mv_size = sizeof(uint64_t) * HASHCOUNT_TAB_LENGTH,
			   .mv_data = (char*)dev->stats.hashcount };
	err = kvs_put_hashcount_entry(dev, &hc_key, &hc_data);
	if (err)
		goto _exit;

	all_bloom_loaded = 1;

	struct ccowd_params* params = dev->rt->init_traits;
	if (params && params->log_flush) {
		if (all_bloom_loaded)
			params->log_err = 0;
		else
			params->log_err = -EIO;
		err = -ENODEV;
		goto _exit;
	}
	je_free(mbuf.base);
	arg->err = err;
	return NULL;

_exit:
	if (kvs) {
		if (kvs->db)
			je_free(kvs->db);
		je_free(kvs);
		dev->device_lfs = NULL;
	}
	je_free(mbuf.base);
	arg->err = err;
	return NULL;
}


/*
 * Read JSON configuration and initialize all devices
 *
 * If certain devices missing or in busy state, transport will continue
 * its operation asyncrhonously by either skipping or waiting on work queue
 * to be completed. Device initialization will be deffered.
 */
static int
kvs_parse_opts(json_value *o, struct reptrans *rt)
{
	size_t i, j;
	char* backend_name = "kvadi";
	json_value *backend_opts = NULL;

	/* syntax error */
	if (o->type != json_object) {
		log_error(lg, "Syntax error: not an object");
		return -1;
	}

	json_value *devices = NULL;
	for (i = 0; i < o->u.object.length; i++) {
		if (strcmp(o->u.object.values[i].name, "devices") == 0) {
			devices = o->u.object.values[i].value;
		} else if (strcmp(o->u.object.values[i].name, "backend") == 0) {
			backend_name = je_strdup(o->u.object.values[i].value->u.string.ptr);
		} else if (strcmp(o->u.object.values[i].name, "backend_opts") == 0) {
			if (o->u.object.values[i].value->type != json_object)
				log_error(lg, "Backend opts has to be an object");
			else
				backend_opts = o->u.object.values[i].value;
		}
	}

	/* devices section not found */
	if (!devices) {
		return 0;
	}

	/* syntax error */
	if (devices->type != json_array) {
		log_error(lg, "Syntax error: devices section not an array");
		return -1;
	}

	/* FIXME: to calm down ASAN */
	usleep(1);

	uint32_t md_max = devices->u.array.length;
	char* j_names[md_max];
	uint32_t j_refs[md_max];
	uint64_t j_part_size[md_max];

	memset(j_names, 0, sizeof(j_names));
	memset(j_refs, 0, sizeof(j_refs));
	memset(j_part_size, 0, sizeof(j_part_size));
	uint32_t n_j = 0;

	for (i = devices->u.array.length; i > 0 ; i--) {
		json_value *d = devices->u.array.values[i - 1];
		char * name = NULL;
		for (j = 0; j < d->u.object.length; j++) {
			char *namekey = d->u.object.values[j].name;
			json_value *v = d->u.object.values[j].value;

			if (strcmp(namekey, "path") == 0) {
				name = v->u.string.ptr;
			} else if (strcmp(namekey, "journal") == 0) {
				if (v->type != json_string)
					continue;
				char *journal = v->u.string.ptr;
				if (!journal) {
					log_error(lg, "Journal ins't defined for a VDEV at index %lu", i);
					return -EINVAL;
				}
				uint32_t idx = 0;
				for (; idx < n_j; idx++)
					if (!strcmp(journal, j_names[idx]))
						break;
				if (!j_names[idx]) {
					j_names[idx] = je_strdup(journal);
					n_j++;
				}
				j_refs[idx]++;
			}
		}
		if (!name)
			log_error(lg, "Device name ins't defined at index %lu", i);
	}

	/* Calculate mdoffload's HDD/SSD part size */
	for (uint32_t i = 0; i < n_j; i++) {
		char mount_point[PATH_MAX];
		int err = kvs_get_mountpoint_by_name(j_names[i], mount_point,
			sizeof(mount_point));
		if (err) {
			log_error(lg, "Couldn't resolve mount point for a disk %s",
				j_names[i]);
			return -ENOENT;
		}

		struct statvfs s;
		if (statvfs(mount_point, &s) != 0) {
			log_error(lg, "Can't access mdoffload device path %s: %d", mount_point,
			    -errno);
			return -ENOENT;
		}
		j_part_size[i] = s.f_frsize * s.f_blocks / j_refs[i];
		if (j_part_size[i] - DEV_LMDB_LOG_MAPSIZE < DEV_LMDB_LOG_MAPSIZE) {
			log_error(lg, "The SSD device at %s is too small: "
				"part size %lu MB is smaller than the journal",
				mount_point, j_part_size[i]/(1024U*1024U));
			return -EINVAL;
		}
		log_notice(lg, "The SSD device %s size %lu MB, part size %lu MB, #parts %u",
			mount_point, (s.f_frsize * s.f_blocks)/(1024U*1024U),
			j_part_size[i]/(1024U*1024U), j_refs[i]);
	}

	int numdevs = 0;
	int err = 0;
	struct kvs_arg arg[devices->u.array.length];
	for (i = 0; i < devices->u.array.length; i++)
		memset(&arg[i], 0, sizeof(struct kvs_arg));
	for (i = 0; i < devices->u.array.length; i++) {
		json_value *d = devices->u.array.values[i];

		/* syntax error, but continue to the next device */
		if (d->type != json_object) {
			log_warn(lg, "Syntax error: dev.%lu is not an object", i);
			err = 1;
			continue;
		}

		char *name = NULL;
		char *path = NULL;
		char *journal = NULL;
		int wal_disabled = 0;
		int verify_chid = 1;
		int gw_cache = 0;
		int zerocopy = 0;
		int journal_maxentries = DEV_LMDB_LOG_MAXENTRIES;
		int journal_maxchunksize = DEV_LMDB_LOG_MAXCHUNKSIZE;
		int sync = 1;
		int readahead = 128;
		int direct = 0;
		int plevel_override = 0;
		uint8_t bloom_enabled = 1;
		uint8_t keycache_enabled = 1;
		uint32_t keycache_size_max = KEY_CACHE_MAX;
		int detached = 0;

		struct repdev_bg_config* bg_cfg =
				je_malloc(sizeof(struct repdev_bg_config));
		*bg_cfg = rt->dev_bg_config;
		arg[i].backend_opts = backend_opts;

		for (j = 0; j < d->u.object.length; j++) {
			char *namekey = d->u.object.values[j].name;
			json_value *v = d->u.object.values[j].value;

			if (strcmp(namekey, "opts") == 0) {
				if (v->type != json_object) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.opts is not an object",
					    i, j);
					err = 1;
					continue;
				}
				arg[i].backend_opts = v;
			} else if (strcmp(namekey, "name") == 0) {
				if (v->type != json_string) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.name is not a string",
					    i, j);
					err = 1;
					continue;
				}
				name = je_strdup(v->u.string.ptr);
			} else if (strcmp(namekey, "path") == 0) {
				if (v->type != json_string) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.path is not a string",
					    i, j);
					err = 1;
					continue;
				}
				path = je_strdup(v->u.string.ptr);
			} if (strcmp(namekey, "wal_disabled") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.wal_disabled is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				wal_disabled = v->u.integer;
			} else if (strcmp(namekey, "journal") == 0) {
				if (v->type != json_string) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.journal is not a string",
					    i, j);
					err = 1;
					continue;
				}
				journal = je_strdup(v->u.string.ptr);
				assert(journal);
			} else if (strcmp(namekey, "verify_chid") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.verify_chid is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				verify_chid = v->u.integer;
			} else if (strcmp(namekey, "gw_cache") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.gw_cache is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				gw_cache = v->u.integer;
			} else if (strcmp(namekey, "sync") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.sync is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				sync = v->u.integer;
			} else if (strcmp(namekey, "direct") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.direct is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				direct = v->u.integer;
			} else if (strcmp(namekey, "readahead") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.readahead is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				readahead = v->u.integer;
			} else if (strcmp(namekey, "zerocopy") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.zerocopy is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				zerocopy = v->u.integer;
			} else if (strcmp(namekey, "journal_maxentries") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.journal_maxentries is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				journal_maxentries = v->u.integer;
			} else if (strcmp(namekey, "journal_maxchunksize") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.journal_maxchunksize is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				journal_maxchunksize = v->u.integer;
			} else if (strcmp(namekey, "plevel_override") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.plevel_override is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				plevel_override = v->u.integer;
			} else if (strcmp(namekey, "bloom_enabled") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.bloom_enabled is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				bloom_enabled = v->u.integer;
			} else if (strcmp(namekey, "keycache_enabled") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.keycache_enabled is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				keycache_enabled = v->u.integer;
			} else if (strcmp(namekey, "keycache_size_max") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
							"dev.%lu.%lu.keycache_size_max is not an "
							"integer", i, j);
					err = 1;
					continue;
				}
				keycache_size_max = v->u.integer;
			} else if (strcmp(namekey, "detached") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
							"dev.%lu.%lu.detached is not an "
							"integer", i, j);
					err = 1;
					continue;
				}
				detached = v->u.integer;
			}
		}

		if (detached) {
			log_notice(lg, "Device %s is detached, skipping initialization",
				name);
			continue;
		}

		size_t n_opts;
		/*
		 * Parse bg timing config
		 * at the moment we just skip parsing errors
		 * as we still have upper level configuration
		 * parsed previously and it will be used
		 */
		reptrans_parse_bg_jobs_config(d, bg_cfg, &n_opts);

		/* skip initialization if important parameters missing */
		if (!name || !path) {
			if (name)
				je_free(name);
			if (path)
				je_free(path);
			je_free(bg_cfg);
			log_notice(lg, "Skipped device at index %lu", i);
			continue;
		}

		/*
		 * DEVICE INITIALIZATION - START
		 *
		 * Allocate device structure, create work queue for deferred
		 * device initialization
		 */

		struct repdev *dev = je_calloc(1, sizeof (*dev));
		if (dev == NULL) {
			return -ENOMEM;
		}
		/*
		* we must set dev->sub_fd to -1, because nn_socket can return 0 as normal good socket
		*/
		dev->sub_fd = -1;
		QUEUE_INIT(&dev->item);
		dev->name = name;
		dev->path = path;
		dev->wal_disabled = wal_disabled;
		dev->journal = journal;
		dev->journal_maxchunksize = journal_maxchunksize;
		dev->journal_maxentries = journal_maxentries;
		dev->bloom_enabled = bloom_enabled;
		dev->keycache_enabled = keycache_enabled;
		dev->keycache_size_max = keycache_size_max;
		dev->rt = rt;
		dev->verify_chid = verify_chid;
		dev->gw_cache = gw_cache;
		dev->__vtbl = &kvs_dev_vtbl;
		if (!memcmp(bg_cfg, &rt->dev_bg_config,
				sizeof(struct repdev_bg_config))) {
			dev->bg_config = &rt->dev_bg_config;
			je_free(bg_cfg);
			bg_cfg = NULL;
		} else
			dev->bg_config = bg_cfg;

		repdev_generate_name(dev);
		log_notice(lg, "vdevid: %016lX%016lX", dev->vdevid.u, dev->vdevid.l);

		arg[i].plevel_override = plevel_override;
		arg[i].sync = sync;
		arg[i].readahead = readahead;
		arg[i].direct = direct;
		arg[i].dev = dev;
		arg[i].zerocopy = zerocopy;
		arg[i].bg_cfg = bg_cfg;
		arg[i].err = 0;
		arg[i].th = 0;
		arg[i].backend_name = backend_name;
		arg[i].n_dev = devices->u.array.length;
		for (uint32_t n = 0; n < n_j; n++) {
			if (strcmp(j_names[n], journal) == 0) {
				arg[i].j_size = j_part_size[n];
				break;
			}
		}
		assert(arg[i].j_size);

		err = pthread_create(&arg[i].th, NULL,
				&kvs_dev_init, (void *)&arg[i]);
		if (err) {
			log_warn(lg, "Dev(%s): cannot start bloom_load thread: (%d) %s",
					dev->name, err, strerror(err));
		} else
			arg[i].init = 1;


		/* done */
	}

	for (i = 0; i < devices->u.array.length; i++) {
		if (arg[i].init)
			pthread_join(arg[i].th, NULL);
	}

	for (i = 0; i < devices->u.array.length; i++) {
		if (!arg[i].init)
			continue;
		struct repdev *dev = arg[i].dev;
		if (!dev || !dev->device_lfs)
			continue;
		err = arg[i].err;
		struct repdev_kvs *kvs = dev->device_lfs;
		/*
		 * Set KVS local configuration (not exposed to Reptrans)
		 */
		kvs->zerocopy = arg[i].zerocopy;
		if (err) {
			if (err != -ENODEV)
				log_error(lg, "Cannot initialize Local data store %s "
						"mnt=%s: %s", dev->name, dev->path, strerror(-err));
			dev->status = dev->prev_status = REPDEV_STATUS_UNAVAILABLE;
		} else {
			log_notice(lg, "Local data store %s mnt=%s initialized",
					dev->name, dev->path);
			dev->status = dev->prev_status = REPDEV_STATUS_ALIVE;
			(void)kvs_dev_stat_refresh(dev);
		}
		reptrans_add_vdev(rt, dev);
		numdevs++;
	}
	return numdevs ?  numdevs : err;
}

/**
 * Configuration & Initialization
 *
 * When this call is complete, transport is ready to be used. All
 * devices discovered and deffered initialization is in progress,
 * channels opened and ready to serve requests. For Local data store it
 * translates to - filesystem mounted, device metafile created and can
 * be opened.
 *
 * Configuration supplied in JSON format, specific to the transport. Error
 * during parsing may occure which MAY cause partial initialization.
 */
static int
kvs_init(json_value *opts, struct reptrans *rt)
{
	int err = 0;

	if (opts) {
		err = kvs_parse_opts(opts, rt);
		if (err == -ENODEV)
			return err;
		if (err < 0) {
			log_error(lg, "Configure file format, LFS version or flags error");
		} else {
			log_info(lg, "Replicast transport over Local FS now initialized");
		}
	}
	return err;
}

static int
kvs_destroy()
{
	return 0;
}

static void
kvs_dev_log_flush(struct repdev *dev, uint32_t flags) {

	uint64_t start = uv_hrtime();
	struct repdev_kvs *kvs = dev->device_lfs;

	for (int j = 0; j < kvs->plevel; ++j) {
		struct repdev_db *db = kvs->db + j;
		type_tag_t first = TT_NAMEINDEX;
		type_tag_t last = TT_LAST;
		if (flags & RD_FLUSH_BATCH_QUEUE) {
			first = TT_BATCH_QUEUE;
			last = TT_BATCH_QUEUE + 1;
		}
		int err = 0;
		for (type_tag_t ttag = first; ttag < last; ttag++) {
			if (is_log_tt(dev, ttag)) {
				struct repdev_log *log = &db->log;
				if (((dev->bg_config->flush_threshold_timeout <
					  start - log->flushed_timestamp) &&
					 (flags & RD_FLUSH_TIMEOUT)) ||
					(flags & RD_FLUSH_FORCE)) {
					err = kvs_log_flush(log, ttag);
					if (err)
						/* flush what we can! */
						break;
				} else {
					log_debug(lg, "skipping flush timeout") ;
				}
				if (!err && (flags & RD_FLUSH_SYNC))
					kvs_log_flush_wait(db, ttag);
			}
		}
	}
}

static int
kvs_dev_ctl(struct repdev *dev, int op, void* arg) {
	if (op == vdevCtlFlush) {
		uint32_t flags;
		memcpy(&flags, arg, sizeof(uint32_t));
		kvs_dev_log_flush(dev, flags);
		return 0;
	} else if (op == vdevCtlDetach) {
		reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
		return 0;
	} else if (op == vdevCtlAttach) {
		reptrans_dev_override_status(dev, REPDEV_STATUS_ALIVE);
		return 0;
	} else
		return -EINVAL;
}

static int
kvs_dev_open(struct repdev* dev) {
	return 0;
}

static void
kvs_dev_destroy(struct repdev *dev)
{
	struct repdev_kvs *kvs = dev->device_lfs;
	struct repdev_db *db = NULL;
	int j;

	/*
	 * FIXME: Temp. kludge for NED-336.
	 */
	usleep(500);
	for (j = 0; j < kvs->plevel; ++j) {
		db = kvs->db + j;
		kvs_lmdb_close(db);
	}
	if(dev->bg_config != &dev->rt->dev_bg_config)
		je_free(dev->bg_config);

	kvs->backend->exit(kvs->be_inst);
	kvs_bm_exit();

	je_free(kvs->db);
	je_free(dev->device_lfs);
	je_free(dev->name);
	je_free(dev->path);
	je_free(dev->journal);
}

static int
kvs_dev_cancel(struct repdev *dev)
{
	struct repdev_kvs *kvs = dev->device_lfs;
	int i, j;
	uv_buf_t key;
	uv_buf_t value;

	/* Waiting until all PUTs are done */
	uint64_t new = 0, old = 0;
	while (!__sync_bool_compare_and_swap(&kvs->bloom_ttag_put_counter, old,
		new)) {
		usleep(1000);
		new = old = 0;
	}

	/* Bloom threads may be still running, make sure they'll all end */
	for (int j = 0; j < kvs->plevel; ++j) {
		struct repdev_db *db = kvs->db + j;
		if (!db->bloom_load_thread)
			continue;
		kvs_bloom_wait(db);
	}

	int err = kvs_dev_quiesce_bloom(dev);
	if (err != 0)
		log_error(lg, "failed or partial failure storing bloom filter(s)");

	key.base = BLOOM_STORE_OK;
	key.len = strlen(key.base);
	value.len = sizeof(int);
	value.base = (char *) &err;

	kvs_config(dev, CFG_WRITE, &key, &value);
	return 0;
}

static int
kvs_dev_enum(struct reptrans *rt, reptrans_enum_cb_t cb, void *arg,
    reptrans_done_cb_t done, uint64_t timeout)
{
	QUEUE *d;
	uv_rwlock_rdlock(&rt->devlock);
	QUEUE_FOREACH(d, &rt->devices) {
		struct repdev *dev = QUEUE_DATA(d, struct repdev, item);
		uv_rwlock_rdunlock(&rt->devlock);

		done(dev, arg, 0);

		uv_rwlock_rdlock(&rt->devlock);
	}
	uv_rwlock_rdunlock(&rt->devlock);
	return 0;
}

part_walk_action_t
kvs_partition_walk(struct repdev *dev, partition_walk_f func,
					  void *arg) {

	struct repdev_kvs *kvs = dev->device_lfs;
	struct repdev_db *db = NULL;

	for (int i = 0; i < kvs->plevel; i++) {
		db = kvs->db + i;
		if (func(db, arg) != PART_WALK_CONTINUE)
			return PART_WALK_TERMINATE;
	}

	return PART_WALK_COMPLETED;
}

static part_walk_action_t
kvs_sync_bloom_to_lmdb(struct repdev_db *db, void *arg) {

	struct repdev_db *zero_db = (struct repdev_db *) arg;
	MDB_txn *txn;
	MDB_val key, data;

	if (db->bloom_loaded <= 0)
		return PART_WALK_TERMINATE;

	char buf[1024] = {0};
	sprintf(buf, "bloom-%s-%d", db->dev->name, db->part);

	key.mv_size = strlen(buf);
	key.mv_data = &buf[0];

	data.mv_size = KEY_BLOOM_BYTELEN + sizeof(db->size) + sizeof(db->entries);
	data.mv_data = NULL;

	int err;
	if (mdb_txn_begin(db->env, NULL, 0, &txn) != 0)
		return PART_WALK_TERMINATE;

	if ((err = mdb_put(txn, db->dbi[TT_HASHCOUNT], &key, &data,
			MDB_RESERVE)) != 0) {
		mdb_txn_abort(txn);
		log_error(lg, "Dev(%s): %s store bloom mdb_put: (%d) %s", db->dev->name,
				type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err));
		return PART_WALK_TERMINATE;
	}
	memcpy(data.mv_data, db->bloom, KEY_BLOOM_BYTELEN);
	memcpy((char*)data.mv_data + KEY_BLOOM_BYTELEN, db->size, sizeof(db->size));
	memcpy((char*)data.mv_data + KEY_BLOOM_BYTELEN + sizeof(db->size), db->entries,
		sizeof(db->entries));

	mdb_txn_commit(txn);
	mdb_env_sync(db->env, 1);

	return PART_WALK_CONTINUE;

}

static part_walk_action_t
kvs_load_bloom_from_lmdb(struct repdev_db *db, void *arg) {
	struct repdev_db *zero_db = (struct repdev_db *) arg;
	MDB_txn *txn;
	MDB_val key, data;
	uv_buf_t u_key, u_val;
	char buf[1024] = {0};
	int err;
	u_key.base = BLOOM_STORE_OK;
	u_key.len = strlen(u_key.base);
	u_val.len = 0;
	u_val.base = NULL;

	if (kvs_config(zero_db->dev, CFG_READ, &u_key, &u_val) != 0) {
		log_info(lg, "bloom config value toxic");
		return PART_WALK_TERMINATE;
	}

	if (strcmp(u_key.base, BLOOM_STORE_OK) != 0 || *(int *) u_val.base != 0) {
		log_info(lg, "bloom magic invalid");
		return PART_WALK_TERMINATE;
	}

	sprintf(buf, "bloom-%s-%d", db->dev->name, db->part);

	key.mv_size = strlen(buf);
	key.mv_data = &buf[0];
	data.mv_size = KEY_BLOOM_BYTELEN + sizeof(db->size) + sizeof(db->entries);
	data.mv_data = NULL;

	if (mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn) !=
		0)
		return PART_WALK_TERMINATE;

	if ((err = mdb_get(txn, db->dbi[TT_HASHCOUNT], &key,
			&data)) != 0) {

		/*
		 * we failed to load the bloom, stop all other loads as well
		 */

		log_error(lg, "Dev(%s): %s mdb_get: (%d) %s", db->dev->name,
				type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err));
		mdb_txn_abort(txn);
		/* note; callee should cleanup db->bloom */
		return PART_WALK_TERMINATE;
	}

	memcpy(db->bloom, data.mv_data, KEY_BLOOM_BYTELEN);
	memcpy(db->size, (char*)data.mv_data + KEY_BLOOM_BYTELEN, sizeof(db->size));
	memcpy(db->entries, (char*)data.mv_data + KEY_BLOOM_BYTELEN + sizeof(db->size),
		sizeof(db->entries));
	mdb_txn_abort(txn);

	db->bloom_loaded = 1;
	return PART_WALK_CONTINUE;
}

int
kvs_dev_quiesce_bloom(struct repdev *rdev) {

	part_walk_action_t state;

	if(rdev->rt->flags & RT_FLAG_RDONLY)
		return 0;

	repdev_status_t status = reptrans_dev_get_status(rdev);
	if (status == REPDEV_STATUS_UNAVAILABLE ||
		status == REPDEV_STATUS_READONLY_FULL ||
		status == REPDEV_STATUS_READONLY_FAULT ||
		status == REPDEV_STATUS_READONLY_FORCED)
		return -EPERM;

	struct repdev_kvs *kvs = rdev->device_lfs;
	struct repdev_db *zero_db = kvs->db;

	state = kvs_partition_walk(rdev, kvs_sync_bloom_to_lmdb, zero_db);
	if (state != PART_WALK_COMPLETED)
		return -EINVAL;

	log_info(lg, "bloom filter stored in lmdb for Dev(%s)", zero_db->dev->name);
	return 0;
}

int
kvs_dev_load_bloom(struct repdev *rdev) {
	part_walk_action_t state;
	uv_buf_t u_key, u_val;
	u_key.base = BLOOM_STORE_OK;
	u_key.len = strlen(u_key.base);
	u_val.len = sizeof(int);

	repdev_status_t status = reptrans_dev_get_status(rdev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return -EPERM;

	struct repdev_kvs *kvs = rdev->device_lfs;
	struct repdev_db *zero_db = kvs->db;

	state = kvs_partition_walk(rdev, kvs_load_bloom_from_lmdb, zero_db);
	if (state != PART_WALK_COMPLETED)
		return -EINVAL;

	/* mark toxic */
	int val = -1;
	u_val.base = (char *) &val;
	if (kvs_config(rdev, CFG_WRITE, &u_key, &u_val) != 0)
		return -EINVAL;

	log_info(lg, "bloom fast path succeeded for Dev(%s)", zero_db->dev->name);
	return 0;

}

static int
kvs_erase(struct reptrans *rt, struct _json_value *o, const erase_opt_t* opts) {
	/* syntax error */
	if (o->type != json_object) {
		log_error(lg, "Syntax error: not an object");
		return -1;
	}

	if ((opts->name && opts->plevel) || opts->journal_group)
		return -EFAULT;

	json_value *devices = NULL, *backend_opts = NULL;
	char* backend_name = NULL;
	kvs_backend_t* backend = NULL;
	for (size_t i = 0; i < o->u.object.length; i++) {
		if (strcmp(o->u.object.values[i].name, "devices") == 0) {
			devices = o->u.object.values[i].value;
		} else if (strcmp(o->u.object.values[i].name, "backend") == 0) {
			backend_name = o->u.object.values[i].value->u.string.ptr;
		} else if (strcmp(o->u.object.values[i].name, "backend_opts") == 0) {
			if (o->u.object.values[i].value->type != json_object)
				log_error(lg, "Backend opts has to be an object");
			else
				backend_opts = o->u.object.values[i].value;
		}
	}

	/* devices section not found */
	if (!devices) {
		return 0;
	}

	if (!backend_name) {
		log_error(lg, "Couldn't find backend ID");
		return -EBADF;
	}

	backend = kvs_backend_get(backend_name);
	if (!backend) {
		log_error(lg, "Couldn't load KVS backend %s", backend_name);
		return -EACCES;
	}
	/* syntax error */
	if (devices->type != json_array) {
		log_error(lg, "Syntax error: devices section not an array");
		return -1;
	}

	size_t n_vdevs = devices->u.array.length;
	int err = 0;

	for (size_t i = 0; i < n_vdevs; i++) {
		json_value *d = devices->u.array.values[i];

		/* syntax error, but continue to the next device */
		if (d->type != json_object) {
			log_warn(lg, "Syntax error: dev.%lu is not an object", i);
			return -EINVAL;
		}

		char* name = NULL;
		char* path = NULL;
		char* journal = NULL;
		for (size_t j = 0; j < d->u.object.length; j++) {
			char *namekey = d->u.object.values[j].name;
			json_value *v = d->u.object.values[j].value;
			if (!strcmp(namekey, "name")) {
				if (v->type != json_string) {
					log_error(lg, "Disk name must be a string at %lu", j);
					return -EBADF;
				}
				name = v->u.string.ptr;
			} if (!strcmp(namekey, "path")) {
				if (v->type != json_string) {
					log_error(lg, "Disk mount path must be a string at index %lu", j);
					return -EBADF;
				}
				path = v->u.string.ptr;
			} else if (!strcmp(namekey, "journal")) {
				if (v->type != json_string) {
					log_error(lg, "A journal must be a string at index %lu", j);
					return -EBADF;
				}
				journal = v->u.string.ptr;
			}
		}

		if (!name || !path || !journal) {
			log_error(lg, "the name, path or journal are absent in rt-kvs.json");
			return -EBADF;
		}
		struct statvfs s;
		if (statvfs(path, &s) != 0) {
			log_error(lg, "Can't access device path %s: %d", path,
			    -errno);
			continue;
		}

		if (opts->name && strcmp(opts->name, name))
			continue;

		/* Erase SSD content */
		struct stat st;
		char cmd[PATH_MAX];
		char mp[PATH_MAX];
		int err = kvs_get_mountpoint_by_name(journal, mp, PATH_MAX);
		if (err) {
			log_error(lg, "Cannot find a mountpoint for journal %s", journal);
			continue;
		}

		int wal_only = opts->flags & RD_ERASE_FLAG_WAL_ONLY;

		if (!wal_only) {
			sprintf(cmd, "%s/%s", mp, name);
			if (!stat(cmd, &st)) {
				sprintf(cmd, "find %s/%s -name \"*\" -print0 | xargs -0 rm -rf;", mp, name);
				err = system(cmd);
				log_notice(lg, "Erased an SSD-situated content for device %s", name);
			} else
				log_notice(lg, "Dev(%s) SSD content has been removed already", name);
		} else {
			sprintf(cmd, "%s/%s/journal", mp, name);
			if (!stat(cmd, &st)) {
				sprintf(cmd, "find %s/%s/journal -name \"*\" -print0 | xargs -0 rm -rf;", mp, name);
				err = system(cmd);
				log_notice(lg, "Dev(%s) journal removed", name);
			} else
				log_notice(lg, "Dev(%s) journal has been removed already", name);
		}
		if (wal_only)
			continue;

		/* Sanitize backend */
		kvs_backend_handle_t h = NULL;
		err = backend->init(path, backend_opts, &h);
		if (err) {
			log_error(lg, "Dev(%s) cannot initialize the backend: %d",
				name, err);
			return -EIO;
		}
		err = backend->erase(h);
		if (err)
			log_error(lg, "Dev(%s) Backend erase error %d", name, err);
		else
			log_notice(lg, "Dev(%s) backend erased", name);
		backend->exit(h);
	}
	return 0;
}

struct reptrans rtkvs = {
	.name		= "rt-kvs",
	.probe		= kvs_init,
	.destroy	= kvs_destroy,
	.dev_open	= kvs_dev_open,
	.dev_free	= kvs_dev_destroy,
	.dev_ctl	= kvs_dev_ctl,
	.dev_close	= kvs_dev_cancel,
	.dev_enum	= kvs_dev_enum,
	.erase		= kvs_erase
};
