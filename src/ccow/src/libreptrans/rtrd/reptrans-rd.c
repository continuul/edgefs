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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <uv.h>

#include "ccowutil.h"
#include "hashtable.h"
#include "serverid.h"
#include "crypto.h"
#include "queue.h"
#include "json.h"
#include "reptrans.h"
#include "ccowd-impl.h"

#include <sys/user.h>
#include "reptrans-rd.h"

#define TXN_ERR_INJECT 0

#define RD_NO_FREE_SPACE(err) (err == MDB_MAP_FULL || err == ENOSPC || err == MDB_MAP_RESIZED)
#define DEV_RD_SMARTCTL_CMD "%s/sbin/smartctl -j -a /dev/disk/by-id/%s 2>/dev/null"
#define DEV_RD_SMARTCTL_CMD_SELFTEST "%s/sbin/smartctl -t %s /dev/disk/by-id/%s >/dev/null 2>/dev/null"
#define DEV_RD_SMARTCTL_CMD_EN "%s/sbin/smartctl -s on -S on -o on /dev/disk/by-id/%s >/dev/null 2>/dev/null"
#define DEV_RD_SMART_READ_INTERVAL (1800 * 1000000)
#define DEV_RD_COMMIT_SIZE_MAX (64*1024UL*1024UL)

#define CMD_DROP_OUTDATED_SIGNATURE "mdofDropOutdated"
#define CMD_VALIDATE_RDKEYS_SIGNATURE "validateRdKeys"
#define CMD_MDOFFLOAD_MIGRATE_SIGNATURE "mdoffloadMigrate"
#define CMD_REBUILD_RDKEYS_SIGNATURE "rebuildRdKeys"
#define CMD_DISK_REPLACE_SIGNATURE "diskReplace"

static int rd_drop_outdated_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta);
static int rd_validate_rdkeys_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta);
static int rd_mdoffload_migrate_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta);
static int rd_rebuild_mdcache_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta);
static int rd_disk_replace_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta);

typedef int (*maintenance_t)(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta);

struct rd_maintenance_entry {
	/* StringID of the maintenance function */
	const char* id;

	/* The function to handle the maintenance */
	maintenance_t func;

/* LMDB environment initialization required before maintenance is started */
#define RDMT_FLAG_LMDB_INIT	(1<<0)

	uint64_t flags;
} rd_maintenance_commands[] = {
	{ .id = CMD_DROP_OUTDATED_SIGNATURE, .func = rd_drop_outdated_handler, .flags = RDMT_FLAG_LMDB_INIT},
	{ .id = CMD_VALIDATE_RDKEYS_SIGNATURE, .func = rd_validate_rdkeys_handler, .flags = RDMT_FLAG_LMDB_INIT},
	{ .id = CMD_MDOFFLOAD_MIGRATE_SIGNATURE, .func = rd_mdoffload_migrate_handler, .flags = RDMT_FLAG_LMDB_INIT},
	{ .id = CMD_REBUILD_RDKEYS_SIGNATURE, .func = rd_rebuild_mdcache_handler, .flags = RDMT_FLAG_LMDB_INIT},
	{ .id = CMD_DISK_REPLACE_SIGNATURE, .func = rd_disk_replace_handler, .flags = RDMT_FLAG_LMDB_INIT},
};

static void
rd_dev_faulted(struct repdev* dev, struct rd_fault_signature* fs);

static int
rd_set_ro_fault(struct repdev* dev, struct rd_fault_signature* fs);

static int
rd_set_unavailable(struct repdev* dev, struct rd_fault_signature* fs, int sync);


static int
rd_is_block_device(const char* path) {
	struct stat st;
	int err = stat(path, &st);
	if (err < 0)
		return -errno;
	return S_ISBLK(st.st_mode) != 0;
}

static int
rd_format_lmdb_part(const char* path) {
	int err = 0, rc = 10;
	char cmd[PATH_MAX*2];
	while ((err = rd_is_block_device(path)) != 1 && --rc > 0)
		sleep(1);
	if (err == 0) {
		log_error(lg, "Couldn't format LMDB partition at %s: not a block devicce", path);
		return -ENOANO;
	} else if (err < 0) {
		log_error(lg, "Couldn't format LMDB partition at %s: file not found", path);
		return -EBADRQC;
	}
	sprintf(cmd, "dd if=/dev/zero of=%s bs=1M count=10 > /dev/null 2>&1", path);
	err = system(cmd);
	return 0;
}

static inline int
is_log_tt(struct repdev *dev, type_tag_t ttag)
{
	if (dev->wal_disabled)
		return 0;
	switch (ttag) {
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


static int
rd_log_cmp(const MDB_val *a, const MDB_val *b, int (*blob_cmp)(const void *,
	const size_t, const void *, const size_t, int* cmp_err), int* cmp_err)
{
	/* In log we follow an additional rule:
	 * if dupsort's value has a delete request without payload,
	 * then such a request has a higher priority
	 */
	int a_prio = 0, b_prio = 0;
	if (a->mv_size == DUPSORT_DEL_MAGIC_SIZE && IS_DUPSORT_DEL(a->mv_data))
		a_prio = 1;
	if (b->mv_size == DUPSORT_DEL_MAGIC_SIZE && IS_DUPSORT_DEL(b->mv_data))
		b_prio = 1;

	if (a_prio || b_prio)
		return b_prio - a_prio;
	int err = blob_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
	if (*cmp_err != 0)
		return 0;
	if (!err && (a->mv_size != b->mv_size)) {
		if (a->mv_size > b->mv_size)
			return 1;
		else if (a->mv_size < b->mv_size)
			return -1;
	}
	return err;
}

static int
rd_log_vbr_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err) {
	return rd_log_cmp(a, b, vbr_cmp, cmp_err);
}

static int
rd_log_batch_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err) {
	return rd_log_cmp(a, b, batch_cmp, cmp_err);
}

static int
rd_log_nameindex_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err) {
	return rd_log_cmp(a, b, nameindex_cmp, cmp_err);
}

static int
rd_log_generic_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err) {
	return rd_log_cmp(a, b, generic_cmp, cmp_err);
}

/** Compare two backref-like items */
static int
rd_lmdb_vbr_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return vbr_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** Compare two trlog items */
static int
rd_lmdb_trlog_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return trlog_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** Compare two batch items */
static int
rd_lmdb_batch_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return batch_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** compare two TT_VERIFICATION_QUEUE keys where UVID and GenID embeeded
 *  into CHID */
static int
rd_lmdb_verqueue_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return verqueue_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

static int
rd_lmdb_incomig_batch_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return incomig_queue_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** Compare two TT_NAMEINDEX items, match UVIDs and GenIDs in reverse order */
static int
rd_lmdb_nameindex_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return nameindex_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** Compare two items lexically */
static int
rd_lmdb_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return generic_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

static inline int
rd_kv_validate(type_tag_t ttag, MDB_val* key, MDB_val* val) {
	int err = 0;
	if (key->mv_size == 0) {
		log_error(lg, "%s key size is 0", type_tag_name[ttag]);
		return -EINVAL;
	}
	if (key->mv_size > 511) {
		log_error(lg, "%s key size %lu exceeded the limit 511 bytes",
			type_tag_name[ttag], key->mv_size);
		return -EINVAL;
	}
	if (val && is_dupsort_tt(ttag) && val->mv_size > 511) {
		log_error(lg, "%s duposrt value size %lu exceeded the limit 511 bytes",
			type_tag_name[ttag], val->mv_size);
		return -EINVAL;
	}
	return 0;
}

static inline MDB_cmp_func*
rd_lmdb_cmp_ttag(type_tag_t ttag) {
	assert(is_dupsort_tt(ttag));
	switch (ttag) {
		case TT_NAMEINDEX:
			return rd_lmdb_nameindex_cmp;
		case TT_VERIFIED_BACKREF:
			return rd_lmdb_vbr_cmp;
		case TT_BATCH_QUEUE:
		case TT_ENCODING_QUEUE:
			return rd_lmdb_batch_cmp;
		default:
			return rd_lmdb_cmp;
	}
}

static inline MDB_cmp_func*
rd_log_cmp_ttag(type_tag_t ttag) {
	assert(is_dupsort_tt(ttag));
	switch (ttag) {
		case TT_NAMEINDEX:
			return rd_log_nameindex_cmp;
		case TT_VERIFIED_BACKREF:
			return rd_log_vbr_cmp;
		case TT_BATCH_QUEUE:
		case TT_ENCODING_QUEUE:
			return rd_log_batch_cmp;
		default:
			return rd_log_generic_cmp;
	}
}


#if TXN_ERR_INJECT
int err_list[] = {
	MDB_PAGE_NOTFOUND,
	MDB_CORRUPTED,
	MDB_CURSOR_FULL,
	MDB_PAGE_FULL,
	MDB_BAD_TXN
};

static inline int
rd_generate_mdb_error() {
	int rc = MDB_SUCCESS;
	if ((rand() % 100000) == 0) {
		int idx = rand() % (sizeof(err_list)/sizeof(err_list[0]));
		rc = err_list[idx];
	}
	return rc;
}
#endif

static int
rdlog_txn_try_begin(struct repdev_log *log, unsigned int flags, MDB_txn **txn) {
	int err = 0;
	err = pthread_rwlock_tryrdlock(&log->access_lock);
	assert(err != EAGAIN);
	if (err)
		return err;
#if TXN_ERR_INJECT
	/* txn error injection */
	err = rd_generate_mdb_error();
	if (!err)
		err = mdb_txn_begin(log->env, NULL, flags, txn);
#else
	err = mdb_txn_begin(log->env, NULL, flags, txn);
#endif
	return err;
}

static int
rdlog_txn_begin(struct repdev_log *log, unsigned int flags, MDB_txn **txn) {
	int err = pthread_rwlock_rdlock(&log->access_lock);
	assert(!err);
	return mdb_txn_begin(log->env, NULL, flags, txn);
}

static inline void
rdlog_unlock(struct repdev_log *log) {
	pthread_rwlock_unlock(&log->access_lock);
}

static void
rdlog_txn_abort(struct repdev_log *log, MDB_txn *txn) {
	mdb_txn_abort(txn);
	rdlog_unlock(log);
}

static int
rdlog_txn_commit(struct repdev_log *log, MDB_txn *txn) {
	int err = 0;
#if TXN_ERR_INJECT
	/* txn error injection */
	err = rd_generate_mdb_error();
	if (!err)
		err = mdb_txn_commit(txn);
	else
		mdb_txn_abort(txn);
#else
	err = mdb_txn_commit(txn);
#endif
	rdlog_unlock(log);
	return err;
}

static int
rd_log_open(struct repdev *dev, const char *path, struct repdev_db *db, int id,
	char * kdevname, int wrap_txn);

static int
rdlog_repair(struct repdev_log *log, int errcode) {
	if (errcode == EACCES)
		return errcode;

	int rc = pthread_mutex_trylock(&log->repair_lock);
	if (rc) {
		/*
		 * The repair is in progress. Block the thread until it's done.
		 */
		pthread_mutex_lock(&log->repair_lock);
		pthread_mutex_unlock(&log->repair_lock);
		return 0;
	}
	pthread_rwlock_wrlock(&log->access_lock);

	char cmd[PATH_MAX];
	char aux[PATH_MAX];
	char* path = je_strdup(log->path);
	char* kname = realpath(path, aux);
	assert(kname);
	struct repdev* dev = log->dev;
	struct repdev_db* db = log->db;
	int logid = log->id;
	int err = 0;

	/* Closing everything here */
	for (int ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (log->dbi[ttag]) {
			mdb_dbi_close(log->env, log->dbi[ttag]);
			log->dbi[ttag] = 0;
		}
	}
	mdb_env_close(log->env);
	log->env = NULL;
	err = rd_format_lmdb_part(kname);
	if (err) {
		log_error(lg, "Dev(%s) log re-init error %d, WAL path %s doesn't point to a block device",
			dev->name, err, kname);

		struct rd_fault_signature fs = {
			.error = err,
			.source = 'l',
			.plevel = db->part + 1
		};

		rd_dev_faulted(dev, &fs);
		err = -EIO;
		goto _exit;
	}
	/* Open the log again */
	err = rd_log_open(dev, path, db, logid, kname, 0);
	if (err) {
		log_error(lg, "Dev(%s) log re-init error %d, log_path %s, log_id %d",
			dev->name, err, path, logid);

		struct rd_fault_signature fs = {
			.error = err,
			.source = 'l',
			.plevel = db->part + 1
		};

		rd_dev_faulted(dev, &fs);
		err = -EIO;
	}
_exit:
	pthread_rwlock_unlock(&log->access_lock);
	pthread_mutex_unlock(&log->repair_lock);
	if (!err)
		log_notice(lg, "Dev(%s) Log partition %s has been formatted",
			dev->name, path);
	je_free(path);
	return err;
}

static int
rd_is_opened(struct repdev_rd *rd) {
	return __sync_fetch_and_add(&rd->opened, 0);
}

static void
rd_set_opened(struct repdev_rd *rd, int val) {
	int old;
	do {
		old = rd->opened;
	} while (!__sync_bool_compare_and_swap(&rd->opened, old, val));
}

static int
rd_track_commit_size(long amount) {
	static long max_size = -1;
	static long curr_size = 0;
	static long peak = 0;
	if (max_size < 0) {
		char* ms_str = getenv("CCOWD_MAX_COMMIT_ALLOC");
		if (!ms_str) {
			if (is_embedded())
				max_size = DEV_RD_COMMIT_SIZE_MAX;
			else
				max_size = 0;
		} else
			max_size = strtol(ms_str, NULL, 10);
		if (max_size)
			log_notice(lg, "RTRD's commit max size set to %lu MB",
				max_size / (1024L*1024));
		peak = max_size;
	}
	atomic_add64(&curr_size, amount);
	if (curr_size > peak) {
		peak = curr_size;
		log_info(lg, "RTRD max. commit size set to %ld MB", peak/(1024*1024));
	}
	return (max_size > 0 ) && (curr_size > max_size) ? 1 : 0;
}

static void
rd_bloom_wait(struct repdev_db *db)
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
rd_bloom_insert(struct repdev_db *db, uint64_t key)
{
	uv_rwlock_wrlock(&db->bloom_lock);
	KEY_BLOOM_ADD(db->bloom, (uint32_t)(key>>32U));
	uv_rwlock_wrunlock(&db->bloom_lock);
}

static inline int
rd_bloom_query(struct repdev_db *db, uint64_t key)
{
	int rc;

	uv_rwlock_rdlock(&db->bloom_lock);
	if (db->bloom_loaded <= 0) {
		uv_rwlock_rdunlock(&db->bloom_lock);
		return -1;
	}

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

	if (e != NULL && ttag == e->ttag) {
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


static int rd_log_flush(struct repdev_log *log, type_tag_t ttag);
static void rd_log_flush_wait(struct repdev_db *db, type_tag_t ttag);

static void *
rd_partition_flush(void *arg) {
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
		if (is_log_tt(dev, ttag)) {
			for (int id = 0; id < DEV_LOGID_MAX; id++) {
				struct repdev_log *log = &DEV_LOGID(db, id);
				err = rd_log_flush(log, ttag);
				if (!err) {
					rd_log_flush_wait(db, ttag);
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
rd_keyhash(struct repdev *dev, MDB_val *key, MDB_val *key_out, uint64_t *out)
{
	int err;
	uint512_t chid;
	crypto_hash_t key_hash_type;
	type_tag_t key_ttag;

	err = reptrans_key_decode(dev, (char *)key->mv_data,
	    key->mv_size, &key_ttag, &key_hash_type,
	    &chid);
	if (err)
		return err;

	*out = chid.u.u.u;
	key_out->mv_data = out;
	key_out->mv_size = sizeof (uint64_t);
	return 0;
}

static int
rd_put_hashcount_entry(struct repdev *dev, MDB_val* key, MDB_val* data);

static int
rd_create_rowusage_entry(struct repdev* dev) {
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = NULL;
	int err = 0;

	for (int i = 0; i < rd->plevel; i++) {
		db = rd->db + i;
		for (type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ++ttag) {
			if (!is_rowusage_data_type_tag(ttag))
				continue;

			MDB_env *env = DEV_ENV(db, ttag);
			for (int i = 0; i < DEV_SHARD_MAX(db, ttag); i++) {
				MDB_dbi dbi = DEV_SHARD(db, ttag, i);
				MDB_txn* txn = NULL;
				MDB_cursor* cur = NULL;

				if (dev->terminating)
					goto _exit;

				err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
				if (err) {
					log_error(lg, "Get(%s): cannot begin txn rowusage_create: (%d) %s",
							dev->name, err, mdb_strerror(err));
					goto _exit;
				}

				err = mdb_cursor_open(txn, dbi, &cur);
				if (err) {
					log_error(lg, "Get(%s): cannot open cursor rowusage_create: (%d) %s",
							dev->name, err, mdb_strerror(err));
					goto _exit;
				}

				int op = MDB_FIRST;
				MDB_val key, data;
				while ((err = mdb_cursor_get(cur, &key, &data, op)) == 0) {
					op =  MDB_NEXT;
					uint512_t chid;
					crypto_hash_t key_hash_type;
					type_tag_t key_ttag;
					if (dev->terminating)
						goto _exit;

					err = reptrans_key_decode(dev, (char *)key.mv_data,
					    key.mv_size, &key_ttag, &key_hash_type,
					    &chid);
					if (err)
						goto _exit;
					uint16_t rowkey = HASHCALC(&chid, HASHCOUNT_MASK);
					dev->stats.rowusage[rowkey] += data.mv_size;
				}
				mdb_cursor_close(cur);
				mdb_txn_abort(txn);
				err = 0;
			}
		}
	}
	if (!err) {
		MDB_val ru_key = { .mv_size = strlen(ROWUSAGE_BLOB_KEY) + 1,
				   .mv_data = ROWUSAGE_BLOB_KEY };
		MDB_val ru_data = { .mv_size = sizeof(uint64_t) * HASHCOUNT_TAB_LENGTH,
				   .mv_data = (char*)dev->stats.rowusage };
		err = rd_put_hashcount_entry(dev, &ru_key, &ru_data);
	}

_exit:
	return err;
}

static void *
rd_bloom_load(void *arg) {

	struct repdev_db *db = arg;
	struct repdev *dev = db->dev;
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;
	MDB_txn *ktxn = NULL;
	MDB_cursor *kcursor = NULL;
	int err = 0;
	uint64_t entries = 0;
	uint64_t before = uv_hrtime();

	for (type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ++ttag) {

		if (dev->terminating)
			break;

		if (!dev->bloom_enabled) {
			log_info(lg, "Dev(%s) can't load, bloom is disabled", dev->name);
			uv_rwlock_wrlock(&db->bloom_lock);
			db->bloom_loaded = -1;
			uv_rwlock_wrunlock(&db->bloom_lock);
			continue;
		}

		if (!is_keycache_tt(ttag) && ttag != TT_NAMEINDEX)
			continue;

		const char* env_path = NULL;
		struct repdev_rd *rd = dev->device_lfs;
		mdb_env_get_path(rd->mdcache_env, &env_path);

		/* in case of hybrid, read keys from SSD if configured */
		if (dev->journal && is_keycache_tt(ttag)) {

			MDB_dbi kdbi = rd->keys_dbi[ttag];

			err = mdb_txn_begin(rd->mdcache_env, NULL, MDB_RDONLY, &ktxn);
			if (err) {
				log_error(lg, "Dev(%s): mdb_txn_begin: (%d) %s, env_path %s",
					dev->name, err, mdb_strerror(err), env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				goto _exit;
			}

			err = mdb_cursor_open(ktxn, kdbi, &kcursor);
			if (err) {
				log_error(lg, "Get(%s): cannot open kcursor bloom_load: (%d) %s, env_path %s",
						dev->name, err, mdb_strerror(err),
						env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				goto _exit;
			}

			int op = MDB_FIRST;
			MDB_val key;
			while ((err = mdb_cursor_get(kcursor, &key, NULL, op)) == 0) {
				op = MDB_NEXT;
				uint64_t kh = *(uint64_t *)key.mv_data;

				rd_bloom_insert(db, kh);
				entries++;

				if (dev->terminating)
					break;
			}

			mdb_cursor_close(kcursor);
			kcursor = NULL;

			mdb_txn_abort(ktxn);
			ktxn = NULL;
			err = 0;
			continue;
		}

		/* capacity, all-flash */
		MDB_env *env = DEV_ENV(db, ttag);
		for (int i = 0; i < DEV_SHARD_MAX(db, ttag); i++) {
			MDB_dbi dbi = DEV_SHARD(db, ttag, i);
			mdb_env_get_path(env, &env_path);

			if (dev->terminating)
				break;

			err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
			if (err) {
				log_error(lg, "Get(%s): cannot begin txn bloom_load: (%d) %s, "
						"env_path %s, plevel %d",
						dev->name, err, mdb_strerror(err),
						env_path, db->part);

				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				goto _exit;
			}

			err = mdb_cursor_open(txn, dbi, &cursor);
			if (err) {
				log_error(lg, "Get(%s): cannot open cursor bloom_load: (%d) %s, "
						"env_path %s, plevel %d",
						dev->name, err, mdb_strerror(err),
						env_path, db->part);
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				goto _exit;
			}

			int op = MDB_FIRST;
			MDB_val key;
			while ((err = mdb_cursor_get(cursor, &key, NULL, op)) == 0) {
				op = (ttag == TT_NAMEINDEX) ? MDB_NEXT_NODUP : MDB_NEXT;
				MDB_val keyhv;
				uint64_t kh;
				err = rd_keyhash(dev, &key, &keyhv, &kh);
				if (err)
					goto _exit;

				rd_bloom_insert(db, kh);
				entries++;

				if (dev->terminating)
					break;
			}

			mdb_cursor_close(cursor);
			cursor = NULL;

			mdb_txn_abort(txn);
			txn = NULL;
			err = 0;
		}
	}

_exit:

	if (cursor)
		mdb_cursor_close(cursor);
	if (txn)
		mdb_txn_abort(txn);
	if (kcursor)
		mdb_cursor_close(kcursor);
	if (ktxn)
		mdb_txn_abort(ktxn);
	log_notice(lg, "Dev(%s/%02d): loaded %ld bloom filter keys"
			" (took ~ %"
			PRIu64
			" ms), err: %d", dev->name, db->part, entries,
			(uv_hrtime() - before) / 1000000, err);

	/* mark the filter as loaded */

	uv_rwlock_wrlock(&db->bloom_lock);
	if (!err && db->bloom_loaded == 0 && !dev->terminating) {
		db->bloom_loaded = 1;
	} else {
		log_error(lg, "bloom loading failed, no bloom available for "
			"Dev(%s)-part-%d", dev->name, db->part);
		db->bloom_loaded = -1;
	}
	uv_rwlock_wrunlock(&db->bloom_lock);
	return NULL;

}

static int
rd_get_size(const char *devpath, long *blk_out, long *ssz_out)
{
	int fd;
	int err;
	volatile long blk = 0, ssz = 0;

	/** In current situation partitions often appear with delay about 30 sec */
	for (int i = 0; i<61; i++) {
		if ((fd = open(devpath, O_RDONLY)) != -1)
			break;

		/** Updating /dev filetree is still in progress */
		usleep(1000000);
	}

	if (fd == -1 ) {
		log_warn(lg, "Dev(%s): not found: %m", devpath);
		return -errno;
	}

	err = ioctl(fd, BLKGETSIZE, &blk);
	if (err) {
		close(fd);
		log_error(lg, "Dev(%s): BLKGETSIZE failed: %d", devpath, err);
		return err;
	}
	err = ioctl(fd, BLKSSZGET, &ssz);
	if (err) {
		close(fd);
		log_error(lg, "Dev(%s): BLKSSZGET failed: %d", devpath, err);
		return err;
	}
	close(fd);

	/* in case of 4K sector sizes, convert */
	blk = blk / (ssz / 512);

	*blk_out = blk;
	if (ssz_out)
		*ssz_out = ssz;
	return 0;
}

static void rd_lmdb_close(struct repdev *dev, struct repdev_db *db);

static int
rd_log_open(struct repdev *dev, const char *path, struct repdev_db *db, int id,
	char * kdevname, int wrap_txn)
{
	int err;
	struct stat st;
	MDB_txn *txn;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_log *log = &db->log[id];
	char fname[PATH_MAX];
	int rt_flags = dev->rt->flags;

	log->id = id;
	if (!log->env) {
		long blk = 0, ssz = 0;
		err = rd_get_size(path, &blk, &ssz);
		if (err) {
			log_error(lg, "Dev(%s): rd_get_size: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}

		/*
		 * Journal log key/value data store (small footprint)
		 */
		err = mdb_env_create(&log->env);
		if (err) {
			log_error(lg, "Dev(%s): cannot create log mdb env %d: (%d) %s",
			    dev->name, id, err, mdb_strerror(err));
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'l',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);

			err = -EIO;
			goto _exit;
		}

		uint64_t log_mapsize = 9ULL*blk*ssz/10ULL - DEV_RD_JPART_TAILROOM;
		log_mapsize = ((log_mapsize) & ~(4096-1));
		mdb_env_set_mapsize(log->env, log_mapsize);
		mdb_env_set_maxreaders(log->env, DEV_LMDB_MAXREADERS);

		err = mdb_env_set_maxdbs(log->env, TT_LAST);
		if (err) {
			log_error(lg, "Dev(%s): cannot set maxdbs %d: (%d) %s",
			    dev->name, id, err, mdb_strerror(err));

			struct rd_fault_signature fs = {
				.error = err,
				.source = 'l',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);

			err = -EIO;
			goto _exit;
		}

		int sync_flag = rd->sync == 0 ? MDB_NOSYNC :
			(rd->sync == 1 ? MDB_NOSYNC :
			 (rd->sync == 2 ? MDB_NOMETASYNC : 0));
		int rdahead_flag = rd->readahead ? 0 : MDB_NORDAHEAD;
		int writemap_flag = rd->writemap ? MDB_WRITEMAP : 0;
		int env_opt = MDB_COALESCE | MDB_LIFORECLAIM | MDB_RAW | MDB_NOTLS | sync_flag \
			      | MDB_NOSUBDIR | rdahead_flag | MDB_NOMEMINIT | MDB_PAGECAPCHECK \
			      | writemap_flag;
		if (rt_flags & RT_FLAG_RDONLY)
			env_opt |= MDB_RDONLY;
#ifdef CCOW_VALGRIND
		if (RUNNING_ON_VALGRIND) {
			env_opt &= ~MDB_NOMEMINIT;
		}
#endif

		strcpy(log->path, path);

		int retry_cnt = 0;

_retry_open:
		/* partition may not appear immediately here, wait for a little bit */
		snprintf(fname, PATH_MAX, "head -c 1k %s >/dev/null 2>/dev/null", path);
		for (int i = 0; i < 60; i++) {
			err = system(fname);
			if (!err) {
				break;
			}
			if (i == 30) {
				snprintf(fname, PATH_MAX, "partprobe %s >/dev/null 2>/dev/null", kdevname);
				err = system(fname);
			}
			usleep(1000000);
		}
		if (err) {
			log_error(lg, "Dev(%s): partition %s not accessible",
			    dev->name, path);
			err = -EIO;
			goto _exit;
		}

		if ((err = rd_is_block_device(kdevname)) != 1) {
			if (retry_cnt++ < 10) {
				usleep(1000000);
				goto _retry_open;
			}
			log_error(lg, "Dev(%s): cannot open log, path=%s is not "
				"a block device", dev->name, log->path);
			err = -EIO;
			goto _exit;
		}

		if (!(rt_flags & RT_FLAG_RDONLY)) {
			sprintf(fname, "rm -f %s-lock", log->path);
			err = system(fname);

			if ((rd->metaloc.version == 0)) {
				err = rd_format_lmdb_part(log->path);
				if (err) {
					log_error(lg, "Dev(%s): cannot format log, path=%s: %d",
						dev->name, log->path, err);
					goto _exit;
				}
				log_notice(lg, "Dev(%s) cleaned log partition %s", dev->name, log->path);
			}
		}

		err = mdb_env_open(log->env, log->path, env_opt, 0664);
		if (err) {
			if ((err == ENOENT || err == EINVAL) && retry_cnt++ < 10) {
				usleep(1000000);
				goto _retry_open;
			}
			log_error(lg, "Dev(%s): cannot open log, path=%s "
			    "mdb env: (%d) %s", dev->name, log->path,
			    err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
	}

	/*
	 * Initialize/Open journal log data store now
	 */
	if (wrap_txn) {
		err = rdlog_txn_begin(log, rt_flags & RT_FLAG_RDONLY ? MDB_RDONLY : 0, &txn);
#if TXN_ERR_INJECT
		if (!err) {
			rdlog_txn_abort(log, txn);
			err = MDB_BAD_TXN;
		}
#endif
		if (err) {
			log_error(lg, "Dev(%s): cannot begin log txn: (%d) %s, env_path %s, log_id %d",
			    dev->name, err, mdb_strerror(err), log->path, log->id);
			err = rdlog_repair(log, err);
			goto _exit;
		}
	} else {
		err = mdb_txn_begin(log->env, NULL, rt_flags & RT_FLAG_RDONLY ? MDB_RDONLY : 0, &txn);
		if (err) {
			log_error(lg, "Dev(%s): cannot begin log txn: (%d) %s, env_path %s, log_id %d",
			    dev->name, err, mdb_strerror(err), log->path, log->id);
			err = -EIO;
			goto _exit;
		}
	}

	for(type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		int flags = 0;

		if (!is_log_tt(dev, ttag))
			continue;

		if (!(rt_flags & RT_FLAG_RDONLY) && (rt_flags & RT_FLAG_CREATE))
			flags = MDB_CREATE;

		if (is_dupsort_tt(ttag))
			flags |= MDB_DUPSORT;

		char dbi_name[PATH_MAX];
		snprintf(dbi_name, PATH_MAX, "%s-part%d-%s-log%d",
		    rd->metaloc.version == 1 ? dev->name : "bd",
		    db->part + 1, type_tag_name[ttag], id);
		err = mdb_dbi_open(txn, dbi_name, flags, &log->dbi[ttag]);
		if (err) {
			rdlog_txn_abort(log, txn);
			log_error(lg, "Dev(%s): cannot open log mdb: (%d) %s, env_path %s, log_id %d",
			    dev->name, err, mdb_strerror(err), log->path, log->id);
			err = rdlog_repair(log, err);
			if (!err)
				err = -EAGAIN;
			else
				err = -EIO;
			goto _exit;
		}
		log->db = db;
		log->dev = dev;

		if (is_dupsort_tt(ttag)) {
			err = mdb_set_dupsort(txn, log->dbi[ttag],
				rd_log_cmp_ttag(ttag));
			assert(err == 0);
		}

		if (ttag == TT_VERIFICATION_QUEUE) {
			err = mdb_set_compare(txn, log->dbi[ttag],
			    rd_lmdb_verqueue_cmp);
			assert(err == 0);
		}

		if (ttag == TT_TRANSACTION_LOG) {
			err = mdb_set_compare(txn, log->dbi[ttag],
			    rd_lmdb_trlog_cmp);
			assert(err == 0);
		}

		if (ttag == TT_BATCH_INCOMING_QUEUE) {
			err = mdb_set_compare(txn, log->dbi[ttag],
				rd_lmdb_incomig_batch_cmp);
			assert(err == 0);
		}

	}
	if (wrap_txn) {
		err = rdlog_txn_commit(log, txn);
		if (err) {
			log_error(lg, "Dev(%s): cannot commit changes to log %s: (%d) %s, env_path %s, log_id %d",
			    dev->name, log->path, err, mdb_strerror(err), log->path, log->id);
			err = rdlog_repair(log, err);
			goto _exit;
		}
	} else {
		err = mdb_txn_commit(txn);
		if (err) {
			log_error(lg, "Dev(%s): cannot commit changes to log %s: (%d) %s, env_path %s, log_id %d",
			    dev->name, log->path, err, mdb_strerror(err), log->path, log->id);
			err = -EIO;
			goto _exit;
		}
	}

	mdb_env_sync(log->env, 1);

	return 0;

_exit:
	if (err)
		rd_lmdb_close(dev, db);
	return err;
}

static void
rd_log_close(struct repdev *dev, struct repdev_db *db, int id)
{
	struct repdev_log *log = &db->log[id];

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
rd_log_flush_wait(struct repdev_db *db, type_tag_t ttag)
{
	/* let flush threads finish. */
	uv_mutex_lock(&db->log_flush_lock);

	while (db->log_flush_cnt != 0)
		uv_cond_wait(&db->log_flush_condvar,
		    &db->log_flush_lock);

	uv_mutex_unlock(&db->log_flush_lock);
}

static void
rd_log_flush_barrier(struct repdev_db *db, type_tag_t ttag, int set)
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
rd_lmdb_close(struct repdev *dev, struct repdev_db *db)
{
	int i;

	for (i = TT_NAMEINDEX; i < TT_LAST; ++i) {
		if (is_log_tt(dev, i))
			rd_log_flush_wait(db, i);
		for (int j = 0; j < DEV_SHARDS_MAX; j++) {
			if (DEV_SHARD(db, i, j) && !(dev->journal && is_mdoffload_tt(dev, i))) {
				mdb_dbi_close(DEV_ENV(db, i), DEV_SHARD(db, i, j));
			}
			if (i == TT_HASHCOUNT)
				break;
		}
	}
	if (db->env[0]) {
		mdb_env_close(db->env[0]);
		db->env[0] = NULL;
	}
	if (!dev->wal_disabled) {
		for (i = 0; i < DEV_LOGID_MAX; i++) {
			rd_log_close(dev, db, i);
		}
	}
	key_cache_fini(db->key_cache);
	db->key_cache = NULL;
}

static void
rd_mdcache_close(struct repdev *dev)
{
	struct repdev_rd *rd = dev->device_lfs;

	for (type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (!is_mdcache_tt(dev, ttag))
			continue;
		if (!rd->mdcache_dbi[ttag])
			continue;
		mdb_dbi_close(rd->mdcache_env, rd->mdcache_dbi[ttag]);
		rd->mdcache_dbi[ttag] = 0;
	}
	for (type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (!is_keycache_tt(ttag))
			continue;
		if (!rd->keys_dbi[ttag])
			continue;
		mdb_dbi_close(rd->mdcache_env, rd->keys_dbi[ttag]);
		rd->keys_dbi[ttag] = 0;
	}
	for (type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (!is_mdoffload_tt(dev, ttag))
			continue;
		if (!rd->mdoffload_dbi[ttag])
			continue;
		mdb_dbi_close(rd->mdcache_env, rd->mdoffload_dbi[ttag]);
		rd->mdoffload_dbi[ttag] = 0;
	}
	if (rd->mdcache_env) {
		mdb_env_close(rd->mdcache_env);
		rd->mdcache_env = NULL;
	}
	if (rd->mdcache) {
		mdcache_fini(rd->mdcache);
		rd->mdcache = NULL;
	}
}

static int
rd_mdcache_get_blob(struct repdev *dev, type_tag_t ttag, uint64_t *kh,
    void **blob_data, size_t *blob_size)
{
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn *txn;
	MDB_val key, data;

	key.mv_size = sizeof (uint64_t);
	key.mv_data = kh;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);
	err = mdb_txn_begin(rd->mdcache_env, NULL, MDB_RDONLY, &txn);
	if (err) {
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'o',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);

		log_error(lg, "Dev(%s): mdb_txn_begin: (%d) %s, env_path %s", dev->name,
		    err, mdb_strerror(err), env_path);
		err = -EIO;
		return err;
	}

	err = mdb_get(txn, rd->mdcache_dbi[ttag], &key, &data);
	if (err) {
		if (err == MDB_NOTFOUND) {
			err = -ENOENT;
		} else {
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);

			log_error(lg, "Get(%s): cannot get value from "
			    "mdcache: (%d) %s, env_path %s", dev->name,
			    err, mdb_strerror(err), env_path);
			err = -EIO;
		}
	}
	*blob_size = data.mv_size;
	*blob_data = data.mv_data;

	mdb_txn_abort(txn);
	return err;
}

static int
rd_mdcache_putdel_blob(struct repdev *dev, type_tag_t ttag, MDB_txn *ext_txn,
    uint64_t *kh, char *blob_data, size_t blob_len, uint64_t *kh_del)
{
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn *txn;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	if (!ext_txn) {
		err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);

			log_error(lg, "Dev(%s): mdb_txn_begin: (%d) %s, env_path %s",
				dev->name, err, mdb_strerror(err), env_path);
			return err;
		}
	} else
		txn = ext_txn;

	if (kh) {
		MDB_val key, data;

		key.mv_size = sizeof (uint64_t);
		key.mv_data = kh;
		data.mv_size = blob_len;
		data.mv_data = NULL; /* MDB_RESERVE will fill it in with pointer */
		err = mdb_put(txn, rd->mdcache_dbi[ttag], &key, &data,
		    MDB_RESERVE|MDB_NOOVERWRITE);
		if (err) {
			if (!ext_txn)
				mdb_txn_abort(txn);
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): %s kh=%lx mdb_put: (%d) %s, ignored",
				    dev->name, type_tag_name[ttag], *kh, err, mdb_strerror(err));
				if (!ext_txn) {
					err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
					if (err) {
						struct rd_fault_signature fs = {
							.error = err,
							.source = 'o',
							.plevel = 0
						};
						rd_dev_faulted(dev, &fs);

						log_error(lg, "Dev(%s): mdcache mdb_txn_begin: (%d) %s, env_path %s",
						    dev->name, err, mdb_strerror(err), env_path);
						return err;
					}
				}
				err = 0;
				goto _kh_del;
			}
			if (!RD_NO_FREE_SPACE(err)) {
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};
				rd_dev_faulted(dev, &fs);

				log_error(lg, "Dev(%s): %s mdcache blob_len=%ld mdb_put: (%d) %s, env_path %s",
					dev->name, type_tag_name[ttag], blob_len, err,
					mdb_strerror(err), env_path);
			} else {
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};

				rd_set_ro_fault(dev, &fs);
			}
			return err;
		}

		memcpy((char *)data.mv_data, blob_data, blob_len);
	}

_kh_del:
	if (kh_del) {
		MDB_val delkey = { .mv_size = sizeof (uint64_t), .mv_data = kh_del };

		err = mdb_del(txn, rd->mdcache_dbi[ttag], &delkey, NULL);
		if (err) {
			if (!ext_txn)
				mdb_txn_abort(txn);
			if (err == MDB_NOTFOUND) {
				log_debug(lg, "Dev(%s): kh=%lx mdb_del: (%d) %s, ignored", dev->name,
				    *kh_del, err, mdb_strerror(err));
				err = 0;
			} else {
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};
				rd_dev_faulted(dev, &fs);

				log_error(lg, "Dev(%s): mdcache mdb_del: (%d) %s, env_path %s",
					dev->name, err, mdb_strerror(err), env_path);
			}
			return err;
		}
	}

	if (!ext_txn) {
		err = mdb_txn_commit(txn);
		if (err) {
			log_warn(lg, "Dev(%s): mdb_txn_commit: (%d) %s",
			    dev->name, err, mdb_strerror(err));
		}
	}

	return err;
}

static int
rd_mdcache_load(struct repdev *dev, type_tag_t ttag)
{
	struct repdev_rd *rd = dev->device_lfs;
	uint64_t before = uv_hrtime();
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;
	int err = 0;
	uint64_t entries = 0;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
	if (err) {
		if (err != EACCES) {
			log_error(lg, "Get(%s): cannot begin txn mdcache_load: (%d) %s, env_path %s",
					dev->name, err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		}
		goto _exit;
	}

	err = mdb_cursor_open(txn, rd->mdcache_dbi[ttag], &cursor);
	if (err) {
		log_error(lg, "Get(%s): cannot open cursor mdcache_load: (%d) %s, env_path %s",
				dev->name, err, mdb_strerror(err), env_path);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'o',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);
		goto _exit;
	}

	int del_cnt = 0, del_blocked = 0;
	int op = MDB_FIRST;
	MDB_val mdbkey;
	while ((err = mdb_cursor_get(cursor, &mdbkey, NULL, op)) == 0) {
		op = MDB_NEXT;
		if (mdbkey.mv_size != sizeof(uint64_t)) {
			log_error(lg, "Dev(%s) invalid mdcache key size %lu, expected %lu, removing",
				dev->name, mdbkey.mv_size, sizeof(uint64_t));
			err = mdb_cursor_del(cursor, 0);
			if (err) {
				log_error(lg, "Dev(%s) unable to delete corrupted mdcache entry: (%d) %s, env_path %s",
					dev->name, err,  mdb_strerror(err), env_path);
			}
			continue;
		}

		mdcache_entry_t *t = NULL;
		mdcache_entry_t *e = NULL;
		mdcache_t *c = rd->mdcache;
		uint64_t *key = (uint64_t *)mdbkey.mv_data;

		entries++;
		HASH_FIND_INT64(c->entries, key, t);
		if (t)
			continue;

		if ((e = je_malloc(sizeof(*e))) == NULL) {
			err = -ENOMEM;
			goto _exit;
		}

		e->key = *key;

		HASH_ADD_INT64(c->entries, key, e);

		if (HASH_COUNT(c->entries) >= c->c && !del_blocked) {
			HASH_ITER(hh, c->entries, e, t) {
				HASH_DELETE(hh, c->entries, e);
				je_free(e);
				err = rd_mdcache_putdel_blob(c->dev, ttag,
				    txn, NULL, NULL, 0, key);
				if (err) {
					del_blocked = err;
				} else if (del_cnt++ > MDCACHE_ADJUST_EVICT) {
					/* delete up to evict max */
					del_blocked = 1;
				}
				break;
			}
		}

		if (dev->terminating)
			break;
	}

	mdb_cursor_close(cursor);

	if (del_cnt) {
		err = mdb_txn_commit(txn);
		if (err) {
			log_error(lg, "Dev(%s) unable to commit mdcache: (%d) %s, env_path %s",
				dev->name, err,  mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		}
	} else
		mdb_txn_abort(txn);

	if (err == MDB_NOTFOUND)
		err = 0;

	log_notice(lg, "Dev(%s): loaded %ld mdcache %s keys (took ~ %" PRIu64 " ms), evicted %d, err: %d",
	    dev->name, entries, type_tag_name[ttag], (uv_hrtime() - before) / 1000000, del_cnt, err);

	return 0;

_exit:
	if (cursor)
		mdb_cursor_close(cursor);
	if (txn)
		mdb_txn_abort(txn);

	return err;

}

static int
rd_lmdb_oomfunc(MDB_env *env, int pid, void* thread_id, size_t txn, unsigned gap,
    int retry)
{
	log_notice(lg, "Detected laggard reader PID=%d TID=%p TXN=%lu GAP=%u retry=%d",
	    pid, thread_id, txn, gap, retry);
	return 0;
}

static int
rd_mdcache_open(struct repdev *dev, char *dbpath)
{
	int err = 0;
	char fname[PATH_MAX];
	struct stat st;
	struct repdev_rd *rd = dev->device_lfs;
	int rt_flags = dev->rt->flags;
	long blk = 0, ssz = 0;
	MDB_txn *txn = NULL;
	err = rd_get_size(dbpath, &blk, &ssz);
	if (err)
		goto _exit;
	uint64_t part_size = blk * ssz;

	uint32_t mdcache_size = part_size / MDCACHE_CM_SIZE;
	err = mdcache_ini(&rd->mdcache, dev, mdcache_size, NULL);
	if (err) {
		log_error(lg, "Dev(%s): failed to init LRU MD cache", dev->name);
		goto _exit;
	}

	/*
	 * Main key/value data store
	 */
	err = mdb_env_create(&rd->mdcache_env);
	if (err) {
		log_error(lg, "Dev(%s): cannot create mdcache mdb env: (%d) %s,",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	mdb_env_set_psize(rd->mdcache_env, rd->metaloc.mdpsize);
	mdb_env_set_mapsize(rd->mdcache_env, part_size);
#ifdef CCOW_VALGRIND
	if (RUNNING_ON_VALGRIND) {
		mdb_env_set_mapsize(rd->mdcache_env, 64ULL * 1024 * 1024);
	}
#endif
	mdb_env_set_maxreaders(rd->mdcache_env, DEV_LMDB_MAXREADERS);

	mdb_env_set_oomfunc(rd->mdcache_env, rd_lmdb_oomfunc);

	int sync_flag = rd->sync == 0 ? MDB_NOSYNC :
		(rd->sync == 1 ? (rd->direct ? MDB_NOSYNC : MDB_NOMETASYNC) :
		 (rd->sync == 2 ? MDB_NOMETASYNC : 0));
	int rdahead_flag = rd->readahead ? 0 : MDB_NORDAHEAD;
	int direct_flag = rd->direct ? MDB_DIRECT : 0;
	int writemap_flag = rd->writemap ? MDB_WRITEMAP : 0;
	int env_opt = MDB_COALESCE | MDB_LIFORECLAIM | MDB_RAW | MDB_NOTLS | sync_flag \
		      | MDB_NOSUBDIR | rdahead_flag | direct_flag | MDB_PAGECAPCHECK | writemap_flag;
	if (rt_flags & RT_FLAG_RDONLY)
		env_opt |= MDB_RDONLY;
	else {
		sprintf(fname, "rm -f %s-lock", dbpath);
		err = system(fname);
	}
#ifdef CCOW_VALGRIND
	if (RUNNING_ON_VALGRIND) {
		env_opt &= ~MDB_NOMEMINIT;
	}
#endif

	int retry_cnt = 0;
_retry_open:
	/* partition may not appear immediately here, wait for a little bit */
	snprintf(fname, PATH_MAX, "head -c 1k %s >/dev/null 2>/dev/null", dbpath);
	for (int i = 0; i < 30; i++) {
		err = system(fname);
		if (!err) {
			break;
		}
		usleep(1000000);
	}
	if (err) {
		log_error(lg, "Dev(%s): partition %s not accessible",
		    dev->name, dbpath);
		err = -EIO;
		goto _exit;
	}

	log_debug(lg, "Dev(%s): opening MDCache Env using path %s mapsize=%ld",
	    dev->name, dbpath, part_size);

	err = mdb_env_set_maxdbs(rd->mdcache_env, TT_LAST*2);
	if (err) {
		log_error(lg, "Dev(%s): cannot set maxdbs: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	err = mdb_env_open(rd->mdcache_env, dbpath, env_opt, 0664);
	if (err) {
		if ((err == ENOENT || err == EINVAL) && retry_cnt++ < 10) {
			usleep(1000000);
			goto _retry_open;
		}
		log_error(lg, "Dev(%s): cannot open, dbpath=%s "
		    "mdb env: (%d) %s", dev->name, dbpath, err,
		    mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	err = mdb_txn_begin(rd->mdcache_env, NULL,
	    rt_flags & RT_FLAG_RDONLY ? MDB_RDONLY : 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): mdb_txn_begin: (%d) %s, env_path %s",
			dev->name, err, mdb_strerror(err), dbpath);
		err = -EIO;
		goto _exit;
	}

	int flags = 0;
	for(type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		flags = 0;

		if (!is_mdcache_tt(dev, ttag))
			continue;

		if (!(rt_flags & RT_FLAG_RDONLY) && (rt_flags & RT_FLAG_CREATE))
			flags = MDB_CREATE;

		flags |= MDB_INTEGERKEY;

		char dbi_name[PATH_MAX];
		snprintf(dbi_name, PATH_MAX, "mdcache-%s", type_tag_name[ttag]);
		err = mdb_dbi_open(txn, dbi_name, flags, &rd->mdcache_dbi[ttag]);
		if (err) {
			log_error(lg, "Dev(%s): cannot open dbi[%s], dbpath=%s "
			    "mdb env: (%d) %s", dev->name, type_tag_name[ttag],
			    dbpath, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
	}

	for(type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		flags = 0;

		if (!is_keycache_tt(ttag))
			continue;

		if (!(rt_flags & RT_FLAG_RDONLY) && (rt_flags & RT_FLAG_CREATE))
			flags = MDB_CREATE;

		flags |= MDB_INTEGERKEY;

		char dbi_name[PATH_MAX];
		snprintf(dbi_name, PATH_MAX, "keys-%s", type_tag_name[ttag]);
		err = mdb_dbi_open(txn, dbi_name, flags, &rd->keys_dbi[ttag]);
		if (err) {
			log_error(lg, "Dev(%s): cannot open dbi[%s], dbpath=%s "
			    "mdb env: (%d) %s", dev->name, type_tag_name[ttag],
			    dbpath, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
	}

	for(type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		flags = 0;

		if (!is_mdoffload_tt(dev, ttag))
			continue;

		if (!(rt_flags & RT_FLAG_RDONLY) && (rt_flags & RT_FLAG_CREATE))
			flags = MDB_CREATE;

		if (is_dupsort_tt(ttag))
			flags |= MDB_DUPSORT;

		char dbi_name[PATH_MAX];
		snprintf(dbi_name, PATH_MAX, "%s", type_tag_name[ttag]);
		err = mdb_dbi_open(txn, dbi_name, flags, &rd->mdoffload_dbi[ttag]);
		if (err) {
			log_error(lg, "Dev(%s): cannot open mdb: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}

		if (is_dupsort_tt(ttag)) {
			err = mdb_set_dupsort(txn, rd->mdoffload_dbi[ttag],
			    rd_lmdb_cmp_ttag(ttag));
			assert(err == 0);
		}

		if (ttag == TT_VERIFICATION_QUEUE) {
			err = mdb_set_compare(txn, rd->mdoffload_dbi[ttag],
			    rd_lmdb_verqueue_cmp);
			assert(err == 0);
		}

		if (ttag == TT_TRANSACTION_LOG) {
			err = mdb_set_compare(txn, rd->mdoffload_dbi[ttag],
			    rd_lmdb_trlog_cmp);
			assert(err == 0);
		}

		if (ttag == TT_BATCH_INCOMING_QUEUE) {
			err = mdb_set_compare(txn, rd->mdoffload_dbi[ttag],
				rd_lmdb_incomig_batch_cmp);
			assert(err == 0);
		}

		/* make DEV_ENV() macro return right environment for MD ttag */
		for (int j = 0; j < rd->plevel; ++j) {
			struct repdev_db *db = rd->db + j;
			db->env[1] = rd->mdcache_env;
		}
	}

	err = mdb_txn_commit(txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot commit to mdb: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	log_notice(lg, "Dev(%s): mdcache %s (size=%luMB, mdcache_size=%u) opened successfully",
	    dev->name, dbpath, part_size/1024/1024, mdcache_size);

	if (rd->mdcache_enable) {
		for(type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
			if (!is_mdcache_tt(dev, ttag))
				continue;

			if (dev->rt->init_traits) {
				struct ccowd_params* params = dev->rt->init_traits;
				if (params->log_flush)
					continue;
			}

			if (ccow_daemon && ccow_daemon->params &&
				ccow_daemon->params->log_flush)
				continue;

			(void)rd_mdcache_load(dev, ttag);
		}
	}

	return 0;
_exit:
	if (txn)
		mdb_txn_abort(txn);
	rd_mdcache_close(dev);
	return err;
}

int
mdcache_ini(mdcache_t **cache, struct repdev *dev, const uint32_t c,
    void (*free_entry)(void *element))
{

	assert(c != 0);
	mdcache_t *new = NULL;

	if (cache == NULL)
		return -EINVAL;
	if ((new = je_malloc(sizeof(*new))) == NULL)
		return -ENOMEM;
	if (uv_rwlock_init(&new->lock) != 0) {
		je_free(new);
		return -ENOMEM;
	}

	new->insert_queue = lfqueue_create(MDCACHE_QUEUE_SIZE);
	if (!new->insert_queue) {
		je_free(new);
		return -ENOMEM;
	}
	new->dev = dev;
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
mdcache_fini(mdcache_t *cache)
{
	mdcache_entry_t *entry, *tmp = NULL;

	if (cache == NULL)
		return -EINVAL;

	uv_rwlock_wrlock(&cache->lock);

	HASH_ITER(hh, cache->entries, entry, tmp) {
		HASH_DEL(cache->entries, entry);
		je_free(entry);
	}

	uv_rwlock_wrunlock(&cache->lock);
	uv_rwlock_destroy(&cache->lock);
	if (cache->insert_queue) {
		void* ptr = NULL;
		while ((ptr = lfqueue_dequeue(cache->insert_queue)) != NULL)
			je_free(ptr);
		lfqueue_destroy(cache->insert_queue);
	}
	je_free(cache);
	return 0;
}

static int
mdcache_stat_update(mdcache_t *c, MDB_txn *txn) {
	int err;
	struct repdev *dev = c->dev;
	struct repdev_rd *rd = dev->device_lfs;

	MDB_envinfo env_info;
	mdb_env_info(rd->mdcache_env, &env_info);

	size_t mdcache_size_max = env_info.me_mapsize;
	size_t mdcache_size = 0;
	size_t mdcache_entries = 0;
	size_t keydb_size = 0;
	size_t keydb_entries = 0;
	size_t mdoffload_size = 0;
	size_t mdoffload_entries = 0;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);
	/* get mdcache db size */
	for(type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (!is_mdcache_tt(dev, ttag))
			continue;

		MDB_dbi dbi = rd->mdcache_dbi[ttag];
		MDB_stat stat;
		err = mdb_stat(txn, dbi, &stat);
		if (err) {
			if (err == MDB_BAD_TXN) {
				err = 0;
			} else {
				log_error(lg, "Dev(%s): mdcache %s mdb_stat: (%d) %s, env_path %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err),
				    env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};
				rd_dev_faulted(dev, &fs);
				err = -EIO;
			}
			return err;
		}
		mdcache_size += stat.ms_psize * (stat.ms_branch_pages +
			stat.ms_leaf_pages + stat.ms_overflow_pages);
		mdcache_entries += stat.ms_entries;
	}

	/* get keys db size */
	for(type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (!is_keycache_tt(ttag))
			continue;

		MDB_dbi dbi = rd->keys_dbi[ttag];
		MDB_stat stat;
		err = mdb_stat(txn, dbi, &stat);
		if (err) {
			if (err == MDB_BAD_TXN) {
				err = 0;
			} else {
				log_error(lg, "Dev(%s): mdcache %s mdb_stat: (%d) %s, env_path %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err), env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};
				rd_dev_faulted(dev, &fs);
				err = -EIO;
			}
			return err;
		}
		keydb_size += stat.ms_psize * (stat.ms_branch_pages +
		    stat.ms_leaf_pages + stat.ms_overflow_pages);
		keydb_entries =+ stat.ms_entries;
	}

	/* get mdoffload db size */
	for(type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (!is_mdoffload_tt(dev, ttag))
			continue;

		MDB_dbi dbi = rd->mdoffload_dbi[ttag];
		MDB_stat stat;
		err = mdb_stat(txn, dbi, &stat);
		if (err) {
			if (err == MDB_BAD_TXN) {
				err = 0;
			} else {
				log_error(lg, "Dev(%s): mdcache %s mdb_stat: (%d) %s, env_path %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err), env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};
				rd_dev_faulted(dev, &fs);
				err = -EIO;
			}
			return err;
		}
		mdoffload_size += stat.ms_psize * (stat.ms_branch_pages +
		    stat.ms_leaf_pages + stat.ms_overflow_pages);
		mdoffload_entries += stat.ms_entries;
	}
	uv_rwlock_wrlock(&c->lock);
	c->stats.total = env_info.me_mapsize;
	c->stats.mdcache_used = mdcache_size;
	c->stats.keydb_used = keydb_size;
	c->stats.mdoffload_used = mdoffload_size;
	c->stats.mdcache_entries = mdcache_entries;
	c->stats.keydb_entries = keydb_entries;
	c->stats.mdoffload_entries = mdoffload_entries;
	uv_rwlock_wrunlock(&c->lock);
	return 0;
}

/* get new mdcache size and check if we close to full, if so
 * start evicting some more. Hiwat is 90%, lowat is 80%. */
int
mdcache_adjust(mdcache_t *c, type_tag_t ttag, MDB_txn *ext_txn)
{
	int err;
	struct repdev *dev = c->dev;
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn *txn;
	int repeat = 0;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);


	if (!ext_txn) {
		err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
		if (err) {
			log_error(lg, "Dev(%s): mdcache mdb_txn_begin: (%d) %s, env_path %s",
				dev->name, err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
			err = -EIO;
			return err;
		}
	} else
		txn = ext_txn;

	mdcache_entry_t *evicted;
	uv_rwlock_rdlock(&c->lock);
	size_t mdcache_size_max = MDCACHE_ADJUST_MAX * c->stats.total / 100;
	size_t mdcache_size = c->stats.mdcache_used + c->stats.mdoffload_used +
		c->stats.keydb_used;
	uv_rwlock_rdunlock(&c->lock);

	do {
		if (!repeat && mdcache_size < mdcache_size_max)
			break;

		mdcache_entry_t *t = NULL;
		mdcache_entry_t *e = NULL;

		evicted = NULL;
		uv_rwlock_wrlock(&c->lock);
		HASH_ITER(hh, c->entries, e, t) {
			HASH_DELETE(hh, c->entries, e);
			evicted = e;
			break;
		}
		uv_rwlock_wrunlock(&c->lock);

		if (evicted) {
			MDB_val delkey = { .mv_size = sizeof (uint64_t),
				.mv_data = &evicted->key };
			err = mdb_del(txn, rd->mdcache_dbi[ttag], &delkey, NULL);
			if (err == MDB_NOTFOUND)
				err = 0;
			if (err) {
				log_error(lg, "Dev(%s): %s mdb_del: (%d) %s, env_path %s",
				    dev->name, type_tag_name[ttag], err,
				    mdb_strerror(err), env_path);
				err = -EIO;
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};
				rd_dev_faulted(dev, &fs);
			}
			c->stats.evicted++;
			je_free(evicted);
		}
	} while (!err && evicted && repeat++ < MDCACHE_ADJUST_EVICT);

	if (repeat) {
		log_debug(lg, "mdcache %s force evicted %d entries, room_left=%ldMB",
		    type_tag_name[ttag], repeat, (mdcache_size_max - mdcache_size)/1024/1024);
	}

	if (!ext_txn) {
		if (err || !repeat)
			mdb_txn_abort(txn);
		else {
			err = mdb_txn_commit(txn);
			if (err) {
				log_warn(lg, "Dev(%s): mdcache mdb_txn_commit: (%d) %s, env_path %s",
				    dev->name, err, mdb_strerror(err), env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};
				rd_dev_faulted(dev, &fs);
				err = -EIO;
			}
		}
	}
	return err;
}

int
mdcache_insert(mdcache_t *c, type_tag_t ttag, MDB_txn *ext_txn, uint64_t *key,
    void *data, uint32_t size)
{
	int err;
	mdcache_entry_t *t = NULL;
	mdcache_entry_t *e = NULL;
	mdcache_entry_t *evicted = NULL;

	if (c == NULL)
		return -EINVAL;

	err = mdcache_adjust(c, ttag, ext_txn);

	if (err)
		return err;

	uv_rwlock_wrlock(&c->lock);
	HASH_FIND_INT64(c->entries, key, t);

	if (t != NULL) {
		uv_rwlock_wrunlock(&c->lock);
		return 0;
	}

	if ((e = je_malloc(sizeof(*e))) == NULL) {
		uv_rwlock_wrunlock(&c->lock);
		return -ENOMEM;
	}

	e->key = *key;

	HASH_ADD_INT64(c->entries, key, e);

	if (HASH_COUNT(c->entries) >= c->c) {
		HASH_ITER(hh, c->entries, e, t) {
			HASH_DELETE(hh, c->entries, e);
			evicted = e;
			break;
		}
	}
	uv_rwlock_wrunlock(&c->lock);

	err = rd_mdcache_putdel_blob(c->dev, ttag, ext_txn, key, data, size,
	    evicted ? &evicted->key : NULL);
	if (err) {
		/* this will block inserts on log flush */
	}

	if (evicted) {
		je_free(evicted);
		c->stats.evicted++;
	}

	return err;
}

static int
mdcache_enqueue(mdcache_t *c, type_tag_t ttag, uint64_t *key, void *data,
	uint32_t size)
{
	assert(key);
	mdcache_entry_t *t = NULL;

	if (c == NULL)
		return -EINVAL;

	uv_rwlock_wrlock(&c->lock);
	HASH_FIND_INT64(c->entries, key, t);
	uv_rwlock_wrunlock(&c->lock);

	if (t != NULL)
		return 0;

	uint8_t* reg = je_calloc(1, sizeof(mdcache_queue_entry_t) + size);
	if (!reg)
		return -ENOMEM;
	mdcache_queue_entry_t e = { .key = *key, .size = size, .ttag = ttag, .buf = reg + sizeof(e)};
	memcpy(reg, &e, sizeof(e));
	memcpy(reg + sizeof(e), data, size);
	int err = lfqueue_enqueue(c->insert_queue, reg);
	if (err)
		je_free(reg);
	return err;
}

static int
mdcache_flush(mdcache_t *c, MDB_txn *ext_txn, int* n_flushed) {
	struct repdev *dev = c->dev;
	struct repdev_rd *rd = dev->device_lfs;
	int err = 0;

	assert(ext_txn);
	assert(c);
	assert(n_flushed);
	/* Limit number of flushed entries to instant queue size.
	 * Otherwise it will flush for a long while under intensive GET
	 */
	*n_flushed = 0;
	int qsize = lfqueue_length(c->insert_queue);

	for (int i = 0; i < qsize; i++) {
		mdcache_queue_entry_t e;
		uint8_t* reg = lfqueue_dequeue(c->insert_queue);
		assert(reg);
		memcpy(&e, reg, sizeof(e));
		err = mdcache_insert(c, e.ttag, ext_txn, &e.key, e.buf, e.size);
		je_free(reg);
		if (err) {
			log_error(lg, "mdcache_insert() error: %d", err);
			break;
		}
		(*n_flushed)++;
	}
	return err;
}

static int
mdcache_queue_len(mdcache_t *c) {
	return lfqueue_length(c->insert_queue);
}

int
mdcache_lookup(mdcache_t *c, type_tag_t ttag, uint64_t *key, void **blob_data,
    uint64_t *blob_size)
{

	mdcache_entry_t *e = NULL;
	int err;

	if (c == NULL || key == NULL || blob_size == NULL)
		return -EINVAL;

	uv_rwlock_wrlock(&c->lock);

	HASH_FIND_INT64(c->entries, key, e);

	if (!e) {
		uv_rwlock_wrunlock(&c->lock);
		*blob_size = 0;
		c->stats.miss++;
		return -ENOENT;
	}

	/* LRUing by deleting and re-inserting it to head */
	HASH_DELETE(hh, c->entries, e);
	HASH_ADD_INT64(c->entries, key, e);
	uv_rwlock_wrunlock(&c->lock);

	err = rd_mdcache_get_blob(c->dev, ttag, key, blob_data, blob_size);
	if (err)
		return err;

	c->stats.hit++;
	return 0;
}

int
mdcache_remove(mdcache_t *c, type_tag_t ttag, MDB_txn *ext_txn, uint64_t *key) {

	mdcache_entry_t *e = NULL;
	int err;

	if (c == NULL)
		return -EINVAL;

	uv_rwlock_wrlock(&c->lock);

	HASH_FIND_INT64(c->entries, key, e);

	if (!e) {
		uv_rwlock_wrunlock(&c->lock);
		return -ENOENT;
	}

	HASH_DELETE(hh, c->entries, e);
	uv_rwlock_wrunlock(&c->lock);

	err = rd_mdcache_putdel_blob(c->dev, ttag, ext_txn, NULL, NULL, 0, key);
	if (err) {
		/* TODO: block inserts */
	}

	je_free(e);
	return 0;
}

static int
rd_key_get(struct repdev *dev, type_tag_t ttag, uint64_t *kh, size_t *blob_size)
{
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn *txn;
	MDB_val key, data;

	if (!rd->mdcache)
		return -EINVAL;

	key.mv_size = sizeof (uint64_t);
	key.mv_data = kh;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	err = mdb_txn_begin(rd->mdcache_env, NULL, MDB_RDONLY, &txn);
	if (err) {
		log_error(lg, "Dev(%s): mdb_txn_begin: (%d) %s, env_path %s",
			dev->name, err, mdb_strerror(err), env_path);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'o',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);
		return err;
	}

	err = mdb_get(txn, rd->keys_dbi[ttag], &key, &data);
	if (err) {
		if (err != MDB_NOTFOUND) {
			log_error(lg, "Get(%s): cannot get value from "
			    "keys: (%d) %s, env_path %s", dev->name, err,
			    mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		}
		goto _exit;
	}

	msgpack_u u;
	msgpack_unpack_init_b(&u, data.mv_data, data.mv_size, 0);

	uint64_t size;
	err = msgpack_unpack_uint64(&u, &size);
	if (err) {
		log_error(lg, "Dev(%s): Error decoding key blob size: buflen=%ld, "
		    "err=%d", dev->name, data.mv_size, err);
		goto _exit;
	}

	*blob_size = size;

_exit:
	mdb_txn_abort(txn);
	return err;
}

static int
rd_key_get_attr(struct repdev *dev, type_tag_t ttag, uint64_t *kh, uint64_t *attrp)
{
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn *txn;
	MDB_val key, data;

	if (!rd->mdcache)
		return -EINVAL;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	key.mv_size = sizeof (uint64_t);
	key.mv_data = kh;

	err = mdb_txn_begin(rd->mdcache_env, NULL, MDB_RDONLY, &txn);
	if (err) {
		log_error(lg, "Dev(%s): mdcache mdb_txn_begin: (%d) %s, env_path %s",
			dev->name, err, mdb_strerror(err), env_path);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'o',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);
		return err;
	}

	err = mdb_get_attr(txn, rd->keys_dbi[ttag], &key, NULL, attrp);
	if (err) {
		if (err != MDB_NOTFOUND) {
			log_error(lg, "Get(%s): cannot get attr from "
			    "keys: (%d) %s, env_path %s", dev->name, err,
			    mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		}
	}

	mdb_txn_abort(txn);
	return err;
}

static int
rd_key_insert(struct repdev *dev, type_tag_t ttag, MDB_txn *ext_txn, uint64_t *kh,
    size_t blob_len, uint64_t attr)
{
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn *txn;

	if (!rd->mdcache)
		return 0;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	assert(blob_len);

	if (rd->mdcache_enable) {
		err = mdcache_adjust(rd->mdcache, TT_CHUNK_MANIFEST, ext_txn);
		if (err)
			return err;

		err = mdcache_adjust(rd->mdcache, TT_VERSION_MANIFEST, ext_txn);
		if (err)
			return err;
	}

	if (!ext_txn) {
		err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
		if (err) {
			log_error(lg, "Dev(%s): mdb_txn_begin: (%d) %s, env_path %s",
				dev->name, err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
			return err;
		}
	} else
		txn = ext_txn;

	MDB_val key, data;
	msgpack_p p;
	char data_len[16];
	uv_buf_t buf = { .len = 16, .base = &data_len[0] };
	msgpack_pack_init_p(&p, buf);

	err = msgpack_pack_uint64(&p, blob_len);
	if (err) {
		if (!ext_txn)
			mdb_txn_abort(txn);
		err = -ENOMEM;
		return err;
	}
	uv_buf_t packed;
	msgpack_get_buffer(&p, &packed);

	key.mv_size = sizeof (uint64_t);
	key.mv_data = kh;
	data.mv_size = packed.len;
	data.mv_data = packed.base;
	/* will overwrite if exists */
	err = mdb_put_attr(txn, rd->keys_dbi[ttag], &key, &data, attr, 0);
	if (err) {
		if (!ext_txn)
			mdb_txn_abort(txn);
		log_error(lg, "Dev(%s): mdcache mdb_put: (%d) %s, env_path %s", dev->name,
		    err, mdb_strerror(err), env_path);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'o',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);
		return err;
	}

	if (!ext_txn) {
		err = mdb_txn_commit(txn);
		if (err) {
			log_warn(lg, "Dev(%s): mdcache mdb_txn_commit: (%d) %s, env_path %s",
				dev->name, err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		}
	}

	return err;
}

static int
rd_key_set_attr(struct repdev *dev, type_tag_t ttag, MDB_txn *ext_txn, uint64_t *kh,
    uint64_t attr)
{
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn *txn;

	if (!rd->mdcache)
		return 0;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	if (!ext_txn) {
		err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
		if (err) {
			log_error(lg, "Dev(%s): mdcache mdb_txn_begin: (%d) %s, env_path %s",
				dev->name, err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
			return err;
		}
	} else
		txn = ext_txn;

	MDB_val key;

	key.mv_size = sizeof (uint64_t);
	key.mv_data = kh;
	err = mdb_set_attr(txn, rd->keys_dbi[ttag], &key, NULL, attr);
	if (err) {
		if (!ext_txn)
			mdb_txn_abort(txn);
		if (err == MDB_KEYEXIST) {
			log_debug(lg, "Dev(%s): %s mdb_set_attr: (%d) %s, ignored",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
			err = 0;
		} else if (err == MDB_NOTFOUND) {
			log_warn(lg, "Dev(%s): %s mdb_set_attr: (%d) %s, ignored",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
			err = 0;
		} else {
			log_error(lg, "Dev(%s): %s mdcache mdb_set_attr: (%d) %s, env_path %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		}
		return err;
	}

	if (!ext_txn) {
		err = mdb_txn_commit(txn);
		if (err) {
			log_warn(lg, "Dev(%s): mdcache mdb_txn_commit: (%d) %s, env_path %s",
				dev->name, err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		}
	}

	return err;
}

static int
rd_key_remove(struct repdev *dev, type_tag_t ttag, MDB_txn *ext_txn, uint64_t *kh_del)
{
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn* txn = ext_txn;

	if (!rd->mdcache)
		return 0;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	if (!txn) {
		err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
		if (err) {
			log_error(lg, "Dev(%s): mdcache mdb_txn_begin: (%d) %s, env_path %s",
				dev->name, err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
			return err;
		}
	}

	MDB_val delkey = { .mv_size = sizeof (uint64_t), .mv_data = kh_del };

	err = mdb_del(txn, rd->keys_dbi[ttag], &delkey, NULL);
	if (err) {
		if (!ext_txn)
			mdb_txn_abort(txn);
		if (err == MDB_NOTFOUND) {
			log_debug(lg, "Dev(%s): %s mdb_del: (%d) %s, ignored",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
			err = 0;
		} else {
			log_error(lg, "Dev(%s): %s mdcache mdb_del: (%d) %s, env_path %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		}
		return err;
	}

	if (!ext_txn) {
		err = mdb_txn_commit(txn);
		if (err) {
			log_warn(lg, "Dev(%s): mdcache mdb_txn_commit: (%d) %s, env_path %s",
				dev->name, err, mdb_strerror(err), env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		}
	}

	return err;
}

static int
rd_mdoffload_drop(struct repdev *dev) {
	struct repdev_rd *rd = dev->device_lfs;
	int err = 0;

	if (!rd->mdcache_env)
		return 0;

	for (type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (!is_mdoffload_tt(dev, ttag))
			continue;
		if (!rd->mdoffload_dbi[ttag])
			continue;
		MDB_txn* txn = NULL;
		err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
		if (err) {
			log_error(lg, "Dev(%s) mdb_txn_begin: (%d) %s", dev->name,
				err, mdb_strerror(err));
			return err;
		}
		err = mdb_drop(txn, rd->mdoffload_dbi[ttag], 0);
		if (err) {
			log_error(lg, "Dev(%s) mdb_drop: (%d) %s", dev->name,
				err, mdb_strerror(err));
		}
		if (err) {
			mdb_txn_abort(txn);
			break;
		} else {
			err = mdb_txn_commit(txn);
			if (err) {
				log_error(lg, "Dev(%s) mdb_txn_commit: (%d) %s", dev->name,
					err, mdb_strerror(err));
				break;
			}
		}
	}
	return err;
}

static int
rd_mdoffload_cleanup(struct repdev *dev, const char* jkname, int plevel) {
	struct repdev_rd *rd = dev->device_lfs;
	int err = 0;
	size_t n_keys_deleted = 0;
	MDB_txn* txn = NULL;
	type_tag_t ttags[] = {
		TT_NAMEINDEX,TT_VERIFIED_BACKREF,TT_TRANSACTION_LOG,
		TT_BATCH_QUEUE,TT_VERIFICATION_QUEUE,TT_BATCH_INCOMING_QUEUE,
		TT_REPLICATION_QUEUE,TT_CHUNK_MANIFEST, TT_ENCODING_QUEUE,
		TT_PARITY_MANIFEST
	};

	if (!rd->mdcache_env)
		return 0;
	/**
	 * mdoffload cleanup code. Need to be run when a plevel has been formated.
	 * We need to find and remove entries which correspond to the plevel.
	 */

	err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s) mdb_txn_begin: (%d) %s", dev->name,
			err, mdb_strerror(err));
		return err;
	}

	for (size_t ti = 0; ti < sizeof(ttags)/sizeof(ttags[0]); ti++) {
		type_tag_t ttag = ttags[ti];
		if (!is_mdoffload_tt(dev, ttag))
			continue;
		if (!rd->mdoffload_dbi[ttag])
			continue;

		MDB_cursor* cur = NULL;
		err = mdb_cursor_open(txn, rd->mdoffload_dbi[ttag], &cur);
		if (err) {
			log_error(lg, "Dev(%s): mdb_cursor_open: (%d) %s",
				dev->name, err, mdb_strerror(err));
			goto _exit;
		}
		int op = MDB_FIRST;
		MDB_val key, data, vmkey;
		while ((err = mdb_cursor_get(cur, &key, &data, op)) == 0) {
			op = MDB_NEXT;
			type_tag_t lttag;
			crypto_hash_t ht;
			uint512_t chid;
			err = reptrans_key_decode(dev, key.mv_data, key.mv_size,
				&lttag, &ht, &chid);
			if (err) {
				log_error(lg, "Key decode error %d", err);
				goto _cont;
			}
			int plevel_calc = PLEVEL_HASHCALC(&chid, rd->plevel - 1);
			if (plevel == plevel_calc) {
				if (ttag == TT_NAMEINDEX) {
					struct vlentry vle;
					msgpack_u u;
					/* if we removed the nameindex, the we
					 * shall remove also corresponding VM.
					 */
					msgpack_unpack_init_b(&u, data.mv_data, data.mv_size, 0);

					err = replicast_unpack_vlentry(&u, &vle);
					if (err) {
						log_error(lg, "Dev(%s) cannot unpack version entry for nhid %lX: %d",
							dev->name, chid.u.u.u, err);
						err = 0;
						goto _cont;;
					}
					msgpack_p *pkey = NULL;
					err = reptrans_key_encode(dev, TT_VERSION_MANIFEST, HASH_TYPE_DEFAULT,
						&vle.content_hash_id, &pkey);
					assert(!err);
					uv_buf_t keybuf;
					msgpack_get_buffer(pkey, &keybuf);
					vmkey.mv_size = keybuf.len;
					vmkey.mv_data = keybuf.base;

					err = mdb_del(txn, rd->mdoffload_dbi[TT_VERSION_MANIFEST], &vmkey, NULL);
					if (err) {
						log_error(lg, "Error deleting version manifest: %d", err);
					}
					log_info(lg, "Dev(%s) removed VM %lX for nameindex %lX plevel %d",
						dev->name, vle.content_hash_id.u.u.u, chid.u.u.u, plevel+1);

					/* VM could have parity manifest */
					if (rd->mdoffload_dbi[TT_PARITY_MANIFEST]) {
						err = mdb_del(txn, rd->mdoffload_dbi[TT_PARITY_MANIFEST], &vmkey, NULL);
						if (err && (err != MDB_NOTFOUND)) {
							log_error(lg, "Error deleting parity manifest");
						}
					}
					msgpack_pack_free(pkey);
				} else if (ttag == TT_VERSION_MANIFEST) {
					/* Remove also a nameindex entry */
					struct vmmetadata md;
					struct vlentry vle;
					uv_buf_t ub = {.base = data.mv_data, .len = data.mv_size };
					rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
					assert(rb);
					int err = replicast_get_metadata(rb, &md);
					if (err) {
						log_error(lg, "Dev(%s) cannot unpack VM %lX: %d",
							dev->name, chid.u.u.u, err);
						err = 0;
						goto _cont;;
					}
					rtbuf_destroy(rb);
					vle.uvid_timestamp = md.uvid_timestamp;
					vle.uvid_src_guid = md.uvid_src_guid;
					vle.uvid_src_cookie = md.uvid_src_cookie;
					vle.generation = md.txid_generation;
					vle.content_hash_id = chid;
					vle.object_deleted = md.object_deleted;
					vle.logical_size = md.logical_size;
					vle.vm_packed_length = data.mv_size;;
					err = reptrans_delete_version_entry(dev,
					    HASH_TYPE_DEFAULT, &md.nhid, &vle);
					if (err && err != -ENOENT) {
						log_error(lg, "Dev(%s) version delete error %d "
							"NHID %lX GEN %lu", dev->name, err,
							md.nhid.u.u.u, md.txid_generation);
					} else if (!err) {
						log_info(lg, "Dev(%s) removed nameindex %lX for VM %lX plevel %d",
							dev->name, md.nhid.u.u.u, chid.u.u.u, plevel+1);
					}
				}
_cont:
				/* This entry matches plevel, remove it */
				err = mdb_cursor_del(cur, 0);
				if (err) {
					log_error(lg, "Dev(%s): mdb_cursor_del: (%d) %s",
						dev->name, err, mdb_strerror(err));
					break;
				}
				log_info(lg, "Dev(%s) removed %s %lX for plevel %d",
					dev->name, type_tag_name[ttag], chid.u.u.u, plevel+1);

				n_keys_deleted++;
			}
		}
		if (err == MDB_NOTFOUND)
			err = 0;
		mdb_cursor_close(cur);
	}

_exit:
	if (txn) {
		if (err)
			mdb_txn_abort(txn);
		else {
			err = mdb_txn_commit(txn);
			if (err) {
				log_error(lg, "Dev(%s) mdoffload commit error: %s (%d)",
					dev->name, mdb_strerror(err), err);
			} else
				log_notice(lg, "Dev(%s) mdoffload changes have been stored, %lu keys have been removed",
					dev->name, n_keys_deleted);
		}
	}
	return err;
}

static int
rd_rebuild_mdcache(struct repdev* dev) {
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn* txn = NULL;
	MDB_val key, data;
	size_t n_keys_inserted = 0;
	size_t n_mdcache_inserted = 0;
	size_t n_keys_deleted = 0;
	size_t n_mdcache_deleted = 0;

	type_tag_t ttags[] = { TT_CHUNK_PAYLOAD, TT_CHUNK_MANIFEST, TT_VERSION_MANIFEST };

	if (!rd->mdcache)
		return 0;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): mdcache mdb_txn_begin: (%d) %s, env_path %s",
			dev->name, err, mdb_strerror(err), env_path);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'o',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);
		return err;
	}
	for (size_t i = 0; i < sizeof(ttags)/sizeof(ttags[0]); i++) {
		type_tag_t ttag = ttags[i];
		MDB_cursor* cur = NULL;
		/* Empty the keys */
		if (is_keycache_tt(ttag)) {
			err = mdb_cursor_open(txn, rd->keys_dbi[ttag], &cur);
			if (err) {
				log_error(lg, "Dev(%s): mdcache mdb_cursor_open: (%d) %s, env_path %s",
					dev->name, err, mdb_strerror(err), env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};
				rd_dev_faulted(dev, &fs);
				goto _exit;
			}
			int op = MDB_FIRST;
			while ((err = mdb_cursor_get(cur, &key, &data, op)) == 0) {
				op = MDB_NEXT;
				err = mdb_cursor_del(cur, 0);
				if (err) {
					log_error(lg, "Dev(%s): mdb_cursor_del: (%d) %s, env_path %s",
						dev->name, err, mdb_strerror(err), env_path);
					struct rd_fault_signature fs = {
						.error = err,
						.source = 'o',
						.plevel = 0
					};
					rd_dev_faulted(dev, &fs);
					break;
				}
				n_keys_deleted++;
			}
			mdb_cursor_close(cur);
			if (err && err != MDB_NOTFOUND)
				goto _exit;
			err = 0;
		}
		/* Empty the mdcache */
		if (is_mdcache_tt(dev, ttag) && rd->mdcache_dbi[ttag] && rd->mdcache_enable) {
			cur = NULL;
			err = mdb_cursor_open(txn, rd->mdcache_dbi[ttag], &cur);
			if (err) {
				log_error(lg, "Dev(%s): mdcache mdb_cursor_open: (%d) %s, env_path %s",
					dev->name, err, mdb_strerror(err), env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'o',
					.plevel = 0
				};
				rd_dev_faulted(dev, &fs);
				goto _exit;
			}
			int op = MDB_FIRST;
			while ((err = mdb_cursor_get(cur, &key, &data, op)) == 0) {
				op = MDB_NEXT;
				uint64_t kh;
				assert(key.mv_size == sizeof(kh));
				memcpy(&kh, key.mv_data, sizeof(kh));
				err = mdcache_remove(rd->mdcache, ttag, txn, &kh);
				if (err) {
					log_error(lg, "Dev(%s): mdcache_remove: (%d)",
						dev->name, err);
					break;
				}
				n_mdcache_deleted++;
			}
			mdb_cursor_close(cur);
			if (err && err != MDB_NOTFOUND)
				goto _exit;
			err = 0;
		}
		/* Iterate main DB and fill up the keys/mdcache */
		for (int j = 0; j < rd->plevel; ++j) {
			struct repdev_db* db = rd->db + j;
			for (int i = 0; i < DEV_SHARDS_MAX; i++) {
				MDB_dbi dbi = DEV_SHARD(db, ttag, i);
				MDB_txn* main_txn = NULL;
				MDB_cursor* cur = NULL;
				err = mdb_txn_begin(DEV_ENV(db, ttag), NULL, MDB_RDONLY, &main_txn);
				if (err) {
					log_error(lg, "Dev(%s): cannot begin txn bloom_load: (%d) %s, env_path %s",
					    dev->name, err, mdb_strerror(err), env_path);
					struct rd_fault_signature fs = {
						.error = err,
						.source = 'o',
						.plevel = 0
					};
					rd_dev_faulted(dev, &fs);
					goto _exit;
				}

				err = mdb_cursor_open(main_txn, dbi, &cur);
				if (err) {
					log_error(lg, "Dev(%s): cannot open cursor bloom_load: (%d) %s, env_path %s",
					    dev->name, err, mdb_strerror(err), env_path);
					struct rd_fault_signature fs = {
						.error = err,
						.source = 'o',
						.plevel = 0
					};
					rd_dev_faulted(dev, &fs);
					goto _exit;
				}

				int op = MDB_FIRST;
				uint64_t attr = 0;
				while ((err = mdb_cursor_get(cur, &key, &data, op)) == 0) {
					op = MDB_NEXT;
					MDB_val keyhv;
					uint64_t kh;

					err = mdb_cursor_get_attr(cur, &key, &data,
						&attr);
					if (err) {
						log_error(lg, "Dev(%s): mdb_cursor_get_attr: (%d) %s, env_path %s",
						    dev->name, err, mdb_strerror(err), env_path);
						struct rd_fault_signature fs = {
							.error = err,
							.source = 'o',
							.plevel = 0
						};
						rd_dev_faulted(dev, &fs);
						break;
					}
					err = rd_keyhash(dev, &key, &keyhv, &kh);
					if (err) {
						log_error(lg, "Dev(%s) lfs_keyhash error %d",
							dev->name, err);
						break;
					}
					if (is_keycache_tt(ttag)) {
						err = rd_key_insert(dev, ttag,
							txn, &kh, data.mv_size, attr);
						if (err) {
							log_error(lg, "Dev(%s) "
								"rd_key_insert error %d",
								dev->name, err);
							break;
						}
						n_keys_inserted++;
					}
					if (is_mdcache_tt(dev, ttag) && rd->mdcache_enable) {
						err = mdcache_insert(rd->mdcache,
							ttag, txn, &kh, data.mv_data,
							data.mv_size);
						if (err) {
							log_error(lg, "Dev(%s) "
								"mdcache_insert error %d",
								dev->name, err);
							break;
						}
						n_mdcache_inserted++;
					}
				}
				if (cur)
					mdb_cursor_close(cur);
				if (main_txn)
					mdb_txn_abort(main_txn);
				if (err && err != MDB_NOTFOUND)
					goto _exit;
				err = 0;
			}
		}
	}

_exit:
	if (err)
		mdb_txn_abort(txn);
	else {
		err = mdb_txn_commit(txn);
		if (err) {
			log_error(lg, "Dev(%s) mdcache mdb_txn_commit %d, env_path %s",
				dev->name, err, env_path);
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'o',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
		} else
			log_notice(lg, "Dev(%s) %lu/%lu keys and "
			"%lu/%lu mdcache entries removed/inserted",
			dev->name, n_keys_deleted, n_keys_inserted,
			n_mdcache_deleted, n_mdcache_inserted);

	}
	return err;
}

static int
rd_update_version(struct repdev *dev);

static int
rd_mdoffload_migrate(struct repdev* dev, type_tag_t ttag) {
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn* txn_offload = NULL;
	MDB_txn* txn_main[RT_RD_PLEVEL_MAX] = {NULL};
	MDB_cursor* offload_cur = NULL;
	size_t n_moved = 0, n_parity_moved = 0;

	if (!dev->journal || !is_mdoffload_tt(dev, ttag))
		return -EINVAL;

	if (ttag != TT_CHUNK_MANIFEST && ttag != TT_VERSION_MANIFEST && ttag != TT_PARITY_MANIFEST) {
		log_error(lg, "Dev(%s) relocation of ttag %s isn't supported",
			dev->name, type_tag_name[ttag]);
		return -EINVAL;
	}
	log_notice(lg, "Dev(%s) mdoffload migration procedure for ttag %s has been started",
		dev->name, type_tag_name[ttag]);


	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	int err = mdb_txn_begin(rd->mdcache_env, NULL, MDB_RDONLY, &txn_offload);
	if (err) {
		log_error(lg, "Dev(%s) mdcache mdb_txn_begin: %s (%d), env_path %s",
			dev->name, mdb_strerror(err), err, env_path);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'o',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);
		goto _exit;
	}

	err = mdb_cursor_open(txn_offload, rd->mdoffload_dbi[ttag], &offload_cur);
	if (err) {
		log_error(lg, "Dev(%s): mdcache mdb_cursor_open: (%d) %s, env_path %s",
			dev->name, err, mdb_strerror(err), env_path);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'o',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);
		goto _exit;
	}
	int op = MDB_FIRST;
	MDB_val key, data, pdata;
	size_t n_puts = 0;
	while ((err = mdb_cursor_get(offload_cur, &key, &data, op)) == 0) {
		/* get shard location */
		uint512_t chid;
		uint64_t attr = 0, pattr = 0;
		crypto_hash_t key_hash_type;
		type_tag_t key_ttag;

		op = MDB_NEXT;
		err = mdb_get_attr(txn_offload, rd->mdoffload_dbi[ttag],
			&key, &data, &attr);
		if (err) {
			log_error(lg, "Dev(%s) cannot get an attribute: %s (%d)",
				dev->name, mdb_strerror(err), err);
			attr = n_moved + 1;
		}
		err = reptrans_key_decode(dev, key.mv_data, key.mv_size,
		    &key_ttag, &key_hash_type, &chid);
		if (err || key_ttag != ttag) {
			log_error(lg, "rd_mdoffload_migrate key decode failed %d, "
				"key_ttag %d, ttag %d(%s)", err, key_ttag,
				ttag, type_tag_name[ttag]);
			err = -EIO;
			goto _exit;
		}
		int plevel = PLEVEL_HASHCALC(&chid, (rd->plevel - 1));
		struct repdev_db* db = rd->db + plevel;
		if (!txn_main[plevel]) {
			err = mdb_txn_begin(db->env[0], NULL, 0, &txn_main[plevel]);
			if (err) {
				log_error(lg, "Dev(%s) main mdb_txn_begin: %s (%d)",
					dev->name, mdb_strerror(err), err);
				goto _exit;
			}
			if (!db->shards[ttag]) {
				char dbi_name[PATH_MAX];
				snprintf(dbi_name, PATH_MAX, "%s-part%d-%s-%d",
				    rd->metaloc.version == 1 ? dev->name : "bd",
				    db->part + 1, type_tag_name[ttag], 0);
				/* Open main table for */
				err = mdb_dbi_open(txn_main[plevel], dbi_name, MDB_CREATE,
					db->shards + ttag);
				if (err) {
					mdb_txn_abort(txn_main[plevel]);
					log_error(lg, "Dev(%s): cannot open mdb: %s (%d) %s",
					    dev->name, dbi_name, err, mdb_strerror(err));
					err = -EIO;
					goto _exit;
				}
			}
		}
		assert(txn_main[plevel]);
		err = mdb_put_attr(txn_main[plevel], db->shards[ttag], &key,
			&data, attr, 0);
		if (err) {
			log_error(lg, "Dev(%s) main table mdb_put: %s (%d)",
				dev->name, mdb_strerror(err), err);
			goto _exit;
		}
		n_moved++;
		/* Prefer small commits */
		if (++n_puts >= 1000) {
			for (int i = 0; i < RT_RD_PLEVEL_MAX; i++) {
				if (txn_main[i]) {
					struct repdev_db* db = rd->db + i;
					err = mdb_txn_commit(txn_main[i]);
					txn_main[i] = NULL;
					if (err) {
						log_error(lg, "Dev(%s) maindb mdb_txn_commit: %s (%d)",
							dev->name, mdb_strerror(err), err);
						goto _exit;
					}
					err = mdb_txn_begin(db->env[0], NULL, 0, &txn_main[i]);
					if (err) {
						log_error(lg, "Dev(%s) main mdb_txn_begin: %s (%d)",
							dev->name, mdb_strerror(err), err);
						goto _exit;
					}
				}
			}
			n_puts = 0;
		}
	}
	mdb_txn_abort(txn_offload);
	txn_offload = NULL;

	/* Commiting changes to the main DB */
	for (int i = 0; i < RT_RD_PLEVEL_MAX; i++) {
		if (txn_main[i]) {
			struct repdev_db* db = rd->db + i;
			err = mdb_txn_commit(txn_main[i]);
			txn_main[i] = NULL;
			if (err) {
				log_error(lg, "Dev(%s) maindb mdb_txn_commit: %s (%d)",
					dev->name, mdb_strerror(err), err);
				goto _exit;
			}
		}
	}
	/* update HDD's metarecord */
	int mm = dev->metadata_mask;
	switch (ttag) {
		case TT_CHUNK_MANIFEST:
			dev->metadata_mask &= ~DEV_METADATA_CM;
			break;
		case TT_VERSION_MANIFEST:
			dev->metadata_mask &= ~DEV_METADATA_VM;
			break;
		case TT_PARITY_MANIFEST:
			dev->metadata_mask &= ~DEV_METADATA_PM;
			break;
		default:
			assert(0);
			break;
	}
	rd->metaloc.metamask = dev->metadata_mask;
	err = rd_update_version(dev);
	if (err) {
		log_error(lg, "Dev(%s) metarecord change error %d", dev->name,
			err);
		goto _exit;
	}
	/* Drop the mdoffload table*/
	err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &txn_offload);
	if (err) {
		log_error(lg, "Dev(%s) mdcache mdb_txn_begin: %s (%d)",
			dev->name, mdb_strerror(err), err);
		goto _exit;
	}
	err = mdb_drop(txn_offload, rd->mdoffload_dbi[ttag], 1);
	if (err) {
		log_error(lg, "Dev(%s) mdoffload dbi drop: %s (%d)", dev->name,
			mdb_strerror(err), err);
		goto _exit;
	}
	err = mdb_txn_commit(txn_offload);
	if (err) {
		log_error(lg, "Dev(%s) mdoffload dbi drop commit: %s (%d)",
			dev->name, mdb_strerror(err), err);
	} else {
		log_notice(lg, "Dev(%s) mdoffload migration finished, "
			"moved %lu manifests and %lu parity manifests", dev->name,
			n_moved, n_parity_moved);
	}
	txn_offload = NULL;

_exit:
	if (txn_offload)
		mdb_txn_abort(txn_offload);
	for (int i = 0; i < RT_RD_PLEVEL_MAX; i++) {
		if (txn_main[i]) {
			struct repdev_db* db = rd->db + i;
			mdb_txn_abort(txn_main[i]);
			mdb_dbi_close(db->env[0], db->shards[ttag]);
		}
	}
	return err;

}

static int
rd_validate_rdkeys(struct repdev* dev) {
	struct repdev_rd *rd = dev->device_lfs;
	MDB_txn* rdkey_txn = NULL;
	MDB_txn* my_txn = NULL;
	MDB_cursor* cur = NULL;
	size_t n_verified  = 0, n_missed = 0, n_wrong_size = 0;

	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	int err = mdb_txn_begin(rd->mdcache_env, NULL, MDB_RDONLY, &rdkey_txn);
	if (err) {
		log_error(lg, "Dev(%s) mdenv txn_begin error %d env_path %s",
			dev->name, err, env_path);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'o',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);
		return err;
	}
	/* the rdkeys tables has a metainfo about several chunk types stored on HDD.
	 * We want to validate that both are consistent
	 */
	for (type_tag_t ttag = TT_NAMEINDEX; ttag < TT_LAST; ttag++) {
		if (!is_keycache_tt(ttag))
			continue;
		for (int i = 0; i < rd->plevel; i++) {
			struct repdev_db* db = rd->db + i;
			err = mdb_txn_begin(DEV_ENV(db, ttag), NULL, MDB_RDONLY, &my_txn);
			if (err) {
				log_error(lg, "Dev(%s) main txn_begin error %d env_path %s",
					dev->name, err, env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				goto _exit;
			}
			err = mdb_cursor_open(my_txn, DEV_SHARD(db, ttag, 0), &cur);
			if (err) {
				log_error(lg, "Dev(%s) main cursor open error %s: %d env_path %s",
					dev->name, type_tag_name[ttag], err, env_path);
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				goto _exit;
			}

			int op = MDB_FIRST;
			MDB_val key, data, pdata;
			size_t n_puts = 0;
			/*
			 *  For each key stored in rdkeys we need to be sure the HDD (mdoffload)
			 * has a chunk with the same key and value size.
			 */
			while ((err = mdb_cursor_get(cur, &key, &data, op)) == 0) {
				/* get shard location */
				uint512_t chid;
				uint64_t attr = 0, pattr = 0;
				crypto_hash_t key_hash_type;
				type_tag_t key_ttag;
				op = MDB_NEXT;

				n_verified++;
				err = reptrans_key_decode(dev, key.mv_data, key.mv_size,
				    &key_ttag, &key_hash_type, &chid);
				if (err || key_ttag != ttag) {
					log_error(lg, "rd_validate_rdkeys key decode failed %d, "
						"key_ttag %d, ttag %d(%s)", err, key_ttag,
						ttag, type_tag_name[ttag]);
					err = -EIO;
					goto _exit;
				}

				MDB_val keyhv;
				uint64_t kh;
				err = rd_keyhash(dev, &key, &keyhv, &kh);
				assert(!err);
				err = mdb_get(rdkey_txn, rd->keys_dbi[ttag], &keyhv, &pdata);
				if (err) {
					log_error(lg, "Dev(%s) chunk %lX %s absent in rdkeys: %d (%s)",
						dev->name, chid.u.u.u, type_tag_name[ttag], err, mdb_strerror(err));
					n_missed++;
					continue;
				}
				/* Validate value size */
				msgpack_u u;
				uint64_t len = 0;
				msgpack_unpack_init_b(&u, pdata.mv_data, pdata.mv_size, 0);
				err = msgpack_unpack_uint64(&u, &len);
				if (err) {
					log_error(lg, "Dev(%s) rdkey's value unpack error: %d", dev->name, err);
					continue;
				}
				if (len != data.mv_size) {
					log_error(lg, "Dev(%s) value size mismatch %lX %s: %lu vs %lu",
						dev->name, chid.u.u.u, type_tag_name[ttag], len, pdata.mv_size);
					n_wrong_size++;
				}
			}
			if (err && err != MDB_NOTFOUND) {
				log_error(lg, "Dev(%s) mdb_cursor_get error %d", dev->name, err);
				goto _exit;
			}
			err = 0;
			mdb_txn_abort(my_txn);
			my_txn = NULL;
		}
	}
_exit:
	if (rdkey_txn)
		mdb_txn_abort(rdkey_txn);
	if (my_txn)
		mdb_txn_abort(my_txn);
	if (!err) {
		log_notice(lg, "Dev(%s) verified %lu rdkeys, %lu (%lu%%) missed, "
			"%lu (%lu%%) size mismatch", dev->name, n_verified,
			n_missed, n_verified ? n_missed*100/n_verified : 0, n_wrong_size,
			n_verified ? n_wrong_size*100/n_verified : 0);
	}
	return err;
}

static int
rd_rebuild_mdcache_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta) {
	return rd_rebuild_mdcache(dev);
}

static int
rd_mdoffload_migrate_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta) {
	char ttag_string[256] = {0};
	int rc = sscanf(meta->maintenance_cmd[cmd_index], CMD_MDOFFLOAD_MIGRATE_SIGNATURE"%s", ttag_string);

	type_tag_t ttag = TT_LAST;
	for (int i =0; i < TT_LAST; i++)
		if (strcmp(ttag_string, type_tag_name[i]) == 0) {
			ttag = i;
			break;
		}
	if (ttag != TT_CHUNK_MANIFEST && ttag != TT_VERSION_MANIFEST && ttag != TT_PARITY_MANIFEST) {
		log_error(lg, "Maintenance: unsupported migration ttag %s", ttag_string);
		return -ENOTTY;
	}
	return rd_mdoffload_migrate(dev, ttag);
}

static int
rd_drop_outdated_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta) {
	int plevel_id = 0;
	assert(dev);
	int rc = sscanf(meta->maintenance_cmd[cmd_index], CMD_DROP_OUTDATED_SIGNATURE"%d", &plevel_id);
	if (rc <= 0) {
		log_error(lg, "A malformed maintenance command %s", meta->maintenance_cmd[cmd_index]);
		return -ENOTTY;
	}

	if (!strlen(meta->journal)) {
		log_error(lg, "The device %s doesn't have a journal SSD attached."
			" It seems the maintenance command was add by mistake,"
			" reseting maintenance mode", meta->device);
		return -ENOTTY;
	}

	if (plevel_id < 0 || plevel_id > meta->plevel) {
		log_error(lg, "The maintenance command error: specified plevel "
			"%d is out of range 1..%d", plevel_id, meta->plevel);
		return -ENOTTY;
	}
		/* An HDD is replaced/new, rebuild mdcache, drop mdoffload */
	int err = rd_mdoffload_cleanup(dev, dev->path, plevel_id - 1);
	if (err) {
		log_error(lg, "Dev(%s) rd_mdoffload_cleanup error: %d", dev->name,
			err);
	} else {
		err = rd_rebuild_mdcache(dev);
		if (!err)
			log_notice(lg, "Dev(%s) mdcache for part"
				"has been re-created", dev->name);
	}
	return err;
}

static int
rd_validate_rdkeys_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta) {
	/* Do nothing, just check and continue */
	int err = rd_validate_rdkeys(dev);
	return 0;
}

static int
rd_disk_replace_handler(struct repdev* dev, int cmd_index, const struct rd_metaloc* meta) {
	assert(dev);
	struct repdev_rd* rd = dev->device_lfs;
	rd->metaloc.state = rdstateOk;
	rd->metaloc.timestamp = time(NULL);
	rd->metaloc.oldname[0] = 0;
	rd->metaloc.maintenance_cmd[cmd_index][0] = 0;
	return rd_update_version(dev);
}

static int
rd_lmdb_init(struct repdev *dev, struct repdev_rd *rd, struct repdev_db *db,
    char *dbpath, type_tag_t ttag, uint64_t part_size, uint32_t rt_flags,
	char * kdevname)
{
	int err = 0;
	struct stat st;
	char fname[PATH_MAX];
	MDB_txn *txn;

	/* skip type tags which needs to be offloaded to MD */
	if (dev->journal && is_mdoffload_tt(dev, ttag))
		return 0;

	if (!DEV_ENV(db, ttag)) {
		/*
		 * Main key/value data store
		 */
		err = mdb_env_create(&DEV_ENV(db, ttag));
		if (err) {
			log_error(lg, "Dev(%s): cannot create ttag=%d mdb env: (%d) %s",
			    dev->name, ttag, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}

		if (dev->journal || rd->metaloc.psize) {
			/* only set psize for main tables */
			mdb_env_set_psize(DEV_ENV(db, ttag), rd->metaloc.psize);
		}

		mdb_env_set_mapsize(DEV_ENV(db, ttag), part_size);
#ifdef CCOW_VALGRIND
		if (RUNNING_ON_VALGRIND) {
			int mb = ttag == TT_CHUNK_PAYLOAD ? 256 : 64;
			mdb_env_set_mapsize(DEV_ENV(db, ttag), 1ULL * mb * 1024 * 1024);
		}
#endif
		mdb_env_set_maxreaders(DEV_ENV(db, ttag), DEV_LMDB_MAXREADERS);

		err = mdb_env_set_maxdbs(DEV_ENV(db, ttag), TT_LAST * DEV_SHARDS_MAX);
		if (err) {
			log_error(lg, "Dev(%s): cannot set maxdbs: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}

		mdb_env_set_oomfunc(DEV_ENV(db, ttag), rd_lmdb_oomfunc);

		int sync_flag = rd->sync == 0 ? MDB_NOSYNC :
			(rd->sync == 1 ? (rd->direct ? MDB_NOSYNC : MDB_NOMETASYNC) :
			 (rd->sync == 2 ? MDB_NOMETASYNC : 0));
		int rdahead_flag = rd->readahead ? 0 : MDB_NORDAHEAD;
		int direct_flag = rd->direct ? MDB_DIRECT : 0;
		int writemap_flag = rd->writemap ? MDB_WRITEMAP : 0;
		unsigned int env_opt = MDB_COALESCE | MDB_LIFORECLAIM | MDB_RAW | MDB_NOTLS | sync_flag \
			      | MDB_NOSUBDIR | rdahead_flag | direct_flag |
			      MDB_PAGECAPCHECK | writemap_flag;
		if (rt_flags & RT_FLAG_RDONLY)
			env_opt |= MDB_RDONLY;
		else {
			sprintf(fname, "rm -f %s-lock", dbpath);
			err = system(fname);
		}
#ifdef CCOW_VALGRIND
		if (RUNNING_ON_VALGRIND) {
			env_opt &= ~MDB_NOMEMINIT;
		}
#endif

		int retry_cnt = 0;
_retry_open:
		/* partition may not appear immediately here, wait for a little bit */
		snprintf(fname, PATH_MAX, "head -c 1k %s >/dev/null 2>/dev/null", dbpath);
		for (int i = 0; i < 30; i++) {
			err = system(fname);
			if (!err) {
				break;
			}
			usleep(1000000);
		}
		if (err) {
			log_error(lg, "Dev(%s): partition %s not accessible",
			    dev->name, dbpath);
			err = -EIO;
			goto _exit;
		}

		if (!(rt_flags & RT_FLAG_RDONLY) && (rd->metaloc.version == 0)) {
			err = rd_format_lmdb_part(dbpath);
			if (err) {
				log_error(lg, "Dev(%s): cannot open, dbpath=%s "
					, dev->name, dbpath);
				err = -EIO;
				goto _exit;
			}
			log_notice(lg, "Dev(%s) cleaned partition %s", dev->name, dbpath);
		}

		log_notice(lg, "Dev(%s) plevel %d opening main env using part %s mapsize=%ld",
			dev->name, db->part, dbpath, part_size);

		err = mdb_env_open(DEV_ENV(db, ttag), dbpath, env_opt, 0664);
		if (err) {
			if ((err == ENOENT || err == EINVAL) && retry_cnt++ < 10) {
				if (retry_cnt == 9) {
					snprintf(fname, PATH_MAX, "partprobe %s >/dev/null 2>/dev/null", kdevname);
					err = system(fname);
				}
				usleep(1000000);
				goto _retry_open;
			}
			log_error(lg, "Dev(%s): cannot open, dbpath=%s "
			    "mdb env: (%d) %s", dev->name, dbpath, err,
			    mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}
	}

	/*
	 * Initialize/Open main data store now
	 */
	int flags = 0;
	if (!(rt_flags & RT_FLAG_RDONLY) && (rt_flags & RT_FLAG_CREATE))
		flags = MDB_CREATE;

	if (is_dupsort_tt(ttag))
		flags |= MDB_DUPSORT;

	err = mdb_txn_begin(DEV_ENV(db, ttag), NULL,
			rt_flags & RT_FLAG_RDONLY ? MDB_RDONLY : 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot begin mdb txn: (%d) %s",
		    dev->name, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	for (int i = 0; i < DEV_SHARDS_MAX; i++) {
		char dbi_name[PATH_MAX];
		snprintf(dbi_name, PATH_MAX, "%s-part%d-%s-%d",
		    rd->metaloc.version == 1 ? dev->name : "bd",
		    db->part + 1, type_tag_name[ttag], i);
		err = mdb_dbi_open(txn, dbi_name, flags, &DEV_SHARD_A(db, ttag, i));
		if (err) {
			mdb_txn_abort(txn);
			log_error(lg, "Dev(%s): cannot open mdb: %s (%d) %s",
			    dev->name, dbi_name, err, mdb_strerror(err));
			err = -EIO;
			goto _exit;
		}

		if (is_dupsort_tt(ttag)) {
			err = mdb_set_dupsort(txn, DEV_SHARD(db, ttag, i),
			    rd_lmdb_cmp_ttag(ttag));
			assert(err == 0);
		}

		if (ttag == TT_VERIFICATION_QUEUE) {
			err = mdb_set_compare(txn, DEV_SHARD(db, ttag, i),
			    rd_lmdb_verqueue_cmp);
			assert(err == 0);
		} else if (ttag == TT_TRANSACTION_LOG) {
			err = mdb_set_compare(txn, DEV_SHARD(db, ttag, i),
			    rd_lmdb_trlog_cmp);
			assert(err == 0);
		} else if (ttag == TT_BATCH_INCOMING_QUEUE) {
			err = mdb_set_compare(txn, DEV_SHARD(db, ttag, i),
				rd_lmdb_incomig_batch_cmp);
			assert(err == 0);
		} else if (ttag == TT_HASHCOUNT)
			break;
	}

	err = mdb_txn_commit(txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot commit %s to mdb: (%d) %s",
		    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	mdb_env_sync(DEV_ENV(db, ttag), 1);

	return 0;

_exit:
	rd_lmdb_close(dev, db);
	return err;
}

part_walk_action_t
rd_partition_walk(struct repdev *dev, partition_walk_f func,
					  void *arg) {

	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = NULL;

	for (int i = 0; i < rd->plevel; i++) {
		db = rd->db + i;
		if (func(db, arg) != PART_WALK_CONTINUE)
			return PART_WALK_TERMINATE;
	}

	return PART_WALK_COMPLETED;
}

struct part_info {
	unsigned int major;
	unsigned int minor;
	char name[32];
};

static void
rd_collect_iostat(struct repdev *dev)
{
	const char *scan_fmt = "%4d %4d %31s %u %u %llu %u %u %u %llu %u %*u %u %u";
	FILE *df = fopen("/proc/diskstats", "r");
	FILE *cf = fopen("/proc/stat", "r");
	FILE *ncf = fopen("/proc/cpuinfo", "r");
	char buf[256];
	char fname[PATH_MAX];
	char dname[PATH_MAX];
	struct repdev_rd *rd = dev->device_lfs;
	struct blkio_info blkio, new_blkio;
	struct cpu_info new_cpu;

	snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s", dev->name);
	char *kdevname = realpath(fname, dname);
	char *devname = kdevname + strlen("/dev/");

	if (!df || !cf || !ncf)
		goto _exit;
	while (fgets(buf, sizeof(buf), df)) {
		int items;
		struct part_info curr;

		items = sscanf(buf, scan_fmt, &curr.major, &curr.minor,
		    &curr.name, &blkio.rd_ios, &blkio.rd_merges,
		    &blkio.rd_sectors, &blkio.rd_ticks, &blkio.wr_ios,
		    &blkio.wr_merges, &blkio.wr_sectors, &blkio.wr_ticks,
		    &blkio.ticks, &blkio.aveq);
		if (items != 13 || strcmp(curr.name, devname) != 0)
			continue;
		new_blkio = blkio;
		break;
	}

	while (fgets(buf, sizeof(buf), cf)) {
		if (!strncmp(buf, "cpu ", 4)) {
			int items;
			unsigned long long nice, irq, softirq;

			items = sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu",
			    &new_cpu.user, &nice, &new_cpu.system, &new_cpu.idle,
			    &new_cpu.iowait, &irq, &softirq);

			new_cpu.user += nice;
			if (items == 4)
				new_cpu.iowait = 0;
			if (items == 7)
				new_cpu.system += irq + softirq;

		}
	}

	unsigned int ncpu = 0;
	while (fgets(buf, sizeof(buf), ncf)) {
		if (!strncmp(buf, "processor\t:", 11))
			ncpu++;
	}
	if (!ncpu)
		goto _exit;

#define CALC_PER_SEC(x) (1000.0 * (x) / delta_ms)

	unsigned int p;
	double delta_ms = 1000.0 *
		((new_cpu.user + new_cpu.system +
		  new_cpu.idle + new_cpu.iowait) -
		 (rd->old_cpu.user + rd->old_cpu.system +
		  rd->old_cpu.idle + rd->old_cpu.iowait)) / ncpu / HZ;

	double n_ticks;
	double n_kbytes;
	double busy;
	double svc_t;
	double wait;
	double size;
	double queue;
	double n_ios;

	blkio.rd_ios = new_blkio.rd_ios - rd->old_blkio.rd_ios;
	blkio.rd_merges = new_blkio.rd_merges - rd->old_blkio.rd_merges;
	blkio.rd_sectors = new_blkio.rd_sectors - rd->old_blkio.rd_sectors;
	blkio.rd_ticks = new_blkio.rd_ticks - rd->old_blkio.rd_ticks;
	blkio.wr_ios = new_blkio.wr_ios - rd->old_blkio.wr_ios;
	blkio.wr_merges = new_blkio.wr_merges - rd->old_blkio.wr_merges;
	blkio.wr_sectors = new_blkio.wr_sectors - rd->old_blkio.wr_sectors;
	blkio.wr_ticks = new_blkio.wr_ticks - rd->old_blkio.wr_ticks;
	blkio.ticks = new_blkio.ticks - rd->old_blkio.ticks;
	blkio.aveq = new_blkio.aveq - rd->old_blkio.aveq;

	n_ios  = blkio.rd_ios + blkio.wr_ios;
	n_ticks = blkio.rd_ticks + blkio.wr_ticks;
	n_kbytes = (blkio.rd_sectors + blkio.wr_sectors) / 2.0;

	queue = blkio.aveq / delta_ms;
	size = n_ios ? n_kbytes / n_ios : 0.0;
	wait = n_ios ? n_ticks / n_ios : 0.0;
	svc_t = n_ios ? blkio.ticks / n_ios : 0.0;
	busy = 100.0 * blkio.ticks / delta_ms;
	if (busy > 100.0)
		busy = 100.0;

	dev->stats.iostat.r_merges = CALC_PER_SEC(blkio.rd_merges);
	dev->stats.iostat.w_merges = CALC_PER_SEC(blkio.wr_merges);
	dev->stats.iostat.r_ios = CALC_PER_SEC(blkio.rd_ios);
	dev->stats.iostat.w_ios = CALC_PER_SEC(blkio.wr_ios);
	dev->stats.iostat.r_sectors = CALC_PER_SEC(blkio.rd_sectors) / 2.0;
	dev->stats.iostat.w_sectors = CALC_PER_SEC(blkio.wr_sectors) / 2.0;
	dev->stats.iostat.size_kb = size;
	dev->stats.iostat.queue = queue;
	dev->stats.iostat.wait_us = wait * 1000.0;
	dev->stats.iostat.svc_t_us = svc_t * 1000.0;
	dev->stats.iostat.busy = busy;

	rd->old_blkio = new_blkio;
	rd->old_cpu = new_cpu;

_exit:
	fclose(ncf);
	fclose(df);
	fclose(cf);
}

static void
rd_collect_smart(struct repdev *dev)
{
	FILE *p;
	char *buffer = NULL;
	size_t result;
	char cmd[1024];
	struct repdev_rd *rd = dev->device_lfs;

	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	if (tm->tm_hour == 0 && tm->tm_min == 0) {
		/* will execute selftest next iteration */
		rd->smart_selftest_scheduled = ((tm->tm_mday % 7) == 0) ? 2 : 1;
		return;
	}

	uint64_t curr_ts = get_timestamp_us();
	if (curr_ts - rd->smart_read_ts >= DEV_RD_SMART_READ_INTERVAL) {

		if (rd->smart_read_ts == 0) {
			/* first time, make sure to enable stats */
			snprintf(cmd, 1024, DEV_RD_SMARTCTL_CMD_EN, nedge_path(), dev->name);
			int err = system(cmd);
		}

		if (rd->smart_selftest_scheduled) {
			/* trigger selftest weekly: long, daily: short */
			snprintf(cmd, 1024, DEV_RD_SMARTCTL_CMD_SELFTEST, nedge_path(),
			    rd->smart_selftest_scheduled == 2 ? "long" : "short",
			    dev->name);
			int err = system(cmd);
			rd->smart_selftest_scheduled = 0;
		}

		rd->smart_read_ts = curr_ts;
	} else
		return;

	snprintf(cmd, 1024, DEV_RD_SMARTCTL_CMD, nedge_path(), dev->name);

	p = popen(cmd, "r");
	if (!p) {
		log_warn(lg, "smartctl exec error");
		return;
	}

	/* copy the file into the buffer */
	buffer = (char*)je_malloc(1024*1024);
	if (!buffer)
		goto _exit;

	result = fread(buffer, 1, 1024*1024, p);
	if (!result || ferror(p)) {
		log_warn(lg, "smartctl buffer read error");
		goto _exit;
	}

	json_value *o = json_parse(buffer, result);
	if (!o) {
		log_error(lg, "Cannot parse smartctl json output produced by cmd '%s'", cmd);
		goto _exit;
	}

	if (o->type != json_object) {
		log_error(lg, "Syntax error: smartctl output is not json, err1");
		goto _json_err;
	}

	/* read JSON and update stats structure */
	for (size_t i = 0; i < o->u.object.length; i++) {
		json_value *v = o->u.object.values[i].value;
		if (strcmp(o->u.object.values[i].name, "smart_status") == 0) {
			for (size_t j = 0; j < v->u.object.length; i++) {
				if (strcmp(v->u.object.values[j].name, "passed") == 0) {
					dev->stats.smart.smart_status = v->u.object.values[j].value->u.integer;
					break;
				}
			}
		} else if (strcmp(o->u.object.values[i].name, "temperature") == 0) {
			for (size_t j = 0; j < v->u.object.length; i++) {
				if (strcmp(v->u.object.values[j].name, "current") == 0) {
					dev->stats.smart.temperature_current = v->u.object.values[j].value->u.integer;
					break;
				}
			}
		} else if (strcmp(o->u.object.values[i].name, "non_medium_error_count") == 0) {
			dev->stats.smart.non_medium_error_count = v->u.integer;
		} else if (strcmp(o->u.object.values[i].name, "percentage_used_endurance_indicator") == 0) {
			dev->stats.smart.percentage_used_endurance_indicator = v->u.integer;
		} else if (strcmp(o->u.object.values[i].name, "total_uncorrected_read_errors") == 0) {
			dev->stats.smart.total_uncorrected_read_errors = v->u.integer;
		} else if (strcmp(o->u.object.values[i].name, "total_uncorrected_write_errors") == 0) {
			dev->stats.smart.total_uncorrected_write_errors = v->u.integer;
		} else if (strcmp(o->u.object.values[i].name, "ata_smart_attributes") == 0) {
			for (size_t j = 0; j < v->u.object.length; j++) {
				if (strcmp(v->u.object.values[j].name, "table") == 0) {
					json_value *attrs = v->u.object.values[j].value;
					if (attrs->type != json_array) {
						log_error(lg, "Syntax error: smartctl output is not json, err2\n");
						goto _json_err;
					}
					for (size_t l = 0; l < attrs->u.array.length; l++) {
						uint64_t *sp = NULL;
						json_value *t = attrs->u.array.values[l];
						if (t->type != json_object) {
							log_error(lg, "Syntax error: smartctl output is not json, err3\n");
							goto _json_err;
						}
						for (size_t k = 0; k < t->u.object.length; k++) {
							if (sp && strcmp(t->u.object.values[k].name, "raw") == 0) {
								json_value *r = t->u.object.values[k].value;
								if (r->type != json_object) {
									log_error(lg, "Syntax error: smartctl output is not json, err4\n");
									goto _json_err;
								}
								for (size_t m = 0; m < r->u.object.length; m++) {
									if (strcmp(r->u.object.values[m].name, "value") == 0) {
										*sp = r->u.object.values[m].value->u.integer;
										break;
									}
								}
								break;
							}
							if (strcmp(t->u.object.values[k].name, "name") != 0)
								continue;
							if (strcmp(t->u.object.values[k].value->u.string.ptr, "Current_Pending_Sector") == 0) {
								sp = &dev->stats.smart.current_pending_sector;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "ECC_Uncorr_Error_Count") == 0) {
								sp = &dev->stats.smart.ecc_uncorr_error_count;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "End-to-End_Error") == 0) {
								sp = &dev->stats.smart.end_to_end_error;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "Offline_Uncorrectable") == 0) {
								sp = &dev->stats.smart.offline_uncorrectable;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "Reallocated_Event_Count") == 0) {
								sp = &dev->stats.smart.reallocated_event_count;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "Reallocated_Sector_Ct") == 0) {
								sp = &dev->stats.smart.reallocated_sector_ct;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "Reported_Uncorrect") == 0) {
								sp = &dev->stats.smart.reported_uncorrect;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "Soft_Read_Error_Rate") == 0) {
								sp = &dev->stats.smart.soft_read_error_rate;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "Spin_Retry_Count") == 0) {
								sp = &dev->stats.smart.spin_retry_count;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "Total_Pending_Sectors") == 0) {
								sp = &dev->stats.smart.total_pending_sectors;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "Unc_Soft_Read_Err_Rate") == 0) {
								sp = &dev->stats.smart.unc_soft_read_err_rate;
							} else if (strcmp(t->u.object.values[k].value->u.string.ptr, "Raw_Read_Error_Rate") == 0) {
								sp = &dev->stats.smart.raw_read_error_rate;
							}
						}
					}
				}
			}
		}
	}

_json_err:
	json_value_free(o);
_exit:
	pclose(p);
	if (buffer)
		je_free(buffer);
	return;
}

static int
rd_lmdb_stat(struct repdev *dev)
{
	int err = 0;
	MDB_txn *txn = NULL, *offload_txn = NULL;
	struct repdev_db *db = NULL;
	struct repdev_rd *rd = dev->device_lfs;

	uint64_t entries = 0;
	uint64_t used_space = 0;
	uint64_t free_space = 0;
	uint64_t total_used_space = 0;
	uint64_t rep_entries = 0;
	uint64_t ver_entries = 0;
	uint64_t capacity = 0;
	uint64_t physical_capacity = 0;
	long blk = 0, ssz = 0;

	repdev_status_t status;
	status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;

	err = rd_get_size(dev->path, &blk, &ssz);
	if (!err) {
		physical_capacity = blk * ssz;
	} else {
		dev->stats.used = 0;
		if (err == -ENOENT) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'm',
				.plevel = 0
			};
			rd_dev_faulted(dev, &fs);
			err = -ENODEV;
		}
		goto out;
	}

	key_cache_stat_t keycache_stats_aggr = { 0, 0, 0 };
	size_t ttag_entries[TT_LAST] = {0};
	size_t ttag_size[TT_LAST] = {0};
	/*
	 * Real VDEV capacity may not match disk size since MDB's map size
	 * is smaller than partition. Also, the disk can keep a WAL.
	 * A more precise way to calculate real size is to sum the mapsize of each plevel.
	 */
	capacity = 0;

	for (int pl = 0; pl < rd->plevel; ++pl) {
		db = rd->db + pl;

		const char* env_path = NULL;
		mdb_env_get_path(db->env[0], &env_path);

		MDB_envinfo env_info;
		mdb_env_info(db->env[0], &env_info);
		capacity += env_info.me_mapsize;

		keycache_stats_aggr.hit += db->key_cache->stats.hit;
		keycache_stats_aggr.miss += db->key_cache->stats.miss;
		keycache_stats_aggr.evicted += db->key_cache->stats.evicted;

		int rc = mdb_txn_begin(DEV_ENV(db, TT_CHUNK_PAYLOAD), NULL, MDB_RDONLY,
			&txn);
		if (rc) {
			log_error(lg, "Dev(%s) mdb_txn_begin %s (%d) env_path %s plevel %d",
				dev->name, mdb_strerror(rc), rc, env_path, db->part);
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, TT_CHUNK_PAYLOAD) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			err = -EIO;
			continue;
		}
		if (dev->journal) {
			/* If journal defined, then there can be TT offloaded
			 * to the journal's partition. Open corresponding
			 * transaction then.
			 */
			for (size_t tt = TT_NAMEINDEX; !err && tt < TT_LAST; tt++) {
				if (!is_mdoffload_tt(dev, tt))
					continue;
				mdb_env_get_path(DEV_ENV(db, tt), &env_path);
				rc = mdb_txn_begin(DEV_ENV(db, tt),
					NULL, MDB_RDONLY, &offload_txn);
				if (rc) {
					mdb_txn_abort(txn);
					err = -EIO;
					log_error(lg, "Dev(%s) mdoffload mdb_txn_begin %s (%d) env_path %s",
						dev->name, mdb_strerror(rc), rc, env_path);
					struct rd_fault_signature fs = {
						.error = err,
						.source = dev->journal && is_mdoffload_tt(dev, tt) ? 'o' : 'm',
						.plevel = db->part + 1
					};
					rd_dev_faulted(dev, &fs);
				}
				break;
			}
			if (err)
				continue;
		} else
			offload_txn = txn;


		for (int tt = TT_NAMEINDEX; !err && tt < TT_LAST; tt++) {
			for (int i = 0; !err && i < DEV_SHARD_MAX(db, tt); i++) {
				MDB_stat mst;
				/* Consider mdoffload TT only once */
				if ((dev->journal && is_mdoffload_tt(dev, tt)) && pl > 0)
					break;

				rc = mdb_stat(dev->journal && is_mdoffload_tt(dev, tt) ?
					offload_txn : txn, DEV_SHARD(db, tt, i),
					&mst);
				if (rc) {
					err = -EIO;
					break;
				}
				ttag_entries[tt] += mst.ms_entries;
				ttag_size[tt] += mst.ms_psize *
					(mst.ms_branch_pages + mst.ms_leaf_pages +
					mst.ms_overflow_pages);
			}
		}
		mdb_txn_abort(txn);
		if (txn != offload_txn)
			mdb_txn_abort(offload_txn);
	}
	for (int tt = TT_NAMEINDEX; tt < TT_LAST; tt++) {
		if (!(dev->journal && is_mdoffload_tt(dev, tt))) {
			total_used_space += ttag_size[tt];
		}
	}
	memcpy(dev->stats.ttag_entries, ttag_entries, sizeof(ttag_entries));
	memcpy(dev->stats.ttag_size, ttag_size, sizeof(ttag_size));
	atomic_set_uint64(&dev->stats.physical_capacity, physical_capacity);
	atomic_set_uint64(&dev->stats.capacity, capacity);
	atomic_set_uint64(&dev->stats.used, total_used_space);
	dev->stats.keycache = keycache_stats_aggr;
	dev->stats.num_objects = ttag_entries[TT_NAMEINDEX];
	if (rd->mdcache) {
		uv_rwlock_rdlock(&rd->mdcache->lock);
		dev->stats.mdcache = rd->mdcache->stats;
		uv_rwlock_rdunlock(&rd->mdcache->lock);
	}

	rd_collect_iostat(dev);
	rd_collect_smart(dev);
out:
	return err;
}

static int
rd_adjust_hdd(struct repdev *dev, char *kdevname)
{
	char rPath[2048];
	int err;
	char *hdd_cfq = getenv("DEV_RD_HDD_CFQ");
	struct repdev_rd *rd = dev->device_lfs;

	if (hdd_cfq) {
		snprintf(rPath, 2048, "echo cfq 2>/dev/null > /sys/block/%s/queue/scheduler", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 2048 2>/dev/null > /sys/block/%s/queue/nr_requests", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 2048 2>/dev/null > /sys/block/%s/queue/max_sectors_kb", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo %d 2>/dev/null > /sys/block/%s/queue/read_ahead_kb", rd->hdd_readahead, kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 2000 2>/dev/null > /sys/block/%s/queue/iosched/fifo_expire_async", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 250 2>/dev/null > /sys/block/%s/queue/iosched/fifo_expire_sync", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 80 2>/dev/null > /sys/block/%s/queue/iosched/slice_async", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 0 2>/dev/null > /sys/block/%s/queue/iosched/low_latency", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 32 2>/dev/null > /sys/block/%s/queue/iosched/quantum", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 5 2>/dev/null > /sys/block/%s/queue/iosched/slice_async_rq", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 8 2>/dev/null > /sys/block/%s/queue/iosched/slice_idle", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 100 2>/dev/null > /sys/block/%s/queue/iosched/slice_sync", kdevname);
		err = system(rPath);
		goto _exit;
	}

	snprintf(rPath, 2048, "echo deadline 2>/dev/null > /sys/block/%s/queue/scheduler", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 500 2>/dev/null > /sys/block/%s/queue/iosched/read_expire", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 5000 2>/dev/null > /sys/block/%s/queue/iosched/write_expire", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 1 2>/dev/null > /sys/block/%s/queue/iosched/writes_starved", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 1024 2>/dev/null > /sys/block/%s/queue/nr_requests", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 0 2>/dev/null > /sys/block/%s/queue/add_random", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo %d 2>/dev/null > /sys/block/%s/queue/read_ahead_kb", rd->hdd_readahead, kdevname);
	err = system(rPath);

_exit:
	log_info(lg, "Dev(%s): rotational HDD /dev/%s adjusted to optimal values",
	    dev->name, kdevname);
	return err;
}

static int
rd_adjust_ssd(struct repdev *dev, char *kdevname)
{
	char rPath[2048];
	int err;
	char *ssd_cfq = getenv("DEV_RD_SSD_CFQ");
	struct repdev_rd *rd = dev->device_lfs;

	if (ssd_cfq) {
		snprintf(rPath, 2048, "echo cfq 2>/dev/null > /sys/block/%s/queue/scheduler", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 256 2>/dev/null > /sys/block/%s/queue/nr_requests", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo %d 2>/dev/null > /sys/block/%s/queue/read_ahead_kb", rd->readahead, kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 1 2>/dev/null > /sys/block/%s/queue/iosched/back_seek_penalty", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 10000 2>/dev/null > /sys/block/%s/queue/iosched/fifo_expire_async", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 20 2>/dev/null > /sys/block/%s/queue/iosched/fifo_expire_sync", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 1 2>/dev/null > /sys/block/%s/queue/iosched/low_latency", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 6 2>/dev/null > /sys/block/%s/queue/iosched/quantum", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 2 2>/dev/null > /sys/block/%s/queue/iosched/slice_async", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 10 2>/dev/null > /sys/block/%s/queue/iosched/slice_async_rq", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 1 2>/dev/null > /sys/block/%s/queue/iosched/slice_idle", kdevname);
		err = system(rPath);
		snprintf(rPath, 2048, "echo 20 2>/dev/null > /sys/block/%s/queue/iosched/slice_sync", kdevname);
		err = system(rPath);
		goto _exit;
	}

	snprintf(rPath, 2048, "echo noop 2>/dev/null > /sys/block/%s/queue/scheduler", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 0 2>/dev/null > /sys/block/%s/queue/add_random", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo 256 2>/dev/null > /sys/block/%s/queue/nr_requests", kdevname);
	err = system(rPath);
	snprintf(rPath, 2048, "echo %d 2>/dev/null > /sys/block/%s/queue/read_ahead_kb", rd->readahead, kdevname);
	err = system(rPath);

_exit:
	log_info(lg, "Dev(%s): non-rotational SSD /dev/%s adjusted to optimal values",
	    dev->name, kdevname);
	return err;
}

static int
is_rotational(char *dname)
{
	char rpath[PATH_MAX] = { 0 };
	char rbuf[16] = { 0 };

	/*
	 * Looking for :
	 * /sys/block/[dev_from_id]/queue/rotational
	 * Build the string for fopen
	 */
	snprintf(rpath, PATH_MAX, "/sys/block/%s/queue/rotational", dname);

	FILE *fp = fopen(rpath, "r");
	if (!fp)
		return -errno;

	int bytes = fread(rbuf, 1, 1, fp);
	fclose(fp);
	if (bytes != 1)
		return -errno;

	return atoi(rbuf);
}

static int
rd_dev_stat_refresh(struct repdev *dev)
{
	assert(dev != NULL);
	assert(dev->path != NULL);
	struct repdev_rd* rd = dev->device_lfs;
	rt_set_thread_vdev_context(dev);

	if ((dev->rt->flags & RT_FLAG_RDHOLD))
		return 0;
	int err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;
	if (!rd_is_opened(rd)) {
		err = -ENOENT;
		goto _exit;
	}

	err = rd_lmdb_stat(dev);
	if (err) {
		log_debug(lg, "LDBM stats returned error: %d", err);
		goto _exit;
	}
	char devpath[2048];
	/* check device type to calculate latency */
	if (dev->stats.nominal_latency == 0) {
		dev->stats.nominal_latency = RT_RD_HDD_LATENCY_US;
		memset(devpath, 0, 2048);
		snprintf(devpath, 2048, "/dev/disk/by-id/%s", dev->name);
		char *con_path = realpath(devpath, NULL);
		if (!con_path) {
			log_warn(lg, "Dev(%s): unable to resolve kdevname: %s",
			    dev->name, strerror(errno));
			err = -errno;
			goto _exit;
		}
		char *dname = con_path + strlen("/dev/");
		int rotational = is_rotational(dname);
		if (rotational < 0) {
			free(con_path);
			log_warn(lg, "Dev(%s): unable to retrieve rotational bit: %s",
			    dev->name, strerror(errno));
			err = rotational;
			goto _exit;
		}

		if (rotational) {
			rd_adjust_hdd(dev, dname);
			dev->stats.rotational = 1;
		} else {
			rd_adjust_ssd(dev, dname);
			dev->stats.nominal_latency = RT_RD_SSD_LATENCY_US;
		}
		free(con_path);

		if (dev->journal) {
			snprintf(devpath, 2048, "/dev/disk/by-id/%s", dev->journal);
			con_path = realpath(devpath, NULL);
			if (!con_path) {
				log_warn(lg, "Dev(%s): unable to resolve journal kdevname: %s",
				    dev->journal, strerror(errno));
				err = -errno;
				goto _exit;
			}
			dname = con_path + strlen("/dev/");
			rd_adjust_ssd(dev, dname);
			free(con_path);
		}
		err = 0;
	}
_exit:
	pthread_rwlock_unlock(&rd->guard);
	return err;
}

static int
rd_key_encode(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid, msgpack_p **ptk, struct repdev_db **db_out,
	MDB_dbi *dbi_out, struct repdev_log **log_out)
{
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db* db;

	err = reptrans_key_encode(dev, ttag, hash_type, chid, ptk);
	if (err) {
		log_error(lg, "TypedKey(%s): cannot encode CHID", dev->name);
		return err;
	}

	/* get part environment */
	int j = PLEVEL_HASHCALC(chid, (rd->plevel - 1));
	db = rd->db + j;

	*db_out = db;

	/* get DBI shard within partition */
	int k = SHARD_HASHCALC(chid, DEV_SHARDS_MASK);
	*dbi_out = DEV_SHARD(db, ttag, k);

	/* get LOG within partition */
	int id = LOGID_HASHCALC(chid, DEV_LOGID_MASK);
	*log_out = &DEV_LOGID(db, id);

	return 0;
}

static int
rd_del_hashcount_entry(struct repdev *dev)
{
	int err;
	MDB_txn *txn;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = rd->db;
	MDB_val key = { .mv_size = strlen(HASHCOUNT_BLOB_KEY) + 1,
			.mv_data = HASHCOUNT_BLOB_KEY };

	if(dev->rt->flags & RT_FLAG_RDONLY)
		return 0;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return -EPERM;

	const char* env_path = NULL;
	mdb_env_get_path(DEV_ENV(db, TT_HASHCOUNT), &env_path);

	err = mdb_txn_begin(DEV_ENV(db, TT_HASHCOUNT), NULL, 0, &txn);
	if (err) {
		log_error(lg,
		    "Dev(%s): rd_del_hashcount_entry mdb_txn_begin: (%d) %s, env_path %s plevel %d",
		    dev->name, err, mdb_strerror(err), env_path, db->part);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		return -EIO;
	}

	err = mdb_del(txn, DEV_SHARD(db, TT_HASHCOUNT, 0), &key, NULL);
	if (err) {
		mdb_txn_abort(txn);
		log_warn(lg, "Dev(%s): %s mdb_del: (%d) %s env_path %s plevel %d", dev->name,
		    type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err), env_path, db->part);
		return -EIO;
	}

	err = mdb_txn_commit(txn);
	if (err) {
		log_error(lg, "Dev(%s): %s mdb_txn_commit: (%d) %s env_path %s plevel %d",
		    dev->name, type_tag_name[TT_HASHCOUNT], err,
		    mdb_strerror(err), env_path, db->part);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		return -EIO;
	}

	return 0;
}

static int
rd_put_hashcount_entry(struct repdev *dev, MDB_val* key, MDB_val* data)
{
	int err;
	MDB_txn *txn;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = rd->db;
	void *data_ptr = data->mv_data;
	int attempt = 0;

	if(dev->rt->flags & RT_FLAG_RDONLY)
		return 0;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE ||
		status == REPDEV_STATUS_READONLY_FULL ||
		status == REPDEV_STATUS_READONLY_FORCED ||
		status == REPDEV_STATUS_READONLY_FAULT)
		return -EPERM;

	const char* env_path = NULL;
	mdb_env_get_path(DEV_ENV(db, TT_HASHCOUNT), &env_path);

_retry:
	err = mdb_txn_begin(DEV_ENV(db, TT_HASHCOUNT), NULL, 0, &txn);
	if (err) {
		log_error(lg,
		    "Dev(%s): rd_put_hashcount_entry mdb_txn_begin: (%d) %s path %s part %d",
		    dev->name, err, mdb_strerror(err), env_path, db->part);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		return -EIO;
	}

	err = mdb_put(txn, DEV_SHARD(db, TT_HASHCOUNT, 0), key, data, MDB_RESERVE);
	if (err) {
		mdb_txn_abort(txn);
		log_error(lg, "Dev(%s): %s mdb_put: (%d) %s path %s part %d", dev->name,
		    type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err), env_path, db->part);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		return -EIO;
	}

	memcpy((char *)data->mv_data, data_ptr, data->mv_size);

	err = mdb_txn_commit(txn);
	if (err) {
		/* we seeing that device maybe unavailable for short period
		 * of time or due to resource constraints, wait and retry */
		if (attempt++ < 3) {
			sleep(1);
			goto _retry;
		}
		log_error(lg, "Dev(%s): %s mdb_txn_commit: (%d) %s path %s part %d",
		    dev->name, type_tag_name[TT_HASHCOUNT], err,
		    mdb_strerror(err), env_path, db->part);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		return -EIO;
	}

	return 0;
}

static int
rd_get_hashcount_entry(struct repdev *dev, MDB_val* key, MDB_val* data)
{
	int err;
	MDB_txn *txn;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = rd->db;

	const char* env_path = NULL;
	mdb_env_get_path(DEV_ENV(db, TT_HASHCOUNT), &env_path);

	err = mdb_txn_begin(DEV_ENV(db, TT_HASHCOUNT), NULL, MDB_RDONLY, &txn);
	if (err) {
		log_error(lg, "rd_get_hashcount_entry mdb_txn_begin: (%d) %s env_path %s part %d",
			err, mdb_strerror(err), env_path, db->part);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		return -EIO;
	}

	err = mdb_get(txn, DEV_SHARD(db, TT_HASHCOUNT, 0), key, data);
	if (err == MDB_NOTFOUND) {
		mdb_txn_abort(txn);
		return -ENOENT;
	} else if (err) {
		log_error(lg, "rd_get_hashcount_entry mdb_get: (%d) %s env_path %s part %d", err,
		    mdb_strerror(err), env_path, db->part);
		struct rd_fault_signature fs = {
			.error = err,
			.source = 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		err = -EIO;
	}

	mdb_txn_abort(txn);
	return err;
}

int
rd_config_impl(struct repdev *dev, dev_cfg_op op,
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
		err = rd_get_hashcount_entry(dev, &mdb_key, &mdb_value);
		if (!err) {
			value->base = mdb_value.mv_data;
			value->len = mdb_value.mv_size;
		}
	} else {
		mdb_value.mv_data = value->base;
		mdb_value.mv_size = value->len;
		err = rd_put_hashcount_entry(dev, &mdb_key, &mdb_value);
	}
	return err;
}

int
rd_config(struct repdev* dev, dev_cfg_op op,
	const uv_buf_t* key, uv_buf_t* value) {
	struct repdev_rd* rd = dev->device_lfs;
	int err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		err = -ENOENT;
		goto _exit;
	}
	err = rd_config_impl(dev, op, key, value);

_exit:
	pthread_rwlock_unlock(&rd->guard);
	return err;
}

static int
rd_log_delete_deferred(void *arg)
{
	struct repdev_log *log = arg;
	struct repdev_db *db = log->db;
	MDB_env *log_env = log->env;
	type_tag_t ttag = log->ttag;
	MDB_dbi log_dbi = log->dbi[ttag];
	rtbuf_t *rbkeys = log->delete_rbkeys;
	struct repdev *dev = log->dev;
	MDB_txn *log_txn = NULL;
	int err;
	uint64_t start_ns = uv_hrtime();
	size_t nbuf_cur = 0;
	size_t delete_bulk_size = DEV_RD_DEL_DEFERRED_BULK;

_repeat:
	/* start log txn */
	err = rdlog_txn_begin(log, 0, &log_txn);
	if (err) {
		log_error(lg, "Get(%s): cannot begin log_delete %s log_txn: (%d) %s env_path %s",
		    dev->name, type_tag_name[ttag], err, mdb_strerror(err), log->path);
		rdlog_unlock(log);
		err = rdlog_repair(log, err);
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
			if (i > nbuf_cur + delete_bulk_size)
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
			MDB_val key = { .mv_size = k->len - sizeof(uint64_t), .mv_data = k->base };
			memcpy(&attr, k->base + k->len - sizeof(uint64_t), sizeof(uint64_t));

			err = mdb_get_attr(log_txn, log_dbi, &key, NULL, &attr_g);
			if (err)
				break;
			if (attr != attr_g)
				continue;

			err = mdb_del(log_txn, log_dbi, &key, NULL);
			if (err && err != MDB_NOTFOUND)
				break;
			err = 0;
			if (i > nbuf_cur + delete_bulk_size)
				break;
		}
	}


	err = rdlog_txn_commit(log, log_txn);
	log_txn = NULL;

	/* Trying to delete less entries at a time*/
	if (err == MDB_PAGE_FULL && delete_bulk_size > DEV_RD_DEL_DEFERRED_BULK / 64) {
		delete_bulk_size /= 2;
		goto _repeat;
	}

	if (err) {
		log_error(lg, "Dev(%s): log_delete rbkeys=%ld %s mdb_txn_commit: (%d) %s env_path %s",
		    dev->name, rbkeys->nbufs, type_tag_name[ttag], err, mdb_strerror(err), log->path);
		err = rdlog_repair(log, err);
		goto _exit;
	}

	nbuf_cur = i + 1;
	if (nbuf_cur < rbkeys->nbufs)
		goto _repeat;

	log_debug(lg, "Dev(%s): LOG DEL: %s, deleted=%ld took=%ldus", dev->name,
	    type_tag_name[ttag], rbkeys->nbufs, (uv_hrtime() - start_ns) / 1000);

_exit:
	if (log_txn)
		rdlog_txn_abort(log, log_txn);
	return err;
}

static void
rd_log_flush_thread(void *arg)
{
	struct repdev_log *log = arg;
	int err = 0;
	MDB_val key, data;
	int delete_keys = 0;
	MDB_cursor *log_cursor = NULL;
	MDB_txn *log_txn = NULL;
	struct repdev *dev = log->dev;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = log->db;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if (!rd_is_opened(rd) || status == REPDEV_STATUS_UNAVAILABLE
		|| status == REPDEV_STATUS_READONLY_FAULT
		|| status == REPDEV_STATUS_READONLY_FORCED) {
		uv_mutex_lock(&db->log_flush_lock);
		db->log_flush_cnt = 0;
		uv_cond_signal(&db->log_flush_condvar);
		uv_mutex_unlock(&db->log_flush_lock);
		return;
	}
	MDB_env *log_env = log->env;
	type_tag_t ttag = log->ttag;
	MDB_dbi log_dbi = log->dbi[ttag];
	MDB_env *main_env = DEV_ENV(db, ttag);
	MDB_txn *main_txn = NULL;
	MDB_txn *md_txn = NULL;
	MDB_cursor *main_cursor[DEV_SHARDS_MAX] = { NULL };

	rtbuf_t *rbkeys = NULL;
	uint32_t rbkeys_i = 0;
	uint64_t start_us = uv_hrtime();
	int force_readonly = 0;
	int force_unavail = 0;
	size_t n_log_entries = 0;
	size_t n_del_entries = 0;
	int delete_max_reached = 0;
	int commit_max_reached = 0;
	long commit_size = 0;

	uv_mutex_lock(&db->log_flush_lock);
	db->log_flush_cnt = pthread_self();
	uv_mutex_unlock(&db->log_flush_lock);
	dev->flushing |= (1 << ttag);
	dev->flushing_part |= (1 << db->part);

_start:
	commit_size = 0;
	n_del_entries = 0;
	delete_max_reached = commit_max_reached = 0;
	rbkeys_i = 0;
	delete_keys = 0;
	main_txn = NULL;
	md_txn = NULL;
	force_readonly = 0;
	force_unavail = 0;
	/* start log txn */
	err = rdlog_txn_begin(log, MDB_RDONLY, &log_txn);
	if (err) {
		if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
			log_error(lg, "Get(%s): cannot begin mdb log_flush log_txn: (%d) %s env_path %s",
			    dev->name, err, mdb_strerror(err), log->path);
			force_unavail = 1;
		} else {
			log_notice(lg, "Get(%s): cannot begin mdb log_flush log_txn: (%d) %s, retry",
			    dev->name, err, mdb_strerror(err));
		}
		rdlog_unlock(log);
		rdlog_repair(log, err);
		err = -EIO;
		goto _exit;
	}

	MDB_stat mstat;
	err = mdb_stat(log_txn, log_dbi, &mstat);
	if (err) {
		if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
			log_error(lg, "Get(%s): cannot begin mdb log_flush mdb_stat: (%d) %s env_path %s",
			    dev->name, err, mdb_strerror(err), log->path);
			force_unavail = 1;
		} else {
			log_notice(lg, "Get(%s): cannot begin mdb log_flush mdb_stat: (%d) %s, retry",
			    dev->name, err, mdb_strerror(err));
		}
		err = -EIO;
		goto _exit;
	}
	/* Reduce number of flushed entries in a case of previous flush error */
	n_log_entries = mstat.ms_entries / (db->flush_error_count[ttag] + 1);

	/* open log cursor */
	err = mdb_cursor_open(log_txn, log_dbi, &log_cursor);
	if (err) {
		if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
			log_error(lg, "Get(%s): cannot open mdb log_flush log_cursor: (%d) %s env_path %s",
			    dev->name, err, mdb_strerror(err), log->path);
			rdlog_txn_abort(log, log_txn);
			log_txn = NULL;
			err = rdlog_repair(log, err);
		} else {
			log_notice(lg, "Get(%s): cannot open mdb log_flush log_cursor: (%d) %s",
			    dev->name, err, mdb_strerror(err));
		}
		err = -EIO;
		goto _exit;
	}

	const char* main_env_path = NULL;
	mdb_env_get_path(main_env, &main_env_path);
	/* start main TT txn */
	err = mdb_txn_begin(main_env, NULL, 0, &main_txn);
	if (err) {
		if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
			log_error(lg, "Get(%s): cannot begin mdb log_flush main_txn: (%d) %s env_path %s part %d",
			    dev->name, err, mdb_strerror(err), main_env_path, db->part);
			force_unavail = 1;
		} else {
			log_notice(lg, "Get(%s): cannot begin mdb log_flush main_txn: (%d) %s env_path %s part %d, retry",
			    dev->name, err, mdb_strerror(err), main_env_path, db->part);
		}
		err = -EIO;
		goto _exit;
	}

	if (dev->journal && is_keycache_tt(ttag)) {

		if (main_env == rd->mdcache_env)
			md_txn = main_txn;

		if (is_mdcache_tt(dev, ttag)) {
			if (rd->mdcache_enable) {
				err = mdcache_adjust(rd->mdcache, ttag, md_txn);
				if (err) {
					if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
						log_error(lg, "Dev(%s): mdcache_adjust: (%d) %s", dev->name,
						    err, mdb_strerror(err));
						force_unavail = 1;
					} else {
						log_notice(lg, "Dev(%s): mdcache_adjust: (%d) %s, retry", dev->name,
						    err, mdb_strerror(err));
					}
					err = -EIO;
					goto _exit;
				}
			}
		}
		if (!md_txn) {
			const char* md_env_path = NULL;
			mdb_env_get_path(rd->mdcache_env, &md_env_path);

			/* start keys table txn */
			err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &md_txn);
			if (err) {
				md_txn = NULL;
				if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
					log_error(lg, "Dev(%s): mdb_txn_begin: (%d) %s env_path %s", dev->name,
					    err, mdb_strerror(err), md_env_path);
					force_unavail = 1;
				} else {
					log_notice(lg, "Dev(%s): mdb_txn_begin: (%d) %s env_path %s", dev->name,
					    err, mdb_strerror(err), md_env_path);
				}
				err = -EIO;
				goto _exit;
			}
			err = mdcache_stat_update(rd->mdcache, md_txn);
			if (err) {
				if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
					log_error(lg, "Dev(%s): mdcache_stat_update: (%d) %s env_path %s", dev->name,
					    err, mdb_strerror(err), md_env_path);
					force_unavail = 1;
				} else {
					log_notice(lg, "Dev(%s): mdcache_stat_update: (%d) %s env_path %s, retry",
						dev->name, err, mdb_strerror(err), md_env_path);
				}
				err = -EIO;
				goto _exit;
			}
		}
	}

	/* Allocate key buffer */
	rbkeys = rtbuf_init(NULL, n_log_entries*2);
	if (!rbkeys) {
		err = -ENOMEM;
		goto _exit;
	}

	/* walk all log records for this TT */
	int mdcache_blocked = 0, keydb_blocked = 0;
	int op = MDB_FIRST;
	while ((err = mdb_cursor_get(log_cursor, &key, &data, op)) == 0 &&
		rbkeys_i < (is_dupsort_tt(ttag) ? 2*n_log_entries : n_log_entries)
		&& !commit_max_reached) {
		op = MDB_NEXT;

		MDB_val keyhv;
		uint64_t kh;
		uint64_t attr = 0;
		if (!is_dupsort_tt(ttag)) {

			err = mdb_cursor_get_attr(log_cursor, &key, &data, &attr);
			if (err) {
				if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
					log_error(lg, "Get(%s): cannot read attr in log_flush: %s (%d) env_path %s",
					    dev->name, mdb_strerror(err), err, log->path);
					mdb_cursor_close(log_cursor);
					log_cursor = NULL;
					rdlog_txn_abort(log, log_txn);
					log_txn = NULL;
					err = rdlog_repair(log, err);
				} else {
					log_notice(lg, "Get(%s): cannot read attr in log_flush: %s (%d) env_path %s, retry",
					    dev->name, mdb_strerror(err), err, log->path);
				}
				err = -EIO;
				goto _exit;
			}
		}

		/* get shard location */
		uint512_t chid;
		crypto_hash_t key_hash_type;
		type_tag_t key_ttag;
		err = reptrans_key_decode(dev, key.mv_data, key.mv_size,
		    &key_ttag, &key_hash_type, &chid);
		if (err || key_ttag != ttag) {
			log_error(lg, "log_flush key decode failed %d, "
				"key_ttag %d, ttag %d(%s)", err, key_ttag,
				ttag, type_tag_name[ttag]);
			err = -EIO;
			goto _exit;
		}
		int shard = SHARD_HASHCALC(&chid, DEV_SHARDS_MASK);
		if (dev->journal && is_mdoffload_tt(dev, ttag))
			shard = 0;

		MDB_dbi main_dbi = DEV_SHARD(db, ttag, shard);

		/* open shard's cursor if not yet */
		if (!main_cursor[shard]) {
			err = mdb_cursor_open(main_txn, main_dbi, &main_cursor[shard]);
			if (err) {
				if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
					log_error(lg, "Get(%s): cannot open mdb log_flush cursor: (%d) %s env_path %s part %d",
					    dev->name, err, mdb_strerror(err), main_env_path, db->part);
					force_unavail = 1;
				} else {
					log_notice(lg, "Get(%s): cannot open mdb log_flush cursor: (%d) %s env_path %s part %d, retry",
					    dev->name, err, mdb_strerror(err), main_env_path, db->part);
				}
				err = -EIO;
				goto _exit;
			}
		}

		if (!is_dupsort_tt(ttag)) {

			if (is_keycache_tt(ttag)) {
				err = rd_keyhash(dev, &key, &keyhv, &kh);
				if (err) {
					log_error(lg, "Get(%s): cannot keyhash in log_flush: (%d)",
					    dev->name, err);
					goto _exit;
				}
			}

			repdev_status_t status = reptrans_dev_get_status(dev);
			int can_delete = status == REPDEV_STATUS_ALIVE ||
				status == REPDEV_STATUS_READONLY_FULL ||
				status == REPDEV_STATUS_READONLY_DATA ||
				status == REPDEV_STATUS_READONLY_ROWEVAC;
			long put_size = 0;
			if (!attr && can_delete) {
				if (delete_max_reached)
					continue;

				/* Blob delete case */
				MDB_val del_val = {0};
				err = mdb_cursor_get(main_cursor[shard], &key, &del_val, MDB_SET);
				if (err)
					goto _check_err;

				err = mdb_cursor_del(main_cursor[shard], 0);
				if (err)
					goto _check_err;
				if (is_hashcount_data_type_tag(ttag))
					reptrans_drop_hashcount(dev, &chid, 1);
				if (is_rowusage_data_type_tag(ttag))
					reptrans_drop_rowusage(dev, &chid, del_val.mv_size);

				if (is_data_type_tag(ttag) && ++n_del_entries >= DEV_RD_DEL_BUKL) {
					/*
					 * Limit number of deletions for data type tags
					 * to not produce large commits in FREE DBI.
					 */
					delete_max_reached = 1;
				}

				if (is_keycache_tt(ttag)) {
					if (dev->journal && !keydb_blocked) {
						err = keydb_blocked = rd_key_remove(dev, ttag, md_txn, &kh);
						if (err)
							log_error(lg, "Dev(%s): log_flush %s rd_key_remove: (%d)",
								dev->name, type_tag_name[ttag], err);
					}
					if (!err && dev->journal && is_mdcache_tt(dev, ttag) &&
						!mdcache_blocked && rd->mdcache_enable) {
						err = mdcache_remove(rd->mdcache, ttag,
							md_txn, &kh);
						if (err && err != -ENOENT) {
							log_error(lg, "Dev(%s): log_flush %s mdcache_remove: (%d)",
								dev->name, type_tag_name[ttag], err);
							mdcache_blocked = err;
						}
					}
				}
				put_size = rd->metaloc.psize*2;
			} else if (data.mv_size != 0) {
				/* Put only if device is operational.
				 * Skip the entry otherwise
				 * */
				int skip = status == REPDEV_STATUS_UNAVAILABLE ||
					status == REPDEV_STATUS_READONLY_FULL ||
					status == REPDEV_STATUS_READONLY_FORCED ||
					status == REPDEV_STATUS_READONLY_FAULT;
				if (!skip && !force_readonly) {
					MDB_val data_out = { .mv_data = NULL, .mv_size = data.mv_size };
					unsigned int flags = MDB_SETATTR | MDB_RESERVE;
					flags |= (dev->rt->flags & RT_FLAG_ALLOW_OVERWRITE) ?
							 0 : MDB_NOOVERWRITE;
					err = mdb_cursor_put_attr(main_cursor[shard], &key, &data_out, attr, flags);
					if (!err) {
						memcpy((char *)data_out.mv_data, data.mv_data, data.mv_size);
						if (is_hashcount_data_type_tag(ttag))
							reptrans_bump_hashcount(dev, &chid, 1);
						if (is_rowusage_data_type_tag(ttag))
							reptrans_bump_rowusage(dev, &chid, data.mv_size);
						put_size = data.mv_size + rd->metaloc.psize*2;
					}
					if (!err && is_keycache_tt(ttag)) {
						if (dev->journal && !keydb_blocked) {
							err = keydb_blocked = rd_key_insert(dev, ttag, md_txn,
							    &kh, data.mv_size, attr);
						}
						if (!err && dev->journal && is_mdcache_tt(dev, ttag) && !mdcache_blocked && rd->mdcache_enable) {
							err = mdcache_blocked = mdcache_insert(rd->mdcache, ttag,
							    md_txn, &kh, data.mv_data, data.mv_size);
						}
					} else if (err == MDB_KEYEXIST && attr) {
						if (dev->journal && is_keycache_tt(ttag))
							err = rd_key_set_attr(dev, ttag, md_txn, &kh, attr);
						else
							err = mdb_set_attr(main_txn, main_dbi, &key, NULL, attr);
					}
				} else
					continue;
			} else {
				/* do not touch HDD if journal defined */
				if (dev->journal && is_keycache_tt(ttag))
					err = rd_key_set_attr(dev, ttag, md_txn, &kh, attr);
				else
					err = mdb_set_attr(main_txn, main_dbi, &key, NULL, attr);
			}
_check_err:
			if (err == MDB_KEYEXIST || err == -EEXIST) {
				log_debug(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (err == MDB_NOTFOUND || err == -ENOENT) {
				log_debug(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (RD_NO_FREE_SPACE(err)) {
				/* Give it try to flush less entries. This can help on highly fragmented DB */
				if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
					log_warn(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
					    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
					force_readonly = 1;
				} else {
					log_info(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
					    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				}
				err = 0;
				goto _exit;
			} else if (err) {
				if (err != MDB_BAD_TXN) {
					if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
						log_error(lg, "Dev(%s): log_flush %s mdb_put (ksize=%ld vsize=%ld: (%d) %s env_path %s part %d",
						    dev->name, type_tag_name[ttag], key.mv_size, data.mv_size, err, mdb_strerror(err),
						    main_env_path, db->part);
						if (err == MDB_PAGE_FULL)
							force_readonly = 1;
						else
							force_unavail = 1;
						err = -EIO;
						goto _exit;
					} else if (err == MDB_PAGE_FULL && db->flush_error_count[ttag] == DEV_RD_FLUSH_ERROR_MAX) {
						/*
						 * MDB_PAGE_FULL workaround.
						 * Remove all processed log entries, drop the commit
						 * and try to flush one more time.
						 *
						 */
						log_notice(lg, "Dev(%s): log_flush %s MDB_PAGE_FULL error count exceeded, removing %u log entries",
						    dev->name, type_tag_name[ttag], rbkeys_i + 1);
						err = -EACCES;
					} else {
						log_notice(lg, "Dev(%s): log_flush %s mdb_put (ksize=%ld vsize=%ld: (%d) %s, retry",
						    dev->name, type_tag_name[ttag], key.mv_size, data.mv_size, err, mdb_strerror(err));
						err = -EIO;
						goto _exit;
					}
				} else {
					/* Need to abort current transaction and
					 * retry later
					 */
					log_warn(lg, "Dev(%s): log_flush %s (%d) %s",
					    dev->name, type_tag_name[ttag],
					    err, mdb_strerror(err));
					err = 0;

				}
			}

			/* add non-dupsort key+atrr to a list for deferred delete */
			rbkeys->bufs[rbkeys_i].base = je_calloc(1, key.mv_size + sizeof(attr));
			if (!rbkeys->bufs[rbkeys_i].base) {
				err = -ENOMEM;
				goto _exit;
			}
			memcpy(rbkeys->bufs[rbkeys_i].base, key.mv_data, key.mv_size);
			memcpy(rbkeys->bufs[rbkeys_i].base + key.mv_size, &attr, sizeof(attr));
			rbkeys->bufs[rbkeys_i].len = key.mv_size + sizeof(attr);
			rbkeys_i++;
			if (err == -EACCES) {
				delete_keys = 1;
				goto _exit;
			}
			rd->flushed_bytes += put_size;
			commit_size += put_size;
			if (rd_track_commit_size(put_size)) {
				commit_max_reached = 1;
				break;
			}
			/* non-dupsort done */
			continue;
		}

		/* set key to a first element and load data */
		err = mdb_cursor_get(log_cursor, &key, &data, MDB_SET_KEY);
		if (err) {
			if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
				log_error(lg, "Dev(%s): log_flush %s mdb_cursor_get (ksize=%ld dsize=%ld: (%d) %s env_path %s",
				    dev->name, type_tag_name[ttag], key.mv_size, data.mv_size, err, mdb_strerror(err), log->path);
				mdb_cursor_close(log_cursor);
				log_cursor = NULL;
				rdlog_txn_abort(log, log_txn);
				log_txn = NULL;
				err = rdlog_repair(log, err);
			} else {
				log_notice(lg, "Dev(%s): log_flush %s mdb_cursor_get (ksize=%ld dsize=%ld: (%d) %s, retry",
				    dev->name, type_tag_name[ttag], key.mv_size, data.mv_size, err, mdb_strerror(err));
			}
			err = -EIO;
			goto _exit;
		}

		/* flush all dupsorts for this key */
		do {
			if (rbkeys_i >= 2*n_log_entries)
				break;
			/* Check is it's a delete case */
			int dp_delete = 0;
			size_t dp_size = 0;
			if (data.mv_size >= DUPSORT_DEL_MAGIC_SIZE &&
				IS_DUPSORT_DEL((char*)data.mv_data + data.mv_size - DUPSORT_DEL_MAGIC_SIZE)) {
				dp_delete = 1;
				dp_size = data.mv_size - DUPSORT_DEL_MAGIC_SIZE;
			}
			MDB_val dupkey = {
				.mv_size = key.mv_size,
				.mv_data = key.mv_data
			};
			MDB_val dupdata = {
				.mv_size = data.mv_size,
				.mv_data = data.mv_data
			};

			if (dp_delete) {
				/*
				 * Dupsort delete request. If it has payload,
				 * then delete only requested entry.
				 * Otherwise delete all entries for the key
				 */
				dupdata.mv_data = dupdata.mv_size ? (char*)dupdata.mv_data : 0;
				dupdata.mv_size = dp_size;
				MDB_cursor_op get_op = dp_size ? MDB_GET_BOTH : MDB_SET_KEY;
				unsigned int del_flag = dp_size ? 0 : MDB_NODUPDATA;

				err = mdb_cursor_get(main_cursor[shard], &dupkey, &dupdata, get_op);
				if (err) {
					if (err == MDB_NOTFOUND) {
						log_debug(lg, "Dev(%s): log_flush %s mdb_cursor_get: (%d) %s",
						    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
						err = 0;
					} else {
						if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
							log_error(lg, "Dev(%s): log_flush %s mdb_cursor_get: (%d) %s, size %lu env_path %s",
							    dev->name, type_tag_name[ttag], err, mdb_strerror(err), dp_size, log->path);
							force_unavail = 1;
						} else {
							log_notice(lg, "Dev(%s): log_flush %s mdb_cursor_get: (%d) %s, size %lu, retry",
							    dev->name, type_tag_name[ttag], err, mdb_strerror(err), dp_size);
						}
						err = -EIO;
						goto _exit;
					}
				} else {
					size_t dupcount = 0;
					if (is_hashcount_data_type_tag(ttag)) {
						dupcount = 1;
						if (del_flag == MDB_NODUPDATA) {
							err = mdb_cursor_count(main_cursor[shard], &dupcount);
							if (err) {
								if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
									log_error(lg, "Dev(%s): log_flush %s mdb_cursor_count: (%d) %s env_path %s",
									    dev->name, type_tag_name[ttag], err, mdb_strerror(err), log->path);
									force_unavail = 1;
								} else {
									log_notice(lg, "Dev(%s): log_flush %s mdb_cursor_count: (%d) %s, retry",
									    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
								}
								err = -EIO;
								goto _exit;
							}
						}
					}
					err = mdb_cursor_del(main_cursor[shard], del_flag);
					if (RD_NO_FREE_SPACE(err)) {
						if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
							log_warn(lg, "Dev(%s): log_flush %s mdb_cursor_del: (%d) %s env_path %s part %d",
							    dev->name, type_tag_name[ttag], err, mdb_strerror(err), main_env_path, db->part);
							force_readonly = 1;
						} else {
							log_info(lg, "Dev(%s): log_flush %s mdb_cursor_del: (%d) %s",
							    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
						}
						err = 0;
						goto _exit;
					} else  if (err) {
						if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
							log_error(lg, "Dev(%s): log_flush %s mdb_cursor_del: (%d) %s, size %lu env_path %s part %d",
							    dev->name, type_tag_name[ttag], err, mdb_strerror(err), dp_size,  main_env_path, db->part);
							if (err == MDB_PAGE_FULL)
								force_readonly = 1;
							else
								force_unavail = 1;
							err = -EIO;
							goto _exit;
						} else if (err == MDB_PAGE_FULL && db->flush_error_count[ttag] == DEV_RD_FLUSH_ERROR_MAX) {
							/*
							 * MDB_PAGE_FULL workaround.
							 * Remove all processed log entries, drop the commit
							 * and try to flush one more time.
							 *
							 */
							log_notice(lg, "Dev(%s): log_flush %s MDB_PAGE_FULL error count exceeded, removing %u log entries",
							    dev->name, type_tag_name[ttag], rbkeys_i + 1);
							err = -EACCES;
						} else {
							log_notice(lg, "Dev(%s): log_flush %s mdb_cursor_del: (%d) %s, size %lu, retry",
							    dev->name, type_tag_name[ttag], err, mdb_strerror(err), dp_size);
							err = -EIO;
							goto _exit;
						}
					}
					if (!err && dupcount)
						reptrans_drop_hashcount(dev, &chid, dupcount);
					long sz = rd->metaloc.psize*2;
					commit_size += sz;
					if (rd_track_commit_size(sz)) {
						commit_max_reached = 1;
						break;
					}
					/*
					 * Here we don't drop rowusage counters because
					 * dupsort ttags aren't used there
					 */
				}
			} else if ((dev->status == REPDEV_STATUS_ALIVE || dev->status == REPDEV_STATUS_INIT)
				&& !force_readonly){
				/* allow unique key/data inserts only */
				err = mdb_cursor_put(main_cursor[shard], &dupkey, &dupdata, MDB_NODUPDATA);

				if (!err && is_hashcount_data_type_tag(ttag))
					reptrans_bump_hashcount(dev, &chid, 1);
				/* Don't bump rowusage because current ttag is dupsort */
				if (err == MDB_KEYEXIST) {
					log_debug(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
					    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
					err = 0;
				} else if (RD_NO_FREE_SPACE(err)) {
					if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
						log_warn(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s env_path %s part %d",
						    dev->name, type_tag_name[ttag], err, mdb_strerror(err),
						    main_env_path, db->part);
						force_readonly = 1;
					} else {
						log_info(lg, "Dev(%s): log_flush %s mdb_put: (%d) %s",
						    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
					}
					err = 0;
					goto _exit;
				} else if (err) {
					if (err != MDB_BAD_TXN) {
						if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
							log_error(lg, "Dev(%s): log_flush %s mdb_put (ksize=%ld dsize=%ld: (%d) %s env_path %s part %d",
							    dev->name, type_tag_name[ttag], key.mv_size, data.mv_size, err,
							    mdb_strerror(err), main_env_path, db->part);
							if (err == MDB_PAGE_FULL)
								force_readonly = 1;
							else
								force_unavail = 1;
							err = -EIO;
							goto _exit;
						} else if (err == MDB_PAGE_FULL && db->flush_error_count[ttag] == DEV_RD_FLUSH_ERROR_MAX) {
							/*
							 * MDB_PAGE_FULL workaround.
							 * Remove all processed log entries, drop the commit
							 * and try to flush one more time.
							 *
							 */
							log_notice(lg, "Dev(%s): log_flush %s MDB_PAGE_FULL error count exceeded, removing %u log entries",
							    dev->name, type_tag_name[ttag], rbkeys_i + 1);
							err = -EACCES;
						} else {
							/* Give it a chance to flush again with fewer number of entries */
							log_notice(lg, "Dev(%s): log_flush %s mdb_put (ksize=%ld dsize=%ld: (%d) %s, retry",
							    dev->name, type_tag_name[ttag], key.mv_size, data.mv_size, err, mdb_strerror(err));
							err = -EIO;
							goto _exit;
						}
					} else {
						/* Need to abort current transaction and
						 * retry later
						 */
						log_warn(lg, "Dev(%s): log_flush %s (%d) %s",
						    dev->name, type_tag_name[ttag],
						    err, mdb_strerror(err));
						err = 0;
						goto _exit;
					}
				}
			} else {
				/* Skip this entry since VDEV is read-only */
				err = -EAGAIN;
			}
			if (!err || err == -EACCES) {
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
				if (err == -EACCES) {
					delete_keys = 1;
					goto _exit;
				}
				rd->flushed_bytes += rd->metaloc.psize; /* ~ page size */
				long sz = rd->metaloc.psize*3;
				commit_size += sz;
				if (rd_track_commit_size(sz)) {
					commit_max_reached = 1;
					break;
				}
			}
		} while ((err = mdb_cursor_get(log_cursor, &key, &data, MDB_NEXT_DUP)) == 0);
	}

	for (int n = 0; n < DEV_SHARDS_MAX; n++) {
		if (main_cursor[n]) {
			mdb_cursor_close(main_cursor[n]);
			main_cursor[n] = NULL;
		}
	}
	mdb_cursor_close(log_cursor);
	log_cursor = NULL;

	rdlog_txn_abort(log, log_txn);
	log_txn = NULL;
	/*
	 * Last mdb error can only be MDB_NOTFOUND
	 * Otherwise log is corrupted
	 */
	if (err && err != MDB_NOTFOUND) {
		rdlog_repair(log, err);
		goto _exit;
	}

	if (rbkeys_i > 0 || (md_txn && mdcache_queue_len(rd->mdcache))) {
		const char* mdenv_path = NULL;
		mdb_env_get_path(rd->mdcache_env, &mdenv_path);

		if (md_txn) {
			err = 0;
			if (mdcache_blocked) {
				if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
					log_error(lg, "Dev(%s): log_flush md_txn %s mdcache blocked: aborted env_path %s",
					    dev->name, type_tag_name[ttag], mdenv_path);
					force_unavail = 1;
				} else {
					/* Give it a chance to flush again with fewer number of entries */
					log_notice(lg, "Dev(%s): log_flush md_txn %s mdcache blocked: retrying",
					    dev->name, type_tag_name[ttag]);
				}
				err = -EIO;
				goto _exit;
			}

			if (keydb_blocked) {
				if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
					log_error(lg, "Dev(%s): log_flush md_txn %s keydb blocked: aborted env_path %s",
					    dev->name, type_tag_name[ttag], mdenv_path);
					force_unavail = 1;
				} else {
					/* Give it a chance to flush again with fewer number of entries */
					log_notice(lg, "Dev(%s): log_flush md_txn %s keydb blocked: retrying",
					    dev->name, type_tag_name[ttag]);
				}
				err = -EIO;
				goto _exit;
			}
			if (rd->mdcache_enable) {
				int n_flushed = 0;
				err = mdcache_flush(rd->mdcache, md_txn, &n_flushed);
				if (err) {
					if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
						log_error(lg, "Dev(%s): log_flush mdcache_%s flush: (%d): aborted env_path %s",
						    dev->name, type_tag_name[ttag], err, mdenv_path);
						force_unavail = 1;
					} else {
						/* Give it a chance to flush again with fewer number of entries */
						log_notice(lg, "Dev(%s): log_flush mdcache_%s flush: (%d), retrying",
						    dev->name, type_tag_name[ttag], err);
					}
					err = -EIO;
					goto _exit;
				}
			}
			if (md_txn != main_txn)
				err = mdb_txn_commit(md_txn);
			md_txn = NULL;
			if (err) {
				if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
					log_error(lg, "Dev(%s) log_flush md_txn %s mdb_txn_commit: (%d) %s, aborted env_path %s",
						dev->name, type_tag_name[ttag], err, mdb_strerror(err), mdenv_path);
					force_unavail = 1;
				} else {
					/* Give it a chance to flush again with fewer number of entries */
					log_error(lg, "Dev(%s) log_flush md_txn %s mdb_txn_commit: (%d) %s, retrying",
						dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				}
				err = -EIO;
				goto _exit;
			}
		}
		if (rbkeys_i > 0) {
			err = mdb_txn_commit(main_txn);
			main_txn = NULL;
			if (err) {
				if (RD_NO_FREE_SPACE(err)) {
					if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
						log_warn(lg, "Dev(%s): log_flush %s mdb_txn_commit: (%d) %s env_path %s part %d",
							dev->name, type_tag_name[ttag], err, mdb_strerror(err),
							main_env_path, db->part);
						force_readonly = 1;
					} else {
						log_info(lg, "Dev(%s): log_flush %s mdb_txn_commit: (%d) %s",
							dev->name, type_tag_name[ttag], err, mdb_strerror(err));
					}
					err = -ENOSPC;
				} else {
					if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
						log_error(lg, "Dev(%s): log_flush main_txn %s mdb_txn_commit: (%d) %s env_path %s part %d",
							dev->name, type_tag_name[ttag], err, mdb_strerror(err),
							main_env_path, db->part);
						if (err == MDB_PAGE_FULL)
							force_readonly = 1;
						else
							force_unavail = 1;
					} else if (err == MDB_PAGE_FULL && db->flush_error_count[ttag] == DEV_RD_FLUSH_ERROR_MAX) {
						/*
						 * MDB_PAGE_FULL workaround.
						 * Remove all processed log entries, drop the commit
						 * and try to flush one more time.
						 */
						log_notice(lg, "Dev(%s): log_flush %s MDB_PAGE_FULL error count exceeded, removing %u log entries",
						    dev->name, type_tag_name[ttag], rbkeys_i + 1);
						err = -EACCES;
						delete_keys = 1;
					} else {
						/* Give it a chance to flush again with fewer number of entries */
						log_notice(lg, "Dev(%s): log_flush main_txn %s mdb_txn_commit: (%d) %s, retry",
							dev->name, type_tag_name[ttag], err, mdb_strerror(err));
					}
					err = -EIO;
				}
				goto _exit;
			}
			db->flush_error_count[ttag] = 0;
		}
	} else {
		if (md_txn && md_txn != main_txn)
			mdb_txn_abort(md_txn);

		mdb_txn_abort(main_txn);

		main_txn = NULL;
		md_txn = NULL;
		err = 0;
	}

	delete_keys = 1;

_exit:
	rd_track_commit_size(-commit_size);

	for (int n = 0; n < DEV_SHARDS_MAX; n++) {
		if (main_cursor[n])
			mdb_cursor_close(main_cursor[n]);
	}

	if (md_txn && md_txn != main_txn)
		mdb_txn_abort(md_txn);
	if (main_txn)
		mdb_txn_abort(main_txn);
	if (log_cursor)
		mdb_cursor_close(log_cursor);
	if (log_txn)
		rdlog_txn_abort(log, log_txn);

	if (delete_keys && rbkeys_i == 0) {
		rtbuf_destroy(rbkeys);
		rbkeys = NULL;
	} else if (delete_keys) {

		/* adjust rbkeys array len */
		rbkeys->nbufs = rbkeys_i;

		log->delete_rbkeys = rbkeys;
		log->ttag = ttag;
		err = rd_log_delete_deferred(log);
		if (err) {
			if (++db->flush_error_count[ttag] > DEV_RD_FLUSH_ERROR_MAX) {
				log_error(lg, "Dev(%s): rd_log_delete_deferred %s: (%d) env_path %s",
					dev->name, type_tag_name[ttag], err, log->path);
				force_unavail = 1;
			} else {
				/* Give it a chance to flush again with fewer number of entries */
				log_notice(lg, "Dev(%s): rd_log_delete_deferred %s: (%d)",
					dev->name, type_tag_name[ttag], err);
			}
		}
		uint64_t  flushed_ts = uv_hrtime();
		log_debug(lg, "Dev(%s): %s journal flushed %u records (%ldus)",
		    dev->name, type_tag_name[ttag], is_dupsort_tt(ttag) ? rbkeys_i/2 : rbkeys_i,
			(flushed_ts - start_us) / 1000);
		log->flushed_timestamp = flushed_ts;

	}

	if (rbkeys) {
		rtbuf_destroy(rbkeys);
		rbkeys = NULL;
	}

	if (force_unavail) {
		struct rd_fault_signature fs = {
			.error = err,
			.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
	} else if (force_readonly) {
		struct rd_fault_signature fs = {
			.error = err,
			.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
			.plevel = db->part + 1
		};
		rd_set_ro_fault(dev, &fs);
	}
	/* Repeat the flush because not all delete entries were flushed */
	if ((delete_max_reached | commit_max_reached) && !err && !force_unavail && !force_readonly) {
		log_info(lg, "Dev(%s) collected %lu delete items to flush for %s, "
			"flushed total %ld MB, total entries %lu, repeating", dev->name, n_del_entries,
			type_tag_name[ttag], commit_size/(1024L*1024L), n_log_entries);
		goto _start;
	}

	dev->flushing &= ~(1 << ttag);
	dev->flushing_part &= ~(1 << db->part);

	uv_mutex_lock(&db->log_flush_lock);
	db->log_flush_cnt = 0;
	db->log_flushed_ttag = ttag;
	uv_cond_broadcast(&db->log_flush_condvar);
	uv_mutex_unlock(&db->log_flush_lock);
}

static int
rd_log_flush(struct repdev_log *log, type_tag_t ttag)
{
	struct repdev *dev = log->dev;
	struct repdev_db *db = log->db;
	int err;

	if(dev->rt->flags & RT_FLAG_RDONLY)
		return 0;

	/* block writers for this partition */
	uv_mutex_lock(&db->log_flush_lock);
	while (db->log_flush_cnt != 0) {
		uv_cond_wait(&db->log_flush_condvar,
		    &db->log_flush_lock);
	}
	db->log_flush_cnt = pthread_self();

	log->ttag = ttag;
	pthread_attr_t attr;
	err = pthread_attr_init(&attr);
	if (!err)
		err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (!err)
		err = pthread_create(&log->flush_thread, &attr,
			(void *)&rd_log_flush_thread, (void *)log);
	if (err) {
		log_error(lg, "Dev(%s): log_flush_thread create %s: (%d) %s",
		    dev->name, type_tag_name[ttag], err, strerror(err));
		err = 0;
		db->log_flush_cnt = 0;
		uv_cond_signal(&db->log_flush_condvar);
	}
	pthread_attr_destroy(&attr);
	uv_mutex_unlock(&db->log_flush_lock);
	return err;
}

/**
 * NOTE: rd_log_append() may return
 * 1) -EBUSY if WAL is being recovered, cannot append
 * 2) -FAULT if there was an unrecoverable error during transaction.
 *     The WAL has been re-created and ready for work, but the last entry
 *     haven't been stored.
 * 3) -EIO if another error has happened
 */
static int
rd_log_append(struct repdev *dev, struct repdev_log *log, type_tag_t ttag,
		crypto_hash_t hash_type, uv_buf_t *keybuf, const rtbuf_t *rb,
		uint64_t attr)
{
	int err = 0, again_cnt = 0;
	MDB_txn *txn = NULL;
	MDB_val key, data;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = log->db;
	MDB_dbi dbi = log->dbi[ttag];
	size_t len = rtbuf_len(rb);

	data.mv_size = len;

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
	 * and SSDs used as a holders of journal. See "sync" rt-rd.json flag.
	 *
	 * Journal stores keys as is, i.e. without keyhash! That is so that we
	 * can implement sharded log_flush() later on..
	 */
_again:
	err = rdlog_txn_try_begin(log, 0, &txn);
	if (err) {
		/* Returns EBUSY when log is being recovered, we should
		 * write to the main db this time. The EAGAIN when no more
		 * reader locks are allowed, must never happen
		 */
		if (err != EBUSY) {
			log_error(lg, "Dev(%s): log_append mdb_txn_begin: (%d) %s log_env %s",
			    dev->name, err, mdb_strerror(err), log->path);
			rdlog_unlock(log);
			err = rdlog_repair(log, err);
			if (!err)
				err = -EFAULT;
			else
				err = -EIO;
		} else
			err = -EBUSY;
		goto _exit;
	}

	size_t ttag_entries = 0;
	size_t log_size = 0;
	for(type_tag_t i = TT_NAMEINDEX; i < TT_LAST; i++) {
		if (!is_log_tt(dev, i))
			continue;

		MDB_stat stat;
		MDB_dbi i_dbi = log->dbi[i];
		err = mdb_stat(txn, i_dbi, &stat);
		if (err) {
			log_error(lg, "Dev(%s): log_append %s mdb_stat: (%d) %s log_env %s",
			    dev->name, type_tag_name[i], err, mdb_strerror(err), log->path);
			rdlog_txn_abort(log, txn);
			txn = NULL;
			err = rdlog_repair(log, err);
			if (err) {
				err = -EIO;
				goto _exit;
			} else
				goto _again;
		}

		log_size += stat.ms_psize * (stat.ms_branch_pages +
		    stat.ms_leaf_pages + stat.ms_overflow_pages);

		if (ttag == i)
			ttag_entries = stat.ms_entries;
	}

	if (log_size > DEV_RD_JPART_MINSIZE(rd->plevel)/4ULL ||
	    ttag_entries > DEV_LMDB_LOG_TT_MAXENTRIES(ttag, dev)) {
		/* abort before flush */
		rdlog_txn_abort(log, txn);
		txn = NULL;

		/* block writers and flush the log because we approuching
		 * configurable limits */
		type_tag_t just_flushed = 0;
		int wait_cnt = 0;
		while (ttag_entries > 2*DEV_LMDB_LOG_TT_MAXENTRIES(ttag, dev)
			&& !dev->terminating) {
			wait_cnt++;

			uv_mutex_lock(&db->log_flush_lock);
			err = uv_cond_timedwait(&db->log_flush_condvar,
			    &db->log_flush_lock, 100000LL); // 100us
			if (err >= 0)
				just_flushed = db->log_flushed_ttag;
			else
				just_flushed = 0;

			uv_mutex_unlock(&db->log_flush_lock);

			if (just_flushed) {
				/* doesn't matter which ttag, recheck log space */
				MDB_txn *txn2;
				err = rdlog_txn_try_begin(log, MDB_RDONLY, &txn2);
				if (err) {
					if (err != EBUSY) {
						rdlog_unlock(log);
						log_error(lg, "Dev(%s): log_append mdb_txn_begin: (%d) %s log_env %s",
						    dev->name, err, mdb_strerror(err), log->path);
						err = rdlog_repair(log, err);
						if (!err)
							err = -EFAULT;
						else
							err = -EIO;
					} else
						err = -EBUSY;
					goto _exit;
				}
				/* get new log_size */
				log_size = 0;
				ttag_entries = 0;
				for(type_tag_t i = TT_NAMEINDEX; i < TT_LAST; i++) {
					if (!is_log_tt(dev, i))
						continue;

					MDB_stat stat;
					MDB_dbi i_dbi = log->dbi[i];
					err = mdb_stat(txn2, i_dbi, &stat);
					if (err) {
						rdlog_txn_abort(log, txn2);
						log_error(lg, "Dev(%s): log_append %s mdb_stat: (%d) %s log_env %s",
						    dev->name, type_tag_name[i], err, mdb_strerror(err), log->path);
						err = -EIO;
						goto _exit;
					}

					log_size = stat.ms_psize * (stat.ms_branch_pages +
					    stat.ms_leaf_pages + stat.ms_overflow_pages);

					if (ttag == i)
						ttag_entries = stat.ms_entries;
				}

				rdlog_txn_abort(log, txn2);
			}
			/* block others for a bit longer if log still full */
			if (log_size < DEV_RD_JPART_MINSIZE(rd->plevel)/2ULL)
				break;
		}

		log_debug(lg, "Dev(%s): log_append wait_cnt %d just_flushed %d %s "
		    "log_entries %ld log_size %luMB",
		    dev->name, wait_cnt, just_flushed, type_tag_name[ttag],
		    ttag_entries, log_size/1024/1024UL);

		if ((!db->log_flush_cnt && !(just_flushed == ttag) &&
		    (ttag_entries > DEV_LMDB_LOG_TT_MAXENTRIES(ttag, dev))) ||
		     (log_size > 7ULL*(DEV_RD_JPART_MINSIZE(rd->plevel))/10ULL -
		      dev->journal_maxchunksize) ||
		      (ttag_entries > 32*DEV_LMDB_LOG_TT_MAXENTRIES(ttag, dev))) {
			err = rd_log_flush(log, ttag);
			if (err) {
				return err;
			}
		}

		/* reopen read-write txn again and do append */
		err = rdlog_txn_try_begin(log, 0, &txn);
		if (err) {
			assert(err != EAGAIN);
			if (err != EBUSY) {
				log_error(lg, "Dev(%s): log_append mdb_txn_begin: (%d) %s log_env %s",
				    dev->name, err, mdb_strerror(err), log->path);
				rdlog_unlock(log);
				err = rdlog_repair(log, err);
				if (!err)
					err = -EFAULT;
				else
					err = -EIO;
			} else
				err = -EBUSY;
			goto _exit;
		}
	}

	key.mv_size = keybuf->len;
	key.mv_data = keybuf->base;

	err = rd_kv_validate(ttag, &key, &data);
	if (err) {
		err = -EINVAL;
		goto _exit;
	}
	if (is_dupsort_tt(ttag)) {
		assert(rb->nbufs <= 1);
		assert(data.mv_size < 511);
		data.mv_data = len ? rtbuf(rb, 0).base : NULL;

		uint8_t* del_ptr = je_calloc(1, len + DUPSORT_DEL_MAGIC_SIZE);
		if (!del_ptr) {
			err = -ENOMEM;
			goto _exit;
		}
		MDB_val data_del = {.mv_size = len + DUPSORT_DEL_MAGIC_SIZE,
				.mv_data = del_ptr};
		memcpy(data_del.mv_data, data.mv_data, data.mv_size);
		memcpy((uint8_t*)data_del.mv_data + data.mv_size, DUPSORT_DEL_MAGIC, DUPSORT_DEL_MAGIC_SIZE);
		MDB_cursor* cur = NULL;
		err = mdb_cursor_open(txn, dbi, &cur);
		if (err) {
			log_error(lg, "Dev(%s): log_append %s mdb_cursor_open: (%d) %s log_env %s",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err), log->path);
			rdlog_txn_abort(log, txn);
			txn = NULL;
			err = rdlog_repair(log, err);
			if (!err)
				err = -EFAULT;
			else
				err = -EIO;
			goto _exit;
		}
		if (attr == 0) {
			/* Delete case. If data isn't provided, then remove all duplicates.
			 * Otherwise remove only the requested entry
			 * IMPORTANT: log comparator has to put the
			 * all dupsort delete request to the first position
			 * */
			err = mdb_cursor_get(cur, &key, data.mv_size ? &data : NULL,
				data.mv_size ? MDB_GET_BOTH : MDB_SET);
			if (err && err != MDB_NOTFOUND) {
				log_error(lg, "Dev(%s): log_append %s mdb_cursor_get: (%d) %s log_path %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err), log->path);
				mdb_cursor_close(cur);
				cur = NULL;
				rdlog_txn_abort(log, txn);
				txn = NULL;
				err = rdlog_repair(log, err);
				if (!err)
					err = -EFAULT;
				else
					err = -EIO;
				goto _exit;
			} else if (!err){
				err = mdb_cursor_del(cur, data.mv_size ? 0 : MDB_NODUPDATA);
				if (err)
					goto _check_err;
			}
			/* Add the delete request to the WAL to flush it to main TT */
			err = mdb_cursor_put(cur, &key, &data_del, MDB_NODUPDATA);
			mdb_cursor_close(cur);
			if (err == MDB_KEYEXIST)
				err = 0;
			if (err)
				goto _check_err;
		} else {
			assert(data.mv_size);
			/* dupsort append case. Remove a pending removal requests (if any)*/
			err = mdb_cursor_get(cur, &key, &data_del, MDB_GET_BOTH);
			if (err && err != MDB_NOTFOUND) {
				log_error(lg, "Dev(%s): log_append %s mdb_cursor_get: (%d) %s log_env %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err),
				    log->path);
				err = -EIO;
				goto _exit;
			} else if (!err) {
				err = mdb_cursor_del(cur, 0);
				if (err)
					goto _check_err;
			}
			/* Add the put request to the WAL to flush it to main TT */
			err = mdb_cursor_put(cur, &key, &data, MDB_NODUPDATA);
			mdb_cursor_close(cur);
			if (err == MDB_KEYEXIST)
				err = 0;
		}
_check_err:
		je_free(del_ptr);
		if (err) {
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (RD_NO_FREE_SPACE(err)) {
				log_debug(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
			} else {
				log_error(lg, "Dev(%s): log_append %s mdb error: (%d) %s, "
					"attr %lu, data size %lu, key size %lu log_env %s",
					dev->name, type_tag_name[ttag], err,
					mdb_strerror(err), attr, data.mv_size,
					key.mv_size, log->path);
				mdb_cursor_close(cur);
				cur = NULL;
				rdlog_txn_abort(log, txn);
				txn = NULL;
				err = rdlog_repair(log, err);
				if (!err)
					err = -EFAULT;
				else
					err = -EIO;
			}
			goto _exit;
		}
	} else {

		data.mv_data = NULL; /* MDB_RESERVE */

		unsigned int flags = MDB_RESERVE;
		/*
		 * There are 3 different options:
		 * 1) attr == 0 && len == 0 - delete case, overwrite an existing blob
		 * 2) attr > 0 && len == 0 - change blob attribute only. Don't overwrite
		 * 3) attr > 0 && len > 0 - put new blob. Overwrite case. We cannot
		 *        rely on key/data uniqueness since some TTs are stored with
		 *        a "foreign" CHID (TT_PARTIY_MANIFEST)
		 */
		flags |= (!len && attr) ? MDB_NOOVERWRITE : 0;
		err = mdb_put_attr(txn, dbi, &key, &data, attr, flags);
		if (err == MDB_KEYEXIST) {
			err = mdb_set_attr(txn, dbi, &key, NULL, attr);
			data.mv_data = NULL;
		}
		if (err) {
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (RD_NO_FREE_SPACE(err)) {
				log_debug(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
			} else {
				log_error(lg, "Dev(%s): log_append %s mdb_put_set_attr: (%d) "
					"%s attr %lu key size %lu data size %lu log_path %s", dev->name,
					type_tag_name[ttag], err, mdb_strerror(err), attr,
					key.mv_size, data.mv_size, log->path);
				rdlog_txn_abort(log, txn);
				txn = NULL;
				err = rdlog_repair(log, err);
				if (!err)
					err = -EFAULT;
				else
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

	err =rdlog_txn_commit(log, txn);
	txn = NULL;
	if (err) {
		if (again_cnt++ < 3) {
			err = rd_log_flush(log, ttag);
			if (err) {
				return err;
			}
			usleep(100000);
			goto _again;
		}
		if (RD_NO_FREE_SPACE(err)) {
			log_warn(lg, "Dev(%s): log_append %s log_size %ld entries %ld mdb_txn_commit: (%d) %s",
			    dev->name, type_tag_name[ttag], log_size, ttag_entries, err, mdb_strerror(err));
			err = -ENOSPC;
		} else {
			log_error(lg, "Dev(%s): log_append %s log_size %ld entries %ld mdb_txn_commit: (%d) %s log_env %s",
			    dev->name, type_tag_name[ttag], log_size, ttag_entries, err, mdb_strerror(err), log->path);
			err = rdlog_repair(log, err);
			if (!err)
				err = -EFAULT;
			else
				err = -EIO;
		}
	}

_exit:
	if (txn)
		rdlog_txn_abort(log, txn);

	if (!err && (is_keycache_tt(ttag) || ttag == TT_NAMEINDEX)) {
		MDB_txn* md_txn = NULL;
		MDB_val keyhv;
		uint64_t kh;
		err = rd_keyhash(dev, &key, &keyhv, &kh);
		if (err)
			return err;
		if (ttag == TT_NAMEINDEX && !attr) {
			rd_bloom_insert(db, kh);
		} else {
			if (data.mv_size) {
				rd_bloom_insert(db, kh);
				key_cache_insert(db->key_cache, &kh, ttag, data.mv_size);
			} else if (!attr)
				key_cache_remove(db->key_cache, &kh, ttag);
		}
		/* Journal is updated on WAL flush */
	}
	return err;
}

static int
rd_put_blob_with_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid, uint64_t attr,
    uint64_t options)
{
	struct repdev_rd *rd = dev->device_lfs;
	int err = 0, mdb_err = 0, log_inserted = 1;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	msgpack_p *ptk = NULL;
	MDB_val key, data;
	size_t len = rtbuf_len(rb);
	MDB_txn *txn = NULL;
	size_t put_len = 0;
	int overwrite = options & REPDEV_PUT_OPT_OVERWRITE;

	assert (ttag != TT_HASHCOUNT);

	err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		err = -ENOENT;
		goto _exit;
	}
	rt_set_thread_vdev_context(dev);

	err = rd_key_encode(dev, ttag, hash_type, chid, &ptk, &db, &dbi,
	    &log);
	if (err)
		goto _exit;

	uv_buf_t keybuf;
	msgpack_get_buffer(ptk, &keybuf);

	key.mv_size = keybuf.len;
	key.mv_data = keybuf.base;
	data.mv_size = len;

	if (!overwrite && is_log_tt(dev, ttag) && (rtbuf_len(rb) < dev->journal_maxchunksize)) {
		/* For dupsort operations use attr as follow:
		 * 0 - delete entry, 1 - put entry
		 */
		int cnt = 5;
		if (is_dupsort_tt(ttag))
			attr = 1;
		do {
			err = rd_log_append(dev, log, ttag, hash_type, &keybuf,
				rb, attr);
		} while (err == -EFAULT && --cnt);

		assert (err != -EEXIST);

		if (err != -ENOSPC && err != -EBUSY)
			goto _term;
		/*
		 * instead of returning error, need to try to add this
		 * entry to the main TT store, so we will fall through..
		 */
	}

	err = rd_kv_validate(ttag, &key, &data);
	if (err) {
		err = -EINVAL;
		goto _term;
	}
	/*
	 * Place this chunk directly into main TT data store
	 */
	const char* env_path = NULL;
	mdb_env_get_path(DEV_ENV(db, ttag), &env_path);

	err = mdb_txn_begin(DEV_ENV(db, ttag), NULL, 0, &txn);
	if (err) {
		struct rd_fault_signature fs = {
			.error = err,
			.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		log_error(lg, "Dev(%s): put_blob mdb_txn_begin: (%d) %s env_path %s part %d",
		    dev->name, err, mdb_strerror(err), env_path, db->part);
		err = -EIO;
		goto _exit;
	}

	data.mv_data = rtbuf(rb, 0).base;

	if (is_dupsort_tt(ttag)) {
		assert(rb->nbufs == 1);
		assert(data.mv_size < 511);

		err = mdb_put(txn, dbi, &key, &data, MDB_NODUPDATA);
		if (err) {
			mdb_err = err;
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): put_blob_with_attr %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = 0;
			} else if (RD_NO_FREE_SPACE(err)) {
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_set_ro_fault(dev, &fs);
				log_warn(lg, "Dev(%s): put_blob_with_attr %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
			} else {
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				log_error(lg, "Dev(%s): put_blob_with_attr %s mdb_put: (%d) %s env_path %s part %d",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err), env_path, db->part);
				err = -EIO;
			}
			goto _exit;
		}
	} else {
		if (overwrite && !dev->wal_disabled) {
			MDB_txn *log_txn = NULL;
			do {
			err = rdlog_txn_try_begin(log, 0, &log_txn);
				if (err) {
					/* Returns EBUSY when log is being recovered, we should
					 * write to the main db this time. The EAGAIN when no more
					 * reader locks are allowed, must never happen
					 */
					if (err != EBUSY) {
						log_error(lg, "Dev(%s): log_append mdb_txn_begin: (%d) %s log_env %s",
						    dev->name, err, mdb_strerror(err), log->path);
						rdlog_unlock(log);
						err = rdlog_repair(log, err);
						if (err)
							err = -EIO;;
					} else
						err = -EBUSY;
				}
			} while (err == -EBUSY);
			if (err) {
				log_error(lg, "Dev(%s) log_open error: (%d) env_path %s part %d",
					dev->name, err, env_path, db->part);
				goto _term;
			}
			err = mdb_del(log_txn, log->dbi[ttag], &key, NULL);
			if (!err)
				err = rdlog_txn_commit(log, log_txn);
			else
				rdlog_txn_abort(log, log_txn);

			if (err && err != MDB_NOTFOUND) {
				log_error(lg, "Dev(%s): log delete mdb_txn_commit: (%d) %s log_env %s",
				    dev->name, err, mdb_strerror(err), log->path);
				goto _term;
			}
			err = 0;
		}
		unsigned int flags = MDB_RESERVE;
		flags |= overwrite ? 0 : MDB_NOOVERWRITE;
		err = mdb_put_attr(txn, dbi, &key, &data, attr, flags);
		if (err == MDB_KEYEXIST && attr) {
			err = mdb_set_attr(txn, dbi, &key, NULL, attr);
		} else if (!err) {
			size_t copied = 0;
			for (int i = 0; i < (int)rb->nbufs; i++) {
				memcpy((char *)data.mv_data + copied, rtbuf(rb, i).base,
				    rtbuf(rb, i).len);
				copied += rtbuf(rb, i).len;
			}
			put_len = copied;
		}
		if (err) {
			mdb_err = err;
			if (err == MDB_KEYEXIST) {
				log_debug(lg, "Dev(%s): "
					"put_blob %s mdb_put: (%d) %s",
					dev->name, type_tag_name[ttag],
					err, mdb_strerror(err));
				err = 0;
			} else if (RD_NO_FREE_SPACE(err)) {
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_set_ro_fault(dev, &fs);
				log_warn(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
					dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
			} else {
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				log_error(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s env_path %s part %d",
					dev->name, type_tag_name[ttag], err, mdb_strerror(err),
					env_path, db->part);
				err = -EIO;
			}
			goto _exit;
		}
	}

	err = mdb_txn_commit(txn);
	txn = NULL;
	if (err) {
		struct rd_fault_signature fs = {
			.error = err,
			.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		log_error(lg, "Dev(%s): put_blob %s mdb_txn_commit: (%d) %s env_path %s part %d",
		    dev->name, type_tag_name[ttag], err, mdb_strerror(err), env_path, db->part);
		err = -EIO;
		goto _exit;
	} else if (!mdb_err) {
		if (is_hashcount_data_type_tag(ttag))
			reptrans_bump_hashcount(dev, chid, 1);
		if (is_rowusage_data_type_tag(ttag))
			reptrans_bump_rowusage(dev, chid, put_len);
	}

_exit:
	if (txn)
		mdb_txn_abort(txn);

	if (!err && (is_keycache_tt(ttag) || ttag == TT_NAMEINDEX) && data.mv_size) {
		MDB_val keyhv;
		uint64_t kh;
		err = rd_keyhash(dev, &key, &keyhv, &kh);
		if (err) {
			pthread_rwlock_unlock(&rd->guard);
			if (ptk)
				msgpack_pack_free(ptk);
			return err;
		}

		/* on success: update caches so that query_blob() can be
		 * effective */
		rd_bloom_insert(db, kh);

		if (ttag != TT_NAMEINDEX) {
			key_cache_insert(db->key_cache, &kh, ttag, data.mv_size);

			/* insert into a journal if defined*/
			if (dev->journal) {
				rd_key_insert(dev, ttag, NULL, &kh, data.mv_size, attr);
				if (is_mdcache_tt(dev, ttag) && rd->mdcache_enable && rb->nbufs == 1) {
					struct repdev_rd *rd = dev->device_lfs;
					err = mdcache_enqueue(rd->mdcache, ttag, &kh,
					    data.mv_data, data.mv_size);
					if (err) {
						log_warn(lg, "Dev(%s) put_blob: mdcache_enqueue: %d",
							dev->name, err);
						err = 0;
					}
				}
			}
		}
	}
_term:
	pthread_rwlock_unlock(&rd->guard);
	if (ptk)
		msgpack_pack_free(ptk);
	return err;
}

static int
rd_put_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const rtbuf_t *rb, uint512_t *chid)
{
	return rd_put_blob_with_attr(dev, ttag, hash_type, rb, chid, 2, 0);
}

static int
rd_set_blob_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uint64_t attr)
{
	int err;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi_main;
	msgpack_p *ptk = NULL;
	MDB_val keyhv;
	uint64_t kh;

	err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		err = -ENODEV;
		goto _exit;
	}

	rt_set_thread_vdev_context(dev);
	err = rd_key_encode(dev, ttag, hash_type, chid, &ptk, &db, &dbi_main,
	    &log);
	if (err)
		goto _exit;

	uv_buf_t keybuf;
	msgpack_get_buffer(ptk, &keybuf);

	MDB_val key;
	key.mv_size = keybuf.len;
	key.mv_data = keybuf.base;

	if (is_keycache_tt(ttag)) {
		err = rd_keyhash(dev, &key, &keyhv, &kh);
		if (err)
			goto _exit;

		if (!rd_bloom_query(db, kh)) {
			err = -ENOENT;
			goto _exit;
		}
	}


	if (is_log_tt(dev, ttag) && !is_dupsort_tt(ttag)) {
		rtbuf_t rb = { .bufs = NULL, .nbufs = 0 };
		msgpack_get_buffer(ptk, &keybuf); /* it can be overwritten in keyhash */
		int cnt = 5;
		do {
			err = rd_log_append(dev, log, ttag, hash_type, &keybuf, &rb,
				attr);
		} while (err == -EFAULT && --cnt);

		assert (err != -EEXIST);

		if (err != -ENOSPC && err != -EBUSY)
			goto _exit;
		/*
		 * instead of returning error, need to try to add attribute
		 * directly into the main TT store, so we will fall through..
		 */
	}

	err = rd_kv_validate(ttag, &key, NULL);
	if (err) {
		err = -EINVAL;
		goto _exit;
	}
	/* do not touch HDD if journal defined */
	if (dev->journal && is_keycache_tt(ttag)) {
		err = rd_key_set_attr(dev, ttag, NULL, &kh, attr);
		if (err) {
			log_error(lg, "Dev(%s): rd_key_set_attr: (%d) %s",
			    dev->name, err, mdb_strerror(err));
		}
	} else {
		MDB_txn *txn;
		const char* env_path = NULL;
		mdb_env_get_path(DEV_ENV(db, ttag), &env_path);

		/*
		 * Set attribute to the chunk directly into main TT data store
		 */
		err = mdb_txn_begin(DEV_ENV(db, ttag), NULL, 0, &txn);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			log_error(lg, "Dev(%s): put_blob mdb_txn_begin: (%d) %s env_path %s part %d",
			    dev->name, err, mdb_strerror(err), env_path, db->part);
			err = -EIO;
			goto _exit;
		}

		err = mdb_set_attr(txn, dbi_main, &key, NULL, attr);
		if (err) {
			mdb_txn_abort(txn);
			if (err == MDB_NOTFOUND) {
				err = -ENOENT;
			} else if (RD_NO_FREE_SPACE(err)) {
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_set_ro_fault(dev, &fs);
				log_warn(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err));
				err = -ENOSPC;
			} else {
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				log_error(lg, "Dev(%s): put_blob %s mdb_put: (%d) %s env_path %s part %d",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err),
				    env_path, db->part);
				err = -EIO;
			}
			goto _exit;
		}

		err = mdb_txn_commit(txn);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			log_error(lg, "Dev(%s): put_blob %s mdb_txn_commit: (%d) %s env_path %s part %d",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err),
			    env_path, db->part);
			err = -EIO;
			goto _exit;
		}
	}

_exit:
	pthread_rwlock_unlock(&rd->guard);
	if (ptk)
		msgpack_pack_free(ptk);
	return err;
}

static int
rd_stat_filter(void *arg, void **data, size_t *size, int set)
{
	struct blob_stat *bs = arg;

	if (set)
		return 0;

	if (bs)
		bs->size = *size;
	return 0;
}

struct rd_lookup_stat {
	size_t n_del_log; /* Number of delete entries in the log */
	size_t n_ht_log; /* Number of values added to skip array */
	size_t n_log;	/* Number of valid values in the log */
	size_t n_dup_main; /* number of valid entries found in main table */
	size_t n_skip_main; /* number of entries skipped in main table */
};

static int
rd_log_lookup(struct repdev *dev, struct repdev_db *db, struct repdev_log *log,
    MDB_dbi dbi_main, int ttag, int flags, uv_buf_t *keybuf, crypto_hash_t hash_type,
	rtbuf_t *rb, int max_num, reptrans_blob_filter filter_cb, void *arg,
	uint64_t *attrp, int no_mdcache)
{
	int err = 0;
	MDB_val key, data = { .mv_size = 0, .mv_data = NULL };
	MDB_val usr_data = { .mv_size = 0, .mv_data = NULL };
	struct repdev_rd *rd = dev->device_lfs;
	MDB_cursor *cursor = NULL;
	MDB_txn *txn = NULL;
	MDB_dbi dbi;
	int found = 0, repeat;
	MDB_val keyhv;
	uint64_t kh;
	size_t dupcount = 0;
	int dupcount_noent = 0;
	int mapped = rd->zerocopy >= 2;

	/* For dupsort TT we keep a hash table for blobs scheduled for removal
	 * and a two linked list of values (log and main) in order to merge
	 * them later and create ordered de-duplicated array of values.
	 */
	struct mlist_node *list_main = NULL;
	size_t main_count = 0;
	struct mlist_node *list_log = NULL;
	size_t log_count = 0;


	struct rd_lookup_stat st = {.n_log = 0};
	struct rt_lhtbl* ht = NULL;
	if (is_dupsort_tt(ttag)) {
		ht = rt_lhtbl_create(DEV_LMDB_LOG_DUPSORT_MAXENTRIES);
		if (!ht)
			return -ENOMEM;
	}

	if (filter_cb && filter_cb != rd_stat_filter)
		filter_cb(arg, &usr_data.mv_data, &usr_data.mv_size, 1);

	if (is_log_tt(dev, ttag) && !(flags & GBF_FLAG_NO_WAL)) {
		/*
		 * Lookup in journal log first (in memory lookup) then in
		 * TT main db.
		 */
		dbi = log->dbi[ttag];
		repeat = 0;
	} else {
		/*
		 * This is direct TT main lookup.
		 */
		dbi = dbi_main;
		repeat = 1;
	}

	key.mv_size = keybuf->len;
	key.mv_data = keybuf->base;

_repeat:
	data = usr_data;
	if (is_keycache_tt(ttag)) {
		err = rd_keyhash(dev, &key, &keyhv, &kh);
		if (err)
			goto _exit;

		if (!rd_bloom_query(db, kh)) {
			err = MDB_NOTFOUND;
			goto _exit;
		}

		uint64_t outsize;
		err = key_cache_lookup(db->key_cache, &kh, ttag, &outsize);
		if (!err && filter_cb == rd_stat_filter) {
			/* found and we doing just stat_blob() - done */
			filter_cb(arg, NULL, &outsize, 0);
			return 0;
		} else
			err = 0;

		if (repeat && dev->journal) {
			/* We are here due to bloom filter, keycache and journal
			 * lookup misses. Now, lookup in keys table */

			err = rd_key_get(dev, ttag, &kh, &outsize);
			if (err == MDB_NOTFOUND) {
				/* not found for sure - done */
				goto _exit;
			}

			if (!err && filter_cb == rd_stat_filter) {
				/* found but we doing just stat_blob() - done */
				filter_cb(arg, NULL, &outsize, 0);
				return 0;
			}
		}
	}

	const char* env_path = NULL;

	if (!repeat) {
		mdb_env_get_path(log->env, &env_path);
		err = rdlog_txn_try_begin(log, MDB_RDONLY, &txn);
		if (err) {
			/* Returns EBUSY when log is being recovered, we should
			 * write to the main db this time. The EAGAIN when no more
			 * reader locks are allowed, must never happen
			 */
			assert(err != EAGAIN);
			if (err != EBUSY) {
				log_error(lg, "Dev(%s): cannot begin mdb log_lookup txn: (%d) %s env_path %s",
				    dev->name, err, mdb_strerror(err), env_path);
				rdlog_unlock(log);
				err = rdlog_repair(log, err);
				if (!err)
					err = -EFAULT;
				else
					err = -EIO;
			} else
				err = -EBUSY;
			goto _exit;
		}
	} else {
		mdb_env_get_path(DEV_ENV(db, ttag), &env_path);
		err = mdb_txn_begin(DEV_ENV(db, ttag), NULL, MDB_RDONLY, &txn);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			log_error(lg, "Get(%s): cannot begin main txn in log_lookup: (%d) %s env_path %s part %d",
			    dev->name, err, mdb_strerror(err), env_path, db->part);
			err = -EIO;
			goto _exit;
		}
	}

	if (!is_dupsort_tt(ttag)) {

		assert(!(flags & GBF_FLAG_DUPCOUNT));

		err = MDB_NOTFOUND;
		if (dev->journal && repeat == 1 && is_mdcache_tt(dev, ttag) &&
			!attrp && !no_mdcache && rd->mdcache_enable) {
			/* see if we can get it from MD cache? */
			err = mdcache_lookup(rd->mdcache, ttag, &kh, &data.mv_data, &data.mv_size);
			if (err)
				err = MDB_NOTFOUND;
		}

		if (err == MDB_NOTFOUND) {
			if (repeat == 0) {
				/* Check whether the chunk is scheduled for removal */
				uint64_t zattr = 0;
				err = mdb_get_attr(txn, dbi, &key, &data, &zattr);
				if (!err && !zattr) {
					repeat = 1;
					err = MDB_NOTFOUND;
					goto _exit;
				}
			}
			if (attrp) {
				/* If journal defined avoid attr lookups in HDD */
				if (repeat == 1 && dev->journal && is_keycache_tt(ttag)) {
					err = rd_key_get_attr(dev, ttag, &kh, attrp);
				} else {
					err = mdb_get_attr(txn, dbi, &key, &data, attrp);
				}
			} else
				err = mdb_get(txn, dbi, &key, &data);
			if (err) {
				if (err != MDB_NOTFOUND) {
					log_error(lg, "Get(%s): cannot get value from "
					    "mdb: (%d) %s env_path %s", dev->name, err,
					    mdb_strerror(err), env_path);
					if (!repeat) {
						rdlog_txn_abort(log, txn);
						txn = NULL;
						err = rdlog_repair(log, err);
						if (!err)
							err = -EFAULT;
						else
							err = -EIO;
					} else {
						struct rd_fault_signature fs = {
							.error = err,
							.source = 'l',
							.plevel = db->part + 1
						};
						rd_dev_faulted(dev, &fs);
						err = -EIO;
					}
				}
				goto _exit;
			} else if (attrp) {
				/* found touch record - return */
				goto _exit;
			}
			if (data.mv_size == 0) {
				/* this is lookup for normal chunk but in the log we only
				 * have a touch on it. Lookup in main TT next */
				assert(repeat == 0);
				err = MDB_NOTFOUND;
				goto _exit;
			}
		}

		uv_buf_t ent = { .len = data.mv_size, .base = data.mv_data };
		if (filter_cb) {
			/* Skip the entry if filter has failed */
			err = filter_cb(arg, (void **)&ent.base, &ent.len, 0);
			if (err < 0)
				goto _exit;
		}
		if (rb) {
			if (rd->zerocopy >= 1)
				err = rtbuf_add_mapped(rb, &ent, 1);
			else {
				err = rtbuf_add_alloc(rb, &ent, 1);
				if (repeat == 1 && ttag == TT_CHUNK_PAYLOAD) {
					void *aligned_addr = (void*)((((uint64_t)ent.base)>>12UL)<<12UL);
					madvise(aligned_addr, ent.len, MADV_DONTNEED);
				}
			}
		}
		if (err) {
			log_error(lg, "Get(%s): out of memory on log_lookup: %d",
			    dev->name, err);
			err = -ENOMEM;
			goto _exit;
		}
		/* Blob found, regardless of where it has happened, terminating */
		found = 1;
		repeat = 1;
		goto _exit;
	}

	err = mdb_cursor_open(txn, dbi, &cursor);
	if (err) {
		log_error(lg, "Get(%s): cannot open mdb log_lookup cursor: (%d) %s env_path %s",
		    dev->name, err, mdb_strerror(err), env_path);
		if (!repeat) {
			rdlog_txn_abort(log, txn);
			txn = NULL;
			err = rdlog_repair(log, err);
			if (!err)
				err = -EFAULT;
			else
				err = -EIO;
		} else {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			err = -EIO;
		}
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
			int delete = 0;
			if (data.mv_size >= DUPSORT_DEL_MAGIC_SIZE &&
				IS_DUPSORT_DEL((char*)data.mv_data + data.mv_size - DUPSORT_DEL_MAGIC_SIZE)) {
				data.mv_size -= DUPSORT_DEL_MAGIC_SIZE;
				if (!data.mv_size) {
					/* Delete all. Skip the main DB lookup since the
					 * current entry will destroy all entries in
					 * the main TT at WAL flush
					 */
					dupcount = 0;
					skip_main = 1;
				}
				delete = 1;
				st.n_del_log++;
			}
			/* Add blob delete requests to a hash map
			 * Also use it to filter out duplicates if DUPCOUNT flag is set.
			 * In normal mode duplicates will be filtered out by
			 * the msort_nodup() which is faster.
			 */
			if (data.mv_size && (delete || (flags & GBF_FLAG_DUPCOUNT) ||
				(filter_cb && filter_cb != rd_stat_filter))) {
				err = rt_lhtbl_insert(ht, data.mv_data, data.mv_size);
				assert(!err);
				st.n_ht_log++;
			}
			if (delete)
				continue;
			st.n_log++;
		} else  {
			if (!rt_lhtbl_query(ht, data.mv_data, data.mv_size)) {
				/*
				 * Skip values scheduled for removal when
				 * looking in main TT
				 */
				st.n_skip_main++;
				continue;

			}
			st.n_dup_main++;
		}
		if (flags & GBF_FLAG_DUPCOUNT) {
			dupcount++;
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
				if (filter_cb == rd_stat_filter) {
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
				if (!err)
					log_count++;
			} else {
				err = rt_duplist_add(&list_main, data.mv_data, data.mv_size, mapped);
				if (!err)
					main_count++;
			}
			if (err) {
				log_error(lg,
					"Get(%s): out of memory on log_lookup: %d",
					dev->name, err);
				goto _exit;
			}
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
	if (err && err != MDB_NOTFOUND) {
		log_error(lg, "mdb_cursor_get() returned %d injournal %d env_path %s\n",
		    err, !repeat, env_path);
		if (!repeat) {
			mdb_cursor_close(cursor);
			cursor = NULL;
			rdlog_txn_abort(log, txn);
			txn = NULL;
			err = rdlog_repair(log, err);
			if (!err)
				err = -EFAULT;
			else
				err = -EIO;
		} else {
			err = -EIO;
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
		}
		goto _exit;
	}
	if (skip_main)
		repeat = 1;

_exit:
	if (cursor)
		mdb_cursor_close(cursor);
	if (txn) {
		if (mdb_txn_env(txn) == log->env)
			rdlog_txn_abort(log, txn);
		else
			mdb_txn_abort(txn);
	}
	if (err == MDB_NOTFOUND && !repeat && (!found || (flags & (GBF_FLAG_ALL | GBF_FLAG_DUPCOUNT)))) {
		/* now lookup in main TT */
		dbi = dbi_main;
		cursor = NULL;
		txn = NULL;
		repeat++;
		goto _repeat;
	} else if (repeat && err == MDB_NOTFOUND && (found || dupcount))
		err = 0;

	if (err == MDB_NOTFOUND)
		err = -ENOENT;

	/* merge dupsort's log and main blob lists to a the result buffer */
	if (main_count || log_count) {
		if (!err && rb) {
			err = rt_duplist2rtbuf(ttag, list_log,log_count, list_main,
				main_count, rb, mapped);
			if (err) {
				log_error(lg, "Dev(%s) dupsort merge error %d\n",
					dev->name, err);
			}
		} else {
			if (list_log)
				msort_free_list(list_log, NULL);
			if (list_main)
				msort_free_list(list_main, NULL);
		}
	}
	if (ht)
		rt_lhtbl_destroy(ht);
	if (!err && (flags & GBF_FLAG_DUPCOUNT) && arg)
		*(size_t *)arg = dupcount;
#if 0
	printf("#log %lu, #ht %lu, #log_del %lu, #skip %lu, #main %lu, #bufs %lu\n",
		st.n_log, st.n_ht_log, st.n_del_log, st.n_skip_main,
		st.n_dup_main, rb ? rb->nbufs : 0);
#endif
	return err;
}

static int
rd_dupcount_fast(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid, size_t max, size_t* pcount) {

	assert(is_dupsort_tt(ttag));
	size_t count = 0;

	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	msgpack_p *ptk;
	MDB_txn* txn = NULL;
	MDB_cursor* cur = NULL;
	struct repdev_rd *rd = dev->device_lfs;
	int repeat = rd->metaloc.wal ? 0 : 1;

	assert (ttag != TT_HASHCOUNT);

	int err = rd_key_encode(dev, ttag, hash_type, chid, &ptk, &db, &dbi,
	    &log);
	if (err)
		return err;

	uv_buf_t keybuf;
	msgpack_get_buffer(ptk, &keybuf);

_repeat:
	if (!repeat) {
		err = rdlog_txn_try_begin(log, MDB_RDONLY, &txn);
		if (err) {
			/* Returns EBUSY when log is being recovered, we should
			 * write to the main db this time. The EAGAIN when no more
			 * reader locks are allowed, must never happen
			 */
			assert(err != EAGAIN);
			if (err != EBUSY) {
				log_error(lg, "Dev(%s): cannot begin mdb rd_dupcount_fast txn: (%d) %s",
				    dev->name, err, mdb_strerror(err));
				rdlog_unlock(log);
				err = rdlog_repair(log, err);
				if (!err)
					err = -EFAULT;
				else
					err = -EIO;
			} else
				err = -EBUSY;
			goto _exit;
		}
	} else {
		err = mdb_txn_begin(DEV_ENV(db, ttag), NULL, MDB_RDONLY, &txn);
		if (err) {
			log_error(lg, "Get(%s): cannot begin mdb rd_dupcount_fast txn: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			err = -EIO;
			goto _exit;
		}
	}
	MDB_dbi m_dbi = repeat ? dbi : log->dbi[ttag];
	err = mdb_cursor_open(txn, m_dbi, &cur);
	if (!err) {
		MDB_val key = {.mv_data = keybuf.base, .mv_size = keybuf.len };
		MDB_val val;
		err = mdb_cursor_get(cur, &key, &val, MDB_SET);
		if (!err) {
			size_t cnt = 0;
			err = mdb_cursor_count(cur, &cnt);
			count += cnt;
		}
	}
	if (err && err != MDB_NOTFOUND) {
		if (!repeat) {
			/* Returns EBUSY when log is being recovered, we should
			 * write to the main db this time. The EAGAIN when no more
			 * reader locks are allowed, must never happen
			 */
			assert(err != EAGAIN);
			if (err != EBUSY) {
				log_error(lg, "Dev(%s): cannot begin mdb rd_dupcount_fast txn: (%d) %s",
				    dev->name, err, mdb_strerror(err));
				rdlog_txn_abort(log, txn);
				txn = NULL;
				err = rdlog_repair(log, err);
				if (!err)
					err = -EFAULT;
				else
					err = -EIO;
			} else
				err = -EBUSY;
		} else {
			log_error(lg, "Get(%s): cannot begin mdb rd_dupcount_fast txn: (%d) %s",
			    dev->name, err, mdb_strerror(err));
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			err = -EIO;
		}
	} else
		err = 0;

_exit:
	if (cur)
		mdb_cursor_close(cur);
	if (txn) {
		if (mdb_txn_env(txn) == log->env)
			rdlog_txn_abort(log, txn);
		else
			mdb_txn_abort(txn);
	}
	if (!err) {
		if (!repeat && (!max || (max > count))) {
			repeat = 1;
			goto _repeat;
		}
		*pcount = count;
	}
	if (ptk)
		msgpack_pack_free(ptk);
	return err;
}

static int
rd_get_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	int flags, const uint512_t *chid, rtbuf_t **rb, int max_num,
	reptrans_blob_filter filter_cb, void *arg)
{
	int err = 0;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	msgpack_p *ptk = NULL;
	struct repdev_rd *rd = dev->device_lfs;

	assert (ttag != TT_HASHCOUNT);

	err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		err = -ENOENT;
		goto _exit;
	}

	rt_set_thread_vdev_context(dev);

	if (flags & GBF_FLAG_DUPCOUNT_ROUGH) {
		err = rd_dupcount_fast(dev, ttag, hash_type, chid, max_num, arg);
		pthread_rwlock_unlock(&rd->guard);
		return err;
	}

	*rb = NULL;
	err = rd_key_encode(dev, ttag, hash_type, chid, &ptk, &db, &dbi,
	    &log);
	if (err)
		goto _exit;

	uv_buf_t keybuf;
	msgpack_get_buffer(ptk, &keybuf);

	*rb = rtbuf_init_empty();
	if (!*rb) {
		log_error(lg, "Get(%s): out of memory", dev->name);
		err = -ENOMEM;
		goto _exit;
	}
	int cnt = 5;
	do {
		err = rd_log_lookup(dev, db, log, dbi, ttag, flags, &keybuf, hash_type,
			*rb, max_num, filter_cb, arg, NULL, 0);
	} while (err == -EFAULT && --cnt);

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
			err = rd_keyhash(dev, &key, &keyhv, &kh);
			if (!err) {
				key_cache_insert(db->key_cache, &kh, ttag, rtbuf_len(*rb));
				if (is_mdcache_tt(dev, ttag) && rd->mdcache_enable && (*rb)->nbufs == 1) {
					mdcache_enqueue(rd->mdcache, ttag, &kh,
					    rtbuf(*rb, 0).base, rtbuf(*rb, 0).len);
				}
			} else
				err = 0;
		}
	}
_exit:
	pthread_rwlock_unlock(&rd->guard);
	if (ptk)
		msgpack_pack_free(ptk);
	if (err == -ENOENT) {
		if (unlikely((lg->level <= LOG_LEVEL_DEBUG))) {
			char chidbuf[UINT512_BYTES * 2 + 1];
			uint512_dump(chid, chidbuf, UINT512_BYTES * 2 + 1);
			log_debug(lg, "blob not found: chid=%s", chidbuf);
		}
	}
	return err;
}

static int
rd_get_blob_attr(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid, uint64_t *attrp)
{
	int err = 0;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	msgpack_p *ptk = NULL;
	struct repdev_rd* rd = dev->device_lfs;

	err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		err = -ENOENT;
		goto _exit;
	}

	rt_set_thread_vdev_context(dev);
	err = rd_key_encode(dev, ttag, hash_type, chid, &ptk, &db, &dbi, &log);
	if (err)
		goto _exit;

	uv_buf_t keybuf;
	msgpack_get_buffer(ptk, &keybuf);

	int cnt = 5;
	do {
		err = rd_log_lookup(dev, db, log, dbi, ttag, GBF_FLAG_ONE, &keybuf,
			hash_type, NULL, 1, NULL, NULL, attrp, 1);
	} while (err == -EFAULT && --cnt);

_exit:
	pthread_rwlock_unlock(&rd->guard);
	if (ptk)
		msgpack_pack_free(ptk);
	return err;
}

static int
rd_delete_blob_value(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uv_buf_t *val, size_t len)
{
	int err;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	MDB_env* env;
	msgpack_p *ptk = NULL;
	uv_buf_t keybuf;
	MDB_val key, data;
	MDB_txn* txn;
	size_t deleted = 0;
	rtbuf_t* rb = NULL;
	size_t del_size = 0;

	struct repdev_rd *rd = dev->device_lfs;
	assert(is_dupsort_tt(ttag));

	err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		err = -ENOENT;
		goto _exit;
	}

	rt_set_thread_vdev_context(dev);
	err = rd_key_encode(dev, ttag, hash_type, chid, &ptk, &db, &dbi,
	    &log);
	if (err) {
		log_error(lg, "Dev(%s): delete_blob rd_key_encode: (%d) %s",
		    dev->name, err, strerror(err));
		goto _exit;
	}

	msgpack_get_buffer(ptk, &keybuf);

	if (is_log_tt(dev, ttag)) {
		rtbuf_t* rbl = rtbuf_init_mapped(val, 1);
		if (!rbl) {
			err = -ENOMEM;
			goto _exit;
		}
		for (size_t i = 0; i < len; i++) {
			rbl->bufs[0] = val[i];
			/*
			 * A void attr signals blob to be removed
			 */
			int cnt = 5;
			do {
				err = rd_log_append(dev, log, ttag, hash_type, &keybuf, rbl, 0);
			} while (err == -EFAULT && --cnt);

			if (err) {
				if (err != -ENOSPC && err != -EBUSY) {
					log_error(lg, "Dev(%s): delete_blob rd_log_append: (%d) %s",
					    dev->name, err, mdb_strerror(err));
					err = -EIO;
					break;
				}
			}
		}
		rtbuf_destroy(rbl);
		if (!err || err == -EIO)
			goto _exit;
	}

	/* Non-log delete */
	rd_log_flush_barrier(db, ttag, 1);

	/*
	 * This is direct TT main lookup.
	 */
	env = DEV_ENV(db, ttag);
	msgpack_get_buffer(ptk, &keybuf);
	key.mv_data = keybuf.base;
	key.mv_size = keybuf.len;

	err = rd_kv_validate(ttag, &key, NULL);
	if (err) {
		err = -EINVAL;
		goto _exit;
	}

	const char* env_path = NULL;
	mdb_env_get_path(env, &env_path);

	err = mdb_txn_begin(env, NULL, 0, &txn);
	if (err) {
		struct rd_fault_signature fs = {
			.error = err,
			.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		log_error(lg, "Dev(%s): delete_blob mdb_txn_begin: (%d) %s env_path %s part %d",
		    dev->name, err, mdb_strerror(err), env_path, db->part);
		err = -EIO;
		goto _exit;
	}
	if (val) {
		for (size_t i = 0; !err && val && i < len; ++i) {
			data.mv_data = val[i].base;
			data.mv_size = val[i].len;
			err = mdb_del(txn, dbi, &key, &data);
			if (err == MDB_NOTFOUND)
				err = 0;
			else if (!err) {
				deleted++;
				del_size += val[i].len;
			} else {
				log_error(lg, "Dev(%s): delete_blob mdb_del: (%d) %s env_path %s part %d",
				    dev->name, err, mdb_strerror(err), env_path, db->part);
				break;
			}
		}
	} else {
		MDB_cursor* cur = NULL;
		err = mdb_cursor_open(txn, dbi, &cur);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			log_error(lg, "Dev(%s): delete_blob mdb_cursor_open: (%d) %s env_path %s part %d",
			    dev->name, err, mdb_strerror(err), env_path, db->part);
			err = -EIO;
			goto _exit;
		}
		MDB_val data_empty = { .mv_size = 0, .mv_data = NULL };
		err = mdb_cursor_get(cur, &key, &data_empty, MDB_SET_KEY);
		if (!err)
			mdb_cursor_count(cur, &deleted);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			log_error(lg, "Dev(%s): delete_blob mdb_cursor_get/count: (%d) %s env_path %s part %d",
			    dev->name, err, mdb_strerror(err), env_path, db->part);
			err = -EIO;
			goto _exit;
		}
		if (deleted) {
			err = mdb_cursor_del(cur, MDB_NODUPDATA);
			if (err && err != MDB_NOTFOUND) {
				deleted = 0;
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				log_error(lg, "Dev(%s): delete_blob mdb_cursor_del: (%d) %s env_path %s part %d",
				    dev->name, err, mdb_strerror(err), env_path, db->part);
			} else
				del_size += data_empty.mv_size;
		}
	}
	if (err) {
		log_error(lg, "Dev(%s): %p delete_blob mdb_del: (%d) %s",
		    dev->name, env, err, mdb_strerror(err));
		err = -EIO;
		mdb_txn_abort(txn);
	} else {
		err = mdb_txn_commit(txn);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			log_error(lg, "Dev(%s): cannot commit delete "
			    "transaction: %d, %s env_path %s part %d", dev->name, err,
			    mdb_strerror(err), env_path, db->part);
			err = -EIO;
		} else if (deleted) {
			if (is_hashcount_data_type_tag(ttag))
				reptrans_drop_hashcount(dev, chid, deleted);
			if (is_rowusage_data_type_tag(ttag))
				reptrans_drop_rowusage(dev, chid, del_size);
		}
	}
	rd_log_flush_barrier(db, ttag, 0);

_exit:
	pthread_rwlock_unlock(&rd->guard);
	if (rb)
		rtbuf_destroy(rb);
	if (ptk)
		msgpack_pack_free(ptk);
	log_debug(lg, "Dev(%s): %s delete_blob_value deleted=%lu entries, err=%d",
	    dev->name, type_tag_name[ttag], deleted, err);
	return err;
}

static int
rd_delete_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
    const uint512_t *chid)
{
	int err;
	MDB_txn *txn = NULL;
	MDB_val key;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db, *db_lock = NULL;
	struct repdev_log *log;
	MDB_dbi dbi;
	MDB_dbi dbi_main;
	MDB_env* env;
	msgpack_p *ptk = NULL;
	uv_buf_t keybuf;
	MDB_val keyhv;
	uint64_t kh;
	size_t del_size = 0;

	err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		err = -ENOENT;
		goto _exit;
	}

	rt_set_thread_vdev_context(dev);
	err = rd_key_encode(dev, ttag, hash_type, chid, &ptk, &db, &dbi_main,
	    &log);
	if (err) {
		log_error(lg, "Dev(%s): delete_blob rd_key_encode: (%d) %s",
		    dev->name, err, strerror(err));
		goto _exit;
	}
	msgpack_get_buffer(ptk, &keybuf);
	key.mv_data = keybuf.base;
	key.mv_size = keybuf.len;

	if (is_log_tt(dev, ttag)) {
		rtbuf_t* rb = rtbuf_init_empty();
		/*
		 * A void attr signals blob to be removed
		 */
		int cnt = 5;
		do {
			err = rd_log_append(dev, log, ttag, hash_type, &keybuf, rb, 0);
		} while (err == -EFAULT && --cnt);

		rtbuf_destroy(rb);
		if (!err || err != -ENOSPC || err != -EBUSY) {
			if (err) {
				log_error(lg, "Get(%s): rd_log_append() returned %d",
					dev->name, err);
				err = -EIO;
			}
			goto _exit;
		}
		/* No space in WAL, try to remove directly from TT */
	}

	err = rd_kv_validate(ttag, &key, NULL);
	if (err) {
		err = -EINVAL;
		goto _exit;
	}

	dbi = dbi_main;
	db_lock = db;
	rd_log_flush_barrier(db_lock, ttag, 1);

	if (is_keycache_tt(ttag)) {
		err = rd_keyhash(dev, &key, &keyhv, &kh);
		if (err)
			goto _exit;

		key_cache_remove(db->key_cache, &kh, ttag);
		if (dev->journal) {
			const char* env_path = NULL;
			mdb_env_get_path(rd->mdcache_env, &env_path);

			MDB_txn *md_txn;
			err = mdb_txn_begin(rd->mdcache_env, NULL, 0, &md_txn);
			if (err) {
				log_error(lg, "Dev(%s): md_txn mdb_txn_begin: (%d) %s env_path %s", dev->name,
				    err, mdb_strerror(err), env_path);
				goto _exit;
			}

			size_t blob_size = 0;
			err = rd_key_get(dev, ttag, &kh, &blob_size);
			if (!err) {
				del_size += blob_size;
				err = rd_key_remove(dev, ttag, md_txn, &kh);
				if (err) {
					mdb_txn_abort(md_txn);
					goto _exit;
				}
			}
			if (is_mdcache_tt(dev, ttag) && rd->mdcache_enable) {
				err = mdcache_remove(rd->mdcache, ttag, md_txn, &kh);
				if (err) {
					mdb_txn_abort(md_txn);
					goto _exit;
				}
			}
			err = mdb_txn_commit(md_txn);
			if (err) {
				log_error(lg, "Dev(%s): md_txn delete_blob %s mdb_txn_commit: (%d) %s env_path %s",
				    dev->name, type_tag_name[ttag], err, mdb_strerror(err), env_path);
				goto _exit;
			}
		}
	}

	env = DEV_ENV(db, ttag);
	const char* env_path = NULL;
	mdb_env_get_path(rd->mdcache_env, &env_path);

	err = mdb_txn_begin(env, NULL, 0, &txn);
	if (err) {
		struct rd_fault_signature fs = {
			.error = err,
			.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		log_error(lg, "Dev(%s): delete_blob mdb_txn_begin: (%d) %s env_path %s part %d",
		    dev->name, err, mdb_strerror(err), env_path, db->part);
		err = -EIO;
		goto _exit;
	}

	size_t nameindex_cnt = 0;

	MDB_cursor *cnt_cursor;
	err = mdb_cursor_open(txn, dbi, &cnt_cursor);
	if (err) {
		struct rd_fault_signature fs = {
			.error = err,
			.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
			log_error(lg, "Get(%s): cannot open mdb delete_blob "
				"cursor: (%d) %s env_path %s part %d", dev->name, err,
				mdb_strerror(err), env_path, db->part);
		err = -EIO;
		goto _exit;
	}
	MDB_val data_empty = { .mv_size = 0, .mv_data = NULL };
	err = mdb_cursor_get(cnt_cursor, &key, &data_empty, MDB_SET_KEY);
	if (!err) {
		if (ttag == TT_NAMEINDEX)
			mdb_cursor_count(cnt_cursor, &nameindex_cnt);
		int flag = is_dupsort_tt(ttag) ? MDB_NODUPDATA : 0;
		err = mdb_cursor_del(cnt_cursor, flag);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			log_error(lg, "Get(%s): mdb delete_blob "
				"cursor: (%d) %s env_path %s part %d", dev->name, err,
				mdb_strerror(err), env_path, db->part);
			err = -EIO;
			goto _exit;
		}
		if (!del_size)
			del_size += data_empty.mv_size;
		if (is_hashcount_data_type_tag(ttag)) {
			size_t del_cnt = (ttag == TT_NAMEINDEX) ? nameindex_cnt : 1;
			if (del_cnt)
				reptrans_drop_hashcount(dev, chid, del_cnt);
		}
		if (is_rowusage_data_type_tag(ttag))
			reptrans_drop_rowusage(dev, chid, del_size);
	} else if (err == MDB_NOTFOUND)
		err = 0;
	else {
		log_error(lg, "Get(%s): mdb_cursor_get/mdb_cursor_count delete_blob "
			": (%d) %s env_path %s part %d", dev->name, err,mdb_strerror(err),
			env_path, db->part);
		struct rd_fault_signature fs = {
			.error = err,
			.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
			.plevel = db->part + 1
		};
		rd_dev_faulted(dev, &fs);
		err = -EIO;
	}
	rd_log_flush_barrier(db_lock, ttag, 0);
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
			log_error(lg, "Dev(%s): delete_blob %s mdb_txn_commit: (%d) %s env_path %s part %d",
			    dev->name, type_tag_name[ttag], err, mdb_strerror(err), env_path, db->part);
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
		}
	}
	if (db_lock)
		rd_log_flush_barrier(db_lock, ttag, 0);
	pthread_rwlock_unlock(&rd->guard);
	if (ptk)
		msgpack_pack_free(ptk);
	return err;
}


static int
rt_qsort_u64_cmp(const void* a, const void* b) {
	uint64_t a_val = *((uint64_t*)a);
	uint64_t b_val = *((uint64_t*)b);
	if (a_val < b_val)
		return -1;
	else if (a_val > b_val)
		return 1;
	return 0;
}

static int
rt_u64_lookup(uint64_t* deleted, uint64_t size, uint64_t value) {
	int first = 0;
	int last = size - 1;
	int middle = (first+last)/2;

	while (first <= last) {
		if (deleted[middle] < value)
			first = middle + 1;
		else if (deleted[middle] == value)
			return 1;
		else
			last = middle - 1;
		middle = (first + last)/2;
	}
	return 0;
}
/* this value shouldn't be big to reduce long readers */
#define ITERATOR_BATCH_NUM 64

static int
rd_iterate_blobs_shard(struct repdev *dev, type_tag_t ttag,
    reptrans_blob_callback callback, void *param, int want_values,
    int max_blobs, int jpart, int shard, struct rt_imsort* sh, uv_buf_t del)
{
	int err = 0;
	MDB_cursor *cursor = NULL;
	MDB_txn *txn = NULL;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = NULL;

	int batched;
	long k;
	int new_part = 1;

	rtbuf_t *rbl;

	db = rd->db + jpart;


	k = 0;
	rbl = rtbuf_init_empty();
	if (!rbl)
		return -ENOMEM;

	do {
		batched = 0;
		const char* env_path = NULL;
		mdb_env_get_path(DEV_ENV(db, ttag), &env_path);

		err = mdb_txn_begin(DEV_ENV(db, ttag), NULL, MDB_RDONLY, &txn);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			log_error(lg, "Get(%s): cannot begin mdb "
			    "iterate_blobs txn: (%d) %s env_path %s part %d",
			    dev->name, err, mdb_strerror(err), env_path, db->part);
			err = -EIO;
			break;
		}

		MDB_dbi dbi_last = DEV_SHARD(db, ttag, shard);
		err = mdb_cursor_open(txn, dbi_last, &cursor);
		if (err) {
			struct rd_fault_signature fs = {
				.error = err,
				.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
				.plevel = db->part + 1
			};
			rd_dev_faulted(dev, &fs);
			mdb_txn_abort(txn);
			log_error(lg, "Get(%s): cannot open mdb "
			    "iterate_blobs cursor: (%d) %s env_path %s part %d",
			    dev->name, err, mdb_strerror(err), env_path, db->part);
			err = -EIO;
			break;
		}

		rtbuf_t *rb = rtbuf_init(NULL, ITERATOR_BATCH_NUM);
		if (!rb) {
			mdb_cursor_close(cursor);
			mdb_txn_abort(txn);
			err = -ENOMEM;
			break;
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
				err = -ENOMEM;
				break;
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

			if (del.len) {
				uint64_t ikey;
				if (is_keycache_tt(ttag)) {
					MDB_val aux;
					err = rd_keyhash(dev, &key, &aux, &ikey);
					assert(err == 0);
				} else {
					rt_lhtbl_hahs(key.mv_data, key.mv_size, &ikey);
				}
				/* Skip entries schedule for removal */
				if (rt_u64_lookup((uint64_t*)del.base, del.len, ikey))
					continue;
			}

			uv_buf_t bufkey = {
				.len = key.mv_size,
				.base = key.mv_data
			};
			err = rtbuf_set_alloc(rb, batched, &bufkey, 1);
			if (err) {
				log_error(lg, "rtbuf_add failed %d\n",
				    err);
				break;
			}

			uv_buf_t bufdata = {
				.len = data.mv_size,
				.base = data.mv_data
			};
			if (rbv) {
				err = rtbuf_set_alloc(rbv, batched, &bufdata, 1);
				if (err) {
					log_error(lg,
					    "rtbuf_add failed %d\n",
					    err);
					rtbuf_free_one(rb, --rb->nbufs);
					break;
				}
			}
			batched++;

			if ((batched == ITERATOR_BATCH_NUM) || ((max_blobs != -1) && (k + batched >= max_blobs))) {
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

			err = reptrans_key_decode(dev, rtbuf(rb, i).base,
			    rtbuf(rb, i).len, &key_ttag, &key_hash_type,
			    &chid);
			if (err || key_ttag != ttag ||
			    (rbv && !rbv->nbufs))
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
			new_part = 0;
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

	err = 0;
	return err;
}

static int
rd_log_fetch_entries(struct repdev* dev, struct repdev_db *db, type_tag_t ttag,
	uv_buf_t* res, int want_values, struct rt_imsort* sh) {
	uint64_t* deleted = res ? (uint64_t*)res->base : NULL;
	uint64_t n = res ? res->len : 0;
	MDB_txn* log_txn = NULL;

	assert(is_dupsort_tt(ttag) == 0);

	int err = 0;
	struct repdev_log *log = NULL;

	if (is_log_tt(dev, ttag)) {
		for (int id = 0; id < DEV_LOGID_MAX; id++) {
			MDB_val key, data;
			MDB_cursor* log_cursor = NULL;
			log = &DEV_LOGID(db, id);
			err = rdlog_txn_try_begin(log, MDB_RDONLY, &log_txn);

			if (err) {
				if (err != EBUSY) {
					log_error(lg, "Get(%s): cannot begin log mdb "
					    "iterate_blobs txn: (%d) %s log_env %s", dev->name,
					    err, mdb_strerror(err), log->path);
					rdlog_unlock(log);
					err = rdlog_repair(log, err);
					if (!err)
						err = -EFAULT;
					else
						err = -EIO;
				} else
					err = -EBUSY;
				goto _exit;
			}

			MDB_stat db_stat;
			err = mdb_stat(log_txn, log->dbi[ttag], &db_stat);
			if (err) {
				log_error(lg, "Get(%s): cannot open stat log mdb "
					": (%d) %s log_env %s", dev->name,
					err, mdb_strerror(err), log->path);
				err = -EIO;
				goto _exit;
			}
			if (!db_stat.ms_entries) {
				rdlog_txn_abort(log, log_txn);
				log_txn = NULL;
				continue;
			} else {
				uint64_t* new_deleted = je_malloc((db_stat.ms_entries + n)*sizeof(uint64_t));
				if (!new_deleted) {
					err = -ENOMEM;
					log_error(lg, "Dev(%s) %lu bytes allocation error",
						dev->name, db_stat.ms_entries + n);
					err = -EIO;
					goto _exit;
				}
				memcpy(new_deleted, deleted, n*sizeof(uint64_t));
				je_free(deleted);
				deleted = new_deleted;
			}
			err = mdb_cursor_open(log_txn, log->dbi[ttag], &log_cursor);
			if (err) {
				log_error(lg, "Get(%s): cannot open log mdb "
				    "iterate_blobs cursor: (%d) %s log_env %s", dev->name,
				    err, mdb_strerror(err), log->path);
				rdlog_txn_abort(log, log_txn);
				log_txn = NULL;
				err = rdlog_repair(log, err);
				if (!err)
					err = -EFAULT;
				else
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
					log_error(lg, "Get(%s): cannot read attr: %s (%d) log_env %s",
					    dev->name, mdb_strerror(err), err, log->path);
					mdb_cursor_close(log_cursor);
					log_cursor = NULL;
					rdlog_txn_abort(log, log_txn);
					log_txn = NULL;
					err = rdlog_repair(log, err);
					if (!err)
						err = -EFAULT;
					else
						err = -EIO;
					goto _exit;
				}
				if (!attr) {
					MDB_val aux;
					uint64_t ikey = 0;
					if (is_keycache_tt(ttag)) {
						err = rd_keyhash(dev, &key, &aux, &ikey);
						if (err) {
							log_error(lg, "Get(%s): rd_keyhash error "
							    "iterate_blobs cursor: (%d) %s", dev->name,
							    err, mdb_strerror(err));
							err = -EIO;
							goto _exit;
						}
					} else {
						rt_lhtbl_hahs(key.mv_data, key.mv_size, &ikey);
					}
					deleted[n++] =  ikey;
				} else if (sh) {
					type_tag_t ltt;
					crypto_hash_t ht;
					uint512_t chid;
					err = reptrans_key_decode(dev, key.mv_data,
						key.mv_size, &ltt, &ht, &chid);
					if (err) {
						log_error(lg, "Dev(%s) couldn't decode key %s: %d",
							dev->name, type_tag_name[ttag], err);
					} else {
						uv_buf_t val = {.len = data.mv_size, .base = data.mv_data };
						err = reptrans_imsort_add_kv(sh, ht, &chid,
							want_values ? &val : NULL, new_etry);
						new_etry = 0;
						if (err)
							log_error(lg, "Dev(%s) cannot append log's data to imsort: %d",
								dev->name, err);
					}
					err = 0;
				}
			}
			if (err != MDB_NOTFOUND) {
				log_error(lg, "Get(%s): mdb_cursor_get: %s (%d)",
				    dev->name, mdb_strerror(err), err);
				mdb_cursor_close(log_cursor);
				log_cursor = NULL;
				rdlog_txn_abort(log, log_txn);
				log_txn = NULL;
				err = rdlog_repair(log, err);
				if (!err)
					err = -EFAULT;
				else
					err = -EIO;
				goto _exit;
			}
			mdb_cursor_close(log_cursor);
			err = 0;
			rdlog_txn_abort(log, log_txn);
			log_txn = NULL;
		}
	}
	if (deleted != (uint64_t*)res->base) {
		qsort(deleted, n, sizeof(uint64_t), rt_qsort_u64_cmp);
		res->base = (char*)deleted;
		res->len = n;
	}

_exit:
	if (log_txn)
		rdlog_txn_abort(log, log_txn);
	if (err)
		je_free(deleted);
	return err;
}

static int
rd_iterate_blobs_strict(struct repdev *dev, type_tag_t ttag,
    reptrans_blob_callback callback, void *param, int want_values,
    int max_blobs)
{
	int err = 0;
	MDB_cursor *cursor = NULL;
	MDB_txn *txn = NULL;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = NULL;

	struct rt_imsort* sh = NULL;

	err = reptrans_imsort_create(dev, ttag, param, &sh);
	if (err) {
		log_error(lg, "Dev(%s) cannot create imsort instance: %d",
		    dev->name, err);
		return err;
	}

	err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		pthread_rwlock_unlock(&rd->guard);
		return -ENOENT;
	}

	int blobs_dist[rd->plevel*DEV_SHARDS_MAX];
	if (max_blobs != -1 && !(dev->journal && is_mdoffload_tt(dev, ttag))) {
		/*
		 * Need to figure out the weight of each plevel.
		 * Chunks might be distributed unevenly.
		 */
		size_t total = 0;
		for (int j = 0; j <  rd->plevel; j++) {
			db = rd->db + j;
			assert(db);
			for (int i = 0; i < DEV_SHARD_MAX(db, ttag); i++) {
				MDB_txn *txn = NULL;
				MDB_dbi dbi = DEV_SHARD(db, ttag, i);
				err = mdb_txn_begin(DEV_ENV(db, ttag), NULL, MDB_RDONLY, &txn);
				if (err) {
					pthread_rwlock_unlock(&rd->guard);
					log_error(lg, "Dev(%s): cannot begin mdb txn: (%d) %s",
						dev->name, err, mdb_strerror(err));
					return err;
				}
				MDB_stat dstat;
				mdb_stat(txn, dbi, &dstat);
				blobs_dist[j*DEV_SHARD_MAX(db, ttag) + i] = dstat.ms_entries;
				total += dstat.ms_entries;
				mdb_txn_abort(txn);
			}
		}
		if (!total) {
			pthread_rwlock_unlock(&rd->guard);
			return 0;
		}
		for (int j = 0; j < rd->plevel*DEV_SHARDS_MAX; j++)
			blobs_dist[j] = 1LL + blobs_dist[j] * (long long)max_blobs / total;
	} else if (max_blobs == -1) {
		for (int j = 0; j < rd->plevel*DEV_SHARDS_MAX; j++)
			blobs_dist[j] = -1;
	} else if (dev->journal && is_mdoffload_tt(dev, ttag)) {
		db = rd->db + (rd->plevel -1);
		for (int shard=0; shard < DEV_SHARD_MAX(db, ttag); shard++) {
			blobs_dist[(rd->plevel -1)*DEV_SHARD_MAX(db, ttag) + shard] = max_blobs / DEV_SHARD_MAX(db, ttag);
		}
	}

	uv_buf_t del = {.base = NULL, .len = 0};

	for (int j = 0; j < rd->plevel; j++) {
		db = rd->db + j;
		int cnt = 5;
		do {
			err = rd_log_fetch_entries(dev, db, ttag, &del, want_values, sh);
		} while (err == -EFAULT && --cnt);
		if (err) {
			pthread_rwlock_unlock(&rd->guard);
			goto _exit;
		}

		if (dev->journal && is_mdoffload_tt(dev, ttag) && j != rd->plevel -1)
			continue;

		for (int shard=0; shard < DEV_SHARD_MAX(db, ttag); shard++) {
			err = rd_iterate_blobs_shard(dev, ttag,
			    callback, param, want_values,
			    blobs_dist[j*DEV_SHARD_MAX(db, ttag) + shard], j, shard, sh, del);
			if (err && err != MDB_NOTFOUND)
				log_error(lg, "Get(%s): cannot load part %d, shard: %d err: %d",
				    dev->name, j, shard, err);
		}
		if (del.base)
			je_free(del.base);
		del.base = NULL;
		del.len = 0;
	}
	pthread_rwlock_unlock(&rd->guard);
	err = reptrans_imsort_iterate(sh, callback, RT_KEY_FORMAT_MSGPACK);

_exit:
	if (sh)
		reptrans_imsort_destroy(sh);
	return err;
}


static int
rd_iterate_blobs_nonstrict(struct repdev *dev, type_tag_t ttag,
    reptrans_blob_callback callback, void *param, int want_values)
{
	int err = 0;
	MDB_cursor *cursor = NULL;
	MDB_txn *txn = NULL;
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = NULL;

	struct rt_imsort* sh = NULL;

	int batched;
	long k;
	uv_buf_t del = {.base = NULL, .len = 0};

	for (int j = 0; j < rd->plevel; j++) {
		rtbuf_t *rbl;

		db = rd->db + j;

		err = pthread_rwlock_tryrdlock(&rd->guard);
		if (err)
			return err;

		if (!rd_is_opened(rd)) {
			err = -ENOENT;
			pthread_rwlock_unlock(&rd->guard);
			return err;
		}

		if (!is_dupsort_tt(ttag)) {
			int cnt = 5;
			do {
				err = rd_log_fetch_entries(dev, db, ttag, &del,want_values, NULL);
			} while (err == -EFAULT && --cnt);

			/* there is no plevels for mdoffload, this is optimization */
			if (dev->journal && is_mdoffload_tt(dev, ttag) && j != rd->plevel -1) {
				pthread_rwlock_unlock(&rd->guard);
				continue;
			}
		} else if (is_log_tt(dev, ttag)) {

			for (int id = 0; id < DEV_LOGID_MAX; id++) {
				struct repdev_log *log = &DEV_LOGID(db, id);
				err = rd_log_flush(log, ttag);
				if (err)
					break;
			}
			if (err) {
				pthread_rwlock_unlock(&rd->guard);
				return err;
			}
			rd_log_flush_wait(db, ttag);

			/* there is no plevels for mdoffload, this is optimization */
			if (dev->journal && is_mdoffload_tt(dev, ttag) && j != rd->plevel -1) {
				pthread_rwlock_unlock(&rd->guard);
				continue;
			}
		}
		pthread_rwlock_unlock(&rd->guard);
		int shard = 0;
_next_shard:
		k = 0;
		rbl = rtbuf_init_empty();
		if (!rbl)
			return -ENOMEM;
		int locked = 0;
		do {
			batched = 0;
			const char* env_path = NULL;

			err = pthread_rwlock_tryrdlock(&rd->guard);
			if (err)
				break;
			locked = 1;

			if (!rd_is_opened(rd)) {
				err = -ENOENT;
				break;
			}

			mdb_env_get_path(DEV_ENV(db, ttag), &env_path);

			err = mdb_txn_begin(DEV_ENV(db, ttag), NULL, MDB_RDONLY, &txn);
			if (err) {
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				log_error(lg, "Get(%s): cannot begin mdb "
				    "iterate_blobs txn: (%d) %s env_path %s part %d", dev->name,
				    err, mdb_strerror(err), env_path, db->part);
				err = -EIO;
				break;
			}

			MDB_dbi dbi_last = DEV_SHARD(db, ttag, shard);
			err = mdb_cursor_open(txn, dbi_last, &cursor);
			if (err) {
				mdb_txn_abort(txn);
				struct rd_fault_signature fs = {
					.error = err,
					.source = dev->journal && is_mdoffload_tt(dev, ttag) ? 'o' : 'm',
					.plevel = db->part + 1
				};
				rd_dev_faulted(dev, &fs);
				log_error(lg, "Get(%s): cannot open mdb "
				    "iterate_blobs cursor: (%d) %s env_path %s part %d", dev->name,
				    err, mdb_strerror(err), env_path, db->part);
				err = -EIO;
				break;
			}

			rtbuf_t *rb = rtbuf_init(NULL, ITERATOR_BATCH_NUM);
			if (!rb) {
				mdb_cursor_close(cursor);
				mdb_txn_abort(txn);
				err = -ENOMEM;
				break;
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
					err = -ENOMEM;
					break;
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

				/* Skip entries schedule for removal */
				if (del.len) {
					uint64_t ikey;
					if (is_keycache_tt(ttag)) {
						MDB_val aux;
						err = rd_keyhash(dev, &key, &aux, &ikey);
						assert(err == 0);
					} else {
						rt_lhtbl_hahs(key.mv_data, key.mv_size, &ikey);
					}

					if (rt_u64_lookup((uint64_t*)del.base, del.len, ikey))
						continue;
				}

				uv_buf_t bufkey = {
					.len = key.mv_size,
					.base = key.mv_data
				};
				err = rtbuf_set_alloc(rb, batched, &bufkey, 1);
				if (err) {
					log_error(lg, "rtbuf_add failed %d\n",
					    err);
					break;
				}

				uv_buf_t bufdata = {
					.len = data.mv_size,
					.base = data.mv_data
				};
				if (rbv) {
					err = rtbuf_set_alloc(rbv, batched, &bufdata, 1);
					if (err) {
						log_error(lg,
						    "rtbuf_add failed %d\n",
						    err);
						rtbuf_free_one(rb, --rb->nbufs);
						break;
					}
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
			locked = 0;
			pthread_rwlock_unlock(&rd->guard);
			for (size_t i = 0; i < rb->nbufs; i++) {
				uint512_t chid;
				crypto_hash_t key_hash_type;
				type_tag_t key_ttag;

				err = reptrans_key_decode(dev, rtbuf(rb, i).base,
				    rtbuf(rb, i).len, &key_ttag, &key_hash_type,
				    &chid);
				if (err || key_ttag != ttag ||
				    (rbv && !rbv->nbufs))
					continue;
				err = callback(dev, ttag, key_hash_type, &chid,
				    rbv ? &rbv->bufs[i] : NULL, param);
				if (!rd_is_opened(rd))
					err = -ENODEV;
				if (err) {
					char chidbuf[UINT512_BYTES * 2 + 1];
					uint512_dump(&chid, chidbuf,
					    UINT512_BYTES * 2 + 1);
					if (err != -ENOSPC && err != -ENODEV) {
						log_debug(lg, "dev %s: ttag %s, CHID %s, err %d",
						    dev->name, type_tag_name[ttag], chidbuf, err);
					}
					rtbuf_destroy(rb);
					if (rbv)
						rtbuf_destroy(rbv);
					rtbuf_destroy(rbl);
					if (del.base)
						je_free(del.base);
					return err;
				}
			}
			rtbuf_destroy(rb);
			if (rbv)
				rtbuf_destroy(rbv);

			k += batched;
		} while (batched == ITERATOR_BATCH_NUM);

		if (locked) {
			pthread_rwlock_unlock(&rd->guard);
			locked = 0;
		}

		if (rbl)
			rtbuf_destroy(rbl);

		if (++shard < DEV_SHARD_MAX(db, ttag))
			goto _next_shard;
		if (del.base)
			je_free(del.base);
		del.base = NULL;
		del.len = 0;
	}
	err = 0;
	return err;
}


static int
rd_iterate_blobs(struct repdev *dev, type_tag_t ttag,
    reptrans_blob_callback callback, void *param, int want_values,
    int strict_order, int max_blobs)
{
	rt_set_thread_vdev_context(dev);
	if (strict_order) {
		return rd_iterate_blobs_strict(dev, ttag,
		    callback, param, want_values, max_blobs);
	}
	return rd_iterate_blobs_nonstrict(dev, ttag,
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
rd_list_blob_chids(struct repdev *dev, type_tag_t ttag, uint64_t ng,
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
	int err = rd_iterate_blobs(dev, ttag, list_blob_chids_iter, &param, 0,
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
rd_stat_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid, struct blob_stat *bs)
{
	int err = 0;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	msgpack_p *ptk = NULL;
	struct repdev_rd* rd = dev->device_lfs;

	assert(ttag != TT_HASHCOUNT);

	err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		err = -ENOENT;
		goto _exit;
	}

	rt_set_thread_vdev_context(dev);
	err = rd_key_encode(dev, ttag, hash_type, chid, &ptk, &db, &dbi, &log);
	if (err)
		goto _exit;

	uv_buf_t keybuf;
	msgpack_get_buffer(ptk, &keybuf);

	int cnt = 5;
	do {
		err = rd_log_lookup(dev, db, log, dbi, ttag, GBF_FLAG_ONE, &keybuf,
			hash_type, NULL, 1, rd_stat_filter, bs, NULL, 1);
	} while (err == -EFAULT && --cnt);

	if (err) {
		log_debug(lg, "Stat(%s): cannot stat blob from mdb: %d",
		    dev->name, err);
		if (bs)
			bs->size = 0;
	}
_exit:
	pthread_rwlock_unlock(&rd->guard);
	if (ptk)
		msgpack_pack_free(ptk);
	return err;
}

static int
rd_query_blob(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid, size_t *outsize)
{
	int err = 0;
	struct repdev_db *db;
	struct repdev_log *log;
	MDB_dbi dbi;
	msgpack_p *ptk = NULL;
	struct repdev_rd* rd = dev->device_lfs;

	if (!is_keycache_tt(ttag) && ttag != TT_NAMEINDEX)
		return 1;

	err = pthread_rwlock_tryrdlock(&rd->guard);
	if (err)
		return err;

	if (!rd_is_opened(rd)) {
		err = -ENOENT;
		goto _exit;
	}

	rt_set_thread_vdev_context(dev);
	err = rd_key_encode(dev, ttag, hash_type, chid, &ptk, &db, &dbi, &log);
	if (err)
		goto _exit;

	uv_buf_t keybuf;
	msgpack_get_buffer(ptk, &keybuf);

	MDB_val key;
	key.mv_size = keybuf.len;
	key.mv_data = keybuf.base;

	MDB_val keyhv;
	uint64_t kh;
	err = rd_keyhash(dev, &key, &keyhv, &kh);
	if (err)
		goto _exit;

	if (!db->dev->keycache_enabled) {
		err = rd_bloom_query(db, kh);
		if (err)
			err = -1; /* to signify that direct match disabled */
	} else {
		err = rd_bloom_query(db, kh);
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
	pthread_rwlock_unlock(&rd->guard);
	if (ptk)
		msgpack_pack_free(ptk);
	return err;
}

static int
rd_compactify(struct repdev* dev, type_tag_t ttag_req, size_t thd_mb,
	comp_cb_t cb) {
	return 0;
}

struct repdev_vtbl rd_dev_vtbl = {
	.stat_refresh = rd_dev_stat_refresh,
	.put_blob = rd_put_blob,
	.put_blob_with_attr = rd_put_blob_with_attr,
	.get_blob = rd_get_blob,
	.get_blob_attr = rd_get_blob_attr,
	.set_blob_attr = rd_set_blob_attr,
	.delete_blob = rd_delete_blob,
	.delete_blob_value = rd_delete_blob_value,
	.iterate_blobs = rd_iterate_blobs,
	.list_blob_chids = rd_list_blob_chids,
	.stat_blob = rd_stat_blob,
	.query_blob = rd_query_blob,
	.compactify = rd_compactify,
	.config = rd_config
};

static int
rd_metaloc_serialize(const struct rd_metaloc* ml, uv_buf_t* buf) {
	char* ptr = buf->base;
	assert(ml);
	char buff[4096];
	sprintf(buff, "{\n"
	    "\t\"created-timestamp\" : %lu,\n"
	    "\t\"plevel\" : %d,\n"
	    "\t\"device\" : \"%s\",\n"
	    "\t\"oldname\" : \"%s\",\n"
	    "\t\"jpart\" : %d,\n"
	    "\t\"journal\" : \"%s\",\n"
	    "\t\"wal\" : %d,\n"
	    "\t\"offload\" : \"%s\",\n"
	    "\t\"vdevid\" : \"%016lX%016lX\",\n"
	    "\t\"version\" : %d,\n"
	    "\t\"metamask\" : %d,\n"
	    "\t\"bcache\" : %d,\n"
	    "\t\"psize\" : %d,\n"
	    "\t\"mdpsize\" : %d,\n"
	    "\t\"state\" : %d,\n"
	    "\t\"retries\" : %d,\n"
	    "\t\"pid\" : %d,\n"
	    "\t\"faults\": [ ",
	    ml->timestamp, ml->plevel, ml->device, ml->oldname,
	    ml->first_journal_part,
	    ml->journal, ml->wal, ml->mdoffload,
	    ml->vdev_id.u, ml->vdev_id.l, ml->version,
	    ml->metamask, ml->bcache, ml->psize, ml->mdpsize,
	    ml->state, ml->retries, ml->pid);
	for (int i = 0; i < ml->n_faults; i++) {
		sprintf(buff +strlen(buff), "\"%d%c%d\"%c",
			ml->faults[i].error, ml->faults[i].source,
			ml->faults[i].plevel, i == ml->n_faults - 1 ? ' ' : ',');
	}
	sprintf(buff +strlen(buff), "]\n,\t\"mtcmd\" : [");
	for (int i = 0; i < ml->n_cmds; i++) {
		if (!strlen(ml->maintenance_cmd[i]))
			continue;
		sprintf(buff +strlen(buff), "\"%s\"%s",
			ml->maintenance_cmd[i], i == ml->n_cmds - 1 ? "" : ",");
	}
	sprintf(buff +strlen(buff),"]\n}\n");
	if (strlen(buff) + 1 > buf->len)
		return -ERANGE;
	strcpy(buf->base, buff);
	return 0;
}

static int
rd_metaloc_deserialize(uv_buf_t* buf, struct rd_metaloc* ml_out) {
	char* ptr = buf->base;
	assert(ml_out);
	struct rd_metaloc ml = *ml_out;

	/* read metafile */
	json_value *o = json_parse(buf->base, buf->len);
	if (!o) {
		log_error(lg, "Cannot parse metalloc meta record");
		return -ENOENT;
	}

	if (o->type != json_object) {
		log_error(lg, "Syntax error: metalloc not a JSON object");
		json_value_free(o);
		return -ENOENT;
	}

	/* read JSON and update device structure */
	size_t i;
	for (i = 0; i < o->u.object.length; i++) {
		if (strncmp(o->u.object.values[i].name,
			DEV_CREATED_TIMESTAMP,
			strlen(DEV_CREATED_TIMESTAMP)) == 0) {
			ml.timestamp =
				o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,
			"plevel", 6) == 0) {
			ml.plevel = o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,
			"version", 7) == 0) {
			ml.version = o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,
			"metamask", 8) == 0) {
			ml.metamask = o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,
			"bcache", 6) == 0) {
			ml.bcache = o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,
			"device", 6) == 0) {
			strcpy(ml.device, o->u.object.values[i].value->u.string.ptr);
		} else if (strncmp(o->u.object.values[i].name,
			"oldname", 7) == 0) {
			strcpy(ml.oldname, o->u.object.values[i].value->u.string.ptr);
		} else if (strncmp(o->u.object.values[i].name,
			"vdevid", 6) == 0) {
			uint128_fromhex(o->u.object.values[i].value->u.string.ptr, UINT128_BYTES * 2 + 1, &ml.vdev_id);
		} else if (strncmp(o->u.object.values[i].name,
			"journal", 7) == 0) {
			strcpy(ml.journal, o->u.object.values[i].value->u.string.ptr);
		} else if (strncmp(o->u.object.values[i].name,
			"offload", 7) == 0) {
			strcpy(ml.mdoffload, o->u.object.values[i].value->u.string.ptr);
		}  else if (strncmp(o->u.object.values[i].name,
			"jpart", 5) == 0) {
			ml.first_journal_part = o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,
			"state", 5) == 0) {
			ml.state = o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,
			"retries", 7) == 0) {
			ml.retries = o->u.object.values[i].value->u.integer;
		} else if (strcmp(o->u.object.values[i].name, "psize") == 0) {
			ml.psize = o->u.object.values[i].value->u.integer;
		} else if (strcmp(o->u.object.values[i].name, "mdpsize") == 0) {
			ml.mdpsize = o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,
			"wal", 3) == 0) {
			ml.wal = !!o->u.object.values[i].value->u.integer;
		} else if (strcmp(o->u.object.values[i].name, "pid") == 0) {
			ml.pid = o->u.object.values[i].value->u.integer;
		} else if (strncmp(o->u.object.values[i].name,"mtcmd", 6) == 0) {
			if (o->u.object.values[i].value->type != json_array) {
				log_error(lg, "Error parsing metaloc on device %s: "
					"the \"mtcmd\" isn't an array", ml.device);
				return -EINVAL;
			}
			json_value* v = o->u.object.values[i].value;
			assert(v);
			ml.n_cmds = 0;
			for (uint32_t j = 0; j < v->u.array.length; j++) {
				json_value* p = v->u.array.values[j];
				if (strlen(p->u.string.ptr) >= sizeof(ml.maintenance_cmd[0])) {
					log_error(lg, "A metaloc problem: maintenance command string \"%s\" is tool long",
						p->u.string.ptr);
					return -EINVAL;
				}
				strcpy(ml.maintenance_cmd[j], p->u.string.ptr);
				ml.n_cmds++;
			}
		} else if (strcmp(o->u.object.values[i].name, "pid") == 0) {
				ml.pid = !!o->u.object.values[i].value->u.integer;
		}else if (strncmp(o->u.object.values[i].name,
			"faults", 6) == 0) {
			if (o->u.object.values[i].value->type != json_array) {
				log_error(lg, "Error parsing metaloc on device %s: "
					"the \"faults\" isn't an array", ml.device);
				return -EINVAL;
			}
			json_value* v = o->u.object.values[i].value;
			assert(v);
			for (uint32_t j = 0; j < v->u.array.length; j++) {
				json_value* p = v->u.array.values[j];
				struct rd_fault_signature* s = ml.faults + ml.n_faults;
				int res = sscanf(p->u.string.ptr, "%d%c%d", &s->error, &s->source, &s->plevel);
				if (res != 3) {
					log_error(lg, "metaloc signature parsing error: %s", p->u.string.ptr);
					return -EINVAL;
				}
				ml.n_faults++;
			}
		}
	}
	json_value_free(o);
	*ml_out = ml;
	return 0;
}

static int
rd_read_metaloc(char *fname, uv_buf_t *meta)
{
	char mbuf[RD_METALOC_SIZE];
	int fd, err;

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		log_error(lg, "Cannot open vdev for read: %s", fname);
		return -errno;
	}

	err = pread(fd, mbuf, RD_METALOC_SIZE, DEV_RD_MAGIC_OFFSET);
	if (err <= 0) {
		close(fd);
		log_error(lg, "Cannot read vdev %s", fname);
		return -errno;
	}

	if (strncmp(mbuf, DEV_MAGIC, strlen(DEV_MAGIC)) != 0) {
		log_warn(lg, "foreign vdev detected %s", fname);
		close(fd);
		return -ENODEV;
	}

	if (meta) {
		memcpy(meta->base, mbuf + strlen(DEV_MAGIC), err - strlen(DEV_MAGIC));
		meta->len = err;
	}

	close(fd);
	return 0;
}

static int
rd_metaloc_to_disk(char *fname, uv_buf_t *meta)
{
	int fd, err;
	char buf[RD_METALOC_SIZE + strlen(DEV_MAGIC) + 1];

	assert(meta->len <= RD_METALOC_SIZE);

	memset(buf, 0, sizeof(buf));
	fd = open(fname, O_SYNC | O_WRONLY, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		log_error(lg, "Cannot open vdev: %s", fname);
		return -errno;
	}

	memcpy(buf, DEV_MAGIC, strlen(DEV_MAGIC));
	memcpy(buf + strlen(DEV_MAGIC), meta->base, meta->len);

	err = pwrite(fd, buf, sizeof(buf), DEV_RD_MAGIC_OFFSET);
	if (err < 0) {
		close(fd);
		log_error(lg, "Cannot write to vdev: %s", fname);
		return -errno;
	}
	log_info(lg, "Created meta record on vdev %s ", fname);

	close(fd);
	return 0;
}

static int
rd_metaloc_to_file(char *fname, uv_buf_t *meta)
{
	int fd, err;

	fd = open(fname, O_SYNC | O_WRONLY | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		log_error(lg, "Cannot open file: %s", fname);
		return -errno;
	}

	err = pwrite(fd, meta->base, strlen(meta->base), 0);
	if (err < 0) {
		close(fd);
		log_error(lg, "Cannot write to file: %s", fname);
		return -errno;
	}
	close(fd);
	return 0;
}


static int
rd_write_metaloc(char *fname, struct rd_metaloc* meta) {
	char buf[RD_METALOC_SIZE] = {0};
	char path[PATH_MAX];
	uv_buf_t ub = {.base = buf, .len = sizeof(buf) };
	int err =rd_metaloc_serialize(meta, &ub);

	err = rd_metaloc_to_disk(fname, &ub);
	if (err) {
		log_error(lg, "Dev(%s): cannot update metaloc: %d", meta->device,
			err);
		return err;
	}
	sprintf(path, "%s/var/run/disk/%s.metaloc", nedge_path(), meta->device);
	err = rd_metaloc_to_file(path, &ub);
	if (err)
		log_error(lg, "Dev(%s): cannot update metaloc: %d", meta->device,
			err);
	return err;
}

static int
rd_update_version(struct repdev *dev)
{
	struct repdev_rd* rd = dev->device_lfs;
	int err = rd_write_metaloc(dev->path, &rd->metaloc);
	if (err) {
		log_error(lg, "Dev(%s): cannot update metaloc: %d", dev->name, err);
	}

	return err;
}

static int
rd_version_convert(struct repdev* dev) {
	struct repdev_rd *rd = dev->device_lfs;
	int err = 0;
	int update = 0;
	int version = rd->metaloc.version;
	assert(rd->metaloc.plevel > 0);
	assert(rd->metaloc.bcache == 0 || rd->metaloc.bcache == 1);
	assert(!strlen(rd->metaloc.journal) || (rd->metaloc.metamask > 0 && rd->metaloc.metamask <= 0xff));
	if (version == DEV_RD_VERSION) {
		log_notice(lg, "Dev(%s) RTRD version matched", rd->metaloc.device);
		return 0;
	}
	if (version > DEV_RD_VERSION) {
		log_notice(lg, "Dev(%s) the detected RTRD version %d is newer "
			"than current %d, skipping", dev->name, version, DEV_RD_VERSION);
		return 0;
	}
	if (version)
		log_notice(lg, "Dev(%s) the detected RTRD version %d",
			rd->metaloc.device, version);

	if (version < 3 && rd->mdcache) {
		err = rd_rebuild_mdcache(dev);
		if (err)
			log_error(lg, "Dev(%s) mdcache conversion error: %d",
				rd->metaloc.device, err);
	}

	if (version < 4) {
		/* mark bloom toxic */
		uv_buf_t u_key, u_val;
		u_key.base = BLOOM_STORE_OK;
		u_key.len = strlen(u_key.base);
		int val = -1;
		u_val.base = (char *) &val;
		u_val.len = sizeof(int);
		err = rd_config_impl(dev, CFG_WRITE, &u_key, &u_val);
		if (err != 0) {
			log_error(lg, "Dev(%s) error while making bloom toxic: %d",
				rd->metaloc.device, err);
			return -EINVAL;
		}
	}

	if (version < 5) {
		/*
		 * In the 5th version we dropped support of metainfo entry in LMDB,
		 * the per-row data usage support has been added.
		 * We need to create it before starting IO.
		 */
		err = rd_create_rowusage_entry(dev);
		if (err) {
			log_error(lg, "Dev(%s) rowusage creation error: %d",
				dev->name, err);
			return err;
		}
	}
	rd->metaloc.version = DEV_RD_VERSION;
	rd->metaloc.timestamp = time(NULL);
	err = rd_update_version(dev);
	if (!err) {
		if (version)
			log_notice(lg, "Dev(%s) RTRD version has been converted",
				rd->metaloc.device);
		else
			log_notice(lg, "Dev(%s) RTRD metaloc record created",
				rd->metaloc.device);
	}
	return err;
}

static int
rd_bcache_name_by_kdev(const char* kdevname, int part_index, char* bcachedev) {
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int err = 0;
	const char *kdev = kdevname + strlen("/dev/");
	char fname[PATH_MAX];

	snprintf(fname, PATH_MAX, "/sys/block/%s/%s%d/bcache/dev/uevent",
	    kdev, kdev, part_index);

	for (int uevent_retry = 0; uevent_retry < 120; uevent_retry++) {
		fp = fopen(fname, "r");
		if (fp)
			break;
		sleep(1);
	}
	if (fp == NULL)
		return -EIO;

	bcachedev[0] = 0;
	while ((read = getline(&line, &len, fp)) != -1) {
		char keyname[len];
		char val[len];
		err = sscanf(line, "%32[^=]=%s", keyname, val);
		free(line);
		line = NULL;
		if (err >= 0 && strcmp(keyname, "DEVNAME") == 0) {
			strcpy(bcachedev, val);
			break;
		}
	}
	if (line)
		free(line);

	fclose(fp);

	if (bcachedev[0] == 0)
		return -ENOENT;
	return 0;
}

static int
rd_command_process(struct repdev* dev, struct rd_metaloc* meta, int env_inited);

/* Creates 3 types of partitions:
 * 1) #parts "main" partitions
 * 2) #jparts WAL partitions
 * 3) #cpart mdoffload partitions
 */
static int
rd_partition(struct reptrans *rt, const char *name, int parts, int jparts, int initial_discard,
    int mdcache_reserved, int cparts, int actual_plevel, int *created_out)
{
	char fname[PATH_MAX];
	char dname[PATH_MAX];
	char cmd[8 * PATH_MAX];
	char tmp[8 * PATH_MAX];
	struct stat st;
	long blk = 0, ssz = 0;
	int err;

	*created_out = 0;

	snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s", name);
	char *kdevname = realpath(fname, dname);

	err = rd_get_size(fname, &blk, &ssz);
	if (err)
		return err;

	if (rt->init_traits) {
		struct ccowd_params* params = rt->init_traits;
		if (params->log_flush || params->log_recovery)
			return -ENODEV;
	}

	uint64_t jpart_size = 4ULL*DEV_RD_JPART_MINSIZE(actual_plevel)/3ULL;
	jpart_size = ((jpart_size) & ~(4096-1));
	jpart_size /= (size_t)ssz;

	uint64_t part_size = 0;
	uint64_t cpart_size = 0;

	if (!parts) {
		if (cparts)
			cpart_size = ((blk - DEV_RD_HEADROOM - (uint64_t)jparts * jpart_size) / (uint64_t)cparts);
	} else {
		part_size = ((blk - DEV_RD_HEADROOM - (uint64_t)jparts * jpart_size) / parts);
		if (mdcache_reserved != -1) {
			cpart_size = ((uint64_t)mdcache_reserved * part_size / 100) * (uint64_t)parts / (uint64_t)cparts;
			part_size = (100UL - (uint64_t)mdcache_reserved) * part_size / 100;
		}
	}


	if ((uint64_t)blk < DEV_RD_HEADROOM + (uint64_t)jparts * jpart_size + (uint64_t)cparts * cpart_size) {
		uint64_t need = (1ULL + ssz *
		    (DEV_RD_HEADROOM + (uint64_t)jparts * jpart_size + (uint64_t)cparts * cpart_size)) /
			(1024ULL * 1024ULL);
		log_error(lg, "Dev(%s, %s): device too small, need at least %ldMB",
		    name, kdevname, need);
		return err;
	}

	char *devname = kdevname + strlen("/dev/");
	if (!is_rotational(devname) && initial_discard) {
		snprintf(cmd, 8 * PATH_MAX, "mkswap -f %s >/dev/null 2>/dev/null; "
		    "swapon -d %s >/dev/null 2>/dev/null; "
		    "swapoff %s >/dev/null 2>/dev/null; "
		    "wipefs -o 0xff6 %s >/dev/null 2>/dev/null",
		    kdevname, kdevname, kdevname, kdevname);
		err = system(cmd);
		if (err) {
			log_warn(lg, "Dev(%s, %s): cannot send TRIM: %d",
			    name, kdevname, err);
		} else {
			log_notice(lg, "Dev(%s, %s): TRIM issued successfully",
			    name, kdevname);
		}
	}

	snprintf(cmd, 8 * PATH_MAX, "sgdisk -S %d %s >/dev/null 2>/dev/null",
	    2 + parts + jparts + cparts, kdevname);
	err = system(cmd);
	if (err) {
		log_error(lg, "Dev(%s, %s): cannot allocate %d partitions: %d",
		    name, kdevname, parts, err);
		log_error(lg, "FAILED CMD: %s", cmd);
		return err;
	}

	strcpy(cmd, "sgdisk");
	for (int i = 1; i < parts + 1; i++) {
		snprintf(tmp, 8 * PATH_MAX, " -n %d:0:%ld -t %d:8300 -c %d:'Replicast Data'",
		    i, i * part_size, i, i);
		strcat(cmd, tmp);
	}
	for (int j = 1; j < jparts + 1; j++) {
		snprintf(tmp, 8 * PATH_MAX, " -n %d:0:%ld -t %d:8300 -c %d:'Replicast Journal'",
		    parts + j, parts * part_size + j * jpart_size,
		    parts + j, parts + j);
		strcat(cmd, tmp);
	}
	for (int j = 1; j < cparts + 1; j++) {
		snprintf(tmp, 8 * PATH_MAX, " -n %d:0:%ld -t %d:8300 -c %d:'Replicast MD Cache'",
		    parts + jparts + j, parts * part_size + jparts * jpart_size + j * cpart_size,
		    parts + jparts + j, parts + jparts + j);
		strcat(cmd, tmp);
	}
	snprintf(tmp, 8 * PATH_MAX, " -n %d:%ld:%ld -t %d:8300 -c %d:'Replicast Config'",
	    parts + jparts + cparts + 1, DEV_RD_MAGIC_OFFSET / ssz, DEV_RD_MAGIC_OFFSET / ssz + 1,
	    parts + jparts + cparts + 1, parts + jparts + cparts + 1);
	strcat(cmd, tmp);

	snprintf(tmp, 8 * PATH_MAX, " %s >/dev/null 2>/dev/null", kdevname);
	strcat(cmd, tmp);

	int retry = 0; /* to workaround redhat bug (they use older version) */
	do {
		err = system(cmd);
		if (err) {
			if (retry++ < 3) {
				sleep(1);
				if (retry == 1) {
					snprintf(tmp, 8 * PATH_MAX, "partprobe %s >/dev/null 2>/dev/null", kdevname);
					err = system(tmp);
				}
				continue;
			}
			log_error(lg, "Dev(%s, %s): cannot create partitions: %d",
			    name, kdevname, err);
			log_error(lg, "FAILED CMD: %s", cmd);
			return err;
		}
	} while (err);

	/* give kernel some time */
	usleep(3000000);

	snprintf(cmd, 8 * PATH_MAX, "partprobe -s %s >/dev/null 2>/dev/null", kdevname);
	err = system(cmd);
	int retries = 20;

	do {
		usleep(1000000);
		err = 0;
		/* Make sure partitions were created */
		for (int i = 1; i < parts + jparts + cparts + 1; i++) {
			snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s-part%d", name, i);
			char *kdevname = realpath(fname, dname);
			if (!kdevname) {
				log_warn(lg, "Dev(%s) couldn't resolve partition path for %s",
					name, fname);
				err = -ENOENT;
			} else {
				int res = rd_is_block_device(kdevname);
				if (res != 1) {
					log_warn(lg, "Dev(%s) %s is not a block device",
						name, kdevname);
					err = -ENOANO;
				}
			}
			if (err)
				break;
		}
	} while (err && --retries > 0);

	if (err) {
		log_error(lg, "Dev(%s) couldn't resolve created partition(s). Make "
			"sure device or partition entry in the /dev folder isn't "
			"replaced by a regular file", name);
		return err;
	}

	log_notice(lg, "Dev(%s, %s): created %d main partitions of size %ldMB, "
	    " %d WAL journals and %d MD caches", name, kdevname, parts,
	    part_size * ssz / 1024 / 1024, jparts, cparts);

	*created_out = parts + jparts;

	return 0;
}

static int
rd_make_bcache(json_value *devices, const char *jname, int parts, int bcache_discard,
    int bcache_bucket_size, char** created_main_parts, int n_parts,
    int wipe_cache_device)
{
	char fname[PATH_MAX] = { 0 };
	char dname[PATH_MAX] = { 0 };
	char cmd[128 * PATH_MAX] = { 0 };
	char tmp[128 * PATH_MAX] = { 0 };
	int err;

	/* ensure kernel module actually pre-loaded */
	err = system("modprobe bcache");
	if (err) {
		log_warn(lg, "Dev(%s): cannot load bcache kernel module: %d",
		    jname, err);
	}

	/* need some delay after module is loaded */
	sleep(1);

	/* cache device has to have part1 pre-created */
	snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s-part1", jname);
	char *kdevname = realpath(fname, dname);

	if (wipe_cache_device) {
		log_notice(lg, "Wiping bcache caching device at %s", fname);
		snprintf(cmd, 128 * PATH_MAX, "wipefs --force -a %s >/dev/null 2>/dev/null", fname);
		err = system(cmd);

		snprintf(cmd, 128 * PATH_MAX, "make-bcache -b %dK -w 4K --wipe-bcache -C %s",
		    bcache_bucket_size, fname);

		if (bcache_discard)
			strcat(cmd, " --discard ");

		strcat(cmd, " --writeback >/dev/null 2>/dev/null");

		int attempts = 0;
		do {
			err = system(cmd);
			usleep(100000);

			/* workaround for bcache bug, somtimes need to run it twice */
			err = system(cmd);

			snprintf(tmp, 128 * PATH_MAX, "bcache-super-show %s 2>/dev/null >/dev/null",
			    kdevname);
			err = system(tmp);
			if (err) {
				log_warn(lg, "Dev(%s): bcache-super-show %s returns err %d, retry %d",
				    jname, kdevname, err, attempts);
				usleep(1000000);
			}
		} while (err && attempts++ < 3);
	}

	snprintf(cmd, 128 * PATH_MAX, "bcache-super-show %s|awk '/cset.uuid/{print $2}'", fname);
	FILE *fp = popen(cmd, "r");
	if (!fp) {
		log_error(lg, "Dev(%s): cannot read bcache cset: %d",
		    jname, -errno);
		return err;
	}

	char *cset;
	err = fscanf(fp, "%ms", &cset);
	pclose(fp);

	if (err != 1) {
		log_error(lg, "Dev(%s): cannot parse bcache cset: %d",
		    jname, -errno);
		return -EBADF;
	}

	int n_attached = 0;
	for (size_t i = 0; i < devices->u.array.length; i++) {
		json_value *d = devices->u.array.values[i];

		char *name = NULL;
		char *journal = NULL;
		for (size_t j = 0; j < d->u.object.length; j++) {
			char *namekey = d->u.object.values[j].name;
			json_value *v = d->u.object.values[j].value;

			if (strcmp(namekey, "name") == 0) {
				name = v->u.string.ptr;
			} else if (strcmp(namekey, "journal") == 0) {
				if (strcmp(v->u.string.ptr, jname) == 0) {
					journal = v->u.string.ptr;
					break;
				}
			}
		}

		if (!journal)
			continue;

		if (!wipe_cache_device) {
			int skip = 1;
			for (int k = 0; k < n_parts; k++) {
				if (!strcmp(created_main_parts[k], name)) {
					skip = 0;
					break;
				}
			}
			if (skip)
				continue;
		}

		int first = 1;
		while(first <= parts) {
			snprintf(cmd, 128 * PATH_MAX, "make-bcache -b %dK -w 4K --cset-uuid=%s",
			    bcache_bucket_size, cset);

			snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s", name);
			char *kdevname_backend = realpath(fname, dname);
			int last = first + 3 > parts ? parts : first + 3;

			for (int i = first; i <= last; i++) {
				snprintf(tmp, 128 * PATH_MAX, " -B %s%d", kdevname_backend, i);
				strcat(cmd, tmp);
			}

			if (bcache_discard)
				strcat(cmd, " --discard ");

			strcat(cmd, " --writeback >/dev/null 2>/dev/null");

			int attempts = 0;
			do {
				err = system(cmd);
				usleep(100000);

				/* workaround for bcache bug, somtimes need to run it twice */
				err = system(cmd);

				snprintf(tmp, 128 * PATH_MAX, "bcache-super-show %s%d 2>/dev/null >/dev/null",
				    kdevname_backend, 1);
				err = system(tmp);
				if (err) {
					log_warn(lg, "Dev(%s): bcache-super-show %s returns err %d, retry %d",
					    jname, kdevname_backend, err, attempts);
					/* could be kernel slow on part creations */
					usleep(1000000);
				}
			} while (err && attempts++ < 3);

			for (int i = first; i <= last; i++) {
				char bcachedev[128] = {0};
				err = rd_bcache_name_by_kdev(kdevname_backend, i, bcachedev);
				if (!err)
					log_notice(lg, "Dev(%s) %s%d -> /dev/%s", jname,
						kdevname_backend, i, bcachedev);
				else {
					log_error(lg, "Dev(%s) bcache lookup error for %s%d: %d",
						jname, kdevname_backend, i, err);
					return -EIO;
				}
			}
			first = last + 1;
		}
		n_attached++;
	}

	if (n_attached)
		log_notice(lg, "Dev(%s): bcache active for %d main partitions",
			jname, parts * n_attached);

	free(cset);
	return 0;
}

static int
rd_calc_plevel(const char* name) {

	int rc = 0;
	char fname[PATH_MAX];
	char dname[PATH_MAX];
	long blk = 0, ssz = 0;
	snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s", name);
	char *kdevname = realpath(fname, dname);
	int err = rd_get_size(kdevname, &blk, &ssz);
	if (err) {
		log_error(lg, "Dev(%s) error getting disk size: %d", name, err);
		return err;
	}
	int p = (blk*ssz) / DEV_RD_PREFERED_PART_SIZE;
	if ((blk*ssz) % DEV_RD_PREFERED_PART_SIZE > DEV_RD_PREFERED_PART_SIZE / 2)
		p++;
	/* Adjust to power of 2 */
	rc = 1;
	while (p > rc)
		rc <<= 1;
	if (is_embedded() && rc > RT_RD_PLEVEL_EMBEDDED)
		rc = RT_RD_PLEVEL_EMBEDDED;
	return rc;
}

static char*
rd_kpath(const char* disk_id, int index, char* buffer) {
	char aux[PATH_MAX];
	if (!index)
		sprintf(aux, "/dev/disk/by-id/%s", disk_id);
	else
		sprintf(aux, "/dev/disk/by-id/%s-part%d", disk_id, index);
	return realpath(aux, buffer);
}

/* The jgroup is a journal group that gets together VDEVs attached to the
 *  same SSD device. All the pointers in it are borrowed from corresponding
 *  rd_metaloc structure.
 */
struct jgroup {
	const char* journal_device;
	uint16_t n_members;
	int plevel; /* Maximum VDEV plevel in this group */
	struct rd_metaloc* members[DEV_JMEMBERS_MAX];
	/* These to be fetched from rt-rd.json */
	int bcache_discard;
	int bcache_bucket_size;
	int mdcache_reserved;
	int initial_discard;
	int wipe_bcache;

};

struct rd_disks {
	size_t n_disks;
	struct rd_metaloc* metas;
	struct jgroup groups[DEV_JOURNALS_MAX];
	size_t n_groups;
};

int
rd_fetch_disk_info(json_value *devices, struct rd_disks** disks_out) {
	assert(devices);
	assert(disks_out);
	char fname[PATH_MAX];
	size_t jgindex[DEV_RD_MAXNUM]={0};
	size_t jgoffset[DEV_RD_MAXNUM]={0};

	struct rd_disks* disks = NULL;
	int err = 0;

	if (!devices->u.array.length)
		return -ENOENT;

	disks = je_calloc(1, sizeof(*disks));
	if (!disks)
		return -ENOMEM;

	disks->n_disks = devices->u.array.length;
	disks->metas = je_calloc(disks->n_disks, sizeof(struct rd_metaloc));
	if (!disks->metas) {
		err = -ENOMEM;
		goto _exit;
	}

	for (size_t i = 0; i < devices->u.array.length; i++) {
		json_value *d = devices->u.array.values[i];

		/* syntax error, but continue to the next device */
		if (d->type != json_object) {
			log_error(lg, "Syntax error: dev.%lu is not an object", i);
			return -EINVAL;
		}

		char *journal = NULL;
		char *name = NULL;
		int plevel = 0, bcache = -1, wal = 1;
		int psize = DEV_RD_PSIZE;
		int mdpsize = DEV_RD_MDPSIZE;
		/* Looking for disk ID */
		for (size_t j = 0; j < d->u.object.length; j++) {
			char *namekey = d->u.object.values[j].name;
			json_value *v = d->u.object.values[j].value;
			if (strcmp(namekey, "name") == 0) {
				if (v->type != json_string) {
					log_error(lg, "Syntax error: "
					    "dev.%lu.%lu.name is not a string",
					    i, j);
					return -EINVAL;
				}
				name = v->u.string.ptr;
				break;
			}
		}

		if (!name) {
			log_error(lg, "Couldn't find device name at index %lu", i);
			err = -ENOENT;
			goto _exit;
		}

		/* Check whether the partition configured already */
		snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s", name);
		char mbuf[RD_METALOC_SIZE];
		uv_buf_t ml_ub = {.len = sizeof(mbuf), .base = mbuf};
		/* check if this is new device? */
		disks->metas[i].version = 0;
		disks->metas[i].bcache = -1;
		disks->metas[i].plevel = 0;
		disks->metas[i].metamask = 0;
		disks->metas[i].wal = -1;
		disks->metas[i].psize = 0;
		disks->metas[i].mdpsize = 0;
		disks->metas[i].vdev_id.u = 0;
		disks->metas[i].vdev_id.l = 0;
		err = rd_read_metaloc(fname, &ml_ub);
		if (!err)
			err = rd_metaloc_deserialize(&ml_ub, disks->metas + i);
		/*
		 * if a metaloc record exists and it has the latest version,
		 * then skip further initialization
		 */
		if (!err && disks->metas[i].version == DEV_RD_VERSION)
			continue;
		err = 0;
		strcpy(disks->metas[i].device, name);
		for (size_t j = 0; j < d->u.object.length; j++) {
			char *namekey = d->u.object.values[j].name;
			json_value *v = d->u.object.values[j].value;

			if (strcmp(namekey, "journal") == 0) {
				if (v->type != json_string) {
					log_error(lg, "Syntax error: "
					    "dev.%lu.%lu.journal is not a string",
					    i, j);
					return -EINVAL;
				}
				journal = v->u.string.ptr;
			} else if (strcmp(namekey, "plevel_override") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%lu.%lu.plevel_override is not an "
					    "integer", i, j);
					err = 1;
					continue;
				}
				plevel = v->u.integer;
			} else if (strcmp(namekey, "wal_disabled") == 0) {
				wal = !v->u.integer;
			} else if (strcmp(namekey, "bcache") == 0) {
				bcache = !!v->u.integer;
			} else if (strcmp(namekey, "mdpsize") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
					    "dev.%s.mdpsize is not an "
					    "integer", name);
						continue;
				}
				mdpsize = v->u.integer;
			} else if (strcmp(namekey, "psize") == 0) {
				if (v->type != json_integer) {
					log_warn(lg, "Syntax error: "
						    "dev.%s.psize is not an "
						    "integer", name);
					continue;
				}
				psize = v->u.integer;
			}
		}

		if (!disks->metas[i].plevel) {
			if (!plevel) {
				plevel = rd_calc_plevel(name);
				if (plevel <= 0) {
					log_error(lg, "Dev(%s) plevel calc error %d",
						name, plevel);
					err = plevel;
					goto _exit;
				}
				log_info(lg, "Dev(%s) calculated plevel %d", name, plevel);
			}
			disks->metas[i].plevel = plevel;
		}

		if (disks->metas[i].wal < 0)
			disks->metas[i].wal = wal;
		if (disks->metas[i].bcache < 0 && bcache >= 0)
			disks->metas[i].bcache = bcache;
		else {
			/*  RTRD prior v4 had another default bcache ena/dis value.
			 *  Since v5 bcache option is in metaloc.
			 *  Using bcache autodetection if bcache ins't found in metaloc
			 */
			char buff[PATH_MAX];
			char* kdevname = rd_kpath(name, 0, buff);
			char *kdev = kdevname + strlen("/dev/");
			snprintf(fname, PATH_MAX, "/sys/block/%s/%s1/bcache/dev/uevent",
				kdev, kdev);
			struct stat st;
			int rc = stat(fname, &st);
			disks->metas[i].bcache = rc ? 0 : 1;
			log_notice(lg, "Dev(%s) bcache %s (autodetected)",
				name, disks->metas[i].bcache ? "enabled" :
				"disabled");
		}
		if (!disks->metas[i].psize)
			disks->metas[i].psize = psize;

		if (!disks->metas[i].mdpsize)
			disks->metas[i].mdpsize = mdpsize;

		if (journal)
			strcpy(disks->metas[i].journal, journal);
		else
			disks->metas[i].journal[0] = 0;
	}

	memset(jgindex, 0, sizeof(jgindex));
	memset(jgoffset, 0, sizeof(jgindex));
	/* Detecting journal groups */
	for (size_t i = 0; i < disks->n_disks; i++) {
		if (!disks->metas[i].journal[0])
			continue;
		json_value *d = devices->u.array.values[i];
		int bcache_discard = 0;
		int bcache_bucket_size = BCACHE_BUCKET_SIZE_KB;
		int mdcache_reserved = MDCACHE_RESERVED_PCT;
		int initial_discard = 0;

		for (size_t j = 0; j < d->u.object.length; j++) {
			char *namekey = d->u.object.values[j].name;
			json_value *v = d->u.object.values[j].value;
			if (strcmp(namekey, "bcache_discard") == 0) {
				bcache_discard = v->u.integer;
			} else if (strcmp(namekey, "bcache_bucket_size") == 0) {
				bcache_bucket_size = v->u.integer;
			} else if (strcmp(namekey, "mdcache_reserved") == 0) {
				mdcache_reserved = v->u.integer;
			} else if (strcmp(namekey, "initial_discard") == 0) {
				initial_discard = v->u.integer;
			}
		}
		struct jgroup* jg = NULL;
		for (size_t j = 0; j < DEV_JOURNALS_MAX; j++) {
			if (!disks->groups[j].journal_device) {
				jg = disks->groups + j;
				jg->journal_device = disks->metas[i].journal;
				jg->members[0] = disks->metas + i;
				jg->n_members = 1;
				jg->plevel = disks->metas[i].plevel;
				disks->n_groups++;
				jgoffset[i] = 0;
				jgindex[i] = j;
				break;
			}
			if (!strcmp(disks->groups[j].journal_device, disks->metas[i].journal)) {
				jg = disks->groups + j;
				uint16_t didx = jg->n_members;
				jg->members[didx] = disks->metas + i;
				/* Override disk plevel with maximum in this jgroup */
				if (disks->metas[i].plevel > jg->plevel)
					jg->plevel = disks->metas[i].plevel;
				jgoffset[i] = didx;
				jg->n_members++;
				jgindex[i] = j;
				break;
			}
		}
		if (jg) {
			if (!jg->bcache_discard)
				jg->bcache_discard = bcache_discard;
			if (jg->bcache_bucket_size < bcache_bucket_size)
				jg->bcache_bucket_size = bcache_bucket_size;
			if (jg->mdcache_reserved < mdcache_reserved)
				jg->mdcache_reserved = mdcache_reserved;
			if (!jg->initial_discard)
				jg->initial_discard = initial_discard;
		}
	}
	/* Finishing metalocs */
	for (size_t i = 0; i < disks->n_disks; i++) {
		struct rd_metaloc* meta = disks->metas + i;

		if (meta->version == DEV_RD_VERSION)
			continue;

		if (!meta->journal[0]) {
			meta->mdoffload[0] = 0;
			if (!meta->wal)
				meta->first_journal_part = 0;
			else
				meta->first_journal_part = DEV_LOGID_MAX * meta->plevel + 1;
		} else {
			struct jgroup* jg = disks->groups + jgindex[i];
			meta->plevel = jg->plevel;
			if (!meta->wal) {
				meta->first_journal_part = 0;
				int opart = (meta->bcache ? 1 : 0) + jgoffset[i] + 1;
				sprintf(meta->mdoffload, "%s-part%d",
					meta->journal, opart);
			} else {
				meta->first_journal_part = (meta->bcache ? 1 : 0) +
					jgoffset[i]*meta->plevel + 1;
				int mdpart_index = meta->plevel*jg->n_members +
					jgoffset[i] + (meta->bcache ? 1 : 0) + 1;
				sprintf(meta->mdoffload, "%s-part%d",
					meta->journal, mdpart_index);
			}
		}
	}

_exit:
	if (err && disks) {
		if (disks->metas)
			je_free(disks->metas);
		je_free(disks);
	} else if (!err)
		*disks_out = disks;
	return err;
}

static int
rd_check_and_create_partitions(struct reptrans *rt, json_value *json_dev,
	struct rd_disks* rdisks, const char* disk_name) {
	char fname[PATH_MAX] = {0};
	int err = 0;

	char** created_main_parts = je_calloc(rdisks->n_disks, sizeof(char*));
	int n_main_parts_created = 0;
	int parts_created = 0;
	struct jgroup* jg = NULL;
	int replace = 0;

	for (size_t i = 0 ; i < rdisks->n_disks; i++) {
		/* create partitions on "main" device HDD
		 * There are:
		 * main partitions: #plevel
		 * journal partitions: #plevel or 0 (if journal disabled or on SSD)
		 **/
		struct rd_metaloc* meta = rdisks->metas + i;

		/* If disk name is provided, then process only this VDEV */
		if (disk_name && strcmp(meta->device, disk_name))
			continue;

		for (int n = 0; n < meta->n_cmds; n++) {
			if (!strcmp(meta->maintenance_cmd[n], CMD_DISK_REPLACE_SIGNATURE) &&
				(meta->state == rdstateMaintenance)) {
				replace = 1;
				break;
			}
		}

		if (meta->version) {
			/* The metalock has version set that means
			 * the partition has been allocated already.
			 * Skip partitioning unless this is a disk replacement
			 * command
			 */
			if (!replace)
				continue;
		}


		for (size_t j = 0; j < rdisks->n_groups; j++)
			if (!strcmp(meta->journal, rdisks->groups[j].journal_device)) {
				jg = rdisks->groups + j;
				break;
			}

		int has_journal = strlen(meta->journal);
		int create_jparts = (!meta->wal || has_journal) ? 0 : 1;
		int created = 0;
		int discard = jg ? jg->initial_discard : 0;
		err = rd_partition(rt, meta->device, meta->plevel,
			DEV_LOGID_MAX * meta->plevel * create_jparts,
			discard, -1, 0, meta->plevel, &created);
		if (err)
			return err;

		if (created) {
			/* We just created a new main partition. If it will be
			 * attached to bcache, then we have to wipe it out.
			 */
			int lreplace = 0;
			for (int n = 0; n < meta->n_cmds; n++) {
				if (!strcmp(meta->maintenance_cmd[n], CMD_DISK_REPLACE_SIGNATURE) &&
					(meta->state == rdstateMaintenance)) {
					lreplace = 1;
					break;
				}
			}
			created_main_parts[n_main_parts_created++] = je_strdup(meta->device);
			if (has_journal && meta->bcache && !lreplace) {
				assert(jg);
				jg->wipe_bcache = 1;
			}
		}
		parts_created += created;
	}

	/*
	 * Partitioning SSD(s)
	 * There can be:
	 * 1) a caching partition for bcache (if enabled)
	 * 2) #plevel*#journal_group_members WAL partitions (if enabled)
	 * 3) #journal_group_members mdcache/mdoffload partitions
	 *
	 */
	for (size_t k = 0; k < rdisks->n_groups; k++) {
		if (!replace)
			jg = rdisks->groups + k;
		else
			assert(jg);
		int created = 0;
		const char* jname = jg->journal_device;
		int bcache = jg->members[0]->bcache;
		int wal = jg->members[0]->wal;

		/* Check whether the partition configured already */
		snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s", jname);
		char mbuf[RD_METALOC_SIZE];
		uv_buf_t ml_ub = {.len = sizeof(mbuf), .base = mbuf};
		/* Skip already initialized journals */
		err = rd_read_metaloc(fname, &ml_ub);
		if (err == -ENODEV) {
			log_notice(lg, "A metaloc entry not found for journal %s, partitioning", jname);
			err = rd_partition(rt, jname, bcache ? 1 : 0,
				wal ? jg->n_members * jg->plevel * DEV_LOGID_MAX : 0,
				jg->initial_discard, jg->mdcache_reserved, jg->n_members,
				jg->plevel, &created);
			if (!err) {
				/* Append metaloc entry to journal device */
				err = rd_metaloc_serialize(jg->members[0], &ml_ub);
				assert(err == 0);
				err = rd_metaloc_to_disk(fname, &ml_ub);
			}
		}
		if (err)
			return err;

		parts_created += created;

		if (bcache && n_main_parts_created) {
			rd_make_bcache(json_dev, jname, jg->plevel,
				jg->bcache_discard, jg->bcache_bucket_size,
				created_main_parts, n_main_parts_created,
				jg->wipe_bcache);
		}
		if (replace)
			break;
	}

	if (parts_created)
		/* data-container work-around (this will succeed in container only) */
		err = system("mount -t devtmpfs /dev /dev >/dev/null 2>/dev/null");
	je_free(created_main_parts);
	return 0;
}

static int
rd_command_process(struct repdev* dev, struct rd_metaloc* meta, int env_inited) {
	int faultID = -ERANGE;
	char pathbuff[PATH_MAX];
	char* kpath = rd_kpath(meta->device, 0, pathbuff);
	for (int cmd_idx = 0; cmd_idx < RT_RD_PLEVEL_MAX; cmd_idx++)
	for (size_t i = 0; i < sizeof(rd_maintenance_commands)/sizeof(rd_maintenance_commands[0]); i++) {
		if (strstr(meta->maintenance_cmd[cmd_idx], rd_maintenance_commands[i].id) == meta->maintenance_cmd[cmd_idx]) {
			if (env_inited != !!(rd_maintenance_commands[i].flags & RDMT_FLAG_LMDB_INIT)) {
				/* The calling mode doest match */
				return -EDOM;
			}
			faultID = faultID == -ERANGE ? 0 : faultID;
			char buf[RD_METALOC_SIZE];
			uv_buf_t ub = {.base = buf, .len = sizeof(buf) };

			/* Increment and store retry counter */
			meta->retries++;
			meta->pid = getpid();
			int err = rd_write_metaloc(kpath, meta);
			if (err) {
				log_error(lg, "Unable to store "
					"metaloc on %s", meta->device);
				return err;
			}
			/* Run maintenance command */
			log_notice(lg, "Dev(%s) running command %s", meta->device,
				meta->maintenance_cmd[cmd_idx]);
			err = rd_maintenance_commands[i].func(dev, cmd_idx, meta);
			meta->pid = 0;
			if (!err || err == -ENOTTY) {
				/* No error, the clear processed command and error counter*/
				meta->retries = 0;
				meta->maintenance_cmd[cmd_idx][0] = 0;
				err = 0;
			} else if (meta->retries >= 3) {
				meta->state = rdstateFault;
				meta->retries = 0;
				int n = meta->n_faults++;
				meta->faults[n].error = 0;
				meta->faults[n].source = 'c';
				meta->faults[n].plevel = 0;
				log_error(lg, "Dev(%s) maintenance command %s failed %d",
					meta->device, meta->maintenance_cmd[cmd_idx], err);
				faultID = err;
			}
			int rc = rd_write_metaloc(kpath, meta);
			if (rc) {
				log_error(lg, "Unable to store metaloc on %s",
					meta->device);
				return rc;
			}
		}
	}
	if (!meta->retries) {
		meta->state = rdstateOk;
		int rc = rd_write_metaloc(kpath, meta);
		if (rc) {
			log_error(lg, "Unable to store metaloc on %s",
				meta->device);
			return rc;
		}
	}
	return faultID;
}

static int
rd_tune_bcache(struct repdev_db* db, const json_value *d) {
	int bcache_writearound = BCACHE_CACHE_MODE;
	int bcache_sequential_cutoff = BCACHE_SEQUENTIAL_CUTOFF;
	int bcache_sequential_merge = 0;
	int bcache_writeback_percent = BCACHE_WBC_PERCENT;
	int bcache_writeback_delay = BCACHE_WBC_DELAY;
	int bcache_congested_read_threshold_us = 0;
	int bcache_congested_write_threshold_us = 0;

	struct repdev* dev = db->dev;

	for (size_t j = 0; j < d->u.object.length; j++) {
		char *namekey = d->u.object.values[j].name;
		json_value *v = d->u.object.values[j].value;

		if (strcmp(namekey, "bcache_writearound") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bcache_writearound is not an "
				    "integer", dev->name);
				continue;
			}
			bcache_writearound = v->u.integer;
		} else if (strcmp(namekey, "bcache_sequential_cutoff") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bcache_sequential_cutoff is not an "
				    "integer", dev->name);
				continue;
			}
			bcache_sequential_cutoff = v->u.integer;
		} else if (strcmp(namekey, "bcache_sequential_merge") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bcache_sequential_merge is not an "
				    "integer", dev->name);
				continue;
			}
			bcache_sequential_merge = v->u.integer;
		} else if (strcmp(namekey, "bcache_writeback_percent") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bcache_writeback_percent is not an "
				    "integer", dev->name);
				continue;
			}
			bcache_writeback_percent = v->u.integer;
		} else if (strcmp(namekey, "bcache_writeback_delay") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bcache_writeback_delay is not an "
				    "integer", dev->name);
				continue;
			}
			bcache_writeback_delay = v->u.integer;
		} else if (strcmp(namekey, "bcache_congested_read_threshold_us") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bcache_congested_read_threshold_us is not an "
				    "integer", dev->name);
				continue;
			}
			bcache_congested_read_threshold_us = v->u.integer;
		} else if (strcmp(namekey, "bcache_congested_write_threshold_us") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bcache_congested_write_threshold_us is not an "
				    "integer", dev->name);
				continue;
			}
			bcache_congested_write_threshold_us = v->u.integer;
		}
	}

	char fname[PATH_MAX];
	char *kdev = dev->path + strlen("/dev/");

	snprintf(fname, PATH_MAX, "echo 0 2>/dev/null > /sys/block/%s/%s%d/bcache/readahead",
	    kdev, kdev, db->part + 1);
	int err __attribute__((unused)) = system(fname);

	snprintf(fname, PATH_MAX, "echo %d 2>/dev/null > /sys/block/%s/%s%d/bcache/sequential_cutoff",
	    bcache_sequential_cutoff, kdev, kdev, db->part + 1);
	err = system(fname);

	struct stat st_seqmerge;
	snprintf(fname, PATH_MAX, "/sys/block/%s/%s%d/bcache/sequential_merge",
	    kdev, kdev, db->part + 1);
	if (stat(fname, &st_seqmerge) == 0) {
		snprintf(fname, PATH_MAX, "echo %d 2>/dev/null > /sys/block/%s/%s%d/bcache/sequential_merge",
		    bcache_sequential_merge, kdev, kdev, db->part + 1);
		err = system(fname);
	}

	struct stat st_readthr;
	snprintf(fname, PATH_MAX, "/sys/block/%s/%s%d/bcache/cache/congested_read_threshold_us",
	    kdev, kdev, db->part + 1);
	if (stat(fname, &st_readthr) == 0) {
		snprintf(fname, PATH_MAX, "echo %d 2>/dev/null > /sys/block/%s/%s%d/bcache/cache/congested_read_threshold_us",
		    bcache_congested_read_threshold_us, kdev, kdev, db->part + 1);
		err = system(fname);
	}

	struct stat st_writethr;
	snprintf(fname, PATH_MAX, "/sys/block/%s/%s%d/bcache/cache/congested_write_threshold_us",
	    kdev, kdev, db->part + 1);
	if (stat(fname, &st_writethr) == 0) {
		snprintf(fname, PATH_MAX, "echo %d 2>/dev/null > /sys/block/%s/%s%d/bcache/cache/congested_write_threshold_us",
		    bcache_congested_write_threshold_us, kdev, kdev, db->part + 1);
		err = system(fname);
	}

	char *wbmod = "writeback";
	if (bcache_writearound == 1)
		wbmod = "writearound";
	else if (bcache_writearound == 2)
		wbmod = "writethrough";
	snprintf(fname, PATH_MAX, "echo %s 2>/dev/null > /sys/block/%s/%s%d/bcache/cache_mode",
	    wbmod, kdev, kdev, db->part + 1);
	err = system(fname);
	snprintf(fname, PATH_MAX, "echo %d 2>/dev/null > /sys/block/%s/%s%d/bcache/writeback_percent",
	    bcache_writeback_percent, kdev, kdev, db->part + 1);
	err = system(fname);
	snprintf(fname, PATH_MAX, "echo %d 2>/dev/null > /sys/block/%s/%s%d/bcache/writeback_delay",
	    bcache_writeback_delay, kdev, kdev, db->part + 1);
	err = system(fname);
	return 0;
}

struct rd_create_repdev_arg {
	struct reptrans* rt;
	/* if dev is set, then it won't be allocated, but reused */
	struct repdev* dev;
	const json_value *odev;
	struct rd_metaloc* meta;
	int err;
	pthread_t tid;
	int new;
	int n_ndevs;
};

static int
rd_dev_open_envs(struct repdev* dev) {
	char fname[PATH_MAX];
	struct repdev_rd* rd = dev->device_lfs;
	int err = 0;
	long blk = 0, ssz = 0;
	int is_new = rd->metaloc.version == 0;
	int maintenance = rd->metaloc.state == rdstateMaintenance;

	if (rd_is_opened(rd)) {
		log_notice(lg, "Dev(%s) already opened", dev->name);
		return 0;
	}
	/*
	 * Parts location initialization
	 */
	for (int j = 0; j < rd->plevel; ++j) {
		char envpath[PATH_MAX];

		struct repdev_db* db = rd->db + j;
		db->part = j;
		db->dev = dev;
		struct stat st;

		snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s-part%d", rd->metaloc.device, j + 1);
		for (int i = 1; i < 299; i++) {
			if ((i % 60) == 0) {
				char fname2[PATH_MAX];
				snprintf(fname2, PATH_MAX, "partprobe %s >/dev/null 2>/dev/null", dev->path);
				err = system(fname2);
				usleep(1000000);
			}
			err = stat(fname, &st);
			if (!err)
				break;
			usleep(1000000);
		}
		if (err) {
			err = -EACCES;
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'm',
				.plevel = j+1
			};
			rd_dev_faulted(dev, &fs);
			log_error(lg, "Partition %s not found after 5 min polling", fname);
			goto _exit;
		}

		err = rd_get_size(fname, &blk, &ssz);
		if (err) {
			err = -EACCES;
			struct rd_fault_signature fs = {
				.error = err,
				.source = 'm',
				.plevel = j+1
			};
			rd_dev_faulted(dev, &fs);
			goto _exit;
		}
		uint64_t part_size = blk * ssz;
		memset(db->bloom, 0, KEY_BLOOM_BYTELEN);

		if (rd->metaloc.bcache) {
			char bcachedev[128] = { 0 };
			err = rd_bcache_name_by_kdev(dev->path, db->part + 1, bcachedev);
			if (err) {
				if (err == -EIO)
					log_error(lg, "Dev(%s): cannot open /sys/blob/bcache/uevent entry for %s%d: %s",
					    dev->name, dev->path, db->part + 1, strerror(errno));
				if (err == -ENOENT)
					log_error(lg, "Dev(%s): bcache name lookup error for %s%d",
					    dev->name, dev->path, db->part + 1);
				struct rd_fault_signature fs = {
					.error = -199,
					.source = 'm',
					.plevel = j+1
				};
				rd_dev_faulted(dev, &fs);
				goto _exit;
			}
			snprintf(envpath, PATH_MAX, "/dev/%s", bcachedev);

		} else
			snprintf(envpath, PATH_MAX, "/dev/disk/by-id/%s-part%d",
				rd->metaloc.device, db->part + 1);

		log_debug(lg, "Dev(%s): initializing main env on %s",
		    dev->name, envpath);

		for (int i = TT_NAMEINDEX; i < TT_LAST; ++i) {
			/*
			 * LMDB initialization
			 */
			err = rd_lmdb_init(dev, rd, db, envpath, i, part_size,
				dev->rt->flags, dev->path);
			if (err) {
				struct rd_fault_signature fs = {
					.error = err,
					.source = 'm',
					.plevel = j+1
				};
				rd_dev_faulted(dev, &fs);
				err = -EIO;
				goto _exit;
			}

			/* last partition, no WAL - create MD cache */
			if (j + 1 == rd->plevel && i + 1 == TT_LAST && dev->journal && dev->wal_disabled) {
				snprintf(envpath, PATH_MAX, "/dev/disk/by-id/%s",
					rd->metaloc.mdoffload);
				err = rd_mdcache_open(dev, envpath);
				if (err) {
					struct rd_fault_signature fs = {
						.error = err,
						.source = 'o',
						.plevel = 0
					};
					rd_dev_faulted(dev, &fs);
					err = -EIO;
					goto _exit;
				}
			}
		}

		/*
		 * Initialize/Open write log file
		 */
		if (!dev->wal_disabled && !(dev->rt->flags & RT_FLAG_RDHOLD)) {
			for (int i = 0; i < DEV_LOGID_MAX; i++) {
				const char* jname = dev->journal ?
					rd->metaloc.journal : rd->metaloc.device;
				snprintf(envpath, PATH_MAX, "/dev/disk/by-id/%s-part%d",
					jname, j + rd->metaloc.first_journal_part);

				err = rd_log_open(dev, envpath, db, i, dev->path, 1);

				if (err) {
					struct rd_fault_signature fs = {
						.error = err,
						.source = 'l',
						.plevel = j+1
					};
					rd_dev_faulted(dev, &fs);
					goto _exit;
				}

				log_notice(lg, "Dev(%s): journal %d:%d (%u maxentries %u maxchunk) "
				    "initialized on %s", dev->name, db->part + 1,
				    i, dev->journal_maxentries,
				    dev->journal_maxchunksize, envpath);

				/* last partition - create MD cache */
				if (j + 1 == rd->plevel && i + 1 == DEV_LOGID_MAX && dev->journal) {
					snprintf(envpath, PATH_MAX, "/dev/disk/by-id/%s",
						rd->metaloc.mdoffload);
					err = rd_mdcache_open(dev, envpath);
					if (err) {
						struct rd_fault_signature fs = {
							.error = err,
							.source = 'o',
							.plevel = 0
						};
						rd_dev_faulted(dev, &fs);
						err = -EIO;
						goto _exit;
					}
				}
			}
		}

		/* init the keycache, if not yet */
		if (dev->keycache_enabled == 1 && !db->key_cache) {
			if (key_cache_ini(&db->key_cache, dev->keycache_size_max, NULL) != 0)
				log_error(lg, "Dev(%s): failed to init LRU key cache",
				    dev->name);
			else
				log_info(lg, "Dev(%s-part%d): key cache initialized with max size %d",
				    dev->name, db->part, dev->keycache_size_max);
		}
	}

	if (maintenance) {
		err = rd_command_process(dev, &rd->metaloc, 1);
		if (err) {
			assert(err != -ERANGE);
			assert(err != -EDOM);
			goto _exit;
		}
		/* Maintenance done, start device operations */
	}

	/* Check stored RTRD version ID. Convert to new format, if needed */
	if ((dev->rt->flags & RT_FLAG_VERSION_CHECK) || (DEV_RD_VERSION != rd->metaloc.version)) {
		err = rd_version_convert(dev);
		if (err)
			goto _exit;
	}
	if (is_new && dev->journal) {
		/* An HDD is replaced/new, rebuild mdcache, drop mdoffload */
		err = rd_rebuild_mdcache(dev);
		if (err) {
			log_error(lg, "Dev(%s) mdcache creation error: %d", dev->name,
				err);
			goto _exit;
		} else {
			err = rd_mdoffload_drop(dev);
			if (!err)
				log_notice(lg, "Dev(%s) mdcache for part"
					"has been re-created", dev->name);
			else
				goto _exit;
		}
	}

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

	int need_bloom = 0;

	/* this is for testing purposes only */
	if (getenv("BLOOM_FAST_PATH") &&
		strcmp(getenv("BLOOM_FAST_PATH"), "0") == 0) {
		log_info(lg, "purposely bypassing bloom filter loading from DB");
		need_bloom = 1;
	} else if (!(dev->rt->flags & RT_FLAG_VERSION_CHECK) && !is_new) {
		rd_dev_load_bloom(dev);
	}

	/* need to load HC/rowusage table as flush will possibly update it */
	uv_buf_t u_key, u_val;
	u_key.len = strlen(HASHCOUNT_BLOB_KEY) + 1;
	u_key.base = HASHCOUNT_BLOB_KEY;
	u_val.len = 0;
	u_val.base = NULL;

	err = rd_config_impl(dev, CFG_READ, &u_key, &u_val);
	if (!err && u_val.len == sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH) {
		memcpy(&dev->stats.hashcount, u_val.base,
			sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH);
		dev->stats.hashcount[HASHCOUNT_TAB_LENGTH] = 0;
	} else if (err == -ENOENT) {
		dev->stats.hashcount[HASHCOUNT_TAB_LENGTH] = 1;
		err = 0;
	}

	u_key.len = strlen(ROWUSAGE_BLOB_KEY) + 1;
	u_key.base = ROWUSAGE_BLOB_KEY;
	u_val.len = 0;
	u_val.base = NULL;

	err = rd_config_impl(dev, CFG_READ, &u_key, &u_val);
	if (!err && u_val.len == sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH) {
		memcpy(&dev->stats.rowusage, u_val.base,
			sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH);
		dev->stats.rowusage[HASHCOUNT_TAB_LENGTH] = 0;
	} else if (err == -ENOENT) {
		dev->stats.rowusage[HASHCOUNT_TAB_LENGTH] = 1;
		err = 0;
	}


	/* flush the WALs if any and update HC table too */

	for (int j = 0; j < rd->plevel; ++j) {
		struct repdev_db* db = rd->db + j;
		err = pthread_create(&db->bloom_load_thread, NULL,
			&rd_partition_flush, (void *)db);
		if (err) {
			log_warn(lg, "Dev(%s): cannot start WAL flush thread: (%d) %s",
					dev->name, err, strerror(err));
			err = 0;
		}
	}

	/* and wait */

	for (int j = 0; j < rd->plevel; ++j) {
		struct repdev_db* db = rd->db + j;
		pthread_join(db->bloom_load_thread, NULL);
		db->bloom_load_thread = 0;
	}

	/*
	 * load bloom filters -- but do not wait for them to finish
	 */
	for (int j = 0; j < rd->plevel; ++j) {
		pthread_attr_t attr;

		struct repdev_db* db = rd->db + j;
		if (db->bloom_loaded == 1 && !need_bloom)
			continue;

		db->bloom_loaded = 0;

		log_notice(lg, "Dev(%s) part %d: needed to take bloom load slow path",
			dev->name, db->part+1);

		err = pthread_attr_init(&attr);
		if (!err)
			err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

		err = pthread_create(&db->bloom_load_thread, NULL,
				&rd_bloom_load, (void *) db);
		if (err) {
			log_warn(lg, "Dev(%s): cannot start bloom_load thread: (%d) %s",
					dev->name, err, strerror(err));
			uv_rwlock_wrlock(&db->bloom_lock);
			db->bloom_loaded = -1;
			uv_rwlock_wrunlock(&db->bloom_lock);
		}

		pthread_attr_destroy(&attr);
	}

	/* finaly, update HC/rowusage table again so that upper layer can read
	 * it correctly upon successful recovery */
	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status != REPDEV_STATUS_UNAVAILABLE &&
		status != REPDEV_STATUS_READONLY_FULL &&
		status != REPDEV_STATUS_READONLY_FORCED &&
		status != REPDEV_STATUS_READONLY_FAULT) {
		MDB_val hc_key = { .mv_size = strlen(HASHCOUNT_BLOB_KEY) + 1,
				   .mv_data = HASHCOUNT_BLOB_KEY };
		MDB_val hc_data = { .mv_size = sizeof(uint64_t) * HASHCOUNT_TAB_LENGTH,
				   .mv_data = (char*)dev->stats.hashcount };
		err = rd_put_hashcount_entry(dev, &hc_key, &hc_data);
		if (err)
			goto _exit;

		MDB_val ru_key = { .mv_size = strlen(ROWUSAGE_BLOB_KEY) + 1,
				   .mv_data = ROWUSAGE_BLOB_KEY };
		MDB_val ru_data = { .mv_size = sizeof(uint64_t) * HASHCOUNT_TAB_LENGTH,
				   .mv_data = (char*)dev->stats.rowusage };
		err = rd_put_hashcount_entry(dev, &ru_key, &ru_data);
	}

_exit:
	return err;
}

/* Create or initialize a repdev structure based on information provided */
static int
rd_repdev_prepare(struct rd_create_repdev_arg* p) {
	struct rd_metaloc* meta = p->meta;
	struct repdev* dev = p->dev;
	const json_value *d = p->odev;
	struct reptrans* rt = p->rt;

	char *name = NULL;
	char *journal = NULL;
	char *metadata = NULL;
	int metadata_mask = 0;
	int verify_chid = 1;
	int gw_cache = 0;
	int zerocopy = 0;
	int journal_maxentries = DEV_LMDB_LOG_MAXENTRIES;
	int journal_maxchunksize = DEV_LMDB_LOG_MAXCHUNKSIZE;
	int bcache_wbc_threshold_mb = BCACHE_WBC_THRESHOLD_MB;
	int bcache_wbc_flush_mb = BCACHE_WBC_FLUSH_MB;
	int sync = 1;
	int writemap = 0;
	int readahead = MEDIA_READAHEAD;
	int hdd_readahead = HDD_READAHEAD;
	int direct = 0;
	int detached = 0;
	int mdcache_enable = 0;
	int err = 0;
	uint8_t bloom_enabled = 1;
	uint8_t keycache_enabled = 1;
	uint32_t keycache_size_max = KEY_CACHE_MAX;
	int newalloc = 0;
	char fname[PATH_MAX];
	struct repdev_bg_config* bg_cfg = NULL;
	struct repdev_rd* rd = NULL;
	long blk = 0, ssz = 0;

	snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s", meta->device);
	char *kdevname = realpath(fname, NULL);

	/*
	 * The RTRD doesn't work with versions higher than current.
	 */
	if (meta->version > DEV_RD_VERSION) {
		log_error(lg, "Error: unknown RD version %d, expected %d",
			meta->version, DEV_RD_VERSION);
		return -EINVAL;
	}

	if (!meta->plevel) {
		log_error(lg, "Dev(%s) Fatal: plevel in undefined", meta->device);
		return -EINVAL;
	}

	if (d->type != json_object) {
		log_warn(lg, "Dev(%s) Syntax error: \"device\" is not an object",
			meta->device);
		return -EINVAL;
	}

	bg_cfg = je_malloc(sizeof(struct repdev_bg_config));
	*bg_cfg = rt->dev_bg_config;

	name = je_strdup(meta->device);
	journal = strlen(meta->journal) ? je_strdup(meta->journal) : NULL;
	for (size_t j = 0; j < d->u.object.length; j++) {
		char *namekey = d->u.object.values[j].name;
		json_value *v = d->u.object.values[j].value;

		if (strcmp(namekey, "detached") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
					"dev.%s.detached is not an "
					"integer", name);
				continue;
			}
			detached = v->u.integer;
		} else if (strcmp(namekey, "mdcache_enable") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.wal_disabled is not an "
				    "integer", name);
				continue;
			}
			mdcache_enable = v->u.integer;
		} else if (strcmp(namekey, "metadata") == 0) {
			if (v->type != json_string) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.metadata is not a string",
				    name);
				continue;
			}
			char *sp = NULL;
			char *token = strtok_r(v->u.string.ptr, ",", &sp);
			metadata = je_strdup(token);
			assert(metadata);

			char *metadata_mask_ptr = strtok_r(NULL, ",", &sp);
			if (metadata_mask_ptr) {
				if (sscanf(metadata_mask_ptr, "%x", &metadata_mask) != 1) {
					log_warn(lg, "Syntax error: "
					    "dev.%s.metadata typetag mask is not a HEX string",
					    name);
					continue;
				}
			}
		} else if (strcmp(namekey, "bcache_wbc_threshold_mb") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bcache_wbc_threshold_mb is not an "
				    "integer", name);
				continue;
			}
			bcache_wbc_threshold_mb = v->u.integer;
		} else if (strcmp(namekey, "bcache_wbc_flush_mb") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bcache_wbc_flush_mb is not an "
				    "integer", name);
				continue;
			}
			bcache_wbc_flush_mb = v->u.integer;
		} else if (strcmp(namekey, "verify_chid") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.verify_chid is not an "
				    "integer", name);
				continue;
			}
			verify_chid = v->u.integer;
		} else if (strcmp(namekey, "gw_cache") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.gw_cache is not an "
				    "integer", name);
				continue;
			}
			gw_cache = v->u.integer;
		} else if (strcmp(namekey, "sync") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.sync is not an "
				    "integer", name);
				continue;
			}
			sync = v->u.integer;
		} else if (strcmp(namekey, "writemap") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.writemap is not an "
				    "integer", name);
				continue;
			}
			writemap = v->u.integer;
		} else if (strcmp(namekey, "hdd_readahead") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.hdd_readahead is not an "
				    "integer", name);
				continue;
			}
			hdd_readahead = v->u.integer;
		} else if (strcmp(namekey, "readahead") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.readahead is not an "
				    "integer", name);
				continue;
			}
			readahead = v->u.integer;
		} else if (strcmp(namekey, "zerocopy") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.zerocopy is not an "
				    "integer", name);
				continue;
			}
			zerocopy = v->u.integer;
		} else if (strcmp(namekey, "direct") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.direct is not an "
				    "integer", name);
				continue;
			}
			direct = v->u.integer;
		} else if (strcmp(namekey, "journal_maxentries") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.journal_maxentries is not an "
				    "integer", name);
				continue;
			}
			journal_maxentries = v->u.integer;
		} else if (strcmp(namekey, "journal_maxchunksize") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.journal_maxchunksize is not an "
				    "integer", name);
				continue;
			}
			journal_maxchunksize = v->u.integer;
		} else if (strcmp(namekey, "bloom_enabled") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.bloom_enabled is not an "
				    "integer", name);
				continue;
			}
			bloom_enabled = v->u.integer;
		} else if (strcmp(namekey, "keycache_enabled") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
				    "dev.%s.keycache_enabled is not an "
				    "integer", name);
				continue;
			}
			keycache_enabled = v->u.integer;
		} else if (strcmp(namekey, "keycache_size_max") == 0) {
			if (v->type != json_integer) {
				log_warn(lg, "Syntax error: "
					"dev.%s.keycache_size_max is not an "
					"integer", name);
				continue;
			}
			keycache_size_max = v->u.integer;
		}
	}
	size_t n_opts;
	/*
	 * Parse bg timing config
	 * at the moment we just skip parsing errors
	 * as we still have upper level configuration
	 * parsed previously and it will be used
	 */
	reptrans_parse_bg_jobs_config(d, bg_cfg, &n_opts);


	/*
	 * Allocate device structure
	 */
	if (!dev) {
		 dev = je_calloc(1, sizeof (*dev));
		 if (!dev) {
			 err = -ENOMEM;
			 goto _exit;
		 }
		rd = je_calloc(1, sizeof(*rd));
		if (!rd) {
			err = -ENOMEM;
			goto _exit;
		}
		rd->db = je_calloc(meta->plevel, sizeof(struct repdev_db));
		if (!rd->db) {
			err = -ENOMEM;
			goto _exit;
		}
		/*
		* we must set dev->sub_fd to -1, because nn_socket can return 0 as normal good socket
		*/
		dev->sub_fd = -1;
		QUEUE_INIT(&dev->item);
		dev->rt = rt;
		dev->__vtbl = &rd_dev_vtbl;
		dev->device_lfs = rd;
		pthread_rwlock_init(&rd->guard, NULL);
		newalloc = 1;
	} else {
		rd = dev->device_lfs;
		if (meta->plevel > rd->plevel) {
			for (int i = 0; i < rd->plevel; i++)
				je_free(rd->db->bloom + i);
			je_free(rd->db);
			rd->db = je_calloc(meta->plevel, sizeof(struct repdev_db));
			if (!rd->db) {
				err = -ENOMEM;
				goto _exit;
			}
		}
	}
	if (dev->name)
		je_free(dev->name);
	dev->name = name;
	memcpy(&rd->metaloc, meta, sizeof(struct rd_metaloc));
	dev->keycache_enabled = keycache_enabled;
	dev->keycache_size_max = keycache_size_max;
	if (is_embedded())
		dev->keycache_size_max /= p->n_ndevs * meta->plevel;
	/* Initialize just created DBs */
	if (newalloc || meta->plevel > rd->plevel) {
		for (int i = 0; i < meta->plevel; i++) {
			struct repdev_db* db = rd->db + i;
			db->bloom = je_calloc(1, KEY_BLOOM_BYTELEN);
			if (!db->bloom) {
				err = -ENOMEM;
				goto _exit;
			}
			uv_rwlock_init(&db->bloom_lock);
			uv_mutex_init(&db->log_flush_lock);
			uv_cond_init(&db->log_flush_condvar);
			/* init the keycache */
			if (dev->keycache_enabled == 1) {
				if (key_cache_ini(&db->key_cache, dev->keycache_size_max, NULL) != 0)
					log_error(lg, "Dev(%s): failed to init LRU key cache",
					    dev->name);
				else
					log_info(lg, "Dev(%s-part%d): key cache initialized with max size %d",
					    dev->name, db->part, dev->keycache_size_max);
			} else {
				log_info(lg, "key cache disabled for dev %s", dev->name);
				rd->db->key_cache = NULL;
			}
			if (!dev->wal_disabled) {
				for (int j = 0; j < DEV_LOGID_MAX; j++) {
					pthread_rwlock_init(&db->log[j].access_lock, NULL);
					pthread_mutex_init(&db->log[j].repair_lock, NULL);
					db->log[j].dev = dev;
					db->log[j].db = db;
				}
			}
		}
	}

	err = rd_get_size(fname, &blk, &ssz);
	if (err) {
		err = -ENODEV;
		goto _exit;
	}
	assert(ssz > 0 && ssz <= 4096);
	dev->stats.physical_capacity = blk * ssz;
	dev->plevel = rd->plevel = rd->metaloc.plevel;
	rd->sync = sync;
	rd->writemap = writemap;
	rd->readahead = readahead;
	rd->hdd_readahead = hdd_readahead;
	rd->bcache_wbc_threshold_mb = bcache_wbc_threshold_mb;
	rd->bcache_wbc_flush_mb = bcache_wbc_flush_mb;
	rd->direct = direct;
	rd->mdcache_enable = mdcache_enable;
	rd->zerocopy = zerocopy;

	if (dev->path)
		free(dev->path);
	dev->path = kdevname;
	dev->wal_disabled = !meta->wal;
	if (dev->journal)
		je_free(dev->journal);
	dev->journal = journal;
	dev->bcache = rd->metaloc.bcache;
	dev->journal_maxchunksize = journal_maxchunksize;
	dev->journal_maxentries = journal_maxentries;
	dev->bloom_enabled = bloom_enabled;
	dev->verify_chid = verify_chid;
	dev->gw_cache = gw_cache;
	if (!memcmp(bg_cfg, &rt->dev_bg_config,
			sizeof(struct repdev_bg_config))) {
		dev->bg_config = &rt->dev_bg_config;
		je_free(bg_cfg);
		bg_cfg = NULL;
	} else
		dev->bg_config = bg_cfg;
	if (journal) {
		if (rd->metaloc.version == 0 || rd->metaloc.metamask == 0)
			dev->metadata_mask = rd->metaloc.metamask = (journal && !metadata ) ? DEV_METADATA_DEFAULT : metadata_mask;
		else
			dev->metadata_mask = meta->metamask;
	} else {
		dev->metadata_mask = rd->metaloc.metamask = 0;
	}
	if (newalloc)
		dev->status = dev->prev_status = detached ? REPDEV_STATUS_UNAVAILABLE : REPDEV_STATUS_INIT;
	if (!rd->metaloc.vdev_id.u && !rd->metaloc.vdev_id.l) {
		repdev_generate_name(dev);
		rd->metaloc.vdev_id = dev->vdevid;
	} else
		dev->vdevid = rd->metaloc.vdev_id;

	for (int i = 0; i < rd->plevel; i++) {
		struct repdev_db* db = rd->db + i;
		db->dev = dev;
		db->part = i;
		if (!rd->metaloc.bcache)
			continue;
		rd_tune_bcache(db, d);
	}
	p->dev = dev;
_exit:
	if (err) {
		if (name)
			je_free(name);
		if (journal)
			je_free(journal);
		if (metadata)
			je_free(metadata);
		if (dev)
			je_free(dev);
		if (bg_cfg)
			je_free(bg_cfg);
	}
	return err;
}

static void*
rd_dev_init_thread(void* arg) {
	struct rd_create_repdev_arg* p = arg;
	struct rd_metaloc* meta = NULL;
	struct repdev* dev = NULL;
	struct repdev_rd* rd = NULL;
	/* Create a VDEV structure */
	int err = rd_repdev_prepare(p);
	if (err) {
		p->dev = NULL;
		p->err = err;
		return p;
	}
	dev = p->dev;
	rd = dev->device_lfs;
	meta = &rd->metaloc;
	/*
	 * in case we want to put a hold on the page cache we use this trick
	 * to keep a reference to the pages. See rthold.c
	 */
	if(dev->rt->flags & RT_FLAG_RDHOLD) {
		/* add device to the transport */
		reptrans_add_vdev(dev->rt, dev);
		p->err = 0;
		return p;
	}
	/* Check disk status. Available since RTRDv6 */
	if (meta->version >= DEV_RD_VERSION_EXT_METALOC && meta->state != rdstateOk) {
		if (meta->state == rdstateFault) {
			log_notice(lg, "The device %s marked as faulted", meta->device);
			dev->status = REPDEV_STATUS_UNAVAILABLE;
		} else if (meta->state == rdstateMaintenance) {
			/*
			 * Maintenance requested. Make sure no other tools
			 * is active at the moment.
			 */
			if (meta->pid) {
				struct stat sts;
				char proc_path[128];
				sprintf(proc_path, "/proc/%d", meta->pid);
				if (stat(proc_path, &sts) == -1 && errno == ENOENT) {
					/* The process has died */
					meta->pid = 0;
				} else {
					log_notice(lg, "Dev(%s) it seems "
						"the maintenance is being performed"
						" by process with PID %d, "
						"skipping device initialization",
						meta->device, meta->pid);
					dev->status = REPDEV_STATUS_UNAVAILABLE;
				}
			}
			/*
			 * We are allowed to run maintenance command (if supported).
			 * But first make sure the maintenance attempts
			 * count didn't exceed a threshold
			 */
			char buf[RD_METALOC_SIZE];
			uv_buf_t ub = {.base = buf, .len = sizeof(buf) };
			if (meta->retries >= 3) {
				char pathbuff[PATH_MAX];
				char* kpath = rd_kpath(meta->device, 0, pathbuff);

				meta->state = rdstateFault;
				meta->retries = 0;
				int n = meta->n_faults++;
				meta->faults[n].error = 0;
				meta->faults[n].source = 'c';
				meta->faults[n].plevel = 0;
				int err = rd_write_metaloc(kpath, meta);
				if (err) {
					log_error(lg, "Unable to store "
						"metaloc on %s, skipping the device"
						" initialization", meta->device);
				}
				log_error(lg, "The device %s became unavailable "
					"because %d maintenance attempts "
					"have failed", meta->device, 3);
				dev->status = REPDEV_STATUS_UNAVAILABLE;
			}

			err = rd_command_process(NULL, meta, 0);
			if (err) {
				if (err == -ERANGE) {
					/*
					 * Requested maintenance command isn't supported.
					 * It might be handled by an external tool
					 * We are skipping this device.
					 */
					log_notice(lg, "Dev(%s) maintenance command(s) isn't supported",
						meta->device);
					dev->status = REPDEV_STATUS_UNAVAILABLE;
				} else if (err == -EDOM) {
					/*
					 * The command needs to be run
					 * again when LMDB envs are initialized
					 */
				} else {
					/*
					 * There was an error during maintenance,
					 * skip this device
					 */
					dev->status = REPDEV_STATUS_UNAVAILABLE;
				}
			}
		}
	}
	dev->prev_status = dev->status;
	return p;
}

static int
rd_dev_open(struct repdev* dev) {
	struct repdev_rd* rd = dev->device_lfs;
	int err = 0;
	if (rd_is_opened(rd))
		return -EEXIST;
	/*
	 * Take a common lock. It will be acquired when
	 * there are no LMDB operations in progress
	 */
	pthread_rwlock_wrlock(&rd->guard);
	err = rd_dev_open_envs(dev);
	pthread_rwlock_unlock(&rd->guard);
	if (!err) {
		rd_set_opened(rd, 1);
		(void)rd_dev_stat_refresh(dev);
	}
	return err;
}

static void
rd_dev_close_nolock(struct repdev* dev);

static int
rd_dev_reopen(struct repdev* dev) {
	struct repdev_rd* rd = dev->device_lfs;
	int err = 0;
	/*
	 * Take a common lock. It will be acquired when
	 * there are no LMDB operations in progress
	 */
	pthread_rwlock_wrlock(&rd->guard);
	if (rd_is_opened(rd)) {
		rd_dev_close_nolock(dev);
		rd_set_opened(rd, 0);
	}

	err = rd_dev_open_envs(dev);
	pthread_rwlock_unlock(&rd->guard);
	if (!err) {
		rd_set_opened(rd, 1);
		(void)rd_dev_stat_refresh(dev);
	}
	return err;
}

struct rd_dev_lookup_arg {
	const char* name;
	struct repdev* dev;
};

static int
rd_dev_lookup_cb(struct repdev* dev, void* arg) {
	struct rd_dev_lookup_arg* p = arg;
	if (!strcmp(dev->name, p->name)) {
		p->dev = dev;
		return -1;
	}
	return 0;
}

static int
rd_dev_discover(struct reptrans* rt, json_value *o, const char* disk_name) {
	size_t i, j;
	int err;

	/* syntax error */
	if (o->type != json_object) {
		log_error(lg, "Syntax error: not an object");
		return -1;
	}

	json_value *devices = NULL;
	for (i = 0; i < o->u.object.length; i++) {
		if (strcmp(o->u.object.values[i].name, "devices") == 0) {
			devices = o->u.object.values[i].value;
			break;
		}
	}

	/* devices section not found */
	if (!devices) {
		log_error(lg, "Couldn't find device entry in json object");
		return -EINVAL;
	}

	/* syntax error */
	if (devices->type != json_array) {
		log_error(lg, "Syntax error: devices section not an array");
		return -1;
	}
	int found = 0;
	for (i = devices->u.array.length; i > 0 ; i--) {
		json_value *d = devices->u.array.values[i - 1];
		char devpath[PATH_MAX];
		char *name = NULL, *jname = NULL;
		for (j = 0; j < d->u.object.length; j++) {
			char *namekey = d->u.object.values[j].name;
			json_value *v = d->u.object.values[j].value;
			if (strcmp(namekey, "name") == 0) {
				found = !strcmp(v->u.string.ptr, disk_name);
				if (found)
					break;
			}
		}
		if (found)
			break;
	}
	if (disk_name && !found) {
		log_error(lg, "Cannot discover: disk %s not found in rt-rd.json",
			disk_name);
		return -ENOENT;
	}

	struct rd_disks* disks = NULL;
	err = rd_fetch_disk_info(devices, &disks);
	if (err) {
		log_error(lg, "Couldn't fetch VDEVs configuration");
		return err;
	}
	assert(disks);

	err = rd_check_and_create_partitions(rt, devices, disks, disk_name);
	if (err) {
		/* error logged within rd_check_partitions() */
		return err;
	}

	struct rd_create_repdev_arg arg[disks->n_disks];
	int numdevs = 0;
	for (i = 0; i < disks->n_disks; i++) {
		struct rd_metaloc* meta = disks->metas + i;
		json_value *d = devices->u.array.values[i];
		struct repdev* dev = NULL;
		arg[i].new = 0;
		if (disk_name && strcmp(disk_name, meta->device))
				continue;
		/*
		 * We want to re-use the data structure bound to the VDEV.
		 * If this is a replacement case, then lookup for "old" VDEV name
		 */
		struct rd_dev_lookup_arg a = {.dev = NULL , .name = meta->device};

		for (int n = 0; n < meta->n_cmds; n++) {
			if (!strcmp(meta->maintenance_cmd[n], CMD_DISK_REPLACE_SIGNATURE) &&
				(meta->state == rdstateMaintenance) &&
				strlen(meta->oldname)) {
				a.name = meta->oldname;
				break;
			}
		}
		reptrans_foreach_vdev(rd_dev_lookup_cb, &a);
		if (a.dev) {
			dev = a.dev;
			struct repdev_rd* rd = dev->device_lfs;
			/* make sure the VDEV is detached */
			if (rd_is_opened(rd)) {
				if (disk_name) {
					log_error(lg, "Cannot probe/replace disk %s,"
						"make sure it's detached/faulted",
						disk_name);
					return -EBUSY;
				}
				continue;
			}
			arg[i].new = 1;
		} else
			arg[i].new = 2;
		arg[i].dev = dev;
		arg[i].err = 0;
		arg[i].meta = meta;
		arg[i].odev = d;
		arg[i].rt = rt;
		err = pthread_create(&arg[i].tid, NULL, rd_dev_init_thread, arg + i);
		if (err) {
			log_error(lg, "Unable to create an init pthread for device %s",
				meta->device);
			return err;
		}
		numdevs++;
	}

	for (i = 0; i < disks->n_disks; i++) {
		if (!arg[i].new)
			continue;
		pthread_join(arg[i].tid, NULL);
		if (arg[i].err) {
			err = arg[i].err;
			log_error(lg, "Dev(%s) rd_dev_init_thread error %d",
				arg[i].dev->name, err);
		} else if (arg[i].new == 2) {
			assert(arg[i].dev);
			reptrans_add_vdev(rt, arg[i].dev);
		}
	}
	if (!err && !numdevs) {
		log_notice(lg, "No devices discovered");
		err = -ENOENT;
	} else if (!err)
		log_notice(lg, "Probed %d disk(s)", numdevs);
	return err;
}

static int
rd_parse_opts(json_value *o, struct reptrans *rt)
{
	size_t i, j;
	int err;

	/* syntax error */
	if (o->type != json_object) {
		log_error(lg, "Syntax error: not an object");
		return -1;
	}

	json_value *devices = NULL;
	for (i = 0; i < o->u.object.length; i++) {
		if (strcmp(o->u.object.values[i].name, "devices") == 0) {
			devices = o->u.object.values[i].value;
			break;
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

	for (i = devices->u.array.length; i > 0 ; i--) {
		json_value *d = devices->u.array.values[i - 1];
		char devpath[PATH_MAX];
		char *name = NULL, *jname = NULL;
		for (j = 0; j < d->u.object.length; j++) {
			char *namekey = d->u.object.values[j].name;
			json_value *v = d->u.object.values[j].value;
			if (strcmp(namekey, "name") == 0) {
				name = v->u.string.ptr;
			} else if (strcmp(namekey, "journal") == 0) {
				jname = v->u.string.ptr;
				break;
			}
		}
		if(!name)
			continue;

		int bad_journal = 0;
		if (jname) {
			snprintf(devpath, PATH_MAX, "/dev/disk/by-id/%s", jname);
			if (access(devpath, F_OK))
				bad_journal = 1;
		}

		snprintf(devpath, PATH_MAX, "/dev/disk/by-id/%s", name);
		if (!access(devpath, F_OK) && !bad_journal)
			continue;
		log_error(lg, "Dev(%s): %s, skipping", name, bad_journal ?
		    "missing journal device symlink" : "missing device symlink");

		for (j = i; j < devices->u.array.length; j++) {
			devices->u.array.values[j - 1] = devices->u.array.values[j];
		}
		devices->u.array.length --;
		json_value_free(d);
	}
	/* Prepare a folder for reserved metaloc copies */
	char cmd[PATH_MAX];
	sprintf(cmd, "mkdir -p %s/var/run/disk", nedge_path());
	err = system(cmd);
	/* Getting disks configuration */
	struct rd_disks* disks = NULL;
	err = rd_fetch_disk_info(devices, &disks);
	if (err) {
		log_error(lg, "Couldn't fetch VDEVs configuration");
		return err;
	}
	assert(disks);

	err = rd_check_and_create_partitions(rt, devices, disks, NULL);
	if (err) {
		/* error logged within rd_check_partitions() */
		return err;
	}

	struct rd_create_repdev_arg arg[disks->n_disks];
	int numdevs = 0;
	for (i = 0; i < disks->n_disks; i++) {
		struct rd_metaloc* meta = disks->metas + i;
		json_value *d = devices->u.array.values[i];

		arg[i].dev = NULL;
		arg[i].err = 0;
		arg[i].meta = meta;
		arg[i].odev = d;
		arg[i].rt = rt;
		arg[i].n_ndevs = disks->n_disks;
		err = pthread_create(&arg[i].tid, NULL, rd_dev_init_thread, arg + i);
		if (err) {
			log_error(lg, "Unable to create an init pthread for device %s",
				meta->device);
		}
	}

	for (i = 0; i < disks->n_disks; i++)
		pthread_join(arg[i].tid, NULL);

	for (i = 0; i < devices->u.array.length; i++) {
		struct repdev *dev = arg[i].dev;
		if (!dev)
			log_error(lg, "Cannot initialize Local data store %lu: %d", i, arg[i].err);
		else {
			struct repdev_rd *rd = dev->device_lfs;
			assert(rd);

			if (dev->gw_cache) {
				log_notice(lg, "Local data store %s kdev=%s initialized : gw cache",
				    dev->name, dev->path);
			} else {
				log_notice(lg, "Local data store %s kdev=%s initialized",
				    dev->name, dev->path);
			}
			reptrans_add_vdev(rt, dev);
			numdevs++;
		}
		/* done */
	}
	return numdevs;
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
rd_probe(json_value *opts, struct reptrans *rt)
{
	int err = 0;

	if (opts) {
		err = rd_parse_opts(opts, rt);
		if (err == -ENODEV)
			return err;
		if (err < 0) {
			log_error(lg, "Configure file format, RD version or flags error");
		} else {
			log_info(lg, "Replicast transport over Raw Disk now initialized");
		}
		/* now, start rdhold daemon if we should */
		if (err > 0 && getenv("HOST_HOSTNAME") != NULL &&
		    !(rt->flags & RT_FLAG_STANDALONE || rt->flags & RT_FLAG_RDONLY) &&
		    !(rt->flags & RT_FLAG_RDHOLD)) {
			struct stat st;
			char *rdhold_loc = NULL;
			int rdhold_running = 0;

			char rd_path[PATH_MAX];
			snprintf(rd_path, sizeof(rd_path), "%s/var/run/rdhold.pid", nedge_path());
			if (stat(rd_path, &st) == 0) {
				rdhold_running = 1;
			}

			snprintf(rd_path, sizeof(rd_path), "%s/sbin/rdhold", nedge_path());
			if (stat(rd_path, &st) == 0) {
				rdhold_loc = rd_path;
			} else {
				snprintf(rd_path, sizeof(rd_path), "%s/src/ccow/tools/rdhold", nedge_path());
				if (stat(rd_path, &st) == 0)
					rdhold_loc = rd_path;
			}
			if (rdhold_loc && !rdhold_running) {
				int err2 = system(rdhold_loc);
				if (err2) {
					log_warn(lg, "rdhold: %s, err %d",
					    rdhold_loc, err2);
				} else {
					log_notice(lg, "rdhold: %s, started "
					    "successfully", rdhold_loc);
				}
			}
		}
	}
	return err;
}

static int
rd_destroy()
{
	return 0;
}

static void
rd_dev_log_flush(struct repdev *dev, uint32_t flags) {

	uint64_t start = uv_hrtime();
	struct repdev_rd *rd = dev->device_lfs;

	char fname[PATH_MAX];
	snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s", dev->name);

	repdev_status_t status;
	status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return;

	if (access(fname, F_OK) != 0) {
		struct rd_fault_signature fs = {
			.error = -ENOENT,
			.source = 'm',
			.plevel = 0
		};
		rd_dev_faulted(dev, &fs);
		return;
	}

	for (int j = 0; j < rd->plevel; ++j) {
		struct repdev_db *db = rd->db + j;
		type_tag_t first = TT_NAMEINDEX;
		type_tag_t last = TT_LAST;
		if (flags & RD_FLUSH_BATCH_QUEUE) {
			first = TT_BATCH_QUEUE;
			last = TT_BATCH_QUEUE + 1;
		}
		int err = 0;
		for (type_tag_t ttag = first; ttag < last; ttag++) {
			if (is_log_tt(dev, ttag)) {
				for (int id = 0; id < DEV_LOGID_MAX; id++) {
					struct repdev_log *log = &DEV_LOGID(db, id);
					if (((dev->bg_config->flush_threshold_timeout <
						  start - log->flushed_timestamp) &&
						 (flags & RD_FLUSH_TIMEOUT)) ||
						(flags & RD_FLUSH_FORCE)) {
						err = rd_log_flush(log, ttag);
						if (err)
							/* flush what we can! */
							break;
					} else {
						log_debug(lg, "skipping flush timeout") ;
					}
				}
				if (!err && (flags & RD_FLUSH_SYNC))
					rd_log_flush_wait(db, ttag);
			}
		}

		if (dev->journal &&
		    rd->flushed_bytes > rd->bcache_wbc_threshold_mb * 1024UL * 1024UL) {
			char dname[PATH_MAX];
			char cmd[PATH_MAX+128];
			char *kdevname = realpath(fname, dname);
			if (!kdevname) {
				log_error(lg, "Dev(%s) realpath returned %d\n, fname %s", dev->name, errno, fname);
				continue;
			}
			char *kdev = kdevname + strlen("/dev/");

			/* echo has to be in sectors (512b) */
			snprintf(cmd, PATH_MAX+128,
			    "echo %lu 2>/dev/null > /sys/block/%s/%s%d/bcache/writeback_rate",
			    rd->bcache_wbc_flush_mb * 1024UL * 1024UL / 512UL, kdev, kdev, j + 1);
			err = system(cmd);

			log_info(lg, "WBC flushed %lu MBytes to %s%d, err=%d",
			    rd->bcache_wbc_flush_mb, kdev, j + 1, err);

			rd->flushed_bytes = 0;
		}
	}
}

static int
rd_dev_ctl(struct repdev* dev, int op, void* arg) {
	if (op == vdevCtlFlush) {
		uint32_t flags = 0;
		memcpy(&flags, arg, sizeof(uint32_t));
		rd_dev_log_flush(dev, flags);
		return 0;
	} else if (op == vdevCtlDetach) {
		struct rd_fault_signature sg = {
			.error = 0,
			.source = 'e',
			.plevel = 0
		};
		return rd_set_unavailable(dev, &sg, 1);
	} else if (op == vdevCtlAttach) {
		repdev_status_t status = reptrans_dev_get_status(dev);
		if (status == REPDEV_STATUS_UNAVAILABLE) {
			char fname[PATH_MAX];
			struct rd_metaloc meta = {0};
			snprintf(fname, PATH_MAX, "/dev/disk/by-id/%s", dev->name);
			char mbuf[RD_METALOC_SIZE];
			struct repdev_rd* rd = dev->device_lfs;
			/* the metaloc could be modified until we were slipping */

			uv_buf_t ml_ub = {.len = sizeof(mbuf), .base = mbuf};
			int err = rd_read_metaloc(fname, &ml_ub);
			if (!err)
				err = rd_metaloc_deserialize(&ml_ub, &meta);
			if (err) {
				log_error(lg, "Dev(%s) metaloc corrupted", dev->name);
				return err;
			} else {
				if (meta.pid != 0) {
					struct stat sts;
					char proc_path[128];
					sprintf(proc_path, "/proc/%d", meta.pid);
					if (stat(proc_path, &sts) == -1 && errno == ENOENT) {
						/* The process has died */
						meta.pid = 0;
					} else {
						log_error(lg, "Dev(%s) cannot attach. "
							"Maintenance is in progress. Process ID %d",
							dev->name, meta.pid);
						return -EBUSY;
					}
				}
				memcpy(rd->metaloc.faults, meta.faults, sizeof(meta.faults));
				rd->metaloc.n_faults = meta.n_faults;
				memcpy(rd->metaloc.maintenance_cmd, meta.maintenance_cmd, sizeof(meta.maintenance_cmd));
				rd->metaloc.n_cmds = meta.n_cmds;
				rd->metaloc.state = meta.state;
			}
		}
		if (status == REPDEV_STATUS_READONLY_FORCED) {
			/**
			 * IMPORTANT. Must be a BUG in LMDB.
			 * REPDEV_STATUS_READONLY_FORCED is used by the
			 * `efscli device check` to inspect environment content.
			 * It performs write transactions as well. Once written,
			 * the mdb_copy tool detects environment inconsistency:
			 * expected DB's root doesn't correspond to the found one.
			 * We suppose there are race conditions with a multiprocess
			 * concurrent write to the environment.
			 * To avoid this issue, we want to re-open envs
			 */
			return rd_dev_reopen(dev);
		} else
			return rd_dev_open(dev);
	} else if (vdevCtlDiscover) {
		struct vdevCtlDiscoverArg* p = arg;
		log_notice(lg, "Probing disk %s", p->name);
		return rd_dev_discover(dev->rt, p->cfg, p->name);
	} else
		return -EINVAL;
}

static void
rd_dev_close_nolock(struct repdev* dev) {
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = NULL;
	uv_buf_t key;
	uv_buf_t value;
	for (int j = 0; j < rd->plevel; ++j) {
		struct repdev_db *db = rd->db + j;
		if (!db->bloom_load_thread)
			continue;
		rd_bloom_wait(db);
	}
	repdev_status_t status = reptrans_dev_get_status(dev);
	/*
	 * Do not store bloom in READONLY_FORCED because it might lead to
	 * put races with `efscli device check`. LMDB bug?
	 */
	if (status == REPDEV_STATUS_ALIVE || status == REPDEV_STATUS_INIT) {
		int err = rd_dev_quiesce_bloom(dev);
		if (err != 0)
			log_error(lg, "failed or partial failure storing bloom filter(s)");

		key.base = BLOOM_STORE_OK;
		key.len = strlen(key.base);
		value.len = sizeof(int);
		value.base = (char *) &err;
		rd_config_impl(dev, CFG_WRITE, &key, &value);
	}

	for (int j = 0; j < rd->plevel; ++j) {
		db = rd->db + j;
		rd_lmdb_close(dev, db);
		db->bloom_loaded = 0;
	}
	if (!(dev->rt->flags & RT_FLAG_RDHOLD))
		rd_mdcache_close(dev);
}

static int
rd_dev_close(struct repdev* dev) {
	struct repdev_rd *rd = dev->device_lfs;
	struct repdev_db *db = NULL;
	uv_buf_t key;
	uv_buf_t value;

	/*
	 * Only one thread is allowed to set rd->opened = 2
	 * Other will fail to avoid concurrent close.
	 * As well, they will fail if the device had been closed already
	 */
	int res = __sync_bool_compare_and_swap(&rd->opened, 1, 2);
	if (!res)
		return 0; /* Is closing in another thread or already closed */
	/* To not wait forever limit lock time to 10 min */
	struct timespec tp;
	(void)clock_gettime(CLOCK_REALTIME, &tp);
	tp.tv_sec += 10*60;
	int err = pthread_rwlock_timedwrlock(&rd->guard, &tp);
	if (err)
		return err;
	rd_dev_close_nolock(dev);
	res = __sync_bool_compare_and_swap(&rd->opened, 2, 0);
	assert(res);
	pthread_rwlock_unlock(&rd->guard);
	return 0;
}

static void
rd_dev_free(struct repdev* dev) {
	struct repdev_rd *rd = dev->device_lfs;


	if (dev->bg_config != &dev->rt->dev_bg_config)
		je_free(dev->bg_config);
	for (int i = 0; i < rd->plevel; i++) {
		if (rd->db[i].bloom)
			je_free(rd->db[i].bloom);
		uv_mutex_destroy(&rd->db[i].log_flush_lock);
		uv_cond_destroy(&rd->db[i].log_flush_condvar);
		uv_rwlock_destroy(&rd->db[i].bloom_lock);
	}
	je_free(rd->db);
	je_free(dev->device_lfs);
	je_free(dev->name);
	free(dev->path);
	je_free(dev->journal);
}

static int
rd_dev_enum(struct reptrans *rt, reptrans_enum_cb_t cb, void *arg,
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

static part_walk_action_t
rd_sync_bloom_to_lmdb(struct repdev_db *db, void *arg) {

	struct repdev_db *zero_db = (struct repdev_db *) arg;
	MDB_txn *txn;
	MDB_val key, data;

	if (db->bloom_loaded <= 0)
		return PART_WALK_TERMINATE;

	char buf[1024] = {0};
	sprintf(buf, "bloom-%s-%d", db->dev->name, db->part);

	key.mv_size = strlen(buf);
	key.mv_data = &buf[0];

	data.mv_size = KEY_BLOOM_BYTELEN;
	data.mv_data = db->bloom;

	int err;
	if (mdb_txn_begin(DEV_ENV(db, TT_HASHCOUNT), NULL, 0, &txn) != 0)
		return PART_WALK_TERMINATE;

	if ((err = mdb_put(txn, DEV_SHARD(db, TT_HASHCOUNT, 0), &key, &data,
			0)) != 0) {
		mdb_txn_abort(txn);
		log_error(lg, "Dev(%s): %s store bloom mdb_put: (%d) %s", db->dev->name,
				type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err));
		return PART_WALK_TERMINATE;
	}

	mdb_txn_commit(txn);
	mdb_env_sync(DEV_ENV(db, TT_HASHCOUNT), 1);

	return PART_WALK_CONTINUE;

}

static part_walk_action_t
rd_load_bloom_from_lmdb(struct repdev_db *db, void *arg) {
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

	if (rd_config_impl(zero_db->dev, CFG_READ, &u_key, &u_val) != 0) {
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
	data.mv_size = KEY_BLOOM_BYTELEN;
	data.mv_data = NULL;

	if (mdb_txn_begin(DEV_ENV(db, TT_HASHCOUNT), NULL, MDB_RDONLY, &txn) !=
		0)
		return PART_WALK_TERMINATE;

	if ((err = mdb_get(txn, DEV_SHARD(db, TT_HASHCOUNT, 0), &key,
			&data)) != 0) {

		/*
		 * we failed to load the bloom, stop all other loads as well
		 */

		log_info(lg, "Dev(%s) part %d: unable to find bloom key, "
				"partition seems to be formatted",
				db->dev->name, db->part + 1);
		mdb_txn_abort(txn);
		/* note; callee should cleanup db->bloom */
		return PART_WALK_CONTINUE;
	}

	memcpy(db->bloom, data.mv_data, data.mv_size);
	mdb_txn_abort(txn);

	uv_rwlock_wrlock(&db->bloom_lock);
	db->bloom_loaded = 1;
	uv_rwlock_wrunlock(&db->bloom_lock);
	log_info(lg, "Dev(%s) part %d: bloom fast path succeeded",
		zero_db->dev->name, zero_db->part + 1);
	return PART_WALK_CONTINUE;
}

int
rd_dev_quiesce_bloom(struct repdev *rdev) {

	part_walk_action_t state;

	if(rdev->rt->flags & RT_FLAG_RDONLY)
		return 0;

	repdev_status_t status = reptrans_dev_get_status(rdev);
	if (status == REPDEV_STATUS_UNAVAILABLE ||
		status == REPDEV_STATUS_READONLY_FULL ||
		status == REPDEV_STATUS_READONLY_FORCED ||
		status == REPDEV_STATUS_READONLY_FAULT)
		return -EPERM;

	struct repdev_rd *rd = rdev->device_lfs;
	struct repdev_db *zero_db = rd->db;

	state = rd_partition_walk(rdev, rd_sync_bloom_to_lmdb, zero_db);
	if (state != PART_WALK_COMPLETED)
		return -EINVAL;

	log_info(lg, "bloom filter stored in lmdb for Dev(%s)", zero_db->dev->name);
	return 0;
}

int
rd_dev_load_bloom(struct repdev *rdev) {
	part_walk_action_t state;

	uv_buf_t u_key, u_val;
	u_key.base = BLOOM_STORE_OK;
	u_key.len = strlen(u_key.base);
	u_val.len = sizeof(int);

	struct repdev_rd *rd = rdev->device_lfs;
	struct repdev_db *zero_db = rd->db;

	state = rd_partition_walk(rdev, rd_load_bloom_from_lmdb, zero_db);
	if (state != PART_WALK_COMPLETED) {
		/* clean up */
		return -EINVAL;
	}

	/* mark toxic */
	int val = -1;
	u_val.base = (char *) &val;
	if (rd_config_impl(rdev, CFG_WRITE, &u_key, &u_val) != 0)
		return -EINVAL;

	return 0;

}

static int
rd_bcache_by_path(const char* part_path, char* bcache_name) {
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char disk_name [PATH_MAX] = {0};
	char fname[PATH_MAX];
	int part_index = -1;
	/* Looking for disk name skipping partition suffix */
	int err = sscanf(part_path, "/dev/%32[^0-9]%d", disk_name, &part_index);

	if (part_index > 0) {
		snprintf(fname, PATH_MAX, "/sys/block/%s/%s%d/bcache/dev/uevent",
			disk_name, disk_name, part_index);
	} else {
		snprintf(fname, PATH_MAX, "/sys/block/%s/bcache/dev/uevent",
			disk_name);
	}
	fp = fopen(fname, "r");
	if (fp == NULL) {
		log_error(lg, "Dev(%s): isn't a bcache-attached partition", part_path);
		return -ENOENT;
	}
	bcache_name[0] = 0;
	while ((read = getline(&line, &len, fp)) != -1) {
		char keyname[len];
		char val[len];
		err = sscanf(line, "%32[^=]=%s", keyname, val);
		free(line);
		line = NULL;
		if (err >= 0 && strcmp(keyname, "DEVNAME") == 0) {
			sprintf(bcache_name,"/dev/%s", val);
			break;
		}
	}
	if (line)
		free(line);

	fclose(fp);
	return strlen(bcache_name) ? 0 : -EIO;
}

#if 0
#define system(...) (printf("%s\n", __VA_ARGS__),0)
#endif

int
rd_destroy_gpt(const char* name, int n_parts, int empty_destroyed_cache, int noio) {
	char cmd[PATH_MAX];
	char path[PATH_MAX];
	char aux[PATH_MAX];
	char pname[128];
	char* mpath = NULL;
	char mname[128];
	const char* kpath = NULL;
	int err = 0;
	static const char* cleaned_disks[DEV_RD_MAXNUM] = {NULL};

	if (empty_destroyed_cache) {
		for(size_t n = 0 ; n < DEV_RD_MAXNUM; n++)
			cleaned_disks[n] = NULL;
	}
	int found = 0, idx = 0;
	for (; cleaned_disks[idx]; idx++) {
		if (!strcmp(name, cleaned_disks[idx])) {
			found = 1;
			break;
		}
	}
	if (found)
		return -EEXIST;

	cleaned_disks[idx] = name;

	mpath = rd_kpath(name, 0, NULL);
	if (!mpath) {
		log_error(lg, "Couldn't resolve VDEV name %s", name);
		return -ENOENT;
	}
	sscanf(mpath, "/dev/%s", mname);
	/* Stopping bcache set */
	kpath = rd_kpath(name, 1, aux);
	if (kpath) {
		sscanf(kpath, "/dev/%s", pname);
		struct stat st;
		sprintf(cmd, "/sys/block/%s/%s/bcache/set/stop", mname, pname);
		if (!stat(cmd, &st)) {
			sprintf(cmd, "echo 1 > /sys/block/%s/%s/bcache/set/stop", mname, pname);
			err = system(cmd);
		}
	}

	/* destroy parts headers */
	for (int i = 0; i < n_parts; i++) {
		struct stat st;
		kpath = rd_kpath(name, i+1, aux);
		if (!kpath) {
			/* Make sure a regular file haven't replaced a block device entry */
			if (isdigit(mpath[strlen(mpath)-1]))
				sprintf(aux, "%sp%d", mpath, i+1);
			else
				sprintf(aux, "%s%d", mpath, i+1);
			err = stat(aux, &st);
			if (!err && !S_ISBLK(st.st_mode)) {
				log_error(lg, "%s is NOT a block device. Remove the file and repeat", aux);
				return -ENOANO;
			}
			continue;
		}
		err = stat(kpath, &st);
		if (err)
			continue;
		if (!S_ISBLK(st.st_mode)) {
			log_error(lg, "%s is NOT a block device. Remove the file and repeat", kpath);
			return -ENOANO;
		}
		if (!noio) {
			sprintf(cmd, "dd if=/dev/zero of=%s bs=1M count=10 > /dev/null 2>&1",
				kpath);
			err = system(cmd);
		}
	}
	/* Destroy GPT */
	if (!noio) {
		sprintf(cmd, "wipefs -a %s > /dev/null 2>&1", mpath);
		err = system(cmd);
		sleep(1);
		int cnt = 30;
		do {
			sprintf(cmd, "partprobe %s > /dev/null 2>&1", mpath);
			err = system(cmd);
			if (err)
				sleep(1);
		} while (err && --cnt);
		if (err && !cnt) {
			log_error(lg, "Cannot partprobe %s, try to reboot the node and zap it again", mpath);
			return -EIO;
		}
		if ((err = rd_is_block_device(mpath)) != 1) {
			log_error(lg, "%s is NOT a block device. Remove the file and repeat", mpath);
			return -ENOANO;
		}
		sprintf(cmd, "wipefs -a %s > /dev/null 2>&1", mpath);
		err = system(cmd);

		sleep(1);

		err = rd_format_lmdb_part(mpath);
		if (err) {
			log_error(lg, "%s is NOT a block device. Remove the file and repeat", mpath);
			return -ENOANO;
		}
		sprintf(cmd, "rm -f /dev/disk/by-id/%s-part*-lock > /dev/null 2>&1", name);
		err = system(cmd);
	}
	if (mpath)
		free(mpath);
	return 0;
}

static void*
rd_close_thread(void* arg) {
	struct repdev* dev = arg;
	struct repdev_rd* rd = dev->device_lfs;
	log_notice(lg, "Dev(%s) starting closing procedure", dev->name);
	int err = rd_dev_close(dev);
	if (!err)
		log_notice(lg, "Dev(%s) all RTRD environments are closed",
			dev->name);
	else
		log_error(lg, "Dev(%s) RTRD rd_dev_close error %d", dev->name,
			err);
	return NULL;
}

/**
 * Make a VDEV unavailable. Detach it from LMDB environments asynchronously.
 *
 * @param fs  if specified, store fault signature in metaloc and
 * persistently mark the VDEV unavailable
 */
static int
rd_set_unavailable(struct repdev* dev, struct rd_fault_signature* fs, int sync) {
	struct repdev_rd* rd = dev->device_lfs;
	int err = 0;

	if (rd_is_opened(rd) != 1)
		return 0;

	if (fs) {
		char buf[RD_METALOC_SIZE];
		char real_name[PATH_MAX];
		uv_buf_t ub = {.base = buf, .len = sizeof(buf) };
		int pos = rd->metaloc.n_faults;
		(void)rd_kpath(rd->metaloc.device, 0, real_name);
		rd->metaloc.faults[pos] = *fs;
		rd->metaloc.n_faults++;
		rd->metaloc.timestamp = time(NULL);
		rd->metaloc.state = rdstateFault;
		int err = rd_write_metaloc(real_name, &rd->metaloc);
		if (err) {
			log_error(lg, "Dev(%s) unable to store metaloc on fault at %s",
				rd->metaloc.device, real_name);
		}
	}

	if (sync) {
		log_notice(lg, "Dev(%s) attempting to close environments", dev->name);
		err = rd_dev_close(dev);
		if (!err)
			log_notice(lg, "Dev(%s) all RTRD environments are closed",
				dev->name);
		else
			log_error(lg, "Dev(%s) RTRD rd_dev_close error %d", dev->name,
				err);
	} else {
		pthread_attr_t attr;
		pthread_t tid;
		err = pthread_attr_init(&attr);
		if (!err)
			err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (!err)
			err = pthread_create(&tid, &attr, rd_close_thread, (void *)dev);
	}
	return err;
}

static void
rd_dev_faulted(struct repdev* dev, struct rd_fault_signature* fs) {
	reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
	rd_set_unavailable(dev, fs, 0);
}

static int
rd_set_ro_fault(struct repdev* dev, struct rd_fault_signature* fs) {
	struct repdev_rd* rd = dev->device_lfs;
	reptrans_dev_set_status(dev, REPDEV_STATUS_READONLY_FAULT);
	char buf[RD_METALOC_SIZE];
	char real_name[PATH_MAX];
	uv_buf_t ub = {.base = buf, .len = sizeof(buf) };
	if (fs) {
		int pos = rd->metaloc.n_faults;
		rd->metaloc.faults[pos] = *fs;
		rd->metaloc.n_faults++;
	}
	(void)rd_kpath(rd->metaloc.device, 0, real_name);
	rd->metaloc.timestamp = time(NULL);
	rd->metaloc.state = rdstateReadOnly;
	int err = rd_write_metaloc(real_name, &rd->metaloc);
	if (err) {
		log_error(lg, "Dev(%s) unable to store metaloc on fault at %s",
			rd->metaloc.device, real_name);
	}

	return err;
}

static int
rd_erase(struct reptrans *rt, struct _json_value *o, const erase_opt_t* opts) {
	/* syntax error */
	if (o->type != json_object) {
		log_error(lg, "Syntax error: not an object");
		return -1;
	}

	json_value *devices = NULL;
	for (size_t i = 0; i < o->u.object.length; i++) {
		if (strcmp(o->u.object.values[i].name, "devices") == 0) {
			devices = o->u.object.values[i].value;
			break;
		}
	}

	/* devices section not found */
	if (!devices) {
		log_notice(lg, "Couldn't find any RTRD devices in rt-rd.json");
		return 0;
	}

	/* syntax error */
	if (devices->type != json_array) {
		log_error(lg, "Syntax error: devices section not an array");
		return -1;
	}
	/* Fetching disk info */
	struct rd_disks* d = NULL;
	int err = rd_fetch_disk_info(devices, &d);
	if (err) {
		log_error(lg, "Unable to fetch disk information: "
			"rd_fetch_disk_info() failed with code %d", err);
		return -EINVAL;
	}
	assert(d);
	/* Stopping the rdhold */
	char pid_file[PATH_MAX];
	snprintf(pid_file, sizeof(pid_file), "%s/var/run/rdhold.pid", nedge_path());
	struct stat st;
	err = stat(pid_file, &st);
	if (!err) {
		char line[1024];
		FILE* f = fopen(pid_file, "r");
		assert(f);
		char* l = fgets(line, sizeof(line), f);
		pid_t pid = strtoul(line, NULL, 10);
		fclose(f);
		if (pid > 0) {
			log_notice(lg, "Stopping rdhold");
			kill(pid, SIGTERM);
			sleep(10);
			kill(pid, SIGKILL);
			sleep(2);
			unlink(pid_file);
		}
	}
	/* Formatting */
	int clean_list = 1;
	int mdoffload_rebuild = 0;
	for (size_t i = 0; i < d->n_disks; i++) {
		struct rd_metaloc* meta = d->metas + i;

		struct jgroup* jg = NULL;
		for (size_t j = 0; j < d->n_groups; j++)
			if (!strcmp(meta->journal, d->groups[j].journal_device)) {
				jg = d->groups + j;
				break;
			}

		char buf[RD_METALOC_SIZE];
		uv_buf_t ub = {.base = buf, .len = sizeof(buf) };
		char sym_name[PATH_MAX];
		char cmd[PATH_MAX];
		char* real_name = NULL;
		char* real_jname = NULL;
		int plevel = meta->plevel;
		int bcache = meta->bcache;
		int jbcache = meta->bcache && jg; /* Journal has a bcache partition */
		const char* name = meta->device;
		const char* jname = strlen(meta->journal) ? meta->journal : NULL;
		int jindex = -1;
		int metaloc_restore = meta->version >= DEV_RD_VERSION_EXT_METALOC;

		if (opts->name && strcmp(opts->name, name))
			continue;
		err = 0;
		if (opts->journal_group) {
			if (!jg) {
				/* Journal group supported only in hybrid mode */
				return -ESPIPE;
			} else if (strcmp(opts->journal_group, jg->journal_device)) {
				/* Not our group, skipping */
				continue;
			}
		}
		real_name = rd_kpath(name, 0, NULL);
		if (!real_name) {
			log_error(lg, "Couldn't resolve VDEV name %s", name);
			continue;
		}
		if (jname) {
			real_jname = rd_kpath(jname, 0, NULL);
			if (!real_jname) {
				log_error(lg, "Couldn't resolve VDEV's jounal name %s",
					jname);
				continue;
			}
		}
		if (opts->plevel > plevel) {
			log_error(lg, "Dev(%s) wrong plevel %d, expected 1..%d",
				name, opts->plevel, plevel);
			return -ENFILE;
		}
		if (opts->flags & RD_ERASE_FLAG_RESTORE_ML) {
			if (!metaloc_restore) {
				log_error(lg, "The RTRDv%d doen't support metaloc recovery",
					meta->version);
				return -EINVAL;
			}
			err = 0;
			goto _mlrestore;
		}
		int wal_only = opts->flags & RD_ERASE_FLAG_WAL_ONLY;
		int cap_gpt_destroy = opts->flags & RD_REASE_FLAG_GPT_DESTROY;
		int noio = !!(opts->flags & RD_ERASE_FLAG_NOIO);
		/*
		 * Main partitions. We are allowed to destroy GPT if one of following:
		 * a) the journal device isn't defined
		 * b) we are going to zap whole journal group
		 * c) Zapping all known disks
		 * d) This is new a new disk (has no metaloc record,
		 *    that is, meta->version == 0
		 * */
		if (!opts->plevel && !wal_only &&
			((!jg && cap_gpt_destroy) ||
				opts->journal_group ||
				!opts->name ||
				!meta->version)) {
			log_notice(lg, "Formatting entire main device at %s",
				real_name);

			char msuf[PATH_MAX];
			sscanf(real_name, "/dev/%s", msuf);

			/* Erase entire device */
			if (real_jname && bcache) {
				/* Stopping bcache backed devices */
				for (int i = 0; i < plevel; i++) {
					struct stat st;
					char pname[PATH_MAX];
					char psuf[PATH_MAX];
					char* ppath = NULL;

					ppath = rd_kpath(name, i+1, NULL);
					if (!ppath)
						continue;
					sscanf(ppath, "/dev/%s", psuf);
					sprintf(cmd, "/sys/block/%s/%s/bcache/stop",
						msuf, psuf);
					if (!stat(cmd, &st)) {
						sprintf(cmd, "echo 1 > /sys/block/%s/%s/bcache/stop",
							msuf, psuf);
						err = system(cmd);
					}
					if (ppath)
						free(ppath);
				}
			}
			/* Destroy GPT */
			err = rd_destroy_gpt(name, 256, clean_list, noio);
			clean_list = 0;
			if (err && err != -EEXIST) {
				log_error(lg, "GPT destroy error at %s", real_name);
				return err;
			}
			metaloc_restore = 0;
			err = 0;
		} else if (!wal_only){
			char aux[PATH_MAX] = {0};
			char bcache_name[PATH_MAX] = {0};
			const char* sub_name = NULL;
			char* part_path = NULL;
			for (int i = 0; i < plevel; i++) {
				if (opts->plevel && opts->plevel != i+1)
					continue;
				part_path = rd_kpath(name, i + 1, aux);
				if (!part_path) {
					log_notice(lg, "The main partition %s-part%d for plevel%d not found!",
						name, i+1, i+1);
					return 0;
				}
				log_notice(lg, "Formatting main partition at %s plevel %d", part_path, i+1);
				sub_name = part_path;
				if (jname && bcache) {
					/* Try to find bcache device name if attached */
					int err = rd_bcache_by_path(part_path, bcache_name);
					if (!err) {
						sub_name = bcache_name;
						log_notice(lg, "Use bcache at %s for %s", sub_name, part_path);
					}
				}
				if (!noio) {
					err = rd_format_lmdb_part(sub_name);
					if (err)
						return err;
				}
			}
			err = 0;
		}
		/* Delete journal */
		if (meta->wal) {
			if (opts->name) {
				/* Erase a VDEV journals set */
				const char* wal_name = jname ? jname : name;
				char aux[PATH_MAX];
				for (int n = 0; n < plevel; n++) {
					if (opts->plevel && opts->plevel != n + 1)
						continue;
					char* kname = rd_kpath(wal_name, meta->first_journal_part + n, aux);
					if (!kname)
						continue;
					log_notice(lg, "Formatting a WAL partition at %s", kname);
					if (!noio) {
						err = rd_format_lmdb_part(kname);
						if (err) {
							log_error(lg, "Partition %s format error: %d", kname, err);
							return err;
						}
					}
				}
				if (jname && !wal_only) {
					if (!opts->plevel) {
						/* Erase the mdcache/mdoffload */
						const char* off_name = rd_kpath(meta->mdoffload, 0, aux);
						if (off_name) {
							log_notice(lg, "Formatting the mdoffload partition at %s", off_name);
							if (!noio) {
								err = rd_format_lmdb_part(off_name);
								if (err) {
									log_error(lg, "Partition %s format error: %d", off_name, err);
									return err;
								}
							}
						}
					} else {
						/* if a plevel erase, then
						 * 1) mdoffload needs to be cleaned from garbage
						 * 2) rdkeys and mdcache to be rebuilt
						 */
						mdoffload_rebuild = noio ? 0 : 1;
					}
				}
				err = 0;
			} else {
				/* Destroy journals GPT as well as a bcache
				 * caching partition and mdoffload
				 */
				err = rd_destroy_gpt(jname ? jname : name, 256, clean_list, noio);
				clean_list = 0;
				if (err) {
					if (err != -EEXIST) {
						log_error(lg, "Journal GPT destroy error at %s", real_jname);
						return err;
					}
					err = 0;
				} else if (!err) {
					log_notice(lg, "Destroyed GPT of a journal at %s", real_jname);
				}
			}
		} else if (jname) {
			/* No WALL, but journal device exists and so do mdcache and mdoffload,
			 * have to clean them
			 */
			if (!opts->name) {
				err = rd_destroy_gpt(jname, 256, clean_list, noio);
				clean_list = 0;
				if (err && err != -EEXIST) {
					log_error(lg, "mdoffload GPT destroy error at %s", real_jname);
					return err;
				} else if (!err) {
					log_notice(lg, "Destroyed GPT of a mdoffload part at %s", real_jname);
				}
				err = 0;
			} else if (!wal_only) {
				if (!opts->plevel) {
					char aux[PATH_MAX];
					char* kpath = rd_kpath(meta->mdoffload, 0, aux);
					if (kpath) {
						log_notice(lg, "Formatting the mdcache at %s", kpath);
						if (!noio) {
							err = rd_format_lmdb_part(kpath);
							if (err) {
								log_error(lg, "Partition %s format error: %d", kpath, err);
								return err;
							}
						}
					}
				} else {
					mdoffload_rebuild = noio ? 0 : 1;
				}
				err = 0;
			}
		}

		if (mdoffload_rebuild) {

			/*
			 * Activate a mdoffload cleanup command.
			 * Persist the state in the metaloc
			 */
			meta->state = rdstateMaintenance;
			meta->retries = 0;
			snprintf(meta->maintenance_cmd[meta->n_cmds++], sizeof(meta->maintenance_cmd[0]),
				"%s%d", CMD_DROP_OUTDATED_SIGNATURE,
				opts->plevel);
			int err = rd_write_metaloc(real_name, meta);
			if (err) {
				log_error(lg, "Unable to store the metaloc on %s",
					meta->device);
			}
			rt->flags = RT_FLAG_CREATE | RT_FLAG_STANDALONE;
			err = rt->probe(o, rt);
			if (err > 0) {
				QUEUE* d = NULL;
				uv_rwlock_rdlock(&rt->devlock);
				QUEUE_FOREACH(d, &rt->devices) {
					struct repdev *dev;
					dev = QUEUE_DATA(d, struct repdev, item);
					if (strcmp(dev->name, opts->name))
						continue;
					uv_rwlock_rdunlock(&rt->devlock);
					err = rt->dev_open(dev);
					rt->dev_close(dev);
					uv_rwlock_rdlock(&rt->devlock);
					break;
				}
				uv_rwlock_rdunlock(&rt->devlock);
				rt->destroy();
				err = 0;
			} else {
				/*
				 * Rebuild finished with an error.
				 * Device's partitions aren't consistent.
				 * On the next RTRD startup there will be one
				 * more attempt to rebuild. If it fails,
				 * the VDEV will be marked as faulted.
				 * */
				metaloc_restore = 0;
			}
		} else
			err = 0;
		/* If a main partition was formatted without affecting GPT and
		 * the device ins't new, then its metaloc has to be restored
		 * for normal operations
		 */
_mlrestore:
		if (!err && metaloc_restore) {
			meta->state = rdstateOk;
			meta->retries = 0;
			meta->n_faults = 0;
			meta->timestamp = time(NULL);
			int err = rd_write_metaloc(real_name, meta);
			if (err) {
				log_error(lg, "Unable to store the metaloc on %s",
					meta->device);
			}
		}
		if (real_name)
			free(real_name);
		if (real_jname)
			free(real_jname);

	}
	return err;
}

struct reptrans rtrd = {
	.name		= "rt-rd",
	.probe		= rd_probe,
	.destroy	= rd_destroy,
	.dev_open	= rd_dev_open,
	.dev_close	= rd_dev_close,
	.dev_free	= rd_dev_free,
	.dev_ctl	= rd_dev_ctl,
	.dev_enum	= rd_dev_enum,
	.erase		= rd_erase
};

