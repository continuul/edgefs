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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <uv.h>
#include <wchar.h>
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <net/if.h>
#include "ccowutil.h"
#include "ccow-impl.h"
#include "ccow.h"
#include "server-list.h"
#include "crypto.h"
#include "json.h"
#include "state.h"
#include "lfq.h"
#include "hashtable.h"
#include "cmcache.h"
#include "msgpackalt.h"
#include "auditd.h"
#include "auditc.h"
#include "trlog.h"
#include "fastlzlib.h"
#include "flexhash.h"
#include "ec-common.h"
#include "ccow-dynamic-fetch.h"

#define SERVERID_CACHE_FILE "%s/var/run/serverid.cache"
#define CCOW_DEFAULT_CONFIG "%s/etc/ccow/ccow.json"

#define SYSTEM_GUID_BUF_LEN 33

void (* signal_tgtd) (int signum) = NULL;
int ucache_test = 0;

uv_mutex_t uc_mi_mutex = PTHREAD_MUTEX_INITIALIZER;

uint64_t uc_mi_e_gbl = 0;

size_t uc_mi_total = 0;
size_t uc_mi_free = 0;
size_t uc_mi_buffered = 0;
size_t uc_mi_cached = 0;
size_t uc_mi_swapcached = 0;

typedef struct idlog_ {
	int get_accept;
	int put_accept;
} idlog_t;

int is_container = 0;

const char ccow_empty_str[1] = "";

int
uc_mi_get_meminfo(ucache_t * uc)
{
	int do_read = 0;

	uv_mutex_lock(&uc_mi_mutex);

	if (uc_mi_e_gbl > uc->uc_mi_e_lcl) {
		/*
		 * the global "time" of the last update is greater than the
		 * local "time". this means another thread has updated the
		 * information. use the global copy.
		 */
		do_read = 0;
		uc->uc_mi_e_lcl = uc_mi_e_gbl;

	} else if (uc_mi_e_gbl <= uc->uc_mi_e_lcl) {
		/*
		 * global "time" has not been updated. udpate data.
		 */
		do_read = true;
		uc_mi_e_gbl++;
		uc->uc_mi_e_lcl = uc_mi_e_gbl;
	}

	uv_mutex_unlock(&uc_mi_mutex);

	if (!do_read) {
		/*
		 * return without reading /proc/meminfo.
		 */
		return 0;
	}

	FILE * fp = 0;
	char buf[128];
	size_t rv;
	size_t haml = 0, rss = 0;
	if (is_container && !(getenv("DATA_CONTAINER"))) {
		fp = fopen("/sys/fs/cgroup/memory/memory.stat", "r");
		if (fp == 0) {
			log_error(lg, "fopen returned error : %s", strerror(errno));
			return 1;
		}
		while (fgets(buf, sizeof(buf), fp)) {
			if (sscanf(buf, "cache %zu", &rv) == 1) {
				uc_mi_cached = rv;
				continue;
			}
			if (sscanf(buf, "swap %zu", &rv) == 1) {
				uc_mi_swapcached = rv;
				continue;
			}
			if (sscanf(buf, "rss %zu", &rv) == 1) {
				rss = rv;
				continue;
			}
			if (sscanf(buf, "hierarchical_memory_limit %zu", &rv) == 1) {
				haml = rv;
				if (getenv("CCOW_MEMORY_LIMIT"))
					uc_mi_total = rv;
				else
					uc_mi_total = haml;
				break;
			}
		}
		fclose(fp);
		if (haml && rss)
			uc_mi_free = uc_mi_total - rss;
		else
			uc_mi_free = haml;
		uc_mi_buffered = 0;
		return 0;
	}


	/*
	 * read and parse /proc/meminfo, but only in the case of data-container
	 * or baremetal.
	 */
	fp = fopen("/proc/meminfo", "r");
	if (fp == 0) {
		log_error(lg, "fopen returned error : %s", strerror(errno));
		return 1;
	}
	int cached_read = 0;
	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "MemTotal: %zu kB", &rv) == 1) {
			uc_mi_total = rv * 1024UL;
			continue;
		}
		if (sscanf(buf, "MemFree: %zu kB", &rv) == 1) {
			uc_mi_free = rv * 1024UL;
			continue;
		}
		if (sscanf(buf, "Buffers: %zu kB", &rv) == 1) {
			uc_mi_buffered = rv * 1024UL;
			continue;
		}
		if (sscanf(buf, "Cached: %zu kB", &rv) == 1) {
			if (!cached_read) {
				uc_mi_cached = rv * 1024UL;
				cached_read = 1;
				continue;
			}
		}
		if (sscanf(buf, "SwapCached: %zu kB", &rv) == 1) {
			uc_mi_swapcached = rv * 1024UL;
			break;
		}
	}

	fclose(fp);
	return 0;
}


int
accounting_cid_skip(char *cid, size_t cid_size)
{
	// skeep empty names
	if (cid_size <= 1) {
		return 1;
	}

	/* do not do accounting for log objects */
	if (cid_size >= strlen(TRLOG_TID_PREFIX) &&
	    strncmp(cid, TRLOG_TID_PREFIX, strlen(TRLOG_TID_PREFIX)) == 0)
		return 1;

	/* do not do accounting for admin objects */
	if (cid_size == strlen(RT_SYSVAL_TENANT_ADMIN) + 1 &&
	    strcmp(cid, RT_SYSVAL_TENANT_ADMIN) == 0)
		return 1;

	return 0;
}


int
accounting_tid_skip(char *tid, size_t tid_size)
{
	// skeep empty names
	if (tid_size <= 1) {
		return 1;
	}

	/* do not do accounting for log objects */
	if (tid_size >= strlen(TRLOG_TID_PREFIX) &&
	    strncmp(tid, TRLOG_TID_PREFIX, strlen(TRLOG_TID_PREFIX)) == 0)
		return 1;

	/* do not do accounting for svcs objects */
	if (tid_size == strlen(RT_SYSVAL_TENANT_SVCS) + 1 &&
	    strcmp(tid, RT_SYSVAL_TENANT_SVCS) == 0)
		return 1;

	/* do not do accounting for admin objects */
	if (tid_size == strlen(RT_SYSVAL_TENANT_ADMIN) + 1 &&
	    strcmp(tid, RT_SYSVAL_TENANT_ADMIN) == 0)
		return 1;

	return 0;
}

/* globally shared logging service between tenants */
static LOGGER lg_ccow;
static ifvbuf_t ifvbuf_ccow;
ifvbuf_t *ifvbuf = NULL;
static volatile int mtc_inprog = 0;
static uint64_t iflink_update_ts = 0;
static struct ccow_shm_process *ccow_process_table;
struct ccow_shm_process *myproc;
static volatile struct ccow *mtc = NULL;
volatile unsigned long *ccow_glock_mem;
pthread_rwlock_t mtc_lock = PTHREAD_RWLOCK_INITIALIZER;

static ucache_t *mtc_ucache = NULL;
static QUEUE mtc_queue;
pthread_mutex_t mtc_queue_lock = PTHREAD_MUTEX_INITIALIZER;

static void ccow_ucache_timer_cb(uv_timer_t* handle, int status);
static void ccow_ucache_timer_close_cb(uv_handle_t* handle);
static void ccow_operation_free(struct ccow_op *op);

static int
ccow_process_tenant_data(ccow_lookup_t iter, char *cid_tid, struct ccow_cluster_stats *data)
{
	int err = 0;
	size_t val_size;

	int pos = 0;
	uint64_t val;
	struct ccow_metadata_kv *kv;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, pos++))) {
		if (!strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE)) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &val);

			data->cluster_logical_size += val;

		} else if (!strcmp(kv->key, RT_SYSKEY_OBJECT_COUNT)) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &val);

			data->cluster_objects += val;
		} else if (!strcmp(kv->key, RT_SYSKEY_ESTIMATED_USED)) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &val);

			data->cluster_estimated_used += val;
		}
	}

	return err;
}
/*
 * Iterate through a list of tenants in a cluster specified by clname or by context
 * and return the accounting data for these tenants.
 * data must be pre-allocated.
 */
int
ccow_cluster_accounting(struct ccow *tc, char *clname,  size_t clsize,
	const char *tenant_pattern, size_t pattern_size,
	size_t count, struct ccow_cluster_stats *data)
{
	int err = 0;
	assert(data);
	ccow_lookup_t tnlp;

	char *cid = clname ? clname : tc->cid;
	size_t cid_size = clname ? clsize : tc->cid_size;
	if (accounting_cid_skip(cid, cid_size))
		return 0;


	/* Tenant Lookup doesnt understand a count of 0. */
	// FIXME: btreenam cannot handle more than INT32_MAX chunks at a time
	//  so we must fix this. NED-1064
	if (count == 0)
		count = INT32_MAX;
	err = ccow_tenant_lookup(tc, clname, clsize, tenant_pattern, pattern_size, count, &tnlp);
	if (err == -ENOENT) {
		err = 0;
		goto _cleanup;
	} else if (err) {
		log_error(lg, "Cluster accounting request error: %d", err);
		goto _cleanup;
	}

	int pos = 0;
	struct ccow_metadata_kv *kv;
	while ((kv = ccow_lookup_iter(tnlp, CCOW_MDTYPE_NAME_INDEX, pos++))) {
		/* Iterate through all the tenants listed in the cluster */
		int get_err = 0;
		char *tid = (char *)kv->key;
		uint16_t tid_size = kv->key_size;

		if (accounting_tid_skip(tid, tid_size))
			continue;

		data->cluster_tenants++;
		ccow_completion_t c;
		ccow_lookup_t iter;
		err = ccow_create_completion(tc, NULL, NULL, 1, &c);
		if (err) {
			log_error(lg, "Cluster Accounting unable to proceed \
			    Failing with error: %d", err);
			goto _cleanup;
		}

		err = ccow_admin_pseudo_get(cid, cid_size, tid, tid_size, "", 1, "", 1,
				NULL, 0, 0,	CCOW_GET, c, &iter);

		if (err) {
			ccow_release(c);
			continue;
		}
		err = ccow_wait(c, -1);
		if (err) {
			if (iter)
				ccow_lookup_release(iter);
			continue;
		}

		/* Process the tenant info now! */
		char *cid_tid = (char *) je_calloc(1, cid_size + tid_size + 1);
		memcpy(cid_tid, cid, cid_size);
		strcat(cid_tid, "/");
		strncat(cid_tid, tid, tid_size);
		err = ccow_process_tenant_data(iter, cid_tid, data);


		/* Inner cleanup */
		je_free(cid_tid);
		ccow_lookup_release(iter);
	}

_cleanup:
	if (tnlp)
		ccow_lookup_release(tnlp);
	return err;
}

static void
ccow_process_bucket_data(ccow_lookup_t iter, struct ccow_tenant_stats *data)
{

	int pos = 0;
	struct ccow_metadata_kv *kv;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, pos++))) {
		if (!strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE)) {
			uint64_t val;
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &val);
			data->tenant_logical_size += val;
		} else if (!strcmp(kv->key, RT_SYSKEY_OBJECT_COUNT)) {
			uint64_t val;
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &val);
			data->tenant_objects += val;
		}
	}

	return;
}
/*
 * Iterate through a list of buckets in a tenant specified by pattern
 * and return the accounting data for these buckets.
 * data must be pre-allocated.
 */
int
ccow_tenant_accounting(struct ccow *tc, const char *bucket_pattern,
    size_t pattern_size, size_t count, struct ccow_tenant_stats *data)
{
	int err = 0;
	assert(data);
	ccow_lookup_t bk;
	/* Bucket Lookup doesnt understand a count of 0. */
	// FIXME: btreenam cannot handle more than INT32_MAX chunks at a time
	//  so we must fix this. NED-1064
	if (count == 0)
		count = INT32_MAX;
	err = ccow_bucket_lookup(tc, bucket_pattern, pattern_size, count, &bk);
	if (err == -ENOENT) {
		err = 0;
		goto _cleanup;
	} else if (err) {
		log_error(lg, "Tenant accounting request error: %d", err);
		goto _cleanup;
	}

	int pos = 0;
	struct ccow_metadata_kv *kv;
	while ((kv = ccow_lookup_iter(bk, CCOW_MDTYPE_NAME_INDEX, pos++))) {
		/* Iterate through all the buckets listed in the tenant */
		int get_err = 0;
		char *bid = (char *)kv->key;
		uint16_t bid_size = kv->key_size;
		data->tenant_buckets++;
		ccow_completion_t c;
		ccow_lookup_t iter;
		err = ccow_create_completion(tc, NULL, NULL, 1, &c);
		if (err) {
			log_error(lg, "Tenant Accounting unable to proceed \
			    Failing with error: %d", err);
			goto _cleanup;
		}

		err = ccow_get(bid, bid_size, "", 1, c, NULL, 0, 0, &iter);
		if (err) {
			ccow_release(c);
			continue;
		}
		err = ccow_wait(c, -1);
		if (err) {
			if (iter)
				ccow_lookup_release(iter);
			continue;
		}

		/* Process the bucket info now! */
		ccow_process_bucket_data(iter, data);

		/* Inner cleanup */
		ccow_lookup_release(iter);
	}

_cleanup:
	if (bk)
		ccow_lookup_release(bk);
	return err;
}

void
ccow_error_fmt(struct ccow_io *io, int log_level)
{
	struct ccow_op *op = io->op;
	struct ccow_completion *c = op->comp;
	struct ccow *tc = op->comp->tc;
	struct class_req *r = CCOW_IO_REQ(io);

	if (op->tid && *op->tid != 0 && op->tid_size > 6 &&
	    memcmp(op->tid, TRLOG_TID_PREFIX, 6) == 0)
		return;

	char nhid_buf[UINT512_BYTES * 2 + 1];
	uint512_dump(&c->vm_name_hash_id, nhid_buf, UINT512_BYTES * 2 + 1);
	uint16_t nhid_row = HASHROWID(&c->vm_name_hash_id, tc->flexhash);

	char chid_buf[UINT512_BYTES * 2 + 1];
	uint16_t chid_row = 0;
	if ((io->optype != CCOW_RING) && (r != NULL)) {
		uint512_dump(&r->chid, chid_buf, UINT512_BYTES * 2 + 1);
		chid_row = HASHROWID(&r->chid, tc->flexhash);
	} else {
		log_notice(lg, "Client cannot establish RING communication. "
		    "Check that local ccow-daemon is running.");
		return;
	}
	if (log_level == LOG_LEVEL_ERROR) {
		log_error(lg, "Affected OID: %s/%s/%s/%s, hashmask=%X", op->cid,
		    op->tid, op->bid, op->oid, tc->flexhash->hashmask);
		log_error(lg, "Affected NHID: %s ROW: %d", nhid_buf, nhid_row);
		if (r == NULL)
			log_error(lg, "Affected CHID: could not be determined");
		else
			log_error(lg, "Affected CHID: %s ROW: %d", chid_buf, chid_row);
	} else if (log_level == LOG_LEVEL_WARN) {
		log_warn(lg, "Affected OID: %s/%s/%s/%s, hashmask=%X", op->cid,
		    op->tid, op->bid, op->oid, tc->flexhash->hashmask);
		log_warn(lg, "Affected NHID: %s ROW: %d", nhid_buf, nhid_row);
		if (r == NULL)
			log_warn(lg, "Affected CHID: could not be determined");
		else
			log_warn(lg, "Affected CHID: %s ROW: %d", chid_buf, chid_row);
	}
}


static int
ccow_parse_config__tenant(struct ccow *tc, json_value *tenant)
{
	int err;

	/* defaults */
	int tenant_schedprio = sched_get_priority_max(SCHED_RR);;
	int tenant_ucache_size = CCOW_UCACHE_SIZE;
	int tenant_ucache_size_max = CCOW_UCACHE_SIZE_MAX;

	uint32_t ucache_size_limit = UCACHE_SIZE_LIM;

	int cmcache_hash_size = CMCACHE_HASH_SIZE;
	int cmcache_lru_hiwat = CMCACHE_HASH_SIZE * 3;
	int cmcache_lru_lowat = 3 * CMCACHE_HASH_SIZE / 4;
	uint64_t cmcache_timer_timeout = CMCACHE_TIMER_TIMEOUT;
	uint64_t cmcache_timer_repeat  = CMCACHE_TIMER_REPEAT;

	uint8_t disable_read_ahead = 0;
	uint32_t read_ahead_factor = READ_AHEAD_FACTOR;
	uint32_t read_ahead_detect = READ_AHEAD_DETECT;

	int comphash_bulk_max = COMPHASH_BULK_MAX;
	int comphash_threshold_size = COMPHASH_THRESHOLD_SIZE;
	int hash_type = HASH_TYPE_DEFAULT;
	int verify_chid = 1;
	int failure_domain = FD_SERVER;
	int io_rate_max = CCOW_IO_RATE_MAX;
	int compress_type = COMPRESSOR_DEFAULT;
	int replication_count = RT_SYSVAL_REPLICATION_COUNT;
	int sync_put = RT_SYSVAL_SYNC_PUT;
	int sync_put_named = RT_SYSVAL_SYNC_PUT_NAMED;
	int sync_put_ack_min = RT_SYSVAL_SYNC_PUT_ACK_MIN;
	int sync_put_dedup_min = RT_SYSVAL_SYNC_PUT_DEDUP_MIN;
	int sync_put_extra = RT_SYSVAL_SYNC_PUT_EXTRA;
	int sync_put_extra_wait = RT_SYSVAL_SYNC_PUT_EXTRA_WAIT;
	int sync_put_fd_min = RT_SYSVAL_SYNC_PUT_FD_MIN;
	int sync_put_commit_wait = RT_SYSVAL_SYNC_PUT_COMMIT_WAIT;
	int select_policy = RT_SYSVAL_SELECT_POLICY;
	int expunge_onsplit = RT_SYSVAL_EXPUNGE_ONSPLIT;
	char *chunkmap_type = RT_SYSVAL_CHUNKMAP_BTREE;
	uint16_t number_of_versions = RT_SYSVAL_NUMBER_OF_VERSIONS_DEFAULT;
	uint16_t chunkmap_btree_order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_DEFAULT;
	uint8_t chunkmap_btree_marker = RT_SYSVAL_CHUNKMAP_BTREE_MARKER_DEFAULT;
	uint32_t chunkmap_chunk_size = RT_SYSVAL_CHUNKMAP_CHUNK_SIZE;
	uint8_t unicastio = REPLICAST_UNICAST_UDP;
	uint16_t track_statistics = 1;
	uint32_t iops_rate_lim = 0;
	uint8_t  ec_enabled = RT_SYSVAL_EC_ENABLED;
	uint32_t ec_data_mode = RT_SYSVAL_EC_DATA_MODE;
	uint64_t ec_trg_policy = RT_SYSVAL_EC_TRG_POLICY;
	uint8_t  file_object_transparency = RT_SYSVAL_FILE_OBJECT_TRANSPARANCY;
	uint64_t object_delete_after = RT_SYSVAL_OBJECT_DELETE_AFTER;
	uint64_t slg_timeout = RT_SYSVAL_SERVERLIST_GET_TIMEOUT;
	uint64_t tp_size = CCOW_TP_SIZE_DEFAULT;
	uint64_t api_depth = CCOW_API_DEPTH;
	uint64_t compl_lfq_depth = CCOW_COMPL_LFQ_DEPTH;
	uint64_t isgw_backoff_time = CCOW_ISGW_BACKOFF_TIME;

	if (is_embedded()) {
		api_depth = CCOW_API_DEPTH_EMBEDDED;
		compl_lfq_depth = CCOW_COMPL_LFQ_DEPTH_EMBEDDED;
		io_rate_max = CCOW_IO_RATE_MAX_EMBEDDED;
	}

	int join_delay = RT_SYSVAL_JOIN_DELAY;

	if (!tenant)
		goto _default_exit;

	/* syntax error */
	if (tenant->type != json_object) {
		log_error(lg, "Syntax error: user section not an object"
		    ": -EINVAL");
		return -EINVAL;
	}

	size_t j;
	for (j = 0; j < tenant->u.object.length; j++) {
		char *namekey = tenant->u.object.values[j].name;
		json_value *v = tenant->u.object.values[j].value;

		/* tenant_schedprio */
		if (strcmp(namekey, "tenant_schedprio") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: tenant_schedprio "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			tenant_schedprio = v->u.integer;
			if (tenant_schedprio < 1 || tenant_schedprio > 99) {
				log_error(lg,
				    "tenant_schedprio: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey, "comphash_threshold_size") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "comphash_threshold_size not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			comphash_threshold_size = v->u.integer;
		} else if (strcmp(namekey, "thread_pool_size") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "thread_pool_size not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			tp_size = v->u.integer;
		} else if (strcmp(namekey, "comphash_bulk_max") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "comphash_bulk_max not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			comphash_bulk_max = v->u.integer;
		/* ucache size limit */
		} else if (strcmp(namekey,
			    "ucache_size_limit") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "ucache_size_limit is not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			ucache_size_limit = v->u.integer;
			if (ucache_size_limit > 100) {
				log_error(lg,
				    "ucache_size_limit: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}

		/* cmcache */
		} else if (strcmp(namekey,
			    "cmcache_lru_hiwat") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "cmcache_lru_hiwat not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			cmcache_lru_hiwat = v->u.integer;
		} else if (strcmp(namekey,
			    "cmcache_lru_lowat") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "cmcache_lru_lowat not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			cmcache_lru_lowat = v->u.integer;
		} else if (strcmp(namekey,
			    "cmcache_hash_size") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "cmcache_hash_size is not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			cmcache_hash_size = v->u.integer;
			if (cmcache_hash_size < 0 ||
			    cmcache_hash_size > CMCACHE_HASH_SIZE_MAX) {
				log_error(lg,
				    "cmcache_hash_size: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey,
			    "cmcache_timer_timeout") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "cmcache_timer_timeout is not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			cmcache_timer_timeout = v->u.integer;
		} else if (strcmp(namekey,
			    "cmcache_timer_repeat") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "cmcache_timer_repeat is not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			cmcache_timer_repeat = v->u.integer;


		/* read ahead */
		} else if (strcmp(namekey,
			    "disable_read_ahead") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "disable_read_ahead is not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			disable_read_ahead = v->u.integer;
			if (disable_read_ahead != 0 &&
			    disable_read_ahead != 1) {
				log_error(lg,
				    "disable_read_ahead: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey,
			    "read_ahead_factor") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "read_ahead_factor is not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			read_ahead_factor = v->u.integer;
			if (read_ahead_factor == 0) {
				log_error(lg,
				    "read_ahead_factor: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey,
			    "read_ahead_detect") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "read_ahead_detect is not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			read_ahead_detect = v->u.integer;
			if (read_ahead_detect == 0) {
				log_error(lg,
				    "read_ahead_detect: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* ucache_size */
		} else if (strcmp(namekey,
			    "tenant_ucache_size") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "tenant_ucache_size is not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			tenant_ucache_size = v->u.integer;
			if (tenant_ucache_size < 0 ||
			    tenant_ucache_size > CCOW_UCACHE_SIZE_MAX) {
				log_error(lg,
				    "tenant_ucache_size: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey,
			    "tenant_ucache_size_max") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "tenant_ucache_size_max is not an integer: "
				    "-EINVAL");
				return -EINVAL;
			}
			tenant_ucache_size_max = v->u.integer;
			if (tenant_ucache_size_max < 0) {
				log_error(lg,
				    "tenant_ucache_size_max: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* multicast group join delay */
		} else if (strcmp(namekey, "join_delay") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: join_delay"
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			join_delay = v->u.integer;
			if (join_delay < 0) {
				log_error(lg, "join_delay: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* failure_domain */
		} else if (strcmp(namekey, "failure_domain") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: failure_domain"
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			failure_domain = v->u.integer;
			if (failure_domain >= FD_END || failure_domain < 0) {
				log_error(lg, "failure_domain: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* verify_chid */
		} else if (strcmp(namekey, "verify_chid") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: verify_chid"
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			verify_chid = v->u.integer;
			if (verify_chid > 1 || verify_chid < 0) {
				log_error(lg, "verify_chid: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* hash_type */
		} else if (strcmp(namekey, "hash_type") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: hash_type "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			hash_type = v->u.integer;
			if (hash_type < 0 || hash_type >= HASH_TYPE_END) {
				log_error(lg, "hash_type: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* compress_type */
		} else if (strcmp(namekey, "compress_type") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: compress_type "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			compress_type = v->u.integer;
			if (compress_type < 0 ||
			    compress_type >= COMPRESSOR_END) {
				log_error(lg, "compress_type: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* io_rate_max */
		} else if (strcmp(namekey, "io_rate_max") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "io_rate_max is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			io_rate_max = v->u.integer;
			if (io_rate_max > CCOW_IO_RATE_MAX_HI ||
			    io_rate_max < CCOW_IO_RATE_MAX_LOW) {
				log_error(lg,
				    "io_rate_max: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* sync_put_extra_wait */
		} else if (strcmp(namekey, "sync_put_extra_wait") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "sync_put_extra_wait is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			sync_put_extra_wait = v->u.integer;
			if (sync_put_extra_wait < 1 ||
			    sync_put_extra_wait >= CLIENT_PUTCOMMON_TIMEOUT_PP_MS) {
				log_error(lg,
				    "sync_put_extra_wait: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* sync_put_extra */
		} else if (strcmp(namekey, "sync_put_extra") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "sync_put_extra is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			sync_put_extra = v->u.integer;
			if (sync_put_extra < 0 || sync_put_extra > 16) {
				log_error(lg,
				    "sync_put_extra: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* sync_put_dedup_min */
		} else if (strcmp(namekey, "sync_put_dedup_min") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "sync_put_dedup_min is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			sync_put_dedup_min = v->u.integer;
			if (sync_put_dedup_min < 0 ||
			    (sync_put && sync_put_dedup_min > sync_put)) {
				log_error(lg,
				    "sync_put_dedup_min: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* sync_put_ack_min */
		} else if (strcmp(namekey, "sync_put_ack_min") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "sync_put_ack_min is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			sync_put_ack_min = v->u.integer;
			if (sync_put_ack_min < 0 ||
			    (sync_put && sync_put_ack_min > sync_put)) {
				log_error(lg,
				    "sync_put_ack_min: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* number_of_versions */
		} else if (strcmp(namekey, "number_of_versions") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "number_of_versions is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			number_of_versions = (uint16_t)v->u.integer;
			if (v->u.integer > 65535) {
				log_error(lg,
				    "number_of_versions: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		/* fixed chunk_size */
		} else if (strcmp(namekey,
			    "chunkmap_chunk_size") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				   "chunkmap_chunk_size is not an integer"
				   ": -EINVAL");
				return -EINVAL;
			}
			chunkmap_chunk_size = v->u.integer;
			if (chunkmap_chunk_size < REPLICAST_CHUNK_SIZE_MIN ||
			    chunkmap_chunk_size > REPLICAST_CHUNK_SIZE_MAX) {
				log_error(lg, "chunkmap_chunk_size: "
				    "invalid arugment: -EINVAL");
				return -EINVAL;
			}
		/* btree order */
		} else if (strcmp(namekey, "chunkmap_btree_order") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "chunkmap_btree_order is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			chunkmap_btree_order = (uint16_t)v->u.integer;
			if (chunkmap_btree_order < 1 ||
			    chunkmap_btree_order >
			    RT_SYSVAL_CHUNKMAP_BTREE_ORDER_MAX) {
				log_error(lg, "chunkmap_btree_order: -EINVAL");
				return -EINVAL;
			}
		/* btree marker */
		} else if (strcmp(namekey, "chunkmap_btree_marker") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "chunkmap_btree_marker is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			chunkmap_btree_marker = (uint8_t)v->u.integer;
			if (chunkmap_btree_marker != 0 && chunkmap_btree_marker != 1) {
				log_error(lg, "chunkmap_btree_marker: -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey, "chunkmap_type") == 0) {
			if (v->type != json_string) {
				log_error(lg, "Syntax error: "
				    "chunkmap_type not a str: -EINVAL");
				return -EINVAL;
			}
			chunkmap_type = v->u.string.ptr;
		/* replication_count */
		} else if (strcmp(namekey, "replication_count") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "replication_count is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			replication_count = v->u.integer;
			if (replication_count <
				REPLICAST_REPLICATION_COUNT_MIN ||
			    replication_count >
				REPLICAST_REPLICATION_COUNT_MAX) {
				log_error(lg,
				    "replication_count: invalid arugment"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey, "sync_put_named") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "sync_put_named is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			sync_put_named = v->u.integer;
			if (sync_put_named < 1 ||
			    sync_put_named > REPLICAST_SYNC_PUT_MAX) {
				log_error(lg,
				    "sync_put_named: invalid argument"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey, "sync_put") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "sync_put is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			sync_put = v->u.integer;
			if (sync_put < 0 ||
			    sync_put > REPLICAST_SYNC_PUT_MAX) {
				log_error(lg,
				    "sync_put: invalid argument"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey, "sync_put_fd_min") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "sync_put_fd_min is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			sync_put_fd_min = v->u.integer;
			if (sync_put_fd_min < 2 ||
			    sync_put_fd_min > REPLICAST_SYNC_PUT_MAX) {
				log_error(lg,
				    "sync_put: invalid argument"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey, "sync_put_commit_wait") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "sync_put_commit_wait is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			sync_put_commit_wait = v->u.integer;
			if (sync_put_commit_wait < 0 ||
			    sync_put_commit_wait > 1) {
				log_error(lg,
				    "sync_put: invalid argument"
				    ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey, "select_policy") == 0) {
			/* json format on file under tenant:
			 * "select_policy" : [ 1, 2, 4 ]
			 * 1 - WINDOW
			 * 2 - SPACE
			 * 4 - QDEPTH
			 */
			if (v->type != json_array) {
				log_error(lg, "Syntax error: "
				    "select_policy is not an array"
				    ": -EINVAL");
				return -EINVAL;
			}
			select_policy = 0;
			for (size_t i = 0 ; i < v->u.array.length; i++) {
				json_value *d = v->u.array.values[i];
				if (d->type != json_integer) {
					log_error(lg, "Syntax error: "
					    "select_policy.%lu is not an"
					    "integer", i);
					continue;
				}
				if ((d->u.integer < 0) ||
				    (d->u.integer > REPLICAST_SELECT_POLICY_MAX)) {
					log_error(lg, "select_policy: invalid "
					    "argument %ld : -EINVAL",
					    d->u.integer);
					continue;
				}
				if ((d->u.integer > 1) && (d->u.integer % 2)) {
					log_error(lg, "select_policy: invalid "
					    "argument %ld : -EINVAL",
					    d->u.integer);
					continue;
				}
				select_policy |= d->u.integer;
			}
			if (!select_policy)
				select_policy = RT_SYSVAL_SELECT_POLICY;
			log_debug(lg, "select_policy set %d", select_policy);
		} else if (strcmp(namekey, "unicast_io") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: unicast_io "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			unicastio = v->u.integer;
			if (unicastio != REPLICAST_UNICAST_UDP &&
			    unicastio != REPLICAST_UNICAST_UDP_MCPROXY &&
			    unicastio != REPLICAST_UNICAST_TCP && unicastio != 0) {
				log_error(lg, "unicast_io: invalid arugment"
					      ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey, "track_statistics") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: track_statistics "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			track_statistics = v->u.integer;
		} else if (strcmp(namekey, "expunge_onsplit") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: expunge_onsplit "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			expunge_onsplit = v->u.integer;
		} else if (strcmp(namekey, "iops_rate_lim") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: iops_rate_lim "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			iops_rate_lim = v->u.integer;
		} else if (strcmp(namekey, "ec_enabled") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: ec_enabled "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			if (v->u.integer < 0 || v->u.integer > 1) {
				log_error(lg, "Syntax error: ec_enabled "
					"wrong value: %ld", v->u.integer);
				return -EINVAL;
			}
			ec_enabled = v->u.integer;
		} else if (strcmp(namekey, "ec_algorithm") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: ec_algorithm "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			ec_data_mode = v->u.integer;
		} else if (strcmp(namekey, "slg_timeout") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: ec_algorithm "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			slg_timeout = v->u.integer;
		} else if (strcmp(namekey, "ec_trg_policy") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: ec_algorithm "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			ec_trg_policy = v->u.integer;
		} else if (strcmp(namekey, "file_object_transparency") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: file_object_transparency "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			if (v->u.integer < 0 || v->u.integer > 1) {
				log_error(lg, "Syntax error: file_object_transparency "
					"wrong value: %ld", v->u.integer);
				return -EINVAL;
			}
			file_object_transparency = v->u.integer;
		} else if (strcmp(namekey, "api_depth") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: api_depth "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			api_depth = v->u.integer;
		} else if (strcmp(namekey, "lfq_depth") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: lfq_depth "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			compl_lfq_depth = v->u.integer;
		} else if (strcmp(namekey, "isgw_backoff_time") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: isgw_backoff_time "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			isgw_backoff_time = v->u.integer;
		}
	}

_default_exit:
	/*
	 * Set tenant user in accordance with supplied
	 * configuration options now...
	 */
	tc->tenant_schedprio = tenant_schedprio;
	tc->tenant_ucache_size = tenant_ucache_size;
	tc->tenant_ucache_size_max = tenant_ucache_size_max;
	tc->ucache_size_limit = ucache_size_limit;

	tc->cmcache_lru_hiwat     = cmcache_lru_hiwat;
	tc->cmcache_lru_lowat     = cmcache_lru_lowat;
	tc->cmcache_hash_size     = cmcache_hash_size;
	tc->cmcache_timer_timeout = cmcache_timer_timeout;
	tc->cmcache_timer_repeat  = cmcache_timer_repeat;

	tc->disable_read_ahead = disable_read_ahead;
	tc->read_ahead_factor = read_ahead_factor;
	tc->read_ahead_detect = read_ahead_detect;
	tc->verify_chid = verify_chid;
	tc->failure_domain = failure_domain;
	tc->compress_type = compress_type;
	tc->hash_type = hash_type;
	tc->number_of_versions = number_of_versions;
	tc->io_rate_max = io_rate_max;
	tc->join_delay = join_delay;
	tc->replication_count = replication_count;
	tc->sync_put = sync_put;
	tc->sync_put_named = sync_put_named;
	tc->sync_put_ack_min = sync_put_ack_min;
	tc->sync_put_dedup_min = sync_put_dedup_min;
	tc->sync_put_extra = sync_put_extra;
	tc->sync_put_extra_wait = sync_put_extra_wait;
	tc->sync_put_fd_min = sync_put_fd_min;
	tc->sync_put_commit_wait = sync_put_commit_wait;
	tc->select_policy = select_policy;
	tc->chunkmap_chunk_size = chunkmap_chunk_size;
	tc->unicastio = unicastio;
	tc->chunkmap_type = je_strdup(chunkmap_type);
	tc->track_statistics = track_statistics;
	tc->iops_rate_lim = iops_rate_lim;
	if (!tc->chunkmap_type)
		return -ENOMEM;
	tc->chunkmap_btree_order = chunkmap_btree_order;
	tc->chunkmap_btree_marker = chunkmap_btree_marker;
	tc->comphash_bulk_max = comphash_bulk_max;
	tc->comphash_threshold_size = comphash_threshold_size;
	tc->ec_enabled = ec_enabled;
	tc->ec_data_mode = ec_data_mode;
	tc->ec_trg_policy = ec_trg_policy;
	tc->file_object_transparency = file_object_transparency;
	tc->object_delete_after = object_delete_after;
	tc->inline_data_flags = 0;
	tc->slg_timeout = slg_timeout;
	tc->tp_size = tp_size;
	tc->expunge_onsplit = expunge_onsplit;
	tc->api_depth = api_depth;
	tc->compl_lfq_depth = compl_lfq_depth;
	tc->isgw_backoff_time = isgw_backoff_time;
	return 0;
}

static int
ccow_parse_config(struct ccow *tc)
{
	int err;
	size_t i;
	json_value *opts = tc->opts;

	/* syntax error */
	if (opts->type != json_object) {
		log_error(lg, "Syntax error: not an object: -EINVAL");
		return -EINVAL;
	}

	json_value *tenant = NULL;

	uint64_t trlog_interval_us = TRLOG_INTERVAL_DEFAULT_US;
	uint64_t trlog_quarantine = TRLOG_PROCESSING_QUARANTINE;

	for (i = 0; i < opts->u.object.length; i++) {
		if (strncmp(opts->u.object.values[i].name, "tenant", 6) == 0) {
			tenant = opts->u.object.values[i].value;
		} else if (strncmp(opts->u.object.values[i].name, "trlog", 5) == 0) {
			json_value *trlog = opts->u.object.values[i].value;
			for (size_t j = 0; j < trlog->u.object.length; j++) {
				char *k = trlog->u.object.values[j].name;
				json_value *v = trlog->u.object.values[j].value;
				if (strncmp(k, "interval", 8) == 0) {
					if (v->type != json_integer || v->u.integer < 1) {
						log_error(lg, "Syntax error: trlog "
						    "interval is not an integer or incorrect value");
						return -EINVAL;
					}
					trlog_interval_us = v->u.integer * 1000000UL;
				} else if (strncmp(k, "quarantine", 10) == 0) {
					if (v->type != json_integer || v->u.integer < 1 || v->u.integer > 8) {
						log_error(lg, "Syntax error: trlog "
						    "quarantine is not an integer or incorrect value");
						return -EINVAL;
					}
					trlog_quarantine = v->u.integer;
				}
			}
		} else if (strncmp(opts->u.object.values[i].name, "cache", 5) == 0) {
			json_value *v = opts->u.object.values[i].value;
			if (v->type != json_string) {
				log_error(lg, "Syntax error: "
				    "cache parameter is not a string: "
				    "-EINVAL");
				return -EINVAL;
			}
			if (strncmp(v->u.string.ptr, "gw", 2) == 0)
				tc->gw_cache = 1;
		}
	}
	if (tc->gw_cache != 1) {
		int gw_cache = 0;
		char *env_gwcache = getenv("CCOW_GW_CACHE_ENABLED");
		if (env_gwcache) {
			gw_cache = atoi(env_gwcache);
			tc->gw_cache = gw_cache;
		}
	}

	tc->trlog_interval_us = trlog_interval_us;
	tc->trlog_quarantine = trlog_quarantine;

	err = ccow_parse_config__tenant(tc, tenant);
	if (err)
		return err;

	return 0;
}

static void
ccow_tenant_notified(uv_poll_t *treq, int status, int events)
{
	struct ccow *tc = treq->data;

	char *buf = NULL;
	int nread = nn_recv(tc->sub_fd, buf, NN_MSG, NN_DONTWAIT);
	if (nread < 0) {
		return;
	}

	/* FIXME: update tenant parameters */
	nn_freemsg(buf);
}


static int
ccow_tenant_subscribe(struct ccow *tc)
{

	int err;

	assert(tc->sub_fd == -1);

	char pub_address[INET6_ADDRSTRLEN + 10];
	sprintf(pub_address, "tcp://127.0.0.1:%d", AUDITD_PUB_PORT);

	// FIXME: calculate pub address based on NHID
	//
	// struct sockaddr_in6 send_addr;
	// flexhash_get_hashaddr(tc->flexhash, &tc->cluster_hash_id, &send_addr);
	// char dst[INET6_ADDRSTRLEN];
	// inet_ntop(AF_INET6, &send_addr.sin6_addr, dst, INET6_ADDRSTRLEN);
	// sprintf(pub_address, "tcp://[%s]:%d", dst, AUDITD_PUB_PORT);

	char phid_buf[UINT512_BYTES * 2 + 1];
	memset(phid_buf, 0, UINT512_BYTES * 2 + 1);

	uint512_dump(&tc->cluster_hash_id, phid_buf, UINT512_BYTES * 2 + 1);

	char topic[AUDITD_TOPIC_MAXLEN];
	sprintf(topic, "counts.ccow.namedput.%s", phid_buf);

	tc->sub_req.data = tc;
	err = auditc_subscribe(tc->loop, pub_address, topic, &tc->sub_fd,
				&tc->sub_req, ccow_tenant_notified);
	if (err == 0) {
		log_debug(lg, "Subscribed to topic: %s", topic);
	}

	return err;
}


static void
ccow_tenant_unsubscribe(struct ccow *tc)
{
	int err;

	if (tc->sub_fd == -1)
		return;

	char phid_buf[UINT512_BYTES * 2 + 1];
	memset(phid_buf, 0, UINT512_BYTES * 2 + 1);

	uint512_dump(&tc->cluster_hash_id, phid_buf, UINT512_BYTES * 2 + 1);

	char topic[AUDITD_TOPIC_MAXLEN];
	sprintf(topic, "counts.ccow.namedput.%s", phid_buf);


	err = auditc_unsubscribe(&tc->sub_fd, &tc->sub_req, topic);
	if (err) {
		log_error(lg, "Error unsubscibing for %s", topic);
	}
}

void ccow_delayed_api_call(uv_poll_t* handle, int status, int events)
{
	struct ccow *tc = (struct ccow *)handle->data;
	uv_async_send(&tc->api_call);

	/* reset - stop */
	struct itimerspec timspec;
	memset(&timspec, 0, sizeof (timspec));
	timerfd_settime(tc->congest_timerfd, 0, &timspec, 0);
	uv_poll_stop(handle);
}

static void
ccow__on_api_call(uv_async_t *handle, int status)
{
	struct ccow *tc = (struct ccow *)handle->data;
	struct state *st;
	uint64_t delay_ns = 0;
	struct itimerspec timspec;

	while ((st = lfqueue_dequeue(tc->api_lfq_hp))) {
		if (st->io != NULL && (!st->io->comp || st->io->comp->released))
			continue;
		if (st->io != NULL)
			QUEUE_INSERT_TAIL(&tc->inprog_queue, &st->io->inprog_item);
		state_event(st, EV_CALL);
	}
	uint64_t rtt0 = flexhash_get_rtt(CLIENT_FLEXHASH, &uint512_null,
					 FH_MSG_UNSOLICITED, 4096);

	uint64_t rtt1 = flexhash_get_rtt(CLIENT_FLEXHASH, &uint512_null,
					 FH_MSG_GET_SOLICITED, 8192);

	int rate_diff = tc->io_rate_max - tc->io_rate_lim;
	rate_diff = rate_diff < 0 ? 0 : rate_diff;

	if (tc->io_rate > tc->io_rate_lim) {
		/*
		 * We still bound by the rate limit or cluster weight.
		 * Retry again in 1 us
		 */
		delay_ns = CCOW_IO_RATE_DELAY_NS * (rtt0 + rtt1) * (1 + rate_diff);
		goto _delayed_call;
	}
	while ((st = lfqueue_dequeue(tc->api_lfq))) {
		if (st->io != NULL && (!st->io->comp || st->io->comp->released))
			continue;
		if (st->io != NULL)
			QUEUE_INSERT_TAIL(&tc->inprog_queue,
					  &st->io->inprog_item);
		state_event(st, EV_CALL);

		/* Cont i/o is not a real I/O, so do not throttle for it */
		if (st->io != NULL && st->io->optype != CCOW_PUT_CONT &&
		    st->io->optype != CCOW_GET_CONT &&
		    st->io->optype != CCOW_CONT)
			tc->io_rate++;

		if (tc->io_rate >= tc->io_rate_lim) {
			/*
			 * We just hit the rate limit. Throttle queue.
			 */
			delay_ns = CCOW_IO_RATE_DELAY_NS * (rtt0 + rtt1) * (1 + rate_diff);
			break;
		}

		struct ccow_completion *c = st->io->comp;
		if (!c->iops_rate_lim)
			continue;

		/*
		 * Per object rate-limiting. Introduce adjusted delay for this
		 * context. Assumption is that this context handling one object,
		 * i.e. block I/O case. In case of object, we expect settings
		 * on per tenant basis, i.e. tenant metadata, same for file.
		 */
		if (c->iops_rate_lim < tc->get_iops + tc->put_iops) {
			uint64_t delta = (tc->get_iops + tc->put_iops) - c->iops_rate_lim;
			tc->iops_rate_adjust += ccow_retry_log2(CCOW_IOPS_RATE_LIM_DELAY_NS * tc->io_rate, delta);
			delay_ns = tc->iops_rate_adjust;
			break;
		} else {
			uint64_t delta = c->iops_rate_lim - (tc->get_iops + tc->put_iops);
			uint64_t new_delay = ccow_retry_log2(CCOW_IOPS_RATE_LIM_DELAY_NS * tc->io_rate, delta);
			if (tc->iops_rate_adjust > new_delay) {
				tc->iops_rate_adjust -= new_delay;
				delay_ns = tc->iops_rate_adjust;
				break;
			}
		}
	}

	if (tc->put_retry_prev < tc->put_retry_cnt ||
	     tc->get_retry_prev < tc->get_retry_cnt) {
		tc->io_rate_lim >>= 1;
		if (tc->io_rate_lim < 2)
			tc->io_rate_lim = 2;
		tc->io_adjust_period += tc->io_rate_lim * 2;
	} else if (!tc->io_adjust_period && tc->io_rate_lim < tc->io_rate_max) {
		tc->io_rate_lim++;
		tc->io_adjust_period = tc->io_rate_lim * 2;
	}

	tc->put_retry_prev = tc->put_retry_cnt;
	tc->get_retry_prev = tc->get_retry_cnt;
	if (tc->io_adjust_period)
		tc->io_adjust_period--;

	log_debug(lg, "io_rate %d io_rate_lim %d get_retry %lu put_retry %lu",
	    tc->io_rate, tc->io_rate_lim, tc->get_retry_cnt, tc->put_retry_cnt);

	if (!delay_ns)
		return;

_delayed_call:
	memset(&timspec, 0, sizeof (timspec));

	/* reset */
	if (uv_is_active((uv_handle_t *)&tc->congest_req)) {
		uv_poll_stop(&tc->congest_req);
		timerfd_settime(tc->congest_timerfd, 0, &timspec, 0);
	}

	/* set */
	timspec.it_value.tv_nsec = delay_ns;
	int err = timerfd_settime(tc->congest_timerfd, 0, &timspec, 0);
	if (err) {
		usleep(1);
		uv_async_send(&tc->api_call);
		return;
	}

	/* start */
	uv_poll_start(&tc->congest_req, UV_READABLE, ccow_delayed_api_call);
	return;
}

static void
ccow__on_enter(uv_async_t *handle, int status)
{
	struct ccow *tc = (struct ccow *)handle->data;

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		// ccow_tenant_subscribe(tc);
	}
}

static void
ccow_timer_process_scan_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
ccow__on_exit(uv_async_t *handle, int status)
{
	struct ccow *tc = (struct ccow *)handle->data;

	uv_close((uv_handle_t *)&tc->api_call, NULL);
	uv_close((uv_handle_t *)handle, NULL);
	uv_close((uv_handle_t *)&tc->enter_handle, NULL);

	if (uv_is_active((uv_handle_t *)&tc->congest_req))
		uv_poll_stop(&tc->congest_req);
	uv_close((uv_handle_t *)&tc->congest_req, NULL);

	close(tc->congest_timerfd);

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		ccow_tenant_unsubscribe(tc);
	}

	if (tc->ucache_timer_req) {
		/*
		 * stop the timer if it has been initialized
		 */
		uv_timer_stop(tc->ucache_timer_req);
		uv_close((uv_handle_t *)tc->ucache_timer_req, ccow_ucache_timer_close_cb);
	}

	if (tc->cmcache)
		ccow_cmcache_free(tc->cmcache);

	uv_mutex_lock(&tc->pscan_timer_lock);

	tc->pscan_terminate_worker = 1;
	if (tc->pscan_work_inprog) {
		uv_mutex_unlock(&tc->pscan_timer_lock);
		uv_barrier_wait(&tc->pscan_term_bar);
		uv_barrier_destroy(&tc->pscan_term_bar);
	} else
		uv_mutex_unlock(&tc->pscan_timer_lock);

	if (tc->timer_process_scan) {
		uv_timer_stop(tc->timer_process_scan);
		uv_close((uv_handle_t *)tc->timer_process_scan,
		    ccow_timer_process_scan_close_cb);
	}

	/* cancel all inprog IOs */
	QUEUE *q = NULL;
	while (!QUEUE_EMPTY(&tc->inprog_queue)) {
		q = QUEUE_HEAD(&tc->inprog_queue);
		struct ccow_io *io = QUEUE_DATA(q, struct ccow_io, inprog_item);

		if (io->op->busy_cnt != 0) {
			log_debug(lg, "canceling IO %p", io);
			state_event(&io->state, EV_ERR);
		}
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
	}
	if (tc->netobj)
		ccow_network_destroy(tc->netobj);
}

/*
 * Each client cluster context processed in its own event loop. Primary reason
 * is better isolation in case of multi-tenancy.
 */
static void
main_loop(void *arg)
{
	struct ccow *tc = arg;
	int err;

	log_info(lg, "CCOW library main loop started");

	tc->loop_thrid = uv_thread_self();

	if (tc->opts_override)
		tc->opts_override(tc);

	struct ccowtp_job_config ccow_tp_cfg = {
		.sched = SCHED_OTHER,
		.prio = 0,
		.weight = 100,
		.min = 0,
		.resiliency = 0
	};

	if (tc->tp_size) {
		log_debug(lg, "Created a tenant thread pool, size %u", tc->tp_size);
		tc->tp = ccowtp_create(tc->loop, &ccow_tp_cfg, 1, tc->tp_size);
	} else {
		log_debug(lg, "Using shared thread pool");
	}
	assert(tc->tp);

	if (getuid() == 0) {
		struct sched_param params;

		memset(&params, 0, sizeof (params));
		params.sched_priority = tc->tenant_schedprio;

		err = pthread_setschedparam(pthread_self(), SCHED_FIFO, &params);
		if (err) {
			log_warn(lg, "Cannot set tenant_schedprio. Error %d", err);
		} else
			log_info(lg, "CCOW library main loop priority set to %d",
			    tc->tenant_schedprio);
	}

#if 0
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	srand(get_timestamp_us());
	CPU_SET(rand() % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
	sched_setaffinity(0, sizeof(cpuset), &cpuset);
#endif
	/* get to the shared memory segment for the process table of
	 * all the ccow processes on this node
	 */
	err = ccow_init_shmseg();
	if (err) {
		tc->startup_err = err;
		log_error(lg, "Unable to access the ccow process table err: %d", err);
		return;
	}

	is_container = getenv("HOST_HOSTNAME") ? 1 : 0;

	/*
	 * UCACHE has to be initialized in uv loop thread
	 */
	if (!mtc) {
		pthread_rwlock_wrlock(&mtc_lock);
		if (!mtc) {
			mtc = tc;
			log_info(lg, "tc %p now elected as proc master on start", tc);
		}
		if (!mtc_ucache) {
			mtc_ucache = ccow_ucache_create((struct ccow *)mtc);
			if (!mtc_ucache) {
				pthread_rwlock_unlock(&mtc_lock);
				tc->startup_err = -ENOMEM;
				return;
			}
			QUEUE_INIT(&mtc_queue);
		}
		pthread_rwlock_unlock(&mtc_lock);
	}
	tc->ucache = mtc_ucache;
	assert(tc->ucache->tc == mtc);
	pthread_mutex_lock(&mtc_queue_lock);
	QUEUE_INSERT_TAIL(&mtc_queue, &tc->mtc_item);
	pthread_mutex_unlock(&mtc_queue_lock);

	err = uv_barrier_init(&tc->ucache_term_bar, 2);
	if (err != 0) {
		tc->startup_err = err;
		return;
	}

	if (!ucache_test) {
		tc->ucache_timer_req = je_malloc(sizeof (*tc->ucache_timer_req));
		if (!tc->ucache_timer_req) {
			tc->startup_err = -ENOMEM;
			return;
		}

		err = uv_timer_init(tc->loop, tc->ucache_timer_req);
		if (err != 0) {
			log_error(lg, "uv_timer_init returned error \"%s\"", strerror(errno));
			je_free(tc->ucache_timer_req);
			tc->startup_err = err;
			return;
		}

		tc->ucache_timer_req->data = tc;

		tc->tp_stat_counter = UCACHE_TIMER_TIMEOUT;
		err = uv_timer_start(tc->ucache_timer_req, ccow_ucache_timer_cb,
		    UCACHE_TIMER_TIMEOUT, UCACHE_TIMER_REPEAT);
		if (err != 0) {
			log_error(lg, "uv_timer_start returned error \"%s\"", strerror(errno));
			je_free(tc->ucache_timer_req);
			tc->startup_err = err;
			return;
		}
	}

	tc->cmcache = ccow_cmcache_create(tc);
	if (!tc->cmcache) {
		tc->startup_err = -ENOMEM;
		return;
	}

	/*
	 * Initialize client network, retrieve list of servers.
	 * This will also parse networking configuration
	 */
	tc->netobj = ccow_network_init(tc);
	if (!tc->netobj) {
		tc->startup_err = -EINVAL;
		return;
	}

	err = ccow_add_proc(tc->netobj->if_speeds, tc->netobj->if_indexes_count);
	if (err) {
		tc->startup_err = err;
		log_error(lg, "Unable to add to the ccow process table err: %d", err);
		return;
	}
	ifvbuf = replicast_ifvbuf_init(&ifvbuf_ccow, tc->netobj->if_speeds,
	    tc->netobj->if_indexes_count);

	/*
	 * PSCAN timer for VBUF management
	 */
	tc->pscan_terminate_worker = 0;
	err = uv_barrier_init(&tc->pscan_term_bar, 2);
	if (err) {
		tc->startup_err = -ENOMEM;
		return;
	}
	uv_mutex_init(&tc->pscan_timer_lock);
	tc->timer_process_scan = je_malloc(sizeof (*tc->timer_process_scan));
	if (!tc->timer_process_scan) {
		tc->startup_err = -ENOMEM;
		return;
	}
	uv_timer_init(tc->loop, tc->timer_process_scan);
	tc->timer_process_scan->data = tc;
	tc->pscan_work_inprog = 0;
	err = uv_timer_start(tc->timer_process_scan, ccow_pscan_timer_cb,
	    PSCAN_TIMER_TIMEOUT, PSCAN_TIMER_REPEAT);
	if (err != 0) {
		log_error(lg, "uv_timer_start returned error \"%s\"", strerror(errno));
		tc->startup_err = -errno;
		return;
	}

	uv_async_init(tc->loop, &tc->enter_handle, ccow__on_enter);
	uv_async_init(tc->loop, &tc->exit_handle, ccow__on_exit);
	uv_async_init(tc->loop, &tc->api_call, ccow__on_api_call);
	uv_handle_t *t = (uv_handle_t *)&tc->api_call;
	t->data = (void *)tc;
	t = (uv_handle_t *)&tc->enter_handle;
	t->data = (void *)tc;
	t = (uv_handle_t *)&tc->exit_handle;
	t->data = (void *)tc;

	tc->congest_timerfd = timerfd_create(CLOCK_MONOTONIC,
	    TFD_NONBLOCK | TFD_CLOEXEC);
	if (tc->congest_timerfd == -1) {
		tc->startup_err = -errno;
	}
	tc->congest_req.data = (void *)tc;
	uv_poll_init(tc->loop, &tc->congest_req, tc->congest_timerfd);

	/* synchronize with ccow_tenant_init() */
	uv_barrier_wait(&tc->main_barrier);

	if (!tc->startup_err) {
		uv_run(tc->loop, UV_RUN_DEFAULT);

		while (!uv_workers_empty(tc->loop)
			   || !uv_wq_empty(tc->loop)) {
			usleep(10000);
			uv_run(tc->loop, UV_RUN_ONCE);
		}


		/* Free memory allocated by uv_loop_new() in an unusual way.
		 * See a note for NED-1049 for explanation
		 **/

		/* Workaround made in NED-1049 has open filedescriptor leakage
		 * The problem why uv_loop_delete made seg faults, was because not all handles where "uv_close"-ed.
		 * Every handle should be closed before call uv_loop_delete.
		 * uv_timer_stop or similar functions are not mandatory to call prior uv_close.
		 * uv_close itself calls corresponding stop depending on the handle type.
		 * for more info see NED-3835
		*/
		uv_loop_delete(tc->loop);
		if (tc->netobj)
			ccow_network_finish_destroy(tc->netobj);
		ccowtp_free(tc->tp);
		tc->loop = NULL;

		uv_mutex_destroy(&tc->pscan_timer_lock);
	}

	log_info(lg, "CCOW library main loop terminated");
}

static int
ccow_destroy_completion(struct ccow_completion *c)
{
	struct ccow *tc = c->tc;
	int err;

	log_trace(lg, "c %p: busy_ops %lu operations_num %lu, operations_end %lu, "
	    "comp_lfq %d ", c, c->busy_ops, c->operations_num,
	    c->operations_end, lfqueue_length(tc->comp_lfq));

	uv_mutex_lock(&c->operations_mutex);

	if (c->wait_count > 0) {
		uv_mutex_unlock(&c->operations_mutex);
		return -EAGAIN;
	}

	/*
	 * Those ops which are not yet created needs to decrement its
	 * reference counting too.
	 */
	for (uint32_t i = c->operations_end; i < c->operations_num; i++) {
		if (c->busy_ops == 0)
			break;
		c->busy_ops--;
	}
	for(uint32_t i = 0; i < c->operations_end; i++) {
		struct ccow_op *op = c->operations_done[i];
		if (op) {
			if (!op->completed) {
				uv_mutex_unlock(&c->operations_mutex);
				log_trace(lg, "c %p: completion cleanup delayed, "
				    "cannot relase op->index %d", c, i);
				return 0;
			}
		}
	}

	if (c->custom_md) {
		/* custom metadata initialized without iterator case */
		rtbuf_destroy(c->custom_md);
		c->custom_md = NULL;
	}
	uv_mutex_unlock(&c->operations_mutex);

	/*
	 * All I/O completed. Move resources back to main pool.
	 */
	struct ccow_io *io;
	while ((io = lfqueue_dequeue(c->done_lfq)) != NULL) {
		ccow_destroy_io(io);
	}

	for(uint32_t i = 0; i < c->operations_end; i++) {
		struct ccow_op *op = c->operations_done[i];
		if (op)
			ccow_operation_free(op);
	}

	if (c->ver_name) {
		je_free(c->ver_name->tid);
		je_free(c->ver_name->bid);
		je_free(c->ver_name->oid);
		je_free(c->ver_name);
	}
	if (c->ver_rb)
		rtbuf_destroy(c->ver_rb);

	if (c->operations != NULL) {
		log_debug(lg, "freeing : c->operations %p on destroy", c->operations);
		je_free(c->operations);
		c->operations = NULL;
	}

	je_free(c->chunkmap_type);

	c->chunkmap_type = NULL;

	if (c->md_overrides) {
		rtbuf_destroy(c->md_overrides);
		c->md_overrides = NULL;
	}

	if (c->version_vm_content_hash_id) {
		je_free(c->version_vm_content_hash_id);
		c->version_vm_content_hash_id = NULL;
	}

	pthread_spin_lock(&tc->comp_lfq->ring_lock);
	if (!tc->reserved_comp) {
		tc->reserved_comp = c;
		pthread_spin_unlock(&tc->comp_lfq->ring_lock);
	} else {
		pthread_spin_unlock(&tc->comp_lfq->ring_lock);
		err = lfqueue_enqueue(tc->comp_lfq, c);
		assert(!err);
	}
	return 0;
}

void
ccow_stream_flags(ccow_completion_t comp, int *flags)
{
	struct ccow_completion *c = comp;
	if (flags && *flags) {
		c->cont_flags = *flags;
		log_debug(lg, "stream cont_flags updated to 0x%x", c->cont_flags);
	}
	if (flags)
		*flags = c->cont_flags;
}

static int
ccow_create_stream_completion_versioned_internal(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp,
    const char *cid, size_t cid_size, const char *tid, size_t tid_size,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    uint64_t *genid, uint64_t version_uvid_timestamp,
    const char *version_vm_content_hash_id, int *flags, ccow_lookup_t *iter)
{
	int err = ccow_create_completion(cluster, cb_arg, cb_complete,
	    operations_num, pcomp);
	if (err) {
		log_debug(lg, "ccow_create_completion returned error %d", err);
		*pcomp = NULL;
		return err;
	}

	struct ccow_completion *c = *pcomp;

	c->cont = 1;
	c->cont_flags = CCOW_CONT_F_EXIST | (flags ? *flags : 0);
	c->cont_generation = genid;
	c->version_uvid_timestamp = version_uvid_timestamp;
	if (version_vm_content_hash_id) {
		c->version_vm_content_hash_id = (uint512_t *) je_malloc(sizeof(uint512_t));
		if (!c->version_vm_content_hash_id) {
			err = -ENOMEM;
			log_error(lg, "ccow_create_completion returned error %d", err);
			ccow_release(c);
			*pcomp = NULL;
			return err;
		}
		uint512_fromhex(version_vm_content_hash_id, (UINT512_BYTES * 2 + 1),
		    c->version_vm_content_hash_id);
	} else {
		c->version_vm_content_hash_id = NULL;
	}

	c->chunkmap_flags = CCOW_STREAM;
	c->chunkmap_ctx = NULL;

	int get_io_attributes = (c->cont_flags & CCOW_CONT_F_REPLACE) ?
		RD_ATTR_OBJECT_REPLACE : 0;
	get_io_attributes |= (c->cont_flags & CCOW_CONT_F_SKIP_TRLOG_UPDATE) ?
		RD_ATTR_TRLOG_SOP : 0;
	err = ccow_tenant_put(cid, cid_size, tid, tid_size, bid, bid_size,
	    oid, oid_size, c, NULL, 0, 0, CCOW_CONT, NULL, get_io_attributes);
	if (err) {
		c->cont_flags &= ~CCOW_CONT_F_EXIST;
		log_debug(lg, "ccow_tenant_put returned error %d", err);
		ccow_drop(c);
		*pcomp = NULL;
		return err;
	}

	err = ccow_wait(c, 0);
	if (err == -ENOENT) {
		c->cont_flags &= ~CCOW_CONT_F_EXIST;
	} else if (err) {
		ccow_drop(c);
		log_debug(lg, "ccow_wait returned error %d", err);
		*pcomp = NULL;
		return err;
	}

	if (flags)
		*flags = c->cont_flags;

	/* if application passed iterator then it must not release it because
	 * of nature of stream NG..UG/UP..NP. I.e. either finalize() or release()
	 * will free it */
	if (iter)
		*iter = c->init_op->iter;

	/* reset completion as it will be completed in finalize later */
	c->init_op->completed = 0;

	return 0;
}

/*
 * Create stream completion object, locked to a specific object.
 *
 * Scope: PUBLIC
 */
int
ccow_admin_pseudo_create_stream_completion(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp,
    const char *cid, size_t cid_size, const char *tid, size_t tid_size,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
	uint64_t *genid, int *flags, ccow_lookup_t *iter) {

	return ccow_admin_pseudo_create_stream_completion_versioned(cluster, cb_arg,
		    cb_complete, operations_num, pcomp,
		    cid, cid_size, tid, tid_size, bid, bid_size, oid, oid_size,
		    genid, 0, NULL, flags, iter);
}

/*
 * Create stream completion object, locked to a specific object.
 *
 * Scope: PUBLIC
 */
int
ccow_create_stream_completion(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
	uint64_t *genid, int *flags, ccow_lookup_t *iter) {

	return ccow_create_stream_completion_versioned(cluster, cb_arg,
		    cb_complete, operations_num, pcomp,
		    bid, bid_size, oid, oid_size,
			genid, 0, NULL,	flags, iter);
}


/*
 * Create stream completion for versioned object, locked to a specific object.
 *
 * Scope: PUBLIC
 */
int
ccow_create_stream_completion_versioned(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    uint64_t *genid, uint64_t version_uvid_timestamp,
    const char *version_vm_content_hash_id, int *flags, ccow_lookup_t *iter)
{
	return ccow_create_stream_completion_versioned_internal(cluster, cb_arg,
	    cb_complete, operations_num, pcomp, cluster->cid, cluster->cid_size,
	    cluster->tid, cluster->tid_size, bid, bid_size, oid, oid_size,
	    genid, version_uvid_timestamp, version_vm_content_hash_id, flags,
	    iter);
}

/*
 * Create stream "pseudo" completion for versioned object, locked to a
 * specific object.
 *
 * Scope: PUBLIC
 */
int
ccow_admin_pseudo_create_stream_completion_versioned(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp,
    const char *cid, size_t cid_size, const char *tid, size_t tid_size,
    const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    uint64_t *genid, uint64_t version_uvid_timestamp,
    const char *version_vm_content_hash_id, int *flags, ccow_lookup_t *iter)
{

	if (memcmp_quick(cluster->tid, cluster->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Permission Denied, not admin");
		log_hexdump(lg, "TID:", cluster->tid, cluster->tid_size);
		return -EPERM;
	}

	return ccow_create_stream_completion_versioned_internal(cluster, cb_arg,
	    cb_complete, operations_num, pcomp, cid, cid_size,
	    tid, tid_size, bid, bid_size, oid, oid_size,
	    genid, version_uvid_timestamp, version_vm_content_hash_id, flags,
	    iter);
}

/*
 * Replenish completion queue.
 *
 * Free up previously released completions and move them back
 * to the comp_lfq (inside of ccow_destroy_completion).
 */
static void
ccow_replenish_completions(struct ccow *tc, struct ccow_completion *c)
{
	int err;
	unsigned int n_done = 2;
	unsigned int n_keep = 4;
	unsigned long n_cap = lfqueue_cap(tc->comp_lfq);
	if (n_cap >= n_done) {
		struct ccow_completion *c_ptr;
		while ((c_ptr = lfqueue_dequeue(tc->released_lfq))) {
			if (n_cap >= n_keep) {
				if (c_ptr == c || c_ptr->busy_ops > 0) {
					lfqueue_enqueue(tc->released_lfq, c_ptr);
					break;
				}
				err = ccow_destroy_completion(c_ptr);
				if (err != 0) {
					lfqueue_enqueue(tc->released_lfq, c_ptr);
					break;
				}
				n_cap = lfqueue_cap(tc->comp_lfq);
				continue;
			}
			lfqueue_enqueue(tc->released_lfq, c_ptr);
			break;
		}
	}
}

/*
 * Create completion object
 *
 * Scope: PUBLIC
 */
int
ccow_create_completion(ccow_t cluster, void *cb_arg,
    ccow_callback_t cb_complete, int operations_num, ccow_completion_t *pcomp)
{
	struct ccow *tc = cluster;
	int err = 0;
	struct ccow_completion *c = NULL;

	log_trace(lg, "tc %p, cb_arg %p, cb_complete %p, "
	    "operations_num %d, pcomp %p: comp_lfq %d ",
	    tc, cb_arg, cb_complete, operations_num, pcomp,
	    lfqueue_length(tc->comp_lfq));

	//
	// We use op_num == 0 to signify preloading of completion md to handle
	// cases where we'd otherwise overwrite the MD from attr_modify() at the
	// closing of the namedget
	//
	assert(operations_num >= 0);

	int dequeue_cnt = 0;
	if (tc->loop_thrid == uv_thread_self()) {
		/*
		 * Throttle I/O flow if we in TC context -
		 * we can not sleep for too long here but we can loop
		 * for while up to 10ms.
		 */
		while ((c = lfqueue_dequeue(tc->comp_lfq)) == NULL &&
		    dequeue_cnt++ < CCOW_COMP_USER_THROTTLE_MAX * 1000) {
			usleep(1);
			if ((dequeue_cnt % 250) == 0)
				ccow_replenish_completions(tc, NULL);
		}

		/* Attempt to allocate from reserved completion if
		 * we have it */
		pthread_spin_lock(&tc->comp_lfq->ring_lock);
		if (!c && tc->reserved_comp) {
			c = tc->reserved_comp;
			tc->reserved_comp = NULL;
		}
		pthread_spin_unlock(&tc->comp_lfq->ring_lock);
	} else {
		/*
		 * Throttle I/O flow if we in user thread context - we can
		 * sleep for much longer in this context.
		 */
		while ((c = lfqueue_dequeue(tc->comp_lfq)) == NULL &&
		    dequeue_cnt++ < CCOW_COMP_USER_THROTTLE_MAX * 1000) {
			usleep(1000);
			if ((dequeue_cnt % 250) == 0)
				ccow_replenish_completions(tc, NULL);
		}
	}
	if (!c) {
		err = -ENOSPC;
		log_error(lg, "create compl: out of resources: %d", err);
		return err;
	}

	c->chunkmap_flags = 0;
	c->chunkmap_ctx = NULL;

	uv_mutex_lock(&c->operations_mutex);
	c->wait_count = 0;
	uv_mutex_unlock(&c->operations_mutex);

	assert(c->operations == NULL);

	c->operations = je_calloc(operations_num * 2 + 2, sizeof (void *));
	if (!c->operations) {
		err = lfqueue_enqueue(tc->comp_lfq, c);
		assert(!err);
		return -ENOMEM;
	}

	if (operations_num > 0) {
		c->sop_generation = NULL;
		c->cont_flags = 0;
		c->cont_generation = NULL;
		c->version_vm_content_hash_id = NULL;
		c->operations_done = c->operations + operations_num;
		c->operations_num = operations_num;
		c->operations_end = 0;
		c->needs_final_put = 0;
		c->needs_final_md = 0;
		c->busy_ops = operations_num;
		c->comp_arg = cb_arg;
		c->comp_cb = cb_complete;
		c->tc = tc;
		c->status = 0;
		c->released = 0;
		c->custom_md = NULL;
		c->md_overrides = NULL;
		c->md_overrides_added = 0;
		c->init_op = NULL;
		c->ver_rb = NULL;
		c->ver_name = NULL;
		c->failed = 0;
		c->canceled = 0;
		c->dst_txid_generation = ~0ULL; /* mark as unknown */
		c->was_object_deleted = 0;
		c->file_object_transparency = 0;
		c->object_delete_after = 0;
		c->inline_data_flags = 0;

		// Reset stats
		c->object_count_mod = 0;
		c->object_count = 0;
		c->logical_sz_mod = 0;
		c->logical_sz = 0;
		c->used_sz_mod = 0;
		c->used_sz = 0;

		// Reset sharding index
		c->shard_index = 0;

		/* inherit values from the tenant */
		ccow_copy_inheritable_tc_to_comp(tc, c);
	}

	if (c->chunkmap_type != NULL) {
		je_free(c->chunkmap_type);
		c->chunkmap_type = NULL;
	}

	c->chunkmap_type = je_strdup(tc->chunkmap_type);
	if (!c->chunkmap_type) {
		je_free(c->operations);
		c->operations = NULL;
		err = lfqueue_enqueue(tc->comp_lfq, c);
		assert(!err);
		return -ENOMEM;
	}

	c->cont = 0;
	c->usel = NULL;

	*pcomp = c;
	return 0;
}

#define PROP_INH(_ptr_from, _ptr_to) \
	(_ptr_to)->hash_type = (_ptr_from)->hash_type; \
	(_ptr_to)->compress_type = (_ptr_from)->compress_type; \
	(_ptr_to)->replication_count = (_ptr_from)->replication_count; \
	(_ptr_to)->sync_put = (_ptr_from)->sync_put; \
	(_ptr_to)->select_policy = (_ptr_from)->select_policy; \
	(_ptr_to)->failure_domain = (_ptr_from)->failure_domain; \
	(_ptr_to)->number_of_versions = (_ptr_from)->number_of_versions; \
	(_ptr_to)->chunkmap_chunk_size = (_ptr_from)->chunkmap_chunk_size; \
	(_ptr_to)->chunkmap_btree_order = (_ptr_from)->chunkmap_btree_order; \
	(_ptr_to)->chunkmap_btree_marker = (_ptr_from)->chunkmap_btree_marker; \
	(_ptr_to)->track_statistics = (_ptr_from)->track_statistics; \
	(_ptr_to)->iops_rate_lim = (_ptr_from)->iops_rate_lim; \
	(_ptr_to)->ec_enabled = (_ptr_from)->ec_enabled; \
	(_ptr_to)->ec_data_mode = (_ptr_from)->ec_data_mode; \
	(_ptr_to)->ec_trg_policy = (_ptr_from)->ec_trg_policy; \
	(_ptr_to)->file_object_transparency = (_ptr_from)->file_object_transparency; \
	(_ptr_to)->object_delete_after = (_ptr_from)->object_delete_after; \
	(_ptr_to)->inline_data_flags = (_ptr_from)->inline_data_flags;

int
ccow_copy_inheritable_md(ccow_completion_t comp_in, ccow_completion_t comp_out)
{
	int err = 0;
	struct ccow_completion *c_in = (struct ccow_completion *)comp_in;
	struct ccow_completion *c_out = (struct ccow_completion *)comp_out;
	assert(c_in);
	assert(c_out);

	if (!c_in || !c_out)
		return -EINVAL;

	PROP_INH(c_in, c_out);
	return 0;
}

int
ccow_verify_mdop(ccow_op_t optype, ccow_metadata_kv_t attrs[], uint32_t attr_nr)
{
	/*
	 * For system meta-data only logical size and object counts
	 * can be inserted or deleted from existing value. All other
	 * attributes must have "update" operation.
	 */
	for (uint32_t i = 0; i < attr_nr; i++) {
		if (attrs[i]->mdtype == CCOW_MDTYPE_METADATA &&
		    (optype == CCOW_INSERT_MD || optype == CCOW_DELETE_MD) &&
		    strcmp(attrs[i]->key, RT_SYSKEY_LOGICAL_SIZE) &&
		    strcmp(attrs[i]->key, RT_SYSKEY_OBJECT_COUNT) &&
		    strcmp(attrs[i]->key, RT_SYSKEY_ESTIMATED_USED))
			return -EINVAL;
		if (attrs[i]->mdtype == CCOW_MDTYPE_METADATA &&
		    optype == CCOW_UPDATE_MD &&
		    strcmp(attrs[i]->key, RT_SYSKEY_REPLICATION_COUNT) &&
		    strcmp(attrs[i]->key, RT_SYSKEY_SYNC_PUT) &&
		    strcmp(attrs[i]->key, RT_SYSKEY_SELECT_POLICY) &&
		    strcmp(attrs[i]->key, RT_SYSKEY_NUMBER_OF_VERSIONS) &&
		    strcmp(attrs[i]->key, RT_SYSKEY_COMPRESS_TYPE) &&
		    strcmp(attrs[i]->key, RT_SYSKEY_TRACK_STATISTICS) &&
		    strcmp(attrs[i]->key, RT_SYSKEY_IOPS_RATE_LIM))
			return -EINVAL;
		/* Future - add attr specific validation */
	}
	return 0;
}

void
ccow_copy_inheritable_md_to_comp(struct vmmetadata *md_from,
    struct ccow_completion *comp_to)
{
	PROP_INH(md_from, comp_to);
}

void
ccow_copy_inheritable_comp_to_md(struct ccow_completion *comp_from,
    struct vmmetadata *md_to)
{
	PROP_INH(comp_from, md_to);
}

void
ccow_copy_inheritable_tc_to_comp(struct ccow *tc_from,
    struct ccow_completion *comp_to)
{
	PROP_INH(tc_from, comp_to);
}

void
ccow_copy_inheritable_md_to_tc(struct vmmetadata *md_from, struct ccow *tc_to)
{
	PROP_INH(md_from, tc_to);
}

/*
 * Called by modify_custom(), check for existance of metadata pointed by
 * key/value pair, if it exists modify it in place and return 1, else
 * return 0 and the new metadata entry will be added by ccow_attr_modify_custom
 */
static int
ccow_check_md_entry_and_modify(ccow_completion_t comp,
    const char *key, int key_size, void *value, int val_size, ccow_kvtype_t type)
{
	int err = 0, code = 0, found = -1;
	size_t j = 0;
	struct ccow_completion *c = comp;
	uv_buf_t buf;
	msgpack_p *p = NULL;
	uint32_t key_len;

	if (!c->custom_md || c->custom_md->nbufs == 0) {
		return -ENOENT;
	}

	rtbuf_t *md = c->custom_md;
	if (!md)
		return -ENOENT;
	/* Iterate through the list of existing MD keys until we find the key */
	for (j = 0; j < md->nbufs; j++) {
		msgpack_u *m = msgpack_unpack_init_p(&rtbuf(md, j), 0);
		if (m == NULL) {
			log_error(lg, "Malformed metadata entry.\n");
			return -ENOENT;
		}
		const uint8_t *payload;
		err = msgpack_unpack_raw(m, &payload, &key_len);
		if (err) {
			log_error(lg, "Malformed metadata entry.\n");
			msgpack_unpack_free(m);
			return -ENOENT;
		}
		/* Compare the stored key/key_len to the input key/size. */
		if (memcmp_quick(payload, key_len, key, key_size) == 0) {
			found = j;
			msgpack_unpack_free(m);
			break;
		}
		msgpack_unpack_free(m);
	}
	if (found == -1) {
		log_debug(lg, "key %s not found on update", key);
		return -ENOENT;
	}

	p = msgpack_pack_init();
	if (p == NULL)
		return -ENOMEM;

	if (value != NULL || ((type == CCOW_KVTYPE_RAW) && val_size > 0)) {
		err = ccow_pack_kv(p, key, key_size, value, val_size, type);
		if (err)
			goto _mdexit_free;

		/* Add new key/value pair to the custom_md, will delete. */
		MCHK(err, msgpack_get_buffer(p, &buf), goto _mdexit_free);
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err)
			goto _mdexit_free;
	}

	/* Delete the Entry. */
	err = rtbuf_delete_element(md, found);
	if (err)
		return err;

	msgpack_pack_free(p);
	return 0;

_mdexit_free:
	msgpack_pack_free(p);
	return -ENOMEM;

}


/*
 * Set custom per-completion (means bucket or object) parameter.
 * Incoming fields will have metadata name specified :
 * "X-Account-Meta-name"  where char *key will point to "name"
 * Extendible to deal with containers and objects.
 */
int
ccow_attr_modify_custom(ccow_completion_t comp, ccow_kvtype_t type,
    char *key, int key_size, void *value, int val_size, ccow_lookup_t clp)
{
	int err = 0;
	uint8_t updated = 0;
	struct ccow_completion *c = comp;
	struct ccow_lookup *iter = (struct ccow_lookup *)clp;

	if (!c->custom_md) {
		c->custom_md = rtbuf_init_empty();
	}

	rtbuf_t *md = c->custom_md;

	uv_buf_t buf;
	msgpack_p *p = msgpack_pack_init();
	if (!p)
		return -ENOMEM;

	if (c->vm_txid_generation > 1) {
		if (!strcmp(key, RT_SYSKEY_SYSTEM_GUID)) {
			if (p)
				msgpack_pack_free(p);
			return -EPERM;
		}
	}

	/* Update Case needs to happen before new case, so we dont overpack */

	/* value == NULL is a deletion request */
	err = ccow_check_md_entry_and_modify(comp, key, key_size, value, val_size, type);
	if (err != -ENOENT || (value == NULL && err == -ENOENT)) {
		msgpack_pack_free(p);
		return err;
	}
	/* Pack the key. */
	err = msgpack_pack_raw(p, key, key_size);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}
	switch (type) {
		/* New MD case */
	case CCOW_KVTYPE_RAW:
		err = msgpack_pack_raw(p, value, val_size);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	case CCOW_KVTYPE_STR:
		err = msgpack_pack_str(p, (char *)value);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	case CCOW_KVTYPE_UINT64:
		err = msgpack_pack_uint64(p, *(uint64_t *)value);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	case CCOW_KVTYPE_INT64:
		msgpack_pack_int64(p, *(int64_t *)value);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	case CCOW_KVTYPE_UINT32:
		msgpack_pack_uint32(p, *(uint32_t *)value);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	case CCOW_KVTYPE_INT32:
		msgpack_pack_int32(p, *(int32_t *)value);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	case CCOW_KVTYPE_INT16:
		msgpack_pack_int16(p, *(int16_t *)value);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	case CCOW_KVTYPE_UINT16:
		msgpack_pack_uint16(p, *(uint16_t *)value);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	case CCOW_KVTYPE_UINT8:
		msgpack_pack_uint8(p, *(uint8_t *)value);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	case CCOW_KVTYPE_INT8:
		msgpack_pack_int8(p, *(int8_t *)value);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = msgpack_get_buffer(p, &buf);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		err = rtbuf_add_alloc(md, &buf, 1);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
		break;
	default:
		break;
	}
	if (p)
		msgpack_pack_free(p);

	c->needs_final_put = 1;
	return 0;
}

/*
 * Set md_overrides per-completion (means bucket or object) parameter.
 */
int
ccow_attr_modify_md_overrides(ccow_completion_t comp,
    char *key, uint64_t value)
{
	int err = 0;
	struct ccow_completion *c = comp;

	int key_size = strlen(key);

	msgpack_p *p = msgpack_pack_init();
	if (!p)
		return -ENOMEM;
	if (!c->md_overrides) {
		c->md_overrides = rtbuf_init_empty();
		uint8_t ver = 1;
		msgpack_pack_uint8(p, ver);
		if (err) {
			msgpack_pack_free(p);
			return err;
		}
	}

	rtbuf_t *md = c->md_overrides;
	uv_buf_t buf;

	/* Pack the key. */
	err = msgpack_pack_raw(p, key, key_size);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}

	// Pack the value
	err = msgpack_pack_uint64(p, value);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}
	err = msgpack_get_buffer(p, &buf);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}
	err = rtbuf_add_alloc(md, &buf, 1);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}
	if (p)
		msgpack_pack_free(p);
	return 0;
}

/*
 * Add md overrides to vm payload
 */
rtbuf_t *
ccow_add_md_overrides_to_payload(ccow_completion_t comp, rtbuf_t *payload)
{
	int err = 0;
	struct ccow_completion *c = comp;

	if (!payload) {
		log_error(lg, "invalid payload");
		return NULL;
	}

	// Overrides already present, remove them
	if (rtbuf_is_override(payload)) {
		size_t last = payload->nbufs - 1;
		uv_buf_t last_buf = rtbuf(payload, last);
		uint8_t *base = (uint8_t *)last_buf.base;
		void *marker_start = base + last_buf.len - override_marker_size;
		uint32_t lx;
		memcpy(&lx, marker_start, 4);
		if (lx == 0 || lx >= last_buf.len) {
			log_error(lg, "corrupted payload");
			return NULL;
		}
		void *new_base = (void *)je_realloc(last_buf.base, lx);
		if (new_base == NULL) {
			log_error(lg, "can't reallocate rtbuf");
			return NULL;
		}
		payload->bufs[last].base = new_base;
		payload->bufs[last].len = lx;
	}

	uint32_t override_initial_length = rtbuf_len(payload);
	uint32_t override_content_length = (uint32_t) rtbuf_len(c->md_overrides);
	uint32_t override_num = (uint32_t) c->md_overrides->nbufs;

	err = rtbuf_add_alloc_one(c->md_overrides, override_marker_size);
	if (err) {
		log_error(lg, "can't allocate rtbuf: %d", err);
		return NULL;
	}

	uv_buf_t marker = rtbuf(c->md_overrides, c->md_overrides->nbufs - 1);
	memcpy(marker.base, &override_initial_length, 4);
	memcpy(marker.base+4, &override_content_length, 4);
	memcpy(marker.base+8, &override_num, 4);
	memcpy(marker.base+12, override_marker, sizeof(override_marker));

	size_t nbufs = payload->nbufs + c->md_overrides->nbufs;
	uv_buf_t bufs[nbufs];

	size_t n = 0;
	for (size_t i=0; i < payload->nbufs; i++) {
		bufs[n] = payload->bufs[i];
		n++;
	}
	for (size_t i=0; i < c->md_overrides->nbufs; i++) {
		bufs[n] = c->md_overrides->bufs[i];
		n++;
	}

	uv_buf_t buf;
	err = rtbuf_serialize_bufs(bufs, nbufs, &buf);
	if (err) {
		log_error(lg, "can't serialize buffers: %d", err);
		return NULL;
	}

	rtbuf_free(payload);
	je_free(payload->bufs);

	rtbuf_t *tmp = rtbuf_init(&buf, 1);
	if (!tmp) {
		log_error(lg, "can't allocate buffer: %d", err);
		return NULL;
	}
	payload->bufs = tmp->bufs;
	payload->nbufs = tmp->nbufs;
	payload->attrs = tmp->attrs;
	je_free(tmp);

	// Set md_overrides_added flag
	c->md_overrides_added = 1;
	return payload;
}

/**
 * Edit single md override entry or create one.
 */
int
ccow_edit_md_overrides(rtbuf_t* src_vm, char *key, uint64_t new_value,
	rtbuf_t** tgt_vm)
{
	assert(src_vm->nbufs == 1);
	rtbuf_t* tmp = rtbuf_init(NULL, 3);
	int err = 0;

	uint32_t override_initial_length = src_vm->bufs->len;
	uint32_t override_content_length = 0;
	uint32_t override_num = 0;
	uv_buf_t override = {.len = 0 };
	int key_replaced = 0;
	size_t key_size = strlen(key);
	uv_buf_t resbuf = {.len = 0, .base = 0};
	msgpack_p *p = NULL;

	if (rtbuf_is_override(src_vm)) {
		uv_buf_t marker = rtbuf(src_vm, src_vm->nbufs - 1);


		if (marker.len < override_marker_size) {
			log_error(lg, "Wrong override marker size %lu", override_marker_size);
			return -EINVAL;
		}
		void *marker_start = marker.base + marker.len - override_marker_size;


		memcpy(&override_initial_length, marker_start, 4);
		memcpy(&override_content_length, (uint8_t *)marker_start+4, 4);
		memcpy(&override_num, (uint8_t *)marker_start + 8, 4);

		if (!override_initial_length || !override_content_length || !override_num) {
			log_error(lg, "Corrupted override header");
			return -EINVAL;
		}

		if (marker.len < (override_marker_size + override_content_length)) {
			log_error(lg, "Corrupted override header");
			return -EINVAL;
		}
		override.base = (marker.base +
		    (marker.len - override_marker_size - override_content_length));
		override.len =  override_content_length;
		if (override.len < 8) {
			log_error(lg, "Corrupted override header");
			return -EINVAL;
		}
	}
	/* Copy VM payload */
	rtbuf(tmp, 0).len = override_initial_length;
	rtbuf(tmp, 0).base = je_memdup(rtbuf(src_vm,0).base, override_initial_length);
	if (!rtbuf(tmp, 0).base) {
		err = -ENOMEM;
		goto _exit;
	}

	p = msgpack_pack_init();
	if (!p) {
		err = -ENOMEM;
		goto _exit;
	}

	msgpack_pack_uint8(p, 1);
	if (err) {
		log_error(lg, "Error packing a override version: %d", err);
		goto _exit;
	}

	if (override_num) {
		uint8_t ver;
		msgpack_u u;
		msgpack_unpack_init_b(&u, override.base, override.len, 0);
		err = msgpack_unpack_uint8(&u, &ver);
		if (!err && ver == 1) {
			/* There are some overrides. Copy them over replacing old value */
			for (uint16_t n=0; n<override_num; n++) {
				const uint8_t *data;
				uint64_t value;
				uint32_t nout;
				err = msgpack_unpack_raw(&u, &data, &nout);
				if (err) {
					log_error(lg, "Key unpack error %d", err);
					goto _exit;
				}
				err = msgpack_unpack_uint64(&u, (uint64_t *) &value);
				if (err) {
					log_error(lg, "Value unpack error %d", err);
					goto _exit;
				}
				/* Copying key to the destination */
				err = msgpack_pack_raw(p, data, nout);
				if (err) {
					log_error(lg, "Key pack error %d", err);
					goto _exit;
				}
				/* Replace a value if the key matches */
				if (nout == key_size && !memcmp(data,key,nout)) {
					value = new_value;
					key_replaced = 1;
				}
				/* Pack the value */
				err = msgpack_pack_uint64(p, value);
				if (err) {
					log_error(lg, "Value pack error %d", err);
					goto _exit;
				}
			}
		}
	}

	if (!override_num || !key_replaced) {
		/* No old overrides or the key is new. Append new override */
		err = msgpack_pack_raw(p, key, key_size);
		if (err) {
			log_error(lg, "Error packing a new key %s: %d", key, err);
			goto _exit;
		}
		err = msgpack_pack_uint64(p, new_value);
		if (err) {
			log_error(lg, "Error packing a new value %lu: %d", new_value, err);
			goto _exit;
		}
		override_num++;
	}
	msgpack_get_buffer(p, tmp->bufs + 1);
	tmp->attrs[1] = RTBUF_ATTR_MMAP;
	override_content_length = rtbuf(tmp, 1).len;
	/** Create marker buffer */
	rtbuf(tmp, 2).len = override_marker_size;
	rtbuf(tmp, 2).base = je_malloc(rtbuf(tmp, 2).len);

	uv_buf_t marker = rtbuf(tmp, 2);
	memcpy(marker.base, &override_initial_length, 4);
	memcpy(marker.base+4, &override_content_length, 4);
	memcpy(marker.base+8, &override_num, 4);
	memcpy(marker.base+12, override_marker, sizeof(override_marker));

	err = rtbuf_serialize_bufs(tmp->bufs, tmp->nbufs, &resbuf);
	if (err)
		log_error(lg, "can't serialize buffers: %d", err);

_exit:
	if (err) {
		if (resbuf.base)
			je_free(resbuf.base);
	} else {
		*tgt_vm = rtbuf_init(&resbuf, 1);
	}
	if (p)
		msgpack_pack_free(p);
	rtbuf_destroy(tmp);
	return err;
}

int
ccow_get_default_attribute(ccow_completion_t c, ccow_default_attr_t attr, void* val) {
	int ret = 0;
	switch (attr) {
		case CCOW_ATTR_HASH_TYPE :
			memcpy(val, &c->hash_type, sizeof(c->hash_type));
			break;
		case CCOW_ATTR_FAILURE_DOMAIN :
			memcpy(val, &c->failure_domain, sizeof(c->failure_domain));
			break;
		case CCOW_ATTR_REPLICATION_COUNT :
			memcpy(val, &c->replication_count, sizeof(c->replication_count));
			break;
		case CCOW_ATTR_INLINE_DATA_FLAGS :
			memcpy(val, &c->inline_data_flags, sizeof(c->inline_data_flags));
			break;
		case CCOW_ATTR_TRACK_STATISTICS :
			memcpy(val, &c->track_statistics, sizeof(c->track_statistics));
			break;
		case CCOW_ATTR_IOPS_RATE_LIM :
			memcpy(val, &c->iops_rate_lim, sizeof(c->iops_rate_lim));
			break;
		case CCOW_ATTR_COMPRESS_TYPE :
			memcpy(val, &c->compress_type, sizeof(c->compress_type));
			break;
		case CCOW_ATTR_SYNC_PUT :
			memcpy(val, &c->sync_put, sizeof(c->sync_put));
			break;
		case CCOW_ATTR_SELECT_POLICY :
			memcpy(val, &c->select_policy, sizeof(c->select_policy));
			break;
		case CCOW_ATTR_CHUNKMAP_TYPE :
			strcpy(val, c->chunkmap_type);
			break;
		case CCOW_ATTR_CHUNKMAP_CHUNK_SIZE :
			memcpy(val, &c->chunkmap_chunk_size, sizeof(c->chunkmap_chunk_size));
			break;
		case CCOW_ATTR_BTREE_ORDER :
			memcpy(val, &c->chunkmap_btree_order, sizeof(c->chunkmap_btree_order));
			break;
		case CCOW_ATTR_BTREE_MARKER:
			memcpy(val, &c->chunkmap_btree_marker, sizeof(c->chunkmap_btree_marker));
			break;
		case CCOW_ATTR_NUMBER_OF_VERSIONS :
			memcpy(val, &c->number_of_versions, sizeof(c->number_of_versions));
			break;
		case CCOW_ATTR_EC_ALGORITHM :
			memcpy(val, &c->ec_data_mode, sizeof(c->ec_data_mode));
			break;
		case CCOW_ATTR_EC_ENABLE :
			memcpy(val, &c->ec_enabled, sizeof(c->ec_enabled));
			break;
		case CCOW_ATTR_EC_TRG_POLICY :
			memcpy(val, &c->ec_trg_policy, sizeof(c->ec_trg_policy));
			break;
		case CCOW_ATTR_FILE_OBJECT_TRANSPARANCY :
			memcpy(val, &c->file_object_transparency, sizeof(c->file_object_transparency));
			break;
		case CCOW_ATTR_OBJECT_DELETE_AFTER :
			memcpy(val, &c->object_delete_after, sizeof(c->object_delete_after));
			break;
		case CCOW_ATTR_LOGICAL_SZ :
			memcpy(val, &c->logical_sz, sizeof(c->logical_sz));
			break;
		case CCOW_ATTR_PREV_LOGICAL_SZ :
			memcpy(val, &c->prev_logical_sz, sizeof(c->prev_logical_sz));
			break;
		case CCOW_ATTR_OBJECT_COUNT :
			memcpy(val, &c->object_count, sizeof(c->object_count));
			break;
		case CCOW_ATTR_ESTIMATED_USED :
			memcpy(val, &c->used_sz, sizeof(c->used_sz));
			break;
		default :
			ret = -EINVAL;
			break;
	}
	return ret;
}

int
ccow_attr_modify_default(ccow_completion_t comp, ccow_default_attr_t attr,
    void *value, ccow_lookup_t clp)
{
	int err = 0;
	struct ccow_completion *c = comp;
	struct ccow *tenant = c->tc;

	switch (attr) {
	case CCOW_ATTR_HASH_TYPE :
		c->hash_type = *(uint8_t *)value;
		if (CRYPTO_HASH_TYPE(c->hash_type) >= HASH_TYPE_END) {
			log_error(lg, "hash_type: invalid arugment (%d): %d",
			    err, c->hash_type);
			c->hash_type = tenant->hash_type;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.hash_type = c->hash_type;
		break;
	case CCOW_ATTR_FAILURE_DOMAIN :
		c->failure_domain = *(uint8_t *)value;
		if (c->failure_domain >= FD_END) {
			err = -EINVAL;
			log_error(lg, "failure_domain: invalid arugment (%d): %d",
			    err, c->failure_domain);
			c->failure_domain = tenant->failure_domain;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.failure_domain = c->failure_domain;
		break;
	case CCOW_ATTR_REPLICATION_COUNT :
		c->replication_count = *(uint8_t *)value;
		if (c->replication_count < REPLICAST_REPLICATION_COUNT_MIN ||
		    c->replication_count > REPLICAST_REPLICATION_COUNT_MAX) {
			err = -EINVAL;
			log_error(lg, "replication_count: invalid arugment (%d): %d",
			    err, c->replication_count);
			c->replication_count = tenant->replication_count;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.replication_count = c->replication_count;
		break;
	case CCOW_ATTR_INLINE_DATA_FLAGS :
		c->inline_data_flags = *(uint16_t *)value;
		if (c->cont)
			c->init_op->metadata.inline_data_flags = c->inline_data_flags;
		break;
	case CCOW_ATTR_TRACK_STATISTICS :
		c->track_statistics = *(uint16_t *)value;
		if (c->cont)
			c->init_op->metadata.track_statistics = c->track_statistics;
		break;
	case CCOW_ATTR_IOPS_RATE_LIM :
		c->iops_rate_lim = *(uint32_t *)value;
		if (c->cont)
			c->init_op->metadata.iops_rate_lim = c->iops_rate_lim;
		break;
	case CCOW_ATTR_COMPRESS_TYPE :
		c->compress_type = *(uint8_t *)value;
		if (c->compress_type >= COMPRESSOR_END) {
			err = -EINVAL;
			log_error(lg, "compress_type: invalid arugment (%d): %d",
			    err, c->compress_type);
			c->compress_type = tenant->compress_type;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.compress_type = c->compress_type;
		break;
	case CCOW_ATTR_SYNC_PUT :
		c->sync_put = *(uint8_t *)value;
		if (c->sync_put > REPLICAST_SYNC_PUT_MAX) {
			err = -EINVAL;
			log_error(lg, "sync_put: invalid argument (%d): %d",
			    err, c->sync_put);
			c->sync_put = tenant->sync_put;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.sync_put = c->sync_put;
		break;
	case CCOW_ATTR_SELECT_POLICY :
		c->select_policy = *(uint8_t *)value;
		if (c->select_policy > REPLICAST_SELECT_POLICY_MAX) {
			c->select_policy = tenant->select_policy;
			err = -EINVAL;
			log_error(lg, "select_policy: invalid argument %d", err);
			return err;
		}
		if (c->cont)
			c->init_op->metadata.select_policy = c->select_policy;
		break;
	case CCOW_ATTR_CHUNKMAP_TYPE :
		if (chunkmap_find((char *)value) == NULL) {
			log_error(lg, "chunkmap_type: invalid argument: %d",
			    err);
			err = -EINVAL;
			return err;
		}
		if (c->chunkmap_type != NULL) {
			je_free(c->chunkmap_type);
			c->chunkmap_type = NULL;
		}
		c->chunkmap_type = je_strdup((char *)value);

		if (!c->chunkmap_type)
			return -ENOMEM;

		if (c->cont)
			strcpy(c->init_op->metadata.chunkmap_type, c->chunkmap_type);
		break;
	case CCOW_ATTR_CHUNKMAP_CHUNK_SIZE :
		c->chunkmap_chunk_size = *(uint32_t *)value;
		if (c->chunkmap_chunk_size < REPLICAST_CHUNK_SIZE_MIN ||
		    c->chunkmap_chunk_size > REPLICAST_CHUNK_SIZE_MAX) {
			err = -EINVAL;
			log_error(lg, "chunkmap_chunk_size: invalid "
			    "argument (%d): %d", err, c->chunkmap_chunk_size);
			c->chunkmap_chunk_size = tenant->chunkmap_chunk_size;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.chunkmap_chunk_size = c->chunkmap_chunk_size;
		break;
	case CCOW_ATTR_BTREE_ORDER :
		c->chunkmap_btree_order = *(uint16_t *)value;
		if (c->chunkmap_btree_order < 1 ||
		    c->chunkmap_btree_order >
		    RT_SYSVAL_CHUNKMAP_BTREE_ORDER_MAX) {
			err = -EINVAL;
			log_error(lg, "chunkmap_btree_order: invalid "
			    "argument (%d): %d", err, c->chunkmap_btree_order);
			c->chunkmap_btree_order = tenant->chunkmap_btree_order;
			return err;
		}
		if (c->cont) {
			c->init_op->metadata.chunkmap_btree_order = c->chunkmap_btree_order;
			/* not enough, we also need to recreate btree on init */
			if (c->init_op->txid_generation == 1 && c->init_op->chm_handle) {
				c->init_op->chm->destroy(c->init_op->chm_handle);
				c->init_op->chm_handle = NULL;
				err = c->init_op->chm->create(c->init_op, ccow_vmpack,
				    ccow_cmpack, &c->init_op->chm_handle);
				if (err) {
					log_error(lg, "chunkmap_btree_order: cannot create btree: %d", err);
					c->chunkmap_btree_order = tenant->chunkmap_btree_order;
					return err;
				}
			}
		}
		break;
	case CCOW_ATTR_BTREE_MARKER:
		c->chunkmap_btree_marker = *(uint8_t *)value;
		if ((c->chunkmap_btree_marker != 1) &&
		    (c->chunkmap_btree_marker != 0)) {
			err = -EINVAL;
			log_error(lg, "chunkmap_btree_marker : invalid "
			    "argument (%d): %d", err, c->chunkmap_btree_marker);
			c->chunkmap_btree_marker = 0;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.chunkmap_btree_marker = c->chunkmap_btree_marker;
		break;
	case CCOW_ATTR_NUMBER_OF_VERSIONS :
		c->number_of_versions = *(uint16_t *)value;
		if (c->cont)
			c->init_op->metadata.number_of_versions = c->number_of_versions;
		break;
	case CCOW_ATTR_EC_ALGORITHM :
		c->ec_data_mode = *(uint32_t *)value;
		err = ec_mode_check(c->tc->flexhash, c->tc->failure_domain,
			c->ec_data_mode);
		if (err) {
			log_error(lg, "EC algorithm: invalid arugment (%d): %d",
			    err, c->ec_data_mode);
			c->ec_data_mode = c->tc->ec_data_mode;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.ec_data_mode = c->ec_data_mode;
		break;
	case CCOW_ATTR_EC_ENABLE :
		c->ec_enabled = *(uint8_t *)value;
		if (c->ec_enabled > 1) {
			err = -EINVAL;
			log_error(lg, "EC enable: invalid argument (%d): %d",
			    err, c->ec_enabled);
			c->ec_enabled = c->tc->ec_enabled;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.ec_enabled = c->ec_enabled;
		break;
	case CCOW_ATTR_EC_TRG_POLICY :
		c->ec_trg_policy = *(uint64_t *)value;
		err = ec_check_trg_policy(c->ec_trg_policy);
		if (err) {
			log_error(lg, "EC triggering policy: invalid argument "
				"(%d): %lx", err, c->ec_trg_policy);
			c->ec_trg_policy = c->tc->ec_trg_policy;
			return err;
		}
		if (c->cont)
			c->init_op->metadata.ec_trg_policy = c->ec_trg_policy;
		break;
	case CCOW_ATTR_FILE_OBJECT_TRANSPARANCY :
		c->file_object_transparency = *(uint8_t *)value;

		if (c->cont) {
			c->init_op->metadata.file_object_transparency = c->file_object_transparency;
		}
		break;
	case CCOW_ATTR_OBJECT_DELETE_AFTER :
		c->object_delete_after = *(uint64_t *)value;
		if (c->cont) {
			c->init_op->metadata.object_delete_after = c->object_delete_after;
		}
		break;
	case CCOW_ATTR_LOGICAL_SZ :
		c->logical_sz = *(uint64_t *)value;
		break;
	case CCOW_ATTR_PREV_LOGICAL_SZ :
		c->logical_sz_mod = 1;
		c->prev_logical_sz = *(uint64_t *)value;
		break;
	case CCOW_ATTR_OBJECT_COUNT :
		c->object_count_mod = 1;
		c->object_count = *(uint64_t *)value;
		break;
	case CCOW_ATTR_ESTIMATED_USED :
		c->used_sz_mod = 1;
		c->used_sz = *(uint64_t *)value;
		break;
	default :
		break;
	}

	c->needs_final_put = 1;
	return 0;
}

/*
 *  wait for asyncrhonous operation to finish. The shared part.
 *
 * Scope: PUBLIC
 */
int
ccow_wait_common(ccow_completion_t comp, int index, int timed, uint32_t timeout_ms)
{
	struct ccow_completion *c = comp;
	int ret;
	int delay_count = timeout_ms;

	log_trace(lg, "comp %p, index %d", comp, index);

	/*
	 * if I/O completes faster then this thread is advancing, handle
	 * it gracefully...
	 */
	uv_mutex_lock(&c->operations_mutex);

	if (c->operations_end == 0) {
		uv_mutex_unlock(&c->operations_mutex);
		log_debug(lg, "Completion %p finished unexpectedly", c);
		ccow_release(c);
		return 0;
	}

	if (c->failed) {
		ret = c->status;
		uv_mutex_unlock(&c->operations_mutex);
		log_warn(lg, "Completion %p already failed, don't wait, status = %d", c, ret);
		ccow_release(c);
		return ret;
	}


	if (index == -1) {
		for(uint32_t i = 0; i < c->operations_end; i++) {
			struct ccow_op *op = c->operations[i];

			if (!op)
				continue;

			log_debug(lg, "found : op = %p : i = %d, status = %d", op, i, c->status);

			if (!timed)
				while (!op->completed) {
					op->need_wait = 1;
					c->wait_count++;
					uv_cond_wait(&op->wait_cond,
						&c->operations_mutex);
					c->wait_count--;
				}
			else
				while (!op->completed && delay_count) {
					op->need_wait = 1;
					c->wait_count++;
					uv_cond_timedwait(&op->wait_cond,
						&c->operations_mutex, 1000000LL);
					if (!op->completed)
						delay_count--;
					c->wait_count--;
				}

			if (c->released) {
				ret = c->status;
				uv_mutex_unlock(&c->operations_mutex);
				return ret;
			}
		}
		ret = c->status;
		if (c->busy_ops == 0)
			ccow_release_internal(c, 0);
		uv_mutex_unlock(&c->operations_mutex);
		return !delay_count && timed ? -EBUSY : ret;
	}

	if (index >= (long)c->operations_num) {
		uv_mutex_unlock(&c->operations_mutex);
		log_error(lg, "Wrong operation index %d >= %lu", index,
		    c->operations_num);
		return -EBADF;
	}

	struct ccow_op *op = c->operations[index];
	if (!op) {
		ret = c->status;
		if (c->busy_ops == 0)
			ccow_release_internal(c, 0);
		uv_mutex_unlock(&c->operations_mutex);
		return ret;
	}

	if (!timed)
		while (!op->completed) {
			op->need_wait = 1;
			c->wait_count++;
			uv_cond_wait(&op->wait_cond,
				&c->operations_mutex);
			c->wait_count--;
		}
	else
		while (!op->completed && delay_count) {
			op->need_wait = 1;
			c->wait_count++;
			uv_cond_timedwait(&op->wait_cond,
				&c->operations_mutex, 1000000LL);
			if (!op->completed)
				delay_count--;
			c->wait_count--;
		}

	log_debug(lg, "ccow_wait unblocked now: comp %p op %p, index %d",
	    comp, op, index);
	ret = c->status;
	if (ret == 0 && op->status &&
	    (op->optype == CCOW_INSERT_LIST || op->optype == CCOW_DELETE_LIST))
		ret = op->status;
	if (c->busy_ops == 0)
		ccow_release_internal(c, 0);
	uv_mutex_unlock(&c->operations_mutex);
	return !delay_count && timed ? -EBUSY : ret;
}

/*
 * Wait for asyncrhonous operation to finish
 *
 * Scope: PUBLIC
 */
int
ccow_wait(ccow_completion_t comp, int index)
{
	return ccow_wait_common(comp, index, 0, 0);
}

/*
 * Timed wait for asyncrhonous operation to finish
 *
 * Scope: PUBLIC
 */
int
ccow_timed_wait(ccow_completion_t comp, int index, uint32_t timeout_ms)
{
	return ccow_wait_common(comp, index, 1, timeout_ms);
}

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
int ccow_list_cont_status(ccow_completion_t comp, int index) {
	if (index >= (long)comp->operations_num) {
		return -EINVAL;
	}
	struct ccow_op *op = comp->operations[index];
	if (op == NULL)
		return -EINVAL;
	return op->status;
}

int
ccow_completion_released(ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	return c->released;
}

void
ccow_release_internal(ccow_completion_t comp, int unsafe)
{
	int err;
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	log_trace(lg, "released %ld busy_ops %ld op_end %ld", c->released,
	    c->busy_ops, c->operations_end);

	if (c->released || c->busy_ops) {
		return;
	}

	if (unsafe)
		uv_mutex_lock(&c->operations_mutex);

	/*
	 * Case where operations not yet issued and therefore we can
	 * return completion back to its available queue..
	 */
	if (c->operations_end == 0) {
		if (unsafe)
			uv_mutex_unlock(&c->operations_mutex);
		log_debug(lg, "operations not yet issued: c = %p, destroy comp", c);
		ccow_destroy_completion(c);
		return;
	}

	/*
	 * If some I/O not yet ack'ed mark this completion as "released" but
	 * keep it outside of main completion pool. When all I/O completed
	 * "released" flag will trigger actual resource release..
	 */
	c->released = 1;
	if (unsafe)
		uv_mutex_unlock(&c->operations_mutex);

	log_debug(lg, "queueing to released_lfq : c = %p", c);
	err = lfqueue_enqueue(tc->released_lfq, c);
	assert(!err);
}

/*
 * Release completion
 *
 * Scope: PUBLIC
 */
void
ccow_release(ccow_completion_t comp)
{
	int err;
	struct ccow_completion *c = comp;

	ccow_release_internal(comp, 1);
}

/*
 * Drop completion
 *
 * Scope: PUBLIC
 */
void
ccow_drop(ccow_completion_t comp)
{
	int err;
	struct ccow_completion *c = comp;

	c->busy_ops = 0;
	ccow_release_internal(comp, 1);
}

/*
 * Finalize stream of UNNAMED PUT/GETs
 *
 * Scope: PUBLIC
 */
int
ccow_finalize(ccow_completion_t comp, ccow_lookup_t *li)
{
	int err;
	struct ccow_completion *c = comp;
	if (c == NULL) return -EINVAL;
	if (c->init_op == NULL) return -EINVAL;
	struct ccow_op *op = c->init_op;
	struct ccow *tc = c->tc;

	comp->chunkmap_flags |= CCOW_FINAL;

	log_debug(lg, "===> PutFinalize %lu operations(s) (c = %p)",
	    c->operations_end - 1, c);
	log_hexdump(lg, "CID:", (char *)op->cid, op->cid_size);
	log_hexdump(lg, "TID:", (char *)op->tid, op->tid_size);
	log_hexdump(lg, "BID:", (char *)op->bid, op->bid_size);
	log_hexdump(lg, "OID:", (char *)op->oid, op->oid_size);

	/* cannot be called from tenant's event loop context! */
	nassert(tc->loop_thrid != uv_thread_self());

	uv_mutex_lock(&c->operations_mutex);
	if (op->finalizing) {
		uv_mutex_unlock(&c->operations_mutex);
		return 0;
	}
	op->finalizing = 1;
	/* skip op->namedput_io for failed completion and
	 * other stuff done in ccow_fail_io_notrace()
	 */
	if (c->failed) {
		log_debug(lg, "failed completion = %p, release it", c);
		ccow_operation_destroy(c->init_op, 0);
		ccow_release_internal(c, 0);
		uv_mutex_unlock(&c->operations_mutex);
		return 0;
	}

	uv_mutex_unlock(&c->operations_mutex);

	log_debug(lg, "op = %p", op);
	log_debug(lg, "op->namedget_io = %p", op->namedget_io);
	log_debug(lg, "op->namedput_io = %p", op->namedput_io);

	c->status = 0;
	op->status = 0;

	/*
	 * Set by iterator mod and chunking algorithms in case of if ANY
	 * modification being made. I.e. to MD or VM reflist.
	 */
	if (c->needs_final_put) {
		(*c->cont_generation)++;

		/*
		 * If application requests finalized metadata, set flag
		 */
		if (li)
			c->needs_final_md = 1;
	}

	ccow_io_lock(op->namedput_io);
	ccow_chain_io(op, op->namedput_io);

	/* Note: after the chaining because of namedget_io use in lookup! */
	op->namedput_io->cont_op = op;

	/* force mem barrier for need_wait here as it can be on the different
	 * thread and we do not have lock protecting it here */
	int *need_wait_membar = &op->namedput_io->cont_op->need_wait;
	*(volatile int *)need_wait_membar = 1;

	if (op->busy_cnt == 0) {
		log_debug(lg, "io %p: immediate start namedput_io, status=%d",
		    op->namedput_io, op->status);
		/* reset status to 0 so start io will work on the named put */
		op->status = 0;
		err = ccow_start_io(op->namedput_io);
		if (err) {
			if (c->needs_final_put)
				(*c->cont_generation)--;
			ccow_io_unlock(op->namedput_io);
			return err;
		}
	} else {
		log_debug(lg, "io %p: deferred start namedput_io, status=%d, busy_cnt %ld",
		    op->namedput_io, op->status, op->busy_cnt);
	}
	ccow_io_unlock(op->namedput_io);

	err = ccow_wait(c, 0);
	log_debug(lg, "ccow_wait returned %d", err);

	if (err && c->needs_final_put)
		(*c->cont_generation)--;

	if (err && !c->canceled) {
		return err;
	}

	/*
	 * If user passes lookup iterator, make sure we move responsibility
	 * to free it to the user...
	 */
	if (li) {
		*li = op->iter;
		op->iter = NULL;
	}

	uv_mutex_lock(&c->operations_mutex);
	for (uint32_t i = 1; i < c->operations_end; i++) {
		struct ccow_op *op = c->operations[i];
		if (!op)
			continue;

		ccow_operation_destroy(op, 0);
	}

	/*
	 * Those ops which are not yet created needs to decrement its
	 * reference counting too. Same as in destroy_completion()
	 */
	for (uint32_t i = c->operations_end; i < c->operations_num; i++) {
		if (c->busy_ops == 0)
			break;
		c->busy_ops--;
	}

	ccow_operation_destroy(c->init_op, 0);
	ccow_release_internal(c, 0);
	uv_mutex_unlock(&c->operations_mutex);

	return 0;
}

/*
 * Abort and cancel stream of UNNAMED PUT/GETs
 *
 * Issue NamedPut and fail it with -EINTR. Other then that I/O cancel is
 * essentially finalize()
 *
 * Scope: PUBLIC
 */
int
ccow_cancel(ccow_completion_t comp)
{
	struct ccow_completion *c = comp;

	c->canceled = 1;
	return ccow_finalize(c, NULL);
}

/*
 * Create operation
 *
 * Scope: PRIVATE
 */
int
ccow_operation_create(struct ccow_completion *c, ccow_op_t optype,
        struct ccow_op **pop)
{
	return ccow_operation_create_cont(c, optype, pop, NULL);
}

int
ccow_operation_create_cont(struct ccow_completion *c, ccow_op_t optype,
    struct ccow_op **pop, int *index)
{
	int err;
	struct ccow_op *op;
	struct ccow *tc = c->tc;
	log_trace(lg, "c %p, %s, pop %p: operations_end %lu", c,
	    ccow_op2str(optype), pop, c->operations_end);

	/* cannot be called from tenant's event loop context when blocking
	 * I/O is requested, i.e. no async callback set */
#ifndef NEDGE_NDEBUG
	if (c->comp_cb == NULL)
		assert(tc->loop_thrid != uv_thread_self());
#endif

	op = je_calloc(1, sizeof (struct ccow_op));
	if (!op) {
		err = -ENOMEM;
		log_error(lg, "op create alloc error: out of memory: %d", err);
		return err;
	}

	op->comp = c;
	op->chm = NULL;
	op->optype = optype;
	if (c->init_op) {
		op->name_hash_id = c->init_op->name_hash_id;
		op->txid_generation = c->init_op->txid_generation;
	}
	QUEUE_INIT(&op->isgw_srv_list);
	assert(tc->cmcache != NULL);

	op->op_cmcache = tc->cmcache;
	uv_cond_init(&op->wait_cond);

	assert(op->status == 0);

	/*
	 * While event loop is protected, application can call us from
	 * different threads. We have to protect operations array.
	 */
	uv_mutex_lock(&c->operations_mutex);
	op->index = c->operations_end++;
	if (index != NULL)
		*index = op->index;
	c->operations[op->index] = op;
	uv_mutex_unlock(&c->operations_mutex);

	*pop = op;
	return 0;
}

/*
 * Destroy operation
 *
 * Scope: PRIVATE
 */
void
ccow_operation_destroy(struct ccow_op *op, int unsafe)
{
	struct ccow_completion *c = op->comp;
	struct ccow *tc = c->tc;

	log_trace(lg, "op %p (%s): busy_ops %lu, c %p",
		op, ccow_op2str(op->optype),
	    c->busy_ops, c);

	if (unsafe)
		uv_mutex_lock(&c->operations_mutex);

	assert(c->busy_ops <= c->operations_num);
	if (c->busy_ops > 0)
		c->busy_ops--;

	op->completed = 1;
	if (op != c->init_op && c->comp_cb == NULL &&
	    (tc->loop_thrid == uv_thread_self() || op->need_wait)) {
		log_debug(lg, "sending signal to ccow_wait");
		uv_cond_signal(&op->wait_cond);
	}

	if (c->operations == NULL) {
		if (unsafe)
			uv_mutex_unlock(&c->operations_mutex);
		return;
	}

	c->operations[op->index] = NULL;
	c->operations_done[op->index] = op;

	if (op->chunks) {
		rtbuf_destroy(op->chunks);
		op->chunks = NULL;
	}
	while (!QUEUE_EMPTY(&op->isgw_srv_list)) {
		QUEUE *q = QUEUE_HEAD(&op->isgw_srv_list);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		struct iswg_addr_item* e = QUEUE_DATA(q, struct iswg_addr_item, item);
		je_free(e);
	}

	if (unsafe)
		uv_mutex_unlock(&c->operations_mutex);
}

static void
ccow_operation_free(struct ccow_op *op)
{
	struct ccow_completion *c = op->comp;
	struct ccow *tc = c->tc;

	log_trace(lg, "op %p (%s): busy_ops %lu, c %p",
		op, ccow_op2str(op->optype),
	    c->busy_ops, c);

	/* For some PUT operations op->iter internally used, so free it */
	if (op->optype == CCOW_CLONE || op->optype == CCOW_PUT ||
	    op->optype == CCOW_INSERT_LIST || op->optype == CCOW_DELETE_LIST ||
	    op->optype == CCOW_INSERT_LIST_WITH_MD ||
	    op->optype == CCOW_DELETE_LIST_WITH_MD ||
	    op->optype == CCOW_CONT) {
		if (op->iter) {
			ccow_lookup_release(op->iter);
			op->iter = NULL;
		}
	}

	if (op->chm_handle)
		op->chm->destroy(op->chm_handle);

	if (op->chids)
		je_free(op->chids);

	if (op->vm_reflist)
		rtbuf_destroy(op->vm_reflist);

	if (op->copy_opts)
		je_free(op->copy_opts);

	if (op->cid)
		je_free(op->cid);
	if (op->tid)
		je_free(op->tid);
	if (op->bid)
		je_free(op->bid);
	if (op->oid)
		je_free(op->oid);

	uv_cond_destroy(&op->wait_cond);
	je_free(op);
}

/*
 * Construct I/O object
 *
 * Scope: PRIVATE
 */
int
ccow_create_io(struct ccow_completion *c, struct ccow_op *op, ccow_op_t optype,
    const struct transition *trans_tbl, int trans_max, void *data,
    state_term_t term_cb, struct ccow_io **pio)
{
	struct ccow *tc = c->tc;
	log_trace(lg, "c %p, op %p (%s), trans_tbl %p, "
	    "trans_max %d, data %p, term_cb %p, pio %p",
		c, op, ccow_op2str(optype),
	    trans_tbl, trans_max, data, term_cb, pio);

	struct ccow_io *io;
	if (tc->loop_thrid == uv_thread_self()) {
		io = lfqueue_dequeue(tc->ios_lfq);
	} else {
		/*
		 * Throttle I/O flow if we in user thread context.
		 */
		int dequeue_fail_cnt = 0;
		while ((io = lfqueue_dequeue(tc->ios_lfq)) == NULL &&
		    dequeue_fail_cnt++ < CCOW_IO_USER_THROTTLE_MAX * 1000) {
			usleep(1000);
			if ((dequeue_fail_cnt % 1000) == 0)
				ccow_replenish_completions(tc, NULL);
		}
	}
	if (!io) {
		log_error(lg, "create io: out of resources: -ENOSPC");
		return -ENOSPC;
	}
	io->op = op;
	io->cont_op = NULL;
	io->optype = optype;
	io->comp = c;
	io->parent_io = NULL;
	io->next = NULL;
	io->attributes = 0;
	io->parallel_io = 0;
	io->started = 0;
	io->done = 0;
	io->network_payload_len = 0;

	/* make sure io->state can be converted to ccow_io */
	assert((void *)io == (void *)&io->state);

	memset(&io->state, 0, sizeof (io->state));
	io->state.table = trans_tbl;
	io->state.cur = ST_UNUSED;
	io->state.max = trans_max;
	io->state.term_cb = term_cb;
	io->state.data = data;
	io->state.io = io;

	QUEUE_INIT(&io->p_queue);
	QUEUE_INIT(&io->p_busy_queue);
	QUEUE_INIT(&io->p_item);
	QUEUE_INIT(&io->inprog_item);
	QUEUE_INIT(&io->pio_queue);
	QUEUE_INIT(&io->pio_item);

	io->rmw_ctx = NULL;
	*pio = io;
	return 0;
}

/*
 * Destruct I/O object
 */
void
ccow_destroy_io(struct ccow_io *io)
{
	int err;
	struct ccow_completion *c = io->comp;
	struct ccow *tc = c->tc;

	log_trace(lg, "io %p", io);

	assert(io->state.cur == ST_UNUSED || io->state.cur == ST_TERM);

	QUEUE *q;
	struct ccow_io *parallel_io;

	ccow_io_lock(io);
	while (!QUEUE_EMPTY(&io->p_queue)) {
		q = QUEUE_HEAD(&io->p_queue);
		ccow_io_unlock(io);

		parallel_io = QUEUE_DATA(q, struct ccow_io, p_item);
		log_debug(lg, "q = %p : parallel_io = %p", q, parallel_io);
		ccow_destroy_io(parallel_io);

		ccow_io_lock(io);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
	}
	ccow_io_unlock(io);

	je_free(io->state.data);
	io->state.data = NULL;

	err = lfqueue_enqueue(tc->ios_lfq, io);
	assert(!err);
}

int
ccow_fail_io_warn_level(struct ccow_io *fail_io, int err)
{
	return (
	    (fail_io->comp->canceled) ||
	    (fail_io->optype == CCOW_INSERT_LIST_CONT ||
	     fail_io->optype == CCOW_DELETE_LIST_CONT ||
	     fail_io->optype == CCOW_INSERT_LIST ||
	     fail_io->optype == CCOW_INSERT_MD ||
	     fail_io->optype == CCOW_INSERT_LIST_WITH_MD ||
	     fail_io->optype == CCOW_GET_LIST ||
	     fail_io->optype == CCOW_RING ||
	     fail_io->optype == CCOW_DELETE_LIST ||
	     fail_io->optype == CCOW_DELETE_LIST_WITH_MD ||
	     fail_io->optype == CCOW_DELETE_MD) ||
	   (fail_io->optype == CCOW_GET && err == -ENOENT) ||
	   ((fail_io->op->cid && *fail_io->op->cid == 0) &&
	    (fail_io->op->tid && *fail_io->op->tid == 0) &&
	    (fail_io->op->bid && *fail_io->op->bid == 0) &&
	    (fail_io->op->oid && *fail_io->op->oid == 0)) ||
	   (fail_io->optype == CCOW_PUT && (fail_io->attributes & RD_ATTR_NO_OVERWRITE)) ||
	   ((fail_io->op->cid && *fail_io->op->cid != 0) &&
	    (err == -ENOENT || err == -EEXIST || err == -EINTR || err == -ENOSPC))) ||
	    (fail_io->optype == CCOW_PUT && (fail_io->attributes & RD_ATTR_RETRY_FAILFAST));
}

/*
 * Mark I/O as failed. This will also mark corresponding operation as failed.
 * Eventually I/O needs to be completed and pipe-line will not proceed with
 * the next I/O..
 *
 * Scope: PRIVATE
 */
void
ccow_fail_io_notrace(struct ccow_io *fail_io, int err)
{
	struct ccow_completion *c = fail_io->comp;
	struct ccow *tc = c->tc;

	log_trace(lg, "fail_io %p err %d\n", fail_io, err);

	/*
	 * Do failing job only once!
	 */
	if (fail_io->attributes & RD_ATTR_SERIAL_OP && err == -EWOULDBLOCK)
		return;

	uv_mutex_lock(&c->operations_mutex);
	if (c->failed != 0) {
		uv_mutex_unlock(&c->operations_mutex);
		return;
	}
	else
		c->failed = 1;

	c->status = fail_io->op->status = err;

	if (c->comp_cb && !fail_io->op->completed) {
		fail_io->op->completed = 1;
		uv_cond_signal(&fail_io->op->wait_cond);
		uv_mutex_unlock(&c->operations_mutex);
		c->comp_cb(c, c->comp_arg, fail_io->cont_op ?
				fail_io->cont_op->index : fail_io->op->index,
				fail_io->op->status);
	} else
		uv_mutex_unlock(&c->operations_mutex);

	ccow_io_lock(fail_io);
	if (fail_io->parent_io) {
		struct ccow_io *parent_io = fail_io->parent_io;

		QUEUE *q;
		struct ccow_io *io;

		while (!QUEUE_EMPTY(&parent_io->p_queue)) {
			q = QUEUE_HEAD(&parent_io->p_queue);
			ccow_io_unlock(fail_io);

			io = QUEUE_DATA(q, struct ccow_io, p_item);
			log_debug(lg, "q = %p : io =  %p", q, io);
			if (c->comp_cb) {
				c->comp_cb(c, c->comp_arg, io->cont_op ?
						io->cont_op->index : io->op->index,
						err);
			}
			ccow_destroy_io(io);

			ccow_io_lock(fail_io);
			QUEUE_REMOVE(q);
			QUEUE_INIT(q);
		}

		/*
		 * Let busy I/Os to fail gracefully on next event, which most
		 * likely will be retry or timeout.
		 */
		q = NULL;
		QUEUE_FOREACH(q, &parent_io->p_busy_queue) {
			io = QUEUE_DATA(q, struct ccow_io, p_item);
			state_next(&io->state, EV_ERR);
		}

		/*
		 * We need to traverse all chained_io starting from parent and
		 * cancel all outstanding ones.
		 */
		fail_io = parent_io;
	}

	struct ccow_io *io = fail_io->next;
	while (io) {
		if (err == -ENOENT || err == -EEXIST || err == -EINTR|| err == -ENOSPC)
			log_warn(lg, "failing I/O %p (%s) error %d", io,
			    ccow_op2str(io->optype), err);
		else
			log_error(lg, "failing I/O %p (%s) error %d", io,
			    ccow_op2str(io->optype), err);
		if (c->comp_cb) {
			ccow_io_unlock(fail_io);
			c->comp_cb(c, c->comp_arg, io->cont_op ?
					io->cont_op->index : io->op->index, err);
			ccow_io_lock(fail_io);
		}
		struct ccow_io *tmpio = io;
		io = io->next;
		ccow_io_unlock(fail_io);

		if (tc->io_rate)
			tc->io_rate--;

		ccow_destroy_io(tmpio);

		ccow_io_lock(fail_io);
	}

	/* this is to terminate in complete */
	fail_io->next = NULL;

	ccow_io_unlock(fail_io);

	uv_mutex_lock(&c->operations_mutex);

	/*
	 * Mark all but this operations in flight as destroyed.
	 */
	log_debug(lg, "marking in-flight operations as destroyed.");

	for (uint32_t i = 0; i < c->operations_end; i++) {
		struct ccow_op *op = c->operations[i];

		log_debug(lg, "i = %d : operations_end = %lu : op = %p : "
		    " fail_io->op = %p (%s)",
			i, c->operations_end, op,
		    fail_io->op, ccow_op2str(fail_io->op->optype));

		if (!op || op == fail_io->op)
			continue;

		ccow_operation_destroy(op, 0);
	}

	/*
	 * Those ops which are not yet created needs to decrement its
	 * reference counting too.
	 */
	for (uint32_t i = c->operations_end; i < c->operations_num; i++) {
		if (c->busy_ops == 0)
			break;
		c->busy_ops--;
	}
	assert(c->busy_ops <= c->operations_num);

	uv_mutex_unlock(&c->operations_mutex);
}

/*
 * Complete an outstainding I/O
 *
 * Scope: PRIVATE
 */
int
ccow_complete_io(struct ccow_io *done_io)
{
	int err;
	struct ccow_completion *c = done_io->comp;
	struct ccow *tc = c->tc;
	struct ccow_op *op = done_io->op;
	struct ccow_io *io = done_io;

	log_trace(lg, "done_io %p: busy_ops %lu, busy_cnt %lu, io_rate %d, "
	    "parent_io %p, next_io %p op %p (%s)", done_io, c->busy_ops,
	    op->busy_cnt, tc->io_rate, done_io->parent_io,
	    done_io->parent_io ? done_io->parent_io->next : done_io->next,
	    op, ccow_op2str(op->optype));

	nassert(tc->loop_thrid == uv_thread_self());
	assert(done_io->state.cur == ST_TERM);

	uint64_t stop_timestamp = get_timestamp_us();
	/*
	 *	Calculate latency of this IO based on 4KB normalization
	 */
	uint64_t total_data = io->network_payload_len;

	if (total_data >= 4096)
		io->latency =
		(stop_timestamp - io->start_timestamp) / (total_data / 4096);
	/*
	 * Update the running average
	 */
	uint64_t avg_put_latency = 0, avg_get_latency = 0;
	if (total_data && !(io->attributes & RD_ATTR_LOGICAL_DELETE)) {
		if (io->optype == CCOW_PUT || io->optype == CCOW_PUT_CONT) {
			tc->put_bw_cnt += total_data;
			tc->put_iops_cnt++;
			if (total_data >= 4096)
				tc->avg_put_latency =
					avg_ring_update(&tc->avg_put_lat_ring, io->latency);
		} else if (io->optype == CCOW_GET || io->optype == CCOW_GET_CONT) {
			tc->get_bw_cnt += total_data;
			tc->get_iops_cnt++;
			if (total_data >= 4096)
				tc->avg_get_latency =
					avg_ring_update(&tc->avg_get_lat_ring, io->latency);
		}
		if (stop_timestamp > tc->stats_refresh_timer) {
			tc->stats_refresh_timer += 5000000;
			tc->get_iops = tc->get_iops_cnt / 5;
			tc->put_iops = tc->put_iops_cnt / 5;
			tc->put_bw = tc->put_bw_cnt / 5;
			tc->get_bw = tc->get_bw_cnt / 5;
			log_debug(lg, "tc->avg_putlancy = %lu, %lu : %lu, iops: %lu latency: %lu bw: %lu",
			    tc->avg_put_latency, stop_timestamp, tc->stats_refresh_timer,
			    tc->put_iops_cnt, io->latency, tc->put_bw_cnt);
			log_debug(lg, "tc->avg_getlancy = %lu, %lu : %lu, iops: %lu latency: %lu bw: %lu",
			    tc->avg_get_latency, stop_timestamp, tc->stats_refresh_timer,
			    tc->get_iops_cnt, io->latency, tc->get_bw_cnt);
			tc->get_iops_cnt = 0;
			tc->put_iops_cnt = 0;
			tc->get_bw_cnt = 0;
			tc->put_bw_cnt = 0;
		}
	}
	/*
	 * Remove it from inprog I/Os list
	 */
	QUEUE_REMOVE(&done_io->inprog_item);
	QUEUE_INIT(&done_io->inprog_item);

	/*
	 * Move I/O to done queue
	 */
	err = lfqueue_enqueue(c->done_lfq, done_io);
	assert(!err);

	if (tc->io_rate)
		tc->io_rate--;

	ccow_io_lock(done_io);

	assert(op->busy_cnt >= 1);
	atomic_dec(&op->busy_cnt);
	int op_completed = op->busy_cnt == 0;

	log_debug(lg, "op_completed = %d : op->busy_cnt = %lu, c->status %d",
	    op_completed, op->busy_cnt, c->status);

	/*
	 * nameget_io is re-used as special pointer that links groups of parallel
	 * get_cont to the next (put_cont) io in the chain. So if such io has been
	 * completed clean namedget_io->next that was pointing to this io
	 * (for further reuse of nameget_io)
	 */
	if (op->namedget_io && done_io == op->namedget_io->next) {
		op->namedget_io->next = NULL;
	}
	done_io->done = 1;
	if (done_io->parent_io) {
		/*
		 * Parallel I/O completion processing.
		 *
		 * This is the completion of a parallel io, we just need to remove
		 * it from the queue and wait for the next completion.
		 */

		QUEUE_REMOVE(&done_io->p_item);
		QUEUE_INIT(&done_io->p_item);

		struct ccow_io *parent_io = done_io->parent_io;

		/*
		 * This is the last IO in a parallel queue, start the next IO
		 * n the chain, which is held by the parent IO's next pointer.
		 * NOTE:  Potential optimization by driving the whole parallel
		 * queue directly from the completion of the previous chained
		 * I/O rather than driving it serially from the completion of
		 * the parent I/O.
		 */
		if (QUEUE_EMPTY(&parent_io->p_busy_queue) &&
		    QUEUE_EMPTY(&parent_io->p_queue)) {

			/* For Cont I/O we need to finalize parent's FSM */
			if (op->optype == CCOW_CONT) {
				if (state_check(&parent_io->state, ST_TERM) &&
				    !done_io->next && op_completed) {
					if (!parent_io->next) {
						ccow_io_unlock(done_io);
						goto _emerg_exit;
					}
					/* if parent still has something -
					 * complete first, fall-through.. */
				} else {
					ccow_io_unlock(done_io);
					state_event(&parent_io->state, EV_DONE);
					return 0;
				}
			}

			/* For Normal I/O need to check parent's chain */
			done_io->next = parent_io->next;
		} else {
			while (!QUEUE_EMPTY(&parent_io->p_queue)) {
				QUEUE *q = QUEUE_HEAD(&parent_io->p_queue);
				struct ccow_io *io = QUEUE_DATA(q, struct ccow_io, p_item);
				log_debug(lg, "q = %p : io = %p", q, io);

				log_debug(lg, "starting io %p (%s)", io, ccow_op2str(io->op->optype));

				err = ccow_start_io(io);
				if (err) {
					ccow_io_unlock(done_io);
					if (err != -ENOENT)
						log_error(lg, "start io p_queue error: %d", err);
					ccow_fail_io(io, err);
					goto _emerg_exit;
				}

				QUEUE_REMOVE(q);
				QUEUE_INIT(q);
				QUEUE_INSERT_TAIL(&parent_io->p_busy_queue, &io->p_item);
			}

			/* Wait for MORE parallel I/Os to complete... */
			ccow_io_unlock(done_io);
			return 0;
		}

	} else if (!QUEUE_EMPTY(&done_io->p_queue)) {
		/*
		 * Initial parallel I/O scheduling for chained I/Os.
		 *
		 * This is the completion of a std I/O.
		 * Start any requested parallel I/Os if present:
		 */

		log_debug(lg, "HERE : done_io = %p : empty = %d ",
		    done_io, QUEUE_EMPTY(&done_io->p_queue));

		while (!QUEUE_EMPTY(&done_io->p_queue)) {
			QUEUE *q = QUEUE_HEAD(&done_io->p_queue);
			struct ccow_io *io = QUEUE_DATA(q, struct ccow_io, p_item);
			log_debug(lg, "q = %p : io = %p", q, io);

			log_debug(lg, "starting io %p (%s)", io, ccow_op2str(io->op->optype));

			err = ccow_start_io(io);
			if (err) {
				ccow_io_unlock(done_io);
				log_error(lg, "start io initial error: %d", err);
				ccow_fail_io(io, err);
				goto _emerg_exit;
			}

			QUEUE_REMOVE(q);
			QUEUE_INIT(q);
			QUEUE_INSERT_TAIL(&done_io->p_busy_queue, &io->p_item);
		}

		/* Wait for parallel I/Os to complete... */
		ccow_io_unlock(done_io);
		return 0;
	}

	/*
	 * Starting next chained I/O if any
	 *
	 * If there are any additional IOs to be started, do so.
	 */
	if (done_io->next && op_completed) {
		log_debug(lg, "starting done_io->next %p", done_io->next);
		/* namedget_io is special "link" io that shouldn't be run in the
		 * middle of completion. If done_io->next points to namedget_io
		 * than replace it with the io following after namedget_io
		 * if there is nothing after it than all outstanding io were done
		 */
		if (done_io->next == op->namedget_io) {
			if (op->namedget_io->next) {
				done_io->next = op->namedget_io->next;
				op->namedget_io->next = NULL;
			}
			else {
				ccow_io_unlock(done_io);
				goto _emerg_exit;
			}
		}
		if (done_io->next->optype == CCOW_GET_CONT) {
			if (!done_io->next->next) {
				/* keep tail_io pointing to namedget_io
				 * if chain ended with get_cont*/
				op->namedget_io->next = NULL;
				done_io->next->next = op->namedget_io;
				op->tail_io = op->namedget_io;
			}
			/* there we start parallel get_cont from the chain */
			done_io->next->parallel_io = 1;
			err = ccow_start_io(done_io->next);

			QUEUE *q;
			/* pio_queue contains linked list of get_cont io that
			 * should be run in parallel with done_io->next. Iterate over
			 * it and start */
			QUEUE_FOREACH(q, &done_io->next->pio_queue) {

				struct ccow_io *io = QUEUE_DATA(q, struct ccow_io, pio_item);

				log_debug(lg, "q = %p : io = %p", q, io);
				log_debug(lg, "starting parallel io %p (%s)",
						io, ccow_op2str(io->op->optype));

				io->parallel_io = 1;
				if (done_io->next->next) {
					io->next = done_io->next->next;
				}
				else {
					io->next = op->namedget_io;
					op->tail_io = op->namedget_io;
				}
				err = ccow_start_io(io);
				if (err) {
					log_error(lg, "start io initial error: %d", err);
					ccow_fail_io(io, err);
					ccow_io_unlock(done_io);
					goto _emerg_exit;
				}
			}
		}
		else {
			err = ccow_start_io(done_io->next);
		}
		ccow_io_unlock(done_io);

		if (err && err != -EEXIST) {
			log_error(lg, "start io error: %d", err);
			ccow_fail_io(done_io->next, err);
			goto _emerg_exit;
		}

		if (op->optype != CCOW_CONT) {
			/* Wait for next chained I/Os to complete... */
			return 0;
		}
		log_debug(lg, "completing CONT I/O %p", done_io);
		goto _emerg_exit;
	}

	ccow_io_unlock(done_io);

_emerg_exit:
	if (op_completed || done_io->parallel_io) {
		struct ccow_op *cont_op = done_io->cont_op;

		log_debug(lg, "operation is completed %s cont_op %p",
		    ccow_op2str(op->optype), cont_op);

		/*
		 * Notify caller on completion
		 */
		log_debug(lg, "<==== ccow_complete_io %d \n", cont_op ? cont_op->index :
			    op->index);
		uv_mutex_lock(&c->operations_mutex);
		if (c->comp_cb) {
			if (c->released && !op->status)
				op->status = -ECANCELED;
			struct ccow_op *cb_op = cont_op ? cont_op : op;
			if (!cb_op->completed) {
				uv_mutex_unlock(&c->operations_mutex);
				c->comp_cb(c, c->comp_arg, cb_op->index, op->status);
				uv_mutex_lock(&c->operations_mutex);
			}
		}

		if (op->optype != CCOW_CONT) {
			ccow_operation_destroy(op, 0);

			if (c->busy_ops == 0 && c->comp_cb)
				ccow_release_internal(c, 0);
		} else {
			/*
			 * Do not destroy CONT operation, keep it running.
			 * However, cleanup compressed cont_op->chunks.
			 */

			if (cont_op != NULL &&
			    (c->comp_cb == NULL || cont_op->need_wait)) {
				log_debug(lg, "cont_op = %p (%s): c->comp_cb = %p "
				    ": cont_op->need_wait = %d", cont_op, ccow_op2str(cont_op->optype),
				    c->comp_cb, cont_op->need_wait);
				cont_op->completed = 1;
				uv_cond_signal(&cont_op->wait_cond);
			} else if (cont_op == NULL) {
				/* index 0 op always waits */
				log_debug(lg, "cont_op = %p : op->completed = 1",
				    cont_op);
				op->completed = 1;
				uv_cond_signal(&op->wait_cond);
			} else {
				cont_op->completed = 1;
				log_debug(lg, "cont_op = %p (%s)", cont_op, ccow_op2str(cont_op->optype));
			}
			if (cont_op && cont_op->optype == CCOW_PUT_CONT &&
			    cont_op->index > 0 && cont_op->chunks) {
				rtbuf_destroy(cont_op->chunks);
				cont_op->chunks = NULL;
			}
		}
		uv_mutex_unlock(&c->operations_mutex);

		/*
		 * Move some i/o resources back to main pool for this
		 * completed operation only.
		 *
		 * TODO: find a way to avoid double enqueue... performance!
		 */
		struct ccow_io *io;
		while ((io = lfqueue_dequeue(c->done_lfq)) != NULL) {
			if ((cont_op && io->cont_op == cont_op) || io->op == op)
				ccow_destroy_io(io);
			else {
				err = lfqueue_enqueue(c->done_lfq, io);
				assert(!err);
			}
		}

		ccow_replenish_completions(tc, c);
	}

	return 0;
}

/*
 * Start an I/O previously created with ccow_create_io()
 *
 * Scope: PRIVATE
 */
int
ccow_start_io(struct ccow_io *io)
{
	struct ccow_completion *c = io->comp;
	struct ccow *tc = c->tc;

	struct ccow_op *op = io->op;

	log_trace(lg, "io %p op %p (%s) status %d", io, op, ccow_op2str(op->optype),
	    op->status);

	if (!io->started)
		/* note check and set isn't atomic
		 * and needs protection at upper level */
		io->started = 1;
	else
		return -EEXIST;
	if (op->status != 0) {
		return op->status;
	}

	/* Modify iov mapped to ma_bufs for write part of read-modify-write
	 * Note: we assume all reads were completed before any write starts
	 */
	if (io->optype == CCOW_PUT_CONT && io->rmw_ctx && io->rmw_ctx->ma_bufs) {
		struct ccow_rmw_context *ch_ctx = io->rmw_ctx;
		log_trace(lg, "rmv, index %i \n", io->cont_op->index);
		if (ch_ctx->l0 > 0) {
			memcpy(&ch_ctx->ma_bufs[0] + ch_ctx->s0, ch_ctx->buf, ch_ctx->l0);
		}
		if (ch_ctx->l2 > 0) {
			memcpy(&ch_ctx->ma_bufs[op->metadata.chunkmap_chunk_size],
					ch_ctx->buf + ch_ctx->l0 + ch_ctx->l1, ch_ctx->l2);
		}
	}
//	if (op->optype == CCOW_CONT && op->namedput_io != io && c->canceled)
//		return -EINTR;

	/*
	 * Start the per-io timer for gateway statistics, this will be aggr and
	 * forwarded through to the NP every TIMER seconds (5s) and then sent
	 * from each device as a vdev stat for GET and PUT
	 * TODO: define TIMER
	 */
	io->start_timestamp = get_timestamp_us();

	io->state.cur = ST_INIT;

	/*
	 * API LFQ as deep as IO, so we must always succeed in scheduling it
	 */
	atomic_inc(&op->busy_cnt);

	int err = 0;
	if (io->optype == CCOW_RING)
		err = lfqueue_enqueue(tc->api_lfq_hp, &io->state);
	else
		err = lfqueue_enqueue(tc->api_lfq, &io->state);
	assert(err == 0);

	uv_async_send(&tc->api_call);

	return 0;
}

/*
 * Serially chain I/O with the next in order
 *
 * Scope: PRIVATE
 */
void
ccow_chain_io(struct ccow_op *op, struct ccow_io *io)
{
	struct ccow_io *cur_io = NULL;
	assert(io);

	log_trace(lg, "op %p (%s), io %p", op, ccow_op2str(op->optype), io);

	/* Namedput could be NULL for the Get cases */

	cur_io = (op->tail_io == NULL) ? op->namedget_io : op->tail_io;
	assert(cur_io != NULL);
	log_debug(lg, "op->namedget_io %p, op->tail_io %p, cur_io->next_io %p, "
			"cur_io->parallel_io %i, cur_io->done %i", op->namedget_io,
			op->tail_io, cur_io->next, cur_io->parallel_io, cur_io->done);

	struct ccow_io *tmp = cur_io->next;

	/*
	 *
	 */
	if (io->optype == CCOW_GET_CONT) {
		if (((cur_io->parallel_io || cur_io->done)
					&& !cur_io->next) || cur_io == op->namedget_io) {
			/*
			 * nothing has been put in the next io chain, so all that's
			 * been posted are gets. Start the i/o now.
			 */
			if (cur_io == op->namedget_io)
				op->namedget_io->next = NULL;
			assert(cur_io->next == NULL);
			io->parallel_io = 1;
			io->next = op->namedget_io;
			op->tail_io = op->namedget_io;
			log_debug(lg, "new io %p set to run as parallel get_cont "
					"to current io %p, op %p (%s)",
					io, cur_io, io->op, ccow_op2str(io->optype));

		}
		else if (!cur_io->next && op->tail_io->optype == CCOW_GET_CONT) {
			/*
			 * The last i/o in the chain is get. Schedule current get
			 * to be done in parallel with it. (Add to the pio_queue).
			 */

			QUEUE_INSERT_TAIL(&op->tail_io->pio_queue, &io->pio_item);
			log_debug(lg, "new io %p chained as parallel get_cont to %p", io, cur_io);
		}
		else {
			/*
			 * add get to the next io chain.
			 */
			cur_io->next = io;
			io->next = tmp;
			op->tail_io = io;

			log_debug(lg, "new io %p chained after %p", io, cur_io);
		}
	} else {
		/*
		 * add this io to the next io chain.
		 */
		cur_io->next = io;
		io->next = tmp;
		op->tail_io = io;

		log_debug(lg, "new io %p chained after %p", io, cur_io);
	}
}

/*
 * Add an io to be executed in parallel with the parent io's p_queue
 *
 * Scope: PRIVATE
 */
void
ccow_parallel_io(struct ccow_op *op, struct ccow_io *io)
{
	assert(io);

	/* Queue up the incoming IOs */
	log_trace(lg, "op %p (%s), io %p: parent_io %p", op, ccow_op2str(op->optype), io, io->parent_io);

	struct class_req *req = CCOW_IO_REQ(io);
	assert(req != NULL);

	/*
	 * If the incoming IO has a parent, add this to that IO, otherwise
	 * we will schedule at the end of the chain.
	 */

	if (io->parent_io) {
		log_debug(lg, "queueing io %p to parent %p",
		    io, io->parent_io);
		log_debug(lg, "io->optype = %s", ccow_op2str(io->optype));
		log_debug(lg, "parent_io->optype = %s", ccow_op2str(io->parent_io->optype));

		QUEUE_INSERT_TAIL(&io->parent_io->p_queue, &io->p_item);
	} else {
		log_debug(lg, "chaining op = %p (%s): io = %p", op, ccow_op2str(op->optype), io);
	}
}

/*
 * Chunk supplied user buffer
 *
 * Scope: PUBLIC
 */
int
ccow_chunk(const char *buf, uint64_t len, size_t size, struct iovec **iov,
    size_t *iovcnt)
{
	if (!len || !size)
		return -EPERM;
	size_t cnt = len / size;
	size_t last_size = len % size;
	if (last_size != 0)
		cnt++;
	struct iovec *v = je_calloc(cnt, sizeof (struct iovec));
	if (!v) {
		*iovcnt = 0;
		return -ENOMEM;
	}
	*iovcnt = cnt;
	size_t i;
	for (i = 0; i < cnt; i++) {
		v[i].iov_base = (char *)buf + (i * size);
		v[i].iov_len = (i + 1 == cnt && last_size) ? last_size : size;
	}
	*iov = v;
	*iovcnt = cnt;
	return 0;
}

uint64_t
ccow_get_segment_guid(ccow_t tc)
{
	return tc->this_guid.l;
}

void
ccow_assign_this_guid(ccow_t tc, char *system_guid, size_t system_guid_size)
{
        char buf[SYSTEM_GUID_BUF_LEN] = { 0 };

	assert(system_guid_size >= sizeof(uint64_t) * 2 + 1);

	/* get first 16c XXXXXXXX-XXXX-XXXX */
        memcpy(buf, system_guid, 8);
        memcpy(buf + 8, system_guid + 9, 4);
        memcpy(buf + 12, system_guid + 14, 4);

	tc->this_guid.u = tc->this_serverid.u;
	tc->this_guid.l = strtoull(buf, NULL, 16);

	uint128_logdump(lg, "this_guid", &tc->this_guid);
	uint128_logdump(lg, "this_serverid", &tc->this_serverid);
}

static int
ccow_sysobj_check_cluster(struct ccow *tc, const char *cid, size_t cid_size)
{
	int err;
	ccow_completion_t c;

	/*
	 * Read root system object with NHID = 0x0
	 */
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "ccow_create_completion returned error = %d", err);
		return err;
	}

	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	struct iovec iov = { .iov_base = buf,
		.iov_len = CCOW_CLUSTER_CHUNK_SIZE };
	memcpy(buf, cid, cid_size);
	iov.iov_len = cid_size;
	ccow_lookup_t iter;
	err = ccow_tenant_get("", 1, "", 1, "", 1, "", 1, c, &iov, 1, 1,
	    CCOW_GET_LIST, &iter);
	if (err) {
		ccow_release(c);
		log_error(lg, "ccow_tenant_get = %d", err);
		return err;
	}
	err = ccow_wait(c, -1);
	if (err) {
		log_error(lg, "Error while reading system object: %d, "
		    "looking for cid=%s", err, cid);
		goto _cleanup;
	}

	err = -ENOENT;
	char *system_guid = NULL;
	size_t system_guid_size = 0;
	struct ccow_metadata_kv *kv = NULL;
	do {
		kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX|CCOW_MDTYPE_CUSTOM, -1);
		if (kv == NULL)
			break;
		if (memcmp_quick(kv->key, kv->key_size, cid, cid_size) == 0) {
			err = 0;
		}
		if (kv->type == CCOW_KVTYPE_RAW) {
			if (!strcmp(kv->key, RT_SYSKEY_SYSTEM_GUID)) {
				system_guid = (char *)kv->value;
				system_guid_size = kv->value_size;
			}
		}
		if (err == 0 && system_guid)
			break;
	} while (kv != NULL);

	if (err)
		goto _cleanup;

	/* Update tenant context with corresponding attributes */
	ccow_copy_inheritable_md_to_tc(iter->metadata, tc);
	tc->sysobj_hash_id = iter->metadata->nhid;

	if (system_guid)
		ccow_assign_this_guid(tc, system_guid, system_guid_size);

_cleanup:
	if (iter)
		ccow_lookup_release(iter);
	return err;
}

static int
ccow_sysobj_check_tenant(struct ccow *tc, const char *tid,
    size_t tid_size)
{
	int err;
	ccow_completion_t c;

	assert(tc->cid);

	/*
	 * Read cluster system object
	 */
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	char buf[CCOW_TENANT_CHUNK_SIZE];
	struct iovec iov = { .iov_base = buf,
		.iov_len = CCOW_TENANT_CHUNK_SIZE };
	memcpy(buf, tid, tid_size);
	iov.iov_len = tid_size;
	ccow_lookup_t iter;
	err = ccow_tenant_get(tc->cid, tc->cid_size, "", 1, "", 1, "", 1,
	    c, &iov, 1, 1, CCOW_GET_LIST, &iter);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, -1);
	if (err) {
		if (err == -ENOENT) {
			log_error(lg, "Cannot find tenant %s n cluster object %s: %d",
			    tid, tc->cid, err);
		} else
			log_error(lg, "Error while reading cluster object %s: %d",
			    tc->cid, err);
		log_error(lg, "\n\t\t+--------------------------------------+"
		              "\n\t\t+  ERROR: cluster is not initialized!? +"
		              "\n\t\t+--------------------------------------+");
		goto _cleanup;
	}

	err = -ENOENT;
	struct ccow_metadata_kv *kv = NULL;
	do {
		kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1);
		if (kv == NULL)
			break;
		if (memcmp_quick(kv->key, kv->key_size, tid, tid_size) == 0) {
			err = 0;
			break;
		}
	} while (kv != NULL);

	if (err)
		goto _cleanup;

_cleanup:
	if (iter)
		ccow_lookup_release(iter);
	return err;
}

/*
 * Build name_hash_id for a request
 *
 * cid, tenant, bucket and object => Name Hash ID
 */
int
ccow_build_name_hashes(struct ccow_completion *c, struct ccow_op *op)
{
	int err;
	struct ccow *tc = c->tc;

	if (*op->cid) {
		if (memcmp_quick(tc->cid, tc->cid_size, op->cid,
			    op->cid_size) == 0) {
			/* use pre-built value */
			op->cluster_hash_id = tc->cluster_hash_id;
		} else {
			err = crypto_hash_with_type(HASH_TYPE_DEFAULT,
			    (uint8_t *)op->cid, op->cid_size,
			    (uint8_t *)&op->cluster_hash_id);
			if (err) {
				log_error(lg, "Error while calculating cluster "
				    "hash id value: %d", err);
				return err;
			}
		}
	} else if (*op->tid == 0) {
		/* system root object is 0x0 */
		err = crypto_hash_with_type(HASH_TYPE_DEFAULT,
		    (uint8_t *)op->cid, op->cid_size,
		    (uint8_t *)&op->name_hash_id);
		if (err) {
			log_error(lg, "Error while calculating cluster "
			    "hash id value: %d", err);
		}
		tc->sysobj_hash_id = op->name_hash_id;
		return err;
	}

	if (*op->tid == 0) {
		op->parent_hash_id = tc->sysobj_hash_id;
		op->name_hash_id = op->cluster_hash_id;
		return 0;
	} else {
		op->parent_hash_id = op->cluster_hash_id;
		assert(tc->tid);
		if (memcmp_quick(tc->tid, tc->tid_size, op->tid,
			    op->tid_size) == 0 &&
		    memcmp_quick(op->tid, op->tid_size, RT_SYSVAL_TENANT_ADMIN,
			    sizeof (RT_SYSVAL_TENANT_ADMIN)) != 0) {
			/* use pre-built value */
			op->tenant_hash_id = tc->tenant_hash_id;
		} else {
			crypto_state_t S;
			err = crypto_init_with_type(&S, HASH_TYPE_DEFAULT);
			if (err) {
				log_error(lg, "crypto_init: tenant hash id %d",
				    err);
				return err;
			}
			err = crypto_update(&S, (uint8_t *)op->cid,
			    op->cid_size);
			if (err) {
				log_error(lg, "crypto_update: tenant hash id %d",
				    err);
				return err;
			}
			err = crypto_update(&S, (uint8_t *)op->tid,
			    op->tid_size);
			if (err) {
				log_error(lg, "crypto_update: tenant hash id %d",
				    err);
				return err;
			}
			err = crypto_final(&S, (uint8_t *)&op->tenant_hash_id);
			if (err) {
				log_error(lg, "crypto_final: tenant hash id %d",
				    err);
				return err;
			}
		}
	}

	if (*op->bid == 0) {
		if (*op->oid == 0) {
			op->name_hash_id = op->tenant_hash_id;
			return 0;
		}
		op->bucket_hash_id = op->tenant_hash_id;
	} else {
		if (*op->tid == 0) {
			err = -EBADF;
			log_error(lg, "Invalid bucked id: %d", err);
			return err;
		}
		op->parent_hash_id = op->tenant_hash_id;

		crypto_state_t S;
		err = crypto_init_with_type(&S, HASH_TYPE_DEFAULT);
		if (err) {
			log_error(lg, "crypto_init: tenant hash id %d", err);
			return err;
		}

		err = crypto_update(&S, (uint8_t *)op->cid, op->cid_size);
		if (err) {
			log_error(lg, "crypto_update: bucket hash id %d", err);
			return err;
		}

		err = crypto_update(&S, (uint8_t *)op->tid, op->tid_size);
		if (err) {
			log_error(lg, "crypto_update: bucket hash id %d", err);
			return err;
		}

		/*
		 * If bucket name has '/' separator, we should consider it to
		 * be a true directory. In which case parent of the object has
		 * to be calculated accordingly.
		 */
		char *dir = je_malloc(op->bid_size + 1);
		if (!dir)
			return -ENOMEM;
		memcpy(dir, op->bid, op->bid_size);
		dir[op->bid_size] = 0;
		char *sep_pos = strrchr(dir, '/');
		if (*op->oid != 0 && sep_pos) {
			/* parent bid */
			*sep_pos = 0;
			err = crypto_update(&S, (uint8_t *)dir, strlen(dir) + 1);
			if (err) {
				je_free(dir);
				log_error(lg, "crypto_update: bucket hash id %d", err);
				return err;
			}

			/* parent oid */
			char *odir = sep_pos + 1;
			err = crypto_update(&S, (uint8_t *)odir, strlen(odir) + 1);
			if (err) {
				je_free(dir);
				log_error(lg, "crypto_update: bucket hash id %d", err);
				return err;
			}
		} else {
			err = crypto_update(&S, (uint8_t *)op->bid, op->bid_size);
			if (err) {
				je_free(dir);
				log_error(lg, "crypto_update: bucket hash id %d", err);
				return err;
			}
		}
		je_free(dir);

		crypto_final(&S, (uint8_t *)&op->bucket_hash_id);
		if (err) {
			log_error(lg, "crypto_final: bucket hash id %d", err);
			return err;
		}
	}

	if (*op->oid == 0) {
		op->name_hash_id = op->bucket_hash_id;
		return 0;
	} else {
		op->parent_hash_id = op->bucket_hash_id;

		crypto_state_t S;
		err = crypto_init_with_type(&S, HASH_TYPE_DEFAULT);
		if (err) {
			log_error(lg, "crypto_init: object hash id %d", err);
			return err;
		}

		err = crypto_update(&S, (uint8_t *)op->cid, op->cid_size);
		if (err) {
			log_error(lg, "crypto_update: object hash id %d", err);
			return err;
		}

		err = crypto_update(&S, (uint8_t *)op->tid, op->tid_size);
		if (err) {
			log_error(lg, "crypto_update: object hash id %d", err);
			return err;
		}

		err = crypto_update(&S, (uint8_t *)op->bid, op->bid_size);
		if (err) {
			log_error(lg, "crypto_update: object hash id %d", err);
			return err;
		}

		err = crypto_update(&S, (uint8_t *)op->oid, op->oid_size);
		if (err) {
			log_error(lg, "crypto_update: object hash id %d", err);
			return err;
		}

		crypto_final(&S, (uint8_t *)&op->object_hash_id);
		if (err) {
			log_error(lg, "crypto_final: object hash id %d", err);
			return err;
		}
	}

	op->name_hash_id = op->object_hash_id;
	return 0;
}

static int
ccow_context_load_guid(ccow_t tc)
{
	int err;
	struct ccow_completion *c;
	ccow_lookup_t iter = NULL;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;
	err = ccow_admin_pseudo_get("", 1, "", 1, "", 1, "", 1, NULL, 0, 0,
	    CCOW_GET, c, &iter);
	if (err) {
		ccow_release(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		log_warn(lg, "System unitialized, please run system init.");
		return err;
	}

	char *system_guid = NULL;
	size_t system_guid_size = 0;
	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_CUSTOM, pos++))) {
		if (kv->type == CCOW_KVTYPE_RAW) {
			if (!strcmp(kv->key, RT_SYSKEY_SYSTEM_GUID)) {
				system_guid = (char *)kv->value;
				system_guid_size = kv->value_size;
				break;
			}
		}
	}

	if (system_guid)
		ccow_assign_this_guid(tc, system_guid, system_guid_size);

	if (iter)
		ccow_lookup_release(iter);

	return err;
}

static int
ccow_context_create(const char *jsonstr, const char *tid, struct ccow **tc_out,
    void (*opts_override)(struct ccow *))
{
	int err;

	if (!lg)
		lg = Logger_init(&lg_ccow, "ccow");

	load_crypto_lib();
	if (!jsonstr || strlen(jsonstr) == 0 || !tid) {
		err = -EINVAL;
		log_error(lg, "Missing configuration: %d", err);
		return err;
	}

	struct ccow *tc = je_calloc(1, sizeof (*tc));
	if (!tc) {
		err = -ENOMEM;
		log_error(lg, "Out of memory: tc alloc");
		return err;
	}
	tc->loop = uv_loop_new();
	tc->opts_override = opts_override;
	/*
	* we must set tc->sub_fd to -1, because nn_socket can return 0 as normal good socket
	*/
	tc->sub_fd = -1;

	/*
	 * Parse supplied default tenant configuration
	 */
	tc->opts = json_parse(jsonstr, strlen(jsonstr));
	if (!tc->opts) {
		log_error(lg, "Cannot parse configuration:\n%s\n", jsonstr);
		ccow_tenant_term(tc);
		return -EINVAL;
	}
	err = ccow_parse_config(tc);
	if (err) {
		ccow_tenant_term(tc);
		return err;
	}

	tc->completions = je_calloc(tc->compl_lfq_depth, sizeof(struct ccow_completion));
	if (!tc->completions) {
		err = -ENOMEM;
		log_error(lg, "Out of memory: compl alloc");
		return err;
	}

	tc->ios = je_calloc(CCOW_IO_LFQ_DEPTH(tc), sizeof(struct ccow_io));
	if (!tc->ios) {
		err = -ENOMEM;
		log_error(lg, "Out of memory: compl alloc");
		return err;
	}

	int fd;
	char srv_path[PATH_MAX];
	snprintf(srv_path, sizeof(srv_path), SERVERID_CACHE_FILE, nedge_path());
	if ((fd = open(srv_path, O_RDONLY)) < 0) {
		log_error(lg, "Cannot open SERVERID cache file: %s",
		    strerror(errno));
		if (serverid_init(&tc->this_serverid) == -1) {
		    log_error(lg, "Cannot generate SERVERID cache file: %s",
			strerror(errno));
		    return -1;
		}
	} else {
	    char serverid[UINT128_BYTES * 2 + 1] = { 0 };
	    if (read(fd, serverid, UINT128_BYTES * 2 + 1) < 0) {
		    log_error(lg, "Cannot read SERVERID cache: %s",
			strerror(errno));
		    close(fd);
		    return -1;
	    }
	    close(fd);
	    uint128_fromhex(serverid, UINT128_BYTES * 2 + 1, &tc->this_serverid);
	}

	/* slow start */
	tc->io_rate_lim = 2;
	tc->io_rate = 0;

	tc->api_lfq = lfqueue_create(CCOW_IO_LFQ_DEPTH(tc));
	if (!tc->api_lfq) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}
	tc->api_lfq_hp = lfqueue_create(CCOW_IO_LFQ_HP_DEPTH);
	if (!tc->api_lfq_hp) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}
	QUEUE_INIT(&tc->inprog_queue);

	/*
	 * Create completion queue and populate it with ready to use
	 * I/O queues. Also, populate main loop I/O queue.
	 */
	tc->comp_lfq = lfqueue_create(tc->compl_lfq_depth);
	if (!tc->comp_lfq) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}
	int i;
	for (uint32_t i = 0; i < tc->compl_lfq_depth; i++) {
		struct ccow_completion *c = &tc->completions[i];
		err = lfqueue_enqueue(tc->comp_lfq, c);
		assert(!err);
		err = uv_mutex_init(&c->io_mutex);
		assert(!err);
		err = uv_mutex_init(&c->operations_mutex);
		assert(!err);
		c->done_lfq = lfqueue_create(CCOW_IO_LFQ_DEPTH(tc));
		if (!c->done_lfq) {
			ccow_tenant_term(tc);
			return -ENOMEM;
		}
	}
	tc->reserved_comp = lfqueue_dequeue(tc->comp_lfq);
	tc->released_lfq = lfqueue_create(tc->compl_lfq_depth);
	if (!tc->released_lfq) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}
	tc->ios_lfq = lfqueue_create(CCOW_IO_LFQ_DEPTH(tc));
	if (!tc->ios_lfq) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}
	for (uint32_t i = 0; i < CCOW_IO_LFQ_DEPTH(tc); i++) {
		struct ccow_io *io = &tc->ios[i];
		err = lfqueue_enqueue(tc->ios_lfq, io);
		assert(!err);
	}

	uv_barrier_init(&tc->main_barrier, 2);
	uv_thread_create(&tc->main_thread, main_loop, tc);
	uv_barrier_wait(&tc->main_barrier);
	uv_barrier_destroy(&tc->main_barrier);

	if (tc->startup_err) {
		err = tc->startup_err;
		ccow_tenant_term(tc);
		return err;
	}

	// this flexhash is only for bootup. it gets replaced by
	// the most current one by server-list-get called from
	// ccow_create_context
	tc->flexhash = flexhash_table_create(FLEXHASH_BOOTUP_VDEVS, FH_CLIENT_SIDE);
	if (!tc->flexhash) {
		log_error(lg, "Unable to create the default flexhash");
		ccow_tenant_term(tc);
		return -ENOMEM;
	}

	/*
	 * Issue RT_SERVER_LIST_GET
	 */
	struct ccow_completion *c;
	err = ccow_create_completion(tc, NULL, NULL, 1, (ccow_completion_t *)&c);
	if (err) {
		return err;
	}

	err = server_list_get_init(tc->netobj, c, uint128_null, 0, 0);
	if (err) {
		ccow_tenant_term(tc);
		return err;
	}

	*tc_out = tc;
	err = ccow_wait(c, -1);

	/* encode svcinfo this context belongs to */
	char *svcname = getenv("CCOW_SVCNAME");
	char *svctype = getenv("CCOW_SVCTYPE");
	snprintf((char*)&tc->svcinfo, sizeof(tc->svcinfo),
	    "%s^%s", svctype ? svctype : "undef", svcname ? svcname : "undef");

	return err;
}

static int
inherit_from_tenant(struct ccow *tc) {
	ccow_completion_t c;
	ccow_lookup_t iter = NULL;

	int err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg,"create completion err: %d", err);
		goto _cleanup;
	}

	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
		"", 1, "", 1, c, NULL, 0, 0, CCOW_GET, &iter);
	if (err) {
		log_error(lg,"Tenant get err: %d", err);
		ccow_drop(c);
		goto _cleanup;
	}

	err = ccow_wait(c, -1);
	if (err) {
		log_error(lg,"Tenant read err: %d", err);
		ccow_drop(c);
		goto _cleanup;
	}

	/* Update tenant context with corresponding attributes */
	if (iter)
		ccow_copy_inheritable_md_to_tc(iter->metadata, tc);

_cleanup:
	if (iter)
		ccow_lookup_release(iter);
	return err;
}

/*
 * Initialize CCOW library from default configuration file.
 *
 * Scope: PUBLIC
 */
int
ccow_default_tenant_init(const char *cid, size_t cid_size,
    const char *tid, size_t tid_size, ccow_t *ptctx)
{
	char ccow_path[PATH_MAX];
	snprintf(ccow_path, sizeof(ccow_path), CCOW_DEFAULT_CONFIG, nedge_path());
	int ccow_fd = open(ccow_path, O_RDONLY);
	if (ccow_fd < 0) {
		log_error(lg, "%s open error: %d", ccow_path, ccow_fd);
		return ccow_fd;
	}

	char conf[16384] = "";
	int err = read(ccow_fd, conf, 16383);
	if (err < 0) {
		log_error(lg, "%s read error: %d", ccow_path, err);
		close(ccow_fd);
		return err;
	}
	close(ccow_fd);

	*ptctx = NULL;
	err = ccow_tenant_init(conf, cid, cid_size, tid,  tid_size, ptctx);
	return err;
}


/*
 * Initialize CCOW library.
 *
 * Scope: PUBLIC
 */
int
ccow_tenant_init(const char *jsonstr, const char *cid, size_t cid_size,
    const char *tid, size_t tid_size, ccow_t *pcluster)
{
	int err;

	assert(cid && cid_size > 0);
	assert(tid && tid_size > 0);

	if (!lg)
		lg = Logger_init(&lg_ccow, "ccow");

	if (memcmp_quick(tid, tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) == 0) {
		err = -EINVAL;
		log_error(lg, "Wrong TID argument: %d", err);
		log_hexdump(lg, "TID:", (char *)tid, tid_size);
		return err;
	}

	struct ccow *tc;
	err = ccow_context_create(jsonstr, tid, &tc, NULL);
	if (err) {
		log_error(lg, "ccow_context_create err = %d", err);
		return err;
	}
	tc->stats_refresh_timer = get_timestamp_us();

	/*
	 * Verify that cluster with cid exists
	 */
	assert(tc->cid == NULL);
	err = ccow_sysobj_check_cluster(tc, cid, cid_size);
	if (err) {
		log_error(lg, "ccow_sysobj_check_cluster returned err = %d", err);
		ccow_tenant_term(tc);
		return err;
	}

	tc->cid = je_memdup(cid, cid_size);
	if (!tc->cid) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}
	tc->cid_size = cid_size;

	// Shard cache
	tc->shard_cache_inprog = 0;
	tc->shard_cache_timer_cnt = 0;
	tc->shard_cache = sop_shard_table_create();
	if (!tc->shard_cache) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}


	/* Pre-build cluster_hash_id */
	err = crypto_hash_with_type(HASH_TYPE_DEFAULT, (uint8_t *)tc->cid,
	    cid_size, (uint8_t *)&tc->cluster_hash_id);
	if (err) {
		log_error(lg, "Error while calculating cluster hash id "
		    "value: %d", err);
		ccow_tenant_term(tc);
		return err;
	}

	/*
	 * Verify that tenant with TID exists
	 */
	assert(tc->tid == NULL);
	err = ccow_sysobj_check_tenant(tc, tid, tid_size);
	if (err) {
		log_error(lg, "ccow_tenant_term err = %d", err);
		ccow_tenant_term(tc);
		return err;
	}

	tc->tid = je_memdup(tid, tid_size);
	if (!tc->tid) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}
	tc->tid_size = tid_size;

	/* Pre-build tenant_hash_id */
	crypto_state_t S;
	err = crypto_init_with_type(&S, HASH_TYPE_DEFAULT);
	if (err) {
		log_error(lg, "crypto_init: tenant hash id %d", err);
		ccow_tenant_term(tc);
		return err;
	}
	err = crypto_update(&S, (uint8_t *)tc->cid, cid_size);
	if (err) {
		log_error(lg, "crypto_update: tenant hash id %d", err);
		ccow_tenant_term(tc);
		return err;
	}
	err = crypto_update(&S, (uint8_t *)tc->tid, tid_size);
	if (err) {
		log_error(lg, "crypto_update: tenant hash id %d", err);
		ccow_tenant_term(tc);
		return err;
	}
	err = crypto_final(&S, (uint8_t *)&tc->tenant_hash_id);
	if (err) {
		log_error(lg, "crypto_final: tenant hash id %d", err);
		ccow_tenant_term(tc);
		return err;
	}

	err = inherit_from_tenant(tc);
	if (err) {
		log_error(lg, "inherite_from_tenant err: %d", err);
		ccow_tenant_term(tc);
		return err;
	}

	uv_async_send(&tc->enter_handle);
	/* now start the timer that periodically scans the process table */

	if (tc == mtc)
		ccow_isgw_service_create(tc);
	/* done */
	*pcluster = tc;
	return 0;
}

/*
 * Initialize CCOW library as admin.
 *
 * Scope: PUBLIC
 */
int
ccow_admin_init_override(const char *jsonstr, const char *cid, size_t cid_size,
    ccow_t *pcluster, void (*opts_override)(struct ccow *))
{
	int err;

	assert(cid && cid_size > 0);

	struct ccow *tc;
	err = ccow_context_create(jsonstr, RT_SYSVAL_TENANT_ADMIN, &tc,
	    opts_override);
	if (err)
		return err;

	tc->tid = je_strdup(RT_SYSVAL_TENANT_ADMIN);
	if (!tc->tid) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}
	tc->tid_size = strlen(RT_SYSVAL_TENANT_ADMIN) + 1;

	tc->cid = je_memdup(cid, cid_size);
	if (!tc->cid) {
		ccow_tenant_term(tc);
		return -ENOMEM;
	}
	tc->cid_size = cid_size;

	if (*cid) {
		/*
		 * Verify that cluster with cid exists
		 */
		err = ccow_sysobj_check_cluster(tc, cid, cid_size);
		if (err) {
			ccow_tenant_term(tc);
			return err;
		}

		/* Pre-build cluster_hash_id */
		err = crypto_hash_with_type(HASH_TYPE_DEFAULT, (uint8_t *)tc->cid,
		    cid_size, (uint8_t *)&tc->cluster_hash_id);
		if (err) {
			log_error(lg, "Error while calculating cluster hash id "
			    "value: %d", err);
			ccow_tenant_term(tc);
			return err;
		}
	} else {
		err = ccow_context_load_guid(tc);
		if (err) {
			log_warn(lg, "Error while loading cluster segment guid "
			    "value: %d", err);
		}
	}

	if (tc == mtc)
		ccow_isgw_service_create(tc);
	/* done */
	*pcluster = tc;

	return 0;
}

int
ccow_admin_init(const char *jsonstr, const char *cid, size_t cid_size,
    ccow_t *pcluster)
{
	return ccow_admin_init_override(jsonstr, cid, cid_size, pcluster, NULL);
}


/*
 * Perform a generic put as tenant.
 */
int
ccow_pseudo_put(const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t off,
	ccow_op_t optype, struct ccow_copy_opts *copy_opts,
	ccow_completion_t comp, int64_t attrs)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	return ccow_tenant_put(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    bid, bid_size, oid, oid_size, c, iov, iovcnt, off, optype,
	    copy_opts, attrs);
}


/*
 * Perform a put as admin on behalf of a tenant.
 */
int
ccow_admin_pseudo_put(const char *cid, size_t cid_size, const char *tid,
	size_t tid_size, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t off,
	ccow_op_t optype, struct ccow_copy_opts *copy_opts,
	ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Permission Denied, not admin");
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		return -EPERM;
	}

	return ccow_tenant_put(cid, cid_size, tid, tid_size, bid, bid_size,
	    oid, oid_size, c, iov, iovcnt, off, optype, copy_opts, 0);
}


/*
 * Perform a put hidden as admin on behalf of a tenant.
 */
int
ccow_admin_pseudo_put_notrlog(const char *cid, size_t cid_size, const char *tid,
	size_t tid_size, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t off,
	ccow_op_t optype, struct ccow_copy_opts *copy_opts,
	ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
			strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Permission Denied, not admin");
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		return -EPERM;
	}

	return ccow_tenant_put(cid, cid_size, tid, tid_size, bid, bid_size,
		oid, oid_size, c, iov, iovcnt, off, optype, copy_opts, RD_ATTR_TRLOG_SOP);
}

/*
 * Perform a generic get as tenant.
 */
int
ccow_pseudo_get(const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t offset,
    ccow_op_t optype, ccow_completion_t comp, ccow_lookup_t *i)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	int err;

	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    bid, bid_size, oid, oid_size, c, iov, iovcnt, offset, optype, i);
	return err;
}

/*
 * Perform a get as admin on behalf of a tenant.
 */
int
ccow_admin_pseudo_get(const char *cid, size_t cid_size, const char *tid,
	size_t tid_size, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, struct iovec *iov, size_t iovcnt, uint64_t offset,
    ccow_op_t optype, ccow_completion_t comp, ccow_lookup_t *i)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	int err;

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Permission Denied, not admin");
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		return -EPERM;
	}

	err = ccow_tenant_get(cid, cid_size, tid, tid_size, bid, bid_size,
	    oid, oid_size, c, iov, iovcnt, offset, optype, i);
	return err;
}

int
ccow_admin_pseudo_getobj(const char *nhid_str, struct iovec *iov, size_t iovcnt,
    uint64_t offset, ccow_op_t optype, ccow_completion_t comp, ccow_lookup_t *i)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	int err;

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Permission Denied, not admin");
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		return -EPERM;
	}

	err = ccow_tenant_getobj(nhid_str, c, iov, iovcnt, offset, optype, i);
	return err;
}

/*
 * Perform a delete as admin on behalf of a tenant.
 */
int
ccow_admin_pseudo_delete(const char *cid, size_t cid_size, const char *tid,
	size_t tid_size, const char *bid, size_t bid_size, const char *oid,
	size_t oid_size, ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Permission Denied, not admin");
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		return -EPERM;
	}

	return ccow_tenant_put(cid, cid_size, tid, tid_size, bid, bid_size,
	    oid, oid_size, c, NULL, 0, 0, CCOW_PUT, NULL,
	    RD_ATTR_LOGICAL_DELETE);
}

/*
 * Abort outstanding CCOW I/O.
 *
 * Scope: PUBLIC
 */
void
ccow_tenant_abort(ccow_t cluster)
{
	int i;
	struct ccow *tc = cluster;

	if (tc == NULL)
		return;

	tc->abort = 1;
}

/*
 * Terminate CCOW library.
 *
 * Scope: PUBLIC
 */
void
ccow_tenant_term(ccow_t cluster)
{
	int i;
	struct ccow *tc = cluster;

	if (tc == NULL)
		return;

	tc->abort = 1;

	if (tc->main_thread) {
		uv_async_send(&tc->exit_handle);
		ccowtp_stop(tc->tp, 0);
		uv_thread_join(&tc->main_thread);
		/* TODO: workaround for timing bug in Jenkins tests */
		usleep(50000);
	}
	if (tc->opts)
		json_value_free(tc->opts);
	if (tc->api_lfq)
		lfqueue_destroy(tc->api_lfq);
	if (tc->api_lfq_hp)
		lfqueue_destroy(tc->api_lfq_hp);
	if (tc->released_lfq) {
		struct ccow_completion *c;
		while ((c = lfqueue_dequeue(tc->released_lfq))) {

			static int cdc_3 = 0;
			log_debug(lg, "cdc_3 = %d", ++cdc_3);

			ccow_destroy_completion(c);
			uv_mutex_destroy(&c->operations_mutex);
			uv_mutex_destroy(&c->io_mutex);
		}
		lfqueue_destroy(tc->released_lfq);
	}
	if (tc->comp_lfq) {
		pthread_spin_lock(&tc->comp_lfq->ring_lock);
		if (tc->reserved_comp) {
			pthread_spin_unlock(&tc->comp_lfq->ring_lock);
			lfqueue_enqueue(tc->comp_lfq, tc->reserved_comp);
			pthread_spin_lock(&tc->comp_lfq->ring_lock);
			tc->reserved_comp = NULL;
		}
		pthread_spin_unlock(&tc->comp_lfq->ring_lock);
		lfqueue_destroy(tc->comp_lfq);
		for (uint32_t i = 0; i < tc->compl_lfq_depth; i++) {
			struct ccow_completion *c = &tc->completions[i];
			assert(c);
			if (c->operations != NULL) {
				je_free(c->operations);
				c->operations = NULL;
			}

			if (c->chunkmap_type != NULL) {
				je_free(c->chunkmap_type);
				c->chunkmap_type = NULL;
			}

			if (c->done_lfq) {
				lfqueue_destroy(c->done_lfq);
			}
		}
	}

	pthread_rwlock_wrlock(&mtc_lock);
	QUEUE_REMOVE(&tc->mtc_item);
	QUEUE_INIT(&tc->mtc_item);
	struct ccow *next_tc = NULL;
	pthread_mutex_lock(&mtc_queue_lock);
	if (!QUEUE_EMPTY(&mtc_queue)) {
		QUEUE *q = QUEUE_HEAD(&mtc_queue);
		next_tc = QUEUE_DATA(q, struct ccow, mtc_item);
	}
	pthread_mutex_unlock(&mtc_queue_lock);
	if (mtc == tc) {
		if (next_tc) {
			/* relink to the next available TC */
			mtc = next_tc;
			assert(mtc->ucache == mtc_ucache);
			mtc_ucache->tc = (struct ccow *)mtc;
		} else {
			/* last open context */
			ccow_ucache_free((struct ccow *)mtc);
			tc->ucache = mtc_ucache = NULL;
			mtc = NULL;
			QUEUE_INIT(&mtc_queue);
		}
		ccow_isgw_service_destroy();
	}

	pthread_rwlock_unlock(&mtc_lock);

	if (tc->ios_lfq)
		lfqueue_destroy(tc->ios_lfq);
	if (tc->cid)
		je_free(tc->cid);
	if (tc->tid)
		je_free(tc->tid);
	if (tc->flexhash)
		flexhash_table_destroy(tc->flexhash);
	if (tc->chunkmap_type) {
		je_free(tc->chunkmap_type);
	}
	if (tc->shard_cache)
		sop_shard_table_destroy(tc->shard_cache);
	if (tc->completions)
		je_free(tc->completions);
	if (tc->ios)
		je_free(tc->ios);
	je_free(tc);
	unload_crypto_lib();
	log_flush(lg);
}

int
ccow_tenant_assign_mcbase(struct ccow *tc, char *tenant_rcv_mcbase,
    uint16_t port)
{
	int err;

	pid_t pid = getpid();
	unsigned long thrid = ccow_gettid();

	struct in6_addr addr;
	if (inet_pton(AF_INET6, tenant_rcv_mcbase, &addr) != 1) {
		log_error(lg, "conversion error: wrong tenant recvaddr %s",
		    tenant_rcv_mcbase);
		return -1;
	}

	int alloc_len = tc->tid ? tc->tid_size : strlen(RT_SYSVAL_TENANT_ADMIN);
	alloc_len += 3 * CCOW_MAX_STRLEN_64;

	char idstr[alloc_len];
	memset(idstr, 0, alloc_len);

	if (tc->tid) {
		memcpy(idstr, tc->tid, tc->tid_size);
		sprintf(idstr + tc->tid_size, ":%ld:%d:%lu", gethostid(),
		    pid, thrid);
	} else
		sprintf(idstr, "%s:%d:%lu", RT_SYSVAL_TENANT_ADMIN, pid, thrid);

	uint512_t id_hash;
	err = crypto_hash_with_type(HASH_TYPE_DEFAULT, (uint8_t *)idstr, alloc_len,
	    (uint8_t *)&id_hash);
	if (err) {
		log_error(lg, "crypto_hash: tenant_recvaddr %d", err);
		return err;
	}

	flexhash_get_tenant_rcvaddr(CLIENT_FLEXHASH, &id_hash,
			addr, port, &tc->tenant_recvaddr);

	tc->tenant_recvport = port;
	tc->rcv_joined = 0;

	if (unlikely(LOG_LEVEL_DEBUG >= lg->level)) {
		char dst[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &tc->tenant_recvaddr.sin6_addr, dst,
		    INET6_ADDRSTRLEN);
		log_debug(lg, "addr base: %s.%d idstr: %s tenant_mcaddr: %s.%d",
						tenant_rcv_mcbase, port,
						idstr, dst, port);
	}

	return 0;
}

int
ccow_tenant_join_rcvaddr(struct replicast *robj, struct ccow *tc, uint32_t if_index)
{
	int err = 0;
	char dst[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &tc->tenant_recvaddr.sin6_addr, dst, INET6_ADDRSTRLEN);
	log_debug(lg, "Joining tenant receive MC group %s", dst);
	err = replicast_join(robj, dst, if_index);
	if (err) {
		log_error(lg, "Unable to join MC group %s", dst);
	}
	tc->rcv_joined = 1;
	return err;
}

int
ccow_tenant_leave_rcvaddr(struct ccow *tc)
{
	int err = 0;
	char dst[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &tc->tenant_recvaddr.sin6_addr, dst, INET6_ADDRSTRLEN);
	log_debug(lg, "Leaving tenant receive MC group %s", dst);
	err = replicast_leave(tc->netobj->robj[0], dst, tc->netobj->if_indexes[0]);
	if (err) {
		log_error(lg, "Unable to leave MC group %s", dst);
		return err;
	}

	return err;
}

int
ccow_get_stats(ccow_t tctx, ccow_stats_t *stats)
{
	if ((tctx == NULL) || (stats == NULL))
		return -EINVAL;

	*stats = &tctx->stats;

	return 0;
}

void
ccow_print_stats(ccow_stats_t stats)
{
	log_flush(lg);
	log_notice(lg, "\n"
	    "------------------------------------------------------------\n"
	    "ccow: \n"
	    "    puts           = %"PRIu64" \n"
	    "    gets           = %"PRIu64" \n"
	    "    put_conts      = %"PRIu64" \n"
	    "    get_conts      = %"PRIu64" \n"
	    "    zblock_gets    = %"PRIu64" \n"
	    "    zblock_puts    = %"PRIu64" \n"
	    "    thin_reads     = %"PRIu64" \n"
	    "    dedupe_hits    = %"PRIu64" \n"
	    "------------------------------------------------------------\n",
	    stats->ccow.puts,
	    stats->ccow.gets,
	    stats->ccow.put_conts,
	    stats->ccow.get_conts,
	    stats->ccow.zeroblock_get_hits,
	    stats->ccow.zeroblock_put_hits,
	    stats->ccow.thin_read_hits,
	    stats->ccow.dedupe_hits
	);
	log_notice(lg, "\n"
	    "------------------------------------------------------------\n"
	    "cmcache: \n"
	    "    hash_size      = %"PRIu64" \n"
	    "    lru_hiwat      = %"PRIu64" \n"
	    "    lru_max        = %"PRIu64" \n"
	    "    lru_count      = %"PRIu64" \n"
	    "    lru_lowat      = %"PRIu64" \n"
	    "    size_max       = %zu \n"
	    "    size           = %zu \n"
	    "    hits           = %"PRIu64" \n"
	    "    misses         = %"PRIu64" \n"
	    "    put_hits       = %"PRIu64" \n"
	    "    put_misses     = %"PRIu64" \n"
	    "    evicts         = %"PRIu64" \n"
	    "    overwr_evicts  = %"PRIu64" \n"
	    "------------------------------------------------------------\n",
	    stats->cmcache.cmc_hash_size,
	    stats->cmcache.cmc_lru_hiwat,
	    stats->cmcache.cmc_lru_max,
	    stats->cmcache.cmc_lru_count,
	    stats->cmcache.cmc_lru_lowat,
	    stats->cmcache.cmc_size_max,
	    stats->cmcache.cmc_size,
	    stats->cmcache.cmc_hits,
	    stats->cmcache.cmc_misses,
	    stats->cmcache.cmc_put_hits,
	    stats->cmcache.cmc_put_misses,
	    stats->cmcache.cmc_evicts,
	    stats->cmcache.cmc_overwr_evicts
	);
	log_notice(lg, "\n"
	    "------------------------------------------------------------\n"
	    "ucache: \n"
	    "    puts           = %"PRIu64" \n"
	    "    gets           = %"PRIu64" \n"
	    "    ucsize_max     = %zu \n"
	    "    ucsize_lim     = %zu \n"
	    "    mem_limit      = %zu \n"
	    "    ucsize         = %zu \n"
	    "    total ram      = %zu \n"
	    "    free ram       = %zu \n"
	    "    hits           = %"PRIu64" \n"
	    "    misses         = %"PRIu64" \n"
	    "    put_hits       = %"PRIu64" \n"
	    "    put_misses     = %"PRIu64" \n"
	    "    put_evicts     = %"PRIu64" \n"
	    "    expand_nomem   = %"PRIu64" \n"
	    "    expands        = %"PRIu64" \n"
	    "    shrinks        = %"PRIu64" \n"
	    "    inprogs        = %"PRIu64" \n"
	    "    size_cur       = %"PRIu64" \n"
	    "    size_inc       = %"PRIu64" \n"
	    "    size_min       = %"PRIu64" \n"
	    "    size_max       = %"PRIu64" \n"
	    "    lru_count      = %"PRIu64" \n"
	    "    overwr_evicts  = %"PRIu64" \n"
	    "------------------------------------------------------------\n",
	    stats->ucache.puts,
	    stats->ucache.gets,
	    stats->ucache.ucsize_max,
	    stats->ucache.ucsize_lim,
	    stats->ucache.mem_limit,
	    stats->ucache.ucsize,
	    stats->ucache.total_ram,
	    stats->ucache.free_ram,
	    stats->ucache.hits,
	    stats->ucache.misses,
	    stats->ucache.put_hits,
	    stats->ucache.put_misses,
	    stats->ucache.put_evicts,
	    stats->ucache.expand_nomem,
	    stats->ucache.expands,
	    stats->ucache.shrinks,
	    stats->ucache.inprogs,
	    stats->ucache.size_cur,
	    stats->ucache.size_inc,
	    stats->ucache.size_min,
	    stats->ucache.size_max,
	    stats->ucache.lru_count,
	    stats->ucache.overwr_evicts
	);
	log_notice(lg, "\n"
	    "------------------------------------------------------------\n"
	    "read ahead: \n"
	    "    disabled       = %"PRIu64" \n"
	    "    enabled        = %"PRIu64" \n"
	    "    sequential     = %"PRIu64" \n"
	    "    non_sequential = %"PRIu64" \n"
	    "    detected       = %"PRIu64" \n"
	    "    not_detected   = %"PRIu64" \n"
	    "    factored       = %"PRIu64" \n"
	    "    not_factored   = %"PRIu64" \n"
	    "------------------------------------------------------------\n",
	    stats->read_ahead.disabled,
	    stats->read_ahead.enabled,
	    stats->read_ahead.sequential,
	    stats->read_ahead.non_sequential,
	    stats->read_ahead.detected,
	    stats->read_ahead.not_detected,
	    stats->read_ahead.factored,
	    stats->read_ahead.not_factored
	);
	log_flush(lg);
}

int
ccow_ucache_idx(ucache_t *uc, uint512_t *chid)
{
	/* calulcate position in cache */
	uint32_t hv;
	int i;

	FNV_hash(chid, sizeof (uint512_t), global_seed, &hv);
	i = hv % uc->size_cur;

	return i;
}

int
ccow_set_usertimer_callback(struct ccow *tc, ccow_usertimer_cb_t cb, void *arg)
{

	pthread_rwlock_rdlock(&mtc_lock);
	if (tc->user_timer_cb != NULL) {
		pthread_rwlock_unlock(&mtc_lock);
		return EBUSY;
	}

	tc->user_timer_cb = cb;
	tc->user_timer_arg = arg;
	pthread_rwlock_unlock(&mtc_lock);

	return 0;
}

int
ccow_clear_usertimer_callback(struct ccow *tc)
{

	pthread_rwlock_rdlock(&mtc_lock);
	if (tc->user_timer_cb == NULL) {
		pthread_rwlock_unlock(&mtc_lock);
		return ENOENT;
	}
	tc->user_timer_cb = NULL;
	tc->user_timer_arg = NULL;
	pthread_rwlock_unlock(&mtc_lock);
	return 0;
}

void
ccow_ucache_timer_worker(void * arg)
{
	struct ccow * tc = arg;
	ccow_usertimer_cb_t ut_cb;
	void *ut_arg;

	pthread_rwlock_rdlock(&mtc_lock);
	ut_cb = tc->user_timer_cb;
	ut_arg = tc->user_timer_arg;
	ccow_isgw_service_update(tc);
	pthread_rwlock_unlock(&mtc_lock);

	if (ut_cb) {
		ut_cb(tc, ut_arg);
	}

	pthread_rwlock_rdlock(&mtc_lock);

	if (tc->shard_cache &&
	    !tc->shard_cache_inprog &&
	    (tc->shard_cache_timer_cnt++ >= 200)) {
	     /* pops every 100s */
	     tc->shard_cache_inprog = 1;
	     tc->shard_cache_timer_cnt = 0;
	     pthread_rwlock_unlock(&mtc_lock);
	     evict_sop_cache(tc);
	     pthread_rwlock_rdlock(&mtc_lock);
	     tc->shard_cache_inprog = 0;
	}

	if (tc->ucache_work_inprog == 0 || tc->ucache_terminate_worker) {
		goto _exit;
	}

	ucache_t * uc = tc->ucache;
	if (uc == NULL) {
		goto _exit;
	}

	int rv = uc_mi_get_meminfo(uc);
	if (rv != 0) {
		goto _exit;
	}

	if ((uc_mi_total == 0) || (uc_mi_free == 0)) {
		goto _exit;
	}

	assert(uc_mi_total != 0);
	assert(uc_mi_free  != 0);

	uc->tc->stats.ucache.total_ram = uc_mi_total;
	uc->tc->stats.ucache.free_ram  = uc_mi_free + uc_mi_buffered +
		uc_mi_cached;
	if (uc->tc->stats.ucache.free_ram > uc_mi_swapcached + 1)
		uc->tc->stats.ucache.free_ram -= uc_mi_swapcached;

	assert(uc->tc->stats.ucache.total_ram != 0);
	assert(uc->tc->stats.ucache.free_ram  != 0);

	double fp =
		(uc->tc->stats.ucache.free_ram * 100)/uc->tc->stats.ucache.total_ram;

	unsigned long free_pct = fp;

	uc->tc->stats.ucache.size_cur  = uc->size_cur;
	uc->tc->stats.ucache.size_inc  = uc->size_inc;
	uc->tc->stats.ucache.size_min  = uc->size_min;
	uc->tc->stats.ucache.size_max  = uc->size_max;
	uc->tc->stats.ucache.lru_count = uc->lru_count;

	uc->timer_count++;

	int i = (uc->size_cur - uc->size_min) / uc->size_inc;

	if ((i/4) <= ((int) uc->timer_count % 2)) {
		ccow_ucache_expand(uc, free_pct);
	}

	if ((i/4) >= ((int) uc->timer_count % 4)) {
		ccow_ucache_shrink(uc, free_pct);
	}

	ccow_ucache_evict(uc, free_pct);
	// ccow_print_stats(&uc->tc->stats);

_exit:
	tc->ucache_work_inprog = 0;

	if (tc->ucache_terminate_worker) {
		/*
		 * the worker has been asked to terminate.  sync up with
		 * ccow_ucache_free.
		 */
		pthread_rwlock_unlock(&mtc_lock);
		uv_barrier_wait(&tc->ucache_term_bar);
	} else
		pthread_rwlock_unlock(&mtc_lock);
}

static void
ccow_ucache_timer_after(void * arg, int status)
{
	struct ccow * tc = arg;
}

static void
ccow_ucache_timer_cb(uv_timer_t* handle, int status)
{
	struct ccow * tc = handle->data;

	pthread_rwlock_rdlock(&mtc_lock);

	if (tc != mtc) {
		pthread_rwlock_unlock(&mtc_lock);
		return;
	}

	if (tc->ucache_work_inprog != 0 || tc->ucache_terminate_worker) {
		pthread_rwlock_unlock(&mtc_lock);
		return;
	}

	tc->ucache_work_inprog = 1;

	pthread_rwlock_unlock(&mtc_lock);

	struct ccowtp_stat tpstat = {0};
	ccowtp_stat(tc->tp, &tpstat);

	if (tc->tp_stat_counter >= 60000) {
		tc->tp_stat_counter = 0;
		log_info(lg, "CCOW TPStat(%p): util curr/max (abs): %lu%%/%lu%%"
			" (%lu/%lu), pend %lu", tc, tpstat.busy_ratio[0],
			tpstat.busy_max_ratio[0], tpstat.busy[0],
			tpstat.busy_max[0], tpstat.pending[0]);
	}
	tc->tp_stat_counter += UCACHE_TIMER_REPEAT;
	if (tpstat.pending[0] > 1)
		log_warn(lg, "CCOW TP(%p) pending works %lu, busy workers %lu",
			tc, tpstat.pending[0], tpstat.busy[0]);

	ccowtp_work_queue(tc->tp, 0, ccow_ucache_timer_worker,
	    ccow_ucache_timer_after, tc);
}

ucache_t*
ccow_ucache_create(struct ccow *tc)
{
	ucache_t *uc = je_calloc(1, sizeof (ucache_t));
	if (!uc)
		return NULL;

	tc->ucache_work_inprog = 0;
	tc->ucache_terminate_worker = 0;

	log_info(lg, "Creating tenant ucache size of %lu", tc->tenant_ucache_size);
	uc->cache = je_calloc(tc->tenant_ucache_size, sizeof (ucache_entry_t));
	if (!uc->cache) {
		je_free(uc);
		return NULL;
	}

	uc->size_cur = tc->tenant_ucache_size;
	uc->size_min = uc->size_cur;
	uc->size_inc = uc->size_cur;
	uc->size_max = tc->tenant_ucache_size_max;

	assert(uc->size_cur != 0);
	assert(uc->size_max != 0);
	assert(uc->size_max > uc->size_min);

	QUEUE_INIT(&uc->lru_q);

	int err = uv_mutex_init(&uc->uc_pos_mutex);
	if (err) {
		uc->size_cur = 0;
		je_free(uc->cache);
		je_free(uc);
		return NULL;
	}

	uc->tc = tc;

	struct sysinfo si;
	int rv = sysinfo(&si);
	assert(rv == 0);

	log_info(lg, "Total ram memory on the server: %ld", si.totalram);

	long mem_limit = 0;
	char *env_memlim = getenv("CCOW_MEMORY_LIMIT");
	if (env_memlim) {
		mem_limit = atoll(env_memlim);
	} else if (is_embedded()) {
		mem_limit = UCACHE_MEMLIMIT_EMBEDDED;
	}
	tc->stats.ucache.mem_limit = mem_limit;
	tc->stats.ucache.ucsize_max = si.totalram;
	tc->stats.ucache.ucsize_lim = (si.totalram * tc->ucache_size_limit) / 100;
	log_info(lg, "Tenant ucache memory limits: %ld/%ld",
	    tc->stats.ucache.ucsize_lim, mem_limit);

	return uc;
}

void
ccow_ucache_expand(ucache_t *uc, unsigned long fp)
{
	uv_mutex_lock(&uc->uc_pos_mutex);

	if (uc->lru_count < uc->size_cur) {
		/* there is empty space, no need to expand */
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return;
	}

	if (fp < UCACHE_FREE_SPACE_LIM) {
		/* there's not enough freeram to expand */
		uc->tc->stats.ucache.expand_nomem++;
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return;
	}

	/* do not expand if already at max */
	if (uc->size_cur == uc->size_max) {
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return;
	}

	if (QUEUE_EMPTY(&uc->lru_q)) {
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return;
	}

	/* expand */
	uc->tc->stats.ucache.expands++;

	/* move the LRU queue to a temporary queue header for now */
	QUEUE new_lru;
	QUEUE_NEXT(&new_lru) = QUEUE_NEXT(&uc->lru_q);
	QUEUE_PREV(&new_lru) = QUEUE_PREV(&uc->lru_q);
	QUEUE_PREV_NEXT(&uc->lru_q) = &new_lru;
	QUEUE_NEXT_PREV(&uc->lru_q) = &new_lru;
	QUEUE_INIT(&uc->lru_q);

	uc->size_cur += uc->size_inc;

	/* allocate new, bigger hash table */
	je_free(uc->cache);

	uc->cache = je_calloc(uc->size_cur, sizeof(ucache_hdr_t));

	if (uc->cache == NULL) {
		while(!QUEUE_EMPTY(&new_lru)) {
			QUEUE * lru = QUEUE_TAIL(&new_lru);
			ucache_entry_t * itm = QUEUE_DATA(lru, ucache_entry_t, lru_link);
			QUEUE_REMOVE(lru);

			uc->tc->stats.ucache.ucsize -= itm->value.len;

			je_free(itm->value.base);
			je_free(itm);
		}

		uc->size_cur = 0;
		uc->lru_count = 0;

		return;
	}

	uc->lru_count = 0;
	uc->tc->stats.ucache.ucsize = 0;

	uv_mutex_unlock(&uc->uc_pos_mutex);

	/* repopulate the hash table and LRU */
	while(!QUEUE_EMPTY(&new_lru)) {
		QUEUE * lru = QUEUE_TAIL(&new_lru);
		ucache_entry_t * itm = QUEUE_DATA(lru, ucache_entry_t, lru_link);
		QUEUE_REMOVE(lru);

		uv_buf_t buf;

		buf.base = itm->value.base;
		buf.len  = itm->value.len;
		ccow_ucache_put(uc, &itm->key, &buf, 1);
		je_free(itm->value.base);
		je_free(itm);
	}
}

void
ccow_ucache_evict_overwrite(void *arg, void *ch)
{
	ucache_t *ucache = (ucache_t *) arg;
	uint512_t *chid = ch;

	assert(ucache != NULL);
	assert(chid != 0);

	uv_mutex_lock(&ucache->uc_pos_mutex);

	if (ucache->uc_inprog) {
		ucache->tc->stats.ucache.inprogs++;
		uv_mutex_unlock(&ucache->uc_pos_mutex);
		return;
	}

	ucache->uc_inprog = 1;

	/* position in cache */
	int i = ccow_ucache_idx(ucache, chid);

	if (ucache->cache[i].count == 0) {
		/* empty cache entry, nothing to evict */
		ucache->uc_inprog = 0;
		uv_mutex_unlock(&ucache->uc_pos_mutex);
		return;
	}

	QUEUE * ent;
	ucache_entry_t * itm;

	QUEUE_FOREACH(ent, &ucache->cache[i].hdr) {
		itm = QUEUE_DATA(ent, ucache_entry_t, col_link);

		if (uint512_cmp(&itm->key, chid) == 0) {
			QUEUE_REMOVE(&itm->lru_link);
			QUEUE_REMOVE(&itm->col_link);

			ucache->lru_count--;
			ucache->tc->stats.ucache.ucsize -= itm->value.len;

			je_free(itm->value.base);
			je_free(itm);
			ucache->tc->stats.ucache.overwr_evicts++;

			ucache->uc_inprog = 0;
			uv_mutex_unlock(&ucache->uc_pos_mutex);
			return;
		}
	}

	ucache->uc_inprog = 0;
	uv_mutex_unlock(&ucache->uc_pos_mutex);
}

void
ccow_ucache_shrink(ucache_t *uc, unsigned long fp)
{
	uv_mutex_lock(&uc->uc_pos_mutex);

	/* do not shrink if free ram percentage is greater than limit */
	if (fp > UCACHE_FREE_SPACE_LIM)  {
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return;
	}

	/* do not shrink if already at the minimum */
	if (uc->size_cur == uc->size_min) {
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return;
	}

	/* shrink */
	uc->tc->stats.ucache.shrinks++;

	/* evict excess entries */
	uint64_t new_size = uc->size_cur - uc->size_inc;

	while(!QUEUE_EMPTY(&uc->lru_q)) {

		if (uc->lru_count <= new_size)
			break;

		QUEUE * lru = QUEUE_TAIL(&uc->lru_q);
		ucache_entry_t * itm = QUEUE_DATA(lru, ucache_entry_t, lru_link);
		QUEUE_REMOVE(lru);
		QUEUE_REMOVE(&itm->col_link);

		uc->lru_count--;

		je_free(itm->value.base);
		je_free(itm);
	}

	if (QUEUE_EMPTY(&uc->lru_q)) {
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return;
	}

	/* move the LRU queue to a temporary queue header for now */
	QUEUE new_lru;
	QUEUE_NEXT(&new_lru) = QUEUE_NEXT(&uc->lru_q);
	QUEUE_PREV(&new_lru) = QUEUE_PREV(&uc->lru_q);
	QUEUE_PREV_NEXT(&uc->lru_q) = &new_lru;
	QUEUE_NEXT_PREV(&uc->lru_q) = &new_lru;
	QUEUE_INIT(&uc->lru_q);

	uc->size_cur = new_size;

	/* allocate new, smaller hash table */
	je_free(uc->cache);
	uc->cache = je_calloc(uc->size_cur, sizeof(ucache_hdr_t));
	if (uc->cache == NULL) {
		log_debug(lg, "failed to allocate ucache");
		while(!QUEUE_EMPTY(&new_lru)) {
			QUEUE * lru = QUEUE_TAIL(&new_lru);
			ucache_entry_t * itm = QUEUE_DATA(lru, ucache_entry_t, lru_link);
			QUEUE_REMOVE(lru);

			uc->tc->stats.ucache.ucsize -= itm->value.len;

			je_free(itm->value.base);
			je_free(itm);
		}

		uc->size_cur = 0;
		uc->lru_count = 0;

		return;
	}

	uc->lru_count = 0;

	uv_mutex_unlock(&uc->uc_pos_mutex);

	/* repopulate the hash table and LRU */
	while(!QUEUE_EMPTY(&new_lru)) {
		QUEUE * lru = QUEUE_TAIL(&new_lru);
		ucache_entry_t * itm = QUEUE_DATA(lru, ucache_entry_t, lru_link);
		QUEUE_REMOVE(lru);
		uc->tc->stats.ucache.ucsize -= itm->value.len;

		uv_buf_t buf;

		buf.base = itm->value.base;
		buf.len  = itm->value.len;

		ccow_ucache_put(uc, &itm->key, &buf, 1);
		je_free(itm->value.base);
		je_free(itm);
	}
}

void
ccow_ucache_evict(ucache_t *uc, unsigned long fp)
{
	uint32_t count;
	uv_mutex_lock(&uc->uc_pos_mutex);

	/* do not evict if we have enough free ram percentage */
	if (fp > UCACHE_FREE_SPACE_LIM)
		count = 1;
	else
		count = UCACHE_EVICT_COUNT;

	/* evict */
	while(!QUEUE_EMPTY(&uc->lru_q)) {

		if (count-- == 0)
			break;

		QUEUE * lru = QUEUE_TAIL(&uc->lru_q);
		ucache_entry_t * itm = QUEUE_DATA(lru, ucache_entry_t, lru_link);
		QUEUE_REMOVE(lru);
		uc->tc->stats.ucache.ucsize -= itm->value.len;
		QUEUE_REMOVE(&itm->col_link);

		uc->lru_count--;

		je_free(itm->value.base);
		je_free(itm);
	}

	uv_mutex_unlock(&uc->uc_pos_mutex);
}

static void
ccow_ucache_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

void
ccow_ucache_free(struct ccow * tc)
{
	/*
	 * this function called while holding mtc_lock
	 */
	ucache_t *uc = tc->ucache;

	tc->ucache_terminate_worker = 1;
	if (tc->ucache_work_inprog != 0) {
		/*
		 * request and wait for worker to terminate.
		 */
		uv_barrier_wait(&tc->ucache_term_bar);
		uv_barrier_destroy(&tc->ucache_term_bar);
	}

	for (uint64_t i = 0; i < uc->size_cur; i++) {
		if (uc->cache[i].count > 0) {

			QUEUE * ent;
			ucache_entry_t * itm;

			while (!QUEUE_EMPTY(&uc->lru_q)) {
				QUEUE * ent = QUEUE_NEXT(&uc->lru_q);
				itm = QUEUE_DATA(ent, ucache_entry_t, lru_link);

				QUEUE_REMOVE(ent);
				QUEUE_REMOVE(&itm->col_link);

				uc->lru_count--;
				if (itm->value.base && itm->value.len)
					je_free(itm->value.base);
				je_free(itm);
			}
		}
	}

	uv_mutex_destroy(&uc->uc_pos_mutex);
	je_free(uc->cache);
	je_free(uc);
}

void
ccow_ucache_put(ucache_t *uc, uint512_t *chid, uv_buf_t *chunks, int nbufs)
{
	struct ccow *tc = uc->tc;

	tc->stats.ucache.puts++;

	/* evict what's old */
	uv_mutex_lock(&uc->uc_pos_mutex);

	if (uc->uc_inprog) {
		tc->stats.ucache.inprogs++;
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return;
	}

	if (uc->cache == NULL) {
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return;
	}

	uc->uc_inprog = 1;

	/* position in cache */
	int i = ccow_ucache_idx(uc, chid);

	if (uc->cache[i].count == 0) {
		/* empty cache entry, init the collision queue hdr */
		QUEUE_INIT(&uc->cache[i].hdr);
	}

	QUEUE * ent;
	ucache_entry_t * itm;

	QUEUE_FOREACH(ent, &uc->cache[i].hdr) {
		itm = QUEUE_DATA(ent, ucache_entry_t, col_link);

		if (uint512_cmp(&itm->key, chid) == 0) {

			QUEUE_REMOVE(&itm->lru_link);
			QUEUE_INSERT_HEAD(&uc->lru_q, &itm->lru_link);

			tc->stats.ucache.put_hits++;

			uc->uc_inprog = 0;
			uv_mutex_unlock(&uc->uc_pos_mutex);
			return;
		}
	}

	tc->stats.ucache.put_misses++;

	/* item was not found in queue, evict LRU item if cache is full to
	 * make room. */

	size_t used_total = tc->stats.ucache.total_ram - tc->stats.ucache.free_ram;
	int ucache_too_big = (tc->stats.ucache.mem_limit &&
	    tc->stats.ucache.ucsize >= tc->stats.ucache.mem_limit);

	if ((!QUEUE_EMPTY(&uc->lru_q)) &&
	    ((uc->lru_count == uc->size_cur) ||
	     (used_total >= tc->stats.ucache.ucsize_lim) || ucache_too_big)) {
		assert(uc->size_cur != 0);
		assert(uc->cache != NULL);

		ent = QUEUE_TAIL(&uc->lru_q);
		itm = QUEUE_DATA(ent, ucache_entry_t, lru_link);

		/* remove from LRU */
		QUEUE_REMOVE(ent);
		uc->lru_count--;

		QUEUE_REMOVE(&itm->col_link);
		int t = ccow_ucache_idx(uc, &itm->key);
		uc->cache[i].count--;

		if (itm->value.base && itm->value.len) {
			tc->stats.ucache.ucsize -= itm->value.len;
			je_free(itm->value.base);
		}

		tc->stats.ucache.put_evicts++;

	} else {
		itm = je_calloc(1, sizeof(ucache_entry_t));
		if (itm == NULL) {
			uc->uc_inprog = 0;
			uv_mutex_unlock(&uc->uc_pos_mutex);
			return;
		}
	}

	QUEUE_INSERT_HEAD(&uc->lru_q, &itm->lru_link);
	uc->lru_count++;

	QUEUE_INSERT_HEAD(&uc->cache[i].hdr, &itm->col_link);
	uc->cache[i].count++;

	/* put new in place */
	memcpy(&itm->key, chid, sizeof (uint512_t));

	size_t total_len = 0;
	for (int cidx = 0; cidx < nbufs; cidx++) {
		uv_buf_t *chunk = chunks + cidx;
		total_len += chunk->len;
	}

	itm->value.base = je_malloc(total_len);
	if (itm->value.base) {
		tc->stats.ucache.ucsize += total_len;
		size_t copied = 0;
		for (int cidx = 0; cidx < nbufs; cidx++) {
			uv_buf_t *chunk = chunks + cidx;
			memcpy((char *) itm->value.base + copied,
			    chunk->base, chunk->len);
			copied += chunk->len;
		}
		itm->value.len = total_len;
	}

	uc->uc_inprog = 0;
	uv_mutex_unlock(&uc->uc_pos_mutex);
}

int
ccow_ucache_get(ucache_t *uc, uint512_t *chid, uv_buf_t *buf)
{
	struct ccow *tc = uc->tc;

	tc->stats.ucache.gets++;

	uv_mutex_lock(&uc->uc_pos_mutex);

	if (uc->uc_inprog) {
		tc->stats.ucache.inprogs++;
		uv_mutex_unlock(&uc->uc_pos_mutex);
		return 0;
	}

	uc->uc_inprog = 1;

	/* position in cache */
	int i = ccow_ucache_idx(uc, chid);

	QUEUE * ent;
	ucache_entry_t * itm;

	if (uc->lru_count == 0) {
		QUEUE_INIT(&uc->lru_q);
	}

	if (uc->cache[i].count == 0) {
		QUEUE_INIT(&uc->cache[i].hdr);
	}

	QUEUE_FOREACH(ent, &uc->cache[i].hdr) {
		itm = QUEUE_DATA(ent, ucache_entry_t, col_link);

		if (itm->value.base && uint512_cmp(&itm->key, chid) == 0) {
			/* hit */
			tc->stats.ucache.hits++;

			buf->base = je_malloc(itm->value.len);
			if (buf->base) {
				memcpy(buf->base, itm->value.base,
				    itm->value.len);
				buf->len = itm->value.len;
			}

			uc->uc_inprog = 0;
			uv_mutex_unlock(&uc->uc_pos_mutex);
			return buf->base != NULL;
		}
	}

	/* miss */
	tc->stats.ucache.misses++;

	uc->uc_inprog = 0;
	uv_mutex_unlock(&uc->uc_pos_mutex);

	return 0;
}

int
ccow_ucache_get_uncomp(ucache_t *uc, uint512_t *chid, struct ccow_op *dest_op,
    int verify_chid, uint8_t hash_type, uint8_t compress_type,
    struct iovec *iov_out)
{
	int found;
	uv_buf_t compchunk;

	found = ccow_ucache_get(uc, chid, &compchunk);
	if (!found)
		return 0;

	struct hashuncomp ch;
	ch.status = 0;
	ch.chunk = (uv_buf_t *)iov_out;
	ch.data_in = &compchunk;
	ch.compress_type = compress_type;
	ch.nbufs = 1;
	ch.chid_in = chid;
	ch.hash_type = hash_type;
	ch.op = dest_op;
	ch.verify_chid = verify_chid;
	ch.rb_cached = 1;
	hashuncomp_one(&ch);

	je_free(compchunk.base);

	if (ch.status)
		return 0;

	/* hit and uncompressed successfully*/
	return 1;
}

/*
 * Return the system guid, stripped of -'s, must be free'd elsewhere.
 */
char *
ccow_get_system_guid_formatted(ccow_t tc)
{
	struct ccow *cl = (struct ccow *)tc;
	struct ccow_lookup *iter = NULL;
	struct ccow_completion *c;
	int err = 0;

	assert(cl);
	if (memcmp_quick(cl->tid, cl->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Operation not permitted");
		log_hexdump(lg, "TID:", cl->tid, cl->tid_size);
		return NULL;
	}

	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err)
		return NULL;
	err = ccow_admin_pseudo_get("", 1, "", 1, "", 1, "", 1, NULL, 0, 0,
	    CCOW_GET, c, &iter);
	if (err) {
		ccow_release(c);
		return NULL;
	}
	err = ccow_wait(c, 0);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		log_warn(lg, "System unitialized, please run system init.");
		return NULL;
	}

	char *system_guid = NULL;
	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_CUSTOM, pos++))) {
		if (kv->type == CCOW_KVTYPE_RAW) {
			if (!strcmp(kv->key, RT_SYSKEY_SYSTEM_GUID)) {
				system_guid = je_memdup((char *)kv->value,
				    kv->value_size);
			}
		}
	}
	if (iter)
		ccow_lookup_release(iter);
	if (!system_guid) {
		log_error(lg, "System unitialized, please run system init.");
		return NULL;
	}
	//
	// FIXME: there may be a much more efficient string lib for this..
	//
	//  XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	char *system_guid_buf = je_calloc(1, SYSTEM_GUID_BUF_LEN);
	if (!system_guid_buf) {
		if (system_guid)
			je_free(system_guid);
		log_error(lg, "Unable to allocate guid buffer, -ENOMEM");
		return NULL;
	}
	memcpy(system_guid_buf, system_guid, 8);
	memcpy(system_guid_buf + 8, system_guid + 9, 4);
	memcpy(system_guid_buf + 12, system_guid + 14, 4);
	memcpy(system_guid_buf + 16, system_guid + 19, 4);
	memcpy(system_guid_buf + 20, system_guid + 24, 12);

	log_info(lg, "system_guid: %s", system_guid_buf);

	if (system_guid)
		je_free(system_guid);

	return system_guid_buf;

}

#define CCOW_SHM_BASE  2121

int
ccow_init_shmseg()
{
	int shmid;
	int created = 0;
	void *ret_seg = NULL;
	int key = CCOW_SHM_BASE + 2;

	// locate the segment first
	if ((shmid = shmget(key, sizeof(struct ccow_shm_process)*CCOW_MAX_PROCESS + sizeof(uint64_t), 0666)) < 0) {
		// not found so we create it
		if ((shmid = shmget(key, sizeof(struct ccow_shm_process)*CCOW_MAX_PROCESS + sizeof(uint64_t), IPC_CREAT | 0666)) < 0) {
			log_error(lg, "Unable to create a shared memory segment "
			    " error: %d ", shmid);
			return shmid;
		} else {
			created = 1;
		}
	}
	if ((ret_seg = shmat(shmid, NULL, 0)) == (char *) -1) {
		log_error(lg, "Unable to attach to the the shared memory segment"
		    " error: %d", errno);
		return -errno;
	}

	// just making sure that if this is a newly created we set it to zero
	if (created)
		memset(ret_seg, 0, sizeof(struct ccow_shm_process)*CCOW_MAX_PROCESS+sizeof(uint64_t));

	ccow_process_table = (struct ccow_shm_process *)  ret_seg;
	ccow_glock_mem = (uint64_t *)((char *)ret_seg + sizeof(struct ccow_shm_process)*CCOW_MAX_PROCESS);

	return 0;
}

#define CCOW_GLOCK_ATTEMPTS_SECS	10

void
ccow_glock()
{
	int counter = 0;
	while (CAS(ccow_glock_mem, 0, 1) && counter++ < CCOW_GLOCK_ATTEMPTS_SECS * 1000)
		usleep(1000);
	if (counter >= CCOW_GLOCK_ATTEMPTS_SECS * 1000) {
		log_error(lg, "Forcefully reseting global initiator lock");
		*ccow_glock_mem = 1;
	}
}

void
ccow_gunlock()
{
	while (CAS(ccow_glock_mem, 1, 0))
		usleep(1000);
}

int
ccow_add_proc(uint32_t if_speeds[], int if_count)
{
	int pid = (int) getpid();

	ccow_glock();

	for (int i = 0; i < CCOW_MAX_PROCESS; i++) {
		struct ccow_shm_process *proc = &ccow_process_table[i];
		if (proc->pid == pid) {
			myproc = proc;
			proc->ts = get_timestamp_us();
			proc->alive = CCOW_PROC_ALIVE;
			ccow_gunlock();
			return 0;
		}
	}

	for (int i = 0; i < CCOW_MAX_PROCESS; i++) {
		struct ccow_shm_process *proc = &ccow_process_table[i];
		if (proc->alive != CCOW_PROC_ALIVE) {
			myproc = proc;
			proc->pid = pid;
			proc->ts = get_timestamp_us();
			proc->alive = CCOW_PROC_ALIVE;
			proc->if_count = if_count;
			for (int j = 0; j < if_count; j++) {
				replicast_vbuf_init(&proc->vbuf[j], if_speeds[j]);
			}
			ccow_gunlock();
			return 0;
		}
	}

	ccow_gunlock();

	// empty slot not found
	return -1;
}


void
ccow_pscan_timer_worker(void * arg)
{
	struct ccow *tc = arg;

	/* serializing TC term */
	uv_mutex_lock(&tc->pscan_timer_lock);

	if (tc->pscan_work_inprog == 0 || tc->pscan_terminate_worker)
		goto _exit;

	int mypid = (int) getpid();
	uint64_t ifsum[REPLICAST_SRV_INTERFACES_MAX] = {0};

	if (!tc->netobj) {
		log_warn(lg, "Network not initialized. Skipping proc update");
		goto _exit;
	}

	ccow_glock();

	for (int i = 0; i < CCOW_MAX_PROCESS; i++) {
		struct ccow_shm_process *proc = &ccow_process_table[i];
		if (proc->ts && (proc->alive == CCOW_PROC_ALIVE)) {
			/* if this guy has not been updated in the last
			 * 900ms, mark it dead
			 */
			if ((proc->ts + 900000) < get_timestamp_us()
			    && (proc->pid != mypid)) {
				proc->ts = 0;
				proc->alive = CCOW_PROC_DEAD;
				log_debug(lg, "proc %d found dead", proc->pid);
				/* skip dead slot's reserved capacity */
				continue;
			}
			for (int j = 0; j < ifvbuf->if_count; j++) {
				ifsum[j] += proc->vbuf[j].reserved;
			}
		}
		if (proc->pid == mypid) {
			/* update my proc status */
			proc->ts = get_timestamp_us();
			proc->alive = CCOW_PROC_ALIVE;
		}
	}

	ccow_gunlock();

	/* now update local physical capacity based on proc gatherings */
	for (int i = 0; i < ifvbuf->if_count; i++) {
		ifvbuf->pvbuf[i].reserved = ifsum[i];
	}

	/* update link status ~ every 5s */
	if (iflink_update_ts && iflink_update_ts + 5000000UL > get_timestamp_us())
		goto _exit;

	iflink_update_ts = get_timestamp_us();

	for (int i = 0; i < ifvbuf->if_count; i++) {
		char ifname[IF_NAMESIZE];
		uint32_t speed;
		uint8_t duplex, link_status;
		int mtu;

		if (if_indextoname(tc->netobj->if_indexes[i], ifname) == NULL)
			continue;

		int err = ethtool_info(ifname, &speed, &duplex, &link_status, &mtu);
		if (err) {
			log_warn(lg, "Interface %s not answering to ETHTOOL requests",
			    ifname);
			continue;
		}
		int speed_check = (int) speed;
		if (speed_check != -1 && speed != tc->netobj->if_speeds[i]) {
			log_notice(lg, "Interface %s speed changed from %u to %u Mbps",
			    ifname, tc->netobj->if_speeds[i], speed);
			replicast_vbuf_link_update(&tc->netobj->robj[i]->rvbuf, speed);
			replicast_vbuf_link_update(&ifvbuf->pvbuf[i], speed);
			tc->netobj->if_speeds[i] = speed;
		}
	}

_exit:
	tc->pscan_work_inprog = 0;

	if (tc->pscan_terminate_worker) {
		/*
		 * the worker has been asked to terminate.  sync up with
		 * tc term routine.
		 */
		uv_mutex_unlock(&tc->pscan_timer_lock);
		uv_barrier_wait(&tc->pscan_term_bar);
	} else
		uv_mutex_unlock(&tc->pscan_timer_lock);
}

void
ccow_pscan_timer_after(void * arg, int status)
{
	struct ccow *tc = arg;
	pthread_rwlock_rdlock(&mtc_lock);
	if (tc == mtc)
		mtc_inprog = 0;
	pthread_rwlock_unlock(&mtc_lock);
}

void
ccow_pscan_timer_cb(uv_timer_t* handle, int status)
{
	struct ccow *tc = handle->data;

	pthread_rwlock_rdlock(&mtc_lock);
	if (tc != mtc || mtc_inprog) {
		/* skip non-MTC contexts and in-progress*/
		pthread_rwlock_unlock(&mtc_lock);
		return;
	}
	mtc_inprog = 1;

	uv_mutex_lock(&tc->pscan_timer_lock);
	if (tc->pscan_work_inprog || tc->pscan_terminate_worker) {
		mtc_inprog = 0;
		uv_mutex_unlock(&tc->pscan_timer_lock);
		pthread_rwlock_unlock(&mtc_lock);
		return;
	}

	tc->pscan_work_inprog = 1;
	uv_mutex_unlock(&tc->pscan_timer_lock);
	pthread_rwlock_unlock(&mtc_lock);

	ccowtp_work_queue(tc->tp, 0, ccow_pscan_timer_worker, ccow_pscan_timer_after, tc);
}

static void
signal_handler(int signum)
{
	static int terminating = 0;

	if (terminating) {
		log_warn(lg, "Received signal [%s] while exiting! Ignoring..",
		    strsignal(signum));
		return;
	}

	if (signum == SIGHUP) {
		Logger_hup(lg);

		if (signal_tgtd != NULL)
			signal_tgtd(signum);

		return;
	}
	terminating = 1;
	log_error(lg, "Received signal [%s]! Terminating..", strsignal(signum));

	signal(signum, SIG_DFL);
	raise(signum);
}

void
ccow_hup_lg(void)
{
	static int called = 0;

	if (called) {
		return;
	}
	called = 1;

	signal(SIGHUP, signal_handler);
}

/* Is new region subset (or proper subset) of this region? */
int
ccow_region_subset(ccow_region_t this_region, ccow_region_t new_region)
{
	return new_region->off >= this_region->off &&
		new_region->off + new_region->len <=
		this_region->off + this_region->len;
}

/* Does new region intersect with this region? */
int
ccow_region_intersects(ccow_region_t this_region, ccow_region_t new_region)
{
	return	ccow_region_subset(this_region, new_region) ||
		ccow_region_subset(new_region, this_region) ||
		(this_region->off < new_region->off &&
		new_region->off < this_region->off + this_region->len) ||
		(new_region->off < this_region->off &&
		this_region->off < new_region->off + new_region->len);
}

int
ccow_is_region_empty(ccow_region_t this_region)
{
	return this_region->off == 0 && this_region->len == 0;
}

/*
 * Return a intersection b.
 */
void
ccow_region_intersection(ccow_region_t a, ccow_region_t b, ccow_region_t in)
{
	in->off = in->len = 0;

	/* Don't intersect, return empty sets */
	if (!ccow_region_intersects(a, b))
		return;

	if (ccow_region_subset(a, b)) {
		in->off = a->off == b->off ? a->off : b->off;
		in->len = b->len;
	} else if (ccow_region_subset(b, a)) {
		in->off = a->off == b->off ? b->off : a->off;
		in->len = a->len;
	} else {
		in->off = a->off < b->off ? b->off : a->off;
		in->len = a->off < b->off ? (a->off + a->len) - b->off :
					    (b->off + b->len) - a->off;
	}
}
/*
 * Return a - b.
 * diff could create a left part and right part.
 */
void
ccow_region_diff(ccow_region_t a, ccow_region_t b,
		 ccow_region_t left_region, ccow_region_t right_region)
{
	left_region->off = left_region->len = 0;
	right_region->off = right_region->len = 0;

	/* If a and b are proper subsets or don't intersect, return empty sets */
	if ((a->off == b->off && a->len == b->len) ||
	    !ccow_region_intersects(a, b))
		return;

	if (ccow_region_subset(a, b)) {
		left_region->off = a->off == b->off ? 0 : a->off;
		left_region->len = b->off - a->off;

		right_region->off = b->off + b->len == a->off + a->len ? 0 :
				    b->off + b->len;
		right_region->len = (a->off + a->len) - (b->off + b->len);
	} else if (ccow_region_subset(b, a)) {
		left_region->off = a->off == b->off ? 0 : b->off;
		left_region->len = a->off - b->off;

		right_region->off = b->off + b->len == a->off + a->len ? 0 :
				    a->off + a->len;
		right_region->len = (b->off + b->len) - (a->off + a->len);
	} else {
		left_region->off = a->off < b->off ? a->off : b->off;
		left_region->len = a->off < b->off ? b->off - a->off :
						     a->off - b->off;

		right_region->off = a->off < b->off ? a->off + a->len :
						      b->off + b->len;
		right_region->len = a->off < b->off ?
				    (b->off + b->len) - (a->off + a->len) :
				    (a->off + a->len) - (b->off + b->len);
	}
}


/**
 * Create nhid based inode number
 *
 * @param nhid name hash id
 * @param nhid_size name hash id size
 * @param inode_number - output inode number pointer
 * @returns 0 on success, negative error code on failure
 */
int
ccow_object_inode_number(void *nhid, size_t nhid_size, uint64_t *inode_number) {
	 int err;
	 uint512_t tmp;


	 err = crypto_hash_with_type(HASH_TYPE_XXHASH_64,
	            (uint8_t *)nhid, nhid_size, (uint8_t *)&tmp);
	 if (err)
	    return err;


	 uint64_t res = tmp.u.u.u & 0xFFFFFFFFFFFFFFFULL;
	 // Setup type 3 for object
	 uint64_t inode_type = 3;

	 res = res | (inode_type << 60);

     *inode_number = res;
	 return 0;
}

int
ccow_ec_timeout_expired(const struct vmmetadata *md) {
	int rc = 0;
	if (md->ec_enabled && md->uvid_timestamp &&
		GET_TRG_POLICY_TYPE(md->ec_trg_policy) == EC_TRG_POLICY_TIMEOUT) {
		uint64_t ts_current = get_timestamp_us();
		uint64_t ts_expiration = md->uvid_timestamp +
			GET_TRG_POLICY_VALUE(md->ec_trg_policy)*1000000LL;
		if (GET_TRG_POLICY_VALUE(md->ec_trg_policy) > EC_UNENCODE_AHEAD_DELAY)
			ts_expiration -= EC_UNENCODE_AHEAD_DELAY*1000000LL;
		rc = ts_current > ts_expiration;
	}
	return rc;
}

uint64_t
ccow_lost_response_delay_ms(struct ccow *tc) {
	return lost_response_delay_ms(tc->netobj);
}

uint64_t
ccow_consensus_delay_ms(struct ccow *tc) {
	uint64_t lc_send_time = *(volatile uint64_t *)&tc->last_consensus_send_time;
	uint64_t lc_recv_time = *(volatile uint64_t *)&tc->last_consensus_recv_time;
	if (!lc_send_time || !lc_recv_time)
		return 0;
	if (lc_recv_time > lc_send_time)
		return 0;
	return (lc_send_time - lc_recv_time)/1000;
}

uint32_t
ccow_chunk_size(ccow_completion_t c) {
	return c->chunkmap_chunk_size;
}

uint64_t
ccow_logical_size(ccow_completion_t c) {
	return c->logical_sz;
}

uint64_t
ccow_trlog_quarantine(struct ccow *tc) {
	return tc->trlog_quarantine;
}

uint64_t
ccow_trlog_interval_us(struct ccow *tc) {
	return tc->trlog_interval_us;
}

struct evloop_marshal_request {
	struct state state;
	struct state* tgt_state;
	int event;
};

/* Code for cross-tenant context event marshaling */
static void
tc_marshal__send(struct state *st) {
	struct evloop_marshal_request* r = st->data;
	state_event(r->tgt_state, r->event);
}

static void
tc_marshal__term(struct state *st) {
	struct evloop_marshal_request* r = st->data;
	je_free(r);
}

static const struct transition elmarsh_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_ANY,  EV_CALL, &tc_marshal__send, ST_TERM, NULL },
};

void
tc_marshal_call(struct state* st_tgt, ccow_t tc, int event) {
	struct evloop_marshal_request* r = je_calloc(1,sizeof(*r));
	r->state.table = elmarsh_tbl;
	r->state.cur = ST_INIT;
	r->state.max = sizeof(elmarsh_tbl) / sizeof(*elmarsh_tbl);
	r->state.term_cb = tc_marshal__term;
	r->state.data = r;
	r->event = event;
	r->tgt_state = st_tgt;

	if (tc->main_thread == uv_thread_self()) {
		state_event(&r->state, EV_CALL);
	} else {
		while (lfqueue_enqueue(tc->api_lfq_hp, &r->state) != 0) {
			usleep(250);
		}
		uv_async_send(&tc->api_call);
	}
}

static void
ccow_chunk_lookup_cb(struct getcommon_client_req *r) {
	struct ccow_io *io = r->io;
	assert(io);
	struct ccow_op *op = io->op;
	assert(op);
	ccow_completion_t c = op->comp;
	assert(c);

	c->replication_count = (int64_t)r->chunkmap_data;
}

int
ccow_chunk_lookup(ccow_completion_t c, const uint512_t* chid, const uint512_t* ngchid,
	int ht, uint64_t attr, int repCnt) {

	struct ccow_op *get_op;
	struct ccow_io *get_io;
	int rc = 0;

	int err = ccow_operation_create(c, CCOW_GET, &get_op);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_unnamedget_create(c, ccow_chunk_lookup_cb,
		get_op, &get_io, NULL);
	if (err) {
		ccow_operation_destroy(get_op, 1);
		ccow_release(c);
		return err;
	}

	get_io->attributes |= RD_ATTR_GET_CONSENSUS | RD_ATTR_CHUNK_LOOKUP | attr;

	struct getcommon_client_req *req = CCOW_IO_REQ(get_io);
	rtbuf_t *rb = NULL;

	req->chid = *chid;
	req->ng_chid = *ngchid;
	req->hash_type = ht;
	req->chunkmap_data = (void*)((int64_t)repCnt);

	err = ccow_start_io(get_io);
	if (err) {
		ccow_operation_destroy(get_op, 1);
		ccow_release(c);
		return err;
	}
	return 0;
}

