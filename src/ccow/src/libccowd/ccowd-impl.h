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
#ifndef __CCOWD_IMPL_H__
#define __CCOWD_IMPL_H__

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "json.h"
#include "replicast.h"
#include "clengine.h"
#include "trlog.h"
#include "auditc.h"
#include "flexhash.h"
#include "serverid.h"
#include "ccowd.h"
#include "msort.h"
#include "enc_host.h"
#include "ccowtp.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define STARTUP_SLEEP_TIME (250 * 1000)		/* time before init exit */
#define STARTUP_THREAD_SYNC_NUM	2		/* number of threads to
						   syncrhonize at startup */

#define CCOWD_CLENGINE		"corosync"	/* default cluster engine */
#define CCOWD_NETWORK_MC_TTL	4		/* default multicast TTL */
#define CCOWD_MCBASE_ADDR	"FF02::C:0:0:0"	/* default Mulit-Cast base */
#define CCOWD_MCBASE4_ADDR	"234.0.0.0"	/* default IPv4 Mulit-Cast base */
#define CCOWD_MCBASE_PORT	10399		/* default CCOW MC port */
#define CCOWD_RLIMIT_NOFILE	131072

#define CCOWD_CACHESZ_UMANIFEST 4*1024
#define CCOWD_CACHESZ_UDATA	CCOWD_CACHESZ_UMANIFEST
#define CCOWD_CACHE_POLICY_HRU	1

/*
 * libccow overrides for daemon's internal BG jobs
 */
#define CCOWD_UCACHE_SIZE (1 * 1024)
#define CCOWD_UCACHE_SIZE_MAX (4 * 1024)
#define CCOWD_CMCACHE_HASH_SIZE (8 * 1024)

/*
 * drive's ports are dynamically assigned and will be following this base,
 * i.e. 10401, 10402, etc..
 */
#define CCOWD_BASE_PORT		10400		/* default CCOW daemon port */
#define CCOWD_GW_CACHE_PORT	60001

#define CCOWD_CONF_DIR		"%s/etc/ccow"
#define CCOWD_CONF_FILE		"ccowd.json"
#define CCOW_CONF_FILE		"ccow.json"

#define CCOW_AUDITC_NS		"ccow"

#define CCOW_HOST_STATS_START_TIMER_MS	1000
#define CCOW_HOST_STATS_TIMER_MS	5000
#define	CCOW_DEV_WAL_FLUSH_TIMEOUT	5000
#define CCOWD_DEV_WAL_FLUSH_INTERVAL 5000

#define CCOW_FLEXHASH_STATS_START_TIMER_MS	10000
#define CCOW_FLEXHASH_STATS_TIMER_MS		(300LU * 1000)

#define CCOW_LICENSE_START_TIMER_MS	(1200 * 1000)
#define CCOW_LICENSE_TIMER_MS		(6LU * 3600 * 1000)

#define CCOW_TRAN_START_TIMER_MS	(60 * 1000)
#define CCOW_HEALTHY_UPDATE_TIMER_MS	(10 * 1000)

#define CCOW_GW_CACHE_TIMER_MS		(5 * 1000UL)

#define CCOW_DEV_HB_TIMER_MS		(DEV_PERFMON_TIMER_MS + 1000)
#define CCOWD_DEV_HB_LIMIT		200

#define CCOW_MAX_TRANSPORTS		16

#define SHARD_VDEV_PREFIX		"shard.vdev."

#define CCOW_EVAC_URL			"tcp://127.0.0.1"
#define CCOW_EVAC_NN_PORT		"10900"

#define CCOWD_TP_PRIO_HI	0
#define CCOWD_TP_PRIO_NORMAL	1

#define LOCATE_MATCH_VBR_ATTR (1<<0) /* Count only VBRs with specified attribute */
#define LOCATE_MATCH_REFCHID  (1<<1) /* Could only VBRs with specified refCHID */
#define LOCATE_MATCH_VBR      (1<<2) /* Find a specific VBR */
#define LOCATE_FLAG_ROWEVAC   (1<<3) /* The row evacuation task is in progres on a VDEV */
#define LOCATE_FLAG_HAS_PM    (1<<4) /* The manifest has corresponding parity manifest */
#define LOCATE_SKIP_WO_VBRS   (1<<5) /* Skip entries without VBR(s) */

/*
 * Implementation of ccow daemon object
 */
struct ccowd {
	uv_loop_t *loop;		/* cluster event loop */
	unsigned long loop_thrid;	/* main loop thread id */
	uv_thread_t main_thread;	/* thread where daemon loop loops */
	uv_thread_t main_watcher;	/* watcher for daemon loop */
	json_value *opts;		/* parsed cluster configuration */
	int unicastio;			/* replicast_send() config */
	int sync_put_named;		/* selected sync put named cnt */
	int track_statistics;		/* override for MD ccow-track-statistics */
	uv_barrier_t main_barrier;	/* syncrhonization on start */
	uv_async_t exit_handle;		/* exit handler */

	uv_rwlock_t fh_lock;		/* to be used during flexhash rebuild */
	uv_mutex_t fh_mutex;		/* used for cond wait cases */
	uv_cond_t fh_condv;		/* to be used during flexhash rebuild */
	volatile struct flexhash *flexhash;	/* Flexhash Table for this ccowd */
	int flexhash_version;		/* changed everytime a new one is updated */
	uv_async_t auditc_message;	/* Audit client door bell */
	uv_async_t clengine_rebuild_message;	/* SIGUSR1 clengine rebuild door bell */
	uv_async_t clengine_rebuild_message_no_cp; /* SIGUSR2 clengine rebuild door bell */
	auditc_link *aclink;		/* Audit client link and IPC */
	uv_poll_t ipc_req;		/* for IPC message pipe */
	int startup_err;		/* set to non-0 in case of start err */
	uv_timer_t host_stats_timer;	/* periodic host stats timer */
	uv_timer_t tran_timer;		/* periodic transaction processing timer */
	uv_timer_t gw_cache_timer;      /* periodic gateway cache timer */
	uv_timer_t fhstats_timer;	/* periodic device/fh stats timer */
	uv_timer_t devhb_timer;		/* device heart-beat timer */
	uv_timer_t wal_flush_timer;
	uv_timer_t healthy_timer;
	int hb_progress;
	int flush_progress;
	uint32_t hb_limit;
	uint32_t wal_flush_interval;	/* value in msec for flushing WAL */
	int scrub_signal_rcvd;		/* indicates that scrub signal received */

	/* TRLOG globals (copy) */
	uint64_t trlog_interval_us;
	uint64_t trlog_quarantine;

	volatile uint64_t leader_batch_seq_ts;	/* trlog coordinated signal from leader */
	volatile uint64_t local_batch_seq_ts;	/* trlog local inprog batch seq from leader */
	volatile uint64_t leader_coordinated_ts;	/* keeps timestamp of inprog TRLOG flush seqid */
	volatile uint64_t local_coordinated_ts;	/* keeps timestamp of inprog TRLOG flush seqid (local timestamp )*/
	volatile int skip_cp;		/* Skip checkpoint for the next rebalance, set by sigusr2 */
	volatile int bg_restart;	/* Restart BG jobs */
	ccowd_host_enc_t *enc_ctx;

	/* Cluster ring configuration */
	char *clengine;

	/* Replicast main-thread configuration */
	struct replicast *robj[REPLICAST_SRV_INTERFACES_MAX];
	int if_indexes[REPLICAST_SRV_INTERFACES_MAX];
	uint32_t if_speeds[REPLICAST_SRV_INTERFACES_MAX];
	char if_names[REPLICAST_SRV_INTERFACES_MAX][64];
	int if_indexes_count;
	int server_if_index;
	char *unix_socket_addr;
	char *server_ip6addr;
	char *server_ip4addr;
	char *msg_origin_addr;
	uint16_t server_port;
	char *mcbase_ip4addr;
	char *mcbase_ip6addr;
	struct sockaddr_in6 server_sockaddr;
	struct sockaddr_in6 msg_origin_sockaddr;
	struct sockaddr_in6 mcbase_sockaddr;
	uint16_t mcbase_port;
	uint16_t zone;
	int mc_ttl;
	uint16_t license_checked;

	/* Transports */
	int transport_count;
	char *transport_name[CCOW_MAX_TRANSPORTS];
	volatile uint16_t leader;
	volatile int tran_running;
	volatile int role_changed;
	struct trlog_handle trhdl;
	/* Delta of failure domain count between flexhash versions
	 * +ve number indicates the numbers of failure domains added
	 * -ve number indicates the number of failure domains removed
	 * zero indicates no change
	 */
	int fddelta;
	struct ccowd_params *params;

	clengine_hb_t clengine_hb;
	int do_core_dump;
	struct ccowtp* tp; /* ccowd's private thread pool */
	int keep_corrupted;
	uint64_t maintenance_ts;
};


#define SERVER_FLEXHASH ccow_daemon->flexhash
#define SERVER_FLEXHASH_SAFE_CALL(exp, locktype) do { \
	ccowd_fhready_lock(locktype); \
	(exp); \
	ccowd_fhready_unlock(locktype); \
} while (0);

extern struct ccowd *ccow_daemon;

#define COORDINATED_TS() \
	(ccow_daemon->leader_coordinated_ts + \
		(get_timestamp_us() - ccow_daemon->local_coordinated_ts))


int ccowd_read_file(const char *filename, rtbuf_t **prb);
void ccowd_wait_for_fhrebuild_term(volatile int* term);
void ccowd_set_fhrebuild_is_done();
void ccow_daemon_process_shutdown();

#define ccowd_fhready_lock(locktype) do \
{ \
	/*log_debug(lg, "FH_LOCK type=%d", locktype);*/ \
	if (locktype == FH_LOCK_READ) { \
		uv_rwlock_rdlock(&ccow_daemon->fh_lock); \
	} else if (locktype == FH_LOCK_WRITE) { \
		uv_rwlock_wrlock(&ccow_daemon->fh_lock); \
	} \
} while (0)

#define ccowd_fhready_unlock(locktype) do \
{ \
	/*log_debug(lg, "FH_UNLOCK type=%d", locktype);*/ \
	if (locktype == FH_LOCK_READ) { \
		uv_rwlock_rdunlock(&ccow_daemon->fh_lock); \
	} else if (locktype == FH_LOCK_WRITE) { \
		uv_rwlock_wrunlock(&ccow_daemon->fh_lock); \
	} \
} while (0)

#define auditc(o, ...) \
	auditc_##o(ccow_daemon->aclink, ##__VA_ARGS__); \
	uv_async_send(&ccow_daemon->auditc_message);

#define auditc_low(o, ...) \
	if (auditc_low_##o(ccow_daemon->aclink, ccowtp_pending(ccow_daemon->tp), ##__VA_ARGS__)) \
		uv_async_send(&ccow_daemon->auditc_message);

/* ccowd.<prefix>.<serverid>.<vdevid>.<phid>.<nhid>.<uint64val>: <value> */
#define auditc_obj_uint64(o, prefix, vdevid, ron, uint64val, ...) do { \
	char key[2 * (UINT512_BYTES * 2 + 1) + 2 * (UINT128_BYTES * 2 + 1) + 128]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	char nhid[UINT512_BYTES * 2 + 1]; \
	char phid[UINT512_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	uint512_dump(&(ron)->name_hash_id, nhid, UINT512_BYTES * 2 + 1); \
	uint512_dump(&(ron)->parent_hash_id, phid, UINT512_BYTES * 2 + 1); \
	sprintf(key, "%s.%s.%s.%s.%s.%"PRIu64, prefix, serverstr, vdevstr, phid, nhid, uint64val); \
	auditc(o, key, ##__VA_ARGS__); \
} while (0)

/* ccowd.<prefix>.<serverid>.<vdevid>.<phid>.<nhid>: <value> */
#define auditc_obj(o, prefix, vdevid, ron, ...) do { \
	char key[2 * (UINT512_BYTES * 2 + 1) + 2 * (UINT128_BYTES * 2 + 1) + 128]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	char nhid[UINT512_BYTES * 2 + 1]; \
	char phid[UINT512_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	uint512_dump(&(ron)->name_hash_id, nhid, UINT512_BYTES * 2 + 1); \
	uint512_dump(&(ron)->parent_hash_id, phid, UINT512_BYTES * 2 + 1); \
	sprintf(key, "%s.%s.%s.%s.%s", prefix, serverstr, vdevstr, phid, nhid); \
	auditc(o, key, ##__VA_ARGS__); \
} while (0)

/* ccowd.<prefix>.<serverid>.<vdevid>.<phid>.<nhid>: <value> */
#define auditc_low_obj(o, prefix, vdevid, ron, ...) do { \
	char key[2 * (UINT512_BYTES * 2 + 1) + 2 * (UINT128_BYTES * 2 + 1) + 128]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	char nhid[UINT512_BYTES * 2 + 1]; \
	char phid[UINT512_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	uint512_dump(&(ron)->name_hash_id, nhid, UINT512_BYTES * 2 + 1); \
	uint512_dump(&(ron)->parent_hash_id, phid, UINT512_BYTES * 2 + 1); \
	sprintf(key, "%s.%s.%s.%s.%s", prefix, serverstr, vdevstr, phid, nhid); \
	auditc_low(o, key, ##__VA_ARGS__); \
} while (0)

#define auditc_low_obj_rowevac(o, prefix, id, vdevid, tgt, row, total, processed, state) do { \
	char key[2 * (UINT128_BYTES * 2 + 1) + 128]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char tgtstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(tgt, tgtstr, UINT128_BYTES * 2 + 1); \
	uint64_t total1 = total; \
	uint64_t processed1 = processed; \
	uint64_t state1 = state; \
	sprintf(key, "%s.%lx.%s.%s.%s.%d.total", prefix, id, serverstr, vdevstr, tgtstr, row); \
	auditc(o, key, total1); \
	sprintf(key, "%s.%lx.%s.%s.%s.%d.evacuated", prefix, id, serverstr, vdevstr, tgtstr, row); \
	auditc(o, key, processed1); \
	sprintf(key, "%s.%lx.%s.%s.%s.%d.state", prefix, id, serverstr, vdevstr, tgtstr, row); \
	auditc_low(o, key, state1); \
} while (0)


/* ccowd.<prefix>.<serverid>.<vdevid>: <value> */
#define auditc_objid(o, prefix, vdevid, ...) do { \
	char key[2 * (UINT128_BYTES * 2 + 1) + 128]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	sprintf(key, "%s.%s.%s", prefix, serverstr, vdevstr); \
	auditc(o, key, ##__VA_ARGS__); \
} while (0)

/* ccowd.<prefix>.<serverid>.<vdevid>: <value> */
#define auditc_low_objid(o, prefix, vdevid, ...) do { \
	char key[2 * (UINT128_BYTES * 2 + 1) + 128]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	sprintf(key, "%s.%s.%s", prefix, serverstr, vdevstr); \
	auditc_low(o, key, ##__VA_ARGS__); \
} while (0)


/* ccowd.<prefix>.<serverid>.<vdevid>.<rowid_0>#<rowusage0>^..<rowid_n>#<rowusageN>: <numrows> */
#define auditc_low_rowusage(o, prefix, vdevid, numrows, fh) do { \
	char key[8192]; \
	int nrows = 0; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	sprintf(key, "%s.%s.%s.", prefix, serverstr, vdevstr); \
	for (int row = 0; row < numrows; row++) { \
		if (!flexhash_is_rowmember_fhrow(fh, vdevid, row)) \
			continue; \
		nrows++; \
		sprintf(key+strlen(key), "%d#%lu^", row, reptrans_get_rowusage(dev, row, numrows)/(1024UL*1024UL)); \
	} \
	key[strlen(key)-1] = 0; \
	auditc_low(o, key, nrows); \
} while (0)

/* ccowd.<prefix>.<serverid>.<nhid>.<value>: <value> */
#define auditc_obj_latency(o, prefix, serverid, nhid, value1, value2, value3, value4, value5, value6, ...) do { \
	char key[1 * (UINT512_BYTES * 2 + 1) + 1 * (UINT128_BYTES * 2 + 1) + 8 * REPLICAST_STR_MAXLEN]; \
	char nhidstr[UINT512_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	uint128_dump(serverid, serverstr, UINT128_BYTES * 2 + 1); \
	uint512_dump(nhid, nhidstr, UINT512_BYTES * 2 + 1); \
	uint64_t val1 = value1; \
	uint64_t val2 = value2; \
	uint64_t val3 = value3; \
	uint64_t val4 = value4; \
	uint64_t val5 = value5; \
	uint64_t val6 = value6; \
	sprintf(key, "%s.%s.%s.%"PRIu64".%"PRIu64".%"PRIu64".%"PRIu64".%"PRIu64".%"PRIu64, \
	    prefix, serverstr, nhidstr, val1, val2, val3, val4, val5, val6); \
	auditc(o, key, ##__VA_ARGS__); \
} while (0)

/* ccowd.<prefix>.<serverid>.<vdevid>.<value>: <value> */
#define auditc_objid2(o, prefix, vdevid, value1, ...) do { \
	char key[2 * (UINT128_BYTES * 2 + 1) + 128]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	uint64_t val1 = value1; \
	sprintf(key, "%s.%s.%s.%lu", prefix, serverstr, vdevstr, val1); \
	auditc(o, key, ##__VA_ARGS__); \
} while (0)


/* ccowd.<prefix>.<serverid>.<vdevid>.<strval>: <value> */
#define auditc_objid_str(o, prefix, vdevid, strval, ...) do { \
	char key[8192]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	sprintf(key, "%s.%s.%s.%s", prefix, serverstr, vdevstr, strval); \
	auditc(o, key, ##__VA_ARGS__); \
} while (0)


/* ccowd.<prefix>.<serverid>.<vdevid>.<strval>: <value> */
#define auditc_low_objid_str(o, prefix, vdevid, strval, ...) do { \
	char key[8192]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	uint128_dump(&server_get()->id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	sprintf(key, "%s.%s.%s.%s", prefix, serverstr, vdevstr, strval); \
	auditc_low(o, key, ##__VA_ARGS__); \
} while (0)

/* sending out serverid and ip6addr */
/* ccowd.<prefix>.<serverid>.<ip6addr>.<vdevstr>: <value> */
#define auditc_servervdev(o, prefix, id, vdevid, addrstr, ...) do { \
	char key[(UINT128_BYTES * 2 + 1) + 256]; \
	char serverstr[UINT128_BYTES * 2 + 1]; \
	char vdevstr[UINT128_BYTES * 2 + 1]; \
	uint128_dump(id, serverstr, UINT128_BYTES * 2 + 1); \
	uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1); \
	sprintf(key, "%s.%s.%s.%s", prefix, serverstr, addrstr, vdevstr); \
	log_debug(lg, "key: %s", key); \
	auditc(o, key, ##__VA_ARGS__); \
} while (0)

static inline int
ccowd_get_fddelta()
{
	return ccow_daemon->fddelta <= 0 ? ccow_daemon->fddelta : 0;
}

#define CCOWD_IPC_FLAG_THREADED	(1<<0) /* Run the command in a dedicated worker thread */

struct ccowd_ipc_cmd {
	/* Following to be filled up prior registering */
	const char* key;
	int (*handler) (struct ccowd_ipc_cmd* cmd, uv_buf_t msg, uv_buf_t* resp);
	int flags;

	/* Used by handler to preserve its state */
	void* ctx;

	/* Used by the uthash */
	UT_hash_handle hh;
};

int
ccowd_register_ipc_cmd(const struct ccowd_ipc_cmd* cmd);

#ifdef	__cplusplus
}
#endif

#endif
