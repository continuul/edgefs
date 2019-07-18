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
#ifndef __FLEXHASH_H__
#define __FLEXHASH_H__

#include "replicast.h"
#include "hashtable.h"
#include "json.h"

#include "fhprivate.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FH_GOOD_HC	1
#define FH_NOGOOD_HC	0

#define FH_REBUILD_NEXT	1
#define FH_NO_REBUILD	0

#define FH_CLIENT_SIDE 1
#define FH_SERVER_SIDE 2

#define	FH_TABLE_JOIN	1
#define	FH_TABLE_NOJOIN	0

#define SERVER_ALPHA_FACTOR	250		/* server padding on client start */

#define FH_GENID_CLIENT		1
#define FH_GENID_SERVER		2

#define FH_MIN_DELAYED_START	40		/* min permitted delayed start, us */

#define FH_LOCK_READ		1
#define FH_LOCK_WRITE		2

/* Max number of rows that we keep track of for
 * multicast joins. Used for pre-allocation only
 */
#define FH_MAX_JOINED_ROWS		4096

/* 10 PB cluster at  4 TB per drive would result in 2500 devices
 * we pad that upto 3000 devices
 * If we choose 3 vdevs per server, we take the max as 1000
 * servers
 *
 * */
#define FLEXHASH_MAX_VDEVS		3000
#define FLEXHASH_MAX_SERVERS		1000
#define FLEXHASH_MAX_ZONES		30


typedef enum vdevstate_ {
	VDEV_STATE_NONE		= 0,
	VDEV_STATE_DEAD		= 1,
	VDEV_STATE_ALIVE	= 2,
	VDEV_STATE_READ_ONLY	= 3
} vdevstate_t;

#define FH_CKPREAD_CP           0
#define FH_CKPREAD_DISK         1
#define FH_CKPREAD_SKIP         2

typedef struct {
	uint32_t postal_code;
	uint16_t power_grid;
	uint32_t building;
	uint8_t  hvac;
	uint8_t  floor;
	uint32_t room;
	uint32_t rack;
	uint32_t subnet;
} failure_domain_t;

struct rowcount;

struct fhserver {
	uint128_t	id;		/* id of the server or a vdev */
	uint64_t	weight;		/* weight computed for this device */
	uint32_t	zone;		/* zone for this server */
	failure_domain_t	failuredomain;	/* Failure domain */
	uint128_t	ipaddr;		/* ip send the I/O traffic */
	uint16_t	port;		/* port for the IO traffic */
	int		nr_vdevs;	/* number of vdevs in this server */
	struct rowcount *rcount;	/* row count used during rebalancing */
	struct dlist	vdevlist;	/* linked list of vdev pointers */
	uint8_t		gateway;	/* gateway only flag with no disks */
	volatile uint64_t inprog_seqid;	/* last processed TRLOG inprog seqid */
	struct fhserver	*next;		/* next element in this list */
};

struct lvdev {
	uint128_t	vdevid;		/* unique id for this vdev */
	vdevstate_t	state;		/* current state alive or dead */
	struct fhserver	*server;	/* server this is part of */
	uint64_t	size;		/* total size of the vdev */
	uint64_t	logical_used;	/* logical_used vdev */
	uint64_t	avail;		/* free space available */
	volatile uint64_t seqid;	/* last processed TRLOG flush seqid */
	uint16_t	activerows;	/* # of active rows = used, 0 = unused */
	int		idx;		/* hashtable id used for debug dump */
	uint32_t	numrows;	/* keep track of the hashcount */
	uint16_t	hashcount[FLEXHASH_MAX_TAB_LENGTH]; /* hashcount obtained */
	struct rowcount *rcount;	/* keep track of hashcount temporarily */
	uint16_t	port; 		/* VDEV unicast UDP listening port */
};


struct flexhash;
struct vdevstore {
	struct flexhash *fhtable;	/* point to the parent flexhash */
	int		lvdevcount;	/* total current count of entries */
	struct lvdev	*lvdevlist;	/* array list of vdev ids */
	hashtable_t	*hashtable;	/* map vdevids to array indexes */
	hashtable_t	*vdevusage;	/* vdev usage count based on RT */
	pthread_mutex_t mutex;		/* hashtable update needs a mutex */
};

struct server_rec
{
    uint64_t hash;
    struct fhserver *sptr;
};

struct flexhash {
	volatile uint64_t genid;	/* generation id timestamp */
	uint64_t	cpgenid;	/* checkpoint generation id timestamp */
	uint8_t		leader;		/* set if this is a leader table */
	int		numdevices;	/* number of devices initialized with */
	int		numrows;	/* number of rows in this flexhash */
	uint16_t	hashmask;	/* mask based on the number of rows */
	struct dlist	*dl;		/* list of rows */
	uv_mutex_t	mutex;		/* mutex for serverlist */
	int		servercount;	/* count of servers discovered */
	struct fhserver	*serverlist;	/* list of servers discovered */
	int		zonecount;	/* count of zones found */
	uint8_t		zonelist[FLEXHASH_MAX_ZONES];	/* list of zones found */
	struct sockaddr_in6	mcbase_in6_addr; /* negot group mcast addr */
	uint16_t	mcbase_port;	/* port for the multicast traffic */
	struct vdevstore *vdevstore;    /* store vdevids here */
	struct rebuild_ctx rebuild_ctx;/* use while rebuild is in-progress */
	int		stale;		/* if a new flexhash is being built
					   this one can be marked as stale */
	uint8_t		fhlogid;	/* json log file id */
	uint64_t	total_capacity;	/* total storage capacity represented */
	uint64_t	total_logical_used; /* trlog notified logical used */
	volatile int	is_ready;	/* used during rebalance */
	volatile int	fh_ready;	/* trigged due to corosync FH_READY */
	uint32_t	checkpoint_numdevices; /* leader wanted this device count */
	uv_timer_t	stats_timer;	/* timer for stats */
	uint8_t		fdmode;		/* failure domain selected on rebalance */
	uint8_t		ckpread;	/* this fh was built by reading a checkpoint */
	int		total_activerows;
	int devsperrow; /* devices per row */
	struct server_rec *sorted_servers;
	int sorted_servers_cnt;
	int		skip_cp;	/* used when rebuilding w/o a cp intentionally */
	hashtable_t	*zonerowusage; /* some row usage used only on rebalance using rowcount */
	uv_timer_t	rowusage_timer; /* kick off a timer in the leader to re-eval a timer */
};

struct fddelta
{
	int	vdev_delta;	/* stock delta count between two tables */
	int	server_delta;	/* stock delta count between the tables */
	int	zone_delta;	/* stock delta in zone count */
	int	affected_vdevs;	/* count of unique vdevs added and deleted */
	int	affected_servers; /* count of unique servers that went through change */
	int	affected_zones; /* count of unique zones that went through change */
	int	prev_numrows; /* numrows of the previous table */
	int	prev_numdevices; /* number of devices in the last table */
};

#define FH_PRISTINE 1
#define FH_AFFECTED -1
#define FH_REBUILD 0

#define flexhash_is_affected(fh) \
	((fh)->is_read == FH_AFFECTED) /* Changed respect to origin */

#define flexhash_is_pristine(fh) \
	((fh)->is_ready == FH_PRISTINE) /* Just created,consistent with fddelta */

#define flexhahs_is_rebuiding(fh) \
	((fh)->is_ready == FH_REBUILD) /* Rebuild is in progress */

struct flexhash *flexhash_table_create(int numdevices, int fh_clientserver);

void flexhash_table_destroy(volatile struct flexhash *fhtable);

void flexhash_table_dump(volatile struct flexhash *fhtable, const char *desc);

int flexhash_numrows(volatile struct flexhash *fhtable);

void flexhash_distribution(volatile struct flexhash *fhtable);

int flexhash_rebuild_start(volatile struct flexhash *fhtable, int nr_nodes,
				int known_vdevs);

void flexhash_rebuild_done(volatile struct flexhash **fhtable, int checkpoint,
				int rmvdev, int skip_cp);

int flexhash_rebuild_inprogress(volatile struct flexhash *fhtable);

void flexhash_set_leader(volatile struct flexhash *fhtable);

void flexhash_set_genid(volatile struct flexhash *fhtable, uint64_t genid);

int flexhash_delta_rebalance(volatile struct flexhash *fhtable);

void flexhash_lock(volatile struct flexhash *fhtable);

void flexhash_unlock(volatile struct flexhash *fhtable);

struct fhserver *flexhash_add_server_only(volatile struct flexhash *fhtable,
					struct cl_node *node);

int flexhash_add_vdevs(volatile struct flexhash *fhtable, struct cl_node *node,
	struct fhserver *fhserver, int join, int validhc, int rebuild_next);

struct fhserver *flexhash_get_fhserver(volatile struct flexhash *fhtable, uint128_t *sdevid);

int flexhash_remove_server(volatile struct flexhash *fhtable, struct cl_node *node);

void flexhash_update_vdev_physical_used(volatile struct flexhash *fhtable,
					uint128_t *vdevid,
					uint64_t physical_used);

uint64_t flexhash_total_logical_used(volatile struct flexhash *fhtable,
					uint64_t *new_total_logical_used);
void local_flexhash_update_vdev_seqid(volatile struct flexhash *fhtable,
					char *vdevstr,
					uint64_t seqid);
int local_flexhash_update_serverid_seqid(volatile struct flexhash *fhtable,
    char *serveridstr, uint64_t inprog_seqid);

int flexhash_cpset(volatile struct flexhash *fhtable, uint64_t recv_genid);

int flexhash_leave(volatile struct flexhash *fhtable, uint128_t *vdevid);

int vdevstore_mark_alive(struct vdevstore *vdevstore, uint128_t *vdevid);

int vdevstore_mark_dead(struct vdevstore *vdevstore, uint128_t *vdevid);

int vdevstore_mark_ro(struct vdevstore *vdevstore, uint128_t *vdevid);

int vdevstore_get_state(struct vdevstore *vdevstore, uint128_t *vdevid,
	vdevstate_t* state);

int flexhash_getvdev_index(volatile struct flexhash *fhtable, uint128_t *vdevid);

/* review */
void local_flexhash_row_update(volatile struct flexhash *fhtable, char *json_str);

void flexhash_hashcount_init(struct cl_node *node);

int flexhash_get_nodecopy(volatile struct flexhash *fhtable,
				uint128_t *serverid,
				struct cl_node **node, int hflags);

void flexhash_set_fhready(volatile struct flexhash *fhtable);

void flexhash_copy_mcbase(volatile struct flexhash *dst_fhtable,
				volatile struct flexhash *src_fhtabe);

void flexhash_add_serverlist(volatile struct flexhash *fhtable,
				struct cl_node *nodelist,
				int numnodes,
				int rebuild_next);

void flexhash_set_fdmode(volatile struct flexhash *fhtable);

int flexhash_add_node(struct flexhash *fhtable, struct cl_node *node);

uint64_t flexhash_total_capacity(volatile struct flexhash *fhtable);

int flexhash_add_server(volatile struct flexhash *fhtable,
			struct cl_node *node,
			int validhc,
			int join,
			int rebuild_next);

int flexhash_checkpoint_file_stat();

/* read the checkpoint from a file. is asis_mode ==1, use the filename as is.
 * if the asis_mode ==0, it will pick up the file from <edgefs_home>/var/run
 */
struct flexhash *flexhash_read_checkpoint(char *filename, int asis_mode);

int flexhash_save_checkpoint(char *savebuf);

int flexhash_get_checkpoint(rtbuf_t **retbuf);

int flexhash_hashrowcount(int numdevs);

void flexhash_sumsquares_seeded(uint128_t *id, uint16_t *hashcount, uint32_t numhashrows);

/* reptrans uses */
void flexhash_get_rowaddr(volatile struct flexhash *fhtable,
				uint16_t row,
				struct sockaddr_in6 *addr);

typedef enum fh_io_type {
	FH_IOTYPE_NONE = 0,
	FH_IOTYPE_GET,
	FH_IOTYPE_GET_M,
	FH_IOTYPE_PUT,
	FH_IOTYPE_PUT_J,
	FH_IOTYPE_PUT_DEV
} fh_io_type_t;

int flexhash_is_rowmember(volatile struct flexhash *fhtable,
				uint128_t *vdevid,
				const uint512_t *hashid);

/* Extract out x bits from the hash id using the hashmask */
#define HASHROWID(id, fhtable)	HASHCALC(id, fhtable->hashmask)

int flexhash_get_ngcount(volatile struct flexhash *fhtable,
				const uint512_t *hashid,
				fhrow_t *row_out, int *ngcount);

uint64_t flexhash_estimate_client_start(uint64_t genid, uint64_t genid_delta,
					uint64_t now, uint64_t pp_rcvd);

uint64_t flexhash_estimate_delta_time(volatile struct flexhash *fhtable,
			uint128_t *vdevid, uint64_t required_len,
			fh_io_type_t iotype, uint64_t lat4k_current,
			uint64_t lat64k_current, uint64_t lat512k_current);

uint64_t flexhash_estimate_90th(volatile struct flexhash *fhtable,
			uint128_t *vdevid, uint64_t required_len,
			uint64_t lat4k_current,
			uint64_t lat64k_current, uint64_t lat512k_current);

fhrow_t flexhash_get_addr_fhrow(struct sockaddr_in6 *addr);

int flexhash_is_rowmember_fhrow(volatile struct flexhash *fhtable, uint128_t *vdevid,
					fhrow_t row);

void flexhash_get_hashaddr(volatile struct flexhash *fhtable, uint512_t *hashid,
				struct sockaddr_in6 *addr);

int flexhash_get_vdev_row(volatile struct flexhash *fhtable, uint128_t *vdevid,
				fhrow_t* row);
int flexhash_valid_servercount(volatile struct flexhash *fhtable);

int flexhash_zcount(volatile struct flexhash *fhtable);

int flexhash_is_stale(volatile struct flexhash *fhtable);


/* replicast uses */

uint64_t flexhash_get_genid(int mode, void *ctx);
int flexhash_is_fhready(int mode, void *ctx);

/* libccowd uses */
char *flexhash_get_row_median_json(volatile struct flexhash *fhtable);

/* when booting up we use a default set of the number of vdevs in the cluster
 * this is only during bootup. When nodes exchange each other's node info
 * and create a new flexhash, they get the correct number of devices
 * discovered in the new flexhash
 */
#define FLEXHASH_BOOTUP_VDEVS		9

void flexhash_mark_stale(volatile struct flexhash *fhtable);
int flexhash_checkpoint_exists(void);
int flexhash_assign_mcbase(volatile struct flexhash *fhtable,
			uint128_t *addr, uint16_t port);
int flexhash_check_seqid(volatile struct flexhash *fhtable, uint64_t seqid);
int flexhash_check_inprog_seqid(volatile struct flexhash *fhtable, uint64_t inprog_seqid);

/* libccow uses these */

typedef enum mdgtype_ {
	FH_MSG_GET_SOLICITED,
	FH_MSG_PUT_SOLICITED,
	FH_MSG_UNSOLICITED,
	FH_MSG_PUT_SELECT,
	FH_MSG_NAMEDGET_SELECT,
	FH_MSG_UNNAMEDGET_SELECT
} fh_msg_t;


uint64_t flexhash_get_rtt(volatile struct flexhash *fhtable, uint512_t *chid,
			  fh_msg_t msg_type, uint64_t req_len);

void flexhash_update_rtt(volatile struct flexhash *fhtable, uint512_t *chid,
			  fh_msg_t msg_type, uint64_t start,
			  uint64_t end, uint64_t req_len);

void flexhash_dump_repnode(struct cl_node *node, uint32_t numnode);

uint64_t flexhash_genid(volatile struct flexhash *fhtable);

void flexhash_dump(volatile struct flexhash *fhtable, int mode);

void flexhash_reset_genid(int mode, void *ctx);

int flexhash_find_master(volatile struct flexhash *fhtable,
    const uint512_t *hashid, int shard_index, uint128_t *vdevid_out);

void flexhash_set_rtaddr(volatile struct flexhash *fhtable, uint128_t *vdevs,
					int numvdevs, struct sockaddr_in6 *);

int flexhash_client_rthash_exists(volatile struct flexhash *fhtable, uint64_t rtid);

int flexhash_client_rthash_add(volatile struct flexhash *fhtable, uint64_t rtid);

int flexhash_validate_vdev(volatile struct flexhash *fhtable, uint128_t *vdevid);

/* isgw */
void fh_get_genid_filepath(char *file);

/* unit tests */

int flexhash_zpr(int numdevices, int numzones);

int flexhash_fddelta(volatile struct flexhash *fhtable, char *fhtable2, struct fddelta *fddelta);

void flexhash_summary(volatile struct flexhash *fhtable);

struct dlist *flexhash_devicelist(volatile struct flexhash *fhtable, fhrow_t rowid);

void flexhash_json_dump(FILE *fd, volatile struct flexhash *fhtable, int leader,
				const char *desc);

int flexhash_spr(volatile struct flexhash *fhtable);

void flexhash_clear_stale(volatile struct flexhash *fhtable);

void flexhash_rebalance(struct flexhash *fhtable);

uint128_t vdevstore_getvdev_id(struct vdevstore *vdevstore, int idx);

int vdevstore_remove_vdev(volatile struct flexhash *fh, uint128_t *vdevid);

void flexhash_disk_dump(volatile struct flexhash *fhtable, char *filename, int leader, const char *desc);

void flexhash_mem_dump(volatile struct flexhash *fhtable, int leader, const char *desc,
    char **bp, size_t *bsize);
struct flexhash* flexhash_read_buf(int numdevices, char *buf, int len);

enum evac_policy {
	EVAC_ROW_PARTICIPATION = 1,
	EVAC_ROW_MEDIAN_AVAIL_SPACE,
	EVAC_SERVER_AVAIL_SPACE,
	EVAC_ZONE_AVAIL_SPACE,
	EVAC_END
};

typedef struct id_rowdata_
{
	int rowcount;
	int *rows;
	uint8_t fdmode;
	uint32_t zone;
	uint128_t srvid;
} id_rowdata_t;

typedef struct id_rowdata_list_
{
	id_rowdata_t		*idrow;
	struct id_rowdata_list_	*next;
} id_rowdata_list_t;

typedef struct rowevac_ {
	uint128_t	from_vdev;		/* from this vdev */
	uint128_t	to_vdev;		/* to this vdev */
	int		row;			/* to this row */
	int		rowusage_median;	/* per device row usage median */
} rowevac_t;

typedef struct rowevac_list_ {
	rowevac_t		*rowevac;
	struct rowevac_list_	*next;
} rowevac_list_t;


typedef struct evac_job {
	QUEUE     item;
	int       row;
	int       state;
	uint64_t  id;
	uint128_t vdev_id;
	uint64_t  flags;
	uint64_t  amount; /* Amount in bytes to be moved from src to dst */
	size_t    evacuated; /* Number of chunks evacuated */
	size_t    moved_amount; /* Number of bytes evacuated */
} evac_job_t;

#define MAX_PER_ROW_VDEVS 10
#define MAX_EVAC_MSG 4096

static char *evac_state_str [] = {
	"Evacuation does not apply or not started",
	"Evacuation initiated",
	"Evacuation in progress",
	"Evacuation successful"
	"Evacuation failed"
};

typedef struct rowusage_xfer_ {
	int		numrows;	/* number rows from current flexhash */
	QUEUE		queue; /* Evacuation jobs queue */
	uint64_t	genid;		/* generation id */
	uint64_t	ro_ref_count; /* The READ-ONLY  requests refCounter */
	evac_job_t*	jobs[FLEXHASH_MAX_TAB_LENGTH];	/* pointer to a job which is in progress now */
	uv_rwlock_t	lock;		/* need a lock on insert */
} rowusage_xfer_t;

typedef void (*revac_candidate_cb_t)(int rowsperdev, hashtable_t *src_t,
						     hashtable_t *tgt_t);
typedef void (*evac_policy_func_t)(struct flexhash *fhtable, int rowsperdev,
					revac_candidate_cb_t evac_cb);

void flexhash_evac(enum evac_policy, struct flexhash *fhtable, int rowsperdev,
			revac_candidate_cb_t revac);

int flexhash_get_row_server_addrs(int is_client, void *ctx,
    uint16_t row, struct sockaddr_in6 *addrs_out, int *addrs_len);

int flexhash_serverid_by_key(volatile struct flexhash *fhtable,
    uint128_t *key128, uint128_t *id_out);

int flexhash_row_rebalance(rowusage_xfer_t *row_xfer, int row, int ngcount);

int flexhash_update_checkpoint(volatile struct flexhash *fhtable, char *desc);
int flexhash_fddelta_checkpoint(volatile struct flexhash *fhtable, int *fd_delta_value,
				struct fddelta *fddelta);

int flexhash_exists(volatile struct flexhash *fhtable, fhrow_t row, uint128_t *vdevid);

int flexhash_get_nodes(volatile struct flexhash *fhtable, struct cl_node **nodes,
	int *numnodes, int hcflags);

void flexhash_get_tenant_rcvaddr(volatile struct flexhash *fhtable, uint512_t *hashid,
	struct in6_addr inaddr, uint16_t port, struct sockaddr_in6 *outaddr);

volatile struct flexhash *flexhash_join(volatile struct flexhash *fhtable,
			fhrow_t rowid, sdevid_t *vdevid);

int flexhash_vdev_leave(volatile struct flexhash *fhtable, fhrow_t rowid, int index);

struct lvdev *vdevstore_get_lvdev(struct vdevstore *vdevstore, uint128_t *vdevid);

int vdevstore_getvdev_index_nl(struct vdevstore *vdevstore, uint128_t *vdevid);

int flexhash_row_zonecount(volatile struct flexhash *fhtable, fhrow_t row);

int flexhash_row_servercount(volatile struct flexhash *fhtable, fhrow_t row);

struct lvdev* flexhash_get_lvdev(volatile struct flexhash *fhtable, fhrow_t rowid,
				 uint128_t *vdevid);
char *flexhash_get_median_candidates_json(volatile struct flexhash *fhtable);

int flexhash_split(volatile struct flexhash *fhtable);
int flexhash_checkpoint_servercount();
int flexhash_checkpoint_numdevices();

#ifdef __cplusplus
}
#endif


#endif /* __FLEXHASH_H__ */
