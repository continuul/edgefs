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
#ifndef __CLUSTER_H__
#define __CLUSTER_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <memory.h>
#include <string.h>

#include "queue.h"
#include "ccowutil.h"
#include "reptrans.h"
#include "flexhash.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define CL_MAX_NODES 384
#define CL_PROTO_VER 0x1
#define CL_MAX_DISCOVERY_COUNT 2
#define CL_IN_PROGRESS_TIMEOUT_US 1000000 /* 10 seconds */
#define CL_MIN_VDEVS_PER_LEADER 3



struct clengine_handlers {
	void (*join_handler)(struct cl_node *joined, struct cl_node *members,
	    size_t nr_members, int result, void *opaque, int msg_len);
	void (*leave_handler)(struct cl_node *left, struct cl_node *members,
	    size_t nr_members);
	void (*notify_handler)(struct cl_node *sender, void *msg,
	    size_t msg_len);
	void (*flexhash_handler)(struct cl_node *sender, void *msg,
	    size_t msg_len);
};

struct cluster_engine {
	QUEUE item;

	int group_fd;
	uv_poll_t *group_poll_fd;
	uv_timer_t *fhtimer_req;
	uv_timer_t *clust_health_req;
	uv_timer_t *coro_timer_req;

	/* this represents the server this instance of cluster engine
	 * hosted on. this is myself. We use this to keep track of network
	 * requests which contain data about myself that other nodes know
	 * about
	 */
	struct cl_node me;

	/* List of other nodes that this cluster node knows about.
	 * also contains my own node instance.
	 */
	struct cl_node nodes[CL_MAX_NODES];
	size_t nr_nodes;

	const char *name;

	uint64_t last_discovery;

	/*
	 * remove the vdev from the table if not found in
	 * discovery after reading from the checkpoint
	 *
	 */
	int rmvdev;

	/*
	 * Initialize the cluster engine
	 *
	 * On success, this function returns the file descriptor that
	 * may be used with the poll(2) to monitor cluster events.  On
	 * error, returns -1.
	 */
	int (*init)(struct clengine_handlers *handlers, const char *option);

	/*
	 * Join the cluster
	 *
	 * This function is used to join the cluster, and notifies a
	 * join event to all the nodes.  The copy of 'opaque' is
	 * passed to check_join_cb() and join_handler().
	 * check_join_cb() is called on one of the nodes which already
	 * paticipate in the cluster.  If the content of 'opaque' is
	 * changed in check_join_cb(), the updated 'opaque' must be
	 * passed to join_handler().
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*join)(struct cl_node *myself,
		    int (*check_join_cb)(struct cl_node *joining,
			    void *opaque, int opaque_len),
		    void *opaque, size_t opaque_len);

	/*
	 * Leave the cluster
	 *
	 * This function is used to leave the cluster, and notifies a
	 * leave event to all the nodes.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*leave)(void);

	/*
	 * Notify a message to all nodes in the cluster
	 *
	 * This function sends 'msg' to all the nodes.  The notified
	 * messages can be read through notify_handler() in
	 * clengine_handlers.  If 'block_cb' is specified, block_cb() is
	 * called before 'msg' is notified to all the nodes.  All the
	 * cluster events including this notification are blocked
	 * until block_cb() returns or this blocking node leaves the
	 * cluster. This callback must be not called from the dispatch
	 * (main) thread.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*notify)(void *msg, size_t msg_len, void (*block_cb)(void *arg));

	/*
	 * Send a stats update
	 *
	 * This function sends 'msg' to all the nodes.  The notified
	 * messages can be read through update_handler() in
	 * clengine_handlers.  If 'block_cb' is specified, block_cb() is
	 * called before 'msg' is notified to all the nodes.  All the
	 * cluster events including this notification are blocked
	 * until block_cb() returns or this blocking node leaves the
	 * cluster. This callback must be not called from the dispatch
	 * (main) thread.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*update)(void *msg, size_t msg_len, void (*block_cb)(void *arg));
	/*
	 * Dispatch handlers
	 *
	 * This function dispatches handlers according to the
	 * delivered events (join/leave/notify) in the cluster.
	 *
	 * Note that the events sequence is totally ordered; all nodes
	 * call the handlers in the same sequence.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*dispatch)(void);

	/*
	 * Flexhash Update
	 */
	int (*flexhash_update)(void *msg, size_t msg_len);

};

typedef int (* clengine_register_rowusage_cb_t)(uint128_t *, uint128_t *, uint32_t, int);

extern QUEUE cluster_engines;
extern struct cluster_engine *g_ceng;

int clengine_init(const char *name, struct cl_node *myself);
void clengine_tick();
int clengine_stop();
int clengine_destroy();
int clengine_reinit(int skip_cp);
void clengine_get_nodes(struct cl_node **members, size_t *nr_members);
int clengine_update_nodevdevs(uint128_t *serverid, struct cl_node *nodes,
    size_t nr_vdevs);
struct cluster_engine *clengine_find(const char *name);
const char *clengine_get_option(struct cluster_engine *ceng, const char *arg);

void clengine_update_hashcount(struct cl_node *nodes, int nr_nodes);
int clengine_copy_cl_node(struct cl_node *dst_node, struct cl_node *src_node);
void clengine_destroy_cl_node(struct cl_node *node, int nr_nodes);
int clengine_copy_mynodeinfo(struct repmsg_server_list_get *msg);
uint128_t *clengine_get_mynodeid();

void clengine_notify_others();
void clengine_notify_auditserv(struct cl_node *, uint128_t *vdevid);
int clengine_learn_cluster(struct cl_node *cn, int nr_nodes);

int clengine_get_node(uint128_t *serverid, struct cl_node **node);

int clengine_blob_lookup_request(type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t* chid, const uint128_t *ipaddr, uint32_t scope_id, uint16_t port,
	uint32_t sequence_num, uint32_t sub_sequence_num, uint64_t txcookie);

int cl_node_state_count(enum cl_node_state state);
void cl_node_set_state(uint128_t *serverid, enum cl_node_state state);
void cl_all_nodes_set_state(enum cl_node_state state);
int cl_node_state_match(uint128_t *serverid, enum cl_node_state state);

void  clengine_register_rowusage_start_cb(clengine_register_rowusage_cb_t fn);
void  clengine_register_rowusage_end_cb(clengine_register_rowusage_cb_t fn);

int clengine_fh_update(char *srvid, struct cl_node *node);
int clengine_fh_update_full(char *nodeidstr, struct cl_node *members,
    size_t nr_members, uint64_t fh_genid, uint32_t checkpoint_numdevices);

int
blob_lookup_srv_init(struct replicast *robj, struct repctx *ctx,
	struct state *state);


#define clengine_register(eng) \
static void __attribute__((constructor)) regist_ ## eng(void) {	\
	if (!eng.init || !eng.join || !eng.leave || \
	    !eng.notify || !eng.dispatch) \
		panic("the eng '%s' is incomplete\n", eng.name); \
	QUEUE_INIT(&eng.item); \
	QUEUE_INSERT_TAIL(&cluster_engines, &eng.item);	\
}

#define CLENGINE_STAT_PHYSICAL_USED		1
#define CLENGINE_STAT_LOGICAL_USED		2
#define CLENGINE_HB_MAXERR			90
#define CLENGINE_CORO_MAXERR			90

int clengine_notify(char *msg);
int corosync_cleanup(void);
int clengine_self(uint128_t *id);
void clengine_notify_vdev_state(uint128_t *vdevid, vdevstate_t state);
void clengine_update_others(uint128_t *server_id, int stat_type,
    const char* msg);
int
clengine_notify_maintenance(int minutes);

void clengine_fh_row_update(char *msg);

int corosync_hostlist();
int corosync_ring_status();
int corosync_ringid_value();
void corosync_ring_reinit(int *fd_out);
void clengine_reenable();
int corosync_shutdown();

struct coro_stat
{
	int hostcount;
	int static_ring;
	uint64_t ringid;
	uint64_t genid;
	int vdevcount;
};

typedef struct clengine_hb_
{
	volatile uint16_t hb;
	uint8_t thread_errcount;
	uint8_t coro_errcount;
	uint8_t trun;

} clengine_hb_t;

void clengine_set_genid(volatile struct flexhash *fhtable);
int clengine_notify_rebuild_change(volatile struct flexhash *ofhtable, int rmvdev);
void clengine_notify_rowusage_change(int start, uint128_t *srv_vdevid,
					uint128_t *dest_vdevid, int rcount,
					int fdomain);

int fhrebalance_row_usage(struct flexhash *fhtable);

#ifdef	__cplusplus
}
#endif

#endif
