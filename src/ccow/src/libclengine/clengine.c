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
#include <uv.h>

#include "ccowutil.h"
#include "clengine.h"
#include "cltopo.h"
#include "replicast.h"
#include "reptrans.h"
#include "ccowd-impl.h"
#include "rowevac-srv.h"
#include "flexhash.h"
#include "queue.h"
#include "probes.h"

extern volatile int ccowd_terminating;
QUEUE cluster_engines = QUEUE_INIT_STATIC(cluster_engines);
struct cluster_engine *g_ceng = NULL;
clengine_register_rowusage_cb_t g_cl_rowchange_start_fn = NULL;
clengine_register_rowusage_cb_t g_cl_rowchange_end_fn = NULL;
static uint8_t cl_discoveries = 0;

#define CLENGINE_FHTIMER_TIMEOUT_MS	3000
#define CLENGINE_CORO_TIMEOUT		5000
#define CLENGINE_CORO_GRACE_PERIOD_MS	(30)

/* Forward declaration */
static void clengine_fhtimer_timeout(uv_timer_t *treq, int status);
static void clengine_corosync_timeout(uv_timer_t *treq, int status);
static void fhrebalance_timer(volatile struct flexhash *fhtable);
static void clengine_bgrestart_request();

void
clengine_register_rowusage_start_cb(clengine_register_rowusage_cb_t fn)
{
	g_cl_rowchange_start_fn = fn;
}

void
clengine_register_rowusage_end_cb(clengine_register_rowusage_cb_t fn)
{
	g_cl_rowchange_end_fn = fn;
}

static double clengine_get_vdev_online_status(struct cl_vdev *vdev) {
	double status = 0.0;
	vdevstate_t state = vdev->state;
	if (state == VDEV_STATE_DEAD) {
		status = 0.0;
	} else if (state == VDEV_STATE_ALIVE) {
		status = 1.0;
	} else if (state == VDEV_STATE_READ_ONLY) {
		status = 2.0;
	}
	return status;
}

static int
clengine_update_fddelta(volatile struct flexhash *fh)
{
	int err;
	struct fddelta fddelta;
	err = flexhash_fddelta_checkpoint(fh, &ccow_daemon->fddelta, &fddelta);
	if (err != 0) {
		/*
		 * We cannot calculate delta difference. This
		 * can be due to missing flexhash-checkpoint.json
		 *
		 */
		ccow_daemon->fddelta = 0;
		fddelta.prev_numdevices = fh->numdevices;
	} else {
		log_notice(lg, "New failure domain status: %d (%s)",
		    ccow_daemon->fddelta,
		    ccow_daemon->fddelta < 0 ? "SPLIT" : "GOOD");
		if (CLENGINE_CLENGINE_UPDATE_FDDELTA_ENABLED()) {
			CLENGINE_CLENGINE_UPDATE_FDDELTA(ccow_daemon->fddelta,
				fddelta.vdev_delta, fddelta.server_delta,
				fddelta.zone_delta, fddelta.affected_vdevs,
				fddelta.affected_servers,  fddelta.affected_zones,
				fddelta.prev_numrows, fddelta.prev_numdevices,
				err);
		}
	}

	// returns the known checkpoint numdevices
	return fddelta.prev_numdevices;
}

static int
check_join_cb(struct cl_node *joining,
	void *opaque, int opaque_len)
{
	// FIXME: check join criteria
	return 1; /* allow */
}

/*
 *  clengine_self(uint128_t *id)
 *
 *  if the id passed in is my own return true(1) else return false(0)
 */
int
clengine_self(uint128_t *id)
{
	return (uint128_cmp(id, &g_ceng->me.serverid) == 0);

}

static void
clengine_evict_failed_nodes()
{
	struct cl_node pruned_nodes[g_ceng->nr_nodes];
	char serverstr[UINT128_STR_BYTES];
	size_t expected_nodes = 0, i;

	log_debug(lg, "No. of nodes before eviction: %d",
			(int)g_ceng->nr_nodes);
	for (i = 0; i< g_ceng->nr_nodes; i++) {

		/* check for state */
		if (g_ceng->nodes[i].state == CL_NODE_QUERY_FAILED) {
			uint128_dump(&g_ceng->nodes[i].serverid, serverstr, UINT128_STR_BYTES);
			log_notice(lg, "Evicting node : %s, %ld", serverstr, i);
			g_ceng->nodes[i].vdevs = NULL;
			continue;
		}

		/* check for duplicates */
		int found_dup = 0;
		for (size_t j = i + 1; j < g_ceng->nr_nodes; j++) {
			if (uint128_cmp(&g_ceng->nodes[i].serverid, &g_ceng->nodes[j].serverid) == 0) {
				uint128_dump(&g_ceng->nodes[i].serverid, serverstr, UINT128_STR_BYTES);
				log_notice(lg, "Evicting duplicate node : %s, %ld", serverstr, i);
				found_dup = 1;
				g_ceng->nodes[i].vdevs = NULL;
				break;
			}
		}
		if (found_dup)
			continue;

		pruned_nodes[expected_nodes] = g_ceng->nodes[i];
		expected_nodes++;
	}
	g_ceng->nr_nodes = expected_nodes;
	for (i = 0; i< g_ceng->nr_nodes; i++)
		g_ceng->nodes[i] = pruned_nodes[i];

	/* Reduce the count by no. of evicted nodes */
	ccow_daemon->flexhash->rebuild_ctx.expected_nr_nodes = expected_nodes;
	log_debug(lg, "No. of nodes after eviction: %d",
			(int)g_ceng->nr_nodes);
}

#define CL_HOST_RETRY_MAX 3
#define CL_RING_RETRY_MAX 3
#define CL_QUORUM_RETRY_MAX 3

struct coro_stat g_coro;

void clengine_set_genid(volatile struct flexhash *fhtable)
{
	g_coro.genid = fhtable->genid;
}

int
clengine_flexhash_vdevcount()
{
	int count=0;
	for (int i =0; i < SERVER_FLEXHASH->vdevstore->lvdevcount; i++) {
		if (SERVER_FLEXHASH->vdevstore->lvdevlist[i].state != VDEV_STATE_DEAD)
			count++;
	}
	return count;
}

uint64_t
clengine_flexhash_genid()
{
	return SERVER_FLEXHASH->genid;
}

static void
clengine_start_fhtimer()
{
	if (g_ceng->fhtimer_req->data)
		uv_timer_stop(g_ceng->fhtimer_req);
	g_ceng->fhtimer_req->data = ccow_daemon;
	uv_timer_start(g_ceng->fhtimer_req, clengine_fhtimer_timeout,
		       CLENGINE_FHTIMER_TIMEOUT_MS, 0);
}

static void
clengine_rediscover_on_drive_change()
{
	if (!cl_discoveries && (SERVER_FLEXHASH->ckpread == 1) &&
	    (SERVER_FLEXHASH->checkpoint_numdevices != 0) &&
	    (SERVER_FLEXHASH->leader == 1) &&
	    g_ceng->fhtimer_req->data == NULL) { /* no timer in progress */
		clengine_start_fhtimer();
		log_notice(lg, "Restarting fhtimer for rediscovery on drive change");
	}
}

void
clengine_process_shutdown()
{
	log_notice(lg, "clengine shutdown ");
	log_flush(lg);
	ccow_daemon_process_shutdown();
}


static void
clengine_hb_thread(void *arg)
{
	clengine_hb_t *clengine_hb = arg;
	int ckpe = flexhash_checkpoint_exists();
	if (ckpe == 0) {
		// not need to do corosync heartbeat because we do not
		// want to create multiple leaders in the cluster
		return;
	}
	while (!clengine_hb->hb && !ccowd_terminating) {

		if ((clengine_hb->thread_errcount > CLENGINE_HB_MAXERR)
		    || ( clengine_hb->coro_errcount > CLENGINE_CORO_MAXERR)) {
			log_error(lg, "Clengine heartbeat errcount: %d transport errcount %d",
			    clengine_hb->thread_errcount, clengine_hb->coro_errcount);
			char* survive = getenv("NEDGE_SURVIVE");
			if (!survive)
				clengine_process_shutdown();
			return;
		}
		clengine_hb->thread_errcount++;
		sleep(1);
	}
}

static void
clengine_hb_thread_done(void *arg, int err)
{
	clengine_hb_t *clengine_hb = arg;
	clengine_hb->trun = 0;
	clengine_hb->thread_errcount = 0;
}

int
clengine_hb_monitor(clengine_hb_t *clengine_hb)
{
	if (clengine_hb->trun != 0) {
		return -1;
	}
	clengine_hb->hb = 0;
	clengine_hb->trun = 1;
	ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_HI, clengine_hb_thread,
		clengine_hb_thread_done, clengine_hb);

	return 0;
}

static void cluster_health_timeout(uv_timer_t *treq, int status);
static void
clengine_health_start()
{
	if (g_ceng->clust_health_req->data)
		uv_timer_stop(g_ceng->clust_health_req);
	g_ceng->clust_health_req->data = ccow_daemon;
	uv_timer_start(g_ceng->clust_health_req,
		cluster_health_timeout,
		(SERVER_LIST_GET_MAX_RETRY + 1)*SERVER_LIST_GET_TIMEOUT_MS, 0);
}

static void
clengine_corosync_timeout(uv_timer_t *treq, int status)
{
	log_trace(lg, "treq %p status %d", treq, status);

	int err = clengine_hb_monitor(&ccow_daemon->clengine_hb);
	if (err != 0) {
		log_warn(lg, "hb thread already running ");
	}
	int hs = corosync_hostlist();
	if (hs < 0) {
		clengine_reenable();
		ccow_daemon->clengine_hb.coro_errcount++;
		return;
	}
	if (hs != g_coro.hostcount)
		log_notice(lg, "hostcount changed from %d to %d", g_coro.hostcount, hs);
	g_coro.hostcount = hs;
	int i = corosync_ring_status();
	if (i < 0) {
		clengine_reenable();
		ccow_daemon->clengine_hb.coro_errcount++;
		return;
	}
	g_coro.static_ring = i;
	if (i != g_coro.static_ring)
		log_notice(lg, "local nodeid changed from %d to %d", g_coro.static_ring, i);
	uint64_t val;
	err = corosync_ringid_value(&val);
	if (err < 0) {
		clengine_reenable();
		ccow_daemon->clengine_hb.coro_errcount++;
		return;
	}
	if (val != g_coro.ringid) {
		log_notice(lg, "ringid changed from %lu to %lu", g_coro.ringid, val);
	}
	g_coro.ringid = val;
	uint64_t genid = clengine_flexhash_genid();
	if (genid != g_coro.genid && genid != 1) {
		log_warn(lg, "current genid %lu does not match previous genid: %lu",
				genid, g_coro.genid);
	}
	g_coro.genid = genid;

	int vdevcount = clengine_flexhash_vdevcount();
	if (g_coro.vdevcount && vdevcount && (vdevcount != g_coro.vdevcount)) {
		log_warn(lg, "current vdevcount:%d does not match previous count: %d",
		    vdevcount, g_coro.vdevcount);
	}

	g_coro.vdevcount = vdevcount;

	if ((SERVER_FLEXHASH->ckpread == 1) && (SERVER_FLEXHASH->checkpoint_numdevices != 0)) {
		if ((uint32_t) vdevcount != SERVER_FLEXHASH->checkpoint_numdevices) {
			log_warn(lg, "current vdevcount:%d does not match checkpoint vdevcount:%d",
			    vdevcount, SERVER_FLEXHASH->checkpoint_numdevices);
		}
	}
	ccow_daemon->clengine_hb.coro_errcount = 0;
	ccow_daemon->clengine_hb.hb = 1;
}


static void
clengine_corotimer_start()
{
	if (!g_ceng->coro_timer_req->data)
		g_ceng->coro_timer_req->data = ccow_daemon;
	uv_timer_start(g_ceng->coro_timer_req, clengine_corosync_timeout,
			CLENGINE_CORO_GRACE_PERIOD_MS, CLENGINE_CORO_TIMEOUT);
}

static void
cluster_health_timeout(uv_timer_t *treq, int status)
{
	/* Assume - cluster is healthy and dicovery is not in progress */
	int healthy = 1, in_progress = 0, timeout_rediscover = 0;
	char serverstr[UINT128_STR_BYTES];

	log_trace(lg, "treq %p status %d", treq, status);

	if (treq->data) {
		uv_timer_stop(treq);
		treq->data = NULL;
	}
	for (size_t i = 0; i < g_ceng->nr_nodes; i++) {
		uint128_dump(&g_ceng->nodes[i].serverid, serverstr, UINT128_STR_BYTES);
		log_trace(lg, "%s in state %d", serverstr,
						g_ceng->nodes[i].state);
		if (g_ceng->nodes[i].state == CL_NODE_NEW ||
		    g_ceng->nodes[i].state == CL_NODE_QUERY_FAILED)
			healthy = 0;

		if (g_ceng->nodes[i].state == CL_NODE_QUERY_ISSUED)
			in_progress = 1;
	}

	/* if we have passed 30 seconds since the last in-progress, we kick off
	 * again, because it is possible that we did not get the responses and
	 * we do not want to stay in in-progress forever
	 */
	uint64_t in_progress_timediff = get_timestamp_us() - g_ceng->last_discovery;
	if ((in_progress_timediff > CL_IN_PROGRESS_TIMEOUT_US)
	    && in_progress ) {
		log_notice(lg, "%dus since the last discovery, "
		    "restart discovery", CL_IN_PROGRESS_TIMEOUT_US);
		timeout_rediscover = 1;
	}

	if (!healthy || timeout_rediscover) {
		log_notice(lg, "Cluster not formed. Restarting discovery "
			       "- attempt %d", cl_discoveries);
		/*
		 * Discovery has failed. Hence set discovery states
		 * of all the nodes to NEW. Restart the discovery even if
		 * some queries are outstanding.
		 *
		 * If any previous queries are replied they will be
		 * ignored, if state is NEW. Otherwise, they will be processed.
		 * Discovery timer is large and chances of delayed replies are
		 * very low.
		 */
		if (cl_discoveries  > CL_MAX_DISCOVERY_COUNT) {
			/* Currently evicts failed nodes from last discovery */
			clengine_evict_failed_nodes();
			cl_discoveries = 0;
		}
		cl_all_nodes_set_state(CL_NODE_NEW);
		cl_discoveries++;

		/* Restart the discovery - restart fhtimer */
		clengine_start_fhtimer();
		log_notice(lg, "Restarting fhtimer for rediscovery");
	}

	/*
	 * No discovery failures are noticed and discovery is still in process.
	 * Restart the timer.
	 */
	if (healthy && in_progress) {
		clengine_health_start();
	}

	/* Discovery complete. Reset counter for next discovery */
	if (healthy && !in_progress) {
		log_notice(lg, "Cluster is formed with %ld nodes", g_ceng->nr_nodes);
		cl_discoveries = 0;
		if (getenv("CCOW_ROW_EVAC") != NULL)
			fhrebalance_timer(ccow_daemon->flexhash);
	}
}

static int
clengine_nodes_dev_nr(struct cl_node *node, int nr_nodes)
{
	int dev_nr = 0;

	for (int i = 0; i < nr_nodes; i++)
		dev_nr += node[i].nr_vdevs;

	return dev_nr;
}

/*
 * FH Leader election logic.
 *
 * A server with the lowest ServerID will be assigned as a leader. It has to
 * recompute FH based on supplied information around the cluster and when
 * completed send cluster-wide notification.
 *
 * This logic equally works for server joins/leaves as well as large scope
 * cluster splits at the switch levels.
 *
 * On each join/leave we start seconds-resolution timer which would buffer
 * us from the noise on the network and give leader an oppurtunity to
 * re-calculate FH safely.
 */
static void
clengine_fhtimer_timeout(uv_timer_t *treq, int status)
{
	int i;
	struct cl_node *nodeptr = NULL, *me = NULL;

	log_trace(lg, "treq %p status %d", treq, status);

	if (treq->data) {
		uv_timer_stop(treq);
		treq->data = NULL;
	}

	struct cl_node *known_nodes = &g_ceng->nodes[0];
	int nr_nodes = g_ceng->nr_nodes;

	for (i = 0; i < nr_nodes; i++) {
		me = &g_ceng->nodes[i];
		if (uint128_cmp(&me->serverid, &g_ceng->me.serverid) == 0) {
			break;
		}
	}

	/* if I don't have enough devices I cannot be a leader */
	if (server_get()->numdisks == 0) {
		log_info(lg, "Gateway sees NR_NODES : %d", nr_nodes);
		struct cl_node *min_nodeptr = &g_ceng->nodes[0];
		i = 0;
		do {
			nodeptr = &g_ceng->nodes[i++];
			struct cl_node *nodenext = &g_ceng->nodes[i];
			int res = uint128_cmp(&nodenext->serverid, &min_nodeptr->serverid);
			if (res < 0) {
				min_nodeptr = nodenext;
			}
		} while (i < nr_nodes - 1);

		/* gateway cannot be a leader */
		ccow_daemon->leader = 0;

		if (uint128_cmp(&min_nodeptr->serverid, &g_ceng->me.serverid) == 0) {
			log_info(lg, "Not enough vdevs to be leader server, waiting for FH_READY");
		} else {
			char out[UINT128_STR_BYTES];
			uint128_dump(&min_nodeptr->serverid, out, UINT128_STR_BYTES);

			if (nr_nodes > 1) {
				log_info(lg, "Not enough vdevs to be leader server, current leader is %s", out);
				/* gateway case: pull the entire nodelist */
				flexhash_set_genid(SERVER_FLEXHASH, 1);
				cltopo_learn(min_nodeptr, 0, 1, g_ceng);
			} else {
				log_info(lg, "Not enough servers to elect a leader");
			}
		}
		return;
	}

	/* If my serverid is the lowest, I'm a leader */
	for (i = 0; i < nr_nodes; i++) {
		nodeptr = &g_ceng->nodes[i];
		int res = uint128_cmp(&nodeptr->serverid, &g_ceng->me.serverid);
		if (res < 0 && nodeptr->nr_vdevs > 0) {
			ccow_daemon->leader = 0;
			return;
		}
	}

	ccow_daemon->leader = 1;

	char out[UINT128_STR_BYTES];
	uint128_dump(&g_ceng->me.serverid, out, UINT128_STR_BYTES);
	log_info(lg, "ServerID:<%s> is a leader", out);

	int is_rebalance = flexhash_delta_rebalance(SERVER_FLEXHASH);
	if (is_rebalance == 0) {
		clengine_notify_others();
		return;
	}

	int numdevices = clengine_nodes_dev_nr(g_ceng->nodes, nr_nodes);

	ccowd_fhready_lock(FH_LOCK_WRITE);
	int err = flexhash_rebuild_start(SERVER_FLEXHASH,
					 nr_nodes, numdevices);
	ccowd_fhready_unlock(FH_LOCK_WRITE);
	if (err) {
		log_error(lg, "Unable to start a FlexHash rebuild");
		return;
	}

	int me_found = 0;
	for (i = 0; i < nr_nodes; i++) {
		nodeptr = &g_ceng->nodes[i];
		if (uint128_cmp(&nodeptr->serverid, &g_ceng->me.serverid) == 0) {
			me_found = 1;
			break;
		}
	}
	/* Assert that matching nodes to myself is found */
	assert (nr_nodes > 0);
	if (!me_found) {
		log_warn(lg, "This serverid not found in list of nodes: %d. "
		    "Retrying", nr_nodes);
		return;
	}
	*nodeptr = g_ceng->me;
	nodeptr->state = CL_NODE_QUERY_ISSUED;

	/*
	 * Update leader's information locally as clengine_learn_cluster()
	 * will not send SLG to the leader (itself - me).
	 */
	err = reptrans_copy_hashcount(0, nodeptr);
	if (err) {
		log_error(lg, "Unable to start flexhash rebuild");
		g_ceng->me.vdevs = NULL;
		g_ceng->me.nr_vdevs = 0;
		return;
	}

	g_ceng->me.vdevs = nodeptr->vdevs;
	g_ceng->me.nr_vdevs = nodeptr->nr_vdevs;

	clengine_fh_update(out, nodeptr);

	log_notice(lg, "Sending out a topo learn to %d nr_nodes", nr_nodes);
	clengine_learn_cluster(known_nodes, nr_nodes);

	g_ceng->last_discovery = get_timestamp_us();

	ccow_daemon->role_changed = 1;

	/* Start cluster health timer */
	if (g_ceng->clust_health_req->data == NULL) {
		clengine_health_start();
	}
}

/*
 * Match existing nodes with new and copy the state.
 */
static void
clengine_preserve_node_states(struct cl_node *members, size_t nr_members)
{
	for (size_t i = 0; i < nr_members; i++) {
		for (size_t j = 0; j < g_ceng->nr_nodes; j++) {
			if (uint128_cmp(&members[i].serverid,
					&g_ceng->nodes[j].serverid)  == 0) {
				members[i].state = g_ceng->nodes[j].state;
				break;
			}
		}
	}

}

/*
 * Copy new nodes passed from corosync into clengine.
 */
static void
clengine_copy_new_nodes(struct cl_node *members, size_t nr_members)
{
	for (size_t i = 0; i < nr_members; i++) {
		g_ceng->nodes[i] = members[i];
		g_ceng->nodes[i].vdevs = NULL;
	}
	g_ceng->nr_nodes = nr_members;
}

static void
clengine_join_cb(struct cl_node *joined, struct cl_node *members,
	size_t nr_members, int result, void *opaque,
	int opaque_len)
{
	int err;
	size_t i;
	char out[UINT128_STR_BYTES];
	char serverstr[UINT128_STR_BYTES];
	char dst[INET6_ADDRSTRLEN];
	uint128_dump(&joined->serverid, out, UINT128_STR_BYTES);
	inet_ntop(AF_INET6, &joined->addr, dst, INET6_ADDRSTRLEN);

	log_trace(lg, "joined %p members %p nr_members %ld result %d "
	    "opaque %p opaque_len %d", joined, members, nr_members, result,
	    opaque, opaque_len);

	log_trace(lg, "ServerID:<%s> joined. ip:<%s> ", out, dst);

	clengine_preserve_node_states(members, nr_members);
	clengine_copy_new_nodes(members, nr_members);
	clengine_reptrans_notify(1, nr_members);

	/* restart fhtimer on every join */
	clengine_start_fhtimer();
	SERVER_FLEXHASH->is_ready = FH_AFFECTED;

	// since the timer need a count of all devices
	// we make sure we add the nr_vdev count to the global
	// list
	for (i = 0; i < nr_members; i++) {
		struct cl_node *node = &g_ceng->nodes[i];
		if (uint128_cmp(&joined->serverid, &node->serverid) == 0) {
			if ((opaque_len > 0) && (opaque)) {
				g_ceng->nodes[i].nr_vdevs
					= opaque_len/sizeof (struct cl_vdev);
				g_ceng->nodes[i].vdevs = (struct cl_vdev *) opaque;
				log_debug(lg, "NR MEMBER %lu NR VDEVS %d",
				    i, g_ceng->nodes[i].nr_vdevs);
			}
		}
	}

	// we don't need to add ourselves.
	if (uint128_cmp(&joined->serverid, &g_ceng->me.serverid) == 0)
		return;


	log_info(lg, "Adding ServerID:<%s> ip:<%s> to flexhash", out, dst);
	flexhash_lock(SERVER_FLEXHASH);
	struct fhserver *fhserver
		= flexhash_add_server_only(SERVER_FLEXHASH, joined);
	flexhash_unlock(SERVER_FLEXHASH);
	if (!fhserver) {
		uint128_dump(&joined->serverid, serverstr, UINT128_STR_BYTES);
		log_warn(lg, "Unable to add server: %s ", serverstr);
		return;
	}

	// these are updates for non-initial case, i.e. genid != 1
	if ((opaque_len > 0) && (opaque) && SERVER_FLEXHASH->genid != 1) {
		joined->vdevs = (struct cl_vdev *) opaque;
		joined->nr_vdevs = opaque_len/sizeof (struct cl_vdev);

		err = flexhash_add_vdevs(SERVER_FLEXHASH,
		    joined, fhserver, 0, FH_NOGOOD_HC, FH_NO_REBUILD);
		if (err) {
			log_error(lg, "Unable to add vdevs to the server ");
			return;
		}
	}
}

static void
clengine_leave_cb(struct cl_node *left, struct cl_node *members,
	size_t nr_members)
{
	char out[UINT128_STR_BYTES];
	char dst[INET6_ADDRSTRLEN];
	uint128_dump(&left->serverid, out, UINT128_STR_BYTES);
	inet_ntop(AF_INET6, &left->addr, dst, INET6_ADDRSTRLEN);

	log_trace(lg, "left %p members %p nr_members %ld", left, members,
	    nr_members);

	log_info(lg, "ServerID %s ip %s left\n", out, dst);

	/* prevent self-induced amnesia */
	if (uint128_cmp(&left->serverid, &g_ceng->me.serverid) == 0)
		return;

	struct fhserver *fhserver;
	flexhash_lock(SERVER_FLEXHASH);
	fhserver = flexhash_get_fhserver(SERVER_FLEXHASH, &left->serverid);
	if (!fhserver) {
		log_debug(lg, "Cannot find serverid %s in FH", out);
		flexhash_unlock(SERVER_FLEXHASH);
		return;
	}

	if (fhserver->nr_vdevs > 0) {
		struct fhdev *fhdev = fhserver->vdevlist.devlist;
		while (fhdev != NULL) {
			struct lvdev *lvdev = fhdev->vdev;
			/* tell the audit server about this server's vdevids */
			auditc_servervdev(gauge, "clengine.server", &left->serverid,
			    &lvdev->vdevid, dst, 0.0);
			fhdev = fhdev->next;
		}
	} else {
		auditc_servervdev(gauge, "clengine.server", &left->serverid,
		    &uint128_null, dst, 0.0);
	}

	int err = flexhash_remove_server(SERVER_FLEXHASH, left);
	flexhash_unlock(SERVER_FLEXHASH);
	if (err) {
		log_error(lg, "Unable to remove serverid %s from "
		    "flexhash err=%d", out, err);
	}

	clengine_preserve_node_states(members, nr_members);
	clengine_copy_new_nodes(members, nr_members);
	clengine_reptrans_notify(0, nr_members);
	/* restart fhtimer on every leave */
	clengine_start_fhtimer();
	SERVER_FLEXHASH->is_ready = FH_AFFECTED;
}

static int
clnotify_blob_lookup_pack(msgpack_p* p, const uint512_t* chid, uint8_t ttag,
	uint8_t hash_type, const uint128_t *ipaddr, uint32_t scope_id, uint16_t port,
	uint32_t sequence_num, uint32_t sub_sequence_num, uint64_t txcookie) {
	int err = replicast_pack_uint512(p, chid);
	if (err)
		return err;

	err = msgpack_pack_uint8(p, ttag);
	if (err)
		return err;

	err = msgpack_pack_uint8(p, hash_type);
	if (err)
		return err;

	err = msgpack_pack_uint16(p, port);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, sequence_num);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, sub_sequence_num);
	if (err)
		return err;
	err = msgpack_pack_uint64(p, txcookie);
	if (err)
		return err;

	err = replicast_pack_uint128(p, ipaddr);
	if (err)
		return err;
	err = msgpack_pack_uint32(p, scope_id);

	return err;
}

static int
clnotify_blob_lookup_unpack(msgpack_u* u, uint512_t* chid, uint8_t* ttag,
	uint8_t* hash_type, uint128_t *ipaddr, uint32_t *scope_id, uint16_t *port,
	uint32_t *sequence_num, uint32_t *sub_sequence_num, uint64_t *txcookie) {

	int err = replicast_unpack_uint512(u, chid);
	if (err)
		return err;

	err = msgpack_unpack_uint8(u, ttag);
	if (err)
		return err;

	err = msgpack_unpack_uint8(u, hash_type);
	if (err)
		return err;

	err = msgpack_unpack_uint16(u, port);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, sequence_num);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, sub_sequence_num);
	if (err)
		return err;
	err = msgpack_unpack_uint64(u, txcookie);
	if (err)
		return err;
	err = replicast_unpack_uint128(u, ipaddr);
	if (err)
		return err;
	err = msgpack_unpack_uint32(u, scope_id);

	return err;
}

int
clengine_queue_rowusage_job(uint128_t *src_vdevid, uint128_t *dest_vdevid,
			    uint32_t row, int same_fdomain)
{
	int err=0;

	char src_vdevstr[64];
	char dest_vdevstr[64];
	uint128_dump(src_vdevid, src_vdevstr, 64);
	uint128_dump(dest_vdevid, dest_vdevstr, 64);
	return err;
}

static void
clengine_notify_cb(struct cl_node *sender, void *msg, size_t msg_len)
{
	log_trace(lg, "sender %p msg %p msg_len %ld", sender, msg, msg_len);

	char *cmd = (char *) msg;
	if (strncmp(cmd, "BG_RESTART", 10) == 0) {
		reptrans_bgjobs_restart();
	} else if (strncmp(cmd, "STAT_UPDATE", 11) == 0) {
		/* Message format as ASCII string:
		 *
		 * <srvid>:<type>:<srv_phys_used>:<n_devs>
		 * :<vdevid1>:<vdev1_used_bytes>:..
		 * :<vdevidN>:<vdevN_used_bytes>
		 */

		*(cmd + msg_len) = 0;
		char srvid[UINT128_BYTES*2 + 1];
		memcpy(srvid, cmd + 11, UINT128_BYTES*2);
		srvid[UINT128_BYTES*2] = 0;
		char *sp = NULL;
		char *token = strtok_r(cmd + 45, ":", &sp);
		if (!token)
			return;
		uint32_t stat_type = strtoull(token, NULL, 10);
		token = strtok_r(NULL, ":", &sp);
		if (!token)
			return;
		uint64_t value = strtoull(token, NULL, 10);

		log_debug(lg, "Updating FH table for %s : %u : %lu", srvid,
		    stat_type, value);
		if (stat_type == CLENGINE_STAT_PHYSICAL_USED) {
			token = strtok_r(NULL, ":", &sp);
			if (!token) {
				log_error(lg, "An unexpected end of a STAT_UPDATE message");
				return;
			}
			int n_vdevs = strtoull(token, NULL, 10);
			for (int i = 0; i < n_vdevs; i++) {
				uint128_t vdevid = uint128_null;
				uint64_t used = 0;
				token = strtok_r(NULL, ":", &sp);
				if (!token) {
					log_error(lg, "An unexpected end of a STAT_UPDATE message");
					return;
				}
				assert(strlen(token) == UINT128_BYTES*2);
				uint128_fromhex(token, strlen(token), &vdevid);
				token = strtok_r(NULL, ":", &sp);
				if (!token) {
					log_error(lg, "An unexpected end of a STAT_UPDATE message");
					return;
				}
				used = strtoull(token, NULL, 10);
				flexhash_update_vdev_physical_used(SERVER_FLEXHASH,
				    &vdevid, used);
			}
		} else if (stat_type == CLENGINE_STAT_LOGICAL_USED)
			flexhash_total_logical_used(SERVER_FLEXHASH, &value);
	} else if (strncmp(cmd, "TRLOG_BATCH_FINISHED.", 21) == 0) {
		// <vdevid>:<seq_ts as uint64>
		*(cmd + msg_len) = 0;

		char vdevid[32 + 1];
		memcpy(vdevid, cmd + 21, 32);
		vdevid[32] = 0;

		uint64_t batch_seq_ts = strtoull(cmd + 54, NULL, 10);
		if (batch_seq_ts) {
			log_debug(lg, "TRLOG batch finished for %s.%lu",
			    vdevid, batch_seq_ts);
			flexhash_lock(SERVER_FLEXHASH);
			local_flexhash_update_vdev_seqid(SERVER_FLEXHASH,
			    vdevid, batch_seq_ts);
			flexhash_unlock(SERVER_FLEXHASH);
		} else {
			log_error(lg, "Received batch_seq_ts == 0");
		}
	} else if (strncmp(cmd, "TRLOG_INPROG_BATCH_FINISHED.", 28) == 0) {
		// <serverid>:<seq_ts as uint64>
		*(cmd + msg_len) = 0;

		char serverid[32 + 1];
		memcpy(serverid, cmd + 28, 32);
		serverid[32] = 0;

		uint64_t batch_seq_ts = strtoull(cmd + 61, NULL, 10);
		if (batch_seq_ts) {
			log_debug(lg, "TRLOG inprog batch finished for %s.%lu",
			    serverid, batch_seq_ts);
			flexhash_lock(SERVER_FLEXHASH);
			local_flexhash_update_serverid_seqid(SERVER_FLEXHASH,
			    serverid, batch_seq_ts);
			flexhash_unlock(SERVER_FLEXHASH);
		} else {
			log_error(lg, "Received inprog batch_seq_ts == 0");
		}
	} else if (strncmp(cmd, "TRLOG_INPROG_BATCH.", 19) == 0) {
		*(cmd + msg_len) = 0;
		uint64_t cts = strtoull(cmd + 19, NULL, 10);
		if (cts) {
			ccowd_fhready_lock(FH_LOCK_WRITE);
			ccow_daemon->leader_batch_seq_ts = cts;
			ccowd_fhready_unlock(FH_LOCK_WRITE);
		} else {
			log_error(lg, "Received inprog batch CTS == 0");
		}

	} else if (strncmp(cmd, "TRLOG_CTS.", 10) == 0) {
		*(cmd + msg_len) = 0;
		uint64_t cts = strtoull(cmd + 10, NULL, 10);
		if (cts) {
			log_info(lg, "CTS drift %ld us",
			    ((int64_t)cts - (int64_t)COORDINATED_TS()));
			if (ccow_daemon->leader_coordinated_ts != cts)
				ccow_daemon->local_coordinated_ts = get_timestamp_us();
			ccow_daemon->leader_coordinated_ts = cts;
		} else {
			log_error(lg, "Received batch CTS == 0");
		}

	} else if (strncmp(cmd, "GW_CACHE_GC.", 12) == 0) {
		/*
		 * run a pass of the gateway cache garbage collector.
		 */
		reptrans_gw_cache_gc();

	} else if (strncmp(cmd, "FH_CPUPD.", 9) == 0) {
		*(cmd + msg_len) = 0;
		char *sig = cmd + 9;
		if (ccow_daemon->leader) {
			log_debug(lg, "Received FH_CPUPD request, sig=%s", sig);
			if (strncmp("SIGUSR1", sig, 7) == 0)
				raise(SIGUSR1);
			else if (strncmp("SIGUSR2", sig, 7) == 0)
				raise(SIGUSR2);
			else
				log_error(lg, "Received wrong FH_CPUPD request, sig=%s", sig);
		}
	} else if (strncmp(cmd, "FH_CPSET.", 9) == 0) {
		*(cmd + msg_len) = 0;
		uint64_t recv_genid = strtoull(cmd + 9, NULL, 10);
		if (recv_genid != 0) {
			log_debug(lg, "Received FH_CPSET request, genid=%lu",
			    recv_genid);
			flexhash_lock(SERVER_FLEXHASH);
			int err = flexhash_cpset(SERVER_FLEXHASH, recv_genid);
			flexhash_unlock(SERVER_FLEXHASH);
			if (!err)
				SERVER_FLEXHASH->cpgenid = recv_genid;
			else
				log_error(lg, "Unable to set FH checkpoint, err %d", err);
		}
	} else if (strncmp(cmd, "FH_READY.", 9) == 0) {
		/*
		 * Stop the timer if still running. The fact that we received
		 * notification means we've got new FH and ready to update. So, we
		 * do not need timer any longer..
		 */
		if (g_ceng->fhtimer_req->data) {
			uv_timer_stop(g_ceng->fhtimer_req);
			g_ceng->fhtimer_req->data = NULL;
		}
		*(cmd + msg_len) = 0;
		uint64_t recv_genid = strtoull(cmd + 9, NULL, 10);
		log_notice(lg, "Received new FlexHash update genid=%ld", recv_genid);
	} else if (strncmp(cmd, "FH_VDEV_DEAD", 12) == 0) {
		// pull the vdevid and tell flexhash that this is dead
		char *vstr = cmd + 12;
		if (msg_len != (12 + UINT128_STR_BYTES)) {
			log_error(lg, "Incorrect size of message received on FH_VDEV_DEAD");
			return;
		}
		uint128_t vdevid;
		uint128_fromhex(vstr, (msg_len - 12), &vdevid);
		log_notice(lg, "Received a vdev dead message for %s", vstr);
		flexhash_leave(SERVER_FLEXHASH, &vdevid);
		if (SERVER_FLEXHASH->leader == 1) {
			clengine_rediscover_on_drive_change();
			return;
		}
	} else if (strncmp(cmd, "FH_VDEV_ALIVE", 13) == 0) {
		char *vstr = cmd + 13;
		if (msg_len != (13 + UINT128_STR_BYTES)) {
			log_error(lg, "Incorrect size of message received on FH_VDEV_ALIVE");
			return;
		}
		uint128_t vdevid;
		uint128_fromhex(vstr, (msg_len - 13), &vdevid);
		vdevstore_mark_alive(SERVER_FLEXHASH->vdevstore, &vdevid);
		if (SERVER_FLEXHASH->leader == 1) {
			clengine_rediscover_on_drive_change();
			return;
		}
	} else if (strncmp(cmd, "FH_VDEV_READ_ONLY", 17) == 0) {
		char *vstr = cmd + 17;
		if (msg_len != (17 + UINT128_STR_BYTES)) {
			log_error(lg, "Incorrect size of message received on FH_VDEV_READ_ONLY");
			return;
		}
		uint128_t vdevid;
		uint128_fromhex(vstr, (msg_len - 17), &vdevid);
		vdevstore_mark_ro(SERVER_FLEXHASH->vdevstore, &vdevid);
		if (SERVER_FLEXHASH->leader == 1) {
			clengine_rediscover_on_drive_change();
			return;
		}
	} else if (strncmp(cmd, "SET_MAINTTIME", 13) == 0) {
		char value[16] = {0};
		memcpy(value, cmd + 13, msg_len - 13);
		int minutes = strtol(value, NULL, 10);
		if (minutes) {
			log_notice(lg, "Maintenance mode is activated for %d minutes", minutes);
				ccow_daemon->maintenance_ts = get_timestamp_monotonic_us() + minutes*60*1024UL*1024UL;
		} else if (ccow_daemon->maintenance_ts) {
			log_notice(lg, "Maintenance mode deactivated");
			ccow_daemon->maintenance_ts = 0;
		}
	} else if (strncmp(cmd, "BLOB_LOOKUP_REQ", 15) == 0) {
		uint512_t chid;
		msgpack_u* u = msgpack_unpack_init(cmd+15, msg_len-15, 0);
		if (!u) {
			log_error(lg, "Couldn't start msgunpack");
			return;
		}
		uint8_t ttag8 = 0, hash_type8 = 0;
		uint128_t ipaddr;
		uint16_t port = 0;
		uint32_t sequence_num = 0;
		uint32_t sub_sequence_num = 0;
		uint64_t txcookie = 0;
		uint32_t scope_id = 0;
		int err = clnotify_blob_lookup_unpack(u, &chid, &ttag8, &hash_type8, &ipaddr, &scope_id, &port, &sequence_num, &sub_sequence_num, &txcookie);
		msgpack_unpack_free(u);
		if (err) {
			log_error(lg, "Error during blob lookup request");
			return;
		}
		crypto_hash_t hash_type = hash_type8;
		type_tag_t ttag = ttag8;

		uint128_t* vdevs = NULL;
		uint16_t ndevs = 0;
		err = reptrans_blob_lookup(ttag, hash_type, &chid, &vdevs, &ndevs);
		if (err) {
			log_error(lg, "Blob lookup error");
			return;
		}

		char chidstr[UINT512_BYTES * 2 + 1];
		uint512_dump(&chid, chidstr, UINT512_BYTES * 2 + 1);
		if (!ndevs) {
			log_notice(lg, "Lookup for CHID %s TYPE %s haven't "
				"given any results", chidstr, type_tag_name[ttag]);
		} else {
			char *vdevstr = je_malloc((UINT128_BYTES * 2 + 2) * ndevs + 1);
			if (!vdevstr) {
				log_error(lg, "Memory allocation error");
				return;
			}
			memset(vdevstr, 0, (UINT128_BYTES * 2 + 2) * ndevs + 1);
			for (size_t n = 0; n < ndevs; n++) {
				if (n > 0)
					strcat(vdevstr, ", ");
				uint128_dump(vdevs + n, vdevstr + strlen(vdevstr), UINT128_STR_BYTES);
			}
			log_notice(lg, "Blob lookup: CHID %s TYPE %s found on VDEV(s): %s"
				, chidstr, type_tag_name[ttag], vdevstr);
			je_free(vdevstr);
		}


		static struct repmsg_blob_lookup omsg;
		omsg.hdr.transaction_id.sequence_num = sequence_num;
		omsg.hdr.transaction_id.sub_sequence_num = sub_sequence_num;
		omsg.hdr.transaction_id.txcookie = txcookie;
		struct repmsg_blob_lookup_result *rep_msg = je_calloc(1, sizeof(struct repmsg_blob_lookup_result));
		rep_msg->ndevs = ndevs;

		struct sockaddr_in6 to_addr;
		to_addr.sin6_port = htons(port);
		to_addr.sin6_family = AF_INET6;
		to_addr.sin6_flowinfo = 0;
		to_addr.sin6_scope_id = scope_id;
		memcpy(&to_addr.sin6_addr,
		    &ipaddr, sizeof(to_addr.sin6_addr));

		msgpack_p *p = msgpack_pack_init();
		if (!p)
			goto err;
		err = replicast_pack_uvbuf_vdevs(p, vdevs, ndevs);
		if (err) {
			goto err1;
		}
		uv_buf_t payload;
		payload.base = (char *)p->buffer;
		payload.len = msgpack_get_len(p);

		/* Send ack with list of vdevs */
		replicast_send(ccow_daemon->robj[0], NULL, RT_BLOB_LOOKUP_RESULT,
				(struct repmsg_generic *)rep_msg, (struct repmsg_generic *)&omsg,
				&payload, 1, &to_addr, NULL, NULL, NULL);
err1:
		msgpack_pack_free(p);
err:
		je_free(vdevs);

	} else if (strncmp(cmd, "FH_ROW_UPDATE", 13) == 0 && msg_len > 14) {
		local_flexhash_row_update(SERVER_FLEXHASH, &cmd[14]);
	} else if (strncmp(cmd, "FH_ROW_USAGE_CHANGE", 19) == 0) {
		*(cmd + msg_len) = 0;
		size_t cursor = 20;

		/* Process start of row change */
		if (cmd[cursor] == 'S' && strncmp(&cmd[cursor], "START", 5) == 0) {

			cursor += 6;

			char src_vdevstr[UINT128_STR_BYTES + 1];
			memcpy(src_vdevstr, &cmd[cursor], UINT128_STR_BYTES);
			src_vdevstr[UINT128_STR_BYTES] = 0;

			cursor += UINT128_STR_BYTES;
			char dest_vdevstr[UINT128_STR_BYTES + 1];
			memcpy(dest_vdevstr, &cmd[cursor], UINT128_STR_BYTES);
			dest_vdevstr[UINT128_STR_BYTES] = 0;

			cursor += UINT128_STR_BYTES;
			char *row_str = &cmd[cursor];
			char *fdomain_part = strchr(&cmd[cursor], ':');
			*fdomain_part = '\0';
			fdomain_part++;
			uint32_t rowid = strtoul(row_str, NULL, 10);
			int same_fdomain = atoi(fdomain_part);

			uint128_t src_vdevid;
			uint128_t tgt_vdevid;
			uint128_fromhex(src_vdevstr, UINT128_STR_BYTES, &src_vdevid);
			uint128_fromhex(dest_vdevstr, UINT128_STR_BYTES, &tgt_vdevid);
			int member = flexhash_is_rowmember_fhrow(SERVER_FLEXHASH, &tgt_vdevid, rowid);
			if (!member) {
				flexhash_join(SERVER_FLEXHASH, rowid, &tgt_vdevid);
				rowevac_join_target(&tgt_vdevid, rowid);
				reptrans_on_flexhash_rebuild_done(SERVER_FLEXHASH, 1);
				if (flexhash_checkpoint_exists()) {
					SERVER_FLEXHASH->genid++;
					flexhash_update_checkpoint(SERVER_FLEXHASH, "Row Usage update");
				}
			}
		}

		/* Process start of row change */
		if (cmd[cursor] == 'E' && strncmp(&cmd[cursor], "END", 3) == 0) {
			cursor += 4;

			char src_vdevstr[UINT128_STR_BYTES + 1];
			memcpy(src_vdevstr, &cmd[cursor], UINT128_STR_BYTES);
			src_vdevstr[UINT128_STR_BYTES] = 0;

			cursor += UINT128_STR_BYTES;
			char tgt_vdevstr[UINT128_STR_BYTES + 1];
			memcpy(tgt_vdevstr, &cmd[cursor], UINT128_STR_BYTES);
			tgt_vdevstr[UINT128_STR_BYTES] = 0;

			cursor += UINT128_STR_BYTES;
			uint32_t rowid = strtoul(&cmd[cursor], NULL, 10);

			uint128_t src_vdevid, tgt_vdevid;
			uint128_fromhex(src_vdevstr, UINT128_STR_BYTES, &src_vdevid);
			uint128_fromhex(tgt_vdevstr, UINT128_STR_BYTES, &tgt_vdevid);
			int member = flexhash_is_rowmember_fhrow(SERVER_FLEXHASH, &src_vdevid, rowid);
			if (member) {
				int idx = flexhash_getvdev_index(SERVER_FLEXHASH, &src_vdevid);
				assert(idx >= 0);
				flexhash_vdev_leave(SERVER_FLEXHASH, rowid, idx);
				if (flexhash_checkpoint_exists()) {
					SERVER_FLEXHASH->genid++;
					flexhash_update_checkpoint(SERVER_FLEXHASH, "Row Usage update");
				}
			} else {
				log_error(lg, "The VDEV %016lX%016lX isn't a member of row %d on leave",
					src_vdevid.u, src_vdevid.l, rowid);
			}
		}
	}
}

static void
clengine_flexhash_cb(struct cl_node *sender, void *fhbuf, size_t fhbuf_len)
{
	assert(ccow_daemon->loop_thrid == uv_thread_self());

	// ignore self messages
	if (uint128_cmp(&sender->serverid, &g_ceng->me.serverid) == 0) {
		return;
	}

	int ckp_numdevices = flexhash_checkpoint_numdevices();

	struct flexhash *cfhtable = flexhash_read_buf(ckp_numdevices, fhbuf, fhbuf_len);
	if (!cfhtable) {
		log_error(lg, "Unable to read the flexhash table from corosync buffer");
		return;
	}

	if (cfhtable->genid == SERVER_FLEXHASH->genid) {
		log_error(lg, "Received a flexhash with the same genid, ignoring ");
		return;
	}
	flexhash_copy_mcbase(cfhtable, SERVER_FLEXHASH);

	// We are the receiver here so we cannot be a leader
	cfhtable->leader = 0;

	ccowd_fhready_lock(FH_LOCK_WRITE);

	volatile struct flexhash *tmpfh = ccow_daemon->flexhash;
	ccow_daemon->flexhash = cfhtable;
	ccow_daemon->flexhash_version++;
	ccow_daemon->flexhash->checkpoint_numdevices = clengine_update_fddelta(ccow_daemon->flexhash);
        flexhash_set_fhready(ccow_daemon->flexhash);
        clengine_set_genid(ccow_daemon->flexhash);
        flexhash_set_fdmode(ccow_daemon->flexhash);
        flexhash_table_destroy(tmpfh);

	ccowd_fhready_unlock(FH_LOCK_WRITE);

	flexhash_table_dump(ccow_daemon->flexhash, "corosync_received");

	// now go through the flexhash and do mc group joins for the vdevs that belong to me.
        reptrans_on_flexhash_rebuild_done(ccow_daemon->flexhash, 1);
        if (ccow_daemon && ccow_daemon->bg_restart) {
                ccow_daemon->bg_restart = 0;
                clengine_bgrestart_request();
        }
        clengine_notify_auditserv(&g_ceng->me, NULL);
}

static void
clengine_dispatch(uv_poll_t *req, int status, int events)
{
	if (events & UV_READABLE) {
		g_ceng->dispatch();
	}
}

int
clengine_init(const char *name, struct cl_node *myself)
{
	nassert(ccow_daemon->loop_thrid == uv_thread_self());
	g_ceng = clengine_find(name);
	if (!g_ceng) {
		log_error(lg, "Cluster engine %s not found", name);
		return -1;
	}

	int err = clengine_copy_cl_node(&g_ceng->me, myself);
	if (err) {
		log_error(lg, "Unable to copy my node information to the cluster engine");
		return err;
	}

	struct clengine_handlers handlers;
	handlers.join_handler = clengine_join_cb;
	handlers.leave_handler = clengine_leave_cb;
	handlers.notify_handler = clengine_notify_cb;
	handlers.flexhash_handler = clengine_flexhash_cb;

	g_ceng->group_fd = g_ceng->init(&handlers, NULL);
	if (g_ceng->group_fd < 0)
		return -1;

	char out[UINT128_STR_BYTES];
	char dst[INET6_ADDRSTRLEN];
	uint128_dump(&g_ceng->me.serverid, out, UINT128_STR_BYTES);
	inet_ntop(AF_INET6, &ccow_daemon->msg_origin_sockaddr.sin6_addr, dst, INET6_ADDRSTRLEN);
	log_notice(lg, "Cluster Engine join cluster: <%s> node:<%s> ip:<%s> 4over6:%d",
		name, out, dst, REP_IS_4OVER6(&ccow_daemon->msg_origin_sockaddr));

	if (myself->nr_vdevs > 0) {
		/* tell the audit server about this server */
		for (uint32_t i = 0; i < myself->nr_vdevs; i++) {
			struct cl_vdev *vdev = &myself->vdevs[i];
			double vdev_status = clengine_get_vdev_online_status(vdev);
			auditc_servervdev(gauge, "clengine.server", &myself->serverid,
			    &vdev->vdevid, dst, vdev_status);
		}
	} else {
		auditc_servervdev(gauge, "clengine.server", &myself->serverid,
		    &uint128_null, dst, 1.0);
	}

	g_ceng->group_poll_fd = je_calloc(1, sizeof (uv_poll_t));
	if (!g_ceng->group_poll_fd)
		return -ENOMEM;

	uv_poll_init(ccow_daemon->loop, g_ceng->group_poll_fd,
	    g_ceng->group_fd);
	uv_poll_start(g_ceng->group_poll_fd, UV_READABLE, clengine_dispatch);

	g_ceng->fhtimer_req = je_calloc(1, sizeof (uv_timer_t));
	if (!g_ceng->fhtimer_req)
		return -ENOMEM;
	uv_timer_init(ccow_daemon->loop, g_ceng->fhtimer_req);

	g_ceng->clust_health_req = je_calloc(1, sizeof (uv_timer_t));
	if (!g_ceng->clust_health_req)
		return -ENOMEM;
	uv_timer_init(ccow_daemon->loop, g_ceng->clust_health_req);

	g_ceng->coro_timer_req = je_calloc(1, sizeof (uv_timer_t));
	if (!g_ceng->coro_timer_req)
		return -ENOMEM;
	uv_timer_init(ccow_daemon->loop, g_ceng->coro_timer_req);

	err = g_ceng->join(myself, check_join_cb, myself->vdevs,
	    myself->nr_vdevs * sizeof (struct cl_vdev));
	if (err) {
		log_error(lg, "Error while joining, err: %d", err);
		return err;
	}
	replicast_state_init(ccow_daemon->robj[0], RT_SERVER_LIST_GET,
	    cltopo_server_list_init);

	replicast_state_init(ccow_daemon->robj[0], RT_BLOB_LOOKUP,
		blob_lookup_srv_init);

	clengine_register_rowusage_start_cb(clengine_queue_rowusage_job);

	log_info(lg, "Cluster Engine %s now initialized", name);
	clengine_corotimer_start();

	/* mark vdevs as dead and do not remove them */
	g_ceng->rmvdev = 0;

	return 0;
}


int
clengine_stop()
{
	nassert(ccow_daemon->loop_thrid == uv_thread_self());
	return g_ceng->leave();
}

static void
clengine_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

int
clengine_destroy()
{
	if (g_ceng->fhtimer_req->data)
		uv_timer_stop(g_ceng->fhtimer_req);
	uv_close((uv_handle_t *)g_ceng->fhtimer_req, clengine_close_cb);

	if (g_ceng->clust_health_req->data)
		uv_timer_stop(g_ceng->clust_health_req);
	uv_close((uv_handle_t *)g_ceng->clust_health_req, clengine_close_cb);

	if (g_ceng->coro_timer_req->data)
		uv_timer_stop(g_ceng->coro_timer_req);
	uv_close((uv_handle_t *)g_ceng->coro_timer_req, clengine_close_cb);

	if (g_ceng->group_fd != -1) {
		if (uv_is_active((uv_handle_t *)g_ceng->group_poll_fd))
			uv_poll_stop(g_ceng->group_poll_fd);

		uv_close((uv_handle_t *)g_ceng->group_poll_fd, clengine_close_cb);
	}

	return corosync_cleanup();
}

void
clengine_tick()
{
	nassert(ccow_daemon->loop_thrid == uv_thread_self());
	uv_run(ccow_daemon->loop, UV_RUN_ONCE);
}

int
clengine_reinit(int skip_cp)
{
	if (ccow_daemon->startup_err)
		return -ENOEXEC;
	ccow_daemon->skip_cp = skip_cp;
	clengine_destroy();
	int err = clengine_init("corosync", &g_ceng->me);

	log_notice(lg, "clengine reinit err=%d, skip: %d", err, skip_cp);

	return err;
}

void
clengine_reenable()
{
	if (g_ceng->group_fd != -1) {
		if (uv_is_active((uv_handle_t *)g_ceng->group_poll_fd))
			uv_poll_stop(g_ceng->group_poll_fd);
		uv_close((uv_handle_t *)g_ceng->group_poll_fd, clengine_close_cb);
		g_ceng->group_fd = -1;
		return;
	}

	corosync_ring_reinit(&g_ceng->group_fd);
	if (g_ceng->group_fd == -1)
		return;

	g_ceng->group_poll_fd = je_calloc(1, sizeof (uv_poll_t));
	if (!g_ceng->group_poll_fd)
		return;

	uv_poll_init(ccow_daemon->loop, g_ceng->group_poll_fd,
	    g_ceng->group_fd);
	uv_poll_start(g_ceng->group_poll_fd, UV_READABLE, clengine_dispatch);

	log_notice(lg, "clengine reenabled successfully");
}

static void
clengine_notify__async(struct repdev *dev, void *arg, int status)
{
	uv_buf_t *msg = arg;
	assert(msg != NULL);

	g_ceng->notify(msg->base, msg->len, NULL);

	je_free(msg->base);
	je_free(msg);
}

int
clengine_notify_raw(char *msg, size_t len)
{
	struct reptrans *rt = NULL;
	QUEUE *q;

	QUEUE_FOREACH(q, &all_rts) {
		rt = QUEUE_DATA(q, struct reptrans, item);
		break;
	}
	if (!rt)
		return -EBADF;

	struct reptrans_call *call = je_calloc(1, sizeof(struct reptrans_call));
	if (call == NULL) {
		return -ENOMEM;
	}
	uv_buf_t *buf = je_calloc(1, sizeof(uv_buf_t));
	if (!msg) {
		je_free(call);
		return -ENOMEM;
	}
	buf->base = je_malloc(len);
	if (!len) {
		je_free(buf);
		je_free(call);
		return -ENOMEM;
	}
	memcpy(buf->base, msg, len);
	buf->len = len;
	call->method = clengine_notify__async;
	call->arg = buf;
	if (!call->arg) {
		je_free(call);
		return -ENOMEM;
	}
	QUEUE_INIT(&call->item);
	uv_mutex_lock(&rt->call_mutex);
	QUEUE_INSERT_TAIL(&rt->call_queue, &call->item);
	uv_mutex_unlock(&rt->call_mutex);
	uv_async_send(&rt->call_async);
	return 0;
}

int
clengine_notify(char *msg) {
	return clengine_notify_raw(msg, strlen(msg)+1);
}

struct cluster_engine *
clengine_find(const char *name)
{
	int len;
	QUEUE *q;

	QUEUE_FOREACH(q, &cluster_engines) {
		struct cluster_engine *ceng =
			QUEUE_DATA(q, struct cluster_engine, item);
		len = strlen(ceng->name);

		if (strncmp(ceng->name, name, len) == 0 &&
		    (name[len] == ':' || name[len] == '\0'))
			return ceng;
	}

	return NULL;
}

const char *
clengine_get_option(struct cluster_engine *ceng, const char *arg)
{
	int len = strlen(ceng->name);

	if (arg[len] == ':')
		return je_strdup(arg + len + 1);
	else
		return NULL;
}

int
clengine_get_node(uint128_t *serverid, struct cl_node **node)
{
	int err = 0;
	if (uint128_cmp(serverid, &g_ceng->me.serverid) == 0) {
		struct cl_node *retnode = je_calloc(1, sizeof (struct cl_node));
		if (!retnode)
			return -ENOMEM;

		struct cl_node *myself = &g_ceng->me;
		err = reptrans_copy_hashcount(0, myself);
		if (err) {
			je_free(retnode);
			retnode = NULL;
			return -ENOMEM;
		}
		flexhash_hashcount_init(myself);

		err = clengine_copy_cl_node(retnode, myself);
		if (err) {
			je_free(retnode);
			retnode = NULL;
			return -ENOMEM;
		}
		*node = retnode;
		err = 0;
	} else {
		err = flexhash_get_nodecopy(SERVER_FLEXHASH, serverid,
						node, FH_GOOD_HC);
	}

	return err;
}


int
clengine_copy_cl_node(struct cl_node *dst_node, struct cl_node *src_node)
{
	if (!src_node || !dst_node)
		return -EBADF;

	/* This happens on cluster_reinit() */
	if (dst_node == src_node)
		return 0;

	dst_node->serverid = src_node->serverid;
	dst_node->addr = src_node->addr;
	dst_node->port = src_node->port;
	dst_node->zone = src_node->zone;
	dst_node->nr_vdevs = src_node->nr_vdevs;

	if (src_node->nr_vdevs == 0) {
		// no need to copy the vdevs.
		return 0;
	}
	dst_node->vdevs
		= je_calloc(dst_node->nr_vdevs, sizeof (struct cl_vdev));
	if (!dst_node->vdevs)
		return -ENOMEM;
	memcpy(dst_node->vdevs, src_node->vdevs,
			dst_node->nr_vdevs * sizeof (struct cl_vdev));

	return 0;
}

void
clengine_destroy_cl_node(struct cl_node *node, int nr_nodes)
{
	if (!node)
		return;
	if (node && nr_nodes > 0) {
		struct cl_node *nodeptr = node;
		for (int i = 0; i < nr_nodes; i++) {
			je_free(nodeptr->vdevs);
			nodeptr->vdevs = NULL;
			nodeptr++;
		}
		je_free(node);
		node = NULL;
	}
}

uint128_t *
clengine_get_mynodeid()
{
	if (!g_ceng)
		return NULL;
	return &g_ceng->me.serverid;
}

int
clengine_copy_mynodeinfo(struct repmsg_server_list_get *msg)
{
	struct cl_node *node = &g_ceng->me;

	msg->sender_serverid = node->serverid;
	msg->sender_recv_addr = node->addr;
	msg->sender_recv_port = node->port;
	msg->nr_vdevs = node->nr_vdevs;
	msg->zone = node->zone;
	msg->vdevs = je_calloc(node->nr_vdevs, sizeof (struct cl_vdev));
	if (!msg->vdevs)
		return -ENOMEM;
	memcpy(msg->vdevs, node->vdevs, node->nr_vdevs * sizeof (struct cl_vdev));
	msg->sender_flags |= SLG_SENDER_SERVER;

	return 0;
}

void
clengine_notify_others(void)
{
	assert(ccow_daemon->loop_thrid == uv_thread_self());

	flexhash_set_fhready(ccow_daemon->flexhash);

	/* only leader calls us, hence assert */
	assert(ccow_daemon->flexhash->leader == 1);

	/* send new FlexHash buffer */
	char *bp;
	size_t bsize = 0;
	flexhash_mem_dump(ccow_daemon->flexhash, 1, "memdump_for_transfer", &bp, &bsize);
	if (!bp) {
		log_error(lg, "Error notifying others with new FlexHash!");
		return;
	}

	int err = g_ceng->flexhash_update(bp, bsize);
	if (err) {
		free(bp);
		log_error(lg, "FATAL: FH leader cannot update the RING");
		clengine_process_shutdown();
		return;
	}
	free(bp);

	/* send FH_READY update, mostly for backward compatibility */
	char buf[128];
	sprintf(buf, "FH_READY.%lu", ccow_daemon->flexhash->genid);
	g_ceng->notify(buf, strlen(buf), NULL);
	clengine_notify_auditserv(&g_ceng->me, NULL);
}

void
clengine_update_others(uint128_t *server_id, int stat_type, const char* msg_str)
{
	char derp[UINT128_STR_BYTES];
	uint128_dump(server_id, derp, UINT128_STR_BYTES);

	assert(msg_str);
	char *msg = je_calloc(1, strlen(msg_str) + 64);
	sprintf(msg, "%s:%s:%u:%s", "STAT_UPDATE", derp, stat_type, msg_str);

	if (ccow_daemon->loop_thrid == uv_thread_self())
		g_ceng->notify(msg, strlen(msg) + 1, NULL);
	else
		clengine_notify(msg);
	je_free(msg);
}

void
clengine_notify_rowusage_change(int start, uint128_t *srv_vdevid,
				uint128_t *dest_vdevid, int rcount,
				int same_fdomain)
{
	char src_vdevstr[64];
	char dest_vdevstr[64];
	uint128_dump(srv_vdevid, src_vdevstr, 64);
	uint128_dump(dest_vdevid, dest_vdevstr, 64);
	char *msg = je_calloc(1, 2 * 64 + sizeof(int) + 4*sizeof(char));
	if (start)
		sprintf(msg, "%s:%s:%s:%s:%d:%d", "FH_ROW_USAGE_CHANGE",
						"START",
						src_vdevstr,
						dest_vdevstr,
						rcount, same_fdomain);
	else
		sprintf(msg, "%s:%s:%s:%s:%d", "FH_ROW_USAGE_CHANGE",
						"END",
						src_vdevstr,
						dest_vdevstr,
						rcount);
	if (ccow_daemon->loop_thrid == uv_thread_self())
		g_ceng->notify(msg, strlen(msg) + 1, NULL);
	else
		clengine_notify(msg);

	je_free(msg);
}

void
clengine_fh_row_update(char *msg)
{
	g_ceng->notify(msg, strlen(msg) + 1, NULL);
}

void
clengine_notify_vdev_state(uint128_t *vdevid, vdevstate_t state)
{
	char msgbuf[2*UINT128_STR_BYTES];
	char out[UINT128_STR_BYTES];
	double vdev_status = 0.0;
	uint128_dump(vdevid, out, UINT128_STR_BYTES);
	if (state == VDEV_STATE_DEAD) {
		sprintf(msgbuf, "FH_VDEV_DEAD%s",out);
		vdev_status = 0.0;
	} else if (state == VDEV_STATE_ALIVE) {
		sprintf(msgbuf, "FH_VDEV_ALIVE%s",out);
		vdev_status = 1.0;
	} else if (state == VDEV_STATE_READ_ONLY) {
		sprintf(msgbuf, "FH_VDEV_READ_ONLY%s",out);
		vdev_status = 2.0;
	}
	clengine_notify(msgbuf);

	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ccow_daemon->msg_origin_sockaddr.sin6_addr, dst,
	    INET6_ADDRSTRLEN);

	// now tell the audit server
	auditc_servervdev(gauge, "clengine.server", &g_ceng->me.serverid,
	    vdevid, dst, vdev_status);
}

int
clengine_notify_maintenance(int minutes)
{
	char msgbuf[128];
	sprintf(msgbuf, "SET_MAINTTIME%d", minutes);

	if (ccow_daemon->loop_thrid == uv_thread_self())
		g_ceng->notify(msgbuf, strlen(msgbuf) + 1, NULL);
	else
		clengine_notify(msgbuf);
	return 0;
}

int
clengine_blob_lookup_request(type_tag_t ttag, crypto_hash_t hash_type,
		const uint512_t* chid, const uint128_t *ipaddr, uint32_t scope_id, uint16_t port,
		uint32_t sequence_num, uint32_t sub_sequence_num, uint64_t txcookie)
{
	msgpack_p* p = msgpack_pack_init();
	if (!p) {
		return -ENOMEM;
	}
	int err = clnotify_blob_lookup_pack(p, chid, ttag, hash_type, ipaddr, scope_id, port, sequence_num, sub_sequence_num, txcookie);
	if (err) {
		msgpack_pack_free(p);
		return err;
	}
	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);
	char* msg = je_calloc(1, buf.len + 15);
	if (!msg) {
		msgpack_pack_free(p);
		return -ENOMEM;
	}

	strcat(msg, "BLOB_LOOKUP_REQ");
	memcpy(msg+15, buf.base, buf.len);

	if (ccow_daemon->loop_thrid == uv_thread_self()) {
		err = g_ceng->notify(msg, buf.len + 15, NULL);
		if (err) {
			log_error(lg, "Error at send a blob lookup notification: %d", err);
		}
	} else
		clengine_notify_raw(msg, buf.len + 15);

	je_free(msg);
	msgpack_pack_free(p);
	return err;
}

static void
clengine_bgrestart_request()
{
	static char* msg = "BG_RESTART";

	if (ccow_daemon->loop_thrid == uv_thread_self())
		g_ceng->notify(msg, strlen(msg) + 1, NULL);
	else
		clengine_notify(msg);
}

int
cl_node_state_match(uint128_t *serverid, enum cl_node_state state)
{
	for (size_t i = 0; i < g_ceng->nr_nodes; i++) {
		if (uint128_cmp(serverid, &g_ceng->nodes[i].serverid) == 0 &&
		    g_ceng->nodes[i].state == state)
			return 1;
	}
	return 0;
}

int
cl_node_state_count(enum cl_node_state state)
{
	int count = 0;

	for (size_t i = 0; i < g_ceng->nr_nodes; i++)
		if (g_ceng->nodes[i].state == state)
			count++;
	return count;
}

void
cl_node_set_state(uint128_t *serverid, enum cl_node_state state)
{
	for (size_t i = 0; i < g_ceng->nr_nodes; i++) {
		if (uint128_cmp(serverid, &g_ceng->nodes[i].serverid) == 0) {
			g_ceng->nodes[i].state = state;
			return;
		}
	}
}

void
cl_all_nodes_set_state(enum cl_node_state state)
{
	for (size_t i = 0; i < g_ceng->nr_nodes; i++)
		g_ceng->nodes[i].state = state;
}

int
clengine_learn_cluster(struct cl_node *cn, int nr_nodes)
{
	int ret = 0;
	struct cl_node *nodeptr;
	char serverstr[UINT128_STR_BYTES], dst[INET6_ADDRSTRLEN];

	for (int i = 0; i < nr_nodes; i++) {
		nodeptr = &cn[i];
		/* Skip the request to the leader (me) */
		if (uint128_cmp(&nodeptr->serverid, &g_ceng->me.serverid) == 0)
			continue;

		uint128_dump(&nodeptr->serverid, serverstr, UINT128_STR_BYTES);
		inet_ntop(AF_INET6, &nodeptr->addr, dst, INET6_ADDRSTRLEN);
		/* TODO: ret from each call gets over-written */
		if (nodeptr->state != CL_NODE_QUERY_ISSUED &&
		    nodeptr->state != CL_NODE_QUERY_SUCCESS) {
			log_info(lg, "Sending out topo learn on leader "
				     "for %s (state %d) at %s",
				     serverstr, nodeptr->state, dst);
			ret = cltopo_learn(nodeptr, nr_nodes, 0, g_ceng);
			if (ret == 0)
				cl_node_set_state(&nodeptr->serverid,
						 CL_NODE_QUERY_ISSUED);
		} else {
			log_warn(lg, "Ignored topo learn on leader "
				     "for %s (state %d) at %s",
				     serverstr, nodeptr->state, dst);
		}
	}
	return ret;
}

/*
 * Recreate flexhash using information from all the nodes.
 */
int
clengine_fh_update_full(char *nodeidstr, struct cl_node *members,
		        size_t nr_members, uint64_t fh_genid,
			uint32_t checkpoint_numdevices)
{
	/* this is a response to the get all request to the leader
	 * to get the latest version of the flexhash that the leader
	 * knows about
	 */

	log_debug(lg, "Received RT_SERVER_LIST_RESPONSE with null parent "
	    "id: %s numdevices: %d", nodeidstr, checkpoint_numdevices);

	int numdevices = clengine_nodes_dev_nr(members, nr_members);

	struct flexhash *newfhtable = flexhash_table_create(checkpoint_numdevices,
	    FH_SERVER_SIDE);
	if (!newfhtable) {
		log_error(lg, "Not enough memory to allocate a new"
		    " flexhash");
		return -ENOMEM;
	}

	newfhtable->checkpoint_numdevices = checkpoint_numdevices;
	newfhtable->numdevices = numdevices;
	flexhash_copy_mcbase(newfhtable, ccow_daemon->flexhash);
	if (fh_genid > 1)
		flexhash_set_genid(newfhtable, fh_genid);
	else {
		log_warn(lg, "Cluster is not ready, retrying ");
		return -ETIME;
	}

	flexhash_lock(newfhtable);
	flexhash_add_serverlist(newfhtable, (struct cl_node *)members,
		(int) nr_members, FH_NO_REBUILD);
	flexhash_unlock(newfhtable);

	ccowd_fhready_lock(FH_LOCK_WRITE);

	volatile struct flexhash *tmpfh = ccow_daemon->flexhash;
	ccow_daemon->flexhash = newfhtable;
	ccow_daemon->flexhash_version++;

	clengine_update_fddelta(ccow_daemon->flexhash);
	flexhash_set_fhready(ccow_daemon->flexhash);
	clengine_set_genid(ccow_daemon->flexhash);
	flexhash_set_fdmode(ccow_daemon->flexhash);
	flexhash_table_destroy(tmpfh);

	ccowd_fhready_unlock(FH_LOCK_WRITE);

	flexhash_table_dump(ccow_daemon->flexhash, "received");

	// now go through the flexhash and do mc group joins
	// for the vdevs that belong to me.
	reptrans_on_flexhash_rebuild_done(ccow_daemon->flexhash, 1);
	if (ccow_daemon && ccow_daemon->bg_restart) {
		ccow_daemon->bg_restart = 0;
		clengine_bgrestart_request();
	}
	clengine_notify_auditserv(&g_ceng->me, NULL);

	// now we notify the background threads to kick off
	ccowd_set_fhrebuild_is_done();

	return 0;
}

void
clengine_notify_auditserv(struct cl_node *node, uint128_t *vdevid)
{
	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &node->addr, dst, INET6_ADDRSTRLEN);

	if (vdevid) {
		auditc_servervdev(gauge, "clengine.server",
		    &node->serverid, vdevid, dst, 1.0);
	} else if (node->nr_vdevs > 0) {
		/* tell the audit server about this server */
		for (uint32_t i = 0; i < node->nr_vdevs; i++) {
			struct cl_vdev *vdev = &node->vdevs[i];
			double vdev_status = clengine_get_vdev_online_status(vdev);
			auditc_servervdev(gauge, "clengine.server",
			    &node->serverid, &vdev->vdevid, dst, vdev_status);
		}
	} else {
		/* we are gateway, send vdev 00000 */
		auditc_servervdev(gauge, "clengine.server",
		    &node->serverid, &uint128_null, dst, 1.0);
	}
}

/*
 * Update flexhash with a SINGLE node information.
 */
int
clengine_fh_update(char *srvid, struct cl_node *node)
{
	volatile struct flexhash *fh = ccow_daemon->flexhash;
	struct rebuild_ctx *rb_ctx;
	int err = 0;
	uint64_t ring_capacity;

	/* if we are trying to rebuild the flexhash */
	if (flexhash_rebuild_inprogress(fh)) {
		rb_ctx = (struct rebuild_ctx *)&fh->rebuild_ctx;
		int expected_nr_nodes = rb_ctx->expected_nr_nodes;
		if (cl_node_state_match(&node->serverid,
					CL_NODE_QUERY_ISSUED)) {
			cl_node_set_state(&node->serverid,
					  CL_NODE_QUERY_SUCCESS);
			err = flexhash_add_node(rb_ctx->fhtable, node);
			if (err < 0) {
				log_error(lg, "failed to add node %s",
						srvid);
				return err;
			}
		}
		rb_ctx->rcvd_nr_nodes = cl_node_state_count(CL_NODE_QUERY_SUCCESS);

		log_debug(lg, "Received node reply. received: %d "
			      "expected: %d", rb_ctx->rcvd_nr_nodes,
					      expected_nr_nodes);
		/* Rebalance flexhash if discovery is complete */
		if (expected_nr_nodes == rb_ctx->rcvd_nr_nodes) {
			log_debug(lg, "Reached node replies. "
				      "expected: %d received: %d",
				      expected_nr_nodes, rb_ctx->rcvd_nr_nodes);
			int skip_cp = ccow_daemon->skip_cp;
			ccowd_fhready_lock(FH_LOCK_WRITE);
			int ckp = clengine_notify_rebuild_change(fh, g_ceng->rmvdev);
			flexhash_rebuild_done(&fh, ckp, g_ceng->rmvdev, ccow_daemon->skip_cp);
			ccow_daemon->skip_cp = 0;
			ccow_daemon->flexhash = fh;
			clengine_update_fddelta(fh);
			ccowd_fhready_unlock(FH_LOCK_WRITE);

			/* Signal waiting threads */
			ccowd_set_fhrebuild_is_done();
			cl_all_nodes_set_state(CL_NODE_JOINED);

			reptrans_on_flexhash_rebuild_done(fh, 1);
			if (ccow_daemon && ccow_daemon->bg_restart) {
				ccow_daemon->bg_restart = 0;
				clengine_bgrestart_request();
			}

			flexhash_set_leader(ccow_daemon->flexhash);
			if (ckp)
				flexhash_table_dump(ccow_daemon->flexhash, "checkpoint-notify");
			else
				flexhash_table_dump(ccow_daemon->flexhash, "notify");
			/*
			 * notify all through corosync nodes to pull data
			 * from us.
			 */
			clengine_notify_others();
			clengine_set_genid(ccow_daemon->flexhash);

			/*
			 * Flexhash is now rebalanced and this is the
			 * leader, now take charge and send a notification
			 * to the AAS to update its local cached copy of
			 * system capacity for device support.
			 */
			ring_capacity = flexhash_total_capacity(fh);
			auditc_objid(gauge, "license.capacity",
				     &uint128_null, ring_capacity);

		}

	} else { /* regular discovery , don't override hashcount*/
		err = flexhash_add_server(ccow_daemon->flexhash, node,
			FH_TABLE_NOJOIN, FH_NOGOOD_HC, FH_NO_REBUILD);
		if (err)
			log_error(lg, "Cannot update flexhash for "
				      "%s err=%d", srvid, err);
	}
	clengine_notify_auditserv(node, NULL);
	return err;
}

static int
clengine_vdevs_gone(struct flexhash *fhtable, uint128_t *serverid)
{
	struct fhserver *sptr = fhtable->serverlist;
	struct fhserver *psptr=NULL;
	for(; sptr; sptr=sptr->next) {
		if (uint128_cmp(&sptr->id, serverid) == 0) {
			if (psptr == NULL) {
				fhtable->serverlist = sptr->next;
			} else {
				psptr->next = sptr->next;
			}
			return 0;
		}
		psptr=sptr;
	}
	return -ENOENT;
}
/*
 * This code is run on the leader when the rebuild is done
 * to send out notifications to other servers on what is in
 * memory flexhash vs what was in checkpoint
 * It sends out dead messages for servers and vdevs if they are
 * not found in memory
 * returns
 * 1 - if checkpoint found
 * 0 - if no checkpoint found
 *
 */

int
clengine_notify_rebuild_change(volatile struct flexhash *ofhtable, int rmvdev)
{
	volatile struct rebuild_ctx *rb_ctx = &(ofhtable->rebuild_ctx);
	int err = flexhash_checkpoint_file_stat();
	if (err != 0) {
		return 0;
	}

	if (rmvdev == 0)
		return 1;

	struct flexhash *fhtable = rb_ctx->fhtable;
	struct flexhash *ckpfhtable = flexhash_read_checkpoint(NULL, 0);
	struct fhserver *msptr = ckpfhtable->serverlist;
	struct fhserver *nsptr = fhtable->serverlist;
	for (; msptr; msptr = msptr->next) {
		char serverstr[UINT128_STR_BYTES];
		uint128_dump(&msptr->id, serverstr, UINT128_STR_BYTES);
		struct fhserver *itserver = flexhash_get_fhserver(fhtable, &msptr->id);
		if (itserver == NULL) {
			int err = clengine_vdevs_gone(ckpfhtable, &msptr->id);
			if (err != 0) {
				log_error(lg, "Server %s not found", serverstr);
			}
		}
	}
	flexhash_table_destroy(ckpfhtable);
	return 1;
}

static void
publish_evac_stats(uint128_t *devid, int src)
{
	int numrows = SERVER_FLEXHASH->numrows;
	/** @warning Limit for maximum numbers of raws in cluster */
	enum { E_MAX_DIGITS_4_ROWNUM = 5 };
	/** @warning Potential stack oveflow on large numrows */
	char row_usage[numrows * (1 + E_MAX_DIGITS_4_ROWNUM) + 2];
	unsigned row_idx = 0;

	row_usage[0] = '\0';
	for (int i = 0; i < numrows; i++) {
		if (flexhash_is_rowmember_fhrow(SERVER_FLEXHASH, devid, i)) {
			row_idx += snprintf(row_usage + row_idx, sizeof(row_usage) - row_idx,
					(row_idx == 0) ? "%u" : "_%u", i);
		}
	}
	auditc_objid_str(gauge, src ? "reptrans.evac.src_dev_rows" :
					"reptrans.evac.tgt_dev_rows",
			 devid, row_usage, 0);
}

static void
publish_evac_row_medians(uint128_t *devid)
{
	char *median_str;

	median_str = flexhash_get_row_median_json(SERVER_FLEXHASH);
	if (median_str)
		auditc_objid_str(gauge, "reptrans.flexhas.rows.mean",
			 devid, median_str, 0);
}

static void
setup_pair(uint128_t *src_id, uint128_t *target_id,
	   id_rowdata_t *src_idd, id_rowdata_t *target_idd,
	   hashtable_t *tgt_t, int same_fdomain)
{
	char vdevstr[64];

	uint128_dump(target_id, vdevstr, 64);
	int candidate_rows[SERVER_FLEXHASH->numrows];
	int count = 0;
	int j;

	memset(&candidate_rows[0], -1, sizeof(candidate_rows));

	for (j = 0; j < SERVER_FLEXHASH->numrows; j++) {
		if (src_idd->rows[j] == target_idd->rows[j])
			continue;
		if (target_idd->rows[j] != 0)
			candidate_rows[count++] = j;
	}

	// for now we pick up the first one.
	int rcount = candidate_rows[0];
	if (rcount < 0) {
		log_error(lg, "No candidate row found for target %s ", vdevstr);
		return;
	}

	// send out the message because the src will pick it up
	uint128_dump(src_id, vdevstr, 64);
	clengine_notify_rowusage_change(1, src_id, target_id, rcount, same_fdomain);
	publish_evac_stats(target_id, 0);

	target_idd->rowcount--;
	target_idd->rows[rcount] = 0;
	int err = hashtable_put(tgt_t, target_id, sizeof(uint128_t),
				target_idd, sizeof(id_rowdata_t));
	if (err < 0) {
		log_error(lg, "Unable to put vdev: %s into the hashtable", vdevstr);
		return;
	}
}

static int
is_same_fdomain(id_rowdata_t *src_idd, id_rowdata_t *tgt_idd)
{
	assert(src_idd->fdmode == tgt_idd->fdmode);
	switch (src_idd->fdmode) {
	case FD_ZONE:
		return src_idd->zone == tgt_idd->zone;
		break; /* Not reached */
	case FD_SERVER:
		return uint128_cmp(&src_idd->srvid, &tgt_idd->srvid) == 0;
		break; /* Not reached */
	case FD_ANY_FIRST:
		return 1;
		break; /* Not reached */
	default:
		return 0;
		break; /* Not reached */
	}
	return 0;
}

void
fhrebalance_notify_pair(uint128_t *src_id, id_rowdata_t *idd, hashtable_t *tgt_t)
{
	unsigned int tgt_kcount;
	uint128_t **tgt_vidl = (uint128_t **) hashtable_keys(tgt_t, &tgt_kcount);
	id_rowdata_t *found_idd;
	size_t sz;
	int lowrow = SERVER_FLEXHASH->numrows;
	char vdevstr[64];

	for (unsigned int i = 0; i < tgt_kcount; i++) {
		uint128_t *tvdevid = tgt_vidl[i];
		uint128_dump(tvdevid, vdevstr, 64);
		log_debug(lg, "Searching target vdev : %s", vdevstr);

		found_idd = (id_rowdata_t *) hashtable_get(tgt_t, tvdevid,
							   sizeof (uint128_t),
							   &sz);
		if (found_idd) {
			if (found_idd->rowcount <= lowrow) {
				log_debug(lg, "Found target vdev : %s."
						" Pairing", vdevstr);
				int same_fdomain = is_same_fdomain(idd, found_idd);
				setup_pair(src_id, tvdevid, idd,
					   found_idd, tgt_t, same_fdomain);
			}
		}
	}

}

/*
 * Here:
 *
 * src_t is greater than rowsperdev
 * tgt_t is less than rowsperdev
 */
void
fhrebalance_revac_policy(int rowsperdev, hashtable_t *src_t, hashtable_t *tgt_t)
{
	unsigned int src_kcount, tgt_kcount, count = 0;
	uint128_t **src_vidl = (uint128_t **) hashtable_keys(src_t, &src_kcount);
	uint128_t **tgt_vidl = (uint128_t **) hashtable_keys(tgt_t, &tgt_kcount);
	id_rowdata_list_t *src_list, *tgt_list;

	log_debug(lg, "Running device evacuation policy");
	for (unsigned int i = 0; i < src_kcount; i++, count++) {
		size_t sz;
		publish_evac_stats(src_vidl[i], 1);
		id_rowdata_t *idd = (id_rowdata_t *) hashtable_get(src_t, src_vidl[i],
								   sizeof (uint128_t),
								   &sz);
		if (idd)
			fhrebalance_notify_pair(src_vidl[i], idd, tgt_t);
	}

	if (src_kcount)
		publish_evac_row_medians(src_vidl[0]);

	if (tgt_kcount - count > 0 ) {
		log_warn(lg, "devices_not_processed: %d devices_less: %d "
				"rows_per_dev: %d", tgt_kcount - count,
				tgt_kcount, rowsperdev);
	}
}

int
fhrebalance_row_usage(struct flexhash *fhtable)
{
	fhtable->devsperrow = flexhash_devs_perrow(fhtable, fhtable->numdevices);
	int rowsperdev = (fhtable->devsperrow * fhtable->numrows)/fhtable->numdevices;
	if (fhtable->is_ready)
		flexhash_evac(EVAC_ROW_PARTICIPATION, fhtable,
				rowsperdev, fhrebalance_revac_policy);

	return 0;
}

#define FHREBALANCE_TIMER_TIMEOUT_MS	2000

static void
fhrebalance_timer_timeout(uv_timer_t *treq, int status)
{
	if (treq->data) {
		uv_timer_stop(treq);
		treq->data = NULL;
	}
	struct flexhash *fhtable = treq->data;
	if (!ccow_daemon->flexhash)
		return;

	struct flexhash *g_fhtable = (struct flexhash *) ccow_daemon->flexhash;
	if (!g_fhtable->leader) {
		log_notice(lg, "fhrebalance_timer_timeout: Not a leader ");
		return;
	}
	int rebuild = g_fhtable->rebuild_ctx.rebuild;
	if (rebuild == 1) {
		log_notice(lg, "fhrebalance_timer_timeout: rebuild is in progress");
		return;
	}
	struct flexhash *nfhtable =
		flexhash_read_checkpoint("flexhash-checkpoint.json", 0);
	if (!nfhtable) {
		log_error(lg, "Unable to read the flexhash checkpoint");
		return;
	}

	/* TODO: Get evac policy config and call appropriate function */
	int err = fhrebalance_row_usage(nfhtable);
	if (err) {
		log_error(lg, "fhrebalance_timer_timeout: Failed on timer "
				"based flexhash row usage balance");
		return;
	}
}

static void
fhrebalance_timer(volatile struct flexhash *fhtable)
{
	if (fhtable->rowusage_timer.data) {
		uv_timer_stop((uv_timer_t *) &fhtable->rowusage_timer);
	} else {
		uv_timer_init(ccow_daemon->loop,
				(uv_timer_t *) &fhtable->rowusage_timer);
	}
	fhtable->rowusage_timer.data = (struct flexhash *) fhtable;

	uv_timer_start((uv_timer_t *) &fhtable->rowusage_timer,
			fhrebalance_timer_timeout, FHREBALANCE_TIMER_TIMEOUT_MS, 0);
}

