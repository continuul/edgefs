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
#include <unistd.h>
#include <sys/socket.h>
#include <corosync/cpg.h>
#include <corosync/cfg.h>
#include <corosync/quorum.h>
#include <uv.h>

#include "ccowutil.h"
#include "ccowd-impl.h"
#include "clengine.h"
#include "queue.h"
#include "logger.h"

#define MAX_CS_QUEUE_FULL 120
#define MAX_CS_ERR_RETRY_SEND 120
#define MAX_CS_ERR_RETRY_JOIN 60

struct cpg_node {
	uint32_t nodeid;
	uint32_t pid;
	uint32_t gone;
	struct cl_node ent;
};

void dump_cpg_node(char *prefix, struct cpg_node *cpg_node);

static cpg_handle_t cpg_handle;
#define GRP_NAME	"nexenta-ccow"
static struct cpg_name cpg_group = { 12, GRP_NAME };
int corosync_initialized=0;
extern volatile int ccowd_terminating;

static struct cpg_node this_node;

static struct clengine_handlers corosync_handlers;
static int (*corosync_check_join_cb)(struct cl_node *joining, void *opaque,
    int opaque_len);

static struct cpg_node cpg_nodes[CL_MAX_NODES];
static size_t nr_cpg_nodes;

/* multicast message type */
enum corosync_message_type {
	COROSYNC_MSG_TYPE_JOIN_REQUEST,
	COROSYNC_MSG_TYPE_JOIN_RESPONSE,
	COROSYNC_MSG_TYPE_LEAVE,
	COROSYNC_MSG_TYPE_NOTIFY,
	COROSYNC_MSG_TYPE_BLOCK,
	COROSYNC_MSG_TYPE_UNBLOCK,
	COROSYNC_MSG_TYPE_STAT_UPDATE, /* kept for backward compat */
	COROSYNC_MSG_TYPE_FLEXHASH
};

struct corosync_message {
	struct cpg_node sender;
	enum corosync_message_type type : 4;
	int result : 4;
	uint32_t msg_len;
	uint32_t nr_nodes;
	struct cpg_node nodes[CL_MAX_NODES];
	uint8_t msg[0];
};

void
show_node(struct cl_node *node)
{
	char idstr[64];
	char dst[INET6_ADDRSTRLEN];
	uint128_dump(&node->serverid, idstr, 64);
	inet_ntop(AF_INET6, &node->addr, dst, INET6_ADDRSTRLEN);
	log_debug(lg, "node: <%s> ip: <%s>", idstr, dst);
}


static int
cpg_node_equal(struct cpg_node *a, struct cpg_node *b)
{
	return (a->nodeid == b->nodeid && a->pid == b->pid);
}

static inline int
find_cpg_node(struct cpg_node *nodes, size_t nr_nodes, struct cpg_node *key)
{
	size_t i;

	for (i = 0; i < nr_nodes; i++) {
		struct cpg_node *nodeptr = &nodes[i];
		if (cpg_node_equal(nodeptr, key)) {
			return i;
		}
	}
	return -1;
}

static inline void
add_cpg_node(struct cpg_node *nodes, size_t nr_nodes, struct cpg_node *added)
{
	nodes[nr_nodes++] = *added;
}

static inline int
del_cpg_node(struct cpg_node *nodes, size_t nr_nodes,
				struct cpg_node *deled)
{
	int idx;

	idx = find_cpg_node(nodes, nr_nodes, deled);
	if (idx < 0) {
		log_warn(lg, "Cannot find node . nodeid: %d", deled->nodeid);
		return -1;
	}

	nr_nodes--;
	memmove(nodes + idx, nodes + idx + 1,
	    sizeof (*nodes) * (nr_nodes - idx));

	return 0;
}

static inline void
update_cpg_node(struct cpg_node *nodes, size_t nr_nodes,
    int idx, struct cpg_node *upn)
{
	nodes[idx] = *upn;
}

static void
build_node_list(struct cpg_node *nodes, size_t nr_nodes,
			    struct cl_node *entries)
{
	size_t i;

	for (i = 0; i < nr_nodes; i++)
		entries[i] = nodes[i].ent;
}


static int
csync_send_msg(enum corosync_message_type type, int result,
    struct cpg_node *sender, struct cpg_node *nodes, size_t nr_nodes,
    void *msg, size_t msg_len)
{
	struct iovec iov[2];
	int ret, iov_cnt = 1;
	int retry_count=0;
	struct corosync_message cmsg = {
		.type = type,
		.msg_len = msg_len,
		.result = result,
		.sender = *sender,
		.nr_nodes = nr_nodes,
	};

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	if (nodes)
		memcpy(cmsg.nodes, nodes, sizeof (*nodes) * nr_nodes);

	iov[0].iov_base = (void *)&cmsg;
	iov[0].iov_len = sizeof (cmsg);
	if (msg) {
		iov[1].iov_base = msg;
		iov[1].iov_len = msg_len;
		iov_cnt++;
	}
retry:
	retry_count++;
	ret = cpg_mcast_joined(cpg_handle, CPG_TYPE_AGREED, iov, iov_cnt);
	switch (ret) {
	case CS_OK:
		break;
	case CS_ERR_TRY_AGAIN:
		if (retry_count < MAX_CS_ERR_RETRY_SEND && !ccowd_terminating) {
			usleep(10000);
			log_debug(lg, "Failed to send message (%d), msg_len=%ld: retrying %d on try again",
			    ret, msg_len, retry_count);
			goto retry;
		}
		break;
	case CS_ERR_QUEUE_FULL:
		if (retry_count < MAX_CS_QUEUE_FULL && !ccowd_terminating) {
			usleep(10000);
			log_debug(lg, "Failed to send message (%d), msg_len=%ld: retrying %d on queue full",
			    ret, msg_len, retry_count);
			goto retry;
		}
		log_error(lg, "Failed to send message (%d), msg_len=%ld: queue full",
		    ret, msg_len);
		break;
	default:
		if (retry_count < MAX_CS_QUEUE_FULL && !ccowd_terminating) {
			usleep(10000);
			goto retry;
		}
		log_error(lg, "Failed to send message (%d), msg_len=%ld: unknown networking error (%s)",
		    ret, msg_len, cs_strerror(ret));
	}
	return ret;
}


static void
ceng_cpg_deliver(cpg_handle_t handle, const struct cpg_name *group_name,
    uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
	struct cl_node entries[CL_MAX_NODES];
	struct corosync_message *cmsg = msg;
	int ret;
	int idx;

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	log_debug(lg, "CPG deliver type: %d group_name: %s"
	    " nodeid: %d pid: %d ", cmsg->type, group_name->value, nodeid, pid);

	switch (cmsg->type) {
	case COROSYNC_MSG_TYPE_JOIN_REQUEST:
		log_debug(lg, "COROSYNC_MSG_TYPE_JOIN_REQUEST nodeid: %d", nodeid);
		idx = find_cpg_node(cpg_nodes, nr_cpg_nodes, &cmsg->sender);
		if (idx < 0) {
			add_cpg_node(cpg_nodes, nr_cpg_nodes, &cmsg->sender);
			nr_cpg_nodes++;
		} else {
			update_cpg_node(cpg_nodes, nr_cpg_nodes, idx, &cmsg->sender);
		}
		int ret = csync_send_msg(COROSYNC_MSG_TYPE_JOIN_RESPONSE,
		    0, &this_node, cpg_nodes, nr_cpg_nodes, this_node.ent.vdevs,
		    this_node.ent.nr_vdevs * sizeof (struct cl_vdev));
		if (ret != CS_OK) {
			log_error(lg, "Unable to send JOIN_RESPONSE err: %d" \
			    " message: %s", ret, cs_strerror(ret));
		}
		break;
	case COROSYNC_MSG_TYPE_NOTIFY:
		log_debug(lg, "COROSYNC_MSG_TYPE_NOTIFY nodeid: %d", nodeid);
		corosync_handlers.notify_handler(&cmsg->sender.ent,
		    cmsg->msg, cmsg->msg_len);
		break;
	case COROSYNC_MSG_TYPE_FLEXHASH:
		log_debug(lg, "COROSYNC_MSG_TYPE_FLEXHASH nodeid: %d", nodeid);
		corosync_handlers.flexhash_handler(&cmsg->sender.ent,
		    cmsg->msg, cmsg->msg_len);
		break;
	case COROSYNC_MSG_TYPE_LEAVE:
		log_debug(lg, "COROSYNC_MSG_TYPE_LEAVE nodeid: %d", nodeid);
		/*
		 * Don't delete this_node from cpg node list.
		 * Otherwise this_node will foget itself - creating problems
		 * when this_node happens to be a leader.
		 */
		if (cmsg->sender.nodeid == this_node.nodeid) {
			log_notice(lg, "Corosync node: %d ignoring leave"
				      " message from itself", cmsg->sender.nodeid);
			return;
		}
		ret = del_cpg_node(cpg_nodes, nr_cpg_nodes, &cmsg->sender);
		if (ret == 0)
			nr_cpg_nodes--;
		build_node_list(cpg_nodes, nr_cpg_nodes, entries);
		corosync_handlers.leave_handler(&cmsg->sender.ent,
		    entries, nr_cpg_nodes);
		break;
	case COROSYNC_MSG_TYPE_JOIN_RESPONSE:
		log_debug(lg, "COROSYNC_MSG_TYPE_JOIN_RESPONSE nodeid: %d ", nodeid);
		struct cl_node *nodeptr = &cmsg->sender.ent;
		show_node(nodeptr);

		idx = find_cpg_node(cpg_nodes, nr_cpg_nodes, &cmsg->sender);
		if (idx < 0 ) {
			add_cpg_node(cpg_nodes, nr_cpg_nodes, &cmsg->sender);
			nr_cpg_nodes++;
		} else {
			update_cpg_node(cpg_nodes, nr_cpg_nodes,
			    idx, &cmsg->sender);
		}
		build_node_list(cpg_nodes, nr_cpg_nodes, entries);
		corosync_handlers.join_handler(&cmsg->sender.ent, entries,
		    nr_cpg_nodes, 0, cmsg->msg, cmsg->msg_len);

		break;
	case COROSYNC_MSG_TYPE_UNBLOCK:
		/* FIXME: create a callback that updates the states in 
		 * g_ceng->nodes to indicate that this is unblocked
		 */
		log_warn(lg, "Unsupported COROSYNC_MSG_TYPE_UNBLOCK");
		break;
	case COROSYNC_MSG_TYPE_BLOCK:
		/* FIXME: create a callback that updates the states in 
		 * g_ceng->nodes to indicate that this node is blocked
		 */
		log_warn(lg, "Unsupported COROSYNC_MSG_TYPE_BLOCK");
		/* fall through */
	default:
		break;
	}
}

static void
ceng_cpg_confchg(cpg_handle_t handle, const struct cpg_name *group_name,
    const struct cpg_address *member_list, size_t member_list_entries,
    const struct cpg_address *left_list, size_t left_list_entries,
    const struct cpg_address *joined_list, size_t joined_list_entries)
{
	size_t i;
	struct cpg_node joined_nodes[CL_MAX_NODES];
	struct cpg_node left_nodes[CL_MAX_NODES];
	struct cl_node entries[CL_MAX_NODES];

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	log_debug(lg, "CPG config: mem:%zu, joined:%zu, left:%zu",
		member_list_entries, joined_list_entries,
		left_list_entries);

	/* convert cpg_address to cpg_node */
	for (i = 0; i < left_list_entries; i++) {
		left_nodes[i].nodeid = left_list[i].nodeid;
		left_nodes[i].pid = left_list[i].pid;
		log_debug(lg, "left nodeid: %d pid: %d", left_nodes[i].nodeid,
					left_nodes[i].pid);

	}
	for (i = 0; i < joined_list_entries; i++) {
		joined_nodes[i].nodeid = joined_list[i].nodeid;
		joined_nodes[i].pid = joined_list[i].pid;
		log_debug(lg, "joined nodeid: %d pid: %d", joined_nodes[i].nodeid,
		    joined_nodes[i].pid);
		/* we do not do a if check if we have joined before because turns
		 * out we can miss joins in certain multi-node cases. Hence
		 * we send out the join request unconditionally. Sure we may generate
		 * a lot more join message traffic, but the messages are not misssed
		 * and the topology is established reliably
		 */
		int ret = csync_send_msg(COROSYNC_MSG_TYPE_JOIN_REQUEST, 0,
		    &this_node, NULL, 0, NULL, 0);
		if (ret != CS_OK) {
			log_error(lg, "Unable to send JOIN_REQUEST err: %d"
			    " message: %s", ret, cs_strerror(ret));
		}
	}

	/* dispatch leave_handler */
	for (i = 0; i < left_list_entries; i++) {
		struct cpg_node sender = left_nodes[i];
		int idx = find_cpg_node(cpg_nodes, nr_cpg_nodes, &sender);
		if (idx < 0) {
			log_warn(lg, "nodeid: %d not found", sender.nodeid);
			continue;
		}
		sender = cpg_nodes[idx];
		int ret = csync_send_msg(COROSYNC_MSG_TYPE_LEAVE, 0, &sender, NULL, 0,
		    NULL, 0);
		if (ret != CS_OK) {
			log_error(lg, "Unable to send the LEAVE message"
			    " err: %d message: %s", ret, cs_strerror(ret));
		}
	}
}

static int
corosync_init(struct clengine_handlers *handlers, const char *option)
{
	int ret, fd;
	uint32_t nodeid;
	corosync_cfg_handle_t cfg_handle;
	cpg_callbacks_t cb = {
		.cpg_deliver_fn = ceng_cpg_deliver,
		.cpg_confchg_fn = ceng_cpg_confchg
	};

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	log_trace(lg, "handlers: %p, option: %p", handlers, option);

	corosync_handlers = *handlers;

	ret = cpg_initialize(&cpg_handle, &cb);
	if (ret != CS_OK) {
		log_error(lg,
		    "Failed to initialize cpg (%d) - is corosync running?",
		    ret);
		return -1;
	}

	ret = corosync_cfg_initialize(&cfg_handle, NULL);
	if (ret != CS_OK) {
		log_error(lg, "Failed to initialize cfg (%d)", ret);
		return -1;
	}

	ret = corosync_cfg_local_get(cfg_handle, &nodeid);
	if (ret != CS_OK) {
		log_error(lg, "Failed to get node id (%d) message: %s",\
		    ret, cs_strerror(ret));
		return -1;
	}

	corosync_cfg_finalize(cfg_handle);

	this_node.nodeid = nodeid;
	this_node.pid = getpid();

	ret = cpg_fd_get(cpg_handle, &fd);
	if (ret != CS_OK) {
		log_error(lg, "Failed to get cpg file descriptor (%d) message: %s",\
		    ret, cs_strerror(ret));
		return -1;
	}
	corosync_initialized = 1;
	return fd;
}

int corosync_cleanup(void)
{
	int ret;

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	if ((this_node.ent.vdevs) && (this_node.ent.nr_vdevs > 0))
		je_free(this_node.ent.vdevs);

	ret = cpg_finalize(cpg_handle);
	if (ret != CS_OK) {
		log_error(lg, "Failed to finalize cpg (%d) message: %s", ret, cs_strerror(ret));
		return -1;
	}
	corosync_initialized = 0;

	return 0;
}

int
corosync_shutdown()
{
	cs_error_t ret;
	corosync_cfg_handle_t cfg_handle;
	corosync_cfg_callbacks_t callbacks;

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	callbacks.corosync_cfg_shutdown_callback = NULL;

	ret = corosync_cfg_initialize (&cfg_handle, &callbacks);
	if (ret != CS_OK) {
		log_error (lg, "Could not initialize corosync configuration "
		    "API error %d message: %s", ret, cs_strerror(ret));
		return -1;
	}
	log_notice(lg, "Shutting down corosync\n");
	ret = corosync_cfg_try_shutdown (cfg_handle, COROSYNC_CFG_SHUTDOWN_FLAG_REQUEST);
	if (ret != CS_OK) {
		log_error(lg, "Could not shutdown (error = %d) message: %s",
		    ret, cs_strerror(ret));
		return -1;
	}
	(void) corosync_cfg_finalize (cfg_handle);

	return 0;
}


void
corosync_ring_reinit(int *fd_out)
{
	cs_error_t ret;

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	*fd_out = -1;

	ret = cpg_finalize(cpg_handle);
	if (ret != CS_OK) {
		log_warn(lg, "Failed to finalize cpg (%d)", ret);
	}

	cpg_callbacks_t cb = {
		.cpg_deliver_fn = ceng_cpg_deliver,
		.cpg_confchg_fn = ceng_cpg_confchg
	};

	ret = cpg_initialize(&cpg_handle, &cb);
	if (ret != CS_OK) {
		log_error(lg,
		    "Failed to initialize cpg (%d) - is corosync running?",
		    ret);
		return;
	}

	while (!ccowd_terminating &&
	    (ret = cpg_join(cpg_handle, &cpg_group)) == CS_ERR_TRY_AGAIN) {
		log_warn(lg, "reinit cpg_join returned %d, retrying", ret);
		usleep(100000);
	}

	ret = cpg_fd_get(cpg_handle, fd_out);
	if (ret != CS_OK) {
		log_error(lg, "Failed to get cpg file descriptor (%d)", ret);
	} else
		log_info(lg, "Corosync re-init success, new fd=%d", *fd_out);
}



static int
corosync_join(struct cl_node *myself,
    int (*check_join_cb)(struct cl_node *joining, void *opaque, int opaque_len),
    void *opaque, size_t opaque_len)
{
	int ret;
	int retry_count=0;
	log_trace(lg, "myself: %p opaque: %p opaque_len: %ld",
	    myself, opaque, opaque_len);

	assert(ccow_daemon->loop_thrid == uv_thread_self());

retry:
	retry_count++;
	ret = cpg_join(cpg_handle, &cpg_group);
	switch (ret) {
	case CS_OK:
		break;
	case CS_ERR_TRY_AGAIN:
		if (retry_count < MAX_CS_ERR_RETRY_JOIN) {
			log_warn(lg, "Failed to send message (%d): retrying %d on try again",
			    ret, retry_count);
			usleep(100000);
			goto retry;
		}
		break;
	case CS_ERR_SECURITY:
		log_error(lg, "Permission denied to join the " GRP_NAME " group"
		    "CS_ERR_SECURITY");
		return -1;
	default:
		log_error(lg, "Failed to join the " GRP_NAME " group (%d)", ret);
		return -1;
	}

	this_node.ent = *myself;
	this_node.ent.nr_vdevs = 0;
	this_node.ent.vdevs = NULL;
	if ((opaque) && ( opaque_len > 0)) {
		this_node.ent.nr_vdevs = (opaque_len/sizeof (struct cl_vdev));
		this_node.ent.vdevs = je_calloc(this_node.ent.nr_vdevs,
		    sizeof (struct cl_vdev));
		if (!this_node.ent.vdevs) {
			log_error(lg, "Unable to allocate memory for vdevs");
			return -ENOMEM;
		}
		memcpy(this_node.ent.vdevs, opaque, opaque_len);
	}

	if (retry_count >= MAX_CS_ERR_RETRY_JOIN) {
		(void) csync_send_msg(COROSYNC_MSG_TYPE_JOIN_REQUEST, 0,
		    &this_node, NULL, 0, opaque, opaque_len);
	}

	return 0;
}

static int
corosync_leave(void)
{
	int ret;

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	ret = csync_send_msg(COROSYNC_MSG_TYPE_LEAVE, 0, &this_node, NULL, 0,
			    NULL, 0);
	if (ret == CS_OK)
		return 0;
	log_error(lg, "Unable to send the LEAVE message err: %d", ret);
	return -1;
}
#define SEND_MSG_RETRY 12
static int
corosync_notify(void *msg, size_t msg_len, void (*block_cb)(void *))
{
	int err = 0;
	log_trace(lg, "msg: %p msg_len: %ld", msg, msg_len);

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	int retry = 0;
	int ret;
	while ((ret = csync_send_msg(COROSYNC_MSG_TYPE_NOTIFY, 0, &this_node,\
			    NULL, 0, msg, msg_len)) != CS_OK) {
		if (ccowd_terminating)
			break;
		if (retry++ > SEND_MSG_RETRY) {
			log_error(lg, "Unable to send the notify message len: %ld"
			    "err: %d message: %s", msg_len, ret, cs_strerror(ret));
			err = -1;
			break;
		}
		usleep(100000);
	}
	return err;
}

static int
corosync_flexhash_update(void *fhbuf, size_t fhbuf_len)
{
	int err = 0;
	log_trace(lg, "flexhash update: %p buf_len: %ld ", fhbuf, fhbuf_len);

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	int retry = 0;
	int ret;
	while ((ret = csync_send_msg(COROSYNC_MSG_TYPE_FLEXHASH, 0, &this_node,\
			    NULL, 0, fhbuf, fhbuf_len)) != CS_OK) {
		if (ccowd_terminating)
			break;
		if (retry++ > 3) {
			log_error(lg, "Unable to send flexhash update err: %d message: %s",
			    ret, cs_strerror(ret));
			err = -1;
			break;
		}
		usleep(100000);
	}
	return err;
}

static int
corosync_dispatch(void)
{
	int ret;

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	ret = cpg_dispatch(cpg_handle, CS_DISPATCH_ALL);
	if (ret != CS_OK)
		return -1;
	return ret;
}

int corosync_hostlist(void)
{
	cs_error_t ret;
	int membercount=0;
	struct cpg_name name;
	struct cpg_address nodes[CL_MAX_NODES];

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	strcpy(name.value, GRP_NAME);
	name.length = strlen(name.value);

	ret = cpg_membership_get(cpg_handle, &name, &nodes[0], &membercount);
	if (ret == CS_OK) {
		return membercount;
	}
	log_error(lg, "Unable to get the member list err: %d message: %s",
	    ret, cs_strerror(ret));
	return -1;
}

static uint32_t g_quorate;
static uint64_t g_ring_id;
static uint32_t g_called;

static void quorum_notification_fn(
	quorum_handle_t handle,
	uint32_t quorate,
	uint64_t ring_id,
	uint32_t view_list_entries,
	uint32_t *view_list)
{
	g_called = 1;
	g_quorate = quorate;
	g_ring_id = ring_id;
}


int
corosync_ringid_value(uint64_t *ringid)
{
	quorum_handle_t q_handle;
	quorum_callbacks_t callbacks;
	int is_quorate;
	int err;
	uint32_t qtype;

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	callbacks.quorum_notify_fn = quorum_notification_fn;
	err=quorum_initialize(&q_handle, &callbacks, &qtype);
	if (err != CS_OK) {
		log_error(lg, "Cannot connect to quorum service, is it loaded? "
		    " err: %d message: %s", err, cs_strerror(err));
		return -1;
	}

	err=quorum_getquorate(q_handle, &is_quorate);
	if (err != CS_OK) {
		log_error(lg, "quorum_getquorate FAILED: err: %d message: %s",
		    err, cs_strerror(err));
		return -1;
	}

	err=quorum_trackstart(q_handle, CS_TRACK_CURRENT);
	if (err != CS_OK) {
		log_error(lg, "quorum_trackstart FAILED: err: %d message: %s",
		    err, cs_strerror(err));
		return -1;
	}

	g_called = 0;
	while (g_called == 0)
		quorum_dispatch(q_handle, CS_DISPATCH_ONE);

	quorum_finalize(q_handle);

	*ringid = g_ring_id;
	return 0;

}

int corosync_ring_status()
{
	cs_error_t ret;
	unsigned int interface_count;
	char **interface_names;
	char **interface_status;
	unsigned int i;
	unsigned int nodeid;
	corosync_cfg_handle_t cfg_handle;

	assert(ccow_daemon->loop_thrid == uv_thread_self());

	if (!corosync_initialized) {
		log_error(lg, "Waiting for corosync to initialize");
		return -1;
	}

	ret = corosync_cfg_initialize(&cfg_handle, NULL);
	if (ret != CS_OK) {
		log_error(lg, "Failed to initialize cfg err: %d message: %s",
		    ret, cs_strerror(ret));
		return -1;
	}

	ret = corosync_cfg_local_get(cfg_handle, &nodeid);
	if (ret != CS_OK) {
		log_error(lg, "Unable to get the nodeid. err: %d message: %s",
		    ret, cs_strerror(ret));
		return -1;
	}

	ret = corosync_cfg_ring_status_get (cfg_handle,
			&interface_names,
			&interface_status,
			&interface_count);
	if (ret != CS_OK) {
		log_error(lg, "Unable to get the ring status. err: %d message: %s",
		    ret, cs_strerror(ret));
		return -1;
	}

	corosync_cfg_finalize(cfg_handle);

	for (i =0; i < interface_count; i++) {
		/*
		   log_error(lg, " if ring: %d tid: %s status: %s\n",
			i, interface_names[i], interface_status[i]);
		 */
		free(interface_names[i]);
		free(interface_status[i]);
	}
	free(interface_names);
	free(interface_status);

	return 0;
}

struct cluster_engine ceng_corosync = {
	.name	    = "corosync",

	.init	    = corosync_init,
	.join	    = corosync_join,
	.leave	    = corosync_leave,
	.notify	    = corosync_notify,
	.dispatch   = corosync_dispatch,
	.flexhash_update = corosync_flexhash_update,
};

clengine_register(ceng_corosync);
