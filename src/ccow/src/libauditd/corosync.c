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
#include <uv.h>

#include "ccowutil.h"
#include "auditd-impl.h"
#include "queue.h"
#include "logger.h"

void dump_cpg_node(char *prefix, struct cpg_node *cpg_node);

static cpg_handle_t cpg_handle;
#define GRP_NAME	"nexenta-stats"
static struct cpg_name cpg_group = { 13, GRP_NAME };

static corosync_cfg_handle_t cfg_handle;
static struct cpg_node this_node;

static struct clstat_handlers corosync_handlers;

/* copied from clstat.h */
#define CL_MAX_NODES 384
static struct cpg_node cpg_nodes[CL_MAX_NODES];
static size_t nr_cpg_nodes;

/* multicast message type */
enum corosync_message_type {
	COROSYNC_MSG_TYPE_JOIN_REQUEST,
	COROSYNC_MSG_TYPE_JOIN_RESPONSE,
	COROSYNC_MSG_TYPE_LEAVE,
	COROSYNC_MSG_TYPE_NOTIFY
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


static int
csync_send_msg(enum corosync_message_type type, int result,
    struct cpg_node *sender, struct cpg_node *nodes, size_t nr_nodes,
    void *msg, size_t msg_len)
{
	struct iovec iov[2];
	int ret, iov_cnt = 1;
	struct corosync_message cmsg = {
		.type = type,
		.msg_len = msg_len,
		.result = result,
		.sender = *sender,
		.nr_nodes = nr_nodes,
	};

	if (nodes)
		memcpy(cmsg.nodes, nodes, sizeof (*nodes) * nr_nodes);

	iov[0].iov_base = (void *)&cmsg;
	iov[0].iov_len = sizeof (cmsg);
	if (msg) {
		iov[1].iov_base = msg;
		iov[1].iov_len = msg_len;
		iov_cnt++;
	}
	int retry_cnt = 0;
retry:
	ret = cpg_mcast_joined(cpg_handle, CPG_TYPE_AGREED, iov, iov_cnt);
	switch (ret) {
	case CS_OK:
		break;
	case CS_ERR_TRY_AGAIN:
		if (retry_cnt++ < 10) {
			usleep(100);
			goto retry;
		}
		/* ignore error */
		log_debug(lg, "Failed to send message type %d (err=%d try again) after 10 attempts", type, ret);
		break;
	case CS_ERR_QUEUE_FULL:
		if (retry_cnt++ < 10) {
			usleep(100000);
			goto retry;
		}
		/* ignore error */
		log_warn(lg, "Failed to send message type %d (err=%d queue full) after 10 attempts", type, ret);
		break;
	default:
		log_warn(lg, "Failed to send message (%d), msg_len=%ld", ret,
		    msg_len);
		sleep(1);
		clstat_reinit();
	}
	return 0;
}


static void
ceng_cpg_deliver(cpg_handle_t handle, const struct cpg_name *group_name,
    uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
	struct corosync_message *cmsg = msg;
	int ret;
	int idx;

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
		    0, &this_node, cpg_nodes, nr_cpg_nodes, NULL, 0);
		break;
	case COROSYNC_MSG_TYPE_NOTIFY:
		log_debug(lg, "COROSYNC_MSG_TYPE_NOTIFY nodeid: %d", nodeid);
		corosync_handlers.notify_handler(&cmsg->sender,
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
				      " message from itself", nodeid);
			return;
		}
		ret = del_cpg_node(cpg_nodes, nr_cpg_nodes, &cmsg->sender);
		if (ret == 0)
			nr_cpg_nodes--;
		corosync_handlers.leave_handler(&cmsg->sender, cpg_nodes, nr_cpg_nodes);
		break;
	case COROSYNC_MSG_TYPE_JOIN_RESPONSE:
		log_debug(lg, "COROSYNC_MSG_TYPE_JOIN_RESPONSE nodeid: %d ", nodeid);

		idx = find_cpg_node(cpg_nodes, nr_cpg_nodes, &cmsg->sender);
		if (idx < 0 ) {
			add_cpg_node(cpg_nodes, nr_cpg_nodes, &cmsg->sender);
			nr_cpg_nodes++;
		} else {
			update_cpg_node(cpg_nodes, nr_cpg_nodes,
			    idx, &cmsg->sender);
		}
		corosync_handlers.join_handler(&cmsg->sender, cpg_nodes,
		    nr_cpg_nodes, 0, cmsg->msg, cmsg->msg_len);

		break;
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

	}
}

static int corosync_init(struct clstat_handlers *handlers)
{
	int ret, fd;
	uint32_t nodeid;
	cpg_callbacks_t cb = {
		.cpg_deliver_fn = ceng_cpg_deliver,
		.cpg_confchg_fn = ceng_cpg_confchg
	};

	log_trace(lg, "handlers: %p", handlers);

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
		log_error(lg, "Failed to get node id (%d)", ret);
		return -1;
	}

	this_node.nodeid = nodeid;
	this_node.pid = getpid();

	ret = cpg_fd_get(cpg_handle, &fd);
	if (ret != CS_OK) {
		log_error(lg, "Failed to get cpg file descriptor (%d)", ret);
		return -1;
	}

	return fd;
}

int clstat_cleanup(void)
{
	int ret, err = 0;

	ret = corosync_cfg_finalize(cfg_handle);
	if (ret != CS_OK) {
		log_warn(lg, "Failed to finalize corosync cfg (%d)", ret);
		err = -ret;
	}

	ret = cpg_finalize(cpg_handle);
	if (ret != CS_OK) {
		log_warn(lg, "Failed to finalize cpg (%d)", ret);
		err = -ret;
	}

	return err;
}


static int corosync_join(
    int (*check_join_cb)(struct cpg_node *joining, void *opaque, int opaque_len),
    void *opaque, size_t opaque_len)
{
	int ret;
retry:
	ret = cpg_join(cpg_handle, &cpg_group);
	switch (ret) {
	case CS_OK:
		break;
	case CS_ERR_TRY_AGAIN:
		log_debug(lg, "Failed to join the " GRP_NAME " group: retrying");
		usleep(100000);
		goto retry;
	case CS_ERR_SECURITY:
		log_error(lg, "Permission denied to join the " GRP_NAME " group"
		    "CS_ERR_SECURITY");
		return -1;
	default:
		log_error(lg, "Failed to join the " GRP_NAME " group (%d)", ret);
		return -1;
	}

	return 0;
}

static int corosync_leave(void)
{
	return csync_send_msg(COROSYNC_MSG_TYPE_LEAVE, 0, &this_node, NULL, 0,
			    NULL, 0);
}

static int corosync_notify(void *msg, size_t msg_len, void (*block_cb)(void *))
{
	int ret;
	log_trace(lg, "msg: %p msg_len: %ld", msg, msg_len);
	ret = csync_send_msg(COROSYNC_MSG_TYPE_NOTIFY, 0, &this_node,
		    NULL, 0, msg, msg_len);
	return ret;
}

static int corosync_dispatch(void)
{
	int ret;
	ret = cpg_dispatch(cpg_handle, CS_DISPATCH_ALL);
	if (ret != CS_OK)
		return -1;
	return ret;
}

struct clstat_engine ceng_corosync = {
	.name	    = "corosync",

	.init	    = corosync_init,
	.join	    = corosync_join,
	.leave	    = corosync_leave,
	.notify	    = corosync_notify,
	.dispatch   = corosync_dispatch
};

clstat_register(ceng_corosync);
