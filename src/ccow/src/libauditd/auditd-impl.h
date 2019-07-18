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
#ifndef __AUDITD_IMPL_H__
#define __AUDITD_IMPL_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "queue.h"

#define AUDITD_CONF_DIR		"%s/etc/ccow"
#define AUDITD_CONF_FILE	"auditd.ini"
#define AUDITD_RLIMIT_NOFILE	65536

struct cpg_node {
	uint32_t nodeid;
	uint32_t pid;
};

struct clstat_handlers {
	void (*join_handler)(struct cpg_node *joined, struct cpg_node *members,
	    size_t nr_members, int result, void *opaque, int msg_len);
	void (*leave_handler)(struct cpg_node *left, struct cpg_node *members,
	    size_t nr_members);
	void (*notify_handler)(struct cpg_node *sender, void *msg,
	    size_t msg_len);
	void (*update_handler)(struct cpg_node *sender, void *msg,
	    size_t msg_len);
};

struct clstat_engine {
	QUEUE item;

	int group_fd;
	uv_poll_t group_poll_fd;
	uv_timer_t fhtimer_req;
	uv_timer_t clust_health_req;

	size_t nr_nodes;

	const char *name;

	uint64_t last_discovery;

	/*
	 * Initialize the cluster engine
	 *
	 * On success, this function returns the file descriptor that
	 * may be used with the poll(2) to monitor cluster events.  On
	 * error, returns -1.
	 */
	int (*init)(struct clstat_handlers *handlers);

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
	int (*join)(int (*check_join_cb)(struct cpg_node *joining,
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
	 * clstat_handlers.  If 'block_cb' is specified, block_cb() is
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
};

extern int clstat_reinit();
extern int clstat_notify(void *msg, size_t msg_len);
extern int clstat_dump(void);
extern int clstat_cleanup(void);
extern QUEUE clstat_engines;

#define clstat_register(eng) \
static void __attribute__((constructor)) regist_ ## eng(void) {	\
	if (!eng.init || !eng.join || !eng.leave || \
	    !eng.notify || !eng.dispatch) \
		panic("the eng '%s' is incomplete\n", eng.name); \
	QUEUE_INIT(&eng.item); \
	QUEUE_INSERT_TAIL(&clstat_engines, &eng.item);	\
}

#ifdef	__cplusplus
}
#endif

#endif
