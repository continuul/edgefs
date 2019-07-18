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
#include <string.h>
#include <stdlib.h>

#include "ccowutil.h"
#include "reptrans.h"
#include "serverid.h"
#include "flexhash.h"
#include "clengine.h"
#include "crypto.h"

#include <corosync/cpg.h>

Logger lg;
static char logfile[128];
FILE *logfp;

uv_loop_t *g_loop;
static int g_running;

#define cerror(fmt, args...) \
do { \
	unsigned long pid = getpid(); \
	struct timeval tp; \
	gettimeofday(&tp, 0); \
	int ms = tp.tv_usec / 1000; \
	time_t meow = time(NULL); \
	struct tm tm; \
	char _dbuf[64]; \
	strftime(_dbuf, 64, "%Y-%m-%d %H:%M:%S", localtime_r(&meow, &tm)); \
	char _buf[512]; \
	snprintf(_buf, 512, "[%lu] %s.%03d:%s:%d: "fmt, \
		pid, _dbuf, ms, __FUNCTION__, __LINE__, ##args); \
	fprintf(logfp, "%s\n", _buf); \
} while(0)

#define cprint(fmt, args...) \
	cerror(fmt, ##args)

#define cprintf(fmt, args...) \
	fprintf(logfp, fmt, ##args)

#define cprint128(s, id) \
do { \
	char out[64]; \
	uint128_dump(id, out, 64); \
	fprintf(logfp, "%s:%d: %s %s\n", __FUNCTION__, __LINE__, s, out); \
} while (0)

#define MAX_SERVERS     100

#define CORO_INIT	1
#define CORO_JOINED	2
#define CORO_SUSPEND	6
#define CORO_LEAVING	7

#define PUBLISH_TIMER_MS	500
#define REBUILD_TIMER_MS	1000
#define FX_TIMER_MS		5000

struct coroclass
{
	cpg_handle_t handle;
	uint32_t nodeid;
	uint32_t pid;
	uint128_t serverid;
	int cpg_fd;
	uv_poll_t poll_fd;
	struct cpg_name corogroup;
	cpg_callbacks_t cb;
	int numdevices;
	int servercount;
	uint32_t nodeid_list[MAX_SERVERS];
	uint32_t pid_list[MAX_SERVERS];
	uint128_t serverid_list[MAX_SERVERS];
	int state;
	uv_timer_t publish_timer;
	uv_timer_t rebuild_timer;
	uv_timer_t fx_timer;
	int leader;
} coroclass;

struct flexclass
{
	uint128_t selfid;
	struct cl_node selfnode;
	volatile struct flexhash *flexhash;
	uv_async_t hdl;
} flexclass;

#define IO_TIMER_MS 100

struct ioclass
{
	uv_work_t io_work;
	uv_timer_t io_timer;
} ioclass;

#define CMSG_NODE_ONE		1
#define CMSG_NODE_ALL		2
#define CMSG_NODE_PUBLISH	3

struct coromsg {
	uint32_t nodeid;
	uint32_t pid;
	int type;
	uint128_t serverid;
	uint32_t nr_nodes;
};

static void
io_timer_exec(uv_timer_t *req, int status)
{
	// Randomly select three devices in any row
	// and mark them active
	struct flexclass *fx = req->data;
	struct dlist *rowdl;
	struct fhdev *fhdev;
	struct lvdev *lvdev;
	int numrows, row, i, index;

	if (flexhash_is_stale(fx->flexhash))
		return;

	numrows = flexhash_numrows(fx->flexhash);
	row = random() % numrows;
	rowdl = &fx->flexhash->dl[row];

	for (i = 0; i < 3; i++) {
		index = random() % rowdl->numdevs;
		fhdev = rowdl->devlist;
		while (index--) {
			fhdev = fhdev->next;
		}
		lvdev = fhdev->vdev;
		lvdev->activerows++;
	}
}

static void
io_terminate(struct ioclass *io)
{
	cprint("Terminating IO");
	uv_close((uv_handle_t *)&io->io_timer, NULL);
}

static void
io_stop(struct ioclass *io)
{
	cprint("Stopping IO");
	uv_timer_stop(&io->io_timer);
}

static void
io_start(struct ioclass *io)
{
	cprint("Starting IO");
	uv_timer_start(&io->io_timer, io_timer_exec, IO_TIMER_MS, IO_TIMER_MS);
}

static void
io_init(struct ioclass *io, struct flexclass *fx)
{
	cprint("Initializing IO");
	uv_timer_init(g_loop, &io->io_timer);
	io->io_timer.data = fx;
}

//=============================================================================

static int
row_servercount(struct dlist *dl)
{
	uint128_t serverid[MAX_SERVERS];
	int count = 0, found;
	struct fhdev *head;
	struct fhserver *fhserver;

	memset(serverid, 0, MAX_SERVERS * sizeof(uint128_t));
	head = dl->devlist;
	while (head != NULL) {
		struct lvdev *lvdev = head->vdev;
		uint128_t *id = &lvdev->server->id;

		found = 0;
		for (int j = 0; j < count; j++)
			if (uint128_cmp(&serverid[j], id) == 0)
				found = 1;
		if (!found)
			serverid[count++] = *id;

		head = head->next;
	}

	return count;
}

static void
fxdump(struct flexclass *fx)
{
	volatile struct flexhash *fhtable = fx->flexhash;
	int numdev = fhtable->vdevstore->lvdevcount;
	int numrows = fhtable->numrows;

	struct dlist *dl;
	struct fhdev *head;

	cprintf("Flexhash genid %lu\n", fx->flexhash->genid);
	cprintf("FlexHash Table numrows = %d {\n", numrows);
	for (int i = 0; i < numrows; i++) {
		dl = &fhtable->dl[i];
		cprintf("%d : row: ", i);
		head = dl->devlist;
		while (head != NULL) {
			struct lvdev *lvdev = head->vdev;
			cprintf("%d ", lvdev->idx);
			head = head->next;
		}
		cprintf("\n");
		cprintf(" #devs: %d #servers: %d\n", dl->numdevs, row_servercount(dl));
	}
	cprintf("} FlexHash Table numrows = %d\n", fhtable->numrows);
}

static int
flexhash_rebuild(struct flexclass *fx)
{
	struct cl_node *nodes;
	int nr_nodes, numdevices, i;
	int err = flexhash_get_nodes(fx->flexhash, &nodes, &nr_nodes, FH_GOOD_HC);
	if (err) {
		cerror("Failed to get nodes from flexhash");
		return -1;
	}

	numdevices = 0;
	for (i = 0; i < nr_nodes; i++)
		numdevices += nodes[i].nr_vdevs;

	unsigned long time_start, time_end;
	time_start = (unsigned long)time(NULL);
	flexhash_rebuild_start(fx->flexhash, nr_nodes, numdevices);
	flexhash_add_serverlist(fx->flexhash->rebuild_ctx.fhtable, nodes, nr_nodes, FH_REBUILD_NEXT);
	flexhash_rebuild_done(&fx->flexhash, 0, 0, 0);
	time_end = (unsigned long)time(NULL);
	fxdump(fx);
	cprint("Flexhash rebuild time: %lu ms", (time_end - time_start) / 1000);

	for (i = 0; i < nr_nodes; i++)
		if (nodes[i].nr_vdevs)
			je_free(nodes[i].vdevs);
	je_free(nodes);
	return 0;
}

static void
flexhash_recreate(struct flexclass *fx, int numdevices)
{
	flexhash_table_destroy(fx->flexhash);
	fx->flexhash = flexhash_table_create(numdevices, FH_SERVER_SIDE);
	flexhash_mark_stale(fx->flexhash);
}

static void
flexhash_terminate(struct flexclass *fx)
{
	cprint("Terminating flexhash");
	uv_close((uv_handle_t *)&fx->hdl, NULL);
	if (fx->selfnode.vdevs)
		je_free(fx->selfnode.vdevs);
}

static void
flexhash_stop(struct flexclass *fx)
{
	cprint("Stopping flexhash");
	flexhash_mark_stale(fx->flexhash);
}

static void
flexhash_start(struct flexclass *fx)
{
	cprint("Starting flexhash");
}

static int
flexhash_init(struct flexclass *fx, int numdevices)
{
	cprint("Initializing flexhash");

	char input[128];
	snprintf(input, 128, "Random server ID %d %ld", (int) getpid(), random());
	crypto_hash(CRYPTO_BLAKE2B, 16, (uint8_t *)input, strlen(input), (uint8_t *)&fx->selfid);
	cprint128("Serverid:", &fx->selfid);
	fx->flexhash = flexhash_table_create(numdevices, FH_SERVER_SIDE);

	struct cl_node *node = &fx->selfnode;
	node->serverid = fx->selfid;
	node->nr_vdevs = numdevices;
	node->vdevs = je_calloc(node->nr_vdevs, sizeof(struct cl_vdev));
	if (!node->vdevs) {
		cerror("Failed to allocate memory");
		return -1;
	}

	for (uint32_t i = 0; i < node->nr_vdevs; i++) {
		struct cl_vdev *vdev = &node->vdevs[i];
		snprintf(input, 128, "Random vdev ID %d %ld %u", (int) getpid(), random(), i);
		crypto_hash(CRYPTO_BLAKE2B, 16, (uint8_t *)input, 128, (uint8_t *)&vdev->vdevid);
		vdev->size = 104876000;
		vdev->activerows = 0;
		vdev->numrows = FLEXCOUNT_TAB_LENGTH;
		flexhash_sumsquares_seeded(&vdev->vdevid, vdev->hashcount, FLEXCOUNT_TAB_LENGTH);
	}

	flexhash_mark_stale(fx->flexhash);

	uv_async_init(g_loop, &fx->hdl, NULL);

	return 0;
}

//=============================================================================

static void corosync_terminate(struct coroclass *cfl);
static void corosync_stop(struct coroclass *cfl);
static void corosync_fx_cb(uv_timer_t* handle, int status);

static void
corosync_update_hc(struct coroclass *cfl, struct flexclass *fx, struct cl_node *node, int nr_nodes)
{
	int i;
	struct cl_node *rnode = NULL;
	cprint("Updating hashcounts");
	for (i = 0; i < nr_nodes; i++) {
		if (uint128_cmp(&fx->selfnode.serverid, &node[i].serverid) == 0) {
			rnode = &node[i];
			break;
		}
	}

	uint32_t j, k;
	struct cl_vdev *rvdev, *fvdev;
	for (j = 0; j < rnode->nr_vdevs; j++) {
		rvdev = &rnode->vdevs[j];
		for (k = 0; k < fx->selfnode.nr_vdevs; k++) {
			fvdev = &fx->selfnode.vdevs[k];
			if (uint128_cmp(&rvdev->vdevid, &fvdev->vdevid) == 0) {
				fvdev->activerows = rvdev->activerows;
				memcpy(fvdev->hashcount, rvdev->hashcount, sizeof(fvdev->hashcount));
				break;
			}
		}
	}
}

static void
corosync_add_server(struct coroclass *cfl, uint32_t nodeid, uint32_t pid, uint128_t *serverid)
{
	int k = cfl->servercount;
	cfl->nodeid_list[k] = nodeid;
	cfl->pid_list[k] = pid;
	cfl->serverid_list[k] = *serverid;
	cfl->servercount++;
}

static void
corosync_remove_server(struct coroclass *cfl, uint32_t nodeid, uint32_t pid)
{
	int j, k, index, found = 0;
	for (j = 1; j < cfl->servercount; j++) {
		if (nodeid == cfl->nodeid_list[j] && pid == cfl->pid_list[j]) {
			cprint128("Removing server", &cfl->serverid_list[j]);
			index = j;
			found = 1;
			break;
		}
	}

	if (!found)
		return;

	for (j = index + 1; j < cfl->servercount; j++) {
		k = j - 1;
		cfl->nodeid_list[k] = cfl->nodeid_list[j];
		cfl->pid_list[k] = cfl->pid_list[j];
		cfl->serverid_list[k] = cfl->serverid_list[j];
	}

	cfl->servercount--;
}

static int
corosync_find_server1(struct coroclass *cfl, uint128_t *serverid)
{
	for (int j = 0; j < cfl->servercount; j++)
		if (uint128_cmp(&cfl->serverid_list[j], serverid) == 0)
			return j;
	return -1;
}

static int
corosync_find_server2(struct coroclass *cfl, uint32_t nodeid, uint32_t pid)
{
	for (int j = 0; j < cfl->servercount; j++)
		if (nodeid == cfl->nodeid_list[j] && pid == cfl->pid_list[j])
			return j;
	return -1;
}

static void
corosync_publish(struct coroclass *cfl, struct iovec *iov, int iovcnt)
{
	int ret;
	do {
		ret = cpg_mcast_joined(cfl->handle, CPG_TYPE_FIFO, iov, iovcnt);
		if (ret == CS_ERR_TRY_AGAIN)
			sleep(1);
		else if (ret != CS_OK)
			cerror("Failed to publish node info");
	} while (ret == CS_ERR_TRY_AGAIN);
}

static void
corosync_clear_leader(struct coroclass *cfl, struct ioclass *io)
{
	if (cfl->leader) {
		uv_timer_stop(&cfl->fx_timer);
		io_stop(io);
	}
	cfl->leader = 0;
}

static void
corosync_mark_leader(struct coroclass *cfl, struct ioclass *io)
{
	cfl->leader = 1;
	uv_timer_start(&cfl->fx_timer, corosync_fx_cb, FX_TIMER_MS, FX_TIMER_MS);
	io_start(io);
}

static int
self_leader(struct coroclass *cfl, struct flexclass *fx)
{
	for (int i = 0; i < cfl->servercount; i++)
		if (uint128_cmp(&cfl->serverid_list[i], &fx->selfnode.serverid) < 0)
			return 0;
	return 1;
}

static void
corosync_publish_all(struct coroclass *cfl, struct flexclass *fx)
{
	struct coromsg cmsg;
	struct iovec iov[2];
	uv_buf_t payload;
	int err;

	cprint("Sending flexhash");
	struct cl_node *nodes;
	int nr_nodes;
	err = flexhash_get_nodes(fx->flexhash, &nodes, &nr_nodes, FH_GOOD_HC);
	if (err) {
		cerror("Failed to get nodes from flexhash");
		return;
	}

	cprint("Packing %d nodes", nr_nodes);
	err = replicast_pack_uvbuf_nodes(nodes, nr_nodes, &payload, NULL);
	if (err) {
		cerror("Failed to pack payload");
		return;
	}

	cmsg.type = CMSG_NODE_ALL;
	cmsg.nodeid = cfl->nodeid;
	cmsg.pid = cfl->pid;
	cmsg.serverid = cfl->serverid;
	cmsg.nr_nodes = nr_nodes;
	iov[0].iov_base = &cmsg;
	iov[0].iov_len = sizeof(struct coromsg);
	iov[1].iov_base = payload.base;
	iov[1].iov_len = payload.len;

	corosync_publish(cfl, iov, 2);
	je_free(payload.base);
}

static void
corosync_publish_self(struct coroclass *cfl, struct flexclass *fx)
{
	struct coromsg cmsg;
	struct iovec iov[2];
	uv_buf_t payload;
	int ret;

	ret = replicast_pack_uvbuf_nodes(&fx->selfnode, 1, &payload, NULL);
	if (ret) {
		cerror("Failed to pack payload");
		return;
	}

	cmsg.type = CMSG_NODE_ONE;
	cmsg.nodeid = cfl->nodeid;
	cmsg.pid = cfl->pid;
	cmsg.serverid = cfl->serverid;
	cmsg.nr_nodes = 1;
	iov[0].iov_base = &cmsg;
	iov[0].iov_len = sizeof(struct coromsg);
	iov[1].iov_base = payload.base;
	iov[1].iov_len = payload.len;

	corosync_publish(cfl, iov, 2);
	je_free(payload.base);
}

static void
corosync_publish_request(struct coroclass *cfl)
{
	struct coromsg cmsg;
	struct iovec iov[1];

	cmsg.type = CMSG_NODE_PUBLISH;
	cmsg.nodeid = cfl->nodeid;
	cmsg.pid = cfl->pid;
	cmsg.serverid = cfl->serverid;
	cmsg.nr_nodes = 0;
	iov[0].iov_base = &cmsg;
	iov[0].iov_len = sizeof(struct coromsg);

	corosync_publish(cfl, iov, 1);
}

static void
corosync_publish_cb(uv_timer_t* handle, int status)
{
	corosync_publish_self(&coroclass, &flexclass);
}

static void
corosync_rebuild_cb(uv_timer_t* handle, int status)
{
	struct coroclass *cfl = &coroclass;
	struct flexclass *fx = &flexclass;
	struct ioclass *io = &ioclass;

	if (cfl->servercount != fx->flexhash->servercount) {
		cerror("Replies from all servers not received. Restarting discovery.");
		return;
	}

	if (!self_leader(cfl, fx)) {
		cprint("Skip rebuilding flexhash.");
		return;
	}

	// We are the leader
	flexhash_clear_stale(fx->flexhash);
	flexhash_rebuild(fx);
	corosync_publish_all(cfl, fx);
	corosync_mark_leader(cfl, io);
}

static void
corosync_fx_cb(uv_timer_t* handle, int status)
{
	corosync_publish_all(&coroclass, &flexclass);
}

static void
process_all_nodes(struct coroclass *cfl, struct flexclass *fx,
	struct cl_node *node, int nr_nodes)
{
	int i, err, numdevices = 0;

	cprint("Receiving flexhash");
	for (i = 0; i < nr_nodes; i++)
		numdevices += node[i].nr_vdevs;

	flexhash_recreate(fx, numdevices);

	for (i = 0; i < nr_nodes; i++) {
		err = corosync_find_server1(cfl, &node[i].serverid);
		if (err < 0) {
			cprint128("Failed to find server.", &node[i].serverid);
			return;
		}

		err = flexhash_add_server(fx->flexhash, &node[i], FH_TABLE_JOIN, FH_GOOD_HC, FH_NO_REBUILD);
		if (err) {
			cerror("Failed to add server");
			return;
		}

		cprint128("Flexhash server added: ", &node[i].serverid);
	}

	fxdump(fx);
	flexhash_clear_stale(fx->flexhash);

	if (self_leader(cfl, fx)) {
		cerror("Leader incorrect. Restarting discovery.");
		uv_timer_stop(&cfl->fx_timer);
		corosync_publish_request(cfl);
	}
}

static void
process_one_node(struct coroclass *cfl, struct flexclass *fx,
	struct cl_node *node, struct coromsg *cmsg)
{
	// Add server to corosync
	int err, index;
	index = corosync_find_server2(cfl, cmsg->nodeid, cmsg->pid);
	if (index < 0) {
		corosync_add_server(cfl, cmsg->nodeid, cmsg->pid, &cmsg->serverid);
		cprint128("Corosync server added: ", &cmsg->serverid);
	}

	// Add server to the flexhash. Don't join the flexhash.
	err = flexhash_add_server(fx->flexhash, node, FH_TABLE_NOJOIN, FH_GOOD_HC, FH_REBUILD_NEXT);
	if (err) {
		cerror("Flexhash failed to add server");
		return;
	}

	// There is high possibility that multiple join messages will be received.
	uv_timer_stop(&cfl->rebuild_timer);
	uv_timer_start(&cfl->rebuild_timer, corosync_rebuild_cb, REBUILD_TIMER_MS, 0);
}

static void
deliver(cpg_handle_t handle, const struct cpg_name *name,
	uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
	struct coroclass *cfl = &coroclass;
	struct flexclass *fx = &flexclass;
	struct ioclass *io = &ioclass;
	struct coromsg *cmsg = msg;
	uv_buf_t payload;
	struct cl_node *node = NULL;
	int nr_nodes;
	int err, ret;

	cprint("CPG deliver: group %s pid %u type %d", name->value, cmsg->pid, cmsg->type);

	nr_nodes = cmsg->nr_nodes;
	if (nr_nodes) {
		payload.base = (char *)msg + sizeof(struct coromsg);
		payload.len = msg_len - sizeof(struct coromsg);
		err = replicast_unpack_uvbuf_nodes(&payload, nr_nodes, &node,
		    NULL, 0);
		if (err) {
			cerror("Failed to unpack node info");
			return;
		}
		cprint("Unpacked %d nodes", nr_nodes);
	}

	switch (cmsg->type) {
	case CMSG_NODE_PUBLISH:
		corosync_clear_leader(cfl, io);
		uv_timer_stop(&cfl->publish_timer);
		uv_timer_start(&cfl->publish_timer, corosync_publish_cb, PUBLISH_TIMER_MS, 0);
		break;

	case CMSG_NODE_ONE:
		process_one_node(cfl, fx, node, cmsg);
		break;

	case CMSG_NODE_ALL:
		if (uint128_cmp(&fx->selfnode.serverid, &cmsg->serverid) != 0)
			process_all_nodes(cfl, fx, node, nr_nodes);
		corosync_update_hc(cfl, fx, node, nr_nodes);
		break;

	default:
		cerror("Invalid message");
		break;
	}

	for (int i = 0; i < nr_nodes; i++)
		if (node[i].nr_vdevs)
			je_free(node[i].vdevs);
	if (node)
		je_free(node);
}

static void
confchg(cpg_handle_t handle, const struct cpg_name *name,
	const struct cpg_address *members, size_t nr_members,
	const struct cpg_address *left, size_t nr_left,
	const struct cpg_address *joined, size_t nr_joined)
{
	unsigned long i;
	struct coroclass *cfl = &coroclass;
	struct flexclass *fx = &flexclass;
	struct ioclass *io = &ioclass;

	cprint("CPG config: group %s members %lu joined %lu left %lu",
		name->value, nr_members, nr_joined, nr_left);

	for(i = 0; i < nr_joined; i++)
		cprint("Joined nodeid: %u pid: %u", joined[i].nodeid, joined[i].pid);
	for(i = 0; i < nr_left; i++)
		cprint("Left nodeid: %u pid: %u", left[i].nodeid, left[i].pid);
	for(i = 0; i < nr_members; i++)
		cprint("Member nodeid: %u pid: %u", members[i].nodeid, members[i].pid);

	corosync_clear_leader(cfl, io);

	if (cfl->state == CORO_SUSPEND) {
		corosync_stop(cfl);
		return;
	}

	if (cfl->state == CORO_LEAVING) {
		corosync_terminate(cfl);
		return;
	}

	for(i = 0; i < nr_left; i++) {
		int index = corosync_find_server2(cfl, left[i].nodeid, left[i].pid);
		if (index > 0) {
			cprint128("Corosync server removed:", &cfl->serverid_list[index]);
			corosync_remove_server(cfl, left[i].nodeid, left[i].pid);
			flexhash_recreate(fx, fx->selfnode.nr_vdevs);
		}
	}

	uv_timer_stop(&cfl->fx_timer);
	corosync_publish_request(cfl);
}

static void
dispatch(uv_poll_t *req, int status, int events)
{
	if (!(events & UV_READABLE))
		return;
	struct coroclass *cfl = req->data;
	cpg_dispatch(cfl->handle, CS_DISPATCH_ALL);
}

static void
corosync_terminate(struct coroclass *cfl)
{
	cprint("Terminating corosync");
	if (cfl->state == CORO_JOINED) {
		uv_timer_stop(&cfl->publish_timer);
		uv_close((uv_handle_t *)&cfl->publish_timer, NULL);
		uv_timer_stop(&cfl->rebuild_timer);
		uv_close((uv_handle_t *)&cfl->rebuild_timer, NULL);
		uv_timer_stop(&cfl->fx_timer);
		uv_close((uv_handle_t *)&cfl->fx_timer, NULL);

		cfl->state = CORO_LEAVING;
		cpg_leave(cfl->handle, &cfl->corogroup);
		return;
	}

	uv_poll_stop(&cfl->poll_fd);
	uv_close((uv_handle_t *)&cfl->poll_fd, NULL);
	cpg_finalize(cfl->handle);
	fclose(logfp);
}

static void
corosync_stop(struct coroclass *cfl)
{
	cprint("Stopping corosync");
	if (cfl->state == CORO_JOINED) {
		cfl->state = CORO_SUSPEND;
		cpg_leave(cfl->handle, &cfl->corogroup);
		return;
	}
 
	uv_poll_stop(&cfl->poll_fd);
	uv_timer_stop(&cfl->publish_timer);
	uv_timer_stop(&cfl->rebuild_timer);
	uv_timer_stop(&cfl->fx_timer);
}

static int
corosync_start(struct coroclass *cfl)
{
	cprint("Starting corosync");
	uv_poll_start(&cfl->poll_fd, UV_READABLE, dispatch);

	int timeout = 30;
	int err = -1;
	while (timeout--) {
		err = cpg_join(cfl->handle, &cfl->corogroup);
		if (err == CS_OK) {
			cfl->state = CORO_JOINED;
			err = 0;
			break;
		}
		if (err != CS_ERR_TRY_AGAIN)
			cerror("cpg_join failed %d", err);
		sleep(1);
	}

	return err;
}

static int
corosync_init(struct coroclass *cfl, struct flexclass *fx, int numdevices)
{
	uint32_t nodeid;
	int err;

	cprint("Initializing corosync");
	cfl->corogroup.length = 8;
	strcpy(cfl->corogroup.value, "coroflex");
	cfl->cb.cpg_deliver_fn = deliver;
	cfl->cb.cpg_confchg_fn = confchg;

	err = cpg_initialize(&cfl->handle, &cfl->cb);
	if (err != CS_OK) {
		cerror("Error initializing corosync");
		return -1;
	}

	err = cpg_fd_get(cfl->handle, &cfl->cpg_fd);
	if (err != CS_OK) {
		cerror("Error initializing corosync");
		return -1;
	}

	err = cpg_local_get(cfl->handle, &nodeid);
	if (err != CS_OK) {
		cerror("Error getting nodeid");
		return -1;
	}

	cfl->nodeid = nodeid;
	cfl->pid = getpid();
	cfl->serverid = fx->selfid;
	cfl->nodeid_list[0] = cfl->nodeid;
	cfl->pid_list[0] = cfl->pid;
	cfl->serverid_list[0] = fx->selfid;
	cfl->servercount = 1;

	cfl->numdevices = numdevices;
	cfl->poll_fd.data = cfl;
	uv_poll_init(g_loop, &cfl->poll_fd, cfl->cpg_fd);
	cfl->state = CORO_INIT;
	cfl->leader = 0;
	uv_timer_init(g_loop, &cfl->publish_timer);
	uv_timer_init(g_loop, &cfl->rebuild_timer);
	uv_timer_init(g_loop, &cfl->fx_timer);
	return 0;
}

static void
coroflex_term()
{
	io_stop(&ioclass);
	io_terminate(&ioclass);
	flexhash_stop(&flexclass);
	flexhash_terminate(&flexclass);
	corosync_terminate(&coroclass);
}

static void
coroflex_stop()
{
	io_stop(&ioclass);
	flexhash_stop(&flexclass);
	corosync_stop(&coroclass);
	g_running = 0;
}

static int
coroflex_start()
{
	flexhash_start(&flexclass);
	if (corosync_start(&coroclass))
		return -1;
	g_running = 1;
	return 0;
}

static int
coroflex_init(int numdevices)
{
	if (flexhash_init(&flexclass, numdevices))
		return -1;
	if (corosync_init(&coroclass, &flexclass, flexclass.selfnode.nr_vdevs))
		return -1;
	io_init(&ioclass, &flexclass);
	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGUSR1)
		(g_running == 0) ? coroflex_start() : coroflex_stop();

	if (signum == SIGINT)
		coroflex_term();
}

static void
usage(char *program, int err)
{
	printf("Usage: %s [ -d <numdevices> ] -f <logfile-path> \n", program);
	printf("Runs a corosync process with provided no of devices (default 10).\n");
	printf("Multiple instances can be run on the same host.\n");
	printf("The instances communicate with each other and simulate\n");
	printf("topology discovery and coordinated flexhash creation.\n");
	exit(err);
}

static void
parse_options(int argc, char **argv, int *numdevices)
{
	int opt, nd;

	while ((opt = getopt(argc, argv, "hd:f:")) != -1) {
		switch(opt) {
		case 'd':
			nd = (int) strtol(optarg, NULL, 10);
			*numdevices = nd;
			break;
		case 'f':
			strncpy(logfile, optarg, 128);
			break;

		case 'h':
		default:
			usage(argv[0], 0);
			break;
		}
	}

	if (logfile[0] == 0) {
		printf("Provide logfile path.\n");
		usage(argv[0], 1);
	}

	logfp = fopen(logfile, "a+");
	if (!logfp) {
		fprintf(stderr, "Error opening file %s\n", logfile);
		usage(argv[0], 1);
	}
}

int main(int argc, char **argv)
{
	int err, numdevices = 10;
	parse_options(argc, argv, &numdevices);

	// Redirect logger output to provided file
	lg = Logger_create("coroflex_test");
	lg->level = LOG_LEVEL_DEBUG;
	lg->file = logfp;

	signal(SIGINT, signal_handler);
	signal(SIGUSR1, signal_handler);

	srandom((unsigned int)time(NULL));

	g_loop = uv_default_loop();

	if (coroflex_init(numdevices))
		return -1;

	if (coroflex_start())
		return -1;

	cprint("Press Ctrl+C to terminate");
	uv_run(g_loop, UV_RUN_DEFAULT);
}

