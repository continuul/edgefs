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
#include <netinet/in.h>
#include <net/if.h>
#include <sys/user.h>
#include <sys/param.h>
#include <wchar.h>
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>
#include <dlfcn.h>
#include <json.h>

#include "ccowutil.h"
#include "queue.h"
#include "reptrans.h"
#include "replicast.h"
#include "json.h"
#include "clengine.h"
#include "ccowd-impl.h"
#include "auditd.h"
#include "ccow.h"
#include "erasure-coding.h"
#include "reptrans_bg_sched.h"
#include "vmm_cache.h"
#include "ccow-impl.h"
#include "rt_locks.h"
#include "rcvd_cache.h"
#include "opp-status-srv.h"
#include "putcommon_server.h"
#include "reptrans-flex.h"
#include "gwcache.h"
#include "probes.h"
#include "trlog.h"
#include "bufcursor.h"
#include "rowevac.h"
#include "rowevac-srv.h"

#define VBRS_PER_GET	5000

__thread volatile void* _tls_vdev_ptr;

static int
dev_rep_count_verify_one(space_reclaim_work_t *work, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, uv_buf_t *val,
	uint512_t *nhid, int rep_count);

static int
reptrans_replicate_one(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, const uint512_t* nhid,
	uint8_t rep_count);

static void
reptrans_suspend_timestamp(struct reptrans* rt);

static void
reptrans_resume_timestamp(struct reptrans* rt);

static void
reptrans_sync_timestamp(uv_timer_t* handle, int status);


extern struct ccowd *ccow_daemon;
extern volatile int ccowd_terminating;
QUEUE all_rts = QUEUE_INIT_STATIC(all_rts);
uint128_t all_vdevs[REPTRANS_MAX_VDEVS];

#define TRANS_CONF_DIR "%s/etc/ccow"

static int
disk_detach_cb(struct repdev* dev, void* arg) {
	char* diskID = arg;
	if (!strcmp(diskID, dev->name)) {
		reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
		int err = dev->rt->dev_ctl(dev, vdevCtlDetach, NULL);
		if(!err)
			err = 1;
		return err;
	}
	return 0;
}

static int
disk_detach_hdl(struct ccowd_ipc_cmd* p, uv_buf_t msg, uv_buf_t* resp) {
	char* diskID = msg.base;

	char* rbuf = je_malloc(128);
	if (!rbuf)
		return -ENOMEM;

	int err = reptrans_foreach_vdev(disk_detach_cb, diskID);
	if (!err)
		err = -ENOENT;
	else if (err == 1)
		err = 0;
	sprintf(rbuf, "DISK_DETACH_REPLY%d", err);
	resp->base = rbuf;
	resp->len = strlen(rbuf) + 1;
	return 0;
}

static int
disk_attach_cb(struct repdev* dev, void* arg) {
	char* diskID = arg;
	if (!strcmp(diskID, dev->name)) {
		int err = 0;
		repdev_status_t status = reptrans_dev_get_status(dev);
		if (status == REPDEV_STATUS_UNAVAILABLE ||
			status == REPDEV_STATUS_INIT ||
			status == REPDEV_STATUS_READONLY_FORCED) {
			err = dev->rt->dev_ctl(dev, vdevCtlAttach, NULL);
			if (!err) {
				err = 1;
				reptrans_dev_override_status(dev, REPDEV_STATUS_ALIVE);
			}
		}
		return err;
	}
	return 0;
}

static int
disk_attach_hdl(struct ccowd_ipc_cmd* p, uv_buf_t msg, uv_buf_t* resp) {
	char* diskID = msg.base;

	char* rbuf = je_malloc(128);
	if (!rbuf)
		return -ENOMEM;
	int err = reptrans_foreach_vdev(disk_attach_cb, diskID);
	if (!err)
		err = -ENOENT;
	else if (err == 1)
		err = 0;
	sprintf(rbuf, "DISK_ATTACH_REPLY%d", err);
	resp->base = rbuf;
	resp->len = strlen(rbuf) + 1;
	return 0;
}

struct disk_status_cb_arg {
	const char* name;
	int status;
};

static int
disk_status_cb(struct repdev* dev, void* arg) {
	struct disk_status_cb_arg* p = arg;
	if (!strcmp(p->name, dev->name)) {
		p->status = reptrans_dev_get_status(dev);
		return 1;
	}
	return 0;
}

static int
disk_status_hdl(struct ccowd_ipc_cmd* p, uv_buf_t msg, uv_buf_t* resp) {
	char* diskID = msg.base;

	char* rbuf = je_malloc(256);
	if (!rbuf)
		return -ENOMEM;

	struct disk_status_cb_arg arg = {
		.name = diskID,
		.status = -1
	};
	int err = reptrans_foreach_vdev(disk_status_cb, &arg);
	if (arg.status < 0)
		sprintf(rbuf, "DISK_STATUS_REPLY_NOT_FOUND");
	else
		sprintf(rbuf, "DISK_STATUS_REPLY_%s", repdev_status_name[arg.status]);
	resp->base = rbuf;
	resp->len = strlen(rbuf) + 1;
	return 0;
}

static int
disk_roforce_cb(struct repdev* dev, void* arg) {
	struct disk_status_cb_arg* p = arg;

	if (!strcmp(p->name, dev->name)) {
		repdev_status_t status = reptrans_dev_get_status(dev);
		if (status == REPDEV_STATUS_ALIVE ||
			status == REPDEV_STATUS_READONLY_DATA ||
			status == REPDEV_STATUS_READONLY_FULL ||
			status == REPDEV_STATUS_READONLY_FAULT) {
			reptrans_dev_set_status(dev, REPDEV_STATUS_READONLY_FORCED);
			/* Give it 1 sec to finish current put */
			sleep(1);
			p->status = 0;
		} else
			p->status = -EPERM;
		return -1;
	}
	return 0;
}

static int
disk_roforce_hdl(struct ccowd_ipc_cmd* p, uv_buf_t msg, uv_buf_t* resp) {
	char* diskID = msg.base;

	char* rbuf = je_malloc(256);
	if (!rbuf)
		return -ENOMEM;

	struct disk_status_cb_arg arg = {
		.name = diskID,
		.status = -ENOENT
	};
	int err = reptrans_foreach_vdev(disk_roforce_cb, &arg);
	sprintf(rbuf, "DISK_ROFORCE_REPLY%d", arg.status);

	resp->base = rbuf;
	resp->len = strlen(rbuf) + 1;
	return 0;
}

static rtbuf_t * reptrans_read_file(const char *filename);

static int
disk_discovery_cb(struct repdev* dev, void* p) {
	struct disk_status_cb_arg* a = p;
	char conffile[4096];
	struct vdevCtlDiscoverArg arg = { .name = a->name };

	/*
	 * Use any first VDEV to send discovery request
	 * Read configuration file
	 */
	sprintf(conffile, TRANS_CONF_DIR "/%s.json", nedge_path(), dev->rt->name);
	rtbuf_t *rb = reptrans_read_file(conffile);
	if (!rb) {
		log_warn(lg, "Cannot open configuration file %s",
		    conffile);

		a->status = -EBADF;
		goto _done;
	}

	/*
	 * Parse configuration file
	 */
	arg.cfg = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (!arg.cfg) {
		log_warn(lg, "Cannot parse configuration file %s",
		    conffile);
		a->status = -EBADF;
		goto _done;
	}

	a->status = dev->rt->dev_ctl(dev, vdevCtlDiscover, &arg);

_done:
	if (rb)
		rtbuf_destroy(rb);
	return -1;
}

static int
disk_discovery_hdl(struct ccowd_ipc_cmd* p, uv_buf_t msg, uv_buf_t* resp) {
	char* rbuf = je_malloc(256);
	if (!rbuf)
		return -ENOMEM;

	struct disk_status_cb_arg arg = {
		.name = msg.base,
		.status = 0
	};
	int err = reptrans_foreach_vdev(disk_discovery_cb, &arg);
	sprintf(rbuf, "DISK_DISCOVERY_REPLY%d", arg.status);
	resp->base = rbuf;
	resp->len = strlen(rbuf) + 1;
	return 0;
}

static struct ccowd_ipc_cmd rtipcmds[] = {
	{ .key = "DISK_DETACH_", .handler = disk_detach_hdl, .flags = CCOWD_IPC_FLAG_THREADED},
	{ .key = "DISK_ATTACH_", .handler = disk_attach_hdl, .flags = CCOWD_IPC_FLAG_THREADED},
	{ .key = "DISK_STATUS_", .handler = disk_status_hdl, .flags = CCOWD_IPC_FLAG_THREADED},
	{ .key = "DISK_ROFORCE_", .handler = disk_roforce_hdl, .flags = 0},
	{ .key = "DISK_DISCOVERY_", .handler = disk_discovery_hdl, .flags = CCOWD_IPC_FLAG_THREADED},
};

static int
reptrans_get_row_fd_number(struct repdev* dev, const uint512_t* ngchid) {
	int nfd = -1;
	uint16_t n_groups = 0;
	SERVER_FLEXHASH_SAFE_CALL(n_groups = flexhash_numrows(SERVER_FLEXHASH), FH_LOCK_READ);
	uint16_t row = HASHCALC(ngchid, n_groups - 1);
	ccow_t tc = reptrans_get_tenant_context(dev->rt, 0);
	if (tc) {
		int fd_policy = tc->failure_domain;
		nfd = reptrans_get_fd_targets_number(fd_policy);;
		if (fd_policy == FD_ZONE)
			nfd = flexhash_row_zonecount(CLIENT_FLEXHASH, row);
		else if (fd_policy == FD_SERVER)
			nfd = flexhash_row_servercount(CLIENT_FLEXHASH, row);
		reptrans_put_tenant_context(dev->rt, tc);
	}
	return nfd;
}

/*
 * Read file into allocated rtbuf_t. Returns NULL on error.
 * Syncrhonous operation.
 */
static rtbuf_t *
reptrans_read_file(const char *filename)
{
	struct stat st;
	if (stat(filename, &st) != 0) {
		log_error(lg, "Cannot access configuration file %s: %s",
		    filename, strerror(errno));
		return NULL;
	}

	rtbuf_t *rb = rtbuf_init_alloc_one(st.st_size);
	if (!rb) {
		log_error(lg, "Out of memory while reading %s", filename);
		return NULL;
	}

	int fd = open(filename, O_RDONLY);
	if (fd == -1) {
		rtbuf_destroy(rb);
		log_error(lg, "Cannot open configuration file %s: %s",
		    filename, strerror(errno));
		return NULL;
	}
	int len = read(fd, rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (len == -1) {
		close(fd);
		rtbuf_destroy(rb);
		log_error(lg, "Cannot read configuration file %s: %s",
		    filename, strerror(errno));
		return NULL;
	}
	close(fd);
	return rb;
}

void
clengine_reptrans_notify(int leave_join, int nr_members) {
	struct reptrans *rt = NULL;
	QUEUE* q;
	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		if (rt->terminating)
			continue;
		uv_rwlock_wrlock(&rt->cl_healthy_lock);
		rt->fd_delta_valid_time = 0;
		uv_rwlock_wrunlock(&rt->cl_healthy_lock);
	}
}

void
reptrans_fddelta_update(uint64_t period_ms) {
	if (!ccow_daemon)
		return;

	struct reptrans *rt = NULL;
	QUEUE* q;
	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		if (rt->terminating)
			continue;
		int prog = 0;
		SERVER_FLEXHASH_SAFE_CALL(prog =
			flexhash_rebuild_inprogress(SERVER_FLEXHASH), FH_LOCK_READ);
		uv_rwlock_wrlock(&rt->cl_healthy_lock);
		if (ccowd_get_fddelta() != rt->fd_delta_prev || prog)
			rt->fd_delta_valid_time = 0;
		else
			rt->fd_delta_valid_time += period_ms;
		rt->fd_delta_prev = ccowd_get_fddelta();
		if (!ccowd_get_fddelta())
			reptrans_resume_timestamp(rt);
		else
			reptrans_suspend_timestamp(rt);
		uv_rwlock_wrunlock(&rt->cl_healthy_lock);
	}
}

int
is_cluster_healthy(struct reptrans* rt, int rep_cnt) {
	if (rt->terminating)
		return 0;
	int prog = 0;
	SERVER_FLEXHASH_SAFE_CALL(prog =
		flexhash_rebuild_inprogress(SERVER_FLEXHASH), FH_LOCK_READ);
	if (prog)
		return 0;
	uv_rwlock_rdlock(&rt->cl_healthy_lock);
	uint64_t dt = rt->fd_delta_valid_time;
	uv_rwlock_rdunlock(&rt->cl_healthy_lock);
	if (dt > CLUSTER_HEALTHY_INTERVAL && ccowd_get_fddelta() + rep_cnt >= 1)
		return 1;
	else
		return 0;
}

struct vbr_nhid_extract_data {
	uint512_t* nhid;
	volatile int found;
};

static int
nhdi_vbr_iterator (struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, uv_buf_t* vbr_buf, const struct backref* vbr,
	void* arg) {
	struct vbr_nhid_extract_data* p = arg;
	if (vbr->ref_type == TT_NAMEINDEX) {
		*p->nhid = vbr->name_hash_id;
		p->found= 1;
		return -EEXIST;
	}
	return 0;
}

int
reptrans_get_vm_nhid(struct repdev* dev, const uint512_t* vmchid,
	uint512_t* nhid) {
	assert(nhid);
	assert(vmchid);
	assert(dev);
	/*
	 * VM NHID can be taken from VBR if ref_type == TT_NAMEINDEX
	 * Otherwise NHID is to be extracted from VM's metadata.
	 */
	struct vbr_nhid_extract_data data = { .found = 0, .nhid = nhid };
	int err = reptrans_vbrs_iterate(dev, vmchid, HASH_TYPE_DEFAULT,
		nhdi_vbr_iterator, &data);
	if (err && err != -EEXIST)
		return err;
	if (!data.found) {
		rtbuf_t* rb = NULL;
		struct vmmetadata md;
		err = reptrans_get_blob(dev, TT_VERSION_MANIFEST,
			HASH_TYPE_DEFAULT, vmchid, &rb);
		if (err || !rb)
			return -ENOENT;
		err = replicast_get_metadata(rb, &md);
		rtbuf_destroy(rb);
		if (err)
			return err;
		*nhid = md.nhid;
	}
	return 0;
}

/**
 * A set of replicast wrappers to be used internally in reptrans
 * for its own purpose.
 * It adds to replicast message header a payload's hashID
 * and protocol-related info.
 */

/**
 * Send generic message (buffer)
 */
int
reptrans_ng_send(enum rt_proto_id id, struct replicast *robj,
	struct repctx *ctx, enum replicast_opcode opcode,
	struct repmsg_generic *omsg, uv_buf_t bufs[], unsigned int nbufs,
	struct sockaddr_in6 *to_addr, replicast_send_cb cb, void *data) {

	struct repmsg_ng msg;
	uint512_t hid;

	memset(&msg, 0, sizeof (msg));
	rtbuf_t* rt = rtbuf_init_mapped(bufs, nbufs);
	int err = rtbuf_hash(rt, HASH_TYPE_XXHASH_64, &hid);
	msg.hashID = hid.u.u.u;
	rtbuf_destroy(rt);

	msg.attr = reptrans_get_ngproto_version(id);
	msg.attr |= id << 8;

	if (ctx && ctx->attributes == RD_ATTR_UNICAST_UDP_MCPROXY)
		msg.hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;

	if (err)
		return err;

	return replicast_send(robj, ctx, opcode, (struct repmsg_generic*)&msg,
		omsg, bufs, nbufs, to_addr, cb, data, NULL);
}

struct ng_send_cb_data {
	void* data;
	msgpack_p* p;
	replicast_send_cb cb;
};

static void
reptrans_ng_send_pack_done_cb(void *data, int status, int ctx_valid) {
	struct ng_send_cb_data* ptr = (struct ng_send_cb_data*)data;
	assert(ptr);
	assert(ptr->p);

	msgpack_pack_free(ptr->p);
	if (ptr->cb) {
		ptr->cb(ptr->data, status, ctx_valid);
	}
	je_free(ptr);
}
/**
 * Send a message converted to msgpack
 *
 * @param pack_cb points to function that converts the @param dptr into msgpack
 */
int
reptrans_ng_send_pack(enum rt_proto_id id, struct replicast *robj,
	struct repctx *ctx, enum replicast_opcode opcode,
	struct repmsg_generic *omsg, void* dptr, rt_ng_pack_cb pack_cb,
	struct sockaddr_in6 *to_addr, replicast_send_cb cb, void *data) {
	assert(pack_cb);

	uv_buf_t uvb;
	msgpack_p *p = msgpack_pack_init();
	int err = pack_cb(p, dptr);

	if (err) {
		msgpack_pack_free(p);
		return err;
	}
	msgpack_get_buffer(p,&uvb);

	struct ng_send_cb_data* cb_data = je_calloc(1, sizeof(struct ng_send_cb_data));
	if (!cb_data)
		return -ENOMEM;

	cb_data->data = data;
	cb_data->cb = cb;
	cb_data->p = p;

	return reptrans_ng_send(id, robj, ctx, opcode, omsg, &uvb, 1,
		to_addr, reptrans_ng_send_pack_done_cb, cb_data);
}

/**
 * Receive generic message
 */
int
reptrans_ng_recv(enum rt_proto_id id, struct repwqe *wqe, rtbuf_t** rt_out) {
	struct repmsg_ng* msg = (struct repmsg_ng*) wqe->msg;
	uv_buf_t buf;
	uint512_t hid;

	if (RT_PROTO_ID(msg) != id || RT_PROTO_VER(msg) != reptrans_get_ngproto_version(id))
		return RT_PROTO_VER(msg);

	buf.base = repwqe_payload(wqe);
	buf.len = repwqe_payload_len(wqe);
	rtbuf_t *rt = rtbuf_init_mapped(&buf, 1);
	int err = rtbuf_hash(rt, HASH_TYPE_XXHASH_64, &hid);
	if (err) {
		rtbuf_destroy(rt);
		return err;
	}
	if (hid.u.u.u != msg->hashID) {
		rtbuf_destroy(rt);
		return -EINVAL;
	}
	*rt_out = rt;
	return 0;
}

/**
 * Receive a message sent by reptrans_ng_send_pack() and unpack it.
 *
 * @param cb points to a function that convert message payload (msgpack)
 *			 to a data structure referred by the @param dptr
 */
int
reptrans_ng_recv_unpack(enum rt_proto_id id, struct repwqe *wqe,
	void* dptr, rt_ng_unpack_cb cb) {
	assert(cb);

	rtbuf_t* rtb = NULL;
	int err = reptrans_ng_recv(id, wqe, &rtb);
	if (err)
		return err;

	msgpack_u* u = msgpack_unpack_init(rtb->bufs[0].base, rtb->bufs[0].len, 0);
	if (!u) {
		rtbuf_destroy(rtb);
		return -ENOMEM;
	}
	err = cb(u, dptr);
	msgpack_unpack_free(u);
	rtbuf_destroy(rtb);
	return err;
}

void
reptrans_io_avg(struct repdev* dev) {
	int dev_active = dev->robj->stats.namedget_active +
		dev->robj->stats.unnamedget_active +
		dev->robj->stats.namedput_active +
		dev->robj->stats.unnamedput_active;
	dev->num_ios_avg = avg_ring_update(&dev->io_avg_samples, dev_active);
}

int
reptrans_replicast_delay_internal(struct repdev *dev, uint32_t delay_max,
	const char* file, int line)
{
	uint64_t ts = get_timestamp_us();
	uint32_t incr_delay = 0;
	struct reptrans* rt = dev->rt;
	struct repdev* dev_iter = NULL;
	QUEUE* d;
	int rc = 0;

	if (dev->status == REPDEV_STATUS_UNAVAILABLE ||
		dev->status == REPDEV_STATUS_INIT) {
		rc =  1;
		goto _exit;
	}

	double utilization = reptrans_get_utilization(dev);

	/* Utilization greater then configured high watermark. Do not
	 * throttle BG I/O - let it run and preempt front I/O, always */
	if (utilization >= dev->bg_config->dev_utilization_threshold_high) {
		if (!dev->bg_prioriry_inverted) {
			bg_set_job_prio(dev->bg_sched, BG_SPACE_RECLAIM,
				dev->bg_config->replication_priority);
			bg_set_job_prio(dev->bg_sched, BG_REPLICATION,
				dev->bg_config->space_reclaim_priority);
			bg_set_job_prio(dev->bg_sched, BG_GARBAGE_COLLECTOR,
				dev->bg_config->ec_encoder_priority);
			bg_set_job_prio(dev->bg_sched, BG_EC_ENCODER,
				dev->bg_config->gc_priority);

			dev->bg_prioriry_inverted = 1;
			log_info(lg, "Dev(%s) BG priority INVERTED", dev->name);
			reptrans_perf_set_iops_max(&dev->ngcount_limiter, NGCOUNT_OPS_LIMIT*2);
		}
		rc = 0;
		goto _exit;
	} else if (dev->bg_prioriry_inverted &&
		utilization <= dev->bg_config->dev_utilization_threshold_high - 0.05) {
		bg_set_job_prio(dev->bg_sched, BG_SPACE_RECLAIM,
			dev->bg_config->space_reclaim_priority);
		bg_set_job_prio(dev->bg_sched, BG_REPLICATION,
			dev->bg_config->replication_priority);
		bg_set_job_prio(dev->bg_sched, BG_GARBAGE_COLLECTOR,
			dev->bg_config->gc_priority);
		bg_set_job_prio(dev->bg_sched, BG_EC_ENCODER,
			dev->bg_config->ec_encoder_priority);

		dev->bg_prioriry_inverted = 0;
		log_info(lg, "Dev(%s) BG priority RESTORED", dev->name);
		reptrans_perf_set_iops_max(&dev->ngcount_limiter, NGCOUNT_OPS_LIMIT);
	}

	double k = dev->bg_config->dev_utilization_threshold_high - utilization;
	if (k <= 0.0) {
		rc = 0;
		goto _exit;
	}
	incr_delay = (uint32_t)(100.0 * k) + 1;
	if (dev && !dev->terminating && delay_max && dev->num_ios_avg > 0) {
		uint32_t delay_us = incr_delay * dev->num_ios_avg;
		if (delay_us > delay_max)
			delay_us = delay_max;
		usleep(delay_us);
	}
	/* Calculate a per reptrans IO rate value in order to throttle EC BGs
	 */
	int rt_iorate = 0;
	uv_rwlock_rdlock(&dev->rt->devlock);
	QUEUE_FOREACH(d, &rt->devices) {
		struct repdev *dev;
		dev_iter = QUEUE_DATA(d, struct repdev, item);
		rt_iorate += dev_iter->num_ios_avg;
	}
	uv_rwlock_rdunlock(&rt->devlock);

	for (uint8_t i = 0; i < dev->rt->tc_pool_sz; i++) {
		if (dev->rt->tc_pool[i])
			rt_iorate += dev->rt->tc_pool[i]->io_rate;
	}
	/* Start EC BG throttling when IO rate more than 1 per a VDEV,
	 * Stop EC BGs when average IO rate > 10
	 */
	int iorate_norm = 1000 - 100*rt_iorate/rt->ndevs;
	if (iorate_norm < 0)
		iorate_norm = 0;
	rt->active_ec_bg_limit = EC_BG_MAX*iorate_norm*rt->ndevs/1000;

_exit:
	ts = get_timestamp_us() - ts;
	if (delay_max && ts > delay_max*5L) {
		log_debug(lg, "too long delay: %.3f vs %.3f ms, IO AVG %lu at %s:%d,",
			ts/1000.f, delay_max/1000.f, dev->num_ios_avg, file, line);
	}
	return rc;
}

static int
reptrans_replicast_leave(struct repdev *dev, fhrow_t row, int blocking) {
	struct sockaddr_in6 addr;
	flexhash_get_rowaddr(SERVER_FLEXHASH, row, &addr);
	char dst[INET6_ADDRSTRLEN];
	fhrow_t fhrows = flexhash_numrows(SERVER_FLEXHASH);
	inet_ntop(AF_INET6, &addr.sin6_addr, dst, INET6_ADDRSTRLEN);
	int j =  row / (fhrows >> (ccow_daemon->if_indexes_count - 1));
	if (blocking)
		return replicast_leave(dev->robj, dst, ccow_daemon->if_indexes[j]);
	return reptrans_notify_membership_change(dev, 0, dst, ccow_daemon->if_indexes[j]);
}

static void
reptrans_dev_status_notify(struct repdev *dev)
{
	char vdevstr[64];
	int err=0;

	/* Do not notify until ccow-daemon is fully initialized */
	if (!ccow_daemon || ccow_daemon->startup_err)
		return;

	uint128_dump(&dev->vdevid, vdevstr, 64);

	repdev_status_t vdev_status = reptrans_dev_get_status(dev);
	if (dev->status_changed && vdev_status != dev->prev_status) {
		switch (vdev_status) {
		case REPDEV_STATUS_READONLY_FULL:
		case REPDEV_STATUS_READONLY_DATA:
		case REPDEV_STATUS_READONLY_ROWEVAC:
		case REPDEV_STATUS_READONLY_FORCED:
		case REPDEV_STATUS_READONLY_FAULT:
			SERVER_FLEXHASH_SAFE_CALL(err = vdevstore_mark_ro(SERVER_FLEXHASH->vdevstore,
				&dev->vdevid), FH_LOCK_WRITE);
			if (err < 0) {
				log_warn(lg, "Unable to mark vdev: %s as READ_ONLY", vdevstr);
			} else {
				clengine_notify_vdev_state(&dev->vdevid, VDEV_STATE_READ_ONLY);
				log_notice(lg, "vdev %s marked READ_ONLY and notified to the cluster", vdevstr);
			}
			break;

		case REPDEV_STATUS_ALIVE:
			if (dev->prev_status == REPDEV_STATUS_UNAVAILABLE) {
				/*
				 * When device is returning from unavailable state,
				 * it's absent in FH and there is no point to mark it alive.
				 * At the moment there is absent a grateful way
				 * to attach a dead VDEV. So for now, invoke a
				 * clengine re-initialize procedure
				 */
				uv_async_send(&ccow_daemon->clengine_rebuild_message);
			} else {
				SERVER_FLEXHASH_SAFE_CALL(err = vdevstore_mark_alive(
					SERVER_FLEXHASH->vdevstore, &dev->vdevid), FH_LOCK_WRITE);
				if (err < 0) {
					log_error(lg, "Unable to mark vdev: %s as ALIVE", vdevstr);
				} else {
					clengine_notify_vdev_state(&dev->vdevid, VDEV_STATE_ALIVE);
					log_notice(lg, "vdev %s marked ALIVE and notified to the cluster", vdevstr);
				}
			}
			break;

		case REPDEV_STATUS_UNAVAILABLE:
			{
				log_error(lg, "Dev(%s): vdevid %s became unavailable. "
				    "Marking vdev as DEAD", dev->name, vdevstr);
				clengine_notify_vdev_state(&dev->vdevid, VDEV_STATE_DEAD);

				fhrow_t fhrows = flexhash_numrows(SERVER_FLEXHASH);
				for (size_t i = 0; i < fhrows; i++) {
					int nfound;
					SERVER_FLEXHASH_SAFE_CALL(nfound =
						flexhash_exists(SERVER_FLEXHASH, i, &dev->vdevid), FH_LOCK_READ);
					if (nfound)
						reptrans_replicast_leave(dev, i, 0);
				}
			}

			break;

		default:
			break;
		}
		dev->prev_status = vdev_status;
	}
	/* notify for each disk periodically, telling current status */
	char dst[INET6_ADDRSTRLEN];
	struct server_stat *server = server_get();
	inet_ntop(AF_INET6, &ccow_daemon->msg_origin_sockaddr.sin6_addr,
		dst, INET6_ADDRSTRLEN);

	double notify_status = 2.0;
	if (dev->status == REPDEV_STATUS_UNAVAILABLE)
		notify_status = 0;
	else if (dev->status == REPDEV_STATUS_ALIVE)
		notify_status = 1;

	auditc_servervdev(gauge, "clengine.server", &server->id, &dev->vdevid,
		dst, notify_status);

	if (dev->status_changed)
		dev->status_changed = 0;
}

repdev_status_t
reptrans_dev_set_status(struct repdev *dev, repdev_status_t status) {
	assert(dev);
	int rc = 0;
	repdev_status_t prev = dev->status;
	if (status != prev) {
		/* Unavailable is an immutable state */
		if (prev == REPDEV_STATUS_UNAVAILABLE && status != REPDEV_STATUS_INIT)
			return -EPERM;
		if (prev == REPDEV_STATUS_READONLY_FAULT &&
			status != REPDEV_STATUS_UNAVAILABLE &&
			status != REPDEV_STATUS_READONLY_FORCED)
			return -EPERM;
		if (status != REPDEV_STATUS_UNAVAILABLE &&
		    (prev == REPDEV_STATUS_READONLY_DATA ||
		     prev == REPDEV_STATUS_READONLY_FULL) &&
		    dev->status_changed_expires > get_timestamp_us())
			return -EPERM;
		dev->status_changed_expires = 0;
		dev->status = status;
		if (prev != REPDEV_STATUS_INIT && status != REPDEV_STATUS_INIT) {
			dev->status_changed = 1;
			dev->status_changed_expires = get_timestamp_us() + REPDEV_STATE_EXPIRATION_TIMEOUT_US;
			log_notice(lg, "Dev(%s) status changed %s -> %s", dev->name,
				repdev_status_name[prev],
				repdev_status_name[status]);
			if (!(dev->rt->flags & RT_FLAG_STANDALONE))
				reptrans_dev_status_notify(dev);
		}
		if (!(dev->rt->flags & RT_FLAG_STANDALONE))
			bg_sched_suspend(dev->bg_sched, status == REPDEV_STATUS_UNAVAILABLE);
	}
	return prev;
}

/***
 * Use it carefully only in exceptional situations because it breaks
 * state transition rules.
 */
repdev_status_t
reptrans_dev_override_status(struct repdev *dev, repdev_status_t status) {
	assert(dev);
	int rc = 0;
	repdev_status_t prev = dev->status;
	if (status != prev) {
		dev->status_changed_expires = 0;
		dev->status = status;
		if (prev != REPDEV_STATUS_INIT && status != REPDEV_STATUS_INIT) {
			dev->status_changed = 1;
			dev->status_changed_expires = get_timestamp_us() + REPDEV_STATE_EXPIRATION_TIMEOUT_US;
			log_notice(lg, "Dev(%s) status changed %s -> %s", dev->name,
				repdev_status_name[prev],
				repdev_status_name[status]);
			if (!(dev->rt->flags & RT_FLAG_STANDALONE))
				reptrans_dev_status_notify(dev);
		}
		if (!(dev->rt->flags & RT_FLAG_STANDALONE))
			bg_sched_suspend(dev->bg_sched, status == REPDEV_STATUS_UNAVAILABLE);
	}
	return prev;
}

static void
bg_init_jobs(struct repdev* dev);

static void
reptrans_notify_membership_change__async(struct repdev_call *c);

static void
reptrans_dev__on_call(uv_async_t *handle, int status)
{
	struct repdev *dev = container_of(handle, struct repdev, call_async);
	QUEUE* q;

	do {
		uv_mutex_lock(&dev->call_mutex);
		if (QUEUE_EMPTY(&dev->call_queue)) {
			uv_mutex_unlock(&dev->call_mutex);
			return;
		}
		q = QUEUE_HEAD(&dev->call_queue);
		struct repdev_call *c = QUEUE_DATA(q, struct repdev_call, item);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		uv_mutex_unlock(&dev->call_mutex);

		c->method(c);
		je_free(c);
	} while (1);
}

void
reptrans_dev_ctxfree_one(struct repdev* dev, struct repctx *ctx) {
	struct state *st = ctx->state;
	uint32_t *stat_cnt = ctx->stat_cnt;
	struct repreq_common *req = st->data;
	st->data = NULL;
	assert(req);
	reptrans_lock_unref(dev->robj_lock, stat_cnt);
	reptrans_io_avg(dev);
	repctx_destroy(ctx);
	je_free(req);
}

static void
reptrans_replicast_wait__exec(void *arg) {
	struct repdev* dev = (struct repdev*)arg;
#if 1
	/**
	 * NED-5504
	 * We get here in VDEV termination phase. dev->terminating is set
	 * and no more PUT transactions are allowed.
	 * It's safe to store the bloom filter
	 */
	assert(dev->terminating);
	int err = dev->rt->dev_close(dev);
	if (err) {
		log_error(lg, "repdev %s thread cancel error %d", dev->path,
		    err);
	}

	reptrans_lock_wait_unref(dev->robj_lock);
#else
	uint32_t count;
	while ((count = reptrans_lock_check_unref(dev->robj_lock)) != 0) {
		usleep (100000);
		log_notice(lg,
			"Dev(%s) robj stats: %d %d %d %d %d %d %d %d %d %d %d\n",
			dev->path,
			dev->robj->stats.cacheget_active,
			dev->robj->stats.namedget_active,
			dev->robj->stats.namedput_active,
			dev->robj->stats.ngrequest_active,
			dev->robj->stats.ngrequest_count_active,
			dev->robj->stats.ngrequest_locate_active,
			dev->robj->stats.ngrequest_purge_active,
			dev->robj->stats.ngrequest_purge_active_srv,
			dev->robj->stats.ngrequest_send_active,
			dev->robj->stats.unnamedget_active,
			dev->robj->stats.unnamedput_active);
#if 0
		if (count < 3) {
			QUEUE *q;
			QUEUE_FOREACH(q, &dev->robj->ctxq_recv) {
				struct repctx *ctx = QUEUE_DATA(q, struct repctx,
								item);
				struct state *st = ctx->state;
				log_debug(lg, "%p cur: %d ev_cur: %d ev_prev: %d\n",
					st, st->cur, st->ev_cur, st->ev_prev);
				if (dev->robj->stats.namedput_active) {
					struct putcommon_srv_req *r = st->data;
					log_debug(lg, "inexec: %d\n", r->inexec);
				}
			}
		}
#endif
	}
#endif
}

static void
reptrans_replicast_wait__done(void *arg, int status)
{
	struct repdev* dev = (struct repdev*) arg;
	int err = replicast_destroy(dev->robj);
	if (err) {
		log_warn(lg, "Error while destroying replicast object for "
			"device %s", dev->name);
	}
	uv_rwlock_rdunlock(&dev->term_lock);
}

static void
reptrans_dev__on_exit(uv_async_t *handle, int status)
{
	struct repdev *dev = container_of(handle, struct repdev, exit_handle);
	if (!(dev->rt->flags & RT_FLAG_STANDALONE)) {

		size_t fhrows = flexhash_numrows(SERVER_FLEXHASH);
		/** @warning Potential stack overflow */
		char left_mcgrps[ fhrows * 6 + 1];
		unsigned left_mcgrps_idx = 0;
		*left_mcgrps = 0;

		fhrows = flexhash_numrows(SERVER_FLEXHASH);
		for (size_t i = 0; i < fhrows; i++) {
			int nfound;
			SERVER_FLEXHASH_SAFE_CALL(nfound = flexhash_exists(SERVER_FLEXHASH, i, &dev->vdevid), FH_LOCK_READ);
			if (nfound || reptrans_dev_get_status(dev) == REPDEV_STATUS_UNAVAILABLE) {
				reptrans_replicast_leave(dev, i, 1);
				int j =  i / (fhrows >> (ccow_daemon->if_indexes_count - 1));
				left_mcgrps_idx += snprintf(left_mcgrps + left_mcgrps_idx,
					sizeof(left_mcgrps) - left_mcgrps_idx,
					"%s%d.%d",
					(i == 0 ? "" : ","), (int)i,
					ccow_daemon->if_indexes[j]);
			}
		}

		log_debug(lg, "Replicast object %s left groups [%s]",
		    dev->robj->name, left_mcgrps);
		reptrans_unsubscribe_events(dev);

		replicast_join_cache_cleanup(dev);

		if (!dev->perfmon_wip) {
			if (dev->vdevstats_timer.data) {
				uv_timer_stop(&dev->vdevstats_timer);
				dev->vdevstats_timer.data = NULL;
			}
			uv_close((uv_handle_t *)&dev->vdevstats_timer, NULL);
		}

		if (dev->ts_store_timer.data) {
			uv_timer_stop(&dev->ts_store_timer);
			dev->ts_store_timer.data = NULL;
		}
		uv_close((uv_handle_t *)&dev->ts_store_timer, NULL);

		uv_timer_stop(&dev->ts_store_timer);
		dev->ts_store_timer.data = dev;
		reptrans_sync_timestamp(&dev->ts_store_timer, 1);

		bg_sched_terminate(dev->bg_sched);

		ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_LOW,
			reptrans_replicast_wait__exec,
			reptrans_replicast_wait__done, dev);
	} else
		uv_rwlock_rdunlock(&dev->term_lock);

	/* Free lock structures */
	rt_locks_destroy(dev);
	/* FIXME: cancel outstanding background works */

	uv_close((uv_handle_t *)&dev->call_async, NULL);
	uv_close((uv_handle_t *)handle, NULL);
	uv_mutex_lock(&dev->call_mutex);
	/* Free pending calls if any */
	while (!QUEUE_EMPTY(&dev->call_queue)) {
		QUEUE* q = QUEUE_HEAD(&dev->call_queue);
		struct repdev_call *c = QUEUE_DATA(q, struct repdev_call, item);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		je_free(c);
	};
	reptrans_stable_version_destroy(dev);
	uv_mutex_unlock(&dev->call_mutex);
	uv_sem_destroy(&dev->recover_sem);
}

static void reptrans_dev_async_call__wrapper(struct repdev_call *c)
{
	reptrans_enum_cb_t cb = (reptrans_enum_cb_t)c->args[0];
	struct repdev *dev = (struct repdev *)c->args[1];
	void *arg = c->args[2];
	int status = 0;
	struct reptrans_call *rtc = (struct reptrans_call *)c->done;

	assert(dev != NULL);
	assert(cb != NULL);
	if (cb && dev)
		status = cb(dev, arg);

	if (rtc) {
		/*
		 * Return call data has to be allocated by the caller and
		 * passed in via done
		 */

		QUEUE_INIT(&rtc->item);
		uv_mutex_lock(&dev->rt->call_mutex);
		rtc->status = status;
		QUEUE_INSERT_TAIL(&dev->rt->call_queue, &rtc->item);
		uv_mutex_unlock(&dev->rt->call_mutex);
		uv_async_send(&dev->rt->call_async);
	}
}

void reptrans_done__on_call(uv_async_t *handle, int status)
{
	struct reptrans *rt = container_of(handle, struct reptrans, call_async);
	QUEUE* q;
	struct reptrans_call *c;

	do {
		uv_mutex_lock(&rt->call_mutex);
		if (QUEUE_EMPTY(&rt->call_queue)) {
			uv_mutex_unlock(&rt->call_mutex);
			return;
		}
		q = QUEUE_HEAD(&rt->call_queue);
		c = QUEUE_DATA(q, struct reptrans_call, item);
		if (c->dev && c->dev->terminating) {
			uv_mutex_unlock(&rt->call_mutex);
			return;
		}
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		uv_mutex_unlock(&rt->call_mutex);

		c->method(c->dev, c->arg, c->status);
		je_free(c);
	} while (1);
}

static uint128_t *
reptrans_guid2sid(uint128_t *guid, uint128_t *r)
{
	flexhash_lock(SERVER_FLEXHASH);
	int found = flexhash_serverid_by_key(SERVER_FLEXHASH, guid, r);
	flexhash_unlock(SERVER_FLEXHASH);
	assert(found);
	return r;
}

static void
push_gw_stats(struct reptrans_gw_stats *gw_stats)
{
	char b64_in[4 * REPLICAST_STR_MAXLEN + 4], b_msg[8 * REPLICAST_STR_MAXLEN];

	/*
	 * We send 0 latency if this is not an update. Metric namedput
	 * used here on purpose - see auditservWorker.js
	 */

	snprintf(b64_in, sizeof(b64_in), "%s/%s/%s/%s", gw_stats->cid, gw_stats->tid,
	    gw_stats->bid, gw_stats->oid);

	char *b64_out = NULL;
	b64_out = b64_encode((const unsigned char*)b64_in, strlen(b64_in) + 1);
	if (!b64_out) {
		log_error(lg, "Get(): Invalid b64 encode, -ENOMEM");
		return;
	}

	snprintf(b_msg, sizeof(b_msg), "%s^%s", "namedput.obj_latency_update", b64_out);
	uint128_t rbuf;
	auditc_obj_latency(gauge, b_msg,
	    reptrans_guid2sid(&gw_stats->uvid_src_guid, &rbuf), &gw_stats->svcinfo,
	    gw_stats->avg_put_latency, gw_stats->put_iops, gw_stats->put_bw,
	    gw_stats->avg_get_latency, gw_stats->get_iops, gw_stats->get_bw,
	    gw_stats->uvid_src_cookie);
	je_free(b64_out);
	memset(gw_stats, 0, sizeof(*gw_stats));
}

static void
push_stats(struct repdev *dev)
{
	uint128_t *nodeserverid;

	if (dev->terminating)
		return;

	struct reptrans_devinfo_req *stat = &dev->stats;

	uv_mutex_lock(&stat->stat_mutex);
	if (stat->writes > stat->writes_snap) {
		stat->write_bw = (stat->bytes_out - stat->bytes_out_snap) / 5ULL;
		stat->write_iops = (stat->writes - stat->writes_snap) / 5ULL;
		stat->writes_snap = stat->writes;
		stat->bytes_out_snap = stat->bytes_out;
	} else {
		stat->write_bw = 0;
		stat->write_iops = 0;
	}
	if (stat->reads > stat->reads_snap) {
		stat->read_bw = (stat->bytes_in - stat->bytes_in_snap) / 5ULL;
		stat->read_iops = (stat->reads - stat->reads_snap) / 5ULL;
		stat->reads_snap = stat->reads;
		stat->bytes_in_snap = stat->bytes_in;
	} else {
		stat->read_bw = 0;
		stat->read_iops = 0;
	}
	uv_mutex_unlock(&stat->stat_mutex);

	uv_mutex_lock(&stat->gw_stat_mutex);
	if (stat->gw_stats_put_bw.put_bw)
		push_gw_stats(&stat->gw_stats_put_bw);
	if (stat->gw_stats_get_bw.get_bw)
		push_gw_stats(&stat->gw_stats_get_bw);
	if (stat->gw_stats_put_iops.put_iops)
		push_gw_stats(&stat->gw_stats_put_iops);
	if (stat->gw_stats_get_iops.get_iops)
		push_gw_stats(&stat->gw_stats_get_iops);
	if (stat->gw_stats_put_lat.avg_put_latency)
		push_gw_stats(&stat->gw_stats_put_lat);
	if (stat->gw_stats_get_lat.avg_get_latency)
		push_gw_stats(&stat->gw_stats_get_lat);
	uv_mutex_unlock(&stat->gw_stat_mutex);

	reptrans_lock_ref(dev->robj_lock, NULL);

	auditc_low_objid(gauge, "reptrans.write_bw", &dev->vdevid, stat->write_bw);
	auditc_low_objid(gauge, "reptrans.read_bw", &dev->vdevid, stat->read_bw);
	auditc_low_objid(gauge, "reptrans.write_iops", &dev->vdevid, stat->write_iops);
	auditc_low_objid(gauge, "reptrans.read_iops", &dev->vdevid, stat->read_iops);


	repdev_status_t status = reptrans_dev_get_status(dev);
	if (unlikely(status == REPDEV_STATUS_READONLY_FULL ||
		status == REPDEV_STATUS_READONLY_DATA) &&
	    (reptrans_get_utilization(dev) <
		dev->bg_config->dev_capacity_limit)) {
		// reset the READ-ONLY
		reptrans_dev_set_status(dev, REPDEV_STATUS_ALIVE);
	}

	if (dev->journal) {
		auditc_low_objid_str(gauge, "reptrans.journal", &dev->vdevid,
		    dev->journal, 0);
	}
	auditc_low_objid_str(gauge, "reptrans.devname", &dev->vdevid,
	    dev->name, stat->nominal_latency > 1 ? 0 : 1);
	auditc_low_objid(gauge, "reptrans.put_latency", &dev->vdevid,
	    MAX(stat->put4k_latency, stat->put4k_latency_j));
	auditc_low_objid(gauge, "reptrans.get_latency", &dev->vdevid,
	    stat->get4k_latency);
	auditc_low_objid(gauge, "reptrans.delete_latency", &dev->vdevid,
	    stat->delete_latency);
	auditc_low_objid(gauge, "reptrans.capacity", &dev->vdevid,
	    atomic_get_uint64(&stat->capacity));
	auditc_low_objid(gauge, "reptrans.used", &dev->vdevid,
	    stat->used);
	auditc_low_objid(gauge, "reptrans.num_objects", &dev->vdevid,
	    stat->num_objects);
	auditc_low_objid(gauge, "reptrans.nominal_latency", &dev->vdevid,
	    stat->nominal_latency);

	auditc_low_objid(gauge, "reptrans.verify_delay_avg", &dev->vdevid,
			dev->verify_delay_avg);
	auditc_low_objid(gauge, "reptrans.incoming_batch_delay_avg", &dev->vdevid,
			dev->incoming_batch_delay_avg);
	auditc_low_objid(gauge, "reptrans.ngcount_delay_avg", &dev->vdevid,
			dev->ngcount_delay_avg);
	auditc_low_objid(gauge, "reptrans.ngcount_delay", &dev->vdevid,
			dev->ngcount_delay);
	auditc_low_objid(gauge, "reptrans.get_disk_qdepth", &dev->vdevid,
			dev->get_disk_qdepth);
	auditc_low_objid(gauge, "reptrans.put_disk_qdepth", &dev->vdevid,
			dev->put_disk_qdepth);
	auditc_low_objid(gauge, "reptrans.get_net_tx", &dev->vdevid,
			dev->get_net_tx);
	auditc_low_objid(gauge, "reptrans.put_net_rx", &dev->vdevid,
			dev->put_net_rx);
	auditc_low_objid(gauge, "reptrans.total", &dev->vdevid,
			dev->robj->rvbuf.total);
	auditc_low_objid(gauge, "reptrans.queued", &dev->vdevid,
			dev->robj->rvbuf.queued);
	auditc_low_objid(gauge, "reptrans.reserved", &dev->vdevid,
			dev->robj->rvbuf.reserved);
	auditc_low_objid(gauge, "reptrans.namedget_active", &dev->vdevid,
			dev->robj->stats.namedget_active);
	auditc_low_objid(gauge, "reptrans.namedput_active", &dev->vdevid,
			dev->robj->stats.namedput_active);
	auditc_low_objid(gauge, "reptrans.unnamedget_active", &dev->vdevid,
			dev->robj->stats.unnamedget_active);
	auditc_low_objid(gauge, "reptrans.unnamedput_active", &dev->vdevid,
			dev->robj->stats.unnamedput_active);
	auditc_low_objid(gauge, "reptrans.rep_queued", &dev->vdevid,
			stat->ttag_entries[TT_REPLICATION_QUEUE]);
	auditc_low_objid(gauge, "reptrans.ver_queued", &dev->vdevid,
			stat->ttag_entries[TT_VERIFICATION_QUEUE]);

	auditc_low_objid(gauge, "reptrans.batch_entries_queued", &dev->vdevid,
			stat->ttag_entries[TT_BATCH_QUEUE]);
	auditc_low_objid(gauge, "reptrans.incoming_batches_queued", &dev->vdevid,
			stat->ttag_entries[TT_BATCH_INCOMING_QUEUE]);

	ccowd_fhready_lock(FH_LOCK_READ);
	auditc_low_rowusage(gauge, "reptrans.rowusagecounters", &dev->vdevid,
		ccow_daemon->flexhash->numrows, ccow_daemon->flexhash);
	ccowd_fhready_unlock(FH_LOCK_READ);

	size_t n_persitent_md = stat->ttag_entries[TT_CHUNK_MANIFEST] +
			stat->ttag_entries[TT_VERSION_MANIFEST] +
			stat->ttag_entries[TT_PARITY_MANIFEST] +
			stat->ttag_entries[TT_VERIFIED_BACKREF];
	size_t n_persitent_md_size = stat->ttag_size[TT_CHUNK_MANIFEST] +
			stat->ttag_size[TT_VERSION_MANIFEST] +
			stat->ttag_size[TT_PARITY_MANIFEST] +
			stat->ttag_size[TT_VERIFIED_BACKREF];
	size_t temp_md_size = 0;
	size_t n_temp_md = 0;
	size_t n_offload_md = 0;
	size_t offload_md_size = 0;
	for (int tt = TT_NAMEINDEX; tt < TT_LAST; tt++) {
		int md_offload = dev->journal && is_mdoffload_tt(dev, tt);
		if (is_tempmd_tt(tt)) {
			n_temp_md += stat->ttag_entries[tt];
			temp_md_size += stat->ttag_size[tt];
		}
		if (md_offload) {
			n_offload_md += stat->ttag_entries[tt];
			offload_md_size += stat->ttag_size[tt];
		}
	}
	auditc_low_objid(gauge, "reptrans.persistent_md_entries", &dev->vdevid,
		n_persitent_md);
	auditc_low_objid(gauge, "reptrans.persistent_md_size", &dev->vdevid,
		n_persitent_md_size);
	auditc_low_objid(gauge, "reptrans.temporary_md_entries", &dev->vdevid,
		n_temp_md);
	auditc_low_objid(gauge, "reptrans.temporary_md_size", &dev->vdevid,
		temp_md_size);
	auditc_low_objid(gauge, "reptrans.mdoffload_entries", &dev->vdevid,
		n_offload_md);
	auditc_low_objid(gauge, "reptrans.mdoffload_size", &dev->vdevid,
		offload_md_size + stat->mdcache.keydb_used);
	auditc_low_objid(gauge, "reptrans.mdoffload_total", &dev->vdevid,
		stat->mdcache.total - stat->mdcache.mdcache_used);
	auditc_low_objid(gauge, "reptrans.mdcache_size", &dev->vdevid,
		stat->mdcache.mdcache_used);
	auditc_low_objid(gauge, "reptrans.mdcache_entries", &dev->vdevid,
		stat->mdcache.mdcache_entries);
	auditc_low_objid(gauge, "reptrans.mdcache_hit", &dev->vdevid,
		stat->mdcache.hit);
	auditc_low_objid(gauge, "reptrans.mdcache_miss", &dev->vdevid,
		stat->mdcache.miss);
	auditc_low_objid(gauge, "reptrans.mdcache_evicted", &dev->vdevid,
		stat->mdcache.evicted);
	auditc_low_objid(gauge, "reptrans.payload_entries", &dev->vdevid,
		stat->ttag_entries[TT_CHUNK_PAYLOAD]);
	auditc_low_objid(gauge, "reptrans.payload_size", &dev->vdevid,
		stat->ttag_size[TT_CHUNK_PAYLOAD]);

	auditc_low_objid(gauge, "reptrans.cm_entries", &dev->vdevid,
		stat->ttag_entries[TT_CHUNK_MANIFEST]);
	auditc_low_objid(gauge, "reptrans.cm_size", &dev->vdevid,
		stat->ttag_size[TT_CHUNK_MANIFEST]);

	auditc_low_objid(gauge, "reptrans.vm_entries", &dev->vdevid,
		stat->ttag_entries[TT_VERSION_MANIFEST]);
	auditc_low_objid(gauge, "reptrans.vm_size", &dev->vdevid,
		stat->ttag_size[TT_VERSION_MANIFEST]);

	auditc_low_objid(gauge, "reptrans.vbr_entries", &dev->vdevid,
		stat->ttag_entries[TT_VERIFIED_BACKREF]);
	auditc_low_objid(gauge, "reptrans.vbr_size", &dev->vdevid,
		stat->ttag_size[TT_VERIFIED_BACKREF]);


	auditc_low_objid(gauge, "reptrans.num_retransmit", &dev->vdevid,
			stat->num_retransmit);

	/* S.M.A.R.T stats */
	auditc_low_objid(gauge, "reptrans.smart_health_status", &dev->vdevid,
	    stat->smart.smart_status);
	auditc_low_objid(gauge, "reptrans.smart_temperature_current", &dev->vdevid,
	    stat->smart.temperature_current);
	auditc_low_objid(gauge, "reptrans.smart_non_medium_error_count", &dev->vdevid,
	    stat->smart.non_medium_error_count);
	auditc_low_objid(gauge, "reptrans.smart_percentage_used_endurance_indicator", &dev->vdevid,
	    stat->smart.percentage_used_endurance_indicator);
	auditc_low_objid(gauge, "reptrans.smart_total_uncorrected_read_errors", &dev->vdevid,
	    stat->smart.total_uncorrected_read_errors);
	auditc_low_objid(gauge, "reptrans.smart_total_uncorrected_write_errors", &dev->vdevid,
	    stat->smart.total_uncorrected_write_errors);
	auditc_low_objid(gauge, "reptrans.smart_current_pending_sector", &dev->vdevid,
	    stat->smart.current_pending_sector);
	auditc_low_objid(gauge, "reptrans.smart_ecc_uncorr_error_count", &dev->vdevid,
	    stat->smart.ecc_uncorr_error_count);
	auditc_low_objid(gauge, "reptrans.smart_end_to_end_error", &dev->vdevid,
	    stat->smart.end_to_end_error);
	auditc_low_objid(gauge, "reptrans.smart_offline_uncorrectable", &dev->vdevid,
	    stat->smart.offline_uncorrectable);
	auditc_low_objid(gauge, "reptrans.smart_reallocated_event_count", &dev->vdevid,
	    stat->smart.reallocated_event_count);
	auditc_low_objid(gauge, "reptrans.smart_reallocated_sector_ct", &dev->vdevid,
	    stat->smart.reallocated_sector_ct);
	auditc_low_objid(gauge, "reptrans.smart_reported_uncorrect", &dev->vdevid,
	    stat->smart.reported_uncorrect);
	auditc_low_objid(gauge, "reptrans.smart_soft_read_error_rate", &dev->vdevid,
	    stat->smart.soft_read_error_rate);
	auditc_low_objid(gauge, "reptrans.smart_spin_retry_count", &dev->vdevid,
	    stat->smart.spin_retry_count);
	auditc_low_objid(gauge, "reptrans.smart_total_pending_sectors", &dev->vdevid,
	    stat->smart.total_pending_sectors);
	auditc_low_objid(gauge, "reptrans.smart_total_pending_sectors", &dev->vdevid,
	    stat->smart.total_pending_sectors);
	auditc_low_objid(gauge, "reptrans.smart_unc_soft_read_err_rate", &dev->vdevid,
	    stat->smart.unc_soft_read_err_rate);
	auditc_low_objid(gauge, "reptrans.smart_raw_read_error_rate", &dev->vdevid,
	    stat->smart.raw_read_error_rate);

	/* iostat */
	auditc_low_objid(gauge, "reptrans.iostat_r_merges", &dev->vdevid,
	    stat->iostat.r_merges);
	auditc_low_objid(gauge, "reptrans.iostat_w_merges", &dev->vdevid,
	    stat->iostat.w_merges);
	auditc_low_objid(gauge, "reptrans.iostat_r_ios", &dev->vdevid,
	    stat->iostat.r_ios);
	auditc_low_objid(gauge, "reptrans.iostat_w_ios", &dev->vdevid,
	    stat->iostat.w_ios);
	auditc_low_objid(gauge, "reptrans.iostat_r_sectors", &dev->vdevid,
	    stat->iostat.r_sectors);
	auditc_low_objid(gauge, "reptrans.iostat_w_sectors", &dev->vdevid,
	    stat->iostat.w_sectors);
	auditc_low_objid(gauge, "reptrans.iostat_busy", &dev->vdevid,
	    stat->iostat.busy);
	auditc_low_objid(gauge, "reptrans.iostat_svc_t_us", &dev->vdevid,
	    stat->iostat.svc_t_us);
	auditc_low_objid(gauge, "reptrans.iostat_wait_us", &dev->vdevid,
	    stat->iostat.wait_us);
	auditc_low_objid(gauge, "reptrans.iostat_size_kb", &dev->vdevid,
	    stat->iostat.size_kb);
	auditc_low_objid(gauge, "reptrans.iostat_queue", &dev->vdevid,
	    stat->iostat.queue);

	/* BG job progress. Only few of them have real progress handler.
	 * If a BG job ins't started, its progress value is -1
	 * If a BG job is in progress, but here is no progress handler,
	 * then a progress value is fixed to 1000.
	 * If a BG job has a handler, then it returns a BG job completion ratio
	 * in range 0..100% multiplied by 10.
	 */
	auditc_low_objid(gauge, "reptrans.bg_incoming", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_INCOMING_BATCH));

	auditc_low_objid(gauge, "reptrans.bg_verify", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_VERIFICATION));

	auditc_low_objid(gauge, "reptrans.bg_replication", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_REPLICATION));

	auditc_low_objid(gauge, "reptrans.bg_ecenoder", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_EC_ENCODER));

	auditc_low_objid(gauge, "reptrans.bg_trlog", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_TRANSACTION_LOGGER));

	auditc_low_objid(gauge, "reptrans.bg_rowusage", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_ROWUSAGE));

	auditc_low_objid(gauge, "reptrans.bg_gwcache", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_GW_CACHE));

	auditc_low_objid(gauge, "reptrans.bg_gc", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_GARBAGE_COLLECTOR));

	auditc_low_objid(gauge, "reptrans.bg_space_reclaim", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_SPACE_RECLAIM));

	auditc_low_objid(gauge, "reptrans.bg_scrub", &dev->vdevid,
		bg_get_job_progress(dev->bg_sched, BG_SCRUB));

	rowevac_auditc_notify(dev);

	/* there are internal stats */
	/* TODO: needs a view so this is displayed only under certain conditions */
	auditc_low_objid(gauge, "reptrans.put_num_nameindex", &dev->vdevid,
			dev->stat_blob_put[TT_NAMEINDEX]);
	auditc_low_objid(gauge, "reptrans.get_num_nameindex", &dev->vdevid,
			dev->stat_blob_get[TT_NAMEINDEX]);

	auditc_low_objid(gauge, "reptrans.put_num_payloads", &dev->vdevid,
			dev->stat_blob_put[TT_CHUNK_PAYLOAD]);
	auditc_low_objid(gauge, "reptrans.get_get_payloads", &dev->vdevid,
			dev->stat_blob_get[TT_CHUNK_PAYLOAD]);

	auditc_low_objid(gauge, "reptrans.put_num_vmanifests", &dev->vdevid,
			dev->stat_blob_put[TT_VERSION_MANIFEST]);
	auditc_low_objid(gauge, "reptrans.get_num_vmanifests", &dev->vdevid,
			dev->stat_blob_get[TT_VERSION_MANIFEST]);

	auditc_low_objid(gauge, "reptrans.put_num_cmanifests", &dev->vdevid,
			dev->stat_blob_put[TT_CHUNK_MANIFEST]);
	auditc_low_objid(gauge, "reptrans.get_num_cmanifests", &dev->vdevid,
			dev->stat_blob_get[TT_CHUNK_MANIFEST]);

	auditc_low_objid(gauge, "reptrans.put_num_pmanifests", &dev->vdevid,
			dev->stat_blob_put[TT_PARITY_MANIFEST]);
	auditc_low_objid(gauge, "reptrans.get_num_pmanifests", &dev->vdevid,
			dev->stat_blob_get[TT_PARITY_MANIFEST]);

	reptrans_lock_unref(dev->robj_lock, NULL);
}

static int stat_refresh(struct repdev *dev, void *arg)
{
	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl)
		return -EPERM;

	if (dev->__vtbl->stat_refresh)
	    return dev->__vtbl->stat_refresh(dev);
	return -1;
}

typedef struct stat_update_work {
	struct repdev *dev;
} stat_update_work_t;

static void
stat_update__exec(void *arg)
{
	int err;
	assert(arg != NULL);

	stat_update_work_t *suw = arg;
	struct repdev* dev = suw->dev;
	assert(suw != NULL);
	assert(suw->dev != NULL);

	repdev_status_t status = reptrans_dev_get_status(suw->dev);
	if(suw->dev->terminating)
		return;
	if (status == REPDEV_STATUS_UNAVAILABLE) {
		char dst[INET6_ADDRSTRLEN];
		struct server_stat *server = server_get();
		inet_ntop(AF_INET6, &ccow_daemon->msg_origin_sockaddr.sin6_addr,
			dst, INET6_ADDRSTRLEN);
		auditc_servervdev(gauge, "clengine.server",
			&server->id, &suw->dev->vdevid, dst, 0.0);
		auditc_low_objid_str(gauge, "reptrans.devname", &dev->vdevid,
			dev->name, 0);
		return;
	}

	err = stat_refresh(suw->dev, NULL);
	if (err) {
		if (err != -ENODEV)
			log_error(lg, "Error doing a stat on vdev: %s",
				suw->dev->name);
	} else
		push_stats(suw->dev);
}

static void
stat_update__done(void *arg, int status)
{
	assert(arg != NULL);

	stat_update_work_t *suw = arg;
	assert(suw != NULL);
	struct repdev *dev = suw->dev;
	assert(suw->dev != NULL);

	if (suw->dev->terminating) {
		if (dev->vdevstats_timer.data) {
			uv_timer_stop(&dev->vdevstats_timer);
			dev->vdevstats_timer.data = NULL;
		}
		uv_close((uv_handle_t *)&dev->vdevstats_timer, NULL);
		je_free(suw);
		return;
	}
	dev->perfmon_wip = 0;

	if (!g_ceng) {
		je_free(suw);
		return;
	}

	char vdevstr[64];
	uint128_dump(&dev->vdevid, vdevstr, 64);

	ccowd_fhready_lock(FH_LOCK_WRITE);
	flexhash_update_vdev_physical_used(SERVER_FLEXHASH, &dev->vdevid,
	    dev->stats.used);
	ccowd_fhready_unlock(FH_LOCK_WRITE);

	log_info(lg, "Dev(%s): Used: %lu  Cap: %lu PhyCap: %lu Util: %.2f%%",
	    dev->name, dev->stats.used,
	    dev->stats.capacity, dev->stats.physical_capacity,
	    100.0 * reptrans_get_utilization(dev));

	reptrans_dev_status_notify(dev);

	ccowd_fhready_lock(FH_LOCK_READ);
	uint64_t p_weight = flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
				dev, FH_IOTYPE_PUT);
	uint64_t g_weight = flexhash_estimate_vdev_weight(SERVER_FLEXHASH,
				dev, FH_IOTYPE_GET);
	ccowd_fhready_unlock(FH_LOCK_READ);
	struct ccowtp_stat tpstat = {0};
	ccowtp_stat(dev->tp, &tpstat);

	log_info(lg, "TPStat(%s): HI  util curr/max (abs): %lu%%/%lu%% (%lu/%lu),"
		" pend %lu, latency(avg/max): %lu/%lu:%lu/%lu uS",
		dev->name, tpstat.busy_ratio[REPTRANS_TP_PRIO_HI],
		tpstat.busy_max_ratio[REPTRANS_TP_PRIO_HI],
		tpstat.busy[REPTRANS_TP_PRIO_HI],
		tpstat.busy_max[REPTRANS_TP_PRIO_HI],
		tpstat.pending[REPTRANS_TP_PRIO_HI],
		tpstat.full_latency_avg, tpstat.full_latency_max,
		tpstat.prop_latency_avg, tpstat.prop_latency_max);

	log_info(lg, "TPStat(%s): MID util curr/max (abs): %lu%%/%lu%% (%lu/%lu),"
		" pend %lu, latency(avg/max): %lu/%lu:%lu/%lu uS",
		dev->name, tpstat.busy_ratio[REPTRANS_TP_PRIO_MID],
		tpstat.busy_max_ratio[REPTRANS_TP_PRIO_MID],
		tpstat.busy[REPTRANS_TP_PRIO_MID],
		tpstat.busy_max[REPTRANS_TP_PRIO_MID],
		tpstat.pending[REPTRANS_TP_PRIO_MID],
		tpstat.full_latency_avg, tpstat.full_latency_max,
		tpstat.prop_latency_avg, tpstat.prop_latency_max);

	log_info(lg, "TPStat(%s): LOW util curr/max (abs): %lu%%/%lu%% (%lu/%lu),"
		" pend %lu, latency(avg/max): %lu/%lu:%lu/%lu uS",
		dev->name, tpstat.busy_ratio[REPTRANS_TP_PRIO_LOW],
		tpstat.busy_max_ratio[REPTRANS_TP_PRIO_LOW],
		tpstat.busy[REPTRANS_TP_PRIO_LOW],
		tpstat.busy_max[REPTRANS_TP_PRIO_LOW],
		tpstat.pending[REPTRANS_TP_PRIO_LOW],
		tpstat.full_latency_avg, tpstat.full_latency_max,
		tpstat.prop_latency_avg, tpstat.prop_latency_max);

	log_info(lg, "Stat(%s): status=%s put4k=%ld putj4k=%ld "
	    "put90th_4k=%ld putj90th_4k=%ld put64k=%ld putj64k=%ld "
	    "put90th_64k=%ld putj90th_64k=%ld put512k=%ld putj512k=%ld "
	    "put90th_512k=%ld putj90th_512k=%ld get4k=%ld getm4k=%ld "
	    "get64k=%ld getm64k=%ld get512k=%ld getm512k=%ld "
	    "p_weight=%ld g_weight=%ld acth=%d rsvb=%ld keycache=%u:%u:%u "
	    "mdcache=%u:%u:%u:%lu:%lu wbw=%lu wiops=%lu rbw=%lu riops=%lu ",
	    dev->name, repdev_status_name[dev->status],
	    dev->stats.put4k_latency, dev->stats.put4k_latency_j,
	    dev->stats.put90th_4k_latency, dev->stats.put90th_4k_latency_j,
	    dev->stats.put64k_latency, dev->stats.put64k_latency_j,
	    dev->stats.put90th_64k_latency, dev->stats.put90th_64k_latency_j,
	    dev->stats.put512k_latency, dev->stats.put512k_latency_j,
	    dev->stats.put90th_512k_latency, dev->stats.put90th_512k_latency_j,
	    dev->stats.get4k_latency, dev->stats.get4k_latency_m,
	    dev->stats.get64k_latency, dev->stats.get64k_latency_m,
	    dev->stats.get512k_latency, dev->stats.get512k_latency_m, p_weight, g_weight,
	    dev->loop->active_handles, replicast_get_reserved_vbuf(&dev->robj->rvbuf),
	    dev->stats.keycache.hit, dev->stats.keycache.miss, dev->stats.keycache.evicted,
	    dev->stats.mdcache.hit, dev->stats.mdcache.miss, dev->stats.mdcache.evicted,
	    dev->stats.mdcache.mdcache_used + dev->stats.mdcache.mdoffload_used + dev->stats.mdcache.keydb_used,
	    dev->stats.mdcache.total, dev->stats.write_bw, dev->stats.write_iops,
	    dev->stats.read_bw, dev->stats.read_iops);

	int high_lat = (dev->get4k_avg_samples.mean_uncap >
	    (dev->stats.nominal_latency * DEV_DEAD_THRESHOLD_FACTOR)) ? 1 : 0;

	/* Marking device as DEAD if threshold reached */
	repdev_status_t vdev_status = reptrans_dev_get_status(dev);
	if (high_lat && vdev_status != REPDEV_STATUS_UNAVAILABLE) {
		log_notice(lg, "Dev(%s): vdevid %s avg get4k_latency %luus is %d "
		    "times higher then nominal %lu",
		    dev->name, vdevstr, dev->get4k_avg_samples.mean_uncap,
		    DEV_DEAD_THRESHOLD_FACTOR, dev->stats.nominal_latency);
	}
	if (vdev_status != REPDEV_STATUS_UNAVAILABLE) {
		log_debug(lg, "Dev(%s): vdevid %s avg get_latency %ldus vs "
		    "nominal %ldus", dev->name, vdevstr, dev->stats.get4k_latency,
		    dev->stats.nominal_latency);
		log_debug(lg, "Dev(%s): Updating hb", dev->name);
		unsigned long oldhb;
		do {
			oldhb = dev->hb;
		} while (!__sync_bool_compare_and_swap(&dev->hb, oldhb, 0));
	}

	uv_mutex_lock(&dev->stats.stat_mutex);
	if (vdev_status != REPDEV_STATUS_UNAVAILABLE &&
	    ((dev->read_inprog && dev->read_last + DEV_READ_LAST_FAIL_MAX_NS < uv_hrtime()))) {
		char* survive = getenv("NEDGE_SURVIVE");
		if (!survive) {
			uv_mutex_unlock(&dev->stats.stat_mutex);
			log_error(lg, "Dev(%s): critical failure due to lack of system resources. "
			    "Marking as unavailable", dev->name);
			reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
		} else
			log_notice(lg, "Dev(%s) resource starvation: GET delay %lu mS, PUT delay %lu mS",
				dev->name, dev->read_last/1000000L, dev->write_last/1000000L);
	}
	uv_mutex_unlock(&dev->stats.stat_mutex);

	je_free(suw);
}

static void
dev_perfmon(uv_timer_t *req, int status)
{
	struct repdev *dev = req->data;
	if (dev->terminating)
		return;

	reptrans_process_touch_queue(dev);

	struct stat_update_work *suw = je_malloc(sizeof(stat_update_work_t));
	if (suw == NULL) {
		log_error(lg, "Error doing a stat on vdev: %s",
			dev->name);
		return;
	}
	suw->dev = dev;
	if (!dev->perfmon_wip) {
		dev->perfmon_wip = 1;
		ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, stat_update__exec,
			stat_update__done, suw);
	} else {
		je_free(suw);
	}
}

static int
bg_verify_init(struct bg_job_entry* job, void** pdata) {
	static const char* str[] = {
			"BATCHES_SENT", "BYTES_SENT", "BATCH_QUEUE_ADDED",
			"VERIFY_DELAY_US", "VBRS_VERIFIED"
	};
	struct repdev *dev = job->sched->dev;
	verify_work_t *work = je_calloc(1, sizeof(verify_work_t));
	assert(work != NULL);
	work->dev = dev;
	work->job = job;
	*pdata = work;
	bg_sched_register_counters(job, 5, str);
	return 0;
}

static void
bg_verify_work(struct bg_job_entry* job, void* data)
{
	assert(data != NULL);

	verify_work_t *work = (verify_work_t*) data;
	assert(work != NULL);
	assert(ccow_daemon != NULL);
	verify_state_t* vs = job->state;

	if (!flexhash_is_pristine(SERVER_FLEXHASH) ||
		(ccowd_get_fddelta() && vs->rep_count_min &&
			ccowd_get_fddelta() + vs->rep_count_min <= 0))
		return;

	reptrans_set_thrname(job->sched->dev, "bgver");

	int err = reptrans_verify_queue(work);
	if (err && err != -ENODEV) {
		log_error(lg, "Error in reptrans_verify_queue: %d", err);
	}
	job->sched->dev->bq_cleaned = 1;
}


static void
bg_verify_done(struct bg_job_entry* job, void* data)
{
	assert(data != NULL);
	verify_work_t *work = (verify_work_t*) data;
	assert(work != NULL);
	assert(work->dev != NULL);

	job->chunk_counter = work->verify_queue_items;

	bg_sched_set_counter(job, work->batches_sent, 0);

	bg_sched_set_counter(job, work->bytes_sent, 1);

	bg_sched_set_counter(job, work->verify_entries, 2);

	bg_sched_set_counter(job, work->dev->verify_delay_avg, 3);

	bg_sched_set_counter(job, work->n_verified, 4);

	je_free(work);
}

static int
bg_incoming_batch_init(struct bg_job_entry* job, void** pdata) {
	static const char* str[] = {
			"REFS_VERIFIED", "REQUESTS_QUEUED",
			"BATCHES_PROCESSED", "INCOMING_BATCH_DELAY_AVG", "REFS_SKIPPED"
	};
	struct repdev *dev = job->sched->dev;
	incoming_batch_work_t *work = je_calloc(1, sizeof(incoming_batch_work_t));
	assert(work != NULL);
	work->dev = dev;
	*pdata = work;
	bg_sched_register_counters(job, 5, str);
	return 0;
}

int reptrans_process_batches(incoming_batch_work_t *work);
static void
bg_incoming_batch_work(struct bg_job_entry* job, void* data)
{
	assert(data != NULL);

	incoming_batch_work_t *work = (incoming_batch_work_t*) data;
	assert(work != NULL);
	assert(ccow_daemon != NULL);

	reptrans_set_thrname(job->sched->dev, "bgiqu");

	work->job = job;
	int err = reptrans_process_batches(work);
	if (err && err != -ENODEV && err != -EAGAIN && err != -EACCES) {
		log_error(lg, "Error in reptrans_process_batches: %d", err);
	}
}


static void
bg_incoming_batch_done(struct bg_job_entry* job, void* data)
{
	assert(data != NULL);
	incoming_batch_work_t *work = (incoming_batch_work_t *) data;
	assert(work != NULL);
	assert(work->dev != NULL);

	job->chunk_counter = work->n_refs;

	bg_sched_set_counter(job, work->n_verified, 0);

	bg_sched_set_counter(job, work->n_queued, 1);

	bg_sched_set_counter(job, work->n_batches, 2);

	bg_sched_set_counter(job, work->dev->incoming_batch_delay_avg, 3);

	bg_sched_set_counter(job, work->n_skipped, 4);

	je_free(work);
}

static void
fill_vlentry(struct vlentry *vle, struct vmmetadata *md, uint512_t *vmchid, uint32_t vm_packed_length)
{
	vle->uvid_timestamp = md->uvid_timestamp;
	vle->uvid_src_guid = md->uvid_src_guid;
	vle->uvid_src_cookie = md->uvid_src_cookie;
	vle->generation = md->txid_generation;
	vle->content_hash_id = *vmchid;
	vle->object_deleted = md->object_deleted;
	vle->logical_size = md->logical_size;
	vle->vm_packed_length = vm_packed_length;
}


/* TODO: Refactor all timer-activated activities to use one set of API's */
static int
dev_space_reclaim_callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param)
{
	space_reclaim_work_t *work = (space_reclaim_work_t*)param;
	struct bg_job_entry* job = work->job;

	if (bg_job_wait_resume(job, 30000))
		return -EINVAL;

	job->chunk_counter++;

	assert(is_data_type_tag(ttag));
	char keybuf[UINT512_BYTES * 2 + 1];
	uint512_dump(key, keybuf, UINT512_BYTES * 2 + 1);

	int rep_count = reptrans_get_chunk_rep_count(dev, hash_type, key);
	if (rep_count < 0) {
		/* something wrong with LFS db */
		log_error(lg,
			"Space Reclaim(%s, %s): get repcount failed %d %s",
			dev->path, keybuf, rep_count, strerror(-rep_count));
		return 0;
	}
	if (rep_count == 1) {
		/* This is the only instance of this chunk, do nothing */
		log_debug(lg,
			"Space Reclaim(%s, %s): unique chunk, moving on",
			dev->path, keybuf);
			return 0;
	}

	manifest_lock_status_t rst;
	struct manifest_lock_entry* re = NULL;
	if (ttag != TT_CHUNK_PAYLOAD) {
		/* Lock the manifest*/
		do {
			re = reptrans_manifest_lock_or_wait(dev, key, &rst);
		} while (!re);
	}
	int err = 0;
	/* self healing */
	if (rep_count > 0) {
		uint512_t nhid = uint512_null;
		/* We have a backref, let's keep the chunk */
		/* Handle non-orphans:
		 *	- get actual replication count (ARC) from NG
		 *	- if ARC < rep_count, then
		 *		start replication (unnamed put)
		 *	- if ARC > rep_count and dev is eligible, then
		 *		reclaim space (delete backrefs and the blob)
		 */
		if (ttag == TT_VERSION_MANIFEST) {
			/*
			 * NHID has to be fetched from manifest, since VBR
			 * may not have it if the VM is referenced
			 * by a CM (snapshot)
			 */
			err = reptrans_get_vm_nhid(dev, key, &nhid);
			if (err) {
				log_error(lg, "Metadata unpack error: %d", err);
				if (re)
					reptrans_manifest_unlock(dev, re, SPACE_RECLAIM_DONE);
				return err;
			}
		}
		err = dev_rep_count_verify_one(work, ttag, hash_type, key, val,
			&nhid, rep_count);
		if (re)
			reptrans_manifest_unlock(dev, re, SPACE_RECLAIM_DONE);
		if (err == -EXDEV) {
			reptrans_replicate_one(dev, ttag, hash_type, key, &nhid,
				rep_count);
			work->n_replicated++;
		}
		return 0;
	}

	/* Do not remove chunks in a split condition */
	if (!is_cluster_healthy(dev->rt, 1)) {
		if (re)
			reptrans_manifest_unlock(dev, re, SPACE_RECLAIM_DONE);
		return 0;
	}

	/* Check for speculative backref - verify may still be in progress */
	err = reptrans_check_speculative_hold(dev, hash_type, ttag, key);
	if (err != -ENOENT) {
		log_debug(lg, "Space Reclaim(%s, %s): get speculative backref %d",
		    dev->path, keybuf, err);
		/* We found a speculative backref, or something went wrong */
		/* In either case, bail out */
		if (re)
			reptrans_manifest_unlock(dev, re, SPACE_RECLAIM_DONE);
		return 0;
	}

	double utilization = reptrans_get_utilization(dev);
	repdev_status_t status = reptrans_dev_get_status(dev);
	int can_delete = !reptrans_refresh_status(dev, ttag, ioTypeDelete);

	if (utilization >= dev->bg_config->dev_utilization_threshold_low && can_delete) {

		log_info(lg,
		    "Space Reclaim(%s, %s, %s, %s): orphan found, "
		    "utilization %d%% greater then configured %d%%, deleting",
		    dev->path, keybuf, type_tag_name[ttag],
		    hash_type_name[hash_type],
		    (int)(utilization * 100),
		    (int)(dev->bg_config->dev_utilization_threshold_low * 100));

		work->n_removed++;
		if (ttag == TT_CHUNK_MANIFEST || ttag == TT_VERSION_MANIFEST)
			err = reptrans_delete_manifest(dev, ttag, hash_type, key);
		else
			err = reptrans_delete_blob(dev, ttag, hash_type,key);
		if (err) {
			log_warn(lg, "Dev(%s): couldn't delete blob(s) %s %s %s",
			    dev->name, type_tag_name[ttag], keybuf,
			    hash_type_name[hash_type]);
		} else {
			keybuf[16] = 0;
			log_debug(lg, "Dev(%s): deleted blob %s %s", dev->name,
			    type_tag_name[ttag], keybuf);
		}
	}
	if (re)
		reptrans_manifest_unlock(dev, re, SPACE_RECLAIM_DONE);
	return 0;
}

static int
bg_space_reclaim_init(struct bg_job_entry* job, void** pdata) {
	static const char* str[] = {"NGCOUNT_DELAY", "REMOVED",
		"REPL_SCHEDULED", "ERC_RECOVERED"};
	space_reclaim_work_t *work =
	    je_calloc(1, sizeof(space_reclaim_work_t));
	assert(work != NULL);
	job->chunks_total = job->sched->dev->stats.ttag_entries[TT_CHUNK_PAYLOAD] +
			job->sched->dev->stats.ttag_entries[TT_CHUNK_MANIFEST] +
			job->sched->dev->stats.ttag_entries[TT_VERSION_MANIFEST];
	work->dev = job->sched->dev;
	work->job = job;
	*pdata = work;
	bg_sched_register_counters(job, 4, str);
	return 0;
}

static void
bg_space_reclaim_work(struct bg_job_entry* job, void* data) {
	assert(data != NULL);
	space_reclaim_work_t *work = (space_reclaim_work_t*)data;
	struct repdev *dev = work->dev;
	uint512_t keys;
	int err;
	assert(dev != NULL);

	type_tag_t data_types[] = {
		TT_CHUNK_PAYLOAD, TT_CHUNK_MANIFEST, TT_VERSION_MANIFEST
	};

	reptrans_set_thrname(dev, "bgspc");

	size_t i;
	err = 0;
	for (i = 0; !err && i < (sizeof(data_types) / sizeof(type_tag_t)); ++i) {

		err = reptrans_iterate_blobs(dev, data_types[i],
			dev_space_reclaim_callback, work, 0);
		/* TODO: What do we do with an error here? */
		if (err)
			log_debug(lg, "Space Reclaim(%s): %s iter err %d: %s",
				dev->path, type_tag_name[data_types[i]], err,
				strerror(err));
	}
}

static void
bg_space_reclaim_done(struct bg_job_entry* job, void* data) {
	assert(data != NULL);
	space_reclaim_work_t *work = (space_reclaim_work_t*)data;
	bg_sched_set_counter(job, work->dev->ngcount_delay_avg, 0);
	bg_sched_set_counter(job, work->n_removed, 1);
	bg_sched_set_counter(job, work->n_replicated, 2);
	bg_sched_set_counter(job, work->n_erc, 3);
	je_free(work);
}

static int
bg_space_reclaim_progress(struct bg_job_entry* job) {
	struct repdev* dev = job->sched->dev;
	if (dev->terminating ||
		!(job->status == BG_STATUS_PROGRESS ||
		job->status == BG_STATUS_PAUSED ||
		job->status == BG_STATUS_PREEMPTED))
		return -1;

	if (!job->chunks_total)
		return 1000;

	size_t ratio = job->chunk_counter*1000/job->chunks_total;
	if (ratio > 1000)
		ratio = 1000;

	return ratio;
}

static void
reptrans_tenant_context_startup(struct ccow *tc)
{
	struct ccowtp_job_config ccow_tp_cfg = {
		.sched = SCHED_OTHER,
		.prio = 0,
		.weight = 50,
		.min = 0,
		.resiliency = 0
	};

	tc->tenant_ucache_size = CCOWD_UCACHE_SIZE;
	tc->tenant_ucache_size_max = CCOWD_UCACHE_SIZE_MAX;
	tc->cmcache_hash_size = CCOWD_CMCACHE_HASH_SIZE;
	tc->cmcache_lru_hiwat = CCOWD_CMCACHE_HASH_SIZE * 3;
	tc->cmcache_lru_lowat = 3 * CCOWD_CMCACHE_HASH_SIZE / 4;
	tc->sync_put_dedup_min = 0;
	QUEUE* q;
	QUEUE_FOREACH(q, &all_rts) {
		struct reptrans* rt = QUEUE_DATA(q, struct reptrans, item);
		if (!rt->tc_wh) {
			assert (rt->dev_bg_config.tenant_thread_pool_size <= REPDEV_TC_TP_MAX_SZ);
			rt->tc_wh = ccowtp_create_wh(rt->dev_bg_config.tenant_thread_pool_size);
			assert(rt->tc_wh);
		}
		tc->tp_size = 0;
		tc->tp = ccowtp_create_shared(tc->loop, &ccow_tp_cfg, 1, rt->tc_wh);
		break;
	}
}

ccow_t
reptrans_get_tenant_context(struct reptrans *rt, uint64_t key)
{
	ccow_t tc;
	uv_mutex_lock(&rt->tc_mutex);
	if (rt->tc_term) {
		uv_mutex_unlock(&rt->tc_mutex);
		return NULL;
	}

	int cur;
	if (key == 0) {
		cur = rt->tc_cursor;
	} else {
		/* If key is provided, try to allocate sharded TC. However,
		 * if it is not yet available, give up and let logic below to
		 * fall through. */
		cur = key % rt->tc_pool_sz;
		if (rt->tc_pool[cur] == NULL)
			cur = rt->tc_cursor;
	}

	tc = rt->tc_pool[cur];
	if (tc != NULL) {
		rt->tc_ref[cur]++;
		rt->tc_cursor = (rt->tc_cursor + 1) % rt->tc_pool_sz;
		uv_mutex_unlock(&rt->tc_mutex);
		return tc;
	}
	/* Temporary block SIGTERM */
	struct sigaction new_action, old_action;
	new_action.sa_handler = SIG_IGN;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction (SIGINT, &new_action, &old_action);

	log_trace(lg, "Creating tenant context...");
	char path[PATH_MAX];
	snprintf(path, sizeof(path), TRANS_CONF_DIR "/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	char *buf = NULL;
	if (fd < 0)
		goto out;
	buf = je_calloc(1, 16384);
	if (!buf)
		goto out;
	if (read(fd, buf, 16383) < 0)
		goto out;
	int err = ccow_admin_init_override(buf, "", 1,
	    &rt->tc_pool[rt->tc_cursor], reptrans_tenant_context_startup);
	if (!err) {
		tc = rt->tc_pool[rt->tc_cursor];
		/*
		 * This is running on data node. Hence, GW cache flag
		 * has no significance. Infact when GW cache attempts to make
		 * regular GET request, it will first try itself.
		 */
		rt->tc_ref[rt->tc_cursor] = 1;
		rt->tc_cursor = (rt->tc_cursor + 1) % rt->tc_pool_sz;
		log_trace(lg, "The tenant context sucessfuly created");
	} else {
		log_error(lg, "Couldn't create tenant context");
		rt->tc_pool[rt->tc_cursor] = NULL;
	}
out:
	if (fd >= 0)
		close(fd);
	if (buf)
		je_free(buf);
	/* unblock SIGTERM */
	sigaction (SIGINT, &old_action, NULL);
	uv_mutex_unlock(&rt->tc_mutex);
	return tc;
}

static int
reptrans_match_tenant_context(struct reptrans *rt, ccow_t tc)
{
	for (uint8_t i = 0; i < rt->tc_pool_sz; i++) {
		if (rt->tc_pool[i] == tc)
			return (int)i;
	}
	return -1;
}

void
reptrans_put_tenant_context(struct reptrans *rt, ccow_t tc)
{
	uv_mutex_lock(&rt->tc_mutex);
	int idx = reptrans_match_tenant_context(rt, tc);
	assert(idx != -1);
	if (rt->tc_ref[idx])
		rt->tc_ref[idx]--;
	uv_mutex_unlock(&rt->tc_mutex);
}

static int
reptrans_try_free_tenant_context(struct reptrans *rt, int idx)
{
	int rc = 0;
	uv_mutex_lock(&rt->tc_mutex);
	rt->tc_term = 1;

	if (!rt->tc_ref[idx]) {
		if (rt->tc_pool[idx]) {
			ccow_tenant_term(rt->tc_pool[idx]);
			rt->tc_pool[idx] = NULL;
		}
		rc = 1;
	} else {
		ccow_tenant_abort(rt->tc_pool[idx]);
	}

	uv_mutex_unlock(&rt->tc_mutex);
	return rc;
}

static int
vbr_all_filter_cb(void *arg, void **data, size_t *size, int set) {
	if (set) {
		*data = NULL;
		*size = 0;
	}
	return 1;
}

struct vbr_iterate_arg {
	struct repdev* dev;
	const uint512_t* chid;
	crypto_hash_t hash_type;
	vbr_iterator_cb_t cb;
	void* cb_arg;
};

static int
vbrs_iterate_filter_cb(void *arg, void **data, size_t *size, int set) {
	if (set) {
		*data = NULL;
		*size = 0;
		return 0;
	}
	struct vbr_iterate_arg* p = arg;
	vbr_iterator_cb_t cb = p->cb;
	void* cb_arg = p->cb_arg;
	struct backref vbr_rd;
	uv_buf_t buf = { .base = *data, .len = *size };

	msgpack_u *uu = msgpack_unpack_init(*data, *size, 0);
	if (!uu)
		return -EFAULT;
	int err = reptrans_unpack_vbr(uu, &vbr_rd);
	msgpack_unpack_free(uu);
	if (err)
		return -EFAULT;

	err = cb(p->dev, p->chid, p->hash_type, &buf, &vbr_rd, cb_arg);
	if (err)
		return -1;
	return 0;
}

int
reptrans_vbrs_iterate(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, vbr_iterator_cb_t cb, void* arg) {
	assert(cb);
	struct vbr_iterate_arg it_arg = {
		.dev = dev,
		.chid = chid,
		.hash_type = hash_type,
		.cb = cb,
		.cb_arg = arg
	};
	rtbuf_t* rb = NULL;
	int err = reptrans_get_blobs(dev, TT_VERIFIED_BACKREF, hash_type, chid,
		&rb, 0, vbrs_iterate_filter_cb, &it_arg);
	if (err == -1 || err == -ENOENT)
		err = 0;

	if (rb) {
		assert(rb->nbufs == 0);
		rtbuf_destroy(rb);
	}
	return err;
}

struct del_old_vbrs_arg {
	const struct  backref* vbr;
	rtbuf_t*	to_del;
};

static int
delete_old_vbs__cb (struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, uv_buf_t* vbr_buf, const struct backref* vbr,
	void* arg) {
	struct del_old_vbrs_arg* p = (struct del_old_vbrs_arg*)arg;
	if (uint512_cmp(&vbr->ref_chid, &p->vbr->ref_chid))
		return 0;
	if (vbr->rep_count == p->vbr->rep_count && vbr->attr == p->vbr->attr)
		return 0;
	int err = rtbuf_add_alloc(p->to_del, vbr_buf, 1);
	return err;
}

int
reptrans_delete_old_vbrs(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const struct backref* vbr, int* n_del) {
	rtbuf_t* rb_out = rtbuf_init_empty();
	if (!rb_out)
		return -ENOMEM;
	if (!dev->__vtbl)
		return -EPERM;

	int err = reptrans_refresh_status(dev, TT_VERIFIED_BACKREF, ioTypeDelete);
	if (err)
		return err;

	struct del_old_vbrs_arg arg = { .vbr = vbr, .to_del = rb_out };
	err = reptrans_vbrs_iterate(dev, chid, hash_type,
		delete_old_vbs__cb, (void*)&arg);
	if (!err && rb_out->nbufs) {
		err = reptrans_delete_blob_value(dev, TT_VERIFIED_BACKREF,
			hash_type, chid, rb_out->bufs, rb_out->nbufs);
		if (!err)
			*n_del = rb_out->nbufs;
	}
	if (rb_out)
		rtbuf_destroy(rb_out);
	return err;
}

static int
delete_all_vbs__cb (struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, uv_buf_t* vbr_buf, const struct backref* vbr,
	void* arg) {
	struct del_old_vbrs_arg* p = (struct del_old_vbrs_arg*)arg;

	if (uint512_cmp(&vbr->ref_chid, &p->vbr->ref_chid))
		return 0;

	int err = rtbuf_add_alloc(p->to_del, vbr_buf, 1);
	return err;
}

int
reptrans_delete_vbrs_all_repcounts(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const struct backref* vbr, int* n_del) {
	rtbuf_t* rb_out = rtbuf_init_empty();
	if (!rb_out)
		return -ENOMEM;
	if (!dev->__vtbl)
		return -EPERM;

	int err = reptrans_refresh_status(dev, TT_VERIFIED_BACKREF, ioTypeDelete);
	if (err)
		return err;

	struct del_old_vbrs_arg arg = { .vbr = vbr, .to_del = rb_out };
	err = reptrans_vbrs_iterate(dev, chid, hash_type,
		delete_all_vbs__cb, (void*)&arg);
	if (!err && rb_out->nbufs) {
		err = reptrans_delete_blob_value(dev, TT_VERIFIED_BACKREF,
			hash_type, chid, rb_out->bufs, rb_out->nbufs);
		if (!err)
			*n_del = rb_out->nbufs;
	}
	if (rb_out)
		rtbuf_destroy(rb_out);
	return err;
}

static int
delete_vbrs_by_attr__cb (struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, uv_buf_t* vbr_buf, const struct backref* vbr,
	void* arg) {
	struct del_old_vbrs_arg* p = (struct del_old_vbrs_arg*)arg;

	if (uint512_cmp(&vbr->ref_chid, &p->vbr->ref_chid))
		return 0;

	if (vbr->attr != p->vbr->attr)
		return 0;

	int err = rtbuf_add_alloc(p->to_del, vbr_buf, 1);
	return err;
}
int
reptrans_delete_vbrs_by_attr(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const struct backref* vbr, int* n_del) {
	rtbuf_t* rb_out = rtbuf_init_empty();
	if (!rb_out)
		return -ENOMEM;
	if (!dev->__vtbl)
		return -EPERM;

	int err = reptrans_refresh_status(dev, TT_VERIFIED_BACKREF, ioTypeDelete);
	if (err)
		return err;

	struct del_old_vbrs_arg arg = { .vbr = vbr, .to_del = rb_out };
	err = reptrans_vbrs_iterate(dev, chid, hash_type,
		delete_vbrs_by_attr__cb, (void*)&arg);
	if (!err && rb_out->nbufs) {
		err = reptrans_delete_blob_value(dev, TT_VERIFIED_BACKREF,
			hash_type, chid, rb_out->bufs, rb_out->nbufs);
		if (!err)
			*n_del = rb_out->nbufs;
	}
	if (rb_out)
		rtbuf_destroy(rb_out);
	return err;
}

struct vbr_count_all__cb {
	int count;
	const uint512_t* ref_chid;
	uint64_t attr_mask;
	uint64_t* attr_value;
	int max;
};

static int
retrans_count_vbrs_all_repcount__cb(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, uv_buf_t* vbr_buf, const struct backref* vbr,
	void* arg) {
	struct vbr_count_all__cb* p = (struct vbr_count_all__cb*)arg;

	if (p->ref_chid) {
		if (uint512_cmp(&vbr->ref_chid, p->ref_chid))
			return 0;
	}
	if (p->attr_value) {
		/*
		 * The attribute is a bit field. User provides a bitmask and value.
		 */
		if ((vbr->attr & p->attr_mask) != *p->attr_value)
			return 0;
	}

	p->count++;
	return p->count >= p->max;
}

int
retrans_count_vbrs_all_repcount(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, const uint512_t* ref_chid, uint64_t attr_mask,
	uint64_t* attr_value, int vbrs_max) {
	struct vbr_count_all__cb arg = {
		.count = 0,
		.ref_chid = ref_chid,
		.attr_mask = attr_mask,
		.attr_value = attr_value,
		.max = vbrs_max
	};
	reptrans_vbrs_iterate(dev, chid, hash_type,
		retrans_count_vbrs_all_repcount__cb, (void*)&arg);
	return arg.count;
}

static int
vbr_stat_cb(void *arg, void **data, size_t *size, int set) {
	uv_buf_t* ub = arg;
	if (set) {
		*data = ub->base;
		*size = ub->len;
		return 0;
	}
	return 1;
}

int
reptrans_vbr_stat_value(struct repdev* dev,  crypto_hash_t hash_type,
	const uint512_t* chid, uv_buf_t vbr_val) {

	rtbuf_t* rb = NULL;

	int err = dev->__vtbl->get_blob(dev, TT_VERIFIED_BACKREF, hash_type, GBF_FLAG_DUPCOUNT,
		chid, &rb, 1, vbr_stat_cb, &vbr_val);
	if (rb)
		rtbuf_destroy(rb);
	return err;
}

int
reptrans_vbr_stat(struct repdev* dev, crypto_hash_t hash_type,
	const uint512_t* chid, struct backref* vbr) {

	char buf[1024];
	uv_buf_t ub = { .base = buf, .len = 1024 };
	msgpack_p p;
	msgpack_pack_init_p(&p, ub);
	int err = reptrans_pack_vbr(&p, vbr);

	uv_buf_t vbr_buf;
	msgpack_get_buffer(&p, &vbr_buf);
	return reptrans_vbr_stat_value(dev, hash_type, chid, vbr_buf);
}

static int
compound_append_chunk(msgpack_p* p, type_tag_t ttag, uv_buf_t* buf) {
	int err = msgpack_pack_uint8(p, ttag);
	if (err)
		return err;

	err = msgpack_pack_uint32(p, buf->len);
	if (err)
		return err;;

	err = msgpack_pack_raw(p, buf->base, buf->len);
	return err ? err : (int)msgpack_get_len(p);
}

static int
compound_send_one(struct repdev* dev, uint64_t attr, uint8_t rep_cnt,
	uint64_t compound_flags, const uint512_t* chid, crypto_hash_t hash_type,
	uint64_t chunk_count, msgpack_p* payload, const char* group, struct vdev_sel* sel) {

	uv_buf_t payload_buf;
	msgpack_get_buffer(payload, &payload_buf);
	char* base = payload_buf.base - COMPOUND_HDR_RESERVED;
	int n_tgts = 1;
	struct vdev_sel* lsel = sel;
	int sec_tr = !(attr & RD_ATTR_TARGETED) && !(compound_flags & COMPOUND_FLAG_PRIMARY_PUT);
	if (sec_tr) {
		/*
		 * this is secondary transfer. We must be sure replicas will go
		 * to the same devices as the primary compound
		 * */
		attr |= RD_ATTR_COMPOUND_TARGETED;
		assert(sel->len > 0);
		n_tgts = sel->len;
		lsel = NULL;
	}

	uv_buf_t hdr_buf = {.len = COMPOUND_HDR_RESERVED, .base = base};
	rtbuf_t* man_rb = NULL;
	if (!sec_tr && (attr & (RD_ATTR_CHUNK_MANIFEST | RD_ATTR_VERSION_MANIFEST))) {
		/* If there is a EC protection request, then it needs to be replicated too */
		int err = reptrans_get_blob(dev, TT_ENCODING_QUEUE, HASH_TYPE_DEFAULT,
			chid, &man_rb);
		if (!err && man_rb)
			compound_flags |= COMPOUND_FLAG_REQUEST_EC;
	}

	msgpack_p p;
	msgpack_pack_init_p(&p, hdr_buf);
	/* Compound version goes first */
	int err = msgpack_pack_uint32(&p, RT_PROT_COMPOUND_VERSION);
	if (err)
		return err;
	/* Compound flags */
	err = msgpack_pack_uint64(&p, compound_flags);
	if (err)
		return err;
	/* Main chunk hash type */
	err = msgpack_pack_uint8(&p, hash_type);
	if (err)
		return err;
	/* Main chunk's CHID */
	err = replicast_pack_uint512(&p, chid);
	if (err)
		return err;

	if (man_rb) {
		struct verification_request* req =
			(struct verification_request*)man_rb->bufs->base;
		uint64_t time_to_trigger = req->uvid_timestamp - reptrans_get_timestamp(dev)/1000000;
		err = msgpack_pack_uint64(&p, time_to_trigger);
		if (err)
			return err;
		err = msgpack_pack_uint8(&p, req->width);
		if (err)
			return err;
		err = msgpack_pack_uint8(&p, req->n_parity);
		if (err)
			return err;
		err = msgpack_pack_uint8(&p, req->domain);
		if (err)
			return err;
		err = msgpack_pack_uint8(&p, req->algorithm);
		if (err)
			return err;
	}

	/* Number of chunks in this compound */
	err = msgpack_pack_uint64(&p, chunk_count);
	if (err)
		return err;

	char chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
	/* The header and the payload are in the same memory region, but with
	 * a fixed offset 1024 bytes. Concatenate them before sending.
	 */
	size_t hdr_len = msgpack_get_len(&p);
	memmove(base + hdr_len, payload_buf.base, payload_buf.len);
	struct iovec ciov = { .iov_len = payload_buf.len + hdr_len, .iov_base = base };

	ccow_t ct = reptrans_get_tenant_context(dev->rt, 0);
	if (!ct) {
		err = -EPERM;
		log_error(lg, "Dev(%s): compound_send_one get context, err %d",
			dev->name, err);
		goto out;
	}

	ccow_completion_t c;
	err = ccow_create_completion(ct, NULL, NULL, n_tgts, &c);
	if (err) {
		log_error(lg, "Dev(%s): compound_send_one create comp, err %d",
			dev->name, err);
		reptrans_put_tenant_context(dev->rt, ct);
		goto out;
	}

	uint8_t select_policy = CCOW_SELECT_POLICY_SPACE;
	err = ccow_attr_modify_default(c, CCOW_ATTR_SELECT_POLICY,
	    (void *)&select_policy, NULL);
	if (err) {
		log_error(lg, "Dev(%s): compound_send_one set policy, err %d",
			dev->name, err);
		ccow_release(c);
		reptrans_put_tenant_context(dev->rt, ct);
		goto out;
	}

	if (attr & (RD_ATTR_TARGETED | RD_ATTR_COMPOUND_TARGETED))
		rep_cnt = 1;

	err = ccow_attr_modify_default(c, CCOW_ATTR_REPLICATION_COUNT,
	    (void *)&rep_cnt, NULL);
	if (err) {
		log_error(lg, "Dev(%s): compound_send_one set repcnt, err %d",
			dev->name, err);
		ccow_release(c);
		reptrans_put_tenant_context(dev->rt, ct);
		goto out;
	}

	uint8_t ht = hash_type;
	err = ccow_attr_modify_default(c, CCOW_ATTR_HASH_TYPE,
	    (void *)&ht, NULL);
	if (err) {
		log_error(lg, "Dev(%s): compound_send_one set hash type, err %d",
			dev->name, err);
		ccow_release(c);
		reptrans_put_tenant_context(dev->rt, ct);
		goto out;
	}


	for (int n = 0; n < n_tgts; n++) {
		if (sec_tr)
			group = (const char*)&sel->vdevs[n];

		if (lsel)
			ccow_completion_keep_selected(c, lsel);

		err = ccow_admin_pseudo_put_chunks(&ciov, 1, attr, (const char*)chid,
			group, c);
		if (err) {
			log_error(lg, "Dev(%s): Replicate One: pseudo_put, err %d",
				dev->name, err);
			ccow_release(c);
			reptrans_put_tenant_context(dev->rt, ct);
			goto out;
		}
	}


	log_debug(lg, "Replicate Chunk(%s, %s, %d): err %d", dev->path, chidstr,
		rep_cnt, err);

	err = ccow_wait(c, -1);
	reptrans_put_tenant_context(dev->rt, ct);

out:
	if (!err && (compound_flags & (COMPOUND_FLAG_PRIMARY_PUT | RD_ATTR_TARGETED))
		== COMPOUND_FLAG_PRIMARY_PUT) {
		if (!(compound_flags & COMPOUND_FLAG_OVERRIDE_SELECTED) && !sel->len) {
			/* Have enough replicas already.
			 * We don't want to put secondary compounds
			 */
			err = -EEXIST;
		} else if (compound_flags & COMPOUND_FLAG_OVERRIDE_SELECTED) {
			/*
			 * We want to put secondary compounds to every VDEVs
			 * where primary chunk resides
			 */
			type_tag_t ttag = TT_LAST;
			if (attr & RD_ATTR_CHUNK_MANIFEST)
				ttag = TT_CHUNK_MANIFEST;
			else if (attr & RD_ATTR_VERSION_MANIFEST)
				ttag = TT_VERSION_MANIFEST;
			else if (attr & RD_ATTR_CHUNK_PAYLOAD)
				ttag = TT_CHUNK_PAYLOAD;
			else {
				log_error(lg, "Dev(%s) cannot fetch type tag from attribute %lX", dev->name, attr);
				return -EINVAL;
			}
			uint128_t* pvdev = NULL;
			uint512_t nhid = ttag == TT_VERSION_MANIFEST ? *((uint512_t*)group) : uint512_null;
			err = ngcount_chunks(dev, ttag, hash_type, chid, &nhid,
				rep_cnt, &pvdev, 0, NULL, NULL);
			if (err < 0) {
				log_error(lg, "Dev(%s) error locating chunk replicas %d",
					dev->name, err);
			} else if (!err) {
				log_error(lg, "Dev(%s) cannot find primary chunk replicas location", dev->name);
				err = -EINVAL;
			} else {
				assert(pvdev);
				int n_vdevs = sizeof(sel->vdevs)/sizeof(sel->vdevs[0]);
				if (err < n_vdevs)
					n_vdevs = err;
				memcpy(sel->vdevs, pvdev, n_vdevs*sizeof(uint128_t));
				sel->len = err;
				err = 0;
			}
			if (pvdev)
				je_free(pvdev);
		}
	}
	return err;
}

static int
comp_vbr_blob_filter(void *arg, void **data, size_t *size, int set) {
	uv_buf_t* ub = arg;
	if (set) {
		if (ub->len) {
			*size = ub->len;
			*data = ub->base;
		} else {
			*data = NULL;
			*size = 0;
		}
		return 0;
	}
	memcpy(ub->base, *data, *size);
	ub->len = *size;
	return 1;
}

static int
reptrans_check_parent(struct repdev* dev, const struct backref* vbr) {
	int err = 0;
	if (vbr->ref_type == TT_NAMEINDEX) {
		/* The ttag is VM and parent if NAMEINDEX.
		 * Only ngrequest-count support NI lookup
		 */
		int32_t actual_count = ngcount_chunks(dev, TT_NAMEINDEX,
			HASH_TYPE_DEFAULT, NULL, &vbr->name_hash_id, 1,
			NULL, vbr->generation, NULL, NULL);
		if (!actual_count) {
			err = -ENOENT;
			log_debug(lg, "Dev(%s) VM doesn't have a NI entry", dev->name);
		} else if (actual_count < 0) {
			log_error(lg, "Dev(%s) NI lookup error %d", dev->name, err);
			err = actual_count;
		}
	} else {
		struct chunk_info ci = {
			.chid = vbr->ref_chid,
			.hash_type = vbr->ref_hash,
			.ttype = vbr->ref_type,
			.n_vdevs = 0
		};
		const uint512_t* nh = vbr->ref_type == TT_VERSION_MANIFEST ? &vbr->name_hash_id : NULL;
		err = ec_locate_chunk(dev, &ci, nh, 1);
		if (!err && (!ci.n_vdevs || !ci.n_vbrs_max))
			err = -ENOENT;
	}
	return err;
}

int
reptrans_replicate_chunk(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, uint64_t attr,
	const void *nhid_vdevid, uint8_t rep_count, int opts) {

	uint64_t flags = COMPOUND_FLAG_PRIMARY_PUT;
	uint64_t chunk_count = 0;
	rtbuf_t* rb = NULL;
	uv_buf_t buf = { .len = COMPOUND_SIZE_MAX };
	char chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
	struct vdev_sel sel = {.len = 0};
	rtbuf_t* vbr_rb = NULL;
	struct vmmetadata md;


	/* Allocate here a space to keep the last VBR in */
	uv_buf_t ub_last = {.len = 0 };
	ub_last.base = je_malloc(512);
	if (!ub_last.base)
		return -ENOMEM;

	if (!(opts & REPLICATE_OPTIONAL_VBR)) {
		/* Ensure there is at least one VBR */
		size_t count = 0;
		int err = reptrans_get_chunk_count_limited(dev, hash_type,
			TT_VERIFIED_BACKREF, (uint512_t*)chid, 1, &count);
		/*
		 * VBR may not exist - either the chunk has been deleted, or
		 * has not been verified yet. In either case, just skip the
		 * request.
		 */
		if (err) {
			if (err == -ENOENT) {
				log_debug(lg,
					"Dev(%s): Replicate One(%s): get VBR, err %d",
					dev->name, chidstr, err);
				err = reptrans_check_speculative_hold(dev, hash_type,
				    ttag, chid);
				if (err == 0) {
					err = -EAGAIN;
				}
			} else {
				log_error(lg,
					"Dev(%s): Replicate One(%s): get VBR, err %d",
					dev->name, chidstr, err);
			}
			je_free(ub_last.base);
			return err;
		}
	}


	char* base = je_malloc(buf.len + COMPOUND_HDR_RESERVED);
	if (!base)
		return -ENOMEM;
	buf.base = base + COMPOUND_HDR_RESERVED;
	msgpack_p p;
	msgpack_pack_init_p(&p, buf);

	/* EC VBRs will be filtered out by a server */
	if (!(opts & REPLICATE_EC_VBR))
		flags |= COMPOUND_FLAG_SKIP_EC_VBRS;

	if (REPLICATE_NO_VBR_OWERWRITE)
		flags |= COMPOUND_FLAG_KEEP_ALL_VBRS;

	switch (ttag) {
		case TT_CHUNK_PAYLOAD:
			attr |= RD_ATTR_CHUNK_PAYLOAD;
			break;

		case TT_CHUNK_MANIFEST:
			attr |= RD_ATTR_CHUNK_MANIFEST;
			break;

		case TT_VERSION_MANIFEST:
			attr |= RD_ATTR_VERSION_MANIFEST;
			break;

		default:
			log_error(lg, "Replicate Chunk(%s): unexpected chunk TT %s",
				dev->path, type_tag_name[ttag]);
			return -EINVAL;
	}

	const char* group = (attr & RD_ATTR_TARGETED) || (ttag == TT_VERSION_MANIFEST) ?
		(const char*)nhid_vdevid : (const char*)chid;

	log_trace(lg, "Dev(%s): ttag %s rep_count %d chid %s", dev->name,
	    type_tag_name[ttag], rep_count, chidstr);

	int err = reptrans_get_blob_verify(dev, ttag, hash_type, chid, &rb);
	if (err < 0 || !rb) {
		log_warn(lg, "Dev(%s): Replicate One(%s): get blob, err %d",
			dev->name, chidstr, err);
		goto _out;
	}
	if (ttag == TT_VERSION_MANIFEST) {
		/*
		 * VM can be replicated without or without corresponding NI entry.
		 * The NI isn't required if the VM is referenced by a snapshot object.
		 */
		err = replicast_get_metadata(rb, &md);
		if (err) {
			log_error(lg, "Dev(%s) VM unpack error %d", dev->name, err);
			goto _out;
		}
		struct vlentry query = {
			.uvid_timestamp = ~0ULL,
			.generation =  md.txid_generation
		};
		rtbuf_t* rb_vers = NULL;
		err = reptrans_get_versions(dev, &md.nhid, &query,
			&rb_vers);
		if (!err && rb_vers)
			flags |= COMPOUND_FLAG_NEED_VERSION;
		if (rb_vers)
			rtbuf_destroy(rb_vers);
		if (memcmp_quick(md.oid, md.oid_size, "marker", 7)) {
			char oname[REPLICAST_OBJPATH_MAXLEN];
			sprintf(oname, "%s/%s/%s/%s", md.cid, md.tid, md.bid, md.oid);
			log_debug(lg, "Dev(%s) replicating VM %s object %s %s version entry, err %d",
				dev->name, chidstr, oname,
				flags & COMPOUND_FLAG_NEED_VERSION ? "with" : "WITHOUT", err);
		}
	}

	/* Packing main chunk */
	err = compound_append_chunk(&p, ttag, rb->bufs);
	if (err < 0) {
		log_error(lg, "Dev(%s) error packing data chunk %s: %d\n",
			dev->name, chidstr, err);
		goto _out;
	}
	chunk_count++;
	if (err >= COMPOUND_SIZE_MAX) {
		log_error(lg, "Dev(%s) the main chunk is too big (%lu bytes) for replication",
			dev->name, rb->bufs->len);
		err = -EINVAL;
		goto _out;
	}
	rtbuf_destroy(rb);
	rb = NULL;
	if (ttag == TT_VERSION_MANIFEST || ttag == TT_CHUNK_MANIFEST) {
		/* Replicate also parity manifests, if any */
		err = reptrans_get_blob(dev, TT_PARITY_MANIFEST, hash_type,
			chid, &rb);
		if (err && err != -ENOENT)
			goto _out;
		if (!err) {
			/* Primary compound has to fit main chunk + parity + at least 1 VBR */
			if (msgpack_get_len(&p) + rb->bufs->len + 256 >= COMPOUND_SIZE_MAX) {
				log_error(lg, "Dev(%s) primary compound size exceeded the limit: %lu vs %lu\n",
					dev->name, msgpack_get_len(&p) + rb->bufs->len + 256, (size_t)COMPOUND_SIZE_MAX);
				err = -EINVAL;
				goto _out;
			}
			err = compound_append_chunk(&p, TT_PARITY_MANIFEST, rb->bufs);
			if (err < 0) {
				log_error(lg, "Dev(%s) error packing parity manifest %s: %d\n",
					dev->name, chidstr, err);
				goto _out;
			}
			chunk_count++;
		}
	}
	/* Processing VBRs. There can be millions */
	size_t n_vbrs = 0;
	size_t n_vbrs_get = 0;
	do {
		err = reptrans_get_blobs(dev, TT_VERIFIED_BACKREF, hash_type, chid,
			&vbr_rb, VBRS_PER_GET, comp_vbr_blob_filter, &ub_last);

		if (err)
			break;
		assert(vbr_rb);
		n_vbrs_get = vbr_rb->nbufs;
		for (size_t n = 0; n < vbr_rb->nbufs; n++) {
			struct backref vbr_rd;
			msgpack_u uu;
			msgpack_unpack_init_b(&uu, vbr_rb->bufs[n].base, vbr_rb->bufs[n].len, 0);
			err = reptrans_unpack_vbr(&uu, &vbr_rd);
			if (err) {
				log_error(lg, "Dev(%s) VBR unpack error", dev->name);
				goto _out;
			}
			if (opts & REPLICATE_CHECK_PARENT) {
				/*
				 * We want to replicate only actual VBRs, that is,
				 * if parent exists an it has a VBR
				 */
				err = reptrans_check_parent(dev, &vbr_rd);
					if (err) {
						if (err != -ENOENT)
							goto _out;
						log_debug(lg, "Dev(%s) %s %s replication skipped: "
							"lack of or unverified parent,  "
							"refChid %016lX refType %s nhid %016lX",
							dev->name, chidstr, type_tag_name[ttag],
							vbr_rd.ref_chid.u.u.u, type_tag_name[vbr_rd.ref_type],
							vbr_rd.name_hash_id.u.u.u);
						continue;
					}
			}
			err = compound_append_chunk(&p, TT_VERIFIED_BACKREF, vbr_rb->bufs + n);
			if (err < 0) {
				log_error(lg, "Dev(%s) error packing VBR %s: %d\n",
					dev->name, chidstr, err);
				goto _out;
			}
			n_vbrs++;
			chunk_count++;
			if (msgpack_get_len(&p) > COMPOUND_SIZE_MAX || chunk_count > COMPOUND_MAX_CHUNKS) {
				err = compound_send_one(dev, attr, rep_count, flags, chid,
					hash_type, chunk_count, &p, group, &sel);
				if (err) {
					if (err) {
						if ((flags & COMPOUND_FLAG_PRIMARY_PUT) && err == -EEXIST) {
							/*
							 * Chunk has enough replicas already,
							 * skip further actions
							 **/
							err = 0;
						}
					}
					goto _out;
				}
				msgpack_pack_init_p(&p, buf);
				chunk_count = 0;
				flags &= ~COMPOUND_FLAG_PRIMARY_PUT;
			}
		}
		if (vbr_rb) {
			rtbuf_destroy(vbr_rb);
			vbr_rb = NULL;
		}
	} while (n_vbrs_get >= VBRS_PER_GET);

	if (msgpack_get_len(&p) > 0) {
		if (!n_vbrs && !(opts & REPLICATE_OPTIONAL_VBR)) {
			log_debug(lg, "Dev(%s) skipping replication chunk %s due to lack of VBRs",
				dev->name, chidstr);
			err = 0;
		} else {
			err = compound_send_one(dev, attr, rep_count, flags, chid,
				hash_type, chunk_count, &p, group, &sel);
			if ((flags & COMPOUND_FLAG_PRIMARY_PUT) && err == -EEXIST) {
				/*
				 * Chunk has enough replicas already,
				 *  reset the error
				 */
				err = 0;
			}
		}
	}

_out:
	if (ub_last.base)
		je_free(ub_last.base);
	if (rb)
		rtbuf_destroy(rb);
	if (base)
		je_free(base);
	if (vbr_rb)
		rtbuf_destroy(vbr_rb);
	return err;
}

static int
reptrans_replicate_one(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, const uint512_t* nhid,
	uint8_t rep_count) {

	uint64_t attr = RD_ATTR_COMPOUND | RD_ATTR_RETRY_FAILFAST | RD_ATTR_NCOMP;
	return reptrans_replicate_chunk(dev, ttag, hash_type, chid, attr, nhid,
		rep_count, REPLICATE_CHECK_PARENT);
}


int
reptrans_replicate_vbrs(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, const uint512_t *nhid,
	uint8_t rep_count)
{
	rtbuf_t *rb = NULL;
	struct verification_request vreq = {
		.chid = *chid,
		.vtype = RT_VERIFY_NORMAL,
		.ttag = ttag,
		.htype = hash_type,
	};

	if (nhid)
		vreq.nhid = *nhid;

	char chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);

	log_trace(lg, "Dev(%s): ttag %s rep_count %d chid %s", dev->name,
	    type_tag_name[ttag], rep_count, chidstr);

	/* Extract all VBRs */
	int err = reptrans_get_blobs(dev, TT_VERIFIED_BACKREF, hash_type, chid,
		&rb, 0, vbr_all_filter_cb, NULL);
	if (err < 0 || !rb) {
		/*
		 * VBR may not exist - either the chunk has been deleted, or
		 * has not been verified yet. In either case, just skip the
		 * request.
		 */
		if (err == -ENOENT) {
			log_debug(lg,
				"Dev(%s): chid %s get VBR, err %d",
				dev->name, chidstr, err);
			err = reptrans_check_speculative_hold(dev, hash_type,
			    ttag, chid);
			if (err == 0) {
				err = -EAGAIN;
			}
		} else {
			log_error(lg,
				"Dev(%s): Replicate One(%s): get VBR, err %d",
				dev->name, chidstr, err);
		}
		goto out;
	}

	msgpack_u *u;
	for (size_t n = 0; !err && n < rb->nbufs; n++) {
		u = msgpack_unpack_init(rtbuf(rb, n).base, rtbuf(rb, n).len, 0);
		err = reptrans_unpack_vbr(u, &vreq.vbr);
		msgpack_unpack_free(u);
		assert(!err);
		err = reptrans_enqueue_batch_request(dev, NULL, &vreq);
		if (err)
			log_error(lg,
				"Dev(%s): chid %s enqueue batch req err %d",
				dev->name, chidstr, err);
	}

out:
	if (rb)
		rtbuf_destroy(rb);
	return err;
}

static int
reptrans_replicate_one__cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *chid, uv_buf_t *val, void *param)
{
	int err = 0;
	msgpack_u *u = NULL;
	struct manifest_lock_entry * lock = NULL;
	char chidstr[UINT512_BYTES * 2 + 1];

	assert(param != NULL);
	struct bg_job_entry* job = (struct bg_job_entry*)param;

	replication_work_t *work = (replication_work_t*)job->data;
	assert(work != NULL);

	if (bg_job_wait_resume(job, 30000))
		return -EINVAL;

	job->chunk_counter++;

	/* We are called from an iterator over a replication queue */
	/* 1. Unpack queue entry */
	u =  msgpack_unpack_init(val->base, val->len, 0);
	if (!u) {
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		log_error(lg, "Replicate One CB(%s, %s): unpack init failed",
		    dev->path, chidstr);
		err = -ENOMEM;
		goto delete_queue_entry;
	}
	uint32_t n = 0;
	err = msgpack_unpack_array(u, &n);
	if (err || n != 5) {
		err = -EBADF;
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		log_error(lg, "Replicate One CB(%s, %s): unpack arr err %d",
		    dev->path, chidstr, err);
		goto delete_queue_entry;
	}
	uint512_t chunk_chid;
	err = replicast_unpack_uint512(u, &chunk_chid);
	if (err) {
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		log_error(lg, "Replicate One CB(%s, %s): unpack chid err %d",
		    dev->path, chidstr, err);
		goto delete_queue_entry;
	}
	uint512_t chunk_nhid;
	err = replicast_unpack_uint512(u, &chunk_nhid);
	if (err) {
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		log_error(lg, "Replicate One CB(%s, %s): unpack nhid err %d",
		    dev->path, chidstr, err);
		goto delete_queue_entry;
	}
	uint32_t chunk_ttag;
	err = msgpack_unpack_uint32(u, &chunk_ttag);
	if (err) {
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		log_error(lg, "Replicate One CB(%s, %s): unpack ttag err %d",
		    dev->path, chidstr, err);
		goto delete_queue_entry;
	}
	if (err)
		goto delete_queue_entry;
	uint32_t chunk_hash_type;
	err = msgpack_unpack_uint32(u, &chunk_hash_type);
	if (err) {
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		log_error(lg, "Replicate One CB(%s, %s): unpack htype err %d",
		    dev->path, chidstr, err);
		goto delete_queue_entry;
	}
	uint8_t rep_count;
	err = msgpack_unpack_uint8(u, &rep_count);
	if (err) {
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		log_error(lg, "Replicate One CB(%s, %s): unpack rep_count err %d",
		    dev->path, chidstr, err);
		goto delete_queue_entry;
	}

	if (chunk_ttag == TT_CHUNK_MANIFEST || chunk_ttag == TT_VERSION_MANIFEST) {
		lock = reptrans_manifest_trylock(dev, &chunk_chid);
		if (!lock) {
			/* Manifest has been locked already, try later */
			err = 0;
			goto out;
		}
	}
	/* 2. Fulfill the request */
	err = reptrans_replicate_one(dev, (type_tag_t)chunk_ttag,
	    (crypto_hash_t)chunk_hash_type, &chunk_chid, &chunk_nhid,
	    rep_count);

	if (lock)
		reptrans_manifest_unlock(dev, lock, REPLICATION_DONE);
	if (err == -EAGAIN || err == -EINTR) {
		/* Chunk is pending verification or IO timeout,
		 * repeat it later.
		 */
		err = 0;
		goto out;
	}
	if (err == -ENOENT) {
		/* Chunk or VBR is removed, don't interrupt the replication */
		err = 0;
	}
delete_queue_entry:
	/* 3. Delete queue entry */
	err = reptrans_delete_blob(dev, ttag, hash_type, chid);
	if (err) {
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		log_error(lg, "Replicate One CB(%s, %s): del blob err %d",
		    dev->path, chidstr, err);
	}

out:
	if (u)
		msgpack_unpack_free(u);
	return err;
}

static int
bg_replication_init(struct bg_job_entry* job, void** pdata) {
	replication_work_t *work =
	    je_calloc(1, sizeof(replication_work_t));
	assert(work != NULL);

	work->dev = job->sched->dev;
	*pdata = work;
	return 0;
}


static void
bg_replication_work(struct bg_job_entry* job, void* data) {
	assert(data != NULL);
	replication_work_t *work = (replication_work_t*)data;

	assert(work != NULL);
	struct repdev *dev = work->dev;
	assert(dev != NULL);

	reptrans_set_thrname(dev, "bgrep");
	ccow_t cl = reptrans_get_tenant_context(dev->rt, 0);
	if (!cl) {
		log_error(lg, "Cannot initialize replication tenant context");
		return;
	}
	reptrans_put_tenant_context(dev->rt, cl);

	int err = reptrans_iterate_blobs(dev, TT_REPLICATION_QUEUE,
		reptrans_replicate_one__cb, job, 1);
}

static void
bg_replication_done(struct bg_job_entry* job, void* data) {
	assert(data != NULL);
	replication_work_t *work = (replication_work_t*)data;
	je_free(work);
}

typedef struct replication_rq {
	struct repdev *dev;
	type_tag_t ttag;
	crypto_hash_t hash_type;
	uint512_t chid;
	uint512_t nhid;
	uint8_t rep_count;
} replication_rq_t;

static void
enqueue_replication__exec(void *arg)
{
	assert(arg != NULL);

	replication_rq_t *rq = arg;
	assert(rq != NULL);

	int err = enqueue_replication(rq->dev, rq->ttag, rq->hash_type,
		&rq->chid, &rq->nhid, rq->rep_count);
	if (err)
		log_error(lg, "Dev(%s): enqueue_replication failed %d",
			rq->dev->name, err);
}

static void
enqueue_replication__done(void *arg, int status)
{
	assert(arg != NULL);

	replication_rq_t *rq = arg;

	je_free(rq);
}

void
enqueue_replication__async(struct repdev_call *c)
{
	assert(c != NULL);

	replication_rq_t *rq = (replication_rq_t *)c->args[0];
	assert(rq != NULL);

	ccowtp_work_queue(rq->dev->tp, REPTRANS_TP_PRIO_LOW, enqueue_replication__exec,
		enqueue_replication__done, rq);
}

int
enqueue_replication__dpc(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, const uint512_t *nhid,
	uint8_t rep_count)
{
	assert(dev != NULL);
	assert(chid != NULL);
	assert(nhid != NULL);

	replication_rq_t *rq = je_malloc(sizeof(replication_rq_t));
	if (rq == NULL)
		return -ENOMEM;
	rq->dev = dev;
	rq->ttag = ttag;
	rq->hash_type = hash_type;
	rq->chid = *chid;
	rq->nhid = *nhid;
	rq->rep_count = rep_count;

	struct repdev_call *call = je_calloc(1, sizeof(struct repdev_call));
	if (call == NULL) {
		je_free(rq);
		return -ENOMEM;
	}
	call->method = enqueue_replication__async;
	call->args[0] = rq;
	QUEUE_INIT(&call->item);
	uv_mutex_lock(&dev->call_mutex);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	uv_mutex_unlock(&dev->call_mutex);
	uv_async_send(&dev->call_async);
	return 0;
}

struct rep_count_verify_data {
	uint512_t chid;
	uint512_t nhid;
	type_tag_t ttag;
	crypto_hash_t hash_type;
	struct repdev *dev;
	uint8_t rep_count;
	int completed;
	uv_cond_t wait_cond;
	uv_mutex_t wait_mutex;

	/* set as a result of ngrequest-count */
	int32_t actual_count;
	uint128_t *vdevs;
	uint64_t generation;
	int stable_version;
};

int enqueue_replication(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, const uint512_t *nhid,
	uint8_t rep_count)
{
	char chidstr[UINT512_BYTES * 2 + 1];
	/* Mark blob for replication */
	int err = -ENOMEM;
	rtbuf_t *rb = NULL;
	uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);

	log_trace(lg, "Dev(%s): ttag %s chid %s", dev->name,
	    type_tag_name[ttag], chidstr);

	msgpack_p *p = msgpack_pack_init();
	if (!p) {
		log_error(lg, "Rep Count CB(%s, %s), msgpack init nomem",
			dev->path, chidstr);
		goto out;
	}
	err = msgpack_pack_array(p, 5);
	if (err) {
		log_error(lg, "Rep Count CB(%s, %s), pack arr err %d",
			dev->path, chidstr, err);
		goto out;
	}
	err = replicast_pack_uint512(p, chid);
	if (err) {
		log_error(lg, "Rep Count CB(%s, %s), pack chid err %d",
			dev->path, chidstr, err);
		goto out;
	}
	err = replicast_pack_uint512(p, nhid);
	if (err) {
		log_error(lg, "Rep Count CB(%s, %s), pack nhid err %d",
			dev->path, chidstr, err);
		goto out;
	}
	err = msgpack_pack_uint32(p, (uint32_t)ttag);
	if (err) {
		log_error(lg, "Rep Count CB(%s, %s), pack ttag err %d",
			dev->path, chidstr, err);
		goto out;
	}
	err = msgpack_pack_uint32(p, (uint32_t)hash_type);
	if (err) {
		log_error(lg, "Rep Count CB(%s, %s), pack ttag err %d",
			dev->path, chidstr, err);
		goto out;
	}
	err = msgpack_pack_uint8(p, rep_count);
	if (err) {
		log_error(lg, "Rep Count CB(%s, %s), pack rep_count err %d",
			dev->path, chidstr, err);
		goto out;
	}
	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);
	rb = rtbuf_init_mapped(&buf, 1);
	if (!rb) {
		log_error(lg, "Rep Count CB(%s, %s), rtbuf init nomem",
			dev->path, chidstr);
		err = -ENOMEM;
		goto out;
	}
	err = reptrans_put_blob(dev, TT_REPLICATION_QUEUE,
	    HASH_TYPE_DEFAULT, rb, (uint512_t*)chid, 0);

out:
	if (rb)
		rtbuf_destroy(rb);
	if (p)
		msgpack_pack_free(p);
	return err;
}

static int
dev_rep_count__callback(void *data, int32_t actual_count, uint128_t *vdevs,
    uint64_t generation_max, int stable_version)
{
	struct rep_count_verify_data *rd =
	    (struct rep_count_verify_data *)data;

	assert(rd != NULL);

	/* set the result */
	rd->actual_count = actual_count;
	rd->vdevs = vdevs;
	rd->generation = generation_max;
	rd->dev->ngcount_delay = get_timestamp_us() - rd->dev->ngcount_delay;
	uv_mutex_lock(&rd->wait_mutex);
	rd->completed = 1;
	rd->stable_version = stable_version;
	uv_cond_signal(&rd->wait_cond);
	uv_mutex_unlock(&rd->wait_mutex);
	return 0;
}

static void
reptrans_dev_async_call__verify_one(struct repdev_call *c)
{
	struct rep_count_verify_data *data = c->args[0];
	assert(data != NULL);

	data->dev->ngcount_delay = get_timestamp_us();
	int err = ngrequest_count(data->dev, data->hash_type, &data->chid,
	    &data->nhid, data->rep_count, data->ttag, data->generation,
	    dev_rep_count__callback, data);
	if (err && !data->dev->terminating) {
		data->dev->ngcount_delay = get_timestamp_us() -
				data->dev->ngcount_delay;
		char chidbuf[UINT512_BYTES * 2 + 1];
		uint512_dump(&data->chid, chidbuf, UINT512_BYTES * 2 + 1);
		log_warn(lg, "Error %d while verifying chid %s for rep_count %d",
			err, chidbuf, data->rep_count);
		/* Here we cannot let GC remove a VBR, so fake the count */
		assert(err < 0);
		data->actual_count = err;
		uv_mutex_lock(&data->wait_mutex);
		data->completed = 1;
		uv_cond_signal(&data->wait_cond);
		uv_mutex_unlock(&data->wait_mutex);
	}
}

int ngcount_chunks(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t *chid, const uint512_t *nhid, int rep_count,
	uint128_t** vdevs, uint64_t generation, uint64_t* generation_max_out,
	int* stable_version)
{
	int err = 0;

	ccowd_wait_for_fhrebuild_term(&dev->terminating);
	if (dev->terminating)
		return -ENODEV;

	struct repdev_call *call = je_calloc(1, sizeof(struct repdev_call));
	if (call == NULL)
		return -ENOMEM;

	struct rep_count_verify_data *rd = je_calloc(1, sizeof (*rd));
	if (rd == NULL) {
		je_free(call);
		return -ENOMEM;
	}
	rd->dev = dev;
	rd->rep_count = rep_count;
	if (chid) {
		assert(ttag != TT_NAMEINDEX);
		rd->chid = *chid;
	} else
		assert(ttag == TT_NAMEINDEX);
	assert(nhid);
	rd->nhid = *nhid;
	rd->ttag = ttag;
	rd->hash_type = hash_type;
	rd->rep_count = rep_count;
	rd->completed = 0;
	rd->generation = generation;
	uv_cond_init(&rd->wait_cond);
	uv_mutex_init(&rd->wait_mutex);
	usleep(dev->ngcount_delay_avg);

	/* Send message to device */
	call->method = reptrans_dev_async_call__verify_one;
	call->args[0] = rd;
	QUEUE_INIT(&call->item);
	uv_mutex_lock(&dev->call_mutex);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	uv_mutex_unlock(&dev->call_mutex);
	uv_async_send(&dev->call_async);

	/* Wait for ngrequest_count() result */
	uv_mutex_lock(&rd->wait_mutex);
	while (!rd->completed && !dev->terminating)
		uv_cond_timedwait(&rd->wait_cond, &rd->wait_mutex, 100000000LL);
	uv_mutex_unlock(&rd->wait_mutex);

	if (dev->ngcount_delay > NGCOUNT_MAX_DELAY_US)
		dev->ngcount_delay = NGCOUNT_MAX_DELAY_US;

	dev->ngcount_delay_avg = avg_ring_update(&dev->ngcount_avg_samples,
	    dev->ngcount_delay/4);

	int32_t actual_count = -1;
	if (!dev->terminating) {
		actual_count = rd->actual_count;
	}

	if (generation_max_out)
		*generation_max_out = rd->generation;

	if (stable_version)
		*stable_version = rd->stable_version;

	if (vdevs)
		*vdevs = rd->vdevs;
	else
		je_free(rd->vdevs);

	uv_cond_destroy(&rd->wait_cond);
	uv_mutex_destroy(&rd->wait_mutex);
	je_free(rd);

	if (actual_count >= 0) {
		uint64_t delay = reptrans_perf_limiter_update(&dev->ngcount_limiter);
		usleep(delay);
	}

	return actual_count;
}


int
nglocate_chunk(struct repdev* dev, struct chunk_info* info, uint512_t* nhid,
	struct backref* vbr, uint64_t attr_mask, size_t vbrs_max, uint32_t mode) {
	int err = ec_locate_chunk_ext(dev, info, nhid, vbr, attr_mask, vbrs_max,
		mode);
	if (!err) {
		uint64_t delay = reptrans_perf_limiter_update(&dev->ngcount_limiter);
		usleep(delay);
	}
	return err;
}


struct fd_cmp_arg {
	struct lvdev** lvdevs;
	int n_devs;
	int policy;
};

static int
fd_cmp_cb(const void* a, const void *b, void *arg) {
	int rc = 0;
	struct lvdev** lvdeva = (struct lvdev**)a;
	struct lvdev** lvdevb = (struct lvdev**)b;
	struct fd_cmp_arg* zarg = arg;
	switch(zarg->policy) {
		case FD_ANY_FIRST:
			/* Shouldn't happen. In either case return 0*/
			break;

		case FD_SERVER:
			rc = uint128_cmp(&(*lvdeva)->server->id,
				&(*lvdevb)->server->id);
			break;

		case FD_ZONE:
			if ((*lvdeva)->server->zone > (*lvdevb)->server->zone)
				rc = 1;
			if ((*lvdeva)->server->zone < (*lvdevb)->server->zone)
				rc = -1;
			break;

		default:
			log_error(lg, "Unknown failure domain %d",
				zarg->policy);
	}
	return rc;
}

static int
reptrans_is_lowest_vdev_id(const uint128_t* cur_vdev, uint128_t* vdevs, int n_devs) {
	int rc = 1;
	for (int i = 0; i < n_devs; i++) {
		if (uint128_cmp(cur_vdev, vdevs + i) > 0) {
			rc = 0;
			break;
		}
	}
	return rc;
}

static int
reptrans_chunk_delete_policy_check(const uint128_t* cur_vdevid,
	uint128_t* vdevids, int n_devs, int policy) {
	char vdevstr[UINT128_BYTES*2+1];
	struct lvdev *lvdevs[n_devs];
	/* Cannot remove any single chunk */
	if (n_devs <= 1)
		return 0;

	/* If policy is VDEV, then just pick up the one with minimal VDEV Id
	 */
	if (policy == FD_ANY_FIRST) {
		return reptrans_is_lowest_vdev_id(cur_vdevid, vdevids, n_devs);
	}

	/*
	 * Trying to find 2 or more VDEVs that belong to the same
	 * host/zone. If found, then minimal VDEV ID has to be selected
	 * only among them. Otherwise use all VDEV IDs to find minimal one
	 */
	ccowd_fhready_lock(FH_LOCK_READ);
	for (int i = 0; i < n_devs; i++) {
		lvdevs[i] = vdevstore_get_lvdev(SERVER_FLEXHASH->vdevstore,
			vdevids + i);
		/* Cannot find a VDEV ID, something went wrong. Do not remove
		 * copies in this case
		 */
		if (!lvdevs[i]) {
			char vdevstr[UINT128_BYTES*2+1];
			uint128_dump(vdevids + 1, vdevstr, UINT128_BYTES*2+1);
			log_error(lg, "Delete policy check error: "
				"cannot find VDEV ID %s", vdevstr);
			ccowd_fhready_unlock(FH_LOCK_READ);
			return 0;
		}
	}

	/* Sort according to failure domain */
	struct fd_cmp_arg zarg = {
		.lvdevs = lvdevs,
		.n_devs = n_devs,
		.policy = policy
	};
	qsort_r(lvdevs, n_devs, sizeof(lvdevs[0]), fd_cmp_cb, &zarg);
	int pos_first = 0, pos_last = 0;
	for (int i = 1; i < n_devs; i++) {
		int match = 0;
		if (policy == FD_SERVER) {
			match = uint128_cmp(&lvdevs[i-1]->server->id,
					&lvdevs[i]->server->id) == 0;
		} else {
			match = lvdevs[i-1]->server->zone == lvdevs[i]->server->zone;
		}
		if (match)
			pos_last = i;
		if ((!match || i == n_devs-1) && (pos_last > pos_first)) {
			/*  At least two replicas are located in the
			 *  same host/zone. Check if current VDEV
			 *  belongs to the domain/zone. Allow
			 *  removal if the VDEV ID is the smallest one.
			 */
			int dev_found = 0;
			int exist_smaller_vdev = 0;
			for (int j = pos_first; j <= pos_last; j++) {
				int res = uint128_cmp(cur_vdevid,
					&lvdevs[j]->vdevid);
				if (res == 0)
					dev_found = 1;
				if (res > 0) {
					exist_smaller_vdev = 1;
					break;
				}
			}
			if (dev_found && !exist_smaller_vdev) {
				ccowd_fhready_unlock(FH_LOCK_READ);
				return 1;
			}
		}
		if (!match)
			pos_last = pos_first = i;
	}
	ccowd_fhready_unlock(FH_LOCK_READ);
	return 0;
}

static int
qsort_uint128_cmp(const void *a, const void *b) {
	uint128_t* a128 = (uint128_t*)a;
	uint128_t* b128 = (uint128_t*)b;
	return uint128_cmp(a128, b128);
}

int
reptrans_get_effective_rep_count(const uint128_t* vdev_ids, size_t n_ids,
	int failure_domain) {

	if (!n_ids)
		return 0;

	if (failure_domain == FD_ANY_FIRST)
		return n_ids;

	uint128_t* fd_ids = je_calloc(n_ids, sizeof(uint128_t));
	if (!fd_ids)
		return -ENOMEM;

	int eRC = 1;
	/* Collect hosts/zones ID */
	for (size_t i = 0; i < n_ids; i++) {
		struct lvdev *lv = vdevstore_get_lvdev(SERVER_FLEXHASH->vdevstore,
			(uint128_t*)(vdev_ids + i));
		if (!lv) {
			char vdevstr[UINT128_BYTES*2+1];
			uint128_dump(vdev_ids + i, vdevstr, UINT128_BYTES*2+1);
			log_error(lg, "eRC calc error: "
				"cannot find VDEV ID %s", vdevstr);
			je_free(fd_ids);
			return -ENODEV;
		}
		switch(failure_domain) {
			case FD_SERVER:
				fd_ids[i] = lv->server->id;
				break;
			case FD_ZONE:
				fd_ids[i].l = lv->server->zone;
		}
	}
	/* Calculate eRC */
	qsort(fd_ids, n_ids, sizeof(uint128_t), qsort_uint128_cmp);
	for (size_t i = 1; i < n_ids; i++) {
		if (!uint128_cmp(fd_ids + i, fd_ids + i - 1))
			continue;
		eRC++;
	}
	je_free(fd_ids);
	return eRC;
}

static int
vbr_delete_nonec_iterator_cb (struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, uv_buf_t* vbr_buf, const struct backref* vbr,
	void* arg) {
	rtbuf_t* values = arg;
	if (!(vbr->attr & VBR_ATTR_EC))
		rtbuf_add_alloc(values, vbr_buf, 1);
	return 0;
}

int
uint128_subset_remove(uint128_t* src, size_t n, uint128_t* what,
	size_t m, uint128_t** res, size_t* n_out) {
	/* Sort both arrays */
	uint128_t* new_array = je_calloc(n, sizeof(uint128_t));
	if (!new_array)
		return -ENOMEM;
	size_t len = 0;
	qsort(src, n, sizeof(uint128_t), qsort_uint128_cmp);
	qsort(what, m, sizeof(uint128_t), qsort_uint128_cmp);
	size_t i = 0, j = 0;
	while (i < n) {
		if (uint128_cmp(src+i, what + j)) {
			/* Doesn't match, adding output */
			new_array[len++] = src[i];
		} else if (j < m - 1)
			j++;
		i++;
	}
	*n_out = len;
	if (len)
		*res = new_array;
	else
		je_free(new_array);
	return 0;
}

static int
dev_rep_count_verify_one(space_reclaim_work_t *work, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, uv_buf_t *val,
	uint512_t *nhid, int rep_count)
{
	struct repdev *dev = work->dev;
	int to_be_removed = 0, err = 0;
	double utilization = 0;
	int is_manifest = ttag == TT_CHUNK_MANIFEST || ttag == TT_VERSION_MANIFEST;

	if (!dev->__vtbl)
		return -EPERM;

	ccow_t tc = reptrans_get_tenant_context(dev->rt, 0);
	if (!tc) {
		log_error(lg, "Error getting tenant context");
		return 0;
	}
	int fd = tc->failure_domain;
	reptrans_put_tenant_context(dev->rt, tc);

	char chidbuf[UINT512_BYTES * 2 + 1];
	uint512_dump(chid, chidbuf, UINT512_BYTES * 2 + 1);

	/* Look for replicas location*/
	struct chunk_info info = {
		.chid = *chid,
		.hash_type = hash_type,
		.ttype = ttag,
	};
	uint512_t* nh = ttag == TT_VERSION_MANIFEST ? nhid : NULL;
	err = nglocate_chunk(dev, &info, nh, NULL, 0, 1, LOCATE_FLAG_HAS_PM);
	if (err) {
		log_warn(lg, "Dev(%s) VBR %s locate error %d", dev->name,
		    chidbuf, err);
		return err;
	}
	int32_t total_count = info.n_vdevs;
	if (total_count <= 0) {
		/*
		 * An error or some chunks aren't verified.
		 * Try next time
		 */
		return total_count;
	}

	/* Consider only already verified chunks */
	for (int i = 0; i < total_count; i++) {
		if (!info.nvbrs[i]) {
			if (i < total_count - 1)
				memmove(info.vdevs+i, info.vdevs + i + 1,
					sizeof(uint128_t)*(total_count-i-1));
			info.n_vdevs--;
		}
	}
	int32_t actual_count = info.n_vdevs;

	if (is_manifest) {
		/*
		 * If some manifest replicas are parity protected, then first we need
		 * to find and remove ones without parity manifest(PM). They will be
		 * replicated later along with PM
		 */
		struct blob_stat bstat = {.size = 0};
		err = reptrans_blob_stat(dev, TT_PARITY_MANIFEST,
			HASH_TYPE_DEFAULT, chid, &bstat);
		if (err && !bstat.size && (info.flags & LOCATE_FLAG_HAS_PM) && actual_count > 1) {
			to_be_removed = 1;
			log_debug(lg, "Dev(%s) removing manifest %s "
				"without PM", dev->name, chidbuf);
			goto _check_and_rm;
		}
	}

	/*
	 * vdevs - array of VDEVs chunk copies are located on
	 * aRC - actual replication count. Number of VDEVs the chunk's copies located on
	 * eRC - effective replication count, number of unique hosts/zones chunk's copies located on
	 * RC - expected effective replication count.
	 *
	 * 1. aRC == eRC == RC. The best case, nothing to replicate or remove.
	 * 2. aRC > eRC. Have two or more copies of a chunk within the same host/zone.
	 *	Estimate if current VDEV belongs to such a host/zone and its
	 *	VDEV ID is minimal among all VDEVs in this host/zone. Remove the chunk
	 *	if condition meet.
	 * 3. eRC < RC. Replication required. Ensure that current VDEV has a
	 * 	minimal VDEV ID among all vdevs and start replication.
	 *
	 * 4. eRC > RC. Remove single redundant copy on a VDEV with minimal VDEV ID.
	 * 	Schedule removal only if condition p.2 failed.
	 * 	Allowed to remove only one chunk at a time.
	 *
	 */
	int eRC;
	SERVER_FLEXHASH_SAFE_CALL(eRC = reptrans_get_effective_rep_count(
		info.vdevs, actual_count, fd), FH_LOCK_READ);
	if (eRC < 0)
		return eRC;

	log_debug(lg, "Dev(%s): %s actual_count %d rep_count %d eRC %d chid %s nhid %lX",
	    dev->name, chidbuf, actual_count, rep_count, eRC, chidbuf, (*nhid).u.u.u);

	if (eRC == actual_count && rep_count == actual_count) {
		/* The best case, nothing to do, exiting */
		return 0;
	}
	work->n_erc++;
	if (total_count == actual_count && rep_count > eRC &&
		reptrans_is_lowest_vdev_id(&dev->vdevid, info.vdevs, actual_count) &&
		is_cluster_healthy(dev->rt, RT_SYSVAL_REPLICATION_COUNT)) {
		/* Replication required. Ensure that current VDEV has a
		*  minimal VDEV ID among all vdevs and start replication.
		*  Do replication only in a stale conditions
		*/
		if (!ccow_daemon->maintenance_ts ||
			ccow_daemon->maintenance_ts < get_timestamp_monotonic_us()) {
			if (eRC > 1) {
				int nfd = reptrans_get_row_fd_number(dev, ttag == TT_VERSION_MANIFEST ? nhid : chid);
				if (nfd < 0 && nfd >= rep_count) {
					return enqueue_replication(dev, ttag, hash_type, chid,
						nhid, rep_count);
				} else {
					log_debug(lg, "Dev(%s) chunk %s %s cannot be replicated now: eRC %d, RC %d, nFDs %d",
						dev->name, chidbuf, type_tag_name[ttag], eRC, rep_count, nfd);
					return 0;
				}
			} else {
				/* Emergency replication! */
				return -EXDEV;
			}
		}
	}
	if (ttag == TT_CHUNK_PAYLOAD) {
		/* Deletion is allowed only on a VDEV without a EC VBRs */
		struct chunk_info ec_info = info;
		ec_info.n_vdevs = 0;
		struct backref br = {
			.attr = VBR_ATTR_EC
		};
		err = nglocate_chunk(dev, &ec_info, nh, &br, VBR_ATTR_EC,
			1, LOCATE_MATCH_VBR_ATTR);
		if (err) {
			log_error(lg, "Dev(%s) ec_locate_chunk_ext error %d", dev->name, err);
			return err;
		}
		if (ec_info.n_vbrs_max) {
			if (ec_info.n_vbrs_min) {
				/* All VDEVs got EC VBRs, can't delete */
				log_debug(lg, "Dev(%s) data chunk %s is "
					"protected by a EC VBR on every %u "
					"VDEVs", dev->name, chidbuf,ec_info.n_vdevs);
				return 0;
			}
			/* There are some EC VBRs, exclude those VDEVs from list */
			size_t n = info.n_vdevs;
			for (size_t i = 0; i < n; i++) {
				for (size_t j = 0; j < ec_info.n_vdevs; j++) {
					if (!uint128_cmp(info.vdevs + i, ec_info.vdevs + j)
						&& ec_info.nvbrs[j]) {
						memmove(info.vdevs+i, info.vdevs + i + 1,
							sizeof(uint128_t)*(n-i-1));
						info.n_vdevs--;
					}
				}
			}
			log_debug(lg, "Dev(%s) excluded %lu EC VBRs", dev->name,
				n - info.n_vdevs);
		}
	}

	if (actual_count > eRC) {
		struct blob_stat bstat;
		/*
		* Have two or more copies of a chunk within the same host/zone.
		* Estimate if current VDEV belongs to such a host/zone and its
		* VDEV ID is minimal among all VDEVs in this host/zone. Remove the chunk
		* if condition meet. Don't remove a manifest which is scheduled
		* for EC encoding.
		**/
		to_be_removed = reptrans_chunk_delete_policy_check(&dev->vdevid,
				info.vdevs, info.n_vdevs, fd);
		if (to_be_removed && (!is_manifest || (reptrans_blob_stat(dev,
			TT_ENCODING_QUEUE, HASH_TYPE_DEFAULT, chid, &bstat) == -ENOENT))) {
			log_debug(lg, "Dev(%s) removing VBR of chunk %s "
				"which has a duplicate on this FD",
				dev->name, chidbuf);
		} else
			to_be_removed = 0;
	}
	if (!to_be_removed && eRC > rep_count) {
		struct blob_stat bstat;
		int lowest_vdevid = reptrans_is_lowest_vdev_id(&dev->vdevid,
			info.vdevs, info.n_vdevs);
		if (lowest_vdevid && (!is_manifest || (reptrans_blob_stat(dev,
			TT_ENCODING_QUEUE, HASH_TYPE_DEFAULT, chid, &bstat) == -ENOENT))) {
			/* Remove single redundant copy on a VDEV with minimal VDEV ID.
			 * Allowed to remove only one chunk at a time.
			 */
			to_be_removed = 1;
			log_debug(lg, "Dev(%s) removing VBR for chunk %s "
				"which has ERC %d bigger than expected %d",
				dev->name, chidbuf, eRC, rep_count);
		}
	}

_check_and_rm:

	utilization = reptrans_get_utilization(dev);
	if (to_be_removed && utilization >= dev->bg_config->dev_utilization_threshold_low) {
		/* VBR sharing disabled to check if it's really required */
#if 0
		/*
		 * Just in case we have a VBR that nobody else has
		 */
		err = reptrans_replicate_vbrs(dev, ttag, hash_type, chid,
			nhid, rep_count);
		if (err) {
			log_error(lg, "Space Reclaim(%s, %s, %s, %s): "
				"failed to replicate VBRs",
				dev->name, chidbuf, type_tag_name[ttag],
				hash_type_name[hash_type]);
			return err;
		}
#endif
		log_info(lg,
			"Space Reclaim(%s, %s, %s, %s): "
			"rep count exceeded, deleting",
			dev->name, chidbuf, type_tag_name[ttag],
			hash_type_name[hash_type]);

		if (ttag == TT_CHUNK_PAYLOAD) {
			/*
			 * for data chunks we are removing only non-EC VBRs
			 * which could be added since we started the iteration.
			 * Chunk will be removed on the next SR cycle if there
			 * aren't any EC VBRs
			 */
			rtbuf_t* rb = rtbuf_init_empty();
			if (!rb)
				return -ENOMEM;
			err = reptrans_vbrs_iterate(dev, chid, hash_type,
				vbr_delete_nonec_iterator_cb, rb);
			if (!err && rb->nbufs) {
				repdev_status_t status = reptrans_dev_get_status(dev);
				if(status == REPDEV_STATUS_UNAVAILABLE)
					err = -EACCES;
				else
					err = reptrans_delete_blob_value(dev,
					TT_VERIFIED_BACKREF, hash_type,
					chid, rb->bufs, rb->nbufs);
				log_debug(lg, "Dev(%s) %s removed %lu non-EC VBRs",
					dev->name, chidbuf, rb->nbufs);
			} else if (err) {
				log_error(lg,
					"Dev(%s) error removing VBR for chunk %s",
					dev->name, chidbuf);
			}
			rtbuf_destroy(rb);
		} else {
			/* Manifests removed in-place */
			err = reptrans_delete_blob(dev, TT_VERIFIED_BACKREF, hash_type,
				chid);
			log_debug_vbr(lg, "Dev(%s): del VBR %s", dev->name, chidbuf);
			if (err != 0)
				return err;
			err = reptrans_delete_manifest(dev, ttag, hash_type, chid);
		}
	}
	return err;
}

struct deferred_delete_entry {
	uint8_t nameindex;
	uint512_t chid;
	uint512_t nhid;
	uint8_t rep_cnt;
	crypto_hash_t vbr_hash_type;
	uint16_t number_of_versions;
	struct deferred_delete_entry* next;
	union {
		struct vlentry version;
		struct backref vbr;
	};
};

struct gc_work_arg {
	struct bg_job_entry* job;
	struct deferred_delete_entry* tail;
	size_t qsize;
	struct chunk_info last_info; /* Last CHID processed by the GC */
	int vbr_replication_required; /* Non-zero if VBRs for the last CHID require replication */
};

static int
gc_deferred_delete(struct repdev* dev, struct deferred_delete_entry* e);

static int
reptrans_validate_verified_br(struct repdev *dev, const uint512_t* chid,
	struct backref *vbr, crypto_hash_t vbr_hash_type,
	struct gc_work_arg* arg)
{
	assert(dev != NULL);
	assert(vbr != NULL);
	gc_work_t* work = (gc_work_t*)arg->job->data;
	assert(work);

	int err = 0;
	uint512_t vmchid = *chid;
	struct vmmetadata md = {.nhid = uint512_null };
	rtbuf_t* rb = NULL;
	/* Initiate the top-down delete if there is no nameindex entries for this VM */
	if (vbr->ref_type == TT_NAMEINDEX) {
		err = reptrans_get_blob(dev, TT_VERSION_MANIFEST, HASH_TYPE_DEFAULT,
			chid, &rb);
		if (err) {
			/* Stale backref, removing */
			err = -ESTALE;
			goto _exit;
		}
		assert(rb);
		/*
		 * Check if there any other VBRs. The VM can be
		 * referenced by a snapview object.
		 */
		size_t n_vbrs = 0;
		err = reptrans_get_chunk_count_limited(dev, HASH_TYPE_DEFAULT,
			TT_VERIFIED_BACKREF, (uint512_t*)chid, 2, &n_vbrs);
		if (err || n_vbrs > 1) {
			if (err) {
				if (err == -ENOENT)
					log_warn(lg, "Dev(%s) error getting VBRs count: %d",
						dev->name, err);
				else
					log_error(lg, "Dev(%s) error getting VBRs count: %d",
						dev->name, err);
			}
			err = 0;
			goto _replicate_vbrs;
		}

		err = replicast_get_metadata(rb, &md);
		if (err) {
			log_error(lg, "VM metadata unpack error");
			err = 0;
			goto _exit;
		}

		// Check for delete after header, and number_of_versions == 1
		if (md.object_delete_after > 0 && md.object_deleted == 0 && md.number_of_versions == 1) {
			uint8_t out_of_date = (md.object_delete_after*1000000) < get_timestamp_us();

			if (out_of_date) {
				uint64_t generation_max = 0;
				int32_t count = ngcount_chunks(dev, TT_NAMEINDEX,
					HASH_TYPE_DEFAULT, NULL, &vbr->name_hash_id, 1,
					NULL, 0, &generation_max, NULL);

				// Expunge the latest version
				if (count > 0 && md.txid_generation == generation_max) {
					log_trace(lg, "reptrans_validate_verified_br bid: %s, oid: %s, gen: %lu, count: %u, max_gen: %lu, number_of_versions: %u",
						md.bid, md.oid, md.txid_generation, count, generation_max, md.number_of_versions);
					err = ngrequest_purge(dev, md.hash_type, &md.nhid,
						md.txid_generation, 0, 0, 0);
					if (err) {
						log_error(lg, "Delete after(%s) error purging bid: %s, oid: %s, version: %ld error: %d",
							dev->name, md.bid, md.oid, md.txid_generation, err);
						err = 0;
						goto _exit;
					}

					md.object_deleted = RT_DELETED_EXPUNGED;
					err = reptrans_put_trlog(dev, &md, &vmchid, RD_ATTR_OBJECT_REPLACE, NULL, NULL, 0, NULL, NULL);
					if (err) {
						log_error(lg, "Delete after(%s) trlog put error bid: %s, oid: %s, version: %ld error: %d",
							dev->name, md.bid, md.oid, md.txid_generation, err);
					}
					err = 0;
					goto _exit;
				}
			}  // if out_of_date
		}

		// Check for deleted header, and number_of_versions == 1
		if (md.object_deleted == 1 && md.number_of_versions == 1) {
			uint8_t out_of_date = ((md.uvid_timestamp + DELETE_QUARANTINE_TIMEOUT) < get_timestamp_us());

			if (out_of_date) {
				log_trace(lg, "delete_cleanup expunge bid: %s, oid: %s, gen: %lu, uvid: %lu, deleted: %u, number_of_versions: %u",
					md.bid, md.oid, md.txid_generation, md.uvid_timestamp, md.object_deleted, md.number_of_versions);

				// Expange the deleted version
				err = ngrequest_purge(dev, md.hash_type, &md.nhid,
					md.txid_generation, md.txid_generation, md.uvid_timestamp, 0);

				if (err) {
					rtbuf_destroy(rb);
					log_error(lg, "Delete (%s) error purging bid: %s, oid: %s, version: %ld error: %d",
						dev->name, md.bid, md.oid, md.txid_generation, err);
					return 0;
				}
			}  // if out_of_date
		}

		struct vlentry version = {
			.uvid_timestamp = md.uvid_timestamp,
			.uvid_src_guid = md.uvid_src_guid,
			.uvid_src_cookie = md.uvid_src_cookie,
			.generation = md.txid_generation,
			.content_hash_id = *chid,
			.object_deleted = md.object_deleted,
			.logical_size = md.logical_size
		};

		char nhidstr[UINT512_BYTES*2+1];
		uint512_dump(&vbr->name_hash_id, nhidstr, UINT512_BYTES*2+1);
		log_debug(lg, "Dev(%s) top-down lookup %s gen %lu\n",
			dev->name, nhidstr, md.txid_generation);

		uint64_t gen_max = 0;
		int stable_version = 0;
		int32_t actual_count = ngcount_chunks(dev, TT_NAMEINDEX,
			HASH_TYPE_DEFAULT, NULL, &vbr->name_hash_id, 1,
			NULL, md.txid_generation, &gen_max, &stable_version);

		/* VBR removal may lead to data loss. So we need to be sure that
		 * parent manifest/version has been removed and
		 * cluster is in a consistent state. To do that we implemented
		 * two stage removal confirmation. During first stage we are looking
		 * for removal candidates and put them to a deferred GC list. Every candidate
		 * will be checked by a deferred worker after few seconds after a GC finish.
		 * If lack of a parent is confirmed twice, then a VBR will be removed.
		 */
		int outdated_version = (gen_max > md.number_of_versions) &&
			(gen_max - md.number_of_versions >= md.txid_generation);
		if ((!stable_version && (!actual_count || outdated_version)) && is_cluster_healthy(dev->rt, vbr->rep_count)) {
			err = 0;
			struct deferred_delete_entry* del_arg = je_calloc(1, sizeof(*del_arg));
			if (!del_arg) {
				log_error(lg, "Dev(%s) out of memory", dev->name);
				goto _exit;
			}
			del_arg->nameindex = 1;
			del_arg->chid = *chid;
			del_arg->nhid = vbr->name_hash_id;
			del_arg->version = version;
			del_arg->next = arg->tail;
			del_arg->vbr_hash_type = vbr_hash_type;
			del_arg->rep_cnt = vbr->rep_count;
			del_arg->number_of_versions = md.number_of_versions;
			arg->tail = del_arg;
			arg->qsize++;
			work->n_vers_purged++;
			goto _exit;
		}
	} else {
		int actual_count = ngcount_chunks(dev, vbr->ref_type, vbr->ref_hash,
			&vbr->ref_chid, &vbr->name_hash_id, 1, NULL, 0, NULL, NULL);
		if (!actual_count && is_cluster_healthy(dev->rt, vbr->rep_count)) {
			err = 0;
			struct deferred_delete_entry* del_arg = je_calloc(1, sizeof(*del_arg));
			if (!del_arg) {
				log_error(lg, "Dev(%s) out of memory", dev->name);
				goto _exit;
			}
			del_arg->vbr = *vbr;
			del_arg->next = arg->tail;
			arg->tail = del_arg;
			arg->qsize++;
			del_arg->chid = *chid;
			del_arg->vbr_hash_type = vbr_hash_type;
			del_arg->rep_cnt = vbr->rep_count;
			work->n_garbage_chunks++;
			goto _exit;
		}
	}

_replicate_vbrs:;

	type_tag_t chunk_ttag = reptrans_backref_attr2ttag(vbr->attr);
	if (chunk_ttag == TT_INVALID) {
		/*
		 * Previous VBR version (prior nedge 2.2) didn't keep chunk ttag
		 * in VBR and such VBRs cannot be replicated
		 */
		err = 0;
		goto _exit;
	}
	uint512_t nhid = chunk_ttag == TT_VERSION_MANIFEST ? vbr->name_hash_id : uint512_null;

	/* Skip replication of chunks that are a part of parity-protected manifest */
	if (vbr->attr & VBR_ATTR_EC)
		goto _exit;

	/* If we haven't seen this chunk before, then check if we want to do VBR replication */
	if (uint512_cmp(&arg->last_info.chid, chid)) {
		arg->last_info.chid = *chid;
		arg->last_info.hash_type = vbr_hash_type;
		arg->last_info.ttype = chunk_ttag;
		arg->vbr_replication_required = 0;
		/* We want to do VBR replication only if VBRs are unevenly distributed*/
		/* locate with coarse VBR counting. It must be fast */
		uint512_t* nh = chunk_ttag == TT_VERSION_MANIFEST ? &nhid : NULL;
		err = ec_locate_chunk(dev, &arg->last_info, nh, ~0UL);
		if (err) {
			log_warn(lg, "Dev(%s) chunk locate error %d, skipping VBR replication",
				dev->name, err);
			err = 0;
			goto _exit;
		}
		if (arg->last_info.n_vdevs > 1 && arg->last_info.n_vbrs_min != arg->last_info.n_vbrs_max
				&& arg->last_info.n_vbrs_max > 1)
			arg->vbr_replication_required = 1;
	}

	if (arg->vbr_replication_required) {
		struct chunk_info ci_vbr = arg->last_info;
		arg->last_info.n_vdevs = 0;
		/* Locate the chunk and the VBR */
		uint512_t* nh = chunk_ttag == TT_VERSION_MANIFEST ? &nhid : NULL;
		err = nglocate_chunk(dev, &ci_vbr, nh, vbr, 0, 1, LOCATE_MATCH_VBR);
		if (err) {
			log_warn(lg, "Dev(%s) locate VBR error %d", dev->name,
				err);
			err = 0;
			goto _exit;
		}

		/* For each VDEV without the VBR do a targeted VBR propagation */
		for (size_t i = 0; i < ci_vbr.n_vdevs; i++) {
			/* Skip if there is the VBR copy */
			if (ci_vbr.nvbrs[i] > 0)
				continue;

			/* Skip if there were no VBRs to avoid races with the space reclaim*/
			int skip = 0;
			for (size_t j = 0; j < arg->last_info.n_vdevs; j++) {
				if (!uint128_cmp(arg->last_info.vdevs + j, ci_vbr.vdevs + i) &&
					!arg->last_info.nvbrs[j]) {
					skip = 1;
					break;
				}
			}
			if (skip)
				continue;

			/* Make sure the VDEV is alive */
			ccowd_fhready_lock(FH_LOCK_READ);
			struct vdevstore *vdevstore = SERVER_FLEXHASH->vdevstore;
			int idx = flexhash_getvdev_index(SERVER_FLEXHASH, ci_vbr.vdevs + i);
			if (idx < 0 || vdevstore->lvdevlist[idx].state != VDEV_STATE_ALIVE) {
				ccowd_fhready_unlock(FH_LOCK_READ);
				continue;
			}
			ccowd_fhready_unlock(FH_LOCK_READ);
			struct verification_request vreq = {
				.chid = *chid,
				.vtype = RT_VERIFY_NORMAL | RT_VERIFY_SKIP_UNVERIFIED,
				.ttag = chunk_ttag,
				.htype = vbr_hash_type,
				.vbr = *vbr,
				.target_vdevid = ci_vbr.vdevs[i],
				.nhid = nhid
			};

#if 1
			err = reptrans_propagate_verification_request_targeted(dev, ci_vbr.vdevs + i, &vreq);
#else
			err = reptrans_enqueue_batch_request(dev, NULL, &vreq);
#endif
			if (err)
				log_error(lg, "Dev(%s) VBR replication: enqueue batch req err %d",
					dev->name, err);
			err = 0;
		}
	}

_exit:
	if (arg->qsize > 100) {
		gc_deferred_delete(dev, arg->tail);
		arg->tail = NULL;
		arg->qsize = 0;
		log_debug(lg, "Dev(%s) submitted a deferred delete work", dev->name);
	}
	if (rb)
		rtbuf_destroy(rb);

	return err;
}

static int
gc_iterator_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *chid, uv_buf_t *val, void *param)
{
	msgpack_u *u = NULL;
	char chidstr[UINT512_BYTES * 2 + 1];
	struct backref br;
	struct gc_work_arg* arg = param;
	assert(arg);

	uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);

	if (!dev->__vtbl)
		return -EPERM;

	struct bg_job_entry* job = arg->job;
	assert(job);

	gc_work_t* work = (gc_work_t*)job->data;
	assert(work);

	assert(ttag == TT_VERIFIED_BACKREF);

	if (bg_job_wait_resume(job, 10000))
		return -ENODEV;

	job->chunk_counter++;

	int err = -ENOMEM;
	/* 1. Unpack back reference */
	u =  msgpack_unpack_init(val->base, val->len, 0);
	if (!u) {
		log_error(lg, "Validate BR(%s, %s): unpack init failed",
		    dev->path, chidstr);
		return 0;
	}
	err = reptrans_unpack_vbr(u, &br);
	msgpack_unpack_free(u);
	if (err) {
		log_error(lg, "Validate BR(%s, %s): unpack VBR err %d",
		    dev->path, chidstr, err);
		return err;
	}
	if (br.ref_type == TT_PARITY_MANIFEST) {
		/* Parity chunk is a special case. The parity manifest
		 * is put after parity chunk(s). We need a room after a chunk is put
		 * before we start top-down lookup for reference.
		 */
		uint64_t ts = 0;
		err = reptrans_get_blob_ts(dev, TT_CHUNK_PAYLOAD, hash_type, chid,
			&ts);
		if (err) {
			log_error(lg, "Parity chunk %s absent", chidstr);
		} else {
			uint64_t dt = reptrans_get_timestamp(dev) - ts;
			if (dt < PARITY_MANIFEST_LAG_TIME*1000LL) {
				log_debug(lg, "Parity chunk %s GC skipped, dt %lu",
					chidstr, dt);
				return 0;
			}
		}
	}
	/* 2. Validate back reference.
	 *    For EC VBR double check if the cluster is healthy
	 */
	err = reptrans_validate_verified_br(dev, chid, &br, hash_type, arg);
	/* 3. Immediate delete Delete stale back reference */
	if (err == -ESTALE) {
		log_debug_vbr(lg, "Dev(%s): del stale VBR %s", dev->name,
		    chidstr);
		repdev_status_t status = reptrans_dev_get_status(dev);
		if(status == REPDEV_STATUS_UNAVAILABLE)
			err = -EACCES;
		else
			err = reptrans_delete_blob_value(dev, ttag, hash_type,
				chid, val, 1);
		if (err) {
			log_warn(lg, "Dev(%s): cannot delete blob %s value: %d",
			    dev->name, chidstr, err);
		}
	}
	return 0;
}

struct gc_deferred_arg {
	struct repdev* dev;
	uv_timer_t* tmr;
	struct deferred_delete_entry* tail;
};

static void
gc_deferred_work(void* arg) {
	struct gc_deferred_arg* darg = arg;
	struct repdev* dev = darg->dev;
	struct deferred_delete_entry* tail = darg->tail, *tmp;
	for(; tail; tmp = tail,tail = tail->next,je_free(tmp)) {
		/*
		 * We cannot process the deferred work if the VDEV isn't operational.
		 * Just drop the work
		 */
		repdev_status_t status = reptrans_dev_get_status(dev);
		if (dev->terminating ||
			status == REPDEV_STATUS_UNAVAILABLE ||
			status == REPDEV_STATUS_READONLY_FORCED ||
			status == REPDEV_STATUS_READONLY_FAULT)
			continue;
		if (tail->nameindex) {
			uint64_t gen_max = 0;
			int stable_version = 0;
			int32_t actual_count = ngcount_chunks(dev, TT_NAMEINDEX,
				HASH_TYPE_DEFAULT, NULL, &tail->nhid, 1,
				NULL, tail->version.generation, &gen_max, &stable_version);
			int outdated_version = (gen_max > tail->number_of_versions) &&
				(gen_max - tail->number_of_versions >= tail->version.generation);

			if (stable_version || (!outdated_version && actual_count) ||
				!is_cluster_healthy(dev->rt, tail->rep_cnt))
				continue;
			if (outdated_version) {
				log_debug(lg, "Dev(%s) found an outdated object version NHID %lX gen %lu",
					dev->name, tail->nhid.u.u.u, tail->version.generation);
				int err = reptrans_delete_version_entry(dev, HASH_TYPE_DEFAULT,
					&tail->nhid, &tail->version);
				if (err && err != -ENOENT)
					log_error(lg, "Dev(%s) cannot delete version entry NHID %lX\n",
						dev->name, tail->nhid.u.u.u);
			}
			int err = reptrans_notify_delete_version(dev, HASH_TYPE_DEFAULT,
				&tail->nhid, &tail->version);
			if (err) {
				log_error(lg, "Dev(%s) purge propagation error", dev->name);
			} else {
				char chidbuf[UINT512_BYTES * 2 + 1];
				uint512_dump(&tail->chid, chidbuf, UINT512_BYTES * 2 + 1);
				log_debug(lg, "Dev(%s) purge version %lu VM %s",
					dev->name, tail->version.generation, chidbuf);
			}
		} else {
			int actual_count = ngcount_chunks(dev, tail->vbr.ref_type, tail->vbr.ref_hash,
				&tail->vbr.ref_chid, &tail->vbr.name_hash_id, 1, NULL, 0, NULL, NULL);
			if (actual_count || !is_cluster_healthy(dev->rt, tail->rep_cnt))
				continue;
			uint8_t buf[1024];
			uv_buf_t ub_p = { .base = (char*)buf, .len = sizeof(buf) };
			uv_buf_t ub;
			msgpack_p p;
			msgpack_pack_init_p(&p, ub_p);
			int err = reptrans_pack_vbr(&p, &tail->vbr);
			if (!err) {
				char chidstr[UINT512_BYTES*2+1];
				uint512_dump(&tail->chid, chidstr, UINT512_BYTES*2 + 1);
				log_debug_vbr(lg, "Dev(%s): del stale VBR %lX -> %lX", dev->name,
					tail->chid.u.u.u, tail->vbr.ref_chid.u.u.u);
				msgpack_get_buffer(&p, &ub);
				repdev_status_t status = reptrans_dev_get_status(dev);
				if(status == REPDEV_STATUS_UNAVAILABLE)
					err = -EACCES;
				else
					err = reptrans_delete_blob_value(dev,
						TT_VERIFIED_BACKREF, tail->vbr_hash_type,
						&tail->chid, &ub, 1);
				if (err) {
					log_error(lg, "Dev(%s): cannot delete blob %s value: %d",
						dev->name, chidstr, err);
				}
			}
		}
	}
	log_debug(lg, "Dev(%s) GC deferred work done", dev->name);
}

static void
gc_deferred_timer_close_cb(uv_handle_t* handle)
{
	struct gc_deferred_arg* darg = handle->data;
	je_free(darg->tmr);
	je_free(darg);
}

static void
gc_deferred_work_done(void* arg, int status) {
	struct gc_deferred_arg* darg = arg;
	uv_timer_stop(darg->tmr);
	uv_close((uv_handle_t *)darg->tmr, gc_deferred_timer_close_cb);
}

static void
gc_deferred_delete_tmr_cb(uv_timer_t* handle, int status) {
	struct gc_deferred_arg* darg = handle->data;
	struct repdev* dev = darg->dev;

	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_LOW, gc_deferred_work,
		gc_deferred_work_done, darg);
}

void
gc_deferred_delete__async(struct repdev_call *c) {
	struct gc_deferred_arg* darg = (struct gc_deferred_arg*)c->args[0];
	struct repdev* dev = (struct repdev*)c->args[1];

	uv_timer_init(dev->loop, darg->tmr);
	uv_timer_start(darg->tmr, gc_deferred_delete_tmr_cb, 3000, 0);
}

static int
gc_deferred_delete(struct repdev* dev, struct deferred_delete_entry* e) {
	struct gc_deferred_arg* darg = je_calloc(1, sizeof (*darg));
	if (!darg) {
		log_error(lg, "Dev(%s) Out of memory", dev->name);
		return -ENOMEM;
	}
	darg->tmr = je_calloc(1, sizeof(uv_timer_t));
	if (!darg->tmr) {
		je_free(darg);
		log_error(lg, "Dev(%s) Out of memory", dev->name);
		return -ENOMEM;
	}
	darg->dev = dev;
	darg->tail = e;
	darg->tmr->data = darg;
	struct repdev_call *call = je_calloc(1, sizeof(struct repdev_call));
	if (call == NULL) {
		je_free(darg);
		return -ENOMEM;
	}
	call->method = gc_deferred_delete__async;
	call->args[0] = darg;
	call->args[1] = dev;
	if (dev->thread_id != pthread_self()) {
		QUEUE_INIT(&call->item);
		uv_mutex_lock(&dev->call_mutex);
		QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
		uv_mutex_unlock(&dev->call_mutex);
		uv_async_send(&dev->call_async);
	} else {
		gc_deferred_delete__async(call);
		je_free(call);
	}
	return 0;
}

static void
bg_gc_work(struct bg_job_entry* job, void* data)
{
	assert(data != NULL);

	gc_work_t *work = (gc_work_t *)data;
	assert(work != NULL);
	struct repdev *dev = work->dev;
	assert(dev != NULL);

	reptrans_set_thrname(dev, "bggc");
	struct gc_work_arg gc_arg = {
		.job = job,
		.tail = NULL,
		.qsize = 0,
		.last_info = { .chid = uint512_null },
		.vbr_replication_required = 0
	};

	int err = reptrans_iterate_blobs(dev, TT_VERIFIED_BACKREF,
		gc_iterator_cb, &gc_arg, 1);
	if (err && err != -ENODEV && err != -EAGAIN)
		log_error(lg, "dev %s gc verified backref error %d",
		    work->dev->path, err);

	if (!gc_arg.qsize && dev->terminating)
		return;

	if (dev->terminating && gc_arg.qsize) {
		struct deferred_delete_entry* tail = gc_arg.tail, *tmp;
		for(; tail; tmp = tail,tail = tail->next,je_free(tmp));
		return;
	}
	gc_deferred_delete(dev, gc_arg.tail);
}

static void
bg_gc_done(struct bg_job_entry* job, void* data) {
	assert(data != NULL);

	gc_work_t *work = (gc_work_t *)data;
	assert(work != NULL);
	bg_sched_set_counter(job, work->n_garbage_chunks, 0);
	bg_sched_set_counter(job, work->n_vers_purged, 1);
	je_free(work);
}

static int
bg_gc_init(struct bg_job_entry* job, void** pdata) {
	static const char* gc_counters[] = {
		"GARBAGE_COLLECTED",
		"VERSIONS_PURGED"};

	job->chunks_total = job->sched->dev->stats.ttag_entries[TT_VERIFIED_BACKREF];
	gc_work_t *work = je_calloc(1, sizeof(gc_work_t));
	assert(work != NULL);
	work->job = job;
	work->dev = job->sched->dev;
	bg_sched_register_counters(job, 2, gc_counters);
	*pdata = work;
	return 0;
}

static int
bg_gc_progress(struct bg_job_entry* job) {
	struct repdev* dev = job->sched->dev;
	if (dev->terminating ||
		!(job->status == BG_STATUS_PROGRESS ||
		job->status == BG_STATUS_PAUSED ||
		job->status == BG_STATUS_PREEMPTED))
		return -1;

	if (!job->chunks_total)
		return 1000;
	size_t ratio = job->chunk_counter*1000/job->chunks_total;
	if (ratio > 1000)
		ratio = 1000;
	return ratio;
}

static int
reptrans_scrub_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *chid, uv_buf_t *val, void *param) {
	char chidstr[UINT512_BYTES * 2 + 1];
	char refchidstr[UINT512_BYTES * 2 + 1];

	scrub_work_t *work = (scrub_work_t *)param;
	assert(work);
	struct bg_job_entry* job = work->job;

	uint512_t nhid;
	assert(job);

	assert(ttag == TT_VERSION_MANIFEST || ttag == TT_CHUNK_MANIFEST);

	if (bg_job_wait_resume(job, 1000000))
		return -ENODEV;

	uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);

	log_debug(lg, "Dev(%s) scrubbing manifest %s type %s",
		dev->path, chidstr, type_tag_name[ttag]);
	job->chunk_counter++;
	int err = -ENOMEM;
	/*
	 * Get VBR and extract rep. count
	 */
	rtbuf_t* vrb = NULL;
	err = reptrans_get_blob(dev, TT_VERIFIED_BACKREF, hash_type,
		chid, &vrb);
	if (err || !vrb) {
		/*
		 * VBR may not exist, probably scheduled for removal
		 * or verification is in progress. Won't check this manifest
		 */
		log_debug(lg, "Dev(%s) no VBR manifest %s type %s, skipping",
			dev->path, chidstr, type_tag_name[ttag]);
		return 0;
	}

	struct backref vbr;
	msgpack_u *u = msgpack_unpack_init(rtbuf(vrb, 0).base,
		rtbuf(vrb, 0).len, 0);
	err = reptrans_unpack_vbr(u, &vbr);
	msgpack_unpack_free(u);
	rtbuf_destroy(vrb);
	if (err) {
		log_error(lg, "Error during VBR unpack for "
			"mainifest CHID: %s, type: %s, dev: %s\n",
			chidstr, type_tag_name[ttag], dev->path);
		return 0;
	}
	/* In critical spit condition we shouldn't report error to a user.
	 * EC recovery may not be possible, too. So just skip the manifest.
	 */
	if (!is_cluster_healthy(dev->rt, vbr.rep_count))
		return 0;


	err = reptrans_check_parent(dev, &vbr);
	if (err) {
		if (err != -ENOENT) {
			log_error(lg, "Dev(%s) sccubber: parent lookup error %d",
				dev->name, err);
			return 0;
		}
		log_debug(lg, "Dev(%s) the manifest %s %s doesn't have a verified parent",
			dev->name, chidstr, type_tag_name[ttag]);
		return 0;
	}
	/*
	 * Extract chunk references
	 */
	rtbuf_t* rin = rtbuf_init_mapped(val, 1), *refs = NULL;
	if (ttag == TT_CHUNK_MANIFEST)
		replicast_unpack_cm_refs(rin, &refs, 0);
	else {
		struct vmmetadata md;
		err = replicast_get_metadata(rin, &md);
		if (!err) {
			if (md.object_deleted) {
				/*
				* VM with logical_deleted field set doesn't
				* have refentries
				*/
				rtbuf_destroy(rin);
				return 0;
			}
			err = replicast_get_refs(rin, &refs, 0);
			if (err)
				log_error(lg, "replicast_get_refs err=%d", err);
		} else
			log_error(lg, "replicast_get_metadata err=%d", err);
		nhid = md.nhid;
	}
	if (err) {
		log_error(lg, "Corrupted manifest CHID: %s, type: %s, dev: %p",
			chidstr, type_tag_name[ttag], dev);
		rtbuf_destroy(rin);
		return 0;
	}
	assert(refs != NULL);
	struct blob_stat bstat = {0};
	err = reptrans_blob_stat(dev, TT_PARITY_MANIFEST, HASH_TYPE_DEFAULT,
		chid, &bstat);
	int is_parity_protected = !err && bstat.size > 0;
	int corrupted = 0;
	/* check existence of the referenced chunks */
	for (size_t i = 0; ccow_daemon->scrub_signal_rcvd &&
	    !is_parity_protected && i < refs->nbufs; i++) {

		struct refentry *e =
			(struct refentry *)rtbuf(refs, i).base;

		/* Lookup only for data chunks and chunk manifests */
		uint8_t ref_ttag = ref_to_ttag[RT_REF_TYPE(e)];
		if (ref_ttag == TT_INVALID ||
			ref_ttag == TT_VERSION_MANIFEST ||
			RT_REF_TYPE(e) == RT_REF_TYPE_INLINE_VERSION ||
			RT_REF_TYPE(e) == RT_REF_TYPE_INLINE_MANIFEST)
			continue;

		bg_replicast_delay(dev, 500000, job);

		work->n_refs++;

		int actual_count = ngcount_chunks(dev, ref_ttag, RT_REF_HASH_TYPE(e),
			&e->content_hash_id, &nhid, 1, NULL, 0, NULL, NULL);

		if (actual_count < 0) {
			uint512_dump(&e->content_hash_id, refchidstr, UINT512_BYTES * 2 + 1);
			log_warn(lg, "ngcount_chunks returned error (likely networking): CHID: %s, type: %s, err: %d",
				refchidstr, type_tag_name[ref_ttag], actual_count);
		} else if (actual_count == 0) {
			char nhidstr[UINT512_BYTES * 2 + 1];
			char pchidstr[UINT512_BYTES * 2 + 1];
			uint512_dump(&e->content_hash_id, refchidstr,
				UINT512_BYTES * 2 + 1);
			uint512_dump(&vbr.name_hash_id, nhidstr,
				UINT512_BYTES * 2 + 1);
			uint512_dump(&vbr.ref_chid, pchidstr,
				UINT512_BYTES * 2 + 1);


			log_warn(lg, "Detected missing chunk DEV: %s,"
				"manifest %s, type: %s, ref: %s, "
				"ref_type: %s, nhid: %s, parent CHID %s, parent type %s",
				dev->name, chidstr, type_tag_name[ttag],
				refchidstr, type_tag_name[ref_ttag],
				nhidstr, pchidstr, type_tag_name[vbr.ref_type]);

			log_add_flush_f(dev->rt->scrub_lg, LOG_LEVEL_WARN,
				"Detected missing chunk DEV: %s,"
				"manifest %s, type: %s, ref: %s, "
				"ref_type: %s, nhid: %s, parent CHID %s, parent type %s",
				dev->name, chidstr, type_tag_name[ttag],
				refchidstr, type_tag_name[ref_ttag],
				nhidstr, pchidstr, type_tag_name[vbr.ref_type]);
			work->n_lost_chunks++;
			if (!corrupted) {
				work->n_corrupted_manifests++;
				corrupted = 1;
			}

		} else {
			uint512_dump(&e->content_hash_id, refchidstr,
				UINT512_BYTES * 2 + 1);
			log_debug(lg, "Dev(%s) Scrubber found %d replicas of a "
				"ref_chid %s, ref_type: %s, manifest %s, "
				"type: %s", dev->path, actual_count, refchidstr,
				type_tag_name[ref_ttag], chidstr,
				type_tag_name[ttag]);
		}
	}
	if (is_parity_protected) {
		/* Parity protected manifest has to be checked only on a VDEV
		 * with the minimal ID
		 */
		struct chunk_info manifest_info = {
			.chid = *chid,
			.hash_type = hash_type,
			.ttype = TT_PARITY_MANIFEST,
			.n_vdevs = 0
		};
		err = ec_locate_chunk_retry(dev, &manifest_info,
			ttag == TT_VERSION_MANIFEST ? &nhid : NULL, 1);
		if (err) {
			log_error(lg, "Dev(%s) manifest locate error CHID %s "
				"type %s: %d", dev->path, chidstr,
				type_tag_name[ttag], err);
			goto _out;
		}
		for (uint32_t i = 0; i < manifest_info.n_vdevs; i++) {
			if (uint128_cmp(manifest_info.vdevs + i,
				&dev->vdevid) < 0 || !manifest_info.nvbrs[i]) {
				uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
				log_debug(lg, "Dev(%s) manifest %s "
					"type %s recovery skipped, ndevs %u",
					dev->path, chidstr, type_tag_name[ttag],
					manifest_info.n_vdevs);
				goto _out;
			}
		}
		if (dev->rt->active_ec_bg >= dev->rt->active_ec_bg_limit)
			goto _out;
		atomic_inc(&dev->rt->active_ec_bg);
		struct ec_recovery_stat rstat = {0};
		err = ec_recover_manifest_heal(dev, chid, &nhid, ttag, refs, &rstat, job);
		atomic_dec(&dev->rt->active_ec_bg);
		if (err) {
			log_error(lg, "Dev(%s) ec_recover_manifest_from_refs() "
				"returned error code %d", dev->path, err);
		}
		if (rstat.data_mising) {
			work->n_lost_chunks += rstat.data_mising;
			work->n_corrupted_manifests++;
		} else if (rstat.data_restored) {
			work->n_recovered += rstat.data_restored;
			work->n_recovered_manifests++;
		}
	}
_out:
	rtbuf_destroy(refs);
	rtbuf_destroy(rin);
	if (work->n_refs - work->n_refs_prev >= 1000000) {
		log_warn(lg, "Scrubber on Dev(%s) has tracked %lu references, "
			"found %lu missing chunks", dev->path,
			work->n_refs, work->n_lost_chunks);
		work->n_refs_prev = work->n_refs;
	}
	log_info(lg, "Dev(%s) finished manifest %s code %d", dev->path,
		chidstr, err);

	return 0;
}

static void
bg_scrub_work(struct bg_job_entry* job, void* data)
{
	assert(data != NULL);

	scrub_work_t *work = (scrub_work_t *)data;
	assert(work != NULL);
	struct repdev *dev = work->dev;
	assert(dev != NULL);

	reptrans_set_thrname(dev, "scrub");

	int err = reptrans_iterate_blobs(dev, TT_VERSION_MANIFEST,
		reptrans_scrub_cb, work, 1);
	if (err && err != -ENODEV)
		log_error(lg, "dev %s crub callback returned error %d", work->dev->path, err);
	/* TODO: What do we do with an error here? */
	err = reptrans_iterate_blobs(dev, TT_CHUNK_MANIFEST,
		reptrans_scrub_cb, work, 1);
	if (err && err != -ENODEV)
		log_error(lg, "dev %s scrub callback returned error %d", work->dev->path, err);
}

static void
bg_scrub_done(struct bg_job_entry* job, void* data) {
	assert(data != NULL);

	scrub_work_t *work = (scrub_work_t *)data;
	assert(work != NULL);

	ccow_daemon->scrub_signal_rcvd--;
	bg_sched_set_counter(job, work->n_lost_chunks, 0);
	bg_sched_set_counter(job, work->n_corrupted_manifests, 1);
	bg_sched_set_counter(job, work->n_recovered, 2);
	bg_sched_set_counter(job, work->n_recovered_manifests, 3);
	je_free(work);
}

static int
bg_scrub_init(struct bg_job_entry* job, void** pdata) {
	static const char* scrub_countes[] = {
		"LOST_CHUNKS", "CORRUPTED_MANIFEST", "RECOVERED_CHUNKS",
		"RECOVERED_MANIFESTS"
	};

	job->chunks_total = job->sched->dev->stats.ttag_entries[TT_VERSION_MANIFEST] +
		job->sched->dev->stats.ttag_entries[TT_CHUNK_MANIFEST];
	scrub_work_t *work = je_calloc(1, sizeof(scrub_work_t));
	assert(work != NULL);

	work->dev = job->sched->dev;
	work->job = job;
	bg_sched_register_counters(job, 4, scrub_countes);
	*pdata = work;
	return 0;
}

static int
bg_scrub_progress(struct bg_job_entry* job) {
	struct repdev* dev = job->sched->dev;
	if (dev->terminating ||
		!(job->status == BG_STATUS_PROGRESS ||
		job->status == BG_STATUS_PAUSED ||
		job->status == BG_STATUS_PREEMPTED))
		return -1;

	if (!job->chunks_total)
		return 1000;
	size_t ratio = job->chunk_counter*1000/job->chunks_total;
	if (ratio > 1000)
		ratio = 1000;
	return ratio;
}

static void
trlog_setids(struct repdev *dev, char *tid, size_t tid_size,
    char *bid, size_t bid_size)
{
	char serverid[UINT128_STR_BYTES], vdevid[UINT128_STR_BYTES];
	struct server_stat *stat = server_get();
	uint128_dump(&stat->id, serverid, UINT128_STR_BYTES);
	uint128_dump(&dev->vdevid, vdevid, UINT128_STR_BYTES);
	snprintf(tid, tid_size, "%s%s", TRLOG_TID_PREFIX, serverid);
	snprintf(bid, bid_size, "%s", vdevid);
}

static int
trlog_bucket_create(ccow_t tc, const char *tid, size_t tid_size,
    const char *bid, size_t bid_size)
{
	ccow_completion_t c;
	int err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	uint16_t num_vers = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
	if (err) {
		ccow_release(c);
		return err;
	}

	/* TSObj length is 24c, we can handle up to 64K per CM, so
	 * optimal maximum order will be ~ 64000/(82+24)/2 = 256 */
	uint16_t order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_TSOBJ;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER, &order, NULL);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_admin_pseudo_put("", 1, tid, tid_size, bid, bid_size,
		"", 1, NULL, 0, 0, CCOW_PUT, NULL, c);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err) {
		return err;
	}

	struct iovec iov = { .iov_base = (char *)bid, .iov_len = strlen(bid) + 1 };
	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	if (err)
		return err;
	// Add the bucket to the BTN of the tenant, since we've bypassed normal
	// ccow_bucket_create()
	ccow_lookup_t iter;
	err = ccow_admin_pseudo_get("", 1, tid, tid_size,
	    "", 1, "", 1, NULL, 0, 0, CCOW_GET, c, &iter);
	if (err) {
		ccow_drop(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		ccow_drop(c);
		goto _err;
	}
	err = ccow_admin_pseudo_put("", 1, tid, tid_size,
	    "", 1, "", 1, &iov, 1, 0, CCOW_INSERT_LIST, 0, c);
	if (err) {
		ccow_release(c);
		goto _err;
	}
	err = ccow_wait(c, 1);
_err:
	if (iter)
		ccow_lookup_release(iter);
	return err;
}

static int
trlog_hierarhy_create(struct repdev *dev)
{
	int err;

	ccow_t tc = reptrans_get_tenant_context(dev->rt, 0);
	if (!tc) {
		log_error(lg, "Dev(%s): Failed to get tenant context", dev->name);
		return -EPERM;
	}

	char bid[UINT128_STR_BYTES], tid[UINT128_STR_BYTES + 10];
	trlog_setids(dev, tid, UINT128_STR_BYTES + 10, bid, UINT128_STR_BYTES);

	err = ccow_tenant_create(tc, tid, strlen(tid) + 1, NULL);
	if (err == -EEXIST) {
		log_debug(lg, "Dev(%s): Tenant %s already exists.", dev->name, tid);
	} else if (err) {
		log_error(lg, "Dev(%s): Failed to create tenant %s err %d",
			dev->name, tid, err);
		goto _err;
	}

	err = trlog_bucket_create(tc, tid, strlen(tid) + 1, bid, strlen(bid) + 1);
	if (err == -EEXIST) {
		log_debug(lg, "Dev(%s): Bucket %s already exists.", dev->name, bid);
		err = 0;
	} else if (err) {
		log_error(lg, "Dev(%s): Failed to create bucket %s err %d",
			dev->name, bid, err);
		goto _err;
	}

	log_debug(lg, "Dev(%s): trlog tenant %s bucket %s ready",
		dev->name, tid, bid);
_err:
	reptrans_put_tenant_context(dev->rt, tc);
	return err;
}

static void
trlog_format_key(struct trlog_data *data, char *key, int len)
{
	char nhid_str[UINT512_STR_BYTES];
	char phid_str[UINT512_STR_BYTES];
	char vmchid_str[UINT512_STR_BYTES];
    char serverid_str[UINT128_STR_BYTES];

    uint128_dump(&data->serverid, serverid_str, UINT128_STR_BYTES);

	uint512_dump(&data->nhid, nhid_str, UINT512_STR_BYTES);
	uint512_dump(&data->phid, phid_str, UINT512_STR_BYTES);
	uint512_dump(&data->vmchid, vmchid_str, UINT512_STR_BYTES);

	snprintf(key, len, "%s\1%s\1%lu\1%lu\1%s\1%u\1%ld\1%s\1%s\1%s\1%s\1%lu\1%u\1%lu\1%s\1%s\1%s\1%s\1%s", phid_str, nhid_str,
		data->generation, data->timestamp, vmchid_str, data->trtype,
		data->deltasize, data->cid, data->tid, data->bid, data->oid, data->size,
		data->object_deleted, data->multipart_size, data->etag, data->content_type,
		serverid_str, data->owner, data->srcip);
}

static int
bg_trlog_cb(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
    uint512_t *chid, uv_buf_t *val, void *param)
{
	int err;
	msgpack_u u;
	struct bg_job_entry *job = param;
	assert(job);
	trlog_work_t *work = job->data;
	struct trlog_data data;
	struct iovec iov;
	rtbuf_t* rb = NULL;

	assert(ttag == TT_TRANSACTION_LOG);
	assert(work);
	assert(work->oid);
	assert(work->c);

	/* The job has to be terminated as soon as possible */
	if (bg_job_is_term_forced(job))
		return -ENODEV;

	err = reptrans_get_blob(dev, ttag, hash_type, chid, &rb);
	if (err) {
		if (err != -ENOENT) {
			log_error(lg, "Dev(%s) error getting TRLOG entry: %d",
				dev->name, err);
			return err;
		}
		return 0;
	}
	assert(rb);
	assert(rb->nbufs);
	assert(rb->bufs);

	msgpack_unpack_init_b(&u, rb->bufs->base, rb->bufs->len, 0);
	err = trlog_unpack(&u, &data);
	if (err) {
		log_error(lg, "Dev(%s): Failed to unpack trlog", dev->name);
		goto _local_memfree_trlog_data;
	}

	/* collect batch from previous to up to a coordinated checkpoint */
	assert(data.timestamp);
	if (chid->u.u.l >= work->batch_seq_ts) {
		err = 0;
		goto _local_memfree_trlog_data;
	}
	if (work->batch_seq_prev_ts &&
	    chid->u.u.l < (work->batch_seq_prev_ts - ccow_daemon->trlog_interval_us * TRLOG_OLD_RESULT_MAX)) {
		err = 0;
		log_warn(lg, "Dev(%s): TRLOG skip stale %lu %lu %lu",
		    dev->name, data.timestamp, chid->u.u.l,
		    work->batch_seq_prev_ts);
		work->stale_vmchids[work->stale++] = *chid;
		if (work->stale > TRLOG_TSOBJ_MAX_ENTRIES - 1)
			err = -ENOSPC;
		goto _local_memfree_trlog_data;
	}

	char key[TRLOG_KEY_LEN];
	trlog_format_key(&data, key, TRLOG_KEY_LEN);
	iov.iov_base = key;
	iov.iov_len = strlen(key) + 1;

	if (unlikely(LOG_LEVEL_DEBUG >= lg->level)) {
		char tid[UINT128_STR_BYTES + 10], bid[UINT128_STR_BYTES];
		trlog_setids(dev, tid, UINT128_STR_BYTES + 10, bid, UINT128_STR_BYTES);
		log_debug(lg, "Dev(%s): TRLOG TSObj insert /%s/%s/ <= %s/%s/%s/%s %ld",
		    dev->name, tid, bid, data.cid, data.tid, data.bid, data.oid,
		    data.size);
	} else
		log_debug(lg, "Dev(%s): TRLOG TSObj insert %s/%s/%s/%s %ld",
		    dev->name, data.cid, data.tid, data.bid, data.oid, data.size);

	err = ccow_insert_list_cont(work->c, &iov, 1, 1, &work->index);
	if (err) {
		ccow_release(work->c);
		goto _local_memfree_trlog_data;
	}
	err = ccow_wait(work->c, work->index);
	if (!err) {
		assert(work->index > 0);
		work->processed_vmchids[work->index - 1] = *chid;
	}
	if (work->index > TRLOG_TSOBJ_MAX_ENTRIES - 1)
		err = -ENOSPC;

_local_memfree_trlog_data:
	if (data.cid)
		je_free(data.cid);
	if (data.tid)
		je_free(data.tid);
	if (data.bid)
		je_free(data.bid);
	if (data.oid)
		je_free(data.oid);
	if (data.etag)
		je_free(data.etag);
	if (data.content_type)
		je_free(data.content_type);
	if (data.owner)
		je_free(data.owner);
	if (data.srcip)
		je_free(data.srcip);
	if (rb)
		rtbuf_destroy(rb);
	return err;
}

static void
bg_trlog_batch_finished(uint64_t batch_seq_ts, char *vdevidstr)
{
	char buf[128];
	sprintf(buf, "TRLOG_BATCH_FINISHED.%s.%lu", vdevidstr, batch_seq_ts);
	clengine_notify(buf);
}

static void
bg_trlog_work(struct bg_job_entry *job, void* data)
{
	int err;
	trlog_work_t *work = data;
	assert(work != NULL);
	struct repdev *dev = work->dev;
	ccow_completion_t c_check;
	ccow_completion_t c;
	struct iovec iov;
	uint64_t batch_seq_ts = 0, batch_seq_prev_ts = 0;

	assert(dev != NULL);
	reptrans_set_thrname(dev, "trlog");

_restart_behind:

	if (dev->terminating)
		return;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE ||
		status == REPDEV_STATUS_READONLY_FORCED ||
		status == REPDEV_STATUS_READONLY_FAULT)
		return;

	if (!dev->__vtbl)
		return;

	if (!ccow_daemon->leader_coordinated_ts)
		return;

	char tid[UINT128_STR_BYTES + 10], bid[UINT128_STR_BYTES];
	trlog_setids(dev, tid, UINT128_STR_BYTES + 10, bid, UINT128_STR_BYTES);

	char shardbuf[128];
	sprintf(shardbuf, SHARD_VDEV_PREFIX "%s", bid);

	ccow_t tc = reptrans_get_tenant_context(dev->rt, 0);
	if (!tc) {
		log_error(lg, "Dev(%s): Failed to get tenant context", dev->name);
		return;
	}

	if (!dev->trlog_bucket_ready) {
		/* serialize insertions across vdev threads */
		uv_mutex_lock(&dev->rt->trlog_mutex);
		err = ccow_create_completion(tc, NULL, NULL, 2, &c_check);
		if (err)
			goto _err;
		/* check if /// - root object exists */
		err = ccow_admin_pseudo_get("", 1, "", 1, "", 1, "", 1, NULL, 0,
		    0, CCOW_GET, c_check, NULL);
		if (err) {
			ccow_drop(c_check);
			goto _err;
		}
		err = ccow_wait(c_check, 0);
		if (err) {
			ccow_drop(c_check);
			err = 0;
			goto _err;
		}
		/* check if /tid/bid exists */
		err = ccow_admin_pseudo_get("", 1, tid, strlen(tid) + 1,
		    bid, strlen(bid) + 1, "", 1, NULL, 0, 0, CCOW_GET_LIST,
		    c_check, NULL);
		if (err) {
			ccow_release(c_check);
			goto _err;
		}
		err = ccow_wait(c_check, 1);
		if (err && err == -ENOENT) {
			err = trlog_hierarhy_create(dev);
			if (err)
				goto _err;
			dev->trlog_bucket_ready = 1;
		} else if (err) {
			goto _err;
		} else
			dev->trlog_bucket_ready = 1;
		uv_mutex_unlock(&dev->rt->trlog_mutex);
	}

	char msg_prefix[PATH_MAX];
	snprintf(msg_prefix, sizeof(msg_prefix), "Dev(%s): ", dev->name);
	/* Read per VDEV marker so that we can check if we have stale TRLOG
	 * data which needs skipping and removal. Use marker as a starting
	 * batch number. */
	err = trlog_read_marker_seq_tss(tc, msg_prefix, shardbuf, &batch_seq_ts, &batch_seq_prev_ts);
	if (err) {
		log_error(lg, "Dev(%s): Failed to read VDEV %s TRLOG marker",
		    dev->name, bid);
		goto _err;
	}
	if (batch_seq_ts == 0) {
		uint64_t cts = COORDINATED_TS();
		if (batch_seq_prev_ts == 0) {
			batch_seq_ts = cts - (cts % ccow_daemon->trlog_interval_us);
		} else {
			batch_seq_ts = batch_seq_prev_ts + ccow_daemon->trlog_interval_us;
			if (batch_seq_ts + 1000000UL >= cts) {
				reptrans_put_tenant_context(dev->rt, tc);
				return;
			}
		}

		/* in-progress - update VDEV marker */
		err = trlog_write_marker_seq_tss(tc, shardbuf,
				batch_seq_ts, batch_seq_prev_ts);
		if (err) {
			if (err != -ENOSPC)
				log_error(lg, "Dev(%s): Failed to update in-progress "
					"TRLOG marker for VDEV %s",
					dev->name, bid);
			else
				log_warn(lg, "Dev(%s): Failed to update in-progress "
					"TRLOG marker for VDEV %s, out of space",
					dev->name, bid);

			goto _err;
		}
	}

	char oid[24];
	uint64_t genid = 0;
	snprintf(oid, 24, "%023lu", batch_seq_ts);

	/* check if /tid/bid/oid exists */
	err = ccow_create_completion(tc, NULL, NULL, 1, &c_check);
	if (err)
		goto _err;
	err = ccow_admin_pseudo_get("", 1, tid, strlen(tid) + 1,
	    bid, strlen(bid) + 1, oid, strlen(oid) + 1, NULL, 0, 0,
	    CCOW_GET_LIST, c_check, NULL);
	if (err) {
		ccow_release(c_check);
		goto _err;
	}
	err = ccow_wait(c_check, 0);
	if (err == -EEXIST) {
		/* case - work is already done */
		log_warn(lg, "Dev(%s): TRLOG found %s/%s/%s/%s - skip",
		    dev->name, "", tid, bid, oid);
		err = 0;
		goto _final;
	}

	int part = 0;

_append:
	log_debug(lg, "Dev(%s): TRLOG working on %s/%s/%s/%s part=%d",
	    dev->name, "", tid, bid, oid, part);

	err = ccow_create_completion(tc, NULL, NULL, TRLOG_TSOBJ_MAX_ENTRIES + 1, &c);
	if (err)
		goto _err;

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
	if (err) {
		ccow_release(c);
		goto _err;
	}

	uint16_t dis = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_TRACK_STATISTICS,
	    (void *)&dis, NULL);
	if (err) {
		ccow_release(c);
		goto _err;
	}

	/* with this each entry has to fit in ~ 4730c, we need very large CMs */
	uint16_t order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_MAX;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER, &order, NULL);
	if (err) {
		ccow_release(c);
		goto _err;
	}

	uint16_t num_vers = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	if (err) {
		ccow_release(c);
		goto _err;
	}

	uint64_t delete_after = get_timestamp_us() / 1000000 +
		dev->bg_config->trlog_delete_after_hours * 3600;
	err = ccow_attr_modify_default(c, CCOW_ATTR_OBJECT_DELETE_AFTER,
		    (void *)&delete_after, NULL);
	if (err) {
		ccow_release(c);
		goto _err;
	}

	int c_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
	ccow_stream_flags(c, &c_flags);

	c->cont = 1;
	c->cont_flags = CCOW_CONT_F_EXIST;
	c->cont_generation = &genid;
	c->chunkmap_flags = CCOW_STREAM;
	c->chunkmap_ctx = NULL;
	err = ccow_admin_pseudo_put("", 1, tid, strlen(tid) + 1,
	    bid, strlen(bid) + 1, oid, strlen(oid) + 1,
	    NULL, 0, 0, CCOW_CONT, NULL, c);
	if (err) {
		ccow_release(c);
		goto _err;
	}
	err = ccow_wait(c, 0);
	if (err)
		goto _err;

	c->init_op->completed = 0;
	c->init_op->namedput_io->attributes |= RD_ATTR_NO_TRLOG;

	work->batch_seq_ts = batch_seq_ts;
	work->batch_seq_prev_ts = batch_seq_prev_ts;
	work->c = c;
	work->oid = oid;
	work->index = work->stale = 0;
	for (int i = 0; i < TRLOG_TSOBJ_MAX_ENTRIES; i++) {
		work->processed_vmchids[i] = uint512_null;
		work->stale_vmchids[i] = uint512_null;
	}
	err = reptrans_iterate_blobs_strict_order_limited(dev, TT_TRANSACTION_LOG,
		bg_trlog_cb, job, 0, TRLOG_TSOBJ_MAX_ENTRIES + 256);
	if (err && err != -ENOSPC)
		log_error(lg, "Dev(%s): reptrans_iterate_blobs failed", dev->name);

	int nospc = err == -ENOSPC;
	if (work->index > 0) {

		err = ccow_finalize(c, NULL);
		if (err)
			goto _err;

		for (int i = 0; i < work->index; i++) {
			err = reptrans_delete_blob(dev, TT_TRANSACTION_LOG,
				HASH_TYPE_DEFAULT, &work->processed_vmchids[i]);
			if (err) {
				log_error(lg, "Dev(%s): Failed to delete "
					"tran ts %s", dev->name, oid);
			}
		}
		for (int i = 0; i < work->stale; i++) {
			err = reptrans_delete_blob(dev, TT_TRANSACTION_LOG,
				HASH_TYPE_DEFAULT, &work->stale_vmchids[i]);
			if (err) {
				log_error(lg, "Dev(%s): Failed to delete "
					"tran ts %s", dev->name, oid);
			}
		}

		if (nospc) {
			part++;
			goto _append;
		}
	} else {
		if (!err || err == -ENOSPC) {
			err = 0;
			for (int i = 0; i < work->stale; i++) {
				err = reptrans_delete_blob(dev, TT_TRANSACTION_LOG,
					HASH_TYPE_DEFAULT, &work->stale_vmchids[i]);
				if (err) {
					log_error(lg, "Dev(%s): Failed to delete "
						"tran ts %s", dev->name, oid);
				}
			}
		}
		int do_final = !err;
		err = ccow_cancel(c);
		if (err) {
			log_warn(lg, "Dev(%s): Failed to cancel TRLOG flush",
			    dev->name);
		}
		if (do_final) {
			/* empty TRLOG type tag case - no work done */
			log_info(lg, "Dev(%s): TRLOG is empty, sending finish signal",
			    dev->name);
			err = 0;
			goto _final;
		}
		goto _err;
	}

	/* Update final work->index for BG job accounting */
	work->index += part * TRLOG_TSOBJ_MAX_ENTRIES;

_final:

	/* final - update VDEV marker */
	err = trlog_write_marker_seq_tss(tc, shardbuf, 0LU, batch_seq_ts);
	if (err) {
		if (err != -ENOSPC)
			log_error(lg, "Dev(%s): Failed to update final marker for VDEV %s",
				dev->name, bid);
		else
			log_warn(lg, "Dev(%s): Failed to update final marker for VDEV %s",
				dev->name, bid);

		if (!dev->terminating && work->index) {
			/* we should keep trying if we've flushed something */
			usleep(1000000);
			goto _final;
		}
	}

	bg_trlog_batch_finished(batch_seq_ts, bid);

_err:
	if (!dev->trlog_bucket_ready)
		uv_mutex_unlock(&dev->rt->trlog_mutex);
	if (err)
		log_warn(lg, "Dev(%s): unknown error while TRLOG flush: %d, "
		    "will try to recover next time", dev->name, err);
	reptrans_put_tenant_context(dev->rt, tc);

	/* need to keep 2 x trlog_interval_us window to avoid stale entries */
	if (!err && batch_seq_ts && (batch_seq_ts + 2 * ccow_daemon->trlog_interval_us) < COORDINATED_TS()) {
		log_info(lg, "Dev(%s): flushed %d entries, continue TRLOG flush due to its beign behind current time by %ldms",
		    dev->name, work->index, (COORDINATED_TS() - (batch_seq_ts + 2 * ccow_daemon->trlog_interval_us))/1000UL);
		goto _restart_behind;
	}
}

static void
bg_trlog_done(struct bg_job_entry* job, void* data)
{
	trlog_work_t *work = data;
	assert(work != NULL);

	job->chunk_counter = work->index;
	bg_sched_set_counter(job, work->index, 0);
	je_free(work->processed_vmchids);
	je_free(work->stale_vmchids);
	je_free(work);
}

static int
bg_trlog_init(struct bg_job_entry* job, void** pdata)
{
	static const char* str[] = {
		"TRLOG_ENTRIES_PROCESSED"
	};
	trlog_work_t *work = je_calloc(1, sizeof(trlog_work_t));
	if (!work)
		return -ENOMEM;

	work->processed_vmchids = je_calloc(TRLOG_TSOBJ_MAX_ENTRIES, sizeof(uint512_t));
	if (!work->processed_vmchids) {
		je_free(work);
		return -ENOMEM;
	}

	work->stale_vmchids = je_calloc(TRLOG_TSOBJ_MAX_ENTRIES, sizeof(uint512_t));
	if (!work->stale_vmchids) {
		je_free(work->processed_vmchids);
		je_free(work);
		return -ENOMEM;
	}
	work->dev = job->sched->dev;
	work->job = job;
	*pdata = work;
	bg_sched_register_counters(job, 1, str);
	return 0;
}

void
reptrans_device_rowusage_init(rowusage_xfer_t *vdev_xfer_list)
{
	memset(vdev_xfer_list, 0, sizeof(*vdev_xfer_list));
	uv_rwlock_init(&vdev_xfer_list->lock);
	vdev_xfer_list->numrows = 0;
	QUEUE_INIT(&vdev_xfer_list->queue);
}

void
reptrans_destroy_device_rowusage(struct repdev *dev)
{
	rowusage_xfer_t *vdev_xfer_list = &dev->rowusage_list;

	uv_rwlock_wrlock(&vdev_xfer_list->lock);
	vdev_xfer_list->numrows = 0;
	uv_rwlock_wrunlock(&vdev_xfer_list->lock);
}

void
reptrans_start_scrub() {
	struct reptrans *rt = NULL;
	QUEUE* q;
	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);

			ccow_daemon->scrub_signal_rcvd++;
			bg_force_job(dev->bg_sched, BG_SCRUB);

			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}
}

int
reptrans_get_vdevs_usage(uint64_t** usage) {
	struct reptrans *rt = NULL;
	QUEUE* q;
	uint64_t *us = je_calloc(REPTRANS_MAX_VDEVS, sizeof(uint64_t));
	if (!us)
		return -ENOMEM;
	int cnt = 0;
	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);

			uint64_t capacity = atomic_get_uint64(&dev->stats.capacity);
			if (cnt < REPTRANS_MAX_VDEVS && capacity) {
				uint64_t used = atomic_get_uint64(&dev->stats.used);
				us[cnt++] = used * 1000000LL/capacity;
			}

			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}
	*usage = us;
	return cnt;
}


static int
vbr_iterator_print_cb(struct repdev* dev, const uint512_t* chid,
	crypto_hash_t hash_type, uv_buf_t* vbr_buf, const struct backref* vbr,
	void* arg) {
	char chidstr[UINT512_STR_BYTES];
	char nhidstr[UINT512_STR_BYTES];
	char chidstr_main[UINT512_STR_BYTES];
	size_t* cnt = arg;
	++(*cnt);
	uint512_dump(&vbr->ref_chid, chidstr, UINT512_STR_BYTES);
	uint512_dump(&vbr->name_hash_id, nhidstr, UINT512_STR_BYTES);
	uint512_dump(chid, chidstr_main, UINT512_STR_BYTES);
	if (*cnt <= 10)
		log_notice(lg, "Dev(%s) CHID %s VBR%lu: ref_type %s, ref_chid %s, "
			"NHID %s, gen %lu, rep_cnt %u", dev->name, chidstr_main,
			*cnt, type_tag_name[vbr->ref_type], chidstr, nhidstr,
			vbr->generation, vbr->rep_count);
	else
		return -1;
	return 0;
}


int
reptrans_blob_lookup(type_tag_t ttag, crypto_hash_t hash_type,
	const uint512_t* chid, uint128_t** vdevs, uint16_t* ndevs) {
	struct reptrans *rt = NULL;
	int count = 0, err = 0;
	uint128_t *devlist = je_calloc(REPTRANS_MAX_VDEVS, sizeof(uint128_t));
	assert(ndevs);
	QUEUE* q;
	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);
			char chidstr[UINT512_STR_BYTES];
			uint512_dump(chid, chidstr, UINT512_STR_BYTES);
			struct blob_stat stat = {.size = 0};
			if (ttag == TT_VERIFIED_BACKREF) {
				size_t num = 0;
				err = reptrans_blob_stat(dev, ttag, hash_type, chid, &stat);
				if (!err) {
					err = reptrans_vbrs_iterate(dev, chid, hash_type,
						vbr_iterator_print_cb, &num);
					log_notice(lg, "Dev(%s) for CHID %s found %lu VBRs",
						dev->name,chidstr, num);
					if (!num) {
						log_error(lg, "Couldn't get VBR at lookup: %d", err);
						je_free(devlist);
						return err;
					}
					devlist[count++] = dev->vdevid;
				}
			} else {
				uint64_t size = 0;
				rtbuf_t* rb = NULL;
				int stat_err = reptrans_blob_stat(dev, ttag, hash_type, chid, &stat);
				int query_error = reptrans_blob_query(dev, ttag, hash_type, chid, &size);
				err = reptrans_get_blob(dev, ttag, hash_type, chid, &rb);
				log_notice(lg, "Dev(%s) blobfind %s type %s result: stat(%d, %lu), "
					"query(%d, %lu), get(%d, %lu)\n", dev->name, chidstr,
					type_tag_name[ttag], stat_err, stat.size, query_error,
					size, err, rb ? rb->bufs[0].len : 0);
				if (!err)
					devlist[count++] = dev->vdevid;
				if (rb)
					rtbuf_destroy(rb);
			}
			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}
	*ndevs = count;
	if (count)
		*vdevs = devlist;
	else
		je_free(devlist);
	return 0;
}

static void
dev_event_notified(uv_poll_t *treq, int status, int events)
{
	struct repdev *dev = treq->data;

	char *buf = NULL;
	int nread = nn_recv(dev->sub_fd, &buf, NN_MSG, NN_DONTWAIT);
	if (nread < 0) {
		if (errno != EAGAIN)
			log_error(lg, " Error receiving events errno=%d"
			    "errmsg=%s\n", errno, strerror(errno));
		return;
	}

	/* TODO: Update events of interest */
	nn_freemsg(buf);
}

void
reptrans_subscribe_events(struct repdev *dev)
{
	int err;

	char pub_address[INET6_ADDRSTRLEN + 10];
	sprintf(pub_address, "tcp://127.0.0.1:%d", AUDITD_PUB_PORT);

	char vdevstr[UINT128_BYTES * 2 + 1];
	memset(vdevstr, 0, UINT128_BYTES*2 + 1);
	uint128_dump(&dev->vdevid, vdevstr, UINT128_BYTES*2 + 1);

	char topic[AUDITD_TOPIC_MAXLEN];
	sprintf(topic, "gauges.ccow.reptrans.put_latency.%s.mean", vdevstr);

	dev->sub_req.data = dev;
	err = auditc_subscribe(dev->loop, pub_address, topic, &dev->sub_fd,
	    &dev->sub_req, dev_event_notified);
	if (err == 0) {
		log_debug(lg, "Subscribed to event %s for %s", topic,
		    dev->name);
	}
}

void
reptrans_unsubscribe_events(struct repdev *dev)
{
	int err;

	if (dev->sub_fd == -1)
		return;

	char vdevstr[UINT128_BYTES * 2 + 1];
	memset(vdevstr, 0, UINT128_BYTES*2 + 1);
	uint128_dump(&dev->vdevid, vdevstr, UINT128_BYTES*2 + 1);

	char topic[AUDITD_TOPIC_MAXLEN];
	sprintf(topic, "gauges.ccow.reptrans.put_latency.%s.mean", vdevstr);

	err = auditc_unsubscribe(&dev->sub_fd, &dev->sub_req, topic);
	if (err) {
		log_error(lg, "Error unsubscibing for %s", topic);
	}
}

/*
 * Main device thread.
 *
 * Each device has its own thread and event loop. Incoming messages
 * processed in parallel without the need to worry for locks/mutexes.
 */
static void
reptrans_dev_thread(void *arg)
{
	struct repdev *dev = arg;
	struct sched_param params;
	int err;

	assert(dev->__vtbl);

	dev->loop_thrid = uv_thread_self();

	memset(&params, 0, sizeof (params));
	params.sched_priority = 10;
	err = pthread_setschedparam(pthread_self(), SCHED_RR, &params);
	if (err) {
		log_warn(lg, "Unable to set real-time thread priority on "
		    "device %s", dev->name);
	}
	reptrans_set_thrname(dev, "vdev");

	if (!(dev->rt->flags & RT_FLAG_STANDALONE)) {
		dev->robj->loop_thrid = dev->loop_thrid;
		if (dev->bg_config->compact_on_boot && dev->__vtbl->compactify)
			dev->__vtbl->compactify(dev, TT_LAST, 0, NULL);
		uv_mutex_lock(&dev->rt->comp_mutex);
		uv_mutex_unlock(&dev->rt->comp_mutex);
		dev->rt->ts_offset = uv_hrtime()/1000;
		bg_sched_start(dev->bg_sched);
	}
	/* block thread */
	uv_run(dev->loop, UV_RUN_DEFAULT);

	while (!uv_workers_empty(dev->loop)
		   || !uv_wq_empty(dev->loop)) {
		usleep(10000);
		uv_run(dev->loop, UV_RUN_ONCE);
	}

	log_trace(lg, "repdev %s thread finished", dev->path);
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
	if (!(dev->rt->flags & RT_FLAG_STANDALONE)) {
		usleep(100000);
		bg_sched_destroy(dev->bg_sched);
		bg_sched_destroy_finished(dev->bg_sched);
		dev->bg_sched = NULL;
		replicast_finish_destroy(dev->robj);
		reptrans_lock_destroy(dev->robj_lock);
		ccowtp_free(dev->tp);
	}
	uv_loop_delete(dev->loop);
	dev->loop = NULL;

	dev->__vtbl = NULL;
}

int
reptrans_get_vdevs(uint128_t **vdevs, size_t *nr_vdevs)
{
	QUEUE *q;
	struct reptrans *rt;
	int err;
	size_t i = 0;

	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;

		rt = QUEUE_DATA(q, struct reptrans, item);

		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);

			all_vdevs[i++] = dev->vdevid;

			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}

	*vdevs = all_vdevs;
	*nr_vdevs = i;

	return 0;
}

static int
reptrans_read_serverid(uint128_t *id)
{
	int fd, err;
	char idname[SERVER_ID_MAXLEN + 1];

	char srv_path[PATH_MAX];
	snprintf(srv_path, sizeof(srv_path), SERVERID_CACHE_FILE, nedge_path());

	fd = open(srv_path, O_RDONLY);
	if (fd < 0)
		return -EINVAL;

	memset(idname, 0, SERVER_ID_MAXLEN + 1);
	err = read(fd, idname, SERVER_ID_MAXLEN);
	if (err < 0) {
		close(fd);
		return -errno;
	}
	uint128_fromhex(idname, SERVER_ID_MAXLEN, id);
	return 0;
}

static void
reptrans_cache__on_exit(uv_async_t *handle, int status)
{
	struct repdev *dev = container_of(handle, struct repdev, exit_handle);
	uint32_t if_index;
	uint128_t *nodeserverid = NULL, sid;
	char cache_mc_addr[INET6_ADDRSTRLEN + IFNAMSIZ];
	int err;

	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_LOW, reptrans_replicast_wait__exec,
	    reptrans_replicast_wait__done, dev);

	/* clengine may not be initialized here */
	nodeserverid = clengine_get_mynodeid();
	if (nodeserverid == (uint128_t *)NULL) {
		err = reptrans_read_serverid(&sid);
		if (err)
			return;
		nodeserverid = &sid;
	}

	assert(nodeserverid != (uint128_t *)NULL);
	get_gwcache_addr(nodeserverid, cache_mc_addr, INET6_ADDRSTRLEN + IFNAMSIZ,
			 NULL);
	if_index = if_nametoindex(ccow_daemon->if_names[0]);

	reptrans_unsubscribe_events(dev);
	bg_sched_terminate(dev->bg_sched);

	replicast_leave(dev->robj, cache_mc_addr, if_index);
	gw_lru_destroy();

	uv_close((uv_handle_t *)&dev->call_async, NULL);
	uv_close((uv_handle_t *)handle, NULL);
	uv_sem_destroy(&dev->recover_sem);
}

static int
reptrans_create_cache_loop(struct repdev *dev, uint16_t base_port_offset)
{
	uint128_t *nodeserverid = NULL, sid;
	int err;
	struct reptrans *rt = dev->rt;
	uint32_t if_index;

	dev->loop = uv_loop_new();
	if (!dev->loop)
		return -ENOMEM;

	dev->listen_port = ccow_daemon->server_port + base_port_offset;
	struct ccowtp_job_config cfg[] = {
		{
			.sched = SCHED_RR,
			.prio = 1,
			.weight = 50,
			.min = 25,
			.resiliency = 1000
		},
		{
			.sched = SCHED_OTHER,
			.prio = 0,
			.weight = 40,
			.min = 25,
			.resiliency = 1000
		},
		{
			.sched = SCHED_OTHER,
			.prio = 0,
			.weight = 10,
			.min = 20,
			.resiliency = 100
		}
	};
	dev->tp = ccowtp_create(dev->loop, cfg, 3,
		dev->bg_config->thread_pool_size);
	assert(dev->tp);

	dev->robj_lock = reptrans_lock_create();
	/* default GW cache device port */
	char cache_mc_addr[INET6_ADDRSTRLEN + IFNAMSIZ];
	char listen_addr[INET6_ADDRSTRLEN + IFNAMSIZ];

	if_index = if_nametoindex(ccow_daemon->if_names[0]);
	if (if_index == 0) {
		log_error(lg, "Dev(%s) could not get index for %s",
		    dev->name, ccow_daemon->if_names[0]);
		return -errno;
	}

	/* clengine may not be initialized here */
	nodeserverid = clengine_get_mynodeid();
	if (nodeserverid == (uint128_t *)NULL) {
		err = reptrans_read_serverid(&sid);
		if (err)
			return err;
		nodeserverid = &sid;
	}

	assert(nodeserverid != (uint128_t *)NULL);
	get_gwcache_addr(nodeserverid, cache_mc_addr, INET6_ADDRSTRLEN + IFNAMSIZ,
	    NULL);

	/* building msg_origin_addr */
	char msg_origin_addr[INET6_ADDRSTRLEN + IFNAMSIZ];
	if (ccow_daemon->server_ip4addr) {
		strcpy(msg_origin_addr, ccow_daemon->server_ip4addr);
		strcpy(listen_addr, ccow_daemon->server_ip4addr);
	} else {
		if (strncmp(ccow_daemon->server_ip6addr, "::",
			    strlen("::")) == 0) {
			err = find_ipv6local(ccow_daemon->if_names[0],
					     msg_origin_addr);
			if (err != 0)
				return err;
		} else
			snprintf(msg_origin_addr, INET6_ADDRSTRLEN + IFNAMSIZ,
			    "%s", ccow_daemon->server_ip6addr);
		sprintf(listen_addr, "::%%%s", ccow_daemon->if_names[0]);
	}

	uv_mutex_lock(&rt->tc_mutex);
	dev->robj = replicast_init(dev->name, dev->loop,
	    listen_addr, dev->listen_port, NULL, msg_origin_addr, cache_mc_addr,
	    CCOWD_GW_CACHE_PORT, ccow_daemon->mc_ttl, dev);
	if (!dev->robj) {
		uv_mutex_unlock(&rt->tc_mutex);
		log_error(lg, "Cannot start device thread for %s",
		    dev->name);
		return -EIO;
	}
	uv_mutex_unlock(&rt->tc_mutex);

	err = gw_lru_init(dev);
	if (err) {
		log_error(lg, "Dev(%s) Cannot initialize LRU", dev->name);
		replicast_destroy(dev->robj);
		return err;
	}

	/* Now join a MC address */
	err = replicast_join(dev->robj, cache_mc_addr, if_index);
	if (err) {
		log_error(lg, "Dev(%s) Cannot join MC addr %s",
		    dev->name, cache_mc_addr);
		gw_lru_destroy();
		replicast_destroy(dev->robj);
		return -EIO;
	}

	replicast_vbuf_init(&dev->robj->rvbuf, ccow_daemon->if_speeds[0]);
	dev->robj->server_ctx = ccow_daemon;
	dev->robj->dev_ctx = dev;

	/* Cache device support only UNNAMED GETs */
	replicast_state_init(dev->robj, RT_UNNAMED_CHUNK_GET,
	    gwcachedget_srv_init);
	replicast_state_init(dev->robj, RT_PINGPONG, pingpong_init);

	/* add device to the transport */
	uv_rwlock_wrlock(&rt->devlock);
	QUEUE_INSERT_TAIL(&rt->devices, &dev->item);
	uv_rwlock_wrunlock(&rt->devlock);

	QUEUE_INIT(&dev->rtfree_timer_queue);
	QUEUE_INIT(&dev->call_queue);
	QUEUE_INIT(&dev->lock_q);
	QUEUE_INIT(&dev->reqfree_queue);
	dev->exit_handle.data = dev;
	QUEUE_INIT(&dev->mcjoin_queue);

	uv_sem_init(&dev->recover_sem, DEV_RECOVER_INPROG_MAX);
	uv_async_init(dev->loop, &dev->exit_handle, reptrans_cache__on_exit);
	uv_mutex_init(&dev->call_mutex);
	uv_mutex_init(&dev->stats.stat_mutex);
	uv_mutex_init(&dev->stats.gw_stat_mutex);
	uv_mutex_init(&dev->lk_mutex);
	uv_async_init(dev->loop, &dev->call_async, reptrans_dev__on_call);
	reptrans_device_rowusage_init(&dev->rowusage_list);

	dev->bg_sched = bg_sched_create(dev);
	assert(dev->bg_sched);
	bg_init_jobs(dev);

	/* start device loop and thread */
	uv_thread_create(&dev->thread_id, reptrans_dev_thread, dev);

	return 0;
}

void
reptrans_add_vdev(struct reptrans* rt, struct repdev* dev) {
	/* add device to the transport */
	uv_rwlock_wrlock(&rt->devlock);
	QUEUE_INSERT_TAIL(&rt->devices, &dev->item);
	uv_rwlock_wrunlock(&rt->devlock);
}
/*
 * All the drivers will call this function in terms of to create
 * per-device loop.
 */
int
reptrans_create_device_loop(struct repdev *dev, uint16_t base_port_offset)
{
	int err;
	struct reptrans *rt = dev->rt;

	if (strlen(dev->name) > REPTRANS_MAX_DEVNAME) {
		log_error(lg, "Cannot start device thread for %s: name is too long",
		    dev->name);
		return -EINVAL;
	}

	/* create new per-device event loop */
	dev->loop = uv_loop_new();
	if (!dev->loop)
		return -ENOMEM;

	if (!(dev->rt->flags & RT_FLAG_STANDALONE)) {
		struct ccowtp_job_config cfg[] = {
			{
				.sched = SCHED_RR,
				.prio = 1,
				.weight = dev->bg_config->tp_hi_weight,
				.min = dev->bg_config->tp_hi_reserved,
				.resiliency = dev->bg_config->tp_hi_resiliency
			},
			{
				.sched = SCHED_OTHER,
				.prio = 0,
				.weight = dev->bg_config->tp_mid_weight,
				.min = dev->bg_config->tp_mid_reserved,
				.resiliency = dev->bg_config->tp_mid_resiliency
			},
			{
				.sched = SCHED_OTHER,
				.prio = 0,
				.weight = dev->bg_config->tp_low_weight,
				.min = dev->bg_config->tp_low_reserved,
				.resiliency = dev->bg_config->tp_low_resiliency
			}
		};
		dev->tp = ccowtp_create(dev->loop, cfg, 3,
			dev->bg_config->thread_pool_size);
		assert(dev->tp);
		dev->robj_lock = reptrans_lock_create();
		/* default base 10400, so devices spread out... 10401,10402,etc */
		dev->listen_port = ccow_daemon->server_port + base_port_offset;
		/*
		 * FIXME: we'll need to enhance libreplicast with ability to reply
		 *        to via less loaded interface. At the moment all the replies
		 *        goes via very first selected interface.
		 */
		char listen_addr[INET6_ADDRSTRLEN + IFNAMSIZ];

		/* rcvd_cache for in-memory puts and gets */
		err = reptrans_init_rcvd_cache(dev);
		if (err < 0) {
			log_error(lg, "Unable to initialize the RCVD cache");
			return err;
		}

		dev->vmm_ht = ccow_vmmcache_create();
		if (!dev->vmm_ht) {
			log_error(lg, "Unable to initialize the VMM cache");
			return -ENOMEM;
		}

		/* building msg_origin_addr */
		char msg_origin_addr[INET6_ADDRSTRLEN + IFNAMSIZ];
		if (ccow_daemon->server_ip4addr) {
			strcpy(msg_origin_addr, ccow_daemon->server_ip4addr);
			strcpy(listen_addr, ccow_daemon->server_ip4addr);
		} else {
			if (strncmp(ccow_daemon->server_ip6addr, "::",
				    strlen("::")) == 0) {
				err = find_ipv6local(ccow_daemon->if_names[0],
						     msg_origin_addr);
				if (err != 0)
					return err;
			} else
				snprintf(msg_origin_addr, INET6_ADDRSTRLEN + IFNAMSIZ,
				    "%s", ccow_daemon->server_ip6addr);

			snprintf(listen_addr, INET6_ADDRSTRLEN + IFNAMSIZ,
			    "::%%%s", ccow_daemon->if_names[0]);
		}

		uv_mutex_lock(&rt->tc_mutex);
		dev->robj = replicast_init(dev->name, dev->loop,
		    listen_addr, dev->listen_port, NULL, msg_origin_addr, listen_addr,
		    ccow_daemon->mcbase_port, ccow_daemon->mc_ttl, dev);
		if (!dev->robj) {
			uv_mutex_unlock(&rt->tc_mutex);
			log_error(lg, "Cannot start device thread for %s",
				  dev->name);
			return -EIO;
		}
		uv_mutex_unlock(&rt->tc_mutex);
		replicast_vbuf_init(&dev->robj->rvbuf, ccow_daemon->if_speeds[0]);
		dev->robj->server_ctx = ccow_daemon;
		dev->robj->dev_ctx = dev;
		replicast_state_init(dev->robj, RT_NAMED_CHUNK_PUT_PROPOSAL,
		    namedput_srv_init);
		replicast_state_init(dev->robj, RT_UNNAMED_CHUNK_PUT_PROPOSAL,
		    unnamedput_srv_init);
		replicast_state_init(dev->robj, RT_NAMED_CHUNK_GET, namedget_srv_init);
		replicast_state_init(dev->robj, RT_UNNAMED_CHUNK_GET,
		    unnamedget_srv_init);
		replicast_state_init(dev->robj, RT_PINGPONG, pingpong_init);
		replicast_state_init(dev->robj, RT_NGREQUEST, ngrequest_init);
		replicast_state_init(dev->robj, RT_NGREQUEST_COUNT, ngrequest_count_init);
		replicast_state_init(dev->robj, RT_NGREQUEST_PURGE, ngrequest_purge_init);
		replicast_state_init(dev->robj, RT_NGREQUEST_LOCATE, ngrequest_locate_init);
		replicast_state_init(dev->robj, RT_RECOVERY, recovery_request_init);
		replicast_state_init(dev->robj, RT_OPP_STATUS, opps_request_init);
		replicast_state_init(dev->robj, RT_ROWEVAC, rowevac_request_init);
		replicast_state_init(dev->robj, RT_RES_GET, resget_srv_init);

		/* Periodically monitor performance stats on the disk */
		uv_timer_init(dev->loop, &dev->vdevstats_timer);
		dev->vdevstats_timer.data = dev;
		uv_timer_start(&dev->vdevstats_timer, dev_perfmon,
				DEV_PERFMON_START_TIMER_MS, DEV_PERFMON_TIMER_MS);
		uv_timer_init(dev->loop, &dev->ts_store_timer);
		dev->ts_store_timer.data = dev;
		uv_timer_start(&dev->ts_store_timer, reptrans_sync_timestamp,
			TIMESTAMP_TIMER_MS, TIMESTAMP_TIMER_MS);

		log_debug(lg, "dev %s bg cfg: ver(%ld,%ld,%u,%u),sr(%ld,%ld,%u,%u),"
				"rep(%ld,%ld,%u,%u),gc(%ld,%ld,%u,%u),utilt(%f),"
				"utilh(%f), sbrt(%ld) vqt(%ld)",
				dev->path,
				dev->bg_config->backref_verify_start_ms,
				dev->bg_config->backref_verify_timer_ms,
				dev->bg_config->verify_priority,
				dev->bg_config->verify_exlusive,
				dev->bg_config->space_reclaim_start_ms,
				dev->bg_config->space_reclaim_timer_ms,
				dev->bg_config->space_reclaim_priority,
				dev->bg_config->space_reclaim_exclusive,
				dev->bg_config->replication_start_ms,
				dev->bg_config->replication_timer_ms,
				dev->bg_config->replication_priority,
				dev->bg_config->replication_exclusive,
				dev->bg_config->gc_start_ms,
				dev->bg_config->gc_timer_ms,
				dev->bg_config->gc_priority,
				dev->bg_config->gc_exclusive,
				dev->bg_config->dev_utilization_threshold_low,
				dev->bg_config->dev_utilization_threshold_high,
				dev->bg_config->speculative_backref_timeout,
				dev->bg_config->version_quarantine_timeout);

		ccowd_wait_for_fhrebuild_term(&dev->terminating);
		dev->bg_sched = bg_sched_create(dev);
		assert(dev->bg_sched);
		bg_init_jobs(dev);
		dev->verify_delay_avg = 100;
		dev->incoming_batch_delay_avg = 100;
		dev->ngcount_delay_avg = 100;
		dev->hc_flush = 0;
		reptrans_stable_version_init(dev);
		reptrans_device_rowusage_init(&dev->rowusage_list);

		reptrans_perf_limiter_create(&dev->ngcount_limiter,
			NGCOUNT_OPS_LIMIT, 1000000U);

		/* Initializing blob touch queues */
		size_t depth = 0;
		if (is_embedded())
			depth = REPDEV_TOUCH_QUEUE_SIZE_EMBEDDED/sizeof(struct touch_queue_entry);
		else
			depth = REPDEV_TOUCH_QUEUE_SIZE/sizeof(struct touch_queue_entry);
		dev->tchqs = je_calloc(depth, sizeof(struct touch_queue_entry));
		dev->tchq_free = lfqueue_create(depth);
		dev->tchq_inprog = lfqueue_create(depth);
		for (size_t i = 0; i < depth; i++)
			lfqueue_enqueue(dev->tchq_free, dev->tchqs + i);
		dev->ttable = NULL;
#if 0
		/* send out the subscriptions */
		reptrans_subscribe_events(dev);
#endif
	}

	QUEUE_INIT(&dev->rtfree_timer_queue);
	QUEUE_INIT(&dev->call_queue);
	QUEUE_INIT(&dev->lock_q);
	QUEUE_INIT(&dev->reqfree_queue);
	dev->exit_handle.data = dev;
	QUEUE_INIT(&dev->mcjoin_queue);

	uv_mutex_init(&dev->hc_mutex);
	uv_sem_init(&dev->recover_sem, DEV_RECOVER_INPROG_MAX);
	uv_async_init(dev->loop, &dev->exit_handle, reptrans_dev__on_exit);
	uv_mutex_init(&dev->call_mutex);
	uv_mutex_init(&dev->stats.stat_mutex);
	uv_mutex_init(&dev->stats.gw_stat_mutex);
	uv_mutex_init(&dev->lk_mutex);
	uv_mutex_init(&rt->ts_mutex);
	uv_async_init(dev->loop, &dev->call_async, reptrans_dev__on_call);
	uv_rwlock_init(&dev->term_lock);

	dev->sop_queues = sop_list_ht_create();
	if (!dev->sop_queues) {
		log_error(lg, "could not initiate sop_queues for %s device", dev->name);
		return -ENOMEM;
	}

	/* start device loop and thread */
	uv_thread_create(&dev->thread_id, reptrans_dev_thread, dev);

	/* Initialize locking */
	rt_locks_init(dev);
	return 0;
}

static int
rt_reptrans_enum(struct reptrans *rt, reptrans_enum_cb_t cb, void *arg,
    reptrans_done_cb_t done, uint64_t timeout)
{
	QUEUE *d;
	uv_rwlock_rdlock(&rt->devlock);
	QUEUE_FOREACH(d, &rt->devices) {
		struct repdev *dev;
		dev = QUEUE_DATA(d, struct repdev, item);
		uv_rwlock_rdunlock(&rt->devlock);

		if (cb) {
			struct repdev_call  *call =
				je_calloc(1, sizeof(struct repdev_call));
			if (call == NULL) {
				return -ENOMEM;
			}
			if (done) {
				struct reptrans_call *rtc = je_calloc(1,
					sizeof(struct reptrans_call));
				if (rtc == NULL) {
					je_free(call);
					return -ENOMEM;
				}
				rtc->method = done;
				rtc->dev = dev;
				rtc->arg = arg;
				/* status will be assigned by the wrapper */
				call->done = rtc;
			}

			call->method = reptrans_dev_async_call__wrapper;
			call->args[0] = cb;
			call->args[1] = dev;
			call->args[2] = arg;
			QUEUE_INIT(&call->item);
			uv_mutex_lock(&dev->call_mutex);
			QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
			uv_mutex_unlock(&dev->call_mutex);
			/* Send messages */
			uv_async_send(&dev->call_async);
			/* wait for completion with timeout ? */
		} else {
			done(dev, arg, 0);
		}

		uv_rwlock_rdlock(&rt->devlock);
	}
	uv_rwlock_rdunlock(&rt->devlock);
	return 0;
}

static void
reptrans_count_dev(struct repdev *dev, void *arg, int status)
{
	/* Don't count GW cache */
	if (dev->gw_cache)
		return;

	int *count = (int *)arg;
	assert(count);
	(*count)++;
}

static void
reptrans_get_flexcounts(struct repdev *dev, struct cl_vdev *vdev)
{
	uint64_t buf[HASHCOUNT_TAB_LENGTH];
	assert(dev != NULL);
	assert(vdev != NULL);
	vdev->vdevid = dev->vdevid;
	vdev->port = dev->listen_port;
	vdev->activerows = 0;
	int new_dev = 0;

	memset(&buf[0], 0, sizeof (buf));
	uv_mutex_lock(&dev->hc_mutex);

	/*
	 * If device is new, flag will be set.
	 */
	if (dev->stats.hashcount[HASHCOUNT_TAB_LENGTH]) {
		/* device has no HASHCOUNT on it */
		vdev->numrows = 0;
		new_dev = 1;
	} else {
		vdev->numrows = FLEXHASH_MAX_TAB_LENGTH;
		memcpy(buf, dev->stats.hashcount,
			HASHCOUNT_TAB_LENGTH * sizeof (uint64_t));
	}

	vdev->size = dev->stats.physical_capacity;
	vdev->avail =  dev->stats.physical_capacity - dev->stats.used;
	uv_mutex_unlock(&dev->hc_mutex);

	/*
	 * We convert from device larger HC array (64bit counters) to what
	 * is our FH maximum can ever be.
	 *
	 * This reducing amount of traffic which is going on on clengine
	 * during FH rebuilds...
	 */
	memset(&vdev->hashcount[0], 0, sizeof(vdev->hashcount));

	for (int i = 0; !new_dev && i < HASHCOUNT_TAB_LENGTH; ++i) {
		int row = i % FLEXHASH_MAX_TAB_LENGTH;
		vdev->hashcount[row] += buf[i];
	}

	for (int i = 0; !new_dev && i < FLEXHASH_MAX_TAB_LENGTH; i++) {
		int row = i % FLEXHASH_MAX_TAB_LENGTH;
		if (vdev->hashcount[row] > 0)
			vdev->activerows++;
	}

	repdev_status_t vdev_status = reptrans_dev_get_status(dev);
	switch (vdev_status) {
	case REPDEV_STATUS_READONLY_FULL:
	case REPDEV_STATUS_READONLY_DATA:
	case REPDEV_STATUS_READONLY_ROWEVAC:
	case REPDEV_STATUS_READONLY_FORCED:
	case REPDEV_STATUS_READONLY_FAULT:
		vdev->state = VDEV_STATE_READ_ONLY;
		break;

	case REPDEV_STATUS_ALIVE:
	case REPDEV_STATUS_INIT:
		vdev->state = VDEV_STATE_ALIVE;
		break;

	case REPDEV_STATUS_UNAVAILABLE:
		vdev->state = VDEV_STATE_DEAD;
		break;
	default:
		vdev->state = VDEV_STATE_DEAD;
		break;
	};
}

uint64_t
reptrans_get_flexcount(struct repdev *dev, uint16_t ngnum, int fhnumrows)
{
	uint64_t flexcount = 0;
	int i;
	uv_mutex_lock(&dev->hc_mutex);
	for (i = ngnum; i < HASHCOUNT_TAB_LENGTH; i += fhnumrows)
		flexcount += dev->stats.hashcount[i];
	uv_mutex_unlock(&dev->hc_mutex);
	return flexcount;
}

size_t
reptrans_get_rowusage(struct repdev *dev, uint16_t ngnum, int fhnumrows)
{
	size_t rowusage = 0;
	int i;
	uv_mutex_lock(&dev->hc_mutex);
	for (i = ngnum; i < HASHCOUNT_TAB_LENGTH; i += fhnumrows)
		rowusage += dev->stats.rowusage[i];
	uv_mutex_unlock(&dev->hc_mutex);
	return rowusage;
}

int
reptrans_copy_hashcount(int rt_num, struct cl_node *node)
{
	QUEUE *q;
	struct reptrans *rt;
	int n_dev = 0, i = 0;
	struct reptrans_hashcount  *rhc;

	reptrans_enum(NULL, &n_dev, reptrans_count_dev, 0);
	if (n_dev == 0)
		return 0;

	if (node->vdevs) {
		je_free(node->vdevs);
		node->nr_vdevs = 0;
	}
	node->vdevs = je_calloc(n_dev, sizeof (struct cl_vdev));
	if (node->vdevs == NULL)
		goto nomem;
	node->nr_vdevs = n_dev;

	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);

		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);

			if (!dev->gw_cache) {
				reptrans_get_flexcounts(dev, node->vdevs + i);
				i++;
			}

			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}
	log_debug(lg, "reptrans initialized for %d devices", n_dev);
	return 0;
nomem:
	log_error(lg, "Cannot allocate memory for hash count table\n");
	return -ENOMEM;
}

int
reptrans_estimate_row_usage(struct repdev* dev, uint16_t row, int numrows, size_t* n_estimated) {
	if (dev->terminating)
		return -ENODEV;
	size_t rc = 0;
	for (size_t i = row; i < HASHCOUNT_TAB_LENGTH; i += numrows) {
		rc += dev->stats.hashcount[i];
	}
	*n_estimated = rc;
	return 0;
}

static int
reptrans_load_config(struct reptrans* rt)
{
	QUEUE *d;

	QUEUE_FOREACH(d, &rt->devices) {
		int err;
		uv_buf_t key, value;
		struct repdev *dev;

		dev = QUEUE_DATA(d, struct repdev, item);

		if (!dev->__vtbl)
			continue;
		int dev_ro = 0;
		repdev_status_t dev_status = reptrans_dev_get_status(dev);

		if (dev_status == REPDEV_STATUS_UNAVAILABLE)
			continue;

		dev_ro = dev_status == REPDEV_STATUS_READONLY_FORCED ||
			dev_status == REPDEV_STATUS_READONLY_FAULT;
		/* Load hashcount */
		key.len = strlen(HASHCOUNT_BLOB_KEY) + 1;
		key.base = HASHCOUNT_BLOB_KEY;
		err = dev->__vtbl->config(dev, CFG_READ, &key, &value);
		if (err) {
			if (err == -ENOENT) {
				log_debug(lg, "Dev(%s) hascount is absent, "
					"skipping", dev->path);
				dev->stats.hashcount[HASHCOUNT_TAB_LENGTH] = 1;
				err = 0;
			}
			if (err)
				return err;
		} else if (value.len == sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH) {
			memcpy(&dev->stats.hashcount, value.base,
				sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH);
			dev->stats.hashcount[HASHCOUNT_TAB_LENGTH] = 0;
		} else {
			log_error(lg,"Dev(%s) wrong hashcount size: "
				"%lu vs %lu", dev->path, value.len,
				sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH);
			err = -EINVAL;
			return err;
		}

		/* Load rowusage */
		key.len = strlen(ROWUSAGE_BLOB_KEY) + 1;
		key.base = ROWUSAGE_BLOB_KEY;
		err = dev->__vtbl->config(dev, CFG_READ, &key, &value);
		if (err) {
			if (err == -ENOENT) {
				log_debug(lg, "Dev(%s) rowusage is absent, "
					"skipping", dev->path);
				dev->stats.rowusage[HASHCOUNT_TAB_LENGTH] = 1;
				err = 0;
			}
			if (err)
				return err;
		} else if (value.len == sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH) {
			memcpy(&dev->stats.rowusage, value.base,
				sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH);
			dev->stats.rowusage[HASHCOUNT_TAB_LENGTH] = 0;
		} else {
			log_error(lg,"Dev(%s) wrong rowusage size: "
				"%lu vs %lu", dev->path, value.len,
				sizeof (uint64_t) * HASHCOUNT_TAB_LENGTH);
			err = -EINVAL;
			return err;
		}

		/* Load timestamp */
		key.len = strlen(TIMESTAMP_KEY) + 1;
		key.base = TIMESTAMP_KEY;
		value.len = 0;
		value.base = NULL;

		err = dev->__vtbl->config(dev, CFG_READ, &key, &value);
		if (err) {
			if (err == -ENOENT) {
				log_warn(lg, "Dev(%s) timestamp is absent, "
					"forcing to zero", dev->path);
				if (!dev_ro) {
					dev->timestamp = 0;
					value.len = sizeof(uint64_t);
					value.base = (char*)&dev->timestamp;
					err = dev->__vtbl->config(dev, CFG_WRITE,
						&key, &value);
				} else
					err = 0;
			}
			if (err)
				return err;
		}

		if (value.len == sizeof(uint64_t)) {
			memcpy(&dev->timestamp, value.base, sizeof(uint64_t));
			log_notice(lg, "Dev(%s) loaded TS=%lu", dev->path, dev->timestamp);
		} else {
			log_error(lg,"Dev(%s) wrong size of timestamp entry: "
				"%lu vs %lu", dev->path, value.len, sizeof(uint64_t));
			err = -EINVAL;
			return err;
		}
	}
	return 0;
}

static void
replicast_work_done_cb(void *arg, int status)
{
	struct repdev* dev = arg;
	/* dev may not be accessible at this point if terminating */
	if (ccowd_terminating)
		return;
	dev->reptrans_ts_sync_inprog = 0;
}

static void
ts_sync_work(void* arg) {
	struct repdev* dev = arg;
	int err = reptrans_refresh_status(dev, TT_HASHCOUNT, ioTypeWrite);

	if (err || dev->terminating || !dev->__vtbl)
		return;

	uv_buf_t key, value;
	key.len = strlen(TIMESTAMP_KEY) + 1;
	key.base = TIMESTAMP_KEY;
	value.len = sizeof(uint64_t);
	value.base = (char*)&dev->sync_timestamp;
	err = dev->__vtbl->config(dev, CFG_WRITE, &key, &value);
	if (!err)
		log_debug(lg, "Dev(%s) timestamp stored %lu", dev->path,
			dev->sync_timestamp);
	else if (err != -EPERM)
		log_error(lg, "Dev(%s) time sync error: %d", dev->path, err);
	reptrans_put_hashcount(dev);
}

static void
reptrans_sync_timestamp(uv_timer_t* handle, int status) {
	struct repdev* dev = handle->data;

	dev->sync_timestamp = reptrans_get_timestamp(dev);

	if (!status) {
		if (dev->terminating)
			return;
		if (dev->reptrans_ts_sync_inprog)
			return;
		dev->reptrans_ts_sync_inprog = 1;
		ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_NORMAL, ts_sync_work,
			replicast_work_done_cb, dev);
	} else {
		ts_sync_work(dev);
		replicast_work_done_cb(dev, 0);
	}
}

struct repdev_open_arg {
	pthread_t tid;
	struct repdev* dev;
	int err;
	int started;
};

static void*
reptrans_dev_open_thread(void* arg) {
	struct repdev_open_arg* p = arg;
	p->err = p->dev->rt->dev_open(p->dev);
	return p;
}

int
reptrans_init_common(uint64_t timeout, struct cl_node *this_node,
	uint32_t flags, const struct repdev_bg_config* cfg, void* rt_params)
{
	QUEUE *q;
	struct reptrans *rt = NULL;
	int rt_num = 0, err = 0;

	err = ec_cm_init();
	if (err) {
		log_error(lg, "Error initializing EC codec manager: %d", err);
		return err;
	}
	/*
	 * Load transport driver configuration file and initialize it
	 */
	QUEUE_FOREACH(q, &all_rts) {
		rt = QUEUE_DATA(q, struct reptrans, item);

		if (cfg)
			rt->dev_bg_config = *cfg;
		else
			bg_set_default_config(&rt->dev_bg_config);

		uv_rwlock_init(&rt->devlock);
		uv_rwlock_init(&rt->cl_healthy_lock);
		rt->flags = flags;
		rt->ts_offset = ~0UL;
		QUEUE_INIT(&rt->devices);
		uv_mutex_init(&rt->tc_mutex);
		uv_mutex_init(&rt->trlog_mutex);
		uv_mutex_init(&rt->comp_mutex);
		uv_mutex_init(&rt->comp_stat_mutex);
		rt->max_comp_entries = 10;
		rt->comp_stat = je_calloc(rt->max_comp_entries,
			sizeof(struct compactify_status));
		rt->comp_entries = 0;
		rt->init_traits = rt_params;
		uv_mutex_lock(&rt->comp_mutex);
		if (!(flags & RT_FLAG_STANDALONE)) {
			/*
			 * In the standalone mode we aren't going to use
			 * any call queues or background jobs. Initialize
			 * minimum reptrans and repdev functions to be able
			 * to call functions like reptrans_get_blob, reptrans_put_blob,
			 * e.g. functions-wrappers for struct repdev_vtbl
			 */
			uv_mutex_init(&rt->call_mutex);
			QUEUE_INIT(&rt->call_queue);
			uv_async_init(ccow_daemon->loop, &rt->call_async,
			    reptrans_done__on_call);

			rt->dev_enum = rt_reptrans_enum;
			QUEUE_INIT(&rt->recovery_queue);
			uv_mutex_init(&rt->recovery_queue_mutex);

			/* Create a srubber-dedicated log file */
			char *env_level = getenv(CCOW_LOG_LEVEL);
			char *env_colors = getenv(CCOW_LOG_COLORS);
			char *env_stdout = getenv(CCOW_LOG_STDOUT);

			unsetenv(CCOW_LOG_COLORS);
			unsetenv(CCOW_LOG_STDOUT);
			setenv(CCOW_LOG_LEVEL, "5", 1);

			rt->scrub_lg = Logger_create(cfg->scrubber_log_name);
			if (!rt->scrub_lg) {
				err = -ENOMEM;
				goto done;
			}

			if (env_level)
				setenv(CCOW_LOG_LEVEL, env_level, 1);
			if (env_colors)
				setenv(CCOW_LOG_COLORS, env_colors, 1);
			if (env_stdout)
				setenv(CCOW_LOG_STDOUT, env_stdout, 1);
			rt->chids_ht = hashtable_create(CHIDS_HASHTABLE_SIZE, 0,
				0.05);
			uv_mutex_init(&rt->opps_lock);
		}

		/*
		 * Transport driver configuration file is <name>.json
		 */
		char conffile[1024];
		sprintf(conffile, TRANS_CONF_DIR "/%s.json", nedge_path(), rt->name);

		/*
		 * Read configuration file
		 */
		rtbuf_t *rb = reptrans_read_file(conffile);
		if (!rb) {
			log_warn(lg, "Cannot open configuration file %s",
			    conffile);

			err = -EBADF;
			goto done;
		}

		/*
		 * Parse configuration file
		 */
		json_value *opts = json_parse(rtbuf(rb, 0).base,
		    rtbuf(rb, 0).len);
		if (!opts) {
			log_warn(lg, "Cannot parse configuration file %s",
			    conffile);
			rtbuf_destroy(rb);

			err = -EBADF;
			goto done;
		}

		rtbuf_destroy(rb);

		/*
		 * TRANSPORT INITIALIZATION - PROBING
		 * After probe rt->devices will have a list of all known devices,
		 * including detached or faulted.
		 */

		err = rt->probe(opts, rt);
		json_value_free(opts);
done:
		if (err >= 0) {
			static uint16_t base_port_offset = 1;
			QUEUE* q = NULL;
			rt->ndevs = err;
			struct repdev_open_arg args[err];
			int n = 0;
			QUEUE_FOREACH(q, &rt->devices) {
				struct repdev *dev;
				dev = QUEUE_DATA(q, struct repdev, item);
				/* For each new VDEV create corresponding network services */
				if (dev->gw_cache && ccow_daemon)
					reptrans_create_cache_loop(dev, base_port_offset);
				else
					reptrans_create_device_loop(dev, base_port_offset);
				base_port_offset++;
				args[n].started = 0;
				if (reptrans_dev_get_status(dev) != REPDEV_STATUS_UNAVAILABLE) {
					/* Attach each VDEV to its key-value engine */
					args[n].dev = dev;
					args[n].err = 0;
					err = pthread_create(&args[n].tid, NULL, reptrans_dev_open_thread, args + n);
					if (!err)
						args[n].started = 1;
					else
						log_error(lg, "Dev(%s) repdev open thread create error: %d",
							dev->name, err);
				} else if (!(rt->flags & RT_FLAG_STANDALONE)) {
					char dst[INET6_ADDRSTRLEN];
					struct server_stat *server = server_get();
					inet_ntop(AF_INET6, &ccow_daemon->msg_origin_sockaddr.sin6_addr,
						dst, INET6_ADDRSTRLEN);
					auditc_servervdev(gauge, "clengine.server",
						&server->id, &dev->vdevid, dst, 0.0);
					bg_sched_suspend(dev->bg_sched, 1);
				}
				n++;
			}
			for (int i = 0; i < n; i++) {
				if (!args[i].started)
					continue;
				pthread_join(args[i].tid, NULL);
				if (args[i].err) {
					log_error(lg, "Dev(%s) unable to open VDEV: %d",
						args[i].dev->name, args[i].err);
				}
			}
			rt->active_ec_bg_limit = rt->ndevs * EC_BG_MAX;
			int rc = reptrans_load_config(rt);
			if (rc) {
				uv_mutex_unlock(&rt->comp_mutex);
				log_error(lg, "Error loading reptrans configuration: %d", rc);
				return rc;
			}
			rt_num++;
		}
		uv_mutex_unlock(&rt->comp_mutex);
	}

	if (this_node && rt_num) {
		err = reptrans_copy_hashcount(rt_num, this_node);
		if (err)
			return err;
	}

	if (rt) {
		rt->tc_pool_sz = rt->dev_bg_config.tenant_pool_sz;
		if (is_embedded() && rt->ndevs)
			rt->tc_pool_sz = rt->ndevs;
		for (uint8_t i = 0; i < rt->tc_pool_sz; i++) {
			rt->tc_pool[i] = NULL;
			rt->tc_ref[i] = 0;
		}
	}
	if (err)
		return err;

	for (size_t i = 0; i < sizeof(rtipcmds)/sizeof(rtipcmds[0]); i++)
		ccowd_register_ipc_cmd(rtipcmds + i);
	return rt_num;
}

#define MAXPATH 128

int
reptrans_init(uint64_t timeout, struct cl_node *this_node,
	const struct repdev_bg_config* cfg, uint32_t flags,
	int transport_count, char *transport_name[], void* params)
{
	/*
	 * certain external libraries will fail to initialize a logger instance
	 * this work around allows it to work by creating one when NULL. If this
	 * happens be loud about it so that it wont go unnoticed
	 *
	 */

	if (lg == NULL) {
		lg = Logger_create("reptrans");
		log_warn(lg, "implicitly created logger as none was provided");
	}

	if (flags & RT_FLAG_STANDALONE)
		load_crypto_lib();

	for (int i = 0; i < transport_count; ++i) {
		char lib_name[MAXPATH];
		void *lib_handle = NULL;
		struct reptrans *rt = NULL;
		if (snprintf(lib_name, MAXPATH, "lib%s.so",
				transport_name[i]) <= 0)
			panic("invalid transport name '%s'\n",
				transport_name[i]);
		lib_handle = dlopen(lib_name, RTLD_LAZY | RTLD_LOCAL);
		if (!lib_handle) {
			char *errstr = dlerror();
			panic("cannot load '%s' library: %s\n", lib_name,
				errstr ? errstr :  "unknown error in dlopen");
		}
		rt = dlsym(lib_handle, transport_name[i]);
		if (!rt || !rt->probe)
			panic("the rt '%s' is incomplete\n",
				transport_name[i]);
		rt->handle = lib_handle;
		QUEUE_INIT(&rt->item);
		QUEUE_INSERT_TAIL(&all_rts, &rt->item);

	}

	int err = reptrans_init_common(timeout, this_node, flags, cfg, params);
	if (err > 0) {
		/* Mark VDEVs alive */
		struct reptrans *rt = NULL;
		QUEUE *q;

		QUEUE_FOREACH(q, &all_rts) {
			QUEUE *d;
			rt = QUEUE_DATA(q, struct reptrans, item);
			if (!rt)
				continue;
			QUEUE_FOREACH(d, &rt->devices) {
				struct repdev *dev;
				dev = QUEUE_DATA(d, struct repdev, item);
				if (reptrans_dev_get_status(dev) == REPDEV_STATUS_INIT)
					reptrans_dev_set_status(dev, REPDEV_STATUS_ALIVE);
			}
		}
	}
	return err;
}

int reptrans_enum(reptrans_enum_cb_t cb, void *arg,
    reptrans_done_cb_t done, uint64_t timeout)
{
	QUEUE *q;
	struct reptrans *rt;
	int rc;

	/*
	 * Iterate through all transports calling enum()
	 */
	QUEUE_FOREACH(q, &all_rts) {
		rt = QUEUE_DATA(q, struct reptrans, item);
		rt->dev_enum(rt, cb, arg, done, timeout);
	}
	return 0;
}

static void stat_done_helper(struct repdev *dev, void *arg, int status)
{
	reptrans_stat_cb_t stats_cb = (reptrans_stat_cb_t)arg;
	assert(stats_cb != NULL);
	stats_cb(dev, &dev->stats, status);
}

int reptrans_enum_stat(reptrans_devinfo_req_type_t req,
    reptrans_stat_cb_t stats_cb, uint64_t timeout)
{
	return reptrans_enum(req == STAT_REG_DEVICE ? stat_refresh : NULL,
	    stats_cb, stat_done_helper, timeout);
}

/*
 * Asyncrhonous operation.
 * Causes all VDEVs in all transports to flush their caches (if there are any).
 */
int
reptrans_flush(uint32_t flags)
{
	struct reptrans *rt = NULL;
	QUEUE *q;

	if (ccowd_terminating)
	    return 0;

	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		if (!rt)
			continue;

		log_trace(lg, "Sent flush to repdevs");

		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);

			if (dev->terminating) {
				return 0;
			}
			rt->dev_ctl(dev, vdevCtlFlush, &flags);

			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}

	if (rt && !(rt->flags & RT_FLAG_STANDALONE))
		auditc_flush(ccow_daemon->aclink);

	log_trace(lg, "The reptrans is flushed");
	return 0;
}

int
reptrans_robj_mcproxy(struct replicast *robj, uint16_t fhrow,
    const uv_buf_t buf, ssize_t nread, char *sender)
{
	struct reptrans *rt = NULL;
	QUEUE *q;

	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		if (!rt)
			continue;

		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);

			if (dev->terminating) {
				return -ENODEV;
			}

			/* skip if device isn't part of proxied row */
			if (!dev->joined_rows[fhrow]) {
				uv_rwlock_rdlock(&rt->devlock);
				continue;
			}

			struct replicast_mcproxy_call *call =
				je_calloc(1, sizeof(struct replicast_mcproxy_call));
			if (call == NULL) {
				return -ENOMEM;
			}

			struct replicast *robj = dev->robj;

			/* Send message to remote replicast object */
			call->method = replicast_mcproxy_recv;
			call->args[0] = robj;
			call->args[1] = je_memdup(buf.base, buf.len);
			if (!call->args[1]) {
				je_free(call);
				return -ENOMEM;
			}
			call->args[2] = (void*)(long)buf.len;
			call->args[3] = (void*)(long)nread;
			call->args[4] = je_strdup(sender);
			if (!call->args[4]) {
				je_free(call->args[1]);
				je_free(call);
				return -ENOMEM;
			}
			QUEUE_INIT(&call->item);
			uv_mutex_lock(&robj->mcproxy_mutex);
			QUEUE_INSERT_TAIL(&robj->mcproxy_queue, &call->item);
			uv_mutex_unlock(&robj->mcproxy_mutex);
			uv_async_send(&robj->mcproxy_async);

			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}

	return 0;
}

/*
 *
 */
static int
bg_gw_iterate_blobs_cb(struct repdev *dev, type_tag_t ttag,
       crypto_hash_t hash_type, uint512_t *chid, uv_buf_t *val, void *param)
{
	assert(dev != NULL);

	gw_cache_work_t *work = param;

	uint64_t lwm = dev->bg_config->gw_cache_lw_mark;
	uint64_t capac = dev->stats.physical_capacity;
	uint64_t avail = dev->stats.physical_capacity - dev->stats.used;

	if (!gwcache_contains_chid(chid)) {
		if (avail > lwm)
			reptrans_delete_blob(dev, ttag, hash_type, chid);
	}

	return 0;
}

static void
bg_gw_cache_work(struct bg_job_entry *job, void* data)
{
	gw_cache_work_t *work = data;
	assert(work != NULL);
	assert(work->dev != NULL);

	type_tag_t ttags[] = {TT_CHUNK_PAYLOAD, TT_CHUNK_MANIFEST, TT_VERSION_MANIFEST};
	size_t ttag_cnt = sizeof(ttags)/sizeof(ttags[0]);

	int i, err = 0;

	if (work->dev->gw_cache) {

		uint64_t capac = work->dev->stats.physical_capacity;
		uint64_t hw = work->dev->bg_config->gw_cache_hw_mark;
		uint64_t lw = work->dev->bg_config->gw_cache_lw_mark;
		uint64_t avail = work->dev->stats.physical_capacity - work->dev->stats.used;

		uint64_t hwm = (capac * hw) / 100;
		uint64_t lwm = (capac * lw) / 100;

		work->hw = hwm;
		work->lw = lwm;

		if (avail >= hwm) {
			for (i = 0; i < (int) ttag_cnt; i++) {
				err = reptrans_iterate_blobs(work->dev,
				    ttags[i], bg_gw_iterate_blobs_cb, work, 0);
				assert(err == 0);

				avail = work->dev->stats.physical_capacity - work->dev->stats.used;
				if (avail <= lwm)
					break;

			}
		}
	}

	return;
}

static void
bg_gw_cache_done(struct bg_job_entry* job, void* data)
{
	gw_cache_work_t *work = data;
	assert(work != NULL);

	je_free(work);
}

static int
bg_gw_cache_init(struct bg_job_entry* job, void** pdata)
{
	gw_cache_work_t *work = je_calloc(1, sizeof(gw_cache_work_t));
	if (!work)
		return -ENOMEM;

	work->dev = job->sched->dev;
	*pdata = work;

	return 0;
}

int
reptrans_gw_cache_gc(void)
{
	struct reptrans *rt = NULL;
	QUEUE *q;

	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		if (!rt)
			continue;

		log_trace(lg, "Sent GW CACHE to repdevs");

		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);

			if (dev->terminating) {
				return 0;
			}

			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}

	return 0;
}

static void
compactify_status_cb(const struct compactify_status* status) {
	static const char* status_name[] = {
			"DONE","PROGRESS", "ERROR"
	};
	struct repdev* dev = status->dev;
	uv_mutex_lock(&dev->rt->comp_stat_mutex);
	size_t n = 0;
	for (n = 0; n < dev->rt->comp_entries; n++) {
		if (dev->rt->comp_stat[n].dev == status->dev)
			break;
	}
	if (n == dev->rt->comp_entries) {
		/* not found, create one */
		if (n >= dev->rt->max_comp_entries) {
			dev->rt->comp_stat = je_realloc(dev->rt->comp_stat,
				dev->rt->max_comp_entries*2*sizeof(struct compactify_status));
			dev->rt->max_comp_entries *= 2;
		}
		dev->rt->comp_entries++;
	}
	dev->rt->comp_stat[n] = *status;
	/* refresh JSON file */
	char comp_path[PATH_MAX];
	snprintf(comp_path, sizeof(comp_path), COMPACTIFY_STATUS_FILE, nedge_path());
	FILE* file = fopen(comp_path, "w+");
	if (!file) {
		log_error(lg, "Couldn't open/create compacify status file");
		uv_mutex_unlock(&dev->rt->comp_stat_mutex);
		return;
	}
	fprintf(file, "[\n");
	struct tm *tmp = NULL, tmp2;
	char timestr[20];
	for (int i = 0; i < dev->rt->comp_entries; i++) {
		fprintf(file, "{\"dev\":\"%s\",",dev->rt->comp_stat[i].dev->path);
		tmp = localtime_r(&dev->rt->comp_stat[i].started_at, &tmp2);
		assert(tmp);
		if (tmp) {

			strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tmp);
			fprintf(file, "\"started\": \"%s\",", timestr);
		}
		if (dev->rt->comp_stat[i].done_at) {
			tmp = localtime_r(&dev->rt->comp_stat[i].done_at, &tmp2);
			assert(tmp);
			if (tmp) {
				strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tmp);
				fprintf(file, "\"finished\": \"%s\",", timestr);
			}
		} else {
			fprintf(file, "\"finished\": \"-\",");
		}
		fprintf(file, "\"state\":\"%s\",",
			status_name[dev->rt->comp_stat[i].state]);
		fprintf(file, "\"progress\":%d,", dev->rt->comp_stat[i].progress);
		int compression = 0;
		if (dev->rt->comp_stat[i].orig_size_kb)
			compression = (dev->rt->comp_stat[i].orig_size_kb -
			 dev->rt->comp_stat[i].comp_size_kb) *  100 /
			 dev->rt->comp_stat[i].orig_size_kb;
		fprintf(file, "\"comp_rate\":%d}", compression);
		if ( i < dev->rt->comp_entries - 1)
			fprintf(file, ",\n");
	}
	fprintf(file, "\n]\n");
	fclose(file);
	uv_mutex_unlock(&dev->rt->comp_stat_mutex);
}

static void
compactify_work(void* arg) {
	struct repdev *dev = (struct repdev *)arg;

	if (!dev->__vtbl)
		return;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if(status == REPDEV_STATUS_UNAVAILABLE)
		return;

	uv_mutex_lock(&dev->rt->comp_mutex);
	dev->comp_wip = 1;
	bg_sched_suspend(dev->bg_sched, 1);
	dev->__vtbl->compactify(dev, TT_LAST, 0, compactify_status_cb);
	bg_sched_suspend(dev->bg_sched, 0);
	uv_mutex_unlock(&dev->rt->comp_mutex);
}

static void
compactify_work_done(void* arg, int status) {
	struct repdev *dev = (struct repdev *)arg;
	dev->comp_wip = 0;
	log_notice(lg, "Compactifcation finished on dev %s", dev->path);
}

void
reptrans_compactify() {
	struct reptrans *rt = NULL;
	QUEUE *q;

	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);

		log_notice(lg, "Compactify spawn");
		char comp_path[PATH_MAX];
		snprintf(comp_path, sizeof(comp_path), COMPACTIFY_STATUS_FILE, nedge_path());
		unlink(comp_path);
		memset(rt->comp_stat, 0,
			rt->max_comp_entries*sizeof(struct compactify_status));
		rt->comp_entries = 0;
		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);

			if (!dev->comp_wip && dev->__vtbl && dev->__vtbl->compactify) {
				ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_MID,
					compactify_work,
					compactify_work_done, dev);
			}

			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}
}

static void *
reptrans_term_thread(void *arg) {
	struct repdev* dev = arg;
	struct reptrans* rt = dev->rt;
	struct touch_table_entry* t = NULL, *tmp = NULL;

	if (rt->flags & RT_FLAG_STANDALONE)
		rt->dev_close(dev);

	sop_list_ht_destroy(dev->sop_queues);

	uv_rwlock_wrlock(&dev->term_lock);
	if (dev->tp)
		ccowtp_stop(dev->tp, 0);
	uv_rwlock_wrunlock(&dev->term_lock);

	if (dev->thread_id)
		uv_thread_join(&dev->thread_id);

	rt->dev_free(dev);
	reptrans_destroy_rcvd_cache(dev);
	if (dev->vmm_ht)
		ccow_vmmcache_free(dev->vmm_ht);
	if (dev->tchqs)
		je_free(dev->tchqs);
	HASH_ITER(hh, dev->ttable, t, tmp) {
		HASH_DEL(dev->ttable, t);
		je_free(t);
	}
	uv_mutex_destroy(&dev->lk_mutex);
	uv_mutex_destroy(&dev->call_mutex);
	uv_mutex_destroy(&dev->hc_mutex);
	uv_mutex_destroy(&dev->stats.stat_mutex);
	uv_mutex_destroy(&dev->stats.gw_stat_mutex);
	je_free(dev);
	return NULL;
}

int
reptrans_destroy()
{
	QUEUE *q,*q_dev;
	int rt_full = 0;
	struct repdev *rt_dev;
	int err = 0;

	struct server_stat *server = server_get();

	QUEUE_FOREACH(q, &all_rts) {
		struct reptrans *rt = NULL;
		rt = QUEUE_DATA(q, struct reptrans, item);

		if (rt->flags & RT_FLAG_RDHOLD) {
			QUEUE_FOREACH(q_dev, &rt->devices) {
				rt_dev = QUEUE_DATA(q_dev, struct repdev, item);
				rt->dev_free(rt_dev);
			}
			continue;
		}

		struct repdev *devlist[rt->ndevs];
		pthread_t term_threads[rt->ndevs];
		/* stop the timer and store timestamps */
		rt->terminating = 1;
		/*
		 * Walk through all transport's device and cancel
		 * all outstanding tasks/commands
		 */
		uint32_t n = 0;
		char dst[INET6_ADDRSTRLEN];

		QUEUE_FOREACH(q_dev, &rt->devices) {
			rt_dev = QUEUE_DATA(q_dev, struct repdev, item);
			devlist[n++] = rt_dev;
			/*
			 * Send message to AAS so we know this device is offline.
			 */
			if (!(rt->flags & RT_FLAG_STANDALONE)) {
				repdev_status_t status = reptrans_dev_get_status(rt_dev);
				if (status != REPDEV_STATUS_UNAVAILABLE && status != REPDEV_STATUS_READONLY_FAULT) {
					reptrans_put_hashcount(rt_dev);
					reptrans_dev_set_status(rt_dev, REPDEV_STATUS_INIT);
				}
				inet_ntop(AF_INET6, &ccow_daemon->msg_origin_sockaddr.sin6_addr,
				    dst, INET6_ADDRSTRLEN);
				auditc_servervdev(gauge, "clengine.server", &server->id,
					&rt_dev->vdevid, dst, 0.0);
			}
			rt_dev->terminating = 1;
			/* The lock to be released when the replicast object is destroyed */
			uv_rwlock_rdlock(&rt_dev->term_lock);
			uv_async_send(&rt_dev->exit_handle);
		}
		if (!n && !(rt->flags & RT_FLAG_STANDALONE)) {
			inet_ntop(AF_INET6, &ccow_daemon->msg_origin_sockaddr.sin6_addr,
			    dst, INET6_ADDRSTRLEN);
			auditc_servervdev(gauge, "clengine.server", &server->id,
				&uint128_null, dst, 0.0);
		}
		log_debug(lg, "Sent TERM to %d repdevs", n);
		for (uint8_t i = 0; i < rt->tc_pool_sz; i++) {
			/* will issue abort first */
			reptrans_try_free_tenant_context(rt, i);
		}
		for (uint8_t i = 0; i < rt->tc_pool_sz; i++) {
			while (!reptrans_try_free_tenant_context(rt, i))
				usleep(100000);
		}

		for (uint32_t i = 0; i < n; i++) {
			struct repdev *dev = devlist[i];
			err = pthread_create(term_threads + i, NULL,
				reptrans_term_thread, dev);
			if (err)
				log_error(lg, "Couldn't start a thread %d", err);
		}
		for (uint32_t i = 0; i < n; i++) {
			err = pthread_join(term_threads[i], NULL);
			if (err)
				log_error(lg, "Thread join error %d", err);
		}

		if (err < 0)
			break;

		opps_ht_destroy(rt);
		if (rt->tc_wh)
			ccowtp_destroy_wh(rt->tc_wh);
		/*
		 * TRANSPORT TERMINATION
		 *
		 * destroy() may result in returning negative value which may be
		 * used as a hint that transport is busy.
		 */
		log_debug(lg, "RT(%s): rt_destroy called", rt->name);
		err = rt->destroy();
		if (err)
			break;

		je_free(rt->comp_stat);
		if (!(rt->flags & RT_FLAG_STANDALONE)) {
			rt_full++;
			uv_close((uv_handle_t *)&rt->call_async, NULL);
			log_flush(rt->scrub_lg);
			je_free(rt->scrub_lg);
		}
	}

	if (rt_full)
		auditc_flush(ccow_daemon->aclink);
	ec_cm_exit();

	log_notice(lg, "The reptrans library is de-initialized");
	return err;
}

struct reptrans *
reptrans_find(const char *name)
{
	QUEUE *q;
	struct reptrans *rt;
	int len;

	QUEUE_FOREACH(q, &all_rts) {
		rt = QUEUE_DATA(q, struct reptrans, item);
		len = strlen(rt->name);

		if (strncmp(rt->name, name, len) == 0 && name[len] == '\0')
			return rt;
	}

	return NULL;
}

int
reptrans_key_decode(struct repdev *dev, const char *buffer, int buflen,
    type_tag_t *ttag, crypto_hash_t *hash_type, uint512_t *chid)
{
	int err;
	uint32_t u_ttag = 0;
	uint8_t u_hash_type = 0;

	msgpack_u u;
	msgpack_unpack_init_b(&u, buffer, buflen, 0);

	err = msgpack_unpack_uint32(&u, &u_ttag);
	if (err) {
		log_error(lg, "(%s): Error decoding key: buflen= %d, "
		    "err=%d, u_ttag=%d", dev->name, buflen, err, (int)u_ttag);
		return err;
	}
	*ttag = u_ttag;

	err = msgpack_unpack_uint8(&u, &u_hash_type);
	if (err) {
		log_error(lg, "(%s): Error decoding key: buflen= %d, "
		    "err=%d, u_hash_type=%d", dev->name, buflen, err,
		    (int)u_hash_type);
		return err;
	}
	*hash_type = u_hash_type;

	err = replicast_unpack_uint512(&u, chid);
	if (err) {
		log_error(lg, "(%s): Error decoding key: buflen= %d, err=%d",
		    dev->name, buflen, err);
		uint512_logdump(lg, "Failed key", chid);
	}

	return err;
}

int
reptrans_key_encode(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
    const uint512_t *chid, msgpack_p **packed_typekey)
{
	int err;

	/*
	 * Note: msgpack does key verification on unpack. Device optionally may
	 * implement CRC64 of the key, though it would be a redundant check.
	 */
	msgpack_p *p = msgpack_pack_init();
	if (!p)
		return -ENOMEM;
	err = msgpack_pack_uint32(p, ttag);
	if (err)
		goto _exit;
	err = msgpack_pack_uint8(p, hash_type);
	if (err)
		goto _exit;
	err = replicast_pack_uint512(p, chid);
	if (err)
		goto _exit;
	*packed_typekey = p;
	return 0;
_exit:
	msgpack_pack_free(p);
	return err;
}

int
reptrans_put_hashcount(struct repdev *dev)
{
	uv_buf_t key_hc = {0}, data_hc = {0}, key_rowusage = {0}, data_rowusage = {0};
	int err = 0;

	if (!dev->__vtbl)
		return -EPERM;

	if (!dev->hc_flush)
		return 0;

	if (!dev->stats.hashcount[HASHCOUNT_TAB_LENGTH]) {
		key_hc.len = strlen(HASHCOUNT_BLOB_KEY) + 1;
		key_hc.base = HASHCOUNT_BLOB_KEY;
		data_hc.len = sizeof(uint64_t) * HASHCOUNT_TAB_LENGTH;
		data_hc.base = je_malloc(data_hc.len);
		if (!data_hc.base)
			return -ENOMEM;
	}

	if (!dev->stats.rowusage[HASHCOUNT_TAB_LENGTH]) {
		key_rowusage.len = strlen(ROWUSAGE_BLOB_KEY) + 1;
		key_rowusage.base = ROWUSAGE_BLOB_KEY;
		data_rowusage.len = sizeof(uint64_t) * HASHCOUNT_TAB_LENGTH;
		data_rowusage.base = je_malloc(data_rowusage.len);
		if (!data_rowusage.base) {
			if (data_hc.base)
				je_free(data_hc.base);
			return -ENOMEM;
		}

	}

	if (key_hc.len || key_rowusage.len) {
		uv_mutex_lock(&dev->hc_mutex);
		if (key_hc.len)
			memcpy(data_hc.base, (char*)&dev->stats.hashcount,
				data_hc.len);
		if (key_rowusage.len)
			memcpy(data_rowusage.base, (char*)&dev->stats.rowusage,
				data_rowusage.len);
		dev->hc_flush = 0;
		uv_mutex_unlock(&dev->hc_mutex);
		if (key_hc.len) {
			err = dev->__vtbl->config(dev, CFG_WRITE, &key_hc, &data_hc);
			if (err)
				log_error(lg, "Error writing hashcount: %d", err);
		}
		if (key_rowusage.len) {
			err = dev->__vtbl->config(dev, CFG_WRITE, &key_rowusage, &data_rowusage);
			if (err)
				log_error(lg, "Error writing rowusage: %d", err);
		}
	}
	if (data_hc.base)
		je_free(data_hc.base);
	if (data_rowusage.base)
		je_free(data_rowusage.base);
	return err;
}

void
reptrans_bump_hashcount(struct repdev *dev, const uint512_t *chid, size_t hc_cnt)
{
	assert(chid != NULL);
	uint16_t hashkey = HASHCALC(chid, HASHCOUNT_MASK);

	nassert(dev->loop_thrid != uv_thread_self());

	uv_mutex_lock(&dev->hc_mutex);
	dev->stats.hashcount[hashkey] += hc_cnt;
	dev->hc_flush = 1;

	log_debug(lg, "%s chid.u.u.u %lX HC: inc %x %ld",
	    dev->name, chid->u.u.u, hashkey,
	    dev->stats.hashcount[hashkey]);

	/*
	 * Reset driver flag. Device is not new anymore.
	 */
	dev->stats.hashcount[HASHCOUNT_TAB_LENGTH] = 0;
	uv_mutex_unlock(&dev->hc_mutex);
}

void
reptrans_bump_rowusage(struct repdev *dev, const uint512_t *chid, size_t size)
{
	assert(chid != NULL);
	uint16_t hashkey = HASHCALC(chid, HASHCOUNT_MASK);

	nassert(dev->loop_thrid != uv_thread_self());

	uv_mutex_lock(&dev->hc_mutex);
	dev->stats.rowusage[hashkey] += size;
	dev->hc_flush = 1;

	log_debug(lg, "%s chid.u.u.u %lX ROWUSAGE: inc %x %ld",
	    dev->name, chid->u.u.u, hashkey,
	    dev->stats.rowusage[hashkey]);

	/*
	 * Reset driver flag. Device is not new anymore.
	 */
	dev->stats.rowusage[HASHCOUNT_TAB_LENGTH] = 0;
	uv_mutex_unlock(&dev->hc_mutex);
}

void
reptrans_drop_hashcount(struct repdev *dev, const uint512_t *chid, size_t hc_cnt)
{
	int flush = 0;
	assert(chid != NULL);
	uint16_t hashkey = HASHCALC(chid, HASHCOUNT_MASK);

	nassert(dev->loop_thrid != uv_thread_self());

	uv_mutex_lock(&dev->hc_mutex);
	if (dev->stats.hashcount[hashkey] >= hc_cnt) {
		dev->stats.hashcount[hashkey] -= hc_cnt;
		dev->hc_flush = 1;
		log_debug(lg, "%s chid.u.u.u %lX HC: dec %d %ld",
		    dev->name, chid->u.u.u,
		    hashkey, dev->stats.hashcount[hashkey]);
	}
	uv_mutex_unlock(&dev->hc_mutex);
}

void
reptrans_drop_rowusage(struct repdev *dev, const uint512_t *chid, size_t size)
{
	int flush = 0;
	assert(chid != NULL);
	uint16_t hashkey = HASHCALC(chid, HASHCOUNT_MASK);

	nassert(dev->loop_thrid != uv_thread_self());

	uv_mutex_lock(&dev->hc_mutex);
	if (dev->stats.rowusage[hashkey] >= size) {
		dev->stats.rowusage[hashkey] -= size;
		dev->hc_flush = 1;
		log_debug(lg, "%s chid.u.u.u %lX ROWUSAGE: dec %d %lu",
		    dev->name, chid->u.u.u,
		    hashkey, dev->stats.rowusage[hashkey]);
	}
	uv_mutex_unlock(&dev->hc_mutex);
}

static inline void
reptrans_put_update_latency(struct repdev *dev, uint64_t start, uint64_t end,
	size_t reqlen) {
	if (dev->journal && reqlen < dev->journal_maxchunksize) {
		if (reqlen < 65536) {
			uint64_t norm4k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 4096);
			if (norm4k_latency > DEV_AVGLAT4K_MIN && norm4k_latency < DEV_AVGLAT4K_MAX) {
				dev->stats.put4k_latency_j = avg_ring_update(&dev->put4k_avg_samples_j, norm4k_latency);
				dev->stats.put90th_4k_latency_j = avg_ring_90th(&dev->put4k_avg_samples_j);
			}
		} else if (reqlen < 524288) {
			uint64_t norm64k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 65536);
			if (norm64k_latency > DEV_AVGLAT64K_MIN && norm64k_latency < DEV_AVGLAT64K_MAX) {
				dev->stats.put64k_latency_j = avg_ring_update(&dev->put64k_avg_samples_j, norm64k_latency);
				dev->stats.put90th_64k_latency_j = avg_ring_90th(&dev->put64k_avg_samples_j);

			}
		} else {
			uint64_t norm512k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 524288);
			if (norm512k_latency > DEV_AVGLAT512K_MIN && norm512k_latency < DEV_AVGLAT512K_MAX) {
				dev->stats.put512k_latency_j = avg_ring_update(&dev->put512k_avg_samples_j, norm512k_latency);
				dev->stats.put90th_512k_latency_j = avg_ring_90th(&dev->put512k_avg_samples_j);
			}
		}
	} else {
		if (reqlen < 65536) {
			uint64_t norm4k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 4096);
			if (norm4k_latency > DEV_AVGLAT4K_MIN && norm4k_latency < DEV_AVGLAT4K_MAX) {
				dev->stats.put4k_latency = avg_ring_update(&dev->put4k_avg_samples, norm4k_latency);
				dev->stats.put90th_4k_latency = avg_ring_90th(&dev->put4k_avg_samples);
			}
		} else if (reqlen < 524288) {
			uint64_t norm64k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 65536);
			if (norm64k_latency > DEV_AVGLAT64K_MIN && norm64k_latency < DEV_AVGLAT64K_MAX) {
				dev->stats.put64k_latency = avg_ring_update(&dev->put64k_avg_samples, norm64k_latency);
				dev->stats.put90th_64k_latency = avg_ring_90th(&dev->put64k_avg_samples);
			}
		} else {
			uint64_t norm512k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 524288);
			if (norm512k_latency > DEV_AVGLAT512K_MIN && norm512k_latency < DEV_AVGLAT512K_MAX) {
				dev->stats.put512k_latency = avg_ring_update(&dev->put512k_avg_samples, norm512k_latency);
				dev->stats.put90th_512k_latency = avg_ring_90th(&dev->put512k_avg_samples);
			}
		}
	}
}

int
reptrans_refresh_status(struct repdev *dev, type_tag_t ttag, int io_type) {
	repdev_status_t status = reptrans_dev_get_status(dev);
	repdev_status_t calc_status = status;

	int err = 0;
	/* Neither operations are available in REPDEV_STATUS_UNAVAILABLE state */
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return -EACCES;

	if (status == REPDEV_STATUS_READONLY_FORCED || status == REPDEV_STATUS_READONLY_FAULT) {
		/* Forced read-only permits only read */
		if (io_type == ioTypeWrite || io_type == ioTypeDelete)
			return -EACCESS;
		else
			return 0;
	}

	if (status == REPDEV_STATUS_READONLY_ROWEVAC) {
		/* During row evacuation deletes and read are allowed.
		 * Write operation allowed only for non-data types
		 */
		if (io_type == ioTypeRead || io_type == ioTypeDelete)
			return 0;
		else if (is_ccow_data_tt(ttag))
			return -EACCESS;
		else
			return 0;
	}

	double util = reptrans_get_utilization(dev);
	/* Upgrade of "downgrade" the read-only status based on disk utilization */
	if (util >= dev->bg_config->dev_capacity_max_full)
		calc_status = REPDEV_STATUS_READONLY_FULL;
	else if (is_ccow_data_tt(ttag) && util >= dev->bg_config->dev_capacity_max_data)
		calc_status = REPDEV_STATUS_READONLY_DATA;
	/* And change the status */
	if ((status == REPDEV_STATUS_ALIVE && status != calc_status) ||
		(status == REPDEV_STATUS_READONLY_DATA &&
		calc_status == REPDEV_STATUS_READONLY_FULL)) {
		reptrans_dev_set_status(dev, calc_status);
		status = calc_status;
	}

	if (io_type == ioTypeWrite) {
		/* Permits writes of non-data type tags in READONLY_DATA state */
		if (is_ccow_data_tt(ttag) && status == REPDEV_STATUS_READONLY_DATA)
			err = -EACCES;
		else if (status == REPDEV_STATUS_READONLY_FULL)
			err = -EACCES;
	}
	return err;
}

int
reptrans_put_blob(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid, int compute)
{
	int err;
	uint64_t start = 0, end;

	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl)
		return -EPERM;

	if (dev->terminating && is_bloom_tt(ttag))
		return -ENODEV;

	err = reptrans_refresh_status(dev, ttag, ioTypeWrite);
	if (err)
		return err;

	if (compute) {
		err = rtbuf_hash(rb, hash_type, chid);
		if (err) {
			log_error(lg, "Put(%s): cannot calculate CHID: %d",
				dev->name, err);
			return err;
		}
	}

	if (ttag == TT_CHUNK_PAYLOAD || ttag == TT_CHUNK_MANIFEST || ttag == TT_PARITY_MANIFEST)
		start = uv_hrtime();
	err = dev->__vtbl->put_blob(dev, ttag, hash_type, rb, chid);
	assert(err != -EEXIST);
	if (err < 0)
		goto _exit;
	if (ttag == TT_CHUNK_PAYLOAD || ttag == TT_CHUNK_MANIFEST || ttag == TT_PARITY_MANIFEST) {
		uint64_t end = uv_hrtime();
		size_t reqlen = rtbuf_len(rb);
		uv_mutex_lock(&dev->stats.stat_mutex);
		dev->stats.writes++;
		dev->stats.bytes_out += (uint64_t)reqlen;
		reptrans_put_update_latency(dev, start, end, reqlen);
		uv_mutex_unlock(&dev->stats.stat_mutex);
	}

_exit:
	if (BLOB_REPTRANS_PUT_BLOB_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_PUT_BLOB(dev->name, ttag, hash_type, chidstr,
		compute, err, uv_hrtime() - start);
	}

	if (err == 0) {
		dev->stat_blob_put[ttag]++;
	}

	return 0;
}

int
reptrans_put_blob_with_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid, int compute,
    uint64_t attr) {
	return reptrans_put_blob_with_attr_opts(dev, ttag, hash_type, rb, chid,
		compute, attr, 0);
}

int
reptrans_put_blob_with_attr_opts(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const rtbuf_t *rb, uint512_t *chid, int compute,
    uint64_t attr, uint64_t options)
{
	int err = 0;
	uint64_t start = 0, end;

	nassert(dev->loop_thrid != uv_thread_self());
	assert(is_data_tt(ttag));

	if (!dev->__vtbl) {
		err = -EPERM;
		goto _out;
	}

	if (dev->terminating && is_bloom_tt(ttag))
		return -ENODEV;

	err = reptrans_refresh_status(dev, ttag, ioTypeWrite);
	if (err)
		return err;

	if (compute) {
		err = rtbuf_hash(rb, hash_type, chid);
		if (err) {
			log_error(lg, "Put(%s): cannot calculate CHID: %d",
				dev->name, err);
			goto _out;
		}
	}

	start = uv_hrtime();
	uv_mutex_lock(&dev->stats.stat_mutex);
	dev->write_last = start;
	dev->write_inprog++;
	uv_mutex_unlock(&dev->stats.stat_mutex);
	err = dev->__vtbl->put_blob_with_attr(dev, ttag, hash_type, rb, chid,
	    attr, options);
	uv_mutex_lock(&dev->stats.stat_mutex);
	dev->write_inprog--;
	uv_mutex_unlock(&dev->stats.stat_mutex);
	assert(err != -EEXIST);
	if (err < 0)
		goto _out;
	if (ttag == TT_CHUNK_PAYLOAD || ttag == TT_CHUNK_MANIFEST || ttag == TT_PARITY_MANIFEST) {
		uint64_t end = uv_hrtime();
		size_t reqlen = rtbuf_len(rb);
		uv_mutex_lock(&dev->stats.stat_mutex);
		dev->stats.writes++;
		dev->stats.bytes_out += (uint64_t)reqlen;
		reptrans_put_update_latency(dev, start, end, reqlen);
		uv_mutex_unlock(&dev->stats.stat_mutex);
	}
_out:
	if (BLOB_REPTRANS_PUT_BLOB_WITH_ATTR_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_PUT_BLOB_WITH_ATTR(dev->name, ttag, hash_type,
			chidstr, compute, attr, err, uv_hrtime() - start);
	}
	return err;
}

int
reptrans_get_blob(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, rtbuf_t **rb)
{
	int err;
	uint64_t start = 0, end;

	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl)
		return -EPERM;

	err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	start = uv_hrtime();
	uv_mutex_lock(&dev->stats.stat_mutex);
	dev->read_last = start;
	dev->read_inprog++;
	uv_mutex_unlock(&dev->stats.stat_mutex);
	err = dev->__vtbl->get_blob(dev, ttag, hash_type, GBF_FLAG_ONE,
	    chid, rb, 1, NULL, NULL);
	uv_mutex_lock(&dev->stats.stat_mutex);
	dev->read_inprog--;
	uv_mutex_unlock(&dev->stats.stat_mutex);
	if (err != 0)
		return err;
	if (ttag == TT_CHUNK_PAYLOAD || ttag == TT_CHUNK_MANIFEST || ttag == TT_PARITY_MANIFEST) {
		end = uv_hrtime();
		size_t reqlen = rtbuf_len(*rb);
		uv_mutex_lock(&dev->stats.stat_mutex);
		dev->stats.reads++;
		dev->stats.bytes_in += (uint64_t)reqlen;
		if (ttag == TT_CHUNK_MANIFEST && dev->metadata_mask & DEV_METADATA_CM) {
			if (reqlen < 65536) {
				uint64_t norm4k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 4096);
				if (norm4k_latency > DEV_AVGLAT4K_MIN)
					dev->stats.get4k_latency_m = avg_ring_update(&dev->get4k_avg_samples_m, norm4k_latency);
			} else if (reqlen < 524288) {
				uint64_t norm64k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 65536);
				if (norm64k_latency > DEV_AVGLAT64K_MIN)
					dev->stats.get64k_latency_m = avg_ring_update(&dev->get64k_avg_samples_m, norm64k_latency);
			} else {
				uint64_t norm512k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 524288);
				if (norm512k_latency > DEV_AVGLAT512K_MIN)
					dev->stats.get512k_latency_m = avg_ring_update(&dev->get512k_avg_samples_m, norm512k_latency);
			}
		} else {
			if (reqlen < 65536) {
				uint64_t norm4k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 4096);
				if (norm4k_latency > DEV_AVGLAT4K_MIN)
					dev->stats.get4k_latency = avg_ring_update(&dev->get4k_avg_samples, norm4k_latency);
			} else if (reqlen < 524288) {
				uint64_t norm64k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 65536);
				if (norm64k_latency > DEV_AVGLAT64K_MIN)
					dev->stats.get64k_latency = avg_ring_update(&dev->get64k_avg_samples, norm64k_latency);
			} else {
				uint64_t norm512k_latency = reptrans_normalized_latency((end - start) / 1000, reqlen, 524288);
				if (norm512k_latency > DEV_AVGLAT512K_MIN)
					dev->stats.get512k_latency = avg_ring_update(&dev->get512k_avg_samples, norm512k_latency);
			}
		}
		uv_mutex_unlock(&dev->stats.stat_mutex);
	}
	/* case when LLD is incorrectly returns err */
	if (*rb && (*rb)->nbufs == 0) {
		rtbuf_destroy(*rb);
		*rb = NULL;
		err = -ENOENT;
	}
	if (BLOB_REPTRANS_GET_BLOB_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_GET_BLOB(dev->name, ttag, hash_type, chidstr,
			err, uv_hrtime()-start);
	}

	if (err == 0) {
		dev->stat_blob_get[ttag]++;
	}
	return err;
}

int
reptrans_get_blob_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uint64_t *attr)
{
	int err;
	uint64_t start = 0, end;

	nassert(dev->loop_thrid != uv_thread_self());
	assert(!is_dupsort_tt(ttag));

	if (!dev->__vtbl)
		return -EPERM;

	err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	err = dev->__vtbl->get_blob_attr(dev, ttag, hash_type, chid, attr);
	if (err == 0) {
		dev->stat_blob_get[ttag]++;
	}

	return err;
}

int
reptrans_get_blob_ts(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uint64_t *attr)
{
	int err = 0;
	uint64_t start = uv_hrtime();

	err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	err = reptrans_get_blob_attr(dev, ttag, hash_type, chid, attr);
	if (BLOB_REPTRANS_GET_BLOB_TS_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_GET_BLOB_TS(dev->name, ttag, hash_type, chidstr,
			*attr, err, uv_hrtime() - start);
	}
	return err;
}

int
reptrans_set_blob_attr(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uint64_t attr)
{
	int err;
	uint64_t start = 0, end;

	nassert(dev->loop_thrid != uv_thread_self());
	assert(!is_dupsort_tt(ttag));

	if (!dev->__vtbl)
		return -EPERM;

	if (dev->terminating && is_bloom_tt(ttag))
		return -ENODEV;

	err = reptrans_refresh_status(dev, ttag, ioTypeWrite);
	if (err)
		return err;

	err = dev->__vtbl->set_blob_attr(dev, ttag, hash_type, chid, attr);
	if (err == 0) {
		dev->stat_blob_put[ttag]++;
	}

	return err;
}

int
reptrans_set_blob_ts(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, uint64_t ts)
{
	int err = 0;
	uint64_t start = uv_hrtime();

	err = reptrans_refresh_status(dev, ttag, ioTypeWrite);
	if (err)
		return err;

	err = reptrans_set_blob_attr(dev, ttag, hash_type, chid, ts);
	if (BLOB_REPTRANS_SET_BLOB_TS_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_SET_BLOB_TS(dev->name, ttag, hash_type, chidstr,
			ts, err, uv_hrtime() - start);
	}
	return err;
}

int
reptrans_touch_blob(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid)
{
	int err;

	err = reptrans_refresh_status(dev, ttag, ioTypeWrite);
	if (err)
		return err;

	err = reptrans_blob_stat(dev, ttag, hash_type, chid, NULL);
	if (!err) {
		uint64_t ts = reptrans_get_timestamp(dev);
		err = reptrans_set_blob_ts(dev, ttag, hash_type, chid, ts);
	}

	return err;
}

int
reptrans_get_blob_verify(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, rtbuf_t **rb)
{
	char chidstr[UINT512_BYTES * 2 + 1];
	uint64_t start = uv_hrtime();

	int err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	err = reptrans_get_blob(dev, ttag, hash_type, chid, rb);
	if (err)
		goto _exit;
	uint512_t c_chid;
	err = rtbuf_hash(*rb, hash_type, &c_chid);
	if (err || uint512_cmp(chid, &c_chid)) {
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		if (err)
			log_error(lg, "Dev(%s) %s chunk %s size %lu hashID calculation error %d",
				dev->name, type_tag_name[ttag], chidstr, (*rb)->bufs->len, err);
		else
			log_error(lg, "Dev(%s): %s chunk %s size %lu is corrupt",
			    dev->name, type_tag_name[ttag], chidstr, (*rb)->bufs->len);

		if (!ccow_daemon->keep_corrupted) {
			log_error(lg,
			    "Dev(%s): %s chunk %s size %lu removing corrupted",
			    dev->name, type_tag_name[ttag], chidstr, (*rb)->bufs->len);

			if (ttag == TT_CHUNK_MANIFEST || ttag == TT_VERSION_MANIFEST)
				err = reptrans_delete_manifest(dev, ttag, hash_type, chid);
			else
				err = reptrans_delete_blob(dev, ttag, hash_type, chid);
			if (err)
				log_error(lg,
				    "Dev(%s): removing corrupt %s chunk %s error %d",
				    dev->name, type_tag_name[ttag], chidstr, err);
		}
		rtbuf_destroy(*rb);
		*rb = NULL;
		err = -EIO;
	}
_exit:
	if (BLOB_REPTRANS_GET_BLOB_VERIFY_ENABLED()) {
		uint512_dump(chid, chidstr, UINT512_BYTES * 2 + 1);
		BLOB_REPTRANS_GET_BLOB_VERIFY(dev->name, ttag, hash_type,
			chidstr, err, uv_hrtime()-start);
	}
	return err;
}

int
reptrans_get_blobs(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid, rtbuf_t **rb,
	int max_num, reptrans_blob_filter filter_cb, void *arg)
{
	int err = 0;
	uint64_t start = uv_hrtime();

	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl) {
		err = -EPERM;
		goto _exit;
	}

	err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	err = dev->__vtbl->get_blob(dev, ttag, hash_type, GBF_FLAG_ALL,
	    chid, rb, max_num, filter_cb, arg);
_exit:
	if (BLOB_REPTRANS_GET_BLOBS_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_GET_BLOBS(dev->name, ttag, hash_type, chidstr,
			max_num, err, uv_hrtime() - start);
	}
	return err;
}

int
reptrans_delete_blob(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *chid)
{
	int err = 0;
	uint64_t start = 0, end;

	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl) {
		err = -EPERM;
		goto _exit;
	}

	err = reptrans_refresh_status(dev, ttag, ioTypeDelete);
	if (err)
		return err;

	start = uv_hrtime();
	err = dev->__vtbl->delete_blob(dev, ttag, hash_type, chid);
	if (err < 0) {
		log_debug(lg, "Dev(%s): delete_blob returned err=%d, ignoring",
		    dev->name, err);
		err = 0;
		goto _exit;
	}
	if (ttag == TT_CHUNK_PAYLOAD) {
		end = uv_hrtime();
		uint64_t latency = (end - start) / 1000;
		dev->stats.delete_latency = avg_ring_update(
		    &dev->delete_avg_samples, latency);
	}
_exit:
	if (BLOB_REPTRANS_DELETE_BLOB_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_DELETE_BLOB(dev->name, ttag, hash_type, chidstr,
			err, uv_hrtime() - start);
	}
	return err;
}

int
reptrans_delete_blob_value(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid, uv_buf_t *val,
	size_t len) {
	int err = 0;
	uint64_t start = 0, end;

	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl) {
		err = -EPERM;
		goto _exit;
	}

	err = reptrans_refresh_status(dev, ttag, ioTypeDelete);
	if (err)
		return err;

	start = uv_hrtime();
	err = dev->__vtbl->delete_blob_value(dev, ttag, hash_type, chid, val, len);
	if (err < 0) {
		log_debug(lg, "Dev(%s): delete_blob_value returned err=%d, ignoring",
		    dev->name, err);
		err = 0;
		goto _exit;
	}
	if (ttag == TT_CHUNK_PAYLOAD) {
		end = uv_hrtime();
		uint64_t latency = (end - start) / 1000;
		dev->stats.delete_latency = avg_ring_update(
		    &dev->delete_avg_samples, latency);
	}
_exit:
	if (BLOB_REPTRANS_DELETE_BLOB_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_DELETE_BLOB(dev->name, ttag, hash_type, chidstr,
			err, uv_hrtime() - start);
	}
	return err;
}

int
reptrans_list_blob_chids(struct repdev *dev, type_tag_t ttag,
    uint64_t ng, uint64_t mask, int max, uint512_t *chids)
{
	nassert(dev->loop_thrid != uv_thread_self());
	if (!dev->__vtbl)
		return -EPERM;
	int err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;
	return dev->__vtbl->list_blob_chids(dev, ttag, ng, mask, max, chids);
}

int
reptrans_blob_stat(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *key, struct blob_stat *stat)
{
	int rc = -ENOTSUP;
	uint64_t start = uv_hrtime();
	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl) {
		rc = -EPERM;
		goto _exit;
	}

	int err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	if (dev->__vtbl->stat_blob)
		rc = dev->__vtbl->stat_blob(dev, ttag, hash_type, key, stat);

_exit:
	if (BLOB_REPTRANS_BLOB_STAT_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(key, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_BLOB_STAT(dev->name, ttag, hash_type, chidstr,
			stat->size, rc, uv_hrtime() - start);
	}
	return rc;
}

int
reptrans_blob_query(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, const uint512_t *key, uint64_t *outsize)
{
	int rc = -ENOTSUP;
	uint64_t start = uv_hrtime();

	if (!dev->__vtbl) {
		rc = -EPERM;
		goto _exit;
	}

	int err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	if (dev->__vtbl->query_blob)
		rc = dev->__vtbl->query_blob(dev, ttag, hash_type, key, outsize);

_exit:
	if (BLOB_REPTRANS_BLOB_QUERY_ENABLED()) {
		char chidstr[UINT512_BYTES*2+1];
		uint512_dump(key, chidstr, UINT512_BYTES*2+1);
		BLOB_REPTRANS_BLOB_QUERY(dev->name, ttag, hash_type, chidstr,
			rc, uv_hrtime() - start);
	}
	return rc;
}

int
reptrans_iterate_blobs(struct repdev *dev, type_tag_t ttag,
	reptrans_blob_callback callback, void *param, int want_values)
{
	int rc = -ENOTSUP;

	if (!dev->__vtbl)
		return -EPERM;

	int err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	if (dev->__vtbl->iterate_blobs)
		rc = dev->__vtbl->iterate_blobs(dev, ttag, callback, param,
			want_values, 0, -1);
	return rc;
}

int
reptrans_iterate_blobs_strict_order(struct repdev *dev, type_tag_t ttag,
	reptrans_blob_callback callback, void *param, int want_values)
{
	int rc = -ENOTSUP;

	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl)
		return -EPERM;

	int err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	if (dev->__vtbl->iterate_blobs)
		rc = dev->__vtbl->iterate_blobs(dev, ttag, callback, param,
			want_values, 1, -1);
	return rc;
}

int
reptrans_iterate_blobs_strict_order_limited(struct repdev *dev, type_tag_t ttag,
	reptrans_blob_callback callback, void *param, int want_values, int max_blobs)
{
	int rc = -ENOTSUP;

	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl)
		return -EPERM;

	int err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;

	if (dev->__vtbl->iterate_blobs)
		rc = dev->__vtbl->iterate_blobs(dev, ttag, callback, param,
			want_values, 1, max_blobs);
	return rc;
}

static void
reptrans_suspend_timestamp(struct reptrans* rt) {
	if (rt->ts_suspended)
		return;
	uv_mutex_lock(&rt->ts_mutex);
	rt->ts_offset = uv_hrtime()/1000L - rt->ts_offset;
	rt->ts_suspended = 1;
	uv_mutex_unlock(&rt->ts_mutex);
}

static void
reptrans_resume_timestamp(struct reptrans* rt) {
	if (!rt->ts_suspended)
		return;
	uv_mutex_lock(&rt->ts_mutex);
	rt->ts_offset = uv_hrtime()/1000L - rt->ts_offset;
	rt->ts_suspended = 0;
	uv_mutex_unlock(&rt->ts_mutex);
}

static uint64_t
hrtime_internal(struct reptrans* rt)
{
	uint64_t rc = 0;
	uv_mutex_lock(&rt->ts_mutex);
	if (rt->ts_suspended)
		rc = rt->ts_offset;
	else
		rc = uv_hrtime()/1000L - rt->ts_offset;
	uv_mutex_unlock(&rt->ts_mutex);
	return rc;
}

uint64_t
reptrans_get_timestamp(struct repdev *dev)
{
	if (dev->rt->ts_offset == ~0UL)
		return 0;
	else
		return hrtime_internal(dev->rt) + dev->timestamp;
}

int
reptrans_delete_manifest(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, const uint512_t *chid)
{
	assert(ttag == TT_VERSION_MANIFEST || ttag == TT_CHUNK_MANIFEST);
	assert(hash_type == HASH_TYPE_DEFAULT);
	struct blob_stat bstat =  { .size = 0 };
	uint32_t vm_packed_length = 0;
	struct vmmetadata md;
	rtbuf_t *rb = NULL;
	int err;

	if (ttag == TT_VERSION_MANIFEST) {
		/*
		 * A VM may contain a corresponding version entry.
		 * Remove it first to avoid orphans
		 */
		err = reptrans_get_blob(dev, ttag, hash_type, chid, &rb);
		if (!err && rb) {
			err = replicast_get_metadata(rb, &md);
			vm_packed_length = rtbuf_len(rb);
		} else
			return err;
		if (vm_packed_length) {
			struct vlentry vle;
			fill_vlentry(&vle, &md, (uint512_t *)chid, vm_packed_length);
			err = reptrans_delete_version_entry(dev,
			    HASH_TYPE_DEFAULT, &md.nhid, &vle);
			if (err && err != -ENOENT) {
				log_error(lg, "Dev(%s) version delete error %d "
					"NHID %lX GEN %lu", dev->name, err,
					md.nhid.u.u.u, md.txid_generation);
			}
		}
	}

	/* Remove the manifest */
	err = reptrans_delete_blob(dev, ttag, hash_type, chid);
	if (!err) {
		/* Remove also parity manifest (if exists) */
		err = reptrans_blob_stat(dev, TT_PARITY_MANIFEST, hash_type,
			chid, &bstat);
		if (!err && bstat.size > 0) {
			err = reptrans_delete_blob(dev, TT_PARITY_MANIFEST,
				hash_type, chid);
		} else
			err = 0;
	}

	if (rb)
		rtbuf_destroy(rb);
	return err;
}

struct repcount_filter_data {
	int count;
	uint512_t nhid;
	uint64_t uvid;
	uint64_t genid;
};

static int
chunk_rep_count_filter(void *arg, void **data, size_t *size, int set)
{
	if (set) {
		return 0;
	}

	assert(arg != NULL);
	int err;
	struct repcount_filter_data *ptr = (struct repcount_filter_data *)arg;

	msgpack_u u;
	msgpack_unpack_init_b(&u, *data, (uint32_t)*size, 0);

	struct backref vbr;
	err = reptrans_unpack_vbr(&u, &vbr);
	if (err)
		return 0;
	/* filter by MAX rep_count */
	if (vbr.rep_count > ptr->count) {
		ptr->count = vbr.rep_count;
		ptr->nhid = vbr.name_hash_id;
		ptr->uvid = vbr.uvid_timestamp;
		ptr->genid = vbr.generation;
	}

	/* by returning 0 here we do not allocate rtbuf for this VBR
	 * and will continue to filter for the next one */
	return 0;
}

int
reptrans_get_chunk_rep_count(struct repdev *dev, crypto_hash_t hash_type,
	uint512_t *chid)
{
	struct repcount_filter_data filter_data = {0};
	int rep_count = 0;
	rtbuf_t *rb = NULL;

	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl)
		return -EPERM;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return -EACCES;

	/*
	 * Read all the VBRs corresponding to this chid and get MAX(rep_count)
	 */
	int err = dev->__vtbl->get_blob(dev, TT_VERIFIED_BACKREF, hash_type,
		GBF_FLAG_ALL, chid, &rb, 0, chunk_rep_count_filter, &filter_data);

	char chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(chid, chidstr, sizeof (chidstr));

	rep_count = filter_data.count;

	if (err == 0) {
		log_debug(lg, "Dev(%s): Got chunk %s rep count %d", dev->name,
		    chidstr, rep_count);
	} else {
		if (err != -ENOENT) {
			rep_count = err;
			log_debug(lg, "Dev(%s): Failed to get chunk %s rep "
			    "count, err %d", dev->name, chidstr, err);
		}
	}

	if (rb)
		rtbuf_destroy(rb);
	return rep_count;
}

int
reptrans_get_chunk_count_limited(struct repdev *dev, crypto_hash_t hash_type,
    type_tag_t ttag, uint512_t *chid, int n_max, size_t *countp)
{
	rtbuf_t *rb = NULL;

	nassert(dev->loop_thrid != uv_thread_self());

	/*
	 * TODO: add support for non-dupsort tags
	 */
	assert(is_dupsort_tt(ttag));

	if (!dev->__vtbl)
		return -EPERM;

	int err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;
	/*
	 * Count all the VBRs corresponding to this chid
	 */
	err = dev->__vtbl->get_blob(dev, ttag, hash_type, GBF_FLAG_DUPCOUNT,
	    chid, &rb, n_max, NULL, countp);

	char chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(chid, chidstr, sizeof (chidstr));

	if (!err) {
		log_debug(lg, "Dev(%s): Got chunk %s count %lu", dev->name,
		    chidstr, *countp);
	} else {
		if (err != -ENOENT) {
			log_debug(lg, "Dev(%s): Failed to get chunk %s  "
			    "count, err %d", dev->name, chidstr, err);
		}
	}

	if (rb)
		rtbuf_destroy(rb);
	return err;
}

int
reptrans_get_chunk_count(struct repdev *dev, crypto_hash_t hash_type,
    type_tag_t ttag, uint512_t *chid, size_t *countp)
{
	return reptrans_get_chunk_count_limited(dev, hash_type, ttag, chid, 0,
		countp);
}

int
reptrans_get_depcount_coarse(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	uint512_t *chid, int n_max, size_t *countp)
{
	rtbuf_t *rb = NULL;

	nassert(dev->loop_thrid != uv_thread_self());
	assert(is_dupsort_tt(ttag));

	if (!dev->__vtbl)
		return -EPERM;

	int err = reptrans_refresh_status(dev, ttag, ioTypeRead);
	if (err)
		return err;
	/*
	 * Count all the VBRs corresponding to this chid
	 */
	err = dev->__vtbl->get_blob(dev, ttag, hash_type, GBF_FLAG_DUPCOUNT_ROUGH,
	    chid, &rb, n_max, NULL, countp);

	char chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(chid, chidstr, sizeof (chidstr));

	if (!err) {
		log_debug(lg, "Dev(%s): Got chunk %s count %lu", dev->name,
		    chidstr, *countp);
	} else {
		if (err != -ENOENT) {
			log_debug(lg, "Dev(%s): Failed to get chunk %s  "
			    "count, err %d", dev->name, chidstr, err);
		}
	}
	if (rb)
		rtbuf_destroy(rb);
	return err;
}


static int
vbr_one_filter_cb(void *arg, void **data, size_t *size, int set) {
	uv_buf_t *buf = arg;

	if (set) {
		*size = buf->len;
		*data = buf->base;
		return 0;
	}

	return 1;
}

int
reptrans_put_backref(struct repdev *dev, const uint512_t *chid,
    crypto_hash_t hash_type, struct backref *br)
{
	int err;
	rtbuf_t *rb = NULL;
	assert(dev != NULL);
	assert(chid != NULL);
	assert(br != NULL);

	msgpack_p *p = msgpack_pack_init();
	if (p == NULL) {
		err = -ENOMEM;
		goto _exit;
	}

	err = reptrans_pack_vbr(p, br);

	if (err)
		goto _exit;

	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);
	rb = rtbuf_init_mapped(&buf, 1);
	if (!rb) {
		err = -ENOMEM;
		goto _exit;
	}

	char chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(chid, chidstr, sizeof (chidstr));

	err = reptrans_put_blob(dev, TT_VERIFIED_BACKREF, hash_type, rb,
	    (uint512_t *)chid, 0);

_exit:
	if (rb)
		rtbuf_destroy(rb);
	if (p)
		msgpack_pack_free(p);
	if (err == 0) {
		log_debug(lg, "Dev(%s): created new verified backref %s",
		    dev->name, chidstr);
	}

	return err;
}

int
reptrans_del_backref(struct repdev *dev, const uint512_t *chid,
    crypto_hash_t hash_type, struct backref *br)
{
	int err;
	rtbuf_t *rb = NULL;
	assert(dev != NULL);
	assert(chid != NULL);
	assert(br != NULL);

	msgpack_p *p = msgpack_pack_init();
	if (p == NULL) {
		err = -ENOMEM;
		goto _exit;
	}

	err = reptrans_pack_vbr(p, br);

	if (err)
		goto _exit;

	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);
	rb = rtbuf_init_mapped(&buf, 1);
	if (!rb) {
		err = -ENOMEM;
		goto _exit;
	}

	char chidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(chid, chidstr, sizeof (chidstr));

	err = reptrans_delete_blob_value(dev, TT_VERIFIED_BACKREF, hash_type,
		chid, rb->bufs, 1);

_exit:
	if (rb)
		rtbuf_destroy(rb);
	if (p)
		msgpack_pack_free(p);
	if (err == 0) {
		log_debug(lg, "Dev(%s): deleted a verified backref for %s",
		    dev->name, chidstr);
	}

	return err;
}
int
reptrans_check_speculative_hold(struct repdev *dev,
    crypto_hash_t hash_type, type_tag_t ttag, const uint512_t *chid)
{
	int err;
	uint64_t ts;

	nassert(dev->loop_thrid != uv_thread_self());

	err = reptrans_get_blob_ts(dev, ttag, hash_type, chid, &ts);
	if (err) {
		if (err != -ENOENT)
			log_error(lg, "Cannot get blob ts: %d", err);
		goto _exit;
	}

	uint64_t current_ts = reptrans_get_timestamp(dev);
	/* So there is an SBR, make sure it hasn't expired yet */
	if (ts + dev->bg_config->speculative_backref_timeout >= current_ts) {
		err = 0;
	} else {
		log_debug(lg, "Speculative hold expired: %ld %ld %ld",
		    ts, dev->bg_config->speculative_backref_timeout,
		    current_ts);
		err = -ENOENT;
	}

_exit:
	if (err == -ENOENT)
		uint512_logdump(lg, "No unexpired holds", chid);
	else
		uint512_logdump(lg, "Failed to get speculative hold", chid);
	return err;
}

int
reptrans_put_version(struct repdev *dev, struct vmmetadata *md,
    uint512_t *vmchid, uint32_t vm_packed_length)
{
	int err = -ENOMEM;
	struct vlentry newver;
	rtbuf_t *rb = NULL;
	fill_vlentry(&newver, md, vmchid, vm_packed_length);

	msgpack_p *p = msgpack_pack_init();
	if (!p)
		goto out;

	err = replicast_pack_vlentry(p, &newver);
	if (err)
		goto out;

	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);
	rb = rtbuf_init_mapped(&buf, 1);
	if (!rb) {
		err = -ENOMEM;
		goto out;
	}
	err = reptrans_put_blob(dev, TT_NAMEINDEX, HASH_TYPE_DEFAULT, rb,
	    &md->nhid, 0);
	if (err)
		goto out;
out:
	if (rb)
		rtbuf_destroy(rb);
	if (p)
		msgpack_pack_free(p);
	return err;
}

static int
reptrans_get_versions_filter(void *arg, void **data, size_t *size, int set)
{
	uv_buf_t *packed_query = arg;

	if (set) {
		*data = packed_query->base;
		*size = packed_query->len;
		return 0;
	}

	struct vlentry *query = (struct vlentry *)((uv_buf_t *)arg + 1)->base;
	struct vlentry vle;
	int err;

	msgpack_u u;
	msgpack_unpack_init_b(&u, *data, (uint32_t)*size, 0);


	uint32_t n;
	err = msgpack_unpack_array(&u, &n);
	if (err)
		return 0;
	if (n != 8)
		return 0;
	err = msgpack_unpack_uint64(&u, &vle.uvid_timestamp);
	if (err)
		return 0;
	err = msgpack_unpack_uint64(&u, &vle.generation);
	if (err)
		return 0;

	/* request for the latest UVID? */
	if (query->uvid_timestamp == ~0ULL) {
		if (query->generation == 0ULL || query->generation == ~0ULL)
			return 1;
		/* with specific generation? */
		if (vle.generation == query->generation)
			return 1;
	} else if (vle.uvid_timestamp == query->uvid_timestamp) {
		return ((query->generation == 0ULL) ||
			(query->generation == ~0ULL) ||
			(vle.generation == query->generation));
	}
	/* skip */
	return 0;
}

int
reptrans_get_versions(struct repdev *dev, const uint512_t *nhid,
    struct vlentry *query, rtbuf_t **out)
{
	int err;
	rtbuf_t *rb = NULL;
	int found = 0;

	*out = NULL;

	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl)
		return -EPERM;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return -EACCES;

	msgpack_p *p = msgpack_pack_init();
	if (!p)
		return -ENOMEM;

	err = replicast_pack_vlentry(p, query);
	if (err) {
		goto _exit;
	}

	uv_buf_t buf[2];

	/* index0 - packed query */
	msgpack_get_buffer(p, &buf[0]);

	/* index1 - query itself */
	buf[1].base = (char *)query;
	buf[1].len = sizeof (*query);

	int flag = (query->uvid_timestamp == ~0ULL &&
		    (query->generation == ~0ULL || query->generation > 0)) ?
		GBF_FLAG_ONE : GBF_FLAG_ALL;
	err = dev->__vtbl->get_blob(dev, TT_NAMEINDEX, HASH_TYPE_DEFAULT,
	    flag, nhid, &rb, 0, reptrans_get_versions_filter, &buf);
	if (err) {
		goto _exit;
	}

	/* this rtbuf will contain unpacked struct vlentry matching query */
	*out = rtbuf_init(NULL, rb->nbufs);
	if (!*out) {
		err = -ENOMEM;
		goto _exit;
	}

	for (size_t i = 0; i < rb->nbufs; i++) {
		struct vlentry vle;
		msgpack_u u;

		msgpack_unpack_init_b(&u, rtbuf(rb, i).base, rtbuf(rb, i).len, 0);

		err = replicast_unpack_vlentry(&u, &vle);
		if (err) {
			log_error(lg, "Cannot decode version entry %d", (int)i);
			err = -EBADF;
			goto _exit;
		}

		uv_buf_t ent = { .base = (char *)&vle, .len = sizeof (vle) };
		err = rtbuf_set_alloc(*out, i, &ent, 1);
		if (err) {
			err = -ENOMEM;
			goto _exit;
		}
	}

_exit:
	if (err && *out) {
		rtbuf_destroy(*out);
		*out = NULL;
	}
	if (rb)
		rtbuf_destroy(rb);
	if (p)
		msgpack_pack_free(p);
	return err;
}

int
reptrans_notify_delete_version(struct repdev *dev, crypto_hash_t hash_type,
	const uint512_t *nhid, void *entry)
{
	struct vlentry *ver = (struct vlentry *)entry;

	char nhidbuf[UINT512_BYTES * 2 + 1];
	uint512_dump(nhid, nhidbuf, UINT512_BYTES * 2 + 1);
	log_debug(lg, "Dev(%s): uvid %ld genid %ld nhid %s", dev->name,
	    ver->uvid_timestamp, ver->generation, nhidbuf);

	assert(hash_type == HASH_TYPE_DEFAULT);
	/*
	 * Schedule top-down deletion of the version
	 */

	struct verification_request req = {
		.vtype = RT_VERIFY_NORMAL | RT_VERIFY_DELETE,
		.chid = ver->content_hash_id,
		.ttag = TT_VERSION_MANIFEST,
		.htype = HASH_TYPE_DEFAULT,
		.nhid = *nhid,
		.uvid_timestamp = 0,
		.generation = ver->generation,
		.vbr = {
			.name_hash_id = *nhid,
			.generation = ver->generation,
			.uvid_timestamp = ver->uvid_timestamp,
			.ref_type = TT_NAMEINDEX,
			.ref_chid = *nhid,
			.ref_hash = HASH_TYPE_DEFAULT,
			.rep_count = 0,
			.attr = VBR_ATTR_VM
		}
	};

	return reptrans_enqueue_batch_request(dev, NULL, &req);
}

int
reptrans_delete_version_entry(struct repdev *dev, crypto_hash_t hash_type,
    const uint512_t *chid, struct vlentry *ver)
{
	nassert(dev->loop_thrid != uv_thread_self());

	if (!dev->__vtbl)
		return -EPERM;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE)
		return -EACCES;

	msgpack_p *p = msgpack_pack_init();
	if (!p)
		return -ENOMEM;

	int err = replicast_pack_vlentry(p, ver);
	if (err) {
		goto _exit;
	}

	uv_buf_t buf[1];
	msgpack_get_buffer(p, &buf[0]);

	err = reptrans_delete_blob_value(dev, TT_NAMEINDEX,
		hash_type, chid, &buf[0], 1);
	if (err != 0)
		uint512_logdump(lg, "Failed to delete version entry", chid);
	else {
		char hidstr[UINT512_BYTES*2+1];
		uint512_dump(chid, hidstr, UINT512_BYTES*2+1);
		log_debug(lg, "Dev(%s) removed nameindex %s gen %lu",
		    dev->name, hidstr, ver->generation);
	}
_exit:
	if (p)
		msgpack_pack_free(p);

	return err;
}

int
reptrans_purge_versions(struct repdev *dev, const uint512_t *nhid,
	uint64_t hi_version, uint64_t low_version, uint64_t version_uvid_timestamp,
	crypto_hash_t hash_type, int trlog_object)
{
	/*
	 * 1. Read all the object versions, add version_uvid_timestamp to query if required
	 *
	 * TODO: this can be optimize - read range low - hi then delete
	 */

	int err = reptrans_refresh_status(dev, TT_NAMEINDEX, ioTypeDelete);
	if (err)
		return err;

	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation = 0ULL
	};
	rtbuf_t *rb_vers = NULL;
	err = reptrans_get_versions(dev, nhid, &query, &rb_vers);
	char nhidbuf[UINT512_BYTES * 2 + 1];
	uint512_dump(nhid, nhidbuf, UINT512_BYTES * 2 + 1);
	log_trace(lg, "dev %s nhid %s hi_version %lu, low_version %lu, "
	    "version_uvid_timestamp %lu, nbufs %d, err %d",
		dev->path, nhidbuf, hi_version, low_version, version_uvid_timestamp,
		rb_vers ? (int)rb_vers->nbufs : 0, err);
	if (err)
		goto _done;

	/*
	 * 2. Notify and delete versions  >= low_version and <= hi_version
	 */
	size_t i;
	for (i = 0; i < rb_vers->nbufs; ++i) {
		struct vlentry *vers = (struct vlentry *)rtbuf(rb_vers, i).base;
		if (vers->generation <= hi_version && vers->generation >= low_version) {
			if (version_uvid_timestamp > 0 && vers->uvid_timestamp != version_uvid_timestamp) {
				continue;
			}

			/* Delete only version entries. The top-down delete will be
			 * applied to a whole tree later by the space reclaim BG
			*/
			err = reptrans_delete_version_entry(dev, hash_type, nhid, vers);
			log_debug(lg, "dev(%s) delete generation %lu err %d"
				" nhid %s", dev->name, vers->generation, err, nhidbuf);
			if (err && err != -ENOENT)
				log_error(lg, "dev(%s) nhid %s delete version failed %d",
					dev->name, nhidbuf, err);
		}
	}

_done:
	if (rb_vers)
		rtbuf_destroy(rb_vers);

	return err;
}

int
reptrans_delete_index(struct repdev *dev, crypto_hash_t hash_type,
	uint512_t *key)
{
	/*
	 * 1. Read all the object's versions
	 */
	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation = 0
	};
	rtbuf_t *rb_vers = NULL;
	int err = reptrans_get_versions(dev, key, &query, &rb_vers);
	if (err) {
		if (err == -ENOENT)
			goto _delete;
		return err;
	}

	/*
	 * 2. Notify about the delete to take verification actions
	 */
	for (size_t i = 0; !err && i < rb_vers->nbufs; ++i) {
		err = reptrans_notify_delete_version(dev, hash_type,
			key, rtbuf(rb_vers, i).base);
		if (err) {
			log_warn(lg, "Dev(%s): unable to notify peers with "
			    "index delete event", dev->name);
			continue;
		}
	}

_delete:
	/*
	 * 3. Delete nameindex entry
	 */
	err = reptrans_delete_blob(dev, TT_NAMEINDEX, HASH_TYPE_DEFAULT, key);
	if (err) {
		log_error(lg, "Dev(%s): unable to delete index entry (%d) %s",
			dev->name, err, strerror(-err));
	}

	if (rb_vers)
		rtbuf_destroy(rb_vers);
	return err;
}

int
reptrans_number_of_versions(struct repdev *dev, crypto_hash_t hash_type, uint512_t *key)
{
	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation = 0
	};
	rtbuf_t *rb_vers = NULL;
	int err = reptrans_get_versions(dev, key, &query, &rb_vers);
	if (err) {
		if (rb_vers)
			rtbuf_destroy(rb_vers);
		return err;
	}

	int res = rb_vers->nbufs;
	rtbuf_destroy(rb_vers);

	return res;
}

static int
reptrans_has_version_filter(void *arg, void **data, size_t *size, int set) {
	uint64_t* gen = arg;
	struct vlentry vle;
	int err;
	msgpack_u u;

	if (set) {
		*data = NULL;
		*size = 0;
		return 0;
	}
	msgpack_unpack_init_b(&u, *data, (uint32_t)*size, 0);

	uint32_t n;
	err = msgpack_unpack_array(&u, &n);
	if (err)
		return 0;
	if (n != 8)
		return 0;
	err = msgpack_unpack_uint64(&u, &vle.uvid_timestamp);
	if (err)
		return 0;
	err = msgpack_unpack_uint64(&u, &vle.generation);
	if (err)
		return 0;
	return vle.generation == *gen;
}

int
reptrans_has_version(struct repdev *dev, crypto_hash_t hash_type,
	uint512_t *nhid, uint64_t generation)
{
	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation = generation
	};
	rtbuf_t *rb_ver = NULL;
	int err = reptrans_get_blobs(dev, TT_NAMEINDEX, HASH_TYPE_DEFAULT,
		nhid, &rb_ver, GBF_FLAG_ONE, reptrans_has_version_filter,
		&generation);
	if (err)
		return err;

	int res = rb_ver->nbufs;
	rtbuf_destroy(rb_ver);
	return res;
}

int
reptrans_delete_version(struct repdev *dev, struct vmmetadata *md,
    uint512_t *vmchid, uint32_t vm_packed_length)
{
	struct vlentry ver;
	fill_vlentry(&ver, md, vmchid, vm_packed_length);
	int err = reptrans_delete_version_entry(dev, HASH_TYPE_DEFAULT,
		&md->nhid, &ver);
	return err;
}

int
trlog_skip(struct repdev *dev, struct vmmetadata *md)
{
	// Skip NFS aux structures
	if (md->inline_data_flags & RT_INLINE_DATA_TYPE_NFS_AUX) {
		return 1;
	}

	/* do not write transaction log for log objects */
	if (md->tid_size >= strlen(TRLOG_TID_PREFIX) &&
	    strncmp(md->tid, TRLOG_TID_PREFIX, strlen(TRLOG_TID_PREFIX)) == 0)
		return 1;

	/* do not write transaction log for svcs objects */
	if (md->tid_size == strlen(RT_SYSVAL_TENANT_SVCS) + 1 &&
	    strcmp(md->tid, RT_SYSVAL_TENANT_SVCS) == 0)
		return 1;

	/* do not write transaction log for admin objects */
	if (md->tid_size == strlen(RT_SYSVAL_TENANT_ADMIN) + 1 &&
	    strcmp(md->tid, RT_SYSVAL_TENANT_ADMIN) == 0)
		return 1;

	/* skip self vdevid */
	char bid[UINT128_STR_BYTES];
	uint128_dump(&dev->vdevid, bid, UINT128_STR_BYTES);
	if (md->bid_size >= strlen(bid) && strcmp(md->bid, bid) == 0)
		return 1;

	/* skip system object updates */
	if (uint512_cmp(&md->phid, &uint512_null) == 0)
		return 1;

	/* skip bucket MD object updates */
	uint512_t oid_v;
	uint512_fromhex(md->oid, (UINT512_BYTES * 2 + 1), &oid_v);
	if (uint512_cmp(&md->phid, &oid_v) == 0) {
		return 1;
	}

	return 0;
}

static int
trlog_put_blob(struct repdev *dev, struct trlog_data *data)
{
	rtbuf_t *rb = NULL;
	int err;

	msgpack_p *p = msgpack_pack_init();
	if (!p) {
		log_error(lg, "Dev(%s): msgpack init failed", dev->name);
		return -ENOMEM;
	}

	err = trlog_pack(p, data);
	if (err) {
		log_error(lg, "Dev(%s): msgpack failed", dev->name);
		goto _out;
	}

	uv_buf_t buf;
	msgpack_get_buffer(p, &buf);
	rb = rtbuf_init_mapped(&buf, 1);
	if (!rb) {
		log_error(lg, "Dev(%s): rtbuf init failed", dev->name);
		goto _out;
	}

	/*
	 * Insertion of timestamp key into TRLOG journal has to be
	 * atomic with second-range interval.
	 */

	uint512_t key = uint512_null;
	key.u.u.u = data->vmchid.u.u.u;
_reinsert:
	key.u.u.l = COORDINATED_TS();

	uint64_t ts = get_timestamp_us();

	err = reptrans_put_blob(dev, TT_TRANSACTION_LOG, HASH_TYPE_DEFAULT,
		rb, &key, 0);
	if (err) {
		log_error(lg, "Dev(%s): reptrans_put_blob failed", dev->name);
		goto _out;
	}

	uint64_t ts2 = get_timestamp_us();
	if (ts2 - ts > 750000UL && !dev->terminating) {
		log_warn(lg, "TRLOG put took %ld us", ts2 - ts);
		err = reptrans_delete_blob(dev, TT_TRANSACTION_LOG,
		    HASH_TYPE_DEFAULT, &key);
		if (err && err != -ENOENT) {
			log_error(lg, "Dev(%s): reptrans_delete_blob failed",
			    dev->name);
			goto _out;
		}
		goto _reinsert;
	}

_out:
	if (rb)
		rtbuf_destroy(rb);
	if (p)
		msgpack_pack_free(p);

	return err;
}

int
reptrans_put_trlog(struct repdev *dev, struct vmmetadata *md,
    uint512_t *vmchid, uint64_t attributes, char *etag, char*content_type,
	uint64_t multipart_size, char *owner, char *srcip)
{
	struct trlog_data trdata, *data = &trdata;
	struct server_stat *stat = server_get();
	char vmchid_str[UINT512_STR_BYTES];

	if (trlog_skip(dev, md))
		return 0;

	int is_sop = attributes & RD_ATTR_TRLOG_SOP;
	int is_replace = attributes & RD_ATTR_OBJECT_REPLACE;
	int is_replace_insert = (int)((attributes & RD_ATTR_OBJECT_REPLACE_INSERT) >> 32);
	uint64_t is_isgw = attributes & RD_ATTR_ISGW_TRLOG;

	uint128_t rbuf;
	memcpy(&data->serverid, reptrans_guid2sid(&md->uvid_src_guid, &rbuf), sizeof(uint128_t));
	memcpy(&data->vdevid, &dev->vdevid, sizeof(uint128_t));
	memcpy(&data->nhid, &md->nhid, sizeof(uint512_t));
	memcpy(&data->phid, &md->phid, sizeof(uint512_t));
	memcpy(&data->vmchid, vmchid, sizeof(uint512_t));
	data->timestamp = md->uvid_timestamp;
	data->generation = md->txid_generation;
	data->deltasize = 0;
	data->cid = md->cid;
	data->tid = md->tid;
	data->bid = md->bid;
	data->oid = md->oid;
	data->size = md->logical_size;
	data->multipart_size = multipart_size;
	data->etag = NULL;
	data->content_type = content_type;
	data->owner = owner;
	data->srcip = srcip;
	if (etag) {
		uint512_dump(vmchid, vmchid_str, UINT512_STR_BYTES);
		if (strcmp(etag, vmchid_str)) {
		    data->etag = etag;
		}
	}
	data->object_deleted = md->object_deleted;

	if (((md->creation_time == md->uvid_timestamp && !is_replace) || is_replace_insert) && !md->object_deleted) {
		data->trtype = TRLOG_OBJ_CREATE;
		data->deltasize = md->logical_size;
	} else if (md->object_deleted == RT_DELETED_EXPUNGED_VERSION) {
		data->trtype = TRLOG_VERSION_EXPUNGE;
		data->deltasize = 0;
	} else if (md->object_deleted == RT_DELETED_EXPUNGED) {
		data->trtype = TRLOG_EXPUNGE;
		data->deltasize = -md->logical_size;
	} else if (md->object_deleted == RT_DELETED_VERSION) {
		data->trtype = TRLOG_OBJ_UPDATE;
		data->deltasize = -md->logical_size;
	} else if (md->object_deleted) {
		data->trtype = TRLOG_OBJ_DELETE;
		data->deltasize = -md->logical_size;
	} else {
		data->trtype = TRLOG_OBJ_UPDATE;
		data->deltasize = md->logical_size;
		data->deltasize -= md->prev_logical_size;
	}

	if (!(md->inline_data_flags & (RT_INLINE_DATA_TYPE_SNAPVIEW|RT_INLINE_DATA_TYPE_USER_KV)) &&
	     memcmp(md->chunkmap_type, RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX,
		    sizeof (RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX)) == 0) {
		if (md->creation_time == md->uvid_timestamp)
			data->trtype = TRLOG_DIR_CREATE;
		else if (md->object_deleted) {
			data->trtype = TRLOG_DIR_DELETE;
		} else {
			data->trtype = TRLOG_DIR_UPDATE;
		}
	}
	if (is_sop) {
		data->trtype |= TRLOG_SKIP_BTN_UPDATE;
	}
	if (is_isgw) {
		data->trtype |= TRLOG_ISGW_UPDATE;
	}

	if (unlikely(LOG_LEVEL_DEBUG >= lg->level)) {
		uint512_dump(vmchid, vmchid_str, UINT512_STR_BYTES);
		log_debug(lg, "Dev(%s): Writing trlog trtype=%d for %s/%s/%s/%s, generation: %lu, timestamp: %lu, chid %s\n",
		    dev->name, data->trtype, md->cid, md->tid, md->bid, md->oid,
			data->generation, data->timestamp, vmchid_str);
	}

	int err = trlog_put_blob(dev, data);

	return err;
}

uint64_t
reptrans_normalized_latency(uint64_t delta, size_t size, size_t factor)
{
	uint64_t num = (size/factor);
	if (size % factor)
		num++;
	return delta / num;
}

static void
reptrans_notify_membership_change__async(struct repdev_call *c)
{
	struct repdev *dev = (struct repdev *)c->args[0];
	int join = (long)c->args[1];
	char *mcgrp = (char *)c->args[2];
	uint32_t if_index = (unsigned long)c->args[3];

	if (join) {
		replicast_join(dev->robj, mcgrp, if_index);
	} else {
		replicast_leave(dev->robj, mcgrp, if_index);
	}
	je_free(mcgrp);
}

int reptrans_notify_membership_change(struct repdev *dev, int join,
	const char *mcgrp, uint32_t if_index)
{
	struct repdev_call	*call =
		je_calloc(1, sizeof(struct repdev_call));
	if (call == NULL) {
		return -ENOMEM;
	}
	call->method = reptrans_notify_membership_change__async;
	call->args[0] = dev;
	call->args[1] = (void *)(long)join;
	call->args[2] = (void *)je_strdup(mcgrp);
	call->args[3] = (void *)(long)if_index;
	QUEUE_INIT(&call->item);
	uv_mutex_lock(&dev->call_mutex);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	uv_mutex_unlock(&dev->call_mutex);
	return 0;
}

void
reptrans_dev_change_membership(volatile struct flexhash *fhtable, struct repdev *dev,
				int join)
{
	fhrow_t row;
	/** @warning Potential stack overflow */
	char joined_mcgrps[fhtable->numrows * 12 + 1];
	unsigned joined_mcgrps_idx = 0;
	*joined_mcgrps = 0;
	char vdevstr[64];
	uint128_dump(&dev->vdevid, vdevstr, 64);

	for (row = 0; row < fhtable->numrows; row++) {
		struct sockaddr_in6 addr;
		flexhash_get_rowaddr(SERVER_FLEXHASH, row, &addr);
		char dst[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr.sin6_addr, dst, INET6_ADDRSTRLEN);
		int j =  row / (fhtable->numrows >> (ccow_daemon->if_indexes_count - 1));
		int nfound = flexhash_exists(fhtable, row, &dev->vdevid);
		if (nfound) {
			if (dev->joined_rows[row] == 0) {
				int err = reptrans_notify_membership_change(
				    dev, join, dst, ccow_daemon->if_indexes[j]);
				if (err) {
					log_error(lg, "Error during membership"
					    "change dev: %s row: %d",
					    dev->name, row);
				}
				joined_mcgrps_idx += snprintf(joined_mcgrps + joined_mcgrps_idx,
						sizeof(joined_mcgrps) - joined_mcgrps_idx,
						"%s%d.%d",
				    (row == 0 ? "" : ","), row, ccow_daemon->if_indexes[j]);
				log_info(lg, "Joining vdev: %s row: %d", vdevstr, row);
				dev->joined_rows[row] = 1;
			} else {
				log_debug(lg, "Already joined vdev: %s row: %d",
				    vdevstr, row);
			}
		} else {
			if (dev->joined_rows[row]) {
				log_warn(lg, "Unable to find vdev: %s at row: %d."
				    "Leaving.", vdevstr, row);
				replicast_leave(dev->robj, dst,
				    ccow_daemon->if_indexes[j]);
			}

			dev->joined_rows[row] = 0;
		}
	}

	/* Send messages */
	uv_async_send(&dev->call_async);
	log_debug(lg, "Replicast object %s scheduled to join groups [%s]",
	    dev->robj->name, joined_mcgrps);
}

static void
reptrans_bg_restart__exec(void* arg) {
	struct repdev* dev = arg;

	if (dev->terminating)
		return;
	int err = bg_job_restart(dev->bg_sched, BG_SPACE_RECLAIM);
	if (!err)
		err = bg_job_restart(dev->bg_sched, BG_SCRUB);
}

static void
reptrans_bg_restart__done(void* arg, int status) {
}

int
reptrans_foreach_vdev(foreach_vdev_cb_t cb, void* arg) {
	QUEUE *q;
	struct reptrans *rt;
	int err = 0;
	size_t i = 0;

	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);
			err = cb(dev, arg);
			uv_rwlock_rdlock(&rt->devlock);
			if (err)
				break;
		}
		uv_rwlock_rdunlock(&rt->devlock);
		if (err)
			break;
	}
	return err;
}

struct flexhash_rebuild_done_arg {
	volatile struct flexhash *fhtable;
	int join;
};

static int
reptrans_on_flexhash_rebuild_done_cb(struct repdev* dev, void* arg) {
	struct flexhash_rebuild_done_arg* e = arg;
	reptrans_dev_change_membership(e->fhtable, dev, e->join);
	repdev_status_t vdev_status = reptrans_dev_get_status(dev);
	if (vdev_status != REPDEV_STATUS_ALIVE)
		dev->status_changed = 1;
	rowevac_try_resume(dev);
	return 0;
}


void
reptrans_on_flexhash_rebuild_done(volatile struct flexhash *fhtable, int join)
{
	struct flexhash_rebuild_done_arg arg = {.fhtable = fhtable, .join = join };
	reptrans_foreach_vdev(reptrans_on_flexhash_rebuild_done_cb, &arg);
}

void
reptrans_bgjobs_restart() {
	QUEUE *q;
	struct reptrans *rt;
	int err;
	size_t i = 0;

	QUEUE_FOREACH(q, &all_rts) {
		QUEUE *d;
		rt = QUEUE_DATA(q, struct reptrans, item);
		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);
				ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_LOW,
					reptrans_bg_restart__exec,
					reptrans_bg_restart__done, dev);
			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}
}

int
reptrans_enqueue_vm_encoding(struct repdev* dev, const uint512_t* vmchid,
	const struct vmmetadata* md) {
	/* Check and enqueue VM for EC */
	int n = 0, m = 0, cid = 0;
	int err = 0;
	FROM_CODECFMT(md->ec_data_mode, n, m);
	cid = GET_CODECID(md->ec_data_mode);
	if (strcmp(md->chunkmap_type,
		RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX) &&
		md->ec_enabled) {
		int trg_policy = GET_TRG_POLICY_TYPE(md->ec_trg_policy);
		uint64_t policy_val = GET_TRG_POLICY_VALUE(md->ec_trg_policy);
		/* In ver. 2.0 handle only timeout policy */
		if (trg_policy == EC_TRG_POLICY_TIMEOUT) {
			struct verification_request v = {
				.vtype = RT_VERIFY_PARITY | RT_VERIFY_NORMAL,
				.chid = *vmchid,
				.ttag = TT_VERSION_MANIFEST,
				.htype = HASH_TYPE_DEFAULT,
				.nhid = md->nhid,
				.uvid_timestamp = reptrans_get_timestamp(dev)/1000000 + policy_val,
				.generation = md->txid_generation,
				.width = n,
				.n_parity = m,
				.domain = md->failure_domain,
				.algorithm = cid,
				.vbr = {
					.generation = md->txid_generation,
					.uvid_timestamp = md->uvid_timestamp,
					.name_hash_id = md->nhid,
					.ref_type = TT_NAMEINDEX,
					.ref_chid = md->nhid,
					.ref_hash = HASH_TYPE_DEFAULT,
					.rep_count = md->replication_count,
					.attr = VBR_ATTR_VM
				}
			};
			err = reptrans_request_encoding(dev, &v);
			if (err) {
				log_error(lg, "Error requesting object encoding");
			} else {
				char chidstr[UINT512_BYTES*2+1];
				uint512_dump(vmchid, chidstr, UINT512_BYTES*2+1);
				log_debug(lg, "Dev(%s) VM %s encoding enqueued",
					dev->name, chidstr);
			}
		}
	}
	return err;
}

static void
bg_init_jobs(struct repdev* dev)
{
	struct bg_job_entry* job = je_calloc(1, sizeof(struct bg_job_entry));
	/* Verification job */
	srand(get_timestamp_us());

	job->start = dev->bg_config->backref_verify_start_ms +
		(rand() % dev->bg_config->backref_verify_start_ms);
	job->interval = dev->bg_config->backref_verify_timer_ms +
		(rand() % dev->bg_config->backref_verify_timer_ms);
	/* Verification */
	job->init = bg_verify_init;
	job->work = bg_verify_work;
	job->work_done = bg_verify_done;
	job->priority = dev->bg_config->verify_priority;
	job->exclusive = dev->bg_config->verify_exlusive;
	verify_state_t* vs = je_calloc(1, sizeof(verify_state_t));
	if (!vs) {
		log_error(lg, "Memory allocation error");
		je_free(job);
		return;
	}
	job->state = vs;
	bg_sched_register_job(dev->bg_sched, job, BG_VERIFICATION);

	/* Incoming Batch Queue */
	job = je_calloc(1, sizeof(struct bg_job_entry));
	job->init = bg_incoming_batch_init;
	job->work = bg_incoming_batch_work;
	job->work_done = bg_incoming_batch_done;
	job->priority = dev->bg_config->incoming_batch_priority;
	job->exclusive = dev->bg_config->incoming_batch_exclusive;
	job->start = dev->bg_config->incoming_batch_start_ms +
		(rand() % dev->bg_config->incoming_batch_start_ms);
	job->interval = dev->bg_config->incoming_batch_timer_ms +
		(rand() % dev->bg_config->incoming_batch_timer_ms);
	ibatch_state_t* ibs = je_calloc(1, sizeof(ibatch_state_t));
	if (!ibs) {
		log_error(lg, "Memory allocation error");
		je_free(job);
		return;
	}
	job->state = ibs;
	bg_sched_register_job(dev->bg_sched, job, BG_INCOMING_BATCH);

	/* Replication */
	job = je_calloc(1, sizeof(struct bg_job_entry));
	job->start = dev->bg_config->replication_start_ms +
		(rand() % dev->bg_config->replication_start_ms);
	job->interval = dev->bg_config->replication_timer_ms +
		(rand() % dev->bg_config->replication_timer_ms);
	job->init = bg_replication_init;
	job->work = bg_replication_work;
	job->work_done = bg_replication_done;
	job->priority = dev->bg_config->replication_priority;
	job->exclusive = dev->bg_config->replication_exclusive;
	bg_sched_register_job(dev->bg_sched, job, BG_REPLICATION);

	/* Space Reclaim */
	job = je_calloc(1, sizeof(struct bg_job_entry));
	job->start = dev->bg_config->space_reclaim_start_ms +
		(rand() % dev->bg_config->space_reclaim_start_ms);
	job->interval = dev->bg_config->space_reclaim_timer_ms +
		(rand() % dev->bg_config->space_reclaim_timer_ms);
	job->init = bg_space_reclaim_init;
	job->work = bg_space_reclaim_work;
	job->work_done = bg_space_reclaim_done;
	job->progress = bg_space_reclaim_progress;
	job->priority = dev->bg_config->space_reclaim_priority;
	job->exclusive = dev->bg_config->space_reclaim_exclusive;
	bg_sched_register_job(dev->bg_sched, job, BG_SPACE_RECLAIM);

	/* garbage collector */
	job = je_calloc(1, sizeof(struct bg_job_entry));
	job->start = dev->bg_config->gc_start_ms +
		(rand() % dev->bg_config->gc_start_ms);
	job->interval = dev->bg_config->gc_timer_ms +
		(rand() % dev->bg_config->gc_timer_ms);
	job->init = bg_gc_init;
	job->work = bg_gc_work;
	job->work_done = bg_gc_done;
	job->progress = bg_gc_progress;
	job->priority = dev->bg_config->gc_priority;
	job->exclusive = dev->bg_config->gc_exclusive;
	bg_sched_register_job(dev->bg_sched, job, BG_GARBAGE_COLLECTOR);

	/* scrubber */
	job = je_calloc(1, sizeof(struct bg_job_entry));
	job->start = dev->bg_config->scrub_start_ms;
	job->interval = dev->bg_config->scrub_start_ms;
	job->init = bg_scrub_init;
	job->progress = bg_scrub_progress;
	job->work = bg_scrub_work;
	job->work_done = bg_scrub_done;
	job->priority = dev->bg_config->scrub_priority;
	job->exclusive = dev->bg_config->scrub_exclusive;
	bg_sched_register_job(dev->bg_sched, job, BG_SCRUB);

	/* EC encoder */
	job = je_calloc(1, sizeof(struct bg_job_entry));
	job->start = dev->bg_config->ec_encoder_start_ms;
	job->interval = dev->bg_config->ec_encoder_timer_ms;
	job->priority = dev->bg_config->ec_encoder_priority;
	job->exclusive = dev->bg_config->ec_encoder_exclusive;
	ec_fill_encoder_bg_calls(job);
	bg_sched_register_job(dev->bg_sched, job, BG_EC_ENCODER);

	/* Transaction logger */
	job = je_calloc(1, sizeof(struct bg_job_entry));
	assert(job != NULL);
	job->init = bg_trlog_init;
	job->work = bg_trlog_work;
	job->work_done = bg_trlog_done;
	job->start = dev->bg_config->trlog_start_ms;
	job->interval = ccow_daemon->trlog_interval_us / 1000UL;
	job->exclusive = dev->bg_config->trlog_exclusive;
	job->priority = BG_PRIO_RT;
	bg_sched_register_job(dev->bg_sched, job, BG_TRANSACTION_LOGGER);

	/* GW cache device */
	job = je_calloc(1, sizeof(struct bg_job_entry));
	assert(job != NULL);
	job->init = bg_gw_cache_init;
	job->work = bg_gw_cache_work;
	job->work_done = bg_gw_cache_done;
	job->start = dev->bg_config->gw_cache_start_ms;
	job->interval = dev->bg_config->gw_cache_timer_ms;
	job->exclusive = dev->bg_config->gw_cache_exclusive;
	job->priority = BG_PRIO_RT;
	bg_sched_register_job(dev->bg_sched, job, BG_GW_CACHE);

	/* rowusage change in the background */
	job = je_calloc(1, sizeof(struct bg_job_entry));
	assert(job != NULL);
	job->init = bg_rowevac_init;
	job->work = bg_rowevac_work;
	job->work_done = bg_rowevac_done;
	job->start = dev->bg_config->rowusage_start_ms;
	job->interval = dev->bg_config->rowusage_timer_ms;
	job->exclusive = dev->bg_config->rowusage_exclusive;
	job->priority = BG_PRIO_RT;
	bg_sched_register_job(dev->bg_sched, job, BG_ROWUSAGE);
}

int
reptrans_parse_bg_jobs_config(const json_value* obj, struct repdev_bg_config* cfg, size_t* n_opts) {

	if (obj->type != json_object)
		return -EPERM;

	*n_opts = 0;

	for (size_t j = 0; j < obj->u.object.length; j++) {
		char *namekey = obj->u.object.values[j].name;
		json_value *v = obj->u.object.values[j].value;

		if (strncmp(namekey, "backref_verify_timer", 20) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: backref verify "
						"timer is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->backref_verify_timer_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "backref_verify_start", 20) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: backref verify "
						"start is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->backref_verify_start_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "backref_verify_priority", 23) == 0) {
			if (v->type != json_integer || v->u.integer <= 0 ||
				v->u.integer > BG_TOTAL - 1) {
				log_error(lg, "Syntax error: verify priority "
						" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->verify_priority = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "backref_verify_exclusive", 24) == 0) {
			if (v->type != json_boolean) {
				log_error(lg, "Syntax error: verify exclusive "
						" has to be true or false");
				return -EINVAL;
			}
			cfg->verify_exlusive = v->u.boolean;
			(*n_opts)++;
		} else if (strncmp(namekey, "incoming_batch_timer", 20) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: backref verify "
						"timer is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->incoming_batch_timer_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "incoming_batch_start", 20) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: backref verify "
						"start is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->incoming_batch_start_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "incoming_batch_priority", 23) == 0) {
			if (v->type != json_integer || v->u.integer <= 0 ||
				v->u.integer > BG_TOTAL - 1) {
				log_error(lg, "Syntax error: incoming batch priority "
						" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->incoming_batch_priority = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "incoming_batch_exclusive", 24) == 0) {
			if (v->type != json_boolean) {
				log_error(lg, "Syntax error: incoming batch exclusive "
						" has to be true or false");
				return -EINVAL;
			}
			cfg->incoming_batch_exclusive = v->u.boolean;
			(*n_opts)++;
		} else if (strncmp(namekey, "space_reclaim_timer", 19) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: space reclaim "
						"timer is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->space_reclaim_timer_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "space_reclaim_start", 19) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: space reclaim timer "
						"start is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->space_reclaim_start_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "space_reclaim_priority", 22) == 0) {
			if (v->type != json_integer || v->u.integer <= 0 ||
				v->u.integer > BG_TOTAL - 1) {
				log_error(lg, "Syntax error: space reclaim priority"
						" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->space_reclaim_priority = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "space_reclaim_exclusive", 23) == 0) {
			if (v->type != json_boolean) {
				log_error(lg, "Syntax error: space reclaim exclusive "
						" has to be true or false");
				return -EINVAL;
			}
			cfg->space_reclaim_exclusive = v->u.boolean;
			(*n_opts)++;
		} else if (strncmp(namekey, "replication_timer", 17) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: replication "
						"timer is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->replication_timer_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "replication_start", 17) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: replication timer "
						"start is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->replication_start_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "replication_priority", 20) == 0) {
			if (v->type != json_integer || v->u.integer <= 0 ||
				v->u.integer > BG_TOTAL - 1) {
				log_error(lg, "Syntax error: replication priority"
						" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->replication_priority = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "replication_exclusive", 21) == 0) {
			if (v->type != json_boolean) {
				log_error(lg, "Syntax error: space reclaim exclusive "
						" has to be true or false");
				return -EINVAL;
			}
			cfg->replication_exclusive = v->u.boolean;
			(*n_opts)++;
		} else if (strncmp(namekey, "gc_timer", 8) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: garbage collector "
						"timer is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->gc_timer_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "tenant_pool_sz", 14) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: tenant contexts is not "
					      "an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tenant_pool_sz = v->u.integer > REPDEV_MAX_POOL_SZ ?
					      REPDEV_MAX_POOL_SZ : v->u.integer;
			if (v->u.integer > REPDEV_MAX_POOL_SZ)
				log_notice(lg, "tenant pool size exceeds maximum "
						"size %u. Setting it to max value",
						REPDEV_MAX_POOL_SZ);
			(*n_opts)++;
		} else if (strncmp(namekey, "gc_start", 8) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: garbage collector timer "
						"start is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->gc_start_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "gc_priority", 11) == 0) {
			if (v->type != json_integer || v->u.integer <= 0 ||
				v->u.integer > BG_TOTAL - 1) {
				log_error(lg, "Syntax error: garbage collector priority"
						" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->gc_priority = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "gc_exclusive", 12) == 0) {
			if (v->type != json_boolean) {
				log_error(lg, "Syntax error: garbage collector exclusive"
						" has to be true or false");
				return -EINVAL;
			}
			cfg->gc_exclusive = v->u.boolean;
			(*n_opts)++;
		} else if (strncmp(namekey, "scrub_timer", 8) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: scrub "
						"timer is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->scrub_timer_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey,"scrub_start", 8) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: scrubber timer "
						"start is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->scrub_start_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "scrub_priority", 11) == 0) {
			if (v->type != json_integer || v->u.integer <= 0 ||
				v->u.integer > BG_TOTAL - 1) {
				log_error(lg, "Syntax error: scrubber priority"
						" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->scrub_priority = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "scrub_exclusive", 12) == 0) {
			if (v->type != json_boolean) {
				log_error(lg, "Syntax error: scrubber exclusive"
						" has to be true or false");
				return -EINVAL;
			}
			cfg->scrub_exclusive = v->u.boolean;
			(*n_opts)++;
		} else if (strncmp(namekey, "scrubber_log_name", 17) == 0) {
			if (v->type != json_string || v->u.string.length == 0
				|| strlen(v->u.string.ptr) >= 63) {
				log_error(lg, "Syntax error: the scrubber log file name "
						"has to be a string of non-zero length, but less than 63 symbols");
				return -EINVAL;
			}
			strcpy(cfg->scrubber_log_name, v->u.string.ptr);
		} else if (strncmp(namekey, "ec_encoder_timer", 16) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: EC encoder "
					"timer is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->ec_encoder_timer_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey,"ec_encoder_start", 16) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: EC encoder timer "
					"start is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->ec_encoder_start_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey,"ec_encoder_priority", 11) == 0) {
			if (v->type != json_integer || v->u.integer <= 0 ||
				v->u.integer > BG_TOTAL-1) {
				log_error(lg, "Syntax error: EC encoder priority"
					" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->ec_encoder_priority = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey,"ec_encoder_exclusive", 12) == 0) {
			if (v->type != json_boolean) {
				log_error(lg, "Syntax error: EC encoder exclusive"
					" has to be true or false");
				return -EINVAL;
			}
			cfg->ec_encoder_exclusive = v->u.boolean;
			(*n_opts)++;

		} else if (strncmp(namekey, "trlog_delete_after_hours", 24) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: trlog "
					"delete_after_hours is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->trlog_delete_after_hours = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey,"trlog_start", 11) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: trlog timer "
					"start is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->trlog_start_ms = v->u.integer;
			(*n_opts)++;

		} else if (strncmp(namekey, "_gw_cache_timer", 15) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: gw cache "
					"timer is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->gw_cache_timer_ms = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey,"_gw_cache_start", 15) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: gw cache "
					"start is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->gw_cache_start_ms = v->u.integer;
			(*n_opts)++;

		} else if (strncmp(namekey, "dev_utilization_threshold_low", 29) == 0) {
			if (v->type != json_integer || v->u.integer < 0 ||
				v->u.integer >= 100) {
				log_error(lg, "Syntax error: device utilization"
						"_threshold is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->dev_utilization_threshold_low =
					(double) v->u.integer / 100.0;
			(*n_opts)++;
		} else if (strncmp(namekey, "dev_utilization_threshold_high", 30) == 0) {
			if (v->type != json_integer || v->u.integer < 0 ||
				v->u.integer >= 100) {
				log_error(lg, "Syntax error: device utilization"
						"_threshold is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->dev_utilization_threshold_high =
					(double) v->u.integer / 100.0;
			(*n_opts)++;
		} else if (strncmp(namekey, "dev_capacity_limit", 18) == 0) {
			if (v->type != json_integer || v->u.integer < 0 ||
				v->u.integer >= 100) {
				log_error(lg, "Syntax error: dev_capacity_limit"
						" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->dev_capacity_limit =
					(double) v->u.integer / 100.0;
			(*n_opts)++;
		} else if (strncmp(namekey, "dev_capacity_max", 16) == 0) {
			if (v->type != json_integer || v->u.integer < 0 ||
				v->u.integer >= 100) {
				log_error(lg, "Syntax error: dev_capacity_max"
						" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->dev_capacity_max_data =
					(double) v->u.integer / 100.0;
			(*n_opts)++;
		} else if (strncmp(namekey, "dev_capacity_full", 17) == 0) {
			if (v->type != json_integer || v->u.integer < 0 ||
				v->u.integer >= 100) {
				log_error(lg, "Syntax error: dev_capacity_max_full"
						" is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->dev_capacity_max_full =
					(double) v->u.integer / 100.0;
			(*n_opts)++;
		} else if (strncmp(namekey, "version_quarantine_timeout", 26) == 0) {
			if (v->type != json_integer || v->u.integer < 0) {
				log_error(lg, "Syntax error: version "
					"quarantine timeout is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->version_quarantine_timeout = v->u.integer * 1000;
			(*n_opts)++;
		} else if (strncmp(namekey, "speculative_backref_timeout", 27) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: speculative "
						"backref timeout is not an integer or incorrect value");
				return -EINVAL;
			}
			cfg->speculative_backref_timeout_min = v->u.integer * 1000;
			cfg->speculative_backref_timeout =
					cfg->speculative_backref_timeout_min;
			(*n_opts)++;
		} else if (strncmp(namekey, "compact_on_boot", 15) == 0) {
			if (v->type != json_boolean) {
				log_error(lg, "Syntax error: compactify-on-boot flag "
						"has to be true or false");
				return -EINVAL;
			}
			cfg->compact_on_boot = v->u.boolean;
			(*n_opts)++;
		} else if (strncmp(namekey, "flush_threshhold_timeout", 14) == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: flush_threshhold_timeout "
						"has to be an integer");
				return -EINVAL;
			}
			cfg->flush_threshold_timeout = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "_gw_cache_hw_mark", 18) == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: _gw_cache_hw_mark "
						"has to be an integer");
				return -EINVAL;
			}
			cfg->gw_cache_hw_mark = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "_gw_cache_lw_mark", 18) == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: _gw_cache_lw_mark "
						"has to be an integer");
				return -EINVAL;
			}
			cfg->gw_cache_lw_mark = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "_gw_cache_chids_in_mem", 22) == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: _gw_cache_chids_in_mem "
						"has to be an integer");
				return -EINVAL;
			}
			cfg->gw_cache_chids_in_mem = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "thread_pool_size", 16) == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: thread_pool_size "
						"has to be an integer");
				return -EINVAL;
			}
			cfg->thread_pool_size = v->u.integer;
			(*n_opts)++;
		} else if (strncmp(namekey, "tenant_thread_pool_size", 23) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: tenant contexts is not "
					      "an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tenant_thread_pool_size = v->u.integer > REPDEV_TC_TP_MAX_SZ ?
					REPDEV_TC_TP_MAX_SZ : v->u.integer;
			if (v->u.integer > REPDEV_TC_TP_MAX_SZ)
				log_notice(lg, "tenant thread pool size exceeds maximum "
						"size %u. Setting it to max value",
						REPDEV_TC_TP_MAX_SZ);
			(*n_opts)++;
		} else if (strncmp(namekey, "tp_low_weight", 13) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: a low priority thread weight "
					      "isn't an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tp_low_weight = v->u.integer > DEV_TP_LOW_WEIGHT ?
					DEV_TP_LOW_WEIGHT : v->u.integer;
			if (v->u.integer > DEV_TP_LOW_WEIGHT)
				log_notice(lg, "low priority threads weight exceeds maximum "
						"size %u. Setting it to max value",
						DEV_TP_LOW_WEIGHT);
			(*n_opts)++;
		} else if (strncmp(namekey, "tp_low_reserved", 15) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: a low priority thread reservation "
					      "isn't an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tp_low_reserved = v->u.integer > DEV_TP_LOW_RESERVED ?
					DEV_TP_LOW_RESERVED : v->u.integer;
			if (v->u.integer > DEV_TP_LOW_RESERVED)
				log_notice(lg, "low priority threads reseveration exceeds maximum "
						"size %u. Setting it to max value",
						DEV_TP_LOW_RESERVED);
			(*n_opts)++;
		} else if (strncmp(namekey, "tp_low_resiliency", 17) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: a low priority thread resiliency "
					      "isn't an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tp_low_resiliency = v->u.integer > DEV_TP_LOW_RESILIENCY ?
					DEV_TP_LOW_RESILIENCY : v->u.integer;
			if (v->u.integer > DEV_TP_LOW_RESILIENCY)
				log_notice(lg, "low priority threads resiliency exceeds maximum "
						"size %u. Setting it to max value",
						DEV_TP_LOW_RESILIENCY);
			(*n_opts)++;
		} else if (strncmp(namekey, "tp_mid_weight", 13) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: a mid priority thread weight "
					      "isn't an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tp_mid_weight = v->u.integer > DEV_TP_MID_WEIGHT ?
					DEV_TP_MID_WEIGHT : v->u.integer;
			if (v->u.integer > DEV_TP_MID_WEIGHT)
				log_notice(lg, "low priority threads weight exceeds maximum "
						"size %u. Setting it to max value",
						DEV_TP_MID_WEIGHT);
			(*n_opts)++;
		} else if (strncmp(namekey, "tp_mid_reserved", 15) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: a mid priority thread reservation "
					      "isn't an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tp_mid_reserved = v->u.integer > DEV_TP_MID_RESERVED ?
					DEV_TP_MID_RESERVED : v->u.integer;
			if (v->u.integer > DEV_TP_MID_RESERVED)
				log_notice(lg, "mid priority threads reseveration exceeds maximum "
						"size %u. Setting it to max value",
						DEV_TP_MID_RESERVED);
			(*n_opts)++;
		} else if (strncmp(namekey, "tp_mid_resiliency", 17) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: a mid priority thread resiliency "
					      "isn't an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tp_mid_resiliency = v->u.integer > DEV_TP_MID_RESILIENCY ?
					DEV_TP_MID_RESILIENCY : v->u.integer;
			if (v->u.integer > DEV_TP_MID_RESILIENCY)
				log_notice(lg, "mid priority threads resiliency exceeds maximum "
						"size %u. Setting it to max value",
						DEV_TP_MID_RESILIENCY);
			(*n_opts)++;
		} else if (strncmp(namekey, "tp_hi_weight", 12) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: a high priority thread weight "
					      "isn't an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tp_hi_weight = v->u.integer > DEV_TP_HI_WEIGHT ?
					DEV_TP_HI_WEIGHT : v->u.integer;
			if (v->u.integer > DEV_TP_HI_WEIGHT)
				log_notice(lg, "high priority threads weight exceeds maximum "
						"size %u. Setting it to max value",
						DEV_TP_HI_WEIGHT);
			(*n_opts)++;
		} else if (strncmp(namekey, "tp_hi_reserved", 14) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: a high priority thread reservation "
					      "isn't an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tp_hi_reserved = v->u.integer > DEV_TP_HI_RESERVED ?
					DEV_TP_HI_RESERVED : v->u.integer;
			if (v->u.integer > DEV_TP_HI_RESERVED)
				log_notice(lg, "high priority threads reseveration exceeds maximum "
						"size %u. Setting it to max value",
						DEV_TP_HI_RESERVED);
			(*n_opts)++;
		} else if (strncmp(namekey, "tp_hi_resiliency", 16) == 0) {
			if (v->type != json_integer || v->u.integer <= 0) {
				log_error(lg, "Syntax error: a high priority thread resiliency "
					      "isn't an integer or incorrect value");
				return -EINVAL;
			}
			cfg->tp_hi_resiliency = v->u.integer > DEV_TP_HI_RESILIENCY ?
					DEV_TP_HI_RESILIENCY : v->u.integer;
			if (v->u.integer > DEV_TP_HI_RESILIENCY)
				log_notice(lg, "high priority threads resiliency exceeds maximum "
						"size %u. Setting it to max value",
						DEV_TP_HI_RESILIENCY);
			(*n_opts)++;
		} else if (strncmp(namekey, "elru_sync_ratio", 15) == 0) {
			if (v->type != json_double || v->u.dbl <= 0 || v->u.dbl > 100.0) {
				log_error(lg, "Syntax error: a eLRU sync ratio "
					"has to be a float point value in range 0.0 to 100.0");
				return -EINVAL;
			}
			cfg->elru_touch_ratio = v->u.dbl * 10;
		} else if (strncmp(namekey, "elru_hits_to_sync", 19) == 0) {
			if (v->type != json_integer || v->u.integer < 0) {
				log_error(lg, "Syntax error: a eLRU hits to sync threshold "
					"has to be a zero or a positive integer value");
				return -EINVAL;
			}
			cfg->elru_hits_count = v->u.integer;
		}
	}
	return 0;
}

void
reptrans_close_all_rt() {
	QUEUE *q;
	struct reptrans * rt;
	while (!QUEUE_EMPTY(&all_rts)) {
		q = QUEUE_HEAD(&all_rts);
		rt = QUEUE_DATA(q, struct reptrans, item);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		uv_rwlock_destroy(&rt->devlock);
		uv_rwlock_destroy(&rt->cl_healthy_lock);
		uv_mutex_destroy(&rt->opps_lock);
		uv_mutex_destroy(&rt->call_mutex);
		uv_mutex_destroy(&rt->tc_mutex);
		uv_mutex_destroy(&rt->trlog_mutex);
		uv_mutex_destroy(&rt->comp_mutex);
		uv_mutex_destroy(&rt->comp_stat_mutex);
		uv_mutex_destroy(&rt->recovery_queue_mutex);
		int err = dlclose(rt->handle);
		if (err)
			log_error(lg, "Error closing reptans handle: %s", strerror(err));
	}
}

struct stable_version_entry {
	uint64_t generation;
	uint64_t ts;
};

int
reptrans_stable_version_init(struct repdev* dev) {
	if (dev->stab_versions_map)
		return 0;

	uv_rwlock_init(&dev->stab_versions_lock);
	dev->stab_versions_map = hashtable_create(1000, 0, 0.05);
	if (!dev->stab_versions_map)
		return -ENOMEM;
	return 0;
}

void
reptrans_stable_version_destroy(struct repdev* dev) {
	if (!dev->stab_versions_map)
		return;
	uv_rwlock_wrlock(&dev->stab_versions_lock);
	hashtable_destroy(dev->stab_versions_map);
	dev->stab_versions_map = NULL;
	uv_rwlock_wrunlock(&dev->stab_versions_lock);
}

int
reptrans_stable_version_set(struct repdev* dev, const uint512_t* nhid,
	uint64_t gen, uint64_t ts) {
	uv_rwlock_wrlock(&dev->stab_versions_lock);
	if (!dev->stab_versions_map) {
		uv_rwlock_wrunlock(&dev->stab_versions_lock);
		return -ENODEV;
	}
	struct stable_version_entry entry = {.generation = gen, .ts = ts};
	int err = hashtable_put(dev->stab_versions_map, (void*)nhid, sizeof(*nhid),
		&entry, sizeof(entry));
	uv_rwlock_wrunlock(&dev->stab_versions_lock);
	return err;
}

int
reptrans_stable_version_delete(struct repdev* dev, const uint512_t* nhid) {
	uv_rwlock_wrlock(&dev->stab_versions_lock);
	if (!dev->stab_versions_map) {
		uv_rwlock_wrunlock(&dev->stab_versions_lock);
		return -ENODEV;
	}
	hashtable_remove(dev->stab_versions_map, (void*)nhid, sizeof(*nhid));
	uv_rwlock_wrunlock(&dev->stab_versions_lock);
	return 0;
}

int
reptrans_stable_version_get(struct repdev* dev, uint512_t* nhid,
	uint64_t* gen, uint64_t* ts) {
	uv_rwlock_rdlock(&dev->stab_versions_lock);
	if (!dev->stab_versions_map) {
		uv_rwlock_rdunlock(&dev->stab_versions_lock);
		return -ENODEV;
	}
	size_t value_size = 0;
	struct stable_version_entry* e = hashtable_get(dev->stab_versions_map, nhid, sizeof(*nhid),
		&value_size);
	if (!e) {
		uv_rwlock_rdunlock(&dev->stab_versions_lock);
		return -ENOENT;
	}
	*gen = e->generation;
	*ts = e->ts;
	uv_rwlock_rdunlock(&dev->stab_versions_lock);
	return 0;
}

void
reptrans_perf_limiter_create(struct ngrequest_perf_limiter* pb, uint64_t rate_iops,
	uint64_t interval_us) {
	assert(pb);
	pb->io_rate_max = rate_iops*interval_us/1000000U;
	pb->interval = interval_us;
	pb->ts_begin = 0;
	pb->ops = 0;
	uv_mutex_init(&pb->lock);
}

void
reptrans_perf_set_iops_max(struct ngrequest_perf_limiter* pb, uint64_t rate_iops) {
	assert(pb);
	uv_mutex_lock(&pb->lock);
	pb->io_rate_max = rate_iops*pb->interval/1000000U;
	uv_mutex_unlock(&pb->lock);
}

size_t
reptrans_perf_limiter_update(struct ngrequest_perf_limiter* pb) {
	uv_mutex_lock(&pb->lock);
	uint64_t now = uv_hrtime() / 1000UL;
	uint64_t rate_max = pb->io_rate_max;
	if (!pb->ts_begin)
		pb->ts_begin = now;
	int64_t us_left =  pb->ts_begin + pb->interval - now;
	if (us_left < 0) {
		pb->ts_begin = now;
		pb->ops = 0;
		us_left = pb->interval;
	}
	pb->ops++;
	uv_mutex_unlock(&pb->lock);

	assert(us_left >= 0);
	assert((uint64_t)us_left <= pb->interval);

	if (pb->ops >= rate_max)
		return us_left;

	uint64_t us_per_op_left = us_left/(rate_max - pb->ops);
	return us_per_op_left;
}

int
repdev_generate_name(struct repdev* dev) {
	/*
	 * append the device name here to the serverid string
	 * to generate a cluster unique devicename
	 * in virtual environments, people tend to copy images
	 * and keep the devicename the same although the underlying
	 * devices may be different
	 */
	int err = 0;
	char final_name[SERVER_ID_MAXLEN + strlen(dev->name) + 1];
	if (dev->rt->flags & RT_FLAG_STANDALONE) {
		char srv_path[PATH_MAX];
		snprintf(srv_path, sizeof(srv_path), SERVERID_CACHE_FILE, nedge_path());

		int svrid_fd = open(srv_path, O_RDONLY);
			if (svrid_fd >= 0) {
				err = read(svrid_fd, final_name,
					SERVER_ID_MAXLEN);
				close(svrid_fd);
			}
			final_name[SERVER_ID_MAXLEN-1] = 0;
			if (svrid_fd < 0 || err != SERVER_ID_MAXLEN-1){
				log_notice(lg, "Dev(%s) VDEV ID cannot "
					"be calculated properly",
					dev->name);
			}
	} else
		serverid_dump(final_name, SERVER_ID_MAXLEN);
	strcat(final_name, dev->name);

	/*
	 * Crypto Hash it to size 16
	 *
	 * FIXME: currently primitively based on filesystem name...
	 */
	err = crypto_hash(CRYPTO_BLAKE2B, 16, (const uint8_t *)final_name,
		strlen((char *)final_name), (uint8_t *)&dev->vdevid);
	if (err) {
		log_error(lg, "Cannot calculate GUID for RD "
			"filesystem %s", (char *)dev->name);
	}
	return err;
}

/* The eLRU implementation */

static int
ttable_sort_cb(void* a, void* b) {
	struct touch_table_entry* ta = a;
	struct touch_table_entry* tb = b;

	if (ta->ts > tb->ts)
		return -1;
	else if (ta->ts < tb->ts)
		return 1;

	return tb->hits - ta->hits;
}

static void
srv_getcommon_touch_blob_work(void* arg) {
	struct repdev* dev = arg;
	struct touch_table_entry* t = NULL, *tmp = NULL;
	size_t processed = 0, inserted = 0, touched = 0, hits = 0, evicted = 0;
	uint64_t touch_int = dev->bg_config->speculative_backref_timeout * dev->bg_config->elru_touch_ratio/1000;
	do {
		struct touch_queue_entry* e = lfqueue_dequeue(dev->tchq_inprog);
		assert(e);
		processed++;
		t = NULL;
		if (dev->ttable)
			HASH_FIND(hh, dev->ttable, &e->chid, sizeof(e->chid), t);
		if (!t) {
			t = je_malloc(sizeof(*t));
			if (!t) {
				log_error(lg, "Out of memory");
				return;
			}
			t->chid = e->chid;
			t->ts = get_timestamp_us();
			t->hits = 1;
			HASH_ADD(hh, dev->ttable, chid, sizeof(t->chid), t);
			inserted++;
		} else {
			t->hits++;
			hits++;
		}
		if (t->hits >= dev->bg_config->elru_hits_count &&
			t->ts + touch_int < get_timestamp_us()) {

			t->ts = get_timestamp_us();

			int err = reptrans_touch_blob(dev, e->ttag, e->hash_type,
				&e->chid);

			if (err && err != -ENOENT)
				log_error(lg, "Couldn't touch blob");

			touched++;
		}
		int err = lfqueue_enqueue(dev->tchq_free, e);
		assert(err == 0);
	} while(lfqueue_length(dev->tchq_inprog));

	/* touch table eviction code. Drop outdated entries */
	uint64_t eviction_timeout = dev->bg_config->elru_hits_count == 0 ?
		touch_int : touch_int*dev->bg_config->elru_hits_count;
	HASH_ITER(hh, dev->ttable, t, tmp) {
		if (t->ts + eviction_timeout  < get_timestamp_us()) {
			HASH_DEL(dev->ttable, t);
			je_free(t);
			evicted++;
		}
	}
	/*
	 * If the table size is bigger than a threshold, then evict even more
	 */
	uint64_t max_entries = DEV_MDONLY_TOUCH_TABLE_SIZE/sizeof(*t);
	if (is_embedded())
		max_entries = DEV_MDONLY_TOUCH_TABLE_SIZE_EMBEDDED/sizeof(*t);

	size_t tt_count = HASH_COUNT(dev->ttable);

	if (tt_count > max_entries) {
		/* Sort in timespamp descend order */
		HASH_SORT(dev->ttable, ttable_sort_cb);
		/* Remove the oldest */
		HASH_ITER(hh, dev->ttable, t, tmp) {
			HASH_DEL(dev->ttable, t);
			je_free(t);
			evicted++;
			if (--tt_count <= max_entries)
				break;
		}
	}
	log_debug(lg, "Dev(%s) touch queue worker: handled %lu, inserted %lu,"
		" hits %lu, touched %lu, evicted %lu, tchq_size %lu", dev->name,
		processed, inserted, hits, touched, evicted, tt_count);
}

static void
srv_getcommon_touch_blob_done(void* arg, int status) {
	struct repdev* dev = arg;
	dev->tchd_work_inprog = 0;
}

static void
reptrans_process_touch_queue__sync(struct repdev* dev)
{
	if (dev->tchd_work_inprog)
		return;

	dev->tchd_work_inprog = 1;
	int err = ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_LOW,
		srv_getcommon_touch_blob_work,
		srv_getcommon_touch_blob_done, dev);
	if (err)
		log_error(lg, "Dev(%s) touch queue worker start error: %d",
			dev->name, err);
}

static void
reptrans_process_touch_queue__async_call(struct repdev_call *c)
{
	struct repdev *dev = c->args[0];

	reptrans_process_touch_queue__sync(dev);
}

void
reptrans_process_touch_queue(struct repdev* dev) {
	int qlen = lfqueue_length(dev->tchq_inprog);

	if ((qlen > lfqueue_cap(dev->tchq_free)) ||
		(qlen && dev->tchd_work_ts < get_timestamp_us())) {

		dev->tchd_work_ts = get_timestamp_us() + 60*1000*1000;

		if (dev->thread_id == pthread_self())
			reptrans_process_touch_queue__sync(dev);
		else {
			struct repdev_call *call = je_calloc(1, sizeof(struct repdev_call));
			if (call == NULL) {
				log_error(lg, "Out of memory");
				return;
			}
			/* Send message to device */
			call->method = reptrans_process_touch_queue__async_call;
			call->args[0] = dev;
			QUEUE_INIT(&call->item);
			uv_mutex_lock(&dev->call_mutex);
			QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
			uv_mutex_unlock(&dev->call_mutex);
			uv_async_send(&dev->call_async);
		}
	}
}


int
reptrans_get_fd_targets_number_unsafe(int domain) {
	int fd_item_count = SERVER_FLEXHASH->vdevstore->lvdevcount;
	switch(domain) {
		case FD_SERVER:
			fd_item_count = flexhash_valid_servercount(SERVER_FLEXHASH);
			break;
		case FD_ZONE:
			fd_item_count = SERVER_FLEXHASH->zonecount;
			break;
	}
	return fd_item_count;
}

int
reptrans_get_fd_targets_number(int domain) {
	int fd_item_count = 0;
	ccowd_fhready_lock(FH_LOCK_READ);
	fd_item_count = reptrans_get_fd_targets_number_unsafe(domain);
	ccowd_fhready_unlock(FH_LOCK_READ);
	return fd_item_count;
}

