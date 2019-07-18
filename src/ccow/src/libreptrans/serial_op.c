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

#include "reptrans.h"
#include "state.h"
#include "putcommon_server.h"
#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "rt_locks.h"

#define FINAL_DELAY 500000UL

struct serial_op_item;

static int schedule_lock_item(struct repwqe *wqe, msgpack_u *u);

static int schedule_list_item(struct repwqe *wqe, msgpack_u *u);

typedef int (* schedule)(struct repwqe *wqe, msgpack_u *u);

schedule shedule_item[] = {
	schedule_lock_item,
	schedule_list_item
};

static int isAttrib(uint8_t minor)
{
	return (minor == CCOW_SR_INSERT_MD ||
		minor == CCOW_SR_UPDATE_MD ||
		minor == CCOW_SR_DELETE_MD ||
		minor ==  CCOW_SR_INSERT_LIST_WITH_MD ||
		minor == CCOW_SR_DELETE_LIST_WITH_MD);
}

static int isDelay(struct repmsg_rendezvous_transfer *msg)
{
	return (msg && msg->hdr.attributes & RD_ATTR_EVENTUAL_SOP);
}

static int
isList(uint8_t minor)
{
	return (minor == CCOW_SR_DELETE_LIST ||
		minor == CCOW_SR_INSERT_LIST ||
		minor == CCOW_SR_UPDATE_LIST);
}

static int
isFlush(uint8_t minor)
{
	return (minor == CCOW_SR_FLUSH);
}


static schedule
get_sop_item(uint8_t major, uint8_t minor)
{
	if (major == CCOW_SR_MAJ_LOCK) {
		return shedule_item[0];
	}

	if (isAttrib(minor) || isList(minor) || isFlush(minor))
	{
		return shedule_item[1];
	}

	log_error(lg, "Unable to get serial op major: %u minor: %u", major, minor);
	return NULL;
}


static int
decode_operation(struct repwqe *wqe, uint8_t *major, uint8_t *minor,
		char *cid, size_t *cid_size,
		char *tid, size_t *tid_size,
		char *bid, size_t *bid_size,
		char *oid, size_t *oid_size)
{
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct iovec *iov = NULL;
	uint32_t iov_cnt;

	int err = -EINVAL;

	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;
	struct repmsg_named_chunk_put_proposal *msg_pp =
		(struct repmsg_named_chunk_put_proposal *) req->msg_pp;

	req->payload[0].len = msg->content_length;
	req->payload[0].base = repwqe_payload(wqe);
	rtbuf_t *rb = rtbuf_init_mapped(&req->payload[0], req->nbufs);
	if (!rb) {
		log_error(lg, "decode_operation(%s): out of memory on SOP",
		    dev->name);
		return -ENOMEM;
	}

	uv_buf_t *buf = &rb->bufs[0];
	msgpack_u *u = msgpack_unpack_init(buf->base, buf->len, 0);

	MCHK(err, msgpack_unpack_uint8(u, major), goto _exit);
	MCHK(err, msgpack_unpack_uint8(u, minor), goto _exit);

	if (*major == CCOW_SR_MAJ_LOCK) {
		err = 0;
		goto _exit;
	}

	MCHK(err, msgpack_unpack_map(u, &iov_cnt), goto _exit);

	if (iov_cnt == 0) {
		goto _exit;
	}

	iov = je_calloc(iov_cnt, sizeof(struct iovec));
	if (!iov) {
		goto _exit;
	}

	for (uint32_t i = 0; i < iov_cnt; i++) {
		err = msgpack_unpack_raw(u,
					     (const uint8_t **)&iov[i].iov_base,
					     (uint32_t *)&iov[i].iov_len);
		if (err)
			goto _exit;
	}

	strcpy(cid,"");
	strcpy(tid,"");
	strcpy(bid,"");
	strcpy(oid,"");
	*cid_size = 1;
	*tid_size = 1;
	*bid_size = 1;
	*oid_size = 1;

	switch (*major) {
	case CCOW_SR_MAJ_OBJECT_UPDATE:
		memcpy(oid, iov[3].iov_base, iov[3].iov_len);
		*oid_size = iov[3].iov_len;
		oid[iov[3].iov_len] = 0;
	case CCOW_SR_MAJ_BUCKET_UPDATE:
		memcpy(bid, iov[2].iov_base, iov[2].iov_len);
		*bid_size = iov[2].iov_len;
		bid[iov[2].iov_len] = 0;
	case CCOW_SR_MAJ_TENANT_UPDATE:
		memcpy(tid, iov[1].iov_base, iov[1].iov_len);
		*tid_size = iov[1].iov_len;
		tid[iov[1].iov_len] = 0;
	case CCOW_SR_MAJ_CLUSTER_UPDATE:
		memcpy(cid, iov[0].iov_base, iov[0].iov_len);
		*cid_size = iov[0].iov_len;
		cid[iov[0].iov_len] = 0;
	case CCOW_SR_MAJ_SYS_UPDATE:
		break;
	default:
		goto _exit;
	}
	err = 0;

_exit:
	msgpack_unpack_free(u);
	rtbuf_destroy(rb);
	if (iov)
		je_free(iov);
	return err;
}

static struct repdev *
get_dev(struct repwqe *wqe)
{
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	return dev;
}

static int
namedput_list_exec(struct repdev *dev, uint8_t *data, size_t size, ccow_t tc,
    ccow_completion_t c_inprog, int *index)
{
	struct iovec *iov = NULL;
	uint32_t iov_cnt;
	uint32_t idx;
	int err = 0;
	ccow_op_t optype;
	uint8_t major, minor;
	msgpack_u *uattr;

	log_trace(lg, "Dev(%s): serial list update, size %ld", dev->name, size);

	msgpack_u *u = msgpack_unpack_init(data, size, 0);

	MCHK(err, msgpack_unpack_uint8(u, &major), goto _exit);
	MCHK(err, msgpack_unpack_uint8(u, &minor), goto _exit);

	MCHK(err, msgpack_unpack_map(u, &iov_cnt), goto _exit);

	if (iov_cnt == 0) {
		err = -EINVAL;
		log_error(lg, "Invalid request: %d, index: %d", err, *index);
		goto _exit;
	}

	iov = je_calloc(iov_cnt, sizeof(struct iovec));
	if (!iov) {
		err = -ENOMEM;
		log_error(lg, "No mem error: %d, index: %d", err, *index);
		goto _exit;
	}

	for (uint32_t i = 0; i < iov_cnt; i++) {
		MCHK(err, msgpack_unpack_raw(u,
					     (const uint8_t **)&iov[i].iov_base,
					     (uint32_t *)&iov[i].iov_len),
		     goto _exit);
	}


	idx = major - CCOW_SR_MAJ_SYS_UPDATE;

	if (minor == CCOW_SR_INSERT_LIST) {
		log_debug(lg, "Dev(%s): SOP CCOW_SR_INSERT_LIST key: %s[%d], major: %u, minor: %u\n",
			      dev->name, (char *)iov[idx].iov_base, (int)(iov_cnt - idx), major, minor);
		c_inprog->cont_flags = 0;
		err = ccow_insert_list_cont(c_inprog, &iov[idx], iov_cnt - idx, 1, index);
		if (err) {
			log_error(lg, "Insert list error: %d, index: %d", err, *index);
			goto _exit;
		}
	} else if (minor == CCOW_SR_UPDATE_LIST) {
		log_debug(lg, "Dev(%s): SOP CCOW_SR_UPDATE_LIST key: %s[%d], major: %u, minor: %u\n",
				  dev->name, (char *)iov[idx].iov_base, (int)(iov_cnt - idx), major, minor);
		c_inprog->cont_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
		err = ccow_insert_list_cont(c_inprog, &iov[idx], iov_cnt - idx, 1, index);
		if (err) {
			log_error(lg, "Dev(%s): Update list error: %d, index: %d", dev->name, err, *index);
			goto _exit;
		}
	} else  if (minor == CCOW_SR_DELETE_LIST) {
		log_debug(lg, "Dev(%s): SOP CCOW_SR_DELETE_LIST key: %s, major: %u, minor: %u\n",
			      dev->name, (char *)iov[idx].iov_base, major, minor);
		c_inprog->cont_flags = 0;
		err = ccow_delete_list_cont(c_inprog, &iov[idx], 1, 1, index);
		if (err) {
			log_error(lg, "Dev(%s): Delete list error: %d, index: %d", dev->name, err, *index);
			goto _exit;
		}
	} else {
		log_error(lg, "Dev(%s): SOP Wrong operation key: %s, major: %u, minor: %u\n",
			      dev->name, (char *)iov[idx].iov_base, major, minor);
		goto _exit;
	}

	err = ccow_wait(c_inprog, *index);
	if (err) {
		log_error(lg, "Dev(%s): Wait error: %d, index: %d", dev->name, err, *index);
		goto _exit;
	}
	err = ccow_list_cont_status(c_inprog, *index);

_exit:
	msgpack_unpack_free(u);
	if (iov)
		je_free(iov);
	return err;
}


static int
namedput_list_exec_wqe(void *arg, ccow_t tc, ccow_completion_t c_inprog, int *index)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	int err = 0;

	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;
	struct repmsg_named_chunk_put_proposal *msg_pp =
		(struct repmsg_named_chunk_put_proposal *) req->msg_pp;

	log_trace(lg, "serial list update st: %p dev: %s", st, dev->name);

	req->payload[0].len = msg->content_length;
	req->payload[0].base = repwqe_payload(wqe);
	rtbuf_t *rb = rtbuf_init_mapped(&req->payload[0], req->nbufs);
	if (!rb) {
		log_error(lg, "ListSOP(%s): out of memory while bulk update",
		    dev->name);
		return RT_ERR_NO_RESOURCES;
	}

	uv_buf_t *buf = &rb->bufs[0];
	log_debug(lg, "Payload bufs: %d Payload len: %lu", req->nbufs,
							   rtbuf_len(rb));

	err = namedput_list_exec(dev, (uint8_t *)buf->base, buf->len, tc, c_inprog, index);

	rtbuf_destroy(rb);
	return err;
}


static int
namedput_attrib_exec(struct repdev *dev, uint8_t *data, size_t size, ccow_t tc,
    ccow_completion_t c_inprog, int *index, ccow_lookup_t iter)
{
	struct iovec *iov = NULL;
	uint32_t iov_cnt;
	uint32_t idx;
	int err = 0;
	ccow_op_t optype;
	uint8_t major, minor;
	msgpack_u *uattr;
	struct ccow_metadata_kv *attr = NULL;
	ccow_metadata_kv_t *attrs = NULL;

	log_trace(lg, "Dev(%s): serial list attrib update", dev->name);

	msgpack_u *u = msgpack_unpack_init(data, size, 0);

	MCHK(err, msgpack_unpack_uint8(u, &major), goto _exit);
	MCHK(err, msgpack_unpack_uint8(u, &minor), goto _exit);

	MCHK(err, msgpack_unpack_map(u, &iov_cnt), goto _exit);

	if (iov_cnt == 0) {
		err = -EINVAL;
		log_error(lg, "Dev(%s): Invalid  request: %d, index: %d", dev->name, err, *index);
		goto _exit;
	}

	iov = je_calloc(iov_cnt, sizeof(struct iovec));
	if (!iov) {
		err = -ENOMEM;
		log_error(lg, "Dev(%s): No mem error: %d, index: %d", dev->name, err, *index);
		goto _exit;
	}


	for (uint32_t i = 0; i < iov_cnt; i++) {
		MCHK(err, msgpack_unpack_raw(u,
					     (const uint8_t **)&iov[i].iov_base,
					     (uint32_t *)&iov[i].iov_len),
		     goto _exit);
	}

	switch (minor) {
		case CCOW_SR_INSERT_MD:
			optype = CCOW_INSERT_MD;
			break;
		case CCOW_SR_UPDATE_MD:
			optype = CCOW_UPDATE_MD;
			break;
		case CCOW_SR_DELETE_MD:
			optype = CCOW_DELETE_MD;
			break;
		case CCOW_SR_INSERT_LIST_WITH_MD:
			optype = CCOW_INSERT_LIST_WITH_MD;
			break;
		case CCOW_SR_DELETE_LIST_WITH_MD:
			optype = CCOW_DELETE_LIST_WITH_MD;
			break;
		default:
			goto _exit;
	}

	idx = major - CCOW_SR_MAJ_SYS_UPDATE;
	log_trace(lg, "Dev(%s) container serial update major: %u, minor: %u, optype: %u\n",
		      dev->name, major, minor, optype);

	/* IOV for name key and value pair */
	struct iovec name_iov[2];
	struct iovec *kv_iov = NULL;
	size_t kv_count = 0;

	if (optype == CCOW_INSERT_LIST_WITH_MD ||
		optype == CCOW_DELETE_LIST_WITH_MD) {
		/* Extract key (name) */
		name_iov[0].iov_base = iov[idx].iov_base;
		name_iov[0].iov_len = iov[idx].iov_len;
		idx++;
		/* Extract value */
		name_iov[1].iov_base = iov[idx].iov_base;
		name_iov[1].iov_len = iov[idx].iov_len;
		idx++;
		kv_iov = &name_iov[0];
		kv_count = 2;
	}

	uint64_t sz, obj_cnt;
	uint32_t attr_nr = iov_cnt - idx;
	if (attr_nr < 1) {
		err = -EINVAL;
		goto _exit;
	}
	attr = je_calloc(attr_nr, sizeof(struct ccow_metadata_kv));
	attrs = je_calloc(attr_nr, sizeof(ccow_metadata_kv_t));

	for (uint32_t i = 0; i < attr_nr; i++) {
		uattr = msgpack_unpack_init(iov[idx + i].iov_base,
						iov[idx + i].iov_len, 0);
		err = ccow_unpack_mdkv(uattr, &attr[i]);
		if (err) {
			msgpack_unpack_free(uattr);
			for (uint32_t j = 0; j < i; j++) {
				if (attr[j].key)
					je_free(attr[j].key);
				if (attr[j].value)
					je_free(attr[j].value);
			}
			log_error(lg, "Dev(%s):  decode error: %d", dev->name, err);
			err = -EINVAL;
			goto _exit;
		}
		attrs[i] = &attr[i];
		msgpack_unpack_free(uattr);
	}

	err = ccow_verify_mdop(optype, attrs, attr_nr);
	if (err) {
		for (uint32_t i = 0; i < attr_nr; i++) {
			if (attr[i].key)
				je_free(attr[i].key);
			if (attr[i].value)
				je_free(attr[i].value);
		}
		err = RT_ERR_WRONG_OPCODE;
		goto _exit;
	}

	err = modify_attrs(c_inprog, iter, optype, attrs, attr_nr);

	for (uint32_t i = 0; i < attr_nr; i++) {
		if (attr[i].key)
			je_free(attr[i].key);
		if (attr[i].value)
			je_free(attr[i].value);
	}

	if (err) {
		log_error(lg, "Dev(%s): attr update failed"
				" err: %d", dev->name, err);
		goto _exit;
	} else {
		log_trace(lg, "Dev(%s): attr update on ok"
				" err: %d", dev->name, err);
	}

	// Handle combined operations
	if (minor == CCOW_SR_INSERT_LIST_WITH_MD) {
		log_debug(lg, "Dev(%s): SOP CCOW_SR_INSERT_LIST_MD key: %s[%d], major: %u, minor: %u\n",
				  dev->name, (char *)kv_iov[0].iov_base, (int)(kv_count), major, minor);
		c_inprog->cont_flags = 0;
		err = ccow_insert_list_cont(c_inprog, &kv_iov[0], kv_count, 1, index);
		if (err) {
			log_error(lg, "Dev(%s): Insert list with md error: %d, index: %d", dev->name, err, *index);
			goto _exit;
		}
		err = ccow_wait(c_inprog, *index);
		if (err) {
			log_error(lg, "Dev(%s): Wait error: %d, index: %d", dev->name, err, *index);
			goto _exit;
		}
		err = ccow_list_cont_status(c_inprog, *index);
	} else if (minor == CCOW_SR_DELETE_LIST_WITH_MD) {
		log_debug(lg, "Dev(%s): SOP CCOW_SR_DELETE_LIST_MD key: %s[%d], major: %u, minor: %u\n",
				  dev->name, (char *)kv_iov[0].iov_base, (int)(kv_count), major, minor);
		c_inprog->cont_flags = 0;
		err = ccow_delete_list_cont(c_inprog, &kv_iov[0], 1, 1, index);
		if (err) {
			log_error(lg, "Dev(%s): Delete list with md error: %d, index: %d", dev->name, err, *index);
			goto _exit;
		}
		err = ccow_wait(c_inprog, *index);
		if (err) {
			log_error(lg, "Dev(%s): Wait error: %d, index: %d", dev->name, err, *index);
			goto _exit;
		}
		err = ccow_list_cont_status(c_inprog, *index);
	}

_exit:
	msgpack_unpack_free(u);
	if (iov)
		je_free(iov);
	if (attr)
		je_free(attr);
	if (attrs)
		je_free(attrs);
	return err;
}

static int
namedput_attrib_exec_wqe(void *arg, ccow_t tc, ccow_completion_t c_inprog, int *index, ccow_lookup_t iter)
{
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	int err = 0;

	struct repmsg_rendezvous_transfer *msg =
		(struct repmsg_rendezvous_transfer *)wqe->msg;
	struct repmsg_named_chunk_put_proposal *msg_pp =
		(struct repmsg_named_chunk_put_proposal *) req->msg_pp;

	log_debug(lg, "serial list update st: %p dev: %s", st, dev->name);

	if (!tc) {
		log_error(lg, "Unable to create tenant context: -ENOMEM");
		return RT_ERR_NO_RESOURCES;
	}

	req->payload[0].len = msg->content_length;
	req->payload[0].base = repwqe_payload(wqe);
	rtbuf_t *rb = rtbuf_init_mapped(&req->payload[0], req->nbufs);
	if (!rb) {
		log_error(lg, "AttribPut(%s): out of memory while bulk update",
		    dev->name);
		return RT_ERR_NO_RESOURCES;
	}

	uv_buf_t *buf = &rb->bufs[0];
	log_debug(lg, "Payload bufs: %d Payload len: %lu", req->nbufs,
							   rtbuf_len(rb));

	err = namedput_attrib_exec(dev, (uint8_t *)buf->base, buf->len, tc, c_inprog, index, iter);

	rtbuf_destroy(rb);
	return err;
}

static void
namedput_srv_done_wqe__async(struct repdev_call *c)
{
	void *arg = c->args[0];
	int status = (long)c->args[1];
	uint64_t new_genid = (long)c->args[2];
	struct repwqe *wqe = arg;
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;

	log_trace(lg, "Dev(%s) st %p cur %d completed many SOP operations",
	    dev->name, st, st->cur);

	if (status == 0) {
		req->sop_generation = new_genid;
		putcommon_srv_set_req_status(req, 0, RT_NAMED_PAYLOAD_ACK);
	} else if (status == -EEXIST) {
		putcommon_srv_set_req_status(req, -EEXIST, RT_ERROR);
	} else if (status == -ENOENT) {
		putcommon_srv_set_req_status(req, -ENOENT, RT_ERROR);
	} else {
		putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES, RT_ACCEPT_NOT_NOW);
	}

	if (!(req->sop_state & NAMEDPUT_SOP_STATE_DONE)) {
		req->sop_state |= NAMEDPUT_SOP_STATE_DONE;
		state_event(st, EV_DONE);
	} else {
		log_error(lg, "Dev(%s) ignored serial opertion completion", dev->name);
	}
	return;
}

static int
namedput_srv_done_wqe(struct repdev *dev, void *arg, int status, uint64_t new_genid)
{
	struct repdev_call *call =
		je_calloc(1, sizeof(struct repdev_call));
	if (call == NULL) {
		return -ENOMEM;
	}
	log_trace(lg, "Dev(%s) done many SOP operation", dev->name);
	call->method = namedput_srv_done_wqe__async;
	call->args[0] = arg;
	call->args[1] = (void *)(long)status;
	call->args[2] = (void *)(long)new_genid;
	QUEUE_INIT(&call->item);
	uv_mutex_lock(&dev->call_mutex);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	uv_mutex_unlock(&dev->call_mutex);
	uv_async_send(&dev->call_async);
	return 0;
}

static inline void
namedput_notify_done(void *data, int err, int ctx_valid)
{
	struct ccow_obj_lock *lk = (struct ccow_obj_lock *)data;
	if (err)
		log_error(lg, "Failed to send lock grant "
				"[%" PRIu64 ",%" PRIu64 ") err : %d",
				lk->lk_region.off, lk->lk_region.len, err);
}

static void
namedput_send_notification(struct repdev *dev, struct ccow_obj_lock *lk,
			   enum replicast_error err,
			   ccow_sr_mj_opcode_t major, ccow_sr_mn_opcode_t minor)
{
	struct repmsg_notification notify;
	struct sockaddr_in6 to_addr;

	memset(&notify, 0, sizeof (notify));
	notify.num_datagrams = 1;
	notify.error = err;
	notify.major_opcode = CCOW_SR_MAJ_LOCK;
	notify.minor_opcode = CCOW_SR_LOCK_GRANTED;
	notify.io_cookie = lk->lk_io_cookie;

	char client[INET6_ADDRSTRLEN + 1] = { 0 };
	memcpy(&to_addr.sin6_addr, &lk->lk_client_addr, sizeof(lk->lk_client_addr));

	inet_ntop(AF_INET6, &to_addr.sin6_addr, client, INET6_ADDRSTRLEN);
	log_debug(lg, "Device %s sending lock notification to the client : %s \n",
			dev->name, client);

	to_addr.sin6_port = lk->lk_client_port;
	to_addr.sin6_scope_id = dev->robj->recv_addr.sin6_scope_id;
	to_addr.sin6_family = AF_INET6;
	to_addr.sin6_flowinfo = 0;

	err = replicast_send(dev->robj, NULL, RT_CLIENT_NOTIFICATION,
			     (struct repmsg_generic *)&notify, NULL, NULL,
			     0, (struct sockaddr_in6 *)&to_addr,
			     namedput_notify_done, lk, NULL);
	if (err)
		log_error(lg, "Failed to send lock grant "
				"[%" PRIu64 ",%" PRIu64 ") err : %d",
				lk->lk_region.off, lk->lk_region.len, err);
}

static int
remove_queued_lock(struct repdev *dev, struct ccow_obj_lock *lk)
{
	struct ccow_obj_lock *next_lk = NULL;
	QUEUE *q;
	int err = -ENOENT;

	uv_mutex_lock(&dev->lk_mutex);
	QUEUE_FOREACH(q, &dev->lock_q) {
		next_lk = QUEUE_DATA(q, struct ccow_obj_lock, lk_link);
		/* TODO: Check owner */
		if(uint512_cmp(&next_lk->lk_nhid, &lk->lk_nhid) == 0) {
			QUEUE_REMOVE(q);
			dev->lk_wait_nr--;
			err = 0;
			assert(dev->lk_wait_nr >= 0);
			break;
		}
	}
	uv_mutex_unlock(&dev->lk_mutex);
	return err;
}

static void
unblock_lock(struct repdev *dev, struct ccow_obj_lock *lk)
{
	struct ccow_obj_lock *next_lk = NULL;
	QUEUE *q;
	int err;

	uv_mutex_lock(&dev->lk_mutex);
	QUEUE_FOREACH(q, &dev->lock_q) {
		next_lk = QUEUE_DATA(q, struct ccow_obj_lock, lk_link);
		if(uint512_cmp(&next_lk->lk_nhid, &lk->lk_nhid) == 0) {
			QUEUE_REMOVE(q);
			dev->lk_wait_nr--;
			assert(dev->lk_wait_nr >= 0);
			break;
		}
	}
	uv_mutex_unlock(&dev->lk_mutex);
	if (next_lk) {
		err = rt_add_lock(dev, next_lk, je_free);
		if (err) {
			log_debug(lg, "Device: %s blocked lock not granted [%"
					PRIu64 ",%" PRIu64 ") err: %d. Adding back",
					dev->name, lk->lk_region.off,
					lk->lk_region.len, err);
			/* Add lock back to queue */
			uv_mutex_lock(&dev->lk_mutex);
			QUEUE_INSERT_TAIL(&dev->lock_q, &next_lk->lk_link);
			dev->lk_wait_nr++;
			uv_mutex_unlock(&dev->lk_mutex);
		} else {
			log_debug(lg, "Device: %s blocked lock granted [%"
				      PRIu64 ",%" PRIu64 ") ",
				      dev->name, lk->lk_region.off, lk->lk_region.len);
			/*
			 * Send notification to the client. Unblock the client
			 * Remember we don't have request context here.
			 */
			namedput_send_notification(dev, next_lk, 0,
						   CCOW_SR_MAJ_LOCK,
						   CCOW_SR_LOCK_GRANTED);
		}
	}
}

static int
schedule_lock_item(struct repwqe *wqe, msgpack_u *u)
{
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;

	struct repdev_call *li;
	struct ccow_obj_lock *lk;
	int conflict, err;
	uint8_t major, minor;
	QUEUE *q;

	MCHK(err, msgpack_unpack_uint8(u, &major), goto _exit);
	MCHK(err, msgpack_unpack_uint8(u, &minor), goto _exit);

	if (major != CCOW_SR_MAJ_LOCK) {
		putcommon_srv_set_req_status(req, RT_ERR_WRONG_OPCODE, RT_ERROR);
		return -EINVAL;
	}

	nassert(dev->loop_thrid == uv_thread_self());

	lk = je_calloc(1, sizeof(*lk));
	if (!lk) {
		putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES, RT_ERROR);
		return -ENOMEM;
	}

	/* Decode lock contents */
	err = ccow_unpack_lock(u, lk);
	if (err) {
		je_free(lk);
		putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES, RT_ERROR);
		return err;
	}

	if (lk->lk_mode & CCOW_LOCK_CANCEL && rt_is_locked(dev, lk))
		lk->lk_mode = CCOW_LOCK_UNLOCK;

	/* Request to unlock existing lock */
	if (lk->lk_mode & CCOW_LOCK_UNLOCK) {
		rt_remove_lock(dev, lk);
		log_debug(lg, "Device: %s st: %p lock [%" PRIu64 ",%" PRIu64
			      ") removed", dev->name, st,
			      lk->lk_region.off, lk->lk_region.len);
		/* Unblock the blocked (waiting locks), if any */
		unblock_lock(dev, lk);
		putcommon_srv_set_req_status(req, 0, RT_NAMED_PAYLOAD_ACK);
		req->sop_state |= NAMEDPUT_SOP_STATE_DONE;
		state_event(st, EV_DONE);
		return 0;
	}

	/* If we come here with a cancel request, check lock queue */
	if (lk->lk_mode & CCOW_LOCK_CANCEL) {
		if (remove_queued_lock(dev, lk) == 0) {
			putcommon_srv_set_req_status(req, 0,
						     RT_NAMED_PAYLOAD_ACK);
			req->sop_state |= NAMEDPUT_SOP_STATE_DONE;
			state_event(st, EV_DONE);
		} else
			putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES,
						     RT_ERROR);
		return 0;
	}

	/* Request for a new lock. Check conflict with existing lock */
	conflict = rt_lock_conflicts(dev, lk);
	if (conflict) {
		if (lk->lk_mode & CCOW_LOCK_NON_BLOCK) {
			putcommon_srv_set_req_status(req, RT_ERR_NO_ACCESS,
							  RT_ERROR);
			return -EAGAIN;
		}
		/*
		 * Conflicting lock grant request.
		 * We have wait until other lock client releases this lock.
		 * Tell lock client that this lock is blocked and notification will
		 * be sent when this lock becomes available.
		 */
		uv_mutex_lock(&dev->lk_mutex);
		if (dev->lk_wait_nr >= DEV_MAX_WAIT_LOCKS) {
			uv_mutex_unlock(&dev->lk_mutex);
			je_free(lk);
			putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES,
							  RT_ACCEPT_NOT_NOW);
			return err;
		} else {
			QUEUE_INSERT_TAIL(&dev->lock_q, &lk->lk_link);
			dev->lk_wait_nr++;
			uv_mutex_unlock(&dev->lk_mutex);
			log_debug(lg, "Device: %s st: %p lock blocked [%"
				      PRIu64 ",%" PRIu64 ") ",
				      dev->name, st, lk->lk_region.off,
				      lk->lk_region.len);
			putcommon_srv_set_req_status(req, RT_ERR_BLOCKED, RT_ERROR);
			return -EWOULDBLOCK;
		}
	}

	/* No conflicts. Add the lock */
	err = rt_add_lock(dev, lk, je_free);
	if (err) {
		log_debug(lg, "Device: %s st: %p lock not granted [%"
				PRIu64 ",%" PRIu64 ") err: %d",
				dev->name, st, lk->lk_region.off,
				lk->lk_region.len, err);
		je_free(lk);
		putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES, RT_ERROR);
	} else {
		log_debug(lg, "Device: %s st: %p blocked lock granted [%"
			      PRIu64 ",%" PRIu64 ") ",
			      dev->name, st, lk->lk_region.off, lk->lk_region.len);
		putcommon_srv_set_req_status(req, 0, RT_NAMED_PAYLOAD_ACK);
		req->sop_state |= NAMEDPUT_SOP_STATE_DONE;
		state_event(st, EV_DONE);
	}

_exit:
	return err;
}

#define X_KEY_COUNT	"X-count"
#define X_KEY_DATA	"X-data-"

static void
namedput_journal_close(ccow_completion_t j_inprog, ccow_lookup_t j_iter)
{
	int err;

	log_trace(lg, "close %p lp %p", j_inprog, j_iter);

	/* delete all custom metadata */
	int pos = 0;
	struct ccow_metadata_kv *kv;
	while ((kv = ccow_lookup_iter(j_iter, CCOW_MDTYPE_CUSTOM, pos++))) {
		if (memcmp_quick(kv->key, kv->key_size, X_KEY_COUNT, sizeof(X_KEY_COUNT)) == 0) {
			err = ccow_attr_modify_custom(j_inprog, CCOW_KVTYPE_UINT64,
			    X_KEY_COUNT, sizeof(X_KEY_COUNT), NULL, 0, j_iter);
		} else if (memcmp_safe(kv->key, kv->key_size, X_KEY_DATA, sizeof(X_KEY_DATA)-1) == 0) {
			err = ccow_attr_modify_custom(j_inprog, CCOW_KVTYPE_RAW, kv->key, kv->key_size,
			    NULL, 0, j_iter);
		}
	}

	ccow_lookup_t itfinal;
	err = ccow_finalize(j_inprog, &itfinal);
	if (err) {
		log_warn(lg, "Cannot finalize SOP journal, err=%d", err);
	} else
		ccow_lookup_release(itfinal);
	j_iter = NULL;
}

static void
namedput_journal_cancel(ccow_completion_t j_inprog)
{
	log_trace(lg, "cancel %p", j_inprog);
	int err = ccow_cancel(j_inprog);
	if (err) {
		log_warn(lg, "Cannot cancel SOP journal, err=%d", err);
	}
}

static int
namedput_journal_open(struct repdev *dev, ccow_t tc, char *nhidstr, char *cid, size_t cid_size,
    char *tid, size_t tid_size, char *bid, size_t bid_size,
    char *oid, size_t oid_size, ccow_completion_t c_inprog, ccow_lookup_t iter,
    ccow_completion_t *j_inprog, ccow_lookup_t *j_iter, int *flushed)
{
	int err;

	/*
	 * open shard journal stream completion
	 */
	char j_oid[2048];
	sprintf(j_oid, "%s.%s", oid, nhidstr);

	*flushed = 0;

_reopen:;

	ccow_completion_t jc = NULL;
	ccow_lookup_t ji = NULL;
	uint64_t jgenid = 0;

	err = ccow_admin_pseudo_create_stream_completion(tc,
		NULL, NULL, DEV_SOPS_BATCH + 10, &jc,
		cid, cid_size, tid, tid_size,
		bid, bid_size, j_oid, strlen(j_oid) + 1, &jgenid, NULL, &ji);
	if (err) {
		return err;
	}

	/* list journals suppose to be local */
	((struct ccow_completion *)jc)->init_op->namedput_io->attributes |= RD_ATTR_NO_TRLOG;

	log_trace(lg, "opened %s/%s/%s/%s, genid=%ld", cid, tid, bid, j_oid, jgenid);

	/* marker is set, to ensure guaranteed crash recovery */
	uint16_t marker = 1;
	err = ccow_attr_modify_default(jc, CCOW_ATTR_BTREE_MARKER,
	    (void *)&marker, NULL);
	if (err) {
		if (ji)
			ccow_lookup_release(ji);
		ccow_drop(jc);
		return err;
	}

	/* for minimal zero block, so that it will form VM modification as we
	 * add records to journal */
	uint32_t bs = 4096;
	err = ccow_attr_modify_default(jc, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, NULL);
	if (err) {
		if (ji)
			ccow_lookup_release(ji);
		ccow_drop(jc);
		return err;
	}

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	uint64_t added = 0;
	uint64_t rec_count = 0;
	struct ccow_metadata_kv *data[DEV_SOPS_BATCH + 10];
	while ((kv = ccow_lookup_iter(ji, CCOW_MDTYPE_CUSTOM, pos++))) {
		if (memcmp_quick(kv->key, kv->key_size, X_KEY_COUNT, sizeof(X_KEY_COUNT)) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &rec_count);
		/* format: X-data-###-NUMBER */
		} else if (memcmp_safe(kv->key, kv->key_size, X_KEY_DATA, sizeof(X_KEY_DATA)-1) == 0) {
			int i = atoi(kv->key + sizeof(X_KEY_DATA)+3);
			data[i] = kv;
			added++;

			/* corner case: journal has more entries then we
			 * can process. Adjust rec_count and flush what we can. */
			if (added >= DEV_SOPS_BATCH) {
				rec_count = added;
				break;
			}
		}
	}

	if (!rec_count) {
		/* opened, no records to recover */
		*j_iter = ji;
		*j_inprog = jc;
		return 0;
	}

	log_trace(lg, "in recovery %s/%s/%s/%s, rec_count=%ld, genid=%ld", cid,
	    tid, bid, j_oid, rec_count, jgenid);

	if (added == rec_count) {
		int index = 0;
		for (uint64_t i = 0; i < rec_count; i++) {
			/* recover record */
			struct ccow_metadata_kv *kv = data[i];
			char key[32];
			strncpy(key, kv->key, kv->key_size);
			*(key + sizeof(X_KEY_DATA) + 2) = 0;
			char *minor_str = key + sizeof(X_KEY_DATA) - 1;
			int minor = atoi(minor_str);
			if (isAttrib(minor)) {
				err = namedput_attrib_exec(dev,
				    (uint8_t*)kv->value, kv->value_size,
				    tc, c_inprog, &index, iter);
			} else {
				err = namedput_list_exec(dev,
				    (uint8_t*)kv->value, kv->value_size,
				    tc, c_inprog, &index);
			}

			if (err != -EEXIST && err != -ENOENT)
				break;
		}
	} else {
		log_error(lg, "Cannot recover list from journal %s/%s/%s/%s, rec_count=%ld, actual=%ld",
		    cid, tid, bid, j_oid, rec_count, added);
		rec_count = 0;
	}

	/* close and delete all custom metadata */
	namedput_journal_close(jc, ji);

	*flushed = rec_count;

	if (rec_count)
		log_notice(lg, "Dev(%s): SOP list %s/%s/%s/%s recovered, flushed %ld records",
		    dev->name, cid, tid, bid, oid, rec_count);

	goto _reopen;
}

static int
namedput_journal_add(ccow_completion_t j_inprog, ccow_lookup_t j_iter,
    int minor, uint8_t *data, int size, uint64_t *j_count)
{
	/* Set X-data */
	char k[32];
	sprintf(k, "%s%03d-%ld", X_KEY_DATA, minor, *j_count);
	int err = ccow_attr_modify_custom(j_inprog, CCOW_KVTYPE_RAW, k, strlen(k) + 1,
	    data, size, j_iter);
	if (err)
		return err;

	/* Update X-count */
	(*j_count)++;
	err = ccow_attr_modify_custom(j_inprog, CCOW_KVTYPE_UINT64,
	    X_KEY_COUNT, sizeof(X_KEY_COUNT), j_count, sizeof(uint64_t), j_iter);
	if (err)
		return err;

	log_debug(lg, "added %s %ld, k=%s, lp %p", X_KEY_COUNT, *j_count, k, j_iter);

	/* Write zero block to issue VM marker. This will only modify Version
	 * Manifest and will not actually do I/O other then in-memory update. */
	int idx = 0;
	char b[4096] = { 0 };
	struct iovec iov = { .iov_base = &b[0], .iov_len = 4096 };
	err = ccow_put_cont(j_inprog, &iov, 1, 0, 1, &idx);
	if (err)
		return err;
	err = ccow_wait(j_inprog, idx);
	return err;
}

static void
namedput_list_run(void *arg) {
	int err = 0;
	sop_list_t *sop_list = arg;

	pthread_mutex_lock(sop_list->run_lock);

	struct repdev *dev = sop_list->dev;


	char nhidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(&sop_list->nhid, nhidstr, UINT512_BYTES * 2 + 1);
	nhidstr[16] = 0;

	uint32_t th = (uint32_t)pthread_self();

	log_debug(lg, "Got SOP %p run lock %s, nhid: %s th: %u running: %d\n", sop_list,  dev->name, nhidstr, th, sop_list->running);

	if (lfqueue_length(sop_list->list_q) == 0) {
		log_debug(lg, "No more SOP1, released lock %s, nhid: %s\n", dev->name, nhidstr);
		pthread_mutex_unlock(sop_list->run_lock);
		return;
	}

	ccow_t tc = reptrans_get_tenant_context(dev->rt, sop_list->nhid.u.u.u);
	if (!tc) {
		err = RT_ERR_NO_RESOURCES;
		log_error(lg, "%s Exec batch could not get tenant context, err: %d", dev->name, err);
		pthread_mutex_unlock(sop_list->run_lock);
		return;
	}

	struct repwqe *wqe;

	int count = 0;
	uint8_t major, minor;
	int err_one = 0;
	char cid[REPLICAST_STR_MAXLEN + 1]; size_t cid_size;
	char tid[REPLICAST_STR_MAXLEN + 1]; size_t tid_size;
	char bid[REPLICAST_STR_MAXLEN + 1]; size_t bid_size;
	char oid[REPLICAST_STR_MAXLEN + 1]; size_t oid_size;


	int flags = 0;
	int index = 0;
	int need_finalize = 0;
	ccow_completion_t c_inprog = NULL, j_inprog = NULL;
	ccow_lookup_t iter = NULL, j_iter = NULL;
	uint64_t j_count = 0;

	uint64_t last_update_time = get_timestamp_us();
	uint64_t delay;
	while (count < DEV_SOPS_BATCH) {
		delay = (get_timestamp_us() - last_update_time);
		if (delay >= FINAL_DELAY) {
			break;
		}

		/* break out and finalize on split if c_inprog */
		int fh_inprog = 0;
		SERVER_FLEXHASH_SAFE_CALL(fh_inprog =
		    flexhash_rebuild_inprogress(SERVER_FLEXHASH), FH_LOCK_READ);
		if (fh_inprog || dev->terminating) {
			/* best effort:
			 * drain the queue so that clients would re-send SOP update  */
			log_warn(lg, "Dev(%s) List batch interrupted due to split or termination", dev->name);
			while ((wqe = lfqueue_dequeue(sop_list->list_q))) {
				namedput_srv_done_wqe(dev, wqe, RT_ERR_NO_RESOURCES, 0);
			}
			break;
		}

		wqe = lfqueue_dequeue(sop_list->list_q);
		if (!wqe) {
			usleep(10);
			continue;
		}

		struct repmsg_rendezvous_transfer *msg =
			(struct repmsg_rendezvous_transfer *)wqe->msg;

		err_one = decode_operation(wqe, &major, &minor,
				cid, &cid_size,
				tid, &tid_size,
				bid, &bid_size,
				oid, &oid_size);

		if (err_one) {
			log_error(lg, "Dev(%s) List batch decode error: %d", dev->name, err_one);
		}

		if (count == 0) {

			// just flush, complete immediately avoiding any extra I/O
			if (isFlush(minor)) {
				namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), sop_list->genid);
				need_finalize = 0;
				break;
			}

			sop_list->genid = 0;
			err = ccow_admin_pseudo_create_stream_completion(tc,
				NULL, NULL, DEV_SOPS_BATCH + 10, &c_inprog,
				cid, cid_size,
				tid, tid_size,
				bid, bid_size,
				oid, oid_size, &sop_list->genid, &flags, &iter);
			if (err) {
				log_error(lg, "Dev(%s) List batch create stream error: %d", dev->name, err);
				namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), 0);
				break;
			}
			log_debug(lg, "Dev(%s) SOP oid: %s, flags: %d", dev->name, oid, flags);

			if (!(flags & CCOW_CONT_F_EXIST)) {
				err = ccow_attr_modify_default(c_inprog, CCOW_ATTR_CHUNKMAP_TYPE,
				    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
				if (err) {
					c_inprog = NULL;
					log_error(lg, "Dev(%s) List batch create error1: %d", dev->name, err);
					namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), 0);
					break;
				}
				ccow_lookup_t itfinal;
				err = ccow_finalize(c_inprog, &itfinal);
				if (err) {
					log_error(lg, "Dev(%s) List batch create error2: %d", dev->name, err);
					namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), 0);
					break;
				}
				ccow_lookup_release(itfinal);

				log_debug(lg, "Dev(%s) SOP bid/oid: %s/%s created", dev->name, bid, oid);

				iter = NULL;
				c_inprog = NULL;
				index = 0;
				flags = 0;
				sop_list->genid = 0;

				err = ccow_admin_pseudo_create_stream_completion(tc,
					NULL, NULL, DEV_SOPS_BATCH + 10, &c_inprog,
					cid, cid_size,
					tid, tid_size,
					bid, bid_size,
					oid, oid_size, &sop_list->genid, &flags, &iter);
				if (err) {
					log_error(lg, "Dev(%s) List batch create stream error: %d", dev->name, err);
					namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), 0);
					break;
				}
			}

			// Initialize journal for eventual ops only
			if (isDelay(msg)) {
				int flushed = 0;
				err = namedput_journal_open(dev, tc, nhidstr,
					cid, cid_size,
					tid, tid_size,
					bid, bid_size,
					oid, oid_size, c_inprog, iter, &j_inprog,
					&j_iter, &flushed);
				if (err) {
					ccow_cancel(c_inprog);
					c_inprog = NULL;
					iter = NULL;
					log_error(lg, "Dev(%s) List batch recovery stream error: %d", dev->name, err);
					namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), 0);
					break;
				}
				log_debug(lg, "Dev(%s) SOP flushed: %d", dev->name, flushed);

				if (flushed) {
					// re-open
					ccow_lookup_t itfinal;
					err = ccow_finalize(c_inprog, &itfinal);
					if (err) {
						log_error(lg, "Dev(%s) List batch stream recovery error: %d", dev->name, err);
						namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), 0);
						break;
					}
					ccow_lookup_release(itfinal);

					c_inprog = NULL;
					iter = NULL;
					index = 0;
					flags = 0;
					sop_list->genid = 0;

					err = ccow_admin_pseudo_create_stream_completion(tc,
						NULL, NULL, DEV_SOPS_BATCH + 10, &c_inprog,
						cid, cid_size,
						tid, tid_size,
						bid, bid_size,
						oid, oid_size, &sop_list->genid, &flags, &iter);
					log_debug(lg, "Dev(%s) SOP new completion: %p", dev->name, c_inprog);
					if (err) {
						log_error(lg, "Dev(%s) List batch re-create stream error: %d", dev->name, err);
						namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), 0);
						break;
					}
				}
			}
		}
		log_debug(lg, "Dev(%s) SOP count: %d, genid: %lu", dev->name, count, sop_list->genid);
		count++;
		if (!err_one) {
			if (isAttrib(minor)) {
				err_one = namedput_attrib_exec_wqe(wqe, tc, c_inprog, &index, iter);
			} else if (isList(minor)) {
				err_one = namedput_list_exec_wqe(wqe, tc, c_inprog, &index);
			}
		}

		if (!isDelay(msg) || isFlush(minor)) { // no delay or flush operation
			// finalize
			if (c_inprog) {
				ccow_lookup_t itfinal;
				err = ccow_finalize(c_inprog, &itfinal);
				if (!err)
					ccow_lookup_release(itfinal);
				iter = NULL;
				c_inprog = NULL;
				log_debug(lg, "Dev(%s) SOP finalize oid: %s, flush: %d, genid: %lu", dev->name, oid, isFlush(minor), sop_list->genid);
				if (j_inprog) {
					if (err)
						namedput_journal_cancel(j_inprog);
					else
						namedput_journal_close(j_inprog, j_iter);
				}
			}
			namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), sop_list->genid);
			need_finalize = 0;
			break;
		}

		need_finalize = 1;

		if (!err_one) {
			err_one = namedput_journal_add(j_inprog, j_iter, minor,
			    repwqe_payload(wqe), msg->content_length, &j_count);
		}

		namedput_srv_done_wqe(dev, wqe, (err ? err : err_one), sop_list->genid);
		last_update_time = get_timestamp_us();
	} // while

	log_debug(lg, "Dev(%s) Break list loop delay: %lu, count: %d", dev->name, delay, count);

	if (need_finalize) { // delayed finalize/cancel
		if (c_inprog) {
			ccow_lookup_t itfinal;
			err = ccow_finalize(c_inprog, &itfinal);
			if (!err)
				ccow_lookup_release(itfinal);
			iter = NULL;
			log_debug(lg, "Dev(%s) List batch finalize oid: %s, genid: %lu", dev->name, oid, sop_list->genid);

			if (j_inprog) {
				if (err)
					namedput_journal_cancel(j_inprog);
				else
					namedput_journal_close(j_inprog, j_iter);
			}
		}
	}
	if (iter)
		ccow_lookup_release(iter);

	reptrans_put_tenant_context(dev->rt, tc);

	log_debug(lg, "Finished SOP2 %p, released lock %s, nhid: %s\n",sop_list, dev->name, nhidstr);
	pthread_mutex_unlock(sop_list->run_lock);
}

static void
namedput_list_done(void *arg, int status) {
	sop_list_t *sop_list = arg;

	struct repdev *dev = sop_list->dev;

	log_debug(lg, "Dev(%s) Done SOP3 %p, running: %d\n", dev->name, sop_list, sop_list->running);

	char nhidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(&sop_list->nhid, nhidstr, UINT512_BYTES * 2 + 1);
	nhidstr[16] = 0;

	sop_list->running--;

	if (lfqueue_length(sop_list->list_q) > 0) {
		log_debug(lg, "Dev(%s) Restart SOP %p work, more items in the list %s\n", dev->name, sop_list, nhidstr);
		sop_list->running++;
		ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, namedput_list_run,
			namedput_list_done, sop_list);
	}

}

static int
schedule_list_item(struct repwqe *wqe, msgpack_u *u)
{
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repmsg_named_chunk_put_proposal *msg_pp =
		(struct repmsg_named_chunk_put_proposal *) req->msg_pp;
	struct replicast_object_name *ron = &msg_pp->object_name;
	int empty_index = -1;
	uint8_t i;
	int err;

	nassert(dev->loop_thrid == uv_thread_self());

	/*
	 * Consumer-producer is implementated in a different way.
	 * The difference from classical implementation is that we
	 * don't wait. If we have to wait then we return protocol error.
	 * We do this to avoid protocol complications.
	 */
	uint512_t *nhid = &ron->name_hash_id;
	char nhidstr[UINT512_BYTES * 2 + 1];
	uint512_dump(nhid, nhidstr, UINT512_BYTES * 2 + 1);
	nhidstr[16] = 0;

	size_t ent_size;
	sop_list_t *sop_list;

	pthread_mutex_lock(&dev->sop_queues->ht_lock);
	int qlen = 0;
	sop_list = hashtable_get(dev->sop_queues->ht, (void *)nhid, UINT512_BYTES, &ent_size);
	if (sop_list) {
		log_debug(lg, "Dev(%s) Adding to SOP list %p, %s\n", dev->name, sop_list, nhidstr);
	} else { /* Create serial operations list */
		if (hashtable_size(dev->sop_queues->ht) > DEV_MAX_SOPS) {
			pthread_mutex_unlock(&dev->sop_queues->ht_lock);
			log_error(lg, "SOP queue full for %s", dev->name);
			putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES,
							  RT_ACCEPT_NOT_NOW);
			return -EBUSY;
		}

		sop_list = sop_list_init(nhid, dev);
		log_debug(lg, "Dev(%s) Created SOP list %p, %s\n", dev->name, sop_list, nhidstr);
		if (!sop_list) {
			pthread_mutex_unlock(&dev->sop_queues->ht_lock);
			log_error(lg, "Dev(%s) No resources for scheduling SOP operation", dev->name);
			putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES,
							  RT_ACCEPT_NOT_NOW);
			return -EAGAIN;
		}
		// Add list to hash
		int err = hashtable_put(dev->sop_queues->ht, &sop_list->nhid, UINT512_BYTES,
				sop_list, sizeof(sop_list_t));
		if (err) {
			pthread_mutex_unlock(&dev->sop_queues->ht_lock);
			log_error(lg, "Dev(%s) No resources for scheduling SOP operation for", dev->name);
			putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES,
							  RT_ACCEPT_NOT_NOW);
			return -EAGAIN;
		}
	}
	qlen++;
	lfqueue_enqueue(sop_list->list_q, wqe);

	if (!sop_list->running) {
		log_debug(lg, "Dev(%s) New SOP work, %s\n", dev->name, nhidstr);
		sop_list->running++;
		ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_HI, namedput_list_run,
			namedput_list_done, sop_list);
	}

	// Cleanup empty slots
	unsigned int key_count = 0;
	void **keys = (void **) hashtable_keys(dev->sop_queues->ht, &key_count);
	sop_list_t *slist;
	for (unsigned int i = 0; i < key_count; i++) {
		slist = hashtable_get(dev->sop_queues->ht, keys[i], UINT512_BYTES, &ent_size);

		if (memcmp(&slist->nhid, &sop_list->nhid, UINT512_BYTES) == 0)
			continue;

		if (lfqueue_length(slist->list_q) > 0)
			continue;


		uint512_dump(&slist->nhid, nhidstr, UINT512_BYTES * 2 + 1);
		nhidstr[16] = 0;

		if (slist->running == 0) {
			log_debug(lg, "Dev(%s) Remove empty SOP nhid: %s running: %d\n", dev->name, nhidstr, slist->running);
			hashtable_remove(dev->sop_queues->ht, &slist->nhid, UINT512_BYTES);
			sop_list_destroy(slist);
		}
	}
	if (keys)
		je_free(keys);
	pthread_mutex_unlock(&dev->sop_queues->ht_lock);

	return 0;
}


int
namedput_schedule_serial_op(struct repwqe *wqe, uv_buf_t *buf)
{
	struct repctx *ctx = wqe->ctx;
	struct state *st = ctx->state;
	struct putcommon_srv_req *req = st->data;
	schedule sop;
	struct repdev *dev = req->dev;
	int err;
	uint8_t major, minor, schedule, block;
	char cid[REPLICAST_STR_MAXLEN + 1]; size_t cid_size;
	char tid[REPLICAST_STR_MAXLEN + 1]; size_t tid_size;
	char bid[REPLICAST_STR_MAXLEN + 1]; size_t bid_size;
	char oid[REPLICAST_STR_MAXLEN + 1]; size_t oid_size;
	uint32_t iov_cnt;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE) {
		log_warn(lg, "Disk SOP migrating, canceling scheduling");
		putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES,
						  RT_ACCEPT_NOT_NOW);
		return -EBUSY;
	}

	/* Prepare to unpack the payload */
	msgpack_u *u = msgpack_unpack_init(buf->base, buf->len, 0);
	if (!u) {
		putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES, RT_ERROR);
		return -ENOMEM;
	}

	err = decode_operation(wqe, &major, &minor,
			cid, &cid_size,
			tid, &tid_size,
			bid, &bid_size,
			oid, &oid_size);

	if (err) {
		log_error(lg, "st: %p unable to decode serial op", st);
		msgpack_unpack_free(u);
		putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES, RT_ERROR);
		return err;
	}

	/* Get serial op object of a given type */
	sop = get_sop_item(major, minor);
	if (!sop) {
		log_error(lg, "Dev(%s) st: %p incorrect serial opcodes major: %u minor: %u",
				dev->name, st, major, minor);
		msgpack_unpack_free(u);
		putcommon_srv_set_req_status(req, RT_ERR_NO_RESOURCES, RT_ERROR);
		return -EINVAL;
	}

	/* Schedule the serial operation */
	err = sop(wqe, u);
	if (err)
		req->serial_err = 1;

	msgpack_unpack_free(u);
	return err;
}
