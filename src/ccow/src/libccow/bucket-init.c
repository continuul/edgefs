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
#include <uv.h>
#include <regex.h>
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>

#include "ccowutil.h"
#include "ccow.h"
#include "auditd.h"
#include "ccow-impl.h"

static void
ccow_bucket_notified(uv_poll_t *treq, int status, int events)
{
//	printf("bucket updated!\n");
}

static int
ccow_bucket_subscribe(struct ccow_bucket *bk)
{
	int err;
	struct ccow *tc = bk->tc;

	assert(bk->sub_fd == -1);

	bk->sub_fd = nn_socket(AF_SP, NN_SUB);
	if (bk->sub_fd < 0) {
		log_error(lg, "socket create error: %s [%d]",
		    strerror(errno), (int)errno);
		return -errno;
	}

	/*
	 * Subscribe to receive bucket's parent changes
	 */
	char pub_address[INET6_ADDRSTRLEN + 10];
	sprintf(pub_address, "tcp://127.0.0.1:%d", AUDITD_PUB_PORT);

	// FIXME: calculate pub address based on NHID
	//
	// struct sockaddr_in6 send_addr;
	// flexhash_get_hashaddr(tc->flexhash, &tc->tenant_hash_id, &send_addr);
	// char dst[INET6_ADDRSTRLEN];
	// inet_ntop(AF_INET6, &send_addr.sin6_addr, dst, INET6_ADDRSTRLEN);
	// sprintf(pub_address, "tcp://[%s]:%d", dst, AUDITD_PUB_PORT);

	err = nn_connect(bk->sub_fd, pub_address);
	if(err < 0) {
		nn_close(bk->sub_fd);
		bk->sub_fd = -1;
		log_error(lg, "failed connect to \"%s\": %s [%d]", pub_address,
		    strerror(errno), (int)errno);
		return -errno;
	}

	char phid_buf[UINT512_BYTES * 2 + 1];
	memset(phid_buf, 0, UINT512_BYTES * 2 + 1);

	uint512_dump(&tc->tenant_hash_id, phid_buf, UINT512_BYTES * 2 + 1);

	char topic[AUDITD_TOPIC_MAXLEN];
	sprintf(topic, "counts.ccow.namedput.%s", phid_buf);

	err = nn_setsockopt(bk->sub_fd, NN_SUB, NN_SUB_SUBSCRIBE, topic,
	    strlen(topic));
	if (err < 0) {
		nn_close(bk->sub_fd);
		bk->sub_fd = -1;
		log_error(lg, "setsockopt subscribe error: %s [%d]",
		    strerror(errno), (int)errno);
		return -errno;
	}

	int ipc_fd;
	size_t fdsz = sizeof (ipc_fd);
	err = nn_getsockopt (bk->sub_fd, NN_SOL_SOCKET, NN_RCVFD,
	    (char *)&ipc_fd, &fdsz);
	if (err < 0) {
		nn_close(bk->sub_fd);
		bk->sub_fd = -1;
		log_error(lg, "setsockopt rcv_fd error: %s [%d]",
		    strerror(errno), (int)errno);
		return -errno;
	}

	uv_poll_init(tc->loop, &bk->sub_req, ipc_fd);
	uv_poll_start(&bk->sub_req, UV_READABLE, ccow_bucket_notified);

	log_debug(lg, "Subscribed to tenant topic: %s", topic);

	return 0;
}

static void
ccow_bucket_unsubscribe(struct ccow_bucket *bk)
{
	int err;
	struct ccow *tc = bk->tc;

	if (bk->sub_fd == -1)
		return;

	/*
	 * Unsubscribe from receiving bucket's parent changes
	 */
	char phid_buf[UINT512_BYTES * 2 + 1];
	memset(phid_buf, 0, UINT512_BYTES * 2 + 1);

	uint512_dump(&tc->tenant_hash_id, phid_buf, UINT512_BYTES * 2 + 1);

	char topic[AUDITD_TOPIC_MAXLEN];
	sprintf(topic, "counts.ccow.namedput.%s", phid_buf);

	err = nn_setsockopt(bk->sub_fd, NN_SUB, NN_SUB_UNSUBSCRIBE, topic,
	    strlen(topic));
	if (err < 0) {
		nn_close(bk->sub_fd);
		log_error(lg, "setsockopt error: %s [%d]",
		    strerror(errno), (int)errno);
		bk->sub_fd = -1;
		return;
	}

	uv_poll_stop(&bk->sub_req);
	uv_close((uv_handle_t *)&bk->sub_req, NULL);

	nn_close(bk->sub_fd);
	bk->sub_fd = -1;
}

int
ccow_bucket_init(ccow_t tctx, const char *bid, size_t bid_size,
    ccow_bucket_t *bkctx)
{
	int err;

	struct ccow_bucket *bk = je_calloc(1, sizeof (struct ccow_bucket));
	if (!bk)
		return -ENOMEM;
	bk->tc = tctx;

	/*
	* we must set bk->sub_fd to -1, because nn_socket can return 0 as normal good socket
	*/
	bk->sub_fd = -1;

	err = ccow_bucket_subscribe(bk);
	if (err) {
		je_free(bk);
		return err;
	}

	*bkctx = bk;

	return 0;
}

void
ccow_bucket_term(ccow_bucket_t bkctx)
{
	ccow_bucket_unsubscribe(bkctx);
	je_free(bkctx);
}
