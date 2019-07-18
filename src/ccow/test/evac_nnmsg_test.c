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
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"
#include "ccowd-impl.h"
#include "ccow-impl.h"

ccow_t tc = NULL;
int dd = 0;

static void
libccowd_setup(void **state)
{
    if (!dd) {
        assert_int_equal(ccow_daemon_init(NULL), 0);
        usleep(2 * 1000000L);
    }
}

static void
libccow_setup(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);
	je_free(buf);
}

static void
test_evac_msg(void **state)
{
	int sock;
	int err;
	char cmd[256];
	char vdevstr[64];
	evac_msg_hdr_t evac_hdr;
	char evac_msg[MAX_EVAC_MSG];
	struct nn_msghdr nn_hdr;
	struct nn_iovec iov[2];

	sock = nn_socket(AF_SP, NN_REQ);
	assert(sock >= 0);

	err = nn_connect(sock, CCOWD_IPC_ADDRESS);
	assert(err >= 0);

	memset(&evac_hdr, 0, sizeof(evac_hdr));
	evac_hdr.em_proto_ver = EM_PROTO_VER;
	evac_hdr.em_op = EM_ROW_STATUS_REQ;
	evac_hdr.em_src_devid = CLIENT_FLEXHASH->vdevstore->lvdevlist[0].vdevid;
	/* TODO - fill ip addresses */

	uint128_dump(&evac_hdr.em_src_devid, vdevstr, 64);
	printf("Testing evac opcode %d for device %s\n", evac_hdr.em_op, vdevstr);
	nn_send (sock, &evac_hdr, sizeof(evac_hdr), 0);

	char *buf = NULL;
	memset(&nn_hdr, 0, sizeof(nn_hdr));
	memset(&evac_hdr, 0, sizeof(evac_hdr));
	iov[0].iov_base = &evac_hdr;
	iov[0].iov_len = sizeof(evac_hdr);
	iov[1].iov_base = evac_msg;
	iov[1].iov_len = MAX_EVAC_MSG;
	nn_hdr.msg_iov = iov;
	nn_hdr.msg_iovlen = 2;

	int result = nn_recvmsg(sock, &nn_hdr, 0);
	assert_int_equal(evac_hdr.em_op, EM_ROW_STATUS_REP);
	if (result > 0) {
		printf("Received reply: \n%s\n", evac_msg);
	}
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state) {
    if(!dd) {
        assert_non_null(tc);
        ccow_daemon_term();
    }
}

int
main(int argc, char **argv)
{
    if (argc == 2) {
        if (strcmp(argv[1], "-n") == 0)
             dd = 1;
    }
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(test_evac_msg),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

