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
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>

#include "ccowutil.h"
#include "auditc.h"
#include "common.h"

#define IPC_ADDRESS	"ipc://%s/var/run/auditd-test.ipc"
#define PUB_ADDRESS	"tcp://127.0.0.1:10395"
Logger lg;

int main(void)
{
	lg = Logger_create("auditc_test");

	int sub_fd = nn_socket(AF_SP, NN_SUB);
	if (sub_fd < 0) {
		log_error(lg, "socket create error: %s [%d]",
		    strerror(errno), (int)errno);
		return -1;
	}

	char *topic = "counts.count1";
	int rc = nn_setsockopt(sub_fd, NN_SUB, NN_SUB_SUBSCRIBE, topic, strlen(topic));
	if (rc < 0) {
		nn_close(sub_fd);
		log_error(lg, "setsockopt error: %s [%d]",
		    strerror(errno), (int)errno);
		return -1;
	}

	rc = nn_connect(sub_fd, PUB_ADDRESS);
	if(rc < 0) {
		nn_close(sub_fd);
		log_error(lg, "failed connect to \"%s\": %s [%d]", PUB_ADDRESS,
		    strerror(errno), (int)errno);
		return -1;
	}

	int sub2_fd = nn_socket(AF_SP, NN_SUB);
	if (sub2_fd < 0) {
		log_error(lg, "socket create error: %s [%d]",
		    strerror(errno), (int)errno);
		return -1;
	}

	/* we can subscribe after the connect! */

	topic = "timers.mynamespace.request.p95";
	rc = nn_setsockopt(sub2_fd, NN_SUB, NN_SUB_SUBSCRIBE, topic, strlen(topic));
	if (rc < 0) {
		nn_close(sub2_fd);
		log_error(lg, "setsockopt error: %s [%d]",
		    strerror(errno), (int)errno);
		return -1;
	}

	rc = nn_connect(sub2_fd, PUB_ADDRESS);
	if(rc < 0) {
		nn_close(sub2_fd);
		log_error(lg, "failed connect to \"%s\": %s [%d]", PUB_ADDRESS,
		    strerror(errno), (int)errno);
		return -1;
	}

	auditc_link *link, *link2;
	link = auditc_init("127.0.0.1", 8125);
	sleep(1);
	printf("auditc_init success\n");

	char path[PATH_MAX];
	snprintf(path, sizeof(path), IPC_ADDRESS, nedge_path());
	link2 = auditc_init_with_namespace(path, 0, "mynamespace");
	sleep(1);
	printf("auditc_init_with_namespace success\n");

	auditc_count(link, "count1", 123, 1.0);
	auditc_count(link, "count2", 125, 1.0);
	auditc_gauge(link, "speed", 10);
	auditc_timer(link2, "request", 2400);
	auditc_set(link2, "bk1.create", "obj4");
	auditc_set(link2, "bk1.create", "obj5");
	auditc_set(link2, "bk1.create", "obj6");
	auditc_kv(link2, "bk1", 1);
	auditc_kv(link2, "bk1", 2);
	auditc_kv(link2, "bk2", 3);
	auditc_kv(link2, "bk3", 3);
	auditc_inc(link, "bk1.obj1", 1.0);
	auditc_dec(link, "bk1.obj1", 1.0);
	auditc_inc(link, "count1", 1.0);
	auditc_inc(link, "count1", 1.0);
	auditc_dec(link2, "count2", 1.0);
	int i;
	for(i=0; i<10; i++) {
		auditc_count(link2, "count3", i, 0.8);
	}
	printf("pushed various metrices\n");

#define NUM_SENDS	10000
	uint64_t before, after;
	before = uv_hrtime();
	for (i = 0; i < NUM_SENDS; i++) {
		auditc_count(link, "count1", 123, 1.0);
	}
	printf("pushed %d counters via UDP\n", NUM_SENDS);
	after = uv_hrtime();

	printf("%s stats (UDP): %.2fs (%s/s)\n", fmt(1.0 * NUM_SENDS),
	    (after - before) / 1e9,
	    fmt((1.0 * NUM_SENDS) / ((after - before) / 1e9)));
	fflush(stdout);

	before = uv_hrtime();
	for (i = 0; i < NUM_SENDS; i++) {
		auditc_count(link, "count1", 123, 1.0);
	}
	printf("pushed %d counters via IPC\n", NUM_SENDS);
	after = uv_hrtime();

	printf("%s stats (IPC): %.2fs (%s/s)\n", fmt(1.0 * NUM_SENDS),
	    (after - before) / 1e9,
	    fmt((1.0 * NUM_SENDS) / ((after - before) / 1e9)));
	fflush(stdout);

	auditc_flush(link);
	auditc_flush(link2);

	auditc_finalize(link);
	auditc_finalize(link2);

	char buf[1024];
	rc = nn_recv(sub_fd, buf, 1024, 0);
	if(rc < 0) {
		nn_close(sub_fd);
		log_error(lg, "failed recv from \"%s\": %s [%d]", PUB_ADDRESS,
		    strerror(errno), (int)errno);
		return -1;
	}
	printf("received %d bytes\n", rc);

	/* we can unsubscribe */

	rc = nn_setsockopt(sub_fd, NN_SUB, NN_SUB_UNSUBSCRIBE, topic, strlen(topic));
	if (rc < 0) {
		nn_close(sub_fd);
		log_error(lg, "setsockopt error: %s [%d]",
		    strerror(errno), (int)errno);
		return -1;
	}
	printf("unsubscribed successfully\n");

	nn_close(sub_fd);
	nn_close(sub2_fd);

	return 0;
}
