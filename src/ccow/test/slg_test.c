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

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow-impl.h"
#include "ccowd.h"
#include "server-list.h"

static ccow_t cl = NULL;
static ccow_t cx = NULL;
static ccow_t cy = NULL;

int dd = 0;
uint32_t num_servers = 10;
uint32_t num_disks = 30;
uint32_t loop = 0;

static void
libccowd_setup(void **state)
{
    if(!dd){
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
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cx), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cy), 0);
	je_free(buf);
}

static void
slg_verify_nodes(struct flexhash *fh1, struct flexhash *fh2)
{
	assert_int_equal(fh1->servercount, fh2->servercount);
	assert_int_equal(fh1->serverlist->nr_vdevs, fh2->serverlist->nr_vdevs);

	// Verify serverids and fhdevs
	struct fhserver *s1, *s2;
	struct fhdev *fd1, *fd2;
	s1 = fh1->serverlist;
	s2 = fh2->serverlist;

	while (s1) {
		assert_memory_equal(&s1->id, &s2->id, sizeof(uint128_t));

		fd1 = s1->vdevlist.devlist;
		fd2 = s2->vdevlist.devlist;

		while(fd1) {
			assert_memory_equal(&fd1->vdev->vdevid,
			    &fd2->vdev->vdevid, sizeof(uint128_t));
			fd1 = fd1->next;
			fd2 = fd2->next;
		}

		assert_int_equal(fd2, 0);

		s1 = s1->next;
		s2 = s2->next;
	}

	assert_int_equal(s2, 0);

	// Verify vdevids in vdevstore
	struct vdevstore *v1, *v2;
	v1 = fh1->vdevstore;
	v2 = fh2->vdevstore;

	assert_int_equal(v1->lvdevcount, v2->lvdevcount);
	for(int k = 0; k < v1->lvdevcount; k++)
		assert_memory_equal(&v1->lvdevlist[k].vdevid,
		    &v2->lvdevlist[k].vdevid, sizeof(uint128_t));

	// Verify hashcounts
	v1 = fh1->vdevstore;
	v2 = fh2->vdevstore;

	assert_int_equal(v1->lvdevcount, v2->lvdevcount);
	for(int k = 0; k < v1->lvdevcount; k++) {
		assert_int_equal(v1->lvdevlist[k].numrows, v2->lvdevlist[k].numrows);
		assert_memory_equal(v1->lvdevlist[k].hashcount,
		    v2->lvdevlist[k].hashcount, v1->lvdevlist[k].numrows);
	}
}

static void
slg_request(ccow_t tc, uint32_t flags)
{
	struct ccow_completion *c;
	int err;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = server_list_get_init(tc->netobj, c, uint128_null, 0, flags);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
}

static void
slg_one(ccow_t tc1, ccow_t tc2, uint32_t nr_nodes, uint32_t nr_disks)
{
	struct flexhash *fh1, *fh2;
	uint32_t flags;

	printf("Nodes/Disks Request %u/%u ", nr_nodes, nr_disks);
	flags = SLG_SENDER_DEBUG | (nr_nodes << 10) | (nr_disks << 22);

	slg_request(tc1, flags);
	fh1 = (struct flexhash *) tc1->flexhash;
	printf("Received1 %u/%u ", fh1->servercount, fh1->serverlist->nr_vdevs);

	slg_request(tc2, flags);
	fh2 = (struct flexhash *) tc2->flexhash;
	printf("Received2 %u/%u .. ", fh2->servercount, fh2->serverlist->nr_vdevs);

	slg_verify_nodes(fh1, fh2);
	printf("Verified!\n");
}

static void
slg_test(void **state)
{
	uint32_t n, d, interval;
	assert_non_null(cx);
	assert_non_null(cy);

	interval = (num_disks > 30) ? 3 : 1;

	if (loop)
		for (n = 1; n <= num_servers; n++)
			for (d = 3; d <= num_disks; d += interval)
				slg_one(cx, cy, n ,d);
	else
		slg_one(cx, cy, num_servers, num_disks);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
	assert_non_null(cx);
	ccow_tenant_term(cx);
	assert_non_null(cy);
	ccow_tenant_term(cy);
}

static void
libccowd_teardown(void **state)
{
    if(!dd)
	    ccow_daemon_term();
}

static void
usage()
{
	printf("USAGE: ./slg_test [-n] [-s num_servers] [-d disks_per_server] [-l]\n");
}

int
main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "hns:d:l")) != -1) {
		switch(opt) {
		case 'n':
			dd = 1;
			break;
		case 's':
			num_servers = (uint32_t) atoi(optarg);
			break;
		case 'd':
			num_disks = (uint32_t) atoi(optarg);
			break;
		case 'l':
			loop = 1;
			break;
		case 'h':
			usage();
			exit(0);
		}
	}

	if ((num_servers > FLEXHASH_MAX_SERVERS) ||
	    ((num_disks * num_servers) > FLEXHASH_MAX_VDEVS)) {
		printf("Invalid input. Max servers %u. Max devices %u.",
		    FLEXHASH_MAX_SERVERS, FLEXHASH_MAX_VDEVS);
		exit(1);
	}

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(slg_test),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

