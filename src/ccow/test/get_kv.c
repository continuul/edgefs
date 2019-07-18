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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"

#define GET_FILE_CLUSTER	""
#define GET_FILE_TENANT		""
#define GET_FILE_BUCKET		""
#define GET_FILE_OID		""
#define GET_FILE_BS		4096
#define GET_FILE_BTREE_ORDER	16
#define GET_FILE_PATH		"/tmp/file-kv.read"

size_t block_size = GET_FILE_BS;
off_t object_size = GET_FILE_BS * GET_FILE_BTREE_ORDER;
int btree_order = GET_FILE_BTREE_ORDER;
char *cluster_name = GET_FILE_CLUSTER;
char *tenant_name = GET_FILE_TENANT;
char *bucket_name = GET_FILE_BUCKET;
char *object_name = GET_FILE_OID;
char *file_path = GET_FILE_PATH;
ccow_t cl = NULL;

int dd = 0;
int ec_encode = 0;
char *TEST_ENV = NULL;

extern int errno;

static void
libccowd_setup(void **state)
{
    if(!dd) {
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
	je_free(buf);
}

static void
simple_get_file(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int ccow_fd = open(path, O_RDONLY);
	if (ccow_fd < 0) {
		printf("ccow.json open error %d: %s\n",
			-errno, strerror(errno));
	}
	assert_true(ccow_fd >= 0);

	char buf[16384];
	int err = read(ccow_fd, buf, 16383);
	if (err < 0) {
		printf("ccow.json read error %d: %s\n",
			-errno, strerror(errno));
		close(ccow_fd);
	}
	assert_true(err >= 0);
	close(ccow_fd);
	buf[err] = 0;
	printf("cluster name: %s, tenant name: %s\n",
		cluster_name, tenant_name);
	err = ccow_admin_init(buf, cluster_name, strlen(cluster_name) + 1, &cl);
	if (err) {
		printf("ccow_tenant_init error: %d\n", err);
	}
	assert_int_equal(err, 0);
	assert_non_null(cl);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		printf("ccow_create_completion error: %d\n", err);
	}
	assert_int_equal(err, 0);

	printf("%s/%s/%s/%s\n", cluster_name, tenant_name, bucket_name, object_name);
	ccow_lookup_t iter;
	struct iovec iov = { .iov_base = "", .iov_len = 1 };
        err = ccow_admin_pseudo_get(cluster_name, strlen(cluster_name) + 1,
	    tenant_name, strlen(tenant_name) + 1,
	    bucket_name, strlen(bucket_name) + 1, object_name,
	    strlen(object_name) + 1, &iov, 1, 10000, CCOW_GET_LIST, c, &iter);
	if (err) {
		ccow_release(c);
		printf("ccow_get error: %d\n", err);
	}
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	if (err) {
		printf("ccow_wait error: %d\n", err);
	}
	assert_int_equal(err, 0);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
	ccow_lookup_release(iter);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
    if(!dd) {
        ccow_daemon_term();
    }
}

static void
usage(const char *argv0)
{
	printf(	"\n"
		"USAGE:\n"
		"	%s [-h] [-n] [-b block_size] [-o obj_name]\n"
		"		[-B bucket_name] [-c cluster_name] "
		"[-t tenant_name] [file_path]\n"
		"\n"
		"	-h	Display this message and exit\n"
		"\n"
		"	-n	Do not start daemon\n"
		"\n"
		"	-b	Specify block size in form of "
		"\"[0-9]+[GgMmKkBb]?\"\n"
		"\n"
		"	-o	Specify object name\n"
		"\n"
		"	-B	Specify bucket name\n"
		"\n"
		"	-c	Specify cluster name\n"
		"\n"
		"	-t	Specify tenant name\n"
		"\n", argv0);

	exit(EXIT_SUCCESS);
}

int
main(int argc, char *argv[])
{
	/*
	 * Parse command line
	 */
	int opt;

	while ((opt = getopt(argc, argv, "hno:B:c:t:")) != -1) {
		switch(opt) {
			case 'n':
				dd = 1;
				break;

			case 'o':
				object_name = strdup(optarg);
				break;

			case 'B':
				bucket_name = strdup(optarg);
				break;

			case 'c':
				cluster_name = strdup(optarg);
				break;

			case 't':
				tenant_name = strdup(optarg);
				break;

			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}
	if (optind < argc)
		file_path = argv[optind];

	const UnitTest get_tests[] = {
		unit_test(libccowd_setup),
		unit_test(simple_get_file),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(get_tests);
}

