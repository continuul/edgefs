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
#include "ccow.h"
#include "ccowd.h"

#define TEST_BUCKET_NAME	"simple-get-bucket-test"
ccow_t cl = NULL;

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
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
	je_free(buf);
}

static void
bucket_create(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_create(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *		Put Test Sync, Fixedmap 3x4, bs=4k
 * =======================================================================
 */
#define SIMPLE_TEST_OID		"simple-test"
#define SIMPLE_TEST_BS		4096

static void
simple_put_0_4k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = SIMPLE_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, SIMPLE_TEST_OID, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	je_free(iov[0].iov_base);
}

static void
simple_get_0_4k(void **state)
{
	assert_non_null(cl);
	int err;
	int len = SIMPLE_TEST_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	get(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    NULL);
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
        assert_non_null(cl);
        ccow_daemon_term();
    }
}

static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID, NULL, NULL);
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
		unit_test(bucket_create),
		unit_test(simple_put_0_4k),
		unit_test(simple_get_0_4k),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

