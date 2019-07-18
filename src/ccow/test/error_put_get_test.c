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
#include "replicast.h"

#define TEST_BUCKET_NAME	"error-put-test-test"
ccow_t cl = NULL, tc = NULL;

int dd = 0;
char *TEST_ENV = NULL;

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
	assert_int_equal(ccow_admin_init(buf, "cltest", 7, &tc), 0);
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
#define SIMPLE_TEST_OID_CONT	"simple-test-cont"
#define SIMPLE_TEST_OID_RC1	"simple-test-rc1"
#define SIMPLE_TEST_OID_RC2	"simple-test-rc2"
#define SIMPLE_TEST_OID_RC3	"simple-test-rc3"
#define SIMPLE_TEST_OID_RC4	"simple-test-rc4"
#define SIMPLE_TEST_BS		4096

uv_barrier_t blocker;

static void
error_put_get_cb(ccow_completion_t comp, void *arg, int index, int status)
{
	int err;
	uint64_t off = 0;

	assert_non_null(cl);
	struct iovec iov[1];

	iov[0].iov_len = SIMPLE_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);

	uv_barrier_t *b = arg;

	err = ccow_get(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, comp, iov,
	    1, off, NULL);
	assert_int_equal(err, -EINVAL);

	uv_barrier_wait(b);

	je_free(iov[0].iov_base);
}

static void
error_put_get(void **state)
{
	int err;
	static int cnt = 0;
	uint64_t off = 0;

	assert_non_null(cl);
	struct iovec iov[1];

	iov[0].iov_len = SIMPLE_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	err = uv_barrier_init(&blocker, 2);
	assert_int_equal(err, 0);

	ccow_completion_t c;
	err = ccow_create_completion(cl, &blocker, error_put_get_cb, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_put(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, c, iov,
	    1, off);
	assert_int_equal(err, 0);

	uv_barrier_wait(&blocker);

	je_free(iov[0].iov_base);
}

static void
error_get_put_cb(ccow_completion_t comp, void *arg, int index, int status)
{
	int err;
	uint64_t off = 0;

	assert_non_null(cl);
	struct iovec iov[1];

	iov[0].iov_len = SIMPLE_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);

	uv_barrier_t *b = arg;

	err = ccow_put(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, comp, iov,
	    1, off);
	assert_int_equal(err, -EINVAL);

	err = ccow_get(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, comp, iov,
	    1, off, NULL);
	assert_int_equal(err, -EINVAL);

	uv_barrier_wait(b);

	je_free(iov[0].iov_base);
}

static void
error_get_put(void **state)
{
	int err;
	static int cnt = 0;
	uint64_t off = 0;

	assert_non_null(cl);
	struct iovec iov[1];

	iov[0].iov_len = SIMPLE_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	err = uv_barrier_init(&blocker, 2);
	assert_int_equal(err, 0);

	ccow_completion_t c;
	err = ccow_create_completion(cl, &blocker, error_get_put_cb, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_get(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, c, iov,
	    1, off, NULL);
	assert_int_equal(err, 0);

	uv_barrier_wait(&blocker);

	je_free(iov[0].iov_base);
}

static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_CONT, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_RC1, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_RC2, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_RC3, NULL, NULL);

	if (strncmp(TEST_ENV, "test", 4) == 0)
		return;
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_RC4, NULL, NULL);
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

int
main(int argc, char **argv)
{
	if (argc == 2) {
		if (strcmp(argv[1], "-n") == 0)
			dd = 1;
	}
	TEST_ENV = getenv("NEDGE_ENV");
	if (!TEST_ENV)
		TEST_ENV = "production";
	const UnitTest tests[] = {
#if 0
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(error_put_get),
		unit_test(error_get_put),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
#endif
	};
	return run_tests(tests);
}

