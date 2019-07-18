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

#define TEST_BUCKET_NAME	"seq-bucket-test"
ccow_t cl = NULL;

int dd = 0;

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


#define PUT_TEST_ASYNC_OID		"put-test-async"
#define PUT_TEST_ASYNC_CHUNKMAP		"btree_map"
#define TEST_BS	4096

static void
object_delete(void **state)
{
	delete(cl, TEST_BUCKET_NAME, PUT_TEST_ASYNC_OID, NULL, NULL);
}

static void
put_test_async_cb(ccow_completion_t c, void *arg, int index, int err)
{
	uv_barrier_t *b = arg;
	assert_int_equal(err, 0);
	uv_barrier_wait(b);
}

static void
put_test_async__default_init_0_1k(void **state)
{
	assert_non_null(cl);
	int err = 0;
	struct iovec iov[1];
	iov[0].iov_len = TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	uv_barrier_t b;
	uv_barrier_init(&b, 2);

	ccow_completion_t c;
	err = ccow_create_completion(cl, &b, put_test_async_cb, 1, &c);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, PUT_TEST_ASYNC_OID, &iov[0], 1, 0);

	uv_barrier_wait(&b);
	uv_barrier_destroy(&b);

	je_free(iov[0].iov_base);
}

#define ASYNC_STRESS_MAX	1
static int async_compl = 0;
static int async_err = 0;

static void
put_test_async_stress_cb(ccow_completion_t c, void *arg, int index, int err)
{
	uv_barrier_t *b = arg;

	async_err = err;
	if (err || ++async_compl == ASYNC_STRESS_MAX)
		uv_barrier_wait(b);
}

#define NUM_IOVEC 200
static void
put_test_async__stress(void **state)
{
	assert_non_null(cl);
	int err = 0;
	struct iovec iov[NUM_IOVEC];
	for (int j = 0; j < NUM_IOVEC; j++)
	{
		iov[j].iov_len = TEST_BS;
		iov[j].iov_base = je_malloc(iov[j].iov_len);
	}
	uv_barrier_t b;
	uv_barrier_init(&b, 2);

	/* do the async benchmark */
	uint64_t before = uv_hrtime();

	ccow_completion_t c;
	err = ccow_create_completion(cl, &b, put_test_async_stress_cb,
	    ASYNC_STRESS_MAX, &c);
	assert_int_equal(err, 0);

	async_compl = 0;
	for (int i =0; i < ASYNC_STRESS_MAX; i++)
		put_simple(c, TEST_BUCKET_NAME, PUT_TEST_ASYNC_OID, iov,
		    NUM_IOVEC, 0);

	uv_barrier_wait(&b);
	uv_barrier_destroy(&b);

	uint64_t after = uv_hrtime();

	printf("%s stats (async): %.2fs (%s/s)\n", fmt(1.0 * NUM_IOVEC),
	    (after - before) / 1e9,
	    fmt((1.0 * NUM_IOVEC) / ((after - before) / 1e9)));
	fflush(stdout);

	for (int j = 0; j < NUM_IOVEC; j++) {
		je_free(iov[j].iov_base);
	}
	assert_int_equal(async_err, 0);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	usleep(200000L);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
    if(!dd)
	    ccow_daemon_term();
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
		unit_test(put_test_async__default_init_0_1k),
		unit_test(put_test_async__stress),
		unit_test(put_test_async__stress), /* rewrite */
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
