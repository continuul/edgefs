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
#include "../src/libreplicast/replicast.h"

#define TEST_BUCKET_NAME	"get-bucket-test"
ccow_t tc;
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
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);
	je_free(buf);
}

static void
bucket_create(void **state)
{
	assert_non_null(tc);
       int err = ccow_bucket_create(tc, TEST_BUCKET_NAME,
	   strlen(TEST_BUCKET_NAME) + 1, NULL);
       if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(tc);
       int err = ccow_bucket_delete(tc, TEST_BUCKET_NAME,
	   strlen(TEST_BUCKET_NAME) + 1);
       assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *		        Get test definitions
 * =======================================================================
 */
#define GET_TEST_OID		"get-test"
#define GET_TEST_OID_DEF	"get-test-default"
#define GET_TEST_OID_TWO	"get-test-two"
#define GET_TEST_OID_TWO_DEF	"get-test-two-default"
#define GET_TEST_OID_FOUR	"get-test-four"
#define GET_TEST_OID_FOUR_DEF	"get-test-four-default"
#define GET_TEST_OID_EIGHT	"get-test-eight"
#define GET_TEST_OID_EIGHT_DEF	"get-test-eight-default"
#define GET_TEST_FIXEDMAP_BS	1024

static void
get_test__default_init_0_1k(void **state)
{
	int err;
	int len = GET_TEST_FIXEDMAP_BS * 1;
	char buf[len]; memset(buf, 0, len);
	assert_non_null(tc);

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	uint8_t compress_type = 0; /* memcpy */

	err = ccow_attr_modify_default(c, CCOW_ATTR_COMPRESS_TYPE,
		(void *)&compress_type, NULL);
	assert_int_equal(err, 0);

	struct iovec *iov;
	size_t iovcnt;
	err = ccow_chunk(buf, len, GET_TEST_FIXEDMAP_BS, &iov, &iovcnt);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, GET_TEST_OID_DEF, &iov[0], iovcnt, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	je_free(&iov[0].iov_base);
}

static void
get_test__default_0_1k(void **state)
{
	int err;
	int len = GET_TEST_FIXEDMAP_BS;
	char buf[len]; memset(buf, 0, len);
	assert_non_null(tc);

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	get(tc, TEST_BUCKET_NAME, GET_TEST_OID_DEF, &iov, iovcnt, 0, NULL, NULL,
	    NULL);
}

static void
get_test__default_init_0_2k(void **state)
{
	int err;
	int len = GET_TEST_FIXEDMAP_BS * 2;
	char buf[len]; memset(buf, 0, len);
	assert_non_null(tc);

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	uint8_t compress_type = 1; /* lz4 */

	err = ccow_attr_modify_default(c, CCOW_ATTR_COMPRESS_TYPE,
		(void *)&compress_type, NULL);
	assert_int_equal(err, 0);

	struct iovec *iov;
	size_t iovcnt;
	err = ccow_chunk(buf, len, GET_TEST_FIXEDMAP_BS, &iov, &iovcnt);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, GET_TEST_OID_TWO_DEF, iov, iovcnt, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	je_free(&iov[0].iov_base);
}

static void
get_test__default_0_2k(void **state)
{
	int err;
	int len = GET_TEST_FIXEDMAP_BS * 2;
	char buf[len]; memset(buf, 0, len);

	assert_non_null(tc);
	struct iovec *iov;
	size_t iovcnt;
	err = ccow_chunk(buf, len, GET_TEST_FIXEDMAP_BS, &iov, &iovcnt);
	assert_int_equal(err, 0);

	get(tc, TEST_BUCKET_NAME, GET_TEST_OID_TWO_DEF, iov, iovcnt, 0,
	    NULL, NULL, NULL);

	je_free(iov);
}

static void
get_test__default_init_0_4k(void **state)
{
	int err;
	int len = GET_TEST_FIXEDMAP_BS * 4;
	char buf[len]; memset(buf, 0, len);
	assert_non_null(tc);

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	uint8_t compress_type = 2; /* lz4hc */

	err = ccow_attr_modify_default(c, CCOW_ATTR_COMPRESS_TYPE,
		(void *)&compress_type, NULL);
	assert_int_equal(err, 0);

	struct iovec *iov;
	size_t iovcnt;
	err = ccow_chunk(buf, len, GET_TEST_FIXEDMAP_BS, &iov, &iovcnt);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, GET_TEST_OID_FOUR_DEF, iov, iovcnt, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	je_free(&iov[0].iov_base);
}

static void
get_test__default_0_4k(void **state)
{
	int err;
	int len = GET_TEST_FIXEDMAP_BS * 4;
	char buf[len]; memset(buf, 0, len);

	assert_non_null(tc);
	struct iovec *iov;
	size_t iovcnt;
	err = ccow_chunk(buf, len, GET_TEST_FIXEDMAP_BS, &iov, &iovcnt);
	assert_int_equal(err, 0);

	get(tc, TEST_BUCKET_NAME, GET_TEST_OID_FOUR_DEF, iov, iovcnt, 0,
	    NULL, NULL, NULL);

	je_free(iov);
}

static void
get_test__default_init_0_8k(void **state)
{
	int err;
	int len = GET_TEST_FIXEDMAP_BS * 8;
	char buf[len]; memset(buf, 0, len);
	assert_non_null(tc);

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	uint8_t compress_type = 3; /* snappy */

	err = ccow_attr_modify_default(c, CCOW_ATTR_COMPRESS_TYPE,
		(void *)&compress_type, NULL);
	assert_int_equal(err, 0);

	struct iovec *iov;
	size_t iovcnt;
	err = ccow_chunk(buf, len, GET_TEST_FIXEDMAP_BS, &iov, &iovcnt);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, GET_TEST_OID_EIGHT_DEF, iov, iovcnt, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	je_free(&iov[0].iov_base);
}

static void
get_test__default_0_8k(void **state)
{
	int err;
	int len = GET_TEST_FIXEDMAP_BS * 8;
	char buf[len]; memset(buf, 0, len);

	assert_non_null(tc);
	struct iovec *iov;
	size_t iovcnt;
	err = ccow_chunk(buf, len, GET_TEST_FIXEDMAP_BS, &iov, &iovcnt);
	assert_int_equal(err, 0);

	get(tc, TEST_BUCKET_NAME, GET_TEST_OID_EIGHT_DEF, iov, iovcnt, 0,
	    NULL, NULL, NULL);

	je_free(iov);
}

static void
get_test__empty(void **state)
{
	int err;

	assert_non_null(tc);
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	get_simple(c, TEST_BUCKET_NAME, "get-test-empty", NULL, 0, 0, NULL);

	err = ccow_wait(c, 0);
	assert_int_equal(err, -ENOENT);
}

static void
object_delete(void **state)
{
	assert_non_null(tc);
//	delete(tc, TEST_BUCKET_NAME, GET_TEST_OID, NULL, NULL);
	delete(tc, TEST_BUCKET_NAME, GET_TEST_OID_DEF, NULL, NULL);
	delete(tc, TEST_BUCKET_NAME, GET_TEST_OID_TWO_DEF, NULL, NULL);
	delete(tc, TEST_BUCKET_NAME, GET_TEST_OID_FOUR_DEF, NULL, NULL);
	delete(tc, TEST_BUCKET_NAME, GET_TEST_OID_EIGHT_DEF, NULL, NULL);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	ccow_tenant_term(tc);
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
		unit_test(get_test__default_init_0_1k),
		unit_test(get_test__default_0_1k),
		unit_test(get_test__default_0_1k), // expect it to come from cache
		unit_test(get_test__default_init_0_2k),
		unit_test(get_test__default_0_2k),
		unit_test(get_test__default_init_0_4k),
		unit_test(get_test__default_0_4k),
		unit_test(get_test__default_init_0_8k),
		unit_test(get_test__default_0_8k),
		unit_test(get_test__empty),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
