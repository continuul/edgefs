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

#define TEST_BUCKET_NAME	"simple-put-bucket-test"
ccow_t cl = NULL;

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
#define SIMPLE_TEST_OID_CONT	"simple-test-cont"
#define SIMPLE_TEST_BS		4096

static void
simple_put_stream_0_4k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov_in[3];
	struct iovec iov_out[3];
	for (int i = 0; i < 3; i++) {
		iov_in[i].iov_len = SIMPLE_TEST_BS;
		iov_in[i].iov_base = je_malloc(iov_in[i].iov_len);
		assert_non_null(iov_in[i].iov_base);

		iov_out[i].iov_len = SIMPLE_TEST_BS;
		iov_out[i].iov_base = je_malloc(iov_out[i].iov_len);
		assert_non_null(iov_out[i].iov_base);
	}

	/* first transaction */

	uint64_t genid = 0;
	ccow_completion_t c;
	err = ccow_create_stream_completion(cl, NULL, NULL, 10, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID_CONT, strlen(SIMPLE_TEST_OID_CONT) + 1, &genid,
	    NULL, NULL);
	assert_int_equal(err, 0);

	uint32_t bs = SIMPLE_TEST_BS;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, NULL);
	assert_int_equal(err, 0);

	char bookname_key2[] = "X-Object-Meta-Book";
	char book_value2[] = "Ċ";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key2, 19,
	    book_value2, 0, NULL);
	assert_int_equal(err, 0);

	int op_cnt = 1;

	err = ccow_put_cont(c, &iov_out[0], 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_get_cont(c, &iov_in[0], 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_put_cont(c, &iov_out[1], 2, SIMPLE_TEST_BS, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_get_cont(c, &iov_out[1], 2, SIMPLE_TEST_BS, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	/* verify that stream created object exists */
	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_CONT, NULL, 0, 0, NULL,
	    NULL, &iter);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	ccow_lookup_release(iter);

	/* second transaction */
	err = ccow_create_stream_completion(cl, NULL, NULL, 10, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID_CONT, strlen(SIMPLE_TEST_OID_CONT) + 1, &genid,
	    NULL, NULL);
	assert_int_equal(err, 0);

	op_cnt = 1;

	err = ccow_put_cont(c, &iov_out[0], 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_get_cont(c, &iov_in[0], 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_put_cont(c, &iov_out[0], 3, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_cancel(c);
	assert_int_equal(err, 0);

	for (int i = 0; i < 3; i++) {
		je_free(iov_in[i].iov_base);
		je_free(iov_out[i].iov_base);
	}
}

static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_CONT, NULL, NULL);
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
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(simple_put_stream_0_4k),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

