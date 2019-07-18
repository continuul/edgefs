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

#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"
#include "ccowutil.h"

#define TEST_BUCKET_NAME	"simple-iter-bucket-test"
ccow_t cl;

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

/*
 * =======================================================================
 *		Put Test Sync, Fixedmap 3x4, bs=1k
 * =======================================================================
 */
#define ITER_TEST_OID			"iter-test"
#define ITER_TEST_CHUNKMAP		"btree_map"
#define ITER_TEST_CHUNKMAP_BS		1024

static void
iter_test__init_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = ITER_TEST_CHUNKMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	char * chunkmap_type = ITER_TEST_CHUNKMAP;
	uint32_t bs = ITER_TEST_CHUNKMAP_BS;

	ccow_completion_t c;
	ccow_lookup_t iter;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);
	get_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, NULL, 0, 0, &iter);
	err = ccow_wait(c, 0);
	assert_int_equal(err && err != -ENOENT, 0);
	if (err == -ENOENT) {
		if (iter)
			ccow_lookup_release(iter);
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);
		iter = NULL;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, iter);
	assert_int_equal(err, 0);


	char bookname_key[] = "X-Object-Meta-Book";
	char book_value[] = "GoodbyeOldFriend";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_RAW, bookname_key,
	    strlen(bookname_key) + 1, book_value, strlen(book_value) + 1, iter);
	assert_int_equal(err, 0);

	char booknum_key[] = "X-Object-Meta-NumBooks";
	uint64_t books = 347;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, booknum_key,
	    strlen(booknum_key) + 1, &books, 0, iter);
	assert_int_equal(err, 0);

	char cats_key[] = "X-Object-Meta-Cats";
	uint64_t cats = 42;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, cats_key,
	    strlen(cats_key) + 1, &cats, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	if (iter)
		ccow_lookup_release(iter);
	je_free(iov[0].iov_base);
}


static void
iter_test__md_init_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_CHUNKMAP_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, ITER_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    &iter);

	ccow_lookup_release(iter);
}


static void
iter_test__md_retrieve_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_CHUNKMAP_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, ITER_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    &iter);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
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
		unit_test(iter_test__init_0_1k),
		unit_test(iter_test__md_init_0_1k),
		unit_test(iter_test__md_retrieve_0_1k),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
