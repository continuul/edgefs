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

#define TEST_BUCKET_NAME	"stress-bucket-test"
#define STRESS_TEST_OID		"stress-test3"
#define STRESS_TEST_DEPTH	1
#define STRESS_TEST_WIDTH	512
#define STRESS_TEST_CHUNKMAP	"btree_map"
#define STRESS_TEST_BS		4096

#define NUM_TESTS 50000
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


static void
stress_test_run_put_get(void **state)
{
	int err;
	struct iovec iov[1];

	char * chunkmap_type = STRESS_TEST_CHUNKMAP;
	uint8_t depth = STRESS_TEST_DEPTH;
	uint16_t width = STRESS_TEST_WIDTH;
	uint32_t bs = STRESS_TEST_BS;

	ccow_completion_t c;
	ccow_lookup_t iter;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);
	get_simple(c, TEST_BUCKET_NAME, "", NULL, 0, 0, &iter);
	err = ccow_wait(c, 0);
	assert_int_equal(err && err != -ENOENT, 0);
	if (err == -ENOENT) {
		if (iter)
			ccow_lookup_release(iter);
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);
		iter = NULL;
	}


	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)chunkmap_type, iter);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_FIXEDMAP_DEPTH,
		(void *)&depth, iter);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_FIXEDMAP_WIDTH,
	    (void *)&width, iter);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, iter);
	assert_int_equal(err, 0);

	char bookname_key[] = "X-Object-Meta-Book";
	char book_value[] = "GoodbyeOldFriend";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key, 19,
	    book_value, 0, iter);
	assert_int_equal(err, 0);

	char booknum_key[] = "X-Object-Meta-NumBooks";
	uint64_t books = 347;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, booknum_key, 23,
	    &books, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "", NULL, 0, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	if (iter)
		ccow_lookup_release(iter);

	int len = STRESS_TEST_BS;
	char buf[len];

	get(cl, TEST_BUCKET_NAME, "", NULL, 0, 0, NULL, NULL, &iter);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);

	//dump_iter_to_stdout(iter, CCOW_MDTYPE_CUSTOM);
	if (iter)
		ccow_lookup_release(iter);

	/* Overwrite OBJ MD? */
	ccow_completion_t c2;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c2);
	assert_int_equal(err, 0);

	put_simple(c2, TEST_BUCKET_NAME, "", NULL, 0, 0);
	err = ccow_wait(c2, -1);
	assert_int_equal(err, 0);

	ccow_lookup_t iter2;
	get(cl, TEST_BUCKET_NAME, "", NULL, 0, 0, NULL, NULL, &iter2);

	//dump_iter_to_stdout(iter2, CCOW_MDTYPE_CUSTOM);
	ccow_lookup_release(iter2);
}

static int
stress_test_run_puts_with_md()
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = STRESS_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	char * chunkmap_type = STRESS_TEST_CHUNKMAP;
	uint8_t depth = STRESS_TEST_DEPTH;
	uint16_t width = STRESS_TEST_WIDTH;
	uint32_t bs = STRESS_TEST_BS;

	ccow_completion_t c;
	ccow_lookup_t iter;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);
	get_simple(c, TEST_BUCKET_NAME, "", NULL, 0, 0, &iter);
	err = ccow_wait(c, 0);
	assert_int_equal(err && err != -ENOENT, 0);
	if (err == -ENOENT) {
		if (iter)
			ccow_lookup_release(iter);
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);
		iter = NULL;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)chunkmap_type, iter);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_FIXEDMAP_DEPTH,
		(void *)&depth, iter);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_FIXEDMAP_WIDTH,
	    (void *)&width, iter);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, iter);
	assert_int_equal(err, 0);

	char bookname_key[] = "X-Object-Meta-Book";
	char book_value[] = "GoodbyeOldFriend";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key, 19,
	    book_value, 0, iter);
	assert_int_equal(err, 0);

	char booknum_key[] = "X-Object-Meta-NumBooks";
	uint64_t books = 347;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, booknum_key, 23,
	    &books, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, STRESS_TEST_OID, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	je_free(iov[0].iov_base);
	if (iter)
		ccow_lookup_release(iter);
	return err;
}

static void
stress_test__puts_with_md(void **state)
{
	assert_non_null(cl);
	int err = 0;
	uint64_t before;
	uint64_t after;
	uv_fs_t req;
	int i;

	before = uv_hrtime();

	for (i = 0; i < NUM_TESTS; i++) {
		err = stress_test_run_puts_with_md();
		assert_int_equal(err, 0);
	}

	after = uv_hrtime();

	printf("%s writes of %d Bytes with md (sync): %.2fs (%s/s)\n",
	    fmt(1.0 * NUM_TESTS), STRESS_TEST_BS,
	    (after - before) / 1e9,
	    fmt((1.0 * NUM_TESTS) / ((after - before) / 1e9)));
	fflush(stdout);


}


static int
stress_test_run_gets_with_md()
{
	assert_non_null(cl);
	int err = 0;

	assert_non_null(cl);
	int len = STRESS_TEST_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, STRESS_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    &iter);
	ccow_lookup_release(iter);

	return err;
}


static void
stress_test__reads_with_md(void **state)
{
	assert_non_null(cl);
	int err = 0;
	uint64_t before;
	uint64_t after;
	uv_fs_t req;
	int i;

	before = uv_hrtime();

	for (i = 0; i < NUM_TESTS; i++) {
		err = stress_test_run_gets_with_md();
		assert_int_equal(err, 0);
	}

	after = uv_hrtime();

	printf("%s reads of %d Bytes with md (sync): %.2fs (%s/s)\n",
	    fmt(1.0 * NUM_TESTS), STRESS_TEST_BS,
	    (after - before) / 1e9,
	    fmt((1.0 * NUM_TESTS) / ((after - before) / 1e9)));
	fflush(stdout);

}

static void
stress_test__check_version(void **state)
{
	assert_non_null(cl);
	int err = 0;

	assert_non_null(cl);
	int len = STRESS_TEST_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, STRESS_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    &iter);

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, pos++))) {
		if (kv->type == CCOW_KVTYPE_UINT64) {
			if (strncmp(kv->key, "ccow-tx-generation-id",
				    kv->key_size) == 0)
				printf("\n\t%s: %ld\n\n", kv->key,
				*(uint64_t *)kv->value);
		}
	}
	ccow_lookup_release(iter);
	assert_int_equal(err, 0);
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
		unit_test(bucket_create),
		unit_test(stress_test__check_version),
		unit_test(stress_test__puts_with_md),
		unit_test(stress_test_run_put_get),
		unit_test(stress_test__check_version),
		unit_test(stress_test__reads_with_md),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
