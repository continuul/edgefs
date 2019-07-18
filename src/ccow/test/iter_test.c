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

#define TEST_BUCKET_NAME	"iter-bucket-test"
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
 *		Put Test Sync, Fixedmap 3x4, bs=1k
 * =======================================================================
 */
#define ITER_TEST_OID			"iter-test"
#define ITER_TEST_CHUNKMAP		"btreenam"
#define ITER_TEST_FIXEDMAP_BS		1024

static void
iter_test__init_bucket(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = ITER_TEST_FIXEDMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	char * chunkmap_type = ITER_TEST_CHUNKMAP;
	uint32_t bs = ITER_TEST_FIXEDMAP_BS;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter;
	get_simple(c, TEST_BUCKET_NAME, "", NULL, 0, 0, &iter);

	err = ccow_wait(c, 0);
	assert_int_equal((err && err != -ENOENT), 0);
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
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key, 19,
	    book_value, 0, iter);
	assert_int_equal(err, 0);

	char booknum_key[] = "X-Object-Meta-NumBooks";
	uint64_t books = 200*1024*1024*1024L;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, booknum_key, 23,
	    &books, 0, iter);
	assert_int_equal(err, 0);

	char cats_key[] = "X-Object-Meta-Cats";
	uint64_t cats = 3*1024*1024*1024LU;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, cats_key, 19,
	    &cats, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "", NULL, 0, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	if (iter)
		ccow_lookup_release(iter);
	je_free(iov[0].iov_base);
}

static void
iter_test__md_retrieve_bucket(void **state)
{
	assert_non_null(cl);
	int err;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, "", NULL, 0, 0, NULL, NULL, &iter);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	ccow_lookup_release(iter);
}

static void
iter_test__init_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = ITER_TEST_FIXEDMAP_BS;
	iov[0].iov_base = je_calloc(1, iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	char * chunkmap_type = ITER_TEST_CHUNKMAP;
	uint32_t bs = ITER_TEST_FIXEDMAP_BS;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter;
	get_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0, &iter);

	err = ccow_wait(c, 0);
	assert_int_equal((err && err != -ENOENT), 0);
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

	uint16_t enable = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_TRACK_STATISTICS,
	    (void *)&enable, iter);
	assert_int_equal(err, 0);

	char bookname_key[] = "X-Object-Meta-Book";
	char book_value[] = "GoodbyeOldFriend";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key, 19,
	    book_value, 0, iter);
	assert_int_equal(err, 0);

	char booknum_key[] = "X-Object-Meta-NumBooks";
	uint64_t books = 200*1024*1024*1024L;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, booknum_key, 23,
	    &books, 0, iter);
	assert_int_equal(err, 0);

	char cats_key[] = "X-Object-Meta-Cats";
	uint64_t cats = 3*1024*1024*1024LU;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, cats_key, 19,
	    &cats, 0, iter);
	assert_int_equal(err, 0);
	put_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	if (iter)
		ccow_lookup_release(iter);
	je_free(iov[0].iov_base);
}


static void
iter_test__no_md_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_FIXEDMAP_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	get(cl, TEST_BUCKET_NAME, ITER_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    NULL);
}

static void
iter_test__no_md_0(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_FIXEDMAP_BS;

	struct iovec iov[0];
	size_t iovcnt = 0;

	get(cl, TEST_BUCKET_NAME, ITER_TEST_OID, iov, iovcnt, 0, NULL, NULL,
	    NULL);
}

static void
iter_test__no_md_0_iter(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_FIXEDMAP_BS;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, ITER_TEST_OID, NULL, 0, 0, NULL, NULL,
	    &iter);
	assert_int_not_equal(ccow_lookup_length(iter, CCOW_MDTYPE_ALL), 0);
	ccow_lookup_release(iter);
}

static void
iter_test__md_init_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_FIXEDMAP_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, ITER_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    &iter);
	ccow_lookup_release(iter);
}

static void
iter_test_md_modify_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = ITER_TEST_FIXEDMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter;
	get_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0, &iter);

	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	char bookname_key2[] = "X-Object-Meta-Book";
	char book_value2[] = "Ċ";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key2, 19,
	    book_value2, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	ccow_lookup_release(iter);

	iter = NULL;


	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	get_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0, &iter);

	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	char bookname_key3[] = "X-Object-Meta-Book-AAAAAAAAAAAAAAAA";
	char book_value3[] = "ĊCCCCCCCCCCCCCCCC";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key3, 36,
	    book_value3, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	if (iter)
		ccow_lookup_release(iter);

	je_free(iov[0].iov_base);
}

static void
iter_test_md_del_all(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = ITER_TEST_FIXEDMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter;
	get_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0, &iter);

	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	char key2[] = "X-Object-Meta-Book";
	char *value2 = NULL;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_RAW, key2, 19,
	    value2, 0, iter);
	assert_int_equal(err, 0);

	char key3[] = "X-Object-Meta-Cats";
	char *value3 = NULL;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, key3, 19,
	    value3, 0, iter);
	assert_int_equal(err, 0);

	char key4[] = "X-Object-Meta-NumBooks";
	char *value4 = NULL;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, key4, 23,
	    value4, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0);

	err = ccow_wait(c, 1);
	assert_int_equal(err, 0);

	ccow_lookup_release(iter);
	je_free(iov[0].iov_base);
}

static void
iter_test__list_bucket(void **state)
{
	int err;
	assert_non_null(cl);

	ccow_lookup_t iter;
	printf("all buckets in tenant:\n");
	err = ccow_bucket_lookup(cl, "", 1, 100, &iter);
	assert_int_equal(err, 0);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
	ccow_lookup_release(iter);

	printf("specific bucket:\n");
	err = ccow_bucket_lookup(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, 10, &iter);
	assert_int_equal(err, 0);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
	ccow_lookup_release(iter);

#if 0
	printf("all objects in bucket:\n");
	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	struct iovec iov[10];
	memset(iov, 0, sizeof (iov));
	err = ccow_get_list(TEST_BUCKET_NAME, NULL, c, iov, 10, 0, &iter);
	assert_int_equal(err, 0);

	err = ccow_wait(c, 0);
	if (err) {
		ccow_lookup_release(iter);
		assert_int_equal(err, 0);
	}
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
	ccow_lookup_release(iter);
#endif
}

static void
iter_test_md_del_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = ITER_TEST_FIXEDMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter;
	get_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0, &iter);

	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	char bookname_key2[] = "X-Object-Meta-Book";
	char *book_value2 = NULL;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key2, 19,
	    book_value2, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, ITER_TEST_OID, &iov[0], 1, 0);

	err = ccow_wait(c, 1);
	assert_int_equal(err, 0);

	ccow_lookup_release(iter);
	je_free(iov[0].iov_base);
}

static void
iter_test__md_retrieve_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_FIXEDMAP_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, ITER_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    &iter);

	assert(iter);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	ccow_lookup_release(iter);
}

struct async_work {
	ccow_lookup_t iter;
};

static void
iter_test_async_cb(ccow_completion_t c, void *arg, int index, int err)
{
	struct async_work *w = arg;
	dump_iter_to_stdout(w->iter, CCOW_MDTYPE_ALL);
}

static void
iter_test__md_retrieve_async(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_FIXEDMAP_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	struct async_work w;
	get(cl, TEST_BUCKET_NAME, ITER_TEST_OID, &iov, iovcnt, 0,
	    iter_test_async_cb, &w, &w.iter);
	usleep(1000000UL); // 1s
	if (w.iter)
		ccow_lookup_release(w.iter);
}

static void
iter_test__md_retrieve_and_cast(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_FIXEDMAP_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, ITER_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    &iter);

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_CUSTOM, pos++))) {
		if (!strcmp(kv->key, "X-Object-Meta-Kitty-Cats"))
		{
			uint64_t val;
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &val);
			printf("kv-key: %s\n", kv->key);
			printf("value as a u64: %ld\n", val);
			printf("value as a u32: %d\n", *(uint32_t *)kv->value);
		}
	}
	ccow_lookup_release(iter);
}


static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, TEST_BUCKET_NAME, ITER_TEST_OID, NULL, NULL);
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
		unit_test(iter_test__init_0_1k),
		unit_test(iter_test__md_retrieve_async),
		unit_test(iter_test__md_retrieve_0_1k),
		unit_test(iter_test__no_md_0_1k),
		unit_test(iter_test__no_md_0),
		unit_test(iter_test__no_md_0_iter),
		unit_test(iter_test__md_init_0_1k),
		unit_test(iter_test__md_retrieve_0_1k),
		unit_test(iter_test__init_bucket),
		unit_test(iter_test__md_retrieve_bucket),
		unit_test(iter_test_md_del_0_1k),
		unit_test(iter_test__md_retrieve_0_1k),
		unit_test(iter_test__md_retrieve_and_cast),
		unit_test(iter_test_md_modify_0_1k),
		unit_test(iter_test__md_retrieve_0_1k),
		unit_test(iter_test_md_del_all),
		unit_test(iter_test__md_retrieve_0_1k),
		unit_test(iter_test__list_bucket),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
