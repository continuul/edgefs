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
#include "hashtable.h"
#include "../src/libccow/ccow-impl.h"

ccow_t tc, tc1;
#define TEST_BUCKET_NAME	"bucket123"

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
	assert_true(read(fd, buf, 16384) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_admin_init(buf, "cltest", 7, &tc), 0);
	ccow_tenant_delete(tc, "test1", 6);
	assert_int_equal(ccow_tenant_create(tc, "test1", 6, NULL), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test1", 6, &tc1), 0);
	je_free(buf);
}

static void
tenant_create(void **state)
{
	assert_non_null(tc);
	ccow_tenant_delete(tc, "test2", 6);
	ccow_tenant_delete(tc, "test3", 6);
	ccow_tenant_delete(tc, "test4", 6);
	assert_int_equal(ccow_tenant_create(tc, "test2", 6, NULL), 0);
	assert_int_equal(ccow_tenant_create(tc, "test3", 6, NULL), 0);
	assert_int_equal(ccow_tenant_create(tc, "test4", 6, NULL), 0);
}

static void
tenant_lookup(void **state)
{
	int err;
	assert_non_null(tc);

	ccow_lookup_t iter;
	err = ccow_tenant_lookup(tc, NULL, 0, "test1", 6, 1, &iter);
	assert_int_equal(err, 0);
	ccow_lookup_release(iter);

	err = ccow_tenant_lookup(tc, NULL, 0, "test2", 6, 1, &iter);
	assert_int_equal(err, 0);
	ccow_lookup_release(iter);

	err = ccow_tenant_lookup(tc, NULL, 0, "test3", 6, 1, &iter);
	assert_int_equal(err, 0);
	ccow_lookup_release(iter);

	err = ccow_tenant_lookup(tc, NULL, 0, "test4", 6, 1, &iter);
	assert_int_equal(err, 0);
	ccow_lookup_release(iter);

	err = ccow_tenant_lookup(tc, NULL, 0, "", 1, 10, &iter);
	assert_int_equal(err, 0);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
	ccow_lookup_release(iter);

}

static void
tenant_md_add_delete(void **state)
{
	assert_non_null(tc);
	assert_non_null(tc1);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc1, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter;

	get_simple(c, "", "", NULL, 0, 0, &iter);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
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

	char cats_key[] = "X-Object-Meta-Cats";
	uint64_t cats = 42;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, cats_key, 19,
	    &cats, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, "", "", NULL, 0, 0);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	ccow_lookup_release(iter);

}

static void
tenant_retrieve_md(void **state)
{
	assert_non_null(tc);
	assert_non_null(tc1);
	int err;

	ccow_lookup_t iter;
	get(tc1, "", "", NULL, 0, 0, NULL, NULL, &iter);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	ccow_lookup_release(iter);
}

static void
bucket_create(void **state)
{
	assert_non_null(tc1);
	int err = ccow_bucket_create(tc1, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	usleep(50 * 1000000L);
	assert_non_null(tc1);
	int err = ccow_bucket_delete(tc1, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	printf("bucket_delete err: %d\n", err);
	assert_int_equal(err, 0);
}


static void
put_1k(void **state)
{
	assert_non_null(tc1);
	struct iovec iov[1];
	iov[0].iov_len = 1024;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	put(tc1, TEST_BUCKET_NAME, "test-obj1", &iov[0], 1, 0, NULL, NULL);
	put(tc1, TEST_BUCKET_NAME, "test-obj2", &iov[0], 1, 0, NULL, NULL);

	je_free(iov[0].iov_base);
	usleep(30 * 1000000L);
}

static void
object_delete(void **state)
{
	assert_non_null(tc1);
	delete(tc1, TEST_BUCKET_NAME, "test-obj1", NULL, NULL);
	delete(tc1, TEST_BUCKET_NAME, "test-obj2", NULL, NULL);
}

static void
cluster_lookup(void **state)
{
	assert_non_null(tc);
	int err;
	ccow_lookup_t iter;
	err = ccow_cluster_lookup(tc, NULL, 0, INT32_MAX, &iter);
	assert_int_equal(err, 0);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);

	ccow_lookup_release(iter);
}


static void
tenant_accounting(void **state)
{
	struct ccow_cluster_stats *data =
			(struct ccow_cluster_stats *) je_calloc(1, sizeof(struct ccow_cluster_stats));
	assert_non_null(tc);
	int err;

	err = ccow_cluster_accounting(tc, "cltest",  strlen("cltest") + 1,
		NULL, 0, 0, data);

	printf("Tenants: %lu\n", data->cluster_tenants);
	printf("Objects: %lu\n", data->cluster_objects);
	printf("Logical size: %lu\n\n", data->cluster_logical_size);

	assert_int_equal(err, 0);
	je_free(data);
}


static void
tenant_delete(void **state)
{
	assert_non_null(tc);
	assert_non_null(tc1);
	assert_int_not_equal(ccow_tenant_delete(tc1, "test1", 6), 0);
	assert_int_equal(ccow_tenant_delete(tc, "test1", 6), 0);
	assert_int_equal(ccow_tenant_delete(tc, "test2", 6), 0);
	assert_int_equal(ccow_tenant_delete(tc, "test3", 6), 0);
	assert_int_equal(ccow_tenant_delete(tc, "test4", 6), 0);
}


static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	assert_non_null(tc1);
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
		unit_test(tenant_create),
		unit_test(tenant_lookup),
		unit_test(tenant_md_add_delete),
		unit_test(tenant_retrieve_md),
		unit_test(cluster_lookup),
		unit_test(bucket_create),
		unit_test(put_1k),
		unit_test(tenant_accounting),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(tenant_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
