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

#define SNAPVIEW_TEST_OID	"sv"
#define SIMPLE_TEST_OID		"simple-test"
#define SIMPLE_TEST_BS		1024
#define SNAPSHOT_NAME1		"today-abcd-01-02-1969:0099282"
#define SNAPSHOT_NAME2		"today-abcd-02-02-1969:0099282"
#define SNAPSHOT_NAME3		"today-abcd-03-02-1969:0099282"
#define TEST_BUCKET_NAME	"snapview-bucket-test"
ccow_t cl = NULL;
ccow_snapview_t sv_hdl;

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
simple_snapview_create(void **state)
{
	assert_non_null(cl);

	int err = ccow_snapview_create(cl, &sv_hdl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, SNAPVIEW_TEST_OID,
	    strlen(SNAPVIEW_TEST_OID) + 1);
		if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
simple_snapshot_create(void **state)
{
	assert_non_null(cl);
	assert_non_null(sv_hdl);
	int err = ccow_snapshot_create(cl, sv_hdl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID,
	    strlen(SIMPLE_TEST_OID) + 1, SNAPSHOT_NAME1,
	    strlen(SNAPSHOT_NAME1) + 1);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
	err = ccow_snapshot_create(cl, sv_hdl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID,
	    strlen(SIMPLE_TEST_OID) + 1, SNAPSHOT_NAME2,
	    strlen(SNAPSHOT_NAME2) + 1);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
	err = ccow_snapshot_create(cl, sv_hdl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID,
	    strlen(SIMPLE_TEST_OID) + 1, SNAPSHOT_NAME3,
	    strlen(SNAPSHOT_NAME3) + 1);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
simple_snapshot_delete(void **state)
{
	assert_non_null(cl);
	assert_non_null(sv_hdl);
	int err = ccow_snapshot_delete(cl, sv_hdl, SNAPSHOT_NAME1,
	    strlen(SNAPSHOT_NAME1) + 1);
	assert_int_equal(err, 0);
}

static void
simple_snapview_delete(void **state)
{
	assert_non_null(cl);
	assert_non_null(sv_hdl);
	int err = ccow_snapview_delete(cl, sv_hdl);
	assert_int_equal(err, 0);
}

static void
simple_snapshot_lookup(void **state)
{
	assert_non_null(cl);
	int err;
	ccow_lookup_t iter;
	err = ccow_snapshot_lookup(cl, sv_hdl, "", 1, 10, &iter);
	assert_int_equal(err, 0);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
	ccow_lookup_release(iter);
}

static void
simple_snapview_clone(void **state)
{
	assert_non_null(cl);
	int err;
	err = ccow_clone_snapview_object(cl, sv_hdl, SNAPSHOT_NAME1,
	    strlen(SNAPSHOT_NAME1) + 1, "test", 5, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, "obj1", 5);
	assert_int_equal(err, 0);

}

int runs = 0;
static void
simple_put_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = SIMPLE_TEST_BS;
	iov[0].iov_base = je_calloc(1, iov[0].iov_len);
	assert_non_null(iov[0].iov_base);
	if (runs == 0) {
		strcpy(iov[0].iov_base, "ABCD");
		runs++;
	}
	else
		strcpy(iov[0].iov_base, "CHANGED - DATA");

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_put(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, c, iov,
	    1, 0);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	je_free(iov[0].iov_base);
	assert_int_equal(err, 0);
}

static void
simple_put_inc_version(void **state)
{
	assert_non_null(cl);
	int err;

	for(int i = 0; i < 50; i++)
	{
		struct iovec iov[1];
		iov[0].iov_len = SIMPLE_TEST_BS;
		iov[0].iov_base = je_calloc(1, iov[0].iov_len);
		assert_non_null(iov[0].iov_base);

		snprintf(iov[0].iov_base, SIMPLE_TEST_BS, "CHANGED - DATA %d", i);
		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		err = ccow_put(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
		    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, c, iov,
		    1, 0);
		assert_int_equal(err, 0);

		err = ccow_wait(c, -1);
		je_free(iov[0].iov_base);
		assert_int_equal(err, 0);
	}
}


static void
simple_snapview_get(void **state)
{
	assert_non_null(cl);
	int err;
	int len = SIMPLE_TEST_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, "obj1", &iov, iovcnt, 0, NULL, NULL,
	    &iter);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	ccow_lookup_release(iter);
}

static void
simple_snapshot_obj_get(void **state)
{
	assert_non_null(cl);
	int err;
	int len = SIMPLE_TEST_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID, &iov, iovcnt, 0, NULL, NULL,
	    &iter);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	ccow_lookup_release(iter);
}

static void
simple_snapshot_rollback(void **state)
{
	assert_non_null(cl);
	int err;

	err = ccow_snapshot_rollback(cl, sv_hdl,
	    SNAPSHOT_NAME2, strlen(SNAPSHOT_NAME2) + 1);
	assert_int_equal(err, 0);

	struct iovec iov[1];
	iov[0].iov_len = SIMPLE_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	get_simple(c, TEST_BUCKET_NAME, SIMPLE_TEST_OID, &iov[0], 1, 0, NULL);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	/* Data verification of rollback */
	printf("iov_base : %s, should read : ABCD\n", (char *)iov[0].iov_base);
	assert_int_equal(strcmp("ABCD", iov[0].iov_base), 0);

	je_free(iov[0].iov_base);


}

static void
simple_snapview_destroy(void **state) {
	assert_non_null(cl);
	ccow_snapview_destroy(cl, sv_hdl);
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

static void
bucket_create(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_create(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
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
		unit_test(simple_put_inc_version),
		unit_test(simple_put_0_1k),
		unit_test(simple_snapview_create),
		unit_test(simple_snapshot_obj_get),
		unit_test(simple_snapshot_create),
		unit_test(simple_snapshot_lookup),
		unit_test(simple_snapview_clone),
		unit_test(simple_snapview_get),
		unit_test(simple_put_0_1k),
		unit_test(simple_put_inc_version),
		unit_test(simple_snapshot_obj_get),
		unit_test(simple_snapshot_rollback),
		unit_test(simple_snapshot_obj_get),
		unit_test(simple_snapview_get),
		unit_test(simple_snapshot_delete),
		unit_test(simple_snapshot_lookup),
		unit_test(simple_snapview_delete),
		unit_test(simple_snapview_destroy),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

