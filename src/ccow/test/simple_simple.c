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
ccow_t cl = NULL, tc = NULL;

char *TEST_ENV = NULL;

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
bucket_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
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
/*
 * =======================================================================
 *		Put Test Sync, Fixedmap 3x4, bs=4k
 * =======================================================================
 */
#define SIMPLE_TEST_OID		"simple-test"
#define SIMPLE_TEST_OID3	"abcdefg_3"
#define SIMPLE_TEST_BS		4096
#define SIMPLE_TEST_OBJECTS		500
static void
objects_create(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = SIMPLE_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);


	for (int i = 0; i < SIMPLE_TEST_OBJECTS; i++) {
		char names[1024];
		snprintf(names, 1024, "abcdefg_%d", i);
		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);
		put_simple(c, TEST_BUCKET_NAME, names, &iov[0], 1, 0);
		err = ccow_wait(c, -1);
		assert_int_equal(err, 0);
	}
	je_free(iov[0].iov_base);
}

static void
simple_delete_list(void **state)
{
	int iovcnt = 1;
	struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);

	iov[0].iov_base = je_calloc(1, 1024);
	assert_non_null(iov[0].iov_base);
	snprintf(iov[0].iov_base, 1024, "%s", SIMPLE_TEST_OID3);
	iov[0].iov_len = strlen(iov[0].iov_base) + 1;
	printf("Removing: %s \n", (char *)iov[0].iov_base);

	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_delete_list(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    "", 1, c, iov, 1);
	if (err != 0) {
		printf("ccow_wait 1eturned %d, expected %d \n", err, 0);
	}

	err = ccow_wait(c, -1);
	if (err != 0) {
		printf("ccow_wait returned %d, expected %d \n", err, 0);
	}
	je_free(iov[0].iov_base);
	je_free(iov);
}


static void
simple_insert_list(void **state)
{
	int iovcnt = 1;
	struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);

	iov[0].iov_base = je_calloc(1, 1024);
	assert_non_null(iov[0].iov_base);
	snprintf(iov[0].iov_base, 1024, "%s", SIMPLE_TEST_OID3);
	iov[0].iov_len = strlen(iov[0].iov_base) + 1;
	printf("Updating Bucket with following: %s \n", (char *)iov[0].iov_base);

	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_insert_list(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    "", 1, c, iov, 1);
	if (err != 0) {
		printf("ccow_wait returned %d, expected %d \n", err, 0);
	}

	err = ccow_wait(c, -1);
	if (err != 0) {
		printf("ccow_wait returned %d, expected %d \n", err, 0);
	}
	je_free(iov[0].iov_base);
	je_free(iov);
}



static void
objects_delete(void **state)
{
	assert_non_null(cl);
	for (int i = 0; i < SIMPLE_TEST_OBJECTS; i++) {
		char names[1024];
		snprintf(names, 1024, "abcdefg_%d", i);
		delete(cl, TEST_BUCKET_NAME, names, NULL, NULL);
	}
}

static void
md_retrieve_bucket(void **state)
{
	assert_non_null(cl);
	int err;

	for (int i = 0; i < 5; i++) {
		ccow_lookup_t iter;
		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		char buf[65536];
		struct iovec iov = { .iov_base = buf };
		memcpy(iov.iov_base, "", 0);
		iov.iov_len = 0;
		err = ccow_get_list(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1, "", 1, c, &iov, 1, 10000, &iter);
		if (err) {
			ccow_release(c);
			return;
		}

		err = ccow_wait(c, -1);
		dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
		ccow_lookup_release(iter);
		usleep(5000000);		// sleep 5s
	}
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

int
main(int argc, char **argv)
{
	TEST_ENV = getenv("NEDGE_ENV");
	if (!TEST_ENV)
		TEST_ENV = "production";
	const UnitTest tests[] = {
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(simple_insert_list),
		unit_test(objects_create),
		unit_test(simple_delete_list),
		unit_test(objects_delete),
		unit_test(md_retrieve_bucket),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
	};
	return run_tests(tests);
}

