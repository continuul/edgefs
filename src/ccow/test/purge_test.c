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

#define TEST_BUCKET_NAME	"purge-bucket-test"
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

static void
object_delete(void **state)
{
	assert_non_null(tc);
	delete(tc, TEST_BUCKET_NAME, "test-1v-obj1", NULL, NULL);
	delete(tc, TEST_BUCKET_NAME, "test-10v-obj1", NULL, NULL);
}

static void
put_1_version(void **state)
{
	int err;
	uint16_t num_vers;
	assert_non_null(tc);

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 3, &c);
	assert_int_equal(err, 0);

	num_vers = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "test-1v-obj1", NULL, 0, 0);
	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	num_vers = 0;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "test-1v-obj1", NULL, 0, 0);
	err = ccow_wait(c, 1);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "test-1v-obj1", NULL, 0, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
}

#define NUMBER_OF_ITERATIONS	12
static void
put_10_versions(void **state)
{
	uint16_t *buf = je_malloc(4096);
	assert_non_null(buf);

	assert_non_null(tc);
	ccow_completion_t c;
	int err = ccow_create_completion(tc, NULL, NULL,
		NUMBER_OF_ITERATIONS, &c);
	assert_int_equal(err, 0);

	uint16_t num_vers = 10;

	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
		(void *)&num_vers, NULL);
	assert_int_equal(err, 0);
	struct iovec vec = { buf, 4096 };
	uint16_t i;

	for (i = 0; i < NUMBER_OF_ITERATIONS; ++i) {
		*buf = i;
		put_simple(c, TEST_BUCKET_NAME, "test-10v-obj1", &vec, 1, 0);
		err = ccow_wait(c, i);
		assert_int_equal(err, 0);
	}

	err = ccow_wait(c, -1);
	je_free(buf);
	assert_int_equal(err, 0);
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
		unit_test(put_1_version),
		unit_test(object_delete),
		unit_test(put_10_versions),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
