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

#define	MIN(a, b) (((a) < (b)) ? (a) : (b))
#define	MAX(a, b) (((a) > (b)) ? (a) : (b))

#define	TEST_BUCKET_NAME "test"

static ccow_t tc;
static int dd = 0;
static int runnum = 0;

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
	char *buf;
	int fd;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());

	fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);
	je_free(buf);
}

static void
bucket_create(void **state)
{
	int err;

	assert_non_null(tc);
	err = ccow_bucket_create(tc, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	int err;

	assert_non_null(tc);
	err = ccow_bucket_delete(tc, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
}

static void
put_1k_obj(void **state)
{
	struct iovec iov[1];
	char name[64];
	int i;

	assert_non_null(tc);
	iov[0].iov_len = 1024;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	for (i = 0; i < 1000 ; i ++) {
		sprintf(name, "test-obj-%d-%d", runnum, i);
		put(tc, TEST_BUCKET_NAME, name, &iov[0], 1, 0, NULL, NULL);
	}

	je_free(iov[0].iov_base);
}

static void
delete_1k_obj(void **state)
{
	char name[64];
	int i;

	assert_non_null(tc);
	for (i = 0; i < 1000 ; i ++) {
		sprintf(name, "test-obj-%d-%d", runnum, i);
		delete(tc, TEST_BUCKET_NAME, name, NULL, NULL);
	}
}

static void
run_10min_test(void **state)
{
	int first, last, min, max;
	time_t ts, begin, end;

	first = last = min = max = 0;
	/* Run test for 10 min. */
	ts = time(NULL);
	while (1) {
		begin = time(NULL);
		put_1k_obj(NULL);
		delete_1k_obj(NULL);
		end = time(NULL);

		last = (int)(end - begin);

		min = MIN(min, last);
		max = MAX(max, last);

		if (runnum == 0)
			min = first = last;

		runnum ++;
		if (end > (ts + 600)) {
			printf("Run number %d\n"
			    "First take %d seconds\n"
			    "Last take %d seconds\n"
			    "Min take %d seconds\n"
			    "Max take %d seconds\n",
			    runnum, first, last, min, max);
			return;
		}
	}
}

static void
libccow_teardown(void **state)
{

	assert_non_null(tc);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state)
{

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

		unit_test(run_10min_test),

		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};

	return run_tests(tests);
}

