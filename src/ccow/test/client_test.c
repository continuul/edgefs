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

#define BUCKET_NUM	16
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
libccow_bkcreate(void **state)
{
	assert_non_null(tc);
	int i;
	for (i = 0; i < BUCKET_NUM; i++) {
		char bucket_name[16];
		sprintf(bucket_name, "test-%d", i);
		int err = ccow_bucket_create(tc, bucket_name,
		    strlen(bucket_name) + 1, NULL);
		if (err != -EEXIST)
			assert_int_equal(err, 0);
	}
	printf("Created: %d buckets\n", BUCKET_NUM);
}

static void
libccow_bkdelete(void **state)
{
	assert_non_null(tc);
	int i;
	for (i = 0; i < BUCKET_NUM; i++) {
		char bucket_name[16];
		sprintf(bucket_name, "test-%d", i);
		int err = ccow_bucket_delete(tc, bucket_name,
			    strlen(bucket_name) + 1);
		assert_int_equal(err, 0);
	}
	printf("Deleted: %d buckets\n", BUCKET_NUM);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state) {
    if(!dd){
        assert_non_null(tc);
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
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(libccow_bkcreate),
		unit_test(libccow_bkdelete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
