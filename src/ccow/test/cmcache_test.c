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
#include "../src/libccow/ccow-impl.h"

ccow_t tc, *tc_list;
int dd = 0;

#define NUM_TENANTS		3
int num_tenants_init = 0;

static void
libccowd_setup(void **state)
{
	if(!dd)
		assert_int_equal(ccow_daemon_init(NULL), 0);
	usleep(2 * 1000000L);
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
	je_free(buf);
	tc_list = je_malloc(NUM_TENANTS * sizeof (ccow_t));
	assert_non_null(tc_list);
}

static void
tenant_create(void **state)
{
	assert_non_null(tc);
	int err = ccow_tenant_create(tc, "test1", 6, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(0, 1);
}

static void
tenant_init(void **state)
{
	assert_non_null(tc_list);
	int err = 0;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16384) != -1);
	assert_int_equal(close(fd), 0);

	for (int i = 0; i < NUM_TENANTS; i++) {
		err = ccow_tenant_init(buf, "cltest", 7, "test1", 6, &tc_list[i]);
		if (err) {
			printf("Tenant Init has failed on i = %d\n", i);
			je_free(buf);
			num_tenants_init = i == 0 ? i : i - 1;
			return;
		}
	}
	je_free(buf);
	num_tenants_init = NUM_TENANTS;
}

static void
tenant_delete(void **state)
{
	assert_non_null(tc);
	assert_non_null(tc_list);
	assert_int_equal(ccow_tenant_delete(tc, "test1", 6), 0);
}


static void
libccow_teardown(void **state)
{
	assert_non_null(tc);

	sleep(10);
	for (int i = 0; i < num_tenants_init; i++) {
		ccow_tenant_term(tc_list[i]);
	}
	je_free(tc_list);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state)
{
	if (!dd)
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
		unit_test(tenant_init),
		unit_test(tenant_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
