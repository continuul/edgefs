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
#include "ccow-impl.h"
#include "ccowd.h"

static ccow_t tc;
static ccow_t tc2;
static int daemon_initialized = 0, dd = 0;
static char *config_buf = NULL;

static void
libccowd_setup(void **state)
{
	if (!dd) {
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(2 * 1000000L);
	}
	daemon_initialized = 1;
}

static void
libccow_setup(void **state)
{
	assert_int_equal(daemon_initialized, 1);
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	config_buf = je_calloc(1, 16384);
	assert_non_null(config_buf);
	assert_true(read(fd, config_buf, 16384) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_admin_init(config_buf, "", 1, &tc), 0);
	assert_int_equal(ccow_admin_init(config_buf, "", 1, &tc2), 0);

	/* initialize 0x0 sys object */
	int err = ccow_system_init(tc);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	/* Get request on sysobject */
	get(tc, "", "", NULL, 0, 0, NULL, NULL, NULL);
}

static void
check_guid(void **state)
{
	char *guid;
	assert_non_null(tc);

	guid = ccow_get_system_guid_formatted(tc);
	assert_non_null(guid);
	printf("System GUID: %s\n", guid);
	je_free(guid);
}

static void
cluster_init2(void **state)
{
	int err;
	assert_non_null(tc); assert_non_null(tc2);

	err = ccow_cluster_create(tc2, "cltest2", 8, NULL);
	if (err == -EEXIST)
		assert_int_equal(err, 0);

	/* cleanup the new cluster... */
	assert_int_equal(ccow_cluster_delete(tc2, "cltest2", 8), 0);
}

static void
cluster_init(void **state)
{
	int err;
	assert_non_null(tc); assert_non_null(tc2);

	/* create two clusters!!! */
	err = ccow_cluster_create(tc, "cltest", 7, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	err = ccow_cluster_create(tc2, "cltest2", 8, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	ccow_lookup_t iter;
	err = ccow_cluster_lookup(tc, "cltest", 7, 1, &iter);

	assert_int_equal(err, 0);
	ccow_lookup_release(iter);

	err = ccow_cluster_lookup(tc2, "cltest2", 8, 1, &iter);
	assert_int_equal(err, 0);
	ccow_lookup_release(iter);
}

static void
tenant_create(void **state)
{
	assert_non_null(tc); assert_non_null(tc2);

	/* create two tenants!!! */
	int err  = ccow_tenant_create(tc, "test", 5, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);
	err = ccow_tenant_create(tc2, "test", 5, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	err = ccow_tenant_create(tc, "7d0d2873025a4b09bf109221d814c491", strlen("7d0d2873025a4b09bf109221d814c491") + 1, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);
	err = ccow_tenant_create(tc, "25859eaf477045dba6cbd2071e90ac97", strlen("25859eaf477045dba6cbd2071e90ac97") + 1, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);
	err = ccow_tenant_create(tc, "6309c5fa50cf40b6b5847267d7331d26", strlen("6309c5fa50cf40b6b5847267d7331d26") + 1, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);
	err = ccow_tenant_create(tc, "AUTH_7d0d2873025a4b09bf109221d814c491", strlen("AUTH_7d0d2873025a4b09bf109221d814c491") + 1, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);
	err = ccow_tenant_create(tc, "AUTH_25859eaf477045dba6cbd2071e90ac97", strlen("AUTH_25859eaf477045dba6cbd2071e90ac97") + 1, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);
	err = ccow_tenant_create(tc, "AUTH_6309c5fa50cf40b6b5847267d7331d26", strlen("AUTH_6309c5fa50cf40b6b5847267d7331d26") + 1, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	ccow_lookup_t iter;
	assert_int_equal(ccow_tenant_lookup(tc, NULL, 0, "test", 5, 1, &iter), 0);
	ccow_lookup_release(iter);

	assert_int_equal(ccow_tenant_lookup(tc2, NULL, 0, "test", 5, 1, &iter), 0);
	ccow_lookup_release(iter);

	assert_int_equal(ccow_tenant_lookup(tc2, NULL, 0, "", 1, 2, &iter), 0);
	int tenant_cnt = 0;
	struct ccow_metadata_kv *kv = NULL;
	do {
		kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX,
		    tenant_cnt);
		if(kv == NULL)
			break;
		tenant_cnt++;
	} while (kv != NULL);
	assert_int_equal(tenant_cnt, 2); /* should have "root" and "test" */
	ccow_lookup_release(iter);
}

#define STRESS_TENANT_NUM	20
#define STRESS_BK_NUM		10
static void
tenant_create_more(void **state)
{
	assert_non_null(tc); assert_non_null(tc2);
	assert_int_equal(ccow_tenant_create(tc, "test1", 6, NULL), 0);
	assert_int_equal(ccow_tenant_create(tc, "test2", 6, NULL), 0);

	assert_int_equal(ccow_tenant_delete(tc, "test1", 6), 0);
	assert_int_equal(ccow_tenant_delete(tc, "test2", 6), 0);

	assert_int_equal(ccow_tenant_create(tc2, "test1", 6, NULL), 0);
	assert_int_equal(ccow_tenant_create(tc2, "test2", 6, NULL), 0);

	assert_int_equal(ccow_tenant_delete(tc2, "test1", 6), 0);
	assert_int_equal(ccow_tenant_delete(tc2, "test2", 6), 0);

	printf("Creating %d tenants\n", STRESS_TENANT_NUM);
	char name[100];
	for (int i = 0; i < STRESS_TENANT_NUM; i++) {
		memset(name, 0, 100);
		sprintf(name, "test_%d", i);
		assert_int_equal(ccow_tenant_create(tc, name, strlen(name) + 1, NULL), 0);
		char bkname[100];
		ccow_t tc_name;
		printf("Stressing tenant %s.. \n", name);
		assert_int_equal(ccow_tenant_init(config_buf, "cltest", 7, name, strlen(name) + 1, &tc_name), 0);
		for (int j = 0; j < STRESS_BK_NUM; j++) {
			memset(bkname, 0, 100);
			sprintf(bkname, "bucket_%d", j);
			assert_int_equal(ccow_bucket_create(tc_name, bkname, strlen(bkname) + 1, NULL), 0);
		}
		ccow_tenant_term(tc_name);

	}
	printf("Deleting %d tenants\n", STRESS_TENANT_NUM);
	for (int i = 0; i < STRESS_TENANT_NUM; i++) {
		char bkname[100];
		memset(name, 0, 100);
		sprintf(name, "test_%d", i);
		ccow_t tc_name;
		printf("Stressing tenant %s.. \n", name);
		assert_int_equal(ccow_tenant_init(config_buf, "cltest", 7, name, strlen(name) + 1, &tc_name), 0);
		for (int j = 0; j < STRESS_BK_NUM; j++) {
			memset(bkname, 0, 100);
			sprintf(bkname, "bucket_%d", j);
			assert_int_equal(ccow_bucket_delete(tc_name, bkname, strlen(bkname) + 1), 0);
		}
		assert_int_equal(ccow_tenant_delete(tc, name, strlen(name) + 1), 0);
		ccow_tenant_term(tc_name);
	}
}

static void
cluster_delete(void **state)
{
	assert_non_null(tc); assert_non_null(tc2);
	/* trying to delete non-empty cluster, should result with error */
	assert_int_not_equal(ccow_cluster_delete(tc2, "cltest2", 8), 0);

	/* deleting tenant and trying to delete cluster again */
	assert_int_equal(ccow_tenant_delete(tc2, "test", 5), 0);
	assert_int_equal(ccow_cluster_delete(tc2, "cltest2", 8), 0);

	/* deleting cluster second time, should result in error */
	assert_int_not_equal(ccow_cluster_delete(tc2, "cltest2", 8), 0);
}

static void
libccow_teardown(void **state)
{
	if (config_buf)
		je_free(config_buf);
	assert_non_null(tc); assert_non_null(tc2);
	ccow_tenant_term(tc);
	ccow_tenant_term(tc2);
}

static void
libccowd_teardown(void **state) {
	usleep(200000L);
	if (dd != 1) {
		assert_int_equal(daemon_initialized, 1);
		ccow_daemon_term();
	}
}

int
main(int argc, char **argv)
{
	/*
	 * Parse command line
	 */
	int short_test = 0, opt = 0;

	while ((opt = getopt(argc, argv, "ns")) != -1) {
		switch(opt) {
			case 'n':
				dd = 1;
				daemon_initialized = 1;
				break;

			case 's':
				short_test = 1;
				break;
			default:
				break;
		}
	}

	if (!short_test) {
		const UnitTest tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(check_guid),
			unit_test(cluster_init),
			unit_test(tenant_create),
			unit_test(tenant_create_more),
			unit_test(cluster_delete),
			unit_test(cluster_init2),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		return run_tests(tests);
	} else {
		const UnitTest tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(check_guid),
			unit_test(cluster_init),
			unit_test(tenant_create),
			unit_test(cluster_delete),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		return run_tests(tests);
	}
	return 0;
}
