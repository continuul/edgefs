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

#define CLUSTER		"cltest4"
#define TENANT		"test4"
#define BUCKET	"simple-get-bucket-test"
#define OID		"simple-test"
#define BLOCK_SIZE		4096

ccow_t tc = NULL, tc1 = NULL;
char *buf = NULL;
int dd = 0;
static void
libccowd_setup(void **state)
{
    if (!dd) {
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
	buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_admin_init(buf, "", 1, &tc), 0);
}

static void
bucket_create(void **state)
{
	assert_non_null(tc1);
	int err = ccow_bucket_create(tc1, BUCKET,
	    strlen(BUCKET) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(tc1);
	int err = ccow_bucket_delete(tc1, BUCKET,
	    strlen(BUCKET) + 1);
	assert_int_equal(err, 0);
}

static void
simple_put_0_4k(void **state)
{
	assert_non_null(tc1);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = BLOCK_SIZE;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	ccow_completion_t c;
	err = ccow_create_completion(tc1, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	put_simple(c, BUCKET, OID, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	je_free(iov[0].iov_base);
	asleep();
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc1);
	assert_non_null(tc);
	if (buf)
		je_free(buf);
	ccow_tenant_term(tc);
	ccow_tenant_term(tc1);
}

static void
libccowd_teardown(void **state) {
    if(!dd) {
        assert_non_null(tc1);
        ccow_daemon_term();
    }
}

static void
cluster_create(void **state)
{
	int err;
	assert_non_null(tc);
	err = ccow_cluster_create(tc, CLUSTER, strlen(CLUSTER) + 1, NULL);
	if (err == -EEXIST)
		assert_int_equal(err, 0);
}

static void
cluster_delete(void **state)
{
	int err;
	/* cleanup the new cluster... */
	assert_int_equal(ccow_cluster_delete(tc, CLUSTER, strlen(CLUSTER) + 1), 0);
}

static void
tenant_delete(void **state)
{
	assert_non_null(tc);
	ccow_tenant_delete(tc, TENANT, strlen(TENANT) + 1);
}

static void
tenant_create(void **state)
{
	assert_non_null(tc);
	assert_int_equal(ccow_tenant_create(tc, TENANT, strlen(TENANT) + 1, NULL), 0);
	assert_int_equal(ccow_tenant_init(buf, CLUSTER, strlen(CLUSTER) + 1,
		    TENANT, strlen(TENANT) + 1, &tc1), 0);
}

static int
validate_data(char *cid, char *tid, char *bid, char *oid)
{
	int err;
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter;
        err = ccow_admin_pseudo_get(cid, strlen(cid) + 1, tid == NULL ? "" : tid,
	    tid == NULL ? 1 : strlen(tid) + 1, bid == NULL ? "" : bid,
	    bid == NULL ? 1 : strlen(bid) + 1, "", 1, NULL, 0, 0, CCOW_GET, c, &iter);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	void *t;
	uint64_t logical_size = 0, num_objs = 0;
	struct ccow_metadata_kv *kv = NULL;
	do {
		t = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1);
		kv = (struct ccow_metadata_kv *)t;
		if (kv == NULL)
			break;
		if (strcmp(RT_SYSKEY_LOGICAL_SIZE, (const char *)kv->key) == 0)
			logical_size = *(uint64_t *)kv->value;
		if (strcmp(RT_SYSKEY_OBJECT_COUNT, (const char *)kv->key) == 0)
			num_objs = *(uint64_t *)kv->value;
	} while (kv != NULL);
	printf(" Expected Logical Size: %lu\n Received Logical Size: %lu.\n Expected Num Objs: %lu\n Received Num Objs: %lu.\n", (uint64_t)BLOCK_SIZE, logical_size, 1LU, num_objs);
	if (logical_size < BLOCK_SIZE || logical_size > 2 * BLOCK_SIZE)
		err = (tid == NULL ? 1 : (bid == NULL ? 2 : 3));
	ccow_lookup_release(iter);
	if (num_objs != 1)
		err = -1;
	return err;
}

static void
validate_acct(void **state)
{
	assert_non_null(tc1);
	usleep(15000000);

	printf("Tenant : \n");
	validate_data(CLUSTER, TENANT, NULL, NULL);
	printf("Bucket : \n");
	validate_data(CLUSTER, TENANT, BUCKET, NULL);

}

static void
object_delete(void **state)
{
	assert_non_null(tc1);
	delete(tc1, BUCKET, OID, NULL, NULL);
	usleep(15000000);
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
		unit_test(cluster_create),
		unit_test(tenant_create),
		unit_test(bucket_create),
		unit_test(simple_put_0_4k),
		unit_test(validate_acct),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(tenant_delete),
		unit_test(cluster_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

