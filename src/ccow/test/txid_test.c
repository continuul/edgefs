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

#define TEST_BUCKET_NAME	"txid-bucket-test"
ccow_t cl;
int dd = 0;

uint64_t b_initial_version = 0;
uint64_t b_updated_version = 0;

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

static void
txid_test__init_0_1k(void **state)
{
	assert_non_null(cl);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter;
	get_simple(c, TEST_BUCKET_NAME, "", NULL, 0, 0, &iter);

	err = ccow_wait(c, 0);
	if (iter)
		ccow_lookup_release(iter);
	if (err == -ENOENT) {
		err = ccow_bucket_create(cl, TEST_BUCKET_NAME,
		    strlen(TEST_BUCKET_NAME) + 1, NULL);
		assert_int_equal(err, 0);
	}
}

static uint64_t
txid_test_verify_txid(ccow_lookup_t iter, uint64_t txid_prev)
{
	uint64_t txid_new = 0;
	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, pos++))) {
		if (kv->type == CCOW_KVTYPE_UINT64)
			if (strcmp(kv->key, "ccow-tx-generation-id") == 0) {
				txid_new = *(uint64_t *)kv->value;
				if (txid_prev != 0)
					assert_int_equal(txid_new, txid_prev);
				return txid_new;
			}
	}
	return txid_new;
}

#define NUM_TESTS 100
static void
txid_test__md_retrieve_10000_1k(void **state)
{
	assert_non_null(cl);
	int err;

	uint64_t txid_prev = 0;
	uint64_t txid_new = 0;
	ccow_lookup_t iter;
	for (int i = 0; i < NUM_TESTS; i++)
	{
		get(cl, TEST_BUCKET_NAME, "", NULL, 0, 0, NULL, NULL, &iter);
		txid_new = txid_test_verify_txid(iter, txid_prev);
		txid_prev = txid_new;
		if (iter)
			ccow_lookup_release(iter);
	}
	printf("TXID: %lu  NUM_TESTS: %d\n", txid_new, NUM_TESTS);
	if (!b_initial_version)
		b_initial_version = txid_new;
	else {
		if (b_updated_version != b_initial_version)
			b_updated_version = txid_new;
	}
}

static void
txid_test__md_retrieve_deleted(void **state)
{
	assert_non_null(cl);
	int err;

	uint64_t txid_prev = 0;
	uint64_t txid_new = 0;
	ccow_lookup_t iter;
	for (int i = 0; i < NUM_TESTS; i++)
	{
		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		err = ccow_get(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1, "", 1, c, NULL, 0, 0, &iter);
		assert_int_equal(err, 0);
		err = ccow_wait(c, -1);
		assert_int_equal(err, -ENOENT);
		if (iter)
			ccow_lookup_release(iter);
	}
}

static void
txid_test__verify_bucket_version_update(void **state)
{
	printf("Orig: %lu, Updated: %lu\n", b_initial_version, b_updated_version);
	assert_int_equal((b_updated_version - b_initial_version), 2);
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
		unit_test(txid_test__init_0_1k),
		unit_test(txid_test__md_retrieve_10000_1k),
		unit_test(bucket_delete),
		unit_test(txid_test__md_retrieve_deleted),
		unit_test(txid_test__init_0_1k),
		unit_test(txid_test__md_retrieve_10000_1k),
		unit_test(txid_test__verify_bucket_version_update),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
