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


#define	TEST_BUCKET_NAME "blo_test"
enum {
	TEST_OBJ_QTY = 100,
	/// Must be 2 or larger
	TEST_ITEMS_PER_ITER = 30
};

static ccow_t tc;
static int dd = 0;

static void
libccowd_setup(void **state)
{
	if(!dd){
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(2 * 1000000L);
	}
}

static void
libccowd_teardown(void **state)
{
	if(!dd)
		ccow_daemon_term();
}

static void
libccow_setup(void **state)
{
	char *buf;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);

	buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);
	je_free(buf);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	ccow_tenant_term(tc);
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

	usleep(1000000L);
}

static void
bucket_delete(void **state)
{
	int err;

	assert_non_null(tc);
	err = ccow_bucket_delete(tc, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
	usleep(1000000L);
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

	for (i = 0; i < TEST_OBJ_QTY; i ++) {
		sprintf(name, "test-obj-%d", i);
		put(tc, TEST_BUCKET_NAME, name, &iov[0], 1, 0, NULL, NULL);
	}

	je_free(iov[0].iov_base);

	/** @warning It looks like we need to wait for TRLOG tick */
	usleep(21*1000000L);
}

static void
delete_1k_obj(void **state)
{
	char name[64];
	int i;

	assert_non_null(tc);
	for (i = 0; i < TEST_OBJ_QTY; i ++) {
		sprintf(name, "test-obj-%d", i);
		delete(tc, TEST_BUCKET_NAME, name, NULL, NULL);
	}

	/** @warning It looks like we need to wait for TRLOG tick */
	usleep(21*1000000L);
}


static char *
list_iter(void **state, unsigned *counter, char *last_key)
{
	int err;
	struct iovec iov;

	ccow_lookup_t iter = NULL;
	ccow_completion_t c = NULL;

	assert_non_null(tc);

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	iov.iov_base = last_key ? je_strdup(last_key) : NULL;
	iov.iov_len = last_key ? strlen(last_key) + 1 : 0;

	err = ccow_get_list(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			ccow_empty_str, 1, c, &iov, 1, TEST_ITEMS_PER_ITER, &iter);
	if(err) {
		ccow_release(c);
		assert_int_equal(err, 0);
	}

	err = ccow_wait(c, -1);
	if(err) {
		if (iter)
			ccow_lookup_release(iter);
		assert_int_equal(err, 0);
	}

	if (!last_key)
		last_key = je_strdup("");

	fflush(stdout);
	int pos = (last_key[0] == 0) ? 0 : 1;
	for (unsigned i=pos; i<TEST_ITEMS_PER_ITER; i++) {
		struct ccow_metadata_kv *kv;

		kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, i);
		je_free(last_key);
		if (kv == NULL) {
			/* End of lookup object. */
			last_key = NULL;
			break;
		}

		printf("[%03u] %s\n", *counter, kv->key);
		last_key = je_strdup(kv->key);
		(*counter) ++;
	}
	fflush(stdout);

	if (iter) {
		ccow_lookup_release(iter);
		iter = NULL;
	}

	je_free(iov.iov_base);

	return last_key;
}

static void
list_1k_obj(void **state)
{
	unsigned counter = 0;
	char *last_key = /*NULL*/ je_strdup("");

	do {
		last_key = list_iter(state, &counter, last_key);
	} while (last_key != NULL);

	assert_int_equal(counter, TEST_OBJ_QTY);
	usleep(1000000L);
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

		unit_test(put_1k_obj),
		unit_test(list_1k_obj),
		unit_test(delete_1k_obj),

		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};

	return run_tests(tests);
}
