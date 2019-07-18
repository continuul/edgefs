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

ccow_t tc = NULL;
int dd = 0;
int all = 0;

static void
usage(void)
{
    printf("\n"
           "USAGE:\n"
           "     ./bucket_lookup_test [-n] [-a] \n"
           "\n"
           "    -n   Disable ccowserv startup.\n"
           "\n"
           "    -a   run advanced tests.\n"
           "\n"
           "\n");
    exit(EXIT_SUCCESS);
}

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
bucket_lookup_list_all(void **state)
{
	int err;
	assert_non_null(tc);

	ccow_lookup_t bk;
	err = ccow_bucket_lookup(tc, "", 1, 1, &bk);
	assert_int_equal(err, 0);
	ccow_lookup_release(bk);
}

static void
bucket_lookup_non_existing(void **state)
{
	int err;
	assert_non_null(tc);

	ccow_lookup_t bk;
	err = ccow_bucket_lookup(tc, "lookup_non_existent", 20, 1, &bk);
	if (err) {
		if (bk)
			ccow_lookup_release(bk);
		assert_int_equal(err, -ENOENT);
	}
	else {
		assert_non_null(bk);
		struct ccow_metadata_kv *kv =
			ccow_lookup_iter(bk, CCOW_MDTYPE_NAME_INDEX, 0);
		assert_non_null(kv);
		printf("Additional Bucket(s) Exist: %s\n", kv->key);
		assert_true(strcmp(kv->key, "lookup_non_existent"));
		ccow_lookup_release(bk);
	}
}

static void
bucket_create(void **state)
{
	int err;
	assert_non_null(tc);

	err = ccow_bucket_create(tc, "test", 5, NULL);
	assert_int_equal(err, 0);
}

#define NUM_SYNC_REQS 10
static void
lookup_benchmark(void **state)
{
	uint64_t before;
	uint64_t after;
	uv_fs_t req;
	int i, err;

	assert_non_null(tc);

	/* do the sync benchmark */
	before = uv_hrtime();

	for (i = 0; i < NUM_SYNC_REQS; i++) {
		ccow_lookup_t bk;
		err = ccow_bucket_lookup(tc, "test", 5, 1, &bk);
		assert_int_equal(err, 0);
		ccow_lookup_release(bk);
	}

	after = uv_hrtime();

	printf("%s stats (sync): %.2fs (%s/s)\n", fmt(1.0 * NUM_SYNC_REQS),
	    (after - before) / 1e9,
	    fmt((1.0 * NUM_SYNC_REQS) / ((after - before) / 1e9)));
	fflush(stdout);
}

static void
bucket_delete(void **state)
{
	int err;
	assert_non_null(tc);

	err = ccow_bucket_delete(tc, "test", 5);
	assert_int_equal(err, 0);
}

//advanced tests

static void
bucket_create_adv(void **state)
{
    if(!all)
        return;
    int err;
    assert_non_null(tc);

    err = ccow_bucket_create(tc, "bk1", 4, NULL);
    assert_int_equal(err, 0);
    err = ccow_bucket_create(tc, "bk1-1", 6, NULL);
    assert_int_equal(err, 0);
    err = ccow_bucket_create(tc, "bk1-2", 6, NULL);
    assert_int_equal(err, 0);
    err = ccow_bucket_create(tc, "bk1-3", 6, NULL);
    assert_int_equal(err, 0);
    err = ccow_bucket_create(tc, "bk1-4", 6, NULL);
    assert_int_equal(err, 0);
    err = ccow_bucket_create(tc, "bk1-5", 6, NULL);
    assert_int_equal(err, 0);
    err = ccow_bucket_create(tc, "bk1-6", 6, NULL);
    assert_int_equal(err, 0);
    err = ccow_bucket_create(tc, "bk1-7", 6, NULL);
    assert_int_equal(err, 0);
    err = ccow_bucket_create(tc, "bk1-8", 6, NULL);
    assert_int_equal(err, 0);
    err = ccow_bucket_create(tc, "bk1-9", 6, NULL);
    assert_int_equal(err, 0);
}

static void
bucket_lookup_adv(void **state)
{
    if(!all)
        return;
    int err;
    assert_non_null(tc);

    ccow_lookup_t bk;
    struct ccow_metadata_kv *kv;
    int found = 0;
    err = ccow_bucket_lookup(tc, "bk1", 4, 1, &bk);
    assert_int_equal(err, 0);
    while ((kv = (struct ccow_metadata_kv *)ccow_lookup_iter(bk,
                CCOW_MDTYPE_NAME_INDEX, -1))) {
        if (!kv->key_size)
        continue;
        found ++;
    }
    assert_int_equal(found, 10);

    found = 0;
    err = ccow_bucket_lookup(tc, "bk1-", 5, 1, &bk);
    assert_int_equal(err, 0);
    while ((kv = (struct ccow_metadata_kv *)ccow_lookup_iter(bk,
                CCOW_MDTYPE_NAME_INDEX, -1))) {
        if (!kv->key_size)
        continue;
        found ++;
    }
    assert_int_equal(found, 9);

}

static void
bucket_delete_adv(void **state)
{
    if(!all)
        return;
    int err;
    assert_non_null(tc);

    err = ccow_bucket_delete(tc, "bk1", 4);
    assert_int_equal(err, 0);
    err = ccow_bucket_delete(tc, "bk1-1", 6);
    assert_int_equal(err, 0);
    err = ccow_bucket_delete(tc, "bk1-2", 6);
    assert_int_equal(err, 0);
    err = ccow_bucket_delete(tc, "bk1-3", 6);
    assert_int_equal(err, 0);
    err = ccow_bucket_delete(tc, "bk1-4", 6);
    assert_int_equal(err, 0);
    err = ccow_bucket_delete(tc, "bk1-5", 6);
    assert_int_equal(err, 0);
    err = ccow_bucket_delete(tc, "bk1-6", 6);
    assert_int_equal(err, 0);
    err = ccow_bucket_delete(tc, "bk1-7", 6);
    assert_int_equal(err, 0);
    err = ccow_bucket_delete(tc, "bk1-8", 6);
    assert_int_equal(err, 0);
    err = ccow_bucket_delete(tc, "bk1-9", 6);
    assert_int_equal(err, 0);
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
    if(!dd){
        assert_non_null(tc);
        ccow_daemon_term();
    }
}

int
main(int argc, char **argv)
{
    if (argc >= 2) {
        int opt;
        while ((opt = getopt(argc, argv, "na")) != -1) {
            switch(opt) {

            case 'n':
                dd = 1;
                break;

            case 'a':
                all = 1;
                break;
            default:
                usage();
            }
        }
    }

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_lookup_non_existing),
		unit_test(bucket_create),
		unit_test(bucket_lookup_list_all),
		unit_test(lookup_benchmark),
		unit_test(bucket_delete),
        unit_test(bucket_create_adv),
        unit_test(bucket_lookup_adv),
        unit_test(bucket_delete_adv),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
