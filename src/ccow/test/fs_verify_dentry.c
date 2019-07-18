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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <ccow.h>
#include <ccowd.h>
#include <cmocka.h>
#include <ccowfsio.h>
#include "common.h"

#define TEST_CLUSTER "cltest"
#define TEST_TENANT "test"
#define TEST_BUCKET "fsio_test"
#define FSIO_EXPORT_PATH "cltest/test/fsio_test"

/* This test is to verify directory entry vai libccow */
static ccow_t cl = NULL;
static ci_t *ci;
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
libccowd_teardown(void **state)
{
	if (!dd) {
		ccow_daemon_term();
	}
}

static void libccow_setup(void **state) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
    int fd = open(path, O_RDONLY);
    assert_true(fd >= 0);
    char *buf = je_calloc(1, 16384);
    assert_non_null(buf);
    assert_true(read(fd, buf, 16383) != -1);
    assert_int_equal(close(fd), 0);
    assert_int_equal(ccow_tenant_init(buf, TEST_CLUSTER, strlen(TEST_CLUSTER) + 1, TEST_TENANT, strlen(TEST_TENANT) + 1, &cl), 0);
    je_free(buf);
}

static void libccow_teardown(void **state) {
    assert_non_null(cl);
    ccow_tenant_term(cl);
}

static void bucket_create(void **state) {
    assert_non_null(cl);
	ccow_completion_t c = NULL;
	uint32_t cs = 1024 * 1024;

	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert(!err);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
			(void *) &cs, NULL);
	assert(!err);

    err = ccow_bucket_create(cl, TEST_BUCKET,
        strlen(TEST_BUCKET) + 1, c);
    if (err != -EEXIST)
        assert_int_equal(err, 0);
}

static void bucket_delete(void **state) {
    assert_non_null(cl);
    int err = ccow_bucket_delete(cl, TEST_BUCKET,
        strlen(TEST_BUCKET) + 1);
    if (err != -EEXIST)
        assert_int_equal(err, 0);
}

static void
libccowfsio_setup(void **state)
{
    assert_int_equal(ccow_fsio_init(), 0);
    ci = ccow_fsio_ci_alloc();
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
    assert_int_equal(ccow_fsio_create_export(ci, FSIO_EXPORT_PATH, path, 4096, NULL, NULL), 0);
}

static void
libccowfsio_teardown(void **state)
{
    ccow_fsio_delete_export(ci);
    ccow_fsio_ci_free(ci);
    ci = NULL;
    ccow_fsio_term();
}

static void
create_dir_entry(void **state)
{
	inode_t inode;
	char name[32], shard_name[128];
	int err;

	sprintf(name, "flat_file");
	err = ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE,
				name, 0750, 0, 0, &inode);
	assert_int_equal(err, 0);
	printf("Added file: %s to: %s\n", name, ROOT_INODE_STR);
}

static void
test_dir_entry(void **state)
{
	char name[32], shard_name[128];
	int err;

	sprintf(name, "flat_file");
	/* Get root shard */
	test_get_shard_name(ROOT_INODE_STR, name,
				shard_name, FSIO_DIR_SHARD_COUNT);
	
	printf("Shard name: %s\n", shard_name);

	ccow_completion_t c;
	ccow_lookup_t iter;

	printf("== Verify via libccow ==\n");
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	char buf[65536];
	struct iovec _get_iov = { .iov_base = "", .iov_len = 1 };

	printf("Listing: %s\n", shard_name);
	err = ccow_get_list(TEST_BUCKET, strlen(TEST_BUCKET) + 1,
			    shard_name, strlen(shard_name) + 1,
			    c, &_get_iov, 1, 10, &iter);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
	ccow_lookup_release(iter);

	printf("Deleting file: %s\n", name);
	err = ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, name);
	assert_int_equal(err, 0);
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
		unit_test(libccowfsio_setup),
		unit_test(create_dir_entry),
		unit_test(libccowfsio_teardown),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown),
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(libccowfsio_setup),
		unit_test(test_dir_entry),
		unit_test(libccowfsio_teardown),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
