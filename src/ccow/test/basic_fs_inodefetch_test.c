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
#include <ccowfsio.h>
#include <cmocka.h>

ccow_t tc = NULL;
static ci_t *ci;
int dd = 0;

#define DIR_NAME "inode-fetch"
#define FILE_NAME "foo"

inode_t dir_inode;
inode_t file_inode;

static void
test_setup(void **state)
{
    assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, DIR_NAME, 0755, 1, 1, NULL), 0);
    assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, DIR_NAME, &dir_inode), 0);

    assert_int_equal(ccow_fsio_touch(ci, dir_inode, FILE_NAME, 0755, 0, 0, &file_inode), 0);
	printf("dir inode:%ju file inode:%ju\n", dir_inode, file_inode);

}

static void
test_fetch_inode(void **state)
{
    struct stat stat;

    printf("Fetch sync\n");
    assert_int_equal(testonly_remove_inode_from_cache(ci, file_inode), 0);
    assert_int_equal(testonly_fetch_inode(ci, file_inode, 1), 0);
    assert_int_equal(ccow_fsio_get_file_stat(ci, file_inode, &stat), 0);


    printf("Fetch async\n");
    assert_int_equal(testonly_remove_inode_from_cache(ci, file_inode), 0);
    assert_int_equal(testonly_fetch_inode(ci, file_inode, 0), 0);
    assert_int_equal(ccow_fsio_get_file_stat(ci, file_inode, &stat), 0);
}

static void
test_fetch_not_existing_inode(void **state)
{
    struct stat stat;
    inode_t dummy = 3739034979228601;

    printf("Fetch sync - non existing inode : %lu\n", (uint64_t)dummy);
    assert_int_equal(testonly_fetch_inode(ci, dummy, 1), ENOENT);

    printf("Fetch async - non existing inode : %lu\n", dummy);
    assert_int_equal(testonly_fetch_inode(ci, dummy, 0), 0);
    assert_int_equal(ccow_fsio_get_file_stat(ci, dummy, &stat), ENOENT);
}

static void
test_fetch_deleted_inode(void **state)
{
    struct stat stat;
    void *inode_ref = NULL;
    void *deleted_inode_ref = NULL;

    printf("Fetch - deleted inode\n");
    assert_int_equal(testonly_get_inode_ref(ci, file_inode, &inode_ref), 0);
    assert_int_equal(ccow_fsio_get_file_stat(ci, file_inode, &stat), 0);
    assert_int_equal(ccow_fsio_delete(ci, dir_inode, FILE_NAME), 0);

	// Getting new ref should not be possible
    assert_int_equal(testonly_get_inode_ref(ci, file_inode, &deleted_inode_ref), ENOENT);
    assert_int_equal(testonly_remove_inode_from_cache_by_ref(ci, inode_ref), 0);

    // Deleted file. Should not be possible to fetch the inode
    assert_int_equal(testonly_fetch_inode(ci, file_inode, 1), ENOENT);
    assert_int_equal(ccow_fsio_get_file_stat(ci, file_inode, &stat), ENOENT);

    // This is the last ref put on the object, it will be deleted.
    assert_int_equal(testonly_put_inode_ref(ci, inode_ref), 0);
}

static void
test_cleanup(void **state)
{
    assert_int_equal(ccow_fsio_delete(ci, dir_inode, FILE_NAME), ENOENT);
    assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, DIR_NAME), 0);
}

static void
libccowfsio_setup(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	assert_int_equal(ccow_fsio_init(), 0);
	ci = ccow_fsio_ci_alloc();

	assert_int_equal(ccow_fsio_create_export(ci, "cltest/test/test", path, 4096, NULL, NULL), 0);
}

static void
libccowfsio_teardown(void **state)
{
	ccow_fsio_delete_export(ci);
	ccow_fsio_ci_free(ci);
	ccow_fsio_term();
}

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
libccow_bucket_create(void **state)
{
    assert_non_null(tc);

	ccow_completion_t c = NULL;
	uint32_t cs = 1024 * 1024;

	int err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert(!err);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
		(void *) &cs, NULL);
	assert(!err);

    err = ccow_bucket_create(tc, "test", 5, c);
	if (err != EEXIST)
		assert_int_equal(err, 0);
}

static void
libccow_bucket_delete(void **state)
{
    int err;
    assert_non_null(tc);

    err = ccow_bucket_delete(tc, "test", 5);
    assert_int_equal(err, 0);
}

static void
libccow_teardown(void **state)
{
    assert_non_null(tc);
    ccow_tenant_term(tc);
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
        unit_test(libccow_bucket_create),
		unit_test(libccowfsio_setup),

		unit_test(test_setup),
		unit_test(test_fetch_inode),
		unit_test(test_fetch_not_existing_inode),
		unit_test(test_fetch_deleted_inode),
		unit_test(test_cleanup),

		unit_test(libccowfsio_teardown),
		unit_test(libccow_bucket_delete),
        unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
