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

#include <openssl/md5.h>

#define	PATTERN_BUFFER_SZ	(128 * 1024 * 1024)
#define	UNALIGNED_PATTERN_SZ	200000
#define CHUNK_X_SZ 100000
#define CHUNK_Y_SZ 40000
#define CHUNK_Z_SZ 120000

#define	NUM_OF_NODES		256
#define	NUM_OF_FLAT_NODES	NUM_OF_NODES
#define	NUM_OF_DEEP_NODES	NUM_OF_NODES

#define TEST_BUCKET	"test"

unsigned char pattern_md5[MD5_DIGEST_LENGTH];
fsio_fsinfo_t fs_info;
ccow_t tc = NULL;
static ci_t *ci;
static char *testfile = "/BIGFILE";
char *pattern_buf;
int debug = 1;
int dd = 0;

static void
test_fsinfo_before(void **state)
{
	fsio_fsinfo_t fsinfo;
	int err;

	err = ccow_fsio_fsinfo(ci, &fsinfo);
	assert_int_equal(err, 0);
	printf("FS stats at the beginning\n"
	    "\tbytes { total: %lu, free: %lu, avail: %lu }\n"
	    "\tfiles { total: %lu, free: %lu, avail: %lu }\n",
	    fsinfo.total_bytes, fsinfo.free_bytes, fsinfo.avail_bytes,
	    fsinfo.total_files, fsinfo.free_files, fsinfo.avail_files);
	memcpy(&fs_info, &fsinfo, sizeof(fs_info));
}

static void
test_fsinfo_after(void **state)
{
	fsio_fsinfo_t fsinfo;
	int err;

	err = ccow_fsio_fsinfo(ci, &fsinfo);
	assert_int_equal(err, 0);
	printf("FS stats at the end\n"
	    "\tbytes { total: %lu, free: %lu, avail: %lu }\n"
	    "\tfiles { total: %lu, free: %lu, avail: %lu }\n",
	    fsinfo.total_bytes, fsinfo.free_bytes, fsinfo.avail_bytes,
	    fsinfo.total_files, fsinfo.free_files, fsinfo.avail_files);
	assert_int_equal(fs_info.free_bytes, fsinfo.free_bytes);
	assert_int_equal(fs_info.free_files, fsinfo.free_files);
}

static void
test_256_files_flat(void **state)
{
	inode_t inode;
	char name[32];
	int err, i;

	printf("===================== %s ======================\n", __func__);
	for (i = 0; i < NUM_OF_FLAT_NODES; i++) {
		sprintf(name, "test%d", i);
		err = ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, name, 0750, 0, 0, &inode);
		if (err == EEXIST)
			err = 0;
		assert_int_equal(err, 0);
		err = ccow_fsio_touch(ci, inode, "testfile", 0644, 1, 2, NULL);
		assert_int_equal(err, 0);
	}
}

static void
test_256_files_deep(void **state)
{
	inode_t inode;
	int err, i;

	printf("===================== %s ======================\n", __func__);
	/* Start from root (inode CCOW_FSIO_ROOT_INODE). */
	inode = CCOW_FSIO_ROOT_INODE;
	for (i = 0; i < NUM_OF_DEEP_NODES; i++) {
		err = ccow_fsio_mkdir(ci, inode, "test", 0770, 0, 0, &inode);
		if (err == EEXIST)
			err = 0;
		assert_int_equal(err, 0);
	}
	err = ccow_fsio_touch(ci, inode, "deep-testfile", 0644, 1, 2, NULL);
}

static void
test_file_flat(void **state)
{
	struct stat stat;
	inode_t inode;
	int err;

	printf("===================== %s ======================\n", __func__);
	err = ccow_fsio_find(ci, "/test7", &inode);
	assert_int_equal(err, 0);
	err = ccow_fsio_get_file_stat(ci, inode, &stat);
	assert_int_equal(err, 0);

	assert_int_equal((stat.st_mode & 0777), 0750);
	assert(S_ISDIR(stat.st_mode));
}

static void
test_file_deep(void **state)
{
	struct stat stat;
	inode_t inode;
	int err;

	printf("===================== %s ======================\n", __func__);
	err = ccow_fsio_find(ci, "/test/test/test/test", &inode);
	assert_int_equal(err, 0);
	err = ccow_fsio_get_file_stat(ci, inode, &stat);
	assert_int_equal(err, 0);

	assert_int_equal((stat.st_mode & 0777), 0770);
	assert(S_ISDIR(stat.st_mode));
}

int
recursive_delete(inode_t parent, fsio_dir_entry *dir_entry, uint64_t count,
    void *ptr)
{
	int err = 0;
	uint64_t i;

	for (i=0; i< count; i++) {
		if (dir_entry[i].name[0] == '.' && (dir_entry[i].name[1] == '\0' ||
		    (dir_entry[i].name[1] == '.' && dir_entry[i].name[2] == '\0')))
			continue;

		if (ccow_fsio_is_dir(ci, dir_entry[i].inode)) {
			bool eof;
			ccow_fsio_readdir_cb4(ci, dir_entry[i].inode, recursive_delete, 0, NULL, &eof);
		}
		if (dir_entry[i].inode != CCOW_FSIO_ROOT_INODE) {
			err = ccow_fsio_delete(ci, parent, dir_entry[i].name);
			assert(err == 0);
		}
	}

	return (0);
}

static void
test_recursive_delete(void **state)
{
	inode_t inode;

	printf("===================== %s ======================\n", __func__);
	bool eof;
	ccow_fsio_readdir_cb4(ci, CCOW_FSIO_ROOT_INODE, recursive_delete, 0, NULL, &eof);
}

static void
libccowfsio_setup(void **state)
{
	assert_int_equal(ccow_fsio_init(), 0);
	ci = ccow_fsio_ci_alloc();

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());

	assert_int_equal(ccow_fsio_create_export(ci, "cltest/test/" TEST_BUCKET,
			path, 4096, NULL, NULL), 0);
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

	err = ccow_bucket_create(tc, TEST_BUCKET, strlen(TEST_BUCKET)+1, c);
	if (err != EEXIST)
		assert_int_equal(err, 0);
}

static void
libccow_bucket_delete(void **state)
{
	int err;
	assert_non_null(tc);

	err = ccow_bucket_delete(tc, TEST_BUCKET, strlen(TEST_BUCKET)+1);
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

		unit_test(test_fsinfo_before),

		unit_test(test_256_files_flat),
		unit_test(test_256_files_deep),
		unit_test(test_file_flat),
		unit_test(test_file_deep),
		unit_test(test_recursive_delete),

		unit_test(test_fsinfo_after),

		unit_test(libccowfsio_teardown),
		unit_test(libccow_bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
