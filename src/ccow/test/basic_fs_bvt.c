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

#define CCOW_JSON "%s/etc/ccow/ccow.json"
#define TEST_CLUSTER "cltest"
#define TEST_TENANT "test"
#define TEST_BUCKET "fsio_test"
#define FSIO_EXPORT_PATH "cltest/test/fsio_test"
#define TEST_BUCKET2 "fsio_test2"
#define FSIO_EXPORT_PATH2 "cltest/test/fsio_test2"
#define TEST_BUCKET3 "fsio_test3"
#define FSIO_EXPORT_PATH3 "cltest/test/fsio_test3"

#define NUM_OF_FLAT_DIRS    11
#define NUM_OF_DEEP_DIRS    11
#define NUM_OF_FLAT_FILE    11

static ccow_t cl = NULL;
static ci_t *ci;
static ci_t *ci2;
static ci_t *ci3;
static inode_t part1_inode1;
static inode_t part1_inode2;
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
	snprintf(path, sizeof(path), CCOW_JSON, nedge_path());
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

// FOT disabled in these tests for now
#if 0
	uint8_t fot = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_FILE_OBJECT_TRANSPARANCY,
	    (void *) &fot, NULL);
	assert(!err);
#endif

	err = ccow_bucket_create(cl, TEST_BUCKET,
	    strlen(TEST_BUCKET) + 1, c);
	if (err != -EEXIST)
		assert_int_equal(err, 0);

/* taken from replicast.h */
#define FOT_INODE2OID ".nexenta_inode2oid"
	err = ccow_bucket_inode_ref_create(cl, TEST_BUCKET,
	    strlen(TEST_BUCKET) + 1, FOT_INODE2OID, strlen(FOT_INODE2OID) + 1);
}

static void bucket_delete(void **state) {
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BUCKET,
	    strlen(TEST_BUCKET) + 1);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void bucket_create2(void **state) {
	assert_non_null(cl);
	ccow_completion_t c = NULL;
	uint32_t cs = 1024 * 1024;

	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert(!err);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *) &cs, NULL);
	assert(!err);

	err = ccow_bucket_create(cl, TEST_BUCKET2,
	    strlen(TEST_BUCKET2) + 1, c);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void bucket_delete2(void **state) {
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BUCKET2,
	    strlen(TEST_BUCKET2) + 1);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void bucket_create3(void **state) {
	assert_non_null(cl);
	ccow_completion_t c = NULL;
	uint32_t cs = 1024 * 1024;

	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert(!err);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *) &cs, NULL);
	assert(!err);

	err = ccow_bucket_create(cl, TEST_BUCKET3,
	    strlen(TEST_BUCKET3) + 1, c);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void bucket_delete3(void **state) {
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BUCKET3,
	    strlen(TEST_BUCKET3) + 1);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
libccowfsio_setup(void **state)
{
	char path[PATH_MAX];
	assert_int_equal(ccow_fsio_init(), 0);
	ci = ccow_fsio_ci_alloc();
	snprintf(path, sizeof(path), CCOW_JSON, nedge_path());
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
libccowfsio_setup2(void **state)
{
	char path[PATH_MAX];
	ci2 = ccow_fsio_ci_alloc();
	snprintf(path, sizeof(path), CCOW_JSON, nedge_path());
	assert_int_equal(ccow_fsio_create_export(ci2, FSIO_EXPORT_PATH2, path, 4096, NULL, NULL), 0);
}

static void
libccowfsio_teardown2(void **state)
{
	ccow_fsio_delete_export(ci2);
	ccow_fsio_ci_free(ci2);
	ci2 = NULL;
}

static void
libccowfsio_setup3(void **state)
{
	char path[PATH_MAX];
	ci3 = ccow_fsio_ci_alloc();
	snprintf(path, sizeof(path), CCOW_JSON, nedge_path());
	assert_int_equal(ccow_fsio_create_export(ci3, FSIO_EXPORT_PATH3, path, 4096, NULL, NULL), 0);
}

static void
libccowfsio_teardown3(void **state)
{
	ccow_fsio_delete_export(ci3);
	ccow_fsio_ci_free(ci3);
	ci3 = NULL;
}

static int
recursive_delete(inode_t parent, fsio_dir_entry *dir_entry, uint64_t count, void *ptr)
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
		if (dir_entry[i].inode != CCOW_FSIO_ROOT_INODE &&
		    dir_entry[i].inode != CCOW_FSIO_LOST_FOUND_DIR_INODE) {
			err = ccow_fsio_delete(ci, parent, dir_entry[i].name);
			assert(err == 0);
			/* verify recovery entry removed */
			if (INODE_IS_DIR(dir_entry[i].inode))
				assert_int_equal(testonly_recovery_entry_exists(ci,
				    dir_entry[i].inode, 6), 1);
			else
				assert_int_equal(testonly_recovery_entry_exists(ci,
				    dir_entry[i].inode, 6), 0);
		}
	}

	return (0);
}

static int
verify_link_count_uncached(ci_t *cip, inode_t ino, int expected)
{
	struct stat stat;
	int err = 0;

	/* refresh inode and check */
	err = testonly_refresh_inode(cip, ino);
	if (err) {
		printf("ino: %lu testonly_refresh_inode error %d\n", ino, err);
		return err;
	}
	err = ccow_fsio_get_file_stat(cip, ino, &stat);
	if (err) {
		printf("ino: %lu ccow_fsio_get_file_stat error %d\n", ino, err);
		return err;
	}
	if (stat.st_nlink != (uint64_t) expected) {
		printf("ino: %lu link count error %lu != %d\n",
			ino, stat.st_nlink, expected);
		return 1;
	}
	return 0;
}

static int
verify_link_count_cached(ci_t *cip, inode_t ino, int expected)
{
	struct stat stat;
	int err = 0;

	/* don't refresh inode, check (possibly) cached value */
	err = ccow_fsio_get_file_stat(cip, ino, &stat);
	if (err) {
		printf("ino: %lu ccow_fsio_get_file_stat error %d\n", ino, err);
		return err;
	}
	if (stat.st_nlink != (uint64_t) expected) {
		printf("ino: %lu link count error %ld != %d\n",
			ino, stat.st_nlink, expected);
		return 1;
	}
	return 0;
}

static void
test_create_delete_ops(void **state)
{
	inode_t inode, parent_inode;
	char name[32];
	struct stat stat;
	int err, i, parent_count;;

	printf("===================== Test flat directories ==================\n");
	/* root dir starts out with link count 3: itself, "." and .lost+found */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3), 0);
	for (i = 0; i < NUM_OF_FLAT_DIRS; i++) {
		sprintf(name, "flat_dir_%d", i);
		err = ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, name, 0750, 0, 0, &inode);
		if (err == EEXIST)
			err = 0;
		assert_int_equal(err, 0);
		/* every directory starts out with link count 2: itself and . */
		assert_int_equal(verify_link_count_uncached(ci, inode, 2), 0);
		/* parent dir gets a link for every .. in child dir */
		assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4 + i), 0);
	}
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3 + NUM_OF_FLAT_DIRS), 0);

	printf("===================== Test locking ==================\n");
	struct flock flk;
	memset(&flk, 0, sizeof(flk));

	printf("lock type: %d\n", flk.l_type);
	assert_int_equal(ccow_fsio_query_lock(ci, CCOW_FSIO_ROOT_INODE, LOCK_SH,
						0, 100, &flk), 0);
	printf("lock type: %d\n", flk.l_type);
	assert_int_equal(ccow_fsio_lock(ci, CCOW_FSIO_ROOT_INODE, LOCK_SH,
						0, 100), 0);
	assert_int_equal(ccow_fsio_query_lock(ci, CCOW_FSIO_ROOT_INODE, LOCK_SH,
						0, 100, &flk), 0);
	printf("lock type: %d\n", flk.l_type);

	printf("===================== Test deep directories ==================\n");
	parent_inode = CCOW_FSIO_ROOT_INODE;
	/* we start with root, so next dir creation adds 1 */
	parent_count = 3 + NUM_OF_FLAT_DIRS + 1;
	for (i = 0; i < NUM_OF_DEEP_DIRS; i++) {
		err = ccow_fsio_mkdir(ci, parent_inode, "deep_dir", 0770, 0, 0, &inode);
		if (err == EEXIST)
			err = 0;
		assert_int_equal(err, 0);
		assert_int_equal(verify_link_count_uncached(ci, inode, 2), 0);
		assert_int_equal(verify_link_count_uncached(ci, parent_inode, parent_count), 0);
		parent_inode = inode;
		/* all subsequent parent dirs will have 3 when sub dir created */
		parent_count = 3;
	}
	/* still same for root dir */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3 + NUM_OF_FLAT_DIRS + 1), 0);

	printf("===================== Test flat files ==================\n");
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(name, "flat_file_%d", i);
		err = ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, name, 0750, 0, 0, &inode);
		if (err == EEXIST)
			err = 0;
		assert_int_equal(err, 0);
		/* new file has link count 1 */
		assert_int_equal(verify_link_count_uncached(ci, inode, 1), 0);
	}
	/* files should not change link count of dir */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3 + NUM_OF_FLAT_DIRS + 1), 0);

	printf("=============== Test delete directories and files =============\n");
	bool eof;
	ccow_fsio_readdir_cb4(ci, CCOW_FSIO_ROOT_INODE, recursive_delete, 0, NULL, &eof);
	/* root should be back to link count 3 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3), 0);
}

static void
test_namespace_ops(void **state)
{
	struct stat stat;
	inode_t file_inode, file_rename1_inode, file_rename2_inode, pre_existing_inode,
		dir_inode, old_parent_inode, new_parent_inode, dir_rename_inode, lookup;
	char *file_name = "testfile";
	char *link_name = "testfile_link";
	char *file_rename1 = "testfile_rename1";
	char *file_rename2 = "testfile_rename2";
	char *dir_name = "subdir";
	char *dir_rename = "subdir-rename";
	char *old_parent = "parent-old";
	char *new_parent = "parent-new";
	uint16_t mode = S_IFDIR | 0750;

	printf("===================== Link/Unlink Test =========================\n");
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name,
		0750, 0, 0, &file_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, file_inode, 1), 0);

	/* hard link not supported
	assert_int_equal(ccow_fsio_link(ci, CCOW_FSIO_ROOT_INODE, link_name, file_inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, file_inode, &stat), 0);
	assert_int_equal(stat.st_nlink, 2);

	assert_int_equal(ccow_fsio_unlink(ci, CCOW_FSIO_ROOT_INODE, link_name), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, file_inode, &stat), 0);
	assert_int_equal(stat.st_nlink, 1);
	*/

	assert_int_equal(ccow_fsio_unlink(ci, CCOW_FSIO_ROOT_INODE, file_name), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, file_inode, &stat), ENOENT);

	printf("===================== Rename File Same Directory ===============\n");
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name,
		0750, 0, 0, &file_inode), 0);
	assert_int_equal(ccow_fsio_move(ci, CCOW_FSIO_ROOT_INODE, file_name,
		CCOW_FSIO_ROOT_INODE, file_rename1), 0);

	printf("===================== Find / lookup Renamed File ===============\n");
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_rename1,
		&file_rename1_inode), 0);
	assert_int_equal(file_inode, file_rename1_inode);
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_name,
		&file_inode), ENOENT);
	assert_int_equal(verify_link_count_uncached(ci, file_rename1_inode, 1), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3), 0);
	assert_int_equal(testonly_recovery_entry_exists(ci, file_rename1_inode,
		16), 0);

	printf("===================== Move Directory ===========================\n");

	/* make a destination parent directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, new_parent,
		mode, 0, 0, &new_parent_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, new_parent_inode, 2), 0);
	/* +1 on root */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/* make a source parent directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, old_parent,
		mode, 0, 0, &old_parent_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, old_parent_inode, 2), 0);
	/* +1 on root */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 5), 0);

	/* create a child sub-directory */
	assert_int_equal(ccow_fsio_mkdir(ci, old_parent_inode, dir_name,
		mode, 0, 0, &dir_inode), 0);
	/* new dir should have link count 2 */
	assert_int_equal(verify_link_count_uncached(ci, dir_inode, 2), 0);
	/* parent should have link count incremented */
	assert_int_equal(verify_link_count_uncached(ci, old_parent_inode, 3), 0);

	/* now move sub-directory from old parent to new parent */
	assert_int_equal(ccow_fsio_move(ci, old_parent_inode, dir_name,
		new_parent_inode, dir_rename), 0);

	/* new parent +1 link count, old parent -1 link count */
	assert_int_equal(verify_link_count_uncached(ci, new_parent_inode, 3), 0);
	assert_int_equal(verify_link_count_uncached(ci, old_parent_inode, 2), 0);

	printf("===================== Find / lookup Moved Directory ============\n");
	/* find in new parent */
	assert_int_equal(ccow_fsio_lookup(ci, new_parent_inode, dir_rename,
		&dir_rename_inode), 0);
	/* is still the same inode */
	assert_true(dir_inode == dir_rename_inode);
	/* doesn't exist in old parent */
	assert_int_equal(ccow_fsio_lookup(ci, old_parent_inode, dir_name,
		&dir_inode), ENOENT);
	/* root inode unchanged */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 5), 0);
	/* verify no recovery entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, dir_rename_inode,
		16), 0);

	printf("===================== Move File to new Directory ================\n");
	/* re-using file_rename1, new_parent */
	assert_int_equal(ccow_fsio_move(ci, CCOW_FSIO_ROOT_INODE, file_rename1,
		new_parent_inode, file_rename2), 0);
	/* find in new parent */
	assert_int_equal(ccow_fsio_lookup(ci, new_parent_inode, file_rename2,
		&file_rename2_inode), 0);
	/* doesn't exist in old parent with old name */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_rename1,
		&lookup), ENOENT);
	/* is still the same inode */
	assert_true(file_rename1_inode == file_rename2_inode);
	/* verify no recovery entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_rename2_inode,
		16), 0);

	printf("===================== Move File to new Dir, Target Exists ======\n");
	/* make a file with same name (re-using file_rename2) */
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_rename2,
		0750, 0, 0, &pre_existing_inode), 0);
	/* confirm this is a different inode than the one we're going to move */
	assert_false(pre_existing_inode == file_rename2_inode);
	/* move file to the pre-existing target with the same name */
	assert_int_equal(ccow_fsio_move(ci, new_parent_inode, file_rename2,
		CCOW_FSIO_ROOT_INODE, file_rename2), 0);
	/* fresh lookup in new location */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_rename2,
		&lookup), 0);
	/* the move actually deletes the pre-existing target,
	 * so the inode should be the source
	 */
	assert_false(lookup == pre_existing_inode);
	assert_true(lookup == file_rename2_inode);
	/* verify no recovery entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_rename2_inode,
		16), 0);

	/* cleanup */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, file_rename2), 0);
	assert_int_equal(ccow_fsio_delete(ci, new_parent_inode, dir_rename), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, new_parent), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, old_parent), 0);
	/* root back to normal */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3), 0);
}

static void
test_metadata_ops(void **state)
{
	struct stat stat;
	inode_t inode;
	char *file_name = "foo";

	printf("===================== chmod/chown Test ==================\n");
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name, 0750, 0, 0, &inode), 0);
	/* cached md */
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_mode & 0750, 0750);
	/* uncached md */
	assert_int_equal(testonly_refresh_inode(ci, inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_mode & 0750, 0750);

	stat.st_mode = 0777;
	assert_int_equal(ccow_fsio_set_file_stat(ci, inode, &stat), 0);
	/* cached md */
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_mode & 0777, 0777);
	assert_int_equal(stat.st_uid, 0);
	assert_int_equal(stat.st_gid, 0);
	/* uncached md */
	assert_int_equal(testonly_refresh_inode(ci, inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_mode & 0777, 0777);
	assert_int_equal(stat.st_uid, 0);
	assert_int_equal(stat.st_gid, 0);

	stat.st_uid = 7;
	stat.st_gid = 5;
	assert_int_equal(ccow_fsio_set_file_stat(ci, inode, &stat), 0);
	/* cached md */
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_uid, 7);
	assert_int_equal(stat.st_gid, 5);
	/* uncached md */
	assert_int_equal(testonly_refresh_inode(ci, inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_uid, 7);
	assert_int_equal(stat.st_gid, 5);

	printf("===================== Set attr Test ==================\n");
	stat.st_size = 1024 * 10 + 20;
	assert_int_equal(ccow_fsio_set_file_stat(ci, inode, &stat), 0);
	/* cached md */
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_size,  1024 * 10 + 20);
	/* uncached md */
	assert_int_equal(testonly_refresh_inode(ci, inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_size,  1024 * 10 + 20);

	assert_int_equal(ccow_fsio_unlink(ci, CCOW_FSIO_ROOT_INODE, file_name), 0);
}

static void
test_read_write_ops(void **state)
{
	char *data = "#!/bin/sh\n" "echo \"Starting inetd super server.\"";
	ccow_fsio_file_t *file = NULL;
	size_t write_amount;
	inode_t inode;
	char *file_name = "foo";
	char *file_path = "/foo";
	struct stat stat;
	size_t read;
	char *buf = NULL;
	int eof;

	printf("===================== Write Test ========================\n");
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name, 0750, 0, 0, &inode), 0);
	ccow_fsio_open(ci, file_path, &file, O_WRONLY);
	/* FSIO will take ownership of the write buffer. Don't free it.*/
	char *data2 = je_strdup(data);
	ccow_fsio_write(file, 0, strlen(data2), (void *)data2, &write_amount);
	ccow_fsio_close(file);

	printf("===================== Read Test =========================\n");
	assert_int_equal(ccow_fsio_find(ci, file_path, &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_true(stat.st_size < 1000);
	assert_true(stat.st_size > 0);
	buf = je_malloc(stat.st_size + 1);
	assert_true(buf != NULL);
	ccow_fsio_open(ci, file_path, &file, O_RDONLY);
	ccow_fsio_read(file, 0, stat.st_size, (void *)buf, &read, &eof);
	ccow_fsio_close(file);
	buf[stat.st_size] = '\0';
	assert_int_equal(strcmp(data, buf), 0);

	je_free(buf);

	assert_int_equal(ccow_fsio_unlink(ci, CCOW_FSIO_ROOT_INODE, file_name), 0);
}

static void
test_clone(void **state)
{
	char *data = "testing clone";
	ccow_fsio_file_t *file = NULL;
	size_t write_amount;
	inode_t inode, inode_clone;
	char *file_name = "testfile";
	char *file_path = "/testfile";
	char *clone_name = "clonefile";
	char *clone_path = "/clonefile";
	struct stat stat;
	size_t read;
	char *buf = NULL;
	int eof;

	/* create a file */
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name, 0750, 0, 0, &inode), 0);
	ccow_fsio_open(ci, file_path, &file, O_WRONLY);
	/* FSIO will take ownership of the write buffer. Don't free it.*/
	char *data2 = je_strdup(data);
	ccow_fsio_write(file, 0, strlen(data2), (void *)data2, &write_amount);
	ccow_fsio_close(file);

	/* clone file */
	printf("===================== Clone Test =========================\n");
	assert_int_equal(ccow_fsio_clone_file(TEST_CLUSTER, TEST_TENANT, TEST_BUCKET,
		TEST_BUCKET2, file_path, clone_path, CLONE_FILE_FLAG_GUARDED), 0);

	/* confirm it exists and contains same contents */
	file = NULL;
	assert_int_equal(ccow_fsio_find(ci2, clone_path, &inode_clone), 0);
	assert_int_equal(testonly_refresh_inode(ci2, inode_clone), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci2, inode_clone, &stat), 0);
	assert_int_equal(stat.st_nlink, 1);
	buf = je_malloc(stat.st_size + 1);
	assert_true(buf != NULL);
	ccow_fsio_open(ci2, clone_path, &file, O_RDONLY);
	ccow_fsio_read(file, 0, stat.st_size, (void *)buf, &read, &eof);
	ccow_fsio_close(file);
	buf[stat.st_size] = '\0';
	assert_int_equal(strcmp(data, buf), 0);

	je_free(buf);

	/* link count on source file is not affected */
	assert_int_equal(testonly_refresh_inode(ci, inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_nlink, 1);
	/* link count on source directory is not affected */
	assert_int_equal(testonly_refresh_inode(ci, CCOW_FSIO_ROOT_INODE), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, CCOW_FSIO_ROOT_INODE, &stat), 0);
	assert_int_equal(stat.st_nlink, 3);
	/* link count on dest directory is not affected */
	assert_int_equal(testonly_refresh_inode(ci2, CCOW_FSIO_ROOT_INODE), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci2, CCOW_FSIO_ROOT_INODE, &stat), 0);
	assert_int_equal(stat.st_nlink, 3);

	assert_int_equal(ccow_fsio_unlink(ci, CCOW_FSIO_ROOT_INODE, file_name), 0);
	assert_int_equal(ccow_fsio_unlink(ci2, CCOW_FSIO_ROOT_INODE, clone_name), 0);
}

static void
test_create_eexist(void **state)
{
	inode_t inode, inode_retry = 0;
	char *file_name = "testeexist";
	struct stat stat;
	int err;

	/* Note: This logic mimics that in nedge_create(),
	 * which will ignore EEXIST from ccow_fsio_touch(),
	 * then attempts a ccow_fsio_get_file_stat().
	 * See bug NED-6369
	 */
	printf("===================== Stat on EEXIST Test =========================\n");
	/* Create a file */
	err = ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name, 0750, 0, 0, &inode);
	assert_int_equal(err, 0);
	/* Now attempt a 2nd creation */
	err = ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name, 0750, 0, 0, &inode_retry);
	assert_int_equal(err, EEXIST);
	/* inode must be valid */
	assert_int_equal(inode, inode_retry);
	/* do a stat on inode */
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode_retry, &stat), 0);
	/* cleanup */
	assert_int_equal(ccow_fsio_unlink(ci, CCOW_FSIO_ROOT_INODE, file_name), 0);
}

static void
test_mkdir_failure_after_inode_creation(void **state)
{
	inode_t inode, parent_inode, lookup, inode_twin;
	char *parent_dir = "parent-dir-creation";
	char *child_dir = "dir-creation";
	uint16_t mode = S_IFDIR | 0750;

	/*
	 * test case scenario for directory creation failure:
	 * - inode creation succeded
	 * - ".." NOT added to child directory
	 * - child NOT added to parent directory
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__create_node(),
	 * if that changes this test case will probably need to be changed
	 */

	/* make a directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, parent_dir,
		mode, 0, 0, &parent_inode), 0);
	/* empty dir has default link count 2, one for itself and one for "."  */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* create sub directory inode */
	assert_int_equal(testonly_create_inode(ci, parent_inode, child_dir,
		mode, 0, 0, &inode, NULL), 0);
	/* new dir inode has link count 0 by default */
	assert_int_equal(verify_link_count_uncached(ci, inode, 0), 0);
	/* no namespace linkage so parent link count same */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);
	/* can't lookup the sub-directory in parent */
	assert_int_equal(ccow_fsio_lookup(ci, parent_inode, child_dir, &lookup), ENOENT);
	/* also can't delete the orphaned sub-directory */
	assert_int_equal(ccow_fsio_delete(ci, parent_inode, child_dir), ENOENT);

	/* try to re-create the orphan (use real mkdir api) */
	assert_int_equal(ccow_fsio_mkdir(ci, parent_inode, child_dir,
		mode, 0, 0, &inode_twin), 0);
	/* it better be a different inode */
	assert_int_not_equal(inode, inode_twin);
	/* now parent link count incremented */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 3), 0);
	/* can we still delete twin and parent */
	assert_int_equal(ccow_fsio_delete(ci, parent_inode, child_dir), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, parent_dir), 0);
}

static void
test_mkdir_failure_after_dotdot(void **state)
{
	inode_t inode, parent_inode, inode_twin, lookup;
	char *parent_dir = "parent-dir-dotdot";
	char *child_dir = "dir-dotdot";
	uint16_t mode = S_IFDIR | 0750;

	/*
	 * test case scenario for directory creation failure:
	 * - inode creation succeded
	 * - ".." added to child directory successful
	 * - child NOT added to parent directory
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__create_node(),
	 * if that changes this test case will probably need to be changed
	 */

	/* make a directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, parent_dir,
		mode, 0, 0, &parent_inode), 0);
	/* empty dir has default link count 2, one for itself and one for "."  */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* create sub directory inode only */
	assert_int_equal(testonly_create_inode(ci, parent_inode, child_dir,
		mode, 0, 0, &inode, NULL), 0);
	/* new dir inode should have link count 0 by default */
	assert_int_equal(verify_link_count_uncached(ci, inode, 0), 0);

	/* add ".." to child sub dir with link to parent
	 * this also initialzes link count of child to 2
	 */
	assert_int_equal(testonly_dir_add_entry(ci, inode, "..", parent_inode, 2), 0);

	/* note, we haven't added the child to parent dir */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* we now have an orphan, can't lookup the sub-directory in parent */
	assert_int_equal(ccow_fsio_lookup(ci, parent_inode, child_dir, &lookup), ENOENT);
	/* also can't delete the orphaned sub-directory */
	assert_int_equal(ccow_fsio_delete(ci, parent_inode, child_dir), ENOENT);

	/* try to re-create the orphan (use real mkdir api) */
	assert_int_equal(ccow_fsio_mkdir(ci, parent_inode, child_dir,
		mode, 0, 0, &inode_twin), 0);

	/* it better be a different inode */
	assert_int_not_equal(inode, inode_twin);
	/* now parent link count incremented */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 3), 0);
	/* we should still be able to delete twin and parent */
	assert_int_equal(ccow_fsio_delete(ci, parent_inode, child_dir), 0);
	/* parent link count was decremented */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, parent_dir), 0);
}

static void
test_rmdir_failure_after_recovery_insert(void **state)
{
	inode_t subdir_inode, lookup;
	char *subdir_name = "subdir-dir-rm";
	void *inode_ref = NULL;
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario for directory deletion failure
	 * - recovery entry added
	 * - ganesha failure immediately after
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__delete_internal(),
	 * if that changes this test case will probably need to be changed
	 */

	/* create a child directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
		mode, 0, 0, &subdir_inode), 0);
	/* new dir should have link count 2 */
	assert_int_equal(verify_link_count_uncached(ci, subdir_inode, 2), 0);
	/* parent should have link count incremented */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);
	/* get a ref on inode */
	assert_int_equal(testonly_get_inode_ref(ci, subdir_inode, &inode_ref), 0);

	/************** Failure setup ******************/

	/* insert recovery entry table */
	assert_int_equal(testonly_recovery_insert_deleted(ci, subdir_inode,
	    CCOW_FSIO_ROOT_INODE, subdir_name, 2, 1), 0);
	/* purge the inode from cache and free inode (no put done) */
	assert_int_equal(testonly_inode_purge_by_ref(ci, inode_ref), 0);
	inode_ref = NULL;

	/************** Recovery ******************/

	/* try the recovery handler */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* the recovery entry should be deleted (DELETE api == 6) */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 6), 0);

	/* recovery does nothing, so nothing else should have changed */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
	    &lookup), 0);
	assert_int_equal(lookup, subdir_inode);
	assert_int_equal(verify_link_count_uncached(ci, subdir_inode, 2), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/**************** Cleanup ***************/

	/* we can delete the sub-directory */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, subdir_name),
	    0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3), 0);
}

static void
test_rmdir_failure_before_dotdot(void **state)
{
	inode_t child_inode, parent_inode, lookup;
	char *parent_name = "parent-rm-dotdot";
	char *child_name = "dir-rm-dotdot";
	void *inode_ref = NULL;
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario for directory deletion failure
	 * - recovery entry inserted
	 * - child directory removed from parent
	 * - the ".." NOT removed from child
	 * - the link count NOT decremented from child
	 * - the child inode NOT marked for deletion
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__delete_internal(),
	 * if that changes this test case will probably need to be changed
	 */

	/* make a parent directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, parent_name,
		mode, 0, 0, &parent_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* create a child directory */
	assert_int_equal(ccow_fsio_mkdir(ci, parent_inode, child_name,
		mode, 0, 0, &child_inode), 0);
	/* new dir should have link count 2 */
	assert_int_equal(verify_link_count_uncached(ci, child_inode, 2), 0);
	/* parent should have link count incremented */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 3), 0);
	/* get a ref on inode */
	assert_int_equal(testonly_get_inode_ref(ci, child_inode, &inode_ref), 0);

	/************** Failure setup ******************/

	/* insert recovery entry table */
	assert_int_equal(testonly_recovery_insert_deleted(ci, child_inode,
	    parent_inode, child_name, 2, 1), 0);
	/* remove child from parent */
	assert_int_equal(testonly_dir_remove_entry(ci, parent_inode, child_name,
	    1), 0);
	/* the parent should have link count decremented */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);
	/* link count on child still 2 since namespace cleanup not done */
	assert_int_equal(verify_link_count_uncached(ci, child_inode, 2), 0);
	/* purge the inode from cache and free inode (no put done) */
	assert_int_equal(testonly_inode_purge_by_ref(ci, inode_ref), 0);
	inode_ref = NULL;

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* inode should no longer exist-- uses api that allows 0 link count */
	assert_int_equal(testonly_get_inode_ref_for_recovery(ci, child_inode,
	    &inode_ref), ENOENT);
	/* the recovery entry should be deleted (DELETE api == 6) */
	assert_int_equal(testonly_recovery_entry_exists(ci, child_inode, 6), 0);
	/* parent link count still 2 */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/**************** Cleanup ***************/

	/* delete the parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, parent_name), 0);
	/* root link count */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3), 0);
}

static void
test_rmdir_failure_before_dotdot_parent_deleted(void **state)
{
	inode_t child_inode, parent_inode, lookup;
	char *parent_name = "parent-rm-dotdot-parent-gone";
	char *child_name = "dir-rm-dotdot-parent-gone";
	void *inode_ref = NULL;
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario for directory deletion failure
	 * - recovery entry inserted
	 * - child directory removed from parent
	 * - the ".." NOT removed from child
	 * - the link count NOT decrimented from child
	 * - the child inode NOT marked for deletion
	 * - the parent dir was deleted
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__delete_internal(),
	 * if that changes this test case will probably need to be changed
	 */

	/* make a parent directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, parent_name,
		mode, 0, 0, &parent_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* create a child directory */
	assert_int_equal(ccow_fsio_mkdir(ci, parent_inode, child_name,
		mode, 0, 0, &child_inode), 0);
	/* new dir should have link count 2 */
	assert_int_equal(verify_link_count_uncached(ci, child_inode, 2), 0);
	/* parent should have link count incremented */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 3), 0);
	/* get a ref on inode */
	assert_int_equal(testonly_get_inode_ref(ci, child_inode, &inode_ref), 0);

	/************** Failure setup ******************/

	/* insert recovery entry table */
	assert_int_equal(testonly_recovery_insert_deleted(ci, child_inode,
	    parent_inode, child_name, 2, 1), 0);
	/* remove child from parent */
	assert_int_equal(testonly_dir_remove_entry(ci, parent_inode, child_name, 1), 0);
	/* delete the parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, parent_name), 0);
	/* purge the inode from cache and free inode (no put done) */
	assert_int_equal(testonly_inode_purge_by_ref(ci, inode_ref), 0);
	inode_ref = NULL;

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* inode should no longer exist-- uses api that allows 0 link count */
	assert_int_equal(testonly_get_inode_ref_for_recovery(ci, child_inode,
	    &inode_ref), ENOENT);
	/* the recovery entry should be deleted (DELETE api == 6) */
	assert_int_equal(testonly_recovery_entry_exists(ci, child_inode, 6), 0);
	/* root link count */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3), 0);
}

static void
test_rmdir_failure_before_mark_deletion(void **state)
{
	inode_t child_inode, parent_inode, lookup;
	char *parent_name = "parent-rm-mark";
	char *child_name = "dir-rm-mark";
	void *inode_ref = NULL;
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario
	 * - recovery entry inserted
	 * - child directory successfully removed from parent
	 * - the ".." successfully removed from child,
	 *   and link count successfully decremented from child
	 * - the child inode NOT marked for deletion
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__delete_internal(),
	 * if that changes this test case will probably need to be changed
	 */

	/* make a parent directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, parent_name,
		mode, 0, 0, &parent_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* create a child directory */
	assert_int_equal(ccow_fsio_mkdir(ci, parent_inode, child_name,
		mode, 0, 0, &child_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, child_inode, 2), 0);

	/* parent should have link count incremented */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 3), 0);

	/* get a ref on inode */
	assert_int_equal(testonly_get_inode_ref(ci, child_inode, &inode_ref), 0);

	/************** Failure setup ******************/

	/* insert recovery entry table */
	assert_int_equal(testonly_recovery_insert_deleted(ci, child_inode,
	    parent_inode, child_name, 2, 1), 0);

	/* remove child from parent */
	assert_int_equal(testonly_dir_remove_entry(ci, parent_inode, child_name, 1), 0);

	/* remove ".." from child, also remove link count */
	assert_int_equal(testonly_dir_remove_entry(ci, child_inode, "..", 2), 0);

	/* purge the inode from cache and free inode (no put done) */
	assert_int_equal(testonly_inode_purge_by_ref(ci, inode_ref), 0);
	inode_ref = NULL;

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* inode should no longer exist-- uses api that allows 0 link count */
	assert_int_equal(testonly_get_inode_ref_for_recovery(ci, child_inode,
	    &inode_ref), ENOENT);
	/* the recovery entry should be deleted (DELETE api == 6) */
	assert_int_equal(testonly_recovery_entry_exists(ci, child_inode, 6), 0);
	/* root link count */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/**************** Cleanup ***************/

	/* delete the parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, parent_name), 0);
	/* root link count */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 3), 0);
}

static void
test_rmdir_failure_before_mark_deletion_parent_deleted(void **state)
{
	inode_t child_inode, parent_inode, lookup;
	char *parent_name = "parent-rm-mark-parent-gone";
	char *child_name = "dir-rm-mark-parent-gone";
	void *inode_ref = NULL;
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario
	 * - insert recovery table entry
	 * - child directory successfully removed from parent
	 * - the ".." successfully removed from child,
	 *   and the link count successfully decremented from child
	 * - the child inode NOT marked for deletion
	 * - the parent directory is deleted
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__delete_internal(),
	 * if that changes this test case will probably need to be changed
	 */

	/* make a parent directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, parent_name,
		mode, 0, 0, &parent_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* create a child directory */
	assert_int_equal(ccow_fsio_mkdir(ci, parent_inode, child_name,
		mode, 0, 0, &child_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, child_inode, 2), 0);
	/* parent should have link count incremented */
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 3), 0);
	/* get a ref on inode */
	assert_int_equal(testonly_get_inode_ref(ci, child_inode, &inode_ref), 0);

	/************** Failure setup ******************/

	/* insert recovery entry table */
	assert_int_equal(testonly_recovery_insert_deleted(ci, child_inode,
	    parent_inode, child_name, 2, 1), 0);
	/* remove child from parent */
	assert_int_equal(testonly_dir_remove_entry(ci, parent_inode, child_name,
	    1), 0);
	/* remove ".." from child, also remove link count */
	assert_int_equal(testonly_dir_remove_entry(ci, child_inode, "..", 2), 0);
	/* delete the parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE,
	    parent_name), 0);
	/* purge the inode from cache and free inode (no put done) */
	assert_int_equal(testonly_inode_purge_by_ref(ci, inode_ref), 0);
	inode_ref = NULL;

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* inode should no longer exist-- uses api that allows 0 link count */
	assert_int_equal(testonly_get_inode_ref_for_recovery(ci, child_inode,
	    &inode_ref), ENOENT);
	/* the recovery entry should be deleted (DELETE api == 6) */
	assert_int_equal(testonly_recovery_entry_exists(ci, child_inode, 6), 0);
}

static void
test_rmdir_failure_directory_notempty(void **state)
{
	inode_t file_inode, parent_inode;
	char *file_name = "testfile";
	char *parent_dir = "dir-not-empty";
	uint16_t mode = S_IFDIR | 0750;

	/* make a parent directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, parent_dir,
		mode, 0, 0, &parent_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* create a file under directory */
	assert_int_equal(ccow_fsio_touch(ci, parent_inode, file_name, 0750, 0, 0, &file_inode), 0);

	/* attempt rmdir */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, parent_dir), ENOTEMPTY);

	/* confirm no recovery entry was created */
	assert_int_equal(testonly_recovery_entry_exists(ci, parent_inode, 6), 0);

	/* cleanup */
	assert_int_equal(ccow_fsio_delete(ci, parent_inode, file_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, parent_dir), 0);
}

static void
test_rm_file_failure_after_recovery_insert(void **state)
{
	inode_t file_inode, lookup;
	char *file_name = "testfile-recovery-insert";
	uint16_t mode = S_IFDIR | 0750;

	/* create a file */
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name,
	    0750, 0, 0, &file_inode), 0);

	/* insert recovery entry table */
	assert_int_equal(testonly_recovery_insert_deleted(ci, file_inode,
	    CCOW_FSIO_ROOT_INODE, file_name, 1, 1), 0);

	/* confirm recovery entry exists */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 6), 1);

	/* invoke recovery handler */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/* the recovery entry should be deleted (DELETE api == 6) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 6), 0);

	/* recovery does nothing, so nothing else should have changed */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_name,
	    &lookup), 0);
	assert_int_equal(lookup, file_inode);

	/* cleanup */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, file_name), 0);
}

static void
test_rm_file_failure_after_dir_rm_entry(void **state)
{
	inode_t file_inode, lookup;
	char *file_name = "file-rm-entry";
	void *inode_ref = NULL;
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario
	 * - insert recovery table entry
	 * - file successfully removed from parent dir
	 * - file NOT unlinked
	 * - ganesha unclean shutdown directly after
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__delete_internal(),
	 * if that changes this test case will probably need to be changed
	 */

	/* create a file */
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name,
	    0750, 0, 0, &file_inode), 0);
	/* get a ref on inode */
	assert_int_equal(testonly_get_inode_ref(ci, file_inode, &inode_ref), 0);

	/************** Failure setup ******************/

	/* insert recovery entry table */
	assert_int_equal(testonly_recovery_insert_deleted(ci, file_inode,
	    CCOW_FSIO_ROOT_INODE, file_name, 1, 1), 0);
	/* remove file from parent */
	assert_int_equal(testonly_dir_remove_entry(ci, CCOW_FSIO_ROOT_INODE,
	    file_name, 0), 0);
	/* confirm child is orphan */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_name,
	    &lookup), ENOENT);
	/* child link count is still 1 */
	assert_int_equal(verify_link_count_uncached(ci, file_inode, 1), 0);
	/* purge the inode from cache and free inode (no put done) */
	assert_int_equal(testonly_inode_purge_by_ref(ci, inode_ref), 0);
	inode_ref = NULL;

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* inode should no longer exist-- uses api that allows 0 link count */
	assert_int_equal(testonly_get_inode_ref_for_recovery(ci, file_inode,
	    &inode_ref), ENOENT);
	/* the recovery entry should be deleted (DELETE api == 6) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 6), 0);
}

static void
test_rm_file_failure_after_dir_rm_entry_parent_deleted(void **state)
{
	inode_t file_inode, parent_inode, lookup;
	char *file_name = "file-rm-entry-gone";
	char *parent_name = "parent-rm-entry-gone";
	void *inode_ref = NULL;
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario
	 * - insert recovery table entry
	 * - file successfully removed from parent dir
	 * - file NOT unlinked
	 * - ganesha unclean shutdown directly after
	 * - parent directory deleted
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__delete_internal(),
	 * if that changes this test case will probably need to be changed
	 */

	/* make a parent directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, parent_name,
		mode, 0, 0, &parent_inode), 0);

	/* create a file */
	assert_int_equal(ccow_fsio_touch(ci, parent_inode, file_name,
	    0750, 0, 0, &file_inode), 0);

	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* get a ref on inode */
	assert_int_equal(testonly_get_inode_ref(ci, file_inode, &inode_ref), 0);

	/************** Failure setup ******************/

	/* insert recovery entry table */
	assert_int_equal(testonly_recovery_insert_deleted(ci, file_inode,
	    parent_inode, file_name, 1, 1), 0);

	/* remove file from parent */
	assert_int_equal(testonly_dir_remove_entry(ci, parent_inode, file_name,
	    0), 0);

	/* confirm child is orphan */
	assert_int_equal(ccow_fsio_lookup(ci, parent_inode, file_name,
	    &lookup), ENOENT);

	/* child link count is still 1 */
	assert_int_equal(verify_link_count_uncached(ci, file_inode, 1), 0);

	/* remove parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE,
	    parent_name), 0);

	/* purge the inode from cache and free inode (no put done) */
	assert_int_equal(testonly_inode_purge_by_ref(ci, inode_ref), 0);
	inode_ref = NULL;

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* inode should no longer exist-- uses api that allows 0 link count */
	assert_int_equal(testonly_get_inode_ref_for_recovery(ci, file_inode,
	    &inode_ref), ENOENT);

	/* the recovery entry should be deleted (DELETE api == 6) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 6), 0);
}

static void
test_rm_file_failure_after_update_md(void **state)
{
	inode_t file_inode, parent_inode, lookup;
	char *file_name = "file-update-md";
	char *parent_name = "parent-update-md";
	void *inode_ref = NULL;
	uint16_t mode = S_IFDIR | 0750;

	/*
	 * The ccowfs_inode_unlink is two steps, update refcount (link
	 * count) and ctime to disk, and then mark as deleted. There is
	 * the possibility that this gets updated and then ganesha goes down
	 * before an inode put.
	 */

	/* test case scenario
	 * - insert recovery table entry
	 * - file successfully removed from parent dir
	 * - file metadata for ctime and link count updated to disk
	 * - inode NOT marked deleted
	 * - ganesha unclean shutdown directly after
	 *
	 * NOTE: this follows logic flow in fsio_namespace.c:__delete_internal(),
	 * if that changes this test case will probably need to be changed
	 */

	/* make a parent directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, parent_name,
		mode, 0, 0, &parent_inode), 0);

	/* create a file */
	assert_int_equal(ccow_fsio_touch(ci, parent_inode, file_name,
	    0750, 0, 0, &file_inode), 0);

	assert_int_equal(verify_link_count_uncached(ci, parent_inode, 2), 0);

	/* get a ref on inode */
	assert_int_equal(testonly_get_inode_ref(ci, file_inode, &inode_ref), 0);

	/************** Failure setup ******************/

	/* insert recovery entry table */
	assert_int_equal(testonly_recovery_insert_deleted(ci, file_inode,
	    parent_inode, file_name, 1, 1), 0);

	/* remove file from parent */
	assert_int_equal(testonly_dir_remove_entry(ci, parent_inode, file_name,
	    0), 0);

	/* confirm child is orphan */
	assert_int_equal(ccow_fsio_lookup(ci, parent_inode, file_name,
	    &lookup), ENOENT);

	/* child link count is still 1 */
	assert_int_equal(verify_link_count_uncached(ci, file_inode, 1), 0);

	/* this test api does:
	 * - an unlink and updates metadata flush to disk
	 * - does NOT do a put
	 * to simulate a crash before a put was done
	 * Note: inode deleted flag is not an attribute stored on disk
	 */
	assert_int_equal(testonly_inode_unlink_by_ref(ci, inode_ref, 0, 1), 0);
	/* purge the inode from cache and free inode (no put done) */
	assert_int_equal(testonly_inode_purge_by_ref(ci, inode_ref), 0);
	inode_ref = NULL;

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* inode should no longer exist-- uses api that allows 0 link count */
	assert_int_equal(testonly_get_inode_ref_for_recovery(ci, file_inode,
	    &inode_ref), ENOENT);

	/* the recovery entry should be deleted (DELETE api == 6) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 6), 0);

	/**************** Cleanup ***************/

	/* delete the parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, parent_name), 0);
}

static void
test_move_dir_failure_recoverytable_add(void **state)
{
	inode_t subdir_inode, destdir_inode, lookup, file_inode;
	char *subdir_name = "subdir-move";
	char *destdir_name = "dir-new-parent";
	char *new_name = "subdir-move-newname";
	char filename[32];
	uint16_t mode = S_IFDIR | 0750;
	int i;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - ganesha goes down directly afterwards
	 *
	 * logic follows order in ccow_fsio_dir_move()
	 */

	/* make a sub directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
		mode, 0, 0, &subdir_inode), 0);

	/* populate with some files */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_touch(ci, subdir_inode, filename,
		    0750, 0, 0, &file_inode), 0);
	}

	/* can find child in parent */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
	    &lookup), 0);
	/* can find ".." in child */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	/* ".." points to parent */
	assert_int_equal(CCOW_FSIO_ROOT_INODE, lookup);
	/* link count on parent increased +1 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
	    mode, 0, 0, &destdir_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 5), 0);

	/* insert the sub dir into the recovery table
	 * pass in timestamp of 1 to force the recovery run
	 */
	assert_int_equal(testonly_recovery_insert_moved(ci, subdir_inode,
	    CCOW_FSIO_ROOT_INODE, subdir_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm it exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 1);

	/* try the recovery handler */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/* the recovery table entry was removed by handler */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 0);

	/* nothing else has changed */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
	    &lookup), 0);
	/* can find ".." in child */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	/* ".." points to parent */
	assert_int_equal(CCOW_FSIO_ROOT_INODE, lookup);

	/* now do the 2nd move attempt */
	assert_int_equal(ccow_fsio_move(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
		destdir_inode, new_name), 0);
	/* confirm new parent */
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same subdir */
	assert_int_equal(lookup, subdir_inode);
	/* validate ".." in child */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	assert_int_equal(destdir_inode, lookup);
	/* link count on old parent decreased -1 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);
	/* link count on new parent increased +1 */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 3), 0);
	/* files were also moved */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, filename,
		    &file_inode), 0);
	}

	/* cleanup */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_delete(ci, subdir_inode, filename), 0);
	}
	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_dir_failure_rm_src(void **state)
{
	inode_t subdir_inode, destdir_inode, lookup, file_inode;
	char *subdir_name = "subdir-src";
	char *destdir_name = "dir-new-parent-src";
	char *new_name = "subdir-newname-src";
	char filename[32];
	uint16_t mode = S_IFDIR | 0750;
	int i;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - child directory was removed from old parent
	 * - ganesha goes down directly afterwards
	 *
	 * logic follows order in ccow_fsio_dir_move()
	 */

	/* make a sub directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
		mode, 0, 0, &subdir_inode), 0);

	/* populate with some files */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_touch(ci, subdir_inode, filename,
		    0750, 0, 0, &file_inode), 0);
	}

	/* validate current state */
	/* can find child in parent */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name, &lookup), 0);
	/* can find ".." in child */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	/* ".." points to parent */
	assert_int_equal(CCOW_FSIO_ROOT_INODE, lookup);
	/* link count on parent increased +1 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/* make a new parent destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 5), 0);

	/************** Failure setup ******************/

	/* insert the sub dir into the recovery table
	 * pass in timestamp of 1 to force the recovery run
	 */
	assert_int_equal(testonly_recovery_insert_moved(ci, subdir_inode,
	    CCOW_FSIO_ROOT_INODE, subdir_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm it exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 1);

	/* only remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, CCOW_FSIO_ROOT_INODE, subdir_name, 1), 0);
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name, &lookup), ENOENT);

	/************** Recovery ******************/

	/* try the recovery handler */
	assert_int_equal(testonly_recovery_handler(ci), 0);
	/* confirm the recovery handler moved dir to new parent */
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same subdir */
	assert_int_equal(lookup, subdir_inode);
	/* recovery fixed ".." to point to new parent */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	assert_int_equal(destdir_inode, lookup);
	/* link count on old parent decreased -1 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);
	/* link count on new parent increased +1 */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 3), 0);
	/* the recovery table entry was removed by handler */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 0);
	/* files still exist in dir */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, filename, &file_inode), 0);
	}

	/* cleanup */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_delete(ci, subdir_inode, filename), 0);
	}

	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_dir_failure_rm_dotdot(void **state)
{
	inode_t subdir_inode, destdir_inode, lookup, file_inode;
	char *subdir_name = "subdir-rm-dot";
	char *destdir_name = "dir-new-parent-rm-dot";
	char *new_name = "subdir-rm-dot-newname";
	char filename[32];
	uint16_t mode = S_IFDIR | 0750;
	int i;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - child directory was removed from old parent
	 * - ".." link to old parent removed
	 * - ganesha goes down directly afterwards
	 *
	 * logic follows order in ccow_fsio_dir_move()
	 */

	/* make a sub directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
		mode, 0, 0, &subdir_inode), 0);

	/* populate with some files */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_touch(ci, subdir_inode, filename,
		    0750, 0, 0, &file_inode), 0);
	}

	/* can find child in parent */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name, &lookup), 0);
	/* can find ".." in child */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	/* ".." points to parent */
	assert_int_equal(CCOW_FSIO_ROOT_INODE, lookup);
	/* link count on parent increased +1 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 5), 0);

	/************** Failure setup ******************/

	/* insert the sub dir into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, subdir_inode,
	    CCOW_FSIO_ROOT_INODE, subdir_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm it exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 1);

	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, CCOW_FSIO_ROOT_INODE, subdir_name, 1), 0);
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name, &lookup), ENOENT);

	/* remove ".." link to the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, subdir_inode, "..", 0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), ENOENT);

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm the recovery handler moved dir to new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same subdir */
	assert_int_equal(lookup, subdir_inode);
	/* recovery added ".." to point to new parent */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	assert_int_equal(destdir_inode, lookup);
	/* link count on old parent decreased -1 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);
	/* link count on new parent increased +1 */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 3), 0);
	/* the recovery table entry was removed by handler */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 0);
	/* files still exist in dir */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, filename, &file_inode), 0);
	}

	/* cleanup */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_delete(ci, subdir_inode, filename), 0);
	}
	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_dir_failure_add_dotdot(void **state)
{
	inode_t subdir_inode, destdir_inode, lookup, file_inode;
	char *subdir_name = "subdir-add-dot";
	char *destdir_name = "dir-new-parent-add-dot";
	char *new_name = "subdir-add-dot-newname";
	char filename[32];
	uint16_t mode = S_IFDIR | 0750;
	int i;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - child directory was removed from old parent
	 * - ".." link to old parent removed
	 * - ".." link to new parent added
	 * - ganesha goes down directly afterwards
	 *
	 * logic follows order in ccow_fsio_dir_move()
	 */

	/* make a sub directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
		mode, 0, 0, &subdir_inode), 0);

	/* populate with some files */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_touch(ci, subdir_inode, filename,
		    0750, 0, 0, &file_inode), 0);
	}

	/* can find child in parent */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name, &lookup), 0);
	/* can find ".." in child */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	/* ".." points to parent */
	assert_int_equal(CCOW_FSIO_ROOT_INODE, lookup);
	/* link count on parent increased +1 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 5), 0);

	/************** Failure setup ******************/

	/* insert the sub dir into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, subdir_inode,
	    CCOW_FSIO_ROOT_INODE, subdir_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm it exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 1);

	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, CCOW_FSIO_ROOT_INODE, subdir_name, 1), 0);
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name, &lookup), ENOENT);

	/* remove ".." link to the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, subdir_inode, "..", 0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), ENOENT);

	/* add ".." link to the new parent */
	assert_int_equal(testonly_dir_add_entry(ci, subdir_inode, "..", destdir_inode, 0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	assert_int_equal(destdir_inode, lookup);

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm the recovery handler moved dir to new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same subdir */
	assert_int_equal(lookup, subdir_inode);
	/* confirm ".." still points to new parent */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	assert_int_equal(destdir_inode, lookup);
	/* link count on old parent decreased -1 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);
	/* link count on new parent increased +1 */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 3), 0);
	/* the recovery table entry was removed by handler */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 0);

	/* files still exist in dir */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, filename, &file_inode), 0);
	}

	/**************** Cleanup ***************/

	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_delete(ci, subdir_inode, filename), 0);
	}
	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_dir_failure_recoverytable_rm(void **state)
{
	inode_t subdir_inode, destdir_inode, lookup, file_inode;
	char *subdir_name = "subdir-table-rm";
	char *destdir_name = "dir-new-parent-table-rm";
	char *new_name = "subdir-table-rm-newname";
	char filename[32];
	uint16_t mode = S_IFDIR | 0750;
	int i;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - child directory was removed from old parent
	 * - ".." link to old parent removed
	 * - ".." link to new parent added
	 * - child directory added to new parent
	 * - ganesha goes down directly afterwards
	 *
	 * logic follows order in ccow_fsio_dir_move()
	 */

	/* make a sub directory */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
		mode, 0, 0, &subdir_inode), 0);

	/* populate with some files */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_touch(ci, subdir_inode, filename,
		    0750, 0, 0, &file_inode), 0);
	}

	/* can find child in parent */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, subdir_name, &lookup), 0);
	/* can find ".." in child */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	/* ".." points to parent */
	assert_int_equal(CCOW_FSIO_ROOT_INODE, lookup);
	/* link count on parent increased +1 */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 5), 0);

	/************** Failure setup ******************/

	/* do a move */
	assert_int_equal(ccow_fsio_move(ci, CCOW_FSIO_ROOT_INODE, subdir_name,
		destdir_inode, new_name), 0);

	/* insert the sub dir back into the recovery table,
	 * to simulate failure before recovery table removal */
	assert_int_equal(testonly_recovery_insert_moved(ci, subdir_inode,
	    CCOW_FSIO_ROOT_INODE, subdir_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm it exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 1);

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm subdir still in new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same subdir */
	assert_int_equal(lookup, subdir_inode);
	/* confirm ".." still points to new parent */
	assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, "..", &lookup), 0);
	assert_int_equal(destdir_inode, lookup);
	/* link count on old parent */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);
	/* link count on new parent */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 3), 0);
	/* only the recovery table entry was removed by handler */
	assert_int_equal(testonly_recovery_entry_exists(ci, subdir_inode, 16), 0);

	/* files still exist in dir */
	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_lookup(ci, subdir_inode, filename, &file_inode), 0);
	}

	/**************** Cleanup ***************/

	for (i = 0; i < NUM_OF_FLAT_FILE; i++) {
		sprintf(filename, "move_file_%d", i);
		assert_int_equal(ccow_fsio_delete(ci, subdir_inode, filename), 0);
	}
	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_file_failure_recoverytable_add(void **state)
{
	inode_t file_inode, destdir_inode, lookup;
	char *file_name = "file-move";
	char *destdir_name = "dir-new-parent";
	char *new_name = "file-move-newname";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - ganesha goes down directly afterwards
	 *
	 * logic follows order in ccow_fsio_dir_move()
	 */

	/* make a file */
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name,
		    0750, 0, 0, &file_inode), 0);
	/* can find child in parent */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_name, &lookup), 0);
	assert_int_equal(lookup, file_inode);

	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/************** Failure setup ******************/

	/* insert the file into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, file_inode,
	    CCOW_FSIO_ROOT_INODE, file_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm it exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 1);

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* recovery only removes table entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 0);
	/* confirm file still in old parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_name, &lookup), 0);
	/* it's the same file */
	assert_int_equal(lookup, file_inode);
	/* link count on old parent unchanged */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);
	/* link count on new parent unchanged */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, file_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_file_failure_src(void **state)
{
	inode_t file_inode, destdir_inode, lookup;
	char *file_name = "file-move-src";
	char *destdir_name = "dir-new-parent-src";
	char *new_name = "file-move-src-newname";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - file removed from old parent
	 * - ganesha goes down directly afterwards
	 *
	 * logic follows order in ccow_fsio_dir_move()
	 */

	/* make a file */
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name,
		    0750, 0, 0, &file_inode), 0);
	/* can find child in parent */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_name, &lookup), 0);
	assert_int_equal(lookup, file_inode);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/************** Failure setup ******************/

	/* insert the file into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, file_inode,
	    CCOW_FSIO_ROOT_INODE, file_name, destdir_inode, new_name, 1, 1), 0);
	/* confirm it exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 1);
	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, CCOW_FSIO_ROOT_INODE, file_name, 0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_name, &lookup), ENOENT);

	/************** Recovery ******************/

	/* recover the orphan */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm recovery moved to  new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same file */
	assert_int_equal(lookup, file_inode);
	/* link count on old parent unchanged */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);
	/* link count on new parent unchanged */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);
	/* recovery removed table entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_file_failure_dest(void **state)
{
	inode_t file_inode, destdir_inode, lookup;
	char *file_name = "file-move-dest";
	char *destdir_name = "dir-new-parent-dest";
	char *new_name = "file-move-dest-newname";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - file removed from old parent
	 * - file added to new parent
	 * - ganesha goes down directly afterwards
	 *
	 * logic follows order in ccow_fsio_dir_move()
	 */

	/* make a file */
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name,
		    0750, 0, 0, &file_inode), 0);
	/* can find child in parent */
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_name, &lookup), 0);
	assert_int_equal(lookup, file_inode);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);

	/************** Failure setup ******************/

	/* insert the file into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, file_inode,
	    CCOW_FSIO_ROOT_INODE, file_name, destdir_inode, new_name, 1, 1), 0);
	/* confirm it exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 1);
	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, CCOW_FSIO_ROOT_INODE, file_name, 0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, file_name, &lookup), ENOENT);
	/* add to new parent */
	assert_int_equal(testonly_dir_add_entry(ci, destdir_inode, new_name, file_inode, 0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	assert_int_equal(lookup, file_inode);

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* recovery only removes table entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 0);
	/* otherwise still in dest directory */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same file */
	assert_int_equal(lookup, file_inode);
	/* link count on old parent unchanged */
	assert_int_equal(verify_link_count_uncached(ci, CCOW_FSIO_ROOT_INODE, 4), 0);
	/* link count on new parent unchanged */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 2), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_file_enoent(void **state)
{
	inode_t file_inode, destdir_inode, lookup;
	char *file_name = "file-move-gone";
	char *destdir_name = "dir-new-parent-gone";
	char *new_name = "file-move-gone-newname";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - file inode no longer exists
	 *
	 * logic follows order in ccow_fsio_dir_move()
	 * TODO: actually, not sure how this test case is possible,
	 * as a delete would have overwritten move recovery entry
	 */

	/* make a file */
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, file_name,
		    0750, 0, 0, &file_inode), 0);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);

	/************** Failure setup ******************/

	/* insert the file into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, file_inode,
	    CCOW_FSIO_ROOT_INODE, file_name, destdir_inode, new_name, 1, 1), 0);
	/* confirm it exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 1);
	/* remove the file -- must do this via this test api
	 * and not ccow_fsio_delete, as we don't want to disturb the
	 * recovery entry
	 */
	assert_int_equal(testonly_inode_delete_unsafe(ci,
	    CCOW_FSIO_ROOT_INODE, file_name, file_inode), 0);

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* recovery only removes table entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 0);
	/* check for delete entry too */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 6), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_recovery_threshhold(void **state)
{
	inode_t file_inode_recovered, file_inode_filtered, destdir_inode, lookup;
	char *file_name_recovered = "file-recovered";
	char *file_name_filtered = "file-filtered";
	char *destdir_name = "dir-parent-threshhold";
	char *new_name_recovered = "file-recovered-newname";
	char *new_name_filtered = "file-filtered-newname";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on processing recovery table
	 * - recovery entry with timestamp above threshhold is processed
	 * - recovery entry with timestamp below threshhold not processed
	 */

	/* make a file */
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE,
	    file_name_recovered, 0750, 0, 0, &file_inode_recovered), 0);
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE,
	    file_name_filtered, 0750, 0, 0, &file_inode_filtered), 0);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);

	/************** Failure setup ******************/

	/* remove file from old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, CCOW_FSIO_ROOT_INODE,
	    file_name_recovered, 0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE,
	    file_name_recovered, &lookup), ENOENT);
	assert_int_equal(testonly_dir_remove_entry(ci, CCOW_FSIO_ROOT_INODE,
	    file_name_filtered, 0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE,
	    file_name_filtered, &lookup), ENOENT);

	/* get current time in microseconds */
	uint64_t current_time = get_nondecreasing_timestamp_us();
	/* 1 second greater than threshhold for allowing recovery
	 * see RECOVERY_HANDLER_THRESHHOLD
	 */
	uint64_t threshhold_time = current_time - (81 * 1000000);
	/* insert the file into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci,
	    file_inode_recovered, CCOW_FSIO_ROOT_INODE, file_name_recovered,
	    destdir_inode, new_name_recovered, 1, threshhold_time), 0);
	assert_int_equal(testonly_recovery_insert_moved(ci,
	    file_inode_filtered, CCOW_FSIO_ROOT_INODE, file_name_filtered,
	    destdir_inode, new_name_filtered, 1, current_time), 0);

	/************** Recovery ******************/

	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* handler recovers orphan with timestamp exceeds threshhold */
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name_recovered,
	    &lookup), 0);
	/* it's the same file */
	assert_int_equal(lookup, file_inode_recovered);
	/* handler removes table entry with timestamp exceeds threshhold */
	assert_int_equal(testonly_recovery_entry_exists(ci,
	    file_inode_recovered, 16), 0);

	/* handler does not recover orphan with timestamp under threshhold */
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name_filtered,
	    &lookup), ENOENT);
	/* handler leaves table entry with timestamp under threshhold */
	assert_int_equal(testonly_recovery_entry_exists(ci,
	    file_inode_filtered, 16), 1);

	/**************** Cleanup ***************/

	/* have to use unsafe delete test api, since it doesn't have a
	 * parent and I don't want to wait 110 seconds to recover it
	 */
	assert_int_equal(testonly_inode_delete_unsafe(ci, CCOW_FSIO_ROOT_INODE,
	    file_name_filtered, file_inode_filtered), 0);
	/* Note: the delete from the inode put will remove the recovery entry */
	assert_int_equal(ccow_fsio_delete(ci, destdir_inode,
	    new_name_recovered), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE,
	    destdir_name), 0);
}

static void
test_move_file_source_gone(void **state)
{
	inode_t file_inode, srcdir_inode, destdir_inode, lookup;
	char *file_name = "file-src-gone";
	char *srcdir_name = "dir-old-parent-src-gone";
	char *destdir_name = "dir-new-parent-src-gone";
	char *new_name = "file-src-gone-newname";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added for the intended move
	 * - file removed from source directory
	 * - source directory was deleted
	 */

	/* make an old parent directory source */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, srcdir_name,
	    mode, 0, 0, &srcdir_inode), 0);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
	    mode, 0, 0, &destdir_inode), 0);
	/* make a file */
	assert_int_equal(ccow_fsio_touch(ci, srcdir_inode, file_name,
	    0750, 0, 0, &file_inode), 0);


	/************** Failure setup ******************/

	/* insert the file into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, file_inode,
	    srcdir_inode, file_name, destdir_inode, new_name, 1, 1), 0);
	/* confirm entry exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 1);
	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, srcdir_inode, file_name,
	    0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, srcdir_inode, file_name, &lookup),
	    ENOENT);
	/* delete old parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, srcdir_name), 0);

	/************** Recovery ******************/

	/* recover the orphan */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm recovery moved to  new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same file */
	assert_int_equal(lookup, file_inode);
	/* recovery removed table entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_dir_source_gone(void **state)
{
	inode_t dir_inode, srcdir_inode, destdir_inode, lookup;
	char *dir_name = "subdir-src-gone";
	char *srcdir_name = "dir-src-src-gone";
	char *destdir_name = "dir-dest-src-gone";
	char *new_name = "subdir-src-gone-newname";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added
	 * - directory removed from old parent
	 * - ganesha goes down
	 * - source directory was deleted
	 */

	/* make an old parent directory source */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, srcdir_name,
	    mode, 0, 0, &srcdir_inode), 0);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
	    mode, 0, 0, &destdir_inode), 0);
	/* make a sub-directory */
	assert_int_equal(ccow_fsio_mkdir(ci, srcdir_inode, dir_name,
	    mode, 0, 0, &dir_inode), 0);


	/************** Failure setup ******************/

	/* insert the dir into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, dir_inode,
	    srcdir_inode, dir_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm entry exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, dir_inode, 16), 1);
	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, srcdir_inode, dir_name,
	    1), 0);
	assert_int_equal(ccow_fsio_lookup(ci, srcdir_inode, dir_name, &lookup),
	    ENOENT);
	/* delete old parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, srcdir_name), 0);

	/************** Recovery ******************/

	/* recover the orphan */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm recovery moved to  new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same directory */
	assert_int_equal(lookup, dir_inode);
	/* recovery removed table entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, dir_inode, 16), 0);
	/* check ".." exists and points to new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, dir_inode, "..", &lookup), 0);
	assert_int_equal(lookup, destdir_inode);
	/* verify link count */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 3), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_dir_source_gone_dot_rm(void **state)
{
	inode_t dir_inode, srcdir_inode, destdir_inode, lookup;
	char *dir_name = "subdir-src-gone-dot-rm";
	char *srcdir_name = "dir-src-src-gone-dot-rm";
	char *destdir_name = "dir-dest-src-gone-dot-rm";
	char *new_name = "subdir-src-gone-dot-rm-newname";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added
	 * - directory removed from old parent
	 * - ".." link to old parent removed
	 * - ganesha goes down
	 * - source directory was deleted
	 */

	/* make an old parent directory source */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, srcdir_name,
	    mode, 0, 0, &srcdir_inode), 0);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
	    mode, 0, 0, &destdir_inode), 0);
	/* make a sub-directory */
	assert_int_equal(ccow_fsio_mkdir(ci, srcdir_inode, dir_name,
	    mode, 0, 0, &dir_inode), 0);


	/************** Failure setup ******************/

	/* insert the dir into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, dir_inode,
	    srcdir_inode, dir_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm entry exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, dir_inode, 16), 1);
	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, srcdir_inode, dir_name,
	    1), 0);
	assert_int_equal(ccow_fsio_lookup(ci, srcdir_inode, dir_name, &lookup),
	    ENOENT);
	/* remove ".." from subdir */
	assert_int_equal(testonly_dir_remove_entry(ci, dir_inode, "..",
	    0), 0);
	/* delete old parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, srcdir_name), 0);

	/************** Recovery ******************/

	/* recover the orphan */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm recovery moved to new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same directory */
	assert_int_equal(lookup, dir_inode);
	/* recovery removed table entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, dir_inode, 16), 0);
	/* check ".." exists and points to new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, dir_inode, "..", &lookup), 0);
	assert_int_equal(lookup, destdir_inode);
	/* verify link count */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 3), 0);
	assert_int_equal(verify_link_count_uncached(ci, dir_inode, 2), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_dir_source_gone_dot_add(void **state)
{
	inode_t dir_inode, srcdir_inode, destdir_inode, lookup;
	char *dir_name = "subdir-src-gone-dot-add";
	char *srcdir_name = "dir-src-src-gone-dot-add";
	char *destdir_name = "dir-dest-src-gone-dot-add";
	char *new_name = "subdir-src-gone-dot-add-rename";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added
	 * - directory removed from old parent
	 * - ".." link to old parent removed
	 * - ".." link to new parent added
	 * - ganesha goes down
	 * - source directory was deleted
	 */

	/* make an old parent directory source */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, srcdir_name,
	    mode, 0, 0, &srcdir_inode), 0);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
	    mode, 0, 0, &destdir_inode), 0);
	/* make a sub-directory */
	assert_int_equal(ccow_fsio_mkdir(ci, srcdir_inode, dir_name,
	    mode, 0, 0, &dir_inode), 0);

	/************** Failure setup ******************/

	/* insert the dir into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, dir_inode,
	    srcdir_inode, dir_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm entry exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, dir_inode, 16), 1);
	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, srcdir_inode, dir_name,
	    1), 0);
	assert_int_equal(ccow_fsio_lookup(ci, srcdir_inode, dir_name, &lookup),
	    ENOENT);
	/* remove ".." from subdir */
	assert_int_equal(testonly_dir_remove_entry(ci, dir_inode, "..",
	    0), 0);
	/* add ".." to new parent */
	assert_int_equal(testonly_dir_add_entry(ci, dir_inode, "..",
	    destdir_inode, 0), 0);
	/* delete old parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, srcdir_name), 0);

	/************** Recovery ******************/

	/* recover the orphan */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm recovery moved to new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, destdir_inode, new_name, &lookup), 0);
	/* it's the same directory */
	assert_int_equal(lookup, dir_inode);
	/* recovery removed table entry */
	assert_int_equal(testonly_recovery_entry_exists(ci, dir_inode, 16), 0);
	/* check ".." exists and points to new parent */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, dir_inode, "..", &lookup), 0);
	assert_int_equal(lookup, destdir_inode);
	/* verify link counts */
	assert_int_equal(verify_link_count_uncached(ci, destdir_inode, 3), 0);
	assert_int_equal(verify_link_count_uncached(ci, dir_inode, 2), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci, destdir_inode, new_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
}

static void
test_move_dir_dest_gone(void **state)
{
	inode_t dir_inode, srcdir_inode, destdir_inode, lookup;
	char *dir_name = "subdir-dest-gone";
	char *srcdir_name = "dir-src-dest-gone";
	char *destdir_name = "dir-dest-dest-gone";
	char *new_name = "subdir-dest-gone-rename";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added
	 * - directory removed from old parent
	 * - ganesha goes down
	 * - destination directory was deleted
	 */

	/* make an old parent directory source */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, srcdir_name,
	    mode, 0, 0, &srcdir_inode), 0);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
	    mode, 0, 0, &destdir_inode), 0);
	/* make a sub-directory */
	assert_int_equal(ccow_fsio_mkdir(ci, srcdir_inode, dir_name,
	    mode, 0, 0, &dir_inode), 0);

	/************** Failure setup ******************/

	/* insert the dir into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, dir_inode,
	    srcdir_inode, dir_name, destdir_inode, new_name, 2, 1), 0);
	/* confirm entry exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, dir_inode, 16), 1);
	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, srcdir_inode, dir_name,
	    1), 0);
	assert_int_equal(ccow_fsio_lookup(ci, srcdir_inode, dir_name, &lookup),
	    ENOENT);
	/* delete the destination parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);

	/************** Recovery ******************/

	/* recover the orphan */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm the directory is in the .lost+found */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_LOST_FOUND_DIR_INODE,
	    new_name, &lookup), 0);
	/* it's the same inode */
	assert_int_equal(lookup, dir_inode);
	/* validate ".." points to .lost+found */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, dir_inode, "..", &lookup), 0);
	assert_int_equal(lookup, CCOW_FSIO_LOST_FOUND_DIR_INODE);
	/* link count for .lost+found increased */
	assert_int_equal(verify_link_count_uncached(ci,
	    CCOW_FSIO_LOST_FOUND_DIR_INODE, 3), 0);
	/* link count for subdir is same */
	assert_int_equal(verify_link_count_uncached(ci, dir_inode, 2), 0);
	/* recovery entry was removed */
	assert_int_equal(testonly_recovery_entry_exists(ci, dir_inode, 16), 0);

	/**************** Cleanup ***************/
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE,
	    srcdir_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_LOST_FOUND_DIR_INODE,
	    new_name), 0);
	assert_int_equal(verify_link_count_uncached(ci,
	    CCOW_FSIO_LOST_FOUND_DIR_INODE, 2), 0);
}

static void
test_move_file_dest_gone(void **state)
{
	inode_t file_inode, srcdir_inode, destdir_inode, lookup;
	char *file_name = "file-dest-gone";
	char *srcdir_name = "dir-src-dest-gone";
	char *destdir_name = "dir-dest-dest-gone";
	char *new_name = "file-dest-gone-rename";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added
	 * - directory removed from old parent
	 * - ganesha goes down
	 * - destination directory was deleted
	 */

	/* make an old parent directory source */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, srcdir_name,
	    mode, 0, 0, &srcdir_inode), 0);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, destdir_name,
	    mode, 0, 0, &destdir_inode), 0);
	/* make a file */
	assert_int_equal(ccow_fsio_touch(ci, srcdir_inode, file_name,
	    0750, 0, 0, &file_inode), 0);

	/************** Failure setup ******************/

	/* insert the file into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci, file_inode,
	    srcdir_inode, file_name, destdir_inode, new_name, 1, 1), 0);
	/* confirm entry exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 1);
	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci, srcdir_inode, file_name,
	    0), 0);
	assert_int_equal(ccow_fsio_lookup(ci, srcdir_inode, file_name, &lookup),
	    ENOENT);
	/* delete the destination parent */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, destdir_name), 0);

	/************** Recovery ******************/

	/* recover the orphan */
	assert_int_equal(testonly_recovery_handler(ci), 0);

	/************ Validate Recovery ***********/

	/* confirm the file is in the .lost+found */
	lookup = 0;
	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_LOST_FOUND_DIR_INODE,
	    new_name, &lookup), 0);
	/* it's the same inode */
	assert_int_equal(lookup, file_inode);
	/* link count for .lost+found unchanged */
	assert_int_equal(verify_link_count_uncached(ci,
	    CCOW_FSIO_LOST_FOUND_DIR_INODE, 2), 0);
	/* link count for file is same */
	assert_int_equal(verify_link_count_uncached(ci, file_inode, 1), 0);
	/* recovery entry was removed */
	assert_int_equal(testonly_recovery_entry_exists(ci, file_inode, 16), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE,
	    srcdir_name), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_LOST_FOUND_DIR_INODE,
	    new_name), 0);
	assert_int_equal(verify_link_count_uncached(ci,
	    CCOW_FSIO_LOST_FOUND_DIR_INODE, 2), 0);
}

static void
test_move_file_lost_found_gone_part1(void **state)
{
	inode_t file_inode, srcdir_inode, destdir_inode, lookup;
	char *file_name = "file-lf-gone";
	char *srcdir_name = "dir-src-lf-gone";
	char *destdir_name = "dir-dest-lf-gone";
	char *new_name = "file-lf-gone-rename";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on move failure:
	 * - recovery entry added
	 * - directory removed from old parent
	 * - ganesha goes down
	 * - destination directory was deleted
	 * - .lost+found deleted
	 *
	 * Notes:
	 * 1) This test case crosses libccowfsio_teardown3/setup3 and
	 *    test_recovery_on_startup_part2, so always must be executed
	 *    together
	 * 2) We use a bogus timestamp so we don't have to finagle
	 *    the threshhold to kick in. We've also tested the threshhold
	 *    logic separately in test_recovery_threshhold.
	 */

	/* make an old parent directory source */
	assert_int_equal(ccow_fsio_mkdir(ci3, CCOW_FSIO_ROOT_INODE, srcdir_name,
	    mode, 0, 0, &srcdir_inode), 0);
	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci3, CCOW_FSIO_ROOT_INODE, destdir_name,
	    mode, 0, 0, &destdir_inode), 0);
	/* make a file */
	assert_int_equal(ccow_fsio_touch(ci3, srcdir_inode, file_name,
	    0750, 0, 0, &file_inode), 0);
	/* save the inode for part2 */
	part1_inode1 = file_inode;

	/************** Failure setup ******************/

	/* insert the file into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci3, file_inode,
	    srcdir_inode, file_name, destdir_inode, new_name, 1, 1), 0);
	/* confirm entry exists (MOVE = 16) */
	assert_int_equal(testonly_recovery_entry_exists(ci3, file_inode, 16), 1);
	/* remove from the old parent */
	assert_int_equal(testonly_dir_remove_entry(ci3, srcdir_inode, file_name,
	    0), 0);
	assert_int_equal(ccow_fsio_lookup(ci3, srcdir_inode, file_name, &lookup),
	    ENOENT);
	/* delete the destination parent */
	assert_int_equal(ccow_fsio_delete(ci3, CCOW_FSIO_ROOT_INODE, destdir_name), 0);
	/* delete the .lost+found */
	assert_int_equal(ccow_fsio_delete(ci3, CCOW_FSIO_ROOT_INODE, LOST_FOUND_DIR_NAME), 0);

	/************** Recovery ******************/

	/* add to .lost+found should fail, but handler doesn't return err,
	 * only errors should be logged (expect error messages if
	 * CCOW_LOG_STDOUT=1)
	 */
	assert_int_equal(testonly_recovery_handler(ci3), 0);

	/************ Validate Recovery ***********/

	/* confirm the recovery entry still exists */
	assert_int_equal(testonly_recovery_entry_exists(ci3, file_inode, 16), 1);

	/* now must run libccowfsio_teardown3/setup3 and
	 * recovery_on_startup_part2...
	 */
}

static void
test_recovery_on_startup_part1(void **state)
{
	inode_t file_inode, destdir_inode, lookup;
	char *file_name = "file-move-startup";
	char *destdir_name = "dir-parent-threshhold";
	char *new_name = "file-move-startup-newname";
	uint16_t mode = S_IFDIR | 0750;

	/* test case scenario on recovery
	 * - insert move into recovery table
	 * - shutdown fsio
	 * - startup fsio
	 * - validate recovery triggered on startup
	 * Notes:
	 * 1) This test case crosses libccowfsio_teardown3/setup3 and
	 *    test_recovery_on_startup_part2, so always must be executed
	 *    together
	 * 2) We use a bogus timestamp so we don't have finagle
	 *    the threshhold to kick in. We've also tested the threshhold
	 *    logic separately in test_recovery_threshhold.
	 */

	/* make a file */
	assert_int_equal(ccow_fsio_touch(ci3, CCOW_FSIO_ROOT_INODE,
	    file_name, 0750, 0, 0, &file_inode), 0);
	/* save the inode for part2 */
	part1_inode2 = file_inode;

	/* make a new parent directory destination for the move */
	assert_int_equal(ccow_fsio_mkdir(ci3, CCOW_FSIO_ROOT_INODE, destdir_name,
		mode, 0, 0, &destdir_inode), 0);

	/************** Failure setup ******************/

	/* remove file from old parent */
	assert_int_equal(testonly_dir_remove_entry(ci3, CCOW_FSIO_ROOT_INODE,
	    file_name, 0), 0);
	assert_int_equal(ccow_fsio_lookup(ci3, CCOW_FSIO_ROOT_INODE,
	    file_name, &lookup), ENOENT);
	/* insert the file into the recovery table */
	assert_int_equal(testonly_recovery_insert_moved(ci3,
	    file_inode, CCOW_FSIO_ROOT_INODE, file_name,
	    destdir_inode, new_name, 1, 1), 0);

	/* do the fsio shutdown... */
}

static void
test_recovery_on_startup_part2(void **state)
{
	inode_t file_inode1, lf_inode;
	char *srcdir_name1 = "dir-src-lf-gone";
	char *new_name1 = "file-lf-gone-rename";

	inode_t file_inode2, destdir_inode2;
	char *file_name2 = "file-move-startup";
	char *destdir_name2 = "dir-parent-threshhold";
	char *new_name2 = "file-move-startup-newname";

	/* Test case scenarios to test recovery handler is run
	 * on FSIO init in ccow_fsio_export_create()
	 *
	 * 1) Setup done in test_move_file_lost_found_gone_part1():
	 * - insert move of file into recovery table
	 * - remove file from old source parent directory
	 * - delete destination directory
	 * - delete .lost+found directory
	 *
	 * 2) Setup done in test_recovery_on_startup_part1():
	 * - insert move of file into recovery table
	 * - remove file from old source parent directory
	 *
	 * 3) Do libccowfsio_teardown3/setup3
	 * - Shutdown and startup should re-create .lost+found for
	 *   scenario *   (1) above.
	 * - Recovery handler should run and move file from scenario (1)
	 *   into .lost+found.
	 * - Recovery handler should successfully complete move for file
	 *   from scenario (2).
	 *
	 * Notes:
	 * This test case crosses libccowfsio_teardown/setup and
	 * test_recovery_on_startup_part1, so always must be executed
	 * together
	 */

	/************ Validate Recovery ***********/

	/* Scenario (1) */

	/* confirm the .lost+found was re-created */
	assert_int_equal(ccow_fsio_lookup(ci3, CCOW_FSIO_ROOT_INODE,
	    LOST_FOUND_DIR_NAME, &lf_inode), 0);
	assert_int_equal(lf_inode, CCOW_FSIO_LOST_FOUND_DIR_INODE);
	/* the file from test_move_file_lost_found_gone_part1() was
	 * moved into .lost+found
	 */
	assert_int_equal(ccow_fsio_lookup(ci3, CCOW_FSIO_LOST_FOUND_DIR_INODE,
	    new_name1, &file_inode1), 0);
	/* it's the same inode we saved earlier */
	assert_int_equal(file_inode1, part1_inode1);
	/* validate link count for .lost+found */
	assert_int_equal(verify_link_count_uncached(ci3,
	    CCOW_FSIO_LOST_FOUND_DIR_INODE, 2), 0);
	/* link count for file is same */
	assert_int_equal(verify_link_count_uncached(ci3, file_inode1, 1), 0);
	/* recovery entry was removed */
	assert_int_equal(testonly_recovery_entry_exists(ci3, file_inode1, 16), 0);

	/* Scenario (2) */

	/* get the dest dir */
	assert_int_equal(ccow_fsio_lookup(ci3, CCOW_FSIO_ROOT_INODE,
	    destdir_name2, &destdir_inode2), 0);
	/* handler recovered orphan */
	assert_int_equal(ccow_fsio_lookup(ci3, destdir_inode2, new_name2,
	    &file_inode2), 0);
	/* it's the same inode from part1 */
	assert_int_equal(file_inode2, part1_inode2);
	/* handler removed table entry */
	assert_int_equal(testonly_recovery_entry_exists(ci3, file_inode2, 16), 0);

	/**************** Cleanup ***************/

	assert_int_equal(ccow_fsio_delete(ci3, CCOW_FSIO_LOST_FOUND_DIR_INODE,
	    new_name1), 0);
	assert_int_equal(verify_link_count_uncached(ci3,
	    CCOW_FSIO_LOST_FOUND_DIR_INODE, 2), 0);
	assert_int_equal(ccow_fsio_delete(ci3, CCOW_FSIO_ROOT_INODE,
	    srcdir_name1), 0);
	assert_int_equal(ccow_fsio_delete(ci3, destdir_inode2, new_name2), 0);
	assert_int_equal(ccow_fsio_delete(ci3, CCOW_FSIO_ROOT_INODE,
	    destdir_name2), 0);
}

static void
test_ccow_fsio_is_not_empty(void **state)
{
	inode_t file_inode1, file_inode2, lookup;
	char *file_name1 = "file-in-root";
	char *file_name2 = "file-in-lf";

	/* TODO: This test case is not working. ccow_fsio_is_not_empty and
	 * ccow_fsio_delete_bucket want a logger, and fsio_lg gets reset
	 * by those apis, which later causes ASAN error.
	 */

	/* test bucket empty check for .lost+found not empty */

	/* add file to root */
	assert_int_equal(ccow_fsio_touch(ci3, CCOW_FSIO_ROOT_INODE,
	    file_name1, 0750, 0, 0, &file_inode1), 0);

	/* add file to .lost+found */
	assert_int_equal(ccow_fsio_touch(ci3, CCOW_FSIO_LOST_FOUND_DIR_INODE,
	    file_name2, 0750, 0, 0, &file_inode2), 0);

	/* validate is not empty */
	assert_int_equal(ccow_fsio_is_not_empty(cl, FSIO_EXPORT_PATH3,
	    NULL), 1);

	/* remove file under root */
	assert_int_equal(ccow_fsio_delete(ci3, CCOW_FSIO_ROOT_INODE,
	    file_name1), 0);

	/* validate still is not empty */
	assert_int_equal(ccow_fsio_is_not_empty(cl, FSIO_EXPORT_PATH3,
	    NULL), 1);

	/* remove file under .lost+found */
	assert_int_equal(ccow_fsio_delete(ci3, CCOW_FSIO_LOST_FOUND_DIR_INODE,
	    file_name2), 0);

	/* validate empty */
	assert_int_equal(ccow_fsio_is_not_empty(cl, FSIO_EXPORT_PATH3,
	    NULL), 0);

	/* now delete bucket */
	assert_int_equal(ccow_fsio_delete_bucket(cl, FSIO_EXPORT_PATH3,
	    NULL), 0);
}

int
main(int argc, char **argv)
{
	int create_bucket_only = 0, opt = 0;

	while ((opt = getopt(argc, argv, "nc")) != -1) {
		switch(opt) {
			case 'n':
				dd = 1;
				break;
			case 'c':
				create_bucket_only = 1;
				break;
			default:
				break;
		}
	}

	if (!create_bucket_only) {
		const UnitTest tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(bucket_create2),
			unit_test(libccowfsio_setup),
			unit_test(libccowfsio_setup2),

			unit_test(test_create_delete_ops),
			unit_test(test_namespace_ops),
			unit_test(test_metadata_ops),
			unit_test(test_read_write_ops),
			unit_test(test_clone),
			unit_test(test_create_eexist),
			unit_test(test_mkdir_failure_after_inode_creation),
			unit_test(test_mkdir_failure_after_dotdot),

			unit_test(test_rmdir_failure_directory_notempty),
			unit_test(test_rmdir_failure_after_recovery_insert),
			unit_test(test_rmdir_failure_before_dotdot),
			unit_test(test_rmdir_failure_before_dotdot_parent_deleted),
			unit_test(test_rmdir_failure_before_mark_deletion),
			unit_test(test_rmdir_failure_before_mark_deletion_parent_deleted),
			unit_test(test_rm_file_failure_after_recovery_insert),
			unit_test(test_rm_file_failure_after_dir_rm_entry),
			unit_test(test_rm_file_failure_after_dir_rm_entry_parent_deleted),
			unit_test(test_rm_file_failure_after_update_md),

			unit_test(test_move_dir_failure_recoverytable_add),
			unit_test(test_move_dir_failure_rm_src),
			unit_test(test_move_dir_failure_rm_dotdot),
			unit_test(test_move_dir_failure_add_dotdot),
			unit_test(test_move_dir_failure_recoverytable_rm),
			unit_test(test_move_file_failure_recoverytable_add),
			unit_test(test_move_file_failure_src),
			unit_test(test_move_file_failure_dest),
			unit_test(test_move_file_enoent),
			unit_test(test_move_file_source_gone),
			unit_test(test_move_dir_source_gone),
			unit_test(test_move_dir_source_gone_dot_rm),
			unit_test(test_move_dir_source_gone_dot_add),
			unit_test(test_move_dir_dest_gone),
			unit_test(test_move_file_dest_gone),
			unit_test(test_recovery_threshhold),

			unit_test(bucket_create3),
			unit_test(libccowfsio_setup3),
			unit_test(test_move_file_lost_found_gone_part1),
			unit_test(test_recovery_on_startup_part1),
			unit_test(libccowfsio_teardown3),
			unit_test(libccowfsio_setup3),
			unit_test(test_recovery_on_startup_part2),
			unit_test(libccowfsio_teardown3),
			unit_test(bucket_delete3),

			unit_test(libccowfsio_teardown2),
			unit_test(libccowfsio_teardown),
			unit_test(bucket_delete),
			unit_test(bucket_delete2),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		return run_tests(tests);
	} else {
		const UnitTest tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(libccowfsio_setup),
			unit_test(libccowfsio_teardown),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		return run_tests(tests);
	}
}
