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

#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

#include <ccow.h>
#include <ccowd.h>
#include <ccowfsio.h>
#include <cmocka.h>

ccow_t tc = NULL;
static ci_t *ci;
int dd = 0;
pthread_mutex_t thr_lock = PTHREAD_MUTEX_INITIALIZER;

#define SHARDED_DIR_BKNAME "fsio_sharded_dir_bk1"

void
printFileStat(ci_t *ci, char *prefix, char *path)
{
	struct stat stat;
	int err;

	inode_t inode;
	err = ccow_fsio_find(ci, path, &inode);
	if (err != 0) {
		printf("%d: File \"%s\" not found\n", __LINE__, path);
		return;
	}
	err = ccow_fsio_get_file_stat(ci, inode, &stat);
	if (err != 0) {
		printf("%d: error '%s' getting file info : %s\n", __LINE__, strerror(err), path);
		return;
	}
	printf("%d: %s: %s: %03o %d:%d i:%ju, lnk:%ld\n", __LINE__, prefix,
	    path, stat.st_mode, stat.st_uid, stat.st_gid, stat.st_ino, (long)stat.st_nlink);
}

int
dir_cb(inode_t parent, fsio_dir_entry *dir_entry, uint64_t count,  void *ptr)
{
	for (uint64_t i=0; i<count; i++) {
		printf("name: %s inode:%ju\n", dir_entry[i].name, dir_entry[i].inode);
	}
	return 0;
}

static void
readdir_helper(ci_t *ci, char *path, char *start)
{
	inode_t inode;
	assert_int_equal(ccow_fsio_find(ci, path, &inode), 0);
	bool eof;
	assert_int_equal(ccow_fsio_readdir_cb4(ci, inode, dir_cb, start, NULL, &eof), 0);
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

	err = ccow_bucket_create(tc, SHARDED_DIR_BKNAME, strlen(SHARDED_DIR_BKNAME)+1, c);
	if (err != EEXIST)
		assert_int_equal(err, 0);
}

static void
libccow_bucket_delete(void **state)
{
	int err;
	assert_non_null(tc);

	err = ccow_bucket_delete(tc, SHARDED_DIR_BKNAME, strlen(SHARDED_DIR_BKNAME)+1);
	assert_int_equal(err, 0);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	ccow_tenant_term(tc);
}


static void
libccowfsio_setup(void **state)
{
	assert_int_equal(ccow_fsio_init(), 0);
	ci = ccow_fsio_ci_alloc();
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());

	assert_int_equal(ccow_fsio_create_export(ci, "cltest/test/" SHARDED_DIR_BKNAME,
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

#define TEST_DIR_NAME "test-dir"
#define TEST_DIR_PATH "/test-dir"
#define FILE_NAME_PREFIX "foo"
#define MAX_FILE_NAME_LEN 256

uint64_t RAND_THREAD_COUNT = 2;
uint64_t THREAD_COUNT = 16;
int FILE_PER_THREAD = 10; // if you change it, do not forget to increase
                          // random_* array sizes by (FILE_PER_THREAD * FILE_PER_THREAD)
int random_insert_success[100];
int random_insert_error[100];
int random_remove_success[100];
int random_remove_error[100];
inode_t dir_inode = 0;

static
void *threaded_insert(void *args)
{
	char file_name[MAX_FILE_NAME_LEN];
	uint64_t thread_id = (uint64_t) args;

	printf("%s thread_id: %lu\n", __func__, thread_id);

	for (int i=0; i<FILE_PER_THREAD; i++) {
		snprintf(file_name, MAX_FILE_NAME_LEN, "%s_%d_%lu", FILE_NAME_PREFIX, i, thread_id);
		int err = ccow_fsio_touch(ci, dir_inode, file_name, 0755, 0, 0, NULL);
		if (err != EAGAIN && err != EEXIST && err != 0)
			assert_int_equal(err, 0);
	}

	return NULL;
}

static
void *threaded_remove(void *args)
{
	char file_name[MAX_FILE_NAME_LEN];
	uint64_t thread_id = (uint64_t) args;

	for (int i=0; i<FILE_PER_THREAD; i++) {
		snprintf(file_name, MAX_FILE_NAME_LEN, "%s_%d_%lu", FILE_NAME_PREFIX, i, thread_id);
		assert_int_equal(ccow_fsio_delete(ci, dir_inode, file_name), 0);;
		assert_int_equal(ccow_fsio_delete(ci, dir_inode, file_name), ENOENT);;
	}
	return NULL;
}

static
void *threaded_insert_random(void *args)
{
	char file_name[MAX_FILE_NAME_LEN];
	int err = 0;

	for (int i=0; i<FILE_PER_THREAD * FILE_PER_THREAD; i++) {
		snprintf(file_name, MAX_FILE_NAME_LEN, "%s_%d", FILE_NAME_PREFIX, i);
		err = ccow_fsio_touch(ci, dir_inode, file_name, 0755, 0, 0, NULL);
		assert_int_equal(err == 0 || err == EEXIST, 1);
		pthread_mutex_lock(&thr_lock);
		if (err == 0) {
			assert(random_insert_success[i] == 0);
			random_insert_success[i]++;
		}
		else {
			assert(random_insert_error[i] == 0);
			random_insert_error[i]++;
		}
		pthread_mutex_unlock(&thr_lock);
	}
	return NULL;
}

static
void *threaded_remove_random(void *args)
{
	char file_name[MAX_FILE_NAME_LEN];
	int err = 0;

	for (int i=0; i<FILE_PER_THREAD * FILE_PER_THREAD; i++) {
		snprintf(file_name, MAX_FILE_NAME_LEN, "%s_%d", FILE_NAME_PREFIX, i);
		err = ccow_fsio_delete(ci, dir_inode, file_name);
		assert_int_equal(err == 0 || err == ENOENT, 1);
		pthread_mutex_lock(&thr_lock);
		if (err == 0) {
			assert(random_remove_success[i] == 0);
			random_remove_success[i]++;
		}
		else {
			assert(random_remove_error[i] == 0);
			random_remove_error[i]++;
		}
		pthread_mutex_unlock(&thr_lock);
	}
	return NULL;
}

static void
test_parallel_insert_random(void **state)
{
	pthread_t tids[RAND_THREAD_COUNT];

	printf("Parallel insert random\n");
	assert_int_not_equal(dir_inode, 0);

	memset(random_insert_success, 0, 100);
	memset(random_insert_error, 0, 100);

	printf("Creating insert threads\n");
	for (uint64_t i=0; i<RAND_THREAD_COUNT; i++)
		assert_int_equal(pthread_create(&tids[i], NULL, threaded_insert_random, NULL), 0);

	printf("Waiting for insert threads\n");
	for (uint64_t i=0; i<RAND_THREAD_COUNT; i++)
		assert_int_equal(pthread_join(tids[i], NULL), 0);

	printf("Dir after inserts:\n");
	readdir_helper(ci, TEST_DIR_PATH, NULL);

	//Each file must be created successfully once and only once
	for (int i=1; i<(FILE_PER_THREAD * FILE_PER_THREAD); i++){
		if (random_insert_success[i] != 1 || random_insert_error[i] != 1) {
			printf("insert problem with file :%d success:%d error:%d\n",
			    i, random_insert_success[i], random_insert_error[i]);
		}
		pthread_mutex_lock(&thr_lock);
		assert(random_insert_success[i] == 1);
		assert(random_insert_error[i] == 1);
		pthread_mutex_unlock(&thr_lock);
	}
}

static void
test_parallel_remove_random(void **state)
{
	pthread_t tids[RAND_THREAD_COUNT];
	char full_file_name[MAX_FILE_NAME_LEN];

	printf("Parallel remove random\n");
	assert_int_not_equal(dir_inode, 0);

	for (int i=0; i<FILE_PER_THREAD * FILE_PER_THREAD; i++) {
		snprintf(full_file_name, MAX_FILE_NAME_LEN, "%s/%s_%d", TEST_DIR_PATH, FILE_NAME_PREFIX, i);
		assert_int_equal(ccow_fsio_exists(ci, full_file_name), 1);
	}

	printf("Creating remove threads\n");
	for (uint64_t i=0; i<RAND_THREAD_COUNT; i++)
		assert_int_equal(pthread_create(&tids[i], NULL, threaded_remove_random, NULL), 0);

	printf("Waiting for remove threads\n");
	for (uint64_t i=0; i<RAND_THREAD_COUNT; i++)
		assert_int_equal(pthread_join(tids[i], NULL), 0);

	printf("Dir after remove:\n");
	readdir_helper(ci, TEST_DIR_PATH, NULL);

	//Each file must be deleted successfully once and only once
	for (int i=1; i<(FILE_PER_THREAD * FILE_PER_THREAD); i++){
		if (random_remove_success[i] != 1 || random_remove_error[i] != 1) {
			printf("remove problem with file :%d success:%d error:%d\n",
			    i, random_remove_success[i], random_remove_error[i]);
		}
		pthread_mutex_lock(&thr_lock);
		assert(random_remove_success[i] == 1);
		assert(random_remove_error[i] == 1);
		pthread_mutex_unlock(&thr_lock);
	}
}

static void
test_parallel_insert(void **state)
{
	pthread_t tids[THREAD_COUNT];

	printf("Parallel insert\n");
	assert_int_not_equal(dir_inode, 0);

	printf("Creating insert threads\n");
	for (uint64_t i=0; i<THREAD_COUNT; i++)
		assert_int_equal(pthread_create(&tids[i], NULL, threaded_insert, (void *)i), 0);

	printf("Waiting for insert threads\n");
	for (uint64_t i=0; i<THREAD_COUNT; i++)
		assert_int_equal(pthread_join(tids[i], NULL), 0);

	printf("Dir after inserts:\n");
	readdir_helper(ci, TEST_DIR_PATH, NULL);
}

static void
test_parallel_remove(void **state)
{
	pthread_t tids[THREAD_COUNT];

	printf("Parallel remove\n");
	assert_int_not_equal(dir_inode, 0);

	printf("Creating remove threads\n");
	for (uint64_t i=0; i<THREAD_COUNT; i++)
		assert_int_equal(pthread_create(&tids[i], NULL, threaded_remove, (void *)i), 0);

	printf("Waiting for remove threads\n");
	for (uint64_t i=0; i<THREAD_COUNT; i++)
		assert_int_equal(pthread_join(tids[i], NULL), 0);

	printf("Dir after remove:\n");
	readdir_helper(ci, TEST_DIR_PATH, NULL);
}

static void
test_create_dir(void **state)
{
	printf("mkdir\n");
	int err = ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, TEST_DIR_NAME, 0755, 0, 0, NULL);
	if (err && err != EEXIST)
		assert_int_equal(err, 0);
	assert_int_equal(ccow_fsio_find(ci, TEST_DIR_PATH, &dir_inode), 0);
}

static void
test_cleanup(void **state)
{
	printf("rmdir\n");
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, TEST_DIR_NAME), 0);
}

static void
test_sharded_ops(void **state)
{
#define FSIO_SHARD_COUNT 16
#define ENTRIES 5
	int err = 0;
	ccow_shard_context_t list_context = NULL;
	char oid[] = "fsio-shard-test-oid";
	uint64_t ENTRY_SIZE = 504;
	struct iovec iov[2];
	char *keys[ENTRIES] = {"key1", "key2", "key3", "key4", "key5"};
	int64_t size = 0, link = 0, blocks = 0;

	assert_non_null(tc);

	// Create sharded list
	err = ccow_shard_context_create(oid, strlen(oid)+1,
	    FSIO_SHARD_COUNT, &list_context);
	assert_int_equal(err, 0);

	err = ccow_sharded_list_create(tc,
	    SHARDED_DIR_BKNAME, strlen(SHARDED_DIR_BKNAME)+1,
	    list_context);
	assert_int_equal(err, 0);

	/* Init attribute to zero */
	err = ccow_sharded_attributes_put(tc,
	    SHARDED_DIR_BKNAME, strlen(SHARDED_DIR_BKNAME)+1,
	    list_context,
	    oid, strlen(oid)+1, 0, 0, 0);
	assert_int_equal(err, 0);

	/* Add entries and set size accordingly */
	for (uint64_t i=0; i<ENTRIES; i++) {
		iov[0].iov_base = keys[i];
		iov[0].iov_len = strlen(keys[i]) + 1;
		iov[1].iov_base = NULL;
		iov[1].iov_len = 0;

		err = ccow_sharded_list_put(tc,
		    SHARDED_DIR_BKNAME, strlen(SHARDED_DIR_BKNAME)+1,
		    list_context, iov, 2);
		assert_int_equal(err, 0);

		err = ccow_sharded_attributes_put(tc,
		    SHARDED_DIR_BKNAME, strlen(SHARDED_DIR_BKNAME)+1,
		    list_context,
		    oid, strlen(oid)+1, ENTRY_SIZE, 1, 7);
		assert_int_equal(err, 0);
	}

	/* Get and confirm size attribute */
	err = ccow_sharded_attributes_get(tc,
	    SHARDED_DIR_BKNAME, strlen(SHARDED_DIR_BKNAME)+1,
	    list_context,
	    &size, &link, &blocks);
	assert_int_equal(err, 0);

	printf("Got link: %ld, blocks: %ld, size:%ld\n",
	    link, blocks, size);

	assert_int_equal(link, ENTRIES * 1);
	assert_int_equal(blocks, ENTRIES * 7);
	assert_int_equal(size, ENTRIES * ENTRY_SIZE);

	/* cleanup */
	if (list_context) {
		ccow_sharded_list_destroy(tc,
		    SHARDED_DIR_BKNAME, strlen(SHARDED_DIR_BKNAME)+1,
		    list_context);
		ccow_shard_context_destroy(&list_context);
	}
}

int
main(int argc, char **argv)
{
	if (argc == 2) {
		if (strcmp(argv[1], "-n") == 0)
			dd = 1;
	}

	printf("THREAD_COUNT: %lu RAND_THREAD_COUNT %lu FILE_PER_THREAD: %d\n",
	    THREAD_COUNT, RAND_THREAD_COUNT, FILE_PER_THREAD);

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(libccow_bucket_create),
		unit_test(libccowfsio_setup),
		unit_test(test_create_dir),
		unit_test(test_parallel_insert),
		unit_test(test_parallel_remove),
		unit_test(test_parallel_insert_random),
		unit_test(test_parallel_remove_random),
		unit_test(test_cleanup),
		unit_test(test_sharded_ops),
		unit_test(libccowfsio_teardown),
		unit_test(libccow_bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
