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
#include <pthread.h>
#include <time.h>

#include <ccow.h>
#include <ccowd.h>
#include <ccowfsio.h>
#include <cmocka.h>

#include <openssl/md5.h>

#define  MIN(a, b) (((a) < (b))?(a):(b))

#define	PATTERN_BUFFER_SZ	(4 * 1024)
#define TESTFILE "bigfile"
#define TESTFILE_PATH "/bigfile"
#define TESTFILE_SIZE (1024 * 1024 * 1)

#define READ_THREAD_COUNT 70
#define WRITE_THREAD_COUNT 30
#define SETATTR_THREAD_COUNT 20
#define PER_THREAD_SETATTR_COUNT 5

unsigned char pattern_md5[MD5_DIGEST_LENGTH];
ccow_t tc = NULL;
static ci_t *ci;
char *pattern_buf;
int dd = 0;

static void
test_create(void **state)
{
	struct stat stat;
	inode_t inode;
	ccow_fsio_file_t *file;
	size_t offset = 0;
	size_t write_amount = 0;
	size_t to_write = 0;

	printf("===================== Touch Test File ======================\n");
	ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, TESTFILE);
	assert_int_equal(ccow_fsio_touch(ci, CCOW_FSIO_ROOT_INODE, TESTFILE, 0755, 0, 0, &inode), 0);

	printf("===================== Write Test File ======================\n");
	assert_int_equal(ccow_fsio_open(ci, TESTFILE_PATH, &file, O_WRONLY), 0);
	while (offset < TESTFILE_SIZE) {
		to_write = MIN(PATTERN_BUFFER_SZ, (TESTFILE_SIZE - offset));

		/* FSIO takes ownership of the write buffer.*/
		char *new_pattern_buf = (char *)je_malloc(PATTERN_BUFFER_SZ);
		memcpy(new_pattern_buf, pattern_buf, PATTERN_BUFFER_SZ);
		assert_int_equal(ccow_fsio_write(file, offset,
			    to_write, (void *)new_pattern_buf,
			    &write_amount), 0);
		offset += write_amount;
	}
	printf("Written :%d bytes\n", (int)offset);
	assert_int_equal(ccow_fsio_close(file), 0);

	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_size, TESTFILE_SIZE);
}

static void
hexdump(const unsigned char *buf, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		printf("%02x%c", buf[i], ((i % 16 == 15) ? '\n' : ' '));
	}
}

static void
generate_patern(void **state)
{
	int c, fh, max;

	pattern_buf = je_malloc(PATTERN_BUFFER_SZ);
	assert(pattern_buf != NULL);

	fh = open("/dev/urandom", O_RDONLY);
	assert(fh > 0);
	c = read(fh, pattern_buf, PATTERN_BUFFER_SZ);
	assert(c == PATTERN_BUFFER_SZ);
	close(fh);

	MD5((const unsigned char *)pattern_buf, PATTERN_BUFFER_SZ, pattern_md5);
	printf("%d: PATTERN MD5 =\"", __LINE__);
	hexdump(pattern_md5, MD5_DIGEST_LENGTH);
	printf("\"\n");
}

static void
free_patern(void **state)
{
	assert(pattern_buf != NULL);
	je_free(pattern_buf);
	pattern_buf = NULL;
}

struct thread_args
{
	ccow_fsio_file_t *file;
	struct stat stat;
	inode_t inode;
	int id;
};

struct thread_args read_threads_args[READ_THREAD_COUNT];
struct thread_args write_threads_args[WRITE_THREAD_COUNT];
struct thread_args set_attr_threads_args[SETATTR_THREAD_COUNT];

static
void *threaded_read(void *args)
{
	struct thread_args *thr_args = (struct thread_args *)args;
	ccow_fsio_file_t *file = thr_args->file;
	int thr_id = thr_args->id;
	char *data;
	size_t read_size = 0;
	size_t offset = 0;
	int eof = 0;
	size_t to_read = PATTERN_BUFFER_SZ;
	unsigned char md5[MD5_DIGEST_LENGTH];

	data = je_malloc(PATTERN_BUFFER_SZ);
	assert(data != NULL);


	while ((offset < TESTFILE_SIZE) && !eof)
	{
		to_read = MIN(PATTERN_BUFFER_SZ, TESTFILE_SIZE - offset);
		assert_int_equal(ccow_fsio_read(file, offset, to_read, (void *)data, &read_size, &eof), 0);
		offset += read_size;
		//MD5((const unsigned char *)data, read_size, md5);
		//assert_int_equal(memcmp(md5, pattern_md5, MD5_DIGEST_LENGTH), 0);
	}
	printf("threaded_read %d: Got %d bytes\n", thr_id, (int)offset);

	je_free(data);
	return NULL;
}

static
void *threaded_write(void *args)
{
	struct thread_args *thr_args = (struct thread_args *)args;
	ccow_fsio_file_t *file = thr_args->file;
	int thr_id = thr_args->id;
	size_t write_amount = 0;
	size_t offset = 0;
	size_t to_write = 0;

	while (offset < TESTFILE_SIZE) {
		to_write = MIN(PATTERN_BUFFER_SZ, (TESTFILE_SIZE - offset));

		/* FSIO takes ownership of the write buffer.*/
		char *new_pattern_buf = (char *)je_malloc(PATTERN_BUFFER_SZ);
		memcpy(new_pattern_buf, pattern_buf, PATTERN_BUFFER_SZ);
		assert_int_equal(ccow_fsio_write(file, offset,
			    to_write, (void *)new_pattern_buf,
			    &write_amount), 0);
		offset += write_amount;
	}
	printf("threaded_write %d: wrote %d bytes\n", thr_id, (int)offset);

	return NULL;
}

static
void *threaded_set_attr(void *args)
{
	struct thread_args *thr_args = (struct thread_args *)args;
	int thr_id = thr_args->id;
	inode_t inode = thr_args->inode;
	struct stat stat = thr_args->stat;
	int i;

	stat.st_uid = thr_id;
	stat.st_gid = thr_id;

	for(i=0; i<PER_THREAD_SETATTR_COUNT; i++){
		assert_int_equal(ccow_fsio_set_file_stat(ci, inode, &stat), 0);
		sleep(1);
	}

	return NULL;
}

static void
multiple_reader(void **testfile)
{
	pthread_t tids[READ_THREAD_COUNT];
	ccow_fsio_file_t *file;
	int i;

	assert_int_equal(ccow_fsio_open(ci, TESTFILE_PATH, &file, O_RDONLY), 0);
	printf("===================== Creating Read threads ==========================\n");
	for (i=0; i<READ_THREAD_COUNT; i++)
	{
		read_threads_args[i].file = file;
		read_threads_args[i].id = i;
		assert_int_equal(pthread_create(&tids[i], NULL, threaded_read, &read_threads_args[i]), 0);
	}

	printf("===================== Waiting for Read threads ==========================\n");
	for (i=0; i<READ_THREAD_COUNT; i++)
	{
		assert_int_equal(pthread_join(tids[i], NULL), 0);
	}
	assert_int_equal(ccow_fsio_close(file), 0);
}


static void
multiple_writer(void **testfile)
{
	pthread_t tids[WRITE_THREAD_COUNT];
	ccow_fsio_file_t *file;
	int i;

	assert_int_equal(ccow_fsio_open(ci, TESTFILE_PATH, &file, O_RDWR), 0);
	printf("===================== Creating Write threads ==========================\n");
	for (i=0; i<WRITE_THREAD_COUNT; i++)
	{
		write_threads_args[i].file = file;
		write_threads_args[i].id = i;
		assert_int_equal(pthread_create(&tids[i], NULL, threaded_write, &write_threads_args[i]), 0);
	}

	printf("===================== Waiting for Write threads ==========================\n");
	for (i=0; i<WRITE_THREAD_COUNT; i++)
	{
		assert_int_equal(pthread_join(tids[i], NULL), 0);
	}
	assert_int_equal(ccow_fsio_close(file), 0);
}

static void
multiple_set_attr(void **testfile)
{
	pthread_t tids[SETATTR_THREAD_COUNT];
	struct stat stat;
	inode_t inode;
	int i;

	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, TESTFILE, &inode), 0);
	printf("inode: %lu\n", inode);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);

	printf("===================== Creating set_attr threads ==========================\n");
	for (i=0; i<SETATTR_THREAD_COUNT; i++)
	{
		set_attr_threads_args[i].file = NULL;
		set_attr_threads_args[i].stat = stat;
		set_attr_threads_args[i].id = i;
		set_attr_threads_args[i].inode = inode;
		assert_int_equal(pthread_create(&tids[i], NULL, threaded_set_attr, &set_attr_threads_args[i]), 0);
	}

	printf("===================== Waiting for set_attr threads ==========================\n");
	for (i=0; i<SETATTR_THREAD_COUNT; i++)
	{
		assert_int_equal(pthread_join(tids[i], NULL), 0);
	}
}


static void
multiple_reads_writes_set_attr(void **testfile)
{
	pthread_t r_tids[READ_THREAD_COUNT];
	pthread_t w_tids[WRITE_THREAD_COUNT];
	pthread_t s_tids[SETATTR_THREAD_COUNT];
	struct stat stat;
	inode_t inode;
	ccow_fsio_file_t *file;
	int i;

	assert_int_equal(ccow_fsio_open(ci, TESTFILE_PATH, &file, O_RDWR), 0);
	printf("===================== Creating Read threads ==========================\n");
	for (i=0; i<READ_THREAD_COUNT; i++)
	{
		read_threads_args[i].file = file;
		read_threads_args[i].id = i;
		assert_int_equal(pthread_create(&r_tids[i], NULL, threaded_read, &read_threads_args[i]), 0);
	}

	printf("===================== Creating Write threads ==========================\n");
	for (i=0; i<WRITE_THREAD_COUNT; i++)
	{
		write_threads_args[i].file = file;
		write_threads_args[i].id = i;
		assert_int_equal(pthread_create(&w_tids[i], NULL, threaded_write, &write_threads_args[i]), 0);
	}


	assert_int_equal(ccow_fsio_lookup(ci, CCOW_FSIO_ROOT_INODE, TESTFILE, &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);

	printf("===================== Creating set_attr threads ==========================\n");
	for (i=0; i<SETATTR_THREAD_COUNT; i++)
	{
		set_attr_threads_args[i].file = NULL;
		set_attr_threads_args[i].stat = stat;
		set_attr_threads_args[i].id = i;
		set_attr_threads_args[i].inode = inode;
		assert_int_equal(pthread_create(&s_tids[i], NULL, threaded_set_attr, &set_attr_threads_args[i]), 0);
	}

	printf("===================== Waiting for set_attr threads ==========================\n");
	for (i=0; i<SETATTR_THREAD_COUNT; i++)
	{
		assert_int_equal(pthread_join(s_tids[i], NULL), 0);
	}

	printf("===================== Waiting for Write threads ==========================\n");
	for (i=0; i<WRITE_THREAD_COUNT; i++)
	{
		assert_int_equal(pthread_join(w_tids[i], NULL), 0);
	}


	printf("===================== Waiting for Read threads ==========================\n");
	for (i=0; i<READ_THREAD_COUNT; i++)
	{
		assert_int_equal(pthread_join(r_tids[i], NULL), 0);
	}
	assert_int_equal(ccow_fsio_close(file), 0);
}

static void
test_cleanup(void **state)
{
	printf("===================== Clean up ==========================\n");
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, TESTFILE), 0);
}

static void
libccowfsio_setup(void **state)
{
	assert_int_equal(ccow_fsio_init(), 0);
	ci = ccow_fsio_ci_alloc();
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
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

		unit_test(generate_patern),
		unit_test(test_create),
		unit_test(multiple_reader),
		unit_test(multiple_writer),
		unit_test(multiple_set_attr),
		unit_test(multiple_reads_writes_set_attr),

		unit_test(test_cleanup),
		unit_test(free_patern),

		unit_test(libccowfsio_teardown),
		unit_test(libccow_bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
