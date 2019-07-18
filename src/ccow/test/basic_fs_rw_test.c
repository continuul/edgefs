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

#define PATTERN_CHUNKS	128
#define	CHUNK_SZ	(1024 * 1024)
#define	PATTERN_BUFFER_SZ	(PATTERN_CHUNKS * CHUNK_SZ)
#define CHUNK_X_SZ 999999
#define CHUNK_Y_SZ 400000
#define CHUNK_Z_SZ (1024 * 1024 - 1)
#define	MIN(a, b) (((a) < (b))?(a):(b))

unsigned char pattern_md5[MD5_DIGEST_LENGTH];
ccow_t tc = NULL;
static ci_t *ci;
static char *testfile = "/BIGFILE";
char *pattern_buf;
int dd = 0;

int
_touch(ci_t *ci, char *path, uint16_t mode, uint16_t uid, uint16_t gid)
{
	char *dir, *filename;
	inode_t inode;
	int err;

	err = ccow_fsio_find(ci, path, &inode);
	if (err == 0)
		return (EEXIST);
	if (err != ENOENT)
		return (err);

	dir = je_strdup(path);
	if (dir == NULL)
		return (ENOMEM);

	filename = strrchr(dir, '/');
	if (filename == NULL) {
		err = EINVAL;
		goto errout;
	}
	*filename = '\0';
	filename++;
	if (strlen(filename) == 0) {
		err = EINVAL;
		goto errout;
	}
	if (strlen(dir) == 0) {
		inode = CCOW_FSIO_ROOT_INODE;
	} else {
		err = ccow_fsio_find(ci, dir, &inode);
		if (err != 0)
			goto errout;
	}

	ccow_fsio_touch(ci, inode, filename, mode, uid, gid, NULL);

errout:
	je_free(dir);
	return (err);
}

static void
test_create(void **state)
{
	struct stat stat;
	inode_t inode;

	ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, "", 0755, 1, 1, NULL);
	_touch(ci, testfile, 0640, 0, 0);
	assert_int_equal(ccow_fsio_find(ci, testfile, &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
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
	int c;
	char tmp_buff[CHUNK_SZ];

	pattern_buf = je_malloc(PATTERN_BUFFER_SZ);
	assert(pattern_buf != NULL);

	char ch = 0;
	for (int i=0; i<CHUNK_SZ; i++) {
		tmp_buff[i] = ch++;
	}

	for (int i=0; i<PATTERN_CHUNKS; i++) {
		memcpy(pattern_buf + i*CHUNK_SZ, tmp_buff, CHUNK_SZ);
	}

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

static void
test_write_op(void **state)
{
	ccow_fsio_file_t *file;
	size_t write_amount;

	printf("===================== Write Test ======================\n");
	ccow_fsio_open(ci, testfile, &file, O_WRONLY);
	char *new_pattern_buff = (char *)je_malloc(PATTERN_BUFFER_SZ);
	memcpy(new_pattern_buff, pattern_buf, PATTERN_BUFFER_SZ);
	ccow_fsio_write(file, 0, PATTERN_BUFFER_SZ, (void *)new_pattern_buff, &write_amount);
	ccow_fsio_close(file);
}

static void
test_read_op_file(char *testfile)
{
	unsigned char md5[MD5_DIGEST_LENGTH];
	ccow_fsio_file_t *file;
	struct stat stat;
	inode_t inode;
	size_t read;
	char *data;
	int o, eof;

	printf("===================== Read Test =========================\n");
	ccow_fsio_open(ci, testfile, &file, O_RDONLY);
	assert_int_equal(ccow_fsio_find(ci, testfile, &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	data = je_malloc(stat.st_size);
	assert_true(data != NULL);
	assert(ccow_fsio_read(file, 0, stat.st_size, (void *)data, &read, &eof) == 0);
	ccow_fsio_close(file);

	assert(read == (size_t)stat.st_size && eof);
	MD5((const unsigned char *)data, stat.st_size, md5);
	printf("%d: file %s, size %ju, MD5 =\"", __LINE__, testfile, stat.st_size);
	hexdump(md5, MD5_DIGEST_LENGTH);
	printf("\"\n");
	o = memcmp(md5, pattern_md5, MD5_DIGEST_LENGTH);
	printf("MD5 sum of test pattern and \"%s\" file is %sidentical\n", testfile, (o != 0) ? "not " : "");
	assert(o == 0);

	je_free(data);
}

static void
test_read_op(void **state)
{
	test_read_op_file(testfile);
}

static void
test_write_chunked_op(void **state)
{
	ccow_fsio_file_t *file;
	size_t write_amount;
	struct stat stat;
	inode_t inode;
	off_t offset;
	int cz;

	_touch(ci, "/c", 0640, 0, 0);
	assert_int_equal(ccow_fsio_find(ci, "/c", &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	cz = stat.st_blksize;
	assert(cz == 1024 *1024);
	printf("=============== Write Test (chunk size %d) ==============\n", cz);
	ccow_fsio_open(ci, "/c", &file, O_WRONLY);
	for (offset = 0; offset < PATTERN_BUFFER_SZ; offset += cz) {
		size_t write_sz = MIN(PATTERN_BUFFER_SZ - offset, cz);
		char *new_pattern_buff = (char *)je_malloc(write_sz);
		memcpy(new_pattern_buff, pattern_buf+offset, write_sz);
		ccow_fsio_write(file, offset, write_sz,
		    (void *)new_pattern_buff, &write_amount);
		assert(write_amount == write_sz);
	}
	ccow_fsio_close(file);

	test_read_op_file("/c");
}

static void
test_interlived_write(void **state)
{
	ccow_fsio_file_t *fhy, *fhx, *fhz;
	size_t write_amount;
	char *fx, *fy, *fz;
	int x, y, z, f;

	fx = "/x";
	fy = "/y";
	fz = "/z";

	_touch(ci, fx, 0640, 0, 0);
	_touch(ci, fy, 0640, 0, 0);
	_touch(ci, fz, 0640, 0, 0);

	ccow_fsio_open(ci, fx, &fhx, O_RDWR);
	ccow_fsio_open(ci, fy, &fhy, O_RDWR);
	ccow_fsio_open(ci, fz, &fhz, O_RDWR);

	f = x = y = z = 0;
	while (1) {
		if ((PATTERN_BUFFER_SZ - x) > CHUNK_X_SZ) {
			char *new_pattern_buff = (char *)je_malloc(CHUNK_X_SZ);
			memcpy(new_pattern_buff, pattern_buf + x, CHUNK_X_SZ);
			ccow_fsio_write(fhx, x, CHUNK_X_SZ, (void *)new_pattern_buff, &write_amount);
			x += write_amount;
		} else
			f |= 1;
		if ((PATTERN_BUFFER_SZ - y) > CHUNK_Y_SZ) {
			char *new_pattern_buff = (char *)je_malloc(CHUNK_Y_SZ);
			memcpy(new_pattern_buff, pattern_buf + y, CHUNK_Y_SZ);
			ccow_fsio_write(fhy, y, CHUNK_Y_SZ, (void *)new_pattern_buff, &write_amount);
			y += write_amount;
		} else
			f |= 2;
		if ((PATTERN_BUFFER_SZ - z) > CHUNK_Z_SZ) {
			char *new_pattern_buff = (char *)je_malloc(CHUNK_Z_SZ);
			memcpy(new_pattern_buff, pattern_buf + z, CHUNK_Z_SZ);
			ccow_fsio_write(fhz, z, CHUNK_Z_SZ, (void *)new_pattern_buff, &write_amount);
			z += write_amount;
		} else
			f |= 4;
		if (f == 7)
			break;
	}
	if ((PATTERN_BUFFER_SZ - x) > 0) {
		char *new_pattern_buff = (char *)je_malloc(PATTERN_BUFFER_SZ - x);
		memcpy(new_pattern_buff, pattern_buf + x, PATTERN_BUFFER_SZ - x);
		ccow_fsio_write(fhx, x, PATTERN_BUFFER_SZ - x, (void *)new_pattern_buff, &write_amount);
		x += write_amount;
	}

	if ((PATTERN_BUFFER_SZ - y) > 0) {
		char *new_pattern_buff = (char *)je_malloc(PATTERN_BUFFER_SZ - y);
		memcpy(new_pattern_buff, pattern_buf + y, PATTERN_BUFFER_SZ - y);
		ccow_fsio_write(fhy, y, PATTERN_BUFFER_SZ - y, (void *)new_pattern_buff, &write_amount);
		y += write_amount;
	}
	if ((PATTERN_BUFFER_SZ - z) > 0) {
		char *new_pattern_buff = (char *)je_malloc(PATTERN_BUFFER_SZ - z);
		memcpy(new_pattern_buff, pattern_buf + z, PATTERN_BUFFER_SZ - z);
		ccow_fsio_write(fhz, z, PATTERN_BUFFER_SZ - z, (void *)new_pattern_buff, &write_amount);
		z += write_amount;
	}

	assert(x == PATTERN_BUFFER_SZ);
	assert(y == PATTERN_BUFFER_SZ);
	assert(z == PATTERN_BUFFER_SZ);

	ccow_fsio_close(fhx);
	ccow_fsio_close(fhy);
	ccow_fsio_close(fhz);

	test_read_op_file("/x");
	test_read_op_file("/y");
	test_read_op_file("/z");
}

static void
test_interlived_threaded_write(void **state)
{
	ccow_fsio_file_t *fhy, *fhx, *fhz;
	size_t write_amount;
	char *fx, *fy, *fz;
	int x, y, z, f;

	fx = "/x";
	fy = "/y";
	fz = "/z";

	_touch(ci, fx, 0640, 0, 0);
	_touch(ci, fy, 0640, 0, 0);
	_touch(ci, fz, 0640, 0, 0);

	ccow_fsio_open(ci, fx, &fhx, O_RDWR);
	ccow_fsio_open(ci, fy, &fhy, O_RDWR);
	ccow_fsio_open(ci, fz, &fhz, O_RDWR);

	f = x = y = z = 0;
	while (1) {
		if ((PATTERN_BUFFER_SZ - x) > CHUNK_X_SZ) {
			char *new_pattern_buff = (char *)je_malloc(CHUNK_X_SZ);
			memcpy(new_pattern_buff, pattern_buf + x, CHUNK_X_SZ);
			ccow_fsio_write(fhx, x, CHUNK_X_SZ, (void *)new_pattern_buff, &write_amount);
			x += write_amount;
		} else
			f |= 1;
		if ((PATTERN_BUFFER_SZ - y) > CHUNK_Y_SZ) {
			char *new_pattern_buff = (char *)je_malloc(CHUNK_Y_SZ);
			memcpy(new_pattern_buff, pattern_buf + y, CHUNK_Y_SZ);
			ccow_fsio_write(fhy, y, CHUNK_Y_SZ, (void *)new_pattern_buff, &write_amount);
			y += write_amount;
		} else
			f |= 2;
		if ((PATTERN_BUFFER_SZ - z) > CHUNK_Z_SZ) {
			char *new_pattern_buff = (char *)je_malloc(CHUNK_Z_SZ);
			memcpy(new_pattern_buff, pattern_buf + z, CHUNK_Z_SZ);
			ccow_fsio_write(fhz, z, CHUNK_Z_SZ, (void *)new_pattern_buff, &write_amount);
			z += write_amount;
		} else
			f |= 4;
		if (f == 7)
			break;
	}
	if ((PATTERN_BUFFER_SZ - x) > 0) {
		char *new_pattern_buff = (char *)je_malloc(PATTERN_BUFFER_SZ - x);
		memcpy(new_pattern_buff, pattern_buf + x, PATTERN_BUFFER_SZ - x);
		ccow_fsio_write(fhx, x, PATTERN_BUFFER_SZ - x, (void *)new_pattern_buff, &write_amount);
		x += write_amount;
	}
	if ((PATTERN_BUFFER_SZ - y) > 0) {
		char *new_pattern_buff = (char *)je_malloc(PATTERN_BUFFER_SZ - y);
		memcpy(new_pattern_buff, pattern_buf + y, PATTERN_BUFFER_SZ - y);
		ccow_fsio_write(fhy, y, PATTERN_BUFFER_SZ - y, (void *)new_pattern_buff, &write_amount);
		y += write_amount;
	}
	if ((PATTERN_BUFFER_SZ - z) > 0) {
		char *new_pattern_buff = (char *)je_malloc(PATTERN_BUFFER_SZ - z);
		memcpy(new_pattern_buff, pattern_buf + z, PATTERN_BUFFER_SZ - z);
		ccow_fsio_write(fhz, z, PATTERN_BUFFER_SZ - z, (void *)new_pattern_buff, &write_amount);
		z += write_amount;
	}

	assert(x == PATTERN_BUFFER_SZ);
	assert(y == PATTERN_BUFFER_SZ);
	assert(z == PATTERN_BUFFER_SZ);

	ccow_fsio_close(fhx);
	ccow_fsio_close(fhy);
	ccow_fsio_close(fhz);

	test_read_op_file("/x");
	test_read_op_file("/y");
	test_read_op_file("/z");
}

static void
test_unaligned_write(void **state)
{
	ccow_fsio_file_t *file;
	size_t write_amount;

	ccow_fsio_open(ci, "/y", &file, O_RDWR);
	char *new_pattern_buff = (char *)je_malloc(4096);
	memcpy(new_pattern_buff, pattern_buf + 40000, 4096);
	ccow_fsio_write(file, 200, 4096, (void *)new_pattern_buff, &write_amount);
	ccow_fsio_close(file);
	memcpy(pattern_buf + 200, pattern_buf + 40000, 4096);

	MD5((const unsigned char *)pattern_buf, PATTERN_BUFFER_SZ, pattern_md5);
	printf("%d: PATTERN MD5 =\"", __LINE__);
	hexdump(pattern_md5, MD5_DIGEST_LENGTH);
	printf("\"\n");

	test_read_op_file("/y");
}

static void
test_bidir_op(void **state)
{
	ccow_fsio_file_t *file;
	size_t read, write_amount, sz;
	char *data, *name;
	struct stat stat;
	int eof, err, o;
	inode_t inode;
	off_t offset;
	uint8_t *md5;
	size_t file_size = 0;

	name = "/c";
	printf("============= Simultaneous Read & Write Test ===========\n");

	err = ccow_fsio_open(ci, name, &file, O_RDWR);
	assert(err == 0);

	offset = 2000000;
	sz = 88888;

	MD5((const unsigned char *)pattern_buf, PATTERN_BUFFER_SZ, pattern_md5);
	printf("%d: PATTERN MD5 BEFORE CHANGE =\"", __LINE__);
	hexdump(pattern_md5, MD5_DIGEST_LENGTH);
	printf("\"\n");

	err = ccow_fsio_read(file, offset, sz, (void *)(pattern_buf + 1234567), &read, &eof);
	assert(err == 0);
	assert(read == sz);
	assert(!eof);

	MD5((const unsigned char *)pattern_buf, PATTERN_BUFFER_SZ, pattern_md5);
	printf("%d: PATTERN MD5 AFTER CHANGE =\"", __LINE__);
	hexdump(pattern_md5, MD5_DIGEST_LENGTH);
	printf("\"\n");

	/* Make single write which (+ 1 read) is less than preallocated stream ops count */
	char *new_pattern_buff = (char *)je_malloc(PATTERN_BUFFER_SZ);
	memcpy(new_pattern_buff, pattern_buf, PATTERN_BUFFER_SZ);
	ccow_fsio_write(file, 0, PATTERN_BUFFER_SZ, (void *)new_pattern_buff, &write_amount);

	printf("Sleep 8 sec to expire autoflush timer.\n");
	sleep(8);

	/* Recalculate pattern checksum. */
	MD5((const unsigned char *)pattern_buf, PATTERN_BUFFER_SZ, pattern_md5);
	printf("%d: PATTERN MD5 =\"", __LINE__);
	hexdump(pattern_md5, MD5_DIGEST_LENGTH);
	printf("\"\n");

	ccow_fsio_get_size(file, &file_size);

	assert(file_size > 0);
	data = je_malloc(file_size);
	assert_true(data != NULL);
	ccow_fsio_read(file, 0, file_size, (void *)data, &read, &eof);

	assert(read == (size_t)file_size);

	md5 = MD5((const unsigned char *)data, file_size, NULL);
	printf("%d: file %s, size %ju, MD5 =\"", __LINE__, name, file_size);
	hexdump(md5, MD5_DIGEST_LENGTH);
	printf("\"\n");
	o = memcmp(md5, pattern_md5, MD5_DIGEST_LENGTH);
	printf("MD5 sum of test pattern and \"%s\" file BEFORE CLOSE is %sidentical\n", name,
	    (o != 0) ? "not " : "");
	assert(o == 0);

	je_free(data);

	ccow_fsio_close(file);

	/* Compare updated file with pattern. */
	printf("AFTER CLOSE:\n");
	test_read_op_file(name);
}


static void
test_unaligned_read(void **state)
{
}

static void
test_preinit(void **state)
{
	inode_t inode;

	printf("===================== Preinit ==========================\n");
	/* Root dir has inode CCOW_FSIO_ROOT_INODE. testfile + 1 to get name w/o '/'. */
	ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, testfile + 1);
	ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "c");
	ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "x");
	ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "y");
	ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "z");
}

static void
test_cleanup(void **state)
{
	inode_t inode;

	printf("===================== Clean up ==========================\n");
	/* Root dir has inode CCOW_FSIO_ROOT_INODE. testfile + 1 to get name w/o '/'. */
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, testfile + 1), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "c"), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "x"), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "y"), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "z"), 0);
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
		unit_test(test_preinit),
		unit_test(test_create),
		unit_test(generate_patern),
		unit_test(test_write_op),
		unit_test(test_read_op),
		unit_test(test_write_chunked_op),
		unit_test(test_interlived_write),
		unit_test(test_unaligned_write),
		unit_test(test_bidir_op),
		unit_test(test_cleanup),
		unit_test(free_patern),
		unit_test(libccowfsio_teardown),
		unit_test(libccow_bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
