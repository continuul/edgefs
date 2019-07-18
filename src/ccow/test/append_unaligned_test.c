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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "ccowd.h"
#include "replicast.h"

#define TEST_FILE_CLUSTER	"cltest"
#define TEST_FILE_TENANT	"test"
#define TEST_BUCKET_NAME        "unaligned-obj-bucket"
#define TEST_FILE_OID		"file"
#define TEST_FILE_PART1		"file.1"
#define TEST_FILE_PART2		"file.2"
#define TEST_FILE_PART3		"file.3"
#define ITER_TEST_CHUNKMAP		"btreenam"
#define ITER_TEST_CHUNKMAP_BS		1024
#define PUT_FILE_BS			524288

extern int errno;
char *cluster_name = TEST_FILE_CLUSTER;
char *tenant_name = TEST_FILE_TENANT;
char *bucket_name = TEST_BUCKET_NAME;
char *object_name = TEST_FILE_OID;
const char *parts[3] = {TEST_FILE_PART1, TEST_FILE_PART2, TEST_FILE_PART3};
size_t block_size = PUT_FILE_BS;
char *src_md5;
char *dst_md5;

ccow_t cl;
int dd = 0;

static void
libccowd_setup(void **state)
{
    if(!dd) {
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
	int err = ccow_bucket_create(cl, bucket_name,
	    strlen(bucket_name) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, TEST_BUCKET_NAME, object_name, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, TEST_FILE_PART1, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, TEST_FILE_PART2, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, TEST_FILE_PART3, NULL, NULL);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, bucket_name,
	    strlen(bucket_name) + 1);
	assert_int_equal(err, 0);
}

struct mapping {
	size_t len;
	char *addr;
	size_t iovcnt;
	struct iovec *iov;
};

void get_file__cb(ccow_completion_t comp, void *arg, int index, int status)
{
	assert_non_null(arg);
	struct mapping *mp = (struct mapping *)arg;
	assert_non_null(mp->addr);
	assert_non_null(mp->iov);
	printf("get_file__cb: index %d, status %d\n", index, status);
}

static void
iter_test__init_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = ITER_TEST_CHUNKMAP_BS;
	iov[0].iov_base = je_calloc(1, iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	char * chunkmap_type = ITER_TEST_CHUNKMAP;
	uint32_t bs = ITER_TEST_CHUNKMAP_BS;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter;
	get_simple(c, TEST_BUCKET_NAME, TEST_FILE_OID, &iov[0], 1, 0, &iter);

	err = ccow_wait(c, 0);
	assert_int_equal((err && err != -ENOENT), 0);
	if (err == -ENOENT) {
		if (iter)
			ccow_lookup_release(iter);
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);
		iter = NULL;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, iter);
	assert_int_equal(err, 0);

	uint16_t enable = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_TRACK_STATISTICS,
	    (void *)&enable, iter);
	assert_int_equal(err, 0);

	char bookname_key[] = "X-Object-Meta-Book";
	char book_value[] = "GoodbyeOldFriend";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key, 19,
	    book_value, 0, iter);
	assert_int_equal(err, 0);

	char booknum_key[] = "X-Object-Meta-NumBooks";
	uint64_t books = 200*1024*1024*1024L;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, booknum_key, 23,
	    &books, 0, iter);
	assert_int_equal(err, 0);

	char cats_key[] = "X-Object-Meta-Cats";
	uint64_t cats = 3*1024*1024*1024LU;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64, cats_key, 19,
	    &cats, 0, iter);
	assert_int_equal(err, 0);
	put_simple(c, TEST_BUCKET_NAME, TEST_FILE_OID, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	if (iter)
		ccow_lookup_release(iter);
	je_free(iov[0].iov_base);
}

static void
iter_test__md_retrieve_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	int len = ITER_TEST_CHUNKMAP_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, object_name, &iov, iovcnt, 0, NULL, NULL,
	    &iter);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	if (iter)
		ccow_lookup_release(iter);
}

static void
getMD5sum(const char *object, char *md5)
{

	FILE *fp;
	char cmd[50];
	sprintf(cmd, "%s %s %s", "/usr/bin/md5sum", object, "|awk '{print $1}'");
	fp = popen(cmd, "r");
	assert_non_null(fp);
	char *res = fgets(md5, 33, fp);
	assert_non_null(res);
	pclose(fp);
}

static void
simple_get_file(void)
{
	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		printf("ccow_create_completion error: %d\n", err);
	}
	assert_int_equal(err, 0);

	printf("bucket name: %s, object name: %s\n", bucket_name, object_name);
	ccow_lookup_t iter;
	err = ccow_get(bucket_name, strlen(bucket_name) + 1, object_name,
		strlen(object_name) + 1, c, NULL, 0, 0, &iter);
	if (err) {
		ccow_release(c);
		printf("ccow_get error: %d\n", err);
	}
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	if (err) {
		printf("ccow_wait error: %d\n", err);
	}
	assert_int_equal(err, 0);

	uint64_t size = 0;
	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
		if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &size);
		}
	}
	block_size = PUT_FILE_BS;
	printf("object size %lu, block size %zu\n", size, block_size);
	if (iter)
		ccow_lookup_release(iter);
	int iovcnt = size / block_size + !!(size % block_size);
	char *iob = je_malloc(iovcnt * block_size);
	assert_non_null(iob);

	struct iovec *iov = je_malloc(iovcnt * sizeof(struct iovec));
	assert_non_null(iov);
	for (int i = 0; i < iovcnt; i++) {
		iov[i].iov_len = block_size;
		iov[i].iov_base = iob + i * block_size;
	}
	if (size % block_size)
		iov[iovcnt - 1].iov_len = size % block_size;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		printf("ccow_create_completion error: %d\n", err);
	}
	assert_int_equal(err, 0);
	err = ccow_get(bucket_name, strlen(bucket_name) + 1, object_name,
		strlen(object_name) + 1, c, iov, iovcnt, 0, NULL);
	if (err) {
		ccow_release(c);
		printf("ccow_get error: %d\n", err);
	}
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	if (err) {
		printf("ccow_wait error: %d\n", err);
	}
	assert_int_equal(err, 0);
	int fd = open(object_name, O_WRONLY | O_CREAT | O_TRUNC, 0);
	assert_true(fd >= 0);
	err = write(fd, iob, size);
	assert_int_equal(err, size);
	close(fd);
	je_free(iov);
	je_free(iob);

	dst_md5 = je_malloc(33);
	assert_non_null(dst_md5);
	getMD5sum(object_name, dst_md5);
}

static int
simple_put_unaligned_file(void)
{
	int err = 0;
	err = system("/bin/dd if=/dev/urandom of=file.1 bs=400K count=1");
	assert_int_equal(err, 0);
	err = system("/bin/dd if=/dev/urandom of=file.2 bs=500K count=1");
	assert_int_equal(err, 0);
	err = system("/bin/dd if=/dev/urandom of=file.3 bs=200K count=1");
	assert_int_equal(err, 0);
	err = system("/bin/cat file.1 file.2 file.3 > src_obj");
	assert_int_equal(err, 0);
	src_md5 = je_malloc(33);
	assert_non_null(src_md5);
	getMD5sum("src_obj", src_md5);

	size_t iovcnt=0;
	uint64_t offset = 0;
	uint64_t size = 0;
	ccow_lookup_t iter;
	struct ccow_metadata_kv *kv = NULL;
	int total_parts = 3;
	ccow_completion_t c;

	for (int part = 0; part < total_parts; part++) {
		assert_non_null(cl);

		struct stat st;

		int fd = open(parts[part], O_RDONLY);
		assert_false(fd < 0);

		err = fstat(fd, &st);
		assert_int_equal(err, 0);
		size_t len = st.st_size;
		size_t iovcnt = len / block_size + !!(len % block_size);

		if (len < block_size)
			block_size = len;

		assert_true(iovcnt > 0);

		struct iovec *iov = je_malloc(iovcnt * sizeof(struct iovec));
		assert_non_null(iov);
		char *iob = je_malloc(iovcnt * block_size);
		assert_non_null(iob);
		for (size_t i = 0; i < iovcnt; i++) {
			iov[i].iov_len = block_size;
			iov[i].iov_base = iob + i * block_size;
			ssize_t bytes = read(fd, iov[i].iov_base, block_size);
			assert_int_not_equal(bytes, -1);
		}
		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		printf("bucket name: %s, object name: %s\n", bucket_name, parts[part]);
		iov[0].iov_len = len;
		err = ccow_put(bucket_name, strlen(bucket_name) + 1, parts[part],
			strlen(parts[part]) + 1, c, iov, 1, 0);
		assert_int_equal(err, 0);
		err = ccow_wait(c, -1);
		assert_int_equal(err, 0);
		close(fd);
		je_free(iob);
		je_free(iov);

	}
	return err;
}

static void
append_objects_unaligned(void **state)
{
	simple_put_unaligned_file();
	ccow_completion_t c;
	int total_parts = 3;
	char *iob = je_malloc(total_parts * (strlen(TEST_FILE_PART1) + 1));
	assert_non_null(iob);
	struct iovec *iov = je_malloc(total_parts * sizeof(struct iovec));
	assert_non_null(iov);
	for (int i = 0; i < total_parts; i++) {
		iov[i].iov_base = iob + i * (strlen(parts[i]) + 1);
		iov[i].iov_len = strlen(parts[i]) + 1;
		strncpy((char*)iov[i].iov_base, parts[i], strlen(parts[i]) + 1);
	}

	int err = ccow_copy_objects(cluster_name, strlen(cluster_name) + 1, tenant_name,
	      strlen(tenant_name) + 1, bucket_name, strlen(bucket_name) + 1,
	      object_name, strlen(object_name) + 1, iov, total_parts, cl);
	assert_int_equal(err, 0);
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	simple_get_file();
	assert_true ((strcmp(src_md5, dst_md5)) == 0);
	je_free(src_md5);
	je_free(dst_md5);
	err = system("rm -f file*");
	assert_int_equal(err, 0);
	err = system("rm -f src_obj");
	assert_int_equal(err, 0);
	je_free(iov);
	je_free(iob);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
    if(!dd) {
        ccow_daemon_term();
    }
}

static void
usage(const char *argv0)
{
	printf(	"\n"
		"USAGE:\n"
		"	%s [-h] [-n] "
		"\n"
		"	-h	Display this message and exit\n"
		"\n"
		"	-n	Do not start daemon\n"
		"\n", argv0);

	exit(EXIT_SUCCESS);
}

int
main(int argc, char *argv[])
{
	/*
	 * Parse command line
	 */
	int opt;

	while ((opt = getopt(argc, argv, "hn")) != -1) {
		switch(opt) {
			case 'n':
				dd = 1;
				break;

			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}

	const UnitTest get_tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(iter_test__init_0_1k),
		unit_test(append_objects_unaligned),
		unit_test(iter_test__md_retrieve_0_1k),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(get_tests);
}

