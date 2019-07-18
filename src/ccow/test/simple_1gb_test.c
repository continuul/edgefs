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

#define TEST_BUCKET_NAME	"put-1gb-bucket-test"
#define INPUT_BUFFER_SIZE_128K	(128 * 1024)

ccow_t cl = NULL, tc = NULL;
unsigned char *checksumput, *checksumget;
char *rand_input_buf;
int dd = 0;

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
	int fd;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
	assert_int_equal(ccow_admin_init(buf, "cltest", 7, &tc), 0);
	je_free(buf);
	rand_input_buf = (char *)je_calloc(1, INPUT_BUFFER_SIZE_128K);
	assert(rand_input_buf);

	fd = open("/dev/urandom", O_RDONLY);
	int len = read(fd, rand_input_buf, INPUT_BUFFER_SIZE_128K);
	assert(len);
	close(fd);
}

static void
bucket_create(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_create(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *		Put Cont Test
 * =======================================================================
 */
#define SIMPLE_TEST_OID		"simple-test"
#define SIMPLE_TEST_OID2	"simple-test2"
#define SIMPLE_TEST_BS		(1024 * 1024)
#define INPUT_BUFFER_SIZE	(1024 * 1024 * 1024UL)
#define TEST_BLOCK_SIZE		(1024 * 1024)
#define TEST_IOVCNT		64
#define RAND_BUFS		1

static void
object_delete(void **state)
{
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID2, NULL, NULL);
}

static void
simple_random128k_streamall_put(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec *iov_in;
	uint64_t before, read_ns;

	iov_in = (struct iovec *)je_malloc(1 * sizeof(struct iovec));
	iov_in[0].iov_len = INPUT_BUFFER_SIZE_128K;
	iov_in[0].iov_base = rand_input_buf;

	before = uv_hrtime();
	checksumput = getMd5sum(rand_input_buf, INPUT_BUFFER_SIZE_128K);
	read_ns = (uv_hrtime() - before);
	printf("%u Bytes Checksummed in: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE_128K,
	    read_ns / 1e9, fmt(INPUT_BUFFER_SIZE_128K / (read_ns / 1e9)));

	uint64_t genid = 0;
	ccow_completion_t c;
	err = ccow_create_stream_completion(cl, NULL, NULL, 2, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
	assert_int_equal(err, 0);

	int index;
	before = uv_hrtime();
	err = ccow_put_cont(c, &iov_in[0], 1, 0, 1, &index);
	assert_int_equal(err, 0);

	err = ccow_wait(c, index);
	assert_int_equal(err, 0);

	printf(" now flushing ...\n");
	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	read_ns = (uv_hrtime() - before);
	printf("%u Bytes Written: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE_128K,
	    read_ns / 1e9, fmt(INPUT_BUFFER_SIZE_128K / (read_ns / 1e9)));

	je_free(iov_in);
}

static void
simple_random128k_streamall_get(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec *iov_in;
	uint64_t before, read;

	iov_in = (struct iovec *)je_malloc(1 * sizeof(struct iovec));
	iov_in[0].iov_len = INPUT_BUFFER_SIZE_128K;
	iov_in[0].iov_base = je_calloc(1, iov_in[0].iov_len);

	uint64_t genid = 0;
	ccow_completion_t c;
	err = ccow_create_stream_completion(cl, NULL, NULL, 2, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
	assert_int_equal(err, 0);

	before = uv_hrtime();

	int index;
	err = ccow_get_cont(c, &iov_in[0], 1, 0, 1, &index);
	assert_int_equal(err, 0);

	err = ccow_wait(c, index);
	assert_int_equal(err, 0);

	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	read = (uv_hrtime() - before);
	printf("%u Bytes Read: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE_128K, read / 1e9,
	    fmt(INPUT_BUFFER_SIZE_128K / (read / 1e9)));

	before = uv_hrtime();
	checksumget = getMd5sum(iov_in[0].iov_base, INPUT_BUFFER_SIZE_128K);
	read = (uv_hrtime() - before);

	printf("%u Bytes Checksummed: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE_128K,
	    read / 1e9, fmt(INPUT_BUFFER_SIZE_128K / (read / 1e9)));

	je_free(iov_in[0].iov_base);
	je_free(iov_in);
}

static void
simple_1gb_streamall_put(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec *iov_in;
	uint64_t before, read;
	size_t num_iov = INPUT_BUFFER_SIZE / TEST_BLOCK_SIZE;

	char *input_buf = (char *)je_calloc(1, INPUT_BUFFER_SIZE);
	char *p = input_buf;
	iov_in = (struct iovec *)je_malloc(num_iov * sizeof(struct iovec));

	for (size_t i = 0; i < num_iov; i++) {
		iov_in[i].iov_len = TEST_BLOCK_SIZE;
		iov_in[i].iov_base = p;
		if (RAND_BUFS || i % 2) {
			*(long *)p = i;
			memcpy(p + 8, rand_input_buf, 8);
		}
		p += TEST_BLOCK_SIZE;
	}
	before = uv_hrtime();
	checksumput = getMd5sum(input_buf, INPUT_BUFFER_SIZE);
	read = (uv_hrtime() - before);
	printf("%lu Bytes Checksummed in: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE,
	    read / 1e9, fmt(INPUT_BUFFER_SIZE / (read / 1e9)));

	uint64_t genid = 0;
	ccow_completion_t c;
	err = ccow_create_stream_completion(cl, NULL, NULL, num_iov + 1, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
	assert_int_equal(err, 0);

	before = uv_hrtime();
	int op_cnt = 1;
	struct iovec *iov_ptr = NULL;
	size_t i = 0;
	for (i = 0; i < num_iov / TEST_IOVCNT; i++)
	{
		iov_ptr = &iov_in[i * TEST_IOVCNT];
		err = ccow_put_cont(c, iov_ptr, TEST_IOVCNT,
		    TEST_BLOCK_SIZE * i * TEST_IOVCNT, 0, NULL);
		assert_int_equal(err, 0);
		printf(".");
	}
	if (num_iov % TEST_IOVCNT) {
		iov_ptr = &iov_in[(num_iov / TEST_IOVCNT) * TEST_IOVCNT];
		err = ccow_put_cont(c, iov_ptr, num_iov % TEST_IOVCNT,
		    TEST_BLOCK_SIZE * (num_iov / TEST_IOVCNT) * TEST_IOVCNT,
		    0, NULL);
		assert_int_equal(err, 0);
		printf(".");
	}
	printf(" now flushing ...\n");
	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	read = (uv_hrtime() - before);
	printf("%lu Bytes Written: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE,
	    read / 1e9, fmt(INPUT_BUFFER_SIZE / (read / 1e9)));

	je_free(iov_in);
	je_free(input_buf);
}

static void
simple_1gb_streamall_get(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec *iov_in;
	uint64_t before, read;
	size_t num_iov = INPUT_BUFFER_SIZE / TEST_BLOCK_SIZE;

	iov_in = (struct iovec *)je_malloc(num_iov * sizeof(struct iovec));

	for (size_t i = 0; i < num_iov; i++) {
		iov_in[i].iov_len = TEST_BLOCK_SIZE;
		iov_in[i].iov_base = je_calloc(1, iov_in[i].iov_len);
		*(long *)iov_in[i].iov_base = i + 1;
	}

	uint64_t genid = 0;
	ccow_completion_t c;
	err = ccow_create_stream_completion(cl, NULL, NULL, num_iov + 1, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
	assert_int_equal(err, 0);

	before = uv_hrtime();

	int op_cnt = 1;
	struct iovec *iov_ptr = NULL;
	size_t i = 0;
	for (i = 0; i < num_iov / TEST_IOVCNT; i++)
	{
		iov_ptr = &iov_in[i * TEST_IOVCNT];
		err = ccow_get_cont(c, iov_ptr, TEST_IOVCNT,
		    TEST_BLOCK_SIZE * i * TEST_IOVCNT, 1, NULL);
		assert_int_equal(err, 0);
		err = ccow_wait(c, op_cnt++);
		assert_int_equal(err, 0);
	}
	if (num_iov % TEST_IOVCNT) {
		iov_ptr = &iov_in[(num_iov / TEST_IOVCNT) * TEST_IOVCNT];
		err = ccow_get_cont(c, iov_ptr, num_iov % TEST_IOVCNT,
		    TEST_BLOCK_SIZE * (num_iov / TEST_IOVCNT) * TEST_IOVCNT,
		    1, NULL);
		assert_int_equal(err, 0);
		err = ccow_wait(c, op_cnt++);
		assert_int_equal(err, 0);
	}
	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	read = (uv_hrtime() - before);
	printf("%lu Bytes Read: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE, read / 1e9,
	    fmt(INPUT_BUFFER_SIZE / (read / 1e9)));

	char *input_buf = (char *)je_calloc(1, INPUT_BUFFER_SIZE);
	char *p = input_buf;
	for ( size_t i = 0; i < num_iov; i++) {
		memcpy(p, iov_in[i].iov_base, TEST_BLOCK_SIZE);
		p+=TEST_BLOCK_SIZE;
	}

	before = uv_hrtime();
	checksumget = getMd5sum(input_buf, INPUT_BUFFER_SIZE);
	read = (uv_hrtime() - before);

	printf("%lu Bytes Checksummed: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE,
	    read / 1e9, fmt(INPUT_BUFFER_SIZE / (read / 1e9)));

	for (size_t i = 0; i < num_iov; i++) {
		je_free(iov_in[i].iov_base);
	}
	je_free(iov_in);
	je_free(input_buf);
}

static void
simple_1gb_stream_put(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec *iov_in;
	uint64_t before, read;
	uint64_t genid = 0;
	ccow_completion_t c;
	size_t num_iov = INPUT_BUFFER_SIZE / TEST_BLOCK_SIZE;

	char *input_buf = (char *)je_calloc(1, INPUT_BUFFER_SIZE);
	char *p = input_buf;
	iov_in = (struct iovec *)je_malloc(num_iov * sizeof(struct iovec));

	for (size_t i = 0; i < num_iov; i++) {
		iov_in[i].iov_len = TEST_BLOCK_SIZE;
		iov_in[i].iov_base = p;
		if (RAND_BUFS || i % 2) {
			*(long *)p = i;
			memcpy(p + 8, rand_input_buf, 8);
		}
		p += TEST_BLOCK_SIZE;
	}

	before = uv_hrtime();
	checksumput = getMd5sum(input_buf, INPUT_BUFFER_SIZE);
	read = (uv_hrtime() - before);
	printf("%lu Bytes Checksummed: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE,
	    read / 1e9, fmt(INPUT_BUFFER_SIZE / (read / 1e9)));

	err = ccow_create_stream_completion(cl, NULL, NULL, TEST_IOVCNT, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID2, strlen(SIMPLE_TEST_OID2) + 1, &genid, NULL, NULL);
	assert_int_equal(err, 0);

	before = uv_hrtime();

	int op_cnt = 1;
	struct iovec *iov_ptr = NULL;
	for (size_t i = 0; i < num_iov / TEST_IOVCNT; i++)
	{
		iov_ptr = &iov_in[i * TEST_IOVCNT];
		if ( i % 8 ) {
			iov_ptr = &iov_in[i * TEST_IOVCNT];
			err = ccow_create_stream_completion(cl, NULL, NULL,
			    TEST_IOVCNT, &c, TEST_BUCKET_NAME,
			    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID2,
			    strlen(SIMPLE_TEST_OID2) + 1, &genid, NULL, NULL);
			assert_int_equal(err, 0);
		}
		err = ccow_put_cont(c, iov_ptr, TEST_IOVCNT,
		    TEST_BLOCK_SIZE * i * TEST_IOVCNT, 1, NULL);
		assert_int_equal(err, 0);
		err = ccow_wait(c, op_cnt++);
		assert_int_equal(err, 0);

		if (( i + 1 ) % 8) {
			err = ccow_finalize(c, NULL);
			assert_int_equal(err, 0);
			op_cnt = 1;
			c = NULL;
		}
	}
	if (num_iov % TEST_IOVCNT) {
		if (!c) {
			err = ccow_create_stream_completion(cl, NULL, NULL,
			    TEST_IOVCNT, &c, TEST_BUCKET_NAME,
			    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID2,
			    strlen(SIMPLE_TEST_OID2) + 1, &genid, NULL, NULL);
			assert_int_equal(err, 0);
		}
		iov_ptr = &iov_in[num_iov  - (num_iov % TEST_IOVCNT)];
		assert(c);
		err = ccow_put_cont(c, iov_ptr, num_iov % TEST_IOVCNT,
		    TEST_BLOCK_SIZE * (num_iov / TEST_IOVCNT),
		    1, NULL);
		assert_int_equal(err, 0);
		err = ccow_wait(c, op_cnt++);
		assert_int_equal(err, 0);
	}
	if (c)
		err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	read = (uv_hrtime() - before);
	printf("%lu Bytes Written: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE,
	    read / 1e9, fmt(INPUT_BUFFER_SIZE / (read / 1e9)));

	je_free(iov_in);
	je_free(input_buf);
}

static void
simple_1gb_stream_get(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec *iov_in;
	uint64_t before, read;
	size_t num_iov = INPUT_BUFFER_SIZE / TEST_BLOCK_SIZE;
	uint64_t genid = 0;
	ccow_completion_t c;

	iov_in = (struct iovec *)je_malloc(num_iov * sizeof(struct iovec));

	for (size_t i = 0; i < num_iov; i++) {
		iov_in[i].iov_len = TEST_BLOCK_SIZE;
		iov_in[i].iov_base = je_calloc(1, iov_in[i].iov_len);
	}

	err = ccow_create_stream_completion(cl, NULL, NULL, TEST_IOVCNT, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID2, strlen(SIMPLE_TEST_OID2) + 1, &genid, NULL, NULL);
	assert_int_equal(err, 0);

	before = uv_hrtime();
	int op_cnt = 1;
	struct iovec *iov_ptr = NULL;
	for (size_t i = 0; i < num_iov / TEST_IOVCNT; i++)
	{
		iov_ptr = &iov_in[i * TEST_IOVCNT];
		if ( i % 4 ) {
			iov_ptr = &iov_in[i * TEST_IOVCNT];
			err = ccow_create_stream_completion(cl, NULL, NULL, TEST_IOVCNT,
			    &c, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			    SIMPLE_TEST_OID2, strlen(SIMPLE_TEST_OID2) + 1,
			    &genid, NULL, NULL);
			assert_int_equal(err, 0);
		}
		err = ccow_get_cont(c, iov_ptr, TEST_IOVCNT,
		    TEST_BLOCK_SIZE * i * TEST_IOVCNT, 1, NULL);
		assert_int_equal(err, 0);

		err = ccow_wait(c, op_cnt++);
		assert_int_equal(err, 0);

		if (( i + 1 ) % 4) {
			err = ccow_finalize(c, NULL);
			assert_int_equal(err, 0);
			op_cnt = 1;
			c = NULL;
		}
	}
	if (num_iov % TEST_IOVCNT) {
		if (!c) {
			err = ccow_create_stream_completion(cl, NULL, NULL,
			    TEST_IOVCNT, &c, TEST_BUCKET_NAME,
			    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID2,
			    strlen(SIMPLE_TEST_OID2) + 1, &genid, NULL, NULL);
			assert_int_equal(err, 0);
		}
		iov_ptr = &iov_in[num_iov - (num_iov % TEST_IOVCNT)];
		err = ccow_get_cont(c, iov_ptr, num_iov % TEST_IOVCNT,
		    TEST_BLOCK_SIZE * (num_iov / TEST_IOVCNT),
		    1, NULL);
		assert_int_equal(err, 0);
		err = ccow_wait(c, op_cnt++);
		assert_int_equal(err, 0);
	}
	if (c)
		err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	char *input_buf = (char *)je_calloc(1, INPUT_BUFFER_SIZE);
	char *p = input_buf;
	for ( size_t i = 0; i < num_iov; i++) {
		memcpy(p, iov_in[i].iov_base, TEST_BLOCK_SIZE);
		p+=TEST_BLOCK_SIZE;
	}

	before = uv_hrtime();
	checksumget = getMd5sum(input_buf, INPUT_BUFFER_SIZE);
	assert(checksumget);
	read = (uv_hrtime() - before);

	printf("%lu Bytes Checksummed: %.3fs (%s/s)\n", INPUT_BUFFER_SIZE,
	    read / 1e9, fmt(INPUT_BUFFER_SIZE / (read / 1e9)));

	for (size_t i = 0; i < num_iov; i++) {
		je_free(iov_in[i].iov_base);
	}
	je_free(iov_in);
	je_free(input_buf);
}

static void
checksum_verify(void **state)
{
	assert_non_null(checksumput);
	assert_non_null(checksumget);

	assert_int_equal(memcmp(checksumput, checksumget, MD5_DIGEST_LENGTH), 0);

	je_free(checksumput);
	je_free(checksumget);
}

static void
libccow_teardown(void **state)
{
	je_free(rand_input_buf);
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
	if(!dd) {
		ccow_daemon_term();
	}
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
		unit_test(simple_random128k_streamall_put),
		unit_test(simple_random128k_streamall_get),
		unit_test(checksum_verify),
		unit_test(simple_1gb_streamall_put),
		unit_test(simple_1gb_streamall_get),
		unit_test(checksum_verify),
		unit_test(simple_1gb_stream_put),
		unit_test(simple_1gb_stream_get),
		unit_test(checksum_verify),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

