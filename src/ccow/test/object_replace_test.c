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

#define TEST_BUCKET_NAME	"object-replace-test"
#define INPUT_BUFFER_SIZE_128K	(128 * 1024)

ccow_t cl = NULL, tc = NULL;
unsigned char *checksumput1g, *checksumget1g;
unsigned char *checksumput512, *checksumget512;
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
#define SIMPLE_TEST_BS		(1024 * 1024)
#define INPUT_BUFFER_SIZE	(1024 * 1024 * 1024UL)
#define TEST_BLOCK_SIZE		(1024 * 1024)
#define TEST_IOVCNT		64
#define RAND_BUFS		1

static void
object_delete(void **state)
{
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID, NULL, NULL);
}

static void
simple_512m_stream_put(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec *iov_in;
	uint64_t genid = 0;
	ccow_completion_t c;
	size_t num_iov = INPUT_BUFFER_SIZE / TEST_BLOCK_SIZE / 2;

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

	checksumput512 = getMd5sum(input_buf, INPUT_BUFFER_SIZE);
	int attrs = 0;
	attrs |= CCOW_CONT_F_REPLACE;
	err = ccow_create_stream_completion(cl, NULL, NULL, TEST_IOVCNT, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, &genid,
	    &attrs, NULL);
	assert_int_equal(err, 0);

	int op_cnt = 1;
	struct iovec *iov_ptr = NULL;
	for (size_t i = 0; i < num_iov / TEST_IOVCNT; i++)
	{
		iov_ptr = &iov_in[i * TEST_IOVCNT];
		if ( i % 8 ) {
			printf(". ");
			iov_ptr = &iov_in[i * TEST_IOVCNT];
			err = ccow_create_stream_completion(cl, NULL, NULL,
			    TEST_IOVCNT, &c, TEST_BUCKET_NAME,
			    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID,
			    strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
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
			    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID,
			    strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
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
	printf("\n");
	if (c)
		err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	je_free(iov_in);
	je_free(input_buf);
}


static void
simple_512m_stream_get(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec *iov_in;
	size_t num_iov = INPUT_BUFFER_SIZE / (TEST_BLOCK_SIZE * 2);
	uint64_t genid = 0;
	ccow_completion_t c;
	uint64_t expected_size = 0;

	iov_in = (struct iovec *)je_malloc(num_iov * sizeof(struct iovec));

	for (size_t i = 0; i < num_iov; i++) {
		iov_in[i].iov_len = TEST_BLOCK_SIZE;
		iov_in[i].iov_base = je_calloc(1, iov_in[i].iov_len);
		expected_size += TEST_BLOCK_SIZE;
	}

	ccow_lookup_t iter;
	err = ccow_create_stream_completion(cl, NULL, NULL, TEST_IOVCNT, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, &iter);
	assert_int_equal(err, 0);
	assert_non_null(iter);

	void *t;
	uint64_t logical_size = 0;
	struct ccow_metadata_kv *kv = NULL;
	do {
		t = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA | CCOW_MDTYPE_CUSTOM, -1);
		kv = (struct ccow_metadata_kv *)t;
		if (kv == NULL)
			break;
		if (strcmp("ccow-logical-size", (const char *)kv->key) == 0)
			logical_size = *(uint64_t *)kv->value;
	} while (kv != NULL);

	printf("Following Logical Size received after rewrite: %lu\n", logical_size);

	if (logical_size != expected_size) {
		printf("Invalid MD entry for logical size!\n expected: %lu != current: %lu\n", expected_size, logical_size);
		assert_non_null(NULL);
	}

	int op_cnt = 1;
	struct iovec *iov_ptr = NULL;
	for (size_t i = 0; i < num_iov / TEST_IOVCNT; i++)
	{
		iov_ptr = &iov_in[i * TEST_IOVCNT];
		if ( i % 4 ) {
			printf(". ");
			iov_ptr = &iov_in[i * TEST_IOVCNT];
			err = ccow_create_stream_completion(cl, NULL, NULL, TEST_IOVCNT,
			    &c, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1,
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
			    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID,
			    strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
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
	printf("\n");
	if (c)
		err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	char *input_buf = (char *)je_calloc(1, INPUT_BUFFER_SIZE);
	char *p = input_buf;
	for ( size_t i = 0; i < num_iov; i++) {
		memcpy(p, iov_in[i].iov_base, TEST_BLOCK_SIZE);
		p+=TEST_BLOCK_SIZE;
	}

	checksumget512 = getMd5sum(input_buf, INPUT_BUFFER_SIZE);
	assert(checksumget512);
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

	checksumput1g = getMd5sum(input_buf, INPUT_BUFFER_SIZE);

	err = ccow_create_stream_completion(cl, NULL, NULL, TEST_IOVCNT, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
	assert_int_equal(err, 0);

	int op_cnt = 1;
	struct iovec *iov_ptr = NULL;
	for (size_t i = 0; i < num_iov / TEST_IOVCNT; i++)
	{
		iov_ptr = &iov_in[i * TEST_IOVCNT];
		if ( i % 8 ) {
			printf(". ");
			iov_ptr = &iov_in[i * TEST_IOVCNT];
			err = ccow_create_stream_completion(cl, NULL, NULL,
			    TEST_IOVCNT, &c, TEST_BUCKET_NAME,
			    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID,
			    strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
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
			    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID,
			    strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
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
	printf("\n");
	if (c)
		err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	je_free(iov_in);
	je_free(input_buf);
}

static void
simple_1gb_stream_get(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec *iov_in;
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
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
	assert_int_equal(err, 0);

	int op_cnt = 1;
	struct iovec *iov_ptr = NULL;
	for (size_t i = 0; i < num_iov / TEST_IOVCNT; i++)
	{
		iov_ptr = &iov_in[i * TEST_IOVCNT];
		if ( i % 4 ) {
			printf(". ");
			iov_ptr = &iov_in[i * TEST_IOVCNT];
			err = ccow_create_stream_completion(cl, NULL, NULL, TEST_IOVCNT,
			    &c, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1,
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
			    strlen(TEST_BUCKET_NAME) + 1, SIMPLE_TEST_OID,
			    strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
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
	printf("\n");
	if (c)
		err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	char *input_buf = (char *)je_calloc(1, INPUT_BUFFER_SIZE);
	char *p = input_buf;
	for ( size_t i = 0; i < num_iov; i++) {
		memcpy(p, iov_in[i].iov_base, TEST_BLOCK_SIZE);
		p+=TEST_BLOCK_SIZE;
	}

	checksumget1g = getMd5sum(input_buf, INPUT_BUFFER_SIZE);
	assert(checksumget1g);
	for (size_t i = 0; i < num_iov; i++) {
		je_free(iov_in[i].iov_base);
	}
	je_free(iov_in);
	je_free(input_buf);
}

static void
checksum_verify(void **state)
{
	assert_non_null(checksumput1g);
	assert_non_null(checksumget1g);
	assert_non_null(checksumput512);
	assert_non_null(checksumget512);

	assert_int_equal(memcmp(checksumput1g, checksumget1g, MD5_DIGEST_LENGTH), 0);
	assert_int_equal(memcmp(checksumput512, checksumget512, MD5_DIGEST_LENGTH), 0);

	je_free(checksumput1g);
	je_free(checksumput1g);
	je_free(checksumget512);
	je_free(checksumget512);
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
		unit_test(simple_1gb_stream_put),
		unit_test(simple_1gb_stream_get),
		unit_test(simple_512m_stream_put),
		unit_test(simple_512m_stream_get),
		unit_test(checksum_verify),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

