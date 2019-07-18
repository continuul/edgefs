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

#define STRESS_TEST_BID		"stress-stream-io-test-bucket"
#define STRESS_TEST_OID		"stress-stream-io-test-object"
#define STRESS_TEST_DEPTH	1
#define STRESS_TEST_WIDTH	512
#define STRESS_TEST_CHUNKMAP	"btree_map"
#define STRESS_TEST_BS		4096

ccow_t cl = NULL;
int verbose = 0;
int dd = 0;

/*
 * usage
 *
 * Display usage and exit.
 */
static void
usage(void)
{
	printf("\n"
	       "USAGE:\n"
	       "     ./stream_io_negative_test [-h] [-v] \n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -v   Enable verbose debug outout.\n"
	       "\n");

	exit(EXIT_SUCCESS);
}

static void
libccowd_setup(void **state)
{
	if (dd)
		return;
	assert_int_equal(ccow_daemon_init(NULL), 0);
	usleep(2 * 1000000L);
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
	int err = ccow_bucket_create(cl, STRESS_TEST_BID,
	    strlen(STRESS_TEST_BID) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, STRESS_TEST_BID, STRESS_TEST_OID, NULL, NULL);
	int err = ccow_bucket_delete(cl, STRESS_TEST_BID,
	    strlen(STRESS_TEST_BID) + 1);
	assert_int_equal(err, 0);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
	if (dd)
		return;
	ccow_daemon_term();
}

uint32_t SST_BS		= 1024;

/*
 * stress_stream_io_test_async_cb
 */
static void
stream_io_negative_test_async_cb(ccow_completion_t c, void *arg, int index,
    int err)
{
	uv_barrier_t *b = arg;

	if (verbose)
		fprintf(stderr, "asnc_cb idx %d, err %d\n", index, err);

	if (err != 0) {
		printf("IO completed with err = %d\n", err);
		assert(err == 0);
	}

	if (index != 0)
		uv_barrier_wait(b);
}

/*
 * finalize_test
 */
static void
finalize_test(void **state)
{
	int err = 0, i = 0, j = 0, k = 0;
	char *buf_out, *buf_in;
	ccow_completion_t c;
	struct iovec *iov_out, *iov_in;
	uv_barrier_t b;
	uint64_t offset = 0;
	uint64_t genid = 0;

	size_t io_size = SST_BS;

	buf_out = je_calloc(SST_BS, 1);
	assert(buf_out != NULL);

	buf_in = je_calloc(SST_BS, 1);
	assert(buf_in != NULL);

	iov_out = je_calloc(sizeof(struct iovec), 1);
	assert(iov_out != NULL);

	iov_in = je_calloc(sizeof(struct iovec), 1);
	assert(iov_in != NULL);

	/*
	 * create stream completion
	 */
	err = ccow_create_stream_completion(cl, &b,
	    stream_io_negative_test_async_cb,
	    1, &c, STRESS_TEST_BID, strlen(STRESS_TEST_BID) + 1,
	    STRESS_TEST_OID, strlen(STRESS_TEST_OID) + 1, &genid, 0, NULL);

	assert(err == 0);

	/*
	 * iterate through the number of IOs per test
	 */
	char * out = buf_out;

	memset(out, 0, SST_BS);
	sprintf(out, "byte me world");

	iov_out[0].iov_len  = SST_BS;
	iov_out[0].iov_base = out;

	/*
	 * put
	 */
	offset = 0;

	uv_barrier_init(&b, 2);

	err = ccow_put_cont(c, iov_out, 1, offset, 0, NULL);
	if (err != 0) {
		printf("err = %d", err);
		assert(err == 0);
	}
	uv_barrier_wait(&b);
	uv_barrier_destroy(&b);

	/*
	 * finalize completion
	 */
	err = ccow_finalize(c, NULL);
	if (err != 0) {
		printf("err = %d", err);
		assert(err == 0);
	}

	/*
	 * put
	 */
	offset = 0;

	uv_barrier_init(&b, 2);

	err = ccow_put_cont(c, iov_out, 1, offset, 0, NULL);
	if (err != -EINVAL) {
		printf("err = %d, expected %d (-EINAL)", err, -EINVAL);
		assert_int_equal(err, 0);
	}
	uv_barrier_destroy(&b);

	je_free(buf_out);
	je_free(buf_in);
	je_free(iov_out);
	je_free(iov_in);
}

/*
 * main
 */
int
main(int argc, char ** argv)
{
	/*
	 * parse command line options
	 */
	int opt;

	while ((opt = getopt(argc, argv, "hv")) != -1) {
		switch(opt) {

		case 'h':
			usage();
			break;

		case 'v':
			verbose = 1;
			break;

		default:
			usage();
			break;
		}
	}

	/*
	 * run tests
	 */
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),

		unit_test(finalize_test),

		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
