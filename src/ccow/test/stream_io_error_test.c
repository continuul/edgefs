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

#define TEST_BID		"stream-io-error-test-bucket"
#define TEST_OID		"stream-io-error-test-object"

#define OP_CNT_DEF		128
#define BTREE_ORDER_DEF		16
#define FAIL_IO_DEF		0

int32_t OP_CNT			=  OP_CNT_DEF;
int BTREE_ORDER			=  BTREE_ORDER_DEF;
int FAIL_IO			=  FAIL_IO_DEF;

ccow_t cl = NULL;
int verbose = 0;

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
	       "     ./stream_io_error_test [-h] [-c count] \n"
	       "          [-f fail_io] [-o btree_order] \n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -c   Specify the number of operations per stream.\n"
	       "         (Defaults to %d).\n"
	       "\n"
	       "    -o   Specify the btree order.\n"
	       "         (Defaults to %d).\n"
	       "\n"
	       "    -v   Enable verbose debug outout.\n"
	       "\n",
	       OP_CNT_DEF, BTREE_ORDER_DEF);

	exit(EXIT_SUCCESS);
}

static void
libccowd_setup(void **state)
{
	assert_int_equal(ccow_daemon_init(NULL), 0);
	usleep(2 * 1000000L);
}

static void
libccow_setup(void **state)
{
	int err;
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

	/*
	 * set default attributes:
	 */
	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);

	if (err != 0) {
		printf("ccow_create_completion returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_map";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *) chunkmap_type, NULL);

	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	uint16_t order = BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *)&order, NULL);

	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);
}

static void
bucket_create(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_create(cl, TEST_BID, strlen(TEST_BID) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BID, strlen(TEST_BID) + 1);
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
	ccow_daemon_term();
}

uint32_t SST_BS		= 1024;
int32_t  SST_ITER_CNT	= 1;
int32_t  SST_IOV_CNT    = 1;

/*
 * stream_io_error_test_async_cb
 */
static void
stream_io_error_test_cb(ccow_completion_t c, void *arg, int index,
    int err)
{
	uv_barrier_t *b = arg;

	if (err != 0) {
		printf("IO completed with err = %d \n", err);
	}

	if (index != 0)
		uv_barrier_wait(b);
}

/*
 * stream_io_test
 */


static void
stream_io_test(void **state)
{
	int err = 0, i = 0, j = 0, k = 0;
	char *buf_out, *buf_in;
	ccow_completion_t c;
	struct iovec *iov_out, *iov_in;
	uv_barrier_t b;
	uint64_t offset = 0;

	size_t io_size = SST_BS * SST_IOV_CNT;

	buf_out = je_calloc(SST_IOV_CNT * SST_BS, 1);
	assert(buf_out != NULL);

	buf_in = je_calloc(SST_IOV_CNT * SST_BS, 1);
	assert(buf_in != NULL);

	iov_out = je_calloc(SST_IOV_CNT, sizeof(struct iovec));
	assert(iov_out != NULL);

	iov_in = je_calloc(SST_IOV_CNT, sizeof(struct iovec));
	assert(iov_in != NULL);

	/*
	 * iterate through the number of tests
	 */
	uint64_t genid = 0;
	for (i = 0; i < SST_ITER_CNT; i++) {
		if (verbose)
			printf("i = %6.6d \n", i);

		/*
		 * create stream completion
		 */
		err = ccow_create_stream_completion(cl, &b,
		    stream_io_error_test_cb,
		    OP_CNT, &c, TEST_BID, strlen(TEST_BID) + 1,
		    TEST_OID, strlen(TEST_OID) + 1, &genid, NULL, NULL);

		assert(err == 0);

		/*
		 * iterate through the number of IOs per test
		 */
		for (j = 0; j < ((OP_CNT - 1)/2); j++) {

			for (k = 0; k < SST_IOV_CNT; k++) {
				/*
				 * create the buffer contents
				 */
				char * out = buf_out + (k * SST_BS);

				memset(out, 0, SST_BS);
				sprintf(out, "byte me world : i = 0x%4.4x "
				    ": j = 0x%4.4x : k = 0x%4.4x "
				    ": SST_BS = 0x%4.4x",
				    i, j, k, SST_BS);

				iov_out[k].iov_len  = SST_BS;
				iov_out[k].iov_base = out;
			}

			/*
			 * put
			 */
			offset = j * SST_BS * SST_IOV_CNT;

			uv_barrier_init(&b, 2);

			err = ccow_put_cont(c, iov_out, SST_IOV_CNT, offset,
			    0, NULL);

			if (err != 0) {
				printf("ccow_put_cont returned err %d\n", err);
			} else {
				uv_barrier_wait(&b);
				uv_barrier_destroy(&b);
			}

			/*
			 * get
			 */
			for (k = 0; k < SST_IOV_CNT; k++) {
				/*
				 * create iov in
				 */
				char * in = buf_in + (k * SST_BS);

				memset(buf_in, 0, SST_BS);

				iov_in[k].iov_len  = SST_BS;
				iov_in[k].iov_base = in;
			}

			offset = j * SST_BS * SST_IOV_CNT;

			uv_barrier_init(&b, 2);

			err = ccow_get_cont(c, iov_in, SST_IOV_CNT, offset,
			    0, NULL);

			if (err != 0) {
				printf("ccow_get_cont returned err %d\n", err);
			} else {
				uv_barrier_wait(&b);
				uv_barrier_destroy(&b);
			}
		}

		/*
		 * finalize completion
		 */
		err = ccow_finalize(c, NULL);
		printf("ccow_finalize returned err %d \n", err);
		assert(err == 0);
	}

	je_free(buf_out);
	je_free(buf_in);
	je_free(iov_out);
	je_free(iov_in);
}

CCOW_EI_TAG_EXTERN(unnamedput_cont__init);
CCOW_EI_TAG_EXTERN(unnamedget_cont__init);

static void
stream_io_test_put(void **state)
{
	CCOW_EI_TAG_INIT(unnamedput_cont__init, 5);
	stream_io_test(state);
	CCOW_EI_TAG_DISABLE(unnamedput_cont__init);
}

static void
stream_io_test_get(void **state)
{
	CCOW_EI_TAG_INIT(unnamedget_cont__init, 5);
	stream_io_test(state);
	CCOW_EI_TAG_DISABLE(unnamedget_cont__init);
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

	while ((opt = getopt(argc, argv, "hc:o:v")) != -1) {
		switch(opt) {

		case 'h':
			usage();
			break;

		case 'c':
			OP_CNT = atoi(optarg);
			break;

		case 'o':
			BTREE_ORDER = atoi(optarg);
			break;

		case 'v':
			verbose = 1;
			break;

		default:
			usage();
			break;
		}
	}

	if (verbose) {
		printf("btree order      = %d \n"
		       "fail io          = %d \n"
		       "operation count  = %d \n",
		       BTREE_ORDER, FAIL_IO, OP_CNT);
	}

	/*
	 * run tests
	 */
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(stream_io_test_put),
		unit_test(stream_io_test_get),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
