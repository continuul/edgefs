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
#include "ccow-impl.h"

#define VMM_TEST_BID		"vmm-test-bucket"
#define VMM_TEST_OID		"vmm-test-object"

ccow_t cl = NULL;
int verbose = 0;
int dd = 0;

int32_t  SST_KEYVAL	= 0;
int32_t  SST_OP_CNT	= 16;
uint32_t SST_BS		= 1024;
int32_t  SST_ITER_CNT	= 1;
int32_t  SST_ASYNC	= 0;
uint8_t  SST_MARKERS    = 1;
uint8_t  SST_FAIL	= 0;
uint8_t  SST_RECOVER	= 0;
uint32_t SST_THREADS    = 1;

uv_barrier_t thread_barrier;

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
	       "     ./vmm_test [-h] [-v] [-f] [-i] [-r] [-t thread_count] -m -n \n"
	       "          [-o op_count]\n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -v   Enable verbose debug output.\n"
	       "\n"
	       "    -f   Fail (terminate) process in mid-stream.\n"
	       "\n"
	       "    -k   Do not delete bucket and objects in recovery mode.\n"
	       "\n"
	       "    -m   Disable markers.\n"
	       "\n"
	       "    -o   Number of operations in a stream. (Defaults to 16.)\n"
	       "\n"
	       "    -i   Use key-value btree.\n"
	       "\n"
	       "    -r   Recover process.\n"
	       "\n"
	       "    -t   Number of threads. (Defaults to 1.)\n"
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
	int err = ccow_bucket_create(cl, VMM_TEST_BID,
	    strlen(VMM_TEST_BID) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);

	for (uint32_t i = 0; i < SST_THREADS; i++) {
		char oid[128];
		sprintf(oid, "%s-%4.4d", VMM_TEST_OID, i);
		delete(cl, VMM_TEST_BID, oid, NULL, NULL);
	}
	int err = ccow_bucket_delete(cl, VMM_TEST_BID,
	    strlen(VMM_TEST_BID) + 1);
	if (err != 0) {
		printf("error deleting bucket, err = %d \n", err);
	}
	assert_int_equal(err, 0);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);

	ccow_stats_t stats;

	int rv = ccow_get_stats(cl, &stats);
	if (rv == 0) {
		ccow_print_stats(stats);
	}

	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
	if (dd)
		return;
	ccow_daemon_term();
}

/*
 * pattern_001
 */
pthread_mutex_t cb_lock = PTHREAD_MUTEX_INITIALIZER;
uint32_t cb_cnt = 0;

static void
async_cb2(ccow_completion_t c, void *arg, int index, int err)
{
	uv_barrier_t *b = arg;

	if (index == 0)
		return;

	if (verbose) {
		printf("asnc_cb idx %d, err %d\n",
		    index, err);
	}

	if (err != 0) {
		printf("IO completed with err = %d\n", err);
		assert(err == 0);
	}

	uv_barrier_wait(b);
}

static void
fail_thread(void * arg)
{
	assert(SST_FAIL);

	uint32_t thread_idx = *((uint32_t *) arg);

	int err = 0, i = 0, j = 0;
	char *buf_out, *buf_in;
	ccow_completion_t c;
	struct iovec *iov_out, *iov_in;
	uv_barrier_t b;
	uint64_t offset = 0;

	size_t io_size = SST_BS;

	buf_out = je_calloc(SST_BS, 1);
	assert(buf_out != NULL);

	buf_in = je_calloc(SST_BS, 1);
	assert(buf_in != NULL);

	iov_out = je_calloc(2, sizeof(struct iovec));
	assert(iov_out != NULL);

	iov_in = je_calloc(1, sizeof(struct iovec));
	assert(iov_in != NULL);

	uint64_t genid = 0;

	if (verbose)
		printf("i = %6.6d \n", i);

	memset(iov_out, 0, 2*sizeof(struct iovec));
	memset(iov_in,  0, sizeof(struct iovec));

	/*
	 * create stream completion
	 */
	char oid[128];
	sprintf(oid, "%s-%4.4d", VMM_TEST_OID, thread_idx);
	printf("oid=%s\n", oid);

	int cont_flags = CCOW_CONT_F_REPLACE;

	err = ccow_create_stream_completion(cl, &b,
	    async_cb2,
	    SST_OP_CNT, &c, VMM_TEST_BID, strlen(VMM_TEST_BID) + 1,
	    oid, strlen(oid) + 1, &genid,
	    &cont_flags, NULL);

	assert(err == 0);

	/*
	 * enable version manifest markers
	 */
	if (SST_MARKERS) {
		uint16_t marker = 1;
		err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_MARKER,
		    (void *)&marker, NULL);
		assert_int_equal(err, 0);
	}

	if (SST_KEYVAL) {
		char * chunkmap_type = "btree_key_val";
		err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
		    (void *) chunkmap_type, NULL);
		assert_int_equal(err, 0);
	}

	/*
	 * iterate through the number of IOs per test
	 */
	for (j = 0; j < SST_OP_CNT; j++) {
		if (verbose)
			printf("i = %6.6d, j = %6.6d \n", i, j);

		if (j >= SST_OP_CNT/2) {
			/*
			 * wait for all threads. this is the -f case.
			 */
			printf("Waiting for thread barrier to unblock %d ops\n", j);
			uv_barrier_wait(&thread_barrier);

			printf("Sleeping for 10s\n");
			sleep(10);

			printf("Simulating error exit ..\n");
			exit(0);
		}

		/*
		 * create the buffer contents
		 */
		sprintf(buf_out, "byte me world : i = 0x%4.4x "
		    ": j = 0x%4.4x "
		    ": SST_BS = 0x%4.4x "
		    ": thread_idx = %3d",
		    i, j, SST_BS, thread_idx);

		iov_out[0].iov_len  = SST_BS;
		iov_out[0].iov_base = buf_out;

		/*
		 * put
		 */
		offset = j * SST_BS;

		uv_barrier_init(&b, 2);

		if (SST_KEYVAL) {
			iov_out[1].iov_len  = 0;
			iov_out[1].iov_base = NULL;
			if (verbose) printf("inserting key= %s\n", (char*)iov_out[0].iov_base);
			err = ccow_insert_list_cont(c, iov_out, 2, 0, NULL);
			assert(err == 0);
		} else {
			err = ccow_put_cont(c, iov_out, 1, offset, 0, NULL);
			assert(err == 0);
		}

		uv_barrier_wait(&b);
		uv_barrier_destroy(&b);
	}
}

static void
recover_thread(void * arg)
{
	assert(!SST_FAIL);

	uint32_t thread_idx = *((uint32_t *) arg);

	int err = 0, i = 0, j = 0;
	char *buf_out, *buf_in;
	ccow_completion_t c;
	struct iovec *iov_out, *iov_in;
	uint64_t offset = 0;

	size_t io_size = SST_BS;

	buf_out = je_calloc(SST_BS, 1);
	assert(buf_out != NULL);

	buf_in = je_calloc(SST_BS, 1);
	assert(buf_in != NULL);

	iov_out = je_calloc(1, sizeof(struct iovec));
	assert(iov_out != NULL);

	iov_in = je_calloc(1, sizeof(struct iovec));
	assert(iov_in != NULL);

	uint64_t genid = 0;

	if (verbose)
		printf("i = %6.6d \n", i);

	memset(iov_out, 0, sizeof(struct iovec));
	memset(iov_in,  0, sizeof(struct iovec));

	/*
	 * create stream completion
	 */
	char oid[128];
	sprintf(oid, "%s-%4.4d", VMM_TEST_OID, thread_idx);

	err = ccow_create_stream_completion(cl, NULL, NULL,
	    SST_OP_CNT, &c, VMM_TEST_BID, strlen(VMM_TEST_BID) + 1,
	    oid, strlen(oid) + 1, &genid,
	    NULL, NULL);

	assert(err == 0);

	/*
	 * enable version manifest markers
	 */
	uint16_t marker = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_MARKER,
	    (void *)&marker, NULL);
	assert_int_equal(err, 0);

	if (SST_KEYVAL) {
		char * chunkmap_type = "btree_key_val";
		err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
		    (void *) chunkmap_type, NULL);
		assert_int_equal(err, 0);

		printf("recovered genid=%lu\n", genid);
	} else {

		/*
		 * iterate through the number of IOs per test
		 */
		int index = 0;
		for (j = 0; j < SST_OP_CNT; j++) {
			if (verbose)
				printf("i = %6.6d, j = %6.6d \n", i, j);

			if (j >= SST_OP_CNT/2) {
				continue;
			}

			/*
			 * create the buffer contents
			 */

			char tmp[SST_BS];
			memset(tmp, 0, SST_BS);

			sprintf(tmp, "byte me world : i = 0x%4.4x "
			    ": j = 0x%4.4x "
			    ": SST_BS = 0x%4.4x "
			    ": thread_idx = %3d",
			    i, j, SST_BS, thread_idx);

			/*
			 * get
			 */
			offset = j * SST_BS;

			iov_out[0].iov_len  = SST_BS;
			iov_out[0].iov_base = buf_out;

			memset(buf_out, 0, SST_BS);

			err = ccow_get_cont(c, iov_out, 1, offset, 1, &index);
			assert_int_equal(err, 0);

			err = ccow_wait(c, index);
			assert_int_equal(err, 0);

			err = strncmp(tmp, buf_out, SST_BS);

			if (err != 0) {
				printf("offset   : %"PRIx64" \n", offset);
				printf("expected : \"%s\" \n", tmp);
				printf("received : \"%s\" \n", buf_out);
			}

			assert_int_equal(err, 0);
		}
	}

	/*
	 * finalize completion
	 */
	err = ccow_finalize(c, NULL);
	if (err != 0) {
		printf("ccow_finalize returned error %d\n", err);
		assert(err == 0);
	}

	je_free(buf_out);
	je_free(buf_in);
	je_free(iov_out);
	je_free(iov_in);

	/*
	 * wait for all threads. this is -r mode.
	 */
	uv_barrier_wait(&thread_barrier);
}

static void
stream_io_test(void **state)
{
	uint32_t i;

	uv_barrier_init(&thread_barrier, SST_THREADS);

	uv_thread_t * id = je_calloc(SST_THREADS, sizeof(uv_thread_t));
	assert(id != NULL);

	uint32_t * arg = je_calloc(SST_THREADS, sizeof (uint32_t));
	assert(arg != NULL);

	if (SST_FAIL) {
		for (i = 0; i < SST_THREADS; i++) {
			arg[i] = i;
			uv_thread_create(&id[i], fail_thread, &arg[i]);
		}
	} else {
		for (i = 0; i < SST_THREADS; i++) {
			arg[i] = i;
			uv_thread_create(&id[i], recover_thread, &arg[i]);
		}

	}

	for (i = 0; i < SST_THREADS; i++) {
		uv_thread_join(&id[i]);
	}

	uv_barrier_destroy(&thread_barrier);

	je_free(id);
	je_free(arg);
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
	opterr = 0;

	while ((opt = getopt(argc, argv, "hvimnfo:rt:")) != -1) {
		switch(opt) {

		case 'n':
			dd = 1;
			break;


		case 'h':
			usage();
			break;

		case 'v':
			verbose = 1;
			break;

		case 'f':
			SST_FAIL = 1;
			break;

		case 'i':
			SST_KEYVAL = 1;
			break;

		case 'm':
			SST_MARKERS = 0;
			break;

		case 'o':
			SST_OP_CNT = atoi(optarg);
			break;

		case 'r':
			SST_RECOVER = 1;
			break;

		case 't':
			SST_THREADS = atoi(optarg);
			break;

		default:
			usage();
			break;
		}
	}

	if (dd == 0) {
		printf("This test requires the -n option.\n");
		exit(EXIT_SUCCESS);
	}

	if ((SST_FAIL == 0) && (SST_RECOVER == 0)) {
		printf("-f or -r option is required.\n");
		exit(EXIT_SUCCESS);
	}

	if ((SST_FAIL == 1) && (SST_RECOVER == 1)) {
		printf("-f and -r options are mutually exclusive.\n");
		exit(EXIT_SUCCESS);
	}

	if (verbose) {
		printf("block size       = %d \n"
		       "iterations       = %d \n"
		       "operaction count = %d \n"
		       "async            = %d \n"
		       "markers          = %d \n",
		       SST_BS, SST_ITER_CNT, SST_OP_CNT,
		       SST_ASYNC, SST_MARKERS);
	}

	/*
	 * run tests
	 */
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),

		unit_test(stream_io_test),

		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
