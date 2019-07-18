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

#define STRESS_TEST_BID		"stress-stream-io-test-bucket"
#define STRESS_TEST_OID		"stress-stream-io-test-object"
#define STRESS_TEST_CHUNKMAP	"btree_map"
#define STRESS_TEST_ORDER	4
#define STRESS_TEST_BS		4096

ccow_t cl = NULL;
int verbose = 0;
int readonly = 0;
int keep_bucket = 0;
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
	       "     ./stress_stream_io_test [-h] [-b block_size] \n"
	       "          [-i iteratations] [-o op_count] \n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -a   Enable async mode which will submit batches of IOs \n"
	       "         in parallel.\n"
	       "\n"
	       "    -b   Specify the block size form of \"[0-9]+[GMKB]?\".\n"
	       "         (Defaults to 1024).\n"
	       "\n"
	       "    -i   Specify the number of iterations.\n"
	       "         (Defaults to 1024).\n"
	       "\n"
	       "    -m   Enable version manifest markers.\n"
	       "\n"
	       "    -o   Specify the number of stream IOs per iteration.\n"
	       "         (Defaults to 128).\n"
	       "\n"
	       "    -p   Specify the test pattern: \n"
	       "         1: alternating put/get within stream. \n"
	       "         2: stream of puts followed by stream of gets. \n"
	       "         3: stream of puts followed by stream of gets \n"
	       "             intermediate finalizes are skipped \n"
	       "         (defaults to 1). \n"
	       "\n"
	       "    -s   Specify the number of iovec entries per IO.  I/O size\n"
	       "         will be iovec_entries * block_size.\n"
	       "         (Defaults to 1).\n"
	       "\n"
	       "    -v   Enable verbose debug outout.\n"
	       "\n"
	       "    -r   Skip write part of the test.\n"
		   "\n"
		   "    -k   Don't delete the test bucket (useful before run with -r)\n"
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
	if (err == 0 && readonly) {
		printf("read only test expects the bucket from the previous run, "
				"consider re-run of the write test with -k option");
		assert(0);
	}
}

static void
bucket_delete(void **state)
{
	if (keep_bucket) {
		printf("bucket delete skipped due to -k or -r option \n");
		return;
	}
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

int32_t  SST_OP_CNT	= 128;
uint32_t SST_BS		= 1024;
int32_t  SST_ITER_CNT	= 1024;
int32_t  SST_IOV_CNT    = 1;
int32_t  SST_PATTERN    = 1;
int32_t  SST_ASYNC	= 0;
uint8_t  SST_MARKERS    = 0;

/*
 * stress_stream_io_test_async_cb
 */
static void
stress_stream_io_test_async_cb(ccow_completion_t c, void *arg, int index,
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
 * pattern_001
 */
static void
pattern_001(void **state)
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
		    stress_stream_io_test_async_cb,
		    SST_OP_CNT, &c, STRESS_TEST_BID, strlen(STRESS_TEST_BID) + 1,
		    STRESS_TEST_OID, strlen(STRESS_TEST_OID) + 1, &genid,
		    NULL, NULL);

		assert(err == 0);

		if (SST_MARKERS) {
			/*
			 * enable version manifest markers
			 */
			uint16_t marker = 1;
			err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_MARKER,
			    (void *)&marker, NULL);
			assert_int_equal(err, 0);
		}

		/*
		 * iterate through the number of IOs per test
		 */
		for (j = 0; j < ((SST_OP_CNT - 1)/ 2); j++) {
			if (verbose)
				printf("i = %6.6d, j = %6.6d \n", i, j);

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
			if (!readonly) {

				offset = j * SST_BS * SST_IOV_CNT;

				uv_barrier_init(&b, 2);

				err = ccow_put_cont(c, iov_out, SST_IOV_CNT, offset,
						0, NULL);
				assert(err == 0);

				uv_barrier_wait(&b);
				uv_barrier_destroy(&b);

			}

			for (k = 0; k < SST_IOV_CNT; k++) {
				/*
				 * create iov in
				 */
				char * in = buf_in + (k * SST_BS);

				memset(buf_in, 0, SST_BS);

				iov_in[k].iov_len  = SST_BS;
				iov_in[k].iov_base = in;
			}

			/*
			 * get
			 */
			offset = j * SST_BS * SST_IOV_CNT;

			uv_barrier_init(&b, 2);

			err = ccow_get_cont(c, iov_in, SST_IOV_CNT, offset,
			    0, NULL);
			assert(err == 0);

			uv_barrier_wait(&b);
			uv_barrier_destroy(&b);

			/*
			 * compare
			 */
			err = memcmp(buf_in, buf_out, SST_BS * SST_IOV_CNT);
			if (err != 0) {
				printf("data comparison error \n");
				sleep(10);
				for (k = 0; k < SST_IOV_CNT; k++) {
					char *in = buf_in + (k * SST_BS);
					char *out = buf_out + (k * SST_BS);

					int cmp = memcmp(in, out, SST_IOV_CNT);

					if (cmp != 0) {
						printf("err = %d\n", err);
						printf("cmp = %d\n", cmp);
						printf("k   = %d\n", k);
						printf("out = %s\n", out);
						printf("in  = %s\n", in);
						assert(0);
					}
				}
				printf("err = %d\n", err);
				printf("k   = %d\n", k);
				assert(0);
			}

		}

		/*
		 * finalize completion
		 */
		err = ccow_finalize(c, NULL);
		assert(err == 0);
	}

	je_free(buf_out);
	je_free(buf_in);
	je_free(iov_out);
	je_free(iov_in);
}


/*
 * pattern_002
 */
pthread_mutex_t cb_lock = PTHREAD_MUTEX_INITIALIZER;
uint32_t cb_cnt = 0;

static void
async_cb2(ccow_completion_t c, void *arg, int index,
    int err)
{
	uv_barrier_t *b = arg;

	if (index == 0)
		return;

	if (SST_ASYNC)
		pthread_mutex_lock(&cb_lock);

	if (verbose) {
		if (SST_ASYNC) {
			printf("asnc_cb idx %d, err %d, cb_cnt %d\n",
			    index, err, cb_cnt);
		} else {
			printf("asnc_cb idx %d, err %d\n",
			    index, err);
		}
	}

	if (err != 0) {
		printf("IO completed with err = %d\n", err);
		assert(err == 0);
	}

	if (SST_ASYNC) {
		cb_cnt--;
		if (cb_cnt == 0) {
			pthread_mutex_unlock(&cb_lock);
			uv_barrier_wait(b);
		} else {
			pthread_mutex_unlock(&cb_lock);
		}
	} else {
		uv_barrier_wait(b);
	}
}
static void
pattern_002(void **state)
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

		memset(iov_out, 0, SST_IOV_CNT *  sizeof(struct iovec));
		memset(iov_in,  0, SST_IOV_CNT *  sizeof(struct iovec));

		if (SST_ASYNC) {
			pthread_mutex_lock(&cb_lock);
			cb_cnt = SST_OP_CNT;
			pthread_mutex_unlock(&cb_lock);
		}
		/*
		 * create stream completion
		 */
		err = ccow_create_stream_completion(cl, &b,
		    async_cb2,
		    SST_OP_CNT, &c, STRESS_TEST_BID, strlen(STRESS_TEST_BID) + 1,
		    STRESS_TEST_OID, strlen(STRESS_TEST_OID) + 1, &genid,
		    NULL, NULL);

		assert(err == 0);

		if (SST_MARKERS) {
			/*
			 * enable version manifest markers
			 */
			uint16_t marker = 1;
			err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_MARKER,
			    (void *)&marker, NULL);
			assert_int_equal(err, 0);
		}
		if (!readonly) {
			if (SST_ASYNC) {
				uv_barrier_init(&b, 2);
			}
			/*
		 	 * iterate through the number of IOs per test
		 	 */
			for (j = 0; j < SST_OP_CNT; j++) {
				if (verbose)
					printf("i = %6.6d, j = %6.6d \n", i, j);

				for (k = 0; k < SST_IOV_CNT; k++) {
					/*
					 * create the buffer contents
					 */
					char * out = buf_out + (k * SST_BS);

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

				if (!SST_ASYNC) {
					uv_barrier_init(&b, 2);
				}

				err = ccow_put_cont(c, iov_out, SST_IOV_CNT, offset,
					0, NULL);
				assert(err == 0);

				if (!SST_ASYNC) {
					uv_barrier_wait(&b);
					uv_barrier_destroy(&b);
				}
			}

			if (SST_ASYNC) {
				uv_barrier_wait(&b);
				uv_barrier_destroy(&b);
			}

			/*
			 * finalize completion
			 */
			err = ccow_finalize(c, NULL);
			if (err != 0) {
				printf("ccow_finalize returned error %d\n", err);
				assert(err == 0);
			}
		}

		if (SST_ASYNC) {
			pthread_mutex_lock(&cb_lock);
			cb_cnt = SST_OP_CNT;
			pthread_mutex_unlock(&cb_lock);
		}
		/*
		 * create stream completion
		 */
		err = ccow_create_stream_completion(cl, &b,
		    async_cb2,
		    SST_OP_CNT, &c, STRESS_TEST_BID, strlen(STRESS_TEST_BID) + 1,
		    STRESS_TEST_OID, strlen(STRESS_TEST_OID) + 1, &genid,
		    NULL, NULL);

		assert(err == 0);

		if (SST_ASYNC) {
			uv_barrier_init(&b, 2);
		}

		/*
		 * iterate through the number of IOs per test
		 */
		for (j = 0; j < SST_OP_CNT; j++) {
			if (verbose)
				printf("i = %6.6d, j = %6.6d \n", i, j);

			for (k = 0; k < SST_IOV_CNT; k++) {
				/*
				 * create iov in
				 */
				char * in = buf_in + (k * SST_BS);

				iov_in[k].iov_len  = SST_BS;
				iov_in[k].iov_base = in;
			}

			/*
			 * get
			 */
			offset = j * SST_BS * SST_IOV_CNT;

			if (!SST_ASYNC) {
				uv_barrier_init(&b, 2);
			}

			err = ccow_get_cont(c, iov_in, SST_IOV_CNT, offset,
			    0, NULL);
			assert(err == 0);

			if (!SST_ASYNC) {
				uv_barrier_wait(&b);
				uv_barrier_destroy(&b);
			}
		}

		if (!SST_ASYNC) {
			/*
			 * compare
			 */
			err = memcmp(buf_in, buf_out, SST_BS * SST_IOV_CNT);
			if (err != 0) {
				printf("data comparison error \n");
				//sleep(10);
				for (k = 0; k < SST_IOV_CNT; k++) {
					char *in  = buf_in + (k * SST_BS);
					char *out = buf_out + (k * SST_BS);

					printf("in  : \"%s\" \n", in);
					printf("out : \"%s\" \n", out);

					int cmp = memcmp(in, out, SST_BS);

					if (cmp != 0) {
						printf("err = %d\n", err);
						printf("cmp = %d\n", cmp);
						printf("k   = %d\n", k);
						printf("out = %s\n", out);
						printf("in  = %s\n", in);
						assert(0);
					}
				}
				printf("err = %d\n", err);
				printf("k   = %d\n", k);
				assert(0);
			}
		}

		if (SST_ASYNC) {
			uv_barrier_wait(&b);
			uv_barrier_destroy(&b);
		}

		/*
		 * finalize completion
		 */
		err = ccow_finalize(c, NULL);
		assert(err == 0);
	}

	je_free(buf_out);
	je_free(buf_in);
	je_free(iov_out);
	je_free(iov_in);
}
static void
pattern_003(void **state)
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

	if (SST_ASYNC) {
		uv_barrier_init(&b, 2);
	}

	/*
	 * create stream completion
	 */
	err = ccow_create_stream_completion(cl, &b,
	    async_cb2,
		SST_OP_CNT * SST_ITER_CNT * 2, &c, STRESS_TEST_BID, strlen(STRESS_TEST_BID) + 1,
	    STRESS_TEST_OID, strlen(STRESS_TEST_OID) + 1, &genid,
	    NULL, NULL);

	assert(err == 0);


	if (SST_ASYNC) {
		pthread_mutex_lock(&cb_lock);
		cb_cnt = SST_OP_CNT * SST_ITER_CNT * 2;
		pthread_mutex_unlock(&cb_lock);
	}

	for (i = 0; i < SST_ITER_CNT; i++) {
		if (verbose)
			printf("i = %6.6d \n", i);

		memset(iov_out, 0, SST_IOV_CNT *  sizeof(struct iovec));
		memset(iov_in,  0, SST_IOV_CNT *  sizeof(struct iovec));

		if (!readonly) {
			/*
			 * iterate through the number of IOs per test
			 */
			for (j = 0; j < SST_OP_CNT; j++) {
				if (verbose)
					printf("i = %6.6d, j = %6.6d PUT \n", i, j);

				for (k = 0; k < SST_IOV_CNT; k++) {
					/*
					 * create the buffer contents
					 */
					char * out = buf_out + (k * SST_BS);

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

				if (!SST_ASYNC) {
					uv_barrier_init(&b, 2);
				}

				err = ccow_put_cont(c, iov_out, SST_IOV_CNT, offset,
					0, NULL);
				assert(err == 0);

				if (!SST_ASYNC) {
					uv_barrier_wait(&b);
					uv_barrier_destroy(&b);
				}
			}
		}

		/*
		 * iterate through the number of IOs per test
		 */
		for (j = 0; j < SST_OP_CNT; j++) {
			if (verbose)
				printf("i = %6.6d, j = %6.6d GET \n", i, j);

			for (k = 0; k < SST_IOV_CNT; k++) {
				/*
				 * create iov in
				 */
				char * in = buf_in + (k * SST_BS);

				iov_in[k].iov_len  = SST_BS;
				iov_in[k].iov_base = in;
			}

			/*
			 * get
			 */
			offset = j * SST_BS * SST_IOV_CNT;

			if (!SST_ASYNC) {
				uv_barrier_init(&b, 2);
			}

			err = ccow_get_cont(c, iov_in, SST_IOV_CNT, offset,
			    0, NULL);
			assert(err == 0);

			if (!SST_ASYNC) {
				uv_barrier_wait(&b);
				uv_barrier_destroy(&b);
			}
		}

		if (!SST_ASYNC) {
			/*
			 * compare
			 */
			err = memcmp(buf_in, buf_out, SST_BS * SST_IOV_CNT);
			if (err != 0) {
				printf("data comparison error \n");
				//sleep(10);
				for (k = 0; k < SST_IOV_CNT; k++) {
					char *in  = buf_in + (k * SST_BS);
					char *out = buf_out + (k * SST_BS);

					printf("in  : \"%s\" \n", in);
					printf("out : \"%s\" \n", out);

					int cmp = memcmp(in, out, SST_BS);

					if (cmp != 0) {
						printf("err = %d\n", err);
						printf("cmp = %d\n", cmp);
						printf("k   = %d\n", k);
						printf("out = %s\n", out);
						printf("in  = %s\n", in);
						assert(0);
					}
				}
				printf("err = %d\n", err);
				printf("k   = %d\n", k);
				assert(0);
			}
		}

	}

	if (SST_ASYNC) {
		uv_barrier_wait(&b);
		uv_barrier_destroy(&b);
	}

	/*
	 * finalize completion
	 */
	err = ccow_finalize(c, NULL);
	assert(err == 0);

	je_free(buf_out);
	je_free(buf_in);
	je_free(iov_out);
	je_free(iov_in);
}

static void
stream_io_test(void **state)
{
	switch (SST_PATTERN) {
	case 1:
		pattern_001(state);
		break;

	case 2:
		pattern_002(state);
		break;

	case 3:
		pattern_003(state);
		break;

	default:
		printf("Invalid test pattern (%d) \n", SST_PATTERN);
		usage();
		break;
	}
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

	while ((opt = getopt(argc, argv, "amnhb:i:o:p:s:vrk")) != -1) {
		switch(opt) {

		case 'n':
			dd = 1;
			break;


		case 'h':
			usage();
			break;

		case 'a':
			SST_ASYNC = 1;
			break;

		case 'b':
			SST_BS = sst_convert_bytes(optarg);
			break;

		case 'i':
			SST_ITER_CNT = atoi(optarg);
			break;

		case 'm':
			SST_MARKERS = 1;
			break;

		case 'o':
			SST_OP_CNT = atoi(optarg);
			break;

		case 'p':
			SST_PATTERN = atoi(optarg);
			break;

		case 's':
			SST_IOV_CNT = atoi(optarg);
			break;

		case 'v':
			verbose = 1;
			break;

		case 'r':
			readonly = 1;
			keep_bucket = 1;
			break;

		case 'k':
			keep_bucket = 1;
			break;

		default:
			usage();
			break;
		}
	}

	if (verbose) {
		printf("block size       = %d \n"
		       "iterations       = %d \n"
		       "operaction count = %d \n"
		       "iov count        = %d \n"
		       "pattern          = %d \n"
		       "async            = %d \n"
		       "markers          = %d \n",
		       SST_BS, SST_ITER_CNT, SST_OP_CNT, SST_IOV_CNT,
		       SST_PATTERN, SST_ASYNC, SST_MARKERS);
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
