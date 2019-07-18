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
#include <pthread.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"
#include "replicast.h"
#include "../src/libccow/ccow-impl.h"

char *STRESS_TEST_BID = "ccowperf-test-bucket";
#define STRESS_TEST_OID		"ccowperf-test-object"
#define STRESS_SNAPVIEW_OID "ccowperf-test-snapview"
#define STRESS_SNAPSHOT_NAME "ccowperf-test-snapshot"
char *buf;
ccow_t *cl;
int verbose = 0;
int dd = 0;

/*
 * Basic operatives.
 */
int64_t  SST_ENC_EN	= 0;
int64_t  SST_OP_CNT	= 128;
uint64_t SST_BS		= 1024;
int64_t  SST_ITER_CNT	= 1024;
int64_t  SST_IOV_CNT    = 1;
int32_t  SST_PATTERN    = 1;
int64_t  SST_THREAD_CNT	= 1;
int32_t  SST_SYNC	= 1;
int32_t  SST_WRITE	= 1;
int32_t  SST_READ	= 0;
int32_t  SST_RAND	= 0;
int32_t  SST_COMPARE	= 0;
int32_t  SST_SEQ	= 0;
int32_t  SST_INIT_WRITE	= 1;
int      SST_NUM_VERSIONS = 1;
uint16_t  BTREE_ORDER = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_DEFAULT;
uint16_t SST_SNAPSHOT_INTERVAL = 0;
int16_t SST_SNAPHOST_EXPUNGE = -1;
int16_t SST_SHARE_BUFFERS = 0;
char btree_env[64];

/*
 * Threads for the client contexts.
 */
pthread_t *client_contexts_threads;
struct thread_context {
	int thread_no;
	uint64_t spent_ns;
};
struct thread_context *t_ctx;
uv_barrier_t t_sync;

static char * buf_shared = NULL;

static void
client_io_async_cb(ccow_completion_t c, void *arg, int index,
    int err)
{
	uv_barrier_t *b = arg;

	if (verbose)
		fprintf(stderr, "asnc_cb idx %d, err %d\n", index, err);

	if (err != 0) {
		printf("IO completed with err = %d\n", err);
		assert(err == 0);
	}

	if (index != 0 && SST_SYNC)
		uv_barrier_wait(b);
}

static void
client_tenant_term(void *d)
{

	printf("%s: Tenant Term...\n", __func__);
	struct thread_context *tctx = (struct thread_context *)d;
	ccow_tenant_term(cl[tctx->thread_no]);
	pthread_exit(0);
}

static void
shuffle(int *a, int n) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int usec = tv.tv_usec;
	srand48(usec);

	int i = n - 1;
	int j, temp;

	while (i > 0)
	{
		j = rand() % (i + 1);
		temp = a[i];
		a[i] = a[j];
		a[j] = temp;
		i = i - 1;
	}
}

/*
 * Client I/O routine.
 */
static void
client_do_io(void *d)
{
	struct thread_context *tctx = (struct thread_context *)d;
	int tnum = tctx->thread_no;
	char sv_oid_buff[64];
	ccow_t clt = cl[tnum];
	ccow_snapview_t sv_hdl;
	uint64_t before, read, iter_before, iter_read, bytes;

	int err = 0, ii, i = 0, jj, j = 0, k = 0;
	int sh_count = 0, sh_next = SST_SNAPSHOT_INTERVAL - 1;
	char *buf_out, *buf_in;
	ccow_completion_t c;
	struct iovec *iov_out, *iov_in;
	uv_barrier_t b;
	uint64_t offset = 0;
	uint64_t thr_offset = SST_BS*tnum*BTREE_ORDER/2;
	char objname[64];

	printf("thr[%d] offset %lu\n", tnum, thr_offset);
	size_t io_size = SST_BS * SST_IOV_CNT;

	if (!SST_SHARE_BUFFERS) {
		buf_out = je_calloc(SST_IOV_CNT, SST_BS);
		assert(buf_out != NULL);

		/*
		 * Randomize 2/3 of data out...
		 */
		srand(time(NULL));
		for (k = 0; k < SST_IOV_CNT; k++) {
			char *out = buf_out + (k * SST_BS);
			for (i = 0; i < (int)SST_BS/6; i++)
				*((uint32_t *)out + i) = rand();
		}
	} else {
		buf_out = buf_shared;
	}
	buf_in = je_calloc(SST_IOV_CNT, SST_BS);
	assert(buf_in != NULL);

	iov_out = je_calloc(SST_IOV_CNT, sizeof(struct iovec));
	assert(iov_out != NULL);

	iov_in = je_calloc(SST_IOV_CNT, sizeof(struct iovec));
	assert(iov_in != NULL);

	sprintf(objname, "%s-%d-%ld", STRESS_TEST_OID, tnum, SST_BS);

	/* wait for all the threads */
	printf("threadno: %d ready\n", tctx->thread_no);
	uv_barrier_wait(&t_sync);

	printf("%s: About to do work... %s/%s\n", __func__, STRESS_TEST_BID, objname);

	/*
	 * iterate through the number of tests
	 */

	int arr_i[SST_ITER_CNT];
	for (k = 0; k < SST_ITER_CNT; k++)
		arr_i[k] = k;

	int arr_j[SST_OP_CNT];
	for (k = 0; k < SST_OP_CNT; k++)
		arr_j[k] = k;

	if (SST_RAND) {
		shuffle(arr_i, SST_ITER_CNT);
		shuffle(arr_j, SST_OP_CNT);
	}

	before = uv_hrtime();
	uint64_t genid = 0;
	for (ii = 0; ii < SST_ITER_CNT; ii++) {
		i = arr_i[ii];
		iter_before = uv_hrtime();
		if (verbose)
			printf("i = %6.6d \n", i);

		if (SST_WRITE) {
			/*
			 * create stream completion for writes
			 */
			assert(clt);
			err = ccow_create_stream_completion(clt, &b,
			    client_io_async_cb, SST_OP_CNT, &c,
			    STRESS_TEST_BID, strlen(STRESS_TEST_BID) + 1,
			    objname, strlen(objname) + 1, &genid, NULL, NULL);
			assert(err == 0);

			if (ii == 0) {

				uint8_t hash_type = 8; // XXHASH_128
				if (SST_ENC_EN)
					CRYPTO_ENC_SET(hash_type);
				err = ccow_attr_modify_default(c, CCOW_ATTR_HASH_TYPE,
				    (void *)&hash_type, NULL);
				assert_int_equal(err, 0);

				uint16_t num_vers = SST_NUM_VERSIONS;
				err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
				    (void *)&num_vers, NULL);
				assert_int_equal(err, 0);

				uint32_t bs = SST_BS;
				err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
				    (void *)&bs, NULL);
				assert_int_equal(err, 0);

				err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
				    (uint16_t *)&BTREE_ORDER, NULL);
				assert_int_equal(err, 0);

				uint16_t vv = 1;
				err = ccow_attr_modify_default(c, CCOW_ATTR_TRACK_STATISTICS,
				    (uint16_t *)&vv, NULL);
				assert_int_equal(err, 0);

				if (SST_INIT_WRITE) {
					iov_out[0].iov_len  = SST_BS;
					iov_out[0].iov_base = buf_out;
					if (SST_SEQ)
						offset = SST_OP_CNT * SST_BS * SST_IOV_CNT * SST_ITER_CNT;
					else
						offset = (SST_OP_CNT * SST_BS * SST_IOV_CNT) - SST_BS;
					printf("write last chunk at offset %"PRIx64"\n",
					    offset);
					if (SST_SYNC)
						uv_barrier_init(&b, 2);
					err = ccow_put_cont(c, iov_out, 1, offset,
					    0, NULL);
					assert_int_equal(err, 0);
					if (SST_SYNC) {
						uv_barrier_wait(&b);
						uv_barrier_destroy(&b);
					}
					err = ccow_finalize(c, NULL);
					assert(err == 0);

					assert(clt);
					err = ccow_create_stream_completion(clt, &b,
					    client_io_async_cb, SST_OP_CNT, &c,
					    STRESS_TEST_BID, strlen(STRESS_TEST_BID) + 1,
					    objname, strlen(objname) + 1, &genid,
					    NULL, NULL);
					assert(err == 0);
				}

				if (SST_SNAPSHOT_INTERVAL) {
					sprintf(btree_env,"NEDGE_SV_BTREE_ORDER=%u", BTREE_ORDER);
					putenv(btree_env);
					sprintf(sv_oid_buff, "%s-%d", STRESS_SNAPVIEW_OID, tnum);
					err = ccow_snapview_create(clt, &sv_hdl, STRESS_TEST_BID,
						    strlen(STRESS_TEST_BID) + 1, sv_oid_buff,
						    strlen(sv_oid_buff) + 1);
					if (err != -EEXIST)
						assert_int_equal(err, 0);
				}
			}
		}

		/*
		 * iterate through the number of IOs per test
		 */
		for (jj = 0; jj < SST_OP_CNT; jj++) {
			j = arr_j[jj];
			if (verbose)
				printf("i = %6.6d, j = %6.6d \n", i, j);

			if (SST_WRITE) {
				for (k = 0; k < SST_IOV_CNT; k++) {
					/*
					 * create the buffer contents
					 */
					if (!SST_SHARE_BUFFERS) {
						char * out = buf_out + (k * SST_BS);
						sprintf(out, "byte me world : i = 0x%4.4x "
						": j = 0x%4.4x : k = 0x%4.4x "
						": SST_BS = 0x%"PRIx64" tnum=%d",
						i, j, k, SST_BS, tnum);
						iov_out[k].iov_len  = SST_BS;
						iov_out[k].iov_base = out;
					} else {
						uint64_t op_offset = j * (k+1) * SST_BS;
						iov_out[k].iov_len  = SST_BS;
						if (j < BTREE_ORDER) {
							iov_out[k].iov_base = buf_shared + op_offset;
						} else
							iov_out[k].iov_base = buf_shared + thr_offset + op_offset;
					}
				}

				/*
				 * put
				 */
				if (SST_SEQ)
					offset = (i * SST_BS * SST_IOV_CNT * SST_OP_CNT) + j * SST_BS * SST_IOV_CNT;
				else
					offset = j * SST_BS * SST_IOV_CNT;

				if (SST_SYNC)
					uv_barrier_init(&b, 2);
				err = ccow_put_cont(c, iov_out, SST_IOV_CNT, offset,
				    0, NULL);
				assert_int_equal(err, 0);
				if (SST_SYNC) {
					uv_barrier_wait(&b);
					uv_barrier_destroy(&b);
				}
			}
		}
		if (SST_WRITE) {
			err = ccow_finalize(c, NULL);
			assert(err == 0);
			if (SST_SNAPSHOT_INTERVAL && i == sh_next) {
				char buf[64];
				sprintf(buf, "%s-%d", STRESS_SNAPSHOT_NAME, sh_count++);
				printf("Creating snapshot %s\n", buf);
				err = ccow_snapshot_create(clt, sv_hdl, STRESS_TEST_BID,
				    strlen(STRESS_TEST_BID) + 1, objname,
				    strlen(objname) + 1, buf,
				    strlen(buf) + 1);
				assert_int_equal(err, 0);
				sh_next += SST_SNAPSHOT_INTERVAL;
			}
		}

		if (SST_READ) {
			/*
			 * create stream completion for reads
			 */
			assert(clt);
			err = ccow_create_stream_completion(clt, &b,
			    client_io_async_cb, SST_OP_CNT, &c,
			    STRESS_TEST_BID, strlen(STRESS_TEST_BID) + 1,
			    objname, strlen(objname) + 1, &genid, NULL, NULL);
			assert_int_equal(err, 0);
		}

		for (jj = 0; jj < SST_OP_CNT; jj++) {
			j = arr_j[jj];
			if (SST_READ) {
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
				if (SST_SEQ)
					offset = (i * SST_BS * SST_IOV_CNT * SST_OP_CNT) + j * SST_BS * SST_IOV_CNT;
				else
					offset = j * SST_BS * SST_IOV_CNT;

				if (SST_SYNC)
					uv_barrier_init(&b, 2);

				err = ccow_get_cont(c, iov_in, SST_IOV_CNT, offset,
				    0, NULL);
				assert_int_equal(err, 0);

				if (SST_SYNC) {
					uv_barrier_wait(&b);
					uv_barrier_destroy(&b);
				}
			}
		}
		if (SST_READ) {
			err = ccow_finalize(c, NULL);
			assert(err == 0);
		}

		if (SST_WRITE && SST_READ && SST_COMPARE) {
			err = memcmp(buf_in, buf_out, SST_BS * SST_IOV_CNT);
			if (err != 0) {
				printf("data comparison error \n");
				for (k = 0; k < SST_IOV_CNT; k++) {
					char *in = buf_in + (k * SST_BS);
					char *out = buf_out + (k * SST_BS);

					printf("out : \"%s\" \n", out);
					printf("in  : \"%s\" \n", in);

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

		iter_read = (uv_hrtime() - iter_before);
		bytes = SST_OP_CNT * SST_IOV_CNT * SST_BS;
		printf("Iter%d: %.2f MBytes: %.3fs (%.2fMB/s)\n", i, 1.0 * bytes / 1024 / 1024,
		    iter_read / 1e9, 1.0 * bytes / (iter_read / 1e9) / 1024 / 1024);

		// ccow_print_stats(&cl[tctx->thread_no]->stats);
	}
	tctx->spent_ns = (uv_hrtime() - before);

	printf("%s: Finished work...\n", __func__);
	bytes = SST_ITER_CNT * SST_OP_CNT * SST_IOV_CNT * SST_BS;
	printf("%.2f MBytes: %.3fs (%.2fMB/s)\n", 1.0 * bytes / 1024 / 1024,
	    tctx->spent_ns / 1e9, 1.0 * bytes / (tctx->spent_ns / 1e9) / 1024 / 1024);
	printf("IOPs: %.2f\n", (1.0 * bytes / SST_BS) / (tctx->spent_ns * 1.0 / 1e9));
	fflush(stdout);
	if (SST_WRITE && SST_SNAPSHOT_INTERVAL) {
		ccow_snapview_destroy(clt, sv_hdl);
	}
	if (!SST_SHARE_BUFFERS)
		je_free(buf_out);
	je_free(buf_in);
	je_free(iov_out);
	je_free(iov_in);
}

/*
 * Client Tenant Create and Issue the I/O.
 */
static void
client_tenant_create(void *d)
{
	struct thread_context *tctx = (struct thread_context *)d;
	int err = ccow_tenant_init(buf, "cltest", 7, "test", 5,
	    &cl[tctx->thread_no]);
	if (err) {
		printf("ccow_tenant_init error: %d\n", err);
		pthread_exit((void*)-ENOMEM);
	}

	if (tctx->thread_no == 0) {
		err = ccow_bucket_create(cl[tctx->thread_no], STRESS_TEST_BID,
		    strlen(STRESS_TEST_BID) + 1, NULL);
	}

	if (SST_SNAPHOST_EXPUNGE >= 0) {
		/* Special case - delete a snapshot and exit */
		char buff_oid[64];
		char buff_name[64];
		int tnum = tctx->thread_no;
		ccow_t clt = cl[tnum];
		ccow_snapview_t sv_hdl;

		/* snapview had to be created before */
		sprintf(buff_oid, "%s-%d", STRESS_SNAPVIEW_OID, tnum);
		err = ccow_snapview_create(clt, &sv_hdl, STRESS_TEST_BID,
			    strlen(STRESS_TEST_BID) + 1, buff_oid,
			    strlen(buff_oid) + 1);
		assert_int_equal(err, -EEXIST);

		sprintf(buff_name, "%s-%d", STRESS_SNAPSHOT_NAME, SST_SNAPHOST_EXPUNGE);
		printf("Deleting snapshot %s\n", buff_name);
		err = ccow_snapshot_delete(clt, sv_hdl, buff_name, strlen(buff_name) + 1);
		assert_int_equal(err, 0);
		ccow_snapview_destroy(clt, sv_hdl);
		usleep(2000000);
	} else {
		/* Now start I/O */
		client_do_io(d);

		usleep(2000000);

		ccow_stats_t stats;
		int rv = ccow_get_stats(cl[tctx->thread_no], &stats);
		if (rv == 0) {
			ccow_print_stats(stats);
		}
	}

	client_tenant_term(d);
}
/*
 * Client Setup function.
 */
static void
client_setup()
{
	int err = 0;
	/* First spawn the threads. */
	/* Each thread will create a tenant context and then begin I/O */
	client_contexts_threads = (pthread_t *)je_calloc(SST_THREAD_CNT, sizeof (pthread_t*));
	assert_non_null(client_contexts_threads);
	cl = (ccow_t *)je_calloc(SST_THREAD_CNT, sizeof (ccow_t*));
	assert_non_null(cl);
	t_ctx = (struct thread_context *)je_calloc(SST_THREAD_CNT, sizeof (struct thread_context));
	assert_non_null(t_ctx);
	if (SST_SHARE_BUFFERS) {
		/* Create and randomize a shared buffer */
		buf_shared = je_calloc(SST_IOV_CNT*SST_OP_CNT*2*SST_THREAD_CNT, SST_BS);
		srand(time(NULL));
		for (int k = 0; k < 2*SST_IOV_CNT*SST_OP_CNT*SST_THREAD_CNT; k++) {
			char *out = buf_shared + (k * SST_BS);
			for (int i = 0; i < (int)SST_BS/4; i++)
				*((uint32_t *)out + i) = rand();
		}
	}
	uv_barrier_init(&t_sync, SST_THREAD_CNT);
	for(int i = 0; i < SST_THREAD_CNT; i++)
	{
		t_ctx[i].thread_no = i;
		printf("threadno: %d  other: %p\n", t_ctx[i].thread_no, (void *)&t_ctx[i]);
		pthread_create(&client_contexts_threads[i], NULL,
		    (void *)&client_tenant_create, (void *)&t_ctx[i]);
		usleep(500000);
	}

}

static void
client_shutdown()
{
	assert_non_null(client_contexts_threads);

	uint64_t total_spent_ns = 0;
	for (int i = 0; i < SST_THREAD_CNT; i++) {
		pthread_join(client_contexts_threads[i], NULL);
		total_spent_ns += t_ctx[i].spent_ns;
	}
	uint64_t total_bytes = SST_THREAD_CNT * SST_ITER_CNT * SST_OP_CNT * SST_IOV_CNT * SST_BS;
	uint64_t avg_spent_ns = total_spent_ns / SST_THREAD_CNT;

	sleep(1);
	printf("================= TOTAL ================\n");
	float iops = (1.0 * total_bytes / SST_BS) / (avg_spent_ns * 1.0 / 1e9);
	printf("%.2f MBytes: %.3fs (%.2fMB/s)\n", 1.0 * total_bytes / 1024 / 1024, avg_spent_ns / 1e9, iops * (1.0 * SST_BS / 1024 / 1024));
	printf("IOPs: %.2f\n", iops);
	fflush(stdout);
	uv_barrier_destroy(&t_sync);
	je_free(client_contexts_threads);
	je_free(t_ctx);
	if (SST_SHARE_BUFFERS && buf_shared) {
		je_free(buf_shared);
	}
}




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
	       "     ./ccowperf_test [-h] [-b block_size] \n"
	       "          [-i iteratations] [-o op_count] [-t threads]\n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -b   Specify the block size form of \"[0-9]+[GMKB]?\".\n"
	       "         (Defaults to 1024).\n"
		   "\n"
		   "    -d   Specify the btree order in range 4..192.\n"
		   "         (Defaults to 192).\n"
	       "\n"
	       "    -i   Specify the number of iterations.\n"
	       "         (Defaults to 1024).\n"
	       "\n"
	       "    -o   Specify the number of stream IOs per iteration.\n"
	       "         (Defaults to 128).\n"
	       "\n"
	       "    -s   Specify the number of iovec entries per IO.  I/O size\n"
	       "         will be iovec_entries * block_size.\n"
	       "         (Defaults to 1).\n"
	       "\n"
	       "    -t   Specify the number of parallel tenant contexts,\n"
	       "         this will be the equivalent of threads/clients.\n"
	       "         (Defaults to 1).\n"
	       "\n"
	       "    -E   Enable encryption.\n"
	       "\n"
	       "    -f   Wait for cont I/O to complete before scheduling next.\n"
	       "\n"
	       "    -r|-w|-c Measure Read/Write/Compare I/O performance.\n"
	       "\n"
	       "    -v   Enable verbose debug output.\n"
	       "\n"
	       "    -n   Disable ccowserv startup.\n"
	       "\n"
	       "    -N   Number of versions to keep (default: 1)\n"
	       "\n"
	       "    -q   Sequential I/O. Used with -r|-w|-c combination.\n"
		   "\n"
		   "    -a   Create a snapshot after specified number of versions.\n"
		   "         Used with -w option.\n"
		   "\n"
		   "    -e   Delete a snapshot with specified index.\n"
		   "\n"
		   "    -S   Share data buffers between threads. For dedup testing.\n"
		   "\n"
	       "\n");

	exit(EXIT_SUCCESS);
}

/*
 * ================== LIBCCOW/D STARTUP/SHUDOWN FUNCTIONS ====================
 */
static void
libccowd_setup(void **state)
{
    if(!dd){
        assert_int_equal(ccow_daemon_init(NULL), 0);
        usleep(2 * 1000000L);
    }
}

static void
libccowd_teardown(void **state) {
	if(!dd)
		ccow_daemon_term();
	je_free(buf);
	je_free(cl);
}
/*
 * ================== LIBCCOW/D STARTUP/SHUDOWN FUNCTIONS ====================
 */

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

	while ((opt = getopt(argc, argv, "hqfrwWcb:d:i:o:p:s:vh:t:na:e:gSEB:N:")) != -1) {
		switch(opt) {

		case 'h':
			usage();
			break;

		case 'B':
			STRESS_TEST_BID = optarg;
			break;

		case 'b':
			SST_BS = sst_convert_bytes(optarg);
			break;

		case 'i':
			SST_ITER_CNT = atoi(optarg);
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

		case 't':
			SST_THREAD_CNT = atoi(optarg);
			break;

		case 'f':
			SST_SYNC = 1;
			break;

		case 'r':
			SST_READ = 1;
			SST_WRITE = 0;
			break;

		case 'w':
			SST_WRITE = 1;
			break;

		case 'W':
			SST_INIT_WRITE = 1;
			break;

		case 'c':
			SST_READ = 1;
			SST_WRITE = 1;
			SST_COMPARE = 1;
			SST_SYNC = 1;
			break;

		case 'n':
			dd = 1;
			break;

		case 'v':
			verbose = 1;
			break;

		case 'E':
			SST_ENC_EN = 1;
			break;

		case 'g':
			SST_RAND = 1;
			break;

		case 'q':
			SST_SEQ = 1;
			break;

		case 'd':
			BTREE_ORDER = atoi(optarg);
			if (BTREE_ORDER < 4)
				BTREE_ORDER = 4;
			if (BTREE_ORDER > 640)
				BTREE_ORDER = 640;
			break;

		case 'a':
			SST_SNAPSHOT_INTERVAL = atoi(optarg);
			break;

		case 'e':
			SST_SNAPHOST_EXPUNGE = atoi(optarg);
			break;

		case 'S':
			SST_SHARE_BUFFERS = 1;
			break;

		case 'N':
			SST_NUM_VERSIONS = atoi(optarg);
			break;

		default:
			usage();
			break;
		}
	}

	if (verbose) {
		printf("block size       = %"PRIu64"\n"
		       "iterations       = %"PRIu64"\n"
		       "operation count = %"PRIu64"\n"
		       "iov count        = %"PRIu64"\n"
		       "pattern          = %d\n"
		       "tenant contexts  = %"PRIu64"\n",
		       SST_BS, SST_ITER_CNT, SST_OP_CNT, SST_IOV_CNT,
		       SST_PATTERN, SST_THREAD_CNT);
	}


	/*
	 * Init the ccow.json for all the threads to read only.
	 */
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);

	/*
	 * run tests
	 */
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(client_setup),
		unit_test(client_shutdown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
