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

#define TEST_BUCKET_NAME	"paread-test-bucket"
#define TEST_NUM_ITERS		750
#define TEST_NUM_THREADS	5
char *buf;
ccow_t *cl;
int dd = 0;

/*
 * Threads for the client contexts.
 */
pthread_t *client_contexts_threads;
struct thread_context {
	int thread_no;
};
struct thread_context *t_ctx;
uv_barrier_t t_sync;


static void
client_tenant_term(void *d)
{

	printf("%s: Tenant Term...\n", __func__);
	struct thread_context *tctx = (struct thread_context *)d;
	ccow_tenant_term(cl[tctx->thread_no]);
	pthread_exit(0);
}

static void
client_do_io(void *d)
{
	struct thread_context *tctx = (struct thread_context *)d;
	int tnum = tctx->thread_no;
	ccow_t clt = cl[tnum];
	int err = 0;

	if(tnum == 0) {
		//
		// this is the writer
		//
		ccow_completion_t c;
		for (int i = 0; i < TEST_NUM_ITERS; i++) {
			size_t iovcnt = 1;
			struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
			assert_non_null(iov);

			/*
			 * a insert_list call appears to be required in order to make the
			 * metadata changes stick.  so change chunk_map type and btree order,
			 * and put a key of "zzz".
			 */
			if (i % 100 == 0)
				printf("Updating Bucket %d times\n", i);
			iov[0].iov_base = je_calloc(1, 1024);
			assert_non_null(iov[0].iov_base);
			snprintf(iov[0].iov_base, 1024, "abcdefg_%d", i);
			iov[0].iov_len = strlen(iov[0].iov_base) + 1;

			err = ccow_create_completion(clt, NULL, NULL, 1, &c);
			assert_int_equal(err, 0);

			err = ccow_insert_list(
			    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			    "", 1, c, iov, 1);

			err = ccow_wait(c, -1);
			if (err != 0) {
				printf("ccow_wait returned %d, expected %d \n", err, 0);
				assert_int_equal(err, 0);
			}
			je_free(iov[0].iov_base);
			je_free(iov);
		}
		return;
	} else {
		// this is a reader
		ccow_completion_t c;
		ccow_lookup_t iter;
		for (int i = 0; i < TEST_NUM_ITERS; i++) {
			size_t iovcnt = 1;
			struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
			assert_non_null(iov);
			if (i % 100 == 0)
				printf("Reading Bucket %d times from thread %d\n", i, tnum);

			err = ccow_create_completion(clt, NULL, NULL, 1, &c);
			assert_int_equal(err, 0);

			err = ccow_get_list(
			    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			    "",  1, c, iov, 1, TEST_NUM_ITERS, &iter);
			assert_int_equal(err, 0);

			err = ccow_wait(c, -1);
			if (err != 0 && err != -ENOENT) {
				printf("ccow_wait returned %d, expected %d \n",
				    err, 0);
			}
			if (iter)
				ccow_lookup_release(iter);
			if (err == -ENOENT) err = 0;
			// temporarily : remove this later
			if ( (err == EINTR) || (err == -EINTR) ) err = 0;
			assert_int_equal(err, 0);
			je_free(iov);
		}
		return;
	}
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
		err = ccow_bucket_create(cl[tctx->thread_no], TEST_BUCKET_NAME,
		    strlen(TEST_BUCKET_NAME) + 1, NULL);
	}

	uv_barrier_wait(&t_sync);
	/* Now start I/O */
	client_do_io(d);
	usleep(2000000);
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
	client_contexts_threads = (pthread_t *)je_calloc(TEST_NUM_THREADS, sizeof (pthread_t*));
	assert_non_null(client_contexts_threads);
	cl = (ccow_t *)je_calloc(TEST_NUM_THREADS, sizeof (ccow_t*));
	assert_non_null(cl);
	t_ctx = (struct thread_context *)je_calloc(TEST_NUM_THREADS, sizeof (struct thread_context));
	assert_non_null(t_ctx);
	uv_barrier_init(&t_sync, TEST_NUM_THREADS);
	for(int i = 0; i < TEST_NUM_THREADS; i++)
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
	for (int i = 0; i < TEST_NUM_THREADS; i++) {
		pthread_join(client_contexts_threads[i], NULL);
	}
	sleep(1);
	je_free(client_contexts_threads);
	je_free(t_ctx);
}

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
	if(!dd) {
		ccow_daemon_term();
	}
	je_free(buf);
	je_free(cl);
	return;
}


int
main(int argc, char **argv)
{
	if (argc == 2) {
		if (strcmp(argv[1], "-n") == 0)
		     dd = 1;
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

