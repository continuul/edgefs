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
#include "replicast.h"

#define TEST_BUCKET_NAME	"simple-put-bucket-test"
#define SIMPLE_TEST_OID		"simple-test"
#define TEST_NUM_THREADS	7
#define TEST_NUM_ITERS		500000


int dd = 0;
char *TEST_ENV = NULL;

char *buf;
ccow_t *cl;
volatile int put_object_now = 0;
volatile int stop_threads = 0;


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

	if(tnum == 0 && put_object_now) {
		//
		// this is the writer, but only the second time around.
		//
		struct iovec iov[1];
		iov[0].iov_len = 4096;
		iov[0].iov_base = je_malloc(iov[0].iov_len);
		assert_non_null(iov[0].iov_base);

		ccow_completion_t c;
		err = ccow_create_completion(clt, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		put_simple(c, TEST_BUCKET_NAME, SIMPLE_TEST_OID, &iov[0], 1, 0);

		err = ccow_wait(c, -1);
		assert_int_equal(err, 0);
		je_free(iov[0].iov_base);
		return;
	} else {
		// this is a reader
		ccow_completion_t c;
		ccow_lookup_t iter;
		for (int i = 0; i < TEST_NUM_ITERS && !stop_threads; i++) {
			if (i % 128)
				printf(". ");
			size_t iovcnt = 1;
			struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
			assert_non_null(iov);

			err = ccow_create_completion(clt, NULL, NULL, 1, &c);
			assert_int_equal(err, 0);
			get_simple(c, TEST_BUCKET_NAME, SIMPLE_TEST_OID, iov, iovcnt, 0, NULL);
			// wait up to 1s and timeout
			err = ccow_timed_wait(c, 0, 1000);
			if (err != 0 && err != -EBUSY && err != -ENOENT) {
				printf("ccow_wait returned %d, expected %d \n",
				    err, 0);
			}
			if (err == -EBUSY || err == -ENOENT) err = 0;
			assert_int_equal(err, 0);
			je_free(iov);
			usleep(10);
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

static void
client_shutdown()
{
	assert_non_null(client_contexts_threads);

	stop_threads = 1;
	for (int i = 0; i < TEST_NUM_THREADS; i++) {
		pthread_join(client_contexts_threads[i], NULL);
	}
	sleep(1);
	stop_threads = 0;
	put_object_now = 1;
	je_free(client_contexts_threads);
	je_free(t_ctx);
	je_free(cl);
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
	sleep(5);
	client_shutdown();

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
	TEST_ENV = getenv("NEDGE_ENV");
	if (!TEST_ENV)
		TEST_ENV = "production";
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(client_setup),
		unit_test(client_setup),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

