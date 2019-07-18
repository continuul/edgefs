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

ccow_t tc = NULL;
int dd = 0;

/*
 * This test simulates the threading that the ccowgw and s3gw will be using
 * to interface with the bindings, specifically this means that many threads
 * will be sharing the same tenant context physically and submitting to it's
 * work queues at the same time.
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
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);
	je_free(buf);
}

struct worker_context {
	int worker_no;
	uv_work_t wreq;
	ccow_t tc;
};

#define NUM_WORKERS	50
#define TEST_BID	"test"
int completed = 0;
struct worker_context *ch;

static void
beginWork(uv_work_t *wreq)
{
	struct worker_context *ch = wreq->data;
	char bucket_name[64];
	sprintf(bucket_name, "%s-%d", TEST_BID, ch->worker_no);
	printf("About to create bucket: %s with worker: %d\n", bucket_name, ch->worker_no);
	int err = ccow_bucket_create(tc, bucket_name, strlen(bucket_name), NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
afterWork(uv_work_t *wreq, int status)
{
	struct worker_context *ch = wreq->data;
	printf("bucket completion status: %d worker: %d\n", status, ch->worker_no);
}

static void
queue_workers(void **state)
{
	assert_non_null(tc);
	ch = (struct worker_context *) je_malloc
		(NUM_WORKERS * sizeof (struct worker_context));
	struct ccow *ctx = (struct ccow *)tc;
	for (int i = 0; i < NUM_WORKERS; i ++)
	{
		ch[i].worker_no = i;
		ch[i].wreq.data = &ch[i];
		ch[i].tc = tc;
		uv_queue_work(uv_default_loop(), &ch[i].wreq, beginWork,
		    afterWork);
		printf("queueing a worker.. %d\n", i);
	}
}

static void
libccow_teardown(void **state)
{
	printf("Waiting for IO to complete for 4s..\n");
	usleep(4000000);

	ccow_lookup_t iter;
	printf("all buckets in tenant:\n");
	int err = ccow_bucket_lookup(tc, "", 1, 100, &iter);
	assert_int_equal(err, 0);

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++))) {
		if (kv->type == CCOW_KVTYPE_RAW) {
			char format[16];
			sprintf(format, "key %%.%us\n", kv->key_size);
			printf(format, kv->key);
		} else if (kv->type == CCOW_KVTYPE_STR)
			printf("key %s\n", kv->key);
	}
	printf("pos %d\n", pos);
	ccow_lookup_release(iter);
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state)
{
    if(!dd){
        assert_non_null(tc);
        ccow_daemon_term();
    }
    je_free(ch);
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
		unit_test(queue_workers),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
