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
#include "ccow-impl.h"
#include "ccowd.h"
#include "replicast.h"

#define TEST_BUCKET_NAME	"simple-put-bucket-test"
#define SIMPLE_TEST_OID		"simple-test"
#define IO_LEN			4096

ccow_t cl = NULL, tc = NULL;
pthread_t client_lock_threads[2];
pthread_t stress_threads[2];

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
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
	assert_int_equal(ccow_admin_init(buf, "cltest", 7, &tc), 0);
	je_free(buf);
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

static void
object_create(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = IO_LEN;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, SIMPLE_TEST_OID, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	je_free(iov[0].iov_base);
}

static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID, NULL, NULL);
}

static void
set_lock(struct ccow_obj_lock *lk, uint8_t mode, uint64_t off, uint64_t len)
{
	memset(lk, 0, sizeof(*lk));
	lk->lk_mode = mode;
	lk->lk_region.off = off;
	lk->lk_region.len = len;
	lk->lk_ref_count = 0;
}

static void
test_lock_region(struct ccow_obj_lock *lk, uint8_t mode,
		 uint64_t off, uint64_t len, int expect_err)
{
	int err;
	struct iovec iov;

	/* Lock region [off, len) */
	set_lock(lk, mode, off, len);
	iov.iov_base = lk;
	iov.iov_len = sizeof(iov);

	/* ccow_lock blocks */
	err = ccow_lock(tc, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, lk);
	printf("Err - expected: %d actual: %d\n", expect_err, err);
	assert_int_equal(err, expect_err);

}

static int
lock_region_get_status(struct ccow_obj_lock *lk, uint8_t mode,
			uint64_t off, uint64_t len)
{
	int err;
	struct iovec iov;

	/* Lock region [off, len) */
	set_lock(lk, mode, off, len);
	iov.iov_base = lk;
	iov.iov_len = sizeof(iov);

	/* ccow_lock blocks */
	err = ccow_lock(tc, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, lk);
	return err;
}

static void
lock_region(struct ccow_obj_lock *lk, uint8_t mode, uint64_t off, uint64_t len)
{
	int err;

	err = lock_region_get_status(lk, mode, off, len);
	assert_int_equal(err, 0);
}

static void
unlock_region(struct ccow_obj_lock *lk, uint64_t off, uint64_t len)
{
	lock_region(lk, CCOW_LOCK_UNLOCK, off, len);
}

static void
lock_rt_ex_non_overlap(void **state)
{
	int err;
	struct iovec iov;
	struct ccow_obj_lock lk1, lk2;

	printf("Locking [0, 100)\n");
	/* Lock region [0, 100) */
	lock_region(&lk1, CCOW_LOCK_EXCL, 0, 100);
	printf("Locking [100, 100)\n");
	/* Lock region [100, 100) */
	lock_region(&lk2, CCOW_LOCK_EXCL, 100, 100);

	/* Unlock regions */
	printf("Unlocking [0, 100)\n");
	unlock_region(&lk1, 0, 100);
	printf("Unlocking [100, 100)\n");
	unlock_region(&lk2, 100, 100);
}

static void
ex_overlap_lock(void *arg)
{
	int thrid = (intptr_t)arg;
	int err;
	struct ccow_obj_lock lk;

	if (thrid == 1)
		usleep(1000);

	printf("Thread %d - locking [0, 100)\n", thrid);
	/* Lock region [0, 100) */
	lock_region(&lk, CCOW_LOCK_EXCL, 0, 100);

	if (thrid == 0)
		sleep(1);

	/* Unlock regions */
	printf("Thread %d - unlocking [0, 100)\n", thrid);
	unlock_region(&lk, 0, 100);
}

static void
lock_rt_ex_overlap(void **state)
{
	pthread_create(&client_lock_threads[0], NULL, (void *)&ex_overlap_lock,
			(void *)0);
	pthread_create(&client_lock_threads[1], NULL, (void *)&ex_overlap_lock,
			(void *)1);

	pthread_join(client_lock_threads[0], NULL);
	pthread_join(client_lock_threads[1], NULL);
}

/* Blocking and non-blocking lcok threads */
static void
stress_ex_lock(void *arg)
{
	int thrid = (intptr_t)arg;
	int err;
	int i;
	uint8_t mode = CCOW_LOCK_EXCL;
	struct ccow_obj_lock lk;

	if (thrid == 1)
		mode |= CCOW_LOCK_NON_BLOCK;

	for (i = 0; i < 100; i++) {
		/* Lock region [0, 100) */
		if (thrid == 1) {
			err = lock_region_get_status(&lk, mode, 0, 100);
			if (err == 0) {
				usleep(15);
				unlock_region(&lk, 0, 100);
			}
		} else {
			lock_region(&lk, mode, 0, 100);
			usleep(15);
			unlock_region(&lk, 0, 100);
		}
	}

	printf("Thread %d - finished work\n", thrid);
}

static void
stress_locks(void **state)
{
	printf("==== Started stress lock test. ===\n"
		"=== If this hangs then there is a deadlock ===\n");
	pthread_create(&stress_threads[0], NULL, (void *)&stress_ex_lock,
			(void *)0);
	pthread_create(&stress_threads[1], NULL, (void *)&stress_ex_lock,
			(void *)1);

	pthread_join(stress_threads[0], NULL);
	pthread_join(stress_threads[1], NULL);
	printf("=== Stress lock test complete ===\n");
}

static void
lock_rt_nonblock(void **state)
{
	struct ccow_obj_lock lk1, lk2;

	printf("locking [0, 100)\n");
	/* Lock region [0, 100) */
	lock_region(&lk1, CCOW_LOCK_EXCL, 0, 100);

	printf("testing lock [0, 100)\n");
	test_lock_region(&lk2, CCOW_LOCK_EXCL | CCOW_LOCK_NON_BLOCK,
			 0, 100, -EPERM);
	unlock_region(&lk1, 0, 100);

}

static void
lock_rt_fetch(void **state)
{
	struct ccow_obj_lock lk_in, lk_out, lk_fetch;
	struct iovec in_iov, out_iov;
	ccow_completion_t c;
	msgpack_p *inp = NULL, *outp = NULL;
	int err;

	printf("fetching lock [0, 100)\n");
	err = ccow_fetch_lock(tc, TEST_BUCKET_NAME,
				strlen(TEST_BUCKET_NAME) + 1,
				SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1,
				&lk_out, CCOW_LOCK_EXCL, 0, 100);
	printf("Fetching lock with error - %d\n", err);
	assert_int_equal(err, -ENOENT);

	/* Lock region [0, 100) */
	printf("Locking the region now\n");
	lock_region(&lk_in, CCOW_LOCK_EXCL, 0, 100);
	err = ccow_fetch_lock(tc, TEST_BUCKET_NAME,
				strlen(TEST_BUCKET_NAME) + 1,
				SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1,
				&lk_fetch, CCOW_LOCK_EXCL, 0, 100);

	printf("Fetching lock with error - %d\n", err);
	assert_int_equal(err, 0);
	if (!err) {
		printf("Got lock\n");
		printf("Received lock [%"PRIu64", %"PRIu64") mode %u\n",
                        lk_fetch.lk_region.off, lk_fetch.lk_region.len,
			lk_fetch.lk_mode);
	}

	unlock_region(&lk_in, 0, 100);
	msgpack_pack_free(outp);
}

static void
lock_rt_sh_non_overlap(void **state)
{
	int err;
	struct iovec iov;
	struct ccow_obj_lock lk1, lk2;

	printf("Locking [0, 100)\n");
	/* Lock region [0, 100) */
	lock_region(&lk1, CCOW_LOCK_SHARED, 0, 100);
	printf("Locking [100, 100)\n");
	/* Lock region [200, 200) */
	lock_region(&lk2, CCOW_LOCK_SHARED, 100, 100);

	/* Unlock regions */
	printf("Unlocking [0, 100)\n");
	unlock_region(&lk1, 0, 100);
	printf("Unlocking [100, 100)\n");
	unlock_region(&lk2, 100, 100);
}

static void
lock_rt_sh_overlap(void **state)
{
	int err;
	struct iovec iov;
	struct ccow_obj_lock lk1, lk2;

	printf("Locking shared [0, 100)\n");
	/* Lock region [0, 100) */
	lock_region(&lk1, CCOW_LOCK_SHARED, 0, 100);
	printf("Locking shared [0, 100)\n");
	/* Lock region [0, 100) */
	lock_region(&lk2, CCOW_LOCK_SHARED, 0, 100);

	/* Unlock regions */
	printf("Unlocking [0, 100)\n");
	unlock_region(&lk1, 0, 100);
	printf("Unlocking [100, 100)\n");
	unlock_region(&lk2, 0, 100);
}

static void
lock_rt_cancel(void **state)
{
	int err;
	struct iovec iov;
	struct ccow_obj_lock lk1, lk2;

	/* 1. Cancel a lock not held */
	printf("Cancel unlocked region [0, 100)\n");
	test_lock_region(&lk1, CCOW_LOCK_CANCEL, 0, 100, -ENOENT);

	/* 2. Cancel a lock held */
	printf("Locking shared [0, 100)\n");
	/* Lock region [0, 100) */
	lock_region(&lk2, CCOW_LOCK_SHARED, 0, 100);
	printf("Cancel unlocked region [0, 100)\n");
	test_lock_region(&lk1, CCOW_LOCK_CANCEL, 0, 100, 0);

	/* 3. Cancel a wait-lock */
	/* TODO: This is test to be implemented after lock owner is used */
}

static void
libccow_teardown(void **state)
{
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
		unit_test(object_create),
		unit_test(lock_rt_ex_non_overlap),
		unit_test(lock_rt_sh_non_overlap),
		unit_test(lock_rt_sh_overlap),
		unit_test(lock_rt_ex_overlap),
		unit_test(lock_rt_cancel),
		unit_test(lock_rt_nonblock),
		unit_test(stress_locks),
		unit_test(lock_rt_fetch),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

