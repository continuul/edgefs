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
#include <time.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"
#include "replicast.h"

#define TEST_BUCKET_NAME	"simple-put-bucket-test"
ccow_t cl = NULL, tc = NULL;

int dd = 0;
char *TEST_ENV = NULL;

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

/*
 * =======================================================================
 *		Put Test Sync, Fixedmap 3x4, bs=4k
 * =======================================================================
 */
#define SIMPLE_TEST_OID		"simple-test"
#define SIMPLE_TEST_OID_CONT	"simple-test-cont"
#define SIMPLE_TEST_OID_RC1	"simple-test-rc1"
#define SIMPLE_TEST_OID_RC2	"simple-test-rc2"
#define SIMPLE_TEST_OID_RC3	"simple-test-rc3"
#define SIMPLE_TEST_OID_RC4	"simple-test-rc4"
#define SIMPLE_TEST_BS		4096

static void
simple_put_0_4k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = SIMPLE_TEST_BS;
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

#define SIMPLE_CHUNK_IOVCNT 100
static void
simple_put_chunk_0_4k(void **state)
{
	assert_non_null(cl);
	int err;
	size_t iovcnt = SIMPLE_CHUNK_IOVCNT;
	struct iovec iov[SIMPLE_CHUNK_IOVCNT];
	for (size_t i = 0; i < SIMPLE_CHUNK_IOVCNT; i++) {
		iov[i].iov_len = SIMPLE_TEST_BS;
		iov[i].iov_base = je_malloc(iov[i].iov_len);
		assert_non_null(iov[i].iov_base);
	}
	static char rand_buf[128] = { 0 };
	static int cnt = 0;

	if (*rand_buf == 0 && *(rand_buf + 1) == 0) {
		unsigned int v = rand(), *ptr = (unsigned int *)rand_buf;
		for (size_t j = 0; j < 128 / 4; j++)
			ptr[j] = (v << 16) ^ rand();
	}

	/* make all iov's random, so that it will stress compression algos  */
	for (size_t i = 0; i < iovcnt; i++) {
		rand_buf[0] = cnt++;
		memcpy(iov[i].iov_base, rand_buf, iov[i].iov_len < 128 ?
		    iov[i].iov_len : 128);
	}
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, SIMPLE_CHUNK_IOVCNT, &c);
	assert_int_equal(err, 0);

	for (size_t i = 0; i < iovcnt; i ++)
	{
		err = ccow_admin_pseudo_put_chunks(&iov[i], 1,
		    RD_ATTR_CHUNK_PAYLOAD, NULL, NULL, c);
		assert_int_equal(err, 0);
		err = ccow_wait(c, i);
		assert_int_equal(err, 0);
	}

	for (size_t i = 0; i < SIMPLE_CHUNK_IOVCNT; i++) {
		je_free(iov[i].iov_base);
	}
}

static void
simple_put_stream_0_4k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov_in[3];
	struct iovec iov_out[3];
	for (int i = 0; i < 3; i++) {
		iov_in[i].iov_len = SIMPLE_TEST_BS;
		iov_in[i].iov_base = je_malloc(iov_in[i].iov_len);
		assert_non_null(iov_in[i].iov_base);

		iov_out[i].iov_len = SIMPLE_TEST_BS;
		iov_out[i].iov_base = je_malloc(iov_out[i].iov_len);
		assert_non_null(iov_out[i].iov_base);
	}

	/* first transaction */

	uint64_t genid = 0;
	ccow_completion_t c;
	err = ccow_create_stream_completion(cl, NULL, NULL, 10, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID_CONT, strlen(SIMPLE_TEST_OID_CONT) + 1, &genid,
	    NULL, NULL);
	assert_int_equal(err, 0);

	uint32_t bs = SIMPLE_TEST_BS;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, NULL);
	assert_int_equal(err, 0);

	char bookname_key2[] = "X-Object-Meta-Book";
	char book_value2[] = "Ċ";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key2, 19,
	    book_value2, 0, NULL);
	assert_int_equal(err, 0);

	int op_cnt = 1;

	err = ccow_put_cont(c, &iov_out[0], 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_get_cont(c, &iov_in[0], 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_put_cont(c, &iov_out[1], 2, SIMPLE_TEST_BS, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_get_cont(c, &iov_out[1], 2, SIMPLE_TEST_BS, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	/* verify that stream created object exists */
	ccow_lookup_t iter;
	get(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_CONT, NULL, 0, 0, NULL,
	    NULL, &iter);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	ccow_lookup_release(iter);

	/* second transaction */
	err = ccow_create_stream_completion(cl, NULL, NULL, 10, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID_CONT, strlen(SIMPLE_TEST_OID_CONT) + 1, &genid,
	    NULL, NULL);
	assert_int_equal(err, 0);

	op_cnt = 1;

	err = ccow_put_cont(c, &iov_out[0], 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_get_cont(c, &iov_in[0], 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_put_cont(c, &iov_out[0], 3, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, op_cnt++);
	assert_int_equal(err, 0);

	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	for (int i = 0; i < 3; i++) {
		je_free(iov_in[i].iov_base);
		je_free(iov_out[i].iov_base);
	}
}

static void
simple_put_async_cb(ccow_completion_t c, void *arg, int index, int err)
{
	uv_barrier_t *b = arg;
	assert_int_equal(err, 0);
	printf("index = %d\n", index);
	if (index != 0)
		uv_barrier_wait(b);
}

static void
simple_put_stream_0_4k_async(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov_in[3];
	struct iovec iov_out[3];
	for (int i = 0; i < 3; i++) {
		iov_in[i].iov_len = SIMPLE_TEST_BS;
		iov_in[i].iov_base = je_malloc(iov_in[i].iov_len);
		assert_non_null(iov_in[i].iov_base);

		iov_out[i].iov_len = SIMPLE_TEST_BS;
		iov_out[i].iov_base = je_malloc(iov_out[i].iov_len);
		assert_non_null(iov_out[i].iov_base);
	}

	uint64_t before, write, read;
	int cmds_max = 3;

	/* first transaction */

	uv_barrier_t b;
	uv_barrier_init(&b, 2);

	/* always sync, will wait */
	uint64_t genid = 0;
	ccow_completion_t c;
	err = ccow_create_stream_completion(cl, &b, simple_put_async_cb, 10,
	    &c, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    SIMPLE_TEST_OID, strlen(SIMPLE_TEST_OID) + 1, &genid, NULL, NULL);
	assert_int_equal(err, 0);

	before = uv_hrtime();
	err = ccow_put_cont(c, &iov_out[0], 1, 0, 0, NULL);
	assert_int_equal(err, 0);
	uv_barrier_wait(&b);
	write = (uv_hrtime() - before);

	uv_barrier_destroy(&b);
	uv_barrier_init(&b, 2);

	printf("%s stats (sync write): %.3fs (%s/s)\n", fmt(1.0), write / 1e9,
	    fmt(1.0 / (write / 1e9)));
	fflush(stdout);

	before = uv_hrtime();
	err = ccow_get_cont(c, &iov_in[0], 1, 0, 0, NULL);
	assert_int_equal(err, 0);
	uv_barrier_wait(&b);
	read = (uv_hrtime() - before);

	printf("%s stats (sync read): %.3fs (%s/s)\n", fmt(1.0), read / 1e9,
	    fmt(1.0 / (read / 1e9)));
	fflush(stdout);

	uv_barrier_destroy(&b);
	uv_barrier_init(&b, 2);

	before = uv_hrtime();
	err = ccow_put_cont(c, &iov_out[1], 2, SIMPLE_TEST_BS, 1, NULL);
	assert_int_equal(err, 0);
	uv_barrier_wait(&b);
	write = (uv_hrtime() - before);

	printf("%s stats (sync 2 chunks write): %.3fs (%s/s)\n", fmt(1.0), write / 1e9,
	    fmt(1.0 / (write / 1e9)));
	fflush(stdout);

	uv_barrier_destroy(&b);
	uv_barrier_init(&b, 2);

	before = uv_hrtime();
	err = ccow_get_cont(c, &iov_out[1], 2, SIMPLE_TEST_BS, 0, NULL);
	assert_int_equal(err, 0);
	uv_barrier_wait(&b);
	read = (uv_hrtime() - before);

	printf("%s stats (sync 2 chunks read): %.3fs (%s/s)\n", fmt(1.0), read / 1e9,
	    fmt(1.0 / (read / 1e9)));
	fflush(stdout);

	uv_barrier_destroy(&b);
	uv_barrier_init(&b, 2);

	/* always sync, will wait */
	ccow_lookup_t iter;
	err = ccow_finalize(c, &iter);
	assert_int_equal(err, 0);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	ccow_lookup_release(iter);

	for (int i = 0; i < 3; i++) {
		je_free(iov_in[i].iov_base);
		je_free(iov_out[i].iov_base);
	}
}

static void
simple_put_0_120(int repcnt, char *oid, void *state)
{
	assert_non_null(cl);

	if (repcnt > 3 && strncmp(TEST_ENV, "test", 4) == 0)
		return;

	int err = 0;
	size_t iovcnt = 124;
	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);
	char *buf = je_malloc(iovcnt * SIMPLE_TEST_BS);
	assert_non_null(buf);

	size_t i;
	for (i = 0; i < iovcnt; i++) {
		iov[i].iov_base = buf + i * SIMPLE_TEST_BS;
		iov[i].iov_len =  SIMPLE_TEST_BS;
	}

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	ccow_lookup_t iter = NULL;
	uint8_t rc = repcnt;
	err = ccow_attr_modify_default(c, CCOW_ATTR_REPLICATION_COUNT, (void *)&rc, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, oid, &iov[0], iovcnt, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	if (iter)
		ccow_lookup_release(iter);
	je_free(buf);
	je_free(iov);
}
#define put_0_120(_rc, _oid) \
	static void simple_put_0_120 ## _##_rc (void **state) { \
		simple_put_0_120(_rc, _oid, state); \
	}
put_0_120(1, SIMPLE_TEST_OID_RC1)
put_0_120(2, SIMPLE_TEST_OID_RC2)
put_0_120(3, SIMPLE_TEST_OID_RC3)
put_0_120(4, SIMPLE_TEST_OID_RC4)

char randobj[256];

void
get_iter_sz(ccow_lookup_t iter, uint64_t *psz, uint64_t *sz)
{
	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_ALL, pos++))) {
		if (kv->type == CCOW_KVTYPE_UINT64) {
			if (strcmp(kv->key, RT_SYSKEY_PREV_LOGICAL_SIZE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, psz);
			} else if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
				ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, sz);
			}
		}
	}
	assert_null(kv);
}


static void
write_rand_obj(void **state, char *buf, int len, uint64_t pexpected, uint64_t expected)
{
	ccow_completion_t c;
	struct iovec iov[1];
	ccow_lookup_t iter0, iter;
	uint64_t genid, psz, sz;
	int err;

	assert_non_null(cl);

	printf("write_rnd_obj : %s  len: %d\n", randobj, len);


	iov[0].iov_len = len;
	iov[0].iov_base = buf;

	genid = 0;
	psz = sz = (uint64_t)-1;
	/* always sync, will wait */
	err = ccow_create_stream_completion(cl, NULL, NULL, 1, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    randobj, strlen(randobj) + 1, &genid, NULL, &iter0);
	assert_int_equal(err, 0);
	get_iter_sz(iter0, &psz, &sz);

	err = ccow_put_cont(c, &iov[0], 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	/* always sync, will wait */
	err = ccow_finalize(c, &iter);
	assert_int_equal(err, 0);
	//dump_iter_to_stdout(iter, CCOW_MDTYPE_METADATA | CCOW_MDTYPE_CUSTOM);
	get_iter_sz(iter, &psz, &sz);
	if ((sz != expected) || (psz != pexpected))
		printf("%s: size: %lu == expected: %lu\t"
		    "prev-size: %lu == prev-expected: %lu\n", __func__,
		    sz, expected,
		    psz, pexpected);
	assert_int_equal(sz, expected);
	assert_int_equal(psz, pexpected);
	ccow_lookup_release(iter);
}

static void
create_rand_obj_zero_sz(void **state)
{
	write_rand_obj(state, /* As RO buffer. */randobj, 0, 0, 0);
}

static void
write_rand_obj_1st_time(void **state)
{
	write_rand_obj(state, /* As RO buffer. */randobj, 256, 0, 256);
}

static void
write_rand_obj_2nd_time(void **state)
{
	write_rand_obj(state, /* As RO buffer. */randobj, 256, 256, 256);
}

static void
write_rand_obj_3rd_time(void **state)
{
	write_rand_obj(state, /* As RO buffer. */randobj, 256, 256, 256);
}

static void
write_rand_obj_4th_time(void **state)
{
	write_rand_obj(state, /* As RO buffer. */randobj, 256, 256, 256);
}

static void
write_rand_obj_5th_time(void **state)
{
	write_rand_obj(state, /* As RO buffer. */randobj, 256, 256, 256);
}

static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_CONT, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_RC1, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_RC2, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_RC3, NULL, NULL);

	if (strncmp(TEST_ENV, "test", 4) == 0)
		return;
	delete(cl, TEST_BUCKET_NAME, SIMPLE_TEST_OID_RC4, NULL, NULL);

	delete(cl, TEST_BUCKET_NAME, randobj, NULL, NULL);
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

static void
simple_mod_guid(void **state) {
	assert_non_null(cl);
	int err;

	ccow_lookup_t iter;
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	err = ccow_admin_pseudo_get("", 1, "", 1, "", 1, "", 1, NULL, 0, 0,
	    CCOW_GET, c, &iter);
	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	char key[] = "X-system-guid";
	char value[] = "OMG-NEW-GUID";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, key, 14,
	    value, 13, NULL);
	assert_int_equal(err, -EPERM);
	ccow_admin_pseudo_put("", 1, "", 1, "", 1, "", 1, NULL, 0, 0,
	    CCOW_PUT, NULL, c);

	err = ccow_wait(c, 1);
	assert_int_equal(err, 0);
	if (iter)
		ccow_lookup_release(iter);
}

int
main(int argc, char **argv)
{
	if (argc == 2) {
		if (strcmp(argv[1], "-n") == 0)
			dd = 1;
	}
	TEST_ENV = getenv("NEDGE_ENV");
	if (!TEST_ENV)
		TEST_ENV = "production";

	snprintf(randobj, 254, "simple-test-rand-obj-%u", (uint32_t)time(NULL));
	randobj[255] = '\0';

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(simple_put_0_4k),
		unit_test(simple_put_chunk_0_4k),
		unit_test(simple_put_stream_0_4k),
		unit_test(simple_put_stream_0_4k_async),
		unit_test(simple_put_0_120_1),
		unit_test(simple_put_0_120_2),
		unit_test(simple_put_0_120_3),
		unit_test(simple_put_0_120_4),
		unit_test(simple_mod_guid),
		unit_test(create_rand_obj_zero_sz),
		unit_test(write_rand_obj_1st_time),
		unit_test(write_rand_obj_2nd_time),
		unit_test(write_rand_obj_3rd_time),
		unit_test(write_rand_obj_4th_time),
		unit_test(write_rand_obj_5th_time),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

