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

#define TEST_BUCKET_NAME		"libbtreemap-bucket-test"

char *LBTM_TEST_BT_OID_1 =		"lbtm-test-btree_1";
char *LBTM_TEST_BT_OID_2 =		"lbtm-test-btree_2";
char *LBTM_TEST_BT_OID_3 =		"lbtm-test-btree_3";
char *LBTM_TEST_BT_OID_4 =		"lbtm-test-btree_4";
char *LBTM_TEST_BT_OID_5 =		"lbtm-test-btree_5";
char *LBTM_TEST_BT_OID_6 =		"lbtm-test-btree_6";
char *LBTM_TEST_BT_OID_7 =		"lbtm-test-btree_7";
char *oid = NULL;

int dd = 0;

uint32_t TEST_BTREE_ORDER	=  8;
uint64_t TEST_IO_COUNT		= 10;
uint32_t TEST_IOV_COUNT_MIN	=  1;
uint32_t TEST_IOV_COUNT_MAX	= 32;
uint64_t TEST_MAX_OFF		= (8 * 1024 * 1024 * 1024L);
size_t   TEST_CHUNK_SIZE	= (1 * 1024);

// ============================================================================
// usage
// ============================================================================
static void
usage(void)
{
	printf("\n"
	       "USAGE:\n"
	       "     ./btree_rand_update_test [-h] [-c io_count] [-b btree_order] \n"
	       "         [-i min:max] [-o max_offset]\n"
	       "\n"
	       "OPTIONS:\n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -n   CCOW daemon running in separate process.\n"
	       "\n"
	       "    -c   IO count, may be appended with a unit specifier\n"
	       "         of K,M, or G.\n"
	       "         (Defaults to 10.)\n"
	       "\n"
	       "    -b   Btree orderr\n"
	       "         (Defaults to 8.)\n"
	       "\n"
	       "    -i   Range of IO vector sizes.\n"
	       "         (Defaults to 1:32.)\n"
	       "\n"
	       "    -o   Maximum offset, may be appended with a unit specifier\n"
	       "         of K,M, or G.  This value will be rounded up to the\n"
	       "         next power of 2.\n"
	       "         (Defaults to 8G).\n"
	       "\n");

	exit(EXIT_SUCCESS);
}

// ============================================================================
// random for 64 bit chunk aligned offset
// ============================================================================
static uint64_t
random_off(void)
{
	uint64_t rv = 0, m = TEST_MAX_OFF - 1;
	uint32_t h = 0, l = 0, mh = 0, ml = 0;

	l = rand();
	h = rand();

	ml = (m & 0xffffffff) & l;
	mh = ((m >> 32) & 0xffffffff) & h;

	rv = mh;
	rv = (rv << 32) | ml;

	rv = (rv / TEST_CHUNK_SIZE) * TEST_CHUNK_SIZE;

	return rv;
}

// ============================================================================
// round up off to nearest power of 2
// ============================================================================
static void
roundup_off(void)
{
	uint64_t v = 1;

	while (TEST_MAX_OFF > 0) {
		TEST_MAX_OFF = TEST_MAX_OFF >> 1;
		v = v << 1;
	}

	TEST_MAX_OFF = v;
}

// ============================================================================
//
// ============================================================================
typedef struct test_ctx {
	ccow_t cl;
	ccow_completion_t comp;
} test_ctx_t;

test_ctx_t test_info;

// ============================================================================
//
// ============================================================================

static void
btmt_get(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
	 size_t off, ccow_callback_t cb_async, void *arg, ccow_lookup_t *iter,
	 int expected)
{
	assert_non_null(test_info.cl);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);

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

	uint16_t order = TEST_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *)&order, NULL);

	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	err = ccow_get(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov,
	    iovcnt, off, iter);

	if (err != 0) {
		printf("ccow_get returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);

	if (err != expected) {
		printf("ccow_wait returned error status %d \n", err);
	}
	assert_int_equal(err, expected);
}

void
btmt_put(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
	uint64_t off, ccow_callback_t cb_async, void *arg)
{
	assert_non_null(test_info.cl);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
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

	uint16_t order = TEST_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		(void *)&order, NULL);
	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	err = ccow_put(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov,
	    iovcnt, off);
	if (err != 0) {
		printf("ccow_put returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);
	if (err != 0) {
		printf("ccow_wait returned error status %d \n", err);
	}
	assert_int_equal(err, 0);
}

static void
libccowd_setup(void **state)
{
    if (!dd) {
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
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &test_info.cl), 0);
	je_free(buf);
}

static void
bucket_create(void **state)
{
	assert_non_null(test_info.cl);
	int err = ccow_bucket_create(test_info.cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(test_info.cl);
	int err = ccow_bucket_delete(test_info.cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *		LBTM Test
 * =======================================================================
 */

static void
libbtreemap_noop(void **state)
{
	usleep(2 * 1000000L);
}

static void
libbtreemap_teardown(void **state)
{
}

static void
libccow_teardown(void **state)
{
	assert_non_null(test_info.cl);
	ccow_tenant_term(test_info.cl);
}

static void
libccowd_teardown(void **state) {
    if(!dd)
        ccow_daemon_term();
}

// ============================================================================
//
// ============================================================================

static void
test_001_ccowd_setup(void **state)
{
    if(!dd){
        assert_int_equal(ccow_daemon_init(NULL), 0);
        usleep(2 * 1000000L);
    }

    memset(&test_info, 0, sizeof(test_info));
}

static void
test_001_ccow_setup(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &test_info.cl), 0);
	je_free(buf);
}

static void
test_001_bucket_create(void **state)
{
	assert_non_null(test_info.cl);
	int err = ccow_bucket_create(test_info.cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}


void test_001_setup(void ** state)
{
	*state = &test_info;
}

void test_001_io(void ** state)
{
	int err = 0;

	char * buffer = je_calloc(1, TEST_CHUNK_SIZE);
	assert_non_null(buffer);

	size_t iovcnt = (TEST_IOV_COUNT_MAX - TEST_IOV_COUNT_MIN) + 1;
	iovcnt = (rand() % iovcnt) + TEST_IOV_COUNT_MIN;

	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);

	iov[0].iov_base = buffer;
	iov[0].iov_len = TEST_CHUNK_SIZE;

	uint64_t off = random_off();

	btmt_put(test_info.cl, TEST_BUCKET_NAME, LBTM_TEST_BT_OID_1,
	    iov, iovcnt, off, NULL, NULL);

	je_free(buffer);
	je_free(iov);
}

void test_001(void ** state)
{
	for (uint64_t i = 0; i < TEST_IO_COUNT; i++) {
		if (i % 1024 == 0) {
			printf("%"PRIu64"\n", i);
		}
		test_001_io(state);
	}
}

// ============================================================================
//
// ============================================================================
int
main(int argc, char **argv)
{
	/*
	 * parse command line options
	 */
	int opt;
	char *t1, *t2, str[132];

	//srand (time(NULL));
	srand(0);

	while ((opt = getopt(argc, argv, "hnc:b:i:vo:")) != -1) {
		switch(opt) {

		case 'h':
			usage();
			break;

		case 'n':
			dd = 1;
			break;

		case 'c':
			TEST_IO_COUNT = sst_convert_bytes(optarg);
			break;

		case 'b':
			TEST_BTREE_ORDER = atoi(optarg);
			break;

		case 'i':
			strcpy(str, optarg);

			char *sp;
			t1 = strtok_r(str, ":", &sp);

			if (strcmp(t1, optarg) == 0) {
			    printf("Error: optarg must be in form of \"min:max\" \n");
			    usage();
			}

			t2 =  strtok_r(NULL, ":", &sp);

			TEST_IOV_COUNT_MIN = atoi(t1);
			TEST_IOV_COUNT_MAX = atoi(t2);
			break;

		case 'o':
			TEST_MAX_OFF = sst_convert_bytes(optarg);;
			roundup_off();
			break;

		default:
			usage();
			break;
		}
	}

	const UnitTest tests[] = {

		unit_test(test_001_ccowd_setup),
		unit_test(test_001_ccow_setup),
		unit_test(test_001_bucket_create),
		unit_test_setup(libbtreemap_noop, test_001_setup),
		unit_test(test_001),
		unit_test_teardown(libbtreemap_noop, libbtreemap_teardown),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
