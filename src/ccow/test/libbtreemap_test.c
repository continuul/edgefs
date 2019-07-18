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
ccow_t cl = NULL;

char *LBTM_TEST_BT_OID_1 =		"lbtm-test-btree_1";
char *LBTM_TEST_BT_OID_2 =		"lbtm-test-btree_2";
char *LBTM_TEST_BT_OID_3 =		"lbtm-test-btree_3";
char *LBTM_TEST_BT_OID_4 =		"lbtm-test-btree_4";
char *LBTM_TEST_BT_OID_5 =		"lbtm-test-btree_5";
char *LBTM_TEST_BT_OID_6 =		"lbtm-test-btree_6";
char *LBTM_TEST_BT_OID_7 =		"lbtm-test-btree_7";
char *oid = NULL;

int dd = 0;

#define LBTM_TEST_BTREE_ORDER		4

static void
btmt_get(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
	 size_t off, ccow_callback_t cb_async, void *arg, ccow_lookup_t *iter,
	 int expected)
{
	assert_non_null(cl);
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

	uint16_t order = LBTM_TEST_BTREE_ORDER;
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
	assert_non_null(cl);
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

	uint16_t order = LBTM_TEST_BTREE_ORDER;
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
 *		LBTM Test
 * =======================================================================
 */

static void
libbtreemap_noop(void **state)
{
	usleep(2 * 1000000L);
}

#define BTMT_DEF_SETUP(_oid)						\
static void								\
libbtreemap_setup_##_oid(void **state)					\
{									\
	assert_non_null(cl);						\
	ccow_completion_t c;						\
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);	\
	if (err != 0) {							\
		printf("ccow_create_completion returned error %d \n",	\
		    err);						\
	}								\
	assert_int_equal(err, 0);					\
									\
	char *chunkmap_type = "btree_map";				\
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,	\
	    (void *)chunkmap_type, NULL);				\
	if (err != 0) {							\
		printf("ccow_ccow_attr_modify_default"			\
		    "returned error %d \n", err);			\
	}								\
	assert_int_equal(err, 0);					\
									\
	uint16_t order = LBTM_TEST_BTREE_ORDER;				\
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,	\
		(void *)&order, NULL);					\
	if (err != 0) {							\
		printf("ccow_ccow_attr_modify_default"			\
		    "returned error %d \n", err);			\
	}								\
	assert_int_equal(err, 0);					\
									\
	oid = LBTM_TEST_BT_OID_##_oid;					\
									\
	static struct cminfo cmi;					\
	cmi.comp = c;							\
	strcpy(cmi.oid, oid);						\
									\
	*state = &cmi;							\
}

BTMT_DEF_SETUP(1)
BTMT_DEF_SETUP(2)
BTMT_DEF_SETUP(3)
BTMT_DEF_SETUP(4)
BTMT_DEF_SETUP(5)
BTMT_DEF_SETUP(6)
BTMT_DEF_SETUP(7)

static void
libbtreemap_teardown(void **state)
{
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
    if(!dd)
        ccow_daemon_term();
}

// ============================================================================
//		put test cases
// ============================================================================

#define BTMT_DEF_PUT(_offset, _size, _count)				\
static void								\
libbtreemap_put_##_offset##_##_size##_##_count(void **state)		\
{									\
	assert_non_null(cl);						\
	struct cminfo *cmi = *state;					\
	int i;								\
									\
	char buffer[_size * _count];					\
	memset(buffer, 0, _size * _count);				\
									\
	size_t iovcnt = _count;						\
	struct iovec *iov = je_calloc(iovcnt,				\
	    sizeof (struct iovec));					\
	assert_non_null(iov);						\
									\
	for (i = 0; i < _count; i++) {					\
		char *ptr = &buffer[i * _size];				\
									\
		sprintf(ptr, "%6.6d: %6.6d: %6.6d: byte me world.",	\
		    (_offset + (i * _size)), _size , _count);		\
									\
		iov[i].iov_base = ptr;					\
		iov[i].iov_len  = _size;				\
	}								\
									\
	uint64_t offset = _offset;					\
									\
	btmt_put(cl, TEST_BUCKET_NAME, oid, iov, iovcnt,		\
	    offset, NULL, NULL);					\
	je_free(iov);							\
}

BTMT_DEF_PUT(    0, 1024, 1)
BTMT_DEF_PUT(    0, 1024, 8)
BTMT_DEF_PUT( 1024, 1024, 1)
BTMT_DEF_PUT( 2048, 1024, 1)
BTMT_DEF_PUT( 3072, 1024, 1)
BTMT_DEF_PUT( 4096, 1024, 1)
BTMT_DEF_PUT( 5120, 1024, 1)
BTMT_DEF_PUT( 6144, 1024, 1)
BTMT_DEF_PUT( 7168, 1024, 1)
BTMT_DEF_PUT( 8192, 1024, 1)
BTMT_DEF_PUT( 9216, 1024, 1)
BTMT_DEF_PUT(10240, 1024, 1)
BTMT_DEF_PUT(    0, 4096, 1)
BTMT_DEF_PUT(    0, 4096, 64)
BTMT_DEF_PUT( 4096, 4096, 1)
BTMT_DEF_PUT( 8192, 4096, 1)
BTMT_DEF_PUT(12276, 4096, 1)
BTMT_DEF_PUT(16368, 4096, 1)
BTMT_DEF_PUT(20460, 4096, 1)
BTMT_DEF_PUT(24552, 4096, 1)
BTMT_DEF_PUT(28644, 4096, 1)
BTMT_DEF_PUT(32736, 4096, 1)
BTMT_DEF_PUT(36828, 4096, 1)
BTMT_DEF_PUT(40960, 4096, 1)

// ============================================================================
//		get test cases
// ============================================================================

#define BTMT_DEF_GET(_offset, _size, _count, _exp_count,		\
    _exp_data_cmp_err)							\
static void								\
libbtreemap_get_##_offset##_##_size##_##_count##_##_exp_count##_##_exp_data_cmp_err \
	(void **state)							\
{									\
	assert_non_null(cl);						\
	struct cminfo *cmi = *state;					\
	int i;								\
									\
	char buffer[_size * _count];					\
	memset(buffer, 0, _size * _count);				\
									\
	size_t iovcnt = _count;						\
	struct iovec *iov = je_calloc(iovcnt,				\
	    sizeof (struct iovec));					\
	assert_non_null(iov);						\
									\
	for (i = 0; i < _count; i++) {					\
		iov[i].iov_base = &buffer[i * _size];			\
		iov[i].iov_len  = _size;				\
	}								\
									\
	uint64_t offset = _offset;					\
									\
	btmt_get(cl, TEST_BUCKET_NAME, oid, iov, iovcnt,		\
	        offset, NULL, NULL, NULL, 0);				\
									\
	char tmp[_size];						\
									\
	for (i = 0; i < _count; i++) {					\
		sprintf(tmp, "%6.6d: %6.6d: %6.6d: byte me world.",	\
		    (_offset + (_size * i)),				\
		    _size, _exp_count);					\
									\
		char * ptr = &buffer[i * _size];			\
									\
		int rv = strcmp(ptr, tmp);				\
									\
		if ((rv != 0) && !( _exp_data_cmp_err)) {		\
			printf("data verification error \n"		\
			    "    wrote: \"%s\" \n"			\
			    "    read:  \"%s\" \n",			\
			    tmp, ptr);					\
			assert_int_equal(rv, 0);			\
		}							\
									\
		if ((rv == 0) && (_exp_data_cmp_err)) {			\
			printf("expected data verification error \n"	\
			    "    wrote: \"%s\" \n"			\
			    "    read:  \"%s\" \n",			\
			    tmp, ptr);					\
			assert_int_not_equal(rv, 0);			\
		}							\
									\
		if (_exp_data_cmp_err) {				\
			break;						\
		}							\
	}								\
	je_free(iov);							\
}

BTMT_DEF_GET(    0, 1024,  1,  1, 0)
BTMT_DEF_GET(    0, 1024,  1,  8, 0)
BTMT_DEF_GET(    0, 1024,  4,  4, 0)
BTMT_DEF_GET( 1024, 1024,  1,  8, 0)
BTMT_DEF_GET( 2048, 1024,  1,  8, 0)
BTMT_DEF_GET( 3072, 1024,  1,  8, 0)
BTMT_DEF_GET( 4096, 1024,  1,  8, 0)
BTMT_DEF_GET( 5120, 1024,  1,  8, 0)
BTMT_DEF_GET( 6144, 1024,  1,  8, 0)
BTMT_DEF_GET( 7168, 1024,  1,  8, 0)
BTMT_DEF_GET(    0, 1024,  4,  1, 0)
BTMT_DEF_GET(    0, 1024,  4,  1, 1)
BTMT_DEF_GET(    0, 1024,  8,  8, 0)
BTMT_DEF_GET( 1024, 1024,  1,  1, 0)
BTMT_DEF_GET( 2048, 1024,  1,  1, 0)
BTMT_DEF_GET( 3072, 1024,  1,  1, 0)
BTMT_DEF_GET( 4096, 1024,  1,  1, 0)
BTMT_DEF_GET( 5120, 1024,  1,  1, 0)
BTMT_DEF_GET( 6144, 1024,  1,  1, 0)
BTMT_DEF_GET( 7168, 1024,  1,  1, 0)
BTMT_DEF_GET( 8192, 1024,  1,  1, 0)
BTMT_DEF_GET( 9216, 1024,  1,  1, 0)
BTMT_DEF_GET(10240, 1024,  1,  1, 0)
BTMT_DEF_GET(    0, 4096,  1,  1, 0)
BTMT_DEF_GET(    0, 4096,  1, 64, 0)
BTMT_DEF_GET(    0, 4096, 64, 64, 0)
BTMT_DEF_GET( 4096, 4096,  1,  1, 0)
BTMT_DEF_GET( 4096, 4096,  1, 64, 0)
BTMT_DEF_GET( 8192, 4096,  1,  1, 0)
BTMT_DEF_GET( 8192, 4096,  1, 64, 0)
BTMT_DEF_GET(12276, 4096,  1,  1, 0)
BTMT_DEF_GET(16368, 4096,  1,  1, 0)
BTMT_DEF_GET(20460, 4096,  1,  1, 0)
BTMT_DEF_GET(24552, 4096,  1,  1, 0)
BTMT_DEF_GET(28644, 4096,  1,  1, 0)
BTMT_DEF_GET(32736, 4096,  1,  1, 0)
BTMT_DEF_GET(36828, 4096,  1,  1, 0)
BTMT_DEF_GET(40960, 4096,  1,  1, 0)

// ============================================================================
//
// ============================================================================
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

		// oid = 1
		unit_test_setup(libbtreemap_noop, libbtreemap_setup_1),

		// offset = 0 : size = 1K : count = 1
		unit_test(libbtreemap_put_0_1024_1),
		// offset = 1K : size = 1K : count = 1
		unit_test(libbtreemap_put_1024_1024_1),
		unit_test(libbtreemap_put_2048_1024_1),
		unit_test(libbtreemap_put_3072_1024_1),
		unit_test(libbtreemap_put_4096_1024_1),
		unit_test(libbtreemap_put_5120_1024_1),
		unit_test(libbtreemap_put_6144_1024_1),
		unit_test(libbtreemap_put_7168_1024_1),

		unit_test(libbtreemap_put_8192_1024_1),
		unit_test(libbtreemap_put_9216_1024_1),
		unit_test(libbtreemap_put_10240_1024_1),

		unit_test(libbtreemap_get_0_1024_1_1_0),
		unit_test(libbtreemap_get_1024_1024_1_1_0),
		unit_test(libbtreemap_get_2048_1024_1_1_0),
		unit_test(libbtreemap_get_3072_1024_1_1_0),
		unit_test(libbtreemap_get_4096_1024_1_1_0),
		unit_test(libbtreemap_get_5120_1024_1_1_0),
		unit_test(libbtreemap_get_6144_1024_1_1_0),
		unit_test(libbtreemap_get_7168_1024_1_1_0),
		unit_test(libbtreemap_get_8192_1024_1_1_0),
		unit_test(libbtreemap_get_9216_1024_1_1_0),
		unit_test(libbtreemap_get_10240_1024_1_1_0),

		unit_test_teardown(libbtreemap_noop, libbtreemap_teardown),

		unit_test_setup(libbtreemap_noop, libbtreemap_setup_2),
		unit_test(libbtreemap_put_0_4096_1),

		unit_test(libbtreemap_put_4096_4096_1),
		unit_test(libbtreemap_put_8192_4096_1),
		unit_test(libbtreemap_put_12276_4096_1),
		unit_test(libbtreemap_put_16368_4096_1),
		unit_test(libbtreemap_put_20460_4096_1),
		unit_test(libbtreemap_put_24552_4096_1),
		unit_test(libbtreemap_put_28644_4096_1),
		unit_test(libbtreemap_put_32736_4096_1),
		unit_test(libbtreemap_put_36828_4096_1),
		unit_test(libbtreemap_put_40960_4096_1),

		unit_test(libbtreemap_get_0_4096_1_1_0),
		unit_test(libbtreemap_get_4096_4096_1_1_0),
		unit_test(libbtreemap_get_8192_4096_1_1_0),
		unit_test(libbtreemap_get_12276_4096_1_1_0),
		unit_test(libbtreemap_get_16368_4096_1_1_0),
		unit_test(libbtreemap_get_20460_4096_1_1_0),
		unit_test(libbtreemap_get_24552_4096_1_1_0),
		unit_test(libbtreemap_get_28644_4096_1_1_0),
		unit_test(libbtreemap_get_32736_4096_1_1_0),
		unit_test(libbtreemap_get_36828_4096_1_1_0),
		unit_test(libbtreemap_get_40960_4096_1_1_0),

		unit_test_teardown(libbtreemap_noop, libbtreemap_teardown),

		unit_test_setup(libbtreemap_noop, libbtreemap_setup_3),

		unit_test(libbtreemap_put_0_1024_1),
		unit_test(libbtreemap_put_1024_1024_1),
		unit_test(libbtreemap_put_2048_1024_1),
		unit_test(libbtreemap_put_3072_1024_1),
		unit_test(libbtreemap_get_0_1024_4_1_0),

		unit_test_teardown(libbtreemap_noop, libbtreemap_teardown),

		unit_test_setup(libbtreemap_noop, libbtreemap_setup_4),

		unit_test(libbtreemap_put_0_4096_64),
		//		unit_test(libbtreemap_get_0_4096_64_64_0),
		unit_test(libbtreemap_get_0_4096_1_64_0),
		unit_test(libbtreemap_get_4096_4096_1_64_0),
		//		unit_test(libbtreemap_get_8192_4096_1_64_0),

		unit_test_teardown(libbtreemap_noop, libbtreemap_teardown),

		unit_test_setup(libbtreemap_noop, libbtreemap_setup_5),

		unit_test(libbtreemap_put_0_1024_8),
		unit_test(libbtreemap_get_0_1024_8_8_0),
		unit_test(libbtreemap_get_0_1024_1_8_0),
		unit_test(libbtreemap_get_1024_1024_1_8_0),
		unit_test(libbtreemap_get_2048_1024_1_8_0),
		unit_test(libbtreemap_get_3072_1024_1_8_0),
		unit_test(libbtreemap_get_4096_1024_1_8_0),
		unit_test(libbtreemap_get_5120_1024_1_8_0),
		unit_test(libbtreemap_get_6144_1024_1_8_0),
		unit_test(libbtreemap_get_7168_1024_1_8_0),

		unit_test_teardown(libbtreemap_noop, libbtreemap_teardown),

		unit_test_setup(libbtreemap_noop, libbtreemap_setup_6),

		//		unit_test(libbtreemap_put_0_1024_1),
		unit_test(libbtreemap_put_1024_1024_1),
		//		unit_test(libbtreemap_put_2048_1024_1),
		unit_test(libbtreemap_put_3072_1024_1),
		unit_test(libbtreemap_get_0_1024_4_1_1),

		unit_test_teardown(libbtreemap_noop, libbtreemap_teardown),

		//		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
