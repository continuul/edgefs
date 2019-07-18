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

#define TEST_BUCKET_NAME		"libbtreenam-bucket-test"
ccow_t cl = NULL;

#define LBTN_TEST_BT_OID		"lbtn-test-btree"
#define LBTN_TEST_BTREE_ORDER		4

// ============================================================================
//
// ============================================================================
#define TEST2_BUCKET_NAME		"libbtreenam-bucket-test2"
#define LBTN_TEST2_BT_OID		"lbtn-test2-btree"
#define LBTN_TEST2_BTREE_ORDER		32

char *test_bucket_name = NULL;
char *lbtn_test_bt_oid = NULL;

int dd = 0;
int c_flags = 0;

typedef int err_t;

static void
btnt_get(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
    uint64_t off, ccow_callback_t cb_async, void *arg, ccow_lookup_t *iter,
    err_t exp[], size_t count)
{
	assert_non_null(cl);
	int err;
	int i;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_key_val";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *) chunkmap_type, NULL);
	assert_int_equal(err, 0);

	uint16_t order = LBTN_TEST_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *)&order, NULL);
	assert_int_equal(err, 0);

	err = ccow_get_list(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov,
	    iovcnt, count, iter);
	assert_int_equal(err, 0);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);

	for (i = 0; i < (int) count; i++) {
		if (err == exp[i])
			break;
	}

	if (i == (int) count) {
		printf("err = %d \n", err);
		assert_true(0);
	}
}

static void
btnt_get_key(void **state, char *key, err_t expected[], size_t count)
{
	assert_non_null(cl);
	int err = 0;
	size_t iovcnt = 1;
	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);
	char *buf = je_malloc(16384);
	assert_non_null(buf);

	struct cminfo *cmi_ptr = *state;

	size_t i;
	for (i = 0; i < iovcnt; i++) {
		iov[i].iov_base = key;
		iov[i].iov_len  = strlen(key);
	}

	btnt_get(cl, test_bucket_name, cmi_ptr->oid, iov, iovcnt, 0,
			NULL, NULL, NULL, expected, count);

	je_free(buf);
	je_free(iov);
}

void
btnt_insert_list(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
	 ccow_callback_t cb_async, void *arg, err_t exp[], size_t count)
{
	assert_non_null(cl);
	int err;
	int i;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
	assert_int_equal(err, 0);

	ccow_stream_flags(c, &c_flags);

	char *chunkmap_type = "btree_key_val";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *) chunkmap_type, NULL);
	assert_int_equal(err, 0);

	uint16_t order = LBTN_TEST_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *)&order, NULL);
	assert_int_equal(err, 0);

	err = ccow_insert_list(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c,
	    iov, iovcnt);
	assert_int_equal(err, 0);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);

	for (i = 0; i < (int) count; i++) {
		if (err == exp[i])
			break;
	}

	if (i == (int) count) {
		printf("err = %d \n", err);
		assert_true(0);
	}
}

static void
btnt_insert_key(void **state, char *key, err_t exp[], size_t count)
{
	assert_non_null(cl);
	int err = 0;
	size_t iovcnt = 1;
	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);
	char *buf = je_malloc(16384);
	assert_non_null(buf);

	struct cminfo *cmi_ptr = *state;

	size_t i;
	for (i = 0; i < iovcnt; i++) {
		iov[i].iov_base = key;
		iov[i].iov_len  = strlen(key);
	}

	btnt_insert_list(cl, test_bucket_name, cmi_ptr->oid, iov, iovcnt,
	    NULL, NULL, exp, count);

	je_free(buf);
	je_free(iov);
}

static void
btnt_delete_list(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
uint64_t off, ccow_callback_t cb_async, void *arg, err_t exp[], size_t count)
{
	assert_non_null(cl);
	int err, i;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_key_val";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *) chunkmap_type, NULL);
	assert_int_equal(err, 0);

	uint16_t order = LBTN_TEST_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *)&order, NULL);
	assert_int_equal(err, 0);

	err = ccow_delete_list(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c,
	    iov, iovcnt);
	assert_int_equal(err, 0);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);

	for (i = 0; i < (int) count; i++) {
		if (err == exp[i])
			break;
	}

	if (i == (int) count) {
		printf("error %d not in {", err);
		for (i = 0; i < (int) count; i++) {
			if (i != 0) {
				printf(", ");
			}
			printf("%d", exp[i]);
		}
		printf("}\n");
		assert_true(0);
	}
}

static void
btnt_delete_key(void **state, char *key, err_t exp[], size_t count)
{
	assert_non_null(cl);
	int err = 0;
	size_t iovcnt = 1;
	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);
	char *buf = je_malloc(16384);
	assert_non_null(buf);

	struct cminfo *cmi_ptr = *state;

	size_t i;
	for (i = 0; i < iovcnt; i++) {
		iov[i].iov_base = key;
		iov[i].iov_len  = strlen(key);
	}

	btnt_delete_list(cl, test_bucket_name, cmi_ptr->oid, iov, iovcnt, 0,
	    NULL, NULL, exp, count);

	je_free(buf);
	je_free(iov);
}

#if 0
static void
btnt_get_list(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
    uint64_t off, ccow_callback_t cb_async, void *arg, ccow_lookup_t *iter,
    err_t exp[], size_t count)
{
	int err, i;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_key_val";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *) chunkmap_type, NULL);
	assert_int_equal(err, 0);


	uint16_t order = LBTN_TEST_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *)&order, NULL);
	assert_int_equal(err, 0);

	err = ccow_get_list(bid, oid, c, iov, iovcnt, off, iter);
	assert_int_equal(err, 0);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);

	for (i = 0; i < (int) count; i++) {
		if (err == exp[i])
			break;
	}

	if (i == (int) count) {
		printf("error %d not in {", err);
		for (i = 0; i < (int) count; i++) {
			if (i != 0) {
				printf(", ");
			}
			printf("%d", exp[i]);
		}
		printf("}\n");
		assert_true(0);
	}
}
#endif

#if 0
static void
btnt_get_keys(void **state, char *key, size_t key_count ,
	 err_t expected[], size_t count)
{
	int err = 0;
	size_t iovcnt = key_count;

	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);

	struct cminfo *cmi_ptr = *state;

	if (key != NULL) {
		iov[0].iov_base = key;
		iov[0].iov_len  = strlen(key);
	}

	btnt_get_list(cl, TEST_BUCKET_NAME, cmi_ptr->oid, iov, iovcnt, -1,
		NULL, NULL, NULL, expected, count);

	je_free(iov);
}
#endif

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
	char *buf;
	*state = buf = je_calloc(1, 16384);

	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);

	je_free(*state);
	*state = NULL;
}

static void
bucket_create(void **state)
{
	assert_non_null(cl);

	test_bucket_name = TEST_BUCKET_NAME;

	int err = ccow_bucket_create(cl, test_bucket_name,
	    strlen(test_bucket_name), NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, test_bucket_name, strlen(test_bucket_name));
	assert_int_equal(err, 0);
}

static void
bucket2_create(void **state)
{
	assert_non_null(cl);

	test_bucket_name = TEST2_BUCKET_NAME;

	int err = ccow_bucket_create(cl, test_bucket_name,
	    strlen(test_bucket_name), NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket2_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST2_BUCKET_NAME,
	    strlen(TEST2_BUCKET_NAME));
	assert_int_equal(err, 0);
}

/*
* =======================================================================
*		LBTN Test
* =======================================================================
*/

static void
libbtreenam_noop(void **state)
{
	usleep(2 * 1000000L);
}

static void
libbtreenam_setup(void **state)
{
	assert_non_null(cl);
	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_key_val";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
			(void *)chunkmap_type, NULL);
	assert_int_equal(err, 0);

	uint16_t order = LBTN_TEST_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
			(void *)&order, NULL);
	assert_int_equal(err, 0);

	static struct cminfo cmi;
	cmi.comp = c; strcpy(cmi.oid, LBTN_TEST_BT_OID);

	*state = &cmi;
}

static void
libbtreenam2_setup(void **state)
{
	assert_non_null(cl);
	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_key_val";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
			(void *)chunkmap_type, NULL);
	assert_int_equal(err, 0);

	uint16_t order = LBTN_TEST2_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
			(void *)&order, NULL);
	assert_int_equal(err, 0);

	static struct cminfo cmi;
	cmi.comp = c; strcpy(cmi.oid, LBTN_TEST2_BT_OID);

	*state = &cmi;
}

static void
libbtreenam_teardown(void **state)
{
}

/*
 *
 */

static void
libbtreenam_insert_list_zzz(void **state)
{
	c_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
	err_t exp[1] = {0};
	btnt_insert_key(state, "zzz", exp, 1);
	c_flags = 0;
}

static void
libbtreenam_insert_list_aaa(void **state)
{
	err_t exp[1] = {0};
	btnt_insert_key(state, "aaa", exp, 1);
}

static void
libbtreenam_insert_list_bbb(void **state)
{
	err_t exp[1] = {0};
	btnt_insert_key(state, "bbb", exp, 1);
}

static void
libbtreenam_insert_list_ccc(void **state)
{
	err_t exp[1] = {0};
	btnt_insert_key(state, "ccc", exp, 1);
}

static void
libbtreenam_insert_list_ddd(void **state)
{
	err_t exp[1] = {0};
	btnt_insert_key(state, "ddd", exp, 1);
}

#if 0
static void
libbtreenam_insert_list_ddd_EEXIST(void **state)
{
	err_t exp[1] = {-EEXIST};
	btnt_insert_key(state, "ddd", exp, 1);
}
#endif

static void
libbtreenam_insert_list_eee(void **state)
{
	err_t exp[1] = {0};
	btnt_insert_key(state, "eee", exp, 1);
}

static void
libbtreenam_insert_list_fff(void **state)
{
	err_t exp[1] = {0};
	btnt_insert_key(state, "fff", exp, 1);
}

static void
libbtreenam_delete_list_zzz(void **state)
{
	err_t exp[1] = {0};
	btnt_delete_key(state, "zzz", exp, 1);
}

static void
libbtreenam_delete_list_aaa(void **state)
{
	err_t exp[1] = {0};
	btnt_delete_key(state, "aaa", exp, 1);
}

static void
libbtreenam_delete_list_bbb(void **state)
{
	err_t exp[1] = {0};
	btnt_delete_key(state, "bbb", exp, 1);
}

static void
libbtreenam_delete_list_ccc(void **state)
{
	err_t exp[1] = {0};
	btnt_delete_key(state, "ccc", exp, 1);
}

static void
libbtreenam_delete_list_ddd(void **state)
{
	err_t exp[1] = {0};
	btnt_delete_key(state, "ddd", exp, 1);
}

static void
libbtreenam_delete_list_eee(void **state)
{
	err_t exp[1] = {0};
	btnt_delete_key(state, "eee", exp, 1);
}

static void
libbtreenam_delete_list_fff(void **state)
{
	err_t exp[1] = {0};
	btnt_delete_key(state, "fff", exp, 1);
}

static void
libbtreenam_delete_list_cleanup_zzz(void **state)
{
	err_t exp[3] = {0, -ENOENT, -ENOENT};
	btnt_delete_key(state, "zzz", exp, 3);
}


static void
libbtreenam_delete_list_cleanup_aaa(void **state)
{
	err_t exp[3] = {0, -ENOENT, -ENOENT};
	btnt_delete_key(state, "aaa", exp, 3);
}

static void
libbtreenam_delete_list_cleanup_bbb(void **state)
{
	err_t exp[3] = {0, -ENOENT, -ENOENT};
	btnt_delete_key(state, "bbb", exp, 3);
}

static void
libbtreenam_delete_list_cleanup_ccc(void **state)
{
	err_t exp[3] = {0, -ENOENT, -ENOENT};
	btnt_delete_key(state, "ccc", exp, 3);
}

static void
libbtreenam_delete_list_cleanup_ddd(void **state)
{
	err_t exp[3] = {0, -ENOENT, -ENOENT};
	btnt_delete_key(state, "ddd", exp, 3);
}

static void
libbtreenam_delete_list_cleanup_eee(void **state)
{
	err_t exp[3] = {0, -ENOENT, -ENOENT};
	btnt_delete_key(state, "eee", exp, 3);
}

static void
libbtreenam_delete_list_cleanup_fff(void **state)
{
	err_t exp[3] = {0, -ENOENT, -ENOENT};
	btnt_delete_key(state, "fff", exp, 3);
}

static void
libbtreenam_get_aaa(void **state)
{
	err_t exp[1] = {0};
	btnt_get_key(state, "aaa", exp, 1);
}

#if 0
static void
libbtreenam_get_abc_ENOENT(void **state)
{
	err_t exp[1] = {-ENOENT};
	btnt_get_key(state, "abc", exp, 1);
}
#endif

static void
libbtreenam_get_bbb(void **state)
{
	err_t exp[1] = {0};
	btnt_get_key(state, "bbb", exp, 1);
}

static void
libbtreenam_get_ccc(void **state)
{
err_t exp[1] = {0};
btnt_get_key(state, "ccc", exp, 1);
}

static void
libbtreenam_get_ddd(void **state)
{
	err_t exp[1] = {0};
	btnt_get_key(state, "ddd", exp, 1);
}

#if 0
static void
libbtreenam_get_first_4(void **state)
{
	err_t exp[1] = {0};
	btnt_get_keys(state, NULL, 4, exp, 1);
}
#endif

#if 0
static void
libbtreenam_get_first_5(void **state)
{
	err_t exp[1] = {0};
	btnt_get_keys(state, NULL, 5, exp, 1);
}
#endif

static void
libbtreenam_get_eee(void **state)
{
	err_t exp[1] = {0};
	btnt_get_key(state, "eee", exp, 1);
}

static void
libccow_teardown(void **state)
{
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state)
{
    if(!dd)
	    ccow_daemon_term();
}

// ============================================================================
// libbtreenam2 test suite
// ============================================================================

#define COUNT 100

static void
libbtreenam2_delete_list_cleanup_iterate(void **state)
{
	assert_non_null(cl);
	int i = 0;
	char key[10];

	printf("Deleting %d keys. \n", COUNT);

	struct timeval start;
	struct timeval end;
	struct timeval res;

	memset(key, 0 , 10);

	gettimeofday(&start, NULL);

	for (i = 0; i < COUNT; i++) {
		sprintf(key, "%5.5d", i);
		// printf("Deleting key %s \n", key);

		err_t exp[3] = {0, -ENOENT, -ENOENT};
		btnt_delete_key(state, key, exp, 3);
	}

	gettimeofday(&end, NULL);

	timersub(&end, &start, &res);

	printf("%d operations in %d.%6.6d seconds \n",
	    COUNT, (int) res.tv_sec, (int) res.tv_usec);
}

static void
libbtreenam2_insert_list_iterate(void **state)
{
	assert_non_null(cl);
	int i = 0;
	char key[10];

	printf("Inserting %d keys. \n", COUNT);

	struct timeval start;
	struct timeval end;
	struct timeval res;

	memset(key, 0 , 10);

	gettimeofday(&start, NULL);

	for (i = 0; i < COUNT; i++) {
		sprintf(key, "%5.5d", i);
		err_t exp[1] = {0};
		btnt_insert_key(state, key, exp, 1);
	}

	gettimeofday(&end, NULL);

	timersub(&end, &start, &res);

	printf("%d operations in %d.%6.6d seconds \n",
	    COUNT, (int) res.tv_sec, (int) res.tv_usec);
}

static void
libbtreenam2_get_list_iterate(void **state)
{
	assert_non_null(cl);
	int i = 0;
	char key[10];

	printf("Getting %d keys. \n", COUNT);

	struct timeval start;
	struct timeval end;
	struct timeval res;

	memset(key, 0 , 10);

	gettimeofday(&start, NULL);

	for (i = 0; i < COUNT; i++) {
		sprintf(key, "%5.5d", i);
		// printf("Getting key %s \n", key);

		err_t exp[1] = {0};
		btnt_get_key(state, key, exp, 1);
	}

	gettimeofday(&end, NULL);

	timersub(&end, &start, &res);

	printf("%d operations in %d.%6.6d seconds \n",
	    COUNT, (int) res.tv_sec, (int) res.tv_usec);
}

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

		unit_test_setup(libbtreenam_noop, libbtreenam_setup),

		unit_test(libbtreenam_delete_list_cleanup_aaa),
		unit_test(libbtreenam_delete_list_cleanup_bbb),
		unit_test(libbtreenam_delete_list_cleanup_ccc),
		unit_test(libbtreenam_delete_list_cleanup_ddd),
		unit_test(libbtreenam_delete_list_cleanup_eee),
		unit_test(libbtreenam_delete_list_cleanup_fff),
		unit_test(libbtreenam_delete_list_cleanup_zzz),

		unit_test(libbtreenam_insert_list_zzz),
		unit_test(libbtreenam_insert_list_zzz),
		unit_test(libbtreenam_delete_list_cleanup_zzz),

		unit_test(libbtreenam_insert_list_aaa),
		unit_test(libbtreenam_insert_list_bbb),
		unit_test(libbtreenam_insert_list_ccc),
		unit_test(libbtreenam_insert_list_ddd),

// TBD		unit_test(libbtreenam_get_first_4),

		unit_test(libbtreenam_insert_list_eee),
		unit_test(libbtreenam_insert_list_fff),

		unit_test(libbtreenam_get_aaa),
		unit_test(libbtreenam_get_bbb),
		unit_test(libbtreenam_get_ccc),
		unit_test(libbtreenam_get_ddd),
		unit_test(libbtreenam_get_eee),

// TBD		unit_test(libbtreenam_get_first_5),
// TBD		unit_test(libbtreenam_get_abc_ENOENT),

// TBD		unit_test(libbtreenam_insert_list_ddd_EEXIST),

		unit_test(libbtreenam_delete_list_aaa),
		unit_test(libbtreenam_delete_list_bbb),
		unit_test(libbtreenam_delete_list_ccc),
		unit_test(libbtreenam_delete_list_ddd),
		unit_test(libbtreenam_delete_list_eee),
		unit_test(libbtreenam_delete_list_fff),
		unit_test_teardown(libbtreenam_noop, libbtreenam_teardown),

		unit_test(bucket_delete),

		unit_test(bucket2_create),
		unit_test_setup(libbtreenam_noop, libbtreenam2_setup),

		unit_test(libbtreenam2_delete_list_cleanup_iterate),
		unit_test(libbtreenam2_insert_list_iterate),
		unit_test(libbtreenam2_get_list_iterate),
		unit_test(bucket2_delete),

		unit_test_teardown(libbtreenam_noop, libbtreenam_teardown),

		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};

	return run_tests(tests);
}
