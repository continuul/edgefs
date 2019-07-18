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
#include "ccow-impl.h"
#include "ccowd.h"

#define TEST_BUCKET_NAME	"test-bucket"
#define TEST_OBJECT_NAME	"update-test-object"
#define TEST_NUM_THREADS	10
#define TEST_NUM_ITERS		5
#define MAX_OBJ_SZ		128

#define TEST_NUM_BUCKETS	128

#define TEST_OBJECT_BTREE_NAME "test-object-btree"
#define DIR_OBJECT		 "dir-object"
#define ENTRY_SIZE (3 *(sizeof(struct refentry)))

ccow_t tc = NULL;
int dd = 0, daemon_initialized = 0;
char *buf = NULL;

struct thread_context {
	int thread_no;
	ccow_op_t optype;
    char *oid;
    int oid_size;
};

struct thread_context t_ctx[TEST_NUM_THREADS];
uv_thread_t client_contexts_threads[TEST_NUM_THREADS];

static void
libccowd_setup(void **state)
{
	if(!dd){
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(2 * 1000000L);
	}
	daemon_initialized = 1;
}

static void
libccow_setup(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	*state = buf = je_calloc(1, 16384);

	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);

	je_free(*state);
	buf = *state = NULL;
}

static void
libccow_teardown(void **state)
{
	if (buf)
		je_free(buf);
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state) {
	usleep(200000L);
	if (dd != 1) {
		assert_int_equal(daemon_initialized, 1);
		ccow_daemon_term();
	}
	daemon_initialized = 0;
}

static void
bucket_create(void **state)
{
	assert_non_null(tc);

	int err = ccow_bucket_create(tc, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);

	if (err != 0) {
		printf("ccow_bucket_create returned error %d. \n", err);
		assert_int_equal(err, 0);
	}
}

static void
bucket_delete(void **state)
{
	assert_non_null(tc);

	int err = ccow_bucket_delete(tc, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);

	if (err != 0) {
		printf("ccow_bucket_delete returned error %d. \n", err);
		assert_int_equal(err, 0);
	}
}

static void
object_create(void **state)
{
	assert_non_null(tc);
	int err;
	ccow_completion_t c;
	struct iovec iov;
	iov.iov_len = 1;
	iov.iov_base = "";

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE, (void *)"btree_key_val", NULL);

	put_simple(c, TEST_BUCKET_NAME, TEST_OBJECT_BTREE_NAME, &iov, 0, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	ccow_completion_t c1;
	ccow_lookup_t iter;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c1);
	assert_int_equal(err, 0);

	char buf[65536];
	struct iovec _get_iov = { .iov_base = buf };
	memcpy(_get_iov.iov_base, "", 0);
	_get_iov.iov_len = 0;

	err = ccow_get_list(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1, "",  1, c1, &_get_iov, 1, 10000, &iter);
	assert_int_equal(err, 0);
	err = ccow_wait(c1, -1);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
	ccow_lookup_release(iter);
}

static void
dir_create(void **state)
{
	assert_non_null(tc);
	int err;
	ccow_completion_t c;
	uint16_t num_vers, order;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
					RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX,
					NULL);
	assert_int_equal(err, 0);
	num_vers = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
					&num_vers, NULL);
	assert_int_equal(err, 0);
	order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_1K;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
					&order, NULL);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, DIR_OBJECT, NULL, 0, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
}

static void
object_delete(void **state)
{
    assert_non_null(tc);
    delete(tc, TEST_BUCKET_NAME, TEST_OBJECT_BTREE_NAME, NULL, NULL);
}

int
get_objs_nr(char *oid, int oid_size)
{
	int err;
	ccow_lookup_t iter = NULL;
	ccow_completion_t c;
	int count = 0;
	/* Pattern name */
	struct iovec iov = { .iov_base = "", .iov_len = 1 };
	struct ccow_metadata_kv *kv = NULL;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_get_list(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			    oid, oid_size, c, &iov, 1, TEST_NUM_THREADS * TEST_NUM_ITERS,
			    &iter);

	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	if (err != 0) {
		if (iter)
			ccow_lookup_release(iter);
		printf("ccow_get_list wait err: %d\n", err);
		return err == -ENOENT ? 0 : -1;
	}
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, count++)));
	if (iter)
		ccow_lookup_release(iter);
	// count increments in the final case where lookup_iter returns kv=NULL
	if (count != 0)
		count--;
	return count;
}

static void
send_update_list(void *arg)
{
	struct thread_context *tctx = (struct thread_context *)arg;
	int thr_id = tctx->thread_no;
	int err;
	char obj1[MAX_OBJ_SZ];
	ccow_completion_t c;
	struct iovec iov;

	for (int i = 0; i < TEST_NUM_ITERS; i++) {

		sprintf(obj1, "%s-%d-%d-1", TEST_OBJECT_NAME, thr_id, i);
		iov.iov_base = obj1;
		iov.iov_len = strlen(obj1) + 1;

		err = ccow_create_completion(tc, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		err = ccow_container_update_list(tc->cid, tc->cid_size, tc->tid,
						 tc->tid_size, TEST_BUCKET_NAME,
						 strlen(TEST_BUCKET_NAME) + 1,
						 tctx->oid, tctx->oid_size, c, &iov, 1,
						 tctx->optype);
		assert_int_equal(err, 0);

		err = ccow_wait(c, -1);
		if (err != 0) {
			printf("ccow_container_update_list optype %d error: %d\n",
				tctx->optype, err);
			break;
		}
		assert_int_equal(err, 0);
	}
}

static void
test_delete_list(char *oid, int oid_size)
{
	printf("Objs = %d\n", get_objs_nr(oid, oid_size));
	for (int i = 0; i < TEST_NUM_THREADS; i++) {
		t_ctx[i].thread_no = i;
		t_ctx[i].optype = CCOW_DELETE_LIST;
        t_ctx[i].oid = oid;
        t_ctx[i].oid_size = oid_size;
		uv_thread_create(&client_contexts_threads[i],
			       (void *)&send_update_list, (void *)&t_ctx[i]);
		usleep(100000);
	}
	for (int i = 0; i < TEST_NUM_THREADS; i++)
		uv_thread_join(&client_contexts_threads[i]);

	int expected_objs = 0;
	usleep(5000000);
	int actual_objs = get_objs_nr(oid, oid_size);
	printf("expected_objs = %d, Actual objs = %d\n", expected_objs, actual_objs);
	assert_int_equal(expected_objs, actual_objs);
}

static void
serial_bucket_delete_list(void **state)
{
    test_delete_list("", 1);
}

static void
serial_object_delete_list(void **state)
{
    test_delete_list(TEST_OBJECT_BTREE_NAME, strlen(TEST_OBJECT_BTREE_NAME) + 1);
}

static void
send_bucket_insert(void *arg)
{
	struct thread_context *tctx = (struct thread_context *)arg;
	int thr_id = tctx->thread_no;
	int err;
	char buf[1024];

	for (int i = 0; i < TEST_NUM_BUCKETS; i++) {
		sprintf(buf, "abcd-%d-%d", thr_id, i);
		err = ccow_bucket_create(tc, buf, strlen(buf) + 1, NULL);
		assert_int_equal(err, 0);
	}
}

static void
send_bucket_delete(void *arg)
{
	struct thread_context *tctx = (struct thread_context *)arg;
	int thr_id = tctx->thread_no;
	int err;
	char buf[1024];

	for (int i = 0; i < TEST_NUM_BUCKETS; i++) {
		sprintf(buf, "abcd-%d-%d", thr_id, i);
		err = ccow_bucket_delete(tc, buf, strlen(buf) + 1);
		assert_int_equal(err, 0);
	}
}

static void
stress_bucket_insert(void **state)
{
	for(int i = 0; i < TEST_NUM_THREADS; i++) {
		t_ctx[i].thread_no = i;
		uv_thread_create(&client_contexts_threads[i],
			       (void *)&send_bucket_insert, (void *)&t_ctx[i]);
		usleep(100000);
	}
	for (int i = 0; i < TEST_NUM_THREADS; i++)
		uv_thread_join(&client_contexts_threads[i]);
}

static void
stress_bucket_delete(void **state)
{
	for(int i = 0; i < TEST_NUM_THREADS; i++) {
		t_ctx[i].thread_no = i;
		uv_thread_create(&client_contexts_threads[i],
			       (void *)&send_bucket_delete, (void *)&t_ctx[i]);
		usleep(100000);
	}
	for (int i = 0; i < TEST_NUM_THREADS; i++)
		uv_thread_join(&client_contexts_threads[i]);
}

static void
test_insert_list(char *oid, int oid_size)
{
	for(int i = 0; i < TEST_NUM_THREADS; i++) {
		t_ctx[i].thread_no = i;
		t_ctx[i].optype = CCOW_INSERT_LIST;
        t_ctx[i].oid = oid;
        t_ctx[i].oid_size = oid_size;
		uv_thread_create(&client_contexts_threads[i],
			       (void *)&send_update_list, (void *)&t_ctx[i]);
		usleep(100000);
	}
	for (int i = 0; i < TEST_NUM_THREADS; i++)
		uv_thread_join(&client_contexts_threads[i]);

	int expected_objs = TEST_NUM_THREADS * TEST_NUM_ITERS;
	usleep(5000000);
	int actual_objs = get_objs_nr(oid, oid_size);
	printf("expected_objs = %d, Actual objs = %d\n", expected_objs, actual_objs);
	assert_int_equal(expected_objs, actual_objs);
}

static void
serial_bucket_insert_list(void **state)
{
    test_insert_list("", 1);
}

static void
serial_object_insert_list(void **state)
{
    test_insert_list(TEST_OBJECT_BTREE_NAME, strlen(TEST_OBJECT_BTREE_NAME) + 1);
}

static void
list_op_with_md(ccow_op_t op)
{
	int err;
	char obj_key[MAX_OBJ_SZ];
	char obj_value[MAX_OBJ_SZ];
	struct ccow_metadata_kv attr;
	msgpack_p *p;
	uv_buf_t ubuf;
	uint64_t dir_sz = ENTRY_SIZE;

	ccow_completion_t c;
	struct iovec iov[3];


	sprintf(obj_key, "sub_dir_key");
	iov[0].iov_base = obj_key;
	iov[0].iov_len = strlen(obj_key) + 1;
	sprintf(obj_value, "sub_dir_value");
	iov[1].iov_base = obj_value;
	iov[1].iov_len = strlen(obj_value) + 1;

	attr.mdtype = CCOW_MDTYPE_METADATA;
	attr.type = CCOW_KVTYPE_UINT64;
	attr.key = RT_SYSKEY_LOGICAL_SIZE;
	attr.key_size = strlen(RT_SYSKEY_LOGICAL_SIZE);
	attr.value = &dir_sz;
	attr.value_size = sizeof(dir_sz);
	err = ccow_pack_mdkv(&attr, &p);
	assert_int_equal(err, 0);
	err = msgpack_get_buffer(p, &ubuf);
	assert_int_equal(err, 0);
	iov[2].iov_base = ubuf.base;
	iov[2].iov_len = ubuf.len;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_container_update_list(tc->cid, tc->cid_size, tc->tid,
					 tc->tid_size, TEST_BUCKET_NAME,
					 strlen(TEST_BUCKET_NAME) + 1,
					 DIR_OBJECT, strlen(DIR_OBJECT) + 1,
					 c, iov, 3, op);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	if (err != 0) {
		printf("ccow_container_update_list optype %d error: %d\n",
			CCOW_INSERT_LIST_WITH_MD, err);
	}
	assert_int_equal(err, 0);

	ccow_completion_t c1;
	ccow_lookup_t iter;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c1);
	assert_int_equal(err, 0);

	char buf[65536];
	struct iovec _get_iov = { .iov_base = "", .iov_len = 1 };

	err = ccow_get_list(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1, DIR_OBJECT, strlen(DIR_OBJECT) + 1, c1, &_get_iov, 1, 10000, &iter);
	assert_int_equal(err, 0);
	err = ccow_wait(c1, -1);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
	ccow_lookup_release(iter);
}

static void
serial_object_insert_list_with_md(void **state)
{
	list_op_with_md(CCOW_INSERT_LIST_WITH_MD);
}

static void
serial_object_delete_list_with_md(void **state)
{
	list_op_with_md(CCOW_DELETE_LIST_WITH_MD);
}

void
get_bucket_sz(char *oid, int oid_size)
{
	int err;
	ccow_completion_t c;
	ccow_lookup_t iter;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_get(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
                   oid, oid_size, c, NULL, 0, 0, &iter);
	if (err) {
		ccow_release(c);
		printf("ccow_get error: %d\n", err);
	}
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	if (err) {
		printf("ccow_wait error: %d\n", err);
	}
	assert_int_equal(err, 0);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	ccow_lookup_release(iter);
}

static void
test_ins_del_md_failure(void **state, ccow_op_t op, char *oid, int oid_size)
{
	int err;
	uint16_t stats = 10;
	ccow_completion_t c;
	char buf[64];
	struct iovec iov;
	struct ccow_metadata_kv attr;
	msgpack_p *p;
	uv_buf_t ubuf;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	/* Set the size */
	attr.mdtype = CCOW_MDTYPE_METADATA;
	attr.type = CCOW_KVTYPE_UINT16;
	attr.key = RT_SYSKEY_TRACK_STATISTICS;
	attr.key_size = strlen(RT_SYSKEY_TRACK_STATISTICS);
	attr.value = &stats;
	attr.value_size = sizeof(stats);
	err = ccow_pack_mdkv(&attr, &p);
	assert_int_equal(err, 0);
	msgpack_get_buffer(p, &ubuf);
	assert_non_null(p);
	iov.iov_base = ubuf.base;
	iov.iov_len = ubuf.len;

	err = ccow_container_update_list(tc->cid, tc->cid_size,
					 tc->tid, tc->tid_size,
					 TEST_BUCKET_NAME,
					 strlen(TEST_BUCKET_NAME) + 1,
					 oid, oid_size, c, &iov, 1, op);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	assert_int_not_equal(err, 0);
	msgpack_pack_free(p);
}

static void
serial_ins_del_md(void **state, ccow_op_t op, char *oid, int oid_size)
{
	int err;
	uint64_t cur_sz;
	uint64_t increment = 10;
	ccow_completion_t c;
	char buf[64];
	struct iovec iov[2];
	struct ccow_metadata_kv attr[2];
	msgpack_p *p[2];
	uv_buf_t ubuf[2];
	char bookname_key[] = "X-Object-Meta-Book";
	char book_value[] = "GoodbyeOldFriend";

	get_bucket_sz(oid, oid_size);

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	/* Set the size */
	attr[0].mdtype = CCOW_MDTYPE_METADATA;
	attr[0].type = CCOW_KVTYPE_UINT64;
	attr[0].key = RT_SYSKEY_LOGICAL_SIZE;
	attr[0].key_size = strlen(RT_SYSKEY_LOGICAL_SIZE);
	attr[0].value = &increment;
	attr[0].value_size = sizeof(increment);
	err = ccow_pack_mdkv(&attr[0], &p[0]);
	assert_int_equal(err, 0);
	err = msgpack_get_buffer(p[0], &ubuf[0]);
	assert_int_equal(err, 0);
	iov[0].iov_base = ubuf[0].base;
	iov[0].iov_len = ubuf[0].len;

	/* Set custom attribute */
	attr[1].mdtype = CCOW_MDTYPE_CUSTOM;
	attr[1].type = CCOW_KVTYPE_STR;
	attr[1].key = bookname_key;
	attr[1].key_size = strlen(bookname_key) + 1;
	attr[1].value = book_value;
	attr[1].value_size = strlen(book_value) + 1;
	err = ccow_pack_mdkv(&attr[1], &p[1]);
	assert_int_equal(err, 0);
	err = msgpack_get_buffer(p[1], &ubuf[1]);
	assert_int_equal(err, 0);
	iov[1].iov_base = ubuf[1].base;
	iov[1].iov_len = ubuf[1].len;

	err = ccow_container_update_list(tc->cid, tc->cid_size,
					 tc->tid, tc->tid_size,
					 TEST_BUCKET_NAME,
					 strlen(TEST_BUCKET_NAME) + 1,
					 oid, oid_size, c, iov, 2, op);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	msgpack_pack_free(p[0]);
	msgpack_pack_free(p[1]);

	get_bucket_sz(oid, oid_size);
}

static void
test_update_md_failure(void **state, char *oid, int oid_size)
{
	int err;
	uint8_t domain = 10;
	ccow_completion_t c;
	char buf[64];
	struct iovec iov;
	struct ccow_metadata_kv attr;
	msgpack_p *p;
	uv_buf_t ubuf;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	/* Set the size */
	attr.mdtype = CCOW_MDTYPE_METADATA;
	attr.type = CCOW_KVTYPE_UINT8;
	attr.key = RT_SYSKEY_FAILURE_DOMAIN;
	attr.key_size = strlen(RT_SYSKEY_FAILURE_DOMAIN);
	attr.value = &domain;
	attr.value_size = sizeof(domain);
	err = ccow_pack_mdkv(&attr, &p);
	assert_int_equal(err, 0);
	msgpack_get_buffer(p, &ubuf);
	assert_non_null(p);
	iov.iov_base = ubuf.base;
	iov.iov_len = ubuf.len;

	err = ccow_container_update_list(tc->cid, tc->cid_size,
					 tc->tid, tc->tid_size,
					 TEST_BUCKET_NAME,
					 strlen(TEST_BUCKET_NAME) + 1,
					 oid, oid_size, c, &iov, 1, CCOW_UPDATE_MD);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	assert_int_not_equal(err, 0);
	msgpack_pack_free(p);
}

static void
test_update_md(void **state, char *oid, int oid_size)
{
	int err;
	uint16_t vers = 5;
	ccow_completion_t c;
	struct iovec iov[2];
	struct ccow_metadata_kv attr[2];
	msgpack_p *p[2];
	uv_buf_t ubuf[2];
	char bookname_key[] = "X-Object-Meta-Book";
	char book_value[] = "NewEdition";

	get_bucket_sz(oid, oid_size);

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	/* Set the size */
	attr[0].mdtype = CCOW_MDTYPE_METADATA;
	attr[0].type = CCOW_KVTYPE_UINT16;
	attr[0].key = RT_SYSKEY_NUMBER_OF_VERSIONS;
	attr[0].key_size = strlen(RT_SYSKEY_NUMBER_OF_VERSIONS);
	attr[0].value = &vers;
	attr[0].value_size = sizeof(vers);
	err = ccow_pack_mdkv(&attr[0], &p[0]);
	assert_int_equal(err, 0);
	msgpack_get_buffer(p[0], &ubuf[0]);
	assert_non_null(p[0]);
	iov[0].iov_base = ubuf[0].base;
	iov[0].iov_len = ubuf[0].len;

	/* Set custom attribute */
	attr[1].mdtype = CCOW_MDTYPE_CUSTOM;
	attr[1].type = CCOW_KVTYPE_STR;
	attr[1].key = bookname_key;
	attr[1].key_size = strlen(bookname_key) + 1;
	attr[1].value = book_value;
	attr[1].value_size = strlen(book_value) + 1;
	err = ccow_pack_mdkv(&attr[1], &p[1]);
	assert_int_equal(err, 0);
	msgpack_get_buffer(p[1], &ubuf[1]);
	assert_non_null(p[1]);
	iov[1].iov_base = ubuf[1].base;
	iov[1].iov_len = ubuf[1].len;

	err = ccow_container_update_list(tc->cid, tc->cid_size,
					 tc->tid, tc->tid_size,
					 TEST_BUCKET_NAME,
					 strlen(TEST_BUCKET_NAME) + 1,
					 oid, oid_size, c, iov, 2, CCOW_UPDATE_MD);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	msgpack_pack_free(p[0]);
	msgpack_pack_free(p[1]);

	get_bucket_sz(oid, oid_size);
}

static void
serial_bucket_update_md(void **state)
{
	test_update_md_failure(state, "", 1);
	test_update_md(state, "", 1);
}

static void
serial_bucket_insert_md(void **state)
{
	test_ins_del_md_failure(state, CCOW_INSERT_MD, "", 1);
	serial_ins_del_md(state, CCOW_INSERT_MD, "", 1);
}

static void
serial_bucket_delete_md(void **state)
{
	test_ins_del_md_failure(state, CCOW_DELETE_MD, "", 1);
	serial_ins_del_md(state, CCOW_DELETE_MD, "", 1);
}

static void
serial_object_update_md(void **state)
{
	test_update_md_failure(state, TEST_OBJECT_BTREE_NAME, strlen(TEST_OBJECT_BTREE_NAME) + 1);
	test_update_md(state, TEST_OBJECT_BTREE_NAME, strlen(TEST_OBJECT_BTREE_NAME) + 1);
}

static void
serial_object_insert_md(void **state)
{
	test_ins_del_md_failure(state, CCOW_INSERT_MD,
                            TEST_OBJECT_BTREE_NAME,
                            strlen(TEST_OBJECT_BTREE_NAME) + 1);
	serial_ins_del_md(state, CCOW_INSERT_MD,
                      TEST_OBJECT_BTREE_NAME,
                      strlen(TEST_OBJECT_BTREE_NAME) + 1);
}

static void
serial_object_delete_md(void **state)
{
	test_ins_del_md_failure(state, CCOW_DELETE_MD,
                            TEST_OBJECT_BTREE_NAME,
                            strlen(TEST_OBJECT_BTREE_NAME) + 1);
	serial_ins_del_md(state, CCOW_DELETE_MD,
                            TEST_OBJECT_BTREE_NAME,
                            strlen(TEST_OBJECT_BTREE_NAME) + 1);
}

int
main(int argc, char **argv)
{
	if (argc == 2) {
		if (strcmp(argv[1], "-n") == 0) {
			dd = 1;
			daemon_initialized = 1;
		}
	}
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(dir_create),

		unit_test(object_create),
		unit_test(serial_object_insert_list),
		unit_test(serial_object_insert_md),
		unit_test(serial_object_update_md),
		unit_test(serial_object_delete_md),
		unit_test(serial_object_delete_list),

		unit_test(serial_object_insert_list_with_md),
		unit_test(serial_object_delete_list_with_md),

		unit_test(stress_bucket_insert),
		unit_test(stress_bucket_delete),

		unit_test(serial_bucket_insert_list),
		unit_test(serial_bucket_insert_md),
		unit_test(serial_bucket_update_md),
		unit_test(serial_bucket_delete_md),
		unit_test(serial_bucket_delete_list),

		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};

	return run_tests(tests);
}
