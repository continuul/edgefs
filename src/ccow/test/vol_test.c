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

#define TEST_BUCKET_NAME	"vol-bucket-test"
ccow_t cl = NULL;
int dd = 0;

static void
libccowd_setup(void **state)
{
	if (!dd) {
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(1 * 1000000L);
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
 *		Vol Test Sync, Fixedmap 3x4, bs=16k
 * =======================================================================
 */

static void
btree_64_16k_setup(void **state)
{
	assert_non_null(cl);
	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	static struct cminfo cmi;
	cmi.comp = c;
	strcpy(cmi.oid, "vol-test-btree-64-16k");
	strcpy(cmi.chunkmap_type, "btree_map");
	cmi.btree_order = 64;
	cmi.fixed_bs = 4 * 0xFFFF;

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)cmi.chunkmap_type, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&cmi.fixed_bs, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		(void *)&cmi.btree_order, NULL);
	assert_int_equal(err, 0);
	*state = &cmi;
}

/*
 * =======================================================================
 *		Vol Test Sync, Fixedmap 3x4, bs=256
 * =======================================================================
 */

static void
btree_64_256b_setup(void **state)
{
	assert_non_null(cl);
	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	static struct cminfo cmi;
	cmi.comp = c;
	strcpy(cmi.oid, "vol-test-btree-64-256");
	strcpy(cmi.chunkmap_type, "btree_map");
	cmi.btree_order = 64;
	cmi.fixed_bs = 256;

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)cmi.chunkmap_type, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&cmi.fixed_bs, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		(void *)&cmi.btree_order, NULL);
	assert_int_equal(err, 0);

	*state = &cmi;
}

/*
 * =======================================================================
 *		Vol Test Sync, Btree, order=4
 * =======================================================================
 */

static void
btree_4_setup(void **state)
{
	assert_non_null(cl);
	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	static struct cminfo cmi;
	cmi.comp = c;
	strcpy(cmi.oid, "vol-test-btree-4");
	strcpy(cmi.chunkmap_type, "btree_map");
	cmi.btree_order = 4;
	cmi.fixed_bs = 1024;

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)cmi.chunkmap_type, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		(void *)&cmi.btree_order, NULL);
	assert_int_equal(err, 0);

	*state = &cmi;
}

/*
 * =======================================================================
 *		Vol Test Sync, Btree, order=120
 * =======================================================================
 */

static void
btree_120_setup(void **state)
{
	assert_non_null(cl);
	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	static struct cminfo cmi;
	cmi.comp = c;
	strcpy(cmi.oid, "vol-test-btree-120");
	strcpy(cmi.chunkmap_type, "btree_map");
	cmi.btree_order = 120;
	cmi.fixed_bs = 1024;

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)cmi.chunkmap_type, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		(void *)&cmi.btree_order, NULL);
	assert_int_equal(err, 0);

	*state = &cmi;
}

static void
vol_format__create_0_5(void **state)
{
	assert_non_null(cl);
	struct cminfo *cmi_ptr = *state;
	int err = 0;
	size_t iovcnt = 5;
	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);
	char *buf = je_malloc(iovcnt * cmi_ptr->fixed_bs);
	assert_non_null(buf);

	size_t i;
	for (i = 0; i < iovcnt; i++) {
		iov[i].iov_base = buf + i * cmi_ptr->fixed_bs;
		iov[i].iov_len = cmi_ptr->fixed_bs;
	}

	put_simple(cmi_ptr->comp, TEST_BUCKET_NAME, cmi_ptr->oid, iov, iovcnt, 0);

	err = ccow_wait(cmi_ptr->comp, -1);
	assert_int_equal(err, 0);

	if (cmi_ptr->iter)
		ccow_lookup_release(cmi_ptr->iter);
	je_free(buf);
	je_free(iov);
}

static void
vol_format__overwrite_0_5(void **state)
{
	assert_non_null(cl);
	struct cminfo *cmi_ptr = *state;
	int err = 0;
	size_t iovcnt = 5;
	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);
	char *buf = je_malloc(iovcnt * cmi_ptr->fixed_bs);
	assert_non_null(buf);

	size_t i;
	for (i = 0; i < iovcnt; i++) {
		iov[i].iov_base = buf + i * cmi_ptr->fixed_bs;
		iov[i].iov_len =  cmi_ptr->fixed_bs;
	}

	put(cl, TEST_BUCKET_NAME, cmi_ptr->oid, iov, iovcnt, 0, NULL, NULL);

	je_free(buf);
	je_free(iov);
}

static void
vol_format__overwrite_0_120(void **state)
{
	assert_non_null(cl);
	struct cminfo *cmi_ptr = *state;
	int err = 0;
	size_t iovcnt = 120;
	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);
	char *buf = je_malloc(120 * cmi_ptr->fixed_bs);
	assert_non_null(buf);

	size_t i;
	for (i = 0; i < iovcnt; i++) {
		iov[i].iov_base = buf + i * cmi_ptr->fixed_bs;
		iov[i].iov_len =  cmi_ptr->fixed_bs;
	}

	put(cl, TEST_BUCKET_NAME, cmi_ptr->oid, iov, iovcnt, 0, NULL, NULL);

	je_free(buf);
	je_free(iov);
}

static void
vol_format__append_0_18(void **state)
{
	assert_non_null(cl);
	struct cminfo *cmi_ptr = *state;
	int err = 0;
	size_t iovcnt = 18;
	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);
	char *buf = je_malloc(18 * cmi_ptr->fixed_bs);
	assert_non_null(buf);

	size_t i;
	for (i = 0; i < iovcnt; i++) {
		iov[i].iov_base = buf + i * cmi_ptr->fixed_bs;
		iov[i].iov_len = cmi_ptr->fixed_bs;
	}

	put(cl, TEST_BUCKET_NAME, cmi_ptr->oid, iov, iovcnt, 0, NULL, NULL);

	je_free(buf);
	je_free(iov);
}

static void
vol_format__get_multi(void **state)
{
	assert_non_null(cl);
	struct cminfo *cmi_ptr = *state;
	int num_items = 4;
	int offsets[] = { 0,
		1 * cmi_ptr->fixed_bs,
		2 * cmi_ptr->fixed_bs,
		3 * cmi_ptr->fixed_bs };

	get_offsets(cl, TEST_BUCKET_NAME, cmi_ptr->oid, cmi_ptr->fixed_bs,
	    offsets, num_items);
	char *buf = je_malloc(num_items * cmi_ptr->fixed_bs);
	struct iovec *iov = je_calloc(num_items, sizeof (struct iovec));
	for (int i = 0; i < num_items; i++) {
		iov[i].iov_base = buf + i * cmi_ptr->fixed_bs;
		iov[i].iov_len = cmi_ptr->fixed_bs;
	}

	get(cl, TEST_BUCKET_NAME, cmi_ptr->oid, iov, num_items,
	    7 * cmi_ptr->fixed_bs, NULL, NULL, NULL);

}

static void
vol_format__gap(void **state)
{
	assert_non_null(cl);
	struct cminfo *cmi_ptr = *state;
	int num_items = 4;
	int offsets[] = { 0,
		(16 * cmi_ptr->fixed_bs) - cmi_ptr->fixed_bs,
		16 * cmi_ptr->fixed_bs,
		(16 * cmi_ptr->fixed_bs) + cmi_ptr->fixed_bs };

	put_offsets(cl, TEST_BUCKET_NAME, cmi_ptr->oid, cmi_ptr->fixed_bs,
	    offsets, num_items);
}

/* Do not append all of the IOs send some as chained iovecs. */
static void
vol_format__append_gap(void **state)
{
	assert_non_null(cl);
	struct cminfo *cmi_ptr = *state;
	int err = 0;
	int num_items = 1;
	int offsets[] = { 0 };

	/*
	 * This test veriying that the following access pattern works:
	 *
	 *    write to [0], [3,4,5], then fill in gap [1], [2] and then add
	 *    one more vector at the end [6].
	 */

	put_offsets(cl, TEST_BUCKET_NAME, cmi_ptr->oid, cmi_ptr->fixed_bs,
	    offsets, num_items);

	char *buf = je_malloc(3 * cmi_ptr->fixed_bs);
	struct iovec *iov = je_calloc(3, sizeof (struct iovec));
	for (int i = 0; i < 3; i++) {
		iov[i].iov_base = buf + i * cmi_ptr->fixed_bs;
		iov[i].iov_len = cmi_ptr->fixed_bs;
	}

	/* notice offset is 768 */
	put(cl, TEST_BUCKET_NAME, cmi_ptr->oid, iov, 1,
	    3 * cmi_ptr->fixed_bs, NULL, NULL);

	int offsets2[] = { 1 * cmi_ptr->fixed_bs, 2 * cmi_ptr->fixed_bs,
		6 * cmi_ptr->fixed_bs };
	put_offsets(cl, TEST_BUCKET_NAME, cmi_ptr->oid, cmi_ptr->fixed_bs,
	    offsets2, 3);

	je_free(buf);
	je_free(iov);
}

static void
vol_test_sleepy(void **state)
{
	asleep();
}

static void
vol_format_teardown(void **state)
{
	assert_non_null(cl);
	struct cminfo *cmi_ptr = *state;
	delete(cl, TEST_BUCKET_NAME, cmi_ptr->oid, NULL, NULL);
}

static void
libccow_teardown(void **state)
{
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
	usleep(1 * 1000000L);
	if (!dd)
		ccow_daemon_term();
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

		unit_test_setup(vol_format__create_0_5, btree_64_16k_setup),
		unit_test(vol_format__overwrite_0_5),
//		unit_test(vol_format__get_multi),
		unit_test(vol_format__append_0_18),
		unit_test(vol_format__gap),
		unit_test(vol_format__append_gap),
		unit_test_teardown(NULL, vol_format_teardown),

//		unit_test(vol_test_sleepy),

		unit_test_setup(vol_format__create_0_5, btree_64_256b_setup),
		unit_test(vol_format__overwrite_0_5),
//		unit_test(vol_format__get_multi),
		unit_test(vol_format__append_0_18),
		unit_test(vol_format__gap),
		unit_test(vol_format__append_gap),
		unit_test_teardown(NULL, vol_format_teardown),

		unit_test_setup(vol_format__create_0_5, btree_4_setup),
		unit_test(vol_format__overwrite_0_5),
//		unit_test(vol_format__get_multi),
		unit_test(vol_format__append_0_18),
		unit_test(vol_format__gap),
		unit_test(vol_format__append_gap),
		unit_test_teardown(NULL, vol_format_teardown),

//		unit_test(vol_test_sleepy),

		unit_test_setup(vol_format__create_0_5, btree_120_setup),
		unit_test(vol_format__overwrite_0_120),
//		unit_test(vol_format__get_multi),
		unit_test(vol_format__append_0_18),
		unit_test(vol_format__gap),
		unit_test(vol_format__append_gap),
		unit_test_teardown(NULL, vol_format_teardown),

		unit_test(vol_test_sleepy),

		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
