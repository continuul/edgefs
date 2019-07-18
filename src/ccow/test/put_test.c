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
#include "flexhash.h"
#include "ccow-impl.h"
#include "server-list.h"

#define TEST_BUCKET_NAME	"put-bucket-test"
ccow_t cl = NULL;
ccow_t cu = NULL;

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
	assert_int_equal(err == 0 || err == -ENOENT, 1);
}

/*
 * =======================================================================
 *		Put Test Sync, Fixedmap 3x4, bs=1k
 * =======================================================================
 */
#define PUT_TEST_OID		"put-test"
#define PUT_TEST_CHUNKMAP	"btree_map"
#define PUT_TEST_CHUNKMAP_BS	1024

static void
put_test__fixed_init_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = PUT_TEST_CHUNKMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	char * chunkmap_type = PUT_TEST_CHUNKMAP;
	uint32_t bs = PUT_TEST_CHUNKMAP_BS;

	ccow_completion_t c;
	ccow_lookup_t iter;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	get_simple(c, TEST_BUCKET_NAME, PUT_TEST_OID, NULL, 0, 0, &iter);
	err = ccow_wait(c, 0);
	assert_int_equal(err && err != -ENOENT, 0);
	if (err == -ENOENT) {
		if (iter)
			ccow_lookup_release(iter);
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);
		iter = NULL;
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)chunkmap_type, iter);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, iter);
	assert_int_equal(err, 0);


	char bookname_key[] = "X-Object-Meta-Book";
	char book_value[] = "GoodbyeOldFriend";
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR, bookname_key, 19,
	    book_value, 0, iter);
	assert_int_equal(err, 0);

	char booknum_key[] = "X-Object-Meta-NumBooks";
	uint64_t books = 347;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64,
	    booknum_key, 23, &books, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, PUT_TEST_OID, &iov[0], 1, 0);
	err = ccow_wait(c, 1);
	assert_int_equal(err, 0);

	if (iter)
		ccow_lookup_release(iter);
	je_free(iov[0].iov_base);
}

static void
put_test__default_init_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = PUT_TEST_CHUNKMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	ccow_completion_t c;
	ccow_lookup_t iter;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	get_simple(c, TEST_BUCKET_NAME, "put-test-default-1k", NULL, 0, 0, &iter);
	err = ccow_wait(c, 0);
	assert_int_equal(err && err != -ENOENT, 0);
	if (err == -ENOENT) {
		if (iter)
			ccow_lookup_release(iter);
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);
		iter = NULL;
	}
	char bookname_key[] = "X-Object-Meta-Book";
	char book_value[] = "GoodbyeOldFriend";

	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_STR,
	    bookname_key, 19, book_value, 0, iter);
	assert_int_equal(err, 0);

	char booknum_key[] = "X-Object-Meta-NumBooks";
	uint64_t books = 347;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64,
	    booknum_key, 23, &books, 0, iter);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "put-test-default-1k", &iov[0], 1, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	if (iter)
		ccow_lookup_release(iter);
	je_free(iov[0].iov_base);
}

static void
put_test__default_overwrite_append_0_8k(void **state)
{
	assert_non_null(cl);
	int err = 0;
	struct iovec iov[1];
	iov[0].iov_len = PUT_TEST_CHUNKMAP_BS * 8;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	put(cl, TEST_BUCKET_NAME, "put-test-default-1k", &iov[0], 1, 0, NULL,
	    NULL);

	je_free(iov[0].iov_base);
}

static void
put_test__unaligned_9k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[3];
	int i;

	for (i = 0; i < 2; i++) {
		iov[i].iov_len = 4096;
		iov[i].iov_base = je_malloc(iov[i].iov_len);
		assert_non_null(iov[i].iov_base);
	}
	iov[i].iov_len = 48;
	iov[i].iov_base = je_malloc(iov[i].iov_len);

	ccow_completion_t c;
	ccow_lookup_t iter;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	uint16_t order = 4;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *) &order, NULL);
	assert_int_equal(err, 0);

	uint32_t bs = 4096;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, NULL);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "put-test-unaligned-9k", &iov[0], 3, 0);
	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	get_simple(c, TEST_BUCKET_NAME, "put-test-unaligned-9k", NULL, 0, 0, &iter);
	err = ccow_wait(c, 1);
	assert_int_equal(err && err != -ENOENT, 0);

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	uint64_t logical_size;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, pos++))) {
		if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &logical_size);

		}
	}

	assert_int_equal(logical_size, 8240);

	if (iter)
		ccow_lookup_release(iter);

	for (i = 0; i < 3; i++) {
		je_free(iov[i].iov_base);
	}
}

static void
put_test__unaligned_49k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[13];
	int i;

	for (i = 0; i < 12; i++) {
		iov[i].iov_len = 4096;
		iov[i].iov_base = je_malloc(iov[i].iov_len);
		assert_non_null(iov[i].iov_base);
	}
	iov[i].iov_len = 48;
	iov[i].iov_base = je_malloc(iov[i].iov_len);

	ccow_completion_t c;
	ccow_lookup_t iter;
	err = ccow_create_completion(cl, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);

	uint16_t order = 4;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *) &order, NULL);
	assert_int_equal(err, 0);

	uint32_t bs = 4096;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, NULL);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "put-test-unaligned-49k", &iov[0], 13, 0);
	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	get_simple(c, TEST_BUCKET_NAME, "put-test-unaligned-49k", NULL, 0, 0, &iter);
	err = ccow_wait(c, 1);
	assert_int_equal(err && err != -ENOENT, 0);

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	uint64_t logical_size;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, pos++))) {
		if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &logical_size);

		}
	}

	assert_int_equal(logical_size, 49200);

	if (iter)
		ccow_lookup_release(iter);

	for (i = 0; i < 13; i++) {
		je_free(iov[i].iov_base);
	}
}

/*
 * =======================================================================
 *		Put Test Async, Fixedmap 3x4, bs=1k
 * =======================================================================
 */
#define PUT_TEST_ASYNC_OID		"put-test-async"
#define PUT_TEST_ASYNC_CHUNKMAP		"btree_map"
#define PUT_TEST_ASYNC_FIXEDMAP_DEPTH	1
#define PUT_TEST_ASYNC_FIXEDMAP_WIDTH	64
#define PUT_TEST_ASYNC_CHUNKMAP_BS	4096

static void
put_test_async_cb(ccow_completion_t c, void *arg, int index, int err)
{
	uv_barrier_t *b = arg;
	assert_int_equal(err, 0);
	uv_barrier_wait(b);
}

static void
put_test_async__fixed_init_0_1k(void **state)
{
	assert_non_null(cl);
	int err = 0;
	struct iovec iov[1];
	iov[0].iov_len = PUT_TEST_ASYNC_CHUNKMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	uv_barrier_t b;
	uv_barrier_init(&b, 2);

	char * chunkmap_type = PUT_TEST_ASYNC_CHUNKMAP;
	uint8_t depth = PUT_TEST_ASYNC_FIXEDMAP_DEPTH;
	uint8_t hash_type = 8; // XXHASH_128
	uint16_t width = PUT_TEST_ASYNC_FIXEDMAP_WIDTH;
	uint32_t bs = PUT_TEST_ASYNC_CHUNKMAP_BS;

	ccow_completion_t c;
	err = ccow_create_completion(cl, &b, put_test_async_cb, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)chunkmap_type, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_FIXEDMAP_DEPTH,
		(void *)&depth, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_HASH_TYPE,
		(void *)&hash_type, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_FIXEDMAP_WIDTH,
	    (void *)&width, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, NULL);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, PUT_TEST_ASYNC_OID, &iov[0], 1, 0);
	uv_barrier_wait(&b);
	uv_barrier_destroy(&b);

	je_free(iov[0].iov_base);
}

static void
put_test_async__default_init_0_1k(void **state)
{
	assert_non_null(cl);
	int err = 0;
	struct iovec iov[1];
	iov[0].iov_len = PUT_TEST_ASYNC_CHUNKMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	uv_barrier_t b;
	uv_barrier_init(&b, 2);

	ccow_completion_t c;
	err = ccow_create_completion(cl, &b, put_test_async_cb, 1, &c);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, PUT_TEST_ASYNC_OID, &iov[0], 1, 0);

	uv_barrier_wait(&b);
	uv_barrier_destroy(&b);

	je_free(iov[0].iov_base);
}

static void
put_test_async__default_overwrite_append_0_8k(void **state)
{
	assert_non_null(cl);
	int err = 0;
	struct iovec iov[1];
	iov[0].iov_len = PUT_TEST_ASYNC_CHUNKMAP_BS * 8;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	uv_barrier_t b;
	uv_barrier_init(&b, 2);

	ccow_completion_t c;
	err = ccow_create_completion(cl, &b, put_test_async_cb, 1, &c);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, PUT_TEST_ASYNC_OID, &iov[0], 1, 0);

	uv_barrier_wait(&b);
	uv_barrier_destroy(&b);

	je_free(iov[0].iov_base);
}

#define ASYNC_STESS_MAX		100
static int async_max = ASYNC_STESS_MAX;
static int async_compl = 0;

static void
put_test_async_stress_cb(ccow_completion_t c, void *arg, int index, int err)
{
	uv_barrier_t *b = arg;
	if (err)
		printf("Warning: async callback received err %d\n", err);

	if (++async_compl == async_max)
		uv_barrier_wait(b);
}

static void
put_test_async__stress(void **state)
{
	assert_non_null(cl);
	int err = 0;
	struct iovec iov[1];
	iov[0].iov_len = PUT_TEST_ASYNC_CHUNKMAP_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	uv_barrier_t b;
	uv_barrier_init(&b, 2);

	/* do the async benchmark */
	uint64_t before = uv_hrtime();

	for (int i = 0; i < async_max; i++) {
		ccow_completion_t c;
		err = ccow_create_completion(cl, &b, put_test_async_stress_cb, 1, &c);
		if (err) {
			async_max = i;
			break;
		}
		usleep(1); // to make sure VM CHID is unique
		put_simple(c, TEST_BUCKET_NAME, PUT_TEST_ASYNC_OID, &iov[0], 1,
		    0);
	}

	uv_barrier_wait(&b);
	uv_barrier_destroy(&b);

	uint64_t after = uv_hrtime();

	printf("%s stats (async): %.2fs (%s/s)\n", fmt(1.0 * async_max),
	    (after - before) / 1e9,
	    fmt((1.0 * async_max) / ((after - before) / 1e9)));
	fflush(stdout);

	je_free(iov[0].iov_base);
}

static void
put_test_convert_vdev_rows(struct cl_vdev *vdevptr,
	volatile struct flexhash *fhtable,
	struct lvdev *lvdev)
{
	char vdevstr[UINT128_BYTES * 2 + 1];

	lvdev->numrows = fhtable->numrows;
	memset(lvdev->hashcount, 0, sizeof (lvdev->hashcount));
	for (int j = 0; j < vdevptr->numrows; j++) {
		int row = j % lvdev->numrows;
		if (vdevptr->hashcount[j] > 0)
			lvdev->hashcount[row]++;
	}

	lvdev->activerows = 0;
	if (vdevptr->activerows > 0) {
		for (uint32_t j = 0; j < lvdev->numrows; j++) {
			if (lvdev->hashcount[j] > 0)
				lvdev->activerows++;
		}
	}

	uint128_dump(&vdevptr->vdevid, vdevstr, UINT128_BYTES * 2 + 1);
	log_debug(lg, "vdev: %s activerows: %u converted-activerows: %u",
	    vdevstr, vdevptr->activerows, lvdev->activerows);
}

static int
put_test_flexhash_update(ccow_t tc)
{
	struct ccow *cl = (struct ccow *) tc;
	struct fhserver *sdevptr;
	char str[UINT128_BYTES * 2 + 1];
	struct cl_node node;
	volatile struct flexhash *fhtable = cl->flexhash;

	log_debug(lg, "Client flexhash update started.");

	sdevptr = cl->flexhash->serverlist;
	for (; sdevptr != NULL; sdevptr = sdevptr->next) {
		// Get latest flexhash from server
		struct ccow_completion *c;
		if (ccow_create_completion(cl, NULL, NULL, 1, (ccow_completion_t *)&c)) {
			log_error(lg, "Error creating completion.");
			return -1;
		}

		if (server_list_get_init(cl->netobj, c, sdevptr->id, &node,
		    SLG_SENDER_SERVER)) {
			log_error(lg, "Error server_list_get_init");
			return -1;
		}

		if (ccow_wait(c, -1)) {
			log_error(lg, "Error server_list_get_init");
			return -1;
		}

		uint128_dump(&sdevptr->id, str, UINT128_BYTES * 2 + 1);
		log_debug(lg, "Found server %s nr_vdevs %u", str, node.nr_vdevs);

		if (node.nr_vdevs == 0)
			continue;

		struct cl_vdev *vdevptr;
		struct lvdev lv, *lvdev;
		for (uint32_t k = 0; k < node.nr_vdevs; k++) {
			// Convert vdev hashcount to lvdev
			vdevptr = &node.vdevs[k];
			put_test_convert_vdev_rows(vdevptr, fhtable, &lv);

			// Find vdev in flexhash
			int idx = flexhash_getvdev_index(fhtable, &vdevptr->vdevid);
			if (idx == -ENOENT)
				continue;

			lvdev = &fhtable->vdevstore->lvdevlist[idx];

			// Update activerows
			if ((lvdev->activerows == 0) && lv.activerows)
				lvdev->activerows = lv.activerows;
		}

		je_free(node.vdevs);
	}

	log_debug(lg, "Client flexhash update completed.");
	return 0;
}

static void
put_test_flexhash_rebuild(ccow_t tc)
{
	struct ccow *cl = (struct ccow *) tc;
	volatile struct flexhash *fhtable = cl->flexhash;
	struct cl_node *node;
	int numnodes;

	// Update client flexhash
	if (put_test_flexhash_update(tc)) {
		log_error(lg, "Failed to rebuild flexhash.");
		return;
	}

	// Client side flexhash has been updated. Now rebuild.
	log_debug(lg, "Client flexhash rebuild started.");

	if (flexhash_get_nodes(fhtable, &node, &numnodes, 1)) {
		log_error(lg, "Failed to rebuild flexhash.");
		return;
	}

	flexhash_rebuild_start(fhtable, fhtable->servercount, 0);

	flexhash_add_serverlist(fhtable->rebuild_ctx.fhtable, node, numnodes,
		FH_REBUILD_NEXT);

	flexhash_rebuild_done(&cl->flexhash, 0, 0, 0);

	for (int i = 0; i < numnodes; i++)
		je_free(node[i].vdevs);

	je_free(node);
	log_debug(lg, "Client flexhash rebuild completed.");
}

#define PUT_TEST_FR_BS			4096
#define PUT_TEST_FR_IO_COUNT		40
#define PUT_TEST_FR_REPEAT_COUNT	10

static void
put_test_flexhash_rebuild_verify(void **state)
{
	assert_non_null(cu);
	int err = 0;
	struct iovec iov[1];

	char oid[512];
	char wrdata[PUT_TEST_FR_IO_COUNT][PUT_TEST_FR_BS];
	char rddata[PUT_TEST_FR_BS];
	char temp[64];

	//fprintf(stderr, "Generating %u objects of size %u\n",
	//    PUT_TEST_FR_IO_COUNT, PUT_TEST_FR_BS);
	srandom((unsigned int)time(NULL));
	for (int i = 0; i < PUT_TEST_FR_IO_COUNT; i++)
		for (int j = 0; j < PUT_TEST_FR_BS; j++)
			wrdata[i][j] = (char)('A' + (random() % 26));

	iov[0].iov_len = PUT_TEST_FR_BS;
	iov[0].iov_base = je_malloc(PUT_TEST_FR_BS);
	assert_non_null(iov[0].iov_base);

	//fprintf(stderr, "Writing objects\n");
	for (int i = 0; i < PUT_TEST_FR_IO_COUNT; i++) {
		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		memcpy(iov[0].iov_base, wrdata[i], PUT_TEST_FR_BS);
		snprintf(oid, 512, "%s-%d", "put-test-fr-verify", i);
		err = ccow_put(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
		    oid, strlen(oid) + 1, c, iov, 1, 0);
		assert_int_equal(err, 0);
		err = ccow_wait(c, -1);
		assert_int_equal(err, 0);
	}

	//fprintf(stderr, "Reading and verifying objects before rebuild\n");
	for (int i = 0; i < PUT_TEST_FR_IO_COUNT; i++) {
		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		snprintf(oid, 512, "%s-%d", "put-test-fr-verify", i);
		get_simple(c, TEST_BUCKET_NAME, oid, &iov[0], 1, 0, NULL);
		err = ccow_wait(c, -1);
		assert_int_equal(err, 0);

		memcpy(rddata, iov[0].iov_base, PUT_TEST_FR_BS);
		assert_memory_equal(rddata, wrdata[i], PUT_TEST_FR_BS);
	}

	// Once client flexhash is rebuilt, no writes can be performed.
	// Use another context for rebuild and read.
	for (int k = 0; k < PUT_TEST_FR_REPEAT_COUNT; k++) {
		//fprintf(stderr, "Rebuilding client flexhash\n");
		put_test_flexhash_rebuild(cu);

		//fprintf(stderr, "Reading and verifying objects\n");
		for (int i = 0; i < PUT_TEST_FR_IO_COUNT; i++) {
			ccow_completion_t c;
			err = ccow_create_completion(cu, NULL, NULL, 1, &c);
			assert_int_equal(err, 0);

			snprintf(oid, 512, "%s-%d", "put-test-fr-verify", i);
			get_simple(c, TEST_BUCKET_NAME, oid, &iov[0],
			    1, 0, NULL);
			err = ccow_wait(c, -1);
			assert_int_equal(err, 0);

			memcpy(rddata, iov[0].iov_base, PUT_TEST_FR_BS);
			assert_memory_equal(rddata, wrdata[i], PUT_TEST_FR_BS);
		}
	}

	je_free(iov[0].iov_base);
}

static void
object_delete(void **state)
{
//	delete(cl, TEST_BUCKET_NAME, PUT_TEST_OID, NULL, NULL);
//	delete(cl, TEST_BUCKET_NAME, "put-test-default-1k", NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, PUT_TEST_ASYNC_OID, NULL, NULL);
}


static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	usleep(100000L);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
    if(!dd)
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
		unit_test(put_test__unaligned_9k),
		unit_test(put_test__unaligned_49k),
//		unit_test(put_test__default_init_0_1k),
//		unit_test(put_test__default_overwrite_append_0_8k),
//		unit_test(put_test__fixed_init_0_1k),
//		unit_test(put_test_async__default_init_0_1k),
//		unit_test(put_test_async__default_overwrite_append_0_8k),
		unit_test(put_test_async__fixed_init_0_1k),
		unit_test(put_test_async__stress),
		unit_test(object_delete),
//		unit_test(put_test_flexhash_rebuild_verify),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
