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
#include "reptrans.h"

/*
 * CAUTION: non-production internal unit test for reptrans debugging only
 */
#define MAX_DEV 256
struct repdev *devices[MAX_DEV];
struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

static ccow_t cl;
static int n_dev = 0;
static uint32_t seed = 0;

static void
libccowd_setup(void **state) {
	assert_int_equal(ccow_daemon_init(NULL), 0);
	usleep(2 * 1000000L);
}

static void
libccowd_teardown(void **state) {
	usleep(100000L);
	ccow_daemon_term();
}

static void
libccow_setup(void **state) {
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16384) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
	je_free(buf);
}

static void
libccow_teardown(void **state) {
	assert_non_null(cl);
	usleep(100000L);
	ccow_tenant_term(cl);
}

static void
enum_dev__done_cb(struct repdev *dev, void *arg, int status) {
	struct enum_dev_arg *da = (struct enum_dev_arg *)arg;
	assert_non_null(da);
	if (status == 0)
		da->dev[da->n_dev++] = dev;
	assert_true(da->n_dev < MAX_DEV);
}

static void
libreptrans_setup(void **state)
{
	struct enum_dev_arg enum_arg = {0, devices};
	assert_int_equal(reptrans_enum(NULL, &enum_arg,
		    enum_dev__done_cb, 0), 0);
	n_dev = enum_arg.n_dev;
}

static void
randomize_buffer(void* buf, size_t size) {
	static unsigned int seek = 0;
	char* ptr = (char*)buf;

	for(size_t i=0; i < size; i++) {
		*ptr = rand_r(&seed) % 256;
	}
}

int ccow_blob_lookup_request(struct ccow_network *netobj, const uint512_t* chid,
	uint8_t ttag, uint8_t hash_type, struct ccow_completion *c,
	uint128_t* vdevs_out, size_t* n_vdev_max);

static void
blob_lookup_test(void **state) {

	uv_buf_t chunk = { .base = je_malloc(1024), .len = 1024 };
	randomize_buffer(chunk.base, chunk.len);
	rtbuf_t *rb = rtbuf_init_mapped(&chunk, 1);
	uint512_t chid;
	uint64_t attr = -1;

	for (int i = 0; i < n_dev; i++) {
		assert_int_equal(reptrans_put_blob_with_attr(devices[i], TT_CHUNK_PAYLOAD,
			HASH_TYPE_XXHASH_64, rb, &chid, 1, attr) ,0);
	}

	usleep(10*1000000LL);

	size_t n_vdevs = n_dev * 2;
	uint128_t vdevs[n_vdevs];
	for (int i = 0; i < 5; i++) {
		struct ccow_completion *c;
		assert_int_equal(ccow_create_completion(cl, NULL, NULL, 1,
			(ccow_completion_t *)&c), 0);
		assert_int_equal(ccow_blob_lookup_request(cl->netobj, &chid, TT_CHUNK_PAYLOAD,
			HASH_TYPE_XXHASH_64, c, vdevs, &n_vdevs), 0);
		assert_int_equal(ccow_wait(c, -1), 0);
		assert_int_equal(n_vdevs, n_dev);
	}

	for (int i = 0; i < n_dev; i++) {
		assert_int_equal(reptrans_delete_blob(devices[i], TT_CHUNK_PAYLOAD,
			HASH_TYPE_XXHASH_64, &chid) ,0);
	}

	struct ccow_completion *c;
	assert_int_equal(ccow_create_completion(cl, NULL, NULL, 1,
		(ccow_completion_t *)&c), 0);

	assert_int_equal(ccow_blob_lookup_request(cl->netobj, &chid, TT_CHUNK_PAYLOAD,
		HASH_TYPE_XXHASH_64, c, vdevs, &n_vdevs), 0);

	assert_int_equal(ccow_wait(c, -1), 0);
	assert_int_equal(n_vdevs, 0);
}

static void
libreptrans_teardown(void **state) {
	ccow_daemon_term();
}

int
main(int argc, char *argv[]) {
   int opt;
   srand(time(NULL));
   seed = rand();

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(libreptrans_setup),
		unit_test(blob_lookup_test),
		unit_test(libreptrans_teardown),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
