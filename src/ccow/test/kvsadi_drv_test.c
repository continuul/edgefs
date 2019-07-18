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
/*
 * kvsadi_drv_test.c
 *
 *  Created on: Apr 21, 2018
 *      Author: root
 */
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"

#include "../src/libreptrans/kvsadi_drv.h"

#define BATCH_SIZE 16
#define KEY_SIZE 16

static void kvsadi_put_test(void **state) {
	kvsadi_handle_t* h = NULL;
	size_t value_size = 4096;
	type_tag_t ttag = TT_CHUNK_PAYLOAD;

	int err = kvsadi_init("doesn't matter", &h);
	assert_int_equal(err, 0);

	char keys[BATCH_SIZE][KEY_SIZE] = {0};
	char *value = NULL;
	char *get_value = NULL;

	value = je_malloc(value_size);

	for(size_t n=0; n < value_size; n++) {
		value[n] = rand() % 256;
	}

	/* But batch of buffers */
	uv_buf_t k[BATCH_SIZE];
	uv_buf_t v[BATCH_SIZE];

	for (size_t n = 0; n < BATCH_SIZE; n++) {
		keys[n][0] = n;
		v[n].len = value_size - n;
		v[n].base = value + n;
		k[n].len = KEY_SIZE;
		k[n].base = keys[n];
	}

	err = kvsadi_put(h, ttag, k, v, BATCH_SIZE);
	assert_int_equal(err, 0);

	/* Verify data are stored */
	get_value = je_malloc(value_size);
	char key1[KEY_SIZE] = {0};
	uv_buf_t k1 = { .base = key1, .len = KEY_SIZE };
	uv_buf_t v1 = {.base = get_value, .len = value_size};
	for (size_t n = 0; n < BATCH_SIZE; n++) {
		key1[0] = n;
		v1.len = value_size - n;
		err = kvsadi_get(h, ttag, k1, &v1);
		assert_int_equal(err, 0);
		err = memcmp(value+n, get_value, v1.len);
		assert_int_equal(err, 0);
	}

	/* Testing an iterator */
	rtbuf_t* rt_key = rtbuf_init_empty();
	rtbuf_t* rt_value = rtbuf_init_empty();
	kvsadi_iter_t* it = NULL;

	err = kvsadi_iterator_create(h, &it, ttag, 16, 1);
	assert_int_equal(err, 0);
	assert_non_null(it);

	while ((err = kvsadi_iterator_next(it, rt_key, rt_value)) == -EAGAIN || !err) {
		/* Verify values */
		for (size_t i = 0; i < rt_value->nbufs; i++) {
			char* key =  rtbuf(rt_key, i).base;
			char* data = rtbuf(rt_value, i).base;
			size_t off = key[0];
			size_t size = rtbuf(rt_value, i).len;
			err = memcmp(data, value + off, size);
			assert_int_equal(err, 0);
		}
		rtbuf_free(rt_key);
		rtbuf_free(rt_value);

		if (!err)
			break;
	}
	assert_int_equal(err, 0);
	rtbuf_clean(rt_key);
	rtbuf_clean(rt_value);

	err = kvsadi_iterator_destroy(it);
	assert_int_equal(err, 0);

	/* Verify exist function */
	for (size_t n = 0; n < BATCH_SIZE + 100; n++) {
		key1[0] = n;
		err = kvsadi_exist(h, ttag, k1);
		if (n < BATCH_SIZE)
			assert_int_equal(err, 0);
		else {
			assert_int_equal(err, -ENOENT);
			continue;
		}
	}

	/* Delete values */
	err = kvsadi_delete(h, ttag, k, BATCH_SIZE);
	assert_int_equal(err, 0);

	/* Make sure values were deleted */
	for (size_t n = 0; n < BATCH_SIZE; n++) {
		key1[0] = n;
		err = kvsadi_exist(h, ttag, k1);
		assert_int_equal(err, -ENOENT);
	}

	kvsadi_exit(h);
	je_free(value);
	je_free(get_value);
}

int main(int argc, char **argv) {
	lg = Logger_create("kvsadi");
	const UnitTest tests[] = {
		unit_test(kvsadi_put_test),
	};
	return run_tests(tests);
}
