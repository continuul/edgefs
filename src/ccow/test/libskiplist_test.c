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
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <uv.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "skiplist.h"

struct skiplist *sl;
Logger lg = NULL;

struct kv_t {
	const char *k;
	const char *v;
} kv_infos[] = {
	{"1", "1"},
	{"3", "3"},
	{"5", "5"},
	{"7", "7"},
	{"2", "2"},
	{"4", "4"},
	{"6", "6"},
	{"8", "8"},
	{"9", "9"},
	{"0", "0"},
};
static int kv_num = sizeof (kv_infos) / sizeof (kv_infos[0]);

static int
keycmp(const void *ka, const size_t ka_len, const void *kb, const size_t kb_len)
{
	int diff;
	ssize_t len_diff;
	unsigned int len;

	len = ka_len;
	len_diff = (ssize_t) ka_len - (ssize_t) kb_len;
	if (len_diff > 0) {
		len = kb_len;
		len_diff = 1;
	}

	diff = memcmp(ka, kb, len);
	return diff ? diff : len_diff<0 ? -1 : len_diff;
}

static void
libskiplist_setup(void **state)
{
	lg = Logger_create("libskiplist_test");
	assert_non_null(lg);
	sl = msl_create(keycmp);
	assert_non_null(sl);
}

static void
libskiplist_setget(void **state)
{
	int i = 0, err;

	printf("set\n");
	for (i = 0; i < kv_num; i++) {
		err = msl_set(sl, kv_infos[i].k, 2, kv_infos[i].v, 2, NULL);
		assert_int_equal(err, 0);
		printf("key: %s\tvalue: %s\n", kv_infos[i].k, kv_infos[i].v);
	}

	printf("get\n");
	for (i = 0; i < kv_num; i++) {
		const char *v = (const char *)msl_get(sl, kv_infos[i].k, 2, NULL);
		printf("key: %s\tvalue: %s\n", kv_infos[i].k, v == NULL ? "(null)" : v);
	}
}

static void
libskiplist_erase(void **state)
{
	char *old_val;

	printf("count %d\n", msl_count(sl));

	old_val = msl_erase(sl, "0", 2, NULL);
	printf("erase 0\n");
	assert_int_equal(memcmp(old_val, "0", 2), 0);

	old_val = msl_erase(sl, "7", 2, NULL);
	printf("erase 7\n");
	assert_int_equal(memcmp(old_val, "7", 2), 0);

	old_val = msl_erase(sl, "6", 2, NULL);
	printf("erase 6\n");
	assert_int_equal(memcmp(old_val, "6", 2), 0);

	old_val = msl_erase(sl, "10", 2, NULL);
	printf("erase 10\n");
	assert_null(old_val);

	printf("get\n");
	for (int i = 0; i < kv_num; i++) {
		const char *v = (const char *)msl_get(sl, kv_infos[i].k, 2, NULL);
		printf("key: %s\tvalue: %s\n", kv_infos[i].k, v == NULL ? "(null)" : v);
	}

	printf("count %d\n", msl_count(sl));
}

static void
libskiplist_search(void **state)
{
	int err;
	struct skiplist_iter it;
	char *old_val;

	printf("search\n");

	msl_search(sl, "5", strlen("5")+1, &it);
	if (it.v != NULL) {
		const char *k = msl_iter_getk(&it, NULL);
		const char *v = msl_iter_getv(&it, NULL);

		printf("Search 5 result key: %s\tvalue: %s\n", k, v);
	}

	msl_search(sl, "61", strlen("61")+1, &it);
	if (it.v != NULL) {
		const char *k = msl_iter_getk(&it, NULL);
		const char *v = msl_iter_getv(&it, NULL);

		printf("Search 61 result key: %s\tvalue: %s\n", k, v);
	}

	msl_search(sl, ".", strlen(".")+1, &it);
	if (it.v != NULL) {
		const char *k = msl_iter_getk(&it, NULL);
		const char *v = msl_iter_getv(&it, NULL);

		printf("Search . result key: %s\tvalue: %s\n", k, v);
	}


	msl_search(sl, "91", strlen("91")+1, &it);
	if (it.v != NULL) {
		const char *k = msl_iter_getk(&it, NULL);
		const char *v = msl_iter_getv(&it, NULL);

		printf("Search 91 result key: %s\tvalue: %s\n", k, v);
	} else {
		printf("Search 91 result not found\n");
	}


	msl_search(sl, "", 1, &it);
	if (it.v != NULL) {
		const char *k = msl_iter_getk(&it, NULL);
		const char *v = msl_iter_getv(&it, NULL);

		printf("Search blank result key: %s\tvalue: %s\n", k, v);
	} else {
		printf("Search blank result not found\n");
	}

}


static void
libskiplist_from(void **state)
{
	int err;
	struct skiplist_iter it;
	char key[64];
	char *k, *v;

	strcpy(key,"5");
	printf("\nfrom %s\n", key);
	msl_search(sl, key, strlen(key) + 1, &it);
	while (it.v != NULL) {
		k = msl_iter_getk(&it, NULL);
		v = msl_iter_getv(&it, NULL);
		printf("key: %s\tvalue: %s\n", k, v);
		it = msl_iter_next(sl, &it);
	}

	strcpy(key,"61");
	printf("\nfrom %s\n", key);
	msl_search(sl, key, strlen(key) + 1, &it);
	while (it.v != NULL) {
		k = msl_iter_getk(&it, NULL);
		v = msl_iter_getv(&it, NULL);
		printf("key: %s\tvalue: %s\n", k, v);
		it = msl_iter_next(sl, &it);
	}


	strcpy(key,".");
	printf("\nfrom %s\n", key);
	msl_search(sl, key, strlen(key) + 1, &it);
	while (it.v != NULL) {
		k = msl_iter_getk(&it, NULL);
		v = msl_iter_getv(&it, NULL);
		printf("key: %s\tvalue: %s\n", k, v);
		it = msl_iter_next(sl, &it);
	}

	strcpy(key,"91");
	printf("\nfrom %s\n", key);
	msl_search(sl, key, strlen(key) + 1, &it);
	while (it.v != NULL) {
		k = msl_iter_getk(&it, NULL);
		v = msl_iter_getv(&it, NULL);
		printf("key: %s\tvalue: %s\n", k, v);
		it = msl_iter_next(sl, &it);
	}

	strcpy(key,"");
	printf("\nfrom %s\n", key);
	msl_search(sl, key, strlen(key) + 1, &it);
	while (it.v != NULL) {
		k = msl_iter_getk(&it, NULL);
		v = msl_iter_getv(&it, NULL);
		printf("key: %s\tvalue: %s\n", k, v);
		it = msl_iter_next(sl, &it);
	}

}

static void
libskiplist_stress(void **state)
{
	int i = 0, err, num = 1000000;
	uint64_t t1, t2;
	struct skiplist_iter it;

	struct skiplist *xsl = msl_create(keycmp);


	printf("stress insert\n");
	t1 = get_timestamp_us();
	for (i = 0; i < num; i++) {
		char *key = malloc(32);
		sprintf(key,"key%d", i);
		char *value = malloc(32);
		sprintf(value,"value%d", i);
		err = msl_set(xsl, key, strlen(key) + 1, value, strlen(value) + 1, NULL);
		assert_int_equal(err, 0);
	}
	t2 = get_timestamp_us();
	printf("stress insert time: %luns\n", (t2 - t1)/num);

	printf("stress search\n");
	char buf[32];
	sprintf(buf,"key%d_", num/2);
	t1 = get_timestamp_us();
	msl_search(xsl, buf, strlen(buf)+1, &it);
	t2 = get_timestamp_us();
	printf("stress search time: %luns\n", (t2 - t1));

	if (it.v != NULL) {
		const char *k = msl_iter_getk(&it, NULL);
		const char *v = msl_iter_getv(&it, NULL);

		printf("Stress search %s result key: %s\tvalue: %s\n", buf, k, v);
	}

	msl_destroy_free(xsl);
}


static void
libskiplist_iter(void **state)
{
	int err;
	struct skiplist_iter it;
	char *old_val;

	printf("iter\n");
	it = msl_iter_next(sl, NULL);
	while (it.v != NULL) {
		const char *k = msl_iter_getk(&it, NULL);
		const char *v = msl_iter_getv(&it, NULL);

		printf("key: %s\tvalue: %s\n", k, v);

		it = msl_iter_next(sl, &it);
	}

	msl_debug(sl, 0);

	printf("set one\n");
	err = msl_set(sl, kv_infos[6].k, 2, kv_infos[6].v, 2, NULL);
	assert_int_equal(err, 0);
	printf("key: %s\tvalue: %s\n", kv_infos[6].k, kv_infos[6].v);

	msl_debug(sl, 0);
	printf("count %d\n", msl_count(sl));

	printf("can get value 5\n");
	old_val = msl_get(sl, "5", 2, NULL);
	assert_non_null(old_val);

	printf("iter erase 5\n");
	it = msl_iter_next(sl, NULL);
	while (it.v != NULL) {
		const char *k = msl_iter_getk(&it, NULL);
		const char *v = msl_iter_getv(&it, NULL);

		it = msl_iter_next(sl, &it);

		if (strcmp(k, "5") == 0) {
			printf("can get value 5 within iter\n");
			old_val = msl_get(sl, k, 2, NULL);
			assert_non_null(old_val);
			printf("can erase value 5 within iter\n");
			old_val = msl_erase(sl, k, 2, NULL);
			assert_non_null(old_val);
			assert_int_equal(strcmp(k, "5"), 0);
			assert_int_equal(strcmp(old_val, "5"), 0);
			old_val = msl_get(sl, k, 2, NULL);
			assert_null(old_val);
			continue;
		}

		printf("key: %s\tvalue: %s\n", k, v);
	}

	msl_debug(sl, 0);
	printf("count %d\n", msl_count(sl));

	old_val = msl_erase(sl, "1", 2, NULL);
	printf("erase 1\n");
	assert_int_equal(memcmp(old_val, "1", 2), 0);

	old_val = msl_erase(sl, "2", 2, NULL);
	printf("erase 2\n");
	assert_int_equal(memcmp(old_val, "2", 2), 0);

	old_val = msl_erase(sl, "3", 2, NULL);
	printf("erase 3\n");
	assert_int_equal(memcmp(old_val, "3", 2), 0);

	old_val = msl_erase(sl, "4", 2, NULL);
	printf("erase 4\n");
	assert_int_equal(memcmp(old_val, "4", 2), 0);

	old_val = msl_erase(sl, "6", 2, NULL);
	printf("erase 6\n");
	assert_int_equal(memcmp(old_val, "6", 2), 0);

	old_val = msl_erase(sl, "8", 2, NULL);
	printf("erase 8\n");
	assert_int_equal(memcmp(old_val, "8", 2), 0);

	msl_debug(sl, 0);
	printf("count %d\n", msl_count(sl));

	printf("set the same one, 9\n");
	err = msl_set(sl, "9", 2, "9", 2, NULL);
	assert_int_equal(err, 0);
	assert_int_equal(msl_count(sl), 1);

	printf("set the same one, 9, again\n");
	err = msl_set(sl, "9", 2, "9", 2, NULL);
	assert_int_equal(err, 0);
	assert_int_equal(msl_count(sl), 1);

	msl_debug(sl, 0);
	printf("count %d\n", msl_count(sl));

	printf("set one more, 8\n");
	err = msl_set(sl, "8", 2, "8", 2, NULL);
	assert_int_equal(err, 0);
	assert_int_equal(msl_count(sl), 2);

	printf("iter erase 8, 9, last one\n");
	it = msl_iter_next(sl, NULL);
	while (it.v != NULL) {
		const char *k = msl_iter_getk(&it, NULL);
		const char *v = msl_iter_getv(&it, NULL);

		it = msl_iter_next(sl, &it);

		if (strcmp(k, "9") == 0 || strcmp(k, "8") == 0) {
			old_val = msl_get(sl, k, 2, NULL);
			assert_non_null(old_val);
			old_val = msl_erase(sl, k, 2, NULL);
			assert_non_null(old_val);
			old_val = msl_get(sl, k, 2, NULL);
			assert_null(old_val);
			continue;
		}

		printf("key: %s\tvalue: %s\n", k, v);
	}

	msl_debug(sl, 0);
	printf("count %d\n", msl_count(sl));
}

static void
libskiplist_teardown(void **state)
{
	msl_destroy(sl);
}

int
main()
{
	const UnitTest tests[] = {
		unit_test(libskiplist_setup),
		unit_test(libskiplist_setget),
		unit_test(libskiplist_search),
		unit_test(libskiplist_from),
		unit_test(libskiplist_erase),
		unit_test(libskiplist_iter),
		unit_test(libskiplist_stress),
		unit_test(libskiplist_teardown),
	};
	return run_tests(tests);
}
