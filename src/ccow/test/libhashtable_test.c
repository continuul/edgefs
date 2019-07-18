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
#include "hashtable.h"
#include "lfq.h"

hashtable_t *tbl;
Logger lg = NULL;

char *s1 = (char*)"teststring 1";
char *s2 = (char*)"teststring 2 xxx";
char *s3 = (char*)"teststring 3 zzzzzz";

static struct timespec
snap_time()
{
	struct timespec t;
	clock_gettime(CLOCK_REALTIME, &t);
	return t;
}

static double
get_elapsed(struct timespec t1, struct timespec t2)
{
	double ft1 = t1.tv_sec + ((double)t1.tv_nsec / 1000000000.0);
	double ft2 = t2.tv_sec + ((double)t2.tv_nsec / 1000000000.0);
	return ft2 - ft1;
}

static void
libhashtable_setup(void **state)
{
	lg = Logger_create("libhashtabl_test");
	assert_non_null(lg);
	tbl = hashtable_create(256, HT_KEY_CONST | HT_VALUE_CONST, 0.05);
	assert_non_null(tbl);
}

static void
libhashtable_put(void **state)
{
	int err = hashtable_put(tbl, s1, strlen(s1) + 1, s2, strlen(s2) + 1);
	assert_int_equal(err, 0);
	int contains = hashtable_contains(tbl, s1, strlen(s1) + 1);
	assert_int_equal(contains, 1);

	size_t value_size;
	char *got = hashtable_get(tbl, s1, strlen(s1) + 1, &value_size);
	assert_non_null(got);
	assert_int_equal(value_size, strlen(s2) + 1);
}

static void
libhashtable_replace(void **state)
{
	/* replacing s2 with s3 for key s1 */
	int err = hashtable_put(tbl, s1, strlen(s1) + 1, s3, strlen(s3) + 1);
	assert_int_equal(err, 0);

	unsigned int num_keys;
	void **keys = hashtable_keys(tbl, &num_keys);
	assert_int_equal(num_keys, 1);
	assert_non_null(keys);
	je_free(keys);

	size_t value_size;
	char *got = hashtable_get(tbl, s1, strlen(s1) + 1, &value_size);
	assert_non_null(got);
	assert_int_equal(value_size, strlen(s3) + 1);
}

static void
libhashtable_remove(void **state)
{
	hashtable_remove(tbl, s1, strlen(s1) + 1);

	int contains = hashtable_contains(tbl, s1, strlen(s1) + 1);
	assert_int_equal(contains, 0);

	unsigned int num_keys;
	void **keys = hashtable_keys(tbl, &num_keys);
	assert_int_equal(num_keys, 0);
}

static void
libhashtable_stress(void **state)
{
	int key_count = 1000000;
	int i;
	int *many_keys = je_malloc(key_count * sizeof (*many_keys));
	assert_non_null(many_keys);
	int *many_values = je_malloc(key_count * sizeof (*many_values));
	assert_non_null(many_values);

	srand(time(NULL));

	for (i = 0; i < key_count; i++) {
		many_keys[i] = i;
		many_values[i] = rand();
	}

	struct timespec t1;
	struct timespec t2;

	t1 = snap_time();

	for (i = 0; i < key_count; i++) {
		hashtable_put(tbl, &(many_keys[i]), sizeof(many_keys[i]),
		    &(many_values[i]), sizeof(many_values[i]));
	}

	t2 = snap_time();

	fprintf(stderr, "Inserting %d keys took %.2f seconds\n", key_count,
	    get_elapsed(t1, t2));
	fprintf(stderr, "Checking inserted keys\n");

	int ok_flag = 1;
	for (i = 0; i < key_count; i++) {
		if (hashtable_contains(tbl, &(many_keys[i]), sizeof(many_keys[i]))) {
			size_t value_size;
			int value;

			value = *(int*)hashtable_get(tbl, &(many_keys[i]),
			    sizeof (many_keys[i]), &value_size);

			if (value != many_values[i]) {
				fprintf(stderr, "Key value mismatch. Got "
				    "{%d: %d} expected: {%d: %d}\n",
				    many_keys[i], value, many_keys[i],
				    many_values[i]);
				ok_flag = 0;
				break;
			}
		} else {
			fprintf(stderr, "Missing key-value pair {%d: %d}\n",
			    many_keys[i], many_values[i]);
			ok_flag = 0;
			break;
		}
	}

	assert_int_equal(ok_flag, 1);

	printf("Inserting %d keys resulted in %d collisions\n", key_count,
	    tbl->collisions);

	/* clear */
	hashtable_destroy(tbl);
	tbl = hashtable_create(256, HT_KEY_CONST | HT_VALUE_CONST, 0.05);
	assert_non_null(tbl);

	hashtable_resize(tbl, 4194304);
	t1 = snap_time();

	for (i = 0; i < key_count; i++) {
		hashtable_put(tbl, &(many_keys[i]), sizeof(many_keys[i]),
		    &(many_values[i]), sizeof(many_values[i]));
	}

	t2 = snap_time();

	fprintf(stderr, "Inserting %d keys (on preallocated table) took %.2f "
	    "seconds\n", key_count, get_elapsed(t1, t2));
	for (i = 0; i < key_count; i++) {
		hashtable_remove(tbl, &(many_keys[i]), sizeof(many_keys[i]));
	}
	assert_int_equal(hashtable_size(tbl), 0);
	je_free(many_keys);
	je_free(many_values);

}

static void
libhashtable_teardown(void **state)
{
	hashtable_destroy(tbl);
}

static void
libhashtable_lfqqueue(void **state)
{
	lfqueue_t q = lfqueue_create(3);
	assert_non_null(q);
	assert_int_equal(lfqueue_cap(q), 3);

	TIMER_INIT();

	TIMER_START();
	char *a = "a"; assert_int_equal(lfqueue_enqueue(q, a), 0);
	TIMER_STOP(1UL, "enqueue");
	assert_int_equal(lfqueue_length(q), 1);
	assert_int_equal(lfqueue_cap(q), 2);
	TIMER_RESTART();
	char *d_a = lfqueue_dequeue(q);
	TIMER_STOP(1UL, "dequeue");
	char *d_end = lfqueue_dequeue(q);
	assert_null(d_end);
	assert_int_equal(lfqueue_length(q), 0);
	assert_int_equal(lfqueue_cap(q), 3);
	assert_null(d_end);

	assert_int_equal(lfqueue_enqueue(q, a), 0);
	char *b = "b"; assert_int_equal(lfqueue_enqueue(q, b), 0);
	char *c = "c"; assert_int_equal(lfqueue_enqueue(q, c), 0);
	assert_int_not_equal(lfqueue_enqueue(q, c), 0);
	assert_int_equal(lfqueue_length(q), 3);
	assert_int_equal(lfqueue_cap(q), 0);

	d_a = lfqueue_dequeue(q);
	assert_string_equal(d_a, a);
	TIMER_RESTART();
	assert_int_equal(lfqueue_length(q), 2);
	TIMER_STOP(1UL, "length");
	char *d_b = lfqueue_dequeue(q);
	assert_int_equal(lfqueue_length(q), 1);
	assert_string_equal(d_b, b);
	char *d_c = lfqueue_dequeue(q);
	assert_string_equal(d_c, c);
	assert_int_equal(lfqueue_length(q), 0);
	assert_int_equal(lfqueue_cap(q), 3);
	d_end = lfqueue_dequeue(q);
	assert_int_equal(lfqueue_length(q), 0);
	assert_int_equal(lfqueue_cap(q), 3);
	assert_null(d_end);

	assert_int_equal(lfqueue_enqueue(q, a), 0);
	assert_int_equal(lfqueue_length(q), 1);

	d_a = lfqueue_dequeue(q);
	assert_string_equal(d_a, a);
	assert_int_equal(lfqueue_length(q), 0);

	d_end = lfqueue_dequeue(q);
	assert_int_equal(lfqueue_length(q), 0);
	assert_null(d_end);

	lfqueue_destroy(q);
}

int
main()
{
	const UnitTest tests[] = {
		unit_test(libhashtable_setup),
		unit_test(libhashtable_put),
		unit_test(libhashtable_replace),
		unit_test(libhashtable_remove),
		unit_test(libhashtable_stress),
		unit_test(libhashtable_lfqqueue),
		unit_test(libhashtable_teardown),
	};
	return run_tests(tests);
}
