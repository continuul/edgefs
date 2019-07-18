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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "cmocka.h"
#include "ccowutil.h"
#include "msort.h"

static int
cmp_test(void *data1, void *data2)
{
	int a = (intptr_t)data1;
	int b = (intptr_t)data2;

	return a - b;
}

static int
cmp_test_rev(void *data1, void *data2)
{
	int a = (intptr_t)data1;
	int b = (intptr_t)data2;

	return b - a;
}

static struct mlist_node *
build_list(int data[], int nele)
{
	struct mlist_node *head = NULL, *node;

	for (int i = 0; i < nele; i++) {
		node = je_calloc(1, sizeof(*node));
		assert_non_null(node);
		node->data = (void *)(unsigned long)data[i];
		node->next = head;
		head = node;
	}

	return head;
}

void
print_list(struct mlist_node *head)
{
	assert_non_null(head);
	struct mlist_node *node = head;

	for (node = head; node != NULL; node = node->next)
		printf("%ld ", (intptr_t)node->data);

	printf("\n");
}

static void
destroy_list(struct mlist_node *head)
{
	assert_non_null(head);
	msort_free_list(head, NULL);
}

static void
msort_unordered_1()
{
	struct mlist_node *l1, *l2, *m;
	int data1[3] = { 5, 3, 1 };
	int data2[3] = { 6, 4, 2 };

	l1 = build_list(data1, sizeof(data1)/sizeof(data1[0]));
	print_list(l1);

	l2 = build_list(data2, sizeof(data2)/sizeof(data2[0]));
	print_list(l2);

	printf("Merging two sorted lists\n");
	m = msort_merge_lists(l1, l2, cmp_test);
	print_list(m);
	destroy_list(m);
}

static void
msort_unordered_2()
{
	struct mlist_node *l1 = NULL, *l2, *m;
	int data2[3] = { 3, 2, 1 };

	printf("First list empty\n");
	l2 = build_list(data2, sizeof(data2)/sizeof(data2[0]));
	print_list(l2);

	m = msort_merge_lists(l1, l2, cmp_test);
	print_list(m);
	destroy_list(m);
}

static void
msort_ordered()
{
	struct mlist_node *l1, *l2, *m;
	int data1[3] = { 3, 2, 1 };
	int data2[4] = { 7, 6, 5, 4 };

	l1 = build_list(data1, sizeof(data1)/sizeof(data1[0]));
	print_list(l1);

	l2 = build_list(data2, sizeof(data2)/sizeof(data2[0]));
	print_list(l2);

	printf("Merging two sorted lists\n");
	m = msort_merge_lists(l1, l2, cmp_test);
	print_list(m);
	destroy_list(m);
}

static void
msort_ordered_reverse()
{
	struct mlist_node *l1, *l2, *m;
	int data1[3] = { 1, 2, 3 };
	int data2[4] = { 4, 5, 6, 7 };

	l1 = build_list(data1, sizeof(data1)/sizeof(data1[0]));
	print_list(l1);

	l2 = build_list(data2, sizeof(data2)/sizeof(data2[0]));
	print_list(l2);

	printf("Merging two pre-sorted lists in reverse\n");
	m = msort_merge_lists(l1, l2, cmp_test_rev);
	print_list(m);
	destroy_list(m);
}

static void
msort_duplicates()
{
	struct mlist_node *l1, *l2, *m;
	int data1[3] = { 4, 2, 1 };
	int data2[5] = { 8, 6, 5, 4, 3 };

	l1 = build_list(data1, sizeof(data1)/sizeof(data1[0]));
	print_list(l1);

	l2 = build_list(data2, sizeof(data2)/sizeof(data2[0]));
	print_list(l2);

	printf("Merging two sorted lists\n");
	m = msort_merge_lists(l1, l2, cmp_test);
	print_list(m);
	destroy_list(m);
}


static void
msort_test_dup_cb(void* arg, struct mlist_node *node) {
	int* cnt = (int*) arg;
	++(*cnt);
}

static void
msort_duplicates1()
{
	struct mlist_node *l1, *l2, *m;
	int data1[] = { 99, 8, 6, 5, 4, 3 };
	int data2[] = { 99, 8, 6, 5, 4, 3 };
	int n_dup = 0;

	l1 = build_list(data1, sizeof(data1)/sizeof(data1[0]));
	print_list(l1);

	l2 = build_list(data2, sizeof(data2)/sizeof(data2[0]));
	print_list(l2);

	printf("Merging two sorted lists (nodups)\n");
	m = msort_merge_lists_nodup(l1, l2, cmp_test, msort_test_dup_cb, &n_dup);
	printf("Skipped %d duplicates\n", n_dup);
	print_list(m);
	destroy_list(m);
}

static void
msort_duplicates2()
{
	struct mlist_node *l1, *l2, *m;
	int data1[] = { 78, 15, 3 };
	int data2[] = { 99, 8, 6, 5, 4, 3 };
	int n_dup = 0;

	l1 = build_list(data1, sizeof(data1)/sizeof(data1[0]));
	print_list(l1);

	l2 = build_list(data2, sizeof(data2)/sizeof(data2[0]));
	print_list(l2);

	printf("Merging two sorted lists (nodups)\n");
	m = msort_merge_lists_nodup(l1, l2, cmp_test, msort_test_dup_cb, &n_dup);
	printf("Skipped %d duplicates\n", n_dup);
	print_list(m);
	destroy_list(m);
}

static void
msort_duplicates3()
{
	struct mlist_node *l1, *l2, *m;
	int data1[] = { 78, 44, 39, 32, 29, 20, 19, 15, 3,  };
	int data2[] = { 99, 8, 6, 5, 4, 3 };
	int n_dup = 0;

	l1 = build_list(data1, sizeof(data1)/sizeof(data1[0]));
	print_list(l1);

	l2 = build_list(data2, sizeof(data2)/sizeof(data2[0]));
	print_list(l2);

	printf("Merging two sorted lists (nodups)\n");
	m = msort_merge_lists_nodup(l1, l2, cmp_test, msort_test_dup_cb, &n_dup);
	printf("Skipped %d duplicates\n", n_dup);
	print_list(m);
	destroy_list(m);
}

int
main(int argc, char **argv)
{
	const UnitTest tests[] = {
		unit_test(msort_unordered_1),
		unit_test(msort_unordered_2),
		unit_test(msort_ordered),
		unit_test(msort_ordered_reverse),
		unit_test(msort_duplicates),
		unit_test(msort_duplicates1),
		unit_test(msort_duplicates2),
		unit_test(msort_duplicates3)
	};

	return run_tests(tests);
}
