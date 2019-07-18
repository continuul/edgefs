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
#include <assert.h>

#include "ccowutil.h"
#include "msort.h"

/* Merge of two sorted lists (each list must have been sorted first) */
static struct mlist_node *
msort_merge_lists_common(struct mlist_node *l1, struct mlist_node *l2,
		  msort_compare_fn compare_cb, msort_dup_cb dup_cb, void* arg)
{
	int rc;

	if (!l1)
		return l2;
	if (!l2)
		return l1;

	assert(compare_cb != NULL);

	/* Set the merge list head */
	struct mlist_node *merge_head;
	rc = compare_cb(l1->data, l2->data);
	if (rc < 0)
		merge_head = l1;
	else {
		/* Switch the lists */
		merge_head = l2;
		l2 = l1;
		l1 = merge_head;
		if (!rc && dup_cb) {
			struct mlist_node *tmp = l2;
			l2 = l2->next;
			dup_cb(arg, tmp);
		}
	}

	/* Now merge the lists */
	while (l1->next && l2) {
		rc = compare_cb(l1->next->data, l2->data);
		if (rc > 0) {
			/* Switch the lists */
			struct mlist_node *tmp = l1->next;
			l1->next = l2;
			l2 = tmp;
		} else if (!rc && dup_cb) {
			struct mlist_node *tmp = l2;
			l2 = l2->next;
			dup_cb(arg, tmp);
		}
		l1 = l1->next;
	}
	if (!l1->next)
		l1->next = l2;

	return merge_head;
}

struct mlist_node *
msort_merge_lists(struct mlist_node *l1, struct mlist_node *l2,
		  msort_compare_fn compare_cb) {
	return msort_merge_lists_common(l1, l2, compare_cb, NULL, NULL);
}

struct mlist_node *
msort_merge_lists_nodup(struct mlist_node *l1, struct mlist_node *l2,
		  msort_compare_fn compare_cb, msort_dup_cb dup_cb, void* arg) {
	return msort_merge_lists_common(l1, l2, compare_cb, dup_cb, arg);
}


void
msort_free_list(struct mlist_node *head, msort_free_data_fn free_cb)
{
	struct mlist_node *node = head;

	while (node) {
		struct mlist_node *tmp = node->next;
		if (free_cb && node->data)
			free_cb(node->data);
		je_free(node);
		node = tmp;
	}
}
