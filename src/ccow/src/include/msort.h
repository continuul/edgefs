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

#ifndef __MSORT_H__
#define __MSORT_H__

/* Merge list node */
struct mlist_node {
	struct mlist_node *next, *cont;
	void *data;
};

/*
 * function to compare data withing the list
 * Returns < 0, if d < d2
 *         = 0, if d1 == d2
 *         > 0, if d1 > d2
 */
typedef int (*msort_compare_fn)(void *d1, void *d2);
typedef void (*msort_free_data_fn)(void *);
typedef void (*msort_dup_cb)(void*, struct mlist_node *);

struct mlist_node *
msort_merge_lists(struct mlist_node *l1, struct mlist_node *l2,
		  msort_compare_fn compare_cb);

struct mlist_node *
msort_merge_lists_nodup(struct mlist_node *l1, struct mlist_node *l2,
		  msort_compare_fn compare_cb, msort_dup_cb dup_cb, void* arg);

void msort_free_list(struct mlist_node *head, msort_free_data_fn free_cb);
#endif
