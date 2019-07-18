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

#include "rt_locks.h"
#include "cmocka.h"

static struct repdev test_dev;
struct ccow_obj_lock lk1, lk2, lk3, lk4, test_lk;

static inline void
set_lock(struct ccow_obj_lock *lk, uint8_t mode, char nhid,
	 uint64_t off, uint64_t len)
{
	memset(lk, 0, sizeof(*lk));
	lk->lk_mode = mode;
	memset(&lk->lk_nhid, nhid, sizeof(lk->lk_nhid));
	lk->lk_region.off = off;
	lk->lk_region.len = len;
}

static inline void
set_lock_region(struct ccow_obj_lock *lk, uint64_t off, uint64_t len)
{
	lk->lk_region.off = off;
	lk->lk_region.len = len;
}

static void
locks_test_diff_objs_ex_overlap()
{
	set_lock(&lk1, CCOW_LOCK_EXCL, 'a', 0, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	set_lock(&lk2, CCOW_LOCK_EXCL, 'b', 0, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 1);

	rt_remove_lock(&test_dev, &lk1);
	rt_remove_lock(&test_dev, &lk2);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);
}

static void
locks_test_ex_sh_non_overlap()
{
	set_lock(&lk1, CCOW_LOCK_SHARED, 'a', 0, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	set_lock(&lk2, CCOW_LOCK_EXCL, 'a', 200, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 1);

	rt_remove_lock(&test_dev, &lk1);
	rt_remove_lock(&test_dev, &lk2);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);
}

static void
locks_test_is_locked()
{
	set_lock(&lk1, CCOW_LOCK_EXCL, 'a', 0, 100);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);

	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	set_lock(&lk2, CCOW_LOCK_EXCL, 'a', 200, 100);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);

	rt_remove_lock(&test_dev, &lk1);
	assert_int_equal(lk1.lk_ref_count, 0);
}

static void
locks_test_ex_non_overlap()
{
	set_lock(&lk1, CCOW_LOCK_EXCL, 'a', 0, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	set_lock(&lk2, CCOW_LOCK_EXCL, 'a', 200, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 1);

	rt_remove_lock(&test_dev, &lk1);
	rt_remove_lock(&test_dev, &lk2);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);
}

static void
locks_test_ex_sh_overlap()
{
	int err;

	set_lock(&lk1, CCOW_LOCK_SHARED, 'a', 0, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	set_lock(&lk2, CCOW_LOCK_EXCL, 'a', 50, 100);
	err = rt_add_lock(&test_dev, &lk2, NULL);
	assert_int_equal(err, -16);

	rt_remove_lock(&test_dev, &lk1);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);

	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);
	rt_remove_lock(&test_dev, &lk2);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);
}

static void
locks_test_sh_overlap()
{
	/* 1. Region to be locked is subset of already locked region */
	/* R1 - [0, 100), R2 - [20, 30) */
	set_lock(&lk1, CCOW_LOCK_SHARED, 'a', 0, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	set_lock(&lk2, CCOW_LOCK_SHARED, 'a', 20, 30);
	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 1);

	rt_remove_lock(&test_dev, &lk1);

	assert_int_equal(rt_is_locked(&test_dev, &lk2), 1);
	rt_remove_lock(&test_dev, &lk2);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);

	/* 2. Region to be locked intersects already locked region */
	/* R1 - [0, 100), R2 - [50, 100) */
	set_lock(&lk1, CCOW_LOCK_SHARED, 'a', 0, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	set_lock(&lk2, CCOW_LOCK_SHARED, 'a', 50, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 1);

	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 0, 50);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 50, 100);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 100, 50);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);

	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 1000, 50);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 0);

	/* Adding lock may modify the contents of the locks */
	set_lock_region(&test_lk, 0, 100);
	rt_remove_lock(&test_dev, &test_lk);

	set_lock_region(&test_lk, 50, 100);
	rt_remove_lock(&test_dev, &test_lk);

	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);

	/* 3. Region to be locked is superset of already locked region(s) */
	/* R1 - [50, 50), R2 - [0, 200) */
	set_lock(&lk1, CCOW_LOCK_SHARED, 'a', 50, 50);
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	set_lock(&lk2, CCOW_LOCK_SHARED, 'a', 0, 200);
	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);

	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 0, 50);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 50, 100);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 100, 100);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);

	/* Adding lock may modify the contents of the locks */
	set_lock_region(&test_lk, 50, 50);
	rt_remove_lock(&test_dev, &test_lk);

	set_lock_region(&test_lk, 0, 200);
	rt_remove_lock(&test_dev, &test_lk);

	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);

	/*
	 * 4. Region to be locked is superset of already locked region(s) and
	 *    also intersects with a already locked region
	 */
	/* R1 - [20, 30), R2 - [60, 20), R3 - [100, 50), R4 - [0, 120) */
	set_lock(&lk1, CCOW_LOCK_SHARED, 'a', 20, 30);
	set_lock(&lk2, CCOW_LOCK_SHARED, 'a', 60, 20);
	set_lock(&lk3, CCOW_LOCK_SHARED, 'a', 100, 50);
	set_lock(&lk4, CCOW_LOCK_SHARED, 'a', 0, 120);

	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);
	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 1);
	assert_int_equal(rt_add_lock(&test_dev, &lk3, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk3), 1);
	assert_int_equal(rt_add_lock(&test_dev, &lk4, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk4), 1);

	/* Adding lock may modify the contents of the locks. Hence use test lock */
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 0, 20);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 20, 30);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 50, 10);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 60, 20);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 80, 40);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);
	set_lock(&test_lk, CCOW_LOCK_SHARED, 'a', 120, 30);
	assert_int_equal(rt_is_locked(&test_dev, &test_lk), 1);

	/* Adding lock may modify the contents of the locks. Hence use test lock */
	set_lock_region(&test_lk, 20, 30);
	rt_remove_lock(&test_dev, &test_lk);
	set_lock_region(&test_lk, 60, 20);
	rt_remove_lock(&test_dev, &test_lk);
	set_lock_region(&test_lk, 100, 50);
	rt_remove_lock(&test_dev, &test_lk);
	set_lock_region(&test_lk, 0, 120);
	rt_remove_lock(&test_dev, &test_lk);

	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk3), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk4), 0);
}

static void
locks_test_boundary()
{
	/* Region1 0 - 99 [0, 100) */
	set_lock(&lk1, CCOW_LOCK_EXCL, 'a', 0, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	/* Region2 100 - 199 [100, 200) */
	set_lock(&lk2, CCOW_LOCK_EXCL, 'a', 100, 100);

	/* Test end of region1 and start of region2 */
	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 1);

	rt_remove_lock(&test_dev, &lk1);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);

	/* Test start of region2 and end of region1 (tests different code path) */
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);
	rt_remove_lock(&test_dev, &lk1);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);

	rt_remove_lock(&test_dev, &lk2);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);
}

static void
locks_test_ex_overlap()
{
	int err;

	set_lock(&lk1, CCOW_LOCK_EXCL, 'a', 0, 100);
	assert_int_equal(rt_add_lock(&test_dev, &lk1, NULL), 0);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 1);

	set_lock(&lk2, CCOW_LOCK_EXCL, 'a', 0, 100);
	err = rt_add_lock(&test_dev, &lk2, NULL);
	assert_int_equal(err, -16);

	rt_remove_lock(&test_dev, &lk1);
	assert_int_equal(rt_is_locked(&test_dev, &lk1), 0);

	assert_int_equal(rt_add_lock(&test_dev, &lk2, NULL), 0);
	rt_remove_lock(&test_dev, &lk2);
	assert_int_equal(rt_is_locked(&test_dev, &lk2), 0);
}

static void
locks_teardown()
{
	rt_locks_destroy(&test_dev);
}

static void
locks_setup()
{
	rt_locks_init(&test_dev);
}

int
main(int argc, char **argv)
{
	const UnitTest tests[] = {
		unit_test(locks_setup),
		unit_test(locks_test_ex_non_overlap),
		unit_test(locks_test_ex_sh_non_overlap),
		unit_test(locks_test_diff_objs_ex_overlap),
		unit_test(locks_test_ex_overlap),
		unit_test(locks_test_is_locked),
		unit_test(locks_test_boundary),
		unit_test(locks_test_sh_overlap),
		unit_test(locks_teardown)
	};

	return run_tests(tests);
}
