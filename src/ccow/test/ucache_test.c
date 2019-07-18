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
#include <sys/sysinfo.h>
#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"
#include "ccow-impl.h"

ccow_t tc_0 = NULL;
ccow_t tc_1 = NULL;

ucache_t * uc_0 = NULL;
ucache_t * uc_1 = NULL;

static struct cminfo cmi;

/* **************************************************************************** 
 *
 * ***************************************************************************/ 
#define ASSIGN_CHID(_chid, _val)                                        \
        memset(&(_chid), 0, sizeof(uint512_t));                         \
	_chid.l.l.l = _val;

/* **************************************************************************** 
 *
 * ***************************************************************************/ 
#define	assert_ptr_equal(_a, _b)					\
	({								\
	int r = (_a == _b);						\
	assert_true(r);							\
	})

/* **************************************************************************** 
 *
 * ***************************************************************************/ 
static void
check(ucache_t * uc, int line)
{
	unsigned int i = 0;
	unsigned int t = 0;

	for (i = 0; i < uc->size_cur; i++) {
		t += uc->cache[i].count;
	}

	if (t != uc->lru_count) {
		printf("%s : %d : count mismatch, %d != %"PRId64" \n",
		    __FILE__, line, t, uc->lru_count);
	}

	assert_int_equal(t, uc->lru_count);
}

/* ****************************************************************************
 * put helper
 * ***************************************************************************/
static void
put_helper(ucache_t * uc, int i)
{
	uint512_t chid;
	uv_buf_t buf;
	char base[512];

	ASSIGN_CHID(chid, i);
	memset(base, 0, 512);
	sprintf(base, "CHID : %d ", i);

	buf.base = base;
	buf.len  = 512;

	ccow_ucache_put(uc, &chid, &buf, 1);
}

/* ****************************************************************************
 * libccow & libccowd setup & teardown
 * ***************************************************************************/
static void
libccowd_setup(void **state)
{
	lg = Logger_create("ccache_test_lg");

	ucache_test = 1;

	tc_0 = je_calloc(1, sizeof(*tc_0));
	assert_non_null(tc_0);

	tc_1 = je_calloc(1, sizeof(*tc_1));
	assert_non_null(tc_1);

	tc_0->tenant_ucache_size     = 8;
	tc_0->tenant_ucache_size_max = 32;
	tc_0->ucache_size_limit = UCACHE_SIZE_LIM;

	tc_1->tenant_ucache_size     = 8;
	tc_1->tenant_ucache_size_max = 32;
	tc_1->ucache_size_limit = UCACHE_SIZE_LIM;
}

static void
libccow_setup(void **state)
{
}

static void
libccow_teardown(void **state)
{
}

static void
libccowd_teardown(void **state) {
	je_free(tc_0);
	je_free(tc_1);
}

/* ****************************************************************************
 * create
 * ***************************************************************************/
static void
create_test(void **state)
{
	assert_non_null(tc_0);
	assert_non_null(tc_1);

	uc_0 = ccow_ucache_create(tc_0);
	assert_non_null(uc_0);
	tc_0->ucache = uc_0;

	uc_1 = ccow_ucache_create(tc_1);
	assert_non_null(uc_1);
	tc_1->ucache = uc_1;

	assert_non_null(uc_0->lru_q[0]);
	assert_non_null(uc_0->lru_q[1]);
	assert_ptr_equal(uc_0->lru_q[0], uc_0->lru_q[1]);
	assert_int_equal(uc_0->lru_count, 0);

	assert_non_null(uc_1->lru_q[0]);
	assert_non_null(uc_1->lru_q[1]);
	assert_ptr_equal(uc_1->lru_q[0], uc_1->lru_q[1]);
	assert_int_equal(uc_1->lru_count, 0);
}

/* ****************************************************************************
 * free
 * ***************************************************************************/
static void
free_test(void **state)
{
	assert_non_null(uc_0);
	assert_non_null(uc_1);

	ccow_ucache_free(uc_0->tc);
	ccow_ucache_free(uc_1->tc);
}

/* ****************************************************************************
 * put
 * ***************************************************************************/
static void
put_test(void **state)
{
	int i, t;
	uint512_t chid;
	uv_buf_t buf;
	char base[512];

	assert_non_null(tc_0);
	assert_non_null(tc_1);
	assert_non_null(uc_0);
	assert_non_null(uc_1);

	for (int i = 0; i < 8; i++) {
		assert_int_equal(uc_0->lru_count, i);
		put_helper(uc_0, i);
		assert_int_equal(uc_0->lru_count, i + 1);
	}

	check(uc_0, __LINE__);

	for (int i = 8; i < 16; i++) {
		assert_int_equal(uc_0->lru_count, 8);
		put_helper(uc_0, i);
		assert_int_equal(uc_0->lru_count, 8);
	}

	check(uc_0, __LINE__);
}

/* ****************************************************************************
 * expand
 * ***************************************************************************/
static void
expand_test(void **state)
{
	int i;

	assert_non_null(tc_0);
	assert_non_null(tc_1);
	assert_non_null(uc_0);
	assert_non_null(uc_1);

	assert_int_equal(uc_0->lru_count, 0);

	for (int i = 0; i < 4; i++) {
		assert_int_equal(uc_0->lru_count, i);
		put_helper(uc_0, i);
		assert_int_equal(uc_0->lru_count, i + 1);
	}

	check(uc_0, __LINE__);
	assert_int_equal(uc_0->lru_count, 4);

	ccow_ucache_expand(uc_0, UCACHE_FREE_SPACE_LIM);

	assert_int_equal(uc_0->size_cur, 8);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);

	for (int i = 4; i < 8; i++) {
		assert_int_equal(uc_0->lru_count, i);
		put_helper(uc_0, i);
		assert_int_equal(uc_0->lru_count, i + 1);
	}

	check(uc_0, __LINE__);

	ccow_ucache_expand(uc_0, UCACHE_FREE_SPACE_LIM);

	assert_int_equal(uc_0->size_cur, 16);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);

	for (int i = 8; i < 16; i++) {
		assert_int_equal(uc_0->lru_count, i);
		put_helper(uc_0, i);
		assert_int_equal(uc_0->lru_count, i + 1);
	}

	check(uc_0, __LINE__);

	ccow_ucache_expand(uc_0, UCACHE_FREE_SPACE_LIM);

	assert_int_equal(uc_0->size_cur, 24);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);

	for (int i = 16; i < 24; i++) {
		assert_int_equal(uc_0->lru_count, i);
		put_helper(uc_0, i);
		assert_int_equal(uc_0->lru_count, i + 1);
	}

	check(uc_0, __LINE__);

	ccow_ucache_expand(uc_0, UCACHE_FREE_SPACE_LIM);

	assert_int_equal(uc_0->size_cur, 32);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);

	for (int i = 24; i < 32; i++) {
		assert_int_equal(uc_0->lru_count, i);
		put_helper(uc_0, i);
		assert_int_equal(uc_0->lru_count, i + 1);
	}

	check(uc_0, __LINE__);

	ccow_ucache_expand(uc_0, UCACHE_FREE_SPACE_LIM);

	assert_int_equal(uc_0->size_cur, 32);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);

	ccow_ucache_expand(uc_0, UCACHE_FREE_SPACE_LIM - 10);

	assert_int_equal(uc_0->size_cur, 32);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);
}

/* ****************************************************************************
 * shrink
 * ***************************************************************************/
static void
shrink_test(void **state)
{
	int i;

	struct sysinfo si;
	int rv = sysinfo(&si);
	assert(rv == 0);

	double tr = si.totalram;
	double fr = si.freeram;
	double fp = (fr * 100)/tr;

	for (i = 0; i < 32; i++) {
		put_helper(uc_1, (i + 1000));
		if (i % 8 == 7) {
			ccow_ucache_expand(uc_1, UCACHE_FREE_SPACE_LIM);
		}
		check(uc_1, __LINE__);
	}

	ccow_ucache_expand(uc_1, UCACHE_FREE_SPACE_LIM - 10);
	check(uc_1, __LINE__);

	assert_int_equal(uc_1->size_cur, 32);
	assert_int_equal(uc_1->size_inc, 8);
	assert_int_equal(uc_1->size_min, 8);
	assert_int_equal(uc_1->size_max, 32);
	assert_int_equal(uc_1->lru_count, 32);

	assert_int_equal(uc_0->size_cur, 32);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);
	assert_int_equal(uc_0->lru_count, 32);

	ccow_ucache_shrink(uc_0, UCACHE_FREE_SPACE_LIM - 10);

	assert_int_equal(uc_0->size_cur, 24);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);
	assert_int_equal(uc_0->lru_count, 24);
}

/* ****************************************************************************
 * evict
 * ***************************************************************************/
static void
evict_test(void **state)
{
	assert_int_equal(uc_0->size_cur, 24);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);
	assert_int_equal(uc_0->lru_count, 24);

	assert_int_equal(uc_1->size_cur, 32);
	assert_int_equal(uc_1->size_inc, 8);
	assert_int_equal(uc_1->size_min, 8);
	assert_int_equal(uc_1->size_max, 32);
	assert_int_equal(uc_1->lru_count, 32);

	ccow_ucache_evict(uc_0, UCACHE_FREE_SPACE_LIM);
	ccow_ucache_evict(uc_1, UCACHE_FREE_SPACE_LIM);

	assert_int_equal(uc_0->size_cur, 24);
	assert_int_equal(uc_0->size_inc, 8);
	assert_int_equal(uc_0->size_min, 8);
	assert_int_equal(uc_0->size_max, 32);
	assert_int_equal(uc_0->lru_count, 24 - UCACHE_EVICT_COUNT);

	assert_int_equal(uc_1->size_cur, 32);
	assert_int_equal(uc_1->size_inc, 8);
	assert_int_equal(uc_1->size_min, 8);
	assert_int_equal(uc_1->size_max, 32);
	assert_int_equal(uc_1->lru_count, 32 - UCACHE_EVICT_COUNT);
}

/* ****************************************************************************
 * main
 * ***************************************************************************/
int
main(int argc, char **argv)
{
	const UnitTest tests [] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(create_test),
		unit_test(put_test),
		unit_test(free_test),
		unit_test(create_test),
		unit_test(expand_test),
		unit_test(shrink_test),
		unit_test(evict_test),
		unit_test(free_test),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};

	return run_tests(tests);
}
