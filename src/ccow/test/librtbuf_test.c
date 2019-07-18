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

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "rtbuf.h"

static void
init(void **state)
{
	uv_buf_t buf;
	buf.base = je_malloc(10);
	assert_non_null(buf.base);
	buf.len = 10;
	rtbuf_t *rb = rtbuf_init(&buf, 1);
	assert_non_null(rb);
	assert_int_equal(rb->nbufs, 1);
	assert_int_equal(rtbuf_len(rb), 10);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 0);

	uv_buf_t buf2;
	buf2.base = je_malloc(20);
	assert_non_null(buf2.base);
	buf2.len = 20;
	assert_int_equal(rtbuf_add(rb, &buf2, 1), 0);
	assert_int_equal(rb->nbufs, 2);
	assert_int_equal(rtbuf(rb, 0).len, 10);
	assert_int_equal(rtbuf(rb, 1).len, 20);
	assert_int_equal(rtbuf_len(rb), 30);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 0);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 0);

	uv_buf_t buf34[2];
	buf34[0].base = je_malloc(30);
	assert_non_null(buf34[0].base);
	buf34[0].len = 30;
	buf34[1].base = je_malloc(40);
	assert_non_null(buf34[1].base);
	buf34[1].len = 40;
	assert_int_equal(rtbuf_add(rb, buf34, 2), 0);
	assert_int_equal(rb->nbufs, 4);
	assert_int_equal(rtbuf(rb, 0).len, 10);
	assert_int_equal(rtbuf(rb, 1).len, 20);
	assert_int_equal(rtbuf(rb, 2).len, 30);
	assert_int_equal(rtbuf(rb, 3).len, 40);
	assert_int_equal(rtbuf_len(rb), 100);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 0);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 0);
	assert_int_equal(rb->attrs[2] & RTBUF_ATTR_MMAP, 0);
	assert_int_equal(rb->attrs[3] & RTBUF_ATTR_MMAP, 0);

//	uint512_t out;
//	assert_int_equal(rtbuf_hash(rb, HTYPE_SHA2_512, &out), 0);

	rtbuf_destroy(rb);
}

static void
init_mapped(void **state)
{
	char *mybuf = je_malloc(500);
	assert_non_null(mybuf);

	uv_buf_t buf;
	buf.base = mybuf;
	buf.len = 500;
	rtbuf_t *rb = rtbuf_init_mapped(&buf, 1);
	assert_non_null(rb);
	assert_int_equal(rb->nbufs, 1);
	assert_int_equal(rtbuf_len(rb), 500);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);

	uv_buf_t buf2;
	buf2.base = mybuf;
	buf2.len = 300;
	assert_int_equal(rtbuf_add_mapped(rb, &buf2, 1), 0);
	assert_int_equal(rb->nbufs, 2);
	assert_int_equal(rtbuf(rb, 0).len, 500);
	assert_int_equal(rtbuf(rb, 1).len, 300);
	assert_int_equal(rtbuf_len(rb), 800);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 1);

	uv_buf_t buf3;
	buf3.base = je_malloc(100);
	buf3.len = 100;
	assert_int_equal(rtbuf_add(rb, &buf3, 1), 0);
	assert_int_equal(rb->nbufs, 3);
	assert_int_equal(rtbuf(rb, 0).len, 500);
	assert_int_equal(rtbuf(rb, 1).len, 300);
	assert_int_equal(rtbuf(rb, 2).len, 100);
	assert_int_equal(rtbuf_len(rb), 900);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[2] & RTBUF_ATTR_MMAP, 0);

//	uint512_t out;
//	assert_int_equal(rtbuf_hash(rb, HTYPE_SHA2_512, &out), 0);

	rtbuf_destroy(rb);
	je_free(mybuf);
}

static void
init_alloc(void **state)
{
	rtbuf_t *rb = rtbuf_init_alloc_one(10);
	assert_non_null(rb);
	assert_int_equal(rb->nbufs, 1);
	assert_int_equal(rtbuf_len(rb), 10);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 0);

	uv_buf_t buf2;
	buf2.base = je_malloc(20);
	assert_non_null(buf2.base);
	buf2.len = 20;
	assert_int_equal(rtbuf_add_alloc(rb, &buf2, 1), 0);
	je_free(buf2.base);
	assert_int_equal(rb->nbufs, 2);
	assert_int_equal(rtbuf(rb, 0).len, 10);
	assert_int_equal(rtbuf(rb, 1).len, 20);
	assert_int_equal(rtbuf_len(rb), 30);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 0);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 0);

//	uint512_t out;
//	assert_int_equal(rtbuf_hash(rb, HTYPE_SHA2_512, &out), 0);

	rtbuf_destroy(rb);
}

static void
init_add_remove(void **state)
{
	char *mybuf = je_malloc(500);
	assert_non_null(mybuf);

	uv_buf_t buf;
	buf.base = mybuf;
	buf.len = 500;
	rtbuf_t *rb = rtbuf_init_mapped(&buf, 1);
	assert_non_null(rb);
	assert_int_equal(rb->nbufs, 1);
	assert_int_equal(rtbuf_len(rb), 500);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);

	uv_buf_t buf2;
	buf2.base = mybuf;
	buf2.len = 300;
	assert_int_equal(rtbuf_add_mapped(rb, &buf2, 1), 0);
	assert_int_equal(rb->nbufs, 2);
	assert_int_equal(rtbuf(rb, 0).len, 500);
	assert_int_equal(rtbuf(rb, 1).len, 300);
	assert_int_equal(rtbuf_len(rb), 800);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 1);

	uv_buf_t buf3;
	buf3.base = je_malloc(100);
	buf3.len = 100;
	assert_int_equal(rtbuf_add(rb, &buf3, 1), 0);
	assert_int_equal(rb->nbufs, 3);
	assert_int_equal(rtbuf(rb, 0).len, 500);
	assert_int_equal(rtbuf(rb, 1).len, 300);
	assert_int_equal(rtbuf(rb, 2).len, 100);
	assert_int_equal(rtbuf_len(rb), 900);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[2] & RTBUF_ATTR_MMAP, 0);
	/* Delete the 2nd element */
	assert_int_equal(rtbuf_delete_element(rb, 1), 0);
	/* Verify the new element is built properly */
	assert_int_equal(rb->nbufs, 2);
	assert_int_equal(rtbuf(rb, 0).len, 500);
	assert_int_equal(rtbuf(rb, 1).len, 100);
	assert_int_equal(rtbuf_len(rb), 600);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 0);

	rtbuf_destroy(rb);
	je_free(mybuf);
}

static void
init_destroy_empty(void **state)
{
	rtbuf_t *rb = rtbuf_init_empty();
	rtbuf_destroy(rb);
}

static void
init_add_remove_boundaries(void **state)
{
	char *mybuf = je_malloc(500);
	assert_non_null(mybuf);

	uv_buf_t buf;
	buf.base = mybuf;
	buf.len = 500;
	rtbuf_t *rb = rtbuf_init_mapped(&buf, 1);
	assert_non_null(rb);
	assert_int_equal(rb->nbufs, 1);
	assert_int_equal(rtbuf_len(rb), 500);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);

	uv_buf_t buf2;
	buf2.base = mybuf;
	buf2.len = 300;
	assert_int_equal(rtbuf_add_mapped(rb, &buf2, 1), 0);
	assert_int_equal(rb->nbufs, 2);
	assert_int_equal(rtbuf(rb, 0).len, 500);
	assert_int_equal(rtbuf(rb, 1).len, 300);
	assert_int_equal(rtbuf_len(rb), 800);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 1);

	uv_buf_t buf3;
	buf3.base = je_malloc(100);
	buf3.len = 100;
	assert_int_equal(rtbuf_add(rb, &buf3, 1), 0);
	assert_int_equal(rb->nbufs, 3);
	assert_int_equal(rtbuf(rb, 0).len, 500);
	assert_int_equal(rtbuf(rb, 1).len, 300);
	assert_int_equal(rtbuf(rb, 2).len, 100);
	assert_int_equal(rtbuf_len(rb), 900);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[2] & RTBUF_ATTR_MMAP, 0);

	/* Delete the 1st element */
	assert_int_equal(rtbuf_delete_element(rb, 0), 0);
	/* Verify the new element is built properly */
	assert_int_equal(rb->nbufs, 2);
	assert_int_equal(rtbuf(rb, 0).len, 300);
	assert_int_equal(rtbuf(rb, 1).len, 100);
	assert_int_equal(rtbuf_len(rb), 400);
	assert_int_equal(rb->attrs[0] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb->attrs[1] & RTBUF_ATTR_MMAP, 0);

	/* Delete the last element */
	assert_int_equal(rtbuf_delete_element(rb, 1), 0);
	/* Verify the new element is built properly */
	assert_int_equal(rb->nbufs, 1);
	assert_int_equal(rtbuf(rb, 0).len, 300);
	assert_int_equal(rtbuf_len(rb), 300);
	/* Delete the very element */
	assert_int_equal(rtbuf_delete_element(rb, 0), 0);

	rtbuf_destroy(rb);
	je_free(mybuf);
}


static void
init_chop(void **state)
{
	char *mybuf1 = je_malloc(500);
	assert_non_null(mybuf1);
	char *mybuf2 = je_malloc(500);
	assert_non_null(mybuf2);
	char *mybuf3 = je_malloc(500);
	assert_non_null(mybuf3);
	char *mybuf4 = je_malloc(500);
	assert_non_null(mybuf4);

	uv_buf_t buf1;
	buf1.base = mybuf1;
	buf1.len = 500;
	rtbuf_t *rb1 = rtbuf_init_mapped(&buf1, 1);
	assert_non_null(rb1);
	assert_int_equal(rb1->nbufs, 1);
	assert_int_equal(rtbuf_len(rb1), 500);
	assert_int_equal(rb1->attrs[0] & RTBUF_ATTR_MMAP, 1);

	uv_buf_t buf2;
	buf2.base = mybuf2;
	buf2.len = 500;
	assert_int_equal(rtbuf_add_mapped(rb1, &buf2, 1), 0);
	assert_int_equal(rb1->nbufs, 2);
	assert_int_equal(rtbuf(rb1, 0).len, 500);
	assert_int_equal(rtbuf(rb1, 1).len, 500);
	assert_int_equal(rtbuf_len(rb1), 1000);
	assert_int_equal(rb1->attrs[0] & RTBUF_ATTR_MMAP, 1);
	assert_int_equal(rb1->attrs[1] & RTBUF_ATTR_MMAP, 1);

	rtbuf_t *head = NULL, *tail;
	assert_int_equal(rtbuf_chop_mapped(rb1, 1024, &head, &tail), 0);
	assert_non_null(head);
	assert_null(tail);
	assert_int_equal(rtbuf_len(head), rtbuf_len(rb1));
	rtbuf_destroy(head);

	assert_int_equal(rtbuf_chop_mapped(rb1, 512, &head, &tail), 0);
	assert_non_null(head);
	assert_non_null(tail);
	assert_int_equal(rtbuf_len(head), 500);
	assert_int_equal(rtbuf_len(tail), 500);
	rtbuf_destroy(head);
	rtbuf_destroy(tail);

	assert_int_equal(rtbuf_chop_mapped(rb1, 500, &head, &tail), 0);
	assert_non_null(head);
	assert_non_null(tail);
	assert_int_equal(rtbuf_len(head), 500);
	assert_int_equal(rtbuf_len(tail), 500);
	rtbuf_destroy(head);
	rtbuf_destroy(tail);

	assert_int_equal(rtbuf_chop_mapped(rb1, 300, &head, &tail), 0);
	assert_non_null(head);
	assert_non_null(tail);
	assert_int_equal(rtbuf_len(head), 300);
	assert_int_equal(rtbuf_len(tail), 700);
	assert_int_equal(head->bufs[0].base, rb1->bufs[0].base);
	assert_int_equal(tail->bufs[0].base, rb1->bufs[0].base + 300);
	rtbuf_destroy(head);
	rtbuf_destroy(tail);

	rtbuf_destroy(rb1);
	je_free(mybuf1);
	je_free(mybuf2);
	je_free(mybuf3);
	je_free(mybuf4);
}

int
main()
{
	const UnitTest tests[] = {
		unit_test(init),
		unit_test(init_mapped),
		unit_test(init_alloc),
		unit_test(init_destroy_empty),
		unit_test(init_add_remove),
		unit_test(init_add_remove_boundaries),
		unit_test(init_chop),
	};
	return run_tests(tests);
}
