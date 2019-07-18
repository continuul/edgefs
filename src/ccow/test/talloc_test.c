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
#include <stdlib.h>
#include <jemalloc/jemalloc.h>

#include "cmocka.h"
#include "talloc.h"

static void
all_in_one(void **state)
{
	char* a = talloc( 3243, NULL );
	assert_non_null(a);
	char* b = talloc( 3243, a );
	assert_non_null(b);
	char* c = talloc( 3243, a );
	assert_non_null(c);
	char* d = talloc( 3243, b );
	assert_non_null(d);
	char* e = talloc( 3243, d );
	assert_non_null(e);
	char* f = talloc( 3243, d );
	assert_non_null(f);

	char* g = talloc( 3243, NULL );
	assert_non_null(g);
	char* h = talloc( 3243, g );
	assert_non_null(h);
	char* i = talloc( 3243, h );
	assert_non_null(i);
	char* j = talloc( 3243, h );
	assert_non_null(j);
	char* k = talloc( 3243, j );
	assert_non_null(k);

	c = trealloc( c, 12345 );
	assert_non_null(c);
	d = trealloc( d, 12345 );
	assert_non_null(d);
	e = trealloc( e, 12345 );
	assert_non_null(e);

	g = trealloc( g, 12345 );
	assert_non_null(g);
	j = trealloc( j, 12345 );
	assert_non_null(j);
	j = trealloc( j, 12345 );
	assert_non_null(j);
	i = trealloc( i, 12345 );
	assert_non_null(i);

	talloc_steal( h, g ); /* same as talloc_steal( h, talloc_get_parent(h) ); */

	tfree(a);
	tfree(j);
	tfree(g);

	((int*)h)[123] = 456;
	tfree(h);

	(void)f;
	(void)k;
}

static void
je_malloc_free(void **state)
{
	void *buf1 = malloc(128);
	free(buf1);
	void *buf2 = malloc(128);
// This may fail under malloc
//	assert_true(buf1 != buf2);
	free(buf2);
}

int
main()
{
	const UnitTest tests[] = {
		unit_test(all_in_one),
		unit_test(je_malloc_free),
	};
	return run_tests(tests);
}
