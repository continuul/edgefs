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
#include <uv.h>

#include "../src/libccow/ccow-impl.h"
#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "cmcache.h"
#include "replicast.h"
#include "ccow.h"
#include "ccowd.h"
#define CMSIZE_MAX	8192

struct ccow *tc;
int dd = 0;

static void
libccowd_setup(void **state)
{
    if(!dd){
        assert_int_equal(ccow_daemon_init(NULL), 0);
        usleep(2 * 1000000L);
    }
}

static void
libccow_setup(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf;
	*state = buf = je_calloc(1, 16384);

	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);

	je_free(*state);
	*state = NULL;
}

static void
libchunk_cmcache_put(void **state)
{
	rtbuf_t *rb;

	struct refentry *re = je_malloc(sizeof (struct refentry));
	assert_non_null(re);

	re->offset = 0;
	re->length = 0x1000;

	uv_buf_t buf = { .base = (char *)re, .len = sizeof (struct refentry) };
	rb = rtbuf_init(&buf, 1);
	assert_non_null(rb);

	uint512_t k = { {{0, 1}, {0, 2}}, {{0, 3}, {0, 4}} };
	ccow_cmcache_put(tc->cmcache, &k, rb);
	rtbuf_destroy(rb);
}

static void
libchunk_cmcache_get(void **state)
{
	uint512_t k = { {{0, 1}, {0, 2}}, {{0, 3}, {0, 4}} };
	rtbuf_t *rl;
	int err = ccow_cmcache_get(tc->cmcache, &k, &rl);
	assert_int_equal(err, 1);
	assert_non_null(rl);
	rtbuf_destroy(rl);
}

static void
libccow_teardown(void **state)
{
	ccow_daemon_term(tc);
}

int
main(int argc, char **argv)
{
	if (argc == 2) {
		if (strcmp(argv[1], "-n") == 0)
			dd = 1;
	}

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(libchunk_cmcache_put),
		unit_test(libchunk_cmcache_get),
		unit_test(libccow_teardown),
	};
	return run_tests(tests);
}
