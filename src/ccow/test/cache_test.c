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

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"

ccow_t tc;
static int other_daemon_running = 0;
static char *config_buf;
static char *cache_bucket = "cache-bucket-test";
static struct cminfo cmi;

static void
libccowd_setup(void **state)
{
	if (!other_daemon_running) {
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
	config_buf = je_calloc(1, 16384);
	assert_non_null(config_buf);
	assert_true(read(fd, config_buf, 16384) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_admin_init(config_buf, "", 1, &tc), 0);

	/* initialize 0x0 sys object */
	int err = ccow_system_init(tc);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	/* check if 0x0 sys object exists */
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 2, &c);
	assert_int_equal(err, 0);
	/* Get request on sysobject */

	get(tc, "", "", NULL, 0, 0, NULL, NULL, NULL);

	err = ccow_admin_pseudo_get("", 1, "svcs", 5, "", 1, "", 1, NULL, 0, 0,
	    CCOW_GET, c, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	/* create new global service */
	err = ccow_bucket_create(tc, cache_bucket, strlen(cache_bucket) + 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_admin_pseudo_get("", 1, "svcs", 5, cache_bucket, strlen(cache_bucket) + 1, "", 1, NULL,
	    0, 0, CCOW_GET, c, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, 1);
	assert_int_equal(err, 0);

}

static void
cache_obj_create(void **state)
{
	assert_non_null(tc);
	ccow_completion_t c;
	int err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	cmi.comp = c;
	strcpy(cmi.oid, "cache-test-obj");
	strcpy(cmi.chunkmap_type, "btree_map");
	cmi.btree_order = 4;
	cmi.fixed_bs = 256;

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
					(void *)cmi.chunkmap_type, NULL);
	assert_int_equal(err, 0);
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
					(void *)&cmi.fixed_bs, NULL);
	assert_int_equal(err, 0);
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
					(void *)&cmi.btree_order, NULL);
	assert_int_equal(err, 0);
	*state = &cmi;
}

static void
cache_obj_delete(void **state)
{
	assert_non_null(tc);
	struct cminfo *cmi_ptr = *state;

	assert_non_null(cmi_ptr);
	delete(tc, cache_bucket, cmi_ptr->oid, NULL, NULL);
}

static void
cache_test_unnamed_get(void **state)
{
	struct cminfo *cmi_ptr = *state;
	int err;
	size_t put_iovcnt = 2;
	size_t get_iovcnt = 2;
	size_t i;
	struct iovec *put_iov;
	struct iovec *get_iov;
	char *put_buf, *get_buf;

	assert_non_null(tc);
	put_iov = je_calloc(put_iovcnt, sizeof(*put_iov));
	get_iov = je_calloc(get_iovcnt, sizeof(*get_iov));
	assert_non_null(put_iov);
	assert_non_null(get_iov);

	put_buf = je_malloc(put_iovcnt * cmi_ptr->fixed_bs);
	get_buf = je_malloc(get_iovcnt * cmi_ptr->fixed_bs);
	assert_non_null(put_buf);
	assert_non_null(get_buf);

	for (i = 0; i < put_iovcnt; i++) {
		put_iov[i].iov_base = put_buf + i * cmi_ptr->fixed_bs;
		put_iov[i].iov_len = cmi_ptr->fixed_bs;
	}

	for (i = 0; i < get_iovcnt; i++) {
		get_iov[i].iov_base = get_buf + i * cmi_ptr->fixed_bs;
		get_iov[i].iov_len = cmi_ptr->fixed_bs;
	}

	/* Write data */
	put(tc, cache_bucket, cmi_ptr->oid, &put_iov[0], 1, 3 * cmi_ptr->fixed_bs, NULL, NULL);
	put(tc, cache_bucket, cmi_ptr->oid, &put_iov[1], 1, 5 * cmi_ptr->fixed_bs, NULL, NULL);

	/* Fetch some data */
	get(tc, cache_bucket, cmi_ptr->oid, &get_iov[0], 1, 3 * cmi_ptr->fixed_bs, NULL, NULL, NULL);
	get(tc, cache_bucket, cmi_ptr->oid, &get_iov[1], 1, 5 * cmi_ptr->fixed_bs, NULL, NULL, NULL);

	/* Compare data */
	err = memcmp(put_iov[0].iov_base, get_iov[0].iov_base, cmi_ptr->fixed_bs);
	assert_int_equal(err, 0);
	err = memcmp(put_iov[1].iov_base, get_iov[1].iov_base, cmi_ptr->fixed_bs);
	assert_int_equal(err, 0);
	je_free(put_buf);
	je_free(get_buf);
	je_free(put_iov);
	je_free(get_iov);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	int err = ccow_bucket_delete(tc, cache_bucket, strlen(cache_bucket) + 1);
	assert_int_equal(err, 0);
	if (config_buf)
		je_free(config_buf);
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state) {
	usleep(200000L);
	if (!other_daemon_running)
		ccow_daemon_term();
}

int
main(int argc, char **argv)
{
	if (argc == 2) {
		if (strcmp(argv[1], "-n") == 0) {
			other_daemon_running = 1;
		}
	}

	const UnitTest tests [] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test_setup(NULL, cache_obj_create),
		unit_test(cache_test_unnamed_get),
		unit_test_teardown(NULL, cache_obj_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)	
	};

	return run_tests(tests);
}
