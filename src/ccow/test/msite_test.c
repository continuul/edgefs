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
/** @file Multi-bucket multi-site test. Should be used after cluster_test only. */

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "ccowd.h"

static int daemon_initialized = 0, dd = 0;
static char *config_buf = NULL;

static void
libccowd_setup(void **state)
{
	if (!dd) {
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(2 * 1000000L);
	}
	daemon_initialized = 1;
}

static void
create_service(ccow_t adm_tc, const char *bucket_id, const char *destination,
		struct iovec *iov_serve, unsigned iov_size);

static void
libccow_setup(void **state)
{
	ccow_t adm_tc;

	assert_int_equal(daemon_initialized, 1);
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);

	enum { E_CONFIG_BUF_SIZE = 16384 };
	config_buf = je_calloc(1, E_CONFIG_BUF_SIZE);
	assert_non_null(config_buf);
	assert_true(read(fd, config_buf, E_CONFIG_BUF_SIZE) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_admin_init(config_buf, "", 1, &adm_tc), 0);

	char bucket1_1[] = "cltest/test/svcbk1";   //< for msite_file_test.js
	char bucket2_1[] = "cltest/test/svcbk2_1";
	char bucket2_2[] = "cltest/test/svcbk2_2";
	char bucket3_1[] = "cltest/test/svcbk3_1";
	char bucket3_2[] = "cltest/test/svcbk3_2";
	char bucket3_3[] = "cltest/test/svcbk3_3";

	//< iov_serve_1 is dedicated for msite_file_test.js
	struct iovec iov_serve_1[1] = {{ .iov_base = bucket1_1, .iov_len = strlen(bucket1_1) + 1 }};

	struct iovec iov_serve_2[2] = {{ .iov_base = bucket2_1, .iov_len = strlen(bucket2_1) + 1 },
	                               { .iov_base = bucket2_2, .iov_len = strlen(bucket2_2) + 1 }};
	struct iovec iov_serve_3[3] = {{ .iov_base = bucket3_1, .iov_len = strlen(bucket3_1) + 1 },
	                               { .iov_base = bucket3_2, .iov_len = strlen(bucket3_2) + 1 },
	                               { .iov_base = bucket3_3, .iov_len = strlen(bucket3_3) + 1 }};

	/* create new global services */
	create_service(adm_tc, "svctest1", "file:///tmp/isgw.tmp", iov_serve_1, 1); //< for msite_file_test.js
	create_service(adm_tc, "svctest2", "file:///tmp/isgw2.tmp", iov_serve_2, 2);
	create_service(adm_tc, "svctest3", "file:///tmp/isgw3.tmp", iov_serve_3, 3);

	ccow_tenant_term(adm_tc);
}

static void
create_service(ccow_t adm_tc, const char *bucket_id, const char *destination,
		struct iovec *iov_serve, unsigned iov_size)
{
	int err;

	ccow_completion_t svcs_comp;
	err = ccow_create_completion(adm_tc, NULL, NULL, 7, &svcs_comp);
	assert_int_equal(err, 0);

	err = ccow_admin_pseudo_get("", 1, "svcs", 5, "", 1, "", 1, NULL, 0, 0,
	    CCOW_GET, svcs_comp, NULL);
	assert_int_equal(err, 0);

	unsigned ccow_wait_idx = 0;
	err = ccow_wait(svcs_comp, ccow_wait_idx); ccow_wait_idx ++;
	assert_int_equal(err, 0);

	err = ccow_bucket_create(adm_tc, bucket_id, strlen(bucket_id)+1, svcs_comp);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	ccow_lookup_t iter = NULL;
	err = ccow_admin_pseudo_get("", 1, "svcs", 5, bucket_id, strlen(bucket_id)+1, "", 1, NULL,
	    0, 0, CCOW_GET, svcs_comp, &iter);
	assert_int_equal(err, 0);

	err = ccow_wait(svcs_comp, ccow_wait_idx); ccow_wait_idx ++;
	assert_int_equal(err, 0);

	char *isgw_keys[] = {"X-ISGW-Remote", "X-Status"};
	const char *isgw_values[] = {destination, "enabled"};
	for (int i = 0; i< 2; i++) {
		err = ccow_attr_modify_custom(svcs_comp, CCOW_KVTYPE_RAW,
		    isgw_keys[i], strlen(isgw_keys[i]) + 1,
		    (void *)isgw_values[i], strlen(isgw_values[i]) + 1, iter);
		assert_int_equal(err, 0);
	}

	ccow_lookup_release(iter);

	err = ccow_admin_pseudo_put("", 1, "svcs", 5, bucket_id, strlen(bucket_id) + 1, "", 1, NULL,
	    0, 0, CCOW_PUT, NULL, svcs_comp);
	assert_int_equal(err, 0);

	err = ccow_wait(svcs_comp, ccow_wait_idx); ccow_wait_idx ++;
	assert_int_equal(err == 0 || err == -EEXIST, 1);

	for (unsigned i = 0; i<iov_size; i++) {
		err = ccow_insert_list(bucket_id, strlen(bucket_id) + 1, "", 1, svcs_comp, iov_serve + i, 1);
		assert_int_equal(err, 0);

		err = ccow_wait(svcs_comp, ccow_wait_idx); ccow_wait_idx ++;
		assert_int_equal(err == 0 || err == -EEXIST, 1);
	}

	ccow_release(svcs_comp);
}

static void
buckets_create(void **state)
{
	int err;
	ccow_t tc_tmp;
	assert_int_equal(ccow_tenant_init(config_buf, "cltest", 7, "test", 5, &tc_tmp), 0);

	err = ccow_bucket_create(tc_tmp, "svcbk1", 7, NULL); //< for msite_file_test.js
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	err = ccow_bucket_create(tc_tmp, "svcbk2_1", 9, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	err = ccow_bucket_create(tc_tmp, "svcbk2_2", 9, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	err = ccow_bucket_create(tc_tmp, "svcbk3_1", 9, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	err = ccow_bucket_create(tc_tmp, "svcbk3_2", 9, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	err = ccow_bucket_create(tc_tmp, "svcbk3_3", 9, NULL);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	ccow_tenant_term(tc_tmp);
}
static void
libccow_teardown(void **state)
{
	if (config_buf)
		je_free(config_buf);
}

static void
libccowd_teardown(void **state) {
	usleep(200000L);
	if (dd != 1) {
		assert_int_equal(daemon_initialized, 1);
		ccow_daemon_term();
	}
}

int
main(int argc, char **argv)
{
	/*
	 * Parse command line
	 */
	int opt = 0;

	while ((opt = getopt(argc, argv, "n")) != -1) {
		switch(opt) {
			case 'n':
				dd = 1;
				daemon_initialized = 1;
				break;

			default:
				break;
		}
	}

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(buckets_create),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
