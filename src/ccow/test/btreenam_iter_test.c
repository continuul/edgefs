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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"


#define TEST_BTREE_ORDER	4
#define LBTN_BID		"lbtn-bucket"

uint8_t  LBTN_VERBOSE		= 0;
int32_t  LBTN_COUNT		= 128;
int32_t  LBTN_COUNT_2		= 100;
int32_t  LBTN_COUNT_3		= 128;
int32_t  LBTN_LOOKUP		=  16;

#define VPRINT(_fmt, _args...)							\
{										\
	if (LBTN_VERBOSE) {							\
		printf(_fmt, ## _args);						\
	}									\
}

static ccow_t cl = NULL;
static int dd = 0;

// ----------------------------------------------------------------------------
// setup and tear down functions
// ----------------------------------------------------------------------------
static void
libccowd_setup(void **state)
{
	if(!dd){
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(2 * 1000000L);
	}
}

static void
libccowd_teardown(void **state)
{
	if (!dd) {
		ccow_daemon_term();
	}
}

static void
libccow_setup(void **state)
{
	char *buf;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
	je_free(buf);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}


// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------
static void
create_list(void **state)
{
	int  i;

	for (i = 0; i < LBTN_COUNT; i++) {
		int iovcnt = 1;
		struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
		assert_non_null(iov);

		iov[0].iov_base = je_calloc(1, 1024);
		assert_non_null(iov[0].iov_base);
		snprintf(iov[0].iov_base, 1024, "%s_%5.5d", "LBTN_OBJECT", i);
		iov[0].iov_len = strlen(iov[0].iov_base) + 1;
		VPRINT("Updating Bucket with following: %s \n", (char *)iov[0].iov_base);

		ccow_completion_t c;
		int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		uint16_t order = TEST_BTREE_ORDER;
		err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		    (void *) &order, NULL);
		assert_int_equal(err, 0);

		err = ccow_insert_list(LBTN_BID, strlen(LBTN_BID) + 1,
		    "", 1, c, iov, 1);
		if (err != 0) {
			printf("ccow_insert_list returned %d, expected %d \n", err, 0);
		}

		err = ccow_wait(c, -1);
		if ((err != 0) && (err != -EEXIST)) {
			printf("ccow_wait returned %d, expected %d \n", err, 0);
			assert_int_equal(err, 0);
		}

		je_free(iov[0].iov_base);
		je_free(iov);

	}
}

static void
delete_list(void **state)
{
	int  i;

	for (i = 0; i < LBTN_COUNT; i++) {
		int iovcnt = 1;
		struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
		assert_non_null(iov);

		iov[0].iov_base = je_calloc(1, 1024);
		assert_non_null(iov[0].iov_base);
		snprintf(iov[0].iov_base, 1024, "%s_%5.5d", "LBTN_OBJECT", i);
		iov[0].iov_len = strlen(iov[0].iov_base) + 1;
		VPRINT("Deleting Bucket with following: %s \n", (char *)iov[0].iov_base);

		ccow_completion_t c;
		int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		err = ccow_delete_list(LBTN_BID, strlen(LBTN_BID) + 1,
		    "", 1, c, iov, 1);
		if (err != 0) {
			printf("ccow_delete_list returned %d, expected %d \n", err, 0);
		}

		err = ccow_wait(c, -1);
		if ((err != 0) && (err != -ENOENT)) {
			printf("ccow_wait returned %d, expected %d \n", err, 0);
			assert_int_equal(err, 0);
		}

		je_free(iov[0].iov_base);
		je_free(iov);

	}
}
static void look_up(void **state)
{
	assert_non_null(cl);
	int err;

	ccow_lookup_t iter;
	ccow_completion_t c;
	char buf[1024];

	for (int i = 0; i < 1; i++) {
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		struct iovec iov = { .iov_base = "", iov.iov_len = 1};

		err = ccow_get_list(LBTN_BID, strlen(LBTN_BID) + 1, "", 1,
		    c, &iov, 1, LBTN_LOOKUP, &iter);
		if (err) {
			ccow_release(c);
			return;
		}

		err = ccow_wait(c, -1);
		assert_int_equal(err, 0);

		dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);
		ccow_lookup_release(iter);
	}


	// Try to get the key in the middle
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	snprintf(buf, sizeof(buf), "%s_%5.5d", "LBTN_OBJECT", LBTN_COUNT_2);
	printf("\nList from key: %s\n", buf);
	struct iovec iov1 = { .iov_base = buf };
	iov1.iov_len = strlen(buf) + 1;
	err = ccow_get_list(LBTN_BID, strlen(LBTN_BID) + 1, "", 1,
	    c, &iov1, 1, LBTN_LOOKUP, &iter);
	if (err) {
		ccow_release(c);
		return;
	}

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);

	ccow_lookup_release(iter);

	// Try to get the key in the middle where key does not exist
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	snprintf(buf, sizeof(buf), "%s_%5.5d-a", "LBTN_OBJECT", LBTN_COUNT_2);
	printf("\nList from key: %s\n", buf);
	iov1.iov_base = buf;
	iov1.iov_len = strlen(buf) + 1;

	err = ccow_get_list(LBTN_BID, strlen(LBTN_BID) + 1, "", 1,
	    c, &iov1, 1, LBTN_LOOKUP, &iter);
	if (err) {
		ccow_release(c);
		return;
	}

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);

	ccow_lookup_release(iter);

	// Try to get the key after last
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	snprintf(buf, sizeof(buf), "%s_%5.5d", "LBTN_OBJECT", LBTN_COUNT_3);
	printf("\nList from key: %s\n", buf);
	struct iovec iov2 = { .iov_base = buf };
	iov2.iov_len = strlen(buf) + 1;

	err = ccow_get_list(LBTN_BID, strlen(LBTN_BID) + 1, "", 1,
	    c, &iov2, 1, LBTN_LOOKUP, &iter);
	if (err) {
		ccow_release(c);
		return;
	}

	err = ccow_wait(c, -1);
	assert_int_equal(err, -ENOENT);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_NAME_INDEX);

	ccow_lookup_release(iter);


	usleep(5000000);		// sleep 5s
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------
static void
usage(void)
{
	printf("\n"
	       "USAGE:\n"
	       "     ./btreenam_iter_test [-h] [-i object_count] \n"
	       "          [-l lookup_count] \n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -i   Specify the number of objects.\n"
	       "         (Defaults to 128).\n"
	       "\n"
	       "    -l   Specify number of objects to fetch via ccow_get_list. \n"
	       "         (Defaults to 16).\n"
	       "\n"
	       "    -v   Enable verbose output.\n"
	       "\n");

	exit(EXIT_SUCCESS);
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------
int
main(int argc, char **argv)
{
	int opt = 0;

	/*
	 * parse command line options
	 */
	while ((opt = getopt(argc, argv, "nhi:l:v")) != -1) {
		switch (opt) {

		case 'h':
			usage();
			break;

		case 'i':
			LBTN_COUNT_3 = LBTN_COUNT = sst_convert_bytes(optarg);
			break;

		case 'l':
			LBTN_LOOKUP = sst_convert_bytes(optarg);
			break;

		case 'n':
			dd = 1;
			break;

		case 'v':
			LBTN_VERBOSE = 1;
			break;

		default:
			usage();
			break;
		}
	}

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),

		unit_test(create_list),
		unit_test(look_up),
		unit_test(delete_list),

		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};

	return run_tests(tests);
}
