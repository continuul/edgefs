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
#include <string.h>
#include <errno.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"

#define TEST_BUCKET_NAME "stress-btreemap-bucket-test"
ccow_t cl = NULL;

int SBTM_TEST_CHUNK_SIZE	= 1024;
int SBTM_TEST_ITERATIONS	= 1024;
int SBTM_TEST_BTREE_ORDER	=   64;
int SBTM_TEST_TIME              =    0;

uint64_t SBTM_TEST_MAX          =    0;

uint8_t SBTM_TEST_RANDOM        =    0;
uint8_t SBTM_TEST_VERBOSE       =    0;

char SBTM_TEST_OID[1024];

time_t START;
time_t NOW;

uint64_t SBTM_BATCH = 0;
uint64_t SBTM_BATCH_MAX = 0;
uint64_t SBTM_BATCH_SIZE = 10;

uint64_t SBTM_OFF_MAX = 1024 * 1024 * 1024L;
uint64_t * SBTM_OFF_BUF = NULL;
uint64_t SBTM_OFF_IDX = 0;
char * SBTM_OFF_LOG_NAME = "sbtm.log";

uint64_t SBTM_PUTS = 0;
uint64_t SBTM_GETS = 0;

int dd = 0;

/*
 * usage
 *
 * Display usage and exit.
 */
static void
usage(void)
{
	printf("\n"
	       "USAGE:\n"
	       "     ./stress_btreemap_test [-h] [-b batch_size] [-c chunk_size] [-i iteratations] \n"
	       "          [-m max_offset] [-o btree_order] [-r] [-s] [-t minutes]\n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -c   Specify the chunk size form of \"[0-9]+[GMKB]?\".\n"
	       "         (Defaults to 1024).\n"
	       "\n"
	       "    -i   Specify the number of iterations.\n"
	       "         (Defaults to 1024).\n"
	       "\n"
	       "    -m   Specify the max offset in form of \"[0-9]+[GMKB]?\".\n"
	       "         (Defaults to none).\n"
	       "\n"
	       "    -o   Specifiy the btree order.\n"
	       "         (Defaults to 128).\n"
	       "\n"
	       "    -r   Generate random offsets.\n"
	       "         (Defaults to sequential.)\n"
	       "\n"
	       "    -t   Specify time interval in form fo \"[0-9]+[HMS]?\".\n"
	       "         (Units defaults to minutes).\n"
	       "         (Supersedes -i option.)\n"
	       "    -b   Specify batch size.\n"
	       "         (Defaults to 10).\n"
	       "\n"
	       "    -v   Enable verbose debug outout.\n"
	       "\n");

	exit(EXIT_SUCCESS);
}

static void
btmt_get(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
	 size_t off, ccow_callback_t cb_async, void *arg, ccow_lookup_t *iter,
	 int expected)
{
	assert_non_null(cl);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);

	if (err != 0) {
		printf("ccow_create_completion returned error status %d \n", err);
	}
	assert_int_equal(err, 0);
	err = ccow_get(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov,
	    iovcnt, off, iter);

	if (err != 0) {
		printf("ccow_get returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);

	if (err != expected) {
		printf("ccow_wait returned error status %d \n", err);
	}
	assert_int_equal(err, expected);
}

void
btmt_put(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
	uint64_t off, ccow_callback_t cb_async, void *arg)
{
	assert_non_null(cl);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
	if (err != 0) {
		printf("ccow_create_completion returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_map";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
				       (void *) chunkmap_type, NULL);
	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	uint16_t order = SBTM_TEST_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		(void *)&order, NULL);
	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	err = ccow_put(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov,
	    iovcnt, off);
	if (err != 0) {
		printf("ccow_put returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	if (cb_async) {
		assert(0);
		return;
	}

	err = ccow_wait(c, -1);
	if (err != 0) {
		printf("ccow_wait returned error status %d \n", err);
	}
	assert_int_equal(err, 0);
}

static void
libccowd_setup(void **state)
{
	int err = 0;

	if(!dd){
		err = ccow_daemon_init(NULL);

		if (err != 0) {
			printf("ccow_daemon_init returned err = %d \n", err);
		}

		assert_int_equal(err, 0);
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
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
	je_free(buf);
}

static void
bucket_create(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_create(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	int err = ccow_bucket_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *		LBTM Test
 * =======================================================================
 */

static void
libbtreemap_noop(void **state)
{
	usleep(2 * 1000000L);
}

static void
libbtreemap_setup(void **state)
{
	assert_non_null(cl);
	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err != 0) {
		printf("ccow_create_completion returned error %d \n",
		    err);
	}
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_map";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)chunkmap_type, NULL);
	if (err != 0) {
		printf("ccow_ccow_attr_modify_default"
		    "returned error %d \n", err);
	}
	assert_int_equal(err, 0);

	uint16_t order = SBTM_TEST_BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		(void *)&order, NULL);
	if (err != 0) {
		printf("ccow_ccow_attr_modify_default"
		    "returned error %d \n", err);
	}
	assert_int_equal(err, 0);

	static struct cminfo cmi;
	cmi.comp = c;
	strcpy(cmi.oid, SBTM_TEST_OID);

	*state = &cmi;
}

static void
libbtreemap_teardown(void **state)
{
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
    if (SBTM_OFF_BUF)
	    je_free(SBTM_OFF_BUF);
    if(!dd){
        ccow_daemon_term();
    }
}

/*
 * sbtm_put
 *
 * Helper function to perform get on the object.
 */
static void
sbtm_put(void **state, uint64_t offset, size_t size, size_t count)
{
	assert_non_null(cl);
	struct cminfo *cmi = *state;
	size_t i;

	char *buffer;
	buffer = je_calloc(1, size * count);
	assert(buffer != NULL);

	size_t iovcnt = count;
	struct iovec *iov = je_calloc(iovcnt,
	    sizeof (struct iovec));
	assert_non_null(iov);

	for (i = 0; i < count; i++) {
		char *ptr = &buffer[i * size];

		sprintf(ptr, "%6.6zu: %10.10zu: %6.6zu: byte me world.",
		    (offset + (i * size)), size , count);

		iov[i].iov_base = ptr;
		iov[i].iov_len  = size;
	}

	btmt_put(cl, TEST_BUCKET_NAME, SBTM_TEST_OID, iov, iovcnt,
	    offset, NULL, NULL);
	je_free(iov);
	je_free(buffer);
}

/*
 * sbtm_get
 *
 * Helper function to perform get on the object.
 */
static void
sbtm_get(void **state, uint64_t offset, size_t size, size_t count,
	size_t exp_count)
{
	assert_non_null(cl);
	struct cminfo *cmi = *state;
	size_t i;

	char *buffer;
	buffer = je_calloc(1, size * count);
	assert(buffer != NULL);

	size_t iovcnt = count;
	struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);

	for (i = 0; i < count; i++) {
		iov[i].iov_base = &buffer[i * size];
		iov[i].iov_len  = size;
	}

	btmt_get(cl, TEST_BUCKET_NAME, SBTM_TEST_OID, iov, iovcnt,
	        offset, NULL, NULL, NULL, 0);

	char *tmp = (char *) je_calloc(1, size);
	assert(tmp != NULL);

	for (i = 0; i < count; i++) {
		sprintf(tmp, "%6.6zu: %10.10zu: %6.6zu: byte me world.",
		    (offset + (size * i)),
		    size, exp_count);

		char * ptr = &buffer[i * size];

		int rv = strcmp(ptr, tmp);

		if (rv != 0) {
			printf("data verification error \n"
			       "    wrote: \"%s\" \n"
			       "    read:  \"%s\" \n",
			       tmp, ptr);
			assert(0);
			assert_int_equal(rv, 0);
		}
	}
	je_free(iov);
	je_free(buffer);
	je_free(tmp);
}

/*
 * sbtm_do_puts
 */
static int
sbtm_do_puts(void **state)
{
	assert_non_null(cl);
	uint i = 0;
	uint64_t offset = 0;
	size_t size = SBTM_TEST_CHUNK_SIZE;

	int rv = 0;

	/*
	 * puts
	 */
	for (i = (SBTM_BATCH * SBTM_BATCH_SIZE);
		    i < ((SBTM_BATCH + 1) * SBTM_BATCH_SIZE); i++) {

		if (i == (SBTM_BATCH * SBTM_BATCH_SIZE)) {
			printf("PUT iteration %d. \n", i);
		}

		/*
		 * calculate offset
		 */
		if (SBTM_TEST_RANDOM) {
			offset = rand() % SBTM_OFF_MAX;
			offset *= SBTM_TEST_CHUNK_SIZE;
		} else {
			offset = (((SBTM_BATCH * SBTM_BATCH_SIZE) + SBTM_OFF_IDX) *
			    SBTM_TEST_CHUNK_SIZE);
		}

		if (SBTM_TEST_MAX != 0) {
			offset %= SBTM_TEST_MAX;
		}

		SBTM_OFF_BUF[SBTM_OFF_IDX++] = offset;

		if (SBTM_TEST_VERBOSE) {
			printf("PUT : i = %8.8d : offset = %20"PRId64" \n",
			    i, offset);
		}

		/*
		 * put
		 */
		sbtm_put(state, offset, size, 1);
		SBTM_PUTS++;
	}

	return rv;
}

/*
 * sbtm_do_gets
 */
static int
sbtm_do_gets(void **state)
{
	assert_non_null(cl);
	uint i = 0;
	uint64_t offset = 0;
	size_t size = SBTM_TEST_CHUNK_SIZE;
	int rv;

	/*
	 * gets
	 */
	for (i = (SBTM_BATCH * SBTM_BATCH_SIZE);
		    i < ((SBTM_BATCH + 1) * SBTM_BATCH_SIZE); i++) {

		if (i == (SBTM_BATCH * SBTM_BATCH_SIZE)) {
			printf("GET iteration %d. \n", i);
		}

		offset = SBTM_OFF_BUF[SBTM_OFF_IDX++];

		if (SBTM_TEST_MAX != 0)
			offset %= SBTM_TEST_MAX;

		if (SBTM_TEST_VERBOSE) {
			printf("GET : i = %8.8d : offset = %20"PRId64" \n",
			    i, offset);
		}

		sbtm_get(state, offset, size, 1, 1);
		SBTM_GETS++;
	}

	return 0;
}

static void
sbtm_unit_test(void **state) {

	srand(time(NULL));
	time(&START);

	SBTM_BATCH = 0;

	while (1) {

		if (SBTM_TEST_TIME != 0) {
			/*
			 * test is run with a time interval, done with puts if
			 * the interval has been reached.
			 */
			time(&NOW);
			if ((NOW - START) > SBTM_TEST_TIME) {
				break;
			}
		}

		// do a batch of puts

		SBTM_OFF_IDX = 0;
		sbtm_do_puts(state);

		// do a batch of gets

		SBTM_OFF_IDX = 0;
		sbtm_do_gets(state);

		SBTM_BATCH++;
		if (SBTM_BATCH >= SBTM_BATCH_MAX)
			break;
	}

	printf("%"PRId64" puts, %"PRId64" gets \n", SBTM_PUTS, SBTM_GETS);
}

/*
 * sbtm_convert_time
 *
 * convert a null terminated string in the form "[0-9]+[HMS]?" to the
 * corresponding number of seconds
 */
int sbtm_convert_time(const char * in_string)
{
	int rv = 0;
	size_t len = strlen(in_string);
	size_t factor = 1;
	char str[128];

	if ((len == 0) || (len > 127))
		return rv;

	strcpy(str, in_string);

	switch(str[len - 1]) {

	case 'H':
		factor = 3600;
		str[len - 1] = 0;
		break;

	case 'M':
		factor = 60;
		str[len - 1] = 0;
		break;

	case 'S':
		factor = 1;
		str[len - 1] = 0;
		break;

	default:
		if (('0' <= str[len - 1]) && (str[len - 1] <= '9')) {
			factor = 1;
		} else {
			usage();
		}
		break;
	}

	rv = factor * atoi(str);

	return rv;
}

/*
 * sbtm_convert_bytes
 *
 * convert a null terminated string in the form "[0-9]+[GMKB]?" to the
 * corresponding number of bytes.
 */
uint64_t sbtm_convert_bytes(const char * in_string)
{
	uint64_t rv = 0;
	size_t len = strlen(in_string);
	size_t factor = 1;
	char str[128];

	if ((len == 0) || (len > 127))
		return rv;

	strcpy(str, in_string);

	switch(str[len - 1]) {

	case 'G':
		factor *= 1024;

	case 'M':
		factor *= 1024;

	case 'K':
		factor *= 1024;

	case 'B':
		str[len - 1] = 0;
		break;

	default:
		break;
	}

	rv = factor * atoi(str);

	return rv;
}

/*
 * main
 */
int
main(int argc, char **argv)
{
	int opt = 0;

	/*
	 * parse command line options
	 */
	while ((opt = getopt(argc, argv, "hc:i:b:m:o:rt:vn")) != -1) {
		switch (opt) {

		case 'h':
			usage();
			break;
                case 'b':
                        SBTM_BATCH_SIZE = atoi(optarg);
                        break;
		case 'c':
			SBTM_TEST_CHUNK_SIZE = sbtm_convert_bytes(optarg);
			break;

		case 'i':
			SBTM_TEST_ITERATIONS = atoi(optarg);
			break;

		case 'm':
			SBTM_TEST_MAX = sbtm_convert_bytes(optarg);
			break;

		case 'o':
			SBTM_TEST_BTREE_ORDER = atoi(optarg);
			break;

		case 'r':
			SBTM_TEST_RANDOM = 1;
			break;

		case 't':
			SBTM_TEST_TIME = sbtm_convert_time(optarg);
			break;

		case 'v':
			SBTM_TEST_VERBOSE = 1;
			break;

		case 'n':
			dd = 1;
			break;

		default:
			usage();
			break;
		}
	}


	SBTM_OFF_BUF = je_calloc(SBTM_BATCH_SIZE, sizeof(uint64_t));
	assert(SBTM_OFF_BUF);

	memset(SBTM_TEST_OID, 0 , 1024);
	sprintf(SBTM_TEST_OID, "sbtm-test-btree-%d-%d-%d",
	    SBTM_TEST_CHUNK_SIZE, SBTM_TEST_ITERATIONS, SBTM_TEST_BTREE_ORDER);

	if (SBTM_TEST_VERBOSE) {
		printf("Chunk Size  = %d \n"
		       "Iterations  = %d \n"
		       "Btree Order = %d \n"
		       "Run Time    = %d \n"
		       "Object ID   = \"%s\" \n"
		       "Max offset  = %"PRIu64" \n"
		       "Random      = %d \n",
		    SBTM_TEST_CHUNK_SIZE, SBTM_TEST_ITERATIONS, SBTM_TEST_BTREE_ORDER,
		    SBTM_TEST_TIME, SBTM_TEST_OID, SBTM_TEST_MAX, SBTM_TEST_RANDOM);
	}

	SBTM_BATCH = 0;
	SBTM_BATCH_MAX = ((SBTM_TEST_ITERATIONS - 1) / SBTM_BATCH_SIZE) + 1;

	/*
	 * tests
	 */
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),

		unit_test_setup(libbtreemap_noop, libbtreemap_setup),
		unit_test(sbtm_unit_test),
		unit_test_teardown(libbtreemap_noop, libbtreemap_teardown),

//		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
