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
#include "btree.h"

#define TEST_BUCKET_NAME	"btreenam-stream-test-bucket"
char TEST_OBJECT_NAME[64];
uint32_t TEST_EC_ENABLE	= 0;
uint32_t TEST_RANDOM_KEYS = 0;
uint32_t OVERWRITE_SET = 0;
uint32_t CHUNK_SIZE = 1048576;
uint16_t ORDER = 4;
uint32_t GENERATE = 100;
uint32_t GENERATE_ONLY = 0;
uint32_t GENERATE_PREFIX_MOD = 10;


static uint32_t KEY_SIZE = 64;
static uint32_t VAL_SIZE = 32;


ccow_t cl = NULL;
int dd = 0;
int debug = 0;

/*
 * ============================================================================
 * usage
 * ============================================================================
 */
static void
usage(void)
{
	printf("\n"
	       "USAGE:\n"
	       "     ./btreenam_stream_test [-h] [-k key_size] [-v value_size] [-c chunk_size] [-o btree_order] [-g count] [-e] [-d]\n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -d   Enable debug mode.\n"
	       "\n"
	       "    -c   Specify chunk_size of in bytes.\n"
	       "         (defaults to %u).\n"
	       "\n"
	       "    -o   Specify btree_order.\n"
	       "         (defaults to %u).\n"
	       "\n"
	       "    -g   Specify test key/value set size, that will be preserved after test finish.\n"
	       "         (defaults to %u).\n"
	       "\n"
	       "    -p   Specify generated prefix modula number. Used with -g.\n"
	       "         (defaults to %u).\n"
	       "\n"
	       "    -k   Specify size of key in bytes.\n"
	       "         (defaults to %d).\n"
	       "\n"
	       "    -v   Specify size of value in bytes.\n"
	       "         (defaults to %d).\n"
	       "\n"
	       "    -e   Enable erasure coding.\n"
	       "         (defaults to false).\n"
	       "\n"
	       "    -r   Use random object name.\n"
	       "         (defaults to PID).\n"
	       "\n"
	       " Example to generate 1000 pseudo folders with 1000 random key records each:\n"
	       "\n"
	       "   for i in `seq 1 1000`; do ./test/btreenam_stream_test -n -g 1000 -d -R -p 2; done\n"
	       "   nelist cltest test btreenam-stream-test-bucket btreenam-stream-test-object|wc -l\n"
	       "\n",
		   CHUNK_SIZE, ORDER, GENERATE, GENERATE_PREFIX_MOD, KEY_SIZE, VAL_SIZE);

	exit(EXIT_SUCCESS);
}

// ============================================================================
//
// ============================================================================
static int
search_iter(ccow_lookup_t iter, char * key)
{
	struct ccow_metadata_kv *kv = NULL;
	int pos = 0, rv = 0;

	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++))) {

		if (kv->type == CCOW_KVTYPE_RAW) {
			rv = strcmp(key, kv->key);

			if (rv == 0)
				return 1;
		}
	}

	return 0;
}

// ============================================================================
//
// ============================================================================

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
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);

	je_free(*state);
	*state = NULL;
}

static void
bucket_create(void **state)
{
	assert_non_null(cl);

	int err = ccow_bucket_create(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);

	if (err != 0 && err != -EEXIST) {
		printf("ccow_bucket_create returned error %d. \n", err);
		assert_int_equal(err, 0);
	}
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);

	int err = ccow_bucket_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);

	if (err != 0) {
		printf("ccow_bucket_delete returned error %d. \n", err);
		assert_int_equal(err, 0);
	}
}

// ============================================================================
//
// ============================================================================

static void
libbtreenam_noop(void **state)
{
//	usleep(2 * 1000000L);
}

static void
libbtreenam_setup(void **state)
{
}

static void
libbtreenam_teardown(void **state)
{
}

static void
libccow_teardown(void **state)
{
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state)
{
    if (!dd) {
	    ccow_daemon_term();
    }
}

// ============================================================================
//
// ============================================================================
static void
write_keys(void **state, char * keys[], char * vals[], int count, int verbose)
{
	int err, index = 0;
	uint64_t genid = 0;
	assert_non_null(cl);
	ccow_completion_t c;

	int i;

	size_t iovcnt = 2;
	struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);

	/*
	 * a insert_list call appears to be required in order to make the
	 * metadata changes stick.  so change chunk_map type and btree order,
	 * and put a key of "zzz".
	 */
	iov[0].iov_base = je_calloc(1, KEY_SIZE);
	assert_non_null(iov[0].iov_base);
	iov[1].iov_base = je_calloc(1, VAL_SIZE);
	assert_non_null(iov[1].iov_base);

	strcpy(iov[0].iov_base, "zzz");
	iov[0].iov_len = strlen(iov[0].iov_base) + 1;

	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	char * chunkmap_type = "btree_key_val";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *) chunkmap_type, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *) &ORDER, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&CHUNK_SIZE, NULL);
	assert_int_equal(err, 0);

	if (TEST_EC_ENABLE) {
		int ec = 1;
		err = ccow_attr_modify_default(c, CCOW_ATTR_EC_ENABLE,
		    &ec, NULL);
		assert_int_equal(err, 0);
	}

	err = ccow_insert_list(
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    TEST_OBJECT_NAME, strlen(TEST_OBJECT_NAME) + 1,
	    c, iov, 1);

	err = ccow_wait(c, -1);
	if (err && err != -EEXIST) {
		printf("ccow_wait returned %d, expected %d \n", err, 0);
		assert_int_equal(err, 0);
	}

	/*
	 * create stream completion
	 */
	err = ccow_create_stream_completion(cl, NULL, NULL, count+1, &c,
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    TEST_OBJECT_NAME, strlen(TEST_OBJECT_NAME) + 1,
	    &genid, 0, NULL);
	if (err != 0) {
		printf("ccow_create_stream_completion returned %d \n", err);
		assert_int_equal(err, 0);
	}
	assert_non_null(c);

	for (i = 0; i < count; i++) {
		/*
		 * write key
		 */
		strcpy(iov[0].iov_base, keys[i]);
		iov[0].iov_len = strlen(iov[0].iov_base) + 1;
		strcpy(iov[1].iov_base, vals[i]);
		iov[1].iov_len = strlen(iov[1].iov_base) + 1;

		if (OVERWRITE_SET) {
			int c_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
			ccow_stream_flags(c, &c_flags);
		}

		if (verbose) printf("inserting: %s => value len %ld\n", keys[i], iov[1].iov_len);
		err = ccow_insert_list_cont(c, iov, 2, 1, &index);
		if (err != 0) {
			printf("ccow_insert_list_cont returned %d, expected %d\n",
			    err, 0);
		}
		assert_int_equal(err, 0);

		err = ccow_wait(c, index);
		if (err != 0) {
			printf("ccow_wait for ccow_insert_list_cont returned %d,"
			    " expected %d \n", err, 0);
			assert_int_equal(err, 0);
		}
	}

	/* finalize */
	err = ccow_finalize(c, NULL);
	if (err != 0) {
		printf("ccow_finalize returned %d \n", err);
		assert_int_equal(err, 0);
	}

	/* cleanup */
	je_free(iov[0].iov_base);
	je_free(iov[1].iov_base);
	je_free(iov);

	*state = NULL;
}

// ============================================================================
//
// ============================================================================
static void
verify_keys(void **state, char * keys[], char * values[], int count)
{
	int err, index = 0;
	uint64_t genid = 0;
	assert_non_null(cl);
	ccow_completion_t c;
	ccow_lookup_t iter;
	struct ccow_metadata_kv * kv = NULL;
	int pos = 0;

	int i;

	size_t iovcnt = 1;
	struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);

	iov[0].iov_base = je_calloc(1, KEY_SIZE);
	assert_non_null(iov[0].iov_base);

	strcpy(iov[0].iov_base, keys[0]);
	iov[0].iov_len = strlen(iov[0].iov_base) + 1;

	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_get_list(
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    TEST_OBJECT_NAME, strlen(TEST_OBJECT_NAME) + 1,
	    c, iov, 1, count + 1, &iter);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	if (err != 0) {
		printf("ccow_wait returned %d, expected %d \n",
		    err, 0);
	}
	assert_int_equal(err, 0);

	for (i = 0; i < count; i++) {

		kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++);

		if (kv == NULL) {
			printf("Key \"%s\" not found. \n", keys[i]);
			assert_non_null(kv);
		}

		assert_string_equal(kv->key, keys[i]);
		if (values)
			assert_string_equal(kv->value, values[i]);
	}

	kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++);
	assert_non_null(kv);

	/* cleanup */
	ccow_lookup_release(iter);
	je_free(iov[0].iov_base);
	je_free(iov);

	*state = NULL;
}


// ============================================================================
//
// ============================================================================
static void
delete_keys(void **state)
{
	int err, index = 0;
	uint64_t genid = 0;
	assert_non_null(cl);
	ccow_completion_t c;
	ccow_lookup_t iter;
	struct ccow_metadata_kv * kv = NULL;
	int pos = 0, i;

	size_t iovcnt = 1;
	struct iovec * iov = je_calloc(iovcnt, sizeof (struct iovec));
	assert_non_null(iov);

	iov[0].iov_base = je_calloc(1, KEY_SIZE);
	assert_non_null(iov[0].iov_base);

	strcpy(iov[0].iov_base, "");
	iov[0].iov_len = strlen(iov[0].iov_base) + 1;

	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_get_list(
	    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    TEST_OBJECT_NAME, strlen(TEST_OBJECT_NAME) + 1,
	    c, iov, 1, 1024, &iter);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	if (err == -ENOENT) {
		printf("delete_keys: not found\n");
		goto delete_keys_cleanup;
	}

	if (err != 0) {
		printf("ccow_wait returned %d, expected %d \n",
		    err, 0);
	}

	assert_int_equal(err, 0);

	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++))) {

		if (kv->type == CCOW_KVTYPE_RAW) {
			assert(kv->key_size <= KEY_SIZE);
			assert(kv->key_size == strlen(kv->key) + 1);

			strcpy(iov[0].iov_base, kv->key);
			iov[0].iov_len = kv->key_size;

			err = ccow_create_completion(cl, NULL, NULL, 1, &c);
			assert_int_equal(err, 0);

			err = ccow_delete_list(
			    TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			    TEST_OBJECT_NAME, strlen(TEST_OBJECT_NAME) + 1,
			    c, iov, 1);
			assert_int_equal(err, 0);

			err = ccow_wait(c, -1);

			if (err == -ENOENT) {
				goto delete_keys_cleanup;
			}

			if (err != 0) {
				printf("ccow_wait returned %d, expected %d \n",
				    err, 0);
			}
			assert_int_equal(err, 0);
		}
	}

delete_keys_cleanup:
	/* cleanup */
	if (iter)
		ccow_lookup_release(iter);

	je_free(iov[0].iov_base);
	je_free(iov);

	*state = NULL;
}

// ============================================================================
//
// ============================================================================
static void
unit_test_000(void **state)
{
	if (GENERATE_ONLY)
		return;
	delete_keys(state);
}

// ============================================================================
//
// ============================================================================
static void
unit_test_001(void **state)
{
	char * keys[] = { "a01", "a02" };
	char * vals[] = { "v01", "v02" };
	if (GENERATE_ONLY)
		return;

	write_keys(state, keys, vals, 2, debug);
	verify_keys(state, keys, NULL, 2);
	delete_keys(state);
}


// ============================================================================
//
// ============================================================================
static void
unit_test_002(void **state)
{
	char * keys[7] = {
		"a01", "a02", "a03", "a04", "a05",
		"a06", "a07"
	};
	char * vals[7] = {
		"v01", "v02", "v03", "v04", "v05",
		"v06", "v07"
	};
	if (GENERATE_ONLY)
		return;

	write_keys(state, keys, vals, 7, debug);
	verify_keys(state, keys, NULL, 7);
	delete_keys(state);
}

// ============================================================================
//
// ============================================================================
static void
unit_test_003(void **state)
{
	char * keys[8] = {
		"a01", "a02", "a03", "a04", "a05",
		"a06", "a07", "a08"
	};
	char * vals[8] = {
		"v01", "v02", "v03", "v04", "v05",
		"v06", "v07", "v08"
	};
	if (GENERATE_ONLY)
		return;

	write_keys(state, keys, vals, 8, debug);
	verify_keys(state, keys, NULL, 8);
	delete_keys(state);
}

// ============================================================================
//
// ============================================================================
static void
unit_test_004(void **state)
{
	char * keys[25] = {
		"a01", "a02", "a03", "a04", "a05",
		"a06", "a07", "a08", "a09", "a10",
		"a11", "a12", "a13", "a14", "a15",
		"a16", "a17", "a18", "a19", "a20",
		"a21", "a22", "a23", "a24", "a25"
	};
	char * vals[25] = {
		"v01", "v02", "v03", "v04", "v05",
		"v06", "v07", "v08", "v09", "v10",
		"v11", "v12", "v13", "v14", "v15",
		"v16", "v17", "v18", "v19", "v20",
		"v21", "v22", "v23", "v24", "v25"
	};
	if (GENERATE_ONLY)
		return;

	write_keys(state, keys, vals, 25, debug);
	verify_keys(state, keys, NULL, 25);
	delete_keys(state);
}

// ============================================================================
//
// ============================================================================
static void
unit_test_005(void **state)
{
	if (GENERATE_ONLY)
		return;
	char * key = je_calloc(1, KEY_SIZE);
	assert_non_null(key);

	char * val = je_calloc(1, VAL_SIZE);
	assert_non_null(val);

	for (uint32_t i = 0; i < KEY_SIZE - 1; i++) {
		key[i] = '.';
	}

	for (uint32_t i = 0; i < VAL_SIZE - 1; i++) {
		val[i] = '.';
	}

	srand(time(NULL));
	for (int i = 0; i < 25; i++) {
		char buf[16] = {0};
		snprintf(buf, 16, "b%09d", TEST_RANDOM_KEYS ? rand() : i);
		memcpy(key, buf, strlen(buf));
		snprintf(buf, 16, "v%09d", TEST_RANDOM_KEYS ? rand() : i);
		memcpy(val, buf, strlen(buf));

		write_keys(state, &key, &val, 1, debug);
		verify_keys(state, &key, NULL, 1);
	}
	delete_keys(state);
	je_free(key);
	je_free(val);
}

// ============================================================================
// Overwrite key's value in the same stream sequence
// ============================================================================
static void
unit_test_006(void **state)
{
	char * keys[25] = {
		"q01", "q02", "q03", "q04", "q05",
		"q06", "q07", "q08", "q09", "q10",
		"q11", "q12", "q13", "q14", "q15",
		"q01", "q02", "q03", "q04", "q05",
		"q06", "q07", "q08", "q09", "q10"
	};
	char * vals[25] = {
		"v01", "v02", "v03", "v04", "v05",
		"v06", "v07", "v08", "v09", "v10",
		"v11", "v12", "v13", "v14", "v15",
		"v16", "v17", "v18", "v19", "v20",
		"v21", "v22", "v23", "v24", "v25"
	};
	if (GENERATE_ONLY)
		return;

	OVERWRITE_SET = 1;
	write_keys(state, keys, vals, 25, debug);
	verify_keys(state, &keys[15], &vals[15], 10);
	delete_keys(state);
	OVERWRITE_SET = 0;
}

// ============================================================================
// Overwrite key's value in the same stream sequence - RANDOM
// ============================================================================
static void
unit_test_007(void **state)
{
	char * keys[3] = {
		"q10", "q15", "q10"
	};
	char * vals[3] = {
		"s10", "s15", "s10"
	};
	if (GENERATE_ONLY)
		return;

	OVERWRITE_SET = 1;
	write_keys(state, keys, vals, 3, debug);
	verify_keys(state, keys, vals, 2);
	delete_keys(state);
	OVERWRITE_SET = 0;
}


// ============================================================================
// Generate test set, and keep it
// ============================================================================
static void
test_generate(void **state)
{
	if (!GENERATE)
		return;

	printf("\nInsert %u key/value pairs into %s/%s\n", GENERATE, TEST_BUCKET_NAME, TEST_OBJECT_NAME);

	char **keys = je_calloc(GENERATE, sizeof(char *));
	char **vals = je_calloc(GENERATE, sizeof(char *));
	uint32_t p = 0;
	srand((uint32_t)time(NULL));
	for (uint32_t i=0; i< GENERATE; i++) {
		keys[i] = (char *) je_malloc(KEY_SIZE);
		vals[i] = (char *) je_malloc(VAL_SIZE);
		if ((i % GENERATE_PREFIX_MOD) == 0) p++;
		sprintf(keys[i],"pk%08u/tk%08lu", p, TEST_RANDOM_KEYS ? rand() + get_timestamp_us() : i);
		sprintf(vals[i],"tv%08u", rand());
	}

	write_keys(state, keys, vals, GENERATE, debug);
	if (!TEST_RANDOM_KEYS)
		verify_keys(state, keys, vals, GENERATE);

	for (uint32_t i=0; i< GENERATE; i++) {
		je_free(keys[i]);
		je_free(vals[i]);
	}

	je_free(keys);
	je_free(vals);
}

// ============================================================================
//
// ============================================================================
int
main(int argc, char **argv)
{
	int opt;

	sprintf(TEST_OBJECT_NAME, "btreenam-stream-test-object");

	while ((opt = getopt(argc, argv, "hndr:Rc:g:o:k:v:ep:")) != -1) {
		switch(opt) {

		case 'h':
			usage();
			break;

		case 'n':
			dd = 1;
			break;

		case 'd':
			debug = 1;
			break;

		case 'c':
			CHUNK_SIZE = sst_convert_bytes(optarg);
			break;

		case 'o':
			ORDER = sst_convert_bytes(optarg);
			break;

		case 'g':
			GENERATE_ONLY = 1;
			GENERATE = sst_convert_bytes(optarg);
			break;

		case 'p':
			GENERATE_PREFIX_MOD = sst_convert_bytes(optarg);
			break;

		case 'k':
			KEY_SIZE = sst_convert_bytes(optarg);
			if (KEY_SIZE < 16) {
				printf("key size has to be >= 9\n");
				exit(1);
			}
			break;

		case 'v':
			VAL_SIZE = sst_convert_bytes(optarg);
			if (VAL_SIZE < 16) {
				printf("value size has to be >= 9\n");
				exit(1);
			}
			break;

		case 'e':
			TEST_EC_ENABLE = 1;
			break;

		case 'r': {
			int custom_id = atoi(optarg);
			time_t seconds= time(NULL);
			sprintf(TEST_OBJECT_NAME, "btreenam-stream-test-object.%ld",
			    custom_id ? custom_id : (long)seconds);
			break;
		}
		case 'R':
			TEST_RANDOM_KEYS = 1;
			break;

		default:
			usage();
			break;
		}
	}

	printf("\nInsert key/value pairs into %s/%s\n\n", TEST_BUCKET_NAME, TEST_OBJECT_NAME);

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),

		unit_test_setup(libbtreenam_noop, libbtreenam_setup),

		unit_test(unit_test_000),
		unit_test(unit_test_001),
		unit_test(unit_test_002),
		unit_test(unit_test_003),
		unit_test(unit_test_004),
		unit_test(unit_test_005),
		unit_test(unit_test_006),
		unit_test(unit_test_007),
		unit_test(test_generate),

		unit_test_teardown(libbtreenam_noop, libbtreenam_teardown),

//		unit_test(bucket_delete),

		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};

	return run_tests(tests);
}
