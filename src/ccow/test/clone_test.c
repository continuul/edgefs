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

#define TEST_BUCKET_NAME	"clone-bucket-test"
#define CLONE_TEST_BS	1024
#define REPLICATION_COUNT_OVERRIDE 2
#define NUMBER_OF_VERSIONS_OVERRIDE 5
#define REPLICATION_COUNT_OVERRIDE2 4
#define NUMBER_OF_VERSIONS_OVERRIDE2 7
ccow_t cl;

int dd = 0;

char source_name[64];
char cloned_name[64];
char cloned_override_name[64];
char cloned_override_name2[64];


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
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
}


static void
clone_test__clone_0_1k(void **state)
{
	assert_non_null(cl);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	struct ccow_copy_opts copy_opts;
	copy_opts.tid = "test";
	copy_opts.bid = TEST_BUCKET_NAME;
	copy_opts.oid = cloned_name;
	copy_opts.tid_size = 5;
	copy_opts.bid_size = strlen(TEST_BUCKET_NAME) + 1;
	copy_opts.oid_size = strlen(cloned_name) + 1;
	copy_opts.genid = NULL;
	copy_opts.version_uvid_timestamp = 0;
	copy_opts.version_vm_content_hash_id = NULL;


	err = ccow_clone(c, "test", 5, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    source_name, strlen(source_name) + 1, &copy_opts);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

}

static void
clone_test__clone_to_self(void **state)
{
	assert_non_null(cl);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	struct ccow_copy_opts copy_opts;
	copy_opts.tid = "test";
	copy_opts.bid = TEST_BUCKET_NAME;
	copy_opts.oid = source_name;
	copy_opts.tid_size = 5;
	copy_opts.bid_size = strlen(TEST_BUCKET_NAME) + 1;
	copy_opts.oid_size = strlen(source_name) + 1;
	copy_opts.genid = NULL;
	copy_opts.version_uvid_timestamp = 0;
	copy_opts.version_vm_content_hash_id = NULL;

	err = ccow_clone(c, "test", 5, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    source_name, strlen(source_name) + 1, &copy_opts);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

}
static void
clone_test__get_self_clone(void **state)
{
	assert_non_null(cl);
	int err;
	int len = CLONE_TEST_BS;
	char buf[len];

	struct iovec *iov;
	size_t iovcnt;
	err = ccow_chunk(buf, len, CLONE_TEST_BS, &iov, &iovcnt);
	assert_int_equal(err, 0);

	get(cl, TEST_BUCKET_NAME, source_name, iov, iovcnt, 0,
	    NULL, NULL, NULL);
	assert_int_equal(err, 0);

	je_free(iov);
}


static void
clone_test__get_clone_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	int len = CLONE_TEST_BS;
	char buf[len];

	struct iovec *iov;
	size_t iovcnt;
	err = ccow_chunk(buf, len, CLONE_TEST_BS, &iov, &iovcnt);
	assert_int_equal(err, 0);

	get(cl, TEST_BUCKET_NAME, cloned_name, iov, iovcnt, 0,
	    NULL, NULL, NULL);
	assert_int_equal(err, 0);

	je_free(iov);
}


static void
clone_test__default_init_0_1k(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = CLONE_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	uint32_t bs = 4096;
	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, NULL);
	put_simple(c, TEST_BUCKET_NAME, source_name, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	je_free(iov[0].iov_base);
}

static void
clone_test__md_override(void **state)
{
	assert_non_null(cl);
	int err;
	struct iovec iov[1];
	iov[0].iov_len = CLONE_TEST_BS;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	uint32_t bs = 4096;
	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	uint64_t value1 = REPLICATION_COUNT_OVERRIDE;
	err = ccow_attr_modify_md_overrides(c, RT_SYSKEY_REPLICATION_COUNT, value1);
	assert_int_equal(err, 0);

	uint64_t value2 = NUMBER_OF_VERSIONS_OVERRIDE;
	err = ccow_attr_modify_md_overrides(c, RT_SYSKEY_NUMBER_OF_VERSIONS, value2);
	assert_int_equal(err, 0);

	uint64_t value3 = 0;
	err = ccow_attr_modify_md_overrides(c, RT_SYSKEY_EC_ENABLED, value3);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_md_overrides(c, RT_SYSKEY_ONDEMAND, ondemandPolicyUnpin);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, NULL);
	put_simple(c, TEST_BUCKET_NAME, cloned_override_name, &iov[0], 1, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	je_free(iov[0].iov_base);
}


static void
clone_test_override(void **state)
{
	assert_non_null(cl);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	struct ccow_copy_opts copy_opts;
	copy_opts.tid = "test";
	copy_opts.bid = TEST_BUCKET_NAME;
	copy_opts.oid = cloned_override_name2;
	copy_opts.tid_size = 5;
	copy_opts.bid_size = strlen(TEST_BUCKET_NAME) + 1;
	copy_opts.oid_size = strlen(cloned_override_name2) + 1;
	copy_opts.genid = NULL;
	copy_opts.version_uvid_timestamp = 0;
	copy_opts.version_vm_content_hash_id = NULL;

	uint64_t value1 = REPLICATION_COUNT_OVERRIDE2;
	err = ccow_attr_modify_md_overrides(c, RT_SYSKEY_REPLICATION_COUNT, value1);
	assert_int_equal(err, 0);

	uint64_t value2 = NUMBER_OF_VERSIONS_OVERRIDE2;
	err = ccow_attr_modify_md_overrides(c, RT_SYSKEY_NUMBER_OF_VERSIONS, value2);
	assert_int_equal(err, 0);

	uint64_t value3 = 0;
	err = ccow_attr_modify_md_overrides(c, RT_SYSKEY_EC_ENABLED, value3);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_md_overrides(c, RT_SYSKEY_ONDEMAND, ondemandPolicyLocal);
	assert_int_equal(err, 0);

	err = ccow_clone(c, "test", 5, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    cloned_override_name, strlen(cloned_override_name) + 1, &copy_opts);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

}

static void
clone_test__md_retrieve(void **state)
{
	assert_non_null(cl);
	int err;
	int len = CLONE_TEST_BS;
	char buf[len];

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	size_t iovcnt = 1;

	ccow_lookup_t iter, iter2, iter3, iter4;
	get(cl, TEST_BUCKET_NAME, source_name, &iov, iovcnt, 0, NULL, NULL,
	    &iter);

	get(cl, TEST_BUCKET_NAME, cloned_name, &iov, iovcnt, 0, NULL, NULL,
	    &iter2);

	get(cl, TEST_BUCKET_NAME, cloned_override_name, &iov, iovcnt, 0, NULL, NULL,
	    &iter3);

	get(cl, TEST_BUCKET_NAME, cloned_override_name2, &iov, iovcnt, 0, NULL, NULL,
	    &iter4);


	printf("\n%s attributes\n", source_name);
	dump_iter_to_stdout(iter, CCOW_MDTYPE_ALL);
	printf("\n%s attributes\n", cloned_name);
	dump_iter_to_stdout(iter2, CCOW_MDTYPE_ALL);
	printf("\n%s attributes\n", cloned_override_name);
	dump_iter_to_stdout(iter3, CCOW_MDTYPE_ALL);
	printf("\n%s attributes\n", cloned_override_name2);
	dump_iter_to_stdout(iter4, CCOW_MDTYPE_ALL);


	// Verify overrides
	printf("\nVerify attributes for %s\n", cloned_override_name);
	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter3, CCOW_MDTYPE_VERSIONS, pos++))) {
		char key[64];
		memcpy(key, kv->key, kv->key_size);
		key[kv->key_size] = '\0';
		if (strcmp(key,RT_SYSKEY_REPLICATION_COUNT) == 0) {
			uint8_t value;
			memcpy(&value, kv->value, 1);
			printf("Key: %s value: %u\n", key, value);
			assert_int_equal(REPLICATION_COUNT_OVERRIDE, value);
		} else if (strcmp(key,RT_SYSKEY_NUMBER_OF_VERSIONS) == 0) {
			uint16_t value;
			memcpy(&value, kv->value, 2);
			printf("Key: %s value: %u\n", key, value);
			assert_int_equal(NUMBER_OF_VERSIONS_OVERRIDE, value);
		} else if (strcmp(key,RT_SYSKEY_INLINE_DATA_FLAGS) == 0) {
			uint16_t value;
			memcpy(&value, kv->value, 2);
			printf("Key: %s value: %u\n", key, value);
			assert_true(RT_ONDEMAND_GET(value) == ondemandPolicyUnpin);
		}
	}

	// Verify overrides 2
	printf("\nVerify attributes for %s\n", cloned_override_name2);
	kv = NULL;
	pos = 0;
	while ((kv = ccow_lookup_iter(iter4, CCOW_MDTYPE_VERSIONS, pos++))) {
		char key[64];
		memcpy(key, kv->key, kv->key_size);
		key[kv->key_size] = '\0';
		if (strcmp(key,RT_SYSKEY_REPLICATION_COUNT) == 0) {
			uint8_t value;
			memcpy(&value, kv->value, 1);
			printf("Key: %s value: %u\n", key, value);
			assert_int_equal(REPLICATION_COUNT_OVERRIDE2, value);
		} else if (strcmp(key,RT_SYSKEY_NUMBER_OF_VERSIONS) == 0) {
			uint16_t value;
			memcpy(&value, kv->value, 2);
			printf("Key: %s value: %u\n", key, value);
			assert_int_equal(NUMBER_OF_VERSIONS_OVERRIDE2, value);
		} else if (strcmp(key,RT_SYSKEY_INLINE_DATA_FLAGS) == 0) {
			uint16_t value;
			memcpy(&value, kv->value, 2);
			printf("Key: %s value: %u\n", key, value);
			assert_true(RT_ONDEMAND_GET(value) == ondemandPolicyLocal);
		}
	}


	ccow_lookup_release(iter);
	ccow_lookup_release(iter2);
	ccow_lookup_release(iter3);
	ccow_lookup_release(iter4);
}

static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, TEST_BUCKET_NAME, source_name, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, cloned_name, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, cloned_override_name, NULL, NULL);
	delete(cl, TEST_BUCKET_NAME, cloned_override_name2, NULL, NULL);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
    if(!dd)
        ccow_daemon_term();
}

int
main(int argc, char **argv)
{
    if (argc == 2) {
        if (strcmp(argv[1], "-n") == 0)
             dd = 1;
    }

    time_t seconds= time(NULL);
    sprintf(source_name,"source_name.%ld", (long) seconds);
    sprintf(cloned_name,"cloned_name.%ld", (long) seconds);
    sprintf(cloned_override_name,"cloned_override_name.%ld", (long) seconds);
    sprintf(cloned_override_name2,"cloned_override_name2.%ld", (long) seconds);

	printf("Source name: %s\n", source_name);
	printf("Cloned name: %s\n", cloned_name);
	printf("Cloned override name: %s\n", cloned_override_name);
	printf("Cloned override name2: %s\n", cloned_override_name2);


	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(clone_test__default_init_0_1k),
		unit_test(clone_test__clone_0_1k),
		unit_test(clone_test__get_clone_0_1k),
		unit_test(clone_test__md_override),
		unit_test(clone_test__clone_to_self),
		unit_test(clone_test_override),
		unit_test(clone_test__md_retrieve),
		unit_test(clone_test__get_self_clone),
		unit_test(object_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
