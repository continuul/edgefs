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

#define TEST_BUCKET_NAME	"delete-bucket-test"
ccow_t tc;

char object_3v_name[64];
char version_vm_content_hash_id[3][512];
uint64_t version_uvid_timestamp[3];
int dd = 0;
uint16_t num_vers = 3;

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
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);
	je_free(buf);
}

static void
bucket_create(void **state)
{
	assert_non_null(tc);
	int err = ccow_bucket_create(tc, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(tc);
	int err = ccow_bucket_delete(tc, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
}

static void
put_1k(void **state)
{
	assert_non_null(tc);
	struct iovec iov[1];
	iov[0].iov_len = 1024;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	put(tc, TEST_BUCKET_NAME, "test-obj1", &iov[0], 1, 0, NULL, NULL);
	put(tc, TEST_BUCKET_NAME, "test-obj2", &iov[0], 1, 0, NULL, NULL);

	je_free(iov[0].iov_base);
}

static void
object_delete(void **state)
{
	assert_non_null(tc);
	delete(tc, TEST_BUCKET_NAME, "test-obj1", NULL, NULL);
	delete(tc, TEST_BUCKET_NAME, "test-1v-obj1", NULL, NULL);
}


static void
object_expunge(void **state)
{
	int err;
	assert_non_null(tc);

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	err = ccow_expunge(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1, "test-obj2", strlen("test-obj2") + 1, c);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
}

static void
object_versions(void **state)
{
    ccow_lookup_t iter;
    int err;
    uint64_t genid;
    uint64_t timestamp;

    assert_non_null(tc);

	ccow_completion_t c;
    err = ccow_create_completion(tc, NULL, NULL, 1, &c);
    assert_int_equal(err, 0);

    err = ccow_get_versions(TEST_BUCKET_NAME,
    		strlen(TEST_BUCKET_NAME) + 1, object_3v_name, strlen(object_3v_name) + 1,  c, &iter);
    assert_int_equal(err, 0);

    err = ccow_wait(c, 0);
    assert_int_equal(err, 0);

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	char *c512;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_VERSIONS, pos++))) {
		char *b = je_malloc(kv->key_size + 1);
		char *c = je_malloc(kv->value_size + 1);
		memcpy(b, kv->key, kv->key_size);
		b[kv->key_size] = '\0';
		memcpy(c, kv->value, kv->value_size);
		c[kv->value_size] = '\0';
		printf("%d: %s: %s\n", pos, b, c);
		char *sp;
		c512 = strtok_r(b,"|", &sp);
		timestamp = atol(c512);
		c512 = strtok_r(NULL,"|", &sp);
		genid = atoi(c512);
		if (genid <= num_vers) {
			c512 = strtok_r(c,"|", &sp);
			c512 = strtok_r(NULL,"|", &sp);
			strcpy(version_vm_content_hash_id[genid-1], c512);
			version_uvid_timestamp[genid-1] = timestamp;
		}
		je_free(b);
		je_free(c);
	}

    ccow_lookup_release(iter);
}

static void
object_v_expunge(void **state)
{
	int err;
	assert_non_null(tc);

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, num_vers, &c);
	assert_int_equal(err, 0);


	for (int i=0; i < num_vers; i++) {
		uint64_t *genid_test = (uint64_t *)je_malloc(sizeof(uint64_t));
		*genid_test = i+1;
		printf("Expunge generation: %lu, version_uvid_timestamp: %lu, version_vm_content_hash_id: %s\n",
				*genid_test, version_uvid_timestamp[i], version_vm_content_hash_id[i]);

		err = ccow_expunge_version(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1, object_3v_name, strlen(object_3v_name) + 1,
				genid_test, version_uvid_timestamp[i], version_vm_content_hash_id[i], c);
		assert_int_equal(err, 0);

		err = ccow_wait(c, i);
		assert_int_equal(err, 0);
		je_free(genid_test);
	}


	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	struct iovec iov_name;
	iov_name.iov_base = (void *) object_3v_name;
	iov_name.iov_len = strlen(object_3v_name) + 1;

	err = ccow_delete_list(TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1, "", 1, c, &iov_name, 1);
	assert_int_equal(err, 0);

	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);
}

static void
put_1_version(void **state)
{
	int err;
	assert_non_null(tc);

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 3, &c);
	assert_int_equal(err, 0);

	num_vers = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "test-1v-obj1", NULL, 0, 0);
	err = ccow_wait(c, 0);
	assert_int_equal(err, 0);

	num_vers = 0;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "test-1v-obj1", NULL, 0, 0);
	err = ccow_wait(c, 1);
	assert_int_equal(err, 0);

	put_simple(c, TEST_BUCKET_NAME, "test-1v-obj1", NULL, 0, 0);
	err = ccow_wait(c, 2);
	assert_int_equal(err, 0);
}

static void
put_3_version(void **state)
{
	int err;
	assert_non_null(tc);

	num_vers = 3;

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, num_vers+1, &c);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	assert_int_equal(err, 0);

	for (int i=0; i<num_vers; i++) {
		put_simple(c, TEST_BUCKET_NAME, object_3v_name, NULL, 0, 0);
		err = ccow_wait(c, i);
		assert_int_equal(err, 0);
	}

	printf("Waiting for 40secs due to TRLOG...\n");
	usleep(40 * 1000000L);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	ccow_tenant_term(tc);
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
    sprintf(object_3v_name,"v3obj.%ld", (long) seconds);
    printf("Object name: %s\n\n", object_3v_name);

    const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),


		unit_test(put_1k),
		unit_test(put_1_version),
		unit_test(object_delete),
		unit_test(object_expunge),

		unit_test(put_3_version),
		unit_test(object_versions),
		unit_test(object_v_expunge),

		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
