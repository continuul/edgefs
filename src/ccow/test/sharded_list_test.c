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
#include "ccow-impl.h"
#include "ccowd.h"
#include "replicast.h"

#define TEST_BUCKET_NAME	"sharded-list-bucket-test"
#define TEST_SHARD_COUNT	4

#define MAX_THREADS       512

int object_count = 100;
int event_count = 1000;
int object_num = 0;
int thread_count = 10;
int verbose = 0;
int marker_num = -1;
int get_count = 0;
char shard_name[64];
char shard_attrs[64];
char shard_event[64];
ccow_t tn[MAX_THREADS];
int64_t event_size = 0;
int64_t event_objs = 0;
int64_t event_used = 0;


ccow_t cl = NULL, tc = NULL;
int dd = 0;

ccow_shard_context_t list_shard_context;
ccow_shard_context_t attributes_shard_context;
ccow_shard_context_t event_shard_context;

char *TEST_ENV = NULL;

// ----------------------------------------------------------------------------
// setup and tear down functions
// ----------------------------------------------------------------------------
static void libccowd_setup(void **state) {
	if (!dd) {
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(2 * 1000000L);
	}
}

static void get_tenant(ccow_t *tn) {
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, tn), 0);
	je_free(buf);
}

static void libccow_setup(void **state) {
	get_tenant(&cl);
	for (int i=0; i<thread_count; i++) {
		get_tenant(&tn[i]);
	}
}

static void libccowd_teardown(void **state) {
	if (!dd) {
		ccow_daemon_term();
	}
}

// ----------------------------------------------------------------------------
// bucket create/delete
// ----------------------------------------------------------------------------
static void bucket_create(void **state) {
	assert_non_null(cl);
	int err = ccow_bucket_create(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void bucket_delete(void **state) {
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *      Create shard context
 * =======================================================================
 */
static void shard_context_create(void **state) {
	assert_non_null(cl);
	int err = ccow_shard_context_create(shard_name,
	    strlen(shard_name) + 1,
	    TEST_SHARD_COUNT, &list_shard_context);
	assert_int_equal(err, 0);

	err = ccow_shard_context_create(shard_attrs,
	    strlen(shard_attrs) + 1,
	    TEST_SHARD_COUNT, &attributes_shard_context);
	assert_int_equal(err, 0);

	err = ccow_shard_context_create(shard_event,
	    strlen(shard_event) + 1,
	    TEST_SHARD_COUNT, &event_shard_context);
	assert_int_equal(err, 0);
}


/*
 * =======================================================================
 *      Destroy shard context
 * =======================================================================
 */
static void shard_context_destroy(void **state) {
	assert_non_null(cl);
	ccow_shard_context_destroy(&list_shard_context);
	ccow_shard_context_destroy(&attributes_shard_context);
	ccow_shard_context_destroy(&event_shard_context);
}


/*
 * =======================================================================
 *		Create shared list
 * =======================================================================
 */
static void sharded_list_create(void **state) {
	assert_non_null(cl);
	int err = ccow_sharded_list_create(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context);
	assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *		Create shared attributes object
 * =======================================================================
 */
static void sharded_attributes_create(void **state) {
	assert_non_null(cl);
	int err = ccow_sharded_attributes_create(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, attributes_shard_context);
	assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *		Create shared attributes object
 * =======================================================================
 */
static void sharded_event_create(void **state) {
	assert_non_null(cl);
	int err = ccow_sharded_attributes_create(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, event_shard_context);
	assert_int_equal(err, 0);
}

static void sharded_list_destroy(void **state) {
	assert_non_null(cl);
	int err = ccow_sharded_list_destroy(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context);
	assert_int_equal(err, 0);

	err = ccow_sharded_list_destroy(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context);
	assert_int_equal(err, -ENOENT);

}

static void sharded_attributes_destroy(void **state) {
	assert_non_null(cl);
	int err = ccow_sharded_attributes_destroy(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, attributes_shard_context);
	assert_int_equal(err, 0);
}

static void sharded_event_destroy(void **state) {
	assert_non_null(cl);
	int err = ccow_sharded_attributes_destroy(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, event_shard_context);
	assert_int_equal(err, 0);
}

static void create_key(char *key, int num) {
	sprintf(key, "key%5.5d", num);
}

/*
 * =======================================================================
 *      Shared list on demand
 * =======================================================================
 */
static void sharded_list_demand(void **state) {
	assert_non_null(cl);
	ccow_shard_context_t shard_context;
	char shard[64];
	char key[64];
	char value[64];
	int i = 99;


	time_t seconds= time(NULL);
	sprintf(shard,"dshard.%ld", (long) seconds);
	printf("Demand shard name: %s/%s\n", TEST_BUCKET_NAME, shard);

	int err = ccow_shard_context_create(shard,
	    strlen(shard) + 1,
	    TEST_SHARD_COUNT, &shard_context);
	assert_int_equal(err, 0);


	create_key(key, i);
	sprintf(value, "value%d", i);
	struct iovec iov[2];
	struct iovec oov[1];

	if (verbose)
		printf("sharded_list_demand put key: %s, value: %s\n", key, value);

	iov[0].iov_base = key;
	iov[0].iov_len = strlen(key) + 1;
	iov[1].iov_base = value;
	iov[1].iov_len = strlen(value) + 1;

	err = ccow_sharded_list_get(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, shard_context, key,
	    strlen(key) + 1, oov, 1);
	assert_int_equal(err, -ENOENT);

	err = ccow_sharded_list_put(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, shard_context, iov, 2);
	assert_int_equal(err, 0);

	err = ccow_sharded_list_get(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, shard_context, key,
	    strlen(key) + 1, oov, 1);
	assert_int_equal(err, 0);
	if (verbose)
		printf("sharded_list_demand get key: %s, value: %s\n", key, (char *) oov->iov_base);
	assert_int_equal(strcmp(value, (char *) oov->iov_base), 0);

	if (oov->iov_base)
		je_free(oov->iov_base);

	int64_t delta_size = 10;
	int64_t delta_objs = 1;
	int64_t delta_used = 30;
	err = ccow_sharded_attributes_put(cl, TEST_BUCKET_NAME,
		strlen(TEST_BUCKET_NAME) + 1, shard_context, key,
		strlen(key) + 1, delta_size, delta_objs, delta_used);
	assert_int_equal(err, 0);


	int64_t logical_size;
	int64_t obj_count;
	int64_t estimated_used;

	err = ccow_sharded_attributes_get(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, shard_context,
	    &logical_size, &obj_count, &estimated_used);
	if (verbose)
		printf("Demand err: %d logical_size: %ld, object_count: %ld, estimated_used: %ld\n",
				err, logical_size, obj_count, estimated_used);
	assert_int_equal(logical_size, delta_size);
	assert_int_equal(obj_count, delta_objs);
	assert_int_equal(estimated_used, delta_used);


	ccow_shard_context_destroy(&shard_context);
}


/*
 * =======================================================================
 *		Shared list delete one
 * =======================================================================
 */
void *sharded_list_delete_one(void *data) {
	char key[64];
	char value[64];

	int i = *(int *)data;
	int t = i % thread_count;

	create_key(key, i);


	if (verbose)
		printf("DELETE thread[%lu], key: %s thread: %d\n", pthread_self(), key, t);


	int err = ccow_sharded_list_delete(tn[t], TEST_BUCKET_NAME,
		strlen(TEST_BUCKET_NAME) + 1, list_shard_context, key, strlen(key) + 1);
	if (err) {
		printf("DELETE key %s error: %d\n", key, err);
	}
	//assert_int_equal(err, 0);

	pthread_exit(0);
	return NULL;
}

/*
 * =======================================================================
 *		Shared list put one
 * =======================================================================
 */
void *sharded_list_put_one(void *data) {
	char key[64];
	char value[64];

	int i = *(int *)data;
	int t = i % thread_count;

	create_key(key, i);

	sprintf(value, "value%d", i);

	if (verbose)
		printf("PUT thread[%lu], key: %s, value: %s thread: %d\n", pthread_self(), key, value, t);

	struct iovec iov[2];

	iov[0].iov_base = key;
	iov[0].iov_len = strlen(key) + 1;
	iov[1].iov_base = value;
	iov[1].iov_len = strlen(value) + 1;

	int err = ccow_sharded_list_put(tn[t], TEST_BUCKET_NAME,
		strlen(TEST_BUCKET_NAME) + 1, list_shard_context, iov, 2);
	assert_int_equal(err, 0);

	int64_t delta_size = 10;
	int64_t delta_objs = 1;
	int64_t delta_used = 30;
	err = ccow_sharded_attributes_put(tn[t], TEST_BUCKET_NAME,
		strlen(TEST_BUCKET_NAME) + 1, attributes_shard_context, key,
		strlen(key) + 1, delta_size, delta_objs, delta_used);
	assert_int_equal(err, 0);


	pthread_exit(0);
	return NULL;
}


/*
 * =======================================================================
 *		Shared list put
 * =======================================================================
 */
static void sharded_list_put_thread(void **state) {
	assert_non_null(cl);
	char key[64];
	char value[64];
	pthread_t th[thread_count];
	int id[thread_count];
	int i;

	i = 0;
	while (i < object_count) {
		int batch = (i / thread_count);
		if (verbose)
			printf("PUT Batch #%d\n", batch);
		for (int t = 0; t < thread_count; t++) {
			id[t] = i+t;
			if (id[t] >= object_count)
				break;
			(void) pthread_create(&th[t], NULL, sharded_list_put_one, &id[t]);
		}

		for (int t = 0; t < thread_count; t++) {
			if (id[t] >= object_count)
				break;
			(void) pthread_join(th[t], NULL);
		}


		i += thread_count;
	}

	object_num += object_count;

}


/*
 * =======================================================================
 *		Shared list delete
 * =======================================================================
 */
static void sharded_list_delete_thread(void **state) {
	assert_non_null(cl);
	char key[64];
	char value[64];
	pthread_t th[thread_count];
	int id[thread_count];
	int i;

	i = 0;
	while (i < object_count) {
		int batch = (i / thread_count);
		if (verbose)
			printf("DELETE Batch #%d\n", batch);
		for (int t = 0; t < thread_count; t++) {
			id[t] = i+t;
			if ((id[t] % 5) != 0)
				continue;
			if (id[t] >= object_count)
				break;
			(void) pthread_create(&th[t], NULL, sharded_list_delete_one, &id[t]);
		}

		for (int t = 0; t < thread_count; t++) {
			if ((id[t] % 5) != 0)
				continue;
			if (id[t] >= object_count)
				break;
			(void) pthread_join(th[t], NULL);
		}


		i += thread_count;
	}

}


/*
 * =======================================================================
 *      Shared list overwrite error
 * =======================================================================
 */
static void sharded_list_overwrite_error(void **state) {
	assert_non_null(cl);
	char key[64];
	char value[64];
	struct iovec iov[2];
	int i, err;

	// clear default overwrite flag
	list_shard_context->overwrite = 0;

	// create old key/value
	i = 1;
	create_key(key, i);

	sprintf(value, "value%d", i);

	iov[0].iov_base = key;
	iov[0].iov_len = strlen(key) + 1;
	iov[1].iov_base = value;
	iov[1].iov_len = strlen(value) + 1;

	err = ccow_sharded_list_put(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context, iov, 2);
	assert_int_equal(err, -EEXIST);

	// set overwrite flag
	list_shard_context->overwrite = CCOW_CONT_F_INSERT_LIST_OVERWRITE;

	err = ccow_sharded_list_put(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context, iov, 2);
	assert_int_equal(err, 0);


	// clear default overwrite flag
	list_shard_context->overwrite = 0;

	// delete new key
	i = -1;
	create_key(key, i);

	sprintf(value, "value%d", i);

	err = ccow_sharded_list_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context, key, strlen(key) + 1);
	assert_int_equal(err, -ENOENT);

}


/*
 * =======================================================================
 *		Shared attributes put
 * =======================================================================
 */
static void sharded_attributes_put(void **state) {
	assert_non_null(cl);
	char key[64];
	char value[64];
	for (int i = 0; i < object_count; i++) {
		int64_t delta_size = 10;
		int64_t delta_objs = 1;
		int64_t delta_used = 30;
		create_key(key, i);
		sprintf(value, "value%d", i);
		int err = ccow_sharded_attributes_put(cl, TEST_BUCKET_NAME,
		    strlen(TEST_BUCKET_NAME) + 1, attributes_shard_context, key,
		    strlen(key) + 1, delta_size, delta_objs, delta_used);
		if (err) {
			printf("Put attributes error: %d", err);
		}
		assert_int_equal(err, 0);
		object_num++;
	}
}

/*
 * =======================================================================
 *		Shared list put
 * =======================================================================
 */
static void sharded_list_delete(void **state) {
	assert_non_null(cl);
	char key[64];
	struct iovec iov[1];

	// Delete last key
	create_key(key, object_count - 1);
	int err = ccow_sharded_list_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context, key,
	    strlen(key) + 1);
	assert_int_equal(err, 0);

	// Delete last key again
	create_key(key, object_count - 1);
	err = ccow_sharded_list_delete(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context, key,
	    strlen(key) + 1);
	assert_int_equal(err, -ENOENT);

	// Try to get deleted key
	create_key(key, object_count - 1);
	err = ccow_sharded_list_get(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context, key,
	    strlen(key) + 1, iov, 1);
	assert_int_equal(err, -ENOENT);

	// Try to get non-existing key
	time_t seconds= time(NULL);
	sprintf(key,"bad_key.%ld", (long) seconds);
	err = ccow_sharded_list_get(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context, key,
	    strlen(key) + 1, iov, 1);
	assert_int_equal(err, -ENOENT);

}

/*
 * =======================================================================
 *		Shared attributes delete
 * =======================================================================
 */
static void sharded_attributes_delete(void **state) {
	assert_non_null(cl);
	char key[64];
	// Delete last key
	create_key(key, object_count - 1);
	// Update attributes
	int64_t delta_size = -10;
	int64_t delta_objs = -1;
	int64_t delta_used = -30;
	int err = ccow_sharded_attributes_put(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, attributes_shard_context, key,
	    strlen(key) + 1, delta_size, delta_objs, delta_used);
	assert_int_equal(err, 0);
	object_num--;
}

/*
 * =======================================================================
 *		Shared list put with md
 * =======================================================================
 */
static void sharded_put_with_md(void **state) {
	assert_non_null(cl);
	char key[64];
	char value[64];

	int64_t delta_size = 10;
	int64_t delta_objs = 1;
	int64_t delta_used = 30;

	int i = 0;
	create_key(key, i);
	sprintf(value, "value%d", i);

	struct iovec iov[2];
	iov[0].iov_base = key;
	iov[0].iov_len = strlen(key) + 1;
	iov[1].iov_base = value;
	iov[1].iov_len = strlen(value) + 1;

	int err = ccow_sharded_list_put_with_md(cl, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			attributes_shard_context, key, strlen(key) + 1, NULL, 0, iov, 2,
			delta_size, delta_objs, delta_used);
	if (err) {
		printf("sharded_put_with_md error: %d", err);
	}
	assert_int_equal(err, 0);
	object_num++;
}

static void sharded_put_with_md_eventual(void **state) {
	assert_non_null(cl);
	char key[64];
	char value[64];

	event_size = 0;
	event_objs = 0;
	event_used = 0;

	int64_t delta_size = 10;
	int64_t delta_objs = 1;
	int64_t delta_used = 30;

	int i = event_count;

	ccow_shard_context_set_eventual(event_shard_context, 1);

	uint64_t before = uv_hrtime();
	for (int j = 0; j < event_count; j++) {
		create_key(key, i+j);
		sprintf(value, "value%d", i + j);

		struct iovec iov[2];
		iov[0].iov_base = key;
		iov[0].iov_len = strlen(key) + 1;
		iov[1].iov_base = value;
		iov[1].iov_len = strlen(value) + 1;

		int err = ccow_sharded_list_put_with_md(cl, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
				event_shard_context, key, strlen(key) + 1, NULL, 0, iov, 2,
				delta_size, delta_objs, delta_used);

		if (verbose || err)
			printf("%d: sharded_put_with_md_eventual key: %s, value: %s, err=%d\n", j, key,
			    (char *) value, err);

		assert_int_equal(err, 0);
		event_size += delta_size;
		event_objs += delta_objs;
		event_used += delta_used;
	}
	uint64_t spent = uv_hrtime() - before;

	printf("ccow_sharded_list_put_with_md eventual: %.2fs (%s/s)\n", spent / 1e9,
	    fmt(event_count*1.0 / (spent / 1e9)));
}

/*
 * =======================================================================
 *		Shared list with md get
 * =======================================================================
 */
static void sharded_list_with_md_get(void **state) {
	assert_non_null(cl);
	size_t value_size;
	char key[64];
	char value[64];
	struct iovec iov[1];

	int i = 0;
	create_key(key, i);
	sprintf(value, "value%d", i);

	int err = ccow_sharded_list_get(cl, TEST_BUCKET_NAME,
		    strlen(TEST_BUCKET_NAME) + 1, attributes_shard_context, key,
		    strlen(key) + 1, iov, 1);

	assert_int_equal(err, 0);

	if (verbose)
		printf("sharded_list_with_md_get key: %s, value: %s\n", key,
		    (char *) iov->iov_base);

	err = memcmp(value, iov->iov_base, iov->iov_len);
	assert_int_equal(err, 0);

	if (iov->iov_base)
		je_free(iov->iov_base);

}

static void sharded_list_with_md_get_eventual(void **state) {
	assert_non_null(cl);
	size_t value_size;
	char key[64];
	char value[64];
	struct iovec iov[1];
	int err = 0;
	int i = event_count;

	for (int j = 0; j < event_count; j++) {
		create_key(key, i+j);
		sprintf(value, "value%d", i + j);

		err = ccow_sharded_list_get(cl, TEST_BUCKET_NAME,
			    strlen(TEST_BUCKET_NAME) + 1, event_shard_context, key,
			    strlen(key) + 1, iov, 1);

		if (err)
			printf("%d: sharded_list_with_md_get key: %s, err=%d\n", j, key, err);

		assert_int_equal(err, 0);

		err = memcmp(value, iov->iov_base, iov->iov_len);
		if (verbose || err)
			printf("%d: sharded_list_with_md_get key: %s, value: %s, err=%d\n", j, key,
			    (char *) iov->iov_base, err);

		assert_int_equal(err, 0);

		if (iov->iov_base)
			je_free(iov->iov_base);
	}

	int64_t logical_size;
	int64_t obj_count;
	int64_t estimated_used;

	err = ccow_sharded_attributes_get(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, event_shard_context,
	    &logical_size, &obj_count, &estimated_used);
	assert_int_equal(err, 0);
	if (verbose)
		printf("Eventual logical_size: %ld, object_count: %ld, estimated_used: % ld\n",
				logical_size, obj_count, estimated_used);
	assert_int_equal(logical_size, event_size);
	assert_int_equal(obj_count, event_objs);
	assert_int_equal(event_used, estimated_used);
}

/*
 * =======================================================================
 *		Shared list get list eventual
 * =======================================================================
 */
static void sharded_list_get_list_eventual(void **state) {
	assert_non_null(cl);
	size_t value_size;
	char marker[64] = "";
	char key[64];
	int res_count = event_count;

	ccow_lookup_t iter;

	if (marker_num >= 0) {
	   create_key(marker, marker_num);
	   res_count -= marker_num;
	}

	if (verbose)
		printf("list_get_list Marker: %s Get list count eventual: %d\n", marker, event_count);

	int err = ccow_sharded_get_list(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, event_shard_context,
		marker, strlen(marker) + 1,  NULL, event_count, &iter);
	assert_int_equal(err, 0);

	struct ccow_metadata_kv *kv;
	int n = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1))) {
		if (verbose)
		    printf("test result list eventual kv->key: %s value: %s\n", kv->key, (char *)kv->value);
		n++;
	}

	if (verbose)
		printf("list_get_list_eventual total: %d\n", n);

	ccow_lookup_release(iter);

	assert_int_equal(res_count, n);
}


/*
 * =======================================================================
 *		Shared list get
 * =======================================================================
 */
static void sharded_list_get(void **state) {
	assert_non_null(cl);
	size_t value_size;
	char key[64];
	char value[64];
	int err;
	struct iovec iov[1];
	for (int i = 0; i < object_count - 1; i++) {
		if ((i % 5) == 0)
			continue;
		create_key(key, i);
		sprintf(value, "value%d", i);
		int err = ccow_sharded_list_get(cl, TEST_BUCKET_NAME,
		    strlen(TEST_BUCKET_NAME) + 1, list_shard_context, key,
		    strlen(key) + 1, iov, 1);
		assert_int_equal(err, 0);
		int cmp = strcmp(value, (char *)iov->iov_base);
		if (i < 10 && verbose)
				printf("sharded_list_get key: %s, value: %s\n", key,
				    (char *) iov->iov_base);
		assert_int_equal(cmp, 0);

		if (iov->iov_base)
			je_free(iov->iov_base);
	}

}

/*
 * =======================================================================
 *		Shared list get list
 * =======================================================================
 */
static void sharded_list_get_list(void **state) {
	assert_non_null(cl);
	size_t value_size;
	char marker[64] = "";
	char key[64];

	if (marker_num >= 0)
	    create_key(marker, marker_num);

	ccow_lookup_t iter;

	if (get_count <=0)
	    get_count = object_count;
	if (marker_num > 0)
	    get_count -=  marker_num;

	if (verbose)
		printf("list_get_list Marker: %s Get list count: %d\n", marker, get_count);

	int err = ccow_sharded_get_list(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, list_shard_context, marker,
	    strlen(marker) + 1,
	    NULL, get_count, &iter);
	assert_int_equal(err, 0);

	struct ccow_metadata_kv *kv;
	int ikey = (marker_num >= 0 ? marker_num + 1 : 0);
	int n = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1))) {
		if ((ikey % 5) == 0)
			ikey++;
		create_key(key, ikey++);
		if (verbose)
		    printf("test result list key: %s kv->key: %s\n", key, kv->key);
		n++;
		assert_int_equal(strcmp(key, kv->key), 0);
	}
	if (verbose)
		printf("list_get_list total: %d\n", n);

	ccow_lookup_release(iter);
}

/*
 * =======================================================================
 *		Shared attributes get
 * =======================================================================
 */
static void sharded_attributes_get(void **state) {
	assert_non_null(cl);

	int err = 0;
	int64_t logical_size;
	int64_t obj_count;
	int64_t estimated_used;

	err = ccow_sharded_attributes_get(cl, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, attributes_shard_context,
	    &logical_size, &obj_count, &estimated_used);
	assert_int_equal(err, 0);
	if (verbose)
		printf("logical_size: %ld, object_count: %ld, object_num: %d, estimated_used: % ld\n",
				logical_size, obj_count, object_num, estimated_used);
	assert_int_equal(obj_count, object_num);
}

static void libccow_teardown(void **state) {
	assert_non_null(cl);

	ccow_tenant_term(cl);
	for (int i=0; i<thread_count; i++) {
		ccow_tenant_term(tn[i]);
	}
}

int main(int argc, char **argv) {
	int opt;
	while ((opt = getopt(argc, argv, "nc:e:g:hm:t:v")) != -1) {
		switch (opt) {
		case 'c':
			object_count = atoi(optarg);
			break;

		case 'e':
			event_count = atoi(optarg);
			break;

		case 'h':
			printf("\nUsage: -c <object_count> -e <eventual_count> -m <marker_num> -g <get_count> -t <thread_count> -v [-n]\n\n");
			printf("\n\n where -v enables verbose mode");
			exit(0);
			break;

		case 'm':
			marker_num = atoi(optarg);
			break;

		case 'n':
			dd = 1;
			break;

		case 'g':
			get_count = atoi(optarg);
			break;

		case 't':
			thread_count = atoi(optarg);
			break;

		case 'v':
			verbose = 1;
			break;

		default:
			break;
		}
	}

	time_t seconds= time(NULL);
	sprintf(shard_name,"shard_name.%ld", (long) seconds);
	sprintf(shard_attrs,"shard_attrs.%ld", (long) seconds);
	sprintf(shard_event,"shard_event.%ld", (long) seconds);

	printf("Shard name: %s/%s\n", TEST_BUCKET_NAME, shard_name);
	printf("Shard attributes name: %s/%s\n", TEST_BUCKET_NAME, shard_attrs);
	printf("Shard eventual name: %s/%s\n", TEST_BUCKET_NAME, shard_event);


	printf("Object count: %d\n", object_count);
	printf("Thread count: %d\n", thread_count);
	printf("Marker num: %d\n", marker_num);
	printf("Get count: %d\n", get_count);

	TEST_ENV = getenv("NEDGE_ENV");
	if (!TEST_ENV)
		TEST_ENV = "production";
	const UnitTest tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(shard_context_create),
			unit_test(sharded_list_create),
			unit_test(sharded_attributes_create),
			unit_test(sharded_event_create),
			unit_test(sharded_list_put_thread),
			unit_test(sharded_list_delete_thread),
			unit_test(sharded_attributes_put),
			unit_test(sharded_attributes_get),
			unit_test(sharded_list_get),
			unit_test(sharded_list_get_list),
			unit_test(sharded_list_overwrite_error),
			unit_test(sharded_list_delete),

			unit_test(sharded_attributes_delete),
			unit_test(sharded_attributes_get),

			unit_test(sharded_put_with_md),
			unit_test(sharded_list_with_md_get),

			unit_test(sharded_put_with_md_eventual),
			unit_test(sharded_list_get_list_eventual),
			unit_test(sharded_list_with_md_get_eventual),
			unit_test(sharded_list_get_list_eventual),

			unit_test(sharded_attributes_get),

			unit_test(sharded_list_demand),
			unit_test(sharded_list_destroy),
			unit_test(sharded_attributes_destroy),
			unit_test(sharded_event_destroy),
			unit_test(shard_context_destroy),
			unit_test(bucket_delete),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

