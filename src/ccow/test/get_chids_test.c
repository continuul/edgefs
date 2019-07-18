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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
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

#define GET_FILE_CLUSTER	"cltest"
#define GET_FILE_TENANT		"test"
#define GET_FILE_BUCKET		"get_chids_bucket-test"
#define GET_FILE_OID		"file-put"
#define GET_FILE_OID_CONT	"file-put-cont"
#define GET_FILE_OID_RC1	"file-put-rc1"
#define GET_FILE_OID_RC2	"file-put-rc2"
#define GET_FILE_OID_RC3	"file-put-rc3"
#define GET_FILE_OID_RC4	"file-put-rc4"
#define GET_FILE_BS		4096
#define GET_FILE_BTREE_ORDER	16
#define GET_FILE_EC_ALGORITHM	ECA_XOR
#define GET_FILE_EC_WIDTH	3
#define GET_FILE_EC_PARITY	1
#define GET_FILE_PATH		"/tmp/file-put.read"
#define PUT_FILE_PATH		"/var/log/syslog"

size_t block_size = GET_FILE_BS;
off_t object_size = GET_FILE_BS * GET_FILE_BTREE_ORDER;
int btree_order = GET_FILE_BTREE_ORDER;
uint8_t ec_algorithm = GET_FILE_EC_ALGORITHM;
uint8_t ec_width = GET_FILE_EC_WIDTH;
uint8_t ec_parity = GET_FILE_EC_PARITY;
char *cluster_name = GET_FILE_CLUSTER;
char *tenant_name = GET_FILE_TENANT;
char *bucket_name = GET_FILE_BUCKET;
char *object_name = PUT_FILE_PATH;
char * chunkmap_type = "btree_map";
uint8_t rep_cnt = 3;
uint16_t n_versions = 1;
char *file_path = PUT_FILE_PATH;
ccow_t cl = NULL;

int dd = 0;
int ec_encode = 0;
char *TEST_ENV = NULL;

extern int errno;

static void
libccowd_setup(void **state)
{
    if(!dd) {
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
	int err = ccow_bucket_create(cl, bucket_name,
	    strlen(bucket_name) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, bucket_name,
	    strlen(bucket_name) + 1);
	assert_int_equal(err, 0);
}

struct mapping {
	size_t len;
	char *addr;
	size_t iovcnt;
	struct iovec *iov;
};

void get_file__cb(ccow_completion_t comp, void *arg, int index, int status)
{
	assert_non_null(arg);
	struct mapping *mp = (struct mapping *)arg;
	assert_non_null(mp->addr);
	assert_non_null(mp->iov);
	printf("get_file__cb: index %d, status %d\n", index, status);
}

static void
simple_put_file()
{
	assert_non_null(cl);
	assert((block_size % 1024) == 0);

	struct stat st;

	int fd = open(file_path, O_RDONLY);
	assert_false(fd < 0);

	int err = fstat(fd, &st);
	assert_int_equal(err, 0);

	off_t len = st.st_size;
	if (object_size && object_size < len)
		len = object_size;
	size_t iovcnt = len / block_size + !!(len % block_size);
	assert_true(iovcnt > 0);

	struct iovec *iov = je_malloc(iovcnt * sizeof(struct iovec));
	assert_non_null(iov);

	iov[0].iov_base = je_malloc(len);
	assert_non_null(iov[0].iov_base);

	iov[0].iov_len = len;

	char *addr = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	assert_non_null(addr);
	err = close(fd);
	assert_int_equal(err, 0);

	memcpy(iov[0].iov_base, addr, len);

	err = munmap(addr, len);
	assert_int_equal(err, 0);

	printf("simple_put_file: iovcnt %lu, len %lu\n", iovcnt, len);

	for (size_t i = 1; i < iovcnt; i++) {
		iov[i].iov_len = block_size;
		iov[i].iov_base = (char *)iov[i - 1].iov_base + block_size;
	}
	if (len % block_size)
		iov[iovcnt - 1].iov_len = len % block_size;
	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, iovcnt, &c);
	assert_int_equal(err, 0);
	uint32_t bs = block_size;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
		(void *)&bs, NULL);
	assert_int_equal(err, 0);

	uint16_t bto = btree_order;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER, (void *)&bto,
		NULL);
	assert_int_equal(err, 0);
	err = ccow_attr_modify_default(c, CCOW_ATTR_REPLICATION_COUNT,
		(void *)&rep_cnt, NULL);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
		(void *)&n_versions, NULL);
	assert_int_equal(err, 0);

	printf("bucket name: %s, object name: %s\n", bucket_name, object_name);
	err = ccow_put(bucket_name, strlen(bucket_name) + 1, object_name,
		strlen(object_name) + 1, c, iov, iovcnt, 0);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	je_free(iov[0].iov_base);
	je_free(iov);
}

static void
get_chids(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int ccow_fd = open(path, O_RDONLY);
	if (ccow_fd < 0) {
		printf("ccow.json open error %d: %s\n",
			-errno, strerror(errno));
	}
	assert_true(ccow_fd >= 0);

	char buf[16384];
	int err = read(ccow_fd, buf, 16383);
	if (err < 0) {
		printf("ccow.json read error %d: %s\n",
			-errno, strerror(errno));
		close(ccow_fd);
	}
	assert_true(err >= 0);
	close(ccow_fd);
	buf[err] = 0;
	printf("cluster name: %s, tenant name: %s\n",
		cluster_name, tenant_name);
	assert_non_null(cl);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		printf("ccow_create_completion error: %d\n", err);
	}
	assert_int_equal(err, 0);

	printf("bucket name: %s, object name: %s\n", bucket_name, object_name);
	ccow_lookup_t iter;

	simple_put_file();
	
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		printf("ccow_create_completion error: %d\n", err);
	}

	err = ccow_get(bucket_name, strlen(bucket_name) + 1, object_name,
		strlen(object_name) + 1, c, NULL, 0, 0, &iter);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	if (err) {
		printf("ccow_wait error: %d\n", err);
	}
	assert_int_equal(err, 0);

	struct ccow_metadata_kv *kv = NULL;
	uint64_t size = 0;
	uint32_t chunk_size = 0;
	uint512_t vmchid;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
		if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &size);
		} else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv,
			    &chunk_size);
		} else if (strcmp(kv->key, RT_SYSKEY_VM_CONTENT_HASH_ID) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT512, kv,
			    &vmchid);
		}
	}
	printf("object size %lu, block size %u\n", size, chunk_size);
	ccow_lookup_release(iter);
	int iovcnt = size / chunk_size + !!(size % chunk_size);
	char *iob = je_malloc(iovcnt*chunk_size);
	assert_non_null(iob);

	struct iovec *iov = je_malloc(iovcnt * sizeof(struct iovec));
	assert_non_null(iov);
	for (int i = 0; i < iovcnt; i++) {
		iov[i].iov_len = chunk_size;
		iov[i].iov_base = iob + i*chunk_size;
	}
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		printf("ccow_create_completion error: %d\n", err);
	}
	assert_int_equal(err, 0);

	rtbuf_t *rb=NULL;
	err = ccow_get_chids(cluster_name, strlen(cluster_name) + 1, tenant_name,
              strlen(tenant_name) + 1, bucket_name, strlen(bucket_name) + 1,
              object_name, strlen(object_name) + 1, &vmchid, RD_ATTR_CHUNK_MANIFEST,
              c, iov, iovcnt, &rb, &iter);
	if (err) {
		ccow_release(c);
		printf("ccow_get_chids error: %d\n", err);
	}
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	if (err) {
		printf("ccow_wait error: %d\n", err);
	}
	ccow_lookup_release(iter);

	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		printf("ccow_create_completion error: %d\n", err);
	}
	assert_int_equal(err, 0);
	char vv[sizeof (uint512_t) * 2 + 1];

	if (rb) {
	    for (unsigned int i=0;i<rb->nbufs;i++) {
                struct refentry *re = (struct refentry *)rtbuf(rb, i).base;
	        printf("%lu,", re->offset);
	        uint512_dump((uint512_t *)&re->content_hash_id, vv, sizeof (uint512_t) * 2 + 1);
 	        printf("%s\n", vv);
            }
	   je_free(rb);
	}
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
    if(!dd) {
        ccow_daemon_term();
    }
}

static void
usage(const char *argv0)
{
	printf(	"\n"
		"USAGE:\n"
		"	%s [-h] [-n] [-b block_size] [-o obj_name]\n"
		"		[-B bucket_name] [-c cluster_name] "
		"[-t tenant_name] [file_path]\n"
		"\n"
		"	-h	Display this message and exit\n"
		"\n"
		"	-n	Do not start daemon\n"
		"\n"
		"	-o	Specify object name\n"
		"\n"
		"	-B	Specify bucket name\n"
		"\n"
		"	-c	Specify cluster name\n"
		"\n"
		"	-t	Specify tenant name\n"
		"\n", argv0);

	exit(EXIT_SUCCESS);
}

int
main(int argc, char *argv[])
{
	/*
	 * Parse command line
	 */
	int opt;

	while ((opt = getopt(argc, argv, "hno:B:c:t:")) != -1) {
		switch(opt) {
			case 'n':
				dd = 1;
				break;

			case 'o':
				object_name = strdup(optarg);
				break;

			case 'B':
				bucket_name = strdup(optarg);
				break;
			
			case 'c':
				cluster_name = strdup(optarg);
				break;

			case 't':
				tenant_name = strdup(optarg);
				break;

			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}
	if (optind < argc)
		file_path = argv[optind];

	const UnitTest get_tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(get_chids),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(get_tests);
}

