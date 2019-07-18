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
#define GET_FILE_BUCKET		"put-file-bucket-test"
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

int chunk_count = -1;
uint64_t offset = 0;
size_t block_size = GET_FILE_BS;
off_t object_size = GET_FILE_BS * GET_FILE_BTREE_ORDER;
int btree_order = GET_FILE_BTREE_ORDER;
uint8_t ec_algorithm = GET_FILE_EC_ALGORITHM;
uint8_t ec_width = GET_FILE_EC_WIDTH;
uint8_t ec_parity = GET_FILE_EC_PARITY;
char *cluster_name = GET_FILE_CLUSTER;
char *tenant_name = GET_FILE_TENANT;
char *bucket_name = GET_FILE_BUCKET;
char *object_name = GET_FILE_OID;
char *file_path = GET_FILE_PATH;
ccow_t cl = NULL;

int ec_encode = 0;
int no_file = 0;
char *TEST_ENV = NULL;

extern int errno;

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
	assert_int_equal(ccow_tenant_init(buf, cluster_name, strlen(cluster_name)+1,
	    tenant_name, strlen(tenant_name)+1, &cl), 0);
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
simple_get_file(void **state)
{
	int get_fd = 0;
	if (!no_file) {
		get_fd = open(file_path, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600);
		if (!get_fd) {
			fprintf(stderr, "Error opening an output file %d: %s", -errno,
				strerror(errno));
		}
		assert_true(get_fd >= 0);
	}
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
	err = ccow_tenant_init(buf, cluster_name, strlen(cluster_name) + 1,
		tenant_name, strlen(tenant_name) + 1, &cl);
	if (err) {
		printf("ccow_tenant_init error: %d\n", err);
	}
	assert_int_equal(err, 0);
	assert_non_null(cl);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		printf("ccow_create_completion error: %d\n", err);
	}
	assert_int_equal(err, 0);

	printf("bucket name: %s, object name: %s\n", bucket_name, object_name);
	ccow_lookup_t iter;
	err = ccow_get(bucket_name, strlen(bucket_name) + 1, object_name,
		strlen(object_name) + 1, c, NULL, 0, 0, &iter);
	if (err) {
		ccow_release(c);
		printf("ccow_get error: %d\n", err);
	}
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	if (err) {
		printf("ccow_wait error: %d\n", err);
	}
	assert_int_equal(err, 0);

	uint64_t size = 0;
	uint32_t chunk_size = 0;
	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
		if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &size);
		} else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv,
			    &chunk_size);
		}
	}


	if (chunk_count != -1)
		size = chunk_count * chunk_size + 1;

	printf("object size %lu, block size %u offset %ld chunk_count %d\n",
	    size, chunk_size, offset, chunk_count);
	ccow_lookup_release(iter);
	char* iob = NULL;
	if (!no_file) {
		assert_int_equal(fallocate(get_fd, 0, 0, size), 0);
		iob = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_PRIVATE, get_fd, 0);
		assert_true(iob != MAP_FAILED);
	} else {
		iob = je_malloc(size);
		assert_non_null(iob);
	}

	int iovcnt = chunk_count == -1 ?
		(int)(size / chunk_size + !!(size % chunk_size)) : chunk_count;

	struct iovec *iov = je_malloc(iovcnt * sizeof(struct iovec));
	assert_non_null(iov);
	for (int i = 0; i < iovcnt; i++) {
		iov[i].iov_len = chunk_size;
		iov[i].iov_base = iob + i*chunk_size;
	}
	size_t pos = 0;
	uint64_t genid = 0;
	err = ccow_create_stream_completion(cl, NULL, NULL, 2+iovcnt, &c,
		bucket_name, strlen(bucket_name) + 1,
		object_name, strlen(object_name) + 1, &genid,
		NULL, NULL);
		assert_int_equal(err, 0);
	
	uint32_t bs = chunk_size;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
		(void *)&bs, NULL);
	assert_int_equal(err, 0);
	
	int cnt = 0;
	while (pos < iovcnt) {
		size_t iolen = CCOW_IOVCNT_MAX_EMBEDDED;
		if (pos + iolen > iovcnt)
			iolen = iovcnt - pos;


		printf("read offset %lu\n", pos*chunk_size);
		err = ccow_get_cont(c, iov + pos, iolen, pos*chunk_size, 1, &cnt);
		
		if (!err)
			err = ccow_wait(c, cnt);

		if (err != 0) {
			printf("ERROR: ccow_wait returned err = %d \n", err);
			break;
              	}
		pos += iolen;
	}
	ccow_finalize(c, NULL);
	if (!no_file) {
		close(get_fd);
		munmap(iob, size);
	} else {
		for (int k = 0; chunk_count != -1 && k < chunk_count; k++) {
			printf("Start of chunk %d:\n", k+1);
			for (int j = 0; j < 16; j++) {
				printf("%lX: ", offset + k*chunk_size + j*16);
				for (int i = 0; i < 16; i++) {
					printf(" 0x%x", (uint8_t)((char*)iov[k].iov_base)[i+j*16]);
				}
				printf("\n");
			}
		}
		je_free(iob);
	}
	je_free(iov);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
usage(const char *argv0)
{
	printf(	"\n"
		"USAGE:\n"
		"	%s [-h] [-c cluster_name] [-t tenant_name]\n"
		"          [-B bucket_name ] [-o obj_name] <file_path>\n"
		"\n"
		"	-h	Display this message and exit\n"
		"\n"
		"	-o	Specify object name\n"
		"\n"
		"	-B	Specify bucket name\n"
		"\n"
		"	-c	Specify cluster name\n"
		"\n"
		"	-t	Specify tenant name\n"
		"\n"
		"	-C	Number of chunks to read off offset\n"
		"\n"
		"	-O	Start offset (0 default)\n"
		"\n"
		"	-f	Don't create an ouput file\n"
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

	while ((opt = getopt(argc, argv, "nhfo:O:C:B:c:t:")) != -1) {
		switch(opt) {
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

			case 'O':
				offset = atol(optarg);;
				break;

			case 'C':
				chunk_count = atoi(optarg);;
				break;

			case 'f':
				no_file = 1;
				break;

			case 'n':
				// ignore
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
		unit_test(simple_get_file),
		unit_test(libccow_teardown)
	};
	return run_tests(get_tests);
}

