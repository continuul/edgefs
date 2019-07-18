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
#include "ccowd.h"
#include "replicast.h"
#include "ccow-impl.h"
#include "../src/libccow/ec-common.h"

#define PUT_FILE_BUCKET		"put-file-bucket-test"
#define PUT_FILE_CLUSTER	"cltest"
#define PUT_FILE_TENANT		"test"
#define PUT_FILE_OID		"file-put"
#define PUT_FILE_BS		4096
#define PUT_FILE_EC_ALGORITHM	ECA_XOR
#define PUT_FILE_EC_WIDTH	3
#define PUT_FILE_EC_PARITY	1
#define PUT_FILE_PATH		"/var/log/syslog"

size_t block_size = PUT_FILE_BS;
off_t object_size = 0;
int btree_order = -1;
uint8_t ec_algorithm = PUT_FILE_EC_ALGORITHM;
uint8_t ec_width = PUT_FILE_EC_WIDTH;
uint8_t ec_parity = PUT_FILE_EC_PARITY;
char *bucket_name = PUT_FILE_BUCKET;
char *object_name = PUT_FILE_OID;
char *cluster_name = PUT_FILE_CLUSTER;
char *tenant_name = PUT_FILE_TENANT;
char *file_path = PUT_FILE_PATH;
char *clone_path = NULL;
ccow_t cl = NULL;
int offset = 0;
int dd = 0;
int ec_encode = 0;
int ec_version = 0;
int obj_replace = 0;
uint64_t ec_delay = 120;
uint16_t n_versions = 1;
char *TEST_ENV = NULL;
uint8_t rep_cnt = 0;
int show_perf = 0;
int mdonly = 0;
uint64_t pin = ondemandPolicyUnpin;
uint64_t expunge_genid = 0ULL;

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
simple_put_file(void **state)
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

	struct iovec *tmp_iov = je_malloc(iovcnt * sizeof(struct iovec));
	assert_non_null(tmp_iov);

	void *tmp = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(tmp != MAP_FAILED);

	char *mmaped = tmp;
	assert_non_null(mmaped);
	iov[0].iov_base = mmaped + offset;
	len -= offset;

	err = close(fd);
	assert_int_equal(err, 0);
	iov[0].iov_len = block_size;

	printf("simple_put_file: iovcnt %lu, len %lu, offset %d\n", iovcnt,
		len, offset);

	for (size_t i = 1; i < iovcnt; i++) {
		iov[i].iov_len = block_size;
		iov[i].iov_base = (char *)iov[i - 1].iov_base + block_size;
	}
	if (len % block_size) {
		iov[iovcnt - 1].iov_len = len % block_size;
	}

	tmp_iov[0].iov_len = block_size;
	tmp_iov[0].iov_base = je_malloc(block_size);

	assert_non_null(tmp_iov[0].iov_base);

	ccow_completion_t c;
	int attrs = 0;
	uint64_t genid = 0;
	if (obj_replace)
		attrs |= CCOW_CONT_F_REPLACE;
	err = ccow_create_stream_completion(cl, NULL, NULL, 2, &c,
		bucket_name, strlen(bucket_name) + 1,
		object_name, strlen(object_name) + 1, &genid,
		&attrs, NULL);
	assert_int_equal(err, 0);

	uint32_t bs = block_size;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
		(void *)&bs, NULL);
	assert_int_equal(err, 0);

	if (btree_order > 0) {
		uint16_t bto = btree_order;
		err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
			(void *)&bto, NULL);
		assert_int_equal(err, 0);
	}
	if (rep_cnt > 0) {
		err = ccow_attr_modify_default(c, CCOW_ATTR_REPLICATION_COUNT,
			(void *)&rep_cnt, NULL);
		assert_int_equal(err, 0);
	}

	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
		(void *)&n_versions, NULL);
	assert_int_equal(err, 0);

	if (ec_encode) {
		uint8_t ec_enabled = 1;
		err = ccow_attr_modify_default(c, CCOW_ATTR_EC_ENABLE,
			(void *)&ec_enabled, NULL);
		assert_int_equal(err, 0);

		uint32_t ec_algo = TO_CODECFMT(ec_width, ec_parity);;
		SET_CODECID(ec_algo, ec_algorithm);
		err = ccow_attr_modify_default(c, CCOW_ATTR_EC_ALGORITHM,
			(void *)&ec_algo, NULL);
		assert_int_equal(err, 0);

		uint64_t trg_policy = TO_TRG_POLICY(EC_TRG_POLICY_TIMEOUT, ec_delay);
		err = ccow_attr_modify_default(c, CCOW_ATTR_EC_TRG_POLICY,
			(void *)&trg_policy, NULL);

	}
	if (mdonly) {
		uint16_t inline_flags = c->inline_data_flags;
		RT_ONDEMAND_SET(c->inline_data_flags, ondemandPolicyUnpin);
		err = ccow_attr_modify_default(c, CCOW_ATTR_INLINE_DATA_FLAGS,
			(void *)&inline_flags, NULL);

	}

	printf("bucket name: %s, object name: %s\n", bucket_name, object_name);
	err = ccow_get_cont(c, tmp_iov, 1, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, 1);
	if (err > 0)
		printf("ccow_wait returned err %d (%s)\n", err, strerror(err));
	if (err < 0)
		printf("ccow_wait returned err -%d (%s)\n", -err, strerror(-err));
	assert_int_equal(err, 0);

	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	je_free(tmp_iov[0].iov_base);
	je_free(tmp_iov);
	tmp_iov = NULL;

	size_t pos = 0;
	while (pos < iovcnt) {
		uint64_t ts = get_timestamp_us();
		size_t iolen = CCOW_IOVCNT_MAX_EMBEDDED;
		if (pos + iolen > iovcnt)
			iolen = iovcnt - pos;
		err = ccow_create_stream_completion(cl, NULL, NULL, 2, &c,
			bucket_name, strlen(bucket_name) + 1,
			object_name, strlen(object_name) + 1, &genid,
			&attrs, NULL);
		assert_int_equal(err, 0);

		err = ccow_put_cont(c, iov + pos, iolen, pos*block_size, 1, NULL);
		assert_int_equal(err, 0);

		err = ccow_wait(c, 1);
		assert_int_equal(err, 0);

		err = ccow_finalize(c, NULL);
		assert_int_equal(err, 0);
		if (err != 0) {
			printf("ccow_wait returned err = %d \n", err);
		}
		if (show_perf) {
			uint64_t perf = iolen*block_size*1000000UL/(get_timestamp_us() - ts);
			printf("Written %lu (%lu kB/s)\n", iolen*block_size, perf/1024);
		}
		assert_int_equal(err, 0);
		pos += iolen;
	}
	err = munmap(mmaped, len+offset);
	assert_int_equal(err, 0);
	je_free(iov);
}

static void
clone_test(void **state)
{
	assert_non_null(cl);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	struct ccow_copy_opts copy_opts;
	copy_opts.tid = tenant_name;
	copy_opts.tid_size = strlen(tenant_name) + 1;
	copy_opts.bid = bucket_name;
	copy_opts.bid_size = strlen(bucket_name) + 1;
	copy_opts.oid = clone_path;
	copy_opts.oid_size = strlen(clone_path) + 1;
	copy_opts.genid = NULL;
	copy_opts.version_uvid_timestamp = 0;
	copy_opts.version_vm_content_hash_id = NULL;
	printf("Clonning %s -> %s\n", object_name, clone_path);
	err = ccow_clone(c, "test", 5, bucket_name, strlen(bucket_name) + 1,
		object_name, strlen(object_name) + 1, &copy_opts);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
}

static void
pin_test(void** state)
{
	assert_non_null(cl);
	int err = ccow_ondemand_policy_change(cl, bucket_name, strlen(bucket_name) + 1,
		object_name, strlen(object_name) + 1, 0, pin);
	assert_int_equal(err, 0);
}

static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, bucket_name, object_name, NULL, NULL);
}

static void
object_expunge(void **state)
{
	assert_non_null(cl);
	if (expunge_genid == 0) {
		ccow_completion_t c;
		int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);
		assert_int_equal(ccow_expunge(bucket_name,strlen(bucket_name) + 1,
			object_name, strlen(object_name) + 1, c), 0);
		assert_int_equal(ccow_wait(c, 0), 0);
	} else {
		/* Find a version we going to expunge */
		ccow_completion_t c;
		 ccow_lookup_t iter;
		int err = ccow_create_completion(cl, NULL, NULL, 2, &c);
		assert_int_equal(err, 0);

		err = ccow_get_versions(bucket_name,strlen(bucket_name) + 1, object_name, strlen(object_name) + 1,  c, &iter);
		assert_int_equal(err, 0);

		err = ccow_wait(c, 0);
		assert_int_equal(err, 0);

		struct ccow_metadata_kv *kv = NULL;
		int pos = 0;
		char *c512;
		char version_vm_content_hash_id[512];
		uint64_t version_uvid_timestamp = 0;
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
			uint64_t timestamp = atol(c512);
			c512 = strtok_r(NULL,"|", &sp);
			uint64_t genid = atoi(c512);
			if (expunge_genid == genid) {
				c512 = strtok_r(c,"|", &sp);
				c512 = strtok_r(NULL,"|", &sp);
				strcpy(version_vm_content_hash_id, c512);
				version_uvid_timestamp = timestamp;
				break;
			}
			je_free(b);
			je_free(c);
		}
		ccow_lookup_release(iter);
		if (!version_uvid_timestamp) {
			printf("ERROR: Version %lu not found", expunge_genid);
			assert_int_not_equal(version_uvid_timestamp, 0);
		}
		err = ccow_expunge_version(bucket_name,strlen(bucket_name) + 1, object_name, strlen(object_name) + 1,
			&expunge_genid, version_uvid_timestamp, version_vm_content_hash_id, c);
		assert_int_equal(err, 0);

		err = ccow_wait(c, 1);
		assert_int_equal(err, 0);
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
		"	%s [-h] [-b block_size] [-s file_size] [-n]\n"
		"		[-o obj_name] [-B bucket_name] [file_path]\n"
		"\n"
		"	-h	Display this message and exit\n"
		"\n"
		"	-b	Specify block size in form of "
		"\"[0-9]+[GgMmKkBb]?\"\n"
		"\n"
		"	-s	Specify file size in form of "
		"\"[0-9]+[GgMmKkBb]?\"\n"
		"\n"
		"	-n	Do not start daemon\n"
		"\n"
		"	-o	Specify object name\n"
		"\n"
		"	-B	Specify bucket name\n"
		"\n"
		"	-t	Specify tenant name\n"
		"\n"
		"	-c	Specify cluster name\n"
		"\n"
		"	-d	btree order (valid range 4..192)\n"
		"\n"
		"	-e	erasure-encode object\n"
		"\n"
		"	-a	EC algorithm index (1 - XOR)\n"
		"\n"
		"	-w	EC stripe width (valid range 2..32)\n"
		"\n"
		"	-p	EC # of parity bits (valid range 1..6)\n"
		"\n"
		"	-v	EC encoding delay, sec\n"
		"\n"
		"	-r	Replication count for put operation\n"
		"\n"
		"	-N	Number of object versions to keep\n"
		"\n"
		"	-R	Replace the object (opposite to overwrite)"
		"\n"
		"	-D	Delete the object"
		"\n"
		"	-O	File offset to put from"
		"\n"
		"	-C	Clone object to specified OID"
		"\n"
		"	-P	Show write progress"
		"\n"
		"	-M	Put an object with MDonly option set"
		"\n"
		"	-E <gen> Expunge an object version/all"
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
	int del = 0;
	int persist = 0;
	int expunge = 0;

	while ((opt = getopt(argc, argv, "hea:w:p:d:b:s:no:B:r:v:N:RDO:C:PMm:c:t:E:")) != -1) {
		switch(opt) {
			case 'm':
				persist =1;
				pin = atoi(optarg);
				break;

			case 'e':
				ec_encode = 1;
				break;
			case 'a':
				ec_algorithm = atoi(optarg);
				if (ec_algorithm <= ECA_NONE ||
					ec_algorithm >= ECA_END)
					ec_algorithm = PUT_FILE_EC_ALGORITHM;
				break;
			case 'w':
				ec_width = atoi(optarg);
				if (ec_width < 2)
				       ec_width = 2;
				if (ec_width > 32)
					ec_width = 32;
				break;
			case 'p':
				ec_parity = atoi(optarg);
				if (ec_parity < 1)
				       ec_parity = 1;
				if (ec_parity > 6)
					ec_parity = 6;
				break;
			case 'P':
				show_perf = 1;
				break;
			case 'd':
				btree_order = atoi(optarg);
				if (btree_order < 4)
					btree_order = 4;
				if (btree_order > 640)
					btree_order = 640;
				break;
			case 'b':
				block_size = sst_convert_bytes(optarg);
				break;

			case 's':
				object_size = sst_convert_bytes(optarg);
				break;

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

			case 'r':
				rep_cnt = sst_convert_bytes(optarg);
				break;

			case 'v':
				ec_delay = atoi(optarg);
				break;

			case 'N':
				n_versions = sst_convert_bytes(optarg);
				break;

			case 'R':
				obj_replace = 1;
				break;

			case 'D':
				del = 1;
				break;

			case 'O':
				offset = atoi(optarg);
				if (offset < 0)
					offset = 0;
				break;

			case 'C':
				clone_path = strdup(optarg);
				break;

			case 'M':
				mdonly = 1;
				break;

			case 'E':
				expunge = 1;
				expunge_genid = atoi(optarg);
				break;

			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}
	if (optind < argc) {
		file_path = argv[optind];
	}
	TEST_ENV = getenv("NEDGE_ENV");
	if (!TEST_ENV)
		TEST_ENV = "production";
	if (del) {
		const UnitTest edelete_tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(object_delete),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		return run_tests(edelete_tests);
	} if (expunge) {
		const UnitTest edelete_tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(object_expunge),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		return run_tests(edelete_tests);
	} else if (clone_path) {
		const UnitTest edelete_tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(clone_test),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		return run_tests(edelete_tests);
	} else if (persist) {
		const UnitTest persist_tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(pin_test),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		return run_tests(persist_tests);
	} else {
		const UnitTest put_tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(simple_put_file),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		return run_tests(put_tests);
	}
}

