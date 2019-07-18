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
#include "../src/libccow/ec-common.h"
#include "../src/libccow/opp-status.h"

#define UE_BUCKET	"ec-unencode-bucket"
#define UE_OID		"ec-unencode-object"
#define UE_BS		4096
#define UE_EC_ALGORITHM	ECA_RS
#define UE_EC_WIDTH	3
#define UE_EC_PARITY	2
#define UE_N_OVERWRITE	3

size_t block_size = UE_BS;
off_t object_size = 128*1024;
int btree_order = -1;
uint8_t ec_algorithm = UE_EC_ALGORITHM;
uint8_t ec_width = UE_EC_WIDTH;
uint8_t ec_parity = UE_EC_PARITY;
char *bucket_name = UE_BUCKET;
char *object_name = UE_OID;
ccow_t cl = NULL;
int offset = 0;
int n_overwrite = UE_N_OVERWRITE;
int dd = 0;
int n_versions = 1;
uint64_t ec_delay = 120;
uint8_t rep_cnt = 0;
int new_tenant = 0;

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
put_data(void **state)
{
	assert_non_null(cl);
	assert((block_size % 1024) == 0);

	off_t len = object_size;
	uint64_t genid = 0;

	size_t iovcnt = len / block_size + !!(len % block_size);
	assert_true(iovcnt > 0);

	struct iovec *iov = je_malloc(iovcnt * sizeof(struct iovec));
	assert_non_null(iov);
	char* buf = je_malloc(iovcnt * block_size);
	/* Fill up with random data */
	for (size_t k = 0; k < iovcnt * block_size/4; k++) {
		*((uint32_t *)buf + k) = rand();
	}
	iov[0].iov_base = buf;
	iov[0].iov_len = block_size;

	for (size_t i = 1; i < iovcnt; i++) {
		iov[i].iov_len = block_size;
		iov[i].iov_base = (char *)iov[i - 1].iov_base + block_size;
	}

	ccow_completion_t c;
	int attrs = 0;
	int err = ccow_create_stream_completion(cl, NULL, NULL, iovcnt, &c,
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
	assert_int_equal(err, 0);
	err = ccow_get_cont(c, iov, iovcnt, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, 1);
	assert_int_equal(err, 0);
	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);

	err = ccow_create_stream_completion(cl, NULL, NULL, iovcnt, &c,
		bucket_name, strlen(bucket_name) + 1,
		object_name, strlen(object_name) + 1, &genid,
		&attrs, NULL);

	assert_int_equal(err, 0);

	printf("bucket name: %s, object name: %s\n", bucket_name, object_name);
	err = ccow_put_cont(c, iov, iovcnt, 0, 1, NULL);
	assert_int_equal(err, 0);

	err = ccow_wait(c, 1);
	if (err != 0) {
		printf("ccow_wait returned err = %d \n", err);
	}
	assert_int_equal(err, 0);
	err = ccow_finalize(c, NULL);
	assert_int_equal(err, 0);
	je_free(buf);
	je_free(iov);
}

static void
wait_for_encoding(void **state) {
	printf("Sleeping for %lu sec\n", ec_delay);
	sleep(ec_delay);

	ccow_completion_t c;
	int err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);
	uint512_t vmchid, nhid;

	ccow_lookup_t iter;
	err = ccow_get(bucket_name, strlen(bucket_name) + 1, object_name,
		strlen(object_name) + 1, c, NULL, 0, 0, &iter);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA | CCOW_MDTYPE_CUSTOM, -1))) {
		if (strcmp(kv->key, RT_SYSKEY_VM_CONTENT_HASH_ID) == 0) {
			memcpy(&vmchid, kv->value, sizeof(uint512_t));
		} else if (strcmp(kv->key, RT_SYSKEY_NAME_HASH_ID) == 0) {
			memcpy(&nhid, kv->value, sizeof(uint512_t));
		}
	}
	ccow_lookup_release(iter);
	char chidstr[UINT512_BYTES*2+1];
	char nhidstr[UINT512_BYTES*2+1];
	uint512_dump(&vmchid, chidstr, UINT512_BYTES*2+1);
	uint512_dump(&nhid, nhidstr, UINT512_BYTES*2+1);
	chidstr[21] = 0;
	nhidstr[21] = 0;
	printf("Object's VMCHID %s NHID %s\n", chidstr, nhidstr);
	int flags = OPP_STATUS_FLAG_VERIFY | OPP_STATUS_FLAG_ERC | OPP_STATUS_FLAG_CPAR;
	opp_status_t os;
	size_t total_chunks;
	size_t total_verified;
	int done_cnt = 0;
	do {
		sleep(15);
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);
		err = ccow_opp_satus_request(cl,&vmchid, &nhid, c, flags, &os);
		assert_int_equal(err, 0);
		err = ccow_wait(c, -1);
		assert_int_equal(err, 0);
		total_chunks = os.n_cp + os.n_cm_zl + os.n_cm_tl;
		total_verified = os.n_cp_verified + os.n_cm_zl_verified + os.n_cm_tl_verified;
		printf("ecstat: EC %lu/%lu, VER %lu/%lu\n",
			os.n_cm_zl_pp, os.n_cm_zl, total_verified, total_chunks);
		if (os.n_cm_zl_pp == os.n_cm_zl && total_chunks == total_verified)
			done_cnt++;
	} while (done_cnt < 3);

}


static void
object_overwrite(void **state) {
	off_t len = object_size;
	uint64_t genid = 0;
	ccow_completion_t c;
	size_t iovcnt = len / block_size + !!(len % block_size);

	char* buf = je_calloc(1,iovcnt * block_size);
	struct iovec *iov = je_malloc(iovcnt * sizeof(struct iovec));
	assert_non_null(iov);

	iov[0].iov_base = buf;
	iov[0].iov_len = block_size;

	/* Getting the object */
	for (size_t i = 1; i < iovcnt; i++) {
		iov[i].iov_len = block_size;
		iov[i].iov_base = (char *)iov[i - 1].iov_base + block_size;
	}

	int attrs = 0;
	int err = ccow_create_stream_completion(cl, NULL, NULL, iovcnt, &c,
		bucket_name, strlen(bucket_name) + 1,
		object_name, strlen(object_name) + 1, &genid,
		&attrs, NULL);
	assert_int_equal(err, 0);
	int index = 0;
	err = ccow_get_cont(c, iov, iovcnt, 0, 1, &index);
	assert_int_equal(err, 0);

	err = ccow_wait(c, index);
	assert_int_equal(err, 0);
	printf("Object recevied, overriding...\n");
	/* Replacing one or several chunks */
	int z = n_overwrite;
	for (size_t n = offset; n < iovcnt && z; n++,z--) {
		printf("Overwriting chunk %lu\n", n);
		for (size_t k = 0; k < block_size/4; k++) {
			*((uint32_t *)iov[n].iov_base + k) = rand();
		}
	}
	if (!new_tenant) {
		err = ccow_put_cont(c, iov + offset, n_overwrite, 0, 1, &index);
		assert_int_equal(err, 0);
		err = ccow_wait(c, index);
		assert_int_equal(err, 0);
		err = ccow_finalize(c, NULL);
		assert_int_equal(err, 0);
	} else {
		ccow_t cl2 = NULL;
		ccow_completion_t c2;
		int attrs2 = 0;
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
		int fd = open(path, O_RDONLY);
		assert_true(fd >= 0);
		char *buf2 = je_calloc(1, 16384);
		assert_non_null(buf2);
		assert_true(read(fd, buf2, 16383) != -1);
		assert_int_equal(close(fd), 0);
		assert_int_equal(ccow_tenant_init(buf2, "cltest", 7, "test",
			5, &cl2), 0);
		je_free(buf2);

		err = ccow_create_stream_completion(cl2, NULL, NULL, iovcnt, &c2,
				bucket_name, strlen(bucket_name) + 1,
				object_name, strlen(object_name) + 1, &genid,
				&attrs2, NULL);

		err = ccow_put_cont(c2, iov + offset, n_overwrite, 0, 1, &index);
		assert_int_equal(err, 0);
		err = ccow_wait(c2, index);
		assert_int_equal(err, 0);
		err = ccow_finalize(c2, NULL);
		assert_int_equal(err, 0);
	}
	je_free(buf);
	je_free(iov);
}
static void
object_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, bucket_name, object_name, NULL, NULL);
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
		"	-d	btree order (valid range 4..192)\n"
		"\n"
		"	-a	EC algorithm index (1 - XOR)\n"
		"\n"
		"	-w	EC stripe width (valid range 2..32)\n"
		"\n"
		"	-p	EC # of parity bits (valid range 1..6)\n"
		"\n"
		"	-r	Replication count for put operation\n"
		"\n"
		"	-N	Number of object versions to keep\n"
		"\n"
		"	-O	File offset to put from, blocks\n"
		"\n"
		"	-W	Number of blocks to overwrite\n"
		"\n"
		"	-T	Use new TC on overwrite"
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

	while ((opt = getopt(argc, argv, "hea:w:p:d:b:s:no:B:r:N:O:W:T")) != -1) {
		switch(opt) {
			case 'a':
				ec_algorithm = atoi(optarg);
				if (ec_algorithm <= ECA_NONE ||
					ec_algorithm >= ECA_END)
					ec_algorithm = UE_EC_ALGORITHM;
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
			case 'd':
				btree_order = atoi(optarg);
				if (btree_order < 4)
					btree_order = 4;
				if (btree_order > 192)
					btree_order = 192;
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

			case 'r':
				rep_cnt = sst_convert_bytes(optarg);
				break;

			case 'O':
				offset = atoi(optarg);
				if (offset < 0)
					offset = 0;
				break;

			case 'W':
				n_overwrite = atoi(optarg);
				if (n_overwrite < 0)
					n_overwrite = UE_N_OVERWRITE;
				break;

			case 'N':
				n_versions = atoi(optarg);
				if (n_versions < 0)
					n_versions = 1;
				break;
			case 'T':
				new_tenant = 1;
				break;

			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}

	const UnitTest put_tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(put_data),
		unit_test(wait_for_encoding),
		unit_test(object_overwrite),
		unit_test(object_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(put_tests);
}

