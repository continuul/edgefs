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

#include "replicast.h"
#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"

/*
 * =======================================================================
 *		Stgt creation of LUNs, Btree with sector size 4k
 * =======================================================================
 */
#define STGT_MARKERS_DEF	0
#define STGT_LUN_DEF		0
#define STGT_CNT_DEF		1
#define STGT_TEST_BS_DEF	4096
#define STGT_TEST_CS_DEF	(32 * 1024)
#define STGT_TEST_VS_DEF	(8 * 1024 * 1024 * 1024L)

static uint32_t stgt_markers = STGT_MARKERS_DEF;
static uint32_t stgt_lun = STGT_LUN_DEF;
static uint32_t stgt_cnt = STGT_CNT_DEF;
static uint32_t stgt_bs  = STGT_TEST_BS_DEF;
static uint32_t stgt_cs  = STGT_TEST_CS_DEF;
static uint64_t stgt_vs  = STGT_TEST_VS_DEF;

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
	       "     ./stgt_test [-h] [-l lun] [-n count] \n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -b   Block size, may be appended with a unit specifier\n"
	       "         of B,K,M, or G.\n"
	       "         (Defaults to 4K.)\n"
	       "\n"
	       "    -c   Chunk size, may be appended with a unit specifier\n"
	       "         of B,K,M, or G.\n"
	       "         (Defaults to 32K.)\n"
	       "\n"
	       "    -l   Starting logical unit number.\n"
	       "         (Defaults to 0.)\n"
	       "\n"
	       "    -n   Number of logical units to create.\n"
	       "         (Defaults to 1.)\n"
	       "\n"
	       "    -m   Enable use of Manifest Markers\n"
	       "\n"
	       "    -v   Volume size, may be appended with a unit specifier\n"
	       "         of B,K,M, or G.\n"
	       "         (Defaults to 8G.)\n"
	       "\n"
	       "    -x   Run tgtd Call libiscsi xcopy unit tests \n"
	       "         \n"
	       "\n"
	       "    -B bucket  Use specific bucket name\n"
	       "         \n"
	       "         \n"
	       "\n");

	exit(EXIT_SUCCESS);
}


char *STGT_BUCKET_NAME = "ccowbd";
ccow_t cl = NULL;

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
	int err = ccow_bucket_create(cl, STGT_BUCKET_NAME,
	    strlen(STGT_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
stgt_lun_create(void **state)
{
	uint32_t lun_start = stgt_lun;
	uint32_t lun_count = stgt_cnt;
	uint32_t lun;

	for (lun = lun_start; lun < (lun_count + lun_start); lun++) {
		printf("Creating LUN %d. \n", lun);

		assert_non_null(cl);
		int err;

		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		uint32_t bs = stgt_cs;
		err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
		    (void *)&bs, NULL);
		assert_int_equal(err, 0);

		uint16_t tracking = 1;
		err = ccow_attr_modify_default(c, CCOW_ATTR_TRACK_STATISTICS,
		    (void *)&tracking, NULL);
		assert_int_equal(err, 0);

		uint16_t num_vers = 1;
		err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
		    (void *)&num_vers, NULL);
		assert_int_equal(err, 0);

		uint16_t order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_DEFAULT;
		err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		    (void *)&order, NULL);
		assert_int_equal(err, 0);

		if (stgt_markers) {
			uint16_t marker = 1;
			err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_MARKER,
			    (void *)&marker, NULL);
			assert_int_equal(err, 0);
		}

		uint64_t volsize = stgt_vs;
		err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64,
		    "X-volsize", strlen("X-volsize") + 1, &volsize, 0, NULL);
		assert_int_equal(err, 0);

		uint32_t blocksize = stgt_bs;
		err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT32,
		    "X-blocksize", strlen("X-blocksize") + 1, &blocksize, 0, NULL);
		assert_int_equal(err, 0);

		uint8_t hash_type = 8; // XXHASH_128
		err = ccow_attr_modify_default(c, CCOW_ATTR_HASH_TYPE,
		    (void *)&hash_type, NULL);
		assert_int_equal(err, 0);

		char tmp[32];
		sprintf(tmp, "%d", lun);

		struct iovec iov[1];
		iov[0].iov_len = stgt_cs;
		iov[0].iov_base = je_malloc(iov[0].iov_len);
		assert_non_null(iov[0].iov_base);

		uint64_t lastsect_off = volsize - stgt_cs;
		printf("Writing %d bytes to lastsect_off 0x%lX ...\n",
		    stgt_cs, lastsect_off);

		put_simple(c, STGT_BUCKET_NAME, tmp, &iov[0], 1, lastsect_off);

		err = ccow_wait(c, -1);
		assert_int_equal(err, 0);

		je_free(iov[0].iov_base);
	}
}

// ============================================================================
// libccow_teardown
//
// 1. terminate ccow tenant
// ============================================================================
static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
stgt_run_target_test(void **state) {

	int err;
	pid_t tgtd_pid = fork();
	char cmd[PATH_MAX];
	snprintf(cmd, sizeof(cmd), "%s/sbin/tgtd", nedge_path());
	switch(tgtd_pid) {
		case -1:
			printf("can't fork \n");
			assert_true(false);
			break;
		case 0:
			printf("starting iscsi target \n");

			execl(cmd, cmd, "-f", NULL);
			break;
		default:
			sleep(1);
			printf("creating LUNs\n");
			err = system("tgt_lun.sh -l1 -n1");
			assert_int_equal(err, 0);
			err = system("iscsi-test-cu iscsi://127.0.0.1/iqn.2005-11.com.nexenta"
					":storage.disk1.ccow.gateway2/1 --test ALL.ExtendedCopy --dataloss");
			assert_int_equal(err, 0);
			err = system("iscsi-test-cu iscsi://127.0.0.1/iqn.2005-11.com.nexenta"
								":storage.disk1.ccow.gateway2/1"
								" --test ALL.ReceiveCopyResults.OpParams --dataloss");
			assert_int_equal(err, 0);
			kill(tgtd_pid,SIGTERM);
			break;
		}
}



// ==================================
// test options
// ==================================
const UnitTest tests[] = {
	unit_test(libccow_setup),
	unit_test(bucket_create),
	unit_test(stgt_lun_create),
	unit_test(libccow_teardown),
};

const UnitTest xcopytests[] = {
	unit_test(libccow_setup),
	unit_test(bucket_create),
	unit_test(stgt_lun_create),
	unit_test(stgt_run_target_test),
	unit_test(libccow_teardown),
};

/*
 * ============================================================================
 * main
 * ============================================================================
 */
int
main(int argc, char ** argv)
{
	/*
	 * parse command line options
	 */
	int opt;
	int runiscsitests = 0;

	while ((opt = getopt(argc, argv, "hxb:c:l:n:v:mB:")) != -1) {
		switch(opt) {

		case 'h':
			usage();
			break;

		case 'm':
			stgt_markers = 1;
			break;

		case 'b':
			stgt_bs = sst_convert_bytes(optarg);
			break;

		case 'B':
			STGT_BUCKET_NAME = optarg;
			break;

		case 'c':
			stgt_cs = sst_convert_bytes(optarg);
			break;

		case 'l':
			stgt_lun = atoi(optarg);
			break;

		case 'n':
			stgt_cnt = atoi(optarg);
			break;

		case 'v':
			stgt_vs = sst_convert_bytes(optarg);
			break;

		case 'x':
			runiscsitests = 1;
			break;

		default:
			usage();
			break;
		}
	}

	if (runiscsitests) {
		return run_tests(xcopytests);
	}

	return run_tests(tests);
}

