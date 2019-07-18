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
#include "ccowd-impl.h"
#include "reptrans.h"

#define TRANS_RTRD	"rtrd"
#define MAX_DEV 256
static ccow_t tc;
static char *config_buf = NULL;

const char *transport[] = { "rtlfs" };
struct repdev *devices[MAX_DEV];
struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

static int n_dev = 0;
static int dd = 0;
static int daemon_initialized = 0;
char *cval = NULL;
type_tag_t ttag;
crypto_hash_t htype;


type_tag_t
convert_ttag(char *ttype)
{
	type_tag_t tt = TT_INVALID;
	if (!ttype) {
		return tt;
	}
	if (strcmp(ttype, "TT_CHUNK_MANIFEST") == 0) {
		tt = TT_CHUNK_MANIFEST;
	} else if (strcmp(ttype, "TT_CHUNK_PAYLOAD") == 0) {
		tt = TT_CHUNK_PAYLOAD;
	} else if (strcmp(ttype, "TT_VERSION_MANIFEST") == 0) {
		tt = TT_VERSION_MANIFEST;
	} else if (strcmp(ttype, "TT_NAMEINDEX") == 0) {
		tt = TT_NAMEINDEX;
	} else {
		printf("WARNING: not supported ttype %s\n", ttype);
	}
	return tt;
}

crypto_hash_t
convert_htype(char *hash_type)
{
	crypto_hash_t hdef = HASH_TYPE_DEFAULT;
	if (!hash_type) {
		return hdef;
	}
	if (strcmp(hash_type, "HASH_TYPE_BLAKE2B_256") == 0) {
		hdef = HASH_TYPE_BLAKE2B_256;
	} else if (strcmp(hash_type, "HASH_TYPE_BLAKE2B_512") == 0) {
		hdef = HASH_TYPE_BLAKE2B_512;
	} else if (strcmp(hash_type, "HASH_TYPE_XXHASH_128") == 0) {
		hdef = HASH_TYPE_XXHASH_128;
	} else {
		printf("WARNING: not supported htype %s\n", hash_type);
	}
	return hdef;
}

static void
enum_dev__done_cb(struct repdev *dev, void *arg, int status)
{
	struct enum_dev_arg *da = (struct enum_dev_arg *)arg;
	assert_non_null(da);
	if (status == 0)
		da->dev[da->n_dev++] = dev;
	assert_true(da->n_dev < MAX_DEV);
}

static void
libccowd_setup(void **state)
{
	if (!dd) {
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(2 * 1000000L);
	}
	daemon_initialized = 1;
}

static void
libccow_setup(void **state)
{
	assert_int_equal(daemon_initialized, 1);
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	config_buf = je_calloc(1, 16384);
	assert_non_null(config_buf);
	assert_true(read(fd, config_buf, 16384) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_admin_init(config_buf, "", 1, &tc), 0);

	/* initialize 0x0 sys object */
	int err = ccow_system_init(tc);
	if (err && err != -EEXIST)
		assert_int_equal(err, 0);

	/* Get request on sysobject */
	get(tc, "", "", NULL, 0, 0, NULL, NULL, NULL);
}

static void
libreptrans_setup(void **state)
{
	struct enum_dev_arg enum_arg = {0, devices};
	assert_int_equal(reptrans_enum(NULL, &enum_arg,
		    enum_dev__done_cb, 0), 0);
	n_dev = enum_arg.n_dev;
	printf("ndev: %d", n_dev);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	usleep(100000L);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state) {
	usleep(100000L);
	if (!dd) {
		ccow_daemon_term();
	}
}

static int
libreptrans_enum(void)
{
	struct enum_dev_arg enum_arg = {0, devices};

	assert_int_equal(reptrans_enum(NULL, &enum_arg,
		    enum_dev__done_cb, 0), 0);
	return enum_arg.n_dev;
}

static void
reptrans_del_test(void **state)
{
	assert_non_null(cval);
	uint512_t chid = uint512_null;

	uint512_fromhex(cval, UINT512_BYTES * 2 + 1, &chid);

	int err =  reptrans_init(0, NULL, NULL,
		RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;

	int n = err;
	assert_int_not_equal(n, 0);
	for (int i = 0; i < n; i++) {
		struct repdev* dev = devices[i];
		char chidstr[UINT512_STR_BYTES];
		uint512_dump(&chid, chidstr, UINT512_STR_BYTES);
		printf("Dev: %s ttag %s ht %s chid %s\n", dev->path, type_tag_name[ttag], hash_type_name[htype], chidstr);
		err = reptrans_delete_blob(dev, ttag, htype, &chid);
		if (err != 0) {
			printf("Error: %d\n", err);
		}
	}

	usleep(1000L);
}

void
usage(char *arg)
{
	printf("%s -n -d <ID> -t <type_tag> -h <hashtype>\n", arg);
}

int
main(int argc, char *argv[]) {

	int opt = 0;
	char *state = NULL;

	while ((opt = getopt(argc, argv, "nd:t:h:")) != -1) {
		switch(opt) {
			case 'n':
				dd = 1;
				daemon_initialized = 1;
				break;
			case 'd':
				cval = optarg;
				break;
			case 't':
				ttag = convert_ttag(optarg);
				break;
			case 'h':
				htype = convert_htype(optarg);
				break;
			default:
				break;
		}
	}

	if (!cval) {
		usage(argv[0]);
		return -EINVAL;
	}
	char cmd[PATH_MAX];
	snprintf(cmd, sizeof(cmd), "cat %s/etc/ccow/ccowd.json|grep rtrd 2>/dev/null >/dev/null",
		nedge_path());

	if (system(cmd) == 0)
		transport[0] = TRANS_RTRD;

	const UnitTest tests[] = {
		unit_test(reptrans_del_test),
	};
	return run_tests(tests);
}
