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
#include "reptrans.h"

#define MAX_DEV 256
ccow_t cl;
int n_dev = 0;
struct repdev *devices[MAX_DEV];
struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

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
libreptrans_setup(void **state)
{
	assert_int_equal(ccow_daemon_init(NULL), 0);
	struct enum_dev_arg enum_arg = {0, devices};
	assert_int_equal(reptrans_enum(NULL, &enum_arg,
		    enum_dev__done_cb, 0), 0);
	n_dev = enum_arg.n_dev;
}

static int
compare_buf_version_timestamps(const void *a, const void *b)
{
	struct vlentry *aver = (struct vlentry *)a;
	struct vlentry *bver = (struct vlentry *)b;
	return bver->uvid_timestamp - aver->uvid_timestamp;
}

#define N_VERSIONS      12
#define N_OLD_VERSIONS  10

int
reptrans_delete_version_entry(struct repdev *dev, crypto_hash_t hash_type,
	const uint512_t *chid, struct vlentry *ver);

static void
reptrans_put_version__test(void **state)
{
	assert_int_not_equal(n_dev, 0);
	struct vmmetadata md;
	struct timeval tv;
	struct vlentry **vers = NULL;

	size_t i;
	uint512_t nhid = { { {0, 1}, {2, 3} }, { {4, 5}, {6, 7} } };
	memset(&md, 0, sizeof(struct vmmetadata));
	for (i = 0; i < N_VERSIONS; ++i) {
		(void)gettimeofday(&tv, NULL);
		md.uvid_timestamp = tv.tv_sec * 1000000L + tv.tv_usec;
		md.nhid = nhid;
		md.replication_count = 3;
		md.txid_generation = 1;
		assert_int_equal(reptrans_put_version(devices[0], &md, &nhid, 0), 0);
	}
	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation = 0ULL
	};
	rtbuf_t *rb_vers = NULL;
	int err = reptrans_get_versions(devices[0], &md.nhid, &query, &rb_vers);
	char nhidbuf[UINT512_BYTES * 2 + 1];
	uint512_dump(&md.nhid, nhidbuf, UINT512_BYTES * 2 + 1);
	log_trace(lg, "dev %s nhid %s number_of_versions %d nbufs %d\n",
		devices[0]->path, nhidbuf, (int)md.number_of_versions,
		rb_vers ? (int)rb_vers->nbufs : 0);
	assert_int_equal(err, 0);
	vers = je_malloc(sizeof(struct vlentry *) * rb_vers->nbufs);
	assert_non_null(vers);
	for (i = 0; i < rb_vers->nbufs; ++i)
		vers[i] = (struct vlentry *)rtbuf(rb_vers, i).base;

	qsort(vers, rb_vers->nbufs, sizeof(struct vlentry *),
		compare_buf_version_timestamps);

	for (i = N_OLD_VERSIONS; !err && i < rb_vers->nbufs; ++i) {
		log_trace(lg, "dev %s nhid %s delete version %lu\n",
			devices[0]->path, nhidbuf, vers[i]->uvid_timestamp);
		err = reptrans_delete_version_entry(devices[0],
			HASH_TYPE_DEFAULT, &md.nhid, vers[i]);
		if (err)
			log_error(lg,
				"dev %s nhid %s delete version failed %d\n",
				devices[0]->path, nhidbuf, err);
	}

	if (vers)
		je_free(vers);

	if (rb_vers)
		rtbuf_destroy(rb_vers);
	assert_int_equal(reptrans_delete_index(devices[0], HASH_TYPE_DEFAULT,
			&md.nhid), 0);
}

static void
libreptrans_teardown(void **state)
{
	ccow_daemon_term();
}

int
main()
{
	const UnitTest tests[] = {
		unit_test(libreptrans_setup),
		unit_test(reptrans_put_version__test),
		unit_test(libreptrans_teardown)
	};
	return run_tests(tests);
}
