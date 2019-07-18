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
#include "reptrans.h"

static ccow_t tc;
static int daemon_initialized = 0, dd = 0;
static char *config_buf = NULL;

#define TRANS_RTRD	"rtrd"
#define TRANS_RTKVS	"rtkvs"
#define MAX_DEV		256
#define N_VERSIONS	10
#define N_OLD_VERSIONS	5

struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

Logger lg;
struct repdev *devices[MAX_DEV];
const char *transport[] = { "rtlfs" };


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
}

static void
libccow_teardown(void **state)
{
	if (config_buf)
		je_free(config_buf);
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

int reptrans_enum(reptrans_enum_cb_t cb, void *arg,
    reptrans_done_cb_t done, uint64_t timeout)
{
	QUEUE *q;
	struct reptrans *rt;
	int rc;

	/*
	 * Iterate through all transports calling enum()
	 */
	QUEUE_FOREACH(q, &all_rts) {
		rt = QUEUE_DATA(q, struct reptrans, item);
		rt->dev_enum(rt, cb, arg, done, timeout);
	}
	return 0;
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

static int
libreptrans_enum(void)
{
	struct enum_dev_arg enum_arg = {0, devices};

	assert_int_equal(reptrans_enum(NULL, &enum_arg,
		    enum_dev__done_cb, 0), 0);
	return enum_arg.n_dev;
}

#define NUM_OPS 1000

struct ccow_lookup_arg {
	int index;
	ccow_completion_t c;
};

static int
ccow_lookup_iterator(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	uint512_t *key, uv_buf_t *val, void *param) {
	struct ccow_lookup_arg* p = param;
	uint64_t attr = RD_ATTR_CHUNK_PAYLOAD;
	uint512_t ngchid = *key;

	if (ttag == TT_CHUNK_MANIFEST)
		attr = RD_ATTR_CHUNK_MANIFEST;
	else if (ttag == TT_VERSION_MANIFEST) {
		struct vmmetadata md;
		rtbuf_t* rb = rtbuf_init_mapped(val, 1);
		assert_int_equal(0, replicast_get_metadata(rb, &md));
		ngchid = md.nhid;
		rtbuf_destroy(rb);
		attr = RD_ATTR_VERSION_MANIFEST;
	}

	p->c->replication_count = 0;
	if (0 == rand() % 32)
		key->u.u.u = 0;

	log_notice(lg, "Looking for payload %016lX %s", key->u.u.u, type_tag_name[ttag]);
	assert_int_equal(0, ccow_chunk_lookup(p->c, key, &ngchid, hash_type, attr, 1));
	assert_int_equal(0, ccow_wait(p->c, p->index++));
	if (key->u.u.u != 0)
		assert_int_equal(1, p->c->replication_count);
	else
		assert_int_equal(0, p->c->replication_count);
	log_notice(lg, "Lookup done for payload %016lX RC %d", key->u.u.u, p->c->replication_count);
	return p->index > NUM_OPS;
}

static void
ccow_payload_lookup(void** state) {
	ccow_completion_t c;
	assert_int_equal(0, ccow_create_completion(tc, NULL, NULL, NUM_OPS*3 + 2, &c));

	struct ccow_lookup_arg arg = { .index = 0, .c = c };
	int err = libreptrans_enum();
	assert_true(err > 0);

	if (err <= 0)
		return;
	struct repdev* dev = devices[1];

	(void)reptrans_iterate_blobs(dev, TT_CHUNK_PAYLOAD, ccow_lookup_iterator, &arg, 0);
	(void)reptrans_iterate_blobs(dev, TT_CHUNK_MANIFEST, ccow_lookup_iterator, &arg, 0);
	(void)reptrans_iterate_blobs(dev, TT_VERSION_MANIFEST, ccow_lookup_iterator, &arg, 1);
}


static void
libccowd_teardown(void **state) {
	usleep(200000L);
	if (dd != 1) {
		assert_int_equal(daemon_initialized, 1);
		ccow_daemon_term();
	}
}

int
main(int argc, char **argv)
{
	/*
	 * Parse command line
	 */
	int opt = 0;

	while ((opt = getopt(argc, argv, "ns")) != -1) {
		switch(opt) {
			case 'n':
				dd = 1;
				daemon_initialized = 1;
				break;
			default:
				break;
		}
	}

	lg = Logger_create("reptrans");
	if (argc > 1 && strcmp(argv[1], "-s") == 0) {
		dd = 1;
	}
	char cmd[PATH_MAX];
	snprintf(cmd, sizeof(cmd), "cat %s/etc/ccow/ccowd.json|grep rtrd 2>/dev/null >/dev/null",
			nedge_path());
	if (system(cmd) == 0)
		transport[0] = TRANS_RTRD;
	else {
		snprintf(cmd, sizeof(cmd), "cat %s/etc/ccow/ccowd.json|grep rtkvs 2>/dev/null >/dev/null",
				nedge_path());
		if (system(cmd) == 0)
			transport[0] = TRANS_RTKVS;
	}
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(ccow_payload_lookup),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
	return 0;
}


