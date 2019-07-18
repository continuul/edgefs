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

#define TEST_BID		"io-error-test-bucket"
#define TEST_OID		"io-error-test-object"

#define BTREE_ORDER_DEF		16

int BTREE_ORDER			=  BTREE_ORDER_DEF;

ccow_t cl = NULL;
int verbose = 0;

/*
 * usage
 *
 * Display usage and exit.
 */
static void
usage(void)
{
	printf("\n"
	       "USAGE:\n"
	       "     ./io_error_test [-h] [-o btree_order] \n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -o   Specify the btree order.\n"
	       "         (Defaults to %d).\n"
	       "\n"
	       "    -v   Enable verbose debug outout.\n"
	       "\n",
	       BTREE_ORDER_DEF);

	exit(EXIT_SUCCESS);
}

/*
 * iet_put
 *
 * IO error test put helper.
 */
void
iet_put(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
	uint64_t off, ccow_callback_t cb_async, void *arg)
{
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
	if (err != 0) {
		printf("ccow_create_completion returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_map";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
				       (void *) chunkmap_type, NULL);
	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	uint16_t order = BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
		(void *)&order, NULL);
	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	err = ccow_put(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov,
	    iovcnt, off);
	if (err != 0) {
		printf("ccow_put returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);
	if (err != 0) {
		printf("ccow_wait returned error status %d \n", err);
	}
	assert_int_equal(err, 0);
}

static void
libccowd_setup(void **state)
{
	assert_int_equal(ccow_daemon_init(NULL), 0);
	usleep(2 * 1000000L);
}

static void
libccow_setup(void **state)
{
	int err;
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

	/*
	 * set default attributes:
	 */
	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);

	if (err != 0) {
		printf("ccow_create_completion returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	char *chunkmap_type = "btree_map";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *) chunkmap_type, NULL);

	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);

	uint16_t order = BTREE_ORDER;
	err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
	    (void *)&order, NULL);

	if (err != 0) {
		printf("ccow_attr_modify_default returned error status %d \n", err);
	}
	assert_int_equal(err, 0);
}

static void
bucket_create(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_create(cl, TEST_BID, strlen(TEST_BID) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BID, strlen(TEST_BID) + 1);
	assert_int_equal(err, 0);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
	ccow_daemon_term();
}

uint32_t SST_BS		= 1024;
int32_t  SST_ITER_CNT	= 1;
int32_t  SST_IOV_CNT    = 1;

/*
 * io_error_test_async_cb
 */
static void
io_error_test_cb(ccow_completion_t c, void *arg, int index,
    int err)
{
	uv_barrier_t *b = arg;

	if (err != 0) {
		printf("IO completed with err = %d \n", err);
	}

	if (index != 0)
		uv_barrier_wait(b);
}

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
#define CCOW_CREATE_COMPLETION(_tc, _arg, _cb_async, _op_num, _c, _err) ({	\
	int rv = ccow_create_completion(_tc, _arg, _cb_async, _op_num, _c);	\
	if (rv != _err) {							\
		printf("ccow_create_completion returned %d, expected %d. \n",	\
			rv, _err);						\
		assert_int_equal(rv, _err);					\
	}									\
	_err;									\
})

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
#define CCOW_ATTR_MODIFY_DEFAULT(_c, _type, _value, _lookup, _err) ({		\
	int rv = ccow_attr_modify_default(_c, _type,				\
		(void *) _value, _lookup);					\
	if (rv != _err) {							\
		printf("ccow_attr_modify_default returned %d, expected %d. \n",	\
			rv, _err);						\
		assert_int_equal(rv, _err);					\
	}									\
	_err;									\
})

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
#define CCOW_PUT(_bid, _oid, _c, _iov, _iovcnt, _off, _err) ({			\
	int rv = ccow_put(_bid, strlen(_bid) + 1, _oid, strlen(_oid) + 1,	\
		_c, _iov, _iovcnt, _off);					\
	if (rv != _err) {							\
		printf("ccow_put returned %d, expected %d. \n",			\
			rv, _err);						\
		assert_int_equal(rv, _err);					\
	}									\
	_err;									\
})

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
#define CCOW_GET(_bid, _oid, _c, _iov, _iovcnt, _off, _iter, _err) ({		\
	int rv = ccow_get(_bid, strlen(_bid) + 1, _oid, strlen(_oid) + 1,       \
		c, _iov, _iovcnt, _off, _iter);					\
	if (rv != _err) {							\
		printf("ccow_get returned %d, expected %d. \n",			\
			rv, _err);						\
		assert_int_equal(rv, _err);					\
	}									\
	_err;									\
})

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
#define CCOW_WAIT(_c, _index, _err) ({						\
	int rv = ccow_wait(_c, _index);						\
	if (rv != _err) {							\
		printf("ccow_wait returned %d, expected %d. \n",		\
			rv, _err);						\
		assert_int_equal(rv, _err);					\
	}									\
	_err;									\
})

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
CCOW_EI_TAG_EXTERN(btm_create_01);

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
#define _16K (16 * 1024)
#define _16M (16 * 1024 * 1024)

static void
io_test_put_no_err(void **state)
{
	struct ccow_completion *c;
	char *chunkmap_type = "btree_map";
	uint16_t btree_order = 128;

	char * buffer = je_calloc(1, _16K);
	static struct iovec iov_out[1];
	iov_out[0].iov_len  = _16K;
	iov_out[0].iov_base = buffer;

	CCOW_CREATE_COMPLETION(cl, NULL, NULL, 1, &c, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_CHUNKMAP_TYPE, chunkmap_type, NULL, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_BTREE_ORDER, &btree_order, NULL, 0);
	CCOW_PUT(TEST_BID, TEST_OID, c, iov_out, 1, 0, 0);
	CCOW_WAIT(c, -1, 0);
}

static void
io_test_put_btm_create_01(void **state)
{
	struct ccow_completion *c;
	char *chunkmap_type = "btree_map";
	uint16_t btree_order = 128;

	char * buffer = je_calloc(1, _16K);
	static struct iovec iov_out[1];
	iov_out[0].iov_len  = _16K;
	iov_out[0].iov_base = buffer;

	CCOW_EI_TAG_INIT(btm_create_01, 1);
	CCOW_CREATE_COMPLETION(cl, NULL, NULL, 1, &c, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_CHUNKMAP_TYPE, chunkmap_type, NULL, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_BTREE_ORDER, &btree_order, NULL, 0);
	CCOW_PUT(TEST_BID, TEST_OID, c, iov_out, 1, 0, 0);
	CCOW_WAIT(c, -1, -ENOMEM);
	CCOW_EI_TAG_DISABLE(btm_create_01);
}

static void
io_test_get_btm_create_01(void **state)
{
	struct ccow_completion *c;
	char *chunkmap_type = "btree_map";
	uint16_t btree_order = 128;

	char * buffer = je_calloc(1, _16K);
	static struct iovec iov_out[1];
	iov_out[0].iov_len  = _16K;
	iov_out[0].iov_base = buffer;

	CCOW_EI_TAG_INIT(btm_create_01, 2);
	CCOW_CREATE_COMPLETION(cl, NULL, NULL, 1, &c, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_CHUNKMAP_TYPE, chunkmap_type, NULL, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_BTREE_ORDER, &btree_order, NULL, 0);
	CCOW_PUT(TEST_BID, TEST_OID, c, iov_out, 1, 0, 0);
	CCOW_WAIT(c, -1, 0);

	CCOW_CREATE_COMPLETION(cl, NULL, NULL, 1, &c, 0);
	CCOW_GET(TEST_BID, TEST_OID, c, iov_out, 1, 0, NULL, 0);
	CCOW_WAIT(c, -1, -ENOMEM);
	CCOW_EI_TAG_DISABLE(btm_create_01);
}

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
CCOW_EI_TAG_EXTERN(btree_create_01);

static void
io_test_put_btree_create_01(void **state)
{
	struct ccow_completion *c;
	char *chunkmap_type = "btree_map";
	uint16_t btree_order = 128;

	char * buffer = je_calloc(1, _16K);
	static struct iovec iov_out[1];
	iov_out[0].iov_len  = _16K;
	iov_out[0].iov_base = buffer;

	CCOW_EI_TAG_INIT(btree_create_01, 1);
	CCOW_CREATE_COMPLETION(cl, NULL, NULL, 1, &c, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_CHUNKMAP_TYPE, chunkmap_type, NULL, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_BTREE_ORDER, &btree_order, NULL, 0);
	CCOW_PUT(TEST_BID, TEST_OID, c, iov_out, 1, 0, 0);
	CCOW_WAIT(c, -1, -ENOMEM);
	CCOW_EI_TAG_DISABLE(btm_create_01);
}

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
CCOW_EI_TAG_EXTERN(allocate_btree_node_01);

static void
io_test_put_allocate_btree_node_01(void **state)
{
	struct ccow_completion *c;
	char *chunkmap_type = "btree_map";
	uint16_t btree_order = 128;

	char * buffer = je_calloc(1, _16K);
	static struct iovec iov_out[1];
	iov_out[0].iov_len  = _16K;
	iov_out[0].iov_base = buffer;

	CCOW_EI_TAG_INIT(allocate_btree_node_01, 1);
	CCOW_CREATE_COMPLETION(cl, NULL, NULL, 1, &c, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_CHUNKMAP_TYPE, chunkmap_type, NULL, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_BTREE_ORDER, &btree_order, NULL, 0);
	CCOW_PUT(TEST_BID, TEST_OID, c, iov_out, 1, 0, 0);
	CCOW_WAIT(c, -1, -ENOMEM);
	CCOW_EI_TAG_DISABLE(btm_create_01);
}

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
CCOW_EI_TAG_EXTERN(btm_update_01);

static void
io_test_put_btm_update_01(void **state)
{
	struct ccow_completion *c;
	char *chunkmap_type = "btree_map";
	uint16_t btree_order = 128;

	char * buffer = je_calloc(1, _16K);
	static struct iovec iov_out[1];
	iov_out[0].iov_len  = _16K;
	iov_out[0].iov_base = buffer;

	CCOW_EI_TAG_INIT(btm_update_01, 1);
	CCOW_CREATE_COMPLETION(cl, NULL, NULL, 1, &c, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_CHUNKMAP_TYPE, chunkmap_type, NULL, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_BTREE_ORDER, &btree_order, NULL, 0);
	CCOW_PUT(TEST_BID, TEST_OID, c, iov_out, 1, 0, 0);
	CCOW_WAIT(c, -1, -ENOMEM);
	CCOW_EI_TAG_DISABLE(btm_create_01);
}

/* ----------------------------------------------------------------------------
 *
 * --------------------------------------------------------------------------*/
CCOW_EI_TAG_EXTERN(btm_update_02);

static void
io_test_put_btm_update_02(void **state)
{
	struct ccow_completion *c;
	char *chunkmap_type = "btree_map";
	uint16_t btree_order = 128;

	char * buffer = je_calloc(1, _16K);
	static struct iovec iov_out[1];
	iov_out[0].iov_len  = _16K;
	iov_out[0].iov_base = buffer;

	CCOW_EI_TAG_INIT(btm_update_02, 1);
	CCOW_CREATE_COMPLETION(cl, NULL, NULL, 1, &c, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_CHUNKMAP_TYPE, chunkmap_type, NULL, 0);
	CCOW_ATTR_MODIFY_DEFAULT(c, CCOW_ATTR_BTREE_ORDER, &btree_order, NULL, 0);
	CCOW_PUT(TEST_BID, TEST_OID, c, iov_out, 1, 0, 0);
	CCOW_WAIT(c, -1, -EIO);
	CCOW_EI_TAG_DISABLE(btm_create_01);
}

static void
error_injection_disabled(void **state)
{
	printf("error injection disabled. \n");
	printf("configure with \"--enable-ccow-error-injection\". \n");
}

/* ----------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int
main(int argc, char ** argv)
{
	/*
	 * parse command line options
	 */
	int opt;

	while ((opt = getopt(argc, argv, "ho:v")) != -1) {
		switch(opt) {

		case 'h':
			usage();
			break;

		case 'o':
			BTREE_ORDER = atoi(optarg);
			break;

		case 'v':
			verbose = 1;
			break;

		default:
			usage();
			break;
		}
	}

	if (verbose) {
		printf("btree order      = %d \n",
		       BTREE_ORDER);
	}

	/*
	 * run tests
	 */
#ifdef CCOW_EI
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),

		unit_test(io_test_put_no_err),
		unit_test(io_test_put_btm_create_01),
		unit_test(io_test_get_btm_create_01),
		unit_test(io_test_put_btree_create_01),
		unit_test(io_test_put_allocate_btree_node_01),
// FIXME:		unit_test(io_test_put_btm_update_01),
// FIXME:		unit_test(io_test_put_btm_update_02),

		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
#else
	const UnitTest tests[] = {
		unit_test(error_injection_disabled)
	};
#endif
	return run_tests(tests);
}
