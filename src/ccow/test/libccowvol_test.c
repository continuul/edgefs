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
#include <sys/sysinfo.h>
#include "ccowutil.h"
#include "cmocka.h"
#include "libccowvol.h"
#include "ccow.h"
#include "ccowd.h"
#include "common.h"

int dd = 0;
ccow_t cl = NULL;
struct ccow_info * ci = NULL;

int BLOCKS_TO_TEST = 1;

#define TEST_BID		"test-bucket"
#define TEST_OID		"object1"
#define TEST_OID2		"object2"
#define BLK_SIZE		4096
#define CHNK_SIZE		(16 * 1024)
#define VOL_SIZE		(1024 * 1024 * 1024L)
#define MAX_PATH_LENGHT 1024

char pattern[] = "abcd123";
char pattern2[] = "321dcba";

#define JOB_PARAMS "%s/thirdparty/fio/fio-2.2.10/examples/ccowvolaio-rw1.fio"
#define FIO_PATH "%s/sbin/fio"
char job_params[1024];

extern char * optarg;
extern int opterr;
/* **************************************************************************** 
 *
 * ***************************************************************************/ 
#define	assert_ptr_equal(_a, _b)					\
	({								\
	int r = (_a == _b);						\
	assert_true(r);							\
	})

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
			"     ./libccowvol_test [-h] [-fpath] [-n ] \n"
			"\n"
			"    -h   Display this help message and exit.\n"
			"\n"
			"    -f   run fio test with specified job file\n"
			"         if the path is unspecified run default test \n"
			"\n"
			"    -b   Specify the number of blocks to use. (Default is 1)\n"
			"\n"
			"    choice one option or no options."
			"\n");

	exit(EXIT_SUCCESS);
}

/* ****************************************************************************
 * libccow & libccowd setup & teardown
 * ***************************************************************************/
static void
libccowd_setup(void **state)
{
	if (dd)
		return;
	assert_int_equal(ccow_daemon_init(NULL), 0);
	usleep(2 * 1000000L);
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
	int err = ccow_bucket_create(cl, TEST_BID, strlen(TEST_BID) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	delete(cl, TEST_BID, TEST_OID, NULL, NULL);
	int err = ccow_bucket_delete(cl, TEST_BID, strlen(TEST_BID) + 1);
	assert_int_equal(err, 0);
}

static void
libccowvol_setup_test(void **state)
{
}

static void
libccowvol_fio_run(void **state)
{
	char full_cmd[MAX_PATH_LENGHT];
	if (!strlen(job_params))
		snprintf(full_cmd, MAX_PATH_LENGHT, FIO_PATH " " JOB_PARAMS, nedge_path(), nedge_path());
	else
		snprintf(full_cmd, MAX_PATH_LENGHT, FIO_PATH " %s",  nedge_path(), job_params);

	int err = system(full_cmd);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);

	ccow_stats_t stats;

	int rv = ccow_get_stats(cl, &stats);
	if (rv == 0) {
		ccow_print_stats(stats);
	}

	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
	if (dd)
		return;
	ccow_daemon_term();
}

static void
libccowvol_teardown_test(void **state)
{
}

/* ****************************************************************************
 * libccowvol_create_test
 * ***************************************************************************/
static void
libccowvol_create_test(void **state)
{
	int err = 0;

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	uint32_t cs = CHNK_SIZE;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *) &cs, NULL);
	assert_int_equal(err, 0);

	uint64_t vs = VOL_SIZE;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64,
	    "X-volsize", strlen("X-volsize") + 1, &vs, 0, NULL);
	assert_int_equal(err, 0);

	uint32_t bs = CHNK_SIZE;
	err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT32,
	    "X-blocksize", strlen("X-blocksize") + 1, &bs, 0, NULL);
	assert_int_equal(err, 0);

	uint16_t nv = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *) &nv, NULL);
	assert_int_equal(err, 0);

	uint8_t ht = 8; // XXHASH_128
	err = ccow_attr_modify_default(c, CCOW_ATTR_HASH_TYPE,
	    (void *) &ht, NULL);
	assert_int_equal(err, 0);

	struct iovec iov[1];
	iov[0].iov_len = CHNK_SIZE;
	iov[0].iov_base = je_malloc(iov[0].iov_len);
	assert_non_null(iov[0].iov_base);

	uint64_t lastsect_off = VOL_SIZE - CHNK_SIZE;
	put_simple(c, TEST_BID, TEST_OID, &iov[0], 1, lastsect_off);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	je_free(iov[0].iov_base);
}
static void
libccowvol_create_test2(void **state)
{
        int err = 0;

        ccow_completion_t c;
        err = ccow_create_completion(cl, NULL, NULL, 1, &c);
        assert_int_equal(err, 0);

        uint32_t cs = CHNK_SIZE;
        err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
            (void *) &cs, NULL);
        assert_int_equal(err, 0);

        uint64_t vs = VOL_SIZE;
        err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT64,
            "X-volsize", strlen("X-volsize") + 1, &vs, 0, NULL);
        assert_int_equal(err, 0);

        uint32_t bs = CHNK_SIZE;
        err = ccow_attr_modify_custom(c, CCOW_KVTYPE_UINT32,
            "X-blocksize", strlen("X-blocksize") + 1, &bs, 0, NULL);
        assert_int_equal(err, 0);

        uint16_t nv = 1;
        err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
            (void *) &nv, NULL);
        assert_int_equal(err, 0);

        uint8_t ht = 8; // XXHASH_128
        err = ccow_attr_modify_default(c, CCOW_ATTR_HASH_TYPE,
            (void *) &ht, NULL);
        assert_int_equal(err, 0);

        struct iovec iov[1];
        iov[0].iov_len = CHNK_SIZE;
        iov[0].iov_base = je_malloc(iov[0].iov_len);
        assert_non_null(iov[0].iov_base);

        uint64_t lastsect_off = VOL_SIZE - CHNK_SIZE;
        put_simple(c, TEST_BID, TEST_OID2, &iov[0], 1, lastsect_off);

        err = ccow_wait(c, -1);
        assert_int_equal(err, 0);

        je_free(iov[0].iov_base);
}
/* ****************************************************************************
 * libccowvol_open
 * ***************************************************************************/
static void
libccowvol_open_test(void **state)
{
	char uri[1024];
	int fd, err;

	ci = je_calloc(1, sizeof(struct ccow_info));
	assert_non_null(ci);

	ci->tctx = cl;
	ci->blk_size = BLK_SIZE;
	ci->chunk_size = CHNK_SIZE;
	ci->size = VOL_SIZE;

	uint64_t sz = VOL_SIZE;

	memset(uri, 0, sizeof(uri));
	sprintf(uri, "%s/%s/%s/%s", "cltest", "test", TEST_BID, TEST_OID);

	err = ccow_vol_open(ci, uri, &fd, &sz);
	if (err != 0) {
		log_error(lg, "libccowvol_ccowbd_open returned err = %d ", err);
		assert_int_equal(err, 0);
	}
}

/* ****************************************************************************
 * libccowvol_write
 * ***************************************************************************/
uv_barrier_t libccowvol_write_bar;

static void *
libccowvol_write_cb(void * args)
{
	uv_barrier_wait(&libccowvol_write_bar);
	return NULL;
}

static void
libccowvol_write_test(void **state)
{
	int err;
	int i, n;
	uint8_t * ptr;

	ccow_aio_t aio = je_calloc(1, sizeof(struct ccow_aio));
	assert_non_null(aio);

	uint8_t * buf = je_calloc(CHNK_SIZE, sizeof(uint8_t));
	assert_non_null(buf);

	n = CHNK_SIZE / sizeof(pattern);
	ptr = buf;
	for (i = 0; i < n; i++) {
		memcpy(ptr, pattern, sizeof(pattern));
		ptr += sizeof(pattern);
	}
	memcpy(ptr, pattern, CHNK_SIZE % sizeof(pattern));

	aio->aio_offset = 0;
	aio->aio_buf = buf;
	aio->aio_nbytes = CHNK_SIZE;
	aio->aio_cbfunction = libccowvol_write_cb;
	aio->aio_cbargs = aio;
	aio->aio_sigevent = CCOW_VOL_SIGEV_THREAD;
	aio->ci = ci;

	uv_barrier_init(&libccowvol_write_bar, 2);

	err = ccow_vol_write(aio);
	assert_int_equal(err, 0);

	uv_barrier_wait(&libccowvol_write_bar);
	uv_barrier_destroy(&libccowvol_write_bar);

	/*  second write test with aio_suspend - return */

	aio->aio_offset = 0;
	aio->aio_buf = buf;
	aio->aio_nbytes = CHNK_SIZE;
	aio->aio_sigevent = CCOW_VOL_SIGEV_NONE;
	aio->ci = ci;

	err = ccow_vol_write(aio);
	assert_int_equal(err, 0);

	err = ccow_vol_error(aio);
	if (err == 0) {
		/* ccow have done the job, but call suspend anyway */
		err = ccow_vol_suspend(&aio, 1, NULL);
		assert_int_equal(err, 0);
		err = ccow_vol_return(aio);
		if (err == CHNK_SIZE)
			err = 0;
		if (err == -EINPROGRESS)
			err = EINPROGRESS;
	}
	while ( err == EINPROGRESS ) {
		err = ccow_vol_suspend(&aio, 1, NULL);
		assert_int_equal(err, 0);
		err = ccow_vol_return(aio);
		if (err == CHNK_SIZE)
			err = 0;
		if (err == -EINPROGRESS)
			err = EINPROGRESS;
	}

	assert_int_equal(err, 0);
	je_free(buf);
	je_free(aio);
}

/* ****************************************************************************
 * libccowvol_read
 * ***************************************************************************/
uv_barrier_t libccowvol_read_bar;

static void *
libccowvol_read_cb(void * args)
{
	uv_barrier_wait(&libccowvol_read_bar);
	return NULL;
}


static void
libccowvol_read_test(void **state)
{
	int err;
	int i, n;
	uint8_t * ptr;

	ccow_aio_t aio = je_calloc(1, sizeof(struct ccow_aio));
	assert_non_null(aio);

	uint8_t * buf = je_calloc(CHNK_SIZE, sizeof(uint8_t));
	assert_non_null(buf);

	aio->aio_offset = 0;
	aio->aio_buf = buf;
	aio->aio_nbytes = CHNK_SIZE;
	aio->aio_cbfunction = libccowvol_read_cb;
	aio->aio_cbargs = aio;
	aio->aio_sigevent = CCOW_VOL_SIGEV_THREAD;
	aio->ci = ci;

	uv_barrier_init(&libccowvol_read_bar, 2);

	err = ccow_vol_read(aio);
	assert_int_equal(err, 0);

	uv_barrier_wait(&libccowvol_read_bar);
	uv_barrier_destroy(&libccowvol_read_bar);

	n = CHNK_SIZE / sizeof(pattern);
	ptr = buf;
	for (i = 0; i < n; i++) {
		err = memcmp(ptr, pattern, sizeof(pattern));
		assert_int_equal(err, 0);
		ptr += sizeof(pattern);
	}
	err = memcmp(ptr, pattern, CHNK_SIZE % sizeof(pattern));
	assert_int_equal(err, 0);

/*  second read test with aio_suspend - return */

	aio->aio_offset = 0;
	aio->aio_buf = buf;
	aio->aio_nbytes = CHNK_SIZE;
	aio->aio_sigevent = CCOW_VOL_SIGEV_NONE;
	aio->ci = ci;

	err = ccow_vol_read(aio);
	assert_int_equal(err, 0);

	err = ccow_vol_error(aio);
	if (err == 0) {
		/* ccow have done the job, but call suspend anyway */
		err = ccow_vol_suspend(&aio, 1, NULL);
		assert_int_equal(err, 0);
		err = ccow_vol_return(aio);
		if (err == CHNK_SIZE)
			err = 0;
		if (err == -EINPROGRESS)
			err = EINPROGRESS;
	}
	while ( err == EINPROGRESS ) {
		err = ccow_vol_suspend(&aio, 1, NULL);
		assert_int_equal(err, 0);
		err = ccow_vol_return(aio);
		if (err == CHNK_SIZE)
			err = 0;
		if (err == -EINPROGRESS)
			err = EINPROGRESS;
	}
	assert_int_equal(err, 0);
	je_free(buf);
	je_free(aio);
}

/* ****************************************************************************
 * libccowvol_unmap
 * ***************************************************************************/

static void
libccowvol_unmap_test(void **state)
{
	int err;
	int i, n;
	uint8_t * ptr;

	ccow_aio_t aio = je_calloc(1, sizeof(struct ccow_aio));
	assert_non_null(aio);

	uint8_t * buf = je_calloc(BLK_SIZE * BLOCKS_TO_TEST, sizeof(uint8_t));
	assert_non_null(buf);

	aio->aio_offset = 0;
	aio->aio_buf = NULL;
	aio->aio_nbytes = BLK_SIZE * BLOCKS_TO_TEST;
	aio->aio_cbfunction = libccowvol_write_cb;
	aio->aio_cbargs = aio;
	aio->aio_sigevent = CCOW_VOL_SIGEV_THREAD;
	aio->ci = ci;
	aio->aio_lio_opcode = CCOW_VOL_LIO_UNMAP;

	uv_barrier_init(&libccowvol_write_bar, 2);

	err = ccow_vol_add_to_queue(aio);
	assert_int_equal(err, 0);

	uv_barrier_wait(&libccowvol_write_bar);
	uv_barrier_destroy(&libccowvol_write_bar);

	/* verify unmap */

	aio->aio_offset = 0;
	aio->aio_buf = buf;
	aio->aio_nbytes = BLK_SIZE * BLOCKS_TO_TEST;
	aio->aio_cbfunction = libccowvol_read_cb;
	aio->aio_cbargs = aio;
	aio->aio_sigevent = CCOW_VOL_SIGEV_THREAD;
	aio->ci = ci;

	uv_barrier_init(&libccowvol_read_bar, 2);

	err = ccow_vol_read(aio);
	assert_int_equal(err, 0);

	uv_barrier_wait(&libccowvol_read_bar);
	uv_barrier_destroy(&libccowvol_read_bar);

	for (i = 0; i < BLK_SIZE * BLOCKS_TO_TEST; i++) {
		if (buf[i] != 0)
			break;
	}
	assert_int_equal(i, BLK_SIZE * BLOCKS_TO_TEST);
}

/* ****************************************************************************
 * libccowvol_write_same
 * ***************************************************************************/

static void
libccowvol_write_same_test(void **state)
{
	int err;
	int i, n;
	uint8_t * ptr;

	ccow_aio_t aio = je_calloc(1, sizeof(struct ccow_aio));
	assert_non_null(aio);

	uint8_t * buf = je_calloc(BLK_SIZE, sizeof(uint8_t));
	assert_non_null(buf);
	uint8_t * verify_buf = je_calloc(BLK_SIZE * BLOCKS_TO_TEST, sizeof(uint8_t));
	assert_non_null(verify_buf);

	n = BLK_SIZE / sizeof(pattern2);
	ptr = buf;
	for (i = 0; i < n; i++) {
		memcpy(ptr, pattern2, sizeof(pattern2));
		ptr += sizeof(pattern2);
	}
	memcpy(ptr, pattern2, BLK_SIZE % sizeof(pattern2));

	aio->aio_offset = 0;
	aio->aio_buf = buf;
	aio->aio_nbytes = BLK_SIZE * BLOCKS_TO_TEST;
	aio->aio_in_size = BLK_SIZE;
	aio->aio_cbfunction = libccowvol_write_cb;
	aio->aio_cbargs = aio;
	aio->aio_sigevent = CCOW_VOL_SIGEV_THREAD;
	aio->ci = ci;
	aio->aio_lio_opcode = CCOW_VOL_LIO_WRITE_SAME;

	uv_barrier_init(&libccowvol_write_bar, 2);

	err = ccow_vol_add_to_queue(aio);
	assert_int_equal(err, 0);

	uv_barrier_wait(&libccowvol_write_bar);
	uv_barrier_destroy(&libccowvol_write_bar);

	/* verify write_same */

	aio->aio_offset = 0;
	aio->aio_buf = verify_buf;
	aio->aio_nbytes = BLK_SIZE * BLOCKS_TO_TEST;
	aio->aio_cbfunction = libccowvol_read_cb;
	aio->aio_cbargs = aio;
	aio->aio_sigevent = CCOW_VOL_SIGEV_THREAD;
	aio->ci = ci;

	uv_barrier_init(&libccowvol_read_bar, 2);

	err = ccow_vol_read(aio);
	assert_int_equal(err, 0);

	uv_barrier_wait(&libccowvol_read_bar);
	uv_barrier_destroy(&libccowvol_read_bar);

	ptr = verify_buf;
	for (i = 0; i < BLOCKS_TO_TEST; i++) {
		if (memcmp(ptr, buf, BLK_SIZE))
			break;
		ptr += BLK_SIZE;
	}
	assert_int_equal(i, BLOCKS_TO_TEST);
}

/* ****************************************************************************
 * libccowvol_fsync
 * ***************************************************************************/

int io_cb_num;
#define IO_NUM (10 * 2) // should be multiple of ops inside while (io < IO_NUM)

static void *
libccowvol_sync_cb(void * args)
{
	uv_barrier_wait(&libccowvol_write_bar);
	return NULL;
}

static void *
libccowvol_io_cb(void * args)
{
	io_cb_num++;
	return NULL;
}

static void
libccowvol_sync_test(void **state)
{
	int err;
	int i, n, io;
	uint8_t * ptr;
	ccow_aio_t aio;

	ccow_aio_t aio_arr = je_calloc(IO_NUM, sizeof(struct ccow_aio));
	assert_non_null(aio_arr);

	ccow_aio_t sync_aio = je_calloc(1, sizeof(struct ccow_aio));
	assert_non_null(sync_aio);

	uint8_t buf[IO_NUM][CHNK_SIZE];
	assert_non_null(buf);

	n = CHNK_SIZE / sizeof(pattern);

	uv_barrier_init(&libccowvol_write_bar, 2);
	io_cb_num = 0;

	/* create sync op aio */

	sync_aio->aio_offset = 0;
	sync_aio->aio_buf = 0;
	sync_aio->aio_nbytes = 0;
	sync_aio->aio_cbfunction = libccowvol_sync_cb;
	sync_aio->aio_cbargs = sync_aio;
	sync_aio->aio_sigevent = CCOW_VOL_SIGEV_THREAD;
	sync_aio->ci = ci;

	/* prepare IO*/

	for (io = 0; io < IO_NUM; io++) {
		aio = &aio_arr[io];
		ptr = buf[io];
		for (i = 0; i < n; i++) {
			memcpy(ptr, pattern, sizeof(pattern));
			ptr += sizeof(pattern);
		}
		memcpy(ptr, pattern, CHNK_SIZE % sizeof(pattern));

		aio->aio_offset = io * CHNK_SIZE;
		aio->aio_buf = buf[io];
		aio->aio_nbytes = CHNK_SIZE;
		aio->aio_cbfunction = libccowvol_io_cb;
		aio->aio_cbargs = aio;
		aio->aio_sigevent = CCOW_VOL_SIGEV_THREAD;
		aio->ci = ci;
	}

	/* start IO */

	io = 0;
	while (io < IO_NUM) {
		err = ccow_vol_write(&aio_arr[io]);
		assert_int_equal(err, 0);
		io++;

		err = ccow_vol_read(&aio_arr[io]);
		assert_int_equal(err, 0);

		io++;
	}

	err = ccow_vol_fsync(sync_aio);
	assert_int_equal(err, 0);

	uv_barrier_wait(&libccowvol_write_bar);

	/* all io should be completed at this moment*/
	assert_int_equal(io_cb_num, IO_NUM);

	uv_barrier_destroy(&libccowvol_write_bar);

	/*  second with blocking sync */

	io_cb_num = 0;

	/* create sync op aio */

	sync_aio->aio_offset = 0;
	sync_aio->aio_buf = 0;
	sync_aio->aio_nbytes = 0;
	sync_aio->aio_cbfunction = NULL;
	sync_aio->aio_cbargs = NULL;
	sync_aio->aio_sigevent = CCOW_VOL_SIGEV_NONE;
	sync_aio->ci = ci;


	/* start IO */

	io = 0;
	while (io < IO_NUM) {
		err = ccow_vol_write(&aio_arr[io]);
		assert_int_equal(err, 0);
		io++;

		err = ccow_vol_read(&aio_arr[io]);
		assert_int_equal(err, 0);

		io++;
	}

	/* do blocking sync */

	err = ccow_vol_synchronize(sync_aio);
	assert_int_equal(err, 0);
	assert_int_equal(io_cb_num, IO_NUM);

	je_free(aio_arr);
	je_free(sync_aio);
}


/* ****************************************************************************
 * test sequences
 * ***************************************************************************/

const UnitTest create_bucket_tests [] = {
	unit_test(libccowd_setup),
	unit_test(libccow_setup),
	unit_test(bucket_create),
	unit_test(libccowvol_setup_test),
	unit_test(libccowvol_create_test),
        unit_test(libccowvol_create_test2),
	unit_test(libccowvol_open_test),
	unit_test(libccowvol_write_test),
	unit_test(libccowvol_read_test),
	unit_test(libccowvol_teardown_test),

	unit_test(libccow_teardown),
	unit_test(libccowd_teardown)
};
const UnitTest unit_tests [] = {
        unit_test(libccowd_setup),
        unit_test(libccow_setup),
        unit_test(bucket_create),
        unit_test(libccowvol_setup_test),
        unit_test(libccowvol_create_test),
        unit_test(libccowvol_open_test),
        unit_test(libccowvol_write_test),
        unit_test(libccowvol_read_test),
        unit_test(libccowvol_write_same_test),
        unit_test(libccowvol_unmap_test),
        unit_test(libccowvol_sync_test),
        unit_test(libccowvol_teardown_test),
        unit_test(bucket_delete),
        unit_test(libccow_teardown),
        unit_test(libccowd_teardown)
};

const UnitTest fio_run [] = {
	unit_test(libccowd_setup),
	unit_test(libccow_setup),
	unit_test(bucket_create),
	unit_test(libccowvol_setup_test),
	unit_test(libccowvol_create_test),
	unit_test(libccowvol_open_test),
	unit_test(libccowvol_fio_run),
	unit_test(libccowvol_teardown_test),
	unit_test(bucket_delete),
	unit_test(libccow_teardown),
	unit_test(libccowd_teardown)
};

/* ****************************************************************************
 * main
 * ***************************************************************************/
int
main(int argc, char ** argv)
{
	int opt;
	/*
	 * parse command line options
	 */
	opterr = 0;
	if ((opt = getopt(argc, argv, "hnb:f::")) != -1) {
		switch(opt) {

		case 'h':
			usage();
			return 0;

		case 'f':
			if (optarg && strlen(optarg)) {
				strncpy(job_params, optarg, MAX_PATH_LENGHT);
			} else
				job_params[0] = 0;
			return run_tests(fio_run);

		case 'n':
			dd = 1;
			break;

		case 'b':
			BLOCKS_TO_TEST = atoi(optarg);
			break;

		default:
			usage();
			return 0;
		}
	}

	return run_tests(unit_tests);
}
