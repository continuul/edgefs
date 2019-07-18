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
#include "cmocka.h"
#include "common.h"
#include "ccow-impl.h"
#include "ccowd-impl.h"
#include "ccow.h"
#include "ccowd.h"
#include "flexhash.h"
#include "reptrans.h"
#include "erasure-coding.h"
#include "reptrans-data.h"

/*
 * CAUTION: non-production internal unit test for EC debugging only
 */

#define TEST_BUCKET_NAME        "reptrans-bucket-test"
#define MAX_DEV 256
#define MAX_CHUNK_SIZE 256*1024
ccow_t cl;
struct bg_sched;
struct repdev *devices[MAX_DEV];
struct enum_dev_arg {
    int n_dev;
    struct repdev **dev;
};

static int n_dev = 0;
static int dd = 0, n_iter = 100;
static unsigned int seed = 0;
extern struct ccowd *ccow_daemon;

/* Forward declaration of some external functions */
int
bg_sched_is_terminated(struct bg_sched* sched);

void
bg_sched_terminate(struct bg_sched* sched);

/* Several internal functions */
static void
libreptrans_disable_bg() {
    for(int i = 0; i < n_dev; i++) {
        struct repdev* dev = devices[i];
        bg_sched_terminate(dev->bg_sched);
    }

    for(int i = 0; i < n_dev; i++) {
        struct repdev* dev = devices[i];
        while (!bg_sched_is_terminated(dev->bg_sched)) {
            usleep(10000);
        }
    }
}

static void
randomize_buffer(uv_buf_t* buf) {
    srand(uv_hrtime());
    for (size_t i = 0; i < buf->len/sizeof(int); i++) {
        int* val = (int*)buf->base;
        *(val + i) = rand();
    }
}

static struct repdev*
get_device(uint128_t* vdevid, size_t l_devs) {
    struct repdev* ret = NULL;
    for (size_t k = 0; k < l_devs; k++) {
        for (int n = 0; n < n_dev; n++) {
            if (!uint128_cmp(&devices[n]->vdevid, vdevid+k)) {
                ret = devices[n];
                goto _exit;
            }
        }
    }
_exit:
    return ret;
}

/* Tests */
static void
libccowd_setup(void **state)
{
    if (!dd) {
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
    assert_true(read(fd, buf, 16384) != -1);
    assert_int_equal(close(fd), 0);
    assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
    je_free(buf);
}

static void
libccow_teardown(void **state)
{
    assert_non_null(cl);
    usleep(100000L);
    ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
    usleep(100000L);
    if (!dd) {
        ccow_daemon_term();
    }
}

static void
bucket_create(void **state)
{
    assert_non_null(cl);
    int err = ccow_bucket_create(cl, TEST_BUCKET_NAME,
        strlen(TEST_BUCKET_NAME) + 1, NULL);
    if (err != -EEXIST)
        assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
    assert_non_null(cl);
    int err = ccow_bucket_delete(cl, TEST_BUCKET_NAME,
        strlen(TEST_BUCKET_NAME) + 1);
    assert_int_equal(err, 0);
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
libreptrans_setup(void **state)
{
    struct enum_dev_arg enum_arg = {0, devices};
    assert_int_equal(reptrans_enum(NULL, &enum_arg,
            enum_dev__done_cb, 0), 0);
    n_dev = enum_arg.n_dev;
    libreptrans_disable_bg();
}

/*
 * Simple unnamed put test:
 * - create a random chunk
 * - invoke unnamed put
 * - find stored chunks
 */
static void
simple_unnamed_put_chunk_test(void **state) {
    ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
    assert_non_null(cl);
    for (int cnt = 0; cnt < n_iter; cnt++) {
            /* prepare a chunk */
        uv_buf_t ub;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;

        ub.base = je_calloc(1, ub.len);
        randomize_buffer(&ub);
        struct chunk_info info = {
                .chid = uint512_null,
                .ttype = TT_CHUNK_PAYLOAD,
                .hash_type = HASH_TYPE_XXHASH_64
        };
        /* First put it using usual unnamed put , storing compressed CHID */
        int err = ec_unnamed_put_chunk(cl, &ub, 3, RD_ATTR_CHUNK_PAYLOAD,
            info.hash_type, NULL, NULL, &info.chid);
        assert_int_equal(err, 0);
        /* Try to find our chunk copies */
        err =  ec_locate_chunk(devices[0], &info, NULL, 1);
        assert_int_equal(err, 0);
        assert_true (info.n_vdevs > 1);
        assert_int_equal(info.n_vbrs_max, 0);
        assert_int_equal(info.n_vbrs_min, 0);
        if (!dd) {
            struct repdev* dev = get_device(info.vdevs, info.n_vdevs);
            if (dev) {
                rtbuf_t* rb_load = NULL;
                err = reptrans_get_blob(dev, info.ttype, info.hash_type,
                    &info.chid, &rb_load);
                assert_int_equal(err, 0);
                assert_non_null(rb_load);
                assert_int_equal(rb_load->nbufs, 1);
                rtbuf_destroy(rb_load);
            }
        }
        if (info.vdevs)
            je_free(info.vdevs);
        if (ub.base)
            je_free(ub.base);
    }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

/*
 * Unnamed put without compression
 * -create random chunk, calculate its hashID
 * -invoke unnamed put with RD_ATTR_NCOMP set
 * -find stored chunks using locate request
 * -ensure chunk copies on the disk are equal to the original one
 */
static void
ncomp_unnamed_put_chunk_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    for (int cnt = 0; cnt < n_iter; cnt++) {
        /* prepare a chunk */
        uv_buf_t ub;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;

        ub.base = je_calloc(1, ub.len);
        randomize_buffer(&ub);
        struct chunk_info info = {
                .chid = uint512_null,
                .ttype = TT_CHUNK_PAYLOAD,
                .hash_type = HASH_TYPE_XXHASH_64
        };
        /* Calculate chunk CHID */
        rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
        assert_non_null(rb);
        int err = rtbuf_hash(rb, info.hash_type, &info.chid);
        assert_int_equal(err, 0);
        /* Putting the chunk without compression */
        uint32_t attr = RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_NCOMP;
        err = ec_unnamed_put_chunk(cl, &ub, 3, attr, info.hash_type,
            &info.chid, NULL, NULL);
        /* Locating  chunk copies */
        err =  ec_locate_chunk(devices[0], &info, NULL, 1);
		assert_int_equal(err, 0);
        assert_true (info.n_vdevs > 1);
        assert_int_equal(info.n_vbrs_max, 0);
        assert_int_equal(info.n_vbrs_min, 0);
        if (!dd) {
            struct repdev* dev = get_device(info.vdevs, info.n_vdevs);
            if (dev) {
                rtbuf_t* rb_load = NULL;
                err = reptrans_get_blob(dev, info.ttype, info.hash_type,
                    &info.chid, &rb_load);
                assert_int_equal(err, 0);
                assert_non_null(rb_load);
                assert_int_equal(rb_load->nbufs, 1);
                assert_int_equal(0, memcmp(rtbuf(rb_load,0).base,
                    ub.base, ub.len));
                rtbuf_destroy(rb_load);
            }
        }
        if (rb)
            rtbuf_destroy(rb);
        if (info.vdevs)
            je_free(info.vdevs);
        if (ub.base)
            je_free(ub.base);
        }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

/**
 * Compound unnamed put test:
 * -create a random chunk
 * -create 2 VBRs
 * -create a compound
 * -put the compound using unnamed put with RD_ATTR_COMPOUND
 * -ensure the compound was unpacked and required chunk and VBRs are stored
 */
static void
compound_unnamed_put_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    for (int cnt = 0; cnt < n_iter; cnt++) {
        /* prepare a chunk */
        uv_buf_t ub;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;

        ub.base = je_calloc(1, ub.len);
        randomize_buffer(&ub);
        struct chunk_info info = {
                .chid = uint512_null,
                .ttype = TT_CHUNK_PAYLOAD,
                .hash_type = HASH_TYPE_BLAKE2B_256
        };
        /* Calculate chunk CHID */
        rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
        assert_non_null(rb);
        int err = rtbuf_hash(rb, info.hash_type, &info.chid);
        rtbuf_destroy(rb);
        assert_int_equal(err, 0);
        /* Preparing VBRs */
        struct iovec iov[3];
        uv_buf_t buf, ub_vbr1, ub_vbr2, chid_buf;

        struct backref vbr1 = {
                .generation = 1,
                .uvid_timestamp = 0,
                .name_hash_id = uint512_null,
                .ref_type = TT_CHUNK_MANIFEST,
                .rep_count = 3,
                .ref_hash = HASH_TYPE_DEFAULT,
                .attr = VBR_ATTR_CP
        };
        chid_buf.base = (char*)&vbr1.ref_chid;
        chid_buf.len = sizeof(uint512_t);
        randomize_buffer(&chid_buf);

        msgpack_p *p = NULL, *pvbr = msgpack_pack_init();
        reptrans_pack_vbr(pvbr, &vbr1);
        msgpack_get_buffer(pvbr, &ub_vbr1);

        struct backref vbr2 = {
                .generation = 1,
                .uvid_timestamp = 0,
                .name_hash_id = uint512_null,
                .ref_type = TT_CHUNK_MANIFEST,
                .rep_count = 3,
                .ref_hash = HASH_TYPE_DEFAULT,
                .attr = VBR_ATTR_CP
        };
        chid_buf.base = (char*)&vbr2.ref_chid;
        chid_buf.len = sizeof(uint512_t);
        randomize_buffer(&chid_buf);

        msgpack_p *pvbr2 = msgpack_pack_init();
        reptrans_pack_vbr(pvbr2, &vbr2);
        msgpack_get_buffer(pvbr2, &ub_vbr2);

        /* Packing a compound */
        iov[0].iov_base = ub.base;
        iov[0].iov_len = ub.len;
        iov[1].iov_base = ub_vbr1.base;
        iov[1].iov_len = ub_vbr1.len;
        iov[2].iov_base = ub_vbr2.base;
        iov[2].iov_len = ub_vbr2.len;
        type_tag_t tts[3] = {TT_CHUNK_PAYLOAD, TT_VERIFIED_BACKREF,
        	TT_VERIFIED_BACKREF };
        err = reptrans_pack_compound(iov, 3, tts, &info.chid, &p,
        	info.hash_type, COMPOUND_FLAG_PRIMARY_PUT);
        assert_int_equal(err, 0);
        msgpack_get_buffer(p, &buf);
        /* Sending compound using unnamed put */
        uint32_t attr = RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_COMPOUND;
        err = ec_unnamed_put_chunk(cl, &buf, 2, attr, info.hash_type,
            &info.chid, &info.chid, NULL);
        msgpack_pack_free(pvbr);
        msgpack_pack_free(pvbr2);
        msgpack_pack_free(p);
        assert_int_equal(err, 0);
        usleep(20000);
        /* Locating  chunk copies */
        err =  ec_locate_chunk(devices[0], &info, NULL, 1);
        assert_int_equal(err, 0);
        assert_true (info.n_vdevs > 1);
        assert_int_equal(info.n_vbrs_max, 2);
        assert_int_equal(info.n_vbrs_min, 2);
        if (!dd) {
            /* when run on single node cluster - try to load
             * the chunk from a disk */
            struct repdev* dev = get_device(info.vdevs, info.n_vdevs);
            if (dev) {
                rtbuf_t* rb_load = NULL;
                err = reptrans_get_blob(dev, info.ttype, info.hash_type,
                    &info.chid, &rb_load);
                assert_int_equal(err, 0);
                assert_non_null(rb_load);
                assert_int_equal(rb_load->nbufs, 1);
                assert_int_equal(0, memcmp(rtbuf(rb_load,0).base,
                    ub.base, ub.len));
                rtbuf_destroy(rb_load);
            }
        }
        je_free(ub.base);
        je_free(info.vdevs);
    }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

/*
 * Put a chunk to a specified VDEV
 * -create random chunk
 * -put it using unnamed put with RD_ATTR_TARGETED set
 * -ensure a chunk copy is on the expected VDEV
 */
static void
targeted_unnamed_put_chunk_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    for (int cnt = 0; cnt < n_iter; cnt++) {
            /* prepare a chunk */
        struct repdev* dev = devices[cnt % n_dev];
        uv_buf_t ub;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;

        ub.base = je_calloc(1, ub.len);
        randomize_buffer(&ub);
        struct chunk_info info = {
                .chid = uint512_null,
                .ttype = TT_CHUNK_PAYLOAD,
                .hash_type = HASH_TYPE_XXHASH_64
        };
        /* put it to a defined vdev , storing compressed CHID */
        int err = ec_unnamed_put_chunk(cl, &ub, 1,
            RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_TARGETED, info.hash_type, NULL,
            &dev->vdevid, &info.chid);
        assert_int_equal(err, 0);
        /* try to load a chunk from local storage */
        rtbuf_t* rb_load = NULL;
        err = reptrans_get_blob(dev, info.ttype, info.hash_type,
            &info.chid, &rb_load);
        assert_int_equal(err, 0);
        assert_non_null(rb_load);
        assert_int_equal(rb_load->nbufs, 1);
        rtbuf_destroy(rb_load);
        if (info.vdevs)
            je_free(info.vdevs);
        if (ub.base)
            je_free(ub.base);
    }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

/*
 * Targeted uncompressed unnamed put test
 * - create a random chunk and calculate it's CHID
 * - put chunk with RD_ATTR_NCOMP and RD_ATTR_TARGETED attributes set
 * - ensure a chunk copy is on expected VDEV and its content match original one
 */
static void
targeted_ncomp_unnamed_put_chunk_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    struct chunk_info info = {
            .chid = uint512_null,
            .ttype = TT_CHUNK_PAYLOAD,
            .hash_type = HASH_TYPE_DEFAULT
    };

    for (int cnt = 0; cnt < n_iter; cnt++) {
        struct repdev* dev = devices[cnt % n_dev];
        /* prepare a chunk */
        uv_buf_t ub;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;

        ub.base = je_calloc(1, ub.len);
        randomize_buffer(&ub);
        if (info.ttype != TT_PARITY_MANIFEST) {
            /* Calculate chunk CHID */
            rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
            assert_non_null(rb);
            int err = rtbuf_hash(rb, info.hash_type, &info.chid);
            rtbuf_destroy(rb);
        } else {
            /* Randomize CHID, parity manifest has a synthetic key*/
            uv_buf_t ub_chid = {
                .base = (char*)&info.chid,
                .len = sizeof(uint512_t) };
            randomize_buffer(&ub_chid);
        }
        /* Putting the chunk without compression to a specified VDEV*/
        uint32_t attr = RD_ATTR_NCOMP | RD_ATTR_TARGETED;
        attr |= type_tag_to_attr(info.ttype);
        int err = ec_unnamed_put_chunk(cl, &ub, 1, attr, info.hash_type,
            &info.chid, &dev->vdevid, NULL);
        assert_int_equal(err, 0);
        usleep(10000);
        /* Try to load the chunk from a disk */
        rtbuf_t* rb_load = NULL;
        err = reptrans_get_blob(dev, info.ttype, info.hash_type,
            &info.chid, &rb_load);
        assert_int_equal(err, 0);
        assert_non_null(rb_load);
        assert_int_equal(rb_load->nbufs, 1);
        assert_int_equal(0, memcmp(rtbuf(rb_load,0).base, ub.base, ub.len));
        rtbuf_destroy(rb_load);
        if (info.vdevs)
            je_free(info.vdevs);
        if (ub.base)
            je_free(ub.base);
        if (info.ttype == TT_CHUNK_PAYLOAD)
            info.ttype = TT_PARITY_MANIFEST;
        else if (info.ttype == TT_PARITY_MANIFEST)
            info.ttype = TT_CHUNK_PAYLOAD;
    }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}
/*
 * Targeted compound unnamed put test
 * -create a random chunk
 * -create 2 VBRs
 * -create a compound
 * -put the compound using unnamed put with RD_ATTR_COMPOUND and RD_ATTR_NCOMP
 * -ensure the compound was unpacked and required chunk and VBRs are stored
 */
static void
targeted_compound_unnamed_put_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    for (int cnt = 0; cnt < n_iter; cnt++) {
        struct repdev* dev = devices[cnt % n_dev];
        /* prepare a chunk */
        uv_buf_t ub;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;

        ub.base = je_calloc(1, ub.len);
        randomize_buffer(&ub);
        struct chunk_info info = {
                .chid = uint512_null,
                .ttype = TT_CHUNK_PAYLOAD,
                .hash_type = HASH_TYPE_BLAKE2B_256
        };
        /* Calculate chunk CHID */
        rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
        assert_non_null(rb);
        int err = rtbuf_hash(rb, info.hash_type, &info.chid);
        rtbuf_destroy(rb);
        assert_int_equal(err, 0);
        /* Preparing VBRs */
        struct iovec iov[3];
        uv_buf_t buf, ub_vbr1, ub_vbr2, chid_buf;

        struct backref vbr1 = {
                .generation = 1,
                .uvid_timestamp = 0,
                .name_hash_id = uint512_null,
                .ref_type = TT_CHUNK_MANIFEST,
                .rep_count = 3,
                .ref_hash = HASH_TYPE_DEFAULT,
                .attr = VBR_ATTR_CP
        };
        chid_buf.base = (char*)&vbr1.ref_chid;
        chid_buf.len = sizeof(uint512_t);
        randomize_buffer(&chid_buf);

        msgpack_p *p = NULL, *pvbr = msgpack_pack_init();
        reptrans_pack_vbr(pvbr, &vbr1);
        msgpack_get_buffer(pvbr, &ub_vbr1);

        struct backref vbr2 = {
                .generation = 1,
                .uvid_timestamp = 0,
                .name_hash_id = uint512_null,
                .ref_type = TT_CHUNK_MANIFEST,
                .rep_count = 3,
                .ref_hash = HASH_TYPE_DEFAULT,
                .attr = VBR_ATTR_CP
        };
        chid_buf.base = (char*)&vbr2.ref_chid;
        chid_buf.len = sizeof(uint512_t);
        randomize_buffer(&chid_buf);

        msgpack_p *pvbr2 = msgpack_pack_init();
        reptrans_pack_vbr(pvbr2, &vbr2);
        msgpack_get_buffer(pvbr2, &ub_vbr2);

        /* Packing a compound */
        iov[0].iov_base = ub.base;
        iov[0].iov_len = ub.len;
        iov[1].iov_base = ub_vbr1.base;
        iov[1].iov_len = ub_vbr1.len;
        iov[2].iov_base = ub_vbr2.base;
        iov[2].iov_len = ub_vbr2.len;
        type_tag_t tts[3] = {TT_CHUNK_PAYLOAD, TT_VERIFIED_BACKREF,
        	TT_VERIFIED_BACKREF };
        err = reptrans_pack_compound(iov, 3, tts, &info.chid, &p,
        	info.hash_type, COMPOUND_FLAG_PRIMARY_PUT);
        assert_int_equal(err, 0);
        msgpack_get_buffer(p, &buf);
        /* Sending compound using unnamed put */
        uint32_t attr =
                RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_COMPOUND | RD_ATTR_TARGETED;
        err = ec_unnamed_put_chunk(cl, &buf, 1, attr, info.hash_type,
            &info.chid, &dev->vdevid, NULL);
        msgpack_pack_free(pvbr);
        msgpack_pack_free(pvbr2);
        msgpack_pack_free(p);
        assert_int_equal(err, 0);
        usleep(20000);
        /* try to load the chunk from local store */
        rtbuf_t* rb_load = NULL;
        err = reptrans_get_blob(dev, info.ttype, info.hash_type,
            &info.chid, &rb_load);
        assert_int_equal(err, 0);
        assert_non_null(rb_load);
        assert_int_equal(rb_load->nbufs, 1);
        assert_int_equal(0, memcmp(rtbuf(rb_load,0).base, ub.base, ub.len));
        rtbuf_destroy(rb_load);
        je_free(ub.base);
    }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

/*
 * unname put/get test.
 * - Create a random chunk
 * - put is using unnamed put
 * - get it using unnamed get
 * - ensure the original chunk and its copy are identical
 */
static void
simple_unnamed_put_get_chunk_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    struct chunk_info info = {
            .chid = uint512_null,
            .ttype = TT_CHUNK_PAYLOAD,
            .hash_type = HASH_TYPE_XXHASH_64
    };
    for (int cnt = 0; cnt < n_iter; cnt++) {
            /* prepare a chunk */
        uv_buf_t ub, ub_read;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;
        ub_read.len = ub.len;
        ub.base = je_calloc(1, ub.len);
        ub_read.base = je_calloc(1, ub_read.len);
        randomize_buffer(&ub);
        /* First put it using usual unnamed put , storing compressed CHID */
        int err = ec_unnamed_put_chunk(cl, &ub, 3, RD_ATTR_CHUNK_PAYLOAD,
            info.hash_type, NULL, NULL, &info.chid);
        assert_int_equal(err, 0);
        /* Try to find our chunk copies */
        err =  ec_locate_chunk(devices[0], &info, NULL, 1);
        assert_int_equal(err, 0);
        assert_true (info.n_vdevs > 1);
        assert_int_equal(info.n_vbrs_max, 0);
        assert_int_equal(info.n_vbrs_min, 0);
        /* Doing a simple unnamed get */
        uint32_t attr = type_tag_to_attr(info.ttype);
        err = ec_unnamed_get_chunk(cl, &info.chid, &info.chid, engcNHID, attr,
            info.hash_type, cl->compress_type, &ub_read );
        assert_int_equal(err, 0);
        assert_int_equal(memcmp(ub_read.base, ub.base, ub.len), 0);
        je_free(ub.base);
        je_free(ub_read.base);
        je_free(info.vdevs);
    }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

/*
 * unnamd put/get test without compression
 * - Create a random chunk, calculate its CHID
 * - put is using unnamed put
 * - get it using unnamed get
 * - ensure the original chunk, its copy and the one on the disk are identical
 */
static void
ncomp_unnamed_put_get_chunk_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    struct chunk_info info = {
            .chid = uint512_null,
            .ttype = TT_CHUNK_PAYLOAD,
            .hash_type = HASH_TYPE_XXHASH_64
    };
    for (int cnt = 0; cnt < n_iter; cnt++) {
            /* prepare a chunk */
        uv_buf_t ub, ub_read;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;
        ub_read.len = ub.len;
        ub.base = je_calloc(1, ub.len);
        ub_read.base = je_calloc(1, ub_read.len);
        randomize_buffer(&ub);
        if (info.ttype != TT_PARITY_MANIFEST) {
            /* Calculate chunk CHID */
            rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
            assert_non_null(rb);
            int err = rtbuf_hash(rb, info.hash_type, &info.chid);
            rtbuf_destroy(rb);
        } else {
            /* Randomize CHID, parity manifest has a synthetic key*/
            uv_buf_t ub_chid = {
                .base = (char*)&info.chid,
                .len = sizeof(uint512_t) };
            randomize_buffer(&ub_chid);
        }
        /* First put it using usual unnamed put , storing compressed CHID */
        uint32_t attr = type_tag_to_attr(info.ttype) | RD_ATTR_NCOMP;
        int err = ec_unnamed_put_chunk(cl, &ub, 3, attr, info.hash_type,
            &info.chid, &info.chid, NULL);
        assert_int_equal(err, 0);
        /* Try to find our chunk copies */
        err =  ec_locate_chunk(devices[0], &info, NULL, 1);
        assert_int_equal(err, 0);
        assert_true (info.n_vdevs > 1);
        assert_int_equal(info.n_vbrs_max, 0);
        assert_int_equal(info.n_vbrs_min, 0);
        /* Doing a simple unnamed get */
        err = ec_unnamed_get_chunk(cl, &info.chid, &info.chid, engcNHID, attr,
            info.hash_type, cl->compress_type, &ub_read );
        assert_int_equal(err, 0);
        assert_int_equal(memcmp(ub_read.base, ub.base, ub.len), 0);
        je_free(ub.base);
        je_free(ub_read.base);
        je_free(info.vdevs);
        if (info.ttype == TT_CHUNK_PAYLOAD)
            info.ttype = TT_PARITY_MANIFEST;
        else if (info.ttype == TT_PARITY_MANIFEST)
            info.ttype = TT_CHUNK_PAYLOAD;
    }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

/*
 * Targeted unnmaed put/get test
 * - create random chunk
 * - put the chunk on a specified VDEV
 * - get the chunk from VDEV specified
 */
static void
targeted_unnamed_put_get_chunk_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    struct chunk_info info = {
            .chid = uint512_null,
            .ttype = TT_CHUNK_PAYLOAD,
            .hash_type = HASH_TYPE_XXHASH_64
    };

    for (int cnt = 0; cnt < n_iter; cnt++) {
            /* prepare a chunk */
        struct repdev* dev = devices[cnt % n_dev];
        uv_buf_t ub, ub_read;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;
        ub_read.len = ub.len;
        ub_read.base = je_calloc(1, ub.len);
        ub.base = je_calloc(1, ub.len);
        randomize_buffer(&ub);
        /* put it to a defined vdev , storing compressed CHID */
        int err = ec_unnamed_put_chunk(cl, &ub, 1,
            RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_TARGETED, info.hash_type, NULL,
            &dev->vdevid, &info.chid);
        assert_int_equal(err, 0);
        /* Detect a chunk locally */
        rtbuf_t* rb_load = NULL;
        err = reptrans_get_blob(dev, info.ttype, info.hash_type,
            &info.chid, &rb_load);
        assert_int_equal(err, 0);
        assert_non_null(rb_load);
        assert_int_equal(rb_load->nbufs, 1);
        rtbuf_destroy(rb_load);
        /* Doing a simple unnamed get */
        err = ec_unnamed_get_chunk(cl, &info.chid, &dev->vdevid, engcVDEV,
            RD_ATTR_CHUNK_PAYLOAD | RD_ATTR_TARGETED, info.hash_type,
            cl->compress_type, &ub_read);
        assert_int_equal(err, 0);
        assert_int_equal(memcmp(ub_read.base, ub.base, ub.len), 0);
        je_free(info.vdevs);
        je_free(ub.base);
        je_free(ub_read.base);
    }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

/*
 * Targeted unnmaed put/get test without compression
 * - create random chunk, calculate its CHID
 * - put the chunk on a specified VDEV
 * - get the chunk from VDEV specified
 * - ensure that original, gotten and a chunk on the disk are equal
 */
static void
targeted_ncomp_unnamed_put_get_chunk_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    struct chunk_info info = {
            .chid = uint512_null,
            .ttype = TT_CHUNK_PAYLOAD,
            .hash_type = HASH_TYPE_XXHASH_64
    };

    for (int cnt = 0; cnt < n_iter; cnt++) {
            /* prepare a chunk */
        struct repdev* dev = devices[cnt % n_dev];
        uv_buf_t ub, ub_read;
        ub.len = rand() >> 12;
        if (ub.len < 128)
            ub.len = 128;
        if (ub.len > MAX_CHUNK_SIZE)
            ub.len = MAX_CHUNK_SIZE;
        ub_read.len = ub.len;
        ub_read.base = je_calloc(1, ub.len);
        ub.base = je_calloc(1, ub.len);
        randomize_buffer(&ub);
        if (info.ttype != TT_PARITY_MANIFEST) {
            /* Calculate chunk CHID */
            rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
            assert_non_null(rb);
            int err = rtbuf_hash(rb, info.hash_type, &info.chid);
            rtbuf_destroy(rb);
        } else {
            /* Randomize CHID, parity manifest has a synthetic key*/
            uv_buf_t ub_chid = {
                .base = (char*)&info.chid,
                .len = sizeof(uint512_t) };
            randomize_buffer(&ub_chid);
        }
        uint32_t attr = RD_ATTR_TARGETED | RD_ATTR_NCOMP;
        attr |= type_tag_to_attr(info.ttype);
        /* put it to a defined vdev , storing compressed CHID */
        int err = ec_unnamed_put_chunk(cl, &ub, 1, attr, info.hash_type,
            &info.chid, &dev->vdevid, NULL);
        assert_int_equal(err, 0);
        /* Detect a chunk locally */
        rtbuf_t* rb_load = NULL;
        err = reptrans_get_blob(dev, info.ttype, info.hash_type,
            &info.chid, &rb_load);
        assert_int_equal(err, 0);
        assert_non_null(rb_load);
        assert_int_equal(rb_load->nbufs, 1);
        assert_int_equal(rb_load->bufs->len, ub.len);
        assert_int_equal(memcmp(rb_load->bufs->base, ub.base, ub.len), 0);
        rtbuf_destroy(rb_load);
        /* Doing a simple unnamed get */
        err = ec_unnamed_get_chunk(cl, &info.chid, &dev->vdevid, engcVDEV, attr,
            info.hash_type, cl->compress_type, &ub_read);
        assert_int_equal(err, 0);
        assert_int_equal(memcmp(ub_read.base, ub.base, ub.len), 0);
        je_free(info.vdevs);
        je_free(ub.base);
        je_free(ub_read.base);
        if (info.ttype == TT_CHUNK_PAYLOAD)
            info.ttype = TT_PARITY_MANIFEST;
        else if (info.ttype == TT_PARITY_MANIFEST)
            info.ttype = TT_CHUNK_PAYLOAD;
    }
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

#define SIMPLE_TEST_BS 16*1024
/*
 * Put an object with low btree order
 */
static void
object_put_test(void **state) {
	ccow_t cl = reptrans_get_tenant_context(devices[0]->rt, 0);
	assert_non_null(cl);
    int err = 0;
    size_t iovcnt = 64;
    struct iovec *iov = je_calloc(iovcnt, sizeof (struct iovec));
    assert_non_null(iov);
    char *buf = je_malloc(iovcnt * SIMPLE_TEST_BS);
    assert_non_null(buf);

    uv_buf_t ub_buf = { .base = buf, .len = iovcnt * SIMPLE_TEST_BS };
    randomize_buffer(&ub_buf);
    size_t i;
    for (i = 0; i < iovcnt; i++) {
        iov[i].iov_base = buf + i * SIMPLE_TEST_BS;
        iov[i].iov_len =  SIMPLE_TEST_BS;
    }

    ccow_completion_t c;
    err = ccow_create_completion(cl, NULL, NULL, 1, &c);
    assert_int_equal(err, 0);

    ccow_lookup_t iter = NULL;
    uint8_t rc = 3;
    err = ccow_attr_modify_default(c, CCOW_ATTR_REPLICATION_COUNT,
        (void *)&rc, iter);
    assert_int_equal(err, 0);
    uint16_t num_vers = 1;
    err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
        (void *)&num_vers, NULL);
    assert_int_equal(err, 0);
    uint16_t btree_order = 32;
    err = ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER,
        (uint16_t *)&btree_order, NULL);
    assert_int_equal(err, 0);

    put_simple(c, TEST_BUCKET_NAME, "ec-locate-test", &iov[0], iovcnt, 0);

    err = ccow_wait(c, -1);
    assert_int_equal(err, 0);

    if (iter)
        ccow_lookup_release(iter);
    je_free(buf);
    je_free(iov);
    reptrans_put_tenant_context(devices[0]->rt, cl);
}

static int
get_ext_refs_blob_iterator(struct repdev *dev, type_tag_t ttag,
    crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {

    int* count = (int*) param;
    char chidbuf[UINT512_BYTES * 2 + 1];
    char vdevbuf[UINT128_BYTES * 2 + 1];
    int err = 0;

    rtbuf_t* cm = rtbuf_init_mapped(val, 1), *refs = NULL;
    if (ttag == TT_VERSION_MANIFEST)
        err = replicast_get_refs(cm, &refs, 0);
    else
        err = replicast_unpack_cm_refs(cm, &refs, 0);

    assert_int_equal(err, 0);
    struct chunk_info* infos = NULL;
    int n_infos = 0;
    err = ec_get_chunk_info(dev, refs, NULL, 0, 1, 0, &infos, &n_infos);
    assert_int_equal(err, 0);

    for (int i = 0; i < n_infos; i++) {
        uint512_dump(&infos[i].chid, chidbuf, UINT512_BYTES * 2 + 1);
        chidbuf[21] = 0;
        printf("%d. CHID %s, VBRs min: %lu, VBRs max: %lu, VDEVS: ", i,
                chidbuf, infos[i].n_vbrs_min, infos[i].n_vbrs_max);
        for (size_t j = 0; j < infos[i].n_vdevs; j++) {
            uint128_dump(infos[i].vdevs+j, vdevbuf, UINT128_BYTES * 2 + 1);
            printf("%s,", vdevbuf);
        }
        printf("\n");
        if (infos[i].vdevs)
            je_free(infos[i].vdevs);
    }
    je_free(infos);
    rtbuf_destroy(cm);
    rtbuf_destroy(refs);
    (*count)++;
    usleep(10000);
    return *count > 10 ? 1 : 0;
}

/*
 * ec_get_ext_refs()
 * For each manifest on the deisk:
 * - unpack the manifest and fetch refteries
 * - retrieve extended chunk info using ngrequest_locate
 */
static void
get_ext_refs_test(void **state) {
    for(int n = 0; n < n_dev; n++) {
        struct repdev* dev = devices[n];
        int count = 0;
        reptrans_iterate_blobs(dev, TT_VERSION_MANIFEST,
            get_ext_refs_blob_iterator, &count, 0);
        count = 0;
        reptrans_iterate_blobs(dev, TT_CHUNK_MANIFEST,
            get_ext_refs_blob_iterator, &count, 0);
    }
}

static void
codec_run() {
	int err;
	ec_codec_id i = EC_CID_RS;
	for (; i< EC_CID_TOTAL; i++) {
		struct ec_codec_info* info = NULL;
		err =  ec_cm_codec_info(i, &info);
		assert_int_equal(err, 0);
		assert_non_null(info);
		printf("Testing codec %s, n_formats %d\n", info->name,
				info->n_formats);
		for (int j = 0; j < info->n_formats; j++) {
			ec_codec_format fmt = info->formats[j];
			int n_data = fmt >> 8;
			int n_parity = fmt & 0xFF;
			printf("\tFormat %d:%d\n", n_data, n_parity);
			for (int x = 0; x < 50; x++) {
				codec_handle_t handle = 0;
				/* Create codec instance */
				err = ec_cm_create_instance(i, fmt, &handle);
				assert_int_equal(err, 0);
				/* Allocate fragments of data */
				struct ec_fragment* frgs =
					je_calloc(n_data+n_parity, sizeof(*frgs));
				assert_non_null(frgs);
				uv_buf_t ub_orig[n_data];
				for (int n = 0; n < n_data+n_parity; n++) {
					frgs[n].index = n;
					if (n >= n_data)
						continue;
					int len = 0;
					len = rand() % 128*1024;
					if (len < 100)
						len = 100;
					ub_orig[n].len = frgs[n].buf.len = len;
					ub_orig[n].base = frgs[n].buf.base =
						je_calloc(1, frgs[n].buf.len);
					randomize_buffer(&frgs[n].buf);
				}
				/* Encode */
				uv_buf_t ctx;
				err = ec_cm_encode(handle, frgs, frgs+n_data, &ctx);
				assert_int_equal(err, 0);
				assert_true(frgs[n_data].buf.len > 0);
				assert_non_null(frgs[n_data].buf.base);
				/**
				 * Will restore fragment to,
				 * force its data pointer to NULL
				 */
				for(int n = 0; n < n_parity; n++) {
					frgs[n].buf.base = NULL;
				}
				err = ec_cm_recover(handle, frgs, &ctx);
				assert_int_equal(err, 0);
				for(int n = 0; n < n_parity; n++) {
					assert_non_null(frgs[n].buf.base);
					assert_int_equal(memcmp(frgs[n].buf.base,
								ub_orig[n].base,
								ub_orig[n].len), 0);
				}
				/* Destroy codec */
				ec_cm_destroy_instance(handle);
				for(int n = 0; n < n_data; n++) {
					je_free(ub_orig[n].base);
				}

				je_free(frgs);
				usleep(10);
			}
		}
	}
}

static void
ec_cm_test(void **state) {
	int i;
	int err = ec_cm_init();
	if (err) {
		log_error(lg, "Error initializing EC codec manager: %d", err);
		return;
	}

	uv_thread_t id[6];
	for(i = 0; i < 6; i++)
		uv_thread_create(&id[i], codec_run, NULL);
	for(i = 0; i < 6; i++)
		uv_thread_join(&id[i]);

}

ccache_t*
ec_ccache_create(size_t cachesz);

static int
manifest_encode_test_iterator(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {
	struct verification_request vreq = {
		.domain = EC_DOMAIN_VDEV,
		.algorithm = EC_CID_XOR,
		.width = 5,
		.n_parity = 1,
		.ttag = ttag,
		.htype = hash_type,
		.chid = *key
	};
	int err = ec_encode_manifest(dev, &vreq, NULL);
	if (err == -1)
		err = 0;
	assert_int_equal(err, 0);
	return 0;
}

static void
manifest_encode_test(void **state) {
	for(int n = 0; n < n_dev; n++) {
	struct repdev* dev = devices[n];
	int count = 0;
	reptrans_iterate_blobs(dev, TT_VERSION_MANIFEST,
			manifest_encode_test_iterator, &count, 0);
	count = 0;
	reptrans_iterate_blobs(dev, TT_CHUNK_MANIFEST,
			manifest_encode_test_iterator, &count, 0);
	}
}

static int
manifest_recover_test_iterator(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {
	/* Check if parity manifest present */
	struct blob_stat pastat = {0};
	int err = reptrans_blob_stat(dev, ttag, hash_type, key, &pastat);
	if (err || pastat.size == 0)
		return 0;
	/* Load manifest and extract refs */
	rtbuf_t* rb = NULL;
	err = reptrans_get_blob(dev, ttag, hash_type, key, &rb);
	if (err)
		return 0;
	rtbuf_t* refs = NULL;
	err = replicast_unpack_cm_refs(rb, &refs, 0);
	if (err || !refs)
		return 0;

	int idx = -1;
	for (size_t i = 0; i < refs->nbufs; ++i) {
		struct refentry *e =
			(struct refentry *)rtbuf(refs, i).base;
		uint8_t ref_ttag = ref_to_ttag[RT_REF_TYPE(e)];
		if (ref_ttag == TT_CHUNK_PAYLOAD) {
			idx = i;
			break;
		}
	}
	if (idx < 0)
		return 0;
	uint32_t missing = idx;
	struct refentry* e = NULL;
	uint512_t nhid = uint512_null;
	err = ec_recover_manifest_from_refs(dev, key, &nhid, ttag, refs, 0,
		NULL, 0, NULL);
	return err;
}

static void
manifest_recover_test(void **state) {
	for(int n = 0; n < n_dev; n++) {
	struct repdev* dev = devices[n];
	int count = 0;
	reptrans_iterate_blobs(dev, TT_CHUNK_MANIFEST,
			manifest_recover_test_iterator, &count, 0);
	}
}

static void
delay_test(void **state) {
	sleep(3600);
}


static int
in_array(int a[], int n, int e) {
	for (int i = 0; i < n; i++)
		if (a[i] == e)
			return 1;
	return 0;
}

static void
init_pset_data(ec_dev_info_t devs[], int n_devs, struct chunk_info chunks[], int n_chunks)
{
	int i, j, k, id;
	for(i = 0; i < n_devs; i++) {
		/* Init Device */
		uint128_set64(&devs[i].vdevid, 0, i);
		uint128_set64(&devs[i].hostid, 0, i % 20);
		devs[i].zoneid = i % 10;
		/* Init Chunk */
		chunks[i].n_vdevs = (i % 3 + 1);
		int a[chunks[i].n_vdevs];
		memset(a, 0, sizeof(a[0]) * chunks[i].n_vdevs);

		for(j = 0; j < (int)chunks[i].n_vdevs; j++) {
			do {
				id = rand() % n_devs;
			} while(in_array(a, j, id));
			uint128_set64(&chunks[i].vdevs[j], 0, id);
			a[j] = id;
		}
	}
}

int check_psets(struct ec_pset *psets, int n_psets) {
	int i, j, k;
	struct ec_pset_entry *e;
	struct ec_parity_chunk *p;
	uint128_t *e1,*e2;

	for(i = 0; i < n_psets; i++) {
		e = psets[i].entries;
		p = psets[i].parity;
		for(j = 1; j < psets[i].n_entries + psets[i].n_parity - 1; j++) {
			if (j < psets[i].n_entries)
				e1 = &e[j].tgt_vdev;
			else
				e1 = &p[j - psets[i].n_entries].vdevid;

			for(k = j + 1; k < psets[i].n_entries + psets[i].n_parity; k++) {
				if (k < psets[i].n_entries)
					e2 = &e[k].tgt_vdev;
				else
					e2 = &p[k - psets[i].n_entries].vdevid;
				if (!uint128_cmp(e1, e2)) return 1;
			}
		}
	}
	return 0;
}

void print_psets(struct ec_pset *psets, int n_psets) {
	struct ec_pset_entry *e;
	for(int i = 0; i < n_psets; i++) {
		printf("#%d e=%d\t", i, psets[i].n_entries);
		for(int j = 0; j < psets[i].n_entries; j++) {
			e = &psets[i].entries[j];
			printf(" %lu", e->tgt_vdev.l);
		}
		printf("\n");
	}
}

static void
build_parity_sets(void **state) {
	int n_devs = 200;
	int n_chunks = n_devs;
	ec_dev_info_t devs[n_devs];
	struct chunk_info chunks[n_chunks];
	struct ec_pset *psets = NULL;
	int n_psets, err, i, debug = 0;

	init_pset_data(devs, n_devs, chunks, n_chunks);

	for(ec_domain_t domain = EC_DOMAIN_VDEV; domain < EC_DOMAIN_LAST; domain++)
		for(int n_parity = 1; n_parity < 3;  n_parity++)
			for(int width = 2; width < 9; width++) {
				err = ec_build_parity_sets(devs, n_devs, chunks,
						n_chunks, width, n_parity,
						domain, 2, &psets,  &n_psets);
				if (!n_psets)
					continue;
				if (err) fail();
				if (debug) print_psets(psets, n_psets);
				if (check_psets(psets, n_psets)) fail();
				printf("Domain:%d Width:%d Parity:%d PASSED\n",
						domain, width, n_parity);

				for(i = 0; i < n_psets; i++) {
					je_free(psets[i].entries);
					je_free(psets[i].parity);
				}
				je_free(psets);

			}

	for(i = 0; i < n_chunks; i++) {
		je_free(chunks[i].vdevs);
	}
}

static void
vbr_delete_test(void **state) {
	uint512_t chid, ref_chid;
	uv_buf_t ub_aux = { .base=(char*)&chid, .len=sizeof(uint512_t) };
	randomize_buffer(&ub_aux);
	ub_aux.base = (char*)&ref_chid;
	randomize_buffer(&ub_aux);
	struct repdev* dev = devices[0];
	char chidstr[UINT512_BYTES*2+1];
	uint512_dump(&chid, chidstr, UINT512_BYTES*2+1);
	chidstr[31] = 0;

	int n_vbrs = 5, err = 0;
	struct backref vbr = {
		.ref_chid = ref_chid,
		.generation = 0,
		.uvid_timestamp = 0,
		.ref_type = TT_CHUNK_MANIFEST,
		.ref_hash = HASH_TYPE_DEFAULT,
		.rep_count = n_vbrs,
		.attr = VBR_ATTR_CP
	};
	printf ("Putting %d VBRs with chid %s\n", n_vbrs, chidstr);
	for (int i = 0; i < n_vbrs; i++) {
		int flags = RD_FLUSH_FORCE;
		dev->rt->dev_ctl(dev, vdevCtlFlush, &flags);
		err = reptrans_put_backref(dev, &chid, HASH_TYPE_DEFAULT, &vbr);
		assert_int_equal(err, 0);
		vbr.rep_count--;
	}
}

int
main(int argc, char *argv[]) {
   int opt, daemon_only = 0;
   srand(time(NULL));
   seed = rand();
   while ((opt = getopt(argc, argv, "dni:")) != -1) {
        switch (opt) {
        case 'i':
            n_iter = strtol(optarg, NULL, 10);
            break;

        case 'n':
            dd = 1;
            break;

        case 'd':
            daemon_only = 1;
            break;

        default:
            break;
        }
    }

   if (daemon_only) {
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(libreptrans_setup),
		unit_test(delay_test),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)};
	return run_tests(tests);
   } else {
    const UnitTest tests[] = {
	unit_test(libccowd_setup),
	unit_test(libccow_setup),
	unit_test(bucket_create),
	unit_test(libreptrans_setup),
	unit_test(vbr_delete_test),
	unit_test(simple_unnamed_put_chunk_test),
	unit_test(ncomp_unnamed_put_chunk_test),
	unit_test(compound_unnamed_put_test),
	unit_test(targeted_unnamed_put_chunk_test),
	unit_test(targeted_ncomp_unnamed_put_chunk_test),
	unit_test(targeted_compound_unnamed_put_test),
	unit_test(simple_unnamed_put_get_chunk_test),
	unit_test(ncomp_unnamed_put_get_chunk_test),
	unit_test(targeted_unnamed_put_get_chunk_test),
	unit_test(targeted_ncomp_unnamed_put_get_chunk_test),
	unit_test(object_put_test),
	unit_test(get_ext_refs_test),
	unit_test(manifest_encode_test),
	unit_test(manifest_recover_test),
	unit_test(ec_cm_test),
	unit_test(bucket_delete),
	unit_test(libccow_teardown),
	unit_test(libccowd_teardown),
	unit_test(build_parity_sets),
	unit_test(ec_cm_test),
    };
    return run_tests(tests);
   }
}
