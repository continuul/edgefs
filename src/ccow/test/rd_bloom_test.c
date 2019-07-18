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
#include "reptrans.h"
#include "rtrd/reptrans-rd.h"
#include "cmocka.h"
#include "logger.h"

Logger lg;
#define MAX_RPDEV 255

struct repdev *rpdev[MAX_RPDEV];
char *transport[1] = {"rtrd"};

struct enum_dev_arg {
    int n_dev;
    struct repdev **dev;
};

static void
enum_cb(struct repdev *dev, void *arg, int status) {

    struct enum_dev_arg *da = (struct enum_dev_arg *) arg;

    if (status == 0)
        da->dev[da->n_dev++] = dev;
}

struct enum_dev_arg devices = {0, rpdev};

static void
rd_init(void **state) {

    if (reptrans_init(0, NULL, NULL, RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1,
            (char **) transport, NULL) <= 0) {
        log_error(lg, "Failed reptrans_init()\n");
        assert_non_null(NULL);

    }

    if (reptrans_enum(NULL, &devices, enum_cb, 0) != 0) {
        log_error(lg, "Failed to enumerate devices\n");
        assert_non_null(NULL);
    }

    /* for testing purposes we need to wait for the bloom filters to be loaded*/

    for (int i = 0; i < devices.n_dev; i++) {
        struct repdev_rd *rd = devices.dev[i]->device_lfs;
        struct repdev_db *db = rd->db;

        while (!db->bloom_loaded)
            sleep(1);

        printf("bloom loaded for %s\n", db->dev->name);

    }
}

static void
fini(void **state) {
	reptrans_destroy();
	reptrans_close_all_rt();
}

static void
bloom_store_test(void **state) {
    assert_int_equal(rd_dev_quiesce_bloom(devices.dev[0]), 0);

}

/*
 * here we test a simple loading of the bloom filter from lmdb
 *
 */

static void
bloom_compare_test(void **state) {
    struct repdev_rd *rd = devices.dev[0]->device_lfs;
    struct repdev_db *db = rd->db;
    struct repdev_db *zero_db = rd->db;

    int err;

    for (int i = 0; i < rd->plevel; i++) {
        db = rd->db + i;
        MDB_txn *txn;
        MDB_val key, data;

        uint8_t *target = je_calloc(1, KEY_BLOOM_BYTELEN);
        char buf[1024] = {0};
        sprintf(buf, "bloom-%s-%d", db->dev->name, db->part);

        key.mv_size = strlen(buf);
        key.mv_data = &buf[0];

        data.mv_size = KEY_BLOOM_BYTELEN;
        data.mv_data = NULL;

        err = mdb_txn_begin(DEV_ENV(db, TT_HASHCOUNT), NULL, MDB_RDONLY,
                &txn);

        err = mdb_get(txn, DEV_SHARD(db, TT_HASHCOUNT, 0), &key, &data);

        if (err) {
            mdb_txn_abort(txn);
            log_error(lg, "Dev(%s): %s mdb_put: (%d) %s", db->dev->name,
                    type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err));
            err = -EIO;
        }

        memcpy(target, data.mv_data, data.mv_size);

        /*
         * Here is where we actually compare. We compare the async loaded
         * values from rtrd, with the ones we just read from the DB
         */

        for (uint32_t i = 0; i < KEY_BLOOM_BYTELEN; i++)
            assert_int_equal (target[i] - db->bloom[i], 0);

        /* for good measure */
        assert_int_equal(memcmp(target, db->bloom, KEY_BLOOM_BYTELEN), 0);
    }

    assert_int_equal(err, 0);

}

part_walk_action_t
wipe_bloom(struct repdev_db *db, void *arg) {

    je_free(db->bloom);
    db->bloom = NULL;
    db->bloom_loaded = -1;
    db->bloom = je_calloc(1, KEY_BLOOM_BYTELEN);

    return PART_WALK_CONTINUE;
}

int mark_valid(struct repdev *dev) {
    uv_buf_t u_key, u_val;
    u_key.base = BLOOM_STORE_OK;
    u_key.len = strlen(u_key.base);
    u_val.len = sizeof(int);

    int val = 0;

    u_val.base = (char *) &val;
    if (rd_config(dev, CFG_WRITE, &u_key, &u_val) != 0)
        return -EINVAL;
    return 0;
}

/*
 * Basically the same as the previous test however now we test the
 * loading from lmdb in rtrd compared to again -- our raw access to
 * the DB
 */

static void
bloom_compare_test_2(void **state) {

    struct repdev_rd *rd = devices.dev[0]->device_lfs;
    struct repdev_db *db = rd->db;
    struct repdev_db *zero_db = rd->db;

    assert_int_equal(mark_valid(devices.dev[0]), 0);

    rd_partition_walk(devices.dev[0], wipe_bloom, NULL);

    /* reload them using our new function */
    rd_dev_load_bloom(devices.dev[0]);

    for (int i = 0; i < rd->plevel; i++) {
        db = rd->db + i;
        MDB_txn *txn;
        MDB_val key, data;

        char *target = je_calloc(1, KEY_BLOOM_BYTELEN);
        char buf[1024] = {0};
        sprintf(buf, "bloom-%s-%d", db->dev->name, db->part);

        key.mv_size = strlen(buf);
        key.mv_data = &buf[0];

        data.mv_size = KEY_BLOOM_BYTELEN;
        data.mv_data = NULL;
        int err;
        err = mdb_txn_begin(DEV_ENV(db, TT_HASHCOUNT), NULL, MDB_RDONLY,
                &txn);

        err = mdb_get(txn, DEV_SHARD(db, TT_HASHCOUNT, 0), &key, &data);

        if (err) {
            mdb_txn_abort(txn);
            log_error(lg, "Dev(%s): %s mdb_put: (%d) %s", db->dev->name,
                    type_tag_name[TT_HASHCOUNT], err, mdb_strerror(err));
            err = -EIO;
            return;
        }

        memcpy(target, data.mv_data, data.mv_size);

        mdb_txn_abort(txn);

        for (uint32_t i = 0; i < KEY_BLOOM_BYTELEN; i++)
            assert_int_equal (target[i] - db->bloom[i], 0);

        assert_int_equal(memcmp(target, db->bloom, KEY_BLOOM_BYTELEN), 0);
    }

}

static void
bloom_wipe_test(void **state) {

    part_walk_action_t wa = rd_partition_walk(devices.dev[0], wipe_bloom, NULL);
    assert_int_equal(wa, PART_WALK_COMPLETED);
}

/*
 * Loading the bloom is guarded by two commits during store. if the value
 * is anything other then 0 -- the bloom filter in lmdb is considered toxic
 */

static void
bloom_toxic(void **state) {

    uv_buf_t u_key, u_val;

    u_key.base = BLOOM_STORE_OK;
    u_key.len = strlen(u_key.base);
    u_val.len = sizeof(int);

    int err = 0;

    u_val.base = NULL;

    assert_int_equal(rd_config(devices.dev[0], CFG_READ, &u_key, &u_val), 0);

    assert_int_equal(strcmp(u_key.base, BLOOM_STORE_OK), 0);
    assert_int_equal(*(int *) u_val.base, -1);


    err = 0;
    u_val.len = sizeof(int);
    u_val.base = (char *) &err;

    rd_config(devices.dev[0], CFG_WRITE, &u_key, &u_val);
    /* load should succeed  */
    assert_int_equal(rd_dev_load_bloom(devices.dev[0]), 0);
}


int
main(int argc, char *argv[]) {

    lg = Logger_create("test");

    /*
     * we need to set this value so we can load the filters
     * old style and compare to new style
     */

    setenv("BLOOM_FAST_PATH", "0", 1);

    const UnitTest tests[] = {
            unit_test(rd_init),

            unit_test(bloom_store_test),
            unit_test(bloom_compare_test),

            unit_test(bloom_store_test),
            unit_test(bloom_compare_test_2),

            unit_test(bloom_store_test),
            unit_test(bloom_compare_test_2),

            unit_test(bloom_wipe_test),
            unit_test(bloom_toxic),


            unit_test(fini)

    };

    return run_tests(tests);
}
