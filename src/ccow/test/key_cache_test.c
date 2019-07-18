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
/*
 * This test simply tests the simple LRU
 * cache in rtrd more elaborate replace
 * strategies are worth exploring
 *
 */
#include <linux/limits.h>
#include "reptrans.h"
#include "rtrd/reptrans-rd.h"
#include "cmocka.h"
#include "logger.h"

Logger lg;

struct repdev_db db = {0};

static void
init_cache(void **state) {
    assert_int_equal(key_cache_ini(&db.key_cache, 10, NULL), 0);
}

static void
fini_cache(void **state) {
    assert_int_equal(key_cache_fini(db.key_cache), 0);
}

static void
insert_key(void **state) {
    uint64_t k = 1;
    uint32_t s = 1;
    type_tag_t ttag = TT_CHUNK_PAYLOAD;

    assert_int_equal(key_cache_insert(db.key_cache, &k, ttag, s), 0);
    assert_int_equal(HASH_COUNT(db.key_cache->entries), 1);
}

static void
dup_keys(void **state) {
    uint64_t k = 1;
    uint32_t s = 1;
    type_tag_t ttag = TT_CHUNK_PAYLOAD;

    assert_int_equal(key_cache_insert(db.key_cache, &k, ttag, s), -EEXIST);
    assert_int_equal(HASH_COUNT(db.key_cache->entries), 1);
}

static void
lookup_test(void **state) {
    uint64_t k = 1;
    uint64_t value;
    type_tag_t ttag = TT_CHUNK_PAYLOAD;

    for (int i = 0; i < 100; i++) {

        assert_int_equal(key_cache_lookup(db.key_cache, &k, ttag, &value),
                0);
        assert_int_equal(value, 1);
    }

    for (int i = 0; i < 100; i++) {

        assert_int_equal(key_cache_lookup(db.key_cache, &k, TT_CHUNK_MANIFEST, &value),
                -ENOENT);
    }
}

static void
remove_test(void **state) {
    uint64_t k = 123;
    uint64_t value;
    type_tag_t ttag = TT_CHUNK_PAYLOAD;

    assert_int_equal(key_cache_insert(db.key_cache, &k, ttag, 333), 0);
    k = 321;
    assert_int_equal(key_cache_remove(db.key_cache, &k, ttag), -ENOENT);

    k = 123;
    assert_int_equal(key_cache_lookup(db.key_cache, &k, ttag, &value),
            0);
    assert_int_equal(value, 333);

    assert_int_equal(key_cache_remove(db.key_cache, &k, ttag), 0);
    assert_int_equal(key_cache_remove(db.key_cache, &k, ttag), -ENOENT);
    assert_int_equal(key_cache_lookup(db.key_cache, &k, ttag, &value),
            -ENOENT);
    assert_null(value);
}

static void
evict_test(void **state) {
    /*
     * the first key, should be evicted after inserting more and it
     * not being used
     */
    type_tag_t ttag = TT_CHUNK_MANIFEST;

    for (uint64_t k = 2; k < 100; k++)
        assert_int_equal(key_cache_insert(db.key_cache, &k, ttag, 0), 0);

    uint64_t nothere = 2;

    uint32_t result;

    assert_int_equal(key_cache_lookup(db.key_cache, &nothere, ttag, (void *) &result),
            -ENOENT);
    assert_int_equal(result, 0);

}

static void
evict_test_2(void **state) {
    /*
     * the first key, should not be evicted after inserting more and
     * being used
     */
    uint64_t here = 1;
    uint64_t result;
    type_tag_t ttag = TT_CHUNK_MANIFEST;

    for (uint64_t k = 1; k < 1000; k++) {
        assert_int_equal(key_cache_insert(db.key_cache, &k, ttag, k), 0);
        assert_int_equal(
                key_cache_lookup(db.key_cache, &here, ttag, (void *) &result), 0);
    }

    assert_int_equal(key_cache_lookup(db.key_cache, &here, ttag, &result),
            0);

    assert_int_not_equal(result, 0);
    assert_int_not_equal(db.key_cache->stats.miss, 0);
    assert_int_not_equal(db.key_cache->stats.hit, 0);
    assert_int_equal(db.key_cache->c - 1, HASH_COUNT(db.key_cache->entries));

}

int
main(int argc, char *argv[]) {

    lg = Logger_create("key_chache_test");

    const UnitTest tests[] = {
            unit_test(init_cache),
            unit_test(insert_key),
            unit_test(dup_keys),
            unit_test(remove_test),
            unit_test(lookup_test),
            unit_test(evict_test),
            unit_test(evict_test_2),
            unit_test(remove_test),
            unit_test(fini_cache),

            unit_test(init_cache),
            unit_test(insert_key),
            unit_test(dup_keys),
            unit_test(remove_test),
            unit_test(lookup_test),
            unit_test(evict_test),
            unit_test(evict_test_2),
            unit_test(remove_test),
            unit_test(fini_cache),

    };
    return run_tests(tests);
}
