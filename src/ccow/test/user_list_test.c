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
#include "replicast.h"

int user_count = 100;
int marker_num = 5;
int get_count = 5;

ccow_t cl = NULL, tc = NULL;
int dd = 0;
int writeon = 1;
int readon = 1;

ccow_shard_context_t list_shard_context;
ccow_shard_context_t attributes_shard_context;

char *TEST_ENV = NULL;

// ----------------------------------------------------------------------------
// setup and tear down functions
// ----------------------------------------------------------------------------
static void libccowd_setup(void **state)
{
    if (!dd) {
        assert_int_equal(ccow_daemon_init(NULL), 0);
        usleep(2 * 1000000L);
    }
}

static void libccow_setup(void **state)
{
    assert_int_equal(ccow_default_tenant_init("cltest", 7, "test", 5, &cl), 0);
}

static void libccowd_teardown(void **state)
{
    if (!dd) {
        ccow_daemon_term();
    }
}

static void create_name(char *buf, int num)
{
    sprintf(buf, "user%5.5d", num);
}

/*
 * =======================================================================
 *		Users put
 * =======================================================================
 */
static void users_put(void **state)
{
    if (!writeon)
        return;
    assert_non_null(cl);
    char name[64];
    char value[64];
    for (int i = 0; i < user_count; i++) {
        create_name(name, i);

        sprintf(value, "{ type: %d, password: xx%d }", i, i);
        struct iovec iov[2];

        iov[0].iov_base = name;
        iov[0].iov_len = strlen(name) + 1;
        iov[1].iov_base = value;
        iov[1].iov_len = strlen(value) + 1;

        int err = ccow_user_put(cl, iov);
        if (err) {
            printf("Put user error: %d", err);
        }
        assert_int_equal(err, 0);
    }
}

/*
 * =======================================================================
 *		Users delete
 * =======================================================================
 */
static void users_delete(void **state)
{
    if (!writeon)
        return;
    assert_non_null(cl);
    char name[64];
    // Delete last name
    create_name(name, user_count - 1);
    int err = ccow_user_delete(cl, name, strlen(name) + 1);
    assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *		Users get
 * =======================================================================
 */
static void users_get(void **state)
{
    if (!readon)
        return;
    assert_non_null(cl);
    size_t value_size;
    char name[64];
    int err;
    struct iovec iov[1];
    for (int i = 0; i < user_count - 1; i++) {
        create_name(name, i);
        int err = ccow_user_get(cl, name, strlen(name) + 1, iov);
        assert_int_equal(err, 0);
        if (i < 10)
            printf("users_get name: %s, value: %s\n", name, (char *)iov->iov_base);
        if (iov->iov_base)
            je_free(iov->iov_base);
    }
    // Try to get deleted name
    create_name(name, user_count - 1);
    err = ccow_user_get(cl, name, strlen(name) + 1, iov);
    assert_int_equal(err, -ENOENT);

    // Try to get non-existing name
    create_name(name, 9999999);
    err = ccow_user_get(cl, name, strlen(name) + 1, iov);
    assert_int_equal(err, -ENOENT);

}

/*
 * =======================================================================
 *		Get user list
 * =======================================================================
 */
static void users_get_list(void **state)
{
    if (!readon)
        return;
    assert_non_null(cl);
    size_t value_size;
    char marker[64];
    char name[64];
    create_name(marker, marker_num);

    printf("list_get_list Marker: %s\n", marker);

    ccow_lookup_t iter;

    int err = ccow_user_list(cl, marker, strlen(marker) + 1, get_count, &iter);

    struct ccow_metadata_kv *kv;
    int ikey = marker_num + 1;
    while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1))) {
        create_name(name, ikey++);
        printf("test result list name: %s kv->key: %s\n", name, kv->key);
        assert_int_equal(strcmp(name, kv->key), 0);
    }

    ccow_lookup_release(iter);
}

static void libccow_teardown(void **state)
{
    assert_non_null(cl);
    ccow_tenant_term(cl);
}

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "rwnc:g:hm:")) != -1) {
        switch (opt) {
        case 'c':
            user_count = atoi(optarg);
            break;

        case 'h':
            printf("\nUsage: -c <user_count> -m <marker_num> -g <get_count> [-n] [-w]/[-r]\n");
            printf("\twhere: -w write only mode, -r read only mode \n\n");
            exit(0);
            break;

        case 'm':
            marker_num = atoi(optarg);
            break;

        case 'n':
            dd = 1;
            break;

        case 'w':
            writeon = 1;
            readon = 0;
            break;

        case 'r':
            writeon = 0;
            readon = 1;
            break;

        case 'g':
            get_count = atoi(optarg);
            break;

        default:
            break;
        }
    }

    printf("User count: %d\n", user_count);
    printf("Marker num: %d\n", marker_num);
    printf("Get count: %d\n", get_count);

    TEST_ENV = getenv("NEDGE_ENV");
    if (!TEST_ENV)
        TEST_ENV = "production";
    const UnitTest tests[] = {
        unit_test(libccowd_setup),
        unit_test(libccow_setup),
        unit_test(users_put),
        unit_test(users_delete),
        unit_test(users_get),
        unit_test(users_get_list),
        unit_test(libccow_teardown),
        unit_test(libccowd_teardown)
    };
    return run_tests(tests);
}
