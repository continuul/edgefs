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
#include <time.h>
#include <string.h>
#include <errno.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"
#include "replicast.h"

#define TEST_BUCKET    "acl-bucket"

int acl_count = 100;

ccow_t cl = NULL, tc = NULL;
int dd = 0;
int writeon = 1;
int readon = 1;

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
    sprintf(buf, "acl%5.5d", num);
}

/*
 * =======================================================================
 *		ACLs put
 * =======================================================================
 */
static void acls_put(void **state)
{
    if (!writeon)
        return;
    assert_non_null(cl);
    char key[64];
    char value[64];

    srand(time(NULL));
    for (int i = 0; i < acl_count; i++) {
        create_name(key, i);

        sprintf(value, "{ type: %d,  access: xx%d, r: %d }", i, i, rand());
        printf("Put test key: %s, value: %s\n", key, value);
        struct iovec iov[1];

        iov[0].iov_base = value;
        iov[0].iov_len = strlen(value) + 1;

        int err = ccow_acl_put(cl, TEST_BUCKET, strlen(TEST_BUCKET) + 1, key,
                               strlen(key) + 1, (uint64_t) i, iov);
        if (err) {
            printf("Put acl error: %d", err);
        }
        assert_int_equal(err, 0);
    }
}

/*
 * =======================================================================
 *		ACLs delete
 * =======================================================================
 */
static void acls_delete(void **state)
{
    if (!writeon)
        return;
    assert_non_null(cl);
    char key[64];
    // Delete last key
    create_name(key, acl_count - 1);
    int err = ccow_acl_delete(cl, TEST_BUCKET, strlen(TEST_BUCKET) + 1, key, strlen(key) + 1, acl_count - 1);
    assert_int_equal(err, 0);
}

/*
 * =======================================================================
 *		ACLs get
 * =======================================================================
 */
static void acls_get(void **state)
{
    if (!readon)
        return;
    assert_non_null(cl);
    size_t value_size;
    char key[64];
    int err;
    struct iovec iov[1];
    for (int i = 0; i < acl_count - 1; i++) {
        create_name(key, i);
        int err = ccow_acl_get(cl, TEST_BUCKET, strlen(TEST_BUCKET) + 1,
                               key, strlen(key) + 1, i, iov);
        assert_int_equal(err, 0);
        if (err) {
            printf("acls_get key: %s, err: %d\n", key, err);
        }
        if (i < 10)
            printf("acls_get key: %s, value: %s\n", key, (char *)iov->iov_base);
        if (iov->iov_base)
            je_free(iov->iov_base);
    }

    // Try to get deleted key
    create_name(key, acl_count - 1);
    err = ccow_acl_get(cl, TEST_BUCKET, strlen(TEST_BUCKET) + 1, key, strlen(key) + 1, acl_count - 1, iov);
    assert_int_equal(err, -ENOENT);

    // Try to get non-existing key
    create_name(key, 9999999);
    err = ccow_acl_get(cl, TEST_BUCKET, strlen(TEST_BUCKET) + 1, key, strlen(key) + 1, acl_count, iov);
    assert_int_equal(err, -ENOENT);

}

static void libccow_teardown(void **state)
{
    assert_non_null(cl);
    ccow_tenant_term(cl);
}

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "wrnc:h")) != -1) {
        switch (opt) {
        case 'c':
            acl_count = atoi(optarg);
            break;

        case 'h':
            printf("\nUsage: -c <acl_count> [-n] [-w]/[-r]\n");
            printf("\twhere: -w write only mode, -r read only mode \n\n");
            exit(0);
            break;

        case 'w':
            writeon = 1;
            readon = 0;
            break;

        case 'r':
            writeon = 0;
            readon = 1;
            break;


        case 'n':
            dd = 1;
            break;

        default:
            break;
        }
    }

    printf("ACL count: %d\n", acl_count);

    TEST_ENV = getenv("NEDGE_ENV");
    if (!TEST_ENV)
        TEST_ENV = "production";
    const UnitTest tests[] = {
        unit_test(libccowd_setup),
        unit_test(libccow_setup),
        unit_test(acls_put),
        unit_test(acls_delete),
        unit_test(acls_get),
        unit_test(libccow_teardown),
        unit_test(libccowd_teardown)
    };
    return run_tests(tests);
}
