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

#include "cmocka.h"
#include "common.h"
#include "auditd.h"

int dd = 0;

static void
setup(void **state) {
    if(!dd){
		auditd_daemonize = 0;
		auditd_setup_pidfile_var();

        long err = auditd_init();
        *state = (void *)err;
        assert_int_equal(err, 0);
    }
}

static void
teardown(void **state) {
    if(!dd)
        auditd_term(0);
}

static void
auditd_test_success(void **state) {
	long err = (long)*state;
	assert_int_equal(err, 0);
	printf("Servicing CCOW Audit protocol. Press Ctrl-C to continue\n");
	usleep(3600 * 1000000L);
}

int
main(int argc, char **argv)
{
    if (argc == 2) {
        if (strcmp(argv[1], "-n") == 0)
             dd = 1;
    }
    const UnitTest tests[] = { unit_test_setup_teardown(auditd_test_success, setup, teardown) };

	return run_tests(tests);
}
