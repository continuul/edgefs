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
#include <stdlib.h>
#include "cmocka.h"
#include "common.h"
#include "ccowd.h"

static long interval = 3600;

static void
setup(void **state) {
	long err = ccow_daemon_init(NULL);
	*state = (void *)err;
	assert_int_equal(err, 0);
	usleep(2 * 1000000L);
}

static void
teardown(void **state) {
	long err = (long)*state;
	assert_int_equal(err, 0);
	ccow_daemon_term();
}

static void
daemon_test_success(void **state) {
	long err = (long)*state;
	assert_int_equal(err, 0);
	printf("Serving Replicast protocol for %li seconds. "
		"Press Ctrl-C to continue\n", interval);
	while(interval--)
		usleep(1000000L);
}

int
main(int argc, char** argv)
{
    if (argc == 3) {
        if (strcmp(argv[1], "-i") == 0) {
             long aux = strtol(argv[2], NULL, 10);
             if (aux == 0) {
            	 fprintf(stderr,"Wrong interval value %s\n", argv[2]);
            	 exit(1);
             }
             interval = aux;
        };
    }

	const UnitTest tests[] = {
		unit_test_setup_teardown(daemon_test_success, setup, teardown)
	};
	return run_tests(tests);
}
