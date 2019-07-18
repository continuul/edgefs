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
#include "ccow-impl.h"
#include "ccowd-impl.h"
#include "ccowd.h"
#include "clengine.h"

static ccow_t cl = NULL;
static uint128_t *srcid, *destid;
static uint32_t rowid = 3;

int dd = 0;

static void
libccowd_setup(void **state)
{
    if(!dd){
        assert_int_equal(ccow_daemon_init(NULL), 0);
        usleep(2 * 1000000L);
    }
}

static int
row_usage_notify_test(uint128_t *src_vdevid, uint128_t *dest_vdevid, uint32_t row, int same_fdomain)
{
	char src_vdevstr[64];
	char dest_vdevstr[64];
	int err;

	uint128_dump(src_vdevid, src_vdevstr, 64);
	uint128_dump(dest_vdevid, dest_vdevstr, 64);

	printf("Notification src dev: %s target dev: %s row: %u "
		"same_fdomain? : %d\n", src_vdevstr, dest_vdevstr,
					row, same_fdomain);

	err = memcmp(srcid, src_vdevid, sizeof(uint128_t));
	assert_int_equal(err, 0);
	err = memcmp(destid, dest_vdevid, sizeof(uint128_t));
	assert_int_equal(err, 0);
	assert_int_equal(rowid, row);
	return 0;
}

static void
evac_notify_test(void **state)
{
	char src_vdevstr[64];
	char dest_vdevstr[64];

	clengine_register_rowusage_start_cb(row_usage_notify_test);
	clengine_register_rowusage_end_cb(row_usage_notify_test);

	assert_not_in_range(SERVER_FLEXHASH->numdevices, 0, 1);
	srcid = &SERVER_FLEXHASH->vdevstore->lvdevlist[0].vdevid;
	destid = &SERVER_FLEXHASH->vdevstore->lvdevlist[1].vdevid;

	uint128_dump(srcid, src_vdevstr, 64);
	uint128_dump(destid, dest_vdevstr, 64);

	/* Issue a fake row change message */
	printf("Simulating a START of row change src: %s dest: %s row: %u\n",
		src_vdevstr, dest_vdevstr, rowid);
	clengine_notify_rowusage_change(1, srcid, destid, rowid, 1);

	printf("Simulating a END of row change src: %s dest: %s row: %u\n",
		src_vdevstr, dest_vdevstr, rowid);
	clengine_notify_rowusage_change(0, srcid, destid, rowid, 1);

	/* Wait to test message delivery */
	sleep(1);
}

static void
libccowd_teardown(void **state)
{
    if(!dd)
	    ccow_daemon_term();
}

int
main(int argc, char **argv)
{
    if (argc == 2) {
        if (strcmp(argv[1], "-n") == 0)
             dd = 1;
    }
	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(evac_notify_test),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

