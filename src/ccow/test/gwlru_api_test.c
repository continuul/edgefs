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

#include <stdio.h>
#include "ccowutil.h"
#include "crypto.h"
#include "gwcache.h"
#include "reptrans.h"
#include "cmocka.h"

Logger lg;

static void
lru_test()
{
	uint512_t chid1, chid2;
	struct chid_node *n;

	memset(&chid1, '1', sizeof(uint512_t));
	memset(&chid2, '2', sizeof(uint512_t));

	gw_lru_update(&chid1);
	n = gw_lru_get_first_node();
	assert(uint512_cmp(&chid1, &n->cl_chid) == 0);

	gw_lru_update(&chid2);
	n = gw_lru_get_first_node();
	assert(uint512_cmp(&chid2, &n->cl_chid) == 0);
}

static void
lru_setup()
{
	struct repdev dev;
	struct repdev_bg_config cfg;

	lg = Logger_create("gwlru");
	memset(&dev, 0, sizeof(dev));
	memset(&cfg, 0, sizeof(cfg));
	dev.gw_cache = 1;
	dev.bg_config = &cfg;
	gw_lru_init(&dev);
}

static void
lru_teardown()
{
	gw_lru_destroy();
	Logger_destroy(lg);
	lg = NULL;
}

int
main(int argc, char **argv)
{
	const UnitTest tests[] = {
		unit_test(lru_setup),
		unit_test(lru_test),
		unit_test(lru_teardown)
	};

	return run_tests(tests);
}
