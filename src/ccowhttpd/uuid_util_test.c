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
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <uuid/uuid.h>
#include <json-c/json.h>

#include <uuid_util.h>


void
test_uuid() {
	uuid_t uuid1, uuid2, uuid3;
	int err;

	uuid_util_generate(uuid1);

	char buf[UUID_BUFFER];
	uuid_util_str(uuid1, buf);
	printf("uuid1: %s\n", buf);

	err = uuid_util_parse(buf, uuid2);
	assert(err == 0);

	err = uuid_util_compare(uuid1, uuid2);
	printf("uuid1 vs uuid2: %d\n", err);
	assert(err == 0);

	uuid_util_generate(uuid3);

	uuid_util_str(uuid3, buf);
	printf("uuid3: %s\n", buf);

	err = uuid_util_compare(uuid1, uuid3);
	printf("uuid1 vs uuid3: %d\n", err);
	assert(err != 0);
}

int
main()
{
    test_uuid();
}
