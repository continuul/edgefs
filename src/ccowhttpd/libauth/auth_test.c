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
#include <json-c/json.h>

#include "logger.h"
#include "auth.h"
#include "user.h"
#include "acl.h"

void
test_auth()
{
	User *user;
	int err;

	err = get_user_by_authkey("cltest", "test", "xxx", &user);
	assert(err != 0);
	printf("\nWrong user err: %d\n", err);

	err = get_user_by_authkey("cltest", "test", "PTAA8RZIP6WJP5SRH2MS", &user);
	assert(err == 0);
	printf("\nUser1: %s\n", user_to_string(user));

	User *user2;
	err = get_user_by_authkey("cltest", "test", "XUAYKSRZMOEERAUFGUVR", &user2);
	assert(err == 0);
	printf("\nUser2: %s\n", user_to_string(user2));


	ACL *acl = NULL;
	err = get_access("cltest", "test","bk1", "", "read", user, &acl);
	printf("\nAccess user1 err: %d\n", err);
	if (!err && acl) {
		printf("\nACL: %s\n", acl_to_string(acl));
		printf("\nACL.owner: %s\n", acl_property_string(acl, "owner", NULL));
	}
	err = get_access("cltest", "test","bk1", "", "read", user, &acl);
	printf("\nAccess user1 err: %d\n", err);

	err = get_access("cltest", "test","bk2", "", "read", user, &acl);
	printf("\nAccess user1 err: %d\n", err);
	if (!err && acl) {
		printf("\nACL: %s\n", acl_to_string(acl));
		printf("\nACL.owner: %s\n", acl_property_string(acl, "owner", NULL));
	}

	err = get_access("cltest", "test","bk1", "", "write", user2, &acl);
	printf("\nAccess user2 err: %d\n", err);
	if (!err && acl) {
		printf("\nACL: %s\n", acl_to_string(acl));
		printf("\nACL.owner: %s\n", acl_property_string(acl, "owner", NULL));
	}

	printf("\n\n");
}


int
main()
{
	lg = Logger_create("auth_test");

	int err = auth_init();
	assert(err == 0);

	test_auth();

	auth_destroy();
	printf("\nDone\n");
}
