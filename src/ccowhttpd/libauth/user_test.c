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
#include "user.h"

void
test_user()
{
	User user1, user2;
	struct json_object *juser1, *juser2;
	int err;
	char *str1 = "{ \"username\": \"user1\", \"type\": \"s3\", \
		      \"authkey\": \"FQKPDW7E2OKWKY2VMQGF\", \"secret\": \"ujqa78PLlnm6wzXaxw1YoaKDAD8VwQw3NFcjhzDI\", \
		      \"identity\": \"nedge\", \"admin\": 1 }";
	char *str2 = "{ \"username\": \"user2\", \"type\": \"object\", \
		      \"authkey\": \"XXXXXW7E2OKWKY2VMQGF\", \"secret\": \"ssqa78PLlnm6wzXaxw1YoaKDAD8VwQw3NFcjhzDI\", \
		      \"identity\": \"nedge\", \"admin\": 0 }";

	err = user_init(&user1, "cltest", "test", str1);
	assert(err == 0);
	err = user_init(&user2, "cltest", "test", str2);
	assert(err == 0);

	err = user_put_ht(&user1);
	assert(err == 0);

	err = user_put_ht(&user2);
	assert(err == 0);


	char buf[2048];
	printf("\nUser1: %s\n", user_to_string(&user1));
	printf("User2: %s\n", user_to_string(&user2));

	int admin = user_property_int(&user1, "admin", 0);
	assert(admin == 1);

	const char *authkey = user_property_string(&user1, "authkey", NULL);
	printf("Key: %s\n", authkey);

	const char *secret = user_property_string(&user1, "secret", NULL);
	printf("Secret: %s\n", secret);

	const char *type = user_property_string(&user1, "type", NULL);
	printf("Type: %s\n", type);


	char save_hash[2048];
	const char *auth_hash = user_property_string(&user1, "auth_hash", NULL);
	printf("Auth hash key: %s\n", auth_hash);
	strcpy(save_hash, auth_hash);

	printf("Age1: %d\n", user_age(&user1));
	printf("Expired1: %d\n", user_expired(&user1));

	usleep(2 * 1000000L);
	printf("Age2: %d\n", user_age(&user1));
	printf("Expired2: %d\n", user_expired(&user1));

	User *ref;
	err = user_get_by_hash(auth_hash, &ref);
	assert(err == 0);

	printf("User by auth_hash ref: %s\n", user_to_string(ref));


	err = user_get_by_hash("xxx", &ref);
	assert(err != 0);

	user_delete_ht(auth_hash);
}


int
main()
{
	lg = Logger_create("user_test");

	user_ht_create();

	test_user();

	user_ht_destroy();

	printf("\nDone\n");

}
