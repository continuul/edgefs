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

#include "acl.h"

void
test_acl()
{
	ACL acl1, acl2;
	struct json_object *jacl1, *jacl2;
	int err;
	char *str1 = "{ \"owner\": \"user1\", \
			\"acls\": [ { \"user\": \"*\", \"acls\": \"rw\" }, { \"user\": \"user2\", \"acls\": \"rw\" } ] }";
	char *str2 = "{ \"acls\": [ { \"user\": \":\", \"acls\": \"r\" }, { \"user\": \"user2\", \"acls\": \"r\" } ] }";

	err = acl_init(&acl1, "cltest", "test", "bk1", "", str1);
	assert(err == 0);
	err = acl_init(&acl2, "cltest", "test", "bk2", "", str2);
	assert(err == 0);

	printf("\nACL1: %s\n", acl_to_string(&acl1));
	printf("ACL2: %s\n", acl_to_string(&acl2));

	char save_key[2048];
	const char *aclkey = acl_property_string(&acl1, "aclkey", NULL);
	printf("Key: %s\n", aclkey);
	strcpy(save_key, aclkey);

	const char *owner = acl_property_string(&acl1, "owner", NULL);
	printf("Owner: %s\n", owner);

	printf("Expired1: %d\n", acl_expired(&acl1));

	err = acl_put_ht(&acl1);
	assert(err == 0);

	ACL *ref;
	err = acl_get_by_aclkey(aclkey, &ref);
	assert(err == 0);

	printf("ACL by aclkey ref: %s\n", acl_to_string(ref));


	err = acl_put_ht(&acl2);

	assert(err == 0);

	// Delete and read
	acl_delete_ht(aclkey);

	// Use saved key
	err = acl_get_by_aclkey(save_key, &ref);
	assert(err != 0);
}


int
main()
{
	lg = Logger_create("acl_test");

	acl_ht_create();

	test_acl();

	acl_ht_destroy();

	printf("\nDone\n");
}
