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
#ifndef user_h
#define user_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include "hashtable.h"
#include "ccowutil.h"

#define USER_TTL 300

typedef struct User {
	struct json_object *prop;
    uint64_t created;
} User;

// User methods
int user_init(User *user, char *cluster, char *tenant, char *juser);
void user_destroy(User *user);

const char *user_to_string(User *user);

int user_age(User *user);
int user_expired(User *user);

const char *user_property_string(User *user, char *name, const char *def);
int user_property_int(User *user, char *name, int def);

// User hash table methods
char * build_auth_key(char *cluster, char *tenant, char *authkey, char *buf, int max_len);

int user_ht_create(void);
int user_ht_destroy(void);

int user_put_ht(User *user);
int user_get_by_hash(const char *hash, User **ent);
void user_delete_ht(const char *hash);


#ifdef __cplusplus
}
#endif

#endif
