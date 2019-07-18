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
#ifndef acl_h
#define acl_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include "hashtable.h"
#include "ccowutil.h"

#define ACL_TTL 180

typedef struct ACL {
	struct json_object *prop;
    uint64_t created;
} ACL;

// ACL methods
int acl_init(ACL *acl, char *cluster, char *tenant, char *bucket, char *oid, char *jacl);
void acl_destroy(ACL *acl);

const char *acl_to_string(ACL *acl);

int acl_expired(ACL *acl);

const char *acl_property_string(ACL *acl, char *name, const char *def);

// ACL hash table
char * build_acl_key(char *cluster, char *tenant, char *bucket, char *oid, char *buf, int max_len);

int acl_ht_create(void);
int acl_ht_destroy(void);

int acl_put_ht(ACL *acl);
int acl_get_by_aclkey(const char *aclkey, ACL **ent);
void acl_delete_ht(const char *aclkey);


#ifdef __cplusplus
}
#endif

#endif
