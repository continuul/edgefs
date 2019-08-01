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
#ifndef bucket_options_h
#define bucket_options_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ccow.h"
#include "hashtable.h"
#include "ccowutil.h"

#define BUCKET_OPTIONS_TTL 180

typedef struct BUCKET_OPTIONS {
	struct json_object *prop;
    uint64_t created;
} BUCKET_OPTIONS;

// BUCKET_OPTIONS methods
int bucket_options_init(BUCKET_OPTIONS *bucket_options, char *cluster, char *tenant, char *bucket, char *jbucket_options);
void bucket_options_destroy(BUCKET_OPTIONS *bucket_options);

const char *bucket_options_to_string(BUCKET_OPTIONS *bucket_options);

int bucket_options_expired(BUCKET_OPTIONS *bucket_options);

const char *bucket_options_property_string(BUCKET_OPTIONS *bucket_options, char *name, const char *def);

// BUCKET_OPTIONS hash table
char * build_bucket_options_key(char *cluster, char *tenant, char *bucket, char *buf, int max_len);

int bucket_options_ht_create(void);
int bucket_options_ht_destroy(void);

int bucket_options_put_ht(BUCKET_OPTIONS *bucket_options);
int bucket_options_get_by_bucket_optionskey(const char *bucket_optionskey, BUCKET_OPTIONS **ent);
void bucket_options_delete_ht(const char *bucket_optionskey);

int get_bucket_options(ccow_t tc, char *cluster, char *tenant, char *bucket, BUCKET_OPTIONS **bucket_options);

uint64_t get_object_expiration(BUCKET_OPTIONS *bucket_options, char *oid);


#ifdef __cplusplus
}
#endif

#endif
