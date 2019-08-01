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
#ifndef param_h
#define param_h

#ifdef __cplusplus
extern "C" {
#endif

#include "hashtable.h"
#include "h2o.h"

#define ALLOCATE_OFF  0
#define ALLOCATE_ON   1
#define LOWERCASE_ON  2
#define PARAM_DEFAULT_SIZE 64


#define PARAM_STR(s) (s), strlen(s)

typedef struct param {
	h2o_iovec_t key;
	h2o_iovec_t val;
} param;

typedef struct param_vector {
	param *pairs;
	h2o_mem_pool_t *pool;
	hashtable_t *ht;
	int size;
	int capacity;
	int flags;
} param_vector;


int param_init(h2o_mem_pool_t *pool, int capacity, int allocate, param_vector *params);

char *param_str(param *p, char *buf, unsigned max);

char *param_key_str(param *p, char *buf, unsigned max);

char *param_value_str(param *p, char *buf, unsigned max);

int param_key_equal(param *p, char *key, int key_size);

int param_value_equal(param *p, char *val, int val_size);

int param_add_param(param *p, param_vector *params);

int param_add(char *key, int key_size, char *val, int val_size, param_vector *params);

int param_add_from(char *key, int key_size, char *def, int def_size, param_vector *source, param_vector *params);

int param_add_from_as(char *key, int key_size, char *target_key, int target_key_size, char *def, int def_size, param_vector *source, param_vector *params);

int param_count(param_vector *params);

param *param_get(int i, param_vector *params);

param *param_find(char *key, int key_size, param_vector *params);

param *param_find_value(char *key, int key_size, param_vector *params);

long param_find_long(char *key, int key_size, long def, param_vector *params);

int64_t param_find_int64(char *key, int key_size, int64_t def, param_vector *params);

uint64_t param_find_uint64(char *key, int key_size, uint64_t def, param_vector *params);


int param_has(char *key, int key_size, param_vector *params);

char **param_sort(param_vector *params);

void param_sort_free(char **keys, param_vector *params);


void param_dump(char *header, param_vector *params);

void param_free(param_vector *params);



#ifdef __cplusplus
}
#endif

#endif
