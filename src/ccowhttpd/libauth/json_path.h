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
#ifndef __JSON_PATH_H_INCLUDED__
#define __JSON_PATH_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define MAX_PATH 1024

json_bool get_by_path(struct json_object *jobj, char *path, struct json_object **value);

json_bool get_by_path_array(struct json_object *jobj, char *path, struct json_object **value);

json_bool get_by_path_string(struct json_object *jobj, char *path, const char **value);

json_bool get_by_path_int(struct json_object *jobj, char *path, int *value);

json_bool get_by_path_int64(struct json_object *jobj, char *path, int64_t *value);

json_bool get_by_path_double(struct json_object *jobj, char *path, double *value);

json_bool get_by_path_boolean(struct json_object *jobj, char *path, int *value);

const char *get_by_path_string_def(struct json_object *jobj, char *path, const char *def);

int get_by_path_int_def(struct json_object *jobj, char *path, int def);

int64_t get_by_path_int64_def(struct json_object *jobj, char *path, int64_t def);

double get_by_path_double_def(struct json_object *jobj, char *path, double def);

int get_by_path_boolean_def(struct json_object *jobj, char *path, int def);


#ifdef __cplusplus
}
#endif

#endif
