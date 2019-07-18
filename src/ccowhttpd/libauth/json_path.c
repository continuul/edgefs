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

#include "json_path.h"

json_bool
get_by_path(struct json_object *jobj, char *path, struct json_object **value) {
	if (jobj == NULL || path == NULL)
		return 0;

	char apath[MAX_PATH];
	struct json_object *tmp;
	strncpy(apath, path, MAX_PATH - 1);

	char *p = strchr(apath, '/');
	if (p == NULL) {
		return json_object_object_get_ex(jobj, apath, value);
	}

	*p = '\0';
	if (!json_object_object_get_ex(jobj, apath, &tmp)) {
		return 0;
	}

	return get_by_path(tmp, (p + 1), value);
}

json_bool
get_by_path_array(struct json_object *jobj, char *path, struct json_object **value) {
	if (!get_by_path(jobj, path, value))
		return 0;

	if (json_object_get_type(*value) != json_type_array)
		return 0;

	return 1;
}


json_bool
get_by_path_string(struct json_object *jobj, char *path, const char **value) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return 0;

	if (json_object_get_type(tmp) != json_type_string)
		return 0;

	*value = json_object_get_string(tmp);
	return 1;
}

const char *
get_by_path_string_def(struct json_object *jobj, char *path, const char *def) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return def;

	if (json_object_get_type(tmp) != json_type_string)
		return def;

	return json_object_get_string(tmp);
}


json_bool
get_by_path_int(struct json_object *jobj, char *path, int *value) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return 0;

	if (json_object_get_type(tmp) != json_type_int)
		return 0;

	*value = json_object_get_int(tmp);
	return 1;
}

int
get_by_path_int_def(struct json_object *jobj, char *path, int def) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return def;

	if (json_object_get_type(tmp) != json_type_int)
		return def;

	return json_object_get_int(tmp);
}


json_bool
get_by_path_int64(struct json_object *jobj, char *path, int64_t *value) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return 0;

	if (json_object_get_type(tmp) != json_type_int)
		return 0;

	*value = json_object_get_int64(tmp);
	return 1;
}

int64_t
get_by_path_int64_def(struct json_object *jobj, char *path, int64_t def) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return def;

	if (json_object_get_type(tmp) != json_type_int)
		return def;

	return json_object_get_int64(tmp);
}


json_bool
get_by_path_double(struct json_object *jobj, char *path, double *value) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return 0;

	if (json_object_get_type(tmp) != json_type_double)
		return 0;

	*value = json_object_get_double(tmp);
	return 1;
}


double
get_by_path_double_def(struct json_object *jobj, char *path, double def) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return def;

	if (json_object_get_type(tmp) != json_type_double)
		return def;

	return json_object_get_double(tmp);
}


json_bool
get_by_path_boolean(struct json_object *jobj, char *path, int *value) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return 0;

	if (json_object_get_type(tmp) != json_type_boolean)
		return 0;

	*value = json_object_get_boolean(tmp);
	return 1;
}

int
get_by_path_boolean_def(struct json_object *jobj, char *path, int def) {
	struct json_object *tmp;

	if (!get_by_path(jobj, path, &tmp))
		return def;

	if (json_object_get_type(tmp) != json_type_boolean)
		return def;

	return json_object_get_boolean(tmp);
}

