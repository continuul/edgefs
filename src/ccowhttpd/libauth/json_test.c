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
#include <time.h>
#include <json-c/json.h>

#include "json_path.h"

void
test_json()
{
	struct json_object *jobj, *obj, *arr, *tmp, *val;

	jobj = json_object_new_object();
	json_object_object_add(jobj, "enabled", json_object_new_boolean(1));

	arr = json_object_new_array();
	json_object_array_add(arr, json_object_new_string("one"));
	json_object_array_add(arr, json_object_new_string("two"));
	json_object_object_add(jobj, "depends", arr);

	obj = json_object_new_object();
	json_object_object_add(obj, "key1", json_object_new_int(1234));
	json_object_object_add(obj, "key2", json_object_new_string("abc"));
	json_object_object_add(obj, "key3", json_object_new_double(3.33));
	json_object_object_add(jobj, "obj", obj);

	printf ("\nThe json object: %s\n\n",json_object_to_json_string(jobj));


	const char *value;
	if (get_by_path_string(jobj, "obj/key2", &value)) {
		printf("jobj[obj/key2]: %s\n", value);
	}

	int ivalue;
	if (get_by_path_int(jobj, "obj/key1", &ivalue)) {
		printf("jobj[obj/key1]: %d\n", ivalue);
	}
	assert(get_by_path_int_def(jobj, "obj/key1", 0) == 1234);
	assert(get_by_path_int_def(jobj, "obj/key99", 111) == 111);

	int64_t ivalue64;
	if (get_by_path_int64(jobj, "obj/key1", &ivalue64)) {
		printf("jobj[obj/key1]: %ld\n", ivalue64);
	}

	double dvalue;
	if (get_by_path_double(jobj, "obj/key3", &dvalue)) {
		printf("jobj[obj/key3]: %f\n", dvalue);
	}

	int bvalue;
	if (get_by_path_boolean(jobj, "enabled", &bvalue)) {
		printf("jobj[enabled]: %d\n", bvalue);
	}

	struct json_object *jarr;
	if (get_by_path_array(jobj, "depends", &jarr)) {
		int len = json_object_array_length(jarr);
		printf("jobj[depends] len: %d\n", len);
		for (int i=0; i < len; i++) {
			tmp = json_object_array_get_idx(jarr, i);
			value = json_object_get_string(tmp);
			printf("jobj/depends[%d]: %s\n", i, value);
		}
	}

	if (get_by_path(jobj, "obj", &tmp)) {
		value = json_object_get_string(tmp);
		printf("jobj/obj: %s\n", value);
	}

	struct json_object_iterator it;
	struct json_object_iterator itEnd;

	it = json_object_iter_begin(tmp);
	itEnd = json_object_iter_end(tmp);

	while (!json_object_iter_equal(&it, &itEnd)) {
		val = json_object_iter_peek_value(&it);
		value = json_object_get_string(val);
		printf("%s -> %s\n", json_object_iter_peek_name(&it), value);
		json_object_iter_next(&it);
	}

	json_object_put(jobj);

	printf("\nDone1\n");
}

void
test_json1() {
	struct json_object *jobj, *obj, *arr, *exp, *tmp, *val;
	struct json_object_iterator it;
	struct json_object_iterator itEnd;
	const char *name, *value;

	char* json_str =
	 "{ \"life-1\": { \"Prefix\": [ \"\" ], \"Status\": [ \"Enabled\" ],"
		   "\"Expiration\": [ { \"Days\": [ \"10\" ] } ], \"ID\": 1 },"
	 "  \"life-2\": { \"Prefix\": [ \"folder/\" ], \"Status\": [ \"Enabled\" ],"
	      "\"Expiration\": [ { \"Date\": [ \"2019-07-31T00:00:00.000Z\" ] } ], \"ID\": 2 },"
	 "  \"bucket_optionskey\": \"cltest@test@bk1\" }";

	jobj = json_tokener_parse(json_str);

	printf ("\n\nThe json object1: %s\n\n",json_object_to_json_string(jobj));

	it = json_object_iter_begin(jobj);
	itEnd = json_object_iter_end(jobj);

	const char *status = NULL;
	const char *prefix = NULL;
	const char *expiration_days = NULL;
	const char *expiration_date = NULL;
	int expiration = 0;
	struct tm tm;
	time_t t;


	while (!json_object_iter_equal(&it, &itEnd)) {
		name = json_object_iter_peek_name(&it);
		if (strstr(name, "life-")) {
			val = json_object_iter_peek_value(&it);
			value = json_object_get_string(val);
			printf("%s -> %s\n", name, value);

			if (get_by_path(val, "Status", &tmp)) {
				status = json_object_get_string(json_object_array_get_idx(tmp, 0));
				printf("Status: %s\n", status);
				if (!strstr(status, "Enabled"))
					continue;
			}
			if (get_by_path(val, "Prefix", &tmp)) {
				prefix = json_object_get_string(json_object_array_get_idx(tmp, 0));
				printf("Prefix: %s\n", prefix);
			}
			if (get_by_path(val, "Expiration", &exp)) {
				arr = json_object_array_get_idx(exp, 0);
				printf("Expiration: %s\n", json_object_get_string(tmp));
				if (get_by_path(arr, "Days", &tmp)) {
					expiration_days = json_object_get_string(json_object_array_get_idx(tmp, 0));
					printf("Expiration days: %s\n", expiration_days);
					expiration = (int) time(NULL) + atoi(expiration_days)*24*3600;
					printf("Expiration: %d\n", expiration);
				}
				if (get_by_path(arr, "Date", &tmp)) {
					expiration_date = json_object_get_string(json_object_array_get_idx(tmp, 0));
					printf("Expiration date: %s\n", expiration_date);
					if (strptime(expiration_date, "%Y-%m-%dT%H:%M:%S", &tm)) {
						t = mktime(&tm);
						if (t > 0) {
							expiration = (int) t;
						}
						printf("Expiration: %d\n", expiration);

					}
				}
			}
		}
		json_object_iter_next(&it);
	}

	json_object_put(jobj);

	printf("\nDone2\n");
}


int
main()
{
	test_json();
	test_json1();
}
