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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <json-c/json.h>
#include <jemalloc/jemalloc.h>

#include "ccowutil.h"
#include "user.h"
#include "acl.h"
#include "json_path.h"


#define MAX_KEY_LEN 4096

int
auth_init() {
	user_ht_create();
	acl_ht_create();

	return 0;
}

void
auth_destroy() {
	acl_ht_destroy();
	user_ht_destroy();
}

int
get_user_by_authkey(char *cluster, char *tenant, char *authkey, User **user)
{
#if 0
	char buf[MAX_KEY_LEN];
	char hash[MAX_KEY_LEN];
	if (build_auth_key(cluster, tenant, (char *) authkey, hash, MAX_KEY_LEN) == NULL) {
		return EINVAL;
	}

	int res = user_get_by_hash(hash, user);
	if (res == 0 && !user_expired(*user)) {
		log_trace(lg,"get_user_by_authkey from cash: %s", user_to_string(*user));
		return res;
	}

	User utmp;
	char *result = NULL;
	struct json_object *jresult = NULL, *jobj, *obj, *tmp;

	// FIXME: Call worker

	if (res == 0) {
		log_trace(lg,"from worker: %s", result);
		if (result == NULL) {
			return EINVAL;
		}
		res = user_init(&utmp, cluster, tenant, result);
		if (res != 0)
			return res;
		res = user_put_ht(&utmp);
		if (res != 0)
			return res;
		res = user_get_by_hash(hash, user);
	} else {
		if (err != NULL) {
			log_trace(lg, "Error code: %s\n", (err->code != NULL ? err->code : ""));
			if (err->code != NULL) {
				if (strcmp(err->code, "ENOENT") == 0) {
					res = ENOENT;
				}
			}
			je_free(err);
		}
	}
	return res;
#else
	return EINVAL;
#endif
}

static int
get_acl(char *cluster, char *tenant, char *bucket, char *oid, ACL **acl)
{
#if 0
	char buf[MAX_KEY_LEN];
	char aclkey[MAX_KEY_LEN];

	if (build_acl_key(cluster, tenant, bucket, (oid == NULL ? "" : oid), aclkey, MAX_KEY_LEN) == NULL) {
		log_error(lg, "Error building key");
		return -EINVAL;
	}

	int res = acl_get_by_aclkey(aclkey, acl);
	if (res == 0 && !acl_expired(*acl)) {
		log_trace(lg," from hash: %s", acl_to_string(*acl));
		return 0;
	}

	ACL atmp;
	char *result = NULL;
	nef_worker_handle_t service_hdl;
	nef_call_error_t *err;
	struct json_object *jresult = NULL, *jobj, *obj, *tmp;

	// FIXME: Call worker

	if (res == 0) {
		log_trace(lg,"from worker: %s", result);
		if (result == NULL) {
			return -EINVAL;
		}
		res = acl_init(&atmp, cluster, tenant, bucket, oid, result);
		if (res != 0)
			return res;
		res = acl_put_ht(&atmp);
		if (res != 0)
			return res;
		res = acl_get_by_aclkey(aclkey, acl);
	} else {
		if (err != NULL) {
			log_trace(lg, "Error code: %s\n", (err->code != NULL ? err->code : ""));
			if (err->code != NULL) {
				if (strcmp(err->code, "ENOENT") == 0) {
					res = -ENOENT;
				}
			}
			je_free(err);
		}
	}
	return res;
#else
	return EINVAL;
#endif
}

int
get_access(char *cluster, char *tenant, char *bucket, char *oid, char *operation, User *user, ACL **acl) {
	int err = get_acl(cluster, tenant, bucket, oid, acl);

	if (err && err != -ENOENT) {
		log_trace(lg,"get_acl error: %d", err);
		return err;
	}

	int admin = user_property_int(user, "admin", 0);
	const char *username = user_property_string(user, "username", NULL);

	log_trace(lg,"user: %s, admin: %d, cluster: %s, tenent: %s, bucket: %s, oid: %s, get_acl: %d",
	    username, admin, cluster, tenant, bucket, oid, err);


	int f = 0;
	int r = 0;
	int w = 0;
	int a = 0;
	int b = 0;

	int i;
	struct json_object *acls, *tmp;
	const char *acluser;
	const char *sacls;
	if (err == 0 && get_by_path_array((*acl)->prop, "acls", &acls)) {
		int len = json_object_array_length(acls);
		for (i=0; i < len; i++) {
			tmp = json_object_array_get_idx(acls, i);
			if (get_by_path_string(tmp, "user", &acluser) &&
			    get_by_path_string(tmp, "acls", &sacls)) {
				if (strcmp(acluser, "*") == 0 ||
				    strcmp(acluser, username) == 0 ||
				    (strcmp(acluser, ":") == 0 && username != NULL)) {
					if (strchr(sacls, 'f'))
						f = 1;
					if (strchr(sacls, 'r'))
						r = 1;
					if (strchr(sacls, 'w'))
						w = 1;
					if (strchr(sacls, 'a'))
						a = 1;
					if (strchr(sacls, 'b'))
						b = 1;
				}
			}
		}
	}
	log_trace(lg, " f: %d, r: %d, w: %d, a: %d, b: %d", f, r, w, a, b);

	if (strcmp(operation, "bucket_create") == 0) {
		if (admin) {
			return 0;
		}
	} else if (strcmp(operation, "bucket_list") == 0) {
		return 0;
	} else if (strcmp(operation, "read") == 0) {
		if (admin || f || r) {
			return 0;
		}
	} else if (strcmp(operation, "write") == 0) {
		if (admin || f || w) {
			return 0;
		}
	} else if (strcmp(operation, "read_acp") == 0 ) {
		if (admin || f || a) {
			return 0;
		}
	} else if (strcmp(operation, "write_acp") == 0 ) {
		if (admin || f || b) {
			return 0;
		}
	} else {
		return -EINVAL;
	}

	return -EPERM;
}
