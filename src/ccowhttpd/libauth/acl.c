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
#include "acl.h"
#include "json_path.h"

#define MAX_KEY_LEN 4096
#define ACL_HT_SIZE 128
#define ACL_HT_LOAD_FACTOR 0.085

static hashtable_t *acl_ht = NULL;
static pthread_mutex_t acl_ht_lock;

char *
build_acl_key(char *cluster, char *tenant, char *bucket, char *oid, char *buf, int max_len) {
	int len = strlen(cluster) + strlen(tenant) + strlen(bucket) + 4;
	if (len > max_len)
		return NULL;
	sprintf(buf, "%s\1%s\1%s\1%s", cluster, tenant, bucket, oid);
	return buf;
}


int
acl_init(ACL *acl, char *cluster, char *tenant, char *bucket, char *oid, char *jacl) {
	char buf[MAX_KEY_LEN];
	const char *owner;
	if (!cluster || !tenant || !bucket || !oid || !jacl) {
		return EINVAL;
	}

	acl->prop = json_tokener_parse(jacl);
	if (acl->prop == NULL) {
		return EINVAL;
	}

	if (build_acl_key(cluster, tenant, bucket, oid, buf, MAX_KEY_LEN) == NULL) {
		return EINVAL;
	}
	json_object_object_add(acl->prop, "aclkey", json_object_new_string(buf));

	if (!get_by_path_string(acl->prop, "owner", &owner)) {
		sprintf(buf, "%s/%s", cluster, tenant);
		json_object_object_add(acl->prop, "owner", json_object_new_string(buf));
	}

	acl->created = get_timestamp_us() / 1000;
	return 0;
}

void
acl_destroy(ACL *acl) {
	if (acl->prop) {
		json_object_put(acl->prop);
		acl->prop = NULL;
	}
}

const char *
acl_to_string(ACL *acl) {
	return json_object_to_json_string(acl->prop);
}

int
acl_expired(ACL *acl) {
	uint64_t age = (get_timestamp_us() / 1000 - acl->created)/1000;
	return (age > ACL_TTL);
}

const char *
acl_property_string(ACL *acl, char *name, const char *def) {
	return get_by_path_string_def(acl->prop, name, def);
}


/* ACL hash tables */
int
acl_ht_create(void) {
	if (acl_ht != NULL)
		return 0;

	int err = pthread_mutex_init(&acl_ht_lock, NULL);

	if (err != 0)
		return err;

	acl_ht = hashtable_create(ACL_HT_SIZE, 0, ACL_HT_LOAD_FACTOR);
	return 0;
}


int
acl_ht_destroy(void) {
	if (acl_ht == NULL)
		return 0;


	unsigned int key_count;
	void **keys;
	char *aclkey;
	ACL *acl;
	size_t ent_size;
	keys = hashtable_keys(acl_ht, &key_count);

	for (unsigned int i = 0; i < key_count; i++) {
		aclkey = (char *) keys[i];
		acl = hashtable_get(acl_ht, (void *)aclkey, strlen(aclkey) + 1, &ent_size);
		if (acl != NULL && ent_size == sizeof(ACL)) {
			log_trace(lg, "Destroy ACL by key: %s", aclkey);
			acl_destroy(acl);
		}
	}

	hashtable_destroy(acl_ht);

	acl_ht = NULL;
	pthread_mutex_destroy(&acl_ht_lock);
	return 0;
}

int
acl_put_ht(ACL *acl)
{
	int err = 0;
	const char *aclkey = acl_property_string(acl, "aclkey", NULL);
	if (aclkey == NULL) {
		return EINVAL;
	}

	log_trace(lg, "ht put acl: %s", aclkey);
	acl_delete_ht(aclkey);

	pthread_mutex_lock(&acl_ht_lock);

	err = hashtable_put(acl_ht, (void *)aclkey, strlen(aclkey) + 1,
	    acl, sizeof(ACL));

	pthread_mutex_unlock(&acl_ht_lock);
	return err;

}

int
acl_get_by_aclkey(const char *aclkey, ACL **ent)
{
	size_t ent_size;
	pthread_mutex_lock(&acl_ht_lock);
	*ent = hashtable_get(acl_ht, (void *)aclkey, strlen(aclkey) + 1, &ent_size);
	pthread_mutex_unlock(&acl_ht_lock);

	log_debug(lg, "ht get by aclkey: %s, size: %d", aclkey, (int) ent_size);

	if (*ent != NULL && ent_size == sizeof(ACL))
		return 0;
	else
		return EINVAL;
}


void
acl_delete_ht(const char *aclkey)
{
	pthread_mutex_lock(&acl_ht_lock);
	char buf[MAX_KEY_LEN];
	size_t ent_size;
	ACL *acl = hashtable_get(acl_ht, (void *)aclkey, strlen(aclkey) + 1, &ent_size);

	if (acl != NULL && ent_size == sizeof(ACL)) {
		strcpy(buf, aclkey);
		acl_destroy(acl);
		hashtable_remove(acl_ht, (void *)buf, strlen(buf) + 1);
	}
	pthread_mutex_unlock(&acl_ht_lock);
}

