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
#include "json_path.h"

#define MAX_KEY_LEN 4096
#define USER_HT_SIZE 128
#define USER_HT_LOAD_FACTOR 0.085

static hashtable_t *user_ht = NULL;
static pthread_mutex_t user_ht_lock;

char * build_auth_key(char *cluster, char *tenant, char *authkey, char *buf, int max_len) {
	int len = strlen(cluster) + strlen(tenant) + strlen(authkey) + 3;
	if (len > max_len)
		return NULL;
	sprintf(buf, "%s\1%s\1%s", cluster, tenant, authkey);
	return buf;
}


int
user_init(User *user, char *cluster, char *tenant, char *juser) {
	char buf[MAX_KEY_LEN];
	const char *username;
	const char *authkey;
	if (!cluster || !tenant || !juser) {
		return EINVAL;
	}

	user->prop = json_tokener_parse(juser);
	if (user->prop == NULL) {
		return EINVAL;
	}

	if (!get_by_path_string(user->prop, "username", &username) ||
	    !get_by_path_string(user->prop, "authkey", &authkey)) {
		return EINVAL;
	}

	json_object_object_add(user->prop, "cluster", json_object_new_string(cluster));
	json_object_object_add(user->prop, "tenant", json_object_new_string(tenant));

	if (build_auth_key(cluster, tenant, (char *) authkey, buf, MAX_KEY_LEN) == NULL) {
		return EINVAL;
	}
	json_object_object_add(user->prop, "auth_hash", json_object_new_string(buf));

	user->created = get_timestamp_us() / 1000;
	return 0;
}

void
user_destroy(User *user) {
	if (user->prop) {
		json_object_put(user->prop);
		user->prop = NULL;
	}
}

const char *
user_to_string(User *user) {
	return json_object_to_json_string(user->prop);
}

int
user_age(User *user) {
	uint64_t age = (get_timestamp_us() / 1000 - user->created)/1000;
	return (int) age;
}


int
user_expired(User *user) {
	return (user_age(user) > USER_TTL);
}

const char *
user_property_string(User *user, char *name, const char *def) {
	if (!user)
		return def;
	return get_by_path_string_def(user->prop, name, def);
}

int
user_property_int(User *user, char *name, int def) {
	if (!user)
		return def;
	return get_by_path_int_def(user->prop, name, def);
}


/* User hash tables */
int
user_ht_create(void) {
	if (user_ht != NULL)
		return 0;

	int err = pthread_mutex_init(&user_ht_lock, NULL);

	if (err != 0)
		return err;

	user_ht = hashtable_create(USER_HT_SIZE, 0, USER_HT_LOAD_FACTOR);
	return 0;
}


int
user_ht_destroy(void) {
	if (user_ht == NULL)
		return 0;

	void **keys;
	char *key;
	size_t ent_size;
	unsigned int key_count;
	keys = hashtable_keys(user_ht, &key_count);

	for (unsigned int i = 0; i < key_count; i++) {
		key = (char *) keys[i];
		User *user = hashtable_get(user_ht, (void *)key, strlen(key) + 1, &ent_size);
		if (user != NULL && ent_size == sizeof(User)) {
			log_trace(lg, "Destroy user by key: %s", key);
			user_destroy(user);
		}
	}

	hashtable_destroy(user_ht);
	user_ht = NULL;
	pthread_mutex_destroy(&user_ht_lock);
	return 0;
}

int
user_put_ht(User *user)
{
	int err = 0;

	const char *auth_hash = user_property_string(user, "auth_hash", NULL);
	if (auth_hash == NULL) {
		return EINVAL;
	}

	log_trace(lg, "ht add user: %s", auth_hash);
	user_delete_ht(auth_hash);

	pthread_mutex_lock(&user_ht_lock);

	err = hashtable_put(user_ht, (void *)auth_hash, strlen(auth_hash) + 1,
	    user, sizeof(User));

	pthread_mutex_unlock(&user_ht_lock);
	return err;

}

int
user_get_by_hash(const char *hash, User **ent)
{
	size_t ent_size;
	pthread_mutex_lock(&user_ht_lock);
	*ent = hashtable_get(user_ht, (void *)hash, strlen(hash) + 1, &ent_size);
	pthread_mutex_unlock(&user_ht_lock);

	log_trace(lg,"ht get by user hash: %s, size: %d", hash, (int) ent_size);

	if (*ent != NULL && ent_size == sizeof(User))
		return 0;
	else
		return ENOENT;
}


void
user_delete_ht(const char *hash)
{
	pthread_mutex_lock(&user_ht_lock);
	size_t ent_size;
	char buf[MAX_KEY_LEN];
	User *user = hashtable_get(user_ht, (void *)hash, strlen(hash) + 1, &ent_size);

	if (user != NULL && ent_size == sizeof(User)) {
		strcpy(buf, hash);
		user_destroy(user);
		hashtable_remove(user_ht, (void *)buf, strlen(buf) + 1);
	}
	pthread_mutex_unlock(&user_ht_lock);
}

