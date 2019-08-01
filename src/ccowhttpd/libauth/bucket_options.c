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
#include <time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <json-c/json.h>
#include <jemalloc/jemalloc.h>

#include "ccow.h"
#include "ccowutil.h"
#include "bucket_options.h"
#include "json_path.h"

#define MAX_KEY_LEN 4096
#define MAX_OPTIONS_LEN 16384
#define BUCKET_OPTIONS_HT_SIZE 128
#define BUCKET_OPTIONS_HT_LOAD_FACTOR 0.085

static hashtable_t *bucket_options_ht = NULL;
static pthread_mutex_t bucket_options_ht_lock;

char *
build_bucket_options_key(char *cluster, char *tenant, char *bucket, char *buf, int max_len) {
	int len = strlen(cluster) + strlen(tenant) + strlen(bucket) + 4;
	if (len > max_len)
		return NULL;
	sprintf(buf, "%s@%s@%s", cluster, tenant, bucket);
	return buf;
}


int
bucket_options_init(BUCKET_OPTIONS *bucket_options, char *cluster, char *tenant, char *bucket, char *jbucket_options) {
	char buf[MAX_KEY_LEN];
	const char *owner;
	if (!cluster || !tenant || !bucket || !jbucket_options) {
		return EINVAL;
	}

	bucket_options->prop = json_tokener_parse(jbucket_options);
	if (bucket_options->prop == NULL) {
		return EINVAL;
	}

	if (build_bucket_options_key(cluster, tenant, bucket, buf, MAX_KEY_LEN) == NULL) {
		return EINVAL;
	}
	json_object_object_add(bucket_options->prop, "bucket_optionskey", json_object_new_string(buf));

	bucket_options->created = get_timestamp_us() / 1000;
	return 0;
}

void
bucket_options_destroy(BUCKET_OPTIONS *bucket_options) {
	if (bucket_options->prop) {
		json_object_put(bucket_options->prop);
		bucket_options->prop = NULL;
	}
}

const char *
bucket_options_to_string(BUCKET_OPTIONS *bucket_options) {
	return json_object_to_json_string(bucket_options->prop);
}

int
bucket_options_expired(BUCKET_OPTIONS *bucket_options) {
	uint64_t age = (get_timestamp_us() / 1000 - bucket_options->created)/1000;
	return (age > BUCKET_OPTIONS_TTL);
}

const char *
bucket_options_property_string(BUCKET_OPTIONS *bucket_options, char *name, const char *def) {
	return get_by_path_string_def(bucket_options->prop, name, def);
}


/* BUCKET_OPTIONS hash tables */
int
bucket_options_ht_create(void) {
	if (bucket_options_ht != NULL)
		return 0;

	int err = pthread_mutex_init(&bucket_options_ht_lock, NULL);

	if (err != 0)
		return err;

	bucket_options_ht = hashtable_create(BUCKET_OPTIONS_HT_SIZE, 0, BUCKET_OPTIONS_HT_LOAD_FACTOR);
	return 0;
}


int
bucket_options_ht_destroy(void) {
	if (bucket_options_ht == NULL)
		return 0;


	unsigned int key_count;
	void **keys;
	char *bucket_optionskey;
	BUCKET_OPTIONS *bucket_options;
	size_t ent_size;
	keys = hashtable_keys(bucket_options_ht, &key_count);

	for (unsigned int i = 0; i < key_count; i++) {
		bucket_optionskey = (char *) keys[i];
		bucket_options = hashtable_get(bucket_options_ht, (void *)bucket_optionskey, strlen(bucket_optionskey) + 1, &ent_size);
		if (bucket_options != NULL && ent_size == sizeof(BUCKET_OPTIONS)) {
			log_trace(lg, "Destroy BUCKET_OPTIONS by key: %s", bucket_optionskey);
			bucket_options_destroy(bucket_options);
		}
	}

	hashtable_destroy(bucket_options_ht);

	bucket_options_ht = NULL;
	pthread_mutex_destroy(&bucket_options_ht_lock);
	return 0;
}

int
bucket_options_put_ht(BUCKET_OPTIONS *bucket_options)
{
	int err = 0;
	const char *bucket_optionskey = bucket_options_property_string(bucket_options, "bucket_optionskey", NULL);
	if (bucket_optionskey == NULL) {
		return EINVAL;
	}

	log_trace(lg, "ht put bucket_options: %s", bucket_optionskey);

	bucket_options_delete_ht(bucket_optionskey);

	pthread_mutex_lock(&bucket_options_ht_lock);

	err = hashtable_put(bucket_options_ht, (void *)bucket_optionskey, strlen(bucket_optionskey) + 1,
	    bucket_options, sizeof(BUCKET_OPTIONS));

	pthread_mutex_unlock(&bucket_options_ht_lock);
	return err;

}

int
bucket_options_get_by_bucket_optionskey(const char *bucket_optionskey, BUCKET_OPTIONS **ent)
{
	size_t ent_size;
	pthread_mutex_lock(&bucket_options_ht_lock);
	*ent = hashtable_get(bucket_options_ht, (void *)bucket_optionskey, strlen(bucket_optionskey) + 1, &ent_size);
	pthread_mutex_unlock(&bucket_options_ht_lock);

	log_debug(lg, "ht get by bucket_optionskey: %s, size: %d", bucket_optionskey, (int) ent_size);

	if (*ent != NULL && ent_size == sizeof(BUCKET_OPTIONS))
		return 0;
	else
		return EINVAL;
}


void
bucket_options_delete_ht(const char *bucket_optionskey)
{
	pthread_mutex_lock(&bucket_options_ht_lock);
	char buf[MAX_KEY_LEN];
	size_t ent_size;
	BUCKET_OPTIONS *bucket_options = hashtable_get(bucket_options_ht, (void *)bucket_optionskey, strlen(bucket_optionskey) + 1, &ent_size);

	if (bucket_options != NULL && ent_size == sizeof(BUCKET_OPTIONS)) {
		strcpy(buf, bucket_optionskey);
		bucket_options_destroy(bucket_options);
		hashtable_remove(bucket_options_ht, (void *)buf, strlen(buf) + 1);
	}
	pthread_mutex_unlock(&bucket_options_ht_lock);
}

static int
get_bnhid(ccow_t tc, char *bid, int bid_size, uint512_t *bnhid) {
	int err = 0;

	ccow_completion_t c = NULL;

	// Get attributes
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "get bucket nhid attributes: %d", err);
		c = NULL;
		return err;
	}

	ccow_lookup_t iter = NULL;

	err = ccow_get(bid, bid_size, "", 1, c, NULL, 0, 0, &iter);
	if (err) {
		log_error(lg, "get bucket nhid: %d", err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_error(lg, "get bucket nhid: %d", err);
		if (iter)
			ccow_lookup_release(iter);
		ccow_release(c);
		return err;
	}

	int pos = 0, n = 0;
	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, pos++))) {
		if (strcmp(kv->key, RT_SYSKEY_NAME_HASH_ID) == 0) {
			memcpy(bnhid, kv->value, sizeof(uint512_t));
			n = 1;
			break;
		}
	}

	if (iter)
		ccow_lookup_release(iter);

	if (n == 0)
	  return -ENOENT;

	return 0;
}

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

int Base64Decode(char* b64message, char* buffer, int
 length) { //Decodes a base64 encoded string
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);
	if ((decodeLen+1) > length) {
		return -EINVAL;
	}
	buffer[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	BIO_read(bio, buffer, strlen(b64message));
	BIO_free_all(bio);

	return (0); //success
}

static int
get_options(ccow_t tc, char *bid, int bid_size, char *oid, int oid_size, char *res, int length) {
	int err = 0;

	ccow_completion_t c = NULL;

	// Empty options as default
	strcpy(res,"[]");

	// Get attributes
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "get bucket nhid attributes: %d", err);
		c = NULL;
		return err;
	}

	ccow_lookup_t iter = NULL;

	err = ccow_get(bid, bid_size, oid, oid_size, c, NULL, 0, 0, &iter);
	if (err) {
		log_error(lg, "get bucket options: %d", err);
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err) {
		log_error(lg, "get bucket options: %d", err);
		if (iter)
			ccow_lookup_release(iter);
		ccow_release(c);
		return err;
	}


	strcpy(res, "{");
	int len = 1;
	int pos = 0, n = 0;
	struct ccow_metadata_kv *kv = NULL;
	char option[MAX_KEY_LEN];
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_CUSTOM, pos++))) {
		if (strstr(kv->key, "life-") && kv->value_size < MAX_KEY_LEN) {
			strncpy(option, kv->value, kv->value_size);

			len += (n > 0 ? 4 : 3) + kv->key_size + calcDecodeLength(option);
			if (len >= length) {
				if (iter)
					ccow_lookup_release(iter);
				return -EINVAL;
			}

			if (n > 0) {
				strcat(res, ",");
			}
			strcat(res, "\"");
			strncat(res, kv->key, kv->key_size);
			strcat(res, "\":");

			err = Base64Decode(option, res + strlen(res), MAX_KEY_LEN);
			if (err) {
				log_error(lg, "get bucket options parse error: %d", err);
				break;
			}
			n++;
		}
	}
	len++;
	if (len >= length) {
		err = -EINVAL;
	}
	strcat(res, "}");

	if (iter)
		ccow_lookup_release(iter);
	return err;
}


int
get_bucket_options(ccow_t tc, char *cluster, char *tenant, char *bucket, BUCKET_OPTIONS **bucket_options) {
	char buf[MAX_KEY_LEN];
	char bucket_optionskey[MAX_KEY_LEN];

	if (build_bucket_options_key(cluster, tenant, bucket, bucket_optionskey, MAX_KEY_LEN) == NULL) {
		log_error(lg, "Error building bucket options key");
		return -EINVAL;
	}

	int res = bucket_options_get_by_bucket_optionskey(bucket_optionskey, bucket_options);
	if (res == 0 && !bucket_options_expired(*bucket_options)) {
		log_trace(lg," from cash: %s", bucket_options_to_string(*bucket_options));
		return 0;
	}

	uint512_t bnhid;

	res = get_bnhid(tc, bucket, strlen(bucket) + 1, &bnhid);
	if (res) {
		log_trace(lg,"Bucket %s, chid error: %d", bucket, res);
		return res;
	}

	char nhid[UINT512_BYTES * 2 + 1];
	uint512_dump(&bnhid, nhid, UINT512_BYTES * 2 + 1);
	log_trace(lg,"Bucket %s, chid: %s", bucket, nhid);

	char result[MAX_OPTIONS_LEN];
	res = get_options(tc, bucket, strlen(bucket) + 1, nhid, strlen(nhid) + 1,  result, MAX_OPTIONS_LEN);
	if (res) {
		log_error(lg,"Bucket %s, chid error: %d", bucket, res);
	}


	BUCKET_OPTIONS otmp;
	log_trace(lg,"BUCKET_OPTIONS from cluster: %s", result);
	if (result == NULL) {
		return -EINVAL;
	}
	res = bucket_options_init(&otmp, cluster, tenant, bucket, result);
	if (res != 0) {
	    log_trace(lg,"get_bucket_options parse for bucket %s error: %d", bucket, res);
		return res;
	}
	res = bucket_options_put_ht(&otmp);
	if (res != 0)
		return res;
	res = bucket_options_get_by_bucket_optionskey(bucket_optionskey, bucket_options);
	return res;
}


uint64_t
get_object_expiration(BUCKET_OPTIONS *bucket_options, char *oid) {
	struct json_object *obj, *arr, *exp, *tmp, *val;
	struct json_object_iterator it;
	struct json_object_iterator itEnd;
	const char *name, *value;

	if (!bucket_options || !oid || oid[0] == 0)
		return 0;

	it = json_object_iter_begin(bucket_options->prop);
	itEnd = json_object_iter_end(bucket_options->prop);

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

			log_debug(lg,"Object %s policy: %s value: %s", oid, name, value);

			if (get_by_path(val, "Status", &tmp)) {
				status = json_object_get_string(json_object_array_get_idx(tmp, 0));
				log_debug(lg,"Object %s status: %s", oid, status);
				if (!strstr(status, "Enabled")) {
					json_object_iter_next(&it);
					continue;
				}
			}
			if (get_by_path(val, "Prefix", &tmp)) {
				prefix = json_object_get_string(json_object_array_get_idx(tmp, 0));
				log_debug(lg,"Object %s prefix: %s", oid, prefix);
				if (prefix && prefix[0] != 0) {
					char *p = strstr(oid, prefix);
					if (!p || p != oid) {
						json_object_iter_next(&it);
						continue;
					}
				}
			}
			if (get_by_path(val, "Expiration", &exp)) {
				arr = json_object_array_get_idx(exp, 0);
				printf("Expiration: %s\n", json_object_get_string(tmp));
				if (get_by_path(arr, "Days", &tmp)) {
					expiration_days = json_object_get_string(json_object_array_get_idx(tmp, 0));
					log_debug(lg,"Object %s Expiration days: %s", oid, expiration_days);
					expiration = (int) time(NULL) + atoi(expiration_days)*24*3600;
				}
				if (get_by_path(arr, "Date", &tmp)) {
					expiration_date = json_object_get_string(json_object_array_get_idx(tmp, 0));
					log_debug(lg,"Object %s Expiration date: %s", oid, expiration_date);
					if (strptime(expiration_date, "%Y-%m-%dT%H:%M:%S", &tm)) {
						t = mktime(&tm);
						if (t > 0) {
							expiration = (int) t;
						}
					}
				}
			}
		}
		json_object_iter_next(&it);
	}

	log_trace(lg,"Object %s expiration: %d", oid, expiration);

	return (uint64_t) expiration;
}
