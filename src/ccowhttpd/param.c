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
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>

#include "ccowutil.h"
#include "param.h"


#define HT_LOAD_FACTOR 0.085

int
param_init(h2o_mem_pool_t *pool, int capacity, int flags, param_vector *params)
{
	int ht_flags = 0;

	params->pool = pool;
	params->pairs = pool ? h2o_mem_alloc_pool(pool, param, capacity) :
		je_malloc(capacity * sizeof(param));
	if (params->pairs == NULL)
		return -ENOMEM;

	params->capacity = capacity;
	params->size = 0;
	if (flags & LOWERCASE_ON)
		flags |= ALLOCATE_ON;
	if (flags & ALLOCATE_ON)
		ht_flags = HT_KEY_CONST | HT_VALUE_CONST;
	params->flags = flags;
	params->ht = hashtable_create(capacity, ht_flags, HT_LOAD_FACTOR);

	return 0;
}

char *
param_str(param *p, char *buf, unsigned max) {
	if (!p) {
		buf[0] = '\0';
		return buf;
	}
	if ((p->key.len + p->val.len + 3) > max) {
		buf[0] = '\0';
		return buf;
	}
	char *c = buf;
	memcpy(buf, p->key.base, p->key.len);
	c += p->key.len;
	*c = ':';
	c++;
	*c = ' ';
	c++;
	if (p->val.base) {
		memcpy(c, p->val.base, p->val.len);
		c += p->val.len;
	}
	*c = '\0';
	return buf;
}

char *
param_key_str(param *p, char *buf, unsigned max) {
	if (p == NULL) {
		buf[0] = 0;
		return NULL;
	}
	if ((p->key.len + 1) > max) {
		buf[0] = 0;
		return NULL;
	}
	char *c = buf;
	memcpy(buf, p->key.base, p->key.len);
	c += p->key.len;
	*c = '\0';
	return buf;
}

char *
param_value_str(param *p, char *buf, unsigned max) {
	if (p == NULL) {
		buf[0] = 0;
		return NULL;
	}
	if ((p->val.len + 1) > max) {
		buf[0] = 0;
		return NULL;
	}
	char *c = buf;
	memcpy(buf, p->val.base, p->val.len);
	c += p->val.len;
	*c = '\0';
	return buf;
}


int
param_value_equal(param *p, char *val, int val_size) {
	if (!p)
		return 0;
	if (p->val.base == NULL) {
		return (val == NULL);
	}
	if ((int)p->val.len != val_size) {
		return 0;
	}
	if (strncmp(p->val.base, val, val_size) == 0) {
		return 1;
	}
	return 0;
}


int
param_add_param(param *p, param_vector *params) {
	if (!p)
		return -EINVAL;
	return param_add(p->key.base, p->key.len, p->val.base, p->val.len, params);
}


int
param_add(char *key, int key_size, char *val, int val_size, param_vector *params) {
	if (!key || key_size == 0)
		return -EINVAL;

	// Expand
	if (params->size == params->capacity) {
		params->capacity += params->capacity;
		log_trace(lg, "Realloc to capacity: %d", params->capacity);
		if (params->pool) {
			param *new_pairs = h2o_mem_alloc_pool(params->pool, param, params->capacity);
			memcpy(new_pairs, params->pairs, params->capacity / 2);
			params->pairs = new_pairs;
		} else
			params->pairs = je_realloc(params->pairs, params->capacity*sizeof(param));
		if (params->pairs == NULL)
			return -ENOMEM;
	}
	param *q = &params->pairs[params->size];
	if (params->flags & ALLOCATE_ON) {
		q->key.base = params->pool ? h2o_mem_alloc_pool(params->pool, char, key_size) : je_malloc(key_size);
		if (q->key.base == NULL)
			return -ENOMEM;
		memcpy(q->key.base, key, key_size);
		q->key.len = key_size;
	} else {
		q->key.base = key;
		q->key.len = key_size;
	}
	if (params->flags & LOWERCASE_ON) {
		char *ch = q->key.base;
		for (unsigned int i=0; i < q->key.len; i++)  {
			 *ch = tolower((int) *ch);
			 ch++;
		}
	}
	if (val) {
		if (params->flags & ALLOCATE_ON) {
			q->val.base = params->pool ? h2o_mem_alloc_pool(params->pool, char, val_size) : je_malloc(val_size);
			if (q->val.base == NULL)
				return -ENOMEM;
			memcpy(q->val.base, val, val_size);
			q->val.len = val_size;
		} else {
			q->val.base = val;
			q->val.len = val_size;
		}
	} else {
		q->val.base = NULL;
		q->val.len = 0;
	}
	int err = hashtable_put(params->ht, q->key.base,  q->key.len,
	   q, sizeof(param));
	if (err)
		return err;
	params->size++;
	return 0;
}

param *
param_find(char *key, int key_size, param_vector *params) {
	size_t ent_size;
	param *q;
	q = hashtable_get(params->ht, (void *)key, key_size, &ent_size);
	return q;
}

int
param_has(char *key, int key_size, param_vector *params) {
	size_t ent_size;
	void *q;
	q = hashtable_get(params->ht, (void *)key, key_size, &ent_size);
	return (q != NULL);
}

param *
param_find_value(char *key, int key_size, param_vector *params) {
	param *q;
	q = param_find(key, key_size, params);
	if (q == NULL)
		return NULL;
	if (q->val.base == NULL || q->val.len == 0)
		return NULL;
	return q;
}

long
param_find_long(char *key, int key_size, long def, param_vector *params) {
	param *p = param_find_value(key, key_size, params);
	if (!p)
		return def;
	char buf[256];
	memcpy(buf, p->val.base, p->val.len);
	buf[p->val.len] = '\0';
	long res = 0;
	int n = sscanf(buf, "%ld", &res);
	if (n < 1)
		return def;
	return res;
}

int64_t
param_find_int64(char *key, int key_size, int64_t def, param_vector *params) {
	param *p = param_find_value(key, key_size, params);
	if (!p)
		return def;
	char buf[256];
	memcpy(buf, p->val.base, p->val.len);
	buf[p->val.len] = '\0';
	int64_t res = 0;
	int n = sscanf(buf, "%ld", &res);
	if (n < 1)
		return def;
	return res;
}

uint64_t
param_find_uint64(char *key, int key_size, uint64_t def, param_vector *params) {
	param *p = param_find_value(key, key_size, params);
	if (!p)
		return def;
	char buf[256];
	memcpy(buf, p->val.base, p->val.len);
	buf[p->val.len] = '\0';
	uint64_t res = 0;
	int n = sscanf(buf, "%lu", &res);
	if (n < 1)
		return def;
	return res;
}


int
param_add_from(char *key, int key_size, char *def, int def_size, param_vector *source, param_vector *params) {
	param *p = param_find_value(key, key_size, source);
	if (p) {
        return param_add_param(p, params);
	} else {
		return param_add(key, key_size, def, def_size, params);
	}
}

int
param_add_from_as(char *key, int key_size, char *target_key, int target_key_size, char *def, int def_size,
		param_vector *source, param_vector *params) {
	param *p = param_find_value(key, key_size, source);
	if (p) {
		return param_add(target_key, target_key_size, p->val.base, p->val.len, params);
	} else {
		return param_add(target_key, target_key_size, def, def_size, params);
	}
}


int
param_count(param_vector *params) {
	return params->size;
}

param *
param_get(int i, param_vector *params) {
	param *q = &params->pairs[i];
	return q;
}


void
param_dump(char *header, param_vector *params) {
	if (!(lg->modules && log_module(lg, ___FILE___)) && LOG_LEVEL_DEBUG < lg->level)
		return;
	if (!params) {
		log_trace(lg, "%s: empty", header);
		return;
	}
	param *q;
	for (int i = 0; i < params->size; i++) {
		q = &params->pairs[i];
		char *key = je_strndup(q->key.base, q->key.len);
		if (q->val.base) {
			char *val = je_strndup(q->val.base, q->val.len);
			log_trace(lg, "%s: %s -> %s", header, key, val);
			je_free(val);
		} else {
			log_trace(lg, "%s: %s", header, key);
		}
		je_free(key);
	}
}

static int compare_params(const void * a, const void * b) {
   param *qa = (param *)a;
   param *qb = (param *)b;
   return strcmp(qa->key.base, qb->key.base);
}


void
param_sort(param_vector *params) {
	if (params != NULL && params->pairs != NULL) {
		qsort(params->pairs, (size_t) params->size, sizeof(param), compare_params);
	}
}

void
param_free(param_vector *params) {
	if (params != NULL && params->pairs != NULL) {
		hashtable_destroy(params->ht);
		params->ht = NULL;
		if (params->flags & ALLOCATE_ON) {
			param *q;
			for (int i = 0; i < params->size; i++) {
				q = &params->pairs[i];
				if (q->key.base && !params->pool)
					je_free(q->key.base);
				if (q->val.base && !params->pool)
					je_free(q->val.base);
			}
		}
		if (!params->pool)
			je_free(params->pairs);
		params->pairs = NULL;
	}
}
