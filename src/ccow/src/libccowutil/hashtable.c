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
#include <errno.h>
#include <string.h>

#include "ccowutil.h"
#include "logger.h"
#include "hashtable.h"


/* check if  the hashtable array is empty
 * returns
 *	1	- True. the array is empty
 *	0	- False. the array is not empty
 */
int
hashtable_isempty(hashtable_t *table)
{
	if (table->key_count > 0)
		return 0;
	else
		return 1;
}


hashtable_t *
hashtable_create(int initial_size, int flags, double max_load_factor)
{
	hashtable_t *table = je_malloc(sizeof (*table));
	if (!table) {
		log_error(lg, "hashtable_create failed to allocate memory");
		return NULL;
	}

	table->hashfunc_x86_32  = FNV_hash;
	table->array_size   = initial_size;
	table->array = je_malloc(table->array_size * sizeof (*(table->array)));
	if (!table->array) {
		je_free(table);
		log_error(lg, "hashtable_create failed to allocate memory");
		return NULL;
	}

	table->key_count = 0;
	table->collisions = 0;
	table->flags = flags;
	table->max_load_factor = max_load_factor;
	table->current_load_factor  = 0.0;

	unsigned int i;
	for (i = 0; i < table->array_size; i++) {
		table->array[i] = NULL;
	}

	table->ht_destroy_entry = NULL;

	return table;
}

/*
 * Destroys the hash entry and frees all associated memory.
 *
 * @param flags The hash table flags.
 * @param hash_entry A pointer to the hash entry.
 * @internal
 */
void
hashtable_entry_destroy(int flags, hash_entry *entry)
{
	if (!(flags & HT_KEY_CONST))
		je_free(entry->key);
	if (!(flags & HT_VALUE_CONST))
		je_free(entry->value);
	je_free(entry);
}

static void
hashtable_free(hashtable_t *table)
{
	unsigned int i;
	hash_entry *entry;
	hash_entry *tmp;

	assert(table->array);

	// crawl the entries and delete them
	for (i = 0; i < table->array_size; i++) {
		entry = table->array[i];

		while (entry != NULL) {
			tmp = entry->next;
			if (table->ht_destroy_entry != NULL) {
				table->ht_destroy_entry(entry);
			}
			hashtable_entry_destroy(table->flags, entry);
			entry = tmp;
		}
	}

	table->hashfunc_x86_32 = NULL;
	table->array_size = 0;
	table->key_count = 0;
	table->collisions = 0;
	je_free(table->array);
	table->array = NULL;
}

void
hashtable_destroy(hashtable_t *table)
{
	hashtable_free(table);
	je_free(table);
}

/*
 * Sets the value on an existing hash entry.
 *
 * @param flags The hashtable flags.
 * @param entry A pointer to the hash entry.
 * @param value A pointer to the new value.
 * @param value_size The size of the new value in bytes.
 * @internal
 */
static int
hashtable_set_entry(int flags, hash_entry *entry, void *value,
    size_t value_size)
{
	if (!(flags & HT_VALUE_CONST)) {
		if (entry->value)
			je_free(entry->value);

		entry->value = je_malloc(value_size);
		if (entry->value == NULL) {
			log_error(lg, "Failed to set entry value: "
			    "out of memory");
			return -ENOMEM;
		}
		memcpy(entry->value, value, value_size);
	} else {
		entry->value = value;
	}
	entry->value_size = value_size;

	return 0;
}


/*
 * Compare two hash entries.
 *
 * @param e1 A pointer to the first entry.
 * @param e2 A pointer to the second entry.
 * @returns 1 if both the keys and the values of e1 and e2 match, 0 otherwise.
 *          This is a "deep" compare, rather than just comparing pointers.
 * @internal
 */
static int
hashtable_key_compare(hash_entry *e1, hash_entry *e2)
{
	char *k1 = e1->key;
	char *k2 = e2->key;

	if (e1->key_size != e2->key_size)
		return 0;

	return (memcmp(k1, k2, e1->key_size) == 0);
}

int
hashtable_put_entry(hashtable_t *table, hash_entry *entry)
{
	hash_entry *tmp;
	unsigned int index;

	entry->next = NULL;
	index = hashtable_index(table, entry->key, entry->key_size);
	tmp = table->array[index];

	/* if true, no collision */
	if (tmp == NULL) {
		table->array[index] = entry;
		table->key_count++;
		return 0;
	}

	/* walk down the chain until we either hit the end
	 * or find an identical key, in which case we replace the value */
	while (tmp->next != NULL) {
		if (hashtable_key_compare(tmp, entry))
			break;
		else
			tmp = tmp->next;
	}

	if (hashtable_key_compare(tmp, entry)) {
		/* if the keys are identical, throw away the old entry
		 * and stick the new one into the table */
		int err = hashtable_set_entry(table->flags, tmp, entry->value,
		    entry->value_size);
		if (err)
			return err;

		if (table->ht_destroy_entry != NULL) {
			table->ht_destroy_entry(entry);
		}
		hashtable_entry_destroy(table->flags, entry);
	} else {
		/* else tack the new entry onto the end of the chain */
		tmp->next = entry;
		table->collisions += 1;
		table->key_count++;
		table->current_load_factor =
			(double)table->collisions / table->array_size;

		/*
		 * double the size of the table if autoresize is on and the
		 * load factor has gone too high
		 */
		if (table->current_load_factor > table->max_load_factor) {
			hashtable_resize(table, table->array_size * 2);
			table->current_load_factor =
				(double)table->collisions / table->array_size;
		}
	}

	return 0;
}

/*
 * Creates a new hash entry.
 *
 * @param flags Hash table flags.
 * @param key A pointer to the key.
 * @param key_size The size of the key in bytes.
 * @param value A pointer to the value.
 * @param value_size The size of the value in bytes.
 * @returns A pointer to the hash entry.
 * @internal
 */
hash_entry *
hashtable_entry_create(int flags, void *key, size_t key_size, void *value,
    size_t value_size)
{
	hash_entry *entry = je_malloc(sizeof (*entry));
	if (entry == NULL) {
		log_error(lg, "Failed to create hash_entry");
		return NULL;
	}

	entry->key_size = key_size;
	if (flags & HT_KEY_CONST) {
		entry->key = key;
	} else {
		entry->key = je_malloc(key_size);
		if (entry->key == NULL) {
			log_error(lg, "Failed to create hash_entry");
			je_free(entry);
			return NULL;
		}
		memcpy(entry->key, key, key_size);
	}

	entry->value_size = value_size;
	if (flags & HT_VALUE_CONST) {
		entry->value = value;
	} else {
		entry->value = je_malloc(value_size);
		if (entry->value == NULL) {
			log_error(lg, "Failed to create hash_entry");
			je_free(entry->key);
			je_free(entry);
			return NULL;
		}
		memcpy(entry->value, value, value_size);
	}

	entry->next = NULL;

	return entry;
}

int
hashtable_put(hashtable_t *table, void *key, size_t key_size, void *value,
    size_t value_size)
{
	hash_entry *entry = hashtable_entry_create(table->flags, key, key_size,
	    value, value_size);

	return hashtable_put_entry(table, entry);
}

void *
hashtable_get(hashtable_t *table, void *key, size_t key_size,
    size_t *value_size)
{
	unsigned int index = hashtable_index(table, key, key_size);
	hash_entry *entry = table->array[index];
	hash_entry tmp;
	tmp.key = key;
	tmp.key_size = key_size;

	/* once we have the right index, walk down the chain if any
	 * until we find the right key or hit the end */
	while (entry != NULL) {
		if (hashtable_key_compare(entry, &tmp)) {
			if (value_size != NULL)
				*value_size = entry->value_size;
			return entry->value;
		} else {
			entry = entry->next;
		}
	}

	return NULL;
}

hash_entry *
hashtable_get_entry(hashtable_t *table, void *key, size_t key_size)
{
	unsigned int index = hashtable_index(table, key, key_size);
	hash_entry *entry = table->array[index];
	hash_entry tmp;
	tmp.key = key;
	tmp.key_size = key_size;

	/* once we have the right index, walk down the chain if any
	 * until we find the right key or hit the end */
	while (entry != NULL) {
		if (hashtable_key_compare(entry, &tmp)) {
			return entry;
		} else {
			entry = entry->next;
		}
	}

	return NULL;
}

void
hashtable_remove(hashtable_t *table, void *key, size_t key_size)
{
	unsigned int index  = hashtable_index(table, key, key_size);
	hash_entry *entry = table->array[index];
	hash_entry *prev = NULL;
	hash_entry tmp;
	tmp.key = key;
	tmp.key_size = key_size;

	/* walk down the chain */
	while (entry != NULL) {
		/* if the key matches, take it out and connect its
		 * parent and child in its place */
		if (hashtable_key_compare(entry, &tmp)) {
			if (prev == NULL)
				table->array[index] = entry->next;
			else
				prev->next = entry->next;

			table->key_count--;

			if (prev != NULL)
				table->collisions--;

			if (table->ht_destroy_entry != NULL) {
				table->ht_destroy_entry(entry);
			}
			hashtable_entry_destroy(table->flags, entry);
			return;
		} else {
			prev = entry;
			entry = entry->next;
		}
	}
}

int
hashtable_contains(hashtable_t *table, void *key, size_t key_size)
{
	unsigned int index = hashtable_index(table, key, key_size);
	hash_entry *entry = table->array[index];
	hash_entry tmp;
	tmp.key = key;
	tmp.key_size = key_size;

	/* walk down the chain, compare keys */
	while (entry != NULL) {
		if (hashtable_key_compare(entry, &tmp)) {
			return 1;
		} else
			entry = entry->next;
	}

	return 0;
}

void**
hashtable_keys(hashtable_t *table, unsigned int *key_count)
{
	void **ret;

	if (table->key_count == 0) {
		*key_count = 0;
		return NULL;
	}

	/* array of pointers to keys */
	ret = je_malloc(table->key_count * sizeof (void *));
	if (ret == NULL) {
		log_error(lg, "hashtable_keys failed to allocate memory");
		return NULL;
	}
	*key_count = 0;

	unsigned int i;
	hash_entry *tmp;

	/* loop over all of the chains, walk the chains,
	 * add each entry to the array of keys */
	for (i = 0; i < table->array_size; i++) {
		tmp = table->array[i];

		while (tmp != NULL) {
			ret[*key_count] = tmp->key;
			*key_count += 1;
			tmp = tmp->next;
			/* sanity check, should never actually happen */
			if (*key_count > table->key_count) {
				log_warn(lg, "hashtable_keys: too many keys, "
				    "expected %d, got %d", table->key_count,
				    *key_count);
			}
		}
	}

	return ret;
}

unsigned int
hashtable_index(hashtable_t *table, void *key, size_t key_size)
{
	uint32_t index;

	/* 32 bits of murmur seems to fare pretty well */
	table->hashfunc_x86_32(key, key_size, global_seed, &index);
	index %= table->array_size;
	return index;
}

/* Notice: new_size can be smaller than current size (downsizing allowed) */
int
hashtable_resize(hashtable_t *table, unsigned int new_size)
{
	hashtable_t new_table;

	log_debug(lg, "hashtable_resize(old=%d, new=%d)", table->array_size,
	    new_size);

	new_table.hashfunc_x86_32 = table->hashfunc_x86_32;
	new_table.array_size = new_size;
	new_table.array = je_malloc(new_size * sizeof (hash_entry*));
	if (!new_table.array)
		return -ENOMEM;
	new_table.key_count = 0;
	new_table.collisions = 0;
	new_table.flags = table->flags;
	new_table.max_load_factor = table->max_load_factor;

	unsigned int i;
	for (i = 0; i < new_table.array_size; i++) {
		new_table.array[i] = NULL;
	}

	hash_entry *entry;
	hash_entry *next;
	for (i = 0; i < table->array_size; i++) {
		entry = table->array[i];
		while (entry != NULL) {
			next = entry->next;
			int err = hashtable_put_entry(&new_table, entry);
			if (err) {
				for (int j = i; j >= 0; --j) {
					entry = table->array[j];
					if (table->ht_destroy_entry != NULL) {
						table->ht_destroy_entry (entry);
					}
					hashtable_entry_destroy(table->flags,
					    entry);
				}
				return err;
			}
			entry = next;
		}
		table->array[i] = NULL;
	}

	hashtable_free(table);

	table->hashfunc_x86_32 = new_table.hashfunc_x86_32;
	table->array_size = new_table.array_size;
	table->array = new_table.array;
	table->key_count = new_table.key_count;
	table->collisions = new_table.collisions;

	return 0;
}

void
hashtable_set_seed(uint32_t seed)
{
	global_seed = seed;
}
