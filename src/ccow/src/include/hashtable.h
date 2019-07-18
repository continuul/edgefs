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

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stdint.h>
#include <stddef.h>

/* The initial size of the hash table. */
#define HT_INITIAL_SIZE		256

#define HT_KEY_CONST		0x1
#define HT_VALUE_CONST		0x2

extern uint32_t		global_seed;

/* The hash_func type */
typedef void (hash_func)(const void *key, int len, uint32_t seed, void *out);

/*
 * The hash entry struct. Acts as a node in a linked list.
 */
 typedef struct hash_entry {
	void *key;		/* A pointer to the key. */
	void *value;		/* A pointer to the value. */
	size_t key_size;	/* The size of the key in bytes. */
	size_t value_size;	/* The size of the value in bytes. */

	/*
	 * A pointer to the next hash entry in the chain (or NULL if none).
	 * This is used for collision resolution.
	 */
	struct hash_entry *next;
} hash_entry;


typedef struct hashtable_t {
	hash_func *hashfunc_x86_32;	/* hash function for x86_32 */
	unsigned int key_count;		/* The number of keys in the htable. */
	unsigned int array_size;	/* The size of the internal array. */
	hash_entry **array;		/* The internal hash table array. */
	unsigned int collisions;	/* A count of the num of hash collis */
	int flags;			/* Key flags used */

	/* The max load factor that is acceptable before an autoresize is
	 * triggered, where load_factor is the ratio of collisions to
	 * table size. */
	double max_load_factor;
	double current_load_factor;	/* The current load factor. */

	void (* ht_destroy_entry)(void *);

} hashtable_t;

/*
 * Check of there are any members in the hashtable array
 * returns
 *	1	- true. the array is empty
 *	0	- false. the array is not empty
 *
 */
int hashtable_isempty(hashtable_t *table);


/*
 * Initializes the hashtable_t struct.
 *
 * @param initial_size initial size of bucket's array
 * @param flags Options for the way the table behaves.
 * @param max_load_factor The ratio of collisions:table_size before an
 *        autoresize is triggered for example: if max_load_factor = 0.1, the
 *        table will resize if the number of collisions increases beyond
 *        1/10th of the size of the table
 * @returns table A pointer to the hash table or NULL
 * @internal
 */
hashtable_t *hashtable_create(int initial_size, int flags,
    double max_load_factor);

/*
 * Destroys the hashtable_t struct and frees all relevant memory.
 *
 * @param table A pointer to the hash table.
 * @internal
 */
void hashtable_destroy(hashtable_t *table);

/*
 * Inserts the {key: value} pair into the hash table, makes copies of both key
 * and value.
 *
 * @param table A pointer to the hash table.
 * @param key A pointer to the key.
 * @param key_size The size of the key in bytes.
 * @param value A pointer to the value.
 * @param value_size The size of the value in bytes.
 * @returns 0 on success, negative value on error
 * @internal
 */
int hashtable_put(hashtable_t *table, void *key, size_t key_size,
    void *value, size_t value_size);

/*
 * Inserts an existing hash entry into the hash table.
 *
 * @param table A pointer to the hash table.
 * @param entry A pointer to the hash entry.
 * @returns 0 on success, negative value on error
 * @internal
 */
int hashtable_put_entry(hashtable_t *table, hash_entry *entry);

/*
 * Returns a pointer to the value with the matching key, value_size is set
 * to the size in bytes of the value
 *
 * @param table A pointer to the hash table.
 * @param key A pointer to the key.
 * @param key_size The size of the key in bytes.
 * @param value_size A pointer to a size_t where the size of the return
 *         value will be stored.
 * @returns A pointer to the requested value. If the return value
 *           is NULL, the requested key-value pair was not in the table.
 * @internal
 */
void *hashtable_get(hashtable_t *table, void *key, size_t key_size,
    size_t *value_size);

/*
 * Returns a pointer to the entry stored in the table with the matching key, value_size is set
 * to the size in bytes of the value
 *
 * @param table A pointer to the hash table.
 * @param key A pointer to the key.
 * @param key_size The size of the key in bytes.
 * @returns A pointer to the requested key. If the return value
 *           is NULL, the requested key was not in the table.
 */
hash_entry *hashtable_get_entry(hashtable_t *table, void *key, size_t key_size);

/*
 * Removes the entry corresponding to the specified key from the hash table.
 *
 * @param table A pointer to the hash table.
 * @param key A pointer to the key.
 * @param key_size The size of the key in bytes.
 * @internal
 */
void hashtable_remove(hashtable_t *table, void *key, size_t key_size);

/*
 * Used to see if the hash table contains a key-value pair.
 *
 * @param table A pointer to the hash table.
 * @param key A pointer to the key.
 * @param key_size The size of the key in bytes.
 * @returns 1 if the key is in the table, 0 otherwise
 * @internal
 */
int hashtable_contains(hashtable_t *table, void *key, size_t key_size);

/*
 * Returns the number of entries in the hash table.
 *
 * @param table A pointer to the table.
 * @returns The number of entries in the hash table.
 * @internal
 */
static inline unsigned int
hashtable_size(hashtable_t *table)
{
	return table->key_count;
}

/*
 * Returns an array of all the keys in the hash table.
 *
 * @param table A pointer to the hash table.
 * @param key_count A pointer to an unsigned int that
 *        will be set to the number of keys in the returned array.
 * @returns A pointer to an array of keys.
 * TODO: Add a key_lengths return value as well?
 * @intenal
 */
void **hashtable_keys(hashtable_t *table, unsigned int *key_count);

/* Calulates the index in the hash table's internal array
 *	from the given key, used for debugging currently.
 * @param table A pointer to the hash table.
 * @param key A pointer to the key.
 * @param key_size The size of the key in bytes.
 * @returns The index into the hash table's internal array.
 * @internal
 */
unsigned int hashtable_index(hashtable_t *table, void *key, size_t key_size);

/*
 * Resizes the hash table's internal array. This operation is _expensive_,
 * however it can make an overfull table run faster if the table is expanded.
 * The table can also be shrunk to reduce memory usage.
 *
 * @param table A pointer to the table.
 * @param new_size The desired size of the table.
 * @returns 0 on success, negative value on error
 * @internal
 */
int hashtable_resize(hashtable_t *table, unsigned int new_size);

/*
 * Sets the global security seed to be used in hash function.
 *
 * @param seed The seed to use.
 * @internal
 */
void hashtable_set_seed(uint32_t seed);

#endif
