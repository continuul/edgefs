#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "ccowutil.h"
#include "fsio_system.h"

#include "fsio_listcache.h"

#define MAX_KEY_LEN 2048
#define MIN_CLEAN_KEY_COUNT 1024
#define FSIO_LIST_CACHE_HT_SIZE 32768
#define FSIO_LIST_CACHE_HT_LOAD_FACTOR 0.085

char *build_list_key(inode_t parent, inode_t child, char *buf) {
	sprintf(buf, "%lu_%lu", parent, child);
	return buf;
}

int
fsio_list_cache_entry_init(fsio_list_cache_entry_t *fsio_list_cache_entry, inode_t parent, inode_t child, char *name) {
	fsio_list_cache_entry->parent = parent;
	fsio_list_cache_entry->child = child;
	fsio_list_cache_entry->name = je_strndup(name, MAX_KEY_LEN);
	fsio_list_cache_entry->created = get_timestamp_us() / 1000;
	return 0;
}

void
fsio_list_cache_entry_destroy(fsio_list_cache_entry_t *fsio_list_cache_entry) {
	if (fsio_list_cache_entry->name) {
		je_free(fsio_list_cache_entry->name);
		fsio_list_cache_entry->name = NULL;
	}
}

int
fsio_list_cache_entry_age(fsio_list_cache_entry_t *fsio_list_cache_entry) {
	uint64_t age = (get_timestamp_us() / 1000 - fsio_list_cache_entry->created)/1000;
	return (int) age;
}


int
fsio_list_cache_entry_expired(fsio_list_cache_entry_t *fsio_list_cache_entry) {
	return (fsio_list_cache_entry_age(fsio_list_cache_entry) > FSIO_LIST_CACHE_TTL);
}


/* fsio_list_cache_entry_t hash tables */
int
fsio_list_cache_create(fsio_list_cache_t *fsio_list_cache) {
	if (fsio_list_cache->fsio_list_cache_entry_ht != NULL)
		return 0;

	int err = pthread_mutex_init(&fsio_list_cache->fsio_list_cache_entry_ht_lock, NULL);

	if (err != 0)
		return err;

	fsio_list_cache->fsio_list_cache_entry_ht = hashtable_create(FSIO_LIST_CACHE_HT_SIZE, 0, FSIO_LIST_CACHE_HT_LOAD_FACTOR);
	return 0;
}


int
fsio_list_cache_destroy(fsio_list_cache_t *fsio_list_cache) {
	if (fsio_list_cache == NULL)
		return 0;
	if (fsio_list_cache->fsio_list_cache_entry_ht == NULL)
		return 0;

	void **keys;
	char *key;
	size_t ent_size;
	unsigned int key_count;
	keys = hashtable_keys(fsio_list_cache->fsio_list_cache_entry_ht, &key_count);

	for (unsigned int i = 0; i < key_count; i++) {
		key = (char *) keys[i];
		fsio_list_cache_entry_t *fsio_list_cache_entry = hashtable_get(fsio_list_cache->fsio_list_cache_entry_ht,
			(void *)key, strlen(key) + 1, &ent_size);
		if (fsio_list_cache_entry != NULL && ent_size == sizeof(fsio_list_cache_entry_t)) {
			fsio_list_cache_entry_destroy(fsio_list_cache_entry);
		}
	}

	je_free(keys);

	hashtable_destroy(fsio_list_cache->fsio_list_cache_entry_ht);
	fsio_list_cache->fsio_list_cache_entry_ht = NULL;
	pthread_mutex_destroy(&fsio_list_cache->fsio_list_cache_entry_ht_lock);
	return 0;
}

int
fsio_list_cache_clean(fsio_list_cache_t *fsio_list_cache) {
	if (fsio_list_cache == NULL)
		return 0;
	if (fsio_list_cache->fsio_list_cache_entry_ht == NULL)
		return 0;

	void **keys;
	char *key;
	size_t ent_size;
	unsigned int key_count;
	unsigned int num = 0;

	pthread_mutex_lock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);

	if (fsio_list_cache->fsio_list_cache_entry_ht->key_count < MIN_CLEAN_KEY_COUNT) {
		log_trace(fsio_lg, "fsio_list_cache clean postponed on %u records",
			fsio_list_cache->fsio_list_cache_entry_ht->key_count);
		pthread_mutex_unlock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);
		return 0;
	}

	keys = hashtable_keys(fsio_list_cache->fsio_list_cache_entry_ht, &key_count);

	for (unsigned int i = 0; i < key_count; i++) {
		key = (char *) keys[i];

		fsio_list_cache_entry_t *fsio_list_cache_entry = hashtable_get(fsio_list_cache->fsio_list_cache_entry_ht,
			(void *)key, strlen(key) + 1, &ent_size);
		if (fsio_list_cache_entry != NULL && ent_size == sizeof(fsio_list_cache_entry_t)) {
			if (fsio_list_cache_entry_expired(fsio_list_cache_entry)) {
				fsio_list_cache_entry_destroy(fsio_list_cache_entry);
				num++;
				hashtable_remove(fsio_list_cache->fsio_list_cache_entry_ht, (void *)key, strlen(key) + 1);
			}
		}
	}

	je_free(keys);

	log_trace(fsio_lg, "fsio_list_cache cleaned %u records from %u", num, key_count);

	pthread_mutex_unlock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);

	return 0;
}


int
fsio_list_cache_put(fsio_list_cache_t *fsio_list_cache, fsio_list_cache_entry_t *fsio_list_cache_entry)
{
	int err = 0;

	char buf[128];
	char  *key = build_list_key(fsio_list_cache_entry->parent, fsio_list_cache_entry->child, buf);

	log_trace(fsio_lg, "ht add fsio_list_cache_entry: %s", key);

	pthread_mutex_lock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);

	// Delete old entry
	size_t ent_size;
	fsio_list_cache_entry_t *entry = hashtable_get(fsio_list_cache->fsio_list_cache_entry_ht,
		(void *)key, strlen(key) + 1, &ent_size);

	if (entry != NULL && ent_size == sizeof(fsio_list_cache_entry_t)) {
		fsio_list_cache_entry_destroy(entry);
		hashtable_remove(fsio_list_cache->fsio_list_cache_entry_ht, (void *)key, strlen(key) + 1);
	}

	err = hashtable_put(fsio_list_cache->fsio_list_cache_entry_ht, (void *)key, strlen(key) + 1,
	    fsio_list_cache_entry, sizeof(fsio_list_cache_entry_t));

	pthread_mutex_unlock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);
	return err;
}

int
fsio_list_cache_get(fsio_list_cache_t *fsio_list_cache, char *key, char *res, int res_max)
{
	size_t ent_size;
	pthread_mutex_lock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);

	fsio_list_cache_entry_t *ent = hashtable_get(fsio_list_cache->fsio_list_cache_entry_ht, (void *)key, strlen(key) + 1, &ent_size);

	log_trace(fsio_lg,"ht get by fsio_list_cache_entry key: %s, size: %d", key, (int) ent_size);

	if (ent != NULL && ent_size == sizeof(fsio_list_cache_entry_t)) {
		if (fsio_list_cache_entry_expired(ent)) {
			pthread_mutex_unlock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);
			fsio_list_cache_delete(fsio_list_cache, key);
			return ENOENT;
		}
		strncpy(res, ent->name, res_max);
		pthread_mutex_unlock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);
		return 0;
	} else {
		pthread_mutex_unlock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);
		return ENOENT;
	}
}


void
fsio_list_cache_delete(fsio_list_cache_t *fsio_list_cache, char *key)
{
	pthread_mutex_lock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);
	size_t ent_size;
	fsio_list_cache_entry_t *fsio_list_cache_entry = hashtable_get(fsio_list_cache->fsio_list_cache_entry_ht, (void *)key, strlen(key) + 1, &ent_size);

	if (fsio_list_cache_entry != NULL && ent_size == sizeof(fsio_list_cache_entry_t)) {
		fsio_list_cache_entry_destroy(fsio_list_cache_entry);
		hashtable_remove(fsio_list_cache->fsio_list_cache_entry_ht, (void *)key, strlen(key) + 1);
	}
	pthread_mutex_unlock(&fsio_list_cache->fsio_list_cache_entry_ht_lock);
}
