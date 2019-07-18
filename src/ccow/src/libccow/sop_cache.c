/*
 * Use is subject of licensing terms
 * Nexenta Systems, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include "ccowutil.h"
#include "hashtable.h"
#include "skiplist.h"
#include "sop_cache.h"

// Key compare method
static int
keycmp(const void *ka, const size_t ka_len, const void *kb, const size_t kb_len)
{
	int diff;
	ssize_t len_diff;
	unsigned int len;

	len = ka_len;
	len_diff = (ssize_t) ka_len - (ssize_t) kb_len;
	if (len_diff > 0) {
		len = kb_len;
		len_diff = 1;
	}

	diff = memcmp(ka, kb, len);
	return diff ? diff : len_diff<0 ? -1 : len_diff;
}

// sop_rec methods
sop_rec_t *
sop_rec_init(char *key, size_t key_size, void *value, size_t value_size,
    int64_t delta_size,	int64_t delta_objs, int64_t delta_used,
	int index, int optype, uint64_t genid)
{
	sop_rec_t *res = je_calloc(1, sizeof(sop_rec_t));
	if (!res)
		return NULL;
	res->key = (char *) je_malloc(key_size);
	if (!res->key) {
		je_free(res);
		return NULL;
	}
	memcpy(res->key, key, key_size);
	res->key_size = key_size;
	res->value_size = value_size;
	if (value && value_size > 0) {
		res->value = (char *) je_malloc(value_size);
		if (!res->value) {
			je_free(res->key);
			je_free(res);
			return NULL;
		}
		memcpy(res->value, value, value_size);
	} else {
		res->value = NULL;
	}
	res->delta_size = delta_size;
	res->delta_objs = delta_objs;
	res->delta_used = delta_used;
	res->optype = optype;
	res->genid = genid;
	res->index = index;
	res->insert_time = get_timestamp_us();
	return res;
}

void
sop_rec_destroy(sop_rec_t *sop_rec)
{
	if (!sop_rec)
		return;
	if (sop_rec->key)
		je_free(sop_rec->key);
	if (sop_rec->value)
		je_free(sop_rec->value);
	je_free(sop_rec);
}

// sop_rec_table methods
sop_rec_table *
sop_rec_table_create(int shard_count, const char *bid, char *shard_name)
{
	sop_rec_table *res = je_malloc(sizeof(sop_rec_table));
	if (!res)
		return NULL;

	int err = pthread_mutex_init(&res->ht_lock, NULL);
	if (err != 0)
		return NULL;

	res->ht = hashtable_create(DEFAULT_CACHE_SIZE, HT_VALUE_CONST, 0.08);
	if (!res->ht) {
		je_free(res);
		return NULL;
	}
	res->sl = msl_create(keycmp);

	res->genid = je_calloc(shard_count, sizeof(uint64_t));
	res->shard_count = shard_count;
	res->busy_count = 0;
	res->size = 0;
	res->objs = 0;
	res->used = 0;
	res->bid = je_strdup(bid);
	res->shard_name = je_strdup(shard_name);
	res->insert_time_last = 0;

	return res;
}

void
sop_rec_table_destroy(sop_rec_table *sop_tb)
{
	if (!sop_tb)
		return;
	if (!sop_tb->ht)
		return;


	unsigned int key_count = 0;
	void **keys = NULL;
	char *ckey;
	sop_rec_t *sop_rec;
	size_t ent_size;
	keys = hashtable_keys(sop_tb->ht, &key_count);

	for (unsigned int i = 0; i < key_count; i++) {
		ckey = (char *) keys[i];
		sop_rec = hashtable_get(sop_tb->ht, keys[i], strlen(ckey) + 1, &ent_size);
		if (sop_rec) {
			sop_rec_destroy(sop_rec);
		}
	}

	if (sop_tb->genid)
		je_free(sop_tb->genid);
	if (sop_tb->bid)
		je_free(sop_tb->bid);
	if (sop_tb->shard_name)
		je_free(sop_tb->shard_name);
	hashtable_destroy(sop_tb->ht);
	msl_destroy(sop_tb->sl);
	pthread_mutex_destroy(&sop_tb->ht_lock);
	if (keys)
		je_free(keys);
	je_free(sop_tb);
	return;

}

int
sop_rec_table_put(sop_rec_table *sop_tb, sop_rec_t *sop_rec)
{
	int err = 0;

	if (!sop_rec)
		return -EINVAL;

	pthread_mutex_lock(&sop_tb->ht_lock);

	if (sop_rec->genid > sop_tb->genid[sop_rec->index]) {
		sop_tb->genid[sop_rec->index] = sop_rec->genid;
	}

	if (sop_rec->insert_time > sop_tb->insert_time_last) {
		sop_tb->insert_time_last = sop_rec->insert_time;
	}

	sop_tb->size += sop_rec->delta_size;
	sop_tb->objs += sop_rec->delta_objs;
	sop_tb->used += sop_rec->delta_used;

	// Don't insert attributes only updates
	if (sop_rec->optype != SOP_CACHE_MD) {
		size_t ent_size;
		sop_rec_t *prev_rec = hashtable_get(sop_tb->ht, sop_rec->key,
		    sop_rec->key_size, &ent_size);

		err = hashtable_put(sop_tb->ht, sop_rec->key, sop_rec->key_size,
		    sop_rec, sizeof(sop_rec_t));

		if (!err) {
			hash_entry *entry = hashtable_get_entry(sop_tb->ht, sop_rec->key, sop_rec->key_size);
			if (entry) {
				err = msl_set(sop_tb->sl, entry->key, entry->key_size,
						entry->value, entry->value_size, NULL);
			}
			if (prev_rec)
				sop_rec_destroy(prev_rec);
		}
	}

	pthread_mutex_unlock(&sop_tb->ht_lock);
	return err;
}

int
sop_rec_table_get(sop_rec_table *sop_tb, char *key, size_t key_size,
    sop_rec_t **sop_rec_out)
{
	size_t ent_size;
	pthread_mutex_lock(&sop_tb->ht_lock);
	*sop_rec_out = hashtable_get(sop_tb->ht, (void *)key, key_size, &ent_size);
	pthread_mutex_unlock(&sop_tb->ht_lock);

	if (*sop_rec_out != NULL)
		return 0;
	else
		return -ENOENT;
}


void
sop_rec_table_delete(sop_rec_table *sop_tb,  char *key, size_t key_size)
{
	pthread_mutex_lock(&sop_tb->ht_lock);
	size_t ent_size;
	sop_rec_t *sop_rec;
	sop_rec = hashtable_get(sop_tb->ht, (void *)key, key_size, &ent_size);
	if (sop_rec) {
		sop_rec_destroy(sop_rec);
		hashtable_remove(sop_tb->ht, (void *)key, key_size);
	}
	pthread_mutex_unlock(&sop_tb->ht_lock);
}


// sop_shard_table methods
sop_shard_table *
sop_shard_table_create(void)
{
	sop_shard_table *res = je_malloc(sizeof(sop_shard_table));
	if (!res)
		return NULL;

	int err = pthread_mutex_init(&res->ht_lock, NULL);
	if (err != 0)
		return NULL;

	res->ht = hashtable_create(DEFAULT_CACHE_COUNT, HT_VALUE_CONST, 0.08);
	if (!res->ht) {
		je_free(res);
		return NULL;
	}

	return res;
}

void
sop_shard_table_destroy(sop_shard_table *sop_sh)
{
	if (!sop_sh)
		return;
	if (!sop_sh->ht)
		return;


	unsigned int key_count = 0;
	void **keys = NULL;
	char *ckey;
	sop_rec_table *sop_rec_tb;
	size_t ent_size;
	keys = hashtable_keys(sop_sh->ht, &key_count);

	for (unsigned int i = 0; i < key_count; i++) {
		ckey = (char *) keys[i];
		sop_rec_tb = hashtable_get(sop_sh->ht, keys[i], strlen(ckey) + 1, &ent_size);
		if (sop_rec_tb) {
			sop_rec_table_destroy(sop_rec_tb);
		}
	}

	hashtable_destroy(sop_sh->ht);
	pthread_mutex_destroy(&sop_sh->ht_lock);
	if (keys)
		je_free(keys);
	je_free(sop_sh);
	return;

}

int
sop_shard_table_put(sop_shard_table *sop_sh, char *path, size_t path_size, sop_rec_table *sop_rec_tb)
{
	int err = 0;

	if (!sop_rec_tb)
		return -EINVAL;

	pthread_mutex_lock(&sop_sh->ht_lock);

	err = hashtable_put(sop_sh->ht, (void *)path, path_size,
			sop_rec_tb, sizeof(sop_rec_table));

	pthread_mutex_unlock(&sop_sh->ht_lock);
	return err;
}

int
sop_shard_table_get(sop_shard_table *sop_sh, char *path, size_t path_size, sop_rec_table **sop_rec_tb)
{
	size_t ent_size;
	if (!sop_sh) {
		return -ENOENT;
	}

	pthread_mutex_lock(&sop_sh->ht_lock);
	*sop_rec_tb = hashtable_get(sop_sh->ht, (void *)path, path_size, &ent_size);

	int err = 0;
	if (*sop_rec_tb != NULL) {
		(*sop_rec_tb)->busy_count++;
	} else {
		err = -ENOENT;
	}
	pthread_mutex_unlock(&sop_sh->ht_lock);
	return err;
}

void
sop_shard_table_detach(sop_shard_table *sop_sh, sop_rec_table *sop_rec_tb)
{
	if (!sop_rec_tb) {
		return;
	}
	pthread_mutex_lock(&sop_sh->ht_lock);
	sop_rec_tb->busy_count--;
	pthread_mutex_unlock(&sop_sh->ht_lock);
}

int
sop_shard_table_init(sop_shard_table *sop_sh, int shard_count, char *path,
    size_t path_size, const char *bid, char *shard_name,
	sop_rec_table *new_rec_tb, sop_rec_table **sop_rec_tb_out)
{
	size_t ent_size;

	if (!new_rec_tb) {
		return -ENOMEM;
	}

	pthread_mutex_lock(&sop_sh->ht_lock);

	sop_rec_table *sop_rec_tb = hashtable_get(sop_sh->ht, (void *)path,
	    path_size, &ent_size);
	if (sop_rec_tb) {
		sop_rec_table_destroy(new_rec_tb);
		*sop_rec_tb_out = sop_rec_tb;
		pthread_mutex_unlock(&sop_sh->ht_lock);
		return -EEXIST;
	}


	int err = hashtable_put(sop_sh->ht, (void *)path, path_size,
			new_rec_tb, sizeof(sop_rec_table));

	if (err) {
		sop_rec_table_destroy(new_rec_tb);
		pthread_mutex_unlock(&sop_sh->ht_lock);
		return -ENOMEM;
	}

	new_rec_tb->busy_count++;
	*sop_rec_tb_out = new_rec_tb;
	pthread_mutex_unlock(&sop_sh->ht_lock);

	return err;
}

int
sop_shard_table_delete(sop_shard_table *sop_sh, char *path, size_t path_size)
{
	int err = 0;
	if (!sop_sh) {
		return 0;
	}
	pthread_mutex_lock(&sop_sh->ht_lock);
	size_t ent_size;
	sop_rec_table *sop_rec_tb;
	sop_rec_tb = hashtable_get(sop_sh->ht, (void *)path, path_size, &ent_size);
	if (sop_rec_tb) {
		if (sop_rec_tb->busy_count == 0) {
			sop_rec_table_destroy(sop_rec_tb);
			hashtable_remove(sop_sh->ht, (void *)path, path_size);
		} else { // busy
			err = -EBUSY;
		}
	}
	pthread_mutex_unlock(&sop_sh->ht_lock);
	return err;
}
