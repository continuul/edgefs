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
#include "reptrans.h"
#include "sop_list.h"


// sop_list methods
sop_list_t *sop_list_init(uint512_t *nhid, struct repdev *dev) {
	sop_list_t *res = je_calloc(1, sizeof(sop_list_t));
	if (!res)
		return NULL;
	res->list_q = lfqueue_create(DEV_SOPS_QDEPTH);
	if (!res->list_q) {
		je_free(res);
		return NULL;
	}
	res->nhid = *nhid;
	res->dev = dev;
	res->running = 0;
	res->genid = 0;

	res->run_lock = je_malloc(sizeof(pthread_mutex_t));
	int err = pthread_mutex_init(res->run_lock, NULL);
	if (err != 0)
		return NULL;
	return res;
}

void sop_list_destroy(sop_list_t *sop_list) {
	if (!sop_list)
		return;
	if (sop_list->list_q)
		lfqueue_destroy(sop_list->list_q);
	if (sop_list->run_lock) {
		pthread_mutex_destroy(sop_list->run_lock);
		je_free(sop_list->run_lock);
	}
	je_free(sop_list);
}

// sop_list_ht methods
sop_list_ht *sop_list_ht_create(void) {
	sop_list_ht *res = je_malloc(sizeof(sop_list_ht));
	if (!res)
		return NULL;

	int err = pthread_mutex_init(&res->ht_lock, NULL);
	if (err != 0)
		return NULL;

	res->ht = hashtable_create(DEV_MAX_SOPS, HT_VALUE_CONST, 0.08);
	if (!res->ht) {
		je_free(res);
		return NULL;
	}
	return res;
}

void sop_list_ht_destroy(sop_list_ht *sop_ht) {
	if (!sop_ht)
		return;
	if (!sop_ht->ht)
		return;


	unsigned int key_count = 0;
	void **keys;
	sop_list_t *sop_list;
	size_t ent_size;
	keys = hashtable_keys(sop_ht->ht, &key_count);

	for (unsigned int i = 0; i < key_count; i++) {
		sop_list = hashtable_get(sop_ht->ht, keys[i], UINT512_BYTES, &ent_size);
		if (sop_list) {
			sop_list_destroy(sop_list);
		}
	}

	hashtable_destroy(sop_ht->ht);
	pthread_mutex_destroy(&sop_ht->ht_lock);
	if (keys)
		je_free(keys);
	je_free(sop_ht);
	return;

}

int sop_list_ht_put(sop_list_ht *sop_ht, sop_list_t *sop_list) {
	int err = 0;

	pthread_mutex_lock(&sop_ht->ht_lock);

	err = hashtable_put(sop_ht->ht, &sop_list->nhid, UINT512_BYTES,
			sop_list, sizeof(sop_list_t));

	pthread_mutex_unlock(&sop_ht->ht_lock);
	return err;
}

int sop_list_ht_get(sop_list_ht *sop_ht, uint512_t *nhid, sop_list_t **sop_list) {
	size_t ent_size;
	pthread_mutex_lock(&sop_ht->ht_lock);
	*sop_list = hashtable_get(sop_ht->ht, (void *)nhid, UINT512_BYTES, &ent_size);
	pthread_mutex_unlock(&sop_ht->ht_lock);

	if (*sop_list != NULL)
		return 0;
	else
		return -EINVAL;
}


void sop_list_delete_ht(sop_list_ht *sop_ht, uint512_t *nhid) {
	pthread_mutex_lock(&sop_ht->ht_lock);
	size_t ent_size;
	sop_list_t *sop_list;
	sop_list = hashtable_get(sop_ht->ht, (void *)nhid, UINT512_BYTES, &ent_size);
	if (sop_list && lfqueue_length(sop_list->list_q) == 0) {
		sop_list_destroy(sop_list);
		hashtable_remove(sop_ht->ht, (void *)nhid, UINT512_BYTES);
	}
	pthread_mutex_unlock(&sop_ht->ht_lock);
}
