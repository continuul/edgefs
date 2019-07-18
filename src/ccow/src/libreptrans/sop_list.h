/*
 * Use is subject of licensing terms
 * Nexenta Systems, Inc.
 */
#ifndef __SOP_LIST_H__
#define __SOP_LIST_H__

typedef struct sop_list {
	uint512_t nhid;
	uint64_t genid;
	struct repdev *dev;
	pthread_mutex_t *run_lock;
	lfqueue_t list_q;
	volatile int running;
} sop_list_t;

typedef struct sop_list_ht {
	hashtable_t *ht;
	pthread_mutex_t ht_lock;
} sop_list_ht;

// sop_list methods
sop_list_t *sop_list_init(uint512_t *nhid, struct repdev *dev);
void sop_list_destroy(sop_list_t *sop_list);

// sop_list_ht methods
sop_list_ht *sop_list_ht_create(void);
void sop_list_ht_destroy(sop_list_ht *sop_ht);

int sop_list_ht_put(sop_list_ht *sop_ht, sop_list_t *sop_list);
int sop_list_ht_get(sop_list_ht *sop_ht, uint512_t *nhid, sop_list_t **sop_list);
void sop_list_delete_ht(sop_list_ht *sop_ht, uint512_t *nhid);


#endif
