/*
 * Use is subject of licensing terms
 * Nexenta Systems, Inc.
 */
#ifndef __SOP_CACHE_H__
#define __SOP_CACHE_H__

#define DEFAULT_CACHE_SIZE	1024
#define DEFAULT_CACHE_COUNT	128
#define CACHE_EVICT_TIMEOUT	300000000UL
#define SOP_CACHE_INSERT	1
#define SOP_CACHE_DELETE	2
#define SOP_CACHE_MD		3


typedef struct sop_rec {
	char *key;
	size_t key_size;
	void *value;
	size_t value_size;
	int index;
	int optype;
	int64_t delta_size;
	int64_t delta_objs;
	int64_t delta_used;
	uint64_t genid;
	uint64_t insert_time;
} sop_rec_t;

typedef struct sop_rec_table {
	hashtable_t *ht;
	struct skiplist *sl;
	int shard_count;
	int busy_count;
	int64_t size;
	int64_t objs;
	int64_t used;
	pthread_mutex_t ht_lock;
	uint64_t *genid;
	uint64_t insert_time_last;
	char *bid;
	char *shard_name;
} sop_rec_table;

typedef struct sop_shard_table {
	hashtable_t *ht;
	pthread_mutex_t ht_lock;
} sop_shard_table;


// sop_rec methods
sop_rec_t *sop_rec_init(char *key, size_t key_size, void *value, size_t value_size,
		int64_t delta_size,	int64_t delta_objs,	int64_t delta_used,
		int index, int optype, uint64_t genid);

void sop_rec_destroy(sop_rec_t *sop_rec);

// sop_rec_table methods
sop_rec_table *sop_rec_table_create(int shard_count, const char *bid, char *shard_name);
void sop_rec_table_destroy(sop_rec_table *sop_tb);

int sop_rec_table_put(sop_rec_table *sop_tb, sop_rec_t *sop_rec);
int sop_rec_table_get(sop_rec_table *sop_tb, char *key, size_t key_size, sop_rec_t **sop_rec);
void sop_rec_table_delete(sop_rec_table *sop_tb, char *key, size_t key_size);

// sop_shard_table methods
sop_shard_table *sop_shard_table_create(void);
void sop_shard_table_destroy(sop_shard_table *sop_sh);

int sop_shard_table_put(sop_shard_table *sop_sh, char *path, size_t path_size, sop_rec_table *sop_rec_tb);
int sop_shard_table_get(sop_shard_table *sop_sh, char *path, size_t path_size, sop_rec_table **sop_rec_tb);
void sop_shard_table_detach(sop_shard_table *sop_sh, sop_rec_table *sop_rec_tb);
int sop_shard_table_init(sop_shard_table *sop_sh, int shard_count, char *path,
    size_t path_size, const char *bid, char *shard_name, sop_rec_table *new_rec_tb, sop_rec_table **sop_rec_tb_out);
int sop_shard_table_delete(sop_shard_table *sop_sh, char *path, size_t path_size);


#endif
