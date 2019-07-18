#ifndef fsio_list_cache_entry_h
#define fsio_list_cache_entry_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashtable.h"
#include "ccowfsio.h"

#define FSIO_LIST_CACHE_TTL 20

typedef struct fsio_list_cache_entry_t {
	char *name;
    inode_t parent;
    inode_t child;
    uint64_t created;
} fsio_list_cache_entry_t;

typedef struct fsio_list_cache_t {
    hashtable_t *fsio_list_cache_entry_ht;
    pthread_mutex_t fsio_list_cache_entry_ht_lock;
} fsio_list_cache_t;



// fsio_list_cache_entry_t methods
int fsio_list_cache_entry_init(fsio_list_cache_entry_t *fsio_list_cache_entry, inode_t parent, inode_t child, char *name);
void fsio_list_cache_entry_destroy(fsio_list_cache_entry_t *fsio_list_cache_entry);

int fsio_list_cache_entry_age(fsio_list_cache_entry_t *fsio_list_cache_entry);
int fsio_list_cache_entry_expired(fsio_list_cache_entry_t *fsio_list_cache_entry);

// fsio_list_cache_entry_t hash table methods
char *build_list_key(inode_t parent, inode_t child, char *buf);


int fsio_list_cache_create(fsio_list_cache_t *fsio_list_cache);
int fsio_list_cache_destroy(fsio_list_cache_t *fsio_list_cache);
int fsio_list_cache_clean(fsio_list_cache_t *fsio_list_cache);


int fsio_list_cache_put(fsio_list_cache_t *fsio_list_cache, fsio_list_cache_entry_t *fsio_list_cache_entry);
int fsio_list_cache_get(fsio_list_cache_t *fsio_list_cache, char *key, char *res, int res_max);
void fsio_list_cache_delete(fsio_list_cache_t *fsio_list_cache, char *key);


#ifdef __cplusplus
}
#endif

#endif
