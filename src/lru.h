/*
 * Created by zzzzer on 3/29/19.
 */

#ifndef _NOONE_LRU_H_
#define _NOONE_LRU_H_

#include "hashtable.h"

typedef struct LruCache {
    HashTable *hash_table;
    int capacity;
    int size;
} LruCache;

LruCache *lru_cache_init(int capacity);

void lru_cache_destory(LruCache *lc);

int lru_cache_put(LruCache *lc, char *key, void *value, void **oldvalue);

void *lru_cache_get(LruCache *lc, char *key);

void *lru_cache_remove(LruCache *lc, char *key);

void lru_cache_clear(LruCache *lc);

#endif  /* _NOONE_LRU_H_ */
