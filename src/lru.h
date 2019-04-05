/*
 * Created by zzzzer on 3/29/19.
 */

#ifndef _NOONE_LRU_H_
#define _NOONE_LRU_H_

#include "hashtable.h"

typedef struct LruCache {
    HashTable *hash_table;
    size_t capacity;
    size_t size;
} LruCache;

LruCache *lru_cache_init(size_t capacity);

void lru_cache_destory(LruCache *lc);

int lru_cache_set(LruCache *lc, char *key, void *value, void **oldvalue);

void *lru_cache_get(LruCache *lc, char *key);

void lru_cache_clear(LruCache *lc);

#endif  /* _NOONE_LRU_H_ */
