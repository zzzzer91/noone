/*
 * Created by zzzzer on 3/29/19.
 */

#ifndef _NOONE_LRU_H_
#define _NOONE_LRU_H_

#include "hashtable.h"
#include "queue.h"

typedef struct LruCache {
    HashTable *hash_table;
    SeqQueue *queue;
    size_t capacity;
    size_t size;
} LruCache;

LruCache *init_lru_cache(size_t capacity);

void free_lru_cache(LruCache *lc);

void *lru_cache_set(LruCache *lc, char *key, void *value);

void *lru_cache_get(LruCache *lc, char *key);

void lru_cache_clear(LruCache *lc);

#endif  /* _NOONE_LRU_H_ */
