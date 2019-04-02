/*
 * Created by zzzzer on 3/29/19.
 */

#include "lru.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define LRU_DOMAIN_LEN 64

typedef struct DnsEntry {
    char domain[LRU_DOMAIN_LEN+1];
} DnsEntry;

LruCache *
init_lru_cache(size_t capacity)
{
    assert(capacity > 0);

    LruCache *lc = malloc(sizeof(LruCache));
    if (lc == NULL) {
        return NULL;
    }

    // hashcode 表比例 64
    lc->hash_table = init_hashtable(capacity * 64);
    if (lc->hash_table == NULL) {
        free(lc);
        return NULL;
    }

    lc->queue = init_seqqueue(capacity);
    if (lc->queue == NULL) {
        free_hashtable(lc->hash_table);
        free(lc);
        return NULL;
    }

    lc->capacity = capacity;
    lc->size = 0;

    return lc;
}

void
free_lru_cache(LruCache *lc)
{
    assert(lc != NULL);
    free_hashtable(lc->hash_table);
    free_seqqueue(lc->queue);
    free(lc);
}

int
lru_cache_set(LruCache *lc, char *key, void *value)
{
    assert(lc != NULL && key != NULL);

    DnsEntry *de = malloc(sizeof(DnsEntry));
    if (de == NULL) {
        return -1;
    }

    strncpy(de->domain, key, LRU_DOMAIN_LEN);
    void *ret = hashtable_get(lc->hash_table, key);
    if (ret == NULL) {  // 防止 key 已经在队列中
        de = seqqueue_append(lc->queue, de);
        if (de != NULL) {  // 队满，弹出了最前面的元素
            hashtable_del(lc->hash_table, de->domain);
            free(de);
            lc->size--;
        }
    }
    lc->size = hashtable_set(lc->hash_table, key, value);

    return 0;
}

void *
lru_cache_get(LruCache *lc, char *key)
{
    assert(lc != NULL && key != NULL);

    return hashtable_get(lc->hash_table, key);
}

void
lru_cache_clear(LruCache *lc)
{
    assert(lc != NULL);

}