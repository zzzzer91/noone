/*
 * Created by zzzzer on 3/29/19.
 */

#include "lru.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

LruCache *
lru_cache_init(size_t capacity)
{
    assert(capacity > 0);

    LruCache *lc = malloc(sizeof(LruCache));
    if (lc == NULL) {
        return NULL;
    }

    // hashcode 表比例 32
    lc->hash_table = hashtable_init(capacity * 32);
    if (lc->hash_table == NULL) {
        free(lc);
        return NULL;
    }

    lc->capacity = capacity;
    lc->size = 0;

    return lc;
}

void
lru_cache_destory(LruCache *lc)
{
    assert(lc != NULL);
    lru_cache_clear(lc);
    hashtable_destory(lc->hash_table);
    free(lc);
}

/*
 * 传出过期元素的 value，用于调用者释放
 */
int
lru_cache_set(LruCache *lc, char *key, void *value, void **oldvalue)
{
    assert(lc != NULL && key != NULL);

    *oldvalue = NULL;
    if (lc->size == lc->capacity) {
        *oldvalue = hashtable_remove_oldest(lc->hash_table);
        lc->size--;
    }
    int ret = hashtable_set(lc->hash_table, key, value);
    if (ret < 0) {
        return -1;
    }
    lc->size++;

    return ret;
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
    hashtable_clear(lc->hash_table);
    lc->size = 0;
}