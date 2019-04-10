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

    // hashcode 表比例 16
    lc->hash_table = hashtable_init(capacity * 16);
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
lru_cache_put(LruCache *lc, char *key, void *value, void **oldvalue)
{
    assert(lc != NULL && key != NULL);

    // 先判断是否已存在
    void *tmp = hashtable_get(lc->hash_table, key);
    if (tmp == NULL) {
        if (lc->size == lc->capacity) {  // 已满，自动移除最旧元素
            *oldvalue = hashtable_remove_oldest(lc->hash_table);
            lc->size--;
        }
    } else { // key 已存在，是更新操作，不需要增加 size
        lc->size--;
    }

    int ret = hashtable_put(lc->hash_table, key, value);
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

void *
lru_cache_remove(LruCache *lc, char *key)
{
    assert(lc != NULL && key != NULL);

    void *v = hashtable_remove(lc->hash_table, key);
    if (v != NULL) {
        lc->size--;
    }

    return v;
}

void
lru_cache_clear(LruCache *lc)
{
    assert(lc != NULL);
    hashtable_clear(lc->hash_table);
    lc->size = 0;
}