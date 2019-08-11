/*
 * Created by zzzzer on 4/2/19.
 */

#include "helper.h"
#include "lru.h"
#include "log.h"

void test_lru() {
    int capacity = 4;
    LruCache *lc = lru_cache_init(capacity);

    char s1[] = "rm.api.weibo.com";
    char s2[] = "clients4.google.com";
    char s3[] = "www.bilibili.com";
    char s4[] = "api.unsplash.com";
    char s5[] = "api.bilibili.com";

    void *oldvalue;
    lru_cache_put(lc, s1, (void *)1L, &oldvalue);
    lru_cache_put(lc, s2, (void *)3L, &oldvalue);
    lru_cache_put(lc, s3, (void *)4L, &oldvalue);
    lru_cache_put(lc, s4, (void *)5L, &oldvalue);
    lru_cache_put(lc, s5, (void *)6L, &oldvalue);
    EXPECT_EQ_LONG(1L, (long)oldvalue);
    EXPECT_EQ_POINTER(NULL, lru_cache_get(lc, s1));
    lru_cache_put(lc, s1, (void *)2L, &oldvalue);
    EXPECT_EQ_LONG(3L, (long)oldvalue);
    EXPECT_EQ_POINTER(NULL, lru_cache_get(lc, s2));

    EXPECT_EQ_LONG(capacity, lc->size);
    EXPECT_EQ_LONG(2L, (long)lru_cache_get(lc, s1));
    EXPECT_EQ_LONG(4L, (long)lru_cache_get(lc, s3));
    EXPECT_EQ_LONG(5L, (long)lru_cache_get(lc, s4));
    EXPECT_EQ_LONG(6L, (long)lru_cache_get(lc, s5));

    lru_cache_destory(lc);
}