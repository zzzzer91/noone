/*
 * Created by zzzzer on 4/2/19.
 */

#include "helper.h"
#include "lru.h"
#include "log.h"

void
test_lru()
{
    size_t capacity = 4;
    LruCache *lc = init_lru_cache(capacity);

    char s1[] = "rm.api.weibo.com";
    char s2[] = "clients4.google.com";
    char s3[] = "www.bilibili.com";
    char s4[] = "api.unsplash.com";
    char s5[] = "api.bilibili.com";
    lru_cache_set(lc, s1, (void *) 1L);
    lru_cache_set(lc, s1, (void *) 2L);
    EXPECT_EQ_LONG(2L, (long) lru_cache_get(lc, s1));
    lru_cache_set(lc, s2, (void *) 3L);
    lru_cache_set(lc, s3, (void *) 4L);
    lru_cache_set(lc, s4, (void *) 5L);
    lru_cache_set(lc, s5, (void *) 6L);
    EXPECT_EQ_LONG(capacity, lc->size);
    EXPECT_EQ_LONG((long)NULL, (long) lru_cache_get(lc, s1));  // 最先加入，已被剔除
    EXPECT_EQ_LONG(3L, (long) lru_cache_get(lc, s2));
    EXPECT_EQ_LONG(4L, (long) lru_cache_get(lc, s3));
    EXPECT_EQ_LONG(5L, (long) lru_cache_get(lc, s4));
    EXPECT_EQ_LONG(6L, (long) lru_cache_get(lc, s5));

    free_lru_cache(lc);
}