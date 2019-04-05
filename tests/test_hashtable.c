/*
 * Created by zzzzer on 3/29/19.
 */

#include "helper.h"
#include "hashtable.h"
#include "log.h"
#include <stdlib.h>

void
test_hash_key()
{
    size_t capacity = 1024*32;
    char *table = malloc(sizeof(char) * capacity);
    memset(table, 0, sizeof(char) * capacity);

    int key_count = 0;
    int collisions = 0;  // 碰撞数

    char s[32] = "0a123456789a";
    size_t s_len = strlen(s);
    for (char c1 = '0'; c1 <= '9'; c1++) {
        s[0] = c1;
        for (char c2 = 'a'; c2 <= 'z'; c2++) {
            s[1] = c2;
            for (char c3 = 'a'; c3 <= 'z'; c3++) {
                s[s_len-1] = c3;
                size_t key = djb_hash(s) % capacity;
                if (table[key] == 1) {
                    collisions++;
                } else {
                    table[key] = 1;
                }
                key_count++;
            }
        }
    }
    LOGGER_INFO("test_lru, table 大小：%ld，key 数：%d，碰撞数：%d，碰撞率：%f",
            capacity ,key_count, collisions, collisions / (float)key_count);

    free(table);
}

void
test_table()
{
    size_t capacity = 6;
    HashTable *ht = hashtable_init(capacity);
    char s1[] = "rm.api.weibo.com";
    char s2[] = "clients4.google.com";
    char s3[] = "www.bilibili.com";
    char s4[] = "api.unsplash.com";
    char s5[] = "api.bilibili.com";

    hashtable_set(ht, s1, (void *) 1L);
    hashtable_set(ht, s2, (void *) 3L);
    hashtable_set(ht, s3, (void *) 4L);
    hashtable_set(ht, s4, (void *) 5L);
    hashtable_set(ht, s5, (void *) 6L);
    hashtable_set(ht, s1, (void *) 2L);
    EXPECT_EQ_LONG(5L, ht->size);

    EXPECT_EQ_LONG(2L, (long) hashtable_get(ht, s1));
    EXPECT_EQ_LONG(3L, (long) hashtable_get(ht, s2));
    EXPECT_EQ_LONG(4L, (long) hashtable_get(ht, s3));
    EXPECT_EQ_LONG(5L, (long) hashtable_get(ht, s4));
    EXPECT_EQ_LONG(6L, (long) hashtable_get(ht, s5));

    // 测试删除元素
    EXPECT_EQ_LONG(3L, (long) hashtable_del(ht, s2));
    EXPECT_EQ_POINTER(NULL, hashtable_del(ht, s2));
    EXPECT_EQ_POINTER(NULL, hashtable_get(ht, s2));
    EXPECT_EQ_LONG(4L, ht->size);

    // 测试时间优先队列
    Entry *p = ht->list_head;
    EXPECT_EQ_LONG(2L, (long)p->value);
    p = p->list_next;
    EXPECT_EQ_LONG(6L, (long)p->value);
    p = p->list_next;
    EXPECT_EQ_LONG(5L, (long)p->value);
    p = p->list_next;
    EXPECT_EQ_LONG(4L, (long)p->value);
    p = p->list_next;
    EXPECT_EQ_POINTER(NULL, p);

    //
    EXPECT_EQ_LONG(4L, (long)hashtable_remove_oldest(ht));
    EXPECT_EQ_LONG(5L, (long)hashtable_remove_oldest(ht));
    EXPECT_EQ_LONG(6L, (long)hashtable_remove_oldest(ht));
    EXPECT_EQ_LONG(2L, (long)hashtable_remove_oldest(ht));
    EXPECT_EQ_LONG(0L, ht->size);
    EXPECT_EQ_POINTER(NULL, hashtable_remove_oldest(ht));
    EXPECT_EQ_POINTER(NULL, ht->list_head);
    EXPECT_EQ_POINTER(NULL, ht->list_tail);

    hashtable_clear(ht);
    EXPECT_EQ_LONG(0L, ht->size);
    EXPECT_EQ_POINTER(NULL, ht->list_head);
    EXPECT_EQ_POINTER(NULL, ht->list_tail);

    hashtable_destory(ht);
}

void
test_hashtable()
{
    // test_hash_key();
    test_table();
}