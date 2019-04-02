/*
 * Created by zzzzer on 3/29/19.
 */

#include "helper.h"
#include "hashtable.h"
#include "log.h"
#include <stdlib.h>

#define CAPACITY 1024*64

void
test_hash_key()
{
    char *table = malloc(sizeof(char) * CAPACITY);
    memset(table, 0, sizeof(char) * CAPACITY);

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
                size_t key = djb_hash(s) % CAPACITY;
                if (table[key] == 1) {
                    collisions++;
                } else {
                    table[key] = 1;
                }
                key_count++;
            }
        }
    }
    LOGGER_INFO("test_lru, table 大小：%d，key 数：%d，碰撞数：%d，碰撞率：%f",
            CAPACITY ,key_count, collisions, collisions / (float)key_count);

    free(table);
}

void
test_table()
{
    HashTable *ht = init_hash_table(CAPACITY);
    char s1[] = "rm.api.weibo.com";
    char s2[] = "clients4.google.com";
    hash_set(ht, s1, (void *)123L);
    hash_set(ht, s1, (void *)456L);
    hash_set(ht, s2, (void *)789L);
    EXPECT_EQ_LONG(2L, ht->size);
    EXPECT_EQ_LONG(456L, (long)hash_get(ht, s1));
    EXPECT_EQ_LONG(789L, (long)hash_get(ht, s2));
    EXPECT_EQ_LONG(789L, (long)hash_del(ht, s2));
    EXPECT_EQ_LONG((long)NULL, (long)hash_del(ht, s2));
    EXPECT_EQ_LONG(1L, ht->size);

    free_hash_table(ht);
}

void
test_hashtable()
{
    // test_hash_key();
    test_table();
}