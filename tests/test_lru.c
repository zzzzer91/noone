/*
 * Created by zzzzer on 3/29/19.
 */

#include "lru.h"
#include "log.h"
#include <stdlib.h>

#define CAPACITY 1024*128

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
                size_t key = hash_key(CAPACITY, s);
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
test_lru()
{
    test_hash_key();
}