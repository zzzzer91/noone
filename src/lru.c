/*
 * Created by zzzzer on 3/29/19.
 */

#include "lru.h"
#include <stddef.h>

/*
 * djb
 */
size_t
hash_key(size_t capacity, char *key)
{
    /* 5381 和 33。说是经过大量实验，这两个的结果碰撞小，哈希结果分散 */
    register size_t hash = 5381;

    char c;
    while ((c = *key++)) {
        hash = ((hash << 5U) + hash) + c; /* hash * 33 + c */
    }
    return hash % capacity;
}
