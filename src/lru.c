/*
 * Created by zzzzer on 3/29/19.
 */

#include "lru.h"
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>

HashTable *
init_hash_table(size_t capacity)
{
    HashTable *hash_table = malloc(sizeof(HashTable));
    if (hash_table == NULL) {
        return NULL;
    }

    hash_table->entry_zipper = calloc(capacity, sizeof(EntryZipper));
    if (hash_table->entry_zipper == NULL) {
        return NULL;
    }

    hash_table->size = 0;
    hash_table->capacity = capacity;

    return hash_table;
}

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

int
hash_set(HashTable *ht, void *key, void *value)
{
    assert(ht != NULL);

    size_t hash = hash_key(ht->capacity, key);
    EntryZipper *ez = &ht->entry_zipper[hash];

    // 寻找一个相同的 key
    Entry *p = ez->head;
    int i;
    for (i = 0; i < ez->entry_count; i++) {
        if (p->key == key) {
            p->value = value;
            break;
        }
        p = p->next;
    }
    if (i == ez->entry_count) {  // 拉链中没有相同的 key
        Entry *e = malloc(sizeof(Entry));
        if (e == NULL) {
            return -1;
        }
        e->key = key;
        e->value = value;
        e->hash = hash;

        e->next = ez->head;  // 插入拉链头
        ez->head = e;
        ez->entry_count++;
        ht->size++;
    }

    return 0;
}

void *
hash_get(HashTable *ht, void *key)
{
    assert(ht != NULL);

    size_t hash = hash_key(ht->capacity, key);
    EntryZipper *ez = &ht->entry_zipper[hash];

    if (ez->entry_count == 0) {
        return NULL;
    } else {
        // 寻找一个相同的 key
        Entry *p = ez->head;
        for (int i = 0; i < ez->entry_count; i++) {
            if (p->key == key) {
                return p->value;
            }
            p = p->next;
        }
        return NULL;
    }
}