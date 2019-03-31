/*
 * Created by zzzzer on 3/31/19.
 */

#ifndef _NOONE_HASHTABLE_H_
#define _NOONE_HASHTABLE_H_

#include <stddef.h>

#define KEY_LEN 64

typedef struct Entry {
    char key[KEY_LEN+1];
    void *value;
    size_t hash;         // hash 值
    struct Entry *next;  // 采用拉链法
} Entry;

typedef struct EntryZipper {
    Entry *head;  // 指向拉链头部
    int entry_count;
} EntryZipper;

typedef struct HashTable {
    size_t size;      // 表当前大小
    size_t capacity;  // 表容量
    EntryZipper *entry_zipper;
} HashTable;

HashTable *init_hash_table(size_t capacity);

size_t hash_key(size_t capacity, char *key);

int hash_set(HashTable *ht, char *key, void *value);

void *hash_get(HashTable *ht, char *key);

void *hash_del(HashTable *ht, void *key);

#endif  /* _NOONE_HASHTABLE_H_ */
