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
    size_t hashcode;         // hashcode 值
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

HashTable *init_hashtable(size_t capacity);

void free_hashtable(HashTable *ht);

size_t djb_hash(char *key);

int hashtable_set(HashTable *ht, char *key, void *value);

void *hashtable_get(HashTable *ht, char *key);

void *hashtable_del(HashTable *ht, char *key);

void hashtable_clear(HashTable *ht);

#endif  /* _NOONE_HASHTABLE_H_ */
