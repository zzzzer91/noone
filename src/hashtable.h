/*
 * Created by zzzzer on 3/31/19.
 */

#ifndef _NOONE_HASHTABLE_H_
#define _NOONE_HASHTABLE_H_

#include <stddef.h>

// 作为 key 的字符串的最大长度
#define MAX_HASH_KEY_LEN 80

typedef struct Entry {
    char key[MAX_HASH_KEY_LEN + 1];
    void *value;
    size_t hashcode;
    struct Entry *zipper_prev, *zipper_next;  // 采用拉链法
    struct Entry *list_prev, *list_next;  // 双向链表，按时间排序，最近的在队首
} Entry;

typedef struct ZipperEntry {
    Entry *zipper_head;  // 指向拉链头部
    int entry_count;
} ZipperEntry;

typedef struct HashTable {
    int size;      // 表当前大小
    int capacity;  // 表容量
    ZipperEntry *zipper_entry;  // 指向拉链
    Entry *list_head, *list_tail; // head 指向最近插入的元素
} HashTable;

HashTable *hashtable_init(int capacity);

void hashtable_destory(HashTable *ht);

size_t djb_hash(char *key);

int hashtable_put(HashTable *ht, char *key, void *value);

void *hashtable_get(HashTable *ht, char *key);

void *hashtable_remove(HashTable *ht, char *key);

void *hashtable_remove_oldest(HashTable *ht);

void hashtable_clear(HashTable *ht);

#endif  /* _NOONE_HASHTABLE_H_ */
