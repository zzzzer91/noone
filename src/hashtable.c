/*
 * Created by zzzzer on 3/31/19.
 */

#include "hashtable.h"
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>

HashTable *
hashtable_init(size_t capacity)
{
    assert(capacity > 0);

    HashTable *hash_table = malloc(sizeof(HashTable));
    if (hash_table == NULL) {
        return NULL;
    }

    hash_table->zipper_entry = calloc(capacity, sizeof(ZipperEntry));
    if (hash_table->zipper_entry == NULL) {
        free(hash_table);
        return NULL;
    }

    hash_table->size = 0;
    hash_table->capacity = capacity;
    hash_table->list_head = NULL;

    return hash_table;
}

void
hashtable_destory(HashTable *ht)
{
    assert(ht != NULL);

    hashtable_clear(ht);
    free(ht->zipper_entry);
    free(ht);
}

/*
 * djb
 */
size_t
djb_hash(char *key)
{
    /* 5381 和 33。说是经过大量实验，这两个的结果碰撞小，哈希结果分散 */
    register size_t hash = 5381;

    char c;
    while ((c = *key++)) {
        hash = ((hash << 5U) + hash) + c; /* hashcode * 33 + c */
    }
    return hash;
}

/*
 * 失败返回 -1，表满返回 0，成功返回 hashtable 的大小
 */
int
hashtable_set(HashTable *ht, char *key, void *value)
{
    assert(ht != NULL && key != NULL);  // False 时触发

    if (ht->size == ht->capacity) {  // hashtable 满
        return 0;
    }

    size_t hashcode = djb_hash(key) % ht->capacity;
    ZipperEntry *ze = &ht->zipper_entry[hashcode];

    // 可能存在相同的 key，则更新
    Entry *p = ze->zipper_head;
    for (int i = 0; i < ze->entry_count; i++) {
        if (strncmp(p->key, key, MAX_HASH_KEY_LEN) == 0) {
            p->value = value;

            // 更新队列位置
            if (p->list_prev != NULL) {  // 不在队列头
                p->list_prev->list_next = p->list_next;
                if (p->list_next != NULL) {  // 不在队列尾
                    p->list_next->list_prev = p->list_prev;
                } else {  // 在队列尾，需更新队尾指针
                    ht->list_tail = p->list_prev;
                }
                p->list_prev = NULL;
                p->list_next = ht->list_head;
                ht->list_head->list_prev = p;
                ht->list_head = p;
            }

            return ht->size;
        }
        p = p->zipper_next;
    }

    // 拉链中没有相同的 key
    Entry *e = malloc(sizeof(Entry));
    if (e == NULL) {
        return -1;
    }
    strncpy(e->key, key, MAX_HASH_KEY_LEN);
    e->value = value;
    e->hashcode = hashcode;

    // 放在拉链头
    e->zipper_prev = NULL;
    if (ze->zipper_head != NULL) {
        ze->zipper_head->zipper_prev = e;
    }
    e->zipper_next = ze->zipper_head;
    ze->zipper_head = e;

    // 放在队列头
    e->list_prev = NULL;
    if (ht->list_head != NULL) {
        ht->list_head->list_prev = e;
    } else {
        ht->list_tail = e;  // 插入的是队列中第一个元素，更新尾指针
    }
    e->list_next = ht->list_head;
    ht->list_head = e;

    ze->entry_count++;
    ht->size++;

    return ht->size;
}

void *
hashtable_get(HashTable *ht, char *key)
{
    assert(ht != NULL && key != NULL);

    size_t hashcode = djb_hash(key) % ht->capacity;
    ZipperEntry *ze = &ht->zipper_entry[hashcode];

    // 寻找一个相同的 key
    Entry *p = ze->zipper_head;
    for (int i = 0; i < ze->entry_count; i++) {
        if (strncmp(p->key, key, MAX_HASH_KEY_LEN) == 0) {
            return p->value;
        }
        p = p->zipper_next;
    }
    return NULL;
}

void *
hashtable_del(HashTable *ht, char *key)
{
    assert(ht != NULL && key != NULL);

    size_t hashcode = djb_hash(key) % ht->capacity;
    ZipperEntry *ze = &ht->zipper_entry[hashcode];

    Entry *p = ze->zipper_head;
    for (int i = 0; i < ze->entry_count; i++) {
        if (strncmp(p->key, key, MAX_HASH_KEY_LEN) == 0) {
            void *v =  p->value;
            // 从拉链中删除
            if (p->zipper_prev == NULL) { // 处于拉链头
                ze->zipper_head = p->zipper_next;  // 更新头指针
                if (ze->zipper_head != NULL) {
                    ze->zipper_head->zipper_prev = NULL;
                }
            } else {
                p->zipper_prev->zipper_next = p->zipper_next;
                if (p->zipper_next != NULL) {
                    p->zipper_next->zipper_prev = p->list_prev;
                }
            }
            // 从队列中删除
            if (p->list_prev == NULL) { // 处于队列头
                ht->list_head = p->list_next;  // 更新头指针
                if (ht->list_head != NULL) {
                    ht->list_head->list_prev = NULL;
                } else { // 已处于队列，队列中就一个元素
                    ht->list_tail = NULL;
                }
            } else {
                p->list_prev->list_next = p->list_next;
                if (p->list_next != NULL) {
                    p->list_next->list_prev = p->list_prev;
                } else {  // 处于队列尾
                    ht->list_tail = p->list_prev; // 更新队尾指针
                }
            }

            free(p);

            ze->entry_count--;
            ht->size--;

            return v;
        }
        p = p->zipper_next;
    }
    return NULL;
}

void *
hashtable_remove_oldest(HashTable *ht)
{
    assert(ht != NULL);

    if (ht->size == 0) {
        return NULL;
    }

    Entry *p = ht->list_tail;

    return hashtable_del(ht, p->key);
}

void
hashtable_clear(HashTable *ht)
{
    int size = ht->size;
    Entry *p = ht->list_head;
    for (int i = 0; i < size; i++) {
        ht->zipper_entry[p->hashcode].entry_count--;
        ht->list_head = p->list_next;
        free(p);
        p = ht->list_head;
    }
    ht->list_tail = NULL;
    ht->size = 0;
}