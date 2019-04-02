/*
 * Created by zzzzer on 3/31/19.
 */

#include "hashtable.h"
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>

HashTable *
init_hash_table(size_t capacity)
{
    assert(capacity > 0);

    HashTable *hash_table = malloc(sizeof(HashTable));
    if (hash_table == NULL) {
        return NULL;
    }

    hash_table->entry_zipper = calloc(capacity, sizeof(EntryZipper));
    if (hash_table->entry_zipper == NULL) {
        free(hash_table);
        return NULL;
    }

    hash_table->size = 0;
    hash_table->capacity = capacity;

    return hash_table;
}

void
free_hash_table(HashTable *ht)
{
    assert(ht != NULL);

    for (int i = 0; i < ht->capacity; i++) {
        int entry_count = ht->entry_zipper[i].entry_count;
        Entry *p = ht->entry_zipper[i].head, *pre;
        for (int j = 0; j < entry_count; j++) {
            pre = p;
            p = p->next;
            free(pre);
        }
    }
    free(ht->entry_zipper);
    free(ht);
}

/*
 * djb
 */
inline size_t
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

int
hash_set(HashTable *ht, char *key, void *value)
{
    assert(ht != NULL && key != NULL);  // False 时触发

    size_t hashcode = djb_hash(key) % ht->capacity;
    EntryZipper *ez = &ht->entry_zipper[hashcode];

    // 可能存在相同的 key，则更新
    Entry *p = ez->head;
    int i;
    for (i = 0; i < ez->entry_count; i++) {
        if (strncmp(p->key, key, KEY_LEN) == 0) {
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
        strncpy(e->key, key, KEY_LEN);
        e->value = value;
        e->hashcode = hashcode;

        e->next = ez->head;  // 插入拉链头
        ez->head = e;
        ez->entry_count++;
        ht->size++;
    }

    return 0;
}

void *
hash_get(HashTable *ht, char *key)
{
    assert(ht != NULL && key != NULL);

    size_t hashcode = djb_hash(key) % ht->capacity;
    EntryZipper *ez = &ht->entry_zipper[hashcode];

    if (ez->entry_count == 0) {
        return NULL;
    } else {
        // 寻找一个相同的 key
        Entry *p = ez->head;
        for (int i = 0; i < ez->entry_count; i++) {
            if (strncmp(p->key, key, KEY_LEN) == 0) {
                return p->value;
            }
            p = p->next;
        }
        return NULL;
    }
}

void *
hash_del(HashTable *ht, char *key)
{
    assert(ht != NULL && key != NULL);

    size_t hashcode = djb_hash(key) % ht->capacity;
    EntryZipper *ez = &ht->entry_zipper[hashcode];

    void *v;
    if (ez->entry_count != 0) {
        // 寻找一个相同的 key
        Entry *p = ez->head;
        if (strncmp(p->key, key, KEY_LEN) == 0) {
            v = p->value;
            ez->head = p->next;
            ez->entry_count--;
            ht->size--;
            free(p);
            return v;
        } else {
            Entry *pre = p;
            p = p->next;
            int i;
            for (i = 1; i < ez->entry_count; i++) {
                if (strncmp(p->key, key, KEY_LEN) == 0) {
                    v =  p->value;
                    pre->next = p->next;
                    ez->entry_count--;
                    ht->size--;
                    free(p);
                    return v;
                }
                pre = p;
                p = p->next;
            }
        }
    }
    return NULL;
}
