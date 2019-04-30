/*
 * Created by zzzzer on 4/6/19.
 *
 * 双向链表相关操作, item 结构体需有 list_prev 和 list_next 两个指针成员
 */

#ifndef _NOONE_DLIST_H_
#define _NOONE_DLIST_H_

// item 结构体需有 list_prev 和 list_next 两个指针成员
#define DLIST_ADD_HEAD(head, tail, item) \
    do { \
        item->list_prev = NULL; \
        item->list_next = head; \
        if (head != NULL) { \
            head->list_prev = item; \
        } else { \
            tail = item; \
        } \
        head = item; \
    } while (0)

#define DLIST_DEL(head, tail, item) \
    do { \
        if (item->list_prev != NULL) { \
            item->list_prev->list_next = item->list_next; \
        } else { \
            head = item->list_next; \
        } \
        if (item->list_next != NULL) { \
            item->list_next->list_prev = item->list_prev; \
        } else { \
            tail = item->list_prev; \
        } \
        item->list_prev = NULL; \
        item->list_next = NULL; \
    } while (0)

#endif  /* _NOONE_DLIST_H_ */
