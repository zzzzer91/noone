/*
 * Created by zzzzer on 3/25/19.
 */

#ifndef _NOONE_BUFFER_H_
#define _NOONE_BUFFER_H_

#include <stddef.h>

typedef struct Buffer {
    size_t capacity;
    size_t len;
    size_t idx;
    char *data;
} Buffer;

Buffer *init_buffer(size_t capacity);

void free_buffer(Buffer *buf);

int resize_buffer(Buffer *buf, size_t new_capacity);

// 若超出容量上限，则每次循环增加原来容量的一半，直到满足
#define RESIZE_BUF(buf, size) \
    do { \
        size_t need_cap = (buf)->len + (size); \
        size_t step = (buf)->capacity >> 1U; \
        size_t new_cap = (buf)->capacity + step; \
        while (need_cap > new_cap) { \
            new_cap += step;\
        } \
        resize_buffer(buf, new_cap); \
    } while (0)

#endif  /* _NOONE_BUFFER_H_ */
