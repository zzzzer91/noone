/*
 * Created by zzzzer on 3/25/19.
 */

#ifndef _NOONE_BUFFER_H_
#define _NOONE_BUFFER_H_

#include <stddef.h>

typedef struct Buffer {
    unsigned char *data;
    unsigned char *p;  // 指针
    size_t len;
    size_t capacity;
} Buffer;

int init_buffer(Buffer *buf, size_t capacity);

void free_buffer(Buffer *buf);

int resize_buffer(Buffer *buf, size_t new_size);

#endif /* _NOONE_BUFFER_H_ */
