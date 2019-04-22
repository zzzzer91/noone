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

#endif  /* _NOONE_BUFFER_H_ */
