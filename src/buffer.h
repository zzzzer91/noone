/*
 * Created by zzzzer on 3/25/19.
 */

#ifndef _NOONE_BUFFER_H_
#define _NOONE_BUFFER_H__

#include <stddef.h>

typedef struct Buffer {
    size_t idx;
    size_t len;
    size_t capacity;
    char  *data;
} Buffer;

Buffer *init_buffer(size_t capacity);

void free_buffer(Buffer *buf);

int resize_buffer(Buffer *buf, size_t new_size);

#endif /* _NOONE_BUFFER_H_ */
