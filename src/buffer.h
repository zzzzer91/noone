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
    char data[0];
} Buffer;

Buffer *init_buffer(size_t capacity);

void free_buffer(Buffer *buf);

#endif  /* _NOONE_BUFFER_H_ */
