/*
 * Created by zzzzer on 3/25/19.
 */

#include "buffer.h"
#include <stdlib.h>

int
init_buffer(Buffer *buf, size_t capacity)
{
    buf->data = malloc(capacity*sizeof(unsigned char));
    if (buf->data == NULL) {
        return -1;
    }

    buf->capacity = capacity;
    buf->p = buf->data;
    buf->len = 0;

    return 0;
}

void
free_buffer(Buffer *buf)
{
    if (buf->data != NULL) {
        free(buf->data);
    }

    buf->capacity = 0;
    buf->p = NULL;
    buf->len = 0;
}

int
resize_buffer(Buffer *buf, size_t new_size)
{
    if (buf == NULL || new_size == 0) {
        return -1;
    }

    unsigned char *new_ptr = realloc(buf, new_size*sizeof(unsigned char));
    if (new_ptr == NULL) {
        return -1;
    }

    buf->data = new_ptr;
    buf->capacity = new_size;

    return 0;
}