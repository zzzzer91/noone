/*
 * Created by zzzzer on 3/25/19.
 */

#include "buffer.h"
#include <stdlib.h>

Buffer *
init_buffer(size_t capacity){
    Buffer *buf = malloc(sizeof(Buffer));
    if (buf == NULL) {
        return NULL;
    }

    buf->data = malloc(capacity);
    if (buf->data == NULL) {
        free(buf);
        return NULL;
    }

    buf->capacity = capacity;
    buf->idx = 0;
    buf->len = 0;

    return buf;
}

void
free_buffer(Buffer *buf)
{
    if (buf == NULL) {
        return;
    }

    if (buf->data != NULL) {
        free(buf->data);
    }
    free(buf);
}

int
resize_buffer(Buffer *buf, size_t new_size)
{
    if (buf == NULL || new_size == 0) {
        return -1;
    }

    char *new_ptr = realloc(buf, new_size);
    if (new_ptr == NULL) {
        return -1;
    }

    buf->data = new_ptr;
    buf->capacity = new_size;

    return 0;
}