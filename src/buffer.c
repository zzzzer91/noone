/*
 * Created by zzzzer on 3/25/19.
 */

#include "buffer.h"
#include <stdlib.h>
#include <assert.h>

Buffer *
init_buffer(size_t capacity)
{
    assert(capacity > 0);

    Buffer *buf = malloc(sizeof(Buffer));
    if (buf == NULL) {
        return NULL;
    }

    buf->data = malloc(sizeof(char)*capacity);
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
    assert(buf != NULL);

    free(buf);
    free(buf->data);
}

int
resize_buffer(Buffer *buf, size_t new_capacity)
{
    assert(buf != NULL && new_capacity > 0);

    if (new_capacity <= buf->capacity) {
        return 0;
    }

    buf->data = realloc(buf->data, sizeof(char)*(new_capacity));
    if (buf->data == NULL) {
        return -1;
    }

    buf->capacity = new_capacity;

    return 0;
}