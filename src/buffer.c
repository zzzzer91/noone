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
    Buffer *buf = malloc(sizeof(Buffer) + sizeof(char)*capacity);
    if (buf == NULL) {
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
}