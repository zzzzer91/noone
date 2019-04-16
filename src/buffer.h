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

#define RESIZE_BUF(buf, size) \
    do { \
        size_t need_cap = buf->len + size; \
        size_t step = buf->capacity >> 1U; \
        size_t new_cap = buf->capacity + step; \
        while (need_cap > new_cap) { \
            new_cap += step;\
        } \
        if (resize_buffer(buf, new_cap) < 0) { \
            LOGGER_ERROR("fd: %d, %s, resize_buffer", nd->client_fd, __func__); \
            CLEAR_CLIENT_AND_REMOTE(); \
        } \
        LOGGER_DEBUG("fd: %d, %s, resize_buffer, new_cap: %ld", \
                nd->client_fd, __func__, new_cap); \
    } while (0)

#endif  /* _NOONE_BUFFER_H_ */
