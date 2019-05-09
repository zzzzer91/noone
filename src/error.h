/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_ERROR_H_
#define _NOONE_ERROR_H_

#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

// 注意要在 errno 判断后使用，因为会清 0 errno
#define SYS_ERROR(s, args...) \
    do { \
        if (errno != 0) { \
            LOGGER_ERROR("%s -> " s ": %s", __func__, ##args, strerror(errno)); \
            errno = 0; \
        } else {\
            LOGGER_ERROR("%s -> " s, __func__, ##args); \
        } \
    } while (0)

#define PANIC(s, args...) \
    do { \
        SYS_ERROR(s, ##args);   \
        exit(1); \
    } while (0)

#endif  /* _NOONE_ERROR_H_ */