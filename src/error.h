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

#define SYS_ERROR(s, args...) \
    do { \
        if (errno != 0) { \
            LOGGER_ERROR(s ": %s", ##args, strerror(errno)); \
        } else {\
            LOGGER_ERROR(s, ##args); \
        } \
    } while (0)

#define PANIC(s, args...) \
    do { \
        SYS_ERROR(s, ##args);   \
        exit(1); \
    } while (0)

#endif  /* _NOONE_ERROR_H_ */