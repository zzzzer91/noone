/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_ERROR_H_
#define _NOONE_ERROR_H_

#include "log.h"
#include <errno.h>
#include <string.h>

#define PANIC(s) \
    do { \
        if (errno != 0) { \
            char *err_msg = strerror(errno); \
            LOGGER_ERROR(s ": %s", err_msg); \
        } else {\
            LOGGER_ERROR(s); \
        } \
        exit(1); \
    } while(0)

#endif  /* _NOONE_ERROR_H_ */