/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_LOG_H_
#define _NOONE_LOG_H_

#include <stdio.h>
#include <time.h>

typedef enum {
    DEBUG,
    INFO,
    WARNING,
    ERROR
} LogLevel;

extern LogLevel g_log_level;

void set_log_level(LogLevel level);

#define logger_print(log_level, s) \
    do { \
        fprintf(stderr, "[%s]%s\n", log_level, s); \
    } while (0)

#define logger_debug(s) \
    do { \
        if (g_log_level <= DEBUG) { \
            logger_print("DEBUG", s); \
        } \
    } while (0)

#define logger_info(s) \
    do { \
        if (g_log_level <= INFO) { \
            logger_print("INFO", s); \
        } \
    } while (0)

#define logger_warning(s) \
    do { \
        if (g_log_level <= WARNING) { \
            logger_print("WARNING", s); \
        } \
    } while (0)

#define logger_error(s) \
    do { \
        if (g_log_level <= ERROR) { \
            logger_print("ERROR", s); \
        } \
    } while (0)

#endif  /* _NOONE_LOG_H_ */
