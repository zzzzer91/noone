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

LogLevel g_log_level = INFO;

#define SET_LOG_LEVEL(level) \
    do { \
        g_log_level = level;\
    } while (0)

#define LOGGER_PRINT(log_level, fmt, args...) \
    do { \
        fprintf(stderr, "[" log_level "] " fmt "\n", ##args); \
    } while (0)

#define LOGGER_DEBUG(fmt, args...) \
    do { \
        if (g_log_level <= DEBUG) { \
            LOGGER_PRINT("DEBUG", fmt, ##args); \
        } \
    } while (0)

#define LOGGER_INFO(fmt, args...) \
    do { \
        if (g_log_level <= INFO) { \
            LOGGER_PRINT("INFO", fmt, ##args); \
        } \
    } while (0)

#define LOGGER_WARNING(fmt, args...) \
    do { \
        if (g_log_level <= WARNING) { \
            LOGGER_PRINT("WARNING", fmt, ##args); \
        } \
    } while (0)

#define LOGGER_ERROR(fmt, args...) \
    do { \
        if (g_log_level <= ERROR) { \
            LOGGER_PRINT("ERROR", fmt, ##args); \
        } \
    } while (0)

#endif  /* _NOONE_LOG_H_ */
