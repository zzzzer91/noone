/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_LOG_H_
#define _NOONE_LOG_H_

#include "config.h"
#include <stdio.h>
#include <time.h>

/*
#define LOGGER_PRINT(log_level, fmt, args...) \
    do { \
        time_t t = time(NULL); \
        struct tm *lt = localtime(&t); \
        char nowtime[32] = {0}; \
        strftime(nowtime, 32, "%Y-%m-%d %H:%M:%S", lt); \
        fprintf(stderr, "[%s] " "["log_level"] " fmt "\n", nowtime, ##args); \
    } while(0)
 */

#define LOGGER_PRINT(log_level, fmt, args...) \
        fprintf(stderr, "["log_level"] " fmt "\n", ##args); \


#if NOONE_DEBUG
#define LOGGER_DEBUG(fmt, args...) LOGGER_PRINT("DEBUG", fmt, ##args)
#else
#define LOGGER_DEBUG(fmt, args...)
#endif

#define LOGGER_INFO(fmt, args...) LOGGER_PRINT("INFO", fmt, ##args)

#define LOGGER_WARNING(fmt, args...) LOGGER_PRINT("WARNING", fmt, ##args)

#define LOGGER_ERROR(fmt, args...) LOGGER_PRINT("ERROR", fmt, ##args)

#endif  /* _NOONE_LOG_H_ */
