/*
 * Created by zzzzer on 3/11/19.
 */

#include "log.h"

static void test_logger() {
    LOGGER_PRINT("LOGGER_PRINT", "%s%d", "你好", 123);
    LOGGER_INFO("LOGGER_INFO");
    LOGGER_DEBUG("LOGGER_DEBUG");
    LOGGER_WARNING("LOGGER_WARNING");
    LOGGER_ERROR("LOGGER_ERROR");
}

void test_log() {
    test_logger();
}