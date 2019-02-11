#include "log.h"

LogLevel g_log_level = INFO;

void
set_log_level(LogLevel level)
{
    g_log_level = level;
}
