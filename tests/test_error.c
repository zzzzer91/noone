/*
 * Created by zzzzer on 3/11/19.
 */

#include "error.h"
#include <unistd.h>
#include <fcntl.h>

void
test_panic()
{
    int fd = open("不存在.txt", O_RDONLY);
    if (fd < 0) {
        PANIC("open");
    }
}

void
test_error()
{
    test_panic();
}