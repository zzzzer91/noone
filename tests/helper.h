/*
 * Created by zzzzer on 3/11/19.
 */

#ifndef _NOONE_HELPER_H_
#define _NOONE_HELPER_H_

#include "log.h"
#include "error.h"
#include <stdio.h>

int main_ret;    /* 测试结果，0 成功，1 失败 */
int test_count;  /* 总测试用例 */
int test_pass;   /* 测试通过用例 */

#define EXPECT_EQ_BASE(equality, expect, actual, format) \
    do {\
        test_count++;\
        if (equality) {\
            test_pass++;\
        } else {\
            LOGGER_ERROR("%s:%d: expect: " format " actual: " format,\
                    __FILE__, __LINE__, expect, actual);\
            main_ret = 1;\
        }\
    } while (0)

#define EXPECT_EQ_INT(expect, actual) \
    EXPECT_EQ_BASE((expect) == (actual), expect, actual, "%d")

#define EXPECT_EQ_LONG(expect, actual) \
    EXPECT_EQ_BASE((expect) == (actual), expect, actual, "%ld")

#define EXPECT_EQ_POINTER(expect, actual) \
    EXPECT_EQ_BASE((expect) == (actual), expect, actual, "%p")

#define EXPECT_EQ_STRING(expect, actual, alength) \
    EXPECT_EQ_BASE( \
        sizeof(expect)-1 == (alength) && memcmp(expect, actual, alength) == 0, \
        expect, actual, "%s" \
    )

#define SUMMARY() \
    LOGGER_INFO("%d/%d (%3.2f%%) passed\n", \
        test_pass, test_count, test_pass * 100.0 / test_count)

#endif /* _NOONE_HELPER_H_ */
