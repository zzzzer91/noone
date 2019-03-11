/*
 * Created by zzzzer on 3/11/19.
 */

#ifndef _NOONE_HELPER_H_
#define _NOONE_HELPER_H_

#include <stdio.h>

extern int main_ret;    /* 测试结果，0 成功，1 失败 */
extern int test_count;  /* 总测试用例 */
extern int test_pass;   /* 测试通过用例 */

void summary();

#define EXPECT_EQ_BASE(equality, expect, actual, format) \
    do {\
        test_count++;\
        if (equality) {\
            test_pass++;\
        } else {\
            fprintf(stderr, "%s:%d: expect: " format " actual: " format "\n",\
                    __FILE__, __LINE__, expect, actual);\
            main_ret = 1;\
        }\
    } while (0)

#define EXPECT_EQ_INT(expect, actual) \
    EXPECT_EQ_BASE((expect) == (actual), expect, actual, "%d")

#define EXPECT_EQ_STRING(expect, actual, alength) \
    EXPECT_EQ_BASE( \
        sizeof(expect) - 1 == alength && memcmp(expect, actual, alength) == 0, \
        expect, actual, "%s" \
    )

#endif /* _NOONE_HELPER_H_ */
