/*
 * Created by zzzzer on 3/11/19.
 */

#include "helper.h"
#include "log.h"

int main_ret;    /* 测试结果，0 成功，1 失败 */
int test_count;  /* 总测试用例 */
int test_pass;   /* 测试通过用例 */

void
summary()
{
    LOGGER_INFO("%d/%d (%3.2f%%) passed\n",
           test_pass, test_count, test_pass * 100.0 / test_count);
}