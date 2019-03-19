/*
 * Created by zzzzer on 3/11/19.
 */

#include "helper.h"
#include "test_log.c"
#include "test_cryptor.c"
#include "test_ae.c"

int
main(void)
{
    // test_log();
    test_cryptor();
    test_ae();

    SUMMARY();

    return main_ret;
}