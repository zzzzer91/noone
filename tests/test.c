/*
 * Created by zzzzer on 3/11/19.
 */

#include "helper.h"
#include "test_error.c"
#include "test_cryptor.c"
#include "test_ae.c"
#include "test_lru.c"

int
main(void)
{
    // test_error();
    // test_log();
    test_cryptor();
    test_ae();
    test_lru();

    SUMMARY();

    return main_ret;
}