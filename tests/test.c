/*
 * Created by zzzzer on 3/11/19.
 */

#include "helper.h"
#include "test_log.c"
#include "test_error.c"
#include "test_cryptor.c"
#include "test_ae.c"
#include "test_hashtable.c"
#include "test_lru.c"

int
main(void)
{
    // test_log();
    test_cryptor();
    test_ae();
    test_hashtable();
    test_lru();
    // test_error();

    SUMMARY();

    return main_ret;
}