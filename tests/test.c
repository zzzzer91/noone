/*
 * Created by zzzzer on 3/11/19.
 */

#include "helper.h"
#include "test_cryptor.c"
#include "test_ae.c"
#include "test_hashtable.c"
#include "test_lru.c"
#include "test_dns.c"

int main(void) {
    // test_log();
    test_cryptor();
    test_ae();
    test_hashtable();
    test_lru();
    test_dns();
    // test_error();

    SUMMARY();

    return main_ret;
}