/*
 * Created by zzzzer on 4/2/19.
 */

#include "manager.h"
#include <assert.h>

NooneManager *
init_manager(int user_count)
{
    assert(user_count > 0);

    NooneManager *m = malloc(sizeof(NooneManager));
    if (m == NULL) {
        return NULL;
    }

    m->users_info = malloc(user_count*sizeof(NooneUserInfo));
    if (m->users_info == NULL) {
        free(m);
        return NULL;
    }

    m->user_count = user_count;

    return m;
}