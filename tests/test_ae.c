/*
 * Created by zzzzer on 3/13/19.
 */

#include "ae.h"
#include "helper.h"

void
test_ae()
{
    AeEventLoop *ae_ev_loop = ae_create_event_loop(AE_MAX_EVENTS);

    int set_size = ae_get_event_set_size(ae_ev_loop);
    EXPECT_EQ_INT(AE_MAX_EVENTS, set_size);
    ae_stop_event_loop(ae_ev_loop);
    ae_delete_event_loop(ae_ev_loop);
}