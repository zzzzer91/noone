#ifndef __TCP_H__
#define __TCP_H__

#include "epoll.h"

void accept_conn(ep_event_ex *self);

void read_ssclient(ep_event_ex *self);

void write_ssclient(ep_event_ex *self);

void read_remote(ep_event_ex *self);

void write_remote(ep_event_ex *self);

#endif  /* __TCP_H__ */
