/*
 * Created by zzzzer on 3/18/19.
 */

#ifndef _NOONE_UDP_H_
#define _NOONE_UDP_H_

#include "ae.h"

void udp_accept_conn(AeEventLoop *event_loop, int fd, void *data);

void udp_write_client(AeEventLoop *event_loop, int fd, void *data);

void udp_read_remote(AeEventLoop *event_loop, int fd, void *data);

void udp_write_remote(AeEventLoop *event_loop, int fd, void *data);

#endif  /* _NOONE_UDP_H_ */
