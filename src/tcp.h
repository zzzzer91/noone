/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_TCP_H_
#define _NOONE_TCP_H_

#include "ae.h"

void tcp_accept_conn(AeEventLoop *event_loop, int fd, void *data);

void tcp_read_client(AeEventLoop *event_loop, int fd, void *data);

void tcp_write_client(AeEventLoop *event_loop, int fd, void *data);

void tcp_read_remote(AeEventLoop *event_loop, int fd, void *data);

void tcp_write_remote(AeEventLoop *event_loop, int fd, void *data);

#endif  /* _NOONE_TCP_H_ */
