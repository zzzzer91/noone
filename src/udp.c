/*
 * Created by zzzzer on 3/18/19.
 */

#include "udp.h"
#include "log.h"

void
udp_accept_conn(AeEventLoop *event_loop, int fd, void *data)
{
    LOGGER_ERROR("udp 尚不支持！");
}

void
udp_read_ssclient(AeEventLoop *event_loop, int fd, void *data)
{

}

void
udp_write_ssclient(AeEventLoop *event_loop, int fd, void *data)
{

}

void
udp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{

}

void
udp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{

}