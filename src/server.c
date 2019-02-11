/*
 * noone
 */

#include <unistd.h>      /* close() */
#include <sys/epoll.h>
#include "socket.h"
#include "epoll.h"
#include "error.h"
#include "tcp.h"
#include "log.h"

/* test */
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 9527

int
main(int argc, char *argv[])
{
    size_t i;

    set_log_level(DEBUG);
    
    logger_info("Noone started!");

    int server_fd = server_fd_init(SERVER_ADDR, SERVER_PORT);
    if (server_fd < 0) {
        panic("init_server_fd");
    }

    /* 设置非阻塞 */
    if (setnonblock(server_fd) < 0) {
        panic("setnonblock");
    }

    if (ep_init() < 0) {
        panic("ep_init");
    }

    if (ep_register(server_fd, EPOLLIN|EPOLLET, accept_conn) < 0) {
        panic("ep_register");
    }

    int ready_events_num;
    ep_event_ex *ep_ev_ptr;
    for(;;) {
        ready_events_num = ep_wait(-1);
        for (i = 0; i < ready_events_num; i++) {
            ep_ev_ptr = g_fd_to_event[g_ready_events[i].data.fd];
            if (g_ready_events[i].events & EPOLLIN) {
                logger_debug("EPOLLIN");
                ep_ev_ptr->callback(ep_ev_ptr);
            } else if (g_ready_events[i].events & EPOLLOUT) {
                logger_debug("EPOLLOUT");
                ep_ev_ptr->callback(ep_ev_ptr);
            }
        }
    }

    close(server_fd);
    ep_close();
    return 0;
}
