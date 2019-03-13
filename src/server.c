/*
 * Created by zzzzer on 2/11/19.
 */

#include "socket.h"
#include "ae.h"
#include "error.h"
#include "tcp.h"
#include "log.h"
#include "cryptor.h"
#include <unistd.h>      /* close() */
#include <sys/epoll.h>

/* test */
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 9527
#define KEY (unsigned char *)"abc123"

int
main(int argc, char *argv[])
{
    SET_LOG_LEVEL(DEBUG);

    LOGGER_INFO("Noone started!");

    int server_fd = server_fd_init(SERVER_ADDR, SERVER_PORT);
    if (server_fd < 0) {
        PANIC("init_server_fd");
    }

    /* 设置非阻塞 */
    if (setnonblock(server_fd) < 0) {
        PANIC("setnonblock");
    }

    AeEventLoop *ae_ev_loop = ae_create_event_loop(AE_MAX_EVENTS);

    ae_create_file_event(ae_ev_loop, server_fd, AE_READABLE, accept_conn, NULL);

    ae_run_loop(ae_ev_loop);

    ae_delete_event_loop(ae_ev_loop);

    return 0;
}
