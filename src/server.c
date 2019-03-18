/*
 * Created by zzzzer on 2/11/19.
 */

#include "ae.h"
#include "socket.h"
#include "tcp.h"
#include "udp.h"
#include "cryptor.h"
#include "error.h"
#include "log.h"
#include <unistd.h>      /* close() */
#include <sys/epoll.h>

/* test */
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 9527
#define PASSWD (unsigned char *)"yousonofabitch"

int
main(int argc, char *argv[])
{
    SET_LOG_LEVEL(DEBUG);

    LOGGER_INFO("Noone started!");

    int server_fd = server_fd_init(SERVER_ADDR, SERVER_PORT);
    if (server_fd < 0) PANIC("init_server_fd");

    /* 设置非阻塞 */
    if (setnonblock(server_fd) < 0) PANIC("setnonblock");

    AeEventLoop *ae_ev_loop = ae_create_event_loop(AE_MAX_EVENTS);
    if (ae_ev_loop == NULL) PANIC("ae_create_event_loop");

    CryptorInfo *ci = init_cryptor_info("aes-128-ctr", PASSWD, 32, 16);
    if (ci == NULL) PANIC("init_cryptor_info");
    ae_ev_loop->extra_data = ci;

    int ret = ae_register_file_event(ae_ev_loop, server_fd, AE_IN, accept_conn, NULL, NULL);
    if (ret == -1) PANIC("ae_register_file_event");

    ae_run_loop(ae_ev_loop);

    free(ci);
    ae_delete_event_loop(ae_ev_loop);

    return 0;
}
