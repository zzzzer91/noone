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
#include "transport.h"
#include <unistd.h>
#include <signal.h>

/* test */
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 9527
#define PASSWD (unsigned char *)"123123"

int
main(int argc, char *argv[])
{
    LOGGER_INFO("Noone started!");

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        PANIC("signal");
    }

    // tcp
    int tcp_server_fd = tcp_server_fd_init(SERVER_ADDR, SERVER_PORT);
    if (tcp_server_fd < 0) {
        PANIC("tcp_server_fd_init");
    }
    if (setnonblock(tcp_server_fd) < 0) {
        PANIC("setnonblock");
    }

    // udp 可以和 tcp 绑定同一端口
    int udp_server_fd = udp_server_fd_init(SERVER_ADDR, SERVER_PORT);
    if (udp_server_fd < 0) {
        PANIC("udp_server_fd_init");
    }
    if (setnonblock(udp_server_fd) < 0) {
        PANIC("setnonblock");
    }

    AeEventLoop *ae_ev_loop = ae_create_event_loop(AE_MAX_EVENTS);
    if (ae_ev_loop == NULL) {
        PANIC("ae_create_event_loop");
    }

    CryptorInfo *ci = init_cryptor_info("aes-128-ctr", PASSWD, 32, 16);
    if (ci == NULL) {
        PANIC("init_cryptor_info");
    }
    ae_ev_loop->extra_data = ci;

    int ret = ae_register_event(ae_ev_loop, tcp_server_fd, AE_IN, tcp_accept_conn, NULL, NULL);
    if (ret  < 0) {
        PANIC("ae_register_event");
    }

    ret = ae_register_event(ae_ev_loop, udp_server_fd, AE_IN, udp_accept_conn, NULL, NULL);
    if (ret < 0) {
        PANIC("ae_register_event");
    }

    ae_run_loop(ae_ev_loop, check_last_active);

    free(ci);
    close(tcp_server_fd);
    close(udp_server_fd);
    ae_delete_event_loop(ae_ev_loop);

    return 0;
}
