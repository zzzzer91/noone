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
#include "lru.h"
#include "manager.h"
#include <unistd.h>
#include <signal.h>

/* test */
#define PASSWD (unsigned char *)"123123"

int
main(int argc, char *argv[])
{
    LOGGER_INFO("Noone started!");

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        PANIC("signal");
    }

    AeEventLoop *ae_ev_loop = ae_create_event_loop(AE_MAX_EVENTS);
    if (ae_ev_loop == NULL) {
        PANIC("ae_create_event_loop");
    }

    int tcp_server_fd, udp_server_fd = -1;
    char *server_port_list[] = {"9529"};
    NooneManager *noone_manager = init_manager(1);
    if (noone_manager == NULL) {
        PANIC("init_users_info");
    }
    for (int i = 0; i < noone_manager->user_count; i++) {
        NooneUserInfo *ui = &noone_manager->users_info[i];

        ui->user_idx = i;

        NooneCryptorInfo *ci = init_noone_cryptor_info("aes-128-ctr", PASSWD, 32, 16);
        if (ci == NULL) {
            PANIC("init_noone_cryptor_info");
        }
        ui->cryptor_info = ci;

        LruCache *lc = lru_cache_init(10);
        if (lc == NULL) {
            PANIC("init_lru_cache");
        }
        ui->lru_cache = lc;

        // tcp
        tcp_server_fd = tcp_server_fd_init(server_port_list[i]);
        if (tcp_server_fd < 0) {
            PANIC("tcp_server_fd_init");
        }
        if (setnonblock(tcp_server_fd) < 0) {
            PANIC("setnonblock");
        }
        int ret = ae_register_event(ae_ev_loop, tcp_server_fd,
                AE_IN, tcp_accept_conn, NULL, ui);
        if (ret  < 0) {
            PANIC("ae_register_event");
        }
        ui->tcp_server_fd = tcp_server_fd;

        // udp 可以和 tcp 绑定同一端口
        udp_server_fd = udp_server_fd_init(server_port_list[i]);
        if (udp_server_fd < 0) {
            PANIC("udp_server_fd_init");
        }
        if (setnonblock(udp_server_fd) < 0) {
            PANIC("setnonblock");
        }
        ret = ae_register_event(ae_ev_loop, udp_server_fd,
                AE_IN, udp_accept_conn, NULL, ui);
        if (ret < 0) {
            PANIC("ae_register_event");
        }
        ui->udp_server_fd = udp_server_fd;
    }
    ae_ev_loop->max_listen_fd = udp_server_fd;
    ae_ev_loop->extra_data = noone_manager;

    ae_run_loop(ae_ev_loop, check_last_active);

    return 0;
}
