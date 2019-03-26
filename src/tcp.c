/*
 * Created by zzzzer on 2/11/19.
 */

#include "tcp.h"
#include "transport.h"
#include "socket.h"
#include "ae.h"
#include "error.h"
#include "cryptor.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>      /* close() */
#include <sys/socket.h>  /* accept() */
#include <netinet/in.h>  /* struct sockaddr_in */

static int
handle_stage_init(AeEventLoop *event_loop, int fd, NetData *nd)
{
    LOGGER_DEBUG("fd: %d, STAGE_INIT", fd);

    init_net_data_cipher(event_loop->extra_data, nd);

    nd->plaintext.len = DECRYPT(nd);
    if (nd->plaintext.len < 0) {
        // TODO
    }

    int ret = parse_net_data_header(nd);
    if (ret < 0) {
        // TODO
    }

    nd->ss_stage = STAGE_HANDSHAKE;

    return 0;
}

static int
handle_stage_handshake(AeEventLoop *event_loop, int fd, NetData *nd)
{
    LOGGER_DEBUG("fd: %d, STAGE_HANDSHAKE", fd);
    nd->remote_fd = socket(nd->sockaddr.sa_family, SOCK_STREAM, 0);
    if (nd->remote_fd < 0) {
        PANIC("remote_fd");
    }
    setnonblock(nd->remote_fd);

    connect(nd->remote_fd, &nd->sockaddr, nd->sockaddr_len);

    nd->ss_stage = STAGE_STREAM;

    return 0;
}

void
tcp_accept_conn(AeEventLoop *event_loop, int fd, void *data)
{
    struct sockaddr_in conn_addr;
    socklen_t conn_addr_len = sizeof(conn_addr);
    int conn_fd = accept(fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
    if (conn_fd < 0) {
        LOGGER_ERROR("tcp_accept_conn");
        return;
    }

    if (setnonblock(conn_fd) < 0) {
        LOGGER_ERROR("setnonblock");
        close(conn_fd);
        return;
    }

    NetData *nd = init_net_data();
    if (nd == NULL) {
        LOGGER_ERROR("init_net_data");
        close(conn_fd);
        return;
    }
    nd->ssclient_fd = conn_fd;

    if (ae_register_event(event_loop, conn_fd, AE_IN, tcp_read_ssclient, NULL, nd) < 0) {
        LOGGER_ERROR("init_net_data");
        free_net_data(nd);
        return;
    }
}

void
tcp_read_ssclient(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = 0;
    size_t n = READN(fd, nd->ciphertext.data, nd->ciphertext.capacity, close_flag);
    nd->ciphertext.len += n;
    if (close_flag == 1) {  // ss_client 关闭
        close(fd);
        free(nd);
        ae_unregister_event(event_loop, fd);
    }

    if (nd->ss_stage == STAGE_INIT) {
        handle_stage_init(event_loop, fd, nd);
    } else {
        nd->plaintext.len = DECRYPT(nd);
    }

    nd->ciphertext.idx = 0;
    nd->ciphertext.len = 0;

    if (nd->ss_stage == STAGE_HANDSHAKE) {
        handle_stage_handshake(event_loop, fd, nd);
    }

    if (nd->plaintext.len > 0) {
        ae_register_event(event_loop, nd->remote_fd , AE_OUT, NULL, tcp_write_remote, nd);
    } else {
        nd->plaintext.idx = 0;
    }
}

void
tcp_write_ssclient(AeEventLoop *event_loop, int fd, void *data)
{

    NetData *nd = data;
    nd->remote_cipher.len = ENCRYPT(nd);
    nd->remote.len = 0;
    nd->remote.idx = 0;

    if (nd->is_iv_send == 0) {
        write(fd, nd->cipher_ctx.iv, nd->cipher_ctx.iv_len);
        nd->is_iv_send = 1;
    }

    int close_flag = 0;
    size_t n = WRITEN(fd, nd->remote_cipher.data+nd->remote_cipher.idx,
            nd->remote_cipher.len, close_flag);
    nd->remote_cipher.len -= n;
    if (nd->remote_cipher.len == 0) {
        nd->remote_cipher.idx = 0;
    } else {
        nd->remote_cipher.idx += n;
    }
    ae_modify_event(event_loop, fd, AE_IN, tcp_read_ssclient, NULL, nd);
}

void
tcp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;
    int close_flag = 0;
    nd->remote.len = READN(fd, nd->remote.data+nd->remote.idx,
            nd->remote.capacity, close_flag);

    ae_modify_event(event_loop, nd->ssclient_fd, AE_OUT, NULL, tcp_write_ssclient, nd);
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;
    int close_flag = 0;
    size_t n = WRITEN(fd, nd->plaintext.data+nd->plaintext.idx,
            nd->plaintext.len, close_flag);
    nd->plaintext.len -= n;
    if (nd->plaintext.len == 0) {
        nd->plaintext.idx = 0;
    } else {
        nd->plaintext.idx += n;
    }
    ae_modify_event(event_loop, fd, AE_IN, tcp_read_remote, NULL, nd);
}
