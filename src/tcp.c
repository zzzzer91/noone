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
handle_stage_init(CryptorInfo *ci, NetData *nd)
{
    if (init_net_data_cipher(ci, nd) < 0) {
        return -1;
    }

    size_t ret = DECRYPT(nd);
    if (ret == 0) {
        return -1;
    }
    nd->plaintext.len = ret;

    if (parse_net_data_header(nd) < 0) {
        return -1;
    }

    nd->ss_stage = STAGE_HANDSHAKE;

    return 0;
}

static int
handle_stage_handshake(NetData *nd)
{
    int fd = socket(nd->sockaddr.sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (setnonblock(fd) < 0) {
        close(fd);
        return -1;
    }

    if (connect(fd, &nd->sockaddr, nd->sockaddr_len) < 0) {
        if (errno != EINPROGRESS) {  // 设为非阻塞后，连接会返回 EINPROGRESS
            close(fd);
            return -1;
        }
    }

    nd->remote_fd = fd;

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
    size_t n = READN(fd, nd->ciphertext.data, BUF_CAPACITY, close_flag);
    nd->ciphertext.len += n;
    if (close_flag == 1) {  // ss_client 关闭
        goto CLEAR;
    }

    if (nd->ss_stage == STAGE_INIT) {
        CryptorInfo *ci = event_loop->extra_data;
        if (handle_stage_init(ci, nd) < 0) {
            goto CLEAR;
        }
    } else {
        size_t ret = DECRYPT(nd);
        if (ret == 0) {
            goto CLEAR;
        }
        nd->plaintext.len = ret;
    }

    nd->ciphertext.p = nd->ciphertext.data;
    nd->ciphertext.len = 0;

    if (nd->ss_stage == STAGE_HANDSHAKE) {
        if (handle_stage_handshake(nd) < 0) {
            goto CLEAR;
        }
    }

    if (nd->plaintext.len > 0) {
        if (ae_register_event(event_loop, nd->remote_fd ,
                AE_OUT, NULL, tcp_write_remote, nd) < 0) {
            goto CLEAR;
        }
    } else {
        nd->plaintext.p = nd->plaintext.data;
    }

    return;

CLEAR:
    free_net_data(nd);
    ae_unregister_event(event_loop, fd);
}

void
tcp_write_ssclient(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    size_t ret = ENCRYPT(nd);
    if (ret == 0) {
        return;
    }
    nd->remote_cipher.len = ret;
    nd->remote.p = nd->remote.data;
    nd->remote.len = 0;

    if (nd->is_iv_send == 0) {
        write(fd, nd->cipher_ctx.iv, nd->cipher_ctx.iv_len);
        nd->is_iv_send = 1;
    }

    int close_flag = 0;
    ret = WRITEN(fd, nd->remote_cipher.p, nd->remote_cipher.len, close_flag);
    if (close_flag == 1) {
        // TODO
    }

    nd->remote_cipher.len -= ret;
    if (nd->remote_cipher.len == 0) {
        nd->remote_cipher.p = nd->remote_cipher.data;
    } else {
        nd->remote_cipher.p += ret;
    }
    ae_modify_event(event_loop, fd, AE_IN, tcp_read_ssclient, NULL, nd);
}

void
tcp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;
    int close_flag = 0;
    size_t ret = READN(fd, nd->remote.p, BUF_CAPACITY, close_flag);
    if (close_flag == 1) {
        close(fd);
        ae_unregister_event(event_loop, fd);
    }
    nd->remote.len = ret;

    ae_modify_event(event_loop, nd->ssclient_fd, AE_OUT, NULL, tcp_write_ssclient, nd);
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = 0;
    size_t n = WRITEN(fd, nd->plaintext.p, nd->plaintext.len, close_flag);
    if (close_flag == 1) {
        close(fd);
        ae_unregister_event(event_loop, fd);
    }

    nd->plaintext.len -= n;
    if (nd->plaintext.len == 0) {
        nd->plaintext.p = nd->plaintext.data;
    } else {
        nd->plaintext.p += n;
    }

    ae_modify_event(event_loop, fd, AE_IN, tcp_read_remote, NULL, nd);
}
