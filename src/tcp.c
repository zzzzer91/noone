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

#define CLEAR(event_loop, nd) \
    do { \
        if (nd->ssclient_fd != -1) { \
            close(nd->ssclient_fd); \
            ae_unregister_event(event_loop, nd->ssclient_fd); \
        } \
        if (nd->remote_fd != -1) { \
            close(nd->remote_fd); \
            ae_unregister_event(event_loop, nd->remote_fd); \
        } \
        free_net_data(nd); \
        return; \
    } while (0)

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
        close(conn_fd);
        free_net_data(nd);
        return;
    }
}

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
    int fd = socket(nd->addr_listp->ai_family, nd->addr_listp->ai_socktype, 0);
    if (fd < 0) {
        return -1;
    }
    if (setnonblock(fd) < 0) {
        close(fd);
        return -1;
    }

    LOGGER_DEBUG("connecting %s:%s", nd->domain, nd->remote_port_str);
    if (connect(fd, nd->addr_listp->ai_addr, nd->addr_listp->ai_addrlen) < 0) {
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
tcp_read_ssclient(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = READN(fd, nd->ciphertext);
    if (close_flag == 1) {  // ss_client 关闭
        LOGGER_DEBUG("read, ssclient close!");
        CLEAR(event_loop, nd);
    }
    // LOGGER_DEBUG("fd: %d, read: %ld", fd, n);

    if (nd->ss_stage == STAGE_INIT) {
        CryptorInfo *ci = event_loop->extra_data;
        if (handle_stage_init(ci, nd) < 0) {
            LOGGER_ERROR("handle_stage_init");
            CLEAR(event_loop, nd);
        }
    } else {
        size_t ret = DECRYPT(nd);
        if (ret == 0) {
            LOGGER_ERROR("DECRYPT");
            CLEAR(event_loop, nd);
        }
        nd->plaintext.len = ret;
    }

    nd->ciphertext.p = nd->ciphertext.data;
    nd->ciphertext.len = 0;

    if (nd->ss_stage == STAGE_HANDSHAKE) {
        if (handle_stage_handshake(nd) < 0) {
            LOGGER_ERROR("handle_stage_handshake");
            CLEAR(event_loop, nd);
        }
    }

    if (nd->plaintext.len > 0) {
        if (ae_register_event(event_loop, nd->remote_fd ,
                AE_OUT, NULL, tcp_write_remote, nd) < 0) {
            LOGGER_ERROR("ae_register_event");
            CLEAR(event_loop, nd);
        }
    } else {
        nd->plaintext.p = nd->plaintext.data;
    }
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = WRITEN(fd, nd->plaintext);
    if (close_flag == 1) {
        LOGGER_DEBUG("write, remote close!");
        close(fd);
        ae_unregister_event(event_loop, fd);
    }

    if (nd->plaintext.len == 0) {  // 写完
        nd->plaintext.p = nd->plaintext.data;
        ae_modify_event(event_loop, fd, AE_IN, tcp_read_remote, NULL, nd);
    }
}

void
tcp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = READN(fd, nd->remote);
    if (close_flag == 1) {
        LOGGER_DEBUG("read, remote close!");
        close(fd);
        ae_unregister_event(event_loop, fd);
    }

    size_t ret = ENCRYPT(nd);
    if (ret == 0) {
        LOGGER_ERROR("ENCRYPT");
        // TODO
    }
    nd->remote_cipher.len += ret;
    nd->remote.p = nd->remote.data;
    nd->remote.len = 0;

    ae_modify_event(event_loop, nd->ssclient_fd, AE_OUT, NULL, tcp_write_ssclient, nd);
}

void
tcp_write_ssclient(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    if (nd->is_iv_send == 0) {
        write(fd, nd->cipher_ctx.iv, nd->cipher_ctx.iv_len);
        // TODO
        nd->is_iv_send = 1;
    }

    int close_flag = WRITEN(fd, nd->remote_cipher);
    if (close_flag == 1) {
        LOGGER_DEBUG("write, ssclient close!");
        CLEAR(event_loop, nd);
    }

    if (nd->remote_cipher.len == 0) {
        nd->remote_cipher.p = nd->remote_cipher.data;
        ae_modify_event(event_loop, fd, AE_IN, tcp_read_ssclient, NULL, nd);
    }
}
