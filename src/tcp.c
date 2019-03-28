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

#define CLEAR_SSCLIENT(event_loop, nd) \
    do { \
        if (nd->ssclient_fd != -1) { \
            ae_unregister_event(event_loop, nd->ssclient_fd); \
            close(nd->ssclient_fd); \
        } \
        if (nd->remote_fd != -1) { \
            ae_unregister_event(event_loop, nd->remote_fd); \
            close(nd->remote_fd); \
        } \
        free_net_data(nd); \
        return; \
    } while (0)

#define CLEAR_REMOTE(event_loop, nd) \
    do { \
        ae_unregister_event(event_loop, nd->remote_fd); \
        close(nd->remote_fd); \
        nd->remote_fd = -1; \
    } while (0)

void
tcp_accept_conn(AeEventLoop *event_loop, int fd, void *data)
{
    struct sockaddr_in conn_addr;
    socklen_t conn_addr_len = sizeof(conn_addr);
    int conn_fd = accept(fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
    if (conn_fd < 0) {
        LOGGER_ERROR("fd: %d, tcp_accept_conn", conn_fd);
        return;
    }

    if (setnonblock(conn_fd) < 0) {
        LOGGER_ERROR("fd: %d, setnonblock", conn_fd);
        close(conn_fd);
        return;
    }

    NetData *nd = init_net_data();
    if (nd == NULL) {
        LOGGER_ERROR("fd: %d, init_net_data", conn_fd);
        close(conn_fd);
        return;
    }
    nd->ssclient_fd = conn_fd;

    if (ae_register_event(event_loop, conn_fd, AE_IN, tcp_read_ssclient, NULL, nd) < 0) {
        LOGGER_ERROR("fd: %d, ae_register_event", conn_fd);
        close(conn_fd);
        free_net_data(nd);
        return;
    }
}

static int
handle_stage_init(int fd, CryptorInfo *ci, NetData *nd)
{
    if (init_net_data_cipher(fd, ci, nd) < 0) {
        return -1;
    }

    nd->ss_stage = STAGE_ADDR;

    return 0;
}

static int
handle_stage_addr(NetData *nd)
{
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

    LOGGER_INFO("connecting %s:%s", nd->domain, nd->remote_port_str);
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

    if (nd->ss_stage == STAGE_INIT) {
        CryptorInfo *ci = event_loop->extra_data;
        if (handle_stage_init(fd, ci, nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_init", fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }

    int close_flag = read_net_data(fd, &nd->ciphertext);
    if (close_flag == 1) {  // ss_client 关闭
        LOGGER_DEBUG("fd: %d, read, ssclient close!", fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }

    size_t ret = DECRYPT(nd);
    if (ret == 0) {
        LOGGER_ERROR("fd: %d, DECRYPT", fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
    nd->ciphertext.len = 0;
    nd->plaintext.len += ret;

    if (nd->ss_stage == STAGE_ADDR) {
        if (handle_stage_addr(nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_addr", fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }

    if (nd->ss_stage == STAGE_HANDSHAKE) {
        if (handle_stage_handshake(nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_handshake", fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }

    if (nd->ss_stage == STAGE_STREAM && nd->plaintext.len > 0) {
        if (ae_register_event(event_loop, nd->remote_fd, AE_OUT, NULL, tcp_write_remote, nd) < 0) {
            LOGGER_ERROR("fd: %d, ae_register_event", fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = write_net_data(fd, &nd->plaintext);
    if (close_flag == 1) {
        LOGGER_DEBUG("fd: %d, write, remote close!", fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }

    if (nd->plaintext.len == 0) {  // 写完
        nd->plaintext.p = nd->plaintext.data;
        if (ae_modify_event(event_loop, fd, AE_IN, tcp_read_remote, NULL, nd) < 0) {
            LOGGER_ERROR("fd: %d, ae_modify_event", fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }
}

void
tcp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = read_net_data(fd, &nd->remote);
    if (close_flag == 1) {
        LOGGER_DEBUG("fd: %d, read, remote close!", fd);
        CLEAR_SSCLIENT(event_loop, nd);
        if (nd->remote.len == 0) {
            return;
        }
    }

    size_t ret = ENCRYPT(nd);
    if (ret == 0) {
        LOGGER_ERROR("fd: %d, ENCRYPT", fd);
        CLEAR_SSCLIENT(event_loop, nd);
        return;
    }
    nd->remote.len = 0;
    nd->remote_cipher.len += ret;

    if (ae_modify_event(event_loop, nd->ssclient_fd, AE_OUT, NULL, tcp_write_ssclient, nd) < 0) {
        LOGGER_ERROR("fd: %d, ae_modify_event", fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
}

void
tcp_write_ssclient(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    if (nd->is_iv_send == 0) {
        if (write(fd, nd->cipher_ctx.iv, nd->cipher_ctx.iv_len) < nd->cipher_ctx.iv_len) {
            LOGGER_ERROR("fd: %d, write iv error!", fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
        nd->is_iv_send = 1;
    }

    int close_flag = write_net_data(fd, &nd->remote_cipher);
    if (close_flag == 1) {
        LOGGER_DEBUG("fd: %d, write, ssclient close!", fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }

    if (nd->remote_cipher.len == 0) {
        nd->remote_cipher.p = nd->remote_cipher.data;
        if (ae_modify_event(event_loop, fd, AE_IN, tcp_read_ssclient, NULL, nd) < 0) {
            LOGGER_ERROR("fd: %d, ae_modify_event", fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }
}
