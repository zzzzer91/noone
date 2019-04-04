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
#include "lru.h"
#include "manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>      /* close() */
#include <sys/socket.h>  /* accept() */
#include <netinet/in.h>  /* struct sockaddr_in */

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
    nd->user_info = (NooneUserInfo *)data;

    if (ae_register_event(event_loop, conn_fd, AE_IN, tcp_read_ssclient, NULL, nd) < 0) {
        LOGGER_ERROR("fd: %d, ae_register_event", conn_fd);
        close(conn_fd);
        free_net_data(nd);
        return;
    }
}

static int
handle_stage_init(int fd, NooneCryptorInfo *ci, NetData *nd)
{
    if (init_net_data_cipher(fd, ci, nd) < 0) {
        return -1;
    }

    nd->ss_stage = STAGE_HEADER;

    return 0;
}

static int
handle_stage_header(LruCache *lc, NetData *nd)
{
    if (parse_net_data_header(lc, nd) < 0) {
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

    // 注意：当设置非阻塞 socket 后，tcp 三次握手会异步进行，
    // 所以可能会出现三次握手还未完成，就进行 write，
    // 此时 write 会把 errno 置为 EAGAIN
    LOGGER_INFO("fd: %d, connecting %s:%s", nd->ssclient_fd, nd->remote_domain, nd->remote_port);
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
        if (handle_stage_init(fd, nd->user_info->cryptor_info, nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_init", nd->ssclient_fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }

    int close_flag = read_net_data(fd, &nd->ciphertext);
    if (close_flag == 1) {  // ss_client 关闭
        LOGGER_DEBUG("fd: %d, read, ssclient close!", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }

    size_t ret = DECRYPT(nd);
    if (ret == 0) {
        LOGGER_ERROR("fd: %d, DECRYPT", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
    nd->plaintext.len = ret;

    if (nd->ss_stage == STAGE_HEADER) {
        if (handle_stage_header(nd->user_info->lru_cache, nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_header", nd->ssclient_fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }

    if (nd->ss_stage == STAGE_HANDSHAKE) {
        if (handle_stage_handshake(nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_handshake", fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }

    if (nd->plaintext.len == 0) {  // 解析完头部后，没有数据了
        return;
    }

    // 不需要考虑重复注册问题
    // ae_register_event() 中有相应处理逻辑
    if (ae_register_event(event_loop, nd->remote_fd,
            AE_OUT, NULL, tcp_write_remote, nd) < 0) {

        LOGGER_ERROR("fd: %d, tcp_read_ssclient, ae_register_event", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
    // 相当于不触发这个事件
    if (ae_register_event(event_loop, fd,
            EPOLLERR, NULL, NULL, NULL) < 0) {
        LOGGER_ERROR("fd: %d, tcp_read_ssclient, ae_unregister_event", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = write_net_data(fd, &nd->plaintext);
    if (close_flag == 1) {
        LOGGER_DEBUG("fd: %d, write, remote close!", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
    if (nd->plaintext.len > 0) {  // 没有写完，不能改变事件，要继续写
        return;
    }

    if (ae_register_event(event_loop, fd, AE_IN, tcp_read_remote, NULL, nd) < 0) {
        LOGGER_ERROR("fd: %d, tcp_write_remote, ae_register_event", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }

    if (ae_register_event(event_loop, nd->ssclient_fd,
                          AE_IN, tcp_read_ssclient, NULL, nd) < 0) {

        LOGGER_ERROR("fd: %d, tcp_write_remote, ae_register_event", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
}

void
tcp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = read_net_data(fd, &nd->remote);
    if (close_flag == 1) {
        LOGGER_DEBUG("fd: %d, read, remote close!", nd->ssclient_fd);
        if (nd->remote.len != 0) {  // 读到对端关闭, 但还有数据发给 ss_client
            CLEAR_REMOTE(event_loop, nd);
        } else {
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }

    size_t ret = ENCRYPT(nd);
    if (ret == 0) {
        LOGGER_ERROR("fd: %d, ENCRYPT", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
        return;
    }
    nd->remote_cipher.len = ret;

    if (ae_register_event(event_loop, nd->ssclient_fd,
            AE_OUT, NULL, tcp_write_ssclient, nd) < 0) {

        LOGGER_ERROR("fd: %d, tcp_read_remote, ae_register_event", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
    if (nd->remote_fd != -1) {  // 对端已关闭
        if (ae_register_event(event_loop, fd,
                              EPOLLERR, NULL, NULL, NULL) < 0) {
            LOGGER_ERROR("fd: %d, tcp_read_remote, ae_unregister_event", nd->ssclient_fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }
}

void
tcp_write_ssclient(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    if (nd->is_iv_send == 0) {
        if (write(fd, nd->cipher_ctx->iv, nd->cipher_ctx->iv_len) < nd->cipher_ctx->iv_len) {
            LOGGER_ERROR("fd: %d, write iv error!", nd->ssclient_fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
        nd->is_iv_send = 1;
    }

    int close_flag = write_net_data(fd, &nd->remote_cipher);
    if (close_flag == 1) {
        LOGGER_DEBUG("fd: %d, write, ssclient close!", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
    if (nd->remote_cipher.len > 0) {  // 还有东西可写
        return;
    }

    if (ae_register_event(event_loop, fd, AE_IN, tcp_read_ssclient, NULL, nd) < 0) {
        LOGGER_ERROR("fd: %d, tcp_write_ssclient, ae_register_event", nd->ssclient_fd);
        CLEAR_SSCLIENT(event_loop, nd);
    }
    if (nd->remote_fd != -1) {  // 对端已关闭
        if (ae_register_event(event_loop, nd->remote_fd,
                AE_IN, tcp_read_remote, NULL, nd) < 0) {

            LOGGER_ERROR("fd: %d, tcp_write_ssclient, ae_register_event", nd->ssclient_fd);
            CLEAR_SSCLIENT(event_loop, nd);
        }
    }
}
