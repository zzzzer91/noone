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
#include <arpa/inet.h>   /* inet_ntoa() */
#include <netdb.h>

static void
handle_stage_init(AeEventLoop *event_loop, int fd, NetData *nd)
{
    LOGGER_DEBUG("fd: %d, STAGE_INIT", fd);

    CryptorInfo *ci = event_loop->extra_data;
    nd->cipher_ctx.iv_len = ci->iv_len;
    memcpy(nd->cipher_ctx.iv, nd->ciphertext.data, ci->iv_len);
    nd->ciphertext.idx += ci->iv_len;
    nd->ciphertext.len -= ci->iv_len;
    nd->cipher_ctx.encrypt_ctx = INIT_ENCRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);
    nd->cipher_ctx.decrypt_ctx = INIT_DECRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);
    nd->plaintext.len = DECRYPT(nd);
    if (nd->plaintext.len < 0) {
        // TODO
    }
    int atty = nd->plaintext.data[nd->plaintext.idx];
    nd->plaintext.idx += 1;
    nd->plaintext.len -= 1;
    if (atty == ATYP_DOMAIN) {
        size_t domain_len = nd->plaintext.data[nd->plaintext.idx];  // 域名长度
        nd->plaintext.idx += 1;
        char domain[65];
        memcpy(domain, nd->plaintext.data+nd->plaintext.idx, domain_len);
        domain[domain_len] = 0;  // 加上 '\0'
        nd->plaintext.idx += domain_len;
        nd->plaintext.len -= domain_len;
        LOGGER_DEBUG("%s", domain);

        struct addrinfo hints = {}, *listp;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV; /* 强制只能填端口号, 而不能是端口号对应的服务名 */
        hints.ai_flags |= AI_ADDRCONFIG; /* 只有当主机配置IPv4时, 才返回IPv4地址, IPv6类似 */
        int ret2 = getaddrinfo(domain, NULL, &hints, &listp);
        if (ret2 != 0) {
            LOGGER_ERROR("%s", gai_strerror(ret2));
            exit(1);
        }
        memcpy(&nd->sockaddr, &listp->ai_addr, 14);
        nd->sockaddr.sa_family = (sa_family_t)listp->ai_family;
        nd->sockaddr_len = listp->ai_addrlen;

        freeaddrinfo(listp);

        nd->ss_stage = STAGE_HANDSHAKE;
    } else if (atty == ATYP_IPV4) {
        nd->sockaddr.sa_family = AF_INET;
        struct in_addr addr;
        memcpy(&addr, nd->plaintext.data+nd->plaintext.idx, 4);
        memcpy(nd->sockaddr.sa_data+2, &addr, 4);
        nd->ip = inet_ntoa(addr);
        LOGGER_DEBUG("%s", nd->ip);
        nd->plaintext.idx += 4;
        nd->plaintext.len -= 4;
        nd->sockaddr_len = sizeof(struct sockaddr_in);
        nd->ss_stage = STAGE_HANDSHAKE;
    } else if (atty == ATYP_IPV6) {
        // TODO
        nd->ss_stage = STAGE_HANDSHAKE;
    } else {
        LOGGER_ERROR("ATYP error！");
        return;
    }

    uint16_t port;
    memcpy(&port, nd->plaintext.data+nd->plaintext.idx, 2);
    memcpy(nd->sockaddr.sa_data, &port, 2);
    nd->plaintext.idx += 2;
    nd->plaintext.len -= 2;
    nd->port = ntohs(port);
    LOGGER_DEBUG("%d", nd->port);
}

static void
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
        free(nd);
        close(conn_fd);
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

    /*
     * 开头有两个字段
     * - ATYP 字段：address type 的缩写，取值为：
     *     0x01：IPv4
     *     0x03：域名
     *     0x04：IPv6
     *
     * - DST.ADDR 字段：destination address 的缩写，取值随 ATYP 变化：
     *
     *     ATYP == 0x01：4 个字节的 IPv4 地址
     *     ATYP == 0x03：1 个字节表示域名长度，紧随其后的是对应的域名
     *     ATYP == 0x04：16 个字节的 IPv6 地址
     *     DST.PORT 字段：目的服务器的端口
     */
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
    size_t n = WRITEN(fd, nd->remote_cipher.data+nd->remote_cipher.idx, nd->remote_cipher.len, close_flag);
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
    nd->remote.len = READN(fd, nd->remote.data+nd->remote.idx, nd->remote.capacity, close_flag);

    ae_modify_event(event_loop, nd->ssclient_fd, AE_OUT, NULL, tcp_write_ssclient, nd);
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;
    int close_flag = 0;
    size_t n = WRITEN(fd, nd->plaintext.data+nd->plaintext.idx, nd->plaintext.len, close_flag);
    nd->plaintext.len -= n;
    if (nd->plaintext.len == 0) {
        nd->plaintext.idx = 0;
    } else {
        nd->plaintext.idx += n;
    }
    ae_modify_event(event_loop, fd, AE_IN, tcp_read_remote, NULL, nd);
}
