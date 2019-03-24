/*
 * Created by zzzzer on 2/11/19.
 */

#include "tcp.h"
#include "transport.h"
#include "socket.h"
#include "rio.h"
#include "ae.h"
#include "error.h"
#include "cryptor.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>      /* close() */
#include <sys/socket.h>  /* accept() */
#include <netinet/in.h>  /* struct sockaddr_in */
#include <arpa/inet.h>   /* inet_ntoa() */
#include <netdb.h>

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

    ssize_t ret = rio_readn(fd, nd->ciphertext, sizeof(nd->ciphertext));
    if (ret == 0) {
        LOGGER_DEBUG("ss_client close!");
        exit(1);
        // clear(fd);
    } else if (ret < 0) {
        LOGGER_ERROR("rio_readn");
        return;
    }
    nd->ciphertext_len = (size_t)ret;

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
        CryptorInfo *ci = event_loop->extra_data;
        nd->iv_len = ci->iv_len;
        memcpy(nd->iv, nd->ciphertext, ci->iv_len);
        nd->ciphertext_p += ci->iv_len;
        nd->ciphertext_len -= ci->iv_len;
        nd->encrypt_ctx = INIT_ENCRYPT_CTX(get_cipher("aes-128-ctr"), ci->key, nd->iv);
        nd->decrypt_ctx = INIT_DECRYPT_CTX(get_cipher("aes-128-ctr"), ci->key, nd->iv);
        nd->plaintext_len = DECRYPT(nd);
        if (nd->plaintext_len < 0) {
            //
        }
        int atty = nd->plaintext_p[0];
        nd->plaintext_p += 1;
        if (atty == ATYP_DOMAIN) {
            size_t domain_len = nd->plaintext_p[0];  // 域名长度
            nd->plaintext_p += 1;
            char domain[65];
            memcpy(domain, nd->plaintext_p, domain_len);
            domain[domain_len] = 0;  // 加上 '\0'
            nd->plaintext_p += domain_len;
            nd->plaintext_len -= domain_len;
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
            nd->sockaddr.sin_family = (sa_family_t)listp->ai_family;
            nd->sockaddr_len = listp->ai_addrlen;

            freeaddrinfo(listp);

            nd->ss_stage = STAGE_CONNECTING;
        } else if (atty == ATYP_IPV4) {
            nd->sockaddr.sin_family = AF_INET;
            memcpy(&nd->sockaddr.sin_addr.s_addr, nd->plaintext_p, 4);
            LOGGER_DEBUG("%s", inet_ntoa(nd->sockaddr.sin_addr));
            nd->plaintext_p += 4;
            nd->plaintext_len -= 4;
            nd->sockaddr_len = sizeof(nd->sockaddr);
            nd->ss_stage = STAGE_CONNECTING;
        } else if (atty == ATYP_IPV6) {
//          // TODO
            nd->ss_stage = STAGE_CONNECTING;
        } else {
            LOGGER_ERROR("ATYP error！");
        }

        memcpy(&nd->sockaddr.sin_port, nd->plaintext_p, 2);
        nd->plaintext_p += 2;
        nd->plaintext_len -= 2;
        LOGGER_DEBUG("%d", ntohs(nd->sockaddr.sin_port));
    } else {
        nd->plaintext_len = DECRYPT(nd);
    }

    nd->ciphertext_p = nd->ciphertext;
    nd->ciphertext_len = 0;
    if (nd->ss_stage == STAGE_CONNECTING) {

        LOGGER_DEBUG("STAGE_CONNECTING");
        int remote_fd = socket(nd->sockaddr.sin_family, SOCK_STREAM, 0);
        if (remote_fd < 0) {
            PANIC("remote_fd");
        }
        setnonblock(remote_fd);

        nd->remote_fd = remote_fd;

        connect(remote_fd, (struct sockaddr *)&nd->sockaddr, nd->sockaddr_len);

        ae_register_event(event_loop, remote_fd,
                AE_OUT, NULL, tcp_write_remote, nd);

        nd->ss_stage = STAGE_STREAM;
    }
    // free(nd->decrypt_ctx);

    // 对端关闭
//    ae_unregister_event(event_loop, fd);
//    close(fd);
//    free(nd);
}

void
tcp_write_ssclient(AeEventLoop *event_loop, int fd, void *data)
{

    NetData *nd = data;
    ssize_t len = ENCRYPT(nd);
    ssize_t ret;
    if (nd->is_iv_send == 0) {
        ret = rio_writen(fd, nd->iv, nd->iv_len);
        nd->is_iv_send = 1;
    }
    ret = rio_writen(fd, nd->remote_buf, len);
    LOGGER_DEBUG("tcp_write_ssclient->rio_writen: %ld", ret);
    ae_modify_event(event_loop, fd, AE_IN, tcp_read_ssclient, NULL, nd);
}

void
tcp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;
    ssize_t ret = rio_readn(fd, nd->remote_buf, sizeof(nd->remote_buf));
    if (ret == 0) {
        LOGGER_DEBUG("remote close!");
        exit(1);
        // clear(fd);
    } else if (ret < 0) {
        LOGGER_ERROR("rio_readn");
        return;
    }
    nd->remote_buf_len = (size_t)ret;

    ae_modify_event(event_loop, nd->ssclient_fd, AE_OUT, NULL, tcp_write_ssclient, nd);
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    ssize_t ret = rio_writen(fd, nd->plaintext_p, nd->plaintext_len);
    if (ret < 0) {
        PANIC("rio_writen");
    }
    LOGGER_DEBUG("tcp_write_remote->rio_writen: %ld", ret);
    nd->plaintext_len -= ret;
    if (nd->plaintext_len == 0) {
        nd->plaintext_p = nd->plaintext;
    } else {
        nd->plaintext_p += ret;
    }
    ae_modify_event(event_loop, fd, AE_IN, tcp_read_remote, NULL, nd);
}
