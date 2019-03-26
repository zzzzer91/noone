/*
 * Created by zzzzer on 3/18/19.
 */

#include "transport.h"
#include "log.h"
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>   /* inet_ntoa() */

static void
init_buffer(Buffer *buf)
{
    buf->p = buf->data;
    buf->len = 0;
}

NetData *
init_net_data()
{
    NetData *nd = malloc(sizeof(NetData));
    if (nd == NULL) {
        return NULL;
    }

    nd->ssclient_fd = -1;
    nd->remote_fd = -1;

    nd->ss_stage = STAGE_INIT;
    nd->cipher_ctx.encrypt_ctx = NULL;
    nd->cipher_ctx.decrypt_ctx = NULL;

    init_buffer(&nd->ciphertext);
    init_buffer(&nd->plaintext);
    init_buffer(&nd->remote);
    init_buffer(&nd->remote_cipher);
    nd->is_iv_send = 0;

    return nd;
}

int
init_net_data_cipher(CryptorInfo *ci, NetData *nd)
{
    nd->cipher_ctx.iv_len = ci->iv_len;
    memcpy(nd->cipher_ctx.iv, nd->ciphertext.data, ci->iv_len);
    nd->ciphertext.p += ci->iv_len;
    nd->ciphertext.len -= ci->iv_len;

    EVP_CIPHER_CTX *ctx;
    ctx = INIT_ENCRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);
    if (ctx == NULL) {
        return -1;
    }
    nd->cipher_ctx.encrypt_ctx = ctx;

    ctx = INIT_DECRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);
    if (ctx == NULL) {
        return -1;
    }
    nd->cipher_ctx.decrypt_ctx = ctx;

    return 0;
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
int
parse_net_data_header(NetData *nd)
{
    int atty = nd->plaintext.p[0];
    nd->plaintext.p += 1;
    nd->plaintext.len -= 1;
    if (atty == ATYP_DOMAIN) {
        size_t domain_len = nd->plaintext.p[0];  // 域名长度
        nd->plaintext.p += 1;
        nd->plaintext.len -= 1;
        char domain[65];
        memcpy(domain, nd->plaintext.p, domain_len);
        domain[domain_len] = 0;  // 加上 '\0'
        nd->plaintext.p += domain_len;
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
    } else if (atty == ATYP_IPV4) {
        nd->sockaddr.sa_family = AF_INET;
        struct in_addr addr;
        memcpy(&addr, nd->plaintext.p, 4);
        nd->plaintext.p += 4;
        nd->plaintext.len -= 4;
        memcpy(nd->sockaddr.sa_data+2, &addr, 4);
        nd->ip = inet_ntoa(addr);
        LOGGER_DEBUG("%s", nd->ip);
        nd->sockaddr_len = sizeof(struct sockaddr_in);
    } else if (atty == ATYP_IPV6) {
        // TODO
    } else {
        LOGGER_ERROR("ATYP error！");
        return -1;
    }

    uint16_t port;
    memcpy(&port, nd->plaintext.p, 2);
    nd->plaintext.p += 2;
    nd->plaintext.len -= 2;
    memcpy(nd->sockaddr.sa_data, &port, 2);
    nd->port = ntohs(port);
    LOGGER_DEBUG("%d", nd->port);

    return 0;
}

void
free_net_data(NetData *nd)
{
    if (nd->ssclient_fd != -1) {
        close(nd->ssclient_fd);
    }
    if (nd->remote_fd != -1) {
        close(nd->remote_fd);
    }
    if (nd->cipher_ctx.encrypt_ctx != NULL) {
        EVP_CIPHER_CTX_free(nd->cipher_ctx.encrypt_ctx);
    }
    if (nd->cipher_ctx.decrypt_ctx != NULL) {
        EVP_CIPHER_CTX_free(nd->cipher_ctx.decrypt_ctx);
    }
    free(nd);
}