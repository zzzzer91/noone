/*
 * Created by zzzzer on 3/18/19.
 */

#include "transport.h"
#include "log.h"
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>   /* inet_ntoa() */

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

    init_buffer(&nd->ciphertext, BUF_CAPACITY);
    init_buffer(&nd->plaintext, BUF_CAPACITY);
    init_buffer(&nd->remote, BUF_CAPACITY);
    init_buffer(&nd->remote_cipher, BUF_CAPACITY);
    nd->is_iv_send = 0;

    return nd;
}

int
init_net_data_cipher(CryptorInfo *ci, NetData *nd)
{
    nd->cipher_ctx.iv_len = ci->iv_len;
    memcpy(nd->cipher_ctx.iv, nd->ciphertext.data, ci->iv_len);
    nd->ciphertext.idx += ci->iv_len;
    nd->ciphertext.len -= ci->iv_len;
    nd->cipher_ctx.encrypt_ctx = INIT_ENCRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);
    nd->cipher_ctx.decrypt_ctx = INIT_DECRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);

    return 0;
}

int
parse_net_data_header(NetData *nd)
{
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
        return -1;
    }

    uint16_t port;
    memcpy(&port, nd->plaintext.data+nd->plaintext.idx, 2);
    memcpy(nd->sockaddr.sa_data, &port, 2);
    nd->plaintext.idx += 2;
    nd->plaintext.len -= 2;
    nd->port = ntohs(port);
    LOGGER_DEBUG("%d", nd->port);

    return 0;
}

void
free_net_data(NetData *nd)
{
    if (nd->cipher_ctx.encrypt_ctx != NULL) {
        EVP_CIPHER_CTX_free(nd->cipher_ctx.encrypt_ctx);
    }
    if (nd->cipher_ctx.decrypt_ctx != NULL) {
        EVP_CIPHER_CTX_free(nd->cipher_ctx.decrypt_ctx);
    }
    free_buffer(&nd->ciphertext);
    free_buffer(&nd->plaintext);
    free_buffer(&nd->remote);
    free_buffer(&nd->remote_cipher);
    free(nd);
}