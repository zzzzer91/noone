/*
 * Created by zzzzer on 3/18/19.
 */

#include "transport.h"
#include "log.h"
#include "buffer.h"
#include "socket.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>   /* inet_ntoa() */

NetData *
init_net_data()
{
    NetData *nd = malloc(sizeof(NetData));
    if (nd == NULL) {
        return NULL;
    }

    nd->client_fd = -1;
    nd->remote_fd = -1;
    nd->ss_stage = STAGE_INIT;
    nd->upstream_status = WAIT_STATUS_READING;
    nd->downstream_status = WAIT_STATUS_INIT;
    nd->remote_addr = NULL;
    memset(nd->remote_domain, 0, sizeof(nd->remote_domain));
    memset(nd->remote_port, 0, sizeof(nd->remote_port));
    nd->cipher_ctx = init_noone_cipher_ctx();
    nd->client_buf = init_buffer(CLIENT_BUF_CAPACITY);
    nd->remote_buf = init_buffer(REMOTE_BUF_CAPACITY);
    nd->is_iv_send = 0;

    return nd;
}

void
free_net_data(NetData *nd)
{
    assert(nd != NULL);

    free_noone_cipher_ctx(nd->cipher_ctx);
    free_buffer(nd->client_buf);
    free_buffer(nd->remote_buf);

    free(nd);
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
 *
 * TODO
 * 判断头部长度是否合法
 */
MyAddrInfo *
parse_net_data_header(Buffer *buf, LruCache *lc)
{
    MyAddrInfo *addr_info = NULL;

    int atty = buf->data[0];
    buf->idx += 1;
    buf->len -= 1;
    if (atty == ATYP_DOMAIN) {
        size_t domain_len = buf->data[buf->idx];  // 域名长度
        if (domain_len > MAX_DOMAIN_LEN || domain_len < 4) {
            LOGGER_ERROR("domain_len error!");
            return NULL;
        }
        buf->idx += 1;
        buf->len -= 1;

        // 域名
        char domain[MAX_DOMAIN_LEN+1];
        memcpy(domain, buf->data+buf->idx, domain_len);
        domain[domain_len] = 0;  // 加上 '\0'
        buf->idx += domain_len;
        buf->len -= domain_len;

        // 端口
        uint16_t port;
        memcpy(&port, buf->data+buf->idx, 2);
        buf->idx += 2;
        buf->len -= 2;
        char port_str[MAX_PORT_LEN+1];
        snprintf(port_str, MAX_DOMAIN_LEN+1, "%d", ntohs(port));

        LOGGER_INFO("connecting %s:%s", domain, port_str);
        char domain_and_port[MAX_DOMAIN_LEN+MAX_PORT_LEN+1];
        snprintf(domain_and_port, MAX_DOMAIN_LEN+MAX_PORT_LEN+1, "%s:%s", domain, port_str);

        addr_info = lru_cache_get(lc, domain_and_port);
        if (addr_info == NULL) {
            LOGGER_DEBUG("%s: DNS 查询！", domain_and_port);
            struct addrinfo *addr_list;
            struct addrinfo hints = {0};
            hints.ai_socktype = SOCK_STREAM;
            int ret = getaddrinfo(domain, port_str, &hints, &addr_list);
            if (ret != 0) {
                LOGGER_ERROR("%s", gai_strerror(ret));
                return NULL;
            }
            LOGGER_DEBUG("%s: DNS 查询成功！", domain_and_port);

            // 创建 addr_info
            addr_info = malloc(sizeof(MyAddrInfo));
            addr_info->ai_addrlen = addr_list->ai_addrlen;
            addr_info->ai_family = addr_list->ai_family;
            memcpy(&addr_info->ai_addr, addr_list->ai_addr, addr_info->ai_addrlen);
            freeaddrinfo(addr_list);

            // 加入 lru
            void *oldvalue;
            ret = lru_cache_put(lc, domain_and_port, addr_info, &oldvalue);
            if (ret < 0) {
                free(addr_info);
                return NULL;
            }
            if (oldvalue != NULL) {
                free(oldvalue);
            }
        }
    } else if (atty == ATYP_IPV4) {
        addr_info = malloc(sizeof(MyAddrInfo));
        addr_info->ai_family = AF_INET;
        addr_info->ai_addr.sin.sin_family = AF_INET;
        addr_info->ai_addrlen = sizeof(addr_info->ai_addr.sin);
        // 已经是网络字节序
        memcpy(&addr_info->ai_addr.sin.sin_addr, buf->data+buf->idx, 4);
        buf->idx += 4;
        buf->len -= 4;
        memcpy(&addr_info->ai_addr.sin.sin_port, buf->data+buf->idx, 2);
        buf->idx += 2;
        buf->len -= 2;
    } else if (atty == ATYP_IPV6) {
        addr_info = malloc(sizeof(MyAddrInfo));
        addr_info->ai_family = AF_INET6;
        addr_info->ai_addr.sin6.sin6_family = AF_INET6;
        addr_info->ai_addrlen = sizeof(addr_info->ai_addr.sin6);
        memcpy(&addr_info->ai_addr.sin6.sin6_addr, buf->data+buf->idx, 16);
        buf->idx += 16;
        buf->len -= 16;
        memcpy(&addr_info->ai_addr.sin6.sin6_port, buf->data+buf->idx, 2);
        buf->idx += 2;
        buf->len -= 2;
    } else {
        LOGGER_ERROR("ATYP error！Maybe wrong password or decryption method.");
        return NULL;
    }

    if (buf->len > 0) {
        memcpy(buf->data, buf->data+buf->idx, buf->len);
    }
    buf->idx = 0;

    return addr_info;
}