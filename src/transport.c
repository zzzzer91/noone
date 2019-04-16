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

    nd->ss_stage = STAGE_INIT;
    nd->is_iv_send = 0;
    memset(nd->remote_domain, 0, sizeof(nd->remote_domain));
    memset(nd->remote_port, 0, sizeof(nd->remote_port));
    nd->cipher_ctx = init_noone_cipher_ctx();
    nd->client_fd = -1;
    nd->remote_fd = -1;
    nd->client_event_status = AE_IN | AE_ERR | EPOLLHUP;
    nd->remote_event_status = AE_IN | AE_ERR | EPOLLHUP;
    nd->client_addr = malloc(sizeof(MyAddrInfo));
    nd->remote_addr = NULL;
    nd->client_buf = NULL;  // 交给应用初始化，UDP 不初始化，否则耗内存
    nd->remote_buf = NULL;

    return nd;
}

void
free_net_data(NetData *nd)
{
    assert(nd != NULL);

    free(nd->client_addr);
    free_noone_cipher_ctx(nd->cipher_ctx);
    if (nd->client_buf != NULL) {
        free_buffer(nd->client_buf);
    }
    if (nd->remote_buf != NULL) {
        free_buffer(nd->remote_buf);
    }

    free(nd);
}

/*
 * 检查所有时间的最后激活时间，踢掉超时的时间
 * 更新时间的操作，在 ae_register_event() 中进行。
 */
void
handle_timeout(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;  // client 和 remote 共用 nd
    if (fd == nd->client_fd) {
        LOGGER_DEBUG("kill client fd: %d", fd);
    } else {
        LOGGER_DEBUG("kill remote fd: %d", fd);
    }
    CLEAR_CLIENT_AND_REMOTE();
}

int
create_remote_socket(NetData *nd)
{
    MyAddrInfo *remote_addr = nd->remote_addr;
    int fd = socket(remote_addr->ai_family, remote_addr->ai_socktype, 0);
    if (fd < 0) {
        return -1;
    }
    if (set_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }
//    if (set_nondelay(fd) < 0) {
//        close(fd);
//        return -1;
//    }

    nd->remote_fd = fd;

    return 0;
}

int
handle_stage_init(NetData *nd)
{
    NooneCryptorInfo *ci = nd->user_info->cryptor_info;

    nd->cipher_ctx->decrypt_ctx = INIT_DECRYPT_CTX(ci->cipher_name, ci->key, nd->iv);
    if (nd->cipher_ctx->decrypt_ctx == NULL) {
        return -1;
    }

    nd->cipher_ctx->encrypt_ctx = INIT_ENCRYPT_CTX(ci->cipher_name, ci->key, nd->iv);
    if (nd->cipher_ctx->encrypt_ctx == NULL) {
        return -1;
    }

    nd->ss_stage = STAGE_HEADER;

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
 *
 * TODO
 * 判断头部长度是否合法
 */
int
handle_stage_header(NetData *nd, int socktype)
{
    MyAddrInfo *addr_info = NULL;
    Buffer *buf = nd->client_buf;
    LruCache *lc = nd->user_info->lru_cache;

    int atty = buf->data[0];
    buf->idx += 1;
    buf->len -= 1;
    if (atty == ATYP_DOMAIN) {
        size_t domain_len = buf->data[buf->idx];  // 域名长度
        if (domain_len > MAX_DOMAIN_LEN || domain_len < 4) {
            LOGGER_ERROR("domain_len error!");
            return -1;
        }
        buf->idx += 1;
        buf->len -= 1;

        // 域名
        memcpy(nd->remote_domain, buf->data+buf->idx, domain_len);
        nd->remote_domain[domain_len] = 0;  // 加上 '\0'
        buf->idx += domain_len;
        buf->len -= domain_len;

        // 端口
        uint16_t port;
        memcpy(&port, buf->data+buf->idx, 2);
        buf->idx += 2;
        buf->len -= 2;
        snprintf(nd->remote_port, MAX_DOMAIN_LEN, "%d", ntohs(port));

        char domain_and_port[MAX_DOMAIN_LEN+MAX_PORT_LEN+1];
        snprintf(domain_and_port, MAX_DOMAIN_LEN+MAX_PORT_LEN+1,
                "%s:%s", nd->remote_domain, nd->remote_port);

        addr_info = lru_cache_get(lc, domain_and_port);
        if (addr_info == NULL) {
            LOGGER_DEBUG("fd: %d, %s: DNS 查询！", nd->client_fd, domain_and_port);
            struct addrinfo *addr_list;
            struct addrinfo hints = {0};
            hints.ai_socktype = socktype;
            int ret = getaddrinfo(nd->remote_domain, nd->remote_port, &hints, &addr_list);
            if (ret != 0) {
                LOGGER_ERROR("%s", gai_strerror(ret));
                return -1;
            }
            LOGGER_DEBUG("fd: %d, %s: DNS 查询成功！", nd->client_fd, domain_and_port);

            // 创建 addr_info
            addr_info = malloc(sizeof(MyAddrInfo));
            addr_info->ai_addrlen = addr_list->ai_addrlen;
            addr_info->ai_family = addr_list->ai_family;
            addr_info->ai_socktype = addr_list->ai_socktype;
            memcpy(&addr_info->ai_addr, addr_list->ai_addr, addr_info->ai_addrlen);
            freeaddrinfo(addr_list);

            // 加入 lru
            void *oldvalue;
            ret = lru_cache_put(lc, domain_and_port, addr_info, &oldvalue);
            if (ret < 0) {
                free(addr_info);
                return -1;
            }
            if (oldvalue != NULL) {
                free(oldvalue);
            }
        }
    } else if (atty == ATYP_IPV4) {
        addr_info = malloc(sizeof(MyAddrInfo));
        addr_info->ai_addrlen = sizeof(addr_info->ai_addr.sin);
        addr_info->ai_family = AF_INET;
        addr_info->ai_socktype = socktype;
        addr_info->ai_addr.sin.sin_family = AF_INET;
        // 已经是网络字节序
        inet_ntop(AF_INET, buf->data+buf->idx, nd->remote_domain, sizeof(nd->remote_domain));
        memcpy(&addr_info->ai_addr.sin.sin_addr, buf->data+buf->idx, 4);
        buf->idx += 4;
        buf->len -= 4;
        uint16_t port;
        memcpy(&port, buf->data+buf->idx, 2);
        buf->idx += 2;
        buf->len -= 2;
        addr_info->ai_addr.sin.sin_port = port;
        snprintf(nd->remote_port, MAX_DOMAIN_LEN, "%d", ntohs(port));
    } else if (atty == ATYP_IPV6) {
        addr_info = malloc(sizeof(MyAddrInfo));
        addr_info->ai_addrlen = sizeof(addr_info->ai_addr.sin6);
        addr_info->ai_family = AF_INET6;
        addr_info->ai_socktype = socktype;
        addr_info->ai_addr.sin6.sin6_family = AF_INET6;
        inet_ntop(AF_INET6, buf->data+buf->idx, nd->remote_domain, sizeof(nd->remote_domain));
        memcpy(&addr_info->ai_addr.sin6.sin6_addr, buf->data+buf->idx, 16);
        buf->idx += 16;
        buf->len -= 16;
        uint16_t port;
        memcpy(&port, buf->data+buf->idx, 2);
        buf->idx += 2;
        buf->len -= 2;
        addr_info->ai_addr.sin6.sin6_port = port;
        snprintf(nd->remote_port, MAX_DOMAIN_LEN, "%d", ntohs(port));
    } else {
        LOGGER_ERROR("ATYP error！Maybe wrong password or decryption method.");
        return -1;
    }
    nd->remote_addr = addr_info;

    if (buf->len > 0) {
        memcpy(buf->data, buf->data+buf->idx, buf->len);
    }
    buf->idx = 0;

    nd->ss_stage = STAGE_HANDSHAKE;

    return 0;
}

int
handle_stage_handshake(NetData *nd)
{
    if (create_remote_socket(nd) < 0) {
        return -1;
    }

    MyAddrInfo *remote_addr = nd->remote_addr;

    // 注意：当设置非阻塞 socket 后，tcp 三次握手会异步进行，
    // 所以可能会出现三次握手还未完成，就进行 write，
    // 此时 write 会把 errno 置为 EAGAIN
    if (connect(nd->remote_fd, (struct sockaddr *)&remote_addr->ai_addr,
                remote_addr->ai_addrlen) < 0) {
        if (errno != EINPROGRESS) {  // 设为非阻塞后，连接会返回 EINPROGRESS
            close(nd->remote_fd);
            nd->remote_fd = -1;
            free(remote_addr);
            nd->remote_addr = NULL;
            // TODO
            // lru_cache_remove(nd->user_info->lru_cache, nd->remote_domain);
            LOGGER_ERROR("fd: %d, connect: %s", nd->client_fd, strerror(errno));
            return -1;
        }
    }

    nd->ss_stage = STAGE_STREAM;

    return 0;
}