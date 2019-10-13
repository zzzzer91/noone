/*
 * Created by zzzzer on 3/18/19.
 */

#include "transport.h"
#include "dns.h"
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>   /* inet_ntoa() */

NetData *init_net_data() {
    NetData *nd = malloc(sizeof(NetData));
    if (nd == NULL) {
        return NULL;
    }

    nd->stage = STAGE_INIT;
    nd->is_iv_send = 0;
    nd->cipher_ctx = init_noone_cipher_ctx();
    nd->client_fd = -1;
    nd->remote_fd = -1;
    nd->dns_fd = -1;
    nd->client_event_status = AE_IN | AE_ERR;
    nd->remote_event_status = AE_IN | AE_ERR;
    nd->remote_addr = NULL;
    nd->client_buf = NULL;  // 交给应用初始化，UDP 不初始化，否则耗内存
    nd->remote_buf = NULL;

    return nd;
}

void free_net_data(NetData *nd) {
    assert(nd != NULL);

    free_noone_cipher_ctx(nd->cipher_ctx);
    if (nd->client_buf != NULL) {
        free_buffer(nd->client_buf);
    }
    if (nd->remote_buf != NULL) {
        free_buffer(nd->remote_buf);
    }

    // 不清理 remote_addr，因为会被加入 lru 缓存，交给缓存清理

    free(nd);
}

int create_remote_socket(NetData *nd) {
    MyAddrInfo *remote_addr = nd->remote_addr;
    int fd = socket(remote_addr->ai_family, remote_addr->ai_socktype, 0);
    if (fd < 0) {
        return -1;
    }
    if (set_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }
    if (remote_addr->ai_socktype == SOCK_STREAM) {
        if (set_nondelay(fd) < 0) {
            close(fd);
            return -1;
        }
    }

    nd->remote_fd = fd;

    return 0;
}

int handle_stage_init(NetData *nd) {
    NooneCryptorInfo *ci = nd->user_info->cryptor_info;

    nd->cipher_ctx->decrypt_ctx = INIT_DECRYPT_CTX(ci->cipher_name, ci->key, nd->iv);
    if (nd->cipher_ctx->decrypt_ctx == NULL) {
        return -1;
    }
    nd->cipher_ctx->encrypt_ctx = INIT_ENCRYPT_CTX(ci->cipher_name, ci->key, nd->iv);
    if (nd->cipher_ctx->encrypt_ctx == NULL) {
        return -1;
    }

    nd->stage = STAGE_HEADER;

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
int handle_stage_header(NetData *nd, int socktype) {
    Buffer *buf = nd->client_buf;
    if (buf->len < 2) {
        return -1;
    }

    int header_len = 0;

    int atty = buf->data[header_len];
    header_len += 1;
    if (atty == ATYP_DOMAIN) {
        uint8_t domain_len = (uint8_t)buf->data[header_len];  // 域名长度
        if (domain_len > MAX_DOMAIN_LEN || domain_len < 4) {
            LOGGER_ERROR("domain_len error!");
            return -1;
        }
        header_len += 1;

        if (buf->len < (domain_len + 4)) {
            return -1;
        }

        // 域名
        memcpy(nd->remote_domain, buf->data + header_len, domain_len);
        nd->remote_domain[domain_len] = 0;  // 加上 '\0'
        header_len += domain_len;

        // 端口
        uint16_t port;
        memcpy(&port, buf->data + header_len, 2);
        header_len += 2;
        nd->remote_port = ntohs(port);

        nd->stage = STAGE_DNS;
    } else if (atty == ATYP_IPV4) {
        if (buf->len < 7) {
            return -1;
        }

        MyAddrInfo *addr_info = malloc(sizeof(MyAddrInfo));
        addr_info->ai_addrlen = sizeof(addr_info->ai_addr.sin);
        addr_info->ai_family = AF_INET;
        addr_info->ai_socktype = socktype;
        addr_info->ai_addr.sin.sin_family = AF_INET;

        // 已经是网络字节序
        inet_ntop(AF_INET, buf->data + header_len, nd->remote_domain, sizeof(nd->remote_domain));
        memcpy(&addr_info->ai_addr.sin.sin_addr, buf->data + header_len, 4);
        header_len += 4;

        uint16_t port;
        memcpy(&port, buf->data + header_len, 2);
        header_len += 2;
        addr_info->ai_addr.sin.sin_port = port;
        nd->remote_port = ntohs(port);

        nd->remote_addr = addr_info;

        nd->stage = STAGE_HANDSHAKE;
    } else if (atty == ATYP_IPV6) {
        if (buf->len < 19) {
            return -1;
        }

        MyAddrInfo *addr_info = malloc(sizeof(MyAddrInfo));
        addr_info->ai_addrlen = sizeof(addr_info->ai_addr.sin6);
        addr_info->ai_family = AF_INET6;
        addr_info->ai_socktype = socktype;
        addr_info->ai_addr.sin6.sin6_family = AF_INET6;

        inet_ntop(AF_INET6, buf->data + header_len, nd->remote_domain, sizeof(nd->remote_domain));
        memcpy(&addr_info->ai_addr.sin6.sin6_addr, buf->data + header_len, 16);
        header_len += 16;

        uint16_t port;
        memcpy(&port, buf->data + header_len, 2);
        header_len += 2;
        addr_info->ai_addr.sin6.sin6_port = port;
        nd->remote_port = ntohs(port);

        nd->remote_addr = addr_info;

        nd->stage = STAGE_HANDSHAKE;
    } else {
        TRANSPORT_ERROR("ATYP error！Maybe wrong password or decryption method.");
        return -1;
    }

    buf->len -= header_len;

    if (buf->len > 0) {
        buf->idx += header_len;
    }

    return 0;
}

int handle_stage_dns(NetData *nd) {
    LruCache *lc = nd->user_info->lru_cache;

    char domain_and_port[MAX_DOMAIN_LEN + MAX_PORT_LEN + 2];
    snprintf(domain_and_port, MAX_DOMAIN_LEN + MAX_PORT_LEN + 2, "%s:%d", nd->remote_domain,
             nd->remote_port);

    MyAddrInfo *addr_info = lru_cache_get(lc, domain_and_port);
    if (addr_info == NULL) {
        LOGGER_DEBUG("fd: %d, %s: DNS query!", nd->client_fd, domain_and_port);
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            TRANSPORT_ERROR("socket: %s", strerror(errno));
            return -1;
        }
        if (set_nonblock(sockfd) < 0) {
            close(sockfd);
            return -1;
        }
        nd->dns_fd = sockfd;

        if (dns_send_request(nd->dns_fd, nd->remote_domain) < 0) {
            close(sockfd);
            return -1;
        }
        return 0;
    }
    nd->remote_addr = addr_info;
    nd->stage = STAGE_HANDSHAKE;

    return 0;
}

int handle_stage_handshake(NetData *nd) {
    if (create_remote_socket(nd) < 0) {
        return -1;
    }

    MyAddrInfo *remote_addr = nd->remote_addr;

    // 注意：当设置非阻塞 socket 后，tcp 三次握手会异步进行，
    // 所以可能会出现三次握手还未完成，就进行 write，
    // 此时 write 会把 errno 置为 EAGAIN
    if (connect(nd->remote_fd, (struct sockaddr *)&remote_addr->ai_addr, remote_addr->ai_addrlen) <
        0) {
        if (errno != EINPROGRESS) {  // 设为非阻塞后，连接会返回 EINPROGRESS
            close(nd->remote_fd);
            nd->remote_fd = -1;
            free(remote_addr);
            nd->remote_addr = NULL;
            char domain_and_port[MAX_DOMAIN_LEN + MAX_PORT_LEN + 2];
            snprintf(domain_and_port, MAX_DOMAIN_LEN + MAX_PORT_LEN + 2, "%s:%d", nd->remote_domain,
                     nd->remote_port);
            // 移除缓存
            lru_cache_remove(nd->user_info->lru_cache, domain_and_port);
            TRANSPORT_ERROR("connect: %s", strerror(errno));
            return -1;
        }
        errno = 0;
    }

    nd->stage = STAGE_STREAM;

    return 0;
}

/*
 * 检查所有时间的最后激活时间，踢掉超时的时间
 * 更新时间的操作，在 ae_register_event() 中进行。
 */
void handle_transport_timeout(AeEventLoop *event_loop, int fd, void *data) {
    NetData *nd = data;  // client 和 remote 共用 nd
    if (fd == nd->client_fd) {
        TRANSPORT_ERROR("kill self");
    } else {
        TRANSPORT_ERROR("kill remote fd: %d", fd);
    }
    CLEAR_ALL();
}

int add_dns_to_lru_cache(NetData *nd, MyAddrInfo *addr_info) {
    char domain_and_port[MAX_DOMAIN_LEN + MAX_PORT_LEN + 2];
    snprintf(domain_and_port, MAX_DOMAIN_LEN + MAX_PORT_LEN + 2, "%s:%d", nd->remote_domain,
             nd->remote_port);
    void *oldvalue;
    LruCache *lc = nd->user_info->lru_cache;
    if (lru_cache_put(lc, domain_and_port, addr_info, &oldvalue) < 0) {
        return -1;
    }
    if (oldvalue != NULL) {
        free(oldvalue);
    }

    return 0;
}