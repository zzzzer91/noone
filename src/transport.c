/*
 * Created by zzzzer on 3/18/19.
 */

#include "transport.h"
#include "log.h"
#include "buffer.h"
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
    nd->remote_addr = NULL;
    memset(nd->remote_domain, 0, sizeof(nd->remote_domain));
    memset(nd->remote_port, 0, sizeof(nd->remote_port));
    nd->cipher_ctx = init_noone_cipher_ctx();
    nd->remote_buf = init_buffer(CLIENT_BUF_CAPACITY);
    nd->client_buf = init_buffer(REMOTE_BUF_CAPACITY);
    nd->is_iv_send = 0;

    return nd;
}

void
free_net_data(NetData *nd)
{
    assert(nd != NULL);

    free_noone_cipher_ctx(nd->cipher_ctx);
    free_buffer(nd->remote_buf);
    free_buffer(nd->client_buf);

    free(nd);
}

/*
 * 这个函数必须和非阻塞 socket 配合。
 *
 * 1、当对端套接字已关闭，read() 会返回 0。
 * 2、当（read() == -1 && errno == EAGAIN）时，
 *    代表 EPOLLET 模式的 socket 数据读完。
 * 3、ET 模式下，触发 epoll_wait()，然后执行 read_net_data()，当执行到
 *    read() 时，可能就会碰到 read() 返回 0，此时不能直接 return，
 *    因为前面可能读了数据。
 *    write_net_data() 同理。
 */
int
read_net_data(int fd, char *buf, size_t capacity, size_t *len)
{
    int close_flag = 0;
    size_t nleft = capacity;
    ssize_t nread, sum = 0;
    char *p = buf;
    while (nleft > 0) {
        // 若没设置非阻塞 socket，这里会一直阻塞直到读到 nleft 字节内容。
        // 这是没法接受的。
        nread = read(fd, p, nleft);
        if (nread == 0) {
            close_flag = 1;
            break;
        } else if (nread < 0) {
            if (errno == EAGAIN) {  // 需先设置非阻塞 socket
                break;
            } else if (errno == EINTR) {
                nread = 0;
            } else {
                close_flag = 1;
                break;
            }
        }
        nleft -= nread;
        p += nread;
        sum += nread;
    }
    *len = sum;
    return close_flag;
}

/*
 * 把缓冲区数据写给远端
 */
int
write_net_data(int fd, Buffer *buf)
{
    int close_flag = 0;
    size_t nleft = buf->len;
    ssize_t nwritten, sum = 0;
    char *p = buf->data + buf->idx;
    while (nleft > 0) {
        // 阻塞 socket 会一直等，
        // 非阻塞 socket 会在未成功发送时将 errno 设为 EAGAIN
        nwritten = write(fd, p, nleft);
        if (nwritten == 0) {
            close_flag = 1;
            break;
        } else if (nwritten < 0) {
            if (errno == EAGAIN) {  // 需先设置非阻塞 socket，在三次握手未完成或发送缓冲区满出现
                break;
            } else if (errno == EINTR) {
                nwritten = 0;
            } else {
                close_flag = 1;
                break;
            }
        }
        nleft -= nwritten;
        p += nwritten;
        sum += nwritten;
    }
    buf->len = nleft;
    buf->idx += sum;
    return close_flag;
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
        snprintf(port_str, MAX_DOMAIN_LEN, "%d", ntohs(port));

        addr_info = lru_cache_get(lc, domain);
        if (addr_info == NULL) {
            LOGGER_DEBUG("%s: DNS 查询！", domain);
            struct addrinfo *addr_list;
            struct addrinfo hints = {0};
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_family = AF_UNSPEC;
            int ret = getaddrinfo(domain, port_str, &hints, &addr_list);
            if (ret != 0) {
                LOGGER_ERROR("%s", gai_strerror(ret));
                return NULL;
            }

            // 创建 addr_info
            addr_info = malloc(sizeof(MyAddrInfo));
            addr_info->ai_addrlen = addr_list->ai_addrlen;
            memcpy(&addr_info->ai_addr, addr_list->ai_addr, addr_info->ai_addrlen);
            freeaddrinfo(addr_list);

            // 加入 lru
            void *oldvalue;
            ret = lru_cache_set(lc, domain, addr_info, &oldvalue);
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