/*
 * Created by zzzzer on 3/18/19.
 */

#include "transport.h"
#include "log.h"
#include "buffer.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
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
 */
int
parse_net_data_header(NetData *nd)
{
    int ret;
    struct addrinfo hints = {0};
    hints.ai_socktype = SOCK_STREAM;

    int atty = nd->remote_buf->data[0];
    nd->remote_buf->idx += 1;
    nd->remote_buf->len -= 1;
    if (atty == ATYP_DOMAIN) {
        size_t domain_len = nd->remote_buf->data[nd->remote_buf->idx];  // 域名长度
        if (domain_len > MAX_DOMAIN_LEN) {
            LOGGER_ERROR("domain_len too long!");
            return -1;
        }
        nd->remote_buf->idx += 1;
        nd->remote_buf->len -= 1;

        memcpy(nd->remote_domain, nd->remote_buf->data+nd->remote_buf->idx, domain_len);
        nd->remote_domain[domain_len] = 0;  // 加上 '\0'
        nd->remote_buf->idx += domain_len;
        nd->remote_buf->len -= domain_len;

        hints.ai_family = AF_UNSPEC;
    } else if (atty == ATYP_IPV4) {
        inet_ntop(AF_INET, nd->remote_buf->data+nd->remote_buf->idx,
                nd->remote_domain, sizeof(nd->remote_domain));
        nd->remote_buf->idx += 4;
        nd->remote_buf->len -= 4;

        hints.ai_family = AF_INET;
    } else if (atty == ATYP_IPV6) {
        inet_ntop(AF_INET6, nd->remote_buf->data+nd->remote_buf->idx,
                nd->remote_domain, sizeof(nd->remote_domain));
        nd->remote_buf->idx += 16;
        nd->remote_buf->len -= 16;

        hints.ai_family = AF_INET6;
    } else {
        LOGGER_ERROR("ATYP error！");
        return -1;
    }

    uint16_t port;
    memcpy(&port, nd->remote_buf->data+nd->remote_buf->idx, 2);
    nd->remote_buf->idx += 2;
    nd->remote_buf->len -= 2;
    snprintf(nd->remote_port, MAX_DOMAIN_LEN, "%d", ntohs(port));
    nd->remote_port[5] = 0;

    LruCache *lc = nd->user_info->lru_cache;
    nd->remote_addr = lru_cache_get(lc, nd->remote_domain);
    if (nd->remote_addr == NULL) {
        LOGGER_DEBUG("%s: DNS 查询！", nd->remote_domain);
        ret = getaddrinfo(nd->remote_domain, nd->remote_port, &hints, &nd->remote_addr);
        if (ret != 0) {
            LOGGER_ERROR("%s", gai_strerror(ret));
            return -1;
        }
        void *oldvalue;
        ret = lru_cache_set(lc, nd->remote_domain, nd->remote_addr, &oldvalue);
        if (ret < 0) {
            return -1;
        }
        if (oldvalue != NULL) {
            freeaddrinfo(oldvalue);
        }
    }

    if (nd->remote_buf->len > 0) {
        memcpy(nd->remote_buf->data,
                nd->remote_buf->data+nd->remote_buf->idx, nd->remote_buf->len);
    }

    nd->remote_buf->idx = 0;

    return 0;
}

/*
 * 检查所有时间的最后激活时间，踢掉超时的时间
 * 更新时间的操作，在 ae_register_event() 中进行。
 */
void
check_last_active(AeEventLoop *event_loop)
{
    time_t current_time = time(NULL);
    AeEvent *p = event_loop->list_tail;
    while (p) {
        if ((current_time - p->last_active) < AE_WAIT_SECONDS) {  // 踢出超时
            break;  // 前面的没超时，说明后面的也不会，因为按时间排序
        }
        NetData *nd = p->client_data;  // ss_client 和 remote_client 共用 nd
        LOGGER_DEBUG("kill fd: %d", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        p = p->list_prev;  // 从队尾往前循环
    }
}