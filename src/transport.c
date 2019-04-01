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
    nd->addr_listp = NULL;
    memset(nd->remote_domain, 0, sizeof(nd->remote_domain));
    memset(nd->remote_port, 0, sizeof(nd->remote_port));
    nd->cipher_ctx = init_noone_cipher_ctx();
    init_buffer(&nd->ciphertext, BUF_CAPACITY);
    init_buffer(&nd->plaintext, BUF_CAPACITY);
    init_buffer(&nd->remote, BUF_CAPACITY*2);
    init_buffer(&nd->remote_cipher, BUF_CAPACITY*2);
    nd->is_iv_send = 0;

    return nd;
}

void
free_net_data(NetData *nd)
{
    free_noone_cipher_ctx(nd->cipher_ctx);
    free_buffer(&nd->ciphertext);
    free_buffer(&nd->plaintext);
    free_buffer(&nd->remote);
    free_buffer(&nd->remote_cipher);

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
read_net_data(int fd, Buffer *buf)
{
    int close_flag = 0;
    size_t nleft = buf->capacity;
    ssize_t nread, sum = 0;
    unsigned char *p = buf->data;
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
    buf->len = sum;
    return close_flag;
}

int
write_net_data(int fd, Buffer *buf)
{
    int close_flag = 0;
    size_t nleft = buf->len;
    ssize_t nwritten;
    unsigned char *p = buf->data;
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
    }
    buf->len = nleft;
    return close_flag;
}

int
init_net_data_cipher(int fd, NooneCryptorInfo *ci, NetData *nd)
{
    if (read(fd, nd->cipher_ctx->iv, ci->iv_len) < ci->iv_len) {
        return -1;
    }
    nd->cipher_ctx->iv[ci->iv_len] = 0;
    nd->cipher_ctx->iv_len = ci->iv_len;

    memcpy(nd->cipher_ctx->cipher_name, ci->cipher_name, ci->cipher_name_len);
    nd->cipher_ctx->cipher_name[ci->cipher_name_len] = 0;
    nd->cipher_ctx->cipher_name_len = ci->cipher_name_len;

    memcpy(nd->cipher_ctx->key, ci->key, ci->key_len);
    nd->cipher_ctx->key[ci->key_len] = 0;
    nd->cipher_ctx->key_len = ci->key_len;

    EVP_CIPHER_CTX *ctx;
    ctx = INIT_ENCRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx->iv);
    if (ctx == NULL) {
        return -1;
    }
    nd->cipher_ctx->encrypt_ctx = ctx;

    ctx = INIT_DECRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx->iv);
    if (ctx == NULL) {
        return -1;
    }
    nd->cipher_ctx->decrypt_ctx = ctx;

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
    int ret;
    struct addrinfo hints = {0};
    hints.ai_socktype = SOCK_STREAM;

    int atty = nd->plaintext.data[0];
    nd->plaintext.idx += 1;
    nd->plaintext.len -= 1;
    if (atty == ATYP_DOMAIN) {
        size_t domain_len = nd->plaintext.data[nd->plaintext.idx];  // 域名长度
        if (domain_len > MAX_DOMAIN_LEN) {
            LOGGER_ERROR("domain_len too long!");
            return -1;
        }
        nd->plaintext.idx += 1;
        nd->plaintext.len -= 1;

        memcpy(nd->remote_domain, nd->plaintext.data+nd->plaintext.idx, domain_len);
        nd->remote_domain[domain_len] = 0;  // 加上 '\0'
        nd->plaintext.idx += domain_len;
        nd->plaintext.len -= domain_len;

        hints.ai_family = AF_UNSPEC;
    } else if (atty == ATYP_IPV4) {
        inet_ntop(AF_INET, nd->plaintext.data+nd->plaintext.idx,
                nd->remote_domain, sizeof(nd->remote_domain));
        nd->plaintext.idx += 4;
        nd->plaintext.len -= 4;

        hints.ai_family = AF_INET;
    } else if (atty == ATYP_IPV6) {
        inet_ntop(AF_INET6, nd->plaintext.data+nd->plaintext.idx,
                nd->remote_domain, sizeof(nd->remote_domain));
        nd->plaintext.idx += 16;
        nd->plaintext.len -= 16;

        hints.ai_family = AF_INET6;
    } else {
        LOGGER_ERROR("ATYP error！");
        return -1;
    }

    uint16_t port;
    memcpy(&port, nd->plaintext.data+nd->plaintext.idx, 2);
    nd->plaintext.idx += 2;
    nd->plaintext.len -= 2;
    snprintf(nd->remote_port, MAX_DOMAIN_LEN, "%d", ntohs(port));
    nd->remote_port[5] = 0;

    ret = getaddrinfo(nd->remote_domain, nd->remote_port, &hints, &nd->addr_listp);
    if (ret != 0) {
        LOGGER_ERROR("%s", gai_strerror(ret));
        return -1;
    }

    if (nd->plaintext.len > 0) {
        memcpy(nd->plaintext.data, nd->plaintext.data+nd->plaintext.idx, nd->plaintext.len);
    }

    nd->plaintext.idx = 0;

    return 0;
}

/*
 * 检查所有时间的最后激活时间，踢掉超时的时间
 * 更新时间的操作，在 ae_register_event() 中进行。
 * TODO 性能不行
 */
void
check_last_active(AeEventLoop *event_loop, int fd, void *data)
{
    // 前面占了 6 个描述符，分别是：
    // stdin，stdout，stderr，tcp_server，udp_sever，epfd
    int epfd = event_loop->epfd;
    time_t current_time = time(NULL);
    for (int j = event_loop->maxfd-1; j != epfd; j--) {
        AeEvent *fe = &event_loop->events[j];
        if (fe->mask != AE_NONE) {
            if ((current_time - fe->last_active) > AE_WAIT_SECONDS) {  // 踢出超时
                LOGGER_DEBUG("kill fd: %d", fe->fd);
                NetData *nd = fe->client_data;  // ss_client 和 remote_client 共用 nd
                CLEAR_SSCLIENT(event_loop, nd);
            }
        }
    }
}