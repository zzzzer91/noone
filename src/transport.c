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
    nd->cipher_ctx.encrypt_ctx = NULL;
    nd->cipher_ctx.decrypt_ctx = NULL;
    init_buffer(&nd->ssclient, BUF_CAPACITY);
    init_buffer(&nd->remote, BUF_CAPACITY*2);
    nd->is_iv_send = 0;

    return nd;
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
    free_buffer(&nd->ssclient);
    free_buffer(&nd->remote);

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
    buf->len += sum;
    LOGGER_DEBUG("fd: %d, read: %ld, remain capacity: %ld", fd, sum, nleft);
    return close_flag;
}

int
write_net_data(int fd, Buffer *buf)
{
    int close_flag = 0;
    size_t nleft = buf->len;
    ssize_t nwritten, sum = 0;
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
        sum += nwritten;
    }
    buf->len -= sum;
    LOGGER_DEBUG("fd: %d, write: %ld, remain len: %ld", fd, sum, nleft);
    return close_flag;
}

int
init_net_data_cipher(int fd, CryptorInfo *ci, NetData *nd)
{
    if (read(fd, nd->cipher_ctx.iv, ci->iv_len) < ci->iv_len) {
        return -1;
    }
    nd->cipher_ctx.iv[ci->iv_len] = 0;
    nd->cipher_ctx.iv_len = ci->iv_len;

    memcpy(nd->cipher_ctx.cipher_name, ci->cipher_name, ci->cipher_name_len);
    nd->cipher_ctx.cipher_name[ci->cipher_name_len] = 0;
    nd->cipher_ctx.cipher_name_len = ci->cipher_name_len;

    memcpy(nd->cipher_ctx.key, ci->key, ci->key_len);
    nd->cipher_ctx.key[ci->key_len] = 0;
    nd->cipher_ctx.key_len = ci->key_len;

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
    int ret;
    struct addrinfo hints = {};
    hints.ai_socktype = SOCK_STREAM;

    int atty = nd->ssclient.data[0];
    nd->ssclient.idx += 1;
    nd->ssclient.len -= 1;
    if (atty == ATYP_DOMAIN) {
        size_t domain_len = nd->ssclient.data[nd->ssclient.idx];  // 域名长度
        if (domain_len > 63) {
            LOGGER_ERROR("domain_len too long!");
            return -1;
        }
        nd->ssclient.idx += 1;
        nd->ssclient.len -= 1;

        memcpy(nd->domain, nd->ssclient.data+nd->ssclient.idx, domain_len);
        nd->domain[domain_len] = 0;  // 加上 '\0'
        nd->ssclient.idx += domain_len;
        nd->ssclient.len -= domain_len;

        hints.ai_family = AF_UNSPEC;
    } else if (atty == ATYP_IPV4) {
        inet_ntop(AF_INET, nd->ssclient.data+nd->ssclient.idx, nd->domain, sizeof(nd->domain));
        nd->ssclient.idx += 4;
        nd->ssclient.len -= 4;

        hints.ai_family = AF_INET;
    } else if (atty == ATYP_IPV6) {
        inet_ntop(AF_INET6, nd->ssclient.data+nd->ssclient.idx, nd->domain, sizeof(nd->domain));
        nd->ssclient.idx += 16;
        nd->ssclient.len -= 16;

        hints.ai_family = AF_INET6;
    } else {
        LOGGER_ERROR("ATYP error！");
        return -1;
    }

    uint16_t port;
    memcpy(&port, nd->ssclient.data+nd->ssclient.idx, 2);
    nd->ssclient.idx += 2;
    nd->ssclient.len -= 2;
    snprintf(nd->remote_port_str, 6, "%d", ntohs(port));
    nd->remote_port_str[5] = 0;

    ret = getaddrinfo(nd->domain, nd->remote_port_str, &hints, &nd->addr_listp);
    if (ret != 0) {
        LOGGER_ERROR("%s", gai_strerror(ret));
        return -1;
    }

    return 0;
}