/*
 * Created by zzzzer on 2/11/19.
 */

#include "tcp.h"
#include "transport.h"
#include "socket.h"
#include "ae.h"
#include "cryptor.h"
#include "log.h"
#include "lru.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>      /* close() */
#include <sys/socket.h>  /* accept() */
#include <netinet/in.h>  /* struct sockaddr_in */

#define REGISTER_READ_SSCLIENT() \
    ae_register_event(event_loop, nd->client_fd, AE_IN, \
            tcp_read_client, NULL, tcp_handle_timeout, nd)

#define REGISTER_WRITE_SSCLIENT() \
    ae_register_event(event_loop, nd->client_fd, AE_OUT, \
            NULL, tcp_write_client, tcp_handle_timeout, nd)

#define REGISTER_READ_REMOTE() \
    ae_register_event(event_loop, nd->remote_fd, AE_IN, \
            tcp_read_remote, NULL, tcp_handle_timeout, nd)

#define REGISTER_WRITE_REMOTE() \
    ae_register_event(event_loop, nd->remote_fd, AE_OUT, \
            NULL, tcp_write_remote, tcp_handle_timeout, nd)

#define UNREGISTER_SSCLIENT() \
    ae_unregister_event(event_loop, nd->client_fd)

#define UNREGISTER_REMOTE() \
    ae_unregister_event(event_loop, nd->remote_fd)

/*
 * 这个函数必须和非阻塞 socket 配合。
 *
 * 1、当对端套接字已关闭，read() 会返回 0。
 * 2、当（read() == -1 && errno == EAGAIN）时，
 *    代表非阻塞 socket 数据读完。
 * 3、当执行到 read() 时，可能就会碰到 read() 返回 0，此时不能直接 return 0，
 *    因为前面可能读了数据，将 close_flag 设为 1，代表对端关闭，并且返回读到的数据长度。
 *    write_net_data() 同理。
 */
static int
read_net_data(int fd, void *buf, size_t capacity, int *close_flag)
{
    size_t nleft = capacity;
    ssize_t nread;
    char *p = buf;
    while (nleft > 0) {
        // 若没设置非阻塞 socket，这里会一直阻塞直到读到 nleft 字节内容。
        // 这是没法接受的。
        nread = read(fd, p, nleft);
        if (nread == 0) {
            *close_flag = 1;
            break;
        } else if (nread < 0) {
            if (errno == EAGAIN) {  // 需先设置非阻塞 socket
                break;
            } else if (errno == EINTR) {
                nread = 0;
            } else {
                *close_flag = 1;
                break;
            }
        }
        nleft -= nread;
        p += nread;
    }
    return capacity - nleft;
}

/*
 * 把缓冲区数据写给远端
 */
static int
write_net_data(int fd, void *buf, size_t n, int *close_flag)
{
    size_t nleft = n;
    ssize_t nwritten;
    char *p = buf;
    while (nleft > 0) {
        // 阻塞 socket 会一直等，
        // 非阻塞 socket 会在未成功发送时将 errno 设为 EAGAIN
        nwritten = write(fd, p, nleft);
        if (nwritten == 0) {
            *close_flag = 1;
            break;
        } else if (nwritten < 0) {
            if (errno == EAGAIN) {  // 需先设置非阻塞 socket，在三次握手未完成或发送缓冲区满出现
                break;
            } else if (errno == EINTR) {
                nwritten = 0;
            } else {
                *close_flag = 1;
                break;
            }
        }
        nleft -= nwritten;
        p += nwritten;
    }
    return n - nleft;
}

void
tcp_accept_conn(AeEventLoop *event_loop, int fd, void *data)
{
    struct sockaddr_in conn_addr;
    socklen_t conn_addr_len = sizeof(conn_addr);
    int conn_fd = accept(fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
    if (conn_fd < 0) {
        LOGGER_ERROR("fd: %d, tcp_accept_conn", conn_fd);
        return;
    }

    if (setnonblock(conn_fd) < 0) {
        LOGGER_ERROR("fd: %d, setnonblock", conn_fd);
        close(conn_fd);
        return;
    }

    NetData *nd = init_net_data();
    if (nd == NULL) {
        LOGGER_ERROR("fd: %d, init_net_data", conn_fd);
        close(conn_fd);
        return;
    }
    nd->client_fd = conn_fd;
    nd->user_info = (NooneUserInfo *)data;

    if (REGISTER_READ_SSCLIENT() < 0) {
        LOGGER_ERROR("fd: %d, tcp_accept_conn, REGISTER_READ_SSCLIENT", conn_fd);
        close(conn_fd);
        free_net_data(nd);
        return;
    }
}

static int
handle_stage_init(NetData *nd)
{
    NooneCryptorInfo *ci = nd->user_info->cryptor_info;

    if (read(nd->client_fd, nd->iv, ci->iv_len) < ci->iv_len) {
        return -1;
    }

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

static int
handle_stage_header(NetData *nd)
{
    MyAddrInfo *remote_addr = parse_net_data_header(nd->remote_buf, nd->user_info->lru_cache);
    if (remote_addr == NULL) {
        return -1;
    }

    nd->remote_addr = remote_addr;
    nd->ss_stage = STAGE_HANDSHAKE;

    return 0;
}

static int
handle_stage_handshake(NetData *nd)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOGGER_ERROR("fd: %d, socket: %s", nd->client_fd, strerror(errno));
        return -1;
    }
    if (setnonblock(fd) < 0) {
        close(fd);
        return -1;
    }

    // 注意：当设置非阻塞 socket 后，tcp 三次握手会异步进行，
    // 所以可能会出现三次握手还未完成，就进行 write，
    // 此时 write 会把 errno 置为 EAGAIN
    LOGGER_INFO("fd: %d, connecting", nd->client_fd);
    if (connect(fd, (struct sockaddr *)&nd->remote_addr->ai_addr,
            nd->remote_addr->ai_addrlen) < 0) {
        if (errno != EINPROGRESS) {  // 设为非阻塞后，连接会返回 EINPROGRESS
            close(fd);
            free(nd->remote_addr);
            nd->remote_addr = NULL;
            lru_cache_remove(nd->user_info->lru_cache, nd->remote_domain);
            LOGGER_ERROR("fd: %d, connect: %s", nd->client_fd, strerror(errno));
            return -1;
        }
    }

    nd->remote_fd = fd;

    nd->ss_stage = STAGE_STREAM;

    return 0;
}

void
tcp_read_client(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    if (nd->ss_stage == STAGE_INIT) {
        if (handle_stage_init(nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_init", nd->client_fd);
            CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
            return;
        }
    }

    int close_flag = 0;
    char buf[CLIENT_BUF_CAPACITY];
    size_t nread = read_net_data(fd, buf, sizeof(buf), &close_flag);
    if (close_flag == 1) {  // ss_client 关闭
        LOGGER_DEBUG("fd: %d, tcp_read_client, ssclient close!", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        return;
    }

    size_t ret = DECRYPT(nd, buf, nread);
    if (ret == 0) {
        LOGGER_ERROR("fd: %d, DECRYPT", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        return;
    }
    nd->remote_buf->len = ret;

    if (nd->ss_stage == STAGE_HEADER) {
        if (handle_stage_header(nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_header", nd->client_fd);
            CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
            return;
        }
    }

    if (nd->ss_stage == STAGE_HANDSHAKE) {
        if (handle_stage_handshake(nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_handshake", fd);
            CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
            return;
        }
    }

    if (nd->remote_buf->len == 0) {  // 解析完头部后，没有数据了
        return;
    }

    // 不需要考虑重复注册问题
    // ae_register_event() 中有相应处理逻辑
    if (nd->remote_fd != -1) {  // 触发前，remote 可能已关闭
        if (REGISTER_WRITE_REMOTE() < 0) {
            LOGGER_ERROR("fd: %d, tcp_read_client, REGISTER_WRITE_REMOTE", nd->client_fd);
            CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
            return;
        }
    }
    if (UNREGISTER_SSCLIENT() < 0) {
        LOGGER_ERROR("fd: %d, tcp_read_client, UNREGISTER_SSCLIENT", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        return;
    }
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = 0;
    size_t nwriten = write_net_data(fd,
            nd->remote_buf->data+nd->remote_buf->idx, nd->remote_buf->len, &close_flag);
    if (close_flag == 1) {
        LOGGER_DEBUG("fd: %d, tcp_write_remote, remote close!", nd->client_fd);
        CLEAR_REMOTE(event_loop, nd);
        return;
    }
    nd->remote_buf->len -= nwriten;
    if (nd->remote_buf->len > 0) {  // 没有写完，不能改变事件，要继续写
        nd->remote_buf->idx += nwriten;
        return;
    }
    nd->remote_buf->idx = 0;  // 写完，则重置写位置

    if (REGISTER_READ_REMOTE() < 0) {
        LOGGER_ERROR("fd: %d, tcp_write_remote, REGISTER_READ_REMOTE", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        return;
    }

    if (REGISTER_READ_SSCLIENT() < 0) {
        LOGGER_ERROR("fd: %d, tcp_write_remote, REGISTER_READ_SSCLIENT", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        return;
    }
}

void
tcp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    int close_flag = 0;
    char buf[REMOTE_BUF_CAPACITY];
    size_t nread = read_net_data(fd, buf, sizeof(buf), &close_flag);
    if (close_flag == 1) {
        LOGGER_DEBUG("fd: %d, tcp_read_remote, remote close!", nd->client_fd);
        if (nread == 0) {
            CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
            return;
        } else {  // 对端已关闭，但还有数据写给 client
            CLEAR_REMOTE(event_loop, nd);
        }
    }

    size_t ret = ENCRYPT(nd, buf, nread);
    if (ret == 0) {
        LOGGER_ERROR("fd: %d, ENCRYPT", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        return;
    }
    nd->client_buf->len = ret;

    if (REGISTER_WRITE_SSCLIENT() < 0) {
        LOGGER_ERROR("fd: %d, tcp_read_remote, REGISTER_WRITE_SSCLIENT", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        return;
    }
    if (nd->remote_fd != -1) {
        if (UNREGISTER_REMOTE() < 0) {
            LOGGER_ERROR("fd: %d, tcp_read_remote, UNREGISTER_REMOTE", nd->client_fd);
            CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
            return;
        }
    }
}

void
tcp_write_client(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    if (nd->is_iv_send == 0) {
        NooneCryptorInfo *ci = nd->user_info->cryptor_info;

        if (write(fd, nd->iv, ci->iv_len) < ci->iv_len) {
            LOGGER_ERROR("fd: %d, write iv error!", nd->client_fd);
            CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
            return;
        }
        nd->is_iv_send = 1;
    }

    int close_flag = 0;
    size_t nwriten = write_net_data(fd,
            nd->client_buf->data+nd->client_buf->idx, nd->client_buf->len, &close_flag);
    if (close_flag == 1) {
        LOGGER_DEBUG("fd: %d, tcp_write_client, ssclient close!", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        return;
    }
    nd->client_buf->len -= nwriten;
    if (nd->client_buf->len > 0) {
        nd->client_buf->idx += nwriten;
        return;
    }
    nd->client_buf->idx = 0;

    if (REGISTER_READ_SSCLIENT() < 0) {
        LOGGER_ERROR("fd: %d, tcp_write_client, REGISTER_READ_SSCLIENT", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
        return;
    }
    if (nd->remote_fd != -1) {
        if (REGISTER_READ_REMOTE() < 0) {
            LOGGER_ERROR("fd: %d, tcp_write_client, REGISTER_READ_REMOTE", nd->client_fd);
            CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
            return;
        }
    } else {  // 对端已关闭
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);  // 对端已清理过
        return;
    }
}

/*
 * 检查所有时间的最后激活时间，踢掉超时的时间
 * 更新时间的操作，在 ae_register_event() 中进行。
 */
void
tcp_handle_timeout(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;  // ss_client 和 remote 共用 nd
    if (fd == nd->client_fd) {
        LOGGER_DEBUG("kill client fd: %d", fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
    } else {  // 是远程 fd，不关闭本地
        LOGGER_DEBUG("kill remote fd: %d", fd);
        CLEAR_CLIENT_AND_REMOTE(event_loop, nd);
    }
}