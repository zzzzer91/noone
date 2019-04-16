/*
 * Created by zzzzer on 2/11/19.
 */

#include "tcp.h"
#include "error.h"
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

#define CLIENT_BUF_CAPACITY 16 * 1024
#define REMOTE_BUF_CAPACITY 32 * 1024

#define REGISTER_CLIENT(events) \
    do { \
        if (nd->client_fd != -1) { \
            if (ae_register_event(event_loop, nd->client_fd, events, \
                        tcp_read_client, tcp_write_client, handle_timeout, nd) < 0) { \
                LOGGER_ERROR("fd: %d, %s, REGISTER_CLIENT", nd->client_fd, __func__); \
                CLEAR_CLIENT_AND_REMOTE(); \
            } \
        } \
    } while (0)

#define REGISTER_REMOTE(events) \
    do { \
        if (nd->remote_fd != -1) { \
            if (ae_register_event(event_loop, nd->remote_fd, events, \
                    tcp_read_remote, tcp_write_remote, handle_timeout, nd) < 0) { \
                LOGGER_ERROR("fd: %d, %s, REGISTER_CLIENT", nd->client_fd, __func__); \
                CLEAR_CLIENT_AND_REMOTE(); \
            } \
        } \
    } while (0)

#define ENCRYPT(nd, buf, buf_len) \
    encrypt((nd)->cipher_ctx->encrypt_ctx, (uint8_t *)(buf), (buf_len), \
            (uint8_t *)(nd)->remote_buf->data)

#define DECRYPT(nd, buf, buf_len) \
    decrypt((nd)->cipher_ctx->decrypt_ctx, (uint8_t *)(buf), (buf_len), \
            (uint8_t *)(nd)->client_buf->data)

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
static size_t
read_net_data(int fd, void *buf, size_t capacity, int *close_flag)
{
    *close_flag = 0;
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
            // 需先设置非阻塞 socket
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
                break;
            } else if (errno == EINTR) {
                nread = 0;
            } else {
                SYS_ERROR("read");
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
static size_t
write_net_data(int fd, void *buf, size_t n, int *close_flag)
{
    *close_flag = 0;
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
            // 需先设置非阻塞 socket，在三次握手未完成或发送缓冲区满出现
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else if (errno == EINTR) {
                nwritten = 0;
            } else {
                SYS_ERROR("write");
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
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        SYS_ERROR("fd: %d, accept", client_fd);
        return;
    }
    LOGGER_DEBUG("fd: %d, tcp_accept_conn", client_fd);

    if (set_nonblock(client_fd) < 0) {
        SYS_ERROR("fd: %d, set_nonblock", client_fd);
        close(client_fd);
        return;
    }

//    if (set_nondelay(client_fd) < 0) {
//        SYS_ERROR("set_nondelay: %s", strerror(errno));
//        close(client_fd);
//        return;
//    }

    NetData *nd = init_net_data();
    if (nd == NULL) {
        LOGGER_ERROR("fd: %d, init_net_data", client_fd);
        close(client_fd);
        return;
    }
    nd->client_fd = client_fd;
    nd->user_info = (NooneUserInfo *)data;
    memcpy(&nd->client_addr->ai_addr, &client_addr, client_addr_len);
    nd->client_addr->ai_addrlen = client_addr_len;
    nd->client_buf = init_buffer(CLIENT_BUF_CAPACITY);
    nd->remote_buf = init_buffer(REMOTE_BUF_CAPACITY);

    REGISTER_CLIENT(nd->client_event_status);
}

void
tcp_read_client(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    char buf[CLIENT_BUF_CAPACITY];
    size_t nread = read(fd, buf, sizeof(buf));
    if (nread == 0) {  // ss_client 关闭
        LOGGER_DEBUG("fd: %d, tcp_read_client, client close!", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE();
    } else if (nread < 0) {
        SYS_ERROR("read");
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
            return;
        }
        CLEAR_CLIENT_AND_REMOTE();
    }
    LOGGER_DEBUG("fd: %d, tcp_read_client, nread: %ld", nd->client_fd, nread);

    int iv_len = 0;
    if (nd->ss_stage == STAGE_INIT) {
        iv_len = nd->user_info->cryptor_info->iv_len;
        memcpy(nd->iv, buf, iv_len);
        nread -= iv_len;
        if (handle_stage_init(nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_init", nd->client_fd);
            CLEAR_CLIENT_AND_REMOTE();
        }
        if (nread == 0) {
            return;
        }
    }

    Buffer *cbuf = nd->client_buf;
    size_t ret = DECRYPT(nd, buf+iv_len, nread);
    if (ret == 0) {
        LOGGER_ERROR("fd: %d, tcp_read_client, DECRYPT", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE();
    }
    cbuf->len = ret;

    if (nd->ss_stage == STAGE_HEADER) {
        if (handle_stage_header(nd, SOCK_STREAM) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_header", nd->client_fd);
            CLEAR_CLIENT_AND_REMOTE();
        }
        if (cbuf->len == 0) {
            return;
        }
    }

    if (nd->ss_stage == STAGE_HANDSHAKE) {
        LOGGER_INFO("fd: %d, connecting %s:%s",
                    nd->client_fd, nd->remote_domain, nd->remote_port);
        if (handle_stage_handshake(nd) < 0) {
            LOGGER_ERROR("fd: %d, handle_stage_handshake", fd);
            CLEAR_CLIENT_AND_REMOTE();
        }
    }

    // 不需要考虑重复注册问题
    // ae_register_event() 中有相应处理逻辑
    nd->client_event_status ^= AE_IN;
    nd->remote_event_status |= AE_OUT;
    REGISTER_CLIENT(nd->client_event_status);
    REGISTER_REMOTE(nd->remote_event_status);
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    Buffer *cbuf = nd->client_buf;
    if (cbuf->len == 0) {
        LOGGER_DEBUG("tcp_write_remote 空！");
        return;
    }
    size_t nwriten = write(fd, cbuf->data+cbuf->idx, cbuf->len);
    if (nwriten == 0) {
        LOGGER_DEBUG("fd: %d, tcp_write_remote, remote close!", nd->client_fd);
        CLEAR_REMOTE();
        return;
    } else if (nwriten < 0) {
        SYS_ERROR("write");
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        CLEAR_REMOTE();
        return;
    }
    LOGGER_DEBUG("fd: %d, tcp_write_remote, nwriten: %ld", nd->client_fd, nwriten);

    cbuf->len -= nwriten;
    if (cbuf->len > 0) {  // 没有写完，不能改变事件，要继续写
        LOGGER_DEBUG("fd: %d, tcp_write_remote not completed", nd->client_fd);
        cbuf->idx += nwriten;
        return;  // 没写完，不改变 AE_IN||AE_OUT 状态
    }
    cbuf->idx = 0;

    nd->client_event_status |= AE_IN;
    nd->remote_event_status ^= AE_OUT;
    REGISTER_CLIENT(nd->client_event_status);
    REGISTER_REMOTE(nd->remote_event_status);
}

void
tcp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    char buf[REMOTE_BUF_CAPACITY];
    size_t nread = read(fd, buf, sizeof(buf));
    if (nread == 0) {
        LOGGER_DEBUG("fd: %d, tcp_read_remote, remote close!", nd->client_fd);
        CLEAR_REMOTE();
        return;
    } else if (nread < 0) {
        SYS_ERROR("read");
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
            return;
        }
        CLEAR_REMOTE();
        return;
    }
    LOGGER_DEBUG("fd: %d, tcp_read_remote, nread: %ld", nd->client_fd, nread);

    Buffer *rbuf = nd->remote_buf;
    size_t ret = ENCRYPT(nd, buf, nread);
    if (ret == 0) {
        LOGGER_ERROR("fd: %d, tcp_read_remote, ENCRYPT", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE();
    }
    rbuf->len = ret;

    nd->client_event_status |= AE_OUT;
    nd->remote_event_status ^= AE_IN;
    REGISTER_CLIENT(nd->client_event_status);
    REGISTER_REMOTE(nd->remote_event_status);
}

void
tcp_write_client(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    if (nd->is_iv_send == 0) {
        NooneCryptorInfo *ci = nd->user_info->cryptor_info;
        if (write(fd, nd->iv, ci->iv_len) < ci->iv_len) {
            LOGGER_ERROR("fd: %d, write iv error!", nd->client_fd);
            CLEAR_CLIENT_AND_REMOTE();
        }
        nd->is_iv_send = 1;
    }

    Buffer *rbuf = nd->remote_buf;
    if (rbuf->len == 0) {
        LOGGER_DEBUG("tcp_write_client 空！");
        return;
    }
    size_t nwriten = write(fd, rbuf->data+rbuf->idx, rbuf->len);
    if (nwriten == 0) {
        LOGGER_DEBUG("fd: %d, tcp_write_client, client close!", nd->client_fd);
        CLEAR_CLIENT_AND_REMOTE();
    } else if (nwriten < 0) {
        SYS_ERROR("write");
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        CLEAR_CLIENT_AND_REMOTE();
    }
    LOGGER_DEBUG("fd: %d, tcp_write_client, nwriten: %ld", nd->client_fd, nwriten);

    rbuf->len -= nwriten;
    if (rbuf->len > 0) {
        LOGGER_DEBUG("fd: %d, tcp_write_client not completed", nd->client_fd);
        rbuf->idx += nwriten;
        return;  // 没写完，不能改变状态，因为缓冲区可能被覆盖
    }
    rbuf->idx = 0;

    nd->client_event_status ^= AE_OUT;
    nd->remote_event_status |= AE_IN;
    REGISTER_CLIENT(nd->client_event_status);
    REGISTER_REMOTE(nd->remote_event_status);
}