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
#include "dns.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>      /* close() */
#include <sys/socket.h>  /* accept() */
#include <netinet/in.h>  /* struct sockaddr_in */

#define CLIENT_BUF_CAPACITY 16 * 1024
#define REMOTE_BUF_CAPACITY 32 * 1024

#define TCP_DEBUG(s, args...) \
    do { \
        if (nd->ss_stage > STAGE_INIT) { \
            LOGGER_DEBUG("fd: %d, %s:%d, %s: " s, \
                    nd->client_fd, nd->remote_domain, nd->remote_port, __func__, ##args); \
        } else { \
            LOGGER_DEBUG("fd: %d, %s: " s, nd->client_fd, __func__, ##args); \
        } \
    } while (0)

#define TCP_ERROR(s) \
    do { \
        if (errno != 0) { \
            LOGGER_ERROR("fd: %d, %s -> " s ": %s", nd->client_fd, __func__, strerror(errno)); \
            errno = 0; \
        } else {\
            LOGGER_ERROR("fd: %d, %s -> " s, nd->client_fd, __func__); \
        } \
    } while (0)

#define REGISTER_CLIENT() \
    do { \
        if (nd->client_fd != -1) { \
            if (ae_register_event(event_loop, nd->client_fd, nd->client_event_status, \
                        tcp_read_client, tcp_write_client, handle_stream_timeout, nd) < 0) { \
                TCP_ERROR("REGISTER_CLIENT"); \
                CLEAR_ALL(); \
            } \
        } \
    } while (0)

#define REGISTER_REMOTE() \
    do { \
        if (nd->remote_fd != -1) { \
            if (ae_register_event(event_loop, nd->remote_fd, nd->remote_event_status, \
                    tcp_read_remote, tcp_write_remote, handle_stream_timeout, nd) < 0) { \
                TCP_ERROR("REGISTER_REMOTE"); \
                CLEAR_ALL(); \
            } \
        } \
    } while (0)

#define READ(sockfd, buf, cap) \
    ({ \
        ssize_t ret = read(sockfd, buf, cap); \
        if (ret == 0) { \
            TCP_DEBUG("close!"); \
            CLEAR_ALL(); \
        } else if (ret < 0) { \
            TCP_ERROR("READ"); \
            if (errno == EINTR || errno == EAGAIN \
                    || errno == ETIMEDOUT || errno == EWOULDBLOCK) { \
                return; \
            } \
            CLEAR_ALL(); \
        } \
        TCP_DEBUG("%ld", ret); \
        ret; \
    })

#define WRITE(sockfd, buf, n) \
    ({ \
        ssize_t ret = write(fd, buf, n); \
        if (ret == 0) { \
            TCP_DEBUG("close!"); \
            CLEAR_ALL(); \
        } else if (ret < 0) { \
            TCP_ERROR("WRITE"); \
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { \
                return; \
            } \
            CLEAR_ALL(); \
        } \
        TCP_DEBUG("%ld", ret); \
        ret; \
    })

//#define RESIZE_BUF(buf, size) \
//    do { \
//        size_t need_cap = buf->len + size; \
//        size_t step = buf->capacity >> 1U; \
//        size_t new_cap = buf->capacity + step; \
//        while (need_cap > new_cap) { \
//            new_cap += step;\
//        } \
//        if (resize_buffer(buf, new_cap) < 0) { \
//            TCP_ERROR("RESIZE_BUF"); \
//            CLEAR_ALL(); \
//        } \
//        TCP_DEBUG("RESIZE_BUF: %ld", new_cap); \
//    } while (0)

static void
handle_dns(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;
    TCP_DEBUG("DNS success!");

    char buffer[1024] = {0};
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int n = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addr_len);
    if (n < 0) {
        TCP_ERROR("recvfrom");
        return;
    }

    unsigned int netip = dns_parse_response(buffer);

    CLEAR_DNS();

    // 只支持 ipv4
    MyAddrInfo *addr_info = malloc(sizeof(MyAddrInfo));
    addr_info->ai_addrlen = sizeof(struct sockaddr_in);
    addr_info->ai_family = AF_INET;
    addr_info->ai_socktype = SOCK_STREAM;
    addr_info->ai_addr.sin.sin_addr.s_addr = netip;
    addr_info->ai_addr.sin.sin_family = AF_INET;
    addr_info->ai_addr.sin.sin_port = htons(nd->remote_port);
    nd->remote_addr = addr_info;

    char domain_and_port[MAX_DOMAIN_LEN+MAX_PORT_LEN+1];
    snprintf(domain_and_port, MAX_DOMAIN_LEN+MAX_PORT_LEN,
             "%s:%d", nd->remote_domain, nd->remote_port);
    // 加入 lru
    void *oldvalue;
    LruCache *lc = nd->user_info->lru_cache;
    if (lru_cache_put(lc, domain_and_port, addr_info, &oldvalue) < 0) {
        free(addr_info);
        return;
    }
    if (oldvalue != NULL) {
        // LOGGER_DEBUG("lru replace!");
        free(oldvalue);
    }
    // LOGGER_DEBUG("lru size: %ld", lc->size);

    LOGGER_DEBUG("fd: %d, connecting %s:%d",
                 nd->client_fd, nd->remote_domain, nd->remote_port);
    if (handle_stage_handshake(nd) < 0) {
        TCP_ERROR("handle_stage_handshake");
        CLEAR_ALL();
    }

    if (nd->client_buf->len == 0) {
        nd->client_event_status |= AE_IN;
        REGISTER_CLIENT();
        return;
    }

    nd->remote_event_status |= AE_OUT;
    REGISTER_REMOTE();
}

void
tcp_accept_conn(AeEventLoop *event_loop, int fd, void *data)
{
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        SYS_ERROR("accept");
        return;
    }
    LOGGER_DEBUG("fd: %d, tcp_accept_conn", client_fd);

    if (set_nonblock(client_fd) < 0) {
        SYS_ERROR("set_nonblock");
        close(client_fd);
        return;
    }

    if (set_nondelay(client_fd) < 0) {
        SYS_ERROR("set_nondelay");
        close(client_fd);
        return;
    }

    NetData *nd = init_net_data();
    if (nd == NULL) {
        SYS_ERROR("init_net_data");
        close(client_fd);
        return;
    }

    nd->client_fd = client_fd;
    nd->user_info = data;
    memcpy(&nd->client_addr->ai_addr, &client_addr, client_addr_len);
    nd->client_addr->ai_addrlen = client_addr_len;
    // 多出来的给 iv 分配，和防止加密后长度变化导致溢出
    nd->client_buf = init_buffer(CLIENT_BUF_CAPACITY+128);
    if (nd->client_buf == NULL) {
        SYS_ERROR("init_buffer");
        close(client_fd);
        free_net_data(nd);
        return;
    }
    nd->remote_buf = init_buffer(REMOTE_BUF_CAPACITY+128);
    if (nd->remote_buf == NULL) {
        SYS_ERROR("init_buffer");
        close(client_fd);
        free_net_data(nd);
        return;
    }

    REGISTER_CLIENT();
}

void
tcp_read_client(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    char temp_buf[CLIENT_BUF_CAPACITY];
    ssize_t nread = READ(fd, temp_buf, sizeof(temp_buf));

    int iv_len = 0;
    if (nd->ss_stage == STAGE_INIT) {
        iv_len = nd->user_info->cryptor_info->iv_len;
        memcpy(nd->iv, temp_buf, iv_len);
        nread -= iv_len;
        if (handle_stage_init(nd) < 0) {
            TCP_ERROR("handle_stage_init");
            CLEAR_ALL();
        }
        if (nread == 0) {
            return;
        }
    }

    Buffer *cbuf = nd->client_buf;
    DECRYPT(temp_buf+iv_len, nread, cbuf->data);

    if (nd->ss_stage == STAGE_HEADER) {
        if (handle_stage_header(nd, SOCK_STREAM) < 0) {
            TCP_ERROR("handle_stage_header");
            CLEAR_ALL();
        }
    }

    if (nd->ss_stage == STAGE_DNS) {
        if (handle_stage_dns(nd) < 0) {
            TCP_ERROR("handle_stage_dns");
            CLEAR_ALL();
        }
        if (nd->ss_stage == STAGE_DNS) {  // 异步查询 dns
            if (ae_register_event(event_loop, nd->dns_fd, AE_IN,
                    handle_dns, NULL, handle_stream_timeout, nd) < 0) {
                TCP_ERROR("handle_stage_dns");
                CLEAR_ALL();
            }
            nd->client_event_status ^= AE_IN;
            REGISTER_CLIENT();
            return;
        }
    }

    if (nd->ss_stage == STAGE_HANDSHAKE) {
        LOGGER_DEBUG("fd: %d, connecting %s:%d",
                nd->client_fd, nd->remote_domain, nd->remote_port);
        if (handle_stage_handshake(nd) < 0) {
            TCP_ERROR("handle_stage_handshake");
            CLEAR_ALL();
        }
    }

    // 解析完头部后没有数据了
    if (cbuf->len == 0) {
        return;
    }

    // 不需要考虑重复注册问题
    // ae_register_event() 中有相应处理逻辑
    nd->client_event_status ^= AE_IN;
    nd->remote_event_status |= AE_OUT;
    REGISTER_CLIENT();
    REGISTER_REMOTE();
}

void
tcp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    Buffer *cbuf = nd->client_buf;
    ssize_t nwriten = WRITE(fd, cbuf->data+cbuf->idx, cbuf->len);
    cbuf->len -= nwriten;
    if (cbuf->len > 0) {  // 没有写完，不能改变事件，要继续写
        TCP_DEBUG("not completed!");
        cbuf->idx += nwriten;
        return;  // 没写完，不改变 AE_IN||AE_OUT 状态
    }
    cbuf->idx = 0;

    nd->client_event_status |= AE_IN;
    nd->remote_event_status ^= AE_OUT;
    REGISTER_CLIENT();
    REGISTER_REMOTE();
}

void
tcp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    char temp_buf[REMOTE_BUF_CAPACITY];
    ssize_t nread = READ(fd, temp_buf, sizeof(temp_buf));

    Buffer *rbuf = nd->remote_buf;
    int iv_len = 0;
    if (nd->is_iv_send == 0) {
        iv_len = nd->user_info->cryptor_info->iv_len;
        memcpy(rbuf->data, nd->iv, iv_len);
        nd->is_iv_send = 1;
    }
    ENCRYPT(temp_buf, nread, rbuf->data+iv_len);
    rbuf->len += iv_len;

    nd->client_event_status |= AE_OUT;
    nd->remote_event_status ^= AE_IN;
    REGISTER_CLIENT();
    REGISTER_REMOTE();
}

void
tcp_write_client(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;

    Buffer *rbuf = nd->remote_buf;
    ssize_t nwriten = WRITE(fd, rbuf->data+rbuf->idx, rbuf->len);
    rbuf->len -= nwriten;
    if (rbuf->len > 0) {
        TCP_DEBUG("not completed!");
        rbuf->idx += nwriten;
        return;  // 没写完，不能改变状态，因为缓冲区可能被覆盖
    }
    rbuf->idx = 0;

    nd->client_event_status ^= AE_OUT;
    nd->remote_event_status |= AE_IN;
    REGISTER_CLIENT();
    REGISTER_REMOTE();
}