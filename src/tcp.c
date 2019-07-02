/*
 * Created by zzzzer on 2/11/19.
 */

#include "tcp.h"
#include "transport.h"
#include "dns.h"
#include <unistd.h>      /* close() */

#define CLIENT_BUF_CAPACITY (16 * 1024)
#define REMOTE_BUF_CAPACITY (32 * 1024)

#define TCP_REGISTER_CLIENT_EVENT() \
    REGISTER_CLIENT_EVENT(tcp_read_client, tcp_write_client)

#define TCP_REGISTER_REMOTE_EVENT() \
    REGISTER_REMOTE_EVENT(tcp_read_remote, tcp_write_remote)

#define READ(sockfd, buf, cap) \
    ({ \
        ssize_t ret = read(sockfd, buf, cap); \
        if (ret == 0) { \
            TRANSPORT_DEBUG("close!"); \
            CLEAR_ALL(); \
        } else if (ret < 0) { \
            if (errno == EINTR || errno == EAGAIN \
                    || errno == ETIMEDOUT || errno == EWOULDBLOCK) { \
                return; \
            } \
            TRANSPORT_ERROR("READ: %s", strerror(errno)); \
            CLEAR_ALL(); \
        } \
        TRANSPORT_DEBUG("%ld", ret); \
        (size_t)ret; \
    })

#define WRITE(sockfd, buf, n) \
    ({ \
        ssize_t ret = write(sockfd, buf, n); \
        if (ret == 0) { \
            TRANSPORT_DEBUG("close!"); \
            CLEAR_ALL(); \
        } else if (ret < 0) { \
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { \
                return; \
            } \
            TRANSPORT_ERROR("WRITE: %s", strerror(errno)); \
            CLEAR_ALL(); \
        } \
        TRANSPORT_DEBUG("%ld", ret); \
        (size_t)ret; \
    })

static void handle_dns(AeEventLoop *event_loop, int fd, void *data) {
    NetData *nd = data;
    TRANSPORT_DEBUG("DNS success!");

    char buffer[1024];
    // udp 不关心 remote 地址，用 read，否则用 recvfrom
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n < 0) {
        TRANSPORT_ERROR("read: %s", strerror(errno));
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

    if (add_dns_to_lru_cache(nd, addr_info) < 0) {
        TRANSPORT_ERROR("add_dns_to_lru_cache");
        free(addr_info);
        CLEAR_ALL();
    }

    LOGGER_INFO("fd: %d, connecting %s:%d", nd->client_fd, nd->remote_domain, nd->remote_port);
    if (handle_stage_handshake(nd) < 0) {
        TRANSPORT_ERROR("handle_stage_handshake");
        CLEAR_ALL();
    }

    if (nd->client_buf->len == 0) {
        nd->client_event_status |= AE_IN;
        TCP_REGISTER_CLIENT_EVENT();
        return;
    }

    nd->remote_event_status |= AE_OUT;
    TCP_REGISTER_REMOTE_EVENT();
}

void tcp_accept_conn(AeEventLoop *event_loop, int fd, void *data) {
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
    memcpy(&nd->client_addr.ai_addr, &client_addr, client_addr_len);
    nd->client_addr.ai_addrlen = client_addr_len;
    // 多出来的给 iv 分配，和防止加密后长度变化导致溢出
    nd->client_buf = init_buffer(CLIENT_BUF_CAPACITY + 128);
    if (nd->client_buf == NULL) {
        SYS_ERROR("init_buffer");
        close(client_fd);
        free_net_data(nd);
        return;
    }
    nd->remote_buf = init_buffer(REMOTE_BUF_CAPACITY + 128);
    if (nd->remote_buf == NULL) {
        SYS_ERROR("init_buffer");
        close(client_fd);
        free_net_data(nd);
        return;
    }

    TCP_REGISTER_CLIENT_EVENT();
}

void tcp_read_client(AeEventLoop *event_loop, int fd, void *data) {
    NetData *nd = data;

    char temp_buf[CLIENT_BUF_CAPACITY];
    size_t nread = READ(fd, temp_buf, sizeof(temp_buf));

    uint8_t iv_len = 0;
    if (nd->stage == STAGE_INIT) {
        iv_len = nd->user_info->cryptor_info->iv_len;
        memcpy(nd->iv, temp_buf, iv_len);
        nread -= iv_len;
        if (handle_stage_init(nd) < 0) {
            TRANSPORT_ERROR("handle_stage_init");
            CLEAR_ALL();
        }
        if (nread == 0) {
            return;
        }
    }

    Buffer *cbuf = nd->client_buf;
    DECRYPT(temp_buf + iv_len, nread, cbuf->data);

    if (nd->stage == STAGE_HEADER) {
        if (handle_stage_header(nd, SOCK_STREAM) < 0) {
            TRANSPORT_ERROR("handle_stage_header");
            CLEAR_ALL();
        }
    }

    if (nd->stage == STAGE_DNS) {
        if (handle_stage_dns(nd) < 0) {
            TRANSPORT_ERROR("handle_stage_dns");
            CLEAR_ALL();
        }
        if (nd->stage == STAGE_DNS) {  // 异步查询 dns
            REGISTER_DNS_EVENT(handle_dns);
            // 挂起 client 事件
            nd->client_event_status ^= AE_IN;
            TCP_REGISTER_CLIENT_EVENT();
            return;
        }
    }

    if (nd->stage == STAGE_HANDSHAKE) {
        LOGGER_DEBUG("fd: %d, connecting %s:%d", nd->client_fd, nd->remote_domain, nd->remote_port);
        if (handle_stage_handshake(nd) < 0) {
            TRANSPORT_ERROR("handle_stage_handshake");
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
    TCP_REGISTER_CLIENT_EVENT();
    TCP_REGISTER_REMOTE_EVENT();
}

void tcp_write_remote(AeEventLoop *event_loop, int fd, void *data) {
    NetData *nd = data;

    Buffer *cbuf = nd->client_buf;
    // 这里缓冲区要加上索引
    // 1.是可能解析完头部，索引有偏移
    // 2.是可能上一次没写完
    size_t nwriten = WRITE(fd, cbuf->data + cbuf->idx, cbuf->len);
    cbuf->len -= nwriten;
    if (cbuf->len > 0) {  // 没有写完，不能改变事件，要继续写
        TRANSPORT_DEBUG("not completed!");
        cbuf->idx += nwriten;
        return;  // 没写完，不改变 AE_IN||AE_OUT 状态
    }
    cbuf->idx = 0;

    nd->client_event_status |= AE_IN;
    nd->remote_event_status ^= AE_OUT;
    TCP_REGISTER_CLIENT_EVENT();
    TCP_REGISTER_REMOTE_EVENT();
}

void tcp_read_remote(AeEventLoop *event_loop, int fd, void *data) {
    NetData *nd = data;

    char temp_buf[REMOTE_BUF_CAPACITY];
    size_t nread = READ(fd, temp_buf, sizeof(temp_buf));

    Buffer *rbuf = nd->remote_buf;
    uint8_t iv_len = 0;
    if (nd->is_iv_send == 0) {
        iv_len = nd->user_info->cryptor_info->iv_len;
        memcpy(rbuf->data, nd->iv, iv_len);
        nd->is_iv_send = 1;
    }
    ENCRYPT(temp_buf, nread, rbuf->data + iv_len);
    rbuf->len += iv_len;

    nd->client_event_status |= AE_OUT;
    nd->remote_event_status ^= AE_IN;
    TCP_REGISTER_CLIENT_EVENT();
    TCP_REGISTER_REMOTE_EVENT();
}

void tcp_write_client(AeEventLoop *event_loop, int fd, void *data) {
    NetData *nd = data;

    Buffer *rbuf = nd->remote_buf;
    size_t nwriten = WRITE(fd, rbuf->data + rbuf->idx, rbuf->len);
    rbuf->len -= nwriten;
    if (rbuf->len > 0) {
        TRANSPORT_DEBUG("not completed!");
        rbuf->idx += nwriten;
        return;
    }
    rbuf->idx = 0;

    nd->client_event_status ^= AE_OUT;
    nd->remote_event_status |= AE_IN;
    TCP_REGISTER_CLIENT_EVENT();
    TCP_REGISTER_REMOTE_EVENT();
}