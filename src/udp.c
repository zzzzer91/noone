/*
 * Created by zzzzer on 3/18/19.
 */

#include "udp.h"
#include "transport.h"
#include "dns.h"
#include <unistd.h>
#include <arpa/inet.h>

#define HEAD_PREFIX 128
#define CLIENT_BUF_CAPACITY (8 * 1024)
#define REMOTE_BUF_CAPACITY (8 * 1024)

#define UDP_REGISTER_REMOTE_EVENT() \
    REGISTER_REMOTE_EVENT(udp_read_remote, NULL)

#define RECVFROM(sockfd, buf, buf_cap, addr_p) \
    ({ \
        ssize_t ret = recvfrom(sockfd, buf, buf_cap, 0, \
                (struct sockaddr *)&(addr_p)->ai_addr, &(addr_p)->ai_addrlen); \
        if (ret < 0) { \
            TRANSPORT_ERROR("recvfrom: %s", strerror(errno)); \
            CLEAR_ALL(); \
        } \
        (size_t)ret; \
    })

#define SENDTO(sockfd, buf, buf_len, addr_p) \
    do { \
        if (sendto(sockfd, buf, buf_len, 0, \
                (struct sockaddr *)&(addr_p)->ai_addr, (addr_p)->ai_addrlen) < (buf_len)) { \
            TRANSPORT_ERROR("sendto: %s", strerror(errno));\
            CLEAR_ALL();\
        }\
    } while (0)

static void handle_dns(AeEventLoop *event_loop, int fd, void *data) {
    NetData *nd = data;

    TRANSPORT_DEBUG("DNS success!");

    char buffer[1024];
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

    add_dns_to_lru_cache(nd, addr_info);

    if (create_remote_socket(nd) < 0) {
        TRANSPORT_ERROR("create_remote_socket");
        CLEAR_ALL();
    }

    MyAddrInfo *raddr = nd->remote_addr;
    Buffer *cbuf = nd->client_buf;
    SENDTO(nd->remote_fd, cbuf->data + cbuf->idx, cbuf->len, raddr);

    free_buffer(cbuf);
    nd->client_buf = NULL;

    UDP_REGISTER_REMOTE_EVENT();
}

static int build_send_header(char *buf, MyAddrInfo *remote_addr) {
    char temp_buf[HEAD_PREFIX];
    int header_len = 1;  // 1 留给 atty
    char atty;
    if (remote_addr->ai_addrlen != 16) {  // 是 ipv6
        atty = 0x03;
        memcpy(temp_buf + header_len, &remote_addr->ai_addr.sin6.sin6_addr, 16);
        header_len += 16;
        memcpy(temp_buf + header_len, &remote_addr->ai_addr.sin6.sin6_port, 2);
        header_len += 2;
    } else {  // 是 ipv4
        atty = 0x01;
        memcpy(temp_buf + header_len, &remote_addr->ai_addr.sin.sin_addr, 4);
        header_len += 4;
        memcpy(temp_buf + header_len, &remote_addr->ai_addr.sin.sin_port, 2);
        header_len += 2;
    }
    temp_buf[0] = atty;
    memcpy(buf + HEAD_PREFIX - header_len, temp_buf, header_len);

    return header_len;
}

void udp_read_client(AeEventLoop *event_loop, int fd, void *data) {
    NetData *nd = init_net_data();
    if (nd == NULL) {
        TRANSPORT_ERROR("init_net_data");
        return;
    }
    nd->user_info = (NooneUserInfo *)data;

    TRANSPORT_DEBUG("udp_read_client");

    MyAddrInfo *caddr = &nd->client_addr;
    char cipherbuf[CLIENT_BUF_CAPACITY];
    caddr->ai_addrlen = sizeof(caddr->ai_addr);
    size_t nread = RECVFROM(fd, cipherbuf, sizeof(cipherbuf), caddr);

    uint8_t iv_len = nd->user_info->cryptor_info->iv_len;
    memcpy(nd->iv, cipherbuf, iv_len);
    nread -= iv_len;
    if (handle_stage_init(nd) < 0) {
        TRANSPORT_ERROR("handle_stage_init");
        CLEAR_ALL();
    }

    Buffer *cbuf = init_buffer(CLIENT_BUF_CAPACITY + 128);
    nd->client_buf = cbuf;
    DECRYPT(cipherbuf + iv_len, nread, cbuf->data);

    if (nd->stage == STAGE_HEADER) {
        if (handle_stage_header(nd, SOCK_DGRAM) < 0) {
            TRANSPORT_ERROR("handle_stage_header");
            CLEAR_ALL();
        }
        if (cbuf->len == 0) {  // 解析完头部后，没有数据了
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
            return;
        }
    }

    if (create_remote_socket(nd) < 0) {
        TRANSPORT_ERROR("create_remote_socket");
        CLEAR_ALL();
    }

    MyAddrInfo *raddr = nd->remote_addr;
    SENDTO(nd->remote_fd, cbuf->data + cbuf->idx, cbuf->len, raddr);

    free_buffer(nd->client_buf);
    nd->client_buf = NULL;

    UDP_REGISTER_REMOTE_EVENT();
}

void udp_read_remote(AeEventLoop *event_loop, int fd, void *data) {
    NetData *nd = data;

    TRANSPORT_DEBUG("udp_read_remote");

    char plainbuf[REMOTE_BUF_CAPACITY + HEAD_PREFIX]; // 前面放头部信息
    // 不关心远端 addr，用 read() 即可
    ssize_t nread = read(fd, plainbuf + HEAD_PREFIX, sizeof(plainbuf));
    if (nread < 0) {
        TRANSPORT_ERROR("recvfrom: %s", strerror(errno));
        return;
    }

    int header_len = build_send_header(plainbuf, nd->remote_addr);
    nread += header_len;

    Buffer *rbuf = init_buffer(REMOTE_BUF_CAPACITY + 128);
    nd->remote_buf = rbuf;
    uint8_t iv_len = nd->user_info->cryptor_info->iv_len;
    memcpy(rbuf->data, nd->iv, iv_len);
    ENCRYPT(plainbuf + HEAD_PREFIX - header_len, (size_t)nread, rbuf->data + iv_len);
    rbuf->len += iv_len;

    int sockfd = nd->user_info->udp_server_fd;
    MyAddrInfo *caddr = &nd->client_addr;
    SENDTO(sockfd, rbuf->data, rbuf->len, caddr);

    CLEAR_ALL();
}