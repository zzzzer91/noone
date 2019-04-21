/*
 * Created by zzzzer on 3/18/19.
 */

#include "udp.h"
#include "transport.h"
#include "log.h"
#include "error.h"
#include "socket.h"
#include "dns.h"
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define HEAD_PREFIX 128
#define CLIENT_BUF_CAPACITY 8 * 1024
#define REMOTE_BUF_CAPACITY 8 * 1024

static void
handle_dns(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = data;
    LOGGER_DEBUG("DNS success!");

    char buffer[1024] = {0};
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int n = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addr_len);
    if (n < 0) {
        SYS_ERROR("recvfrom");
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
        free(oldvalue);
    }

    if (create_remote_socket(nd) < 0) {
        SYS_ERROR("create_remote_socket");
        CLEAR_ALL();
    }

    MyAddrInfo *raddr = nd->remote_addr;
    Buffer *cbuf = nd->client_buf;
    if (sendto(nd->remote_fd, cbuf->data, cbuf->len, 0,
               (struct sockaddr *)&raddr->ai_addr, raddr->ai_addrlen) < cbuf->len) {
        SYS_ERROR("sendto");
        CLEAR_ALL();
    }

    free_buffer(cbuf);
    nd->client_buf = NULL;

    if (ae_register_event(event_loop, nd->remote_fd, AE_IN,
            udp_read_remote, NULL, handle_stream_timeout, nd) < 0) {
        SYS_ERROR("ae_register_event");
        CLEAR_ALL();
    }
}
void
udp_read_client(AeEventLoop *event_loop, int fd, void *data)
{
    LOGGER_DEBUG("udp_read_client");
    NetData *nd = init_net_data();
    if (nd == NULL) {
        SYS_ERROR("init_net_data");
        return;
    }
    nd->user_info = (NooneUserInfo *)data;

    MyAddrInfo *caddr = nd->client_addr;
    char cipherbuf[CLIENT_BUF_CAPACITY];
    caddr->ai_addrlen = sizeof(caddr->ai_addr);
    size_t nread = recvfrom(fd, cipherbuf, sizeof(cipherbuf), 0,
            (struct sockaddr *)&caddr->ai_addr, &caddr->ai_addrlen);
    if (nread < 0) {
        SYS_ERROR("recvfrom");
        CLEAR_ALL();
    }

    int iv_len = nd->user_info->cryptor_info->iv_len;
    memcpy(nd->iv, cipherbuf, iv_len);
    nread -= iv_len;
    if (handle_stage_init(nd) < 0) {
        SYS_ERROR("handle_stage_init");
        CLEAR_ALL();
    }

    Buffer *cbuf = init_buffer(CLIENT_BUF_CAPACITY+128);
    nd->client_buf = cbuf;
    DECRYPT(cipherbuf+iv_len, nread, cbuf->data);

    if (nd->ss_stage == STAGE_HEADER) {
        if (handle_stage_header(nd, SOCK_DGRAM) < 0) {
            SYS_ERROR("handle_stage_header");
            CLEAR_ALL();
        }
        if (cbuf->len == 0) {  // 解析完头部后，没有数据了
            CLEAR_ALL();
        }
    }

    if (nd->ss_stage == STAGE_DNS) {
        if (handle_stage_dns(nd) < 0) {
            SYS_ERROR("handle_stage_dns");
            CLEAR_ALL();
        }
        if (nd->ss_stage == STAGE_DNS) {  // 异步查询 dns
            if (ae_register_event(event_loop, nd->dns_fd, AE_IN,
                    handle_dns, NULL, handle_stream_timeout, nd) < 0) {
                SYS_ERROR("handle_stage_dns");
                CLEAR_ALL();
            }
            return;
        }
    }

    if (create_remote_socket(nd) < 0) {
        SYS_ERROR("create_remote_socket");
        CLEAR_ALL();
    }

    MyAddrInfo *raddr = nd->remote_addr;
    if (sendto(nd->remote_fd, cbuf->data, cbuf->len, 0,
            (struct sockaddr *)&raddr->ai_addr, raddr->ai_addrlen) < cbuf->len) {
        SYS_ERROR("sendto");
        CLEAR_ALL();
    }

    free_buffer(nd->client_buf);
    nd->client_buf = NULL;

    if (ae_register_event(event_loop, nd->remote_fd, AE_IN,
                          udp_read_remote, NULL, handle_stream_timeout, nd) < 0) {
        SYS_ERROR("ae_register_event");
        CLEAR_ALL();
    }
}

void
udp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    LOGGER_DEBUG("udp_read_remote");

    NetData *nd = data;

    char plainbuf[REMOTE_BUF_CAPACITY+HEAD_PREFIX]; // 前面放头部信息
    MyAddrInfo remote_addr;
    remote_addr.ai_addrlen = sizeof(remote_addr);
    size_t nread = recvfrom(fd, plainbuf+HEAD_PREFIX, sizeof(plainbuf), 0,
            (struct sockaddr *)&remote_addr.ai_addr, &remote_addr.ai_addrlen);
    if (nread < 0) {
        SYS_ERROR("recvfrom");
        CLEAR_ALL();
    }

    char temp_buf[HEAD_PREFIX];
    int header_len = 1;  // 1 留给 atty
    char atty;
    if (remote_addr.ai_addrlen != 16) {  // 是 ipv6
        atty = 0x03;
        memcpy(temp_buf+header_len, &remote_addr.ai_addr.sin6.sin6_addr, 16);
        header_len += 16;
        memcpy(temp_buf+header_len, &remote_addr.ai_addr.sin6.sin6_port, 2);
        header_len += 2;
    } else {  // 是 ipv4
        atty = 0x01;
        memcpy(temp_buf+header_len, &remote_addr.ai_addr.sin.sin_addr, 4);
        header_len += 4;
        memcpy(temp_buf+header_len, &remote_addr.ai_addr.sin.sin_port, 2);
        header_len += 2;
    }
    temp_buf[0] = atty;
    memcpy(plainbuf+HEAD_PREFIX-header_len, temp_buf, header_len);
    nread += header_len;

    Buffer *rbuf = init_buffer(REMOTE_BUF_CAPACITY+128);
    nd->remote_buf = rbuf;
    int iv_len = nd->user_info->cryptor_info->iv_len;
    memcpy(rbuf->data, nd->iv, iv_len);
    ENCRYPT(plainbuf+HEAD_PREFIX-header_len, nread, rbuf->data+iv_len);
    rbuf->len += iv_len;

    int sockfd = nd->user_info->udp_server_fd;
    MyAddrInfo *caddr = nd->client_addr;
    if (sendto(sockfd, rbuf->data, rbuf->len, 0,
               (struct sockaddr *)&caddr->ai_addr, caddr->ai_addrlen) < rbuf->len) {
        SYS_ERROR("sendto");
        CLEAR_ALL();
    }

    CLEAR_ALL();
}