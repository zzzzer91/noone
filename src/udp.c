/*
 * Created by zzzzer on 3/18/19.
 */

#include "udp.h"
#include "transport.h"
#include "log.h"
#include "error.h"
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define CLIENT_BUF_CAPACITY 8 * 1024
#define REMOTE_BUF_CAPACITY 8 * 1024

#define ENCRYPT(nd, plainbuf, plainbuf_len, cipherbuf) \
    encrypt((nd)->cipher_ctx->decrypt_ctx, (uint8_t *)(plainbuf), (plainbuf_len), \
            (uint8_t *)(cipherbuf))

#define DECRYPT(nd, cipherbuf, cipherbuf_len, plainbuf) \
    decrypt((nd)->cipher_ctx->decrypt_ctx, (uint8_t *)(cipherbuf), (cipherbuf_len), \
            (uint8_t *)(plainbuf))

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
        CLEAR_CLIENT_AND_REMOTE();
    }

    int iv_len = nd->user_info->cryptor_info->iv_len;
    memcpy(nd->iv, cipherbuf, iv_len);
    nread -= iv_len;
    if (handle_stage_init(nd) < 0) {
        SYS_ERROR("handle_stage_init");
        CLEAR_CLIENT_AND_REMOTE();
    }

    Buffer *cbuf = init_buffer(CLIENT_BUF_CAPACITY);
    size_t ret = DECRYPT(nd, cipherbuf+iv_len, nread, cbuf->data);
    if (ret == 0) {
        SYS_ERROR("DECRYPT");
        CLEAR_CLIENT_AND_REMOTE();
    }
    cbuf->len = ret;
    nd->client_buf = cbuf;

    if (nd->ss_stage == STAGE_HEADER) {
        if (handle_stage_header(nd, SOCK_DGRAM) < 0) {
            SYS_ERROR("handle_stage_header");
            CLEAR_CLIENT_AND_REMOTE();
        }
    }

    if (cbuf->len == 0) {  // 解析完头部后，没有数据了
        CLEAR_CLIENT_AND_REMOTE();
        return;
    }

    if (create_remote_socket(nd) < 0) {
        SYS_ERROR("create_remote_socket");
        CLEAR_CLIENT_AND_REMOTE();
    }

    MyAddrInfo *raddr = nd->remote_addr;
    if (sendto(fd, cbuf->data, cbuf->len, 0,
            (struct sockaddr *)&raddr->ai_addr, raddr->ai_addrlen) < cbuf->len) {
        SYS_ERROR("sendto");
        CLEAR_CLIENT_AND_REMOTE();
    }

    free_buffer(cbuf);

    if (ae_register_event(event_loop, nd->remote_fd, AE_IN,
            udp_read_remote, NULL, handle_timeout, nd) < 0) {
        SYS_ERROR("ae_register_event");
        CLEAR_CLIENT_AND_REMOTE();
    }
}

void
udp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{
    LOGGER_DEBUG("udp_read_remote");
    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len;

    NetData *nd = data;

    char plainbuf[REMOTE_BUF_CAPACITY];
    remote_addr_len = sizeof(remote_addr);
    size_t nread = recvfrom(fd, plainbuf, sizeof(plainbuf), 0,
            (struct sockaddr *)&remote_addr, &remote_addr_len);
    if (nread < 0) {
        SYS_ERROR("recvfrom");
        CLEAR_CLIENT_AND_REMOTE();
    }

    char cipherbuf[REMOTE_BUF_CAPACITY];
    int iv_len = nd->user_info->cryptor_info->iv_len;
    size_t cipherbuf_len = ENCRYPT(nd, plainbuf, nread, cipherbuf+iv_len);
    if (cipherbuf_len == 0) {
        SYS_ERROR("ENCRYPT");
        CLEAR_CLIENT_AND_REMOTE();
    }
    cipherbuf_len += iv_len;

    MyAddrInfo *caddr = nd->client_addr;
    if (sendto(fd, cipherbuf, cipherbuf_len, 0,
               (struct sockaddr *)&caddr->ai_addr, caddr->ai_addrlen) < cipherbuf_len) {
        SYS_ERROR("sendto");
        CLEAR_CLIENT_AND_REMOTE();
    }

    CLEAR_CLIENT_AND_REMOTE();
}