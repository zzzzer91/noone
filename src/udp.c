/*
 * Created by zzzzer on 3/18/19.
 */

#include "udp.h"
#include "log.h"
#include "transport.h"
#include <unistd.h>
#include <socket.h>
#include <arpa/inet.h>

static int
handle_stage_init(NetData *nd)
{
    NooneCryptorInfo *ci = nd->user_info->cryptor_info;

    struct sockaddr_in conn_addr;
    socklen_t conn_addr_len = sizeof(conn_addr);
    if (recvfrom(nd->ssclient_fd, nd->cipher_ctx->iv, ci->iv_len, 0,
            (struct sockaddr *)&conn_addr, &conn_addr_len) < ci->iv_len) {
        return -1;
    }
    nd->cipher_ctx->iv[ci->iv_len] = 0;
    nd->cipher_ctx->iv_len = ci->iv_len;

    if (init_net_data_cipher(nd) < 0) {
        return -1;
    }

    nd->ss_stage = STAGE_HEADER;

    return 0;
}

static int
handle_stage_header(NetData *nd)
{
    if (parse_net_data_header(nd) < 0) {
        return -1;
    }

    nd->ss_stage = STAGE_UDP;

    return 0;
}

void
udp_accept_conn(AeEventLoop *event_loop, int fd, void *data)
{
    NetData *nd = init_net_data();
    if (nd == NULL) {
        LOGGER_ERROR("udp_accept_conn, init_net_data");
        return;
    }
    nd->user_info = (NooneUserInfo *)data;

    if (nd->ss_stage == STAGE_INIT) {
        if (handle_stage_init(nd) < 0) {
            LOGGER_ERROR("udp_accept_conn, handle_stage_init");
            CLEAR_SSCLIENT(event_loop, nd);
            return;
        }
    }

    unsigned char buf[BUF_CAPACITY];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    size_t buf_len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addr_len);

    size_t ret = DECRYPT(nd, buf, buf_len);
    if (ret == 0) {
        LOGGER_ERROR("udp_accept_conn, DECRYPT");
        CLEAR_SSCLIENT(event_loop, nd);
        return;
    }
    nd->remote_buf->len = ret;

    if (nd->ss_stage == STAGE_HEADER) {
        if (handle_stage_header(nd) < 0) {
            LOGGER_ERROR("udp_accept_conn, handle_stage_header");
            CLEAR_SSCLIENT(event_loop, nd);
            return;
        }
    }

    if (nd->remote_buf->len == 0) {  // 解析完头部后，没有数据了
        return;
    }
}

void
udp_write_remote(AeEventLoop *event_loop, int fd, void *data)
{

}

void
udp_read_remote(AeEventLoop *event_loop, int fd, void *data)
{

}

void
udp_write_ssclient(AeEventLoop *event_loop, int fd, void *data)
{

}