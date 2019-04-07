/*
 * Created by zzzzer on 3/18/19.
 */

#ifndef _NOONE_TRANSPORT_H_
#define _NOONE_TRANSPORT_H_

#include "cryptor.h"
#include "ae.h"
#include "buffer.h"
#include "log.h"
#include "lru.h"
#include "manager.h"
#include <netdb.h>

#define CLIENT_BUF_CAPACITY 16 * 1024
#define REMOTE_BUF_CAPACITY 32 * 1024
#define MAX_DOMAIN_LEN 64
#define MAX_PORT_LEN 5

// ATYP
#define ATYP_IPV4 0x01
#define ATYP_DOMAIN 0x03
#define ATYP_IPV6 0x04

typedef enum SsStageType {
    STAGE_INIT = 0,   /* 获取 iv 阶段 */
    STAGE_HEADER,     /* 解析 header 阶段，获取 remote 的 ip 和 port */
    STAGE_DNS,        /* 查询 DNS，可能不进行这一步 */
    STAGE_HANDSHAKE,  /* TCP 和 remote 握手阶段 */
    STAGE_STREAM,     /* TCP 传输阶段 */
    STAGE_UDP,
    STAGE_DESTROYED = -1
} SsStageType;

typedef struct NetData {

    int ssclient_fd;

    int remote_fd;

    int is_iv_send;

    SsStageType ss_stage;

    char remote_domain[MAX_DOMAIN_LEN+1];

    char remote_port[MAX_PORT_LEN+1];

    struct addrinfo *remote_addr;

    NooneUserInfo *user_info;  // 指向用户信息

    NooneCipherCtx *cipher_ctx;

    Buffer *remote_buf;  // 要发给 remote 的数据

    Buffer *client_buf;  // 要发给 client 的数据

} NetData;

NetData *init_net_data();

void free_net_data(NetData *nd);

int read_net_data(int fd, char *buf, size_t capacity, size_t *len);

int write_net_data(int fd, Buffer *buf);

int init_net_data_cipher(NetData *nd);

int parse_net_data_header(NetData *nd);

void check_last_active(AeEventLoop *event_loop, int fd, void *data);

#define ENCRYPT(nd, buf, buf_len) \
    encrypt((nd)->cipher_ctx->encrypt_ctx, (unsigned char *)(buf), (buf_len), \
            (unsigned char *)(nd)->client_buf->data)

#define DECRYPT(nd, buf, buf_len) \
    decrypt((nd)->cipher_ctx->decrypt_ctx, (unsigned char *)(buf), (buf_len), \
            (unsigned char *)(nd)->remote_buf->data)

#define CLEAR_SSCLIENT(event_loop, nd) \
    do { \
        if (nd->ssclient_fd != -1) { \
            ae_unregister_event(event_loop, nd->ssclient_fd); \
            close(nd->ssclient_fd); \
            nd->ssclient_fd = -1; \
        } \
        if (nd->remote_fd != -1) { \
            ae_unregister_event(event_loop, nd->remote_fd); \
            close(nd->remote_fd); \
            nd->remote_fd = -1; \
        } \
        free_net_data(nd); \
    } while (0)

#define CLEAR_REMOTE(event_loop, nd) \
    do { \
        ae_unregister_event(event_loop, nd->remote_fd); \
        close(nd->remote_fd); \
        nd->remote_fd = -1; \
    } while (0)

#endif  /* _NOONE_TRANSPORT_H_ */
