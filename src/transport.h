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
#include "socket.h"
#include "manager.h"
#include <netdb.h>

#define MAX_DOMAIN_LEN 63
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
    STAGE_UDP
} SsStageType;

typedef struct NetData {

    char remote_domain[MAX_DOMAIN_LEN+1];

    char remote_port[MAX_PORT_LEN+1];

    uint8_t iv[MAX_IV_LEN];

    int is_iv_send;

    int client_fd;

    int remote_fd;

    int client_event_status;

    int remote_event_status;

    SsStageType ss_stage;

    MyAddrInfo *client_addr;

    MyAddrInfo *remote_addr;

    NooneUserInfo *user_info;  // 指向用户信息

    NooneCipherCtx *cipher_ctx;

    Buffer *client_buf;  // 存放从 client 读到的解密后数据

    Buffer *remote_buf;  // 存放从 remote 读到的加密后数据

} NetData;

#define UNREGISTER_CLIENT() \
    ae_unregister_event(event_loop, nd->client_fd)

#define UNREGISTER_REMOTE() \
    ae_unregister_event(event_loop, nd->remote_fd)

#define CLEAR_CLIENT() \
    do { \
        UNREGISTER_CLIENT(); \
        close(nd->client_fd); \
        nd->client_fd = -1; \
    } while (0)

#define CLEAR_REMOTE() \
    do { \
        UNREGISTER_REMOTE(); \
        close(nd->remote_fd); \
        nd->remote_fd = -1; \
    } while (0)

#define CLEAR_CLIENT_AND_REMOTE() \
    do { \
        if (nd->client_fd != -1) { \
            CLEAR_CLIENT(); \
        } \
        if (nd->remote_fd != -1) { \
            CLEAR_REMOTE();\
        } \
        free_net_data(nd); \
        return; \
    } while (0)

#define ENCRYPT(pbuf, pbuf_len, cbuf) \
    do { \
        size_t ret = encrypt(nd->cipher_ctx->encrypt_ctx, \
                (uint8_t *)(pbuf), (pbuf_len), (uint8_t *)(cbuf)); \
        if (ret == 0) { \
            SYS_ERROR("ENCRYPT"); \
            CLEAR_CLIENT_AND_REMOTE(); \
        } \
        nd->remote_buf->len = ret; \
    } while (0)

#define DECRYPT(cbuf, cbuf_len, pbuf) \
    do { \
        size_t ret = decrypt(nd->cipher_ctx->decrypt_ctx, \
                (uint8_t *)(cbuf), (cbuf_len), (uint8_t *)(pbuf)); \
        if (ret == 0) { \
            SYS_ERROR("DECRYPT"); \
            CLEAR_CLIENT_AND_REMOTE(); \
        } \
        nd->client_buf->len = ret; \
    } while (0)

NetData *init_net_data();

void free_net_data(NetData *nd);

void handle_timeout(AeEventLoop *event_loop, int fd, void *data);

int create_remote_socket(NetData *nd);

int handle_stage_init(NetData *nd);

int handle_stage_header(NetData *nd, int socktype);

int handle_stage_handshake(NetData *nd);

#endif  /* _NOONE_TRANSPORT_H_ */
