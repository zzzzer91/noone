/*
 * Created by zzzzer on 3/18/19.
 */

#ifndef _NOONE_TRANSPORT_H_
#define _NOONE_TRANSPORT_H_

#include "cryptor.h"
#include "ae.h"
#include "buffer.h"
#include "lru.h"
#include "error.h"
#include "socket.h"
#include "manager.h"
#include <netdb.h>

#define MAX_DOMAIN_LEN 63
#define MAX_PORT_LEN 5

// ATYP
#define ATYP_IPV4 0x01
#define ATYP_DOMAIN 0x03
#define ATYP_IPV6 0x04

typedef enum TransportStage {
    STAGE_INIT = 0,   /* 获取 iv 阶段 */
    STAGE_HEADER,     /* 解析 header 阶段，获取 remote 的 ip 和 port */
    STAGE_DNS,        /* 查询 DNS，可能不进行这一步 */
    STAGE_HANDSHAKE,  /* TCP 和 remote 握手阶段 */
    STAGE_STREAM,     /* 传输阶段 */
    STAGE_DESTROYED,  /* 该连接所有资源已销毁，就剩释放 NetData 对象内存 */
} TransportStage;

typedef struct NetData {

    char remote_domain[MAX_DOMAIN_LEN+1];

    uint16_t remote_port;

    uint8_t iv[MAX_IV_LEN];

    int is_iv_send;

    int client_fd;

    int remote_fd;

    int dns_fd;

    int client_event_status;

    int remote_event_status;

    TransportStage stage;

    MyAddrInfo client_addr;  // 不是指针

    MyAddrInfo *remote_addr;  // 不主动释放，交给 lru 缓存释放

    NooneUserInfo *user_info;  // 指向用户信息

    NooneCipherCtx *cipher_ctx;

    Buffer *client_buf;  // 存放从 client 读到的解密后数据

    Buffer *remote_buf;  // 存放从 remote 读到的加密后数据

} NetData;

NetData *init_net_data();

void free_net_data(NetData *nd);

int create_remote_socket(NetData *nd);

int handle_stage_init(NetData *nd);

int handle_stage_header(NetData *nd, int socktype);

int handle_stage_dns(NetData *nd);

int handle_stage_handshake(NetData *nd);

void handle_transport_timeout(AeEventLoop *event_loop, int fd, void *data);

int add_dns_to_lru_cache(NetData *nd, MyAddrInfo *addr_info);

#define TRANSPORT_DEBUG(s, args...) \
    do { \
        if (nd->stage > STAGE_HEADER) { \
            LOGGER_DEBUG("fd: %d, %s:%d, %s: " s, \
                    nd->client_fd, nd->remote_domain, nd->remote_port, __func__, ##args); \
        } else { \
            LOGGER_DEBUG("fd: %d, %s: " s, nd->client_fd, __func__, ##args); \
        } \
    } while (0)

#define TRANSPORT_ERROR(s, args...) \
    do { \
        if (nd->stage > STAGE_HEADER) { \
            LOGGER_ERROR("fd: %d, %s:%d, %s -> " s, \
                    nd->client_fd, nd->remote_domain, nd->remote_port, __func__, ##args); \
        } else { \
            LOGGER_ERROR("fd: %d, %s -> " s, nd->client_fd, __func__, ##args); \
        } \
    } while (0)

#define UNREGISTER_CLIENT() \
    ae_unregister_event(event_loop, nd->client_fd)

#define UNREGISTER_REMOTE() \
    ae_unregister_event(event_loop, nd->remote_fd)

#define UNREGISTER_DNS() \
    ae_unregister_event(event_loop, nd->dns_fd)

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

#define CLEAR_DNS() \
    do { \
        UNREGISTER_DNS(); \
        close(nd->dns_fd); \
        nd->dns_fd = -1; \
    } while (0)

#define CLEAR_ALL() \
    do { \
        if (nd->client_fd != -1) { \
            CLEAR_CLIENT(); \
        } \
        if (nd->remote_fd != -1) { \
            CLEAR_REMOTE();\
        } \
        if (nd->dns_fd != -1) { \
            CLEAR_DNS(); \
        } \
        nd->stage = STAGE_DESTROYED; \
        free_net_data(nd); \
        return; \
    } while (0)

#define REGISTER_CLIENT_EVENT(rcallback, wcallback) \
    do { \
        if (nd->client_fd != -1) { \
            if (ae_register_event(event_loop, nd->client_fd, nd->client_event_status, \
                        rcallback, wcallback, handle_transport_timeout, nd) < 0) { \
                TRANSPORT_ERROR("REGISTER_CLIENT_EVENT"); \
                CLEAR_ALL(); \
            } \
        } \
    } while (0)

#define REGISTER_REMOTE_EVENT(rcallback, wcallback) \
    do { \
        if (nd->remote_fd != -1) { \
            if (ae_register_event(event_loop, nd->remote_fd, nd->remote_event_status, \
                    rcallback, wcallback, handle_transport_timeout, nd) < 0) { \
                TRANSPORT_ERROR("REGISTER_REMOTE_EVENT"); \
                CLEAR_ALL(); \
            } \
        } \
    } while (0)

#define REGISTER_DNS_EVENT(callback) \
    do { \
        if (ae_register_event(event_loop, nd->dns_fd, AE_IN, \
                callback, NULL, handle_transport_timeout, nd) < 0) { \
            TRANSPORT_ERROR("handle_stage_dns"); \
            CLEAR_ALL(); \
        } \
    } while (0)

#define ENCRYPT(pbuf, pbuf_len, cbuf) \
    do { \
        size_t ret = encrypt(nd->cipher_ctx->encrypt_ctx, \
                (uint8_t *)(pbuf), (pbuf_len), (uint8_t *)(cbuf)); \
        if (ret == 0) { \
            TRANSPORT_ERROR("ENCRYPT"); \
            CLEAR_ALL(); \
        } \
        nd->remote_buf->len = ret; \
    } while (0)

#define DECRYPT(cbuf, cbuf_len, pbuf) \
    do { \
        size_t ret = decrypt(nd->cipher_ctx->decrypt_ctx, \
                (uint8_t *)(cbuf), (cbuf_len), (uint8_t *)(pbuf)); \
        if (ret == 0) { \
            TRANSPORT_ERROR("DECRYPT"); \
            CLEAR_ALL(); \
        } \
        nd->client_buf->len = ret; \
    } while (0)

#endif  /* _NOONE_TRANSPORT_H_ */
