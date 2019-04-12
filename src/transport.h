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

#define CLIENT_BUF_CAPACITY 16 * 1024
#define REMOTE_BUF_CAPACITY 32 * 1024
#define MAX_DOMAIN_LEN 63
#define MAX_PORT_LEN 5

// ATYP
#define ATYP_IPV4 0x01
#define ATYP_DOMAIN 0x03
#define ATYP_IPV6 0x04

#define STREAM_UP   0
#define STREAM_DOWN 1

// for each stream, it's waiting for reading, or writing, or both
#define WAIT_STATUS_INIT 0
#define WAIT_STATUS_READING  1
#define WAIT_STATUS_WRITING  2
#define WAIT_STATUS_READWRITING WAIT_STATUS_READING | WAIT_STATUS_WRITING

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

    int upstream_status;

    int downstream_status;

    SsStageType ss_stage;

    MyAddrInfo *remote_addr;

    NooneUserInfo *user_info;  // 指向用户信息

    NooneCipherCtx *cipher_ctx;

    Buffer *remote_buf;  // 要发给 remote 的数据

    Buffer *client_buf;  // 要发给 client 的数据

} NetData;

NetData *init_net_data();

void free_net_data(NetData *nd);

MyAddrInfo *parse_net_data_header(Buffer *buf, LruCache *lc);

#endif  /* _NOONE_TRANSPORT_H_ */
