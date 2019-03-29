/*
 * Created by zzzzer on 3/18/19.
 */

#ifndef _NOONE_TRANSPORT_H_
#define _NOONE_TRANSPORT_H_

#include "cryptor.h"
#include "ae.h"
#include "buffer.h"
#include "log.h"
#include <netdb.h>

#define BUF_CAPACITY 16 * 1024

// ATYP
#define ATYP_IPV4 0x01
#define ATYP_DOMAIN 0x03
#define ATYP_IPV6 0x04

typedef enum SsStageType {
    STAGE_INIT = 0,   /* 获取 iv 阶段 */
    STAGE_ADDR,       /* 解析地址阶段 */
    STAGE_DNS,        /* 查询 DNS */
    STAGE_HANDSHAKE,  /* TCP 握手阶段 */
    STAGE_STREAM,     /* TCP 传输阶段 */
    STAGE_UDP,
    STAGE_DESTROYED = -1
} SsStageType;

typedef struct NetData {

    int ssclient_fd;

    int remote_fd;

    struct addrinfo *addr_listp;

    char domain[64];

    char remote_port_str[6];

    SsStageType ss_stage;

    CipherCtx cipher_ctx;

    int is_iv_send;

    Buffer ciphertext;

    Buffer plaintext;

    Buffer remote;

    Buffer remote_cipher;

} NetData;

NetData *init_net_data();

void free_net_data(NetData *nd);

int read_net_data(int fd, Buffer *buf);

int write_net_data(int fd, Buffer *buf);

int init_net_data_cipher(int fd, CryptorInfo *ci, NetData *nd);

int parse_net_data_header(NetData *nd);

#define ENCRYPT(nd) \
    encrypt((nd)->cipher_ctx.encrypt_ctx, (nd)->remote.data, (nd)->remote.len, \
            (nd)->remote_cipher.data+(nd)->remote_cipher.idx+(nd)->remote_cipher.len)

#define DECRYPT(nd) \
    decrypt((nd)->cipher_ctx.decrypt_ctx, (nd)->ciphertext.data, (nd)->ciphertext.len, \
            (nd)->plaintext.data+(nd)->plaintext.idx+(nd)->plaintext.len)

#endif  /* _NOONE_TRANSPORT_H_ */
