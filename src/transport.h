/*
 * Created by zzzzer on 3/18/19.
 */

#ifndef _NOONE_TRANSPORT_H_
#define _NOONE_TRANSPORT_H_

#include "cryptor.h"

#define BUFFER_LEN 32 * 1024

// ATYP
#define ATYP_IPV4 0x01
#define ATYP_DOMAIN 0x03
#define ATYP_IPV6 0x04

typedef enum SsStageType {
    STAGE_INIT = 0,   /* 获取 iv 阶段 */
    STAGE_ADDR,       /* 解析地址阶段 */
    STAGE_UDP_ASSOC,
    STAGE_DNS,        /* 查询 DNS */
    STAGE_CONNECTING,
    STAGE_STREAM,
    STAGE_DESTROYED = -1
} SsStageType;

typedef struct NetData {

    int ssclient_fd;

    int remote_fd;

    SsStageType ss_stage;

    struct addrinfo *addr_list_p;

    uint16_t port;

    unsigned char iv[MAX_IV_LEN+1];

    EVP_CIPHER_CTX *encrypt_ctx;

    EVP_CIPHER_CTX *decrypt_ctx;

    unsigned char ciphertext[BUFFER_LEN];

    unsigned char *ciphertext_p;

    size_t ciphertext_len;

    unsigned char plaintext[BUFFER_LEN];

    unsigned char *plaintext_p;

    size_t plaintext_len;

    unsigned char remote_buf[BUFFER_LEN];

    unsigned char *remote_buf_p;

    size_t remote_buf_len;

} NetData;

NetData *init_net_data();

#define ENCRYPT_ALIAS(nd) \
    encrypt((nd)->encrypt_ctx, (nd)->plaintext_p, (nd)->plaintext_len, (nd)->ciphertext)

#define DECRYPT(nd) \
    decrypt((nd)->decrypt_ctx, (nd)->ciphertext_p, (nd)->ciphertext_len, (nd)->plaintext)

#endif /* _NOONE_TRANSPORT_H_ */
