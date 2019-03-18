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
    SsStageType ss_stage;
    char ip[16];
    uint16_t port;
    unsigned char iv[MAX_IV_LEN+1];
    EVP_CIPHER_CTX *encrypt_ctx;
    size_t ciphertext_len;
    unsigned char ciphertext[BUFFER_LEN];
    unsigned char *ciphertext_p;
    EVP_CIPHER_CTX *decrypt_ctx;
    size_t plaintext_len;
    unsigned char plaintext[BUFFER_LEN];
    unsigned char *plaintext_p;
} NetData;

NetData *init_net_data();

#define ENCRYPT(sd) \
    encrypt((sd)->encrypt_ctx, (sd)->plaintext_p, (sd)->plaintext_len, (sd)->ciphertext)

#define DECRYPT(sd) \
    decrypt((sd)->decrypt_ctx, (sd)->ciphertext_p, (sd)->ciphertext_len, (sd)->plaintext)

#endif /* _NOONE_TRANSPORT_H_ */
