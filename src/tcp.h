/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_TCP_H_
#define _NOONE_TCP_H_

#include "ae.h"
#include <openssl/evp.h>

#define BUFFER_LEN 16 * 1024

typedef enum SsStageType {
    STAGE_INIT = 0,
    STAGE_ADDR,
    STAGE_UDP_ASSOC,
    STAGE_DNS,
    STAGE_CONNECTING,
    STAGE_STREAM,
    STAGE_DESTROYED = -1
} SsStageType;

typedef struct StreamData {
    SsStageType ss_stage;
    EVP_CIPHER_CTX *encrypt_ctx;
    int ciphertext_len;
    unsigned char ciphertext[BUFFER_LEN];
    EVP_CIPHER_CTX *decrypt_ctx;
    int plaintext_len;
    unsigned char plaintext[BUFFER_LEN];
    unsigned char iv[33];
} StreamData;

void accept_conn(AeEventLoop *event_loop, int fd, void *client_data);

void read_ssclient(AeEventLoop *event_loop, int fd, void *client_data);

void write_ssclient(AeEventLoop *event_loop, int fd, void *client_data);

void read_remote(AeEventLoop *event_loop, int fd, void *client_data);

void write_remote(AeEventLoop *event_loop, int fd, void *client_data);

#endif  /* _NOONE_TCP_H_ */
