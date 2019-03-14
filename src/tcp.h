/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_TCP_H_
#define _NOONE_TCP_H_

#include "ae.h"
#include "cryptor.h"

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
    int is_get_iv;  /* 1 代表是，0 代表否 */
    unsigned char iv[MAX_IV_LEN+1];
    EVP_CIPHER_CTX *encrypt_ctx;
    size_t ciphertext_len;
    unsigned char ciphertext[BUFFER_LEN];
    EVP_CIPHER_CTX *decrypt_ctx;
    size_t plaintext_len;
    unsigned char plaintext[BUFFER_LEN];
} StreamData;

StreamData *init_stream_data();

void accept_conn(AeEventLoop *event_loop, int fd, void *data);

void read_ssclient(AeEventLoop *event_loop, int fd, void *data);

void write_ssclient(AeEventLoop *event_loop, int fd, void *data);

void read_remote(AeEventLoop *event_loop, int fd, void *data);

void write_remote(AeEventLoop *event_loop, int fd, void *data);

#endif  /* _NOONE_TCP_H_ */
