/*
 * Created by zzzzer on 3/18/19.
 */

#ifndef _NOONE_TRANSPORT_H_
#define _NOONE_TRANSPORT_H_

#include "cryptor.h"
#include "ae.h"
#include <netinet/in.h>  /* struct sockaddr_in */

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

    struct sockaddr sockaddr;

    socklen_t sockaddr_len;

    char *ip;

    uint16_t port;

    unsigned char iv[MAX_IV_LEN+1];

    size_t iv_len;

    EVP_CIPHER_CTX *encrypt_ctx;

    EVP_CIPHER_CTX *decrypt_ctx;

    unsigned char ciphertext[BUFFER_LEN];

    unsigned char *ciphertext_p;

    size_t ciphertext_len;

    unsigned char plaintext[BUFFER_LEN];

    unsigned char *plaintext_p;

    size_t plaintext_len;

    int is_iv_send;

    unsigned char remote_buf[BUFFER_LEN];

    unsigned char *remote_buf_p;

    size_t remote_buf_len;

    unsigned char remote_buf_cipher[BUFFER_LEN];

    unsigned char *remote_buf_cipher_p;

    size_t remote_buf_cipher_len;

} NetData;

NetData *init_net_data();

#define ENCRYPT(nd) \
    encrypt((nd)->encrypt_ctx, (nd)->remote_buf_p, (nd)->remote_buf_len, (nd)->remote_buf_cipher)

#define DECRYPT(nd) \
    decrypt((nd)->decrypt_ctx, (nd)->ciphertext_p, (nd)->ciphertext_len, (nd)->plaintext)
/*
 * 1、当对端套接字已关闭，read() 会返回 0。
 * 2、当（read() == -1 && errno == EAGAIN）时，
 *    代表 EPOLLET 模式的 socket 数据读完。
 * 3、ET 模式下，触发 epoll_wait()，然后执行 READN()，当执行到
 *    read() 时，可能就会碰到 read() 返回 0，此时不能直接 return，
 *    因为前面可能读了数据。
 *    WRITEN() 同理。
 */
#define READN(fd, buf, n, close_flag) \
    ({ \
        size_t nleft = n; \
        ssize_t nread; \
        unsigned char *bufp = buf; \
        while (nleft > 0) { \
            nread = read(fd, bufp, nleft); \
            if (nread == 0) {  \
                LOGGER_DEBUG("fd: %d, READN, connect close!", fd); \
                close_flag = 1; \
                break; \
            } else if (nread < 0) { \
                if (errno == EAGAIN) { \
                    break; \
                } else if (errno == EINTR) { \
                    nread = 0; \
                } else { \
                    LOGGER_ERROR("READN"); \
                    close_flag = 1; \
                    return; \
                } \
            } \
            nleft -= nread; \
            bufp += nread; \
        } \
        LOGGER_DEBUG("fd: %d, read: %ld", fd, n - nleft); \
        n - nleft; \
    })

#define WRITEN(fd, buf, n, close_flag) \
    ({ \
        size_t nleft = n; \
        ssize_t nwritten; \
        unsigned char *bufp = buf; \
        while (nleft > 0) { \
            nwritten = write(fd, bufp, nleft); \
            if (nwritten == 0) { \
                LOGGER_DEBUG("fd: %d, WRITEN, connect close!", fd); \
                close_flag = 1; \
                break; \
            } else if (nwritten < 0) { \
                if (errno == EINTR) { \
                    break; \
                } else { \
                    LOGGER_ERROR("WRITEN"); \
                    close_flag = 1; \
                    return; \
                } \
            } \
            nleft -= nwritten; \
            bufp += nwritten; \
        } \
        LOGGER_DEBUG("fd: %d, write: %ld", fd, n - nleft); \
        n - nleft; \
    })

#endif /* _NOONE_TRANSPORT_H_ */
