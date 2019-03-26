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

#define BUF_CAPACITY 32 * 1024

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

int init_net_data_cipher(CryptorInfo *ci, NetData *nd);

int parse_net_data_header(NetData *nd);

void free_net_data(NetData *nd);

#define ENCRYPT(nd) \
    encrypt((nd)->cipher_ctx.encrypt_ctx, (nd)->remote.p, \
            (nd)->remote.len, (nd)->remote_cipher.p+(nd)->remote_cipher.len)

#define DECRYPT(nd) \
    decrypt((nd)->cipher_ctx.decrypt_ctx, (nd)->ciphertext.p, \
            (nd)->ciphertext.len, (nd)->plaintext.p+(nd)->plaintext.len)
/*
 * 1、当对端套接字已关闭，read() 会返回 0。
 * 2、当（read() == -1 && errno == EAGAIN）时，
 *    代表 EPOLLET 模式的 socket 数据读完。
 * 3、ET 模式下，触发 epoll_wait()，然后执行 READN()，当执行到
 *    read() 时，可能就会碰到 read() 返回 0，此时不能直接 return，
 *    因为前面可能读了数据。
 *    WRITEN() 同理。
 */
#define READN(fd, buf) \
    ({ \
        int close_flag = 0; \
        size_t nleft = buf.capacity - (buf.p - buf.data + buf.len); \
        ssize_t nread; \
        unsigned char *p = buf.p + buf.len; \
        while (nleft > 0) { \
            nread = read(fd, p, nleft); \
            if (nread == 0) {  \
                close_flag = 1; \
                break; \
            } else if (nread < 0) { \
                if (errno == EAGAIN) { \
                    break; \
                } else if (errno == EINTR) { \
                    nread = 0; \
                } else { \
                    close_flag = 1; \
                    break; \
                } \
            } \
            nleft -= nread; \
            p += nread; \
            buf.len += nread; \
        } \
        close_flag; \
    })

#define WRITEN(fd, buf) \
    ({ \
        int close_flag = 0; \
        size_t nleft = buf.len; \
        ssize_t nwritten; \
        unsigned char *p = buf.p; \
        while (nleft > 0) { \
            nwritten = write(fd, p, nleft); \
            if (nwritten == 0) { \
                close_flag = 1; \
                break; \
            } else if (nwritten < 0) { \
                if (errno == EAGAIN) { \
                    break; \
                } else if (errno == EINTR) { \
                    nwritten = 0; \
                } else { \
                    close_flag = 1; \
                    break; \
                } \
            } \
            nleft -= nwritten; \
            p += nwritten; \
        } \
        buf.len = nleft; \
        buf.p = p; \
        close_flag; \
    })

#endif /* _NOONE_TRANSPORT_H_ */
