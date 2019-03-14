/*
 * Created by zzzzer on 2/11/19.
 */

#include "tcp.h"
#include "socket.h"
#include "rio.h"
#include "ae.h"
#include "error.h"
#include "cryptor.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>      /* close() */
#include <sys/socket.h>  /* accept() */
#include <netinet/in.h>  /* struct sockaddr_in */

StreamData *
init_stream_data()
{
    StreamData *stream_data = malloc(sizeof(StreamData));
    if (stream_data == NULL) return NULL;

    stream_data->ss_stage = STAGE_INIT;
    stream_data->is_get_iv = 0;

    return stream_data;
}

void
accept_conn(AeEventLoop *event_loop, int fd, void *data)
{
    struct sockaddr_in conn_addr;
    socklen_t conn_addr_len = sizeof(conn_addr);
    int conn_fd = accept(fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
    if (conn_fd < 0) {
        LOGGER_ERROR("accept_conn");
        return;
    }

    if (setnonblock(conn_fd) < 0) {
        LOGGER_ERROR("setnonblock");
        close(conn_fd);
        return;
    }

    StreamData *sd = init_stream_data();
    if (sd == NULL) PANIC("init_stream_data");
    ae_register_file_event(event_loop, conn_fd, AE_IN,
            read_ssclient, write_ssclient, sd);
}

void
read_ssclient(AeEventLoop *event_loop, int fd, void *data)
{
    CryptorInfo *ci = event_loop->extra_data;
    StreamData *sd = data;

    ssize_t ret;
    if (!sd->is_get_iv) {
        ret = rio_readn(fd, sd->iv, ci->iv_len);
        if (ret < 0) {
            LOGGER_ERROR("rio_readn");
            return;
        }
        sd->is_get_iv = 1;
    }

    ret = rio_readn(fd, sd->ciphertext, sizeof(sd->ciphertext));
//    if (errno == EAGAIN) {  /* 正常读完 */
//    }

    sd->ciphertext_len = (size_t)ret;
    printf("%ld\n", sd->ciphertext_len);

    sd->decrypt_ctx = INIT_DECRYPT_CTX(ci->cipher, ci->key, sd->iv);
    sd->plaintext_len = decrypt(sd->decrypt_ctx,
                                sd->ciphertext, sd->ciphertext_len, sd->plaintext);
    printf("%ld\n", sd->plaintext_len);
    /*
     * 开头有两个字段
     * - ATYP 字段：address type 的缩写，取值为：
     *     0x01：IPv4
     *     0x03：域名
     *     0x04：IPv6
     *
     * - DST.ADDR 字段：destination address 的缩写，取值随 ATYP 变化：
     *
     *     ATYP == 0x01：4 个字节的 IPv4 地址
     *     ATYP == 0x03：1 个字节表示域名长度，紧随其后的是对应的域名
     *     ATYP == 0x04：16 个字节的 IPv6 地址
     *     DST.PORT 字段：目的服务器的端口
     */
    printf("%s\n", sd->plaintext);

    free(sd->decrypt_ctx);

    // 对端关闭
    ae_unregister_file_event(event_loop, fd);
    close(fd);
    free(sd);
}

void
write_ssclient(AeEventLoop *event_loop, int fd, void *data)
{
    // int ret = write(self->fd, self->buffer, self->len);
    // if (ret == 0) {  /* 对端关闭 */

    // }
    // if (ret < 0) {
    //     PANIC("write");
    //     close(self->fd);
    //     ep_unregister(self->fd);
    // }
    // self->len = 0;
    // ep_modify(self->fd, EPOLLIN, read_ssclient);
}

void
read_remote(AeEventLoop *event_loop, int fd, void *data)
{

}

void
write_remote(AeEventLoop *event_loop, int fd, void *data)
{

}
