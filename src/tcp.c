/*
 * Created by zzzzer on 2/11/19.
 */

#include "tcp.h"
#include "socket.h"
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

void
accept_conn(AeEventLoop *event_loop, int fd, void *client_data)
{
    struct sockaddr_in conn_addr;
    socklen_t conn_addr_len = sizeof(conn_addr);
    int conn_fd = accept(
        fd,
        (struct sockaddr *)&conn_addr,
        &conn_addr_len
    );
    if (conn_fd < 0) {
        if (errno != EAGAIN && errno != EINTR) {
            LOGGER_ERROR("accept_conn");
            /* 暂不做出错处理 */
        }
    }

    if (setnonblock(conn_fd) < 0) {
        LOGGER_ERROR("setnonblock");
    }

    StreamData *stream_data = malloc(sizeof(StreamData));
    stream_data->ss_stage = STAGE_INIT;
    ae_register_file_event(event_loop, conn_fd, AE_IN, read_ssclient, stream_data);
}

void
read_ssclient(AeEventLoop *event_loop, int fd, void *client_data)
{
    CryptorInfo *cryptor_info = event_loop->extra_data;
    int iv_len = cryptor_info->iv_len;
    StreamData *sd = client_data;
    int ret = (int)read(
        fd,
        sd->iv,
        (size_t)iv_len
    );
    if (ret == 0) {  /* 对端关闭 */

    }
    if (ret < 0) {
        /* 错误处理 */
        PANIC("read");
    }


    ret = (int)read(
            fd,
            sd->ciphertext,
            sizeof(sd->ciphertext)
    );
    sd->ciphertext_len = ret;
    printf("%d\n", sd->ciphertext_len);
    sd->decrypt_ctx = INIT_AES128CTR_DECRYPT_CTX(cryptor_info->key, sd->iv);
    sd->plaintext_len = decrypt(sd->decrypt_ctx,
            sd->ciphertext, sd->ciphertext_len, sd->plaintext);
    printf("%s\n", sd->plaintext);
    printf("%d\n", sd->plaintext_len);
    exit(1);
}

void
write_ssclient(AeEventLoop *event_loop, int fd, void *client_data)
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
read_remote(AeEventLoop *event_loop, int fd, void *client_data)
{

}

void
write_remote(AeEventLoop *event_loop, int fd, void *client_data)
{

}
