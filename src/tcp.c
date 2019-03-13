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
            /* 暂不做出错处理 */
        }
    }

    setnonblock(conn_fd);
}

void
read_ssclient(AeEventLoop *event_loop, int fd, void *client_data)
{
//    int ret = (int)read(
//        self->fd,
//        self->ciphertext,
//        sizeof(self->ciphertext)
//    );
//    if (ret == 0) {  /* 对端关闭 */
//
//    }
//    if (ret < 0) {
//        /* 错误处理 */
//        PANIC("read");
//    }
//
//    self->ciphertext_len = ret;
//    printf("%d\n", self->ciphertext_len);
//    // crypto_aes256cfb_decrypt();
//    // printf("%s\n", self->plaintext);
//    printf("%d\n", self->plaintext_len);
//    exit(1);
    // ep_modify(self->fd, EPOLLOUT, write_ssclient);
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
