#include "tcp.h" 
#include <errno.h>
#include <unistd.h>      /* close() */
#include <sys/socket.h>  /* accept() */
#include <netinet/in.h>  /* struct sockaddr_in */
#include "socket.h"
#include "epoll.h"
#include "error.h"

void
accept_conn(ep_event_ex *self)
{
    struct sockaddr_in conn_addr;
    socklen_t conn_addr_len = sizeof(conn_addr);
    int conn_fd = accept(self->fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
    if (conn_fd < 0) {
        if (errno != EAGAIN && errno != EINTR) {
            /* 暂不做出错处理 */
        }
    }

    setnonblock(conn_fd);

    ep_register(conn_fd, EPOLLIN|EPOLLET, read_ssclient);
}

void
read_ssclient(ep_event_ex *self)
{
    int ret = read(self->fd, self->buffer, sizeof(self->buffer));
    if (ret == 0) {  /* 对端关闭 */

    }
    if (ret < 0) {
        panic("read");
        /* 错误处理 */
    }
    self->len = ret;
    ep_modify(self->fd, EPOLLOUT|EPOLLET, write_ssclient);
}

void
write_ssclient(ep_event_ex *self)
{
    int ret = write(self->fd, self->buffer, self->len);
    if (ret == 0) {  /* 对端关闭 */

    }
    if (ret < 0) {
        panic("write");
        close(self->fd);
        ep_unregister(self->fd);
    }
    self->len = 0;
    ep_modify(self->fd, EPOLLIN|EPOLLET, read_ssclient);
}

void
read_remote(ep_event_ex *self)
{

}

void
write_remote(ep_event_ex *self)
{

}
