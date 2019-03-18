/*
 * Created by zzzzer on 3/14/19.
 */

#include "rio.h"
#include "error.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>

/*
 * 当对端套接字已关闭，read() 会返回 0。
 * （read() == -1 && errno == EAGAIN）时，
 *  代表 EPOLLET 模式的 socket 数据读完。
 */
ssize_t
rio_readn(int fd, void *usrbuf, size_t n)
{
    size_t nleft = n; /* 剩余字节数 */
    ssize_t nread;
    unsigned char *bufp = usrbuf;

    while (nleft > 0) {
        nread = read(fd, bufp, nleft);
        if (nread == 0) {  /* 对端关闭 */
            break;
        } else if (nread < 0) {
            if (errno == EAGAIN) { /* 代表非阻塞模式下，缓冲区无数据 */
                break;
            } else if (errno == EINTR) { /* 如果 read() 被信号打断, 则重启 */
                nread = 0;
            } else { /* 否则是其他错误，则退出 */
                return -1;
            }
        }
        nleft -= nread;
        bufp += nread;
    }

    return n - nleft; /* 返回读取到的字节数 */
}

/*
 * 无缓冲输出函数, 向fd写.
 */
ssize_t
rio_writen(int fd, void *usrbuf, size_t n)
{
    size_t nleft = n;
    ssize_t nwritten;
    unsigned char *bufp = usrbuf; /* 偏移 */

    while (nleft > 0) {
        nwritten = write(fd, bufp, nleft);
        if (nwritten <= 0) { /* 注意这里是小于等于 0 */
            if (errno == EINTR) {
                nwritten = 0;
            } else {
                return -1;
            }
        }
        nleft -= nwritten;
        bufp += nwritten;
    }

    return n;
}