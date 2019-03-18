/*
 * Created by zzzzer on 2/11/19.
 */

#include "socket.h"
#include <fcntl.h>       /* fcntl() */
#include <sys/socket.h>  /* socket(), setsockopt() */
#include <netinet/in.h>  /* struct sockaddr_in */
#include <arpa/inet.h>   /* inet_addr() */

int
tcp_server_fd_init(const char *addr, unsigned short port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        return -1;
    }

    /* 端口复用, 本方主动关闭后, 不进行TIME_WAIT,
     * TIME_WAIT原因是等待对方的ACK, 防止对方未收到FIN包 */
    int on = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(addr);
    server_addr.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        return -1;
    }

    if (listen(server_fd, SOMAXCONN) < 0) {
        return -1;
    }

    return server_fd; 
}

int
udp_server_fd_init(const char *addr, unsigned short port)
{
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        return -1;
    }

    /* 端口复用, 本方主动关闭后, 不进行TIME_WAIT,
     * TIME_WAIT原因是等待对方的ACK, 防止对方未收到FIN包 */
    int on = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(addr);
    server_addr.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        return -1;
    }

    // 注意 udp 不需要 listen()

    return server_fd;
}

int
setnonblock(int sockfd)
{
    int flags;
    if ((flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    
    return 0;
}
