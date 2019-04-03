/*
 * Created by zzzzer on 2/11/19.
 */

#include "socket.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>       /* fcntl() */
#include <sys/socket.h>  /* socket(), setsockopt() */
#include <netinet/in.h>  /* struct sockaddr_in */
#include <arpa/inet.h>   /* inet_addr() */
#include <netdb.h>       /* getaddrinfo(), gai_strerror() */

int
tcp_server_fd_init(const char *port)
{
    struct addrinfo hints, *listp;
    int ret;
    /* 获取主机名可能对应的IP地址的列表 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM; /* TCP */
    hints.ai_flags = AI_NUMERICSERV; /* 强制只能填端口号, 而不能是端口号对应的服务名 */
    hints.ai_flags |= AI_PASSIVE;
    if ((ret = getaddrinfo(NULL, port, &hints, &listp)) != 0) {
        fprintf(stderr, "open_clientfd-getaddrinfo error: %s\n", gai_strerror(ret));
        return -1;
    }

    int server_fd = socket(listp->ai_family, listp->ai_socktype, listp->ai_protocol);
    if (server_fd < 0) {
        return -1;
    }

    /* 端口复用, 本方主动关闭后, 不进行TIME_WAIT,
     * TIME_WAIT原因是等待对方的ACK, 防止对方未收到FIN包 */
    int on = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        return -1;
    }

    if (bind(server_fd, listp->ai_addr, listp->ai_addrlen) < 0) {
        return -1;
    }

    freeaddrinfo(listp);

    if (listen(server_fd, MAX_LISTEN) < 0) {
        return -1;
    }

    return server_fd; 
}

int
udp_server_fd_init(const char *port)
{
    struct addrinfo hints, *listp;
    int ret;
    /* 获取主机名可能对应的IP地址的列表 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM; /* TCP */
    hints.ai_flags = AI_NUMERICSERV; /* 强制只能填端口号, 而不能是端口号对应的服务名 */
    hints.ai_flags |= AI_PASSIVE;
    if ((ret = getaddrinfo(NULL, port, &hints, &listp)) != 0) {
        fprintf(stderr, "open_clientfd-getaddrinfo error: %s\n", gai_strerror(ret));
        return -1;
    }

    int server_fd = socket(listp->ai_family, listp->ai_socktype, listp->ai_protocol);
    if (server_fd < 0) {
        return -1;
    }

    if (bind(server_fd, listp->ai_addr, listp->ai_addrlen) < 0) {
        return -1;
    }

    freeaddrinfo(listp);

    // 注意 udp 不需要 listen()，也不需要设置端口复用

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
