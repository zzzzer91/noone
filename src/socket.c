/*
 * Created by zzzzer on 2/11/19.
 */

#include "socket.h"
#include "error.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>       /* fcntl() */
#include <sys/socket.h>  /* socket(), setsockopt() */
#include <netinet/in.h>  /* struct sockaddr_in */
#include <arpa/inet.h>   /* inet_addr() */
#include <netinet/tcp.h>

/*
 * 只支持 ipv4
 */
int
tcp_ipv4_server_fd_init(uint16_t port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        SYS_ERROR("socket");
        return -1;
    }
    if (set_reuseaddr(server_fd) < 0) {
        SYS_ERROR("set_reuseaddr");
        return -1;
    }
    if (set_nonblock(server_fd) < 0) {
        SYS_ERROR("set_nonblock");
        return -1;
    }
//    if (set_fastopen(server_fd) < 0) {
//        SYS_ERROR("set_fastopen");
//        return -1;
//    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        SYS_ERROR("bind");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, MAX_LISTEN) < 0) {
        SYS_ERROR("listen");
        close(server_fd);
        return -1;
    }

    return server_fd;
}

/*
 * 只支持 ipv4
 */
int
udp_ipv4_server_fd_init(uint16_t port)
{
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        SYS_ERROR("socket");
        return -1;
    }
    if (set_nonblock(server_fd) < 0) {
        SYS_ERROR("set_nonblock");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        SYS_ERROR("bind");
        close(server_fd);
        return -1;
    }

    // 注意 udp 不需要 listen()，也不需要设置端口复用

    return server_fd;
}

/*
 * 设置非阻塞 socket
 */
int
set_nonblock(int sockfd)
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

/*
 * 设置端口复用，本方主动关闭后，不进行 TIME_WAIT，
 * TIME_WAIT 原因是等待对方的 ACK，防止对方未收到 FIN 包
 */
int set_reuseaddr(int sockfd)
{
    int on = 1;
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
}

/*
 * 关闭 TCP NAGLE 算法。
 * 该算法是为了提高较慢的广域网传输效率，减小小分组的报文个数
 */
int
set_nondelay(int sockfd)
{
    int on = 1;
    return setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

/*
 * 开启 TCP fast open
 */
int
set_fastopen(int sockfd)
{
    int on = 1;
    return setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, &on, sizeof(on));
}