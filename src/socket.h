/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_SOCKET_H_
#define _NOONE_SOCKET_H_

#include <netinet/in.h>  /* struct sockaddr_in */

typedef struct MyAddrInfo {
    socklen_t ai_addrlen;
    int ai_family;
    int ai_socktype;
    union {
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } ai_addr;
} MyAddrInfo;

int tcp_ipv4_server_fd_init(uint16_t port);

int udp_ipv4_server_fd_init(uint16_t port);

int set_nonblock(int sockfd);

int set_reuseaddr(int sockfd);

int set_nondelay(int sockfd);

int set_fastopen(int sockfd);

#endif  /* _NOONE_SOCKET_H_ */



