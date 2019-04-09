/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_SOCKET_H_
#define _NOONE_SOCKET_H_

#include <netinet/in.h>  /* struct sockaddr_in */

#define MAX_LISTEN	2048

typedef struct MyAddrInfo {
    uint8_t ai_family;
    socklen_t ai_addrlen;
    union {
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    };
} MyAddrInfo;

int tcp_server_fd_init(const char *addr, uint16_t port);

int udp_server_fd_init(const char *addr, uint16_t port);

int setnonblock(int sockfd);

#endif  /* _NOONE_SOCKET_H_ */



