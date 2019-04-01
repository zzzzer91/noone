/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_SOCKET_H_
#define _NOONE_SOCKET_H_

#define MAX_LISTEN	2048

int tcp_server_fd_init(const char *addr, unsigned short port);

int udp_server_fd_init(const char *addr, unsigned short port);

int setnonblock(int sockfd);

#endif  /* _NOONE_SOCKET_H_ */



