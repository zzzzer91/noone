#ifndef __SOCKET_H__
#define __SOCKET_H__

/* Maximum queue length specifiable by listen.  */
#define SOMAXCONN	128

int server_fd_init(const char *addr, unsigned short port);

int setnonblock(int sockfd);

#endif  /* __SOCKET_H__ */



