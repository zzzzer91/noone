#ifndef __EPOLL_H__
#define __EPOLL_H__

#include <sys/epoll.h>

#define BUFFER_LEN 32 * 1024
#define EP_MAX_EVENTS 4096
#define OPEN_FD_MAX EP_MAX_EVENTS

typedef struct ep_event_extend ep_event_ex;

struct ep_event_extend {
    int fd;
    int events;
    void (*callback)(ep_event_ex *self);
    char buffer[BUFFER_LEN];
    int len;
    long last_active;
};

extern int g_ep_fd;
extern struct epoll_event *g_ready_events;
extern ep_event_ex **g_fd_to_event;

int ep_init();

void ep_close();

int ep_register(int fd, int events, void (*callback)(ep_event_ex *self));

int ep_modify(int fd, int events, void (*callback)(ep_event_ex *self));

int ep_unregister(int fd);

int ep_wait(int timeout);

void ep_close();

#endif  /* __EPOLL_H__ */
