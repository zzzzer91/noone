#include "epoll.h"
#include <stdlib.h>
#include <unistd.h>      /* close() */
#include <time.h>        /* time() */
#include <sys/epoll.h>

int g_ep_fd;
struct epoll_event *g_ready_events;
ep_event_ex **g_fd_to_event;

int
ep_init()
{
    g_ep_fd = epoll_create(EP_MAX_EVENTS+1);
    if (g_ep_fd < 0) {
        return -1;
    }

    g_ready_events = (struct epoll_event *)malloc(
        sizeof(struct epoll_event) * (EP_MAX_EVENTS+1)
    );
    if (g_ready_events == NULL) {
        return -1;
    }

    g_fd_to_event = (ep_event_ex **)malloc(
        sizeof(ep_event_ex *) * OPEN_FD_MAX
    );
    if (g_fd_to_event == NULL) {
        return -1;
    }

    return 0;
}

void
ep_close()
{
    close(g_ep_fd);
    g_ep_fd = -1;

    free(g_ready_events);
    g_ready_events = NULL;
    
    for (size_t i = 0; i < OPEN_FD_MAX; i++) {
        if (g_fd_to_event != NULL) {
            // close(i);
            ep_unregister(i);
        }
    }
    free(g_fd_to_event);
    g_fd_to_event = NULL;
}

int
ep_register(int fd, int events, void (*callback)(ep_event_ex *self))
{
    struct epoll_event epoll_ev;
    epoll_ev.events = events;
    epoll_ev.data.fd = fd;
    ep_event_ex *ep_ev_ptr = (ep_event_ex *)malloc(sizeof(ep_event_ex));
    ep_ev_ptr->fd = fd;
    ep_ev_ptr->events = events;
    ep_ev_ptr->callback = callback;
    ep_ev_ptr->len = 0;
    ep_ev_ptr->last_active = time(NULL);
    g_fd_to_event[fd] = ep_ev_ptr;  /* 放进数组 */

    return epoll_ctl(g_ep_fd, EPOLL_CTL_ADD, fd, &epoll_ev);
}

int
ep_modify(int fd, int events, void (*callback)(ep_event_ex *self))
{
    struct epoll_event epoll_ev;
    epoll_ev.events = events;
    epoll_ev.data.fd = fd;
    g_fd_to_event[fd]->events = events;
    g_fd_to_event[fd]->callback = callback;

    return epoll_ctl(g_ep_fd, EPOLL_CTL_MOD, fd, &epoll_ev);
}

int
ep_unregister(int fd)
{
    free(g_fd_to_event[fd]);
    g_fd_to_event[fd] = NULL;
    return epoll_ctl(g_ep_fd, EPOLL_CTL_DEL, fd, NULL);
}

int
ep_wait(int timeout)
{
    return epoll_wait(g_ep_fd, g_ready_events, EP_MAX_EVENTS+1, timeout);
}
