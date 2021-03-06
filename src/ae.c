/*
 * Created by zzzzer on 2/11/19.
 */

#include "ae.h"
#include "dlist.h"
#include <stdlib.h>
#include <unistd.h>

/*
 * 关联给定事件到 fd
 *
 * 如果 fd 没有关联任何事件，那么这是一个 ADD 操作。
 *
 * 如果已经关联了某个/某些事件，那么这是一个 MOD 操作。
 */
static inline int ae_epoll_add_event(AeEventLoop *event_loop, int fd, uint32_t mask, int op) {
    struct epoll_event ee;
    ee.events = mask;
    ee.data.ptr = NULL;
    ee.data.fd = fd;
    return epoll_ctl(event_loop->epfd, op, fd, &ee);
}

/*
 * 删除事件
 */
static inline int ae_epoll_del_event(AeEventLoop *event_loop, int fd) {
    return epoll_ctl(event_loop->epfd, EPOLL_CTL_DEL, fd, NULL);
}

/*
 * 获取可执行事件，timeout 单位毫秒
 */
static inline int ae_epoll_poll(AeEventLoop *event_loop, int timeout) {
    return epoll_wait(event_loop->epfd, event_loop->ready_events, event_loop->event_set_size,
                      timeout);
}

/*
 * 从双向链表尾部向前循环，按时间排序，尾部是最旧的事件
 */
static inline void ae_check_timeout(AeEventLoop *event_loop) {
    time_t current_time = time(NULL);

    AeEvent *p = event_loop->list_tail;
    while (p) {
        if ((current_time - p->last_active) < AE_WAIT_SECONDS) {
            break;
        }
        if (p->tcallback != NULL) {
            int fd = p->fd;
            p->tcallback(event_loop, fd, p->data);
        }
        p = p->list_prev;
    }
}

/*
 * 处理所有已到达事件。
 *
 * 函数的返回值为已处理事件的数量
 */
static int ae_process_events(AeEventLoop *event_loop, int timeout) {
    int processed = 0;
    int numevents = ae_epoll_poll(event_loop, timeout * 1000);
    // LOGGER_DEBUG("numevents: %d", numevents);
    for (int i = 0; i < numevents; i++) {
        uint32_t mask = event_loop->ready_events[i].events;
        int fd = event_loop->ready_events[i].data.fd;
        AeEvent *fe = &event_loop->events[fd];
        // LOGGER_DEBUG("fd: %d, fe_mask, %d, mask: %d", fd, fe->mask, mask);
        if (fe->mask & mask & AE_IN) {
            fe->rcallback(event_loop, fd, fe->data);
        }
        if (fe->mask & mask & AE_OUT) {
            fe->wcallback(event_loop, fd, fe->data);
        }
        processed++;
    }

    return processed;
}

/*
 * 创建事件处理器
 */
AeEventLoop *ae_create_event_loop(int event_set_size) {
    AeEventLoop *event_loop = malloc(sizeof(AeEventLoop));
    if (event_loop == NULL) {
        return NULL;
    }

    // 创建 epoll 实例
    event_loop->epfd = epoll_create(event_set_size);
    if (event_loop->epfd == -1) {
        free(event_loop);
        return NULL;
    }

    // 初始化文件事件结构
    // Events with mask == AE_NONE are not set.
    event_loop->events = calloc((size_t)event_set_size, sizeof(AeEvent));
    if (event_loop->events == NULL) {
        close(event_loop->epfd);
        free(event_loop);
        return NULL;
    }

    // 初始化事件槽空间，放置 epoll_wait() 已就绪事件
    event_loop->ready_events = malloc(event_set_size * sizeof(struct epoll_event));
    if (event_loop->ready_events == NULL) {
        close(event_loop->epfd);
        free(event_loop->events);
        free(event_loop);
        return NULL;
    }

    event_loop->event_set_size = event_set_size;
    event_loop->stop = 0;
    event_loop->maxfd = -1;
    event_loop->list_head = NULL;
    event_loop->list_tail = NULL;
    event_loop->data = NULL;

    // 返回事件循环
    return event_loop;
}

/*
 * 删除事件处理器
 */
void ae_delete_event_loop(AeEventLoop *event_loop) {
    close(event_loop->epfd);
    free(event_loop->events);
    free(event_loop->ready_events);
    free(event_loop);
}

/*
 * 停止事件处理器
 */
void ae_stop_event_loop(AeEventLoop *event_loop) {
    event_loop->stop = 1;
}

/*
 * 返回当前事件槽大小。
 */
int ae_get_event_set_size(AeEventLoop *event_loop) {
    return event_loop->event_set_size;
}

/*
 * 事件处理器的主循环
 */
void ae_run_loop(AeEventLoop *event_loop) {
    event_loop->stop = 0;

    int count = 0;
    while (!event_loop->stop) {
        // 开始处理事件
        int proc = ae_process_events(event_loop, AE_WAIT_SECONDS);

        if (proc == 0) {  // epoll_wait() 超时返回，直接回调超时函数
            ae_check_timeout(event_loop);
        } else {
            count += proc;
            if (count == 2048) {  // 执行一定数量事件后再回调超时函数，提高性能
                ae_check_timeout(event_loop);
                count = 0;
            }
        }
    }
}

/*
 * 注册 fd
 */
int ae_register_event(AeEventLoop *event_loop, int fd, uint32_t mask, AeCallback *rcallback,
                      AeCallback *wcallback, AeCallback *tcallback, void *data) {
    if (fd < 0 || fd >= event_loop->event_set_size || mask == AE_NONE) {
        return -1;
    }

    // 取出文件事件结构
    AeEvent *fe = &event_loop->events[fd];
    int fe_mask = fe->mask;

    if (fe_mask != mask) {
        // 判断是注册还是修改
        int op = (fe_mask == AE_NONE ? EPOLL_CTL_ADD : EPOLL_CTL_MOD);

        // 监听指定 fd 的指定事件
        if (ae_epoll_add_event(event_loop, fd, mask, op) == -1) {
            return -1;
        }

        fe->fd = fd;

        // 如果有需要，更新事件处理器的最大 fd
        if (fd > event_loop->maxfd) {
            event_loop->maxfd = fd;
        }

        // 设置文件事件类型，以及事件的处理器
        fe->mask = mask;
    }

    // 回调
    fe->rcallback = rcallback;
    fe->wcallback = wcallback;
    fe->tcallback = tcallback;

    // 私有数据
    fe->data = data;

    // 更新事件队列位置
    if (fe_mask == AE_NONE) {  // 新注册事件，加入队列
        DLIST_ADD_HEAD(event_loop->list_head, event_loop->list_tail, fe);
    } else {  // 已注册事件，则更新位置
        if (fe->list_prev != NULL) {  // 否则已在头部，不需要动
            DLIST_DEL(event_loop->list_head, event_loop->list_tail, fe);
            DLIST_ADD_HEAD(event_loop->list_head, event_loop->list_tail, fe);
        }
    }

    // 更新最后激活时间
    fe->last_active = time(NULL);

    return 0;
}

/*
 * 将 fd 从监听队列中删除
 */
int ae_unregister_event(AeEventLoop *event_loop, int fd) {
    if (fd < 0 || fd >= event_loop->event_set_size) {
        return -1;
    }

    // 取出文件事件结构
    AeEvent *fe = &event_loop->events[fd];

    // 未设置监听的事件类型，直接返回
    if (fe->mask == AE_NONE) {
        return 0;
    }

    if (fd == event_loop->maxfd) {
        /* Update the max fd */
        int j;
        for (j = event_loop->maxfd - 1; j >= 0; j--) {
            if (event_loop->events[j].mask != AE_NONE) {
                break;
            }
        }

        event_loop->maxfd = j;
    }

    fe->mask = AE_NONE;

    // 从队列中删除
    DLIST_DEL(event_loop->list_head, event_loop->list_tail, fe);

    return ae_epoll_del_event(event_loop, fd);
}

/*
 * 从双向时间顺序队列中移除，
 * 并且根据 ae_register_event() 中的逻辑（prev 为 NULL，会被当作已在队列头部），
 * 即时再次调用 ae_register_event()，也不会再将该事件加入队列，
 * 除非调用 ae_add_event_to_list（）。
 */
void ae_remove_event_from_list(AeEventLoop *event_loop, int fd) {
    AeEvent *fe = &event_loop->events[fd];
    DLIST_DEL(event_loop->list_head, event_loop->list_tail, fe);
}

void ae_add_event_to_list(AeEventLoop *event_loop, int fd) {
    AeEvent *fe = &event_loop->events[fd];
    DLIST_ADD_HEAD(event_loop->list_head, event_loop->list_tail, fe);
}