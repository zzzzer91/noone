/*
 * Created by zzzzer on 2/11/19.
 */

#include "ae.h"
#include "log.h"
#include "dlist.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>

/*
 * 关联给定事件到 fd
 *
 * 如果 fd 没有关联任何事件，那么这是一个 ADD 操作。
 *
 * 如果已经关联了某个/某些事件，那么这是一个 MOD 操作。
 */
#define AE_EPOLL_ADD_EVENT(event_loop, fd, mask, op) \
    ({\
        struct epoll_event ee; \
        ee.events = mask; \
        ee.data.fd = fd; \
        epoll_ctl(event_loop->epfd, op, fd, &ee); \
    })

/*
 * 删除事件
 */
#define AE_EPOLL_DEL_EVENT(event_loop, fd) \
    ({ \
        epoll_ctl(event_loop->epfd, EPOLL_CTL_DEL, fd, NULL); \
    })

/*
 * 获取可执行事件，timeout 单位毫秒
 */
#define AE_EPOLL_POLL(event_loop, timeout) \
    ({ \
        epoll_wait(event_loop->epfd, event_loop->ready_events, \
                event_loop->event_set_size, timeout); \
    })

/* Process every pending time event, then every pending file event
 * (that may be registered by time event callbacks just processed).
 *
 * 处理所有已到达的时间事件，以及所有已就绪的文件事件。
 *
 * The function returns the number of events processed.
 * 函数的返回值为已处理事件的数量
 *
 * note the fe->mask & mask & ... code: maybe an already processed
 * event removed an element that fired and we still didn't
 * processed, so we check if the event is still valid.
 */
#define ae_process_events(event_loop, timeout) \
    do { \
        int numevents = AE_EPOLL_POLL(event_loop, timeout); \
        for (int i = 0; i < numevents; i++) { \
            uint32_t mask = event_loop->ready_events[i].events; \
            int fd = event_loop->ready_events[i].data.fd; \
            AeEvent *fe = &event_loop->events[fd]; \
            if (fe->mask & mask & AE_IN) { \
                fe->rcallback(event_loop, fd, fe->client_data); \
            } \
            if (fe->mask & mask & AE_OUT) { \
                fe->wcallback(event_loop, fd, fe->client_data); \
            } \
        } \
    } while (0)

/*
 * 创建事件处理器
 */
AeEventLoop *
ae_create_event_loop(int event_set_size)
{
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
    event_loop->events = malloc(sizeof(AeEvent)*event_set_size);
    if (event_loop->events == NULL) {
        close(event_loop->epfd);
        free(event_loop);
        return NULL;
    }
    /* Events with mask == AE_NONE are not set. So let's initialize the
     * vector with it. */
    for (int i = 0; i < event_set_size; i++) {
        event_loop->events[i].mask = AE_NONE;
        event_loop->events[i].list_prev = NULL;
        event_loop->events[i].list_next = NULL;
    }

    // 初始化事件槽空间，放置 epoll_wait() 已就绪事件
    event_loop->ready_events = malloc(sizeof(struct epoll_event)*event_set_size);
    if (event_loop->ready_events == NULL) {
        close(event_loop->epfd);
        free(event_loop->events);
        free(event_loop);
        return NULL;
    }

    // 设置数组大小
    event_loop->event_set_size = event_set_size;

    event_loop->stop = 0;
    event_loop->maxfd = -1;

    event_loop->list_head = NULL;
    event_loop->list_tail = NULL;

    // 返回事件循环
    return event_loop;
}

/*
 * 删除事件处理器
 */
void
ae_delete_event_loop(AeEventLoop *event_loop)
{
    close(event_loop->epfd);
    free(event_loop->events);
    free(event_loop->ready_events);
    free(event_loop);
}

/*
 * 停止事件处理器
 */
void
ae_stop_event_loop(AeEventLoop *event_loop)
{
    event_loop->stop = 1;
}

/*
 * 返回当前事件槽大小。
 */
int
ae_get_event_set_size(AeEventLoop *event_loop)
{
    return event_loop->event_set_size;
}

/*
 * 事件处理器的主循环
 */
void
ae_run_loop(AeEventLoop *event_loop, AeCallback timeout_callback)
{
    event_loop->stop = 0;

    while (!event_loop->stop) {
        // 开始处理事件
        ae_process_events(event_loop, AE_WAIT_SECONDS*1000);

        // 检查超时事件
        if (timeout_callback) {
            timeout_callback(event_loop, -1, NULL);
        }
    }
}

/*
 * 注册 fd
 */
int
ae_register_event(AeEventLoop *event_loop, int fd, uint32_t mask,
        AeCallback *rcallback, AeCallback *wcallback, void *client_data)
{
    if (fd < 0 || fd >= event_loop->event_set_size || mask == AE_NONE) {
        return -1;
    }

    // 取出文件事件结构
    AeEvent *fe = &event_loop->events[fd];
    int fe_mask = fe->mask;

    if (fe_mask != mask) {
        // 判断是注册还是修改
        int op = fe_mask == AE_NONE ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;

        // 监听指定 fd 的指定事件
        if (AE_EPOLL_ADD_EVENT(event_loop, fd, mask, op) == -1) {
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

    // 读写事件
    fe->rcallback = rcallback;
    fe->wcallback = wcallback;

    // 私有数据
    fe->client_data = client_data;

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
int
ae_unregister_event(AeEventLoop *event_loop, int fd)
{
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
        for (j = event_loop->maxfd-1; j >= 0; j--) {
            if (event_loop->events[j].mask != AE_NONE) {
                break;
            }
        }

        event_loop->maxfd = j;
    }

    fe->mask = AE_NONE;

    // 从队列中删除
    DLIST_DEL(event_loop->list_head, event_loop->list_tail, fe);

    return AE_EPOLL_DEL_EVENT(event_loop, fd);
}

void
ae_remove_event_from_list(AeEventLoop *event_loop, int fd)
{
    AeEvent *fe = &event_loop->events[fd];
    DLIST_DEL(event_loop->list_head, event_loop->list_tail, fe);
}