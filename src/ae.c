/*
 * 源自 Redis 。
 *
 * Created by zzzzer on 2/11/19.
 */

#include "ae.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>

/*
 * 关联给定事件到 fd
 */
static int
ae_api_add_event(AeEventLoop *event_loop, int fd, int mask)
{
    struct epoll_event ee;

    /* If the fd was already monitored for some event, we need a MOD
     * operation. Otherwise we need an ADD operation.
     *
     * 如果 fd 没有关联任何事件，那么这是一个 ADD 操作。
     *
     * 如果已经关联了某个/某些事件，那么这是一个 MOD 操作。
     */
    int op = event_loop->events[fd].mask == AE_NONE ?
             EPOLL_CTL_ADD : EPOLL_CTL_MOD;

    // 注册事件到 epoll
    ee.events = 0;
    mask |= event_loop->events[fd].mask; /* Merge old events */
    if (mask & AE_READABLE) ee.events |= EPOLLIN;
    if (mask & AE_WRITABLE) ee.events |= EPOLLOUT;
    ee.data.u64 = 0; /* avoid valgrind warning */
    ee.data.fd = fd;

    if (epoll_ctl(event_loop->epfd, op, fd, &ee) == -1) {
        return -1;
    }

    return 0;
}

/*
 * 从 fd 中删除给定事件
 */
static void
ae_api_del_event(AeEventLoop *event_loop, int fd, int delmask)
{
    struct epoll_event ee;

    int mask = event_loop->events[fd].mask & (~delmask);

    ee.events = 0;
    if (mask & AE_READABLE) ee.events |= EPOLLIN;
    if (mask & AE_WRITABLE) ee.events |= EPOLLOUT;
    ee.data.u64 = 0; /* avoid valgrind warning */
    ee.data.fd = fd;
    if (mask != AE_NONE) {
        epoll_ctl(event_loop->epfd, EPOLL_CTL_MOD, fd, &ee);
    } else {
        /* Note, Kernel < 2.6.9 requires a non null event pointer even for
         * EPOLL_CTL_DEL. */
        epoll_ctl(event_loop->epfd, EPOLL_CTL_DEL, fd, &ee);
    }
}

/*
 * 获取可执行事件
 */
static int
ae_api_poll(AeEventLoop *event_loop, int timeout)
{
    int retval, numevents = 0;

    // 等待时间
    retval = epoll_wait(event_loop->epfd, event_loop->ready_events,
            event_loop->event_set_size, timeout);

    // 有至少一个事件就绪？
    if (retval > 0) {
        int j;

        // 为已就绪事件设置相应的模式
        // 并加入到 event_loop 的 fired 数组中
        numevents = retval;
        for (j = 0; j < numevents; j++) {
            int mask = 0;
            struct epoll_event *e = event_loop->ready_events+j;

            if (e->events & EPOLLIN) mask |= AE_READABLE;
            if (e->events & EPOLLOUT) mask |= AE_WRITABLE;
            if (e->events & EPOLLERR) mask |= AE_WRITABLE;
            if (e->events & EPOLLHUP) mask |= AE_WRITABLE;

            event_loop->fired[j].fd = e->data.fd;
            event_loop->fired[j].mask = mask;
        }
    }

    // 返回已就绪事件个数
    return numevents;
}

/*
 * 创建事件处理器
 */
AeEventLoop *
ae_create_event_loop(int event_set_size)
{
    AeEventLoop *event_loop = malloc(sizeof(*event_loop));
    if (event_loop == NULL) {
        return NULL;
    }

    // 初始化事件槽空间，放置 epoll_wait() 已就绪事件
    event_loop->ready_events = malloc(sizeof(struct epoll_event)*event_loop->event_set_size);
    if (event_loop->ready_events == NULL) {
        ae_delete_event_loop(event_loop);
        return NULL;
    }

    // 创建 epoll 实例
    event_loop->epfd = epoll_create(AE_MAX_EVENTS);
    if (event_loop->epfd == -1) {
        ae_delete_event_loop(event_loop);
        return NULL;
    }

    // 初始化文件事件结构和已就绪文件事件结构数组
    event_loop->events = malloc(sizeof(AeEventLoop)*event_set_size);
    if (event_loop->events == NULL) {
        ae_delete_event_loop(event_loop);
        return NULL;
    }
    event_loop->fired = malloc(sizeof(AeEventLoop)*event_set_size);
    if (event_loop->fired == NULL) {
        ae_delete_event_loop(event_loop);
        return NULL;
    }
    // 设置数组大小
    event_loop->event_set_size = event_set_size;

    event_loop->stop = 0;
    event_loop->maxfd = -1;

    /* Events with mask == AE_NONE are not set. So let's initialize the
     * vector with it. */
    // 初始化监听事件
    for (int i = 0; i < event_set_size; i++) {
        event_loop->events[i].mask = AE_NONE;
    }

    // 返回事件循环
    return event_loop;
}

/*
 * 删除事件处理器
 */
void
ae_delete_event_loop(AeEventLoop *event_loop)
{
    if (event_loop->epfd != -1) close(event_loop->epfd);
    if (event_loop->ready_events != NULL) free(event_loop->ready_events);
    if (event_loop->events != NULL) free(event_loop->events);
    if (event_loop->fired != NULL) free(event_loop->fired);

    free(event_loop);
}

/*
 * 停止事件处理器
 */
void
ae_stop(AeEventLoop *event_loop)
{
    event_loop->stop = 1;
}

/*
 * 返回当前事件槽大小。
 */
int
ae_get_set_size(AeEventLoop *event_loop)
{
    return event_loop->event_set_size;
}

int
ae_wait(int fd, int mask, int timeout)
{
    return 0;
}

/*
 * 事件处理器的主循环
 */
void
ae_run_loop(AeEventLoop *event_loop)
{
    event_loop->stop = 0;

    while (!event_loop->stop) {

        // 如果有需要在事件处理前执行的函数，那么运行它
        if (event_loop->before_sleep != NULL)
            event_loop->before_sleep(event_loop);

        // 开始处理事件
        ae_process_events(event_loop);
    }
}

/*
 * 根据 mask 参数的值，监听 fd 文件的状态，
 * 当 fd 可用时，执行 proc 函数
 */
int
ae_create_file_event(AeEventLoop *event_loop, int fd, int mask,
        AeFileProc *proc, void *client_data)
{
    if (fd >= event_loop->event_set_size) return AE_ERR;

    // 取出文件事件结构
    AeFileEvent *fe = &event_loop->events[fd];

    // 监听指定 fd 的指定事件
    if (ae_api_add_event(event_loop, fd, mask) == -1) {
        return AE_ERR;
    }

    // 设置文件事件类型，以及事件的处理器
    fe->mask |= mask;
    if (mask & AE_READABLE) fe->rfile_proc = proc;
    if (mask & AE_WRITABLE) fe->wfile_proc = proc;

    // 私有数据
    fe->client_data = client_data;

    // 如果有需要，更新事件处理器的最大 fd
    if (fd > event_loop->maxfd) {
        event_loop->maxfd = fd;
    }

    return AE_OK;
}

/*
 * 将 fd 从 mask 指定的监听队列中删除
 */
void
ae_delete_file_event(AeEventLoop *event_loop, int fd, int mask)
{
    if (fd >= event_loop->event_set_size) return;

    // 取出文件事件结构
    AeFileEvent *fe = &event_loop->events[fd];

    // 未设置监听的事件类型，直接返回
    if (fe->mask == AE_NONE) return;

    // 计算新掩码
    fe->mask = fe->mask & (~mask);
    if (fd == event_loop->maxfd && fe->mask == AE_NONE) {
        /* Update the max fd */
        int j;

        for (j = event_loop->maxfd-1; j >= 0; j--) {
            if (event_loop->events[j].mask != AE_NONE) break;
        }

        event_loop->maxfd = j;
    }

    // 取消对给定 fd 的给定事件的监视
    ae_api_del_event(event_loop, fd, mask);
}

/*
 * 获取给定 fd 正在监听的事件类型
 */
int
ae_get_file_events(AeEventLoop *event_loop, int fd)
{
    if (fd >= event_loop->event_set_size) {
        return 0;
    }

    AeFileEvent *fe = &event_loop->events[fd];

    return fe->mask;
}

/* Process every pending time event, then every pending file event
 * (that may be registered by time event callbacks just processed).
 *
 * 处理所有已到达的时间事件，以及所有已就绪的文件事件。
 *
 * Without special flags the function sleeps until some file event
 * fires, or when the next time event occurs (if any).
 *
 * 如果不传入特殊 flags 的话，那么函数睡眠直到文件事件就绪，
 * 或者下个时间事件到达（如果有的话）。
 *
 * If flags is 0, the function does nothing and returns.
 * 如果 flags 为 0 ，那么函数不作动作，直接返回。
 *
 * if flags has AE_ALL_EVENTS set, all the kind of events are processed.
 * 如果 flags 包含 AE_ALL_EVENTS ，所有类型的事件都会被处理。
 *
 * if flags has AE_FILE_EVENTS set, file events are processed.
 * 如果 flags 包含 AE_FILE_EVENTS ，那么处理文件事件。
 *
 * if flags has AE_TIME_EVENTS set, time events are processed.
 * 如果 flags 包含 AE_TIME_EVENTS ，那么处理时间事件。
 *
 * if flags has AE_DONT_WAIT set the function returns ASAP until all
 * the events that's possible to process without to wait are processed.
 * 如果 flags 包含 AE_DONT_WAIT ，
 * 那么函数在处理完所有不许阻塞的事件之后，即刻返回。
 *
 * The function returns the number of events processed.
 * 函数的返回值为已处理事件的数量
 */
int
ae_process_events(AeEventLoop *event_loop)
{
    int processed = 0;

    if (event_loop->maxfd != -1) {
        int j;

        // 处理文件事件
        int numevents = ae_api_poll(event_loop, -1);
        for (j = 0; j < numevents; j++) {
            // 从已就绪数组中获取事件
            AeFileEvent *fe = &event_loop->events[event_loop->fired[j].fd];

            int mask = event_loop->fired[j].mask;
            int fd = event_loop->fired[j].fd;
            int rfired = 0;

            /* note the fe->mask & mask & ... code: maybe an already processed
              * event removed an element that fired and we still didn't
              * processed, so we check if the event is still valid. */
            // 读事件
            if (fe->mask & mask & AE_READABLE) {
                // rfired 确保读/写事件只能执行其中一个
                rfired = 1;
                fe->rfile_proc(event_loop, fd, fe->client_data);
            }
            // 写事件
            if (fe->mask & mask & AE_WRITABLE) {
                if (!rfired || fe->wfile_proc != fe->rfile_proc)
                    fe->wfile_proc(event_loop, fd, fe->client_data);
            }

            processed++;
        }
    }

    return processed; /* return the number of processed file/time events */
}