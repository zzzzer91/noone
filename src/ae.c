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
 * 关联给定事件到 fd，默认 ET 模式
 *
 * 如果 fd 没有关联任何事件，那么这是一个 ADD 操作。
 *
 * 如果已经关联了某个/某些事件，那么这是一个 MOD 操作。
 */
static int
ae_api_add_event(AeEventLoop *event_loop, int fd, uint32_t mask)
{
    int fe_mask = event_loop->events[fd].mask;

    if (fe_mask != mask) {
        int op = fe_mask == AE_NONE ?
                 EPOLL_CTL_ADD : EPOLL_CTL_MOD;

        struct epoll_event ee;
        ee.events = mask | EPOLLET;
        ee.data.u64 = 0; /* avoid valgrind warning */
        ee.data.fd = fd;

        if (epoll_ctl(event_loop->epfd, op, fd, &ee) == -1) {
            return -1;
        }
    }

    return 0;
}

/*
 * 从 fd 中删除给定事件
 */
static void
ae_api_del_event(AeEventLoop *event_loop, int fd)
{
    struct epoll_event ee = {0, {0}};

    /* Note, Kernel < 2.6.9 requires a non null event pointer even for
     * EPOLL_CTL_DEL. */
    epoll_ctl(event_loop->epfd, EPOLL_CTL_DEL, fd, &ee);
}

/*
 * 获取可执行事件
 */
static int
ae_api_poll(AeEventLoop *event_loop, int timeout)
{
    // 等待时间
    return epoll_wait(event_loop->epfd, event_loop->ready_events,
            event_loop->event_set_size, timeout);
}

/*
 * 检查所有时间的最后激活时间，踢掉超时的时间
 */
static void
check_last_active(AeEventLoop *event_loop)
{

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

    // 初始化文件事件结构
    event_loop->events = malloc(sizeof(AeEventLoop)*event_set_size);
    if (event_loop->events == NULL) {
        ae_delete_event_loop(event_loop);
        return NULL;
    }
    /* Events with mask == AE_NONE are not set. So let's initialize the
     * vector with it. */
    // 初始化监听事件
    for (int i = 0; i < event_set_size; i++) {
        event_loop->events[i].mask = AE_NONE;
    }

    // 设置数组大小
    event_loop->event_set_size = event_set_size;

    event_loop->stop = 0;
    event_loop->maxfd = -1;

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
ae_get_event_set_size(AeEventLoop *event_loop)
{
    return event_loop->event_set_size;
}

/*
 * 事件处理器的主循环
 */
void
ae_run_loop(AeEventLoop *event_loop)
{
    event_loop->stop = 0;

    while (!event_loop->stop) {
        // 开始处理事件
        ae_process_events(event_loop);

        // 检查所有时间的最后激活时间，踢掉超时的时间
        check_last_active(event_loop);
    }
}

/*
 * 注册 fd
 */
int
ae_register_file_event(AeEventLoop *event_loop, int fd, uint32_t mask,
        AeFileProc *rfile_proc, AeFileProc *wfile_proc, void *client_data)
{
    if (fd >= event_loop->event_set_size) return -1;

    // 监听指定 fd 的指定事件
    if (ae_api_add_event(event_loop, fd, mask) == -1) {
        return -1;
    }

    // 取出文件事件结构
    AeFileEvent *fe = &event_loop->events[fd];

    fe->last_active = time(NULL);

    // 设置文件事件类型，以及事件的处理器
    fe->mask = mask;

    // 读写事件
    fe->rfile_proc = rfile_proc;
    fe->wfile_proc = wfile_proc;

    // 私有数据
    fe->client_data = client_data;

    // 如果有需要，更新事件处理器的最大 fd
    if (fd > event_loop->maxfd) {
        event_loop->maxfd = fd;
    }

    return 0;
}

/*
 * 修改 fd 监听事件
 */
int
ae_modify_file_event(AeEventLoop *event_loop, int fd, uint32_t mask,
        AeFileProc *rfile_proc, AeFileProc *wfile_proc, void *client_data)
{
    AeFileEvent *fe = &event_loop->events[fd];
    if (fe->mask == AE_NONE) return 0;

    return ae_register_file_event(event_loop, fd, mask,
            rfile_proc, wfile_proc, client_data);
}

/*
 * 将 fd 从监听队列中删除
 */
void
ae_unregister_file_event(AeEventLoop *event_loop, int fd)
{
    if (fd >= event_loop->event_set_size) return;

    // 取出文件事件结构
    AeFileEvent *fe = &event_loop->events[fd];

    // 未设置监听的事件类型，直接返回
    if (fe->mask == AE_NONE) return;

    // 计算新 maxfd
    if (fd == event_loop->maxfd) {
        /* Update the max fd */
        int j;
        for (j = event_loop->maxfd-1; j >= 0; j--) {
            if (event_loop->events[j].mask != AE_NONE) break;
        }

        event_loop->maxfd = j;
    }

    fe->mask = AE_NONE;

    // 取消对给定 fd 的给定事件的监视
    ae_api_del_event(event_loop, fd);
}

/*
 * 获取给定 fd 正在监听的事件类型
 */
int
ae_get_file_events_mask(AeEventLoop *event_loop, int fd)
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
            int fd = event_loop->ready_events[j].data.fd;

            // 从已就绪数组中获取事件
            AeFileEvent *fe = &event_loop->events[fd];

            if (fe->mask & AE_IN) {
                fe->rfile_proc(event_loop, fd, fe->client_data);
            } else if (fe->mask & AE_OUT) {
                fe->wfile_proc(event_loop, fd, fe->client_data);
            } else if (fe->mask & EPOLLHUP) {
                fe->wfile_proc(event_loop, fd, fe->client_data);
            } else if (fe->mask & EPOLLERR) {
                fe->wfile_proc(event_loop, fd, fe->client_data);
            }

            processed++;
        }
    }

    return processed; /* return the number of processed file/time events */
}