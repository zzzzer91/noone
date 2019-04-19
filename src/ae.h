/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_AE_H_
#define _NOONE_AE_H_

#include <sys/epoll.h>
#include <time.h>

#define AE_MAX_EVENTS 4096
#define AE_WAIT_SECONDS 180  // epoll_wait() 和 踢出事件的超时时间

/*
 * 文件事件状态
 */
#define AE_NONE 0          // 未设置
#define AE_IN   EPOLLIN    // 可读
#define AE_OUT  EPOLLOUT   // 可写
#define AE_ERR  EPOLLERR   // 错误，光注册这个可视为将事件挂起

typedef struct AeEventLoop AeEventLoop;

/*
 * 事件回调接口
 */
typedef void AeCallback(AeEventLoop *event_loop, int fd, void *data);

/*
 * File event structure
 */
typedef struct AeEvent {

    int fd;

    // 监听事件类型掩码，
    // 值可以是 AE_IN 或 AE_OUT，或同时
    // AE_NONE 代表无监听事件
    int mask;

    // 读事件
    AeCallback *rcallback;

    // 写事件
    AeCallback *wcallback;

    // 超时之后的回调
    AeCallback *tcallback;

    // 多路复用库的私有数据
    void *data;

    // 最后激活时间，用于踢掉超时连接
    time_t last_active;

    // 事件双向链表
    struct AeEvent *list_prev, *list_next;

} AeEvent;

/*
 * 事件处理器的状态
 */
struct AeEventLoop {
    // epoll_event 实例描述符
    int epfd;

    // max number of file descriptors tracked
    int event_set_size;

    // highest file descriptor currently registered
    int maxfd;

    // 事件处理器的开关
    // 1 代表关闭
    int stop;

    // 事件槽，只用来放置 epoll_wait() 已就绪事件
    struct epoll_event *ready_events;

    // Registered events
    AeEvent *events;

    // 事件会以最后激活时间排序，用于踢出超时事件
    // 最新被激活的事件，会被放置到头部
    AeEvent *list_head, *list_tail;

    // 可以携带一些其他数据
    void *data;
};

/* Prototypes */
AeEventLoop *ae_create_event_loop(int event_set_size);
void ae_delete_event_loop(AeEventLoop *event_loop);
void ae_run_loop(AeEventLoop *event_loop);
void ae_stop_event_loop(AeEventLoop *event_loop);
int ae_get_event_set_size(AeEventLoop *event_loop);

int ae_register_event(AeEventLoop *event_loop, int fd, uint32_t mask,
        AeCallback *rcallback, AeCallback *wcallback, AeCallback *tcallback, void *data);
int ae_unregister_event(AeEventLoop *event_loop, int fd);

void ae_remove_event_from_list(AeEventLoop *event_loop, int fd);
void ae_add_event_to_list(AeEventLoop *event_loop, int fd);

#endif  /* _NOONE_AE_H_ */
