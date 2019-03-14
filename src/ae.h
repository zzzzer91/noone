/*
 * 源自 Redis 。
 *
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_AE_H_
#define _NOONE_AE_H_

#include <sys/epoll.h>
#include <time.h>

#define AE_MAX_EVENTS 8192

/*
 * 文件事件状态
 */
#define AE_NONE 0         // 未设置
#define AE_IN EPOLLIN     // 可读
#define AE_OUT EPOLLOUT   // 可写

typedef struct AeEventLoop AeEventLoop;

/*
 * 事件接口
 */
typedef void AeFileProc(AeEventLoop *event_loop, int fd, void *data);

/*
 * File event structure
 */
typedef struct AeFileEvent {

    // 最后激活时间，用于踢掉超时连接
    time_t last_active;

    // 监听事件类型掩码，
    // 值可以是 AE_IN 或 AE_OUT，不能同时
    int mask;

    // 读事件处理器
    AeFileProc *rfile_proc;

    // 写事件处理器
    AeFileProc *wfile_proc;

    // 多路复用库的私有数据
    void *client_data;

} AeFileEvent;

/*
 * 事件处理器的状态
 */
struct AeEventLoop {
    // epoll_event 实例描述符
    int epfd;

    // 事件槽，只用来放置 epoll_wait() 已就绪事件
    struct epoll_event *ready_events;

    // 目前已注册的最大描述符
    int maxfd;   /* highest file descriptor currently registered */

    // 事件数组容量
    int event_set_size; /* max number of file descriptors tracked */

    // 已注册的文件事件
    AeFileEvent *events; /* Registered events */

    // 事件处理器的开关
    int stop;

    // 可以携带一些其他数据
    void *extra_data;
};

/* Prototypes */
AeEventLoop *ae_create_event_loop(int event_set_size);
void ae_delete_event_loop(AeEventLoop *event_loop);
void ae_run_loop(AeEventLoop *event_loop);
void ae_stop_event_loop(AeEventLoop *event_loop);
int ae_get_event_set_size(AeEventLoop *event_loop);

int ae_register_file_event(AeEventLoop *event_loop, int fd, uint32_t mask,
        AeFileProc *rfile_proc, AeFileProc *wfile_proc, void *client_data);
int ae_modify_file_event(AeEventLoop *event_loop, int fd, uint32_t mask);
void ae_unregister_file_event(AeEventLoop *event_loop, int fd);
int ae_get_file_events_mask(AeEventLoop *event_loop, int fd);
int ae_process_events(AeEventLoop *event_loop);

#endif  /* _NOONE_AE_H_ */
