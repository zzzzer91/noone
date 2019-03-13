/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_TCP_H_
#define _NOONE_TCP_H_

#include "ae.h"
#include <openssl/evp.h>

#define BUFFER_LEN 16 * 1024

typedef enum SsStageType {
    STAGE_INIT = 0,
    STAGE_ADDR,
    STAGE_UDP_ASSOC,
    STAGE_DNS,
    STAGE_CONNECTING,
    STAGE_STREAM,
    STAGE_DESTROYED = -1
} SsStageType;

void accept_conn(AeEventLoop *event_loop, int fd, void *client_data);

void read_ssclient(AeEventLoop *event_loop, int fd, void *client_data);

void write_ssclient(AeEventLoop *event_loop, int fd, void *client_data);

void read_remote(AeEventLoop *event_loop, int fd, void *client_data);

void write_remote(AeEventLoop *event_loop, int fd, void *client_data);

#endif  /* _NOONE_TCP_H_ */
