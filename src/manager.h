/*
 * Created by zzzzer on 4/2/19.
 */

#ifndef _NOONE_USER_H_
#define _NOONE_USER_H_

#include "cryptor.h"
#include "lru.h"

typedef struct NooneUserInfo {
    int user_idx;
    int tcp_server_fd;
    int udp_server_fd;
    NooneCryptorInfo *cryptor_info;
    LruCache *lru_cache;  // 每个用户拥有独立的 lru 缓存
} NooneUserInfo;

typedef struct NooneManager {
    NooneUserInfo *users_info; // 用户数组
    int user_count;
} NooneManager;

NooneManager *init_manager(int user_count);

#endif  /* _NOONE_USER_H_ */
