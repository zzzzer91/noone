/*
 * Created by zzzzer on 3/14/19.
 */

#ifndef _RIO_H_
#define _RIO_H_

#include <sys/types.h>

ssize_t rio_readn(int fd, void *usrbuf, size_t n);
ssize_t rio_writen(int fd, void *usrbuf, size_t n);

#endif /* _RIO_H_ */
