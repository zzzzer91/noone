/*
 * Created by zzzzer on 4/18/19.
 */

#ifndef _NOONE_DNS_H_
#define _NOONE_DNS_H_

int dns_send_request(int sockfd, const char *domain);

int dns_parse_response(int sockfd);

#endif  /* _NOONE_DNS_H_ */
