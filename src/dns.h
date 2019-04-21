/*
 * Created by zzzzer on 4/18/19.
 */

#ifndef _NOONE_DNS_H_
#define _NOONE_DNS_H_

int dns_send_request(int sockfd, const char *domain);

unsigned int dns_parse_response(char *buf);

#endif  /* _NOONE_DNS_H_ */
