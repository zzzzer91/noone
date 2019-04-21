/*
 * Created by zzzzer on 4/21/19.
 */

#include "dns.h"
#include "helper.h"
#include <sys/socket.h>

void
test_dns()
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        SYS_ERROR("socket");
        return;
    }
    dns_send_request(sockfd, "www.baidu.com");
    dns_parse_response(sockfd);
}