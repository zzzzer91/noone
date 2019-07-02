/*
 * Created by zzzzer on 4/21/19.
 */

#include "dns.h"
#include "helper.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void test_dns() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        SYS_ERROR("socket");
        return;
    }
    dns_send_request(sockfd, "www.baidu.com");

    char buffer[1024] = {0};
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addr_len);
    if (n < 0) {
        SYS_ERROR("recvfrom");
        return;
    }
    struct in_addr netip;
    netip.s_addr = dns_parse_response(buffer);
    // printf("%s\n", inet_ntoa(netip));
}