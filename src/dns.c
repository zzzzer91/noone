/*
 * Created by zzzzer on 4/18/19.
 */

#include "dns.h"
#include "error.h"
#include "socket.h"
#include <sys/socket.h>
#include <assert.h>
#include <arpa/inet.h>

#define DNS_SERVER "8.8.8.8"

typedef struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} DnsHeader;

typedef struct dns_question {
    int length;
    unsigned short qtype;
    unsigned short qclass;
    char *qname;
} DnsQuestion;

static int
build_header(DnsHeader *header)
{
    assert(header != NULL);

    memset(header, 0, sizeof(DnsHeader));

    srandom(time(NULL));

    header->id = random();
    header->flags |= htons(0x0100);
    header->qdcount = htons(1);

    return 0;
}

static void
build_hostname(const char *hostname)
{
    assert(hostname != NULL);
}

static int
build_question(DnsQuestion *question, const char *hostname)
{
    assert(question != NULL);

    memset(question, 0, sizeof(DnsQuestion));

    question->qname = malloc(strlen(hostname) + 2);
    if (question->qname == NULL) {
        return -1;
    }

    question->length = strlen(hostname) + 2;

    question->qtype = htons(1);
    question->qclass = htons(1);

    const char delim[2] = ".";

    char *hostname_dup = strdup(hostname);
    char *token = strtok(hostname_dup, delim);

    char *qname_p = question->qname;

    while (token != NULL) {

        size_t len = strlen(token);

        *qname_p = len;
        qname_p ++;

        strncpy(qname_p, token, len+1);
        qname_p += len;

        token = strtok(NULL, delim);
    }

    free(hostname_dup);

    return 0;

}

static int
build_request(DnsHeader *header, DnsQuestion *question, char *request)
{
    int header_s = sizeof(DnsHeader);
    int question_s = question->length + sizeof(question->qtype) + sizeof(question->qclass);

    int length = question_s + header_s;

    int offset = 0;
    memcpy(request+offset, header, sizeof(DnsHeader));
    offset += sizeof(DnsHeader);

    memcpy(request+offset, question->qname, question->length);
    offset += question->length;

    memcpy(request+offset, &question->qtype, sizeof(question->qtype));
    offset += sizeof(question->qtype);

    memcpy(request+offset, &question->qclass, sizeof(question->qclass));

    return length;
}

int
dns_send_request(int sockfd, const char *domain)
{

    struct dns_header header;
    build_header(&header);

    struct dns_question question;
    build_question(&question, domain);

    char request[1024] = {0};
    int req_len = build_request(&header, &question, request);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(DNS_SERVER);
    int slen = sendto(sockfd, request, req_len, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (slen < 0) {
        SYS_ERROR("sendto");
        return -1;
    }

    return 0;
}

int
dns_parse_response(int sockfd)
{
    char buffer[1024] = {0};
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addr_len);
    if (n < 0) {
        SYS_ERROR("recvfrom");
        return -1;
    }

    return 0;
}