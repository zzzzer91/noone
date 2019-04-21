/*
 * Created by zzzzer on 4/18/19.
 *
 * 只支持 ipv4
 */

#include "dns.h"
#include "error.h"
#include "socket.h"
#include <sys/socket.h>
#include <assert.h>
#include <arpa/inet.h>

#define DNS_SERVER1 "8.8.8.8"
#define DNS_SERVER2 "8.8.4.4"
#define DNS_SERVER3 "114.114.114.114"

#define DNS_HOST			0x01
#define DNS_CNAME			0x05

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
    free(question->qname);

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

    int slen;

    // 主服务器，备用服务器各发一遍，增加稳定性
    dest.sin_addr.s_addr = inet_addr(DNS_SERVER3);
    slen = sendto(sockfd, request, req_len, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (slen < 0) {
        SYS_ERROR("sendto");
        return -1;
    }
    dest.sin_addr.s_addr = inet_addr(DNS_SERVER1);
    slen = sendto(sockfd, request, req_len, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (slen < 0) {
        SYS_ERROR("sendto");
        return -1;
    }
//    dest.sin_addr.s_addr = inet_addr(DNS_SERVER2);
//    slen = sendto(sockfd, request, req_len, 0, (struct sockaddr*)&dest, sizeof(dest));
//    if (slen < 0) {
//        SYS_ERROR("sendto");
//        return -1;
//    }

    return 0;
}

static int
is_pointer(int in)
{
    return ((in & 0xC0) == 0xC0);
}

static void
dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len)
{

    int flag = 0, n = 0, alen = 0;
    char *pos = out + (*len);

    while (1) {

        flag = (int)ptr[0];
        if (flag == 0) break;

        if (is_pointer(flag)) {

            n = (int)ptr[1];
            ptr = chunk + n;
            dns_parse_name(chunk, ptr, out, len);
            break;

        } else {

            ptr ++;
            memcpy(pos, ptr, flag);
            pos += flag;
            ptr += flag;

            *len += flag;
            if ((int)ptr[0] != 0) {
                memcpy(pos, ".", 1);
                pos += 1;
                (*len) += 1;
            }
        }

    }

}

/*
 * 返回一个 ipv4 地址
 */
unsigned int
dns_parse_response(char *buf)
{
    int i = 0;
    unsigned char *ptr = (unsigned char *)buf;

    ptr += 4;
    int querys = ntohs(*(unsigned short*)ptr);

    ptr += 2;
    int answers = ntohs(*(unsigned short*)ptr);

    // 跳过 query 区域
    ptr += 6;
    for (i = 0;i < querys;i ++) {
        while (1) {
            int flag = (int)ptr[0];
            ptr += (flag + 1);

            if (flag == 0) {
                break;
            }
        }
        ptr += 4;
    }

    char cname[128], aname[128];
    int len, type, ttl, datalen;

    for (i = 0;i < answers;i ++) {

        bzero(aname, sizeof(aname));
        len = 0;

        dns_parse_name((unsigned char *)buf, ptr, aname, &len);
        ptr += 2;

        type = htons(*(unsigned short*)ptr);
        ptr += 4;

        ttl = htons(*(unsigned short*)ptr);
        ptr += 4;

        datalen = ntohs(*(unsigned short*)ptr);
        ptr += 2;

        if (type == DNS_CNAME) {

            bzero(cname, sizeof(cname));
            len = 0;
            dns_parse_name((unsigned char *)buf, ptr, cname, &len);
            ptr += datalen;

        } else if (type == DNS_HOST) {

            unsigned int netip;

            if (datalen == 4) {
                memcpy(&netip, ptr, datalen);
                return netip;
            }

            ptr += datalen;
        }
    }

    return 0;
}