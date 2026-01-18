#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "proxy_proto.h"

/* Mock global variables from netcat */
int vflag = 0;

static void test_parse_v1() {
    struct proxy_info info;
    int ret;

    printf("Testing v1 parsing...\n");

    /* Valid IPv4 */
    memset(&info, 0, sizeof(info));
    ret = parse_proxy_v1("PROXY TCP4 1.2.3.4 5.6.7.8 1234 5678\r\n", &info);
    assert(ret == 0);
    assert(info.family == AF_INET);
    assert(((struct sockaddr_in*)&info.src)->sin_addr.s_addr == inet_addr("1.2.3.4"));
    assert(((struct sockaddr_in*)&info.dst)->sin_addr.s_addr == inet_addr("5.6.7.8"));
    assert(ntohs(((struct sockaddr_in*)&info.src)->sin_port) == 1234);
    assert(ntohs(((struct sockaddr_in*)&info.dst)->sin_port) == 5678);

    /* Valid IPv6 */
    memset(&info, 0, sizeof(info));
    ret = parse_proxy_v1("PROXY TCP6 ::1 ::2 1234 5678\r\n", &info);
    assert(ret == 0);
    assert(info.family == AF_INET6);
    struct in6_addr in6;
    inet_pton(AF_INET6, "::1", &in6);
    assert(memcmp(&((struct sockaddr_in6*)&info.src)->sin6_addr, &in6, 16) == 0);
    inet_pton(AF_INET6, "::2", &in6);
    assert(memcmp(&((struct sockaddr_in6*)&info.dst)->sin6_addr, &in6, 16) == 0);

    /* UNKNOWN */
    memset(&info, 0, sizeof(info));
    ret = parse_proxy_v1("PROXY UNKNOWN\r\n", &info);
    assert(ret == 0);
    assert(info.family == AF_UNSPEC);

    /* Truncated / Invalid */
    ret = parse_proxy_v1("PROXY TCP4 1.2.3.4\r\n", &info);
    assert(ret == -1);

    ret = parse_proxy_v1("INVALID", &info);
    assert(ret == -1);

    /* Non-printable */
    ret = parse_proxy_v1("PROXY TCP4 1.2.3.4 5.6.7.8 1234 5678\x01\r\n", &info);
    assert(ret == -1);

    printf("v1 parsing tests passed!\n");
}

static void test_parse_v2() {
    struct proxy_info info;
    int ret;
    uint8_t buf[128];
    static const uint8_t sig_v2[12] = {0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a};

    printf("Testing v2 parsing...\n");

    /* Valid IPv4 */
    memset(buf, 0, sizeof(buf));
    memcpy(buf, sig_v2, 12);
    buf[12] = 0x21; /* v2, PROXY */
    buf[13] = 0x11; /* AF_INET, SOCK_STREAM */
    uint16_t len = htons(12);
    memcpy(buf + 14, &len, 2);

    uint32_t src_addr = inet_addr("1.2.3.4");
    uint32_t dst_addr = inet_addr("5.6.7.8");
    uint16_t src_port = htons(1234);
    uint16_t dst_port = htons(5678);

    memcpy(buf + 16, &src_addr, 4);
    memcpy(buf + 20, &dst_addr, 4);
    memcpy(buf + 24, &src_port, 2);
    memcpy(buf + 26, &dst_port, 2);

    memset(&info, 0, sizeof(info));
    ret = parse_proxy_v2(buf, 16 + 12, &info);
    assert(ret == 0);
    assert(info.family == AF_INET);
    assert(((struct sockaddr_in*)&info.src)->sin_addr.s_addr == src_addr);
    assert(ntohs(((struct sockaddr_in*)&info.src)->sin_port) == 1234);

    /* LOCAL */
    memset(buf, 0, sizeof(buf));
    memcpy(buf, sig_v2, 12);
    buf[12] = 0x20; /* v2, LOCAL */
    buf[13] = 0x00; /* UNSPEC */
    len = htons(0);
    memcpy(buf + 14, &len, 2);

    memset(&info, 0, sizeof(info));
    ret = parse_proxy_v2(buf, 16, &info);
    assert(ret == 0);
    assert(info.family == AF_UNSPEC);

    /* Invalid signature */
    buf[0] = 0x00;
    ret = parse_proxy_v2(buf, 16, &info);
    assert(ret == -1);

    printf("v2 parsing tests passed!\n");
}

static void test_serialization_roundtrip() {
    struct proxy_info info, info2;
    char buf1[128];
    uint8_t buf2[128];
    int n;

    printf("Testing serialization round-trip...\n");

    /* v1 Round-trip */
    memset(&info, 0, sizeof(info));
    info.family = AF_INET;
    ((struct sockaddr_in*)&info.src)->sin_family = AF_INET;
    ((struct sockaddr_in*)&info.src)->sin_addr.s_addr = inet_addr("10.0.0.1");
    ((struct sockaddr_in*)&info.src)->sin_port = htons(1234);
    ((struct sockaddr_in*)&info.dst)->sin_family = AF_INET;
    ((struct sockaddr_in*)&info.dst)->sin_addr.s_addr = inet_addr("10.0.0.2");
    ((struct sockaddr_in*)&info.dst)->sin_port = htons(5678);

    n = serialize_proxy_v1(buf1, sizeof(buf1), &info);
    assert(n > 0);
    assert(strcmp(buf1, "PROXY TCP4 10.0.0.1 10.0.0.2 1234 5678\r\n") == 0);

    memset(&info2, 0, sizeof(info2));
    assert(parse_proxy_v1(buf1, &info2) == 0);
    assert(info2.family == info.family);
    assert(((struct sockaddr_in*)&info2.src)->sin_addr.s_addr == ((struct sockaddr_in*)&info.src)->sin_addr.s_addr);

    /* v2 Round-trip */
    memset(&info, 0, sizeof(info));
    info.family = AF_INET6;
    info.type = SOCK_STREAM;
    ((struct sockaddr_in6*)&info.src)->sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &((struct sockaddr_in6*)&info.src)->sin6_addr);
    ((struct sockaddr_in6*)&info.src)->sin6_port = htons(1234);
    ((struct sockaddr_in6*)&info.dst)->sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::2", &((struct sockaddr_in6*)&info.dst)->sin6_addr);
    ((struct sockaddr_in6*)&info.dst)->sin6_port = htons(5678);

    n = serialize_proxy_v2(buf2, sizeof(buf2), &info);
    assert(n == 16 + 36);

    memset(&info2, 0, sizeof(info2));
    assert(parse_proxy_v2(buf2, n, &info2) == 0);
    assert(info2.family == info.family);
    assert(memcmp(&((struct sockaddr_in6*)&info2.src)->sin6_addr, &((struct sockaddr_in6*)&info.src)->sin6_addr, 16) ==
           0);

    printf("Serialization round-trip tests passed!\n");
}

int main() {
    test_parse_v1();
    test_parse_v2();
    test_serialization_roundtrip();
    return 0;
}
