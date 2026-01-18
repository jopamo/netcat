#include "netcat.h"
#include "proxy_proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct proxy_hdr_v2 {
    uint8_t sig[12];
    uint8_t ver_cmd;
    uint8_t fam_proto;
    uint16_t len;
    union {
        struct {
            uint32_t src_addr;
            uint32_t dst_addr;
            uint16_t src_port;
            uint16_t dst_port;
        } ipv4_addr;
        struct {
            uint8_t src_addr[16];
            uint8_t dst_addr[16];
            uint16_t src_port;
            uint16_t dst_port;
        } ipv6_addr;
        struct {
            uint8_t src_addr[108];
            uint8_t dst_addr[108];
        } unix_addr;
    } addr;
} __attribute__((packed));

void send_proxy_v2(int fd) {
    struct proxy_hdr_v2 hdr;
    struct sockaddr_storage local, remote;
    socklen_t len;
    int type;

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.sig, "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a", 12);
    hdr.ver_cmd = 0x21;  // v2, PROXY

    len = sizeof(local);
    if (getsockname(fd, (struct sockaddr*)&local, &len) == -1)
        return;
    len = sizeof(remote);
    if (getpeername(fd, (struct sockaddr*)&remote, &len) == -1)
        return;
    len = sizeof(type);
    getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len);

    if (local.ss_family == AF_INET) {
        hdr.fam_proto = (type == SOCK_STREAM) ? 0x11 : 0x12;
        hdr.len = htons(12);
        hdr.addr.ipv4_addr.src_addr = ((struct sockaddr_in*)&local)->sin_addr.s_addr;
        hdr.addr.ipv4_addr.dst_addr = ((struct sockaddr_in*)&remote)->sin_addr.s_addr;
        hdr.addr.ipv4_addr.src_port = ((struct sockaddr_in*)&local)->sin_port;
        hdr.addr.ipv4_addr.dst_port = ((struct sockaddr_in*)&remote)->sin_port;
        atomicio(vwrite, fd, &hdr, 16 + 12);
    }
    else if (local.ss_family == AF_INET6) {
        hdr.fam_proto = (type == SOCK_STREAM) ? 0x21 : 0x22;
        hdr.len = htons(36);
        memcpy(hdr.addr.ipv6_addr.src_addr, &((struct sockaddr_in6*)&local)->sin6_addr, 16);
        memcpy(hdr.addr.ipv6_addr.dst_addr, &((struct sockaddr_in6*)&remote)->sin6_addr, 16);
        hdr.addr.ipv6_addr.src_port = ((struct sockaddr_in6*)&local)->sin6_port;
        hdr.addr.ipv6_addr.dst_port = ((struct sockaddr_in6*)&remote)->sin6_port;
        atomicio(vwrite, fd, &hdr, 16 + 36);
    }
}

void recv_proxy_v2(int fd) {
    struct proxy_hdr_v2 hdr;
    static const uint8_t sig[12] = {0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a};

    if (atomicio(read, fd, &hdr, 16) != 16)
        return;

    if (memcmp(hdr.sig, sig, 12) != 0) {
        warnx("Invalid PROXY protocol signature");
        return;
    }

    uint16_t len = ntohs(hdr.len);
    if (len > sizeof(hdr.addr)) {
        warnx("PROXY protocol header too large");
        return;
    }

    if (atomicio(read, fd, &hdr.addr, len) != len)
        return;

    if (vflag) {
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        if (hdr.fam_proto == 0x11 || hdr.fam_proto == 0x12) {
            inet_ntop(AF_INET, &hdr.addr.ipv4_addr.src_addr, src, sizeof(src));
            inet_ntop(AF_INET, &hdr.addr.ipv4_addr.dst_addr, dst, sizeof(dst));
            fprintf(stderr, "PROXY v2: %s:%u -> %s:%u\n", src, ntohs(hdr.addr.ipv4_addr.src_port), dst,
                    ntohs(hdr.addr.ipv4_addr.dst_port));
        }
        else if (hdr.fam_proto == 0x21 || hdr.fam_proto == 0x22) {
            inet_ntop(AF_INET6, &hdr.addr.ipv6_addr.src_addr, src, sizeof(src));
            inet_ntop(AF_INET6, &hdr.addr.ipv6_addr.dst_addr, dst, sizeof(dst));
            fprintf(stderr, "PROXY v2: [%s]:%u -> [%s]:%u\n", src, ntohs(hdr.addr.ipv6_addr.src_port), dst,
                    ntohs(hdr.addr.ipv6_addr.dst_port));
        }
    }
}
