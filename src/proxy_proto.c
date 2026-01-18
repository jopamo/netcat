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

static const uint8_t sig_v2[12] = {0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a};

int parse_proxy_v1(const char* line, struct proxy_info* info) {
    char protocol[16], src_addr[INET6_ADDRSTRLEN], dst_addr[INET6_ADDRSTRLEN];
    int src_port, dst_port;

    /* Sanitize: only printable ASCII allowed in v1 header */
    for (const char* p = line; *p; p++) {
        if (!isprint((unsigned char)*p) && *p != '\r' && *p != '\n')
            return -1;
    }

    if (sscanf(line, "PROXY %15s %45s %45s %d %d", protocol, src_addr, dst_addr, &src_port, &dst_port) == 5) {
        if (strcmp(protocol, "TCP4") == 0) {
            struct sockaddr_in* sin_src = (struct sockaddr_in*)&info->src;
            struct sockaddr_in* sin_dst = (struct sockaddr_in*)&info->dst;
            info->family = AF_INET;
            sin_src->sin_family = AF_INET;
            sin_dst->sin_family = AF_INET;
            if (inet_pton(AF_INET, src_addr, &sin_src->sin_addr) != 1)
                return -1;
            if (inet_pton(AF_INET, dst_addr, &sin_dst->sin_addr) != 1)
                return -1;
            sin_src->sin_port = htons(src_port);
            sin_dst->sin_port = htons(dst_port);
            return 0;
        }
        else if (strcmp(protocol, "TCP6") == 0) {
            struct sockaddr_in6* sin6_src = (struct sockaddr_in6*)&info->src;
            struct sockaddr_in6* sin6_dst = (struct sockaddr_in6*)&info->dst;
            info->family = AF_INET6;
            sin6_src->sin6_family = AF_INET6;
            sin6_dst->sin6_family = AF_INET6;
            if (inet_pton(AF_INET6, src_addr, &sin6_src->sin6_addr) != 1)
                return -1;
            if (inet_pton(AF_INET6, dst_addr, &sin6_dst->sin6_addr) != 1)
                return -1;
            sin6_src->sin6_port = htons(src_port);
            sin6_dst->sin6_port = htons(dst_port);
            return 0;
        }
    }

    if (strncmp(line, "PROXY UNKNOWN", 13) == 0) {
        info->family = AF_UNSPEC;
        return 0;
    }

    return -1;
}

int parse_proxy_v2(const uint8_t* buf, size_t len, struct proxy_info* info) {
    const struct proxy_hdr_v2* hdr = (const struct proxy_hdr_v2*)buf;

    if (len < 16)
        return -1;

    if (memcmp(hdr->sig, sig_v2, 12) != 0)
        return -1;

    uint16_t h_len = ntohs(hdr->len);
    if (len < (size_t)16 + h_len)
        return -1;

    if (hdr->fam_proto == 0x11 || hdr->fam_proto == 0x12) {
        if (h_len < 12)
            return -1;
        struct sockaddr_in* sin_src = (struct sockaddr_in*)&info->src;
        struct sockaddr_in* sin_dst = (struct sockaddr_in*)&info->dst;
        info->family = AF_INET;
        sin_src->sin_family = AF_INET;
        sin_dst->sin_family = AF_INET;
        sin_src->sin_addr.s_addr = hdr->addr.ipv4_addr.src_addr;
        sin_dst->sin_addr.s_addr = hdr->addr.ipv4_addr.dst_addr;
        sin_src->sin_port = hdr->addr.ipv4_addr.src_port;
        sin_dst->sin_port = hdr->addr.ipv4_addr.dst_port;
        return 0;
    }
    else if (hdr->fam_proto == 0x21 || hdr->fam_proto == 0x22) {
        if (h_len < 36)
            return -1;
        struct sockaddr_in6* sin6_src = (struct sockaddr_in6*)&info->src;
        struct sockaddr_in6* sin6_dst = (struct sockaddr_in6*)&info->dst;
        info->family = AF_INET6;
        sin6_src->sin6_family = AF_INET6;
        sin6_dst->sin6_family = AF_INET6;
        memcpy(&sin6_src->sin6_addr, hdr->addr.ipv6_addr.src_addr, 16);
        memcpy(&sin6_dst->sin6_addr, hdr->addr.ipv6_addr.dst_addr, 16);
        sin6_src->sin6_port = hdr->addr.ipv6_addr.src_port;
        sin6_dst->sin6_port = hdr->addr.ipv6_addr.dst_port;
        return 0;
    }
    else if ((hdr->ver_cmd & 0x0F) == 0x00) { /* LOCAL */
        info->family = AF_UNSPEC;
        return 0;
    }

    return -1;
}

int serialize_proxy_v1(char* buf, size_t len, const struct proxy_info* info) {
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    uint16_t src_p, dst_p;

    if (info->family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)&info->src)->sin_addr, src, sizeof(src));
        inet_ntop(AF_INET, &((struct sockaddr_in*)&info->dst)->sin_addr, dst, sizeof(dst));
        src_p = ntohs(((struct sockaddr_in*)&info->src)->sin_port);
        dst_p = ntohs(((struct sockaddr_in*)&info->dst)->sin_port);
        return snprintf(buf, len, "PROXY TCP4 %s %s %u %u\r\n", src, dst, src_p, dst_p);
    }
    else if (info->family == AF_INET6) {
        inet_ntop(AF_INET6, &((struct sockaddr_in6*)&info->src)->sin6_addr, src, sizeof(src));
        inet_ntop(AF_INET6, &((struct sockaddr_in6*)&info->dst)->sin6_addr, dst, sizeof(dst));
        src_p = ntohs(((struct sockaddr_in6*)&info->src)->sin6_port);
        dst_p = ntohs(((struct sockaddr_in6*)&info->dst)->sin6_port);
        return snprintf(buf, len, "PROXY TCP6 %s %s %u %u\r\n", src, dst, src_p, dst_p);
    }
    else {
        return snprintf(buf, len, "PROXY UNKNOWN\r\n");
    }
}

int serialize_proxy_v2(uint8_t* buf, size_t len, const struct proxy_info* info) {
    struct proxy_hdr_v2* hdr = (struct proxy_hdr_v2*)buf;
    if (len < 16)
        return -1;

    memset(hdr, 0, 16);
    memcpy(hdr->sig, sig_v2, 12);
    hdr->ver_cmd = 0x21; /* v2, PROXY */

    if (info->family == AF_INET) {
        if (len < 16 + 12)
            return -1;
        hdr->fam_proto = (info->type == SOCK_STREAM) ? 0x11 : 0x12;
        hdr->len = htons(12);
        hdr->addr.ipv4_addr.src_addr = ((struct sockaddr_in*)&info->src)->sin_addr.s_addr;
        hdr->addr.ipv4_addr.dst_addr = ((struct sockaddr_in*)&info->dst)->sin_addr.s_addr;
        hdr->addr.ipv4_addr.src_port = ((struct sockaddr_in*)&info->src)->sin_port;
        hdr->addr.ipv4_addr.dst_port = ((struct sockaddr_in*)&info->dst)->sin_port;
        return 16 + 12;
    }
    else if (info->family == AF_INET6) {
        if (len < 16 + 36)
            return -1;
        hdr->fam_proto = (info->type == SOCK_STREAM) ? 0x21 : 0x22;
        hdr->len = htons(36);
        memcpy(hdr->addr.ipv6_addr.src_addr, &((struct sockaddr_in6*)&info->src)->sin6_addr, 16);
        memcpy(hdr->addr.ipv6_addr.dst_addr, &((struct sockaddr_in6*)&info->dst)->sin6_addr, 16);
        hdr->addr.ipv6_addr.src_port = ((struct sockaddr_in6*)&info->src)->sin6_port;
        hdr->addr.ipv6_addr.dst_port = ((struct sockaddr_in6*)&info->dst)->sin6_port;
        return 16 + 36;
    }
    else {
        hdr->fam_proto = 0x00; /* UNSPEC */
        hdr->len = htons(0);
        return 16;
    }
}

static void report_proxy(const struct proxy_info* info, int version) {
    if (vflag) {
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        uint16_t src_p = 0, dst_p = 0;

        if (info->family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)&info->src)->sin_addr, src, sizeof(src));
            inet_ntop(AF_INET, &((struct sockaddr_in*)&info->dst)->sin_addr, dst, sizeof(dst));
            src_p = ntohs(((struct sockaddr_in*)&info->src)->sin_port);
            dst_p = ntohs(((struct sockaddr_in*)&info->dst)->sin_port);
            fprintf(stderr, "PROXY v%d: %s:%u -> %s:%u\n", version, src, src_p, dst, dst_p);
        }
        else if (info->family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&info->src)->sin6_addr, src, sizeof(src));
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&info->dst)->sin6_addr, dst, sizeof(dst));
            src_p = ntohs(((struct sockaddr_in6*)&info->src)->sin6_port);
            dst_p = ntohs(((struct sockaddr_in6*)&info->dst)->sin6_port);
            fprintf(stderr, "PROXY v%d: [%s]:%u -> [%s]:%u\n", version, src, src_p, dst, dst_p);
        }
        else {
            fprintf(stderr, "PROXY v%d: UNKNOWN\n", version);
        }
    }
}

static int get_proxy_info_from_fd(int fd, struct proxy_info* info) {
    socklen_t len;
    int type;

    memset(info, 0, sizeof(*info));
    len = sizeof(info->src);
    if (getsockname(fd, (struct sockaddr*)&info->src, &len) == -1)
        return -1;
    len = sizeof(info->dst);
    if (getpeername(fd, (struct sockaddr*)&info->dst, &len) == -1)
        return -1;
    len = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == -1)
        return -1;

    info->family = info->src.ss_family;
    info->type = type;
    return 0;
}

void send_proxy_v2(int fd) {
    struct proxy_info info;
    uint8_t buf[512];
    int n;

    if (get_proxy_info_from_fd(fd, &info) == -1)
        return;

    n = serialize_proxy_v2(buf, sizeof(buf), &info);
    if (n > 0)
        atomicio(vwrite, fd, buf, n);
}

void recv_proxy(int fd) {
    struct proxy_info info;
    uint8_t buf[256];

    memset(&info, 0, sizeof(info));

    if (atomicio(read, fd, buf, 5) != 5)
        return;

    if (memcmp(buf, "PROXY", 5) == 0) {
        char line[128];
        size_t i = 5;
        memcpy(line, "PROXY", 5);
        while (i < sizeof(line) - 1) {
            if (atomicio(read, fd, &line[i], 1) != 1)
                return;
            if (line[i] == '\n') {
                line[++i] = '\0';
                break;
            }
            i++;
        }
        if (i == sizeof(line) - 1) {
            warnx("PROXY v1 header too long");
            return;
        }
        if (parse_proxy_v1(line, &info) == 0)
            report_proxy(&info, 1);
        else
            warnx("Invalid PROXY v1 header");
    }
    else if (memcmp(buf, sig_v2, 5) == 0) {
        if (atomicio(read, fd, buf + 5, 11) != 11)
            return;

        uint16_t len = ntohs(((struct proxy_hdr_v2*)buf)->len);
        if (len > sizeof(buf) - 16) {
            warnx("PROXY protocol header too large");
            return;
        }

        if (atomicio(read, fd, buf + 16, len) != len)
            return;

        if (parse_proxy_v2(buf, 16 + len, &info) == 0)
            report_proxy(&info, 2);
        else
            warnx("Invalid PROXY v2 header");
    }
    else {
        warnx("Invalid PROXY protocol signature");
    }
}
