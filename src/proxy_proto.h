#ifndef NETCAT_PROXY_PROTO_H
#define NETCAT_PROXY_PROTO_H

#include <sys/socket.h>
#include <stdint.h>

struct proxy_info {
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    int family;
    int proto;
    int type;
};

void send_proxy_v2(int fd);
void recv_proxy(int fd);

/* For testing */
int parse_proxy_v1(const char* line, struct proxy_info* info);
int parse_proxy_v2(const uint8_t* buf, size_t len, struct proxy_info* info);
int serialize_proxy_v1(char* buf, size_t len, const struct proxy_info* info);
int serialize_proxy_v2(uint8_t* buf, size_t len, const struct proxy_info* info);

#endif
