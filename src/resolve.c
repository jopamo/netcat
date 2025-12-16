#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "nc_ctx.h"

static int nc_socktype(enum nc_proto p) {
    return (p == NC_UDP) ? SOCK_DGRAM : SOCK_STREAM;
}

int nc_resolve_one(const char* host,
                   const char* service,
                   int family,
                   enum nc_proto proto,
                   struct sockaddr_storage* out,
                   socklen_t* out_len,
                   bool numeric_only) {
    struct addrinfo hints = {0};
    hints.ai_family = family;  // AF_UNSPEC / AF_INET / AF_INET6
    hints.ai_socktype = nc_socktype(proto);
    hints.ai_flags = AI_ADDRCONFIG;
    if (numeric_only)
        hints.ai_flags |= AI_NUMERICHOST;

    struct addrinfo* res = NULL;
    int rc = getaddrinfo(host, service, &hints, &res);
    if (rc != 0)
        return -1;

    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

int nc_reverse_name(const struct sockaddr* sa, socklen_t slen, char* host, size_t host_sz, bool numeric_only) {
    int flags = numeric_only ? NI_NUMERICHOST : 0;
    return getnameinfo(sa, slen, host, host_sz, NULL, 0, flags);
}

// Resolve port string (like "http" or "80") to number
unsigned short nc_resolve_port(struct nc_ctx* ctx, const char* port_str) {
    if (!port_str)
        return 0;

    // Try numeric first
    char* endptr;
    unsigned long val = strtoul(port_str, &endptr, 10);
    if (*endptr == '\0' && val > 0 && val <= 65535) {
        ctx->port_num = (unsigned short)val;
        // Try to get service name
        struct servent* se = getservbyport(htons(ctx->port_num), ctx->proto == NC_UDP ? "udp" : "tcp");
        if (se) {
            strncpy(ctx->port_name, se->s_name, sizeof(ctx->port_name) - 1);
            ctx->port_name[sizeof(ctx->port_name) - 1] = '\0';
        }
        else {
            snprintf(ctx->port_name, sizeof(ctx->port_name), "%u", ctx->port_num);
        }
        return ctx->port_num;
    }

    // Not numeric, try service name
    if (!ctx->numeric_only) {
        struct servent* se = getservbyname(port_str, ctx->proto == NC_UDP ? "udp" : "tcp");
        if (se) {
            ctx->port_num = ntohs(se->s_port);
            strncpy(ctx->port_name, se->s_name, sizeof(ctx->port_name) - 1);
            ctx->port_name[sizeof(ctx->port_name) - 1] = '\0';
            return ctx->port_num;
        }
    }

    // Failed
    return 0;
}

// Parse port range string like "20-30" or single port
int nc_parse_port_range(struct nc_ctx* ctx, const char* range_str) {
    if (!range_str)
        return -1;

    char* dash = strchr(range_str, '-');
    // Handle escaped dashes? Not needed for now
    if (dash && dash > range_str && *(dash - 1) != '\\') {
        char low[64], high[64];
        size_t low_len = (size_t)(dash - range_str);
        if (low_len >= sizeof(low))
            return -1;
        strncpy(low, range_str, low_len);
        low[low_len] = '\0';
        strncpy(high, dash + 1, sizeof(high) - 1);
        high[sizeof(high) - 1] = '\0';

        unsigned short lo = nc_resolve_port(ctx, low);
        unsigned short hi = nc_resolve_port(ctx, high);
        if (lo == 0 || hi == 0)
            return -1;
        if (lo > hi) {
            // swap
            unsigned short tmp = lo;
            lo = hi;
            hi = tmp;
        }
        ctx->loport = lo;
        ctx->hiport = hi;
        ctx->curport = hi;  // start from high
        ctx->single_mode = false;
        return 0;
    }
    else {
        // Single port
        unsigned short p = nc_resolve_port(ctx, range_str);
        if (p == 0)
            return -1;
        ctx->loport = p;
        ctx->hiport = p;
        ctx->curport = p;
        ctx->single_mode = true;
        return 0;
    }
}

// Resolve local address string and store in ctx->local_addr
int nc_resolve_local_address(struct nc_ctx* ctx, const char* addr_str) {
    if (!addr_str)
        return -1;

    // Use getaddrinfo with AI_PASSIVE?
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = nc_socktype(ctx->proto);
    hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    struct addrinfo* res = NULL;
    int rc = getaddrinfo(addr_str, NULL, &hints, &res);
    if (rc != 0) {
        // Maybe it's a hostname, try without AI_NUMERICHOST if numeric_only not set
        if (!ctx->numeric_only) {
            hints.ai_flags = AI_PASSIVE;
            rc = getaddrinfo(addr_str, NULL, &hints, &res);
        }
        if (rc != 0)
            return -1;
    }

    memcpy(&ctx->local_addr, res->ai_addr, res->ai_addrlen);
    ctx->local_addrlen = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

// Initialize random port tracking array for range lo..hi (inclusive)
int nc_random_ports_init(struct nc_ctx* ctx, unsigned short lo, unsigned short hi) {
    if (lo == 0 || hi == 0 || lo > hi)
        return -1;
    if (ctx->randports)
        free(ctx->randports);
    ctx->randports = calloc(65536, 1);  // 64K bytes
    if (!ctx->randports)
        return -1;
    for (unsigned short p = lo; p <= hi; p++) {
        ctx->randports[p] = 1;  // mark as 'to be tested'
    }
    return 0;
}

// Get next random port from initialized array, mark as used
unsigned short nc_random_ports_next(struct nc_ctx* ctx) {
    if (!ctx->randports)
        return 0;

    // First try random picks
    for (int tries = 0; tries < 70000; tries++) {
        unsigned short p = rand() & 0xffff;
        if (ctx->randports[p] == 1) {
            ctx->randports[p] = 2;  // marked as used
            return p;
        }
    }

    // Fallback linear search
    for (unsigned short p = 65535; p > 0; p--) {
        if (ctx->randports[p] == 1) {
            ctx->randports[p] = 2;
            return p;
        }
    }
    return 0;
}